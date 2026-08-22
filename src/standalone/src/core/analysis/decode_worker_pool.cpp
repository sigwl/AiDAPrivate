#include "decode_worker_pool.hpp"

#include "../infra/fast_containers.hpp"
#include "../infra/taskflow_runtime.hpp"

#include "../../helpers/diag_log.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr const char* kPhase = "decode_worker_pool";

constexpr std::uint32_t kCppExceptionFatalCode = 0xFFFFFFFFu;

constexpr auto kIdleWakeBackstop = std::chrono::milliseconds(5);

constexpr auto kBackpressureWakeBackstop = std::chrono::milliseconds(2);

constexpr auto kCompletionWakeBackstop = std::chrono::milliseconds(2);

constexpr std::uint32_t kLaneJoinTimeoutMs = 15000;

workspace_error_t pool_error(workspace_error_code_t code, std::string message)
{
    return make_workspace_error(code, std::move(message), kPhase);
}

workspace_error_t pool_cancelled_error()
{
    auto error = pool_error(workspace_error_code_t::cancelled,
        "tile decode batch cancelled");
    error.cancellation = true;
    return error;
}

struct decode_completion_slot_t final {
    aida::infra::fast_blocking_queue<std::optional<tile_decode_completion_t>> queue;
};

class callback_active_guard_t final {
public:
    callback_active_guard_t(std::atomic<std::uint32_t>& active,
        std::condition_variable& cv) noexcept : active_(active), cv_(cv) {}
    ~callback_active_guard_t() {
        if (active_.fetch_sub(1, std::memory_order_seq_cst) == 1)
            cv_.notify_all();
    }

private:
    std::atomic<std::uint32_t>& active_;
    std::condition_variable& cv_;
};

thread_local void* tls_worker_state = nullptr;

}

struct decode_worker_pool_t::worker_state_t final {
    aida::infra::taskflow_runtime::job_handle_t lane_handle{};
    std::mutex mutex;
    std::condition_variable cv;
    std::condition_variable space_cv;
    std::deque<decode_work_item_t> queue;
    std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86;
    std::unique_ptr<decode::worker_owned_capstone_tile_decoder_t> capstone;
    workspace_error_t create_error;
    bool has_create_error = false;
    std::atomic<bool> has_active_item{false};
    decode_work_item_t active_item;
    std::uint32_t index = 0;
    decode_worker_pool_t::impl_t* pool_impl = nullptr;
};

struct decode_worker_pool_t::impl_t final {
    std::vector<std::unique_ptr<worker_state_t>> workers;
    std::vector<std::unique_ptr<decode_completion_slot_t>> slots;
    production_tile_decode_executor_options_t options;
    bool use_x86 = false;
    std::atomic<const provider_snapshot_t*> snapshot{nullptr};
    std::atomic<std::uint64_t> active_items{0};
    std::atomic<bool> stop{false};
    std::atomic<bool> seh_fatal{false};
    std::atomic<std::uint32_t> seh_code{0};
    std::uint32_t max_queue_depth = 4096;
    cancellation_token_t cancellation;
    std::atomic<lease_hook_t> hook{nullptr};
    std::atomic<void*> hook_context{nullptr};
    std::atomic<std::uint32_t> hook_active{0};
    std::atomic<completion_signal_t> completion_signal{nullptr};
    std::atomic<void*> completion_signal_context{nullptr};
    std::atomic<std::uint32_t> completion_signal_active{0};
    std::mutex callback_mutex;
    std::condition_variable callback_cv;
    std::atomic<std::uint64_t> completion_push_count{0};
    std::atomic<std::uint64_t> steal_count{0};
    std::atomic<std::uint64_t> backpressure_wait_count{0};
    std::atomic<std::uint64_t> inline_drain_count{0};
    std::atomic<std::uint64_t> max_queue_depth_seen{0};
    std::atomic<std::uint64_t> lane_clamp_count{0};
};

namespace {

using fabric_token_t = aida::infra::taskflow_runtime::cancellation_token_t;

bool lane_stop_requested(const decode_worker_pool_t::impl_t& impl,
                         const fabric_token_t& lane_token)
{
    return impl.stop.load(std::memory_order_acquire) ||
        impl.cancellation.stop_requested() ||
        lane_token.requested.load(std::memory_order_acquire);
}

decode_worker_pool_t::lease_hook_t pool_hook(const decode_worker_pool_t::impl_t& impl,
                                             void*& context)
{
    const auto hook = impl.hook.load(std::memory_order_seq_cst);
    context = impl.hook_context.load(std::memory_order_seq_cst);
    return hook;
}

void invoke_completion_signal(decode_worker_pool_t::impl_t& impl)
{
    decode_worker_pool_t::completion_signal_t signal = nullptr;
    void* context = nullptr;
    {
        std::lock_guard<std::mutex> lock(impl.callback_mutex);
        signal = impl.completion_signal.load(std::memory_order_seq_cst);
        if (signal == nullptr)
            return;
        context = impl.completion_signal_context.load(std::memory_order_seq_cst);
        impl.completion_signal_active.fetch_add(1, std::memory_order_seq_cst);
    }
    callback_active_guard_t active_guard(
        impl.completion_signal_active, impl.callback_cv);
    signal(context);
}

void note_queue_depth(decode_worker_pool_t::impl_t& impl, std::size_t depth)
{
    const auto value = static_cast<std::uint64_t>(depth);
    auto current = impl.max_queue_depth_seen.load(std::memory_order_relaxed);
    while (value > current &&
           !impl.max_queue_depth_seen.compare_exchange_weak(
               current, value, std::memory_order_relaxed)) {
    }
}

void push_completion(decode_worker_pool_t::impl_t& impl, std::uint32_t shard_index,
                     tile_decode_completion_t completion)
{
    const auto slot_index = static_cast<std::size_t>(
        shard_index % static_cast<std::uint32_t>(impl.slots.size()));
    auto& slot = *impl.slots[slot_index];
    slot.queue.enqueue(std::optional<tile_decode_completion_t>(std::move(completion)));
    impl.active_items.fetch_sub(1, std::memory_order_acq_rel);
    impl.completion_push_count.fetch_add(1, std::memory_order_relaxed);
    invoke_completion_signal(impl);
}

tile_decode_completion_t decode_item(decode_worker_pool_t::worker_state_t& worker,
                                     decode_worker_pool_t::impl_t& impl,
                                     const decode_work_item_t& item)
{
    tile_decode_completion_t completion;
    completion.request_id = item.request.request_id;
    if (worker.has_create_error) {
        completion.error = worker.create_error;
        return completion;
    }
    if (impl.stop.load(std::memory_order_acquire) ||
        impl.cancellation.stop_requested()) {
        completion.error = pool_cancelled_error();
        return completion;
    }
    const auto* snapshot = impl.snapshot.load(std::memory_order_acquire);
    if (snapshot == nullptr) {
        completion.error = pool_error(workspace_error_code_t::integrity_failure,
            "decode worker pool has no bound snapshot");
        return completion;
    }
    const auto& request = item.request;
    ::diag::log_tagged_fmt(kPhase,
        "decode_begin worker=%u request_id=%llu tile_id=%u pass=%u start=0x%llX provider_offset=0x%llX bytes=%llu tid=%lu",
        worker.index,
        static_cast<unsigned long long>(request.request_id),
        static_cast<unsigned>(request.tile_id),
        static_cast<unsigned>(request.pass),
        static_cast<unsigned long long>(request.start.value),
        static_cast<unsigned long long>(request.provider_offset),
        static_cast<unsigned long long>(request.byte_count),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (impl.use_x86) {
        decode::x86_tile_decode_request_t x86_request;
        x86_request.start_address = request.start;
        x86_request.provider_offset = request.provider_offset;
        x86_request.byte_count = request.byte_count;
        x86_request.runtime_address = request.runtime_address;
        x86_request.image_base = request.image_base;
        x86_request.image_size = request.image_size;
        x86_request.provenance = request.provenance;
        x86_request.confidence = request.confidence;
        x86_request.stable_source_id = request.stable_source_id;
        x86_request.limits = impl.options.x86_limits;
        auto result = worker.x86->decode_tile(*snapshot, x86_request, impl.cancellation);
        if (!result) {
            completion.error = result.error();
            ::diag::log_tagged_fmt(kPhase,
                "decode_end worker=%u request_id=%llu ok=0 code=%u msg=%s tid=%lu",
                worker.index,
                static_cast<unsigned long long>(request.request_id),
                static_cast<unsigned>(completion.error->code),
                completion.error->message.c_str(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            return completion;
        }
        auto decoded = result.take_value();
        completion.records.instructions = std::move(decoded.instructions);
        completion.records.operand_facts = std::move(decoded.operand_facts);
        completion.records.target_facts = std::move(decoded.target_facts);
        completion.records.coverage = std::move(decoded.coverage);
        completion.records.bytes_consumed = decoded.usage.bytes_consumed;
        completion.records.invalid_bytes = decoded.usage.invalid_bytes;
        completion.records.delay_slot_counts.resize(
            completion.records.instructions.size(), 0);
        ::diag::log_tagged_fmt(kPhase,
            "decode_end worker=%u request_id=%llu ok=1 instructions=%zu operands=%zu targets=%zu bytes=%llu invalid=%llu tid=%lu",
            worker.index,
            static_cast<unsigned long long>(request.request_id),
            completion.records.instructions.size(),
            completion.records.operand_facts.size(),
            completion.records.target_facts.size(),
            static_cast<unsigned long long>(completion.records.bytes_consumed),
            static_cast<unsigned long long>(completion.records.invalid_bytes),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return completion;
    }
    decode::capstone_tile_identity_t identity;
    identity.decoder_key = impl.options.decoder_key;
    identity.start = request.start;
    identity.provider_offset = request.provider_offset;
    identity.runtime_address = request.runtime_address;
    identity.image_base = request.image_base;
    identity.image_size = request.image_size;
    identity.byte_count = request.byte_count;
    identity.snapshot_generation = snapshot->generation();
    identity.stable_source_id = request.stable_source_id;
    identity.provenance = request.provenance;
    identity.confidence = request.confidence;
    auto result = worker.capstone->decode_tile(*snapshot, identity, impl.cancellation);
    if (!result) {
        completion.error = result.error();
        ::diag::log_tagged_fmt(kPhase,
            "decode_end worker=%u request_id=%llu ok=0 code=%u msg=%s tid=%lu",
            worker.index,
            static_cast<unsigned long long>(request.request_id),
            static_cast<unsigned>(completion.error->code),
            completion.error->message.c_str(),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return completion;
    }
    auto decoded = result.take_value();
    completion.records.instructions = std::move(decoded.instructions);
    completion.records.operand_facts = std::move(decoded.operand_facts);
    completion.records.target_facts = std::move(decoded.target_facts);
    completion.records.delay_slot_counts = std::move(decoded.delay_slot_counts);
    completion.records.coverage = std::move(decoded.coverage);
    completion.records.bytes_consumed = decoded.usage.bytes_consumed;
    completion.records.invalid_bytes = decoded.usage.undecodable_bytes;
    ::diag::log_tagged_fmt(kPhase,
        "decode_end worker=%u request_id=%llu ok=1 instructions=%zu operands=%zu targets=%zu bytes=%llu invalid=%llu tid=%lu",
        worker.index,
        static_cast<unsigned long long>(request.request_id),
        completion.records.instructions.size(),
        completion.records.operand_facts.size(),
        completion.records.target_facts.size(),
        static_cast<unsigned long long>(completion.records.bytes_consumed),
        static_cast<unsigned long long>(completion.records.invalid_bytes),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return completion;
}

void run_item(decode_worker_pool_t::worker_state_t& worker,
              decode_worker_pool_t::impl_t& impl, decode_work_item_t item)
{
    worker.active_item = item;
    worker.has_active_item.store(true, std::memory_order_release);
    auto completion = decode_item(worker, impl, item);
    worker.has_active_item.store(false, std::memory_order_release);
    push_completion(impl, item.shard_index, std::move(completion));
}

bool try_pop_own(decode_worker_pool_t::worker_state_t& worker,
                 decode_work_item_t& item)
{
    std::lock_guard<std::mutex> lock(worker.mutex);
    if (worker.queue.empty())
        return false;
    item = std::move(worker.queue.front());
    worker.queue.pop_front();
    worker.space_cv.notify_one();
    return true;
}

bool try_steal(decode_worker_pool_t::worker_state_t& victim,
               decode_work_item_t& item)
{
    std::lock_guard<std::mutex> lock(victim.mutex);
    if (victim.queue.empty())
        return false;
    item = std::move(victim.queue.back());
    victim.queue.pop_back();
    victim.space_cv.notify_one();
    victim.pool_impl->steal_count.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void drain_worker_queue(decode_worker_pool_t::worker_state_t& worker,
                        decode_worker_pool_t::impl_t& impl)
{
    if (worker.has_active_item.load(std::memory_order_acquire)) {
        tile_decode_completion_t completion;
        completion.request_id = worker.active_item.request.request_id;
        completion.error = pool_cancelled_error();
        push_completion(impl, worker.active_item.shard_index, std::move(completion));
    }
    for (;;) {
        decode_work_item_t item;
        {
            std::lock_guard<std::mutex> lock(worker.mutex);
            if (worker.queue.empty())
                break;
            item = std::move(worker.queue.front());
            worker.queue.pop_front();
        }
        tile_decode_completion_t completion;
        completion.request_id = item.request.request_id;
        completion.error = pool_cancelled_error();
        push_completion(impl, item.shard_index, std::move(completion));
    }
    worker.space_cv.notify_all();
}

void create_worker_decoder(decode_worker_pool_t::worker_state_t& worker,
                           decode_worker_pool_t::impl_t& impl)
{
    if (impl.use_x86) {
        auto created = decode::worker_owned_x86_tile_decoder_t::create(
            impl.options.decoder_key.mode);
        if (!created) {
            worker.create_error = created.error();
            worker.has_create_error = true;
            return;
        }
        worker.x86 = std::move(created.value());
        return;
    }
    auto created = decode::worker_owned_capstone_tile_decoder_t::create(
        impl.options.decoder_key, impl.options.capstone_options, impl.cancellation);
    if (!created) {
        worker.create_error = created.error();
        worker.has_create_error = true;
        return;
    }
    worker.capstone = std::move(created.value());
}

void record_worker_fatal(decode_worker_pool_t::impl_t& impl, std::uint32_t code)
{
    std::uint32_t expected = 0;
    if (impl.seh_code.compare_exchange_strong(expected, code,
            std::memory_order_acq_rel)) {
        impl.seh_fatal.store(true, std::memory_order_release);
        for (auto& worker : impl.workers) {
            worker->cv.notify_all();
            worker->space_cv.notify_all();
        }
        for (auto& slot : impl.slots)
            slot->queue.enqueue(std::optional<tile_decode_completion_t>(std::nullopt));
        invoke_completion_signal(impl);
    }
}

void worker_main_body(decode_worker_pool_t::worker_state_t& worker,
                      decode_worker_pool_t::impl_t& impl,
                      const fabric_token_t& lane_token)
{
    try {
        create_worker_decoder(worker, impl);
        const auto worker_count =
            static_cast<std::uint32_t>(impl.workers.size());
        for (;;) {
            if (impl.stop.load(std::memory_order_acquire))
                break;
            void* hook_context = nullptr;
            decode_worker_pool_t::lease_hook_t hook = nullptr;
            {
                std::lock_guard<std::mutex> lock(impl.callback_mutex);
                hook = pool_hook(impl, hook_context);
                if (hook != nullptr)
                    impl.hook_active.fetch_add(1, std::memory_order_seq_cst);
            }
            if (hook != nullptr) {
                callback_active_guard_t active_guard(
                    impl.hook_active, impl.callback_cv);
                const bool lease_progress = hook(hook_context, worker.index);
                if (lease_progress)
                    continue;
                if (lane_stop_requested(impl, lane_token))
                    break;
            }
            if (impl.stop.load(std::memory_order_acquire))
                break;
            decode_work_item_t item;
            if (try_pop_own(worker, item)) {
                run_item(worker, impl, std::move(item));
                continue;
            }
            bool stole = false;
            for (std::uint32_t offset = 1; offset < worker_count; ++offset) {
                const auto victim_index = (worker.index + offset) % worker_count;
                if (try_steal(*impl.workers[victim_index], item)) {
                    run_item(worker, impl, std::move(item));
                    stole = true;
                    break;
                }
            }
            if (stole)
                continue;
            if (lane_stop_requested(impl, lane_token))
                break;
            {
                std::unique_lock<std::mutex> lock(worker.mutex);
                worker.cv.wait_for(lock, kIdleWakeBackstop, [&] {
                    return !worker.queue.empty() ||
                        lane_stop_requested(impl, lane_token) ||
                        impl.hook.load(std::memory_order_acquire) != nullptr;
                });
            }
        }
    } catch (...) {
        record_worker_fatal(impl, kCppExceptionFatalCode);
    }
}

void worker_lane_body(decode_worker_pool_t::worker_state_t& worker,
                      decode_worker_pool_t::impl_t& impl,
                      const fabric_token_t& lane_token)
{
    tls_worker_state = &worker;
    __try {
        worker_main_body(worker, impl, lane_token);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        record_worker_fatal(impl,
            static_cast<std::uint32_t>(GetExceptionCode()));
    }
    tls_worker_state = nullptr;
    drain_worker_queue(worker, impl);
}

void join_lanes(decode_worker_pool_t::impl_t& impl, std::uint32_t timeout_ms)
{
    namespace rt = aida::infra::taskflow_runtime;
    const auto begin = std::chrono::steady_clock::now();
    for (auto& worker : impl.workers) {
        if (!worker->lane_handle.valid())
            continue;
        const auto elapsed = static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - begin).count());
        const std::uint32_t remaining =
            elapsed >= timeout_ms ? 0 : timeout_ms - elapsed;
        const auto waited = rt::wait_for(worker->lane_handle, remaining);
        const auto handle_id = worker->lane_handle.id;
        worker->lane_handle = {};
        if (waited.timed_out) {
            ::diag::log_tagged_fmt(kPhase,
                "lane_join_timeout worker=%u job_id=%llu timeout_ms=%u",
                worker->index,
                static_cast<unsigned long long>(handle_id), timeout_ms);
        }
    }
}

}

workspace_result_t<std::unique_ptr<decode_worker_pool_t>>
decode_worker_pool_t::create(std::uint32_t worker_count,
    const production_tile_decode_executor_options_t& options,
    std::uint64_t maximum_frontier_wave,
    const cancellation_token_t& cancellation)
{
    namespace rt = aida::infra::taskflow_runtime;
    if (worker_count == 0 || worker_count > 64) {
        return workspace_result_t<std::unique_ptr<decode_worker_pool_t>>::failure(
            pool_error(workspace_error_code_t::invalid_argument,
                "decode worker pool worker count is invalid"));
    }
    const std::uint32_t requested_worker_count = worker_count;
    std::uint64_t lane_clamps = 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::uint32_t fabric_capacity = rt::analysis_compute_capacity();
    const std::uint32_t capacity_ceiling = (std::min<std::uint32_t>)(64u, fabric_capacity);
    if (worker_count > capacity_ceiling)
        ++lane_clamps;
    worker_count = (std::min<std::uint32_t>)(worker_count, capacity_ceiling);
    if (worker_count < 2u) {
        ++lane_clamps;
        worker_count = 2u;
    }
    if (lane_clamps != 0) {
        ::diag::log_tagged_fmt(kPhase,
            "lane_count_clamped requested=%u fabric_capacity=%u clamped=%u",
            requested_worker_count, fabric_capacity, worker_count);
    }
#else
    const std::uint32_t fabric_capacity = worker_count;
#endif
    std::unique_ptr<impl_t> impl;
    try {
        impl = std::make_unique<impl_t>();
    } catch (...) {
        return workspace_result_t<std::unique_ptr<decode_worker_pool_t>>::failure(
            pool_error(workspace_error_code_t::limit_exceeded,
                "decode worker pool allocation failed"));
    }
    impl->lane_clamp_count.store(lane_clamps, std::memory_order_relaxed);
    impl->options = options;
    impl->use_x86 =
        (options.decoder_key.architecture == architecture_id_t::x86 ||
         options.decoder_key.architecture == architecture_id_t::x86_64);
    impl->cancellation = cancellation;
    const std::uint64_t wave_share = worker_count == 0
        ? maximum_frontier_wave
        : (maximum_frontier_wave * 2ULL) / worker_count;
    impl->max_queue_depth = static_cast<std::uint32_t>((std::min)(
        (std::max)(wave_share, 64ULL), 4096ULL));
    try {
        impl->workers.reserve(worker_count);
        impl->slots.reserve(maximum_shard_slots);
        for (std::uint32_t slot = 0; slot < maximum_shard_slots; ++slot)
            impl->slots.push_back(std::make_unique<decode_completion_slot_t>());
        for (std::uint32_t index = 0; index < worker_count; ++index) {
            auto worker = std::make_unique<worker_state_t>();
            worker->index = index;
            worker->pool_impl = impl.get();
            impl->workers.push_back(std::move(worker));
        }
    } catch (...) {
        return workspace_result_t<std::unique_ptr<decode_worker_pool_t>>::failure(
            pool_error(workspace_error_code_t::limit_exceeded,
                "decode worker pool thread creation failed"));
    }
    for (auto& worker : impl->workers) {
        auto* raw = worker.get();
        auto* impl_raw = impl.get();
        rt::task_descriptor_t desc;
        desc.domain = rt::executor_domain_t::feature_worker;
        desc.owner_subsystem = "analysis_workspace";
        desc.label = "decode_worker_pool.lane";
        desc.priority = 3;
        desc.shutdown_policy = "cancel_pending";
        desc.cancellable_body = [raw, impl_raw](const fabric_token_t& token) {
            worker_lane_body(*raw, *impl_raw, token);
        };
        auto submitted = rt::submit(std::move(desc));
        if (!submitted.submitted) {
            impl->stop.store(true, std::memory_order_release);
            for (auto& entry : impl->workers) {
                entry->cv.notify_all();
                entry->space_cv.notify_all();
            }
            for (auto& slot : impl->slots)
                slot->queue.enqueue(std::optional<tile_decode_completion_t>(std::nullopt));
            for (auto& entry : impl->workers) {
                if (entry->lane_handle.valid())
                    rt::cancel(entry->lane_handle);
            }
            join_lanes(*impl, kLaneJoinTimeoutMs);
            ::diag::log_tagged_fmt(kPhase,
                "lane_start_failed worker=%u reason=%s",
                worker->index, submitted.reject_reason.c_str());
            return workspace_result_t<std::unique_ptr<decode_worker_pool_t>>::failure(
                pool_error(workspace_error_code_t::limit_exceeded,
                    "decode worker pool thread creation failed"));
        }
        worker->lane_handle = submitted.handle;
    }
    ::diag::log_tagged_fmt(kPhase,
        "pool_created workers=%u max_queue_depth=%u domain=feature_worker requested=%u fabric_capacity=%u",
        worker_count, impl->max_queue_depth, requested_worker_count, fabric_capacity);
    return workspace_result_t<std::unique_ptr<decode_worker_pool_t>>::success(
        std::unique_ptr<decode_worker_pool_t>(
            new decode_worker_pool_t(std::move(impl))));
}

decode_worker_pool_t::decode_worker_pool_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl))
{
}

decode_worker_pool_t::~decode_worker_pool_t()
{
    namespace rt = aida::infra::taskflow_runtime;
    request_stop();
    for (auto& worker : impl_->workers) {
        if (worker->lane_handle.valid())
            rt::cancel(worker->lane_handle);
    }
    join_lanes(*impl_, kLaneJoinTimeoutMs);
}

void decode_worker_pool_t::bind_snapshot(const provider_snapshot_t& snapshot) noexcept
{
    impl_->snapshot.store(&snapshot, std::memory_order_release);
}

workspace_result_t<void> decode_worker_pool_t::submit(
    std::uint32_t home_worker, decode_work_item_t item)
{
    auto& impl = *impl_;
    const auto worker_count = static_cast<std::uint32_t>(impl.workers.size());
    if (worker_count == 0) {
        return workspace_result_t<void>::failure(
            pool_error(workspace_error_code_t::integrity_failure,
                "decode worker pool has no workers"));
    }
    if (impl.seh_fatal.load(std::memory_order_acquire)) {
        return workspace_result_t<void>::failure(fatal_error());
    }
    impl.active_items.fetch_add(1, std::memory_order_acq_rel);
    const auto home = home_worker % worker_count;
    auto* caller = static_cast<worker_state_t*>(tls_worker_state);
    for (;;) {
        {
            auto& target = *impl.workers[home];
            std::lock_guard<std::mutex> lock(target.mutex);
            if (target.queue.size() < impl.max_queue_depth) {
                target.queue.push_back(std::move(item));
                note_queue_depth(impl, target.queue.size());
                target.cv.notify_one();
                return workspace_result_t<void>::success();
            }
        }
        bool placed = false;
        for (std::uint32_t offset = 1; offset < worker_count && !placed; ++offset) {
            const auto index = (home + offset) % worker_count;
            auto& target = *impl.workers[index];
            std::lock_guard<std::mutex> lock(target.mutex);
            if (target.queue.size() * 2ULL < impl.max_queue_depth) {
                target.queue.push_back(std::move(item));
                note_queue_depth(impl, target.queue.size());
                target.cv.notify_one();
                placed = true;
            }
        }
        if (placed)
            return workspace_result_t<void>::success();
        if (impl.seh_fatal.load(std::memory_order_acquire)) {
            impl.active_items.fetch_sub(1, std::memory_order_acq_rel);
            return workspace_result_t<void>::failure(fatal_error());
        }
        if (impl.stop.load(std::memory_order_acquire) ||
            impl.cancellation.stop_requested()) {
            tile_decode_completion_t completion;
            completion.request_id = item.request.request_id;
            completion.error = pool_cancelled_error();
            push_completion(impl, item.shard_index, std::move(completion));
            return workspace_result_t<void>::success();
        }
        if (caller != nullptr && caller->pool_impl == &impl) {
            decode_work_item_t inline_item;
            if (try_pop_own(*caller, inline_item)) {
                impl.inline_drain_count.fetch_add(1, std::memory_order_relaxed);
                run_item(*caller, impl, std::move(inline_item));
                continue;
            }
        }
        impl.backpressure_wait_count.fetch_add(1, std::memory_order_relaxed);
        auto& target = *impl.workers[home];
        std::unique_lock<std::mutex> lock(target.mutex);
        target.space_cv.wait_for(lock, kBackpressureWakeBackstop, [&] {
            return target.queue.size() < impl.max_queue_depth ||
                impl.stop.load(std::memory_order_acquire) ||
                impl.cancellation.stop_requested() ||
                impl.seh_fatal.load(std::memory_order_acquire);
        });
    }
}

bool decode_worker_pool_t::pop_completion(std::uint32_t shard_slot,
    tile_decode_completion_t& out)
{
    auto& slot = *impl_->slots[
        static_cast<std::size_t>(shard_slot % maximum_shard_slots)];
    std::optional<tile_decode_completion_t> item;
    if (!slot.queue.try_dequeue(item) || !item.has_value())
        return false;
    out = std::move(*item);
    return true;
}

bool decode_worker_pool_t::wait_completion(std::uint32_t shard_slot,
    tile_decode_completion_t& out)
{
    auto& slot = *impl_->slots[
        static_cast<std::size_t>(shard_slot % maximum_shard_slots)];
    std::optional<tile_decode_completion_t> item;
    if (slot.queue.try_dequeue(item)) {
        if (!item.has_value())
            return false;
        out = std::move(*item);
        return true;
    }
    if (impl_->stop.load(std::memory_order_acquire) ||
        impl_->seh_fatal.load(std::memory_order_acquire))
        return false;
    if (!slot.queue.wait_dequeue_timed(item, kCompletionWakeBackstop))
        return false;
    if (!item.has_value())
        return false;
    out = std::move(*item);
    return true;
}

void decode_worker_pool_t::request_stop() noexcept
{
    impl_->stop.store(true, std::memory_order_release);
    for (auto& worker : impl_->workers) {
        worker->cv.notify_all();
        worker->space_cv.notify_all();
    }
    for (auto& slot : impl_->slots)
        slot->queue.enqueue(std::optional<tile_decode_completion_t>(std::nullopt));
    invoke_completion_signal(*impl_);
}

bool decode_worker_pool_t::drained() const noexcept
{
    if (impl_->active_items.load(std::memory_order_acquire) != 0)
        return false;
    for (const auto& worker : impl_->workers) {
        std::lock_guard<std::mutex> lock(worker->mutex);
        if (!worker->queue.empty())
            return false;
    }
    return true;
}

bool decode_worker_pool_t::has_fatal() const noexcept
{
    return impl_->seh_fatal.load(std::memory_order_acquire);
}

workspace_error_t decode_worker_pool_t::fatal_error() const
{
    const auto code = impl_->seh_code.load(std::memory_order_acquire);
    auto error = pool_error(workspace_error_code_t::integrity_failure,
        "decode worker pool worker faulted");
    error.details.emplace_back("exception_code", std::to_string(code));
    error.details.emplace_back("exception_kind",
        code == kCppExceptionFatalCode ? "cxx" : "seh");
    return error;
}

std::uint32_t decode_worker_pool_t::worker_count() const noexcept
{
    return static_cast<std::uint32_t>(impl_->workers.size());
}

void decode_worker_pool_t::set_lease_hook(lease_hook_t hook, void* context) noexcept
{
    {
        std::lock_guard<std::mutex> lock(impl_->callback_mutex);
        impl_->hook_context.store(context, std::memory_order_release);
        impl_->hook.store(hook, std::memory_order_release);
    }
    for (auto& worker : impl_->workers)
        worker->cv.notify_all();
}

void decode_worker_pool_t::clear_lease_hook() noexcept
{
    {
        std::lock_guard<std::mutex> lock(impl_->callback_mutex);
        impl_->hook.store(nullptr, std::memory_order_release);
        impl_->hook_context.store(nullptr, std::memory_order_release);
    }
    const auto started = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(impl_->callback_mutex);
    impl_->callback_cv.wait(lock, [this] {
        return impl_->hook_active.load(std::memory_order_seq_cst) == 0;
    });
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    ::diag::log_tagged_fmt(kPhase,
        "lease_hook_quiescent wait_us=%llu active=%u tid=%lu",
        static_cast<unsigned long long>(elapsed),
        impl_->hook_active.load(std::memory_order_seq_cst),
        static_cast<unsigned long>(GetCurrentThreadId()));
    lock.unlock();
    for (auto& worker : impl_->workers)
        worker->cv.notify_all();
}

void decode_worker_pool_t::set_completion_signal(completion_signal_t signal,
    void* context) noexcept
{
    std::lock_guard<std::mutex> lock(impl_->callback_mutex);
    impl_->completion_signal_context.store(context, std::memory_order_seq_cst);
    impl_->completion_signal.store(signal, std::memory_order_seq_cst);
}

void decode_worker_pool_t::clear_completion_signal() noexcept
{
    {
        std::lock_guard<std::mutex> lock(impl_->callback_mutex);
        impl_->completion_signal.store(nullptr, std::memory_order_seq_cst);
        impl_->completion_signal_context.store(nullptr, std::memory_order_seq_cst);
    }
    const auto started = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(impl_->callback_mutex);
    impl_->callback_cv.wait(lock, [this] {
        return impl_->completion_signal_active.load(std::memory_order_seq_cst) == 0;
    });
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    if (elapsed != 0) {
        ::diag::log_tagged_fmt(kPhase,
            "completion_signal_quiescent wait_us=%llu active=%u tid=%lu",
            static_cast<unsigned long long>(elapsed),
            impl_->completion_signal_active.load(std::memory_order_seq_cst),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
}

decode_worker_pool_statistics_t decode_worker_pool_t::statistics() const noexcept
{
    decode_worker_pool_statistics_t stats;
    stats.completion_push_count =
        impl_->completion_push_count.load(std::memory_order_relaxed);
    stats.steal_count = impl_->steal_count.load(std::memory_order_relaxed);
    stats.backpressure_wait_count =
        impl_->backpressure_wait_count.load(std::memory_order_relaxed);
    stats.inline_drain_count =
        impl_->inline_drain_count.load(std::memory_order_relaxed);
    stats.max_queue_depth_seen =
        impl_->max_queue_depth_seen.load(std::memory_order_relaxed);
    stats.lane_clamp_count =
        impl_->lane_clamp_count.load(std::memory_order_relaxed);
    return stats;
}

}
