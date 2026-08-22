#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../../preview/taskflow_runtime_preview.hpp"

#else

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_MSC_VER) && defined(_MSVC_LANG) && _MSVC_LANG == 201703L
#pragma push_macro("__has_include")
#undef __has_include
#define __has_include(...) 0
#define AIDA_TASKFLOW_RESTORE_HAS_INCLUDE 1
#endif
#include <taskflow/taskflow.hpp>
#if defined(AIDA_TASKFLOW_RESTORE_HAS_INCLUDE)
#undef AIDA_TASKFLOW_RESTORE_HAS_INCLUDE
#pragma pop_macro("__has_include")
#endif
#if !defined(TF_VERSION) || TF_VERSION != 301100
#error Taskflow_version_mismatch
#endif

#include "../diagnostics/metadata_ring.hpp"
#include "../../helpers/diag_log.hpp"
#include "allocator.hpp"
#include "host_topology.hpp"
#include "win_thread.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::infra::taskflow_runtime {

enum class pool_family_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2
};

enum class executor_domain_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2,
    ui_dispatch = 3,
    external_tool = 4,
    long_running = 5,
    security_liveness = 6,
    feature_worker = 7,
    diagnostics = 8
};

inline constexpr std::size_t executor_domain_count = 9;

enum class job_state_t : std::uint8_t {
    queued = 0,
    not_started = 1,
    running = 2,
    completed = 3,
    cancelled = 4,
    failed = 5,
    timed_out = 6
};

struct cancellation_token_t {
    std::atomic<bool> requested{false};
};

struct job_handle_t {
    std::uint64_t id = 0;
    bool valid() const noexcept { return id != 0; }
};

struct task_descriptor_t {
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
    std::function<void()> cancel_hook;
    executor_domain_t domain = executor_domain_t::general;
    std::string owner_subsystem;
    std::string label;
    std::string thread_class;
    std::string session_id;
    std::string target_id;
    std::string diagnostic_id;
    std::string request_id;
    std::string ui_access_policy = "none";
    std::string failure_policy = "reject_not_started";
    std::string shutdown_policy = "drain";
    std::string no_capacity_reason;
    int priority = 3;
    std::uint32_t target_pid = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
};

struct graph_node_descriptor_t {
    std::uint64_t node_id = 0;
    std::string label;
    std::vector<std::uint64_t> depends_on;
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
};

struct graph_descriptor_t {
    executor_domain_t domain = executor_domain_t::general;
    std::string owner_subsystem;
    std::string label;
    std::string phase;
    std::string session_id;
    std::string target_id;
    std::string diagnostic_id;
    std::string request_id;
    std::function<void()> cancel_hook;
    int priority = 3;
    std::uint32_t target_pid = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t generation = 0;
    std::vector<graph_node_descriptor_t> nodes;
};

struct submit_result_t {
    bool submitted = false;
    job_handle_t handle;
    std::string reject_reason;
};

struct wait_result_t {
    bool completed = false;
    bool timed_out = false;
    bool rejected = false;
    bool cancelled = false;
    bool failed = false;
};

struct task_t {
    std::function<void()> fn;
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
};

struct active_task_t {
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t last_cpu_100ns = 0;
    std::uint64_t last_cpu_sample_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    DWORD thread_query_gle = 0;
    DWORD exit_code = 0;
    DWORD tid = 0;
    bool thread_alive = false;
};

struct stats_t {
    bool alive = false;
    bool shutting_down = false;
    int pool_size = 0;
    std::size_t workers = 0;
    std::size_t pending = 0;
    std::uint32_t active = 0;
    std::uint64_t post_attempts = 0;
    std::uint64_t posted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t started = 0;
    std::uint64_t finished = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t failed = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t oldest_active_ms = 0;
    std::uint64_t lane_in_flight = 0;
    std::uint64_t fairness_wait_ns_total = 0;
    std::uint64_t lane_depth[8] = {};
    std::uint64_t lane_admitted[8] = {};
    std::uint32_t active_label_count = 0;
    std::uint32_t healthy_long_lived = 0;
    std::uint32_t hot_workers = 0;
    std::uint32_t not_queryable_workers = 0;
    std::string active_labels;
    std::string top_cpu_labels;
};

struct stuck_worker_diag_t {
    std::uint64_t task_id = 0;
    std::string label;
    const char* label_class = "general";
    const char* lifetime = "bounded_task";
    const char* health = "needs_progress";
    DWORD tid = 0;
    DWORD thread_query_gle = 0;
    DWORD exit_code = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t active_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    std::size_t worker_index = 0;
    bool thread_alive = false;
};

struct active_job_snapshot_t {
    std::uint64_t job_id = 0;
    executor_domain_t domain = executor_domain_t::general;
    job_state_t state = job_state_t::queued;
    std::string label;
    std::string owner_subsystem;
    std::string exception_text;
    std::string target_id;
    int priority = 3;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    std::uint64_t queued_ns = 0;
    std::uint64_t started_ns = 0;
    std::uint64_t fairness_wait_ns = 0;
    std::uint64_t service_units = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    std::uint64_t active_ms = 0;
    std::uint32_t node_count = 0;
    bool graph = false;
    bool cancellation_requested = false;
};

struct runtime_snapshot_t {
    std::uint64_t total_submitted = 0;
    std::uint64_t total_rejected = 0;
    std::uint64_t total_cancelled = 0;
    std::uint64_t total_failed = 0;
    std::uint64_t total_timed_out = 0;
    std::uint32_t total_active = 0;
    std::uint32_t active_per_domain[executor_domain_count] = {};
    std::uint64_t oldest_active_ms = 0;
    std::uint64_t work_queue_pending = 0;
    std::uint64_t service_queue_pending = 0;
    std::uint64_t critical_queue_pending = 0;
    std::uint32_t work_queue_active = 0;
    std::uint32_t service_queue_active = 0;
    std::uint32_t critical_queue_active = 0;
    bool accepting = true;
    bool shutting_down = false;
    std::string labels_under_pressure;
    std::vector<active_job_snapshot_t> active_jobs;
};

struct pool_t;
struct job_record_t;

class worker_interface_t final : public tf::WorkerInterface {
public:
    explicit worker_interface_t(pool_t* pool) noexcept : pool_(pool) {}
    void scheduler_prologue(tf::Worker& worker) override;
    void scheduler_epilogue(tf::Worker& worker, std::exception_ptr ptr) override;

private:
    pool_t* pool_ = nullptr;
};

struct pool_t {
    const char* pool_name = nullptr;
    const char* log_tag = nullptr;
    const char* default_label = nullptr;
    pool_family_t family = pool_family_t::general;
    int configured_pool_size = 0;
    std::shared_ptr<tf::Executor> executor;
    std::mutex executor_mtx;
    std::vector<active_task_t> active_snapshots;
    std::mutex mtx;
    std::atomic<bool> alive{false};
    std::atomic<bool> shutting_down{false};
    std::atomic<bool> shutdown_called{false};
    std::atomic<bool> shutdown_in_progress{false};
    std::atomic<bool> stop_accepting{false};
    std::atomic<std::uint32_t> active_tasks{0};
    std::atomic<std::uint64_t> pending_tasks{0};
    std::atomic<std::uint64_t> post_attempts{0};
    std::atomic<std::uint64_t> posted_tasks{0};
    std::atomic<std::uint64_t> rejected_tasks{0};
    std::atomic<std::uint64_t> started_tasks{0};
    std::atomic<std::uint64_t> finished_tasks{0};
    std::atomic<std::uint64_t> cancelled_tasks{0};
    std::atomic<std::uint64_t> failed_tasks{0};
    std::atomic<std::uint64_t> timed_out_tasks{0};
    std::atomic<std::uint64_t> next_task_id{0};
    std::atomic<std::size_t> worker_count{0};
    std::vector<std::shared_ptr<job_record_t>> admission_queue;
    std::unordered_map<std::string, std::size_t> admitted_targets;
    std::unordered_map<std::string, std::uint64_t> target_pending_nodes;
    std::uint64_t admission_sequence = 0;
    std::uint64_t deferred_nodes = 0;
    std::size_t admitted_jobs = 0;
    std::size_t pending_capacity = 0;
    std::size_t per_target_pending_capacity = 0;
    std::size_t admission_capacity = 0;
    std::array<std::deque<std::shared_ptr<job_record_t>>, 8> priority_lanes;
    std::array<std::uint64_t, 8> lane_depth{};
    std::array<std::uint64_t, 8> lane_dispatched{};
    std::uint64_t lane_in_flight = 0;
    std::atomic<std::uint64_t> fairness_wait_ns_total{0};
    std::atomic<bool> priority_elevated{false};
    std::atomic<std::uint32_t> priority_generation{0};
    std::atomic<std::uint64_t> last_pressure_ms{0};
    std::array<std::atomic<std::uint64_t>, 1024> fairness_wait_ns_ring;
    std::atomic<std::uint32_t> fairness_wait_ns_ring_next{0};

    pool_t(const char* pool_name_in, const char* log_tag_in, const char* default_label_in, pool_family_t family_in, int configured_pool_size_in) noexcept
        : pool_name(pool_name_in),
          log_tag(log_tag_in),
          default_label(default_label_in),
          family(family_in),
          configured_pool_size(configured_pool_size_in) {
        for (auto& slot : fairness_wait_ns_ring)
            slot.store(0u, std::memory_order_relaxed);
    }
};

struct graph_node_record_t {
    std::uint64_t node_id = 0;
    std::uint64_t active_id = 0;
    std::string label;
    std::vector<std::uint64_t> depends_on;
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
    job_state_t state = job_state_t::queued;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    std::string exception_text;
};

struct job_record_t {
    std::uint64_t id = 0;
    executor_domain_t domain = executor_domain_t::general;
    pool_t* pool = nullptr;
    std::string owner_subsystem;
    std::string label;
    std::string thread_class;
    std::string session_id;
    std::string target_id;
    std::string diagnostic_id;
    std::string request_id;
    std::string phase;
    std::string ui_access_policy;
    std::string failure_policy;
    std::string shutdown_policy;
    std::string no_capacity_reason;
    int priority = 3;
    std::uint32_t target_pid = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    std::uint64_t queued_ns = 0;
    std::uint64_t started_ns = 0;
    std::uint64_t fairness_wait_ns = 0;
    std::uint64_t service_units = 0;
    std::uint64_t admission_sequence = 0;
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
    std::function<void()> cancel_hook;
    std::shared_ptr<cancellation_token_t> cancel_token;
    std::shared_ptr<tf::Taskflow> pending_flow;
    std::shared_ptr<tf::Semaphore> target_semaphore;
    tf::Future<void> future;
    bool has_future = false;
    bool graph = false;
    std::atomic<bool> admission_pending{false};
    bool admitted = false;
    std::atomic<bool> active{true};
    bool deadline_reported = false;
    bool cancel_hook_invoked = false;
    bool cancellation_accounted = false;
    std::atomic<bool> finalized{false};
    std::atomic<bool> target_reserved{false};
    std::uint64_t pending_units = 0;
    job_state_t state = job_state_t::queued;
    std::string exception_text;
    std::vector<graph_node_record_t> nodes;
    mutable std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> fabric_lane_queued{false};
    std::atomic<bool> fabric_lane_dispatched{false};
};

inline void pump_lanes(pool_t& p);
inline bool remove_record_from_lane(pool_t& p, const std::shared_ptr<job_record_t>& record);
inline void ensure_deadline_sweeper_started() noexcept;
inline void check_deadlines();
inline bool mark_record_finalized(const std::shared_ptr<job_record_t>& record,
    job_state_t final_state, const std::string& exception_text);

inline std::atomic<std::uint64_t> g_next_job_id{0};
inline std::atomic<std::uint64_t> g_total_submitted{0};
inline std::atomic<std::uint64_t> g_total_rejected{0};
inline std::atomic<std::uint64_t> g_total_cancelled{0};
inline std::atomic<std::uint64_t> g_total_failed{0};
inline std::atomic<std::uint64_t> g_total_timed_out{0};
inline std::atomic<bool> g_stop_accepting{false};
inline std::atomic<bool> g_shutdown_requested{false};
inline std::mutex& g_jobs_mtx = *new std::mutex;
inline std::map<std::uint64_t, std::shared_ptr<job_record_t>>& g_jobs =
    *new std::map<std::uint64_t, std::shared_ptr<job_record_t>>;
inline std::mutex& g_pool_registry_mtx = *new std::mutex;
inline std::vector<pool_t*>& g_registered_pools = *new std::vector<pool_t*>;

inline const char* safe_pool_name(const pool_t& p) {
    return p.pool_name && *p.pool_name ? p.pool_name : "<unnamed>";
}

inline std::shared_ptr<tf::Executor> load_executor(pool_t& p) {
    std::lock_guard<std::mutex> lk(p.executor_mtx);
    return p.executor;
}

inline void store_executor(pool_t& p, std::shared_ptr<tf::Executor> executor) {
    std::lock_guard<std::mutex> lk(p.executor_mtx);
    p.executor = std::move(executor);
}

inline const char* safe_log_tag(const pool_t& p) {
    return p.log_tag && *p.log_tag ? p.log_tag : "taskflow_runtime";
}

inline const char* domain_name(executor_domain_t d) {
    switch (d) {
    case executor_domain_t::general: return "general";
    case executor_domain_t::service: return "service";
    case executor_domain_t::critical: return "critical";
    case executor_domain_t::ui_dispatch: return "ui_dispatch";
    case executor_domain_t::external_tool: return "external_tool";
    case executor_domain_t::long_running: return "long_running";
    case executor_domain_t::security_liveness: return "security_liveness";
    case executor_domain_t::feature_worker: return "feature_worker";
    case executor_domain_t::diagnostics: return "diagnostics";
    default: return "unknown";
    }
}

inline const char* job_state_name(job_state_t s) {
    switch (s) {
    case job_state_t::queued: return "queued";
    case job_state_t::not_started: return "not_started";
    case job_state_t::running: return "running";
    case job_state_t::completed: return "completed";
    case job_state_t::cancelled: return "cancelled";
    case job_state_t::failed: return "failed";
    case job_state_t::timed_out: return "timed_out";
    default: return "unknown";
    }
}

inline std::size_t domain_index(executor_domain_t d) {
    return static_cast<std::size_t>(d);
}

inline bool terminal_state(job_state_t s) {
    return s == job_state_t::completed || s == job_state_t::cancelled || s == job_state_t::failed || s == job_state_t::timed_out;
}

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

inline std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<
        std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct hot_log_gate_t {
    std::atomic<std::uint64_t> total{0};
    std::atomic<std::uint64_t> suppressed{0};
    std::atomic<std::uint64_t> last_emit_ms{0};
};

inline bool fabric_log_verbose() noexcept {
    static const bool verbose = diag::env_flag_enabled("AIDA_FABRIC_LOG_VERBOSE");
    return verbose;
}

inline hot_log_gate_t& hot_log_gate_for(const char* key) noexcept {
    struct slot_t {
        std::atomic<const char*> key{nullptr};
        hot_log_gate_t gate;
    };
    static slot_t slots[16];
    const char* wanted = key && *key ? key : "default";
    for (std::size_t i = 0; i < 16; ++i) {
        const char* expected = nullptr;
        if (slots[i].key.compare_exchange_strong(expected, wanted,
                std::memory_order_acq_rel, std::memory_order_acquire))
            return slots[i].gate;
        if (expected != nullptr && std::strcmp(expected, wanted) == 0)
            return slots[i].gate;
    }
    return slots[15].gate;
}

inline bool hot_log_should_emit(hot_log_gate_t& gate, std::uint64_t& out_suppressed) noexcept {
    const std::uint64_t total = gate.total.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    const std::uint64_t now = now_ms();
    if (total == 1u) {
        gate.last_emit_ms.store(now, std::memory_order_release);
        out_suppressed = 0u;
        return true;
    }
    const std::uint64_t last = gate.last_emit_ms.load(std::memory_order_acquire);
    const bool count_hit = gate.suppressed.load(std::memory_order_acquire) >= 511u;
    const bool time_hit = now < last || now - last >= 2000u;
    if (count_hit || time_hit) {
        out_suppressed = gate.suppressed.exchange(0u, std::memory_order_acq_rel);
        gate.last_emit_ms.store(now, std::memory_order_release);
        return true;
    }
    gate.suppressed.fetch_add(1u, std::memory_order_acq_rel);
    out_suppressed = 0u;
    return false;
}

inline std::uint64_t hot_log_gate_total(const hot_log_gate_t& gate) noexcept {
    return gate.total.load(std::memory_order_acquire);
}

inline int normalized_priority(int priority) {
    return (std::max)(0, (std::min)(7, priority));
}

inline std::string admission_target_key(const job_record_t& record) {
    if (!record.target_id.empty())
        return "target:" + record.target_id;
    if (record.target_pid != 0)
        return "pid:" + std::to_string(record.target_pid);
    if (!record.session_id.empty())
        return "session:" + record.session_id;
    return "owner:" + record.owner_subsystem;
}

inline int clamp_pool_size(unsigned value, unsigned low, unsigned high) {
    if (value < low)
        value = low;
    if (value > high)
        value = high;
    return static_cast<int>(value);
}

inline unsigned host_worker_count(unsigned fallback) {
    const DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n == 0 ? fallback : static_cast<unsigned>(n);
}

inline unsigned fabric_host_worker_count() {
    const unsigned count = host_worker_count(4u);
    return count < 4u ? 4u : count;
}

inline int feature_worker_pool_size() {
    return clamp_pool_size(host_topology::recommended_compute_threads(), 2u, 48u);
}

inline int general_pool_size() {
    return clamp_pool_size((fabric_host_worker_count() + 3u) / 4u, 4u, 16u);
}

inline int service_pool_size() {
    return clamp_pool_size(fabric_host_worker_count() / 2u, 4u, 16u);
}

inline int critical_pool_size() {
    return clamp_pool_size(fabric_host_worker_count() / 4u, 4u, 12u);
}

inline int ui_dispatch_pool_size() {
    return clamp_pool_size(fabric_host_worker_count() / 4u, 2u, 8u);
}

inline int external_tool_pool_size() {
    return clamp_pool_size((fabric_host_worker_count() + 3u) / 4u, 4u, 16u);
}

inline int long_running_pool_size() {
    return clamp_pool_size(fabric_host_worker_count() / 4u, 4u, 16u);
}

inline int diagnostics_pool_size() {
    return clamp_pool_size(fabric_host_worker_count() / 4u, 2u, 8u);
}

inline void register_pool(pool_t& p) {
    std::lock_guard<std::mutex> lk(g_pool_registry_mtx);
    if (std::find(g_registered_pools.begin(), g_registered_pools.end(), &p) == g_registered_pools.end())
        g_registered_pools.push_back(&p);
}

inline pool_t& domain_pool(executor_domain_t d) {
    static pool_t& general = *new pool_t{"runtime.general", "taskflow_runtime", "runtime.general", pool_family_t::general, general_pool_size()};
    static pool_t& service = *new pool_t{"runtime.service", "taskflow_runtime", "runtime.service", pool_family_t::service, service_pool_size()};
    static pool_t& critical = *new pool_t{"runtime.critical", "taskflow_runtime", "runtime.critical", pool_family_t::critical, critical_pool_size()};
    static pool_t& ui_dispatch = *new pool_t{"runtime.ui_dispatch", "taskflow_runtime", "runtime.ui_dispatch", pool_family_t::general, ui_dispatch_pool_size()};
    static pool_t& external_tool = *new pool_t{"runtime.external_tool", "taskflow_runtime", "runtime.external_tool", pool_family_t::general, external_tool_pool_size()};
    static pool_t& long_running = *new pool_t{"runtime.long_running", "taskflow_runtime", "runtime.long_running", pool_family_t::service, long_running_pool_size()};
    static pool_t& security_liveness = *new pool_t{"runtime.security_liveness", "taskflow_runtime", "runtime.security_liveness", pool_family_t::critical, 8};
    static pool_t& feature_worker = *new pool_t{"runtime.feature_worker", "taskflow_runtime", "runtime.feature_worker", pool_family_t::general, feature_worker_pool_size()};
    static pool_t& diagnostics = *new pool_t{"runtime.diagnostics", "taskflow_runtime", "runtime.diagnostics", pool_family_t::general, diagnostics_pool_size()};
    switch (d) {
    case executor_domain_t::service: return service;
    case executor_domain_t::critical: return critical;
    case executor_domain_t::ui_dispatch: return ui_dispatch;
    case executor_domain_t::external_tool: return external_tool;
    case executor_domain_t::long_running: return long_running;
    case executor_domain_t::security_liveness: return security_liveness;
    case executor_domain_t::feature_worker: return feature_worker;
    case executor_domain_t::diagnostics: return diagnostics;
    case executor_domain_t::general:
    default:
        return general;
    }
}

inline bool below_normal_priority_pool(const pool_t& p) {
    return &p == &domain_pool(executor_domain_t::feature_worker) ||
           &p == &domain_pool(executor_domain_t::external_tool) ||
           &p == &domain_pool(executor_domain_t::long_running);
}

inline constexpr std::uint64_t kPoolPriorityQuiescentMs = 2000;

inline std::uint32_t& pool_priority_tls_generation() noexcept {
    static thread_local std::uint32_t generation = 0;
    return generation;
}

inline void evaluate_pool_priority(pool_t& p) noexcept {
    if (!below_normal_priority_pool(p))
        return;
    const std::uint64_t workers =
        static_cast<std::uint64_t>(p.worker_count.load(std::memory_order_acquire));
    if (workers == 0)
        return;
    const std::uint64_t active =
        static_cast<std::uint64_t>(p.active_tasks.load(std::memory_order_acquire));
    const std::uint64_t pending = p.pending_tasks.load(std::memory_order_acquire);
    const std::uint64_t now = now_ms();
    if (active >= workers && pending != 0) {
        p.last_pressure_ms.store(now, std::memory_order_release);
        bool expected = false;
        if (p.priority_elevated.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel, std::memory_order_acquire))
            p.priority_generation.fetch_add(1u, std::memory_order_acq_rel);
        return;
    }
    const std::uint64_t last = p.last_pressure_ms.load(std::memory_order_acquire);
    if (now < last || now - last < kPoolPriorityQuiescentMs)
        return;
    bool expected = true;
    if (p.priority_elevated.compare_exchange_strong(expected, false,
            std::memory_order_acq_rel, std::memory_order_acquire))
        p.priority_generation.fetch_add(1u, std::memory_order_acq_rel);
}

inline void apply_pool_priority_from_worker(pool_t& p) noexcept {
    if (!below_normal_priority_pool(p))
        return;
    const std::uint32_t generation = p.priority_generation.load(std::memory_order_acquire);
    if (pool_priority_tls_generation() == generation)
        return;
    pool_priority_tls_generation() = generation;
    const bool elevated = p.priority_elevated.load(std::memory_order_acquire);
    SetThreadPriority(GetCurrentThread(),
        elevated ? THREAD_PRIORITY_NORMAL : THREAD_PRIORITY_BELOW_NORMAL);
    diag::log_tagged_fmt(safe_log_tag(p),
        "fabric_pool_priority pool=%s tid=%lu level=%s generation=%u",
        safe_pool_name(p),
        static_cast<unsigned long>(GetCurrentThreadId()),
        elevated ? "normal" : "below_normal",
        static_cast<unsigned>(generation));
}

inline std::uint64_t filetime_to_100ns(const FILETIME& ft)
{
    ULARGE_INTEGER v{};
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    return v.QuadPart;
}

inline bool sample_thread_cpu_100ns(DWORD tid, std::uint64_t& cpu_100ns, DWORD& gle, DWORD& exit_code)
{
    cpu_100ns = 0;
    gle = 0;
    exit_code = 0;
    if (tid == 0) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }
    HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!th) {
        gle = GetLastError();
        return false;
    }
    FILETIME create_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    SetLastError(0);
    const BOOL exit_ok = GetExitCodeThread(th, &exit_code);
    const DWORD exit_gle = exit_ok ? 0UL : GetLastError();
    SetLastError(0);
    const BOOL times_ok = GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time);
    gle = times_ok ? 0UL : GetLastError();
    CloseHandle(th);
    if (!exit_ok) {
        gle = exit_gle;
        return false;
    }
    if (!times_ok)
        return false;
    cpu_100ns = filetime_to_100ns(kernel_time) + filetime_to_100ns(user_time);
    return exit_code == STILL_ACTIVE;
}

inline const char* classify_worker_label(const std::string& label, const char* default_class) {
    if (label.find("full_test") != std::string::npos || label.find("test_all") != std::string::npos)
        return "full_test";
    if (label.find("heartbeat") != std::string::npos)
        return "heartbeat";
    if (label.find("mcp") != std::string::npos || label.find("http") != std::string::npos || label.find("sse") != std::string::npos)
        return "mcp_or_http";
    if (label.find("camoufox") != std::string::npos || label.find("browser") != std::string::npos)
        return "camoufox";
    if (label.find("driver") != std::string::npos || label.find("kernel") != std::string::npos || label.find("tctx") != std::string::npos)
        return "driver";
    if (label.find("scanner") != std::string::npos || label.find("scan") != std::string::npos)
        return "scanner";
    if (label.find("ui") != std::string::npos || label.find("render") != std::string::npos || label.find("dialog") != std::string::npos)
        return "ui_adjacent";
    if (label.find("service") != std::string::npos || label.find("listener") != std::string::npos || label.find("watch") != std::string::npos)
        return "long_lived_service";
    return default_class && *default_class ? default_class : "general";
}

inline bool worker_label_long_lived_hint(const char* label_class) {
    return label_class &&
        (std::strcmp(label_class, "heartbeat") == 0 ||
         std::strcmp(label_class, "mcp_or_http") == 0 ||
         std::strcmp(label_class, "camoufox") == 0 ||
         std::strcmp(label_class, "driver") == 0 ||
         std::strcmp(label_class, "long_lived_service") == 0);
}

inline const char* worker_lifetime_label(pool_family_t family, const char* pool_name, const char* label_class)
{
    if (family == pool_family_t::critical)
        return worker_label_long_lived_hint(label_class) ? "long_lived_critical" : "bounded_critical";
    const bool service_pool = (family == pool_family_t::service) || (pool_name && std::strcmp(pool_name, "service") == 0);
    if (service_pool && worker_label_long_lived_hint(label_class))
        return "intentional_service";
    if (service_pool)
        return "service_task";
    if (worker_label_long_lived_hint(label_class))
        return "long_lived_hint";
    return "bounded_task";
}

inline const char* worker_health_label(pool_family_t family, const char* lifetime, bool thread_alive, std::uint32_t cpu_pct_x100, std::size_t pending, bool shutting_down)
{
    if (!thread_alive)
        return "thread_not_queryable";
    if (shutting_down)
        return "shutdown_waiting";
    if (cpu_pct_x100 >= 2500)
        return "hot_cpu";
    if (family == pool_family_t::critical) {
        if (lifetime && std::strcmp(lifetime, "long_lived_critical") == 0 && pending == 0)
            return "healthy_long_lived";
        if (lifetime && std::strcmp(lifetime, "long_lived_critical") == 0)
            return "critical_backlog";
    } else {
        if (lifetime && std::strcmp(lifetime, "intentional_service") == 0 && pending == 0)
            return "healthy_long_lived";
        if (lifetime && std::strcmp(lifetime, "intentional_service") == 0)
            return "service_backlog";
    }
    return "needs_progress";
}

inline void refresh_active_thread_sample(active_task_t& active, std::uint64_t now)
{
    std::uint64_t cpu_100ns = 0;
    DWORD gle = 0;
    DWORD exit_code = 0;
    const bool alive = sample_thread_cpu_100ns(active.tid, cpu_100ns, gle, exit_code);
    active.thread_query_gle = gle;
    active.exit_code = exit_code;
    active.thread_alive = alive;
    if (active.last_cpu_sample_ms != 0 && now > active.last_cpu_sample_ms && cpu_100ns >= active.last_cpu_100ns) {
        active.cpu_delta_100ns = cpu_100ns - active.last_cpu_100ns;
        const std::uint64_t wall_100ns = (now - active.last_cpu_sample_ms) * 10000ULL;
        active.cpu_pct_x100 = wall_100ns != 0 ? static_cast<std::uint32_t>((active.cpu_delta_100ns * 10000ULL) / wall_100ns) : 0U;
        if (active.cpu_pct_x100 > 10000U)
            active.cpu_pct_x100 = 10000U;
    } else {
        active.cpu_delta_100ns = 0;
        active.cpu_pct_x100 = 0;
    }
    active.last_cpu_100ns = cpu_100ns;
    active.last_cpu_sample_ms = now;
}

inline const char* default_class_for(pool_family_t family) {
    return family == pool_family_t::critical ? "critical" : "general";
}

inline void decrement_atomic_if_nonzero(std::atomic<std::uint64_t>& value) {
    std::uint64_t current = value.load(std::memory_order_acquire);
    while (current != 0 &&
           !value.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
    }
}

inline std::size_t resolve_worker_index(tf::Executor* executor) {
    if (!executor)
        return (std::numeric_limits<std::size_t>::max)();
    const int id = executor->this_worker_id();
    if (id < 0)
        return (std::numeric_limits<std::size_t>::max)();
    return static_cast<std::size_t>(id);
}

inline void worker_interface_t::scheduler_prologue(tf::Worker& worker) {
    pool_t* p = pool_;
    if (!p)
        return;
    if (below_normal_priority_pool(*p)) {
        const bool elevated = p->priority_elevated.load(std::memory_order_acquire);
        SetThreadPriority(GetCurrentThread(),
            elevated ? THREAD_PRIORITY_NORMAL : THREAD_PRIORITY_BELOW_NORMAL);
        pool_priority_tls_generation() = p->priority_generation.load(std::memory_order_acquire);
    }
}

inline void worker_interface_t::scheduler_epilogue(tf::Worker& worker, std::exception_ptr ptr) {
    pool_t* p = pool_;
    if (!p)
        return;
    if (ptr) {
        try {
            std::rethrow_exception(ptr);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt(safe_log_tag(*p),
                "taskflow_worker_scheduler_exception pool=%s worker_id=%zu tid=%lu err=%s",
                safe_pool_name(*p),
                worker.id(),
                static_cast<unsigned long>(GetCurrentThreadId()),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt(safe_log_tag(*p),
                "taskflow_worker_scheduler_exception pool=%s worker_id=%zu tid=%lu err=unknown",
                safe_pool_name(*p),
                worker.id(),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    }
}

inline void initialize_pool(pool_t& p, int pool_size) {
    register_pool(p);
    if (pool_size <= 0 || p.shutdown_called.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire))
        return;
    bool expected = false;
    if (!p.alive.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    std::lock_guard<std::mutex> lk(p.mtx);
    if (p.shutdown_called.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) {
        p.alive.store(false, std::memory_order_release);
        return;
    }
    try {
        p.configured_pool_size = pool_size;
        const auto workers = static_cast<std::size_t>(pool_size);
        p.pending_capacity = (std::max<std::size_t>)(4096, workers * 4096);
        p.per_target_pending_capacity =
            (std::max<std::size_t>)(1024, p.pending_capacity / 2);
        p.admission_capacity = (std::max<std::size_t>)(1, workers);
        p.admission_queue.clear();
        p.admitted_targets.clear();
        p.target_pending_nodes.clear();
        p.deferred_nodes = 0;
        p.admitted_jobs = 0;
        for (auto& lane : p.priority_lanes)
            lane.clear();
        p.lane_depth.fill(0);
        p.lane_dispatched.fill(0);
        p.lane_in_flight = 0;
        p.active_snapshots.assign(static_cast<std::size_t>(pool_size), {});
        store_executor(p, std::make_shared<tf::Executor>(static_cast<std::size_t>(pool_size), std::unique_ptr<tf::WorkerInterface>(new worker_interface_t(&p))));
        const auto executor = load_executor(p);
        p.worker_count.store(executor ? executor->num_workers() : 0, std::memory_order_release);
        p.stop_accepting.store(false, std::memory_order_release);
        allocator::initialize();
        host_topology::log_topology_once();
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_pool_started pool=%s workers=%zu configured_pool_size=%d tf_version=%d tid=%lu",
            safe_pool_name(p),
            p.worker_count.load(std::memory_order_acquire),
            pool_size,
            TF_VERSION,
            static_cast<unsigned long>(GetCurrentThreadId()));
        diag::log_tagged_fmt(safe_log_tag(p),
            "fabric_pool_sized pool=%s host=%u workers=%zu pending_capacity=%zu per_target_pending_capacity=%zu admission_capacity=%zu topology_logical=%u topology_compute=%u tid=%lu",
            safe_pool_name(p),
            static_cast<unsigned>(fabric_host_worker_count()),
            p.worker_count.load(std::memory_order_acquire),
            static_cast<unsigned long long>(p.pending_capacity),
            static_cast<unsigned long long>(p.per_target_pending_capacity),
            static_cast<unsigned long long>(p.admission_capacity),
            static_cast<unsigned>(host_topology::current().logical_cores),
            static_cast<unsigned>(host_topology::recommended_compute_threads()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (below_normal_priority_pool(p)) {
            diag::log_tagged_fmt(safe_log_tag(p),
                "taskflow_pool_thread_priority pool=%s workers=%zu priority=below_normal tid=%lu",
                safe_pool_name(p),
                p.worker_count.load(std::memory_order_acquire),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    } catch (const std::exception& ex) {
        store_executor(p, {});
        p.active_snapshots.clear();
        p.worker_count.store(0, std::memory_order_release);
        p.alive.store(false, std::memory_order_release);
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_pool_start_failed pool=%s configured_pool_size=%d err=%s tid=%lu",
            safe_pool_name(p),
            pool_size,
            ex.what(),
            static_cast<unsigned long>(GetCurrentThreadId()));
    } catch (...) {
        store_executor(p, {});
        p.active_snapshots.clear();
        p.worker_count.store(0, std::memory_order_release);
        p.alive.store(false, std::memory_order_release);
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_pool_start_failed pool=%s configured_pool_size=%d err=unknown tid=%lu",
            safe_pool_name(p),
            pool_size,
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
}

inline void initialize() {
    for (std::size_t i = 0; i < executor_domain_count; ++i) {
        pool_t& p = domain_pool(static_cast<executor_domain_t>(i));
        initialize_pool(p, p.configured_pool_size);
    }
    ensure_deadline_sweeper_started();
}

inline bool mark_record_finalized(const std::shared_ptr<job_record_t>& record,
    job_state_t final_state, const std::string& exception_text) {
    if (!record)
        return false;
    std::lock_guard<std::mutex> lk(record->mtx);
    if (record->finalized)
        return false;
    record->finalized = true;
    if (record->finished_ms == 0)
        record->finished_ms = now_ms();
    if (!exception_text.empty())
        record->exception_text = exception_text;
    if (record->state != job_state_t::timed_out && record->state != job_state_t::failed && record->state != job_state_t::cancelled)
        record->state = final_state;
    record->active = false;
    record->cv.notify_all();
    return true;
}

inline void complete_not_started_record(const std::shared_ptr<job_record_t>& record) {
    if (!record)
        return;
    pool_t* p = record->pool;
    bool adjust_pending = false;
    job_state_t final_state = job_state_t::completed;
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        if (record->started_ms != 0 || !record->active || record->finalized)
            return;
        adjust_pending = true;
        if (record->state == job_state_t::timed_out) {
            final_state = job_state_t::timed_out;
        } else if (record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire)) {
            final_state = job_state_t::cancelled;
        }
    }
    if (!mark_record_finalized(record, final_state, {}))
        return;
    if (p && adjust_pending) {
        const auto units = record->pending_units == 0 ? 1u : record->pending_units;
        for (std::uint64_t i = 0; i < units; ++i)
            decrement_atomic_if_nonzero(p->pending_tasks);
    }
    if (p) {
        p->finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
        if (final_state == job_state_t::cancelled)
            p->cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
        if (final_state == job_state_t::timed_out)
            p->timed_out_tasks.fetch_add(1u, std::memory_order_acq_rel);
    }
    if (p && record->fabric_lane_dispatched.exchange(false, std::memory_order_acq_rel)) {
        {
            std::lock_guard<std::mutex> lk(p->mtx);
            if (p->lane_in_flight != 0)
                --p->lane_in_flight;
        }
        pump_lanes(*p);
    }
}

inline bool start_record(const std::shared_ptr<job_record_t>& record, std::uint64_t active_id, const std::string& active_label) {
    pool_t* p = record ? record->pool : nullptr;
    if (!record || !p)
        return false;
    apply_pool_priority_from_worker(*p);
    const std::uint64_t start = now_ms();
    const std::uint64_t start_ns = now_ns();
    std::uint64_t fairness_wait_ns = 0;
    bool fairness_recorded = false;
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        if (record->finalized || !record->active)
            return false;
        p->active_tasks.fetch_add(1u, std::memory_order_acq_rel);
        p->started_tasks.fetch_add(1u, std::memory_order_acq_rel);
        decrement_atomic_if_nonzero(p->pending_tasks);
        if (record->started_ms == 0) {
            record->started_ms = start;
            record->started_ns = start_ns;
            record->fairness_wait_ns = start_ns >= record->queued_ns
                ? start_ns - record->queued_ns : 0;
            fairness_wait_ns = record->fairness_wait_ns;
            fairness_recorded = true;
        }
        if (record->state == job_state_t::queued || record->state == job_state_t::not_started)
            record->state = job_state_t::running;
    }
    if (fairness_recorded) {
        p->fairness_wait_ns_total.fetch_add(fairness_wait_ns, std::memory_order_acq_rel);
        const std::uint32_t ring_slot =
            p->fairness_wait_ns_ring_next.fetch_add(1u, std::memory_order_acq_rel);
        p->fairness_wait_ns_ring[ring_slot & 1023u].store(fairness_wait_ns, std::memory_order_release);
    }
    const DWORD tid = GetCurrentThreadId();
    std::shared_ptr<tf::Executor> executor;
    {
        std::lock_guard<std::mutex> lk(p->mtx);
        executor = load_executor(*p);
    }
    const std::size_t worker_index = resolve_worker_index(executor.get());
    {
        std::lock_guard<std::mutex> lk(p->mtx);
        if (worker_index < p->active_snapshots.size()) {
            auto& active = p->active_snapshots[worker_index];
            active = {};
            active.label = active_label;
            active.id = active_id;
            active.queued_ms = record->queued_ms;
            active.started_ms = start;
            active.tid = tid;
        }
    }
    return true;
}

inline void clear_active_slot(pool_t& p, std::uint64_t active_id) {
    std::lock_guard<std::mutex> lk(p.mtx);
    for (auto& active : p.active_snapshots) {
        if (active.id == active_id)
            active = {};
    }
}

inline void finish_started_record(const std::shared_ptr<job_record_t>& record, std::uint64_t active_id, job_state_t final_state, const std::string& exception_text) {
    pool_t* p = record ? record->pool : nullptr;
    if (!record || !p)
        return;
    if (!mark_record_finalized(record, final_state, exception_text))
        return;
    clear_active_slot(*p, active_id);
    p->finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
    p->active_tasks.fetch_sub(1u, std::memory_order_acq_rel);
    if (final_state == job_state_t::cancelled)
        p->cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
    if (final_state == job_state_t::failed)
        p->failed_tasks.fetch_add(1u, std::memory_order_acq_rel);
    if (final_state == job_state_t::timed_out)
        p->timed_out_tasks.fetch_add(1u, std::memory_order_acq_rel);
    if (final_state == job_state_t::completed) {
        std::lock_guard<std::mutex> lk(record->mtx);
        ++record->service_units;
    }
    if (record->fabric_lane_dispatched.exchange(false, std::memory_order_acq_rel)) {
        {
            std::lock_guard<std::mutex> lk(p->mtx);
            if (p->lane_in_flight != 0)
                --p->lane_in_flight;
        }
        pump_lanes(*p);
    }
    evaluate_pool_priority(*p);
}

inline void invoke_body(const std::function<void()>& body, const std::function<void(const cancellation_token_t&)>& cancellable_body, const std::shared_ptr<cancellation_token_t>& token) {
    if (cancellable_body) {
        static cancellation_token_t never_cancelled;
        cancellable_body(token ? *token : never_cancelled);
    } else if (body) {
        body();
    }
}

inline void invoke_cancel_hook_noexcept(const std::shared_ptr<job_record_t>& record,
    std::function<void()> hook) noexcept
{
    if (!record || !hook)
        return;
    DWORD seh = 0;
    try {
        const std::function<void()> guarded = [&]() { hook(); };
        seh = aida::infra::win_thread::run_function_seh_guarded(guarded);
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt(record->pool ? safe_log_tag(*record->pool) : "taskflow_runtime",
            "taskflow_cancel_hook_exception job_id=%llu err=%s tid=%lu",
            static_cast<unsigned long long>(record->id), ex.what(),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    } catch (...) {
        diag::log_tagged_fmt(record->pool ? safe_log_tag(*record->pool) : "taskflow_runtime",
            "taskflow_cancel_hook_exception job_id=%llu err=unknown tid=%lu",
            static_cast<unsigned long long>(record->id),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    }
    if (seh != 0) {
        diag::log_tagged_fmt(record->pool ? safe_log_tag(*record->pool) : "taskflow_runtime",
            "taskflow_cancel_hook_seh job_id=%llu seh=0x%08lX tid=%lu",
            static_cast<unsigned long long>(record->id), static_cast<unsigned long>(seh),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
}

inline std::string seh_text(DWORD code) {
    if (code == 0)
        return {};
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "seh=0x%08lX", static_cast<unsigned long>(code));
    return std::string(buf);
}

inline void execute_single_record(const std::shared_ptr<job_record_t>& record) {
    if (!record)
        return;
    const std::uint64_t active_id = record->id;
    if (!start_record(record, active_id, record->label))
        return;
    job_state_t final_state = job_state_t::completed;
    std::string exception_text;
    if (record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire)) {
        final_state = job_state_t::cancelled;
    } else {
        try {
            std::function<void()> guarded = [record]() {
                invoke_body(record->body, record->cancellable_body, record->cancel_token);
            };
            const DWORD task_seh = aida::infra::win_thread::run_function_seh_guarded(guarded);
            if (task_seh != 0) {
                final_state = job_state_t::failed;
                exception_text = seh_text(task_seh);
            }
        } catch (const std::exception& ex) {
            final_state = job_state_t::failed;
            exception_text = ex.what();
        } catch (...) {
            final_state = job_state_t::failed;
            exception_text = "unknown";
        }
    }
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        if (record->state == job_state_t::timed_out)
            final_state = job_state_t::timed_out;
        else if (record->state == job_state_t::cancelled
            || (record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire)))
            final_state = job_state_t::cancelled;
    }
    if (final_state == job_state_t::failed) {
        g_total_failed.fetch_add(1u, std::memory_order_acq_rel);
        if (record->cancel_token)
            record->cancel_token->requested.store(true, std::memory_order_release);
    }
    finish_started_record(record, active_id, final_state, exception_text);
    if (final_state == job_state_t::completed) {
        std::uint64_t finish_suppressed = 0;
        auto& finish_gate = hot_log_gate_for("taskflow_job_finish");
        const bool finish_emit = hot_log_should_emit(finish_gate, finish_suppressed);
        if (finish_emit || fabric_log_verbose()) {
            diag::log_tagged_fmt(safe_log_tag(*record->pool),
                "taskflow_job_finish job_id=%llu state=%s label=%s owner=%s domain=%s err=%.300s suppressed=%llu total=%llu tid=%lu",
                static_cast<unsigned long long>(record->id),
                job_state_name(final_state),
                record->label.c_str(),
                record->owner_subsystem.c_str(),
                domain_name(record->domain),
                exception_text.empty() ? "<none>" : exception_text.c_str(),
                static_cast<unsigned long long>(finish_suppressed),
                static_cast<unsigned long long>(hot_log_gate_total(finish_gate)),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    } else {
        diag::log_tagged_fmt(safe_log_tag(*record->pool),
            "taskflow_job_finish job_id=%llu state=%s label=%s owner=%s domain=%s err=%.300s tid=%lu",
            static_cast<unsigned long long>(record->id),
            job_state_name(final_state),
            record->label.c_str(),
            record->owner_subsystem.c_str(),
            domain_name(record->domain),
            exception_text.empty() ? "<none>" : exception_text.c_str(),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
}

inline void execute_graph_node(const std::shared_ptr<job_record_t>& record, std::size_t node_index) {
    if (!record || node_index >= record->nodes.size())
        return;
    const std::uint64_t active_id = record->nodes[node_index].active_id;
    const std::string label = record->nodes[node_index].label;
    if (!start_record(record, active_id, label))
        return;
    job_state_t node_state = job_state_t::completed;
    std::string exception_text;
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        record->nodes[node_index].started_ms = now_ms();
        record->nodes[node_index].state = job_state_t::running;
    }
    if (record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire)) {
        node_state = job_state_t::cancelled;
    } else {
        try {
            std::function<void()> guarded = [record, node_index]() {
                auto& node = record->nodes[node_index];
                invoke_body(node.body, node.cancellable_body, record->cancel_token);
            };
            const DWORD task_seh = aida::infra::win_thread::run_function_seh_guarded(guarded);
            if (task_seh != 0) {
                node_state = job_state_t::failed;
                exception_text = seh_text(task_seh);
            }
        } catch (const std::exception& ex) {
            node_state = job_state_t::failed;
            exception_text = ex.what();
        } catch (...) {
            node_state = job_state_t::failed;
            exception_text = "unknown";
        }
    }
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        record->nodes[node_index].finished_ms = now_ms();
        record->nodes[node_index].state = node_state;
        record->nodes[node_index].exception_text = exception_text;
        if (node_state == job_state_t::failed) {
            record->state = job_state_t::failed;
            record->exception_text = exception_text;
        } else if (node_state == job_state_t::cancelled && record->state != job_state_t::failed && record->state != job_state_t::timed_out) {
            record->state = job_state_t::cancelled;
        }
        if (node_state == job_state_t::completed)
            ++record->service_units;
    }
    if (node_state == job_state_t::failed) {
        g_total_failed.fetch_add(1u, std::memory_order_acq_rel);
        if (record->cancel_token)
            record->cancel_token->requested.store(true, std::memory_order_release);
    }
    clear_active_slot(*record->pool, active_id);
    record->pool->active_tasks.fetch_sub(1u, std::memory_order_acq_rel);
    diag::log_tagged_fmt(safe_log_tag(*record->pool),
        "taskflow_graph_node_finish job_id=%llu node_id=%llu state=%s label=%s owner=%s domain=%s err=%.300s tid=%lu",
        static_cast<unsigned long long>(record->id),
        static_cast<unsigned long long>(record->nodes[node_index].node_id),
        job_state_name(node_state),
        label.c_str(),
        record->owner_subsystem.c_str(),
        domain_name(record->domain),
        exception_text.empty() ? "<none>" : exception_text.c_str(),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

inline void try_admit_deferred(pool_t& p);
inline bool remove_record_from_admission_queue(pool_t& p, const std::shared_ptr<job_record_t>& record);

inline bool remove_record_from_admission_queue(pool_t& p, const std::shared_ptr<job_record_t>& record) {
    if (!record)
        return false;
    std::lock_guard<std::mutex> lk(p.mtx);
    for (auto it = p.admission_queue.begin(); it != p.admission_queue.end(); ++it) {
        if (*it && (*it)->id == record->id) {
            p.deferred_nodes -= (std::min<std::uint64_t>)(p.deferred_nodes,
                static_cast<std::uint64_t>((*it)->nodes.size()));
            p.admission_queue.erase(it);
            record->admission_pending = false;
            record->pending_flow.reset();
            return true;
        }
    }
    return false;
}

inline void release_record_reservation(const std::shared_ptr<job_record_t>& record) {
    if (!record || !record->pool ||
        !record->target_reserved.exchange(false, std::memory_order_acq_rel))
        return;
    pool_t& p = *record->pool;
    const auto key = admission_target_key(*record);
    const auto units = record->nodes.empty() ? 1u : record->nodes.size();
    std::lock_guard<std::mutex> lk(p.mtx);
    auto it = p.target_pending_nodes.find(key);
    if (it != p.target_pending_nodes.end()) {
        it->second = it->second > units ? it->second - units : 0;
        if (it->second == 0)
            p.target_pending_nodes.erase(it);
    }
    p.admitted_targets.erase(key);
}


inline void complete_graph_record(const std::shared_ptr<job_record_t>& record) {
    if (!record)
        return;
    pool_t* p = record->pool;
    job_state_t final_state = job_state_t::completed;
    std::string exception_text;
    std::size_t not_started_nodes = 0;
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        if (!record->active || record->finalized)
            return;
        if (record->state == job_state_t::timed_out) {
            final_state = job_state_t::timed_out;
        } else if (record->state == job_state_t::failed) {
            final_state = job_state_t::failed;
            exception_text = record->exception_text;
        } else if (record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire)) {
            final_state = job_state_t::cancelled;
        }
        const std::uint64_t finished_ms = now_ms();
        record->state = final_state;
        for (auto& node : record->nodes) {
            if (node.started_ms == 0) {
                ++not_started_nodes;
                node.state = final_state == job_state_t::completed ? job_state_t::cancelled : final_state;
                node.finished_ms = finished_ms;
            }
        }
    }
    if (!mark_record_finalized(record, final_state, exception_text))
        return;
    if (p) {
        for (std::size_t i = 0; i < not_started_nodes; ++i)
            decrement_atomic_if_nonzero(p->pending_tasks);
        p->finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
        if (final_state == job_state_t::cancelled)
            p->cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
        if (final_state == job_state_t::failed)
            p->failed_tasks.fetch_add(1u, std::memory_order_acq_rel);
        if (final_state == job_state_t::timed_out)
            p->timed_out_tasks.fetch_add(1u, std::memory_order_acq_rel);
    }
    record->cv.notify_all();
    diag::log_tagged_fmt(p ? safe_log_tag(*p) : "taskflow_runtime",
        "taskflow_graph_finish job_id=%llu state=%s label=%s owner=%s domain=%s nodes=%zu err=%.300s tid=%lu",
        static_cast<unsigned long long>(record->id),
        job_state_name(final_state),
        record->label.c_str(),
        record->owner_subsystem.c_str(),
        domain_name(record->domain),
        record->nodes.size(),
        exception_text.empty() ? "<none>" : exception_text.c_str(),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (p && !record->admission_pending.load(std::memory_order_acquire)) {
        release_record_reservation(record);
        try_admit_deferred(*p);
    }
}

inline void prune_completed_jobs_locked() {
    constexpr std::size_t kMaxRetainedJobs = 8192;
    if (g_jobs.size() <= kMaxRetainedJobs)
        return;
    for (auto it = g_jobs.begin(); it != g_jobs.end() && g_jobs.size() > kMaxRetainedJobs;) {
        bool erase = false;
        if (it->second) {
            std::lock_guard<std::mutex> lk(it->second->mtx);
            erase = !it->second->active && it->second->finished_ms != 0;
        } else {
            erase = true;
        }
        if (erase)
            it = g_jobs.erase(it);
        else
            ++it;
    }
}

inline bool valid_descriptor_body(const task_descriptor_t& desc) {
    return static_cast<bool>(desc.body) || static_cast<bool>(desc.cancellable_body);
}

inline std::string copy_or_default(const std::string& value, const char* fallback) {
    return !value.empty() ? value : std::string(fallback ? fallback : "");
}

inline std::shared_ptr<job_record_t> make_record_from_descriptor(task_descriptor_t&& desc, pool_t& p) {
    auto record = std::make_shared<job_record_t>();
    record->id = g_next_job_id.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    record->domain = desc.domain;
    record->pool = &p;
    record->owner_subsystem = copy_or_default(desc.owner_subsystem, "taskflow_runtime");
    record->label = copy_or_default(desc.label, p.default_label ? p.default_label : "taskflow.job");
    record->thread_class = copy_or_default(desc.thread_class, "");
    record->session_id = copy_or_default(desc.session_id, "");
    record->target_id = copy_or_default(desc.target_id, "");
    record->diagnostic_id = copy_or_default(desc.diagnostic_id, "");
    record->request_id = copy_or_default(desc.request_id, "");
    record->ui_access_policy = copy_or_default(desc.ui_access_policy, "none");
    record->failure_policy = copy_or_default(desc.failure_policy, "reject_not_started");
    record->shutdown_policy = copy_or_default(desc.shutdown_policy, "drain");
    record->no_capacity_reason = copy_or_default(desc.no_capacity_reason, "");
    record->priority = normalized_priority(desc.priority);
    record->target_pid = desc.target_pid;
    record->deadline_ms = desc.deadline_ms;
    record->capacity_lease = desc.capacity_lease;
    record->lease_token = desc.lease_token;
    record->generation = desc.generation;
    record->queued_ms = now_ms();
    record->queued_ns = now_ns();
    record->body = std::move(desc.body);
    record->cancellable_body = std::move(desc.cancellable_body);
    record->cancel_hook = std::move(desc.cancel_hook);
    record->cancel_token = std::make_shared<cancellation_token_t>();
    record->pending_units = 1;
    return record;
}

inline bool remove_record_from_lane(pool_t& p, const std::shared_ptr<job_record_t>& record) {
    if (!record)
        return false;
    std::lock_guard<std::mutex> lk(p.mtx);
    if (!record->fabric_lane_queued.load(std::memory_order_acquire) ||
        record->fabric_lane_dispatched.load(std::memory_order_acquire))
        return false;
    const std::size_t lane_index = (std::min<std::size_t>)(
        static_cast<std::size_t>(record->priority), p.priority_lanes.size() - 1u);
    auto& lane = p.priority_lanes[lane_index];
    bool erased = false;
    for (auto it = lane.begin(); it != lane.end(); ++it) {
        if (*it && (*it)->id == record->id) {
            lane.erase(it);
            erased = true;
            break;
        }
    }
    p.lane_depth[lane_index] = static_cast<std::uint64_t>(lane.size());
    record->fabric_lane_queued.store(false, std::memory_order_release);
    if (!erased) {
        diag::log_tagged_fmt(safe_log_tag(p),
            "fabric_lane_remove_missing job_id=%llu pool=%s lane=%zu tid=%lu",
            static_cast<unsigned long long>(record->id),
            safe_pool_name(p),
            lane_index,
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    return true;
}

inline void pump_lanes(pool_t& p) {
    std::vector<std::shared_ptr<job_record_t>> skipped;
    std::vector<std::shared_ptr<job_record_t>> failed;
    {
        std::unique_lock<std::mutex> lk(p.mtx);
        const auto executor = load_executor(p);
        const bool executor_ready = executor && p.alive.load(std::memory_order_acquire);
        if (!executor_ready) {
            for (std::size_t lane_index = 0; lane_index < p.priority_lanes.size(); ++lane_index) {
                auto& lane = p.priority_lanes[lane_index];
                while (!lane.empty()) {
                    auto record = std::move(lane.front());
                    lane.pop_front();
                    if (record) {
                        record->fabric_lane_queued.store(false, std::memory_order_release);
                        if (record->cancel_token)
                            record->cancel_token->requested.store(true, std::memory_order_release);
                        skipped.push_back(std::move(record));
                    }
                }
                p.lane_depth[lane_index] = 0;
            }
        } else {
            const std::uint64_t workers =
                static_cast<std::uint64_t>(p.worker_count.load(std::memory_order_acquire));
            while (p.lane_in_flight < workers) {
                std::size_t lane_index = p.priority_lanes.size();
                for (std::size_t i = 0; i < p.priority_lanes.size(); ++i) {
                    if (!p.priority_lanes[i].empty()) {
                        lane_index = i;
                        break;
                    }
                }
                if (lane_index == p.priority_lanes.size())
                    break;
                auto& lane = p.priority_lanes[lane_index];
                auto record = std::move(lane.front());
                lane.pop_front();
                p.lane_depth[lane_index] = static_cast<std::uint64_t>(lane.size());
                if (!record)
                    continue;
                record->fabric_lane_queued.store(false, std::memory_order_release);
                ++p.lane_in_flight;
                ++p.lane_dispatched[lane_index];
                lk.unlock();
                bool cancelled = false;
                {
                    std::lock_guard<std::mutex> record_lk(record->mtx);
                    cancelled = !record->active ||
                        (record->cancel_token &&
                         record->cancel_token->requested.load(std::memory_order_acquire));
                    if (!cancelled)
                        record->fabric_lane_dispatched.store(true, std::memory_order_release);
                }
                if (cancelled) {
                    lk.lock();
                    if (p.lane_in_flight != 0)
                        --p.lane_in_flight;
                    if (p.lane_dispatched[lane_index] != 0)
                        --p.lane_dispatched[lane_index];
                    skipped.push_back(std::move(record));
                    continue;
                }
                try {
                    tf::Taskflow flow;
                    auto task = flow.emplace([record]() { execute_single_record(record); });
                    task.name(record->label);
                    lk.lock();
                    const auto executor = load_executor(p);
                    if (!executor || !p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) {
                        --p.lane_in_flight;
                        if (p.lane_dispatched[lane_index] != 0)
                            --p.lane_dispatched[lane_index];
                        lk.unlock();
                        skipped.push_back(std::move(record));
                        continue;
                    }
                    auto future = executor->run(std::move(flow),
                        [record]() { complete_not_started_record(record); });
                    lk.unlock();
                    {
                        std::lock_guard<std::mutex> record_lk(record->mtx);
                        record->future = std::move(future);
                        record->has_future = true;
                        if (record->state == job_state_t::queued)
                            record->state = job_state_t::not_started;
                    }
                    p.posted_tasks.fetch_add(1u, std::memory_order_acq_rel);
                    std::uint64_t dispatch_suppressed = 0;
                    auto& dispatch_gate = hot_log_gate_for("fabric_lane_dispatch");
                    const bool dispatch_emit = hot_log_should_emit(dispatch_gate, dispatch_suppressed);
                    if (dispatch_emit || fabric_log_verbose()) {
                        diag::log_tagged_fmt(safe_log_tag(p),
                            "fabric_lane_dispatch job_id=%llu pool=%s lane=%zu in_flight=%llu owner=%s label=%s suppressed=%llu total=%llu tid=%lu",
                            static_cast<unsigned long long>(record->id),
                            safe_pool_name(p),
                            lane_index,
                            static_cast<unsigned long long>(p.lane_in_flight),
                            record->owner_subsystem.c_str(),
                            record->label.c_str(),
                            static_cast<unsigned long long>(dispatch_suppressed),
                            static_cast<unsigned long long>(hot_log_gate_total(dispatch_gate)),
                            static_cast<unsigned long>(GetCurrentThreadId()));
                    }
                } catch (const std::exception& ex) {
                    record->fabric_lane_dispatched.store(false, std::memory_order_release);
                    lk.lock();
                    if (p.lane_in_flight != 0)
                        --p.lane_in_flight;
                    lk.unlock();
                    {
                        std::lock_guard<std::mutex> record_lk(record->mtx);
                        record->exception_text = ex.what();
                    }
                    failed.push_back(std::move(record));
                } catch (...) {
                    record->fabric_lane_dispatched.store(false, std::memory_order_release);
                    lk.lock();
                    if (p.lane_in_flight != 0)
                        --p.lane_in_flight;
                    lk.unlock();
                    {
                        std::lock_guard<std::mutex> record_lk(record->mtx);
                        record->exception_text = "fabric_lane_dispatch_exception";
                    }
                    failed.push_back(std::move(record));
                }
                lk.lock();
            }
        }
    }
    for (auto& record : skipped)
        complete_not_started_record(record);
    for (auto& record : failed) {
        std::string reason;
        {
            std::lock_guard<std::mutex> record_lk(record->mtx);
            reason = record->exception_text;
        }
        if (mark_record_finalized(record, job_state_t::failed, reason)) {
            decrement_atomic_if_nonzero(p.pending_tasks);
            p.failed_tasks.fetch_add(1u, std::memory_order_acq_rel);
            g_total_failed.fetch_add(1u, std::memory_order_acq_rel);
            p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
        }
        diag::log_tagged_fmt(safe_log_tag(p),
            "fabric_lane_dispatch_failed job_id=%llu pool=%s reason=%.300s owner=%s label=%s tid=%lu",
            static_cast<unsigned long long>(record->id),
            safe_pool_name(p),
            reason.empty() ? "<none>" : reason.c_str(),
            record->owner_subsystem.c_str(),
            record->label.c_str(),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    evaluate_pool_priority(p);
}

inline submit_result_t submit_to_pool(pool_t& p, int pool_size, task_descriptor_t&& desc) {
    ensure_deadline_sweeper_started();
    submit_result_t result;
    register_pool(p);
    p.post_attempts.fetch_add(1u, std::memory_order_acq_rel);
    if (desc.owner_subsystem.empty()) {
        result.reject_reason = "missing_owner_subsystem";
    } else if (desc.label.empty()) {
        result.reject_reason = "missing_label";
    } else if (!valid_descriptor_body(desc)) {
        result.reject_reason = "missing_body";
    } else if (g_stop_accepting.load(std::memory_order_acquire) || p.stop_accepting.load(std::memory_order_acquire) || p.shutdown_called.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) {
        result.reject_reason = "runtime_shutdown_requested";
    }
    if (!result.reject_reason.empty()) {
        p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
        g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_submit_rejected pool=%s reason=%s owner=%s label=%s domain=%s tid=%lu",
            safe_pool_name(p),
            result.reject_reason.c_str(),
            desc.owner_subsystem.empty() ? "<null>" : desc.owner_subsystem.c_str(),
            desc.label.empty() ? "<null>" : desc.label.c_str(),
            domain_name(desc.domain),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }
    if (!p.alive.load(std::memory_order_acquire))
        initialize_pool(p, pool_size);
    std::shared_ptr<job_record_t> record = make_record_from_descriptor(std::move(desc), p);
    {
        std::lock_guard<std::mutex> jobs_lk(g_jobs_mtx);
        prune_completed_jobs_locked();
        g_jobs[record->id] = record;
    }
    bool pending_incremented = false;
    bool no_capacity = false;
    std::uint64_t queued_total = 0;
    try {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (g_stop_accepting.load(std::memory_order_acquire)
            || !p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)
            || p.stop_accepting.load(std::memory_order_acquire) || !load_executor(p)) {
            result.reject_reason = "pool_not_accepting";
        } else {
            queued_total = p.lane_in_flight;
            for (const auto depth : p.lane_depth)
                queued_total += depth;
            if (queued_total >= static_cast<std::uint64_t>(p.pending_capacity)) {
                no_capacity = true;
                result.reject_reason = record->no_capacity_reason.empty()
                    ? "no_capacity" : record->no_capacity_reason;
            } else {
                p.pending_tasks.fetch_add(1u, std::memory_order_acq_rel);
                pending_incremented = true;
                record->fabric_lane_queued.store(true, std::memory_order_release);
                const std::size_t lane_index = (std::min<std::size_t>)(
                    static_cast<std::size_t>(record->priority), p.priority_lanes.size() - 1u);
                auto& lane = p.priority_lanes[lane_index];
                lane.push_back(record);
                p.lane_depth[lane_index] = static_cast<std::uint64_t>(lane.size());
                g_total_submitted.fetch_add(1u, std::memory_order_acq_rel);
                result.submitted = true;
                result.handle.id = record->id;
                std::uint64_t enqueue_suppressed = 0;
                auto& enqueue_gate = hot_log_gate_for("fabric_lane_enqueue");
                const bool enqueue_emit = hot_log_should_emit(enqueue_gate, enqueue_suppressed);
                if (enqueue_emit || fabric_log_verbose()) {
                    diag::log_tagged_fmt(safe_log_tag(p),
                        "fabric_lane_enqueue job_id=%llu pool=%s lane=%zu lane_depth=%llu queued_total=%llu owner=%s label=%s suppressed=%llu total=%llu tid=%lu",
                        static_cast<unsigned long long>(record->id),
                        safe_pool_name(p),
                        lane_index,
                        static_cast<unsigned long long>(p.lane_depth[lane_index]),
                        static_cast<unsigned long long>(queued_total + 1u),
                        record->owner_subsystem.c_str(),
                        record->label.c_str(),
                        static_cast<unsigned long long>(enqueue_suppressed),
                        static_cast<unsigned long long>(hot_log_gate_total(enqueue_gate)),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                }
            }
        }
    } catch (const std::exception& ex) {
        result.reject_reason = ex.what();
    } catch (...) {
        result.reject_reason = "unknown_exception";
    }
    if (!result.submitted) {
        if (pending_incremented)
            decrement_atomic_if_nonzero(p.pending_tasks);
        p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
        g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
        mark_record_finalized(record, job_state_t::failed, result.reject_reason);
        if (no_capacity) {
            diag::log_tagged_fmt(safe_log_tag(p),
                "fabric_no_capacity pool=%s reason=%s queued_total=%llu pending_capacity=%llu owner=%s label=%s domain=%s tid=%lu",
                safe_pool_name(p),
                result.reject_reason.c_str(),
                static_cast<unsigned long long>(queued_total),
                static_cast<unsigned long long>(p.pending_capacity),
                record->owner_subsystem.c_str(),
                record->label.c_str(),
                domain_name(record->domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
        } else {
            diag::log_tagged_fmt(safe_log_tag(p),
                "taskflow_submit_failed pool=%s reason=%.300s owner=%s label=%s domain=%s tid=%lu",
                safe_pool_name(p),
                result.reject_reason.empty() ? "<none>" : result.reject_reason.c_str(),
                record->owner_subsystem.c_str(),
                record->label.c_str(),
                domain_name(record->domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    } else {
        std::uint64_t submit_suppressed = 0;
        auto& submit_gate = hot_log_gate_for("taskflow_submit");
        const bool submit_emit = hot_log_should_emit(submit_gate, submit_suppressed);
        if (submit_emit || fabric_log_verbose()) {
            diag::log_tagged_fmt(safe_log_tag(p),
                "taskflow_submit job_id=%llu pool=%s owner=%s label=%s domain=%s deadline_ms=%llu priority=%d suppressed=%llu total=%llu tid=%lu",
                static_cast<unsigned long long>(record->id),
                safe_pool_name(p),
                record->owner_subsystem.c_str(),
                record->label.c_str(),
                domain_name(record->domain),
                static_cast<unsigned long long>(record->deadline_ms),
                record->priority,
                static_cast<unsigned long long>(submit_suppressed),
                static_cast<unsigned long long>(hot_log_gate_total(submit_gate)),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
        evaluate_pool_priority(p);
        pump_lanes(p);
    }
    return result;
}

inline submit_result_t submit(task_descriptor_t&& desc) {
    pool_t& p = domain_pool(desc.domain);
    return submit_to_pool(p, p.configured_pool_size, std::move(desc));
}

inline std::atomic<bool> g_deadline_sweeper_started{false};

inline void deadline_sweeper_tick() {
    check_deadlines();
    if (g_shutdown_requested.load(std::memory_order_acquire) ||
        g_stop_accepting.load(std::memory_order_acquire))
        return;
    task_descriptor_t desc;
    desc.domain = executor_domain_t::diagnostics;
    desc.owner_subsystem = "taskflow_runtime";
    desc.label = "runtime.deadline_sweeper";
    desc.priority = 7;
    desc.shutdown_policy = "cancel_pending";
    desc.cancellable_body = [](const cancellation_token_t& token) {
        for (int slice = 0; slice < 5; ++slice) {
            if (token.requested.load(std::memory_order_acquire))
                return;
            Sleep(5);
        }
        deadline_sweeper_tick();
    };
    static_cast<void>(submit(std::move(desc)));
}

inline void ensure_deadline_sweeper_started() noexcept {
    bool expected = false;
    if (!g_deadline_sweeper_started.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return;
    if (g_shutdown_requested.load(std::memory_order_acquire) ||
        g_stop_accepting.load(std::memory_order_acquire))
        return;
    try {
        deadline_sweeper_tick();
    } catch (...) {
    }
}

inline void try_admit_deferred(pool_t& p) {
    const auto initial_executor = load_executor(p);
    if (!initial_executor || !p.alive.load(std::memory_order_acquire) ||
        p.shutting_down.load(std::memory_order_acquire) ||
        p.stop_accepting.load(std::memory_order_acquire))
        return;
    std::vector<std::shared_ptr<job_record_t>> admitted;
    std::vector<std::shared_ptr<job_record_t>> still_deferred;
    std::vector<std::shared_ptr<job_record_t>> abandoned;
    std::vector<std::shared_ptr<job_record_t>> candidates;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (p.admission_queue.empty())
            return;
        candidates.swap(p.admission_queue);
        p.deferred_nodes = 0;
    }
    still_deferred.reserve(candidates.size());
    for (auto& record : candidates) {
            if (!record) {
                continue;
            }
            bool active = false;
            {
                std::lock_guard<std::mutex> record_lk(record->mtx);
                active = record->active && !record->finalized;
            }
            if (!record->pending_flow || !active) {
                abandoned.push_back(std::move(record));
                continue;
            }
            const auto key = admission_target_key(*record);
            const auto node_count = record->nodes.size();
            bool can_admit = false;
            {
                std::lock_guard<std::mutex> pool_lk(p.mtx);
                const auto current = p.target_pending_nodes[key];
                if (current + node_count <= p.per_target_pending_capacity) {
                    p.target_pending_nodes[key] = current + node_count;
                    p.admitted_targets[key] = 1;
                    can_admit = true;
                }
            }
            if (can_admit)
                admitted.push_back(std::move(record));
            else
                still_deferred.push_back(std::move(record));
    }
    {
        std::lock_guard<std::mutex> lk(p.mtx);
            p.admission_queue.insert(p.admission_queue.end(),
                std::make_move_iterator(still_deferred.begin()),
                std::make_move_iterator(still_deferred.end()));
            p.deferred_nodes = 0;
            for (const auto& queued : p.admission_queue)
                if (queued)
                    p.deferred_nodes += queued->nodes.size();
        p.deferred_nodes = 0;
        for (const auto& record : p.admission_queue)
            p.deferred_nodes += record ? record->nodes.size() : 0;
    }
    for (auto& record : abandoned) {
        if (!record)
            continue;
        record->admission_pending = false;
        record->pending_flow.reset();
        if (mark_record_finalized(record, job_state_t::cancelled, {})) {
            p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
            p.cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
            release_record_reservation(record);
        }
    }
    for (auto& record : admitted) {
        try {
            auto flow = std::move(*record->pending_flow);
            record->pending_flow.reset();
            record->admission_pending = false;
            record->pending_units = record->nodes.size();
            record->target_reserved = true;
            p.pending_tasks.fetch_add(static_cast<std::uint64_t>(record->nodes.size()), std::memory_order_acq_rel);
            std::unique_lock<std::mutex> pool_lk(p.mtx);
            const auto executor = load_executor(p);
            if (!executor || !p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire))
                throw std::runtime_error("pool executor unavailable during deferred admission");
            auto future = executor->run(std::move(flow), [record]() { complete_graph_record(record); });
            pool_lk.unlock();
            {
                std::lock_guard<std::mutex> record_lk(record->mtx);
                record->future = std::move(future);
                record->has_future = true;
                if (record->state == job_state_t::queued)
                    record->state = job_state_t::not_started;
            }
            p.posted_tasks.fetch_add(1u, std::memory_order_acq_rel);
            g_total_submitted.fetch_add(1u, std::memory_order_acq_rel);
        } catch (const std::exception& ex) {
            if (mark_record_finalized(record, job_state_t::failed, ex.what())) {
                for (std::size_t i = 0; i < record->nodes.size(); ++i)
                    decrement_atomic_if_nonzero(p.pending_tasks);
                release_record_reservation(record);
                p.failed_tasks.fetch_add(1u, std::memory_order_acq_rel);
                p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
                g_total_failed.fetch_add(1u, std::memory_order_acq_rel);
            }
        } catch (...) {
            if (mark_record_finalized(record, job_state_t::failed, "admission_exception")) {
                for (std::size_t i = 0; i < record->nodes.size(); ++i)
                    decrement_atomic_if_nonzero(p.pending_tasks);
                release_record_reservation(record);
                p.failed_tasks.fetch_add(1u, std::memory_order_acq_rel);
                p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
                g_total_failed.fetch_add(1u, std::memory_order_acq_rel);
            }
        }
    }
}

inline submit_result_t submit_graph(graph_descriptor_t&& graph) {
    submit_result_t result;
    if (graph.owner_subsystem.empty()) {
        result.reject_reason = "missing_owner_subsystem";
    } else if (graph.label.empty()) {
        result.reject_reason = "missing_label";
    } else if (graph.nodes.empty()) {
        result.reject_reason = "missing_graph_nodes";
    } else if (g_stop_accepting.load(std::memory_order_acquire)) {
        result.reject_reason = "runtime_shutdown_requested";
    }
    pool_t& p = domain_pool(graph.domain);
    p.post_attempts.fetch_add(1u, std::memory_order_acq_rel);
    if (!result.reject_reason.empty()) {
        p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
        g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
        return result;
    }
    if (!p.alive.load(std::memory_order_acquire))
        initialize_pool(p, p.configured_pool_size);
    auto record = std::make_shared<job_record_t>();
    record->id = g_next_job_id.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    record->domain = graph.domain;
    record->pool = &p;
    record->owner_subsystem = copy_or_default(graph.owner_subsystem, "taskflow_runtime");
    record->label = copy_or_default(graph.label, "taskflow.graph");
    record->phase = copy_or_default(graph.phase, "");
    record->session_id = copy_or_default(graph.session_id, "");
    record->target_id = copy_or_default(graph.target_id, "");
    record->diagnostic_id = copy_or_default(graph.diagnostic_id, "");
    record->request_id = copy_or_default(graph.request_id, "");
    record->priority = normalized_priority(graph.priority);
    record->target_pid = graph.target_pid;
    record->deadline_ms = graph.deadline_ms;
    record->generation = graph.generation;
    record->queued_ms = now_ms();
    record->queued_ns = now_ns();
    record->cancel_hook = std::move(graph.cancel_hook);
    record->cancel_token = std::make_shared<cancellation_token_t>();
    record->graph = true;
    record->nodes.reserve(graph.nodes.size());
    std::unordered_map<std::uint64_t, std::size_t> node_index;
    for (std::size_t i = 0; i < graph.nodes.size(); ++i) {
        const auto& node = graph.nodes[i];
        if ((!node.body && !node.cancellable_body) || node.node_id == 0) {
            result.reject_reason = "invalid_graph_node";
            p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
            g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
            return result;
        }
        graph_node_record_t rec;
        rec.node_id = node.node_id;
        rec.active_id = (record->id * 100000ULL) + static_cast<std::uint64_t>(i + 1u);
        rec.label = copy_or_default(node.label, "taskflow.graph.node");
        rec.depends_on = node.depends_on;
        rec.body = std::move(graph.nodes[i].body);
        rec.cancellable_body = std::move(graph.nodes[i].cancellable_body);
        node_index[rec.node_id] = i;
        record->nodes.push_back(std::move(rec));
    }
    tf::Taskflow flow;
    std::vector<tf::Task> tasks;
    tasks.reserve(record->nodes.size());
    for (std::size_t i = 0; i < record->nodes.size(); ++i) {
        auto t = flow.emplace([record, i]() { execute_graph_node(record, i); });
        t.name(record->nodes[i].label);
        tasks.push_back(t);
    }
    for (std::size_t i = 0; i < record->nodes.size(); ++i) {
        for (const auto dep : record->nodes[i].depends_on) {
            auto it = node_index.find(dep);
            if (it == node_index.end()) {
                result.reject_reason = "missing_graph_dependency";
                p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
                g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
                return result;
            }
            tasks[it->second].precede(tasks[i]);
        }
    }
    {
        std::lock_guard<std::mutex> jobs_lk(g_jobs_mtx);
        prune_completed_jobs_locked();
        g_jobs[record->id] = record;
    }
    bool pending_incremented = false;
    bool deferred = false;
    try {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire) || p.stop_accepting.load(std::memory_order_acquire) || !load_executor(p)) {
            result.reject_reason = "pool_not_accepting";
        } else {
            const auto target_key = admission_target_key(*record);
            const auto node_count = record->nodes.size();
            const auto current_pending = p.target_pending_nodes[target_key];
            const bool other_targets_waiting = !p.admission_queue.empty() ||
                (p.admitted_targets.size() > 1) ||
                (p.admitted_targets.size() == 1 &&
                 p.admitted_targets.find(target_key) == p.admitted_targets.end());
            if (other_targets_waiting &&
                current_pending + node_count > p.per_target_pending_capacity &&
                p.admission_queue.size() < p.admission_capacity) {
                record->pending_flow = std::make_shared<tf::Taskflow>(std::move(flow));
                record->admission_pending = true;
                record->pending_units = 0;
                p.admission_queue.push_back(record);
                p.deferred_nodes += node_count;
                result.submitted = true;
                result.handle.id = record->id;
                deferred = true;
            } else {
                p.target_pending_nodes[target_key] = current_pending + node_count;
                p.admitted_targets[target_key] = 1;
                record->target_reserved = true;
                record->pending_units = node_count;
                p.pending_tasks.fetch_add(static_cast<std::uint64_t>(record->nodes.size()), std::memory_order_acq_rel);
                pending_incremented = true;
                const auto executor = load_executor(p);
                if (!executor)
                    throw std::runtime_error("pool executor unavailable during graph dispatch");
                auto future = executor->run(std::move(flow), [record]() { complete_graph_record(record); });
                {
                    std::lock_guard<std::mutex> record_lk(record->mtx);
                    record->future = std::move(future);
                    record->has_future = true;
                    if (record->state == job_state_t::queued)
                        record->state = job_state_t::not_started;
                }
                p.posted_tasks.fetch_add(1u, std::memory_order_acq_rel);
                g_total_submitted.fetch_add(1u, std::memory_order_acq_rel);
                result.submitted = true;
                result.handle.id = record->id;
            }
        }
    } catch (const std::exception& ex) {
        result.reject_reason = ex.what();
    } catch (...) {
        result.reject_reason = "unknown_exception";
    }
    if (!result.submitted) {
        if (pending_incremented) {
            for (std::size_t i = 0; i < record->nodes.size(); ++i)
                decrement_atomic_if_nonzero(p.pending_tasks);
        }
        p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
        g_total_rejected.fetch_add(1u, std::memory_order_acq_rel);
        mark_record_finalized(record, job_state_t::failed, result.reject_reason);
        release_record_reservation(record);
    } else if (!deferred) {
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_graph_submit job_id=%llu pool=%s owner=%s label=%s phase=%s domain=%s nodes=%zu deadline_ms=%llu tid=%lu",
            static_cast<unsigned long long>(record->id),
            safe_pool_name(p),
            record->owner_subsystem.c_str(),
            record->label.c_str(),
            record->phase.empty() ? "<none>" : record->phase.c_str(),
            domain_name(record->domain),
            record->nodes.size(),
            static_cast<unsigned long long>(record->deadline_ms),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    return result;
}

inline std::shared_ptr<job_record_t> find_job(std::uint64_t job_id) {
    std::lock_guard<std::mutex> lk(g_jobs_mtx);
    auto it = g_jobs.find(job_id);
    return it == g_jobs.end() ? nullptr : it->second;
}

inline bool cancel(job_handle_t handle) {
    if (!handle.valid())
        return false;
    auto record = find_job(handle.id);
    if (!record)
        return false;
    bool signalled = false;
    std::function<void()> cancel_hook;
    bool account_cancellation = false;
    {
        std::lock_guard<std::mutex> lk(record->mtx);
        if (!record->active && terminal_state(record->state))
            return false;
        if (record->cancel_token)
            record->cancel_token->requested.store(true, std::memory_order_release);
        if (record->state != job_state_t::failed && record->state != job_state_t::timed_out)
            record->state = job_state_t::cancelled;
        if (record->has_future)
            signalled = record->future.cancel();
        if (!record->cancel_hook_invoked) {
            record->cancel_hook_invoked = true;
            cancel_hook = std::move(record->cancel_hook);
        }
        if (!record->cancellation_accounted) {
            record->cancellation_accounted = true;
            account_cancellation = true;
        }
    }
    if (record->pool && record->fabric_lane_queued.load(std::memory_order_acquire) &&
        remove_record_from_lane(*record->pool, record)) {
        complete_not_started_record(record);
    }
    if (record->pool && record->admission_pending.load(std::memory_order_acquire) &&
        remove_record_from_admission_queue(*record->pool, record)) {
        if (mark_record_finalized(record, job_state_t::cancelled, {})) {
            record->pool->finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
            record->pool->cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
            release_record_reservation(record);
        }
        try_admit_deferred(*record->pool);
    }
    invoke_cancel_hook_noexcept(record, std::move(cancel_hook));
    if (account_cancellation)
        g_total_cancelled.fetch_add(1u, std::memory_order_acq_rel);
    record->cv.notify_all();
    diag::log_tagged_fmt(record->pool ? safe_log_tag(*record->pool) : "taskflow_runtime",
        "taskflow_cancel job_id=%llu state=cancelled future_signalled=%d label=%s owner=%s domain=%s tid=%lu",
        static_cast<unsigned long long>(handle.id),
        signalled ? 1 : 0,
        record->label.c_str(),
        record->owner_subsystem.c_str(),
        domain_name(record->domain),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

inline bool cancel(std::uint64_t job_id) {
    return cancel(job_handle_t{job_id});
}

inline bool cooperative_cancel_requested(job_handle_t handle) {
    auto record = find_job(handle.id);
    return record && record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire);
}

inline wait_result_t wait_for(job_handle_t handle, std::uint32_t timeout_ms) {
    wait_result_t result;
    if (!handle.valid()) {
        result.rejected = true;
        return result;
    }
    auto record = find_job(handle.id);
    if (!record) {
        result.rejected = true;
        return result;
    }
    std::unique_lock<std::mutex> lk(record->mtx);
    const std::uint64_t start = now_ms();
    const std::uint64_t deadline = start + static_cast<std::uint64_t>(timeout_ms);
    while (record->active) {
        const std::uint64_t current = now_ms();
        if (current >= deadline) {
            result.timed_out = true;
            return result;
        }
        const DWORD remaining = static_cast<DWORD>((std::min<std::uint64_t>)(deadline - current, 25ULL));
        record->cv.wait_for(lk, std::chrono::milliseconds(remaining));
    }
    result.completed = record->state == job_state_t::completed;
    result.cancelled = record->state == job_state_t::cancelled;
    result.failed = record->state == job_state_t::failed;
    result.timed_out = record->state == job_state_t::timed_out;
    return result;
}

inline wait_result_t wait_for(std::uint64_t job_id, std::uint32_t timeout_ms) {
    return wait_for(job_handle_t{job_id}, timeout_ms);
}

inline void check_deadlines() {
    const std::uint64_t current = now_ms();
    std::vector<std::shared_ptr<job_record_t>> expired;
    {
        std::lock_guard<std::mutex> lk(g_jobs_mtx);
        for (const auto& kv : g_jobs) {
            auto& record = kv.second;
            if (!record)
                continue;
            std::lock_guard<std::mutex> record_lk(record->mtx);
            if (!record->active || record->deadline_ms == 0 || record->deadline_reported || current < record->deadline_ms)
                continue;
            record->deadline_reported = true;
            record->state = job_state_t::timed_out;
            if (record->cancel_token)
                record->cancel_token->requested.store(true, std::memory_order_release);
            expired.push_back(record);
        }
    }
    for (const auto& record : expired) {
        bool signalled = false;
        std::function<void()> cancel_hook;
        {
            std::lock_guard<std::mutex> lk(record->mtx);
            if (record->has_future)
                signalled = record->future.cancel();
            if (!record->cancel_hook_invoked) {
                record->cancel_hook_invoked = true;
                cancel_hook = record->cancel_hook;
            }
        }
        if (record->pool && record->fabric_lane_queued.load(std::memory_order_acquire) &&
            remove_record_from_lane(*record->pool, record)) {
            complete_not_started_record(record);
        }
        if (record->pool && record->admission_pending.load(std::memory_order_acquire) &&
            remove_record_from_admission_queue(*record->pool, record)) {
            if (mark_record_finalized(record, job_state_t::timed_out, {})) {
                record->pool->finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
                record->pool->timed_out_tasks.fetch_add(1u, std::memory_order_acq_rel);
                release_record_reservation(record);
            }
            try_admit_deferred(*record->pool);
        }
        invoke_cancel_hook_noexcept(record, std::move(cancel_hook));
        g_total_timed_out.fetch_add(1u, std::memory_order_acq_rel);
        diag::log_tagged_fmt(record->pool ? safe_log_tag(*record->pool) : "taskflow_runtime",
            "taskflow_deadline_timeout job_id=%llu label=%s owner=%s domain=%s deadline_ms=%llu now_ms=%llu future_signalled=%d tid=%lu",
            static_cast<unsigned long long>(record->id),
            record->label.c_str(),
            record->owner_subsystem.c_str(),
            domain_name(record->domain),
            static_cast<unsigned long long>(record->deadline_ms),
            static_cast<unsigned long long>(current),
            signalled ? 1 : 0,
            static_cast<unsigned long>(GetCurrentThreadId()));
        record->cv.notify_all();
    }
}

inline stats_t stats_for(pool_t& p, int pool_size, const char* pool_name) {
    register_pool(p);
    stats_t s;
    s.alive = p.alive.load(std::memory_order_acquire);
    s.shutting_down = p.shutting_down.load(std::memory_order_acquire);
    s.pool_size = pool_size;
    s.active = p.active_tasks.load(std::memory_order_acquire);
    s.pending = static_cast<std::size_t>(p.pending_tasks.load(std::memory_order_acquire));
    s.workers = p.worker_count.load(std::memory_order_acquire);
    s.post_attempts = p.post_attempts.load(std::memory_order_acquire);
    s.posted = p.posted_tasks.load(std::memory_order_acquire);
    s.rejected = p.rejected_tasks.load(std::memory_order_acquire);
    s.started = p.started_tasks.load(std::memory_order_acquire);
    s.finished = p.finished_tasks.load(std::memory_order_acquire);
    s.cancelled = p.cancelled_tasks.load(std::memory_order_acquire);
    s.failed = p.failed_tasks.load(std::memory_order_acquire);
    s.timed_out = p.timed_out_tasks.load(std::memory_order_acquire);
    s.fairness_wait_ns_total = p.fairness_wait_ns_total.load(std::memory_order_acquire);
    {
        std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            s.active_labels = "<stats_lock_busy>";
            s.top_cpu_labels = "<stats_lock_busy>";
            return s;
        }
        s.lane_in_flight = p.lane_in_flight;
        for (std::size_t lane_index = 0; lane_index < 8; ++lane_index) {
            s.lane_depth[lane_index] = p.lane_depth[lane_index];
            s.lane_admitted[lane_index] = p.lane_dispatched[lane_index];
        }
        const std::uint64_t current = now_ms();
        struct top_cpu_item_t {
            std::uint64_t task_id = 0;
            std::string label;
            const char* label_class = "general";
            const char* health = "needs_progress";
            std::uint64_t cpu_delta_100ns = 0;
            std::uint32_t cpu_pct_x100 = 0;
        };
        top_cpu_item_t top_cpu[4];
        std::size_t top_cpu_count = 0;
        for (auto& active : p.active_snapshots) {
            if (active.id == 0)
                continue;
            refresh_active_thread_sample(active, current);
            const char* cls = classify_worker_label(active.label, default_class_for(p.family));
            const char* lifetime = worker_lifetime_label(p.family, pool_name, cls);
            const char* health = worker_health_label(p.family, lifetime, active.thread_alive, active.cpu_pct_x100, s.pending, s.shutting_down);
            if (std::strcmp(health, "healthy_long_lived") == 0)
                ++s.healthy_long_lived;
            if (std::strcmp(health, "hot_cpu") == 0)
                ++s.hot_workers;
            if (!active.thread_alive)
                ++s.not_queryable_workers;
            const std::uint64_t age_ms = current >= active.started_ms ? current - active.started_ms : 0;
            if (s.oldest_active_ms < age_ms)
                s.oldest_active_ms = age_ms;
            ++s.active_label_count;
            const std::uint64_t queued_age_ms = active.queued_ms != 0 && current >= active.queued_ms ? current - active.queued_ms : 0;
            if (active.cpu_delta_100ns != 0) {
                std::size_t pos = top_cpu_count;
                while (pos > 0 && active.cpu_delta_100ns > top_cpu[pos - 1].cpu_delta_100ns)
                    --pos;
                if (pos < 4) {
                    if (top_cpu_count < 4)
                        ++top_cpu_count;
                    for (std::size_t j = top_cpu_count - 1; j > pos; --j)
                        top_cpu[j] = std::move(top_cpu[j - 1]);
                    top_cpu[pos].task_id = active.id;
                    top_cpu[pos].label = active.label;
                    top_cpu[pos].label_class = cls;
                    top_cpu[pos].health = health;
                    top_cpu[pos].cpu_delta_100ns = active.cpu_delta_100ns;
                    top_cpu[pos].cpu_pct_x100 = active.cpu_pct_x100;
                }
            }
            if (s.active_labels.size() < 900) {
                char item[360];
                _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s#%llu:%s:class=%s:life=%s:health=%s:tid=%lu:age_ms=%llu:queued_age_ms=%llu:cpu_delta_100ns=%llu:cpu_pct_x100=%u:alive=%d:gle=%lu",
                    s.active_labels.empty() ? "" : ";",
                    static_cast<unsigned long long>(active.id),
                    active.label.empty() ? "<unnamed>" : active.label.c_str(),
                    cls,
                    lifetime,
                    health,
                    static_cast<unsigned long>(active.tid),
                    static_cast<unsigned long long>(age_ms),
                    static_cast<unsigned long long>(queued_age_ms),
                    static_cast<unsigned long long>(active.cpu_delta_100ns),
                    static_cast<unsigned>(active.cpu_pct_x100),
                    active.thread_alive ? 1 : 0,
                    static_cast<unsigned long>(active.thread_query_gle));
                s.active_labels += item;
            }
        }
        for (std::size_t i = 0; i < top_cpu_count; ++i) {
            char item[260];
            _snprintf_s(item, sizeof(item), _TRUNCATE,
                "%s#%llu:%s:class=%s:cpu_delta_100ns=%llu:cpu_pct_x100=%u:health=%s",
                s.top_cpu_labels.empty() ? "" : ";",
                static_cast<unsigned long long>(top_cpu[i].task_id),
                top_cpu[i].label.empty() ? "<unnamed>" : top_cpu[i].label.c_str(),
                top_cpu[i].label_class,
                static_cast<unsigned long long>(top_cpu[i].cpu_delta_100ns),
                static_cast<unsigned>(top_cpu[i].cpu_pct_x100),
                top_cpu[i].health);
            s.top_cpu_labels += item;
        }
    }
    return s;
}

inline stats_t domain_stats(executor_domain_t d) {
    pool_t& p = domain_pool(d);
    return stats_for(p, p.configured_pool_size, safe_pool_name(p));
}

inline std::uint32_t pool_live_worker_count(executor_domain_t domain) noexcept {
    pool_t& p = domain_pool(domain);
    const std::size_t live = p.worker_count.load(std::memory_order_acquire);
    if (live != 0)
        return static_cast<std::uint32_t>(live);
    const int configured = p.configured_pool_size;
    return configured > 0 ? static_cast<std::uint32_t>(configured) : 0u;
}

inline std::uint32_t analysis_compute_capacity() noexcept {
    const std::uint32_t live = pool_live_worker_count(executor_domain_t::feature_worker);
    if (live < 2u)
        return 2u;
    if (live > 64u)
        return 64u;
    return live;
}

inline std::uint64_t fairness_wait_percentile_ns(executor_domain_t domain, double rank) noexcept {
    pool_t& p = domain_pool(domain);
    std::array<std::uint64_t, 1024> samples{};
    const std::uint64_t written =
        static_cast<std::uint64_t>(p.fairness_wait_ns_ring_next.load(std::memory_order_acquire));
    const std::size_t count = written < 1024u ? static_cast<std::size_t>(written) : 1024u;
    if (count == 0)
        return 0;
    for (std::size_t i = 0; i < count; ++i)
        samples[i] = p.fairness_wait_ns_ring[i].load(std::memory_order_acquire);
    std::sort(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(count));
    double clamped_rank = rank;
    if (clamped_rank < 0.0)
        clamped_rank = 0.0;
    if (clamped_rank > 1.0)
        clamped_rank = 1.0;
    const std::size_t index =
        static_cast<std::size_t>(static_cast<double>(count - 1u) * clamped_rank);
    return samples[index];
}

inline std::vector<stuck_worker_diag_t> stuck_workers_for(pool_t& p, const char* pool_name, std::uint64_t threshold_ms, std::size_t max_records) {
    register_pool(p);
    std::vector<stuck_worker_diag_t> result;
    const std::uint64_t current = now_ms();
    std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
    if (!lk.owns_lock())
        return result;
    const std::size_t pending = static_cast<std::size_t>(p.pending_tasks.load(std::memory_order_acquire));
    for (std::size_t i = 0; i < p.active_snapshots.size(); ++i) {
        if (max_records != 0 && result.size() >= max_records)
            break;
        auto& active = p.active_snapshots[i];
        if (active.id == 0)
            continue;
        refresh_active_thread_sample(active, current);
        const std::uint64_t age_ms = current >= active.started_ms ? current - active.started_ms : 0;
        if (age_ms < threshold_ms)
            continue;
        const char* cls = classify_worker_label(active.label, default_class_for(p.family));
        const char* lifetime = worker_lifetime_label(p.family, pool_name, cls);
        stuck_worker_diag_t d;
        d.task_id = active.id;
        d.label = active.label;
        d.label_class = cls;
        d.lifetime = lifetime;
        d.health = worker_health_label(p.family, lifetime, active.thread_alive, active.cpu_pct_x100, pending, p.shutting_down.load(std::memory_order_acquire));
        d.tid = active.tid;
        d.thread_query_gle = active.thread_query_gle;
        d.exit_code = active.exit_code;
        d.queued_ms = active.queued_ms;
        d.started_ms = active.started_ms;
        d.active_ms = age_ms;
        d.cpu_delta_100ns = active.cpu_delta_100ns;
        d.cpu_pct_x100 = active.cpu_pct_x100;
        d.worker_index = i;
        d.thread_alive = active.thread_alive;
        result.push_back(std::move(d));
    }
    return result;
}

inline std::vector<stuck_worker_diag_t> stuck_workers(std::uint64_t threshold_ms, std::size_t max_records) {
    std::vector<pool_t*> pools;
    {
        std::lock_guard<std::mutex> lk(g_pool_registry_mtx);
        pools = g_registered_pools;
    }
    std::vector<stuck_worker_diag_t> out;
    for (auto* p : pools) {
        if (!p)
            continue;
        auto part = stuck_workers_for(*p, safe_pool_name(*p), threshold_ms, max_records == 0 ? 0 : max_records - out.size());
        out.insert(out.end(), part.begin(), part.end());
        if (max_records != 0 && out.size() >= max_records)
            break;
    }
    return out;
}

inline void log_stuck_workers_for(pool_t& p, const char* pool_name, std::uint64_t threshold_ms, std::size_t max_records) {
    auto stuck = stuck_workers_for(p, pool_name, threshold_ms, max_records);
    if (stuck.empty())
        return;
    std::size_t pending = static_cast<std::size_t>(p.pending_tasks.load(std::memory_order_acquire));
    bool lock_busy = false;
    {
        std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
        if (lk.owns_lock())
            pending = static_cast<std::size_t>(p.pending_tasks.load(std::memory_order_acquire));
        else
            lock_busy = true;
    }
    const std::uint64_t current = now_ms();
    for (const auto& s : stuck) {
        const std::uint64_t queued_age_ms = s.queued_ms != 0 && current >= s.queued_ms ? current - s.queued_ms : 0;
        diag::log_tagged_fmt(safe_log_tag(p),
            "stuck_worker pool=%s task_id=%llu label=%s class=%s lifetime=%s health=%s long_lived_hint=%d worker_index=%zu tid=%lu thread_alive=%d thread_gle=%lu exit_code=0x%08lX active_ms=%llu queued_age_ms=%llu threshold_ms=%llu cpu_delta_100ns=%llu cpu_pct_x100=%u cancellation=%s active=%u pending=%zu pending_lock_busy=%d post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu shutting_down=%d",
            pool_name ? pool_name : safe_pool_name(p),
            static_cast<unsigned long long>(s.task_id),
            s.label.empty() ? "<unnamed>" : s.label.c_str(),
            s.label_class,
            s.lifetime,
            s.health,
            worker_label_long_lived_hint(s.label_class) ? 1 : 0,
            s.worker_index,
            static_cast<unsigned long>(s.tid),
            s.thread_alive ? 1 : 0,
            static_cast<unsigned long>(s.thread_query_gle),
            static_cast<unsigned long>(s.exit_code),
            static_cast<unsigned long long>(s.active_ms),
            static_cast<unsigned long long>(queued_age_ms),
            static_cast<unsigned long long>(threshold_ms),
            static_cast<unsigned long long>(s.cpu_delta_100ns),
            static_cast<unsigned>(s.cpu_pct_x100),
            p.shutting_down.load(std::memory_order_acquire) ? "shutdown_requested" : "not_requested",
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            pending,
            lock_busy ? 1 : 0,
            static_cast<unsigned long long>(p.post_attempts.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.posted_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.rejected_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
            p.shutting_down.load(std::memory_order_acquire) ? 1 : 0);
    }
}

inline void log_stuck_workers(std::uint64_t threshold_ms, std::size_t max_records) {
    std::vector<pool_t*> pools;
    {
        std::lock_guard<std::mutex> lk(g_pool_registry_mtx);
        pools = g_registered_pools;
    }
    std::size_t emitted = 0;
    for (auto* p : pools) {
        if (!p)
            continue;
        const std::size_t remaining = max_records == 0 ? 0 : max_records - emitted;
        auto stuck = stuck_workers_for(*p, safe_pool_name(*p), threshold_ms, remaining);
        if (stuck.empty())
            continue;
        emitted += stuck.size();
        log_stuck_workers_for(*p, safe_pool_name(*p), threshold_ms, remaining);
        if (max_records != 0 && emitted >= max_records)
            break;
    }
}

inline bool post_to(pool_t& p, int pool_size, std::function<void()> f, const char* label) {
    task_descriptor_t desc;
    desc.owner_subsystem = safe_pool_name(p);
    desc.label = label && *label ? label : (p.default_label && *p.default_label ? p.default_label : "taskflow.task");
    desc.domain = p.family == pool_family_t::critical ? executor_domain_t::critical : (p.family == pool_family_t::service ? executor_domain_t::service : executor_domain_t::general);
    desc.body = std::move(f);
    auto result = submit_to_pool(p, pool_size, std::move(desc));
    return result.submitted;
}

inline bool pool_drained(const pool_t& p) {
    if (p.pending_tasks.load(std::memory_order_acquire) != 0 ||
        p.active_tasks.load(std::memory_order_acquire) != 0)
        return false;
    auto& mutable_pool = const_cast<pool_t&>(p);
    std::lock_guard<std::mutex> lk(mutable_pool.mtx);
    if (mutable_pool.deferred_nodes != 0 || mutable_pool.lane_in_flight != 0 ||
        !mutable_pool.admission_queue.empty())
        return false;
    for (const auto& lane : mutable_pool.priority_lanes) {
        if (!lane.empty())
            return false;
    }
    return true;
}

inline void cancel_deferred_records(pool_t& p) {
    std::vector<std::shared_ptr<job_record_t>> deferred;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        deferred.swap(p.admission_queue);
        p.deferred_nodes = 0;
    }
    for (auto& record : deferred) {
        if (!record)
            continue;
        record->admission_pending = false;
        record->pending_flow.reset();
        if (record->cancel_token)
            record->cancel_token->requested.store(true, std::memory_order_release);
        std::function<void()> cancel_hook;
        {
            std::lock_guard<std::mutex> lk(record->mtx);
            if (!record->cancel_hook_invoked) {
                record->cancel_hook_invoked = true;
                cancel_hook = std::move(record->cancel_hook);
            }
        }
        if (mark_record_finalized(record, job_state_t::cancelled, {})) {
            p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
            p.cancelled_tasks.fetch_add(1u, std::memory_order_acq_rel);
            g_total_cancelled.fetch_add(1u, std::memory_order_acq_rel);
        }
        release_record_reservation(record);
        invoke_cancel_hook_noexcept(record, std::move(cancel_hook));
    }
}

inline bool all_pools_quiescent() {
    std::vector<pool_t*> pools;
    {
        std::lock_guard<std::mutex> lk(g_pool_registry_mtx);
        pools = g_registered_pools;
    }
    for (auto* p : pools) {
        if (p && !pool_drained(*p))
            return false;
    }
    return true;
}

inline bool shutdown_pool(pool_t& p, const char* name, std::uint32_t timeout_ms) {
    if (p.shutdown_called.load(std::memory_order_acquire)) return true;
    bool expected = false;
    if (!p.shutdown_in_progress.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire)) return false;
    struct progress_guard_t {
        std::atomic<bool>& value;
        ~progress_guard_t() { value.store(false, std::memory_order_release); }
    } progress_guard{p.shutdown_in_progress};
    p.stop_accepting.store(true, std::memory_order_release);
    p.shutting_down.store(true, std::memory_order_release);
    cancel_deferred_records(p);
    std::shared_ptr<tf::Executor> executor;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        executor = load_executor(p);
    }
    const bool called_from_taskflow_worker = executor && executor->this_worker_id() >= 0;
    if (called_from_taskflow_worker) {
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_shutdown_deferred pool=%s reason=called_from_taskflow_worker active=%u pending=%llu started=%llu finished=%llu tid=%lu",
            name ? name : safe_pool_name(p),
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.pending_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    pump_lanes(p);
    const ULONGLONG start = GetTickCount64();
    const bool infinite_wait = timeout_ms == INFINITE;
    const ULONGLONG deadline = infinite_wait ? 0 : start + timeout_ms;
    while (!pool_drained(p)) {
        if (!infinite_wait && GetTickCount64() >= deadline)
            break;
        Sleep(10);
    }
    if (!pool_drained(p)) {
        const ULONGLONG current = GetTickCount64();
        diag::log_tagged_fmt(safe_log_tag(p),
            "taskflow_shutdown_timeout pool=%s timeout_ms=%lu elapsed_ms=%llu active=%u pending=%llu started=%llu finished=%llu tid=%lu",
            name ? name : safe_pool_name(p),
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(current >= start ? current - start : 0),
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.pending_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long>(GetCurrentThreadId()));
        log_stuck_workers_for(p, name, 0ULL, 16);
        return false;
    }
    std::shared_ptr<tf::Executor> owned_executor;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        owned_executor = load_executor(p);
        store_executor(p, {});
    }
    if (owned_executor) {
        try {
            owned_executor->wait_for_all();
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt(safe_log_tag(p),
                "taskflow_wait_for_all_exception pool=%s err=%s tid=%lu",
                name ? name : safe_pool_name(p),
                ex.what(),
                static_cast<unsigned long>(GetCurrentThreadId()));
        } catch (...) {
            diag::log_tagged_fmt(safe_log_tag(p),
                "taskflow_wait_for_all_exception pool=%s err=unknown tid=%lu",
                name ? name : safe_pool_name(p),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
        owned_executor.reset();
    }
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        for (auto& active : p.active_snapshots)
            active = {};
    }
    p.worker_count.store(0, std::memory_order_release);
    p.alive.store(false, std::memory_order_release);
    p.shutdown_called.store(true, std::memory_order_release);
    const ULONGLONG end = GetTickCount64();
    diag::log_tagged_fmt(safe_log_tag(p),
        "taskflow_shutdown_complete pool=%s elapsed_ms=%llu active=%u pending=%llu started=%llu finished=%llu tid=%lu",
        name ? name : safe_pool_name(p),
        static_cast<unsigned long long>(end >= start ? end - start : 0),
        static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(p.pending_tasks.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

inline runtime_snapshot_t active_snapshot(std::size_t max_jobs = 64) {
    runtime_snapshot_t snap;
    snap.total_submitted = g_total_submitted.load(std::memory_order_acquire);
    snap.total_rejected = g_total_rejected.load(std::memory_order_acquire);
    snap.total_cancelled = g_total_cancelled.load(std::memory_order_acquire);
    snap.total_failed = g_total_failed.load(std::memory_order_acquire);
    snap.total_timed_out = g_total_timed_out.load(std::memory_order_acquire);
    snap.accepting = !g_stop_accepting.load(std::memory_order_acquire);
    snap.shutting_down = g_shutdown_requested.load(std::memory_order_acquire);
    const std::uint64_t current = now_ms();
    {
        std::lock_guard<std::mutex> jobs_lk(g_jobs_mtx);
        for (const auto& kv : g_jobs) {
            auto record = kv.second;
            if (!record)
                continue;
            std::lock_guard<std::mutex> record_lk(record->mtx);
            if (!record->active)
                continue;
            ++snap.total_active;
            const std::size_t idx = domain_index(record->domain);
            if (idx < executor_domain_count)
                ++snap.active_per_domain[idx];
            const std::uint64_t age = record->queued_ms != 0 && current >= record->queued_ms ? current - record->queued_ms : 0;
            if (age > snap.oldest_active_ms)
                snap.oldest_active_ms = age;
            if (snap.labels_under_pressure.size() < 900) {
                if (!snap.labels_under_pressure.empty())
                    snap.labels_under_pressure += ";";
                snap.labels_under_pressure += "#";
                snap.labels_under_pressure += std::to_string(record->id);
                snap.labels_under_pressure += ":";
                snap.labels_under_pressure += record->label;
                snap.labels_under_pressure += ":";
                snap.labels_under_pressure += job_state_name(record->state);
            }
            if (snap.active_jobs.size() < max_jobs) {
                active_job_snapshot_t item;
                item.job_id = record->id;
                item.domain = record->domain;
                item.state = record->state;
                item.label = record->label;
                item.owner_subsystem = record->owner_subsystem;
                item.exception_text = record->exception_text;
                item.target_id = record->target_id;
                item.priority = record->priority;
                item.queued_ms = record->queued_ms;
                item.started_ms = record->started_ms;
                item.finished_ms = record->finished_ms;
                item.queued_ns = record->queued_ns;
                item.started_ns = record->started_ns;
                item.fairness_wait_ns = record->fairness_wait_ns;
                item.service_units = record->service_units;
                item.deadline_ms = record->deadline_ms;
                item.capacity_lease = record->capacity_lease;
                item.active_ms = age;
                item.node_count = static_cast<std::uint32_t>(record->nodes.size());
                item.graph = record->graph;
                item.cancellation_requested = record->cancel_token && record->cancel_token->requested.load(std::memory_order_acquire);
                snap.active_jobs.push_back(std::move(item));
            }
        }
    }
    std::vector<pool_t*> pools;
    {
        std::lock_guard<std::mutex> lk(g_pool_registry_mtx);
        pools = g_registered_pools;
    }
    for (auto* p : pools) {
        if (!p)
            continue;
        const auto active = p->active_tasks.load(std::memory_order_acquire);
        const auto pending = p->pending_tasks.load(std::memory_order_acquire);
        if (p->family == pool_family_t::service) {
            snap.service_queue_active += active;
            snap.service_queue_pending += pending;
        } else if (p->family == pool_family_t::critical) {
            snap.critical_queue_active += active;
            snap.critical_queue_pending += pending;
        } else {
            snap.work_queue_active += active;
            snap.work_queue_pending += pending;
        }
    }
    return snap;
}

inline void json_append_escaped(std::string& out, const std::string& s) {
    for (char c : s) {
        if (c == '"' || c == '\\')
            out += '\\';
        if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else {
            out += c;
        }
    }
}

inline std::string snapshot_json_string() {
    auto snap = active_snapshot(32);
    std::string out;
    out.reserve(4096);
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"total_submitted\":%llu,\"total_rejected\":%llu,\"total_cancelled\":%llu,\"total_failed\":%llu,\"total_timed_out\":%llu,\"total_active\":%u,\"oldest_active_ms\":%llu,\"accepting\":%d,\"shutting_down\":%d,\"work_queue_active\":%u,\"service_queue_active\":%u,\"critical_queue_active\":%u,\"work_queue_pending\":%llu,\"service_queue_pending\":%llu,\"critical_queue_pending\":%llu,\"domains\":[",
        static_cast<unsigned long long>(snap.total_submitted),
        static_cast<unsigned long long>(snap.total_rejected),
        static_cast<unsigned long long>(snap.total_cancelled),
        static_cast<unsigned long long>(snap.total_failed),
        static_cast<unsigned long long>(snap.total_timed_out),
        static_cast<unsigned>(snap.total_active),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        snap.accepting ? 1 : 0,
        snap.shutting_down ? 1 : 0,
        static_cast<unsigned>(snap.work_queue_active),
        static_cast<unsigned>(snap.service_queue_active),
        static_cast<unsigned>(snap.critical_queue_active),
        static_cast<unsigned long long>(snap.work_queue_pending),
        static_cast<unsigned long long>(snap.service_queue_pending),
        static_cast<unsigned long long>(snap.critical_queue_pending));
    out += buf;
    for (std::size_t i = 0; i < executor_domain_count; ++i) {
        if (i > 0)
            out += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"name\":\"%s\",\"active\":%u}",
            domain_name(static_cast<executor_domain_t>(i)),
            static_cast<unsigned>(snap.active_per_domain[i]));
        out += buf;
    }
    out += "],\"active_jobs\":[";
    for (std::size_t i = 0; i < snap.active_jobs.size(); ++i) {
        const auto& j = snap.active_jobs[i];
        if (i > 0)
            out += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"id\":%llu,\"domain\":\"%s\",\"state\":\"%s\",\"active_ms\":%llu,\"deadline_ms\":%llu,\"graph\":%d,\"nodes\":%u,\"cancel\":%d,\"owner\":\"",
            static_cast<unsigned long long>(j.job_id),
            domain_name(j.domain),
            job_state_name(j.state),
            static_cast<unsigned long long>(j.active_ms),
            static_cast<unsigned long long>(j.deadline_ms),
            j.graph ? 1 : 0,
            static_cast<unsigned>(j.node_count),
            j.cancellation_requested ? 1 : 0);
        out += buf;
        json_append_escaped(out, j.owner_subsystem);
        out += "\",\"label\":\"";
        json_append_escaped(out, j.label);
        out += "\",\"exception\":\"";
        json_append_escaped(out, j.exception_text);
        out += "\"}";
    }
    out += "],\"labels_under_pressure\":\"";
    json_append_escaped(out, snap.labels_under_pressure);
    out += "\"}";
    return out;
}

inline bool shutdown(std::uint32_t timeout_ms = 15000) {
    g_shutdown_requested.store(true, std::memory_order_release);
    g_stop_accepting.store(true, std::memory_order_release);
    bool complete = true;
    for (;;) {
        job_handle_t cancel_pending;
        try {
            std::lock_guard<std::mutex> jobs_lk(g_jobs_mtx);
            for (const auto& entry : g_jobs) {
                const auto& record = entry.second;
                if (!record) continue;
                std::lock_guard<std::mutex> record_lk(record->mtx);
                if (record->active && record->shutdown_policy == "cancel_pending"
                    && (!record->cancel_token
                        || !record->cancel_token->requested.load(std::memory_order_acquire))) {
                    cancel_pending.id = record->id;
                    break;
                }
            }
        } catch (...) {
            complete = false;
            break;
        }
        if (!cancel_pending.valid()) break;
        try {
            if (!cancel(cancel_pending)) complete = false;
        } catch (...) {
            complete = false;
            break;
        }
    }
    const std::uint64_t started = now_ms();
    const std::uint64_t deadline = timeout_ms == INFINITE
        ? (std::numeric_limits<std::uint64_t>::max)()
        : started + static_cast<std::uint64_t>(timeout_ms);
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        auto& pool = domain_pool(static_cast<executor_domain_t>(index));
        const std::uint64_t current = now_ms();
        const std::uint32_t remaining = timeout_ms == INFINITE
            ? INFINITE
            : current >= deadline ? 0u
            : static_cast<std::uint32_t>((std::min<std::uint64_t>)(deadline - current,
                static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));
        if (!shutdown_pool(pool, safe_pool_name(pool), remaining)) complete = false;
    }
    return complete;
}

struct shutdown_guard_t {
    ~shutdown_guard_t() noexcept { try { static_cast<void>(shutdown()); } catch (...) {} }
};

inline shutdown_guard_t g_shutdown_guard;

}

#endif
