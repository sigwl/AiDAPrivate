#include "publication_indexes.hpp"

#include "../xref_db.hpp"
#include "parallel_pass.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <limits>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>

namespace aida::analysis::publication_indexes {

namespace {

constexpr std::uint64_t kCacheByteCap = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kCacheGenerationCap = 2;
constexpr std::size_t kDegreeLaneCap = 8;

std::atomic<bool> g_probe_armed{false};
std::atomic<std::uint64_t> g_probe_count{0};

inline void probe_tick() noexcept {
    if (g_probe_armed.load(std::memory_order_relaxed))
        g_probe_count.fetch_add(1, std::memory_order_relaxed);
}

workspace_error_t build_cancel_error(const cancellation_token_t& cancel,
                                     const char* phase) {
    const bool deadline = cancel.deadline_exceeded();
    auto error = make_workspace_error(
        deadline ? workspace_error_code_t::deadline_exceeded
                 : workspace_error_code_t::cancelled,
        deadline ? "Publication index deadline expired"
                 : "Publication index build was cancelled",
        phase);
    error.deadline = deadline;
    error.cancellation = !deadline;
    return error;
}

inline bool xref_stk_less(const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
    if (lhs.source != rhs.source) return lhs.source < rhs.source;
    if (lhs.target != rhs.target) return lhs.target < rhs.target;
    return lhs.kind < rhs.kind;
}

inline bool edge_stk_less(const edge_record_t& lhs, const edge_record_t& rhs) noexcept {
    if (lhs.source != rhs.source) return lhs.source < rhs.source;
    if (lhs.target != rhs.target) return lhs.target < rhs.target;
    return lhs.kind < rhs.kind;
}

inline bool key_less(const detail::key_entry_t& key, address_space_id_t space,
                     std::uint64_t value) noexcept {
    return key.space < space || (key.space == space && key.value < value);
}

inline bool key_matches(const detail::key_entry_t& key, address_space_id_t space,
                        std::uint64_t value) noexcept {
    return key.space == space && key.value == value;
}

std::size_t key_lower_bound(const std::vector<detail::key_entry_t>& keys,
                            address_space_id_t space, std::uint64_t value) noexcept {
    std::size_t lo = 0;
    std::size_t hi = keys.size();
    while (lo < hi) {
        probe_tick();
        const std::size_t mid = lo + (hi - lo) / 2;
        if (key_less(keys[mid], space, value))
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

struct scatter_record_t {
    std::uint64_t value = 0;
    std::uint32_t ordinal = 0;
    address_space_id_t space = address_space_id_t::relative_virtual;
};

static_assert(sizeof(scatter_record_t) == 16,
              "publication index scatter records must remain 16 bytes");

workspace_result_t<void> build_csr(
    const snapshot_table_t<xref_record_t>& xrefs, bool by_target,
    const cancellation_token_t& cancel, const char* phase,
    std::shared_ptr<const std::vector<detail::key_entry_t>>& keys_out,
    std::shared_ptr<const std::vector<std::uint32_t>>& entries_out) {
    const std::size_t count = xrefs.size();
    auto keys = std::make_shared<std::vector<detail::key_entry_t>>();
    auto entries = std::make_shared<std::vector<std::uint32_t>>();
    if (count > (std::numeric_limits<std::uint32_t>::max)()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "Publication xref count exceeds the index ordinal range", phase));
    }
    if (count == 0) {
        keys_out = std::move(keys);
        entries_out = std::move(entries);
        return workspace_result_t<void>::success();
    }
    std::vector<scatter_record_t> records(count);
    std::atomic<bool> stopped{false};
    const auto fill_shards = parallel_shards(count, 0);
    parallel_executor_t::run(fill_shards.size(),
        static_cast<std::uint32_t>(fill_shards.size()),
        "publication_indexes.csr_fill", [&](std::size_t shard) {
            const auto range = fill_shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if ((index & 0x3FFFu) == 0 && cancel.stop_requested()) {
                    stopped.store(true, std::memory_order_relaxed);
                    return;
                }
                if (stopped.load(std::memory_order_relaxed))
                    return;
                const auto& record = xrefs[index];
                const auto& address = by_target ? record.target : record.source;
                records[index] = scatter_record_t{address.value,
                    static_cast<std::uint32_t>(index), address.space};
            }
        });
    if (stopped.load(std::memory_order_relaxed) || cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    parallel_sort(records.begin(), records.end(),
        [](const scatter_record_t& lhs, const scatter_record_t& rhs) noexcept {
            if (lhs.space != rhs.space) return lhs.space < rhs.space;
            if (lhs.value != rhs.value) return lhs.value < rhs.value;
            return lhs.ordinal < rhs.ordinal;
        });
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    std::atomic<std::uint64_t> boundary_total{0};
    const auto boundary_shards = parallel_shards(count - 1, 0);
    parallel_executor_t::run(boundary_shards.size(),
        static_cast<std::uint32_t>(boundary_shards.size()),
        "publication_indexes.csr_runs", [&](std::size_t shard) {
            const auto range = boundary_shards[shard];
            std::uint64_t local = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                const auto& prev = records[index];
                const auto& curr = records[index + 1];
                if (prev.space != curr.space || prev.value != curr.value)
                    ++local;
            }
            boundary_total.fetch_add(local, std::memory_order_relaxed);
        });
    const std::size_t key_count = static_cast<std::size_t>(boundary_total.load()) + 1;
    keys->resize(key_count);
    entries->resize(count);
    std::size_t key_cursor = 0;
    std::size_t run_begin = 0;
    std::uint64_t walked = 0;
    while (run_begin < count) {
        std::size_t run_end = run_begin + 1;
        while (run_end < count && records[run_end].space == records[run_begin].space &&
               records[run_end].value == records[run_begin].value)
            ++run_end;
        auto& key = (*keys)[key_cursor++];
        key.value = records[run_begin].value;
        key.offset = static_cast<std::uint32_t>(run_begin);
        key.space = records[run_begin].space;
        const std::size_t crossed = walked >> 20;
        walked += run_end - run_begin;
        if ((walked >> 20) != crossed && cancel.stop_requested())
            return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
        run_begin = run_end;
    }
    const auto scatter_shards = parallel_shards(count, 0);
    parallel_executor_t::run(scatter_shards.size(),
        static_cast<std::uint32_t>(scatter_shards.size()),
        "publication_indexes.csr_scatter", [&](std::size_t shard) {
            const auto range = scatter_shards[shard];
            auto* output = entries->data();
            for (std::size_t index = range.begin; index < range.end; ++index)
                output[index] = records[index].ordinal;
        });
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    keys_out = std::move(keys);
    entries_out = std::move(entries);
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> verify_xref_order(
    const snapshot_table_t<xref_record_t>& xrefs,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = xrefs.size();
    if (count < 2)
        return workspace_result_t<bool>::success(true);
    std::atomic<bool> violated{false};
    const auto shards = parallel_shards(count - 1, 0);
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.verify_xrefs", [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if ((index & 0x3FFFu) == 0 &&
                    (violated.load(std::memory_order_relaxed) || cancel.stop_requested())) {
                    violated.store(true, std::memory_order_relaxed);
                    return;
                }
                if (xref_stk_less(xrefs[index + 1], xrefs[index])) {
                    violated.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(build_cancel_error(cancel, phase));
    return workspace_result_t<bool>::success(!violated.load(std::memory_order_relaxed));
}

workspace_result_t<void> build_source_keys(
    const snapshot_table_t<xref_record_t>& xrefs,
    const cancellation_token_t& cancel, const char* phase,
    std::shared_ptr<const std::vector<detail::key_entry_t>>& keys_out) {
    const std::size_t count = xrefs.size();
    auto keys = std::make_shared<std::vector<detail::key_entry_t>>();
    if (count == 0) {
        keys_out = std::move(keys);
        return workspace_result_t<void>::success();
    }
    const auto shards = parallel_shards(count, 0);
    std::vector<std::vector<detail::key_entry_t>> locals(shards.size());
    std::atomic<bool> stopped{false};
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.source_keys", [&](std::size_t shard) {
            const auto range = shards[shard];
            auto& local = locals[shard];
            local.reserve(range.end - range.begin > 256 ? 256 : range.end - range.begin);
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if ((index & 0x3FFFu) == 0 && cancel.stop_requested()) {
                    stopped.store(true, std::memory_order_relaxed);
                    return;
                }
                if (stopped.load(std::memory_order_relaxed))
                    return;
                const auto& record = xrefs[index];
                if (index == range.begin ||
                    xrefs[index - 1].source.space != record.source.space ||
                    xrefs[index - 1].source.value != record.source.value) {
                    local.push_back(detail::key_entry_t{record.source.value,
                        static_cast<std::uint32_t>(index), record.source.space});
                }
            }
        });
    if (stopped.load(std::memory_order_relaxed) || cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    std::size_t total = 0;
    for (const auto& local : locals)
        total += local.size();
    keys->reserve(total);
    for (std::size_t shard = 0; shard < shards.size(); ++shard) {
        for (const auto& key : locals[shard]) {
            if (!keys->empty() && key_matches(keys->back(), key.space, key.value))
                continue;
            keys->push_back(key);
        }
    }
    keys_out = std::move(keys);
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> verify_functions(
    const std::vector<function_record_t>& functions,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = functions.size();
    if (count < 2)
        return workspace_result_t<bool>::success(true);
    std::atomic<bool> violated{false};
    const auto shards = parallel_shards(count - 1, 0);
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.verify_functions", [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (violated.load(std::memory_order_relaxed))
                    return;
                const auto& prev = functions[index];
                const auto& curr = functions[index + 1];
                const bool sorted = prev.start.space < curr.start.space ||
                    (prev.start.space == curr.start.space &&
                     prev.start.value <= curr.start.value);
                const bool disjoint = prev.start.space != curr.start.space ||
                    prev.end.value <= curr.start.value;
                if (!sorted || !disjoint) {
                    violated.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(build_cancel_error(cancel, phase));
    return workspace_result_t<bool>::success(!violated.load(std::memory_order_relaxed));
}

workspace_result_t<std::shared_ptr<const detail::function_exact_map_t>>
build_function_exact_fallback(
    const std::vector<function_record_t>& functions,
    const cancellation_token_t& cancel, const char* phase) {
    auto map = std::make_shared<detail::function_exact_map_t>();
    map->reserve(functions.size());
    for (std::size_t index = 0; index < functions.size(); ++index) {
        if ((index & 0x3FFFu) == 0 && cancel.stop_requested())
            return workspace_result_t<
                std::shared_ptr<const detail::function_exact_map_t>>::failure(
                    build_cancel_error(cancel, phase));
        const auto& function = functions[index];
        map->emplace(detail::address_key_t{function.start.value, function.start.space},
                     static_cast<std::uint32_t>(index));
    }
    return workspace_result_t<std::shared_ptr<const detail::function_exact_map_t>>::success(
        std::move(map));
}

workspace_result_t<bool> verify_edge_order(
    const snapshot_table_t<edge_record_t>& edges,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = edges.size();
    if (count < 2)
        return workspace_result_t<bool>::success(true);
    std::atomic<bool> violated{false};
    const auto shards = parallel_shards(count - 1, 0);
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.verify_edges", [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (violated.load(std::memory_order_relaxed))
                    return;
                if (edge_stk_less(edges[index + 1], edges[index])) {
                    violated.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(build_cancel_error(cancel, phase));
    return workspace_result_t<bool>::success(!violated.load(std::memory_order_relaxed));
}

workspace_result_t<std::shared_ptr<const std::vector<std::uint32_t>>>
build_edge_source_ordinals(
    const snapshot_table_t<edge_record_t>& edges,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = edges.size();
    auto ordinals = std::make_shared<std::vector<std::uint32_t>>(count);
    if (count > (std::numeric_limits<std::uint32_t>::max)()) {
        return workspace_result_t<
            std::shared_ptr<const std::vector<std::uint32_t>>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "Publication edge count exceeds the index ordinal range", phase));
    }
    for (std::size_t index = 0; index < count; ++index)
        (*ordinals)[index] = static_cast<std::uint32_t>(index);
    parallel_sort(ordinals->begin(), ordinals->end(),
        [&edges](std::uint32_t lhs, std::uint32_t rhs) noexcept {
            const auto& left = edges[lhs].source;
            const auto& right = edges[rhs].source;
            if (left.space != right.space) return left.space < right.space;
            if (left.value != right.value) return left.value < right.value;
            return lhs < rhs;
        });
    if (cancel.stop_requested())
        return workspace_result_t<
            std::shared_ptr<const std::vector<std::uint32_t>>>::failure(
                build_cancel_error(cancel, phase));
    return workspace_result_t<std::shared_ptr<const std::vector<std::uint32_t>>>::success(
        std::move(ordinals));
}

const function_record_t* panel_enclosing(
    const std::vector<const function_record_t*>& ordered,
    const address_t& address) noexcept {
    auto found = std::upper_bound(ordered.begin(), ordered.end(), address,
        [](const address_t& value, const function_record_t* function) noexcept {
            return value < function->start;
        });
    if (found == ordered.begin())
        return nullptr;
    --found;
    const function_record_t* function = *found;
    if (address.space != function->start.space ||
        address.value < function->start.value ||
        address.value >= function->end.value)
        return nullptr;
    return function;
}

workspace_result_t<void> build_call_degrees(
    const analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel, const char* phase,
    std::shared_ptr<const std::vector<std::uint32_t>>& calls_in_out,
    std::shared_ptr<const std::vector<std::uint32_t>>& calls_out_out) {
    const auto& functions = snapshot.functions;
    const auto& edges = snapshot.edges;
    auto calls_in = std::make_shared<std::vector<std::uint32_t>>(functions.size(), 0);
    auto calls_out = std::make_shared<std::vector<std::uint32_t>>(functions.size(), 0);
    if (functions.empty() || edges.empty()) {
        calls_in_out = std::move(calls_in);
        calls_out_out = std::move(calls_out);
        return workspace_result_t<void>::success();
    }
    std::vector<const function_record_t*> ordered;
    ordered.reserve(functions.size());
    for (const auto& function : functions)
        ordered.push_back(&function);
    std::sort(ordered.begin(), ordered.end(),
        [](const function_record_t* left, const function_record_t* right) noexcept {
            return left->start < right->start;
        });
    const std::uint32_t lane_count = static_cast<std::uint32_t>((std::min)(
        static_cast<std::size_t>(parallel_worker_count()), kDegreeLaneCap));
    const auto shards = parallel_shards(edges.size(), lane_count);
    const std::size_t lane_total = shards.size();
    std::vector<std::vector<std::uint32_t>> lane_in(lane_total);
    std::vector<std::vector<std::uint32_t>> lane_out(lane_total);
    std::atomic<bool> stopped{false};
    parallel_executor_t::run(lane_total, static_cast<std::uint32_t>(lane_total),
        "publication_indexes.call_degrees", [&](std::size_t lane) {
            auto& local_in = lane_in[lane];
            auto& local_out = lane_out[lane];
            local_in.assign(functions.size(), 0);
            local_out.assign(functions.size(), 0);
            const auto range = shards[lane];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if ((index & 0x3FFFu) == 0 && cancel.stop_requested()) {
                    stopped.store(true, std::memory_order_relaxed);
                    return;
                }
                if (stopped.load(std::memory_order_relaxed))
                    return;
                const auto& edge = edges[index];
                if (edge.kind != edge_kind_t::call && edge.kind != edge_kind_t::tail_call)
                    continue;
                const auto* caller = panel_enclosing(ordered, edge.source);
                const auto* callee = panel_enclosing(ordered, edge.target);
                if (caller) {
                    const auto ordinal = static_cast<std::size_t>(caller - functions.data());
                    if (local_out[ordinal] != (std::numeric_limits<std::uint32_t>::max)())
                        ++local_out[ordinal];
                }
                if (callee) {
                    const auto ordinal = static_cast<std::size_t>(callee - functions.data());
                    if (local_in[ordinal] != (std::numeric_limits<std::uint32_t>::max)())
                        ++local_in[ordinal];
                }
            }
        });
    if (stopped.load(std::memory_order_relaxed) || cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    for (std::size_t lane = 0; lane < lane_total; ++lane) {
        for (std::size_t ordinal = 0; ordinal < functions.size(); ++ordinal) {
            const std::uint32_t in_value = lane_in[lane][ordinal];
            const std::uint32_t out_value = lane_out[lane][ordinal];
            auto& merged_in = (*calls_in)[ordinal];
            auto& merged_out = (*calls_out)[ordinal];
            if (merged_in != (std::numeric_limits<std::uint32_t>::max)()) {
                merged_in = in_value == 0 ? merged_in
                    : merged_in > (std::numeric_limits<std::uint32_t>::max)() - in_value
                        ? (std::numeric_limits<std::uint32_t>::max)()
                        : merged_in + in_value;
            }
            if (merged_out != (std::numeric_limits<std::uint32_t>::max)()) {
                merged_out = out_value == 0 ? merged_out
                    : merged_out > (std::numeric_limits<std::uint32_t>::max)() - out_value
                        ? (std::numeric_limits<std::uint32_t>::max)()
                        : merged_out + out_value;
            }
        }
    }
    calls_in_out = std::move(calls_in);
    calls_out_out = std::move(calls_out);
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> verify_symbol_order(
    const std::vector<symbol_record_t>& symbols,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = symbols.size();
    if (count < 2)
        return workspace_result_t<bool>::success(true);
    std::atomic<bool> violated{false};
    const auto shards = parallel_shards(count - 1, 0);
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.verify_symbols", [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (violated.load(std::memory_order_relaxed))
                    return;
                const auto& prev = symbols[index].address;
                const auto& curr = symbols[index + 1].address;
                if (curr.space < prev.space ||
                    (curr.space == prev.space && curr.value < prev.value)) {
                    violated.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    if (cancel.stop_requested())
        return workspace_result_t<bool>::failure(build_cancel_error(cancel, phase));
    return workspace_result_t<bool>::success(!violated.load(std::memory_order_relaxed));
}

workspace_result_t<std::shared_ptr<const std::vector<std::uint32_t>>>
build_symbol_ordinals(
    const std::vector<symbol_record_t>& symbols,
    const cancellation_token_t& cancel, const char* phase) {
    const std::size_t count = symbols.size();
    auto ordinals = std::make_shared<std::vector<std::uint32_t>>(count);
    if (count > (std::numeric_limits<std::uint32_t>::max)()) {
        return workspace_result_t<
            std::shared_ptr<const std::vector<std::uint32_t>>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "Publication symbol count exceeds the index ordinal range", phase));
    }
    for (std::size_t index = 0; index < count; ++index)
        (*ordinals)[index] = static_cast<std::uint32_t>(index);
    parallel_sort(ordinals->begin(), ordinals->end(),
        [&symbols](std::uint32_t lhs, std::uint32_t rhs) noexcept {
            const auto& left = symbols[lhs].address;
            const auto& right = symbols[rhs].address;
            if (left.space != right.space) return left.space < right.space;
            if (left.value != right.value) return left.value < right.value;
            return lhs < rhs;
        });
    if (cancel.stop_requested())
        return workspace_result_t<
            std::shared_ptr<const std::vector<std::uint32_t>>>::failure(
                build_cancel_error(cancel, phase));
    return workspace_result_t<std::shared_ptr<const std::vector<std::uint32_t>>>::success(
        std::move(ordinals));
}

bool xref_records_equal(const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
    return lhs.id == rhs.id && lhs.source == rhs.source && lhs.target == rhs.target &&
        lhs.kind == rhs.kind && lhs.provenance == rhs.provenance &&
        lhs.confidence == rhs.confidence;
}

bool edge_records_equal(const edge_record_t& lhs, const edge_record_t& rhs) noexcept {
    return lhs.id == rhs.id && lhs.source_entity == rhs.source_entity &&
        lhs.target_entity == rhs.target_entity && lhs.source == rhs.source &&
        lhs.target == rhs.target && lhs.kind == rhs.kind &&
        lhs.provenance == rhs.provenance && lhs.confidence == rhs.confidence;
}

bool function_records_equal(const analysis_snapshot_t& lhs_snapshot,
                            const function_record_t& lhs,
                            const analysis_snapshot_t& rhs_snapshot,
                            const function_record_t& rhs) noexcept {
    if (lhs.id != rhs.id || lhs.start != rhs.start || lhs.end != rhs.end ||
        lhs.symbol_id != rhs.symbol_id || lhs.first_block != rhs.first_block ||
        lhs.block_count != rhs.block_count || lhs.first_chunk != rhs.first_chunk ||
        lhs.chunk_count != rhs.chunk_count ||
        lhs.first_block_membership != rhs.first_block_membership ||
        lhs.block_membership_count != rhs.block_membership_count ||
        lhs.provenance != rhs.provenance || lhs.confidence != rhs.confidence ||
        lhs.thunk != rhs.thunk || lhs.noreturn != rhs.noreturn)
        return false;
    const auto left = lhs_snapshot.function_chunks_of(lhs);
    const auto right = rhs_snapshot.function_chunks_of(rhs);
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index].rva_start != right[index].rva_start ||
            left[index].rva_end != right[index].rva_end ||
            left[index].chunk_kind != right[index].chunk_kind)
            return false;
    }
    return true;
}

bool symbol_records_equal(const symbol_record_t& lhs, const symbol_record_t& rhs) noexcept {
    return lhs.id == rhs.id && lhs.address == rhs.address && lhs.name == rhs.name &&
        lhs.kind == rhs.kind && lhs.provenance == rhs.provenance &&
        lhs.confidence == rhs.confidence;
}

bool call_graph_quality_equal(const call_graph_quality_t& lhs,
                              const call_graph_quality_t& rhs) noexcept {
    return lhs.provenance == rhs.provenance && lhs.confidence == rhs.confidence &&
        lhs.contributor_count == rhs.contributor_count && lhs.conflicted == rhs.conflicted;
}

bool call_graph_content_equal(const call_graph_publication_t& lhs,
                              const call_graph_publication_t& rhs) noexcept {
    if (lhs.nodes.size() != rhs.nodes.size() ||
        lhs.call_sites.size() != rhs.call_sites.size() ||
        lhs.candidates.size() != rhs.candidates.size() ||
        lhs.edges.size() != rhs.edges.size() ||
        lhs.conflicts.size() != rhs.conflicts.size() ||
        lhs.indirect_site_count != rhs.indirect_site_count ||
        lhs.unresolved_site_count != rhs.unresolved_site_count ||
        lhs.bounded != rhs.bounded)
        return false;
    for (std::size_t index = 0; index < lhs.nodes.size(); ++index) {
        const auto& left = lhs.nodes[index];
        const auto& right = rhs.nodes[index];
        if (left.function_id != right.function_id || left.address != right.address ||
            left.incoming_edges != right.incoming_edges ||
            left.outgoing_edges != right.outgoing_edges ||
            left.indirect_edges != right.indirect_edges ||
            left.unresolved_sites != right.unresolved_sites)
            return false;
    }
    for (std::size_t index = 0; index < lhs.call_sites.size(); ++index) {
        const auto& left = lhs.call_sites[index];
        const auto& right = rhs.call_sites[index];
        if (left.id != right.id || left.source_function_id != right.source_function_id ||
            left.source_block_id != right.source_block_id ||
            left.instruction_id != right.instruction_id || left.address != right.address ||
            left.first_candidate != right.first_candidate ||
            left.candidate_count != right.candidate_count ||
            left.indirect != right.indirect || left.tail_call != right.tail_call ||
            left.unresolved != right.unresolved)
            return false;
    }
    for (std::size_t index = 0; index < lhs.candidates.size(); ++index) {
        const auto& left = lhs.candidates[index];
        const auto& right = rhs.candidates[index];
        if (left.id != right.id || left.call_site_id != right.call_site_id ||
            left.target != right.target ||
            left.target_function_id != right.target_function_id ||
            left.kind != right.kind || !call_graph_quality_equal(left.quality, right.quality) ||
            left.stable_source_id != right.stable_source_id || left.rank != right.rank ||
            left.external_target != right.external_target)
            return false;
    }
    for (std::size_t index = 0; index < lhs.edges.size(); ++index) {
        const auto& left = lhs.edges[index];
        const auto& right = rhs.edges[index];
        if (left.id != right.id || left.call_site_id != right.call_site_id ||
            left.source_function_id != right.source_function_id ||
            left.source_block_id != right.source_block_id ||
            left.target_function_id != right.target_function_id ||
            left.call_site != right.call_site || left.target != right.target ||
            left.resolution != right.resolution ||
            !call_graph_quality_equal(left.quality, right.quality) ||
            left.candidate_rank != right.candidate_rank ||
            left.external_target != right.external_target ||
            left.target_noreturn != right.target_noreturn)
            return false;
    }
    for (std::size_t index = 0; index < lhs.conflicts.size(); ++index) {
        const auto& left = lhs.conflicts[index];
        const auto& right = rhs.conflicts[index];
        if (left.id != right.id || left.kind != right.kind ||
            left.instruction_id != right.instruction_id ||
            left.source_function_id != right.source_function_id ||
            left.call_site_rva != right.call_site_rva ||
            left.selected_target_rva != right.selected_target_rva ||
            left.competing_target_rva != right.competing_target_rva)
            return false;
    }
    return true;
}

template <typename Record, typename Equal>
bool domain_content_equal(const Record* lhs, const Record* rhs, std::size_t count,
                          Equal&& equal, const cancellation_token_t& cancel) {
    if (count == 0)
        return true;
    std::atomic<bool> mismatch{false};
    const auto shards = parallel_shards(count, 0);
    parallel_executor_t::run(shards.size(), static_cast<std::uint32_t>(shards.size()),
        "publication_indexes.gate_compare", [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if ((index & 0x3FFFu) == 0 &&
                    (mismatch.load(std::memory_order_relaxed) || cancel.stop_requested())) {
                    mismatch.store(true, std::memory_order_relaxed);
                    return;
                }
                if (!equal(lhs[index], rhs[index])) {
                    mismatch.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    return !mismatch.load(std::memory_order_relaxed);
}

enum class cache_state_t : std::uint32_t {
    idle = 0,
    building = 1,
    ready = 2
};

struct cache_entry_t {
    explicit cache_entry_t(
        const std::weak_ptr<const analysis_snapshot_t>& snapshot_value)
        : snapshot_weak(snapshot_value) {}

    std::weak_ptr<const analysis_snapshot_t> snapshot_weak;
    mutable std::shared_mutex gate;
    std::atomic<std::uint32_t> state{static_cast<std::uint32_t>(cache_state_t::idle)};
    std::shared_ptr<const publication_indexes_t> indexes;
    std::atomic<std::uint64_t> accounted{0};
    std::atomic<std::uint64_t> last_use{0};
    std::atomic<std::uint32_t> users{0};
};

struct cache_t {
    std::mutex mutex;
    std::map<const analysis_snapshot_t*, std::shared_ptr<cache_entry_t>> entries;
    std::atomic<std::uint64_t> tick{0};
};

cache_t& cache() {
    static cache_t value;
    return value;
}

void cache_evict(const analysis_snapshot_t* current) {
    auto& store = cache();
    std::lock_guard<std::mutex> lock(store.mutex);
    const auto total_bytes = [&store]() {
        std::uint64_t total = 0;
        for (const auto& item : store.entries)
            total += item.second->accounted.load(std::memory_order_acquire);
        return total;
    };
    const auto evict_oldest = [&store, current]() {
        const analysis_snapshot_t* victim = nullptr;
        std::uint64_t oldest = (std::numeric_limits<std::uint64_t>::max)();
        for (const auto& item : store.entries) {
            if (item.first == current)
                continue;
            const auto& entry = *item.second;
            if (entry.state.load(std::memory_order_acquire) ==
                    static_cast<std::uint32_t>(cache_state_t::building) ||
                entry.users.load(std::memory_order_acquire) != 0)
                continue;
            const std::uint64_t tick = entry.last_use.load(std::memory_order_acquire);
            if (tick < oldest) {
                oldest = tick;
                victim = item.first;
            }
        }
        if (!victim)
            return false;
        const auto found = store.entries.find(victim);
        auto& entry = *found->second;
        const std::uint64_t accounted = entry.accounted.load(std::memory_order_acquire);
        std::uint64_t still_live = 0;
        {
            std::shared_lock<std::shared_mutex> read(entry.gate, std::try_to_lock);
            if (read.owns_lock() && entry.indexes)
                still_live = entry.indexes->live_fresh_bytes();
        }
        std::uint64_t transferred = 0;
        if (still_live != 0 && still_live <= accounted) {
            cache_entry_t* newest = nullptr;
            std::uint64_t newest_tick = 0;
            for (const auto& item : store.entries) {
                if (item.first == victim)
                    continue;
                auto& candidate = *item.second;
                if (candidate.state.load(std::memory_order_acquire) !=
                        static_cast<std::uint32_t>(cache_state_t::ready))
                    continue;
                const std::uint64_t tick =
                    candidate.last_use.load(std::memory_order_acquire);
                if (!newest || tick > newest_tick) {
                    newest = &candidate;
                    newest_tick = tick;
                }
            }
            if (newest) {
                std::shared_lock<std::shared_mutex> read(newest->gate, std::try_to_lock);
                if (read.owns_lock() && newest->indexes) {
                    newest->indexes->account_transferred_bytes(still_live);
                    newest->accounted.fetch_add(still_live, std::memory_order_acq_rel);
                    transferred = still_live;
                }
            }
        }
        const std::uint64_t freed = accounted - transferred;
        diag::log_tagged_fmt("publication_indexes",
            "cache_evict snapshot=%p accounted=%llu freed=%llu transferred=%llu",
            static_cast<const void*>(victim),
            static_cast<unsigned long long>(accounted),
            static_cast<unsigned long long>(freed),
            static_cast<unsigned long long>(transferred));
        store.entries.erase(found);
        return true;
    };
    while (store.entries.size() > kCacheGenerationCap && evict_oldest()) {
    }
    while (total_bytes() > kCacheByteCap && evict_oldest()) {
    }
    if (total_bytes() > kCacheByteCap) {
        diag::log_tagged_fmt("publication_indexes",
            "cache_over_cap bytes=%llu cap=%llu",
            static_cast<unsigned long long>(total_bytes()),
            static_cast<unsigned long long>(kCacheByteCap));
    }
}

std::shared_ptr<const publication_indexes_t> cache_gate_candidate(
    const analysis_snapshot_t* exclude) {
    auto& store = cache();
    std::vector<std::shared_ptr<cache_entry_t>> candidates;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        candidates.reserve(store.entries.size());
        for (const auto& item : store.entries) {
            if (item.first != exclude)
                candidates.push_back(item.second);
        }
    }
    std::shared_ptr<const publication_indexes_t> best;
    std::uint64_t best_tick = 0;
    for (const auto& entry : candidates) {
        if (entry->state.load(std::memory_order_acquire) !=
            static_cast<std::uint32_t>(cache_state_t::ready))
            continue;
        std::shared_lock<std::shared_mutex> read(entry->gate, std::try_to_lock);
        if (!read.owns_lock())
            continue;
        if (!entry->indexes)
            continue;
        const std::uint64_t tick = entry->last_use.load(std::memory_order_acquire);
        if (!best || tick > best_tick) {
            best = entry->indexes;
            best_tick = tick;
        }
    }
    return best;
}

void cache_forget(const analysis_snapshot_t* key) {
    auto& store = cache();
    std::lock_guard<std::mutex> lock(store.mutex);
    store.entries.erase(key);
}


workspace_result_t<std::shared_ptr<const publication_indexes_t>> for_publication_impl(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const hints_t& hints, const cancellation_token_t& cancel) {
    constexpr const char* phase = "publication_indexes.for_publication";
    if (!publication || !publication->snapshot) {
        return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                "Publication indexes require a published snapshot", phase));
    }
    const analysis_snapshot_t* key = publication->snapshot.get();
    auto& store = cache();
    std::shared_ptr<cache_entry_t> entry;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        auto found = store.entries.find(key);
        if (found != store.entries.end()) {
            const auto guard = found->second->snapshot_weak.lock();
            if (!guard || guard.get() != key) {
                store.entries.erase(found);
                found = store.entries.end();
            }
        }
        if (found == store.entries.end()) {
            entry = std::make_shared<cache_entry_t>(
                std::weak_ptr<const analysis_snapshot_t>(publication->snapshot));
            store.entries.emplace(key, entry);
        } else {
            entry = found->second;
        }
        entry->users.fetch_add(1, std::memory_order_acq_rel);
        entry->last_use.store(store.tick.fetch_add(1, std::memory_order_relaxed) + 1,
            std::memory_order_release);
    }
    struct user_guard_t {
        cache_entry_t* entry;
        ~user_guard_t() { entry->users.fetch_sub(1, std::memory_order_acq_rel); }
    } user_guard{entry.get()};
    {
        std::shared_lock<std::shared_mutex> read(entry->gate);
        if (entry->state.load(std::memory_order_acquire) ==
                static_cast<std::uint32_t>(cache_state_t::ready) &&
            entry->indexes)
            return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::success(
                entry->indexes);
    }
    std::unique_lock<std::shared_mutex> write(entry->gate);
    if (entry->state.load(std::memory_order_acquire) ==
            static_cast<std::uint32_t>(cache_state_t::ready) &&
        entry->indexes) {
        return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::success(
            entry->indexes);
    }
    entry->state.store(static_cast<std::uint32_t>(cache_state_t::building),
        std::memory_order_release);
    workspace_result_t<std::shared_ptr<const publication_indexes_t>> built =
        workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "Publication index build did not run", phase));
    try {
        built = publication_indexes_t::build(publication, hints, cancel);
    } catch (const std::bad_alloc&) {
        built = workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            make_workspace_error(workspace_error_code_t::io_failure,
                "Publication index build ran out of memory", phase));
    } catch (const std::exception& exception) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
            "Publication index build failed with an exception", phase);
        error.details.emplace_back("exception", exception.what());
        built = workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            std::move(error));
    } catch (...) {
        built = workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "Publication index build failed with an unknown exception", phase));
    }
    if (!built) {
        entry->state.store(static_cast<std::uint32_t>(cache_state_t::idle),
            std::memory_order_release);
        diag::log_tagged_fmt("publication_indexes",
            "build_failed snapshot=%p code=%s message=%s",
            static_cast<const void*>(key),
            workspace_error_code_name(built.error().code),
            built.error().message.c_str());
        return built;
    }
    entry->indexes = built.value();
    entry->accounted.store(built.value()->accounted_bytes(), std::memory_order_release);
    entry->state.store(static_cast<std::uint32_t>(cache_state_t::ready),
        std::memory_order_release);
    const auto result = entry->indexes;
    write.unlock();
    cache_evict(key);
    return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::success(
        std::move(result));
}

}

void publication_indexes_t::register_fresh_array(
    const std::shared_ptr<const void>& array, std::uint64_t bytes) {
    {
        std::lock_guard<std::mutex> lock(fresh_arrays_mutex_);
        fresh_arrays_.emplace_back(array, bytes);
    }
    bytes_.fetch_add(bytes, std::memory_order_relaxed);
    accounted_bytes_.fetch_add(bytes, std::memory_order_relaxed);
}

std::uint64_t publication_indexes_t::live_fresh_bytes() const noexcept {
    std::lock_guard<std::mutex> lock(fresh_arrays_mutex_);
    std::uint64_t live = 0;
    for (const auto& item : fresh_arrays_) {
        if (item.first.use_count() > 2)
            live += item.second;
    }
    return live;
}

xref_range_t publication_indexes_t::xrefs_to(const address_t& target) const noexcept {
    xref_range_t range;
    const auto& keys = *target_keys_;
    const std::size_t found = key_lower_bound(keys, target.space, target.value);
    if (found >= keys.size() || !key_matches(keys[found], target.space, target.value))
        return range;
    range.begin = keys[found].offset;
    range.end = found + 1 < keys.size() ? keys[found + 1].offset
        : static_cast<std::uint32_t>(target_entries_->size());
    return range;
}

xref_range_t publication_indexes_t::xrefs_from(const address_t& source) const noexcept {
    xref_range_t range;
    const auto& keys = *source_keys_;
    const std::size_t found = key_lower_bound(keys, source.space, source.value);
    if (found >= keys.size() || !key_matches(keys[found], source.space, source.value))
        return range;
    range.begin = keys[found].offset;
    range.end = found + 1 < keys.size() ? keys[found + 1].offset
        : static_cast<std::uint32_t>(source_order_verified_
            ? snapshot_->xrefs.size() : source_entries_->size());
    return range;
}

std::uint32_t publication_indexes_t::xref_to_entry(std::uint32_t ordinal) const noexcept {
    return (*target_entries_)[ordinal];
}

std::uint32_t publication_indexes_t::xref_from_entry(std::uint32_t ordinal) const noexcept {
    return source_order_verified_ ? ordinal : (*source_entries_)[ordinal];
}

std::uint64_t publication_indexes_t::xref_count_to(const address_t& target) const noexcept {
    const auto range = xrefs_to(target);
    return range.end - range.begin;
}

std::size_t publication_indexes_t::xref_target_key_count() const noexcept {
    return target_keys_->size();
}

address_t publication_indexes_t::xref_target_key_at(std::size_t index) const noexcept {
    const auto& key = (*target_keys_)[index];
    return address_t{key.space, key.value};
}

xref_range_t publication_indexes_t::xref_target_run_at(std::size_t index) const noexcept {
    xref_range_t range;
    const auto& keys = *target_keys_;
    range.begin = keys[index].offset;
    range.end = index + 1 < keys.size() ? keys[index + 1].offset
        : static_cast<std::uint32_t>(target_entries_->size());
    return range;
}

const function_record_t* publication_indexes_t::function_containing(
    const address_t& addr) const noexcept {
    const auto& functions = snapshot_->functions;
    if (functions_verified_) {
        std::size_t lo = 0;
        std::size_t hi = functions.size();
        while (lo < hi) {
            probe_tick();
            const std::size_t mid = lo + (hi - lo) / 2;
            const auto& function = functions[mid];
            if (addr.space < function.start.space ||
                (addr.space == function.start.space && addr.value < function.start.value))
                hi = mid;
            else
                lo = mid + 1;
        }
        if (lo == 0)
            return nullptr;
        const auto& function = functions[lo - 1];
        if (function.start.space != addr.space || addr.value < function.start.value ||
            addr.value >= function.end.value)
            return nullptr;
        return &function;
    }
    for (const auto& function : functions) {
        if (function.start.space != addr.space)
            continue;
        if (addr.value >= function.start.value && addr.value < function.end.value)
            return &function;
    }
    return nullptr;
}

const function_record_t* publication_indexes_t::function_at_exact_start(
    const address_t& addr) const noexcept {
    const auto& functions = snapshot_->functions;
    if (functions_verified_) {
        std::size_t lo = 0;
        std::size_t hi = functions.size();
        while (lo < hi) {
            probe_tick();
            const std::size_t mid = lo + (hi - lo) / 2;
            const auto& function = functions[mid];
            if (function.start.space < addr.space ||
                (function.start.space == addr.space && function.start.value < addr.value))
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo >= functions.size())
            return nullptr;
        const auto& function = functions[lo];
        if (function.start.space != addr.space || function.start.value != addr.value)
            return nullptr;
        return &function;
    }
    if (function_exact_fallback_) {
        const auto found = function_exact_fallback_->find(
            detail::address_key_t{addr.value, addr.space});
        if (found != function_exact_fallback_->end())
            return &functions[found->second];
    }
    return nullptr;
}

bool publication_indexes_t::functions_sorted_disjoint() const noexcept {
    return functions_verified_;
}

xref_range_t publication_indexes_t::call_edges_from(
    const function_record_t& fn) const noexcept {
    xref_range_t range;
    const auto& edges = snapshot_->edges;
    const auto lower = [&](address_space_id_t space, std::uint64_t value) {
        std::size_t lo = 0;
        std::size_t hi = edge_order_verified_ ? edges.size()
            : edge_source_ordinals_->size();
        while (lo < hi) {
            probe_tick();
            const std::size_t mid = lo + (hi - lo) / 2;
            const auto& source = edge_order_verified_
                ? edges[mid].source : edges[(*edge_source_ordinals_)[mid]].source;
            if (source.space < space || (source.space == space && source.value < value))
                lo = mid + 1;
            else
                hi = mid;
        }
        return lo;
    };
    range.begin = static_cast<std::uint32_t>(lower(fn.start.space, fn.start.value));
    range.end = static_cast<std::uint32_t>(lower(fn.start.space, fn.end.value));
    return range;
}

std::uint32_t publication_indexes_t::call_edge_entry(std::uint32_t ordinal) const noexcept {
    return edge_order_verified_ ? ordinal : (*edge_source_ordinals_)[ordinal];
}

std::pair<std::uint32_t, std::uint32_t> publication_indexes_t::function_call_degree(
    std::size_t function_ordinal) const noexcept {
    if (!calls_in_ || function_ordinal >= calls_in_->size())
        return {0, 0};
    return {(*calls_in_)[function_ordinal], (*calls_out_)[function_ordinal]};
}

const symbol_record_t* publication_indexes_t::symbol_exact_named(
    const address_t& addr) const noexcept {
    const auto& symbols = snapshot_->symbols;
    const auto walk = [&](std::size_t begin) -> const symbol_record_t* {
        for (std::size_t index = begin; index < symbols.size(); ++index) {
            const auto& symbol = symbol_order_verified_
                ? symbols[index] : symbols[(*symbol_ordinals_)[index]];
            if (symbol.address.space != addr.space || symbol.address.value != addr.value)
                return nullptr;
            if (!symbol.name.empty())
                return &symbol;
        }
        return nullptr;
    };
    std::size_t lo = 0;
    std::size_t hi = symbol_order_verified_ ? symbols.size()
        : (symbol_ordinals_ ? symbol_ordinals_->size() : 0);
    while (lo < hi) {
        probe_tick();
        const std::size_t mid = lo + (hi - lo) / 2;
        const auto& address = symbol_order_verified_
            ? symbols[mid].address : symbols[(*symbol_ordinals_)[mid]].address;
        if (address.space < addr.space ||
            (address.space == addr.space && address.value < addr.value))
            lo = mid + 1;
        else
            hi = mid;
    }
    const std::size_t limit = symbol_order_verified_ ? symbols.size()
        : (symbol_ordinals_ ? symbol_ordinals_->size() : 0);
    if (lo >= limit)
        return nullptr;
    const auto& first = symbol_order_verified_
        ? symbols[lo] : symbols[(*symbol_ordinals_)[lo]];
    if (first.address.space != addr.space || first.address.value != addr.value)
        return nullptr;
    return walk(lo);
}

const symbol_record_t* publication_indexes_t::data_symbol_exact(
    const address_t& addr) const noexcept {
    const auto& symbols = snapshot_->symbols;
    std::size_t lo = 0;
    std::size_t hi = symbol_order_verified_ ? symbols.size()
        : (symbol_ordinals_ ? symbol_ordinals_->size() : 0);
    while (lo < hi) {
        probe_tick();
        const std::size_t mid = lo + (hi - lo) / 2;
        const auto& address = symbol_order_verified_
            ? symbols[mid].address : symbols[(*symbol_ordinals_)[mid]].address;
        if (address.space < addr.space ||
            (address.space == addr.space && address.value < addr.value))
            lo = mid + 1;
        else
            hi = mid;
    }
    const std::size_t limit = symbol_order_verified_ ? symbols.size()
        : (symbol_ordinals_ ? symbol_ordinals_->size() : 0);
    if (lo >= limit)
        return nullptr;
    for (std::size_t index = lo; index < limit; ++index) {
        const auto& symbol = symbol_order_verified_
            ? symbols[index] : symbols[(*symbol_ordinals_)[index]];
        if (symbol.address.space != addr.space || symbol.address.value != addr.value)
            return nullptr;
        if (symbol.kind != symbol_kind_t::function)
            return &symbol;
    }
    return nullptr;
}

namespace {

std::uint64_t snapshot_display_address(const pe_image_t* image,
                                       const address_t& address) noexcept {
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual)
        return address.value;
    if (!image)
        return 0;
    std::uint64_t rva = 0;
    if (address.space == address_space_id_t::relative_virtual) {
        rva = address.value;
    } else if (address.space == address_space_id_t::file_offset) {
        auto translated = image->file_offset_to_rva(address.value);
        if (!translated)
            return 0;
        rva = translated.value();
    } else {
        return 0;
    }
    if (rva >= image->image_size() || image->image_base() > (std::numeric_limits<std::uint64_t>::max)() - rva)
        return 0;
    return image->image_base() + rva;
}

workspace_result_t<std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>
materialize_call_graph(const analysis_snapshot_t& snapshot, std::size_t max_nodes,
                       const cancellation_token_t& cancel,
                       const std::function<bool()>& stop) {
    constexpr const char* phase = "xref_db.call_graph";
    std::vector<const function_record_t*> functions;
    functions.reserve(snapshot.functions.size());
    for (const auto& function : snapshot.functions)
        functions.push_back(&function);
    std::sort(functions.begin(), functions.end(),
        [](const function_record_t* left, const function_record_t* right) noexcept {
            return left->start < right->start;
        });
    std::unordered_map<entity_id_t, std::string> names;
    names.reserve(snapshot.symbols.size());
    for (const auto& symbol : snapshot.symbols) {
        if (!symbol.name.empty())
            names.emplace(symbol.id, symbol.name);
    }
    std::unordered_map<std::uint64_t, xref_db::call_graph_node_t> nodes;
    const auto enclosing = [&functions](const address_t& address)
        -> const function_record_t* {
        auto found = std::upper_bound(functions.begin(), functions.end(), address,
            [](const address_t& value, const function_record_t* function) noexcept {
                return value < function->start;
            });
        if (found == functions.begin())
            return nullptr;
        --found;
        const auto* function = *found;
        if (address.space != function->start.space ||
            address.value < function->start.value ||
            address.value >= function->end.value)
            return nullptr;
        return function;
    };
    const auto assign_name = [&names](xref_db::call_graph_node_t& node,
                                      const function_record_t* function) {
        if (!node.name.empty())
            return;
        if (function && function->symbol_id) {
            const auto found = names.find(*function->symbol_id);
            if (found != names.end())
                node.name = found->second;
        }
        if (node.name.empty()) {
            char text[32]{};
            std::snprintf(text, sizeof(text), "sub_%llX",
                static_cast<unsigned long long>(node.addr));
            node.name = text;
        }
    };
    const auto* image = snapshot.image.get();
    std::size_t visited = 0;
    for (const auto& edge : snapshot.xrefs) {
        if ((++visited & 0xFFFu) == 0 && stop()) {
            const bool deadline = cancel.deadline_exceeded();
            auto error = make_workspace_error(
                deadline ? workspace_error_code_t::deadline_exceeded
                         : workspace_error_code_t::cancelled,
                deadline ? "Xref database deadline expired"
                         : "Xref database request was cancelled",
                phase);
            error.deadline = deadline;
            error.cancellation = !deadline;
            return workspace_result_t<
                std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::failure(
                    std::move(error));
        }
        if (edge.kind != xref_kind_t::call)
            continue;
        const auto* caller_function = enclosing(edge.source);
        const auto* callee_function = enclosing(edge.target);
        const address_t& caller_address =
            caller_function ? caller_function->start : edge.source;
        const address_t& callee_address =
            callee_function ? callee_function->start : edge.target;
        const std::uint64_t caller = snapshot_display_address(image, caller_address);
        const std::uint64_t callee = snapshot_display_address(image, callee_address);
        if (caller == 0 || callee == 0)
            continue;
        auto& caller_node = nodes[caller];
        caller_node.addr = caller;
        auto& callee_node = nodes[callee];
        callee_node.addr = callee;
        assign_name(caller_node, caller_function);
        assign_name(callee_node, callee_function);
        caller_node.callees.push_back(callee);
        callee_node.callers.push_back(caller);
        if (nodes.size() > max_nodes) {
            return workspace_result_t<
                std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "Call graph exceeded its node limit", phase));
        }
    }
    auto result = std::make_shared<std::vector<xref_db::call_graph_node_t>>();
    result->reserve(nodes.size());
    for (auto& item : nodes)
        result->push_back(std::move(item.second));
    std::sort(result->begin(), result->end(),
        [](const xref_db::call_graph_node_t& left,
           const xref_db::call_graph_node_t& right) noexcept {
            return left.addr < right.addr;
        });
    for (auto& node : *result) {
        std::sort(node.callees.begin(), node.callees.end());
        node.callees.erase(std::unique(node.callees.begin(), node.callees.end()),
            node.callees.end());
        std::sort(node.callers.begin(), node.callers.end());
        node.callers.erase(std::unique(node.callers.begin(), node.callers.end()),
            node.callers.end());
    }
    return workspace_result_t<
        std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::success(
            std::move(result));
}

}

workspace_result_t<std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>
publication_indexes_t::call_graph(std::size_t max_nodes,
                                  const cancellation_token_t& cancel,
                                  std::function<bool()> stop) const {
    {
        std::shared_lock<std::shared_mutex> read(call_graph_mutex_);
        if (call_graph_memo_ && call_graph_memo_max_nodes_ == max_nodes)
            return workspace_result_t<
                std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::success(
                    call_graph_memo_);
    }
    std::unique_lock<std::shared_mutex> write(call_graph_mutex_);
    if (call_graph_memo_ && call_graph_memo_max_nodes_ == max_nodes) {
        return workspace_result_t<
            std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::success(
                call_graph_memo_);
    }
    const std::function<bool()> stopped = stop
        ? std::move(stop)
        : std::function<bool()>([&cancel] { return cancel.stop_requested(); });
    auto materialized = materialize_call_graph(*snapshot_, max_nodes, cancel, stopped);
    if (!materialized)
        return materialized;
    std::uint64_t memo_bytes = 0;
    for (const auto& node : *materialized.value()) {
        memo_bytes += sizeof(xref_db::call_graph_node_t) + node.name.size() +
            (node.callees.size() + node.callers.size()) * sizeof(std::uint64_t);
    }
    if (call_graph_memo_bytes_ != 0) {
        bytes_.fetch_sub(call_graph_memo_bytes_, std::memory_order_relaxed);
        accounted_bytes_.fetch_sub(call_graph_memo_bytes_, std::memory_order_relaxed);
    }
    call_graph_memo_ = materialized.value();
    call_graph_memo_max_nodes_ = max_nodes;
    call_graph_memo_bytes_ = memo_bytes;
    bytes_.fetch_add(memo_bytes, std::memory_order_relaxed);
    accounted_bytes_.fetch_add(memo_bytes, std::memory_order_relaxed);
    return workspace_result_t<
        std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>::success(
            std::move(materialized.value()));
}

namespace {

bool module_entry_less_to(const module_entry_t& lhs, const module_entry_t& rhs) noexcept {
    if (lhs.to != rhs.to) return lhs.to < rhs.to;
    if (lhs.from != rhs.from) return lhs.from < rhs.from;
    return lhs.type < rhs.type;
}

bool module_entry_less_from(const module_entry_t& lhs,
                            const module_entry_t& rhs) noexcept {
    if (lhs.from != rhs.from) return lhs.from < rhs.from;
    if (lhs.to != rhs.to) return lhs.to < rhs.to;
    return lhs.type < rhs.type;
}

void module_resort_tie_runs(std::vector<module_entry_t>& entries,
                            bool (*less)(const module_entry_t&, const module_entry_t&),
                            bool (*same_pair)(const module_entry_t&,
                                              const module_entry_t&)) {
    std::size_t run = 0;
    while (run < entries.size()) {
        std::size_t run_end = run + 1;
        while (run_end < entries.size() && same_pair(entries[run], entries[run_end]))
            ++run_end;
        if (run_end - run > 1) {
            std::stable_sort(entries.begin() + static_cast<std::ptrdiff_t>(run),
                entries.begin() + static_cast<std::ptrdiff_t>(run_end), less);
        }
        run = run_end;
    }
}

void module_verify_or_repair(std::vector<module_entry_t>& entries,
                             bool (*less)(const module_entry_t&, const module_entry_t&)) {
    for (std::size_t index = 1; index < entries.size(); ++index) {
        if (less(entries[index], entries[index - 1])) {
            std::stable_sort(entries.begin(), entries.end(), less);
            return;
        }
    }
}

}

workspace_result_t<std::pair<std::vector<module_entry_t>, std::vector<module_entry_t>>>
publication_indexes_t::module_index_pairs(
    const std::function<std::uint64_t(const address_t&)>& display_address,
    const std::function<int(xref_kind_t)>& map_kind,
    const cancellation_token_t& cancel,
    std::function<bool()> stop) const {
    constexpr const char* phase = "publication_indexes.module_index";
    const std::function<bool()> stopped = stop
        ? std::move(stop)
        : std::function<bool()>([&cancel] { return cancel.stop_requested(); });
    std::vector<module_entry_t> to_sorted;
    std::vector<module_entry_t> from_sorted;
    const auto& xrefs = snapshot_->xrefs;
    to_sorted.reserve(xrefs.size());
    from_sorted.reserve(xrefs.size());
    std::size_t visited = 0;
    for (const auto& record : xrefs) {
        if ((++visited & 0xFFFu) == 0 && stopped())
            return workspace_result_t<std::pair<std::vector<module_entry_t>,
                std::vector<module_entry_t>>>::failure(
                    build_cancel_error(cancel, phase));
        const std::uint64_t from = display_address(record.source);
        const std::uint64_t to = display_address(record.target);
        if (from == 0 || to == 0)
            continue;
        from_sorted.push_back(module_entry_t{from, to, map_kind(record.kind)});
    }
    module_resort_tie_runs(from_sorted, &module_entry_less_from,
        [](const module_entry_t& lhs, const module_entry_t& rhs) noexcept {
            return lhs.from == rhs.from && lhs.to == rhs.to;
        });
    module_verify_or_repair(from_sorted, &module_entry_less_from);
    const std::size_t key_total = xref_target_key_count();
    for (std::size_t key_index = 0; key_index < key_total; ++key_index) {
        if ((key_index & 0xFFFu) == 0 && stopped())
            return workspace_result_t<std::pair<std::vector<module_entry_t>,
                std::vector<module_entry_t>>>::failure(
                    build_cancel_error(cancel, phase));
        const auto range = xref_target_run_at(key_index);
        for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal) {
            const auto& record = xrefs[(*target_entries_)[ordinal]];
            const std::uint64_t from = display_address(record.source);
            const std::uint64_t to = display_address(record.target);
            if (from == 0 || to == 0)
                continue;
            to_sorted.push_back(module_entry_t{from, to, map_kind(record.kind)});
        }
    }
    module_resort_tie_runs(to_sorted, &module_entry_less_to,
        [](const module_entry_t& lhs, const module_entry_t& rhs) noexcept {
            return lhs.to == rhs.to && lhs.from == rhs.from;
        });
    module_verify_or_repair(to_sorted, &module_entry_less_to);
    return workspace_result_t<std::pair<std::vector<module_entry_t>,
        std::vector<module_entry_t>>>::success(
            {std::move(to_sorted), std::move(from_sorted)});
}

workspace_result_t<void> publication_indexes_t::build_impl(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const hints_t& hints, const cancellation_token_t& cancel,
    const std::shared_ptr<const publication_indexes_t>& previous,
    const std::shared_ptr<publication_indexes_t>& output) {
    constexpr const char* phase = "publication_indexes.build";
    if (!publication || !publication->snapshot) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                "Publication snapshot is not available", phase));
    }
    const auto& snapshot = *publication->snapshot;
    const struct {
        const void* data;
        std::size_t size;
        const char* name;
    } domains[] = {
        {static_cast<const void*>(snapshot.xrefs.data()), snapshot.xrefs.size(), "xrefs"},
        {static_cast<const void*>(snapshot.edges.data()), snapshot.edges.size(), "edges"},
        {static_cast<const void*>(snapshot.functions.data()), snapshot.functions.size(),
            "functions"},
        {static_cast<const void*>(snapshot.symbols.data()), snapshot.symbols.size(),
            "symbols"},
    };
    for (const auto& domain : domains) {
        if (domain.data == nullptr && domain.size != 0) {
            diag::log_tagged_fmt("publication_indexes",
                "domain_not_resident domain=%s count=%llu", domain.name,
                static_cast<unsigned long long>(domain.size));
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "Publication domain is not resident", phase);
            error.details.emplace_back("domain", domain.name);
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    const auto build_begin = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("publication_indexes",
        "build_start snapshot=%p xrefs=%llu functions=%llu edges=%llu symbols=%llu tid=%lu "
        "hints=%u%u%u%u%u previous=%d",
        static_cast<const void*>(publication->snapshot.get()),
        static_cast<unsigned long long>(snapshot.xrefs.size()),
        static_cast<unsigned long long>(snapshot.functions.size()),
        static_cast<unsigned long long>(snapshot.edges.size()),
        static_cast<unsigned long long>(snapshot.symbols.size()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        hints.xrefs_unchanged ? 1u : 0u, hints.functions_unchanged ? 1u : 0u,
        hints.edges_unchanged ? 1u : 0u, hints.call_graph_unchanged ? 1u : 0u,
        hints.symbols_unchanged ? 1u : 0u, previous ? 1 : 0);
    output->snapshot_ = publication->snapshot;
    bool alias_xrefs = false;
    bool alias_functions = false;
    bool alias_edges = false;
    bool alias_symbols = false;
    if (previous && previous->snapshot_) {
        const auto& prior = *previous->snapshot_;
        alias_xrefs = prior.xrefs.size() == snapshot.xrefs.size() &&
            domain_content_equal(prior.xrefs.data(), snapshot.xrefs.data(),
                snapshot.xrefs.size(), &xref_records_equal, cancel);
        alias_functions = prior.functions.size() == snapshot.functions.size() &&
            domain_content_equal(prior.functions.data(), snapshot.functions.data(),
                snapshot.functions.size(),
                [&prior, &snapshot](const function_record_t& lhs,
                                    const function_record_t& rhs) noexcept {
                    return function_records_equal(prior, lhs, snapshot, rhs);
                }, cancel);
        alias_edges = prior.edges.size() == snapshot.edges.size() &&
            domain_content_equal(prior.edges.data(), snapshot.edges.data(),
                snapshot.edges.size(), &edge_records_equal, cancel);
        alias_symbols = prior.symbols.size() == snapshot.symbols.size() &&
            domain_content_equal(prior.symbols.data(), snapshot.symbols.data(),
                snapshot.symbols.size(), &symbol_records_equal, cancel);
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    }
    diag::log_tagged_fmt("publication_indexes",
        "gate_decision xrefs=%s functions=%s edges=%s symbols=%s",
        alias_xrefs ? "alias_validated" : "rebuild",
        alias_functions ? "alias_validated" : "rebuild",
        alias_edges ? "alias_validated" : "rebuild",
        alias_symbols ? "alias_validated" : "rebuild");
    struct lane_failure_t {
        workspace_error_t error;
    };
    try {
        parallel_executor_t::run(4, 4, "publication_indexes.build", [&](std::size_t lane) {
        switch (lane) {
        case 0: {
            if (alias_xrefs && previous) {
                output->target_keys_ = previous->target_keys_;
                output->target_entries_ = previous->target_entries_;
                output->source_keys_ = previous->source_keys_;
                output->source_entries_ = previous->source_entries_;
                output->source_order_verified_ = previous->source_order_verified_;
                output->aliased_domains_.fetch_or(
                    detail::alias_domain_xrefs, std::memory_order_relaxed);
                output->bytes_.fetch_add(
                    previous->target_keys_->size() * sizeof(detail::key_entry_t) +
                    previous->target_entries_->size() * sizeof(std::uint32_t) +
                    previous->source_keys_->size() * sizeof(detail::key_entry_t) +
                    (previous->source_entries_
                        ? previous->source_entries_->size() * sizeof(std::uint32_t) : 0),
                    std::memory_order_relaxed);
                break;
            }
            std::shared_ptr<const std::vector<detail::key_entry_t>> target_keys;
            std::shared_ptr<const std::vector<std::uint32_t>> target_entries;
            auto built_target = build_csr(snapshot.xrefs, true, cancel, phase,
                target_keys, target_entries);
            if (!built_target) {
                throw lane_failure_t{std::move(built_target.error())};
            }
            auto verified = verify_xref_order(snapshot.xrefs, cancel, phase);
            if (!verified) {
                throw lane_failure_t{std::move(verified.error())};
            }
            std::shared_ptr<const std::vector<detail::key_entry_t>> source_keys;
            std::shared_ptr<const std::vector<std::uint32_t>> source_entries;
            if (verified.value()) {
                auto built_keys = build_source_keys(snapshot.xrefs, cancel, phase,
                    source_keys);
                if (!built_keys) {
                    throw lane_failure_t{std::move(built_keys.error())};
                }
            } else {
                diag::log_tagged_fmt("publication_indexes",
                    "source_order_unverified snapshot=%p action=stable_scatter_fallback",
                    static_cast<const void*>(publication->snapshot.get()));
                auto built_fallback = build_csr(snapshot.xrefs, false, cancel, phase,
                    source_keys, source_entries);
                if (!built_fallback) {
                    throw lane_failure_t{std::move(built_fallback.error())};
                }
            }
            output->target_keys_ = target_keys;
            output->target_entries_ = target_entries;
            output->source_keys_ = source_keys;
            output->source_entries_ = source_entries;
            output->source_order_verified_ = verified.value();
            output->register_fresh_array(target_keys,
                target_keys->size() * sizeof(detail::key_entry_t));
            output->register_fresh_array(target_entries,
                target_entries->size() * sizeof(std::uint32_t));
            output->register_fresh_array(source_keys,
                source_keys->size() * sizeof(detail::key_entry_t));
            if (source_entries) {
                output->register_fresh_array(source_entries,
                    source_entries->size() * sizeof(std::uint32_t));
            }
            break;
        }
        case 1: {
            if (alias_functions && previous) {
                output->functions_verified_ = previous->functions_verified_;
                output->function_exact_fallback_ = previous->function_exact_fallback_;
                output->aliased_domains_.fetch_or(
                    detail::alias_domain_functions, std::memory_order_relaxed);
                output->bytes_.fetch_add(
                    previous->function_exact_fallback_
                        ? previous->function_exact_fallback_->size() *
                            (sizeof(detail::address_key_t) + sizeof(std::uint32_t) + 16)
                        : 0,
                    std::memory_order_relaxed);
                break;
            }
            auto verified = verify_functions(snapshot.functions, cancel, phase);
            if (!verified) {
                throw lane_failure_t{std::move(verified.error())};
            }
            output->functions_verified_ = verified.value();
            if (!verified.value()) {
                diag::log_tagged_fmt("publication_indexes",
                    "functions_unverified snapshot=%p action=linear_and_exact_map_fallback",
                    static_cast<const void*>(publication->snapshot.get()));
                auto fallback = build_function_exact_fallback(snapshot.functions, cancel,
                    phase);
                if (!fallback) {
                    throw lane_failure_t{std::move(fallback.error())};
                }
                output->function_exact_fallback_ = fallback.value();
                output->register_fresh_array(fallback.value(),
                    fallback.value()->size() *
                        (sizeof(detail::address_key_t) + sizeof(std::uint32_t) + 16));
            }
            break;
        }
        case 2: {
            if (alias_edges && previous) {
                output->edge_order_verified_ = previous->edge_order_verified_;
                output->edge_source_ordinals_ = previous->edge_source_ordinals_;
                output->aliased_domains_.fetch_or(
                    detail::alias_domain_edges, std::memory_order_relaxed);
                output->bytes_.fetch_add(
                    previous->edge_source_ordinals_
                        ? previous->edge_source_ordinals_->size() * sizeof(std::uint32_t)
                        : 0,
                    std::memory_order_relaxed);
            } else {
                auto verified = verify_edge_order(snapshot.edges, cancel, phase);
                if (!verified) {
                    throw lane_failure_t{std::move(verified.error())};
                }
                output->edge_order_verified_ = verified.value();
                if (!verified.value()) {
                    diag::log_tagged_fmt("publication_indexes",
                        "edge_order_unverified snapshot=%p action=ordinal_sort_fallback",
                        static_cast<const void*>(publication->snapshot.get()));
                    auto ordinals = build_edge_source_ordinals(snapshot.edges, cancel,
                        phase);
                    if (!ordinals) {
                        throw lane_failure_t{std::move(ordinals.error())};
                    }
                    output->edge_source_ordinals_ = ordinals.value();
                    output->register_fresh_array(ordinals.value(),
                        ordinals.value()->size() * sizeof(std::uint32_t));
                }
            }
            if (alias_edges && alias_functions && previous) {
                output->calls_in_ = previous->calls_in_;
                output->calls_out_ = previous->calls_out_;
                output->bytes_.fetch_add(
                    (previous->calls_in_->size() + previous->calls_out_->size()) *
                        sizeof(std::uint32_t),
                    std::memory_order_relaxed);
            } else {
                std::shared_ptr<const std::vector<std::uint32_t>> calls_in;
                std::shared_ptr<const std::vector<std::uint32_t>> calls_out;
                auto degrees = build_call_degrees(snapshot, cancel, phase, calls_in,
                    calls_out);
                if (!degrees) {
                    throw lane_failure_t{std::move(degrees.error())};
                }
                output->calls_in_ = calls_in;
                output->calls_out_ = calls_out;
                output->register_fresh_array(calls_in,
                    calls_in->size() * sizeof(std::uint32_t));
                output->register_fresh_array(calls_out,
                    calls_out->size() * sizeof(std::uint32_t));
            }
            break;
        }
        case 3: {
            if (alias_symbols && previous) {
                output->symbol_order_verified_ = previous->symbol_order_verified_;
                output->symbol_ordinals_ = previous->symbol_ordinals_;
                output->aliased_domains_.fetch_or(
                    detail::alias_domain_symbols, std::memory_order_relaxed);
                output->bytes_.fetch_add(
                    previous->symbol_ordinals_
                        ? previous->symbol_ordinals_->size() * sizeof(std::uint32_t)
                        : 0,
                    std::memory_order_relaxed);
                break;
            }
            auto verified = verify_symbol_order(snapshot.symbols, cancel, phase);
            if (!verified) {
                throw lane_failure_t{std::move(verified.error())};
            }
            output->symbol_order_verified_ = verified.value();
            if (!verified.value()) {
                diag::log_tagged_fmt("publication_indexes",
                    "symbol_order_unverified snapshot=%p action=ordinal_sort_fallback",
                    static_cast<const void*>(publication->snapshot.get()));
                auto ordinals = build_symbol_ordinals(snapshot.symbols, cancel, phase);
                if (!ordinals) {
                    throw lane_failure_t{std::move(ordinals.error())};
                }
                output->symbol_ordinals_ = ordinals.value();
                output->register_fresh_array(ordinals.value(),
                    ordinals.value()->size() * sizeof(std::uint32_t));
            }
            break;
        }
        default:
            break;
        }
        });
    } catch (lane_failure_t& failure) {
        return workspace_result_t<void>::failure(std::move(failure.error));
    }
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(build_cancel_error(cancel, phase));
    if (previous && alias_xrefs && alias_functions && alias_symbols) {
        const bool call_graph_same =
            call_graph_content_equal(previous->snapshot_->call_graph, snapshot.call_graph);
        if (call_graph_same) {
            std::shared_lock<std::shared_mutex> read(previous->call_graph_mutex_);
            if (previous->call_graph_memo_) {
                output->call_graph_memo_ = previous->call_graph_memo_;
                output->call_graph_memo_max_nodes_ = previous->call_graph_memo_max_nodes_;
                output->call_graph_memo_bytes_ = previous->call_graph_memo_bytes_;
                output->bytes_.fetch_add(previous->call_graph_memo_bytes_,
                    std::memory_order_relaxed);
                output->accounted_bytes_.fetch_add(previous->call_graph_memo_bytes_,
                    std::memory_order_relaxed);
                output->aliased_domains_.fetch_or(
                    detail::alias_domain_call_graph, std::memory_order_relaxed);
            }
        }
    }
    const auto build_end = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("publication_indexes",
        "build_end snapshot=%p elapsed_ms=%lld bytes=%llu aliased=%x verified=%d%d%d%d tid=%lu",
        static_cast<const void*>(publication->snapshot.get()),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
            build_end - build_begin).count()),
        static_cast<unsigned long long>(output->bytes_.load(std::memory_order_relaxed)),
        output->aliased_domains_.load(std::memory_order_relaxed),
        output->source_order_verified_ ? 1 : 0, output->functions_verified_ ? 1 : 0,
        output->edge_order_verified_ ? 1 : 0, output->symbol_order_verified_ ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<const publication_indexes_t>>
publication_indexes_t::build(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const hints_t& hints, const cancellation_token_t& cancel) {
    if (!publication || !publication->snapshot) {
        return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                "Publication snapshot is not available", "publication_indexes.build"));
    }
    const auto previous = cache_gate_candidate(publication->snapshot.get());
    auto output = std::shared_ptr<publication_indexes_t>(new publication_indexes_t);
    auto built = build_impl(publication, hints, cancel, previous, output);
    if (!built) {
        return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::failure(
            std::move(built.error()));
    }
    return workspace_result_t<std::shared_ptr<const publication_indexes_t>>::success(
        std::shared_ptr<const publication_indexes_t>(std::move(output)));
}

workspace_result_t<std::shared_ptr<const publication_indexes_t>> for_publication_result(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel) {
    return for_publication_impl(publication, hints_t{}, cancel);
}

std::shared_ptr<const publication_indexes_t> for_publication(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel) {
    auto result = for_publication_impl(publication, hints_t{}, cancel);
    return result ? result.value() : nullptr;
}

void prebuild(const std::shared_ptr<const analysis_publication_t>& publication,
              const hints_t& hints) {
    if (!publication || !publication->snapshot)
        return;
    try {
        auto built = for_publication_impl(publication, hints, {});
        if (!built) {
            diag::log_tagged_fmt("publication_indexes",
                "prebuild_failed snapshot=%p code=%s message=%s",
                static_cast<const void*>(publication->snapshot.get()),
                workspace_error_code_name(built.error().code),
                built.error().message.c_str());
        }
    } catch (const std::exception& exception) {
        diag::log_tagged_fmt("publication_indexes",
            "prebuild_exception snapshot=%p exception=%s",
            static_cast<const void*>(publication->snapshot.get()), exception.what());
    } catch (...) {
        diag::log_tagged_fmt("publication_indexes",
            "prebuild_exception snapshot=%p exception=unknown",
            static_cast<const void*>(publication->snapshot.get()));
    }
}

namespace selftest {

struct rng_t {
    std::uint64_t state;
    explicit rng_t(std::uint64_t seed)
        : state(seed != 0 ? seed : 0x9E3779B97F4A7C15ULL) {}
    std::uint64_t next() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }
    std::uint64_t below(std::uint64_t n) {
        return n == 0 ? 0 : next() % n;
    }
};

struct corpus_config_t {
    std::size_t xrefs = 0;
    std::size_t unique_sources = 0;
    std::size_t unique_targets = 0;
    std::size_t functions = 0;
    std::size_t edges = 0;
    std::size_t symbols = 0;
    std::uint64_t generation = 1;
    std::uint64_t seed = 0;
    bool unsorted_xrefs = false;
    bool unsorted_functions = false;
    bool overlapping_functions = false;
    bool unsorted_edges = false;
    bool unsorted_symbols = false;
    bool virtual_space_only = false;
    bool mixed_space_drop = false;
    bool function_chunks = false;
};

struct corpus_t {
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    std::shared_ptr<const analysis_publication_t> publication;
};

corpus_t generate(const corpus_config_t& config) {
    rng_t rng(config.seed);
    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->generation = config.generation;
    snapshot->analysis_revision = 1;
    snapshot->overlay_revision = 0;
    snapshot->baseline_complete = true;
    const auto space = config.virtual_space_only
        ? address_space_id_t::virtual_address
        : address_space_id_t::relative_virtual;
    const auto make_address = [&](std::uint64_t value) {
        return address_t{space, value, architecture_id_t::x86_64,
            architecture_mode_t::x86_64};
    };
    std::uint64_t cursor = 0x1000;
    snapshot->functions.reserve(config.functions);
    for (std::size_t index = 0; index < config.functions; ++index) {
        function_record_t function;
        function.id = index + 1;
        const std::uint64_t length = 0x10 + rng.below(0x80);
        function.start = make_address(cursor);
        function.end = make_address(cursor + length);
        if (config.overlapping_functions && index % 7 == 3)
            cursor += length / 2 + 1;
        else
            cursor += length + rng.below(0x20);
        function.provenance = fact_provenance_t::recursive_decode;
        function.confidence = 200;
        snapshot->functions.push_back(std::move(function));
    }
    const std::uint64_t address_ceiling = cursor + 0x1000;
    snapshot->symbols.reserve(config.symbols);
    for (std::size_t index = 0; index < config.symbols; ++index) {
        symbol_record_t symbol;
        symbol.id = index + 1;
        std::uint64_t value = 0;
        if (index % 11 == 5 && index > 0)
            value = snapshot->symbols[index - 1].address.value;
        else
            value = 0x800 + rng.below(address_ceiling - 0x800);
        symbol.address = make_address(value);
        if (index % 4 != 1) {
            char name[40]{};
            std::snprintf(name, sizeof(name), "sym_%llX",
                static_cast<unsigned long long>(value * 31 + index));
            symbol.name = name;
        }
        switch (index % 5) {
        case 0: symbol.kind = symbol_kind_t::function; break;
        case 1: symbol.kind = symbol_kind_t::data; break;
        case 2: symbol.kind = symbol_kind_t::import_symbol; break;
        case 3: symbol.kind = symbol_kind_t::debug_symbol; break;
        default: symbol.kind = symbol_kind_t::export_symbol; break;
        }
        symbol.provenance = fact_provenance_t::debug_symbol;
        symbol.confidence = 180;
        snapshot->symbols.push_back(std::move(symbol));
    }
    std::stable_sort(snapshot->symbols.begin(), snapshot->symbols.end(),
        [](const symbol_record_t& lhs, const symbol_record_t& rhs) noexcept {
            if (lhs.address != rhs.address) return lhs.address < rhs.address;
            if (lhs.name != rhs.name) return lhs.name < rhs.name;
            return lhs.kind < rhs.kind;
        });
    if (config.unsorted_symbols && snapshot->symbols.size() > 4)
        std::swap(snapshot->symbols[1], snapshot->symbols[3]);
    for (std::size_t index = 0; index < snapshot->symbols.size(); ++index)
        snapshot->symbols[index].id = index + 1;
    for (std::size_t index = 0; index < snapshot->functions.size(); ++index) {
        if (!snapshot->symbols.empty() && index % 3 == 0)
            snapshot->functions[index].symbol_id =
                snapshot->symbols[rng.below(snapshot->symbols.size())].id;
    }
    std::vector<std::uint64_t> source_values;
    std::vector<std::uint64_t> target_values;
    source_values.reserve(config.unique_sources);
    target_values.reserve(config.unique_targets);
    const auto pick_value = [&]() {
        if (!snapshot->functions.empty() && rng.below(4) != 0) {
            const auto& function = snapshot->functions[rng.below(snapshot->functions.size())];
            const std::uint64_t span = function.end.value - function.start.value;
            return function.start.value + rng.below(span);
        }
        return 0x400 + rng.below(address_ceiling - 0x400);
    };
    for (std::size_t index = 0; index < config.unique_sources; ++index)
        source_values.push_back(pick_value());
    for (std::size_t index = 0; index < config.unique_targets; ++index)
        target_values.push_back(pick_value());
    snapshot->xrefs.reserve(config.xrefs);
    for (std::size_t index = 0; index < config.xrefs; ++index) {
        xref_record_t record;
        const std::uint64_t skew_s = source_values.empty() ? 0
            : rng.below(5) == 0
                ? rng.below(config.unique_sources)
                : (rng.below(100) * config.unique_sources) / 100;
        const std::uint64_t skew_t = target_values.empty() ? 0
            : rng.below(5) == 0
                ? rng.below(config.unique_targets)
                : (rng.below(100) * config.unique_targets) / 100;
        record.source = make_address(source_values.empty() ? 0
            : source_values[static_cast<std::size_t>(skew_s % source_values.size())]);
        record.target = make_address(target_values.empty() ? 0
            : target_values[static_cast<std::size_t>(skew_t % target_values.size())]);
        switch (rng.below(6)) {
        case 0: record.kind = xref_kind_t::code; break;
        case 1: record.kind = xref_kind_t::call; break;
        case 2: record.kind = xref_kind_t::read; break;
        case 3: record.kind = xref_kind_t::write; break;
        case 4: record.kind = xref_kind_t::address; break;
        default: record.kind = xref_kind_t::relocation; break;
        }
        record.provenance = fact_provenance_t::recursive_decode;
        record.confidence = 220;
        snapshot->xrefs.push_back(record);
    }
    if (config.mixed_space_drop) {
        for (std::size_t index = 0; index < snapshot->xrefs.size(); index += 3) {
            snapshot->xrefs[index].source.space = address_space_id_t::relative_virtual;
            snapshot->xrefs[index].target.space = address_space_id_t::relative_virtual;
        }
    }
    std::stable_sort(snapshot->xrefs.begin(), snapshot->xrefs.end(),
        &xref_stk_less);
    snapshot->xrefs.erase(
        std::unique(snapshot->xrefs.begin(), snapshot->xrefs.end(),
            [](const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
                return lhs.source == rhs.source && lhs.target == rhs.target &&
                    lhs.kind == rhs.kind;
            }),
        snapshot->xrefs.end());
    if (config.unsorted_xrefs && snapshot->xrefs.size() > 8) {
        const std::size_t mid = snapshot->xrefs.size() / 2;
        std::swap_ranges(snapshot->xrefs.begin() + static_cast<std::ptrdiff_t>(mid),
            snapshot->xrefs.begin() + static_cast<std::ptrdiff_t>(mid + 4),
            snapshot->xrefs.begin() + static_cast<std::ptrdiff_t>(mid + 4));
    }
    for (std::size_t index = 0; index < snapshot->xrefs.size(); ++index)
        snapshot->xrefs[index].id = index + 1;
    snapshot->edges.reserve(config.edges);
    for (std::size_t index = 0; index < config.edges; ++index) {
        edge_record_t edge;
        edge.id = index + 1;
        edge.source = make_address(pick_value());
        edge.target = make_address(pick_value());
        switch (rng.below(4)) {
        case 0: edge.kind = edge_kind_t::call; break;
        case 1: edge.kind = edge_kind_t::tail_call; break;
        case 2: edge.kind = edge_kind_t::fallthrough; break;
        default: edge.kind = edge_kind_t::unconditional; break;
        }
        edge.source_entity = index + 1;
        edge.provenance = fact_provenance_t::recursive_decode;
        edge.confidence = 210;
        snapshot->edges.push_back(edge);
    }
    std::stable_sort(snapshot->edges.begin(), snapshot->edges.end(),
        &edge_stk_less);
    if (config.unsorted_edges && snapshot->edges.size() > 4)
        std::swap(snapshot->edges[1], snapshot->edges[2]);
    if (config.unsorted_functions && snapshot->functions.size() > 4)
        std::swap(snapshot->functions[1], snapshot->functions[3]);
    if (config.function_chunks) {
        snapshot->function_chunk_ranges.clear();
        for (std::size_t index = 0; index < snapshot->functions.size(); ++index) {
            auto& function = snapshot->functions[index];
            const std::size_t chunk_total = 1 + index % 3;
            std::uint64_t cursor_value = function.start.value;
            std::vector<address_range_t> ranges;
            ranges.reserve(chunk_total);
            for (std::size_t chunk = 0; chunk < chunk_total; ++chunk) {
                const std::uint64_t remaining = function.end.value - cursor_value;
                const std::uint64_t step = chunk + 1 == chunk_total
                    ? remaining
                    : (std::max<std::uint64_t>)(remaining / (chunk_total - chunk), 1);
                address_range_t range;
                range.rva_start = cursor_value;
                range.rva_end = cursor_value + step;
                range.chunk_kind = static_cast<std::uint8_t>(chunk % 2);
                ranges.push_back(range);
                cursor_value += step;
            }
            if (index % 2 == 0) {
                function.chunks = ranges;
            } else {
                function.first_chunk = static_cast<std::uint32_t>(
                    snapshot->function_chunk_ranges.size());
                function.chunk_count = static_cast<std::uint32_t>(ranges.size());
                for (const auto& range : ranges)
                    snapshot->function_chunk_ranges.push_back(range);
            }
        }
    }
    auto publication = std::make_shared<analysis_publication_t>(snapshot, nullptr,
        nullptr, workspace_readiness_t::baseline_ready);
    return corpus_t{std::move(snapshot), std::move(publication)};
}

bool expect(bool condition, std::string& detail, const std::string& label) {
    if (!condition) {
        detail += "FAIL ";
        detail += label;
        detail += "\n";
        return false;
    }
    return true;
}

std::vector<const xref_record_t*> ref_xrefs_to(const analysis_snapshot_t& snapshot,
                                               const std::vector<std::uint32_t>& walk,
                                               const address_t& key) {
    std::vector<const xref_record_t*> out;
    for (const std::uint32_t index : walk) {
        const auto& record = snapshot.xrefs[index];
        if (record.target.space == key.space && record.target.value == key.value)
            out.push_back(&record);
    }
    return out;
}

std::vector<const xref_record_t*> ref_xrefs_from(const analysis_snapshot_t& snapshot,
                                                 const std::vector<std::uint32_t>& walk,
                                                 const address_t& key) {
    std::vector<const xref_record_t*> out;
    for (const std::uint32_t index : walk) {
        const auto& record = snapshot.xrefs[index];
        if (record.source.space == key.space && record.source.value == key.value)
            out.push_back(&record);
    }
    return out;
}

const function_record_t* ref_function_containing(const analysis_snapshot_t& snapshot,
                                                 const address_t& address) {
    for (const auto& function : snapshot.functions) {
        if (function.start.space != address.space)
            continue;
        if (address.value >= function.start.value && address.value < function.end.value)
            return &function;
    }
    return nullptr;
}

const function_record_t* ref_function_at_exact(const analysis_snapshot_t& snapshot,
                                               const address_t& address) {
    for (const auto& function : snapshot.functions) {
        if (function.start.space == address.space &&
            function.start.value == address.value)
            return &function;
    }
    return nullptr;
}

std::vector<entity_id_t> ref_call_edge_ids(const analysis_snapshot_t& snapshot,
                                           const std::vector<std::uint32_t>& walk,
                                           const function_record_t& function) {
    std::vector<entity_id_t> out;
    for (const std::uint32_t index : walk) {
        const auto& edge = snapshot.edges[index];
        if (edge.source.space != function.start.space ||
            edge.source.value < function.start.value ||
            edge.source.value >= function.end.value)
            continue;
        out.push_back(edge.id);
    }
    return out;
}

struct ref_degree_t {
    std::uint32_t in = 0;
    std::uint32_t out = 0;
};

std::vector<ref_degree_t> ref_degrees(const analysis_snapshot_t& snapshot) {
    std::vector<const function_record_t*> ordered;
    ordered.reserve(snapshot.functions.size());
    for (const auto& function : snapshot.functions)
        ordered.push_back(&function);
    std::sort(ordered.begin(), ordered.end(),
        [](const function_record_t* left, const function_record_t* right) noexcept {
            return left->start < right->start;
        });
    const auto enclosing = [&ordered](const address_t& address)
        -> const function_record_t* {
        auto found = std::upper_bound(ordered.begin(), ordered.end(), address,
            [](const address_t& value, const function_record_t* function) noexcept {
                return value < function->start;
            });
        if (found == ordered.begin())
            return nullptr;
        --found;
        const auto* function = *found;
        if (address.space != function->start.space ||
            address.value < function->start.value ||
            address.value >= function->end.value)
            return nullptr;
        return function;
    };
    std::unordered_map<entity_id_t, std::uint32_t> calls_in;
    std::unordered_map<entity_id_t, std::uint32_t> calls_out;
    for (const auto& edge : snapshot.edges) {
        if (edge.kind != edge_kind_t::call && edge.kind != edge_kind_t::tail_call)
            continue;
        const auto* caller = enclosing(edge.source);
        const auto* callee = enclosing(edge.target);
        if (caller && calls_out[caller->id] != (std::numeric_limits<std::uint32_t>::max)())
            ++calls_out[caller->id];
        if (callee && calls_in[callee->id] != (std::numeric_limits<std::uint32_t>::max)())
            ++calls_in[callee->id];
    }
    std::vector<ref_degree_t> out(snapshot.functions.size());
    for (std::size_t index = 0; index < snapshot.functions.size(); ++index) {
        const auto id = snapshot.functions[index].id;
        out[index].in = calls_in[id];
        out[index].out = calls_out[id];
    }
    return out;
}

const symbol_record_t* ref_symbol_named(const analysis_snapshot_t& snapshot,
                                        const std::vector<std::uint32_t>& walk,
                                        const address_t& address) {
    for (const std::uint32_t index : walk) {
        const auto& symbol = snapshot.symbols[index];
        if (symbol.address.space == address.space &&
            symbol.address.value == address.value && !symbol.name.empty())
            return &symbol;
    }
    return nullptr;
}

const symbol_record_t* ref_data_symbol(const analysis_snapshot_t& snapshot,
                                       const std::vector<std::uint32_t>& walk,
                                       const address_t& address) {
    for (const std::uint32_t index : walk) {
        const auto& symbol = snapshot.symbols[index];
        if (symbol.address.space == address.space &&
            symbol.address.value == address.value &&
            symbol.kind != symbol_kind_t::function)
            return &symbol;
    }
    return nullptr;
}

int ref_map_kind(xref_kind_t kind) {
    switch (kind) {
    case xref_kind_t::call: return 0;
    case xref_kind_t::code: return 1;
    default: return 4;
    }
}

std::uint64_t ref_display(const address_t& address) {
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual)
        return address.value;
    return 0;
}

std::pair<std::vector<module_entry_t>, std::vector<module_entry_t>>
ref_module_pairs(const analysis_snapshot_t& snapshot) {
    std::vector<module_entry_t> to_sorted;
    std::vector<module_entry_t> from_sorted;
    for (const auto& record : snapshot.xrefs) {
        const std::uint64_t from = ref_display(record.source);
        const std::uint64_t to = ref_display(record.target);
        if (from == 0 || to == 0)
            continue;
        to_sorted.push_back(module_entry_t{from, to, ref_map_kind(record.kind)});
        from_sorted.push_back(module_entry_t{from, to, ref_map_kind(record.kind)});
    }
    std::sort(to_sorted.begin(), to_sorted.end(), &module_entry_less_to);
    std::sort(from_sorted.begin(), from_sorted.end(), &module_entry_less_from);
    return {std::move(to_sorted), std::move(from_sorted)};
}

struct ref_call_graph_result_t {
    bool failed = false;
    workspace_error_code_t code = workspace_error_code_t::none;
    std::vector<xref_db::call_graph_node_t> nodes;
};

ref_call_graph_result_t ref_call_graph(const analysis_snapshot_t& snapshot,
                                       std::size_t max_nodes) {
    ref_call_graph_result_t output;
    std::vector<const function_record_t*> functions;
    functions.reserve(snapshot.functions.size());
    for (const auto& function : snapshot.functions)
        functions.push_back(&function);
    std::sort(functions.begin(), functions.end(),
        [](const function_record_t* left, const function_record_t* right) noexcept {
            return left->start < right->start;
        });
    std::unordered_map<entity_id_t, std::string> names;
    names.reserve(snapshot.symbols.size());
    for (const auto& symbol : snapshot.symbols) {
        if (!symbol.name.empty())
            names.emplace(symbol.id, symbol.name);
    }
    std::map<std::uint64_t, xref_db::call_graph_node_t> nodes;
    const auto enclosing = [&functions](const address_t& address)
        -> const function_record_t* {
        auto found = std::upper_bound(functions.begin(), functions.end(), address,
            [](const address_t& value, const function_record_t* function) noexcept {
                return value < function->start;
            });
        if (found == functions.begin())
            return nullptr;
        --found;
        const auto* function = *found;
        if (address.space != function->start.space ||
            address.value < function->start.value ||
            address.value >= function->end.value)
            return nullptr;
        return function;
    };
    const auto assign_name = [&names](xref_db::call_graph_node_t& node,
                                      const function_record_t* function) {
        if (!node.name.empty())
            return;
        if (function && function->symbol_id) {
            const auto found = names.find(*function->symbol_id);
            if (found != names.end())
                node.name = found->second;
        }
        if (node.name.empty()) {
            char text[32]{};
            std::snprintf(text, sizeof(text), "sub_%llX",
                static_cast<unsigned long long>(node.addr));
            node.name = text;
        }
    };
    for (const auto& edge : snapshot.xrefs) {
        if (edge.kind != xref_kind_t::call)
            continue;
        const auto* caller_function = enclosing(edge.source);
        const auto* callee_function = enclosing(edge.target);
        const address_t& caller_address =
            caller_function ? caller_function->start : edge.source;
        const address_t& callee_address =
            callee_function ? callee_function->start : edge.target;
        const std::uint64_t caller = ref_display(caller_address);
        const std::uint64_t callee = ref_display(callee_address);
        if (caller == 0 || callee == 0)
            continue;
        auto& caller_node = nodes[caller];
        caller_node.addr = caller;
        auto& callee_node = nodes[callee];
        callee_node.addr = callee;
        assign_name(caller_node, caller_function);
        assign_name(callee_node, callee_function);
        if (std::find(caller_node.callees.begin(), caller_node.callees.end(), callee)
            == caller_node.callees.end())
            caller_node.callees.push_back(callee);
        if (std::find(callee_node.callers.begin(), callee_node.callers.end(), caller)
            == callee_node.callers.end())
            callee_node.callers.push_back(caller);
        if (nodes.size() > max_nodes) {
            output.failed = true;
            output.code = workspace_error_code_t::limit_exceeded;
            return output;
        }
    }
    output.nodes.reserve(nodes.size());
    for (auto& item : nodes) {
        std::sort(item.second.callees.begin(), item.second.callees.end());
        std::sort(item.second.callers.begin(), item.second.callers.end());
        output.nodes.push_back(std::move(item.second));
    }
    return output;
}

std::vector<address_t> sample_xref_targets(const analysis_snapshot_t& snapshot) {
    std::vector<address_t> keys;
    std::size_t stride = snapshot.xrefs.size() > 97 ? snapshot.xrefs.size() / 97 : 1;
    address_t previous{};
    bool have_previous = false;
    for (std::size_t index = 0; index < snapshot.xrefs.size(); index += stride) {
        const auto& target = snapshot.xrefs[index].target;
        if (!have_previous || target.space != previous.space ||
            target.value != previous.value)
            keys.push_back(target);
        previous = target;
        have_previous = true;
    }
    if (!snapshot.xrefs.empty())
        keys.push_back(snapshot.xrefs.back().target);
    keys.push_back(address_t{snapshot.xrefs.empty()
            ? address_space_id_t::relative_virtual : snapshot.xrefs.front().target.space,
        0, architecture_id_t::x86_64, architecture_mode_t::x86_64});
    keys.push_back(address_t{snapshot.xrefs.empty()
            ? address_space_id_t::relative_virtual : snapshot.xrefs.front().target.space,
        (std::numeric_limits<std::uint64_t>::max)() - 1, architecture_id_t::x86_64,
        architecture_mode_t::x86_64});
    return keys;
}

std::vector<address_t> sample_xref_sources(const analysis_snapshot_t& snapshot) {
    std::vector<address_t> keys;
    std::size_t stride = snapshot.xrefs.size() > 97 ? snapshot.xrefs.size() / 97 : 1;
    address_t previous{};
    bool have_previous = false;
    for (std::size_t index = 0; index < snapshot.xrefs.size(); index += stride) {
        const auto& source = snapshot.xrefs[index].source;
        if (!have_previous || source.space != previous.space ||
            source.value != previous.value)
            keys.push_back(source);
        previous = source;
        have_previous = true;
    }
    if (!snapshot.xrefs.empty())
        keys.push_back(snapshot.xrefs.back().source);
    return keys;
}

bool compare_xref_lists(const std::vector<const xref_record_t*>& reference,
                        const std::vector<const xref_record_t*>& candidate,
                        std::string& detail, const std::string& label) {
    if (!expect(reference.size() == candidate.size(), detail,
            label + " size ref=" + std::to_string(reference.size()) +
            " got=" + std::to_string(candidate.size())))
        return false;
    for (std::size_t index = 0; index < reference.size(); ++index) {
        if (reference[index]->id != candidate[index]->id) {
            return expect(false, detail,
                label + " order mismatch at " + std::to_string(index) +
                " ref_id=" + std::to_string(reference[index]->id) +
                " got_id=" + std::to_string(candidate[index]->id));
        }
    }
    return true;
}

bool run_differential(const corpus_t& corpus, const publication_indexes_t& indexes,
                      std::string& detail, const std::string& tag,
                      const corpus_config_t& config = corpus_config_t{}) {
    bool pass = true;
    const auto& snapshot = *corpus.snapshot;
    std::vector<std::uint32_t> target_walk(snapshot.xrefs.size());
    std::vector<std::uint32_t> source_walk(snapshot.xrefs.size());
    for (std::size_t index = 0; index < snapshot.xrefs.size(); ++index) {
        target_walk[index] = static_cast<std::uint32_t>(index);
        source_walk[index] = static_cast<std::uint32_t>(index);
    }
    if (config.unsorted_xrefs) {
        std::stable_sort(target_walk.begin(), target_walk.end(),
            [&snapshot](std::uint32_t lhs, std::uint32_t rhs) noexcept {
                const auto& left = snapshot.xrefs[lhs].target;
                const auto& right = snapshot.xrefs[rhs].target;
                return left.space < right.space ||
                    (left.space == right.space && left.value < right.value);
            });
        std::stable_sort(source_walk.begin(), source_walk.end(),
            [&snapshot](std::uint32_t lhs, std::uint32_t rhs) noexcept {
                const auto& left = snapshot.xrefs[lhs].source;
                const auto& right = snapshot.xrefs[rhs].source;
                return left.space < right.space ||
                    (left.space == right.space && left.value < right.value);
            });
    }
    std::vector<std::uint32_t> edge_walk(snapshot.edges.size());
    for (std::size_t index = 0; index < snapshot.edges.size(); ++index)
        edge_walk[index] = static_cast<std::uint32_t>(index);
    if (config.unsorted_edges) {
        std::stable_sort(edge_walk.begin(), edge_walk.end(),
            [&snapshot](std::uint32_t lhs, std::uint32_t rhs) noexcept {
                const auto& left = snapshot.edges[lhs].source;
                const auto& right = snapshot.edges[rhs].source;
                return left.space < right.space ||
                    (left.space == right.space && left.value < right.value);
            });
    }
    std::vector<std::uint32_t> symbol_walk(snapshot.symbols.size());
    for (std::size_t index = 0; index < snapshot.symbols.size(); ++index)
        symbol_walk[index] = static_cast<std::uint32_t>(index);
    if (config.unsorted_symbols) {
        std::stable_sort(symbol_walk.begin(), symbol_walk.end(),
            [&snapshot](std::uint32_t lhs, std::uint32_t rhs) noexcept {
                const auto& left = snapshot.symbols[lhs].address;
                const auto& right = snapshot.symbols[rhs].address;
                return left.space < right.space ||
                    (left.space == right.space && left.value < right.value);
            });
    }
    const auto target_keys = sample_xref_targets(snapshot);
    const auto source_keys = sample_xref_sources(snapshot);
    const std::size_t limit_sweep[] = {0, 1, 15, 16, 17, 1000, 100000};
    for (const auto& key : target_keys) {
        const auto reference = ref_xrefs_to(snapshot, target_walk, key);
        const auto range = indexes.xrefs_to(key);
        std::vector<const xref_record_t*> candidate;
        candidate.reserve(range.end - range.begin);
        for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal)
            candidate.push_back(&snapshot.xrefs[indexes.xref_to_entry(ordinal)]);
        pass &= compare_xref_lists(reference, candidate, detail,
            tag + " xrefs_to value=" + std::to_string(key.value));
        for (const std::size_t limit : limit_sweep) {
            const std::size_t ref_take = (std::min)(reference.size(), limit);
            const std::size_t got_take = (std::min)(candidate.size(), limit);
            pass &= expect(ref_take == got_take, detail,
                tag + " xrefs_to limit=" + std::to_string(limit));
        }
        const std::size_t run_size = reference.size();
        pass &= expect((std::min)(reference.size(), run_size) ==
            (std::min)(candidate.size(), run_size), detail,
            tag + " xrefs_to limit=run_size value=" + std::to_string(key.value) +
            " run_size=" + std::to_string(run_size));
        pass &= expect(indexes.xref_count_to(key) == reference.size(), detail,
            tag + " xref_count_to value=" + std::to_string(key.value));
        g_probe_armed.store(true, std::memory_order_relaxed);
        g_probe_count.store(0, std::memory_order_relaxed);
        const std::uint64_t counted = indexes.xref_count_to(key);
        g_probe_armed.store(false, std::memory_order_relaxed);
        const std::uint64_t probes = g_probe_count.load(std::memory_order_relaxed);
        pass &= expect(counted == reference.size() && probes <= 64, detail,
            tag + " xref_count_to probes=" + std::to_string(probes));
    }
    const std::size_t key_total = indexes.xref_target_key_count();
    const std::size_t key_stride = key_total > 97 ? key_total / 97 : 1;
    std::vector<std::size_t> key_samples;
    for (std::size_t key_index = 0; key_index < key_total; key_index += key_stride)
        key_samples.push_back(key_index);
    if (key_total != 0 && key_samples.back() != key_total - 1)
        key_samples.push_back(key_total - 1);
    for (const std::size_t key_index : key_samples) {
        const address_t key = indexes.xref_target_key_at(key_index);
        const auto run = indexes.xref_target_run_at(key_index);
        const auto direct = indexes.xrefs_to(key);
        pass &= expect(run.begin == direct.begin && run.end == direct.end, detail,
            tag + " xref_target_run consistency key=" + std::to_string(key_index));
        const auto reference = ref_xrefs_to(snapshot, target_walk, key);
        pass &= expect(static_cast<std::size_t>(run.end - run.begin) == reference.size(),
            detail, tag + " xref_target_run size value=" + std::to_string(key.value));
    }
    for (const auto& key : source_keys) {
        const auto reference = ref_xrefs_from(snapshot, source_walk, key);
        const auto range = indexes.xrefs_from(key);
        std::vector<const xref_record_t*> candidate;
        candidate.reserve(range.end - range.begin);
        for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal)
            candidate.push_back(&snapshot.xrefs[indexes.xref_from_entry(ordinal)]);
        pass &= compare_xref_lists(reference, candidate, detail,
            tag + " xrefs_from value=" + std::to_string(key.value));
    }
    const std::size_t function_stride = snapshot.functions.size() > 37
        ? snapshot.functions.size() / 37 : 1;
    for (std::size_t index = 0; index < snapshot.functions.size();
         index += function_stride) {
        const auto& function = snapshot.functions[index];
        const std::uint64_t probes[] = {
            function.start.value, function.end.value - 1, function.end.value,
            function.start.value > 0 ? function.start.value - 1 : 0,
            function.start.value +
                (function.end.value - function.start.value) / 2};
        for (const std::uint64_t value : probes) {
            const address_t query{function.start.space, value,
                function.start.architecture, function.start.mode};
            const auto* reference = ref_function_containing(snapshot, query);
            const auto* candidate = indexes.function_containing(query);
            pass &= expect(reference == candidate, detail,
                tag + " function_containing value=" + std::to_string(value) +
                " ref=" + std::to_string(reference ? reference->id : 0) +
                " got=" + std::to_string(candidate ? candidate->id : 0));
        }
        const auto* ref_exact = ref_function_at_exact(snapshot, function.start);
        const auto* got_exact = indexes.function_at_exact_start(function.start);
        pass &= expect(ref_exact == got_exact, detail,
            tag + " function_at_exact_start id=" + std::to_string(function.id));
        const auto reference_edges = ref_call_edge_ids(snapshot, edge_walk, function);
        const auto range = indexes.call_edges_from(function);
        std::vector<entity_id_t> candidate_edges;
        candidate_edges.reserve(range.end - range.begin);
        for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal)
            candidate_edges.push_back(snapshot.edges[indexes.call_edge_entry(ordinal)].id);
        pass &= expect(reference_edges == candidate_edges, detail,
            tag + " call_edges_from id=" + std::to_string(function.id) +
            " ref=" + std::to_string(reference_edges.size()) +
            " got=" + std::to_string(candidate_edges.size()));
    }
    const auto reference_degrees = ref_degrees(snapshot);
    for (std::size_t index = 0; index < snapshot.functions.size(); ++index) {
        const auto degree = indexes.function_call_degree(index);
        pass &= expect(degree.first == reference_degrees[index].in &&
            degree.second == reference_degrees[index].out, detail,
            tag + " function_call_degree ordinal=" + std::to_string(index) +
            " ref=" + std::to_string(reference_degrees[index].in) + "/" +
            std::to_string(reference_degrees[index].out) + " got=" +
            std::to_string(degree.first) + "/" + std::to_string(degree.second));
        if (!pass)
            break;
    }
    const std::size_t symbol_stride = snapshot.symbols.size() > 37
        ? snapshot.symbols.size() / 37 : 1;
    for (std::size_t index = 0; index < snapshot.symbols.size(); index += symbol_stride) {
        const auto& address = snapshot.symbols[index].address;
        const auto* ref_named = ref_symbol_named(snapshot, symbol_walk, address);
        const auto* got_named = indexes.symbol_exact_named(address);
        pass &= expect(ref_named == got_named, detail,
            tag + " symbol_exact_named value=" + std::to_string(address.value));
        const auto* ref_data = ref_data_symbol(snapshot, symbol_walk, address);
        const auto* got_data = indexes.data_symbol_exact(address);
        pass &= expect(ref_data == got_data, detail,
            tag + " data_symbol_exact value=" + std::to_string(address.value));
    }
    if (tag.find("va") != std::string::npos) {
        const auto reference = ref_module_pairs(snapshot);
        auto candidate = indexes.module_index_pairs(
            [](const address_t& address) { return ref_display(address); },
            [](xref_kind_t kind) { return ref_map_kind(kind); }, {});
        pass &= expect(candidate.has_value(), detail, tag + " module_index_pairs build");
        if (candidate) {
            pass &= expect(candidate.value().first.size() == reference.first.size() &&
                candidate.value().second.size() == reference.second.size(), detail,
                tag + " module_index_pairs size");
            if (candidate.value().first.size() == reference.first.size()) {
                for (std::size_t index = 0; index < reference.first.size(); ++index) {
                    const auto& ref = reference.first[index];
                    const auto& got = candidate.value().first[index];
                    if (ref.from != got.from || ref.to != got.to || ref.type != got.type) {
                        pass &= expect(false, detail,
                            tag + " module to_sorted mismatch at " +
                            std::to_string(index));
                        break;
                    }
                }
            }
            if (candidate.value().second.size() == reference.second.size()) {
                for (std::size_t index = 0; index < reference.second.size(); ++index) {
                    const auto& ref = reference.second[index];
                    const auto& got = candidate.value().second[index];
                    if (ref.from != got.from || ref.to != got.to || ref.type != got.type) {
                        pass &= expect(false, detail,
                            tag + " module from_sorted mismatch at " +
                            std::to_string(index));
                        break;
                    }
                }
            }
            if (tag.find("drop") != std::string::npos) {
                std::size_t kept = 0;
                std::size_t dropped = 0;
                for (const auto& record : snapshot.xrefs) {
                    if (ref_display(record.source) == 0 || ref_display(record.target) == 0)
                        ++dropped;
                    else
                        ++kept;
                }
                pass &= expect(dropped != 0 && kept != 0, detail,
                    tag + " display drop mix kept=" + std::to_string(kept) +
                    " dropped=" + std::to_string(dropped));
                pass &= expect(candidate.value().first.size() == kept &&
                    candidate.value().second.size() == kept, detail,
                    tag + " display drop counts ref_kept=" + std::to_string(kept) +
                    " got_to=" + std::to_string(candidate.value().first.size()) +
                    " got_from=" + std::to_string(candidate.value().second.size()));
            }
        }
        const std::size_t node_sweep[] = {100000, 4, 2, 1};
        for (const std::size_t max_nodes : node_sweep) {
            const auto reference_graph = ref_call_graph(snapshot, max_nodes);
            auto candidate_graph = indexes.call_graph(max_nodes, {});
            if (reference_graph.failed) {
                pass &= expect(!candidate_graph.has_value() &&
                    candidate_graph.error().code == reference_graph.code, detail,
                    tag + " call_graph cap max_nodes=" + std::to_string(max_nodes));
                continue;
            }
            pass &= expect(candidate_graph.has_value(), detail,
                tag + " call_graph max_nodes=" + std::to_string(max_nodes));
            if (!candidate_graph)
                continue;
            const auto& got_nodes = *candidate_graph.value();
            pass &= expect(got_nodes.size() == reference_graph.nodes.size(), detail,
                tag + " call_graph node count");
            if (got_nodes.size() != reference_graph.nodes.size())
                continue;
            for (std::size_t index = 0; index < got_nodes.size(); ++index) {
                const auto& ref = reference_graph.nodes[index];
                const auto& got = got_nodes[index];
                if (ref.addr != got.addr || ref.name != got.name ||
                    ref.callees != got.callees || ref.callers != got.callers) {
                    pass &= expect(false, detail,
                        tag + " call_graph node mismatch at " + std::to_string(index) +
                        " addr=" + std::to_string(ref.addr));
                    break;
                }
            }
        }
    }
    return pass;
}

struct timing_report_t {
    double p50_us = 0;
    double p99_us = 0;
};

template <typename F>
timing_report_t measure(F&& fn, std::size_t iterations) {
    std::vector<double> samples;
    samples.reserve(iterations);
    for (std::size_t index = 0; index < iterations; ++index) {
        const auto begin = std::chrono::steady_clock::now();
        fn(index);
        const auto end = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(
            end - begin).count() / 1000.0);
    }
    std::sort(samples.begin(), samples.end());
    timing_report_t report;
    if (!samples.empty()) {
        report.p50_us = samples[samples.size() / 2];
        report.p99_us = samples[(samples.size() * 99) / 100];
    }
    return report;
}

void append_timing(std::string& detail, const char* family,
                   const timing_report_t& report) {
    char line[160]{};
    std::snprintf(line, sizeof(line), "timing %s p50_us=%.1f p99_us=%.1f\n", family,
        report.p50_us, report.p99_us);
    detail += line;
}

}

bool differential_selftest(std::string& detail) {
    using namespace selftest;
    bool pass = true;
    detail += "publication_indexes differential selftest\n";
    struct scale_case_t {
        corpus_config_t config;
        const char* tag;
    };
    const scale_case_t cases[] = {
        {corpus_config_t{1000, 200, 150, 40, 300, 60, 1, 0xA1DA0001ULL,
            false, false, false, false, false, false}, "s1k"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0002ULL,
            false, false, false, false, false, true}, "s100k_va"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0003ULL,
            true, false, false, false, false, false}, "adv_unsorted_xrefs"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0004ULL,
            false, true, false, false, false, false}, "adv_unsorted_functions"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0005ULL,
            false, false, true, false, false, false}, "adv_overlap_functions"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0006ULL,
            false, false, false, true, false, false}, "adv_unsorted_edges"},
        {corpus_config_t{100000, 30000, 12000, 3000, 20000, 5000, 1, 0xA1DA0007ULL,
            false, false, false, false, true, false}, "adv_unsorted_symbols"},
        {corpus_config_t{100000, 100000, 100000, 3000, 20000, 5000, 1, 0xA1DA0008ULL,
            false, false, false, false, false, false}, "adv_all_unique"},
        {corpus_config_t{100000, 4, 3, 3000, 20000, 5000, 1, 0xA1DA0009ULL,
            false, false, false, false, false, true}, "adv_skew_va"},
        {corpus_config_t{3000000, 1500000, 500000, 50000, 400000, 80000, 1, 0xA1DA000AULL,
            false, false, false, false, false, false}, "s3m"},
        {corpus_config_t{0, 0, 0, 0, 0, 0, 1, 0xA1DA000BULL,
            false, false, false, false, false, true, false, false}, "empty_va"},
        {corpus_config_t{1, 1, 1, 1, 1, 1, 1, 0xA1DA000CULL,
            false, false, false, false, false, true, false, false}, "single_va"},
        {corpus_config_t{600, 200, 150, 60, 200, 80, 1, 0xA1DA000DULL,
            false, false, false, false, false, true, true, false}, "drop_va"},
        {corpus_config_t{2000, 500, 400, 120, 600, 150, 1, 0xA1DA000EULL,
            false, false, false, false, false, true, false, true}, "chunks_va"},
    };
    for (const auto& test_case : cases) {
        const auto corpus = generate(test_case.config);
        auto built = publication_indexes_t::build(corpus.publication, hints_t{}, {});
        if (!expect(built.has_value(), detail,
                std::string(test_case.tag) + " build failed: " +
                (built ? std::string() : built.error().message))) {
            pass = false;
            continue;
        }
        const auto& indexes = *built.value();
        pass &= run_differential(corpus, indexes, detail, test_case.tag,
            test_case.config);
        const std::uint64_t xref_bytes =
            static_cast<std::uint64_t>(corpus.snapshot->xrefs.size()) *
            sizeof(xref_record_t);
        const std::uint64_t index_bytes = indexes.index_bytes();
        pass &= expect(index_bytes <= 2 * xref_bytes, detail,
            std::string(test_case.tag) + " memory budget index_bytes=" +
            std::to_string(index_bytes) + " xref_bytes=" + std::to_string(xref_bytes));
        char line[200]{};
        std::snprintf(line, sizeof(line),
            "memory %s xrefs=%llu index_bytes=%llu ratio=%.3f\n", test_case.tag,
            static_cast<unsigned long long>(corpus.snapshot->xrefs.size()),
            static_cast<unsigned long long>(index_bytes),
            xref_bytes != 0 ? static_cast<double>(index_bytes) / xref_bytes : 0.0);
        detail += line;
        cache_forget(corpus.snapshot.get());
    }
    {
        const auto corpus = generate(corpus_config_t{2000000, 800000, 300000, 20000,
            300000, 40000, 1, 0xA1DA0010ULL, false, false, false, false, false, false});
        auto built = publication_indexes_t::build(corpus.publication, hints_t{}, {});
        if (expect(built.has_value(), detail, "timing build")) {
            const auto& indexes = *built.value();
            const auto targets = sample_xref_targets(*corpus.snapshot);
            const auto sources = sample_xref_sources(*corpus.snapshot);
            volatile std::uint64_t sink = 0;
            const auto to_report = measure([&](std::size_t iteration) {
                const auto range = indexes.xrefs_to(targets[iteration % targets.size()]);
                std::uint64_t total = 0;
                const std::uint32_t stop = range.begin +
                    (std::min<std::uint32_t>)(range.end - range.begin, 1000);
                for (std::uint32_t ordinal = range.begin; ordinal < stop; ++ordinal)
                    total += corpus.snapshot->xrefs[indexes.xref_to_entry(ordinal)].id;
                sink += total;
            }, 400);
            append_timing(detail, "xrefs_to_page1k", to_report);
            pass &= expect(to_report.p99_us <= 5000.0, detail,
                "timing xrefs_to p99 " + std::to_string(to_report.p99_us));
            const auto from_report = measure([&](std::size_t iteration) {
                const auto range = indexes.xrefs_from(sources[iteration % sources.size()]);
                std::uint64_t total = 0;
                const std::uint32_t stop = range.begin +
                    (std::min<std::uint32_t>)(range.end - range.begin, 1000);
                for (std::uint32_t ordinal = range.begin; ordinal < stop; ++ordinal)
                    total += corpus.snapshot->xrefs[indexes.xref_from_entry(ordinal)].id;
                sink += total;
            }, 400);
            append_timing(detail, "xrefs_from_page1k", from_report);
            pass &= expect(from_report.p99_us <= 5000.0, detail,
                "timing xrefs_from p99 " + std::to_string(from_report.p99_us));
            const auto count_report = measure([&](std::size_t iteration) {
                sink += indexes.xref_count_to(targets[iteration % targets.size()]);
            }, 400);
            append_timing(detail, "xref_count_to", count_report);
            pass &= expect(count_report.p99_us <= 1000.0, detail,
                "timing xref_count_to p99 " + std::to_string(count_report.p99_us));
            const auto fn_report = measure([&](std::size_t iteration) {
                const auto& function =
                    corpus.snapshot->functions[
                        iteration % corpus.snapshot->functions.size()];
                sink += reinterpret_cast<std::uint64_t>(
                    indexes.function_containing(function.start));
            }, 400);
            append_timing(detail, "function_containing", fn_report);
            pass &= expect(fn_report.p99_us <= 1000.0, detail,
                "timing function_containing p99 " + std::to_string(fn_report.p99_us));
            (void)sink;
        }
        cache_forget(corpus.snapshot.get());
    }
    {
        const auto base = generate(corpus_config_t{120000, 40000, 15000, 4000, 25000,
            6000, 7, 0xA1DA0020ULL, false, false, false, false, false, false});
        auto first = for_publication(base.publication, {});
        pass &= expect(first != nullptr, detail, "churn gen1 build");
        if (first) {
            auto first_graph = first->call_graph(100000, {});
            pass &= expect(first_graph.has_value(), detail, "churn gen1 call_graph");
            auto gen2_snapshot = std::make_shared<analysis_snapshot_t>(*base.snapshot);
            gen2_snapshot->generation = 8;
            auto gen2 = std::make_shared<analysis_publication_t>(gen2_snapshot, nullptr,
                nullptr, workspace_readiness_t::baseline_ready);
            auto second = for_publication(gen2, {});
            pass &= expect(second != nullptr && second != first, detail,
                "churn gen2 build");
            if (second) {
                const std::uint32_t expected_alias = detail::alias_domain_xrefs |
                    detail::alias_domain_functions | detail::alias_domain_edges |
                    detail::alias_domain_symbols | detail::alias_domain_call_graph;
                pass &= expect((second->aliased_domains() & expected_alias) ==
                    expected_alias, detail,
                    "churn gen2 alias mask=" +
                    std::to_string(second->aliased_domains()));
                pass &= run_differential(corpus_t{gen2_snapshot, gen2}, *second, detail,
                    "churn_gen2");
                auto second_graph = second->call_graph(100000, {});
                pass &= expect(second_graph.has_value() &&
                    second_graph.value() == first_graph.value(), detail,
                    "churn gen2 call_graph memo alias");
            }
            auto gen3_snapshot = std::make_shared<analysis_snapshot_t>(*base.snapshot);
            gen3_snapshot->generation = 9;
            gen3_snapshot->xrefs.resize(gen3_snapshot->xrefs.size() * 9 / 10);
            auto gen3 = std::make_shared<analysis_publication_t>(gen3_snapshot, nullptr,
                nullptr, workspace_readiness_t::baseline_ready);
            auto third = for_publication(gen3, {});
            pass &= expect(third != nullptr, detail, "churn gen3 build");
            if (third) {
                pass &= expect((third->aliased_domains() & detail::alias_domain_xrefs) == 0,
                    detail, "churn gen3 xrefs rebuilt");
                const std::uint32_t kept = detail::alias_domain_functions |
                    detail::alias_domain_edges | detail::alias_domain_symbols;
                pass &= expect((third->aliased_domains() & kept) == kept, detail,
                    "churn gen3 alias mask=" + std::to_string(third->aliased_domains()));
                pass &= run_differential(corpus_t{gen3_snapshot, gen3}, *third, detail,
                    "churn_gen3");
            }
            auto gen4_snapshot = std::make_shared<analysis_snapshot_t>(*gen3_snapshot);
            gen4_snapshot->generation = 10;
            auto gen4 = std::make_shared<analysis_publication_t>(gen4_snapshot, nullptr,
                nullptr, workspace_readiness_t::baseline_ready);
            hints_t all_hints;
            all_hints.xrefs_unchanged = true;
            all_hints.functions_unchanged = true;
            all_hints.edges_unchanged = true;
            all_hints.call_graph_unchanged = true;
            all_hints.symbols_unchanged = true;
            prebuild(gen4, all_hints);
            auto fourth = for_publication(gen4, {});
            pass &= expect(fourth != nullptr, detail, "churn gen4 prebuild");
            if (fourth) {
                const std::uint32_t structural = detail::alias_domain_xrefs |
                    detail::alias_domain_functions | detail::alias_domain_edges |
                    detail::alias_domain_symbols;
                pass &= expect((fourth->aliased_domains() & structural) == structural,
                    detail, "churn gen4 hint alias mask=" +
                    std::to_string(fourth->aliased_domains()));
            }
            auto smaller_snapshot = std::make_shared<analysis_snapshot_t>(*gen4_snapshot);
            smaller_snapshot->generation = 11;
            smaller_snapshot->xrefs.resize(smaller_snapshot->xrefs.size() / 2);
            smaller_snapshot->functions.resize(smaller_snapshot->functions.size() / 2);
            smaller_snapshot->edges.resize(smaller_snapshot->edges.size() / 2);
            smaller_snapshot->symbols.resize(smaller_snapshot->symbols.size() / 2);
            auto smaller = std::make_shared<analysis_publication_t>(smaller_snapshot,
                nullptr, nullptr, workspace_readiness_t::baseline_ready);
            prebuild(smaller, all_hints);
            auto fifth = for_publication(smaller, {});
            pass &= expect(fifth != nullptr, detail, "churn gen5 stale hint build");
            if (fifth) {
                const std::uint32_t structural = detail::alias_domain_xrefs |
                    detail::alias_domain_functions | detail::alias_domain_edges |
                    detail::alias_domain_symbols;
                pass &= expect((fifth->aliased_domains() & structural) == 0, detail,
                    "churn gen5 stale cardinality hint rejected mask=" +
                    std::to_string(fifth->aliased_domains()));
                pass &= run_differential(corpus_t{smaller_snapshot, smaller}, *fifth,
                    detail, "churn_gen5_stale_hint");
            }
            auto changed_snapshot =
                std::make_shared<analysis_snapshot_t>(*smaller_snapshot);
            changed_snapshot->generation = 12;
            if (!changed_snapshot->xrefs.empty())
                changed_snapshot->xrefs.front().confidence ^= 1;
            if (!changed_snapshot->functions.empty())
                changed_snapshot->functions.front().thunk =
                    !changed_snapshot->functions.front().thunk;
            if (!changed_snapshot->edges.empty())
                changed_snapshot->edges.front().confidence ^= 1;
            if (!changed_snapshot->symbols.empty())
                changed_snapshot->symbols.front().name += "_changed";
            auto changed = std::make_shared<analysis_publication_t>(changed_snapshot,
                nullptr, nullptr, workspace_readiness_t::baseline_ready);
            prebuild(changed, all_hints);
            auto sixth = for_publication(changed, {});
            pass &= expect(sixth != nullptr, detail, "churn gen6 stale hint build");
            if (sixth) {
                const std::uint32_t structural = detail::alias_domain_xrefs |
                    detail::alias_domain_functions | detail::alias_domain_edges |
                    detail::alias_domain_symbols;
                pass &= expect((sixth->aliased_domains() & structural) == 0, detail,
                    "churn gen6 stale content hint rejected mask=" +
                    std::to_string(sixth->aliased_domains()));
                pass &= run_differential(corpus_t{changed_snapshot, changed}, *sixth,
                    detail, "churn_gen6_stale_hint");
            }
            cache_forget(changed_snapshot.get());
            cache_forget(smaller_snapshot.get());
            cache_forget(gen4_snapshot.get());
            cache_forget(gen3_snapshot.get());
            cache_forget(gen2_snapshot.get());
            cache_forget(base.snapshot.get());
        }
    }
    {
        const corpus_config_t chunks_config{4000, 1200, 900, 160, 1200, 220, 51,
            0xA1DA0060ULL, false, false, false, false, false, true, false, true};
        const auto base = generate(chunks_config);
        auto first = for_publication(base.publication, {});
        pass &= expect(first != nullptr, detail, "chunks gate gen1 build");
        if (first) {
            auto gen2_snapshot = std::make_shared<analysis_snapshot_t>(*base.snapshot);
            gen2_snapshot->generation = 52;
            auto gen2 = std::make_shared<analysis_publication_t>(gen2_snapshot, nullptr,
                nullptr, workspace_readiness_t::baseline_ready);
            auto second = for_publication(gen2, {});
            pass &= expect(second != nullptr, detail, "chunks gate gen2 build");
            if (second) {
                pass &= expect(
                    (second->aliased_domains() & detail::alias_domain_functions) != 0,
                    detail, "chunks gate gen2 functions alias");
                pass &= run_differential(corpus_t{gen2_snapshot, gen2}, *second, detail,
                    "chunks_gen2_va", chunks_config);
            }
            auto inline_snapshot = std::make_shared<analysis_snapshot_t>(*gen2_snapshot);
            inline_snapshot->generation = 53;
            bool inline_drifted = false;
            for (auto& function : inline_snapshot->functions) {
                if (!function.chunks.empty()) {
                    function.chunks.front().rva_end += 1;
                    inline_drifted = true;
                    break;
                }
            }
            pass &= expect(inline_drifted, detail, "chunks gate inline drift target");
            auto inline_pub = std::make_shared<analysis_publication_t>(inline_snapshot,
                nullptr, nullptr, workspace_readiness_t::baseline_ready);
            auto third = for_publication(inline_pub, {});
            pass &= expect(third != nullptr, detail, "chunks gate inline drift build");
            if (third) {
                pass &= expect(
                    (third->aliased_domains() & detail::alias_domain_functions) == 0,
                    detail, "chunks gate inline drift detected");
            }
            auto arena_snapshot = std::make_shared<analysis_snapshot_t>(*gen2_snapshot);
            arena_snapshot->generation = 54;
            bool arena_drifted = false;
            for (const auto& function : arena_snapshot->functions) {
                if (function.chunks.empty() && function.chunk_count != 0) {
                    arena_snapshot->function_chunk_ranges[function.first_chunk].rva_end += 1;
                    arena_drifted = true;
                    break;
                }
            }
            pass &= expect(arena_drifted, detail, "chunks gate arena drift target");
            auto arena_pub = std::make_shared<analysis_publication_t>(arena_snapshot,
                nullptr, nullptr, workspace_readiness_t::baseline_ready);
            auto fourth = for_publication(arena_pub, {});
            pass &= expect(fourth != nullptr, detail, "chunks gate arena drift build");
            if (fourth) {
                pass &= expect(
                    (fourth->aliased_domains() & detail::alias_domain_functions) == 0,
                    detail, "chunks gate arena drift detected");
            }
            cache_forget(arena_snapshot.get());
            cache_forget(inline_snapshot.get());
            cache_forget(gen2_snapshot.get());
            cache_forget(base.snapshot.get());
        }
    }
    {
        const auto pub_a = generate(corpus_config_t{60000, 20000, 8000, 2000, 12000,
            3000, 21, 0xA1DA0030ULL, false, false, false, false, false, false});
        const auto indexes_a = for_publication(pub_a.publication, {});
        pass &= expect(indexes_a != nullptr, detail, "aba gen build");
        const analysis_snapshot_t* key_a = pub_a.snapshot.get();
        const auto pub_d = generate(corpus_config_t{60000, 20000, 8000, 2000, 12000,
            3000, 22, 0xA1DA0031ULL, false, false, false, false, false, false});
        {
            auto& store = cache();
            std::lock_guard<std::mutex> lock(store.mutex);
            store.entries.erase(key_a);
            store.entries.emplace(key_a, std::make_shared<cache_entry_t>(
                std::weak_ptr<const analysis_snapshot_t>(pub_d.snapshot)));
        }
        const auto indexes_a2 = for_publication(pub_a.publication, {});
        pass &= expect(indexes_a2 != nullptr && indexes_a2 != indexes_a, detail,
            "aba guard did not rebuild after stale plant");
        if (indexes_a2) {
            pass &= run_differential(pub_a, *indexes_a2, detail, "aba");
        }
        const auto pub_b = generate(corpus_config_t{60000, 20000, 8000, 2000, 12000,
            3000, 23, 0xA1DA0032ULL, false, false, false, false, false, true});
        const auto indexes_b = for_publication(pub_b.publication, {});
        pass &= expect(indexes_b != nullptr && indexes_b != indexes_a, detail,
            "aba distinct publication");
        if (indexes_b)
            pass &= run_differential(pub_b, *indexes_b, detail, "aba_b_va");
        cache_forget(key_a);
        cache_forget(pub_d.snapshot.get());
        cache_forget(pub_b.snapshot.get());
    }
    {
        const auto corpus = generate(corpus_config_t{50000, 15000, 6000, 1500, 10000,
            2500, 31, 0xA1DA0040ULL, false, false, false, false, false, false});
        cancellation_source_t source;
        source.request_cancel();
        auto built = publication_indexes_t::build(corpus.publication, hints_t{},
            source.token());
        pass &= expect(!built.has_value() &&
            built.error().code == workspace_error_code_t::cancelled &&
            built.error().cancellation, detail, "cancelled build envelope");
        cache_forget(corpus.snapshot.get());
    }
    if (std::getenv("AIDA_PUBLICATION_INDEXES_SELFTEST_FULL") != nullptr) {
        const auto corpus = generate(corpus_config_t{30000000, 15000000, 5000000,
            100000, 300000, 100000, 41, 0xA1DA0050ULL,
            false, false, false, false, false, false});
        const auto build_begin = std::chrono::steady_clock::now();
        auto built = publication_indexes_t::build(corpus.publication, hints_t{}, {});
        const auto build_end = std::chrono::steady_clock::now();
        pass &= expect(built.has_value(), detail, "s30m build");
        if (built) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                build_end - build_begin).count();
            char line[200]{};
            std::snprintf(line, sizeof(line), "s30m build_ms=%lld\n",
                static_cast<long long>(elapsed));
            detail += line;
            const std::uint64_t xref_bytes =
                static_cast<std::uint64_t>(corpus.snapshot->xrefs.size()) *
                sizeof(xref_record_t);
            pass &= expect(built.value()->index_bytes() <= 2 * xref_bytes, detail,
                "s30m memory budget");
            pass &= run_differential(corpus, *built.value(), detail, "s30m");
            const auto targets = sample_xref_targets(*corpus.snapshot);
            volatile std::uint64_t sink = 0;
            const auto report = measure([&](std::size_t iteration) {
                const auto range = built.value()->xrefs_to(
                    targets[iteration % targets.size()]);
                std::uint64_t total = 0;
                const std::uint32_t stop = range.begin +
                    (std::min<std::uint32_t>)(range.end - range.begin, 1000);
                for (std::uint32_t ordinal = range.begin; ordinal < stop; ++ordinal)
                    total += corpus.snapshot->xrefs[
                        built.value()->xref_to_entry(ordinal)].id;
                sink += total;
            }, 200);
            append_timing(detail, "s30m_xrefs_to_page1k", report);
            pass &= expect(report.p99_us <= 5000.0, detail,
                "s30m timing p99 " + std::to_string(report.p99_us));
            (void)sink;
        }
        cache_forget(corpus.snapshot.get());
    }
    diag::log_tagged_fmt("publication_indexes", "selftest_complete pass=%d",
        pass ? 1 : 0);
    detail += pass ? "SELFTEST PASS\n" : "SELFTEST FAIL\n";
    return pass;
}

}
