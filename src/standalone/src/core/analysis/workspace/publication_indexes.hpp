#pragma once

#include "analysis_workspace.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xref_db {
struct call_graph_node_t;
}

namespace aida::analysis::publication_indexes {

struct hints_t {
    bool xrefs_unchanged = false;
    bool functions_unchanged = false;
    bool edges_unchanged = false;
    bool call_graph_unchanged = false;
    bool symbols_unchanged = false;
};

struct xref_range_t {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;
};

struct module_entry_t {
    std::uint64_t from = 0;
    std::uint64_t to = 0;
    int type = 0;
};

namespace detail {

struct key_entry_t {
    std::uint64_t value = 0;
    std::uint32_t offset = 0;
    address_space_id_t space = address_space_id_t::relative_virtual;
};

static_assert(sizeof(key_entry_t) == 16,
              "publication index key entries must remain 16 bytes");

struct address_key_t {
    std::uint64_t value = 0;
    address_space_id_t space = address_space_id_t::relative_virtual;

    friend bool operator==(const address_key_t& lhs, const address_key_t& rhs) noexcept {
        return lhs.value == rhs.value && lhs.space == rhs.space;
    }
};

struct address_key_hash_t {
    std::size_t operator()(const address_key_t& key) const noexcept {
        std::uint64_t value = key.value;
        value ^= static_cast<std::uint64_t>(key.space) << 56;
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdULL;
        value ^= value >> 33;
        value *= 0xc4ceb9fe1a85ec53ULL;
        value ^= value >> 33;
        return static_cast<std::size_t>(value);
    }
};

using function_exact_map_t =
    std::unordered_map<address_key_t, std::uint32_t, address_key_hash_t>;

inline constexpr std::uint32_t alias_domain_xrefs = 1U << 0;
inline constexpr std::uint32_t alias_domain_functions = 1U << 1;
inline constexpr std::uint32_t alias_domain_edges = 1U << 2;
inline constexpr std::uint32_t alias_domain_symbols = 1U << 3;
inline constexpr std::uint32_t alias_domain_call_graph = 1U << 4;

}

class publication_indexes_t final {
public:
    static workspace_result_t<std::shared_ptr<const publication_indexes_t>> build(
        const std::shared_ptr<const analysis_publication_t>& publication,
        const hints_t& hints, const cancellation_token_t& cancel);

    xref_range_t xrefs_to(const address_t& target) const noexcept;
    xref_range_t xrefs_from(const address_t& source) const noexcept;
    std::uint32_t xref_to_entry(std::uint32_t ordinal) const noexcept;
    std::uint32_t xref_from_entry(std::uint32_t ordinal) const noexcept;
    std::uint64_t xref_count_to(const address_t& target) const noexcept;
    std::size_t xref_target_key_count() const noexcept;
    address_t xref_target_key_at(std::size_t index) const noexcept;
    xref_range_t xref_target_run_at(std::size_t index) const noexcept;

    const function_record_t* function_containing(const address_t& addr) const noexcept;
    const function_record_t* function_at_exact_start(const address_t& addr) const noexcept;
    bool functions_sorted_disjoint() const noexcept;

    xref_range_t call_edges_from(const function_record_t& fn) const noexcept;
    std::uint32_t call_edge_entry(std::uint32_t ordinal) const noexcept;
    std::pair<std::uint32_t, std::uint32_t> function_call_degree(
        std::size_t function_ordinal) const noexcept;

    const symbol_record_t* symbol_exact_named(const address_t& addr) const noexcept;
    const symbol_record_t* data_symbol_exact(const address_t& addr) const noexcept;

    workspace_result_t<std::shared_ptr<const std::vector<xref_db::call_graph_node_t>>>
        call_graph(std::size_t max_nodes, const cancellation_token_t& cancel,
                   std::function<bool()> stop = {}) const;

    workspace_result_t<std::pair<std::vector<module_entry_t>, std::vector<module_entry_t>>>
        module_index_pairs(
            const std::function<std::uint64_t(const address_t&)>& display_address,
            const std::function<int(xref_kind_t)>& map_kind,
            const cancellation_token_t& cancel,
            std::function<bool()> stop = {}) const;

    const std::shared_ptr<const analysis_snapshot_t>& snapshot() const noexcept {
        return snapshot_;
    }
    std::uint64_t index_bytes() const noexcept {
        return bytes_.load(std::memory_order_acquire);
    }
    std::uint64_t accounted_bytes() const noexcept {
        return accounted_bytes_.load(std::memory_order_acquire);
    }
    void account_transferred_bytes(std::uint64_t bytes) const noexcept {
        accounted_bytes_.fetch_add(bytes, std::memory_order_acq_rel);
    }
    std::uint64_t live_fresh_bytes() const noexcept;
    std::uint32_t aliased_domains() const noexcept {
        return aliased_domains_.load(std::memory_order_acquire);
    }

private:
    publication_indexes_t() = default;

    static workspace_result_t<void> build_impl(
        const std::shared_ptr<const analysis_publication_t>& publication,
        const hints_t& hints, const cancellation_token_t& cancel,
        const std::shared_ptr<const publication_indexes_t>& previous,
        const std::shared_ptr<publication_indexes_t>& output);

    void register_fresh_array(const std::shared_ptr<const void>& array,
                              std::uint64_t bytes);

    std::shared_ptr<const analysis_snapshot_t> snapshot_;

    std::shared_ptr<const std::vector<detail::key_entry_t>> target_keys_;
    std::shared_ptr<const std::vector<std::uint32_t>> target_entries_;

    std::shared_ptr<const std::vector<detail::key_entry_t>> source_keys_;
    std::shared_ptr<const std::vector<std::uint32_t>> source_entries_;
    bool source_order_verified_ = false;

    bool functions_verified_ = false;
    std::shared_ptr<const detail::function_exact_map_t> function_exact_fallback_;

    bool edge_order_verified_ = false;
    std::shared_ptr<const std::vector<std::uint32_t>> edge_source_ordinals_;
    std::shared_ptr<const std::vector<std::uint32_t>> calls_in_;
    std::shared_ptr<const std::vector<std::uint32_t>> calls_out_;

    bool symbol_order_verified_ = false;
    std::shared_ptr<const std::vector<std::uint32_t>> symbol_ordinals_;

    mutable std::shared_mutex call_graph_mutex_;
    mutable std::size_t call_graph_memo_max_nodes_ = 0;
    mutable std::uint64_t call_graph_memo_bytes_ = 0;
    mutable std::shared_ptr<const std::vector<xref_db::call_graph_node_t>> call_graph_memo_;

    mutable std::mutex fresh_arrays_mutex_;
    std::vector<std::pair<std::shared_ptr<const void>, std::uint64_t>> fresh_arrays_;
    mutable std::atomic<std::uint64_t> bytes_{0};
    mutable std::atomic<std::uint64_t> accounted_bytes_{0};
    std::atomic<std::uint32_t> aliased_domains_{0};
};

workspace_result_t<std::shared_ptr<const publication_indexes_t>> for_publication_result(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel = {});

std::shared_ptr<const publication_indexes_t> for_publication(
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel = {});

void prebuild(const std::shared_ptr<const analysis_publication_t>& publication,
              const hints_t& hints = {});

bool differential_selftest(std::string& detail);

}
