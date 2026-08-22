#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/scan_pointer_preview.hpp"
#else

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "standalone_driver.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "scanner_task_center.hpp"
#include "../mcp/downstream_producer_governor.hpp"

namespace pointer_scanner {

struct pointer_data_t {
	uint64_t address = 0;
	bool     is_static = false;
	int      module_index = -1;
	uint64_t module_offset = 0;
};

struct pointer_chain_t {
	int                   module_index = -1;
	std::string           module_name;
	uint64_t              base_offset = 0;
	std::vector<int64_t>  offsets;
	int                   depth = 0;
	bool                  is_static = false;
	bool                  validated = false;
};

struct scan_config_t {
	uint64_t target_address = 0;
	int      max_depth = 4;
	int64_t  max_offset = 4096;
	int64_t  struct_size = 4096;
	bool     negative_offsets = false;
	bool     only_static_bases = true;
};

struct map_diagnostics_t {
	uint32_t    pid = 0;
	size_t      module_count = 0;
	size_t      raw_region_count = 0;
	size_t      scanned_region_count = 0;
	uint64_t    scanned_bytes = 0;
	size_t      candidate_pointer_count = 0;
	size_t      map_key_count = 0;
	size_t      map_entry_count = 0;
	uint64_t    duration_ms = 0;
	bool        cancelled = false;
	std::string source;
};

struct scan_diagnostics_t {
	uint32_t pid = 0;
	uint64_t target_address = 0;
	int      max_depth = 0;
	int64_t  max_offset = 0;
	int64_t  struct_size = 0;
	bool     negative_offsets = false;
	bool     only_static_bases = false;
	size_t   map_key_count = 0;
	size_t   map_entry_count = 0;
	size_t   chain_count = 0;
	uint64_t duration_ms = 0;
	bool     cancelled = false;
};

struct state_t {
	std::map<uint64_t, std::vector<pointer_data_t>> reverse_map;
	std::mutex                                       map_mutex;
	std::atomic<bool>                                map_building{false};
	std::atomic<float>                               map_progress{0.f};
	std::atomic<bool>                                map_cancel{false};
	size_t                                           map_entry_count = 0;

	std::vector<pointer_chain_t>                     results;
	std::mutex                                       results_mutex;
	std::atomic<bool>                                scanning{false};
	std::atomic<float>                               scan_progress{0.f};
	std::atomic<bool>                                scan_cancel{false};

	std::atomic<bool>                                validating{false};
	std::atomic<float>                               validate_progress{0.f};

	scan_config_t                                    config;
	std::vector<driver_bridge::module_info_t>         cached_modules;
	map_diagnostics_t                                last_map_diagnostics;
	scan_diagnostics_t                               last_scan_diagnostics;

	int                                              selected_result = -1;
	float                                            scroll_y = 0.f;
	float                                            target_scroll_y = 0.f;
	char                                             addr_buf[20] = {};
};

inline state_t g_state;

namespace detail {

inline bool is_static_address(uint64_t addr,
                              const std::vector<driver_bridge::module_info_t>& modules,
                              int& module_idx, uint64_t& module_offset)
{
	for (int i = 0; i < static_cast<int>(modules.size()); ++i) {
		auto& m = modules[i];
		if (addr >= m.base && addr < m.base + m.size) {
			module_idx = i;
			module_offset = addr - m.base;
			return true;
		}
	}
	return false;
}

inline bool is_valid_pointer_target(uint64_t value,
                                    const std::vector<driver_bridge::memory_region_t>& regions)
{
	for (auto& r : regions) {
		if (value >= r.base && value < r.base + r.size && r.state == 0x1000)
			return true;
	}
	return false;
}

struct rscan_context_t {
	const scan_config_t* config = nullptr;
	const std::map<uint64_t, std::vector<pointer_data_t>>* reverse_map = nullptr;
	std::vector<pointer_chain_t>* results = nullptr;
	std::mutex* results_mutex = nullptr;
	const std::vector<driver_bridge::module_info_t>* modules = nullptr;
	std::atomic<bool>* cancel = nullptr;

	std::vector<uint64_t> visited;
	std::vector<int64_t> current_offsets;
	size_t max_results = 10000;
};

inline void rscan(rscan_context_t& ctx, uint64_t value_to_find, int level)
{
	if (ctx.cancel->load()) return;
	if (level >= ctx.config->max_depth) return;

	{
		std::lock_guard<std::mutex> lk(*ctx.results_mutex);
		if (ctx.results->size() >= ctx.max_results) return;
	}

	for (auto& v : ctx.visited) {
		if (v == value_to_find) return;
	}
	ctx.visited.push_back(value_to_find);

	uint64_t start_value = (value_to_find > static_cast<uint64_t>(ctx.config->struct_size))
		? (value_to_find - static_cast<uint64_t>(ctx.config->struct_size)) : 0;
	uint64_t stop_value = value_to_find;
	if (ctx.config->negative_offsets)
		stop_value = value_to_find + static_cast<uint64_t>(ctx.config->struct_size);

	auto it_low = ctx.reverse_map->lower_bound(start_value);
	auto it_high = ctx.reverse_map->upper_bound(stop_value);

	for (auto it = it_low; it != it_high; ++it) {
		if (ctx.cancel->load()) break;

		uint64_t pointer_value = it->first;
		int64_t offset = static_cast<int64_t>(value_to_find) - static_cast<int64_t>(pointer_value);

		if (offset < -ctx.config->max_offset || offset > ctx.config->max_offset)
			continue;

		bool stop_outer = false;
		for (auto& pd : it->second) {
			if (ctx.cancel->load()) { stop_outer = true; break; }

			{
				std::lock_guard<std::mutex> lk(*ctx.results_mutex);
				if (ctx.results->size() >= ctx.max_results) { stop_outer = true; break; }
			}

			ctx.current_offsets.push_back(offset);

			if (pd.is_static) {
				pointer_chain_t chain;
				chain.module_index = pd.module_index;
				if (pd.module_index >= 0 && pd.module_index < static_cast<int>(ctx.modules->size()))
					chain.module_name = (*ctx.modules)[pd.module_index].name;
				chain.base_offset = pd.module_offset;
				chain.offsets.assign(ctx.current_offsets.rbegin(), ctx.current_offsets.rend());
				chain.depth = static_cast<int>(ctx.current_offsets.size());
				chain.is_static = true;

				std::lock_guard<std::mutex> lk(*ctx.results_mutex);
				ctx.results->push_back(std::move(chain));
			}

			if (!pd.is_static && !ctx.config->only_static_bases) {
				pointer_chain_t chain;
				chain.module_index = -1;
				chain.base_offset = pd.address;
				chain.offsets.assign(ctx.current_offsets.rbegin(), ctx.current_offsets.rend());
				chain.depth = static_cast<int>(ctx.current_offsets.size());
				chain.is_static = false;

				std::lock_guard<std::mutex> lk(*ctx.results_mutex);
				ctx.results->push_back(std::move(chain));
			}

			if (level + 1 < ctx.config->max_depth) {
				rscan(ctx, pd.address, level + 1);
			}

			ctx.current_offsets.pop_back();
		}
		if (stop_outer) break;
	}

	ctx.visited.pop_back();
}

}

inline void build_reverse_map()
{
	if (g_state.map_building.load()) {
		diag::log_tagged("pointer_scan", "build_reverse_map refused already_building");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("pointer_scan", "build_reverse_map refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}
	diag::log_tagged_fmt("pointer_scan", "build_reverse_map start pid=%u",
		driver_bridge::attached_pid());

	g_state.map_building.store(true);
	g_state.map_cancel.store(false);
	g_state.map_progress.store(0.f);
	{
		std::lock_guard<std::mutex> lk(g_state.map_mutex);
		g_state.last_map_diagnostics = {};
		g_state.last_map_diagnostics.pid = driver_bridge::attached_pid();
		g_state.last_map_diagnostics.source = "build_reverse_map";
	}

	mcp_standalone::downstream::producer_identity_t brm_id;
	brm_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	brm_id.tool_name = "build_reverse_map";
	mcp_standalone::downstream::scoped_admission_t brm_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(brm_id);
	if (!brm_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(brm_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT build_reverse_map reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		g_state.map_building.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT build_reverse_map token=%llu",
		static_cast<unsigned long long>(brm_admission.token()));

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.pointer_build_reverse_map";
	sub.thread_class = "scanner_pointer_map";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
		sub.target_pid = driver_bridge::attached_pid();
	const uint32_t target_pid = sub.target_pid;
	sub.lease_token = brm_admission.token();
	sub.body = [target_pid]() {
		auto t_start = std::chrono::steady_clock::now();
		auto modules = driver_bridge::enumerate_modules_for(target_pid);
		auto regions = driver_bridge::enumerate_memory_regions_for(target_pid, 4096);

		std::vector<driver_bridge::memory_region_t> readable;
		for (auto& r : regions) {
			if (r.state != 0x1000) continue;
			if (r.protect & 0x100) continue;
			uint32_t p = r.protect & 0xFF;
			if (p == 0x01 || p == 0x00) continue;
			if (r.size > 0x10000000) continue;
			readable.push_back(r);
		}

		uint64_t total_bytes = 0;
		for (auto& r : readable) total_bytes += r.size;
		if (total_bytes == 0) total_bytes = 1;
		uint64_t scanned = 0;
		std::sort(readable.begin(), readable.end(),
			[](const driver_bridge::memory_region_t& a, const driver_bridge::memory_region_t& b) {
				return a.base < b.base;
			});

		std::map<uint64_t, std::vector<pointer_data_t>> new_map;
		size_t entry_count = 0;

		for (auto& region : readable) {
			if (g_state.map_cancel.load()) break;

			const size_t chunk_size = 65536;
			for (uint64_t off = 0; off < region.size; off += chunk_size) {
				if (g_state.map_cancel.load()) break;

				size_t read_sz = chunk_size;
				if (off + read_sz > region.size)
					read_sz = static_cast<size_t>(region.size - off);

				std::vector<uint8_t> data;
				if (!driver_bridge::read_memory_for(target_pid, region.base + off, read_sz, data) ||
					data.size() != read_sz) {
					scanned += read_sz;
					g_state.map_progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
					continue;
				}

				for (size_t i = 0; i + 8 <= data.size(); i += 8) {
					uint64_t value = 0;
					std::memcpy(&value, data.data() + i, 8);

					if (value < 0x10000 || value > 0x00007FFFFFFFFFFF)
						continue;

					auto rit = std::upper_bound(readable.begin(), readable.end(), value,
						[](uint64_t needle, const driver_bridge::memory_region_t& r) {
							return needle < r.base;
						});
					if (rit == readable.begin())
						continue;
					--rit;
					if (value < rit->base || value >= rit->base + rit->size)
						continue;

					pointer_data_t pd;
					pd.address = region.base + off + i;

					int mod_idx = -1;
					uint64_t mod_off = 0;
					pd.is_static = detail::is_static_address(pd.address, modules, mod_idx, mod_off);
					pd.module_index = mod_idx;
					pd.module_offset = mod_off;

					new_map[value].push_back(pd);
					++entry_count;
				}

				scanned += read_sz;
				g_state.map_progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
			}
		}

		size_t module_count = modules.size();
		size_t raw_region_count = regions.size();
		size_t region_count = readable.size();
		{
			std::lock_guard<std::mutex> lk(g_state.map_mutex);
			g_state.reverse_map = std::move(new_map);
			g_state.map_entry_count = entry_count;
			g_state.cached_modules = std::move(modules);
			g_state.last_map_diagnostics.pid = driver_bridge::attached_pid();
			g_state.last_map_diagnostics.module_count = module_count;
			g_state.last_map_diagnostics.raw_region_count = raw_region_count;
			g_state.last_map_diagnostics.scanned_region_count = region_count;
			g_state.last_map_diagnostics.scanned_bytes = total_bytes;
			g_state.last_map_diagnostics.candidate_pointer_count = entry_count;
			g_state.last_map_diagnostics.map_key_count = g_state.reverse_map.size();
			g_state.last_map_diagnostics.map_entry_count = entry_count;
			g_state.last_map_diagnostics.source = "build_reverse_map";
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		{
			std::lock_guard<std::mutex> lk(g_state.map_mutex);
			g_state.last_map_diagnostics.duration_ms = dur_ms;
			g_state.last_map_diagnostics.cancelled = g_state.map_cancel.load();
		}
		diag::log_tagged_fmt("pointer_scan", "build_reverse_map done entries=%zu modules=%zu regions=%zu bytes=%llu duration_ms=%llu cancelled=%d",
			entry_count, module_count, region_count,
			static_cast<unsigned long long>(total_bytes),
			static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.map_cancel.load()));

		g_state.map_building.store(false);
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("pointer_scan", "build_reverse_map worker_queue_rejected");
		g_state.map_building.store(false);
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.pointer_scan", "memory.build_pointer_map", "Build pointer map",
		driver_bridge::attached_pid(), true, []() {
			g_state.map_cancel.store(true, std::memory_order_release);
			return true;
		});

	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE build_reverse_map token=%llu reason=dispatched",
		static_cast<unsigned long long>(brm_admission.token()));
	brm_admission.release("dispatched");
}

inline void start_scan()
{
	if (g_state.scanning.load() || g_state.map_building.load()) {
		diag::log_tagged_fmt("pointer_scan", "start_scan refused busy scanning=%d building=%d",
			static_cast<int>(g_state.scanning.load()),
			static_cast<int>(g_state.map_building.load()));
		return;
	}

	{
		std::lock_guard<std::mutex> lk(g_state.map_mutex);
		if (g_state.reverse_map.empty()) {
			diag::log_tagged("pointer_scan", "start_scan refused map_empty");
			return;
		}
	}

	if (g_state.config.target_address == 0) {
		diag::log_tagged("pointer_scan", "start_scan refused zero_target");
		return;
	}

	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("pointer_scan", "start_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}

	diag::log_tagged_fmt("pointer_scan", "start_scan target=0x%llX depth=%d max_offset=%lld struct=%lld neg=%d static_only=%d",
		static_cast<unsigned long long>(g_state.config.target_address),
		g_state.config.max_depth,
		static_cast<long long>(g_state.config.max_offset),
		static_cast<long long>(g_state.config.struct_size),
		static_cast<int>(g_state.config.negative_offsets),
		static_cast<int>(g_state.config.only_static_bases));
	{
		std::lock_guard<std::mutex> lk(g_state.map_mutex);
		g_state.last_scan_diagnostics = {};
		g_state.last_scan_diagnostics.pid = driver_bridge::attached_pid();
		g_state.last_scan_diagnostics.target_address = g_state.config.target_address;
		g_state.last_scan_diagnostics.max_depth = g_state.config.max_depth;
		g_state.last_scan_diagnostics.max_offset = g_state.config.max_offset;
		g_state.last_scan_diagnostics.struct_size = g_state.config.struct_size;
		g_state.last_scan_diagnostics.negative_offsets = g_state.config.negative_offsets;
		g_state.last_scan_diagnostics.only_static_bases = g_state.config.only_static_bases;
		g_state.last_scan_diagnostics.map_key_count = g_state.reverse_map.size();
		g_state.last_scan_diagnostics.map_entry_count = g_state.map_entry_count;
	}

	g_state.scanning.store(true);
	g_state.scan_cancel.store(false);
	g_state.scan_progress.store(0.f);

	mcp_standalone::downstream::producer_identity_t ss_id;
	ss_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ss_id.tool_name = "pointer_start_scan";
	mcp_standalone::downstream::scoped_admission_t ss_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ss_id);
	if (!ss_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ss_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_start_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		g_state.scan_progress.store(1.f);
		g_state.scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_start_scan token=%llu",
		static_cast<unsigned long long>(ss_admission.token()));

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.pointer_start_scan";
	sub.thread_class = "scanner_pointer_scan";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	sub.lease_token = ss_admission.token();
		const uint32_t target_pid = sub.target_pid;
		sub.body = [target_pid]() {
		try {
		auto t_start = std::chrono::steady_clock::now();
		std::vector<pointer_chain_t> results;
		std::mutex results_mutex;

		detail::rscan_context_t ctx;
		ctx.config = &g_state.config;
		ctx.reverse_map = &g_state.reverse_map;
		ctx.results = &results;
		ctx.results_mutex = &results_mutex;
		ctx.modules = &g_state.cached_modules;
		ctx.cancel = &g_state.scan_cancel;

		detail::rscan(ctx, g_state.config.target_address, 0);

		std::sort(results.begin(), results.end(), [](const pointer_chain_t& a, const pointer_chain_t& b) {
			if (a.is_static != b.is_static) return a.is_static > b.is_static;
			if (a.depth != b.depth) return a.depth < b.depth;
			return a.module_name < b.module_name;
		});

		size_t chain_count = results.size();
		size_t map_key_count = 0;
		size_t map_entry_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.map_mutex);
			map_key_count = g_state.reverse_map.size();
			map_entry_count = g_state.map_entry_count;
		}
		{
			std::lock_guard<std::mutex> lk(g_state.results_mutex);
			g_state.results = std::move(results);
			g_state.selected_result = -1;
		}

		g_state.scan_progress.store(1.f);

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		{
			std::lock_guard<std::mutex> lk(g_state.map_mutex);
			g_state.last_scan_diagnostics.pid = driver_bridge::attached_pid();
			g_state.last_scan_diagnostics.target_address = g_state.config.target_address;
			g_state.last_scan_diagnostics.max_depth = g_state.config.max_depth;
			g_state.last_scan_diagnostics.max_offset = g_state.config.max_offset;
			g_state.last_scan_diagnostics.struct_size = g_state.config.struct_size;
			g_state.last_scan_diagnostics.negative_offsets = g_state.config.negative_offsets;
			g_state.last_scan_diagnostics.only_static_bases = g_state.config.only_static_bases;
			g_state.last_scan_diagnostics.map_key_count = map_key_count;
			g_state.last_scan_diagnostics.map_entry_count = map_entry_count;
			g_state.last_scan_diagnostics.chain_count = chain_count;
			g_state.last_scan_diagnostics.duration_ms = dur_ms;
			g_state.last_scan_diagnostics.cancelled = g_state.scan_cancel.load();
		}
		diag::log_tagged_fmt("pointer_scan", "start_scan done chains=%zu duration_ms=%llu cancelled=%d",
			chain_count, static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.scan_cancel.load()));

		g_state.scanning.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("pointer_scan", "start_scan worker exception err='%s'", ex.what());
			g_state.scan_progress.store(1.f);
			g_state.scanning.store(false);
		} catch (...) {
			diag::log_tagged("pointer_scan", "start_scan worker exception err='<unknown>'");
			g_state.scan_progress.store(1.f);
			g_state.scanning.store(false);
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("pointer_scan", "start_scan worker_queue_rejected");
		g_state.scan_progress.store(1.f);
		g_state.scanning.store(false);
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.pointer_scan", "memory.scan_pointer_chains", "Scan pointer chains",
		driver_bridge::attached_pid(), true, []() {
			g_state.scan_cancel.store(true, std::memory_order_release);
			return true;
		});

	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_start_scan token=%llu reason=dispatched",
		static_cast<unsigned long long>(ss_admission.token()));
	ss_admission.release("dispatched");
}

inline bool validate_chain(const pointer_chain_t& chain)
{
	uint64_t base_addr = 0;

	{
		std::lock_guard<std::mutex> lk(g_state.map_mutex);
		if (chain.is_static && chain.module_index >= 0 &&
		    chain.module_index < static_cast<int>(g_state.cached_modules.size())) {
			base_addr = g_state.cached_modules[chain.module_index].base + chain.base_offset;
		} else {
			base_addr = chain.base_offset;
		}
	}

	uint64_t current = base_addr;
	const uint32_t target_pid = driver_bridge::attached_pid();
	if (target_pid == 0)
		return false;
	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory_for(target_pid, current, 8, buf) || buf.size() < 8)
			return false;

		uint64_t ptr_value = 0;
		std::memcpy(&ptr_value, buf.data(), 8);

		if (i + 1 < chain.offsets.size()) {
			current = ptr_value + chain.offsets[i];
		} else {
			uint64_t final_addr = ptr_value + chain.offsets[i];
			int64_t diff = static_cast<int64_t>(final_addr) - static_cast<int64_t>(g_state.config.target_address);
			return std::abs(diff) <= 8;
		}
	}

	return false;
}

inline void validate_all_results()
{
	if (g_state.validating.load()) {
		diag::log_tagged("pointer_scan", "validate_all_results refused already_validating");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("pointer_scan", "validate_all_results refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}

	size_t pending = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.results_mutex);
		pending = g_state.results.size();
	}
	if (pending == 0) {
		diag::log_tagged("pointer_scan", "validate_all_results no_results");
		return;
	}

	diag::log_tagged_fmt("pointer_scan", "validate_all_results start pending=%zu", pending);

	g_state.validating.store(true);
	g_state.validate_progress.store(0.f);

	mcp_standalone::downstream::producer_identity_t va_id;
	va_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	va_id.tool_name = "validate_all_results";
	mcp_standalone::downstream::scoped_admission_t va_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(va_id);
	if (!va_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(va_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT validate_all_results reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		g_state.validating.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT validate_all_results token=%llu",
		static_cast<unsigned long long>(va_admission.token()));

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.pointer_validate_all";
	sub.thread_class = "scanner_pointer_validate";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	sub.lease_token = va_admission.token();
	sub.body = []() {
		auto t_start = std::chrono::steady_clock::now();
		std::vector<pointer_chain_t> work;
		{
			std::lock_guard<std::mutex> lk(g_state.results_mutex);
			work = g_state.results;
		}

		size_t total = work.size();
		size_t valid_count = 0;
		for (size_t i = 0; i < work.size(); ++i) {
			if (g_state.scan_cancel.load()) break;
			work[i].validated = validate_chain(work[i]);
			if (work[i].validated) ++valid_count;
			if ((i & 0x3F) == 0 && total > 0)
				g_state.validate_progress.store(static_cast<float>(i + 1) / static_cast<float>(total));
		}

		{
			std::lock_guard<std::mutex> lk(g_state.results_mutex);
			if (g_state.results.size() == work.size()) {
				for (size_t i = 0; i < work.size(); ++i) {
					g_state.results[i].validated = work[i].validated;
				}
			}
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("pointer_scan", "validate_all_results done total=%zu valid=%zu duration_ms=%llu",
			total, valid_count, static_cast<unsigned long long>(dur_ms));

		g_state.validate_progress.store(1.f);
		g_state.validating.store(false);
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("pointer_scan", "validate_all_results worker_queue_rejected");
		g_state.validate_progress.store(1.f);
		g_state.validating.store(false);
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.pointer_scan", "memory.validate_pointer_chains", "Validate pointer chains",
		driver_bridge::attached_pid(), true, []() {
			g_state.scan_cancel.store(true, std::memory_order_release);
			return true;
		});

	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE validate_all_results token=%llu reason=dispatched",
		static_cast<unsigned long long>(va_admission.token()));
	va_admission.release("dispatched");
}

inline std::string chain_to_string(const pointer_chain_t& chain)
{
	std::string out;
	if (chain.is_static) {
		out = chain.module_name + "+0x";
		char buf[32];
		snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(chain.base_offset));
		out += buf;
	} else {
		char buf[32];
		snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		out = buf;
	}

	for (auto& off : chain.offsets) {
		char buf[32];
		if (off >= 0)
			snprintf(buf, sizeof(buf), " -> +0x%llX", static_cast<unsigned long long>(off));
		else
			snprintf(buf, sizeof(buf), " -> -0x%llX", static_cast<unsigned long long>(-off));
		out += buf;
	}
	return out;
}

inline std::string export_chain_cpp(const pointer_chain_t& chain)
{
	std::string out;
	out += "uintptr_t resolve_pointer(HANDLE hProcess, uintptr_t moduleBase) {\n";

	if (chain.is_static) {
		char buf[64];
		snprintf(buf, sizeof(buf), "    uintptr_t addr = moduleBase + 0x%llX;\n",
		         static_cast<unsigned long long>(chain.base_offset));
		out += buf;
	} else {
		char buf[64];
		snprintf(buf, sizeof(buf), "    uintptr_t addr = 0x%llX;\n",
		         static_cast<unsigned long long>(chain.base_offset));
		out += buf;
	}

	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		out += "    uintptr_t ptr;\n";
		out += "    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), &ptr, sizeof(ptr), nullptr);\n";

		char buf[64];
		if (chain.offsets[i] >= 0)
			snprintf(buf, sizeof(buf), "    addr = ptr + 0x%llX;\n",
			         static_cast<unsigned long long>(chain.offsets[i]));
		else
			snprintf(buf, sizeof(buf), "    addr = ptr - 0x%llX;\n",
			         static_cast<unsigned long long>(-chain.offsets[i]));
		out += buf;
	}

	out += "    return addr;\n";
	out += "}\n";
	return out;
}

inline std::string export_results_json()
{
	std::lock_guard<std::mutex> lk(g_state.results_mutex);
	std::string out = "[\n";
	for (size_t i = 0; i < g_state.results.size(); ++i) {
		auto& c = g_state.results[i];
		out += "  {\n";
		char buf[64];
		snprintf(buf, sizeof(buf), "    \"module\": \"%s\",\n", c.module_name.c_str());
		out += buf;
		snprintf(buf, sizeof(buf), "    \"base_offset\": \"0x%llX\",\n",
		         static_cast<unsigned long long>(c.base_offset));
		out += buf;
		out += "    \"offsets\": [";
		for (size_t j = 0; j < c.offsets.size(); ++j) {
			snprintf(buf, sizeof(buf), "\"0x%llX\"", static_cast<unsigned long long>(c.offsets[j]));
			out += buf;
			if (j + 1 < c.offsets.size()) out += ", ";
		}
		out += "],\n";
		snprintf(buf, sizeof(buf), "    \"depth\": %d,\n", c.depth);
		out += buf;
		snprintf(buf, sizeof(buf), "    \"static\": %s,\n", c.is_static ? "true" : "false");
		out += buf;
		snprintf(buf, sizeof(buf), "    \"valid\": %s\n", c.validated ? "true" : "false");
		out += buf;
		out += "  }";
		if (i + 1 < g_state.results.size()) out += ",";
		out += "\n";
	}
	out += "]\n";
	return out;
}

inline void cancel_all()
{
	diag::log_tagged("pointer_scan", "cancel_all signalled");
	g_state.map_cancel.store(true);
	g_state.scan_cancel.store(true);
}

inline void clear_results()
{
	std::lock_guard<std::mutex> lk(g_state.results_mutex);
	size_t had = g_state.results.size();
	g_state.results.clear();
	g_state.selected_result = -1;
	diag::log_tagged_fmt("pointer_scan", "clear_results cleared=%zu", had);
}

inline void clear_map()
{
	std::lock_guard<std::mutex> lk(g_state.map_mutex);
	size_t had = g_state.map_entry_count;
	g_state.reverse_map.clear();
	g_state.map_entry_count = 0;
	g_state.last_map_diagnostics = {};
	g_state.last_scan_diagnostics = {};
	diag::log_tagged_fmt("pointer_scan", "clear_map cleared=%zu", had);
}

}

#endif
