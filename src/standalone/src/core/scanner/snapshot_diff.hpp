#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <shlobj.h>
#include <commdlg.h>
#endif

#include "imgui/imgui.h"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/scan_preview_runtime.hpp"
#else
#include "standalone_driver.hpp"
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../infra/executor.hpp"
#include "scanner_task_center.hpp"
#endif
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

namespace snapshot_diff {

struct memory_region_t {
	uint64_t             base = 0;
	uint64_t             size = 0;
	uint32_t             protect = 0;
	std::vector<uint8_t> data;
};

struct snapshot_t {
	uint64_t                   id = 0;
	std::string                name;
	uint32_t                   pid = 0;
	int64_t                    timestamp = 0;
	std::vector<memory_region_t> regions;
	uint64_t                   total_bytes = 0;
};

enum class change_type_t : int {
	unknown = 0,
	pointer_changed,
	float_changed,
	counter_incremented,
	counter_decremented,
	string_modified,
	zeroed_out,
	byte_flip,
};

struct changed_region_t {
	uint64_t             address = 0;
	uint32_t             size = 0;
	std::vector<uint8_t> old_data;
	std::vector<uint8_t> new_data;
	change_type_t        type = change_type_t::unknown;
	std::string          module_name;
};

struct diff_result_t {
	std::string                  snap_a_name;
	std::string                  snap_b_name;
	std::vector<changed_region_t> changes;
	uint64_t                     total_changed_bytes = 0;
	std::size_t                  changed_page_count = 0;
	bool                         truncated = false;
};

struct state_t {
	std::vector<std::shared_ptr<const snapshot_t>> snapshots;
	uint64_t                    snap_a_id = 0;
	uint64_t                    snap_b_id = 0;
	std::shared_ptr<const diff_result_t> published_diff = std::make_shared<const diff_result_t>();
	std::mutex                  mutex;
	std::atomic<bool>           capturing{false};
	std::atomic<bool>           comparing{false};
	std::atomic<bool>           loading{false};
	std::atomic<float>          progress{0.f};
	std::atomic<bool>           cancel{false};
	std::atomic<uint64_t>       operation_generation{1};
	int                         snap_counter = 0;
	std::atomic<uint64_t>       next_snap_id{1};
	std::string                 last_error;

	int                         selected_change = -1;
	std::shared_ptr<const diff_result_t> visible_diff;

	float                       compare_cursor_t = 0.f;
	bool                        compare_cursor_active = false;
};

inline state_t g_state;

inline std::string last_error()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	return g_state.last_error;
}

inline void set_last_error(std::string error)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.last_error = std::move(error);
}

namespace detail {

inline constexpr std::uint64_t maximum_snapshot_bytes = 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t maximum_region_bytes = 256ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t maximum_snapshot_regions = 4096;
inline constexpr std::size_t maximum_diff_ranges = 250000;
inline constexpr std::uint32_t maximum_snapshot_name_bytes = 128;
inline constexpr std::uint64_t maximum_snapshot_file_bytes = maximum_snapshot_bytes +
	static_cast<std::uint64_t>(maximum_snapshot_regions) * 20ULL +
	maximum_snapshot_name_bytes + 32ULL;

inline std::filesystem::path snapshot_dir()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return {};
#else
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"snapshots";
		CoTaskMemFree(appdata);
		return p;
	}
	return std::filesystem::current_path() / "snapshots";
#endif
}

inline change_type_t classify_change(const uint8_t* old_data, const uint8_t* new_data, uint32_t size)
{
	bool all_zero_new = true;
	for (uint32_t i = 0; i < size; ++i)
		if (new_data[i] != 0) { all_zero_new = false; break; }
	if (all_zero_new) return change_type_t::zeroed_out;

	if (size == 4) {
		float old_f, new_f;
		std::memcpy(&old_f, old_data, 4);
		std::memcpy(&new_f, new_data, 4);
		if (std::isfinite(old_f) && std::isfinite(new_f) &&
		    std::abs(old_f) < 1e12f && std::abs(new_f) < 1e12f)
			return change_type_t::float_changed;

		int32_t old_i, new_i;
		std::memcpy(&old_i, old_data, 4);
		std::memcpy(&new_i, new_data, 4);
		if (new_i == old_i + 1) return change_type_t::counter_incremented;
		if (new_i == old_i - 1) return change_type_t::counter_decremented;
	}

	if (size == 8) {
		uint64_t old_val, new_val;
		std::memcpy(&old_val, old_data, 8);
		std::memcpy(&new_val, new_data, 8);
		if (old_val > 0x10000 && new_val > 0x10000 &&
		    old_val < 0x00007FFFFFFFFFFF && new_val < 0x00007FFFFFFFFFFF)
			return change_type_t::pointer_changed;
	}

	if (size >= 4) {
		bool is_string = true;
		for (uint32_t i = 0; i < size; ++i) {
			if (old_data[i] == 0) break;
			if (old_data[i] < 0x20 || old_data[i] > 0x7E) { is_string = false; break; }
		}
		if (is_string) return change_type_t::string_modified;
	}

	if (size == 1) return change_type_t::byte_flip;

	return change_type_t::unknown;
}

inline const char* change_type_name(change_type_t t)
{
	switch (t) {
	case change_type_t::pointer_changed:     return "Pointer";
	case change_type_t::float_changed:       return "Float";
	case change_type_t::counter_incremented: return "Counter++";
	case change_type_t::counter_decremented: return "Counter--";
	case change_type_t::string_modified:     return "String";
	case change_type_t::zeroed_out:          return "Zeroed";
	case change_type_t::byte_flip:           return "Byte";
	default:                                 return "Unknown";
	}
}

inline aida::ui::components::pill_kind_t change_pill_kind(change_type_t t)
{
	switch (t) {
	case change_type_t::pointer_changed:     return aida::ui::components::pill_kind_t::warning;
	case change_type_t::float_changed:       return aida::ui::components::pill_kind_t::info;
	case change_type_t::counter_incremented: return aida::ui::components::pill_kind_t::success;
	case change_type_t::counter_decremented: return aida::ui::components::pill_kind_t::success;
	case change_type_t::string_modified:     return aida::ui::components::pill_kind_t::accent;
	case change_type_t::zeroed_out:          return aida::ui::components::pill_kind_t::error;
	case change_type_t::byte_flip:           return aida::ui::components::pill_kind_t::neutral;
	default:                                 return aida::ui::components::pill_kind_t::neutral;
	}
}

inline bool save_snapshot(const snapshot_t& snap, std::string& error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::scan::record("snapshot.save", snap.name);
	error.clear();
	return true;
#else
	error.clear();
	if (snap.regions.size() > maximum_snapshot_regions ||
		snap.total_bytes > maximum_snapshot_bytes) {
		error = "save_snapshot: snapshot exceeds the bounded persistence limit";
		return false;
	}
	auto dir = snapshot_dir();
	std::error_code filesystem_error;
	std::filesystem::create_directories(dir, filesystem_error);
	if (filesystem_error) {
		error = "save_snapshot: cannot create snapshot directory: " + filesystem_error.message();
		return false;
	}

	char fname[128];
	const auto unique_tick = std::chrono::high_resolution_clock::now().time_since_epoch().count();
	snprintf(fname, sizeof(fname), "snapshot_%lld_%llu_%llu.bin",
		static_cast<long long>(snap.timestamp),
		static_cast<unsigned long long>(snap.id),
		static_cast<unsigned long long>(unique_tick));
	auto path = dir / fname;
	auto temporary = path;
	temporary += ".aida-tmp";
	std::filesystem::remove(temporary, filesystem_error);
	filesystem_error.clear();

	std::ofstream ofs(temporary, std::ios::binary | std::ios::trunc);
	if (!ofs.is_open()) {
		error = "save_snapshot: failed to create temporary snapshot";
		return false;
	}

	uint32_t name_len = static_cast<uint32_t>((std::min)(snap.name.size(),
		static_cast<std::size_t>(maximum_snapshot_name_bytes)));
	ofs.write(reinterpret_cast<const char*>(&name_len), 4);
	ofs.write(snap.name.data(), name_len);
	ofs.write(reinterpret_cast<const char*>(&snap.pid), 4);
	ofs.write(reinterpret_cast<const char*>(&snap.timestamp), 8);
	uint32_t region_count = static_cast<uint32_t>(snap.regions.size());
	ofs.write(reinterpret_cast<const char*>(&region_count), 4);

	for (auto& r : snap.regions) {
		if (r.data.size() > maximum_region_bytes) {
			error = "save_snapshot: region exceeds the bounded persistence limit";
			break;
		}
		ofs.write(reinterpret_cast<const char*>(&r.base), 8);
		uint64_t rsize = r.data.size();
		ofs.write(reinterpret_cast<const char*>(&rsize), 8);
		ofs.write(reinterpret_cast<const char*>(&r.protect), 4);
		if (rsize > 0)
			ofs.write(reinterpret_cast<const char*>(r.data.data()), static_cast<std::streamsize>(rsize));
		if (!ofs) {
			error = "save_snapshot: snapshot write failed or was partial";
			break;
		}
	}
	ofs.flush();
	if (!ofs && error.empty()) error = "save_snapshot: snapshot flush failed";
	ofs.close();
	if (!error.empty()) {
		std::filesystem::remove(temporary, filesystem_error);
		return false;
	}
	const auto encoded_size = std::filesystem::file_size(temporary, filesystem_error);
	if (filesystem_error || encoded_size > maximum_snapshot_file_bytes) {
		error = "save_snapshot: persisted snapshot size verification failed";
		std::filesystem::remove(temporary, filesystem_error);
		return false;
	}
	std::filesystem::rename(temporary, path, filesystem_error);
	if (filesystem_error) {
		error = "save_snapshot: atomic commit failed: " + filesystem_error.message();
		std::filesystem::remove(temporary, filesystem_error);
		return false;
	}
	return true;
#endif
}

inline bool load_snapshot(const std::string& path, snapshot_t& out, std::string& error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)path;
	out = {};
	error = "load_snapshot: preview fixture import is unavailable";
	return false;
#else
	error.clear();
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) {
		error = "load_snapshot: failed to open file";
		return false;
	}
	ifs.seekg(0, std::ios::end);
	const auto encoded_size = ifs.tellg();
	if (encoded_size < 0 || static_cast<std::uint64_t>(encoded_size) > maximum_snapshot_file_bytes) {
		error = "load_snapshot: file exceeds the bounded snapshot limit";
		return false;
	}
	ifs.seekg(0, std::ios::beg);

	uint32_t name_len = 0;
	if (!ifs.read(reinterpret_cast<char*>(&name_len), 4)) {
		error = "load_snapshot: failed reading name length";
		return false;
	}
	if (name_len > maximum_snapshot_name_bytes) {
		error = "load_snapshot: implausible name length";
		return false;
	}

	std::string name;
	name.resize(name_len);
	if (name_len > 0) {
		if (!ifs.read(name.data(), static_cast<std::streamsize>(name_len))) {
			error = "load_snapshot: failed reading name";
			return false;
		}
	}

	uint32_t pid = 0;
	int64_t  ts = 0;
	uint32_t region_count = 0;
	if (!ifs.read(reinterpret_cast<char*>(&pid), 4) ||
	    !ifs.read(reinterpret_cast<char*>(&ts), 8) ||
	    !ifs.read(reinterpret_cast<char*>(&region_count), 4)) {
		error = "load_snapshot: failed reading header";
		return false;
	}

	if (region_count > maximum_snapshot_regions) {
		error = "load_snapshot: implausible region count";
		return false;
	}

	out = snapshot_t{};
	out.name = std::move(name);
	out.pid = pid;
	out.timestamp = ts;
	out.regions.reserve(region_count);

	for (uint32_t i = 0; i < region_count; ++i) {
		memory_region_t r;
		uint64_t rsize = 0;
		if (!ifs.read(reinterpret_cast<char*>(&r.base), 8) ||
		    !ifs.read(reinterpret_cast<char*>(&rsize), 8) ||
		    !ifs.read(reinterpret_cast<char*>(&r.protect), 4)) {
			error = "load_snapshot: failed reading region header";
			return false;
		}

		if (rsize > maximum_region_bytes || out.total_bytes > maximum_snapshot_bytes - rsize) {
			error = "load_snapshot: implausible region size";
			return false;
		}

		r.size = rsize;
		if (rsize > 0) {
			r.data.resize(static_cast<std::size_t>(rsize));
			if (!ifs.read(reinterpret_cast<char*>(r.data.data()), static_cast<std::streamsize>(rsize))) {
				error = "load_snapshot: failed reading region data";
				return false;
			}
		}

		out.total_bytes += rsize;
		out.regions.push_back(std::move(r));
	}
	if (ifs.peek() != std::char_traits<char>::eof()) {
		error = "load_snapshot: unexpected trailing payload";
		return false;
	}

	return true;
#endif
}

}

inline void take_snapshot(const std::string& name = "")
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_state.capturing.store(true);
	snapshot_t snapshot;
	snapshot.id = g_state.next_snap_id.fetch_add(1);
	snapshot.name = name;
	if (snapshot.name.empty()) {
		++g_state.snap_counter;
		snapshot.name = "Snap" + std::to_string(g_state.snap_counter);
	}
	snapshot.pid = 6420;
	snapshot.timestamp = 1710000000 + static_cast<std::int64_t>(snapshot.id) * 12;
	for (int region_index = 0; region_index < 3; ++region_index) {
		memory_region_t region;
		region.base = 0x00007FF7A4C00000ULL + static_cast<std::uint64_t>(region_index) * 0x1000ULL;
		region.size = 256;
		region.protect = region_index == 0 ? 0x20 : 0x04;
		region.data.resize(static_cast<std::size_t>(region.size));
		for (std::size_t index = 0; index < region.data.size(); ++index)
			region.data[index] = static_cast<std::uint8_t>(
				(index * 29U + static_cast<std::size_t>(region_index) * 47U) & 0xFFU);
		if (snapshot.id > 1 && region_index == 1) {
			region.data[40] = static_cast<std::uint8_t>(region.data[40] + 1);
			region.data[41] = 0;
			region.data[42] ^= 0x80;
		}
		snapshot.total_bytes += region.data.size();
		snapshot.regions.push_back(std::move(region));
	}
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		g_state.snapshots.push_back(std::make_shared<const snapshot_t>(std::move(snapshot)));
		if (g_state.snapshots.size() > 10) g_state.snapshots.erase(g_state.snapshots.begin());
	}
	g_state.progress.store(1.f);
	g_state.capturing.store(false);
	aida::preview::scan::record("snapshot.capture", g_state.snapshots.back()->name);
#else
	if (g_state.capturing.load()) {
		diag::log_tagged("snapshot_diff", "take_snapshot refused already_capturing");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("snapshot_diff", "take_snapshot refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		set_last_error("take_snapshot: no process attached");
		return;
	}

	g_state.capturing.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	const std::uint64_t operation_generation =
		g_state.operation_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
	const std::uint32_t target_pid = driver_bridge::attached_pid();

	std::string snap_name = name;
	if (snap_name.empty()) {
		++g_state.snap_counter;
		char buf[32];
		snprintf(buf, sizeof(buf), "Snap%d", g_state.snap_counter);
		snap_name = buf;
	}

	diag::log_tagged_fmt("snapshot_diff", "take_snapshot start name='%s' pid=%u",
		snap_name.c_str(), driver_bridge::attached_pid());

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.snapshot_take";
	sub.thread_class = "scanner_snapshot";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = target_pid;
	sub.generation = operation_generation;
	sub.body = [snap_name, operation_generation, target_pid]() {
		auto t_start = std::chrono::steady_clock::now();
		snapshot_t snap;
		snap.id = g_state.next_snap_id.fetch_add(1);
		snap.name = snap_name;
		snap.pid = target_pid;
		snap.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();

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

		uint64_t total = 0;
		for (auto& r : readable) total += r.size;
		if (total == 0) total = 1;
		uint64_t done = 0;

		bool bounded = false;
		for (auto& r : readable) {
			if (g_state.cancel.load()) break;
			if (snap.total_bytes >= detail::maximum_snapshot_bytes) {
				bounded = true;
				break;
			}

			memory_region_t sr;
			sr.base = r.base;
			sr.protect = r.protect;
			const std::uint64_t remaining = detail::maximum_snapshot_bytes - snap.total_bytes;
			const std::uint64_t requested = (std::min)({r.size,
				detail::maximum_region_bytes, remaining});
			bounded = bounded || requested < r.size;

			const bool read_ok = requested > 0 &&
				driver_bridge::read_memory_for(target_pid, r.base,
					static_cast<std::size_t>(requested), sr.data);
			if (!read_ok || sr.data.size() != static_cast<std::size_t>(requested)) {
				const std::size_t returned = sr.data.size();
				const std::uint64_t unreadable = r.base + static_cast<std::uint64_t>(returned);
				std::lock_guard<std::mutex> lock(g_state.mutex);
				char address_text[32]{};
				std::snprintf(address_text, sizeof(address_text), "0x%016llX",
					static_cast<unsigned long long>(unreadable));
				g_state.last_error = "snapshot read failed at " + std::string(address_text) +
					" unreadable=" + std::to_string(requested - returned) +
					" requested=" + std::to_string(requested) +
					" returned=" + std::to_string(returned);
				diag::log_tagged_fmt("snapshot_diff",
					"take_snapshot read_failed pid=%u first_unreadable=0x%llX unreadable=%llu requested=%llu returned=%zu",
					target_pid, static_cast<unsigned long long>(unreadable),
					static_cast<unsigned long long>(requested - returned),
					static_cast<unsigned long long>(requested), returned);
				g_state.capturing.store(false, std::memory_order_release);
				g_state.progress.store(1.f, std::memory_order_release);
				return;
			}
			if (read_ok) {
				sr.size = sr.data.size();
				snap.total_bytes += sr.data.size();
				snap.regions.push_back(std::move(sr));
			}

			done += r.size;
			g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
		}
		if (g_state.cancel.load(std::memory_order_acquire) ||
			driver_bridge::attached_pid() != target_pid ||
			g_state.operation_generation.load(std::memory_order_acquire) != operation_generation) {
			g_state.progress.store(1.f);
			g_state.capturing.store(false);
			return;
		}

		std::string persistence_error;
		const bool persisted = detail::save_snapshot(snap, persistence_error);
		if (!persisted) {
			std::lock_guard<std::mutex> lock(g_state.mutex);
			g_state.last_error = persistence_error;
		}

		std::size_t region_count = snap.regions.size();
		uint64_t total_bytes = snap.total_bytes;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snapshots.size() >= 10) {
			uint64_t evicted_id = g_state.snapshots.front()->id;
				g_state.snapshots.erase(g_state.snapshots.begin());
				if (g_state.snap_a_id == evicted_id) g_state.snap_a_id = 0;
				if (g_state.snap_b_id == evicted_id) g_state.snap_b_id = 0;
				diag::log_tagged_fmt("snapshot_diff", "take_snapshot evicted_oldest id=%llu",
					static_cast<unsigned long long>(evicted_id));
			}
			g_state.snapshots.push_back(std::make_shared<const snapshot_t>(std::move(snap)));
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("snapshot_diff", "take_snapshot done name='%s' regions=%zu bytes=%llu duration_ms=%llu cancelled=%d",
			snap_name.c_str(), region_count,
			static_cast<unsigned long long>(total_bytes),
			static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.cancel.load()));
		if (!persisted)
			diag::log_tagged_fmt("snapshot_diff", "take_snapshot persistence_failed err='%s'",
				persistence_error.c_str());
		if (bounded)
			diag::log_tagged_fmt("snapshot_diff", "take_snapshot bounded bytes=%llu limit=%llu",
				static_cast<unsigned long long>(total_bytes),
				static_cast<unsigned long long>(detail::maximum_snapshot_bytes));

		g_state.progress.store(1.f);
		g_state.capturing.store(false);
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("snapshot_diff", "take_snapshot worker_queue_rejected");
		set_last_error("take_snapshot: worker queue rejected the task");
		g_state.progress.store(1.f);
		g_state.capturing.store(false);
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.snapshot_diff", "memory.capture_snapshot", "Capture memory snapshot",
		driver_bridge::attached_pid(), true, []() {
			g_state.cancel.store(true, std::memory_order_release);
			return true;
		});
#endif
}

inline void load_from_disk(const std::string& path)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	take_snapshot("Imported Snapshot");
	aida::preview::scan::record("snapshot.load", path.empty() ? "fixture" : path);
#else
	if (g_state.loading.load() || g_state.capturing.load()) {
		diag::log_tagged_fmt("snapshot_diff", "load_from_disk refused busy loading=%d capturing=%d",
			static_cast<int>(g_state.loading.load()),
			static_cast<int>(g_state.capturing.load()));
		return;
	}

	g_state.loading.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	const std::uint64_t operation_generation =
		g_state.operation_generation.fetch_add(1, std::memory_order_acq_rel) + 1;

	std::string fallback_name;
	{
		++g_state.snap_counter;
		char buf[32];
		snprintf(buf, sizeof(buf), "Snap%d", g_state.snap_counter);
		fallback_name = buf;
	}

	diag::log_tagged_fmt("snapshot_diff", "load_from_disk start path='%s'", path.c_str());

	std::string path_copy = path;
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.snapshot_load";
	sub.thread_class = "scanner_snapshot";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 3;
	sub.generation = operation_generation;
	sub.body = [path_copy, fallback_name, operation_generation]() {
		auto t_start = std::chrono::steady_clock::now();
		snapshot_t snap;
		std::string load_error;
		if (!detail::load_snapshot(path_copy, snap, load_error)) {
			{
				std::lock_guard<std::mutex> lock(g_state.mutex);
				g_state.last_error = load_error;
			}
			diag::log_tagged_fmt("snapshot_diff", "load_from_disk failed path='%s' err='%s'",
				path_copy.c_str(), load_error.c_str());
			g_state.progress.store(1.f);
			g_state.loading.store(false);
			return;
		}
		if (g_state.cancel.load(std::memory_order_acquire) ||
			g_state.operation_generation.load(std::memory_order_acquire) != operation_generation) {
			g_state.progress.store(1.f);
			g_state.loading.store(false);
			return;
		}

		snap.id = g_state.next_snap_id.fetch_add(1);
		if (snap.name.empty()) {
			snap.name = fallback_name;
		}

		std::size_t region_count = snap.regions.size();
		uint64_t total_bytes = snap.total_bytes;
		std::string snap_name = snap.name;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snapshots.size() >= 10) {
				uint64_t evicted_id = g_state.snapshots.front()->id;
				g_state.snapshots.erase(g_state.snapshots.begin());
				if (g_state.snap_a_id == evicted_id) g_state.snap_a_id = 0;
				if (g_state.snap_b_id == evicted_id) g_state.snap_b_id = 0;
				diag::log_tagged_fmt("snapshot_diff", "load_from_disk evicted_oldest id=%llu",
					static_cast<unsigned long long>(evicted_id));
			}
			g_state.snapshots.push_back(std::make_shared<const snapshot_t>(std::move(snap)));
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("snapshot_diff", "load_from_disk done path='%s' name='%s' regions=%zu bytes=%llu duration_ms=%llu",
			path_copy.c_str(), snap_name.c_str(), region_count,
			static_cast<unsigned long long>(total_bytes),
			static_cast<unsigned long long>(dur_ms));

		g_state.progress.store(1.f);
		g_state.loading.store(false);
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("snapshot_diff", "load_from_disk worker_queue_rejected");
		set_last_error("load_from_disk: worker queue rejected the task");
		g_state.progress.store(1.f);
		g_state.loading.store(false);
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.snapshot_diff", "memory.load_snapshot", "Load memory snapshot",
		driver_bridge::attached_pid());
#endif
}

inline void compare_snapshots(uint64_t id_a, uint64_t id_b)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_state.comparing.store(true);
	diff_result_t result;
	std::shared_ptr<const snapshot_t> first;
	std::shared_ptr<const snapshot_t> second;
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		for (const auto& snapshot : g_state.snapshots) {
			if (snapshot->id == id_a) first = snapshot;
			if (snapshot->id == id_b) second = snapshot;
		}
	}
	if (!first || !second) {
		g_state.comparing.store(false);
		return;
	}
	result.snap_a_name = first->name;
	result.snap_b_name = second->name;
	for (std::size_t region_index = 0;
		region_index < first->regions.size() && region_index < second->regions.size(); ++region_index) {
		const auto& old_region = first->regions[region_index];
		const auto& new_region = second->regions[region_index];
		const std::size_t size = (std::min)(old_region.data.size(), new_region.data.size());
		bool region_changed = false;
		for (std::size_t index = 0; index < size; ++index) {
			if (old_region.data[index] == new_region.data[index]) continue;
			changed_region_t change;
			change.address = old_region.base + index;
			change.size = 1;
			change.old_data = {old_region.data[index]};
			change.new_data = {new_region.data[index]};
			change.type = detail::classify_change(change.old_data.data(), change.new_data.data(), 1);
			change.module_name = "sample.exe";
			result.changes.push_back(std::move(change));
			++result.total_changed_bytes;
			region_changed = true;
			if (result.changes.size() >= detail::maximum_diff_ranges) {
				result.truncated = true;
				break;
			}
		}
		if (region_changed) ++result.changed_page_count;
		if (result.truncated) break;
	}
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		g_state.published_diff = std::make_shared<const diff_result_t>(std::move(result));
	}
	g_state.progress.store(1.f);
	g_state.comparing.store(false);
	g_state.compare_cursor_active = false;
	aida::preview::scan::record("snapshot.compare", std::to_string(id_a) + ":" + std::to_string(id_b));
#else
	if (g_state.comparing.load()) {
		diag::log_tagged("snapshot_diff", "compare_snapshots refused already_comparing");
		return;
	}
	if (id_a == 0 || id_b == 0 || id_a == id_b) {
		diag::log_tagged_fmt("snapshot_diff", "compare_snapshots refused invalid_ids a=%llu b=%llu",
			static_cast<unsigned long long>(id_a),
			static_cast<unsigned long long>(id_b));
		return;
	}

	diag::log_tagged_fmt("snapshot_diff", "compare_snapshots start a=%llu b=%llu",
		static_cast<unsigned long long>(id_a),
		static_cast<unsigned long long>(id_b));

	g_state.comparing.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	const std::uint64_t operation_generation =
		g_state.operation_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
	g_state.compare_cursor_active = true;
	g_state.compare_cursor_t = 0.f;

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.snapshot_compare";
	sub.thread_class = "scanner_snapshot_compare";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	sub.generation = operation_generation;
	sub.body = [id_a, id_b, operation_generation]() {
		try {
		auto t_start = std::chrono::steady_clock::now();
		diff_result_t result;

		std::shared_ptr<const snapshot_t> snap_a;
		std::shared_ptr<const snapshot_t> snap_b;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			for (const auto& s : g_state.snapshots) {
				if (s->id == id_a) snap_a = s;
				if (s->id == id_b) snap_b = s;
			}
			if (!snap_a || !snap_b) {
				g_state.last_error = (!snap_a && !snap_b)
					? "compare_snapshots: both snapshots evicted"
					: (!snap_a
						? "compare_snapshots: snapshot A evicted"
						: "compare_snapshots: snapshot B evicted");
				g_state.comparing.store(false);
				g_state.compare_cursor_active = false;
				return;
			}
		}

		result.snap_a_name = snap_a->name;
		result.snap_b_name = snap_b->name;

		std::unordered_map<uint64_t, std::size_t> b_map;
		for (std::size_t i = 0; i < snap_b->regions.size(); ++i)
			b_map[snap_b->regions[i].base] = i;

		auto modules = driver_bridge::enumerate_modules();
		std::sort(modules.begin(), modules.end(),
			[](const auto& left, const auto& right) { return left.base < right.base; });

		uint64_t total = snap_a->regions.size();
		if (total == 0) total = 1;
		uint64_t done = 0;

		for (const auto& ra : snap_a->regions) {
			if (g_state.cancel.load()) break;

			auto it = b_map.find(ra.base);
			if (it == b_map.end()) {
				++done;
				g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
				continue;
			}

			const auto& rb = snap_b->regions[it->second];
			uint64_t cmp_size = (std::min)(ra.size, rb.size);
			uint64_t min_data = (std::min)(ra.data.size(), rb.data.size());
			if (min_data < cmp_size) cmp_size = min_data;

			uint64_t i = 0;
			while (i < cmp_size) {
				if ((i & 0xFFFFF) == 0 && g_state.cancel.load()) break;
				if (ra.data[i] == rb.data[i]) { ++i; continue; }

				uint64_t start = i;
				while (i < cmp_size && ra.data[i] != rb.data[i] && (i - start) < 64)
					++i;

				changed_region_t cr;
				cr.address = ra.base + start;
				cr.size = static_cast<uint32_t>(i - start);
				cr.old_data.assign(ra.data.begin() + start, ra.data.begin() + i);
				cr.new_data.assign(rb.data.begin() + start, rb.data.begin() + i);
				cr.type = detail::classify_change(cr.old_data.data(), cr.new_data.data(), cr.size);

				const auto module_after = std::upper_bound(modules.begin(), modules.end(), cr.address,
					[](std::uint64_t address, const auto& module) { return address < module.base; });
				if (module_after != modules.begin()) {
					const auto& module = *std::prev(module_after);
					if (cr.address >= module.base && cr.address - module.base < module.size)
						cr.module_name = module.name;
				}

				const std::uint32_t changed_size = cr.size;
				result.changes.push_back(std::move(cr));
				result.total_changed_bytes += changed_size;
				if (result.changes.size() >= detail::maximum_diff_ranges) {
					result.truncated = true;
					break;
				}
			}

			++result.changed_page_count;
			++done;
			g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
			if (result.truncated) break;
		}

		std::size_t changes_count = result.changes.size();
		uint64_t changed_bytes = result.total_changed_bytes;
		std::size_t changed_pages = result.changed_page_count;
		if (g_state.cancel.load(std::memory_order_acquire) ||
			g_state.operation_generation.load(std::memory_order_acquire) != operation_generation) {
			g_state.progress.store(1.f);
			g_state.comparing.store(false);
			g_state.compare_cursor_active = false;
			return;
		}
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.published_diff = std::make_shared<const diff_result_t>(std::move(result));
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("snapshot_diff", "compare_snapshots done a=%llu b=%llu changes=%zu changed_pages=%zu changed_bytes=%llu duration_ms=%llu cancelled=%d",
			static_cast<unsigned long long>(id_a),
			static_cast<unsigned long long>(id_b),
			changes_count, changed_pages,
			static_cast<unsigned long long>(changed_bytes),
			static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.cancel.load()));

		g_state.progress.store(1.f);
		g_state.comparing.store(false);
		g_state.compare_cursor_active = false;
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("snapshot_diff", "compare_snapshots worker_exception err='%s'", ex.what());
			set_last_error(ex.what());
			g_state.progress.store(1.f);
			g_state.comparing.store(false);
			g_state.compare_cursor_active = false;
		} catch (...) {
			diag::log_tagged("snapshot_diff", "compare_snapshots worker_exception err='<unknown>'");
			set_last_error("compare_snapshots: worker threw an unknown exception");
			g_state.progress.store(1.f);
			g_state.comparing.store(false);
			g_state.compare_cursor_active = false;
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("snapshot_diff", "compare_snapshots worker_queue_rejected");
		set_last_error("compare_snapshots: worker queue rejected the task");
		g_state.progress.store(1.f);
		g_state.comparing.store(false);
		g_state.compare_cursor_active = false;
		return;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.snapshot_diff", "memory.compare_snapshots", "Compare memory snapshots",
		driver_bridge::attached_pid(), true, []() {
			g_state.cancel.store(true, std::memory_order_release);
			return true;
		});
#endif
}

inline void clear_snapshots()
{
	diag::log_tagged("snapshot_diff", "clear_snapshots signalled");
	g_state.cancel.store(true);
	g_state.operation_generation.fetch_add(1, std::memory_order_acq_rel);
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::size_t had = g_state.snapshots.size();
	g_state.snapshots.clear();
	g_state.published_diff = std::make_shared<const diff_result_t>();
	g_state.snap_a_id = 0;
	g_state.snap_b_id = 0;
	g_state.snap_counter = 0;
	g_state.selected_change = -1;
	diag::log_tagged_fmt("snapshot_diff", "clear_snapshots cleared=%zu", had);
}

namespace detail {

inline void render_timeline(ImDrawList* dl, float ox, float oy, float w, float h, float a)
{
	const auto& t = aida::ui::resolved();
	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.panel_bg, a), 10.f);
	dl->AddRect(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.border_subtle, a), 10.f, 0, 1.f);

	struct marker_t {
		std::uint64_t id = 0;
		std::string name;
	};
	std::vector<marker_t> markers;
	std::uint64_t selected_a = 0;
	std::uint64_t selected_b = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		markers.reserve(g_state.snapshots.size());
		for (const auto& snapshot : g_state.snapshots)
			markers.push_back({snapshot->id, snapshot->name});
		selected_a = g_state.snap_a_id;
		selected_b = g_state.snap_b_id;
	}
	const std::size_t snap_count = markers.size();

	float track_y = oy + h * 0.5f;
	float pad_x = 28.f;
	float track_x0 = ox + pad_x;
	float track_x1 = ox + w - pad_x;
	float track_w = track_x1 - track_x0;

	dl->AddLine(ImVec2(track_x0, track_y), ImVec2(track_x1, track_y),
		aida::ui::with_alpha(t.border_strong, a), 2.f);

	if (snap_count == 0U) {
		dl->AddText(body_font, body_font_size,
			ImVec2(ox + w * 0.5f - 80.f, oy + h * 0.5f - 5.f),
			aida::ui::with_alpha(t.text_dim, a),
			"Capture snapshots to populate the timeline");
		return;
	}

	float seg = (snap_count > 1U) ? track_w / static_cast<float>(snap_count - 1U) : 0.f;

	std::size_t idx_a = snap_count;
	std::size_t idx_b = snap_count;
	for (std::size_t i = 0; i < snap_count; ++i) {
		if (selected_a != 0 && markers[i].id == selected_a) idx_a = i;
		if (selected_b != 0 && markers[i].id == selected_b) idx_b = i;
	}

	std::size_t hot_marker = snap_count;
	for (std::size_t i = 0; i < snap_count; ++i) {
		float mx = (snap_count > 1U)
			? (track_x0 + seg * static_cast<float>(i))
			: (track_x0 + track_w * 0.5f);
		float my = track_y;
		ImGui::PushID(static_cast<int>(i) + 100000);
		ImGui::SetCursorScreenPos(ImVec2(mx - 12.f, my - 12.f));
		ImGui::InvisibleButton("##mk", ImVec2(24.f, 24.f));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool clk_r = ImGui::IsItemClicked(ImGuiMouseButton_Right);
		ImGui::PopID();
		if (hov) hot_marker = i;
		uint64_t this_id = markers[i].id;
		if (clk) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snap_a_id == this_id) g_state.snap_a_id = 0;
			else if (g_state.snap_b_id == this_id) g_state.snap_b_id = 0;
			else if (g_state.snap_a_id == 0) g_state.snap_a_id = this_id;
			else if (g_state.snap_b_id == 0) g_state.snap_b_id = this_id;
			else g_state.snap_b_id = this_id;
		}
		if (clk_r) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snap_a_id == this_id) g_state.snap_a_id = 0;
			if (g_state.snap_b_id == this_id) g_state.snap_b_id = 0;
		}
	}

	if (idx_a < snap_count && idx_b < snap_count) {
		float ax = (snap_count > 1U)
			? (track_x0 + seg * static_cast<float>(idx_a))
			: (track_x0 + track_w * 0.5f);
		float bx = (snap_count > 1U)
			? (track_x0 + seg * static_cast<float>(idx_b))
			: (track_x0 + track_w * 0.5f);
		if (ax > bx) std::swap(ax, bx);
		dl->AddRectFilledMultiColor(
			ImVec2(ax, track_y - 2.f), ImVec2(bx, track_y + 2.f),
			t.accent_grad_top, t.accent_grad_top,
			t.accent_grad_bot, t.accent_grad_bot);

		if (g_state.compare_cursor_active) {
			float dt = aida::ui::clock::dt();
			g_state.compare_cursor_t += dt * 1.4f;
			if (g_state.compare_cursor_t > 1.f) {
				g_state.compare_cursor_t = 0.f;
				if (!g_state.comparing.load()) g_state.compare_cursor_active = false;
			}
			float cx_pos = ax + (bx - ax) * g_state.compare_cursor_t;
			dl->AddCircleFilled(ImVec2(cx_pos, track_y), 5.f,
				aida::ui::with_alpha(t.accent_u32, a), 24);
			dl->AddCircle(ImVec2(cx_pos, track_y), 9.f,
				aida::ui::with_alpha(t.accent_u32, a * 0.4f), 24, 1.5f);
		}
	}

	for (std::size_t i = 0; i < snap_count; ++i) {
		float mx = (snap_count > 1U)
			? (track_x0 + seg * static_cast<float>(i))
			: (track_x0 + track_w * 0.5f);
		float my = track_y;
		bool is_a = (idx_a == i);
		bool is_b = (idx_b == i);
		bool is_hot = (hot_marker == i);

		ImU32 outer = aida::ui::with_alpha(t.panel_header, a);
		ImU32 inner = aida::ui::with_alpha(t.text_secondary, a);
		float r_outer = 7.f;
		if (is_a || is_b) {
			outer = aida::ui::with_alpha(t.accent_u32, a);
			inner = aida::ui::with_alpha(t.accent_grad_top, a);
			r_outer = 9.f;
		}
		if (is_hot) {
			r_outer += 2.f;
			dl->AddCircle(ImVec2(mx, my), r_outer + 4.f,
				aida::ui::with_alpha(t.accent_u32, a * 0.5f), 24, 1.5f);
		}

		dl->AddCircleFilled(ImVec2(mx, my), r_outer, outer, 24);
		dl->AddCircleFilled(ImVec2(mx, my), r_outer - 3.f, inner, 24);

		const std::string& nm = markers[i].name;
		ImVec2 ts = ImGui::CalcTextSize(nm.c_str());
		dl->AddText(body_font, body_font_size,
			ImVec2(mx - ts.x * 0.5f, my + 11.f),
			aida::ui::with_alpha(t.text_secondary, a), nm.c_str());

		if (is_a) {
			dl->AddText(body_font, body_font_size,
				ImVec2(mx - 5.f, my - 22.f),
				aida::ui::with_alpha(t.accent_u32, a), "A");
		}
		if (is_b) {
			dl->AddText(body_font, body_font_size,
				ImVec2(mx - 5.f, my - 22.f),
				aida::ui::with_alpha(t.accent_u32, a), "B");
		}
	}
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static bool seeded = false;
	if (!seeded) {
		take_snapshot("Before Patch");
		take_snapshot("After Patch");
		compare_snapshots(g_state.snapshots[0]->id, g_state.snapshots[1]->id);
		g_state.snap_a_id = g_state.snapshots[0]->id;
		g_state.snap_b_id = g_state.snapshots[1]->id;
		seeded = true;
	}
#endif
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;

	const auto& t = aida::ui::resolved();
	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	ImFont* body_em_font = aida::ui::fonts::body_em();
	if (!body_em_font) body_em_font = body_font;
	const float body_em_font_size = aida::ui::fonts::size_or(body_em_font, 14.f);
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height),
		aida::ui::with_alpha(t.bg_base, a));

	float toolbar_h = 52.f;
	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float cx = x0 + 16.f;
	float cy = y0 + (toolbar_h - 32.f) * 0.5f;

	{
		dl->AddText(body_em_font, body_em_font_size,
			ImVec2(cx, y0 + (toolbar_h - body_em_font_size) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), "Snapshot Diff");
		ImVec2 ts = ImGui::CalcTextSize("Snapshot Diff");
		cx += ts.x + 24.f;
	}

	const float btn_gap = 14.f;

	bool busy = g_state.capturing.load() || g_state.comparing.load() || g_state.loading.load();
	bool taking = g_state.capturing.load();
	bool comparing = g_state.comparing.load();
	bool loading = g_state.loading.load();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool live_attach = true;
#else
	bool live_attach = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
#endif

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = taking ? "Capturing..." : "Take Snapshot";
		if (aida::ui::button(lbl, aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy || !live_attach, nullptr, taking)) {
			diag::log_tagged("scan_audit",
				"[scan_audit] snapshot_diff take_snapshot");
			take_snapshot();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	std::size_t snap_count = 0;
	std::uint64_t selected_snapshot_a = 0;
	std::uint64_t selected_snapshot_b = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snap_count = g_state.snapshots.size();
		selected_snapshot_a = g_state.snap_a_id;
		selected_snapshot_b = g_state.snap_b_id;
	}

	bool can_compare = (!busy && snap_count >= 2U &&
		selected_snapshot_a != 0 && selected_snapshot_b != 0 &&
		selected_snapshot_a != selected_snapshot_b);

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = comparing ? "Comparing..." : "Compare";
		if (aida::ui::button(lbl, aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !can_compare, nullptr, comparing)) {
			diag::log_tagged("scan_audit",
				"[scan_audit] snapshot_diff compare");
			compare_snapshots(selected_snapshot_a, selected_snapshot_b);
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Clear All", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy || snap_count == 0U)) {
			clear_snapshots();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl_load = loading ? "Loading..." : "Load";
		if (aida::ui::button(lbl_load, aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy, nullptr, loading)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			load_from_disk({});
#else
			auto initial_dir = detail::snapshot_dir();
			std::string initial_dir_str = initial_dir.string();
			char path_buf[MAX_PATH] = {};
			static const char k_snapshot_filter[] =
				"Snapshot (*.bin)\0*.bin\0"
				"All files (*.*)\0*.*\0\0";
			if (win32_dialog::show_open_file_dialog_ex(g_hwnd,
					"Load Snapshot",
					k_snapshot_filter,
					initial_dir_str.c_str(),
					path_buf, sizeof(path_buf),
					"snapshot_diff::load")) {
				std::string picked(path_buf);
				load_from_disk(picked);
			}
#endif
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		float prog = g_state.progress.load();
		float bar_w = 180.f;
		float bar_x = x0 + width - bar_w - 16.f;
		float bar_y = y0 + (toolbar_h - 6.f) * 0.5f;
		if (busy) {
			aida::ui::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 6.f, prog, false, true);
		} else {
			char info[64];
			snprintf(info, sizeof(info), "%zu snapshot%s", snap_count, snap_count == 1U ? "" : "s");
			ImVec2 ts = ImGui::CalcTextSize(info);
			dl->AddText(body_font, body_font_size,
				ImVec2(x0 + width - ts.x - 16.f, y0 + (toolbar_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a), info);
		}
	}

	float callout_h = 0.f;
	if (!live_attach) {
		callout_h = 26.f;
		ui_anim::render_inline_callout(dl, x0 + 12.f, y0 + toolbar_h + 4.f,
			width - 24.f, 22.f,
			"Take/Compare need a live attach. Load existing snapshot files from disk to inspect them.",
			ui_anim::callout_kind_t::info, 0.6f, 0.6f, 0.85f, a);
	}

	float timeline_h = 64.f;
	detail::render_timeline(dl, x0 + 12.f, y0 + toolbar_h + callout_h + 8.f,
		width - 24.f, timeline_h, a);

	float content_y = y0 + toolbar_h + callout_h + 8.f + timeline_h + 8.f;
	float content_h = (y0 + height) - content_y;

	float detail_h = (g_state.selected_change >= 0) ? 180.f : 0.f;
	float table_h = content_h - detail_h;

	float col_addr_w = 130.f;
	float col_old_w = 170.f;
	float col_new_w = 170.f;
	float col_type_w = 100.f;
	float col_mod_w = width - col_addr_w - col_old_w - col_new_w - col_type_w - 36.f;
	if (col_mod_w < 60.f) col_mod_w = 60.f;

	float hdr_h = 26.f;
	dl->AddRectFilled(ImVec2(x0, content_y),
		ImVec2(x0 + width, content_y + hdr_h),
		aida::ui::with_alpha(t.panel_header, a * 0.85f));
	dl->AddLine(ImVec2(x0, content_y + hdr_h),
		ImVec2(x0 + width, content_y + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	const char* col_names[5] = { "Address", "Old Value", "New Value", "Type", "Module" };
	float col_widths[5] = { col_addr_w, col_old_w, col_new_w, col_type_w, col_mod_w };
	float hx = x0 + 12.f;
	for (std::size_t c = 0; c < 5U; ++c) {
		dl->AddText(body_font, body_font_size,
			ImVec2(hx, content_y + (hdr_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	std::shared_ptr<const diff_result_t> diff_snapshot;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		diff_snapshot = g_state.published_diff;
	}
	if (!diff_snapshot)
		diff_snapshot = std::make_shared<const diff_result_t>();
	if (diff_snapshot->truncated) {
		const char* bounded_label = "Bounded to first 250,000 change ranges";
		const ImVec2 bounded_size = ImGui::CalcTextSize(bounded_label);
		dl->AddText(body_font, body_font_size,
			ImVec2(x0 + width - bounded_size.x - 12.f,
				content_y + (hdr_h - body_font_size) * 0.5f),
			aida::ui::with_alpha(t.warning, a), bounded_label);
	}
	if (g_state.visible_diff != diff_snapshot) {
		g_state.visible_diff = diff_snapshot;
		g_state.selected_change = -1;
	}

	float body_y = content_y + hdr_h;
	float body_h = (table_h > hdr_h) ? (table_h - hdr_h) : 0.f;

	ImGui::SetCursorScreenPos(ImVec2(x0, body_y));
	ImGui::BeginChild("##snap_diff_table", ImVec2(width, body_h), false,
	                  ImGuiWindowFlags_NoBackground);

	static float diff_row_anim_time = 0.f;
	diff_row_anim_time += aida::ui::clock::dt();

	float row_height = 22.f;
	ImGuiListClipper clipper;
	const int visible_count = static_cast<int>((std::min)(
		diff_snapshot->changes.size(), static_cast<std::size_t>(2147483647)));
	clipper.Begin(visible_count, row_height);
	while (clipper.Step()) for (int row_index = clipper.DisplayStart;
		row_index < clipper.DisplayEnd; ++row_index) {
		const auto& c = diff_snapshot->changes[static_cast<std::size_t>(row_index)];
		ImVec2 rp = ImGui::GetCursorScreenPos();

		float entrance = ui_anim::render_row_entrance(row_index, diff_row_anim_time, 0.012f);
		bool hov = ImGui::IsMouseHoveringRect(rp, ImVec2(rp.x + width, rp.y + row_height), true);
		bool sel = (g_state.selected_change == row_index);

		if (sel) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(t.selection, a * entrance));
			dl->AddRectFilled(rp, ImVec2(rp.x + 3.f, rp.y + row_height),
				aida::ui::with_alpha(t.accent_u32, a * entrance));
		} else if (hov) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(t.hover_wash, a * entrance));
		} else if ((static_cast<std::size_t>(row_index) & 1U) != 0U) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), a * entrance));
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_state.selected_change = row_index;

		char addr_str[24];
		snprintf(addr_str, sizeof(addr_str), "0x%llX", static_cast<unsigned long long>(c.address));
		dl->AddText(code_font, code_font_size,
			ImVec2(rp.x + 12.f, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * entrance), addr_str);

		float old_x = rp.x + 12.f + col_addr_w;
		std::string old_hex;
		const std::size_t old_preview_count = (std::min)({
			static_cast<std::size_t>(c.size), c.old_data.size(), std::size_t{8}});
		for (std::size_t j = 0; j < old_preview_count; ++j) {
			char hb[4];
			snprintf(hb, sizeof(hb), "%02X ", static_cast<unsigned int>(c.old_data[j]));
			old_hex += hb;
		}
		if (c.size > 8) old_hex += "...";
		dl->AddText(code_font, code_font_size,
			ImVec2(old_x, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.error, a * entrance), old_hex.c_str());

		float new_x = old_x + col_old_w;
		std::string new_hex;
		const std::size_t new_preview_count = (std::min)({
			static_cast<std::size_t>(c.size), c.new_data.size(), std::size_t{8}});
		for (std::size_t j = 0; j < new_preview_count; ++j) {
			char hb[4];
			snprintf(hb, sizeof(hb), "%02X ", static_cast<unsigned int>(c.new_data[j]));
			new_hex += hb;
		}
		if (c.size > 8) new_hex += "...";
		dl->AddText(code_font, code_font_size,
			ImVec2(new_x, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.success, a * entrance), new_hex.c_str());

		float type_x = new_x + col_new_w;
		ImGui::SetCursorScreenPos(ImVec2(type_x, rp.y + (row_height - 18.f) * 0.5f));
		ImGui::PushID(row_index + 8192);
		aida::ui::pill_kind(detail::change_type_name(c.type), detail::change_pill_kind(c.type),
			aida::ui::size_t_::sm, true);
		ImGui::PopID();

		float mod_x = type_x + col_type_w;
		if (!c.module_name.empty()) {
			dl->AddText(body_font, body_font_size,
				ImVec2(mod_x, rp.y + (row_height - 11.f) * 0.5f),
				aida::ui::with_alpha(t.text_dim, a * entrance), c.module_name.c_str());
		}

		ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + row_height));
	}
	clipper.End();

	if (diff_snapshot->changes.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		if (snap_count == 0U) {
			cfg.title = "No snapshots yet";
			cfg.body = "Capture two snapshots of the target process, then compare them to see what changed.";
		} else {
			cfg.title = "Pick A and B";
			cfg.body = "Click two markers on the timeline above and press Compare.";
		}
		aida::ui::empty_state::render(ImVec2(x0, body_y), ImVec2(width, body_h), cfg);
	}

	ImGui::EndChild();

	if (g_state.selected_change >= 0 &&
		static_cast<std::size_t>(g_state.selected_change) < diff_snapshot->changes.size()) {
		const auto& c = diff_snapshot->changes[static_cast<std::size_t>(g_state.selected_change)];
		float dy = y0 + height - detail_h;
		dl->AddLine(ImVec2(x0, dy), ImVec2(x0 + width, dy),
			aida::ui::with_alpha(t.border_subtle, a), 1.f);
		dl->AddRectFilled(ImVec2(x0, dy), ImVec2(x0 + width, y0 + height),
			aida::ui::with_alpha(t.panel_bg, a));

		dl->AddText(body_em_font, 13.f,
			ImVec2(x0 + 16.f, dy + 10.f),
			aida::ui::with_alpha(t.text_primary, a), "Detail");

		char addr_info[80];
		snprintf(addr_info, sizeof(addr_info), "0x%llX  ·  %u bytes",
		         static_cast<unsigned long long>(c.address), c.size);
		dl->AddText(body_font, body_font_size,
			ImVec2(x0 + 70.f, dy + 11.f),
			aida::ui::with_alpha(t.text_secondary, a), addr_info);

		float hex_y = dy + 36.f;
		float byte_w = 26.f;
		float byte_h = 22.f;
		float row_pad_x = 16.f;

		dl->AddText(body_font, body_font_size,
			ImVec2(x0 + row_pad_x, hex_y + (byte_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.error, a), "Old");
		float ohx = x0 + row_pad_x + 36.f;
		const std::size_t old_detail_count = (std::min)({
			static_cast<std::size_t>(c.size), c.old_data.size(), std::size_t{32}});
		for (std::size_t j = 0; j < old_detail_count; ++j) {
			char hb[4];
			snprintf(hb, sizeof(hb), "%02X", static_cast<unsigned int>(c.old_data[j]));
			bool diff = (j < c.new_data.size() && c.old_data[j] != c.new_data[j]);
			if (diff) {
				dl->AddRectFilled(ImVec2(ohx - 3.f, hex_y),
					ImVec2(ohx + byte_w - 3.f, hex_y + byte_h),
					aida::ui::with_alpha(t.error_soft, a), 4.f);
			}
			dl->AddText(code_font, code_font_size,
				ImVec2(ohx, hex_y + (byte_h - 12.f) * 0.5f),
				aida::ui::with_alpha(diff ? t.error : t.text_dim, a), hb);
			ohx += byte_w;
		}

		hex_y += byte_h + 6.f;
		dl->AddText(body_font, body_font_size,
			ImVec2(x0 + row_pad_x, hex_y + (byte_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.success, a), "New");
		float nhx = x0 + row_pad_x + 36.f;
		const std::size_t new_detail_count = (std::min)({
			static_cast<std::size_t>(c.size), c.new_data.size(), std::size_t{32}});
		for (std::size_t j = 0; j < new_detail_count; ++j) {
			char hb[4];
			snprintf(hb, sizeof(hb), "%02X", static_cast<unsigned int>(c.new_data[j]));
			bool diff = (j < c.old_data.size() && c.old_data[j] != c.new_data[j]);
			if (diff) {
				dl->AddRectFilled(ImVec2(nhx - 3.f, hex_y),
					ImVec2(nhx + byte_w - 3.f, hex_y + byte_h),
					aida::ui::with_alpha(t.success_soft, a), 4.f);
			}
			dl->AddText(code_font, code_font_size,
				ImVec2(nhx, hex_y + (byte_h - 12.f) * 0.5f),
				aida::ui::with_alpha(diff ? t.success : t.text_dim, a), hb);
			nhx += byte_w;
		}

		hex_y += byte_h + 8.f;
		if (c.size == 4) {
			float old_f, new_f;
			std::memcpy(&old_f, c.old_data.data(), 4);
			std::memcpy(&new_f, c.new_data.data(), 4);
			int32_t old_i, new_i;
			std::memcpy(&old_i, c.old_data.data(), 4);
			std::memcpy(&new_i, c.new_data.data(), 4);

			char val_info[160];
			snprintf(val_info, sizeof(val_info), "Int32: %d -> %d   Float: %.6f -> %.6f",
			         old_i, new_i, old_f, new_f);
			dl->AddText(code_font, code_font_size,
				ImVec2(x0 + row_pad_x, hex_y),
				aida::ui::with_alpha(t.text_secondary, a), val_info);
		} else if (c.size == 8) {
			uint64_t old_v, new_v;
			std::memcpy(&old_v, c.old_data.data(), 8);
			std::memcpy(&new_v, c.new_data.data(), 8);
			char val_info[160];
			snprintf(val_info, sizeof(val_info), "UInt64: 0x%llX -> 0x%llX",
			         static_cast<unsigned long long>(old_v), static_cast<unsigned long long>(new_v));
			dl->AddText(code_font, code_font_size,
				ImVec2(x0 + row_pad_x, hex_y),
				aida::ui::with_alpha(t.text_secondary, a), val_info);
		}
	}
}

}
