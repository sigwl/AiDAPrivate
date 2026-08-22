
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "memory_scanner.hpp"
#include "struct_dissector.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../helpers/diag_log.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace scanner_tools {

namespace {

std::atomic<uint64_t> g_scan_session_counter{1};
std::atomic<uint64_t> g_active_scan_session{0};
std::atomic<uint64_t> g_pointer_session_counter{1};
std::atomic<uint64_t> g_active_pointer_session{0};

static uint64_t next_scan_session_id()
{
	return g_scan_session_counter.fetch_add(1, std::memory_order_relaxed);
}

static uint64_t next_pointer_session_id()
{
	return g_pointer_session_counter.fetch_add(1, std::memory_order_relaxed);
}

static std::string lower_copy(std::string s)
{
	for (char& c : s)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

}

static memory_scanner::value_type_t parse_value_type(const std::string& s) {
	const std::string v = lower_copy(s);
	if (v == "byte")    return memory_scanner::value_type_t::byte_val;
	if (v == "int16")   return memory_scanner::value_type_t::int16_val;
	if (v == "int32")   return memory_scanner::value_type_t::int32_val;
	if (v == "int" || v == "integer" || v == "exact" || v == "unknown") return memory_scanner::value_type_t::int32_val;
	if (v == "int64")   return memory_scanner::value_type_t::int64_val;
	if (v == "float")   return memory_scanner::value_type_t::float_val;
	if (v == "double")  return memory_scanner::value_type_t::double_val;
	if (v == "string" || v == "ascii" || v == "str")  return memory_scanner::value_type_t::string_ascii;
	if (v == "utf16" || v == "wstring") return memory_scanner::value_type_t::string_utf16;
	if (v == "aob" || v == "byte_array") return memory_scanner::value_type_t::byte_array;
	return memory_scanner::value_type_t::int32_val;
}

static memory_scanner::scan_mode_t parse_scan_mode(const std::string& s) {
	const std::string v = lower_copy(s);
	if (v == "exact")      return memory_scanner::scan_mode_t::exact;
	if (v == "bigger" || v == "greater" || v == "greater_than") return memory_scanner::scan_mode_t::bigger_than;
	if (v == "smaller" || v == "less" || v == "less_than") return memory_scanner::scan_mode_t::smaller_than;
	if (v == "between")    return memory_scanner::scan_mode_t::value_between;
	if (v == "changed")    return memory_scanner::scan_mode_t::changed;
	if (v == "unchanged")  return memory_scanner::scan_mode_t::unchanged;
	if (v == "increased")  return memory_scanner::scan_mode_t::increased;
	if (v == "decreased")  return memory_scanner::scan_mode_t::decreased;
	if (v == "unknown")    return memory_scanner::scan_mode_t::unknown_initial;
	return memory_scanner::scan_mode_t::exact;
}

static bool parse_u64_param(const json& params, const char* key, uint64_t& out) {
	if (!params.contains(key))
		return false;
	const auto& v = params[key];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return false;
		out = *parsed;
		return true;
	}
	if (v.is_number_unsigned()) {
		out = v.get<uint64_t>();
		return true;
	}
	if (v.is_number_integer()) {
		int64_t s = v.get<int64_t>();
		if (s < 0) return false;
		out = static_cast<uint64_t>(s);
		return true;
	}
	return false;
}

static int clamp_wait_ms(const json& params, int default_ms) {
	int wait_ms = default_ms;
	if (params.contains("wait_ms") && params["wait_ms"].is_number_integer())
		wait_ms = params["wait_ms"].get<int>();
	else if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
		wait_ms = params["timeout_ms"].get<int>();
	if (wait_ms < 0) wait_ms = 0;
	if (wait_ms > 60000) wait_ms = 60000;
	return wait_ms;
}

static size_t limit_param(const json& params, size_t default_limit, size_t max_limit) {
	size_t limit = default_limit;
	if (params.contains("limit") && params["limit"].is_number_integer()) {
		const int requested = params["limit"].get<int>();
		if (requested > 0)
			limit = static_cast<size_t>(requested);
	}
	return std::min(limit, max_limit);
}

static bool wait_for_scan_idle(int wait_ms) {
	const int loops = (wait_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.scanning.load()) return true;
		Sleep(50);
	}
	return !memory_scanner::g_state.scanning.load();
}

static bool wait_for_pointer_idle(int wait_ms) {
	const int loops = (wait_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.pointer_scanning.load()) return true;
		Sleep(50);
	}
	return !memory_scanner::g_state.pointer_scanning.load();
}

static bool wait_budget_active(int wait_ms) {
	return wait_ms > 0;
}

static void apply_region_filter(memory_scanner::scan_config_t& cfg, const std::string& filter) {
	const std::string v = lower_copy(filter);
	if (v.empty() || v == "default" || v == "writable") {
		cfg.writable_only = true;
		cfg.executable_exclude = true;
		return;
	}
	if (v == "all") {
		cfg.writable_only = false;
		cfg.executable_exclude = false;
		return;
	}
	if (v == "non_executable" || v == "noexec") {
		cfg.writable_only = false;
		cfg.executable_exclude = true;
		return;
	}
	if (v == "executable" || v == "code") {
		cfg.writable_only = false;
		cfg.executable_exclude = false;
		return;
	}
}

static json scan_summary_json(size_t limit) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.results_mutex);
	json arr = json::array();
	const size_t n = std::min(st.results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		const auto& r = st.results[i];
		json obj;
		obj["address"] = sa_format_address(r.address);
		obj["value"] = memory_scanner::format_value(r.current_value, st.config.value_type);
		if (!r.previous_value.empty())
			obj["previous"] = memory_scanner::format_value(r.previous_value, st.config.value_type);
		if (!r.module_name.empty()) {
			obj["module"] = r.module_name;
			obj["module_offset"] = sa_format_address(r.module_offset);
			obj["module_expr"] = r.module_name + "+" + sa_format_address(r.module_offset);
		}
		arr.push_back(std::move(obj));
	}
	json result;
	result["session_id"] = g_active_scan_session.load(std::memory_order_relaxed);
	result["scanning"] = st.scanning.load();
	result["scan_count"] = st.scan_count;
	result["total_found"] = st.total_found;
	result["returned"] = arr.size();
	result["value_type"] = memory_scanner::value_type_name(st.config.value_type);
	result["results"] = std::move(arr);
	return result;
}

static json pointer_results_json(size_t limit) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.pointer_mutex);
	json arr = json::array();
	const size_t n = std::min(st.pointer_results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		const auto& p = st.pointer_results[i];
		json obj;
		obj["base"] = sa_format_address(p.base_address);
		if (!p.module_name.empty()) {
			obj["module"] = p.module_name;
			obj["module_offset"] = sa_format_address(p.module_offset);
			obj["module_expr"] = p.module_name + "+" + sa_format_address(p.module_offset);
		}
		json offsets = json::array();
		std::ostringstream expr;
		if (!p.module_name.empty())
			expr << p.module_name << "+" << sa_format_address(p.module_offset);
		else
			expr << sa_format_address(p.base_address);
		for (auto off : p.offsets) {
			offsets.push_back(off);
			if (off >= 0)
				expr << " -> +0x" << std::uppercase << std::hex << off << std::dec;
			else
				expr << " -> -0x" << std::uppercase << std::hex << -off << std::dec;
		}
		obj["offsets"] = std::move(offsets);
		obj["path"] = expr.str();
		arr.push_back(std::move(obj));
	}
	json result;
	result["session_id"] = g_active_pointer_session.load(std::memory_order_relaxed);
	result["scanning"] = st.pointer_scanning.load();
	result["completed"] = !st.pointer_scanning.load();
	result["progress"] = st.pointer_progress.load();
	result["total"] = st.pointer_results.size();
	result["returned"] = arr.size();
	result["results"] = std::move(arr);
	return result;
}

static uint32_t access_type_code(const std::string& type) {
	const std::string v = lower_copy(type);
	if (v == "execute" || v == "exec" || v == "x") return 8;
	if (v == "write" || v == "w") return 1;
	if (v == "read" || v == "r") return 0;
	return std::numeric_limits<uint32_t>::max();
}

static std::string access_type_name(uint32_t access_type) {
	if (access_type == 8) return "execute";
	if (access_type == 1) return "write";
	return "read";
}

static json captured_register_json(const page_guard_engine::pg_capture_t& meta) {
	json regs;
	regs["rip"] = sa_format_address(meta.rip);
	regs["rax"] = sa_format_address(meta.ctx_rax);
	regs["rcx"] = sa_format_address(meta.ctx_rcx);
	regs["rdx"] = sa_format_address(meta.ctx_rdx);
	regs["rbx"] = nullptr;
	regs["rsi"] = nullptr;
	regs["rdi"] = nullptr;
	regs["rbp"] = nullptr;
	regs["rsp"] = nullptr;
	regs["r8"] = nullptr;
	regs["r9"] = nullptr;
	regs["r10"] = nullptr;
	regs["r11"] = nullptr;
	regs["r12"] = nullptr;
	regs["r13"] = nullptr;
	regs["r14"] = nullptr;
	regs["r15"] = nullptr;
	regs["rflags"] = nullptr;
	return regs;
}

static json page_guard_install_failure_json() {
	const auto f = page_guard_engine::g_pg_engine.last_install_failure();
	json result;
	result["reason"] = f.reason;
	result["detail"] = f.detail;
	result["driver_status"] = f.driver_status;
	result["driver_last_error"] = f.driver_last_error;
	result["remote_call_driver_status"] = f.remote_call_driver_status;
	result["remote_call_driver_last_error"] = f.remote_call_driver_last_error;
	result["pid"] = f.pid;
	result["active_pid"] = f.active_pid;
	result["win32_error"] = f.win32_error;
	result["requested_addr"] = sa_format_address(f.requested_addr);
	result["requested_size"] = f.requested_size;
	result["guard_addr"] = sa_format_address(f.guard_addr);
	result["guard_size"] = f.guard_size;
	result["region_base"] = sa_format_address(f.region_base);
	result["region_size"] = f.region_size;
	result["region_state"] = f.region_state;
	result["region_protect"] = f.region_protect;
	result["region_type"] = f.region_type;
	result["attempted_protect"] = f.attempted_protect;
	result["original_protect"] = f.original_protect;
	result["proposed_protect"] = f.proposed_protect;
	result["ring_addr"] = sa_format_address(f.ring_addr);
	result["shellcode_addr"] = sa_format_address(f.shellcode_addr);
	result["context_addr"] = sa_format_address(f.context_addr);
	result["ntdll_base"] = sa_format_address(f.ntdll_base);
	result["ntdll_size"] = f.ntdll_size;
	result["rtl_add_veh"] = sa_format_address(f.rtl_add_veh);
	result["rtl_remove_veh"] = sa_format_address(f.rtl_remove_veh);
	result["veh_result"] = sa_format_address(f.veh_result);
	result["cleanup_shellcode_ok"] = f.cleanup_shellcode_ok != 0;
	result["cleanup_ring_ok"] = f.cleanup_ring_ok != 0;
	result["install_elapsed_ms"] = f.install_elapsed_ms;
	result["install_generation"] = f.install_generation;
	result["current_generation"] = f.current_generation;
	result["mitigation_open_ok"] = f.mitigation_open_ok != 0;
	result["mitigation_open_error"] = f.mitigation_open_error;
	result["mitigation_dynamic_ok"] = f.mitigation_dynamic_ok != 0;
	result["mitigation_dynamic_error"] = f.mitigation_dynamic_error;
	result["mitigation_dynamic_flags"] = f.mitigation_dynamic_flags;
	result["mitigation_cfg_ok"] = f.mitigation_cfg_ok != 0;
	result["mitigation_cfg_error"] = f.mitigation_cfg_error;
	result["mitigation_cfg_flags"] = f.mitigation_cfg_flags;
	result["remote_call"] = json{
		{"id", f.remote_call_id},
		{"function", sa_format_address(f.remote_call_function)},
		{"result", sa_format_address(f.remote_call_result)},
		{"gle", f.remote_call_gle},
		{"active_pid_entry", f.remote_call_active_pid_entry},
		{"active_pid_after", f.remote_call_active_pid_after},
		{"timeout_ms", f.remote_call_timeout_ms},
		{"deadline_ms", f.remote_call_deadline_ms},
		{"deadline_remaining_ms", f.remote_call_deadline_remaining_ms},
		{"elapsed_ms", f.remote_call_elapsed_ms},
		{"completed", f.remote_call_completed != 0},
		{"ok", f.remote_call_ok != 0},
		{"cancelled_before", f.remote_call_cancelled_before != 0},
		{"cancelled_after", f.remote_call_cancelled_after != 0},
		{"deadline_expired_before", f.remote_call_deadline_expired_before != 0},
		{"deadline_expired_after", f.remote_call_deadline_expired_after != 0},
		{"stale_pid", f.remote_call_stale_pid != 0},
		{"late_completion", f.remote_call_late_completion != 0}
	};
	result["remote_call_id"] = f.remote_call_id;
	result["remote_call_gle"] = f.remote_call_gle;
	result["remote_call_stale_pid"] = f.remote_call_stale_pid != 0;
	result["remote_call_deadline_expired_after"] = f.remote_call_deadline_expired_after != 0;
	result["remote_call_cancelled_after"] = f.remote_call_cancelled_after != 0;
	result["remote_call_late_completion"] = f.remote_call_late_completion != 0;
	result["remote_call_lower_phase"] = f.remote_call_lower_phase;
	result["remote_call_lower_completion_reason"] = f.remote_call_lower_completion_reason;
	result["remote_call_lower_gle"] = f.remote_call_lower_gle;
	result["remote_call_lower_worker_tid"] = f.remote_call_lower_worker_tid;
	result["remote_call_lower_worker_alive"] = f.remote_call_lower_worker_alive != 0;
	result["remote_call_lower_queue_depth_at_submit"] = f.remote_call_lower_queue_depth_at_submit;
	result["remote_call_lower_queue_depth_at_start"] = f.remote_call_lower_queue_depth_at_start;
	result["remote_call_lower_queue_depth_after_pop"] = f.remote_call_lower_queue_depth_after_pop;
	result["remote_call_lower_inflight_at_submit"] = f.remote_call_lower_inflight_at_submit;
	result["remote_call_lower_inflight_at_start"] = f.remote_call_lower_inflight_at_start;
	result["remote_call_lower_inflight_after"] = f.remote_call_lower_inflight_after;
	result["quarantined"] = f.quarantined != 0;
	result["quarantine_cleanup_attempted"] = f.quarantine_cleanup_attempted != 0;
	result["quarantine_id"] = f.quarantine_id;
	result["kernel_protect"] = json{
		{"attempted_protect", f.attempted_protect},
		{"original_protect", f.original_protect},
		{"proposed_protect", f.proposed_protect},
		{"region_base", sa_format_address(f.region_base)},
		{"region_size", f.region_size},
		{"region_state", f.region_state},
		{"region_protect", f.region_protect},
		{"region_type", f.region_type}
	};
	result["remote_call"]["driver_status"] = f.remote_call_driver_status;
	result["remote_call"]["driver_last_error"] = f.remote_call_driver_last_error;
	result["remote_call"]["lower"] = json{
		{"phase", f.remote_call_lower_phase},
		{"completion_reason", f.remote_call_lower_completion_reason},
		{"gle", f.remote_call_lower_gle},
		{"worker_tid", f.remote_call_lower_worker_tid},
		{"worker_alive", f.remote_call_lower_worker_alive != 0},
		{"queue_depth_at_submit", f.remote_call_lower_queue_depth_at_submit},
		{"queue_depth_at_start", f.remote_call_lower_queue_depth_at_start},
		{"queue_depth_after_pop", f.remote_call_lower_queue_depth_after_pop},
		{"inflight_at_submit", f.remote_call_lower_inflight_at_submit},
		{"inflight_at_start", f.remote_call_lower_inflight_at_start},
		{"inflight_after", f.remote_call_lower_inflight_after},
		{"worker_error_value", f.remote_call_lower_worker_error_value},
		{"worker_error_category", f.remote_call_lower_worker_error_category},
		{"worker_error_message", f.remote_call_lower_worker_error_message},
		{"completed", f.remote_call_lower_completed != 0},
		{"ok", f.remote_call_lower_ok != 0},
		{"stale_generation", f.remote_call_lower_stale_generation != 0},
		{"cancelled", f.remote_call_lower_cancelled != 0},
		{"deadline_expired", f.remote_call_lower_deadline_expired != 0},
		{"lock_timeout", f.remote_call_lower_lock_timeout != 0},
		{"worker_exception", f.remote_call_lower_worker_exception != 0},
		{"worker_creation_failed", f.remote_call_lower_worker_creation_failed != 0},
		{"late_completion", f.remote_call_lower_late_completion != 0},
		{"generation_at_entry", f.remote_call_lower_generation_at_entry},
		{"generation_after", f.remote_call_lower_generation_after},
		{"queue_wait_ms", f.remote_call_lower_queue_wait_ms},
		{"elapsed_ms", f.remote_call_lower_elapsed_ms},
		{"deadline_remaining_at_queue_ms", f.remote_call_lower_deadline_remaining_at_queue_ms},
		{"deadline_remaining_at_start_ms", f.remote_call_lower_deadline_remaining_at_start_ms},
		{"deadline_remaining_at_finish_ms", f.remote_call_lower_deadline_remaining_at_finish_ms},
		{"allow_zero_result", f.remote_call_allow_zero_result != 0},
		{"zero_result_rejected", f.remote_call_zero_result_rejected != 0},
		{"caller_abandoned", f.remote_call_caller_abandoned != 0},
		{"removed_from_queue", f.remote_call_removed_from_queue != 0},
		{"popped_from_queue", f.remote_call_popped_from_queue != 0},
		{"execution_started", f.remote_call_execution_started != 0},
		{"executing_abandoned", f.remote_call_executing_abandoned != 0}
	};
	result["remote_call"]["seh"] = json{
		{"exception", f.remote_call_seh_exception != 0},
		{"exception_code", f.remote_call_seh_exception_code},
		{"exception_address", sa_format_address(f.remote_call_seh_exception_address)},
		{"fault_address", sa_format_address(f.remote_call_seh_fault_address)},
		{"rip", sa_format_address(f.remote_call_seh_rip)},
		{"rsp", sa_format_address(f.remote_call_seh_rsp)},
		{"rbp", sa_format_address(f.remote_call_seh_rbp)}
	};
	result["veh_target"] = json{
		{"tid", f.veh_target_tid},
		{"teb_exception_list", sa_format_address(f.veh_target_teb_exception_list)},
		{"peb", sa_format_address(f.veh_target_peb)},
		{"loader_lock", sa_format_address(f.veh_target_loader_lock)},
		{"loader_lock_owner", sa_format_address(f.veh_target_loader_lock_owner)},
		{"loader_lock_count", f.veh_target_loader_lock_count},
		{"loader_lock_probe_state", f.veh_target_loader_lock_probe_state},
		{"loader_lock_safe_state", f.veh_target_loader_lock_safe_state},
		{"last_error_before", f.veh_target_last_error_before},
		{"last_error_after", f.veh_target_last_error_after},
		{"wrapper_phase", f.veh_target_wrapper_phase},
		{"seh_probe_state", f.veh_target_seh_probe_state},
		{"exception_state", f.veh_target_exception_state},
		{"exception_code", f.veh_target_exception_code},
		{"exception_address", sa_format_address(f.veh_target_exception_address)}
	};
	result["quarantine"] = json{
		{"active", f.quarantined != 0},
		{"id", f.quarantine_id},
		{"cleanup_attempted", f.quarantine_cleanup_attempted != 0},
		{"veh_remove_attempted", f.quarantine_veh_remove_attempted != 0},
		{"veh_remove_ok", f.quarantine_veh_remove_ok != 0},
		{"retained_shellcode", f.quarantine_retained_shellcode != 0},
		{"retained_ring", f.quarantine_retained_ring != 0}
	};
	return result;
}

template <typename T>
static bool read_scalar_le(const std::vector<uint8_t>& bytes, T& out) {
	if (bytes.size() < sizeof(T))
		return false;
	std::memcpy(&out, bytes.data(), sizeof(T));
	return true;
}

static std::string bytes_hex_preview(const std::vector<uint8_t>& bytes, size_t limit = 64) {
	std::ostringstream os;
	const size_t n = std::min(bytes.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		if (i != 0)
			os << ' ';
		os << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
		   << static_cast<unsigned>(bytes[i]);
	}
	if (bytes.size() > n)
		os << " ...";
	return os.str();
}

static json scanner_activity_json() {
	auto& st = memory_scanner::g_state;
	json state;
	state["target_pid"] = driver_bridge::attached_pid();
	state["scan_session_id"] = g_active_scan_session.load(std::memory_order_relaxed);
	state["pointer_session_id"] = g_active_pointer_session.load(std::memory_order_relaxed);
	state["scanning"] = st.scanning.load();
	state["pointer_scanning"] = st.pointer_scanning.load();
	state["scan_progress"] = st.scan_progress.load();
	state["pointer_progress"] = st.pointer_progress.load();
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		state["scan_results"] = st.results.size();
		state["total_found"] = st.total_found;
	}
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		state["pointer_results"] = st.pointer_results.size();
	}
	return state;
}

static json address_entry_json(const memory_scanner::address_entry_t& e, size_t index) {
	json obj;
	obj["index"] = index;
	obj["address"] = sa_format_address(e.address);
	obj["description"] = e.description;
	obj["value_type"] = memory_scanner::value_type_name(e.value_type);
	obj["type"] = memory_scanner::value_type_name(e.value_type);
	obj["frozen"] = e.frozen;
	obj["value"] = memory_scanner::format_value(e.last_value, e.value_type);
	obj["last_value_size"] = e.last_value.size();
	obj["freeze_value_size"] = e.freeze_value.size();
	if (!e.last_value.empty())
		obj["last_value_hex"] = bytes_hex_preview(e.last_value, 256);
	if (!e.freeze_value.empty())
		obj["freeze_value_hex"] = bytes_hex_preview(e.freeze_value, 256);
	return obj;
}

static size_t address_list_count() {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	return st.address_list.size();
}

static std::optional<size_t> address_index_by_address(uint64_t address) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	for (size_t i = 0; i < st.address_list.size(); ++i) {
		if (st.address_list[i].address == address)
			return i;
	}
	return std::nullopt;
}

static bool address_entry_by_index(size_t index, json& out) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index >= st.address_list.size())
		return false;
	out = address_entry_json(st.address_list[index], index);
	return true;
}

static bool read_memory_exact(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out) {
	out.clear();
	if (size == 0)
		return true;
	if (!driver_bridge::read_memory_for(pid, address, size, out) || out.size() < size)
		return false;
	if (out.size() > size)
		out.resize(size);
	return true;
}

static void add_scanner_action_context(json& result, const char* action) {
	result["action"] = action;
	result["target_pid"] = driver_bridge::attached_pid();
	result["active_scan_state"] = scanner_activity_json();
}

static bool parse_field_type(const std::string& text, struct_dissector::field_type_t& out) {
	const std::string v = lower_copy(text);
	if (v == "int8" || v == "i8") { out = struct_dissector::field_type_t::int8; return true; }
	if (v == "uint8" || v == "u8" || v == "byte") { out = struct_dissector::field_type_t::uint8; return true; }
	if (v == "int16" || v == "i16" || v == "short") { out = struct_dissector::field_type_t::int16; return true; }
	if (v == "uint16" || v == "u16" || v == "ushort") { out = struct_dissector::field_type_t::uint16; return true; }
	if (v == "int32" || v == "i32" || v == "int" || v == "integer") { out = struct_dissector::field_type_t::int32; return true; }
	if (v == "uint32" || v == "u32" || v == "dword") { out = struct_dissector::field_type_t::uint32; return true; }
	if (v == "int64" || v == "i64" || v == "long") { out = struct_dissector::field_type_t::int64; return true; }
	if (v == "uint64" || v == "u64" || v == "qword") { out = struct_dissector::field_type_t::uint64; return true; }
	if (v == "float" || v == "float32" || v == "single") { out = struct_dissector::field_type_t::float32; return true; }
	if (v == "double" || v == "float64") { out = struct_dissector::field_type_t::float64; return true; }
	if (v == "pointer" || v == "ptr") { out = struct_dissector::field_type_t::pointer; return true; }
	if (v == "string" || v == "ascii" || v == "ascii_string") { out = struct_dissector::field_type_t::ascii_string; return true; }
	if (v == "utf16" || v == "utf16_string" || v == "wstring") { out = struct_dissector::field_type_t::utf16_string; return true; }
	if (v == "aob" || v == "byte_array" || v == "bytes") { out = struct_dissector::field_type_t::byte_array; return true; }
	if (v == "padding" || v == "pad") { out = struct_dissector::field_type_t::padding; return true; }
	return false;
}

static bool parse_address_param(const json& params, const char* key, uint64_t& out, std::string& error) {
	if (!params.contains(key)) {
		error = std::string("'") + std::string(key) + std::string("' is required.");
		return false;
	}
	const auto& v = params[key];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) {
			error = std::string("Invalid ") + std::string(key) + std::string(".");
			return false;
		}
		out = *parsed;
		return true;
	}
	if (v.is_number_unsigned()) {
		out = v.get<uint64_t>();
		return true;
	}
	if (v.is_number_integer()) {
		const int64_t s = v.get<int64_t>();
		if (s < 0) {
			error = std::string("Negative ") + std::string(key) + std::string(" is invalid.");
			return false;
		}
		out = static_cast<uint64_t>(s);
		return true;
	}
	error = std::string("'") + std::string(key) + std::string("' must be a string or integer address.");
	return false;
}

static bool parse_i64_param(const json& params, const char* key, int64_t& out, std::string& error) {
	if (!params.contains(key)) {
		error = std::string("'") + std::string(key) + std::string("' is required.");
		return false;
	}
	const auto& v = params[key];
	if (v.is_number_integer()) {
		out = v.get<int64_t>();
		return true;
	}
	if (v.is_number_unsigned()) {
		const uint64_t u = v.get<uint64_t>();
		if (u > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
			error = std::string("'") + std::string(key) + std::string("' is too large.");
			return false;
		}
		out = static_cast<int64_t>(u);
		return true;
	}
	if (v.is_string()) {
		try {
			const std::string s = v.get<std::string>();
			size_t idx = 0;
			out = std::stoll(s, &idx, 0);
			if (idx == s.size())
				return true;
		} catch (...) {
		}
	}
	error = std::string("'") + std::string(key) + std::string("' must be an integer offset.");
	return false;
}

static uint64_t add_signed_offset(uint64_t base, int64_t offset, bool& ok) {
	ok = false;
	if (offset < -0x10000000LL || offset > 0x10000000LL)
		return 0;
	if (offset >= 0) {
		const uint64_t delta = static_cast<uint64_t>(offset);
		if (base > std::numeric_limits<uint64_t>::max() - delta)
			return 0;
		ok = true;
		return base + delta;
	}
	const uint64_t delta = static_cast<uint64_t>(-offset);
	if (base < delta)
		return 0;
	ok = true;
	return base - delta;
}

static size_t field_effective_size(const struct_dissector::field_def_t& f) {
	size_t base = f.size != 0 ? static_cast<size_t>(f.size) : struct_dissector::field_type_size(f.type);
	if (base == 0)
		base = 1;
	const uint32_t count = f.array_count == 0 ? 1 : f.array_count;
	if (base > 0x10000 / count)
		return 0x10000;
	return base * count;
}

static size_t assertion_read_size(struct_dissector::field_type_t type, const json& params) {
	size_t size = struct_dissector::field_type_size(type);
	if (size == 0) {
		if (type == struct_dissector::field_type_t::ascii_string)
			size = 64;
		else if (type == struct_dissector::field_type_t::utf16_string)
			size = 128;
		else
			size = 32;
	}
	if (params.contains("size") && params["size"].is_number_integer()) {
		const int requested = params["size"].get<int>();
		if (requested > 0)
			size = static_cast<size_t>(requested);
	}
	if (size == 0)
		size = 1;
	if (size > 256)
		size = 256;
	return size;
}

static json field_value_json(const std::vector<uint8_t>& bytes, struct_dissector::field_type_t type) {
	json out;
	out["display"] = struct_dissector::format_field_value(bytes, type);
	out["raw_hex"] = bytes_hex_preview(bytes);
	switch (type) {
	case struct_dissector::field_type_t::int8: {
		int8_t v = 0;
		if (read_scalar_le(bytes, v)) out["signed"] = static_cast<int>(v);
		break;
	}
	case struct_dissector::field_type_t::uint8: {
		uint8_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = static_cast<unsigned>(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int16: {
		int16_t v = 0;
		if (read_scalar_le(bytes, v)) out["signed"] = static_cast<int>(v);
		break;
	}
	case struct_dissector::field_type_t::uint16: {
		uint16_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = static_cast<unsigned>(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int32: {
		int32_t v = 0;
		if (read_scalar_le(bytes, v)) { out["signed"] = v; out["hex"] = sa_format_address(static_cast<uint32_t>(v)); }
		break;
	}
	case struct_dissector::field_type_t::uint32: {
		uint32_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = v; out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::int64: {
		int64_t v = 0;
		if (read_scalar_le(bytes, v)) { out["signed"] = v; out["hex"] = sa_format_address(static_cast<uint64_t>(v)); }
		break;
	}
	case struct_dissector::field_type_t::uint64: {
		uint64_t v = 0;
		if (read_scalar_le(bytes, v)) { out["unsigned"] = std::to_string(v); out["hex"] = sa_format_address(v); }
		break;
	}
	case struct_dissector::field_type_t::float32: {
		float v = 0.f;
		if (read_scalar_le(bytes, v)) { out["number"] = v; out["finite"] = std::isfinite(v); }
		break;
	}
	case struct_dissector::field_type_t::float64: {
		double v = 0.0;
		if (read_scalar_le(bytes, v)) { out["number"] = v; out["finite"] = std::isfinite(v); }
		break;
	}
	case struct_dissector::field_type_t::pointer: {
		uint64_t v = 0;
		if (read_scalar_le(bytes, v)) out["pointer"] = sa_format_address(v);
		break;
	}
	default:
		break;
	}
	return out;
}

static bool numeric_sample_value(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes, double& value, bool& finite) {
	finite = true;
	switch (type) {
	case struct_dissector::field_type_t::int8: { int8_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint8: { uint8_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int16: { int16_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint16: { uint16_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int32: { int32_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint32: { uint32_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::int64: { int64_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::uint64: { uint64_t v = 0; if (!read_scalar_le(bytes, v)) return false; value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::float32: { float v = 0.f; if (!read_scalar_le(bytes, v)) return false; finite = std::isfinite(v); value = static_cast<double>(v); return true; }
	case struct_dissector::field_type_t::float64: { double v = 0.0; if (!read_scalar_le(bytes, v)) return false; finite = std::isfinite(v); value = v; return true; }
	default:
		return false;
	}
}

static bool pointer_sample_value(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes, uint64_t& value) {
	if (type != struct_dissector::field_type_t::pointer)
		return false;
	return read_scalar_le(bytes, value);
}

static bool string_sample_printable(struct_dissector::field_type_t type, const std::vector<uint8_t>& bytes) {
	if (type == struct_dissector::field_type_t::ascii_string) {
		for (uint8_t b : bytes) {
			if (b == 0)
				return true;
			if (b < 0x20 || b > 0x7E)
				return false;
		}
		return !bytes.empty();
	}
	if (type == struct_dissector::field_type_t::utf16_string) {
		for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
			uint16_t ch = 0;
			std::memcpy(&ch, bytes.data() + i, sizeof(ch));
			if (ch == 0)
				return true;
			if (ch < 0x20 || ch > 0x7E)
				return false;
		}
		return bytes.size() >= 2;
	}
	return true;
}

static std::string available_struct_names_text() {
	std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
	std::ostringstream os;
	for (size_t i = 0; i < struct_dissector::g_state.structs.size(); ++i) {
		if (i != 0)
			os << ", ";
		os << struct_dissector::g_state.structs[i].name;
	}
	return os.str();
}

static json struct_snapshot_json(int struct_index, const struct_dissector::struct_def_t& sd,
	uint64_t base, const std::vector<uint8_t>& block) {
	json fields = json::array();
	for (size_t i = 0; i < sd.fields.size(); ++i) {
		const auto& f = sd.fields[i];
		const size_t fsz = field_effective_size(f);
		json item;
		item["index"] = i;
		item["name"] = f.name;
		item["offset"] = f.offset;
		if (base <= std::numeric_limits<uint64_t>::max() - f.offset)
			item["address"] = sa_format_address(base + f.offset);
		else
			item["address"] = nullptr;
		item["type"] = struct_dissector::field_type_name(f.type);
		item["declared_size"] = f.size;
		item["array_count"] = f.array_count;
		item["read_size"] = fsz;
		if (fsz == 0 || static_cast<uint64_t>(f.offset) + static_cast<uint64_t>(fsz) > block.size()) {
			item["read_ok"] = false;
			item["value"] = nullptr;
		} else {
			std::vector<uint8_t> bytes(block.begin() + f.offset, block.begin() + f.offset + fsz);
			const bool truncated = bytes.size() > 256;
			if (truncated)
				bytes.resize(256);
			item["read_ok"] = true;
			item["value_truncated"] = truncated;
			item["value"] = field_value_json(bytes, f.type);
		}
		fields.push_back(std::move(item));
	}
	json result;
	result["struct_index"] = struct_index;
	result["struct_name"] = sd.name;
	result["base_address"] = sa_format_address(base);
	result["total_size"] = sd.total_size;
	result["field_count"] = sd.fields.size();
	result["fields"] = std::move(fields);
	return result;
}

static std::string results_to_json(size_t limit = 100) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.results_mutex);

	json arr = json::array();
	size_t n = std::min(st.results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		auto& r = st.results[i];
		json obj;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, r.address);
		obj["address"] = buf;
		obj["value"] = memory_scanner::format_value(r.current_value, st.config.value_type);
		if (!r.previous_value.empty())
			obj["previous"] = memory_scanner::format_value(r.previous_value, st.config.value_type);
		if (!r.module_name.empty()) {
			snprintf(buf, sizeof(buf), "0x%" PRIX64, r.module_offset);
			obj["module"] = r.module_name + "+" + buf;
		}
		arr.push_back(std::move(obj));
	}

	json result;
	result["total_found"] = st.total_found;
	result["showing"] = n;
	result["scan_count"] = st.scan_count;
	result["results"] = std::move(arr);
	return result.dump(2);
}


static tool_result_t handle_first_scan(const json& params) {
	mcp_standalone::downstream::producer_identity_t fs_id;
	fs_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	fs_id.tool_name = "scanner_first_scan";
	mcp_standalone::downstream::scoped_admission_t fs_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(fs_id);
	if (!fs_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(fs_id);
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-REJECT scanner_first_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		return tool_result_t::error(
			std::string("Scanner capacity exhausted; work was not started."),
			"MCP_DOWNSTREAM_CAPACITY_REJECT",
			mcp_standalone::downstream::rejection_json(rej, fs_id));
	}
	diag::log_tagged_fmt("scanner",
		"FEATURE-WORKER-GROUP-ADMIT scanner_first_scan token=%llu",
		static_cast<unsigned long long>(fs_admission.token()));

	memory_scanner::scan_config_t cfg;

	if (params.contains("value_type"))
		cfg.value_type = parse_value_type(params["value_type"].get<std::string>());
	if (params.contains("scan_mode"))
		cfg.scan_mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		cfg.value_text = params["value"].get<std::string>();
	if (params.contains("value2"))
		cfg.value_text2 = params["value2"].get<std::string>();
	if (params.contains("hex") && params["hex"].is_boolean())
		cfg.hex_input = params["hex"].get<bool>();
	if (params.contains("writable_only") && params["writable_only"].is_boolean())
		cfg.writable_only = params["writable_only"].get<bool>();
	if (params.contains("executable_exclude") && params["executable_exclude"].is_boolean())
		cfg.executable_exclude = params["executable_exclude"].get<bool>();
	if (params.contains("alignment") && params["alignment"].is_number())
		cfg.alignment = params["alignment"].get<size_t>();
	parse_u64_param(params, "range_base", cfg.range_base);
	parse_u64_param(params, "range_size", cfg.range_size);

	diag::log_tagged_fmt("scanner", "mcp first_scan request value='%s' type=%s mode=%s writable_only=%d executable_exclude=%d alignment=%zu range=0x%llX+0x%llX",
		cfg.value_text.c_str(),
		memory_scanner::value_type_name(cfg.value_type),
		memory_scanner::scan_mode_name(cfg.scan_mode),
		cfg.writable_only ? 1 : 0,
		cfg.executable_exclude ? 1 : 0,
		cfg.alignment,
		static_cast<unsigned long long>(cfg.range_base),
		static_cast<unsigned long long>(cfg.range_size));

	if (!memory_scanner::first_scan(cfg)) {
		diag::log_tagged("scanner", "mcp first_scan refused");
		if (fs_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_first_scan token=%llu reason=completed",
				static_cast<unsigned long long>(fs_admission.token()));
			fs_admission.release("completed");
		}
		return tool_result_t::error(std::string("Scanner busy or not attached to a process."));
	}


	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		if (mcp_standalone::current_call_cancelled()) {
			json result = scan_summary_json(100);
			result["completed"] = false;
			result["cancelled"] = true;
			result["poll_iteration"] = i;
			diag::log_tagged_fmt("scanner", "mcp first_scan cancelled total=%zu scan_count=%d poll_iteration=%d",
				memory_scanner::g_state.total_found,
				memory_scanner::g_state.scan_count,
				i);
			memory_scanner::reset_scan();
			if (fs_admission.active()) {
				diag::log_tagged_fmt("scanner",
					"FEATURE-WORKER-GROUP-RELEASE scanner_first_scan token=%llu reason=completed",
					static_cast<unsigned long long>(fs_admission.token()));
				fs_admission.release("completed");
			}
			return tool_result_t::error(std::string("Memory scan cancelled."), "cancelled", result);
		}
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp first_scan completed total=%zu scan_count=%d scanning=%d",
		memory_scanner::g_state.total_found,
		memory_scanner::g_state.scan_count,
		memory_scanner::g_state.scanning.load() ? 1 : 0);
	if (memory_scanner::g_state.scanning.load()) {
		json result = scan_summary_json(100);
		result["completed"] = false;
		result["timeout_ms"] = 30000;
		diag::log_tagged_fmt("scanner", "mcp first_scan timeout total=%zu scan_count=%d",
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count);
		memory_scanner::reset_scan();
		if (fs_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_first_scan token=%llu reason=completed",
				static_cast<unsigned long long>(fs_admission.token()));
			fs_admission.release("completed");
		}
		return tool_result_t{false, std::string("Memory scan did not complete within the wait budget."), result};
	}

	if (fs_admission.active()) {
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-RELEASE scanner_first_scan token=%llu reason=completed",
			static_cast<unsigned long long>(fs_admission.token()));
		fs_admission.release("completed");
	}
	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_next_scan(const json& params) {
	mcp_standalone::downstream::producer_identity_t ns_id;
	ns_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ns_id.tool_name = "scanner_next_scan";
	mcp_standalone::downstream::scoped_admission_t ns_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ns_id);
	if (!ns_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ns_id);
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-REJECT scanner_next_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		return tool_result_t::error(
			std::string("Scanner capacity exhausted; work was not started."),
			"MCP_DOWNSTREAM_CAPACITY_REJECT",
			mcp_standalone::downstream::rejection_json(rej, ns_id));
	}
	diag::log_tagged_fmt("scanner",
		"FEATURE-WORKER-GROUP-ADMIT scanner_next_scan token=%llu",
		static_cast<unsigned long long>(ns_admission.token()));

	auto mode = memory_scanner::scan_mode_t::exact;
	std::string val, val2;

	if (params.contains("scan_mode"))
		mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		val = params["value"].get<std::string>();
	if (params.contains("value2"))
		val2 = params["value2"].get<std::string>();

	diag::log_tagged_fmt("scanner", "mcp next_scan request mode=%s val='%s'",
		memory_scanner::scan_mode_name(mode), val.c_str());

	if (!memory_scanner::next_scan(mode, val, val2)) {
		diag::log_tagged("scanner", "mcp next_scan refused");
		if (ns_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_next_scan token=%llu reason=completed",
				static_cast<unsigned long long>(ns_admission.token()));
			ns_admission.release("completed");
		}
		return tool_result_t::error(std::string("Scanner busy or no initial scan performed."));
	}

	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		if (mcp_standalone::current_call_cancelled()) {
			json result = scan_summary_json(100);
			result["completed"] = false;
			result["cancelled"] = true;
			result["poll_iteration"] = i;
			diag::log_tagged_fmt("scanner", "mcp next_scan cancelled total=%zu scan_count=%d poll_iteration=%d",
				memory_scanner::g_state.total_found,
				memory_scanner::g_state.scan_count,
				i);
			memory_scanner::reset_scan();
			if (ns_admission.active()) {
				diag::log_tagged_fmt("scanner",
					"FEATURE-WORKER-GROUP-RELEASE scanner_next_scan token=%llu reason=completed",
					static_cast<unsigned long long>(ns_admission.token()));
				ns_admission.release("completed");
			}
			return tool_result_t::error(std::string("Next memory scan cancelled."), "cancelled", result);
		}
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp next_scan completed total=%zu",
		memory_scanner::g_state.total_found);
	if (memory_scanner::g_state.scanning.load()) {
		json result = scan_summary_json(100);
		result["completed"] = false;
		result["timeout_ms"] = 30000;
		diag::log_tagged_fmt("scanner", "mcp next_scan timeout total=%zu scan_count=%d",
			memory_scanner::g_state.total_found,
			memory_scanner::g_state.scan_count);
		memory_scanner::reset_scan();
		if (ns_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_next_scan token=%llu reason=completed",
				static_cast<unsigned long long>(ns_admission.token()));
			ns_admission.release("completed");
		}
		return tool_result_t{false, std::string("Next memory scan did not complete within the wait budget."), result};
	}

	if (ns_admission.active()) {
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-RELEASE scanner_next_scan token=%llu reason=completed",
			static_cast<unsigned long long>(ns_admission.token()));
		ns_admission.release("completed");
	}
	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_get_results(const json& params) {
	size_t limit = 100;
	if (params.contains("limit") && params["limit"].is_number())
		limit = params["limit"].get<size_t>();
	diag::log_tagged_fmt("scanner", "mcp get_results limit=%zu total=%zu scan_count=%d scanning=%d",
		limit,
		memory_scanner::g_state.total_found,
		memory_scanner::g_state.scan_count,
		memory_scanner::g_state.scanning.load() ? 1 : 0);
	return tool_result_t::ok(results_to_json(limit));
}





static tool_result_t handle_reset_scan(const json&) {
	memory_scanner::reset_scan();
	return tool_result_t::ok(std::string("Scanner reset."));
}

static tool_result_t handle_undo_scan(const json&) {
	memory_scanner::undo_scan();
	auto& st = memory_scanner::g_state;
	json result;
	result["total_found"] = st.total_found;
	result["scan_count"] = st.scan_count;
	return tool_result_t::ok(result.dump());
}

static tool_result_t handle_add_address(const json& params) {
	uint64_t addr = 0;
	std::string error;
	if (!parse_address_param(params, "address", addr, error))
		return tool_result_t::error(error);

	std::string desc;
	if (params.contains("description") && params["description"].is_string())
		desc = params["description"].get<std::string>();

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type") && params["value_type"].is_string())
		vtype = parse_value_type(params["value_type"].get<std::string>());

	const size_t before_count = address_list_count();
	const auto existing_index = address_index_by_address(addr);
	memory_scanner::add_address(addr, desc, vtype);
	const size_t after_count = address_list_count();
	const auto after_index = address_index_by_address(addr);
	const bool added = !existing_index.has_value() && after_index.has_value() && after_count > before_count;
	const bool present = after_index.has_value();

	std::vector<uint8_t> readback;
	const size_t read_size = memory_scanner::value_type_size(vtype);
	const uint32_t target_pid = driver_bridge::attached_pid();
	const bool readback_ok = target_pid != 0 && read_memory_exact(target_pid, addr, read_size, readback);

	json result;
	add_scanner_action_context(result, "scanner_address_list_add");
	result["success"] = present;
	result["added"] = added;
	result["duplicate"] = existing_index.has_value();
	result["address"] = sa_format_address(addr);
	result["index"] = after_index.has_value() ? json(*after_index) : json(nullptr);
	result["list_count_before"] = before_count;
	result["list_count_after"] = after_count;
	result["value_type"] = memory_scanner::value_type_name(vtype);
	result["frozen"] = false;
	result["bytes_written"] = 0;
	result["cancel_requested"] = false;
	result["readback_ok"] = readback_ok;
	result["verified"] = present;
	if (readback_ok) {
		result["readback"] = memory_scanner::format_value(readback, vtype);
		result["readback_hex"] = bytes_hex_preview(readback, 256);
	}
	if (after_index.has_value()) {
		json entry;
		if (address_entry_by_index(*after_index, entry)) {
			result["frozen"] = entry.value("frozen", false);
			result["entry"] = std::move(entry);
		}
	}
	const std::string text = added
		? std::string("Address ") + sa_format_address(addr) + std::string(" added to list.")
		: std::string("Address ") + sa_format_address(addr) + std::string(" already in list.");
	return tool_result_t::ok(text, result);
}

static tool_result_t handle_remove_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(std::string("Missing 'index' parameter."));
	if (!params["index"].is_number_integer())
		return tool_result_t::error(std::string("'index' must be an integer."));
	const auto raw_index = params["index"].get<int64_t>();
	if (raw_index < 0)
		return tool_result_t::error(std::string("'index' must be non-negative."));
	size_t idx = static_cast<size_t>(raw_index);
	const size_t before_count = address_list_count();
	json removed_entry;
	if (!address_entry_by_index(idx, removed_entry))
		return tool_result_t::error(std::string("Address index is out of range."));
	memory_scanner::remove_address(idx);
	const size_t after_count = address_list_count();
	const bool removed = after_count < before_count;
	json result;
	add_scanner_action_context(result, "scanner_address_list_remove");
	result["success"] = removed;
	result["index"] = idx;
	result["address"] = removed_entry.value("address", std::string{});
	result["list_count_before"] = before_count;
	result["list_count_after"] = after_count;
	result["frozen"] = removed_entry.value("frozen", false);
	result["value_type"] = removed_entry.value("value_type", std::string{});
	result["bytes_written"] = 0;
	result["cancel_requested"] = false;
	result["readback_ok"] = false;
	result["verified"] = removed;
	result["removed"] = std::move(removed_entry);
	return tool_result_t::ok(std::string("Address removed."), result);
}

static tool_result_t handle_freeze_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(std::string("Missing 'index' parameter."));
	if (!params["index"].is_number_integer())
		return tool_result_t::error(std::string("'index' must be an integer."));
	const auto raw_index = params["index"].get<int64_t>();
	if (raw_index < 0)
		return tool_result_t::error(std::string("'index' must be non-negative."));
	size_t idx = static_cast<size_t>(raw_index);
	bool enable = true;
	if (params.contains("enable") && params["enable"].is_boolean())
		enable = params["enable"].get<bool>();
	const size_t before_count = address_list_count();
	json before_entry;
	if (!address_entry_by_index(idx, before_entry))
		return tool_result_t::error(std::string("Address index is out of range."));
	memory_scanner::freeze_address(idx, enable);
	const size_t after_count = address_list_count();
	json after_entry;
	const bool have_after = address_entry_by_index(idx, after_entry);
	const bool frozen_after = have_after && after_entry.value("frozen", false);
	const bool freeze_success = have_after && frozen_after == enable;
	json result;
	add_scanner_action_context(result, "scanner_address_list_freeze");
	result["success"] = freeze_success;
	result["index"] = idx;
	result["address"] = before_entry.value("address", std::string{});
	result["list_count_before"] = before_count;
	result["list_count_after"] = after_count;
	result["frozen_before"] = before_entry.value("frozen", false);
	result["frozen"] = frozen_after;
	result["value_type"] = before_entry.value("value_type", std::string{});
	result["bytes_written"] = 0;
	result["cancel_requested"] = false;
	result["readback_ok"] = false;
	result["verified"] = freeze_success;
	result["before"] = std::move(before_entry);
	if (have_after)
		result["after"] = std::move(after_entry);
	return tool_result_t::ok(enable ? std::string("Address frozen.") : std::string("Address unfrozen."), result);
}

static tool_result_t handle_get_address_list(const json&) {
	auto& st = memory_scanner::g_state;
	memory_scanner::refresh_address_list();

	std::lock_guard<std::mutex> lk(st.address_mutex);
	json arr = json::array();
	for (size_t i = 0; i < st.address_list.size(); ++i) {
		arr.push_back(address_entry_json(st.address_list[i], i));
	}
	json result;
	result["action"] = "scanner_address_list_list";
	result["target_pid"] = driver_bridge::attached_pid();
	result["count"] = arr.size();
	result["addresses"] = std::move(arr);
	result["active_scan_state"] = scanner_activity_json();
	return tool_result_t::ok(
		std::to_string(result["count"].get<size_t>()) + std::string(" address(es)."), result);
}

static tool_result_t handle_pointer_scan(const json& params) {
	mcp_standalone::downstream::producer_identity_t ps_id;
	ps_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ps_id.tool_name = "scanner_pointer_scan";
	mcp_standalone::downstream::scoped_admission_t ps_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ps_id);
	if (!ps_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ps_id);
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-REJECT scanner_pointer_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		return tool_result_t::error(
			std::string("Scanner capacity exhausted; work was not started."),
			"MCP_DOWNSTREAM_CAPACITY_REJECT",
			mcp_standalone::downstream::rejection_json(rej, ps_id));
	}
	diag::log_tagged_fmt("scanner",
		"FEATURE-WORKER-GROUP-ADMIT scanner_pointer_scan token=%llu",
		static_cast<unsigned long long>(ps_admission.token()));

	if (!params.contains("address")) {
		if (ps_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
				static_cast<unsigned long long>(ps_admission.token()));
			ps_admission.release("completed");
		}
		return tool_result_t::error(std::string("Missing 'address' parameter."));
	}

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) {
			if (ps_admission.active()) {
				diag::log_tagged_fmt("scanner",
					"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
					static_cast<unsigned long long>(ps_admission.token()));
				ps_admission.release("completed");
			}
			return tool_result_t::error(std::string("Invalid address format."));
		}
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	int max_depth = 4, max_offset = 0x1000;
	if (params.contains("max_depth") && params["max_depth"].is_number())
		max_depth = params["max_depth"].get<int>();
	if (params.contains("max_offset") && params["max_offset"].is_number())
		max_offset = params["max_offset"].get<int>();
	int timeout_ms = 4500;
	if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer()) {
		timeout_ms = params["timeout_ms"].get<int>();
		if (timeout_ms < 100) timeout_ms = 100;
		if (timeout_ms > 30000) timeout_ms = 30000;
	}
	uint64_t scan_base = 0;
	uint64_t scan_size = 0;
	parse_u64_param(params, "range_base", scan_base);
	parse_u64_param(params, "range_size", scan_size);
	const bool allow_partial = params.value("allow_partial", false);

	diag::log_tagged_fmt("scanner", "mcp pointer_scan request addr=0x%llX depth=%d offset=0x%X timeout_ms=%d range=0x%llX+0x%llX",
		static_cast<unsigned long long>(addr), max_depth, max_offset, timeout_ms,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size));

	const bool started = memory_scanner::start_pointer_scan(addr, max_depth, max_offset, scan_base, scan_size);
	if (!started) {
		if (ps_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
				static_cast<unsigned long long>(ps_admission.token()));
			ps_admission.release("completed");
		}
		return tool_result_t::error(std::string("Pointer scan did not start. Ensure the driver is loaded and a process is attached."));
	}
	{
		std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
		diag::log_tagged_fmt("scanner", "mcp pointer_scan started scanning=%d current_results=%zu",
			memory_scanner::g_state.pointer_scanning.load() ? 1 : 0,
			memory_scanner::g_state.pointer_results.size());
	}

	const int loops = (timeout_ms + 49) / 50;
	for (int i = 0; i < loops; ++i) {
		if (!memory_scanner::g_state.pointer_scanning.load()) break;
		if (mcp_standalone::current_call_cancelled()) {
			memory_scanner::cancel_pointer_scan();
			json result;
			add_scanner_action_context(result, "scanner_pointer_scan");
			result["cancelled"] = true;
			result["target_address"] = sa_format_address(addr);
			result["poll_iteration"] = i;
			diag::log_tagged_fmt("scanner", "mcp pointer_scan cancelled tick=%d/%d", i + 1, loops);
			if (ps_admission.active()) {
				diag::log_tagged_fmt("scanner",
					"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
					static_cast<unsigned long long>(ps_admission.token()));
				ps_admission.release("completed");
			}
			return tool_result_t::error(std::string("Pointer scan cancelled."), "cancelled", result);
		}
		if (i == 0 || ((i + 1) % 20) == 0) {
			std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
			diag::log_tagged_fmt("scanner", "mcp pointer_scan wait tick=%d/%d results=%zu",
				i + 1, loops, memory_scanner::g_state.pointer_results.size());
		}
		Sleep(50);
	}
	const bool timed_out = memory_scanner::g_state.pointer_scanning.load();
	if (timed_out) {
		{
			std::lock_guard<std::mutex> lk(memory_scanner::g_state.pointer_mutex);
			diag::log_tagged_fmt("scanner", "mcp pointer_scan timeout addr=0x%llX results_before_cancel=%zu allow_partial=%d",
				static_cast<unsigned long long>(addr),
				memory_scanner::g_state.pointer_results.size(),
				allow_partial ? 1 : 0);
		}
		memory_scanner::cancel_pointer_scan();
	}

	auto& st = memory_scanner::g_state;
	json arr = json::array();
	size_t total_results = 0;
	size_t n = 0;
	bool pointer_scanning_now = false;
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		total_results = st.pointer_results.size();
		pointer_scanning_now = st.pointer_scanning.load();
		diag::log_tagged_fmt("scanner", "mcp pointer_scan collect timed_out=%d total=%zu scanning=%d",
			timed_out ? 1 : 0, total_results, pointer_scanning_now ? 1 : 0);

		n = std::min(total_results, static_cast<size_t>(200));
		for (size_t i = 0; i < n; ++i) {
			auto& p = st.pointer_results[i];
			json obj;
			char buf[20];
			snprintf(buf, sizeof(buf), "0x%" PRIX64, p.base_address);
			obj["base"] = buf;
			if (!p.module_name.empty()) {
				snprintf(buf, sizeof(buf), "0x%" PRIX64, p.module_offset);
				obj["module"] = p.module_name + "+" + buf;
			}
			json offsets = json::array();
			for (auto off : p.offsets)
				offsets.push_back(off);
			obj["offsets"] = std::move(offsets);
			arr.push_back(std::move(obj));
		}
	}

	json result;
	add_scanner_action_context(result, "scanner_pointer_scan");
	result["total"] = total_results;
	result["showing"] = n;
	result["timed_out"] = timed_out && !allow_partial;
	result["partial"] = timed_out;
	result["target_address"] = sa_format_address(addr);
	result["target_pid"] = driver_bridge::attached_pid();
	result["max_depth"] = max_depth;
	result["max_offset"] = max_offset;
	result["range_base"] = scan_base == 0 ? json(nullptr) : json(sa_format_address(scan_base));
	result["range_size"] = scan_size;
	result["timeout_ms"] = timeout_ms;
	result["cancel_requested"] = timed_out;
	result["pointer_scanning"] = pointer_scanning_now;
	result["active_pointer_session"] = g_active_pointer_session.load(std::memory_order_relaxed);
	result["results"] = std::move(arr);
	if (timed_out && !allow_partial) {
		if (ps_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
				static_cast<unsigned long long>(ps_admission.token()));
			ps_admission.release("completed");
		}
		return tool_result_t{false, std::string("Pointer scan did not complete within the timeout."), result};
	}
	if (ps_admission.active()) {
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-RELEASE scanner_pointer_scan token=%llu reason=completed",
			static_cast<unsigned long long>(ps_admission.token()));
		ps_admission.release("completed");
	}
	return tool_result_t::ok(result);
}



static tool_result_t handle_find_what_accesses(const json& params) {
	mcp_standalone::downstream::producer_identity_t fwa_id;
	fwa_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	fwa_id.tool_name = "find_what_accesses";
	mcp_standalone::downstream::scoped_admission_t fwa_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(fwa_id);
	if (!fwa_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(fwa_id);
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-REJECT find_what_accesses reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		return tool_result_t::error(
			std::string("Scanner capacity exhausted; work was not started."),
			"MCP_DOWNSTREAM_CAPACITY_REJECT",
			mcp_standalone::downstream::rejection_json(rej, fwa_id));
	}
	diag::log_tagged_fmt("scanner",
		"FEATURE-WORKER-GROUP-ADMIT find_what_accesses token=%llu",
		static_cast<unsigned long long>(fwa_admission.token()));

	if (!params.contains("address") || !params["address"].is_string()) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("'address' is required."));
	}
	auto address = sa_parse_address(params["address"].get<std::string>());
	if (!address) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("Invalid address."));
	}
	uint64_t size = 4;
	if (params.contains("size") && params["size"].is_number_integer()) {
		int requested = params["size"].get<int>();
		if (requested > 0)
			size = static_cast<uint64_t>(std::min(requested, 4096));
	}
	std::string type = "write";
	if (params.contains("type")) {
		if (!params["type"].is_string()) {
			if (fwa_admission.active()) {
				diag::log_tagged_fmt("scanner",
					"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
					static_cast<unsigned long long>(fwa_admission.token()));
				fwa_admission.release("completed");
			}
			return tool_result_t::error(std::string("'type' must be read, write, or execute."));
		}
		type = params["type"].get<std::string>();
	}
	const uint32_t wanted_access = access_type_code(type);
	if (wanted_access == std::numeric_limits<uint32_t>::max()) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("'type' must be read, write, or execute."));
	}
	const int wait_ms = clamp_wait_ms(params, 5000);
	const size_t limit = limit_param(params, 32, 256);
	if (!driver_bridge::using_kernel_driver()) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("find_what_accesses requires the kernel driver page-guard backend."));
	}
	const uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("No attached process."));
	}
	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	const uint64_t page_size = si.dwPageSize ? si.dwPageSize : 0x1000;
	if (*address > std::numeric_limits<uint64_t>::max() - size) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("Watched address range overflows."));
	}
	const uint64_t end = *address + size;
	if (end > std::numeric_limits<uint64_t>::max() - (page_size - 1)) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("Guard address range overflows."));
	}
	const uint64_t page_base = *address & ~(page_size - 1);
	const uint64_t guard_end = (end + page_size - 1) & ~(page_size - 1);
	const uint64_t guard_size = std::max<uint64_t>(page_size, guard_end - page_base);
	const ULONGLONG started_tick = GetTickCount64();
	auto cancel_reason = []() -> const char* {
		if (mcp_standalone::current_call_cancelled())
			return "mcp_cancelled";
		const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
		if (deadline != 0 && GetTickCount64() >= deadline)
			return "mcp_deadline";
		return nullptr;
	};
	auto log_cancel = [&](const char* phase, const char* reason, uint32_t sid = 0) {
		const ULONGLONG now = GetTickCount64();
		const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
		const std::uint64_t remaining = deadline != 0 && now < deadline ? deadline - now : 0;
		diag::log_tagged_fmt("scanner",
			"find_what_accesses cancel phase=%s reason=%s sid=%u pid=%u active_pid=%u cancelled=%d deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu diag_id=%s",
			phase ? phase : "",
			reason ? reason : "",
			sid,
			pid,
			driver_bridge::attached_pid(),
			mcp_standalone::current_call_cancelled() ? 1 : 0,
			static_cast<unsigned long long>(deadline),
			static_cast<unsigned long long>(remaining),
			static_cast<unsigned long long>(now - started_tick),
			mcp_standalone::current_call_diag_id());
	};
	auto cancelled_result = [&](const char* phase, const char* reason, uint32_t sid, bool cleanup_attempted, bool cleanup_ok, size_t capture_count) -> tool_result_t {
		json result;
		result["address"] = sa_format_address(*address);
		result["size"] = size;
		result["type"] = type;
		result["pid"] = pid;
		result["session_id"] = sid;
		result["guard_base"] = sa_format_address(page_base);
		result["guard_size"] = guard_size;
		result["wait_ms"] = wait_ms;
		result["cancelled"] = true;
		result["cancel_reason"] = reason ? reason : "cancelled";
		result["cancel_phase"] = phase ? phase : "";
		result["cleanup_attempted"] = cleanup_attempted;
		result["cleanup_ok"] = cleanup_ok;
		result["page_guard_captures"] = capture_count;
		result["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started_tick);
		return tool_result_t::error(std::string("find_what_accesses cancelled before completion."), "cancelled", result);
	};
	diag::log_tagged_fmt("scanner",
		"find_what_accesses entry pid=%u address=0x%llX size=0x%llX type=%s wait_ms=%d limit=%zu page_base=0x%llX guard_size=0x%llX attached=%u cancelled=%d deadline_ms=%llu diag_id=%s",
		pid,
		static_cast<unsigned long long>(*address),
		static_cast<unsigned long long>(size),
		type.c_str(),
		wait_ms,
		limit,
		static_cast<unsigned long long>(page_base),
		static_cast<unsigned long long>(guard_size),
		driver_bridge::attached_pid(),
		mcp_standalone::current_call_cancelled() ? 1 : 0,
		static_cast<unsigned long long>(mcp_standalone::current_call_deadline_ms()),
		mcp_standalone::current_call_diag_id());
	if (const char* reason = cancel_reason()) {
		log_cancel("entry", reason);
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return cancelled_result("entry", reason, 0, false, false, 0);
	}
	const bool polling_enabled = false;
	const bool polling_baseline_ok = false;
	diag::log_tagged_fmt("scanner",
		"find_what_accesses baseline pid=%u ok=%d bytes=%zu elapsed_ms=%llu policy=page_guard_only",
		pid,
		polling_baseline_ok ? 1 : 0,
		static_cast<size_t>(0),
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	const uint32_t max_records_per_drain = static_cast<uint32_t>(std::min<size_t>(128, std::max<size_t>(limit * 4, 16)));
	diag::log_tagged_fmt("scanner",
		"find_what_accesses install_begin pid=%u page_base=0x%llX guard_size=0x%llX payloads=1 max_drain=%u elapsed_ms=%llu",
		pid,
		static_cast<unsigned long long>(page_base),
		static_cast<unsigned long long>(guard_size),
		max_records_per_drain,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	if (const char* reason = cancel_reason()) {
		log_cancel("before_install", reason);
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return cancelled_result("before_install", reason, 0, false, false, 0);
	}
	uint32_t sid = page_guard_engine::g_pg_engine.install(pid, page_base, guard_size, true, max_records_per_drain);
	bool pg_failed = false;
	if (sid == 0) {
		json failure = page_guard_install_failure_json();
		pg_failed = true;
		diag::log_tagged_fmt("scanner",
			"find_what_accesses install_failed pid=%u active_pid=%u reason=%s remote_call_id=%llu remote_gle=%lu stale_pid=%d deadline_expired=%d cancelled=%d late_completion=%d elapsed_ms=%llu last_error=%s",
			pid,
			driver_bridge::attached_pid(),
			failure.value("reason", std::string()).c_str(),
			static_cast<unsigned long long>(failure.value("remote_call_id", 0ull)),
			static_cast<unsigned long>(failure.value("remote_call_gle", 0u)),
			failure.value("remote_call_stale_pid", false) ? 1 : 0,
			failure.value("remote_call_deadline_expired_after", false) ? 1 : 0,
			failure.value("remote_call_cancelled_after", false) ? 1 : 0,
			failure.value("remote_call_late_completion", false) ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - started_tick),
			driver_bridge::last_error().c_str());
		json result;
		result["address"] = sa_format_address(*address);
		result["size"] = size;
		result["type"] = type;
		result["pid"] = pid;
		result["session_id"] = sid;
		result["guard_base"] = sa_format_address(page_base);
		result["guard_size"] = guard_size;
		result["wait_ms"] = wait_ms;
		result["failure_reason"] = "page_guard_install_failed";
		result["phase"] = "install";
		result["pg_failed"] = true;
		result["page_guard_installed"] = false;
		result["page_guard_install_failure"] = failure;
		result["polling_fallback_attempted"] = false;
		result["polling_fallback_functional"] = false;
		result["polling_enabled_before_install"] = polling_enabled;
		result["polling_baseline_before_install"] = polling_baseline_ok;
		result["polling_baseline_size_before_install"] = 0;
		result["install_elapsed_ms"] = failure.value("install_elapsed_ms", 0ull);
		result["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started_tick);
		result["driver_last_error"] = driver_bridge::last_error();
		result["remote_call"] = failure.contains("remote_call") ? failure["remote_call"] : json::object();
		result["region"] = json{
			{"base", failure.value("region_base", std::string())},
			{"size", failure.value("region_size", 0ull)},
			{"state", failure.value("region_state", 0u)},
			{"protect", failure.value("region_protect", 0u)},
			{"type", failure.value("region_type", 0u)},
			{"attempted_protect", failure.value("attempted_protect", 0u)},
			{"original_protect", failure.value("original_protect", 0u)},
			{"proposed_protect", failure.value("proposed_protect", 0u)}
		};
		diag::log_tagged_fmt("scanner",
			"find_what_accesses install_terminal_failure pid=%u page_base=0x%llX guard_size=0x%llX polling_fallback_attempted=0 elapsed_ms=%llu",
			pid,
			static_cast<unsigned long long>(page_base),
			static_cast<unsigned long long>(guard_size),
			static_cast<unsigned long long>(GetTickCount64() - started_tick));
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return tool_result_t::error(std::string("find_what_accesses page-guard install failed."), "page_guard_install_failed", result);
	}
	diag::log_tagged_fmt("scanner",
		"find_what_accesses install_done sid=%u pid=%u payloads=1 max_drain=%u elapsed_ms=%llu",
		sid,
		pid,
		max_records_per_drain,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	if (const char* reason = cancel_reason()) {
		log_cancel("after_install", reason, sid);
		const bool cleanup_ok = page_guard_engine::g_pg_engine.uninstall(sid);
		diag::log_tagged_fmt("scanner",
			"find_what_accesses cancel_cleanup phase=after_install sid=%u cleanup_ok=%d elapsed_ms=%llu",
			sid,
			cleanup_ok ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - started_tick));
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return cancelled_result("after_install", reason, sid, true, cleanup_ok, 0);
	}
	const size_t payload_budget = std::min<size_t>(256, std::max<size_t>(limit * 4, 16));
	const bool payload_budget_set = page_guard_engine::g_pg_engine.set_payload_budget(sid, payload_budget);
	diag::log_tagged_fmt("scanner",
		"find_what_accesses payload_budget sid=%u requested_limit=%zu budget=%zu set=%d elapsed_ms=%llu",
		sid,
		limit,
		payload_budget,
		payload_budget_set ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	auto capture_matches = [&](const page_guard_engine::pg_capture_record_t& c) {
		const auto& meta = c.metadata;
		return wanted_access == meta.access_type && meta.fault_addr >= *address && meta.fault_addr < end;
	};
	auto captures = page_guard_engine::g_pg_engine.get_capture_records(sid);
	bool have_match = false;
	for (const auto& c : captures) {
		if (capture_matches(c))
			have_match = true;
	}
	diag::log_tagged_fmt("scanner",
		"find_what_accesses initial_drain sid=%u captures=%zu match=%d elapsed_ms=%llu",
		sid,
		captures.size(),
		have_match ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	const auto started = std::chrono::steady_clock::now();
	const auto deadline = started + std::chrono::milliseconds(wait_ms);
	uint32_t iterations = 0;
	size_t drained_batches = 0;
	bool cancelled = false;
	const char* cancelled_phase = "";
	const char* cancelled_reason = "";
	diag::log_tagged_fmt("scanner",
		"find_what_accesses loop_begin sid=%u wait_ms=%d pg_failed=%d polling_enabled=%d polling_baseline_ok=%d elapsed_ms=%llu",
		sid,
		wait_ms,
		pg_failed ? 1 : 0,
		polling_enabled ? 1 : 0,
		polling_baseline_ok ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	do {
		if (const char* reason = cancel_reason()) {
			cancelled = true;
			cancelled_phase = "loop_before_drain";
			cancelled_reason = reason;
			log_cancel(cancelled_phase, reason, sid);
			break;
		}
		auto batch = page_guard_engine::g_pg_engine.get_capture_records(sid);
		++iterations;
		drained_batches += batch.size();
		for (auto& c : batch) {
			if (capture_matches(c))
				have_match = true;
			captures.push_back(std::move(c));
		}
		if (!batch.empty() || iterations == 1 || (iterations % 20) == 0) {
			diag::log_tagged_fmt("scanner",
				"find_what_accesses loop sid=%u iter=%u batch=%zu total=%zu match=%d polling_delta=%d elapsed_ms=%llu",
				sid,
				iterations,
				batch.size(),
				captures.size(),
				have_match ? 1 : 0,
				0,
				static_cast<unsigned long long>(GetTickCount64() - started_tick));
		}
		if (const char* reason = cancel_reason()) {
			cancelled = true;
			cancelled_phase = "loop_after_sample";
			cancelled_reason = reason;
			log_cancel(cancelled_phase, reason, sid);
			break;
		}
		if (have_match && captures.size() >= limit)
			break;
		if (wait_ms == 0 || std::chrono::steady_clock::now() >= deadline)
			break;
		int sleep_ms = 25;
		const std::uint64_t mcp_deadline = mcp_standalone::current_call_deadline_ms();
		const ULONGLONG now_tick = GetTickCount64();
		if (mcp_deadline != 0 && now_tick < mcp_deadline)
			sleep_ms = static_cast<int>(std::min<std::uint64_t>(25, mcp_deadline - now_tick));
		if (sleep_ms > 0)
			std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
	} while (true);
	diag::log_tagged_fmt("scanner",
		"find_what_accesses loop_end sid=%u iterations=%u drained=%zu total=%zu match=%d polling_delta=%d cancelled=%d cancel_reason=%s elapsed_ms=%llu",
		sid,
		iterations,
		drained_batches,
		captures.size(),
		have_match ? 1 : 0,
		0,
		cancelled ? 1 : 0,
		cancelled_reason ? cancelled_reason : "",
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	diag::log_tagged_fmt("scanner",
		"find_what_accesses tail_begin sid=%u elapsed_ms=%llu",
		sid,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	if (cancelled) {
		diag::log_tagged_fmt("scanner",
			"find_what_accesses tail_skipped sid=%u reason=cancelled phase=%s total=%zu elapsed_ms=%llu",
			sid,
			cancelled_phase ? cancelled_phase : "",
			captures.size(),
			static_cast<unsigned long long>(GetTickCount64() - started_tick));
	} else if (!have_match || captures.size() < limit) {
		auto tail = page_guard_engine::g_pg_engine.get_capture_records(sid);
		for (auto& c : tail) {
			if (capture_matches(c))
				have_match = true;
			captures.push_back(std::move(c));
		}
		diag::log_tagged_fmt("scanner",
			"find_what_accesses tail_done sid=%u tail=%zu total=%zu match=%d polling_delta=%d elapsed_ms=%llu",
			sid,
			tail.size(),
			captures.size(),
			have_match ? 1 : 0,
			0,
			static_cast<unsigned long long>(GetTickCount64() - started_tick));
	} else {
		diag::log_tagged_fmt("scanner",
			"find_what_accesses tail_skipped sid=%u total=%zu limit=%zu match=%d polling_delta=%d elapsed_ms=%llu",
			sid,
			captures.size(),
			limit,
			have_match ? 1 : 0,
			0,
			static_cast<unsigned long long>(GetTickCount64() - started_tick));
	}
	diag::log_tagged_fmt("scanner",
		"find_what_accesses uninstall_begin sid=%u elapsed_ms=%llu",
		sid,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	const bool uninstalled = page_guard_engine::g_pg_engine.uninstall(sid);
	diag::log_tagged_fmt("scanner",
		"find_what_accesses uninstall_done sid=%u ok=%d elapsed_ms=%llu",
		sid,
		uninstalled ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	if (cancelled) {
		if (fwa_admission.active()) {
			diag::log_tagged_fmt("scanner",
				"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
				static_cast<unsigned long long>(fwa_admission.token()));
			fwa_admission.release("completed");
		}
		return cancelled_result(cancelled_phase, cancelled_reason, sid, true, uninstalled, captures.size());
	}
	json arr = json::array();
	for (const auto& c : captures) {
		if (arr.size() >= limit)
			break;
		const auto& meta = c.metadata;
		if (wanted_access != meta.access_type)
			continue;
		if (meta.fault_addr < *address || meta.fault_addr >= end)
			continue;
		json o;
		o["fault_address"] = sa_format_address(meta.fault_addr);
		o["rip"] = sa_format_address(meta.rip);
		o["access_type"] = access_type_name(meta.access_type);
		o["exception_code"] = meta.exception_code;
		o["timestamp_tsc"] = meta.timestamp;
		o["registers"] = captured_register_json(meta);
		o["register_state_source"] = "veh_exception_context";
		o["register_state_complete"] = false;
		o["captured_registers"] = {"rip", "rax", "rcx", "rdx"};
		o["unavailable_registers"] = {"rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"};
		page_guard_engine::serialize_payload_fields(o, c);
		arr.push_back(std::move(o));
	}
	json result;
	result["address"] = sa_format_address(*address);
	result["size"] = size;
	result["type"] = type;
	result["pid"] = pid;
	result["session_id"] = sid;
	result["guard_base"] = sa_format_address(page_base);
	result["guard_size"] = guard_size;
	result["wait_ms"] = wait_ms;
	result["total_captures"] = captures.size();
	result["page_guard_captures"] = captures.size();
	result["polling_delta_captures"] = 0;
	result["polling_fallback_attempted"] = false;
	result["polling_fallback_functional"] = false;
	result["polling_baseline"] = polling_baseline_ok;
	result["pg_failed"] = pg_failed;
	result["returned"] = arr.size();
	result["accesses"] = std::move(arr);
	diag::log_tagged_fmt("scanner",
		"find_what_accesses return sid=%u captures=%zu returned=%zu polling_delta_returned=%d pg_failed=%d elapsed_ms=%llu",
		sid,
		captures.size(),
		result["accesses"].size(),
		0,
		pg_failed ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - started_tick));
	if (fwa_admission.active()) {
		diag::log_tagged_fmt("scanner",
			"FEATURE-WORKER-GROUP-RELEASE find_what_accesses token=%llu reason=completed",
			static_cast<unsigned long long>(fwa_admission.token()));
		fwa_admission.release("completed");
	}
	return tool_result_t::ok(result);
}

static tool_result_t handle_watch_memory_layout(const json& params) {
	uint64_t address = 0;
	std::string error;
	if (!parse_address_param(params, "address", address, error))
		return tool_result_t::error(error);
	std::string struct_name;
	if (params.contains("struct_name") && params["struct_name"].is_string())
		struct_name = params["struct_name"].get<std::string>();
	int refresh_rate_ms = 1000;
	if (params.contains("refresh_rate_ms") && params["refresh_rate_ms"].is_number_integer())
		refresh_rate_ms = params["refresh_rate_ms"].get<int>();
	if (refresh_rate_ms < 0) refresh_rate_ms = 0;
	if (refresh_rate_ms > 60000) refresh_rate_ms = 60000;

	int struct_index = -1;
	struct_dissector::struct_def_t sd;
	bool missing_struct = false;
	{
		std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
		if (!struct_name.empty()) {
			const std::string wanted = lower_copy(struct_name);
			for (size_t i = 0; i < struct_dissector::g_state.structs.size(); ++i) {
				if (lower_copy(struct_dissector::g_state.structs[i].name) == wanted) {
					struct_index = static_cast<int>(i);
					break;
				}
			}
		} else {
			struct_index = struct_dissector::g_state.active_struct;
		}
		if (struct_index < 0 || struct_index >= static_cast<int>(struct_dissector::g_state.structs.size())) {
			missing_struct = true;
		} else {
			struct_dissector::g_state.active_struct = struct_index;
			struct_dissector::g_state.base_address = address;
			struct_dissector::g_state.auto_refresh = refresh_rate_ms > 0;
			struct_dissector::g_state.refresh_interval = refresh_rate_ms > 0
				? static_cast<float>(refresh_rate_ms) / 1000.0f
				: 0.0f;
			sd = struct_dissector::g_state.structs[static_cast<size_t>(struct_index)];
		}
	}
	if (missing_struct)
		return tool_result_t::error(std::string("Struct definition not found. Available structs: ") + available_struct_names_text());

	if (sd.total_size == 0)
		return tool_result_t::error(std::string("Struct definition has no fields."));
	if (sd.total_size > 0x10000)
		return tool_result_t::error(std::string("Struct snapshot size exceeds 65536 bytes."));
	if (address > std::numeric_limits<uint64_t>::max() - sd.total_size)
		return tool_result_t::error(std::string("Struct snapshot address range overflows."));
	const uint32_t target_pid = driver_bridge::attached_pid();
	if (target_pid == 0)
		return tool_result_t::error(std::string("Memory reader is unavailable or no process is attached."));

	std::vector<uint8_t> block;
	if (!driver_bridge::read_memory_for(target_pid, address, sd.total_size, block) || block.size() != sd.total_size)
		return tool_result_t::error(std::string("Failed to read struct memory snapshot."));

	json result = struct_snapshot_json(struct_index, sd, address, block);
	result["watch_active"] = refresh_rate_ms > 0;
	result["refresh_rate_ms"] = refresh_rate_ms;
	result["snapshot_bytes"] = block.size();
	return tool_result_t::ok(result);
}

static tool_result_t handle_assert_memory_type(const json& params) {
	uint64_t address = 0;
	std::string error;
	if (!parse_address_param(params, "address", address, error))
		return tool_result_t::error(error);
	int64_t offset = 0;
	if (!parse_i64_param(params, "offset", offset, error))
		return tool_result_t::error(error);
	if (!params.contains("expected_type") || !params["expected_type"].is_string())
		return tool_result_t::error(std::string("'expected_type' is required."));
	struct_dissector::field_type_t expected_type = struct_dissector::field_type_t::int32;
	const std::string expected_text = params["expected_type"].get<std::string>();
	if (!parse_field_type(expected_text, expected_type))
		return tool_result_t::error(std::string("Unsupported expected_type: ") + expected_text);
	if (expected_type == struct_dissector::field_type_t::nested_struct)
		return tool_result_t::error(std::string("nested_struct assertions require watch_memory_layout."));

	bool offset_ok = false;
	const uint64_t effective = add_signed_offset(address, offset, offset_ok);
	if (!offset_ok)
		return tool_result_t::error(std::string("Effective address overflow or offset outside allowed range."));
	const uint32_t target_pid = driver_bridge::attached_pid();
	if (target_pid == 0)
		return tool_result_t::error(std::string("Memory reader is unavailable or no process is attached."));

	const size_t read_size = assertion_read_size(expected_type, params);
	if (effective > std::numeric_limits<uint64_t>::max() - read_size)
		return tool_result_t::error(std::string("Assertion read address range overflows."));
	int duration_ms = 5000;
	if (params.contains("duration_ms") && params["duration_ms"].is_number_integer())
		duration_ms = params["duration_ms"].get<int>();
	if (duration_ms < 0) duration_ms = 0;
	if (duration_ms > 10000) duration_ms = 10000;
	int sample_interval_ms = 250;
	if (params.contains("sample_interval_ms") && params["sample_interval_ms"].is_number_integer())
		sample_interval_ms = params["sample_interval_ms"].get<int>();
	if (sample_interval_ms < 50) sample_interval_ms = 50;
	if (sample_interval_ms > 1000) sample_interval_ms = 1000;
	int sample_count = duration_ms == 0 ? 1 : (duration_ms / sample_interval_ms) + 1;
	if (sample_count < 1) sample_count = 1;
	if (sample_count > 64) sample_count = 64;

	bool has_bounds = false;
	double min_bound = 0.0;
	double max_bound = 0.0;
	std::string range_source;
	if (params.contains("min") && params["min"].is_number() && params.contains("max") && params["max"].is_number()) {
		min_bound = params["min"].get<double>();
		max_bound = params["max"].get<double>();
		has_bounds = min_bound <= max_bound;
		range_source = "provided";
	} else if (expected_type == struct_dissector::field_type_t::float32 ||
	           expected_type == struct_dissector::field_type_t::float64) {
		min_bound = -1000.0;
		max_bound = 1000.0;
		has_bounds = true;
		range_source = "default_float_sanity";
	}

	json samples = json::array();
	std::vector<uint8_t> previous;
	int read_errors = 0;
	int valid_samples = 0;
	int changed_count = 0;
	int nonfinite_count = 0;
	int out_of_range_count = 0;
	int pointer_invalid_count = 0;
	int string_invalid_count = 0;
	double observed_min = std::numeric_limits<double>::infinity();
	double observed_max = -std::numeric_limits<double>::infinity();

	for (int i = 0; i < sample_count; ++i) {
		if (mcp_standalone::current_call_cancelled())
			return tool_result_t::error(std::string("Memory type assertion cancelled during sampling."));
		std::vector<uint8_t> bytes;
		const bool read_ok = driver_bridge::read_memory_for(target_pid, effective, read_size, bytes) && bytes.size() == read_size;
		json sample;
		sample["index"] = i;
		sample["read_ok"] = read_ok;
		if (!read_ok) {
			++read_errors;
		} else {
			if (!previous.empty() && bytes != previous)
				++changed_count;
			previous = bytes;
			++valid_samples;
			sample["value"] = field_value_json(bytes, expected_type);
			double numeric = 0.0;
			bool finite = true;
			if (numeric_sample_value(expected_type, bytes, numeric, finite)) {
				if (!finite) {
					++nonfinite_count;
				} else {
					observed_min = std::min(observed_min, numeric);
					observed_max = std::max(observed_max, numeric);
					if (has_bounds && (numeric < min_bound || numeric > max_bound))
						++out_of_range_count;
				}
			}
			uint64_t pointer = 0;
			if (pointer_sample_value(expected_type, bytes, pointer)) {
				const bool plausible_pointer = pointer == 0 ||
					(pointer >= 0x10000ULL && pointer <= 0x00007FFFFFFFFFFFULL);
				if (!plausible_pointer)
					++pointer_invalid_count;
			}
			if (!string_sample_printable(expected_type, bytes))
				++string_invalid_count;
		}
		samples.push_back(std::move(sample));
		if (i + 1 < sample_count)
			Sleep(sample_interval_ms);
	}

	json result;
	result["address"] = sa_format_address(address);
	result["offset"] = offset;
	result["effective_address"] = sa_format_address(effective);
	result["expected_type"] = expected_text;
	result["normalized_type"] = struct_dissector::field_type_name(expected_type);
	result["read_size"] = read_size;
	result["duration_ms"] = duration_ms;
	result["sample_interval_ms"] = sample_interval_ms;
	result["sample_count"] = sample_count;
	result["valid_samples"] = valid_samples;
	result["read_errors"] = read_errors;
	result["changed_samples"] = changed_count;
	result["stable"] = changed_count == 0 && valid_samples > 0;
	result["nonfinite_count"] = nonfinite_count;
	result["out_of_range_count"] = out_of_range_count;
	result["pointer_invalid_count"] = pointer_invalid_count;
	result["string_invalid_count"] = string_invalid_count;
	result["plausible"] = valid_samples > 0 && read_errors == 0 && nonfinite_count == 0 &&
		out_of_range_count == 0 && pointer_invalid_count == 0 && string_invalid_count == 0;
	if (std::isfinite(observed_min) && std::isfinite(observed_max)) {
		result["observed_min"] = observed_min;
		result["observed_max"] = observed_max;
	}
	if (has_bounds) {
		result["range"] = {{"min", min_bound}, {"max", max_bound}, {"source", range_source}};
	}
	result["samples"] = std::move(samples);
	return tool_result_t::ok(result);
}

static tool_result_t handle_write_value(const json& params) {
	const std::uint32_t attached_pid = driver_bridge::attached_pid();
	driver_bridge::identity::live_target_identity_t authorized_identity;
	std::string identity_error;
	const bool identity_captured = attached_pid != 0 &&
		driver_bridge::identity::capture_live_target_identity(
			attached_pid, 0, authorized_identity, &identity_error) &&
		driver_bridge::identity::validate_attached_target_identity(authorized_identity).matches;
	if (!identity_captured)
		return tool_result_t::error(identity_error.empty()
			? std::string("No verified live target is attached.") : identity_error);

	if (!params.contains("address") || !params.contains("value"))
		return tool_result_t::error(std::string("Missing 'address' or 'value' parameter."));
	if (!params["value"].is_string())
		return tool_result_t::error(std::string("'value' must be a string."));

	uint64_t addr = 0;
	std::string error;
	if (!parse_address_param(params, "address", addr, error))
		return tool_result_t::error(error);

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type") && params["value_type"].is_string())
		vtype = parse_value_type(params["value_type"].get<std::string>());

	bool hex = false;
	if (params.contains("hex") && params["hex"].is_boolean())
		hex = params["hex"].get<bool>();

	std::string val_str = params["value"].get<std::string>();
	std::vector<uint8_t> bytes = memory_scanner::parse_value(val_str, vtype, hex);
	if (bytes.empty())
		return tool_result_t::error(std::string("Failed to parse value for the requested value_type."));

	const size_t before_count = address_list_count();
	const auto list_index = address_index_by_address(addr);
	const auto transaction = memory_scanner::write_value_exact(addr, vtype, val_str, hex,
		authorized_identity.process.pid,
		authorized_identity.process.creation_time_100ns);
	if (transaction.verified && list_index.has_value())
		memory_scanner::refresh_address_list();
	const size_t after_count = address_list_count();

	json result;
	add_scanner_action_context(result, "scanner_write_value");
	result["success"] = transaction.verified;
	result["address"] = sa_format_address(addr);
	result["index"] = list_index.has_value() ? json(*list_index) : json(nullptr);
	result["list_count_before"] = before_count;
	result["list_count_after"] = after_count;
	result["value_type"] = memory_scanner::value_type_name(vtype);
	result["hex"] = hex;
	result["requested_value"] = val_str;
	result["requested_bytes"] = bytes_hex_preview(bytes, 256);
	result["requested_size"] = bytes.size();
	result["bytes_written"] = transaction.verified ? bytes.size() : 0;
	result["cancel_requested"] = false;
	result["target_pid"] = transaction.target_pid;
	result["process_creation_time_100ns"] =
		std::to_string(transaction.process_creation_time_100ns);
	result["write_attempted"] = transaction.write_attempted;
	result["write_ok"] = transaction.write_ok;
	result["before_read_ok"] = transaction.original_read_ok;
	if (transaction.original_read_ok) {
		result["before"] = memory_scanner::format_value(transaction.original_bytes, vtype);
		result["before_hex"] = bytes_hex_preview(transaction.original_bytes, 256);
	}
	result["readback_ok"] = transaction.readback_ok;
	result["verified"] = transaction.verified;
	if (transaction.readback_ok) {
		result["readback"] = memory_scanner::format_value(transaction.readback_bytes, vtype);
		result["readback_hex"] = bytes_hex_preview(transaction.readback_bytes, 256);
	}
	result["rollback_attempted"] = transaction.rollback_attempted;
	result["rollback_write_ok"] = transaction.rollback_write_ok;
	result["rollback_readback_ok"] = transaction.rollback_readback_ok;
	result["rollback_verified"] = transaction.rollback_verified;
	if (transaction.rollback_readback_ok)
		result["rollback_readback_hex"] =
			bytes_hex_preview(transaction.rollback_readback_bytes, 256);
	if (!transaction.error.empty()) result["error"] = transaction.error;
	if (list_index.has_value()) {
		json entry;
		if (address_entry_by_index(*list_index, entry)) {
			result["frozen"] = entry.value("frozen", false);
			result["entry"] = std::move(entry);
		}
	} else {
		result["frozen"] = false;
	}
	if (!transaction.verified)
		return tool_result_t{false, transaction.error.empty()
			? std::string("Value write verification failed.") : transaction.error, result};
	return tool_result_t::ok(std::string("Value written successfully."), result);
}


void register_scanner_tools(mcp_standalone::server_t& srv) {

	register_compat(srv, {std::string("find_what_accesses"), std::string("memory_scanner"),
		std::string("Monitor reads, writes, or executes touching an address range using the page-guard backend. Returns access RIP, fault address, captured exception-context registers, and payload preview."),
		{{std::string("address"), std::string("string"), std::string("Address to monitor"), true},
		 {std::string("size"), std::string("number"), std::string("Watched byte count, default 4, capped at 4096"), false},
		 {std::string("type"), std::string("string"), std::string("Access type: read, write, execute"), false},
		 {std::string("wait_ms"), std::string("number"), std::string("Capture duration, default 5000, capped at 60000"), false},
		 {std::string("limit"), std::string("number"), std::string("Maximum matching access records to return, default 32"), false}},
		handle_find_what_accesses, false});

	register_compat(srv, {std::string("watch_memory_layout"), std::string("memory_scanner"),
		std::string("Read a live ReClass-style snapshot at an address using an existing struct_dissector definition by name, or the active struct when struct_name is omitted."),
		{{std::string("address"), std::string("string"), std::string("Base address to read"), true},
		 {std::string("struct_name"), std::string("string"), std::string("Struct definition name; omit to use the active struct"), false},
		 {std::string("refresh_rate_ms"), std::string("number"), std::string("Refresh interval to arm in the struct dissector state, 0 disables auto refresh"), false}},
		handle_watch_memory_layout, false});

	register_compat(srv, {std::string("assert_memory_type"), std::string("memory_scanner"),
		std::string("Sample address+offset for a bounded interval and report whether the observed bytes plausibly match an expected scalar, pointer, string, or byte-array type."),
		{{std::string("address"), std::string("string"), std::string("Base address to test"), true},
		 {std::string("offset"), std::string("number"), std::string("Offset from base address"), true},
		 {std::string("expected_type"), std::string("string"), std::string("Type: int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double/pointer/string/utf16/aob"), true},
		 {std::string("duration_ms"), std::string("number"), std::string("Sampling duration, default 5000, capped at 10000"), false},
		 {std::string("sample_interval_ms"), std::string("number"), std::string("Sampling interval, default 250, clamped 50-1000"), false},
		 {std::string("size"), std::string("number"), std::string("Read size for string or byte-array assertions, capped at 256"), false},
		 {std::string("min"), std::string("number"), std::string("Optional numeric lower bound"), false},
		 {std::string("max"), std::string("number"), std::string("Optional numeric upper bound"), false}},
		handle_assert_memory_type, true});

	register_compat(srv, {std::string("scanner_first_scan"), std::string("memory_scanner"),
		std::string("Start a new memory scan. Scans all committed memory of the attached process for values matching the criteria. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{std::string("value"), std::string("string"), std::string("Value to search for"), true},
		 {std::string("value_type"), std::string("string"), std::string("Type: byte/int16/int32/int64/float/double/ascii/utf16/aob"), false},
		 {std::string("scan_mode"), std::string("string"), std::string("Mode: exact/bigger/smaller/between/unknown"), false},
		 {std::string("value2"), std::string("string"), std::string("Second value for 'between' mode"), false},
		 {std::string("hex"), std::string("boolean"), std::string("Interpret value as hexadecimal"), false},
		 {std::string("writable_only"), std::string("boolean"), std::string("Only scan writable pages (default true)"), false},
		 {std::string("executable_exclude"), std::string("boolean"), std::string("Exclude executable pages (default true)"), false},
		 {std::string("alignment"), std::string("number"), std::string("Scan alignment in bytes (default: type size)"), false},
		 {std::string("range_base"), std::string("string"), std::string("Optional scan range base address"), false},
		 {std::string("range_size"), std::string("number"), std::string("Optional scan range size in bytes"), false}},
		handle_first_scan, false});

	register_compat(srv, {std::string("scanner_next_scan"), std::string("memory_scanner"),
		std::string("Refine previous scan results by applying a new comparison. Narrows down results from the last scan."),
		{{std::string("scan_mode"), std::string("string"), std::string("Mode: exact/bigger/smaller/between/changed/unchanged/increased/decreased"), true},
		 {std::string("value"), std::string("string"), std::string("Value for comparison (not needed for changed/unchanged/increased/decreased)"), false},
		 {std::string("value2"), std::string("string"), std::string("Second value for 'between' mode"), false}},
		handle_next_scan, false});

	register_compat(srv, {std::string("scanner_get_results"), std::string("memory_scanner"),
		std::string("Get current scan results. Returns addresses, values, and module info."),
		{{std::string("limit"), std::string("number"), std::string("Maximum results to return (default 100)"), false}},
		handle_get_results, true});

	register_compat(srv, {std::string("scanner_undo"), std::string("memory_scanner"),
		std::string("Undo the last scan refinement, restoring previous results."),
		{}, handle_undo_scan, false});

	register_compat(srv, {std::string("scanner_address_list_manage"), std::string("memory_scanner"),
		std::string("Manage the scanner address watch list. Actions: add, remove, freeze, list."),
		{{std::string("action"), std::string("string"), std::string("add|remove|freeze|list"), true},
		 {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "add") return handle_add_address(p);
			if (action == "remove") return handle_remove_address(p);
			if (action == "freeze") return handle_freeze_address(p);
			if (action == "list") return handle_get_address_list(p);
			return compat_unknown_action("scanner_address_list_manage", action);
		}, false});

	register_compat(srv, {std::string("scanner_write_value"), std::string("memory_scanner"),
		std::string("Write a value to a memory address in the attached process."),
		{{std::string("address"), std::string("string"), std::string("Memory address (hex)"), true},
		 {std::string("value"), std::string("string"), std::string("Value to write"), true},
		 {std::string("value_type"), std::string("string"), std::string("Type: byte/int16/int32/int64/float/double"), false},
		 {std::string("hex"), std::string("boolean"), std::string("Interpret value as hex"), false}},
		handle_write_value, false});

	register_compat(srv, {std::string("scanner_pointer_scan"), std::string("memory_scanner"),
		std::string("Perform a pointer scan to find pointer chains that lead to the target address. Useful for finding stable pointers. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{std::string("address"), std::string("string"), std::string("Target address to find pointers to"), true},
		 {std::string("max_depth"), std::string("number"), std::string("Maximum pointer chain depth (1-7, default 4)"), false},
		 {std::string("max_offset"), std::string("number"), std::string("Maximum offset from pointer base (default 0x1000)"), false},
		 {std::string("range_base"), std::string("string"), std::string("Optional pointer-slot scan range base address"), false},
		 {std::string("range_size"), std::string("number"), std::string("Optional pointer-slot scan range size in bytes"), false},
		 {std::string("timeout_ms"), std::string("number"), std::string("Maximum wait time, capped at 30000 ms"), false},
		 {std::string("allow_partial"), std::string("boolean"), std::string("Return partial results without marking the payload as timed out"), false}},
		handle_pointer_scan, true});

	register_compat(srv, {std::string("scanner_cancel_pointer_scan"), std::string("memory_scanner"),
		std::string("Cancel a running pointer scan."),
		{},
		[](const json&) -> tool_result_t {
			const size_t before_count = address_list_count();
			const bool was_active = memory_scanner::g_state.pointer_scanning.load();
			json before_state = scanner_activity_json();
			memory_scanner::cancel_pointer_scan();
			const bool stopped = wait_for_pointer_idle(500);
			const size_t after_count = address_list_count();
			json result;
			add_scanner_action_context(result, "scanner_cancel_pointer_scan");
			result["success"] = stopped;
			result["cancel_requested"] = true;
			result["address"] = nullptr;
			result["index"] = nullptr;
			result["list_count_before"] = before_count;
			result["list_count_after"] = after_count;
			result["frozen"] = false;
			result["value_type"] = nullptr;
			result["bytes_written"] = 0;
			result["readback_ok"] = false;
			result["verified"] = stopped;
			result["was_active"] = was_active;
			result["pointer_scanning_before"] = before_state.value("pointer_scanning", false);
			result["pointer_scanning_after"] = memory_scanner::g_state.pointer_scanning.load();
			result["active_pointer_session"] = g_active_pointer_session.load(std::memory_order_relaxed);
			result["before_state"] = std::move(before_state);
			return tool_result_t::ok(std::string("Pointer scan cancelled."), result);
		}, false});

	auto scanner_define_struct = [](const json& params) -> tool_result_t {
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(std::string("'name' is required."));
			if (!params.contains("base_address") || !params["base_address"].is_string())
				return tool_result_t::error(std::string("'base_address' is required."));
			auto addr = sa_parse_address(params["base_address"].get<std::string>());
			if (!addr) return tool_result_t::error(std::string("Invalid base_address."));
			int idx = struct_dissector::create_struct(params["name"].get<std::string>());
			if (idx < 0)
				return tool_result_t::error(std::string("Failed to create struct."));
			if (params.value("kind", std::string{"struct"}) == "union" &&
				!struct_dissector::set_structure_kind(idx, struct_dissector::structure_kind_t::union_type)) {
				std::string rollback_error;
				struct_dissector::remove_structure(idx, rollback_error);
				return tool_result_t::error(std::string("Failed to configure union layout."));
			}
			if (params.contains("packing") && !struct_dissector::set_structure_packing(idx,
				params["packing"].get<std::uint16_t>())) {
				std::string rollback_error;
				struct_dissector::remove_structure(idx, rollback_error);
				return tool_result_t::error(std::string("Invalid structure packing."));
			}
			if (params.contains("alignment") && !struct_dissector::set_structure_alignment(idx,
				params["alignment"].get<std::uint16_t>())) {
				std::string rollback_error;
				struct_dissector::remove_structure(idx, rollback_error);
				return tool_result_t::error(std::string("Invalid structure alignment."));
			}
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				struct_dissector::g_state.active_struct = idx;
				struct_dissector::g_state.base_address = *addr;
			}
			json result;
			result["struct_index"] = idx;
			result["name"] = params["name"].get<std::string>();
			result["base_address"] = sa_format_address(*addr);
			return tool_result_t::ok(
				std::string("Structure '") + params["name"].get<std::string>() + std::string("' created at index ") + std::to_string(idx), result);
		};

	auto scanner_add_struct_field = [](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(std::string("'struct_index' is required."));
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(std::string("'name' is required."));
			if (!params.contains("offset") || !params["offset"].is_number())
				return tool_result_t::error(std::string("'offset' is required."));
			if (!params.contains("field_type") || !params["field_type"].is_string())
				return tool_result_t::error(std::string("'field_type' is required."));
			int si = params["struct_index"].get<int>();
			std::string type_str = params["field_type"].get<std::string>();
			struct_dissector::field_type_t ft = struct_dissector::field_type_t::int32;
			if (type_str == "int8") ft = struct_dissector::field_type_t::int8;
			else if (type_str == "uint8") ft = struct_dissector::field_type_t::uint8;
			else if (type_str == "int16") ft = struct_dissector::field_type_t::int16;
			else if (type_str == "uint16") ft = struct_dissector::field_type_t::uint16;
			else if (type_str == "int32") ft = struct_dissector::field_type_t::int32;
			else if (type_str == "uint32") ft = struct_dissector::field_type_t::uint32;
			else if (type_str == "int64") ft = struct_dissector::field_type_t::int64;
			else if (type_str == "uint64") ft = struct_dissector::field_type_t::uint64;
			else if (type_str == "float32") ft = struct_dissector::field_type_t::float32;
			else if (type_str == "float64") ft = struct_dissector::field_type_t::float64;
			else if (type_str == "pointer") ft = struct_dissector::field_type_t::pointer;
			else if (type_str == "ascii_string") ft = struct_dissector::field_type_t::ascii_string;
			else if (type_str == "utf16_string") ft = struct_dissector::field_type_t::utf16_string;
			else if (type_str == "byte_array") ft = struct_dissector::field_type_t::byte_array;
			else if (type_str == "padding") ft = struct_dissector::field_type_t::padding;
			else if (type_str == "nested_struct") ft = struct_dissector::field_type_t::nested_struct;
			else return tool_result_t::error(std::string("Unknown field_type: ") + type_str);
			if (ft == struct_dissector::field_type_t::nested_struct &&
				(!params.contains("target_structure") || !params["target_structure"].is_string()))
				return tool_result_t::error(std::string("nested_struct requires 'target_structure'."));
			struct_dissector::field_def_t fld;
			fld.name = params["name"].get<std::string>();
			fld.type = ft == struct_dissector::field_type_t::nested_struct
				? struct_dissector::field_type_t::byte_array : ft;
			fld.offset = static_cast<uint32_t>(params["offset"].get<int>());
			fld.size = params.value("size", static_cast<uint32_t>((std::max)(std::size_t{1}, struct_dissector::field_type_size(ft))));
			fld.array_count = params.value("array_count", 1u);
			fld.bit_offset = params.value("bit_offset", std::uint16_t{0});
			fld.bit_width = params.value("bit_width", std::uint16_t{0});
			fld.explicit_alignment = params.value("alignment", std::uint16_t{0});
			fld.description = params.value("description", std::string{});
			int fi = struct_dissector::add_field(si, fld);
			if (fi < 0)
				return tool_result_t::error(std::string("Failed to add field."));
			if (params.contains("target_structure") && params["target_structure"].is_string() &&
				!struct_dissector::set_field_nested_target_by_name(si, fi,
					params["target_structure"].get<std::string>(), ft == struct_dissector::field_type_t::pointer)) {
				struct_dissector::remove_field(si, fi);
				return tool_result_t::error(std::string("Field was added, but its target structure was rejected."));
			}
			json result;
			result["field_index"] = fi;
			result["name"] = fld.name;
			result["offset"] = fld.offset;
			result["type"] = type_str;
			return tool_result_t::ok(
				std::string("Field '") + fld.name + std::string("' added at offset ") + std::to_string(fld.offset), result);
		};

	auto scanner_get_struct = [](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(std::string("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				if (si < 0 || si >= static_cast<int>(struct_dissector::g_state.structs.size()))
					return tool_result_t::error(std::string("Invalid struct_index."));
				struct_dissector::g_state.active_struct = si;
			}
			struct_dissector::refresh_values();
			std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
			const auto& sd = struct_dissector::g_state.structs[static_cast<size_t>(si)];
			json fields_arr = json::array();
			for (size_t fi = 0; fi < sd.fields.size(); ++fi) {
				const auto& f = sd.fields[fi];
				json fj;
				fj["index"] = fi;
				fj["name"] = f.name;
				fj["offset"] = f.offset;
				fj["type"] = struct_dissector::field_type_name(f.type);
				fj["size"] = f.size;
				fj["id"] = f.stable_id;
				fj["array_count"] = f.array_count;
				fj["target_structure_id"] = f.target_structure_id;
				fj["enum_id"] = f.enum_id;
				fj["referenced_type"] = f.referenced_type_name;
				fj["bit_offset"] = f.bit_offset;
				fj["bit_width"] = f.bit_width;
				fj["alignment"] = f.explicit_alignment;
				if (fi < struct_dissector::g_state.cached_values.size())
					fj["value"] = struct_dissector::g_state.cached_values[fi].display_text;
				fields_arr.push_back(std::move(fj));
			}
			json result;
			result["name"] = sd.name;
			result["id"] = sd.stable_id;
			result["revision"] = sd.layout_revision;
			result["kind"] = sd.kind == struct_dissector::structure_kind_t::union_type ? "union" : "struct";
			result["packing"] = sd.packing;
			result["alignment"] = sd.explicit_alignment;
			result["base_address"] = sa_format_address(struct_dissector::g_state.base_address);
			result["total_size"] = sd.total_size;
			result["field_count"] = sd.fields.size();
			result["fields"] = std::move(fields_arr);
			return tool_result_t::ok(
				std::string("Struct '") + sd.name + std::string("': ") + std::to_string(sd.fields.size()) + std::string(" field(s)."), result);
		};

	auto scanner_export_struct_c = [](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(std::string("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			std::string code = struct_dissector::export_to_c(si);
			if (code.empty())
				return tool_result_t::error(std::string("Invalid struct_index or empty struct."));
			json result;
			result["c_code"] = code;
			return tool_result_t::ok(code, result);
		};

	auto scanner_export_struct_schema = [](const json&) -> tool_result_t {
		const std::string schema = struct_dissector::serialize_schema();
		json result;
		result["schema_version"] = 3;
		result["schema"] = schema;
		return tool_result_t::ok(std::string("Structure schema exported."), result);
	};

	auto scanner_import_struct_schema = [](const json& params) -> tool_result_t {
		if (!params.contains("schema") || !params["schema"].is_string())
			return tool_result_t::error(std::string("'schema' is required."));
		std::string error;
		if (!struct_dissector::deserialize_schema(params["schema"].get<std::string>(), error))
			return tool_result_t::error(std::string("Structure schema import failed: ") + error);
		json result;
		result["schema_version"] = 3;
		result["schema"] = struct_dissector::serialize_schema();
		return tool_result_t::ok(std::string("Structure schema imported and validated."), result);
	};

	register_compat(srv, {std::string("scanner_struct_manage"), std::string("memory_scanner"),
		std::string("Manage scanner structure definitions. Actions: define, add_field, get, export_c, export_schema, import_schema."),
		{{std::string("action"), std::string("string"), std::string("define|add_field|get|export_c|export_schema|import_schema"), true},
		 {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
		[scanner_define_struct, scanner_add_struct_field, scanner_get_struct, scanner_export_struct_c,
			scanner_export_struct_schema, scanner_import_struct_schema](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "define") return scanner_define_struct(p);
			if (action == "add_field") return scanner_add_struct_field(p);
			if (action == "get") return scanner_get_struct(p);
			if (action == "export_c") return scanner_export_struct_c(p);
			if (action == "export_schema") return scanner_export_struct_schema(p);
			if (action == "import_schema") return scanner_import_struct_schema(p);
			return compat_unknown_action("scanner_struct_manage", action);
		}, false});

}

}
