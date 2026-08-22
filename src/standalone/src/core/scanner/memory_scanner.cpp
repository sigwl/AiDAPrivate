#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "../runtime/standalone_driver_identity.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../settings/standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "scanner_task_center.hpp"
#include "../analysis/workspace/byte_provider.hpp"
#include "../analysis/workspace/pe_image.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <sstream>
#include <iomanip>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace memory_scanner {

namespace {

using live_target_identity_t = driver_bridge::identity::live_target_identity_t;

enum class scan_terminal_t : std::uint8_t {
	active,
	completed,
	cancelled,
	failed
};

struct scan_operation_t {
	std::uint64_t generation = 0;
	std::atomic<std::uint64_t> executor_task_id{0};
	std::atomic<bool> started{false};
	std::atomic<bool> cancellation_requested{false};
	std::atomic<scan_terminal_t> terminal{scan_terminal_t::active};
	std::atomic<int> published_progress_milli{-1};
};

std::atomic<std::uint64_t> g_scan_generation{0};
std::atomic<std::uint64_t> g_active_scan_generation{0};
std::mutex g_scan_operation_mutex;
std::shared_ptr<scan_operation_t> g_active_scan_operation;

std::shared_ptr<scan_operation_t> begin_scan_operation() {
	auto operation = std::make_shared<scan_operation_t>();
	operation->generation = g_scan_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
	g_active_scan_generation.store(operation->generation, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lock(g_scan_operation_mutex);
		g_active_scan_operation = operation;
	}
	return operation;
}

bool owns_scan(const std::shared_ptr<scan_operation_t>& operation) {
	return operation && operation->generation != 0 &&
		g_active_scan_generation.load(std::memory_order_acquire) == operation->generation;
}

void publish_scan_progress(const std::shared_ptr<scan_operation_t>& operation,
	float progress, const char* stage) {
	if (!owns_scan(operation))
		return;
	const std::uint64_t task_id = operation->executor_task_id.load(std::memory_order_acquire);
	if (task_id == 0)
		return;
	const int progress_milli = static_cast<int>((std::max)(0.0f,
		(std::min)(1.0f, progress)) * 1000.0f);
	int previous = operation->published_progress_milli.load(std::memory_order_acquire);
	while (progress_milli < 1000 && previous >= 0 && progress_milli - previous < 5)
		return;
	while (!operation->published_progress_milli.compare_exchange_weak(previous,
		progress_milli, std::memory_order_acq_rel, std::memory_order_acquire)) {
		if (progress_milli < 1000 && previous >= 0 && progress_milli - previous < 5)
			return;
	}
	scanner_task_center::update_executor_task(task_id,
		aida::ui::task_center::task_state_t::running, progress,
		stage ? stage : "Scanning");
}

void finish_scan_operation(const std::shared_ptr<scan_operation_t>& operation,
	scan_terminal_t terminal, const char* detail) {
	const scan_terminal_t requested_terminal = terminal;
	scan_terminal_t expected = scan_terminal_t::active;
	if (!operation->terminal.compare_exchange_strong(expected, terminal,
			std::memory_order_acq_rel, std::memory_order_acquire)) {
		terminal = expected;
		if (terminal != requested_terminal)
			detail = nullptr;
	}
	const bool owner = owns_scan(operation);
	if (owner) {
		if (terminal != scan_terminal_t::cancelled)
			g_state.scan_progress.store(1.0f, std::memory_order_release);
		g_state.scanning.store(false, std::memory_order_release);
		g_state.scan_thread_done.store(true, std::memory_order_release);
	}
	const std::uint64_t task_id = operation->executor_task_id.load(std::memory_order_acquire);
	if (task_id == 0)
		return;
	if (terminal == scan_terminal_t::cancelled) {
		scanner_task_center::update_executor_task(task_id,
			aida::ui::task_center::task_state_t::cancelled,
			owner ? g_state.scan_progress.load(std::memory_order_acquire) : -1.0f, "Cancelled",
			detail ? detail : "Scan cancelled");
	} else if (terminal == scan_terminal_t::failed) {
		scanner_task_center::update_executor_task(task_id,
			aida::ui::task_center::task_state_t::failed,
			owner ? g_state.scan_progress.load(std::memory_order_acquire) : -1.0f, "Failed",
			detail ? detail : "Scan failed");
	} else {
		scanner_task_center::update_executor_task(task_id,
			aida::ui::task_center::task_state_t::completed, 1.0f, "Completed",
			detail ? detail : "Scan completed");
	}
}

void publish_scan_terminal_snapshot(const std::shared_ptr<scan_operation_t>& operation) {
	switch (operation->terminal.load(std::memory_order_acquire)) {
	case scan_terminal_t::completed:
		finish_scan_operation(operation, scan_terminal_t::completed, "Scan completed");
		break;
	case scan_terminal_t::cancelled:
		finish_scan_operation(operation, scan_terminal_t::cancelled, "Scan cancelled");
		break;
	case scan_terminal_t::failed:
		finish_scan_operation(operation, scan_terminal_t::failed, "Scan failed");
		break;
	case scan_terminal_t::active:
		if (operation->started.load(std::memory_order_acquire))
			publish_scan_progress(operation,
				g_state.scan_progress.load(std::memory_order_acquire), "Scanning");
		break;
	}
}

bool same_target_identity(const live_target_identity_t& lhs, const live_target_identity_t& rhs) {
	return lhs.process.pid == rhs.process.pid &&
		lhs.process.creation_time_100ns == rhs.process.creation_time_100ns &&
		lhs.process.normalized_process_path == rhs.process.normalized_process_path &&
		lhs.module.base == rhs.module.base && lhs.module.size == rhs.module.size &&
		lhs.module.normalized_name == rhs.module.normalized_name &&
		lhs.module.normalized_path == rhs.module.normalized_path;
}

bool capture_attached_identity(live_target_identity_t& identity, const char* operation) {
	const std::uint32_t pid = driver_bridge::is_loaded() ? driver_bridge::attached_pid() : 0;
	std::string error;
	if (pid != 0 && driver_bridge::identity::capture_live_target_identity(pid, 0, identity, &error)) {
		const auto validation = driver_bridge::identity::validate_attached_target_identity(identity);
		if (validation.matches) return true;
		error = std::string(driver_bridge::identity::staleness_code(validation.staleness)) +
			": " + validation.detail;
	}
	diag::log_tagged_fmt("mem_scanner", "%s refused target_identity error='%s' pid=%u",
		operation, error.c_str(), pid);
	identity = {};
	return false;
}

std::uint64_t observe_target_identity(const live_target_identity_t& identity) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lock(st.target_binding_mutex);
	const std::uint32_t previous_pid = st.observed_target_pid.load(std::memory_order_relaxed);
	const std::uint64_t previous_creation =
		st.observed_target_creation_time_100ns.load(std::memory_order_relaxed);
	if (previous_pid != identity.process.pid ||
		previous_creation != identity.process.creation_time_100ns) {
		st.observed_target_pid.store(identity.process.pid, std::memory_order_release);
		st.observed_target_creation_time_100ns.store(
			identity.process.creation_time_100ns, std::memory_order_release);
		return st.target_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
	}
	return st.target_epoch.load(std::memory_order_acquire);
}

bool validate_attached_identity(const live_target_identity_t& identity, const char* operation) {
	const auto validation = driver_bridge::identity::validate_attached_target_identity(identity);
	if (validation.matches) return true;
	diag::log_tagged_fmt("mem_scanner",
		"%s refused stale_target code=%s detail='%s' expected_pid=%u current_pid=%u",
		operation, driver_bridge::identity::staleness_code(validation.staleness),
		validation.detail.c_str(), identity.process.pid,
		driver_bridge::is_loaded() ? driver_bridge::attached_pid() : 0);
	return false;
}

}

uint64_t observe_target_binding(uint32_t pid) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lock(st.target_binding_mutex);
	if (st.observed_target_pid.load(std::memory_order_relaxed) != pid) {
		st.observed_target_pid.store(pid, std::memory_order_release);
		st.observed_target_creation_time_100ns.store(0, std::memory_order_release);
		return st.target_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
	}
	return st.target_epoch.load(std::memory_order_acquire);
}

bool target_binding_current(uint32_t pid, uint64_t epoch) {
	const uint32_t current_pid = driver_bridge::is_loaded() ? driver_bridge::attached_pid() : 0;
	return pid != 0 && current_pid == pid &&
		g_state.observed_target_pid.load(std::memory_order_acquire) == pid &&
		g_state.target_epoch.load(std::memory_order_acquire) == epoch;
}

bool validate_target_binding(uint32_t pid, uint64_t epoch,
	uint64_t process_creation_time_100ns) {
	if (pid == 0 || epoch == 0 || process_creation_time_100ns == 0 ||
		!target_binding_current(pid, epoch) ||
		g_state.observed_target_creation_time_100ns.load(std::memory_order_acquire) !=
			process_creation_time_100ns)
		return false;
	live_target_identity_t identity;
	return capture_attached_identity(identity, "validate_target_binding") &&
		identity.process.pid == pid &&
		identity.process.creation_time_100ns == process_creation_time_100ns &&
		target_binding_current(pid, epoch);
}

static bool transaction_target_current(uint32_t pid, uint64_t epoch,
	const live_target_identity_t& identity, const char* operation) {
	return target_binding_current(pid, epoch) &&
		g_state.observed_target_creation_time_100ns.load(std::memory_order_acquire) ==
			identity.process.creation_time_100ns &&
		validate_attached_identity(identity, operation) && target_binding_current(pid, epoch);
}

static std::string scanner_target_key(const live_target_identity_t& identity) {
	if (identity.process.normalized_process_path.empty() ||
		identity.module.normalized_name.empty() || identity.module.size == 0) return {};
	return std::to_string(identity.process.normalized_process_path.size()) + ":" +
		identity.process.normalized_process_path + ":" +
		std::to_string(identity.module.normalized_path.size()) + ":" +
		identity.module.normalized_path + ":" + identity.module.normalized_name + ":" +
		std::to_string(identity.module.size);
}

static std::string legacy_scanner_target_key(const live_target_identity_t& identity) {
	if (identity.module.normalized_name.empty() || identity.module.size == 0) return {};
	return identity.module.normalized_name + ":" + std::to_string(identity.module.size);
}

static void persist_scanner_state() {
	live_target_identity_t target_identity;
	const bool identity_valid = capture_attached_identity(target_identity, "persist_scanner_state");
	const std::uint32_t target_pid = identity_valid ? target_identity.process.pid : 0;
	const std::uint64_t target_epoch = identity_valid ? observe_target_identity(target_identity) :
		observe_target_binding(0);
	const auto modules = identity_valid ? driver_bridge::enumerate_modules() :
		std::vector<driver_bridge::module_info_t>{};
	nlohmann::json root{{"schema", 2}, {"targets", nlohmann::json::object()}};
	{
		std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
		if (!g_sa_settings.memory_scanner_state_json.empty()) {
			auto parsed = nlohmann::json::parse(g_sa_settings.memory_scanner_state_json, nullptr, false);
			if (parsed.is_object() && (parsed.value("schema", 0) == 1 ||
				parsed.value("schema", 0) == 2) && parsed.contains("targets") &&
				parsed["targets"].is_object())
				root = std::move(parsed);
		}
		root["schema"] = 2;
	}
	{
		std::lock_guard<std::mutex> lock(g_state.results_mutex);
		root["config"] = {
			{"value_type", static_cast<int>(g_state.config.value_type)},
			{"scan_mode", static_cast<int>(g_state.config.scan_mode)},
			{"value", g_state.config.value_text.substr(0, 4096)},
			{"value2", g_state.config.value_text2.substr(0, 4096)},
			{"hex", g_state.config.hex_input},
			{"signed", g_state.config.is_signed},
			{"alignment", g_state.config.alignment},
			{"writable_only", g_state.config.writable_only},
			{"exclude_executable", g_state.config.executable_exclude}
		};
	}
	const std::string target_key = identity_valid ? scanner_target_key(target_identity) : std::string{};
	if (!target_key.empty()) {
		nlohmann::json entries = nlohmann::json::array();
		{
			std::lock_guard<std::mutex> lock(g_state.address_mutex);
			for (const auto& entry : g_state.address_list) {
				if (entry.target_pid != target_pid || entry.target_epoch != target_epoch ||
					!same_target_identity(entry.target_identity, target_identity))
					continue;
				for (const auto& module : modules) {
					const std::uint64_t end = module.base + static_cast<std::uint64_t>(module.size);
					if (module.size == 0 || end < module.base || entry.address < module.base || entry.address >= end)
						continue;
					entries.push_back({{"module", module.name.substr(0, 1024)},
						{"module_size", module.size}, {"offset", std::to_string(entry.address - module.base)},
						{"description", entry.description.substr(0, 1024)},
						{"value_type", static_cast<int>(entry.value_type)},
						{"process_creation_time_100ns", std::to_string(
							entry.target_identity.process.creation_time_100ns)},
						{"process_path", entry.target_identity.process.normalized_process_path.substr(0, 4096)},
						{"identity_module_base", std::to_string(entry.target_identity.module.base)},
						{"identity_module_size", std::to_string(entry.target_identity.module.size)},
						{"identity_module_name", entry.target_identity.module.normalized_name.substr(0, 1024)},
						{"identity_module_path", entry.target_identity.module.normalized_path.substr(0, 4096)}});
					break;
				}
				if (entries.size() >= 4096) break;
			}
		}
		if (validate_attached_identity(target_identity, "persist_scanner_state_publish"))
			root["targets"][target_key] = {{"addresses", std::move(entries)}};
	}
	const std::string payload = root.dump();
	{
		std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
		if (g_sa_settings.memory_scanner_state_json == payload) return;
		g_sa_settings.memory_scanner_state_json = payload;
	}
	static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
}

static void restore_scanner_state_for_current_target() {
	const std::uint32_t pid = driver_bridge::is_loaded() ? driver_bridge::attached_pid() : 0;
	live_target_identity_t target_identity;
	const bool identity_valid = pid != 0 &&
		capture_attached_identity(target_identity, "restore_scanner_state");
	const std::uint64_t creation_time = identity_valid ?
		target_identity.process.creation_time_100ns : 0;
	if (g_state.persisted_loaded_pid.load(std::memory_order_acquire) == pid &&
		g_state.persisted_loaded_creation_time_100ns.load(std::memory_order_acquire) == creation_time &&
		((pid != 0 && identity_valid) ||
			g_state.persisted_config_loaded.load(std::memory_order_acquire))) return;
	const std::uint64_t target_epoch = identity_valid ? observe_target_identity(target_identity) :
		observe_target_binding(pid);
	const auto modules = identity_valid ? driver_bridge::enumerate_modules() :
		std::vector<driver_bridge::module_info_t>{};
	const std::string target_key = identity_valid ? scanner_target_key(target_identity) : std::string{};
	nlohmann::json root;
	{
		std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
		root = nlohmann::json::parse(g_sa_settings.memory_scanner_state_json, nullptr, false);
	}
	if (!root.is_object() || (root.value("schema", 0) != 1 && root.value("schema", 0) != 2)) {
		g_state.persisted_loaded_pid.store(pid, std::memory_order_release);
		g_state.persisted_loaded_creation_time_100ns.store(creation_time, std::memory_order_release);
		return;
	}
	if (root.contains("config") && root["config"].is_object()) {
		const auto& config = root["config"];
		const int value_type = config.value("value_type", static_cast<int>(value_type_t::int32_val));
		const int scan_mode = config.value("scan_mode", static_cast<int>(scan_mode_t::exact));
		if (value_type >= 0 && value_type < static_cast<int>(value_type_t::COUNT) &&
			scan_mode >= 0 && scan_mode < static_cast<int>(scan_mode_t::COUNT)) {
			std::lock_guard<std::mutex> lock(g_state.results_mutex);
			g_state.config.value_type = static_cast<value_type_t>(value_type);
			g_state.config.scan_mode = static_cast<scan_mode_t>(scan_mode);
			g_state.config.value_text = config.value("value", std::string{}).substr(0, 4096);
			g_state.config.value_text2 = config.value("value2", std::string{}).substr(0, 4096);
			g_state.config.hex_input = config.value("hex", false);
			g_state.config.is_signed = config.value("signed", true);
			g_state.config.alignment = (std::max<std::size_t>)(1, (std::min<std::size_t>)(
				4096, config.value("alignment", static_cast<std::size_t>(4))));
			g_state.config.writable_only = config.value("writable_only", true);
			g_state.config.executable_exclude = config.value("exclude_executable", true);
			g_state.persisted_config_loaded.store(true, std::memory_order_release);
		}
	}
	std::vector<address_entry_t> restored;
	const std::string legacy_target_key = identity_valid ?
		legacy_scanner_target_key(target_identity) : std::string{};
	const nlohmann::json* persisted_target = nullptr;
	if (!target_key.empty() && root.contains("targets") && root["targets"].is_object()) {
		if (root["targets"].contains(target_key))
			persisted_target = &root["targets"][target_key];
		else if (!legacy_target_key.empty() && root["targets"].contains(legacy_target_key))
			persisted_target = &root["targets"][legacy_target_key];
	}
	if (persisted_target && persisted_target->is_object() &&
		persisted_target->contains("addresses")) {
		const auto& addresses = (*persisted_target)["addresses"];
		if (addresses.is_array()) for (const auto& item : addresses) {
			if (restored.size() >= 4096 || !item.is_object()) break;
			const std::string module_name = item.value("module", std::string{});
			const std::uint32_t module_size = item.value("module_size", 0u);
			const std::string offset_text = item.value("offset", std::string{});
			char* end = nullptr;
			errno = 0;
			const auto offset = std::strtoull(offset_text.c_str(), &end, 10);
			const int value_type = item.value("value_type", -1);
			if (errno != 0 || !end || *end != '\0' || value_type < 0 ||
				value_type >= static_cast<int>(value_type_t::COUNT)) continue;
			const driver_bridge::module_info_t* match = nullptr;
			for (const auto& module : modules) {
				if (module.name != module_name || module.size != module_size) continue;
				if (match) { match = nullptr; break; }
				match = &module;
			}
			if (!match || offset >= match->size || match->base >
				(std::numeric_limits<std::uint64_t>::max)() - offset) continue;
			address_entry_t entry;
			entry.address = match->base + offset;
			entry.description = item.value("description", std::string{}).substr(0, 1024);
			entry.value_type = static_cast<value_type_t>(value_type);
			entry.target_pid = pid;
			entry.target_epoch = target_epoch;
			entry.target_identity = target_identity;
			restored.push_back(std::move(entry));
		}
	}
	if (identity_valid && !validate_attached_identity(target_identity,
		"restore_scanner_state_publish")) restored.clear();
	{
		std::lock_guard<std::mutex> lock(g_state.address_mutex);
		g_state.address_list = std::move(restored);
	}
	g_state.persisted_loaded_pid.store(pid, std::memory_order_release);
	g_state.persisted_loaded_creation_time_100ns.store(creation_time, std::memory_order_release);
}


std::vector<uint8_t> parse_value(const std::string& text, value_type_t type, bool hex) {
	std::vector<uint8_t> out;
	if (text.empty()) return out;

	auto push_le = [&](const void* src, size_t n) {
		const auto* p = static_cast<const uint8_t*>(src);
		out.assign(p, p + n);
	};

	switch (type) {
		case value_type_t::byte_val: {
			uint8_t v = static_cast<uint8_t>(strtoul(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 1);
			break;
		}
		case value_type_t::int16_val: {
			auto v = static_cast<int16_t>(strtol(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 2);
			break;
		}
		case value_type_t::int32_val: {
			auto v = static_cast<int32_t>(strtol(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 4);
			break;
		}
		case value_type_t::int64_val: {
			auto v = static_cast<int64_t>(strtoll(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 8);
			break;
		}
		case value_type_t::float_val: {
			float v = strtof(text.c_str(), nullptr);
			push_le(&v, 4);
			break;
		}
		case value_type_t::double_val: {
			double v = strtod(text.c_str(), nullptr);
			push_le(&v, 8);
			break;
		}
		case value_type_t::string_ascii: {
			out.assign(text.begin(), text.end());
			break;
		}
		case value_type_t::string_utf16: {
			int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
			if (len > 0) {
				std::vector<wchar_t> ws(len);
				MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, ws.data(), len);
				size_t byte_len = (static_cast<size_t>(len) - 1) * sizeof(wchar_t);
				const auto* p = reinterpret_cast<const uint8_t*>(ws.data());
				out.assign(p, p + byte_len);
			}
			break;
		}
		case value_type_t::byte_array: {
			std::istringstream iss(text);
			std::string token;
			while (iss >> token) {
				if (token == "??" || token == "?") {
					out.push_back(0);
				} else {
					out.push_back(static_cast<uint8_t>(strtoul(token.c_str(), nullptr, 16)));
				}
			}
			break;
		}
		default:
			break;
	}
	return out;
}

std::string format_value(const std::vector<uint8_t>& bytes, value_type_t type) {
	if (bytes.empty()) return "";
	char buf[64];

	switch (type) {
		case value_type_t::byte_val:
			if (bytes.size() >= 1) {
				snprintf(buf, sizeof(buf), "%u", bytes[0]);
				return buf;
			}
			break;
		case value_type_t::int16_val:
			if (bytes.size() >= 2) {
				int16_t v;
				std::memcpy(&v, bytes.data(), 2);
				snprintf(buf, sizeof(buf), "%d", static_cast<int>(v));
				return buf;
			}
			break;
		case value_type_t::int32_val:
			if (bytes.size() >= 4) {
				int32_t v;
				std::memcpy(&v, bytes.data(), 4);
				snprintf(buf, sizeof(buf), "%d", v);
				return buf;
			}
			break;
		case value_type_t::int64_val:
			if (bytes.size() >= 8) {
				int64_t v;
				std::memcpy(&v, bytes.data(), 8);
				snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
				return buf;
			}
			break;
		case value_type_t::float_val:
			if (bytes.size() >= 4) {
				float v;
				std::memcpy(&v, bytes.data(), 4);
				snprintf(buf, sizeof(buf), "%.6g", static_cast<double>(v));
				return buf;
			}
			break;
		case value_type_t::double_val:
			if (bytes.size() >= 8) {
				double v;
				std::memcpy(&v, bytes.data(), 8);
				snprintf(buf, sizeof(buf), "%.10g", v);
				return buf;
			}
			break;
		case value_type_t::string_ascii:
			return std::string(bytes.begin(), bytes.end());
		case value_type_t::string_utf16: {
			if (bytes.size() >= 2) {
				int len = WideCharToMultiByte(CP_UTF8, 0,
					reinterpret_cast<const wchar_t*>(bytes.data()),
					static_cast<int>(bytes.size() / sizeof(wchar_t)),
					nullptr, 0, nullptr, nullptr);
				if (len > 0) {
					std::string s(len, '\0');
					WideCharToMultiByte(CP_UTF8, 0,
						reinterpret_cast<const wchar_t*>(bytes.data()),
						static_cast<int>(bytes.size() / sizeof(wchar_t)),
						s.data(), len, nullptr, nullptr);
					return s;
				}
			}
			break;
		}
		case value_type_t::byte_array: {
			std::ostringstream oss;
			for (size_t i = 0; i < bytes.size(); ++i) {
				if (i > 0) oss << ' ';
				oss << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
					<< static_cast<unsigned>(bytes[i]);
			}
			return oss.str();
		}
		default:
			break;
	}
	return "";
}


static bool compare_exact(const uint8_t* mem, const uint8_t* target, size_t sz) {
	return std::memcmp(mem, target, sz) == 0;
}

template <typename T>
static bool compare_bigger(const uint8_t* mem, const uint8_t* target) {
	T a, b;
	std::memcpy(&a, mem, sizeof(T));
	std::memcpy(&b, target, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a > b;
}

template <typename T>
static bool compare_smaller(const uint8_t* mem, const uint8_t* target) {
	T a, b;
	std::memcpy(&a, mem, sizeof(T));
	std::memcpy(&b, target, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a < b;
}

template <typename T>
static bool compare_between(const uint8_t* mem, const uint8_t* lo, const uint8_t* hi) {
	T v, l, h;
	std::memcpy(&v, mem, sizeof(T));
	std::memcpy(&l, lo, sizeof(T));
	std::memcpy(&h, hi, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(v == v) || !(l == l) || !(h == h)) return false;
	}
	return v >= l && v <= h;
}

template <typename T>
static bool compare_changed(const uint8_t* cur, const uint8_t* prev) {
	return std::memcmp(cur, prev, sizeof(T)) != 0;
}

template <typename T>
static bool compare_increased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a > b;
}

template <typename T>
static bool compare_decreased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a < b;
}


static void annotate_modules(std::vector<scan_result_t>& results) {
	auto modules = driver_bridge::enumerate_modules();
	for (auto& r : results) {
		for (const auto& m : modules) {
			if (r.address >= m.base && r.address < m.base + m.size) {
				r.module_name = m.name;
				r.module_offset = r.address - m.base;
				break;
			}
		}
	}
}


static void first_scan_thread(scan_config_t config,
	const std::shared_ptr<scan_operation_t>& operation) {
	auto& st = g_state;
	st.scan_progress.store(0.f);
	uint32_t target_pid = 0;
	uint64_t target_epoch = 0;
	live_target_identity_t target_identity;
	{
		std::lock_guard<std::mutex> lock(st.results_mutex);
		target_pid = st.scan_target_pid;
		target_epoch = st.scan_target_epoch;
		target_identity = st.scan_target_identity;
	}
	if (!target_binding_current(target_pid, target_epoch) ||
		!validate_attached_identity(target_identity, "first_scan_thread_start")) {
		throw std::runtime_error("The attached target changed before the initial memory scan started");
	}

	auto t_start = std::chrono::steady_clock::now();
	auto regions = driver_bridge::enumerate_memory_regions_for(target_pid, 4096);
	diag::log_tagged_fmt("mem_scanner", "first_scan_thread enter pid=%u regions=%zu val_type=%s mode=%s writable_only=%d exec_exclude=%d hex=%d align=%zu range=0x%llX+0x%llX",
		driver_bridge::attached_pid(), regions.size(),
		value_type_name(config.value_type), scan_mode_name(config.scan_mode),
		static_cast<int>(config.writable_only), static_cast<int>(config.executable_exclude),
		static_cast<int>(config.hex_input), config.alignment,
		static_cast<unsigned long long>(config.range_base),
		static_cast<unsigned long long>(config.range_size));

	std::vector<driver_bridge::memory_region_t> scan_regions;
	const bool has_range = config.range_base != 0 && config.range_size != 0;
	const uint64_t range_start = config.range_base;
	const uint64_t max_u64 = std::numeric_limits<uint64_t>::max();
	const uint64_t range_end = has_range
		? (max_u64 - config.range_base < config.range_size ? max_u64 : config.range_base + config.range_size)
		: 0;
	size_t skipped_state = 0;
	size_t skipped_guard = 0;
	size_t skipped_protect = 0;
	size_t skipped_writable = 0;
	size_t skipped_exec = 0;
	size_t skipped_type = 0;
	size_t skipped_range = 0;
	for (const auto& r : regions) {
		if (r.state != 0x1000) { ++skipped_state; continue; }
		if (r.protect & 0x100) { ++skipped_guard; continue; }
		uint32_t base_prot = r.protect & 0xFF;
		if (base_prot == 0x01 || base_prot == 0x00) { ++skipped_protect; continue; }
		if (config.writable_only && !(base_prot & 0xCC)) { ++skipped_writable; continue; }
		if (config.executable_exclude && (base_prot & 0xF0)) { ++skipped_exec; continue; }
		if (r.type == 0x40000) { ++skipped_type; continue; }
		if (has_range) {
			const uint64_t region_start = r.base;
			const uint64_t region_end = max_u64 - r.base < r.size ? max_u64 : r.base + r.size;
			const uint64_t clipped_start = std::max(region_start, range_start);
			const uint64_t clipped_end = std::min(region_end, range_end);
			if (clipped_start >= clipped_end) { ++skipped_range; continue; }
			auto clipped = r;
			clipped.base = clipped_start;
			clipped.size = clipped_end - clipped_start;
			scan_regions.push_back(clipped);
		} else {
			scan_regions.push_back(r);
		}
	}
	diag::log_tagged_fmt("mem_scanner",
		"first_scan_thread region_filter raw=%zu eligible=%zu skipped_state=%zu skipped_guard=%zu skipped_protect=%zu skipped_writable=%zu skipped_exec=%zu skipped_type=%zu skipped_range=%zu",
		regions.size(),
		scan_regions.size(),
		skipped_state,
		skipped_guard,
		skipped_protect,
		skipped_writable,
		skipped_exec,
		skipped_type,
		skipped_range);

	if (scan_regions.empty()) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread no_eligible_regions raw=%zu filtered=0", regions.size());
		st.scan_progress.store(1.f);
		return;
	}

	size_t val_sz = value_type_size(config.value_type);
	std::vector<uint8_t> target_val = parse_value(config.value_text, config.value_type, config.hex_input);
	std::vector<uint8_t> target_val2;
	if (config.scan_mode == scan_mode_t::value_between)
		target_val2 = parse_value(config.value_text2, config.value_type, config.hex_input);

	bool is_string = (config.value_type == value_type_t::string_ascii ||
					  config.value_type == value_type_t::string_utf16);
	bool is_bytearray = (config.value_type == value_type_t::byte_array);
	bool is_unknown = (config.scan_mode == scan_mode_t::unknown_initial);

	if (is_string || is_bytearray)
		val_sz = target_val.size();

	if (is_unknown && val_sz == 0)
		val_sz = (config.value_type == value_type_t::string_utf16) ? 2 : 1;

	size_t align = config.alignment;
	if (is_string || is_bytearray) align = 1;
	if (align == 0) align = 1;

	if (!is_unknown && (val_sz == 0 || target_val.size() < val_sz)) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread invalid_target_val val_sz=%zu got=%zu text='%s'",
			val_sz, target_val.size(), config.value_text.c_str());
		throw std::runtime_error("The initial memory scan value is invalid for the selected type");
	}
	if (config.scan_mode == scan_mode_t::value_between && target_val2.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread invalid_value2 val_sz=%zu got=%zu text2='%s'",
			val_sz, target_val2.size(), config.value_text2.c_str());
		throw std::runtime_error("The initial memory scan upper value is invalid for the selected type");
	}

	std::vector<scan_result_t> all_results;
	std::mutex results_mtx;
	std::atomic<size_t> read_failures{0};
	std::atomic<size_t> read_successes{0};
	std::atomic<size_t> matched_regions{0};
	std::atomic<size_t> worker_exceptions{0};

	size_t total_bytes = 0;
	for (const auto& r : scan_regions) total_bytes += r.size;
	std::atomic<size_t> bytes_done{0};

	auto scan_region = [&](const driver_bridge::memory_region_t& region) {
		if (!owns_scan(operation) || !st.scanning.load(std::memory_order_acquire) ||
			!target_binding_current(target_pid, target_epoch)) {
			if (owns_scan(operation))
				st.scanning.store(false, std::memory_order_release);
			return;
		}
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory_for(target_pid, region.base, static_cast<size_t>(region.size), buf) ||
			buf.size() != static_cast<size_t>(region.size)) {
			size_t failures = read_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
			if (failures <= 16 || (failures % 256) == 0) {
				diag::log_tagged_fmt("mem_scanner",
					"first_scan_thread read_failed base=0x%llX size=0x%llX failures=%zu",
					static_cast<unsigned long long>(region.base),
					static_cast<unsigned long long>(region.size),
					failures);
			}
			return;
		}
		read_successes.fetch_add(1, std::memory_order_acq_rel);

		std::vector<scan_result_t> local;
		local.reserve(256);

		size_t end = buf.size();
		if (!is_unknown && val_sz > 0 && end >= val_sz)
			end = end - val_sz + 1;

		for (size_t i = 0; i < end; i += align) {
			if ((i & 0xFFFF) == 0 &&
				(!owns_scan(operation) || !st.scanning.load())) break;
			bool match = false;

			if (is_unknown) {
				match = true;
			} else if (config.scan_mode == scan_mode_t::exact) {
				match = compare_exact(buf.data() + i, target_val.data(), val_sz);
			} else if (config.scan_mode == scan_mode_t::value_between && !target_val2.empty()) {
				switch (config.value_type) {
					case value_type_t::byte_val:    match = compare_between<uint8_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int16_val:   match = compare_between<int16_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int32_val:   match = compare_between<int32_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int64_val:   match = compare_between<int64_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::float_val:   match = compare_between<float>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::double_val:  match = compare_between<double>(buf.data()+i, target_val.data(), target_val2.data()); break;
					default: break;
				}
			} else {
				switch (config.scan_mode) {
					case scan_mode_t::bigger_than:
						switch (config.value_type) {
							case value_type_t::byte_val:    match = compare_bigger<uint8_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int16_val:   match = compare_bigger<int16_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int32_val:   match = compare_bigger<int32_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int64_val:   match = compare_bigger<int64_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::float_val:   match = compare_bigger<float>(buf.data()+i, target_val.data()); break;
							case value_type_t::double_val:  match = compare_bigger<double>(buf.data()+i, target_val.data()); break;
							default: break;
						}
						break;
					case scan_mode_t::smaller_than:
						switch (config.value_type) {
							case value_type_t::byte_val:    match = compare_smaller<uint8_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int16_val:   match = compare_smaller<int16_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int32_val:   match = compare_smaller<int32_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int64_val:   match = compare_smaller<int64_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::float_val:   match = compare_smaller<float>(buf.data()+i, target_val.data()); break;
							case value_type_t::double_val:  match = compare_smaller<double>(buf.data()+i, target_val.data()); break;
							default: break;
						}
						break;
					default: break;
				}
			}

			if (match) {
				scan_result_t res;
				res.address = region.base + i;
				size_t copy_sz = val_sz;
				if (i + copy_sz <= buf.size())
					res.current_value.assign(buf.data() + i, buf.data() + i + copy_sz);
				local.push_back(std::move(res));

				if (local.size() >= 2000000) break;
			}
		}

		if (!local.empty()) {
			size_t matched = matched_regions.fetch_add(1, std::memory_order_acq_rel) + 1;
			if (matched <= 16) {
				diag::log_tagged_fmt("mem_scanner",
					"first_scan_thread matched_region base=0x%llX size=0x%llX local_hits=%zu",
					static_cast<unsigned long long>(region.base),
					static_cast<unsigned long long>(region.size),
					local.size());
			}
			std::lock_guard<std::mutex> lk(results_mtx);
			all_results.insert(all_results.end(),
				std::make_move_iterator(local.begin()),
				std::make_move_iterator(local.end()));
		}
		bytes_done.fetch_add(static_cast<size_t>(region.size));
		if (total_bytes > 0) {
			const float progress = static_cast<float>(bytes_done.load()) / static_cast<float>(total_bytes);
			st.scan_progress.store(progress);
			publish_scan_progress(operation, progress, "Scanning memory regions");
		}
	};


	char full_test_env[8] = {};
	const DWORD full_test_env_len = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", full_test_env, static_cast<DWORD>(sizeof(full_test_env)));
	const bool full_test_running = full_test_env_len > 0 &&
		(full_test_env[0] == '1' || full_test_env[0] == 't' || full_test_env[0] == 'T' || full_test_env[0] == 'y' || full_test_env[0] == 'Y');
	const std::size_t scanner_wg_size = mcp_standalone::downstream::governor_t::instance().quotas().scanner_worker_group_size;
	const int worker_count = full_test_running ? 0 : static_cast<int>(scanner_wg_size);
	if (full_test_running) {
		diag::log_tagged_fmt("mem_scanner",
			"first_scan_thread full_test_inline_workers regions=%zu bytes=%zu",
			scan_regions.size(),
			total_bytes);
	}
	mcp_standalone::downstream::producer_identity_t scan_id;
	scan_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	scan_id.tool_name = "first_scan";
	mcp_standalone::downstream::scoped_admission_t scan_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(scan_id);
	if (!scan_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(scan_id);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-REJECT first_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		throw std::runtime_error("The scanner worker-group capacity limit rejected the initial scan");
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-ADMIT first_scan token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(scan_admission.token()), scanner_wg_size);
	std::atomic<size_t> next_region{0};
	std::vector<aida::infra::taskflow_runtime::job_handle_t> workers;
	const int actual_workers = static_cast<int>((std::min<size_t>)(static_cast<size_t>(worker_count), scan_regions.size()));
	try {
		workers.reserve(static_cast<size_t>(actual_workers));
		for (int w = 0; w < actual_workers; ++w) {
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "mem_scan.fs.%d", w);
			aida::infra::taskflow_runtime::task_descriptor_t worker_desc;
			worker_desc.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
			worker_desc.owner_subsystem = "mem_scanner";
			worker_desc.label = tname;
			worker_desc.priority = 3;
			worker_desc.shutdown_policy = "cancel_pending";
			worker_desc.cancellable_body = [&](const aida::infra::taskflow_runtime::cancellation_token_t& job_token) {
				for (;;) {
					size_t idx = next_region.fetch_add(1);
					if (idx >= scan_regions.size()) break;
					if (!owns_scan(operation) || !st.scanning.load() ||
						job_token.requested.load(std::memory_order_acquire)) break;
					try {
						scan_region(scan_regions[idx]);
					} catch (...) {
						worker_exceptions.fetch_add(1, std::memory_order_acq_rel);
						read_failures.fetch_add(1, std::memory_order_acq_rel);
					}
				}
			};
			auto worker_submission = aida::infra::taskflow_runtime::submit(std::move(worker_desc));
			if (worker_submission.submitted)
				workers.push_back(worker_submission.handle);
			else
				diag::log_tagged_fmt("mem_scanner", "first_scan_thread worker_start_failed w=%d err='%s'", w,
					worker_submission.reject_reason.empty() ? "<none>" : worker_submission.reject_reason.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread local_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("mem_scanner", "first_scan_thread local_worker_create_failed err='<unknown>'");
	}
	if (workers.empty()) {
		for (size_t idx = 0; idx < scan_regions.size(); ++idx) {
			if (!owns_scan(operation) || !st.scanning.load()) break;
			scan_region(scan_regions[idx]);
		}
	} else {
		for (auto& worker : workers) {
			aida::infra::taskflow_runtime::wait_for(worker, 0xFFFFFFFFu);
		}
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-RELEASE first_scan token=%llu reason=completed",
		static_cast<unsigned long long>(scan_admission.token()));
	scan_admission.release("completed");
	if (!owns_scan(operation) ||
		operation->cancellation_requested.load(std::memory_order_acquire))
		return;
	if (worker_exceptions.load(std::memory_order_acquire) != 0)
		throw std::runtime_error("One or more initial memory scan workers failed");


	std::sort(all_results.begin(), all_results.end(),
		[](const scan_result_t& a, const scan_result_t& b) { return a.address < b.address; });


	constexpr size_t MAX_RESULTS = 5000000;
	size_t total = all_results.size();
	if (all_results.size() > MAX_RESULTS) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread result_truncated raw=%zu kept=%zu",
			total, static_cast<size_t>(MAX_RESULTS));
		all_results.resize(MAX_RESULTS);
	}

	annotate_modules(all_results);

	if (!target_binding_current(target_pid, target_epoch) ||
		!validate_attached_identity(target_identity, "first_scan_publish")) {
		if (operation->cancellation_requested.load(std::memory_order_acquire))
			return;
		throw std::runtime_error("The attached target changed before initial scan results could be published");
	}
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results = std::move(all_results);
		st.total_found = total;
		st.has_initial_scan = true;
		st.scan_count = 1;
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("mem_scanner", "first_scan_thread done regions=%zu bytes=%zu hits=%zu duration_ms=%llu read_ok=%zu read_failed=%zu matched_regions=%zu",
		scan_regions.size(),
		total_bytes,
		total,
		static_cast<unsigned long long>(dur_ms),
		read_successes.load(std::memory_order_acquire),
		read_failures.load(std::memory_order_acquire),
		matched_regions.load(std::memory_order_acquire));

	st.scan_progress.store(1.f);
}


static void next_scan_thread(scan_mode_t mode, std::string value_text, std::string value_text2,
	const std::shared_ptr<scan_operation_t>& operation) {
	auto& st = g_state;
	st.scan_progress.store(0.f);
	auto t_start = std::chrono::steady_clock::now();

	std::vector<scan_result_t> prev;
	value_type_t vtype;
	bool hex_input;
	uint32_t target_pid = 0;
	uint64_t target_epoch = 0;
	live_target_identity_t target_identity;
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		prev = st.results;
		vtype = st.config.value_type;
		hex_input = st.config.hex_input;
		target_pid = st.scan_target_pid;
		target_epoch = st.scan_target_epoch;
		target_identity = st.scan_target_identity;
	}
	if (!target_binding_current(target_pid, target_epoch) ||
		!validate_attached_identity(target_identity, "next_scan_thread_start")) {
		throw std::runtime_error("The attached target changed before the refinement scan started");
	}

	diag::log_tagged_fmt("mem_scanner", "next_scan_thread enter mode=%s prev_count=%zu val='%s' val2='%s' vtype=%s",
		scan_mode_name(mode), prev.size(), value_text.c_str(), value_text2.c_str(), value_type_name(vtype));

	if (prev.empty()) {
		diag::log_tagged("mem_scanner", "next_scan_thread no_prev_results");
		throw std::runtime_error("The refinement scan has no previous results");
	}

	size_t val_sz = value_type_size(vtype);
	std::vector<uint8_t> target_val;
	std::vector<uint8_t> target_val2_bytes;

	bool needs_value = (mode == scan_mode_t::exact || mode == scan_mode_t::bigger_than ||
						mode == scan_mode_t::smaller_than || mode == scan_mode_t::value_between);
	if (needs_value)
		target_val = parse_value(value_text, vtype, hex_input);
	if (mode == scan_mode_t::value_between)
		target_val2_bytes = parse_value(value_text2, vtype, hex_input);

	bool is_varlen = (vtype == value_type_t::string_ascii ||
					  vtype == value_type_t::string_utf16 ||
					  vtype == value_type_t::byte_array);
	if (is_varlen) {
		if (needs_value && !target_val.empty())
			val_sz = target_val.size();
		else if (!prev.empty() && !prev[0].current_value.empty())
			val_sz = prev[0].current_value.size();
	}

	if (val_sz == 0) {
		diag::log_tagged("mem_scanner", "next_scan_thread val_sz_zero");
		throw std::runtime_error("The refinement scan value type has zero width");
	}
	if (needs_value && target_val.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "next_scan_thread invalid_value val_sz=%zu got=%zu",
			val_sz, target_val.size());
		throw std::runtime_error("The refinement scan value is invalid for the selected type");
	}
	if (mode == scan_mode_t::value_between && target_val2_bytes.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "next_scan_thread invalid_value2 val_sz=%zu got=%zu",
			val_sz, target_val2_bytes.size());
		throw std::runtime_error("The refinement scan upper value is invalid for the selected type");
	}

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.scan_history.push_back(prev);
		if (st.scan_history.size() > 10)
			st.scan_history.erase(st.scan_history.begin());
	}

	std::vector<scan_result_t> new_results;
	new_results.reserve(prev.size());

	for (size_t i = 0; i < prev.size(); ++i) {
		if (!owns_scan(operation) || !st.scanning.load() ||
			!target_binding_current(target_pid, target_epoch)) {
			if (owns_scan(operation))
				st.scanning.store(false, std::memory_order_release);
			break;
		}

		auto& pr = prev[i];
		std::vector<uint8_t> cur_bytes;
		if (!driver_bridge::read_memory(pr.address, val_sz, cur_bytes))
			continue;
		if (cur_bytes.size() < val_sz)
			continue;

		bool match = false;
		switch (mode) {
			case scan_mode_t::exact:
				if (target_val.size() >= val_sz)
					match = compare_exact(cur_bytes.data(), target_val.data(), val_sz);
				break;
			case scan_mode_t::bigger_than:
				if (target_val.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_bigger<uint8_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int16_val:   match = compare_bigger<int16_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int32_val:   match = compare_bigger<int32_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int64_val:   match = compare_bigger<int64_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::float_val:   match = compare_bigger<float>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::double_val:  match = compare_bigger<double>(cur_bytes.data(), target_val.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::smaller_than:
				if (target_val.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_smaller<uint8_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int16_val:   match = compare_smaller<int16_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int32_val:   match = compare_smaller<int32_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int64_val:   match = compare_smaller<int64_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::float_val:   match = compare_smaller<float>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::double_val:  match = compare_smaller<double>(cur_bytes.data(), target_val.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::value_between:
				if (target_val.size() >= val_sz && target_val2_bytes.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_between<uint8_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int16_val:   match = compare_between<int16_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int32_val:   match = compare_between<int32_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int64_val:   match = compare_between<int64_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::float_val:   match = compare_between<float>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::double_val:  match = compare_between<double>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::changed:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_changed<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_changed<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_changed<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_changed<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_changed<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_changed<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: match = !compare_exact(cur_bytes.data(), pr.current_value.data(), val_sz); break;
					}
				}
				break;
			case scan_mode_t::unchanged:
				if (pr.current_value.size() >= val_sz)
					match = compare_exact(cur_bytes.data(), pr.current_value.data(), val_sz);
				break;
			case scan_mode_t::increased:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_increased<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_increased<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_increased<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_increased<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_increased<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_increased<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::decreased:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_decreased<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_decreased<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_decreased<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_decreased<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_decreased<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_decreased<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: break;
					}
				}
				break;
			default: break;
		}

		if (match) {
			scan_result_t res;
			res.address = pr.address;
			res.current_value = std::move(cur_bytes);
			res.previous_value = pr.current_value;
			res.module_name = pr.module_name;
			res.module_offset = pr.module_offset;
			new_results.push_back(std::move(res));
		}

		if ((i % 1024) == 0) {
			const float progress = static_cast<float>(i) / static_cast<float>(prev.size());
			st.scan_progress.store(progress);
			publish_scan_progress(operation, progress, "Refining scan results");
		}
	}
	if (operation->cancellation_requested.load(std::memory_order_acquire))
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		if (!st.scan_history.empty())
			st.scan_history.pop_back();
		return;
	}

	size_t hits = new_results.size();
	const bool publish_current = target_binding_current(target_pid, target_epoch) &&
		validate_attached_identity(target_identity, "next_scan_publish");
	if (!publish_current)
		throw std::runtime_error("The attached target changed before refinement results could be published");
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		if (publish_current) {
			st.total_found = hits;
			st.results = std::move(new_results);
			st.scan_count++;
		} else if (!st.scan_history.empty()) {
			st.scan_history.pop_back();
			hits = st.results.size();
		}
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("mem_scanner", "next_scan_thread done prev=%zu hits=%zu duration_ms=%llu scan_count=%d",
		prev.size(), hits, static_cast<unsigned long long>(dur_ms), g_state.scan_count);

	st.scan_progress.store(1.f);
}


static bool wait_scan_worker_ready(const char* op) {
	auto& st = g_state;
	const ULONGLONG start = GetTickCount64();
	for (;;) {
		if (st.scan_thread_done.load(std::memory_order_acquire))
			return true;
		if (!st.scanning.load(std::memory_order_acquire)) {
			st.scan_thread_done.store(true, std::memory_order_release);
			diag::log_tagged_fmt("mem_scanner",
				"%s recovered stale scan_thread_done=0 scanning=0 elapsed_ms=%llu",
				op ? op : "scan",
				static_cast<unsigned long long>(GetTickCount64() - start));
			return true;
		}
		if (GetTickCount64() - start >= 5000) {
			diag::log_tagged_fmt("mem_scanner",
				"%s refused previous_worker_busy elapsed_ms=%llu progress=%.3f",
				op ? op : "scan",
				static_cast<unsigned long long>(GetTickCount64() - start),
				static_cast<double>(st.scan_progress.load(std::memory_order_acquire)));
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

static void freeze_loop() {
	auto& st = g_state;
	diag::log_tagged("mem_scanner", "freeze_loop start");
	struct frozen_write_t {
		uint64_t address = 0;
		std::vector<uint8_t> bytes;
		uint32_t pid = 0;
		uint64_t epoch = 0;
		live_target_identity_t identity;
	};
	std::vector<frozen_write_t> snapshot;
	uint64_t last_logged_count = static_cast<uint64_t>(-1);
	auto last_log_time = std::chrono::steady_clock::now();
	while (st.freeze_active.load()) {
		snapshot.clear();
		{
			std::lock_guard<std::mutex> lk(st.address_mutex);
			for (auto& entry : st.address_list) {
				if (entry.frozen && !entry.freeze_value.empty())
					snapshot.push_back({entry.address, entry.freeze_value,
						entry.target_pid, entry.target_epoch, entry.target_identity});
			}
		}
		auto now = std::chrono::steady_clock::now();
		uint64_t count = snapshot.size();
		bool count_changed = (count != last_logged_count);
		bool throttle_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_log_time).count() >= 30;
		if (count_changed || (count > 0 && throttle_elapsed)) {
			diag::log_tagged_fmt("mem_scanner", "freeze_loop tick count=%llu",
				static_cast<unsigned long long>(count));
			last_logged_count = count;
			last_log_time = now;
		}
		for (auto& p : snapshot) {
			if (!st.freeze_active.load()) break;
			std::unique_lock<std::mutex> entry_lock(st.address_mutex);
			auto entry = std::find_if(st.address_list.begin(), st.address_list.end(),
				[&](const address_entry_t& candidate) {
					return candidate.address == p.address && candidate.target_pid == p.pid &&
						candidate.target_epoch == p.epoch && candidate.frozen &&
						candidate.freeze_value == p.bytes &&
						same_target_identity(candidate.target_identity, p.identity);
				});
			if (entry == st.address_list.end()) continue;
			auto disable_entry = [&]() { entry->frozen = false; };
			if (!transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_before_original_read")) {
				disable_entry();
				continue;
			}
			std::vector<uint8_t> before;
			const bool original_read = driver_bridge::read_memory(p.address, p.bytes.size(), before);
			if (!transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_after_original_read") || !original_read ||
				before.size() != p.bytes.size()) {
				disable_entry();
				continue;
			}
			if (!transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_before_write")) {
				disable_entry();
				continue;
			}
			const bool write_ok = driver_bridge::write_memory(p.address, p.bytes);
			const bool identity_after_write = transaction_target_current(p.pid, p.epoch,
				p.identity, "freeze_after_write");
			std::vector<uint8_t> readback;
			bool verified = false;
			if (write_ok && identity_after_write &&
				transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_before_verify_read")) {
				const bool verify_read = driver_bridge::read_memory(p.address, p.bytes.size(), readback);
				verified = transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_after_verify_read") && verify_read && readback == p.bytes;
			}
			if (verified) continue;
			bool rollback_verified = false;
			if (transaction_target_current(p.pid, p.epoch, p.identity,
					"freeze_before_rollback_write")) {
				const bool rollback_write = driver_bridge::write_memory(p.address, before);
				const bool identity_after_rollback_write = transaction_target_current(p.pid,
					p.epoch, p.identity, "freeze_after_rollback_write");
				if (rollback_write && identity_after_rollback_write &&
					transaction_target_current(p.pid, p.epoch, p.identity,
						"freeze_before_rollback_read")) {
					std::vector<uint8_t> rollback_readback;
					const bool rollback_read = driver_bridge::read_memory(p.address,
						before.size(), rollback_readback);
					rollback_verified = transaction_target_current(p.pid, p.epoch, p.identity,
						"freeze_after_rollback_read") && rollback_read &&
						rollback_readback == before;
				}
			}
			diag::log_tagged_fmt("mem_scanner",
				"freeze_transaction_failed addr=0x%llX write_ok=%d identity_after_write=%d rollback_verified=%d",
				static_cast<unsigned long long>(p.address), static_cast<int>(write_ok),
				static_cast<int>(identity_after_write), static_cast<int>(rollback_verified));
			disable_entry();
		}
		std::unique_lock<std::mutex> wait_lock(st.freeze_wait_mutex);
		st.freeze_wait_cv.wait_for(wait_lock,
			std::chrono::milliseconds(snapshot.empty() ? 100 : 10),
			[&st]() { return !st.freeze_active.load(std::memory_order_acquire); });
	}
	diag::log_tagged("mem_scanner", "freeze_loop stop");
}


struct pointer_entry_t {
	uint64_t address = 0;
	uint64_t value = 0;
	bool     is_static = false;
	std::string module_name;
	uint64_t module_offset = 0;
};

static bool address_in_modules(uint64_t addr,
                               const std::vector<driver_bridge::module_info_t>& modules,
                               std::string& out_name, uint64_t& out_offset) {
	for (const auto& m : modules) {
		if (addr >= m.base && addr < m.base + m.size) {
			out_name = m.name;
			out_offset = addr - m.base;
			return true;
		}
	}
	return false;
}

static void pointer_dfs(const std::multimap<uint64_t, pointer_entry_t>& reverse_map,
                        uint64_t value_to_find,
                        int level,
                        int max_depth,
                        int64_t max_offset,
                        std::vector<int64_t>& current_offsets,
                        std::vector<uint64_t>& visited,
                        std::vector<pointer_result_t>& results,
                        std::mutex& results_mutex,
                        const std::atomic<bool>& cancel,
                        size_t max_results) {
	if (cancel.load()) return;
	if (level >= max_depth) return;

	{
		std::lock_guard<std::mutex> lk(results_mutex);
		if (results.size() >= max_results) return;
	}

	for (auto v : visited) {
		if (v == value_to_find) return;
	}
	visited.push_back(value_to_find);

	uint64_t lo = (value_to_find > static_cast<uint64_t>(max_offset))
	              ? (value_to_find - static_cast<uint64_t>(max_offset)) : 0;
	uint64_t hi = value_to_find + static_cast<uint64_t>(max_offset);

	auto it_low = reverse_map.lower_bound(lo);
	auto it_high = reverse_map.upper_bound(hi);

	for (auto it = it_low; it != it_high; ++it) {
		if (cancel.load()) break;

		uint64_t pointer_value = it->first;
		int64_t offset = static_cast<int64_t>(value_to_find) - static_cast<int64_t>(pointer_value);
		if (offset < -max_offset || offset > max_offset) continue;

		const pointer_entry_t& pe = it->second;

		{
			std::lock_guard<std::mutex> lk(results_mutex);
			if (results.size() >= max_results) {
				visited.pop_back();
				return;
			}
		}

		current_offsets.push_back(offset);

		if (pe.is_static) {
			pointer_result_t chain;
			chain.base_address = pe.address;
			chain.module_name = pe.module_name;
			chain.module_offset = pe.module_offset;
			chain.offsets.assign(current_offsets.rbegin(), current_offsets.rend());

			std::lock_guard<std::mutex> lk(results_mutex);
			if (results.size() < max_results)
				results.push_back(std::move(chain));
		}

		if (level + 1 < max_depth) {
			pointer_dfs(reverse_map, pe.address, level + 1, max_depth, max_offset,
			            current_offsets, visited, results, results_mutex, cancel, max_results);
		}

		current_offsets.pop_back();
	}

	visited.pop_back();
}

static void pointer_scan_thread(uint64_t target_address, int max_depth, int max_offset, uint64_t scan_base, uint64_t scan_size) {
	auto& st = g_state;
	st.pointer_progress.store(0.f);
	auto t_start = std::chrono::steady_clock::now();
	uint32_t target_pid = 0;
	uint64_t target_epoch = 0;
	live_target_identity_t target_identity;
	{
		std::lock_guard<std::mutex> lock(st.pointer_mutex);
		target_pid = st.pointer_target_pid;
		target_epoch = st.pointer_target_epoch;
		target_identity = st.pointer_target_identity;
	}
	if (!target_binding_current(target_pid, target_epoch) ||
		!validate_attached_identity(target_identity, "pointer_scan_thread_start")) {
		st.pointer_progress.store(1.f, std::memory_order_release);
		st.pointer_scanning.store(false, std::memory_order_release);
		return;
	}

	auto modules = driver_bridge::enumerate_modules();
	auto regions = driver_bridge::enumerate_memory_regions_for(target_pid, 4096);

	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread enter target=0x%llX max_depth=%d max_offset=0x%X scan_range=0x%llX+0x%llX modules=%zu regions=%zu",
		static_cast<unsigned long long>(target_address), max_depth, max_offset,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size),
		modules.size(), regions.size());

	if (max_depth < 1) max_depth = 4;
	if (max_depth > 7) max_depth = 7;
	if (max_offset < 0) max_offset = 0x1000;
	if (max_offset > 0x10000) max_offset = 0x10000;

	const bool has_scan_range = scan_base != 0 && scan_size != 0;
	const uint64_t max_u64 = (std::numeric_limits<uint64_t>::max)();
	const uint64_t scan_end = has_scan_range
		? (max_u64 - scan_base < scan_size ? max_u64 : scan_base + scan_size)
		: 0;
	size_t skipped_state = 0;
	size_t skipped_guard = 0;
	size_t skipped_protect = 0;
	size_t skipped_size = 0;
	size_t skipped_range = 0;
	std::vector<driver_bridge::memory_region_t> scan_regions;
	for (const auto& r : regions) {
		if (r.state != 0x1000) { ++skipped_state; continue; }
		if (r.protect & 0x100) { ++skipped_guard; continue; }
		uint32_t protect_flags = r.protect & 0xFF;
		if (protect_flags == 0x01 || protect_flags == 0x00) { ++skipped_protect; continue; }
		if (r.size > 0x10000000) { ++skipped_size; continue; }
		driver_bridge::memory_region_t selected = r;
		if (has_scan_range) {
			const uint64_t region_end = max_u64 - r.base < r.size ? max_u64 : r.base + r.size;
			const uint64_t clipped_start = (std::max)(r.base, scan_base);
			const uint64_t clipped_end = (std::min)(region_end, scan_end);
			if (clipped_start >= clipped_end) { ++skipped_range; continue; }
			selected.base = clipped_start;
			selected.size = clipped_end - clipped_start;
		}
		scan_regions.push_back(selected);
	}
	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread region_filter raw=%zu selected=%zu skipped_state=%zu skipped_guard=%zu skipped_protect=%zu skipped_size=%zu skipped_range=%zu",
		regions.size(),
		scan_regions.size(),
		skipped_state,
		skipped_guard,
		skipped_protect,
		skipped_size,
		skipped_range);

	const std::size_t ptr_wg_size = mcp_standalone::downstream::governor_t::instance().quotas().scanner_worker_group_size;
	const int ptr_worker_count = static_cast<int>(ptr_wg_size);
	std::vector<std::multimap<uint64_t, pointer_entry_t>> partial_maps(static_cast<size_t>(ptr_worker_count));
	std::atomic<size_t> region_idx{0};
	std::atomic<uint64_t> bytes_scanned{0};
	uint64_t total_bytes = 0;
	for (const auto& r : scan_regions) total_bytes += r.size;
	if (total_bytes == 0) total_bytes = 1;

	auto scan_pointer_worker = [&](int w) {
			auto& local_map = partial_maps[static_cast<size_t>(w)];
			size_t idx;
			while ((idx = region_idx.fetch_add(1)) < scan_regions.size()) {
				if (!st.pointer_scanning.load()) break;

				const auto& region = scan_regions[idx];
				const size_t chunk_size = 65536;
				for (uint64_t off = 0; off < region.size; off += chunk_size) {
					if (!st.pointer_scanning.load()) break;
					size_t read_sz = chunk_size;
					if (off + read_sz > region.size)
						read_sz = static_cast<size_t>(region.size - off);

					std::vector<uint8_t> buf;
					if (!driver_bridge::read_memory_for(target_pid, region.base + off, read_sz, buf) ||
						buf.size() != read_sz) {
						bytes_scanned.fetch_add(read_sz);
						st.pointer_progress.store(
							static_cast<float>(bytes_scanned.load()) / static_cast<float>(total_bytes) * 0.5f);
						continue;
					}

					for (size_t i = 0; i + 8 <= buf.size(); i += 8) {
						uint64_t value = 0;
						std::memcpy(&value, buf.data() + i, 8);
						if (value < 0x10000 || value > 0x00007FFFFFFFFFFFULL) continue;

						bool valid = false;
						for (const auto& r2 : scan_regions) {
							if (value >= r2.base && value < r2.base + r2.size) {
								valid = true;
								break;
							}
						}
						if (!valid) {
							const uint64_t lo = (target_address > static_cast<uint64_t>(max_offset))
								? (target_address - static_cast<uint64_t>(max_offset)) : 0;
							const uint64_t hi = max_u64 - target_address < static_cast<uint64_t>(max_offset)
								? max_u64 : target_address + static_cast<uint64_t>(max_offset);
							valid = value >= lo && value <= hi;
						}
						if (!valid) continue;

						pointer_entry_t pe;
						pe.address = region.base + off + i;
						pe.value = value;
						pe.is_static = address_in_modules(pe.address, modules, pe.module_name, pe.module_offset);
						local_map.emplace(value, std::move(pe));
					}

					bytes_scanned.fetch_add(read_sz);
				st.pointer_progress.store(
					static_cast<float>(bytes_scanned.load()) / static_cast<float>(total_bytes) * 0.5f);
			}
		}
	};
	mcp_standalone::downstream::producer_identity_t ptr_id;
	ptr_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ptr_id.tool_name = "pointer_scan_map";
	mcp_standalone::downstream::scoped_admission_t ptr_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ptr_id);
	if (!ptr_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ptr_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_map reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_map token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(ptr_admission.token()), ptr_wg_size);
	std::vector<aida::infra::taskflow_runtime::job_handle_t> ptr_workers;
	try {
		ptr_workers.reserve(static_cast<size_t>(ptr_worker_count));
		for (int w = 0; w < ptr_worker_count; ++w) {
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "ptr_scan.map.%d", w);
			aida::infra::taskflow_runtime::task_descriptor_t worker_desc;
			worker_desc.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
			worker_desc.owner_subsystem = "pointer_scan";
			worker_desc.label = tname;
			worker_desc.priority = 3;
			worker_desc.shutdown_policy = "cancel_pending";
			worker_desc.cancellable_body = [&scan_pointer_worker, w](const aida::infra::taskflow_runtime::cancellation_token_t&) {
				scan_pointer_worker(w);
			};
			auto worker_submission = aida::infra::taskflow_runtime::submit(std::move(worker_desc));
			if (worker_submission.submitted)
				ptr_workers.push_back(worker_submission.handle);
			else
				diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_worker_start_failed w=%d err='%s'", w,
					worker_submission.reject_reason.empty() ? "<none>" : worker_submission.reject_reason.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("pointer_scan", "pointer_scan_thread map_worker_create_failed err='<unknown>'");
	}
	if (ptr_workers.empty()) {
		for (int w = 0; w < ptr_worker_count; ++w)
			scan_pointer_worker(w);
	} else {
		for (auto& worker : ptr_workers) {
			aida::infra::taskflow_runtime::wait_for(worker, 0xFFFFFFFFu);
		}
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_map token=%llu reason=completed",
		static_cast<unsigned long long>(ptr_admission.token()));
	ptr_admission.release("completed");

	if (!st.pointer_scanning.load()) {
		st.pointer_progress.store(1.f);
		return;
	}

	std::multimap<uint64_t, pointer_entry_t> reverse_map;
	for (auto& pm : partial_maps) {
		for (auto& kv : pm)
			reverse_map.emplace(kv.first, std::move(kv.second));
		pm.clear();
	}

	st.pointer_progress.store(0.5f);

	std::vector<pointer_result_t> results;
	std::mutex result_mtx;
	constexpr size_t MAX_RESULTS = 10000;

	std::vector<uint64_t> seed_values;
	{
		uint64_t lo = (target_address > static_cast<uint64_t>(max_offset))
		              ? (target_address - static_cast<uint64_t>(max_offset)) : 0;
		uint64_t hi = target_address + static_cast<uint64_t>(max_offset);
		auto it_low = reverse_map.lower_bound(lo);
		auto it_high = reverse_map.upper_bound(hi);
		std::vector<uint64_t> uniq;
		for (auto it = it_low; it != it_high; ++it) {
			if (uniq.empty() || uniq.back() != it->first)
				uniq.push_back(it->first);
		}
		seed_values = std::move(uniq);
	}

	if (seed_values.empty()) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread no_seeds map_entries=%zu",
			reverse_map.size());
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}

	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_built entries=%zu seeds=%zu",
		reverse_map.size(), seed_values.size());

	std::atomic<size_t> seed_idx{0};
	std::atomic<bool> dfs_cancel{false};

	auto dfs_worker = [&]() {
			std::vector<int64_t> current_offsets;
			std::vector<uint64_t> visited;
			visited.push_back(target_address);
			while (true) {
				size_t idx = seed_idx.fetch_add(1);
				if (idx >= seed_values.size()) break;
				if (!st.pointer_scanning.load()) {
					dfs_cancel.store(true);
					break;
				}

				{
					std::lock_guard<std::mutex> lk(result_mtx);
					if (results.size() >= MAX_RESULTS) {
						dfs_cancel.store(true);
						break;
					}
				}

				uint64_t seed_val = seed_values[idx];
				int64_t offset = static_cast<int64_t>(target_address) - static_cast<int64_t>(seed_val);
				if (offset < -max_offset || offset > max_offset) continue;

				auto range = reverse_map.equal_range(seed_val);
				for (auto it = range.first; it != range.second; ++it) {
					if (!st.pointer_scanning.load() || dfs_cancel.load()) break;
					{
						std::lock_guard<std::mutex> lk(result_mtx);
						if (results.size() >= MAX_RESULTS) {
							dfs_cancel.store(true);
							break;
						}
					}

					const pointer_entry_t& pe = it->second;
					current_offsets.clear();
					current_offsets.push_back(offset);

					{
						pointer_result_t chain;
						chain.base_address = pe.address;
						chain.module_name = pe.module_name;
						chain.module_offset = pe.module_offset;
						chain.offsets.assign(current_offsets.rbegin(), current_offsets.rend());
						std::lock_guard<std::mutex> lk(result_mtx);
						if (results.size() < MAX_RESULTS)
							results.push_back(std::move(chain));
					}

					if (max_depth > 1) {
						pointer_dfs(reverse_map, pe.address, 1, max_depth, max_offset,
						            current_offsets, visited, results, result_mtx,
						            dfs_cancel, MAX_RESULTS);
					}
				}

			st.pointer_progress.store(
				0.5f + (static_cast<float>(idx + 1) / static_cast<float>(seed_values.size())) * 0.5f);
		}
	};
	mcp_standalone::downstream::producer_identity_t dfs_id;
	dfs_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	dfs_id.tool_name = "pointer_scan_dfs";
	mcp_standalone::downstream::scoped_admission_t dfs_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(dfs_id);
	if (!dfs_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(dfs_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_dfs reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_dfs token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(dfs_admission.token()), ptr_wg_size);
	std::vector<aida::infra::taskflow_runtime::job_handle_t> dfs_workers;
	try {
		dfs_workers.reserve(static_cast<size_t>(ptr_worker_count));
		for (int w = 0; w < ptr_worker_count; ++w) {
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "ptr_scan.dfs.%d", w);
			aida::infra::taskflow_runtime::task_descriptor_t worker_desc;
			worker_desc.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
			worker_desc.owner_subsystem = "pointer_scan";
			worker_desc.label = tname;
			worker_desc.priority = 3;
			worker_desc.shutdown_policy = "cancel_pending";
			worker_desc.cancellable_body = [&dfs_worker](const aida::infra::taskflow_runtime::cancellation_token_t&) {
				dfs_worker();
			};
			auto worker_submission = aida::infra::taskflow_runtime::submit(std::move(worker_desc));
			if (worker_submission.submitted)
				dfs_workers.push_back(worker_submission.handle);
			else
				diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread dfs_worker_start_failed w=%d err='%s'", w,
					worker_submission.reject_reason.empty() ? "<none>" : worker_submission.reject_reason.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread dfs_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("pointer_scan", "pointer_scan_thread dfs_worker_create_failed err='<unknown>'");
	}
	if (dfs_workers.empty()) {
		dfs_worker();
	} else {
		for (auto& worker : dfs_workers) {
			aida::infra::taskflow_runtime::wait_for(worker, 0xFFFFFFFFu);
		}
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_dfs token=%llu reason=completed",
		static_cast<unsigned long long>(dfs_admission.token()));
	dfs_admission.release("completed");

	std::sort(results.begin(), results.end(),
		[](const pointer_result_t& a, const pointer_result_t& b) {
			if (!a.module_name.empty() && b.module_name.empty()) return true;
			if (a.module_name.empty() && !b.module_name.empty()) return false;
			if (a.offsets.size() != b.offsets.size())
				return a.offsets.size() < b.offsets.size();
			return a.base_address < b.base_address;
		});

	if (results.size() > MAX_RESULTS)
		results.resize(MAX_RESULTS);

	size_t final_count = results.size();
	const bool publish_current = target_binding_current(target_pid, target_epoch) &&
		validate_attached_identity(target_identity, "pointer_scan_publish");
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		if (publish_current) st.pointer_results = std::move(results);
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread done chains=%zu duration_ms=%llu cancelled=%d",
		final_count, static_cast<unsigned long long>(dur_ms),
		static_cast<int>(!st.pointer_scanning.load()));

	st.pointer_progress.store(1.f);
	st.pointer_scanning.store(false);
}


void initialize() {
	auto& st = g_state;
	{
		std::lock_guard<std::mutex> lock(g_scan_operation_mutex);
		if (owns_scan(g_active_scan_operation))
			g_active_scan_operation->cancellation_requested.store(true, std::memory_order_release);
	}
	st.scanning.store(false);
	st.pointer_scanning.store(false);
	for (int i = 0; i < 100 && !st.scan_thread_done.load(std::memory_order_acquire); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	for (int i = 0; i < 100 && !st.pointer_thread_done.load(std::memory_order_acquire); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		size_t had = st.results.size();
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		diag::log_tagged_fmt("mem_scanner", "initialize reset_results cleared=%zu", had);
	}
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
	}
	restore_scanner_state_for_current_target();
	if (st.freeze_active.load(std::memory_order_acquire) &&
		!st.freeze_thread_done.load(std::memory_order_acquire)) {
		diag::log_tagged("mem_scanner", "initialize freeze_loop_already_running");
		return;
	}
	st.freeze_active.store(true);
	st.freeze_thread_done.store(false, std::memory_order_release);
	diag::log_tagged("mem_scanner", "initialize posting_freeze_loop");
	mcp_standalone::downstream::producer_identity_t freeze_id;
	freeze_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	freeze_id.tool_name = "freeze_loop";
	mcp_standalone::downstream::scoped_admission_t freeze_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(freeze_id);
	if (!freeze_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(freeze_id);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-REJECT freeze_loop reason=%s quota=%s observed=%zu limit=%zu",
			 rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.freeze_active.store(false, std::memory_order_release);
		st.freeze_thread_done.store(true, std::memory_order_release);
		return;
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-ADMIT freeze_loop token=%llu",
		static_cast<unsigned long long>(freeze_admission.token()));
	aida::infra::executor::submission_t freeze_sub;
	freeze_sub.owner_subsystem = "scanner";
	freeze_sub.label = "scanner.freeze_loop";
	freeze_sub.thread_class = "scanner_freeze_loop";
	freeze_sub.domain = aida::infra::executor::domain_t::long_running;
	freeze_sub.priority = 2;
	freeze_sub.target_pid = driver_bridge::attached_pid();
	freeze_sub.lease_token = freeze_admission.token();
	freeze_sub.body = []() {
			freeze_loop();
			g_state.freeze_thread_done.store(true, std::memory_order_release);
		};
	const auto freeze_submission = aida::infra::executor::submit(std::move(freeze_sub));
	if (!freeze_submission.submitted)
	{
		diag::log_tagged_fmt("mem_scanner", "initialize freeze_loop_post_failed reason=%s",
			freeze_submission.reject_reason.empty() ? "unknown" : freeze_submission.reject_reason.c_str());
		st.freeze_active.store(false, std::memory_order_release);
		st.freeze_thread_done.store(true, std::memory_order_release);
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-RELEASE freeze_loop token=%llu reason=%s",
		static_cast<unsigned long long>(freeze_admission.token()),
		freeze_submission.submitted ? "dispatched" : "submission_rejected");
	freeze_admission.release(freeze_submission.submitted ? "dispatched" : "submission_rejected");
}

void shutdown() {
	const uint64_t started = GetTickCount64();
	diag::log_tagged_fmt("mem_scanner",
		"shutdown enter scanning=%d pointer_scanning=%d freeze_active=%d scan_done=%d pointer_done=%d freeze_done=%d",
		g_state.scanning.load(std::memory_order_acquire) ? 1 : 0,
		g_state.pointer_scanning.load(std::memory_order_acquire) ? 1 : 0,
		g_state.freeze_active.load(std::memory_order_acquire) ? 1 : 0,
		g_state.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
		g_state.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0,
		g_state.freeze_thread_done.load(std::memory_order_acquire) ? 1 : 0);
	persist_scanner_state();
	auto& st = g_state;
	{
		std::lock_guard<std::mutex> lock(g_scan_operation_mutex);
		if (owns_scan(g_active_scan_operation))
			g_active_scan_operation->cancellation_requested.store(true, std::memory_order_release);
	}
	st.scanning.store(false);
	st.pointer_scanning.store(false);
	st.freeze_active.store(false);
	st.freeze_wait_cv.notify_all();
	for (int i = 0; i < 100 && (st.scanning.load() || st.pointer_scanning.load()); ++i)
		Sleep(20);
	auto wait_done = [&](const char* worker, const std::atomic<bool>& done) {
		const uint64_t wait_started = GetTickCount64();
		while (!done.load(std::memory_order_acquire) && GetTickCount64() - wait_started < 10000)
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		diag::log_tagged_fmt("mem_scanner", "shutdown worker=%s drained=%d elapsed_ms=%llu",
			worker, done.load(std::memory_order_acquire) ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - wait_started));
	};
	wait_done("scan", st.scan_thread_done);
	wait_done("pointer", st.pointer_thread_done);
	wait_done("freeze", st.freeze_thread_done);
	diag::log_tagged_fmt("mem_scanner",
		"shutdown done elapsed_ms=%llu scan_done=%d pointer_done=%d freeze_done=%d",
		static_cast<unsigned long long>(GetTickCount64() - started),
		st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
		st.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0,
		st.freeze_thread_done.load(std::memory_order_acquire) ? 1 : 0);
}

bool first_scan(const scan_config_t& config) {
	auto& st = g_state;
	restore_scanner_state_for_current_target();
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "first_scan refused already_scanning");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("mem_scanner", "first_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	const uint32_t target_pid = driver_bridge::attached_pid();
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "first_scan")) return false;
	const uint64_t target_epoch = observe_target_identity(target_identity);
	diag::log_tagged_fmt("mem_scanner", "first_scan start type=%s mode=%s val='%s' val2='%s' hex=%d",
		value_type_name(config.value_type), scan_mode_name(config.scan_mode),
		config.value_text.c_str(), config.value_text2.c_str(),
		static_cast<int>(config.hex_input));

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		st.config = config;
		st.scan_target_pid = target_pid;
		st.scan_target_epoch = target_epoch;
		st.scan_target_identity = target_identity;
		st.scan_static_binary = false;
		st.scan_workspace_id.clear();
		st.scan_workspace_generation = 0;
	}
	persist_scanner_state();

	if (!wait_scan_worker_ready("first_scan"))
		return false;

	st.scanning.store(true);
	st.scan_thread_done.store(false, std::memory_order_release);
	auto operation = begin_scan_operation();
	try {
		mcp_standalone::downstream::producer_identity_t fs_id;
		fs_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
		fs_id.tool_name = "first_scan_dispatch";
		mcp_standalone::downstream::scoped_admission_t fs_admission =
			mcp_standalone::downstream::scoped_admission_t::acquire(fs_id);
		if (!fs_admission.active()) {
			auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(fs_id);
			diag::log_tagged_fmt("mem_scanner",
				"FEATURE-WORKER-GROUP-REJECT first_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
				rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-ADMIT first_scan_dispatch token=%llu",
			static_cast<unsigned long long>(fs_admission.token()));
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "scanner";
		sub.label = "scanner.memory_first_scan";
		sub.thread_class = "scanner_scan";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.target_pid = driver_bridge::attached_pid();
		sub.lease_token = fs_admission.token();
		sub.generation = operation->generation;
		sub.body = [config, operation]() {
			operation->started.store(true, std::memory_order_release);
			publish_scan_progress(operation, 0.0f, "Scanning memory regions");
			try {
				first_scan_thread(config, operation);
				finish_scan_operation(operation,
					operation->cancellation_requested.load(std::memory_order_acquire)
						? scan_terminal_t::cancelled : scan_terminal_t::completed,
					operation->cancellation_requested.load(std::memory_order_acquire)
						? "Initial memory scan cancelled" : "Initial memory scan completed");
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("mem_scanner", "first_scan worker exception err='%s'", ex.what());
				finish_scan_operation(operation, scan_terminal_t::failed, ex.what());
				throw;
			} catch (...) {
				diag::log_tagged("mem_scanner", "first_scan worker exception err='<unknown>'");
				finish_scan_operation(operation, scan_terminal_t::failed,
					"Initial memory scan failed with an unknown error");
				throw;
			}
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("mem_scanner", "first_scan worker_post_failed");
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		operation->executor_task_id.store(submitted.task_id, std::memory_order_release);
		const bool task_registered = scanner_task_center::register_executor_task(submitted,
			"view.memory.value_scan", "memory.first_scan", "Initial memory scan",
			driver_bridge::attached_pid(), true, [operation]() {
				if (!owns_scan(operation))
					return false;
				operation->cancellation_requested.store(true, std::memory_order_release);
				return !g_state.scanning.load(std::memory_order_acquire) || cancel_scan();
			});
		if (!task_registered) {
			diag::log_tagged("mem_scanner", "first_scan task_center_registration_failed");
			operation->cancellation_requested.store(true, std::memory_order_release);
			static_cast<void>(cancel_scan());
			static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
			return false;
		}
		publish_scan_terminal_snapshot(operation);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-RELEASE first_scan_dispatch token=%llu reason=dispatched",
			static_cast<unsigned long long>(fs_admission.token()));
		fs_admission.release("dispatched");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "first_scan worker_create_failed err='%s'", ex.what());
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	} catch (...) {
		diag::log_tagged("mem_scanner", "first_scan worker_create_failed err='<unknown>'");
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	}
	return true;
}

bool first_static_scan(const scan_config_t& config,
	std::shared_ptr<const aida::analysis::byte_provider_t> provider,
	std::shared_ptr<const aida::analysis::pe_image_t> image,
	std::string workspace_id, uint64_t workspace_generation) {
	auto& st = g_state;
	if (!provider || !image || workspace_id.empty() || st.scanning.load(std::memory_order_acquire) ||
		!wait_scan_worker_ready("first_static_scan"))
		return false;
	const auto target = parse_value(config.value_text, config.value_type, config.hex_input);
	const auto target2 = parse_value(config.value_text2, config.value_type, config.hex_input);
	std::size_t value_size = value_type_size(config.value_type);
	if (config.value_type == value_type_t::string_ascii ||
		config.value_type == value_type_t::string_utf16 ||
		config.value_type == value_type_t::byte_array)
		value_size = target.size();
	if (config.scan_mode != scan_mode_t::unknown_initial &&
		(value_size == 0 || target.size() < value_size))
		return false;
	if (config.scan_mode == scan_mode_t::value_between && target2.size() < value_size)
		return false;
	if (config.scan_mode == scan_mode_t::unknown_initial && value_size == 0)
		value_size = config.value_type == value_type_t::string_utf16 ? 2 : 1;
	{
		std::lock_guard<std::mutex> lock(st.results_mutex);
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		st.config = config;
		st.scan_target_pid = 0;
		st.scan_target_epoch = 0;
		st.scan_target_identity = {};
		st.scan_static_binary = true;
		st.scan_workspace_id = workspace_id;
		st.scan_workspace_generation = workspace_generation;
	}
	persist_scanner_state();
	st.scanning.store(true, std::memory_order_release);
	st.scan_progress.store(0.0f, std::memory_order_release);
	st.scan_thread_done.store(false, std::memory_order_release);
	auto operation = begin_scan_operation();
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner";
	submission.label = "scanner.static_binary_value_scan";
	submission.thread_class = "scanner_scan";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.generation = operation->generation;
	submission.body = [config, provider = std::move(provider), image = std::move(image),
		target, target2, value_size, workspace_id = std::move(workspace_id), workspace_generation,
		operation]() {
		operation->started.store(true, std::memory_order_release);
		publish_scan_progress(operation, 0.0f, "Scanning static image sections");
		try {
		std::vector<scan_result_t> results;
		std::uint64_t total_bytes = 0;
		for (const auto& section : image->sections())
			if (section.raw_size != 0 && (!config.writable_only || section.writable) &&
				(!config.executable_exclude || !section.executable)) total_bytes += section.raw_size;
		std::uint64_t completed = 0;
		const std::size_t alignment = (std::max<std::size_t>)(1,
			(config.value_type == value_type_t::string_ascii ||
			 config.value_type == value_type_t::string_utf16 ||
			 config.value_type == value_type_t::byte_array) ? 1 : config.alignment);
		for (const auto& section : image->sections()) {
			if (!owns_scan(operation) || !g_state.scanning.load(std::memory_order_acquire)) break;
			if (section.raw_size == 0 || (config.writable_only && !section.writable) ||
				(config.executable_exclude && section.executable)) continue;
			auto bytes_result = provider->read_vector(section.raw_offset, section.raw_size,
				section.raw_size);
			if (!bytes_result)
				throw std::runtime_error("Static scan could not read section " + section.name);
			const auto& bytes = bytes_result.value();
			const std::size_t end = value_size != 0 && bytes.size() >= value_size
				? bytes.size() - value_size + 1 : 0;
			for (std::size_t offset = 0; offset < end && results.size() < 5000000;
				offset += alignment) {
				if ((offset & 0xFFFF) == 0) {
					if (!owns_scan(operation) || !g_state.scanning.load(std::memory_order_acquire)) break;
					if (total_bytes != 0) {
						const float progress = static_cast<float>(completed + offset) /
							static_cast<float>(total_bytes);
						g_state.scan_progress.store(progress, std::memory_order_release);
						publish_scan_progress(operation, progress, "Scanning static image sections");
					}
				}
				bool match = config.scan_mode == scan_mode_t::unknown_initial;
				if (config.scan_mode == scan_mode_t::exact)
					match = compare_exact(bytes.data() + offset, target.data(), value_size);
				else if (config.scan_mode == scan_mode_t::bigger_than) {
					switch (config.value_type) {
					case value_type_t::byte_val: match = compare_bigger<std::uint8_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int16_val: match = compare_bigger<std::int16_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int32_val: match = compare_bigger<std::int32_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int64_val: match = compare_bigger<std::int64_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::float_val: match = compare_bigger<float>(bytes.data()+offset, target.data()); break;
					case value_type_t::double_val: match = compare_bigger<double>(bytes.data()+offset, target.data()); break;
					default: break;
					}
				} else if (config.scan_mode == scan_mode_t::smaller_than) {
					switch (config.value_type) {
					case value_type_t::byte_val: match = compare_smaller<std::uint8_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int16_val: match = compare_smaller<std::int16_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int32_val: match = compare_smaller<std::int32_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::int64_val: match = compare_smaller<std::int64_t>(bytes.data()+offset, target.data()); break;
					case value_type_t::float_val: match = compare_smaller<float>(bytes.data()+offset, target.data()); break;
					case value_type_t::double_val: match = compare_smaller<double>(bytes.data()+offset, target.data()); break;
					default: break;
					}
				} else if (config.scan_mode == scan_mode_t::value_between) {
					switch (config.value_type) {
					case value_type_t::byte_val: match = compare_between<std::uint8_t>(bytes.data()+offset, target.data(), target2.data()); break;
					case value_type_t::int16_val: match = compare_between<std::int16_t>(bytes.data()+offset, target.data(), target2.data()); break;
					case value_type_t::int32_val: match = compare_between<std::int32_t>(bytes.data()+offset, target.data(), target2.data()); break;
					case value_type_t::int64_val: match = compare_between<std::int64_t>(bytes.data()+offset, target.data(), target2.data()); break;
					case value_type_t::float_val: match = compare_between<float>(bytes.data()+offset, target.data(), target2.data()); break;
					case value_type_t::double_val: match = compare_between<double>(bytes.data()+offset, target.data(), target2.data()); break;
					default: break;
					}
				}
				const std::uint64_t section_base = image->image_base() + section.virtual_address;
				if (section_base < image->image_base() || section_base >
					(std::numeric_limits<std::uint64_t>::max)() - offset) continue;
				const std::uint64_t address = section_base + offset;
				if (config.range_base != 0 && config.range_size != 0 &&
					(address < config.range_base || address - config.range_base >= config.range_size)) continue;
				if (match) results.push_back({address,
					std::vector<std::uint8_t>(bytes.begin() + offset, bytes.begin() + offset + value_size),
					{}, section.name, static_cast<std::uint64_t>(section.virtual_address) + offset});
			}
			completed += section.raw_size;
			if (total_bytes != 0) {
				const float progress = static_cast<float>(completed) / static_cast<float>(total_bytes);
				g_state.scan_progress.store(progress, std::memory_order_release);
				publish_scan_progress(operation, progress, "Scanning static image sections");
			}
		}
		if (operation->cancellation_requested.load(std::memory_order_acquire)) {
			finish_scan_operation(operation, scan_terminal_t::cancelled, "Static binary scan cancelled");
			return;
		}
		{
			std::lock_guard<std::mutex> lock(g_state.results_mutex);
			if (!owns_scan(operation) || !g_state.scan_static_binary ||
				g_state.scan_workspace_id != workspace_id ||
				g_state.scan_workspace_generation != workspace_generation)
				throw std::runtime_error("The analysis workspace changed before static scan results could be published");
			g_state.total_found = results.size();
			g_state.results = std::move(results);
			g_state.has_initial_scan = true;
			g_state.scan_count = 1;
		}
		finish_scan_operation(operation, scan_terminal_t::completed,
			"Static binary scan completed");
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("mem_scanner", "static_scan worker exception err='%s'", ex.what());
			finish_scan_operation(operation, scan_terminal_t::failed, ex.what());
			throw;
		} catch (...) {
			diag::log_tagged("mem_scanner", "static_scan worker exception err='<unknown>'");
			finish_scan_operation(operation, scan_terminal_t::failed,
				"Static binary scan failed with an unknown error");
			throw;
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		static_cast<void>(cancel_scan());
		st.scan_thread_done.store(true, std::memory_order_release);
		return false;
	}
	operation->executor_task_id.store(submitted.task_id, std::memory_order_release);
	const bool task_registered = scanner_task_center::register_executor_task(submitted,
		"view.memory.value_scan", "memory.static_scan", "Static binary value scan",
		0, true, [operation]() {
			if (!owns_scan(operation))
				return false;
			operation->cancellation_requested.store(true, std::memory_order_release);
			return !g_state.scanning.load(std::memory_order_acquire) || cancel_scan();
		});
	if (!task_registered) {
		diag::log_tagged("mem_scanner", "static_scan task_center_registration_failed");
		operation->cancellation_requested.store(true, std::memory_order_release);
		static_cast<void>(cancel_scan());
		static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
		return false;
	}
	publish_scan_terminal_snapshot(operation);
	return true;
}

bool next_scan(scan_mode_t mode, const std::string& value_text, const std::string& value_text2) {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "next_scan refused already_scanning");
		return false;
	}
	if (!st.has_initial_scan) {
		diag::log_tagged("mem_scanner", "next_scan refused no_initial_scan");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("mem_scanner", "next_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	live_target_identity_t target_identity;
	uint32_t target_pid = 0;
	uint64_t target_epoch = 0;
	{
		std::lock_guard<std::mutex> lock(st.results_mutex);
		target_pid = st.scan_target_pid;
		target_epoch = st.scan_target_epoch;
		target_identity = st.scan_target_identity;
	}
	if (!target_binding_current(target_pid, target_epoch) ||
		!validate_attached_identity(target_identity, "next_scan")) {
		diag::log_tagged_fmt("mem_scanner",
			"next_scan refused stale_target expected_pid=%u expected_epoch=%llu current_pid=%u",
			target_pid, static_cast<unsigned long long>(target_epoch),
			driver_bridge::attached_pid());
		return false;
	}
	diag::log_tagged_fmt("mem_scanner", "next_scan start mode=%s val='%s' val2='%s'",
		scan_mode_name(mode), value_text.c_str(), value_text2.c_str());

	if (!wait_scan_worker_ready("next_scan"))
		return false;

	st.scanning.store(true);
	st.scan_thread_done.store(false, std::memory_order_release);
	auto operation = begin_scan_operation();
	try {
		mcp_standalone::downstream::producer_identity_t ns_id;
		ns_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
		ns_id.tool_name = "next_scan_dispatch";
		mcp_standalone::downstream::scoped_admission_t ns_admission =
			mcp_standalone::downstream::scoped_admission_t::acquire(ns_id);
		if (!ns_admission.active()) {
			auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ns_id);
			diag::log_tagged_fmt("mem_scanner",
				"FEATURE-WORKER-GROUP-REJECT next_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
				rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-ADMIT next_scan_dispatch token=%llu",
			static_cast<unsigned long long>(ns_admission.token()));
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "scanner";
		sub.label = "scanner.memory_next_scan";
		sub.thread_class = "scanner_scan";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.target_pid = driver_bridge::attached_pid();
		sub.lease_token = ns_admission.token();
		sub.generation = operation->generation;
		sub.body = [mode, value_text, value_text2, operation]() {
			operation->started.store(true, std::memory_order_release);
			publish_scan_progress(operation, 0.0f, "Refining scan results");
			try {
				next_scan_thread(mode, value_text, value_text2, operation);
				finish_scan_operation(operation,
					operation->cancellation_requested.load(std::memory_order_acquire)
						? scan_terminal_t::cancelled : scan_terminal_t::completed,
					operation->cancellation_requested.load(std::memory_order_acquire)
						? "Refinement scan cancelled" : "Refinement scan completed");
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("mem_scanner", "next_scan worker exception err='%s'", ex.what());
				finish_scan_operation(operation, scan_terminal_t::failed, ex.what());
				throw;
			} catch (...) {
				diag::log_tagged("mem_scanner", "next_scan worker exception err='<unknown>'");
				finish_scan_operation(operation, scan_terminal_t::failed,
					"Refinement scan failed with an unknown error");
				throw;
			}
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("mem_scanner", "next_scan worker_post_failed");
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		operation->executor_task_id.store(submitted.task_id, std::memory_order_release);
		const bool task_registered = scanner_task_center::register_executor_task(submitted,
			"view.memory.value_scan", "memory.next_scan", "Refine memory scan",
			driver_bridge::attached_pid(), true, [operation]() {
				if (!owns_scan(operation))
					return false;
				operation->cancellation_requested.store(true, std::memory_order_release);
				return !g_state.scanning.load(std::memory_order_acquire) || cancel_scan();
			});
		if (!task_registered) {
			diag::log_tagged("mem_scanner", "next_scan task_center_registration_failed");
			operation->cancellation_requested.store(true, std::memory_order_release);
			static_cast<void>(cancel_scan());
			static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
			return false;
		}
		publish_scan_terminal_snapshot(operation);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-RELEASE next_scan_dispatch token=%llu reason=dispatched",
			static_cast<unsigned long long>(ns_admission.token()));
		ns_admission.release("dispatched");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "next_scan worker_create_failed err='%s'", ex.what());
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	} catch (...) {
		diag::log_tagged("mem_scanner", "next_scan worker_create_failed err='<unknown>'");
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	}
	return true;
}

bool cancel_scan() {
	auto& st = g_state;
	std::shared_ptr<scan_operation_t> operation;
	{
		std::lock_guard<std::mutex> lock(g_scan_operation_mutex);
		operation = g_active_scan_operation;
	}
	bool expected = true;
	if (!st.scanning.compare_exchange_strong(expected, false,
		std::memory_order_acq_rel, std::memory_order_acquire)) {
		diag::log_tagged("mem_scanner", "cancel_scan refused no_active_scan");
		return false;
	}
	if (owns_scan(operation))
		operation->cancellation_requested.store(true, std::memory_order_release);
	diag::log_tagged_fmt("mem_scanner", "cancel_scan signalled progress=%.3f",
		static_cast<double>(st.scan_progress.load(std::memory_order_acquire)));
	if (owns_scan(operation))
		finish_scan_operation(operation, scan_terminal_t::cancelled, "Scan cancelled");
	return true;
}

void undo_scan() {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "undo_scan refused scanning_in_progress");
		return;
	}
	std::lock_guard<std::mutex> lk(st.results_mutex);
	if (!st.scan_static_binary && (!target_binding_current(st.scan_target_pid, st.scan_target_epoch) ||
		!validate_attached_identity(st.scan_target_identity, "undo_scan"))) return;
	if (st.scan_history.empty()) {
		diag::log_tagged("mem_scanner", "undo_scan refused history_empty");
		return;
	}
	st.results = std::move(st.scan_history.back());
	st.scan_history.pop_back();
	st.total_found = st.results.size();
	if (st.scan_count > 0) st.scan_count--;
	if (st.scan_count == 0) st.has_initial_scan = false;
	diag::log_tagged_fmt("mem_scanner", "undo_scan restored=%zu scan_count=%d",
		st.total_found, st.scan_count);
}

void reset_scan() {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged_fmt("mem_scanner",
			"reset_scan cancelling active scan progress=%.3f",
			static_cast<double>(st.scan_progress.load(std::memory_order_acquire)));
		static_cast<void>(cancel_scan());
		if (!wait_scan_worker_ready("reset_scan")) {
			diag::log_tagged("mem_scanner", "reset_scan refused worker_still_busy");
			return;
		}
	} else if (!st.scan_thread_done.load(std::memory_order_acquire)) {
		st.scan_thread_done.store(true, std::memory_order_release);
		diag::log_tagged("mem_scanner", "reset_scan recovered stale scan_thread_done=0");
	}
	std::lock_guard<std::mutex> lk(st.results_mutex);
	size_t had = st.results.size();
	st.results.clear();
	st.scan_history.clear();
	st.total_found = 0;
	st.has_initial_scan = false;
	st.scan_count = 0;
	st.scan_static_binary = false;
	st.scan_target_pid = 0;
	st.scan_target_epoch = 0;
	st.scan_target_identity = {};
	st.scan_workspace_id.clear();
	st.scan_workspace_generation = 0;
	st.scan_progress.store(1.f, std::memory_order_release);
	diag::log_tagged_fmt("mem_scanner", "reset_scan cleared=%zu", had);
}

void add_address(uint64_t address, const std::string& description, value_type_t type) {
	auto& st = g_state;
	restore_scanner_state_for_current_target();
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "add_address")) return;
	const std::uint64_t target_epoch = observe_target_identity(target_identity);
	{
		std::lock_guard<std::mutex> lk(st.address_mutex);
		for (const auto& e : st.address_list) {
			if (e.address == address && same_target_identity(e.target_identity, target_identity)) {
				diag::log_tagged_fmt("mem_scanner", "add_address skipped_duplicate addr=0x%llX",
					static_cast<unsigned long long>(address));
				return;
			}
		}
		address_entry_t entry;
		entry.address = address;
		entry.description = description;
		entry.value_type = type;
		entry.target_pid = target_identity.process.pid;
		entry.target_epoch = target_epoch;
		entry.target_identity = target_identity;
		st.address_list.push_back(std::move(entry));
		diag::log_tagged_fmt("mem_scanner", "add_address addr=0x%llX type=%s desc='%s' total=%zu",
			static_cast<unsigned long long>(address), value_type_name(type),
			description.c_str(), st.address_list.size());
	}
	persist_scanner_state();
}

void remove_address(size_t index) {
	auto& st = g_state;
	bool removed = false;
	{
		std::lock_guard<std::mutex> lk(st.address_mutex);
		if (index < st.address_list.size()) {
			uint64_t addr = st.address_list[index].address;
			st.address_list.erase(st.address_list.begin() + static_cast<ptrdiff_t>(index));
			diag::log_tagged_fmt("mem_scanner", "remove_address index=%zu addr=0x%llX remaining=%zu",
				index, static_cast<unsigned long long>(addr), st.address_list.size());
			removed = true;
		} else {
			diag::log_tagged_fmt("mem_scanner", "remove_address out_of_range index=%zu size=%zu",
				index, st.address_list.size());
		}
	}
	if (removed) persist_scanner_state();
}

void freeze_address(size_t index, bool enable) {
	auto& st = g_state;
	live_target_identity_t target_identity;
	const bool identity_valid = capture_attached_identity(target_identity, "freeze_address");
	const uint64_t epoch = identity_valid ? observe_target_identity(target_identity) : 0;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index < st.address_list.size()) {
		auto& e = st.address_list[index];
		e.frozen = enable && identity_valid && e.target_pid == target_identity.process.pid &&
			e.target_epoch == epoch && !e.last_value.empty() &&
			same_target_identity(e.target_identity, target_identity);
		if (e.frozen)
			e.freeze_value = e.last_value;
		else
			e.freeze_value.clear();
		diag::log_tagged_fmt("mem_scanner", "freeze_address addr=0x%llX enable=%d has_value=%d",
			static_cast<unsigned long long>(e.address), static_cast<int>(enable),
			static_cast<int>(!e.freeze_value.empty()));
	} else {
		diag::log_tagged_fmt("mem_scanner", "freeze_address out_of_range index=%zu size=%zu",
			index, st.address_list.size());
	}
}

bool freeze_address_exact(size_t index, bool enable, const address_entry_t& expected) {
	auto& st = g_state;
	live_target_identity_t target_identity;
	const bool identity_valid = capture_attached_identity(target_identity, "freeze_address_exact");
	const uint64_t epoch = identity_valid ? observe_target_identity(target_identity) : 0;
	if (!identity_valid || expected.target_pid != target_identity.process.pid ||
		expected.target_epoch != epoch ||
		!same_target_identity(expected.target_identity, target_identity))
		return false;
	std::lock_guard<std::mutex> lock(st.address_mutex);
	if (index >= st.address_list.size())
		return false;
	auto& entry = st.address_list[index];
	if (entry.address != expected.address || entry.description != expected.description ||
		entry.value_type != expected.value_type || entry.frozen != expected.frozen ||
		entry.freeze_value != expected.freeze_value || entry.last_value != expected.last_value ||
		entry.target_pid != expected.target_pid || entry.target_epoch != expected.target_epoch ||
		!same_target_identity(entry.target_identity, expected.target_identity) ||
		(enable && entry.last_value.empty()))
		return false;
	entry.frozen = enable;
	if (enable)
		entry.freeze_value = entry.last_value;
	else
		entry.freeze_value.clear();
	return entry.frozen == enable && (!enable || !entry.freeze_value.empty());
}

write_transaction_result_t write_value_exact(uint64_t address, value_type_t type,
	const std::string& value_text, bool hex, uint32_t expected_pid,
	uint64_t expected_process_creation_time_100ns) {
	write_transaction_result_t result;
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "write_value")) {
		diag::log_tagged_fmt("mem_scanner", "write_value refused_not_attached addr=0x%llX",
			static_cast<unsigned long long>(address));
		result.error = "No verified live target is attached.";
		return result;
	}
	const uint32_t pid = target_identity.process.pid;
	result.target_pid = pid;
	result.process_creation_time_100ns = target_identity.process.creation_time_100ns;
	if ((expected_pid != 0 && expected_pid != pid) ||
		(expected_process_creation_time_100ns != 0 &&
		 expected_process_creation_time_100ns != target_identity.process.creation_time_100ns)) {
		result.error = "The attached process identity changed before the write transaction.";
		return result;
	}
	const uint64_t epoch = observe_target_identity(target_identity);
	{
		std::lock_guard<std::mutex> lock(g_state.address_mutex);
		const auto entry = std::find_if(g_state.address_list.begin(), g_state.address_list.end(),
			[address, type](const address_entry_t& item) {
				return item.address == address && item.value_type == type;
			});
		if (entry != g_state.address_list.end() &&
			(entry->target_pid != pid || entry->target_epoch != epoch ||
				!same_target_identity(entry->target_identity, target_identity))) {
				diag::log_tagged_fmt("mem_scanner", "write_value refused_stale_target addr=0x%llX entry_pid=%u current_pid=%u",
					static_cast<unsigned long long>(address), entry->target_pid, pid);
			result.error = "The address-list entry belongs to a stale target identity.";
			return result;
		}
	}
	auto bytes = parse_value(value_text, type, hex);
	if (bytes.empty()) {
		diag::log_tagged_fmt("mem_scanner", "write_value parse_failed addr=0x%llX text='%s' hex=%d",
			static_cast<unsigned long long>(address), value_text.c_str(), static_cast<int>(hex));
		result.error = "The requested value is invalid for its type.";
		return result;
	}
	std::vector<std::uint8_t> previous;
	if (!transaction_target_current(pid, epoch, target_identity,
			"write_value_before_original_read")) {
		diag::log_tagged_fmt("mem_scanner",
			"write_value refused_identity_before_read addr=0x%llX",
			static_cast<unsigned long long>(address));
		result.error = "The target identity changed before the original read.";
		return result;
	}
	const bool original_read = driver_bridge::read_memory(address, bytes.size(), previous);
	const bool identity_after_original_read = transaction_target_current(pid, epoch,
		target_identity, "write_value_after_original_read");
	result.original_read_ok = identity_after_original_read && original_read &&
		previous.size() == bytes.size();
	if (result.original_read_ok) result.original_bytes = previous;
	if (!result.original_read_ok) {
		diag::log_tagged_fmt("mem_scanner",
			"write_value refused_original_read addr=0x%llX read_ok=%d size=%zu expected=%zu",
			static_cast<unsigned long long>(address), static_cast<int>(original_read),
			previous.size(), bytes.size());
		result.error = "The original bytes could not be read from the exact target.";
		return result;
	}
	if (!transaction_target_current(pid, epoch, target_identity,
			"write_value_before_write")) {
		diag::log_tagged_fmt("mem_scanner",
			"write_value refused_identity_before_write addr=0x%llX",
			static_cast<unsigned long long>(address));
		result.error = "The target identity changed immediately before the write.";
		return result;
	}
	result.write_attempted = true;
	const bool write_ok = driver_bridge::write_memory(address, bytes);
	result.write_ok = write_ok;
	const bool identity_after_write = transaction_target_current(pid, epoch, target_identity,
		"write_value_after_write");
	std::vector<std::uint8_t> readback;
	bool verified = false;
	if (write_ok && identity_after_write &&
		transaction_target_current(pid, epoch, target_identity,
			"write_value_before_verify_read")) {
		const bool verify_read = driver_bridge::read_memory(address, bytes.size(), readback);
		const bool identity_after_verify_read = transaction_target_current(pid, epoch,
			target_identity, "write_value_after_verify_read");
		result.readback_ok = identity_after_verify_read && verify_read &&
			readback.size() == bytes.size();
		if (result.readback_ok) result.readback_bytes = readback;
		verified = result.readback_ok && readback == bytes;
	}
	result.verified = verified;
	bool rollback_attempted = false;
	bool rollback_verified = false;
	if (!verified && transaction_target_current(pid, epoch, target_identity,
			"write_value_before_rollback_write")) {
		rollback_attempted = true;
		result.rollback_attempted = true;
		const bool rollback_write = driver_bridge::write_memory(address, previous);
		result.rollback_write_ok = rollback_write;
		const bool identity_after_rollback_write = transaction_target_current(pid, epoch,
			target_identity, "write_value_after_rollback_write");
		if (rollback_write && identity_after_rollback_write &&
			transaction_target_current(pid, epoch, target_identity,
				"write_value_before_rollback_read")) {
			std::vector<std::uint8_t> rollback_readback;
			const bool rollback_read = driver_bridge::read_memory(address, previous.size(),
				rollback_readback);
			const bool identity_after_rollback_read = transaction_target_current(pid, epoch,
				target_identity, "write_value_after_rollback_read");
			result.rollback_readback_ok = identity_after_rollback_read && rollback_read &&
				rollback_readback.size() == previous.size();
			if (result.rollback_readback_ok)
				result.rollback_readback_bytes = rollback_readback;
			rollback_verified = result.rollback_readback_ok &&
				rollback_readback == previous;
		}
	}
	result.rollback_verified = rollback_verified;
	if (!verified) {
		result.error = rollback_verified
			? "The write could not be verified; the original bytes were restored and verified."
			: "The write could not be verified and restoration could not be verified.";
	}
	diag::log_tagged_fmt("mem_scanner",
		"write_value addr=0x%llX size=%zu type=%s write_ok=%d identity_after_write=%d verified=%d rollback_attempted=%d rollback_verified=%d",
		static_cast<unsigned long long>(address), bytes.size(),
		value_type_name(type), static_cast<int>(write_ok),
		static_cast<int>(identity_after_write), static_cast<int>(verified),
		static_cast<int>(rollback_attempted), static_cast<int>(rollback_verified));
	return result;
}

void write_value(uint64_t address, value_type_t type, const std::string& value_text, bool hex) {
	static_cast<void>(write_value_exact(address, type, value_text, hex, 0, 0));
}

std::string read_value_string(uint64_t address, value_type_t type) {
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "read_value_string")) return "<stale target>";
	const uint64_t target_epoch = observe_target_identity(target_identity);
	size_t sz = value_type_size(type);
	if (type == value_type_t::string_ascii || type == value_type_t::string_utf16)
		sz = 256;
	std::vector<uint8_t> buf;
	if (!target_binding_current(target_identity.process.pid, target_epoch) ||
		!driver_bridge::read_memory(address, sz, buf) ||
		!validate_attached_identity(target_identity, "read_value_string_publish")) return "<read error>";
	if (type == value_type_t::string_ascii) {
		auto it = std::find(buf.begin(), buf.end(), 0);
		if (it != buf.end()) buf.erase(it, buf.end());
	}
	return format_value(buf, type);
}

void refresh_address_list() {
	auto& st = g_state;
	restore_scanner_state_for_current_target();
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "refresh_address_list")) return;
	const uint64_t target_epoch = observe_target_identity(target_identity);
	std::vector<address_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.address_mutex);
		snapshot = st.address_list;
	}
	struct refreshed_value_t {
		uint64_t address = 0;
		value_type_t value_type = value_type_t::int32_val;
		std::vector<uint8_t> value;
		uint32_t target_pid = 0;
		uint64_t target_epoch = 0;
		live_target_identity_t target_identity;
	};
	std::vector<refreshed_value_t> refreshed;
	refreshed.reserve(snapshot.size());
	for (const auto& entry : snapshot) {
		if (!target_binding_current(entry.target_pid, entry.target_epoch) ||
			entry.target_epoch != target_epoch ||
			!same_target_identity(entry.target_identity, target_identity))
			continue;
		size_t sz = value_type_size(entry.value_type);
		if (entry.value_type == value_type_t::string_ascii ||
			entry.value_type == value_type_t::string_utf16) sz = 256;
		std::vector<uint8_t> buf;
		if (driver_bridge::read_memory(entry.address, sz, buf)) {
			if (entry.value_type == value_type_t::string_ascii) {
				auto it = std::find(buf.begin(), buf.end(), 0);
				if (it != buf.end()) buf.erase(it, buf.end());
			}
			refreshed.push_back({entry.address, entry.value_type, std::move(buf),
				entry.target_pid, entry.target_epoch, entry.target_identity});
		}
	}
	if (!validate_attached_identity(target_identity, "refresh_address_list_publish")) return;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	for (auto& update : refreshed) {
			auto current = std::find_if(st.address_list.begin(), st.address_list.end(),
			[&](const address_entry_t& entry) {
				return entry.address == update.address && entry.value_type == update.value_type &&
					entry.target_pid == update.target_pid && entry.target_epoch == update.target_epoch &&
					same_target_identity(entry.target_identity, update.target_identity);
			});
		if (current != st.address_list.end())
			current->last_value = std::move(update.value);
	}
}

bool start_pointer_scan(uint64_t target_address, int max_depth, int max_offset, uint64_t scan_base, uint64_t scan_size) {
	auto& st = g_state;
	if (st.pointer_scanning.load()) {
		diag::log_tagged("pointer_scan", "start_pointer_scan refused already_scanning");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("pointer_scan", "start_pointer_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	live_target_identity_t target_identity;
	if (!capture_attached_identity(target_identity, "start_pointer_scan")) return false;
	const uint64_t target_epoch = observe_target_identity(target_identity);
	diag::log_tagged_fmt("pointer_scan", "start_pointer_scan target=0x%llX depth=%d offset=0x%X scan_range=0x%llX+0x%llX",
		static_cast<unsigned long long>(target_address), max_depth, max_offset,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size));
	st.pointer_scanning.store(true);
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
		st.pointer_target_pid = target_identity.process.pid;
		st.pointer_target_epoch = target_epoch;
		st.pointer_target_identity = target_identity;
	}
	while (!st.pointer_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	st.pointer_thread_done.store(false, std::memory_order_release);
	mcp_standalone::downstream::producer_identity_t ps_id;
	ps_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ps_id.tool_name = "pointer_scan_dispatch";
	mcp_standalone::downstream::scoped_admission_t ps_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ps_id);
	if (!ps_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ps_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_thread_done.store(true, std::memory_order_release);
		st.pointer_scanning.store(false);
		return false;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_dispatch token=%llu",
		static_cast<unsigned long long>(ps_admission.token()));
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.pointer_scan";
	sub.thread_class = "scanner_pointer_scan";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	sub.lease_token = ps_admission.token();
	sub.body = [target_address, max_depth, max_offset, scan_base, scan_size]() {
			pointer_scan_thread(target_address, max_depth, max_offset, scan_base, scan_size);
			g_state.pointer_thread_done.store(true, std::memory_order_release);
		};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted)
	{
		diag::log_tagged("pointer_scan", "start_pointer_scan worker_post_failed");
		st.pointer_thread_done.store(true, std::memory_order_release);
		st.pointer_scanning.store(false);
		return false;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.pointer_scan", "memory.pointer_scan", "Pointer scan",
		driver_bridge::attached_pid(), true, []() {
			cancel_pointer_scan();
			return true;
		});
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_dispatch token=%llu reason=dispatched",
		static_cast<unsigned long long>(ps_admission.token()));
	ps_admission.release("dispatched");
	return true;
}

void cancel_pointer_scan() {
	diag::log_tagged("pointer_scan", "cancel_pointer_scan signalled");
	g_state.pointer_scanning.store(false);
}

}
