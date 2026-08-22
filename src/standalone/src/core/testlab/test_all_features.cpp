#include "test_all_features.hpp"
#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "test_all_debugger.h"
#include "test_all_scanner.h"
#include "test_all_analysis.h"
#include "test_all_network.h"
#include "test_all_burp.h"
#include "test_all_disasm.h"
#include "test_all_mcp.h"
#include "test_all_ui.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../ui/theme.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../network/mitm_proxy.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "../mcp/downstream_producer_governor.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../scanner/aob_generator.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../analysis/pdb_default_skip.hpp"
#include "../analysis/symbol_store.hpp"
#include "../../helpers/diag_log.hpp"
#include "../diagnostics/testlab_hung_packet.hpp"
#include "../diagnostics/metadata_ring.hpp"
#include "../../helpers/globals.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "../../../../../driver/comm.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <deque>
#include <exception>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace test_all_features {

	std::string mcp_coverage_final_summary_line();
	int mcp_coverage_suspect_count();
	void log_mcp_phase_remaining_diagnostics(HANDLE hf, int phase_remaining);

	void flush_full_test_log(void* hf) {
		HANDLE handle = static_cast<HANDLE>(hf);
		if (handle != INVALID_HANDLE_VALUE)
			FlushFileBuffers(handle);
	}

	void write_full_test_log_line(void* hf, const char* data, std::size_t size, bool force_flush) {
		HANDLE handle = static_cast<HANDLE>(hf);
		if (handle == INVALID_HANDLE_VALUE || data == nullptr || size == 0)
			return;

		static std::mutex s_write_mtx;
		static std::uint64_t s_last_flush_ms = 0;
		static std::uint32_t s_bytes_since_flush = 0;

		const bool force_by_text =
			std::strstr(data, "FAIL --") != nullptr ||
			std::strstr(data, "SUSPECT --") != nullptr ||
			std::strstr(data, "INCOMPLETE") != nullptr ||
			std::strstr(data, "FATAL") != nullptr ||
			std::strstr(data, "CRASH") != nullptr ||
			std::strstr(data, "BSOD") != nullptr ||
			std::strstr(data, "SUMMARY") != nullptr;

		std::lock_guard<std::mutex> lk(s_write_mtx);
		DWORD wrote = 0;
		WriteFile(handle, data, static_cast<DWORD>(size), &wrote, nullptr);
		s_bytes_since_flush += wrote;
		const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
		if (force_flush || force_by_text || s_last_flush_ms == 0 || s_bytes_since_flush >= 65536u || now - s_last_flush_ms >= 1000u) {
			FlushFileBuffers(handle);
			s_last_flush_ms = now;
			s_bytes_since_flush = 0;
		}
	}

	void mirror_full_test_log_line(const char* tag, const char* detail, const char* line) {
		const char* safe_tag = tag ? tag : "test";
		const char* safe_detail = detail ? detail : "";
		const bool important =
			std::strstr(safe_detail, "FAIL --") != nullptr ||
			std::strstr(safe_detail, "SUSPECT --") != nullptr ||
			std::strstr(safe_detail, "SKIP --") != nullptr ||
			std::strstr(safe_detail, "INCOMPLETE") != nullptr ||
			std::strstr(safe_detail, "FATAL") != nullptr ||
			std::strstr(safe_detail, "CRASH") != nullptr ||
			std::strstr(safe_detail, "BSOD") != nullptr ||
			std::strstr(safe_detail, "SUMMARY") != nullptr;
		const bool milestone =
			std::strcmp(safe_tag, "start") == 0 ||
			std::strcmp(safe_tag, "run") == 0 ||
			std::strcmp(safe_tag, "phase") == 0 ||
			std::strcmp(safe_tag, "summary") == 0 ||
			std::strcmp(safe_tag, "checkpoint") == 0 ||
			std::strcmp(safe_tag, "heartbeat") == 0 ||
			std::strcmp(safe_tag, "launch") == 0 ||
			std::strcmp(safe_tag, "attach") == 0 ||
			std::strcmp(safe_tag, "cancel") == 0 ||
			std::strcmp(safe_tag, "env") == 0 ||
			std::strcmp(safe_tag, "net-cleanup") == 0;

		if (important || milestone)
			diag::log_tagged_fmt("test_all", "%s: %s", safe_tag, safe_detail);
		if (important && line)
			OutputDebugStringA(line);
	}

	void format_ui_phase_snapshot(char* out, std::size_t cap);

	namespace {


		std::atomic<bool> g_running{ false };
		std::atomic<bool> g_start_queued{ false };
		std::atomic<bool> g_shutdown_cancel_requested{ false };
		std::atomic<bool> g_cancel_requested{ false };
		std::atomic<bool> g_interactive_cancel_cleanup_inflight{ false };
		std::atomic<bool> g_target_unavailable{ false };
		std::atomic<bool> g_full_test_guard_active{ false };
		std::atomic<std::uint32_t> g_full_test_guard_depth{ 0 };

		std::atomic<int>  g_total{ 0 };
		std::atomic<int>  g_current{ 0 };
		std::atomic<int>  g_passed{ 0 };
		std::atomic<int>  g_failed{ 0 };
		std::atomic<int>  g_skipped{ 0 };
		std::atomic<int>  g_prerequisite_skipped{ 0 };

		std::atomic<int>  g_suspect{ 0 };

		std::atomic<std::uint32_t> g_target_pid{ 0 };
		std::atomic<std::uint64_t> g_target_addr{ 0 };
		std::atomic<std::uint64_t> g_target_image_base{ 0 };
		std::atomic<bool>          g_driver_attached{ false };
		std::atomic<std::uint64_t> g_saved_dtb{ 0 };

		std::uint32_t current_target_pid();

		std::mutex g_launch_state_mtx;
		std::string g_target_executable_path;
		std::string g_requested_cwd;
		std::string g_effective_cwd;

		std::mutex g_test_marker_mtx;
		std::string g_first_failure_marker;
		std::string g_last_successful_marker;
		std::atomic<bool> g_first_failure_recorded{ false };

		std::mutex        g_log_mtx;
		enum class overlay_log_severity_t : std::uint8_t {
			normal,
			success,
			warning,
			error
		};
		struct overlay_log_line_t {
			std::string text;
			overlay_log_severity_t severity = overlay_log_severity_t::normal;
		};
		std::deque<overlay_log_line_t> g_log_lines;
		constexpr std::size_t kMaxLogLines = 4096;
		constexpr std::size_t kOverlayRenderTailLines = 512;
		std::atomic<std::uint64_t> g_log_version{ 0 };
		std::atomic<std::uint64_t> g_progress_version{ 0 };
		std::atomic<std::uint64_t> g_overlay_lock_busy_total{ 0 };
		std::atomic<std::uint64_t> g_overlay_snapshot_changes{ 0 };
		std::atomic<std::uint64_t> g_overlay_render_elapsed_us{ 0 };
		std::atomic<std::uint64_t> g_overlay_rendered_rows{ 0 };
		std::atomic<std::uint64_t> g_overlay_cached_rows{ 0 };
		std::atomic<std::uint64_t> g_overlay_total_rows{ 0 };
		std::atomic<bool> g_overlay_snapshot_busy{ false };
		std::atomic<bool> g_overlay_snapshot_changed{ false };
		std::atomic<bool> g_overlay_visible{ false };
		overlay_log_severity_t classify_overlay_log_line(const std::string& line);
		std::uint64_t mix_overlay_dirty_value(std::uint64_t state, std::uint64_t value);
		bool try_snapshot_log_tail_if_changed(std::size_t max_lines,
			std::uint64_t& known_version,
			std::vector<overlay_log_line_t>& out,
			std::size_t* total_lines,
			bool* changed);

		struct destructive_skip_key_t {
			const char* category;
			const char* name;
		};

		constexpr destructive_skip_key_t kExpectedDestructiveSkipKeys[] = {
			{ "thread", "TSR" },
			{ "remote-call", "RC" },
			{ "module", "PINJ" }
		};
		constexpr int kExpectedDestructiveSkipCount =
			static_cast<int>(sizeof(kExpectedDestructiveSkipKeys) / sizeof(kExpectedDestructiveSkipKeys[0]));
		bool g_expected_destructive_skip_seen[kExpectedDestructiveSkipCount] = {};
		int g_expected_destructive_skip_seen_count = 0;
		int g_unexpected_destructive_skip_count = 0;
		int g_duplicate_destructive_skip_count = 0;
		std::vector<std::string> g_unexpected_skip_records;

		std::shared_ptr<const std::string> g_phase_label = std::make_shared<const std::string>();
		std::shared_ptr<const std::string> g_step_label = std::make_shared<const std::string>();
		std::atomic<std::uint64_t> g_run_id{ 0 };
		std::atomic<std::uint64_t> g_run_start_tick{ 0 };
		std::atomic<std::uint64_t> g_phase_start_tick{ 0 };
		std::atomic<std::uint64_t> g_step_start_tick{ 0 };
		std::atomic<int> g_active_phase_index{ 0 };
		std::atomic<int> g_active_phase_planned{ 0 };
		std::atomic<int> g_active_phase_completed{ 0 };
		std::atomic<bool> g_hung_marker_emitted{ false };

		struct phase_ledger_entry_t {
			std::string name;
			int planned = 0;
			int completed = 0;
			int pass_delta = 0;
			int fail_delta = 0;
			int skip_delta = 0;
			int start_passed = 0;
			int start_failed = 0;
			int start_skipped = 0;
			bool entered = false;
			bool done = false;
			bool hung_logged = false;
			std::uint64_t start_ms = 0;
			std::uint64_t end_ms = 0;
			std::string status;
		};

		std::mutex g_phase_ledger_mtx;
		std::vector<phase_ledger_entry_t> g_phase_ledger;
		constexpr std::uint64_t kFullTestHungStepMs = 120000;


		const char* log_path() {
			static const std::string path = []() {
				char buf[MAX_PATH] = {};
				if (diag::build_log_path("aida_full_test.log", buf, sizeof(buf)))
					return std::string(buf);
				return std::string();
			}();
			return path.c_str();
		}

		const char* target_log_path() {
			static const std::string path = []() {
				char buf[MAX_PATH] = {};
				if (diag::build_log_path("aida_test_target.log", buf, sizeof(buf)))
					return std::string(buf);
				return std::string();
			}();
			return path.c_str();
		}

		constexpr const char* kFullTestEnvName = "AIDA_FULL_TEST_RUNNING";
		constexpr const char* kTargetArgsText = "--no-external --duration 0 --net-rate 2000 --absorb-external-single-step";
		constexpr const wchar_t* kTargetArgsWide = L"--no-external --duration 0 --net-rate 2000 --absorb-external-single-step";
		constexpr int kLaunchFeatureTests = 1;
		constexpr int kExtendedFeatureTests = 6;
		constexpr int kDebuggerFeatureTests = 83;
		constexpr int kScannerFeatureTests = 64;
		constexpr int kAnalysisFeatureTests = 77;
		constexpr int kNetworkFeatureTests = 125;
		constexpr int kBurpFeatureTests = 184;
		constexpr int kDisasmFeatureTests = 111;
		constexpr int kMcpFeatureTests = 514;
		constexpr int kUiFeatureTests = 10;


		void format_timestamp(char* out, std::size_t cap) {
			SYSTEMTIME st;
			GetLocalTime(&st);
			std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
				static_cast<unsigned>(st.wYear),
				static_cast<unsigned>(st.wMonth),
				static_cast<unsigned>(st.wDay),
				static_cast<unsigned>(st.wHour),
				static_cast<unsigned>(st.wMinute),
				static_cast<unsigned>(st.wSecond),
				static_cast<unsigned>(st.wMilliseconds));
		}

		HANDLE open_log_file() {
			return CreateFileA(
				log_path(),
				FILE_APPEND_DATA | SYNCHRONIZE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
		}

		void write_log_file(HANDLE hf, const std::string& line) {
			write_full_test_log_line(hf, line.data(), line.size());
		}

		void push_log(const std::string& line) {
			std::lock_guard<std::mutex> lk(g_log_mtx);
			overlay_log_line_t entry;
			entry.text = line;
			entry.severity = classify_overlay_log_line(line);
			g_log_lines.push_back(std::move(entry));
			if (g_log_lines.size() > kMaxLogLines)
				g_log_lines.pop_front();
			g_log_version.fetch_add(1, std::memory_order_acq_rel);
		}

		std::string load_label_snapshot(const std::shared_ptr<const std::string>& slot);

		void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
			char ts[40];
			format_timestamp(ts, sizeof(ts));

			char detail[1024];
			va_list ap;
			va_start(ap, fmt);
			_vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
			va_end(ap);


			char line[1200];
			_snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
			std::string s(line);


			write_log_file(hf, s);

			mirror_full_test_log_line(tag, detail, s.c_str());


			push_log(s);

			if (detail[0] == 'P' && detail[1] == 'A' && detail[2] == 'S' && detail[3] == 'S') {
				std::string phase_label = load_label_snapshot(g_phase_label);
				std::string step_label = load_label_snapshot(g_step_label);
				char marker[256];
				_snprintf_s(marker, sizeof(marker), _TRUNCATE, "phase=%s step=%s tag=%s",
					phase_label.empty() ? "<none>" : phase_label.c_str(),
					step_label.empty() ? "<none>" : step_label.c_str(),
					tag ? tag : "<null>");
				std::lock_guard<std::mutex> lk(g_test_marker_mtx);
				g_last_successful_marker = marker;
			} else if (detail[0] == 'F' && detail[1] == 'A' && detail[2] == 'I' && detail[3] == 'L') {
				bool expected = false;
				if (g_first_failure_recorded.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
					std::string phase_label = load_label_snapshot(g_phase_label);
					std::string step_label = load_label_snapshot(g_step_label);
					char marker[256];
					_snprintf_s(marker, sizeof(marker), _TRUNCATE, "phase=%s step=%s tag=%s",
						phase_label.empty() ? "<none>" : phase_label.c_str(),
						step_label.empty() ? "<none>" : step_label.c_str(),
						tag ? tag : "<null>");
					std::lock_guard<std::mutex> lk(g_test_marker_mtx);
					g_first_failure_marker = marker;
				}
			}
		}

		bool prepare_target_log_file(HANDLE hf) {
			SetLastError(0);
			HANDLE ht = CreateFileA(
				target_log_path(),
				FILE_APPEND_DATA | SYNCHRONIZE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
			DWORD err = ht == INVALID_HANDLE_VALUE ? GetLastError() : 0UL;
			log_msg(hf, "target-log", "prepare path=%s ok=%d err=%lu handle=%p",
				target_log_path(),
				ht != INVALID_HANDLE_VALUE ? 1 : 0,
				static_cast<unsigned long>(err),
				ht == INVALID_HANDLE_VALUE ? nullptr : ht);
			if (ht == INVALID_HANDLE_VALUE)
				return false;

			char ts[40];
			format_timestamp(ts, sizeof(ts));
			char line[512];
			int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
				"[%s] [target-log] prepared by full-test harness pid=%lu tid=%lu\n",
				ts,
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()));
			if (n > 0) {
				DWORD wrote = 0;
				WriteFile(ht, line, static_cast<DWORD>(n), &wrote, nullptr);
				FlushFileBuffers(ht);
			}
			CloseHandle(ht);
			return true;
		}

		std::uint64_t now_ms_tick() {
			return static_cast<std::uint64_t>(GetTickCount64());
		}

		void store_label_snapshot(std::shared_ptr<const std::string>& slot, const char* label) {
			auto next = std::make_shared<const std::string>((label != nullptr) ? label : "");
			std::atomic_store_explicit(&slot, next, std::memory_order_release);
			g_progress_version.fetch_add(1, std::memory_order_acq_rel);
		}

		std::string load_label_snapshot(const std::shared_ptr<const std::string>& slot) {
			auto current = std::atomic_load_explicit(&slot, std::memory_order_acquire);
			return current ? *current : std::string();
		}

		overlay_log_severity_t classify_overlay_log_line(const std::string& line) {
			if (line.find("FAIL") != std::string::npos || line.find("FATAL") != std::string::npos || line.find("CRASH") != std::string::npos)
				return overlay_log_severity_t::error;
			if (line.find("SUSPECT") != std::string::npos || line.find("SKIP") != std::string::npos || line.find("INCOMPLETE") != std::string::npos)
				return overlay_log_severity_t::warning;
			if (line.find("PASS") != std::string::npos)
				return overlay_log_severity_t::success;
			return overlay_log_severity_t::normal;
		}

		std::uint64_t mix_overlay_dirty_value(std::uint64_t state, std::uint64_t value) {
			state ^= value + 0x9E3779B97F4A7C15ull + (state << 6) + (state >> 2);
			return state;
		}

		bool try_snapshot_log_tail_if_changed(std::size_t max_lines,
			std::uint64_t& known_version,
			std::vector<overlay_log_line_t>& out,
			std::size_t* total_lines,
			bool* changed)
		{
			if (changed)
				*changed = false;
			if (total_lines)
				*total_lines = 0;
			std::unique_lock<std::mutex> lk(g_log_mtx, std::try_to_lock);
			if (!lk.owns_lock())
				return false;
			const std::uint64_t current_version = g_log_version.load(std::memory_order_acquire);
			const std::size_t total = g_log_lines.size();
			if (total_lines)
				*total_lines = total;
			if (current_version == known_version)
				return true;
			out.clear();
			const std::size_t count = (std::min)(total, max_lines);
			out.reserve(count);
			const std::size_t skip = total > count ? total - count : 0;
			auto it = g_log_lines.begin();
			std::advance(it, static_cast<std::deque<overlay_log_line_t>::difference_type>(skip));
			for (; it != g_log_lines.end(); ++it)
				out.push_back(*it);
			known_version = current_version;
			if (changed)
				*changed = true;
			g_overlay_snapshot_changes.fetch_add(1, std::memory_order_acq_rel);
			return true;
		}

		int current_completed_count() {
			return g_passed.load(std::memory_order_acquire) +
				g_failed.load(std::memory_order_acquire) +
				g_skipped.load(std::memory_order_acquire);
		}

		int phase_ledger_index_locked(const char* phase) {
			const char* safe_phase = phase ? phase : "";
			for (std::size_t i = 0; i < g_phase_ledger.size(); ++i) {
				if (g_phase_ledger[i].name == safe_phase)
					return static_cast<int>(i);
			}
			return -1;
		}

		void refresh_phase_entry_from_counters(phase_ledger_entry_t& entry) {
			entry.pass_delta = g_passed.load(std::memory_order_acquire) - entry.start_passed;
			entry.fail_delta = g_failed.load(std::memory_order_acquire) - entry.start_failed;
			entry.skip_delta = g_skipped.load(std::memory_order_acquire) - entry.start_skipped;
			entry.completed = entry.pass_delta + entry.fail_delta + entry.skip_delta;
			if (entry.completed < 0)
				entry.completed = 0;
		}

		void publish_active_phase_snapshot_locked(int index) {
			if (index >= 0 && index < static_cast<int>(g_phase_ledger.size())) {
				const auto& entry = g_phase_ledger[static_cast<std::size_t>(index)];
				g_active_phase_index.store(index + 1, std::memory_order_release);
				g_active_phase_planned.store(entry.planned, std::memory_order_release);
				g_active_phase_completed.store(entry.completed, std::memory_order_release);
			} else {
				g_active_phase_index.store(0, std::memory_order_release);
				g_active_phase_planned.store(0, std::memory_order_release);
				g_active_phase_completed.store(0, std::memory_order_release);
			}
			g_current.store(current_completed_count(), std::memory_order_release);
		}

		void reset_phase_ledger(int testlab_count, int total_estimate) {
			std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
			g_phase_ledger.clear();
			auto add = [](const char* name, int planned) {
				phase_ledger_entry_t entry;
				entry.name = name ? name : "";
				entry.planned = planned;
				entry.status = "PENDING";
				g_phase_ledger.push_back(std::move(entry));
			};
			add("launch target", kLaunchFeatureTests);
			add("standalone UI tests", kUiFeatureTests);
			add("testlab features", testlab_count);
			add("extended features", kExtendedFeatureTests);
			add("debugger feature tests", kDebuggerFeatureTests);
			add("scanner feature tests", kScannerFeatureTests);
			add("analysis feature tests", kAnalysisFeatureTests);
			add("network feature tests", kNetworkFeatureTests);
			add("burp suite feature tests", kBurpFeatureTests);
			add("disassembly & decompiler tests", kDisasmFeatureTests);
			add("MCP tool tests", kMcpFeatureTests);
			g_total.store(total_estimate, std::memory_order_release);
			g_current.store(0, std::memory_order_release);
			publish_active_phase_snapshot_locked(-1);
		}

		std::string phase_ledger_snapshot() {
			std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
			for (auto& entry : g_phase_ledger) {
				if (entry.entered && !entry.done)
					refresh_phase_entry_from_counters(entry);
			}
			publish_active_phase_snapshot_locked(g_active_phase_index.load(std::memory_order_acquire) - 1);
			std::string out;
			for (std::size_t i = 0; i < g_phase_ledger.size(); ++i) {
				const auto& e = g_phase_ledger[i];
				char part[320];
				_snprintf_s(part, sizeof(part), _TRUNCATE,
					"%zu:%s planned=%d completed=%d status=%s entered=%d done=%d pass=%d fail=%d skip=%d",
					i + 1,
					e.name.c_str(),
					e.planned,
					e.completed,
					e.status.empty() ? "PENDING" : e.status.c_str(),
					e.entered ? 1 : 0,
					e.done ? 1 : 0,
					e.pass_delta,
					e.fail_delta,
					e.skip_delta);
				if (!out.empty())
					out += "; ";
				out += part;
				if (out.size() > 760) {
					out += "; ...";
					break;
				}
			}
			return out;
		}

		bool phase_entered_snapshot(const char* phase) {
			std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
			const int index = phase_ledger_index_locked(phase);
			return index >= 0 && g_phase_ledger[static_cast<std::size_t>(index)].entered;
		}

		bool phase_done_snapshot(const char* phase) {
			std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
			const int index = phase_ledger_index_locked(phase);
			return index >= 0 && g_phase_ledger[static_cast<std::size_t>(index)].done;
		}

		void copy_label_snapshot(const std::shared_ptr<const std::string>& slot, char* out, std::size_t cap) {
			if (cap == 0) return;
			out[0] = '\0';
			const std::string value = load_label_snapshot(slot);
			_snprintf_s(out, cap, _TRUNCATE, "%s", value.empty() ? "<none>" : value.c_str());
		}

		void format_debug_snapshot_impl(char* out, std::size_t cap) {
			if (out == nullptr || cap == 0) return;

			char phase[192] = {};
			char step[256] = {};
			copy_label_snapshot(g_phase_label, phase, sizeof(phase));
			copy_label_snapshot(g_step_label, step, sizeof(step));

			const std::uint64_t now = now_ms_tick();
			const std::uint64_t run_start = g_run_start_tick.load(std::memory_order_acquire);
			const std::uint64_t phase_start = g_phase_start_tick.load(std::memory_order_acquire);
			const std::uint64_t step_start = g_step_start_tick.load(std::memory_order_acquire);
			const std::uint64_t run_age = (run_start != 0 && now >= run_start) ? (now - run_start) : 0;
			const std::uint64_t phase_age = (phase_start != 0 && now >= phase_start) ? (now - phase_start) : 0;
			const std::uint64_t step_age = (step_start != 0 && now >= step_start) ? (now - step_start) : 0;
			const auto cq = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::critical);
			const auto wq = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::general);
			const auto sq = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::service);
			char ui_phase[900] = {};
			format_ui_phase_snapshot(ui_phase, sizeof(ui_phase));
			const int global_completed = current_completed_count();
			g_current.store(global_completed, std::memory_order_release);
			const int active_phase_index = g_active_phase_index.load(std::memory_order_acquire);
			const int active_phase_planned = g_active_phase_planned.load(std::memory_order_acquire);
			const int active_phase_completed = g_active_phase_completed.load(std::memory_order_acquire);
			std::string ledger = phase_ledger_snapshot();

			_snprintf_s(out, cap, _TRUNCATE,
				"run_id=%llu host_pid=%lu host_tid=%lu running=%d cancel=%d target_unavailable=%d phase=\"%.160s\" phase_age_ms=%llu "
				"step=\"%.220s\" step_age_ms=%llu run_age_ms=%llu total=%d current=%d global_planned=%d global_completed=%d phase_index=%d phase_planned=%d phase_completed=%d "
				"pass=%d fail=%d skip=%d suspect=%d ui={%.620s} "
				"ledger={%.780s} "
				"cq_alive=%d cq_shutdown=%d cq_workers=%zu cq_pending=%zu cq_active=%u cq_active_labels=%u cq_oldest_active_ms=%llu cq_started=%llu cq_finished=%llu cq_labels=%.220s "
				"wq_alive=%d wq_shutdown=%d wq_workers=%zu wq_pending=%zu wq_active=%u wq_active_labels=%u wq_oldest_active_ms=%llu wq_started=%llu wq_finished=%llu wq_labels=%.220s "
				"svc_alive=%d svc_shutdown=%d svc_workers=%zu svc_pending=%zu svc_active=%u svc_active_labels=%u svc_oldest_active_ms=%llu svc_started=%llu svc_finished=%llu svc_labels=%.220s "
				"target_pid=%u driver_attached=%d "
				"image_base=0x%016llX target_addr=0x%016llX saved_dtb=0x%016llX",
				static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()),
				g_running.load(std::memory_order_acquire) ? 1 : 0,
				g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0,
				g_target_unavailable.load(std::memory_order_acquire) ? 1 : 0,
				phase,
				static_cast<unsigned long long>(phase_age),
				step,
				static_cast<unsigned long long>(step_age),
				static_cast<unsigned long long>(run_age),
				g_total.load(std::memory_order_acquire),
				global_completed,
				g_total.load(std::memory_order_acquire),
				global_completed,
				active_phase_index,
				active_phase_planned,
				active_phase_completed,
				g_passed.load(std::memory_order_acquire),
				g_failed.load(std::memory_order_acquire),
				g_skipped.load(std::memory_order_acquire),
				g_suspect.load(std::memory_order_acquire),
				ui_phase[0] ? ui_phase : "<empty>",
				ledger.empty() ? "<empty>" : ledger.c_str(),
				cq.alive ? 1 : 0,
				cq.shutting_down ? 1 : 0,
				cq.workers,
				cq.pending,
				static_cast<unsigned>(cq.active),
				cq.active_label_count,
				static_cast<unsigned long long>(cq.oldest_active_ms),
				static_cast<unsigned long long>(cq.started),
				static_cast<unsigned long long>(cq.finished),
				cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str(),
				wq.alive ? 1 : 0,
				wq.shutting_down ? 1 : 0,
				wq.workers,
				wq.pending,
				static_cast<unsigned>(wq.active),
				wq.active_label_count,
				static_cast<unsigned long long>(wq.oldest_active_ms),
				static_cast<unsigned long long>(wq.started),
				static_cast<unsigned long long>(wq.finished),
				wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str(),
				sq.alive ? 1 : 0,
				sq.shutting_down ? 1 : 0,
				sq.workers,
				sq.pending,
				static_cast<unsigned>(sq.active),
				sq.active_label_count,
				static_cast<unsigned long long>(sq.oldest_active_ms),
				static_cast<unsigned long long>(sq.started),
				static_cast<unsigned long long>(sq.finished),
				sq.active_labels.empty() ? "<none>" : sq.active_labels.c_str(),
				g_target_pid.load(std::memory_order_acquire),
				g_driver_attached.load(std::memory_order_acquire) ? 1 : 0,
				static_cast<unsigned long long>(g_target_image_base.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(g_target_addr.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(g_saved_dtb.load(std::memory_order_acquire)));
		}

		void log_debug_snapshot(HANDLE hf, const char* tag, const char* prefix) {
			char snap[2200] = {};
			format_debug_snapshot_impl(snap, sizeof(snap));
			log_msg(hf, tag ? tag : "snapshot", "%s%s%s",
				prefix ? prefix : "snapshot",
				(prefix && *prefix) ? " | " : "",
				snap);
		}

		DWORD process_thread_count(DWORD pid, DWORD* err_out) {
			if (err_out) *err_out = 0;
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snap == INVALID_HANDLE_VALUE) {
				if (err_out) *err_out = GetLastError();
				return 0;
			}
			THREADENTRY32 te = {};
			te.dwSize = sizeof(te);
			DWORD count = 0;
			if (Thread32First(snap, &te)) {
				do {
					if (te.th32OwnerProcessID == pid)
						++count;
					te.dwSize = sizeof(te);
				} while (Thread32Next(snap, &te));
			} else if (err_out) {
				*err_out = GetLastError();
			}
			CloseHandle(snap);
			return count;
		}

		void format_resource_snapshot_impl(char* out, std::size_t cap, DWORD captured_last_error) {
			if (out == nullptr || cap == 0) return;

			const DWORD pid = GetCurrentProcessId();
			const DWORD tid = GetCurrentThreadId();
			DWORD thread_err = 0;
			const DWORD threads = process_thread_count(pid, &thread_err);
			DWORD handles = 0;
			const BOOL handle_ok = GetProcessHandleCount(GetCurrentProcess(), &handles);
			const DWORD handle_err = handle_ok ? 0UL : GetLastError();

			PROCESS_MEMORY_COUNTERS_EX pmc = {};
			pmc.cb = sizeof(pmc);
			const BOOL mem_ok = GetProcessMemoryInfo(
				GetCurrentProcess(),
				reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
				sizeof(pmc));
			const DWORD mem_err = mem_ok ? 0UL : GetLastError();

			char debug[2200] = {};
			format_debug_snapshot_impl(debug, sizeof(debug));
			const std::uint64_t now = now_ms_tick();
			const std::uint64_t run_start = g_run_start_tick.load(std::memory_order_acquire);
			const std::uint64_t elapsed = (run_start != 0 && now >= run_start) ? (now - run_start) : 0;

			_snprintf_s(out, cap, _TRUNCATE,
				"pid=%lu tid=%lu tick_ms=%llu run_elapsed_ms=%llu last_error=%lu "
				"threads=%lu thread_err=%lu handles=%lu handle_ok=%d handle_err=%lu "
				"mem_ok=%d mem_err=%lu working_set=%llu peak_working_set=%llu "
				"pagefile_usage=%llu private_usage=%llu debug_snapshot={%s}",
				static_cast<unsigned long>(pid),
				static_cast<unsigned long>(tid),
				static_cast<unsigned long long>(now),
				static_cast<unsigned long long>(elapsed),
				static_cast<unsigned long>(captured_last_error),
				static_cast<unsigned long>(threads),
				static_cast<unsigned long>(thread_err),
				static_cast<unsigned long>(handles),
				handle_ok ? 1 : 0,
				static_cast<unsigned long>(handle_err),
				mem_ok ? 1 : 0,
				static_cast<unsigned long>(mem_err),
				static_cast<unsigned long long>(mem_ok ? pmc.WorkingSetSize : 0),
				static_cast<unsigned long long>(mem_ok ? pmc.PeakWorkingSetSize : 0),
				static_cast<unsigned long long>(mem_ok ? pmc.PagefileUsage : 0),
				static_cast<unsigned long long>(mem_ok ? pmc.PrivateUsage : 0),
				debug);
		}

		void log_resource_snapshot(HANDLE hf, const char* tag, const char* prefix, DWORD captured_last_error) {
			char snap[3000] = {};
			format_resource_snapshot_impl(snap, sizeof(snap), captured_last_error);
			log_msg(hf, tag ? tag : "resource", "%s%s%s",
				prefix ? prefix : "resource snapshot",
				(prefix && *prefix) ? " | " : "",
				snap);
		}

		void log_taskflow_runtime_snapshot(HANDLE hf, const char* tag, const char* prefix) {
			const auto st = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::critical);
			const auto wq = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::general);
			const auto sq = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::service);
			log_msg(hf, tag ? tag : "taskflow_runtime",
				"%s%scritical_alive=%d critical_shutting_down=%d critical_pool_size=%d critical_workers=%zu critical_pending=%zu critical_active=%u critical_post_attempts=%llu critical_posted=%llu critical_rejected=%llu critical_started=%llu critical_finished=%llu "
				"work_alive=%d work_shutting_down=%d work_pool_size=%d work_workers=%zu work_pending=%zu work_active=%u work_post_attempts=%llu work_posted=%llu work_rejected=%llu work_started=%llu work_finished=%llu "
				"service_alive=%d service_shutting_down=%d service_pool_size=%d service_workers=%zu service_pending=%zu service_active=%u service_post_attempts=%llu service_posted=%llu service_rejected=%llu service_started=%llu service_finished=%llu",
				prefix ? prefix : "taskflow runtime snapshot",
				(prefix && *prefix) ? " | " : "",
				st.alive ? 1 : 0,
				st.shutting_down ? 1 : 0,
				st.pool_size,
				st.workers,
				st.pending,
				static_cast<unsigned>(st.active),
				static_cast<unsigned long long>(st.post_attempts),
				static_cast<unsigned long long>(st.posted),
				static_cast<unsigned long long>(st.rejected),
				static_cast<unsigned long long>(st.started),
				static_cast<unsigned long long>(st.finished),
				wq.alive ? 1 : 0,
				wq.shutting_down ? 1 : 0,
				wq.pool_size,
				wq.workers,
				wq.pending,
				static_cast<unsigned>(wq.active),
				static_cast<unsigned long long>(wq.post_attempts),
				static_cast<unsigned long long>(wq.posted),
				static_cast<unsigned long long>(wq.rejected),
				static_cast<unsigned long long>(wq.started),
				static_cast<unsigned long long>(wq.finished),
				sq.alive ? 1 : 0,
				sq.shutting_down ? 1 : 0,
				sq.pool_size,
				sq.workers,
				sq.pending,
				static_cast<unsigned>(sq.active),
				static_cast<unsigned long long>(sq.post_attempts),
				static_cast<unsigned long long>(sq.posted),
				static_cast<unsigned long long>(sq.rejected),
				static_cast<unsigned long long>(sq.started),
				static_cast<unsigned long long>(sq.finished));
		}

		void set_full_test_env(HANDLE hf, bool enabled, const char* reason) {
			BOOL ok = SetEnvironmentVariableA(kFullTestEnvName, enabled ? "1" : nullptr);
			DWORD err = ok ? 0UL : GetLastError();
			log_msg(hf, "env", "%s %s ok=%d err=%lu",
				enabled ? "set" : "clear",
				kFullTestEnvName,
				ok ? 1 : 0,
				static_cast<unsigned long>(err));
			diag::log_tagged_fmt("test_all", "%s %s reason=%s ok=%d err=%lu",
				enabled ? "set" : "clear",
				kFullTestEnvName,
				reason ? reason : "",
				ok ? 1 : 0,
				static_cast<unsigned long>(err));
		}

		bool full_test_env_active() {
			char value[16] = {};
			DWORD n = GetEnvironmentVariableA(kFullTestEnvName, value, static_cast<DWORD>(sizeof(value)));
			if (n == 0)
				return false;
			if (n >= sizeof(value))
				return true;
			return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
		}

		const char* camoufox_bridge_state_name(aida::burp::camoufox::bridge_state_t state) {
			using state_t = aida::burp::camoufox::bridge_state_t;
			switch (state) {
				case state_t::stopped: return "stopped";
				case state_t::starting: return "starting";
				case state_t::ready: return "ready";
				case state_t::error: return "error";
			}
			return "unknown";
		}

		void cleanup_camoufox_for_full_test_start(HANDLE hf, const char* reason) {
			auto before = aida::burp::camoufox::get_status();
			const bool active = before.state != aida::burp::camoufox::bridge_state_t::stopped ||
				before.child_pid != 0 ||
				before.cleanup_pending ||
				before.child_alive ||
				before.browser_open ||
				before.page_verified ||
				before.privacy_verified ||
				!before.last_error.empty();
			const bool healthy = before.state == aida::burp::camoufox::bridge_state_t::ready &&
				before.child_alive &&
				before.browser_open &&
				before.page_verified &&
				before.privacy_verified &&
				!before.cleanup_pending &&
				before.last_error.empty();
			log_msg(hf, "camoufox-cleanup", "preflight reason=%s active=%d healthy=%d state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d last_error_len=%zu",
				reason ? reason : "unspecified",
				active ? 1 : 0,
				healthy ? 1 : 0,
				camoufox_bridge_state_name(before.state),
				before.child_pid,
				before.child_alive ? 1 : 0,
				before.browser_open ? 1 : 0,
				before.page_verified ? 1 : 0,
				before.privacy_verified ? 1 : 0,
				before.cleanup_pending ? 1 : 0,
				before.last_error.size());
			if (healthy) {
				log_msg(hf, "camoufox-cleanup", "preflight_reuse reason=%s state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d generation=%llu page_count=%u browser_instances=%u child_processes=%u browser_processes=%u last_error_len=%zu",
					reason ? reason : "unspecified",
					camoufox_bridge_state_name(before.state),
					before.child_pid,
					before.child_alive ? 1 : 0,
					before.browser_open ? 1 : 0,
					before.page_verified ? 1 : 0,
					before.privacy_verified ? 1 : 0,
					before.cleanup_pending ? 1 : 0,
					static_cast<unsigned long long>(before.generation),
					before.page_count,
					before.browser_instance_count,
					before.child_process_count,
					before.browser_process_count,
					before.last_error.size());
				return;
			}
			if (!active)
				return;
			const uint64_t t0 = now_ms_tick();
			const bool cleaned = aida::burp::camoufox::force_cleanup(reason ? reason : "testlab.start_tests_preflight");
			const bool starting_without_child = before.state == aida::burp::camoufox::bridge_state_t::starting &&
				before.child_pid == 0 &&
				!before.child_alive &&
				!before.browser_open;
			const uint32_t idle_wait_ms = starting_without_child ? 1000u : 15000u;
			log_msg(hf, "camoufox-cleanup", "preflight_force_cleanup_done reason=%s cleaned=%d wait_ms=%u starting_without_child=%d elapsed_ms=%llu",
				reason ? reason : "unspecified",
				cleaned ? 1 : 0,
				idle_wait_ms,
				starting_without_child ? 1 : 0,
				static_cast<unsigned long long>(now_ms_tick() - t0));
			const bool idle = aida::burp::camoufox::wait_until_idle(idle_wait_ms, reason ? reason : "testlab.start_tests_preflight");
			auto after = aida::burp::camoufox::get_status();
			log_msg(hf, "camoufox-cleanup", "preflight_done reason=%s cleaned=%d idle=%d wait_ms=%u state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d elapsed_ms=%llu last_error_len=%zu",
				reason ? reason : "unspecified",
				cleaned ? 1 : 0,
				idle ? 1 : 0,
				idle_wait_ms,
				camoufox_bridge_state_name(after.state),
				after.child_pid,
				after.child_alive ? 1 : 0,
				after.browser_open ? 1 : 0,
				after.page_verified ? 1 : 0,
				after.privacy_verified ? 1 : 0,
				after.cleanup_pending ? 1 : 0,
				static_cast<unsigned long long>(now_ms_tick() - t0),
				after.last_error.size());
		}

		void begin_test_guard_impl(const char* source, HANDLE hf = INVALID_HANDLE_VALUE) {
			const std::uint32_t previous_depth = g_full_test_guard_depth.fetch_add(1u, std::memory_order_acq_rel);
			g_full_test_guard_active.store(true, std::memory_order_release);
			log_msg(hf, "env", "full_test_guard_enter source=%s pid=%lu tid=%lu tick64=%llu user_default_skip_load=%d",
				source ? source : "unspecified",
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()),
				static_cast<unsigned long long>(GetTickCount64()),
				pdb_default_skip::get() ? 1 : 0);
			if (previous_depth == 0)
				set_full_test_env(hf, true, source ? source : "full_test_guard_enter");
		}

		void end_test_guard_impl(const char* source, HANDLE hf = INVALID_HANDLE_VALUE) {
			log_msg(hf, "env", "full_test_guard_exit source=%s pid=%lu tid=%lu tick64=%llu user_default_skip_load=%d",
				source ? source : "unspecified",
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()),
				static_cast<unsigned long long>(GetTickCount64()),
				pdb_default_skip::get() ? 1 : 0);
			std::uint32_t depth = g_full_test_guard_depth.load(std::memory_order_acquire);
			while (depth != 0 && !g_full_test_guard_depth.compare_exchange_weak(depth, depth - 1u,
				std::memory_order_acq_rel, std::memory_order_acquire)) {}
			if (depth == 1u) {
				set_full_test_env(hf, false, source ? source : "full_test_guard_exit");
				g_full_test_guard_active.store(false, std::memory_order_release);
			}
		}

		void set_step(const char* label) {
			store_label_snapshot(g_step_label, label);
			g_step_start_tick.store(now_ms_tick(), std::memory_order_release);
			g_hung_marker_emitted.store(false, std::memory_order_release);
			const std::string phase_label = load_label_snapshot(g_phase_label);
			aida::diagnostics::testlab::emit_testlab_breadcrumb(phase_label.c_str(), label, true);
		}

		void set_stepf(const char* fmt, ...) {
			char detail[256];
			va_list ap;
			va_start(ap, fmt);
			_vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
			va_end(ap);
			set_step(detail);
		}

		void cleanup_network_runtime(HANDLE hf, const char* reason) {
			set_stepf("network cleanup: %s", reason ? reason : "unspecified");
			log_debug_snapshot(hf, "net-cleanup", "ENTRY");
			bool proxy_running = mitm_proxy::is_running();
			log_msg(hf, "net-cleanup", "local MITM proxy running=%d before cleanup (%s)",
				proxy_running ? 1 : 0, reason ? reason : "unspecified");
			if (proxy_running) {
				mitm_proxy::drop_all();
				mitm_proxy::stop();
				log_msg(hf, "net-cleanup", "local MITM proxy stop/drop attempted; running=%d",
					mitm_proxy::is_running() ? 1 : 0);
			}

			if (!device || !device->is_connected()) {
				log_msg(hf, "net-cleanup", "SKIP -- driver not connected (%s)",
					reason ? reason : "unspecified");
				log_debug_snapshot(hf, "net-cleanup", "EXIT skipped");
				return;
			}

			log_msg(hf, "net-cleanup", "BEGIN -- clearing stateful WFP/test modes (%s)",
				reason ? reason : "unspecified");

			auto send_cleanup = [&](const char* name, DWORD code, void* req, std::size_t size) {
				std::uint32_t bytes_returned = 0;
				bool ok = device->send_ioctl_raw(code, req, static_cast<std::uint32_t>(size), bytes_returned);
				log_msg(hf, "net-cleanup", "%s ok=%d bytes=%u",
					name, ok ? 1 : 0, bytes_returned);
			};

			voyager::detail::net_cap_ctrl_request cap{};
			cap.operation = 1u;
			send_cleanup("NCAP stop", ioctl_codes::NCAP(), &cap, sizeof(cap));

			voyager::detail::intercept_request ihld{};
			ihld.operation = 1u;
			send_cleanup("IHLD stop+drop-held", ioctl_codes::IHLD(), &ihld, sizeof(ihld));

			voyager::detail::net_filter_rule_request filter{};
			filter.operation = 2u;
			send_cleanup("NFLT clear", ioctl_codes::NFLT(), &filter, sizeof(filter));

			bool mod_clear = driver_bridge::packet_mod_rule_op(3);
			log_msg(hf, "net-cleanup", "PMOD clear ok=%d", mod_clear ? 1 : 0);

			bool redir_clear = driver_bridge::traffic_redirect_op(3);
			log_msg(hf, "net-cleanup", "PRED clear ok=%d", redir_clear ? 1 : 0);

			bool stream_clear = driver_bridge::stream_reassemble_op(4);
			log_msg(hf, "net-cleanup", "STRM clear ok=%d", stream_clear ? 1 : 0);

			voyager::detail::dns_spoof_rule dns{};
			dns.operation = 3u;
			send_cleanup("DNSS clear", ioctl_codes::DNSS(), &dns, sizeof(dns));

			voyager::detail::net_fingerprint_request fp{};
			fp.operation = 1u;
			send_cleanup("NFPR stop", ioctl_codes::NFPR(), &fp, sizeof(fp));

			voyager::detail::bw_monitor_request bw{};
			bw.operation = 1u;
			send_cleanup("BWMN stop", ioctl_codes::BWMN(), &bw, sizeof(bw));
			bw = {};
			bw.operation = 3u;
			send_cleanup("BWMN reset", ioctl_codes::BWMN(), &bw, sizeof(bw));

			log_msg(hf, "net-cleanup", "END -- stateful network cleanup attempted");
			log_debug_snapshot(hf, "net-cleanup", "EXIT");
		}

		void set_phase(const char* label) {
			store_label_snapshot(g_phase_label, label);
			aida::diagnostics::testlab::emit_testlab_breadcrumb(label, "phase_begin", true);
			g_phase_start_tick.store(now_ms_tick(), std::memory_order_release);
		}

		bool cancelled() {
			return g_cancel_requested.load(std::memory_order_acquire);
		}

		int running_done() {
			return current_completed_count();
		}

		bool memory_scanner_scan_idle() {
			auto& st = memory_scanner::g_state;
			return !st.scanning.load(std::memory_order_acquire) &&
				st.scan_thread_done.load(std::memory_order_acquire);
		}

		bool memory_scanner_all_idle() {
			auto& st = memory_scanner::g_state;
			return memory_scanner_scan_idle() &&
				!st.pointer_scanning.load(std::memory_order_acquire) &&
				st.pointer_thread_done.load(std::memory_order_acquire);
		}

		void request_memory_scanner_stop() {
			auto& st = memory_scanner::g_state;
			st.scanning.store(false, std::memory_order_release);
			st.pointer_scanning.store(false, std::memory_order_release);
		}

		bool wait_memory_scanner_scan_idle(DWORD timeout_ms) {
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			while (!memory_scanner_scan_idle()) {
				if (now_ms_tick() >= deadline) return memory_scanner_scan_idle();
				Sleep(10);
			}
			return true;
		}

		bool wait_memory_scanner_all_idle(DWORD timeout_ms) {
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			while (!memory_scanner_all_idle()) {
				if (now_ms_tick() >= deadline) return memory_scanner_all_idle();
				Sleep(10);
			}
			return true;
		}

		bool snapshot_memory_scan_results(std::size_t& found, std::uint64_t& first_addr, DWORD timeout_ms) {
			auto& st = memory_scanner::g_state;
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			for (;;) {
				try {
					if (st.results_mutex.try_lock()) {
						std::lock_guard<std::mutex> lk(st.results_mutex, std::adopt_lock);
						found = st.results.size();
						first_addr = st.results.empty() ? 0 : st.results.front().address;
						return true;
					}
				} catch (...) {
					return false;
				}
				if (now_ms_tick() >= deadline) return false;
				Sleep(5);
			}
		}

		void cleanup_memory_scanner_runtime(HANDLE hf, const char* reason, DWORD timeout_ms) {
			auto& st = memory_scanner::g_state;
			const bool active =
				st.scanning.load(std::memory_order_acquire) ||
				!st.scan_thread_done.load(std::memory_order_acquire) ||
				st.pointer_scanning.load(std::memory_order_acquire) ||
				!st.pointer_thread_done.load(std::memory_order_acquire);
			if (!active) return;

			log_msg(hf, "memscan-cleanup",
				"BEGIN -- %s scanning=%d scan_done=%d pointer_scanning=%d pointer_done=%d",
				reason ? reason : "unspecified",
				st.scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0);

			request_memory_scanner_stop();
			const bool idle = wait_memory_scanner_all_idle(timeout_ms);

			log_msg(hf, "memscan-cleanup",
				"END -- %s idle=%d scanning=%d scan_done=%d pointer_scanning=%d pointer_done=%d",
				reason ? reason : "unspecified",
				idle ? 1 : 0,
				st.scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0);
		}

		void log_phase_begin(HANDLE hf, const char* phase) {
			const std::uint64_t now = now_ms_tick();
			int phase_index = 0;
			int phase_planned = 0;
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				int index = phase_ledger_index_locked(phase);
				if (index < 0) {
					phase_ledger_entry_t entry;
					entry.name = phase ? phase : "";
					entry.status = "PENDING";
					g_phase_ledger.push_back(std::move(entry));
					index = static_cast<int>(g_phase_ledger.size()) - 1;
				}
				auto& entry = g_phase_ledger[static_cast<std::size_t>(index)];
				entry.entered = true;
				entry.done = false;
				entry.start_ms = now;
				entry.end_ms = 0;
				entry.start_passed = g_passed.load(std::memory_order_acquire);
				entry.start_failed = g_failed.load(std::memory_order_acquire);
				entry.start_skipped = g_skipped.load(std::memory_order_acquire);
				entry.pass_delta = 0;
				entry.fail_delta = 0;
				entry.skip_delta = 0;
				entry.completed = 0;
				entry.status = "ACTIVE";
				phase_index = index + 1;
				phase_planned = entry.planned;
				publish_active_phase_snapshot_locked(index);
			}
			log_msg(hf, "phase", "BEGIN %s | phase_index=%d phase_planned=%d phase_completed=0 global_planned=%d global_completed=%d running totals pass=%d fail=%d skip=%d done=%d",
				phase,
				phase_index,
				phase_planned,
				g_total.load(std::memory_order_acquire),
				running_done(),
				g_passed.load(),
				g_failed.load(),
				g_skipped.load(),
				running_done());
			log_debug_snapshot(hf, "phase", "BEGIN snapshot");
		}

		void log_phase_end(HANDLE hf, const char* phase) {
			const std::uint64_t now = now_ms_tick();
			int phase_index = 0;
			int phase_planned = 0;
			int phase_completed = 0;
			int pass_delta = 0;
			int fail_delta = 0;
			int skip_delta = 0;
			std::string status = "DONE";
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				int index = phase_ledger_index_locked(phase);
				if (index < 0) {
					phase_ledger_entry_t entry;
					entry.name = phase ? phase : "";
					entry.status = "DONE_UNPLANNED";
					entry.entered = true;
					entry.done = true;
					entry.start_ms = now;
					entry.end_ms = now;
					g_phase_ledger.push_back(std::move(entry));
					index = static_cast<int>(g_phase_ledger.size()) - 1;
				}
				auto& entry = g_phase_ledger[static_cast<std::size_t>(index)];
				refresh_phase_entry_from_counters(entry);
				entry.done = true;
				entry.end_ms = now;
				if (entry.hung_logged)
					entry.status = "DONE_AFTER_HUNG";
				else if (entry.status != "PREREQUISITE_FAILED")
					entry.status = "DONE";
				phase_index = index + 1;
				phase_planned = entry.planned;
				phase_completed = entry.completed;
				pass_delta = entry.pass_delta;
				fail_delta = entry.fail_delta;
				skip_delta = entry.skip_delta;
				status = entry.status;
				publish_active_phase_snapshot_locked(-1);
			}
			log_msg(hf, "phase", "END %s | phase_index=%d phase_status=%s phase_planned=%d phase_completed=%d phase_pass=%d phase_fail=%d phase_skip=%d global_planned=%d global_completed=%d running totals pass=%d fail=%d skip=%d done=%d",
				phase,
				phase_index,
				status.empty() ? "DONE" : status.c_str(),
				phase_planned,
				phase_completed,
				pass_delta,
				fail_delta,
				skip_delta,
				g_total.load(std::memory_order_acquire),
				running_done(),
				g_passed.load(),
				g_failed.load(),
				g_skipped.load(),
				running_done());
			if (skip_delta != 0 && phase != nullptr && std::strcmp(phase, "testlab features") != 0 && status != "PREREQUISITE_FAILED") {
				log_msg(hf, "phase",
					"FAIL -- phase '%s' produced %d non-destructive SKIP(s); only 'testlab features' may emit SKIPs - converting to FAIL immediately pid=%lu tid=%lu now_ms=%llu passed=%d failed=%d skipped_before_convert=%d",
					phase,
					skip_delta,
					static_cast<unsigned long>(GetCurrentProcessId()),
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(GetTickCount64()),
					g_passed.load(std::memory_order_acquire),
					g_failed.load(std::memory_order_acquire),
					g_skipped.load(std::memory_order_acquire));
				g_skipped.fetch_sub(skip_delta, std::memory_order_acq_rel);
				g_failed.fetch_add(skip_delta, std::memory_order_acq_rel);
			}
			log_debug_snapshot(hf, "phase", "END snapshot");
		}

		void log_hung_heartbeat_if_needed(HANDLE hf) {
			if (!g_running.load(std::memory_order_acquire))
				return;
			const std::uint64_t step_start = g_step_start_tick.load(std::memory_order_acquire);
			const std::uint64_t now = now_ms_tick();
			if (step_start == 0 || now < step_start || now - step_start < kFullTestHungStepMs)
				return;
			bool expected = false;
			if (!g_hung_marker_emitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
				return;
			const std::string phase = load_label_snapshot(g_phase_label);
			const std::string step = load_label_snapshot(g_step_label);
			int phase_index = 0;
			int phase_planned = 0;
			int phase_completed = 0;
			int mcp_entered = 0;
			int mcp_done = 0;
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				int index = phase_ledger_index_locked(phase.c_str());
				if (index >= 0) {
					auto& entry = g_phase_ledger[static_cast<std::size_t>(index)];
					refresh_phase_entry_from_counters(entry);
					entry.hung_logged = true;
					entry.status = "HUNG";
					phase_index = index + 1;
					phase_planned = entry.planned;
					phase_completed = entry.completed;
					publish_active_phase_snapshot_locked(index);
				}
				const int mcp_index = phase_ledger_index_locked("MCP tool tests");
				if (mcp_index >= 0) {
					const auto& mcp = g_phase_ledger[static_cast<std::size_t>(mcp_index)];
					mcp_entered = mcp.entered ? 1 : 0;
					mcp_done = mcp.done ? 1 : 0;
				}
			}
			log_msg(hf, "heartbeat", "HUNG -- step exceeded heartbeat threshold phase_index=%d phase=\"%s\" step=\"%s\" step_age_ms=%llu threshold_ms=%llu phase_planned=%d phase_completed=%d global_planned=%d global_completed=%d mcp_planned=%d mcp_entered=%d mcp_done=%d",
				phase_index,
				phase.empty() ? "<none>" : phase.c_str(),
				step.empty() ? "<none>" : step.c_str(),
				static_cast<unsigned long long>(now - step_start),
				static_cast<unsigned long long>(kFullTestHungStepMs),
				phase_planned,
				phase_completed,
				g_total.load(std::memory_order_acquire),
				running_done(),
				kMcpFeatureTests,
				mcp_entered,
				mcp_done);
			{
				aida::diagnostics::testlab::hung_packet_context_t pkt_ctx;
				pkt_ctx.test_run_id = g_run_id.load(std::memory_order_acquire);
				pkt_ctx.suite = "full_test";
				pkt_ctx.domain = phase.c_str();
				pkt_ctx.test_name = step.c_str();
				pkt_ctx.phase = phase.c_str();
				pkt_ctx.step_label = step.c_str();
				pkt_ctx.step_start_ms = step_start;
				pkt_ctx.step_elapsed_ms = now - step_start;
				pkt_ctx.target_pid = current_target_pid();
				pkt_ctx.driver_attached = g_driver_attached.load(std::memory_order_acquire);
				pkt_ctx.cancellation_requested = g_cancel_requested.load(std::memory_order_acquire);
				pkt_ctx.shutdown_requested = false;
				std::string target_path_snap;
				std::string requested_cwd_snap;
				std::string effective_cwd_snap;
				{
					std::lock_guard<std::mutex> lk(g_launch_state_mtx);
					target_path_snap = g_target_executable_path;
					requested_cwd_snap = g_requested_cwd;
					effective_cwd_snap = g_effective_cwd;
				}
				pkt_ctx.target_executable_path = target_path_snap.c_str();
				pkt_ctx.requested_cwd = requested_cwd_snap.c_str();
				pkt_ctx.effective_cwd = effective_cwd_snap.c_str();
				pkt_ctx.mcp_active_requests = mcp_standalone::active_http_request_count();
				pkt_ctx.mcp_active_leases = mcp_standalone::active_tool_lease_count();
				char downstream_buf[512] = {};
				try {
					auto ds_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
					_snprintf_s(downstream_buf, sizeof(downstream_buf), _TRUNCATE,
						"total_active=%zu total_rejected=%zu shutdown_pending=%zu",
						ds_snap.total_active,
						ds_snap.total_rejected,
						ds_snap.shutdown_pending);
				} catch (...) {
					_snprintf_s(downstream_buf, sizeof(downstream_buf), _TRUNCATE,
						"snapshot_exception=1");
				}
				pkt_ctx.downstream_summary = downstream_buf;
				pkt_ctx.ui_dispatcher_backlog = aida::ui_thread::pending_count();
				auto wq_stats = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::general);
				char wq_buf[512] = {};
				_snprintf_s(wq_buf, sizeof(wq_buf), _TRUNCATE,
					"alive=%d active=%u pending=%zu started=%llu finished=%llu rejected=%llu oldest_ms=%llu",
					wq_stats.alive ? 1 : 0, wq_stats.active, wq_stats.pending,
					static_cast<unsigned long long>(wq_stats.started),
					static_cast<unsigned long long>(wq_stats.finished),
					static_cast<unsigned long long>(wq_stats.rejected),
					static_cast<unsigned long long>(wq_stats.oldest_active_ms));
				pkt_ctx.work_queue_snapshot = wq_buf;
				auto cq_stats = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::critical);
				char cq_buf[512] = {};
				_snprintf_s(cq_buf, sizeof(cq_buf), _TRUNCATE,
					"alive=%d active=%u pending=%zu started=%llu finished=%llu rejected=%llu oldest_ms=%llu",
					cq_stats.alive ? 1 : 0, cq_stats.active, cq_stats.pending,
					static_cast<unsigned long long>(cq_stats.started),
					static_cast<unsigned long long>(cq_stats.finished),
					static_cast<unsigned long long>(cq_stats.rejected),
					static_cast<unsigned long long>(cq_stats.oldest_active_ms));
				pkt_ctx.critical_queue_snapshot = cq_buf;
				pkt_ctx.driver_watchdog_ms = driver_bridge::watchdog_last_ok_tick();
				std::string first_failure_snap;
				std::string last_success_snap;
				{
					std::lock_guard<std::mutex> lk(g_test_marker_mtx);
					first_failure_snap = g_first_failure_marker;
					last_success_snap = g_last_successful_marker;
				}
				pkt_ctx.first_failure_marker = first_failure_snap.c_str();
				pkt_ctx.last_successful_marker = last_success_snap.c_str();
				aida::diagnostics::testlab::log_hung_diagnostic_packet(pkt_ctx);
			}
			g_cancel_requested.store(true, std::memory_order_release);
			log_msg(hf, "heartbeat", "CANCEL -- full test cancellation requested after HUNG step detected step_age_ms=%llu threshold_ms=%llu",
				static_cast<unsigned long long>(now - step_start),
				static_cast<unsigned long long>(kFullTestHungStepMs));
		}

		int finalize_phase_ledger(HANDLE hf) {
			int errors = 0;
			std::vector<phase_ledger_entry_t> snapshot;
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				for (auto& entry : g_phase_ledger) {
					if (entry.entered && !entry.done)
						refresh_phase_entry_from_counters(entry);
				}
				snapshot = g_phase_ledger;
				publish_active_phase_snapshot_locked(-1);
			}
			for (std::size_t i = 0; i < snapshot.size(); ++i) {
				const auto& entry = snapshot[i];
				const int remaining = entry.planned > entry.completed ? entry.planned - entry.completed : 0;
				log_msg(hf, "summary", "PHASE-LEDGER -- phase_index=%zu phase=\"%s\" planned=%d completed=%d pass=%d fail=%d skip=%d entered=%d done=%d hung=%d status=%s remaining=%d",
					i + 1,
					entry.name.c_str(),
					entry.planned,
					entry.completed,
					entry.pass_delta,
					entry.fail_delta,
					entry.skip_delta,
					entry.entered ? 1 : 0,
					entry.done ? 1 : 0,
					entry.hung_logged ? 1 : 0,
					entry.status.empty() ? "PENDING" : entry.status.c_str(),
					remaining);
				if (!entry.entered) {
					++errors;
					log_msg(hf, "summary", "INCOMPLETE -- planned phase was not entered phase_index=%zu phase=\"%s\" planned=%d global_completed=%d global_planned=%d",
						i + 1,
						entry.name.c_str(),
						entry.planned,
						running_done(),
						g_total.load(std::memory_order_acquire));
				} else if (!entry.done) {
					++errors;
					log_msg(hf, "summary", "INCOMPLETE -- phase entered but did not complete phase_index=%zu phase=\"%s\" planned=%d completed=%d remaining=%d",
						i + 1,
						entry.name.c_str(),
						entry.planned,
						entry.completed,
						remaining);
					if (entry.name == "MCP tool tests")
						log_mcp_phase_remaining_diagnostics(hf, remaining);
				} else if (remaining > 0) {
					++errors;
					log_msg(hf, "summary", "INCOMPLETE -- phase completed fewer tests than planned phase_index=%zu phase=\"%s\" planned=%d completed=%d remaining=%d",
						i + 1,
						entry.name.c_str(),
						entry.planned,
						entry.completed,
						remaining);
					if (entry.name == "MCP tool tests")
						log_mcp_phase_remaining_diagnostics(hf, remaining);
				}
				if (entry.hung_logged) {
					++errors;
					log_msg(hf, "summary", "HUNG -- phase exceeded heartbeat threshold phase_index=%zu phase=\"%s\" status=%s planned=%d completed=%d",
						i + 1,
						entry.name.c_str(),
						entry.status.empty() ? "HUNG" : entry.status.c_str(),
						entry.planned,
						entry.completed);
				}
			}
			if (kMcpFeatureTests > 0) {
				if (!phase_entered_snapshot("MCP tool tests")) {
					log_msg(hf, "summary", "INCOMPLETE -- MCP phase planned but not entered planned=%d global_completed=%d global_planned=%d",
						kMcpFeatureTests,
						running_done(),
						g_total.load(std::memory_order_acquire));
				} else if (!phase_done_snapshot("MCP tool tests")) {
					log_msg(hf, "summary", "INCOMPLETE -- MCP phase entered but did not reach phase end planned=%d global_completed=%d global_planned=%d",
						kMcpFeatureTests,
						running_done(),
						g_total.load(std::memory_order_acquire));
				}
			}
			return errors;
		}

		bool target_unavailable() {
			return g_target_unavailable.load(std::memory_order_acquire);
		}

		void mark_target_unavailable(HANDLE hf, const char* tag, const char* reason, std::uint32_t pid, std::uint32_t attached, std::uint32_t exit_code) {
			g_driver_attached.store(false, std::memory_order_release);
			g_target_unavailable.store(true, std::memory_order_release);
			log_msg(hf, tag ? tag : "target-live", "TARGET-UNAVAILABLE -- %s pid=%u attached=%u exit_code_or_err=0x%08X",
				reason ? reason : "target unavailable",
				pid,
				attached,
				exit_code);
		}

		void skip_phase_target_unavailable(HANDLE hf, const char* phase, int tests) {
			const char* label = phase ? phase : "target-dependent phase";
			set_phase(label);
			set_stepf("skip phase: %s", label);
			log_phase_begin(hf, label);
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				const int index = phase_ledger_index_locked(label);
				if (index >= 0)
					g_phase_ledger[static_cast<std::size_t>(index)].status = "PREREQUISITE_FAILED";
			}
			if (tests > 0) {
				g_skipped.fetch_add(tests);
				g_prerequisite_skipped.fetch_add(tests);
			}
			log_msg(hf, "phase", "SKIP -- %s requires a live attached target; prerequisite failed; skipped=%d",
				label,
				tests);
			log_phase_end(hf, label);
		}


		bool is_destructive(const char* category, const char* name) {
			return test_lab::is_destructive_guarded_feature(category, name);
		}

		const char* destructive_reason(const char* category, const char* name) {
			const char* reason = test_lab::destructive_guard_reason(category, name);
			return reason ? reason : "unknown destructive guard";
		}

		std::string skip_key_string(const char* category, const char* name) {
			std::string out = category ? category : "?";
			out += "/";
			out += name ? name : "?";
			return out;
		}

		int expected_destructive_skip_index(const char* category, const char* name) {
			if (category == nullptr || name == nullptr)
				return -1;
			for (int i = 0; i < kExpectedDestructiveSkipCount; ++i) {
				if (std::strcmp(category, kExpectedDestructiveSkipKeys[i].category) == 0 &&
					std::strcmp(name, kExpectedDestructiveSkipKeys[i].name) == 0)
					return i;
			}
			return -1;
		}

		void reset_destructive_skip_accounting() {
			for (int i = 0; i < kExpectedDestructiveSkipCount; ++i)
				g_expected_destructive_skip_seen[i] = false;
			g_expected_destructive_skip_seen_count = 0;
			g_unexpected_destructive_skip_count = 0;
			g_duplicate_destructive_skip_count = 0;
			g_unexpected_skip_records.clear();
		}

		bool record_destructive_skip_key(HANDLE hf, int ordinal, int total, const char* category, const char* name) {
			const char* reason = test_lab::destructive_guard_reason(category, name);
			const int expected_index = expected_destructive_skip_index(category, name);
			const std::string key = skip_key_string(category, name);
			if (expected_index < 0 || reason == nullptr) {
				++g_unexpected_destructive_skip_count;
				g_unexpected_skip_records.push_back(key + " reason=\"" + destructive_reason(category, name) + "\"");
				log_msg(hf, "testlab", "[%d/%d] FAIL %s unexpected destructive skip key reason=\"%s\"",
					ordinal, total, key.c_str(), destructive_reason(category, name));
				return false;
			}
			if (g_expected_destructive_skip_seen[expected_index]) {
				++g_duplicate_destructive_skip_count;
				g_unexpected_skip_records.push_back(key + " reason=\"duplicate expected destructive skip\"");
				log_msg(hf, "testlab", "[%d/%d] FAIL %s duplicate destructive skip key reason=\"%s\" expected_index=%d",
					ordinal, total, key.c_str(), reason, expected_index);
				return false;
			}
			const int before = g_skipped.load(std::memory_order_acquire);
			const int after = g_skipped.fetch_add(1, std::memory_order_acq_rel) + 1;
			g_expected_destructive_skip_seen[expected_index] = true;
			++g_expected_destructive_skip_seen_count;
			log_msg(hf, "testlab", "[%d/%d] SKIP %s expected_destructive_key=1 expected_index=%d reason=\"%s\" skip_before=%d skip_after=%d",
				ordinal, total, key.c_str(), expected_index, reason, before, after);
			return true;
		}

		int log_destructive_skip_accounting(HANDLE hf, const char* tag, const char* scope, bool final_accounting) {
			const char* safe_tag = tag ? tag : "summary";
			const char* safe_scope = scope ? scope : "full-test";
			int missing = 0;
			for (int i = 0; i < kExpectedDestructiveSkipCount; ++i) {
				const bool seen = g_expected_destructive_skip_seen[i];
				if (!seen)
					++missing;
				log_msg(hf, safe_tag, "DESTRUCTIVE-SKIP-KEY -- scope=%s key=%s/%s expected=1 observed=%d reason=\"%s\"",
					safe_scope,
					kExpectedDestructiveSkipKeys[i].category,
					kExpectedDestructiveSkipKeys[i].name,
					seen ? 1 : 0,
					destructive_reason(kExpectedDestructiveSkipKeys[i].category, kExpectedDestructiveSkipKeys[i].name));
			}
			for (const auto& record : g_unexpected_skip_records) {
				log_msg(hf, safe_tag, "UNEXPECTED-SKIP-KEY -- scope=%s key=%s",
					safe_scope,
					record.c_str());
			}
			const int raw_skips = g_skipped.load(std::memory_order_acquire);
			const int prerequisite_skips = g_prerequisite_skipped.load(std::memory_order_acquire);
			const int destructive_skips = (std::max)(0, raw_skips - prerequisite_skips);
			log_msg(hf, safe_tag, "DESTRUCTIVE-SKIP-ACCOUNTING -- scope=%s expected=%d observed_expected=%d missing=%d unexpected=%d duplicate=%d global_skipped=%d final=%d",
				safe_scope,
				kExpectedDestructiveSkipCount,
				g_expected_destructive_skip_seen_count,
				missing,
				g_unexpected_destructive_skip_count,
				g_duplicate_destructive_skip_count,
				destructive_skips,
				final_accounting ? 1 : 0);
			return missing + g_unexpected_destructive_skip_count + g_duplicate_destructive_skip_count;
		}

		bool name_starts_with(const char* name, const char* prefix) {
			if (name == nullptr || prefix == nullptr) return false;
			return std::strncmp(name, prefix, std::strlen(prefix)) == 0;
		}

		bool text_contains_ascii_ci(const std::string& value, const char* needle) {
			if (needle == nullptr || *needle == '\0')
				return true;
			const std::size_t needle_len = std::strlen(needle);
			if (value.size() < needle_len)
				return false;
			for (std::size_t i = 0; i + needle_len <= value.size(); ++i) {
				bool matched = true;
				for (std::size_t j = 0; j < needle_len; ++j) {
					char a = value[i + j];
					char b = needle[j];
					if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
					if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
					if (a != b) {
						matched = false;
						break;
					}
				}
				if (matched)
					return true;
			}
			return false;
		}

		const std::string* parsed_value(const test_lab::result_t& r, const char* label) {
			if (label == nullptr)
				return nullptr;
			for (const auto& kv : r.parsed) {
				if (kv.label == label)
					return &kv.value;
			}
			return nullptr;
		}

		bool parsed_u64(const test_lab::result_t& r, const char* label, std::uint64_t& out) {
			const std::string* value = parsed_value(r, label);
			if (value == nullptr)
				return false;
			const char* s = value->c_str();
			while (*s == ' ' || *s == '\t')
				++s;
			char* end = nullptr;
			out = std::strtoull(s, &end, 0);
			return end != s;
		}

		bool parsed_nonzero(const test_lab::result_t& r, const char* label) {
			std::uint64_t value = 0;
			return parsed_u64(r, label, value) && value != 0;
		}

		bool parsed_truthy(const std::string& value) {
			std::string v = value;
			while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
				v.erase(v.begin());
			while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r' || v.back() == '\n'))
				v.pop_back();
			std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			return v == "1" || v == "true" || v == "yes" || v == "on";
		}

		bool parsed_key_degraded_true(const test_lab::result_t& r, std::string& key) {
			for (const auto& item : r.parsed) {
				const std::string& k = item.label;
				const std::string suffix = "_degraded";
				if (k.size() >= suffix.size() &&
					std::equal(suffix.rbegin(), suffix.rend(), k.rbegin()) &&
					parsed_truthy(item.value)) {
					key = k;
					return true;
				}
			}
			return false;
		}

		bool any_parsed_nonzero(const test_lab::result_t& r, const char* const* labels, std::size_t count) {
			for (std::size_t i = 0; i < count; ++i) {
				if (parsed_nonzero(r, labels[i]))
					return true;
			}
			return false;
		}

		bool parsed_value_contains(const test_lab::result_t& r, const char* label, const char* needle) {
			const std::string* value = parsed_value(r, label);
			return value != nullptr && text_contains_ascii_ci(*value, needle);
		}

		bool parsed_label_truthy(const test_lab::result_t& r, const char* label) {
			const std::string* value = parsed_value(r, label);
			return value != nullptr && parsed_truthy(*value);
		}

		bool feature_evidence_failure_reason(const char* category, const char* name, const test_lab::result_t& r, std::string& reason) {
			reason.clear();
			const char* cat = category ? category : "";
			const char* feature = name ? name : "";
			if (r.bytes_returned == 0 && r.raw.empty() && r.parsed.empty()) {
				reason = "empty_result_without_evidence";
				return true;
			}
			std::string degraded_key;
			if (parsed_key_degraded_true(r, degraded_key)) {
				if (std::strcmp(cat, "thread") == 0 && name_starts_with(feature, "TCTX") && degraded_key == "raw_ioctl_degraded") {
					if (parsed_label_truthy(r, "functional_context_pass") &&
						parsed_label_truthy(r, "functional_context_matches_user_probe") &&
						parsed_value_contains(r, "tctx_result_classification", "functional_context_pass") &&
						parsed_nonzero(r, "functional_context_rip") &&
						parsed_nonzero(r, "functional_context_rsp") &&
						parsed_nonzero(r, "functional_context_rflags")) {
						return false;
					}
					reason = "TCTX raw_ioctl_degraded=1_without_functional_context_pass";
					return true;
				}
				reason = degraded_key + "=1";
				return true;
			}
			if (std::strcmp(cat, "module") == 0 && name_starts_with(feature, "PMOD") && !parsed_nonzero(r, "rule_count")) {
				reason = "PMOD rule_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "module") == 0 && name_starts_with(feature, "DPIN") && !parsed_nonzero(r, "result_count")) {
				reason = "DPIN result_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "module") == 0 && name_starts_with(feature, "IHLD") && !parsed_nonzero(r, "held_matching_self_pid")) {
				reason = "IHLD held_matching_self_pid=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NCAP") && !parsed_nonzero(r, "packets_captured")) {
				reason = "NCAP packets_captured=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 &&
				(name_starts_with(feature, "NCON") || name_starts_with(feature, "DTCP"))) {
				std::uint64_t unknown = 0;
				if (parsed_u64(r, "unknown_tcp_state_count", unknown) && unknown != 0) {
					reason = std::string(feature) + " unknown_tcp_state_count_nonzero";
					return true;
				}
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NCPG") && !parsed_nonzero(r, "packet_count")) {
				reason = "NCPG packet_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NDNS") && !parsed_nonzero(r, "entry_count")) {
				reason = "NDNS entry_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NFLT")) {
				const char* labels[] = { "rule_id", "rule_count", "action", "direction", "protocol" };
				if (!any_parsed_nonzero(r, labels, sizeof(labels) / sizeof(labels[0]))) {
					reason = "NFLT rule_lifecycle_fields_all_zero_or_missing";
					return true;
				}
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NSTS")) {
				const char* labels[] = {
					"bytes_sent", "bytes_received", "packets_sent", "packets_received",
					"active_connections", "total_captured", "total_dns_logged", "active_filter_rules"
				};
				if (!any_parsed_nonzero(r, labels, sizeof(labels) / sizeof(labels[0]))) {
					reason = "NSTS all_activity_counters_zero_or_missing";
					return true;
				}
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "GSKT") && !parsed_nonzero(r, "socket_count")) {
				reason = "GSKT socket_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "SNBF") && !parsed_nonzero(r, "capture_count")) {
				reason = "SNBF capture_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-query") == 0 && name_starts_with(feature, "NFPR") && !parsed_nonzero(r, "result_count")) {
				reason = "NFPR result_count=0_or_missing";
				return true;
			}
			if (std::strcmp(cat, "network-action") == 0 && name_starts_with(feature, "BWMN")) {
				if (!parsed_nonzero(r, "Bytes/sec out") && !parsed_nonzero(r, "Bytes/sec in")) {
					reason = "BWMN throughput_rate_zero_or_missing";
					return true;
				}
			}
			return false;
		}


		std::uint32_t current_target_pid() {
			return g_target_pid.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_addr() {
			return g_target_addr.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_image_base() {
			return g_target_image_base.load(std::memory_order_acquire);
		}

		bool verify_target_liveness(HANDLE hf, const char* checkpoint, bool abort_on_dead = true) {
			(void)abort_on_dead;
			const std::uint32_t pid = current_target_pid();
			if (pid == 0) {
				g_target_unavailable.store(true, std::memory_order_release);
				log_msg(hf, "target-live", "SKIP -- no target pid at %s",
					checkpoint ? checkpoint : "checkpoint");
				return false;
			}

			std::uint32_t attached = driver_bridge::attached_pid();
			if (attached != pid) {
				const bool reattached = driver_bridge::attach(pid);
				log_msg(hf, "target-live", "reattach attempt at %s target_pid=%u previous_attached=%u ok=%d status=\"%s\" last_error=\"%s\"",
					checkpoint ? checkpoint : "checkpoint",
					pid,
					attached,
					reattached ? 1 : 0,
					driver_bridge::status().c_str(),
					driver_bridge::last_error().c_str());
				attached = driver_bridge::attached_pid();
			}

			std::uint32_t exit_code = 0;
			const bool alive = (attached == pid) && driver_bridge::attached_process_alive(&exit_code);
			if (alive) {
				g_driver_attached.store(true, std::memory_order_release);
				g_target_unavailable.store(false, std::memory_order_release);
				log_msg(hf, "target-live", "OK -- target alive at %s pid=%u attached=%u exit_code=0x%08X",
					checkpoint ? checkpoint : "checkpoint", pid, attached, exit_code);
				return true;
			}

			g_failed.fetch_add(1);
			mark_target_unavailable(hf, "target-live", "target is not alive; target-dependent phases will be skipped", pid, attached, exit_code);
			log_msg(hf, "target-live", "FAIL -- target is not alive at %s pid=%u attached=%u exit_code_or_err=0x%08X",
				checkpoint ? checkpoint : "checkpoint",
				pid,
				attached,
				exit_code);
			log_debug_snapshot(hf, "target-live", "DEAD target snapshot");
			return false;
		}


		void populate_defaults(test_lab::state_t& s, std::uint32_t target_pid) {
			s.pid = target_pid;
			s.tid = 0;
			s.addr = current_target_addr();
			s.size = 64;
			s.u32_a = 0;
			s.u32_b = 0;
			s.u64_a = 0;
			s.buf.clear();
			s.text_a = "ntdll.dll";
			s.text_b = "127.0.0.1";
			s.user = nullptr;

			if (target_pid != 0) {
				auto threads = driver_bridge::enumerate_threads_for(target_pid);
				for (const auto& th : threads) {
					if (th.owner_pid == target_pid && th.tid != 0) {
						s.tid = th.tid;
						break;
					}
				}
			}
		}


		std::string wide_to_log_string(const std::wstring& text) {
			if (text.empty())
				return {};
			int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
			if (needed <= 1)
				return {};
			std::string out(static_cast<std::size_t>(needed), '\0');
			int written = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, out.data(), needed, nullptr, nullptr);
			if (written <= 1)
				return {};
			out.resize(static_cast<std::size_t>(written - 1));
			return out;
		}

		std::wstring ensure_trailing_separator(std::wstring path) {
			if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
				path.push_back(L'\\');
			return path;
		}

		std::wstring trim_trailing_separators(std::wstring path) {
			while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
				path.pop_back();
			return path;
		}

		std::wstring join_path(std::wstring base, const wchar_t* leaf) {
			if (base.empty())
				return leaf ? std::wstring(leaf) : std::wstring();
			base = ensure_trailing_separator(std::move(base));
			if (leaf && (leaf[0] == L'\\' || leaf[0] == L'/'))
				return base + (leaf + 1);
			return base + (leaf ? leaf : L"");
		}

		std::wstring full_path_for_log(const std::wstring& path) {
			if (path.empty())
				return {};
			SetLastError(ERROR_SUCCESS);
			DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
			if (needed == 0)
				return path;
			std::vector<wchar_t> buf(static_cast<std::size_t>(needed) + 2u);
			DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buf.size()), buf.data(), nullptr);
			if (written == 0 || written >= buf.size())
				return path;
			return std::wstring(buf.data(), written);
		}

		std::wstring parent_directory_for_path(const std::wstring& path) {
			auto slash = path.find_last_of(L"\\/");
			if (slash == std::wstring::npos)
				return {};
			return path.substr(0, slash + 1);
		}

		std::wstring current_directory_for_launch() {
			SetLastError(ERROR_SUCCESS);
			DWORD needed = GetCurrentDirectoryW(0, nullptr);
			if (needed == 0)
				return {};
			std::vector<wchar_t> buf(static_cast<std::size_t>(needed) + 2u);
			DWORD cwd_len = GetCurrentDirectoryW(static_cast<DWORD>(buf.size()), buf.data());
			if (cwd_len == 0 || cwd_len >= buf.size())
				return {};
			return std::wstring(buf.data(), cwd_len);
		}

		std::wstring normalize_launch_path(const std::wstring& path) {
			std::wstring full = full_path_for_log(path);
			return full.empty() ? path : full;
		}

		std::wstring normalize_found_target(const std::wstring& path) {
			std::wstring full = normalize_launch_path(path);
			if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES)
				return full;
			return path;
		}

		void log_target_launch_context(HANDLE hf, const std::wstring& exe, const std::wstring& work_dir) {
			const std::wstring exe_full = full_path_for_log(exe);
			const std::wstring work_dir_full = full_path_for_log(work_dir);
			const std::wstring command_line = L"\"" + exe_full + L"\" " + kTargetArgsWide;
			const std::string exe_req = wide_to_log_string(exe);
			const std::string exe_eff = wide_to_log_string(exe_full);
			const std::string work_req = work_dir.empty() ? std::string("<inherit>") : wide_to_log_string(work_dir);
			const std::string work_eff = work_dir_full.empty() ? std::string("<inherit>") : wide_to_log_string(work_dir_full);
			std::string command = wide_to_log_string(command_line);
			SetLastError(0);
			DWORD exe_attrs = exe_full.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(exe_full.c_str());
			DWORD exe_attr_err = (exe_attrs == INVALID_FILE_ATTRIBUTES && !exe_full.empty()) ? GetLastError() : 0;
			SetLastError(0);
			DWORD work_attrs = work_dir_full.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(work_dir_full.c_str());
			DWORD work_err = (work_attrs == INVALID_FILE_ATTRIBUTES && !work_dir_full.empty()) ? GetLastError() : 0;
			std::wstring cwd = current_directory_for_launch();
			const std::string cwd_log = cwd.empty() ? std::string("<unavailable>") : wide_to_log_string(cwd);
			log_msg(hf, "launch", "target launch context requested_exe=%s effective_exe=%s requested_work_dir=%s effective_work_dir=%s current_dir=%s command_line=%s host_pid=%lu host_tid=%lu",
				exe_req.c_str(),
				exe_eff.c_str(),
				work_req.c_str(),
				work_eff.c_str(),
				cwd_log.c_str(),
				command.c_str(),
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()));
			log_msg(hf, "launch", "target executable probe attr_ok=%d attr_err=%lu attrs=0x%08lX work_dir_attrs=0x%08lX work_dir_err=%lu work_dir_is_dir=%d",
				exe_attrs != INVALID_FILE_ATTRIBUTES ? 1 : 0,
				static_cast<unsigned long>(exe_attr_err),
				exe_attrs == INVALID_FILE_ATTRIBUTES ? 0UL : static_cast<unsigned long>(exe_attrs),
				work_attrs == INVALID_FILE_ATTRIBUTES ? 0UL : static_cast<unsigned long>(work_attrs),
				static_cast<unsigned long>(work_err),
				(work_attrs != INVALID_FILE_ATTRIBUTES && (work_attrs & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0);
		}

		DWORD log_target_launch_context_seh(HANDLE hf, const std::wstring& exe, const std::wstring& work_dir) {
			__try {
				log_target_launch_context(hf, exe, work_dir);
				return 0;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
		}

		std::wstring current_module_path_for_launch(DWORD& len_out, DWORD& err_out) {
			len_out = 0;
			err_out = ERROR_SUCCESS;
			std::vector<wchar_t> buf(MAX_PATH);
			for (;;) {
				SetLastError(ERROR_SUCCESS);
				DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
				DWORD err = GetLastError();
				if (len == 0) {
					err_out = err;
					return {};
				}
				if (len < buf.size() - 1u) {
					len_out = len;
					err_out = err;
					return std::wstring(buf.data(), len);
				}
				if (buf.size() >= 32768u) {
					len_out = len;
					err_out = ERROR_INSUFFICIENT_BUFFER;
					return {};
				}
				buf.resize(buf.size() * 2u);
			}
		}

		bool read_env_wide(const wchar_t* name, std::wstring& out, DWORD& len_out, DWORD& err_out) {
			out.clear();
			len_out = 0;
			err_out = ERROR_SUCCESS;
			SetLastError(ERROR_SUCCESS);
			DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
			if (needed == 0) {
				err_out = GetLastError();
				return false;
			}
			std::vector<wchar_t> buf(static_cast<std::size_t>(needed) + 2u);
			SetLastError(ERROR_SUCCESS);
			DWORD len = GetEnvironmentVariableW(name, buf.data(), static_cast<DWORD>(buf.size()));
			if (len == 0) {
				err_out = GetLastError();
				return false;
			}
			if (len >= buf.size()) {
				err_out = ERROR_INSUFFICIENT_BUFFER;
				len_out = len;
				return false;
			}
			len_out = len;
			out.assign(buf.data(), len);
			return true;
		}

		std::string filetime_to_log_string(const FILETIME& ft) {
			if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
				return "<none>";
			FILETIME local_ft{};
			SYSTEMTIME st{};
			if (!FileTimeToLocalFileTime(&ft, &local_ft) || !FileTimeToSystemTime(&local_ft, &st))
				return "<invalid>";
			char buf[64] = {};
			_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
				static_cast<unsigned>(st.wYear),
				static_cast<unsigned>(st.wMonth),
				static_cast<unsigned>(st.wDay),
				static_cast<unsigned>(st.wHour),
				static_cast<unsigned>(st.wMinute),
				static_cast<unsigned>(st.wSecond),
				static_cast<unsigned>(st.wMilliseconds));
			return std::string(buf);
		}

		struct target_candidate_t {
			std::string label;
			std::wstring requested;
			std::string source_root;
		};

		struct target_probe_result_t {
			bool is_file = false;
			bool is_dir = false;
			DWORD attrs = INVALID_FILE_ATTRIBUTES;
			DWORD attr_error = ERROR_SUCCESS;
			DWORD meta_error = ERROR_SUCCESS;
			ULONGLONG size = 0;
			std::string mtime;
		};

		target_probe_result_t probe_candidate(HANDLE hf, const target_candidate_t& candidate, std::wstring& normalized_out) {
			normalized_out = normalize_launch_path(candidate.requested);
			target_probe_result_t result{};
			WIN32_FILE_ATTRIBUTE_DATA fad{};
			SetLastError(ERROR_SUCCESS);
			result.attrs = GetFileAttributesW(normalized_out.c_str());
			result.attr_error = (result.attrs == INVALID_FILE_ATTRIBUTES) ? GetLastError() : ERROR_SUCCESS;
			if (result.attrs != INVALID_FILE_ATTRIBUTES) {
				result.is_dir = (result.attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
				result.is_file = !result.is_dir;
				SetLastError(ERROR_SUCCESS);
				if (GetFileAttributesExW(normalized_out.c_str(), GetFileExInfoStandard, &fad)) {
					result.size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
					result.mtime = filetime_to_log_string(fad.ftLastWriteTime);
				} else {
					result.meta_error = GetLastError();
					result.mtime = "<metadata-error>";
				}
			} else {
				result.mtime = "<missing>";
			}

			const std::string requested_log = wide_to_log_string(candidate.requested);
			const std::string normalized_log = wide_to_log_string(normalized_out);
			log_msg(hf, "find_target", "candidate label=%s requested=\"%s\" normalized=\"%s\" attrs=0x%08lX last_error=%lu is_file=%d is_dir=%d size=%llu mtime=%s source_root=\"%s\" meta_error=%lu",
				candidate.label.c_str(),
				requested_log.empty() ? "<empty>" : requested_log.c_str(),
				normalized_log.empty() ? "<empty>" : normalized_log.c_str(),
				result.attrs == INVALID_FILE_ATTRIBUTES ? 0xFFFFFFFFul : static_cast<unsigned long>(result.attrs),
				static_cast<unsigned long>(result.attr_error),
				result.is_file ? 1 : 0,
				result.is_dir ? 1 : 0,
				static_cast<unsigned long long>(result.size),
				result.mtime.c_str(),
				candidate.source_root.empty() ? "<none>" : candidate.source_root.c_str(),
				static_cast<unsigned long>(result.meta_error));
			diag::log_tagged_fmt("test_all", "find_test_target candidate label=%s normalized=\"%s\" is_file=%d is_dir=%d err=%lu size=%llu",
				candidate.label.c_str(),
				normalized_log.empty() ? "<empty>" : normalized_log.c_str(),
				result.is_file ? 1 : 0,
				result.is_dir ? 1 : 0,
				static_cast<unsigned long>(result.attr_error),
				static_cast<unsigned long long>(result.size));
			return result;
		}

		bool path_is_existing_directory(const std::wstring& path) {
			if (path.empty())
				return false;
			std::wstring normalized = normalize_launch_path(path);
			SetLastError(ERROR_SUCCESS);
			DWORD attrs = GetFileAttributesW(normalized.c_str());
			return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
		}

		void add_target_candidate(std::vector<target_candidate_t>& candidates, const char* label, const std::wstring& requested, const std::string& source_root) {
			if (requested.empty())
				return;
			target_candidate_t c;
			c.label = label ? label : "candidate";
			c.requested = requested;
			c.source_root = source_root;
			candidates.push_back(std::move(c));
		}

		void add_root_target_candidates(std::vector<target_candidate_t>& candidates, const std::string& prefix, const std::wstring& root) {
			if (root.empty())
				return;
			const std::wstring normalized_root = ensure_trailing_separator(normalize_launch_path(root));
			const std::string root_log = wide_to_log_string(normalized_root);
			add_target_candidate(candidates, (prefix + "/direct").c_str(), join_path(normalized_root, L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/Release").c_str(), join_path(join_path(normalized_root, L"Release"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/Debug").c_str(), join_path(join_path(normalized_root, L"Debug"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/RelWithDebInfo").c_str(), join_path(join_path(normalized_root, L"RelWithDebInfo"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/build-ninja/Release").c_str(), join_path(join_path(join_path(normalized_root, L"build-ninja"), L"Release"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/build-ninja").c_str(), join_path(join_path(normalized_root, L"build-ninja"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/deps").c_str(), join_path(join_path(normalized_root, L"deps"), L"AiDA_TestTarget.exe"), root_log);
			add_target_candidate(candidates, (prefix + "/package/deps").c_str(), join_path(join_path(join_path(normalized_root, L"package"), L"deps"), L"AiDA_TestTarget.exe"), root_log);
		}

		void add_parent_walk_candidates(std::vector<target_candidate_t>& candidates, const std::string& prefix, const std::wstring& start_dir) {
			std::wstring cursor = ensure_trailing_separator(normalize_launch_path(start_dir));
			for (int depth = 0; depth < 16 && !cursor.empty(); ++depth) {
				char label[96] = {};
				_snprintf_s(label, sizeof(label), _TRUNCATE, "%s/parent_%02d", prefix.c_str(), depth);
				add_root_target_candidates(candidates, label, cursor);
				std::wstring trimmed = trim_trailing_separators(cursor);
				std::wstring parent = parent_directory_for_path(trimmed);
				if (parent.empty() || _wcsicmp(parent.c_str(), cursor.c_str()) == 0)
					break;
				cursor = ensure_trailing_separator(parent);
			}
		}

		std::wstring find_test_target(HANDLE hf) {
			DWORD self_len = 0;
			DWORD self_err = ERROR_SUCCESS;
			std::wstring self_path = current_module_path_for_launch(self_len, self_err);
			if (!self_path.empty())
				self_path = normalize_launch_path(self_path);
			std::wstring module_dir = parent_directory_for_path(self_path);
			const std::string self_path_log = self_path.empty() ? std::string("<unavailable>") : wide_to_log_string(self_path);
			const std::string module_dir_log = module_dir.empty() ? std::string("<unavailable>") : wide_to_log_string(module_dir);
			log_msg(hf, "find_target", "module path len=%lu err=%lu path=%s dir=%s",
				static_cast<unsigned long>(self_len),
				static_cast<unsigned long>(self_err),
				self_path_log.c_str(),
				module_dir_log.c_str());

			std::wstring cwd_dir = current_directory_for_launch();
			if (!cwd_dir.empty())
				cwd_dir = ensure_trailing_separator(normalize_launch_path(cwd_dir));

			std::vector<target_candidate_t> candidates;
			std::wstring env_path;
			DWORD env_len = 0;
			DWORD env_err = ERROR_SUCCESS;
			if (read_env_wide(L"AIDA_TEST_TARGET", env_path, env_len, env_err)) {
				add_target_candidate(candidates, "AIDA_TEST_TARGET", env_path, "AIDA_TEST_TARGET");
				if (path_is_existing_directory(env_path)) {
					add_target_candidate(candidates, "AIDA_TEST_TARGET/AiDA_TestTarget.exe", join_path(env_path, L"AiDA_TestTarget.exe"), "AIDA_TEST_TARGET");
				}
			} else {
				log_msg(hf, "find_target", "candidate label=AIDA_TEST_TARGET env_missing len=%lu last_error=%lu",
					static_cast<unsigned long>(env_len),
					static_cast<unsigned long>(env_err));
			}

			if (!module_dir.empty())
				add_root_target_candidates(candidates, "module_dir", module_dir);
			else
				log_msg(hf, "find_target", "probe[module_dir] skipped because module directory is unavailable");

			if (!cwd_dir.empty())
				add_root_target_candidates(candidates, "cwd", cwd_dir);
			else
				log_msg(hf, "find_target", "probe[cwd] working directory unavailable");

			if (!module_dir.empty())
				add_parent_walk_candidates(candidates, "module_walk", module_dir);
			if (!cwd_dir.empty())
				add_parent_walk_candidates(candidates, "cwd_walk", cwd_dir);

			add_target_candidate(candidates, "fallback/build-ninja/Release", L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\Release\\AiDA_TestTarget.exe", "hardcoded_repo_root");
			add_target_candidate(candidates, "fallback/build-ninja", L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\AiDA_TestTarget.exe", "hardcoded_repo_root");

			std::wstring first_file;
			std::string first_label;
			for (const auto& candidate : candidates) {
				std::wstring normalized;
				target_probe_result_t probe = probe_candidate(hf, candidate, normalized);
				if (probe.is_file && first_file.empty()) {
					first_file = normalized;
					first_label = candidate.label;
				}
			}

			if (!first_file.empty()) {
				const std::string found_log = wide_to_log_string(first_file);
				log_msg(hf, "find_target", "selected label=%s path=\"%s\" total_candidates=%zu",
					first_label.c_str(),
					found_log.empty() ? "<empty>" : found_log.c_str(),
					candidates.size());
				return normalize_found_target(first_file);
			}

			log_msg(hf, "find_target", "FAIL -- AiDA_TestTarget.exe not found in any candidate path total_candidates=%zu", candidates.size());
			return {};
		}


		struct child_status_t {
			bool process_opened = false;
			DWORD open_error = 0;
			bool exit_known = false;
			DWORD exit_code = STILL_ACTIVE;
			bool alive = false;
		};

		child_status_t query_child_status(std::uint32_t pid) {
			child_status_t s{};
			HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
			if (!hp) {
				s.open_error = GetLastError();
				return s;
			}
			s.process_opened = true;
			s.exit_known = GetExitCodeProcess(hp, &s.exit_code) != FALSE;
			s.open_error = s.exit_known ? 0 : GetLastError();
			s.alive = s.exit_known && s.exit_code == STILL_ACTIVE;
			CloseHandle(hp);
			return s;
		}

		bool wait_for_ready_event_with_retry(HANDLE hf, std::uint32_t pid, DWORD total_wait_ms) {
			const ULONGLONG start = GetTickCount64();
			DWORD attempt = 0;
			for (;;) {
				const ULONGLONG now = GetTickCount64();
				const DWORD elapsed = now >= start ? static_cast<DWORD>(now - start) : 0u;
				const DWORD remaining = elapsed >= total_wait_ms ? 0u : total_wait_ms - elapsed;
				child_status_t child = query_child_status(pid);
				if (remaining == 0u) {
					log_msg(hf, "launch", "READY OpenEvent retry budget expired attempts=%lu elapsed_ms=%lu child_open=%d child_exit_known=%d child_exit=0x%08lX child_alive=%d open_err=%lu",
						static_cast<unsigned long>(attempt),
						static_cast<unsigned long>(elapsed),
						child.process_opened ? 1 : 0,
						child.exit_known ? 1 : 0,
						static_cast<unsigned long>(child.exit_code),
						child.alive ? 1 : 0,
						static_cast<unsigned long>(child.open_error));
					return false;
				}
				if (child.exit_known && child.exit_code != STILL_ACTIVE) {
					log_msg(hf, "launch", "READY OpenEvent retry stopped because child exited attempts=%lu elapsed_ms=%lu remaining_ms=%lu exit_code=0x%08lX",
						static_cast<unsigned long>(attempt),
						static_cast<unsigned long>(elapsed),
						static_cast<unsigned long>(remaining),
						static_cast<unsigned long>(child.exit_code));
					return false;
				}

				++attempt;
				struct ready_namespace_t {
					const wchar_t* wide_name;
					const char* log_name;
				};
				const ready_namespace_t namespaces[] = {
					{ L"Global\\WhosWhoTestReady", "Global\\WhosWhoTestReady" },
					{ L"Local\\WhosWhoTestReady", "Local\\WhosWhoTestReady" }
				};
				for (const auto& ns : namespaces) {
					SetLastError(ERROR_SUCCESS);
					HANDLE hReady = OpenEventW(SYNCHRONIZE, FALSE, ns.wide_name);
					DWORD gle = hReady ? ERROR_SUCCESS : GetLastError();
					const ULONGLONG open_now = GetTickCount64();
					const DWORD open_elapsed = open_now >= start ? static_cast<DWORD>(open_now - start) : 0u;
					const DWORD open_remaining = open_elapsed >= total_wait_ms ? 0u : total_wait_ms - open_elapsed;
					log_msg(hf, "launch", "READY OpenEvent attempt=%lu namespace=%s handle=%p gle=%lu elapsed_ms=%lu remaining_ms=%lu child_open=%d child_exit_known=%d child_exit=0x%08lX child_alive=%d child_open_err=%lu",
						static_cast<unsigned long>(attempt),
						ns.log_name,
						hReady,
						static_cast<unsigned long>(gle),
						static_cast<unsigned long>(open_elapsed),
						static_cast<unsigned long>(open_remaining),
						child.process_opened ? 1 : 0,
						child.exit_known ? 1 : 0,
						static_cast<unsigned long>(child.exit_code),
						child.alive ? 1 : 0,
						static_cast<unsigned long>(child.open_error));
					if (!hReady)
						continue;
					set_step("launch: wait READY event");
					DWORD wait = WaitForSingleObject(hReady, open_remaining);
					DWORD wait_err = (wait == WAIT_FAILED) ? GetLastError() : 0u;
					CloseHandle(hReady);
					const ULONGLONG wait_now = GetTickCount64();
					const DWORD wait_elapsed = wait_now >= start ? static_cast<DWORD>(wait_now - start) : 0u;
					child_status_t after_child = query_child_status(pid);
					log_msg(hf, "launch", "READY event wait attempt=%lu namespace=%s wait=0x%08lX wait_err=%lu elapsed_ms=%lu child_open=%d child_exit_known=%d child_exit=0x%08lX child_alive=%d child_open_err=%lu",
						static_cast<unsigned long>(attempt),
						ns.log_name,
						static_cast<unsigned long>(wait),
						static_cast<unsigned long>(wait_err),
						static_cast<unsigned long>(wait_elapsed),
						after_child.process_opened ? 1 : 0,
						after_child.exit_known ? 1 : 0,
						static_cast<unsigned long>(after_child.exit_code),
						after_child.alive ? 1 : 0,
						static_cast<unsigned long>(after_child.open_error));
					if (wait == WAIT_OBJECT_0)
						return true;
					if (wait == WAIT_FAILED && open_remaining > 0u)
						continue;
					return false;
				}
				Sleep(50);
			}
		}

		void poll_child_liveness_after_ready_event_miss(HANDLE hf, std::uint32_t pid, DWORD total_wait_ms) {
			const ULONGLONG start = GetTickCount64();
			for (DWORD attempt = 1; ; ++attempt) {
				const ULONGLONG now = GetTickCount64();
				const DWORD elapsed = now >= start ? static_cast<DWORD>(now - start) : 0u;
				const DWORD remaining = elapsed >= total_wait_ms ? 0u : total_wait_ms - elapsed;
				child_status_t child = query_child_status(pid);
				log_msg(hf, "launch", "READY fallback poll attempt=%lu elapsed_ms=%lu remaining_ms=%lu child_open=%d child_exit_known=%d child_exit=0x%08lX child_alive=%d child_open_err=%lu",
					static_cast<unsigned long>(attempt),
					static_cast<unsigned long>(elapsed),
					static_cast<unsigned long>(remaining),
					child.process_opened ? 1 : 0,
					child.exit_known ? 1 : 0,
					static_cast<unsigned long>(child.exit_code),
					child.alive ? 1 : 0,
					static_cast<unsigned long>(child.open_error));
				if (child.alive || remaining == 0u)
					break;
				Sleep(50);
			}
		}

		bool verify_driver_attach(HANDLE hf, std::uint32_t pid) {
			set_phase("Verifying driver attach");

			const ULONGLONG retry_start = GetTickCount64();
			const DWORD retry_budget_ms = 5000u;
			std::vector<driver_bridge::module_info_t> modules;
			driver_bridge::peb_info_t peb{};
			bool peb_ok = false;
			std::uint64_t exe_base = 0;
			std::string image_name;
			std::uint64_t ntdll_base = 0;
			std::uint64_t image_base = 0;
			std::uint32_t attached = 0;
			bool kernel = false;
			bool can_read = false;
			std::string drv_status;
			std::string drv_err;
			DWORD attempt = 0;

			for (;;) {
				++attempt;
				const ULONGLONG attempt_start = GetTickCount64();
				kernel = driver_bridge::using_kernel_driver();
				can_read = driver_bridge::can_read_memory();
				attached = driver_bridge::attached_pid();
				drv_status = driver_bridge::status();
				drv_err = driver_bridge::last_error();
				modules = driver_bridge::enumerate_modules_for(pid);
				exe_base = 0;
				image_name.clear();
				ntdll_base = 0;
				for (const auto& m : modules) {
					if (m.name.empty()) continue;
					const char* dot = std::strrchr(m.name.c_str(), '.');
					bool is_exe = (dot != nullptr) && (_stricmp(dot, ".exe") == 0);
					if (is_exe && exe_base == 0) {
						exe_base = m.base;
						image_name = m.name;
					}
					if (ntdll_base == 0 && _stricmp(m.name.c_str(), "ntdll.dll") == 0)
						ntdll_base = m.base;
				}
				peb = {};
				peb_ok = driver_bridge::read_peb_for(pid, peb);
				image_base = (peb_ok && peb.image_base != 0) ? peb.image_base : exe_base;
				const ULONGLONG now = GetTickCount64();
				const DWORD elapsed = now >= retry_start ? static_cast<DWORD>(now - retry_start) : 0u;
				const DWORD remaining = elapsed >= retry_budget_ms ? 0u : retry_budget_ms - elapsed;
				const DWORD attempt_elapsed = now >= attempt_start ? static_cast<DWORD>(now - attempt_start) : 0u;
				log_msg(hf, "attach", "attach/module attempt=%lu attached_pid=%u target_pid=%u using_kernel_driver=%d can_read_memory=%d modules=%zu peb_ok=%d peb=0x%016llX image_base_peb=0x%016llX ldr=0x%016llX exe_base=0x%016llX ntdll_base=0x%016llX elapsed_ms=%lu attempt_ms=%lu remaining_ms=%lu status=\"%s\" last_error=\"%s\"",
					static_cast<unsigned long>(attempt),
					attached,
					pid,
					static_cast<int>(kernel),
					static_cast<int>(can_read),
					modules.size(),
					peb_ok ? 1 : 0,
					static_cast<unsigned long long>(peb.peb_address),
					static_cast<unsigned long long>(peb.image_base),
					static_cast<unsigned long long>(peb.ldr_address),
					static_cast<unsigned long long>(exe_base),
					static_cast<unsigned long long>(ntdll_base),
					static_cast<unsigned long>(elapsed),
					static_cast<unsigned long>(attempt_elapsed),
					static_cast<unsigned long>(remaining),
					drv_status.c_str(),
					drv_err.c_str());
				if (attached == pid && !modules.empty() && ntdll_base != 0 && image_base != 0)
					break;
				if (remaining == 0u)
					break;
				Sleep(100);
			}

			if (attached == 0 || attached != pid) {
				log_msg(hf, "attach", "FAIL -- driver attached_pid=%u does not match target pid=%u (last_error=\"%s\")",
					attached, pid, drv_err.c_str());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			if (peb_ok && peb.image_base != 0) {
				log_msg(hf, "attach", "PEB image_base=0x%016llX peb=0x%016llX",
					static_cast<unsigned long long>(peb.image_base),
					static_cast<unsigned long long>(peb.peb_address));
			}

			if (image_base == 0) {
				log_msg(hf, "attach", "FAIL -- could not resolve target image base (modules=%zu)", modules.size());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			log_msg(hf, "attach", "target image base=0x%016llX module=\"%s\" modules_enumerated=%zu",
				static_cast<unsigned long long>(image_base),
				image_name.empty() ? "<unknown>" : image_name.c_str(),
				modules.size());

			std::vector<std::uint8_t> sample;
			bool read_ok = driver_bridge::read_memory_for(pid, image_base, 64, sample);
			if (!read_ok || sample.size() < 2) {
				log_msg(hf, "attach", "FAIL -- sanity read of image base returned %zu bytes (read_ok=%d last_error=\"%s\")",
					sample.size(), static_cast<int>(read_ok), driver_bridge::last_error().c_str());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			std::uint16_t mz = static_cast<std::uint16_t>(sample[0]) |
				(static_cast<std::uint16_t>(sample[1]) << 8);
			bool is_mz = (mz == 0x5A4D);

			log_msg(hf, "attach", "sanity read OK bytes=%zu first4=%02X %02X %02X %02X mz=0x%04X (%s)",
				sample.size(),
				sample[0], sample[1],
				sample.size() > 2 ? sample[2] : 0,
				sample.size() > 3 ? sample[3] : 0,
				static_cast<unsigned>(mz),
				is_mz ? "MZ valid" : "NOT MZ");

			if (!is_mz) {
				log_msg(hf, "attach", "FAIL -- target image base does not start with MZ header (driver read suspect)");
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			std::uint64_t fn_addr = 0;
			if (ntdll_base != 0) {
				fn_addr = driver_bridge::resolve_export(ntdll_base, "NtClose");
				log_msg(hf, "attach", "resolved target ntdll.dll base=0x%016llX NtClose=0x%016llX",
					static_cast<unsigned long long>(ntdll_base),
					static_cast<unsigned long long>(fn_addr));
			} else {
				log_msg(hf, "attach", "WARN -- ntdll.dll not found after retry budget attempts=%lu modules=%zu elapsed_ms=%lu; functions defaulting to image base after budget expiry",
					static_cast<unsigned long>(attempt),
					modules.size(),
					static_cast<unsigned long>(GetTickCount64() - retry_start));
			}

			g_target_image_base.store(image_base, std::memory_order_release);
			g_target_addr.store(fn_addr != 0 ? fn_addr : image_base, std::memory_order_release);
			g_driver_attached.store(true, std::memory_order_release);

			log_msg(hf, "attach", "PASS -- driver attach VERIFIED to pid=%u image_base=0x%016llX known_good_addr=0x%016llX",
				pid,
				static_cast<unsigned long long>(image_base),
				static_cast<unsigned long long>(current_target_addr()));
			g_passed.fetch_add(1);
			return true;
		}


		bool phase_launch_target(HANDLE hf, std::uint32_t& out_pid) {
			set_phase("Launch AiDA_TestTarget.exe");
			log_phase_begin(hf, "launch target");
			log_msg(hf, "launch", "searching for AiDA_TestTarget.exe ...");

			std::wstring exe = find_test_target(hf);
			if (exe.empty()) {
				log_msg(hf, "launch", "FAIL -- AiDA_TestTarget.exe not found; downstream feature tests will run with no attached target");
				out_pid = 0;
				g_target_pid.store(0, std::memory_order_release);
				g_driver_attached.store(false, std::memory_order_release);
				g_target_unavailable.store(true, std::memory_order_release);
				g_failed.fetch_add(1);
				log_phase_end(hf, "launch target");
				return false;
			}
			const std::wstring requested_exe = exe;
			std::wstring normalized_exe = normalize_found_target(exe);
			if (!normalized_exe.empty())
				exe = normalized_exe;

		std::string exe_log = wide_to_log_string(exe);
		log_msg(hf, "launch", "found: %s", exe_log.empty() ? "<unavailable>" : exe_log.c_str());

		{
			std::lock_guard<std::mutex> lk(g_launch_state_mtx);
			g_target_executable_path = exe_log;
		}

		{
			auto parent_dir = std::filesystem::path(exe).parent_path();
			if (!parent_dir.empty()) {
				symbol_store::add_target_module_search_path(parent_dir.string());
			}
		}

		auto t0 = std::chrono::steady_clock::now();


			const std::wstring requested_work_dir = parent_directory_for_path(exe);
			std::wstring work_dir = requested_work_dir;
			if (work_dir.empty())
				work_dir = current_directory_for_launch();
			std::string work_dir_log = wide_to_log_string(work_dir);
			log_msg(hf, "launch", "resolved working_dir=%s", work_dir.empty() ? "<inherit>" : work_dir_log.c_str());
			{
				std::lock_guard<std::mutex> lk(g_launch_state_mtx);
				g_requested_cwd = work_dir_log;
				g_effective_cwd = work_dir_log;
			}
			set_step("launch: log_target_launch_context");
			log_msg(hf, "launch", "BEFORE target launch context probe");
			DWORD context_seh = log_target_launch_context_seh(hf, requested_exe, requested_work_dir);
			if (context_seh != 0) {
				log_msg(hf, "launch", "target launch context probe SEH=0x%08lX; continuing to spawn",
					static_cast<unsigned long>(context_seh));
			} else {
				log_msg(hf, "launch", "AFTER target launch context probe");
			}

			std::uint32_t pid = 0;
			set_step("launch: spawn_and_attach_target");
			log_debug_snapshot(hf, "launch", "BEFORE spawn_and_attach_target");
			bool target_log_ready = prepare_target_log_file(hf);
			BOOL env_ok = SetEnvironmentVariableA("AIDA_TARGET_LOG_PATH", target_log_path());
			log_msg(hf, "launch", "set AIDA_TARGET_LOG_PATH ok=%d err=%lu path=%s",
				env_ok ? 1 : 0,
				env_ok ? 0UL : static_cast<unsigned long>(GetLastError()),
				target_log_path());
			log_msg(hf, "launch", "target log ready=%d", target_log_ready ? 1 : 0);
			log_msg(hf, "launch", "target args: %s", kTargetArgsText);
			log_msg(hf, "launch", "CALL spawn_and_attach_target exe=%s work_dir=%s",
				exe_log.empty() ? "<unavailable>" : exe_log.c_str(),
				work_dir.empty() ? "<inherit>" : work_dir_log.c_str());
			run_target::launch_result_t launch_result{};
			log_msg(hf, "launch", "spawn_and_attach_target request exe=%s cwd=%s command=\"%s\" host_pid=%lu host_tid=%lu",
				exe_log.empty() ? "<unavailable>" : exe_log.c_str(),
				work_dir.empty() ? "<inherit>" : work_dir_log.c_str(),
				(std::string("\"") + exe_log + "\" " + kTargetArgsText).c_str(),
				static_cast<unsigned long>(GetCurrentProcessId()),
				static_cast<unsigned long>(GetCurrentThreadId()));
			run_target::launch_options_t launch_options;
			launch_options.exe_path = exe;
			launch_options.args = kTargetArgsWide;
			launch_options.working_dir = work_dir;
			launch_options.isolation = run_target::isolation_t::same_desktop_jobbed;
			launch_options.block_network = false;
			launch_options.kill_on_host_exit = true;
			launch_options.attach_after_resume = true;
			bool ok = debugger_engine::spawn_and_attach_target(launch_options, &pid, &launch_result);
			DWORD spawn_gle = launch_result.win32_error != 0 ? launch_result.win32_error : GetLastError();
			SetEnvironmentVariableA("AIDA_TARGET_LOG_PATH", nullptr);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
			log_msg(hf, "launch", "spawn_and_attach_target returned ok=%d pid=%u tid=%u elapsed=%lld ms win32_error=%lu result_error=\"%s\" attach_pid=%u driver_attached=%d driver_status=\"%s\" driver_last_error=\"%s\"",
				ok ? 1 : 0,
				pid,
				launch_result.thread_id,
				(long long)ms,
				static_cast<unsigned long>(spawn_gle),
				launch_result.error.c_str(),
				driver_bridge::attached_pid(),
				(g_driver_attached.load(std::memory_order_acquire) && driver_bridge::attached_pid() == pid) ? 1 : 0,
				driver_bridge::status().c_str(),
				driver_bridge::last_error().c_str());
			log_debug_snapshot(hf, "launch", "AFTER spawn_and_attach_target");

			if (!ok || pid == 0) {
				log_msg(hf, "launch", "FAIL -- spawn_and_attach_target returned false pid=%u (elapsed %lld ms) last_error=\"%s\"",
					pid, (long long)ms, driver_bridge::last_error().c_str());
				out_pid = 0;
				g_target_pid.store(0, std::memory_order_release);
				g_driver_attached.store(false, std::memory_order_release);
				g_target_unavailable.store(true, std::memory_order_release);
				g_failed.fetch_add(1);
				log_phase_end(hf, "launch target");
				return false;
			}

			out_pid = pid;
			g_target_pid.store(pid, std::memory_order_release);
			log_msg(hf, "launch", "spawn_and_attach_target returned true pid=%u (elapsed %lld ms)", pid, (long long)ms);


			set_phase("Waiting for test_target READY");
			log_msg(hf, "launch", "waiting for WhosWhoTestReady event (8s timeout, retrying Global/Local until deadline or child exit) ...");

			const bool ready_event_seen = wait_for_ready_event_with_retry(hf, pid, 8000u);
			if (ready_event_seen) {
				log_msg(hf, "launch", "READY event signaled within retry budget");
			} else {
				log_msg(hf, "launch", "READY event not observed; falling back to child liveness polling up to 750ms");
				poll_child_liveness_after_ready_event_miss(hf, pid, 750u);
			}

			bool attach_ok = verify_driver_attach(hf, pid);
			if (!attach_ok) {
				log_msg(hf, "launch", "FAIL -- driver attach verification failed for pid=%u; feature tests cannot trust target reads", pid);
				g_driver_attached.store(false, std::memory_order_release);
				g_target_unavailable.store(true, std::memory_order_release);
			} else {
				g_target_unavailable.store(false, std::memory_order_release);
				log_msg(hf, "launch", "PASS -- target launched and driver attach verified pid=%u", pid);
			}

			log_phase_end(hf, "launch target");
			return attach_ok;
		}

		DWORD run_testlab_feature_seh(test_lab::run_fn fn, test_lab::state_t& s, test_lab::result_t& r) {
			__try {
				fn(s, r);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
			return 0;
		}


		void phase_testlab_features(HANDLE hf, std::uint32_t target_pid) {
			set_phase("Test Lab features");
			log_phase_begin(hf, "testlab features");
			const auto& features = test_lab::all_features();
			int total = static_cast<int>(features.size());
			log_msg(hf, "testlab", "running %d registered features against target pid=%u ...", total, target_pid);

			const std::uint32_t attached_pid = driver_bridge::attached_pid();
			const bool target_verified = target_pid != 0
				&& g_driver_attached.load(std::memory_order_acquire)
				&& attached_pid == target_pid;
			if (!target_verified) {
				mark_target_unavailable(hf, "testlab", "testlab skipped because there is no verified attached target", target_pid, attached_pid, 0);
				if (total > 0) {
					g_skipped.fetch_add(total);
					g_prerequisite_skipped.fetch_add(total);
				}
				{
					std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
					const int index = phase_ledger_index_locked("testlab features");
					if (index >= 0)
						g_phase_ledger[static_cast<std::size_t>(index)].status = "PREREQUISITE_FAILED";
				}
				log_msg(hf, "testlab", "SKIP -- %d registered Test Lab features require a verified target; prerequisite failed; target_pid=%u driver_attached=%d driver_pid=%u",
					total,
					target_pid,
					g_driver_attached.load(std::memory_order_acquire) ? 1 : 0,
					attached_pid);
				log_phase_end(hf, "testlab features");
				return;
			}

			for (int i = 0; i < total; ++i) {
				if (cancelled()) {
					log_msg(hf, "testlab", "cancelled by user");
					break;
				}

				const auto& f = features[static_cast<std::size_t>(i)];
				g_current.store(running_done(), std::memory_order_release);

				const char* name = (f.name != nullptr) ? f.name : "?";
				const char* cat  = (f.category != nullptr) ? f.category : "?";

				if (is_destructive(f.category, f.name)) {
					if (!record_destructive_skip_key(hf, i + 1, total, f.category, f.name))
						g_failed.fetch_add(1, std::memory_order_acq_rel);
					continue;
				}
				if (f.run == nullptr) {
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s (no run fn)", i + 1, total, cat, name);
					g_failed.fetch_add(1);
					continue;
				}

				test_lab::state_t s;
				populate_defaults(s, target_pid);
				std::uint64_t cleanup_alloc = 0;

				if (name_starts_with(name, "PMOD")) {
					s.u32_a = 2;
				} else if (name_starts_with(name, "PRED")) {
					s.u32_a = 3;
				} else if (name_starts_with(name, "NLOG")) {
					s.u32_a = 1;
				} else if (name_starts_with(name, "NCAP")) {
					s.u32_a = 1;
					s.pid = target_pid;
				} else if (name_starts_with(name, "NFLT")) {
					s.u32_a = 3;
				} else if (name_starts_with(name, "IHLD")) {
					s.u32_a = 2;
					s.pid = target_pid;
				} else if (name_starts_with(name, "NFPR")) {
					s.u32_b = 2;
				} else if (name_starts_with(name, "DNSS")) {
					s.u32_a = 3;
				} else if (name_starts_with(name, "BWMN")) {
					s.u32_a = 3;
				} else if (name_starts_with(name, "REGISTER_PID") || name_starts_with(name, "UNREGISTER_PID")) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_sandbox_test";
					if (s.pid == 0) {
						s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
					}
				} else if (name_starts_with(name, "PCEX")) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_test_capture.pcap";
				} else if (name_starts_with(name, "FM")) {
					std::uint64_t alloc = driver_bridge::allocate_memory(0x1000);
					if (alloc != 0) {
						s.addr = alloc;
						s.size = 0x1000;
						cleanup_alloc = alloc;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: allocated target page 0x%016llX for free validation",
							i + 1, total, name, static_cast<unsigned long long>(alloc));
					} else {
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: WARN allocate_memory failed; using default addr=0x%016llX",
							i + 1, total, name, static_cast<unsigned long long>(s.addr));
					}
				} else if (name_starts_with(name, "PM")) {
					std::uint64_t alloc = driver_bridge::allocate_memory(0x1000);
					if (alloc != 0) {
						s.addr = alloc;
						s.size = 0x1000;
						s.u32_a = PAGE_READWRITE;
						cleanup_alloc = alloc;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: allocated target page 0x%016llX protect=0x%08X",
							i + 1, total, name, static_cast<unsigned long long>(alloc), s.u32_a);
					} else {
						s.u32_a = PAGE_READWRITE;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: WARN allocate_memory failed; using default addr=0x%016llX protect=0x%08X",
							i + 1, total, name, static_cast<unsigned long long>(s.addr), s.u32_a);
					}
				} else if (name_starts_with(name, "PHYS") || name_starts_with(name, "MEX") || name_starts_with(name, "V2P")) {
					std::uint64_t saved = g_saved_dtb.load(std::memory_order_acquire);
					if (saved != 0) {
						s.u64_a = saved;
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: injecting saved_dtb=0x%016llX into u64_a",
							i + 1, total, name, static_cast<unsigned long long>(saved));
					} else {
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: WARN no saved dtb (u64_a=0); test may fail",
							i + 1, total, name);
					}
					if (name_starts_with(name, "MEX")) {
						for (const auto& mod : driver_bridge::enumerate_modules_for(target_pid)) {
							if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
								s.addr = mod.base;
								s.text_a = mod.name;
								s.text_b = "NtClose";
								log_msg(hf, "testlab", "[%d/%d] MEX-fixture: module=%s base=0x%016llX export=%s",
									i + 1, total, mod.name.c_str(),
									static_cast<unsigned long long>(mod.base), s.text_b.c_str());
								break;
							}
						}
					}
				}

				test_lab::result_t r;

				log_msg(hf, "testlab", "[%d/%d] START %s/%s pid=%u tid=%u addr=0x%016llX u64_a=0x%016llX u32_a=%u u32_b=%u size=%u text_a=\"%.32s\"",
					i + 1, total, cat, name, s.pid, s.tid,
					static_cast<unsigned long long>(s.addr),
					static_cast<unsigned long long>(s.u64_a),
					s.u32_a, s.u32_b, s.size,
					s.text_a.empty() ? "(none)" : s.text_a.c_str());
				set_stepf("testlab %d/%d %s/%s", i + 1, total, cat, name);
				auto t0 = std::chrono::steady_clock::now();
				DWORD seh_code = 0;
				bool cpp_exception = false;
				std::string cpp_error;
				try {
					seh_code = run_testlab_feature_seh(f.run, s, r);
				} catch (const std::exception& ex) {
					cpp_exception = true;
					cpp_error = ex.what();
				} catch (...) {
					cpp_exception = true;
					cpp_error = "unknown C++ exception";
				}
				auto t1 = std::chrono::steady_clock::now();
				auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
				if (r.elapsed_us == 0) r.elapsed_us = static_cast<std::uint64_t>(us);
				log_msg(hf, "testlab", "[%d/%d] END-RUN %s/%s seh=0x%08lX cpp_exception=%d elapsed=%llu us state=%d ok=%d skipped=%d bytes=%u fields=%zu raw=%zu",
					i + 1, total, cat, name,
					static_cast<unsigned long>(seh_code),
					cpp_exception ? 1 : 0,
					static_cast<unsigned long long>(r.elapsed_us),
					static_cast<int>(r.state.load()),
					r.ok ? 1 : 0,
					r.skipped ? 1 : 0,
					r.bytes_returned,
					r.parsed.size(),
					r.raw.size());

				if (seh_code != 0) {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s threw SEH exception 0x%08lX elapsed=%llu us",
						i + 1, total, cat, name,
						static_cast<unsigned long>(seh_code),
						static_cast<unsigned long long>(r.elapsed_us));
					if (cleanup_alloc != 0) {
						bool freed = driver_bridge::free_memory(cleanup_alloc);
						log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup after SEH addr=0x%016llX freed=%d",
							i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
					}
					continue;
				}

				if (cpp_exception) {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s threw C++ exception \"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						cpp_error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
					if (cleanup_alloc != 0) {
						bool freed = driver_bridge::free_memory(cleanup_alloc);
						log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup after C++ exception addr=0x%016llX freed=%d",
							i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
					}
					continue;
				}

				if (name_starts_with(name, "DTB") && r.ok) {
					for (const auto& kv : r.parsed) {
						if (kv.label == "CR3 (DTB)") {
							std::uint64_t dtb = std::strtoull(kv.value.c_str(), nullptr, 16);
							if (dtb != 0) {
								g_saved_dtb.store(dtb, std::memory_order_release);
								log_msg(hf, "testlab", "[%d/%d] DTB-save: cr3=0x%016llX saved for PHYS/MEX/V2P tests",
									i + 1, total, static_cast<unsigned long long>(dtb));
							}
							break;
						}
					}
				}

				for (const auto& kv : r.parsed) {
					log_msg(hf, "testlab", "[%d/%d] FIELD %s/%s \"%s\" = \"%s\"",
						i + 1, total, cat, name, kv.label.c_str(), kv.value.c_str());
				}

				if (!r.raw.empty()) {
					char hex_preview[97] = {};
					std::size_t preview_n = std::min(r.raw.size(), std::size_t(16));
					for (std::size_t bi = 0; bi < preview_n; ++bi) {
						std::snprintf(hex_preview + bi * 3, sizeof(hex_preview) - bi * 3, "%02X ", static_cast<unsigned>(r.raw[bi]));
					}
					log_msg(hf, "testlab", "[%d/%d] RAW %s/%s total_bytes=%zu raw_preview=[%s]",
						i + 1, total, cat, name, r.raw.size(), hex_preview);
				}

				if (r.skipped) {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s reported a non-destructive skip ntstatus=%s reason=\"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						test_lab_format::ntstatus_to_string(r.ntstatus),
						r.error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
				} else if (r.ok) {
					std::string evidence_reason;
					if (feature_evidence_failure_reason(cat, name, r, evidence_reason)) {
						g_failed.fetch_add(1);
						log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s evidence gate rejected success ntstatus=%s bytes=%u parsed_fields=%zu raw=%zu reason=\"%s\" elapsed=%llu us",
							i + 1, total, cat, name,
							test_lab_format::ntstatus_to_string(r.ntstatus),
							r.bytes_returned,
							r.parsed.size(),
							r.raw.size(),
							evidence_reason.c_str(),
							static_cast<unsigned long long>(r.elapsed_us));
					} else {
						g_passed.fetch_add(1);
						bool target_verified = g_driver_attached.load(std::memory_order_acquire) && target_pid != 0;
						if (!target_verified) {
							g_suspect.fetch_add(1);
							log_msg(hf, "testlab", "[%d/%d] PASS %s/%s SUSPECT (no verified target attach; success may be against host/self) ntstatus=%s bytes=%u elapsed=%llu us",
								i + 1, total, cat, name,
								test_lab_format::ntstatus_to_string(r.ntstatus),
								r.bytes_returned,
								static_cast<unsigned long long>(r.elapsed_us));
						} else {
							log_msg(hf, "testlab", "[%d/%d] PASS %s/%s ntstatus=%s bytes=%u parsed_fields=%zu elapsed=%llu us",
								i + 1, total, cat, name,
								test_lab_format::ntstatus_to_string(r.ntstatus),
								r.bytes_returned,
								r.parsed.size(),
								static_cast<unsigned long long>(r.elapsed_us));
						}
					}
				} else {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s ntstatus=%s error=\"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						test_lab_format::ntstatus_to_string(r.ntstatus),
						r.error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
				}
				if (cleanup_alloc != 0 && (!name_starts_with(name, "FM") || !r.ok)) {
					bool freed = driver_bridge::free_memory(cleanup_alloc);
					log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup addr=0x%016llX freed=%d",
						i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
				}
			}
			const int skip_accounting_errors = log_destructive_skip_accounting(hf, "testlab", "testlab features phase", false);
			if (skip_accounting_errors != 0) {
				g_failed.fetch_add(1, std::memory_order_acq_rel);
				log_msg(hf, "testlab", "FAIL -- destructive skip-key phase accounting errors=%d", skip_accounting_errors);
			}
			log_phase_end(hf, "testlab features");
		}


		bool require_target(HANDLE hf, const char* tag) {
			std::uint32_t pid = current_target_pid();
			bool attached = g_driver_attached.load(std::memory_order_acquire);
			if (pid == 0 || !attached || driver_bridge::attached_pid() != pid) {
				mark_target_unavailable(hf, tag, "no verified attached target", pid, driver_bridge::attached_pid(), 0);
				log_msg(hf, tag, "FAIL -- no verified attached target (pid=%u attached=%d driver_pid=%u)",
					pid, static_cast<int>(attached), driver_bridge::attached_pid());
				g_failed.fetch_add(1);
				return false;
			}
			std::uint32_t exit_code = 0;
			if (!driver_bridge::attached_process_alive(&exit_code)) {
				mark_target_unavailable(hf, tag, "attached target is dead; target-dependent tests will be skipped", pid, driver_bridge::attached_pid(), exit_code);
				log_msg(hf, tag, "FAIL -- attached target pid=%u is dead exit_code_or_err=0x%08X",
					pid, exit_code);
				g_failed.fetch_add(1);
				return false;
			}
			return true;
		}


		void test_disassembly_view(HANDLE hf) {
			const char* tag = "disasm";
			set_phase("Disassembly view");
			log_msg(hf, tag, "START -- decode disassembly window from attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint32_t pid = current_target_pid();
			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			std::uint64_t expected_base = (addr > 0x100) ? addr - 0x100 : 0;
			const std::uint32_t attached_pid = driver_bridge::attached_pid();
			log_msg(hf, tag, "requesting disasm refresh at target 0x%016llX (pid=%u attached_pid=%u expected_base=0x%016llX size=0x%X driver_status=\"%s\" driver_error=\"%s\")",
				static_cast<unsigned long long>(addr),
				pid,
				attached_pid,
				static_cast<unsigned long long>(expected_base),
				0x400u,
				driver_bridge::status().c_str(),
				driver_bridge::last_error().c_str());
			debugger_engine::request_disasm_refresh(addr, 0);

			std::vector<std::uint8_t> bytes;
			std::uint64_t base_out = 0;
			int attempts = 0;
			for (int i = 0; i < 60; ++i) {
				if (cancelled()) break;
				++attempts;
				Sleep(50);
				bytes = debugger_engine::cached_disasm_window(base_out);
				if (!bytes.empty() && base_out == expected_base) break;
				debugger_engine::request_disasm_refresh(addr, 0);
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			log_msg(hf, tag, "cache poll result attempts=%d bytes=%zu base=0x%016llX expected=0x%016llX debugger_error=\"%s\" elapsed=%lld ms",
				attempts,
				bytes.size(),
				static_cast<unsigned long long>(base_out),
				static_cast<unsigned long long>(expected_base),
				debugger_engine::last_error().c_str(),
				(long long)ms);

			if (bytes.empty() || base_out != expected_base) {
				log_msg(hf, tag, "FAIL -- disasm window not populated for target (bytes=%zu base=0x%016llX expected=0x%016llX attached_pid=%u size=0x%X debugger_error=\"%s\") (elapsed %lld ms)",
					bytes.size(), static_cast<unsigned long long>(base_out),
					static_cast<unsigned long long>(expected_base),
					driver_bridge::attached_pid(),
					0x400u,
					debugger_engine::last_error().c_str(),
					(long long)ms);
				g_failed.fetch_add(1);
				return;
			}

			std::uint64_t offset = (addr > base_out) ? (addr - base_out) : 0;
			int decoded = 0;
			int non_db = 0;
			char first_mnem[32] = {};
			std::uint64_t scan = offset;
			while (scan + 1 < bytes.size() && decoded < 8) {
				int avail = static_cast<int>(bytes.size() - scan);
				if (avail > 15) avail = 15;
				AsmInstr ins = zydis_decode_one(bytes.data() + scan, avail, base_out + scan);
				if (decoded == 0)
					std::snprintf(first_mnem, sizeof(first_mnem), "%s", ins.mnem);
				if (std::strcmp(ins.mnem, "db") != 0)
					++non_db;
				if (ins.len <= 0) break;
				scan += static_cast<std::uint64_t>(ins.len);
				++decoded;
			}

			if (non_db > 0) {
				log_msg(hf, tag, "PASS -- disasm window %zu bytes at base 0x%016llX, decoded %d instrs (%d real, first=\"%s\", pass_path=\"forced_sync_cache\") (elapsed %lld ms)",
					bytes.size(), static_cast<unsigned long long>(base_out),
					decoded, non_db, first_mnem, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- disasm window had %zu bytes but no instruction decoded (decoded=%d) (elapsed %lld ms)",
					bytes.size(), decoded, (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_memory_scanner(HANDLE hf) {
			const char* tag = "memscan";
			const int done_before = running_done();
			set_phase("Memory scanner");
			try {
				log_msg(hf, tag, "START -- scan attached target for resident PE marker string");
				auto t0 = std::chrono::steady_clock::now();

				if (!require_target(hf, tag)) return;

				std::uint32_t pid = current_target_pid();
				std::uint64_t image_base = current_target_image_base();

				cleanup_memory_scanner_runtime(hf, "before memory scanner feature", 3000);
				memory_scanner::reset_scan();
				memory_scanner::scan_config_t cfg;
				cfg.value_type = memory_scanner::value_type_t::string_ascii;
				cfg.scan_mode = memory_scanner::scan_mode_t::exact;
				cfg.value_text = "This program cannot be run in DOS mode";
				cfg.writable_only = false;
				cfg.executable_exclude = false;
				cfg.range_base = image_base;
				cfg.range_size = image_base != 0 ? 0x1000 : 0;

				log_msg(hf, tag, "first_scan ASCII \"%s\" against pid=%u range=0x%016llX+0x%llX",
					cfg.value_text.c_str(), pid,
					static_cast<unsigned long long>(cfg.range_base),
					static_cast<unsigned long long>(cfg.range_size));
				bool ok = memory_scanner::first_scan(cfg);
				if (!ok) {
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					log_msg(hf, tag, "FAIL -- first_scan rejected attached target pid=%u range=0x%016llX+0x%llX (elapsed %lld ms)",
						pid,
						static_cast<unsigned long long>(cfg.range_base),
						static_cast<unsigned long long>(cfg.range_size),
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				bool idle = false;
				for (int i = 0; i < 50; ++i) {
					if (cancelled()) break;
					if (memory_scanner_scan_idle()) {
						idle = true;
						break;
					}
					Sleep(20);
				}
				if (!idle)
					idle = wait_memory_scanner_scan_idle(500);
				if (!idle) {
					request_memory_scanner_stop();
					wait_memory_scanner_scan_idle(500);
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					auto& st = memory_scanner::g_state;
					log_msg(hf, tag, "FAIL -- first_scan timed out before results became idle scanning=%d scan_done=%d progress=%.3f (elapsed %lld ms)",
						st.scanning.load(std::memory_order_acquire) ? 1 : 0,
						st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
						st.scan_progress.load(std::memory_order_acquire),
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				std::size_t found = 0;
				std::uint64_t first_addr = 0;
				if (!snapshot_memory_scan_results(found, first_addr, 2000)) {
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					log_msg(hf, tag, "FAIL -- scanner results mutex remained busy after idle scan (elapsed %lld ms)",
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();

				if (found > 0) {
					log_msg(hf, tag, "PASS -- scanner found %zu live matches in target (first=0x%016llX) (elapsed %lld ms)",
						found, static_cast<unsigned long long>(first_addr), (long long)ms);
					g_passed.fetch_add(1);
					return;
				}

				log_msg(hf, tag, "scanner string scan empty after successful idle scan; validating target memory directly");

				std::vector<std::uint8_t> sample;
				bool read_ok = (image_base != 0) &&
					driver_bridge::read_memory_for(pid, image_base, 0x1000, sample);
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();

				const std::string marker = cfg.value_text;
				bool marker_present = read_ok && sample.size() >= marker.size() &&
					std::search(sample.begin(), sample.end(), marker.begin(), marker.end()) != sample.end();
				bool mz_present = read_ok && sample.size() >= 2 && sample[0] == 'M' && sample[1] == 'Z';

				if (marker_present) {
					log_msg(hf, tag, "FAIL -- scanner missed readable PE marker at target image base 0x%016llX (read bytes=%zu elapsed %lld ms)",
						static_cast<unsigned long long>(image_base), sample.size(), (long long)ms);
				} else if (mz_present) {
					log_msg(hf, tag, "FAIL -- target image base was readable but expected PE marker was absent from first page (bytes=%zu elapsed %lld ms)",
						sample.size(), (long long)ms);
				} else {
					log_msg(hf, tag, "FAIL -- scanner found 0 matches and direct target read failed or returned non-PE data (read_ok=%d bytes=%zu elapsed %lld ms)",
						static_cast<int>(read_ok), sample.size(), (long long)ms);
				}
				g_failed.fetch_add(1);
			} catch (const std::exception& ex) {
				request_memory_scanner_stop();
				wait_memory_scanner_scan_idle(3000);
				log_msg(hf, tag, "FAIL -- memory scanner test raised C++ exception: %s", ex.what());
				if (running_done() == done_before)
					g_failed.fetch_add(1);
			} catch (...) {
				request_memory_scanner_stop();
				wait_memory_scanner_scan_idle(3000);
				log_msg(hf, tag, "FAIL -- memory scanner test raised unknown C++ exception");
				if (running_done() == done_before)
					g_failed.fetch_add(1);
			}
		}


		void test_network_view(HANDLE hf) {
			const char* tag = "netview";
			set_phase("Network view");
			log_msg(hf, tag, "START -- enumerate live network endpoints of attached target");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			if (!driver_bridge::using_kernel_driver()) {
				log_msg(hf, tag, "FAIL -- kernel driver not loaded, cannot enumerate target network state");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();

			std::vector<driver_bridge::net_connection_info_t> conns;
			std::vector<driver_bridge::socket_info_t> sockets;
			std::vector<driver_bridge::tcpip_connection_t> tcpip;
			std::size_t observed = 0;
			std::uint32_t attempts = 0;
			for (std::uint32_t attempt = 0; attempt < 20; ++attempt) {
				++attempts;
				conns = driver_bridge::enumerate_connections(pid, 0);
				sockets = driver_bridge::get_socket_handles(pid);
				tcpip = driver_bridge::dump_tcpip_connections(pid, 0);
				observed = conns.size() + sockets.size() + tcpip.size();
				if (observed > 0)
					break;
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			log_msg(hf, tag, "target pid=%u connections=%zu sockets=%zu tcpip=%zu attempts=%u",
				pid, conns.size(), sockets.size(), tcpip.size(), attempts);

			if (observed > 0) {
				std::uint32_t lport = 0, rport = 0;
				if (!conns.empty()) {
					lport = conns.front().local_port;
					rport = conns.front().remote_port;
				} else if (!sockets.empty()) {
					lport = sockets.front().local_port;
					rport = sockets.front().remote_port;
				} else if (!tcpip.empty()) {
					lport = tcpip.front().local_port;
					rport = tcpip.front().remote_port;
				}
				log_msg(hf, tag, "PASS -- observed %zu live endpoints for target (first local_port=%u remote_port=%u) (elapsed %lld ms)",
					observed, lport, rport, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				auto all_conns = driver_bridge::enumerate_connections(0, 0);
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();
				if (!all_conns.empty()) {
					log_msg(hf, tag, "FAIL -- target had 0 live endpoints after %u attempts while driver enumerated %zu system-wide; target not network-active at sample time (elapsed %lld ms)",
						attempts,
						all_conns.size(), (long long)ms);
					g_failed.fetch_add(1);
				} else {
					log_msg(hf, tag, "FAIL -- driver returned 0 connections target-scoped and system-wide (elapsed %lld ms)", (long long)ms);
					g_failed.fetch_add(1);
				}
			}
		}


		void test_hex_view(HANDLE hf) {
			const char* tag = "hexview";
			set_phase("Hex view");
			log_msg(hf, tag, "START -- read attached target image base through driver and validate MZ header");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint32_t pid = current_target_pid();
			std::uint64_t image_base = current_target_image_base();
			if (image_base == 0) {
				log_msg(hf, tag, "FAIL -- target image base unknown");
				g_failed.fetch_add(1);
				return;
			}

			std::vector<std::uint8_t> data;
			bool read_ok = driver_bridge::read_memory_for(pid, image_base, 256, data);

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (!read_ok || data.size() < 64) {
				log_msg(hf, tag, "FAIL -- driver read returned %zu bytes (read_ok=%d last_error=\"%s\") (elapsed %lld ms)",
					data.size(), static_cast<int>(read_ok), driver_bridge::last_error().c_str(), (long long)ms);
				g_failed.fetch_add(1);
				return;
			}

			bool is_mz = (data[0] == 'M' && data[1] == 'Z');
			std::uint32_t e_lfanew = 0;
			if (data.size() >= 0x40) {
				e_lfanew = static_cast<std::uint32_t>(data[0x3C]) |
					(static_cast<std::uint32_t>(data[0x3D]) << 8) |
					(static_cast<std::uint32_t>(data[0x3E]) << 16) |
					(static_cast<std::uint32_t>(data[0x3F]) << 24);
			}

			if (is_mz) {
				log_msg(hf, tag, "PASS -- target image base 0x%016llX hex dump %zu bytes, MZ header present, e_lfanew=0x%08X (elapsed %lld ms)",
					static_cast<unsigned long long>(image_base), data.size(),
					e_lfanew, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- target image base read %zu bytes but no MZ header (first=%02X %02X) (elapsed %lld ms)",
					data.size(), data[0], data[1], (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_aob_generator(HANDLE hf) {
			const char* tag = "aobgen";
			set_phase("AOB generator");
			log_msg(hf, tag, "START -- generate AOB signature from attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();
			log_msg(hf, tag, "generate_from_address target addr=0x%016llX (pid=%u)",
				static_cast<unsigned long long>(addr), pid);

			aob_generator::generate_from_address(addr, 8, true);

			bool done = false;
			for (int i = 0; i < 50; ++i) {
				if (cancelled()) break;
				if (!aob_generator::g_state.generating.load()) { done = true; break; }
				Sleep(40);
			}

			std::size_t byte_count = 0;
			std::uint64_t result_addr = 0;
			std::string sig_text;
			std::string err;
			{
				std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
				byte_count = aob_generator::g_state.current.bytes.size();
				result_addr = aob_generator::g_state.current.address;
				sig_text = aob_generator::format_signature(aob_generator::g_state.current);
				err = aob_generator::g_state.last_error;
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (done && byte_count > 0 && result_addr == addr) {
				log_msg(hf, tag, "PASS -- generated %zu-byte signature for target 0x%016llX: %s (elapsed %lld ms)",
					byte_count, static_cast<unsigned long long>(result_addr),
					sig_text.c_str(), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- AOB generation produced %zu bytes for addr=0x%016llX (done=%d error=\"%s\") (elapsed %lld ms)",
					byte_count, static_cast<unsigned long long>(result_addr),
					static_cast<int>(done), err.c_str(), (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_cfg_view(HANDLE hf) {
			const char* tag = "cfgview";
			set_phase("CFG view");
			log_msg(hf, tag, "START -- build control flow graph for attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();
			log_msg(hf, tag, "build_cfg target entry=0x%016llX (pid=%u)",
				static_cast<unsigned long long>(addr), pid);

			cfg_view::clear();
			cfg_view::build_cfg(addr);

			bool finished = false;
			for (int i = 0; i < 240; ++i) {
				if (cancelled()) break;
				if (!cfg_view::g_state.building.load()) { finished = true; break; }
				Sleep(25);
			}

			const auto model = cfg_view::capture_model();
			const std::size_t blocks = model ? model->blocks.size() : 0;
			const std::size_t nodes = model ? model->graph.nodes.size() : 0;
			const std::size_t edges = model ? model->graph.edges.size() : 0;
			const bool built = model && !model->blocks.empty();
			const std::uint64_t entry = model ? model->entry_addr : 0;

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (finished && built && blocks > 0 && entry == addr) {
				log_msg(hf, tag, "PASS -- CFG built for target 0x%016llX: %zu blocks, %zu nodes, %zu edges (elapsed %lld ms)",
					static_cast<unsigned long long>(addr), blocks, nodes, edges, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- CFG build incomplete blocks=%zu built=%d finished=%d entry=0x%016llX (elapsed %lld ms)",
					blocks, static_cast<int>(built), static_cast<int>(finished),
					static_cast<unsigned long long>(entry), (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void phase_extended_features(HANDLE hf) {
			set_phase("Extended feature tests");
			log_phase_begin(hf, "extended features");
			log_msg(hf, "extended", "running 6 extended feature tests against attached target ...");

			if (!cancelled()) test_disassembly_view(hf);
			if (!cancelled()) test_memory_scanner(hf);
			if (!cancelled()) test_network_view(hf);
			if (!cancelled()) test_hex_view(hf);
			if (!cancelled()) test_aob_generator(hf);
			if (!cancelled()) test_cfg_view(hf);

			log_phase_end(hf, "extended features");
		}

		void drain_decompiler_runtime(HANDLE hf, const char* reason) {
			set_stepf("decompiler drain: %s", reason ? reason : "unspecified");
			const std::uint32_t target_pid = current_target_pid();
			const std::uint32_t attached_pid = driver_bridge::attached_pid();
			const bool driver_attached = g_driver_attached.load(std::memory_order_acquire);
			log_msg(hf, "decompiler-drain",
				"BEGIN -- %s target_pid=%u driver_attached=%d attached_pid=%u",
				reason ? reason : "unspecified",
				target_pid,
				driver_attached ? 1 : 0,
				attached_pid);

			if (cancelled()) {
				log_msg(hf, "decompiler-drain",
					"CANCELLED -- target_pid=%u resolution=cancelled_before_resolution",
					target_pid);
				return;
			}
			if (target_pid == 0) {
				log_msg(hf, "decompiler-drain",
					"SKIP -- target_pid=0 resolution=target_pid_unavailable");
				return;
			}
			if (target_pid == static_cast<std::uint32_t>(GetCurrentProcessId())) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u resolution=SELF_TARGET_REFUSED",
					target_pid);
				return;
			}
			if (!driver_attached || attached_pid != target_pid) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u resolution=driver_target_identity_mismatch driver_attached=%d attached_pid=%u",
					target_pid,
					driver_attached ? 1 : 0,
					attached_pid);
				return;
			}

			auto query_creation_time = [](std::uint32_t pid,
				std::uint64_t& creation_time,
				DWORD& exit_code,
				DWORD& error) noexcept {
				creation_time = 0;
				exit_code = 0;
				error = ERROR_SUCCESS;
				HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
					FALSE, static_cast<DWORD>(pid));
				if (!process) {
					error = GetLastError();
					return false;
				}
				const bool status_ok = GetExitCodeProcess(process, &exit_code) != FALSE;
				if (!status_ok) {
					error = GetLastError();
					CloseHandle(process);
					return false;
				}
				if (exit_code != STILL_ACTIVE) {
					error = ERROR_PROCESS_ABORTED;
					CloseHandle(process);
					return false;
				}
				FILETIME created{};
				FILETIME exited{};
				FILETIME kernel{};
				FILETIME user{};
				if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
					error = GetLastError();
					CloseHandle(process);
					return false;
				}
				ULARGE_INTEGER value{};
				value.LowPart = created.dwLowDateTime;
				value.HighPart = created.dwHighDateTime;
				creation_time = value.QuadPart;
				CloseHandle(process);
				return creation_time != 0;
			};

			std::uint64_t target_creation_time = 0;
			DWORD target_exit_code = 0;
			DWORD target_identity_error = ERROR_SUCCESS;
			if (!query_creation_time(target_pid, target_creation_time,
				target_exit_code, target_identity_error)) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u resolution=process_identity_unavailable exit_code=%lu gle=%lu",
					target_pid,
					static_cast<unsigned long>(target_exit_code),
					static_cast<unsigned long>(target_identity_error));
				return;
			}

			aida::analysis::target_selector_t selector;
			selector.pid = target_pid;
			selector.process_creation_time_100ns = target_creation_time;
			auto resolved = aida::analysis::workspace_registry().resolve(selector);
			if (!resolved) {
				const auto& error = resolved.error();
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u creation_time=%llu resolution=%s phase=%s message=%s",
					target_pid,
					static_cast<unsigned long long>(target_creation_time),
					error.stable_code().c_str(),
					error.phase.c_str(),
					error.message.c_str());
				return;
			}
			auto target_workspace = resolved.take_value();
			if (!target_workspace) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u resolution=null_workspace",
					target_pid);
				return;
			}

			const auto& target_process = target_workspace->identity().process();
			const std::string binary_id = target_workspace->identity().binary_id().to_hex();
			if (target_workspace->target_kind() != aida::analysis::target_kind_t::live_snapshot ||
				!target_process || target_process->pid != target_pid ||
				target_process->creation_time_100ns != target_creation_time) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u binary_id=%s resolution=workspace_identity_mismatch",
					target_pid,
					binary_id.c_str());
				return;
			}
			if (target_workspace->closing() || target_workspace->closed()) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u binary_id=%s resolution=workspace_closing closing=%d closed=%d",
					target_pid,
					binary_id.c_str(),
					target_workspace->closing() ? 1 : 0,
					target_workspace->closed() ? 1 : 0);
				return;
			}

			auto target_context = disasm_view::capture_workspace(target_workspace);
			if (!target_context.workspace || target_context.workspace != target_workspace) {
				g_suspect.fetch_add(1);
				log_msg(hf, "decompiler-drain",
					"SUSPECT -- target_pid=%u binary_id=%s resolution=workspace_closed_during_capture",
					target_pid,
					binary_id.c_str());
				return;
			}

			const auto target_service = target_workspace->decompiler();
			const auto before_snapshot = target_service
				? target_service->snapshot()
				: aida::analysis::decompiler_service_snapshot_t{};
			const int before_tabs = pseudocode_view::tab_count(target_context);
			log_msg(hf, "decompiler-drain",
				"STATE -- target_pid=%u creation_time=%llu binary_id=%s service=%d accepting=%d active=%zu tabs=%d",
				target_pid,
				static_cast<unsigned long long>(target_creation_time),
				binary_id.c_str(),
				target_service ? 1 : 0,
				before_snapshot.accepting ? 1 : 0,
				before_snapshot.active_contexts,
				before_tabs);

			pseudocode_view::close_all_tabs(target_context);
			const int tabs_after_cancel = pseudocode_view::tab_count(target_context);
			const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
			const auto wait_started = std::chrono::steady_clock::now();
			std::size_t target_active = before_snapshot.active_contexts;
			bool wait_cancelled = false;
			bool observed_closing = false;
			bool observed_closed = false;
			bool service_detached = false;
			bool service_replaced = false;
			std::uint32_t consecutive_idle_samples = 0;
			while (target_service) {
				if (cancelled()) {
					wait_cancelled = true;
					break;
				}
				target_active = target_service->snapshot().active_contexts;
				if (target_active == 0) {
					++consecutive_idle_samples;
					if (consecutive_idle_samples >= 2)
						break;
				} else {
					consecutive_idle_samples = 0;
				}
				if (std::chrono::steady_clock::now() >= deadline)
					break;
				Sleep(25);
				observed_closing = observed_closing || target_workspace->closing();
				observed_closed = observed_closed || target_workspace->closed();
				const auto current_service = target_workspace->decompiler();
				service_detached = service_detached ||
					(target_service && !current_service);
				service_replaced = service_replaced ||
					(current_service && current_service.get() != target_service.get());
			}
			observed_closing = observed_closing || target_workspace->closing();
			observed_closed = observed_closed || target_workspace->closed();
			const auto final_service = target_workspace->decompiler();
			service_detached = service_detached ||
				(target_service && !final_service);
			service_replaced = service_replaced ||
				(final_service && target_service && final_service.get() != target_service.get());
			const bool service_appeared = !target_service && final_service;
			if (target_service)
				target_active = target_service->snapshot().active_contexts;
			const bool idle = !target_service || target_active == 0;
			const bool timed_out = !idle && !wait_cancelled &&
				std::chrono::steady_clock::now() >= deadline;
			const int final_tabs = pseudocode_view::tab_count(target_context);
			std::uint64_t final_creation_time = 0;
			DWORD final_exit_code = 0;
			DWORD final_identity_error = ERROR_SUCCESS;
			const bool process_identity_current = query_creation_time(target_pid,
				final_creation_time, final_exit_code, final_identity_error) &&
				final_creation_time == target_creation_time;
			const bool driver_identity_current =
				current_target_pid() == target_pid &&
				g_driver_attached.load(std::memory_order_acquire) &&
				driver_bridge::attached_pid() == target_pid;
			const bool detached_without_close = service_detached &&
				!observed_closing && !observed_closed;
			const bool suspect = !wait_cancelled &&
				(!idle || timed_out || service_replaced || service_appeared ||
					detached_without_close || observed_closing || observed_closed ||
					tabs_after_cancel != 0 || final_tabs != 0 ||
					!process_identity_current || !driver_identity_current);
			if (suspect)
				g_suspect.fetch_add(1);
			const auto waited_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - wait_started).count();
			const char* disposition = suspect
				? "SUSPECT"
				: wait_cancelled
					? "CANCELLED"
					: target_service
						? "PASS"
						: "PASS_NO_SERVICE";
			log_msg(hf, "decompiler-drain",
				"%s -- target_pid=%u creation_time=%llu binary_id=%s idle=%d cancelled=%d timed_out=%d waited_ms=%lld closing=%d closed=%d service_detached=%d service_replaced=%d service_appeared=%d tabs_before=%d tabs_after_cancel=%d tabs_final=%d active_target=%zu process_identity_current=%d driver_identity_current=%d exit_code=%lu gle=%lu",
				disposition,
				target_pid,
				static_cast<unsigned long long>(target_creation_time),
				binary_id.c_str(),
				idle ? 1 : 0,
				wait_cancelled ? 1 : 0,
				timed_out ? 1 : 0,
				static_cast<long long>(waited_ms),
				observed_closing ? 1 : 0,
				observed_closed ? 1 : 0,
				service_detached ? 1 : 0,
				service_replaced ? 1 : 0,
				service_appeared ? 1 : 0,
				before_tabs,
				tabs_after_cancel,
				final_tabs,
				target_active,
				process_identity_current ? 1 : 0,
				driver_identity_current ? 1 : 0,
				static_cast<unsigned long>(final_exit_code),
				static_cast<unsigned long>(final_identity_error));
		}


		void phase_stop_target(HANDLE hf, std::uint32_t pid) {
			if (pid == 0) return;
			set_phase("Stopping test_target");
			auto threads = driver_bridge::enumerate_threads_for(pid);
			uint32_t observed_threads = 0;
			uint32_t resume_calls = 0;
			uint32_t resume_failures = 0;
			for (const auto& th : threads) {
				if (th.owner_pid != pid || th.tid == 0)
					continue;
				++observed_threads;
				for (int guard = 0; guard < 8; ++guard) {
					uint32_t prev_count = 0;
					if (!driver_bridge::resume_thread(th.tid, &prev_count)) {
						++resume_failures;
						break;
					}
					++resume_calls;
					if (prev_count <= 1)
						break;
				}
			}
			log_msg(hf, "cleanup", "pre-signal thread resume sweep pid=%u threads=%u resume_calls=%u failures=%u",
				pid,
				observed_threads,
				resume_calls,
				resume_failures);
			log_msg(hf, "cleanup", "signaling test_target done event for pid=%u", pid);

			HANDLE hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\WhosWhoTestDone");
			if (!hDone) {
				DWORD global_err = GetLastError();
				log_msg(hf, "cleanup", "OpenEvent Global\\WhosWhoTestDone failed err=%lu", static_cast<unsigned long>(global_err));
				hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\WhosWhoTestDone");
				if (!hDone) {
					DWORD local_err = GetLastError();
					log_msg(hf, "cleanup", "OpenEvent Local\\WhosWhoTestDone failed err=%lu", static_cast<unsigned long>(local_err));
				}
			}
			if (hDone) {
				BOOL signaled = SetEvent(hDone);
				DWORD signal_err = signaled ? 0 : GetLastError();
				CloseHandle(hDone);
				log_msg(hf, "cleanup", "WhosWhoTestDone signal_result=%d err=%lu; waiting for process to exit...",
					signaled ? 1 : 0, static_cast<unsigned long>(signal_err));
			} else {
				log_msg(hf, "cleanup", "could not open WhosWhoTestDone event; sending TerminateProcess directly");
			}

			HANDLE hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
			if (hProc) {
				DWORD wait_result = WaitForSingleObject(hProc, 6000);
				if (wait_result != WAIT_OBJECT_0) {
					DWORD exit_code = 0;
					BOOL got_exit = GetExitCodeProcess(hProc, &exit_code);
					log_msg(hf, "cleanup", "process pid=%u did not exit in 6s wait_result=%lu get_exit=%d exit_code=0x%08lX wait_err=%lu; forcing TerminateProcess",
						pid,
						static_cast<unsigned long>(wait_result),
						got_exit ? 1 : 0,
						static_cast<unsigned long>(exit_code),
						static_cast<unsigned long>(GetLastError()));
					BOOL term_ok = TerminateProcess(hProc, 0);
					DWORD term_err = term_ok ? 0 : GetLastError();
					DWORD post_wait = WaitForSingleObject(hProc, 2000);
					DWORD post_exit = 0;
					BOOL got_post_exit = GetExitCodeProcess(hProc, &post_exit);
					log_msg(hf, "cleanup", "TerminateProcess result=%d err=%lu post_wait=%lu get_exit=%d exit_code=0x%08lX",
						term_ok ? 1 : 0,
						static_cast<unsigned long>(term_err),
						static_cast<unsigned long>(post_wait),
						got_post_exit ? 1 : 0,
						static_cast<unsigned long>(post_exit));
				} else {
					DWORD exit_code = 0;
					BOOL got_exit = GetExitCodeProcess(hProc, &exit_code);
					log_msg(hf, "cleanup", "process pid=%u exited cleanly get_exit=%d exit_code=0x%08lX",
						pid,
						got_exit ? 1 : 0,
						static_cast<unsigned long>(exit_code));
				}
				CloseHandle(hProc);
			} else {
				log_msg(hf, "cleanup", "could not open process handle for pid=%u (err=%lu); assuming already exited", pid, static_cast<unsigned long>(GetLastError()));
			}

			log_msg(hf, "cleanup", "test_target shutdown complete");
		}

		struct run_cleanup_guard_t {
			HANDLE* hf = nullptr;
			std::uint32_t* target_pid = nullptr;
			bool active = true;

			~run_cleanup_guard_t() {
				if (!active) return;
				HANDLE h = hf ? *hf : INVALID_HANDLE_VALUE;
				log_msg(h, "cleanup", "abnormal/early exit cleanup guard fired");
				try {
					cleanup_memory_scanner_runtime(h, "abnormal/early exit", 5000);
				} catch (...) {
				}
				try {
					aida::burp::camoufox::force_cleanup("testlab.cleanup_guard");
				} catch (...) {
				}
				try {
					cleanup_network_runtime(h, "abnormal/early exit");
				} catch (const std::exception& ex) {
					log_msg(h, "cleanup", "abnormal/early exit network cleanup threw: %s", ex.what());
				} catch (...) {
					log_msg(h, "cleanup", "abnormal/early exit network cleanup threw: <unknown>");
				}
				if (target_pid) {
					try {
						phase_stop_target(h, *target_pid);
					} catch (const std::exception& ex) {
						log_msg(h, "cleanup", "abnormal/early exit target cleanup threw: %s", ex.what());
					} catch (...) {
						log_msg(h, "cleanup", "abnormal/early exit target cleanup threw: <unknown>");
					}
				}
				if (hf && *hf != INVALID_HANDLE_VALUE) {
					CloseHandle(*hf);
					*hf = INVALID_HANDLE_VALUE;
				}
				g_running.store(false, std::memory_order_release);
			}
		};

		struct full_test_env_guard_t {
			HANDLE* hf = nullptr;
			bool active = false;

			explicit full_test_env_guard_t(HANDLE* handle) : hf(handle), active(true) {
				begin_test_guard_impl("run_all begin", hf ? *hf : INVALID_HANDLE_VALUE);
			}

			void clear(const char* reason) {
				if (!active) return;
				end_test_guard_impl(reason ? reason : "run_all end", hf ? *hf : INVALID_HANDLE_VALUE);
				active = false;
			}

			~full_test_env_guard_t() {
				clear("run_all scope exit");
			}
		};

		struct run_heartbeat_t {
			std::shared_ptr<std::atomic<bool>> stop;

			void start(HANDLE hf) {
				try {
					auto stop_token = std::make_shared<std::atomic<bool>>(false);
					stop = stop_token;
					aida::infra::executor::submission_t submission;
					submission.owner_subsystem = "test_all_features";
					submission.label = "full_test.heartbeat";
					submission.thread_class = "testlab_heartbeat";
					submission.domain = aida::infra::executor::domain_t::security_liveness;
					submission.priority = 0;
					submission.cancel_hook = [stop_token]() { stop_token->store(true, std::memory_order_release); };
					submission.failure_policy = "reject_not_started";
					submission.shutdown_policy = "abandon_on_shutdown";
					submission.body = [stop_token]() {
						while (!stop_token->load(std::memory_order_acquire)) {
							for (int i = 0; i < 50; ++i) {
								if (stop_token->load(std::memory_order_acquire)) return;
								Sleep(100);
							}
							HANDLE hh = open_log_file();
							log_debug_snapshot(hh, "heartbeat", "FULL-TEST live heartbeat");
							log_hung_heartbeat_if_needed(hh);
							if (hh != INVALID_HANDLE_VALUE) CloseHandle(hh);
						}
					};
					const bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
					if (!posted) {
						DWORD err = GetLastError();
						log_msg(hf, "heartbeat", "disabled live heartbeat worker: executor submit failed");
						log_resource_snapshot(hf, "heartbeat", "executor submit failed", err);
						stop_token->store(true, std::memory_order_release);
					}
				} catch (const std::exception& ex) {
					DWORD err = GetLastError();
					log_msg(hf, "heartbeat", "disabled live heartbeat worker: %s", ex.what());
					log_resource_snapshot(hf, "heartbeat", "heartbeat start exception", err);
					if (stop)
						stop->store(true, std::memory_order_release);
				} catch (...) {
					DWORD err = GetLastError();
					log_msg(hf, "heartbeat", "disabled live heartbeat worker: unknown exception");
					log_resource_snapshot(hf, "heartbeat", "heartbeat start unknown exception", err);
					if (stop)
						stop->store(true, std::memory_order_release);
				}
			}

			void stop_and_signal() {
				if (stop)
					stop->store(true, std::memory_order_release);
			}

			~run_heartbeat_t() {
				stop_and_signal();
			}
		};


		void run_all() {
			HANDLE hf = open_log_file();
			full_test_env_guard_t full_test_env_guard{ &hf };
			std::uint32_t target_pid = 0;
			run_cleanup_guard_t cleanup_guard{ &hf, &target_pid, true };
			run_heartbeat_t heartbeat;
			heartbeat.start(hf);
			const std::uint64_t this_run = g_run_id.fetch_add(1, std::memory_order_acq_rel) + 1;
			aida::diagnostics::testlab::reset_emitted_packets();
			aida::diagnostics::testlab::emit_testlab_breadcrumb("run_all", "full_test_start", true);
			g_run_start_tick.store(now_ms_tick(), std::memory_order_release);
			set_step("run_all entry");

			char ts[40];
			format_timestamp(ts, sizeof(ts));
			char header[512];
			_snprintf_s(header, sizeof(header), _TRUNCATE,
				"\n"
				"================================================================\n"
				"[%s] AiDA Full Feature Test -- START\n"
				"================================================================\n",
				ts);
			write_log_file(hf, std::string(header));
			push_log(header);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test START ==========");
			log_msg(hf, "run", "run_id=%llu thread=%lu log_path=%s",
				static_cast<unsigned long long>(this_run),
				static_cast<unsigned long>(GetCurrentThreadId()),
				log_path());
			log_msg(hf, "run", "test_target_log_path=%s", target_log_path());
			set_step("run_all preflight: camoufox cleanup");
			cleanup_camoufox_for_full_test_start(hf, "testlab.run_all_preflight");
			const auto& features = test_lab::all_features();
			int testlab_count = static_cast<int>(features.size());
			int total_estimate =
				kLaunchFeatureTests +
				testlab_count +
				kExtendedFeatureTests +
				kDebuggerFeatureTests +
				kScannerFeatureTests +
				kAnalysisFeatureTests +
				kNetworkFeatureTests +
				kBurpFeatureTests +
				kDisasmFeatureTests +
				kMcpFeatureTests +
				kUiFeatureTests;
			reset_phase_ledger(testlab_count, total_estimate);
			log_debug_snapshot(hf, "run", "initial snapshot");
			log_msg(hf, "run", "progress total estimate=%d launch=%d testlab=%d extended=%d debugger=%d scanner=%d analysis=%d network=%d burp=%d disasm=%d mcp=%d ui=%d",
				total_estimate,
				kLaunchFeatureTests,
				testlab_count,
				kExtendedFeatureTests,
				kDebuggerFeatureTests,
				kScannerFeatureTests,
				kAnalysisFeatureTests,
				kNetworkFeatureTests,
				kBurpFeatureTests,
				kDisasmFeatureTests,
				kMcpFeatureTests,
				kUiFeatureTests);

			bool attach_ok = false;
			if (!cancelled()) {
				set_step("phase call: launch target");
				log_debug_snapshot(hf, "checkpoint", "BEFORE phase_launch_target");
				attach_ok = phase_launch_target(hf, target_pid);
				g_target_unavailable.store(!attach_ok, std::memory_order_release);
				log_debug_snapshot(hf, "checkpoint", "AFTER phase_launch_target");
			}

			log_msg(hf, "summary", "post-launch state: target_pid=%u driver_attached=%d attach_ok=%d",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
				static_cast<int>(attach_ok));

			cleanup_network_runtime(hf, "pre-run reset");

			if (!cancelled()) {
				set_phase("Standalone UI tests");
				set_step("phase call: standalone UI tests");
				log_phase_begin(hf, "standalone UI tests");
				phase_ui_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "standalone UI tests");
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "testlab features", testlab_count);
				} else {
					set_step("phase call: testlab features");
					log_debug_snapshot(hf, "checkpoint", "BEFORE phase_testlab_features");
					phase_testlab_features(hf, target_pid);
					log_debug_snapshot(hf, "checkpoint", "AFTER phase_testlab_features");
					if (!target_unavailable())
						verify_target_liveness(hf, "after testlab features");
				}
			}

			cleanup_network_runtime(hf, "after testlab features");

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "extended features", kExtendedFeatureTests);
				} else {
					set_step("phase call: extended features");
					log_debug_snapshot(hf, "checkpoint", "BEFORE phase_extended_features");
					phase_extended_features(hf);
					log_debug_snapshot(hf, "checkpoint", "AFTER phase_extended_features");
					verify_target_liveness(hf, "after extended features");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "debugger feature tests", kDebuggerFeatureTests);
				} else {
					set_phase("Debugger feature tests");
					set_step("phase call: debugger feature tests");
					log_phase_begin(hf, "debugger feature tests");
					phase_debugger_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "debugger feature tests");
					verify_target_liveness(hf, "after debugger feature tests");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "scanner feature tests", kScannerFeatureTests);
				} else {
					set_phase("Scanner feature tests");
					set_step("phase call: scanner feature tests");
					log_phase_begin(hf, "scanner feature tests");
					phase_scanner_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "scanner feature tests");
					verify_target_liveness(hf, "after scanner feature tests");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "analysis feature tests", kAnalysisFeatureTests);
				} else {
					set_phase("Analysis feature tests");
					set_step("phase call: analysis feature tests");
					log_phase_begin(hf, "analysis feature tests");
					phase_analysis_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "analysis feature tests");
					if (!target_unavailable())
						verify_target_liveness(hf, "after analysis feature tests");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "network feature tests", kNetworkFeatureTests);
				} else {
					set_phase("Network feature tests");
					set_step("phase call: network feature tests");
					log_phase_begin(hf, "network feature tests");
					phase_network_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "network feature tests");
					if (!target_unavailable())
						verify_target_liveness(hf, "after network feature tests");
				}
			}

			cleanup_network_runtime(hf, "after network feature tests");

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "burp suite feature tests", kBurpFeatureTests);
				} else {
					set_phase("Burp suite feature tests");
					set_step("phase call: burp suite feature tests");
					log_phase_begin(hf, "burp suite feature tests");
					phase_burp_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "burp suite feature tests");
					if (!target_unavailable())
						verify_target_liveness(hf, "after burp suite feature tests");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "disassembly & decompiler tests", kDisasmFeatureTests);
				} else {
					set_phase("Disassembly & decompiler tests");
					set_step("phase call: disassembly & decompiler tests");
					log_phase_begin(hf, "disassembly & decompiler tests");
					phase_disasm_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "disassembly & decompiler tests");
					verify_target_liveness(hf, "after disassembly & decompiler tests");
				}
			}

			if (!cancelled()) {
				drain_decompiler_runtime(hf, "after disassembly before MCP");
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "MCP tool tests", kMcpFeatureTests);
				} else {
					set_phase("MCP tool tests");
					set_step("phase call: MCP tool tests");
					log_phase_begin(hf, "MCP tool tests");
					mcp_phase_context_t mcp_context;
					mcp_run_fixture_context_t mcp_fixture_context;
					mcp_context.passed = &g_passed;
					mcp_context.failed = &g_failed;
					mcp_context.skipped = &g_skipped;
					mcp_context.cancelled = cancelled;
					mcp_context.fixture = &mcp_fixture_context;
					phase_mcp_tests(hf, mcp_context);
					log_phase_end(hf, "MCP tool tests");
				}
			}

			try {
				aida::burp::camoufox::force_cleanup("testlab.final_cleanup");
			} catch (...) {
			}
			cleanup_network_runtime(hf, "final cleanup");
			phase_stop_target(hf, target_pid);

			set_phase("Complete");
			const int raw_skip_accounting_errors = log_destructive_skip_accounting(hf, "summary", "final", true);
			const int skip_accounting_errors = target_unavailable() ? 0 : raw_skip_accounting_errors;
			const int raw_skips = g_skipped.load(std::memory_order_acquire);
			const int prerequisite_skips = g_prerequisite_skipped.load(std::memory_order_acquire);
			const int destructive_skips = (std::max)(0, raw_skips - prerequisite_skips);
			if (destructive_skips > kExpectedDestructiveSkipCount) {
				const int converted = destructive_skips - kExpectedDestructiveSkipCount;
				g_skipped.fetch_sub(converted, std::memory_order_acq_rel);
				g_failed.fetch_add(converted, std::memory_order_acq_rel);
				log_msg(hf, "summary", "FAIL -- converted %d non-destructive skip(s) into failures; only the six expected destructive keys may remain skipped", converted);
			}
			const int expected_destructive_skips = target_unavailable() ? 0 : kExpectedDestructiveSkipCount;
			if (skip_accounting_errors != 0 || destructive_skips != expected_destructive_skips) {
				g_failed.fetch_add(1, std::memory_order_acq_rel);
				log_msg(hf, "summary", "FAIL -- destructive skip accounting expected exact key set observed_expected=%d expected=%d raw_skipped=%d errors=%d",
					g_expected_destructive_skip_seen_count,
					expected_destructive_skips,
					destructive_skips,
					skip_accounting_errors);
			}
			const int phase_ledger_errors = finalize_phase_ledger(hf);
			if (phase_ledger_errors != 0) {
				g_failed.fetch_add(phase_ledger_errors, std::memory_order_acq_rel);
				log_msg(hf, "summary", "FAIL -- phase ledger found %d incomplete, hung, or unentered planned phase condition(s)", phase_ledger_errors);
			}
			int p = g_passed.load();
			int f = g_failed.load();
			int s = g_skipped.load();
			int executed = p + f + s;
			int planned = g_total.load();

			log_msg(hf, "summary", "================ VALIDATION SUMMARY ================");
			log_msg(hf, "summary", "target_pid=%u driver_attached=%d target_unavailable=%d image_base=0x%016llX known_good_addr=0x%016llX",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
				target_unavailable() ? 1 : 0,
				static_cast<unsigned long long>(current_target_image_base()),
				static_cast<unsigned long long>(current_target_addr()));

			if (current_target_pid() == 0 || !g_driver_attached.load()) {
				log_msg(hf, "summary", "SUSPECT -- no verified target attach; every PASS that depended on the target is unreliable");
			}

			const int legacy_suspect = g_suspect.load();
			const int mcp_suspect = mcp_coverage_suspect_count();
			int suspect = legacy_suspect + mcp_suspect;
			log_msg(hf, "summary", "MCP-AUDIT-SUMMARY -- %s", mcp_coverage_final_summary_line().c_str());
			if (legacy_suspect > 0) {
				log_msg(hf, "summary", "SUSPECT -- %d test(s) reported PASS while returning zero/empty content; review log entries tagged SUSPECT",
					legacy_suspect);
			}
			if (mcp_suspect > 0) {
				log_msg(hf, "summary", "SUSPECT -- MCP audit reported %d suspicious, incomplete, missing, blocked, expected-empty, diagnostic-fallback, or timeout condition(s); review MCP-AUDIT-SUMMARY and MCP-PHASE-REMAINING-CASE entries",
					mcp_suspect);
			} else {
				log_msg(hf, "summary", "no MCP audit suspect conditions detected");
			}
			if (suspect == 0) {
				log_msg(hf, "summary", "no SUSPECT (empty-pass or MCP audit) tests detected by orchestrator");
			}

			if (planned > executed) {
				log_msg(hf, "summary", "INCOMPLETE -- planned=%d executed=%d remaining=%d cancel=%d target_unavailable=%d",
					planned,
					executed,
					planned - executed,
					cancelled() ? 1 : 0,
					target_unavailable() ? 1 : 0);
			}

			log_msg(hf, "summary", "TOTAL=%d EXECUTED=%d PASSED=%d FAILED=%d SKIPPED=%d SUSPECT=%d", planned, executed, p, f, s, suspect);

			format_timestamp(ts, sizeof(ts));
			char footer[512];
			_snprintf_s(footer, sizeof(footer), _TRUNCATE,
				"[%s] AiDA Full Feature Test -- DONE  (total=%d executed=%d passed=%d failed=%d skipped=%d suspect=%d)\n"
				"================================================================\n\n",
				ts, planned, executed, p, f, s, suspect);
			write_log_file(hf, std::string(footer));
			push_log(footer);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test DONE: total=%d executed=%d passed=%d failed=%d skipped=%d suspect=%d ==========", planned, executed, p, f, s, suspect);

			aida::diagnostics::testlab::emit_testlab_breadcrumb("run_all", "full_test_end", false);

			full_test_env_guard.clear("run_all normal completion");

			if (hf != INVALID_HANDLE_VALUE) {
				flush_full_test_log(hf);
				CloseHandle(hf);
			}
			hf = INVALID_HANDLE_VALUE;

			g_running.store(false, std::memory_order_release);
			cleanup_guard.active = false;
		}


		void log_worker_escape(const char* kind, DWORD code, const char* message) {
			HANDLE hf = open_log_file();
			char snap[1200] = {};
			format_debug_snapshot_impl(snap, sizeof(snap));
			log_msg(hf, "fatal", "FULL-TEST worker escaped kind=%s code=0x%08lX message=\"%s\" snapshot=%s",
				kind ? kind : "?",
				static_cast<unsigned long>(code),
				message ? message : "",
				snap);
			end_test_guard_impl("worker exception escape", hf);
			try {
				cleanup_memory_scanner_runtime(hf, "worker exception escape", 5000);
			} catch (...) {
			}
			try {
				aida::burp::camoufox::force_cleanup("testlab.worker_exception_escape");
			} catch (...) {
			}
			try {
				cleanup_network_runtime(hf, "worker exception escape");
			} catch (const std::exception& ex) {
				log_msg(hf, "cleanup", "worker exception network cleanup threw: %s", ex.what());
			} catch (...) {
				log_msg(hf, "cleanup", "worker exception network cleanup threw: <unknown>");
			}
			std::uint32_t pid = g_target_pid.load(std::memory_order_acquire);
			if (pid != 0) {
				try {
					phase_stop_target(hf, pid);
				} catch (const std::exception& ex) {
					log_msg(hf, "cleanup", "worker exception target cleanup threw: %s", ex.what());
				} catch (...) {
					log_msg(hf, "cleanup", "worker exception target cleanup threw: <unknown>");
				}
			}
			g_running.store(false, std::memory_order_release);
			if (hf != INVALID_HANDLE_VALUE) {
				flush_full_test_log(hf);
				CloseHandle(hf);
			}
		}

		void run_all_cpp_guarded() {
			try {
				run_all();
			} catch (const std::exception& ex) {
				log_worker_escape("c++", 0, ex.what());
			} catch (...) {
				log_worker_escape("c++", 0, "unknown C++ exception");
			}
		}

		DWORD run_all_seh_guarded() {
			__try {
				run_all_cpp_guarded();
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				DWORD code = GetExceptionCode();
				log_worker_escape("seh", code, "SEH exception escaped run_all");
				return code;
			}
			return 0;
		}

		bool start_full_test_worker(HANDLE hf) {
			const std::uint64_t queued_at = now_ms_tick();
			const std::uint64_t session_run_id = g_run_id.load(std::memory_order_acquire) + 1;
			char session_id[64] = {};
			_snprintf_s(session_id, sizeof(session_id), _TRUNCATE, "testlab.run.%llu",
				static_cast<unsigned long long>(session_run_id));

			log_taskflow_runtime_snapshot(hf, "start", "BEFORE full-test taskflow graph submit");

			constexpr std::uint64_t kDispatchSetupNode = 1;
			constexpr std::uint64_t kRunBodyNode = 2;
			constexpr std::uint64_t kFinishEvidenceNode = 3;

			aida::infra::taskflow_runtime::graph_descriptor_t graph;
			graph.owner_subsystem = "testlab";
			graph.label = "full_test.run_all";
			graph.phase = "full_run";
			graph.session_id = session_id;
			graph.diagnostic_id = "full_test.run_all";
			graph.domain = aida::infra::taskflow_runtime::executor_domain_t::critical;
			graph.priority = 1;
			graph.generation = session_run_id;
			graph.cancel_hook = []() {
				g_cancel_requested.store(true, std::memory_order_release);
				diag::log_tagged("test_all", "full-test cancellation requested; current synchronous feature will drain before runner stops");
			};
			graph.nodes.reserve(3);

			aida::infra::taskflow_runtime::graph_node_descriptor_t dispatch_setup;
			dispatch_setup.node_id = kDispatchSetupNode;
			dispatch_setup.label = "full_test.dispatch_setup";
			dispatch_setup.body = [queued_at]() {
				const std::uint64_t entered_at = now_ms_tick();
				const std::uint64_t queue_delay = entered_at >= queued_at ? (entered_at - queued_at) : 0;
				HANDLE entry_hf = open_log_file();
				log_msg(entry_hf, "start", "full-test taskflow graph setup entry tid=%lu queue_delay_ms=%llu",
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(queue_delay));
				log_taskflow_runtime_snapshot(entry_hf, "start", "full-test taskflow graph setup entry");
				if (entry_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(entry_hf);
					CloseHandle(entry_hf);
				}
				diag::log_tagged_fmt("test_all", "full-test taskflow graph setup entry tid=%lu queue_delay_ms=%llu",
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(queue_delay));
			};
			graph.nodes.emplace_back(std::move(dispatch_setup));

			aida::infra::taskflow_runtime::graph_node_descriptor_t run_body;
			run_body.node_id = kRunBodyNode;
			run_body.label = "full_test.run_body";
			run_body.depends_on.push_back(kDispatchSetupNode);
			run_body.body = [queued_at]() {
				const std::uint64_t entered_at = now_ms_tick();
				const std::uint64_t queue_delay = entered_at >= queued_at ? (entered_at - queued_at) : 0;
				HANDLE entry_hf = open_log_file();
				log_msg(entry_hf, "start", "full-test taskflow graph run entry tid=%lu queue_delay_ms=%llu",
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(queue_delay));
				log_taskflow_runtime_snapshot(entry_hf, "start", "full-test taskflow graph run entry");
				if (entry_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(entry_hf);
					CloseHandle(entry_hf);
				}
				diag::log_tagged_fmt("test_all", "full-test taskflow graph run entry tid=%lu queue_delay_ms=%llu",
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(queue_delay));
				(void)run_all_seh_guarded();
			};
			graph.nodes.emplace_back(std::move(run_body));

			aida::infra::taskflow_runtime::graph_node_descriptor_t finish_evidence;
			finish_evidence.node_id = kFinishEvidenceNode;
			finish_evidence.label = "full_test.finish_evidence";
			finish_evidence.depends_on.push_back(kRunBodyNode);
			finish_evidence.body = [queued_at]() {
				const std::uint64_t finished_at = now_ms_tick();
				const std::uint64_t elapsed = finished_at >= queued_at ? (finished_at - queued_at) : 0;
				HANDLE finish_hf = open_log_file();
				log_msg(finish_hf, "summary", "full-test taskflow graph finish evidence tid=%lu elapsed_ms=%llu running=%d cancel=%d target_unavailable=%d total=%d current=%d passed=%d failed=%d skipped=%d suspect=%d",
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(elapsed),
					g_running.load(std::memory_order_acquire) ? 1 : 0,
					g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0,
					g_target_unavailable.load(std::memory_order_acquire) ? 1 : 0,
					g_total.load(std::memory_order_acquire),
					current_completed_count(),
					g_passed.load(std::memory_order_acquire),
					g_failed.load(std::memory_order_acquire),
					g_skipped.load(std::memory_order_acquire),
					g_suspect.load(std::memory_order_acquire));
				log_taskflow_runtime_snapshot(finish_hf, "summary", "full-test taskflow graph finish evidence");
				if (finish_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(finish_hf);
					CloseHandle(finish_hf);
				}
				diag::log_tagged_fmt("test_all", "full-test taskflow graph finish evidence elapsed_ms=%llu",
					static_cast<unsigned long long>(elapsed));
			};
			graph.nodes.emplace_back(std::move(finish_evidence));

			auto result = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
			const bool posted = result.submitted;
			if (!posted) {
				DWORD err = GetLastError();
				const char* reason = result.reject_reason.empty() ? "<none>" : result.reject_reason.c_str();
				log_msg(hf, "start", "FAIL -- full-test taskflow graph submit failed err=%lu reason=%s",
					static_cast<unsigned long>(err),
					reason);
				log_taskflow_runtime_snapshot(hf, "start", "full-test taskflow graph submit failed");
				log_resource_snapshot(hf, "start", "full-test taskflow graph submit failed", err);
				diag::log_tagged_fmt("test_all", "full-test taskflow graph submit failed err=%lu reason=%s",
					static_cast<unsigned long>(err),
					reason);
				return false;
			}
			log_msg(hf, "start", "full-test taskflow graph submitted job_id=%llu session_id=%s nodes=3 domain=critical queued_at_ms=%llu",
				static_cast<unsigned long long>(result.handle.id),
				session_id,
				static_cast<unsigned long long>(queued_at));
			log_taskflow_runtime_snapshot(hf, "start", "full-test taskflow graph submit ok");
			diag::log_tagged_fmt("test_all", "full-test taskflow graph submitted job_id=%llu session_id=%s",
				static_cast<unsigned long long>(result.handle.id),
				session_id);
			return true;
		}

		bool start_tests_impl() {
			if (g_shutdown_cancel_requested.load(std::memory_order_acquire)) {
				diag::log_tagged("test_all", "start_tests rejected: shutdown requested");
				return false;
			}
			bool expected = false;
			if (!g_running.compare_exchange_strong(expected, true)) {
				char snap[1200] = {};
				format_debug_snapshot_impl(snap, sizeof(snap));
				diag::log_tagged_fmt("test_all", "start_tests rejected: run already active | %s", snap);
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "REJECTED -- run already active | %s", snap);
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				return false;
			}

			g_cancel_requested.store(false, std::memory_order_release);
			g_target_unavailable.store(false);
			g_total.store(0);
			g_current.store(0);
			g_passed.store(0);
			g_failed.store(0);
			g_skipped.store(0);
			g_prerequisite_skipped.store(0);
			g_suspect.store(0);
			g_target_pid.store(0);
			g_target_addr.store(0);
			g_target_image_base.store(0);
			g_driver_attached.store(false);
			g_saved_dtb.store(0, std::memory_order_release);
			{
				std::lock_guard<std::mutex> lk(g_launch_state_mtx);
				g_target_executable_path.clear();
				g_requested_cwd.clear();
				g_effective_cwd.clear();
			}
			g_first_failure_recorded.store(false, std::memory_order_release);
			{
				std::lock_guard<std::mutex> lk(g_test_marker_mtx);
				g_first_failure_marker.clear();
				g_last_successful_marker.clear();
			}
			reset_destructive_skip_accounting();
			{
				std::lock_guard<std::mutex> lk(g_phase_ledger_mtx);
				g_phase_ledger.clear();
				publish_active_phase_snapshot_locked(-1);
			}

			{
				std::lock_guard<std::mutex> lk(g_log_mtx);
				g_log_lines.clear();
				g_log_version.fetch_add(1, std::memory_order_acq_rel);
			}
			set_phase("Initializing...");
			set_step("start_tests_impl queued");

			diag::log_tagged_fmt("test_all", "user triggered Test All Features");
			{
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "admission accepted; preflight deferred to full-test run worker");
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
			}

			{
				HANDLE hf = open_log_file();
				log_resource_snapshot(hf, "start", "BEFORE full-test worker start", GetLastError());
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
			}

			try {
				HANDLE launch_hf = open_log_file();
				const bool started = start_full_test_worker(launch_hf);
				if (launch_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(launch_hf);
					CloseHandle(launch_hf);
				}
				if (!started) {
					HANDLE hf = open_log_file();
					g_failed.fetch_add(1);
					g_running.store(false, std::memory_order_release);
					set_full_test_env(hf, false, "taskflow graph submit failed");
					g_full_test_guard_active.store(false, std::memory_order_release);
					set_phase("Idle");
					set_step("taskflow graph submit failed");
					if (hf != INVALID_HANDLE_VALUE) {
						flush_full_test_log(hf);
						CloseHandle(hf);
					}
					return false;
				}
			} catch (const std::exception& ex) {
				DWORD err = GetLastError();
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "FAIL -- full-test worker could not start: %s", ex.what());
				log_resource_snapshot(hf, "start", "worker start exception", err);
				g_failed.fetch_add(1);
				g_running.store(false, std::memory_order_release);
				set_full_test_env(hf, false, "worker start exception");
				g_full_test_guard_active.store(false, std::memory_order_release);
				set_phase("Idle");
				set_step("worker start exception");
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				diag::log_tagged_fmt("test_all", "full-test worker start failed: %s err=%lu", ex.what(), static_cast<unsigned long>(err));
				return false;
			} catch (...) {
				DWORD err = GetLastError();
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "FAIL -- full-test worker could not start: unknown exception");
				log_resource_snapshot(hf, "start", "worker start unknown exception", err);
				g_failed.fetch_add(1);
				g_running.store(false, std::memory_order_release);
				set_full_test_env(hf, false, "worker start unknown exception");
				g_full_test_guard_active.store(false, std::memory_order_release);
				set_phase("Idle");
				set_step("worker start unknown exception");
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				diag::log_tagged_fmt("test_all", "full-test worker start failed: unknown exception err=%lu", static_cast<unsigned long>(err));
				return false;
			}
			diag::log_tagged("test_all", "full test taskflow graph submitted");
			return true;
		}

		bool queue_start_tests_impl(const char* source) {
			const char* tag = source && source[0] ? source : "start_tests";
			if (g_shutdown_cancel_requested.load(std::memory_order_acquire)) {
				set_phase("Cancelling...");
				set_step("start rejected during shutdown");
				return false;
			}
			if (g_running.load(std::memory_order_acquire)) {
				char snap[1200] = {};
				format_debug_snapshot_impl(snap, sizeof(snap));
				diag::log_tagged_fmt("test_all", "start_tests queue rejected: run already active source=%s | %s", tag, snap);
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "REJECTED -- start queue while run active source=%s | %s", tag, snap);
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				return false;
			}
			bool expected = false;
			if (!g_start_queued.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				char snap[1200] = {};
				format_debug_snapshot_impl(snap, sizeof(snap));
				diag::log_tagged_fmt("test_all", "start_tests queue rejected: start already queued source=%s | %s", tag, snap);
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "REJECTED -- start already queued source=%s | %s", tag, snap);
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				return false;
			}
			if (g_shutdown_cancel_requested.load(std::memory_order_acquire)) {
				g_start_queued.store(false, std::memory_order_release);
				set_phase("Cancelling...");
				set_step("start rejected during shutdown");
				return false;
			}

			aida::ui_thread::post([]() { globals::ui::test_all_visible = true; },
				"testlab", "queue_set_visible", "queue_start_tests");
			set_phase("Initializing...");
			set_step("start_tests submitted");
			const std::uint64_t queued_at = now_ms_tick();
			std::string tag_copy = tag;
			HANDLE hf = open_log_file();
			log_msg(hf, "start", "QUEUED -- full-test startup source=%s tid=%lu", tag, static_cast<unsigned long>(GetCurrentThreadId()));
			log_taskflow_runtime_snapshot(hf, "start", "BEFORE full-test startup executor submit");
			if (hf != INVALID_HANDLE_VALUE) {
				flush_full_test_log(hf);
				CloseHandle(hf);
			}

			auto task = [tag_copy, queued_at]() {
				const std::uint64_t entered_at = now_ms_tick();
				HANDLE entry_hf = open_log_file();
				log_msg(entry_hf, "start", "full-test startup executor worker entry source=%s tid=%lu queue_delay_ms=%llu",
					tag_copy.c_str(),
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(entered_at >= queued_at ? entered_at - queued_at : 0));
				log_taskflow_runtime_snapshot(entry_hf, "start", "full-test startup executor worker entry");
				if (entry_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(entry_hf);
					CloseHandle(entry_hf);
				}
				const bool started = start_tests_impl();
				g_start_queued.store(false, std::memory_order_release);
				HANDLE exit_hf = open_log_file();
				log_msg(exit_hf, "start", "full-test startup executor worker exit source=%s started=%d elapsed_ms=%llu",
					tag_copy.c_str(),
					started ? 1 : 0,
					static_cast<unsigned long long>(now_ms_tick() - entered_at));
				log_debug_snapshot(exit_hf, "start", "full-test startup executor worker exit");
				if (exit_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(exit_hf);
					CloseHandle(exit_hf);
				}
			};

			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "test_all_features";
			submission.label = "full_test.start_service";
			submission.thread_class = "testlab_startup";
			submission.domain = aida::infra::executor::domain_t::service;
			submission.priority = 1;
			submission.diagnostic_id = tag;
			submission.failure_policy = "reject_not_started";
			submission.body = std::move(task);
			bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
			if (!posted) {
				DWORD err = GetLastError();
				g_start_queued.store(false, std::memory_order_release);
				set_phase("Idle");
				set_step("startup executor submit failed");
				HANDLE fail_hf = open_log_file();
				log_msg(fail_hf, "start", "FAIL -- full-test startup executor submit failed source=%s err=%lu", tag, static_cast<unsigned long>(err));
				log_taskflow_runtime_snapshot(fail_hf, "start", "full-test startup executor submit failed");
				log_resource_snapshot(fail_hf, "start", "startup executor submit failed", err);
				if (fail_hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(fail_hf);
					CloseHandle(fail_hf);
				}
				diag::log_tagged_fmt("test_all", "full-test startup executor submit failed source=%s err=%lu", tag, static_cast<unsigned long>(err));
				return false;
			}
			diag::log_tagged_fmt("test_all", "full-test startup submitted source=%s", tag);
			return true;
		}

		void run_interactive_cancel_cleanup_worker() {
			struct inflight_reset_t {
				~inflight_reset_t() noexcept {
					g_interactive_cancel_cleanup_inflight.store(false, std::memory_order_release);
				}
			} inflight_reset;
			HANDLE hf = open_log_file();
			const ULONGLONG entered_at = GetTickCount64();
			const std::uint64_t run_id = g_run_id.load(std::memory_order_acquire);

			try {
				const ULONGLONG deadline = entered_at + 15000;
				auto before = aida::burp::camoufox::get_status();
				log_msg(hf, "cancel", "cleanup worker entry run_id=%llu tid=%lu inflight=1 deadline_ms=%llu state=%s child_pid=%u child_alive=%d browser_open=%d cleanup_pending=%d child_processes=%u browser_processes=%u",
					static_cast<unsigned long long>(run_id),
					static_cast<unsigned long>(GetCurrentThreadId()),
					static_cast<unsigned long long>(deadline),
					camoufox_bridge_state_name(before.state),
					before.child_pid,
					before.child_alive ? 1 : 0,
					before.browser_open ? 1 : 0,
					before.cleanup_pending ? 1 : 0,
					before.child_process_count,
					before.browser_process_count);
				const bool cleanup_result = aida::burp::camoufox::force_cleanup("testlab.cancel.interactive.async");
				const ULONGLONG after_cleanup = GetTickCount64();
				const DWORD wait_ms = after_cleanup < deadline ? static_cast<DWORD>(deadline - after_cleanup) : 0u;
				const bool idle = aida::burp::camoufox::wait_until_idle(wait_ms, "testlab.cancel.interactive.async");
				auto after = aida::burp::camoufox::get_status();
				const ULONGLONG finished_at = GetTickCount64();
				const bool residual_processes = after.child_alive || after.browser_process_count != 0 || after.child_process_count != 0;
				const bool residual_worker = after.cleanup_pending;
				log_msg(hf, "cancel", "cleanup receipt run_id=%llu result=%d idle=%d deadline_reached=%d elapsed_ms=%llu wait_ms=%u state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u residual_processes=%d residual_worker=%d last_error_len=%zu",
					static_cast<unsigned long long>(run_id),
					cleanup_result ? 1 : 0,
					idle ? 1 : 0,
					finished_at >= deadline ? 1 : 0,
					static_cast<unsigned long long>(finished_at >= entered_at ? finished_at - entered_at : 0),
					wait_ms,
					camoufox_bridge_state_name(after.state),
					after.child_pid,
					after.child_alive ? 1 : 0,
					after.browser_open ? 1 : 0,
					after.page_verified ? 1 : 0,
					after.privacy_verified ? 1 : 0,
					after.cleanup_pending ? 1 : 0,
					after.child_process_count,
					after.browser_process_count,
					residual_processes ? 1 : 0,
					residual_worker ? 1 : 0,
					after.last_error.size());
			} catch (const std::exception& ex) {
				log_msg(hf, "cancel", "cleanup receipt run_id=%llu result=exception elapsed_ms=%llu message_len=%zu residual_processes=unknown residual_worker=unknown",
					static_cast<unsigned long long>(run_id),
					static_cast<unsigned long long>(GetTickCount64() - entered_at),
					std::strlen(ex.what()));
			} catch (...) {
				log_msg(hf, "cancel", "cleanup receipt run_id=%llu result=unknown_exception elapsed_ms=%llu residual_processes=unknown residual_worker=unknown",
					static_cast<unsigned long long>(run_id),
					static_cast<unsigned long long>(GetTickCount64() - entered_at));
			}
			const ULONGLONG exited_at = GetTickCount64();
			log_msg(hf, "cancel", "cleanup worker exit run_id=%llu tid=%lu elapsed_ms=%llu running=%d cancel=%d target_pid=%u",
				static_cast<unsigned long long>(run_id),
				static_cast<unsigned long>(GetCurrentThreadId()),
				static_cast<unsigned long long>(exited_at >= entered_at ? exited_at - entered_at : 0),
				g_running.load(std::memory_order_acquire) ? 1 : 0,
				g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0,
				g_target_pid.load(std::memory_order_acquire));
			log_debug_snapshot(hf, "cancel", "cleanup worker exit snapshot");
			if (hf != INVALID_HANDLE_VALUE) {
				flush_full_test_log(hf);
				CloseHandle(hf);
			}
		}

		enum class interactive_cancel_cleanup_post_t {
			posted,
			already_inflight,
			rejected
		};

		interactive_cancel_cleanup_post_t post_interactive_cancel_cleanup() {
			bool expected = false;
			if (!g_interactive_cancel_cleanup_inflight.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				HANDLE hf = open_log_file();
				log_msg(hf, "cancel", "cleanup post suppressed reason=already_inflight run_id=%llu inflight=1 running=%d cancel=%d",
					static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
					g_running.load(std::memory_order_acquire) ? 1 : 0,
					g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0);
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				return interactive_cancel_cleanup_post_t::already_inflight;
			}

			bool posted = false;
			try {
				std::function<void()> task = []() {
					run_interactive_cancel_cleanup_worker();
				};
				aida::infra::executor::submission_t submission;
				submission.owner_subsystem = "test_all_features";
				submission.label = "full_test.cancel_cleanup";
				submission.thread_class = "testlab_cancel_cleanup";
				submission.domain = aida::infra::executor::domain_t::service;
				submission.priority = 1;
				submission.failure_policy = "reject_not_started";
				submission.shutdown_policy = "drain";
				submission.cancel_hook = []() {
					g_interactive_cancel_cleanup_inflight.store(false, std::memory_order_release);
				};
				submission.body = std::move(task);
				posted = aida::infra::executor::submit(std::move(submission)).submitted;
			} catch (...) {
				posted = false;
			}

			if (!posted) {
				g_interactive_cancel_cleanup_inflight.store(false, std::memory_order_release);
				HANDLE hf = open_log_file();
				log_msg(hf, "cancel", "cleanup post rejected run_id=%llu inflight_after=0 running=%d cancel=%d",
					static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
					g_running.load(std::memory_order_acquire) ? 1 : 0,
					g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0);
				if (hf != INVALID_HANDLE_VALUE) {
					flush_full_test_log(hf);
					CloseHandle(hf);
				}
				return interactive_cancel_cleanup_post_t::rejected;
			}
			HANDLE hf = open_log_file();
			log_msg(hf, "cancel", "cleanup post accepted run_id=%llu inflight=1 running=%d cancel=%d",
				static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
				g_running.load(std::memory_order_acquire) ? 1 : 0,
				g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0);
			if (hf != INVALID_HANDLE_VALUE) {
				flush_full_test_log(hf);
				CloseHandle(hf);
			}
			return interactive_cancel_cleanup_post_t::posted;
		}

		void request_interactive_cancel() {
			const bool was_requested = g_cancel_requested.exchange(true, std::memory_order_acq_rel);
			diag::log_tagged_fmt("test_all", "cancel request source=interactive previous=%d current=1 run_id=%llu running=%d start_queued=%d",
				was_requested ? 1 : 0,
				static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
				g_running.load(std::memory_order_acquire) ? 1 : 0,
				g_start_queued.load(std::memory_order_acquire) ? 1 : 0);
			set_phase("Cancelling...");
			const interactive_cancel_cleanup_post_t post_state = post_interactive_cancel_cleanup();
			if (post_state == interactive_cancel_cleanup_post_t::posted)
				set_step("cancel cleanup queued");
			else if (post_state == interactive_cancel_cleanup_post_t::already_inflight)
				set_step("cancel cleanup already queued");
			else
				set_step("cancel cleanup queue unavailable");
		}

	}


	bool start_tests() {
		return queue_start_tests_impl("ui_start_tests");
	}

	bool post_hotkey_trigger(const char* source) {
		static std::atomic<bool> s_hotkey_task_inflight{ false };
		static std::atomic<std::uint64_t> s_last_hotkey_post_ms{ 0 };
		const char* tag_ptr = source && source[0] ? source : "ctrl_shift_t";
		const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
		const std::uint64_t last_ms = s_last_hotkey_post_ms.load(std::memory_order_acquire);
		if (last_ms != 0 && now_ms >= last_ms && now_ms - last_ms < 750ULL) {
			diag::log_tagged_fmt("ui", "test_all_hotkey_deduped source=%s age_ms=%llu", tag_ptr, static_cast<unsigned long long>(now_ms - last_ms));
			return false;
		}
		bool expected = false;
		if (!s_hotkey_task_inflight.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
			diag::log_tagged_fmt("ui", "test_all_hotkey_deduped_inflight source=%s", tag_ptr);
			return false;
		}
		s_last_hotkey_post_ms.store(now_ms, std::memory_order_release);
		std::string tag(tag_ptr);
		std::function<void()> task = [tag]() {
			try {
				const bool accepted = trigger_from_hotkey(tag.c_str());
				diag::log_tagged_fmt("ui", "test_all_hotkey_worker_done source=%s accepted=%d", tag.c_str(), accepted ? 1 : 0);
			} catch (const std::exception& e) {
				diag::log_tagged_fmt("ui", "test_all_hotkey_worker_exception source=%s what=%s", tag.c_str(), e.what());
			} catch (...) {
				diag::log_tagged_fmt("ui", "test_all_hotkey_worker_exception source=%s what=<unknown>", tag.c_str());
			}
			s_hotkey_task_inflight.store(false, std::memory_order_release);
		};
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "test_all_features";
		submission.label = "full_test.hotkey";
		submission.thread_class = "testlab_hotkey";
		submission.domain = aida::infra::executor::domain_t::service;
		submission.priority = 1;
		submission.diagnostic_id = tag_ptr;
		submission.failure_policy = "reject_not_started";
		submission.body = std::move(task);
		bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
		if (!posted) {
			s_hotkey_task_inflight.store(false, std::memory_order_release);
			diag::log_tagged_critical_fmt("ui", "test_all_hotkey_post_failed source=%s", tag_ptr);
			return false;
		}
		diag::log_tagged_fmt("ui", "test_all_hotkey_posted source=%s", tag_ptr);
		return true;
	}

	bool trigger_from_hotkey(const char* source) {
		const char* tag = source && source[0] ? source : "ctrl_shift_t";
		aida::ui_thread::post([]() { globals::ui::test_all_visible = true; },
			"testlab", "hotkey_set_visible", "trigger_from_hotkey");
		char snap_before[1200] = {};
		format_debug_snapshot(snap_before, sizeof(snap_before));
		diag::log_tagged_fmt("ui", "test_all_start hotkey=%s before={%s}", tag, snap_before);
		diag::log_tagged_fmt("parser_proof", "%s pressed; starting full Test Lab before={%s}", tag, snap_before);
		auto proof_task = [] {
			run_parser_proof_smoke();
		};
		aida::infra::executor::submission_t proof_submission;
		proof_submission.owner_subsystem = "test_all_features";
		proof_submission.label = "parser_proof.hotkey";
		proof_submission.thread_class = "parser_proof";
		proof_submission.domain = aida::infra::executor::domain_t::diagnostics;
		proof_submission.priority = 4;
		proof_submission.diagnostic_id = tag;
		proof_submission.failure_policy = "reject_not_started";
		proof_submission.body = std::move(proof_task);
		bool proof_posted = aida::infra::executor::submit(std::move(proof_submission)).submitted;
		if (!proof_posted)
			diag::log_tagged("parser_proof", "hotkey parser proof smoke post failed");
		bool accepted = queue_start_tests_impl(tag);
		char snap_after[1200] = {};
		format_debug_snapshot(snap_after, sizeof(snap_after));
		diag::log_tagged_fmt("ui", "test_all_start hotkey=%s accepted=%d proof_posted=%d after={%s}", tag, accepted ? 1 : 0, proof_posted ? 1 : 0, snap_after);
		diag::log_tagged_fmt("parser_proof", "%s start_tests accepted=%d proof_posted=%d after={%s}", tag, accepted ? 1 : 0, proof_posted ? 1 : 0, snap_after);
		return accepted;
	}

	void begin_test_guard(const char* source) {
		HANDLE hf = open_log_file();
		begin_test_guard_impl(source ? source : "external begin_test_guard", hf);
		if (hf != INVALID_HANDLE_VALUE) {
			flush_full_test_log(hf);
			CloseHandle(hf);
		}
	}

	void end_test_guard(const char* source) {
		HANDLE hf = open_log_file();
		end_test_guard_impl(source ? source : "external end_test_guard", hf);
		if (hf != INVALID_HANDLE_VALUE) {
			flush_full_test_log(hf);
			CloseHandle(hf);
		}
	}

	void cancel_tests() {
		request_interactive_cancel();
	}

	void cancel_tests_for_shutdown() {
		g_shutdown_cancel_requested.store(true, std::memory_order_release);
		g_cancel_requested.store(true, std::memory_order_release);
		g_start_queued.store(false, std::memory_order_release);
		set_phase("Cancelling...");
	}

	bool is_running() {
		return g_running.load(std::memory_order_acquire) || g_start_queued.load(std::memory_order_acquire);
	}

	bool is_unattended_full_test_active() {
		return is_running() ||
			g_full_test_guard_active.load(std::memory_order_acquire) ||
			full_test_env_active();
	}

	std::uint64_t overlay_dirty_version() {
		std::uint64_t state = 0xCBF29CE484222325ull;
		state = mix_overlay_dirty_value(state, g_log_version.load(std::memory_order_acquire));
		state = mix_overlay_dirty_value(state, g_progress_version.load(std::memory_order_acquire));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_total.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_current.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_passed.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_failed.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_skipped.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_suspect.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_target_pid.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, g_driver_attached.load(std::memory_order_acquire) ? 1ull : 0ull);
		state = mix_overlay_dirty_value(state, g_running.load(std::memory_order_acquire) ? 1ull : 0ull);
		state = mix_overlay_dirty_value(state, g_start_queued.load(std::memory_order_acquire) ? 1ull : 0ull);
		state = mix_overlay_dirty_value(state, globals::ui::test_all_visible ? 1ull : 0ull);
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_active_phase_index.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_active_phase_planned.load(std::memory_order_acquire)));
		state = mix_overlay_dirty_value(state, static_cast<std::uint64_t>(g_active_phase_completed.load(std::memory_order_acquire)));
		return state;
	}

	overlay_perf_snapshot_t overlay_perf_snapshot() {
		overlay_perf_snapshot_t out;
		out.visible = g_overlay_visible.load(std::memory_order_acquire);
		out.running = is_running();
		out.snapshot_busy = g_overlay_snapshot_busy.load(std::memory_order_acquire);
		out.snapshot_changed = g_overlay_snapshot_changed.load(std::memory_order_acquire);
		out.dirty_version = overlay_dirty_version();
		out.log_version = g_log_version.load(std::memory_order_acquire);
		out.progress_version = g_progress_version.load(std::memory_order_acquire);
		out.lock_busy_total = g_overlay_lock_busy_total.load(std::memory_order_acquire);
		out.snapshot_changes = g_overlay_snapshot_changes.load(std::memory_order_acquire);
		out.render_elapsed_us = g_overlay_render_elapsed_us.load(std::memory_order_acquire);
		out.total_log_lines = static_cast<std::size_t>(g_overlay_total_rows.load(std::memory_order_acquire));
		out.cached_log_lines = static_cast<std::size_t>(g_overlay_cached_rows.load(std::memory_order_acquire));
		out.rendered_log_rows = static_cast<std::size_t>(g_overlay_rendered_rows.load(std::memory_order_acquire));
		return out;
	}

	void set_progress_step(const char* label) {
		set_step(label ? label : "");
	}

	void format_debug_snapshot(char* out, std::size_t cap) {
		format_debug_snapshot_impl(out, cap);
	}

	void current_phase_and_step(char* phase, std::size_t phase_cap, char* step, std::size_t step_cap, std::uint64_t* step_start_ms_out) {
		if (phase && phase_cap > 0) phase[0] = '\0';
		if (step && step_cap > 0) step[0] = '\0';
		if (step_start_ms_out) *step_start_ms_out = 0;
		copy_label_snapshot(g_phase_label, phase, phase_cap);
		copy_label_snapshot(g_step_label, step, step_cap);
		if (step_start_ms_out)
			*step_start_ms_out = g_step_start_tick.load(std::memory_order_acquire);
	}

	void log_external_session_event(const char* source, unsigned msg, std::uintptr_t wparam, std::intptr_t lparam) {
		HANDLE hf = open_log_file();
		log_msg(hf, "session", "external_session_event source=%s msg=0x%04X wparam=0x%016llX lparam=0x%016llX running=%d cancel=%d",
			source ? source : "unknown",
			msg,
			static_cast<unsigned long long>(wparam),
			static_cast<unsigned long long>(static_cast<std::uintptr_t>(lparam)),
			g_running.load(std::memory_order_acquire) ? 1 : 0,
			g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0);
		log_debug_snapshot(hf, "session", source ? source : "external session event");
		if (hf != INVALID_HANDLE_VALUE) {
			flush_full_test_log(hf);
			CloseHandle(hf);
		}
	}

	void render_overlay(float vw, float vh) {
		if (!globals::ui::test_all_visible) {
			g_overlay_visible.store(false, std::memory_order_release);
			return;
		}
		g_overlay_visible.store(true, std::memory_order_release);
		const auto overlay_render_start = std::chrono::steady_clock::now();
		std::size_t overlay_rendered_rows = 0;
		std::size_t overlay_cached_rows = 0;
		std::size_t overlay_total_rows = 0;
		bool overlay_snapshot_busy_now = false;
		bool overlay_snapshot_changed_now = false;

		const auto& t = aida::ui::resolved();

		float ow = vw * 0.7f;
		if (ow < 600.f) ow = 600.f;
		if (ow > vw - 40.f) ow = vw - 40.f;

		float oh = vh * 0.75f;
		if (oh < 400.f) oh = 400.f;
		if (oh > vh - 40.f) oh = vh - 40.f;

		float ox = (vw - ow) * 0.5f;
		float oy = (vh - oh) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(ox, oy), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(ow, oh), ImGuiCond_Always);

		ImGuiWindowFlags flags =
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoDocking;

		bool open = globals::ui::test_all_visible;
		if (ImGui::Begin("Test All Features##test_all_overlay", &open, flags)) {

			bool running = g_running.load(std::memory_order_acquire) || g_start_queued.load(std::memory_order_acquire);


			if (running) ImGui::BeginDisabled();
			if (ImGui::Button("TEST ALL FEATURES", ImVec2(190.f, 30.f))) {
				start_tests();
			}
			if (running) ImGui::EndDisabled();

			ImGui::SameLine();

			if (!running) ImGui::BeginDisabled();
			if (ImGui::Button("Cancel", ImVec2(100.f, 30.f))) {
				request_interactive_cancel();
			}
			if (!running) ImGui::EndDisabled();

			ImGui::SameLine(0.f, 20.f);


			std::string phase_label = load_label_snapshot(g_phase_label);
			if (!phase_label.empty()) {
				ImGui::Text("Phase: %s", phase_label.c_str());
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));


			{
				std::uint32_t tpid = g_target_pid.load();
				bool attached = g_driver_attached.load();
				if (tpid != 0 && attached) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.success);
					ImGui::Text("Target pid: %u   Driver: ATTACHED", tpid);
					ImGui::PopStyleColor();
				} else if (tpid != 0) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
					ImGui::Text("Target pid: %u   Driver: NOT ATTACHED", tpid);
					ImGui::PopStyleColor();
				} else {
					ImGui::TextUnformatted("Target pid: (none)   Driver: not attached");
				}
			}

			ImGui::Dummy(ImVec2(0.f, 4.f));


			{
				int total   = g_total.load();
				int passed  = g_passed.load();
				int failed  = g_failed.load();
				int skipped = g_skipped.load();
				int done    = passed + failed + skipped;

				ImGui::Text("Total: %d", total);
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.success);
				ImGui::Text("Passed: %d", passed);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.error);
				ImGui::Text("Failed: %d", failed);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
				ImGui::Text("Skipped: %d", skipped);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				if (total > 0) {
					float progress = static_cast<float>(done) / static_cast<float>(total);
					ImGui::ProgressBar(progress, ImVec2(200.f, 20.f));
				}
			}

			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));


			ImGui::TextUnformatted("TEST LOG");

			float log_h = oh - ImGui::GetCursorPosY() - 30.f;
			if (log_h < 100.f) log_h = 100.f;

			ImGui::BeginChild("##test_all_log", ImVec2(-1.f, log_h), true,
				ImGuiWindowFlags_HorizontalScrollbar);

			if (g_code_font) ImGui::PushFont(g_code_font);

			static std::vector<overlay_log_line_t> log_snapshot;
			static std::uint64_t log_snapshot_version = 0;
			static std::size_t log_snapshot_total = 0;
			if (try_snapshot_log_tail_if_changed(kOverlayRenderTailLines, log_snapshot_version, log_snapshot, &log_snapshot_total, &overlay_snapshot_changed_now)) {
				overlay_total_rows = log_snapshot_total;
				overlay_cached_rows = log_snapshot.size();
			} else {
				overlay_snapshot_busy_now = true;
				g_overlay_lock_busy_total.fetch_add(1, std::memory_order_acq_rel);
				overlay_total_rows = log_snapshot_total;
				overlay_cached_rows = log_snapshot.size();
			}
			if (overlay_snapshot_busy_now) {
				ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
				ImGui::TextUnformatted("Test log snapshot is busy");
				ImGui::PopStyleColor();
			} else {
				ImGuiListClipper clipper;
				const int row_count = static_cast<int>(log_snapshot.size());
				clipper.Begin(row_count, ImGui::GetTextLineHeightWithSpacing());
				while (clipper.Step()) {
					for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
						const overlay_log_line_t& line = log_snapshot[static_cast<std::size_t>(row)];
						switch (line.severity) {
						case overlay_log_severity_t::success:
							ImGui::PushStyleColor(ImGuiCol_Text, t.success);
							ImGui::TextUnformatted(line.text.c_str());
							ImGui::PopStyleColor();
							break;
						case overlay_log_severity_t::warning:
							ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
							ImGui::TextUnformatted(line.text.c_str());
							ImGui::PopStyleColor();
							break;
						case overlay_log_severity_t::error:
							ImGui::PushStyleColor(ImGuiCol_Text, t.error);
							ImGui::TextUnformatted(line.text.c_str());
							ImGui::PopStyleColor();
							break;
						default:
							ImGui::TextUnformatted(line.text.c_str());
							break;
						}
					}
					overlay_rendered_rows += static_cast<std::size_t>(clipper.DisplayEnd - clipper.DisplayStart);
				}
			}


			if (running) {
				ImGui::SetScrollHereY(1.0f);
			}

			if (g_code_font) ImGui::PopFont();

			ImGui::EndChild();


			ImGui::Text("Log file: %s", log_path());
			ImGui::Text("Target log: %s", target_log_path());
		}
		ImGui::End();

		globals::ui::test_all_visible = open;
		g_overlay_visible.store(globals::ui::test_all_visible, std::memory_order_release);
		g_overlay_snapshot_busy.store(overlay_snapshot_busy_now, std::memory_order_release);
		g_overlay_snapshot_changed.store(overlay_snapshot_changed_now, std::memory_order_release);
		g_overlay_total_rows.store(static_cast<std::uint64_t>(overlay_total_rows), std::memory_order_release);
		g_overlay_cached_rows.store(static_cast<std::uint64_t>(overlay_cached_rows), std::memory_order_release);
		g_overlay_rendered_rows.store(static_cast<std::uint64_t>(overlay_rendered_rows), std::memory_order_release);
		const std::uint64_t overlay_elapsed_us = static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - overlay_render_start).count());
		g_overlay_render_elapsed_us.store(overlay_elapsed_us, std::memory_order_release);
		static std::uint64_t s_last_overlay_slow_log_ms = 0;
		const std::uint64_t now_ms = now_ms_tick();
		const bool overlay_slow = overlay_elapsed_us >= (is_running() ? 8000ull : 4000ull);
		if (overlay_slow && now_ms - s_last_overlay_slow_log_ms >= 5000ull) {
			s_last_overlay_slow_log_ms = now_ms;
			diag::log_tagged_fmt("test_all",
				"overlay_slow elapsed_us=%llu visible=%d running=%d total_rows=%zu cached_rows=%zu rendered_rows=%zu log_version=%llu snapshot_changed=%d snapshot_busy=%d lock_busy_total=%llu",
				static_cast<unsigned long long>(overlay_elapsed_us),
				globals::ui::test_all_visible ? 1 : 0,
				is_running() ? 1 : 0,
				overlay_total_rows,
				overlay_cached_rows,
				overlay_rendered_rows,
				static_cast<unsigned long long>(g_log_version.load(std::memory_order_acquire)),
				overlay_snapshot_changed_now ? 1 : 0,
				overlay_snapshot_busy_now ? 1 : 0,
				static_cast<unsigned long long>(g_overlay_lock_busy_total.load(std::memory_order_acquire)));
		}
	}

}
