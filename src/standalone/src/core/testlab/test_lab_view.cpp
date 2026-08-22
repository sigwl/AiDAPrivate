#include "test_lab_view.hpp"
#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "test_lab_features_c03_safe_headless.hpp"
#include "test_all_features.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../infra/executor.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../ui/theme.hpp"
#include "../ui/ui_anim.hpp"
#include "../ui/empty_state.hpp"
#include "../../../../driver/comm.h"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>
#include <Shellapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <exception>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace test_lab_view {

	namespace {

		int                                 g_selected_idx = -1;
		test_lab::state_t                   g_state;
		std::shared_ptr<test_lab::result_t> g_result = std::make_shared<test_lab::result_t>();
		std::mutex                          g_result_mtx;

		const char* driver_label(test_lab::driver_e d) {
			switch (d) {
				case test_lab::driver_e::whoswho:  return "WHO";
				case test_lab::driver_e::driverless: return "SAFE";
			}
			return "?";
		}

		ImU32 driver_badge_color(test_lab::driver_e d, float alpha) {
			const auto& t = aida::ui::resolved();
			switch (d) {
				case test_lab::driver_e::whoswho:  return aida::ui::with_alpha(t.accent_u32, alpha);
				case test_lab::driver_e::driverless: return aida::ui::with_alpha(t.success, alpha);
			}
			return aida::ui::with_alpha(t.text_dim, alpha);
		}

		ImU32 status_dot_color(test_lab::run_state_e s, test_lab::outcome_e outcome, float alpha) {
			const auto& t = aida::ui::resolved();
			switch (s) {
				case test_lab::run_state_e::idle:     return aida::ui::with_alpha(t.text_dim, alpha);
				case test_lab::run_state_e::running:  return aida::ui::with_alpha(t.accent_u32, alpha);
				case test_lab::run_state_e::complete:
					return aida::ui::with_alpha(outcome == test_lab::outcome_e::passed ? t.success :
						((outcome == test_lab::outcome_e::not_run || outcome == test_lab::outcome_e::cancelled) ? t.warning : t.error), alpha);
			}
			return aida::ui::with_alpha(t.text_dim, alpha);
		}

		const char* result_state_label(test_lab::run_state_e s, test_lab::outcome_e outcome) {
			switch (s) {
				case test_lab::run_state_e::idle: return "Idle";
				case test_lab::run_state_e::running: return "Running";
				case test_lab::run_state_e::complete:
					switch (outcome) {
						case test_lab::outcome_e::not_run: return "Not run";
						case test_lab::outcome_e::missing: return "Missing";
						case test_lab::outcome_e::passed: return "Passed";
						case test_lab::outcome_e::failed: return "Failed";
						case test_lab::outcome_e::timed_out: return "Timed out";
						case test_lab::outcome_e::crashed: return "Crashed";
						case test_lab::outcome_e::cancelled: return "Cancelled";
						case test_lab::outcome_e::malformed_result: return "Malformed result";
						case test_lab::outcome_e::integrity_failure: return "Integrity failure";
					}
			}
			return "Idle";
		}

		const char* result_state_badge(test_lab::run_state_e s, test_lab::outcome_e outcome) {
			switch (s) {
				case test_lab::run_state_e::idle: return "IDLE";
				case test_lab::run_state_e::running: return "RUN";
				case test_lab::run_state_e::complete:
					switch (outcome) {
						case test_lab::outcome_e::not_run: return "N/R";
						case test_lab::outcome_e::missing: return "MISS";
						case test_lab::outcome_e::passed: return "PASS";
						case test_lab::outcome_e::failed: return "FAIL";
						case test_lab::outcome_e::timed_out: return "TIME";
						case test_lab::outcome_e::crashed: return "CRASH";
						case test_lab::outcome_e::cancelled: return "CANCEL";
						case test_lab::outcome_e::malformed_result: return "BAD";
						case test_lab::outcome_e::integrity_failure: return "INTEG";
					}
			}
			return "IDLE";
		}

		ImU32 result_state_color(test_lab::run_state_e s, test_lab::outcome_e outcome) {
			const auto& t = aida::ui::resolved();
			switch (s) {
				case test_lab::run_state_e::idle: return t.text_dim;
				case test_lab::run_state_e::running: return t.accent_u32;
				case test_lab::run_state_e::complete: return outcome == test_lab::outcome_e::passed ? t.success :
					((outcome == test_lab::outcome_e::not_run || outcome == test_lab::outcome_e::cancelled) ? t.warning : t.error);
			}
			return t.text_dim;
		}

		std::string format_elapsed(std::uint64_t elapsed_us) {
			char buf[64];
			if (elapsed_us >= 1000000ull) {
				std::snprintf(buf, sizeof(buf), "%.2f s", static_cast<double>(elapsed_us) / 1000000.0);
			} else if (elapsed_us >= 1000ull) {
				std::snprintf(buf, sizeof(buf), "%.2f ms", static_cast<double>(elapsed_us) / 1000.0);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu us", static_cast<unsigned long long>(elapsed_us));
			}
			return std::string(buf);
		}

		void render_chip(const char* label, ImU32 color, float min_w = 0.f) {
			const auto& t = aida::ui::resolved();
			const char* text = label != nullptr ? label : "";
			ImVec2 ts = ImGui::CalcTextSize(text);
			float h = 22.f;
			float w = (std::max)(min_w, ts.x + 18.f);
			ImVec2 p = ImGui::GetCursorScreenPos();
			ImGui::Dummy(ImVec2(w, h));
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 b(p.x + w, p.y + h);
			dl->AddRectFilled(p, b, aida::ui::with_alpha(color, 0.18f), h * 0.5f);
			dl->AddRect(p, b, aida::ui::with_alpha(color, 0.62f), h * 0.5f, 0, 1.f);
			dl->AddText(ImVec2(p.x + (w - ts.x) * 0.5f, p.y + (h - ts.y) * 0.5f - 0.5f),
				aida::ui::with_alpha(color == 0 ? t.text_secondary : color, 0.95f), text);
		}

		void render_metric_chip(const char* label, const char* value, ImU32 color, float min_w = 0.f) {
			std::string text;
			if (label != nullptr && label[0] != '\0') {
				text.append(label);
				text.append(": ");
			}
			text.append(value != nullptr ? value : "");
			render_chip(text.c_str(), color, min_w);
		}

		void render_empty_panel(const char* title, const char* body, float height = 72.f) {
			const auto& t = aida::ui::resolved();
			ImVec2 p = ImGui::GetCursorScreenPos();
			float w = ImGui::GetContentRegionAvail().x;
			if (w < 80.f) w = 80.f;
			ImGui::Dummy(ImVec2(w, height));
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 b(p.x + w, p.y + height);
			dl->AddRectFilled(p, b, aida::ui::with_alpha(t.panel_header, 0.35f), 6.f);
			dl->AddRect(p, b, aida::ui::with_alpha(t.border_subtle, 0.75f), 6.f, 0, 1.f);
			float y = p.y + 12.f;
			if (title != nullptr && title[0] != '\0') {
				dl->AddText(ImVec2(p.x + 14.f, y), t.text_secondary, title);
				y += ImGui::GetTextLineHeight() + 4.f;
			}
			if (body != nullptr && body[0] != '\0') {
				ImVec4 clip(p.x + 14.f, y, b.x - 14.f, b.y - 8.f);
				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(p.x + 14.f, y),
					t.text_dim, body, nullptr, w - 28.f, &clip);
			}
		}

		void render_clipped_cell(const char* id, const std::string& text, ImU32 color) {
			float avail_w = ImGui::GetContentRegionAvail().x;
			if (avail_w < 24.f) avail_w = 24.f;
			float h = ImGui::GetTextLineHeight();
			ImVec2 p = ImGui::GetCursorScreenPos();
			ImGui::InvisibleButton(id != nullptr ? id : "##cell", ImVec2(avail_w, h));
			ImVec4 clip(p.x, p.y, p.x + avail_w, p.y + h);
			ImGui::GetWindowDrawList()->AddText(ImGui::GetFont(), ImGui::GetFontSize(), p, color,
				text.c_str(), nullptr, 0.f, &clip);
			if (ImGui::IsItemHovered() && ImGui::CalcTextSize(text.c_str()).x > avail_w) {
				ImGui::BeginTooltip();
				ImGui::PushTextWrapPos(560.f);
				ImGui::TextUnformatted(text.c_str());
				ImGui::PopTextWrapPos();
				ImGui::EndTooltip();
			}
		}

		std::string format_result_summary(const test_lab::feature_t& f, const test_lab::result_t& r) {
			std::string out;
			out.reserve(512);
			out.append("feature: ");
			out.append(f.category != nullptr ? f.category : "?");
			out.append("/");
			out.append(f.name != nullptr ? f.name : "?");
			out.append("\n");
			out.append("driver: ");
			out.append(driver_label(f.driver));
			out.append("\n");
			out.append("status: ");
			out.append(result_state_label(r.state.load(std::memory_order_acquire),
				test_lab::effective_outcome(r, f.driver == test_lab::driver_e::driverless)));
			out.append("\n");
			char buf[128];
			std::snprintf(buf, sizeof(buf), "ntstatus: %s (0x%08X)\n",
				test_lab_format::ntstatus_to_string(r.ntstatus),
				static_cast<unsigned>(static_cast<std::uint32_t>(r.ntstatus)));
			out.append(buf);
			std::snprintf(buf, sizeof(buf), "bytes_returned: %u\nelapsed_us: %llu\nraw_size: %zu\nparsed_fields: %zu\n",
				static_cast<unsigned>(r.bytes_returned),
				static_cast<unsigned long long>(r.elapsed_us),
				r.raw.size(),
				r.parsed.size());
			out.append(buf);
			if (!r.error.empty()) {
				out.append("error: ");
				out.append(r.error);
				out.append("\n");
			}
			return out;
		}

		std::string format_raw_hex(const std::vector<std::uint8_t>& raw) {
			std::string out;
			out.reserve(raw.size() * 3);
			char tmp[8];
			for (std::size_t i = 0; i < raw.size(); ++i) {
				std::snprintf(tmp, sizeof(tmp), "%02X ", static_cast<unsigned>(raw[i]));
				out.append(tmp);
			}
			return out;
		}

		std::string format_parsed_fields(const std::vector<test_lab::parsed_field_t>& parsed) {
			std::string out;
			for (const auto& p : parsed) {
				out.append(p.label);
				out.append(": ");
				out.append(p.value);
				out.append("\n");
			}
			return out;
		}

		std::atomic<bool> g_run_all_active{ false };
		std::atomic<bool> g_single_feature_active{ false };
		std::atomic<int>  g_run_all_current{ 0 };
		std::atomic<int>  g_run_all_total{ 0 };
		std::atomic<int>  g_run_all_ok{ 0 };
		std::atomic<int>  g_run_all_fail{ 0 };
		std::atomic<int>  g_run_all_skipped{ 0 };
		std::mutex        g_run_all_status_mtx;
		std::string       g_run_all_status_line;
		std::string       g_run_all_current_name;

		struct run_all_control_t {
			std::atomic<bool> cancel_requested{ false };
			std::atomic<int> ownership{ 0 };
		};

		struct log_tail_line_t {
			std::uint64_t index = 0;
			std::string text;
		};

		struct feature_run_summary_t {
			test_lab::run_state_e state = test_lab::run_state_e::idle;
			test_lab::outcome_e outcome = test_lab::outcome_e::not_run;
			bool ok = false;
			bool skipped = false;
			std::int32_t ntstatus = 0;
			std::uint32_t bytes_returned = 0;
			std::uint64_t elapsed_us = 0;
			std::string error;
			std::uint64_t started_ms = 0;
			std::uint64_t finished_ms = 0;
			std::uint64_t log_line_index = 0;
		};

		std::mutex g_log_tail_mtx;
		std::deque<log_tail_line_t> g_log_tail;
		std::uint64_t g_log_tail_next_index = 1;

		std::mutex g_feature_summary_mtx;
		std::vector<feature_run_summary_t> g_feature_summaries;

		constexpr std::size_t k_log_tail_max_lines = 96;

		void log_render_lock_busy(const char* site, const char* lock_name);

		std::uint64_t now_ms() {
			return static_cast<std::uint64_t>(GetTickCount64());
		}

		void ensure_feature_summary_size_locked(std::size_t feature_count) {
			if (g_feature_summaries.size() != feature_count)
				g_feature_summaries.assign(feature_count, feature_run_summary_t{});
		}

		void reset_feature_summaries() {
			std::lock_guard<std::mutex> lk(g_feature_summary_mtx);
			g_feature_summaries.assign(test_lab::all_features().size(), feature_run_summary_t{});
		}

		void update_feature_summary_start(std::size_t feature_index, std::uint64_t log_index) {
			std::lock_guard<std::mutex> lk(g_feature_summary_mtx);
			const auto& features = test_lab::all_features();
			ensure_feature_summary_size_locked(features.size());
			if (feature_index >= g_feature_summaries.size()) return;
			feature_run_summary_t& s = g_feature_summaries[feature_index];
			s.state = test_lab::run_state_e::running;
			s.outcome = test_lab::outcome_e::not_run;
			s.ok = false;
			s.skipped = false;
			s.ntstatus = 0;
			s.bytes_returned = 0;
			s.elapsed_us = 0;
			s.error.clear();
			s.started_ms = now_ms();
			s.finished_ms = 0;
			if (log_index != 0) s.log_line_index = log_index;
		}

		void update_feature_summary_skip(std::size_t feature_index, const char* reason, std::uint64_t log_index) {
			std::lock_guard<std::mutex> lk(g_feature_summary_mtx);
			const auto& features = test_lab::all_features();
			ensure_feature_summary_size_locked(features.size());
			if (feature_index >= g_feature_summaries.size()) return;
			feature_run_summary_t& s = g_feature_summaries[feature_index];
			if (s.started_ms == 0) s.started_ms = now_ms();
			s.state = test_lab::run_state_e::complete;
			s.outcome = test_lab::outcome_e::not_run;
			s.ok = false;
			s.skipped = true;
			s.ntstatus = 0;
			s.bytes_returned = 0;
			s.elapsed_us = 0;
			s.error = reason != nullptr ? reason : "skipped";
			s.finished_ms = now_ms();
			if (log_index != 0) s.log_line_index = log_index;
		}

		void update_feature_summary_result(std::size_t feature_index, const test_lab::result_t& r, std::uint64_t log_index) {
			std::lock_guard<std::mutex> lk(g_feature_summary_mtx);
			const auto& features = test_lab::all_features();
			ensure_feature_summary_size_locked(features.size());
			if (feature_index >= g_feature_summaries.size()) return;
			feature_run_summary_t& s = g_feature_summaries[feature_index];
			if (s.started_ms == 0) s.started_ms = now_ms();
			s.state = test_lab::run_state_e::complete;
			s.outcome = r.outcome;
			s.ok = r.ok;
			s.skipped = r.skipped;
			s.ntstatus = r.ntstatus;
			s.bytes_returned = r.bytes_returned;
			s.elapsed_us = r.elapsed_us;
			s.error = r.error;
			s.finished_ms = now_ms();
			if (log_index != 0) s.log_line_index = log_index;
		}

		bool try_copy_feature_summaries(const char* site, std::vector<feature_run_summary_t>& out) {
			std::unique_lock<std::mutex> lk(g_feature_summary_mtx, std::try_to_lock);
			if (!lk.owns_lock()) {
				log_render_lock_busy(site, "g_feature_summary_mtx");
				return false;
			}
			ensure_feature_summary_size_locked(test_lab::all_features().size());
			out = g_feature_summaries;
			return true;
		}

		std::uint64_t append_log_tail(const std::string& text) {
			std::lock_guard<std::mutex> lk(g_log_tail_mtx);
			std::uint64_t first_index = 0;
			std::size_t pos = 0;
			while (pos <= text.size()) {
				std::size_t nl = text.find('\n', pos);
				std::size_t end = (nl == std::string::npos) ? text.size() : nl;
				std::string line = text.substr(pos, end - pos);
				if (!line.empty() && line.back() == '\r') line.pop_back();
				if (line.size() > 900) {
					line.resize(897);
					line.append("...");
				}
				log_tail_line_t item;
				item.index = g_log_tail_next_index++;
				item.text = std::move(line);
				if (first_index == 0) first_index = item.index;
				g_log_tail.push_back(std::move(item));
				while (g_log_tail.size() > k_log_tail_max_lines)
					g_log_tail.pop_front();
				if (nl == std::string::npos) break;
				pos = nl + 1;
				if (pos == text.size()) break;
			}
			return first_index;
		}

		bool try_copy_log_tail(const char* site, std::vector<log_tail_line_t>& out) {
			std::unique_lock<std::mutex> lk(g_log_tail_mtx, std::try_to_lock);
			if (!lk.owns_lock()) {
				log_render_lock_busy(site, "g_log_tail_mtx");
				return false;
			}
			out.assign(g_log_tail.begin(), g_log_tail.end());
			return true;
		}

		void log_render_lock_busy(const char* site, const char* lock_name) {
			static std::atomic<unsigned long long> s_last_busy_log_ms{0};
			const unsigned long long now = GetTickCount64();
			unsigned long long last = s_last_busy_log_ms.load(std::memory_order_acquire);
			if (now - last >= 1000ULL && s_last_busy_log_ms.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
				diag::log_tagged_critical_fmt("test_lab_render",
					"lock_busy site=%s lock=%s frame=%d tid=%lu safe_run_active=%d current=%d total=%d ok=%d fail=%d skipped=%d full_test=%d",
					site ? site : "<null>",
					lock_name ? lock_name : "<null>",
					ImGui::GetFrameCount(),
					static_cast<unsigned long>(GetCurrentThreadId()),
					g_run_all_active.load(std::memory_order_acquire) ? 1 : 0,
					g_run_all_current.load(std::memory_order_acquire),
					g_run_all_total.load(std::memory_order_acquire),
					g_run_all_ok.load(std::memory_order_acquire),
					g_run_all_fail.load(std::memory_order_acquire),
					g_run_all_skipped.load(std::memory_order_acquire),
					test_all_features::is_running() ? 1 : 0);
			}
		}

		bool try_copy_result_summary(const char* site, test_lab::run_state_e& state,
			test_lab::outcome_e& outcome, bool& ok, bool& skipped) {
			std::unique_lock<std::mutex> lk(g_result_mtx, std::try_to_lock);
			if (!lk.owns_lock()) {
				log_render_lock_busy(site, "g_result_mtx");
				state = test_lab::run_state_e::idle;
				outcome = test_lab::outcome_e::not_run;
				ok = false;
				skipped = false;
				return false;
			}
			std::shared_ptr<test_lab::result_t> snap = g_result;
			if (!snap) {
				state = test_lab::run_state_e::idle;
				outcome = test_lab::outcome_e::not_run;
				ok = false;
				skipped = false;
				return true;
			}
			state = snap->state.load(std::memory_order_acquire);
			outcome = snap->outcome;
			ok = snap->ok;
			skipped = snap->skipped;
			return true;
		}

		bool try_copy_result_full(const char* site, test_lab::result_t& out) {
			std::unique_lock<std::mutex> lk(g_result_mtx, std::try_to_lock);
			if (!lk.owns_lock()) {
				log_render_lock_busy(site, "g_result_mtx");
				out.state.store(test_lab::run_state_e::idle, std::memory_order_release);
				out.outcome = test_lab::outcome_e::not_run;
				out.ok = false;
				out.skipped = false;
				out.ntstatus = 0;
				out.bytes_returned = 0;
				out.elapsed_us = 0;
				out.error.clear();
				out.raw.clear();
				out.parsed.clear();
				return false;
			}
			std::shared_ptr<test_lab::result_t> snap = g_result;
			if (!snap) {
				out.state.store(test_lab::run_state_e::idle, std::memory_order_release);
				out.outcome = test_lab::outcome_e::not_run;
				out.ok = false;
				out.skipped = false;
				out.ntstatus = 0;
				out.bytes_returned = 0;
				out.elapsed_us = 0;
				out.error.clear();
				out.raw.clear();
				out.parsed.clear();
				return true;
			}
			out.state.store(snap->state.load(std::memory_order_acquire), std::memory_order_release);
			out.outcome = snap->outcome;
			out.ok = snap->ok;
			out.skipped = snap->skipped;
			out.ntstatus = snap->ntstatus;
			out.bytes_returned = snap->bytes_returned;
			out.elapsed_us = snap->elapsed_us;
			out.error = snap->error;
			out.raw = snap->raw;
			out.parsed = snap->parsed;
			return true;
		}

		bool try_replace_result(const char* site, const std::shared_ptr<test_lab::result_t>& result) {
			std::unique_lock<std::mutex> lk(g_result_mtx, std::try_to_lock);
			if (!lk.owns_lock()) {
				log_render_lock_busy(site, "g_result_mtx");
				return false;
			}
			g_result = result;
			return true;
		}

		struct full_test_scope_t {
			const char* source = nullptr;
			bool active = false;

			explicit full_test_scope_t(const char* s) : source(s), active(true) {
				test_all_features::begin_test_guard(source);
			}

			~full_test_scope_t() {
				if (active)
					test_all_features::end_test_guard(source);
			}

			full_test_scope_t(const full_test_scope_t&) = delete;
			full_test_scope_t& operator=(const full_test_scope_t&) = delete;
		};

		const char* run_all_log_path() {
			static const std::string path = []() {
				char buf[MAX_PATH] = {};
				if (diag::build_log_path("aida_test_results.log", buf, sizeof(buf)))
					return std::string(buf);
				return std::string();
			}();
			return path.c_str();
		}

		void open_run_all_log_folder() {
			std::string path = run_all_log_path();
			std::size_t cut = path.find_last_of("\\/");
			if (cut == std::string::npos) return;
			std::string folder = path.substr(0, cut);
			if (folder.empty()) return;
			ShellExecuteA(nullptr, "open", folder.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
		}

		void populate_safe_defaults(test_lab::state_t& s) {
			s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			s.tid = static_cast<std::uint32_t>(GetCurrentThreadId());
			s.addr = 0;
			s.size = 64;
			s.u32_a = 0;
			s.u32_b = 0;
			s.u64_a = 0;
			s.buf.clear();
			s.text_a = "ntdll.dll";
			s.text_b = "";
			s.user = nullptr;
		}

		void format_local_timestamp(char* out, std::size_t cap) {
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

		const char* driver_name(test_lab::driver_e d) {
			switch (d) {
				case test_lab::driver_e::whoswho:  return "whoswho";
				case test_lab::driver_e::driverless: return "driverless";
			}
			return "unknown";
		}

		void flush_run_all_log(HANDLE hFile) {
			if (hFile != INVALID_HANDLE_VALUE)
				FlushFileBuffers(hFile);
		}

		std::uint64_t append_log_line(HANDLE hFile, const std::string& line, bool force_flush = false) {
			const std::uint64_t line_index = append_log_tail(line);
			if (hFile == INVALID_HANDLE_VALUE) return line_index;
			static std::mutex s_log_mtx;
			static std::uint64_t s_last_flush_ms = 0;
			static std::uint32_t s_bytes_since_flush = 0;
			const bool important =
				line.find(" -- FAIL") != std::string::npos ||
				line.find("FATAL") != std::string::npos ||
				line.find("CRASH") != std::string::npos ||
				line.find("BSOD") != std::string::npos ||
				line.find("Run All complete") != std::string::npos;
			std::lock_guard<std::mutex> lk(s_log_mtx);
			DWORD wrote = 0;
			WriteFile(hFile, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
			s_bytes_since_flush += wrote;
			const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
			if (force_flush || important || s_last_flush_ms == 0 || s_bytes_since_flush >= 65536u || now - s_last_flush_ms >= 1000u) {
				FlushFileBuffers(hFile);
				s_last_flush_ms = now;
				s_bytes_since_flush = 0;
			}
			return line_index;
		}

		std::uint64_t append_log_starting(HANDLE hFile,
			const test_lab::feature_t& f,
			const test_lab::state_t& s)
		{
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(256);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(" -- STARTING\n");
			char tmp[160];
			std::snprintf(tmp, sizeof(tmp), "    state: pid=%u tid=%u addr=0x%llX size=%u u32_a=%u\n",
				static_cast<unsigned>(s.pid),
				static_cast<unsigned>(s.tid),
				static_cast<unsigned long long>(s.addr),
				static_cast<unsigned>(s.size),
				static_cast<unsigned>(s.u32_a));
			line.append(tmp);
			return append_log_line(hFile, line);
		}

		std::uint64_t append_log_skip(HANDLE hFile, const test_lab::feature_t& f, const char* reason) {
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(256);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(" -- SKIPPED (").append(reason != nullptr ? reason : "no reason").append(")\n");
			return append_log_line(hFile, line);
		}

		std::uint64_t append_log_result(HANDLE hFile,
			const test_lab::feature_t& f,
			const test_lab::state_t& s,
			const test_lab::result_t& r,
			std::uint64_t elapsed_us)
		{
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(1024);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(" -- ").append(test_lab_format::testlab_outcome_name(
				test_lab::effective_outcome(r, f.driver == test_lab::driver_e::driverless)));
			char tmp[64];
			std::snprintf(tmp, sizeof(tmp), " ntstatus=%s bytes=%u elapsed_us=%llu\n",
				test_lab_format::ntstatus_to_string(r.ntstatus),
				static_cast<unsigned>(r.bytes_returned),
				static_cast<unsigned long long>(elapsed_us));
			line.append(tmp);

			std::snprintf(tmp, sizeof(tmp), "    state: pid=%u tid=%u addr=0x%llX size=%u u32_a=%u\n",
				static_cast<unsigned>(s.pid),
				static_cast<unsigned>(s.tid),
				static_cast<unsigned long long>(s.addr),
				static_cast<unsigned>(s.size),
				static_cast<unsigned>(s.u32_a));
			line.append(tmp);

			if ((!r.ok || r.skipped) && !r.error.empty()) {
				line.append("    error: ").append(r.error).append("\n");
			}
			for (const auto& p : r.parsed) {
				line.append("    ").append(p.label).append(": ").append(p.value).append("\n");
			}
			if (!r.raw.empty()) {
				std::size_t limit = r.raw.size();
				if (limit > 64) limit = 64;
				line.append("    raw[0..");
				std::snprintf(tmp, sizeof(tmp), "%zu]: ", limit);
				line.append(tmp);
				for (std::size_t i = 0; i < limit; ++i) {
					std::snprintf(tmp, sizeof(tmp), "%02X ", static_cast<unsigned>(r.raw[i]));
					line.append(tmp);
				}
				line.append("\n");
			}
			return append_log_line(hFile, line);
		}

		HANDLE open_log_for_append() {
			return CreateFileA(
				run_all_log_path(),
				FILE_APPEND_DATA | SYNCHRONIZE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
		}

		bool name_starts_with(const char* name, const char* prefix) {
			if (name == nullptr || prefix == nullptr) return false;
			std::size_t i = 0;
			while (prefix[i] != '\0') {
				if (name[i] == '\0' || name[i] != prefix[i]) return false;
				++i;
			}
			return true;
		}

		struct run_all_cache_t {
			std::uint64_t dtb = 0;
			std::uint64_t base = 0;
			std::uint64_t alloc_addr = 0;
			std::uint32_t alloc_pid = 0;
			bool sandbox_self_registered = false;
		};

		std::uint64_t resolve_ntdll_base() {
			HMODULE h = GetModuleHandleW(L"ntdll.dll");
			if (h == nullptr) return 0;
			return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h));
		}

		void prime_run_all_cache(run_all_cache_t& cache) {
			cache.dtb = 0;
			cache.base = 0;
			cache.alloc_addr = 0;
			cache.alloc_pid = 0;
			cache.sandbox_self_registered = false;
			if (!device || !device->is_connected()) return;
			std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			cache.dtb = device->solve_dtb_for_pid(self_pid);
			HMODULE self_module = GetModuleHandleW(nullptr);
			if (self_module != nullptr)
				cache.base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(self_module));
			cache.alloc_addr = driver_bridge::allocate_memory_for(self_pid, 0x1000);
			if (cache.alloc_addr != 0) cache.alloc_pid = self_pid;
			diag::log_tagged_fmt("testlab",
				"run-all cache primed: pid=%u dtb=0x%016llX base=0x%016llX alloc_addr=0x%016llX",
				static_cast<unsigned>(self_pid),
				static_cast<unsigned long long>(cache.dtb),
				static_cast<unsigned long long>(cache.base),
				static_cast<unsigned long long>(cache.alloc_addr));
		}

		void release_run_all_cache(run_all_cache_t& cache) noexcept {
			try {
				if (cache.alloc_addr != 0) {
					if (!driver_bridge::free_memory_for(cache.alloc_pid, cache.alloc_addr)) {
						diag::log_tagged_fmt("testlab", "run-all cache free failed: addr=0x%016llX pid=%u",
							static_cast<unsigned long long>(cache.alloc_addr),
							static_cast<unsigned>(cache.alloc_pid));
					}
					cache.alloc_addr = 0;
					cache.alloc_pid = 0;
				}
			} catch (...) {
				diag::log_tagged("testlab", "run-all cache cleanup exception");
				cache.alloc_addr = 0;
				cache.alloc_pid = 0;
			}
		}

		void apply_smart_defaults(const test_lab::feature_t& f,
			test_lab::state_t& s,
			run_all_cache_t& cache)
		{
			const char* name = f.name;
			if (name == nullptr) return;

			if (name_starts_with(name, "PHYS") ||
				name_starts_with(name, "V2P"))
			{
				s.u64_a = cache.dtb;
				if (s.addr == 0) {
					if (cache.base != 0) {
						s.addr = cache.base;
					} else {
						HMODULE h_self = GetModuleHandleW(nullptr);
						if (h_self != nullptr) {
							s.addr = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h_self));
						}
					}
				}
				if (s.size == 0) s.size = 256;
				return;
			}
			if (name_starts_with(name, "DPIN")) {
				s.u64_a = cache.dtb;
				return;
			}
			if (name_starts_with(name, "MEX")) {
				s.u64_a = cache.dtb;
				std::uint64_t mex_base = resolve_ntdll_base();
				if (mex_base == 0) mex_base = cache.base;
				if (mex_base == 0) {
					HMODULE h_self = GetModuleHandleW(nullptr);
					if (h_self != nullptr) {
						mex_base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h_self));
					}
				}
				if (mex_base != 0) s.addr = mex_base;
				if (s.text_a.empty() || s.text_a == "ntdll.dll") s.text_a = "ntdll.dll";
				s.text_b = "NtClose";
				return;
			}
			if (name_starts_with(name, "FM")) {
				if (cache.alloc_addr != 0) {
					s.addr = cache.alloc_addr;
				}
				s.size = 64;
				return;
			}
			if (name_starts_with(name, "PMOD")) {
				s.text_a = "tag1|0|6|80|0|DEAD|BEEF";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "PM")) {
				if (cache.alloc_addr != 0) {
					s.addr = cache.alloc_addr;
				}
				s.size = 64;
				s.u32_a = 0x04u;
				return;
			}
			if (name_starts_with(name, "PRED") || name_starts_with(name, "CKIL")) {
				s.text_a = "tcp://127.0.0.1:80";
				s.text_b = "tcp://127.0.0.1:443";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "DNSS")) {
				s.text_a = "test.example.com";
				s.text_b = "127.0.0.1";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "PCEX")) {
				char tmp[MAX_PATH];
				GetTempPathA(MAX_PATH, tmp);
				s.text_a = std::string(tmp) + "aida_test_capture.pcap";
				return;
			}
			if (name_starts_with(name, "CR")) {
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "STRM")) {
				s.u64_a = (static_cast<std::uint64_t>(80u) << 16) | static_cast<std::uint64_t>(443u);
				return;
			}
			if (name_starts_with(name, "PSBX")) {
				return;
			}
			if (name_starts_with(name, "USBX")) {
				if (!cache.sandbox_self_registered && device && device->is_connected()) {
					std::uint64_t denials = 0;
					if (device->protect_sandbox_pid(s.pid, 0, &denials)) {
						cache.sandbox_self_registered = true;
					}
				}
				return;
			}
			if (name_starts_with(name, "NLOG")) {
				if (!cache.sandbox_self_registered && device && device->is_connected()) {
					std::uint64_t denials = 0;
					if (device->protect_sandbox_pid(s.pid, 0, &denials)) {
						cache.sandbox_self_registered = true;
					}
				}
				s.u32_a = 1u;
				return;
			}
		}

		void start_run_all_safe() {
			if (g_single_feature_active.load(std::memory_order_acquire)) {
				diag::log_tagged("test_lab", "run_all_safe rejected: single feature worker still active");
				return;
			}
			bool expected = false;
			if (!g_run_all_active.compare_exchange_strong(expected, true)) return;
			g_run_all_current.store(0);
			g_run_all_ok.store(0);
			g_run_all_fail.store(0);
			g_run_all_skipped.store(0);
			reset_feature_summaries();
			{
				std::unique_lock<std::mutex> lk(g_run_all_status_mtx, std::try_to_lock);
				if (lk.owns_lock()) {
					g_run_all_status_line = "starting...";
					g_run_all_current_name.clear();
				} else {
					log_render_lock_busy("start_run_all_safe_status", "g_run_all_status_mtx");
				}
			}

			bool posted = false;
			try {
				auto control = std::make_shared<run_all_control_t>();
				aida::infra::executor::submission_t submission;
				submission.owner_subsystem = "test_lab_view";
				submission.label = "test_lab_view.run_all_safe";
				submission.thread_class = "testlab_view_run_all";
				submission.domain = aida::infra::executor::domain_t::long_running;
				submission.priority = 2;
				submission.cancel_hook = [control]() {
					control->cancel_requested.store(true, std::memory_order_release);
					int queued = 0;
					if (control->ownership.compare_exchange_strong(queued, 2, std::memory_order_acq_rel)) {
						g_run_all_active.store(false, std::memory_order_release);
						std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
						g_run_all_status_line = "cancelled before worker start";
						g_run_all_current_name.clear();
					}
				};
				submission.failure_policy = "reject_not_started";
				submission.body = [control]() {
				int queued = 0;
				if (!control->ownership.compare_exchange_strong(queued, 1, std::memory_order_acq_rel))
					return;
				struct active_reset_t {
					std::shared_ptr<run_all_control_t> control;
					~active_reset_t() {
						control->ownership.store(2, std::memory_order_release);
						g_run_all_active.store(false, std::memory_order_release);
					}
				} active_reset{ control };
				HANDLE hFile = INVALID_HANDLE_VALUE;
				run_all_cache_t cache;
				std::size_t active_feature = static_cast<std::size_t>(-1);
				try {
				full_test_scope_t full_test_scope("test_lab_view_run_all");
				const auto& features = test_lab::all_features();
				g_run_all_total.store(static_cast<int>(features.size()));

				hFile = open_log_for_append();
				if (hFile != INVALID_HANDLE_VALUE) {
					char ts[40];
					format_local_timestamp(ts, sizeof(ts));
					char header[256];
					std::snprintf(header, sizeof(header),
						"\n========================================\n"
						"[%s] Run All Safe Tests started (total=%d)\n"
						"========================================\n",
						ts, static_cast<int>(features.size()));
					append_log_line(hFile, std::string(header), true);
				}

				prime_run_all_cache(cache);

				for (std::size_t i = 0; i < features.size(); ++i) {
					if (control->cancel_requested.load(std::memory_order_acquire))
						break;
					active_feature = i;
					const auto& f = features[i];
					g_run_all_current.store(static_cast<int>(i + 1));
					{
						std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
						g_run_all_current_name = (f.name != nullptr ? f.name : "?");
					}

					const char* destructive_reason = test_lab::destructive_guard_reason(f.category, f.name);
					if (destructive_reason != nullptr) {
						g_run_all_skipped.fetch_add(1);
						std::string reason = std::string("destructive guard: ") + destructive_reason;
						std::uint64_t log_index = append_log_skip(hFile, f, reason.c_str());
						update_feature_summary_skip(i, reason.c_str(), log_index);
						test_lab_format::testlab_diag_log_skip(f, reason.c_str());
						active_feature = static_cast<std::size_t>(-1);
						continue;
					}
					if (f.run == nullptr) {
						g_run_all_skipped.fetch_add(1);
						std::uint64_t log_index = append_log_skip(hFile, f, "no run function");
						update_feature_summary_skip(i, "no run function", log_index);
						test_lab_format::testlab_diag_log_skip(f, "no run function");
						active_feature = static_cast<std::size_t>(-1);
						continue;
					}

					test_lab::state_t s;
					populate_safe_defaults(s);
					apply_smart_defaults(f, s, cache);
					if (control->cancel_requested.load(std::memory_order_acquire)) {
						active_feature = static_cast<std::size_t>(-1);
						break;
					}
					test_lab::result_t r;
					std::uint64_t start_log_index = append_log_starting(hFile, f, s);
					update_feature_summary_start(i, start_log_index);
					test_lab_format::testlab_diag_log_entry(f, s);
					auto t0 = std::chrono::steady_clock::now();
					f.run(s, r);
					if (f.driver != test_lab::driver_e::driverless) test_lab::normalize_legacy_result(r);
					auto t1 = std::chrono::steady_clock::now();
					std::uint64_t elapsed_us = static_cast<std::uint64_t>(
						std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
					if (r.elapsed_us == 0) r.elapsed_us = elapsed_us;

					if (r.skipped) g_run_all_skipped.fetch_add(1);
					else if (r.ok) g_run_all_ok.fetch_add(1);
					else           g_run_all_fail.fetch_add(1);

					std::uint64_t result_log_index = append_log_result(hFile, f, s, r, r.elapsed_us);
					update_feature_summary_result(i, r, result_log_index);
					test_lab_format::testlab_diag_log_exit(f, r, r.elapsed_us);
					active_feature = static_cast<std::size_t>(-1);
					if (control->cancel_requested.load(std::memory_order_acquire))
						break;
				}
				active_feature = static_cast<std::size_t>(-1);
				const bool cancelled = control->cancel_requested.load(std::memory_order_acquire);

				if (hFile != INVALID_HANDLE_VALUE) {
					char ts2[40];
					format_local_timestamp(ts2, sizeof(ts2));
					char footer[256];
					std::snprintf(footer, sizeof(footer),
						"[%s] Run All %s: ok=%d fail=%d skipped=%d total=%d\n"
						"========================================\n\n",
						ts2,
						cancelled ? "cancelled" : "complete",
						g_run_all_ok.load(),
						g_run_all_fail.load(),
						g_run_all_skipped.load(),
						g_run_all_total.load());
					append_log_line(hFile, std::string(footer), true);
					flush_run_all_log(hFile);
					CloseHandle(hFile);
					hFile = INVALID_HANDLE_VALUE;
				}

				{
					std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
					char buf[160];
					std::snprintf(buf, sizeof(buf),
						cancelled ? "cancelled: ok=%d fail=%d skipped=%d (log on Desktop)" :
							"done: ok=%d fail=%d skipped=%d (log on Desktop)",
						g_run_all_ok.load(),
						g_run_all_fail.load(),
						g_run_all_skipped.load());
					g_run_all_status_line = buf;
					g_run_all_current_name.clear();
				}
				release_run_all_cache(cache);
				if (hFile != INVALID_HANDLE_VALUE) {
					CloseHandle(hFile);
					hFile = INVALID_HANDLE_VALUE;
				}
				} catch (const std::exception& ex) {
					release_run_all_cache(cache);
					if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
					if (active_feature != static_cast<std::size_t>(-1)) {
						const auto& features = test_lab::all_features();
						if (active_feature < features.size()) {
							test_lab::result_t failure;
							failure.outcome = test_lab::outcome_e::failed;
							failure.error = ex.what();
							failure.state.store(test_lab::run_state_e::complete, std::memory_order_release);
							update_feature_summary_result(active_feature, failure, 0);
						}
					}
					g_run_all_fail.fetch_add(1);
					{
						std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
						g_run_all_status_line = "failed: worker exception";
						g_run_all_current_name.clear();
					}
					diag::log_tagged_fmt("test_lab", "run_all_safe worker exception: %s", ex.what());
				} catch (...) {
					release_run_all_cache(cache);
					if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
					if (active_feature != static_cast<std::size_t>(-1)) {
						const auto& features = test_lab::all_features();
						if (active_feature < features.size()) {
							test_lab::result_t failure;
							failure.outcome = test_lab::outcome_e::failed;
							failure.error = "unknown worker exception";
							failure.state.store(test_lab::run_state_e::complete, std::memory_order_release);
							update_feature_summary_result(active_feature, failure, 0);
						}
					}
					g_run_all_fail.fetch_add(1);
					{
						std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
						g_run_all_status_line = "failed: worker exception";
						g_run_all_current_name.clear();
					}
					diag::log_tagged("test_lab", "run_all_safe worker unknown exception");
				}
				};
				posted = aida::infra::executor::submit(std::move(submission)).submitted;
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("test_lab", "run_all_safe executor submit exception: %s", ex.what());
			} catch (...) {
				diag::log_tagged("test_lab", "run_all_safe executor submit unknown exception");
			}
			if (!posted) {
				g_run_all_active.store(false, std::memory_order_release);
				{
					std::unique_lock<std::mutex> lk(g_run_all_status_mtx, std::try_to_lock);
					if (lk.owns_lock()) {
						g_run_all_status_line = "start failed: executor unavailable";
						g_run_all_current_name.clear();
					} else {
						log_render_lock_busy("start_run_all_safe_post_failed_status", "g_run_all_status_mtx");
					}
				}
				diag::log_tagged("test_lab", "run_all_safe executor submit failed");
			}
		}

		struct grouped_row_t {
			int  feature_idx = -1;
			bool is_header = false;
			std::string header_text;
		};

		struct category_counts_t {
			int pass = 0;
			int fail = 0;
			int skip = 0;
			int running = 0;
		};

		category_counts_t category_counts(const std::string& category,
			const std::vector<feature_run_summary_t>& summaries)
		{
			category_counts_t counts;
			const auto& features = test_lab::all_features();
			for (std::size_t i = 0; i < features.size(); ++i) {
				const char* cat = features[i].category != nullptr ? features[i].category : "Uncategorized";
				if (category != cat || i >= summaries.size()) continue;
				const feature_run_summary_t& s = summaries[i];
				if (s.state == test_lab::run_state_e::running) {
					++counts.running;
				} else if (s.state == test_lab::run_state_e::complete) {
					if (s.skipped) ++counts.skip;
					else if (s.ok) ++counts.pass;
					else ++counts.fail;
				}
			}
			return counts;
		}

		std::string format_category_counts(const category_counts_t& counts) {
			char buf[96];
			if (counts.running > 0) {
				std::snprintf(buf, sizeof(buf), "%d run / %d pass / %d fail / %d skip",
					counts.running, counts.pass, counts.fail, counts.skip);
			} else {
				std::snprintf(buf, sizeof(buf), "%d pass / %d fail / %d skip",
					counts.pass, counts.fail, counts.skip);
			}
			return std::string(buf);
		}

		void build_grouped_rows(std::vector<grouped_row_t>& out) {
			out.clear();
			const auto& features = test_lab::all_features();
			std::string current_cat;
			for (std::size_t i = 0; i < features.size(); ++i) {
				const auto& f = features[i];
				const char* cat = (f.category != nullptr) ? f.category : "Uncategorized";
				if (current_cat != cat) {
					current_cat = cat;
					grouped_row_t hdr;
					hdr.is_header = true;
					hdr.header_text = current_cat;
					out.push_back(hdr);
				}
				grouped_row_t row;
				row.feature_idx = static_cast<int>(i);
				out.push_back(row);
			}
		}

		void render_left_pane(float pane_w, float pane_h, float accumulated_time) {
			const auto& t = aida::ui::resolved();
			ImGui::BeginChild("##testlab_left", ImVec2(pane_w, pane_h), false,
				ImGuiWindowFlags_NoBackground);

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(wp, ImVec2(wp.x + pane_w, wp.y + pane_h),
				aida::ui::with_alpha(t.panel_bg, 0.55f), 6.f);

			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::Indent(10.f);
			ImGui::TextUnformatted("DRIVER TEST LAB");
			ImGui::Unindent(10.f);
			ImGui::Dummy(ImVec2(0.f, 2.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 2.f));

			ImGui::BeginChild("##testlab_left_scroll",
				ImVec2(pane_w - 4.f, pane_h - 64.f), false, ImGuiWindowFlags_None);

			std::vector<grouped_row_t> rows;
			build_grouped_rows(rows);
			const auto& features = test_lab::all_features();
			static std::vector<feature_run_summary_t> s_last_summaries;
			std::vector<feature_run_summary_t> summaries;
			if (try_copy_feature_summaries("left_pane_summary_snapshot", summaries)) {
				s_last_summaries = summaries;
			} else {
				summaries = s_last_summaries;
			}

			int rendered_index = 0;
			for (std::size_t r = 0; r < rows.size(); ++r) {
				const auto& row = rows[r];
				float ent = ui_anim::render_row_entrance(rendered_index, accumulated_time, 0.012f);
				++rendered_index;

				if (row.is_header) {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::Indent(10.f);
					ImGui::TextUnformatted(row.header_text.c_str());
					category_counts_t counts = category_counts(row.header_text, summaries);
					if (counts.pass != 0 || counts.fail != 0 || counts.skip != 0 || counts.running != 0) {
						std::string count_text = format_category_counts(counts);
						float tw = ImGui::CalcTextSize(count_text.c_str()).x;
						float x = pane_w - tw - 22.f;
						if (x > ImGui::GetCursorPosX()) {
						ImGui::SameLine(x);
						ImGui::TextUnformatted(count_text.c_str());
						}
					}
					ImGui::Unindent(10.f);
					continue;
				}

				int fidx = row.feature_idx;
				if (fidx < 0 || fidx >= static_cast<int>(features.size())) continue;
				const auto& f = features[static_cast<std::size_t>(fidx)];

				ImGui::PushID(fidx);
				bool is_selected = (g_selected_idx == fidx);

				float row_h = 34.f;
				ImVec2 row_start = ImGui::GetCursorScreenPos();
				ImGui::InvisibleButton("##row", ImVec2(pane_w - 24.f, row_h));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked();

				ImU32 row_bg = is_selected
					? aida::ui::with_alpha(t.selection_strong, 0.85f * ent)
					: (hov ? aida::ui::with_alpha(t.hover_wash, 0.55f * ent)
					       : aida::ui::with_alpha(t.panel_bg, 0.0f));
				ImDrawList* rdl = ImGui::GetWindowDrawList();
				rdl->AddRectFilled(row_start,
					ImVec2(row_start.x + pane_w - 24.f, row_start.y + row_h),
					row_bg, 4.f);

				float dot_r = 4.f;
				ImVec2 dot_p(row_start.x + 10.f, row_start.y + row_h * 0.5f);
				test_lab::run_state_e rs = test_lab::run_state_e::idle;
				test_lab::outcome_e routcome = test_lab::outcome_e::not_run;
				bool rok = false;
				bool rskipped = false;
				feature_run_summary_t row_summary;
				if (static_cast<std::size_t>(fidx) < summaries.size()) {
					row_summary = summaries[static_cast<std::size_t>(fidx)];
					rs = row_summary.state;
					rok = row_summary.ok;
					rskipped = row_summary.skipped;
					routcome = row_summary.outcome;
				} else if (is_selected) {
					try_copy_result_summary("left_pane_selected_row", rs, routcome, rok, rskipped);
					row_summary.state = rs;
					row_summary.ok = rok;
					row_summary.skipped = rskipped;
					row_summary.outcome = routcome;
				}
				rdl->AddCircleFilled(dot_p, dot_r, status_dot_color(rs, routcome, ent));

				float badge_w = 34.f;
				float badge_h = 16.f;
				ImVec2 ba(row_start.x + 22.f, row_start.y + (row_h - badge_h) * 0.5f);
				ImVec2 bb(ba.x + badge_w, ba.y + badge_h);
				rdl->AddRectFilled(ba, bb, driver_badge_color(f.driver, 0.35f * ent), 3.f);
				rdl->AddRect(ba, bb, driver_badge_color(f.driver, 0.85f * ent), 3.f, 0, 1.f);
				const char* dl_label = driver_label(f.driver);
				ImVec2 dlts = ImGui::CalcTextSize(dl_label);
				rdl->AddText(ImVec2(ba.x + (badge_w - dlts.x) * 0.5f,
						ba.y + (badge_h - dlts.y) * 0.5f),
					aida::ui::with_alpha(t.text_primary, ent), dl_label);

				ImU32 name_col = aida::ui::with_alpha(
					is_selected ? t.text_primary : t.text_secondary, ent);
				const char* state_badge = result_state_badge(rs, routcome);
				ImU32 state_col = result_state_color(rs, routcome);
				float state_badge_w = 44.f;
				float state_badge_h = 16.f;
				ImVec2 sa(row_start.x + pane_w - 24.f - state_badge_w - 8.f,
					row_start.y + (row_h - state_badge_h) * 0.5f);
				ImVec2 sb(sa.x + state_badge_w, sa.y + state_badge_h);
				rdl->AddRectFilled(sa, sb, aida::ui::with_alpha(state_col, 0.16f * ent), 3.f);
				rdl->AddRect(sa, sb, aida::ui::with_alpha(state_col, 0.58f * ent), 3.f, 0, 1.f);
				ImVec2 sts = ImGui::CalcTextSize(state_badge);
				rdl->AddText(ImVec2(sa.x + (state_badge_w - sts.x) * 0.5f,
						sa.y + (state_badge_h - sts.y) * 0.5f),
					aida::ui::with_alpha(state_col, ent), state_badge);

				ImVec4 name_clip(row_start.x + 64.f, row_start.y,
					sa.x - 6.f, row_start.y + row_h);
				rdl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(row_start.x + 64.f, row_start.y + (row_h - ImGui::GetTextLineHeight()) * 0.5f),
					name_col, f.name != nullptr ? f.name : "", nullptr, 0.f, &name_clip);

				if (clicked && fidx != g_selected_idx) {
					g_selected_idx = fidx;
					if (!g_single_feature_active.load(std::memory_order_acquire) &&
						!g_run_all_active.load(std::memory_order_acquire))
						try_replace_result("left_pane_select_reset", std::make_shared<test_lab::result_t>());
				}
				if (hov) {
					ImGui::BeginTooltip();
					ImGui::Text("%s/%s",
						f.category != nullptr ? f.category : "?",
						f.name != nullptr ? f.name : "?");
					ImGui::Text("Status: %s", result_state_label(rs, routcome));
					if (rs == test_lab::run_state_e::complete) {
						ImGui::Text("NTSTATUS: %s", test_lab_format::ntstatus_to_string(row_summary.ntstatus));
						ImGui::Text("Bytes: %u  Elapsed: %s",
							static_cast<unsigned>(row_summary.bytes_returned),
							format_elapsed(row_summary.elapsed_us).c_str());
						if (row_summary.log_line_index != 0)
							ImGui::Text("Evidence line: %llu", static_cast<unsigned long long>(row_summary.log_line_index));
						if (!row_summary.error.empty()) {
							ImGui::PushTextWrapPos(520.f);
							ImGui::Text("Detail: %s", row_summary.error.c_str());
							ImGui::PopTextWrapPos();
						}
					}
					ImGui::EndTooltip();
				}
				ImGui::PopID();
			}

			ImGui::EndChild();

		ImGui::EndChild();
		}

		void render_inputs_section(const test_lab::feature_t& f) {
			const auto& t = aida::ui::resolved();
		ImGui::TextUnformatted("INPUTS");
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));
			if (f.render_inputs != nullptr) {
				f.render_inputs(g_state);
			} else {
				ImGui::TextDisabled("This feature does not require inputs.");
			}
		}

		void run_fn_post_with_feature(const test_lab::feature_t& f, int feature_idx);

		void render_action_row(const test_lab::feature_t& f) {
			test_lab::result_t action_copy;
			try_copy_result_full("action_row_snapshot", action_copy);
			test_lab::run_state_e rs = action_copy.state.load(std::memory_order_acquire);
			bool running = (rs == test_lab::run_state_e::running);

			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (running) ImGui::BeginDisabled();
			if (ImGui::Button("Run", ImVec2(110.f, 28.f))) {
				run_fn_post_with_feature(f, g_selected_idx);
			}
			if (running) ImGui::EndDisabled();
			ImGui::SameLine();

			if (ImGui::Button("Clear", ImVec2(110.f, 28.f))) {
				if (!g_single_feature_active.load(std::memory_order_acquire) &&
					!g_run_all_active.load(std::memory_order_acquire))
					try_replace_result("action_row_clear", std::make_shared<test_lab::result_t>());
			}
		}

		void run_fn_post_with_feature(const test_lab::feature_t& f, int feature_idx) {
			if (g_run_all_active.load(std::memory_order_acquire)) {
				diag::log_tagged("test_lab", "single feature rejected: run-all worker still active");
				return;
			}
			bool expected_active = false;
			if (!g_single_feature_active.compare_exchange_strong(expected_active, true, std::memory_order_acq_rel)) {
				diag::log_tagged("test_lab", "single feature rejected: previous worker still active");
				return;
			}
			test_lab::state_t snapshot = g_state;
			std::shared_ptr<test_lab::result_t> new_result = std::make_shared<test_lab::result_t>();
			new_result->state.store(test_lab::run_state_e::running, std::memory_order_release);
			if (!try_replace_result("single_feature_start", new_result)) {
				g_single_feature_active.store(false, std::memory_order_release);
				new_result->ok = false;
				new_result->outcome = test_lab::outcome_e::failed;
				new_result->error = "result lock busy";
				new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
				if (feature_idx >= 0)
					update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
				return;
			}
			if (feature_idx >= 0)
				update_feature_summary_start(static_cast<std::size_t>(feature_idx), 0);
			test_lab::feature_t feature_copy = f;
			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "test_lab_view";
			submission.label = "test_lab_view.single_feature";
			submission.thread_class = "testlab_feature";
			submission.domain = aida::infra::executor::domain_t::feature_worker;
			submission.priority = 2;
			submission.diagnostic_id = feature_copy.name ? feature_copy.name : "unnamed";
			submission.failure_policy = "reject_not_started";
			submission.body = [feature_copy, snapshot, new_result, feature_idx]() mutable {
				struct active_reset_t {
					~active_reset_t() { g_single_feature_active.store(false, std::memory_order_release); }
				} active_reset;
				try {
				full_test_scope_t full_test_scope("test_lab_view_single_feature");
				if (feature_copy.run == nullptr) {
					new_result->ok = false;
					new_result->outcome = test_lab::outcome_e::failed;
					new_result->error = "no run function";
					test_lab_format::testlab_diag_log_skip(feature_copy, "no run function");
					new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
					if (feature_idx >= 0)
						update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
					return;
				}
				test_lab_format::testlab_diag_log_entry(feature_copy, snapshot);
				auto t0 = std::chrono::steady_clock::now();
				test_lab::result_t local;
				local.state.store(test_lab::run_state_e::running, std::memory_order_release);
				feature_copy.run(snapshot, local);
				if (feature_copy.driver != test_lab::driver_e::driverless) test_lab::normalize_legacy_result(local);
				auto t1 = std::chrono::steady_clock::now();
				std::uint64_t elapsed_us = static_cast<std::uint64_t>(
					std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
				if (local.elapsed_us == 0) local.elapsed_us = elapsed_us;
				test_lab_format::testlab_diag_log_exit(feature_copy, local, local.elapsed_us);
				{
					std::lock_guard<std::mutex> lk(g_result_mtx);
					new_result->ok = local.ok;
					new_result->outcome = local.outcome;
					new_result->skipped = local.skipped;
					new_result->ntstatus = local.ntstatus;
					new_result->bytes_returned = local.bytes_returned;
					new_result->elapsed_us = local.elapsed_us;
					new_result->error = std::move(local.error);
					new_result->raw = std::move(local.raw);
					new_result->parsed = std::move(local.parsed);
				}
				new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
				if (feature_idx >= 0)
					update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
				} catch (const std::exception& ex) {
					{
						std::lock_guard<std::mutex> lk(g_result_mtx);
						new_result->ok = false;
						new_result->outcome = test_lab::outcome_e::failed;
						new_result->skipped = false;
						new_result->error = ex.what();
					}
					new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
					if (feature_idx >= 0)
						update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
					diag::log_tagged_fmt("test_lab", "single_feature worker exception name=%s: %s",
						feature_copy.name ? feature_copy.name : "?", ex.what());
				} catch (...) {
					{
						std::lock_guard<std::mutex> lk(g_result_mtx);
						new_result->ok = false;
						new_result->outcome = test_lab::outcome_e::failed;
						new_result->skipped = false;
						new_result->error = "unknown worker exception";
					}
					new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
					if (feature_idx >= 0)
						update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
					diag::log_tagged_fmt("test_lab", "single_feature worker unknown exception name=%s",
						feature_copy.name ? feature_copy.name : "?");
				}
			};
			bool submitted = false;
			try {
				submitted = aida::infra::executor::submit(std::move(submission)).submitted;
			} catch (const std::exception& ex) {
				new_result->error = ex.what();
				diag::log_tagged_fmt("test_lab", "single_feature executor submit exception name=%s: %s",
					feature_copy.name ? feature_copy.name : "?", ex.what());
			} catch (...) {
				new_result->error = "executor submission exception";
				diag::log_tagged_fmt("test_lab", "single_feature executor submit unknown exception name=%s",
					feature_copy.name ? feature_copy.name : "?");
			}
			if (!submitted) {
				g_single_feature_active.store(false, std::memory_order_release);
				new_result->ok = false;
				new_result->outcome = test_lab::outcome_e::failed;
				if (new_result->error.empty()) new_result->error = "executor unavailable";
				new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
				if (feature_idx >= 0)
					update_feature_summary_result(static_cast<std::size_t>(feature_idx), *new_result, 0);
				diag::log_tagged_fmt("test_lab", "single_feature executor submit failed name=%s",
					feature_copy.name ? feature_copy.name : "?");
			}
		}

		void render_result_section(const test_lab::feature_t& f, int feature_idx) {
			const auto& t = aida::ui::resolved();

			test_lab::result_t local_copy;
			const bool result_snapshot_ok = try_copy_result_full("result_section_snapshot", local_copy);
			test_lab::run_state_e rs = local_copy.state.load(std::memory_order_acquire);
			bool using_cached_summary = false;

			if (rs == test_lab::run_state_e::idle && feature_idx >= 0) {
				static std::vector<feature_run_summary_t> s_last_result_summaries;
				std::vector<feature_run_summary_t> summaries;
				if (try_copy_feature_summaries("result_section_feature_summary", summaries)) {
					s_last_result_summaries = summaries;
				} else {
					summaries = s_last_result_summaries;
				}
				if (static_cast<std::size_t>(feature_idx) < summaries.size()) {
					const feature_run_summary_t& cached = summaries[static_cast<std::size_t>(feature_idx)];
					if (cached.state != test_lab::run_state_e::idle) {
						local_copy.state.store(cached.state, std::memory_order_release);
						local_copy.ok = cached.ok;
						local_copy.outcome = cached.outcome;
						local_copy.skipped = cached.skipped;
						local_copy.ntstatus = cached.ntstatus;
						local_copy.bytes_returned = cached.bytes_returned;
						local_copy.elapsed_us = cached.elapsed_us;
						local_copy.error = cached.error;
						rs = cached.state;
						using_cached_summary = true;
					}
				}
			}

			ImGui::TextUnformatted("RESULT");
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (!result_snapshot_ok) {
				render_empty_panel("Result snapshot busy", "The worker is updating the selected result. Per-feature run status remains visible in the feature list.", 82.f);
				return;
			}

			const auto displayed_outcome = test_lab::effective_outcome(local_copy,
				f.driver == test_lab::driver_e::driverless);
			ImU32 status_col = result_state_color(rs, displayed_outcome);
			char ntbuf[96];
			std::snprintf(ntbuf, sizeof(ntbuf), "%s / 0x%08X",
				test_lab_format::ntstatus_to_string(local_copy.ntstatus),
				static_cast<unsigned>(static_cast<std::uint32_t>(local_copy.ntstatus)));
			char bytesbuf[32];
			std::snprintf(bytesbuf, sizeof(bytesbuf), "%u", static_cast<unsigned>(local_copy.bytes_returned));
			std::string elapsed = format_elapsed(local_copy.elapsed_us);

			render_chip(result_state_label(rs, displayed_outcome), status_col, 104.f);
			if (ImGui::GetContentRegionAvail().x > 172.f) ImGui::SameLine();
			render_metric_chip("NTSTATUS", ntbuf, status_col, 168.f);
			if (ImGui::GetContentRegionAvail().x > 100.f) ImGui::SameLine();
			render_metric_chip("Driver", driver_label(f.driver), driver_badge_color(f.driver, 0.95f), 86.f);
			if (ImGui::GetContentRegionAvail().x > 96.f) ImGui::SameLine();
			render_metric_chip("Bytes", bytesbuf, t.text_secondary, 82.f);
			if (ImGui::GetContentRegionAvail().x > 110.f) ImGui::SameLine();
			render_metric_chip("Elapsed", elapsed.c_str(), t.text_secondary, 102.f);

			ImGui::Dummy(ImVec2(0.f, 8.f));

			if (using_cached_summary) {
			ImGui::TextWrapped("Showing the cached run summary for this feature. Raw bytes and parsed fields are shown when the selected feature has a direct result snapshot; run-all evidence remains in the log tail below.");
				ImGui::Dummy(ImVec2(0.f, 6.f));
			}

			if (rs == test_lab::run_state_e::idle) {
				render_empty_panel("No execution yet", "Run this feature or use Run All Safe Tests to collect driver evidence.", 86.f);
				return;
			}
			if (rs == test_lab::run_state_e::running) {
				ImGui::ProgressBar(0.35f, ImVec2(-1.f, 7.f), "");
				ImGui::Dummy(ImVec2(0.f, 6.f));
				render_empty_panel("Running", "The worker is executing the selected feature and collecting diagnostics.", 86.f);
				return;
			}

			if (ImGui::Button("Copy summary", ImVec2(116.f, 28.f))) {
				std::string out = format_result_summary(f, local_copy);
				ImGui::SetClipboardText(out.c_str());
			}
			if (ImGui::GetContentRegionAvail().x > 118.f) ImGui::SameLine();
			if (ImGui::Button("Copy parsed", ImVec2(110.f, 28.f))) {
				std::string out = format_parsed_fields(local_copy.parsed);
				ImGui::SetClipboardText(out.c_str());
			}
			if (ImGui::GetContentRegionAvail().x > 104.f) ImGui::SameLine();
			if (ImGui::Button("Copy raw", ImVec2(96.f, 28.f))) {
				std::string out = format_raw_hex(local_copy.raw);
				ImGui::SetClipboardText(out.c_str());
			}

			if (!local_copy.error.empty()) {
				ImGui::Dummy(ImVec2(0.f, 8.f));
				ImGui::PushStyleColor(ImGuiCol_Text, t.error);
				ImGui::TextWrapped("error: %s", local_copy.error.c_str());
				ImGui::PopStyleColor();
			}

			ImGui::Dummy(ImVec2(0.f, 8.f));
			if (ImGui::CollapsingHeader("Raw bytes", ImGuiTreeNodeFlags_DefaultOpen)) {
				if (local_copy.raw.empty()) {
					render_empty_panel("No raw bytes", "This feature completed without a raw byte buffer.", 70.f);
				} else {
					float rows = static_cast<float>((local_copy.raw.size() + 15u) / 16u);
					float raw_h = (std::min)(180.f, (std::max)(92.f, 36.f + rows * ImGui::GetTextLineHeight()));
					ImGui::BeginChild("##testlab_raw_dump", ImVec2(0.f, raw_h), true,
						ImGuiWindowFlags_HorizontalScrollbar);
					test_lab_format::render_hex_ascii(local_copy.raw);
					ImGui::EndChild();
				}
			}

			ImGui::Dummy(ImVec2(0.f, 8.f));
			if (ImGui::CollapsingHeader("Parsed fields", ImGuiTreeNodeFlags_DefaultOpen)) {
				if (local_copy.parsed.empty()) {
					render_empty_panel("No parsed fields", "The feature did not return structured parsed fields for this run.", 70.f);
				} else {
					const float row_h = ImGui::GetTextLineHeight() + 4.f;
					const float visible_rows = static_cast<float>((std::min)(local_copy.parsed.size(), static_cast<std::size_t>(10)));
					const float parsed_h = (std::min)(260.f, (std::max)(96.f, 34.f + visible_rows * row_h));
					ImGui::BeginChild("##testlab_parsed_clip", ImVec2(0.f, parsed_h), true,
						ImGuiWindowFlags_HorizontalScrollbar);
					if (ImGui::BeginTable("##testlab_parsed", 2,
						ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg |
						ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp)) {
						ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthStretch, 0.34f);
						ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.66f);
						ImGui::TableHeadersRow();
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(local_copy.parsed.size()), row_h);
						while (clipper.Step()) {
							for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
								const auto& p = local_copy.parsed[static_cast<std::size_t>(row)];
								ImGui::TableNextRow(ImGuiTableRowFlags_None, row_h);
								ImGui::PushID(row);
								ImGui::TableSetColumnIndex(0);
								render_clipped_cell("label", p.label, t.text_secondary);
								ImGui::TableSetColumnIndex(1);
								render_clipped_cell("value", p.value, t.text_primary);
								ImGui::PopID();
							}
						}
						clipper.End();
						ImGui::EndTable();
					}
					ImGui::EndChild();
				}
			}
		}

		void render_run_all_evidence_panel(float max_h = 170.f) {
			const auto& t = aida::ui::resolved();
		ImGui::TextUnformatted("RECENT RUN EVIDENCE");
			ImGui::Separator();

		ImGui::TextWrapped("Log: %s", run_all_log_path());

			if (ImGui::Button("Copy log path", ImVec2(118.f, 26.f))) {
				ImGui::SetClipboardText(run_all_log_path());
			}
			if (ImGui::GetContentRegionAvail().x > 128.f) ImGui::SameLine();
			if (ImGui::Button("Open log folder", ImVec2(126.f, 26.f))) {
				open_run_all_log_folder();
			}

			static std::vector<log_tail_line_t> s_last_tail;
			std::vector<log_tail_line_t> tail;
			bool tail_ok = try_copy_log_tail("run_all_log_tail_panel", tail);
			if (tail_ok) {
				s_last_tail = tail;
			} else {
				tail = s_last_tail;
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));
			if (!tail_ok) {
				ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
				ImGui::TextUnformatted("Log tail snapshot busy; showing the last stable frame.");
				ImGui::PopStyleColor();
			}

			float child_h = max_h;
			if (child_h < 90.f) child_h = 90.f;
			ImGui::BeginChild("##testlab_run_all_tail", ImVec2(0.f, child_h), true,
				ImGuiWindowFlags_HorizontalScrollbar);
			if (tail.empty()) {
				render_empty_panel("No run-all evidence yet", "Run All Safe Tests writes target launch, driver attach, diagnostics, and result evidence here.", 82.f);
			} else {
			const float line_h = ImGui::GetTextLineHeightWithSpacing();
				ImGuiListClipper clipper;
				clipper.Begin(static_cast<int>(tail.size()), line_h);
				while (clipper.Step()) {
					for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
						const auto& line = tail[static_cast<std::size_t>(row)];
						ImGui::Text("[%04llu] %s",
							static_cast<unsigned long long>(line.index),
							line.text.c_str());
					}
				}
				clipper.End();
			if (g_run_all_active.load(std::memory_order_acquire))
					ImGui::SetScrollHereY(1.f);
			}
			ImGui::EndChild();
		}

		void render_right_pane(float pane_w, float pane_h) {
			const auto& t = aida::ui::resolved();
			ImGui::BeginChild("##testlab_right", ImVec2(pane_w, pane_h), false,
				ImGuiWindowFlags_NoBackground);
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(wp, ImVec2(wp.x + pane_w, wp.y + pane_h),
				aida::ui::with_alpha(t.panel_bg, 0.45f), 6.f);

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::Indent(12.f);

			const auto& features = test_lab::all_features();
			if (g_selected_idx < 0 || g_selected_idx >= static_cast<int>(features.size())) {
				ImGui::BeginChild("##testlab_right_scroll_empty",
					ImVec2(pane_w - 32.f, pane_h - 28.f), false, ImGuiWindowFlags_None);
				render_run_all_evidence_panel((std::min)(170.f, (std::max)(100.f, pane_h * 0.36f)));
				ImGui::Dummy(ImVec2(0.f, 10.f));
				ImVec2 empty_pos = ImGui::GetCursorScreenPos();
				float empty_w = ImGui::GetContentRegionAvail().x;
				if (empty_w < 120.f) empty_w = 120.f;
				ImVec2 empty_size(empty_w, (std::max)(140.f, pane_h * 0.34f));
				ImGui::Dummy(empty_size);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::shield;
				cfg.title = "No feature selected";
				cfg.body = "Select a Test Lab feature to inspect inputs, run status, and per-feature evidence.";
				cfg.max_width = 420.f;
				aida::ui::empty_state::render(empty_pos, empty_size, cfg);
				ImGui::EndChild();
				ImGui::Unindent(12.f);
				ImGui::EndChild();
				return;
			}

			const auto& f = features[static_cast<std::size_t>(g_selected_idx)];

			ImGui::Text("%s", f.name != nullptr ? f.name : "");
			if (f.summary != nullptr && f.summary[0] != '\0') {
				ImGui::TextWrapped("%s", f.summary);
			}
			ImGui::Dummy(ImVec2(0.f, 6.f));

			ImGui::BeginChild("##testlab_right_scroll",
				ImVec2(pane_w - 32.f, pane_h - 64.f), false, ImGuiWindowFlags_None);

			render_inputs_section(f);
			ImGui::Dummy(ImVec2(0.f, 8.f));
			render_action_row(f);
			ImGui::Dummy(ImVec2(0.f, 10.f));
			render_result_section(f, g_selected_idx);
			ImGui::Dummy(ImVec2(0.f, 12.f));
			render_run_all_evidence_panel((std::min)(180.f, (std::max)(110.f, pane_h * 0.28f)));

			ImGui::EndChild();
			ImGui::Unindent(12.f);
			ImGui::EndChild();
		}

	}

	void render(float vw, float vh, float accumulated_time) {
		const bool stack_main_panes = vw < 620.f;
		const float top_bar_h = stack_main_panes ? 76.f : 58.f;
		const float gap = 8.f;

		ImVec2 origin_top = ImGui::GetCursorPos();
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp_top = ImGui::GetCursorScreenPos();
		dl->AddRectFilled(wp_top,
			ImVec2(wp_top.x + vw, wp_top.y + top_bar_h),
			aida::ui::with_alpha(t.panel_bg, 0.55f), 6.f);

		ImGui::Dummy(ImVec2(0.f, 4.f));
		ImGui::Indent(10.f);

		bool running = g_run_all_active.load(std::memory_order_acquire);
		if (running) ImGui::BeginDisabled();
		const float run_button_w = std::min(180.f, std::max(136.f, vw - 24.f));
		if (ImGui::Button("Run All Safe Tests", ImVec2(run_button_w, 26.f))) {
			start_run_all_safe();
		}
		if (running) ImGui::EndDisabled();

		std::string status_copy;
		std::string current_name_copy;
		{
			static std::string s_last_status_copy;
			static std::string s_last_current_name_copy;
			std::unique_lock<std::mutex> lk(g_run_all_status_mtx, std::try_to_lock);
			if (lk.owns_lock()) {
				status_copy = g_run_all_status_line;
				current_name_copy = g_run_all_current_name;
				s_last_status_copy = status_copy;
				s_last_current_name_copy = current_name_copy;
			} else {
				log_render_lock_busy("top_status", "g_run_all_status_mtx");
				status_copy = s_last_status_copy;
				current_name_copy = s_last_current_name_copy;
			}
		}

		char run_status_buf[768];
		if (running) {
			std::snprintf(run_status_buf, sizeof(run_status_buf),
				"Running %d / %d  (%s)   pass=%d fail=%d skip=%d",
				g_run_all_current.load(std::memory_order_acquire),
				g_run_all_total.load(std::memory_order_acquire),
				current_name_copy.c_str(),
				g_run_all_ok.load(std::memory_order_acquire),
				g_run_all_fail.load(std::memory_order_acquire),
				g_run_all_skipped.load(std::memory_order_acquire));
		}
		else if (!status_copy.empty()) {
			std::snprintf(run_status_buf, sizeof(run_status_buf), "%s", status_copy.c_str());
		}
		else {
			std::snprintf(run_status_buf, sizeof(run_status_buf), "Evidence log: %s", run_all_log_path());
		}
		const ImGuiStyle& style = ImGui::GetStyle();
		if (ImGui::GetItemRectMax().x + style.ItemSpacing.x + 160.f <= wp_top.x + vw - 12.f) {
			ImGui::SameLine();
		}
		render_clipped_cell("##testlab_run_status", std::string(run_status_buf), t.text_dim);

		ImGui::Dummy(ImVec2(0.f, 3.f));
		int total = g_run_all_total.load(std::memory_order_acquire);
		int current = g_run_all_current.load(std::memory_order_acquire);
		float progress = (total > 0) ? (static_cast<float>(current) / static_cast<float>(total)) : 0.f;
		if (!running && !status_copy.empty() && total > 0)
			progress = 1.f;
		ImGui::PushStyleColor(ImGuiCol_PlotHistogram, running ? t.accent_u32 :
			(g_run_all_fail.load(std::memory_order_acquire) > 0 ? t.error : t.success));
		float progress_w = ImGui::GetContentRegionAvail().x;
		if (progress_w < 120.f) progress_w = 120.f;
		ImGui::ProgressBar(progress, ImVec2(progress_w, 6.f), "");
		ImGui::PopStyleColor();
		ImGui::Unindent(10.f);

		ImGui::SetCursorPos(ImVec2(origin_top.x, origin_top.y + top_bar_h + gap));

		const float left_pane_w = 280.f;
		float right_pane_w = vw - left_pane_w - gap;
		if (right_pane_w < 200.f) right_pane_w = 200.f;
		float remaining_h = vh - top_bar_h - gap;
		if (remaining_h < 100.f) remaining_h = 100.f;

		ImVec2 origin = ImGui::GetCursorPos();
		if (stack_main_panes) {
			float left_h = std::min(220.f, std::max(128.f, remaining_h * 0.38f));
			if (remaining_h - left_h - gap < 150.f)
				left_h = std::max(92.f, remaining_h - gap - 150.f);
			float right_h = std::max(120.f, remaining_h - left_h - gap);
			render_left_pane(vw, left_h, accumulated_time);
			ImGui::SetCursorPos(ImVec2(origin.x, origin.y + left_h + gap));
			render_right_pane(vw, right_h);
		} else {
			render_left_pane(left_pane_w, remaining_h, accumulated_time);
			ImGui::SetCursorPos(ImVec2(origin.x + left_pane_w + gap, origin.y));
			render_right_pane(right_pane_w, remaining_h);
		}
	}

}
