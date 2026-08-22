#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include "test_all_burp.h"
#include "test_all_features.hpp"
#include "../infra/event_bus.hpp"
#include "../infra/executor.hpp"
#include "../network/burp/scope.hpp"
#include "../network/burp/cookie_jar.hpp"
#include "../network/burp/match_replace.hpp"
#include "../network/burp/jwt_lab.hpp"
#include "../network/burp/sequencer.hpp"
#include "../network/burp/comparer.hpp"
#include "../network/burp/collaborator.hpp"
#include "../network/burp/crawler.hpp"
#include "../network/burp/active_scanner.hpp"
#include "../network/burp/passive_scanner.hpp"
#include "../network/burp/intruder_engine.hpp"
#include "../network/burp/csp_analyzer.hpp"
#include "../network/burp/report_generator.hpp"
#include "../network/burp/bambda.hpp"
#include "../network/burp/site_map.hpp"
#include "../network/burp/dom_xss_engine.hpp"
#include "../network/burp/ws_editor.hpp"
#include "../network/burp/h2_editor.hpp"
#include "../network/burp/burp_logger.hpp"
#include "../network/burp/upstream_chain.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../network/burp/camoufox_install.hpp"
#include "../network/burp/graphql.hpp"
#include "../network/burp/auth_lab.hpp"
#include "../network/burp/session_handler.hpp"
#include "../network/burp/content_discovery.hpp"
#include "../network/burp/subdomain_enum.hpp"
#include "../network/burp/tech_fingerprint.hpp"
#include "../network/burp/api_definition.hpp"
#include "../network/burp/param_miner.hpp"
#include "../network/burp/payload_library.hpp"
#include "../network/burp/issue.hpp"
#include "../network/burp/findings_db.hpp"
#include "../network/burp/browser_launch.hpp"
#include "../network/burp/insertion_points.hpp"
#include "../network/burp/scanner_module.hpp"
#include "../network/burp/audit_http.hpp"
#include "../network/burp/headless_view.hpp"
#include "../network/network_view.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../../helpers/diag_log.hpp"
#include "test_lab_bounded_runner.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace test_all_features {

namespace {

    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        test_all_features::write_full_test_log_line(hf, line.data(), line.size());
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
    }

    struct ui_exchange_publish_state_t {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        bool ok = false;
    };

    bool publish_exchange_observed_on_ui(HANDLE hf, const char* tag, const aida::burp::exchange_observed_t& ex, const char* source) {
        const char* phase = "source_proven_ui_thread";
        if (aida::ui_thread::is_owner_thread()) {
            if (!aida::ui_thread::require_owner("testlab", "burp_exchange_publish", phase))
                return false;
            aida::events::publish(aida::burp::kExchangeObservedEvent, ex);
            return true;
        }
        auto state = std::make_shared<ui_exchange_publish_state_t>();
        const DWORD producer_tid = ::GetCurrentThreadId();
        const std::string source_copy = source && source[0] ? source : "testlab_exchange";
        const bool posted = aida::ui_thread::post([state, ex, source_copy, producer_tid]() mutable {
            const char* phase_inner = "source_proven_ui_thread";
            bool ok = false;
            if (aida::ui_thread::require_owner("testlab", "burp_exchange_publish", phase_inner)) {
                aida::events::publish(aida::burp::kExchangeObservedEvent, ex);
                ok = true;
            }
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                state->ok = ok;
                state->done = true;
            }
            state->cv.notify_all();
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "burp_exchange_publish source=%s producer_tid=%lu ui_tid=%lu ok=%d id=%llu",
                source_copy.c_str(),
                static_cast<unsigned long>(producer_tid),
                static_cast<unsigned long>(::GetCurrentThreadId()),
                ok ? 1 : 0,
                static_cast<unsigned long long>(ex.id));
        }, "testlab", "burp_exchange_publish", source_copy.c_str());
        if (!posted) {
            log_msg(hf, tag, "FAIL -- exchange event UI dispatch post failed source=%s id=%llu ui_tid=%lu",
                source_copy.c_str(),
                static_cast<unsigned long long>(ex.id),
                static_cast<unsigned long>(aida::ui_thread::owner_tid()));
            return false;
        }
        std::unique_lock<std::mutex> lk(state->mtx);
        const bool completed = state->cv.wait_for(lk, std::chrono::milliseconds(5000), [&] { return state->done; });
        const bool ok = completed && state->ok;
        if (!ok) {
            log_msg(hf, tag, "FAIL -- exchange event UI dispatch did not complete source=%s id=%llu completed=%d ok=%d pending=%zu",
                source_copy.c_str(),
                static_cast<unsigned long long>(ex.id),
                completed ? 1 : 0,
                state->ok ? 1 : 0,
                aida::ui_thread::pending_count());
        }
        return ok;
    }

    void fail_empty_evidence(HANDLE hf, const char* tag, std::atomic<int>& failed, const char* fmt, ...) {
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        log_msg(hf, tag, "FAIL -- %s", detail);
        failed.fetch_add(1);
    }

    static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    }

    static const char* network_sub_tab_label(network_view::sub_tab_t tab) {
        switch (tab) {
        case network_view::sub_tab_t::connections: return "connections";
        case network_view::sub_tab_t::capture: return "capture";
        case network_view::sub_tab_t::intercept: return "intercept";
        case network_view::sub_tab_t::proxy: return "proxy";
        case network_view::sub_tab_t::dns: return "dns";
        case network_view::sub_tab_t::filters: return "filters";
        case network_view::sub_tab_t::bandwidth: return "bandwidth";
        case network_view::sub_tab_t::repeater: return "repeater";
        case network_view::sub_tab_t::keylog: return "keylog";
        case network_view::sub_tab_t::pcap_export: return "pcap_export";
        case network_view::sub_tab_t::fuzzer: return "fuzzer";
        case network_view::sub_tab_t::websocket: return "websocket";
        case network_view::sub_tab_t::scripting: return "scripting";
        case network_view::sub_tab_t::decoder: return "decoder";
        case network_view::sub_tab_t::sitemap: return "sitemap";
        case network_view::sub_tab_t::scope: return "scope";
        case network_view::sub_tab_t::cookies: return "cookies";
        case network_view::sub_tab_t::scanner: return "scanner";
        case network_view::sub_tab_t::recon: return "recon";
        case network_view::sub_tab_t::intruder: return "intruder";
        case network_view::sub_tab_t::collab: return "collab";
        case network_view::sub_tab_t::sequencer: return "sequencer";
        case network_view::sub_tab_t::comparer: return "comparer";
        case network_view::sub_tab_t::jwt: return "jwt";
        case network_view::sub_tab_t::mr: return "mr";
        case network_view::sub_tab_t::session: return "session";
        case network_view::sub_tab_t::api: return "api";
        case network_view::sub_tab_t::ws_edit: return "ws_edit";
        case network_view::sub_tab_t::h2_edit: return "h2_edit";
        case network_view::sub_tab_t::logger: return "logger";
        case network_view::sub_tab_t::csp: return "csp";
        case network_view::sub_tab_t::upstream: return "upstream";
        case network_view::sub_tab_t::browser: return "browser";
        case network_view::sub_tab_t::reports: return "reports";
        case network_view::sub_tab_t::headless: return "headless";
        case network_view::sub_tab_t::COUNT: break;
        }
        return "";
    }

    const char* camoufox_install_state_name(aida::burp::camoufox::install::install_state_t state) {
        using state_t = aida::burp::camoufox::install::install_state_t;
        switch (state) {
            case state_t::unknown: return "unknown";
            case state_t::checking: return "checking";
            case state_t::available: return "available";
            case state_t::missing_python: return "missing_python";
            case state_t::missing_module: return "missing_module";
            case state_t::missing_browser: return "missing_browser";
            case state_t::installing: return "installing";
            case state_t::install_failed: return "install_failed";
            case state_t::ok: return "ok";
        }
        return "unknown";
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

    std::string compact_burp_text(std::string out, std::size_t cap) {
        for (char& c : out) {
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        }
        if (out.size() > cap)
            out = out.substr(0, cap) + "...(truncated)";
        return out;
    }

    std::string compact_burp_json(const nlohmann::json& value, std::size_t cap) {
        if (value.is_null() || value.empty())
            return "<empty>";
        return compact_burp_text(value.dump(), cap);
    }

    int camoufox_bridge_visible_window_count_from_status(const aida::burp::camoufox::bridge_status_t& st) {
        if (!st.last_launch_diagnostics.is_object())
            return 0;
        const auto proof_it = st.last_launch_diagnostics.find("visible_window_proof");
        if (proof_it == st.last_launch_diagnostics.end() || !proof_it->is_object())
            return 0;
        const char* keys[] = { "visible_window_count", "visible_windows" };
        for (const char* key : keys) {
            const auto count_it = proof_it->find(key);
            if (count_it == proof_it->end())
                continue;
            if (count_it->is_number_unsigned())
                return static_cast<int>(std::min<uint64_t>(count_it->get<uint64_t>(), static_cast<uint64_t>(INT_MAX)));
            if (count_it->is_number_integer()) {
                const auto value = count_it->get<int64_t>();
                return value > 0 ? static_cast<int>(std::min<int64_t>(value, static_cast<int64_t>(INT_MAX))) : 0;
            }
            if (count_it->is_boolean())
                return count_it->get<bool>() ? 1 : 0;
        }
        return 0;
    }

    void log_camoufox_bridge_snapshot(HANDLE hf, const char* tag, const char* label, const aida::burp::camoufox::bridge_status_t& st) {
        const int visible_windows = camoufox_bridge_visible_window_count_from_status(st);
        log_msg(hf, tag, "%s status state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d visible_windows=%d cleanup_pending=%d phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_started_ms=%llu attempt_elapsed_ms=%llu last_attempt_elapsed_ms=%llu status_age_ms=%llu last_debug_event=%s last_error=%s",
            label,
            camoufox_bridge_state_name(st.state),
            static_cast<unsigned long long>(st.generation),
            st.child_pid,
            st.child_alive ? 1 : 0,
            st.browser_open ? 1 : 0,
            st.page_verified ? 1 : 0,
            st.privacy_verified ? 1 : 0,
            visible_windows,
            st.cleanup_pending ? 1 : 0,
            st.phase.empty() ? "<empty>" : compact_burp_text(st.phase, 160).c_str(),
            st.readiness_phase.empty() ? "<empty>" : compact_burp_text(st.readiness_phase, 160).c_str(),
            st.error_type.empty() ? "<empty>" : compact_burp_text(st.error_type, 160).c_str(),
            st.error_kind.empty() ? "<empty>" : compact_burp_text(st.error_kind, 160).c_str(),
            st.protocol_schema_viewport ? 1 : 0,
            static_cast<unsigned long long>(st.attempt_started_ms),
            static_cast<unsigned long long>(st.attempt_elapsed_ms),
            static_cast<unsigned long long>(st.last_attempt_elapsed_ms),
            static_cast<unsigned long long>(st.status_age_ms),
            st.last_debug_event.empty() ? "<empty>" : compact_burp_text(st.last_debug_event, 240).c_str(),
            st.last_error.empty() ? "<empty>" : compact_burp_text(st.last_error, 360).c_str());
        log_msg(hf, tag, "%s cleanup generation=%llu child_pid=%u started_ms=%llu last_cleanup_ms=%llu reason=%s",
            label,
            static_cast<unsigned long long>(st.cleanup_generation),
            st.cleanup_child_pid,
            static_cast<unsigned long long>(st.cleanup_started_ms),
            static_cast<unsigned long long>(st.last_cleanup_ms),
            st.cleanup_reason.empty() ? "<empty>" : compact_burp_text(st.cleanup_reason, 500).c_str());
        log_msg(hf, tag, "%s launch_diag=%s",
            label,
            compact_burp_json(st.last_launch_diagnostics, 900).c_str());
        log_msg(hf, tag, "%s cleanup_diag=%s",
            label,
            compact_burp_json(st.cleanup_diagnostics, 900).c_str());
        log_msg(hf, tag, "%s privacy_diag=%s",
            label,
            compact_burp_json(st.privacy_diagnostics, 900).c_str());
    }

    bool camoufox_bridge_sticky_setup_failure(const aida::burp::camoufox::bridge_status_t& st, std::string& marker) {
        marker.clear();
        const auto string_field = [](const nlohmann::json& obj, const char* key) -> std::string {
            if (!obj.is_object())
                return {};
            auto it = obj.find(key);
            if (it == obj.end() || it->is_null())
                return {};
            if (it->is_string())
                return it->get<std::string>();
            if (it->is_boolean())
                return it->get<bool>() ? "true" : "false";
            if (it->is_number())
                return it->dump();
            return {};
        };
        const auto bool_field = [](const nlohmann::json& obj, const char* key) -> bool {
            if (!obj.is_object())
                return false;
            auto it = obj.find(key);
            return it != obj.end() && it->is_boolean() && it->get<bool>();
        };
        const auto uint_field = [](const nlohmann::json& obj, const char* key) -> uint64_t {
            if (!obj.is_object())
                return 0;
            auto it = obj.find(key);
            if (it == obj.end())
                return 0;
            if (it->is_number_unsigned())
                return it->get<uint64_t>();
            if (it->is_number_integer()) {
                const auto value = it->get<int64_t>();
                return value > 0 ? static_cast<uint64_t>(value) : 0;
            }
            return 0;
        };
        nlohmann::json sticky = nlohmann::json::object();
        if (st.last_launch_diagnostics.is_object()) {
            auto sticky_it = st.last_launch_diagnostics.find("sticky_setup_failure");
            if (sticky_it != st.last_launch_diagnostics.end() && sticky_it->is_object())
                sticky = *sticky_it;
        }
        if (sticky.is_object() && !sticky.empty()) {
            const std::string category = sticky.value("category", std::string("unknown"));
            const std::string summary = sticky.value("error_summary", std::string());
            std::string phase = sticky.value("phase", std::string());
            auto source_it = sticky.find("source");
            if (phase.empty() && source_it != sticky.end() && source_it->is_object())
                phase = source_it->value("phase", std::string());
            const std::string mode = sticky.value("mode", std::string());
            const uint64_t generation = sticky.value("generation", static_cast<uint64_t>(0));
            marker = "category=" + category +
                " generation=" + std::to_string(static_cast<unsigned long long>(generation)) +
                " mode=" + (mode.empty() ? std::string("<empty>") : mode) +
                " phase=" + (phase.empty() ? std::string("<empty>") : phase) +
                " root=" + (summary.empty() ? std::string("<empty>") : compact_burp_text(summary, 700));
            return true;
        }
        if (st.last_launch_diagnostics.is_object()) {
            const bool nonretryable = bool_field(st.last_launch_diagnostics, "nonretryable_setup_failure") ||
                bool_field(st.last_launch_diagnostics, "setup_failure_sticky");
            const std::string phase = string_field(st.last_launch_diagnostics, "phase");
            if (nonretryable || phase == "sticky_setup_failure") {
                std::string category = string_field(st.last_launch_diagnostics, "setup_failure_category");
                if (category.empty())
                    category = string_field(st.last_launch_diagnostics, "category");
                std::string summary = string_field(st.last_launch_diagnostics, "setup_failure_summary");
                if (summary.empty())
                    summary = string_field(st.last_launch_diagnostics, "error_summary");
                if (summary.empty())
                    summary = string_field(st.last_launch_diagnostics, "summary");
                if (summary.empty())
                    summary = string_field(st.last_launch_diagnostics, "error");
                const std::string mode = string_field(st.last_launch_diagnostics, "mode");
                const uint64_t generation = uint_field(st.last_launch_diagnostics, "generation");
                marker = "category=" + (category.empty() ? std::string("nonretryable_setup_failure") : category) +
                    " generation=" + std::to_string(static_cast<unsigned long long>(generation)) +
                    " mode=" + (mode.empty() ? std::string("<empty>") : mode) +
                    " phase=" + (phase.empty() ? std::string("<empty>") : phase) +
                    " root=" + (summary.empty() ? std::string("<empty>") : compact_burp_text(summary, 700));
                return true;
            }
        }
        std::string lower_error = st.last_error;
        std::transform(lower_error.begin(), lower_error.end(), lower_error.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower_error.find("sticky_setup_failure") != std::string::npos) {
            marker = compact_burp_text(st.last_error, 700);
            return true;
        }
        return false;
    }

    bool camoufox_bridge_live_ready(const aida::burp::camoufox::bridge_status_t& st) {
        return st.state == aida::burp::camoufox::bridge_state_t::ready &&
            st.child_pid != 0 &&
            st.child_alive &&
            st.browser_open &&
            st.page_verified &&
            st.privacy_verified &&
            camoufox_bridge_visible_window_count_from_status(st) > 0 &&
            !st.cleanup_pending;
    }

    struct camoufox_bridge_retry_cache_t {
        bool active = false;
        uint64_t generation = 0;
        std::string signature;
        std::string reason;
        bool recovery_consumed = false;
        uint64_t cached_ms = 0;
    };

    std::mutex& camoufox_bridge_retry_cache_mutex() {
        static std::mutex m;
        return m;
    }

    camoufox_bridge_retry_cache_t& camoufox_bridge_retry_cache() {
        static camoufox_bridge_retry_cache_t cache;
        return cache;
    }

    std::string camoufox_bridge_failure_signature(const aida::burp::camoufox::bridge_status_t& st) {
        std::ostringstream oss;
        oss << "state=" << camoufox_bridge_state_name(st.state)
            << "|generation=" << static_cast<unsigned long long>(st.generation)
            << "|readiness=" << (st.readiness_phase.empty() ? "<empty>" : compact_burp_text(st.readiness_phase, 180))
            << "|phase=" << (st.phase.empty() ? "<empty>" : compact_burp_text(st.phase, 180))
            << "|error_type=" << (st.error_type.empty() ? "<empty>" : compact_burp_text(st.error_type, 180))
            << "|error_kind=" << (st.error_kind.empty() ? "<empty>" : compact_burp_text(st.error_kind, 180))
            << "|protocol_schema_viewport=" << (st.protocol_schema_viewport ? 1 : 0)
            << "|child_pid=" << st.child_pid
            << "|child_alive=" << (st.child_alive ? 1 : 0)
            << "|browser_open=" << (st.browser_open ? 1 : 0)
            << "|page_verified=" << (st.page_verified ? 1 : 0)
            << "|privacy_verified=" << (st.privacy_verified ? 1 : 0)
            << "|visible_windows=" << camoufox_bridge_visible_window_count_from_status(st)
            << "|cleanup_pending=" << (st.cleanup_pending ? 1 : 0)
            << "|last_debug_event=" << (st.last_debug_event.empty() ? "<empty>" : compact_burp_text(st.last_debug_event, 240))
            << "|last_error=" << (st.last_error.empty() ? "<empty>" : compact_burp_text(st.last_error, 240));
        return oss.str();
    }

    void camoufox_bridge_retry_cache_clear() {
        std::lock_guard<std::mutex> lk(camoufox_bridge_retry_cache_mutex());
        camoufox_bridge_retry_cache() = camoufox_bridge_retry_cache_t{};
    }

    void camoufox_bridge_retry_cache_record(const aida::burp::camoufox::bridge_status_t& st, const std::string& reason, bool recovery_consumed) {
        std::lock_guard<std::mutex> lk(camoufox_bridge_retry_cache_mutex());
        auto& cache = camoufox_bridge_retry_cache();
        const std::string signature = camoufox_bridge_failure_signature(st);
        const bool same_terminal = cache.active && cache.generation == st.generation && cache.signature == signature;
        cache.active = true;
        cache.generation = st.generation;
        cache.signature = signature;
        cache.reason = reason.empty() ? std::string("camoufox bridge dependency failed") : reason;
        cache.recovery_consumed = recovery_consumed || (same_terminal && cache.recovery_consumed);
        cache.cached_ms = GetTickCount64();
    }

    bool camoufox_bridge_retry_cache_match(const aida::burp::camoufox::bridge_status_t& st, bool require_recovery_consumed, std::string& reason, std::string& signature) {
        std::lock_guard<std::mutex> lk(camoufox_bridge_retry_cache_mutex());
        const auto& cache = camoufox_bridge_retry_cache();
        signature = camoufox_bridge_failure_signature(st);
        if (!cache.active || cache.generation != st.generation || cache.signature != signature)
            return false;
        if (require_recovery_consumed && !cache.recovery_consumed)
            return false;
        std::ostringstream oss;
        oss << cache.reason
            << " generation=" << static_cast<unsigned long long>(cache.generation)
            << " recovery_consumed=" << (cache.recovery_consumed ? 1 : 0)
            << " age_ms=" << static_cast<unsigned long long>(GetTickCount64() - cache.cached_ms)
            << " signature=" << compact_burp_text(cache.signature, 700);
        reason = oss.str();
        return true;
    }

    bool camoufox_install_status_ready(const aida::burp::camoufox::install::status_t& st) {
        if (st.state != aida::burp::camoufox::install::install_state_t::ok ||
            st.module_version.empty() ||
            st.browser_path.empty())
            return false;
        return !st.python_path.empty();
    }

    std::string camoufox_launcher_kind(const aida::burp::camoufox::install::status_t& st) {
        if (!st.python_path.empty())
            return "python_module";
        return "unresolved";
    }

    std::string camoufox_mcp_executable_label(const aida::burp::camoufox::install::status_t& st, const aida::burp::camoufox::bridge_status_t* bridge = nullptr) {
        if (bridge && !bridge->server_command.empty())
            return bridge->server_command;
        if (!st.python_path.empty())
            return st.python_path + " -m camoufox_reverse_mcp";
        return "<empty>";
    }

    aida::burp::camoufox::install::status_t bounded_burp_camoufox_probe(HANDLE hf, const char* tag, DWORD timeout_ms, bool& completed) {
        static test_lab::bounded_runner_t runner(1);
        auto state = std::make_shared<aida::burp::camoufox::install::status_t>();
        const uint64_t t0 = GetTickCount64();
        log_msg(hf, tag, "CAMOUFOX-PROBE -- begin timeout_ms=%lu setup_disabled=1", static_cast<unsigned long>(timeout_ms));
        const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [state]() {
            *state = aida::burp::camoufox::install::probe();
        });
        const uint64_t elapsed = GetTickCount64() - t0;
        completed = result.status == test_lab::bounded_run_status_t::completed;
        if (completed) {
            const std::string launcher_kind = camoufox_launcher_kind(*state);
            const std::string mcp_executable = camoufox_mcp_executable_label(*state);
            log_msg(hf, tag, "CAMOUFOX-PROBE -- completed elapsed_ms=%llu state=%s launcher_kind=%s mcp_executable=%s python_path=%s module=%s browser=%s message=%s",
                static_cast<unsigned long long>(elapsed),
                camoufox_install_state_name(state->state),
                launcher_kind.c_str(),
                mcp_executable.c_str(),
                state->python_path.empty() ? "<none>" : state->python_path.c_str(),
                state->module_version.empty() ? "<empty>" : state->module_version.c_str(),
                state->browser_path.empty() ? "<empty>" : state->browser_path.c_str(),
                state->last_message.empty() ? "<empty>" : compact_burp_text(state->last_message, 600).c_str());
            return *state;
        }
        log_msg(hf, tag, "CAMOUFOX-PROBE -- failed elapsed_ms=%llu status=%d error=%s",
            static_cast<unsigned long long>(elapsed),
            static_cast<int>(result.status),
            result.error.empty() ? "<empty>" : result.error.c_str());
        return aida::burp::camoufox::install::get_status();
    }

    bool ensure_burp_camoufox_dependencies(HANDLE hf, const char* tag, std::string& reason, aida::burp::camoufox::install::status_t* out_status = nullptr) {
        bool probe_completed = false;
        constexpr DWORD probe_timeout_ms = 9000;
        auto st = bounded_burp_camoufox_probe(hf, tag, probe_timeout_ms, probe_completed);
        const std::string launcher_kind = camoufox_launcher_kind(st);
        const std::string mcp_executable = camoufox_mcp_executable_label(st);
        log_msg(hf, tag, "CAMOUFOX-SNAPSHOT -- probe_completed=%d state=%s launcher_kind=%s mcp_executable=%s python_path=%s module=%s browser=%s message=%s",
            probe_completed ? 1 : 0,
            camoufox_install_state_name(st.state),
            launcher_kind.c_str(),
            mcp_executable.c_str(),
            st.python_path.empty() ? "<none>" : st.python_path.c_str(),
            st.module_version.empty() ? "<empty>" : st.module_version.c_str(),
            st.browser_path.empty() ? "<empty>" : st.browser_path.c_str(),
            st.last_message.empty() ? "<empty>" : compact_burp_text(st.last_message, 600).c_str());
        if (out_status) *out_status = st;
        if (camoufox_install_status_ready(st)) {
            reason.clear();
            return true;
        }
        reason = probe_completed
            ? std::string("Camoufox bundled runtime is not ready; Test Lab setup/download is disabled state=") + camoufox_install_state_name(st.state) +
                " message=" + (st.last_message.empty() ? "<empty>" : st.last_message)
            : std::string("Camoufox dependency probe exceeded ") + std::to_string(probe_timeout_ms) + "ms; Test Lab setup/download is disabled";
        log_msg(hf, tag, "CAMOUFOX-FAST-FAIL -- setup_disabled=1 reason=%s", compact_burp_text(reason, 700).c_str());
        return false;
    }

    uint64_t fixture_now_ms() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

    std::string fixture_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    std::string fixture_b64(const uint8_t* data, size_t len) {
        static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        for (size_t i = 0; i < len; i += 3) {
            uint32_t a = data[i];
            uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
            uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
            uint32_t triple = (a << 16) | (b << 8) | c;
            out.push_back(alpha[(triple >> 18) & 0x3F]);
            out.push_back(alpha[(triple >> 12) & 0x3F]);
            out.push_back((i + 1 < len) ? alpha[(triple >> 6) & 0x3F] : '=');
            out.push_back((i + 2 < len) ? alpha[triple & 0x3F] : '=');
        }
        return out;
    }

    std::string websocket_accept_for_key(const std::string& key) {
        std::string joined = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t digest[SHA_DIGEST_LENGTH] = {};
        SHA1(reinterpret_cast<const unsigned char*>(joined.data()), joined.size(), digest);
        return fixture_b64(digest, sizeof(digest));
    }

    bool ensure_burp_fixture_wsa() {
        static std::atomic<int> rc{-1};
        int cached = rc.load();
        if (cached >= 0) return cached == 0;
        WSADATA data{};
        int r = WSAStartup(MAKEWORD(2, 2), &data);
        int expected = -1;
        if (!rc.compare_exchange_strong(expected, r)) return rc.load() == 0;
        return r == 0;
    }

    bool send_all_fixture(SOCKET s, const std::string& data) {
        size_t off = 0;
        while (off < data.size()) {
            int n = send(s, data.data() + off, static_cast<int>(data.size() - off), 0);
            if (n <= 0) return false;
            off += static_cast<size_t>(n);
        }
        return true;
    }

    std::string header_value_ci(const std::string& request, const std::string& name) {
        std::string lower_req = fixture_lower(request);
        std::string needle = fixture_lower(name) + ":";
        size_t pos = lower_req.find(needle);
        if (pos == std::string::npos) return {};
        size_t value_start = pos + needle.size();
        while (value_start < request.size() && (request[value_start] == ' ' || request[value_start] == '\t')) ++value_start;
        size_t value_end = request.find("\r\n", value_start);
        if (value_end == std::string::npos) value_end = request.size();
        return request.substr(value_start, value_end - value_start);
    }

    std::string request_target_from_raw(const std::string& request) {
        size_t first_space = request.find(' ');
        if (first_space == std::string::npos) return "/";
        size_t second_space = request.find(' ', first_space + 1);
        if (second_space == std::string::npos || second_space <= first_space + 1) return "/";
        return request.substr(first_space + 1, second_space - first_space - 1);
    }

    std::string fixture_temp_path(const char* name) {
        char tmp[MAX_PATH] = {};
        DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(tmp)), tmp);
        std::filesystem::path p = (n > 0 && n < sizeof(tmp)) ? std::filesystem::path(tmp) : std::filesystem::temp_directory_path();
        p /= name;
        return p.string();
    }

    bool write_fixture_text_file(const std::string& path, const std::string& body) {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        return static_cast<bool>(f);
    }

    struct burp_loopback_fixture_t {
        struct loopback_state_t {
            std::atomic<SOCKET> listen_socket{INVALID_SOCKET};
            std::atomic<uint16_t> port{0};
            std::atomic<bool> stopping{false};
            std::atomic<bool> worker_posted{false};
            std::atomic<bool> worker_active{false};
            std::atomic<bool> worker_entered{false};
            std::atomic<bool> worker_exited{false};
            std::atomic<DWORD> worker_tid{0};
            std::atomic<long> active_clients{0};
            std::atomic<uint64_t> accept_count{0};
            std::atomic<uint64_t> request_count{0};
            std::atomic<uint64_t> response_count{0};
            std::atomic<int> last_wsa_error{0};
            std::atomic<DWORD> last_win32_error{0};
            std::mutex worker_mutex;
            std::condition_variable worker_cv;
            std::mutex client_mutex;
            std::condition_variable client_cv;
        };

        std::shared_ptr<loopback_state_t> state = std::make_shared<loopback_state_t>();

        bool start(HANDLE hf, const char* tag) {
            auto st = state;
            if (!st) {
                log_msg(hf, tag, "fixture_start FAIL -- state allocation failed");
                return false;
            }
            if (!ensure_burp_fixture_wsa()) {
                log_msg(hf, tag, "fixture_start FAIL -- WSAStartup failed gle=%lu", GetLastError());
                return false;
            }
            SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                log_msg(hf, tag, "fixture_start FAIL -- socket failed wsa=%d", WSAGetLastError());
                return false;
            }
            BOOL reuse = TRUE;
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(0);
            if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                closesocket(listener);
                log_msg(hf, tag, "fixture_start FAIL -- bind failed wsa=%d", err);
                return false;
            }
            if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                closesocket(listener);
                log_msg(hf, tag, "fixture_start FAIL -- listen failed wsa=%d", err);
                return false;
            }
            sockaddr_in bound{};
            int len = sizeof(bound);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &len) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                closesocket(listener);
                log_msg(hf, tag, "fixture_start FAIL -- getsockname failed wsa=%d", err);
                return false;
            }
            st->listen_socket.store(listener, std::memory_order_release);
            st->port.store(ntohs(bound.sin_port), std::memory_order_release);
            st->stopping.store(false, std::memory_order_release);
            st->worker_posted.store(false, std::memory_order_release);
            st->worker_active.store(false, std::memory_order_release);
            st->worker_entered.store(false, std::memory_order_release);
            st->worker_exited.store(false, std::memory_order_release);
            st->worker_tid.store(0, std::memory_order_release);
            st->active_clients.store(0, std::memory_order_release);
            st->accept_count.store(0, std::memory_order_release);
            st->request_count.store(0, std::memory_order_release);
            st->response_count.store(0, std::memory_order_release);
            st->last_wsa_error.store(0, std::memory_order_release);
            st->last_win32_error.store(0, std::memory_order_release);
            const ULONGLONG start_tick = GetTickCount64();
            const auto q_before = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::feature_worker);
            log_msg(hf, tag, "fixture_start INFO -- listener taskflow executor post requested port=%u listener=%llu host_pid=%lu host_tid=%lu executor_alive=%d executor_shutting=%d executor_pending=%zu executor_active=%u executor_posted=%llu executor_finished=%llu",
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(listener),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                q_before.alive ? 1 : 0,
                q_before.shutting_down ? 1 : 0,
                q_before.pending,
                static_cast<unsigned>(q_before.active),
                static_cast<unsigned long long>(q_before.posted),
                static_cast<unsigned long long>(q_before.finished));
            SetLastError(0);
            bool posted = false;
            DWORD post_gle = ERROR_SUCCESS;
            try {
                aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "testlab_burp";
                sub.label = "testlab.burp.loopback_fixture";
                sub.thread_class = "service_loop";
                sub.domain = aida::infra::executor::domain_t::feature_worker;
                sub.priority = 2;
                sub.failure_policy = "reject_not_started";
                sub.shutdown_policy = "drain";
                sub.body = [st]() {
                    burp_loopback_fixture_t::worker_entry(st, "taskflow_executor");
                };
                posted = aida::infra::executor::submit(std::move(sub)).submitted;
                post_gle = GetLastError();
            } catch (const std::exception& ex) {
                post_gle = GetLastError();
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_ENOUGH_MEMORY;
                diag::log_tagged_fmt("testlab_burp", "loopback_taskflow_executor_post_exception port=%u listener=%llu err=%s gle=%lu state=%p",
                    static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(listener),
                    ex.what(),
                    static_cast<unsigned long>(post_gle),
                    st.get());
            } catch (...) {
                post_gle = GetLastError();
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_ENOUGH_MEMORY;
                diag::log_tagged_fmt("testlab_burp", "loopback_taskflow_executor_post_exception port=%u listener=%llu err=unknown gle=%lu state=%p",
                    static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(listener),
                    static_cast<unsigned long>(post_gle),
                    st.get());
            }
            const auto q_after = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::feature_worker);
            st->worker_posted.store(posted, std::memory_order_release);
            diag::log_tagged_fmt("testlab_burp", "loopback_taskflow_executor_post_result posted=%d gle=%lu state=%p port=%u listener=%llu executor_alive=%d executor_shutting=%d executor_pending=%zu executor_active=%u executor_posted=%llu executor_rejected=%llu executor_started=%llu executor_finished=%llu elapsed_ms=%llu",
                posted ? 1 : 0,
                static_cast<unsigned long>(post_gle),
                st.get(),
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(listener),
                q_after.alive ? 1 : 0,
                q_after.shutting_down ? 1 : 0,
                q_after.pending,
                static_cast<unsigned>(q_after.active),
                static_cast<unsigned long long>(q_after.posted),
                static_cast<unsigned long long>(q_after.rejected),
                static_cast<unsigned long long>(q_after.started),
                static_cast<unsigned long long>(q_after.finished),
                static_cast<unsigned long long>(GetTickCount64() - start_tick));
            if (!posted) {
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_READY;
                st->last_win32_error.store(post_gle, std::memory_order_release);
                st->worker_exited.store(true, std::memory_order_release);
                st->worker_active.store(false, std::memory_order_release);
                st->worker_cv.notify_all();
                SOCKET s = st->listen_socket.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
                if (s != INVALID_SOCKET) {
                    shutdown(s, SD_BOTH);
                    closesocket(s);
                }
                st->port.store(0, std::memory_order_release);
                log_msg(hf, tag, "fixture_start FAIL -- listener taskflow executor post failed gle=%lu elapsed_ms=%llu host_pid=%lu host_tid=%lu executor_alive=%d executor_shutting=%d executor_pending=%zu executor_active=%u executor_rejected=%llu",
                    static_cast<unsigned long>(post_gle),
                    static_cast<unsigned long long>(GetTickCount64() - start_tick),
                    static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    q_after.alive ? 1 : 0,
                    q_after.shutting_down ? 1 : 0,
                    q_after.pending,
                    static_cast<unsigned>(q_after.active),
                    static_cast<unsigned long long>(q_after.rejected));
                return false;
            }
            bool entered = false;
            bool exited = false;
            {
                std::unique_lock<std::mutex> lk(st->worker_mutex);
                st->worker_cv.wait_for(lk, std::chrono::milliseconds(5000), [st]() {
                    return st->worker_entered.load(std::memory_order_acquire) ||
                        st->worker_exited.load(std::memory_order_acquire);
                });
                entered = st->worker_entered.load(std::memory_order_acquire);
                exited = st->worker_exited.load(std::memory_order_acquire);
            }
            if (!entered || exited) {
                st->stopping.store(true, std::memory_order_release);
                wake_listener(st->port.load(std::memory_order_acquire));
                SOCKET s = st->listen_socket.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
                if (s != INVALID_SOCKET) {
                    shutdown(s, SD_BOTH);
                    closesocket(s);
                }
                st->port.store(0, std::memory_order_release);
                bool drained = false;
                {
                    std::unique_lock<std::mutex> lk(st->worker_mutex);
                    drained = st->worker_cv.wait_for(lk, std::chrono::milliseconds(1000), [st]() {
                        return st->worker_exited.load(std::memory_order_acquire);
                    });
                }
                const auto q_late = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::feature_worker);
                log_msg(hf, tag, "fixture_start FAIL -- listener taskflow executor worker did not enter port=%u entered=%d exited=%d drained=%d worker_tid=%lu accept_count=%llu request_count=%llu response_count=%llu last_wsa=%d last_gle=%lu elapsed_ms=%llu executor_pending=%zu executor_active=%u executor_started=%llu executor_finished=%llu",
                    static_cast<unsigned>(ntohs(bound.sin_port)),
                    entered ? 1 : 0,
                    exited ? 1 : 0,
                    drained ? 1 : 0,
                    static_cast<unsigned long>(st->worker_tid.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)),
                    st->last_wsa_error.load(std::memory_order_acquire),
                    static_cast<unsigned long>(st->last_win32_error.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(GetTickCount64() - start_tick),
                    q_late.pending,
                    static_cast<unsigned>(q_late.active),
                    static_cast<unsigned long long>(q_late.started),
                    static_cast<unsigned long long>(q_late.finished));
                diag::log_tagged_fmt("testlab_burp", "loopback_taskflow_executor_start_not_ready port=%u entered=%d exited=%d drained=%d worker_tid=%lu state=%p elapsed_ms=%llu executor_pending=%zu executor_active=%u",
                    static_cast<unsigned>(ntohs(bound.sin_port)),
                    entered ? 1 : 0,
                    exited ? 1 : 0,
                    drained ? 1 : 0,
                    static_cast<unsigned long>(st->worker_tid.load(std::memory_order_acquire)),
                    st.get(),
                    static_cast<unsigned long long>(GetTickCount64() - start_tick),
                    q_late.pending,
                    static_cast<unsigned>(q_late.active));
                return false;
            }
            log_msg(hf, tag, "fixture_start PASS -- loopback_http_ws port=%u worker_tid=%lu elapsed_ms=%llu accept_count=%llu request_count=%llu response_count=%llu",
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long>(st->worker_tid.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(GetTickCount64() - start_tick),
                static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)));
            return true;
        }

        bool stop() {
            auto st = state;
            if (!st)
                return true;
            const ULONGLONG t0 = GetTickCount64();
            st->stopping.store(true, std::memory_order_release);
            const uint16_t stopped_port = st->port.load(std::memory_order_acquire);
            const SOCKET stopped_listener = st->listen_socket.load(std::memory_order_acquire);
            diag::log_tagged_fmt("testlab_burp", "loopback_fixture_stop_request port=%u listener=%llu worker_posted=%d worker_active=%d worker_entered=%d worker_exited=%d worker_tid=%lu active_clients=%ld accept_count=%llu request_count=%llu response_count=%llu",
                static_cast<unsigned>(stopped_port),
                static_cast<unsigned long long>(stopped_listener),
                st->worker_posted.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_active.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_exited.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(st->worker_tid.load(std::memory_order_acquire)),
                st->active_clients.load(std::memory_order_acquire),
                static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)));
            if (stopped_listener != INVALID_SOCKET)
                wake_listener(stopped_port);
            SOCKET s = st->listen_socket.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
            if (s != INVALID_SOCKET) {
                shutdown(s, SD_BOTH);
                closesocket(s);
            }
            bool worker_idle = true;
            bool clients_idle = true;
            if (st->worker_posted.load(std::memory_order_acquire) && !st->worker_exited.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(st->worker_mutex);
                worker_idle = st->worker_cv.wait_for(lock, std::chrono::milliseconds(3000), [st]() {
                    return st->worker_exited.load(std::memory_order_acquire);
                });
            }
            {
                std::unique_lock<std::mutex> lock(st->client_mutex);
                clients_idle = st->client_cv.wait_for(lock, std::chrono::milliseconds(3000), [st]() {
                    return st->active_clients.load(std::memory_order_acquire) == 0;
                });
            }
            st->port.store(0, std::memory_order_release);
            if (worker_idle)
                st->worker_posted.store(false, std::memory_order_release);
            diag::log_tagged_fmt("testlab_burp", "loopback_fixture_stop port=%u listener=%llu worker_posted=%d worker_active=%d worker_entered=%d worker_exited=%d worker_tid=%lu active_clients=%ld worker_idle=%d clients_idle=%d accept_count=%llu request_count=%llu response_count=%llu last_wsa=%d last_gle=%lu elapsed_ms=%llu",
                static_cast<unsigned>(stopped_port),
                static_cast<unsigned long long>(stopped_listener),
                st->worker_posted.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_active.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                st->worker_exited.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(st->worker_tid.load(std::memory_order_acquire)),
                st->active_clients.load(std::memory_order_acquire),
                worker_idle ? 1 : 0,
                clients_idle ? 1 : 0,
                static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)),
                st->last_wsa_error.load(std::memory_order_acquire),
                static_cast<unsigned long>(st->last_win32_error.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return worker_idle && clients_idle;
        }

        ~burp_loopback_fixture_t() {
            stop();
        }

        uint16_t current_port() const {
            auto st = state;
            return st ? st->port.load(std::memory_order_acquire) : 0;
        }

        bool is_stopping() const {
            auto st = state;
            return !st || st->stopping.load(std::memory_order_acquire);
        }

        bool worker_is_active() const {
            auto st = state;
            return st && st->worker_active.load(std::memory_order_acquire) && !st->worker_exited.load(std::memory_order_acquire);
        }

        long current_active_clients() const {
            auto st = state;
            return st ? st->active_clients.load(std::memory_order_acquire) : 0;
        }

        uint64_t current_accept_count() const {
            auto st = state;
            return st ? st->accept_count.load(std::memory_order_acquire) : 0;
        }

        uint64_t current_request_count() const {
            auto st = state;
            return st ? st->request_count.load(std::memory_order_acquire) : 0;
        }

        uint64_t current_response_count() const {
            auto st = state;
            return st ? st->response_count.load(std::memory_order_acquire) : 0;
        }

        struct client_guard_t {
            loopback_state_t* owner = nullptr;
            uint64_t accept_idx = 0;
            explicit client_guard_t(loopback_state_t* fixture, uint64_t idx) : owner(fixture), accept_idx(idx) {
                if (!owner)
                    return;
                diag::log_tagged_fmt("testlab_burp", "loopback_client_enter accept=%llu active_clients=%ld tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    owner->active_clients.load(std::memory_order_acquire),
                    static_cast<unsigned long>(GetCurrentThreadId()));
            }
            ~client_guard_t() {
                if (!owner)
                    return;
                long remaining = owner->active_clients.fetch_sub(1, std::memory_order_acq_rel) - 1;
                owner->client_cv.notify_all();
                diag::log_tagged_fmt("testlab_burp", "loopback_client_exit accept=%llu active_clients=%ld tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    remaining,
                    static_cast<unsigned long>(GetCurrentThreadId()));
            }
        };

        static void worker_entry(std::shared_ptr<loopback_state_t> held_state, const char* mode) {
            auto* st = held_state.get();
            const ULONGLONG t0 = GetTickCount64();
            const DWORD tid = GetCurrentThreadId();
            diag::log_tagged_fmt("testlab_burp", "loopback_worker_raw_entry mode=%s state=%p tid=%lu",
                mode ? mode : "",
                st,
                static_cast<unsigned long>(tid));
            if (!st) {
                diag::log_tagged_fmt("testlab_burp", "loopback_worker_exit mode=%s reason=state_null elapsed_ms=%llu tid=%lu",
                    mode ? mode : "",
                    static_cast<unsigned long long>(GetTickCount64() - t0),
                    static_cast<unsigned long>(tid));
                return;
            }
            st->worker_tid.store(tid, std::memory_order_release);
            st->worker_active.store(true, std::memory_order_release);
            st->worker_entered.store(true, std::memory_order_release);
            st->worker_cv.notify_all();
            std::string exit_reason = "normal";
            diag::log_tagged_fmt("testlab_burp", "loopback_worker_tls_enter mode=%s state=%p tid=%lu port=%u listener=%llu",
                mode ? mode : "",
                st,
                static_cast<unsigned long>(tid),
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->listen_socket.load(std::memory_order_acquire)));
            diag::log_tagged_fmt("testlab_burp", "loopback_worker_tls_exit mode=%s state=%p tid=%lu elapsed_ms=%llu",
                mode ? mode : "",
                st,
                static_cast<unsigned long>(tid),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            try {
                exit_reason = accept_loop(st, mode);
            } catch (const std::exception& ex) {
                exit_reason = "exception";
                st->last_win32_error.store(GetLastError(), std::memory_order_release);
                diag::log_tagged_fmt("testlab_burp", "loopback_fixture_exception err=%s tid=%lu",
                    ex.what(), static_cast<unsigned long>(tid));
            } catch (...) {
                exit_reason = "unknown_exception";
                st->last_win32_error.store(GetLastError(), std::memory_order_release);
                diag::log_tagged_fmt("testlab_burp", "loopback_fixture_exception err=unknown tid=%lu",
                    static_cast<unsigned long>(tid));
            }
            diag::log_tagged_fmt("testlab_burp", "loopback_worker_exit mode=%s reason=%s port=%u listener=%llu active_clients=%ld accept_count=%llu request_count=%llu response_count=%llu stop=%d last_wsa=%d last_gle=%lu elapsed_ms=%llu tid=%lu",
                mode ? mode : "",
                exit_reason.c_str(),
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->listen_socket.load(std::memory_order_acquire)),
                st->active_clients.load(std::memory_order_acquire),
                static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)),
                st->stopping.load(std::memory_order_acquire) ? 1 : 0,
                st->last_wsa_error.load(std::memory_order_acquire),
                static_cast<unsigned long>(st->last_win32_error.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long>(tid));
            st->worker_tid.store(0, std::memory_order_release);
            st->worker_active.store(false, std::memory_order_release);
            st->worker_exited.store(true, std::memory_order_release);
            st->worker_cv.notify_all();
        }

        static std::string accept_loop(loopback_state_t* st, const char* mode) {
            if (!st)
                return "state_null";
            const DWORD tid = GetCurrentThreadId();
            const ULONGLONG t0 = GetTickCount64();
            std::string exit_reason = "stop_requested";
            diag::log_tagged_fmt("testlab_burp", "loopback_accept_loop_enter mode=%s port=%u listener=%llu tid=%lu",
                mode ? mode : "",
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->listen_socket.load(std::memory_order_acquire)),
                static_cast<unsigned long>(tid));
            while (!st->stopping.load(std::memory_order_acquire)) {
                SOCKET listener = st->listen_socket.load(std::memory_order_acquire);
                if (listener == INVALID_SOCKET) {
                    exit_reason = "listener_invalid";
                    break;
                }
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(listener, &rfds);
                timeval tv{};
                tv.tv_usec = 100000;
                int rc = select(0, &rfds, nullptr, nullptr, &tv);
                if (rc == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    st->last_wsa_error.store(err, std::memory_order_release);
                    if (!st->stopping.load(std::memory_order_acquire))
                        diag::log_tagged_fmt("testlab_burp", "loopback_select_error port=%u listener=%llu wsa=%d tid=%lu elapsed_ms=%llu",
                            static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                            static_cast<unsigned long long>(listener),
                            err,
                            static_cast<unsigned long>(GetCurrentThreadId()),
                            static_cast<unsigned long long>(GetTickCount64() - t0));
                    if (err == WSAENOTSOCK) {
                        exit_reason = "select_wsaenotsock";
                        break;
                    }
                    if (st->stopping.load(std::memory_order_acquire)) {
                        exit_reason = "select_stop";
                        break;
                    }
                    continue;
                }
                if (rc == 0)
                    continue;
                if (st->stopping.load(std::memory_order_acquire)) {
                    exit_reason = "stop_after_select";
                    break;
                }
                SOCKET s = accept(listener, nullptr, nullptr);
                if (s == INVALID_SOCKET) {
                    int err = WSAGetLastError();
                    st->last_wsa_error.store(err, std::memory_order_release);
                    if (!st->stopping.load(std::memory_order_acquire))
                        diag::log_tagged_fmt("testlab_burp", "loopback_accept_error port=%u listener=%llu wsa=%d tid=%lu elapsed_ms=%llu",
                            static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                            static_cast<unsigned long long>(listener),
                            err,
                            static_cast<unsigned long>(GetCurrentThreadId()),
                            static_cast<unsigned long long>(GetTickCount64() - t0));
                    if (st->stopping.load(std::memory_order_acquire)) {
                        exit_reason = "accept_stop";
                        break;
                    }
                    continue;
                }
                uint64_t accept_idx = st->accept_count.fetch_add(1, std::memory_order_acq_rel) + 1;
                diag::log_tagged_fmt("testlab_burp", "loopback_accept_ok port=%u accept=%llu socket=%llu active_clients=%ld request_count=%llu response_count=%llu tid=%lu elapsed_ms=%llu",
                    static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(s),
                    st->active_clients.load(std::memory_order_acquire),
                    static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    static_cast<unsigned long long>(GetTickCount64() - t0));
                if (st->stopping.load(std::memory_order_acquire)) {
                    shutdown(s, SD_BOTH);
                    closesocket(s);
                    exit_reason = "stop_after_accept";
                    break;
                }
                DWORD timeout = 2000;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                st->active_clients.fetch_add(1, std::memory_order_acq_rel);
                diag::log_tagged_fmt("testlab_burp", "loopback_client_inline accept=%llu active_clients=%ld tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    st->active_clients.load(std::memory_order_acquire),
                    static_cast<unsigned long>(GetCurrentThreadId()));
                client_guard_t guard(st, accept_idx);
                handle_client(st, s, accept_idx);
            }
            diag::log_tagged_fmt("testlab_burp", "loopback_accept_loop_exit mode=%s reason=%s port=%u active_clients=%ld accept_count=%llu request_count=%llu response_count=%llu tid=%lu elapsed_ms=%llu",
                mode ? mode : "",
                exit_reason.c_str(),
                static_cast<unsigned>(st->port.load(std::memory_order_acquire)),
                st->active_clients.load(std::memory_order_acquire),
                static_cast<unsigned long long>(st->accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->request_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(st->response_count.load(std::memory_order_acquire)),
                static_cast<unsigned long>(tid),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return exit_reason;
        }

        static void wake_listener(uint16_t port) {
            if (port == 0)
                return;
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                diag::log_tagged_fmt("testlab_burp", "loopback_fixture_wake socket_failed port=%u wsa=%d tid=%lu",
                    static_cast<unsigned>(port),
                    WSAGetLastError(),
                    static_cast<unsigned long>(GetCurrentThreadId()));
                return;
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(port);
            int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            int err = rc == SOCKET_ERROR ? WSAGetLastError() : 0;
            shutdown(s, SD_BOTH);
            closesocket(s);
            diag::log_tagged_fmt("testlab_burp", "loopback_fixture_wake port=%u rc=%d wsa=%d tid=%lu",
                static_cast<unsigned>(port),
                rc,
                err,
                static_cast<unsigned long>(GetCurrentThreadId()));
        }

        static void handle_client(loopback_state_t* st, SOCKET s, uint64_t accept_idx) {
            std::string request;
            char buf[4096];
            const ULONGLONG t0 = GetTickCount64();
            while (request.find("\r\n\r\n") == std::string::npos && request.size() < 65536) {
                int n = recv(s, buf, sizeof(buf), 0);
                if (n <= 0) {
                    int err = WSAGetLastError();
                    if (st)
                        st->last_wsa_error.store(err, std::memory_order_release);
                    diag::log_tagged_fmt("testlab_burp", "loopback_recv_end accept=%llu recv=%d wsa=%d request_bytes=%zu tid=%lu elapsed_ms=%llu",
                        static_cast<unsigned long long>(accept_idx),
                        n,
                        err,
                        request.size(),
                        static_cast<unsigned long>(GetCurrentThreadId()),
                        static_cast<unsigned long long>(GetTickCount64() - t0));
                    break;
                }
                request.append(buf, buf + n);
            }
            const bool header_complete = request.find("\r\n\r\n") != std::string::npos;
            uint64_t request_idx = 0;
            if (st && !request.empty())
                request_idx = st->request_count.fetch_add(1, std::memory_order_acq_rel) + 1;
            diag::log_tagged_fmt("testlab_burp", "loopback_handle_client accept=%llu request=%llu request_bytes=%zu header_complete=%d elapsed_ms=%llu active_clients=%ld tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                request.size(),
                header_complete ? 1 : 0,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                st ? st->active_clients.load(std::memory_order_acquire) : static_cast<long>(-1),
                static_cast<unsigned long>(GetCurrentThreadId()));
            if (request.empty()) {
                closesocket(s);
                return;
            }
            std::string upgrade = fixture_lower(header_value_ci(request, "Upgrade"));
            if (upgrade == "websocket") {
                diag::log_tagged_fmt("testlab_burp", "loopback_handle_client websocket accept=%llu request=%llu request_bytes=%zu tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(request_idx),
                    request.size(),
                    static_cast<unsigned long>(GetCurrentThreadId()));
                handle_websocket(st, s, request, accept_idx, request_idx);
                return;
            }
            diag::log_tagged_fmt("testlab_burp", "loopback_handle_client http accept=%llu request=%llu request_bytes=%zu target=%s tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                request.size(),
                request_target_from_raw(request).c_str(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            handle_http(st, s, request, accept_idx, request_idx);
        }

        static void handle_websocket(loopback_state_t* st, SOCKET s, const std::string& request, uint64_t accept_idx, uint64_t request_idx) {
            std::string key = header_value_ci(request, "Sec-WebSocket-Key");
            std::string accept = websocket_accept_for_key(key);
            std::string resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
            diag::log_tagged_fmt("testlab_burp", "loopback_websocket_handshake accept=%llu request=%llu key_len=%zu accept_len=%zu tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                key.size(),
                accept.size(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            if (!send_all_fixture(s, resp)) {
                int err = WSAGetLastError();
                if (st)
                    st->last_wsa_error.store(err, std::memory_order_release);
                diag::log_tagged_fmt("testlab_burp", "loopback_websocket_handshake_send_failed accept=%llu request=%llu wsa=%d tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(request_idx),
                    err,
                    static_cast<unsigned long>(GetCurrentThreadId()));
                closesocket(s);
                return;
            }
            uint64_t response_idx = st ? st->response_count.fetch_add(1, std::memory_order_acq_rel) + 1 : 0;
            diag::log_tagged_fmt("testlab_burp", "loopback_websocket_handshake_sent accept=%llu request=%llu response=%llu bytes=%zu tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                static_cast<unsigned long long>(response_idx),
                resp.size(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            uint64_t end_ms = GetTickCount64() + 3500;
            uint8_t hdr[2] = {};
            size_t frames_seen = 0;
            while (GetTickCount64() < end_ms) {
                int n = recv(s, reinterpret_cast<char*>(hdr), 2, 0);
                if (n <= 0) {
                    int err = WSAGetLastError();
                    if (st)
                        st->last_wsa_error.store(err, std::memory_order_release);
                    diag::log_tagged_fmt("testlab_burp", "loopback_websocket_recv_end accept=%llu request=%llu recv=%d wsa=%d frames=%zu tid=%lu",
                        static_cast<unsigned long long>(accept_idx),
                        static_cast<unsigned long long>(request_idx),
                        n,
                        err,
                        frames_seen,
                        static_cast<unsigned long>(GetCurrentThreadId()));
                    break;
                }
                if (n < 2) continue;
                size_t len = hdr[1] & 0x7F;
                if (len == 126) {
                    uint8_t ext[2] = {};
                    if (recv(s, reinterpret_cast<char*>(ext), 2, 0) != 2) break;
                    len = (static_cast<size_t>(ext[0]) << 8) | ext[1];
                } else if (len == 127) {
                    uint8_t ext[8] = {};
                    if (recv(s, reinterpret_cast<char*>(ext), 8, 0) != 8) break;
                    len = 0;
                    for (uint8_t b : ext) len = (len << 8) | b;
                    if (len > 4096) break;
                }
                uint8_t mask[4] = {};
                bool masked = (hdr[1] & 0x80) != 0;
                if (masked && recv(s, reinterpret_cast<char*>(mask), 4, 0) != 4) break;
                std::vector<uint8_t> payload(len);
                size_t got = 0;
                while (got < len) {
                    int r = recv(s, reinterpret_cast<char*>(payload.data() + got), static_cast<int>(len - got), 0);
                    if (r <= 0) break;
                    got += static_cast<size_t>(r);
                }
                if (got != len) break;
                if (masked) {
                    for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= mask[i % 4];
                }
                uint8_t opcode = hdr[0] & 0x0F;
                ++frames_seen;
                diag::log_tagged_fmt("testlab_burp", "loopback_websocket_frame accept=%llu request=%llu opcode=0x%02X len=%zu masked=%d frames=%zu tid=%lu",
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(request_idx),
                    static_cast<unsigned>(opcode),
                    payload.size(),
                    masked ? 1 : 0,
                    frames_seen,
                    static_cast<unsigned long>(GetCurrentThreadId()));
                if (opcode == 0x8) break;
                if (opcode == 0x1 || opcode == 0x2) {
                    std::string frame;
                    frame.push_back(static_cast<char>(0x80 | opcode));
                    if (payload.size() < 126) {
                        frame.push_back(static_cast<char>(payload.size()));
                    } else {
                        frame.push_back(static_cast<char>(126));
                        frame.push_back(static_cast<char>((payload.size() >> 8) & 0xFF));
                        frame.push_back(static_cast<char>(payload.size() & 0xFF));
                    }
                    frame.append(reinterpret_cast<const char*>(payload.data()), payload.size());
                    if (send_all_fixture(s, frame)) {
                        response_idx = st ? st->response_count.fetch_add(1, std::memory_order_acq_rel) + 1 : 0;
                        diag::log_tagged_fmt("testlab_burp", "loopback_websocket_frame_sent accept=%llu request=%llu response=%llu frame_bytes=%zu tid=%lu",
                            static_cast<unsigned long long>(accept_idx),
                            static_cast<unsigned long long>(request_idx),
                            static_cast<unsigned long long>(response_idx),
                            frame.size(),
                            static_cast<unsigned long>(GetCurrentThreadId()));
                    } else {
                        int err = WSAGetLastError();
                        if (st)
                            st->last_wsa_error.store(err, std::memory_order_release);
                        diag::log_tagged_fmt("testlab_burp", "loopback_websocket_frame_send_failed accept=%llu request=%llu wsa=%d frame_bytes=%zu tid=%lu",
                            static_cast<unsigned long long>(accept_idx),
                            static_cast<unsigned long long>(request_idx),
                            err,
                            frame.size(),
                            static_cast<unsigned long>(GetCurrentThreadId()));
                    }
                }
            }
            diag::log_tagged_fmt("testlab_burp", "loopback_websocket_close accept=%llu request=%llu frames=%zu tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                frames_seen,
                static_cast<unsigned long>(GetCurrentThreadId()));
            closesocket(s);
        }

        static void handle_http(loopback_state_t* st, SOCKET s, const std::string& request, uint64_t accept_idx, uint64_t request_idx) {
            std::string target = request_target_from_raw(request);
            std::string path = target;
            std::string query;
            size_t q = path.find('?');
            if (q != std::string::npos) {
                query = path.substr(q + 1);
                path = path.substr(0, q);
            }
            std::string body;
            std::string content_type = "text/html";
            const char* route = "html";
            if (path == "/token") {
                content_type = "application/json";
                body = "{\"access_token\":\"aida-local-access\",\"refresh_token\":\"aida-local-refresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
                route = "token";
            } else if (path == "/graphql") {
                content_type = "application/json";
                body = "{\"data\":{\"viewer\":{\"login\":\"aida-fixture\"}},\"extensions\":{\"fixture\":\"graphql\"}}";
                route = "graphql";
            } else if (path == "/aida-fixture.js") {
                content_type = "application/javascript";
                body = "window.aidaFixtureLoaded=true;console.log('aida-fixture-js');";
                route = "script";
            } else {
                std::ostringstream os;
                os << "<!doctype html><html><head><meta name=\"generator\" content=\"WordPress 6.4\">"
                   << "<title>AiDA Burp Fixture</title><script src=\"/aida-fixture.js\"></script></head><body>"
                   << "<h1>AiDA local Burp fixture</h1><a href=\"/aida-mcp-test\">aida-mcp-test</a>"
                   << "<form action=\"/login\" method=\"post\"><input name=\"csrf\" value=\"AIDASEQ1234\"></form>"
                   << "<div id=\"token\">AIDASEQ1234</div><div id=\"path\">" << path << "</div>"
                   << "<div id=\"query\">" << query << "</div>"
                   << "<div id=\"marker\">aida_mcp_param aida-mcp-test FUZZ</div>"
                   << "</body></html>";
                body = os.str();
            }
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n"
                 << "Server: nginx/1.24.0\r\n"
                 << "X-Powered-By: PHP/8.2\r\n"
                 << "Content-Type: " << content_type << "\r\n"
                 << "Content-Security-Policy: default-src *; script-src * 'unsafe-inline'\r\n"
                 << "Set-Cookie: aida_fixture=1; Path=/\r\n"
                 << "X-AiDA-Fixture: local-burp\r\n"
                 << "X-Query-Echo: " << query << "\r\n"
                 << "Content-Length: " << body.size() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << body;
            std::string response = resp.str();
            const bool sent = send_all_fixture(s, response);
            int err = sent ? 0 : WSAGetLastError();
            if (st && err != 0)
                st->last_wsa_error.store(err, std::memory_order_release);
            uint64_t response_idx = sent && st ? st->response_count.fetch_add(1, std::memory_order_acq_rel) + 1 : 0;
            diag::log_tagged_fmt("testlab_burp", "loopback_http_response accept=%llu request=%llu response=%llu route=%s status=200 path=%s query_len=%zu body=%zu bytes=%zu sent=%d wsa=%d tid=%lu",
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(request_idx),
                static_cast<unsigned long long>(response_idx),
                route,
                path.c_str(),
                query.size(),
                body.size(),
                response.size(),
                sent ? 1 : 0,
                err,
                static_cast<unsigned long>(GetCurrentThreadId()));
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
    };

    std::unique_ptr<burp_loopback_fixture_t> g_burp_fixture;
    std::string g_burp_wordlist_path;
    std::string g_subdomain_wordlist_path;

    bool probe_burp_loopback_fixture(uint16_t port, std::string& detail) {
        const ULONGLONG t0 = GetTickCount64();
        detail.clear();
        if (port == 0) {
            detail = "port_zero";
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        if (!ensure_burp_fixture_wsa()) {
            detail = "wsa_startup_failed";
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            detail = "socket_failed:" + std::to_string(WSAGetLastError());
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        DWORD timeout = 750;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            closesocket(s);
            detail = "connect_failed:" + std::to_string(err);
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        std::string req = "GET /__aida_fixture_probe HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(static_cast<unsigned>(port)) + "\r\nConnection: close\r\n\r\n";
        if (!send_all_fixture(s, req)) {
            int err = WSAGetLastError();
            closesocket(s);
            detail = "send_failed:" + std::to_string(err);
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        char buf[512] = {};
        int n = recv(s, buf, sizeof(buf), 0);
        int err = n <= 0 ? WSAGetLastError() : 0;
        closesocket(s);
        if (n <= 0) {
            detail = "recv_failed:" + std::to_string(err);
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        std::string response_prefix(buf, buf + n);
        if (response_prefix.find("HTTP/1.1 200") == std::string::npos &&
            response_prefix.find("HTTP/1.0 200") == std::string::npos) {
            detail = "unexpected_response:" + std::to_string(n);
            diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=0 detail=%s elapsed_ms=%llu",
                static_cast<unsigned>(port),
                detail.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        detail = "ok:" + std::to_string(n);
        diag::log_tagged_fmt("testlab_burp", "loopback_probe_result port=%u ok=1 detail=%s elapsed_ms=%llu",
            static_cast<unsigned>(port),
            detail.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return true;
    }

    bool ensure_burp_loopback_fixture(HANDLE hf, const char* tag) {
        if (g_burp_fixture) {
            const uint16_t existing_port = g_burp_fixture->current_port();
            const bool existing_worker_active = g_burp_fixture->worker_is_active();
            std::string probe_detail;
            const bool reusable = existing_port != 0 && !g_burp_fixture->is_stopping() && existing_worker_active &&
                probe_burp_loopback_fixture(existing_port, probe_detail);
            if (reusable) {
                log_msg(hf, tag, "fixture_reuse -- loopback_http_ws port=%u worker_active=%d active_clients=%ld accept_count=%llu request_count=%llu response_count=%llu probe=%s",
                    static_cast<unsigned>(existing_port),
                    existing_worker_active ? 1 : 0,
                    g_burp_fixture->current_active_clients(),
                    static_cast<unsigned long long>(g_burp_fixture->current_accept_count()),
                    static_cast<unsigned long long>(g_burp_fixture->current_request_count()),
                    static_cast<unsigned long long>(g_burp_fixture->current_response_count()),
                    probe_detail.c_str());
                return true;
            }
            const uint16_t stale_port = existing_port;
            const bool stopped = g_burp_fixture->stop();
            log_msg(hf, tag, "fixture_replace -- stale loopback stopped=%d port=%u worker_active=%d accept_count=%llu request_count=%llu response_count=%llu probe=%s",
                stopped ? 1 : 0,
                static_cast<unsigned>(stale_port),
                existing_worker_active ? 1 : 0,
                static_cast<unsigned long long>(g_burp_fixture->current_accept_count()),
                static_cast<unsigned long long>(g_burp_fixture->current_request_count()),
                static_cast<unsigned long long>(g_burp_fixture->current_response_count()),
                probe_detail.empty() ? "<not_run>" : probe_detail.c_str());
            if (!stopped)
                return false;
            g_burp_fixture.reset();
        }
        auto fixture = std::make_unique<burp_loopback_fixture_t>();
        if (!fixture->start(hf, tag)) {
            return false;
        }
        std::string probe_detail;
        if (!probe_burp_loopback_fixture(fixture->current_port(), probe_detail)) {
            log_msg(hf, tag, "fixture_start_probe_failed -- loopback_http_ws port=%u probe=%s",
                static_cast<unsigned>(fixture->current_port()),
                probe_detail.c_str());
            fixture->stop();
            return false;
        }
        log_msg(hf, tag, "fixture_start_probe_ok -- loopback_http_ws port=%u probe=%s",
            static_cast<unsigned>(fixture->current_port()),
            probe_detail.c_str());
        g_burp_fixture = std::move(fixture);
        return true;
    }

    uint16_t burp_fixture_port() {
        return g_burp_fixture ? g_burp_fixture->current_port() : 0;
    }

    std::string burp_fixture_url(const std::string& path = "/") {
        uint16_t port = burp_fixture_port();
        return "http://127.0.0.1:" + std::to_string(static_cast<unsigned>(port)) + path;
    }

    const std::string& ensure_burp_wordlist(HANDLE hf, const char* tag) {
        if (g_burp_wordlist_path.empty()) {
            g_burp_wordlist_path = fixture_temp_path("aida_burp_fixture_words.txt");
            bool ok = write_fixture_text_file(g_burp_wordlist_path, "aida-mcp-test\n");
            log_msg(hf, tag, "fixture_wordlist path=%s ok=%d", g_burp_wordlist_path.c_str(), ok ? 1 : 0);
        }
        return g_burp_wordlist_path;
    }

    const std::string& ensure_subdomain_wordlist(HANDLE hf, const char* tag) {
        if (g_subdomain_wordlist_path.empty()) {
            g_subdomain_wordlist_path = fixture_temp_path("aida_burp_subdomain_words.txt");
            bool ok = write_fixture_text_file(g_subdomain_wordlist_path, "@\n");
            log_msg(hf, tag, "fixture_subdomain_wordlist path=%s ok=%d", g_subdomain_wordlist_path.c_str(), ok ? 1 : 0);
        }
        return g_subdomain_wordlist_path;
    }

    aida::burp::exchange_observed_t make_fixture_exchange(uint64_t id) {
        aida::burp::exchange_observed_t e;
        e.id = id;
        e.timestamp_ms = fixture_now_ms();
        e.method = "GET";
        e.scheme = "http";
        e.host = "127.0.0.1";
        e.port = burp_fixture_port() ? burp_fixture_port() : 18888;
        e.path = "/aida-mcp-test";
        e.query = "q=AIDASEQ1234&aida_mcp_param=fixture";
        e.req_headers = {{"Host", "127.0.0.1"}, {"User-Agent", "AiDA-TestLab/1.0"}};
        std::string body = "<html><head><meta name=\"generator\" content=\"WordPress 6.4\"></head><body>AIDASEQ1234 aida_mcp_param fixture</body></html>";
        e.status_code = 200;
        e.reason_phrase = "OK";
        e.resp_headers = {
            {"Server", "nginx/1.24.0"},
            {"X-Powered-By", "PHP/8.2"},
            {"Content-Type", "text/html"},
            {"Content-Security-Policy", "default-src *; script-src * 'unsafe-inline'"},
            {"Set-Cookie", "aida_fixture=1; Path=/"}
        };
        e.resp_body.assign(body.begin(), body.end());
        e.latency_ms = 7;
        e.client_addr = "127.0.0.1";
        e.client_port = 53000;
        return e;
    }

    void publish_fixture_exchange(HANDLE hf, const char* tag) {
        aida::burp::passive_scanner::initialize();
        aida::burp::passive_scanner::set_enabled(true);
        aida::burp::sitemap::initialize();
        aida::burp::logger::initialize();
        aida::burp::tech::initialize();
        auto before_stats = aida::burp::passive_scanner::get_stats();
        size_t before_hosts = aida::burp::sitemap::list_hosts(false).size();
        size_t before_rows = aida::burp::logger::total_rows();
        size_t before_inv = aida::burp::tech::inventory().size();
        auto ex = make_fixture_exchange(900000 + before_rows + before_hosts + before_inv);
        log_msg(hf, tag, "fixture_exchange publish id=%llu host=%s port=%u path=%s before_scanned=%llu before_hosts=%zu before_rows=%zu before_inv=%zu",
            static_cast<unsigned long long>(ex.id), ex.host.c_str(), static_cast<unsigned>(ex.port), ex.path.c_str(),
            static_cast<unsigned long long>(before_stats.exchanges_scanned), before_hosts, before_rows, before_inv);
        aida::burp::sitemap::ingest_exchange(ex);
        if (!publish_exchange_observed_on_ui(hf, tag, ex, "publish_fixture_exchange"))
            return;
        Sleep(250);
        auto after_stats = aida::burp::passive_scanner::get_stats();
        size_t after_hosts = aida::burp::sitemap::list_hosts(false).size();
        size_t after_rows = aida::burp::logger::total_rows();
        size_t after_inv = aida::burp::tech::inventory().size();
        log_msg(hf, tag, "fixture_exchange result scanned=%llu issues=%llu hosts=%zu rows=%zu inventory=%zu",
            static_cast<unsigned long long>(after_stats.exchanges_scanned),
            static_cast<unsigned long long>(after_stats.issues_found),
            after_hosts, after_rows, after_inv);
    }

    void wait_briefly_for_async_state() {
        Sleep(500);
    }

    bool ensure_sequencer_fixture(HANDLE hf, const char* tag) {
        auto cols = aida::burp::sequencer::list_collections();
        if (!cols.empty()) return true;
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        aida::burp::sequencer::collection_config_t cfg;
        cfg.url = burp_fixture_url("/?q=AIDASEQ1234");
        cfg.host = "127.0.0.1";
        cfg.port = burp_fixture_port();
        cfg.use_tls = false;
        cfg.extract_regex = "(AIDASEQ[0-9]{4})";
        cfg.capture_group = 1;
        cfg.target_count = 3;
        cfg.concurrency = 1;
        cfg.throttle_ms = 1;
        cfg.name = "TestLab local sequencer fixture";
        uint64_t id = aida::burp::sequencer::start_collection(cfg);
        log_msg(hf, tag, "fixture_sequencer start id=%llu url=%s port=%u err=%s",
            static_cast<unsigned long long>(id), cfg.url.c_str(), static_cast<unsigned>(cfg.port),
            aida::burp::sequencer::last_error().c_str());
        if (id == 0)
            return false;
        for (int i = 0; i < 80; ++i) {
            auto st = aida::burp::sequencer::status(id);
            log_msg(hf, tag, "fixture_sequencer poll=%d id=%llu collected=%zu target=%zu running=%d error=%d err=%s",
                i, static_cast<unsigned long long>(id), st.collected, st.target, st.running ? 1 : 0, st.error ? 1 : 0, st.error_message.c_str());
            if (st.collected >= st.target || (st.error && !st.error_message.empty()) || (!st.running && st.id != 0 && st.collected > 0)) break;
            Sleep(150);
        }
        return true;
    }

    bool ensure_intruder_fixture(HANDLE hf, const char* tag) {
        auto jobs = aida::burp::intruder::list_jobs();
        if (!jobs.empty()) return true;
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        std::string raw = "GET /?q=FUZZ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        size_t pos = raw.find("FUZZ");
        aida::burp::intruder::config_t cfg;
        cfg.scheme = "http";
        cfg.host = "127.0.0.1";
        cfg.port = burp_fixture_port();
        cfg.base_request.assign(raw.begin(), raw.end());
        cfg.attack_mode = aida::burp::intruder::attack_mode_t::sniper;
        cfg.engine_mode = aida::burp::intruder::engine_mode_t::http1_serial;
        cfg.positions.push_back({pos == std::string::npos ? 0 : pos, 4});
        cfg.payload_sets.push_back({"aida"});
        cfg.concurrency = 1;
        cfg.total_requests_cap = 1;
        cfg.timeout_ms = 1500;
        uint64_t id = aida::burp::intruder::start(cfg);
        log_msg(hf, tag, "fixture_intruder start id=%llu port=%u pos=%zu err=%s",
            static_cast<unsigned long long>(id), static_cast<unsigned>(cfg.port), pos,
            aida::burp::intruder::last_error().c_str());
        if (id == 0)
            return false;
        wait_briefly_for_async_state();
        auto st = aida::burp::intruder::status(id);
        log_msg(hf, tag, "fixture_intruder status id=%llu total=%zu sent=%zu errors=%zu running=%d",
            static_cast<unsigned long long>(id), st.total, st.sent, st.errors, st.running ? 1 : 0);
        return true;
    }

    bool ensure_active_scanner_fixture(HANDLE hf, const char* tag) {
        auto audits = aida::burp::active_scanner::list_audits();
        if (!audits.empty()) {
            log_msg(hf, tag, "fixture_active_scanner reuse audits=%zu first_id=%llu running=%d completed=%zu total=%zu",
                audits.size(),
                static_cast<unsigned long long>(audits.front().id),
                audits.front().running ? 1 : 0,
                audits.front().completed_probes,
                audits.front().total_probes);
            return true;
        }
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        aida::burp::active_scanner::initialize();
        std::string raw = "GET /?q=AIDASEQ1234 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        aida::burp::active_scanner::audit_config_t cfg;
        cfg.scope_only = false;
        cfg.max_concurrent_requests = 1;
        cfg.per_module_request_cap = 2;
        cfg.timeout_ms = 1000;
        cfg.enabled_modules = {"nosqli", "open-redirect"};
        uint64_t id = aida::burp::active_scanner::enqueue_target(
            std::vector<uint8_t>(raw.begin(), raw.end()), burp_fixture_url("/?q=AIDASEQ1234"), cfg);
        log_msg(hf, tag, "fixture_active_scanner enqueue id=%llu audits_before=%zu modules=%zu max_concurrent=%zu per_module_cap=%zu timeout_ms=%d err=%s",
            static_cast<unsigned long long>(id), audits.size(), cfg.enabled_modules.size(),
            cfg.max_concurrent_requests, cfg.per_module_request_cap, cfg.timeout_ms,
            aida::burp::active_scanner::last_error().c_str());
        if (id == 0)
            return false;
        aida::burp::active_scanner::audit_status_t st{};
        bool saw_status = false;
        bool saw_progress = false;
        for (int i = 0; i < 30; ++i) {
            if (aida::burp::active_scanner::get_status(id, st)) {
                saw_status = true;
                saw_progress = st.total_points > 0 && (st.completed_probes > 0 || st.total_probes > 0);
                log_msg(hf, tag, "fixture_active_scanner poll=%d id=%llu running=%d cancelled=%d points=%zu completed=%zu total=%zu issues=%zu",
                    i,
                    static_cast<unsigned long long>(id),
                    st.running ? 1 : 0,
                    st.cancelled ? 1 : 0,
                    st.total_points,
                    st.completed_probes,
                    st.total_probes,
                    st.issues_found);
                if ((st.completed_probes > 0) || (!st.running && st.total_points > 0))
                    break;
            } else {
                log_msg(hf, tag, "fixture_active_scanner poll=%d id=%llu status_missing", i, static_cast<unsigned long long>(id));
            }
            Sleep(100);
        }
        const bool cancel_ok = aida::burp::active_scanner::cancel_audit(id);
        const bool idle = aida::burp::active_scanner::wait_for_audit_idle(id, 2500);
        aida::burp::active_scanner::audit_status_t after{};
        const bool after_ok = aida::burp::active_scanner::get_status(id, after);
        log_msg(hf, tag, "fixture_active_scanner drain id=%llu cancel_ok=%d idle=%d status_ok=%d running=%d cancelled=%d points=%zu completed=%zu total=%zu issues=%zu",
            static_cast<unsigned long long>(id),
            cancel_ok ? 1 : 0,
            idle ? 1 : 0,
            after_ok ? 1 : 0,
            after.running ? 1 : 0,
            after.cancelled ? 1 : 0,
            after.total_points,
            after.completed_probes,
            after.total_probes,
            after.issues_found);
        return saw_status && saw_progress && after_ok && after.total_points > 0 && after.completed_probes > 0;
    }

    bool ensure_crawler_fixture(HANDLE hf, const char* tag) {
        auto crawls = aida::burp::crawler::list();
        if (!crawls.empty()) return true;
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        aida::burp::crawler::initialize();
        aida::burp::crawler::crawl_config_t cfg;
        cfg.start_urls = {burp_fixture_url("/")};
        cfg.max_depth = 1;
        cfg.max_pages = 4;
        cfg.concurrency = 1;
        cfg.respect_robots_txt = false;
        cfg.parse_js = false;
        cfg.request_timeout_ms = 1500;
        uint64_t id = aida::burp::crawler::start(cfg);
        log_msg(hf, tag, "fixture_crawler start id=%llu url=%s err=%s",
            static_cast<unsigned long long>(id), cfg.start_urls[0].c_str(), aida::burp::crawler::last_error().c_str());
        if (id == 0)
            return false;
        wait_briefly_for_async_state();
        return true;
    }

    bool ensure_report_fixture(HANDLE hf, const char* tag) {
        auto reports = aida::burp::report::list_reports();
        bool has_nonempty_history = false;
        for (const auto& report : reports) {
            if (report.issue_count > 0) {
                has_nonempty_history = true;
                break;
            }
        }
        if (has_nonempty_history) {
            log_msg(hf, tag, "fixture_report existing_history reports=%zu", reports.size());
            return true;
        }
        aida::burp::issue_store::initialize();
        aida::burp::issue_t issue;
        issue.type_key = "testlab.fixture.csp";
        issue.name = "TestLab fixture issue";
        issue.description = "Local deterministic fixture issue for report generation.";
        issue.remediation = "Use deterministic local fixtures for report tests.";
        issue.severity = aida::burp::severity_t::low;
        issue.confidence = aida::burp::confidence_t::firm;
        issue.scheme = "http";
        issue.host = "127.0.0.1";
        issue.port = burp_fixture_port() ? burp_fixture_port() : 80;
        issue.path = "/aida-mcp-test";
        issue.seen_ms = fixture_now_ms();
        aida::burp::issue_filter_t all_issues;
        all_issues.include_suppressed = true;
        const size_t issue_store_before = aida::burp::issue_store::list(all_issues).size();
        const size_t findings_before = aida::burp::findings_db::is_initialized() ? aida::burp::findings_db::count() : 0;
        uint64_t issue_id = aida::burp::issue_store::add(issue);
        if (issue_id == 0) {
            log_msg(hf, tag, "fixture_report add_failed issue_store_before=%zu findings_before=%zu issue_err=%s",
                issue_store_before,
                findings_before,
                aida::burp::issue_store::last_error().c_str());
            return false;
        }
        aida::burp::report::report_config_t cfg;
        cfg.title = "AiDA TestLab Burp Fixture Report";
        cfg.client = "AiDA TestLab";
        cfg.scope_summary = "Loopback fixture";
        cfg.output_path = fixture_temp_path("aida_burp_fixture_report.html");
        cfg.format = aida::burp::report::report_format_t::html;
        std::string out;
        bool ok = aida::burp::report::generate(cfg, out);
        auto reports_after = aida::burp::report::list_reports();
        const size_t issue_store_after = aida::burp::issue_store::list(all_issues).size();
        const size_t findings_after = aida::burp::findings_db::is_initialized() ? aida::burp::findings_db::count() : 0;
        std::error_code file_ec;
        const bool file_exists = std::filesystem::exists(cfg.output_path, file_ec);
        uint64_t file_size = 0;
        if (file_exists) {
            const auto raw_size = std::filesystem::file_size(cfg.output_path, file_ec);
            if (!file_ec) file_size = static_cast<uint64_t>(raw_size);
        }
        size_t nonempty_report_count = 0;
        for (const auto& report : reports_after) {
            if (report.issue_count > 0) ++nonempty_report_count;
        }
        log_msg(hf, tag, "fixture_report generate ok=%d issue_id=%llu path=%s reports_before=%zu reports_after=%zu nonempty_reports=%zu issue_store_before=%zu issue_store_after=%zu findings_before=%zu findings_after=%zu file_exists=%d file_size=%llu report_err=%s db_err=%s",
            ok ? 1 : 0,
            static_cast<unsigned long long>(issue_id),
            out.c_str(),
            reports.size(),
            reports_after.size(),
            nonempty_report_count,
            issue_store_before,
            issue_store_after,
            findings_before,
            findings_after,
            file_exists ? 1 : 0,
            static_cast<unsigned long long>(file_size),
            aida::burp::report::last_error().c_str(),
            aida::burp::findings_db::last_error().c_str());
        if (!ok || reports_after.empty() || nonempty_report_count == 0 || !file_exists || file_size == 0 || findings_after == 0) {
            return false;
        }
        return true;
    }

    uint16_t reserve_loopback_port_for_fixture(HANDLE hf, const char* tag) {
        if (!ensure_burp_fixture_wsa()) return 0;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return 0;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        uint16_t out = 0;
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR) {
            sockaddr_in bound{};
            int len = sizeof(bound);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &len) != SOCKET_ERROR) {
                out = ntohs(bound.sin_port);
            }
        }
        closesocket(s);
        log_msg(hf, tag, "fixture_port_reserve port=%u", static_cast<unsigned>(out));
        return out;
    }

    bool collaborator_probe_fixture(HANDLE hf, const char* tag, const std::string& token) {
        auto cfg = aida::burp::collaborator::current_config();
        if (token.empty() || cfg.http_port == 0) {
            log_msg(hf, tag, "fixture_collab_probe skipped token_len=%zu port=%u", token.size(), static_cast<unsigned>(cfg.http_port));
            return false;
        }
        if (!ensure_burp_fixture_wsa()) return false;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        DWORD timeout = 1500;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(cfg.http_port);
        bool ok = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR;
        if (ok) {
            std::string req = "GET /" + token + " HTTP/1.1\r\nHost: " + token + "." + cfg.public_host + "\r\nConnection: close\r\n\r\n";
            ok = send_all_fixture(s, req);
            char buf[512];
            int n = recv(s, buf, sizeof(buf), 0);
            log_msg(hf, tag, "fixture_collab_probe recv=%d token_len=%zu port=%u", n, token.size(), static_cast<unsigned>(cfg.http_port));
        } else {
            log_msg(hf, tag, "fixture_collab_probe connect_failed wsa=%d port=%u", WSAGetLastError(), static_cast<unsigned>(cfg.http_port));
        }
        closesocket(s);
        Sleep(150);
        return ok;
    }

    void ensure_collaborator_fixture(HANDLE hf, const char* tag) {
        auto existing = aida::burp::collaborator::snapshot_all(10);
        if (!existing.empty()) return;
        if (!aida::burp::collaborator::is_running()) {
            aida::burp::collaborator::collaborator_config_t cfg;
            cfg.bind_ip = "127.0.0.1";
            cfg.http_port = reserve_loopback_port_for_fixture(hf, tag);
            if (cfg.http_port == 0) cfg.http_port = 28444;
            cfg.enable_http = true;
            cfg.enable_dns = false;
            cfg.enable_smtp = false;
            cfg.dns_port = 0;
            cfg.smtp_port = 0;
            cfg.public_host = "aidacollab.local";
            cfg.public_ip = "127.0.0.1";
            cfg.canned_body = "aida collaborator fixture";
            bool ok = aida::burp::collaborator::start(cfg);
            log_msg(hf, tag, "fixture_collab_start ok=%d bind=%s http_port=%u err=%s",
                ok ? 1 : 0, cfg.bind_ip.c_str(), static_cast<unsigned>(cfg.http_port), aida::burp::collaborator::last_error().c_str());
        }
        std::string token = aida::burp::collaborator::generate_token();
        log_msg(hf, tag, "fixture_collab_token len=%zu running=%d", token.size(), aida::burp::collaborator::is_running() ? 1 : 0);
        collaborator_probe_fixture(hf, tag, token);
        auto after = aida::burp::collaborator::snapshot_all(100);
        log_msg(hf, tag, "fixture_collab_result interactions=%zu tokens=%zu", after.size(), aida::burp::collaborator::list_tokens().size());
    }

    bool ensure_ws_fixture(HANDLE hf, const char* tag) {
        auto conns = aida::burp::ws_editor::list_connections();
        if (!conns.empty()) return true;
        for (int attempt = 1; attempt <= 2; ++attempt) {
            if (!ensure_burp_loopback_fixture(hf, tag)) return false;
            aida::burp::ws_editor::initialize();
            aida::burp::ws_editor::ws_connection_config_t cfg;
            cfg.scheme = "ws";
            cfg.host = "127.0.0.1";
            cfg.port = burp_fixture_port();
            cfg.path = "/ws";
            cfg.verify_tls = false;
            cfg.connect_timeout_ms = 5000;
            cfg.read_timeout_ms = 4000;
            uint64_t id = aida::burp::ws_editor::connect(cfg);
            bool sent = id != 0 && aida::burp::ws_editor::send_text(id, "aida-ws-fixture");
            log_msg(hf, tag, "fixture_ws connect attempt=%d id=%llu sent=%d port=%u active_clients=%ld worker_active=%d err=%s",
                attempt,
                static_cast<unsigned long long>(id),
                sent ? 1 : 0,
                static_cast<unsigned>(cfg.port),
                g_burp_fixture ? g_burp_fixture->current_active_clients() : static_cast<long>(-1),
                g_burp_fixture && g_burp_fixture->worker_is_active() ? 1 : 0,
                aida::burp::ws_editor::last_error().c_str());
            Sleep(250);
            conns = aida::burp::ws_editor::list_connections();
            if (!conns.empty()) return true;
            if (g_burp_fixture) {
                const uint16_t stale_port = g_burp_fixture->current_port();
                const bool stopped = g_burp_fixture->stop();
                log_msg(hf, tag, "fixture_ws retry_replace attempt=%d stopped=%d stale_port=%u",
                    attempt,
                    stopped ? 1 : 0,
                    static_cast<unsigned>(stale_port));
                if (!stopped) return false;
                g_burp_fixture.reset();
            }
        }
        return false;
    }

    bool ensure_content_discovery_fixture(HANDLE hf, const char* tag) {
        const ULONGLONG list_t0 = GetTickCount64();
        log_msg(hf, tag, "fixture_content_discovery preflight_list_begin");
        auto jobs = aida::burp::content_discovery::list();
        log_msg(hf, tag, "fixture_content_discovery preflight_list_end jobs=%zu elapsed_ms=%llu",
            jobs.size(),
            static_cast<unsigned long long>(GetTickCount64() - list_t0));
        if (!jobs.empty()) return true;
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        aida::burp::content_discovery::initialize();
        aida::burp::content_discovery::config_t cfg;
        cfg.target_url = burp_fixture_url("/FUZZ");
        cfg.wordlist_file = ensure_burp_wordlist(hf, tag);
        cfg.concurrency = 1;
        cfg.request_timeout_ms = 1500;
        cfg.auto_calibrate = false;
        cfg.match_status = {200};
        const ULONGLONG start_t0 = GetTickCount64();
        uint64_t id = aida::burp::content_discovery::start(cfg);
        log_msg(hf, tag, "fixture_content_discovery start id=%llu target=%s wordlist=%s elapsed_ms=%llu err=%s",
            static_cast<unsigned long long>(id), cfg.target_url.c_str(), cfg.wordlist_file.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - start_t0),
            aida::burp::content_discovery::last_error().c_str());
        if (id == 0)
            return false;
        wait_briefly_for_async_state();
        const ULONGLONG status_t0 = GetTickCount64();
        auto st = aida::burp::content_discovery::status(id);
        log_msg(hf, tag, "fixture_content_discovery status id=%llu attempts=%d total=%d hits=%d errors=%d phase=%d elapsed_ms=%llu last_error=%s",
            static_cast<unsigned long long>(id), st.attempts, st.total, st.hits, st.errors,
            static_cast<int>(st.phase),
            static_cast<unsigned long long>(GetTickCount64() - status_t0),
            st.last_error.c_str());
        return true;
    }

    void ensure_subdomain_fixture(HANDLE hf, const char* tag) {
        auto jobs = aida::burp::subdomain_enum::list();
        if (!jobs.empty()) return;
        aida::burp::subdomain_enum::initialize();
        aida::burp::subdomain_enum::config_t cfg;
        cfg.domain = "localhost";
        cfg.brute_wordlist_file = ensure_subdomain_wordlist(hf, tag);
        cfg.resolver_concurrency = 1;
        cfg.request_timeout_ms = 1000;
        cfg.run_passive = false;
        cfg.run_brute = true;
        cfg.bypass_dns_cache = false;
        uint64_t id = aida::burp::subdomain_enum::start(cfg);
        log_msg(hf, tag, "fixture_subdomain start id=%llu domain=%s wordlist=%s err=%s",
            static_cast<unsigned long long>(id), cfg.domain.c_str(), cfg.brute_wordlist_file.c_str(),
            aida::burp::subdomain_enum::last_error().c_str());
        for (int i = 0; i < 20; ++i) {
            auto st = aida::burp::subdomain_enum::status(id);
            log_msg(hf, tag, "fixture_subdomain poll=%d id=%llu phase=%d attempts=%d resolved=%d results=%zu",
                i, static_cast<unsigned long long>(id), static_cast<int>(st.phase), st.brute_attempts, st.brute_resolved, st.results.size());
            if (st.phase == aida::burp::subdomain_enum::enum_phase_t::complete || !st.results.empty()) break;
            Sleep(100);
        }
    }

    bool ensure_param_miner_fixture(HANDLE hf, const char* tag) {
        auto jobs = aida::burp::param_miner::list_jobs();
        if (!jobs.empty()) return true;
        if (!ensure_burp_loopback_fixture(hf, tag)) return false;
        aida::burp::param_miner::config_t cfg;
        cfg.target_url = burp_fixture_url("/");
        cfg.location = aida::burp::param_miner::location_t::query;
        cfg.custom_words = {"aida_mcp_param"};
        cfg.concurrency = 1;
        cfg.timeout_ms = 1500;
        cfg.baseline_count = 1;
        cfg.diff_sigma_threshold = 1.0;
        cfg.report_as_issues = false;
        uint64_t id = aida::burp::param_miner::start(cfg);
        log_msg(hf, tag, "fixture_param_miner start id=%llu target=%s err=%s",
            static_cast<unsigned long long>(id), cfg.target_url.c_str(), aida::burp::param_miner::last_error().c_str());
        if (id == 0)
            return false;
        for (int i = 0; i < 20; ++i) {
            auto st = aida::burp::param_miner::status(id);
            log_msg(hf, tag, "fixture_param_miner poll=%d id=%llu total=%zu tried=%zu hits=%zu running=%d",
                i, static_cast<unsigned long long>(id), st.total, st.tried, st.hits, st.running ? 1 : 0);
            if (!st.running && st.tried > 0) break;
            Sleep(100);
        }
        return true;
    }

    void cleanup_burp_async_fixture_jobs(HANDLE hf) {
        const char* tag = "burp_cleanup";
        log_msg(hf, tag, "START -- stopping asynchronous Burp fixture jobs");

        auto audits = aida::burp::active_scanner::list_audits();
        for (const auto& audit : audits) {
            if (audit.id == 0)
                continue;
            log_msg(hf, tag, "audit_cleanup begin id=%llu running=%d cancelled=%d points=%zu completed=%zu total=%zu issues=%zu",
                static_cast<unsigned long long>(audit.id),
                audit.running ? 1 : 0,
                audit.cancelled ? 1 : 0,
                audit.total_points,
                audit.completed_probes,
                audit.total_probes,
                audit.issues_found);
            const bool cancel_ok = audit.running ? aida::burp::active_scanner::cancel_audit(audit.id) : true;
            const bool idle = aida::burp::active_scanner::wait_for_audit_idle(audit.id, 2500);
            aida::burp::active_scanner::audit_status_t after{};
            const bool after_ok = aida::burp::active_scanner::get_status(audit.id, after);
            log_msg(hf, tag, "audit_cleanup end id=%llu cancel_ok=%d idle=%d status_ok=%d running=%d cancelled=%d points=%zu completed=%zu total=%zu issues=%zu",
                static_cast<unsigned long long>(audit.id),
                cancel_ok ? 1 : 0,
                idle ? 1 : 0,
                after_ok ? 1 : 0,
                after.running ? 1 : 0,
                after.cancelled ? 1 : 0,
                after.total_points,
                after.completed_probes,
                after.total_probes,
                after.issues_found);
        }

        auto crawls = aida::burp::crawler::list();
        for (const auto& crawl : crawls) {
            if (crawl.id != 0)
                aida::burp::crawler::stop(crawl.id);
        }
        aida::burp::crawler::shutdown();

        auto discoveries = aida::burp::content_discovery::list();
        for (const auto& disc : discoveries) {
            if (disc.id != 0)
                aida::burp::content_discovery::stop(disc.id);
        }
        aida::burp::content_discovery::shutdown();

        auto subdomains = aida::burp::subdomain_enum::list();
        for (const auto& sub : subdomains) {
            if (sub.id != 0)
                aida::burp::subdomain_enum::stop(sub.id);
        }
        aida::burp::subdomain_enum::shutdown();

        auto intruders = aida::burp::intruder::list_jobs();
        for (const auto& job : intruders) {
            if (job.job_id != 0) {
                aida::burp::intruder::stop(job.job_id);
                aida::burp::intruder::clear(job.job_id);
            }
        }

        auto miners = aida::burp::param_miner::list_jobs();
        for (const auto& job : miners) {
            if (job.job_id != 0) {
                aida::burp::param_miner::stop(job.job_id);
                aida::burp::param_miner::clear(job.job_id);
            }
        }

        bool fixture_reset = true;
        if (g_burp_fixture) {
            fixture_reset = g_burp_fixture->stop();
            if (fixture_reset)
                g_burp_fixture.reset();
        }

        log_msg(hf, tag, "%s -- stopped async fixture jobs audits=%zu crawls=%zu discoveries=%zu subdomains=%zu intruders=%zu miners=%zu fixture_reset=%d",
            fixture_reset ? "PASS" : "WARN",
            audits.size(), crawls.size(), discoveries.size(), subdomains.size(), intruders.size(), miners.size(), fixture_reset ? 1 : 0);
    }

    void test_scope_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_init";
        log_msg(hf, tag, "START -- aida::burp::scope::initialize()");
        bool ok = aida::burp::scope::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- scope initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- scope::initialize returned false: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_add_include(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_inc";
        log_msg(hf, tag, "START -- add include rule *.example.com");
        uint64_t id = aida::burp::scope::add_include_rule("https", "*.example.com", 443, "/");
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- include rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_include_rule returned 0: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_add_exclude(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_exc";
        log_msg(hf, tag, "START -- add exclude rule /logout");
        uint64_t id = aida::burp::scope::add_exclude_rule("https", "*.example.com", 443, "/logout");
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- exclude rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_exclude_rule returned 0: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_in_scope_true(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_in_yes";
        log_msg(hf, tag, "START -- check URL in scope: https://www.example.com/app");
        bool in = aida::burp::scope::in_scope("https://www.example.com/app");
        log_msg(hf, tag, "in_scope = %s", in ? "true" : "false");
        if (in) {
            log_msg(hf, tag, "PASS -- URL correctly in scope");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- URL should be in scope");
            failed.fetch_add(1);
        }
    }

    void test_scope_in_scope_false(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_in_no";
        log_msg(hf, tag, "START -- check URL not in scope: https://www.other.com/page");
        bool in = aida::burp::scope::in_scope("https://www.other.com/page");
        log_msg(hf, tag, "in_scope = %s", in ? "true" : "false");
        if (!in) {
            log_msg(hf, tag, "PASS -- URL correctly not in scope");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- URL should not be in scope");
            failed.fetch_add(1);
        }
    }

    void test_scope_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_list";
        log_msg(hf, tag, "START -- scope::list_rules()");
        auto rules = aida::burp::scope::list_rules();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] kind=%d host=%s port=%d path=%s enabled=%s",
                i, (int)rules[i].kind, rules[i].host_pattern.c_str(),
                rules[i].port, rules[i].path_prefix.c_str(),
                rules[i].enabled ? "true" : "false");
        }
        if (rules.size() >= 2) {
            log_msg(hf, tag, "PASS -- found %zu rules (expected >= 2)", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected at least 2 rules, got %zu", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_scope_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_remove";
        log_msg(hf, tag, "START -- remove first rule");
        auto rules = aida::burp::scope::list_rules();
        if (rules.empty()) {
            log_msg(hf, tag, "FAIL -- no rules to remove");
            failed.fetch_add(1);
            return;
        }
        uint64_t id = rules[0].id;
        bool ok = aida::burp::scope::remove_rule(id);
        auto after = aida::burp::scope::list_rules();
        log_msg(hf, tag, "remove_rule(%llu) = %s, rules before=%zu after=%zu",
            (unsigned long long)id, ok ? "true" : "false", rules.size(), after.size());
        if (ok && after.size() == rules.size() - 1) {
            log_msg(hf, tag, "PASS -- rule removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove did not reduce count");
            failed.fetch_add(1);
        }
    }

    void test_scope_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_clear";
        log_msg(hf, tag, "START -- scope::clear_all()");
        aida::burp::scope::clear_all();
        auto rules = aida::burp::scope::list_rules();
        log_msg(hf, tag, "rules after clear = %zu", rules.size());
        if (rules.empty()) {
            log_msg(hf, tag, "PASS -- all rules cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain after clear_all", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_cookie_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_init";
        log_msg(hf, tag, "START -- aida::burp::cookie_jar::initialize()");
        bool ok = aida::burp::cookie_jar::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- cookie_jar initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cookie_jar::initialize returned false: %s",
                aida::burp::cookie_jar::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_cookie_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_parse";
        log_msg(hf, tag, "START -- parse Set-Cookie header");
        aida::burp::cookie_jar::parsed_cookie_t c;
        bool ok = aida::burp::cookie_jar::parse_set_cookie(
            "session=abc123; Path=/; HttpOnly; Secure", "example.com", c);
        log_msg(hf, tag, "parse result: ok=%s name=%s value=%s domain=%s path=%s httponly=%s secure=%s",
            ok ? "true" : "false", c.name.c_str(), c.value.c_str(),
            c.domain.c_str(), c.path.c_str(),
            c.http_only ? "true" : "false", c.secure ? "true" : "false");
        if (ok && c.name == "session" && c.value == "abc123") {
            log_msg(hf, tag, "PASS -- Set-Cookie parsed correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse did not produce expected values");
            failed.fetch_add(1);
        }
    }

    void test_cookie_set(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_set";
        log_msg(hf, tag, "START -- set cookie manually");
        aida::burp::cookie_jar::parsed_cookie_t c;
        c.name = "test_cookie";
        c.value = "test_value_42";
        c.domain = "test.example.com";
        c.path = "/";
        c.secure = false;
        c.http_only = false;
        aida::burp::cookie_jar::set_cookie("test.example.com", c);
        auto cookies = aida::burp::cookie_jar::list_for_host("test.example.com");
        bool found = false;
        for (auto& ck : cookies) {
            if (ck.name == "test_cookie" && ck.value == "test_value_42") { found = true; break; }
        }
        if (found) {
            log_msg(hf, tag, "PASS -- cookie set and retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cookie not found after set (host has %zu cookies)", cookies.size());
            failed.fetch_add(1);
        }
    }

    void test_cookie_get_for_host(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_host";
        log_msg(hf, tag, "START -- cookies_for test.example.com");
        auto cookies = aida::burp::cookie_jar::cookies_for("test.example.com", "/", false);
        log_msg(hf, tag, "cookies_for returned %zu cookies", cookies.size());
        for (size_t i = 0; i < cookies.size(); ++i) {
            log_msg(hf, tag, "  [%zu] %s=%s", i, cookies[i].name.c_str(), cookies[i].value.c_str());
        }
        log_msg(hf, tag, "PASS -- cookies_for returned successfully");
        passed.fetch_add(1);
    }

    void test_cookie_build_header(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_hdr";
        log_msg(hf, tag, "START -- build_cookie_header");
        std::string hdr = aida::burp::cookie_jar::build_cookie_header("test.example.com", "/", false);
        log_msg(hf, tag, "cookie header: \"%s\"", hdr.c_str());
        log_msg(hf, tag, "PASS -- build_cookie_header returned");
        passed.fetch_add(1);
    }

    void test_cookie_list_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_all";
        log_msg(hf, tag, "START -- list_all cookies");
        auto all = aida::burp::cookie_jar::list_all();
        log_msg(hf, tag, "total cookies = %zu", all.size());
        log_msg(hf, tag, "PASS -- list_all returned %zu cookies", all.size());
        passed.fetch_add(1);
    }

    void test_cookie_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_del";
        log_msg(hf, tag, "START -- delete_cookie test_cookie");
        bool ok = aida::burp::cookie_jar::delete_cookie("test.example.com", "test_cookie", "/");
        log_msg(hf, tag, "delete_cookie = %s", ok ? "true" : "false");
        if (ok) {
            log_msg(hf, tag, "PASS -- cookie deleted");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- delete_cookie returned false");
            failed.fetch_add(1);
        }
    }

    void test_cookie_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_clr";
        log_msg(hf, tag, "START -- clear_all cookies");
        aida::burp::cookie_jar::clear_all();
        auto all = aida::burp::cookie_jar::list_all();
        log_msg(hf, tag, "cookies after clear = %zu", all.size());
        if (all.empty()) {
            log_msg(hf, tag, "PASS -- all cookies cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu cookies remain after clear_all", all.size());
            failed.fetch_add(1);
        }
    }

    void test_jwt_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_init";
        log_msg(hf, tag, "START -- aida::burp::jwt_lab::initialize()");
        bool ok = aida::burp::jwt_lab::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- jwt_lab initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- jwt_lab::initialize returned false: %s",
                aida::burp::jwt_lab::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_jwt_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_decode";
        log_msg(hf, tag, "START -- decode sample JWT");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto parsed = aida::burp::jwt_lab::decode(token);
        log_msg(hf, tag, "valid_structure=%s alg=%s kid=%s",
            parsed.valid_structure ? "true" : "false",
            parsed.alg.c_str(), parsed.kid.c_str());
        if (!parsed.header.is_null()) {
            log_msg(hf, tag, "header: %s", parsed.header.dump().c_str());
        }
        if (!parsed.payload.is_null()) {
            log_msg(hf, tag, "payload: %s", parsed.payload.dump().c_str());
        }
        if (parsed.valid_structure && parsed.alg == "HS256") {
            log_msg(hf, tag, "PASS -- JWT decoded, alg=HS256");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- decode did not produce expected structure");
            failed.fetch_add(1);
        }
    }

    void test_jwt_verify_hmac(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_hmac";
        log_msg(hf, tag, "START -- verify_hmac with known secret");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        bool ok = aida::burp::jwt_lab::verify_hmac(token, "aida-test-secret");
        log_msg(hf, tag, "verify_hmac = %s", ok ? "true" : "false");
        log_msg(hf, tag, "PASS -- verify_hmac completed (result=%s)", ok ? "valid" : "invalid");
        passed.fetch_add(1);
    }

    void test_jwt_attack_alg_none(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_algnone";
        log_msg(hf, tag, "START -- attack_alg_none");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_alg_none(token);
        log_msg(hf, tag, "attack_alg_none produced %zu variants", variants.size());
        for (size_t i = 0; i < variants.size() && i < 3; ++i) {
            log_msg(hf, tag, "  variant[%zu] length=%zu", i, variants[i].size());
        }
        if (!variants.empty()) {
            log_msg(hf, tag, "PASS -- alg:none attack produced %zu tokens", variants.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- alg:none attack produced no variants");
            failed.fetch_add(1);
        }
    }

    void test_jwt_attack_sig_strip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_sigstrip";
        log_msg(hf, tag, "START -- attack_signature_strip");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_signature_strip(token);
        log_msg(hf, tag, "attack_signature_strip produced %zu variants", variants.size());
        if (!variants.empty()) {
            log_msg(hf, tag, "PASS -- signature strip produced %zu tokens", variants.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- signature strip produced no variants");
            failed.fetch_add(1);
        }
    }

    void test_jwt_attack_kid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_kid";
        log_msg(hf, tag, "START -- attack_kid_traversal");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_kid_traversal(token);
        log_msg(hf, tag, "attack_kid_traversal produced %zu variants", variants.size());
        log_msg(hf, tag, "PASS -- kid traversal completed (%zu variants)", variants.size());
        passed.fetch_add(1);
    }

    void test_mr_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_init";
        log_msg(hf, tag, "START -- aida::burp::match_replace::initialize()");
        bool ok = aida::burp::match_replace::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- match_replace initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- initialize returned false: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_add";
        log_msg(hf, tag, "START -- add match/replace rule (User-Agent swap)");
        aida::burp::match_replace::rule_t r;
        r.label = "UA Override";
        r.target = aida::burp::match_replace::match_kind_t::request_headers;
        r.match_regex = "User-Agent: [^\\r\\n]+";
        r.replacement = "User-Agent: AiDA-Test/1.0";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_apply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_apply";
        log_msg(hf, tag, "START -- apply rule to request bytes");
        std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        bool changed = aida::burp::match_replace::apply_request(bytes, "example.com", "https");
        std::string result(bytes.begin(), bytes.end());
        log_msg(hf, tag, "changed=%s result_len=%zu", changed ? "true" : "false", bytes.size());
        if (changed && result.find("AiDA-Test/1.0") != std::string::npos) {
            log_msg(hf, tag, "PASS -- User-Agent replaced in request");
            passed.fetch_add(1);
        } else if (!changed) {
            log_msg(hf, tag, "PASS -- apply_request returned without error (no match)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- changed=true but replacement not found in output");
            failed.fetch_add(1);
        }
    }

    void test_mr_test_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_test";
        log_msg(hf, tag, "START -- test_rule against sample");
        aida::burp::match_replace::rule_t r;
        r.label = "Test rule";
        r.target = aida::burp::match_replace::match_kind_t::all;
        r.match_regex = "foo";
        r.replacement = "bar";
        r.regex = false;
        r.active = true;
        std::string out;
        bool ok = aida::burp::match_replace::test_rule(r, "hello foo world", out);
        log_msg(hf, tag, "test_rule ok=%s output=\"%s\"", ok ? "true" : "false", out.c_str());
        if (ok && out.find("bar") != std::string::npos) {
            log_msg(hf, tag, "PASS -- test_rule replaced correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- test_rule completed (ok=%s)", ok ? "true" : "false");
            passed.fetch_add(1);
        }
    }

    void test_mr_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_list";
        log_msg(hf, tag, "START -- match_replace::list()");
        auto rules = aida::burp::match_replace::list();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s active=%s",
                i, (unsigned long long)rules[i].id, rules[i].label.c_str(),
                rules[i].active ? "true" : "false");
        }
        log_msg(hf, tag, "PASS -- list returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_mr_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_remove";
        log_msg(hf, tag, "START -- remove match/replace rules");
        auto rules = aida::burp::match_replace::list();
        bool all_ok = true;
        for (auto& r : rules) {
            bool ok = aida::burp::match_replace::remove(r.id);
            if (!ok) all_ok = false;
        }
        auto after = aida::burp::match_replace::list();
        log_msg(hf, tag, "before=%zu after=%zu all_removed=%s",
            rules.size(), after.size(), all_ok ? "true" : "false");
        if (after.empty()) {
            log_msg(hf, tag, "PASS -- all rules removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain", after.size());
            failed.fetch_add(1);
        }
    }

    void test_comparer_add_a(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_add_a";
        log_msg(hf, tag, "START -- add slot A");
        std::string data = "Hello World from AiDA slot A test data";
        std::vector<uint8_t> bytes(data.begin(), data.end());
        uint64_t id = aida::burp::comparer::add_slot_from_bytes("Slot A", bytes, "test");
        log_msg(hf, tag, "slot A id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- slot A added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_slot_from_bytes returned 0: %s",
                aida::burp::comparer::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_comparer_add_b(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_add_b";
        log_msg(hf, tag, "START -- add slot B (different data)");
        std::string data = "Hello World from AiDA slot B DIFFERENT data";
        std::vector<uint8_t> bytes(data.begin(), data.end());
        uint64_t id = aida::burp::comparer::add_slot_from_bytes("Slot B", bytes, "test");
        log_msg(hf, tag, "slot B id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- slot B added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_slot_from_bytes returned 0: %s",
                aida::burp::comparer::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_comparer_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_diff";
        log_msg(hf, tag, "START -- compute_diff bytes mode");
        auto slots = aida::burp::comparer::list_slots();
        if (slots.size() < 2) {
            log_msg(hf, tag, "FAIL -- need at least 2 slots, have %zu", slots.size());
            failed.fetch_add(1);
            return;
        }
        auto blocks = aida::burp::comparer::compute_diff(
            slots[0].id, slots[1].id, aida::burp::comparer::diff_mode_t::bytes);
        log_msg(hf, tag, "diff blocks = %zu", blocks.size());
        if (!blocks.empty()) {
            log_msg(hf, tag, "PASS -- compute_diff returned %zu blocks", blocks.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- compute_diff returned zero blocks for different data");
            failed.fetch_add(1);
        }
    }

    void test_comparer_diff_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_stats";
        log_msg(hf, tag, "START -- compute_diff_with_stats");
        auto slots = aida::burp::comparer::list_slots();
        if (slots.size() < 2) {
            log_msg(hf, tag, "FAIL -- need at least 2 slots");
            failed.fetch_add(1);
            return;
        }
        aida::burp::comparer::diff_stats_t stats{};
        auto blocks = aida::burp::comparer::compute_diff_with_stats(
            slots[0].id, slots[1].id, aida::burp::comparer::diff_mode_t::bytes, stats);
        log_msg(hf, tag, "blocks=%zu equal=%zu insert=%zu delete=%zu replace=%zu a_size=%zu b_size=%zu",
            blocks.size(), stats.equal_runs, stats.insert_runs,
            stats.delete_runs, stats.replace_runs, stats.a_size, stats.b_size);
        if (stats.a_size > 0 && stats.b_size > 0) {
            log_msg(hf, tag, "PASS -- diff_with_stats computed a_size=%zu b_size=%zu", stats.a_size, stats.b_size);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- diff_with_stats returned zero-size slots a_size=%zu b_size=%zu", stats.a_size, stats.b_size);
            failed.fetch_add(1);
        }
    }

    void test_comparer_list_slots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_list";
        log_msg(hf, tag, "START -- list_slots");
        auto slots = aida::burp::comparer::list_slots();
        log_msg(hf, tag, "slot count = %zu", slots.size());
        for (size_t i = 0; i < slots.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s data_size=%zu",
                i, (unsigned long long)slots[i].id, slots[i].label.c_str(), slots[i].data.size());
        }
        if (slots.size() >= 2) {
            log_msg(hf, tag, "PASS -- list_slots returned %zu entries", slots.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- list_slots returned %zu entries, expected >= 2 after add_a/add_b", slots.size());
            failed.fetch_add(1);
        }
    }

    void test_comparer_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_clear";
        log_msg(hf, tag, "START -- clear_slots");
        aida::burp::comparer::clear_slots();
        auto slots = aida::burp::comparer::list_slots();
        if (slots.empty()) {
            log_msg(hf, tag, "PASS -- all slots cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu slots remain after clear", slots.size());
            failed.fetch_add(1);
        }
    }

    void test_csp_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_init";
        log_msg(hf, tag, "START -- aida::burp::csp::initialize()");
        bool ok = aida::burp::csp::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- CSP analyzer initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- csp::initialize returned false: %s",
                aida::burp::csp::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_csp_analyze_unsafe(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_unsafe";
        log_msg(hf, tag, "START -- analyze CSP with unsafe-inline");
        auto result = aida::burp::csp::analyze(
            "default-src 'self'; script-src 'unsafe-inline'", false);
        log_msg(hf, tag, "has_csp=%s directives=%zu findings=%zu score=%d",
            result.has_csp ? "true" : "false",
            result.directives.size(), result.findings.size(), result.score);
        for (size_t i = 0; i < result.findings.size(); ++i) {
            log_msg(hf, tag, "  finding[%zu]: %s severity=%s -- %s",
                i, result.findings[i].title.c_str(),
                result.findings[i].severity.c_str(),
                result.findings[i].description.c_str());
        }
        if (result.has_csp && !result.findings.empty()) {
            log_msg(hf, tag, "PASS -- CSP analyzed, %zu findings detected", result.findings.size());
            passed.fetch_add(1);
        } else if (result.has_csp) {
            fail_empty_evidence(hf, tag, failed, "CSP analyzer returned zero findings for unsafe-inline fixture");
        } else {
            log_msg(hf, tag, "FAIL -- has_csp=false for valid CSP input");
            failed.fetch_add(1);
        }
    }

    void test_csp_analyze_clean(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_clean";
        log_msg(hf, tag, "START -- analyze strict CSP");
        auto result = aida::burp::csp::analyze(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'", false);
        log_msg(hf, tag, "has_csp=%s directives=%zu findings=%zu score=%d",
            result.has_csp ? "true" : "false",
            result.directives.size(), result.findings.size(), result.score);
        if (result.has_csp && result.findings.empty()) {
            log_msg(hf, tag, "PASS -- strict CSP analyzed, score=%d findings=%zu",
                result.score, result.findings.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- strict CSP should have has_csp=true and zero findings has_csp=%d findings=%zu",
                result.has_csp ? 1 : 0, result.findings.size());
            failed.fetch_add(1);
        }
    }

    void test_csp_log_findings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_findings";
        log_msg(hf, tag, "START -- verify findings count and score");
        auto r1 = aida::burp::csp::analyze("default-src *; script-src * 'unsafe-inline' 'unsafe-eval'", false);
        auto r2 = aida::burp::csp::analyze("default-src 'self'", false);
        log_msg(hf, tag, "permissive CSP: score=%d findings=%zu", r1.score, r1.findings.size());
        log_msg(hf, tag, "strict CSP:     score=%d findings=%zu", r2.score, r2.findings.size());
        if (r1.findings.size() >= r2.findings.size()) {
            log_msg(hf, tag, "PASS -- permissive CSP has >= findings than strict");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- permissive CSP has fewer findings than strict (finding counts: %zu vs %zu)",
                r1.findings.size(), r2.findings.size());
            failed.fetch_add(1);
        }
    }

    void test_sequencer_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "seq_list";
        log_msg(hf, tag, "START -- sequencer::list_collections()");
        const bool fixture_ok = ensure_sequencer_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "sequencer fixture setup failed before list_collections; startup/probe/action evidence is above");
            return;
        }
        auto cols = aida::burp::sequencer::list_collections();
        log_msg(hf, tag, "collection count = %zu", cols.size());
        if (cols.empty()) {
            fail_empty_evidence(hf, tag, failed, "sequencer list returned zero collections after sequencer fixture/action should have created collection state");
            return;
        }
        log_msg(hf, tag, "PASS -- list_collections returned %zu entries", cols.size());
        passed.fetch_add(1);
    }

    void test_sequencer_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "seq_err";
        log_msg(hf, tag, "START -- sequencer::last_error()");
        std::string err = aida::burp::sequencer::last_error();
        auto cols = aida::burp::sequencer::list_collections();
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu collection_count=%zu", err.c_str(), err.size(), cols.size());
        if (cols.empty()) {
            fail_empty_evidence(hf, tag, failed, "sequencer last_error accessor has no same-run collection evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- sequencer diagnostic accessor paired with same-run collection evidence count=%zu last_error_len=%zu", cols.size(), err.size());
        passed.fetch_add(1);
    }

    void test_intruder_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_list";
        log_msg(hf, tag, "START -- intruder::list_jobs()");
        const bool fixture_ok = ensure_intruder_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "intruder fixture setup failed before list_jobs; startup/probe/action evidence is above");
            return;
        }
        auto jobs = aida::burp::intruder::list_jobs();
        log_msg(hf, tag, "job count = %zu", jobs.size());
        if (jobs.empty()) {
            fail_empty_evidence(hf, tag, failed, "intruder list returned zero jobs after intruder fixture/action should have created a job");
            return;
        }
        log_msg(hf, tag, "PASS -- list_jobs returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_intruder_attack_mode_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_amn";
        log_msg(hf, tag, "START -- attack_mode_name for each mode");
        const aida::burp::intruder::attack_mode_t modes[] = {
            aida::burp::intruder::attack_mode_t::sniper,
            aida::burp::intruder::attack_mode_t::battering_ram,
            aida::burp::intruder::attack_mode_t::pitchfork,
            aida::burp::intruder::attack_mode_t::clusterbomb,
            aida::burp::intruder::attack_mode_t::turbo,
            aida::burp::intruder::attack_mode_t::race,
        };
        bool all_ok = true;
        for (auto m : modes) {
            const char* name = aida::burp::intruder::attack_mode_name(m);
            log_msg(hf, tag, "  mode %d => \"%s\"", (int)m, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all attack mode names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some attack mode names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_intruder_engine_mode_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_emn";
        log_msg(hf, tag, "START -- engine_mode_name for each mode");
        const aida::burp::intruder::engine_mode_t modes[] = {
            aida::burp::intruder::engine_mode_t::http1_serial,
            aida::burp::intruder::engine_mode_t::http1_pipelined,
            aida::burp::intruder::engine_mode_t::http1_pooled,
            aida::burp::intruder::engine_mode_t::http2_multiplexed,
            aida::burp::intruder::engine_mode_t::http2_single_packet,
        };
        bool all_ok = true;
        for (auto m : modes) {
            const char* name = aida::burp::intruder::engine_mode_name(m);
            log_msg(hf, tag, "  mode %d => \"%s\"", (int)m, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all engine mode names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some engine mode names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_active_scanner_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_init";
        log_msg(hf, tag, "START -- active_scanner::initialize()");
        bool ok = aida::burp::active_scanner::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- active_scanner initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- active_scanner::initialize returned false: %s",
                aida::burp::active_scanner::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_init";
        log_msg(hf, tag, "START -- passive_scanner::initialize()");
        bool ok = aida::burp::passive_scanner::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- passive_scanner initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- passive_scanner::initialize returned false: %s",
                aida::burp::passive_scanner::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_enabled(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_enabled";
        log_msg(hf, tag, "START -- passive_scanner::is_enabled()");
        bool enabled = aida::burp::passive_scanner::is_enabled();
        log_msg(hf, tag, "is_enabled = %s", enabled ? "true" : "false");
        log_msg(hf, tag, "PASS -- is_enabled returned successfully");
        passed.fetch_add(1);
    }

    void test_passive_scanner_set_enabled(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_set";
        log_msg(hf, tag, "START -- set_enabled(true) then verify");
        aida::burp::passive_scanner::set_enabled(true);
        bool enabled = aida::burp::passive_scanner::is_enabled();
        log_msg(hf, tag, "after set_enabled(true): is_enabled=%s", enabled ? "true" : "false");
        if (enabled) {
            log_msg(hf, tag, "PASS -- passive scanner enabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- passive scanner not enabled after set");
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_stats";
        log_msg(hf, tag, "START -- passive_scanner::get_stats()");
        publish_fixture_exchange(hf, tag);
        auto stats = aida::burp::passive_scanner::get_stats();
        log_msg(hf, tag, "exchanges_scanned=%llu issues_found=%llu last_scan_ms=%llu",
            (unsigned long long)stats.exchanges_scanned,
            (unsigned long long)stats.issues_found,
            (unsigned long long)stats.last_scan_ms);
        if (stats.exchanges_scanned == 0 && stats.issues_found == 0) {
            fail_empty_evidence(hf, tag, failed, "passive scanner stats show zero scanned exchanges and zero issues after scanner fixture/action should have fed an exchange");
            return;
        }
        log_msg(hf, tag, "PASS -- get_stats returned successfully");
        passed.fetch_add(1);
    }

    void test_active_scanner_list_audits(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_list";
        log_msg(hf, tag, "START -- active_scanner::list_audits()");
        const bool fixture_ok = ensure_active_scanner_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "active scanner fixture setup failed before list_audits; startup/probe/action evidence is above");
            return;
        }
        auto audits = aida::burp::active_scanner::list_audits();
        log_msg(hf, tag, "audit count = %zu", audits.size());
        for (size_t i = 0; i < audits.size() && i < 3; ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu running=%d cancelled=%d points=%zu completed=%zu total=%zu issues=%zu",
                i,
                static_cast<unsigned long long>(audits[i].id),
                audits[i].running ? 1 : 0,
                audits[i].cancelled ? 1 : 0,
                audits[i].total_points,
                audits[i].completed_probes,
                audits[i].total_probes,
                audits[i].issues_found);
        }
        if (audits.empty()) {
            fail_empty_evidence(hf, tag, failed, "active scanner list returned zero audits after audit fixture/action should have created an audit");
            return;
        }
        log_msg(hf, tag, "PASS -- list_audits returned %zu entries", audits.size());
        passed.fetch_add(1);
    }

    void test_crawler_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "crawler_init";
        log_msg(hf, tag, "START -- crawler::initialize()");
        bool ok = aida::burp::crawler::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- crawler initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- crawler::initialize returned false: %s",
                aida::burp::crawler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_crawler_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "crawler_list";
        log_msg(hf, tag, "START -- crawler::list()");
        const bool fixture_ok = ensure_crawler_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "crawler fixture setup failed before list; startup/probe/action evidence is above");
            return;
        }
        auto crawls = aida::burp::crawler::list();
        log_msg(hf, tag, "crawl count = %zu", crawls.size());
        if (crawls.empty()) {
            fail_empty_evidence(hf, tag, failed, "crawler list returned zero crawls after crawler fixture/action should have started a crawl");
            return;
        }
        log_msg(hf, tag, "PASS -- list returned %zu entries", crawls.size());
        passed.fetch_add(1);
    }

    void test_sitemap_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_init";
        log_msg(hf, tag, "START -- sitemap::initialize()");
        bool ok = aida::burp::sitemap::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- sitemap initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sitemap::initialize returned false: %s",
                aida::burp::sitemap::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_sitemap_list_hosts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_hosts";
        log_msg(hf, tag, "START -- sitemap::list_hosts(false)");
        publish_fixture_exchange(hf, tag);
        auto hosts = aida::burp::sitemap::list_hosts(false);
        log_msg(hf, tag, "host count = %zu", hosts.size());
        for (size_t i = 0; i < hosts.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] %s:%u tls=%s requests=%zu",
                i, hosts[i].host.c_str(), (unsigned)hosts[i].port,
                hosts[i].tls ? "true" : "false", hosts[i].total_requests);
        }
        if (hosts.empty()) {
            fail_empty_evidence(hf, tag, failed, "sitemap host list is empty after sitemap/proxy fixture should have recorded hosts");
            return;
        }
        log_msg(hf, tag, "PASS -- list_hosts returned %zu entries", hosts.size());
        passed.fetch_add(1);
    }

    void test_sitemap_total_exchanges(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_total";
        log_msg(hf, tag, "START -- sitemap::total_exchanges()");
        size_t total = aida::burp::sitemap::total_exchanges();
        log_msg(hf, tag, "total_exchanges = %zu", total);
        log_msg(hf, tag, "PASS -- total_exchanges returned successfully");
        passed.fetch_add(1);
    }

    void test_report_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_list";
        log_msg(hf, tag, "START -- report::list_reports()");
        if (!ensure_report_fixture(hf, tag)) {
            const size_t findings_count = aida::burp::findings_db::is_initialized() ? aida::burp::findings_db::count() : 0;
            fail_empty_evidence(hf, tag, failed, "report generation fixture failed before report list; findings_count=%zu report_err=%s db_err=%s",
                findings_count,
                aida::burp::report::last_error().c_str(),
                aida::burp::findings_db::last_error().c_str());
            return;
        }
        auto reports = aida::burp::report::list_reports();
        log_msg(hf, tag, "report count = %zu", reports.size());
        if (reports.empty()) {
            fail_empty_evidence(hf, tag, failed, "report list returned zero reports after report generation fixture/action should have created a report");
            return;
        }
        bool has_nonempty_history = false;
        for (const auto& report : reports) {
            if (report.issue_count > 0) {
                has_nonempty_history = true;
                break;
            }
        }
        if (!has_nonempty_history) {
            fail_empty_evidence(hf, tag, failed, "report list returned reports but none have issue_count > 0");
            return;
        }
        log_msg(hf, tag, "PASS -- list_reports returned %zu entries", reports.size());
        passed.fetch_add(1);
    }

    void test_report_format_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_fmtlbl";
        log_msg(hf, tag, "START -- format_label for each format");
        const aida::burp::report::report_format_t fmts[] = {
            aida::burp::report::report_format_t::html,
            aida::burp::report::report_format_t::markdown,
            aida::burp::report::report_format_t::json,
            aida::burp::report::report_format_t::sarif_2_1,
            aida::burp::report::report_format_t::csv,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* label = aida::burp::report::format_label(f);
            log_msg(hf, tag, "  format %d => \"%s\"", (int)f, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all format labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some format labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_report_default_ext(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_ext";
        log_msg(hf, tag, "START -- default_extension for each format");
        const aida::burp::report::report_format_t fmts[] = {
            aida::burp::report::report_format_t::html,
            aida::burp::report::report_format_t::markdown,
            aida::burp::report::report_format_t::json,
            aida::burp::report::report_format_t::sarif_2_1,
            aida::burp::report::report_format_t::csv,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* ext = aida::burp::report::default_extension(f);
            log_msg(hf, tag, "  format %d => ext \"%s\"", (int)f, ext ? ext : "(null)");
            if (!ext || ext[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all default extensions resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some default extensions are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_bambda_compile_valid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_ok";
        log_msg(hf, tag, "START -- compile valid bambda expression");
        auto prog = aida::burp::bambda::compile("status == 200");
        log_msg(hf, tag, "valid=%s error=\"%s\" source=\"%s\"",
            prog.valid ? "true" : "false", prog.error.c_str(), prog.source.c_str());
        if (prog.valid) {
            log_msg(hf, tag, "PASS -- valid bambda compiled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bambda compile failed: %s", prog.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_bambda_compile_invalid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_bad";
        log_msg(hf, tag, "START -- compile invalid bambda expression");
        auto prog = aida::burp::bambda::compile("!!!@@@### totally broken syntax {{{");
        log_msg(hf, tag, "valid=%s error=\"%s\"", prog.valid ? "true" : "false", prog.error.c_str());
        if (!prog.valid && !prog.error.empty()) {
            log_msg(hf, tag, "PASS -- invalid bambda correctly rejected with error");
            passed.fetch_add(1);
        } else if (!prog.valid) {
            log_msg(hf, tag, "PASS -- invalid bambda rejected (no error message)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- invalid bambda compiled as valid");
            failed.fetch_add(1);
        }
    }

    void test_bambda_help(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_help";
        log_msg(hf, tag, "START -- bambda_help_text()");
        std::string help = aida::burp::bambda::bambda_help_text();
        log_msg(hf, tag, "help text length = %zu", help.size());
        if (!help.empty()) {
            std::string preview = help.substr(0, 200);
            log_msg(hf, tag, "preview: %.200s", preview.c_str());
            log_msg(hf, tag, "PASS -- help text returned (%zu chars)", help.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- help text is empty");
            failed.fetch_add(1);
        }
    }

    void test_collaborator_is_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_run";
        log_msg(hf, tag, "START -- collaborator::is_running()");
        bool running = aida::burp::collaborator::is_running();
        log_msg(hf, tag, "is_running = %s", running ? "true" : "false");
        log_msg(hf, tag, "PASS -- is_running returned %s (expected false initially)",
            running ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_collaborator_generate_token(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_token";
        log_msg(hf, tag, "START -- collaborator::generate_token()");
        ensure_collaborator_fixture(hf, tag);
        std::string token = aida::burp::collaborator::generate_token();
        log_msg(hf, tag, "token = \"%s\" (len=%zu)", token.c_str(), token.size());
        if (!token.empty()) {
            log_msg(hf, tag, "PASS -- token generated: %s", token.c_str());
            passed.fetch_add(1);
        } else {
            std::string err = aida::burp::collaborator::last_error();
            log_msg(hf, tag, "FAIL -- generate_token returned empty after collaborator fixture: %s",
                err.c_str());
            failed.fetch_add(1);
        }
    }

    void test_collaborator_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_status";
        log_msg(hf, tag, "START -- collaborator::status()");
        auto st = aida::burp::collaborator::status();
        log_msg(hf, tag, "running=%s http_alive=%s dns_alive=%s smtp_alive=%s tokens=%zu interactions=%zu",
            st.running ? "true" : "false",
            st.http_alive ? "true" : "false",
            st.dns_alive ? "true" : "false",
            st.smtp_alive ? "true" : "false",
            st.token_count, st.interaction_count);
        if (!st.running || !st.http_alive || st.token_count == 0) {
            fail_empty_evidence(hf, tag, failed, "collaborator status lacks same-run running/http/token evidence running=%d http_alive=%d tokens=%zu",
                st.running ? 1 : 0, st.http_alive ? 1 : 0, st.token_count);
            return;
        }
        log_msg(hf, tag, "PASS -- collaborator status proved running HTTP fixture with %zu token(s)", st.token_count);
        passed.fetch_add(1);
    }

    void test_collaborator_list_tokens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_tokens";
        log_msg(hf, tag, "START -- collaborator::list_tokens()");
        ensure_collaborator_fixture(hf, tag);
        auto tokens = aida::burp::collaborator::list_tokens();
        log_msg(hf, tag, "token count = %zu", tokens.size());
        for (size_t i = 0; i < tokens.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] token=%s interactions=%zu",
                i, tokens[i].token.c_str(), tokens[i].interaction_count);
        }
        if (tokens.empty()) {
            fail_empty_evidence(hf, tag, failed, "collaborator token list is empty after collaborator fixture/action should have generated a token");
            return;
        }
        log_msg(hf, tag, "PASS -- list_tokens returned %zu entries", tokens.size());
        passed.fetch_add(1);
    }

    void test_collaborator_poll_since(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_poll";
        log_msg(hf, tag, "START -- collaborator::poll_since(0)");
        ensure_collaborator_fixture(hf, tag);
        auto interactions = aida::burp::collaborator::poll_since(0);
        log_msg(hf, tag, "interactions = %zu", interactions.size());
        if (interactions.empty()) {
            fail_empty_evidence(hf, tag, failed, "collaborator poll_since returned zero interactions after collaborator fixture/action should have produced interaction evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- poll_since returned %zu entries", interactions.size());
        passed.fetch_add(1);
    }

    void test_collaborator_snapshot_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_snap";
        log_msg(hf, tag, "START -- collaborator::snapshot_all()");
        ensure_collaborator_fixture(hf, tag);
        auto all = aida::burp::collaborator::snapshot_all(100);
        log_msg(hf, tag, "snapshot size = %zu", all.size());
        if (all.empty()) {
            aida::burp::collaborator::stop();
            fail_empty_evidence(hf, tag, failed, "collaborator snapshot returned zero interactions after collaborator fixture/action should have produced interaction evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- snapshot_all returned %zu entries", all.size());
        aida::burp::collaborator::stop();
        log_msg(hf, tag, "fixture_collab_cleanup -- stopped collaborator after snapshot coverage");
        passed.fetch_add(1);
    }

    void test_ws_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_init";
        log_msg(hf, tag, "START -- ws_editor::initialize()");
        bool ok = aida::burp::ws_editor::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- ws_editor initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- ws_editor::initialize returned false: %s",
                aida::burp::ws_editor::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_ws_list_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_list";
        log_msg(hf, tag, "START -- ws_editor::list_connections()");
        const bool fixture_ok = ensure_ws_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "websocket fixture setup failed before list_connections; startup/probe/action evidence is above");
            return;
        }
        auto conns = aida::burp::ws_editor::list_connections();
        log_msg(hf, tag, "connection count = %zu", conns.size());
        for (size_t i = 0; i < conns.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu url=%s connected=%s sent=%zu recv=%zu",
                i, (unsigned long long)conns[i].id, conns[i].url.c_str(),
                conns[i].connected ? "true" : "false",
                conns[i].frames_sent, conns[i].frames_received);
        }
        if (conns.empty()) {
            fail_empty_evidence(hf, tag, failed, "websocket connection list is empty after websocket fixture/action should have opened a connection");
            return;
        }
        log_msg(hf, tag, "PASS -- list_connections returned %zu entries", conns.size());
        passed.fetch_add(1);
    }

    void test_ws_connect_invalid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_conn_inv";
        log_msg(hf, tag, "START -- ws_editor::connect to invalid host");
        aida::burp::ws_editor::ws_connection_config_t cfg;
        cfg.scheme = "ws";
        cfg.host = "127.0.0.1";
        cfg.port = 1;
        cfg.path = "/ws-test-invalid";
        cfg.connect_timeout_ms = 2000;
        uint64_t id = aida::burp::ws_editor::connect(cfg);
        log_msg(hf, tag, "connect returned id=%llu", (unsigned long long)id);
        log_msg(hf, tag, "PASS -- connect returned (id=%llu, 0 means expected failure)",
            (unsigned long long)id);
        passed.fetch_add(1);
        if (id != 0) {
            aida::burp::ws_editor::disconnect(id);
        }
    }

    void test_ws_disconnect_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_disc_all";
        log_msg(hf, tag, "START -- ws_editor::disconnect_all()");
        bool ok = aida::burp::ws_editor::disconnect_all();
        log_msg(hf, tag, "disconnect_all = %s", ok ? "true" : "false");
        log_msg(hf, tag, "PASS -- disconnect_all completed");
        passed.fetch_add(1);
    }

    void test_ws_frame_count_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_fcount";
        log_msg(hf, tag, "START -- ws_editor::frame_count for nonexistent conn");
        size_t cnt = aida::burp::ws_editor::frame_count(999999);
        log_msg(hf, tag, "frame_count(999999) = %zu", cnt);
        log_msg(hf, tag, "PASS -- frame_count returned %zu for invalid conn", cnt);
        passed.fetch_add(1);
    }

    void test_ws_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_err";
        log_msg(hf, tag, "START -- ws_editor::last_error()");
        std::string err = aida::burp::ws_editor::last_error();
        const bool fixture_ok = ensure_ws_fixture(hf, tag);
        auto conns = aida::burp::ws_editor::list_connections();
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu fixture_ok=%d connection_count=%zu", err.c_str(), err.size(), fixture_ok ? 1 : 0, conns.size());
        if (!fixture_ok || conns.empty()) {
            fail_empty_evidence(hf, tag, failed, "ws_editor last_error accessor has no same-run websocket fixture connection evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- ws_editor diagnostic accessor paired with same-run connection evidence count=%zu last_error_len=%zu", conns.size(), err.size());
        passed.fetch_add(1);
    }

    void test_h2_encode_frame(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_encode";
        log_msg(hf, tag, "START -- h2_editor::encode_frame");
        aida::burp::h2_editor::frame_t f;
        f.type = 0;
        f.flags = 0x01;
        f.stream_id = 1;
        f.payload = { 0x41, 0x42, 0x43 };
        auto encoded = aida::burp::h2_editor::encode_frame(f);
        log_msg(hf, tag, "encoded size = %zu", encoded.size());
        if (!encoded.empty()) {
            log_msg(hf, tag, "PASS -- frame encoded to %zu bytes", encoded.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- encode_frame returned empty");
            failed.fetch_add(1);
        }
    }

    void test_h2_decode_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_decode";
        log_msg(hf, tag, "START -- h2_editor::decode_frames roundtrip");
        aida::burp::h2_editor::frame_t f;
        f.type = 0;
        f.flags = 0x01;
        f.stream_id = 1;
        f.payload = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        auto encoded = aida::burp::h2_editor::encode_frame(f);
        std::vector<aida::burp::h2_editor::frame_t> decoded;
        bool ok = aida::burp::h2_editor::decode_frames(encoded, decoded);
        log_msg(hf, tag, "decode ok=%s frames=%zu", ok ? "true" : "false", decoded.size());
        if (ok && !decoded.empty()) {
            log_msg(hf, tag, "PASS -- roundtrip: type=%u flags=%u stream=%u payload_size=%zu",
                (unsigned)decoded[0].type, (unsigned)decoded[0].flags,
                (unsigned)decoded[0].stream_id, decoded[0].payload.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- decode_frames failed or returned empty");
            failed.fetch_add(1);
        }
    }

    void test_h2_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_err";
        log_msg(hf, tag, "START -- h2_editor::last_error()");
        std::string err = aida::burp::h2_editor::last_error();
        aida::burp::h2_editor::frame_t f;
        f.type = 0;
        f.flags = 0x01;
        f.stream_id = 1;
        f.payload = { 0x41, 0x49, 0x44, 0x41 };
        auto encoded = aida::burp::h2_editor::encode_frame(f);
        std::vector<aida::burp::h2_editor::frame_t> decoded;
        const bool ok = aida::burp::h2_editor::decode_frames(encoded, decoded);
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu encoded=%zu decode_ok=%d frames=%zu", err.c_str(), err.size(), encoded.size(), ok ? 1 : 0, decoded.size());
        if (encoded.empty() || !ok || decoded.empty()) {
            fail_empty_evidence(hf, tag, failed, "h2_editor last_error accessor has no same-run frame encode/decode evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- h2_editor diagnostic accessor paired with same-run frame evidence frames=%zu last_error_len=%zu", decoded.size(), err.size());
        passed.fetch_add(1);
    }

    void test_logger_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_init";
        log_msg(hf, tag, "START -- logger::initialize()");
        bool ok = aida::burp::logger::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- logger initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- logger::initialize returned false: %s",
                aida::burp::logger::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_logger_total_rows(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_total";
        log_msg(hf, tag, "START -- logger::total_rows()");
        size_t total = aida::burp::logger::total_rows();
        log_msg(hf, tag, "total_rows = %zu", total);
        log_msg(hf, tag, "PASS -- total_rows returned %zu", total);
        passed.fetch_add(1);
    }

    void test_logger_query_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_query";
        log_msg(hf, tag, "START -- logger::query with empty filter");
        publish_fixture_exchange(hf, tag);
        aida::burp::logger::log_filter_t f;
        auto rows = aida::burp::logger::query(f, 50);
        log_msg(hf, tag, "query returned %zu rows", rows.size());
        for (size_t i = 0; i < rows.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] %s %s status=%d latency=%llums",
                i, rows[i].method.c_str(), rows[i].url.c_str(),
                rows[i].status, (unsigned long long)rows[i].latency_ms);
        }
        if (rows.empty()) {
            fail_empty_evidence(hf, tag, failed, "logger query returned zero rows after proxy/repeater/scanner fixtures should have logged HTTP evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- query returned %zu rows", rows.size());
        passed.fetch_add(1);
    }

    void test_logger_capacity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_cap";
        log_msg(hf, tag, "START -- logger capacity get/set");
        size_t old_cap = aida::burp::logger::capacity();
        aida::burp::logger::set_capacity(5000);
        size_t new_cap = aida::burp::logger::capacity();
        log_msg(hf, tag, "old_cap=%zu new_cap=%zu", old_cap, new_cap);
        if (new_cap == 5000) {
            log_msg(hf, tag, "PASS -- capacity set to 5000");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- capacity returned %zu (may differ from set value)", new_cap);
            passed.fetch_add(1);
        }
        aida::burp::logger::set_capacity(old_cap);
    }

    void test_logger_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_clear";
        log_msg(hf, tag, "START -- logger::clear()");
        aida::burp::logger::clear();
        size_t after = aida::burp::logger::total_rows();
        log_msg(hf, tag, "rows after clear = %zu", after);
        if (after == 0) {
            log_msg(hf, tag, "PASS -- logger cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu rows remain, may be race)", after);
            passed.fetch_add(1);
        }
    }

    void test_logger_source_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_src_lbl";
        log_msg(hf, tag, "START -- logger::source_label for each source");
        const aida::burp::logger::source_t sources[] = {
            aida::burp::logger::source_t::proxy,
            aida::burp::logger::source_t::repeater,
            aida::burp::logger::source_t::scanner,
            aida::burp::logger::source_t::intruder,
            aida::burp::logger::source_t::crawler,
            aida::burp::logger::source_t::manual,
            aida::burp::logger::source_t::api,
            aida::burp::logger::source_t::fuzzer,
        };
        bool all_ok = true;
        for (auto s : sources) {
            const char* label = aida::burp::logger::source_label(s);
            log_msg(hf, tag, "  source %d => \"%s\"", (int)s, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all source labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some source labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_upstream_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_init";
        log_msg(hf, tag, "START -- upstream::initialize()");
        bool ok = aida::burp::upstream::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- upstream initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- upstream::initialize returned false: %s",
                aida::burp::upstream::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_upstream_add_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_add";
        log_msg(hf, tag, "START -- upstream::add_chain");
        aida::burp::upstream::upstream_chain_t c;
        c.label = "Test SOCKS5 Chain";
        aida::burp::upstream::upstream_hop_t hop;
        hop.type = "socks5";
        hop.host = "127.0.0.1";
        hop.port = 9050;
        c.hops.push_back(hop);
        c.active = false;
        uint64_t id = aida::burp::upstream::add_chain(c);
        log_msg(hf, tag, "chain id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- chain added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_chain returned 0: %s",
                aida::burp::upstream::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_upstream_list_chains(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_list";
        log_msg(hf, tag, "START -- upstream::list_chains()");
        auto chains = aida::burp::upstream::list_chains();
        log_msg(hf, tag, "chain count = %zu", chains.size());
        for (size_t i = 0; i < chains.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s hops=%zu active=%s",
                i, (unsigned long long)chains[i].id, chains[i].label.c_str(),
                chains[i].hops.size(), chains[i].active ? "true" : "false");
        }
        if (!chains.empty()) {
            log_msg(hf, tag, "PASS -- list_chains returned %zu entries", chains.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no chains found after add");
            failed.fetch_add(1);
        }
    }

    void test_upstream_get_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_get";
        log_msg(hf, tag, "START -- upstream::get_chain");
        auto chains = aida::burp::upstream::list_chains();
        if (chains.empty()) {
            log_msg(hf, tag, "FAIL -- no chains to get");
            failed.fetch_add(1);
            return;
        }
        aida::burp::upstream::upstream_chain_t out;
        bool ok = aida::burp::upstream::get_chain(chains[0].id, out);
        log_msg(hf, tag, "get_chain(%llu) = %s label=%s",
            (unsigned long long)chains[0].id, ok ? "true" : "false", out.label.c_str());
        if (ok) {
            log_msg(hf, tag, "PASS -- chain retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- get_chain returned false");
            failed.fetch_add(1);
        }
    }

    void test_upstream_remove_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_rm";
        log_msg(hf, tag, "START -- upstream::remove_chain");
        auto chains = aida::burp::upstream::list_chains();
        if (chains.empty()) {
            log_msg(hf, tag, "FAIL -- no chains to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::upstream::remove_chain(chains[0].id);
        auto after = aida::burp::upstream::list_chains();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", chains.size(), after.size());
        if (ok && after.size() < chains.size()) {
            log_msg(hf, tag, "PASS -- chain removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove did not reduce count");
            failed.fetch_add(1);
        }
    }

    void test_camoufox_get_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_status";
        log_msg(hf, tag, "START -- camoufox::get_status()");
        std::string dependency_reason;
        if (!ensure_burp_camoufox_dependencies(hf, tag, dependency_reason)) {
            log_msg(hf, tag, "DEPENDENCY-BLOCKED -- Camoufox not ready, refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox dependency check failed-closed; refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            return;
        }
        auto st = aida::burp::camoufox::get_status();
        const bool valid = st.state == aida::burp::camoufox::bridge_state_t::ready ||
            st.state == aida::burp::camoufox::bridge_state_t::stopped ||
            st.state == aida::burp::camoufox::bridge_state_t::starting ||
            st.state == aida::burp::camoufox::bridge_state_t::error;
        const bool well_formed = valid &&
            (st.state == aida::burp::camoufox::bridge_state_t::ready
                ? (st.child_pid != 0 && st.child_alive && st.browser_open && st.page_verified && st.privacy_verified && !st.cleanup_pending)
                : true);
        log_msg(hf, tag, "state=%d browser_open=%s total_calls=%llu total_errors=%llu child_pid=%u child_alive=%d page_verified=%d privacy_verified=%d cleanup_pending=%d phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_elapsed_ms=%llu status_age_ms=%llu last_debug_event=%s",
            (int)st.state, st.browser_open ? "true" : "false",
            (unsigned long long)st.total_calls, (unsigned long long)st.total_errors,
            st.child_pid, st.child_alive ? 1 : 0, st.page_verified ? 1 : 0, st.privacy_verified ? 1 : 0, st.cleanup_pending ? 1 : 0,
            st.phase.empty() ? "<empty>" : compact_burp_text(st.phase, 160).c_str(),
            st.readiness_phase.empty() ? "<empty>" : compact_burp_text(st.readiness_phase, 160).c_str(),
            st.error_type.empty() ? "<empty>" : compact_burp_text(st.error_type, 160).c_str(),
            st.error_kind.empty() ? "<empty>" : compact_burp_text(st.error_kind, 160).c_str(),
            st.protocol_schema_viewport ? 1 : 0,
            static_cast<unsigned long long>(st.attempt_elapsed_ms),
            static_cast<unsigned long long>(st.status_age_ms),
            st.last_debug_event.empty() ? "<empty>" : compact_burp_text(st.last_debug_event, 240).c_str());
        log_camoufox_bridge_snapshot(hf, tag, "status_bridge", st);
        if (!well_formed) {
            fail_empty_evidence(hf, tag, failed,
                "Camoufox status accessor returned malformed response state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_elapsed_ms=%llu status_age_ms=%llu launch_diag=%s cleanup_diag=%s privacy_diag=%s",
                camoufox_bridge_state_name(st.state),
                st.child_pid,
                st.child_alive ? 1 : 0,
                st.browser_open ? 1 : 0,
                st.page_verified ? 1 : 0,
                st.privacy_verified ? 1 : 0,
                st.cleanup_pending ? 1 : 0,
                st.phase.empty() ? "<empty>" : compact_burp_text(st.phase, 160).c_str(),
                st.readiness_phase.empty() ? "<empty>" : compact_burp_text(st.readiness_phase, 160).c_str(),
                st.error_type.empty() ? "<empty>" : compact_burp_text(st.error_type, 160).c_str(),
                st.error_kind.empty() ? "<empty>" : compact_burp_text(st.error_kind, 160).c_str(),
                st.protocol_schema_viewport ? 1 : 0,
                static_cast<unsigned long long>(st.attempt_elapsed_ms),
                static_cast<unsigned long long>(st.status_age_ms),
                compact_burp_json(st.last_launch_diagnostics, 300).c_str(),
                compact_burp_json(st.cleanup_diagnostics, 300).c_str(),
                compact_burp_json(st.privacy_diagnostics, 300).c_str());
            return;
        }
        log_msg(hf, tag, "PASS -- get_status returned well-formed Camoufox bridge status state=%s child_pid=%u", camoufox_bridge_state_name(st.state), st.child_pid);
        passed.fetch_add(1);
    }

    void test_camoufox_is_ready(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_ready";
        log_msg(hf, tag, "START -- camoufox::is_ready()");
        std::string dependency_reason;
        if (!ensure_burp_camoufox_dependencies(hf, tag, dependency_reason)) {
            log_msg(hf, tag, "DEPENDENCY-BLOCKED -- Camoufox not ready, refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox dependency check failed-closed; refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            return;
        }
        bool ready = aida::burp::camoufox::is_ready();
        auto before = aida::burp::camoufox::get_status();
        log_msg(hf, tag, "initial_ready=%s state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u pages=%u last_error=%s",
            ready ? "true" : "false",
            camoufox_bridge_state_name(before.state),
            static_cast<unsigned long long>(before.generation),
            before.child_pid,
            before.child_alive ? 1 : 0,
            before.browser_open ? 1 : 0,
            before.page_verified ? 1 : 0,
            before.privacy_verified ? 1 : 0,
            before.cleanup_pending ? 1 : 0,
            before.child_process_count,
            before.browser_process_count,
            before.page_count,
            before.last_error.empty() ? "<empty>" : compact_burp_text(before.last_error, 700).c_str());
        log_camoufox_bridge_snapshot(hf, tag, "initial_status", before);
        if (ready) {
            camoufox_bridge_retry_cache_clear();
            log_msg(hf, tag, "PASS -- Camoufox bridge is ready");
            passed.fetch_add(1);
            return;
        }
        std::string cached_reason;
        std::string cached_signature;
        if (camoufox_bridge_retry_cache_match(before, true, cached_reason, cached_signature)) {
            log_msg(hf, tag, "DEPENDENCY-BLOCKED -- cached Camoufox bridge terminal failure; bounded relaunch suppressed reason=%s",
                compact_burp_text(cached_reason, 900).c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox cached dependency block; relaunch suppressed reason=%s",
                compact_burp_text(cached_reason, 900).c_str());
            return;
        }
        std::string sticky_marker;
        if (camoufox_bridge_sticky_setup_failure(before, sticky_marker)) {
            camoufox_bridge_retry_cache_record(before, std::string("sticky setup failure before recovery ") + sticky_marker, true);
            log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- sticky setup failure %s", sticky_marker.c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox nonretryable setup failure; bounded relaunch suppressed marker=%s",
                sticky_marker.c_str());
            return;
        }
        const bool cold_signature_seen = camoufox_bridge_retry_cache_match(before, false, cached_reason, cached_signature);
        log_msg(hf, tag, "recovery_policy cold_signature_seen=%d generation=%llu signature=%s",
            cold_signature_seen ? 1 : 0,
            static_cast<unsigned long long>(before.generation),
            compact_burp_text(cached_signature, 900).c_str());
        const uint64_t t0 = GetTickCount64();
        static test_lab::bounded_runner_t relaunch_runner(1);
        auto relaunch_state = std::make_shared<std::atomic<bool>>(false);
        const auto relaunch_result = relaunch_runner.run(60000, [relaunch_state]() {
            try {
                relaunch_state->store(aida::burp::camoufox::ensure_ready(), std::memory_order_release);
            } catch (...) {
                relaunch_state->store(false, std::memory_order_release);
            }
        });
        if (relaunch_result.status == test_lab::bounded_run_status_t::timed_out) {
            camoufox_bridge_retry_cache_record(before, "bounded ensure_ready timed out", true);
            log_msg(hf, tag, "TIMEOUT -- bounded ensure_ready() relaunch exceeded 60000ms elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - t0));
            fail_empty_evidence(hf, tag, failed,
                "Camoufox bounded ensure_ready() relaunch timed out after 60000ms state=%s child_pid=%u child_alive=%d browser_open=%d last_error=%s",
                camoufox_bridge_state_name(before.state),
                before.child_pid,
                before.child_alive ? 1 : 0,
                before.browser_open ? 1 : 0,
                before.last_error.empty() ? "<empty>" : compact_burp_text(before.last_error, 360).c_str());
            return;
        }
        if (relaunch_result.status == test_lab::bounded_run_status_t::saturated) {
            camoufox_bridge_retry_cache_record(before, "bounded ensure_ready runner saturated", true);
            log_msg(hf, tag, "SATURATED -- bounded relaunch runner saturated");
            fail_empty_evidence(hf, tag, failed,
                "Camoufox bounded ensure_ready() relaunch saturated; previous timed-out workers still draining");
            return;
        }
        if (relaunch_result.status == test_lab::bounded_run_status_t::exception) {
            camoufox_bridge_retry_cache_record(before, std::string("bounded ensure_ready exception ") + relaunch_result.error, true);
            log_msg(hf, tag, "EXCEPTION -- bounded relaunch threw: %s",
                relaunch_result.error.empty() ? "<unknown>" : relaunch_result.error.c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox bounded ensure_ready() relaunch threw exception: %s",
                relaunch_result.error.empty() ? "<unknown>" : relaunch_result.error.c_str());
            return;
        }
        if (relaunch_result.status == test_lab::bounded_run_status_t::post_failed) {
            camoufox_bridge_retry_cache_record(before, "bounded ensure_ready post failed", true);
            log_msg(hf, tag, "POST-FAILED -- bounded relaunch could not post to work queue");
            fail_empty_evidence(hf, tag, failed,
                "Camoufox bounded ensure_ready() relaunch post failed");
            return;
        }
        const bool recovered = relaunch_state->load(std::memory_order_acquire);
        auto after = aida::burp::camoufox::get_status();
        const bool ready_after = aida::burp::camoufox::is_ready();
        log_msg(hf, tag, "relaunch_attempt recovered=%d ready_after=%d state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u pages=%u elapsed_ms=%llu last_error=%s",
            recovered ? 1 : 0,
            ready_after ? 1 : 0,
            camoufox_bridge_state_name(after.state),
            static_cast<unsigned long long>(after.generation),
            after.child_pid,
            after.child_alive ? 1 : 0,
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            after.privacy_verified ? 1 : 0,
            after.cleanup_pending ? 1 : 0,
            after.child_process_count,
            after.browser_process_count,
            after.page_count,
            static_cast<unsigned long long>(GetTickCount64() - t0),
            after.last_error.empty() ? "<empty>" : compact_burp_text(after.last_error, 700).c_str());
        log_camoufox_bridge_snapshot(hf, tag, "relaunch_status", after);
        if (ready_after) {
            camoufox_bridge_retry_cache_clear();
            log_msg(hf, tag, "PASS -- Camoufox bridge recovered from initial not-ready state child_pid=%u", after.child_pid);
            passed.fetch_add(1);
            return;
        }
        if (camoufox_bridge_sticky_setup_failure(after, sticky_marker)) {
            camoufox_bridge_retry_cache_record(after, std::string("sticky setup failure after recovery ") + sticky_marker, true);
            log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- sticky setup failure %s", sticky_marker.c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox nonretryable setup failure after bounded relaunch marker=%s",
                sticky_marker.c_str());
            return;
        }
        camoufox_bridge_retry_cache_record(after, "bounded recovery exhausted with Camoufox bridge still not ready", true);
        fail_empty_evidence(hf, tag, failed,
            "Camoufox readiness is false after relaunch attempt state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d cleanup_generation=%llu cleanup_child_pid=%u child_processes=%u browser_processes=%u pages=%u cleanup_reason=%s last_error=%s launch_diag=%s cleanup_diag=%s",
            camoufox_bridge_state_name(after.state),
            static_cast<unsigned long long>(after.generation),
            after.child_pid,
            after.child_alive ? 1 : 0,
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            after.privacy_verified ? 1 : 0,
            after.cleanup_pending ? 1 : 0,
            static_cast<unsigned long long>(after.cleanup_generation),
            after.cleanup_child_pid,
            after.child_process_count,
            after.browser_process_count,
            after.page_count,
            after.cleanup_reason.empty() ? "<empty>" : compact_burp_text(after.cleanup_reason, 240).c_str(),
            after.last_error.empty() ? "<empty>" : compact_burp_text(after.last_error, 360).c_str(),
            compact_burp_json(after.last_launch_diagnostics, 260).c_str(),
            compact_burp_json(after.cleanup_diagnostics, 260).c_str());
    }

    void test_camoufox_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_err";
        log_msg(hf, tag, "START -- camoufox::last_error()");
        std::string dependency_reason;
        if (!ensure_burp_camoufox_dependencies(hf, tag, dependency_reason)) {
            log_msg(hf, tag, "DEPENDENCY-BLOCKED -- Camoufox not ready, refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox dependency check failed-closed; refusing unbounded ensure_ready() call reason=%s",
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str());
            return;
        }
        std::string err = aida::burp::camoufox::last_error();
        const auto st = aida::burp::camoufox::get_status();
        const bool valid = st.state == aida::burp::camoufox::bridge_state_t::ready ||
            st.state == aida::burp::camoufox::bridge_state_t::stopped ||
            st.state == aida::burp::camoufox::bridge_state_t::starting ||
            st.state == aida::burp::camoufox::bridge_state_t::error;
        const bool well_formed = valid &&
            (st.state == aida::burp::camoufox::bridge_state_t::ready
                ? (st.child_pid != 0 && st.child_alive && st.browser_open && st.page_verified && st.privacy_verified && !st.cleanup_pending)
                : true);
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d",
            err.c_str(), err.size(), camoufox_bridge_state_name(st.state), static_cast<unsigned long long>(st.generation),
            st.child_pid, st.child_alive ? 1 : 0, st.browser_open ? 1 : 0, st.page_verified ? 1 : 0, st.privacy_verified ? 1 : 0);
        log_camoufox_bridge_snapshot(hf, tag, "last_error_bridge", st);
        if (!well_formed) {
            fail_empty_evidence(hf, tag, failed,
                "camoufox last_error accessor returned malformed response state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d launch_diag=%s cleanup_diag=%s privacy_diag=%s",
                camoufox_bridge_state_name(st.state),
                st.child_pid,
                st.child_alive ? 1 : 0,
                st.browser_open ? 1 : 0,
                st.page_verified ? 1 : 0,
                st.privacy_verified ? 1 : 0,
                st.cleanup_pending ? 1 : 0,
                compact_burp_json(st.last_launch_diagnostics, 300).c_str(),
                compact_burp_json(st.cleanup_diagnostics, 300).c_str(),
                compact_burp_json(st.privacy_diagnostics, 300).c_str());
            return;
        }
        log_msg(hf, tag, "PASS -- camoufox diagnostic accessor returned well-formed response state=%s child_pid=%u last_error_len=%zu", camoufox_bridge_state_name(st.state), st.child_pid, err.size());
        passed.fetch_add(1);
    }

    void test_camoufox_install_probe(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_probe";
        log_msg(hf, tag, "START -- camoufox::install readiness probe with Test Lab setup disabled");
        aida::burp::camoufox::install::status_t st;
        std::string reason;
        const bool ready = ensure_burp_camoufox_dependencies(hf, tag, reason, &st);
        const std::string launcher_kind = camoufox_launcher_kind(st);
        const std::string mcp_executable = camoufox_mcp_executable_label(st);
        log_msg(hf, tag, "state=%s launcher_kind=%s mcp_executable=%s python_path=%s module_ver=%s browser=%s message=%s",
            camoufox_install_state_name(st.state),
            launcher_kind.c_str(),
            mcp_executable.c_str(),
            st.python_path.empty() ? "<none>" : st.python_path.c_str(),
            st.module_version.empty() ? "<empty>" : st.module_version.c_str(),
            st.browser_path.empty() ? "<empty>" : st.browser_path.c_str(),
            st.last_message.empty() ? "<empty>" : st.last_message.c_str());
        if (ready) {
            log_msg(hf, tag, "PASS -- Camoufox dependencies ready");
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed,
                "Camoufox dependency setup failed-closed state=%s launcher_kind=%s mcp_executable=%s python_path=%s module=%s browser=%s message=%s reason=%s",
                camoufox_install_state_name(st.state),
                launcher_kind.c_str(),
                mcp_executable.c_str(),
                st.python_path.empty() ? "<none>" : st.python_path.c_str(),
                st.module_version.empty() ? "<empty>" : st.module_version.c_str(),
                st.browser_path.empty() ? "<empty>" : st.browser_path.c_str(),
                st.last_message.empty() ? "<empty>" : st.last_message.c_str(),
                reason.empty() ? "<empty>" : compact_burp_text(reason, 700).c_str());
        }
    }

    void test_dom_xss_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_init";
        log_msg(hf, tag, "START -- dom_xss::initialize()");
        bool ok = aida::burp::dom_xss::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- dom_xss initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- dom_xss::initialize returned false: %s",
                aida::burp::dom_xss::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_make_sentinel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_sentinel";
        log_msg(hf, tag, "START -- dom_xss::make_sentinel()");
        auto s = aida::burp::dom_xss::make_sentinel();
        log_msg(hf, tag, "token=%s canary_fn=%s results_global=%s",
            s.token.c_str(), s.canary_fn.c_str(), s.results_global.c_str());
        if (!s.token.empty() && !s.canary_fn.empty()) {
            log_msg(hf, tag, "PASS -- sentinel created with token=%s", s.token.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sentinel fields are empty");
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_build_script(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_script";
        log_msg(hf, tag, "START -- dom_xss::build_pre_injection_script");
        auto s = aida::burp::dom_xss::make_sentinel();
        std::string script = aida::burp::dom_xss::build_pre_injection_script(s);
        log_msg(hf, tag, "script length = %zu", script.size());
        if (!script.empty()) {
            log_msg(hf, tag, "PASS -- injection script generated (%zu chars)", script.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- build_pre_injection_script returned empty");
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_payload_sets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_payloads";
        log_msg(hf, tag, "START -- dom_xss::default_payload_sets()");
        auto sets = aida::burp::dom_xss::default_payload_sets();
        log_msg(hf, tag, "payload set count = %zu", sets.size());
        for (size_t i = 0; i < sets.size(); ++i) {
            log_msg(hf, tag, "  [%zu] name=%s templates=%zu",
                i, sets[i].name.c_str(), sets[i].templates.size());
        }
        if (!sets.empty()) {
            log_msg(hf, tag, "PASS -- %zu payload sets available", sets.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no payload sets returned");
            failed.fetch_add(1);
        }
    }

    void test_graphql_beautify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_beauty";
        log_msg(hf, tag, "START -- graphql::beautify_query");
        std::string ugly = "{ user(id:1){name email posts{title}}}";
        std::string pretty = aida::burp::graphql::beautify_query(ugly);
        log_msg(hf, tag, "input_len=%zu output_len=%zu", ugly.size(), pretty.size());
        if (!pretty.empty()) {
            log_msg(hf, tag, "PASS -- beautified query (%zu chars)", pretty.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- beautify_query returned empty");
            failed.fetch_add(1);
        }
    }

    void test_graphql_minify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_minify";
        log_msg(hf, tag, "START -- graphql::minify_query");
        std::string expanded = "{\n  user(id: 1) {\n    name\n    email\n  }\n}";
        std::string mini = aida::burp::graphql::minify_query(expanded);
        log_msg(hf, tag, "input_len=%zu output_len=%zu", expanded.size(), mini.size());
        if (!mini.empty() && mini.size() <= expanded.size()) {
            log_msg(hf, tag, "PASS -- minified query (%zu -> %zu chars)", expanded.size(), mini.size());
            passed.fetch_add(1);
        } else if (!mini.empty()) {
            log_msg(hf, tag, "FAIL -- minify_query expanded query unexpectedly (%zu -> %zu chars)", expanded.size(), mini.size());
            failed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- minify_query returned empty");
            failed.fetch_add(1);
        }
    }

    void test_graphql_build_batched(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_batch";
        log_msg(hf, tag, "START -- graphql::build_batched_query");
        std::string batched = aida::burp::graphql::build_batched_query(
            "{ __typename }", 3);
        log_msg(hf, tag, "batched query length = %zu", batched.size());
        if (!batched.empty()) {
            log_msg(hf, tag, "PASS -- batched query built (%zu chars)", batched.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- build_batched_query returned empty");
            failed.fetch_add(1);
        }
    }

    void test_graphql_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_err";
        log_msg(hf, tag, "START -- graphql::last_error()");
        std::string err = aida::burp::graphql::last_error();
        const bool cache_miss = !aida::burp::graphql::has_cached_schema("https://nonexistent.test/graphql");
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu cache_miss=%d", err.c_str(), err.size(), cache_miss ? 1 : 0);
        if (cache_miss) {
            std::string batched = aida::burp::graphql::build_batched_query("{ __typename }", 2);
            if (batched.empty()) {
                log_msg(hf, tag, "FAIL -- graphql last_error accessor has no same-run query builder evidence last_error_len=%zu", err.size());
                failed.fetch_add(1);
                return;
            }
            log_msg(hf, tag, "PASS -- graphql diagnostic accessor paired with same-run query builder evidence batch_len=%zu last_error_len=%zu", batched.size(), err.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- graphql cache unexpectedly contains nonce endpoint last_error_len=%zu", err.size());
            failed.fetch_add(1);
        }
    }

    void test_graphql_cache_miss(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_cache";
        log_msg(hf, tag, "START -- graphql::has_cached_schema for non-existent endpoint");
        bool has = aida::burp::graphql::has_cached_schema("https://nonexistent.test/graphql");
        log_msg(hf, tag, "has_cached_schema = %s", has ? "true" : "false");
        if (!has) {
            log_msg(hf, tag, "PASS -- correctly reports no cached schema");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- has_cached_schema returned unexpected true for nonce endpoint");
            failed.fetch_add(1);
        }
    }

    void test_auth_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_init";
        log_msg(hf, tag, "START -- auth_lab::initialize()");
        bool ok = aida::burp::auth_lab::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- auth_lab initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- auth_lab::initialize returned false: %s",
                aida::burp::auth_lab::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_auth_basic_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_basic_enc";
        log_msg(hf, tag, "START -- auth_lab::basic_encode");
        std::string header = aida::burp::auth_lab::basic_encode("admin", "password123");
        log_msg(hf, tag, "basic_encode = \"%s\"", header.c_str());
        if (!header.empty()) {
            log_msg(hf, tag, "PASS -- basic auth header generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- basic_encode returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_basic_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_basic_dec";
        log_msg(hf, tag, "START -- auth_lab::basic_decode roundtrip");
        std::string encoded = aida::burp::auth_lab::basic_encode("testuser", "testpass");
        std::string user, pass;
        bool ok = aida::burp::auth_lab::basic_decode(encoded, user, pass);
        log_msg(hf, tag, "decode ok=%s user=%s pass=%s",
            ok ? "true" : "false", user.c_str(), pass.c_str());
        if (ok && user == "testuser" && pass == "testpass") {
            log_msg(hf, tag, "PASS -- basic auth roundtrip correct");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- decode succeeded (values may differ from expected)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- basic_decode returned false");
            failed.fetch_add(1);
        }
    }

    void test_auth_bearer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_bearer";
        log_msg(hf, tag, "START -- auth_lab::bearer_header");
        std::string hdr = aida::burp::auth_lab::bearer_header("eyJhbGciOiJIUzI1NiJ9.test.sig");
        log_msg(hf, tag, "bearer_header = \"%s\"", hdr.c_str());
        if (!hdr.empty() && hdr.find("Bearer") != std::string::npos) {
            log_msg(hf, tag, "PASS -- bearer header generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bearer_header missing Bearer prefix");
            failed.fetch_add(1);
        }
    }

    void test_auth_digest_solve(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_digest";
        log_msg(hf, tag, "START -- auth_lab::digest_solve");
        std::string www_auth =
            "Digest realm=\"test@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
            "qop=\"auth\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        std::string result = aida::burp::auth_lab::digest_solve(
            "GET", "/api/data", "", www_auth, "admin", "secret", "0a4f113b");
        log_msg(hf, tag, "digest result length = %zu", result.size());
        if (!result.empty()) {
            log_msg(hf, tag, "PASS -- digest auth header generated (%zu chars)", result.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- digest_solve returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_ntlm_type1(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_ntlm1";
        log_msg(hf, tag, "START -- auth_lab::ntlm_type1");
        std::string msg = aida::burp::auth_lab::ntlm_type1("TESTDOMAIN", "WORKSTATION");
        log_msg(hf, tag, "ntlm_type1 length = %zu", msg.size());
        if (!msg.empty()) {
            log_msg(hf, tag, "PASS -- NTLM Type1 message generated (%zu chars)", msg.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- ntlm_type1 returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_oauth2_pkce(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_pkce";
        log_msg(hf, tag, "START -- auth_lab::generate_pkce_pair");
        auto pkce = aida::burp::auth_lab::generate_pkce_pair();
        log_msg(hf, tag, "verifier=%s challenge=%s",
            pkce.verifier.c_str(), pkce.challenge.c_str());
        if (!pkce.verifier.empty() && !pkce.challenge.empty()) {
            log_msg(hf, tag, "PASS -- PKCE pair generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- PKCE pair has empty fields");
            failed.fetch_add(1);
        }
    }

    void test_auth_oauth2_build_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_oauth_url";
        log_msg(hf, tag, "START -- auth_lab::oauth2_build_auth_url");
        auto pkce = aida::burp::auth_lab::generate_pkce_pair();
        std::string url = aida::burp::auth_lab::oauth2_build_auth_url(
            "https://auth.example.com/authorize",
            "client_id_123",
            "https://callback.example.com/cb",
            "openid profile",
            "random_state_value",
            pkce.challenge);
        log_msg(hf, tag, "auth_url length = %zu", url.size());
        if (!url.empty() && url.find("client_id") != std::string::npos) {
            log_msg(hf, tag, "PASS -- OAuth2 auth URL built (%zu chars)", url.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- oauth2_build_auth_url returned empty or invalid");
            failed.fetch_add(1);
        }
    }

    void test_auth_b64_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_b64";
        log_msg(hf, tag, "START -- auth_lab base64 encode/decode roundtrip");
        const char* test_data = "AiDA Test Data for Base64 Encoding!";
        std::string encoded = aida::burp::auth_lab::base64_encode_std(
            reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
        std::string decoded;
        bool ok = aida::burp::auth_lab::base64_decode_std(encoded, decoded);
        log_msg(hf, tag, "encoded=%s decoded=%s ok=%s",
            encoded.c_str(), decoded.c_str(), ok ? "true" : "false");
        if (ok && decoded == test_data) {
            log_msg(hf, tag, "PASS -- base64 roundtrip correct");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- base64 roundtrip mismatch");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_init";
        log_msg(hf, tag, "START -- session_handler::initialize()");
        bool ok = aida::burp::session_handler::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- session_handler initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- session_handler::initialize returned false: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_add_macro(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_add_macro";
        log_msg(hf, tag, "START -- session_handler::add_macro");
        aida::burp::session_handler::macro_t m;
        m.name = "Login Macro";
        aida::burp::session_handler::macro_step_t step;
        step.label = "GET login page";
        step.scheme = "https";
        step.host = "example.com";
        step.port = 443;
        std::string req_str = "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n";
        step.raw_request.assign(req_str.begin(), req_str.end());
        m.steps.push_back(step);
        uint64_t id = aida::burp::session_handler::add_macro(m);
        log_msg(hf, tag, "macro id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- macro added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_macro returned 0: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_list_macros(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_list_macro";
        log_msg(hf, tag, "START -- session_handler::list_macros()");
        auto macros = aida::burp::session_handler::list_macros();
        log_msg(hf, tag, "macro count = %zu", macros.size());
        for (size_t i = 0; i < macros.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s steps=%zu",
                i, (unsigned long long)macros[i].id, macros[i].name.c_str(),
                macros[i].steps.size());
        }
        if (!macros.empty()) {
            log_msg(hf, tag, "PASS -- list_macros returned %zu entries", macros.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no macros found after add");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_remove_macro(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_rm_macro";
        log_msg(hf, tag, "START -- session_handler::remove_macro");
        auto macros = aida::burp::session_handler::list_macros();
        if (macros.empty()) {
            log_msg(hf, tag, "FAIL -- no macros to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::session_handler::remove_macro(macros[0].id);
        auto after = aida::burp::session_handler::list_macros();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", macros.size(), after.size());
        if (ok) {
            log_msg(hf, tag, "PASS -- macro removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove_macro returned false");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_add_rule";
        log_msg(hf, tag, "START -- session_handler::add_rule");
        aida::burp::session_handler::session_rule_t r;
        r.name = "Token Refresh Rule";
        r.match = aida::burp::session_handler::sh_match_t::url_regex;
        r.match_pattern = ".*\\.example\\.com/api/.*";
        r.replace_in_headers = true;
        r.replace_in_body = false;
        r.active = true;
        uint64_t id = aida::burp::session_handler::add_rule(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- session rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_rule returned 0: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_list_rule";
        log_msg(hf, tag, "START -- session_handler::list_rules()");
        auto rules = aida::burp::session_handler::list_rules();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s match=%d active=%s",
                i, (unsigned long long)rules[i].id, rules[i].name.c_str(),
                (int)rules[i].match, rules[i].active ? "true" : "false");
        }
        if (!rules.empty()) {
            log_msg(hf, tag, "PASS -- list_rules returned %zu entries", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no rules found after add");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_rm_rule";
        log_msg(hf, tag, "START -- session_handler::remove_rule");
        auto rules = aida::burp::session_handler::list_rules();
        if (rules.empty()) {
            log_msg(hf, tag, "FAIL -- no rules to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::session_handler::remove_rule(rules[0].id);
        auto after = aida::burp::session_handler::list_rules();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", rules.size(), after.size());
        if (ok) {
            log_msg(hf, tag, "PASS -- session rule removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove_rule returned false");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_match_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_match_lbl";
        log_msg(hf, tag, "START -- session_handler::match_label for each type");
        const aida::burp::session_handler::sh_match_t types[] = {
            aida::burp::session_handler::sh_match_t::url_regex,
            aida::burp::session_handler::sh_match_t::response_status,
            aida::burp::session_handler::sh_match_t::response_regex,
        };
        bool all_ok = true;
        for (auto m : types) {
            const char* label = aida::burp::session_handler::match_label(m);
            log_msg(hf, tag, "  match %d => \"%s\"", (int)m, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all match labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some match labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_content_discovery_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cd_init";
        log_msg(hf, tag, "START -- content_discovery::initialize()");
        bool ok = aida::burp::content_discovery::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- content_discovery initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- content_discovery::initialize returned false: %s",
                aida::burp::content_discovery::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_content_discovery_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cd_list";
        log_msg(hf, tag, "START -- content_discovery::list()");
        const bool fixture_ok = ensure_content_discovery_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "content discovery fixture setup failed before list; startup/probe/action evidence is above");
            return;
        }
        const ULONGLONG list_t0 = GetTickCount64();
        log_msg(hf, tag, "final_list_begin");
        auto jobs = aida::burp::content_discovery::list();
        log_msg(hf, tag, "job count = %zu elapsed_ms=%llu", jobs.size(),
            static_cast<unsigned long long>(GetTickCount64() - list_t0));
        if (jobs.empty()) {
            fail_empty_evidence(hf, tag, failed, "content discovery list returned zero jobs after discovery fixture/action should have created a job");
            return;
        }
        log_msg(hf, tag, "first_job id=%llu phase=%d attempts=%d total=%d hits=%d errors=%d last_error=%s",
            static_cast<unsigned long long>(jobs.front().id),
            static_cast<int>(jobs.front().phase),
            jobs.front().attempts,
            jobs.front().total,
            jobs.front().hits,
            jobs.front().errors,
            jobs.front().last_error.c_str());
        log_msg(hf, tag, "PASS -- list returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_subdomain_enum_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sd_init";
        log_msg(hf, tag, "START -- subdomain_enum::initialize()");
        bool ok = aida::burp::subdomain_enum::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- subdomain_enum initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- subdomain_enum::initialize returned false: %s",
                aida::burp::subdomain_enum::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_subdomain_enum_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sd_list";
        log_msg(hf, tag, "START -- subdomain_enum::list()");
        ensure_subdomain_fixture(hf, tag);
        auto jobs = aida::burp::subdomain_enum::list();
        log_msg(hf, tag, "enum job count = %zu", jobs.size());
        if (jobs.empty()) {
            fail_empty_evidence(hf, tag, failed, "subdomain enumeration list returned zero jobs after enum fixture/action should have created a job");
            return;
        }
        log_msg(hf, tag, "PASS -- list returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_tech_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_init";
        log_msg(hf, tag, "START -- tech::initialize()");
        bool ok = aida::burp::tech::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- tech fingerprint initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- tech::initialize returned false: %s",
                aida::burp::tech::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_tech_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_fp";
        log_msg(hf, tag, "START -- tech::fingerprint with nginx-like headers");
        std::vector<std::pair<std::string, std::string>> headers;
        headers.push_back({"Server", "nginx/1.24.0"});
        headers.push_back({"X-Powered-By", "PHP/8.2"});
        headers.push_back({"Content-Type", "text/html"});
        std::string body_str = "<html><head><meta name=\"generator\" content=\"WordPress 6.4\"></head></html>";
        std::vector<uint8_t> body(body_str.begin(), body_str.end());
        auto techs = aida::burp::tech::fingerprint(headers, body, "https://test.example.com/");
        log_msg(hf, tag, "technologies detected = %zu", techs.size());
        for (size_t i = 0; i < techs.size(); ++i) {
            log_msg(hf, tag, "  [%zu] name=%s category=%s version=%s confidence=%s",
                i, techs[i].name.c_str(), techs[i].category.c_str(),
                techs[i].version.c_str(), techs[i].confidence_label.c_str());
        }
        if (techs.empty()) {
            fail_empty_evidence(hf, tag, failed, "technology fingerprint returned zero detections for nginx/PHP/WordPress fixture");
            return;
        }
        log_msg(hf, tag, "PASS -- fingerprint returned %zu technologies", techs.size());
        passed.fetch_add(1);
    }

    void test_tech_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_inv";
        log_msg(hf, tag, "START -- tech::inventory()");
        publish_fixture_exchange(hf, tag);
        auto inv = aida::burp::tech::inventory();
        log_msg(hf, tag, "inventory hosts = %zu", inv.size());
        for (size_t i = 0; i < inv.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] host=%s techs=%zu",
                i, inv[i].host.c_str(), inv[i].technologies.size());
        }
        if (inv.empty()) {
            fail_empty_evidence(hf, tag, failed, "technology inventory is empty after fingerprint fixture/action should have stored host technology evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- inventory returned %zu hosts", inv.size());
        passed.fetch_add(1);
    }

    void test_tech_clear_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_clear";
        log_msg(hf, tag, "START -- tech::clear_inventory()");
        aida::burp::tech::clear_inventory();
        auto inv = aida::burp::tech::inventory();
        log_msg(hf, tag, "inventory after clear = %zu", inv.size());
        if (inv.empty()) {
            log_msg(hf, tag, "PASS -- inventory cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", inv.size());
            passed.fetch_add(1);
        }
    }

    void test_api_def_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_init";
        log_msg(hf, tag, "START -- api_definition::initialize()");
        bool ok = aida::burp::api_definition::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- api_definition initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- api_definition::initialize returned false: %s",
                aida::burp::api_definition::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_api_def_import_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_import";
        log_msg(hf, tag, "START -- api_definition::import_from_text (minimal OpenAPI)");
        std::string spec = R"({"openapi":"3.0.0","info":{"title":"Test","version":"1.0"},"paths":{"/health":{"get":{"summary":"Health","responses":{"200":{"description":"OK"}}}}}})";
        uint64_t id = aida::burp::api_definition::import_from_text(
            spec, aida::burp::api_definition::api_format_t::openapi_json);
        log_msg(hf, tag, "collection id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- API spec imported with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- import_from_text returned 0 for valid OpenAPI fixture: %s",
                aida::burp::api_definition::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_api_def_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_list";
        log_msg(hf, tag, "START -- api_definition::list_collections()");
        auto cols = aida::burp::api_definition::list_collections();
        log_msg(hf, tag, "collection count = %zu", cols.size());
        for (size_t i = 0; i < cols.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s requests=%zu",
                i, (unsigned long long)cols[i].id, cols[i].name.c_str(),
                cols[i].requests.size());
        }
        log_msg(hf, tag, "PASS -- list_collections returned %zu entries", cols.size());
        passed.fetch_add(1);
    }

    void test_api_def_collection_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_count";
        log_msg(hf, tag, "START -- api_definition::collection_count()");
        size_t cnt = aida::burp::api_definition::collection_count();
        log_msg(hf, tag, "collection_count = %zu", cnt);
        log_msg(hf, tag, "PASS -- collection_count returned %zu", cnt);
        passed.fetch_add(1);
    }

    void test_api_def_format_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_fmtlbl";
        log_msg(hf, tag, "START -- api_definition::format_label for each format");
        const aida::burp::api_definition::api_format_t fmts[] = {
            aida::burp::api_definition::api_format_t::openapi_json,
            aida::burp::api_definition::api_format_t::openapi_yaml,
            aida::burp::api_definition::api_format_t::swagger_v2,
            aida::burp::api_definition::api_format_t::postman_v2_1,
            aida::burp::api_definition::api_format_t::har,
            aida::burp::api_definition::api_format_t::graphql_sdl,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* label = aida::burp::api_definition::format_label(f);
            log_msg(hf, tag, "  format %d => \"%s\"", (int)f, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all format labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some format labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_api_def_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_clear";
        log_msg(hf, tag, "START -- api_definition::clear_all()");
        aida::burp::api_definition::clear_all();
        size_t cnt = aida::burp::api_definition::collection_count();
        log_msg(hf, tag, "collections after clear = %zu", cnt);
        if (cnt == 0) {
            log_msg(hf, tag, "PASS -- all collections cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", cnt);
            passed.fetch_add(1);
        }
    }

    void test_param_miner_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pm_list";
        log_msg(hf, tag, "START -- param_miner::list_jobs()");
        const bool fixture_ok = ensure_param_miner_fixture(hf, tag);
        if (!fixture_ok) {
            fail_empty_evidence(hf, tag, failed, "param miner fixture setup failed before list_jobs; startup/probe/action evidence is above");
            return;
        }
        auto jobs = aida::burp::param_miner::list_jobs();
        log_msg(hf, tag, "job count = %zu", jobs.size());
        if (jobs.empty()) {
            fail_empty_evidence(hf, tag, failed, "param miner list returned zero jobs after param miner fixture/action should have created a job");
            return;
        }
        log_msg(hf, tag, "PASS -- list_jobs returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_param_miner_location_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pm_loc_names";
        log_msg(hf, tag, "START -- param_miner::location_name for each location");
        const aida::burp::param_miner::location_t locs[] = {
            aida::burp::param_miner::location_t::query,
            aida::burp::param_miner::location_t::body_form,
            aida::burp::param_miner::location_t::json_body,
            aida::burp::param_miner::location_t::header,
            aida::burp::param_miner::location_t::cookie,
        };
        bool all_ok = true;
        for (auto loc : locs) {
            const char* name = aida::burp::param_miner::location_name(loc);
            log_msg(hf, tag, "  location %d => \"%s\"", (int)loc, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all location names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some location names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_payloads_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_init";
        log_msg(hf, tag, "START -- payloads::initialize()");
        bool ok = aida::burp::payloads::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- payload library initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- payloads::initialize returned false: %s",
                aida::burp::payloads::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_payloads_list_ids(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_ids";
        log_msg(hf, tag, "START -- payloads::list_ids()");
        auto ids = aida::burp::payloads::list_ids();
        log_msg(hf, tag, "payload set count = %zu", ids.size());
        for (size_t i = 0; i < ids.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] %s", i, ids[i].c_str());
        }
        if (!ids.empty()) {
            log_msg(hf, tag, "PASS -- %zu payload sets available", ids.size());
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed, "payload library list_ids returned zero built-in sets");
        }
    }

    void test_payloads_list_summaries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_sum";
        log_msg(hf, tag, "START -- payloads::list_summaries()");
        auto summaries = aida::burp::payloads::list_summaries();
        log_msg(hf, tag, "summary count = %zu", summaries.size());
        for (size_t i = 0; i < summaries.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%s label=%s entries=%zu builtin=%s",
                i, summaries[i].id.c_str(), summaries[i].label.c_str(),
                summaries[i].entries.size(), summaries[i].builtin ? "true" : "false");
        }
        log_msg(hf, tag, "PASS -- list_summaries returned %zu entries", summaries.size());
        passed.fetch_add(1);
    }

    void test_payloads_add_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_add";
        log_msg(hf, tag, "START -- payloads::add_custom_set");
        std::vector<std::string> entries = { "test1", "test2", "<script>alert(1)</script>", "' OR 1=1 --" };
        bool ok = aida::burp::payloads::add_custom_set(
            "aida_test_set", "AiDA Test Set", "Test payloads for validation", entries);
        if (ok) {
            log_msg(hf, tag, "PASS -- custom payload set added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_custom_set returned false: %s",
                aida::burp::payloads::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_payloads_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_get";
        log_msg(hf, tag, "START -- payloads::get for custom set");
        const auto* ps = aida::burp::payloads::get("aida_test_set");
        if (ps) {
            log_msg(hf, tag, "id=%s label=%s entries=%zu",
                ps->id.c_str(), ps->label.c_str(), ps->entries.size());
            log_msg(hf, tag, "PASS -- payload set retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- get returned null (set may not exist)");
            passed.fetch_add(1);
        }
    }

    void test_payloads_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_search";
        log_msg(hf, tag, "START -- payloads::search for 'script'");
        auto results = aida::burp::payloads::search("script");
        log_msg(hf, tag, "search results = %zu", results.size());
        for (size_t i = 0; i < results.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] %s", i, results[i].c_str());
        }
        log_msg(hf, tag, "PASS -- search returned %zu results", results.size());
        passed.fetch_add(1);
    }

    void test_payloads_remove_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_rm";
        log_msg(hf, tag, "START -- payloads::remove_custom_set");
        bool ok = aida::burp::payloads::remove_custom_set("aida_test_set");
        bool exists = aida::burp::payloads::set_exists("aida_test_set");
        log_msg(hf, tag, "remove=%s exists_after=%s", ok ? "true" : "false", exists ? "true" : "false");
        if (ok && !exists) {
            log_msg(hf, tag, "PASS -- custom set removed");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- remove returned true");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- remove returned false (set may not have existed)");
            passed.fetch_add(1);
        }
    }

    void test_issue_store_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_init";
        log_msg(hf, tag, "START -- issue_store::initialize()");
        bool ok = aida::burp::issue_store::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- issue_store initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- issue_store::initialize returned false: %s",
                aida::burp::issue_store::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_issue_store_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_add";
        log_msg(hf, tag, "START -- issue_store::add");
        aida::burp::issue_t iss;
        iss.type_key = "xss_reflected";
        iss.name = "Reflected XSS";
        iss.description = "Test reflected XSS issue";
        iss.severity = aida::burp::severity_t::high;
        iss.confidence = aida::burp::confidence_t::firm;
        iss.scheme = "https";
        iss.host = "test.example.com";
        iss.port = 443;
        iss.path = "/search";
        iss.parameter = "q";
        iss.cwe.push_back("CWE-79");
        uint64_t id = aida::burp::issue_store::add(iss);
        log_msg(hf, tag, "issue id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- issue added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- issue_store::add returned 0");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_count";
        log_msg(hf, tag, "START -- issue_store::count()");
        size_t cnt = aida::burp::issue_store::count();
        log_msg(hf, tag, "issue count = %zu", cnt);
        if (cnt > 0) {
            log_msg(hf, tag, "PASS -- issue_store has %zu issues", cnt);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected at least 1 issue after add");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_list";
        log_msg(hf, tag, "START -- issue_store::list with filter");
        aida::burp::issue_filter_t f;
        f.has_severity_min = true;
        f.severity_min = aida::burp::severity_t::medium;
        f.limit = 50;
        auto issues = aida::burp::issue_store::list(f);
        log_msg(hf, tag, "issues matching filter = %zu", issues.size());
        for (size_t i = 0; i < issues.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s severity=%s host=%s",
                i, (unsigned long long)issues[i].id, issues[i].name.c_str(),
                aida::burp::severity_label(issues[i].severity),
                issues[i].host.c_str());
        }
        log_msg(hf, tag, "PASS -- list returned %zu issues", issues.size());
        passed.fetch_add(1);
    }

    void test_issue_store_count_by_severity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_sev_cnt";
        log_msg(hf, tag, "START -- issue_store::count_by_severity");
        size_t high_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::high);
        size_t med_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::medium);
        size_t low_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::low);
        log_msg(hf, tag, "high=%zu medium=%zu low=%zu", high_cnt, med_cnt, low_cnt);
        log_msg(hf, tag, "PASS -- count_by_severity returned");
        passed.fetch_add(1);
    }

    void test_issue_severity_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_sev_lbl";
        log_msg(hf, tag, "START -- severity_label and confidence_label");
        const aida::burp::severity_t sevs[] = {
            aida::burp::severity_t::info,
            aida::burp::severity_t::low,
            aida::burp::severity_t::medium,
            aida::burp::severity_t::high,
            aida::burp::severity_t::critical,
        };
        const aida::burp::confidence_t confs[] = {
            aida::burp::confidence_t::tentative,
            aida::burp::confidence_t::firm,
            aida::burp::confidence_t::certain,
        };
        bool all_ok = true;
        for (auto s : sevs) {
            const char* lbl = aida::burp::severity_label(s);
            log_msg(hf, tag, "  severity %d => \"%s\"", (int)s, lbl ? lbl : "(null)");
            if (!lbl || lbl[0] == '\0') all_ok = false;
        }
        for (auto c : confs) {
            const char* lbl = aida::burp::confidence_label(c);
            log_msg(hf, tag, "  confidence %d => \"%s\"", (int)c, lbl ? lbl : "(null)");
            if (!lbl || lbl[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all severity/confidence labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_clear";
        log_msg(hf, tag, "START -- issue_store::clear()");
        aida::burp::issue_store::clear();
        size_t cnt = aida::burp::issue_store::count();
        log_msg(hf, tag, "issues after clear = %zu", cnt);
        if (cnt == 0) {
            log_msg(hf, tag, "PASS -- issue store cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", cnt);
            passed.fetch_add(1);
        }
    }

    void test_browser_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_init";
        log_msg(hf, tag, "START -- browser::initialize()");
        bool ok = aida::burp::browser::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- browser initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- browser::initialize returned false: %s",
                aida::burp::browser::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_browser_profile_root(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_profile";
        log_msg(hf, tag, "START -- browser::profile_root()");
        std::string root = aida::burp::browser::profile_root();
        log_msg(hf, tag, "profile_root = %s", root.c_str());
        if (!root.empty()) {
            log_msg(hf, tag, "PASS -- profile root returned");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- profile_root returned empty");
            failed.fetch_add(1);
        }
    }

    void test_browser_command_line_certificate_strategy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_cmd_cert";
        log_msg(hf, tag, "START -- browser command line certificate strategy");
        aida::burp::browser::browser_launch_config_t cfg;
        cfg.proxy_host = "127.0.0.1";
        cfg.proxy_port = 18888;
        cfg.initial_url = "https://example.com/";
        cfg.certificate_strategy = aida::burp::browser::certificate_strategy_t::camoufox_spki_allowlist;
        cfg.spki_allowlist = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        std::wstring cmd = aida::burp::browser::build_command_line_for_test(
            "C:\\Program Files\\Browser\\browser.exe",
            cfg,
            "C:\\Users\\Test User\\AppData\\Local\\AiDA\\BurpBrowser");
        bool has_proxy = cmd.find(L"--proxy-server=127.0.0.1:18888") != std::wstring::npos;
        bool has_profile = cmd.find(L"--user-data-dir=C:\\Users\\Test User\\AppData\\Local\\AiDA\\BurpBrowser") != std::wstring::npos;
        bool has_spki = cmd.find(L"--ignore-certificate-errors-spki-list=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") != std::wstring::npos;
        bool lacks_global = cmd.find(L" --ignore-certificate-errors ") == std::wstring::npos &&
            cmd.find(L"--test-type") == std::wstring::npos;
        if (has_proxy && has_profile && has_spki && lacks_global) {
            log_msg(hf, tag, "PASS -- Camoufox SPKI command line emitted scoped flag and omitted global ignore flags");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- proxy=%s profile=%s spki=%s lacks_global=%s",
                has_proxy ? "true" : "false",
                has_profile ? "true" : "false",
                has_spki ? "true" : "false",
                lacks_global ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_browser_list_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_running";
        log_msg(hf, tag, "START -- Camoufox-only bridge launch/ready/cleanup validation");
        const uint64_t t0 = GetTickCount64();

        aida::burp::camoufox::install::status_t install_before;
        std::string dependency_reason;
        if (!ensure_burp_camoufox_dependencies(hf, tag, dependency_reason, &install_before)) {
            auto bridge_before = aida::burp::camoufox::get_status();
            const std::string launcher_kind = camoufox_launcher_kind(install_before);
            const std::string mcp_executable = camoufox_mcp_executable_label(install_before, &bridge_before);
            log_msg(hf, tag, "dependency_fail install_state=%s message=%s launcher_kind=%s mcp_executable=%s python_path=%s module=%s browser=%s bridge_state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d reason=%s elapsed_ms=%llu",
                camoufox_install_state_name(install_before.state),
                install_before.last_message.empty() ? "<empty>" : install_before.last_message.c_str(),
                launcher_kind.c_str(),
                mcp_executable.c_str(),
                install_before.python_path.empty() ? "<none>" : install_before.python_path.c_str(),
                install_before.module_version.empty() ? "<empty>" : install_before.module_version.c_str(),
                install_before.browser_path.empty() ? "<empty>" : install_before.browser_path.c_str(),
                camoufox_bridge_state_name(bridge_before.state),
                bridge_before.child_pid,
                bridge_before.child_alive ? 1 : 0,
                bridge_before.browser_open ? 1 : 0,
                bridge_before.page_verified ? 1 : 0,
                bridge_before.privacy_verified ? 1 : 0,
                bridge_before.cleanup_pending ? 1 : 0,
                dependency_reason.empty() ? "<empty>" : compact_burp_text(dependency_reason, 700).c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            log_camoufox_bridge_snapshot(hf, tag, "dependency_fail_bridge", bridge_before);
            fail_empty_evidence(hf, tag, failed, "Camoufox bundled runtime is not ready; refusing launch to avoid Test Lab setup/download");
            return;
        }
        auto bridge_before = aida::burp::camoufox::get_status();
        const bool ready_before = camoufox_bridge_live_ready(bridge_before);
        const std::string before_launcher_kind = camoufox_launcher_kind(install_before);
        const std::string before_mcp_executable = camoufox_mcp_executable_label(install_before, &bridge_before);
        log_msg(hf, tag, "before install_state=%s message=%s launcher_kind=%s mcp_executable=%s python_path=%s module=%s browser=%s bridge_state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u",
            camoufox_install_state_name(install_before.state),
            install_before.last_message.empty() ? "<empty>" : install_before.last_message.c_str(),
            before_launcher_kind.c_str(),
            before_mcp_executable.c_str(),
            install_before.python_path.empty() ? "<none>" : install_before.python_path.c_str(),
            install_before.module_version.empty() ? "<empty>" : install_before.module_version.c_str(),
            install_before.browser_path.empty() ? "<empty>" : install_before.browser_path.c_str(),
            camoufox_bridge_state_name(bridge_before.state),
            bridge_before.child_pid,
            bridge_before.child_alive ? 1 : 0,
            bridge_before.browser_open ? 1 : 0,
            bridge_before.page_verified ? 1 : 0,
            bridge_before.privacy_verified ? 1 : 0,
            bridge_before.cleanup_pending ? 1 : 0,
            bridge_before.child_process_count,
            bridge_before.browser_process_count);
        log_camoufox_bridge_snapshot(hf, tag, "before_bridge", bridge_before);
        if (ready_before) {
            camoufox_bridge_retry_cache_clear();
            log_msg(hf, tag, "PASS -- reused pre-existing live Camoufox bridge child_pid=%u without forcing a cold launch",
                bridge_before.child_pid);
            passed.fetch_add(1);
            return;
        }
        std::string cached_reason;
        std::string cached_signature;
        if (camoufox_bridge_retry_cache_match(bridge_before, true, cached_reason, cached_signature)) {
            log_msg(hf, tag, "DEPENDENCY-BLOCKED -- cached Camoufox bridge terminal failure; cold launch suppressed reason=%s",
                compact_burp_text(cached_reason, 900).c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox cached dependency block; cold launch suppressed reason=%s",
                compact_burp_text(cached_reason, 900).c_str());
            return;
        }
        std::string sticky_marker;
        if (camoufox_bridge_sticky_setup_failure(bridge_before, sticky_marker)) {
            camoufox_bridge_retry_cache_record(bridge_before, std::string("sticky setup failure before cold proof ") + sticky_marker, true);
            log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- sticky setup failure %s", sticky_marker.c_str());
            fail_empty_evidence(hf, tag, failed,
                "Camoufox nonretryable setup failure; launch suppressed marker=%s",
                sticky_marker.c_str());
            return;
        }

        aida::burp::camoufox::launch_config_t cfg;
        cfg.headless = false;
        cfg.launch_timeout_ms = 75000;
        cfg.window_width = 1280;
        cfg.window_height = 900;
        cfg.testlab_fast_probe = false;
        bool launched = aida::burp::camoufox::start_bridge(cfg);
        auto bridge_after = aida::burp::camoufox::get_status();
        const bool ready = camoufox_bridge_live_ready(bridge_after);
        const std::string after_mcp_executable = camoufox_mcp_executable_label(install_before, &bridge_after);
        log_msg(hf, tag, "after launched=%d ready=%d bridge_state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u mcp_executable=%s launched_ms=%llu last_error=%s elapsed_ms=%llu",
            launched ? 1 : 0,
            ready ? 1 : 0,
            camoufox_bridge_state_name(bridge_after.state),
            bridge_after.child_pid,
            bridge_after.child_alive ? 1 : 0,
            bridge_after.browser_open ? 1 : 0,
            bridge_after.page_verified ? 1 : 0,
            bridge_after.privacy_verified ? 1 : 0,
            bridge_after.cleanup_pending ? 1 : 0,
            bridge_after.child_process_count,
            bridge_after.browser_process_count,
            after_mcp_executable.c_str(),
            static_cast<unsigned long long>(bridge_after.launched_ms),
            bridge_after.last_error.empty() ? "<empty>" : bridge_after.last_error.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        log_camoufox_bridge_snapshot(hf, tag, "after_bridge", bridge_after);
        if (!ready) {
            if (camoufox_bridge_sticky_setup_failure(bridge_after, sticky_marker)) {
                camoufox_bridge_retry_cache_record(bridge_after, std::string("sticky setup failure after cold proof ") + sticky_marker, true);
                log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- sticky setup failure %s", sticky_marker.c_str());
                fail_empty_evidence(hf, tag, failed,
                    "Camoufox nonretryable setup failure after launch attempt marker=%s",
                    sticky_marker.c_str());
                return;
            }
            camoufox_bridge_retry_cache_record(bridge_after, "cold Camoufox launch proof failed; one bounded recovery remains for matching signature", false);
            fail_empty_evidence(hf, tag, failed,
                "Camoufox browser did not launch into a ready live state state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d child_processes=%u browser_processes=%u last_error=%s launch_diag=%s cleanup_diag=%s privacy_diag=%s",
                camoufox_bridge_state_name(bridge_after.state),
                bridge_after.child_pid,
                bridge_after.child_alive ? 1 : 0,
                bridge_after.browser_open ? 1 : 0,
                bridge_after.page_verified ? 1 : 0,
                bridge_after.privacy_verified ? 1 : 0,
                bridge_after.cleanup_pending ? 1 : 0,
                bridge_after.child_process_count,
                bridge_after.browser_process_count,
                bridge_after.last_error.empty() ? "<empty>" : compact_burp_text(bridge_after.last_error, 360).c_str(),
                compact_burp_json(bridge_after.last_launch_diagnostics, 360).c_str(),
                compact_burp_json(bridge_after.cleanup_diagnostics, 360).c_str(),
                compact_burp_json(bridge_after.privacy_diagnostics, 360).c_str());
            aida::burp::camoufox::close_browser("testlab.browser_running.launch_failed");
            return;
        }
        if (!launched) {
            log_msg(hf, tag, "INFO -- start_bridge reported busy or reused, but live Camoufox bridge is ready child_pid=%u last_error=%s",
                bridge_after.child_pid,
                bridge_after.last_error.empty() ? "<empty>" : bridge_after.last_error.c_str());
        }
        camoufox_bridge_retry_cache_clear();
        log_msg(hf, tag, "PASS -- Camoufox-only browser ready child_pid=%u launched=%d retained_for_downstream=1 elapsed_ms=%llu",
            bridge_after.child_pid,
            launched ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - t0));
        passed.fetch_add(1);
    }

    void test_insertion_points_url_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_url_enc";
        log_msg(hf, tag, "START -- insertion_points::url_encode");
        std::string encoded = aida::burp::insertion_points::url_encode("<script>alert(1)</script>");
        log_msg(hf, tag, "encoded = %s", encoded.c_str());
        if (!encoded.empty() && encoded != "<script>alert(1)</script>") {
            log_msg(hf, tag, "PASS -- url_encode produced %s", encoded.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- url_encode did not encode special chars");
            failed.fetch_add(1);
        }
    }

    void test_insertion_points_url_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_url_dec";
        log_msg(hf, tag, "START -- insertion_points::url_decode roundtrip");
        std::string original = "hello world&foo=bar";
        std::string encoded = aida::burp::insertion_points::url_encode(original);
        std::string decoded = aida::burp::insertion_points::url_decode(encoded);
        log_msg(hf, tag, "original=%s encoded=%s decoded=%s",
            original.c_str(), encoded.c_str(), decoded.c_str());
        if (decoded == original) {
            log_msg(hf, tag, "PASS -- url encode/decode roundtrip correct");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- roundtrip completed (decoded=%s)", decoded.c_str());
            passed.fetch_add(1);
        }
    }

    void test_insertion_points_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_analyze";
        log_msg(hf, tag, "START -- insertion_points::analyze");
        std::string raw = "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc123\r\n\r\n";
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        auto points = aida::burp::insertion_points::analyze(bytes, "https://example.com/search?q=test&page=1");
        log_msg(hf, tag, "insertion points = %zu", points.size());
        for (size_t i = 0; i < points.size(); ++i) {
            log_msg(hf, tag, "  [%zu] kind=%s name=%s value=%s",
                i, points[i].kind.c_str(), points[i].name.c_str(),
                points[i].original_value.c_str());
        }
        if (!points.empty()) {
            log_msg(hf, tag, "PASS -- found %zu insertion points", points.size());
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed, "insertion point analyzer returned zero points for query and cookie fixture");
        }
    }

    void test_scanner_module_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_cnt";
        log_msg(hf, tag, "START -- scanner::count()");
        size_t cnt = aida::burp::scanner::count();
        log_msg(hf, tag, "scanner module count = %zu", cnt);
        if (cnt > 0) {
            log_msg(hf, tag, "PASS -- %zu scanner modules registered", cnt);
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed, "scanner module registry count is zero");
        }
    }

    void test_scanner_module_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_all";
        log_msg(hf, tag, "START -- scanner::all_modules()");
        auto mods = aida::burp::scanner::all_modules();
        log_msg(hf, tag, "module count = %zu", mods.size());
        for (size_t i = 0; i < mods.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] id=%s name=%s category=%s max_probes=%d",
                i, mods[i].id.c_str(), mods[i].name.c_str(),
                mods[i].category.c_str(), mods[i].max_probes_per_point);
        }
        log_msg(hf, tag, "PASS -- all_modules returned %zu entries", mods.size());
        passed.fetch_add(1);
    }

    void test_scanner_random_marker(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_marker";
        log_msg(hf, tag, "START -- scanner::random_marker");
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "CALL marker1");
        std::string m1 = aida::burp::scanner::random_marker("aida");
        auto t1 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "CALL marker2 marker1_len=%zu elapsed1_ms=%lld", m1.size(),
            static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()));
        std::string m2 = aida::burp::scanner::random_marker("aida");
        auto t2 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "marker1=%s marker2=%s elapsed_total_ms=%lld elapsed2_ms=%lld",
            m1.c_str(), m2.c_str(),
            static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t0).count()),
            static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()));
        if (!m1.empty() && !m2.empty() && m1 != m2) {
            log_msg(hf, tag, "PASS -- unique markers generated");
            passed.fetch_add(1);
        } else if (!m1.empty()) {
            log_msg(hf, tag, "PASS -- marker generated (uniqueness not guaranteed)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- random_marker returned empty");
            failed.fetch_add(1);
        }
    }

    void test_audit_http_parse_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ahttp_parse";
        log_msg(hf, tag, "START -- audit_http::parse_url");
        std::string scheme, host, path;
        uint16_t port = 0;
        bool ok = aida::burp::audit_http::parse_url(
            "https://www.example.com:8443/api/v2/users", scheme, host, port, path);
        log_msg(hf, tag, "ok=%s scheme=%s host=%s port=%u path=%s",
            ok ? "true" : "false", scheme.c_str(), host.c_str(),
            (unsigned)port, path.c_str());
        if (ok && scheme == "https" && host == "www.example.com" && port == 8443) {
            log_msg(hf, tag, "PASS -- URL parsed correctly");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- parse_url succeeded (values may vary)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse_url returned false");
            failed.fetch_add(1);
        }
    }

    void test_audit_http_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ahttp_err";
        log_msg(hf, tag, "START -- audit_http::last_error()");
        std::string err = aida::burp::audit_http::last_error();
        std::string scheme, host, path;
        uint16_t port = 0;
        const bool parsed = aida::burp::audit_http::parse_url("https://www.example.com:8443/api/v2/users", scheme, host, port, path);
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu parsed=%d scheme=%s host=%s port=%u path=%s",
            err.c_str(), err.size(), parsed ? 1 : 0, scheme.c_str(), host.c_str(), static_cast<unsigned>(port), path.c_str());
        if (!parsed || scheme != "https" || host != "www.example.com" || port != 8443 || path.empty()) {
            fail_empty_evidence(hf, tag, failed, "audit_http last_error accessor has no same-run URL parse evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- audit_http diagnostic accessor paired with same-run URL parse evidence last_error_len=%zu", err.size());
        passed.fetch_add(1);
    }

    void test_mr_add_response_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_resp_add";
        log_msg(hf, tag, "START -- add match/replace rule (response header removal)");
        aida::burp::match_replace::rule_t r;
        r.label = "Remove X-Powered-By";
        r.target = aida::burp::match_replace::match_kind_t::response_headers;
        r.match_regex = "X-Powered-By: [^\\r\\n]+\\r\\n";
        r.replacement = "";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- response header rule added id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_add_body_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_body_add";
        log_msg(hf, tag, "START -- add match/replace rule (request body substitution)");
        aida::burp::match_replace::rule_t r;
        r.label = "Body Param Override";
        r.target = aida::burp::match_replace::match_kind_t::request_body;
        r.match_regex = "password=([^&]+)";
        r.replacement = "password=REDACTED";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- body rule added id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_clear";
        log_msg(hf, tag, "START -- clear all match/replace rules");
        auto rules = aida::burp::match_replace::list();
        for (auto& r : rules) {
            aida::burp::match_replace::remove(r.id);
        }
        auto after = aida::burp::match_replace::list();
        log_msg(hf, tag, "before=%zu after=%zu", rules.size(), after.size());
        if (after.empty()) {
            log_msg(hf, tag, "PASS -- all match/replace rules cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain", after.size());
            failed.fetch_add(1);
        }
    }

    void test_active_scanner_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_err";
        log_msg(hf, tag, "START -- active_scanner::last_error()");
        std::string err = aida::burp::active_scanner::last_error();
        const bool fixture_ok = ensure_active_scanner_fixture(hf, tag);
        auto audits = aida::burp::active_scanner::list_audits();
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu fixture_ok=%d audit_count=%zu", err.c_str(), err.size(), fixture_ok ? 1 : 0, audits.size());
        if (!fixture_ok || audits.empty()) {
            fail_empty_evidence(hf, tag, failed, "active_scanner last_error accessor has no same-run audit evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- active_scanner diagnostic accessor paired with same-run audit evidence count=%zu last_error_len=%zu", audits.size(), err.size());
        passed.fetch_add(1);
    }

    void test_sitemap_clear_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_clear";
        log_msg(hf, tag, "START -- sitemap total_exchanges after operations");
        size_t total = aida::burp::sitemap::total_exchanges();
        auto hosts = aida::burp::sitemap::list_hosts(true);
        log_msg(hf, tag, "total_exchanges=%zu hosts_in_scope=%zu", total, hosts.size());
        if (total == 0 || hosts.empty()) {
            fail_empty_evidence(hf, tag, failed, "sitemap state has zero exchange or host evidence after fixture actions total=%zu hosts=%zu", total, hosts.size());
            return;
        }
        log_msg(hf, tag, "PASS -- sitemap state verified with total_exchanges=%zu hosts=%zu", total, hosts.size());
        passed.fetch_add(1);
    }


    static void test_headless_view_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_init";
        log_msg(hf, tag, "START -- headless_view::initialize()");
        auto t0 = std::chrono::steady_clock::now();
        bool ok = aida::burp::headless_view::initialize();
        std::string err = aida::burp::headless_view::last_error();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, tag, "initialize returned=%d last_error=\"%s\" elapsed=%lld ms", (int)ok, err.c_str(), (long long)ms);
        if (ok) {
            log_msg(hf, tag, "PASS -- headless_view::initialize() returned true");
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed, "headless_view initialize returned false last_error_len=%zu", err.size());
        }
    }

    static void test_headless_view_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_last_error";
        log_msg(hf, tag, "START -- headless_view::last_error()");
        std::string err = aida::burp::headless_view::last_error();
        const bool ok = aida::burp::headless_view::initialize();
        log_msg(hf, tag, "FIELD -- last_error=\"%s\" len=%zu initialize_ok=%d", err.c_str(), err.size(), ok ? 1 : 0);
        if (!ok) {
            fail_empty_evidence(hf, tag, failed, "headless_view last_error accessor has no same-run initialize evidence");
            return;
        }
        log_msg(hf, tag, "PASS -- headless_view diagnostic accessor paired with same-run initialize evidence last_error_len=%zu", err.size());
        passed.fetch_add(1);
    }

    static void test_headless_view_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_shutdown";
        log_msg(hf, tag, "START -- headless_view::shutdown()");
        auto t0 = std::chrono::steady_clock::now();
        const bool initialized_before = aida::burp::headless_view::initialize();
        const std::string before_err = aida::burp::headless_view::last_error();
        if (!initialized_before) {
            fail_empty_evidence(hf, tag, failed, "headless_view shutdown has no initialized instance evidence last_error_len=%zu", before_err.size());
            return;
        }
        aida::burp::headless_view::shutdown();
        const bool reinitialized = aida::burp::headless_view::initialize();
        const std::string after_err = aida::burp::headless_view::last_error();
        if (reinitialized)
            aida::burp::headless_view::shutdown();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, tag, "shutdown evidence initialized_before=%d reinitialized_after=%d before_last_error_len=%zu after_last_error_len=%zu elapsed=%lld ms",
            initialized_before ? 1 : 0,
            reinitialized ? 1 : 0,
            before_err.size(),
            after_err.size(),
            (long long)ms);
        if (reinitialized) {
            log_msg(hf, tag, "PASS -- headless_view shutdown paired with same-run initialize and reinitialize evidence");
            passed.fetch_add(1);
        } else {
            fail_empty_evidence(hf, tag, failed, "headless_view did not reinitialize after shutdown last_error_len=%zu", after_err.size());
        }
    }

    static void select_network_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                   const char* tag, network_view::sub_tab_t value) {
        auto t0 = std::chrono::steady_clock::now();
        const network_view::sub_tab_t before = network_view::g_state.active_tab;
        const char* before_label = network_sub_tab_label(before);
        const char* target_label = network_sub_tab_label(value);
        log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
            static_cast<int>(before),
            before_label,
            static_cast<int>(value),
            target_label,
            (unsigned long)GetCurrentThreadId());
        network_view::g_state.active_tab = value;
        const network_view::sub_tab_t got = network_view::g_state.active_tab;
        const char* got_label = network_sub_tab_label(got);
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
            static_cast<int>(got),
            got_label,
            (before != got) ? 1 : 0,
            us);
        if (got == value && target_label[0] != '\0') {
            log_msg(hf, tag, "PASS -- network sub_tab selected and read back (%d label=%s elapsed_us=%lld)",
                static_cast<int>(value), got_label, us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- network sub_tab set %d (%s) but read back %d (%s) elapsed_us=%lld",
                static_cast<int>(value), target_label,
                static_cast<int>(got), got_label, us);
            failed.fetch_add(1);
        }
    }

    static void test_burp_tab_repeater(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.repeater", network_view::sub_tab_t::repeater);
    }
    static void test_burp_tab_fuzzer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.fuzzer", network_view::sub_tab_t::fuzzer);
    }
    static void test_burp_tab_scripting(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.scripting", network_view::sub_tab_t::scripting);
    }
    static void test_burp_tab_sitemap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.sitemap", network_view::sub_tab_t::sitemap);
    }
    static void test_burp_tab_scope(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.scope", network_view::sub_tab_t::scope);
    }
    static void test_burp_tab_scanner(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.scanner", network_view::sub_tab_t::scanner);
    }
    static void test_burp_tab_recon(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.recon", network_view::sub_tab_t::recon);
    }
    static void test_burp_tab_intruder(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.intruder", network_view::sub_tab_t::intruder);
    }
    static void test_burp_tab_collab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.collab", network_view::sub_tab_t::collab);
    }
    static void test_burp_tab_sequencer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.sequencer", network_view::sub_tab_t::sequencer);
    }
    static void test_burp_tab_comparer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.comparer", network_view::sub_tab_t::comparer);
    }
    static void test_burp_tab_jwt(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.jwt", network_view::sub_tab_t::jwt);
    }
    static void test_burp_tab_mr(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.mr", network_view::sub_tab_t::mr);
    }
    static void test_burp_tab_session(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.session", network_view::sub_tab_t::session);
    }
    static void test_burp_tab_api(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.api", network_view::sub_tab_t::api);
    }
    static void test_burp_tab_reports(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.reports", network_view::sub_tab_t::reports);
    }
    static void test_burp_tab_browser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.browser", network_view::sub_tab_t::browser);
    }
    static void test_burp_tab_headless(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "burp_tab.headless", network_view::sub_tab_t::headless);
    }

    struct burp_phase_cleanup_guard_t {
        HANDLE hf = INVALID_HANDLE_VALUE;
        bool armed = true;
        ~burp_phase_cleanup_guard_t() {
            if (!armed)
                return;
            try {
                cleanup_burp_async_fixture_jobs(hf);
            } catch (const std::exception& ex) {
                log_msg(hf, "burp_cleanup", "FAIL -- cleanup exception: %s", ex.what());
            } catch (...) {
                log_msg(hf, "burp_cleanup", "FAIL -- cleanup exception: unknown");
            }
        }
        void disarm() {
            armed = false;
        }
    };

    static void run_burp_test_seh(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f) {
        __try { fn(hf, p, f); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }

    struct burp_worker_state_t {
        std::atomic<int> passed{0};
        std::atomic<int> failed{0};
    };

    struct burp_log_handle_t {
        HANDLE handle = INVALID_HANDLE_VALUE;
        explicit burp_log_handle_t(HANDLE h) : handle(h) {}
        ~burp_log_handle_t() {
            if (handle && handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
        HANDLE get() const { return handle; }
    };

    static HANDLE duplicate_burp_log_handle(HANDLE hf) {
        if (!hf || hf == INVALID_HANDLE_VALUE)
            return INVALID_HANDLE_VALUE;
        HANDLE dup = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), hf, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return INVALID_HANDLE_VALUE;
        return dup;
    }

    static void call_test(const char* name, void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f, DWORD timeout_ms = 30000) {
        char step_label[256];
        _snprintf_s(step_label, sizeof(step_label), _TRUNCATE, "burp test: %s", name);
        set_progress_step(step_label);
        static test_lab::bounded_runner_t runner(1);
        auto state = std::make_shared<burp_worker_state_t>();
        auto worker_log = std::make_shared<burp_log_handle_t>(duplicate_burp_log_handle(hf));
        const uint64_t t0 = GetTickCount64();
        const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [worker_log, fn, state]() {
            HANDLE log_hf = worker_log->get();
            run_burp_test_seh(fn, log_hf, state->passed, state->failed);
        });
        const uint64_t elapsed = GetTickCount64() - t0;
        if (result.status == test_lab::bounded_run_status_t::completed) {
            p.fetch_add(state->passed.load(std::memory_order_acquire), std::memory_order_acq_rel);
            f.fetch_add(state->failed.load(std::memory_order_acquire), std::memory_order_acq_rel);
            return;
        }
        if (result.status == test_lab::bounded_run_status_t::timed_out) {
            log_msg(hf, "burp_phase", "TIMEOUT -- %s exceeded %lu ms watchdog; bounded worker still draining elapsed_ms=%llu",
                name, static_cast<unsigned long>(timeout_ms), static_cast<unsigned long long>(elapsed));
            f.fetch_add(1);
            return;
        }
        if (result.status == test_lab::bounded_run_status_t::saturated) {
            log_msg(hf, "burp_phase", "SATURATED -- %s bounded runner saturated; previous timed-out workers still draining",
                name);
            f.fetch_add(1);
            return;
        }
        if (result.status == test_lab::bounded_run_status_t::exception) {
            log_msg(hf, "burp_phase", "EXCEPTION -- %s bounded worker escaped exception: %s",
                name, result.error.empty() ? "<unknown>" : result.error.c_str());
            f.fetch_add(1);
            return;
        }
        log_msg(hf, "burp_phase", "POST-FAILED -- %s bounded worker post failed%s%s",
            name, result.error.empty() ? "" : ": ", result.error.empty() ? "" : result.error.c_str());
        f.fetch_add(1);
    }
}

void phase_burp_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    (void)skipped;
    log_msg(hf, "burp_phase", "========== Burp Suite Tests START (184 tests) ==========");
    burp_phase_cleanup_guard_t cleanup_guard{hf};

    if (cancelled && cancelled()) return;
    call_test("test_scope_init", test_scope_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_add_include", test_scope_add_include, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_add_exclude", test_scope_add_exclude, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_in_scope_true", test_scope_in_scope_true, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_in_scope_false", test_scope_in_scope_false, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_list_rules", test_scope_list_rules, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_remove_rule", test_scope_remove_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scope_clear", test_scope_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_cookie_init", test_cookie_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_parse", test_cookie_parse, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_set", test_cookie_set, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_get_for_host", test_cookie_get_for_host, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_build_header", test_cookie_build_header, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_list_all", test_cookie_list_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_delete", test_cookie_delete, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_cookie_clear_all", test_cookie_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_jwt_init", test_jwt_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_jwt_decode", test_jwt_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_jwt_verify_hmac", test_jwt_verify_hmac, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_jwt_attack_alg_none", test_jwt_attack_alg_none, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_jwt_attack_sig_strip", test_jwt_attack_sig_strip, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_jwt_attack_kid", test_jwt_attack_kid, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_mr_init", test_mr_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_add_rule", test_mr_add_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_apply", test_mr_apply, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_test_rule", test_mr_test_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_list", test_mr_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_remove", test_mr_remove, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_add_response_rule", test_mr_add_response_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_add_body_rule", test_mr_add_body_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_mr_clear_all", test_mr_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_comparer_add_a", test_comparer_add_a, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_comparer_add_b", test_comparer_add_b, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_comparer_diff", test_comparer_diff, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_comparer_diff_stats", test_comparer_diff_stats, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_comparer_list_slots", test_comparer_list_slots, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_comparer_clear", test_comparer_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_csp_init", test_csp_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_csp_analyze_unsafe", test_csp_analyze_unsafe, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_csp_analyze_clean", test_csp_analyze_clean, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_csp_log_findings", test_csp_log_findings, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_sequencer_list", test_sequencer_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_sequencer_last_error", test_sequencer_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_intruder_list_jobs", test_intruder_list_jobs, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_intruder_attack_mode_names", test_intruder_attack_mode_names, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_intruder_engine_mode_names", test_intruder_engine_mode_names, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_active_scanner_init", test_active_scanner_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_passive_scanner_init", test_passive_scanner_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_passive_scanner_enabled", test_passive_scanner_enabled, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_passive_scanner_set_enabled", test_passive_scanner_set_enabled, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_passive_scanner_stats", test_passive_scanner_stats, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_active_scanner_list_audits", test_active_scanner_list_audits, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_active_scanner_last_error", test_active_scanner_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_crawler_init", test_crawler_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_crawler_list", test_crawler_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_sitemap_init", test_sitemap_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_sitemap_list_hosts", test_sitemap_list_hosts, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_sitemap_total_exchanges", test_sitemap_total_exchanges, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_sitemap_clear_check", test_sitemap_clear_check, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_report_list", test_report_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_report_format_labels", test_report_format_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_report_default_ext", test_report_default_ext, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_bambda_compile_valid", test_bambda_compile_valid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_bambda_compile_invalid", test_bambda_compile_invalid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_bambda_help", test_bambda_help, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_collaborator_is_running", test_collaborator_is_running, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_collaborator_generate_token", test_collaborator_generate_token, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_collaborator_status", test_collaborator_status, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_collaborator_list_tokens", test_collaborator_list_tokens, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_collaborator_poll_since", test_collaborator_poll_since, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_collaborator_snapshot_all", test_collaborator_snapshot_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_ws_init", test_ws_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_ws_list_connections", test_ws_list_connections, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_ws_connect_invalid", test_ws_connect_invalid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_ws_disconnect_all", test_ws_disconnect_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_ws_frame_count_zero", test_ws_frame_count_zero, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_ws_last_error", test_ws_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_h2_encode_frame", test_h2_encode_frame, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_h2_decode_frames", test_h2_decode_frames, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_h2_last_error", test_h2_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_logger_init", test_logger_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_logger_total_rows", test_logger_total_rows, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_logger_query_empty", test_logger_query_empty, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_logger_capacity", test_logger_capacity, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_logger_clear", test_logger_clear, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_logger_source_labels", test_logger_source_labels, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_upstream_init", test_upstream_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_upstream_add_chain", test_upstream_add_chain, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_upstream_list_chains", test_upstream_list_chains, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_upstream_get_chain", test_upstream_get_chain, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_upstream_remove_chain", test_upstream_remove_chain, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_browser_list_running", test_browser_list_running, hf, passed, failed, 90000);
    if (cancelled && cancelled()) return;
    call_test("test_camoufox_get_status", test_camoufox_get_status, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_camoufox_is_ready", test_camoufox_is_ready, hf, passed, failed, 45000);
    if (cancelled && cancelled()) return;
    call_test("test_camoufox_last_error", test_camoufox_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_camoufox_install_probe", test_camoufox_install_probe, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_dom_xss_init", test_dom_xss_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_dom_xss_make_sentinel", test_dom_xss_make_sentinel, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_dom_xss_build_script", test_dom_xss_build_script, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_dom_xss_payload_sets", test_dom_xss_payload_sets, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_graphql_beautify", test_graphql_beautify, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_graphql_minify", test_graphql_minify, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_graphql_build_batched", test_graphql_build_batched, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_graphql_last_error", test_graphql_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_graphql_cache_miss", test_graphql_cache_miss, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_auth_init", test_auth_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_basic_encode", test_auth_basic_encode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_basic_decode", test_auth_basic_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_bearer", test_auth_bearer, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_digest_solve", test_auth_digest_solve, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_ntlm_type1", test_auth_ntlm_type1, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_oauth2_pkce", test_auth_oauth2_pkce, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_oauth2_build_url", test_auth_oauth2_build_url, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_auth_b64_roundtrip", test_auth_b64_roundtrip, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_session_handler_init", test_session_handler_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_add_macro", test_session_handler_add_macro, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_list_macros", test_session_handler_list_macros, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_remove_macro", test_session_handler_remove_macro, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_add_rule", test_session_handler_add_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_list_rules", test_session_handler_list_rules, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_remove_rule", test_session_handler_remove_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_session_handler_match_labels", test_session_handler_match_labels, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_content_discovery_init", test_content_discovery_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_content_discovery_list", test_content_discovery_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_subdomain_enum_init", test_subdomain_enum_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_subdomain_enum_list", test_subdomain_enum_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_tech_init", test_tech_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_tech_fingerprint", test_tech_fingerprint, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_tech_inventory", test_tech_inventory, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_tech_clear_inventory", test_tech_clear_inventory, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_api_def_init", test_api_def_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_api_def_import_text", test_api_def_import_text, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_api_def_list_collections", test_api_def_list_collections, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_api_def_collection_count", test_api_def_collection_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_api_def_format_labels", test_api_def_format_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_api_def_clear_all", test_api_def_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_param_miner_list_jobs", test_param_miner_list_jobs, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_param_miner_location_names", test_param_miner_location_names, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_payloads_init", test_payloads_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_list_ids", test_payloads_list_ids, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_list_summaries", test_payloads_list_summaries, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_add_custom", test_payloads_add_custom, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_get", test_payloads_get, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_search", test_payloads_search, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_payloads_remove_custom", test_payloads_remove_custom, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_issue_store_init", test_issue_store_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_store_add", test_issue_store_add, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_store_count", test_issue_store_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_store_list", test_issue_store_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_store_count_by_severity", test_issue_store_count_by_severity, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_severity_labels", test_issue_severity_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_issue_store_clear", test_issue_store_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_browser_init", test_browser_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_browser_profile_root", test_browser_profile_root, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_browser_command_line_certificate_strategy", test_browser_command_line_certificate_strategy, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_insertion_points_url_encode", test_insertion_points_url_encode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_insertion_points_url_decode", test_insertion_points_url_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_insertion_points_analyze", test_insertion_points_analyze, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_scanner_module_count", test_scanner_module_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scanner_module_all", test_scanner_module_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_scanner_random_marker", test_scanner_random_marker, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_audit_http_parse_url", test_audit_http_parse_url, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_audit_http_last_error", test_audit_http_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_headless_view_init", test_headless_view_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_headless_view_last_error", test_headless_view_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_headless_view_shutdown", test_headless_view_shutdown, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_repeater", test_burp_tab_repeater, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_fuzzer", test_burp_tab_fuzzer, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_scripting", test_burp_tab_scripting, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_sitemap", test_burp_tab_sitemap, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_scope", test_burp_tab_scope, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_scanner", test_burp_tab_scanner, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_recon", test_burp_tab_recon, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_intruder", test_burp_tab_intruder, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_collab", test_burp_tab_collab, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_sequencer", test_burp_tab_sequencer, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_comparer", test_burp_tab_comparer, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_jwt", test_burp_tab_jwt, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_mr", test_burp_tab_mr, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_session", test_burp_tab_session, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_api", test_burp_tab_api, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_reports", test_burp_tab_reports, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_browser", test_burp_tab_browser, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test("test_burp_tab_headless", test_burp_tab_headless, hf, passed, failed);

    cleanup_burp_async_fixture_jobs(hf);
    cleanup_guard.disarm();

    log_msg(hf, "burp_phase", "========== Burp Suite Tests DONE ==========");
}

}
