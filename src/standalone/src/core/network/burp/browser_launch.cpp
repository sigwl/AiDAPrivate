#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>

#ifdef small
#undef small
#endif

#include "browser_launch.hpp"
#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"

#include "../cert_generator.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace browser {

namespace {

struct tracked_pid_t
{
    uint32_t    pid = 0;
    std::string browser_path;
    std::string profile_path;
    uint16_t    proxy_port = 0;
    uint64_t    launched_ms = 0;
    certificate_strategy_t certificate_strategy = certificate_strategy_t::camoufox_spki_allowlist;
    std::string spki_hash_prefix;
};

struct state_t
{
    std::mutex                  mtx;
    std::vector<tracked_pid_t>  tracked;
    std::atomic<bool>           initialized{false};
    std::mutex                  err_mtx;
    std::string                 last_err;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

const char* install_state_name(camoufox::install::install_state_t state)
{
    using install_state_t = camoufox::install::install_state_t;
    switch (state) {
    case install_state_t::unknown: return "unknown";
    case install_state_t::checking: return "checking";
    case install_state_t::available: return "available";
    case install_state_t::missing_python: return "missing_python";
    case install_state_t::missing_module: return "missing_module";
    case install_state_t::missing_browser: return "missing_browser";
    case install_state_t::installing: return "installing";
    case install_state_t::install_failed: return "install_failed";
    case install_state_t::ok: return "ok";
    default: return "unknown";
    }
}

const char* bridge_state_name(camoufox::bridge_state_t state)
{
    using bridge_state_t = camoufox::bridge_state_t;
    switch (state) {
    case bridge_state_t::stopped: return "stopped";
    case bridge_state_t::starting: return "starting";
    case bridge_state_t::ready: return "ready";
    case bridge_state_t::error: return "error";
    default: return "unknown";
    }
}

std::string dependency_summary(const camoufox::install::status_t& st)
{
    std::string msg = "camoufox_dependency_unavailable state=";
    msg += install_state_name(st.state);
    msg += " message=";
    msg += st.last_message.empty() ? "<empty>" : st.last_message;
    msg += " python=";
    msg += st.python_path.empty() ? "<empty>" : st.python_path;
    msg += " module=";
    msg += st.module_version.empty() ? "<empty>" : st.module_version;
    msg += " browser=";
    msg += st.browser_path.empty() ? "<empty>" : st.browser_path;
    return msg;
}

bool camoufox_install_ready(const camoufox::install::status_t& st)
{
    return st.state == camoufox::install::install_state_t::ok &&
           !st.python_path.empty() &&
           !st.module_version.empty() &&
           !st.browser_path.empty();
}

std::string proxy_url(const browser_launch_config_t& cfg)
{
    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "http://%s:%u",
                cfg.proxy_host.empty() ? "127.0.0.1" : cfg.proxy_host.c_str(),
                static_cast<unsigned>(cfg.proxy_port));
    return std::string(buf);
}

std::string wide_to_utf8(const wchar_t* w)
{
    if (!w) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return std::string();
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::string local_appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &known)) && known) {
        out = wide_to_utf8(known);
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) out.assign(buf, len);
    }
    if (out.empty()) out = "C:\\Users\\Public";
    return out;
}

bool quote_path(const std::string& in, std::wstring& out)
{
    if (in.empty() || std::any_of(in.begin(), in.end(), [](unsigned char c) {
        return c < 0x20 || c == 0x7f || c == '"';
    }))
        return false;
    std::wstring w = utf8_to_wide(in);
    if (w.empty()) return false;
    out.clear();
    out.reserve(w.size() + 4);
    out.push_back(L'"');
    out.append(w);
    out.push_back(L'"');
    return true;
}

certificate_strategy_t release_safe_strategy(certificate_strategy_t strategy)
{
    if (strategy == certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only &&
        !certificate_strategy_debug_only_available()) {
        return certificate_strategy_t::trust_store_only;
    }
    return strategy;
}

std::string resolve_spki_allowlist(const browser_launch_config_t& cfg)
{
    if (release_safe_strategy(cfg.certificate_strategy) != certificate_strategy_t::camoufox_spki_allowlist)
        return std::string();
    if (!cfg.spki_allowlist.empty()) return cfg.spki_allowlist;
    if (!::cert_generator::is_ready()) {
        if (!::cert_generator::initialize()) {
            diag::log_tagged("browser", "spki initialize_failed");
            return std::string();
        }
    }
    if (!::cert_generator::is_ready()) {
        diag::log_tagged("browser", "spki cert_not_ready");
        return std::string();
    }
    std::string hash = ::cert_generator::spki_sha256_base64(::cert_generator::get_root_ca());
    if (hash.empty()) {
        diag::log_tagged("browser", "spki hash_empty");
    }
    return hash;
}

browser_launch_config_t effective_config(const browser_launch_config_t& cfg)
{
    browser_launch_config_t effective = cfg;
    effective.certificate_strategy = release_safe_strategy(cfg.certificate_strategy);
    effective.spki_allowlist = resolve_spki_allowlist(effective);
    return effective;
}

}

bool initialize()
{
    diag::log_tagged_fmt("browser", "initialize entry");
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("browser", "initialize already_initialized");
        return true;
    }
    diag::log_tagged("burp_browser", "initialized");
    diag::log_tagged_fmt("browser", "initialize done");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("browser", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("browser", "shutdown not_initialized skipping");
        return;
    }
    std::lock_guard<std::mutex> lk(st.mtx);
    size_t n = st.tracked.size();
    st.tracked.clear();
    diag::log_tagged_fmt("browser", "shutdown done cleared_tracked=%zu", n);
}

bool detect_camoufox_path(std::string& out_path)
{
    diag::log_tagged_fmt("browser", "detect_camoufox_path entry");
    auto st = camoufox::install::probe();
    out_path = st.browser_path;
    const bool ok = camoufox_install_ready(st);
    diag::log_tagged_fmt("browser", "detect_camoufox_path result=%d state=%s python=%s module=%s browser=%s message=%s",
        ok ? 1 : 0,
        install_state_name(st.state),
        st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
        st.module_version.empty() ? "<empty>" : st.module_version.c_str(),
        st.browser_path.empty() ? "<empty>" : st.browser_path.c_str(),
        st.last_message.empty() ? "<empty>" : st.last_message.c_str());
    if (!ok)
        set_err(dependency_summary(st));
    else
        set_err(std::string());
    return ok;
}

std::string profile_root()
{
    std::string base = local_appdata_dir();
    base += "\\AiDA";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    if (ec)
        return std::string();
    diag::log_tagged_fmt("browser", "profile_root result=%s", base.c_str());
    return base;
}

std::string compute_profile_path(const std::string& subdir)
{
    std::string sd = subdir.empty() ? std::string("BurpBrowser") : subdir;
    diag::log_tagged_fmt("browser", "compute_profile_path entry subdir=%s", sd.c_str());
    size_t component_start = 0;
    while (component_start <= sd.size()) {
        const size_t component_end = sd.find_first_of("/\\", component_start);
        const std::string component = sd.substr(component_start,
            component_end == std::string::npos ? std::string::npos : component_end - component_start);
        if (component.empty() || component == "." || component == "..")
            return std::string();
        if (component_end == std::string::npos)
            break;
        component_start = component_end + 1;
    }
    const std::string root = profile_root();
    if (root.empty()) return std::string();
    std::error_code root_status_ec;
    const auto root_status = std::filesystem::symlink_status(root, root_status_ec);
    if (root_status_ec || std::filesystem::is_symlink(root_status) ||
        !std::filesystem::is_directory(root_status))
        return std::string();
    std::string base = root + "\\";
    for (char c : sd) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|') {
            base.push_back('_');
        } else {
            base.push_back(c);
        }
    }
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    if (ec) return std::string();
    const auto profile_status = std::filesystem::symlink_status(base, ec);
    if (ec || std::filesystem::is_symlink(profile_status) ||
        !std::filesystem::is_directory(profile_status))
        return std::string();
    const auto root_path = std::filesystem::weakly_canonical(std::filesystem::path(root), ec);
    if (ec) return std::string();
    const auto profile = std::filesystem::weakly_canonical(std::filesystem::path(base), ec);
    if (ec) return std::string();
    const auto relative = std::filesystem::relative(profile, root_path, ec);
    if (ec || relative.empty() || relative == "." || relative.string().find("..") == 0)
        return std::string();
    diag::log_tagged_fmt("browser", "compute_profile_path result=%s", base.c_str());
    return base;
}

bool certificate_strategy_debug_only_available()
{
#if defined(_DEBUG) || !defined(NDEBUG)
    return true;
#else
    return false;
#endif
}

const char* certificate_strategy_name(certificate_strategy_t strategy)
{
    switch (strategy) {
    case certificate_strategy_t::trust_store_only:
        return "trust_store_only";
    case certificate_strategy_t::camoufox_spki_allowlist:
        return "camoufox_spki_allowlist";
    case certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only:
        return "unsafe_ignore_all_for_debug_builds_only";
    default:
        return "trust_store_only";
    }
}

bool certificate_strategy_from_string(const std::string& name, certificate_strategy_t& out)
{
    if (name == "trust_store_only") {
        out = certificate_strategy_t::trust_store_only;
        return true;
    }
    if (name == "camoufox_spki_allowlist") {
        out = certificate_strategy_t::camoufox_spki_allowlist;
        return true;
    }
    if (name == "unsafe_ignore_all_for_debug_builds_only") {
        out = certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only;
        return true;
    }
    return false;
}

std::string spki_hash_prefix(const std::string& allowlist)
{
    if (allowlist.empty()) return std::string();
    size_t end = allowlist.find(',');
    std::string first = allowlist.substr(0, end == std::string::npos ? allowlist.size() : end);
    while (!first.empty() && (first.back() == ' ' || first.back() == '\t' || first.back() == '\r' || first.back() == '\n'))
        first.pop_back();
    size_t start = 0;
    while (start < first.size() && (first[start] == ' ' || first[start] == '\t' || first[start] == '\r' || first[start] == '\n'))
        ++start;
    if (start > 0) first.erase(0, start);
    if (first.size() <= 12) return first;
    return first.substr(0, 12);
}

namespace {

bool remove_directory_recursive(const std::string& path)
{
    if (path.empty()) return false;
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::is_directory(status) || std::filesystem::is_symlink(status))
        return false;
    for (std::filesystem::directory_iterator it(path, std::filesystem::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        const auto child = it->path();
        const auto child_status = std::filesystem::symlink_status(child, ec);
        if (ec || std::filesystem::is_symlink(child_status) ||
            (std::filesystem::is_directory(child_status) && !remove_directory_recursive(child.string())))
            return false;
        if (!std::filesystem::is_directory(child_status) && !std::filesystem::remove(child, ec))
            return false;
        if (ec) return false;
    }
    return !ec;
}

std::wstring build_command_line(const std::string& browser_path,
                                const browser_launch_config_t& cfg,
                                const std::string& profile_path)
{
    std::wstring cmd;
    std::wstring quoted;
    if (!quote_path(browser_path, quoted)) return std::wstring();
    cmd.append(quoted);

    char proxy_arg[256];
    _snprintf_s(proxy_arg, sizeof(proxy_arg), _TRUNCATE,
                " --proxy-server=%s:%u", cfg.proxy_host.c_str(),
                static_cast<unsigned>(cfg.proxy_port));
    cmd.append(utf8_to_wide(proxy_arg));

    std::wstring quoted_profile;
    if (!quote_path(std::string("--user-data-dir=") + profile_path, quoted_profile)) return std::wstring();
    cmd.push_back(L' ');
    cmd.append(quoted_profile);

    cmd.append(L" --no-first-run");
    cmd.append(L" --no-default-browser-check");
    cmd.append(L" --disable-sync");
    cmd.append(L" --proxy-bypass-list=<-loopback>");
    cmd.append(L" --disable-quic");

    if (cfg.certificate_strategy == certificate_strategy_t::camoufox_spki_allowlist &&
        !cfg.spki_allowlist.empty()) {
        cmd.append(L" --ignore-certificate-errors-spki-list=");
        cmd.append(utf8_to_wide(cfg.spki_allowlist));
    }

#if defined(_DEBUG) || !defined(NDEBUG)
    if (cfg.certificate_strategy == certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only) {
        cmd.append(L" --ignore-certificate-errors");
        cmd.append(L" --test-type");
    }
#endif

    if (!cfg.initial_url.empty()) {
        std::wstring qurl;
        if (quote_path(cfg.initial_url, qurl)) {
            cmd.push_back(L' ');
            cmd.append(qurl);
        }
    } else {
        cmd.append(L" about:blank");
    }

    return cmd;
}

}

std::wstring build_command_line_for_test(const std::string& browser_path,
                                         const browser_launch_config_t& cfg,
                                         const std::string& profile_path)
{
    browser_launch_config_t effective = cfg;
    effective.certificate_strategy = release_safe_strategy(effective.certificate_strategy);
    return build_command_line(browser_path, effective, profile_path);
}

bool launch(const browser_launch_config_t& cfg, uint32_t& out_pid)
{
    const uint64_t launch_start_ms = now_ms();
    browser_launch_config_t effective = effective_config(cfg);
    diag::log_tagged_fmt("browser", "launch entry policy=camoufox_only proxy=%s:%u url=%s cert_strategy=%s spki_prefix=%s clear_profile=%d profile_subdir=%s",
        cfg.proxy_host.c_str(),
        static_cast<unsigned>(cfg.proxy_port), cfg.initial_url.c_str(),
        certificate_strategy_name(effective.certificate_strategy),
        spki_hash_prefix(effective.spki_allowlist).c_str(),
        static_cast<int>(cfg.clear_profile_first), cfg.profile_subdir.c_str());
    out_pid = 0;
    auto& st = s();
    if (!st.initialized.load()) initialize();

    std::string profile_path = compute_profile_path(cfg.profile_subdir);
    if (profile_path.empty()) {
        set_err("invalid browser profile subdirectory");
        diag::log_tagged_fmt("browser", "launch rejected invalid_profile_subdir=%s", cfg.profile_subdir.c_str());
        return false;
    }
    if (cfg.clear_profile_first) {
        diag::log_tagged_fmt("browser", "launch clearing_profile profile=%s policy=camoufox_only", profile_path.c_str());
        if (!remove_directory_recursive(profile_path)) {
            set_err("browser profile cleanup rejected or failed");
            diag::log_tagged_fmt("browser", "launch profile_clear_rejected profile=%s", profile_path.c_str());
            return false;
        }
        std::error_code ec;
        std::filesystem::create_directories(profile_path, ec);
        if (ec) {
            set_err("browser profile recreation failed");
            diag::log_tagged_fmt("browser", "launch profile_clear_recreate_failed profile=%s ec=%d", profile_path.c_str(), ec.value());
            return false;
        }
        diag::log_tagged_fmt("browser", "launch profile_clear_result profile=%s ec=0", profile_path.c_str());
    }

    const uint64_t probe_start_ms = now_ms();
    diag::log_tagged_fmt("browser", "launch camoufox_probe_begin profile=%s proxy=%s", profile_path.c_str(), proxy_url(effective).c_str());
    camoufox::install::status_t install_status = camoufox::install::probe();
    diag::log_tagged_fmt("browser", "launch camoufox_probe_done elapsed_ms=%llu state=%s python=%s module=%s browser=%s message=%s",
        static_cast<unsigned long long>(now_ms() - probe_start_ms),
        install_state_name(install_status.state),
        install_status.python_path.empty() ? "<empty>" : install_status.python_path.c_str(),
        install_status.module_version.empty() ? "<empty>" : install_status.module_version.c_str(),
        install_status.browser_path.empty() ? "<empty>" : install_status.browser_path.c_str(),
        install_status.last_message.empty() ? "<empty>" : install_status.last_message.c_str());
    if (!camoufox_install_ready(install_status)) {
        std::string err = dependency_summary(install_status);
        set_err(err);
        diag::log_tagged_fmt("browser", "launch fail_closed dependency_missing elapsed_ms=%llu reason=%s",
            static_cast<unsigned long long>(now_ms() - launch_start_ms), err.c_str());
        return false;
    }

    camoufox::launch_config_t bridge_cfg;
    bridge_cfg.headless = false;
    bridge_cfg.proxy = proxy_url(effective);
    bridge_cfg.python_executable = install_status.python_path;
    bridge_cfg.launch_timeout_ms = 75000;
    bridge_cfg.window_width = 1280;
    bridge_cfg.window_height = 900;

    diag::log_tagged_fmt("browser", "launch camoufox_start_bridge args headless=%d proxy=%s python=%s module=%s timeout_ms=%d window=%dx%d resolved_browser=%s profile=%s",
        static_cast<int>(bridge_cfg.headless), bridge_cfg.proxy.c_str(),
        bridge_cfg.python_executable.c_str(), bridge_cfg.server_module.c_str(),
        bridge_cfg.launch_timeout_ms, bridge_cfg.window_width, bridge_cfg.window_height,
        install_status.browser_path.c_str(), profile_path.c_str());
    bool started = camoufox::start_bridge(bridge_cfg);
    camoufox::bridge_status_t bridge_status = camoufox::get_status();
    diag::log_tagged_fmt("browser", "launch camoufox_start_bridge_done ok=%d elapsed_ms=%llu state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_started_ms=%llu attempt_elapsed_ms=%llu last_attempt_elapsed_ms=%llu status_age_ms=%llu last_debug_event=%s active_url_len=%zu last_error=%s",
        static_cast<int>(started), static_cast<unsigned long long>(now_ms() - launch_start_ms),
        bridge_state_name(bridge_status.state), static_cast<unsigned long>(bridge_status.child_pid),
        static_cast<int>(bridge_status.child_alive), static_cast<int>(bridge_status.browser_open),
        static_cast<int>(bridge_status.page_verified), static_cast<int>(bridge_status.privacy_verified), static_cast<int>(bridge_status.cleanup_pending),
        bridge_status.phase.empty() ? "<empty>" : bridge_status.phase.c_str(),
        bridge_status.readiness_phase.empty() ? "<empty>" : bridge_status.readiness_phase.c_str(),
        bridge_status.error_type.empty() ? "<empty>" : bridge_status.error_type.c_str(),
        bridge_status.error_kind.empty() ? "<empty>" : bridge_status.error_kind.c_str(),
        bridge_status.protocol_schema_viewport ? 1 : 0,
        static_cast<unsigned long long>(bridge_status.attempt_started_ms),
        static_cast<unsigned long long>(bridge_status.attempt_elapsed_ms),
        static_cast<unsigned long long>(bridge_status.last_attempt_elapsed_ms),
        static_cast<unsigned long long>(bridge_status.status_age_ms),
        bridge_status.last_debug_event.empty() ? "<empty>" : bridge_status.last_debug_event.c_str(),
        bridge_status.active_page_url.size(),
        bridge_status.last_error.empty() ? "<empty>" : bridge_status.last_error.c_str());
    if (!started || bridge_status.child_pid == 0 || !bridge_status.child_alive || !bridge_status.browser_open || !bridge_status.page_verified) {
        std::string err = bridge_status.last_error.empty() ? std::string("camoufox bridge did not become ready") : bridge_status.last_error;
        set_err(err);
        diag::log_tagged_fmt("browser", "launch fail_closed bridge_not_ready state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_elapsed_ms=%llu last_debug_event=%s err=%s",
            bridge_state_name(bridge_status.state), static_cast<unsigned long>(bridge_status.child_pid),
            static_cast<int>(bridge_status.child_alive), static_cast<int>(bridge_status.browser_open),
            static_cast<int>(bridge_status.page_verified), static_cast<int>(bridge_status.privacy_verified),
            bridge_status.phase.empty() ? "<empty>" : bridge_status.phase.c_str(),
            bridge_status.readiness_phase.empty() ? "<empty>" : bridge_status.readiness_phase.c_str(),
            bridge_status.error_type.empty() ? "<empty>" : bridge_status.error_type.c_str(),
            bridge_status.error_kind.empty() ? "<empty>" : bridge_status.error_kind.c_str(),
            bridge_status.protocol_schema_viewport ? 1 : 0,
            static_cast<unsigned long long>(bridge_status.attempt_elapsed_ms),
            bridge_status.last_debug_event.empty() ? "<empty>" : bridge_status.last_debug_event.c_str(),
            err.c_str());
        return false;
    }

    if (!effective.initial_url.empty() && effective.initial_url != "about:blank") {
        diag::log_tagged_fmt("browser", "launch initial_navigation_begin child_pid=%lu url_len=%zu",
            static_cast<unsigned long>(bridge_status.child_pid), effective.initial_url.size());
        bool nav_ok = camoufox::navigate(effective.initial_url, std::string("load"), 30000);
        bridge_status = camoufox::get_status();
        diag::log_tagged_fmt("browser", "launch initial_navigation_done ok=%d state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d active_url_len=%zu nav_ms=%llu err=%s",
            static_cast<int>(nav_ok), bridge_state_name(bridge_status.state),
            static_cast<unsigned long>(bridge_status.child_pid), static_cast<int>(bridge_status.child_alive),
            static_cast<int>(bridge_status.browser_open), static_cast<int>(bridge_status.page_verified),
            bridge_status.active_page_url.size(), static_cast<unsigned long long>(bridge_status.last_nav_ms),
            bridge_status.last_error.empty() ? "<empty>" : bridge_status.last_error.c_str());
        if (!nav_ok || !bridge_status.child_alive || !bridge_status.browser_open || !bridge_status.page_verified) {
            std::string err = bridge_status.last_error.empty() ? std::string("camoufox initial navigation failed") : bridge_status.last_error;
            set_err(err);
            return false;
        }
    }

    out_pid = bridge_status.child_pid;
    tracked_pid_t rec;
    rec.pid = out_pid;
    rec.browser_path = install_status.browser_path.empty() ? std::string("Camoufox") : install_status.browser_path;
    rec.profile_path = profile_path;
    rec.proxy_port = effective.proxy_port;
    rec.launched_ms = bridge_status.launched_ms != 0 ? bridge_status.launched_ms : now_ms();
    rec.certificate_strategy = effective.certificate_strategy;
    rec.spki_hash_prefix = spki_hash_prefix(effective.spki_allowlist);

    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                        [out_pid](const tracked_pid_t& r) { return r.pid == out_pid; }),
                         st.tracked.end());
        st.tracked.push_back(rec);
    }

    set_err(std::string());
    diag::log_tagged("burp_browser", "camoufox launched");
    diag::log_tagged_fmt("browser", "launch ok policy=camoufox_only bridge_pid=%u profile=%s proxy_port=%u elapsed_ms=%llu active_url_len=%zu title_len=%zu",
        out_pid, profile_path.c_str(), static_cast<unsigned>(effective.proxy_port),
        static_cast<unsigned long long>(now_ms() - launch_start_ms),
        bridge_status.active_page_url.size(), bridge_status.active_page_title.size());
    return true;
}

bool kill(uint32_t pid)
{
    diag::log_tagged_fmt("browser", "kill entry policy=camoufox_only pid=%u", pid);
    if (pid == 0) {
        diag::log_tagged_fmt("browser", "kill pid_zero rejected");
        set_err("kill_pid_zero");
        return false;
    }

    camoufox::bridge_status_t bridge_status = camoufox::get_status();
    diag::log_tagged_fmt("browser", "kill camoufox_snapshot state=%s child_pid=%lu child_alive=%d browser_open=%d cleanup_pending=%d requested_pid=%u",
        bridge_state_name(bridge_status.state), static_cast<unsigned long>(bridge_status.child_pid),
        static_cast<int>(bridge_status.child_alive), static_cast<int>(bridge_status.browser_open),
        static_cast<int>(bridge_status.cleanup_pending), pid);
    if (bridge_status.child_pid != pid) {
        auto& st = s();
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                            [pid](const tracked_pid_t& r) { return r.pid == pid; }),
                             st.tracked.end());
        }
        set_err("camoufox_pid_not_active");
        diag::log_tagged_fmt("browser", "kill rejected pid_not_active requested_pid=%u active_child_pid=%lu",
            pid, static_cast<unsigned long>(bridge_status.child_pid));
        return false;
    }

    bool ok = camoufox::stop_bridge("browser_launch.stop");
    auto after = camoufox::get_status();
    {
        auto& st = s();
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                        [pid](const tracked_pid_t& r) { return r.pid == pid; }),
                         st.tracked.end());
    }
    if (!ok) {
        std::string err = after.last_error.empty() ? camoufox::last_error() : after.last_error;
        if (err.empty()) err = "camoufox_stop_failed";
        set_err(err);
    } else {
        set_err(std::string());
    }
    diag::log_tagged_fmt("browser", "kill camoufox_stop_result ok=%d requested_pid=%u after_state=%s after_child_pid=%lu cleanup_pending=%d err=%s",
        static_cast<int>(ok), pid, bridge_state_name(after.state), static_cast<unsigned long>(after.child_pid),
        static_cast<int>(after.cleanup_pending), after.last_error.empty() ? "<empty>" : after.last_error.c_str());
    return ok;
}

bool kill_all()
{
    diag::log_tagged_fmt("browser", "kill_all entry policy=camoufox_only");
    camoufox::bridge_status_t before = camoufox::get_status();
    diag::log_tagged_fmt("browser", "kill_all camoufox_snapshot state=%s child_pid=%lu child_alive=%d browser_open=%d cleanup_pending=%d",
        bridge_state_name(before.state), static_cast<unsigned long>(before.child_pid),
        static_cast<int>(before.child_alive), static_cast<int>(before.browser_open),
        static_cast<int>(before.cleanup_pending));

    bool ok = true;
    if (before.child_pid != 0 || before.state != camoufox::bridge_state_t::stopped || before.cleanup_pending)
        ok = camoufox::stop_bridge("browser_launch.restart");

    auto& st = s();
    size_t cleared = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        cleared = st.tracked.size();
        st.tracked.clear();
    }
    camoufox::bridge_status_t after = camoufox::get_status();
    if (!ok) {
        std::string err = after.last_error.empty() ? camoufox::last_error() : after.last_error;
        if (err.empty()) err = "camoufox_stop_failed";
        set_err(err);
    } else {
        set_err(std::string());
    }
    diag::log_tagged_fmt("browser", "kill_all done ok=%d cleared_tracked=%zu after_state=%s after_child_pid=%lu cleanup_pending=%d err=%s",
        static_cast<int>(ok), cleared, bridge_state_name(after.state), static_cast<unsigned long>(after.child_pid),
        static_cast<int>(after.cleanup_pending), after.last_error.empty() ? "<empty>" : after.last_error.c_str());
    return ok;
}

void register_browser_pid(uint32_t pid)
{
    diag::log_tagged_fmt("browser", "register_browser_pid entry policy=camoufox_only pid=%u", pid);
    if (pid == 0) {
        diag::log_tagged_fmt("browser", "register_browser_pid pid_zero rejected");
        return;
    }
    camoufox::bridge_status_t bridge_status = camoufox::get_status();
    if (bridge_status.child_pid != pid || !bridge_status.child_alive) {
        diag::log_tagged_fmt("browser", "register_browser_pid rejected non_camoufox pid=%u active_child_pid=%lu child_alive=%d",
            pid, static_cast<unsigned long>(bridge_status.child_pid), static_cast<int>(bridge_status.child_alive));
        return;
    }
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& r : st.tracked) {
        if (r.pid == pid) {
            diag::log_tagged_fmt("browser", "register_browser_pid already_tracked pid=%u", pid);
            return;
        }
    }
    tracked_pid_t rec;
    rec.pid = pid;
    rec.browser_path = "Camoufox";
    rec.profile_path = compute_profile_path("BurpBrowser");
    rec.launched_ms = bridge_status.launched_ms != 0 ? bridge_status.launched_ms : now_ms();
    st.tracked.push_back(rec);
    diag::log_tagged_fmt("browser", "register_browser_pid registered_camoufox pid=%u total=%zu", pid, st.tracked.size());
}

std::vector<browser_status_t> list_running()
{
    diag::log_tagged_fmt("browser", "list_running entry policy=camoufox_only");
    auto& st = s();
    std::vector<tracked_pid_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        snapshot = st.tracked;
    }

    camoufox::bridge_status_t bridge_status = camoufox::get_status();
    diag::log_tagged_fmt("browser", "list_running camoufox_snapshot state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d tracked=%zu err=%s",
        bridge_state_name(bridge_status.state), static_cast<unsigned long>(bridge_status.child_pid),
        static_cast<int>(bridge_status.child_alive), static_cast<int>(bridge_status.browser_open),
        static_cast<int>(bridge_status.page_verified), static_cast<int>(bridge_status.cleanup_pending),
        snapshot.size(), bridge_status.last_error.empty() ? "<empty>" : bridge_status.last_error.c_str());

    std::vector<browser_status_t> out;
    if (bridge_status.child_pid == 0 || !bridge_status.child_alive || bridge_status.cleanup_pending) {
        size_t removed = 0;
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            removed = st.tracked.size();
            st.tracked.clear();
        }
        diag::log_tagged_fmt("browser", "list_running no_live_camoufox removed_tracked=%zu result_count=0", removed);
        return out;
    }

    tracked_pid_t tracked;
    bool have_tracked = false;
    for (const auto& r : snapshot) {
        if (r.pid == bridge_status.child_pid) {
            tracked = r;
            have_tracked = true;
            break;
        }
    }

    browser_status_t item;
    item.running = true;
    item.pid = bridge_status.child_pid;
    item.browser_path = have_tracked && !tracked.browser_path.empty() ? tracked.browser_path : std::string("Camoufox");
    item.profile_path = have_tracked && !tracked.profile_path.empty() ? tracked.profile_path : compute_profile_path("BurpBrowser");
    item.proxy_port = have_tracked ? tracked.proxy_port : 0;
    item.launched_ms = bridge_status.launched_ms != 0 ? bridge_status.launched_ms : tracked.launched_ms;
    item.certificate_strategy = have_tracked ? tracked.certificate_strategy : certificate_strategy_t::camoufox_spki_allowlist;
    item.spki_hash_prefix = have_tracked ? tracked.spki_hash_prefix : std::string();
    out.push_back(item);

    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                        [&bridge_status](const tracked_pid_t& r) { return r.pid != bridge_status.child_pid; }),
                         st.tracked.end());
        if (!have_tracked) {
            tracked_pid_t rec;
            rec.pid = item.pid;
            rec.browser_path = item.browser_path;
            rec.profile_path = item.profile_path;
            rec.proxy_port = item.proxy_port;
            rec.launched_ms = item.launched_ms;
            rec.certificate_strategy = item.certificate_strategy;
            rec.spki_hash_prefix = item.spki_hash_prefix;
            st.tracked.push_back(rec);
        }
    }

    diag::log_tagged_fmt("browser", "list_running result count=%zu bridge_pid=%u profile=%s proxy_port=%u",
        out.size(), static_cast<unsigned>(item.pid), item.profile_path.c_str(), static_cast<unsigned>(item.proxy_port));
    return out;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("browser", "last_error queried val=%s", st.last_err.c_str());
    return st.last_err;
}

}
}
}
