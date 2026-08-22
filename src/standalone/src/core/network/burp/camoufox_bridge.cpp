#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"

#include "../../infra/event_bus.hpp"
#include "../../infra/executor.hpp"
#include "../../mcp/mcp_client.hpp"
#include "../../mcp/mcp_standalone.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../../helpers/diag_log.hpp"
#include "../../diagnostics/metadata_ring.hpp"
#include "../executor_status.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <array>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <cstring>
#include <exception>
#include <functional>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <set>

namespace aida {
namespace burp {
namespace camoufox {

namespace {

constexpr uint32_t kMinReadyBrowserProcessCount = 2;
constexpr uint64_t kPostNavigationStabilityMsLocalFixture = 1500;
constexpr uint64_t kPostNavigationStabilityMs = 3000;
constexpr uint64_t kPostNavigationStabilityPollMs = 250;
constexpr uint64_t kCleanupDrainWaitMs = 15000;
constexpr uint64_t kCleanupDrainPollMs = 50;
constexpr uint64_t kLifecycleLockWaitMs = 750;

std::string ascii_lower_copy(std::string text);

struct singleton_t
{
    std::string                             session_id          = "default";
    std::recursive_mutex                    mtx;
    std::recursive_mutex                    operation_mtx;
    std::shared_ptr<mcp_client::client_t>   client;
    bridge_state_t                          state              = bridge_state_t::stopped;
    std::string                             last_error;
    std::string                             server_command;
    uint32_t                                child_pid          = 0;
    uint64_t                                launched_ms        = 0;
    uint64_t                                attempt_started_ms = 0;
    uint64_t                                attempt_elapsed_ms = 0;
    uint64_t                                last_attempt_elapsed_ms = 0;
    uint64_t                                last_call_ms       = 0;
    std::atomic<uint64_t>                   total_calls{0};
    std::atomic<uint64_t>                   total_errors{0};
    std::atomic<uint64_t>                   next_request_id{1};
    std::atomic<uint64_t>                   next_activity_token{1};
    std::atomic<uint32_t>                   active_activities{0};
    bool                                    browser_open       = false;
    std::string                             active_page_id;
    std::string                             active_page_url;
    std::string                             active_page_title;
    std::vector<page_status_t>              pages;
    std::string                             active_profile_dir;
    std::string                             effective_ua_policy = "camoufox_native";
    std::string                             ua_override_string;
    bool                                    ua_override         = false;
    bool                                    webrtc_blocked      = false;
    bool                                    privacy_verified    = false;
    nlohmann::json                          privacy_diagnostics = nlohmann::json::object();
    nlohmann::json                          last_launch_diagnostics = nlohmann::json::object();
    bool                                    page_verified      = false;
    bool                                    cleanup_pending    = false;
    bool                                    active_profile_generated = false;
    bool                                    cleanup_profile_generated = false;
    uint64_t                                generation         = 0;
    uint64_t                                launch_admission_token = 0;
    uint64_t                                cleanup_generation = 0;
    uint64_t                                cleanup_started_ms = 0;
    uint32_t                                cleanup_child_pid  = 0;
    std::string                             cleanup_profile_dir;
    std::string                             cleanup_reason;
    nlohmann::json                          cleanup_diagnostics = nlohmann::json::object();
    uint64_t                                last_launch_ms     = 0;
    uint64_t                                last_nav_ms        = 0;
    uint64_t                                last_cleanup_ms    = 0;
    uint64_t                                last_verified_ms   = 0;
    uint64_t                                auto_restart_block_until_ms = 0;
    uint64_t                                auto_restart_block_generation = 0;
    std::string                             auto_restart_block_reason;
    uint64_t                                launch_init_failure_block_until_ms = 0;
    uint64_t                                launch_init_failure_block_generation = 0;
    uint32_t                                launch_init_failure_block_count = 0;
    DWORD                                   launch_init_failure_exit_code = 0;
    std::string                             launch_init_failure_block_command;
    std::string                             launch_init_failure_block_reason;
    std::atomic<bool>                       stop_requested{false};
    std::atomic<uint64_t>                   stop_epoch{0};
    std::atomic<uint32_t>                   tracked_child_pid{0};
    std::string                             cached_python_path;
    launch_config_t                         active_cfg;
    std::vector<std::shared_ptr<mcp_client::client_t>> poisoned_clients;
    std::map<std::string, std::string>             page_url_registry;
};

inline singleton_t& sg()
{
    static singleton_t s;
    return s;
}

std::recursive_timed_mutex& lifecycle_mtx()
{
    static std::recursive_timed_mutex m;
    return m;
}

struct lifecycle_guard_t
{
    std::unique_lock<std::recursive_timed_mutex> lock;
    bool acquired = false;

    lifecycle_guard_t()
        : lock(lifecycle_mtx(), std::defer_lock)
    {
        acquired = lock.try_lock_for(std::chrono::milliseconds(kLifecycleLockWaitMs));
    }
};

struct managed_session_t
{
    std::recursive_mutex                  mtx;
    std::recursive_mutex                  operation_mtx;
    std::shared_ptr<mcp_client::client_t> client;
    std::string                           session_id;
    bridge_state_t                        state = bridge_state_t::stopped;
    std::string                           last_error;
    std::string                           server_command;
    uint32_t                              child_pid = 0;
    uint64_t                              launched_ms = 0;
    uint64_t                              attempt_started_ms = 0;
    uint64_t                              attempt_elapsed_ms = 0;
    uint64_t                              last_attempt_elapsed_ms = 0;
    uint64_t                              last_call_ms = 0;
    std::atomic<uint64_t>                 total_calls{0};
    std::atomic<uint64_t>                 total_errors{0};
    std::atomic<uint64_t>                 next_request_id{1};
    bool                                  browser_open = false;
    bool                                  page_verified = false;
    bool                                  cleanup_pending = false;
    std::string                           active_page_id;
    std::string                           active_page_url;
    std::string                           active_page_title;
    std::string                           active_profile_dir;
    std::string                           effective_ua_policy = "camoufox_native";
    std::string                           ua_override_string;
    bool                                  ua_override = false;
    bool                                  webrtc_blocked = false;
    bool                                  privacy_verified = false;
    nlohmann::json                        privacy_diagnostics = nlohmann::json::object();
    nlohmann::json                        last_launch_diagnostics = nlohmann::json::object();
    bool                                  active_profile_generated = false;
    std::vector<page_status_t>            pages;
    uint64_t                              generation = 0;
    uint64_t                              launch_admission_token = 0;
    uint64_t                              cleanup_generation = 0;
    uint64_t                              cleanup_started_ms = 0;
    uint32_t                              cleanup_child_pid = 0;
    std::string                           cleanup_profile_dir;
    bool                                  cleanup_profile_generated = false;
    std::string                           cleanup_reason;
    nlohmann::json                        cleanup_diagnostics = nlohmann::json::object();
    uint64_t                              last_launch_ms = 0;
    uint64_t                              last_nav_ms = 0;
    uint64_t                              last_cleanup_ms = 0;
    uint64_t                              last_verified_ms = 0;
    std::atomic<bool>                     stop_requested{false};
    launch_config_t                       active_cfg;
};

void clear_privacy_locked();
void clear_privacy_locked(managed_session_t& session);
int json_int_or(const nlohmann::json& j, const char* key, int fallback);
std::string json_string_or(const nlohmann::json& j, const char* key, const std::string& fallback);
bool json_bool_or(const nlohmann::json& j, const char* key, bool fallback);

std::recursive_mutex& sessions_mtx()
{
    static std::recursive_mutex m;
    return m;
}

std::map<std::string, std::shared_ptr<managed_session_t>>& managed_sessions()
{
    static std::map<std::string, std::shared_ptr<managed_session_t>> sessions;
    return sessions;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

bool post_bridge_task(const char* name, std::function<void()> task)
{
    const uint64_t t0 = now_ms();
    bool posted = false;
    std::string reject_reason;
    try
    {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.camoufox";
        sub.label = name ? name : "camoufox.task";
        sub.thread_class = "external_tool";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = std::move(task);
        auto submit_result = aida::infra::executor::submit(std::move(sub));
        posted = submit_result.submitted;
        reject_reason = submit_result.reject_reason;
    }
    catch (...)
    {
        posted = false;
    }
    const auto st = aida::network::executor_status::work_stats();
    diag::log_tagged_fmt("camoufox", "external_tool_executor_post name=%s posted=%d alive=%d shutting_down=%d workers=%zu pending=%llu active=%lu elapsed_ms=%llu reject=%s",
        name ? name : "<null>",
        posted ? 1 : 0,
        st.alive ? 1 : 0,
        st.shutting_down ? 1 : 0,
        st.workers,
        static_cast<unsigned long long>(st.pending),
        static_cast<unsigned long>(st.active),
        static_cast<unsigned long long>(now_ms() - t0),
        reject_reason.empty() ? "<none>" : reject_reason.c_str());
    return posted;
}

uint64_t next_request_id()
{
    return sg().next_request_id.fetch_add(1, std::memory_order_relaxed);
}

constexpr int kToolListWaitMaxMs = 5000;
constexpr int kLaunchWaitMinMs = 5000;
constexpr int kLaunchWaitMaxMs = 120000;
constexpr int kBundledVisibleReadinessMaxMs = 40000;
constexpr int kBundledVisibleLaunchWaitMinMs = 5000;
constexpr int kBundledVisibleLaunchWaitMaxMs = kBundledVisibleReadinessMaxMs;
constexpr int kTestLabLaunchWaitDefaultMs = 40000;
constexpr int kTestLabLaunchWaitMaxMs = 40000;
constexpr int kStrictLaunchBudgetMs = 135000;
constexpr uint64_t kLaunchWaitLogIntervalMs = 5000;
constexpr uint64_t kLaunchWaitTreeLogIntervalMs = 10000;
constexpr DWORD kDependencyProbeTimeoutMs = 9000;
constexpr int kReadinessProbeTimeoutMs = 10000;
constexpr int kNavigationWaitMaxMs = 50000;
constexpr uint64_t kPythonDiscoveryBudgetMs = 15000;
constexpr uint64_t kActivityDrainWaitMs = 45000;
constexpr uint64_t kAutoRestartBlockMs = 120000;
constexpr DWORD kBridgeChildErrorMode = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
thread_local uint32_t g_bridge_activity_depth = 0;
thread_local uint32_t g_camoufox_op_admission_depth = 0;

using get_thread_error_mode_fn = DWORD(WINAPI*)();
using set_thread_error_mode_fn = BOOL(WINAPI*)(DWORD, LPDWORD);

struct thread_error_mode_api_t
{
    get_thread_error_mode_fn get = nullptr;
    set_thread_error_mode_fn set = nullptr;
};

const thread_error_mode_api_t& thread_error_mode_api()
{
    static const thread_error_mode_api_t api = [] {
        thread_error_mode_api_t result;
        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) return result;
        result.get = reinterpret_cast<get_thread_error_mode_fn>(GetProcAddress(kernel32, "GetThreadErrorMode"));
        result.set = reinterpret_cast<set_thread_error_mode_fn>(GetProcAddress(kernel32, "SetThreadErrorMode"));
        if (!result.get || !result.set)
        {
            result.get = nullptr;
            result.set = nullptr;
        }
        return result;
    }();
    return api;
}

DWORD current_error_mode()
{
    const auto& api = thread_error_mode_api();
    return api.get ? api.get() : GetErrorMode();
}

const char* safe_reason(const char* reason)
{
    return (reason && reason[0]) ? reason : "unspecified";
}

mcp_standalone::downstream::producer_identity_t build_camoufox_op_identity(
    const char* tool_name,
    const std::string& session_id,
    uint64_t generation,
    uint32_t child_pid)
{
    mcp_standalone::downstream::producer_identity_t id;
    id.kind = mcp_standalone::downstream::producer_kind_t::camoufox_longop;
    id.principal_id = "camoufox";
    id.session_id = session_id.empty() ? std::string("default") : session_id;
    id.generation = generation;
    id.child_pid = child_pid;
    id.tool_name = tool_name ? std::string(tool_name) : std::string();
    id.command_label = tool_name ? std::string(tool_name) : std::string();
    const char* diag_id = mcp_standalone::current_call_diag_id();
    const char* req_id = mcp_standalone::current_call_request_id();
    if (diag_id && diag_id[0]) id.diagnostic_id = diag_id;
    if (req_id && req_id[0]) id.request_id = req_id;
    id.deadline_ms = mcp_standalone::current_call_deadline_ms();
    return id;
}

struct camoufox_op_admission_t
{
    mcp_standalone::downstream::admission_result_t result;
    mcp_standalone::downstream::producer_identity_t identity;
    bool held = false;
    bool depth_incremented = false;
    bool skipped = false;
    uint64_t generation_at_admit = 0;

    explicit camoufox_op_admission_t(const mcp_standalone::downstream::producer_identity_t& id)
        : identity(id), generation_at_admit(id.generation)
    {
        if (g_camoufox_op_admission_depth > 0)
        {
            skipped = true;
            return;
        }
        result = mcp_standalone::downstream::governor_t::instance().try_admit(id);
        held = result.admitted;
        if (held)
        {
            ++g_camoufox_op_admission_depth;
            depth_incremented = true;
            diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-ADMIT tool=%s session=%s generation=%llu child_pid=%lu token=%llu depth=%u",
                identity.tool_name.c_str(), identity.session_id.c_str(),
                static_cast<unsigned long long>(identity.generation),
                static_cast<unsigned long>(identity.child_pid),
                static_cast<unsigned long long>(result.admission_token),
                static_cast<unsigned>(g_camoufox_op_admission_depth));
            aida::diagnostics::breadcrumb_options_t cf_opts{};
            cf_opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
            cf_opts.label = "camoufox_longop_admit";
            cf_opts.reason = "tool_call_start";
            cf_opts.owner_subsystem = "camoufox_bridge";
            cf_opts.tool_or_request_id = identity.tool_name.c_str();
            cf_opts.session_or_target = identity.session_id.c_str();
            cf_opts.lease_token = result.admission_token;
            cf_opts.generation = identity.generation;
            cf_opts.status_code = 0;
            aida::diagnostics::emit(std::move(cf_opts));
        }
        else
        {
            diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-REJECT tool=%s session=%s generation=%llu child_pid=%lu reason=%s quota=%s scope=%s observed=%zu limit=%zu",
                identity.tool_name.c_str(), identity.session_id.c_str(),
                static_cast<unsigned long long>(identity.generation),
                static_cast<unsigned long>(identity.child_pid),
                result.reason.c_str(), result.quota_name.c_str(), result.quota_scope.c_str(),
                result.observed, result.limit);
            aida::diagnostics::breadcrumb_options_t cf_opts{};
            cf_opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
            cf_opts.label = "camoufox_longop_reject";
            cf_opts.reason = "capacity_rejected";
            cf_opts.owner_subsystem = "camoufox_bridge";
            cf_opts.tool_or_request_id = identity.tool_name.c_str();
            cf_opts.session_or_target = identity.session_id.c_str();
            cf_opts.generation = identity.generation;
            cf_opts.status_code = 1;
            aida::diagnostics::emit(std::move(cf_opts));
        }
    }

    ~camoufox_op_admission_t()
    {
        release("scope_exit");
    }

    camoufox_op_admission_t(const camoufox_op_admission_t&) = delete;
    camoufox_op_admission_t& operator=(const camoufox_op_admission_t&) = delete;

    void release(const char* reason)
    {
        if (!held) return;
        diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-RELEASE reason=%s tool=%s session=%s token=%llu",
            reason ? reason : "completed",
            identity.tool_name.c_str(), identity.session_id.c_str(),
            static_cast<unsigned long long>(result.admission_token));
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
        opts.label = "camoufox_longop_release";
        opts.reason = reason ? reason : "completed";
        opts.owner_subsystem = "camoufox_bridge";
        opts.tool_or_request_id = identity.tool_name.c_str();
        opts.session_or_target = identity.session_id.c_str();
        opts.lease_token = result.admission_token;
        opts.generation = identity.generation;
        opts.status_code = 0;
        aida::diagnostics::emit(std::move(opts));
        mcp_standalone::downstream::governor_t::instance().release(result.admission_token, reason ? reason : "completed");
        held = false;
        if (depth_incremented)
        {
            if (g_camoufox_op_admission_depth > 0)
                --g_camoufox_op_admission_depth;
            depth_incremented = false;
        }
    }

    bool admitted() const noexcept
    {
        return held || (skipped && g_camoufox_op_admission_depth > 0);
    }

    bool is_stale(uint64_t current_generation) const noexcept
    {
        return held && generation_at_admit != 0 && current_generation != 0 && current_generation != generation_at_admit;
    }

    const mcp_standalone::downstream::admission_result_t& rejection() const noexcept { return result; }
    const mcp_standalone::downstream::producer_identity_t& id() const noexcept { return identity; }
};

bool acquire_launch_admission(const char* phase, const std::string& session_id, uint64_t generation, uint32_t child_pid, uint64_t& out_token)
{
    out_token = 0;
    mcp_standalone::downstream::producer_identity_t id;
    id.kind = mcp_standalone::downstream::producer_kind_t::camoufox_longop;
    id.principal_id = "camoufox_launch";
    id.session_id = session_id.empty() ? std::string("default") : session_id;
    id.generation = generation;
    id.child_pid = child_pid;
    id.tool_name = phase ? std::string(phase) : std::string("start_bridge");
    id.command_label = phase ? std::string(phase) : std::string("start_bridge");
    const char* diag_id = mcp_standalone::current_call_diag_id();
    const char* req_id = mcp_standalone::current_call_request_id();
    if (diag_id && diag_id[0]) id.diagnostic_id = diag_id;
    if (req_id && req_id[0]) id.request_id = req_id;

    auto r = mcp_standalone::downstream::governor_t::instance().try_admit(id);
    if (r.admitted)
    {
        out_token = r.admission_token;
        diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-ADMIT phase=%s session=%s generation=%llu child_pid=%lu token=%llu kind=launch",
            phase ? phase : "start_bridge", id.session_id.c_str(),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(child_pid),
            static_cast<unsigned long long>(out_token));
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
        opts.label = "camoufox_launch_admit";
        opts.reason = "launch_start";
        opts.owner_subsystem = "camoufox_bridge";
        opts.tool_or_request_id = phase ? phase : "start_bridge";
        opts.session_or_target = id.session_id.c_str();
        opts.lease_token = out_token;
        opts.generation = generation;
        opts.status_code = 0;
        aida::diagnostics::emit(std::move(opts));
        return true;
    }
    diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-REJECT phase=%s session=%s generation=%llu child_pid=%lu reason=%s quota=%s scope=%s observed=%zu limit=%zu kind=launch",
        phase ? phase : "start_bridge", id.session_id.c_str(),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(child_pid),
        r.reason.c_str(), r.quota_name.c_str(), r.quota_scope.c_str(),
        r.observed, r.limit);
    aida::diagnostics::breadcrumb_options_t opts{};
    opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
    opts.label = "camoufox_launch_reject";
    opts.reason = "launch_capacity_rejected";
    opts.owner_subsystem = "camoufox_bridge";
    opts.tool_or_request_id = phase ? phase : "start_bridge";
    opts.session_or_target = id.session_id.c_str();
    opts.generation = generation;
    opts.status_code = 1;
    aida::diagnostics::emit(std::move(opts));
    return false;
}

void release_launch_admission(uint64_t token, const char* reason, const std::string& session_id)
{
    if (token == 0) return;
    diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-RELEASE reason=%s session=%s token=%llu kind=launch",
        reason ? reason : "completed",
        session_id.empty() ? "default" : session_id.c_str(),
        static_cast<unsigned long long>(token));
    aida::diagnostics::breadcrumb_options_t opts{};
    opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
    opts.label = "camoufox_launch_release";
    opts.reason = reason ? reason : "completed";
    opts.owner_subsystem = "camoufox_bridge";
    opts.session_or_target = session_id.empty() ? "default" : session_id.c_str();
    opts.lease_token = token;
    opts.status_code = 0;
    aida::diagnostics::emit(std::move(opts));
    mcp_standalone::downstream::governor_t::instance().release(token, reason ? reason : "completed");
}

struct launch_admission_guard_t
{
    uint64_t* token_ptr;
    std::string session_id;
    bool committed = false;

    launch_admission_guard_t(uint64_t* ptr, std::string sid)
        : token_ptr(ptr), session_id(std::move(sid)) {}

    ~launch_admission_guard_t()
    {
        if (!committed && token_ptr && *token_ptr != 0)
        {
            const uint64_t t = *token_ptr;
            *token_ptr = 0;
            release_launch_admission(t, "start_bridge_failed", session_id);
        }
    }

    launch_admission_guard_t(const launch_admission_guard_t&) = delete;
    launch_admission_guard_t& operator=(const launch_admission_guard_t&) = delete;
};

class scoped_child_error_mode_t
{
public:
    scoped_child_error_mode_t(const char* phase, DWORD create_flags, const char* command)
        : phase_(safe_reason(phase)),
          command_(command ? command : "<null>"),
          previous_(current_error_mode()),
          desired_(previous_ | kBridgeChildErrorMode)
    {
        const auto& api = thread_error_mode_api();
        DWORD returned_previous = previous_;
        if (api.set)
        {
            api.set(desired_, &returned_previous);
        }
        else
        {
            returned_previous = SetErrorMode(desired_);
        }
        applied_ = current_error_mode();
        diag::log_tagged_fmt("camoufox", "child_error_mode_set phase=%s create_flags=0x%08lX inherited_error_mode=%d default_error_mode_flag=%d previous=0x%08lX returned_previous=0x%08lX desired=0x%08lX applied=0x%08lX command=%s",
            phase_.c_str(),
            static_cast<unsigned long>(create_flags),
            (create_flags & CREATE_DEFAULT_ERROR_MODE) == 0 ? 1 : 0,
            (create_flags & CREATE_DEFAULT_ERROR_MODE) != 0 ? 1 : 0,
            static_cast<unsigned long>(previous_),
            static_cast<unsigned long>(returned_previous),
            static_cast<unsigned long>(desired_),
            static_cast<unsigned long>(applied_),
            command_.c_str());
    }

    scoped_child_error_mode_t(const scoped_child_error_mode_t&) = delete;
    scoped_child_error_mode_t& operator=(const scoped_child_error_mode_t&) = delete;

    ~scoped_child_error_mode_t()
    {
        const DWORD before_restore = current_error_mode();
        const auto& api = thread_error_mode_api();
        DWORD returned_previous = before_restore;
        if (api.set)
        {
            api.set(previous_, &returned_previous);
        }
        else
        {
            returned_previous = SetErrorMode(previous_);
        }
        const DWORD after_restore = current_error_mode();
        diag::log_tagged_fmt("camoufox", "child_error_mode_restore phase=%s previous=0x%08lX applied=0x%08lX before_restore=0x%08lX returned_previous=0x%08lX after_restore=0x%08lX command=%s",
            phase_.c_str(),
            static_cast<unsigned long>(previous_),
            static_cast<unsigned long>(applied_),
            static_cast<unsigned long>(before_restore),
            static_cast<unsigned long>(returned_previous),
            static_cast<unsigned long>(after_restore),
            command_.c_str());
    }

private:
    std::string phase_;
    std::string command_;
    DWORD previous_ = 0;
    DWORD desired_ = 0;
    DWORD applied_ = 0;
};

std::atomic<bool>& prewarm_default_requested()
{
    static std::atomic<bool> requested{false};
    return requested;
}

thread_local bool g_prewarm_default_worker_active = false;

bool prewarm_default_disabled()
{
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_CAMOUFOX_PREWARM", value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= static_cast<DWORD>(sizeof(value))) return false;
    value[sizeof(value) - 1] = '\0';
    if (_stricmp(value, "0") == 0 ||
        _stricmp(value, "false") == 0 ||
        _stricmp(value, "no") == 0 ||
        _stricmp(value, "off") == 0 ||
        _stricmp(value, "disabled") == 0)
        return true;
    return false;
}

void log_prewarm_policy_resolved(const char* reason)
{
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_CAMOUFOX_PREWARM", value, static_cast<DWORD>(sizeof(value)));
    const bool env_unset = (n == 0 || n >= static_cast<DWORD>(sizeof(value)));
    if (!env_unset)
        value[sizeof(value) - 1] = '\0';
    const bool disabled = prewarm_default_disabled();
    diag::log_tagged_fmt("camoufox", "prewarm_policy default=enabled env=%s resolved=%s reason=%s",
        env_unset ? "<unset>" : value,
        disabled ? "disabled" : "enabled",
        reason && reason[0] ? reason : "unspecified");
}

bool env_flag_enabled_a(const char* name);

bool full_test_running_env()
{
    return env_flag_enabled_a("AIDA_FULL_TEST_RUNNING");
}

bool env_flag_enabled_a(const char* name)
{
    if (!name || !name[0]) return false;
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= static_cast<DWORD>(sizeof(value))) return false;
    value[sizeof(value) - 1] = '\0';
    return _stricmp(value, "1") == 0 ||
           _stricmp(value, "true") == 0 ||
           _stricmp(value, "yes") == 0 ||
           _stricmp(value, "on") == 0;
}

int env_int_a(const char* name, int fallback)
{
    if (!name || !name[0]) return fallback;
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= static_cast<DWORD>(sizeof(value))) return fallback;
    value[sizeof(value) - 1] = '\0';
    char* end = nullptr;
    long parsed = std::strtol(value, &end, 10);
    if (end == value) return fallback;
    while (end && *end)
    {
        if (*end != ' ' && *end != '\t') return fallback;
        ++end;
    }
    if (parsed < 0 || parsed > 1000000) return fallback;
    return static_cast<int>(parsed);
}

bool read_env_path_a(const char* name, std::string& out)
{
    out.clear();
    if (!name || !name[0]) return false;
    DWORD need = GetEnvironmentVariableA(name, nullptr, 0);
    if (need == 0 || need > 32768) return false;
    std::string value;
    value.resize(need);
    DWORD got = GetEnvironmentVariableA(name, value.data(), need);
    if (got == 0 || got >= need) return false;
    value.resize(got);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '"'))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '"'))
        value.pop_back();
    if (value.empty()) return false;
    out = value;
    return true;
}

bool env_path_configured_a(const char* name)
{
    std::string value;
    return read_env_path_a(name, value);
}

bool read_env_path_w(const wchar_t* name, std::wstring& out)
{
    out.clear();
    if (!name || !name[0]) return false;
    DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0 || need > 32768) return false;
    std::wstring value;
    value.resize(need);
    DWORD got = GetEnvironmentVariableW(name, value.data(), need);
    if (got == 0 || got >= need) return false;
    value.resize(got);
    while (!value.empty() && (value.front() == L' ' || value.front() == L'\t' || value.front() == L'"'))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == L' ' || value.back() == L'\t' || value.back() == L'"'))
        value.pop_back();
    if (value.empty()) return false;
    out = value;
    return true;
}

bool system_python_discovery_allowed()
{
    return env_flag_enabled_a("AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON");
}

void enforce_private_launch_config(launch_config_t& cfg)
{
    cfg.os = "windows";
    cfg.block_webrtc = true;
}

std::string trim_launch_token(std::string value)
{
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n' || value[begin] == '"'))
        ++begin;
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' || value[end - 1] == '\r' || value[end - 1] == '\n' || value[end - 1] == '"'))
        --end;
    return value.substr(begin, end - begin);
}

bool explicit_persistent_context_requested(const launch_config_t& cfg)
{
    return cfg.persistent_context ||
        !trim_launch_token(cfg.profile_dir).empty() ||
        !trim_launch_token(cfg.user_data_dir).empty();
}

std::string lower_launch_token(std::string value)
{
    value = trim_launch_token(std::move(value));
    for (char& c : value)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return value;
}

std::string normalize_default_launch_token(std::string value, const char* fallback)
{
    value = lower_launch_token(std::move(value));
    if (value.empty() || value == "auto")
        value = fallback && fallback[0] ? std::string(fallback) : std::string("auto");
    return value;
}

std::string normalize_camoufox_ua_policy_for_sidecar(std::string value, bool custom_user_agent)
{
    value = lower_launch_token(std::move(value));
    for (char& c : value)
    {
        if (c == '-') c = '_';
    }
    if (custom_user_agent || value.empty() ||
        value == "auto" ||
        value == "native" ||
        value == "camoufox" ||
        value == "camoufox_native")
        return "camoufox_native";
    if (value == "camoufox_auto" || value == "camoufox_desktop")
        return "camoufox_auto";
    if (value == "camoufox_windows" || value == "windows_camoufox" || value == "windows" || value == "win")
        return "camoufox_windows";
    if (value == "camoufox_macos" || value == "macos_camoufox" || value == "macos" || value == "mac")
        return "camoufox_macos";
    if (value == "camoufox_linux" || value == "linux_camoufox" || value == "linux")
        return "camoufox_linux";
    if (value == "random" || value == "random_camoufox" || value == "random_camoufox_desktop" || value == "rotate" || value == "rotating")
        return "random_camoufox_desktop";
    return value;
}

std::string normalize_launch_path(std::string value)
{
    value = lower_launch_token(std::move(value));
    for (char& c : value)
    {
        if (c == '/') c = '\\';
    }
    while (!value.empty() && (value.back() == '\\' || value.back() == '/'))
        value.pop_back();
    return value;
}

bool requested_launch_path_matches(const std::string& active, const std::string& requested)
{
    const std::string req = normalize_launch_path(requested);
    if (req.empty())
        return true;
    const std::string cur = normalize_launch_path(active);
    return !cur.empty() && cur == req;
}

void preserve_resolved_launch_paths(launch_config_t& target, const launch_config_t& active)
{
    if (target.python_executable.empty())
        target.python_executable = active.python_executable;
    if (target.browser_executable.empty())
        target.browser_executable = active.browser_executable;
}

void normalize_fast_visible_launch_policy(launch_config_t& cfg)
{
    cfg.ua_policy = normalize_camoufox_ua_policy_for_sidecar(
        cfg.ua_policy,
        !trim_launch_token(cfg.user_agent).empty());
}

std::string privacy_relevant_launch_config_mismatch_reason(const launch_config_t& active, const launch_config_t& requested)
{
    if (normalize_default_launch_token(active.session_id, "default") != normalize_default_launch_token(requested.session_id, "default"))
        return "session_id";
    if (active.headless != requested.headless)
        return "headless";
    if (trim_launch_token(active.proxy) != trim_launch_token(requested.proxy))
        return "proxy";
    const std::string requested_os = normalize_default_launch_token(requested.os, "windows");
    const std::string active_os = normalize_default_launch_token(active.os, "windows");
    if (requested_os != "auto" && active_os != "auto" && active_os != requested_os)
        return "os";
    const std::string requested_locale = normalize_default_launch_token(requested.locale, "auto");
    const std::string active_locale = normalize_default_launch_token(active.locale, "auto");
    if (requested_locale != "auto" && active_locale != "auto" && active_locale != requested_locale)
        return "locale";
    if (active.humanize != requested.humanize)
        return "humanize";
    if (active.geoip != requested.geoip)
        return "geoip";
    if (active.block_images != requested.block_images)
        return "block_images";
    if (active.block_webrtc != requested.block_webrtc)
        return "block_webrtc";
    if (trim_launch_token(active.user_agent) != trim_launch_token(requested.user_agent))
        return "user_agent";
    if (normalize_default_launch_token(active.ua_policy, "camoufox_native") != normalize_default_launch_token(requested.ua_policy, "camoufox_native"))
        return "ua_policy";
    const bool requested_profile_dir = !trim_launch_token(requested.profile_dir).empty();
    const bool requested_user_data_dir = !trim_launch_token(requested.user_data_dir).empty();
    const bool requested_persistent = explicit_persistent_context_requested(requested);
    if (requested_persistent && active.persistent_context != requested_persistent)
        return "persistent_context";
    if (requested_profile_dir && trim_launch_token(active.profile_dir) != trim_launch_token(requested.profile_dir))
        return "profile_dir";
    if (requested_user_data_dir && trim_launch_token(active.user_data_dir) != trim_launch_token(requested.user_data_dir))
        return "user_data_dir";
    if (active.enable_trace != requested.enable_trace)
        return "enable_trace";
    if (!requested_launch_path_matches(active.browser_executable, requested.browser_executable))
        return "browser_executable";
    return {};
}

bool privacy_relevant_launch_config_equal(const launch_config_t& a, const launch_config_t& b)
{
    return privacy_relevant_launch_config_mismatch_reason(a, b).empty();
}

std::string hex64(uint64_t v)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i)
    {
        out[static_cast<size_t>(i)] = kHex[v & 0xFu];
        v >>= 4;
    }
    return out;
}

std::string hex_bytes(const unsigned char* data, size_t size)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

std::string hex_status(NTSTATUS status)
{
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(status));
    return std::string(buf);
}

std::string init_script_name(const std::string& js)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : js)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return std::string("aida:inline:") + hex64(h) + ":" + std::to_string(js.size());
}

std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring out;
    out.resize(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), wlen);
    return out;
}

std::string wide_to_utf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out;
    out.resize(static_cast<size_t>(len));
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), len, nullptr, nullptr);
    return out;
}

bool path_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool directory_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

uint64_t filetime_to_u64(const FILETIME& ft)
{
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

bool sha256_file_hex_w(const std::wstring& path, std::string& out, std::string& status)
{
    out.clear();
    status.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        status = "open_gle=" + std::to_string(GetLastError());
        return false;
    }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st))
    {
        status = "open_alg_status=" + hex_status(st);
        CloseHandle(h);
        return false;
    }
    st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(st))
    {
        status = "create_hash_status=" + hex_status(st);
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(h);
        return false;
    }
    std::vector<unsigned char> buffer(65536);
    while (true)
    {
        DWORD got = 0;
        if (!ReadFile(h, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr))
        {
            status = "read_gle=" + std::to_string(GetLastError());
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            CloseHandle(h);
            return false;
        }
        if (got == 0)
            break;
        st = BCryptHashData(hash, buffer.data(), got, 0);
        if (!BCRYPT_SUCCESS(st))
        {
            status = "hash_status=" + hex_status(st);
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            CloseHandle(h);
            return false;
        }
    }
    std::array<unsigned char, 32> digest{};
    st = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    if (!BCRYPT_SUCCESS(st))
    {
        status = "finish_status=" + hex_status(st);
        return false;
    }
    out = hex_bytes(digest.data(), digest.size());
    status = "ok";
    return true;
}

struct local_helper_file_diag_t
{
    bool exists = false;
    DWORD attr = INVALID_FILE_ATTRIBUTES;
    DWORD gle = ERROR_SUCCESS;
    uint64_t size = 0;
    uint64_t mtime_100ns = 0;
    std::string sha256;
    std::string hash_status;
};

local_helper_file_diag_t collect_local_helper_file_diag(const std::string& path)
{
    local_helper_file_diag_t out;
    if (path.empty())
    {
        out.gle = ERROR_PATH_NOT_FOUND;
        out.hash_status = "empty_path";
        return out;
    }
    const std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty())
    {
        out.gle = ERROR_INVALID_PARAMETER;
        out.hash_status = "path_decode_failed";
        return out;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(wpath.c_str(), GetFileExInfoStandard, &fad))
    {
        out.gle = GetLastError();
        out.hash_status = "missing";
        return out;
    }
    out.attr = fad.dwFileAttributes;
    if ((fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        out.gle = ERROR_DIRECTORY;
        out.hash_status = "directory";
        return out;
    }
    out.exists = true;
    out.size = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | static_cast<uint64_t>(fad.nFileSizeLow);
    out.mtime_100ns = filetime_to_u64(fad.ftLastWriteTime);
    sha256_file_hex_w(wpath, out.sha256, out.hash_status);
    return out;
}

std::wstring parent_dir_w(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return {};
    return path.substr(0, pos);
}

std::wstring join_path_w(const std::wstring& a, const std::wstring& b)
{
    if (a.empty()) return b;
    if (b.empty()) return a;
    wchar_t last = a.back();
    if (last == L'\\' || last == L'/') return a + b;
    return a + L"\\" + b;
}

bool append_unique_path(std::vector<std::wstring>& paths, const std::wstring& path)
{
    if (path.empty()) return false;
    for (const auto& existing : paths)
    {
        if (_wcsicmp(existing.c_str(), path.c_str()) == 0) return false;
    }
    paths.push_back(path);
    return true;
}

void append_path_and_ancestors(std::vector<std::wstring>& paths, const std::wstring& path, size_t depth)
{
    std::wstring current = path;
    for (size_t i = 0; i < depth && !current.empty(); ++i)
    {
        append_unique_path(paths, current);
        current = parent_dir_w(current);
    }
}

void append_env_path_roots(std::vector<std::wstring>& paths, const wchar_t* name, size_t depth)
{
    std::wstring value;
    if (read_env_path_w(name, value))
        append_path_and_ancestors(paths, value, depth);
}

void append_camoufox_sidecar_roots(std::vector<std::wstring>& paths)
{
    append_env_path_roots(paths, L"AIDA_CAMOUFOX_EXECUTABLE", 6);
    append_env_path_roots(paths, L"AIDA_CAMOUFOX_PYTHON", 6);
    wchar_t local[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got != 0 && got < MAX_PATH)
    {
        std::wstring aida_root = join_path_w(local, L"AiDA");
        append_unique_path(paths, aida_root);
        append_unique_path(paths, join_path_w(join_path_w(aida_root, L"camoufox"), L"current"));
        append_unique_path(paths, join_path_w(join_path_w(join_path_w(aida_root, L"embedded"), L"camoufox"), L"current"));
        const std::wstring standalone_root = join_path_w(aida_root, L"Standalone");
        append_unique_path(paths, standalone_root);
        append_unique_path(paths, join_path_w(join_path_w(standalone_root, L"camoufox"), L"current"));
        append_unique_path(paths, join_path_w(join_path_w(join_path_w(standalone_root, L"embedded"), L"camoufox"), L"current"));
    }
    std::vector<wchar_t> temp(32768);
    DWORD temp_len = GetTempPathW(static_cast<DWORD>(temp.size()), temp.data());
    if (temp_len != 0 && temp_len < static_cast<DWORD>(temp.size()))
    {
        std::wstring temp_root(temp.data(), temp_len);
        append_unique_path(paths, join_path_w(temp_root, L"AiDA"));
        append_unique_path(paths, join_path_w(join_path_w(temp_root, L"AiDA"), L"camoufox"));
        append_unique_path(paths, join_path_w(join_path_w(join_path_w(temp_root, L"AiDA"), L"camoufox"), L"current"));
        append_unique_path(paths, join_path_w(temp_root, L"aida-camoufox"));
        append_unique_path(paths, join_path_w(join_path_w(temp_root, L"aida-camoufox"), L"current"));
    }
}

std::wstring executable_dir_w()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;)
    {
        DWORD got = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (got == 0) return {};
        if (got < buffer.size())
            return parent_dir_w(std::wstring(buffer.data(), got));
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) return {};
    }
}

std::wstring current_dir_w()
{
    DWORD need = GetCurrentDirectoryW(0, nullptr);
    if (need == 0) return {};
    std::wstring out;
    out.resize(need);
    DWORD got = GetCurrentDirectoryW(need, out.data());
    if (got == 0 || got >= need) return {};
    out.resize(got);
    return out;
}

std::wstring normalized_lower_path(std::wstring value);
bool path_under_root_w(const std::wstring& path, const std::wstring& root);

bool developer_repo_root_w(const std::wstring& dir)
{
    return path_exists_w(join_path_w(dir, L"CMakePresets.json")) &&
        directory_exists_w(join_path_w(join_path_w(dir, L"src"), L"standalone"));
}

void append_developer_repo_candidate(std::vector<std::wstring>& bases, const std::wstring& candidate)
{
    if (developer_repo_root_w(candidate))
        append_unique_path(bases, candidate);
}

void append_developer_repo_roots(std::vector<std::wstring>& bases, const std::wstring& exe_dir)
{
    const std::wstring cwd = current_dir_w();
    append_developer_repo_candidate(bases, cwd);
    const std::wstring parent = parent_dir_w(exe_dir);
    append_developer_repo_candidate(bases, parent);
    const std::wstring grandparent = parent_dir_w(parent);
    append_developer_repo_candidate(bases, grandparent);
    append_developer_repo_candidate(bases, exe_dir);
    append_env_path_roots(bases, L"AIDA_DEVELOPER_REPO_ROOT", 1);
    append_env_path_roots(bases, L"AIDA_REPO_ROOT", 1);
    std::wstring user_profile;
    if (read_env_path_w(L"USERPROFILE", user_profile))
    {
        append_developer_repo_candidate(bases, join_path_w(user_profile, L"AiDAPrivate"));
        append_developer_repo_candidate(bases, join_path_w(join_path_w(user_profile, L"source"), L"AiDAPrivate"));
        append_developer_repo_candidate(bases, join_path_w(join_path_w(join_path_w(user_profile, L"source"), L"repos"), L"AiDAPrivate"));
    }
    std::wstring home_drive;
    std::wstring home_path;
    if (read_env_path_w(L"HOMEDRIVE", home_drive) && read_env_path_w(L"HOMEPATH", home_path))
        append_developer_repo_candidate(bases, join_path_w(home_drive + home_path, L"AiDAPrivate"));
}

std::vector<std::wstring> runtime_base_dirs()
{
    std::vector<std::wstring> bases;
    std::wstring exe_dir = executable_dir_w();
    append_developer_repo_roots(bases, exe_dir);
    append_camoufox_sidecar_roots(bases);
    append_unique_path(bases, exe_dir);
    append_unique_path(bases, current_dir_w());
    append_unique_path(bases, parent_dir_w(exe_dir));
    append_unique_path(bases, parent_dir_w(parent_dir_w(exe_dir)));
    wchar_t local[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got != 0 && got < MAX_PATH)
    {
        append_unique_path(bases, join_path_w(join_path_w(join_path_w(local, L"AiDA"), L"camoufox"), L"current"));
        append_unique_path(bases, join_path_w(join_path_w(join_path_w(join_path_w(local, L"AiDA"), L"embedded"), L"camoufox"), L"current"));
    }
    return bases;
}

bool is_bundled_browser_dir(const std::wstring& dir)
{
    return path_exists_w(join_path_w(dir, L"camoufox.exe")) &&
        path_exists_w(join_path_w(dir, L"application.ini")) &&
        directory_exists_w(join_path_w(dir, L"browser"));
}

bool is_camoufox_browser_executable_path(const std::wstring& candidate)
{
    if (candidate.empty())
        return false;
    const size_t pos = candidate.find_last_of(L"\\/");
    const std::wstring file = pos == std::wstring::npos ? candidate : candidate.substr(pos + 1);
    if (_wcsicmp(file.c_str(), L"camoufox.exe") != 0)
        return false;
    return is_bundled_browser_dir(parent_dir_w(candidate));
}

bool find_bundled_camoufox_executable(std::string& out_path)
{
    const std::wstring name = L"camoufox-135.0.1-beta.24-win.x86_64";
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        std::wstring candidate_dir = base;
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
        candidate_dir = join_path_w(join_path_w(base, L"deps"), name);
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
        candidate_dir = join_path_w(base, name);
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_browser_executable missing base_count=%zu", bases.size());
    return false;
}

std::wstring local_appdata_aida_root()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(root, L"AiDA");
}

void append_bundled_python_candidates(std::vector<std::string>& candidates)
{
    std::vector<std::wstring> rels = {
        L"deps\\camoufox-runtime\\python.exe",
        L"deps\\camoufox-runtime\\Python312\\python.exe",
        L"deps\\camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"deps\\camoufox-python\\python.exe",
        L"deps\\python-3.12.10-x64\\python.exe",
        L"deps\\python\\python.exe",
        L"deps\\python-3.12\\python.exe",
        L"deps\\Python312\\python.exe",
        L"deps\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtime\\python\\python.exe",
        L"deps\\runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtimes\\python\\Python312-3.12.10-x64\\python.exe",
        L"camoufox-runtime\\python.exe",
        L"camoufox-runtime\\Python312\\python.exe",
        L"camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"camoufox-python\\python.exe",
        L"python-3.12.10-x64\\python.exe",
        L"python\\python.exe",
        L"python-3.12\\python.exe",
        L"Python312\\python.exe",
        L"Python312-3.12.10-x64\\python.exe",
        L"runtime\\python\\python.exe",
        L"runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"runtimes\\python\\Python312-3.12.10-x64\\python.exe"
    };
    const auto bases = runtime_base_dirs();
    size_t found_count = 0;
    for (const auto& base : bases)
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (path_exists_w(candidate))
            {
                candidates.push_back(wide_to_utf8(candidate));
                ++found_count;
                diag::log_tagged_fmt("camoufox", "bundled_python_candidate found path=%s base=%s rel=%s",
                    candidates.back().c_str(), wide_to_utf8(base).c_str(), wide_to_utf8(rel).c_str());
            }
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_python_candidate scan complete base_count=%zu rel_count=%zu found=%zu",
        bases.size(), rels.size(), found_count);
}

void append_app_local_python_candidates(std::vector<std::string>& candidates)
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) return;
    std::wstring exact = join_path_w(join_path_w(join_path_w(join_path_w(root, L"runtimes"), L"python"), L"Python312-3.12.10-x64"), L"python.exe");
    if (path_exists_w(exact)) candidates.push_back(wide_to_utf8(exact));
}

bool try_search_path(const wchar_t* exe_name, std::string& out_path)
{
    wchar_t buffer[MAX_PATH * 2] = {0};
    DWORD got = SearchPathW(nullptr, exe_name, nullptr, static_cast<DWORD>(sizeof(buffer) / sizeof(wchar_t)), buffer, nullptr);
    if (got == 0 || got >= sizeof(buffer) / sizeof(wchar_t)) return false;
    out_path = wide_to_utf8(buffer);
    return !out_path.empty();
}

bool try_python_directory(const std::wstring& base, std::string& out_path)
{
    DWORD attr = GetFileAttributesW(base.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return false;

    std::wstring pattern = base + L"\\Python*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::wstring best;
    int best_minor = -1;
    int best_major = -1;
    do
    {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        std::wstring name = fd.cFileName;
        if (name.size() < 8) continue;
        if (name.compare(0, 6, L"Python") != 0) continue;
        std::wstring digits = name.substr(6);
        int major = 0, minor = 0;
        if (digits.size() >= 2)
        {
            major = digits[0] - L'0';
            if (digits.size() >= 3) minor = (digits[1] - L'0') * 10 + (digits[2] - L'0');
            else minor = digits[1] - L'0';
        }
        if (major < 3) continue;
        if (major == 3 && (minor < 10 || minor > 13)) continue;
        if (major > 3) continue;
        if (major > best_major || (major == best_major && minor > best_minor))
        {
            std::wstring candidate = base + L"\\" + name + L"\\python.exe";
            if (path_exists_w(candidate))
            {
                best = candidate;
                best_major = major;
                best_minor = minor;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (best.empty()) return false;
    out_path = wide_to_utf8(best);
    return !out_path.empty();
}

bool try_env_python_root(const wchar_t* env_name, const wchar_t* suffix, std::string& out_path)
{
    wchar_t root[MAX_PATH] = {0};
    DWORD got = GetEnvironmentVariableW(env_name, root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return false;
    std::wstring base = std::wstring(root) + suffix;
    return try_python_directory(base, out_path);
}

bool try_known_python_roots(std::string& out_path)
{
    std::wstring aida_root = local_appdata_aida_root();
    if (!aida_root.empty() && try_python_directory(join_path_w(join_path_w(aida_root, L"runtimes"), L"python"), out_path)) return true;
    if (try_env_python_root(L"ProgramFiles", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"LOCALAPPDATA", L"\\Programs\\Python", out_path)) return true;
    return false;
}

bool is_windows_store_python_alias(const std::string& path)
{
    std::wstring w = utf8_to_wide(path);
    if (w.empty()) return false;
    for (wchar_t& c : w) if (c == L'/') c = L'\\';
    std::wstring lower = w;
    std::wstring needle = L"\\microsoft\\windowsapps\\";
    for (wchar_t& c : lower) c = static_cast<wchar_t>(std::towlower(c));
    return lower.find(needle) != std::wstring::npos;
}

std::wstring normalized_lower_path(std::wstring value)
{
    for (wchar_t& c : value)
    {
        if (c == L'/') c = L'\\';
        c = static_cast<wchar_t>(std::towlower(c));
    }
    while (!value.empty() && (value.back() == L'\\' || value.back() == L'/'))
        value.pop_back();
    return value;
}

bool path_under_root_w(const std::wstring& path, const std::wstring& root)
{
    std::wstring p = normalized_lower_path(path);
    std::wstring r = normalized_lower_path(root);
    if (p.empty() || r.empty() || p.size() <= r.size())
        return false;
    return p.compare(0, r.size(), r) == 0 && p[r.size()] == L'\\';
}

std::wstring camoufox_profile_root_w()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) root = executable_dir_w();
    if (root.empty()) root = current_dir_w();
    if (root.empty()) return {};
    return join_path_w(root, L"camoufox-profiles");
}

bool remove_directory_tree_w(const std::wstring& dir, uint32_t& files_removed, uint32_t& dirs_removed)
{
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return DeleteFileW(dir.c_str()) != FALSE;
    std::wstring pattern = join_path_w(dir, L"*");
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            const std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..")
                continue;
            const std::wstring child = join_path_w(dir, name);
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                if (!remove_directory_tree_w(child, files_removed, dirs_removed))
                {
                    FindClose(h);
                    return false;
                }
            }
            else
            {
                SetFileAttributesW(child.c_str(), fd.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);
                if (!DeleteFileW(child.c_str()))
                {
                    FindClose(h);
                    return false;
                }
                ++files_removed;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    SetFileAttributesW(dir.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
    if (!RemoveDirectoryW(dir.c_str()))
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    ++dirs_removed;
    return true;
}

void purge_generated_profile_dir(const std::string& profile_dir, const std::string& reason)
{
    std::unique_lock<std::recursive_timed_mutex> lifecycle(lifecycle_mtx());
    if (profile_dir.empty())
        return;
    const std::wstring profile_w = utf8_to_wide(profile_dir);
    const std::wstring root_w = camoufox_profile_root_w();
    if (profile_w.empty() || root_w.empty() || !path_under_root_w(profile_w, root_w))
    {
        diag::log_tagged_fmt("camoufox", "profile_cleanup refused reason=%s profile_dir=%s root=%s",
            reason.c_str(), profile_dir.c_str(), wide_to_utf8(root_w).c_str());
        return;
    }
    uint32_t files_removed = 0;
    uint32_t dirs_removed = 0;
    const uint64_t t0 = now_ms();
    const bool ok = remove_directory_tree_w(profile_w, files_removed, dirs_removed);
    const DWORD gle = ok ? 0 : GetLastError();
    diag::log_tagged_fmt("camoufox", "profile_cleanup result=%d gle=%lu reason=%s profile_dir=%s files=%lu dirs=%lu elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long>(gle),
        reason.c_str(),
        profile_dir.c_str(),
        static_cast<unsigned long>(files_removed),
        static_cast<unsigned long>(dirs_removed),
        static_cast<unsigned long long>(now_ms() - t0));
}

bool is_app_controlled_python_path(const std::string& path)
{
    std::wstring w = utf8_to_wide(path);
    if (w.empty()) return false;
    for (const auto& base : runtime_base_dirs())
    {
        if (path_under_root_w(w, base))
            return true;
    }
    std::wstring app_root = local_appdata_aida_root();
    if (!app_root.empty() && path_under_root_w(w, app_root))
        return true;
    return false;
}

std::wstring parent_directory_w(std::wstring path)
{
    for (wchar_t& c : path)
    {
        if (c == L'/') c = L'\\';
    }
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return {};
    return path.substr(0, slash);
}

std::wstring quote_arg_w(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size() + 2);
    out.push_back(L'"');
    for (wchar_t ch : value)
    {
        if (ch == L'"')
            out.push_back(L'\\');
        out.push_back(ch);
    }
    out.push_back(L'"');
    return out;
}

std::string compact_child_output_tail(std::string s, size_t limit);

bool spawn_capture_impl(const std::wstring& application_path, std::wstring cmdline, const std::wstring& working_directory, const char* label, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    out_exit_code = 0;
    out_stdout.clear();
    const char* spawn_label = (label && label[0]) ? label : "process";
    const std::string app_log = application_path.empty() ? std::string("<cmdline>") : wide_to_utf8(application_path);
    const std::string cwd_log = working_directory.empty() ? std::string("<inherit>") : wide_to_utf8(working_directory);
    const uint64_t t0 = now_ms();
    DWORD app_attr = INVALID_FILE_ATTRIBUTES;
    DWORD cwd_attr = INVALID_FILE_ATTRIBUTES;
    if (!application_path.empty())
        app_attr = GetFileAttributesW(application_path.c_str());
    if (!working_directory.empty())
        cwd_attr = GetFileAttributesW(working_directory.c_str());
    diag::log_tagged_fmt("camoufox", "spawn_capture entry label=%s app=%s cwd=%s app_exists=%d cwd_exists=%d cmd_len=%zu timeout_ms=%lu",
        spawn_label,
        app_log.c_str(),
        cwd_log.c_str(),
        static_cast<int>(application_path.empty() || (app_attr != INVALID_FILE_ATTRIBUTES && (app_attr & FILE_ATTRIBUTE_DIRECTORY) == 0)),
        static_cast<int>(working_directory.empty() || (cwd_attr != INVALID_FILE_ATTRIBUTES && (cwd_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)),
        cmdline.size(),
        static_cast<unsigned long>(timeout_ms));

    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
    {
        const DWORD gle = GetLastError();
        out_stdout = "spawn pipe create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture pipe_create_failed label=%s gle=%lu cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
            spawn_label, gle, cmdline.size(), static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    HANDLE child_stdin = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (child_stdin == INVALID_HANDLE_VALUE)
    {
        const DWORD gle = GetLastError();
        out_stdout = "spawn stdin create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture stdin_create_failed label=%s gle=%lu elapsed_ms=%llu",
            spawn_label, gle, static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(wr);
        CloseHandle(rd);
        return false;
    }

    STARTUPINFOEXW sx{};
    sx.StartupInfo.cb         = sizeof(sx);
    sx.StartupInfo.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sx.StartupInfo.hStdOutput = wr;
    sx.StartupInfo.hStdError  = wr;
    sx.StartupInfo.hStdInput  = child_stdin;
    sx.StartupInfo.wShowWindow = SW_HIDE;

    SIZE_T attr_bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_bytes);
    std::vector<uint8_t> attr_storage;
    bool attr_ready = false;
    if (attr_bytes != 0)
    {
        attr_storage.resize(attr_bytes);
        sx.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_storage.data());
        if (InitializeProcThreadAttributeList(sx.lpAttributeList, 1, 0, &attr_bytes))
        {
            HANDLE inherited_handles[] = { wr, child_stdin };
            if (UpdateProcThreadAttribute(
                    sx.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    inherited_handles,
                    sizeof(inherited_handles),
                    nullptr,
                    nullptr))
            {
                attr_ready = true;
            }
            else
            {
                const DWORD gle = GetLastError();
                diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_update_failed label=%s gle=%lu",
                    spawn_label, gle);
                DeleteProcThreadAttributeList(sx.lpAttributeList);
                sx.lpAttributeList = nullptr;
            }
        }
        else
        {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_init_failed label=%s gle=%lu",
                spawn_label, gle);
            sx.lpAttributeList = nullptr;
        }
    }
    if (!attr_ready)
    {
        out_stdout = "spawn handle inheritance isolation failed";
        diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_unavailable label=%s elapsed_ms=%llu",
            spawn_label, static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(wr);
        CloseHandle(child_stdin);
        CloseHandle(rd);
        return false;
    }

    PROCESS_INFORMATION pi{};
    DWORD create_flags = CREATE_NO_WINDOW;
    create_flags |= EXTENDED_STARTUPINFO_PRESENT;
    sx.StartupInfo.cb = sizeof(sx);
    const uint64_t create_t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "spawn_capture create_begin label=%s app=%s cwd=%s cmd_len=%zu timeout_ms=%lu handle_list=%d create_flags=0x%08lX inherited_error_mode=%d process_error_mode_before=0x%08lX desired_child_error_mode=0x%08lX elapsed_ms=%llu",
        spawn_label,
        app_log.c_str(),
        cwd_log.c_str(),
        cmdline.size(),
        static_cast<unsigned long>(timeout_ms),
        attr_ready ? 1 : 0,
        static_cast<unsigned long>(create_flags),
        (create_flags & CREATE_DEFAULT_ERROR_MODE) == 0 ? 1 : 0,
        static_cast<unsigned long>(current_error_mode()),
        static_cast<unsigned long>(current_error_mode() | kBridgeChildErrorMode),
        static_cast<unsigned long long>(create_t0 - t0));
    BOOL ok = FALSE;
    DWORD create_gle = ERROR_SUCCESS;
    {
        scoped_child_error_mode_t child_error_mode("spawn_capture", create_flags, app_log.c_str());
        std::wstring primary_cmdline = cmdline;
        ok = CreateProcessW(
            application_path.empty() ? nullptr : application_path.c_str(),
            primary_cmdline.empty() ? nullptr : primary_cmdline.data(),
            nullptr,
            nullptr,
            TRUE,
            create_flags,
            nullptr,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &sx.StartupInfo,
            &pi);
        create_gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("camoufox", "spawn_capture create_result label=%s ok=%d gle=%lu elapsed_ms=%llu create_elapsed_ms=%llu cmd_len=%zu",
            spawn_label,
            ok ? 1 : 0,
            create_gle,
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long long>(now_ms() - create_t0),
            cmdline.size());
        if (!ok && create_gle == ERROR_INVALID_PARAMETER)
        {
            STARTUPINFOW si{};
            si.cb         = sizeof(si);
            si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = wr;
            si.hStdError  = wr;
            si.hStdInput  = child_stdin;
            si.wShowWindow = SW_HIDE;
            const DWORD fallback_create_flags = CREATE_NO_WINDOW;
            const uint64_t fallback_t0 = now_ms();
            std::wstring fallback_cmdline = cmdline;
            diag::log_tagged_fmt("camoufox", "spawn_capture fallback_create_begin label=%s create_flags=0x%08lX inherited_error_mode=%d process_error_mode_current=0x%08lX desired_child_error_mode=0x%08lX cmd_len=%zu",
                spawn_label,
                static_cast<unsigned long>(fallback_create_flags),
                (fallback_create_flags & CREATE_DEFAULT_ERROR_MODE) == 0 ? 1 : 0,
                static_cast<unsigned long>(current_error_mode()),
                static_cast<unsigned long>(current_error_mode() | kBridgeChildErrorMode),
                cmdline.size());
            SetLastError(0);
            ok = CreateProcessW(
                application_path.empty() ? nullptr : application_path.c_str(),
                fallback_cmdline.empty() ? nullptr : fallback_cmdline.data(),
                nullptr,
                nullptr,
                TRUE,
                fallback_create_flags,
                nullptr,
                working_directory.empty() ? nullptr : working_directory.c_str(),
                &si,
                &pi);
            create_gle = ok ? 0 : GetLastError();
            diag::log_tagged_fmt("camoufox", "spawn_capture fallback_create_result label=%s ok=%d gle=%lu elapsed_ms=%llu fallback_elapsed_ms=%llu cmd_len=%zu",
                spawn_label,
                ok ? 1 : 0,
                create_gle,
                static_cast<unsigned long long>(now_ms() - t0),
                static_cast<unsigned long long>(now_ms() - fallback_t0),
                cmdline.size());
        }
    }
    if (attr_ready)
        DeleteProcThreadAttributeList(sx.lpAttributeList);
    CloseHandle(wr);
    CloseHandle(child_stdin);
    if (!ok)
    {
        out_stdout = "spawn create failed gle=" + std::to_string(create_gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture create_failed label=%s gle=%lu app=%s cwd=%s cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
            spawn_label, create_gle, app_log.c_str(), cwd_log.c_str(), cmdline.size(),
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(rd);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "spawn_capture process_started label=%s pid=%lu cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
        spawn_label, static_cast<unsigned long>(pi.dwProcessId), cmdline.size(),
        static_cast<unsigned long>(timeout_ms), static_cast<unsigned long long>(now_ms() - t0));
    CloseHandle(pi.hThread);

    char buf[4096];
    DWORD elapsed = 0;
    const DWORD step = 100;
    while (true)
    {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0)
        {
            DWORD got = 0;
            if (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0)
                out_stdout.append(buf, buf + got);
        }
        DWORD w = WaitForSingleObject(pi.hProcess, step);
        if (w == WAIT_OBJECT_0) break;
        elapsed += step;
        if (timeout_ms != INFINITE && elapsed >= timeout_ms)
        {
            std::unique_lock<std::recursive_timed_mutex> lifecycle(lifecycle_mtx());
            TerminateProcess(pi.hProcess, 1);
            std::string tail = compact_child_output_tail(out_stdout, 600);
            out_stdout += " spawn timeout elapsed_ms=" + std::to_string(elapsed) + " output_tail=" + tail;
            diag::log_tagged_fmt("camoufox", "spawn_capture timeout label=%s pid=%lu elapsed_ms=%lu cmd_len=%zu captured_len=%zu tail=%.600s",
                spawn_label, static_cast<unsigned long>(pi.dwProcessId),
                static_cast<unsigned long>(elapsed), cmdline.size(), out_stdout.size(), tail.c_str());
            CloseHandle(pi.hProcess);
            CloseHandle(rd);
            return false;
        }
    }
    while (true)
    {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        out_stdout.append(buf, buf + got);
    }
    GetExitCodeProcess(pi.hProcess, &out_exit_code);
    diag::log_tagged_fmt("camoufox", "spawn_capture exit label=%s pid=%lu code=%lu cmd_len=%zu captured_len=%zu elapsed_ms=%llu tail=%.600s",
        spawn_label, static_cast<unsigned long>(pi.dwProcessId), out_exit_code, cmdline.size(), out_stdout.size(),
        static_cast<unsigned long long>(now_ms() - t0),
        compact_child_output_tail(out_stdout, 600).c_str());
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
}

bool spawn_capture(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    return spawn_capture_impl({}, utf8_to_wide(cmdline), {}, "cmdline", timeout_ms, out_exit_code, out_stdout);
}

bool spawn_python_capture(const std::string& python_path, const std::wstring& args, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout, const char* label)
{
    std::wstring app = utf8_to_wide(python_path);
    std::wstring cmdline = quote_arg_w(app);
    if (!args.empty())
    {
        cmdline.push_back(L' ');
        cmdline.append(args);
    }
    return spawn_capture_impl(app, std::move(cmdline), parent_directory_w(app), label, timeout_ms, out_exit_code, out_stdout);
}

bool spawn_executable_capture(const std::string& executable_path, const std::wstring& args, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout, const char* label)
{
    std::wstring app = utf8_to_wide(executable_path);
    std::wstring cmdline = quote_arg_w(app);
    if (!args.empty())
    {
        cmdline.push_back(L' ');
        cmdline.append(args);
    }
    return spawn_capture_impl(app, std::move(cmdline), parent_directory_w(app), label, timeout_ms, out_exit_code, out_stdout);
}

std::string compact_child_output(std::string s, size_t limit = 1600)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    s = s.substr(a, b - a);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s.resize(limit);
        s += "...";
    }
    return s;
}

std::string compact_child_output_tail(std::string s, size_t limit = 1600)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    s = s.substr(a, b - a);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s = s.substr(s.size() - limit);
        s.insert(0, "...");
    }
    return s;
}

std::string read_file_tail_for_log(const std::string& path, size_t max_bytes)
{
    if (path.empty() || max_bytes == 0)
        return {};
    std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty())
        return {};
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0)
    {
        CloseHandle(h);
        return {};
    }
    const uint64_t total = static_cast<uint64_t>(size.QuadPart);
    const uint64_t take = std::min<uint64_t>(total, static_cast<uint64_t>(max_bytes));
    LARGE_INTEGER pos{};
    pos.QuadPart = static_cast<LONGLONG>(total - take);
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
    {
        CloseHandle(h);
        return {};
    }
    std::string out;
    out.resize(static_cast<size_t>(take));
    DWORD got = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0)
        return {};
    out.resize(got);
    return compact_child_output_tail(out, max_bytes);
}

uint64_t file_size_for_log(const std::string& path)
{
    if (path.empty())
        return 0;
    std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty())
        return 0;
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    LARGE_INTEGER size{};
    const BOOL ok = GetFileSizeEx(h, &size);
    CloseHandle(h);
    if (!ok || size.QuadPart <= 0)
        return 0;
    return static_cast<uint64_t>(size.QuadPart);
}

struct setup_path_fingerprint_t
{
    bool exists = false;
    bool directory = false;
    DWORD attr = INVALID_FILE_ATTRIBUTES;
    DWORD gle = ERROR_SUCCESS;
    uint64_t size = 0;
    uint64_t mtime_100ns = 0;
};

setup_path_fingerprint_t collect_setup_path_fingerprint_w(const std::wstring& path)
{
    setup_path_fingerprint_t out;
    if (path.empty())
    {
        out.gle = ERROR_PATH_NOT_FOUND;
        return out;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
    {
        out.gle = GetLastError();
        return out;
    }
    out.exists = true;
    out.attr = fad.dwFileAttributes;
    out.directory = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (!out.directory)
        out.size = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | static_cast<uint64_t>(fad.nFileSizeLow);
    out.mtime_100ns = filetime_to_u64(fad.ftLastWriteTime);
    return out;
}

nlohmann::json setup_path_fingerprint_json(const setup_path_fingerprint_t& fp)
{
    return {
        {"exists", fp.exists},
        {"directory", fp.directory},
        {"attr", static_cast<uint32_t>(fp.attr)},
        {"gle", static_cast<uint32_t>(fp.gle)},
        {"size", fp.size},
        {"mtime_100ns", fp.mtime_100ns}
    };
}

std::string setup_path_fingerprint_key(const setup_path_fingerprint_t& fp)
{
    std::ostringstream oss;
    oss << (fp.exists ? 1 : 0) << ':'
        << (fp.directory ? 1 : 0) << ':'
        << static_cast<unsigned long>(fp.attr) << ':'
        << static_cast<unsigned long>(fp.gle) << ':'
        << fp.size << ':'
        << fp.mtime_100ns;
    return oss.str();
}

std::string normalized_sticky_path_key(const std::string& path)
{
    return normalize_launch_path(path);
}

nlohmann::json local_helper_file_diag_json(const local_helper_file_diag_t& fd)
{
    return {
        {"exists", fd.exists},
        {"attr", static_cast<uint32_t>(fd.attr)},
        {"gle", static_cast<uint32_t>(fd.gle)},
        {"size", fd.size},
        {"mtime_100ns", fd.mtime_100ns},
        {"sha256", fd.sha256},
        {"hash_status", fd.hash_status}
    };
}

std::string local_helper_file_diag_key(const local_helper_file_diag_t& fd)
{
    std::ostringstream oss;
    oss << (fd.exists ? 1 : 0) << ':'
        << static_cast<unsigned long>(fd.attr) << ':'
        << static_cast<unsigned long>(fd.gle) << ':'
        << fd.size << ':'
        << fd.mtime_100ns << ':'
        << (fd.sha256.empty() ? fd.hash_status : fd.sha256);
    return oss.str();
}

struct addon_cache_fingerprint_t
{
    std::string addons_dir;
    std::string ubo_dir;
    std::string manifest_path;
    setup_path_fingerprint_t addons;
    setup_path_fingerprint_t ubo;
    setup_path_fingerprint_t manifest;
};

addon_cache_fingerprint_t collect_addon_cache_fingerprint()
{
    addon_cache_fingerprint_t out;
    wchar_t local[MAX_PATH] = {};
    const DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got == 0 || got >= MAX_PATH)
        return out;
    const std::wstring addons_dir = join_path_w(join_path_w(join_path_w(join_path_w(local, L"camoufox"), L"camoufox"), L"Cache"), L"addons");
    const std::wstring ubo_dir = join_path_w(addons_dir, L"UBO");
    const std::wstring manifest_path = join_path_w(ubo_dir, L"manifest.json");
    out.addons_dir = wide_to_utf8(addons_dir);
    out.ubo_dir = wide_to_utf8(ubo_dir);
    out.manifest_path = wide_to_utf8(manifest_path);
    out.addons = collect_setup_path_fingerprint_w(addons_dir);
    out.ubo = collect_setup_path_fingerprint_w(ubo_dir);
    out.manifest = collect_setup_path_fingerprint_w(manifest_path);
    return out;
}

nlohmann::json addon_cache_fingerprint_json(const addon_cache_fingerprint_t& fp)
{
    return {
        {"addons_dir", fp.addons_dir},
        {"ubo_dir", fp.ubo_dir},
        {"manifest_path", fp.manifest_path},
        {"addons", setup_path_fingerprint_json(fp.addons)},
        {"ubo", setup_path_fingerprint_json(fp.ubo)},
        {"manifest", setup_path_fingerprint_json(fp.manifest)}
    };
}

std::string addon_cache_fingerprint_key(const addon_cache_fingerprint_t& fp)
{
    std::ostringstream oss;
    oss << normalized_sticky_path_key(fp.addons_dir) << '|'
        << setup_path_fingerprint_key(fp.addons) << '|'
        << normalized_sticky_path_key(fp.ubo_dir) << '|'
        << setup_path_fingerprint_key(fp.ubo) << '|'
        << normalized_sticky_path_key(fp.manifest_path) << '|'
        << setup_path_fingerprint_key(fp.manifest);
    return oss.str();
}

struct source_bridge_file_fingerprint_t
{
    std::string path;
    local_helper_file_diag_t file;
};

struct source_bridge_fingerprint_t
{
    std::vector<source_bridge_file_fingerprint_t> files;
};

void append_source_file_candidate(std::vector<std::wstring>& files, const std::wstring& base, const wchar_t* rel)
{
    if (base.empty() || rel == nullptr || rel[0] == L'\0')
        return;
    const std::wstring path = join_path_w(base, rel);
    if (path_exists_w(path))
        append_unique_path(files, path);
}

source_bridge_fingerprint_t collect_source_bridge_fingerprint(const std::string& mode, const std::string& command_path)
{
    source_bridge_fingerprint_t out;
    if (mode != "python")
        return out;

    std::vector<std::wstring> bases = runtime_base_dirs();
    const std::wstring command_w = utf8_to_wide(command_path);
    if (!command_w.empty())
    {
        const std::wstring command_dir = parent_directory_w(command_w);
        append_unique_path(bases, command_dir);
        append_unique_path(bases, parent_dir_w(command_dir));
        append_unique_path(bases, parent_dir_w(parent_dir_w(command_dir)));
    }

    std::vector<std::wstring> files;
    static const wchar_t* rels[] = {
        L"camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\browser.py",
        L"camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\tools\\navigation.py",
        L"deps\\camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\browser.py",
        L"deps\\camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\tools\\navigation.py",
        L".deps\\camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\browser.py",
        L".deps\\camoufox-reverse-mcp\\src\\camoufox_reverse_mcp\\tools\\navigation.py",
        L"src\\camoufox_reverse_mcp\\browser.py",
        L"src\\camoufox_reverse_mcp\\tools\\navigation.py",
        L"Lib\\site-packages\\camoufox_reverse_mcp\\browser.py",
        L"Lib\\site-packages\\camoufox_reverse_mcp\\tools\\navigation.py"
    };

    for (const auto& base : bases)
    {
        for (const wchar_t* rel : rels)
            append_source_file_candidate(files, base, rel);
    }

    constexpr size_t kMaxSourceFingerprintFiles = 24;
    for (size_t i = 0; i < files.size() && i < kMaxSourceFingerprintFiles; ++i)
    {
        source_bridge_file_fingerprint_t item;
        item.path = wide_to_utf8(files[i]);
        item.file = collect_local_helper_file_diag(item.path);
        out.files.push_back(std::move(item));
    }
    return out;
}

nlohmann::json source_bridge_fingerprint_json(const source_bridge_fingerprint_t& fp)
{
    nlohmann::json files = nlohmann::json::array();
    for (const auto& item : fp.files)
    {
        files.push_back({
            {"path", item.path},
            {"file", local_helper_file_diag_json(item.file)}
        });
    }
    return {
        {"count", fp.files.size()},
        {"files", std::move(files)}
    };
}

std::string source_bridge_fingerprint_key(const source_bridge_fingerprint_t& fp)
{
    std::ostringstream oss;
    oss << fp.files.size();
    for (const auto& item : fp.files)
    {
        oss << '|'
            << normalized_sticky_path_key(item.path)
            << '='
            << local_helper_file_diag_key(item.file);
    }
    return oss.str();
}

struct sticky_setup_context_t
{
    std::string session_id;
    std::string mode;
    std::string command_path;
    std::string browser_path;
    local_helper_file_diag_t command_file;
    local_helper_file_diag_t browser_file;
    addon_cache_fingerprint_t addon_cache;
    source_bridge_fingerprint_t source_bridge;
    std::string key;
    nlohmann::json details = nlohmann::json::object();
};

sticky_setup_context_t make_sticky_setup_context(const launch_config_t& cfg, const std::string& mode, const std::string& command_path)
{
    sticky_setup_context_t ctx;
    ctx.session_id = cfg.session_id.empty() ? std::string("default") : cfg.session_id;
    ctx.mode = mode.empty() ? std::string("unknown") : mode;
    ctx.command_path = command_path;
    ctx.browser_path = cfg.browser_executable;
    ctx.command_file = collect_local_helper_file_diag(command_path);
    ctx.browser_file = collect_local_helper_file_diag(cfg.browser_executable);
    ctx.addon_cache = collect_addon_cache_fingerprint();
    ctx.source_bridge = collect_source_bridge_fingerprint(ctx.mode, command_path);
    std::ostringstream key;
    key << "mode=" << ctx.mode
        << "|command=" << normalized_sticky_path_key(ctx.command_path)
        << "|command_file=" << local_helper_file_diag_key(ctx.command_file)
        << "|browser=" << normalized_sticky_path_key(ctx.browser_path)
        << "|browser_file=" << local_helper_file_diag_key(ctx.browser_file)
        << "|addon=" << addon_cache_fingerprint_key(ctx.addon_cache)
        << "|source=" << source_bridge_fingerprint_key(ctx.source_bridge);
    ctx.key = key.str();
    ctx.details = {
        {"session_id", ctx.session_id},
        {"mode", ctx.mode},
        {"command_path", ctx.command_path},
        {"browser_path", ctx.browser_path},
        {"command_file", local_helper_file_diag_json(ctx.command_file)},
        {"browser_file", local_helper_file_diag_json(ctx.browser_file)},
        {"addon_cache", addon_cache_fingerprint_json(ctx.addon_cache)},
        {"source_bridge", source_bridge_fingerprint_json(ctx.source_bridge)}
    };
    return ctx;
}

struct sticky_setup_failure_state_t
{
    bool active = false;
    std::string key;
    std::string category;
    std::string summary;
    std::string session_id;
    std::string mode;
    std::string command_path;
    std::string browser_path;
    std::string debug_log;
    uint64_t generation = 0;
    uint64_t set_ms = 0;
    uint64_t elapsed_ms = 0;
    uint32_t child_pid = 0;
    nlohmann::json context = nlohmann::json::object();
    nlohmann::json source = nlohmann::json::object();
};

std::mutex& sticky_setup_failure_mtx()
{
    static std::mutex m;
    return m;
}

sticky_setup_failure_state_t& sticky_setup_failure_state()
{
    static sticky_setup_failure_state_t s;
    return s;
}

nlohmann::json sticky_source_summary_json(const nlohmann::json& source)
{
    nlohmann::json out = nlohmann::json::object();
    if (!source.is_object())
        return out;
    const char* keys[] = {
        "status", "phase", "transport_phase", "timeout_phase", "sidecar_timeout_phase",
        "readiness_sub_step", "cancellation_source", "strict_launch_budget_blown",
        "error_type", "error_kind", "error_summary", "sidecar_error_type",
        "sidecar_error_kind", "sidecar_error_summary", "last_debug_event_name",
        "debug_phase", "debug_tail_len", "child_debug_log", "debug_log_size",
        "process_tree_count", "browser_process_count", "error_tail", "response_tail"
    };
    for (const char* key : keys)
    {
        auto it = source.find(key);
        if (it != source.end())
            out[key] = *it;
    }
    return out;
}

nlohmann::json sticky_setup_failure_json_from_state(const sticky_setup_failure_state_t& s)
{
    return {
        {"active", s.active},
        {"nonretryable", true},
        {"category", s.category},
        {"error_summary", s.summary},
        {"key", s.key},
        {"generation", s.generation},
        {"session_id", s.session_id},
        {"mode", s.mode},
        {"command_path", s.command_path},
        {"browser_path", s.browser_path},
        {"child_pid", s.child_pid},
        {"debug_log", s.debug_log},
        {"set_ms", s.set_ms},
        {"elapsed_ms", s.elapsed_ms},
        {"context", s.context},
        {"source", s.source}
    };
}

std::string sticky_setup_failure_error_text(const std::string& category, const std::string& summary)
{
    return std::string("camoufox sticky_setup_failure category=") +
        (category.empty() ? "unknown" : category) +
        " root=" +
        (summary.empty() ? std::string("<empty>") : compact_child_output_tail(summary, 700));
}

void attach_sticky_setup_failure(nlohmann::json& target, const nlohmann::json& sticky)
{
    if (!target.is_object())
        target = nlohmann::json::object();
    target["nonretryable_setup_failure"] = true;
    target["sticky_setup_failure"] = sticky;
    target["setup_failure_category"] = json_string_or(sticky, "category", std::string());
    target["setup_failure_key"] = json_string_or(sticky, "key", std::string());
    target["setup_failure_summary"] = json_string_or(sticky, "error_summary", std::string());
}

nlohmann::json set_sticky_setup_failure(const sticky_setup_context_t& ctx,
                                        const std::string& category,
                                        const std::string& summary,
                                        uint64_t generation,
                                        uint32_t child_pid,
                                        const std::string& debug_log,
                                        uint64_t elapsed_ms,
                                        const nlohmann::json& source)
{
    sticky_setup_failure_state_t snapshot;
    {
        std::lock_guard<std::mutex> lk(sticky_setup_failure_mtx());
        auto& state = sticky_setup_failure_state();
        state.active = true;
        state.key = ctx.key;
        state.category = category.empty() ? std::string("unknown") : category;
        state.summary = compact_child_output_tail(summary, 1200);
        state.session_id = ctx.session_id;
        state.mode = ctx.mode;
        state.command_path = ctx.command_path;
        state.browser_path = ctx.browser_path;
        state.debug_log = debug_log;
        state.generation = generation;
        state.set_ms = now_ms();
        state.elapsed_ms = elapsed_ms;
        state.child_pid = child_pid;
        state.context = ctx.details;
        state.source = sticky_source_summary_json(source);
        snapshot = state;
    }
    const nlohmann::json sticky = sticky_setup_failure_json_from_state(snapshot);
    diag::log_tagged_fmt("camoufox",
        "sticky_setup_failure_set generation=%llu session_id=%s category=%s child_pid=%lu elapsed_ms=%llu mode=%s command_path=%s command_exists=%d command_sha256=%s command_hash_status=%s browser_path=%s browser_exists=%d browser_sha256=%s browser_hash_status=%s addon_ubo_exists=%d addon_manifest_exists=%d source_files=%zu debug_log=%s key_tail=%.700s summary=%.900s",
        static_cast<unsigned long long>(generation),
        ctx.session_id.c_str(),
        snapshot.category.c_str(),
        static_cast<unsigned long>(child_pid),
        static_cast<unsigned long long>(elapsed_ms),
        ctx.mode.c_str(),
        ctx.command_path.empty() ? "<empty>" : ctx.command_path.c_str(),
        ctx.command_file.exists ? 1 : 0,
        ctx.command_file.sha256.empty() ? "<empty>" : ctx.command_file.sha256.c_str(),
        ctx.command_file.hash_status.empty() ? "<empty>" : ctx.command_file.hash_status.c_str(),
        ctx.browser_path.empty() ? "<empty>" : ctx.browser_path.c_str(),
        ctx.browser_file.exists ? 1 : 0,
        ctx.browser_file.sha256.empty() ? "<empty>" : ctx.browser_file.sha256.c_str(),
        ctx.browser_file.hash_status.empty() ? "<empty>" : ctx.browser_file.hash_status.c_str(),
        ctx.addon_cache.ubo.exists ? 1 : 0,
        ctx.addon_cache.manifest.exists ? 1 : 0,
        ctx.source_bridge.files.size(),
        debug_log.empty() ? "<empty>" : debug_log.c_str(),
        compact_child_output_tail(ctx.key, 700).c_str(),
        snapshot.summary.empty() ? "<empty>" : snapshot.summary.c_str());
    return sticky;
}

void clear_sticky_setup_failure(const char* reason)
{
    sticky_setup_failure_state_t old;
    {
        std::lock_guard<std::mutex> lk(sticky_setup_failure_mtx());
        auto& state = sticky_setup_failure_state();
        if (!state.active)
            return;
        old = state;
        state = sticky_setup_failure_state_t{};
    }
    diag::log_tagged_fmt("camoufox",
        "sticky_setup_failure_clear reason=%s generation=%llu session_id=%s category=%s child_pid=%lu mode=%s command_path=%s browser_path=%s age_ms=%llu key_tail=%.700s summary=%.900s",
        safe_reason(reason),
        static_cast<unsigned long long>(old.generation),
        old.session_id.empty() ? "<empty>" : old.session_id.c_str(),
        old.category.empty() ? "<empty>" : old.category.c_str(),
        static_cast<unsigned long>(old.child_pid),
        old.mode.empty() ? "<empty>" : old.mode.c_str(),
        old.command_path.empty() ? "<empty>" : old.command_path.c_str(),
        old.browser_path.empty() ? "<empty>" : old.browser_path.c_str(),
        static_cast<unsigned long long>(now_ms() >= old.set_ms ? now_ms() - old.set_ms : 0),
        compact_child_output_tail(old.key, 700).c_str(),
        old.summary.empty() ? "<empty>" : old.summary.c_str());
}

bool sticky_setup_failure_hit_or_clear(const sticky_setup_context_t& ctx,
                                       uint64_t generation,
                                       uint32_t child_pid,
                                       uint64_t elapsed_ms,
                                       nlohmann::json& out_sticky,
                                       std::string& out_error)
{
    sticky_setup_failure_state_t snapshot;
    bool active = false;
    bool key_match = false;
    {
        std::lock_guard<std::mutex> lk(sticky_setup_failure_mtx());
        auto& state = sticky_setup_failure_state();
        active = state.active;
        if (!active)
            return false;
        key_match = state.key == ctx.key;
        snapshot = state;
        if (!key_match)
            state = sticky_setup_failure_state_t{};
    }
    if (!key_match)
    {
        diag::log_tagged_fmt("camoufox",
            "sticky_setup_failure_clear reason=dependency_fingerprint_changed old_generation=%llu old_session_id=%s old_category=%s old_command_path=%s old_browser_path=%s new_session_id=%s new_mode=%s new_command_path=%s new_browser_path=%s old_key_tail=%.500s new_key_tail=%.500s",
            static_cast<unsigned long long>(snapshot.generation),
            snapshot.session_id.empty() ? "<empty>" : snapshot.session_id.c_str(),
            snapshot.category.empty() ? "<empty>" : snapshot.category.c_str(),
            snapshot.command_path.empty() ? "<empty>" : snapshot.command_path.c_str(),
            snapshot.browser_path.empty() ? "<empty>" : snapshot.browser_path.c_str(),
            ctx.session_id.c_str(),
            ctx.mode.c_str(),
            ctx.command_path.empty() ? "<empty>" : ctx.command_path.c_str(),
            ctx.browser_path.empty() ? "<empty>" : ctx.browser_path.c_str(),
            compact_child_output_tail(snapshot.key, 500).c_str(),
            compact_child_output_tail(ctx.key, 500).c_str());
        return false;
    }
    out_sticky = sticky_setup_failure_json_from_state(snapshot);
    out_sticky["hit_generation"] = generation;
    out_sticky["hit_child_pid"] = child_pid;
    out_sticky["hit_elapsed_ms"] = elapsed_ms;
    out_sticky["hit_context"] = ctx.details;
    out_error = sticky_setup_failure_error_text(snapshot.category, snapshot.summary);
    diag::log_tagged_fmt("camoufox",
        "sticky_setup_failure_hit generation=%llu original_generation=%llu session_id=%s original_session_id=%s category=%s child_pid=%lu original_child_pid=%lu elapsed_ms=%llu age_ms=%llu mode=%s command_path=%s browser_path=%s addon_ubo_exists=%d addon_manifest_exists=%d source_files=%zu key_tail=%.700s summary=%.900s",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(snapshot.generation),
        ctx.session_id.c_str(),
        snapshot.session_id.empty() ? "<empty>" : snapshot.session_id.c_str(),
        snapshot.category.empty() ? "<empty>" : snapshot.category.c_str(),
        static_cast<unsigned long>(child_pid),
        static_cast<unsigned long>(snapshot.child_pid),
        static_cast<unsigned long long>(elapsed_ms),
        static_cast<unsigned long long>(now_ms() >= snapshot.set_ms ? now_ms() - snapshot.set_ms : 0),
        ctx.mode.c_str(),
        ctx.command_path.empty() ? "<empty>" : ctx.command_path.c_str(),
        ctx.browser_path.empty() ? "<empty>" : ctx.browser_path.c_str(),
        ctx.addon_cache.ubo.exists ? 1 : 0,
        ctx.addon_cache.manifest.exists ? 1 : 0,
        ctx.source_bridge.files.size(),
        compact_child_output_tail(ctx.key, 700).c_str(),
        snapshot.summary.empty() ? "<empty>" : snapshot.summary.c_str());
    return true;
}

std::string classify_nonretryable_setup_failure_text(const std::string& text)
{
    if (text.empty())
        return {};
    const std::string lower = ascii_lower_copy(text);
    if (lower.find("invalidaddonpath") != std::string::npos ||
        lower.find("invalid addon path") != std::string::npos ||
        (lower.find("manifest.json") != std::string::npos && (lower.find("missing") != std::string::npos || lower.find("not found") != std::string::npos)))
        return "invalid_addon_path";
    if (lower.find("required_reverse_tools_missing") != std::string::npos ||
        lower.find("did not expose required reverse tools") != std::string::npos ||
        lower.find("missing_tools") != std::string::npos)
        return "required_reverse_tools_missing";
    if (lower.find("browser executable not found") != std::string::npos ||
        lower.find("browser executable is unavailable") != std::string::npos ||
        lower.find("browser_required_failed") != std::string::npos)
        return "browser_executable_missing";
    if (lower.find("not a camoufox browser bundle") != std::string::npos ||
        lower.find("browser_rejected_non_camoufox") != std::string::npos)
        return "browser_executable_rejected";
    return {};
}

nlohmann::json maybe_set_sticky_setup_failure(const sticky_setup_context_t& ctx,
                                              const std::string& error_text,
                                              const nlohmann::json& diagnostics,
                                              uint64_t generation,
                                              uint32_t child_pid,
                                              const std::string& debug_log,
                                              uint64_t elapsed_ms)
{
    std::string combined = error_text;
    if (diagnostics.is_object() && !diagnostics.empty())
    {
        combined.push_back(' ');
        combined += diagnostics.dump();
    }
    const std::string category = classify_nonretryable_setup_failure_text(combined);
    if (category.empty())
        return nlohmann::json::object();
    return set_sticky_setup_failure(ctx, category, error_text.empty() ? combined : error_text, generation, child_pid, debug_log, elapsed_ms, diagnostics);
}

size_t text_marker_count(const std::string& text, const std::string& marker)
{
    if (text.empty() || marker.empty())
        return 0;
    size_t count = 0;
    size_t pos = 0;
    while ((pos = text.find(marker, pos)) != std::string::npos)
    {
        ++count;
        pos += marker.size();
    }
    return count;
}

const char* json_type_name(const nlohmann::json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const nlohmann::json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

struct url_log_t
{
    std::string host;
    std::string path;
    bool has_query = false;
    bool has_fragment = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    size_t host_start = 0;
    size_t scheme = url.find("://");
    if (scheme != std::string::npos) host_start = scheme + 3;
    size_t host_end = url.find_first_of("/?#", host_start);
    if (host_end == std::string::npos) host_end = url.size();
    if (host_end > host_start) out.host = url.substr(host_start, host_end - host_start);
    size_t path_start = url.find('/', host_start);
    size_t query_pos = url.find('?', host_start);
    size_t frag_pos = url.find('#', host_start);
    out.has_query = query_pos != std::string::npos;
    out.has_fragment = frag_pos != std::string::npos;
    size_t path_end = url.size();
    if (query_pos != std::string::npos) path_end = query_pos;
    if (frag_pos != std::string::npos && frag_pos < path_end) path_end = frag_pos;
    if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    if (out.host.empty()) out.host = "<relative>";
    return out;
}

bool is_local_fixture_host(const std::string& host)
{
    return host.empty() ||
           host == "<relative>" ||
           host == "localhost" ||
           host == "127.0.0.1" ||
           host == "[::1]" ||
           host == "::1" ||
           host.rfind("127.", 0) == 0;
}

uint64_t stability_budget_for_url(const url_log_t& url)
{
    return is_local_fixture_host(url.host)
        ? kPostNavigationStabilityMsLocalFixture
        : kPostNavigationStabilityMs;
}

void store_page_url_locked(const std::string& page_id, const std::string& url)
{
    if (page_id.empty() || url.empty()) return;
    sg().page_url_registry[page_id] = url;
}

void clear_page_url_locked(const std::string& page_id)
{
    if (page_id.empty()) return;
    sg().page_url_registry.erase(page_id);
}

std::string get_page_url_locked(const std::string& page_id)
{
    if (page_id.empty()) return std::string();
    auto it = sg().page_url_registry.find(page_id);
    if (it == sg().page_url_registry.end()) return std::string();
    return it->second;
}

bool is_page_crash_error(const std::string& error_text)
{
    if (error_text.empty()) return false;
    const std::string lower = error_text;
    return lower.find("Page crashed") != std::string::npos ||
           lower.find("Target crashed") != std::string::npos ||
           lower.find("page crashed") != std::string::npos ||
           lower.find("target crashed") != std::string::npos;
}

struct process_exit_snapshot_t
{
    bool opened = false;
    bool queried = false;
    bool alive = false;
    DWORD gle = 0;
    DWORD exit_code = 0;
};

struct process_identity_snapshot_t
{
    bool opened = false;
    bool exit_queried = false;
    bool image_queried = false;
    bool times_queried = false;
    bool alive = false;
    DWORD gle = 0;
    DWORD exit_code = 0;
    DWORD image_gle = 0;
    DWORD times_gle = 0;
    uint64_t creation_time_100ns = 0;
    std::string image_path;
};

std::string sidecar_executable_path_from_command(std::string command)
{
    while (!command.empty() && std::isspace(static_cast<unsigned char>(command.front())))
        command.erase(command.begin());
    while (!command.empty() && std::isspace(static_cast<unsigned char>(command.back())))
        command.pop_back();
    if (command.empty())
        return {};
    if (command.front() == '"' || command.front() == '\'')
    {
        const char quote = command.front();
        const std::size_t end = command.find(quote, 1);
        if (end != std::string::npos && end > 1)
            return command.substr(1, end - 1);
    }
    const std::string lower = ascii_lower_copy(command);
    const std::size_t exe = lower.find(".exe");
    if (exe != std::string::npos)
        return command.substr(0, exe + 4);
    const std::size_t first_space = command.find_first_of(" \t\r\n");
    return first_space == std::string::npos ? command : command.substr(0, first_space);
}

bool normalized_process_path_equal(const std::string& a, const std::string& b)
{
    const std::string na = normalize_launch_path(a);
    const std::string nb = normalize_launch_path(b);
    return !na.empty() && !nb.empty() && na == nb;
}

process_identity_snapshot_t query_process_identity_snapshot(uint32_t pid)
{
    process_identity_snapshot_t out;
    if (pid == 0)
        return out;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h)
    {
        out.gle = GetLastError();
        return out;
    }
    out.opened = true;
    out.exit_queried = GetExitCodeProcess(h, &out.exit_code) != FALSE;
    out.gle = out.exit_queried ? 0 : GetLastError();
    out.alive = out.exit_queried && out.exit_code == STILL_ACTIVE;
    DWORD path_chars = 32768;
    std::wstring image;
    image.resize(path_chars);
    if (QueryFullProcessImageNameW(h, 0, image.data(), &path_chars))
    {
        image.resize(path_chars);
        out.image_path = wide_to_utf8(image);
        out.image_queried = true;
    }
    else
    {
        out.image_gle = GetLastError();
        image.clear();
        path_chars = MAX_PATH;
        image.resize(path_chars);
        if (QueryFullProcessImageNameW(h, 0, image.data(), &path_chars))
        {
            image.resize(path_chars);
            out.image_path = wide_to_utf8(image);
            out.image_queried = true;
            out.image_gle = 0;
        }
    }
    FILETIME creation{}, exit_time{}, kernel{}, user{};
    if (GetProcessTimes(h, &creation, &exit_time, &kernel, &user))
    {
        out.creation_time_100ns = filetime_to_u64(creation);
        out.times_queried = true;
    }
    else
    {
        out.times_gle = GetLastError();
    }
    CloseHandle(h);
    return out;
}

void populate_child_process_identity(bridge_status_t& status)
{
    if (status.child_pid == 0)
        return;
    const process_identity_snapshot_t identity = query_process_identity_snapshot(status.child_pid);
    status.child_process_identity_available = identity.opened && identity.image_queried && identity.times_queried;
    status.child_process_identity_gle = identity.opened ? (identity.image_queried && identity.times_queried ? 0u : (identity.image_gle != 0 ? identity.image_gle : identity.times_gle)) : identity.gle;
    status.child_process_image_path = identity.image_path;
    status.child_process_creation_time_100ns = identity.creation_time_100ns;
}

process_exit_snapshot_t query_process_exit_snapshot(uint32_t pid)
{
    process_exit_snapshot_t out;
    if (pid == 0)
        return out;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h)
    {
        out.gle = GetLastError();
        return out;
    }
    out.opened = true;
    out.queried = GetExitCodeProcess(h, &out.exit_code) != FALSE;
    out.gle = out.queried ? 0 : GetLastError();
    CloseHandle(h);
    out.alive = out.queried && out.exit_code == STILL_ACTIVE;
    return out;
}

bool process_alive(uint32_t pid)
{
    if (pid == 0) return false;
    const process_exit_snapshot_t snap = query_process_exit_snapshot(pid);
    if (!snap.opened)
    {
        diag::log_tagged_fmt("camoufox", "process_alive open_failed pid=%lu gle=%lu",
            static_cast<unsigned long>(pid), static_cast<unsigned long>(snap.gle));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "process_alive pid=%lu alive=%d gle=%lu exit=%lu",
        static_cast<unsigned long>(pid), static_cast<int>(snap.alive), static_cast<unsigned long>(snap.gle),
        static_cast<unsigned long>(snap.queried ? snap.exit_code : 0));
    return snap.alive;
}

struct process_tree_entry_t
{
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string exe;
};

struct process_tree_reap_result_t
{
    size_t before = 0;
    size_t descendants_before = 0;
    size_t after = 0;
    size_t alive_after = 0;
    uint64_t elapsed_ms = 0;
};

bool contains_process_pid(const std::vector<process_tree_entry_t>& entries, uint32_t pid)
{
    for (const auto& entry : entries)
    {
        if (entry.pid == pid)
            return true;
    }
    return false;
}

std::string compact_process_tree(const std::vector<process_tree_entry_t>& entries)
{
    std::ostringstream oss;
    const size_t limit = std::min<size_t>(entries.size(), 32);
    for (size_t i = 0; i < limit; ++i)
    {
        if (i) oss << ",";
        oss << entries[i].pid << "<-" << entries[i].parent_pid;
        if (!entries[i].exe.empty())
            oss << ":" << entries[i].exe;
    }
    if (entries.size() > limit)
        oss << ",...";
    return oss.str();
}

std::string compact_process_tree_with_exit(const std::vector<process_tree_entry_t>& entries)
{
    std::ostringstream oss;
    const size_t limit = std::min<size_t>(entries.size(), 32);
    for (size_t i = 0; i < limit; ++i)
    {
        if (i) oss << ",";
        const process_exit_snapshot_t exit = query_process_exit_snapshot(entries[i].pid);
        oss << entries[i].pid << "<-" << entries[i].parent_pid;
        if (!entries[i].exe.empty())
            oss << ":" << entries[i].exe;
        oss << ":open=" << (exit.opened ? 1 : 0)
            << ":queried=" << (exit.queried ? 1 : 0)
            << ":alive=" << (exit.alive ? 1 : 0)
            << ":exit=" << static_cast<unsigned long>(exit.queried ? exit.exit_code : 0)
            << ":gle=" << static_cast<unsigned long>(exit.gle);
    }
    if (entries.size() > limit)
        oss << ",...";
    return oss.str();
}

std::string compact_process_tree_delta(const std::string& before, const std::vector<process_tree_entry_t>& after)
{
    std::ostringstream oss;
    oss << "before=" << (before.empty() ? "<empty>" : before) << " after=" << compact_process_tree(after);
    return oss.str();
}

std::vector<process_tree_entry_t> enumerate_process_tree(uint32_t root_pid)
{
    std::vector<process_tree_entry_t> all;
    std::vector<process_tree_entry_t> tree;
    if (root_pid == 0)
        return tree;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        diag::log_tagged_fmt("camoufox", "process_tree_snapshot_failed root_pid=%lu gle=%lu",
            static_cast<unsigned long>(root_pid), static_cast<unsigned long>(GetLastError()));
        tree.push_back({root_pid, 0, std::string()});
        return tree;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            process_tree_entry_t entry;
            entry.pid = static_cast<uint32_t>(pe.th32ProcessID);
            entry.parent_pid = static_cast<uint32_t>(pe.th32ParentProcessID);
            entry.exe = wide_to_utf8(pe.szExeFile);
            all.push_back(std::move(entry));
        } while (Process32NextW(snapshot, &pe));
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "process_tree_process32first_failed root_pid=%lu gle=%lu",
            static_cast<unsigned long>(root_pid), static_cast<unsigned long>(GetLastError()));
    }
    CloseHandle(snapshot);

    for (const auto& entry : all)
    {
        if (entry.pid == root_pid)
        {
            tree.push_back(entry);
            break;
        }
    }
    if (tree.empty())
        tree.push_back({root_pid, 0, std::string()});

    for (size_t i = 0; i < tree.size(); ++i)
    {
        const uint32_t parent = tree[i].pid;
        for (const auto& entry : all)
        {
            if (entry.parent_pid == parent && !contains_process_pid(tree, entry.pid))
                tree.push_back(entry);
        }
    }
    return tree;
}

const char* bridge_state_name(bridge_state_t state)
{
    switch (state)
    {
        case bridge_state_t::stopped: return "stopped";
        case bridge_state_t::starting: return "starting";
        case bridge_state_t::ready: return "ready";
        case bridge_state_t::error: return "error";
    }
    return "unknown";
}

void terminate_process_id_sync(uint32_t pid, const std::string& reason, uint32_t parent_pid = 0, const std::string& exe = std::string());

bool is_camoufox_browser_process_name(const std::string& exe)
{
    std::string name = exe;
    for (char& c : name)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return name == "camoufox.exe" || name.find("camoufox") != std::string::npos;
}

void sweep_stale_camoufox_processes_by_name(uint32_t exclude_pid, const std::string& reason)
{
    if (exclude_pid == 0 && sg().child_pid != 0)
        exclude_pid = sg().child_pid;

    std::set<uint32_t> protected_pids;
    if (exclude_pid != 0)
    {
        std::vector<process_tree_entry_t> tree = enumerate_process_tree(exclude_pid);
        for (const auto& entry : tree)
            protected_pids.insert(entry.pid);
    }
    protected_pids.insert(static_cast<uint32_t>(GetCurrentProcessId()));

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        diag::log_tagged_fmt("camoufox", "stale_process_sweep snapshot_failed reason=%s gle=%lu",
            reason.c_str(), static_cast<unsigned long>(GetLastError()));
        return;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    uint32_t killed = 0;
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            const std::string exe_name = wide_to_utf8(pe.szExeFile);
            if (is_camoufox_browser_process_name(exe_name) &&
                protected_pids.find(static_cast<uint32_t>(pe.th32ProcessID)) == protected_pids.end())
            {
                const uint32_t stale_pid = static_cast<uint32_t>(pe.th32ProcessID);
                diag::log_tagged_critical_fmt("camoufox",
                    "stale_process_sweep killing orphaned camoufox pid=%lu exe=%s reason=%s parent_pid=%lu",
                    static_cast<unsigned long>(stale_pid), exe_name.c_str(),
                    reason.c_str(), static_cast<unsigned long>(pe.th32ParentProcessID));
                terminate_process_id_sync(stale_pid, reason, static_cast<uint32_t>(pe.th32ParentProcessID), exe_name);
                ++killed;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);

    if (killed > 0)
    {
        diag::log_tagged_critical_fmt("camoufox",
            "stale_process_sweep_complete killed=%u reason=%s exclude_pid=%lu",
            static_cast<unsigned>(killed), reason.c_str(), static_cast<unsigned long>(exclude_pid));
    }
    else
    {
        diag::log_tagged_fmt("camoufox",
            "stale_process_sweep_complete killed=0 reason=%s exclude_pid=%lu",
            reason.c_str(), static_cast<unsigned long>(exclude_pid));
    }
}

uint32_t browser_process_count_from_tree(const std::vector<process_tree_entry_t>& tree)
{
    uint32_t browser_count = 0;
    for (const auto& entry : tree)
    {
        if (is_camoufox_browser_process_name(entry.exe))
            ++browser_count;
    }
    return browser_count;
}

bool usable_browser_process_tree(const std::vector<process_tree_entry_t>& tree)
{
    return browser_process_count_from_tree(tree) > 0;
}

bool usable_browser_process_count(uint32_t browser_process_count)
{
    return browser_process_count > 0;
}

bool reduced_browser_process_tree(uint32_t browser_process_count)
{
    return browser_process_count > 0 && browser_process_count < kMinReadyBrowserProcessCount;
}

struct visible_window_snapshot_t
{
    uint32_t visible_window_count = 0;
    RECT first_rect{};
    bool first_rect_valid = false;
    int first_title_len = 0;
    DWORD first_pid = 0;
    uint32_t child_process_count = 0;
    uint32_t browser_process_count = 0;
    std::string process_pids;
};

std::string process_pid_csv(const std::vector<process_tree_entry_t>& tree)
{
    std::ostringstream oss;
    const size_t limit = std::min<size_t>(tree.size(), 48);
    for (size_t i = 0; i < limit; ++i)
    {
        if (i) oss << ",";
        oss << tree[i].pid;
    }
    if (tree.size() > limit)
        oss << ",...";
    return oss.str();
}

struct visible_window_enum_context_t
{
    const std::vector<process_tree_entry_t>* tree = nullptr;
    visible_window_snapshot_t* snapshot = nullptr;
};

BOOL CALLBACK enum_visible_camoufox_window_proc(HWND hwnd, LPARAM param)
{
    auto* ctx = reinterpret_cast<visible_window_enum_context_t*>(param);
    if (!ctx || !ctx->tree || !ctx->snapshot)
        return TRUE;
    if (!IsWindowVisible(hwnd))
        return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0 || !contains_process_pid(*ctx->tree, static_cast<uint32_t>(pid)))
        return TRUE;
    RECT rc{};
    if (!GetWindowRect(hwnd, &rc))
        return TRUE;
    const LONG width = rc.right - rc.left;
    const LONG height = rc.bottom - rc.top;
    if (width <= 0 || height <= 0)
        return TRUE;
    ++ctx->snapshot->visible_window_count;
    if (!ctx->snapshot->first_rect_valid)
    {
        ctx->snapshot->first_rect = rc;
        ctx->snapshot->first_rect_valid = true;
        ctx->snapshot->first_title_len = GetWindowTextLengthW(hwnd);
        ctx->snapshot->first_pid = pid;
    }
    return TRUE;
}

visible_window_snapshot_t sample_visible_window_proof(uint32_t root_pid)
{
    visible_window_snapshot_t out;
    if (root_pid == 0)
        return out;
    const std::vector<process_tree_entry_t> tree = enumerate_process_tree(root_pid);
    out.child_process_count = static_cast<uint32_t>(tree.size());
    out.browser_process_count = browser_process_count_from_tree(tree);
    out.process_pids = process_pid_csv(tree);
    visible_window_enum_context_t ctx;
    ctx.tree = &tree;
    ctx.snapshot = &out;
    EnumWindows(enum_visible_camoufox_window_proc, reinterpret_cast<LPARAM>(&ctx));
    return out;
}

nlohmann::json visible_window_proof_json(const visible_window_snapshot_t& proof, uint32_t child_pid, uint64_t generation, const char* phase)
{
    nlohmann::json out = nlohmann::json::object();
    out["phase"] = phase ? phase : "";
    out["generation"] = generation;
    out["child_pid"] = child_pid;
    out["child_process_count"] = proof.child_process_count;
    out["browser_process_count"] = proof.browser_process_count;
    out["visible_window_count"] = proof.visible_window_count;
    out["first_window_pid"] = static_cast<uint32_t>(proof.first_pid);
    out["first_title_len"] = proof.first_title_len;
    out["process_pids"] = proof.process_pids;
    out["proof"] = proof.visible_window_count > 0;
    out["first_rect"] = {
        {"left", proof.first_rect_valid ? proof.first_rect.left : 0},
        {"top", proof.first_rect_valid ? proof.first_rect.top : 0},
        {"right", proof.first_rect_valid ? proof.first_rect.right : 0},
        {"bottom", proof.first_rect_valid ? proof.first_rect.bottom : 0}
    };
    return out;
}

void log_visible_window_proof(const char* phase, uint64_t generation, uint32_t child_pid, const visible_window_snapshot_t& proof)
{
    diag::log_tagged_fmt("camoufox", "visible_window_proof phase=%s generation=%llu child_pid=%lu visible_window_count=%u first_pid=%lu first_rect=%ld,%ld,%ld,%ld first_title_len=%d child_processes=%u browser_processes=%u process_pids=%s",
        phase ? phase : "<null>",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(child_pid),
        static_cast<unsigned>(proof.visible_window_count),
        static_cast<unsigned long>(proof.first_pid),
        proof.first_rect_valid ? proof.first_rect.left : 0,
        proof.first_rect_valid ? proof.first_rect.top : 0,
        proof.first_rect_valid ? proof.first_rect.right : 0,
        proof.first_rect_valid ? proof.first_rect.bottom : 0,
        proof.first_title_len,
        static_cast<unsigned>(proof.child_process_count),
        static_cast<unsigned>(proof.browser_process_count),
        proof.process_pids.empty() ? "<empty>" : proof.process_pids.c_str());
}

struct bridge_health_snapshot_t
{
    uint32_t child_pid = 0;
    bool child_alive = false;
    bool exit_code_valid = false;
    DWORD exit_code = 0;
    DWORD exit_query_gle = 0;
    uint32_t child_process_count = 0;
    uint32_t browser_process_count = 0;
    std::string process_tree;
};

bridge_health_snapshot_t sample_bridge_health(uint32_t child_pid, bool include_process_tree)
{
    bridge_health_snapshot_t out;
    out.child_pid = child_pid;
    const process_exit_snapshot_t exit = query_process_exit_snapshot(child_pid);
    out.child_alive = exit.alive;
    out.exit_code_valid = exit.queried;
    out.exit_code = exit.exit_code;
    out.exit_query_gle = exit.gle;
    diag::log_tagged_fmt("camoufox", "bridge_health_sample child_pid=%lu opened=%d queried=%d alive=%d exit_code=%lu gle=%lu include_tree=%d",
        static_cast<unsigned long>(child_pid),
        exit.opened ? 1 : 0,
        exit.queried ? 1 : 0,
        out.child_alive ? 1 : 0,
        static_cast<unsigned long>(exit.queried ? exit.exit_code : 0),
        static_cast<unsigned long>(exit.gle),
        include_process_tree ? 1 : 0);
    if (!out.child_alive)
        return out;
    const std::vector<process_tree_entry_t> tree = enumerate_process_tree(child_pid);
    out.child_process_count = static_cast<uint32_t>(tree.size());
    out.browser_process_count = browser_process_count_from_tree(tree);
    if (include_process_tree)
        out.process_tree = compact_process_tree(tree);
    return out;
}

void populate_process_counts(bridge_status_t& s)
{
    s.browser_instance_count = (s.browser_open && s.child_alive && s.child_pid != 0) ? 1u : 0u;
    s.child_process_count = 0;
    s.browser_process_count = 0;
    if (s.child_pid == 0)
        return;
    const std::vector<process_tree_entry_t> tree = enumerate_process_tree(s.child_pid);
    s.child_process_count = static_cast<uint32_t>(tree.size());
    s.browser_process_count = browser_process_count_from_tree(tree);
}

struct action_snapshot_t
{
    bridge_state_t state = bridge_state_t::stopped;
    uint64_t generation = 0;
    uint32_t child_pid = 0;
    bool client = false;
    bool browser_open = false;
    bool page_verified = false;
    bool child_alive = false;
    bool exit_code_valid = false;
    DWORD exit_code = 0;
    DWORD exit_query_gle = 0;
    bool cleanup_pending = false;
    uint64_t total_calls = 0;
    uint64_t total_errors = 0;
    size_t last_error_len = 0;
};

action_snapshot_t action_snapshot()
{
    action_snapshot_t s;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        s.state = sg().state;
        s.generation = sg().generation;
        s.child_pid = sg().child_pid;
        s.client = sg().client != nullptr;
        s.browser_open = sg().browser_open;
        s.page_verified = sg().page_verified;
        s.cleanup_pending = sg().cleanup_pending;
        s.total_calls = sg().total_calls.load(std::memory_order_relaxed);
        s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
        s.last_error_len = sg().last_error.size();
    }
    const process_exit_snapshot_t exit = query_process_exit_snapshot(s.child_pid);
    s.child_alive = exit.alive;
    s.exit_code_valid = exit.queried;
    s.exit_code = exit.exit_code;
    s.exit_query_gle = exit.gle;
    return s;
}

void attach_bridge_call_metadata(call_result_t& r,
                                 const std::string& session_id,
                                 const std::string& tool_name,
                                 uint64_t request_id,
                                 int timeout_ms,
                                 uint64_t elapsed_ms,
                                 uint64_t generation,
                                 uint32_t child_pid,
                                 const std::string& page_id,
                                 const char* phase,
                                 bool late_result,
                                 bool child_alive,
                                 bool browser_open,
                                 bool page_verified,
                                 bool cleanup_pending)
{
    if (!r.data.is_object())
        return;
    r.data["bridge_call"] = {
        {"session_id", session_id.empty() ? std::string("default") : session_id},
        {"tool", tool_name},
        {"request_id", request_id},
        {"aida_operation_id", request_id},
        {"page_id", page_id},
        {"timeout_ms", timeout_ms},
        {"elapsed_ms", elapsed_ms},
        {"generation", generation},
        {"child_pid", child_pid},
        {"child_alive", child_alive},
        {"browser_open", browser_open},
        {"page_verified", page_verified},
        {"cleanup_pending", cleanup_pending},
        {"phase", phase ? phase : ""},
        {"late_result", late_result}
    };
}

std::string selector_for_log(const std::string& selector)
{
    std::string out;
    out.reserve((std::min)(selector.size(), static_cast<size_t>(180)));
    for (char c : selector)
    {
        if (out.size() >= 180)
            break;
        if (c == '\r' || c == '\n' || c == '\t')
            out.push_back(' ');
        else
            out.push_back(c);
    }
    if (selector.size() > out.size())
        out += "...";
    return out.empty() ? std::string("<empty>") : out;
}

void log_action_phase(const char* action, const char* phase, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, const action_snapshot_t& s, uint64_t elapsed_ms, const char* failure_phase = "")
{
    const std::string safe_selector = selector_for_log(selector);
    diag::log_tagged_fmt("camoufox",
        "action_%s action=%s request_id=%llu selector=%s timeout_ms=%d text_len=%zu generation=%llu child_pid=%lu state=%s client=%d browser_open=%d page_verified=%d child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu cleanup_pending=%d calls=%llu errors=%llu err_len=%zu elapsed_ms=%llu failure_phase=%s",
        phase,
        action,
        static_cast<unsigned long long>(request_id),
        safe_selector.c_str(),
        timeout_ms,
        text_len,
        static_cast<unsigned long long>(s.generation),
        static_cast<unsigned long>(s.child_pid),
        bridge_state_name(s.state),
        static_cast<int>(s.client),
        static_cast<int>(s.browser_open),
        static_cast<int>(s.page_verified),
        static_cast<int>(s.child_alive),
        static_cast<int>(s.exit_code_valid),
        static_cast<unsigned long>(s.exit_code_valid ? s.exit_code : 0),
        static_cast<unsigned long>(s.exit_query_gle),
        static_cast<int>(s.cleanup_pending),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors),
        s.last_error_len,
        static_cast<unsigned long long>(elapsed_ms),
        failure_phase ? failure_phase : "");
}

void clear_page_state_locked()
{
    sg().browser_open = false;
    sg().active_page_id.clear();
    sg().active_page_url.clear();
    sg().active_page_title.clear();
    sg().pages.clear();
    sg().page_verified = false;
    sg().last_verified_ms = 0;
    clear_privacy_locked();
}

void clear_auto_restart_block_locked(const char* reason)
{
    if (sg().auto_restart_block_until_ms == 0)
        return;
    diag::log_tagged_fmt("camoufox", "auto_restart_block_clear reason=%s blocked_reason=%s generation=%llu remaining_ms=%llu",
        safe_reason(reason), sg().auto_restart_block_reason.c_str(),
        static_cast<unsigned long long>(sg().auto_restart_block_generation),
        static_cast<unsigned long long>(sg().auto_restart_block_until_ms > now_ms() ? sg().auto_restart_block_until_ms - now_ms() : 0));
    sg().auto_restart_block_until_ms = 0;
    sg().auto_restart_block_generation = 0;
    sg().auto_restart_block_reason.clear();
}

void block_auto_restart_locked(const std::string& reason, uint64_t generation, uint64_t duration_ms)
{
    const uint64_t until_ms = now_ms() + duration_ms;
    sg().auto_restart_block_until_ms = until_ms;
    sg().auto_restart_block_generation = generation;
    sg().auto_restart_block_reason = reason;
    diag::log_tagged_fmt("camoufox", "auto_restart_block_set reason=%s generation=%llu duration_ms=%llu until_ms=%llu state=%d child_pid=%lu browser_open=%d page_verified=%d",
        reason.c_str(), static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(duration_ms), static_cast<unsigned long long>(until_ms),
        static_cast<int>(sg().state), static_cast<unsigned long>(sg().child_pid),
        sg().browser_open ? 1 : 0, sg().page_verified ? 1 : 0);
}

bool auto_restart_blocked_locked(uint64_t now, std::string& reason, uint64_t& remaining_ms, uint64_t& generation)
{
    if (sg().auto_restart_block_until_ms == 0)
        return false;
    if (now >= sg().auto_restart_block_until_ms)
    {
        clear_auto_restart_block_locked("expired");
        return false;
    }
    reason = sg().auto_restart_block_reason;
    remaining_ms = sg().auto_restart_block_until_ms - now;
    generation = sg().auto_restart_block_generation;
    return true;
}

std::string ascii_lower_copy(std::string text)
{
    for (char& ch : text)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return text;
}

void clear_launch_init_failure_block_locked(const char* reason)
{
    if (sg().launch_init_failure_block_until_ms == 0)
        return;
    const uint64_t now = now_ms();
    diag::log_tagged_fmt("camoufox", "launch_init_failure_block_clear reason=%s blocked_reason=%s generation=%llu count=%lu exit_code=0x%08lX remaining_ms=%llu command=%s",
        safe_reason(reason),
        sg().launch_init_failure_block_reason.c_str(),
        static_cast<unsigned long long>(sg().launch_init_failure_block_generation),
        static_cast<unsigned long>(sg().launch_init_failure_block_count),
        static_cast<unsigned long>(sg().launch_init_failure_exit_code),
        static_cast<unsigned long long>(sg().launch_init_failure_block_until_ms > now ? sg().launch_init_failure_block_until_ms - now : 0),
        sg().launch_init_failure_block_command.empty() ? "<empty>" : sg().launch_init_failure_block_command.c_str());
    sg().launch_init_failure_block_until_ms = 0;
    sg().launch_init_failure_block_generation = 0;
    sg().launch_init_failure_exit_code = 0;
    sg().launch_init_failure_block_command.clear();
    sg().launch_init_failure_block_reason.clear();
}

void reset_launch_init_failure_block_locked(const char* reason)
{
    const uint32_t old_count = sg().launch_init_failure_block_count;
    const uint64_t old_until = sg().launch_init_failure_block_until_ms;
    clear_launch_init_failure_block_locked(reason);
    if (old_count != 0 || old_until != 0)
    {
        diag::log_tagged_fmt("camoufox", "launch_init_failure_block_reset reason=%s old_count=%lu active=%d",
            safe_reason(reason),
            static_cast<unsigned long>(old_count),
            old_until != 0 ? 1 : 0);
    }
    sg().launch_init_failure_block_count = 0;
    sg().launch_init_failure_exit_code = 0;
    sg().launch_init_failure_block_command.clear();
    sg().launch_init_failure_block_reason.clear();
}

bool launch_init_failure_blocked_locked(const std::string& command, uint64_t now, std::string& reason, uint64_t& remaining_ms, uint64_t& generation, uint32_t& count)
{
    if (sg().launch_init_failure_block_until_ms == 0)
        return false;
    if (now >= sg().launch_init_failure_block_until_ms)
    {
        clear_launch_init_failure_block_locked("expired");
        return false;
    }
    if (_stricmp(sg().launch_init_failure_block_command.c_str(), command.c_str()) != 0)
    {
        diag::log_tagged_fmt("camoufox", "launch_init_failure_block_command_changed old=%s new=%s remaining_ms=%llu",
            sg().launch_init_failure_block_command.empty() ? "<empty>" : sg().launch_init_failure_block_command.c_str(),
            command.empty() ? "<empty>" : command.c_str(),
            static_cast<unsigned long long>(sg().launch_init_failure_block_until_ms - now));
        clear_launch_init_failure_block_locked("command_changed");
        return false;
    }
    reason = sg().launch_init_failure_block_reason;
    remaining_ms = sg().launch_init_failure_block_until_ms - now;
    generation = sg().launch_init_failure_block_generation;
    count = sg().launch_init_failure_block_count;
    return true;
}

int clamp_launch_wait_ms(int requested)
{
    int wait_ms = requested > 0 ? requested : kLaunchWaitMaxMs;
    if (wait_ms < kLaunchWaitMinMs) wait_ms = kLaunchWaitMinMs;
    if (wait_ms > kLaunchWaitMaxMs) wait_ms = kLaunchWaitMaxMs;
    return wait_ms;
}

bool test_lab_launch_fail_fast_enabled(const launch_config_t& cfg)
{
    return cfg.testlab_fast_probe || env_flag_enabled_a("AIDA_CAMOUFOX_TESTLAB_FAST_PROBE");
}

int test_lab_launch_wait_ms(const launch_config_t& cfg)
{
    const int env_ms = env_int_a("AIDA_CAMOUFOX_TESTLAB_LAUNCH_MS", 0);
    const int requested_ms = cfg.launch_timeout_ms;
    int wait_ms = env_ms;
    if (wait_ms <= 0)
        wait_ms = requested_ms > 0 ? requested_ms : kTestLabLaunchWaitDefaultMs;
    const int before_clamp = wait_ms;
    if (wait_ms < kLaunchWaitMinMs) wait_ms = kLaunchWaitMinMs;
    if (wait_ms > kTestLabLaunchWaitMaxMs) wait_ms = kTestLabLaunchWaitMaxMs;
    if (wait_ms != before_clamp) {
        diag::log_tagged_fmt("camoufox",
            "testlab_launch_wait_clamped requested_ms=%d env_ms=%d before_clamp_ms=%d effective_ms=%d min_ms=%d max_ms=%d fast_probe=%d",
            requested_ms,
            env_ms,
            before_clamp,
            wait_ms,
            kLaunchWaitMinMs,
            kTestLabLaunchWaitMaxMs,
            test_lab_launch_fail_fast_enabled(cfg) ? 1 : 0);
    }
    return wait_ms;
}

int effective_launch_wait_ms(const launch_config_t& cfg, bool bundled_visible_launch)
{
    if (test_lab_launch_fail_fast_enabled(cfg))
        return test_lab_launch_wait_ms(cfg);
    const int requested_ms = cfg.launch_timeout_ms;
    int wait_ms = clamp_launch_wait_ms(requested_ms);
    const int post_clamp_ms = wait_ms;
    if (bundled_visible_launch && wait_ms < kBundledVisibleLaunchWaitMinMs)
        wait_ms = kBundledVisibleLaunchWaitMinMs;
    if (bundled_visible_launch && wait_ms > kBundledVisibleLaunchWaitMaxMs)
        wait_ms = kBundledVisibleLaunchWaitMaxMs;
    diag::log_tagged_fmt("camoufox",
        "effective_launch_wait_ms requested_ms=%d bundled_visible=%d post_clamp_ms=%d bundled_min_ms=%d bundled_max_ms=%d final_wait_ms=%d strict_budget_ms=%d",
        requested_ms,
        bundled_visible_launch ? 1 : 0,
        post_clamp_ms,
        kBundledVisibleLaunchWaitMinMs,
        kBundledVisibleLaunchWaitMaxMs,
        wait_ms,
        kStrictLaunchBudgetMs);
    return wait_ms;
}

int apply_visible_readiness_budget_ms(int launch_wait_ms,
                                      bool bundled_visible_launch,
                                      uint64_t start_ms,
                                      const char* phase,
                                      uint64_t generation,
                                      uint32_t child_pid)
{
    if (!bundled_visible_launch)
        return launch_wait_ms;
    const uint64_t elapsed_ms = now_ms() - start_ms;
    const uint64_t remaining_ms = elapsed_ms >= static_cast<uint64_t>(kBundledVisibleReadinessMaxMs)
        ? 0
        : static_cast<uint64_t>(kBundledVisibleReadinessMaxMs) - elapsed_ms;
    const int bounded_ms = remaining_ms > static_cast<uint64_t>(std::numeric_limits<int>::max())
        ? launch_wait_ms
        : std::min<int>(launch_wait_ms, static_cast<int>(remaining_ms));
    if (bounded_ms != launch_wait_ms)
    {
        diag::log_tagged_fmt("camoufox",
            "visible_readiness_budget_clamped phase=%s generation=%llu child_pid=%lu elapsed_ms=%llu remaining_ms=%llu requested_launch_wait_ms=%d bounded_launch_wait_ms=%d max_total_ms=%d",
            phase && phase[0] ? phase : "<unknown>",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(child_pid),
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long long>(remaining_ms),
            launch_wait_ms,
            bounded_ms,
            kBundledVisibleReadinessMaxMs);
    }
    return std::max(0, bounded_ms);
}

int clamp_navigation_call_wait_ms(int requested)
{
    int wait_ms = requested > 0 ? requested + 5000 : 35000;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > kNavigationWaitMaxMs) wait_ms = kNavigationWaitMaxMs;
    return wait_ms;
}

bool query_python_version(const std::string& python_path, int& major, int& minor, std::string& detail)
{
    const uint64_t t0 = now_ms();
    major = 0;
    minor = 0;
    detail.clear();
    diag::log_tagged_fmt("camoufox", "python_version_probe begin path=%s timeout_ms=%lu",
        python_path.c_str(), static_cast<unsigned long>(kDependencyProbeTimeoutMs));
    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, L"-I -S -c \"import sys; assert sys.implementation.name == 'cpython'; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"", kDependencyProbeTimeoutMs, code, captured, "python_version_probe"))
    {
        detail = "version probe timed out or failed to spawn";
        diag::log_tagged_fmt("camoufox", "python_version_probe spawn_failed path=%s elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0),
            compact_child_output(captured).c_str());
        return false;
    }
    if (code != 0)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe exit=" + std::to_string(code);
        diag::log_tagged_fmt("camoufox", "python_version_probe exit_failed path=%s code=%lu elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long>(code),
            static_cast<unsigned long long>(now_ms() - t0), detail.c_str());
        return false;
    }
    int maj = 0;
    int min = 0;
    if (sscanf_s(captured.c_str(), "%d.%d", &maj, &min) != 2)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe returned no version";
        diag::log_tagged_fmt("camoufox", "python_version_probe parse_failed path=%s elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0),
            detail.c_str());
        return false;
    }
    major = maj;
    minor = min;
    detail = compact_child_output(captured);
    diag::log_tagged_fmt("camoufox", "python_version_probe ok path=%s version=%d.%d elapsed_ms=%llu detail=%s",
        python_path.c_str(), major, minor, static_cast<unsigned long long>(now_ms() - t0),
        detail.c_str());
    return true;
}

bool supported_camoufox_python(const std::string& python_path, std::string* reason = nullptr)
{
    int major = 0;
    int minor = 0;
    std::string detail;
    if (!query_python_version(python_path, major, minor, detail))
    {
        if (reason) *reason = detail;
        return false;
    }
    if (major == 3 && minor == 12)
    {
        if (reason) *reason = "python " + detail;
        return true;
    }
    if (reason)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "python %d.%d outside supported camoufox range 3.10-3.13", major, minor);
        *reason = buf;
    }
    return false;
}

void publish_state(bridge_state_t st, const std::string& err)
{
    bridge_state_changed_t ev;
    ev.state     = st;
    ev.last_error = err;
    ev.child_pid = sg().child_pid;
    aida::events::publish(kBridgeStateChanged, ev);
}

void set_error_locked(const std::string& msg)
{
    sg().last_error = msg;
    diag::log_tagged("camoufox", msg.c_str());
}

void clear_error_locked()
{
    if (!sg().last_error.empty())
    {
        diag::log_tagged_fmt("camoufox", "clearing_last_error previous_len=%zu", sg().last_error.size());
        sg().last_error.clear();
    }
}

bool is_driver_closed_error(const std::string& msg)
{
    std::string s = ascii_lower_copy(msg);
    return s.find("connection closed while reading from the driver") != std::string::npos ||
           s.find("target page, context or browser has been closed") != std::string::npos ||
           s.find("browser has been closed") != std::string::npos ||
           s.find("browsercontext.add_init_script: connection closed") != std::string::npos ||
           s.find("page.add_init_script: connection closed") != std::string::npos ||
           s.find("page.goto: connection closed") != std::string::npos ||
           s.find("page.evaluate: connection closed") != std::string::npos ||
           s.find("page.title: connection closed") != std::string::npos ||
           s.find("page.screenshot: connection closed") != std::string::npos ||
           s.find("page.wait_for_selector: connection closed") != std::string::npos ||
           s.find("page.type: connection closed") != std::string::npos;
}

bool is_bridge_relaunchable_error(const std::string& msg)
{
    std::string s = ascii_lower_copy(msg);
    return is_driver_closed_error(s) ||
           s.find("browser process tree degraded") != std::string::npos ||
           s.find("process tree degraded") != std::string::npos ||
           s.find("navigation_stability_failed") != std::string::npos ||
           s.find("bridge health check failed") != std::string::npos;
}

void disconnect_client_sync(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason);
std::string camoufox_debug_log_path();
nlohmann::json last_camoufox_debug_event_json_from_tail(const std::string& tail);
std::string sidecar_timeout_phase_from_event(const nlohmann::json& event, const std::string& fallback);
void attach_debug_log_snapshot_locked(nlohmann::json& out,
                                      uint32_t child_pid,
                                      const std::string& debug_log,
                                      const std::string& debug_tail);

void disconnect_client_async(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    auto disconnect_task = [cli, reason]() {
        diag::log_tagged_fmt("camoufox", "disconnect_async start reason=%s", reason.c_str());
        cli->disconnect();
        diag::log_tagged_fmt("camoufox", "disconnect_async done reason=%s", reason.c_str());
    };
    if (!post_bridge_task("camoufox.disconnect", disconnect_task)) {
        diag::log_tagged_fmt("camoufox", "disconnect_async_post_failed reason=%s",
            reason.c_str());
        disconnect_client_sync(cli, reason);
    }
}

void disconnect_client_sync(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "disconnect_sync start reason=%s", reason.c_str());
    cli->disconnect();
    diag::log_tagged_fmt("camoufox", "disconnect_sync done reason=%s elapsed_ms=%llu",
        reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
}

void terminate_process_id_sync(uint32_t pid, const std::string& reason, uint32_t parent_pid, const std::string& exe)
{
    if (pid == 0) return;
    const uint64_t t0 = now_ms();
    DWORD before_exit = 0;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        diag::log_tagged_fmt("camoufox", "terminate_process open_failed pid=%lu parent_pid=%lu exe=%s reason=%s gle=%lu",
            static_cast<unsigned long>(pid), static_cast<unsigned long>(parent_pid), exe.c_str(),
            reason.c_str(), static_cast<unsigned long>(GetLastError()));
        return;
    }
    BOOL before_ok = GetExitCodeProcess(h, &before_exit);
    bool already_exited = before_ok && before_exit != STILL_ACTIVE;
    BOOL ok = already_exited ? TRUE : TerminateProcess(h, 1);
    DWORD gle = ok ? 0 : GetLastError();
    DWORD wait_rc = already_exited ? WAIT_OBJECT_0 : WaitForSingleObject(h, 3000);
    DWORD after_exit = 0;
    BOOL after_ok = GetExitCodeProcess(h, &after_exit);
    CloseHandle(h);
    diag::log_tagged_fmt("camoufox", "terminate_process pid=%lu parent_pid=%lu exe=%s reason=%s already_exited=%d before_ok=%d before_exit=%lu ok=%d gle=%lu wait_rc=%lu after_ok=%d after_exit=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(pid), static_cast<unsigned long>(parent_pid), exe.c_str(), reason.c_str(),
        already_exited ? 1 : 0, before_ok ? 1 : 0, static_cast<unsigned long>(before_ok ? before_exit : 0),
        ok ? 1 : 0, static_cast<unsigned long>(gle), static_cast<unsigned long>(wait_rc),
        after_ok ? 1 : 0, static_cast<unsigned long>(after_ok ? after_exit : 0),
        static_cast<unsigned long long>(now_ms() - t0));
}

process_tree_reap_result_t terminate_process_tree_sync(uint32_t root_pid, const std::string& reason)
{
    process_tree_reap_result_t result;
    std::unique_lock<std::recursive_timed_mutex> lifecycle(lifecycle_mtx());
    if (root_pid == 0)
        return result;
    const uint64_t t0 = now_ms();
    std::vector<process_tree_entry_t> tree = enumerate_process_tree(root_pid);
    result.before = tree.size();
    result.descendants_before = tree.size() > 0 ? tree.size() - 1 : 0;
    diag::log_tagged_fmt("camoufox", "process_tree_reap_begin root_pid=%lu reason=%s count=%zu entries=%s",
        static_cast<unsigned long>(root_pid), reason.c_str(), tree.size(), compact_process_tree(tree).c_str());
    for (auto it = tree.rbegin(); it != tree.rend(); ++it)
        terminate_process_id_sync(it->pid, reason, it->parent_pid, it->exe);
    std::vector<process_tree_entry_t> remaining = enumerate_process_tree(root_pid);
    size_t alive_remaining = 0;
    for (const auto& entry : remaining)
    {
        if (process_alive(entry.pid))
            ++alive_remaining;
    }
    result.after = remaining.size();
    result.alive_after = alive_remaining;
    result.elapsed_ms = now_ms() - t0;
    diag::log_tagged_fmt("camoufox", "process_tree_reap_end root_pid=%lu reason=%s before=%zu after=%zu alive_after=%zu entries_after=%s elapsed_ms=%llu",
        static_cast<unsigned long>(root_pid), reason.c_str(), tree.size(), remaining.size(), alive_remaining,
        compact_process_tree(remaining).c_str(), static_cast<unsigned long long>(result.elapsed_ms));
    return result;
}

nlohmann::json cleanup_reap_json(const process_tree_reap_result_t& reap)
{
    return {
        {"before", reap.before},
        {"descendants_before", reap.descendants_before},
        {"after", reap.after},
        {"alive_after", reap.alive_after},
        {"success", reap.alive_after == 0},
        {"elapsed_ms", reap.elapsed_ms}
    };
}

std::string cleanup_status_error_locked(const char* caller)
{
    std::ostringstream oss;
    oss << "camoufox bridge not ready";
    if (caller && caller[0])
        oss << " caller=" << caller;
    oss << " state=" << bridge_state_name(sg().state)
        << " generation=" << sg().generation
        << " child_pid=" << sg().child_pid
        << " cleanup_pending=" << (sg().cleanup_pending ? 1 : 0)
        << " cleanup_generation=" << sg().cleanup_generation
        << " cleanup_child_pid=" << sg().cleanup_child_pid
        << " cleanup_reason=" << (sg().cleanup_reason.empty() ? "<empty>" : sg().cleanup_reason);
    if (!sg().cleanup_diagnostics.is_null() && !sg().cleanup_diagnostics.empty())
        oss << " cleanup_diag=" << compact_child_output_tail(sg().cleanup_diagnostics.dump(), 900);
    return oss.str();
}

void record_cleanup_reap_result(uint64_t generation,
                                const std::string& caller,
                                const std::string& reason,
                                uint32_t child_pid,
                                const process_tree_reap_result_t& reap,
                                uint64_t elapsed_ms,
                                const std::string& stdout_last_frame)
{
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    nlohmann::json diag = sg().cleanup_diagnostics.is_object()
        ? sg().cleanup_diagnostics
        : nlohmann::json::object();
    const std::string debug_tail = read_file_tail_for_log(camoufox_debug_log_path(), 2000);
    diag["caller"] = caller;
    diag["cancellation_source"] = reason;
    diag["readiness_sub_step"] = reason;
    diag["generation"] = generation;
    diag["current_generation"] = sg().generation;
    diag["child_pid"] = child_pid;
    diag["cleanup_pending_after_reap"] = sg().cleanup_pending;
    diag["elapsed_ms"] = elapsed_ms;
    diag["process_reap"] = cleanup_reap_json(reap);
    diag["stdout_last_frame"] = stdout_last_frame.empty() ? std::string("<empty>") : compact_child_output_tail(stdout_last_frame, 1200);
    diag["stderr_last_frame"] = debug_tail;
    diag["stderr_last_frame_len"] = debug_tail.size();
    diag["stop_requested"] = sg().stop_requested.load(std::memory_order_acquire);
    diag["stop_epoch"] = sg().stop_epoch.load(std::memory_order_acquire);
    sg().cleanup_diagnostics = diag;
}

void terminate_process_id_async(uint32_t pid, const std::string& reason)
{
    if (pid == 0) return;
    auto terminate_task = [pid, reason]() {
        terminate_process_tree_sync(pid, reason);
    };
    if (!post_bridge_task("camoufox.terminate", terminate_task)) {
        diag::log_tagged_fmt("camoufox", "terminate_process_post_failed pid=%lu reason=%s",
            static_cast<unsigned long>(pid), reason.c_str());
        terminate_process_tree_sync(pid, reason);
    }
}

void mark_cleanup_started_locked(uint64_t generation, uint32_t child_pid = 0, const std::string& reason = std::string())
{
    const bool cleanup_pending_before = sg().cleanup_pending;
    const uint64_t cleanup_start_ms = now_ms();
    sg().cleanup_pending = true;
    sg().cleanup_generation = generation;
    sg().cleanup_started_ms = cleanup_start_ms;
    sg().cleanup_child_pid = child_pid == 0 ? sg().child_pid : child_pid;
    if (!sg().active_profile_dir.empty() || sg().cleanup_profile_dir.empty())
    {
        sg().cleanup_profile_dir = sg().active_profile_dir;
        sg().cleanup_profile_generated = sg().active_profile_generated;
    }
    sg().cleanup_reason = reason;
    const auto tree = sg().cleanup_child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(sg().cleanup_child_pid);
    const size_t descendant_count = tree.size() > 0 ? tree.size() - 1 : 0;
    const std::string debug_tail = read_file_tail_for_log(camoufox_debug_log_path(), 2000);
    sg().cleanup_diagnostics = {
        {"status", "pending"},
        {"caller", "mark_cleanup_started"},
        {"cancellation_source", reason.empty() ? std::string("<empty>") : reason},
        {"readiness_sub_step", reason.empty() ? std::string("<empty>") : reason},
        {"generation", generation},
        {"current_generation", sg().generation},
        {"child_pid", sg().cleanup_child_pid},
        {"child_processes", tree.size()},
        {"browser_processes", browser_process_count_from_tree(tree)},
        {"process_tree", compact_process_tree(tree)},
        {"cleanup_pending_before", cleanup_pending_before},
        {"cleanup_pending_after", sg().cleanup_pending},
        {"deadline_ms", 0},
        {"elapsed_budget_ms", 0},
        {"stop_requested", sg().stop_requested.load(std::memory_order_acquire)},
        {"stop_epoch", sg().stop_epoch.load(std::memory_order_acquire)},
        {"active_activities", sg().active_activities.load(std::memory_order_acquire)},
        {"stdout_last_frame", "<not captured at cleanup start>"},
        {"stderr_last_frame", debug_tail},
        {"stderr_last_frame_len", debug_tail.size()}
    };
    diag::log_tagged_fmt("camoufox", "cleanup_state_begin generation=%llu child_pid=%lu descendants=%zu profile_dir=%s profile_generated=%d reason=%s state=%d current_generation=%llu pending=%d",
        static_cast<unsigned long long>(generation), static_cast<unsigned long>(sg().cleanup_child_pid),
        descendant_count, sg().cleanup_profile_dir.empty() ? "<empty>" : sg().cleanup_profile_dir.c_str(),
        sg().cleanup_profile_generated ? 1 : 0,
        sg().cleanup_reason.c_str(), static_cast<int>(sg().state),
        static_cast<unsigned long long>(sg().generation), static_cast<int>(sg().cleanup_pending));
}

void mark_cleanup_finished(uint64_t generation, uint64_t elapsed_ms, const std::string& reason, bool reap_complete = true)
{
    std::string cleanup_profile_dir;
    bool should_purge_profile = false;
    std::unique_lock<std::recursive_mutex> lk(sg().mtx);
    const uint64_t age_ms = sg().cleanup_started_ms == 0 ? 0 : now_ms() - sg().cleanup_started_ms;
    const uint32_t cleanup_pid = sg().cleanup_child_pid;
    const std::string cleanup_reason = sg().cleanup_reason;
    cleanup_profile_dir = sg().cleanup_profile_dir;
    const bool cleanup_profile_generated = sg().cleanup_profile_generated;
    nlohmann::json cleanup_diag = sg().cleanup_diagnostics.is_object()
        ? sg().cleanup_diagnostics
        : nlohmann::json::object();
    if (sg().cleanup_generation == generation && reap_complete)
    {
        sg().cleanup_pending = false;
        sg().last_cleanup_ms = elapsed_ms;
        sg().cleanup_started_ms = 0;
        sg().cleanup_child_pid = 0;
        sg().cleanup_profile_dir.clear();
        sg().cleanup_profile_generated = false;
        sg().cleanup_reason.clear();
        if (cleanup_pid != 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == cleanup_pid)
            sg().tracked_child_pid.store(0, std::memory_order_release);
        if (sg().active_profile_dir == cleanup_profile_dir)
        {
            sg().active_profile_dir.clear();
            sg().active_profile_generated = false;
        }
        should_purge_profile = cleanup_profile_generated;
    }
    const std::string debug_tail = read_file_tail_for_log(camoufox_debug_log_path(), 2000);
    cleanup_diag["status"] = sg().cleanup_pending ? "still_pending" : "finished";
    cleanup_diag["caller"] = cleanup_diag.value("caller", std::string("mark_cleanup_finished"));
    cleanup_diag["finish_reason"] = reason;
    cleanup_diag["start_reason"] = cleanup_reason;
    cleanup_diag["generation"] = generation;
    cleanup_diag["current_generation"] = sg().generation;
    cleanup_diag["child_pid"] = cleanup_pid;
    cleanup_diag["elapsed_ms"] = elapsed_ms;
    cleanup_diag["started_age_ms"] = age_ms;
    cleanup_diag["cleanup_pending_after"] = sg().cleanup_pending;
    cleanup_diag["stop_requested"] = sg().stop_requested.load(std::memory_order_acquire);
    cleanup_diag["stop_epoch"] = sg().stop_epoch.load(std::memory_order_acquire);
    cleanup_diag["stderr_last_frame"] = debug_tail;
    cleanup_diag["stderr_last_frame_len"] = debug_tail.size();
    sg().cleanup_diagnostics = cleanup_diag;
    diag::log_tagged_fmt("camoufox", "cleanup_state_done generation=%llu current_generation=%llu pending=%d child_pid=%lu profile_dir=%s profile_generated=%d started_age_ms=%llu start_reason=%s reason=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().cleanup_pending), static_cast<unsigned long>(cleanup_pid),
        cleanup_profile_dir.empty() ? "<empty>" : cleanup_profile_dir.c_str(),
        should_purge_profile ? 1 : 0,
        static_cast<unsigned long long>(age_ms), cleanup_reason.c_str(), reason.c_str(),
        static_cast<unsigned long long>(elapsed_ms));
    lk.unlock();
    if (should_purge_profile && reap_complete)
        purge_generated_profile_dir(cleanup_profile_dir, reason);
}

std::string cleanup_profile_dir_snapshot(uint64_t generation)
{
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    if (sg().cleanup_generation == generation && !sg().cleanup_profile_dir.empty())
        return sg().cleanup_profile_dir;
    return sg().active_profile_dir;
}

void quarantine_client_locked(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    sg().poisoned_clients.push_back(std::move(cli));
    diag::log_tagged_critical_fmt("camoufox", "client_quarantined reason=%s retained=%zu",
        reason.c_str(), sg().poisoned_clients.size());
}

void cleanup_poisoned_client_async(uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    if (child_pid == 0)
    {
        mark_cleanup_finished(generation, 0, reason);
        return;
    }
    auto cleanup_task = [child_pid, reason, generation]() {
        std::unique_lock<std::recursive_timed_mutex> lifecycle(lifecycle_mtx());
        const uint64_t t0 = now_ms();
        const std::string profile_dir = cleanup_profile_dir_snapshot(generation);
        diag::log_tagged_critical_fmt("camoufox", "cleanup_poisoned start generation=%llu reason=%s child_pid=%lu profile_dir=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            profile_dir.empty() ? "<empty>" : profile_dir.c_str());
        const process_tree_reap_result_t reap = terminate_process_tree_sync(child_pid, reason);
        diag::log_tagged_critical_fmt("camoufox", "cleanup_poisoned reap generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            reap.descendants_before, reap.alive_after, reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
        record_cleanup_reap_result(generation, "cleanup_poisoned", reason, child_pid, reap, now_ms() - t0, std::string());
        mark_cleanup_finished(generation, now_ms() - t0, reason, reap.alive_after == 0);
    };
    if (!post_bridge_task("camoufox.cleanup_poisoned", cleanup_task)) {
        diag::log_tagged_fmt("camoufox", "cleanup_poisoned_post_failed generation=%llu reason=%s",
            static_cast<unsigned long long>(generation), reason.c_str());
        cleanup_task();
    }
}

void cleanup_client_async(std::shared_ptr<mcp_client::client_t> cli, uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    if (!cli && child_pid == 0)
    {
        mark_cleanup_finished(generation, 0, reason);
        return;
    }
    auto cleanup_task = [cli, child_pid, reason, generation]() {
        std::unique_lock<std::recursive_timed_mutex> lifecycle(lifecycle_mtx());
        const uint64_t t0 = now_ms();
        const std::string profile_dir = cleanup_profile_dir_snapshot(generation);
        process_tree_reap_result_t reap;
        diag::log_tagged_fmt("camoufox", "cleanup_async start generation=%llu reason=%s child_pid=%lu client=%d profile_dir=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            static_cast<int>(cli != nullptr), profile_dir.empty() ? "<empty>" : profile_dir.c_str());
        if (child_pid != 0)
            reap = terminate_process_tree_sync(child_pid, reason);
        diag::log_tagged_fmt("camoufox", "cleanup_async reap generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d reap_elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            reap.descendants_before, reap.alive_after, child_pid == 0 || reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
        record_cleanup_reap_result(generation, "cleanup_async", reason, child_pid, reap, now_ms() - t0, cli ? cli->last_error() : std::string());
        mark_cleanup_finished(generation, now_ms() - t0, reason, reap.alive_after == 0);
        if (cli)
        {
            disconnect_client_sync(cli, reason);
            diag::log_tagged_fmt("camoufox", "cleanup_async disconnected generation=%llu reason=%s",
                static_cast<unsigned long long>(generation), reason.c_str());
        }
        diag::log_tagged_fmt("camoufox", "cleanup_async done generation=%llu reason=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(),
            static_cast<unsigned long long>(now_ms() - t0));
    };
    if (!post_bridge_task("camoufox.cleanup", cleanup_task)) {
        diag::log_tagged_fmt("camoufox", "cleanup_async_post_failed generation=%llu reason=%s",
            static_cast<unsigned long long>(generation), reason.c_str());
        cleanup_task();
    }
}

bool invalidate_default_ready_bridge_locked(const char* source,
                                            const std::string& reason,
                                            const bridge_health_snapshot_t& health,
                                            std::shared_ptr<mcp_client::client_t>& cleanup_client,
                                            uint32_t& cleanup_child_pid,
                                            uint64_t& cleanup_generation,
                                            std::string& cleanup_reason,
                                            std::string& state_error)
{
    if (sg().state != bridge_state_t::ready)
        return false;
    cleanup_client = sg().client;
    cleanup_child_pid = sg().child_pid != 0 ? sg().child_pid : health.child_pid;
    cleanup_generation = sg().generation;
    cleanup_reason = std::string("health_") + safe_reason(source);
    state_error = std::string("camoufox bridge health check failed during ") + safe_reason(source) + ": " + reason;
    const uint64_t stale_generation = cleanup_generation;
    const uint64_t current_generation = ++sg().generation;
    sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel);
    sg().stop_requested.store(true, std::memory_order_release);
    sg().client.reset();
    sg().state = bridge_state_t::error;
    sg().last_error = state_error;
    clear_page_state_locked();
    mark_cleanup_started_locked(cleanup_generation, cleanup_child_pid, cleanup_reason);
    sg().child_pid = 0;
    sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    diag::log_tagged_critical_fmt("camoufox",
        "bridge_health_invalidated source=%s reason=%s stale_generation=%llu current_generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u active_activities=%lu process_tree=%s",
        safe_reason(source), reason.c_str(), static_cast<unsigned long long>(stale_generation),
        static_cast<unsigned long long>(current_generation),
        static_cast<unsigned long>(cleanup_child_pid), health.child_alive ? 1 : 0,
        health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(health.exit_code_valid ? health.exit_code : 0),
        static_cast<unsigned long>(health.exit_query_gle),
        static_cast<unsigned>(health.child_process_count), static_cast<unsigned>(health.browser_process_count),
        static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
        health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
    return true;
}

void finish_default_ready_bridge_invalidation(std::shared_ptr<mcp_client::client_t> cleanup_client,
                                              uint32_t cleanup_child_pid,
                                              uint64_t cleanup_generation,
                                              const std::string& cleanup_reason,
                                              const std::string& state_error)
{
    if (cleanup_generation != 0)
        cleanup_client_async(cleanup_client, cleanup_child_pid, cleanup_reason, cleanup_generation);
    if (!state_error.empty())
        publish_state(bridge_state_t::error, state_error);
}

bool verify_default_navigation_stability(const char* source,
                                         uint64_t request_id,
                                         const url_log_t& requested_url,
                                         uint64_t expected_generation,
                                         uint32_t expected_child_pid,
                                         uint64_t operation_start_ms,
                                         call_result_t& failure,
                                         const std::string& entry_process_tree = std::string())
{
    const uint64_t t0 = now_ms();
    uint64_t last_log_ms = 0;
    bridge_health_snapshot_t last_health;
    const uint64_t stability_budget = stability_budget_for_url(requested_url);
    for (;;)
    {
        bridge_state_t state = bridge_state_t::stopped;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        bool has_client = false;
        bool browser_open = false;
        bool page_verified = false;
        bool privacy_verified = false;
        bool cleanup_pending = false;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            state = sg().state;
            generation = sg().generation;
            child_pid = sg().child_pid;
            has_client = sg().client != nullptr;
            browser_open = sg().browser_open;
            page_verified = sg().page_verified;
            privacy_verified = sg().privacy_verified;
            cleanup_pending = sg().cleanup_pending;
        }

        const uint32_t health_pid = child_pid != 0 ? child_pid : expected_child_pid;
        last_health = sample_bridge_health(health_pid, true);
        std::string reason;
        if (expected_generation == 0)
            reason = "missing expected generation";
        else if (expected_child_pid == 0)
            reason = "missing expected child pid";
        else if (state != bridge_state_t::ready)
            reason = std::string("bridge state is ") + bridge_state_name(state);
        else if (generation != expected_generation)
            reason = "bridge generation changed";
        else if (child_pid != expected_child_pid)
            reason = "bridge child pid changed";
        else if (!has_client)
            reason = "mcp client is detached";
        else if (!browser_open)
            reason = "browser is not open";
        else if (!page_verified)
            reason = "page is not verified";
        else if (!privacy_verified)
            reason = "privacy is not verified";
        else if (cleanup_pending)
            reason = "cleanup is pending";
        else if (!last_health.child_alive)
            reason = "sidecar process exited";
        else if (!usable_browser_process_count(last_health.browser_process_count))
            reason = "browser process tree empty";

        if (!reason.empty())
        {
            std::shared_ptr<mcp_client::client_t> cleanup_client;
            uint32_t cleanup_child_pid = 0;
            uint64_t cleanup_generation = 0;
            std::string cleanup_reason;
            std::string state_error = std::string("camoufox navigation stability check failed: ") + reason;
            bool invalidated = false;
            {
                std::lock_guard<std::recursive_mutex> lk(sg().mtx);
                if (sg().state == bridge_state_t::ready && sg().generation == expected_generation)
                {
                    invalidated = invalidate_default_ready_bridge_locked(
                        source,
                        reason,
                        last_health,
                        cleanup_client,
                        cleanup_child_pid,
                        cleanup_generation,
                        cleanup_reason,
                        state_error);
                    sg().last_nav_ms = now_ms() - operation_start_ms;
                }
            }
            const std::vector<process_tree_entry_t> health_tree_entries = (health_pid == 0) ? std::vector<process_tree_entry_t>() : enumerate_process_tree(health_pid);
            const std::string tree_with_exit = compact_process_tree_with_exit(health_tree_entries);
            const std::string tree_delta = compact_process_tree_delta(entry_process_tree, health_tree_entries);
            const std::string debug_log = camoufox_debug_log_path();
            const uint64_t debug_size = file_size_for_log(debug_log);
            const std::string debug_tail = read_file_tail_for_log(debug_log, 6000);
            const uint64_t debug_tail_offset = debug_size > debug_tail.size() ? debug_size - debug_tail.size() : 0;
            const size_t marker_page_crashed = text_marker_count(debug_tail, "\"event\":\"page_crashed\"");
            const size_t marker_page_closed = text_marker_count(debug_tail, "\"event\":\"page_closed\"");
            const size_t marker_browser_disconnected = text_marker_count(debug_tail, "\"event\":\"browser_disconnected\"");
            failure.ok = false;
            failure.error = state_error;
            failure.data = {
                {"status", "error"},
                {"phase", "post_navigation_stability"},
                {"source", safe_reason(source)},
                {"reason", reason},
                {"request_id", request_id},
                {"generation", generation},
                {"expected_generation", expected_generation},
                {"child_pid", child_pid},
                {"expected_child_pid", expected_child_pid},
                {"health_child_pid", last_health.child_pid},
                {"child_alive", last_health.child_alive},
                {"child_processes", last_health.child_process_count},
                {"browser_processes", last_health.browser_process_count},
                {"min_browser_processes", kMinReadyBrowserProcessCount},
                {"process_tree", last_health.process_tree},
                {"entry_process_tree", entry_process_tree},
                {"process_tree_with_exit", tree_with_exit},
                {"process_tree_delta", tree_delta},
                {"debug_log", debug_log},
                {"debug_log_size", debug_size},
                {"debug_tail_offset", debug_tail_offset},
                {"debug_tail_len", debug_tail.size()},
                {"debug_marker_page_crashed", marker_page_crashed},
                {"debug_marker_page_closed", marker_page_closed},
                {"debug_marker_browser_disconnected", marker_browser_disconnected},
                {"host", requested_url.host},
                {"path", requested_url.path},
                {"query", requested_url.has_query},
                {"url_len", requested_url.length},
                {"stability_elapsed_ms", now_ms() - t0},
                {"stability_budget_ms", stability_budget},
                {"operation_elapsed_ms", now_ms() - operation_start_ms},
                {"invalidated", invalidated}
            };
            diag::log_tagged_critical_fmt("camoufox",
                "navigation_stability_failed source=%s request_id=%llu reason=%s invalidated=%d expected_generation=%llu generation=%llu expected_child_pid=%lu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u host=%s path=%s query=%d url_len=%zu stability_elapsed_ms=%llu stability_budget_ms=%llu operation_elapsed_ms=%llu debug_offset=%llu debug_tail_len=%zu page_crashed=%zu page_closed=%zu browser_disconnected=%zu process_tree=%s process_tree_exit=%s process_tree_delta=%s",
                safe_reason(source), static_cast<unsigned long long>(request_id), reason.c_str(), invalidated ? 1 : 0,
                static_cast<unsigned long long>(expected_generation), static_cast<unsigned long long>(generation),
                static_cast<unsigned long>(expected_child_pid), static_cast<unsigned long>(child_pid),
                last_health.child_alive ? 1 : 0, static_cast<unsigned>(last_health.child_process_count),
                static_cast<unsigned>(last_health.browser_process_count), requested_url.host.c_str(), requested_url.path.c_str(),
                requested_url.has_query ? 1 : 0, requested_url.length,
                static_cast<unsigned long long>(now_ms() - t0),
                static_cast<unsigned long long>(stability_budget),
                static_cast<unsigned long long>(now_ms() - operation_start_ms),
                static_cast<unsigned long long>(debug_tail_offset),
                debug_tail.size(),
                marker_page_crashed,
                marker_page_closed,
                marker_browser_disconnected,
                last_health.process_tree.empty() ? "<empty>" : last_health.process_tree.c_str(),
                tree_with_exit.empty() ? "<empty>" : tree_with_exit.c_str(),
                tree_delta.empty() ? "<empty>" : tree_delta.c_str());
            if (invalidated)
                finish_default_ready_bridge_invalidation(cleanup_client, cleanup_child_pid, cleanup_generation, cleanup_reason, state_error);
            return false;
        }
        if (reduced_browser_process_tree(last_health.browser_process_count))
        {
            diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=%s phase=navigation_stability request_id=%llu expected_generation=%llu generation=%llu expected_child_pid=%lu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u has_client=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
                safe_reason(source),
                static_cast<unsigned long long>(request_id),
                static_cast<unsigned long long>(expected_generation),
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long>(expected_child_pid),
                static_cast<unsigned long>(child_pid),
                last_health.child_alive ? 1 : 0,
                static_cast<unsigned>(last_health.child_process_count),
                static_cast<unsigned>(last_health.browser_process_count),
                static_cast<unsigned>(kMinReadyBrowserProcessCount),
                has_client ? 1 : 0,
                browser_open ? 1 : 0,
                page_verified ? 1 : 0,
                privacy_verified ? 1 : 0,
                cleanup_pending ? 1 : 0,
                last_health.process_tree.empty() ? "<empty>" : last_health.process_tree.c_str());
        }

        const uint64_t now = now_ms();
        if (now - t0 >= stability_budget)
        {
            diag::log_tagged_fmt("camoufox",
                "navigation_stability_ok source=%s request_id=%llu generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u host=%s path=%s query=%d url_len=%zu stability_elapsed_ms=%llu stability_budget_ms=%llu operation_elapsed_ms=%llu process_tree=%s",
                safe_reason(source), static_cast<unsigned long long>(request_id),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                last_health.child_alive ? 1 : 0, static_cast<unsigned>(last_health.child_process_count),
                static_cast<unsigned>(last_health.browser_process_count), requested_url.host.c_str(), requested_url.path.c_str(),
                requested_url.has_query ? 1 : 0, requested_url.length,
                static_cast<unsigned long long>(now - t0),
                static_cast<unsigned long long>(stability_budget),
                static_cast<unsigned long long>(now - operation_start_ms),
                last_health.process_tree.empty() ? "<empty>" : last_health.process_tree.c_str());
            return true;
        }
        if (now - last_log_ms >= 1000)
        {
            diag::log_tagged_fmt("camoufox",
                "navigation_stability_wait source=%s request_id=%llu generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u elapsed_ms=%llu process_tree=%s",
                safe_reason(source), static_cast<unsigned long long>(request_id),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                last_health.child_alive ? 1 : 0, static_cast<unsigned>(last_health.child_process_count),
                static_cast<unsigned>(last_health.browser_process_count),
                static_cast<unsigned long long>(now - t0),
                last_health.process_tree.empty() ? "<empty>" : last_health.process_tree.c_str());
            last_log_ms = now;
        }
        const uint64_t elapsed = now - t0;
        const uint64_t remaining = elapsed >= stability_budget ? 0 : stability_budget - elapsed;
        Sleep(static_cast<DWORD>((std::min)(kPostNavigationStabilityPollMs, remaining)));
    }
}

process_tree_reap_result_t cleanup_client_reap_now_detach_disconnect(std::shared_ptr<mcp_client::client_t> cli, uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_begin generation=%llu reason=%s child_pid=%lu client=%d",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        static_cast<int>(cli != nullptr));
    process_tree_reap_result_t reap;
    if (child_pid != 0)
        reap = terminate_process_tree_sync(child_pid, reason);
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_result generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d reap_elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        reap.descendants_before, reap.alive_after, child_pid == 0 || reap.alive_after == 0 ? 1 : 0,
        static_cast<unsigned long long>(reap.elapsed_ms));
    record_cleanup_reap_result(generation, "cleanup_sync_reap", reason, child_pid, reap, now_ms() - t0, cli ? cli->last_error() : std::string());
    mark_cleanup_finished(generation, now_ms() - t0, reason, child_pid == 0 || reap.alive_after == 0);
    if (cli)
        disconnect_client_async(cli, reason + ":post_reap_disconnect");
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_end generation=%llu reason=%s child_pid=%lu client_detached=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        static_cast<int>(cli != nullptr), static_cast<unsigned long long>(now_ms() - t0));
    return reap;
}

bool parse_text_to_json(const std::string& text, nlohmann::json& out)
{
    if (text.empty())
    {
        out = nlohmann::json::object();
        return true;
    }
    try
    {
        out = nlohmann::json::parse(text);
        return true;
    }
    catch (...)
    {
        out = nlohmann::json::object();
        out["raw_text"] = text;
        return false;
    }
}

bool parse_json_text_relaxed(const std::string& text, nlohmann::json& out)
{
    if (text.empty())
        return false;
    try
    {
        out = nlohmann::json::parse(text);
        return true;
    }
    catch (...) {}
    size_t first = std::string::npos;
    const size_t arr = text.find('[');
    const size_t obj = text.find('{');
    if (arr != std::string::npos && obj != std::string::npos)
        first = std::min(arr, obj);
    else if (arr != std::string::npos)
        first = arr;
    else
        first = obj;
    if (first == std::string::npos)
        return false;
    const char close_ch = text[first] == '[' ? ']' : '}';
    const size_t last = text.rfind(close_ch);
    if (last == std::string::npos || last <= first)
        return false;
    try
    {
        out = nlohmann::json::parse(text.substr(first, last - first + 1));
        return true;
    }
    catch (...) {}
    return false;
}

nlohmann::json normalize_console_log_data(const nlohmann::json& data)
{
    if (data.is_array())
        return data;
    if (data.is_string())
    {
        const std::string text = data.get<std::string>();
        nlohmann::json parsed;
        if (parse_json_text_relaxed(text, parsed))
            return normalize_console_log_data(parsed);
        nlohmann::json entry = nlohmann::json::object();
        entry["text"] = text;
        return nlohmann::json::array({entry});
    }
    if (data.is_object())
    {
        if (data.contains("text") && data["text"].is_string())
            return nlohmann::json::array({data});
        const char* keys[] = { "value", "result", "logs", "records", "items" };
        for (const char* key : keys)
        {
            if (!data.contains(key))
                continue;
            nlohmann::json nested = normalize_console_log_data(data[key]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("raw_text") && data["raw_text"].is_string())
        {
            const std::string text = data["raw_text"].get<std::string>();
            nlohmann::json parsed;
            if (parse_json_text_relaxed(text, parsed))
                return normalize_console_log_data(parsed);
            nlohmann::json entry = nlohmann::json::object();
            entry["text"] = text;
            return nlohmann::json::array({entry});
        }
    }
    return nlohmann::json::array();
}

std::string hex_u64(ULONG_PTR value)
{
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return std::string(buf);
}

struct guarded_mcp_call_context_t
{
    mcp_client::client_t* client = nullptr;
    const std::string* tool_name = nullptr;
    const nlohmann::json* args = nullptr;
    mcp_client::call_result_t* result = nullptr;
    char error[1024] = {};
    DWORD status = ERROR_SUCCESS;
    bool native_exception = false;
    bool cpp_exception = false;
    DWORD exception_code = ERROR_SUCCESS;
    void* exception_address = nullptr;
    DWORD exception_info_count = 0;
    ULONG_PTR exception_info[4] = {};
};

__declspec(noinline) DWORD guarded_mcp_call_cpp(guarded_mcp_call_context_t* ctx)
{
    if (!ctx || !ctx->client || !ctx->tool_name || !ctx->args || !ctx->result)
    {
        if (ctx)
        {
            ctx->status = ERROR_INVALID_PARAMETER;
            std::snprintf(ctx->error, sizeof(ctx->error), "invalid guarded MCP call context");
        }
        return ERROR_INVALID_PARAMETER;
    }

    try
    {
        *ctx->result = ctx->client->call_tool(*ctx->tool_name, *ctx->args);
        ctx->status = ERROR_SUCCESS;
        return ERROR_SUCCESS;
    }
    catch (const std::exception& ex)
    {
        ctx->cpp_exception = true;
        ctx->status = 0xE06D7363u;
        std::snprintf(ctx->error, sizeof(ctx->error), "C++ exception in MCP call_tool(%s): %.820s",
            ctx->tool_name->c_str(), ex.what());
        return ctx->status;
    }
    catch (...)
    {
        ctx->cpp_exception = true;
        ctx->status = 0xE06D7363u;
        std::snprintf(ctx->error, sizeof(ctx->error), "unknown C++ exception in MCP call_tool(%s)",
            ctx->tool_name->c_str());
        return ctx->status;
    }
}

LONG guarded_mcp_call_seh_filter(EXCEPTION_POINTERS* ep, guarded_mcp_call_context_t* ctx)
{
    if (ctx)
    {
        ctx->native_exception = true;
        ctx->status = 0xC0000005u;
        if (ep && ep->ExceptionRecord)
        {
            EXCEPTION_RECORD* rec = ep->ExceptionRecord;
            ctx->exception_code = rec->ExceptionCode;
            ctx->status = rec->ExceptionCode;
            ctx->exception_address = rec->ExceptionAddress;
            ctx->exception_info_count = static_cast<DWORD>(rec->NumberParameters > 4 ? 4 : rec->NumberParameters);
            for (DWORD i = 0; i < ctx->exception_info_count; ++i)
                ctx->exception_info[i] = rec->ExceptionInformation[i];
        }
        const char* tool = ctx->tool_name ? ctx->tool_name->c_str() : "<null>";
        std::snprintf(ctx->error, sizeof(ctx->error),
            "native exception in MCP call_tool(%s): code=0x%08lX addr=%p info_count=%lu info0=%s info1=%s",
            tool,
            static_cast<unsigned long>(ctx->exception_code ? ctx->exception_code : ctx->status),
            ctx->exception_address,
            static_cast<unsigned long>(ctx->exception_info_count),
            hex_u64(ctx->exception_info[0]).c_str(),
            hex_u64(ctx->exception_info[1]).c_str());
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(noinline) DWORD guarded_mcp_call(guarded_mcp_call_context_t* ctx)
{
    __try
    {
        return guarded_mcp_call_cpp(ctx);
    }
    __except (guarded_mcp_call_seh_filter(GetExceptionInformation(), ctx))
    {
        return ctx ? ctx->status : 0xC0000005u;
    }
}

mcp_client::call_result_t guarded_mcp_failure_result(const std::string& tool_name, const guarded_mcp_call_context_t& ctx, DWORD status)
{
    std::string message = ctx.error[0] ? std::string(ctx.error) : std::string("MCP call_tool failed under guard");
    nlohmann::json data = nlohmann::json::object();
    data["error"] = message;
    data["tool"] = tool_name;
    data["guard_status"] = static_cast<uint32_t>(status);
    data["native_exception"] = ctx.native_exception;
    data["cpp_exception"] = ctx.cpp_exception;
    if (ctx.native_exception)
    {
        data["exception_code"] = static_cast<uint32_t>(ctx.exception_code);
        data["exception_address"] = hex_u64(reinterpret_cast<ULONG_PTR>(ctx.exception_address));
        data["exception_info_count"] = static_cast<uint32_t>(ctx.exception_info_count);
        data["exception_info0"] = hex_u64(ctx.exception_info[0]);
        data["exception_info1"] = hex_u64(ctx.exception_info[1]);
    }
    return mcp_client::call_result_t{false, message, data};
}

bool data_has_native_exception(const nlohmann::json& data)
{
    try
    {
        return data.is_object() && data.contains("native_exception") && data["native_exception"].is_boolean() && data["native_exception"].get<bool>();
    }
    catch (...) {}
    return false;
}

bool result_has_native_exception(const mcp_client::call_result_t& r)
{
    return data_has_native_exception(r.data);
}

bool result_has_native_exception(const call_result_t& r)
{
    return data_has_native_exception(r.data);
}

bool bridge_payload_reports_semantic_failure(const nlohmann::json& data, std::string& reason)
{
    reason.clear();
    if (!data.is_object())
        return false;
    auto err = data.find("error");
    if (err != data.end() && err->is_string() && !err->get<std::string>().empty())
    {
        reason = err->get<std::string>();
        return true;
    }
    auto success = data.find("success");
    if (success != data.end() && success->is_boolean() && !success->get<bool>())
    {
        reason = "payload_success_false";
        return true;
    }
    auto ok = data.find("ok");
    if (ok != data.end() && ok->is_boolean() && !ok->get<bool>())
    {
        reason = "payload_ok_false";
        return true;
    }
    std::string status;
    auto status_it = data.find("status");
    if (status_it != data.end() && status_it->is_string())
        status = status_it->get<std::string>();
    std::string lowered = status;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "failed" || lowered == "error" || lowered == "timeout" || lowered == "cancelled")
    {
        reason = std::string("payload_status_") + lowered;
        return true;
    }
    return false;
}

call_result_t to_bridge_result(const mcp_client::call_result_t& r)
{
    call_result_t out;
    out.ok   = r.success;
    out.text = r.text;
    if (!r.data.is_null())
    {
        out.data = r.data;
    }
    else
    {
        nlohmann::json parsed;
        parse_text_to_json(r.text, parsed);
        out.data = std::move(parsed);
    }
    if (!r.success)
    {
        out.error = r.text;
        if (out.error.empty())
            out.error = "Camoufox reverse MCP call failed without an error message";
    }
    else
    {
        std::string semantic_reason;
        if (bridge_payload_reports_semantic_failure(out.data, semantic_reason))
        {
            out.ok = false;
            out.error = semantic_reason.empty() ? std::string("Camoufox reverse MCP payload reports failure") : semantic_reason;
        }
    }
    diag::log_tagged_fmt("camoufox", "mcp_result_shape success=%d text_len=%zu data_shape=%s error_len=%zu",
        static_cast<int>(r.success), r.text.size(), json_shape(out.data).c_str(), out.error.size());
    return out;
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, uint64_t request_id = 0);
void stamp_aida_operation_id(nlohmann::json& args, const std::string& tool_name, uint64_t request_id);
void update_page_cache_from_json_locked(const nlohmann::json& data, const char* source);

std::string evaluate_result_error(const call_result_t& r)
{
    if (!r.error.empty()) return r.error;
    try
    {
        if (r.data.is_object())
        {
            auto err = r.data.find("error");
            if (err != r.data.end() && err->is_string()) return err->get<std::string>();
            auto value = r.data.find("value");
            if (value != r.data.end() && value->is_object())
            {
                auto value_err = value->find("error");
                if (value_err != value->end() && value_err->is_string()) return value_err->get<std::string>();
            }
        }
    }
    catch (...) {}
    return {};
}

int clamp_direct_action_call_timeout_ms(int requested_ms, int fallback_ms)
{
    int out = requested_ms > 0 ? requested_ms : fallback_ms;
    if (out < 1500) out = 1500;
    if (out > 15000) out = 15000;
    return out;
}

nlohmann::json direct_action_payload(const call_result_t& r)
{
    if (r.data.is_object())
    {
        auto value = r.data.find("value");
        if (value != r.data.end() && !value->is_null())
            return *value;
    }
    return r.data;
}

std::string direct_action_error(const call_result_t& r)
{
    std::string err = evaluate_result_error(r);
    if (!err.empty()) return err;
    nlohmann::json payload = direct_action_payload(r);
    try
    {
        if (payload.is_object())
        {
            auto payload_err = payload.find("error");
            if (payload_err != payload.end() && payload_err->is_string())
                return payload_err->get<std::string>();
        }
    }
    catch (...) {}
    return {};
}

call_result_t direct_action_fail(const char* action, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, uint64_t start_ms, const std::string& phase, const std::string& error)
{
    call_result_t out;
    out.ok = false;
    out.error = error.empty() ? std::string(action) + " failed" : error;
    out.data = nlohmann::json::object();
    out.data["status"] = "failed";
    out.data["action"] = action;
    out.data["request_id"] = request_id;
    out.data["phase"] = phase;
    out.data["elapsed_ms"] = now_ms() - start_ms;
    out.data["selector"] = selector;
    out.data["text_length"] = text_len;
    out.data["error"] = out.error;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_call_ms = now_ms();
        set_error_locked(std::string(action) + " failed: " + out.error);
    }
    sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    bridge_call_completed_t ev{action, false, now_ms() - start_ms};
    aida::events::publish(kBridgeCallCompleted, ev);
    log_action_phase(action, "exit", request_id, selector, timeout_ms, text_len, action_snapshot(), ev.duration_ms, phase.c_str());
    return out;
}

call_result_t direct_action_ok(const char* action, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, uint64_t start_ms, nlohmann::json payload)
{
    call_result_t out;
    out.ok = true;
    if (!payload.is_object())
    {
        nlohmann::json wrapped;
        wrapped["value"] = payload;
        payload = std::move(wrapped);
    }
    auto status_it = payload.find("status");
    if (status_it == payload.end())
        payload["status"] = "ok";
    payload["action"] = action;
    payload["request_id"] = request_id;
    payload["elapsed_ms"] = now_ms() - start_ms;
    payload["selector"] = selector;
    payload["text_length"] = text_len;
    out.data = std::move(payload);
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_call_ms = now_ms();
        clear_error_locked();
    }
    bridge_call_completed_t ev{action, true, now_ms() - start_ms};
    aida::events::publish(kBridgeCallCompleted, ev);
    log_action_phase(action, "exit", request_id, selector, timeout_ms, text_len, action_snapshot(), ev.duration_ms);
    return out;
}

call_result_t dispatch_dom_click_action(const std::string& selector, int timeout_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    log_action_phase("click", "entry", request_id, selector, timeout_ms, 0, action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("click", request_id, selector, timeout_ms, 0, start_ms, "validate_selector", "click: selector is empty");

    const std::string quoted = nlohmann::json(selector).dump();
    std::string expr;
    expr.reserve(quoted.size() + 2600);
    expr += "(()=>{";
    expr += "const selector=" + quoted + ";";
    expr += "const normalized=String(selector).trim().toLowerCase();";
    expr += "const directDocument=normalized==='document'||normalized==='document.body'||normalized==='body'||normalized==='html'||normalized===':root';";
    expr += "let el=null;try{el=directDocument?(document.body||document.documentElement):document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
    expr += "if(!el)return {error:'Element not found: '+selector};";
    expr += "const target=el===document?document.body||document.documentElement:el;";
    expr += "if(!target)return {error:'No clickable target: '+selector};";
    expr += "let rect={left:0,top:0,width:1,height:1};";
    expr += "try{if(target.getBoundingClientRect)rect=target.getBoundingClientRect();}catch(e){}";
    expr += "const vw=window.innerWidth||document.documentElement.clientWidth||1;";
    expr += "const vh=window.innerHeight||document.documentElement.clientHeight||1;";
    expr += "let x=rect.left+(rect.width>0?rect.width/2:1);";
    expr += "let y=rect.top+(rect.height>0?rect.height/2:1);";
    expr += "x=Math.max(0,Math.min(vw-1,Math.round(x)));";
    expr += "y=Math.max(0,Math.min(vh-1,Math.round(y)));";
    expr += "if(target.scrollIntoView)try{target.scrollIntoView({block:'center',inline:'center',behavior:'instant'});}catch(e){}";
    expr += "const init={bubbles:true,cancelable:true,composed:true,view:window,button:0,buttons:1,clientX:x,clientY:y,screenX:x,screenY:y};";
    expr += "function fire(type){let ev=null;try{ev=type.indexOf('pointer')===0&&window.PointerEvent?new PointerEvent(type,Object.assign({pointerId:1,pointerType:'mouse',isPrimary:true},init)):new MouseEvent(type,init);}catch(e){ev=document.createEvent('MouseEvents');ev.initMouseEvent(type,true,true,window,1,x,y,x,y,false,false,false,false,0,null);}target.dispatchEvent(ev);}";
    expr += "try{if(target.focus)target.focus({preventScroll:true});}catch(e){}";
    expr += "fire('pointerover');fire('mouseover');fire('pointermove');fire('mousemove');fire('pointerdown');fire('mousedown');fire('pointerup');fire('mouseup');";
    expr += "if(typeof target.click==='function')target.click();else fire('click');";
    expr += "return {status:'clicked',selector:selector,mode:'dom_dispatch',x:x,y:y};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    const int call_timeout = clamp_direct_action_call_timeout_ms(timeout_ms, 5000);
    log_action_phase("click", "dispatch", request_id, selector, call_timeout, 0, action_snapshot(), now_ms() - start_ms);
    call_result_t r = call_with_deadline("evaluate_js", args, call_timeout, request_id);
    std::string err = direct_action_error(r);
    if (!r.ok || !err.empty())
    {
        if (err.empty()) err = "DOM click dispatch failed";
        diag::log_tagged_fmt("camoufox", "dispatch_dom_click failed request_id=%llu selector=%s ok=%d err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str());
        return direct_action_fail("click", request_id, selector, call_timeout, 0, start_ms, "evaluate_js", err);
    }
    diag::log_tagged_fmt("camoufox", "dispatch_dom_click ok request_id=%llu selector=%s",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return direct_action_ok("click", request_id, selector, call_timeout, 0, start_ms, direct_action_payload(r));
}

call_result_t dispatch_dom_type_text_action(const std::string& selector, const std::string& text, int timeout_ms, int delay_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    log_action_phase("type_text", "entry", request_id, selector, timeout_ms, text.size(), action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("type_text", request_id, selector, timeout_ms, text.size(), start_ms, "validate_selector", "type_text: selector is empty");

    const std::string quoted_selector = nlohmann::json(selector).dump();
    const std::string quoted_text = nlohmann::json(text).dump();
    std::string expr;
    expr.reserve(quoted_selector.size() + quoted_text.size() + 2600);
    expr += "(()=>{";
    expr += "const selector=" + quoted_selector + ";";
    expr += "const text=" + quoted_text + ";";
    expr += "let el=null;try{el=document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
    expr += "if(!el)return {error:'Element not found: '+selector};";
    expr += "const tag=String(el.tagName||'').toLowerCase();";
    expr += "const editable=!!el.isContentEditable||tag==='input'||tag==='textarea';";
    expr += "if(!editable)return {error:'Element is not editable: '+selector};";
    expr += "try{if(el.scrollIntoView)el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});}catch(e){}";
    expr += "try{if(el.focus)el.focus({preventScroll:true});}catch(e){}";
    expr += "function fire(type,extra){let ev=null;try{ev=type==='input'||type==='beforeinput'?new InputEvent(type,Object.assign({bubbles:true,cancelable:true,composed:true,data:text,inputType:'insertText'},extra||{})):new Event(type,{bubbles:true,cancelable:true,composed:true});}catch(e){ev=document.createEvent('Event');ev.initEvent(type,true,true);}el.dispatchEvent(ev);}";
    expr += "fire('beforeinput');";
    expr += "try{if(el.isContentEditable){el.textContent=text;}else{const proto=tag==='textarea'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;const desc=Object.getOwnPropertyDescriptor(proto,'value');if(desc&&desc.set)desc.set.call(el,text);else el.value=text;}}catch(e){return {error:'Element value set failed: '+selector};}";
    expr += "fire('input');fire('change');";
    expr += "return {status:'typed',selector:selector,mode:'dom_value',value_length:String(text).length,delay_ms:" + std::to_string(delay_ms < 0 ? 0 : delay_ms) + "};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    const int call_timeout = clamp_direct_action_call_timeout_ms(timeout_ms, 5000);
    log_action_phase("type_text", "dispatch", request_id, selector, call_timeout, text.size(), action_snapshot(), now_ms() - start_ms);
    call_result_t r = call_with_deadline("evaluate_js", args, call_timeout, request_id);
    std::string err = direct_action_error(r);
    if (!r.ok || !err.empty())
    {
        if (err.empty()) err = "DOM type_text dispatch failed";
        diag::log_tagged_fmt("camoufox", "dispatch_dom_type_text failed request_id=%llu selector=%s ok=%d err=%s text_len=%zu",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str(), text.size());
        return direct_action_fail("type_text", request_id, selector, call_timeout, text.size(), start_ms, "evaluate_js", err);
    }
    diag::log_tagged_fmt("camoufox", "dispatch_dom_type_text ok request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    return direct_action_ok("type_text", request_id, selector, call_timeout, text.size(), start_ms, direct_action_payload(r));
}

bool payload_bool_or(const nlohmann::json& payload, const char* key, bool fallback)
{
    if (!payload.is_object()) return fallback;
    auto it = payload.find(key);
    if (it == payload.end() || !it->is_boolean()) return fallback;
    return it->get<bool>();
}

call_result_t dispatch_dom_wait_for_selector_action(const std::string& selector, int timeout_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    int effective_timeout = timeout_ms > 0 ? timeout_ms : 5000;
    if (effective_timeout < 250) effective_timeout = 250;
    if (effective_timeout > 30000) effective_timeout = 30000;
    log_action_phase("wait_for", "entry", request_id, selector, effective_timeout, 0, action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "validate_selector", "wait_for: selector is empty");

    const std::string quoted_selector = nlohmann::json(selector).dump();
    std::string expr;
    expr.reserve(quoted_selector.size() + 1200);
    expr += "(()=>{";
    expr += "const selector=" + quoted_selector + ";";
    expr += "let el=null;try{el=document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
    expr += "if(!el)return {status:'waiting',found:false,selector:selector};";
    expr += "let visible=true;try{const style=getComputedStyle(el);const rect=el.getBoundingClientRect();visible=style.visibility!=='hidden'&&style.display!=='none'&&rect.width>=0&&rect.height>=0;}catch(e){}";
    expr += "return {status:'found',found:true,visible:visible,selector:selector};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    size_t attempts = 0;
    while (now_ms() - start_ms <= static_cast<uint64_t>(effective_timeout))
    {
        ++attempts;
        if (sg().stop_requested.load(std::memory_order_acquire))
            return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "cancel", "wait_for cancelled by stop request");
        const int eval_timeout = clamp_direct_action_call_timeout_ms(effective_timeout, 2000);
        log_action_phase("wait_for", "poll", request_id, selector, effective_timeout, 0, action_snapshot(), now_ms() - start_ms);
        call_result_t r = call_with_deadline("evaluate_js", args, eval_timeout, request_id);
        std::string err = direct_action_error(r);
        if (!r.ok || !err.empty())
        {
            if (err.empty()) err = "DOM wait_for poll failed";
            diag::log_tagged_fmt("camoufox", "dispatch_dom_wait_for failed request_id=%llu selector=%s ok=%d err=%s attempts=%zu",
                static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str(), attempts);
            return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "evaluate_js", err);
        }
        nlohmann::json payload = direct_action_payload(r);
        if (payload_bool_or(payload, "found", false))
        {
            payload["attempts"] = attempts;
            diag::log_tagged_fmt("camoufox", "dispatch_dom_wait_for ok request_id=%llu selector=%s attempts=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), attempts,
                static_cast<unsigned long long>(now_ms() - start_ms));
            return direct_action_ok("wait_for", request_id, selector, effective_timeout, 0, start_ms, std::move(payload));
        }
        Sleep(50);
    }
    return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "selector_timeout", "wait_for timed out before selector appeared");
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, uint64_t request_id)
{
    call_result_t fail;
    fail.ok = false;
    if (request_id == 0)
        request_id = next_request_id();
    nlohmann::json call_args = args.is_null() ? nlohmann::json::object() : args;
    stamp_aida_operation_id(call_args, tool_name, request_id);

    std::shared_ptr<mcp_client::client_t> cli;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        if (sg().state == bridge_state_t::ready && sg().client)
        {
            cli = sg().client;
        }
    }

    if (!cli)
    {
        bridge_state_t old_state = bridge_state_t::stopped;
        bool had_client = false;
        std::string old_error;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            old_state = sg().state;
            had_client = sg().client != nullptr;
            old_error = sg().last_error;
        }
        diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovering request_id=%llu tool=%s state=%d client=%d old_err_len=%zu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(old_state), static_cast<int>(had_client), old_error.size());
        if (!ensure_ready())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            fail.error = sg().last_error;
            if (fail.error.empty())
                fail.error = old_state == bridge_state_t::stopped
                    ? "camoufox bridge is not running; use browser_lifecycle action=launch before browser navigation or instrumentation"
                    : "camoufox bridge not ready";
            diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovery_failed request_id=%llu tool=%s state=%d client=%d err_len=%zu args_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(sg().state), static_cast<int>(sg().client != nullptr),
                fail.error.size(), json_shape(call_args).c_str());
            return fail;
        }
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            if (sg().state == bridge_state_t::ready && sg().client)
                cli = sg().client;
            else
                fail.error = sg().last_error.empty() ? std::string("camoufox bridge not ready after recovery") : sg().last_error;
        }
        if (!cli)
        {
            diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovery_no_client request_id=%llu tool=%s err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), fail.error.c_str());
            return fail;
        }
    }

    if (timeout_ms <= 0) timeout_ms = 30000;

    struct shared_state_t
    {
        std::mutex                       mtx;
        std::condition_variable          cv;
        bool                             done = false;
        bool                             cancelled = false;
        uint64_t                         generation = 0;
        uint32_t                         child_pid = 0;
        bool                             half_logged = false;
        bool                             quarter_logged = false;
        bool                             ninety_logged = false;
        mcp_client::call_result_t        result;
    };
    auto state = std::make_shared<shared_state_t>();
    {
        std::lock_guard<std::recursive_mutex> g(sg().mtx);
        state->generation = sg().generation;
        state->child_pid = sg().child_pid;
    }

    const uint64_t t0 = now_ms();
    const bool navigation_call = tool_name == "navigate";
    const std::string navigation_page_id = navigation_call ? json_string_or(call_args, "page_id", std::string()) : std::string();
    const std::string navigation_wait_until = navigation_call ? json_string_or(call_args, "wait_until", std::string()) : std::string();
    const std::string navigation_url = navigation_call ? json_string_or(call_args, "url", std::string()) : std::string();
    const url_log_t navigation_url_log = navigation_call ? summarize_url_for_log(navigation_url) : url_log_t{};
    sg().total_calls.fetch_add(1, std::memory_order_relaxed);
    if (navigation_call)
    {
        diag::log_tagged_fmt("camoufox", "navigate call_with_deadline phase=before_dispatch request_id=%llu page_id=%s host=%s path=%s query=%d fragment=%d url_len=%zu wait_until=%s timeout_ms=%d generation=%llu child_pid=%lu args_shape=%s",
            static_cast<unsigned long long>(request_id),
            navigation_page_id.empty() ? "<empty>" : navigation_page_id.c_str(),
            navigation_url_log.host.c_str(),
            navigation_url_log.path.c_str(),
            navigation_url_log.has_query ? 1 : 0,
            navigation_url_log.has_fragment ? 1 : 0,
            navigation_url_log.length,
            navigation_wait_until.empty() ? "<empty>" : navigation_wait_until.c_str(),
            timeout_ms,
            static_cast<unsigned long long>(state->generation),
            static_cast<unsigned long>(state->child_pid),
            json_shape(call_args).c_str());
    }
    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=dispatch request_id=%llu tool=%s timeout_ms=%d generation=%llu child_pid=%lu args_shape=%s",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms, static_cast<unsigned long long>(state->generation),
        static_cast<unsigned long>(state->child_pid), json_shape(call_args).c_str());

    bool posted = post_bridge_task("camoufox.call", [state, cli, tool_name, call_args, request_id]() {
        const uint64_t worker_start = now_ms();
        mcp_client::call_result_t r;
        guarded_mcp_call_context_t call_ctx;
        call_ctx.client = cli.get();
        call_ctx.tool_name = &tool_name;
        call_ctx.args = &call_args;
        call_ctx.result = &r;
        diag::log_tagged_fmt("camoufox", "call_worker phase=enter request_id=%llu tool=%s generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(state->generation),
            static_cast<unsigned long>(state->child_pid));
        if (tool_name == "navigate")
        {
            const std::string worker_page_id = json_string_or(call_args, "page_id", std::string());
            const std::string worker_wait_until = json_string_or(call_args, "wait_until", std::string());
            const url_log_t worker_url = summarize_url_for_log(json_string_or(call_args, "url", std::string()));
            diag::log_tagged_fmt("camoufox", "navigate call_worker phase=before_call_tool request_id=%llu page_id=%s host=%s path=%s query=%d wait_until=%s generation=%llu child_pid=%lu",
                static_cast<unsigned long long>(request_id),
                worker_page_id.empty() ? "<empty>" : worker_page_id.c_str(),
                worker_url.host.c_str(),
                worker_url.path.c_str(),
                worker_url.has_query ? 1 : 0,
                worker_wait_until.empty() ? "<empty>" : worker_wait_until.c_str(),
                static_cast<unsigned long long>(state->generation),
                static_cast<unsigned long>(state->child_pid));
        }
        DWORD guard_status = guarded_mcp_call(&call_ctx);
        if (guard_status != ERROR_SUCCESS)
        {
            r = guarded_mcp_failure_result(tool_name, call_ctx, guard_status);
            diag::log_tagged_critical_fmt("camoufox", "call_with_deadline phase=guarded_failure request_id=%llu tool=%s generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(state->generation),
                static_cast<unsigned long>(state->child_pid), static_cast<unsigned long>(guard_status),
                static_cast<int>(call_ctx.native_exception), static_cast<int>(call_ctx.cpp_exception),
                static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        if (tool_name == "navigate")
        {
            const std::string worker_page_id = json_string_or(call_args, "page_id", std::string());
            const std::string worker_wait_until = json_string_or(call_args, "wait_until", std::string());
            const int response_status = json_int_or(r.data, "final_status", json_int_or(r.data, "initial_status", json_int_or(r.data, "status", json_int_or(r.data, "response_status", -1))));
            const bool navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false) || json_bool_or(r.data, "timed_out", false);
            const url_log_t response_url = summarize_url_for_log(json_string_or(r.data, "url", json_string_or(r.data, "final_url", json_string_or(r.data, "active_url", std::string()))));
            diag::log_tagged_fmt("camoufox", "navigate call_worker phase=after_call_tool request_id=%llu page_id=%s wait_until=%s success=%d response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu text_len=%zu data_shape=%s elapsed_ms=%llu",
                static_cast<unsigned long long>(request_id),
                worker_page_id.empty() ? "<empty>" : worker_page_id.c_str(),
                worker_wait_until.empty() ? "<empty>" : worker_wait_until.c_str(),
                r.success ? 1 : 0,
                response_status,
                navigation_timed_out ? 1 : 0,
                response_url.host.c_str(),
                response_url.path.c_str(),
                response_url.has_query ? 1 : 0,
                response_url.length,
                r.text.size(),
                json_shape(r.data).c_str(),
                static_cast<unsigned long long>(now_ms() - worker_start));
        }
        diag::log_tagged_fmt("camoufox", "call_worker phase=exit request_id=%llu tool=%s success=%d text_len=%zu data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(r.success),
            r.text.size(), json_shape(r.data).c_str(), static_cast<unsigned long long>(now_ms() - worker_start));
        const bool late_navigation_call = tool_name == "navigate";
        const int late_navigation_status = late_navigation_call
            ? json_int_or(r.data, "final_status", json_int_or(r.data, "initial_status", json_int_or(r.data, "status", json_int_or(r.data, "response_status", -1))))
            : -1;
        const bool late_navigation_timed_out = late_navigation_call &&
            (json_bool_or(r.data, "navigation_timed_out", false) || json_bool_or(r.data, "timed_out", false));
        const url_log_t late_navigation_url = late_navigation_call
            ? summarize_url_for_log(json_string_or(r.data, "url", json_string_or(r.data, "final_url", json_string_or(r.data, "active_url", std::string()))))
            : url_log_t{};
        bool cancelled = false;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            cancelled = state->cancelled;
            generation = state->generation;
            child_pid = state->child_pid;
            state->result = std::move(r);
            state->done   = true;
        }
        state->cv.notify_all();
        if (cancelled)
        {
            diag::log_tagged_fmt("camoufox", "call_worker_late_result request_id=%llu tool=%s generation=%llu child_pid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long long>(now_ms() - worker_start));
            if (late_navigation_call)
            {
                const std::string worker_page_id = json_string_or(call_args, "page_id", std::string());
                const std::string worker_wait_until = json_string_or(call_args, "wait_until", std::string());
                diag::log_tagged_fmt("camoufox", "navigate late_result phase=observed request_id=%llu page_id=%s wait_until=%s response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu elapsed_ms=%llu",
                    static_cast<unsigned long long>(request_id),
                    worker_page_id.empty() ? "<empty>" : worker_page_id.c_str(),
                    worker_wait_until.empty() ? "<empty>" : worker_wait_until.c_str(),
                    late_navigation_status,
                    late_navigation_timed_out ? 1 : 0,
                    late_navigation_url.host.c_str(),
                    late_navigation_url.path.c_str(),
                    late_navigation_url.has_query ? 1 : 0,
                    late_navigation_url.length,
                    static_cast<unsigned long long>(now_ms() - worker_start));
            }
            bool recovered = false;
            bool same_client = false;
            bool same_generation = false;
            bool same_child_pid = false;
            bool child_alive = false;
            bool browser_open = false;
            bool page_verified = false;
            bool privacy_verified = false;
            bool cleanup_pending = false;
            bool stop_requested = sg().stop_requested.load(std::memory_order_acquire);
            uint32_t browser_processes = 0;
            uint32_t child_processes = 0;
            const bool result_ok = r.success && !(r.data.is_object() && r.data.contains("error") && r.data["error"].is_string());
            if (result_ok)
            {
                std::lock_guard<std::recursive_mutex> g(sg().mtx);
                same_client = sg().client == cli;
                same_generation = sg().generation == generation;
                same_child_pid = sg().child_pid == child_pid && child_pid != 0;
                child_alive = same_child_pid && process_alive(child_pid);
                const std::vector<process_tree_entry_t> health_tree = child_alive ? enumerate_process_tree(child_pid) : std::vector<process_tree_entry_t>();
                child_processes = static_cast<uint32_t>(health_tree.size());
                browser_processes = browser_process_count_from_tree(health_tree);
                browser_open = sg().browser_open;
                page_verified = sg().page_verified;
                privacy_verified = sg().privacy_verified;
                cleanup_pending = sg().cleanup_pending;
                const bool health_ok = same_client && same_generation && same_child_pid && child_alive && usable_browser_process_count(browser_processes) && browser_open && page_verified && privacy_verified && !cleanup_pending && !stop_requested;
                if (health_ok)
                {
                    if (reduced_browser_process_tree(browser_processes))
                    {
                        diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=call_worker_late_result_health request_id=%llu tool=%s generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d stop_requested=%d process_tree=%s",
                            static_cast<unsigned long long>(request_id),
                            tool_name.c_str(),
                            static_cast<unsigned long long>(generation),
                            static_cast<unsigned long>(child_pid),
                            child_alive ? 1 : 0,
                            static_cast<unsigned>(child_processes),
                            static_cast<unsigned>(browser_processes),
                            static_cast<unsigned>(kMinReadyBrowserProcessCount),
                            browser_open ? 1 : 0,
                            page_verified ? 1 : 0,
                            privacy_verified ? 1 : 0,
                            cleanup_pending ? 1 : 0,
                            stop_requested ? 1 : 0,
                            health_tree.empty() ? "<empty>" : compact_process_tree(health_tree).c_str());
                    }
                    if (r.data.is_object())
                        update_page_cache_from_json_locked(r.data, tool_name.c_str());
                    sg().state = bridge_state_t::ready;
                    sg().last_call_ms = now_ms();
                    clear_error_locked();
                    clear_auto_restart_block_locked("late_success_health_proof");
                    recovered = true;
                }
            }
            diag::log_tagged_fmt("camoufox", "call_worker_late_result_health request_id=%llu tool=%s generation=%llu child_pid=%lu success=%d recovered=%d same_client=%d same_generation=%d same_child_pid=%d child_alive=%d child_processes=%u browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d stop_requested=%d data_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                result_ok ? 1 : 0, recovered ? 1 : 0, same_client ? 1 : 0, same_generation ? 1 : 0,
                same_child_pid ? 1 : 0, child_alive ? 1 : 0,
                static_cast<unsigned>(child_processes), static_cast<unsigned>(browser_processes),
                browser_open ? 1 : 0, page_verified ? 1 : 0, privacy_verified ? 1 : 0,
                cleanup_pending ? 1 : 0, stop_requested ? 1 : 0, json_shape(r.data).c_str());
            if (late_navigation_call)
            {
                const std::string worker_page_id = json_string_or(call_args, "page_id", std::string());
                diag::log_tagged_fmt("camoufox", "navigate late_result phase=health request_id=%llu page_id=%s response_status=%d navigation_timed_out=%d recovered=%d same_client=%d same_generation=%d same_child_pid=%d child_alive=%d browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d stop_requested=%d",
                    static_cast<unsigned long long>(request_id),
                    worker_page_id.empty() ? "<empty>" : worker_page_id.c_str(),
                    late_navigation_status,
                    late_navigation_timed_out ? 1 : 0,
                    recovered ? 1 : 0,
                    same_client ? 1 : 0,
                    same_generation ? 1 : 0,
                    same_child_pid ? 1 : 0,
                    child_alive ? 1 : 0,
                    static_cast<unsigned>(browser_processes),
                    browser_open ? 1 : 0,
                    page_verified ? 1 : 0,
                    privacy_verified ? 1 : 0,
                    cleanup_pending ? 1 : 0,
                    stop_requested ? 1 : 0);
            }
            if (recovered)
                publish_state(bridge_state_t::ready, {});
        }
    });

    if (!posted)
    {
        fail.error = "camoufox call dispatch post failed";
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        diag::log_tagged_fmt("camoufox", "call_with_deadline phase=post_failed request_id=%llu tool=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str());
        return fail;
    }

    std::unique_lock<std::mutex> lk(state->mtx);
    const uint64_t wait_start_ms = now_ms();
    bool cancelled_by_stop = false;
    while (!state->done)
    {
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            cancelled_by_stop = true;
            break;
        }
        const uint64_t elapsed = now_ms() - wait_start_ms;
        if (elapsed >= static_cast<uint64_t>(timeout_ms))
            break;
        const uint64_t half_mark = static_cast<uint64_t>(timeout_ms) / 2;
        const uint64_t quarter_mark = static_cast<uint64_t>(timeout_ms) * 3 / 4;
        const uint64_t ninety_mark = static_cast<uint64_t>(timeout_ms) * 9 / 10;
        if (!state->half_logged && elapsed >= half_mark)
        {
            state->half_logged = true;
            diag::log_tagged_fmt("camoufox", "call_with_deadline progress=50pct request_id=%llu tool=%s elapsed_ms=%llu timeout_ms=%d generation=%llu child_pid=%lu done=%d",
                static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(elapsed), timeout_ms,
                static_cast<unsigned long long>(state->generation), static_cast<unsigned long>(state->child_pid),
                state->done ? 1 : 0);
        }
        if (!state->quarter_logged && elapsed >= quarter_mark)
        {
            state->quarter_logged = true;
            diag::log_tagged_fmt("camoufox", "call_with_deadline progress=75pct request_id=%llu tool=%s elapsed_ms=%llu timeout_ms=%d generation=%llu child_pid=%lu done=%d",
                static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(elapsed), timeout_ms,
                static_cast<unsigned long long>(state->generation), static_cast<unsigned long>(state->child_pid),
                state->done ? 1 : 0);
        }
        if (!state->ninety_logged && elapsed >= ninety_mark)
        {
            state->ninety_logged = true;
            diag::log_tagged_fmt("camoufox", "call_with_deadline progress=90pct request_id=%llu tool=%s elapsed_ms=%llu timeout_ms=%d generation=%llu child_pid=%lu done=%d",
                static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(elapsed), timeout_ms,
                static_cast<unsigned long long>(state->generation), static_cast<unsigned long>(state->child_pid),
                state->done ? 1 : 0);
        }
        const uint64_t remaining = static_cast<uint64_t>(timeout_ms) - elapsed;
        state->cv.wait_for(lk, std::chrono::milliseconds(static_cast<int>(std::min<uint64_t>(remaining, 250))), [&state]() { return state->done; });
    }
    bool got = state->done;
    if (!got)
    {
        std::shared_ptr<mcp_client::client_t> timed_out_client;
        uint32_t timed_out_child_pid = 0;
        uint64_t timed_out_generation = 0;
        bool retained_timed_out_client = false;
        state->cancelled = true;
        timed_out_child_pid = state->child_pid;
        timed_out_generation = state->generation;
        lk.unlock();
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                if (!cancelled_by_stop && sg().child_pid != 0 && process_alive(sg().child_pid))
                {
                    retained_timed_out_client = true;
                    sg().state = bridge_state_t::error;
                    sg().last_error = std::string("call_tool timeout: ") + tool_name;
                    block_auto_restart_locked(std::string("timeout_") + tool_name, sg().generation, kAutoRestartBlockMs);
                    timed_out_child_pid = sg().child_pid;
                    timed_out_generation = sg().generation;
                    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=timeout request_id=%llu timeout_ms=%d tool=%s failure_phase=mcp_response_wait action=retain_client_block_restart generation=%llu child_pid=%lu browser_open=%d page_verified=%d",
                        static_cast<unsigned long long>(request_id), timeout_ms, tool_name.c_str(),
                        static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                        sg().browser_open ? 1 : 0, sg().page_verified ? 1 : 0);
                }
                else
                {
                    timed_out_client = sg().client;
                    sg().client.reset();
                    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=%s request_id=%llu timeout_ms=%d tool=%s failure_phase=mcp_response_wait action=detach_client generation=%llu child_pid=%lu",
                        cancelled_by_stop ? "cancel" : "timeout", static_cast<unsigned long long>(request_id), timeout_ms, tool_name.c_str(), static_cast<unsigned long long>(sg().generation),
                        static_cast<unsigned long>(sg().child_pid));
                    sg().state           = bridge_state_t::error;
                    sg().last_error      = cancelled_by_stop
                        ? std::string("call_tool cancelled by stop request: ") + tool_name
                        : std::string("call_tool timeout: ") + tool_name;
                    clear_page_state_locked();
                    mark_cleanup_started_locked(sg().generation, sg().child_pid, std::string(cancelled_by_stop ? "cancel_" : "timeout_") + tool_name);
                    timed_out_child_pid = sg().child_pid;
                    timed_out_generation = sg().generation;
                    sg().child_pid       = 0;
                }
            }
            else
            {
                diag::log_tagged_fmt("camoufox", "call_with_deadline phase=%s request_id=%llu timeout_ms=%d tool=%s failure_phase=mcp_response_wait action=current_client_changed generation=%llu",
                    cancelled_by_stop ? "cancel" : "timeout", static_cast<unsigned long long>(request_id), timeout_ms, tool_name.c_str(), static_cast<unsigned long long>(sg().generation));
            }
        }
        if (timed_out_client)
            cleanup_client_reap_now_detach_disconnect(timed_out_client, timed_out_child_pid, std::string(cancelled_by_stop ? "cancel_" : "timeout_") + tool_name, timed_out_generation);
        else if (retained_timed_out_client)
        {
            diag::log_tagged_fmt("camoufox", "call_with_deadline retained_timeout request_id=%llu tool=%s generation=%llu child_pid=%lu",
                static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(timed_out_generation), static_cast<unsigned long>(timed_out_child_pid));
            auto recovery_cli = cli;
            const uint64_t recovery_generation = timed_out_generation;
            const uint32_t recovery_child_pid = timed_out_child_pid;
            const uint64_t recovery_request_id = request_id;
            const std::string recovery_tool_name = tool_name;
            post_bridge_task("camoufox.recovery", [recovery_cli, recovery_generation, recovery_child_pid, recovery_request_id, recovery_tool_name]() {
                const uint64_t recovery_start_ms = now_ms();
                Sleep(500);
                bool needs_recovery = false;
                {
                    std::lock_guard<std::recursive_mutex> g(sg().mtx);
                    needs_recovery = sg().state == bridge_state_t::error &&
                                     sg().generation == recovery_generation &&
                                     sg().client == recovery_cli &&
                                     sg().child_pid == recovery_child_pid &&
                                     recovery_child_pid != 0 &&
                                     process_alive(recovery_child_pid);
                }
                if (!needs_recovery)
                {
                    diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery skipped request_id=%llu tool=%s generation=%llu child_pid=%lu reason=state_changed",
                        static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                        static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid));
                    return;
                }
                diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery begin request_id=%llu tool=%s generation=%llu child_pid=%lu",
                    static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                    static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid));
                const std::string list_tool = "list_pages";
                const nlohmann::json list_args = nlohmann::json::object();
                mcp_client::call_result_t list_result;
                guarded_mcp_call_context_t list_ctx;
                list_ctx.client = recovery_cli.get();
                list_ctx.tool_name = &list_tool;
                list_ctx.args = &list_args;
                list_ctx.result = &list_result;
                DWORD list_status = guarded_mcp_call(&list_ctx);
                const uint64_t list_elapsed_ms = now_ms() - recovery_start_ms;
                if (list_status != ERROR_SUCCESS || !list_result.success)
                {
                    diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery list_pages_failed request_id=%llu tool=%s generation=%llu child_pid=%lu guard_status=0x%08lX success=%d elapsed_ms=%llu text_len=%zu",
                        static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                        static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                        static_cast<unsigned long>(list_status), static_cast<int>(list_result.success),
                        static_cast<unsigned long long>(list_elapsed_ms), list_result.text.size());
                    return;
                }
                diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery list_pages_ok request_id=%llu tool=%s generation=%llu child_pid=%lu elapsed_ms=%llu data_shape=%s",
                    static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                    static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                    static_cast<unsigned long long>(list_elapsed_ms), json_shape(list_result.data).c_str());
                bool has_pages = false;
                if (list_result.data.is_object())
                {
                    const auto pages_it = list_result.data.find("pages");
                    if (pages_it != list_result.data.end() && pages_it->is_array() && !pages_it->empty())
                        has_pages = true;
                }
                else if (list_result.data.is_array() && !list_result.data.empty())
                {
                    has_pages = true;
                }
                if (!has_pages)
                {
                    diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery no_pages_creating_new request_id=%llu tool=%s generation=%llu child_pid=%lu",
                        static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                        static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid));
                    const std::string new_page_tool = "new_page";
                    nlohmann::json new_page_args = nlohmann::json::object();
                    new_page_args["page_id"] = std::string("recovered_") + std::to_string(recovery_generation);
                    mcp_client::call_result_t new_page_result;
                    guarded_mcp_call_context_t new_page_ctx;
                    new_page_ctx.client = recovery_cli.get();
                    new_page_ctx.tool_name = &new_page_tool;
                    new_page_ctx.args = &new_page_args;
                    new_page_ctx.result = &new_page_result;
                    DWORD new_page_status = guarded_mcp_call(&new_page_ctx);
                    const uint64_t new_page_elapsed_ms = now_ms() - recovery_start_ms;
                    if (new_page_status != ERROR_SUCCESS || !new_page_result.success)
                    {
                        diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery new_page_failed request_id=%llu tool=%s generation=%llu child_pid=%lu guard_status=0x%08lX success=%d elapsed_ms=%llu text_len=%zu",
                            static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                            static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                            static_cast<unsigned long>(new_page_status), static_cast<int>(new_page_result.success),
                            static_cast<unsigned long long>(new_page_elapsed_ms), new_page_result.text.size());
                        return;
                    }
                    diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery new_page_ok request_id=%llu tool=%s generation=%llu child_pid=%lu elapsed_ms=%llu data_shape=%s",
                        static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                        static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                        static_cast<unsigned long long>(new_page_elapsed_ms), json_shape(new_page_result.data).c_str());
                    {
                        std::lock_guard<std::recursive_mutex> g(sg().mtx);
                        if (sg().generation == recovery_generation && sg().client == recovery_cli)
                        {
                            sg().state = bridge_state_t::ready;
                            clear_error_locked();
                            clear_auto_restart_block_locked("page_crash_recovery_new_page");
                            sg().browser_open = true;
                            sg().page_verified = true;
                            if (!new_page_result.data.is_null())
                                update_page_cache_from_json_locked(new_page_result.data, "page_crash_recovery_new_page");
                            sg().last_call_ms = now_ms();
                        }
                    }
                    publish_state(bridge_state_t::ready, {});
                    diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery recovered_via_new_page request_id=%llu tool=%s generation=%llu child_pid=%lu total_elapsed_ms=%llu",
                        static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                        static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                        static_cast<unsigned long long>(now_ms() - recovery_start_ms));
                    return;
                }
                {
                    std::lock_guard<std::recursive_mutex> g(sg().mtx);
                    if (sg().generation == recovery_generation && sg().client == recovery_cli)
                    {
                        sg().state = bridge_state_t::ready;
                        clear_error_locked();
                        clear_auto_restart_block_locked("page_crash_recovery_list_pages");
                        sg().browser_open = true;
                        sg().page_verified = true;
                        if (!list_result.data.is_null())
                            update_page_cache_from_json_locked(list_result.data, "page_crash_recovery_list_pages");
                        sg().last_call_ms = now_ms();
                    }
                }
                publish_state(bridge_state_t::ready, {});
                diag::log_tagged_fmt("camoufox", "call_with_deadline page_crash_recovery recovered_via_list_pages request_id=%llu tool=%s generation=%llu child_pid=%lu total_elapsed_ms=%llu",
                    static_cast<unsigned long long>(recovery_request_id), recovery_tool_name.c_str(),
                    static_cast<unsigned long long>(recovery_generation), static_cast<unsigned long>(recovery_child_pid),
                    static_cast<unsigned long long>(now_ms() - recovery_start_ms));
            });
        }
        const process_exit_snapshot_t timeout_exit = query_process_exit_snapshot(timed_out_child_pid);
        const std::vector<process_tree_entry_t> timeout_tree_after = timed_out_child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(timed_out_child_pid);
        const std::string call_debug_log = camoufox_debug_log_path();
        const std::string call_debug_tail = read_file_tail_for_log(call_debug_log, 6000);
        const nlohmann::json call_debug_event = last_camoufox_debug_event_json_from_tail(call_debug_tail);
        const std::string sidecar_timeout_phase = sidecar_timeout_phase_from_event(call_debug_event, "mcp_response_wait");
        diag::log_tagged_fmt("camoufox", "call_with_deadline timeout_breadcrumb request_id=%llu tool=%s generation=%llu child_pid=%lu timeout_ms=%d retained_client=%d cancelled_by_stop=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%zu browser_processes=%u process_tree=%s",
            static_cast<unsigned long long>(request_id),
            tool_name.c_str(),
            static_cast<unsigned long long>(timed_out_generation),
            static_cast<unsigned long>(timed_out_child_pid),
            timeout_ms,
            retained_timed_out_client ? 1 : 0,
            cancelled_by_stop ? 1 : 0,
            timeout_exit.queried ? 1 : 0,
            static_cast<unsigned long>(timeout_exit.queried ? timeout_exit.exit_code : 0),
            static_cast<unsigned long>(timeout_exit.gle),
            timeout_tree_after.size(),
            static_cast<unsigned>(browser_process_count_from_tree(timeout_tree_after)),
            timeout_tree_after.empty() ? "<empty>" : compact_process_tree(timeout_tree_after).c_str());
        if (navigation_call)
        {
            diag::log_tagged_fmt("camoufox", "call_tool_navigate_timeout phase=%s tool=%s request_id=%llu page_id=%s host=%s path=%s query=%d wait_until=%s timeout_ms=%d elapsed_ms=%llu sidecar_phase=%s retained_client=%d cancelled_by_stop=%d generation=%llu child_pid=%lu",
                sidecar_timeout_phase.empty() ? "<empty>" : sidecar_timeout_phase.c_str(),
                tool_name.c_str(),
                static_cast<unsigned long long>(request_id),
                navigation_page_id.empty() ? "<empty>" : navigation_page_id.c_str(),
                navigation_url_log.host.c_str(),
                navigation_url_log.path.c_str(),
                navigation_url_log.has_query ? 1 : 0,
                navigation_wait_until.empty() ? "<empty>" : navigation_wait_until.c_str(),
                timeout_ms,
                static_cast<unsigned long long>(now_ms() - wait_start_ms),
                sidecar_timeout_phase.empty() ? "<empty>" : sidecar_timeout_phase.c_str(),
                retained_timed_out_client ? 1 : 0,
                cancelled_by_stop ? 1 : 0,
                static_cast<unsigned long long>(timed_out_generation),
                static_cast<unsigned long>(timed_out_child_pid));
            diag::log_tagged_fmt("camoufox", "navigate call_with_deadline phase=timeout request_id=%llu page_id=%s host=%s path=%s query=%d wait_until=%s timeout_ms=%d retained_client=%d late_result_handling=%s cancelled_by_stop=%d generation=%llu child_pid=%lu browser_processes=%u child_processes=%zu",
                static_cast<unsigned long long>(request_id),
                navigation_page_id.empty() ? "<empty>" : navigation_page_id.c_str(),
                navigation_url_log.host.c_str(),
                navigation_url_log.path.c_str(),
                navigation_url_log.has_query ? 1 : 0,
                navigation_wait_until.empty() ? "<empty>" : navigation_wait_until.c_str(),
                timeout_ms,
                retained_timed_out_client ? 1 : 0,
                retained_timed_out_client ? "retained_client_waiting_for_late_result" : "detached_client_no_late_recovery",
                cancelled_by_stop ? 1 : 0,
                static_cast<unsigned long long>(timed_out_generation),
                static_cast<unsigned long>(timed_out_child_pid),
                static_cast<unsigned>(browser_process_count_from_tree(timeout_tree_after)),
                timeout_tree_after.size());
        }
        publish_state(bridge_state_t::error, std::string(cancelled_by_stop ? "cancelled " : "timeout on ") + tool_name);
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        fail.error = cancelled_by_stop
            ? std::string("camoufox call_tool cancelled by stop request: ") + tool_name
            : std::string("camoufox call_tool timeout: ") + tool_name;
        fail.data = {
            {"status", cancelled_by_stop ? "cancelled" : "timeout"},
            {"phase", "mcp_response_wait"},
            {"transport_phase", "mcp_response_wait"},
            {"sidecar_timeout_phase", sidecar_timeout_phase},
            {"timeout_phase", cancelled_by_stop ? nlohmann::json(nullptr) : nlohmann::json(sidecar_timeout_phase)},
            {"tool", tool_name},
            {"request_id", request_id},
            {"timeout_ms", timeout_ms},
            {"generation", timed_out_generation},
            {"child_pid", timed_out_child_pid},
            {"retained_client", retained_timed_out_client},
            {"cancelled_by_stop", cancelled_by_stop},
            {"exit_code_valid", timeout_exit.queried},
            {"exit_code", timeout_exit.queried ? static_cast<uint32_t>(timeout_exit.exit_code) : 0u},
            {"exit_query_gle", static_cast<uint32_t>(timeout_exit.gle)},
            {"child_process_count", timeout_tree_after.size()},
            {"browser_process_count", browser_process_count_from_tree(timeout_tree_after)},
            {"process_tree", compact_process_tree(timeout_tree_after)},
            {"error", fail.error}
        };
        {
            std::lock_guard<std::recursive_mutex> diag_lk(sg().mtx);
            attach_debug_log_snapshot_locked(fail.data, timed_out_child_pid, call_debug_log, call_debug_tail);
            if (tool_name == "new_page")
            {
                sg().last_launch_diagnostics = fail.data;
                sg().last_launch_diagnostics["caller"] = "new_page";
                sg().last_launch_diagnostics["readiness_sub_step"] = sidecar_timeout_phase;
                sg().last_launch_diagnostics["cleanup_pending_after_timeout"] = sg().cleanup_pending;
            }
        }
        attach_bridge_call_metadata(
            fail,
            "default",
            tool_name,
            request_id,
            timeout_ms,
            now_ms() - t0,
            timed_out_generation,
            timed_out_child_pid,
            navigation_call ? navigation_page_id : json_string_or(call_args, "page_id", std::string()),
            cancelled_by_stop ? "cancelled" : "timeout",
            true,
            timeout_exit.alive,
            false,
            false,
            !retained_timed_out_client);
        if (navigation_call)
        {
            fail.data["page_id"] = navigation_page_id;
            fail.data["wait_until"] = navigation_wait_until;
            fail.data["url_host"] = navigation_url_log.host;
            fail.data["url_path"] = navigation_url_log.path;
            fail.data["url_has_query"] = navigation_url_log.has_query;
            fail.data["url_len"] = navigation_url_log.length;
            fail.data["late_result_handling"] = retained_timed_out_client ? "retained_client_waiting_for_late_result" : "detached_client_no_late_recovery";
        }
        bridge_call_completed_t ev{tool_name, false, now_ms() - t0};
        aida::events::publish(kBridgeCallCompleted, ev);
        return fail;
    }

    mcp_client::call_result_t result = std::move(state->result);
    lk.unlock();

    call_result_t out = to_bridge_result(result);
    const bool driver_closed = !out.ok && is_driver_closed_error(out.error);
    const bool native_exception = !out.ok && result_has_native_exception(out);
    {
        std::lock_guard<std::recursive_mutex> g(sg().mtx);
        sg().last_call_ms = now_ms();
        if (out.ok)
        {
            if (sg().client == cli) clear_error_locked();
        }
        else if (driver_closed)
        {
            if (sg().client == cli)
                sg().last_error = std::string("camoufox driver closed during ") + tool_name + ": " + out.error;
        }
        else if (native_exception)
        {
            sg().last_error = std::string("camoufox native exception during ") + tool_name + ": " + out.error;
        }
    }
    if (!out.ok) sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    if (native_exception)
    {
        std::shared_ptr<mcp_client::client_t> poisoned_client;
        uint32_t poisoned_child_pid = 0;
        uint64_t poisoned_generation = 0;
        std::string state_error = std::string("camoufox native exception during ") + tool_name + ": " + out.error;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                poisoned_client = sg().client;
                poisoned_child_pid = sg().child_pid;
                poisoned_generation = sg().generation;
                sg().client.reset();
                sg().state = bridge_state_t::error;
                clear_page_state_locked();
                mark_cleanup_started_locked(sg().generation, poisoned_child_pid, std::string("native_exception_") + tool_name);
                quarantine_client_locked(std::move(poisoned_client), std::string("native_exception_") + tool_name);
                sg().child_pid = 0;
            }
            sg().last_error = state_error;
        }
        diag::log_tagged_critical_fmt("camoufox", "native_exception invalidated request_id=%llu tool=%s generation=%llu child_pid=%lu err=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(poisoned_generation),
            static_cast<unsigned long>(poisoned_child_pid), out.error.c_str());
        cleanup_poisoned_client_async(poisoned_child_pid, std::string("native_exception_") + tool_name, poisoned_generation);
        publish_state(bridge_state_t::error, state_error);
    }
    else if (driver_closed)
    {
        std::shared_ptr<mcp_client::client_t> closed_client;
        uint32_t closed_child_pid = 0;
        uint64_t closed_generation = 0;
        uint64_t closed_current_generation = 0;
        std::string state_error = std::string("camoufox driver closed during ") + tool_name + ": " + out.error;
        bool retained_evaluate_client = false;
        uint32_t retain_child_pid = 0;
        uint64_t retain_generation = 0;
        bool retain_browser_open = false;
        bool retain_page_verified = false;
        bool invalidated_current_client = false;
        uint64_t live_generation_after = 0;
        uint32_t live_child_pid_after = 0;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                retain_child_pid = sg().child_pid;
                retain_generation = sg().generation;
                retain_browser_open = sg().browser_open;
                retain_page_verified = sg().page_verified;
            }
        }
        if (tool_name == "evaluate_js" && retain_child_pid != 0 && retain_browser_open && retain_page_verified && process_alive(retain_child_pid))
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli && sg().child_pid == retain_child_pid && sg().generation == retain_generation)
            {
                retained_evaluate_client = true;
                sg().last_error = "camoufox evaluate_js transient transport failure";
            }
        }
        if (retained_evaluate_client)
        {
            diag::log_tagged_fmt("camoufox", "driver_closed retained_evaluate_client request_id=%llu tool=%s generation=%llu child_pid=%lu browser_open=%d page_verified=%d err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(retain_generation),
                static_cast<unsigned long>(retain_child_pid), retain_browser_open ? 1 : 0, retain_page_verified ? 1 : 0, out.error.c_str());
        }
        else
        {
            {
                std::lock_guard<std::recursive_mutex> g(sg().mtx);
                if (sg().client == cli)
                {
                    closed_client = sg().client;
                    closed_child_pid = sg().child_pid;
                    closed_generation = sg().generation;
                    closed_current_generation = ++sg().generation;
                    invalidated_current_client = true;
                    sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel);
                    sg().stop_requested.store(true, std::memory_order_release);
                    sg().client.reset();
                    sg().state = bridge_state_t::error;
                    clear_page_state_locked();
                    mark_cleanup_started_locked(closed_generation, closed_child_pid, std::string("driver_closed_") + tool_name);
                    sg().child_pid = 0;
                    sg().last_error = state_error;
                }
                live_generation_after = sg().generation;
                live_child_pid_after = sg().child_pid;
            }
            if (!invalidated_current_client)
            {
                diag::log_tagged_fmt("camoufox", "driver_closed stale_result_ignored request_id=%llu tool=%s live_generation=%llu live_child_pid=%lu err=%s",
                    static_cast<unsigned long long>(request_id),
                    tool_name.c_str(),
                    static_cast<unsigned long long>(live_generation_after),
                    static_cast<unsigned long>(live_child_pid_after),
                    out.error.c_str());
                disconnect_client_async(cli, std::string("driver_closed_stale_") + tool_name);
            }
            else
            {
                const std::vector<process_tree_entry_t> closed_tree = closed_child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(closed_child_pid);
                const std::string closed_tree_compact = compact_process_tree(closed_tree);
                const std::string closed_tree_with_exit = compact_process_tree_with_exit(closed_tree);
                const std::string debug_log = camoufox_debug_log_path();
                const uint64_t debug_size = file_size_for_log(debug_log);
                const std::string debug_tail = read_file_tail_for_log(debug_log, 6000);
                const uint64_t debug_tail_offset = debug_size > debug_tail.size() ? debug_size - debug_tail.size() : 0;
                const size_t marker_page_crashed = text_marker_count(debug_tail, "\"event\":\"page_crashed\"");
                const size_t marker_page_closed = text_marker_count(debug_tail, "\"event\":\"page_closed\"");
                const size_t marker_browser_disconnected = text_marker_count(debug_tail, "\"event\":\"browser_disconnected\"");
                diag::log_tagged_fmt("camoufox", "driver_closed invalidated request_id=%llu tool=%s stale_generation=%llu current_generation=%llu child_pid=%lu active_activities=%lu err=%s debug_offset=%llu debug_tail_len=%zu page_crashed=%zu page_closed=%zu browser_disconnected=%zu process_tree=%s process_tree_exit=%s",
                    static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(closed_generation),
                    static_cast<unsigned long long>(closed_current_generation),
                    static_cast<unsigned long>(closed_child_pid),
                    static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                    out.error.c_str(),
                    static_cast<unsigned long long>(debug_tail_offset),
                    debug_tail.size(),
                    marker_page_crashed,
                    marker_page_closed,
                    marker_browser_disconnected,
                    closed_tree_compact.empty() ? "<empty>" : closed_tree_compact.c_str(),
                    closed_tree_with_exit.empty() ? "<empty>" : closed_tree_with_exit.c_str());
                cleanup_client_async(closed_client, closed_child_pid, std::string("driver_closed_") + tool_name, closed_generation);
                publish_state(bridge_state_t::error, state_error);
            }
        }
    }
    bridge_call_completed_t ev{tool_name, out.ok, now_ms() - t0};
    aida::events::publish(kBridgeCallCompleted, ev);
    {
        bool browser_open = false;
        bool page_verified = false;
        bool cleanup_pending = false;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            browser_open = sg().browser_open;
            page_verified = sg().page_verified;
            cleanup_pending = sg().cleanup_pending;
        }
        attach_bridge_call_metadata(
            out,
            "default",
            tool_name,
            request_id,
            timeout_ms,
            ev.duration_ms,
            state->generation,
            state->child_pid,
            navigation_call ? navigation_page_id : json_string_or(call_args, "page_id", std::string()),
            "complete",
            false,
            process_alive(state->child_pid),
            browser_open,
            page_verified,
            cleanup_pending);
    }
    if (navigation_call)
    {
        const int response_status = json_int_or(out.data, "final_status", json_int_or(out.data, "initial_status", json_int_or(out.data, "status", json_int_or(out.data, "response_status", -1))));
        const bool navigation_timed_out = json_bool_or(out.data, "navigation_timed_out", false) || json_bool_or(out.data, "timed_out", false);
        const url_log_t response_url = summarize_url_for_log(json_string_or(out.data, "url", json_string_or(out.data, "final_url", json_string_or(out.data, "active_url", std::string()))));
        diag::log_tagged_fmt("camoufox", "navigate call_with_deadline phase=complete request_id=%llu page_id=%s wait_until=%s ok=%d response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu elapsed_ms=%llu data_shape=%s error_len=%zu",
            static_cast<unsigned long long>(request_id),
            navigation_page_id.empty() ? "<empty>" : navigation_page_id.c_str(),
            navigation_wait_until.empty() ? "<empty>" : navigation_wait_until.c_str(),
            out.ok ? 1 : 0,
            response_status,
            navigation_timed_out ? 1 : 0,
            response_url.host.c_str(),
            response_url.path.c_str(),
            response_url.has_query ? 1 : 0,
            response_url.length,
            static_cast<unsigned long long>(ev.duration_ms),
            json_shape(out.data).c_str(),
            out.error.size());
    }
    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=complete request_id=%llu tool=%s ok=%d elapsed_ms=%llu data_shape=%s error_len=%zu",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(out.ok), static_cast<unsigned long long>(ev.duration_ms),
        json_shape(out.data).c_str(), out.error.size());
    return out;
}

const std::vector<std::string>& required_reverse_tool_names()
{
    static const std::vector<std::string> names = {
        "launch_browser",
        "close_browser",
        "list_pages",
        "new_page",
        "select_page",
        "close_page",
        "evaluate_js",
        "navigate",
        "diagnose_bloxflip_matrix",
        "get_page_info",
    };
    return names;
}

std::string join_names_for_log(const std::vector<std::string>& names, std::size_t max_chars = 4096)
{
    std::string out;
    for (const auto& name : names)
    {
        if (name.empty())
            continue;
        if (!out.empty())
            out += ",";
        if (out.size() + name.size() + 16 > max_chars)
        {
            out += "...";
            break;
        }
        out += name;
    }
    return out;
}

std::vector<std::string> sorted_tool_inventory(const std::vector<mcp_client::remote_tool_t>& tools)
{
    std::vector<std::string> names;
    names.reserve(tools.size());
    for (const auto& tool : tools)
    {
        if (!tool.original_name.empty())
            names.push_back(tool.original_name);
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

std::vector<std::string> missing_required_reverse_tools(const std::vector<mcp_client::remote_tool_t>& tools)
{
    const std::vector<std::string> inventory = sorted_tool_inventory(tools);
    std::vector<std::string> missing;
    for (const auto& required : required_reverse_tool_names())
    {
        if (!std::binary_search(inventory.begin(), inventory.end(), required))
            missing.push_back(required);
    }
    return missing;
}

bool wait_for_required_reverse_tools(
    mcp_client::client_t* cli,
    int timeout_ms,
    const char* phase,
    const std::string& mode,
    const std::string& command,
    const std::string& session_id,
    uint64_t generation,
    std::string& missing_csv,
    std::string& inventory_csv)
{
    missing_csv.clear();
    inventory_csv.clear();
    if (!cli)
    {
        missing_csv = join_names_for_log(required_reverse_tool_names());
        diag::log_tagged_fmt("camoufox", "reverse_tool_inventory_failed phase=%s mode=%s session_id=%s generation=%llu reason=null_client missing=%s",
            phase ? phase : "unknown",
            mode.c_str(),
            session_id.c_str(),
            static_cast<unsigned long long>(generation),
            missing_csv.c_str());
        return false;
    }
    const uint64_t start = now_ms();
    const uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    uint64_t attempts = 0;
    while (true)
    {
        ++attempts;
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            diag::log_tagged_fmt("camoufox", "reverse_tool_inventory_cancelled phase=%s mode=%s session_id=%s generation=%llu attempts=%llu elapsed_ms=%llu",
                phase ? phase : "unknown",
                mode.c_str(),
                session_id.c_str(),
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(attempts),
                static_cast<unsigned long long>(now_ms() - start));
            missing_csv = join_names_for_log(required_reverse_tool_names());
            return false;
        }
        auto tools = cli->list_tools();
        const std::vector<std::string> inventory = sorted_tool_inventory(tools);
        const std::vector<std::string> missing = missing_required_reverse_tools(tools);
        inventory_csv = join_names_for_log(inventory);
        missing_csv = join_names_for_log(missing);
        if (missing.empty())
        {
            diag::log_tagged_fmt("camoufox", "reverse_tool_inventory_ok phase=%s mode=%s session_id=%s generation=%llu attempts=%llu elapsed_ms=%llu tool_count=%zu required=%s inventory=%s command=%s",
                phase ? phase : "unknown",
                mode.c_str(),
                session_id.c_str(),
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(attempts),
                static_cast<unsigned long long>(now_ms() - start),
                tools.size(),
                join_names_for_log(required_reverse_tool_names()).c_str(),
                inventory_csv.empty() ? "<empty>" : inventory_csv.c_str(),
                command.empty() ? "<empty>" : command.c_str());
            return true;
        }
        if (now_ms() >= deadline)
        {
            diag::log_tagged_fmt("camoufox", "reverse_tool_inventory_missing phase=%s mode=%s session_id=%s generation=%llu attempts=%llu elapsed_ms=%llu timeout_ms=%d tool_count=%zu missing=%s inventory=%s command=%s mcp_last_error=%s",
                phase ? phase : "unknown",
                mode.c_str(),
                session_id.c_str(),
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(attempts),
                static_cast<unsigned long long>(now_ms() - start),
                timeout_ms,
                tools.size(),
                missing_csv.empty() ? "<empty>" : missing_csv.c_str(),
                inventory_csv.empty() ? "<empty>" : inventory_csv.c_str(),
                command.empty() ? "<empty>" : command.c_str(),
                cli->last_error().empty() ? "<empty>" : cli->last_error().c_str());
            return false;
        }
        Sleep(500);
    }
}

void log_required_reverse_tools_missing_launch_skip(
    const char* phase,
    const std::string& mode,
    const std::string& executable_path,
    const std::string& session_id,
    uint64_t generation,
    uint32_t child_pid,
    const std::string& missing_csv,
    const std::string& inventory_csv,
    const std::string& mcp_last_error)
{
    const local_helper_file_diag_t fd = collect_local_helper_file_diag(executable_path);
    diag::log_tagged_fmt("camoufox",
        "launch_browser skipped reason=required_reverse_tools_missing phase=%s mode=%s session_id=%s generation=%llu child_pid=%lu exe_path=%s exe_exists=%d exe_attr=0x%08lX exe_gle=%lu exe_size=%llu exe_mtime_100ns=%llu exe_sha256=%s exe_hash_status=%s missing_tools=%s inventory=%s mcp_last_error=%s",
        phase ? phase : "unknown",
        mode.empty() ? "<empty>" : mode.c_str(),
        session_id.empty() ? "<empty>" : session_id.c_str(),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(child_pid),
        executable_path.empty() ? "<empty>" : executable_path.c_str(),
        fd.exists ? 1 : 0,
        static_cast<unsigned long>(fd.attr),
        static_cast<unsigned long>(fd.gle),
        static_cast<unsigned long long>(fd.size),
        static_cast<unsigned long long>(fd.mtime_100ns),
        fd.sha256.empty() ? "<empty>" : fd.sha256.c_str(),
        fd.hash_status.empty() ? "<empty>" : fd.hash_status.c_str(),
        missing_csv.empty() ? "<empty>" : missing_csv.c_str(),
        inventory_csv.empty() ? "<empty>" : inventory_csv.c_str(),
        mcp_last_error.empty() ? "<empty>" : mcp_last_error.c_str());
}

bool probe_module_installed_locked(const std::string& python_path)
{
    diag::log_tagged_fmt("camoufox", "module_probe start python=%s module=camoufox_reverse_mcp timeout_ms=%lu",
        python_path.c_str(), static_cast<unsigned long>(kDependencyProbeTimeoutMs));
    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, L"-I -c \"import camoufox_reverse_mcp\"", kDependencyProbeTimeoutMs, code, captured, "module_probe"))
    {
        std::string detail = compact_child_output_tail(captured, 600);
        sg().last_error = detail.empty()
            ? std::string("camoufox_reverse_mcp not installed and automatic setup did not complete")
            : std::string("camoufox_reverse_mcp module probe failed to spawn: ") + detail;
        diag::log_tagged_fmt("camoufox", "module_probe spawn_failed detail=%.600s", detail.c_str());
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "camoufox_reverse_mcp not installed and automatic setup did not complete";
        const std::string detail = compact_child_output_tail(captured, 400);
        diag::log_tagged_fmt("camoufox", "module_probe failed exit=%lu captured_len=%zu out=%.400s",
            code, captured.size(), detail.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "module_probe ok exit=%lu captured_len=%zu", code, captured.size());
    return true;
}

bool preflight_server_entry_locked(const std::string& python_path, const launch_config_t& cfg)
{
    const std::string module = cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : cfg.server_module;
    std::wstring args;
    if (module == "camoufox_reverse_mcp")
        args = L"-I -m camoufox_reverse_mcp --help";
    else
        args = std::wstring(L"-I -c \"import importlib; importlib.import_module('") + utf8_to_wide(module) + L"')\"";
    diag::log_tagged_fmt("camoufox", "server_preflight start python=%s module=%s", python_path.c_str(), module.c_str());

    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, args, 4000, code, captured, "server_preflight"))
    {
        std::string detail = compact_child_output_tail(captured, 600);
        sg().last_error = detail.empty()
            ? std::string("camoufox MCP server preflight failed to spawn or timed out: ") + module
            : std::string("camoufox MCP server preflight failed to spawn or timed out: ") + module + ": " + detail;
        diag::log_tagged_fmt("camoufox", "server_preflight spawn_failed module=%s detail=%.600s",
            module.c_str(), detail.c_str());
        return false;
    }
    if (code != 0)
    {
        std::string detail = compact_child_output_tail(captured);
        sg().last_error = std::string("camoufox MCP server preflight failed: ") + (detail.empty() ? std::string("exit=") + std::to_string(code) : detail);
        diag::log_tagged_fmt("camoufox", "server preflight failed module=%s exit=%lu out=%.400s",
            module.c_str(), code, detail.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "server preflight ok module=%s captured_len=%zu", module.c_str(), captured.size());
    return true;
}

bool wait_for_existing_start_bridge_result(const launch_config_t& cfg, uint64_t caller_start_ms)
{
    int wait_ms = effective_launch_wait_ms(cfg, true);
    if (wait_ms < 5000)
        wait_ms = 5000;
    const uint64_t wait_limit_ms = static_cast<uint64_t>(wait_ms) + 5000;
    const uint64_t wait_start_ms = now_ms();
    uint64_t last_log_ms = 0;
    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait_begin wait_ms=%llu requested_timeout_ms=%d testlab_fast_probe=%d caller_elapsed_ms=%llu",
        static_cast<unsigned long long>(wait_limit_ms), cfg.launch_timeout_ms,
        test_lab_launch_fail_fast_enabled(cfg) ? 1 : 0,
        static_cast<unsigned long long>(wait_start_ms - caller_start_ms));
    for (;;)
    {
        const uint64_t now = now_ms();
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().last_error = "camoufox bridge start cancelled by stop request";
            diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_cancelled elapsed_ms=%llu",
                static_cast<unsigned long long>(now - wait_start_ms));
            return false;
        }
        bridge_state_t state = bridge_state_t::starting;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        bool has_client = false;
        bool browser_open = false;
        bool page_verified = false;
        bool privacy_verified = false;
        bool cleanup_pending = false;
        bool child_alive = false;
        std::string err;
        bool inspected = false;
        {
            std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
            if (lk.owns_lock())
            {
                inspected = true;
                state = sg().state;
                generation = sg().generation;
                child_pid = sg().child_pid;
                has_client = sg().client != nullptr;
                browser_open = sg().browser_open;
                page_verified = sg().page_verified;
                privacy_verified = sg().privacy_verified;
                cleanup_pending = sg().cleanup_pending;
                err = sg().last_error;
                child_alive = process_alive(child_pid);
                const bool ready_candidate = state == bridge_state_t::ready && has_client && browser_open && page_verified && privacy_verified && child_alive &&
                    !cleanup_pending && !is_driver_closed_error(err);
                if (ready_candidate)
                {
                    const bridge_health_snapshot_t ready_health = sample_bridge_health(child_pid, true);
                    const bool ready_process_tree = usable_browser_process_count(ready_health.browser_process_count);
                    if (ready_health.child_alive && ready_process_tree)
                    {
                        diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_reuse_ready generation=%llu child_pid=%lu child_processes=%u browser_processes=%u elapsed_ms=%llu process_tree=%s",
                            static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                            static_cast<unsigned>(ready_health.child_process_count),
                            static_cast<unsigned>(ready_health.browser_process_count),
                            static_cast<unsigned long long>(now_ms() - wait_start_ms),
                            ready_health.process_tree.empty() ? "<empty>" : ready_health.process_tree.c_str());
                        return true;
                    }
                    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_reuse_rejected generation=%llu child_pid=%lu health_alive=%d child_processes=%u browser_processes=%u process_tree=%s",
                        static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                        ready_health.child_alive ? 1 : 0,
                        static_cast<unsigned>(ready_health.child_process_count),
                        static_cast<unsigned>(ready_health.browser_process_count),
                        ready_health.process_tree.empty() ? "<empty>" : ready_health.process_tree.c_str());
                }
                if (state != bridge_state_t::starting && !cleanup_pending)
                {
                    if (err.empty())
                        err = "camoufox bridge operation finished without ready state";
                    sg().last_error = err;
                    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_terminal state=%d generation=%llu child_pid=%lu client=%d browser_open=%d page_verified=%d privacy_verified=%d child_alive=%d elapsed_ms=%llu err=%s",
                        static_cast<int>(state), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                        static_cast<int>(has_client), static_cast<int>(browser_open), static_cast<int>(page_verified),
                        static_cast<int>(privacy_verified), static_cast<int>(child_alive), static_cast<unsigned long long>(now_ms() - wait_start_ms), err.c_str());
                    return false;
                }
            }
        }
        if (now - last_log_ms >= 1000)
        {
            diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait state=%d generation=%llu child_pid=%lu inspected=%d client=%d browser_open=%d page_verified=%d privacy_verified=%d child_alive=%d cleanup_pending=%d elapsed_ms=%llu limit_ms=%llu err_len=%zu",
                static_cast<int>(state), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<int>(inspected), static_cast<int>(has_client), static_cast<int>(browser_open),
                static_cast<int>(page_verified), static_cast<int>(privacy_verified), static_cast<int>(child_alive), static_cast<int>(cleanup_pending),
                static_cast<unsigned long long>(now - wait_start_ms), static_cast<unsigned long long>(wait_limit_ms), err.size());
            last_log_ms = now;
        }
        if (now - wait_start_ms >= wait_limit_ms)
            break;
        Sleep(100);
    }
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    sg().last_error = "camoufox bridge operation still busy";
    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait_timeout state=%d generation=%llu child_pid=%lu client=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d elapsed_ms=%llu",
        static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open), static_cast<int>(sg().page_verified),
        static_cast<int>(sg().privacy_verified), static_cast<int>(sg().cleanup_pending), static_cast<unsigned long long>(now_ms() - wait_start_ms));
    return false;
}

bool prepare_install_for_launch_locked(std::string& python_path)
{
    install::status_t st = install::get_status();
    if (st.state == install::install_state_t::unknown ||
        st.state == install::install_state_t::checking)
        st = install::probe();
    if (!st.python_path.empty()) python_path = st.python_path;

    if (st.state != install::install_state_t::ok)
    {
        std::string setup_log;
        bool ready = false;
        try { ready = install::ensure_ready(setup_log); } catch (...) { ready = false; }
        st = install::get_status();
        if (!st.python_path.empty()) python_path = st.python_path;
        if (!ready || st.state != install::install_state_t::ok)
        {
            sg().last_error = install::last_error();
            if (sg().last_error.empty()) sg().last_error = st.last_message;
            if (sg().last_error.empty()) sg().last_error = "camoufox dependency setup did not reach ready state";
            const std::string detail = compact_child_output(setup_log);
            if (!detail.empty() && sg().last_error.find(detail) == std::string::npos)
                sg().last_error += ": " + detail;
            diag::log_tagged_fmt("camoufox", "prepare_install_for_launch setup_failed state=%d err=%s",
                static_cast<int>(st.state), sg().last_error.c_str());
            return false;
        }
    }
    return true;
}

nlohmann::json build_launch_args(const launch_config_t& cfg)
{
    nlohmann::json j;
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(cfg);
    const int launch_timeout_ms = testlab_fast_probe ? test_lab_launch_wait_ms(cfg) : cfg.launch_timeout_ms;
    j["session_id"]    = cfg.session_id.empty() ? std::string("default") : cfg.session_id;
    j["headless"]     = cfg.headless;
    j["os_type"]      = "windows";
    j["locale"]       = cfg.locale.empty() ? std::string("auto") : cfg.locale;
    j["humanize"]     = cfg.humanize;
    j["geoip"]        = cfg.geoip;
    j["block_images"] = cfg.block_images;
    j["block_webrtc"] = true;
    j["webrtc_policy"] = "disabled";
    j["privacy_fail_closed"] = true;
    const bool block_service_workers = env_flag_enabled_a("AIDA_CAMOUFOX_BLOCK_SERVICE_WORKERS");
    const bool fast_visible_fallback_requested = env_flag_enabled_a("AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK");
    if (fast_visible_fallback_requested)
        diag::log_tagged("camoufox", "ignored_fast_fallback env_flag=AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK forced_launch_path=async_camoufox");
    j["service_workers"] = block_service_workers ? std::string("block") : std::string("allow");
    j["block_service_workers"] = block_service_workers;
    const std::string ua_policy = normalize_camoufox_ua_policy_for_sidecar(
        cfg.ua_policy,
        !trim_launch_token(cfg.user_agent).empty());
    j["ua_policy"] = ua_policy;
    j["aida_fast_visible_launch"] = false;
    j["aida_launch_policy_marker"] = "aida_camoufox_bridge_20260620_crash_diag_1";
    if (!cfg.user_agent.empty())
        j["user_agent"] = cfg.user_agent;
    j["enable_trace"] = cfg.enable_trace;
    j["window_width"] = cfg.window_width > 0 ? cfg.window_width : 1280;
    j["window_height"] = cfg.window_height > 0 ? cfg.window_height : 900;
    j["launch_timeout_ms"] = launch_timeout_ms;
    if (testlab_fast_probe)
        j["aida_testlab_fast_probe"] = true;
    const bool persistent_context_requested = explicit_persistent_context_requested(cfg);
    if (persistent_context_requested)
        j["persistent_context"] = true;
    if (!cfg.profile_dir.empty())
        j["profile_dir"] = cfg.profile_dir;
    if (!cfg.user_data_dir.empty())
        j["user_data_dir"] = cfg.user_data_dir;
    if (!cfg.proxy.empty()) j["proxy"] = cfg.proxy;
    if (!cfg.browser_executable.empty())
    {
        j["executable_path"] = cfg.browser_executable;
        j["ff_version"] = 152;
    }
    return j;
}

std::string camoufox_debug_log_path()
{
    char path[MAX_PATH] = {};
    if (diag::build_log_path("aida_camoufox_debug.log", path, sizeof(path)))
        return path;
    std::wstring dir = executable_dir_w();
    if (dir.empty()) return {};
    std::string out = wide_to_utf8(join_path_w(dir, L"aida_camoufox_debug.log"));
    return out;
}

std::string camoufox_working_dir_path()
{
    std::wstring dir = executable_dir_w();
    if (dir.empty()) dir = current_dir_w();
    return wide_to_utf8(dir);
}

std::string camoufox_profile_root_path()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) root = executable_dir_w();
    if (root.empty()) root = current_dir_w();
    if (root.empty()) return {};
    return wide_to_utf8(join_path_w(root, L"camoufox-profiles"));
}

void populate_internal_camoufox_env(mcp_client::server_config_t& scfg, const std::string& session_id, const std::string& browser_executable, const std::string& debug_log)
{
    scfg.env["PYTHONIOENCODING"] = "utf-8";
    scfg.env["AIDA_CAMOUFOX_DEBUG_LOG"] = debug_log;
    scfg.env["AIDA_CAMOUFOX_SESSION_ID"] = session_id.empty() ? std::string("default") : session_id;
    const std::string work_dir = camoufox_working_dir_path();
    if (!work_dir.empty())
        scfg.env["AIDA_CAMOUFOX_WORKING_DIR"] = work_dir;
    const std::string profile_root = camoufox_profile_root_path();
    if (!profile_root.empty())
        scfg.env["AIDA_CAMOUFOX_PROFILE_ROOT"] = profile_root;
    if (!browser_executable.empty())
        scfg.env["AIDA_CAMOUFOX_EXECUTABLE"] = browser_executable;
}

int json_int_or(const nlohmann::json& j, const char* key, int fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end()) return fallback;
    if (it->is_number_integer() || it->is_number_unsigned()) return it->get<int>();
    if (it->is_number_float()) return static_cast<int>(it->get<double>());
    return fallback;
}

double json_double_or(const nlohmann::json& j, const char* key, double fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return fallback;
    return it->get<double>();
}

std::string json_string_or(const nlohmann::json& j, const char* key, const std::string& fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return fallback;
    return it->get<std::string>();
}

bool extract_json_object_at(const std::string& text, std::size_t begin, std::string& out)
{
    out.clear();
    while (begin < text.size() && (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r' || text[begin] == '\n'))
        ++begin;
    if (begin >= text.size() || text[begin] != '{')
        return false;
    bool in_string = false;
    bool escaped = false;
    int depth = 0;
    for (std::size_t i = begin; i < text.size(); ++i)
    {
        const char c = text[i];
        if (in_string)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (c == '\\')
            {
                escaped = true;
            }
            else if (c == '"')
            {
                in_string = false;
            }
            continue;
        }
        if (c == '"')
        {
            in_string = true;
            continue;
        }
        if (c == '{')
        {
            ++depth;
            continue;
        }
        if (c == '}')
        {
            --depth;
            if (depth == 0)
            {
                out = text.substr(begin, i - begin + 1);
                return true;
            }
            if (depth < 0)
                return false;
        }
    }
    return false;
}

std::string last_camoufox_debug_event_from_tail(const std::string& tail)
{
    if (tail.empty()) return {};
    const std::string prefix = "AIDA_CAMOUFOX ";
    std::size_t search_end = tail.size();
    while (search_end > 0)
    {
        std::size_t pos = tail.rfind(prefix, search_end - 1);
        if (pos != std::string::npos)
        {
            std::string json_text;
            if (extract_json_object_at(tail, pos + prefix.size(), json_text))
            {
                nlohmann::json parsed = nlohmann::json::parse(json_text, nullptr, false);
                if (parsed.is_object())
                {
                    std::string event = json_string_or(parsed, "event", std::string());
                    if (!event.empty())
                    {
                        std::string out = event;
                        const int elapsed = json_int_or(parsed, "elapsed_ms", -1);
                        const int uptime = json_int_or(parsed, "uptime_ms", -1);
                        if (elapsed >= 0)
                            out += " elapsed_ms=" + std::to_string(elapsed);
                        if (uptime >= 0)
                            out += " uptime_ms=" + std::to_string(uptime);
                        return out;
                    }
                }
            }
            search_end = pos;
            continue;
        }
        break;
    }
    return {};
}

nlohmann::json last_camoufox_debug_event_json_from_tail(const std::string& tail)
{
    if (tail.empty()) return nlohmann::json::object();
    const std::string prefix = "AIDA_CAMOUFOX ";
    std::size_t search_end = tail.size();
    while (search_end > 0)
    {
        std::size_t pos = tail.rfind(prefix, search_end - 1);
        if (pos != std::string::npos)
        {
            std::string json_text;
            if (extract_json_object_at(tail, pos + prefix.size(), json_text))
            {
                nlohmann::json parsed = nlohmann::json::parse(json_text, nullptr, false);
                if (parsed.is_object() && !json_string_or(parsed, "event", std::string()).empty())
                    return parsed;
            }
            search_end = pos;
            continue;
        }
        break;
    }
    return nlohmann::json::object();
}

std::string sidecar_timeout_phase_from_event(const nlohmann::json& event, const std::string& fallback)
{
    const std::string name = json_string_or(event, "event", std::string());
    const std::string phase = json_string_or(event, "phase", std::string());
    if (name.find("new_page_timeout") != std::string::npos || phase == "new_page" || phase == "page_creation_timeout")
        return "page_creation_timeout";
    if (name.find("page_closed_during_launch") != std::string::npos)
        return "page_closed_during_launch";
    if (name.find("launch_terminal_event") != std::string::npos)
        return json_string_or(event, "reason", std::string("launch_terminal_event"));
    if (name.find("privacy_verify") != std::string::npos || phase == "privacy_verify")
        return "privacy_verify";
    if (name.find("browser_disconnected") != std::string::npos)
        return "browser_disconnected";
    if (name.find("launch_phase_timeout") != std::string::npos && !phase.empty())
        return phase == "new_page" ? "page_creation_timeout" : phase;
    if (!phase.empty())
        return phase == "new_page" ? "page_creation_timeout" : phase;
    return fallback;
}

bool sidecar_launch_terminal_event(const nlohmann::json& event, std::string& reason)
{
    reason.clear();
    if (!event.is_object())
        return false;
    const std::string name = json_string_or(event, "event", std::string());
    const std::string phase = json_string_or(event, "phase", std::string());
    const std::string active_phase = json_string_or(event, "active_launch_phase", std::string());
    const std::string error_kind = json_string_or(event, "error_kind", std::string());
    if (name.empty() && phase.empty() && active_phase.empty() && error_kind.empty())
        return false;
    if (name == "launch_ready" || active_phase == "launch_ready")
        return false;
    if (name == "page_closed_during_launch")
    {
        reason = "page_closed_during_launch";
        return true;
    }
    if (name == "launch_terminal_event")
    {
        reason = json_string_or(event, "reason", std::string("launch_terminal_event"));
        return true;
    }
    if (name == "browser_disconnected")
    {
        reason = "browser_disconnected";
        return true;
    }
    if (name == "subprocess_exit")
    {
        const int exit_code = json_int_or(event, "exit_code", static_cast<int>(STILL_ACTIVE));
        if (exit_code != static_cast<int>(STILL_ACTIVE))
        {
            reason = std::string("subprocess_exit_") + std::to_string(exit_code);
            return true;
        }
    }
    if (name == "launch_error" || name.find("launch_error_") == 0)
    {
        reason = name;
        return true;
    }
    if (error_kind == "target_closed" ||
        error_kind == "browser_disconnected" ||
        error_kind == "browser_closed" ||
        error_kind == "context_closed" ||
        error_kind == "page_crash")
    {
        reason = error_kind;
        return true;
    }
    if (!active_phase.empty() && active_phase != "launch_ready")
    {
        auto browser_connected_it = event.find("browser_connected");
        if (browser_connected_it != event.end() && browser_connected_it->is_boolean() && !browser_connected_it->get<bool>())
        {
            reason = "browser_disconnected_during_" + active_phase;
            return true;
        }
    }
    return false;
}

void attach_debug_log_snapshot_locked(nlohmann::json& out,
                                      uint32_t child_pid,
                                      const std::string& debug_log,
                                      const std::string& debug_tail)
{
    if (!out.is_object())
        out = nlohmann::json::object();
    const nlohmann::json last_event = last_camoufox_debug_event_json_from_tail(debug_tail);
    const std::string last_event_name = json_string_or(last_event, "event", std::string());
    out["child_debug_log"] = debug_log;
    out["debug_log_size"] = file_size_for_log(debug_log);
    out["debug_tail_len"] = debug_tail.size();
    out["last_debug_event_name"] = last_event_name;
    out["last_debug_event"] = last_event.is_object() ? last_event : nlohmann::json::object();
    out["last_debug_event_summary"] = last_camoufox_debug_event_from_tail(debug_tail);
    out["active_operations"] = sg().active_activities.load(std::memory_order_acquire);
    out["stop_requested"] = sg().stop_requested.load(std::memory_order_acquire);
    out["stop_epoch"] = sg().stop_epoch.load(std::memory_order_acquire);
    out["cleanup_pending"] = sg().cleanup_pending;
    out["cleanup_generation"] = sg().cleanup_generation;
    out["cleanup_child_pid"] = sg().cleanup_child_pid;
    out["cleanup_reason"] = sg().cleanup_reason;
    if (sg().cleanup_diagnostics.is_object() && out.find("cleanup_diagnostics") == out.end())
        out["cleanup_diagnostics"] = sg().cleanup_diagnostics;
    if (child_pid != 0 && out.find("process_tree") == out.end())
    {
        const std::vector<process_tree_entry_t> tree = enumerate_process_tree(child_pid);
        out["process_tree"] = compact_process_tree(tree);
        out["process_tree_count"] = tree.size();
        out["browser_process_count"] = browser_process_count_from_tree(tree);
    }
    const char* copy_keys[] = {
        "selected_launch_path", "context_id", "page_id", "requested_page_id", "queue_len",
        "pending_queue_len", "pending_page_task", "context_page_count", "registered_pages",
        "page_event_count", "browser_context_count", "browser_connected", "browser_open",
        "error_type", "error_kind", "error_summary", "phase", "elapsed_ms", "remaining_ms",
        "launch_attempt_id", "attempt_id", "active_launch_phase", "last_debug_event_name",
        "recent_page_events", "active_page_id"
    };
    for (const char* key : copy_keys)
    {
        auto it = last_event.find(key);
        if (it != last_event.end() && out.find(key) == out.end())
            out[key] = *it;
    }
}

std::string launch_profile_dir_from_response(const nlohmann::json& parsed)
{
    if (!parsed.is_object())
        return {};
    auto diagnostics_it = parsed.find("diagnostics");
    if (diagnostics_it == parsed.end() || !diagnostics_it->is_object())
        return {};
    auto profile_it = diagnostics_it->find("profile");
    if (profile_it == diagnostics_it->end() || !profile_it->is_object())
        return {};
    return json_string_or(*profile_it, "profile_dir", std::string());
}

bool json_bool_or(const nlohmann::json& j, const char* key, bool fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_boolean()) return fallback;
    return it->get<bool>();
}

bool launch_profile_generated_from_response(const nlohmann::json& parsed)
{
    if (!parsed.is_object())
        return false;
    auto diagnostics_it = parsed.find("diagnostics");
    if (diagnostics_it == parsed.end() || !diagnostics_it->is_object())
        return false;
    auto profile_it = diagnostics_it->find("profile");
    if (profile_it == diagnostics_it->end() || !profile_it->is_object())
        return false;
    return json_bool_or(*profile_it, "generated", false);
}

std::string json_string_nested_or(const nlohmann::json& j, const char* key, const char* nested_key, const std::string& fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it != j.end() && it->is_string())
        return it->get<std::string>();
    if (nested_key)
    {
        auto nested = j.find(nested_key);
        if (nested != j.end() && nested->is_string())
            return nested->get<std::string>();
    }
    return fallback;
}

nlohmann::json privacy_diagnostics_from_response(const nlohmann::json& parsed)
{
    if (!parsed.is_object())
        return nlohmann::json::object();
    auto diagnostics_it = parsed.find("diagnostics");
    if (diagnostics_it != parsed.end() && diagnostics_it->is_object())
    {
        auto privacy_it = diagnostics_it->find("privacy");
        if (privacy_it != diagnostics_it->end() && privacy_it->is_object())
            return *privacy_it;
    }
    auto privacy_it = parsed.find("privacy");
    if (privacy_it != parsed.end() && privacy_it->is_object())
        return *privacy_it;
    return nlohmann::json::object();
}

nlohmann::json launch_diagnostics_from_response(const nlohmann::json& parsed)
{
    if (!parsed.is_object())
        return nlohmann::json::object();
    nlohmann::json out = nlohmann::json::object();
    auto diagnostics_it = parsed.find("diagnostics");
    if (diagnostics_it != parsed.end() && diagnostics_it->is_object())
        out = *diagnostics_it;
    const char* copy_keys[] = {
        "status", "phase", "timeout_phase", "exception_type", "exception_repr",
        "elapsed_ms", "remaining_ms", "session_id", "generation", "attempt_id",
        "launch_attempt_id", "error_type", "error_kind", "error_summary",
        "browser_open", "browser_connected", "context_count", "page_count",
        "registered_pages", "active_page_id", "active_launch_phase",
        "last_debug_event_name", "last_debug_event", "recent_page_events",
        "cleanup_summary", "cleanup_stderr_tail_len"
    };
    for (const char* key : copy_keys)
    {
        auto it = parsed.find(key);
        if (it != parsed.end() && out.find(key) == out.end())
            out[key] = *it;
    }
    auto err = parsed.find("error");
    if (err != parsed.end() && out.find("error") == out.end())
        out["error"] = *err;
    return out;
}

std::string sidecar_failure_text(const nlohmann::json& parsed, const nlohmann::json& diagnostics, const std::string& fallback)
{
    std::string error = json_string_or(parsed, "error", std::string());
    if (error.empty())
        error = json_string_or(diagnostics, "error", std::string());
    if (!error.empty())
        return error;
    std::string error_summary = json_string_or(parsed, "error_summary", json_string_or(diagnostics, "error_summary", std::string()));
    std::string error_type = json_string_or(parsed, "error_type", json_string_or(diagnostics, "error_type", std::string()));
    std::string error_kind = json_string_or(parsed, "error_kind", json_string_or(diagnostics, "error_kind", std::string()));
    std::string phase = json_string_or(parsed, "phase", json_string_or(diagnostics, "phase", std::string()));
    std::string last_event_name = json_string_or(parsed, "last_debug_event_name", json_string_or(diagnostics, "last_debug_event_name", std::string()));
    nlohmann::json event = nlohmann::json::object();
    auto event_it = diagnostics.find("last_debug_event");
    if (event_it != diagnostics.end() && event_it->is_object())
        event = *event_it;
    else
    {
        auto parsed_event_it = parsed.find("last_debug_event");
        if (parsed_event_it != parsed.end() && parsed_event_it->is_object())
            event = *parsed_event_it;
    }
    if (last_event_name.empty())
        last_event_name = json_string_or(event, "event", std::string());
    if (phase.empty())
        phase = json_string_or(event, "phase", std::string());
    if (!error_summary.empty())
        return error_summary;
    std::string out = error_type.empty() ? std::string("sidecar launch failure") : error_type;
    if (!error_kind.empty() && error_kind != error_type)
        out += " kind=" + error_kind;
    if (!phase.empty())
        out += " phase=" + phase;
    if (!last_event_name.empty())
        out += " last_event=" + last_event_name;
    if (out == "sidecar launch failure" && !fallback.empty())
        return fallback;
    return out;
}

nlohmann::json launch_failure_diagnostics_snapshot(
    nlohmann::json existing,
    const char* status,
    const char* phase,
    uint64_t generation,
    const std::string& session_id,
    const std::string& attempt_id,
    uint32_t child_pid,
    int requested_ms,
    int effective_ms,
    uint64_t elapsed_ms,
    const std::string& error_text,
    const std::string& response_text)
{
    if (!existing.is_object())
        existing = nlohmann::json::object();
    const bool alive = process_alive(child_pid);
    const std::vector<process_tree_entry_t> tree = child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(child_pid);
    const uint32_t child_process_count = static_cast<uint32_t>(tree.size());
    const uint32_t browser_process_count = browser_process_count_from_tree(tree);
    const uint32_t browser_instance_count = (sg().browser_open && alive && child_pid != 0) ? 1u : 0u;
    nlohmann::json out = existing;
    out["status"] = status ? status : "";
    out["phase"] = phase ? phase : "";
    out["generation"] = generation;
    out["session_id"] = session_id.empty() ? std::string("default") : session_id;
    out["attempt_id"] = attempt_id;
    out["child_pid"] = child_pid;
    out["child_alive"] = alive;
    out["requested_ms"] = requested_ms;
    out["effective_ms"] = effective_ms;
    out["elapsed_ms"] = elapsed_ms;
    out["bridge_state"] = bridge_state_name(sg().state);
    out["browser_open"] = sg().browser_open;
    out["page_verified"] = sg().page_verified;
    out["privacy_verified"] = sg().privacy_verified;
    out["webrtc_blocked"] = sg().webrtc_blocked;
    out["cleanup_pending"] = sg().cleanup_pending;
    out["active_page_id"] = sg().active_page_id;
    out["page_count"] = sg().pages.size();
    out["browser_instance_count"] = browser_instance_count;
    out["child_process_count"] = child_process_count;
    out["browser_process_count"] = browser_process_count;
    out["process_tree_count"] = child_process_count;
    out["process_tree"] = compact_process_tree(tree);
    out["error_len"] = error_text.size();
    out["error_tail"] = compact_child_output_tail(error_text, 900);
    out["response_len"] = response_text.size();
    out["response_tail"] = compact_child_output_tail(response_text, 900);
    const std::string debug_log = camoufox_debug_log_path();
    const std::string debug_tail = read_file_tail_for_log(debug_log, 6000);
    attach_debug_log_snapshot_locked(out, child_pid, debug_log, debug_tail);
    return out;
}

nlohmann::json managed_launch_failure_diagnostics_snapshot(
    const managed_session_t& session,
    nlohmann::json existing,
    const char* status,
    const char* phase,
    uint64_t generation,
    const std::string& attempt_id,
    uint32_t child_pid,
    int requested_ms,
    int effective_ms,
    uint64_t elapsed_ms,
    const std::string& error_text,
    const std::string& response_text)
{
    if (!existing.is_object())
        existing = nlohmann::json::object();
    const bool alive = process_alive(child_pid);
    const std::vector<process_tree_entry_t> tree = child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(child_pid);
    const uint32_t child_process_count = static_cast<uint32_t>(tree.size());
    const uint32_t browser_process_count = browser_process_count_from_tree(tree);
    const uint32_t browser_instance_count = (session.browser_open && alive && child_pid != 0) ? 1u : 0u;
    nlohmann::json out = existing;
    out["status"] = status ? status : "";
    out["phase"] = phase ? phase : "";
    out["generation"] = generation;
    out["session_id"] = session.session_id.empty() ? std::string("default") : session.session_id;
    out["attempt_id"] = attempt_id;
    out["child_pid"] = child_pid;
    out["child_alive"] = alive;
    out["requested_ms"] = requested_ms;
    out["effective_ms"] = effective_ms;
    out["elapsed_ms"] = elapsed_ms;
    out["bridge_state"] = bridge_state_name(session.state);
    out["browser_open"] = session.browser_open;
    out["page_verified"] = session.page_verified;
    out["privacy_verified"] = session.privacy_verified;
    out["webrtc_blocked"] = session.webrtc_blocked;
    out["cleanup_pending"] = session.cleanup_pending;
    out["active_page_id"] = session.active_page_id;
    out["page_count"] = session.pages.size();
    out["browser_instance_count"] = browser_instance_count;
    out["child_process_count"] = child_process_count;
    out["browser_process_count"] = browser_process_count;
    out["process_tree_count"] = child_process_count;
    out["process_tree"] = compact_process_tree(tree);
    out["error_len"] = error_text.size();
    out["error_tail"] = compact_child_output_tail(error_text, 900);
    out["response_len"] = response_text.size();
    out["response_tail"] = compact_child_output_tail(response_text, 900);
    const std::string debug_log = camoufox_debug_log_path();
    const std::string debug_tail = read_file_tail_for_log(debug_log, 6000);
    const nlohmann::json last_event = last_camoufox_debug_event_json_from_tail(debug_tail);
    out["child_debug_log"] = debug_log;
    out["debug_log_size"] = file_size_for_log(debug_log);
    out["debug_tail_len"] = debug_tail.size();
    out["last_debug_event_name"] = json_string_or(last_event, "event", std::string());
    out["last_debug_event"] = last_event.is_object() ? last_event : nlohmann::json::object();
    out["last_debug_event_summary"] = last_camoufox_debug_event_from_tail(debug_tail);
    out["selected_launch_path"] = json_string_or(last_event, "selected_launch_path", json_string_or(out, "selected_launch_path", std::string()));
    return out;
}

std::string status_json_string_first(const nlohmann::json& j, std::initializer_list<const char*> keys)
{
    if (!j.is_object()) return {};
    for (const char* key : keys)
    {
        auto it = j.find(key);
        if (it != j.end() && it->is_string())
        {
            std::string value = it->get<std::string>();
            if (!value.empty())
                return value;
        }
    }
    return {};
}

nlohmann::json status_last_debug_event_object(const nlohmann::json& diag)
{
    if (!diag.is_object()) return nlohmann::json::object();
    auto it = diag.find("last_debug_event");
    if (it != diag.end() && it->is_object())
        return *it;
    return nlohmann::json::object();
}

bool status_evidence_contains(const bridge_status_t& s, const nlohmann::json& diag, std::initializer_list<const char*> needles)
{
    std::string evidence;
    evidence.reserve(2048);
    evidence += s.last_error;
    evidence.push_back(' ');
    evidence += s.phase;
    evidence.push_back(' ');
    evidence += s.error_type;
    evidence.push_back(' ');
    evidence += s.error_kind;
    evidence.push_back(' ');
    evidence += s.last_debug_event;
    if (diag.is_object())
    {
        std::string dumped = diag.dump();
        if (dumped.size() > 12000)
            dumped.resize(12000);
        evidence.push_back(' ');
        evidence += dumped;
    }
    evidence = ascii_lower_copy(std::move(evidence));
    for (const char* needle : needles)
    {
        if (needle && needle[0] && evidence.find(ascii_lower_copy(std::string(needle))) != std::string::npos)
            return true;
    }
    return false;
}

int status_visible_window_count_from_diag(const nlohmann::json& diag)
{
    if (!diag.is_object()) return -1;
    auto proof_it = diag.find("visible_window_proof");
    if (proof_it != diag.end() && proof_it->is_object())
    {
        const int from_count = json_int_or(*proof_it, "visible_window_count", -1);
        if (from_count >= 0)
            return from_count;
    }
    return json_int_or(diag, "visible_window_count", -1);
}

int status_diag_page_count(const bridge_status_t& s, const nlohmann::json& diag, const nlohmann::json& event)
{
    int count = json_int_or(diag, "registered_pages", -1);
    count = std::max(count, json_int_or(diag, "page_count", -1));
    count = std::max(count, json_int_or(diag, "context_page_count", -1));
    count = std::max(count, json_int_or(event, "registered_pages", -1));
    count = std::max(count, json_int_or(event, "page_count", -1));
    count = std::max(count, json_int_or(event, "context_page_count", -1));
    if (count < 0 && s.page_count != 0)
        count = static_cast<int>(s.page_count);
    return count;
}

std::string status_derive_readiness_phase(const bridge_status_t& s, const nlohmann::json& diag, const nlohmann::json& event, bool client_connected)
{
    const bool fully_ready =
        s.state == bridge_state_t::ready &&
        client_connected &&
        s.child_alive &&
        s.browser_open &&
        s.page_verified &&
        s.privacy_verified &&
        !s.cleanup_pending &&
        usable_browser_process_count(s.browser_process_count) &&
        !is_driver_closed_error(s.last_error);
    if (fully_ready)
        return "ready";
    const int visible_count = status_visible_window_count_from_diag(diag);
    const bool visible_failed = visible_count == 0 ||
        status_evidence_contains(s, diag, {"visible_window_missing", "visible window proof", "visible_window_proof_failed"});
    const bool privacy_failed = status_evidence_contains(s, diag, {"privacy_not_verified", "privacy verification", "privacy_assertion_failed"}) ||
        (s.browser_open && s.page_verified && !s.privacy_verified);
    const bool diag_browser_connected = json_bool_or(diag, "browser_connected", false) ||
        json_bool_or(event, "browser_connected", false) ||
        json_bool_or(diag, "browser_open", false) ||
        json_bool_or(event, "browser_open", false);
    const int diag_pages = status_diag_page_count(s, diag, event);
    if (s.cleanup_pending)
        return "cleanup_pending";
    if (s.protocol_schema_viewport)
        return "protocol_schema_viewport";
    if (visible_failed)
        return "visible_window_proof_failed";
    if (privacy_failed)
        return "privacy_proof_failed";
    if (diag_browser_connected && (diag_pages == 0 || !s.page_verified))
        return "browser_connected_no_page";
    if (s.child_pid == 0)
        return "child_not_launched";
    if (!s.child_alive)
        return "child_not_alive";
    if (!client_connected)
        return "mcp_client_detached";
    if (!s.browser_open)
        return "browser_not_open";
    if (!s.page_verified)
        return "page_not_verified";
    if (!s.privacy_verified)
        return "privacy_proof_failed";
    if (!usable_browser_process_count(s.browser_process_count))
        return "browser_process_tree_empty";
    if (s.state == bridge_state_t::starting)
        return "starting";
    if (s.state == bridge_state_t::stopped)
        return "stopped";
    return "error";
}

void populate_status_diagnostic_fields(bridge_status_t& s, uint64_t sampled_ms, bool client_connected)
{
    const nlohmann::json diag = s.last_launch_diagnostics.is_object() ? s.last_launch_diagnostics : nlohmann::json::object();
    const nlohmann::json event = status_last_debug_event_object(diag);
    s.phase = status_json_string_first(diag, {"phase", "timeout_phase", "sidecar_timeout_phase", "transport_phase", "active_launch_phase", "status"});
    if (s.phase.empty())
        s.phase = status_json_string_first(event, {"phase", "event"});
    s.error_type = status_json_string_first(diag, {"sidecar_error_type", "error_type", "exception_type"});
    if (s.error_type.empty())
        s.error_type = status_json_string_first(event, {"error_type", "exception_type"});
    s.error_kind = status_json_string_first(diag, {"sidecar_error_kind", "error_kind"});
    if (s.error_kind.empty())
        s.error_kind = status_json_string_first(event, {"error_kind"});
    s.last_debug_event = status_json_string_first(diag, {"last_debug_event_name", "last_debug_event_summary"});
    if (s.last_debug_event.empty())
        s.last_debug_event = status_json_string_first(event, {"event", "phase"});
    s.protocol_schema_viewport =
        ascii_lower_copy(s.error_kind) == "protocol_schema_viewport" ||
        status_evidence_contains(s, diag, {"protocol_schema_viewport", "browser.setdefaultviewport", "setdefaultviewport", "deviceScaleFactor", "isMobile"});
    if (s.attempt_started_ms != 0)
    {
        if (s.state == bridge_state_t::starting && sampled_ms >= s.attempt_started_ms)
            s.attempt_elapsed_ms = sampled_ms - s.attempt_started_ms;
        else if (s.last_launch_ms != 0)
            s.attempt_elapsed_ms = s.last_launch_ms;
        else if (s.attempt_elapsed_ms == 0 && sampled_ms >= s.attempt_started_ms)
            s.attempt_elapsed_ms = sampled_ms - s.attempt_started_ms;
    }
    if (s.state != bridge_state_t::starting && s.last_launch_ms != 0)
        s.last_attempt_elapsed_ms = s.last_launch_ms;
    else if (s.last_attempt_elapsed_ms == 0)
        s.last_attempt_elapsed_ms = s.attempt_elapsed_ms != 0 ? s.attempt_elapsed_ms : s.last_launch_ms;
    uint64_t age_ref = s.last_verified_ms != 0 ? s.last_verified_ms : s.last_call_ms;
    if (age_ref == 0)
        age_ref = s.launched_ms;
    if (age_ref == 0)
        age_ref = s.attempt_started_ms;
    s.status_age_ms = age_ref != 0 && sampled_ms >= age_ref ? sampled_ms - age_ref : 0;
    s.readiness_phase = status_derive_readiness_phase(s, diag, event, client_connected);
    if (s.last_launch_diagnostics.is_object())
    {
        s.last_launch_diagnostics["attempt_started_ms"] = s.attempt_started_ms;
        s.last_launch_diagnostics["attempt_elapsed_ms"] = s.attempt_elapsed_ms;
        s.last_launch_diagnostics["last_attempt_elapsed_ms"] = s.last_attempt_elapsed_ms;
        s.last_launch_diagnostics["status_age_ms"] = s.status_age_ms;
        s.last_launch_diagnostics["readiness_phase"] = s.readiness_phase;
        s.last_launch_diagnostics["protocol_schema_viewport"] = s.protocol_schema_viewport;
        if (!s.phase.empty())
            s.last_launch_diagnostics["phase_flat"] = s.phase;
        if (!s.error_type.empty())
            s.last_launch_diagnostics["error_type_flat"] = s.error_type;
        if (!s.error_kind.empty())
            s.last_launch_diagnostics["error_kind_flat"] = s.error_kind;
        if (!s.last_debug_event.empty())
            s.last_launch_diagnostics["last_debug_event_flat"] = s.last_debug_event;
    }
}

bool normalize_privacy_ice_fields(nlohmann::json& privacy)
{
    if (!privacy.is_object())
        return false;
    const bool webrtc_blocked = json_bool_or(privacy, "webrtc_blocked", false);
    const bool rtc_disabled = json_string_or(privacy, "rtc_peer_connection", std::string()) == "undefined" &&
        json_string_or(privacy, "moz_rtc_peer_connection", std::string()) == "undefined";
    if (!webrtc_blocked || !rtc_disabled)
        return false;
    bool synthesized = false;
    if (privacy.find("ice_probe_ok") == privacy.end())
    {
        privacy["ice_probe_ok"] = true;
        synthesized = true;
    }
    if (privacy.find("ice_candidate_leak_detected") == privacy.end())
    {
        privacy["ice_candidate_leak_detected"] = false;
        synthesized = true;
    }
    if (privacy.find("ice_probe_status") == privacy.end())
        privacy["ice_probe_status"] = "webrtc_api_disabled";
    if (privacy.find("ice_probe_blocked") == privacy.end())
        privacy["ice_probe_blocked"] = true;
    if (privacy.find("ice_candidate_count") == privacy.end())
        privacy["ice_candidate_count"] = 0;
    if (privacy.find("ice_candidate_ip_count") == privacy.end())
        privacy["ice_candidate_ip_count"] = 0;
    if (privacy.find("ice_host_ip_candidate_count") == privacy.end())
        privacy["ice_host_ip_candidate_count"] = 0;
    if (privacy.find("ice_private_ip_candidate_count") == privacy.end())
        privacy["ice_private_ip_candidate_count"] = 0;
    if (privacy.find("ice_public_ip_candidate_count") == privacy.end())
        privacy["ice_public_ip_candidate_count"] = 0;
    return synthesized;
}

void clear_privacy_locked()
{
    sg().effective_ua_policy = "camoufox_native";
    sg().ua_override_string.clear();
    sg().ua_override = false;
    sg().webrtc_blocked = false;
    sg().privacy_verified = false;
    sg().privacy_diagnostics = nlohmann::json::object();
}

void clear_privacy_locked(managed_session_t& session)
{
    session.effective_ua_policy = "camoufox_native";
    session.ua_override_string.clear();
    session.ua_override = false;
    session.webrtc_blocked = false;
    session.privacy_verified = false;
    session.privacy_diagnostics = nlohmann::json::object();
}

void update_privacy_from_response_locked(const nlohmann::json& parsed, const char* source)
{
    nlohmann::json privacy = privacy_diagnostics_from_response(parsed);
    if (!privacy.is_object() || privacy.empty())
        return;
    const bool compat_ice_synthesized = normalize_privacy_ice_fields(privacy);
    sg().privacy_diagnostics = privacy;
    sg().effective_ua_policy = json_string_nested_or(privacy, "effective_ua_policy", "ua_policy", "camoufox_native");
    sg().ua_override = json_bool_or(privacy, "ua_override", false);
    sg().ua_override_string = json_string_or(privacy, "ua_override_string", std::string());
    sg().webrtc_blocked = json_bool_or(privacy, "webrtc_blocked", false);
    const bool webdriver_ok = json_bool_or(privacy, "webdriver_ok", false);
    const bool platform_ok = json_bool_or(privacy, "platform_ok", true);
    const bool oscpu_ok = json_bool_or(privacy, "oscpu_ok", true);
    const bool ice_ok = json_bool_or(privacy, "ice_probe_ok", false);
    const bool ice_leak = json_bool_or(privacy, "ice_candidate_leak_detected", true);
    sg().privacy_verified = sg().webrtc_blocked && webdriver_ok && platform_ok && oscpu_ok && ice_ok && !ice_leak;
    diag::log_tagged_fmt("camoufox", "privacy_status_update source=%s ua_policy=%s ua_override=%d ua_override_len=%zu webrtc_blocked=%d webdriver_ok=%d platform_ok=%d oscpu_ok=%d ice_ok=%d ice_leak=%d ice_status=%s compat_ice_synth=%d",
        source ? source : "unknown",
        sg().effective_ua_policy.c_str(),
        sg().ua_override ? 1 : 0,
        sg().ua_override_string.size(),
        sg().webrtc_blocked ? 1 : 0,
        webdriver_ok ? 1 : 0,
        platform_ok ? 1 : 0,
        oscpu_ok ? 1 : 0,
        ice_ok ? 1 : 0,
        ice_leak ? 1 : 0,
        json_string_or(privacy, "ice_probe_status", std::string()).c_str(),
        compat_ice_synthesized ? 1 : 0);
}

void update_privacy_from_response_locked(managed_session_t& session, const nlohmann::json& parsed, const char* source)
{
    nlohmann::json privacy = privacy_diagnostics_from_response(parsed);
    if (!privacy.is_object() || privacy.empty())
        return;
    const bool compat_ice_synthesized = normalize_privacy_ice_fields(privacy);
    session.privacy_diagnostics = privacy;
    session.effective_ua_policy = json_string_nested_or(privacy, "effective_ua_policy", "ua_policy", "camoufox_native");
    session.ua_override = json_bool_or(privacy, "ua_override", false);
    session.ua_override_string = json_string_or(privacy, "ua_override_string", std::string());
    session.webrtc_blocked = json_bool_or(privacy, "webrtc_blocked", false);
    const bool webdriver_ok = json_bool_or(privacy, "webdriver_ok", false);
    const bool platform_ok = json_bool_or(privacy, "platform_ok", true);
    const bool oscpu_ok = json_bool_or(privacy, "oscpu_ok", true);
    const bool ice_ok = json_bool_or(privacy, "ice_probe_ok", false);
    const bool ice_leak = json_bool_or(privacy, "ice_candidate_leak_detected", true);
    session.privacy_verified = session.webrtc_blocked && webdriver_ok && platform_ok && oscpu_ok && ice_ok && !ice_leak;
    diag::log_tagged_fmt("camoufox", "privacy_status_update session_id=%s source=%s ua_policy=%s ua_override=%d ua_override_len=%zu webrtc_blocked=%d webdriver_ok=%d platform_ok=%d oscpu_ok=%d ice_ok=%d ice_leak=%d ice_status=%s compat_ice_synth=%d",
        session.session_id.c_str(),
        source ? source : "unknown",
        session.effective_ua_policy.c_str(),
        session.ua_override ? 1 : 0,
        session.ua_override_string.size(),
        session.webrtc_blocked ? 1 : 0,
        webdriver_ok ? 1 : 0,
        platform_ok ? 1 : 0,
        oscpu_ok ? 1 : 0,
        ice_ok ? 1 : 0,
        ice_leak ? 1 : 0,
        json_string_or(privacy, "ice_probe_status", std::string()).c_str(),
        compat_ice_synthesized ? 1 : 0);
}

size_t json_array_size_or_zero(const nlohmann::json& j, const char* key)
{
    if (!j.is_object()) return 0;
    auto it = j.find(key);
    if (it == j.end() || !it->is_array()) return 0;
    return it->size();
}

uint64_t json_u64_or(const nlohmann::json& j, const char* key, uint64_t fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end()) return fallback;
    if (it->is_number_unsigned()) return it->get<uint64_t>();
    if (it->is_number_integer()) return static_cast<uint64_t>(it->get<int64_t>());
    return fallback;
}

page_status_t page_status_from_json(const nlohmann::json& j)
{
    page_status_t p;
    if (!j.is_object()) return p;
    p.page_id      = json_string_or(j, "page_id", std::string());
    p.context_id   = json_string_or(j, "context_id", std::string());
    p.url          = json_string_or(j, "url", std::string());
    p.title        = json_string_or(j, "title", std::string());
    p.guid         = json_string_or(j, "guid", std::string());
    p.active       = json_bool_or(j, "active", false);
    p.closed       = json_bool_or(j, "closed", false);
    p.created_ms   = json_u64_or(j, "created_ms", 0);
    p.last_used_ms = json_u64_or(j, "last_used_ms", 0);
    return p;
}

bool page_cache_source_allows_direct_page_fields(const char* source)
{
    const std::string s = source ? std::string(source) : std::string();
    return s == "launch_readiness" ||
           s == "managed_readiness" ||
           s == "navigate_response" ||
           s == "navigate_verify" ||
           s == "reload_verify" ||
           s == "get_page_info" ||
           s == "legacy_page_target_select" ||
           s == "legacy_page_target_restore" ||
           s == "launch_browser" ||
           s == "list_pages" ||
           s == "new_page" ||
           s == "select_page" ||
           s == "close_page" ||
           s == "navigate" ||
           s == "reload";
}

bool page_cache_data_has_page_shape(const nlohmann::json& data, const char* source)
{
    if (!data.is_object()) return false;
    if (page_cache_source_allows_direct_page_fields(source)) return true;
    auto pages_it = data.find("pages");
    if (pages_it != data.end() && pages_it->is_array()) return true;
    auto page_it = data.find("page");
    if (page_it != data.end() && page_it->is_object()) return true;
    if (data.contains("active_page_id") && data["active_page_id"].is_string()) return true;
    if (!data.contains("page_id") || !data["page_id"].is_string()) return false;
    return (data.contains("title") && data["title"].is_string()) ||
           (data.contains("active") && data["active"].is_boolean()) ||
           (data.contains("closed") && data["closed"].is_boolean()) ||
           (data.contains("guid") && data["guid"].is_string()) ||
           data.contains("created_ms") ||
           data.contains("last_used_ms");
}

void merge_page_locked(const page_status_t& incoming)
{
    if (incoming.page_id.empty()) return;
    for (auto& existing : sg().pages)
    {
        if (existing.page_id == incoming.page_id)
        {
            existing = incoming;
            return;
        }
    }
    sg().pages.push_back(incoming);
}

void update_page_cache_from_json_locked(const nlohmann::json& data, const char* source)
{
    if (!data.is_object()) return;
    std::vector<page_status_t> parsed_pages;
    const bool page_shaped_response = page_cache_data_has_page_shape(data, source);
    auto pages_it = data.find("pages");
    if (pages_it != data.end() && pages_it->is_array())
    {
        for (const auto& item : *pages_it)
        {
            page_status_t p = page_status_from_json(item);
            if (!p.page_id.empty())
                parsed_pages.push_back(std::move(p));
        }
    }
    auto page_it = data.find("page");
    if (page_it != data.end() && page_it->is_object())
    {
        page_status_t p = page_status_from_json(*page_it);
        if (!p.page_id.empty())
            parsed_pages.push_back(std::move(p));
    }
    const std::string direct_page_id = page_shaped_response ? json_string_or(data, "page_id", std::string()) : std::string();
    if (!direct_page_id.empty())
    {
        bool already = false;
        for (const auto& p : parsed_pages)
        {
            if (p.page_id == direct_page_id)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            page_status_t p = page_status_from_json(data);
            if (p.page_id.empty()) p.page_id = direct_page_id;
            parsed_pages.push_back(std::move(p));
        }
    }
    if (pages_it != data.end() && pages_it->is_array())
        sg().pages.clear();
    for (const auto& p : parsed_pages)
        merge_page_locked(p);
    const std::string active_page_id = page_shaped_response ? json_string_or(data, "active_page_id", direct_page_id) : std::string();
    if (!active_page_id.empty())
        sg().active_page_id = active_page_id;
    if (sg().active_page_id.empty() && !sg().pages.empty())
        sg().active_page_id = sg().pages.front().page_id;
    if (page_shaped_response && data.contains("url") && data["url"].is_string())
        sg().active_page_url = data["url"].get<std::string>();
    if (page_shaped_response && data.contains("title") && data["title"].is_string())
        sg().active_page_title = data["title"].get<std::string>();
    for (const auto& p : sg().pages)
    {
        if (!sg().active_page_id.empty() && p.page_id == sg().active_page_id)
        {
            if (!p.url.empty()) sg().active_page_url = p.url;
            if (!p.title.empty()) sg().active_page_title = p.title;
            break;
        }
    }
    diag::log_tagged_fmt("camoufox", "page_cache_update source=%s active_page_id=%s page_count=%zu url_len=%zu title_len=%zu",
        source ? source : "unknown", sg().active_page_id.c_str(), sg().pages.size(),
        sg().active_page_url.size(), sg().active_page_title.size());
}

void merge_page_locked(managed_session_t& session, const page_status_t& incoming)
{
    if (incoming.page_id.empty()) return;
    for (auto& existing : session.pages)
    {
        if (existing.page_id == incoming.page_id)
        {
            existing = incoming;
            return;
        }
    }
    session.pages.push_back(incoming);
}

void update_page_cache_from_json_locked(managed_session_t& session, const nlohmann::json& data, const char* source)
{
    if (!data.is_object()) return;
    std::vector<page_status_t> parsed_pages;
    const bool page_shaped_response = page_cache_data_has_page_shape(data, source);
    auto pages_it = data.find("pages");
    if (pages_it != data.end() && pages_it->is_array())
    {
        for (const auto& item : *pages_it)
        {
            page_status_t p = page_status_from_json(item);
            if (!p.page_id.empty())
                parsed_pages.push_back(std::move(p));
        }
    }
    auto page_it = data.find("page");
    if (page_it != data.end() && page_it->is_object())
    {
        page_status_t p = page_status_from_json(*page_it);
        if (!p.page_id.empty())
            parsed_pages.push_back(std::move(p));
    }
    const std::string direct_page_id = page_shaped_response ? json_string_or(data, "page_id", std::string()) : std::string();
    if (!direct_page_id.empty())
    {
        bool already = false;
        for (const auto& p : parsed_pages)
        {
            if (p.page_id == direct_page_id)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            page_status_t p = page_status_from_json(data);
            if (p.page_id.empty()) p.page_id = direct_page_id;
            parsed_pages.push_back(std::move(p));
        }
    }
    if (pages_it != data.end() && pages_it->is_array())
        session.pages.clear();
    for (const auto& p : parsed_pages)
        merge_page_locked(session, p);
    const std::string active_page_id = page_shaped_response ? json_string_or(data, "active_page_id", direct_page_id) : std::string();
    if (!active_page_id.empty())
        session.active_page_id = active_page_id;
    if (session.active_page_id.empty() && !session.pages.empty())
        session.active_page_id = session.pages.front().page_id;
    if (page_shaped_response && data.contains("url") && data["url"].is_string())
        session.active_page_url = data["url"].get<std::string>();
    if (page_shaped_response && data.contains("title") && data["title"].is_string())
        session.active_page_title = data["title"].get<std::string>();
    for (const auto& p : session.pages)
    {
        if (!session.active_page_id.empty() && p.page_id == session.active_page_id)
        {
            if (!p.url.empty()) session.active_page_url = p.url;
            if (!p.title.empty()) session.active_page_title = p.title;
            break;
        }
    }
    diag::log_tagged_fmt("camoufox", "managed_page_cache_update session_id=%s source=%s active_page_id=%s page_count=%zu url_len=%zu title_len=%zu",
        session.session_id.c_str(), source ? source : "unknown", session.active_page_id.c_str(),
        session.pages.size(), session.active_page_url.size(), session.active_page_title.size());
}

std::string normalize_session_id(const std::string& session_id)
{
    std::string out = session_id.empty() ? std::string("default") : session_id;
    for (char& c : out)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '.';
        if (!ok) c = '_';
    }
    if (out.empty()) out = "default";
    if (out.size() > 96) out.resize(96);
    return out;
}

bool is_default_session_id(const std::string& session_id)
{
    const std::string normalized = normalize_session_id(session_id);
    return normalized == "default";
}

bool tool_accepts_page_id_directly(const std::string& tool_name)
{
    return tool_name == "launch_browser" ||
           tool_name == "close_browser" ||
           tool_name == "status" ||
           tool_name == "list_pages" ||
           tool_name == "new_page" ||
           tool_name == "select_page" ||
           tool_name == "close_page" ||
           tool_name == "navigate" ||
           tool_name == "reload" ||
           tool_name == "evaluate_js" ||
           tool_name == "take_screenshot" ||
           tool_name == "take_snapshot" ||
           tool_name == "network_capture" ||
           tool_name == "list_network_requests" ||
           tool_name == "get_network_request" ||
           tool_name == "get_request_initiator" ||
           tool_name == "intercept_request" ||
           tool_name == "scripts" ||
           tool_name == "search_code" ||
           tool_name == "cookies" ||
           tool_name == "get_storage" ||
           tool_name == "hook_function" ||
           tool_name == "add_init_script" ||
           tool_name == "inject_hook_preset" ||
           tool_name == "remove_hooks" ||
           tool_name == "analyze_cookie_sources" ||
           tool_name == "click" ||
           tool_name == "type_text" ||
           tool_name == "wait_for" ||
           tool_name == "get_page_info";
}

bool tool_accepts_aida_operation_id(const std::string& tool_name)
{
    return tool_name == "navigate" ||
           tool_name == "reload" ||
           tool_name == "evaluate_js" ||
           tool_name == "take_screenshot" ||
           tool_name == "take_snapshot" ||
           tool_name == "network_capture" ||
           tool_name == "list_network_requests" ||
           tool_name == "get_network_request" ||
           tool_name == "get_request_initiator" ||
           tool_name == "intercept_request" ||
           tool_name == "scripts" ||
           tool_name == "search_code" ||
           tool_name == "cookies" ||
           tool_name == "get_storage" ||
           tool_name == "hook_function" ||
           tool_name == "add_init_script" ||
           tool_name == "inject_hook_preset" ||
           tool_name == "remove_hooks" ||
           tool_name == "analyze_cookie_sources" ||
           tool_name == "click" ||
           tool_name == "type_text" ||
           tool_name == "wait_for" ||
           tool_name == "get_page_info";
}

void stamp_aida_operation_id(nlohmann::json& args, const std::string& tool_name, uint64_t request_id)
{
    if (!args.is_object() || request_id == 0 || !tool_accepts_aida_operation_id(tool_name))
        return;
    if (!args.contains("aida_operation_id"))
        args["aida_operation_id"] = request_id;
}

call_result_t page_target_select_failure(const std::string& tool_name, const std::string& session_id, const std::string& page_id, const call_result_t& select_result)
{
    call_result_t out;
    out.ok = false;
    out.error = std::string("camoufox page target select failed before ") + tool_name + " session_id=" + session_id + " page_id=" + page_id;
    if (!select_result.error.empty())
        out.error += std::string(": ") + select_result.error;
    out.data = nlohmann::json{
        {"error", out.error},
        {"session_id", session_id},
        {"page_id", page_id},
        {"tool", tool_name},
        {"select_page", select_result.data}
    };
    return out;
}

std::shared_ptr<managed_session_t> get_managed_session(const std::string& session_id, bool create)
{
    const std::string normalized = normalize_session_id(session_id);
    if (normalized == "default") return {};
    std::lock_guard<std::recursive_mutex> lk(sessions_mtx());
    auto& sessions = managed_sessions();
    auto it = sessions.find(normalized);
    if (it != sessions.end())
        return it->second;
    if (!create)
        return {};
    auto session = std::make_shared<managed_session_t>();
    session->session_id = normalized;
    session->active_cfg.session_id = normalized;
    sessions.emplace(normalized, session);
    return session;
}

uint32_t managed_session_count()
{
    std::lock_guard<std::recursive_mutex> lk(sessions_mtx());
    uint32_t count = 1;
    for (const auto& item : managed_sessions())
    {
        if (item.second)
            ++count;
    }
    return count;
}

}

bool ensure_python_available(std::string& out_python_path)
{
    const uint64_t t0 = now_ms();
    const bool allow_system_python = system_python_discovery_allowed();
    diag::log_tagged_fmt("camoufox", "ensure_python_available entry budget_ms=%llu",
        static_cast<unsigned long long>(kPythonDiscoveryBudgetMs));
    std::string cached_python_path;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        cached_python_path = sg().cached_python_path;
    }
    if (!cached_python_path.empty() && path_exists_w(utf8_to_wide(cached_python_path)))
    {
        if (!allow_system_python && !is_app_controlled_python_path(cached_python_path))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=system_python_discovery_disabled elapsed_ms=%llu",
                cached_python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0));
        }
        else
        {
            std::string reason;
            if (supported_camoufox_python(cached_python_path, &reason))
            {
                diag::log_tagged_fmt("camoufox", "ensure_python_available cached path=%s %s elapsed_ms=%llu",
                    cached_python_path.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
                out_python_path = cached_python_path;
                return true;
            }
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=%s elapsed_ms=%llu",
                cached_python_path.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
        }
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            if (_stricmp(sg().cached_python_path.c_str(), cached_python_path.c_str()) == 0)
                sg().cached_python_path.clear();
        }
    }
    std::vector<std::string> candidates;
    std::string env_python;
    if (read_env_path_a("AIDA_CAMOUFOX_PYTHON", env_python))
    {
        if (allow_system_python || is_app_controlled_python_path(env_python))
            candidates.push_back(env_python);
        else
            diag::log_tagged_fmt("camoufox", "ensure_python_available env_python_skipped path=%s policy=AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON", env_python.c_str());
    }
    append_bundled_python_candidates(candidates);
    append_app_local_python_candidates(candidates);
    const size_t app_controlled_candidates = candidates.size();
    if (allow_system_python)
    {
        std::string found;
        if (try_search_path(L"python.exe", found)) candidates.push_back(found);
        found.clear();
        if (try_search_path(L"python3.exe", found)) candidates.push_back(found);
        found.clear();
        if (try_known_python_roots(found)) candidates.push_back(found);
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "ensure_python_available system_python_candidates_skipped app_controlled_candidates=%zu policy=AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON",
            app_controlled_candidates);
    }
    std::vector<std::string> unique_candidates;
    for (const auto& candidate : candidates)
    {
        bool seen = false;
        for (const auto& existing : unique_candidates)
        {
            if (_stricmp(existing.c_str(), candidate.c_str()) == 0)
            {
                seen = true;
                break;
            }
        }
        if (!seen) unique_candidates.push_back(candidate);
    }
    candidates.swap(unique_candidates);
    diag::log_tagged_fmt("camoufox", "ensure_python_available candidate_count=%zu elapsed_ms=%llu",
        candidates.size(), static_cast<unsigned long long>(now_ms() - t0));
    for (size_t candidate_index = 0; candidate_index < candidates.size(); ++candidate_index)
    {
        const std::string& candidate = candidates[candidate_index];
        const uint64_t candidate_start_ms = now_ms();
        const uint64_t total_before_ms = candidate_start_ms >= t0 ? candidate_start_ms - t0 : 0;
        if (total_before_ms >= kPythonDiscoveryBudgetMs)
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available budget_exhausted before_candidate index=%zu total=%zu elapsed_ms=%llu",
                candidate_index, candidates.size(), static_cast<unsigned long long>(total_before_ms));
            break;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available candidate_begin index=%zu total=%zu path=%s elapsed_ms=%llu",
            candidate_index + 1, candidates.size(), candidate.c_str(), static_cast<unsigned long long>(total_before_ms));
        if (is_windows_store_python_alias(candidate))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=windows store python alias candidate_elapsed_ms=%llu elapsed_ms=%llu",
                candidate.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            continue;
        }
        std::string reason;
        if (!supported_camoufox_python(candidate, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=%s candidate_elapsed_ms=%llu elapsed_ms=%llu",
                candidate.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            continue;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available found path=%s %s candidate_elapsed_ms=%llu elapsed_ms=%llu",
            candidate.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().cached_python_path = candidate;
        }
        out_python_path         = candidate;
        return true;
    }
    diag::log_tagged_fmt("camoufox", "ensure_python_available python_not_found candidate_count=%zu elapsed_ms=%llu budget_ms=%llu",
        candidates.size(), static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long long>(kPythonDiscoveryBudgetMs));
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(allow_system_python
        ? "supported CPython 3.12 interpreter not found for Camoufox"
            : std::string("Camoufox app-local Python runtime missing\n") + install::setup_instructions());
    }
    return false;
}

bool find_preferred_developer_python_runtime(std::string& python_path, const char* phase)
{
    const bool allow_system_python = system_python_discovery_allowed();
    std::vector<std::string> candidates;
    if (!python_path.empty())
        candidates.push_back(python_path);
    std::string env_python;
    if (read_env_path_a("AIDA_CAMOUFOX_PYTHON", env_python))
        candidates.push_back(env_python);
    append_bundled_python_candidates(candidates);
    append_app_local_python_candidates(candidates);
    std::vector<std::string> unique_candidates;
    unique_candidates.reserve(candidates.size());
    for (const auto& candidate : candidates)
    {
        if (candidate.empty())
            continue;
        bool seen = false;
        for (const auto& existing : unique_candidates)
        {
            if (_stricmp(existing.c_str(), candidate.c_str()) == 0)
            {
                seen = true;
                break;
            }
        }
        if (!seen)
            unique_candidates.push_back(candidate);
    }
    for (const auto& candidate : unique_candidates)
    {
        if (!allow_system_python && !is_app_controlled_python_path(candidate))
        {
            diag::log_tagged_fmt("camoufox", "developer_python_prefer_skip phase=%s path=%s reason=outside_app_controlled_runtime",
                phase ? phase : "unknown", candidate.c_str());
            continue;
        }
        if (is_windows_store_python_alias(candidate))
        {
            diag::log_tagged_fmt("camoufox", "developer_python_prefer_skip phase=%s path=%s reason=windows_store_alias",
                phase ? phase : "unknown", candidate.c_str());
            continue;
        }
        std::string reason;
        if (!supported_camoufox_python(candidate, &reason))
        {
            diag::log_tagged_fmt("camoufox", "developer_python_prefer_skip phase=%s path=%s reason=%s",
                phase ? phase : "unknown", candidate.c_str(), reason.c_str());
            continue;
        }
        python_path = candidate;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().cached_python_path = candidate;
        }
        diag::log_tagged_fmt("camoufox", "developer_python_preferred phase=%s path=%s reason=%s",
            phase ? phase : "unknown", candidate.c_str(), reason.c_str());
        return true;
    }
    diag::log_tagged_fmt("camoufox", "developer_python_prefer_unavailable phase=%s candidate_count=%zu",
        phase ? phase : "unknown", unique_candidates.size());
    return false;
}

bool drain_pending_cleanup_before_launch_locked(std::unique_lock<std::recursive_mutex>& lk, const char* caller, uint64_t caller_start_ms)
{
    if (!sg().cleanup_pending)
        return true;

    const uint64_t wait_start = now_ms();
    const uint64_t observed_generation = sg().cleanup_generation;
    const uint32_t observed_pid = sg().cleanup_child_pid;
    const uint64_t observed_started_ms = sg().cleanup_started_ms;
    const std::string observed_reason = sg().cleanup_reason;
    const std::vector<process_tree_entry_t> observed_tree = observed_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(observed_pid);
    nlohmann::json diag = sg().cleanup_diagnostics.is_object() ? sg().cleanup_diagnostics : nlohmann::json::object();
    diag["caller"] = caller && caller[0] ? caller : "start_bridge";
    diag["cancellation_source"] = observed_reason.empty() ? std::string("<empty>") : observed_reason;
    diag["readiness_sub_step"] = "pre_launch_cleanup_drain";
    diag["deadline_ms"] = kCleanupDrainWaitMs;
    diag["elapsed_budget_ms"] = 0;
    diag["cleanup_pending_before"] = true;
    diag["cleanup_generation"] = observed_generation;
    diag["cleanup_child_pid"] = observed_pid;
    diag["cleanup_reason"] = observed_reason;
    diag["process_tree"] = compact_process_tree(observed_tree);
    diag["child_processes"] = observed_tree.size();
    diag["browser_processes"] = browser_process_count_from_tree(observed_tree);
    diag["stop_requested"] = sg().stop_requested.load(std::memory_order_acquire);
    diag["stop_epoch"] = sg().stop_epoch.load(std::memory_order_acquire);
    sg().cleanup_diagnostics = diag;
    diag::log_tagged_fmt("camoufox", "start_bridge cleanup_drain_begin caller=%s generation=%llu cleanup_generation=%llu cleanup_child_pid=%lu cleanup_age_ms=%llu caller_elapsed_ms=%llu deadline_ms=%llu cleanup_reason=%s process_tree=%s",
        caller && caller[0] ? caller : "start_bridge",
        static_cast<unsigned long long>(sg().generation),
        static_cast<unsigned long long>(observed_generation),
        static_cast<unsigned long>(observed_pid),
        static_cast<unsigned long long>(observed_started_ms == 0 ? 0 : wait_start - observed_started_ms),
        static_cast<unsigned long long>(wait_start - caller_start_ms),
        static_cast<unsigned long long>(kCleanupDrainWaitMs),
        observed_reason.empty() ? "<empty>" : observed_reason.c_str(),
        observed_tree.empty() ? "<empty>" : compact_process_tree(observed_tree).c_str());

    while (sg().cleanup_pending && now_ms() - wait_start < kCleanupDrainWaitMs)
    {
        lk.unlock();
        Sleep(static_cast<DWORD>(kCleanupDrainPollMs));
        lk.lock();
    }

    const uint64_t waited_ms = now_ms() - wait_start;
    if (!sg().cleanup_pending)
    {
        sg().cleanup_diagnostics["status"] = "drained_before_launch";
        sg().cleanup_diagnostics["elapsed_budget_ms"] = waited_ms;
        sg().cleanup_diagnostics["cleanup_pending_after"] = false;
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_drain_completed caller=%s cleanup_generation=%llu elapsed_ms=%llu last_cleanup_ms=%llu",
            caller && caller[0] ? caller : "start_bridge",
            static_cast<unsigned long long>(observed_generation),
            static_cast<unsigned long long>(waited_ms),
            static_cast<unsigned long long>(sg().last_cleanup_ms));
        return true;
    }

    const uint32_t forced_pid = sg().cleanup_child_pid != 0 ? sg().cleanup_child_pid : observed_pid;
    const uint64_t forced_generation = sg().cleanup_generation != 0 ? sg().cleanup_generation : observed_generation;
    const std::string forced_reason = sg().cleanup_reason.empty() ? observed_reason : sg().cleanup_reason;
    diag::log_tagged_fmt("camoufox", "start_bridge cleanup_drain_reap_begin caller=%s cleanup_generation=%llu child_pid=%lu elapsed_budget_ms=%llu deadline_ms=%llu cleanup_reason=%s",
        caller && caller[0] ? caller : "start_bridge",
        static_cast<unsigned long long>(forced_generation),
        static_cast<unsigned long>(forced_pid),
        static_cast<unsigned long long>(now_ms() - wait_start),
        static_cast<unsigned long long>(kCleanupDrainWaitMs),
        forced_reason.empty() ? "<empty>" : forced_reason.c_str());
    lk.unlock();
    process_tree_reap_result_t reap;
    if (forced_pid != 0)
        reap = terminate_process_tree_sync(forced_pid, std::string("start_bridge_pending_cleanup_drain:") + forced_reason);
    lk.lock();

    if (sg().cleanup_pending && sg().cleanup_generation == forced_generation)
    {
        lk.unlock();
        record_cleanup_reap_result(forced_generation, caller && caller[0] ? caller : "start_bridge", std::string("start_bridge_pending_cleanup_drain:") + forced_reason, forced_pid, reap, now_ms() - wait_start, std::string());
        mark_cleanup_finished(forced_generation, now_ms() - wait_start, std::string("start_bridge_pending_cleanup_drain:") + forced_reason,
            forced_pid == 0 || reap.alive_after == 0);
        lk.lock();
    }

    if (forced_pid != 0 && reap.alive_after != 0)
    {
        sg().state = bridge_state_t::error;
        sg().last_error = "camoufox cleanup failed before relaunch caller=" +
            std::string(caller && caller[0] ? caller : "start_bridge") +
            " cleanup_generation=" + std::to_string(forced_generation) +
            " child_pid=" + std::to_string(forced_pid) +
            " alive_after=" + std::to_string(reap.alive_after) +
            " reason=" + (forced_reason.empty() ? std::string("<empty>") : forced_reason);
        sg().cleanup_diagnostics["status"] = "failed_before_relaunch";
        sg().cleanup_diagnostics["cleanup_pending_after"] = sg().cleanup_pending;
        sg().cleanup_diagnostics["elapsed_budget_ms"] = now_ms() - wait_start;
        sg().cleanup_diagnostics["process_reap"] = cleanup_reap_json(reap);
        diag::log_tagged_critical_fmt("camoufox", "start_bridge cleanup_drain_failed caller=%s cleanup_generation=%llu child_pid=%lu alive_after=%zu elapsed_ms=%llu reason=%s",
            caller && caller[0] ? caller : "start_bridge",
            static_cast<unsigned long long>(forced_generation),
            static_cast<unsigned long>(forced_pid),
            reap.alive_after,
            static_cast<unsigned long long>(now_ms() - wait_start),
            forced_reason.empty() ? "<empty>" : forced_reason.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().cleanup_diagnostics["status"] = "reaped_before_relaunch";
    sg().cleanup_diagnostics["cleanup_pending_after"] = sg().cleanup_pending;
    sg().cleanup_diagnostics["elapsed_budget_ms"] = now_ms() - wait_start;
    diag::log_tagged_fmt("camoufox", "start_bridge cleanup_drain_reap_end caller=%s cleanup_generation=%llu child_pid=%lu alive_after=%zu cleanup_pending=%d elapsed_ms=%llu",
        caller && caller[0] ? caller : "start_bridge",
        static_cast<unsigned long long>(forced_generation),
        static_cast<unsigned long>(forced_pid),
        reap.alive_after,
        sg().cleanup_pending ? 1 : 0,
        static_cast<unsigned long long>(now_ms() - wait_start));
    return true;
}

void finish_start_bridge_failure_cleanup_locked(std::unique_lock<std::recursive_mutex>& lk,
                                                std::shared_ptr<mcp_client::client_t> cli,
                                                uint32_t child_pid,
                                                const std::string& reason,
                                                uint64_t generation,
                                                const std::string& state_error)
{
    lk.unlock();
    const process_tree_reap_result_t reap = cleanup_client_reap_now_detach_disconnect(cli, child_pid, reason, generation);
    lk.lock();
    if (!sg().last_launch_diagnostics.is_object())
        sg().last_launch_diagnostics = nlohmann::json::object();
    sg().last_launch_diagnostics["cleanup_pending_after_reap"] = sg().cleanup_pending;
    sg().last_launch_diagnostics["cleanup_reap"] = cleanup_reap_json(reap);
    sg().last_launch_diagnostics["cleanup_diagnostics"] = sg().cleanup_diagnostics;
    sg().last_launch_diagnostics["last_error_after_reap"] = sg().last_error.empty() ? state_error : sg().last_error;
    if (sg().last_error.empty())
        sg().last_error = state_error.empty() ? cleanup_status_error_locked(reason.c_str()) : state_error;
    if (child_pid != 0 && reap.alive_after != 0)
    {
        sg().last_error += " cleanup_reap_failed child_pid=" + std::to_string(child_pid) +
            " alive_after=" + std::to_string(reap.alive_after) +
            " reason=" + reason;
        sg().cleanup_diagnostics["status"] = "failed_before_return";
        sg().cleanup_diagnostics["process_reap"] = cleanup_reap_json(reap);
    }
}

bool start_bridge(const launch_config_t& cfg)
{
    if (!is_default_session_id(cfg.session_id))
        return start_bridge(cfg, cfg.session_id);
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
    {
        diag::log_tagged_critical_fmt("camoufox", "start_bridge lifecycle_busy session_id=%s", cfg.session_id.empty() ? "default" : cfg.session_id.c_str());
        return false;
    }
    const uint64_t bridge_start_ms = now_ms();
    uint64_t sb_drain_start_ms = 0;
    uint64_t sb_drain_ms = 0;
    uint64_t sb_resolve_ms = 0;
    uint64_t sb_spawn_ms = 0;
    uint64_t sb_connect_ms = 0;
    uint64_t sb_tools_ms = 0;
    uint64_t sb_launch_rpc_ms = 0;
    uint64_t sb_readiness_probe_ms = 0;
    uint64_t sb_visible_window_ms = 0;
    auto emit_stage_timing = [&](bool ok, const char* phase, uint32_t child_pid) {
        diag::log_tagged_fmt("camoufox", "start_bridge stage_timing ok=%d phase=%s session_id=%s drain_ms=%llu resolve_ms=%llu spawn_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu child_pid=%lu",
            ok ? 1 : 0,
            phase && phase[0] ? phase : "unspecified",
            cfg.session_id.empty() ? "default" : cfg.session_id.c_str(),
            static_cast<unsigned long long>(sb_drain_ms),
            static_cast<unsigned long long>(sb_resolve_ms),
            static_cast<unsigned long long>(sb_spawn_ms),
            static_cast<unsigned long long>(sb_connect_ms),
            static_cast<unsigned long long>(sb_tools_ms),
            static_cast<unsigned long long>(sb_launch_rpc_ms),
            static_cast<unsigned long long>(sb_readiness_probe_ms),
            static_cast<unsigned long long>(sb_visible_window_ms),
            static_cast<unsigned long long>(now_ms() - bridge_start_ms),
            static_cast<unsigned long>(child_pid));
    };
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
        return wait_for_existing_start_bridge_result(cfg, bridge_start_ms);
    const uint64_t start_stop_epoch = sg().stop_epoch.load(std::memory_order_acquire);
    launch_config_t effective_cfg = cfg;
    enforce_private_launch_config(effective_cfg);
    normalize_fast_visible_launch_policy(effective_cfg);
    if (effective_cfg.session_id.empty())
        effective_cfg.session_id = "default";
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge forcing_visible requested_headless=1");
        effective_cfg.headless = false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge entry session_id=%s headless=%d module=%s window=%dx%d requested_timeout_ms=%d",
        effective_cfg.session_id.c_str(),
        static_cast<int>(effective_cfg.headless), effective_cfg.server_module.c_str(),
        effective_cfg.window_width, effective_cfg.window_height, effective_cfg.launch_timeout_ms);
    std::unique_lock<std::recursive_mutex> lk(sg().mtx);
    sg().attempt_started_ms = bridge_start_ms;
    sg().attempt_elapsed_ms = 0;

    diag::log_tagged_fmt("camoufox", "start_bridge state_snapshot state=%d generation=%llu client=%d browser_open=%d page_verified=%d child_pid=%lu cleanup_pending=%d",
        static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open),
        static_cast<int>(sg().page_verified), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(sg().cleanup_pending));
    clear_auto_restart_block_locked("start_bridge");
    sb_drain_start_ms = now_ms();
    if (!drain_pending_cleanup_before_launch_locked(lk, "start_bridge", bridge_start_ms))
    {
        sb_drain_ms = now_ms() - sb_drain_start_ms;
        emit_stage_timing(false, "drain", sg().child_pid);
        return false;
    }
    sb_drain_ms = now_ms() - sb_drain_start_ms;

    lk.unlock();
    sweep_stale_camoufox_processes_by_name(0, "start_bridge_pre_launch_sweep");
    lk.lock();

    bool ready_config_mismatch_handled = false;
    if (sg().state == bridge_state_t::ready && sg().client)
    {
        const bool child_alive = process_alive(sg().child_pid);
        const std::vector<process_tree_entry_t> ready_tree = child_alive ? enumerate_process_tree(sg().child_pid) : std::vector<process_tree_entry_t>();
        const uint32_t ready_browser_processes = browser_process_count_from_tree(ready_tree);
        const bool ready_process_tree = usable_browser_process_tree(ready_tree);
        const visible_window_snapshot_t ready_visible = child_alive ? sample_visible_window_proof(sg().child_pid) : visible_window_snapshot_t();
        const bool ready_visible_window = ready_visible.visible_window_count > 0;
        sg().last_launch_diagnostics["visible_window_proof"] = visible_window_proof_json(ready_visible, sg().child_pid, sg().generation, "start_bridge_reuse");
        log_visible_window_proof("start_bridge_reuse", sg().generation, sg().child_pid, ready_visible);
        if (!is_driver_closed_error(sg().last_error) && sg().browser_open && sg().page_verified && sg().privacy_verified && child_alive && ready_process_tree && ready_visible_window)
        {
            if (reduced_browser_process_tree(ready_browser_processes))
            {
                diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=start_bridge_reuse generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d visible_windows=%u process_tree=%s",
                    static_cast<unsigned long long>(sg().generation),
                    static_cast<unsigned long>(sg().child_pid),
                    child_alive ? 1 : 0,
                    static_cast<unsigned>(ready_tree.size()),
                    static_cast<unsigned>(ready_browser_processes),
                    static_cast<unsigned>(kMinReadyBrowserProcessCount),
                    sg().browser_open ? 1 : 0,
                    sg().page_verified ? 1 : 0,
                    sg().privacy_verified ? 1 : 0,
                    static_cast<unsigned>(ready_visible.visible_window_count),
                    ready_tree.empty() ? "<empty>" : compact_process_tree(ready_tree).c_str());
            }
            const std::string mismatch_reason = privacy_relevant_launch_config_mismatch_reason(sg().active_cfg, effective_cfg);
            if (!mismatch_reason.empty())
            {
                diag::log_tagged_fmt("camoufox", "start_bridge ready_config_mismatch restarting generation=%llu child_pid=%lu reason=%s",
                    static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                    mismatch_reason.c_str());
                auto stale_client = sg().client;
                const uint32_t stale_pid = sg().child_pid;
                sg().client.reset();
                sg().child_pid = 0;
                sg().browser_open = false;
                sg().page_verified = false;
                sg().active_page_url.clear();
                sg().active_page_title.clear();
                const std::string restart_reason = "start_bridge_config_mismatch";
                lk.unlock();
                if (stale_pid != 0)
                    terminate_process_tree_sync(stale_pid, restart_reason);
                if (stale_client)
                    disconnect_client_sync(stale_client, restart_reason);
                lk.lock();
                ready_config_mismatch_handled = true;
            }
            else
            {
                diag::log_tagged_fmt("camoufox", "start_bridge already_ready reusing generation=%llu child_pid=%lu active_url_len=%zu title_len=%zu",
                    static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                    sg().active_page_url.size(), sg().active_page_title.size());
                preserve_resolved_launch_paths(effective_cfg, sg().active_cfg);
                sg().active_cfg = effective_cfg;
                sg().last_launch_ms = now_ms() - bridge_start_ms;
                emit_stage_timing(true, "ready_reuse", sg().child_pid);
                clear_sticky_setup_failure("start_bridge_ready_reuse");
                return true;
            }
        }
        if (!ready_config_mismatch_handled)
        {
            diag::log_tagged_fmt("camoufox", "start_bridge invalidating_unverified_ready generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d browser_processes=%u visible_windows=%u process_tree=%s err=%s",
                static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                static_cast<int>(child_alive), static_cast<int>(sg().browser_open), static_cast<int>(sg().page_verified),
                static_cast<int>(sg().privacy_verified),
                static_cast<unsigned>(ready_browser_processes),
                static_cast<unsigned>(ready_visible.visible_window_count),
                ready_tree.empty() ? "<empty>" : compact_process_tree(ready_tree).c_str(),
                sg().last_error.c_str());
            auto stale_client = sg().client;
            const uint32_t stale_pid = sg().child_pid;
            sg().client.reset();
            clear_page_state_locked();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            if (stale_pid != 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == stale_pid)
                sg().tracked_child_pid.store(0, std::memory_order_release);
            lk.unlock();
            if (stale_pid != 0)
                terminate_process_tree_sync(stale_pid, "start_bridge_unverified_ready");
            if (stale_client)
                disconnect_client_async(stale_client, "start_bridge_unverified_ready");
            lk.lock();
        }
    }
    if (sg().state == bridge_state_t::starting)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge already_starting rejected");
        set_error_locked("camoufox bridge already starting");
        return false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge state->starting");

    if (sg().client)
    {
        auto stale_client = sg().client;
        const uint32_t stale_pid = sg().child_pid;
        diag::log_tagged_fmt("camoufox", "start_bridge disconnecting_stale_client state=%d browser_open=%d",
            static_cast<int>(sg().state), static_cast<int>(sg().browser_open));
        if (stale_pid != 0)
        {
            lk.unlock();
            terminate_process_tree_sync(stale_pid, "start_bridge_stale_client");
            lk.lock();
        }
        if (sg().client == stale_client)
            sg().client.reset();
        clear_page_state_locked();
        if (sg().child_pid == stale_pid)
            sg().child_pid = 0;
        if (stale_pid != 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == stale_pid)
            sg().tracked_child_pid.store(0, std::memory_order_release);
        if (stale_client)
        {
            lk.unlock();
            disconnect_client_async(stale_client, "start_bridge_stale_client");
            lk.lock();
        }
    }
    if (sg().stop_epoch.load(std::memory_order_acquire) != start_stop_epoch)
    {
        sg().last_error = "camoufox bridge start cancelled by stop request";
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        diag::log_tagged_fmt("camoufox", "start_bridge cancelled_before_launch elapsed_ms=%llu",
            static_cast<unsigned long long>(sg().last_launch_ms));
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    sg().stop_requested.store(false, std::memory_order_release);
    const uint64_t start_generation = ++sg().generation;
    sg().cleanup_pending = false;
    sg().cleanup_generation = start_generation;
    sg().state          = bridge_state_t::starting;
    sg().session_id     = effective_cfg.session_id;
    sg().last_error.clear();
    sg().active_page_id.clear();
    sg().pages.clear();
    sg().active_profile_dir.clear();
    sg().active_profile_generated = false;
    sg().last_launch_ms = 0;
    sg().last_launch_diagnostics = nlohmann::json::object();
    publish_state(bridge_state_t::starting, std::string());

    {
        uint64_t launch_token = 0;
        if (!acquire_launch_admission("start_bridge", effective_cfg.session_id, start_generation, 0, launch_token))
        {
            sg().state = bridge_state_t::error;
            sg().last_error = "CAMOUFOX-LONGOP-REJECT: downstream producer capacity exhausted for camoufox_longop launch";
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            publish_state(bridge_state_t::error, sg().last_error);
            emit_stage_timing(false, "launch_admission_rejected", 0);
            return false;
        }
        sg().launch_admission_token = launch_token;
    }
    launch_admission_guard_t launch_guard(&sg().launch_admission_token, effective_cfg.session_id);

    std::string python_path = effective_cfg.python_executable;
    const bool testlab_launch = test_lab_launch_fail_fast_enabled(effective_cfg);
    const bool explicit_python_cfg = !effective_cfg.python_executable.empty();
    const bool explicit_python_env = env_path_configured_a("AIDA_CAMOUFOX_PYTHON");
    const uint64_t sb_resolve_start_ms = now_ms();
    diag::log_tagged_fmt("camoufox", "bridge_runtime_select phase=start_bridge mode=python testlab_fast_probe=%d explicit_python_cfg=%d explicit_python_env=%d initial_python=%s",
        testlab_launch ? 1 : 0,
        explicit_python_cfg ? 1 : 0,
        explicit_python_env ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str());
    lk.unlock();
    find_preferred_developer_python_runtime(python_path, "start_bridge");
    const bool python_ready = !python_path.empty();
    lk.lock();
    if (sg().stop_epoch.load(std::memory_order_acquire) != start_stop_epoch)
    {
        sg().last_error = "camoufox bridge start cancelled during Python runtime probe";
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        diag::log_tagged_fmt("camoufox", "start_bridge cancelled_after_python_probe elapsed_ms=%llu",
            static_cast<unsigned long long>(sg().last_launch_ms));
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    diag::log_tagged_fmt("camoufox", "start_bridge python_runtime_resolve final_mode=python testlab_fast_probe=%d python_ready=%d explicit_python_cfg=%d explicit_python_env=%d python=%s",
        testlab_launch ? 1 : 0,
        python_ready ? 1 : 0,
        explicit_python_cfg ? 1 : 0,
        explicit_python_env ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str());

    if (!python_path.empty())
    {
        std::string reason;
        if (!system_python_discovery_allowed() && !is_app_controlled_python_path(python_path))
        {
            reason = "explicit Python path is outside AiDA-controlled Camoufox runtime roots";
            diag::log_tagged_fmt("camoufox", "start_bridge explicit_python_rejected path=%s reason=%s",
                python_path.c_str(), reason.c_str());
            python_path.clear();
        }
        else if (!supported_camoufox_python(python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "start_bridge explicit_python_rejected path=%s reason=%s",
                python_path.c_str(), reason.c_str());
            python_path.clear();
        }
    }
    if (python_path.empty())
    {
        sg().last_error = "Camoufox Python runtime unavailable\n" + install::setup_instructions();
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        diag::log_tagged_fmt("camoufox", "start_bridge python_runtime_unavailable explicit_python_cfg=%d explicit_python_env=%d",
            explicit_python_cfg ? 1 : 0,
            explicit_python_env ? 1 : 0);
        return false;
    }

    if (effective_cfg.browser_executable.empty())
    {
        std::string env_browser;
        if (read_env_path_a("AIDA_CAMOUFOX_EXECUTABLE", env_browser))
            effective_cfg.browser_executable = env_browser;
    }
    if (effective_cfg.browser_executable.empty())
    {
        std::string bundled_browser;
        if (find_bundled_camoufox_executable(bundled_browser))
            effective_cfg.browser_executable = bundled_browser;
    }
    DWORD browser_attr = INVALID_FILE_ATTRIBUTES;
    if (!effective_cfg.browser_executable.empty())
        browser_attr = GetFileAttributesW(utf8_to_wide(effective_cfg.browser_executable).c_str());
    diag::log_tagged_fmt("camoufox", "start_bridge browser_executable=%s exists=%d attr=0x%08lX",
        effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0),
        static_cast<unsigned long>(browser_attr));
    const sticky_setup_context_t setup_ctx = make_sticky_setup_context(
        effective_cfg,
        "python",
        python_path);
    nlohmann::json sticky_hit;
    std::string sticky_hit_error;
    if (sticky_setup_failure_hit_or_clear(setup_ctx, start_generation, sg().child_pid, now_ms() - bridge_start_ms, sticky_hit, sticky_hit_error))
    {
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_error = sticky_hit_error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_launch_diagnostics = {
            {"status", "blocked"},
            {"phase", "sticky_setup_failure"},
            {"generation", start_generation},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"elapsed_ms", sg().last_launch_ms},
            {"caller", "start_bridge"}
        };
        attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky_hit);
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "sticky_setup_failure", 0);
        return false;
    }
    if (effective_cfg.browser_executable.empty() || browser_attr == INVALID_FILE_ATTRIBUTES || (browser_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        sg().last_error = effective_cfg.browser_executable.empty()
            ? std::string("Camoufox browser executable not found\n") + install::setup_instructions()
            : std::string("Configured Camoufox browser executable is unavailable\n") + install::setup_instructions();
        sg().state = bridge_state_t::error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "browser_executable_preflight"},
            {"generation", start_generation},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"browser_path", effective_cfg.browser_executable},
            {"browser_attr", static_cast<uint32_t>(browser_attr)},
            {"elapsed_ms", sg().last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "browser_executable_missing",
            sg().last_error,
            start_generation,
            0,
            camoufox_debug_log_path(),
            sg().last_launch_ms,
            sg().last_launch_diagnostics);
        attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
        sg().last_error = sticky_setup_failure_error_text("browser_executable_missing", sg().last_error);
        diag::log_tagged_fmt("camoufox", "start_bridge browser_required_failed generation=%llu err=%s",
            static_cast<unsigned long long>(start_generation), sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    if (!is_camoufox_browser_executable_path(utf8_to_wide(effective_cfg.browser_executable)))
    {
        sg().last_error = "Configured browser executable is not a Camoufox browser bundle";
        sg().state = bridge_state_t::error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "browser_executable_preflight"},
            {"generation", start_generation},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"browser_path", effective_cfg.browser_executable},
            {"elapsed_ms", sg().last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "browser_executable_rejected",
            sg().last_error,
            start_generation,
            0,
            camoufox_debug_log_path(),
            sg().last_launch_ms,
            sg().last_launch_diagnostics);
        attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
        sg().last_error = sticky_setup_failure_error_text("browser_executable_rejected", sg().last_error);
        diag::log_tagged_fmt("camoufox", "start_bridge browser_rejected_non_camoufox path=%s",
            effective_cfg.browser_executable.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    {
        const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
        diag::log_tagged_fmt("camoufox", "start_bridge persistent_context_policy generation=%llu bundled_visible=%d explicit_persistent=%d cfg_persistent=%d profile_dir=%d user_data_dir=%d default_nonpersistent=1",
            static_cast<unsigned long long>(start_generation),
            bundled_visible_launch ? 1 : 0,
            explicit_persistent_context_requested(effective_cfg) ? 1 : 0,
            effective_cfg.persistent_context ? 1 : 0,
            trim_launch_token(effective_cfg.profile_dir).empty() ? 0 : 1,
            trim_launch_token(effective_cfg.user_data_dir).empty() ? 0 : 1);
    }

    if (!prepare_install_for_launch_locked(python_path))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (!probe_module_installed_locked(python_path))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (!preflight_server_entry_locked(python_path, effective_cfg))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    mcp_client::server_config_t scfg;
    scfg.name      = "camoufox-reverse";
    scfg.transport = mcp_client::transport_type_t::stdio;
    scfg.command   = python_path;
    scfg.args.push_back("-I");
    scfg.args.push_back("-m");
    scfg.args.push_back(effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    for (const auto& a : effective_cfg.extra_args) scfg.args.push_back(a);
    scfg.env["AIDA_CAMOUFOX_PYTHON"] = python_path;
    if (system_python_discovery_allowed())
        scfg.env["AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON"] = "1";
    const std::string child_debug_log = camoufox_debug_log_path();
    populate_internal_camoufox_env(scfg, effective_cfg.session_id, effective_cfg.browser_executable, child_debug_log);
    scfg.enabled                 = true;
    scfg.auto_connect            = false;
    scfg.oauth_enabled           = false;

    const DWORD mcp_create_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    std::string init_block_reason;
    uint64_t init_block_remaining_ms = 0;
    uint64_t init_block_generation = 0;
    uint32_t init_block_count = 0;
    if (launch_init_failure_blocked_locked(scfg.command, now_ms(), init_block_reason, init_block_remaining_ms, init_block_generation, init_block_count))
    {
        sg().state = bridge_state_t::error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_error = "camoufox reverse-MCP launch blocked after immediate process initialization failure; retry after " +
            std::to_string(init_block_remaining_ms) + "ms";
        sg().last_launch_diagnostics = {
            {"status", "blocked"},
            {"phase", "process_initialization_failure_backoff"},
            {"generation", start_generation},
            {"blocked_generation", init_block_generation},
            {"remaining_ms", init_block_remaining_ms},
            {"count", init_block_count},
            {"exit_code", "0xC0000142"},
            {"command", scfg.command},
            {"reason", init_block_reason}
        };
        diag::log_tagged_fmt("camoufox", "start_bridge launch_init_failure_blocked generation=%llu blocked_generation=%llu remaining_ms=%llu count=%lu command=%s reason=%s",
            static_cast<unsigned long long>(start_generation),
            static_cast<unsigned long long>(init_block_generation),
            static_cast<unsigned long long>(init_block_remaining_ms),
            static_cast<unsigned long>(init_block_count),
            scfg.command.empty() ? "<empty>" : scfg.command.c_str(),
            init_block_reason.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().client = std::make_shared<mcp_client::client_t>();
    const std::string cwd_log = wide_to_utf8(current_dir_w());
    const auto workdir_it = scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
    const auto profile_it = scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT");

    diag::log_tagged_fmt("camoufox", "start_bridge mcp_connect_begin generation=%llu mode=%s command=%s module=%s args=%zu cwd=%s workdir=%s profile_root=%s debug_log=%s timeout_ms=%d env_pythonio=%d env_browser=%d env_debug_log=%d env_workdir=%d env_profile=%d browser_exists=%d create_flags=0x%08lX inherited_error_mode=%d process_error_mode_before=0x%08lX desired_child_error_mode=0x%08lX",
        static_cast<unsigned long long>(start_generation),
        "python",
        scfg.command.c_str(),
        effective_cfg.server_module.empty() ? "camoufox_reverse_mcp" : effective_cfg.server_module.c_str(),
        scfg.args.size(),
        cwd_log.empty() ? "<empty>" : cwd_log.c_str(),
        workdir_it == scfg.env.end() ? "<empty>" : workdir_it->second.c_str(),
        profile_it == scfg.env.end() ? "<empty>" : profile_it->second.c_str(),
        child_debug_log.c_str(),
        effective_cfg.launch_timeout_ms,
        static_cast<int>(scfg.env.find("PYTHONIOENCODING") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_EXECUTABLE") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_DEBUG_LOG") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT") != scfg.env.end()),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0),
        static_cast<unsigned long>(mcp_create_flags),
        (mcp_create_flags & CREATE_DEFAULT_ERROR_MODE) == 0 ? 1 : 0,
        static_cast<unsigned long>(current_error_mode()),
        static_cast<unsigned long>(current_error_mode() | kBridgeChildErrorMode));
    sb_resolve_ms = now_ms() - sb_resolve_start_ms;
    const uint64_t sb_spawn_start_ms = now_ms();
    bool connect_ok = false;
    auto connecting_client = sg().client;
    {
        scoped_child_error_mode_t mcp_child_error_mode("start_bridge_mcp_connect", mcp_create_flags, scfg.command.c_str());
        lk.unlock();
        connect_ok = connecting_client->connect(scfg);
        lk.lock();
    }
    sb_spawn_ms = now_ms() - sb_spawn_start_ms;
    sb_connect_ms = sb_spawn_ms;
    if (sg().client != connecting_client ||
        sg().stop_epoch.load(std::memory_order_acquire) != start_stop_epoch ||
        sg().stop_requested.load(std::memory_order_acquire))
    {
        const uint32_t cancelled_pid = connecting_client ? connecting_client->child_process_id() : 0;
        diag::log_tagged_critical_fmt("camoufox", "start_bridge connect_cancelled generation=%llu connect_ok=%d child_pid=%lu stop_epoch_start=%llu stop_epoch_now=%llu stop_requested=%d client_changed=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation),
            connect_ok ? 1 : 0,
            static_cast<unsigned long>(cancelled_pid),
            static_cast<unsigned long long>(start_stop_epoch),
            static_cast<unsigned long long>(sg().stop_epoch.load(std::memory_order_acquire)),
            sg().stop_requested.load(std::memory_order_acquire) ? 1 : 0,
            sg().client != connecting_client ? 1 : 0,
            static_cast<unsigned long long>(sb_connect_ms));
        if (sg().client == connecting_client)
        {
            sg().client.reset();
            clear_page_state_locked();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            sg().last_error = "camoufox bridge connect cancelled by cleanup request";
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            mark_cleanup_started_locked(start_generation, cancelled_pid, "start_bridge_connect_cancelled");
        }
        lk.unlock();
        if (connecting_client)
            cleanup_client_reap_now_detach_disconnect(connecting_client, cancelled_pid, "start_bridge_connect_cancelled", start_generation);
        lk.lock();
        publish_state(bridge_state_t::error, "camoufox bridge connect cancelled by cleanup request");
        emit_stage_timing(false, "connect_cancelled", cancelled_pid);
        return false;
    }
    if (!connect_ok)
    {
        std::string inner = connecting_client ? connecting_client->last_error() : std::string();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("client connect failed: ") + (inner.empty() ? std::string("(no detail)") : inner);
        diag::log_tagged_fmt("camoufox", "start_bridge mcp_connect_failed generation=%llu err=%s",
            static_cast<unsigned long long>(start_generation),
            sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "connect", sg().child_pid);
        return false;
    }
    reset_launch_init_failure_block_locked("start_bridge_mcp_connect_success");
    sg().server_command = python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    sg().child_pid      = connecting_client ? connecting_client->child_process_id() : 0;
    sg().tracked_child_pid.store(sg().child_pid, std::memory_order_release);
    sg().launched_ms    = now_ms();
    diag::log_tagged_fmt("camoufox", "start_bridge connected generation=%llu mode=%s child_pid=%lu command=%s args=%zu cwd=%s workdir=%s profile_root=%s debug_log=%s timeout_ms=%d",
        static_cast<unsigned long long>(start_generation),
        "python",
        static_cast<unsigned long>(sg().child_pid),
        sg().server_command.c_str(),
        scfg.args.size(),
        cwd_log.empty() ? "<empty>" : cwd_log.c_str(),
        workdir_it == scfg.env.end() ? "<empty>" : workdir_it->second.c_str(),
        profile_it == scfg.env.end() ? "<empty>" : profile_it->second.c_str(),
        child_debug_log.c_str(),
        effective_cfg.launch_timeout_ms);

    const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(effective_cfg);
    int launch_wait_ms = effective_launch_wait_ms(effective_cfg, bundled_visible_launch);
    launch_wait_ms = apply_visible_readiness_budget_ms(launch_wait_ms, bundled_visible_launch, bridge_start_ms, "start_bridge_pre_launch", start_generation, sg().child_pid);
    if (bundled_visible_launch && launch_wait_ms < kLaunchWaitMinMs)
    {
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_error = "camoufox visible readiness budget exhausted before launch_browser";
        block_auto_restart_locked("visible_readiness_budget_exhausted", start_generation, kAutoRestartBlockMs);
        mark_cleanup_started_locked(start_generation, failed_pid, "visible_readiness_budget_exhausted");
        const std::string debug_tail = read_file_tail_for_log(child_debug_log, 4000);
        const std::vector<process_tree_entry_t> budget_tree_entries = failed_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(failed_pid);
        sg().last_launch_diagnostics = {
            {"status", "timeout"},
            {"phase", "visible_readiness_budget"},
            {"transport_phase", "pre_launch"},
            {"caller", "start_bridge"},
            {"cancellation_source", "visible_readiness_budget_exhausted"},
            {"generation", start_generation},
            {"attempt_id", std::to_string(start_generation) + "-" + std::to_string(now_ms())},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"child_pid", failed_pid},
            {"child_alive", failed_pid != 0 && process_alive(failed_pid)},
            {"elapsed_ms", sg().last_launch_ms},
            {"requested_ms", cfg.launch_timeout_ms},
            {"effective_ms", launch_wait_ms},
            {"visible_readiness_max_ms", kBundledVisibleReadinessMaxMs},
            {"process_tree", compact_process_tree_with_exit(budget_tree_entries)},
            {"process_tree_count", budget_tree_entries.size()},
            {"debug_tail_len", debug_tail.size()},
            {"stderr_last_frame", debug_tail},
            {"stderr_last_frame_len", debug_tail.size()}
        };
        attach_debug_log_snapshot_locked(sg().last_launch_diagnostics, failed_pid, child_debug_log, debug_tail);
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "visible_readiness_budget_exhausted", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "visible_readiness_budget", failed_pid);
        return false;
    }
    int wait_ms = launch_wait_ms / 4;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > kToolListWaitMaxMs) wait_ms = kToolListWaitMaxMs;
    if (effective_cfg.launch_timeout_ms != launch_wait_ms || testlab_fast_probe)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge launch_timeout_clamped requested_ms=%d effective_ms=%d tool_list_ms=%d generation=%llu bundled_visible=%d testlab_fast_probe=%d",
            effective_cfg.launch_timeout_ms, launch_wait_ms, wait_ms, static_cast<unsigned long long>(start_generation),
            bundled_visible_launch ? 1 : 0, testlab_fast_probe ? 1 : 0);
    }
    effective_cfg.launch_timeout_ms = launch_wait_ms;
    diag::log_tagged_fmt("camoufox", "start_bridge waiting_for_required_tools wait_ms=%d generation=%llu child_pid=%lu mode=%s",
        wait_ms, static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
        "python");
    std::string missing_tools;
    std::string tool_inventory;
    const uint64_t sb_tools_start_ms = now_ms();
    const bool tools_ready = wait_for_required_reverse_tools(
            sg().client.get(),
            wait_ms,
            "start_bridge",
            "python",
            scfg.command,
            effective_cfg.session_id,
            start_generation,
            missing_tools,
            tool_inventory);
    sb_tools_ms = now_ms() - sb_tools_start_ms;
    if (!tools_ready)
    {
        std::string inner = sg().client->last_error();
        const uint32_t failed_pid = sg().child_pid;
        log_required_reverse_tools_missing_launch_skip(
            "start_bridge",
            "python",
            scfg.command,
            effective_cfg.session_id,
            start_generation,
            failed_pid,
            missing_tools,
            tool_inventory,
            inner);
        sg().client->disconnect();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("camoufox MCP server did not expose required reverse tools: ") +
            (missing_tools.empty() ? std::string("<unknown>") : missing_tools) +
            "; inventory=" + (tool_inventory.empty() ? std::string("<empty>") : tool_inventory) +
            "; mcp last_error=" + inner;
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "required_reverse_tools_missing"},
            {"generation", start_generation},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"child_pid", failed_pid},
            {"missing_tools", missing_tools},
            {"inventory", tool_inventory},
            {"mcp_last_error", inner},
            {"elapsed_ms", sg().last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "required_reverse_tools_missing",
            sg().last_error,
            start_generation,
            failed_pid,
            camoufox_debug_log_path(),
            sg().last_launch_ms,
            sg().last_launch_diagnostics);
        attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
        sg().last_error = sticky_setup_failure_error_text("required_reverse_tools_missing", sg().last_error);
        diag::log_tagged("camoufox", sg().last_error.c_str());
        terminate_process_id_async(failed_pid, "required_reverse_tools_missing");
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "tools", failed_pid);
        return false;
    }

    launch_wait_ms = apply_visible_readiness_budget_ms(launch_wait_ms, bundled_visible_launch, bridge_start_ms, "start_bridge_launch_rpc", start_generation, sg().child_pid);
    if (bundled_visible_launch && launch_wait_ms < kLaunchWaitMinMs)
    {
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        sg().last_error = "camoufox visible readiness budget exhausted before launch_browser";
        block_auto_restart_locked("visible_readiness_budget_exhausted_after_tools", start_generation, kAutoRestartBlockMs);
        mark_cleanup_started_locked(start_generation, failed_pid, "visible_readiness_budget_exhausted_after_tools");
        const std::string debug_tail = read_file_tail_for_log(child_debug_log, 4000);
        const std::vector<process_tree_entry_t> budget_tree_entries = failed_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(failed_pid);
        sg().last_launch_diagnostics = {
            {"status", "timeout"},
            {"phase", "visible_readiness_budget"},
            {"transport_phase", "pre_launch"},
            {"caller", "start_bridge"},
            {"cancellation_source", "visible_readiness_budget_exhausted_after_tools"},
            {"generation", start_generation},
            {"attempt_id", std::to_string(start_generation) + "-" + std::to_string(now_ms())},
            {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
            {"child_pid", failed_pid},
            {"child_alive", failed_pid != 0 && process_alive(failed_pid)},
            {"elapsed_ms", sg().last_launch_ms},
            {"requested_ms", cfg.launch_timeout_ms},
            {"effective_ms", launch_wait_ms},
            {"visible_readiness_max_ms", kBundledVisibleReadinessMaxMs},
            {"process_tree", compact_process_tree_with_exit(budget_tree_entries)},
            {"process_tree_count", budget_tree_entries.size()},
            {"debug_tail_len", debug_tail.size()},
            {"stderr_last_frame", debug_tail},
            {"stderr_last_frame_len", debug_tail.size()}
        };
        attach_debug_log_snapshot_locked(sg().last_launch_diagnostics, failed_pid, child_debug_log, debug_tail);
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "visible_readiness_budget_exhausted_after_tools", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "visible_readiness_budget", failed_pid);
        return false;
    }

    sg().active_cfg     = effective_cfg;
    const uint64_t sb_launch_rpc_start_ms = now_ms();

    nlohmann::json args = build_launch_args(effective_cfg);
    const uint64_t launch_attempt_ms = now_ms();
    args["bridge_generation"] = start_generation;
    args["bridge_session_id"] = effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id;
    args["bridge_attempt_id"] = std::to_string(start_generation) + "-" + std::to_string(launch_attempt_ms);
    const std::string launch_ua_policy = args.value("ua_policy", std::string("camoufox_native"));
    const std::string launch_service_workers = args.value("service_workers", std::string("allow"));
    const std::string launch_policy_marker = args.value("aida_launch_policy_marker", std::string());
    diag::log_tagged_fmt("camoufox", "launch_browser request headless=%d has_proxy=%d os=%s locale=%s window=%dx%d timeout_ms=%d testlab_fast_probe=%d ua_policy=%s ua_override_len=%zu persistent_context=%d profile_dir=%d user_data_dir=%d block_webrtc=%d block_service_workers=%d service_workers=%s fast_visible_fallback=%d marker=%s",
        static_cast<int>(effective_cfg.headless), static_cast<int>(!effective_cfg.proxy.empty()),
        effective_cfg.os.c_str(),
        (effective_cfg.locale.empty() ? "auto" : effective_cfg.locale.c_str()),
        json_int_or(args, "window_width", -1), json_int_or(args, "window_height", -1),
        effective_cfg.launch_timeout_ms, testlab_fast_probe ? 1 : 0,
        launch_ua_policy.c_str(),
        effective_cfg.user_agent.size(),
        args.value("persistent_context", false) ? 1 : 0,
        args.contains("profile_dir") ? 1 : 0,
        args.contains("user_data_dir") ? 1 : 0,
        args.value("block_webrtc", true) ? 1 : 0,
        args.value("block_service_workers", false) ? 1 : 0,
        launch_service_workers.c_str(),
        args.value("aida_fast_visible_launch", false) ? 1 : 0,
        launch_policy_marker.c_str());
    struct launch_state_t
    {
        std::mutex                mtx;
        std::condition_variable   cv;
        bool                      done = false;
        bool                      cancelled = false;
        uint64_t                  generation = 0;
        uint32_t                  child_pid = 0;
        mcp_client::call_result_t result;
    };
    auto launch_state = std::make_shared<launch_state_t>();
    auto launch_client = sg().client;
    const uint32_t launch_child_pid = sg().child_pid;
    {
        std::lock_guard<std::mutex> launch_state_lk(launch_state->mtx);
        launch_state->generation = start_generation;
        launch_state->child_pid = launch_child_pid;
    }
    const uint64_t launch_call_start_ms = launch_attempt_ms;
    const uint64_t strict_launch_deadline_ms = launch_call_start_ms + static_cast<uint64_t>(kStrictLaunchBudgetMs);
    uint64_t last_launch_wait_log_ms = 0;
    uint64_t last_launch_debug_poll_ms = 0;
    uint64_t last_launch_tree_log_ms = 0;
    diag::log_tagged_fmt("camoufox", "start_bridge strict_launch_watchdog_armed generation=%llu child_pid=%lu caller_pid=%lu caller_tid=%lu launch_call_start_ms=%llu deadline_ms=%llu budget_ms=%d effective_wait_ms=%d requested_ms=%d bundled_visible=%d testlab_fast_probe=%d",
        static_cast<unsigned long long>(start_generation),
        static_cast<unsigned long>(launch_child_pid),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(launch_call_start_ms),
        static_cast<unsigned long long>(strict_launch_deadline_ms),
        kStrictLaunchBudgetMs,
        launch_wait_ms,
        cfg.launch_timeout_ms,
        bundled_visible_launch ? 1 : 0,
        testlab_fast_probe ? 1 : 0);
    bool launch_posted = post_bridge_task("camoufox.launch", [launch_state, launch_client, args]() {
        const uint64_t worker_start = now_ms();
        const std::string launch_tool = "launch_browser";
        mcp_client::call_result_t r;
        guarded_mcp_call_context_t call_ctx;
        call_ctx.client = launch_client.get();
        call_ctx.tool_name = &launch_tool;
        call_ctx.args = &args;
        call_ctx.result = &r;
        DWORD guard_status = guarded_mcp_call(&call_ctx);
        if (guard_status != ERROR_SUCCESS)
        {
            r = guarded_mcp_failure_result(launch_tool, call_ctx, guard_status);
            diag::log_tagged_critical_fmt("camoufox", "launch_browser guarded_failure generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                static_cast<unsigned long long>(launch_state->generation),
                static_cast<unsigned long>(launch_state->child_pid), static_cast<unsigned long>(guard_status),
                static_cast<int>(call_ctx.native_exception), static_cast<int>(call_ctx.cpp_exception),
                static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        bool cancelled = false;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        {
            std::lock_guard<std::mutex> lk(launch_state->mtx);
            cancelled = launch_state->cancelled;
            generation = launch_state->generation;
            child_pid = launch_state->child_pid;
            launch_state->result = std::move(r);
            launch_state->done = true;
        }
        launch_state->cv.notify_all();
        if (cancelled)
        {
            diag::log_tagged_fmt("camoufox", "launch_browser worker_late_result generation=%llu child_pid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long long>(now_ms() - worker_start));
        }
    });
    if (!launch_posted)
    {
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_error = "launch_browser dispatch post failed";
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, launch_child_pid, "launch_browser_dispatch_failed");
        diag::log_tagged_fmt("camoufox", "launch_browser dispatch_post_failed generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid));
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, launch_child_pid, "launch_browser_dispatch_failed", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    mcp_client::call_result_t launch;
    bool launch_strict_budget_blown = false;
    uint64_t launch_strict_elapsed_ms = 0;
    std::string launch_strict_last_phase;
    std::string launch_strict_last_event;
    std::string launch_strict_sidecar_phase;
    bool launch_sidecar_terminal = false;
    uint64_t launch_sidecar_terminal_elapsed_ms = 0;
    std::string launch_sidecar_terminal_reason;
    std::string launch_sidecar_terminal_event;
    std::string launch_sidecar_terminal_phase;
    {
        std::unique_lock<std::mutex> launch_lk(launch_state->mtx);
        const uint64_t launch_wait_start_ms = now_ms();
        bool launch_cancelled_by_stop = false;
        while (!launch_state->done)
        {
            if (sg().stop_requested.load(std::memory_order_acquire))
            {
                launch_cancelled_by_stop = true;
                break;
            }
            const uint64_t elapsed = now_ms() - launch_wait_start_ms;
            const uint64_t wall_elapsed = now_ms() - launch_call_start_ms;
            const uint64_t now_loop = now_ms();
            nlohmann::json wait_debug_event = nlohmann::json::object();
            std::string wait_debug_event_name;
            std::string wait_sidecar_phase;
            std::string wait_debug_tail;
            if (last_launch_debug_poll_ms == 0 || now_loop - last_launch_debug_poll_ms >= 1000)
            {
                wait_debug_tail = read_file_tail_for_log(child_debug_log, 2000);
                wait_debug_event = last_camoufox_debug_event_json_from_tail(wait_debug_tail);
                wait_debug_event_name = json_string_or(wait_debug_event, "event", std::string());
                wait_sidecar_phase = sidecar_timeout_phase_from_event(wait_debug_event, std::string());
                std::string terminal_reason;
                if (sidecar_launch_terminal_event(wait_debug_event, terminal_reason))
                {
                    launch_sidecar_terminal = true;
                    launch_sidecar_terminal_elapsed_ms = wall_elapsed;
                    launch_sidecar_terminal_reason = terminal_reason;
                    launch_sidecar_terminal_event = wait_debug_event_name;
                    launch_sidecar_terminal_phase = wait_sidecar_phase;
                    diag::log_tagged_critical_fmt("camoufox", "launch_browser sidecar_terminal generation=%llu child_pid=%lu elapsed_ms=%llu reason=%s event=%s phase=%s debug_tail_len=%zu",
                        static_cast<unsigned long long>(start_generation),
                        static_cast<unsigned long>(launch_child_pid),
                        static_cast<unsigned long long>(wall_elapsed),
                        launch_sidecar_terminal_reason.empty() ? "<empty>" : launch_sidecar_terminal_reason.c_str(),
                        launch_sidecar_terminal_event.empty() ? "<none>" : launch_sidecar_terminal_event.c_str(),
                        launch_sidecar_terminal_phase.empty() ? "<none>" : launch_sidecar_terminal_phase.c_str(),
                        wait_debug_tail.size());
                    launch_state->cancelled = true;
                    break;
                }
                last_launch_debug_poll_ms = now_loop;
            }
            const bool log_due = last_launch_wait_log_ms == 0 || now_loop - last_launch_wait_log_ms >= kLaunchWaitLogIntervalMs;
            if (log_due)
            {
                const uint64_t now_wait_log = now_loop;
                const uint64_t remaining_ms = elapsed >= static_cast<uint64_t>(launch_wait_ms)
                    ? 0 : static_cast<uint64_t>(launch_wait_ms) - elapsed;
                const bool tree_due = last_launch_tree_log_ms == 0 || now_wait_log - last_launch_tree_log_ms >= kLaunchWaitTreeLogIntervalMs;
                std::string tree_text;
                if (tree_due && launch_child_pid != 0)
                {
                    tree_text = compact_process_tree_with_exit(enumerate_process_tree(launch_child_pid));
                    last_launch_tree_log_ms = now_wait_log;
                }
                if (wait_debug_tail.empty())
                {
                    wait_debug_tail = read_file_tail_for_log(child_debug_log, 2000);
                    wait_debug_event = last_camoufox_debug_event_json_from_tail(wait_debug_tail);
                    wait_debug_event_name = json_string_or(wait_debug_event, "event", std::string());
                    wait_sidecar_phase = sidecar_timeout_phase_from_event(wait_debug_event, std::string());
                }
                diag::log_tagged_fmt("camoufox", "launch_browser wait generation=%llu child_pid=%lu elapsed_ms=%llu remaining_ms=%llu stop_requested=%d worker_done=%d active=%lu cleanup_pending=%d cleanup_generation=%llu cleanup_child_pid=%lu cleanup_reason=%s debug_tail_len=%zu sidecar_event=%s sidecar_phase=%s sidecar_elapsed_ms=%d sidecar_remaining_ms=%d sidecar_browser_open=%d sidecar_browser_connected=%d sidecar_page_count=%d sidecar_registered_pages=%d sidecar_active_page=%s process_tree=%s",
                    static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid),
                    static_cast<unsigned long long>(wall_elapsed), static_cast<unsigned long long>(remaining_ms),
                    sg().stop_requested.load(std::memory_order_acquire) ? 1 : 0,
                    launch_state->done ? 1 : 0,
                    static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                    sg().cleanup_pending ? 1 : 0, static_cast<unsigned long long>(sg().cleanup_generation),
                    static_cast<unsigned long>(sg().cleanup_child_pid), sg().cleanup_reason.c_str(),
                    wait_debug_tail.size(),
                    wait_debug_event_name.empty() ? "<none>" : wait_debug_event_name.c_str(),
                    wait_sidecar_phase.empty() ? "<none>" : wait_sidecar_phase.c_str(),
                    json_int_or(wait_debug_event, "elapsed_ms", -1),
                    json_int_or(wait_debug_event, "remaining_ms", json_int_or(wait_debug_event, "remaining_budget_ms", -1)),
                    json_bool_or(wait_debug_event, "browser_open", false) ? 1 : 0,
                    json_bool_or(wait_debug_event, "browser_connected", false) ? 1 : 0,
                    json_int_or(wait_debug_event, "page_count", -1),
                    json_int_or(wait_debug_event, "registered_pages", -1),
                    json_string_or(wait_debug_event, "active_page_id", std::string()).empty() ? "<empty>" : json_string_or(wait_debug_event, "active_page_id", std::string()).c_str(),
                    tree_text.empty() ? "<not-sampled>" : tree_text.c_str());
                last_launch_wait_log_ms = now_wait_log;
            }
            const uint64_t now_for_deadline = now_ms();
            if (!launch_state->done && now_for_deadline >= strict_launch_deadline_ms)
            {
                const uint64_t strict_elapsed_ms = now_for_deadline - launch_call_start_ms;
                const std::string strict_debug_tail = read_file_tail_for_log(child_debug_log, 4000);
                const nlohmann::json strict_debug_event = last_camoufox_debug_event_json_from_tail(strict_debug_tail);
                const std::string strict_debug_event_name = json_string_or(strict_debug_event, "event", std::string());
                const std::string strict_sidecar_phase = sidecar_timeout_phase_from_event(strict_debug_event, std::string());
                const std::string strict_debug_phase = last_camoufox_debug_event_from_tail(strict_debug_tail);
                const std::vector<process_tree_entry_t> strict_tree_entries = launch_child_pid == 0
                    ? std::vector<process_tree_entry_t>()
                    : enumerate_process_tree(launch_child_pid);
                const std::string strict_tree_text = compact_process_tree(strict_tree_entries);
                diag::log_tagged_critical_fmt("camoufox",
                    "start_bridge strict_launch_budget_blown generation=%llu child_pid=%lu caller_pid=%lu caller_tid=%lu elapsed_ms=%llu budget_ms=%d requested_ms=%d effective_wait_ms=%d testlab_fast_probe=%d bundled_visible=%d last_phase=%s last_debug_event=%s sidecar_phase=%s sidecar_elapsed_ms=%d sidecar_remaining_ms=%d sidecar_browser_open=%d sidecar_browser_connected=%d sidecar_page_count=%d sidecar_registered_pages=%d sidecar_active_page=%s debug_tail_len=%zu process_tree=%s",
                    static_cast<unsigned long long>(start_generation),
                    static_cast<unsigned long>(launch_child_pid),
                    static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    static_cast<unsigned long long>(strict_elapsed_ms),
                    kStrictLaunchBudgetMs,
                    cfg.launch_timeout_ms,
                    launch_wait_ms,
                    testlab_fast_probe ? 1 : 0,
                    bundled_visible_launch ? 1 : 0,
                    strict_debug_phase.empty() ? "<none>" : strict_debug_phase.c_str(),
                    strict_debug_event_name.empty() ? "<none>" : strict_debug_event_name.c_str(),
                    strict_sidecar_phase.empty() ? "<none>" : strict_sidecar_phase.c_str(),
                    json_int_or(strict_debug_event, "elapsed_ms", -1),
                    json_int_or(strict_debug_event, "remaining_ms", json_int_or(strict_debug_event, "remaining_budget_ms", -1)),
                    json_bool_or(strict_debug_event, "browser_open", false) ? 1 : 0,
                    json_bool_or(strict_debug_event, "browser_connected", false) ? 1 : 0,
                    json_int_or(strict_debug_event, "page_count", -1),
                    json_int_or(strict_debug_event, "registered_pages", -1),
                    json_string_or(strict_debug_event, "active_page_id", std::string()).empty() ? "<empty>" : json_string_or(strict_debug_event, "active_page_id", std::string()).c_str(),
                    strict_debug_tail.size(),
                    strict_tree_text.empty() ? "<empty>" : strict_tree_text.c_str());
                diag::log_tagged_critical_fmt("camoufox",
                    "start_bridge strict_launch_budget_blown debug_tail generation=%llu child_pid=%lu elapsed_ms=%llu debug_tail=%.4000s",
                    static_cast<unsigned long long>(start_generation),
                    static_cast<unsigned long>(launch_child_pid),
                    static_cast<unsigned long long>(strict_elapsed_ms),
                    strict_debug_tail.c_str());
                launch_strict_budget_blown = true;
                launch_strict_elapsed_ms = strict_elapsed_ms;
                launch_strict_last_phase = strict_debug_phase;
                launch_strict_last_event = strict_debug_event_name;
                launch_strict_sidecar_phase = strict_sidecar_phase;
                launch_state->cancelled = true;
                break;
            }
            if (elapsed >= static_cast<uint64_t>(launch_wait_ms))
                break;
            const uint64_t remaining = static_cast<uint64_t>(launch_wait_ms) - elapsed;
            const uint64_t strict_remaining_ms = now_for_deadline >= strict_launch_deadline_ms
                ? 0
                : strict_launch_deadline_ms - now_for_deadline;
            const uint64_t bounded_remaining = std::min<uint64_t>(remaining, strict_remaining_ms == 0 ? remaining : strict_remaining_ms);
            launch_state->cv.wait_for(launch_lk, std::chrono::milliseconds(static_cast<int>(std::min<uint64_t>(bounded_remaining, 250))),
                [&launch_state]() { return launch_state->done; });
        }
        bool launch_done = launch_state->done;
        if (!launch_done)
        {
            launch_state->cancelled = true;
            auto timed_out_client = sg().client;
            const uint32_t timed_out_pid = sg().child_pid;
            sg().client.reset();
            clear_page_state_locked();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            if (launch_sidecar_terminal)
            {
                sg().last_error = std::string("launch_browser sidecar terminal event reason=") +
                    (launch_sidecar_terminal_reason.empty() ? std::string("<empty>") : launch_sidecar_terminal_reason) +
                    " event=" + (launch_sidecar_terminal_event.empty() ? std::string("<none>") : launch_sidecar_terminal_event) +
                    " phase=" + (launch_sidecar_terminal_phase.empty() ? std::string("<none>") : launch_sidecar_terminal_phase) +
                    " elapsed_ms=" + std::to_string(launch_sidecar_terminal_elapsed_ms);
            }
            else if (launch_strict_budget_blown)
            {
                sg().last_error = std::string("launch_browser strict_launch_budget_blown elapsed_ms=") +
                    std::to_string(launch_strict_elapsed_ms) +
                    " budget_ms=" + std::to_string(kStrictLaunchBudgetMs) +
                    " effective_wait_ms=" + std::to_string(launch_wait_ms) +
                    " last_phase=" + (launch_strict_last_phase.empty() ? std::string("<none>") : launch_strict_last_phase) +
                    " last_debug_event=" + (launch_strict_last_event.empty() ? std::string("<none>") : launch_strict_last_event) +
                    " sidecar_phase=" + (launch_strict_sidecar_phase.empty() ? std::string("<none>") : launch_strict_sidecar_phase);
            }
            else
            {
                sg().last_error = launch_cancelled_by_stop
                    ? std::string("launch_browser cancelled by stop request")
                    : std::string("launch_browser timeout after ") + std::to_string(launch_wait_ms) + "ms";
            }
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            const std::string cleanup_reason = launch_sidecar_terminal
                ? std::string("launch_browser_sidecar_terminal_") + (launch_sidecar_terminal_reason.empty() ? std::string("unknown") : launch_sidecar_terminal_reason)
                : (launch_strict_budget_blown
                ? std::string("launch_browser_strict_budget_blown")
                : (launch_cancelled_by_stop ? std::string("launch_browser_cancelled") : std::string("launch_browser_timeout")));
            if (!launch_cancelled_by_stop)
                block_auto_restart_locked(cleanup_reason, start_generation, kAutoRestartBlockMs);
            mark_cleanup_started_locked(start_generation, timed_out_pid, cleanup_reason);
            const std::vector<process_tree_entry_t> timeout_tree_entries = timed_out_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(timed_out_pid);
            const std::string timeout_tree = compact_process_tree_with_exit(timeout_tree_entries);
            const std::string debug_tail = read_file_tail_for_log(child_debug_log, 6000);
            const nlohmann::json debug_event = last_camoufox_debug_event_json_from_tail(debug_tail);
            const std::string debug_phase = last_camoufox_debug_event_from_tail(debug_tail);
            const std::string sidecar_timeout_phase = sidecar_timeout_phase_from_event(debug_event, "mcp_response_wait");
            const char* failure_status = launch_sidecar_terminal
                ? "sidecar_terminal"
                : (launch_strict_budget_blown ? "strict_budget_blown" : (launch_cancelled_by_stop ? "cancelled" : "timeout"));
            const char* cancellation_source = launch_sidecar_terminal
                ? "sidecar_terminal_event"
                : (launch_strict_budget_blown ? "strict_launch_budget_blown" : (launch_cancelled_by_stop ? "stop_requested" : "launch_deadline"));
            sg().last_launch_diagnostics = {
                {"status", failure_status},
                {"phase", "mcp_response_wait"},
                {"transport_phase", "mcp_response_wait"},
                {"sidecar_timeout_phase", sidecar_timeout_phase},
                {"caller", "start_bridge"},
                {"cancellation_source", cancellation_source},
                {"sidecar_terminal_event", launch_sidecar_terminal},
                {"sidecar_terminal_reason", launch_sidecar_terminal_reason},
                {"sidecar_terminal_event_name", launch_sidecar_terminal_event},
                {"sidecar_terminal_phase", launch_sidecar_terminal_phase},
                {"sidecar_terminal_elapsed_ms", launch_sidecar_terminal_elapsed_ms},
                {"strict_launch_budget_blown", launch_strict_budget_blown},
                {"strict_launch_budget_ms", kStrictLaunchBudgetMs},
                {"strict_launch_elapsed_ms", launch_strict_elapsed_ms},
                {"strict_launch_last_phase", launch_strict_last_phase},
                {"strict_launch_last_debug_event", launch_strict_last_event},
                {"strict_launch_sidecar_phase", launch_strict_sidecar_phase},
                {"readiness_sub_step", sidecar_timeout_phase},
                {"timeout_phase", launch_cancelled_by_stop ? nlohmann::json(nullptr) : nlohmann::json(sidecar_timeout_phase)},
                {"generation", start_generation},
                {"attempt_id", args.value("bridge_attempt_id", std::string())},
                {"session_id", effective_cfg.session_id.empty() ? std::string("default") : effective_cfg.session_id},
                {"child_pid", timed_out_pid},
                {"child_alive", timed_out_pid != 0 && process_alive(timed_out_pid)},
                {"bridge_state", bridge_state_name(sg().state)},
                {"browser_open", sg().browser_open},
                {"page_verified", sg().page_verified},
                {"privacy_verified", sg().privacy_verified},
                {"webrtc_blocked", sg().webrtc_blocked},
                {"cleanup_pending", sg().cleanup_pending},
                {"active_page_id", sg().active_page_id},
                {"page_count", sg().pages.size()},
                {"browser_instance_count", (sg().browser_open && timed_out_pid != 0 && process_alive(timed_out_pid)) ? 1u : 0u},
                {"child_process_count", static_cast<uint32_t>(timeout_tree_entries.size())},
                {"browser_process_count", browser_process_count_from_tree(timeout_tree_entries)},
                {"elapsed_ms", sg().last_launch_ms},
                {"deadline_ms", launch_wait_ms},
                {"elapsed_budget_ms", sg().last_launch_ms},
                {"requested_ms", cfg.launch_timeout_ms},
                {"effective_ms", launch_wait_ms},
                {"stop_requested", sg().stop_requested.load(std::memory_order_acquire)},
                {"stop_epoch", sg().stop_epoch.load(std::memory_order_acquire)},
                {"cleanup_reason", cleanup_reason},
                {"cleanup_pending_before_reap", sg().cleanup_pending},
                {"debug_phase", debug_phase},
                {"process_tree", timeout_tree},
                {"process_tree_count", timeout_tree_entries.size()},
                {"debug_tail_len", debug_tail.size()},
                {"stdout_last_frame", launch_sidecar_terminal ? "launch_browser RPC cancelled after sidecar terminal event" : (launch_cancelled_by_stop ? "launch_browser RPC cancelled before response" : "launch_browser RPC deadline expired before response")},
                {"stderr_last_frame", debug_tail},
                {"stderr_last_frame_len", debug_tail.size()}
            };
            attach_debug_log_snapshot_locked(sg().last_launch_diagnostics, timed_out_pid, child_debug_log, debug_tail);
            diag::log_tagged_fmt("camoufox", "launch_browser_debug_tail_read reason=%s generation=%llu child_pid=%lu debug_phase=%s debug_tail_len=%zu",
                failure_status,
                static_cast<unsigned long long>(start_generation),
                static_cast<unsigned long>(timed_out_pid),
                debug_phase.empty() ? "<none>" : debug_phase.c_str(),
                debug_tail.size());
            diag::log_tagged_fmt("camoufox", "launch_browser %s generation=%llu child_pid=%lu elapsed_ms=%llu requested_ms=%d effective_ms=%d stop_requested=%d active=%lu cleanup_pending=%d debug_phase=%s process_tree=%s debug_tail_len=%zu debug_tail=%.6000s",
                failure_status,
                static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(timed_out_pid),
                static_cast<unsigned long long>(sg().last_launch_ms), cfg.launch_timeout_ms, launch_wait_ms,
                sg().stop_requested.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                sg().cleanup_pending ? 1 : 0,
                debug_phase.empty() ? "<none>" : debug_phase.c_str(),
                timeout_tree.empty() ? "<empty>" : timeout_tree.c_str(),
                debug_tail.size(), debug_tail.c_str());
            const nlohmann::json sticky = maybe_set_sticky_setup_failure(
                setup_ctx,
                sg().last_error + " " + debug_tail,
                sg().last_launch_diagnostics,
                start_generation,
                timed_out_pid,
                child_debug_log,
                sg().last_launch_ms);
            if (sticky.is_object() && !sticky.empty())
            {
                attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
                sg().last_error = sticky_setup_failure_error_text(json_string_or(sticky, "category", std::string()), sg().last_error);
                clear_auto_restart_block_locked("sticky_setup_failure_set");
            }
            const std::string state_error = sg().last_error;
            lk.unlock();
            const process_tree_reap_result_t reap = cleanup_client_reap_now_detach_disconnect(timed_out_client, timed_out_pid, cleanup_reason, start_generation);
            lk.lock();
            sg().last_launch_diagnostics["cleanup_pending_after_reap"] = sg().cleanup_pending;
            sg().last_launch_diagnostics["cleanup_reap"] = cleanup_reap_json(reap);
            sg().last_launch_diagnostics["cleanup_diagnostics"] = sg().cleanup_diagnostics;
            sg().last_launch_diagnostics["last_error_after_reap"] = sg().last_error.empty() ? state_error : sg().last_error;
            if (sg().last_error.empty())
                sg().last_error = state_error;
            if (timed_out_pid != 0 && reap.alive_after != 0)
            {
                sg().last_error += " cleanup_reap_failed child_pid=" + std::to_string(timed_out_pid) +
                    " alive_after=" + std::to_string(reap.alive_after) +
                    " reason=" + cleanup_reason;
                sg().cleanup_diagnostics["status"] = "failed_before_return";
                sg().cleanup_diagnostics["process_reap"] = cleanup_reap_json(reap);
                sg().last_launch_diagnostics["cleanup_diagnostics"] = sg().cleanup_diagnostics;
                sg().last_launch_diagnostics["last_error_after_reap"] = sg().last_error;
            }
            publish_state(bridge_state_t::error, sg().last_error.empty() ? state_error : sg().last_error);
            sb_launch_rpc_ms = now_ms() - sb_launch_rpc_start_ms;
            emit_stage_timing(false, launch_sidecar_terminal ? "launch_rpc_sidecar_terminal" : "launch_rpc_timeout", timed_out_pid);
            return false;
        }
        launch = std::move(launch_state->result);
    }
    const uint64_t launch_elapsed_ms = now_ms() - launch_call_start_ms;
    sb_launch_rpc_ms = now_ms() - sb_launch_rpc_start_ms;
    diag::log_tagged_fmt("camoufox", "launch_browser response success=%d generation=%llu child_pid=%lu elapsed_ms=%llu text_len=%zu data_shape=%s error_len=%zu",
        static_cast<int>(launch.success), static_cast<unsigned long long>(start_generation),
        static_cast<unsigned long>(launch_child_pid), static_cast<unsigned long long>(launch_elapsed_ms),
        launch.text.size(), json_shape(launch.data).c_str(), launch.success ? static_cast<size_t>(0) : launch.text.size());
    if (!launch.success)
    {
        const bool native_exception = result_has_native_exception(launch);
        nlohmann::json launch_payload = launch.data;
        if (!launch_payload.is_object())
            parse_text_to_json(launch.text, launch_payload);
        const nlohmann::json response_diag = launch_payload.is_object() ? launch_diagnostics_from_response(launch_payload) : nlohmann::json::object();
        const std::string failure_text = launch_payload.is_object()
            ? sidecar_failure_text(launch_payload, response_diag, launch.text.empty() ? std::string("launch_browser failed with empty MCP error") : launch.text)
            : (launch.text.empty() ? std::string("launch_browser failed with empty MCP error") : launch.text);
        sg().last_error = std::string("launch_browser failed: ") + failure_text;
        sg().last_launch_diagnostics = launch_failure_diagnostics_snapshot(
            response_diag,
            "error",
            native_exception ? "native_exception" : "mcp_transport",
            start_generation,
            effective_cfg.session_id,
            args.value("bridge_attempt_id", std::string()),
            launch_child_pid,
            cfg.launch_timeout_ms,
            launch_wait_ms,
            launch_elapsed_ms,
            failure_text,
            launch.text);
        sg().last_launch_diagnostics["sidecar_error_type"] = json_string_or(response_diag, "error_type", std::string());
        sg().last_launch_diagnostics["sidecar_error_kind"] = json_string_or(response_diag, "error_kind", std::string());
        sg().last_launch_diagnostics["sidecar_error_summary"] = json_string_or(response_diag, "error_summary", failure_text);
        diag::log_tagged_fmt("camoufox", "launch_browser failed generation=%llu attempt_id=%s child_pid=%lu child_alive=%d bridge_state=%s browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree_count=%zu error_len=%zu response_tail=%.900s last_launch_diag=%s",
            static_cast<unsigned long long>(start_generation),
            args.value("bridge_attempt_id", std::string()).c_str(),
            static_cast<unsigned long>(launch_child_pid),
            sg().last_launch_diagnostics.value("child_alive", false) ? 1 : 0,
            bridge_state_name(sg().state),
            sg().browser_open ? 1 : 0,
            sg().page_verified ? 1 : 0,
            sg().privacy_verified ? 1 : 0,
            sg().cleanup_pending ? 1 : 0,
            static_cast<size_t>(sg().last_launch_diagnostics.value("process_tree_count", 0)),
            launch.text.size(),
            compact_child_output_tail(launch.text, 900).c_str(),
            sg().last_launch_diagnostics.dump().c_str());
        const nlohmann::json sticky = maybe_set_sticky_setup_failure(
            setup_ctx,
            sg().last_error,
            sg().last_launch_diagnostics,
            start_generation,
            launch_child_pid,
            child_debug_log,
            now_ms() - bridge_start_ms);
        if (sticky.is_object() && !sticky.empty())
        {
            attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
            sg().last_error = sticky_setup_failure_error_text(json_string_or(sticky, "category", std::string()), sg().last_error);
            clear_auto_restart_block_locked("sticky_setup_failure_set");
        }
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        block_auto_restart_locked(native_exception ? "launch_browser_native_exception" : "launch_browser_failed", start_generation, kAutoRestartBlockMs);
        mark_cleanup_started_locked(start_generation, failed_pid, native_exception ? "launch_browser_native_exception" : "launch_browser_failed");
        if (native_exception)
        {
            quarantine_client_locked(std::move(failed_client), "launch_browser_native_exception");
            const std::string state_error = sg().last_error;
            finish_start_bridge_failure_cleanup_locked(lk, nullptr, failed_pid, "launch_browser_native_exception", start_generation, state_error);
        }
        else
        {
            const std::string state_error = sg().last_error;
            finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_failed", start_generation, state_error);
        }
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "launch_rpc", failed_pid);
        return false;
    }
    int browser_ready_ms_raw = -1;
    int camoufox_launch_ms_raw = -1;
    int diag_elapsed_ms = -1;
    int browser_ready_ms = -1;
    int camoufox_launch_ms = -1;
    int launch_timing_budget_ms = launch_wait_ms > 0 ? launch_wait_ms : kBundledVisibleLaunchWaitMaxMs;
    bool launch_timing_budget_slow = false;
    std::string launch_timing_budget_reason;
    nlohmann::json parsed;
    if (launch.data.is_object())
        parsed = launch.data;
    else
        parse_text_to_json(launch.text, parsed);
    if (parsed.is_object())
    {
        sg().last_launch_diagnostics = launch_diagnostics_from_response(parsed);
        if (parsed.contains("error") && parsed["error"].is_string())
        {
            const std::string parsed_error = parsed["error"].get<std::string>();
            const std::string failure_text = sidecar_failure_text(parsed, sg().last_launch_diagnostics, "launch_browser returned empty error field");
            sg().last_error = std::string("launch_browser returned error: ") + failure_text;
            sg().last_launch_diagnostics = launch_failure_diagnostics_snapshot(
                sg().last_launch_diagnostics,
                json_string_or(sg().last_launch_diagnostics, "status", std::string("error")).c_str(),
                json_string_or(sg().last_launch_diagnostics, "phase", std::string("sidecar_returned_error")).c_str(),
                start_generation,
                effective_cfg.session_id,
                args.value("bridge_attempt_id", std::string()),
                sg().child_pid,
                cfg.launch_timeout_ms,
                launch_wait_ms,
                launch_elapsed_ms,
                failure_text,
                launch.text);
            sg().last_launch_diagnostics["sidecar_error_empty"] = parsed_error.empty();
            sg().last_launch_diagnostics["sidecar_error_type"] = json_string_or(parsed, "error_type", json_string_or(sg().last_launch_diagnostics, "error_type", std::string()));
            sg().last_launch_diagnostics["sidecar_error_kind"] = json_string_or(parsed, "error_kind", json_string_or(sg().last_launch_diagnostics, "error_kind", std::string()));
            sg().last_launch_diagnostics["sidecar_error_summary"] = json_string_or(parsed, "error_summary", json_string_or(sg().last_launch_diagnostics, "error_summary", failure_text));
            const nlohmann::json launch_diag = sg().last_launch_diagnostics.is_object() ? sg().last_launch_diagnostics : nlohmann::json::object();
            diag::log_tagged_fmt("camoufox", "launch_browser returned_error generation=%llu attempt_id=%s child_pid=%lu child_alive=%d phase=%s timeout_phase=%s sidecar_error_type=%s sidecar_error_kind=%s last_event=%s diag_generation=%s session_id=%s remaining_ms=%d err_len=%zu err_tail=%.900s response_tail=%.900s process_tree_count=%zu bridge_state=%s browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d last_launch_diag=%s",
                static_cast<unsigned long long>(start_generation),
                args.value("bridge_attempt_id", std::string()).c_str(),
                static_cast<unsigned long>(sg().child_pid),
                launch_diag.value("child_alive", false) ? 1 : 0,
                json_string_or(launch_diag, "phase", std::string()).c_str(),
                json_string_or(launch_diag, "timeout_phase", std::string()).c_str(),
                json_string_or(launch_diag, "sidecar_error_type", std::string()).c_str(),
                json_string_or(launch_diag, "sidecar_error_kind", std::string()).c_str(),
                json_string_or(launch_diag, "last_debug_event_name", std::string()).c_str(),
                json_string_or(launch_diag, "generation", std::string()).c_str(),
                json_string_or(launch_diag, "session_id", std::string()).c_str(),
                json_int_or(launch_diag, "remaining_ms", -1),
                failure_text.size(),
                compact_child_output_tail(failure_text, 900).c_str(),
                compact_child_output_tail(launch.text, 900).c_str(),
                static_cast<size_t>(launch_diag.value("process_tree_count", 0)),
                bridge_state_name(sg().state),
                sg().browser_open ? 1 : 0,
                sg().page_verified ? 1 : 0,
                sg().privacy_verified ? 1 : 0,
                sg().cleanup_pending ? 1 : 0,
                launch_diag.dump().c_str());
            const nlohmann::json sticky = maybe_set_sticky_setup_failure(
                setup_ctx,
                sg().last_error,
                sg().last_launch_diagnostics,
                start_generation,
                sg().child_pid,
                child_debug_log,
                now_ms() - bridge_start_ms);
            if (sticky.is_object() && !sticky.empty())
            {
                attach_sticky_setup_failure(sg().last_launch_diagnostics, sticky);
                sg().last_error = sticky_setup_failure_error_text(json_string_or(sticky, "category", std::string()), sg().last_error);
                clear_auto_restart_block_locked("sticky_setup_failure_set");
            }
            auto failed_client = sg().client;
            const uint32_t failed_pid = sg().child_pid;
            sg().client.reset();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            clear_page_state_locked();
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            block_auto_restart_locked("launch_browser_returned_error", start_generation, kAutoRestartBlockMs);
            mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_returned_error");
            const std::string state_error = sg().last_error;
            finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_returned_error", start_generation, state_error);
            publish_state(bridge_state_t::error, sg().last_error);
            return false;
        }
        const nlohmann::json diagnostics = parsed.contains("diagnostics") && parsed["diagnostics"].is_object()
            ? parsed["diagnostics"] : nlohmann::json::object();
        const nlohmann::json window = diagnostics.contains("window") && diagnostics["window"].is_object()
            ? diagnostics["window"] : nlohmann::json::object();
        const nlohmann::json bounds = diagnostics.contains("page_bounds") && diagnostics["page_bounds"].is_object()
            ? diagnostics["page_bounds"] : nlohmann::json::object();
        const nlohmann::json viewport = diagnostics.contains("viewport") && diagnostics["viewport"].is_object()
            ? diagnostics["viewport"] : nlohmann::json::object();
        browser_ready_ms_raw = json_int_or(diagnostics, "browser_ready_ms", json_int_or(parsed, "browser_ready_ms", -1));
        camoufox_launch_ms_raw = json_int_or(diagnostics, "camoufox_launch_ms", json_int_or(parsed, "camoufox_launch_ms", -1));
        diag_elapsed_ms = json_int_or(diagnostics, "elapsed_ms", json_int_or(parsed, "elapsed_ms", -1));
        browser_ready_ms = browser_ready_ms_raw > 0 ? browser_ready_ms_raw : diag_elapsed_ms;
        camoufox_launch_ms = camoufox_launch_ms_raw > 0 ? camoufox_launch_ms_raw : browser_ready_ms;
        const std::string parsed_profile_dir = launch_profile_dir_from_response(parsed);
        const bool parsed_profile_generated = launch_profile_generated_from_response(parsed);
        if (!parsed_profile_dir.empty())
        {
            sg().active_profile_dir = parsed_profile_dir;
            sg().active_profile_generated = parsed_profile_generated;
        }
        else
        {
            sg().active_profile_generated = false;
        }
        update_privacy_from_response_locked(parsed, "launch_browser");
        diag::log_tagged_fmt("camoufox", "launch_browser parsed status=%s browser_ready_ms=%d camoufox_launch_ms=%d diag_elapsed_ms=%d profile_dir=%s profile_generated=%d window=%dx%d requested=%dx%d work_area=%dx%d viewport=%dx%d inner=%dx%d outer=%dx%d pos=%d,%d screen=%dx%d avail=%dx%d dpr=%.2f",
            json_string_or(parsed, "status", "unknown").c_str(),
            browser_ready_ms,
            camoufox_launch_ms,
            diag_elapsed_ms,
            parsed_profile_dir.empty() ? "<empty>" : parsed_profile_dir.c_str(),
            parsed_profile_generated ? 1 : 0,
            json_int_or(window, "width", -1), json_int_or(window, "height", -1),
            json_int_or(window, "requested_width", -1), json_int_or(window, "requested_height", -1),
            json_int_or(window.contains("work_area") && window["work_area"].is_object() ? window["work_area"] : nlohmann::json::object(), "width", -1),
            json_int_or(window.contains("work_area") && window["work_area"].is_object() ? window["work_area"] : nlohmann::json::object(), "height", -1),
            json_int_or(viewport, "width", -1), json_int_or(viewport, "height", -1),
            json_int_or(bounds, "innerWidth", -1), json_int_or(bounds, "innerHeight", -1),
            json_int_or(bounds, "outerWidth", -1), json_int_or(bounds, "outerHeight", -1),
            json_int_or(bounds, "screenX", -1), json_int_or(bounds, "screenY", -1),
            json_int_or(bounds, "screenWidth", -1), json_int_or(bounds, "screenHeight", -1),
            json_int_or(bounds, "availWidth", -1), json_int_or(bounds, "availHeight", -1),
            json_double_or(bounds, "devicePixelRatio", 0.0));
        const nlohmann::json phase_timings = diagnostics.contains("phase_timings") && diagnostics["phase_timings"].is_object()
            ? diagnostics["phase_timings"] : nlohmann::json::object();
        const nlohmann::json process_diag = diagnostics.contains("process") && diagnostics["process"].is_object()
            ? diagnostics["process"] : nlohmann::json::object();
        const nlohmann::json selected_page = diagnostics.contains("selected_page") && diagnostics["selected_page"].is_object()
            ? diagnostics["selected_page"] : nlohmann::json::object();
        const nlohmann::json privacy_diag = diagnostics.contains("privacy") && diagnostics["privacy"].is_object()
            ? diagnostics["privacy"] : nlohmann::json::object();
        diag::log_tagged_fmt("camoufox", "launch_browser diagnostics generation=%llu child_pid=%lu diag_generation=%s session_id=%s attempt_id=%s phase=%s remaining_ms=%d phase_count=%zu process_pid=%d descendants=%zu selected_page=%s selected_url_len=%d selected_title_len=%d page_event_count=%d privacy_shape=%s timeout_phase=%s exception_type=%s",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
            json_string_or(diagnostics, "generation", std::string()).c_str(),
            json_string_or(diagnostics, "session_id", std::string()).c_str(),
            json_string_or(diagnostics, "attempt_id", std::string()).c_str(),
            json_string_or(diagnostics, "phase", std::string()).c_str(),
            json_int_or(diagnostics, "remaining_ms", -1),
            phase_timings.size(),
            json_int_or(process_diag, "pid", -1),
            json_array_size_or_zero(process_diag, "descendants"),
            json_string_or(selected_page, "page_id", std::string()).c_str(),
            json_int_or(selected_page, "url_len", -1),
            json_int_or(selected_page, "title_len", -1),
            json_int_or(selected_page, "event_count", -1),
            json_shape(privacy_diag).c_str(),
            json_string_or(diagnostics, "timeout_phase", std::string()).c_str(),
            json_string_or(diagnostics, "exception_type", std::string()).c_str());
        if (bundled_visible_launch && (browser_ready_ms_raw <= 0 || camoufox_launch_ms_raw <= 0) && diag_elapsed_ms > 0)
        {
            diag::log_tagged_fmt("camoufox", "launch_browser timing_budget_elapsed_fallback generation=%llu child_pid=%lu browser_ready_raw=%d camoufox_launch_raw=%d diag_elapsed_ms=%d effective_browser_ready_ms=%d effective_camoufox_launch_ms=%d max_ms=%d",
                static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
                browser_ready_ms_raw, camoufox_launch_ms_raw, diag_elapsed_ms, browser_ready_ms, camoufox_launch_ms, launch_timing_budget_ms);
        }
        if (bundled_visible_launch && (camoufox_launch_ms <= 0 || camoufox_launch_ms > launch_timing_budget_ms || diag_elapsed_ms <= 0 || diag_elapsed_ms > launch_timing_budget_ms))
        {
            launch_timing_budget_slow = true;
            launch_timing_budget_reason = (camoufox_launch_ms <= 0 || diag_elapsed_ms <= 0)
                ? "missing_or_invalid_timing"
                : "elapsed_exceeded_old_budget";
            sg().last_launch_diagnostics["timing_budget_slow_pending"] = {
                {"reason", launch_timing_budget_reason},
                {"browser_ready_ms_raw", browser_ready_ms_raw},
                {"camoufox_launch_ms_raw", camoufox_launch_ms_raw},
                {"diag_elapsed_ms", diag_elapsed_ms},
                {"browser_ready_ms_effective", browser_ready_ms},
                {"camoufox_launch_ms_effective", camoufox_launch_ms},
                {"old_budget_ms", launch_timing_budget_ms}
            };
            diag::log_tagged_fmt("camoufox", "launch_browser timing_budget_slow_pending generation=%llu child_pid=%lu reason=%s browser_ready_raw=%d camoufox_launch_raw=%d browser_ready_ms=%d camoufox_launch_ms=%d old_budget_ms=%d diag_elapsed_ms=%d privacy_verified=%d page_verified=%d browser_open=%d data_shape=%s response_tail=%.900s",
                static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
                launch_timing_budget_reason.c_str(),
                browser_ready_ms_raw, camoufox_launch_ms_raw, browser_ready_ms, camoufox_launch_ms,
                launch_timing_budget_ms, diag_elapsed_ms,
                sg().privacy_verified ? 1 : 0,
                sg().page_verified ? 1 : 0,
                sg().browser_open ? 1 : 0,
                json_shape(parsed).c_str(), compact_child_output_tail(launch.text, 900).c_str());
        }
    }
    if (!sg().privacy_verified)
    {
        sg().last_error = "launch_browser privacy verification diagnostics missing or failed";
        diag::log_tagged_fmt("camoufox", "launch_browser privacy_not_verified generation=%llu child_pid=%lu data_shape=%s response_tail=%.900s",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
            json_shape(parsed).c_str(), compact_child_output_tail(launch.text, 900).c_str());
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_privacy_not_verified");
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_privacy_not_verified", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (sg().stop_requested.load(std::memory_order_acquire))
    {
        sg().last_error = "launch_browser cancelled by stop request";
        auto cancelled_client = sg().client;
        const uint32_t cancelled_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, cancelled_pid, "launch_browser_cancelled_by_stop");
        diag::log_tagged_fmt("camoufox", "launch_browser cancelled_by_stop generation=%llu child_pid=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(cancelled_pid),
            static_cast<unsigned long long>(sg().last_launch_ms));
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, cancelled_client, cancelled_pid, "launch_browser_cancelled_by_stop", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (sg().child_pid == 0 || !process_alive(sg().child_pid))
    {
        sg().last_error = "launch_browser child process is not alive after launch";
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_child_not_alive");
        diag::log_tagged_fmt("camoufox", "launch_browser child_not_alive generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(failed_pid));
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_child_not_alive", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().browser_open = true;
    sg().state = bridge_state_t::ready;
    sg().page_verified = false;
    const uint64_t sb_readiness_probe_start_ms = now_ms();
    nlohmann::json page_args;
    call_result_t page;
    const int kReadinessProbeMaxRetries = 3;
    for (int retry = 0; retry < kReadinessProbeMaxRetries; ++retry)
    {
        page = call_with_deadline("get_page_info", page_args, kReadinessProbeTimeoutMs);
        if (page.ok && page.data.is_object() && page.data.contains("url") && page.data["url"].is_string())
            break;
        diag::log_tagged_fmt("camoufox", "launch_browser readiness_probe_retry generation=%llu retry=%d ok=%d err=%s",
            static_cast<unsigned long long>(start_generation), retry,
            static_cast<int>(page.ok), page.error.c_str());
        if (retry < kReadinessProbeMaxRetries - 1)
            Sleep(2000);
    }
    sb_readiness_probe_ms = now_ms() - sb_readiness_probe_start_ms;
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("launch readiness probe did not return page URL") : page.error;
        sg().last_error = std::string("launch readiness failed: ") + err;
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_readiness_failed");
        diag::log_tagged_fmt("camoufox", "launch_browser readiness_failed generation=%llu child_pid=%lu err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(failed_pid),
            err.c_str(), json_shape(page.data).c_str(), static_cast<unsigned long long>(sg().last_launch_ms));
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_readiness_failed", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "readiness_probe", failed_pid);
        return false;
    }
    update_page_cache_from_json_locked(page.data, "launch_readiness");
    if (sg().active_page_url.empty())
        sg().active_page_url = page.data["url"].get<std::string>();
    if (sg().active_page_title.empty())
        sg().active_page_title = json_string_or(page.data, "title", std::string());
    sg().page_verified = true;
    sg().last_verified_ms = now_ms();
    const uint64_t sb_visible_window_start_ms = now_ms();
    const visible_window_snapshot_t ready_visible = sample_visible_window_proof(sg().child_pid);
    sb_visible_window_ms = now_ms() - sb_visible_window_start_ms;
    sg().last_launch_diagnostics["visible_window_proof"] = visible_window_proof_json(ready_visible, sg().child_pid, start_generation, "launch_ready");
    log_visible_window_proof("launch_ready", start_generation, sg().child_pid, ready_visible);
    if (!effective_cfg.headless && ready_visible.visible_window_count == 0)
    {
        sg().last_error = "launch_browser visible window proof missing after readiness";
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_visible_window_missing");
        diag::log_tagged_fmt("camoufox", "launch_browser visible_window_missing generation=%llu child_pid=%lu child_processes=%u browser_processes=%u process_pids=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation),
            static_cast<unsigned long>(failed_pid),
            static_cast<unsigned>(ready_visible.child_process_count),
            static_cast<unsigned>(ready_visible.browser_process_count),
            ready_visible.process_pids.empty() ? "<empty>" : ready_visible.process_pids.c_str(),
            static_cast<unsigned long long>(sg().last_launch_ms));
        const std::string state_error = sg().last_error;
        finish_start_bridge_failure_cleanup_locked(lk, failed_client, failed_pid, "launch_browser_visible_window_missing", start_generation, state_error);
        publish_state(bridge_state_t::error, sg().last_error);
        emit_stage_timing(false, "visible_window", failed_pid);
        return false;
    }
    if (launch_timing_budget_slow)
    {
        const bridge_health_snapshot_t timing_health = sample_bridge_health(sg().child_pid, true);
        sg().last_launch_diagnostics["timing_budget_slow_accepted"] = {
            {"reason", launch_timing_budget_reason},
            {"generation", start_generation},
            {"child_pid", sg().child_pid},
            {"browser_ready_ms_raw", browser_ready_ms_raw},
            {"camoufox_launch_ms_raw", camoufox_launch_ms_raw},
            {"diag_elapsed_ms", diag_elapsed_ms},
            {"browser_ready_ms_effective", browser_ready_ms},
            {"camoufox_launch_ms_effective", camoufox_launch_ms},
            {"old_budget_ms", launch_timing_budget_ms},
            {"child_alive", timing_health.child_alive},
            {"child_processes", timing_health.child_process_count},
            {"browser_processes", timing_health.browser_process_count},
            {"min_browser_processes", kMinReadyBrowserProcessCount},
            {"browser_open", sg().browser_open},
            {"page_verified", sg().page_verified},
            {"privacy_verified", sg().privacy_verified},
            {"visible_windows", ready_visible.visible_window_count},
            {"cleanup_pending", sg().cleanup_pending},
            {"process_tree", timing_health.process_tree}
        };
        diag::log_tagged_fmt("camoufox", "launch_browser timing_budget_slow_accepted generation=%llu child_pid=%lu reason=%s browser_ready_raw=%d camoufox_launch_raw=%d browser_ready_ms=%d camoufox_launch_ms=%d diag_elapsed_ms=%d old_budget_ms=%d child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d visible_windows=%u cleanup_pending=%d process_tree=%s",
            static_cast<unsigned long long>(start_generation),
            static_cast<unsigned long>(sg().child_pid),
            launch_timing_budget_reason.c_str(),
            browser_ready_ms_raw,
            camoufox_launch_ms_raw,
            browser_ready_ms,
            camoufox_launch_ms,
            diag_elapsed_ms,
            launch_timing_budget_ms,
            timing_health.child_alive ? 1 : 0,
            static_cast<unsigned>(timing_health.child_process_count),
            static_cast<unsigned>(timing_health.browser_process_count),
            static_cast<unsigned>(kMinReadyBrowserProcessCount),
            sg().browser_open ? 1 : 0,
            sg().page_verified ? 1 : 0,
            sg().privacy_verified ? 1 : 0,
            static_cast<unsigned>(ready_visible.visible_window_count),
            sg().cleanup_pending ? 1 : 0,
            timing_health.process_tree.empty() ? "<empty>" : timing_health.process_tree.c_str());
    }
    sg().state = bridge_state_t::ready;
    sg().last_error.clear();
    sg().last_launch_ms = now_ms() - bridge_start_ms;
    const url_log_t ready_url = summarize_url_for_log(sg().active_page_url);
    diag::log_tagged_fmt("camoufox", "bridge ready generation=%llu child_pid=%lu python=%s profile_dir=%s active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu elapsed_ms=%llu",
        static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid), python_path.c_str(),
        sg().active_profile_dir.empty() ? "<empty>" : sg().active_profile_dir.c_str(),
        ready_url.host.c_str(), ready_url.path.c_str(), static_cast<int>(ready_url.has_query),
        ready_url.length, sg().active_page_title.size(), static_cast<unsigned long long>(sg().last_launch_ms));
    publish_state(bridge_state_t::ready, std::string());
    emit_stage_timing(true, "ready", sg().child_pid);
    clear_sticky_setup_failure("start_bridge_ready");
    launch_guard.committed = true;
    if (launch_guard.token_ptr && *launch_guard.token_ptr != 0)
        release_launch_admission(*launch_guard.token_ptr, "start_bridge_ready", effective_cfg.session_id);
    return true;
}

uint64_t begin_activity(const char* owner)
{
    const uint64_t token = sg().next_activity_token.fetch_add(1, std::memory_order_relaxed);
    const uint32_t active = sg().active_activities.fetch_add(1, std::memory_order_acq_rel) + 1;
    ++g_bridge_activity_depth;
    const auto status = get_status();
    diag::log_tagged_fmt("camoufox", "activity_begin owner=%s token=%llu active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu",
        safe_reason(owner), static_cast<unsigned long long>(token), static_cast<unsigned long>(active),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()), static_cast<int>(status.state),
        static_cast<unsigned long long>(status.generation), static_cast<unsigned long>(status.child_pid),
        status.child_alive ? 1 : 0, status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
        status.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(status.total_errors));
    return token;
}

void end_activity(uint64_t token, const char* owner)
{
    uint32_t previous = sg().active_activities.load(std::memory_order_acquire);
    while (previous != 0 && !sg().active_activities.compare_exchange_weak(previous, previous - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
    if (g_bridge_activity_depth != 0)
        --g_bridge_activity_depth;
    const uint32_t active = sg().active_activities.load(std::memory_order_acquire);
    const auto status = get_status();
    diag::log_tagged_fmt("camoufox", "activity_end owner=%s token=%llu active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu",
        safe_reason(owner), static_cast<unsigned long long>(token), static_cast<unsigned long>(active),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()), static_cast<int>(status.state),
        static_cast<unsigned long long>(status.generation), static_cast<unsigned long>(status.child_pid),
        status.child_alive ? 1 : 0, status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
        status.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(status.total_errors));
}

bool stop_bridge(const char* reason)
{
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
    {
        diag::log_tagged_critical_fmt("camoufox", "stop_bridge_lifecycle_busy reason=%s wait_ms=%llu",
            safe_reason(reason), static_cast<unsigned long long>(kLifecycleLockWaitMs));
        return false;
    }
    const uint64_t stop_start_ms = now_ms();
    const uint64_t stop_epoch = sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    const char* stop_reason = safe_reason(reason);
    diag::log_tagged_fmt("camoufox", "stop_bridge entry epoch=%llu reason=%s active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu",
        static_cast<unsigned long long>(stop_epoch), stop_reason,
        static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    sg().stop_requested.store(true, std::memory_order_release);
    diag::log_tagged_fmt("camoufox", "stop_bridge stop_requested_set epoch=%llu reason=%s",
        static_cast<unsigned long long>(stop_epoch), stop_reason);
    if (g_bridge_activity_depth == 0)
    {
        const uint64_t activity_wait_start_ms = now_ms();
        uint64_t last_activity_log_ms = activity_wait_start_ms;
        while (sg().active_activities.load(std::memory_order_acquire) != 0 &&
            now_ms() - activity_wait_start_ms < kActivityDrainWaitMs)
        {
            const uint64_t now = now_ms();
            if (now - last_activity_log_ms >= 1000)
            {
                const auto status = get_status();
                diag::log_tagged_fmt("camoufox", "stop_bridge waiting_for_activity reason=%s active=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d elapsed_ms=%llu limit_ms=%llu",
                    stop_reason, static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                    static_cast<int>(status.state), static_cast<unsigned long long>(status.generation),
                    static_cast<unsigned long>(status.child_pid), status.child_alive ? 1 : 0,
                    status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
                    status.cleanup_pending ? 1 : 0,
                    static_cast<unsigned long long>(now - activity_wait_start_ms),
                    static_cast<unsigned long long>(kActivityDrainWaitMs));
                last_activity_log_ms = now;
            }
            Sleep(25);
        }
        const uint32_t active_after_wait = sg().active_activities.load(std::memory_order_acquire);
        if (active_after_wait != 0)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_timeout reason=%s active=%lu elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long>(active_after_wait),
                static_cast<unsigned long long>(now_ms() - activity_wait_start_ms));
        }
        else if (now_ms() != activity_wait_start_ms)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_drained reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - activity_wait_start_ms));
        }
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_bypass reason=%s tls_depth=%lu active=%lu",
            stop_reason, static_cast<unsigned long>(g_bridge_activity_depth),
            static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)));
    }
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge waiting_for_operation_cancel_signal reason=%s", stop_reason);
        op_lk.lock();
        diag::log_tagged_fmt("camoufox", "stop_bridge operation_lock_acquired_after_wait reason=%s elapsed_ms=%llu",
            stop_reason, static_cast<unsigned long long>(now_ms() - stop_start_ms));
    }
    std::shared_ptr<mcp_client::client_t> cli;
    bool browser_open = false;
    uint32_t child_pid = 0;
    uint64_t stop_generation = 0;
    {
        std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::defer_lock);
        const uint64_t state_wait_start_ms = now_ms();
        while (!lk.try_lock())
        {
            if (now_ms() - state_wait_start_ms >= 5000)
                break;
            Sleep(10);
        }
        if (!lk.owns_lock())
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge busy_stop_requested reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - stop_start_ms));
            return false;
        }
        if (now_ms() - state_wait_start_ms != 0)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge state_lock_acquired reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - state_wait_start_ms));
        }
        diag::log_tagged_fmt("camoufox", "stop_bridge state_snapshot reason=%s state=%d generation=%llu child_pid=%lu browser_open=%d page_verified=%d cleanup_pending=%d",
            stop_reason,
            static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long>(sg().child_pid), static_cast<int>(sg().browser_open),
            static_cast<int>(sg().page_verified), static_cast<int>(sg().cleanup_pending));
        if (sg().state == bridge_state_t::stopped)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge already_stopped reason=%s", stop_reason);
            const uint64_t stale_launch_token = sg().launch_admission_token;
            sg().launch_admission_token = 0;
            const std::string stale_session = sg().session_id.empty() ? std::string("default") : sg().session_id;
            sg().client.reset();
            clear_page_state_locked();
            clear_auto_restart_block_locked("stop_bridge_already_stopped");
            clear_sticky_setup_failure("stop_bridge_already_stopped");
            sg().child_pid = 0;
            sg().cleanup_pending = false;
            sg().last_cleanup_ms = now_ms() - stop_start_ms;
            lk.unlock();
            release_launch_admission(stale_launch_token, "stop_bridge_already_stopped", stale_session);
            return true;
        }
        cli = sg().client;
        browser_open = sg().browser_open;
        child_pid = sg().child_pid;
        stop_generation = ++sg().generation;
        sg().client.reset();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::stopped;
        sg().last_error.clear();
        clear_auto_restart_block_locked("stop_bridge");
        clear_sticky_setup_failure("stop_bridge");
        mark_cleanup_started_locked(stop_generation, child_pid, std::string("stop_bridge:") + stop_reason);
    }
    {
        uint64_t launch_token = 0;
        std::string launch_session;
        {
            std::lock_guard<std::recursive_mutex> slk(sg().mtx);
            launch_token = sg().launch_admission_token;
            sg().launch_admission_token = 0;
            launch_session = sg().session_id.empty() ? std::string("default") : sg().session_id;
        }
        release_launch_admission(launch_token, stop_reason, launch_session);
    }
    diag::log_tagged_fmt("camoufox", "stop_bridge cleanup_sync reason=%s generation=%llu child_pid=%lu client=%d browser_open=%d",
        stop_reason, static_cast<unsigned long long>(stop_generation), static_cast<unsigned long>(child_pid),
        cli ? 1 : 0, browser_open ? 1 : 0);
    cleanup_client_reap_now_detach_disconnect(cli, child_pid, std::string("stop_bridge:") + stop_reason, stop_generation);
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_fmt("camoufox", "bridge stopped reason=%s generation=%llu elapsed_ms=%llu",
        stop_reason, static_cast<unsigned long long>(stop_generation), static_cast<unsigned long long>(now_ms() - stop_start_ms));
    return true;
}

bool force_cleanup_default_impl(const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* cleanup_reason = safe_reason(reason);
    const uint64_t epoch = sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    sg().stop_requested.store(true, std::memory_order_release);

    std::shared_ptr<mcp_client::client_t> cli;
    uint32_t child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    std::string profile_dir;
    bridge_state_t state_before = bridge_state_t::stopped;
    bool browser_open = false;
    bool page_verified = false;
    bool cleanup_pending = false;
    uint64_t generation = epoch;
    bool state_locked = false;
    bool cleanup_marked = false;

    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::defer_lock);
    const uint64_t lock_start = now_ms();
    while (!(state_locked = lk.try_lock()))
    {
        if (now_ms() - lock_start >= 750)
            break;
        Sleep(10);
    }

    if (state_locked)
    {
        state_before = sg().state;
        browser_open = sg().browser_open;
        page_verified = sg().page_verified;
        cleanup_pending = sg().cleanup_pending;
        if (sg().child_pid != 0)
            child_pid = sg().child_pid;
        else if (sg().cleanup_child_pid != 0)
            child_pid = sg().cleanup_child_pid;
        else if (child_pid == 0)
            child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
        profile_dir = !sg().active_profile_dir.empty() ? sg().active_profile_dir : sg().cleanup_profile_dir;
        cli = sg().client;
        generation = ++sg().generation;
        sg().client.reset();
        sg().server_command.clear();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::stopped;
        sg().last_error = std::string("force_cleanup requested: ") + cleanup_reason;
        clear_auto_restart_block_locked("force_cleanup");
        clear_sticky_setup_failure("force_cleanup");
        if (child_pid != 0 || cli)
        {
            mark_cleanup_started_locked(generation, child_pid, std::string("force_cleanup:") + cleanup_reason);
            cleanup_marked = true;
        }
        else
        {
            sg().cleanup_pending = false;
            sg().last_cleanup_ms = now_ms() - t0;
        }
        sg().active_profile_dir.clear();
        sg().active_profile_generated = false;
        const uint64_t force_launch_token = sg().launch_admission_token;
        sg().launch_admission_token = 0;
        const std::string force_launch_session = sg().session_id.empty() ? std::string("default") : sg().session_id;
        lk.unlock();
        release_launch_admission(force_launch_token, cleanup_reason, force_launch_session);
    }
    else
    {
        diag::log_tagged_critical_fmt("camoufox", "force_cleanup_state_lock_busy epoch=%llu reason=%s lock_elapsed_ms=%llu tracked_child_pid=%lu",
            static_cast<unsigned long long>(epoch),
            cleanup_reason,
            static_cast<unsigned long long>(now_ms() - lock_start),
            static_cast<unsigned long>(child_pid));
    }

    const std::vector<process_tree_entry_t> before_tree = child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(child_pid);
    const size_t descendants_before = before_tree.size() > 0 ? before_tree.size() - 1 : 0;
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_begin epoch=%llu generation=%llu reason=%s state_locked=%d lock_elapsed_ms=%llu state_before=%d child_pid=%lu descendants=%zu profile_dir=%s browser_open=%d page_verified=%d cleanup_pending=%d client=%d",
        static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason,
        state_locked ? 1 : 0, static_cast<unsigned long long>(now_ms() - lock_start),
        static_cast<int>(state_before), static_cast<unsigned long>(child_pid), descendants_before,
        profile_dir.empty() ? "<empty>" : profile_dir.c_str(), browser_open ? 1 : 0, page_verified ? 1 : 0,
        cleanup_pending ? 1 : 0, cli ? 1 : 0);

    process_tree_reap_result_t reap;
    if (child_pid != 0)
        reap = terminate_process_tree_sync(child_pid, std::string("force_cleanup:") + cleanup_reason);
    else
        diag::log_tagged_critical_fmt("camoufox", "force_cleanup_no_pid epoch=%llu generation=%llu reason=%s", static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason);

    sweep_stale_camoufox_processes_by_name(0, std::string("force_cleanup_orphan_sweep:") + cleanup_reason);

    if (cli)
        disconnect_client_async(cli, std::string("force_cleanup:") + cleanup_reason + ":disconnect");

    if (cleanup_marked)
        mark_cleanup_finished(generation, now_ms() - t0, std::string("force_cleanup:") + cleanup_reason,
            child_pid == 0 || reap.alive_after == 0);
    else if (child_pid != 0 && reap.alive_after == 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == child_pid)
        sg().tracked_child_pid.store(0, std::memory_order_release);

    const bool success = state_locked && (child_pid == 0 || reap.alive_after == 0);
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_end epoch=%llu generation=%llu reason=%s success=%d child_pid=%lu descendants_before=%zu alive_after=%zu profile_dir=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason,
        success ? 1 : 0, static_cast<unsigned long>(child_pid), reap.descendants_before, reap.alive_after,
        profile_dir.empty() ? "<empty>" : profile_dir.c_str(), static_cast<unsigned long long>(now_ms() - t0));
    return success;
}

bool force_cleanup(const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* cleanup_reason = safe_reason(reason);
    lifecycle_guard_t cleanup_guard;
    if (!cleanup_guard.acquired)
    {
        diag::log_tagged_critical_fmt("camoufox", "force_cleanup_already_in_progress reason=%s wait_ms=%llu elapsed_ms=%llu caller_pid=%lu caller_tid=%lu",
            cleanup_reason,
            static_cast<unsigned long long>(kLifecycleLockWaitMs),
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_guard_acquired reason=%s wait_elapsed_ms=%llu caller_pid=%lu caller_tid=%lu",
        cleanup_reason,
        static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return force_cleanup_default_impl(reason);
}

static nlohmann::json stale_cleanup_proof_json(const stale_sidecar_cleanup_proof_t& proof)
{
    return {
        {"diagnostic_id", proof.diagnostic_id},
        {"request_id", proof.request_id},
        {"tool", proof.tool},
        {"action", proof.action},
        {"bridge_session_id", proof.bridge_session_id},
        {"mcp_session_id", proof.mcp_session_id},
        {"mcp_session_hash", proof.mcp_session_hash},
        {"principal_bucket", proof.principal_bucket},
        {"expected_executable_path", proof.expected_executable_path},
        {"expected_sidecar_pid", proof.expected_sidecar_pid},
        {"expected_bridge_generation", proof.expected_bridge_generation},
        {"expected_process_creation_time_100ns", proof.expected_process_creation_time_100ns},
        {"lease_token", proof.lease_token},
        {"registry_generation", proof.registry_generation},
        {"operation_generation", proof.operation_generation},
        {"sidecar_ownership_marker", proof.sidecar_ownership_marker}
    };
}

static std::string compact_string_list(const std::vector<std::string>& values)
{
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i)
    {
        if (i)
            oss << ",";
        oss << values[i];
    }
    return oss.str();
}

static void stale_cleanup_add_missing_proof_fields(const stale_sidecar_cleanup_proof_t& proof, std::vector<std::string>& missing)
{
    if (proof.expected_executable_path.empty())
        missing.push_back("expected_executable_path");
    if (proof.expected_sidecar_pid == 0)
        missing.push_back("expected_sidecar_pid");
    if (proof.bridge_session_id.empty())
        missing.push_back("bridge_session_id");
    if (proof.mcp_session_id.empty())
        missing.push_back("mcp_session_id");
    if (proof.mcp_session_hash.empty())
        missing.push_back("mcp_session_hash");
    if (proof.registry_generation == 0)
        missing.push_back("registry_generation");
    if (proof.lease_token == 0)
        missing.push_back("lease_token");
    if (proof.operation_generation == 0)
        missing.push_back("operation_generation");
    if (proof.principal_bucket.empty())
        missing.push_back("principal_bucket");
    if (proof.expected_bridge_generation == 0)
        missing.push_back("expected_bridge_generation");
    if (proof.expected_process_creation_time_100ns == 0)
        missing.push_back("expected_process_creation_time_100ns");
    if (proof.sidecar_ownership_marker.empty())
        missing.push_back("sidecar_ownership_marker");
}

static stale_sidecar_cleanup_result_t stale_cleanup_rejected(const stale_sidecar_cleanup_proof_t& proof,
                                                            const char* reason,
                                                            const std::vector<std::string>& missing,
                                                            nlohmann::json extra = nlohmann::json::object())
{
    stale_sidecar_cleanup_result_t result;
    result.rejected = true;
    result.reason = reason ? reason : "rejected";
    result.diagnostics = {
        {"result", "rejected"},
        {"reason", result.reason},
        {"missing", missing},
        {"proof", stale_cleanup_proof_json(proof)}
    };
    if (extra.is_object())
    {
        for (auto it = extra.begin(); it != extra.end(); ++it)
            result.diagnostics[it.key()] = it.value();
    }
    const std::string missing_text = compact_string_list(missing);
    diag::log_tagged_fmt("camoufox",
        "MCP-CAMOUFOX-STALE-CLEANUP-REJECTED reason=%s missing=%s diag_id=%s request_id=%s tool=%s action=%s bridge_session=%s mcp_session=%s session_hash=%s principal_bucket=%s lease_token=%llu operation_generation=%llu registry_generation=%llu expected_generation=%llu expected_pid=%lu expected_path=%s marker=%s",
        result.reason.c_str(),
        missing_text.empty() ? "<none>" : missing_text.c_str(),
        proof.diagnostic_id.c_str(),
        proof.request_id.c_str(),
        proof.tool.c_str(),
        proof.action.c_str(),
        proof.bridge_session_id.c_str(),
        proof.mcp_session_id.c_str(),
        proof.mcp_session_hash.c_str(),
        proof.principal_bucket.c_str(),
        static_cast<unsigned long long>(proof.lease_token),
        static_cast<unsigned long long>(proof.operation_generation),
        static_cast<unsigned long long>(proof.registry_generation),
        static_cast<unsigned long long>(proof.expected_bridge_generation),
        static_cast<unsigned long>(proof.expected_sidecar_pid),
        proof.expected_executable_path.c_str(),
        proof.sidecar_ownership_marker.c_str());
    return result;
}

static nlohmann::json stale_cleanup_identity_json(const process_identity_snapshot_t& identity)
{
    return {
        {"opened", identity.opened},
        {"exit_queried", identity.exit_queried},
        {"image_queried", identity.image_queried},
        {"times_queried", identity.times_queried},
        {"alive", identity.alive},
        {"gle", static_cast<uint32_t>(identity.gle)},
        {"exit_code", static_cast<uint32_t>(identity.exit_queried ? identity.exit_code : 0)},
        {"image_gle", static_cast<uint32_t>(identity.image_gle)},
        {"times_gle", static_cast<uint32_t>(identity.times_gle)},
        {"creation_time_100ns", identity.creation_time_100ns},
        {"image_path", identity.image_path}
    };
}

static bool stale_cleanup_process_identity_matches(const stale_sidecar_cleanup_proof_t& proof,
                                                   const process_identity_snapshot_t& identity,
                                                   std::vector<std::string>& mismatches)
{
    if (!identity.opened)
        mismatches.push_back("process_open");
    if (!identity.exit_queried)
        mismatches.push_back("process_exit_query");
    if (!identity.alive)
        mismatches.push_back("process_alive");
    if (!identity.image_queried || identity.image_path.empty())
        mismatches.push_back("process_image_path");
    else if (!normalized_process_path_equal(identity.image_path, proof.expected_executable_path))
        mismatches.push_back("process_image_path_mismatch");
    if (!identity.times_queried || identity.creation_time_100ns == 0)
        mismatches.push_back("process_creation_time");
    else if (identity.creation_time_100ns != proof.expected_process_creation_time_100ns)
        mismatches.push_back("process_creation_time_mismatch");
    return mismatches.empty();
}

static void clear_managed_page_state_locked(managed_session_t& session)
{
    session.browser_open = false;
    session.page_verified = false;
    session.pages.clear();
    clear_privacy_locked(session);
    session.active_page_id.clear();
    session.active_page_url.clear();
    session.active_page_title.clear();
    session.active_profile_dir.clear();
    session.active_profile_generated = false;
}

stale_sidecar_cleanup_result_t cleanup_stale_sidecar_if_owned(const stale_sidecar_cleanup_proof_t& proof)
{
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
    {
        return stale_cleanup_rejected(proof, "lifecycle_busy", {});
    }
    std::vector<std::string> missing;
    stale_cleanup_add_missing_proof_fields(proof, missing);
    if (!missing.empty())
        return stale_cleanup_rejected(proof, "missing_proof", missing);

    const std::string sid = normalize_session_id(proof.bridge_session_id);
    const bool default_session = is_default_session_id(sid);
    const uint64_t t0 = now_ms();
    std::shared_ptr<mcp_client::client_t> cli;
    uint32_t child_pid = 0;
    uint64_t cleanup_generation = 0;
    std::string state_command;
    std::string state_expected_path;
    nlohmann::json proof_state = nlohmann::json::object();

    if (default_session)
    {
        std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
        if (!lk.owns_lock())
            return stale_cleanup_rejected(proof, "bridge_state_lock_busy", {});

        state_command = sg().server_command;
        state_expected_path = sidecar_executable_path_from_command(state_command);
        proof_state = {
            {"state_session_id", sg().session_id.empty() ? std::string("default") : sg().session_id},
            {"state_generation", sg().generation},
            {"state_child_pid", sg().child_pid},
            {"state_server_command", state_command},
            {"state_expected_executable_path", state_expected_path},
            {"state_cleanup_pending", sg().cleanup_pending},
            {"state_cleanup_child_pid", sg().cleanup_child_pid}
        };
        std::vector<std::string> mismatches;
        if (normalize_session_id(sg().session_id.empty() ? std::string("default") : sg().session_id) != sid)
            mismatches.push_back("bridge_session_id_mismatch");
        if (sg().generation != proof.expected_bridge_generation)
            mismatches.push_back("bridge_generation_mismatch");
        if (sg().child_pid != proof.expected_sidecar_pid)
            mismatches.push_back("sidecar_pid_mismatch");
        if (state_expected_path.empty())
            mismatches.push_back("state_expected_executable_path");
        else if (!normalized_process_path_equal(state_expected_path, proof.expected_executable_path))
            mismatches.push_back("state_executable_path_mismatch");
        if (sg().cleanup_pending)
            mismatches.push_back("cleanup_already_pending");
        if (!mismatches.empty())
            return stale_cleanup_rejected(proof, "state_proof_mismatch", mismatches, proof_state);

        const process_identity_snapshot_t identity = query_process_identity_snapshot(proof.expected_sidecar_pid);
        std::vector<std::string> identity_mismatches;
        if (!stale_cleanup_process_identity_matches(proof, identity, identity_mismatches))
        {
            proof_state["process_identity"] = stale_cleanup_identity_json(identity);
            return stale_cleanup_rejected(proof, "process_identity_mismatch", identity_mismatches, proof_state);
        }

        cli = sg().client;
        child_pid = sg().child_pid;
        cleanup_generation = ++sg().generation;
        sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel);
        sg().stop_requested.store(true, std::memory_order_release);
        sg().client.reset();
        sg().server_command.clear();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::stopped;
        sg().last_error = std::string("mcp stale sidecar cleanup: ") + proof.diagnostic_id;
        clear_auto_restart_block_locked("mcp_stale_sidecar_cleanup");
        clear_sticky_setup_failure("mcp_stale_sidecar_cleanup");
        mark_cleanup_started_locked(cleanup_generation, child_pid, std::string("mcp_stale_sidecar_cleanup:") + proof.diagnostic_id);
        const uint64_t stale_launch_token = sg().launch_admission_token;
        sg().launch_admission_token = 0;
        const std::string stale_launch_session = sg().session_id.empty() ? std::string("default") : sg().session_id;
        proof_state["process_identity"] = stale_cleanup_identity_json(identity);
        proof_state["cleanup_generation"] = cleanup_generation;
        lk.unlock();
        release_launch_admission(stale_launch_token, "stale_cleanup", stale_launch_session);
    }
    else
    {
        auto session = get_managed_session(sid, false);
        if (!session)
            return stale_cleanup_rejected(proof, "managed_session_missing", {});
        std::unique_lock<std::recursive_mutex> lk(session->mtx, std::try_to_lock);
        if (!lk.owns_lock())
            return stale_cleanup_rejected(proof, "managed_state_lock_busy", {});

        state_command = session->server_command;
        state_expected_path = sidecar_executable_path_from_command(state_command);
        proof_state = {
            {"state_session_id", session->session_id},
            {"state_generation", session->generation},
            {"state_child_pid", session->child_pid},
            {"state_server_command", state_command},
            {"state_expected_executable_path", state_expected_path},
            {"state_cleanup_pending", session->cleanup_pending}
        };
        std::vector<std::string> mismatches;
        if (normalize_session_id(session->session_id) != sid)
            mismatches.push_back("bridge_session_id_mismatch");
        if (session->generation != proof.expected_bridge_generation)
            mismatches.push_back("bridge_generation_mismatch");
        if (session->child_pid != proof.expected_sidecar_pid)
            mismatches.push_back("sidecar_pid_mismatch");
        if (state_expected_path.empty())
            mismatches.push_back("state_expected_executable_path");
        else if (!normalized_process_path_equal(state_expected_path, proof.expected_executable_path))
            mismatches.push_back("state_executable_path_mismatch");
        if (session->cleanup_pending)
            mismatches.push_back("cleanup_already_pending");
        if (!mismatches.empty())
            return stale_cleanup_rejected(proof, "state_proof_mismatch", mismatches, proof_state);

        const process_identity_snapshot_t identity = query_process_identity_snapshot(proof.expected_sidecar_pid);
        std::vector<std::string> identity_mismatches;
        if (!stale_cleanup_process_identity_matches(proof, identity, identity_mismatches))
        {
            proof_state["process_identity"] = stale_cleanup_identity_json(identity);
            return stale_cleanup_rejected(proof, "process_identity_mismatch", identity_mismatches, proof_state);
        }

        cli = session->client;
        child_pid = session->child_pid;
        cleanup_generation = ++session->generation;
        session->stop_requested.store(true, std::memory_order_release);
        session->client.reset();
        session->server_command.clear();
        session->child_pid = 0;
        session->state = bridge_state_t::stopped;
        session->last_error = std::string("mcp stale sidecar cleanup: ") + proof.diagnostic_id;
        clear_managed_page_state_locked(*session);
        session->cleanup_pending = true;
        session->cleanup_generation = cleanup_generation;
        session->cleanup_started_ms = now_ms();
        session->cleanup_child_pid = child_pid;
        session->cleanup_reason = std::string("mcp_stale_sidecar_cleanup:") + proof.diagnostic_id;
        session->cleanup_diagnostics = {
            {"status", "pending"},
            {"reason", session->cleanup_reason},
            {"proof", stale_cleanup_proof_json(proof)},
            {"process_identity", stale_cleanup_identity_json(identity)}
        };
        proof_state["process_identity"] = stale_cleanup_identity_json(identity);
        proof_state["cleanup_generation"] = cleanup_generation;
        const uint64_t stale_managed_launch_token = session->launch_admission_token;
        session->launch_admission_token = 0;
        const std::string stale_managed_session_id = session->session_id;
        lk.unlock();
        release_launch_admission(stale_managed_launch_token, "stale_cleanup", stale_managed_session_id);
    }

    stale_sidecar_cleanup_result_t result;
    result.attempted = true;
    const process_tree_reap_result_t reap = terminate_process_tree_sync(child_pid, std::string("mcp_stale_sidecar_cleanup:") + proof.diagnostic_id);
    if (cli)
        cli->disconnect();

    if (default_session)
    {
        mark_cleanup_finished(cleanup_generation, now_ms() - t0, std::string("mcp_stale_sidecar_cleanup:") + proof.diagnostic_id,
            child_pid == 0 || reap.alive_after == 0);
    }
    else
    {
        auto session = get_managed_session(sid, false);
        if (session)
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->cleanup_pending = false;
            session->last_cleanup_ms = now_ms() - t0;
            session->cleanup_diagnostics["status"] = reap.alive_after == 0 ? "finished" : "finished_with_live_processes";
            session->cleanup_diagnostics["process_reap"] = cleanup_reap_json(reap);
            session->cleanup_diagnostics["elapsed_ms"] = now_ms() - t0;
            session->cleanup_child_pid = 0;
        }
    }

    result.cleaned = reap.alive_after == 0;
    result.reason = result.cleaned ? "cleaned" : "cleanup_incomplete";
    result.diagnostics = {
        {"result", result.reason},
        {"attempted", true},
        {"cleaned", result.cleaned},
        {"proof", stale_cleanup_proof_json(proof)},
        {"state", proof_state},
        {"process_reap", cleanup_reap_json(reap)},
        {"elapsed_ms", now_ms() - t0}
    };
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_fmt("camoufox",
        "MCP-CAMOUFOX-STALE-CLEANUP result=%s cleaned=%d diag_id=%s request_id=%s tool=%s action=%s bridge_session=%s mcp_session=%s session_hash=%s principal_bucket=%s lease_token=%llu operation_generation=%llu registry_generation=%llu expected_generation=%llu expected_pid=%lu expected_path=%s creation_time_100ns=%llu cleanup_generation=%llu reap_before=%zu reap_alive_after=%zu elapsed_ms=%llu",
        result.reason.c_str(),
        result.cleaned ? 1 : 0,
        proof.diagnostic_id.c_str(),
        proof.request_id.c_str(),
        proof.tool.c_str(),
        proof.action.c_str(),
        proof.bridge_session_id.c_str(),
        proof.mcp_session_id.c_str(),
        proof.mcp_session_hash.c_str(),
        proof.principal_bucket.c_str(),
        static_cast<unsigned long long>(proof.lease_token),
        static_cast<unsigned long long>(proof.operation_generation),
        static_cast<unsigned long long>(proof.registry_generation),
        static_cast<unsigned long long>(proof.expected_bridge_generation),
        static_cast<unsigned long>(proof.expected_sidecar_pid),
        proof.expected_executable_path.c_str(),
        static_cast<unsigned long long>(proof.expected_process_creation_time_100ns),
        static_cast<unsigned long long>(cleanup_generation),
        reap.before,
        reap.alive_after,
        static_cast<unsigned long long>(now_ms() - t0));
    return result;
}

bool wait_until_idle(uint32_t timeout_ms, const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* wait_reason = safe_reason(reason);
    const uint64_t limit_ms = timeout_ms == 0 ? 1 : static_cast<uint64_t>(timeout_ms);
    uint64_t last_log_ms = 0;
    for (;;)
    {
        const uint64_t now = now_ms();
        std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
        const bool operation_idle = op_lk.owns_lock();
        const uint32_t active = sg().active_activities.load(std::memory_order_acquire);
        bridge_state_t state = bridge_state_t::stopped;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        bool cleanup_pending = false;
        bool child_alive = false;
        size_t err_len = 0;
        bool state_locked = false;
        {
            std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
            state_locked = lk.owns_lock();
            if (state_locked)
            {
                state = sg().state;
                generation = sg().generation;
                child_pid = sg().child_pid != 0 ? sg().child_pid : sg().cleanup_child_pid;
                cleanup_pending = sg().cleanup_pending;
                err_len = sg().last_error.size();
            }
            else
            {
                child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
            }
        }
        if (operation_idle && active == 0 && state_locked && !cleanup_pending)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle ok reason=%s elapsed_ms=%llu state_locked=%d state=%d generation=%llu child_pid=%lu child_alive=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), 1, static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, err_len);
            return true;
        }
        if (now - t0 >= limit_ms)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle timeout reason=%s elapsed_ms=%llu limit_ms=%llu operation_idle=%d active=%lu state_locked=%d state=%d generation=%llu child_pid=%lu child_alive=%d cleanup_pending=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), static_cast<unsigned long long>(limit_ms),
                operation_idle ? 1 : 0, static_cast<unsigned long>(active), state_locked ? 1 : 0, static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, cleanup_pending ? 1 : 0, err_len);
            return false;
        }
        if (now - last_log_ms >= 1000)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle wait reason=%s elapsed_ms=%llu limit_ms=%llu operation_idle=%d active=%lu state_locked=%d state=%d generation=%llu child_pid=%lu child_alive=%d cleanup_pending=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), static_cast<unsigned long long>(limit_ms),
                operation_idle ? 1 : 0, static_cast<unsigned long>(active), state_locked ? 1 : 0, static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, cleanup_pending ? 1 : 0, err_len);
            last_log_ms = now;
        }
        Sleep(50);
    }
}

bool is_ready()
{
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "is_ready busy result=0");
        return false;
    }
    const bridge_health_snapshot_t health = sample_bridge_health(sg().child_pid, true);
    const bool process_tree_ready = usable_browser_process_count(health.browser_process_count);
    bool ready = sg().state == bridge_state_t::ready &&
        sg().client != nullptr &&
        sg().browser_open &&
        sg().page_verified &&
        sg().privacy_verified &&
        health.child_alive &&
        process_tree_ready &&
        !sg().cleanup_pending &&
        !is_driver_closed_error(sg().last_error);
    std::shared_ptr<mcp_client::client_t> cleanup_client;
    uint32_t cleanup_child_pid = 0;
    uint64_t cleanup_generation = 0;
    std::string cleanup_reason;
    std::string state_error;
    if (sg().state == bridge_state_t::ready && !ready)
    {
        std::string reason;
        if (is_driver_closed_error(sg().last_error))
            reason = "driver transport is closed";
        else if (!health.child_alive)
            reason = "sidecar process exited";
        else if (!process_tree_ready)
            reason = "browser process tree empty";
        else if (sg().client == nullptr)
            reason = "mcp client is detached";
        else if (!sg().browser_open)
            reason = "browser is not open";
        else if (!sg().page_verified)
            reason = "page is not verified";
        else if (!sg().privacy_verified)
            reason = "privacy is not verified";
        else if (sg().cleanup_pending)
            reason = "cleanup is pending";
        else
            reason = "readiness verification failed";
        invalidate_default_ready_bridge_locked(
            "is_ready",
            reason,
            health,
            cleanup_client,
            cleanup_child_pid,
            cleanup_generation,
            cleanup_reason,
            state_error);
    }
    if (ready && reduced_browser_process_tree(health.browser_process_count))
    {
        diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=is_ready generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u client=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
            static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long>(sg().child_pid),
            health.child_alive ? 1 : 0,
            static_cast<unsigned>(health.child_process_count),
            static_cast<unsigned>(health.browser_process_count),
            static_cast<unsigned>(kMinReadyBrowserProcessCount),
            sg().client != nullptr ? 1 : 0,
            sg().browser_open ? 1 : 0,
            sg().page_verified ? 1 : 0,
            sg().privacy_verified ? 1 : 0,
            sg().cleanup_pending ? 1 : 0,
            health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
    }
    diag::log_tagged_fmt("camoufox", "is_ready result=%d state=%d generation=%llu client=%d browser_open=%d page_verified=%d privacy_verified=%d child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u err_len=%zu",
        static_cast<int>(ready), static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open),
        static_cast<int>(sg().page_verified), static_cast<int>(sg().privacy_verified), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(health.child_alive), static_cast<unsigned>(health.child_process_count), static_cast<unsigned>(health.browser_process_count), sg().last_error.size());
    lk.unlock();
    if (cleanup_generation != 0)
        finish_default_ready_bridge_invalidation(cleanup_client, cleanup_child_pid, cleanup_generation, cleanup_reason, state_error);
    return ready;
}

bool ensure_ready()
{
    const uint64_t t0 = now_ms();
    uint64_t is_ready_ms = 0;
    uint64_t probe_ms = 0;
    uint64_t setup_ms = 0;
    uint64_t start_bridge_ms = 0;
    diag::log_tagged_fmt("camoufox", "ensure_ready entry");
    const uint64_t is_ready_start_ms = now_ms();
    if (is_ready()) {
        is_ready_ms = now_ms() - is_ready_start_ms;
        diag::log_tagged_fmt("camoufox", "ensure_ready already_ready elapsed_ms=%llu is_ready_ms=%llu",
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long long>(is_ready_ms));
        diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=1 already_ready=1 is_ready_ms=%llu probe_ms=0 setup_ms=0 start_bridge_ms=0 total_ms=%llu",
            static_cast<unsigned long long>(is_ready_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return true;
    }
    is_ready_ms = now_ms() - is_ready_start_ms;
    bool publish_reused_ready = false;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        std::string blocked_reason;
        uint64_t remaining_ms = 0;
        uint64_t blocked_generation = 0;
        if (sg().state == bridge_state_t::error && auto_restart_blocked_locked(now_ms(), blocked_reason, remaining_ms, blocked_generation))
        {
            const bridge_health_snapshot_t health = sample_bridge_health(sg().child_pid, true);
            const bool retained_ready =
                sg().client != nullptr &&
                sg().browser_open &&
                sg().page_verified &&
                sg().privacy_verified &&
                !sg().cleanup_pending &&
                health.child_alive &&
                usable_browser_process_count(health.browser_process_count);
            if (retained_ready)
            {
                if (reduced_browser_process_tree(health.browser_process_count))
                {
                    diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=ensure_ready_reuse_live_bridge generation=%llu current_generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
                        static_cast<unsigned long long>(blocked_generation),
                        static_cast<unsigned long long>(sg().generation),
                        static_cast<unsigned long>(sg().child_pid),
                        health.child_alive ? 1 : 0,
                        static_cast<unsigned>(health.child_process_count),
                        static_cast<unsigned>(health.browser_process_count),
                        static_cast<unsigned>(kMinReadyBrowserProcessCount),
                        sg().browser_open ? 1 : 0,
                        sg().page_verified ? 1 : 0,
                        sg().privacy_verified ? 1 : 0,
                        sg().cleanup_pending ? 1 : 0,
                        health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
                }
                sg().state = bridge_state_t::ready;
                clear_error_locked();
                clear_auto_restart_block_locked("ensure_ready_reuse_live_bridge");
                publish_reused_ready = true;
                diag::log_tagged_fmt("camoufox", "ensure_ready auto_restart_block_reuse_live_bridge generation=%llu current_generation=%llu child_pid=%lu remaining_ms=%llu reason=%s child_alive=%d child_processes=%u browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
                    static_cast<unsigned long long>(blocked_generation),
                    static_cast<unsigned long long>(sg().generation),
                    static_cast<unsigned long>(sg().child_pid),
                    static_cast<unsigned long long>(remaining_ms),
                    blocked_reason.c_str(),
                    health.child_alive ? 1 : 0,
                    static_cast<unsigned>(health.child_process_count),
                    static_cast<unsigned>(health.browser_process_count),
                    sg().browser_open ? 1 : 0,
                    sg().page_verified ? 1 : 0,
                    sg().privacy_verified ? 1 : 0,
                    sg().cleanup_pending ? 1 : 0,
                    health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
            }
            else if (!sg().cleanup_pending && (sg().client == nullptr || !sg().browser_open || !sg().page_verified || !sg().privacy_verified || !health.child_alive || !usable_browser_process_count(health.browser_process_count)))
            {
                diag::log_tagged_fmt("camoufox", "ensure_ready auto_restart_block_cleared_for_unhealthy_bridge generation=%llu current_generation=%llu child_pid=%lu remaining_ms=%llu reason=%s client=%d child_alive=%d child_processes=%u browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
                    static_cast<unsigned long long>(blocked_generation),
                    static_cast<unsigned long long>(sg().generation),
                    static_cast<unsigned long>(sg().child_pid),
                    static_cast<unsigned long long>(remaining_ms),
                    blocked_reason.c_str(),
                    sg().client != nullptr ? 1 : 0,
                    health.child_alive ? 1 : 0,
                    static_cast<unsigned>(health.child_process_count),
                    static_cast<unsigned>(health.browser_process_count),
                    sg().browser_open ? 1 : 0,
                    sg().page_verified ? 1 : 0,
                    sg().privacy_verified ? 1 : 0,
                    sg().cleanup_pending ? 1 : 0,
                    health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
                clear_auto_restart_block_locked("ensure_ready_unhealthy_bridge");
            }
            else
            {
                sg().last_error = std::string("camoufox automatic restart suppressed after ") + blocked_reason;
                diag::log_tagged_fmt("camoufox", "ensure_ready auto_restart_blocked generation=%llu current_generation=%llu child_pid=%lu remaining_ms=%llu reason=%s client=%d child_alive=%d child_processes=%u browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d process_tree=%s",
                    static_cast<unsigned long long>(blocked_generation),
                    static_cast<unsigned long long>(sg().generation),
                    static_cast<unsigned long>(sg().child_pid),
                    static_cast<unsigned long long>(remaining_ms),
                    blocked_reason.c_str(),
                    sg().client != nullptr ? 1 : 0,
                    health.child_alive ? 1 : 0,
                    static_cast<unsigned>(health.child_process_count),
                    static_cast<unsigned>(health.browser_process_count),
                    sg().browser_open ? 1 : 0,
                    sg().page_verified ? 1 : 0,
                    sg().privacy_verified ? 1 : 0,
                    sg().cleanup_pending ? 1 : 0,
                    health.process_tree.empty() ? "<empty>" : health.process_tree.c_str());
                diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=0 blocked=1 is_ready_ms=%llu probe_ms=%llu setup_ms=%llu start_bridge_ms=%llu total_ms=%llu",
                    static_cast<unsigned long long>(is_ready_ms),
                    static_cast<unsigned long long>(probe_ms),
                    static_cast<unsigned long long>(setup_ms),
                    static_cast<unsigned long long>(start_bridge_ms),
                    static_cast<unsigned long long>(now_ms() - t0));
                return false;
            }
        }
    }
    if (publish_reused_ready)
    {
        publish_state(bridge_state_t::ready, std::string());
        diag::log_tagged_fmt("camoufox", "ensure_ready reused_ready elapsed_ms=%llu is_ready_ms=%llu",
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long long>(is_ready_ms));
        diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=1 reused_ready=1 is_ready_ms=%llu probe_ms=0 setup_ms=0 start_bridge_ms=0 total_ms=%llu",
            static_cast<unsigned long long>(is_ready_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return true;
    }
    install::status_t st = install::get_status();
    if (st.state == install::install_state_t::unknown ||
        st.state == install::install_state_t::checking)
    {
        const uint64_t probe_start_ms = now_ms();
        diag::log_tagged_fmt("camoufox", "ensure_ready probe_begin state=%d elapsed_ms=%llu",
            static_cast<int>(st.state), static_cast<unsigned long long>(now_ms() - t0));
        st = install::probe();
        probe_ms = now_ms() - probe_start_ms;
        diag::log_tagged_fmt("camoufox", "ensure_ready probe_end state=%d python=%s message=%s elapsed_ms=%llu",
            static_cast<int>(st.state), st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
            st.last_message.empty() ? "<empty>" : st.last_message.c_str(),
            static_cast<unsigned long long>(now_ms() - t0));
    }
    if (st.state != install::install_state_t::ok)
    {
        std::string setup_log;
        bool setup_ready = false;
        const uint64_t setup_start_ms = now_ms();
        diag::log_tagged_fmt("camoufox", "ensure_ready setup_begin state=%d elapsed_ms=%llu",
            static_cast<int>(st.state), static_cast<unsigned long long>(setup_start_ms - t0));
        try { setup_ready = install::ensure_ready(setup_log); } catch (...) { setup_ready = false; }
        st = install::get_status();
        diag::log_tagged_fmt("camoufox", "ensure_ready setup_end ready=%d state=%d python=%s setup_elapsed_ms=%llu setup_log_len=%zu err=%s",
            static_cast<int>(setup_ready), static_cast<int>(st.state),
            st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
            static_cast<unsigned long long>(now_ms() - setup_start_ms), setup_log.size(),
            install::last_error().c_str());
        setup_ms = now_ms() - setup_start_ms;
        if (!setup_ready || st.state != install::install_state_t::ok)
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().last_error = install::last_error();
            if (sg().last_error.empty()) sg().last_error = compact_child_output(setup_log);
            if (sg().last_error.empty()) sg().last_error = "camoufox dependency setup did not reach ready state";
            diag::log_tagged_fmt("camoufox", "ensure_ready install_not_ready state=%d err=%s",
                static_cast<int>(st.state), sg().last_error.c_str());
            diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=0 install_not_ready=1 is_ready_ms=%llu probe_ms=%llu setup_ms=%llu start_bridge_ms=0 total_ms=%llu",
                static_cast<unsigned long long>(is_ready_ms),
                static_cast<unsigned long long>(probe_ms),
                static_cast<unsigned long long>(setup_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            return false;
        }
    }
    launch_config_t cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        cfg = sg().active_cfg;
    }
    cfg.headless = false;
    if (cfg.server_module.empty()) cfg.server_module = "camoufox_reverse_mcp";
    if (cfg.python_executable.empty()) cfg.python_executable = st.python_path;
    if (cfg.python_executable.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_error = st.last_message.empty()
            ? "Camoufox Python runtime unavailable after dependency setup"
            : st.last_message;
        diag::log_tagged_fmt("camoufox", "ensure_ready missing_python_after_setup state=%d err=%s",
            static_cast<int>(st.state), sg().last_error.c_str());
        diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=0 missing_python=1 is_ready_ms=%llu probe_ms=%llu setup_ms=%llu start_bridge_ms=0 total_ms=%llu",
            static_cast<unsigned long long>(is_ready_ms),
            static_cast<unsigned long long>(probe_ms),
            static_cast<unsigned long long>(setup_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "ensure_ready starting_bridge mode=%s command=%s module=%s has_proxy=%d",
        "python",
        cfg.python_executable.c_str(),
        cfg.server_module.c_str(),
        static_cast<int>(!cfg.proxy.empty()));
    if (g_prewarm_default_worker_active && sg().stop_requested.load(std::memory_order_acquire))
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_error = "Camoufox prewarm cancelled by stop request";
        diag::log_tagged_fmt("camoufox", "ensure_ready prewarm_cancelled_before_start_bridge elapsed_ms=%llu stop_epoch=%llu",
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long long>(sg().stop_epoch.load(std::memory_order_acquire)));
        diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=0 prewarm_cancelled=1 is_ready_ms=%llu probe_ms=%llu setup_ms=%llu start_bridge_ms=0 total_ms=%llu",
            static_cast<unsigned long long>(is_ready_ms),
            static_cast<unsigned long long>(probe_ms),
            static_cast<unsigned long long>(setup_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    const uint64_t start_bridge_start_ms = now_ms();
    bool ok = start_bridge(cfg);
    start_bridge_ms = now_ms() - start_bridge_start_ms;
    diag::log_tagged_fmt("camoufox", "ensure_ready exit ok=%d elapsed_ms=%llu err_len=%zu",
        static_cast<int>(ok), static_cast<unsigned long long>(now_ms() - t0), last_error().size());
    diag::log_tagged_fmt("camoufox", "ensure_ready stage_timing ok=%d is_ready_ms=%llu probe_ms=%llu setup_ms=%llu start_bridge_ms=%llu total_ms=%llu",
        static_cast<int>(ok),
        static_cast<unsigned long long>(is_ready_ms),
        static_cast<unsigned long long>(probe_ms),
        static_cast<unsigned long long>(setup_ms),
        static_cast<unsigned long long>(start_bridge_ms),
        static_cast<unsigned long long>(now_ms() - t0));
    return ok;
}

bool prewarm_default_async(const char* reason)
{
    const char* owner = safe_reason(reason);
    const bool prev_requested = prewarm_default_requested().load(std::memory_order_acquire);
    log_prewarm_policy_resolved(owner);
    if (full_test_running_env())
    {
        diag::log_tagged_fmt("camoufox", "prewarm_default_policy_resolved env=%s resolved=disabled reason=%s previously_posted=%d full_test_active=1",
            "<unset_or_present>",
            owner,
            prev_requested ? 1 : 0);
        diag::log_tagged_fmt("camoufox", "prewarm_default_deferred_full_test reason=%s", owner);
        return true;
    }
    if (prewarm_default_disabled())
    {
        diag::log_tagged_fmt("camoufox", "prewarm_default_policy_resolved env=disable_value resolved=disabled reason=%s previously_posted=%d full_test_active=0",
            owner,
            prev_requested ? 1 : 0);
        diag::log_tagged_fmt("camoufox", "prewarm_default_disabled reason=%s", owner);
        return true;
    }
    diag::log_tagged_fmt("camoufox", "prewarm_default_policy_resolved resolved=enabled reason=%s previously_posted=%d full_test_active=0",
        owner,
        prev_requested ? 1 : 0);
    bridge_status_t before = get_status();
    const bool ready = before.state == bridge_state_t::ready &&
                       before.child_alive &&
                       before.browser_open &&
                       before.page_verified &&
                       before.privacy_verified &&
                       !before.cleanup_pending &&
                       usable_browser_process_count(before.browser_process_count);
    if (ready)
    {
        prewarm_default_requested().store(true, std::memory_order_release);
        diag::log_tagged_fmt("camoufox", "prewarm_default_already_ready reason=%s generation=%llu child_pid=%lu child_processes=%u browser_processes=%u privacy_verified=%d cleanup_pending=%d last_launch_ms=%llu last_nav_ms=%llu",
            owner,
            static_cast<unsigned long long>(before.generation),
            static_cast<unsigned long>(before.child_pid),
            static_cast<unsigned>(before.child_process_count),
            static_cast<unsigned>(before.browser_process_count),
            before.privacy_verified ? 1 : 0,
            before.cleanup_pending ? 1 : 0,
            static_cast<unsigned long long>(before.last_launch_ms),
            static_cast<unsigned long long>(before.last_nav_ms));
        return true;
    }
    bool expected = false;
    if (!prewarm_default_requested().compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        diag::log_tagged_fmt("camoufox", "prewarm_default_already_requested reason=%s state=%d child_pid=%lu browser_open=%d page_verified=%d child_alive=%d",
            owner,
            static_cast<int>(before.state),
            static_cast<unsigned long>(before.child_pid),
            before.browser_open ? 1 : 0,
            before.page_verified ? 1 : 0,
            before.child_alive ? 1 : 0);
        return true;
    }
    std::string reason_copy(owner);
    aida::infra::executor::submission_t prewarm_sub;
    prewarm_sub.owner_subsystem = "burp.camoufox";
    prewarm_sub.label = "camoufox.prewarm_default";
    prewarm_sub.thread_class = "external_tool";
    prewarm_sub.domain = aida::infra::executor::domain_t::external_tool;
    prewarm_sub.priority = 3;
    prewarm_sub.body = [reason_copy]() {
        const uint64_t t0 = now_ms();
        diag::log_tagged_fmt("camoufox", "prewarm_default_worker_begin reason=%s pid=%lu tid=%lu",
            reason_copy.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        bool ok = false;
        struct prewarm_worker_scope_t {
            prewarm_worker_scope_t() { g_prewarm_default_worker_active = true; }
            ~prewarm_worker_scope_t() { g_prewarm_default_worker_active = false; }
        } prewarm_scope;
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            diag::log_tagged_fmt("camoufox", "prewarm_default_worker_cancelled_before_ensure_ready reason=%s stop_epoch=%llu",
                reason_copy.c_str(),
                static_cast<unsigned long long>(sg().stop_epoch.load(std::memory_order_acquire)));
        }
        else
        {
            try { ok = ensure_ready(); } catch (...) { ok = false; }
        }
        bridge_status_t after = get_status();
        diag::log_tagged_fmt("camoufox", "prewarm_default_worker_end reason=%s ok=%d elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d last_launch_ms=%llu last_nav_ms=%llu err_len=%zu",
            reason_copy.c_str(),
            ok ? 1 : 0,
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<int>(after.state),
            static_cast<unsigned long long>(after.generation),
            static_cast<unsigned long>(after.child_pid),
            after.child_alive ? 1 : 0,
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            static_cast<unsigned long long>(after.last_launch_ms),
            static_cast<unsigned long long>(after.last_nav_ms),
            after.last_error.size());
        if (!ok)
            prewarm_default_requested().store(false, std::memory_order_release);
    };
    bool posted = aida::infra::executor::submit(std::move(prewarm_sub)).submitted;
    if (!posted)
    {
        prewarm_default_requested().store(false, std::memory_order_release);
        diag::log_tagged_fmt("camoufox", "prewarm_default_post_failed reason=%s state=%d child_pid=%lu",
            owner,
            static_cast<int>(before.state),
            static_cast<unsigned long>(before.child_pid));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "prewarm_default_posted reason=%s state=%d child_pid=%lu browser_open=%d page_verified=%d child_alive=%d",
        owner,
        static_cast<int>(before.state),
        static_cast<unsigned long>(before.child_pid),
        before.browser_open ? 1 : 0,
        before.page_verified ? 1 : 0,
        before.child_alive ? 1 : 0);
    return true;
}

call_result_t managed_call_with_deadline(const std::shared_ptr<managed_session_t>& session, const std::string& tool_name, const nlohmann::json& args, int timeout_ms, bool allow_starting = false)
{
    call_result_t fail;
    fail.ok = false;
    if (!session)
    {
        fail.error = "camoufox managed session is unavailable";
        return fail;
    }
    if (timeout_ms <= 0) timeout_ms = 30000;
    const uint64_t request_id = session->next_request_id.fetch_add(1, std::memory_order_relaxed);
    nlohmann::json call_args = args.is_null() ? nlohmann::json::object() : args;
    stamp_aida_operation_id(call_args, tool_name, request_id);
    std::shared_ptr<mcp_client::client_t> cli;
    uint64_t generation = 0;
    uint32_t child_pid = 0;
    bridge_state_t session_state = bridge_state_t::stopped;
    bool has_client = false;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session_state = session->state;
        has_client = static_cast<bool>(session->client);
        if (session->client && (session->state == bridge_state_t::ready || (allow_starting && session->state == bridge_state_t::starting)))
            cli = session->client;
        generation = session->generation;
        child_pid = session->child_pid;
    }
    if (!cli)
    {
        diag::log_tagged_fmt("camoufox", "managed_call not_ready session_id=%s request_id=%llu tool=%s state=%d has_client=%d allow_starting=%d generation=%llu child_pid=%lu last_error=%s",
            session->session_id.c_str(),
            static_cast<unsigned long long>(request_id),
            tool_name.c_str(),
            static_cast<int>(session_state),
            has_client ? 1 : 0,
            allow_starting ? 1 : 0,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(child_pid),
            session->last_error.c_str());
        fail.error = session->last_error.empty() ? std::string("camoufox managed session is not ready") : session->last_error;
        return fail;
    }
    struct shared_state_t
    {
        std::mutex                mtx;
        std::condition_variable   cv;
        bool                      done = false;
        bool                      cancelled = false;
        mcp_client::call_result_t result;
    };
    auto state = std::make_shared<shared_state_t>();
    const uint64_t t0 = now_ms();
    session->total_calls.fetch_add(1, std::memory_order_relaxed);
    const bridge_health_snapshot_t managed_entry_health = sample_bridge_health(child_pid, true);
    diag::log_tagged_fmt("camoufox", "managed_call dispatch session_id=%s request_id=%llu tool=%s timeout_ms=%d generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u caller_pid=%lu caller_tid=%lu args_shape=%s process_tree=%s",
        session->session_id.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms,
        static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
        managed_entry_health.child_alive ? 1 : 0,
        managed_entry_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(managed_entry_health.exit_code_valid ? managed_entry_health.exit_code : 0),
        static_cast<unsigned long>(managed_entry_health.exit_query_gle),
        static_cast<unsigned>(managed_entry_health.child_process_count),
        static_cast<unsigned>(managed_entry_health.browser_process_count),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        json_shape(call_args).c_str(),
        managed_entry_health.process_tree.empty() ? "<empty>" : managed_entry_health.process_tree.c_str());
    bool posted = post_bridge_task("camoufox.session.call", [state, cli, tool_name, call_args, request_id, generation, child_pid, sid = session->session_id]() {
        const uint64_t worker_start = now_ms();
        mcp_client::call_result_t r;
        guarded_mcp_call_context_t call_ctx;
        call_ctx.client = cli.get();
        call_ctx.tool_name = &tool_name;
        call_ctx.args = &call_args;
        call_ctx.result = &r;
        DWORD guard_status = guarded_mcp_call(&call_ctx);
        if (guard_status != ERROR_SUCCESS)
        {
            r = guarded_mcp_failure_result(tool_name, call_ctx, guard_status);
            diag::log_tagged_critical_fmt("camoufox", "managed_call guarded_failure session_id=%s request_id=%llu tool=%s generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                sid.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long>(guard_status), static_cast<int>(call_ctx.native_exception),
                static_cast<int>(call_ctx.cpp_exception), static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->result = std::move(r);
            state->done = true;
        }
        state->cv.notify_all();
    });
    if (!posted)
    {
        fail.error = "camoufox managed call dispatch post failed";
        session->total_errors.fetch_add(1, std::memory_order_relaxed);
        return fail;
    }
    std::unique_lock<std::mutex> lk(state->mtx);
    const bool got = state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&state]() { return state->done; });
    if (!got)
    {
        state->cancelled = true;
        lk.unlock();
        uint32_t timed_out_pid = 0;
        {
            std::lock_guard<std::recursive_mutex> slk(session->mtx);
            timed_out_pid = session->child_pid;
            session->state = bridge_state_t::error;
            session->last_error = std::string("camoufox managed call timeout: ") + tool_name;
            session->client.reset();
            session->child_pid = 0;
            session->browser_open = false;
            session->page_verified = false;
            clear_privacy_locked(*session);
        }
        const std::string timeout_tree = timed_out_pid == 0 ? std::string() : compact_process_tree(enumerate_process_tree(timed_out_pid));
        const process_exit_snapshot_t timeout_exit = query_process_exit_snapshot(timed_out_pid);
        diag::log_tagged_fmt("camoufox", "managed_call_timeout_cleanup_begin session_id=%s request_id=%llu tool=%s generation=%llu child_pid=%lu timeout_ms=%d exit_valid=%d exit_code=%lu exit_gle=%lu process_tree=%s",
            session->session_id.c_str(),
            static_cast<unsigned long long>(request_id),
            tool_name.c_str(),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(timed_out_pid),
            timeout_ms,
            timeout_exit.queried ? 1 : 0,
            static_cast<unsigned long>(timeout_exit.queried ? timeout_exit.exit_code : 0),
            static_cast<unsigned long>(timeout_exit.gle),
            timeout_tree.empty() ? "<empty>" : timeout_tree.c_str());
        process_tree_reap_result_t reap;
        if (timed_out_pid != 0)
            reap = terminate_process_tree_sync(timed_out_pid, std::string("managed_timeout_") + session->session_id + "_" + tool_name);
        diag::log_tagged_fmt("camoufox", "managed_call_timeout_cleanup_done session_id=%s request_id=%llu tool=%s generation=%llu child_pid=%lu descendants_before=%zu alive_after=%zu success=%d elapsed_ms=%llu",
            session->session_id.c_str(),
            static_cast<unsigned long long>(request_id),
            tool_name.c_str(),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(timed_out_pid),
            reap.descendants_before,
            reap.alive_after,
            timed_out_pid == 0 || reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
        session->total_errors.fetch_add(1, std::memory_order_relaxed);
        fail.error = std::string("camoufox managed call timeout: ") + tool_name;
        fail.data = {
            {"status", "timeout"},
            {"phase", "mcp_response_wait"},
            {"timeout_phase", "mcp_response_wait"},
            {"tool", tool_name},
            {"request_id", request_id},
            {"timeout_ms", timeout_ms},
            {"generation", generation},
            {"child_pid", timed_out_pid},
            {"session_id", session->session_id},
            {"process_tree", timeout_tree},
            {"error", fail.error}
        };
        attach_bridge_call_metadata(
            fail,
            session->session_id,
            tool_name,
            request_id,
            timeout_ms,
            now_ms() - t0,
            generation,
            timed_out_pid,
            json_string_or(call_args, "page_id", std::string()),
            "timeout",
            true,
            timeout_exit.alive,
            false,
            false,
            true);
        return fail;
    }
    mcp_client::call_result_t result = std::move(state->result);
    lk.unlock();
    call_result_t out = to_bridge_result(result);
    {
        std::lock_guard<std::recursive_mutex> slk(session->mtx);
        session->last_call_ms = now_ms();
        if (out.ok)
        {
            session->last_error.clear();
            if (out.data.is_object())
                update_page_cache_from_json_locked(*session, out.data, tool_name.c_str());
        }
        else
        {
            session->last_error = out.error;
            session->total_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    const bridge_health_snapshot_t managed_exit_health = sample_bridge_health(child_pid, true);
    bridge_state_t exit_state = bridge_state_t::stopped;
    bool exit_browser_open = false;
    bool exit_page_verified = false;
    bool exit_cleanup_pending = false;
    {
        std::lock_guard<std::recursive_mutex> slk(session->mtx);
        exit_state = session->state;
        exit_browser_open = session->browser_open;
        exit_page_verified = session->page_verified;
        exit_cleanup_pending = session->cleanup_pending;
    }
    attach_bridge_call_metadata(
        out,
        session->session_id,
        tool_name,
        request_id,
        timeout_ms,
        now_ms() - t0,
        generation,
        child_pid,
        json_string_or(call_args, "page_id", std::string()),
        exit_state == bridge_state_t::error ? "complete_error" : "complete",
        false,
        managed_exit_health.child_alive,
        exit_browser_open,
        exit_page_verified,
        exit_cleanup_pending);
    diag::log_tagged_fmt("camoufox", "managed_call complete session_id=%s request_id=%llu tool=%s ok=%d elapsed_ms=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u data_shape=%s err_len=%zu process_tree=%s",
        session->session_id.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(out.ok),
        static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long>(child_pid),
        managed_exit_health.child_alive ? 1 : 0,
        managed_exit_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(managed_exit_health.exit_code_valid ? managed_exit_health.exit_code : 0),
        static_cast<unsigned long>(managed_exit_health.exit_query_gle),
        static_cast<unsigned>(managed_exit_health.child_process_count),
        static_cast<unsigned>(managed_exit_health.browser_process_count),
        json_shape(out.data).c_str(),
        out.error.size(),
        managed_exit_health.process_tree.empty() ? "<empty>" : managed_exit_health.process_tree.c_str());
    return out;
}

bridge_status_t managed_status(const std::shared_ptr<managed_session_t>& session)
{
    bridge_status_t s;
    if (!session)
    {
        s.state = bridge_state_t::stopped;
        s.session_count = managed_session_count();
        return s;
    }
    std::lock_guard<std::recursive_mutex> lk(session->mtx);
    s.session_id = session->session_id;
    s.active_session_id = session->session_id;
    s.state = session->state;
    s.last_error = session->last_error;
    s.server_command = session->server_command;
    s.child_pid = session->child_pid;
    s.launched_ms = session->launched_ms;
    s.attempt_started_ms = session->attempt_started_ms;
    s.attempt_elapsed_ms = session->attempt_elapsed_ms;
    s.last_attempt_elapsed_ms = session->last_attempt_elapsed_ms;
    s.last_call_ms = session->last_call_ms;
    s.total_calls = session->total_calls.load(std::memory_order_relaxed);
    s.total_errors = session->total_errors.load(std::memory_order_relaxed);
    s.browser_open = session->browser_open;
    s.active_page_id = session->active_page_id;
    s.active_page_url = session->active_page_url;
    s.active_page_title = session->active_page_title;
    s.active_profile_dir = session->active_profile_dir;
    s.active_profile_generated = session->active_profile_generated;
    s.effective_ua_policy = session->effective_ua_policy;
    s.ua_override_string = session->ua_override_string;
    s.ua_override = session->ua_override;
    s.webrtc_blocked = session->webrtc_blocked;
    s.privacy_verified = session->privacy_verified;
    s.privacy_diagnostics = session->privacy_diagnostics;
    s.last_launch_diagnostics = session->last_launch_diagnostics;
    s.page_verified = session->page_verified;
    s.cleanup_pending = session->cleanup_pending;
    s.cleanup_generation = session->cleanup_generation;
    s.cleanup_started_ms = session->cleanup_started_ms;
    s.cleanup_child_pid = session->cleanup_child_pid;
    s.cleanup_reason = session->cleanup_reason;
    s.cleanup_diagnostics = session->cleanup_diagnostics;
    s.generation = session->generation;
    s.last_launch_ms = session->last_launch_ms;
    s.last_nav_ms = session->last_nav_ms;
    s.last_cleanup_ms = session->last_cleanup_ms;
    s.last_verified_ms = session->last_verified_ms;
    s.pages = session->pages;
    s.page_count = static_cast<uint32_t>(session->pages.size());
    s.session_count = managed_session_count();
    s.child_alive = process_alive(s.child_pid);
    populate_child_process_identity(s);
    populate_process_counts(s);
    const bool client_connected = session->client != nullptr;
    if (s.state == bridge_state_t::ready && (!s.child_alive || !s.browser_open || !s.page_verified || !s.privacy_verified || !usable_browser_process_count(s.browser_process_count)))
    {
        s.state = bridge_state_t::error;
        if (s.last_error.empty())
            s.last_error = s.child_alive && s.browser_open && s.page_verified && s.privacy_verified
                ? "camoufox managed browser process tree empty"
                : "camoufox managed session readiness verification failed";
    }
    else if (s.state == bridge_state_t::ready && reduced_browser_process_tree(s.browser_process_count))
    {
        diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=managed_status session_id=%s generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d",
            s.session_id.c_str(),
            static_cast<unsigned long long>(s.generation),
            static_cast<unsigned long>(s.child_pid),
            s.child_alive ? 1 : 0,
            static_cast<unsigned>(s.child_process_count),
            static_cast<unsigned>(s.browser_process_count),
            static_cast<unsigned>(kMinReadyBrowserProcessCount),
            s.browser_open ? 1 : 0,
            s.page_verified ? 1 : 0,
            s.privacy_verified ? 1 : 0,
            s.cleanup_pending ? 1 : 0);
    }
    populate_status_diagnostic_fields(s, now_ms(), client_connected);
    return s;
}

bool start_managed_bridge(const launch_config_t& cfg, const std::string& session_id)
{
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
    {
        diag::log_tagged_critical_fmt("camoufox", "managed_start_lifecycle_busy session_id=%s wait_ms=%llu",
            normalize_session_id(session_id).c_str(), static_cast<unsigned long long>(kLifecycleLockWaitMs));
        return false;
    }
    const uint64_t t0 = now_ms();
    uint64_t preflight_ms = 0;
    uint64_t connect_ms = 0;
    uint64_t tools_ms = 0;
    uint64_t launch_rpc_ms = 0;
    uint64_t readiness_probe_ms = 0;
    uint64_t visible_window_ms = 0;
    const std::string sid = normalize_session_id(session_id);
    auto session = get_managed_session(sid, true);
    if (!session) return start_bridge(cfg);
    std::unique_lock<std::recursive_mutex> op_lk(session->operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->last_error = "camoufox managed session operation already active";
        return false;
    }
    launch_config_t effective_cfg = cfg;
    enforce_private_launch_config(effective_cfg);
    normalize_fast_visible_launch_policy(effective_cfg);
    effective_cfg.session_id = sid;
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "managed_start forcing_visible session_id=%s requested_headless=1", sid.c_str());
        effective_cfg.headless = false;
    }
    std::shared_ptr<mcp_client::client_t> stale_reuse_client;
    uint32_t stale_reuse_pid = 0;
    std::string stale_reuse_cleanup_reason;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        if (session->cleanup_pending)
        {
            session->last_error = "camoufox managed session cleanup still pending after incomplete process reap";
            session->cleanup_diagnostics["status"] = "pending_reap_blocks_start";
            diag::log_tagged_critical_fmt("camoufox", "managed_start_cleanup_pending session_id=%s generation=%llu cleanup_generation=%llu child_pid=%lu profile_dir=%s",
                sid.c_str(), static_cast<unsigned long long>(session->generation),
                static_cast<unsigned long long>(session->cleanup_generation),
                static_cast<unsigned long>(session->cleanup_child_pid),
                session->cleanup_profile_dir.empty() ? "<empty>" : session->cleanup_profile_dir.c_str());
            return false;
        }
        session->attempt_started_ms = t0;
        session->attempt_elapsed_ms = 0;
        const bool child_alive = process_alive(session->child_pid);
        const std::vector<process_tree_entry_t> ready_tree = child_alive ? enumerate_process_tree(session->child_pid) : std::vector<process_tree_entry_t>();
        const uint32_t ready_browser_processes = browser_process_count_from_tree(ready_tree);
        const bool ready_process_tree = usable_browser_process_count(ready_browser_processes);
        if (session->state == bridge_state_t::ready && session->client && session->browser_open && session->page_verified && session->privacy_verified && child_alive && ready_process_tree)
        {
            if (reduced_browser_process_tree(ready_browser_processes))
            {
                diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=managed_start_reuse session_id=%s generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u browser_open=%d page_verified=%d privacy_verified=%d process_tree=%s",
                    sid.c_str(),
                    static_cast<unsigned long long>(session->generation),
                    static_cast<unsigned long>(session->child_pid),
                    child_alive ? 1 : 0,
                    static_cast<unsigned>(ready_tree.size()),
                    static_cast<unsigned>(ready_browser_processes),
                    static_cast<unsigned>(kMinReadyBrowserProcessCount),
                    session->browser_open ? 1 : 0,
                    session->page_verified ? 1 : 0,
                    session->privacy_verified ? 1 : 0,
                    ready_tree.empty() ? "<empty>" : compact_process_tree(ready_tree).c_str());
            }
            const std::string mismatch_reason = privacy_relevant_launch_config_mismatch_reason(session->active_cfg, effective_cfg);
            if (!mismatch_reason.empty())
            {
                stale_reuse_client = session->client;
                stale_reuse_pid = session->child_pid;
                stale_reuse_cleanup_reason = std::string("managed_start_config_mismatch_") + sid;
                session->client.reset();
                session->child_pid = 0;
                session->browser_open = false;
                session->page_verified = false;
                session->pages.clear();
                clear_privacy_locked(*session);
                session->active_page_id.clear();
                session->active_page_url.clear();
                session->active_page_title.clear();
                session->last_error.clear();
                diag::log_tagged_fmt("camoufox", "managed_start ready_config_mismatch restarting session_id=%s child_pid=%lu reason=%s",
                    sid.c_str(), static_cast<unsigned long>(stale_reuse_pid), mismatch_reason.c_str());
            }
            else
            {
                preserve_resolved_launch_paths(effective_cfg, session->active_cfg);
                session->active_cfg = effective_cfg;
                session->last_launch_ms = now_ms() - t0;
                diag::log_tagged_fmt("camoufox", "managed_start reuse_ready session_id=%s child_pid=%lu page_count=%zu",
                    sid.c_str(), static_cast<unsigned long>(session->child_pid), session->pages.size());
                clear_sticky_setup_failure("managed_start_ready_reuse");
                return true;
            }
        }
        else if (session->state == bridge_state_t::ready && session->client)
        {
            const bool stale_browser_open = session->browser_open;
            const bool stale_page_verified = session->page_verified;
            stale_reuse_client = session->client;
            stale_reuse_pid = session->child_pid;
            stale_reuse_cleanup_reason = std::string("managed_start_invalid_ready_") + sid;
            session->client.reset();
            session->child_pid = 0;
            session->browser_open = false;
            session->page_verified = false;
            session->pages.clear();
            clear_privacy_locked(*session);
            session->active_page_id.clear();
            session->active_page_url.clear();
            session->active_page_title.clear();
            session->last_error.clear();
            diag::log_tagged_fmt("camoufox", "managed_start invalidating_unverified_ready session_id=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d browser_processes=%u process_tree=%s",
                sid.c_str(), static_cast<unsigned long>(stale_reuse_pid),
                static_cast<int>(child_alive), static_cast<int>(stale_browser_open),
                static_cast<int>(stale_page_verified), static_cast<unsigned>(ready_browser_processes),
                ready_tree.empty() ? "<empty>" : compact_process_tree(ready_tree).c_str());
        }
    }
    if (stale_reuse_pid != 0)
        terminate_process_tree_sync(stale_reuse_pid, stale_reuse_cleanup_reason.empty() ? std::string("managed_start_stale_ready_") + sid : stale_reuse_cleanup_reason);
    if (stale_reuse_client)
        stale_reuse_client->disconnect();
    std::string python_path = effective_cfg.python_executable;
    const bool testlab_launch = test_lab_launch_fail_fast_enabled(effective_cfg);
    const bool explicit_python_cfg = !effective_cfg.python_executable.empty();
    const bool explicit_python_env = env_path_configured_a("AIDA_CAMOUFOX_PYTHON");
    diag::log_tagged_fmt("camoufox", "bridge_runtime_select phase=managed_start session_id=%s mode=python testlab_fast_probe=%d explicit_python_cfg=%d explicit_python_env=%d initial_python=%s",
        sid.c_str(),
        testlab_launch ? 1 : 0,
        explicit_python_cfg ? 1 : 0,
        explicit_python_env ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str());
    find_preferred_developer_python_runtime(python_path, "managed_start");
    const bool python_ready = !python_path.empty();
    diag::log_tagged_fmt("camoufox", "managed_start python_runtime_resolve session_id=%s final_mode=python testlab_fast_probe=%d python_ready=%d explicit_python_cfg=%d explicit_python_env=%d python=%s",
        sid.c_str(),
        testlab_launch ? 1 : 0,
        python_ready ? 1 : 0,
        explicit_python_cfg ? 1 : 0,
        explicit_python_env ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str());

    if (!python_path.empty())
    {
        std::string reason;
        if (!system_python_discovery_allowed() && !is_app_controlled_python_path(python_path))
        {
            reason = "explicit Python path is outside AiDA-controlled Camoufox runtime roots";
            diag::log_tagged_fmt("camoufox", "managed_start explicit_python_rejected session_id=%s path=%s reason=%s",
                sid.c_str(), python_path.c_str(), reason.c_str());
            python_path.clear();
        }
        else if (!supported_camoufox_python(python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "managed_start explicit_python_rejected session_id=%s path=%s reason=%s",
                sid.c_str(), python_path.c_str(), reason.c_str());
            python_path.clear();
        }
    }
    {
        diag::log_tagged_fmt("camoufox", "managed_start python_resolve_begin session_id=%s explicit=%d elapsed_ms=%llu",
            sid.c_str(), static_cast<int>(!python_path.empty()),
            static_cast<unsigned long long>(now_ms() - t0));
        if (python_path.empty())
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = "Camoufox Python runtime unavailable\n" + install::setup_instructions();
            diag::log_tagged_fmt("camoufox", "managed_start python_runtime_unresolved session_id=%s elapsed_ms=%llu explicit_python_cfg=%d explicit_python_env=%d err=%s",
                sid.c_str(),
                static_cast<unsigned long long>(now_ms() - t0),
                explicit_python_cfg ? 1 : 0,
                explicit_python_env ? 1 : 0,
                session->last_error.c_str());
            return false;
        }
        diag::log_tagged_fmt("camoufox", "managed_start python_resolve_end session_id=%s python=%s elapsed_ms=%llu",
            sid.c_str(), python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0));
    }
    if (effective_cfg.browser_executable.empty())
    {
        std::string env_browser;
        if (read_env_path_a("AIDA_CAMOUFOX_EXECUTABLE", env_browser))
            effective_cfg.browser_executable = env_browser;
    }
    if (effective_cfg.browser_executable.empty())
    {
        std::string bundled_browser;
        if (find_bundled_camoufox_executable(bundled_browser))
            effective_cfg.browser_executable = bundled_browser;
    }
    DWORD browser_attr = INVALID_FILE_ATTRIBUTES;
    if (!effective_cfg.browser_executable.empty())
        browser_attr = GetFileAttributesW(utf8_to_wide(effective_cfg.browser_executable).c_str());
    diag::log_tagged_fmt("camoufox", "managed_start browser_executable session_id=%s path=%s exists=%d attr=0x%08lX",
        sid.c_str(),
        effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0),
        static_cast<unsigned long>(browser_attr));
    const sticky_setup_context_t setup_ctx = make_sticky_setup_context(
        effective_cfg,
        "python",
        python_path);
    uint64_t setup_generation = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        setup_generation = session->generation + 1;
    }
    nlohmann::json sticky_hit;
    std::string sticky_hit_error;
    if (sticky_setup_failure_hit_or_clear(setup_ctx, setup_generation, 0, now_ms() - t0, sticky_hit, sticky_hit_error))
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = sticky_hit_error;
        session->last_launch_ms = now_ms() - t0;
        session->last_launch_diagnostics = {
            {"status", "blocked"},
            {"phase", "sticky_setup_failure"},
            {"generation", setup_generation},
            {"session_id", sid},
            {"elapsed_ms", session->last_launch_ms},
            {"caller", "managed_start"}
        };
        attach_sticky_setup_failure(session->last_launch_diagnostics, sticky_hit);
        diag::log_tagged_fmt("camoufox", "managed_start sticky_setup_failure_blocked session_id=%s generation=%llu elapsed_ms=%llu err=%s",
            sid.c_str(),
            static_cast<unsigned long long>(setup_generation),
            static_cast<unsigned long long>(session->last_launch_ms),
            session->last_error.c_str());
        return false;
    }
    if (effective_cfg.browser_executable.empty() || browser_attr == INVALID_FILE_ATTRIBUTES || (browser_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = effective_cfg.browser_executable.empty()
            ? std::string("Camoufox browser executable not found\n") + install::setup_instructions()
            : std::string("Configured Camoufox browser executable is unavailable\n") + install::setup_instructions();
        session->last_launch_ms = now_ms() - t0;
        session->last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "browser_executable_preflight"},
            {"generation", setup_generation},
            {"session_id", sid},
            {"browser_path", effective_cfg.browser_executable},
            {"browser_attr", static_cast<uint32_t>(browser_attr)},
            {"elapsed_ms", session->last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "browser_executable_missing",
            session->last_error,
            setup_generation,
            0,
            camoufox_debug_log_path(),
            session->last_launch_ms,
            session->last_launch_diagnostics);
        attach_sticky_setup_failure(session->last_launch_diagnostics, sticky);
        session->last_error = sticky_setup_failure_error_text("browser_executable_missing", session->last_error);
        diag::log_tagged_fmt("camoufox", "managed_start browser_required_failed session_id=%s err=%s",
            sid.c_str(), session->last_error.c_str());
        return false;
    }
    if (!is_camoufox_browser_executable_path(utf8_to_wide(effective_cfg.browser_executable)))
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = "Configured browser executable is not a Camoufox browser bundle";
        session->last_launch_ms = now_ms() - t0;
        session->last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "browser_executable_preflight"},
            {"generation", setup_generation},
            {"session_id", sid},
            {"browser_path", effective_cfg.browser_executable},
            {"elapsed_ms", session->last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "browser_executable_rejected",
            session->last_error,
            setup_generation,
            0,
            camoufox_debug_log_path(),
            session->last_launch_ms,
            session->last_launch_diagnostics);
        attach_sticky_setup_failure(session->last_launch_diagnostics, sticky);
        session->last_error = sticky_setup_failure_error_text("browser_executable_rejected", session->last_error);
        diag::log_tagged_fmt("camoufox", "managed_start browser_rejected_non_camoufox session_id=%s path=%s",
            sid.c_str(), effective_cfg.browser_executable.c_str());
        return false;
    }
    {
        const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
        diag::log_tagged_fmt("camoufox", "managed_start persistent_context_policy session_id=%s bundled_visible=%d explicit_persistent=%d cfg_persistent=%d profile_dir=%d user_data_dir=%d default_nonpersistent=1",
            sid.c_str(),
            bundled_visible_launch ? 1 : 0,
            explicit_persistent_context_requested(effective_cfg) ? 1 : 0,
            effective_cfg.persistent_context ? 1 : 0,
            trim_launch_token(effective_cfg.profile_dir).empty() ? 0 : 1,
            trim_launch_token(effective_cfg.user_data_dir).empty() ? 0 : 1);
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        const uint64_t preflight_start_ms = now_ms();
        diag::log_tagged_fmt("camoufox", "managed_start preflight_begin session_id=%s command=%s browser=%s elapsed_ms=%llu",
            sid.c_str(), python_path.c_str(),
            effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
            static_cast<unsigned long long>(preflight_start_ms - t0));
        const bool preflight_ok = prepare_install_for_launch_locked(python_path) && probe_module_installed_locked(python_path) && preflight_server_entry_locked(python_path, effective_cfg);
        if (!preflight_ok)
        {
            preflight_ms = now_ms() - preflight_start_ms;
            std::lock_guard<std::recursive_mutex> slk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = sg().last_error.empty() ? std::string("camoufox managed session preflight failed") : sg().last_error;
            session->last_launch_ms = now_ms() - t0;
            session->last_launch_diagnostics = {
                {"status", "error"},
                {"phase", "mcp_server_preflight"},
                {"generation", setup_generation},
                {"session_id", sid},
                {"command", python_path},
                {"elapsed_ms", session->last_launch_ms},
                {"error", session->last_error}
            };
            const nlohmann::json sticky = maybe_set_sticky_setup_failure(
                setup_ctx,
                session->last_error,
                session->last_launch_diagnostics,
                setup_generation,
                0,
                camoufox_debug_log_path(),
                session->last_launch_ms);
            if (sticky.is_object() && !sticky.empty())
            {
                attach_sticky_setup_failure(session->last_launch_diagnostics, sticky);
                session->last_error = sticky_setup_failure_error_text(json_string_or(sticky, "category", std::string()), session->last_error);
            }
            diag::log_tagged_fmt("camoufox", "managed_start preflight_failed session_id=%s preflight_elapsed_ms=%llu elapsed_ms=%llu err=%s",
                sid.c_str(), static_cast<unsigned long long>(now_ms() - preflight_start_ms),
                static_cast<unsigned long long>(now_ms() - t0), session->last_error.c_str());
            diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=preflight session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
                sid.c_str(),
                static_cast<unsigned long long>(preflight_ms),
                static_cast<unsigned long long>(connect_ms),
                static_cast<unsigned long long>(tools_ms),
                static_cast<unsigned long long>(launch_rpc_ms),
                static_cast<unsigned long long>(readiness_probe_ms),
                static_cast<unsigned long long>(visible_window_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            return false;
        }
        preflight_ms = now_ms() - preflight_start_ms;
        diag::log_tagged_fmt("camoufox", "managed_start preflight_end session_id=%s preflight_elapsed_ms=%llu elapsed_ms=%llu",
            sid.c_str(), static_cast<unsigned long long>(now_ms() - preflight_start_ms),
            static_cast<unsigned long long>(now_ms() - t0));
    }
    mcp_client::server_config_t scfg;
    scfg.name = std::string("camoufox-reverse-") + sid;
    scfg.transport = mcp_client::transport_type_t::stdio;
    scfg.command = python_path;
    scfg.args.push_back("-I");
    scfg.args.push_back("-m");
    scfg.args.push_back(effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    for (const auto& a : effective_cfg.extra_args) scfg.args.push_back(a);
    scfg.env["AIDA_CAMOUFOX_PYTHON"] = python_path;
    if (system_python_discovery_allowed())
        scfg.env["AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON"] = "1";
    uint64_t managed_generation = 0;
    const std::string child_debug_log = camoufox_debug_log_path();
    populate_internal_camoufox_env(scfg, sid, effective_cfg.browser_executable, child_debug_log);
    auto log_managed_failure_diagnostics = [&](const char* phase, uint32_t pid, const std::string& error, const std::string& response_tail = std::string()) {
        const std::string tree = pid == 0 ? std::string() : compact_process_tree(enumerate_process_tree(pid));
        const std::string debug_tail = read_file_tail_for_log(child_debug_log, 6000);
        const std::string debug_phase = last_camoufox_debug_event_from_tail(debug_tail);
        const std::string compact_response_tail = compact_child_output_tail(response_tail, 900);
        diag::log_tagged_fmt("camoufox", "managed_start_failure phase=%s session_id=%s generation=%llu child_pid=%lu elapsed_ms=%llu err_len=%zu response_tail=%.900s debug_phase=%s stderr_tail_len=%zu stderr_tail=%.6000s process_tree=%s",
            safe_reason(phase),
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            static_cast<unsigned long>(pid),
            static_cast<unsigned long long>(now_ms() - t0),
            error.size(),
            compact_response_tail.c_str(),
            debug_phase.empty() ? "<none>" : debug_phase.c_str(),
            debug_tail.size(),
            debug_tail.c_str(),
            tree.empty() ? "<empty>" : tree.c_str());
    };
    auto cleanup_managed_process = [&](const char* phase, uint32_t pid, const std::string& reason) {
        const std::string before_tree = pid == 0 ? std::string() : compact_process_tree(enumerate_process_tree(pid));
        diag::log_tagged_fmt("camoufox", "managed_start_cleanup_begin phase=%s session_id=%s generation=%llu child_pid=%lu reason=%s process_tree=%s",
            safe_reason(phase),
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            static_cast<unsigned long>(pid),
            reason.c_str(),
            before_tree.empty() ? "<empty>" : before_tree.c_str());
        process_tree_reap_result_t reap;
        if (pid != 0)
            reap = terminate_process_tree_sync(pid, reason);
        diag::log_tagged_fmt("camoufox", "managed_start_cleanup_done phase=%s session_id=%s generation=%llu child_pid=%lu reason=%s descendants_before=%zu alive_after=%zu success=%d elapsed_ms=%llu",
            safe_reason(phase),
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            static_cast<unsigned long>(pid),
            reason.c_str(),
            reap.descendants_before,
            reap.alive_after,
            pid == 0 || reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
    };
    scfg.enabled = true;
    scfg.auto_connect = false;
    scfg.oauth_enabled = false;
    auto cli = std::make_shared<mcp_client::client_t>();
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::starting;
        session->last_error.clear();
        session->cleanup_pending = false;
        session->browser_open = false;
        session->page_verified = false;
        session->pages.clear();
        clear_privacy_locked(*session);
        session->last_launch_diagnostics = nlohmann::json::object();
        session->active_profile_dir.clear();
        session->active_profile_generated = false;
        session->active_page_id.clear();
        session->generation++;
        managed_generation = session->generation;
    }
    {
        uint64_t managed_launch_token = 0;
        if (!acquire_launch_admission("start_managed_bridge", sid, managed_generation, 0, managed_launch_token))
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = "CAMOUFOX-LONGOP-REJECT: downstream producer capacity exhausted for camoufox_longop managed launch";
            return false;
        }
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->launch_admission_token = managed_launch_token;
    }
    launch_admission_guard_t managed_launch_guard(&session->launch_admission_token, sid);

    const std::string cwd_log = wide_to_utf8(current_dir_w());
    const auto workdir_it = scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
    const auto profile_it = scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT");
    const DWORD mcp_create_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    {
        std::lock_guard<std::recursive_mutex> glk(sg().mtx);
        std::string init_block_reason;
        uint64_t init_block_remaining_ms = 0;
        uint64_t init_block_generation = 0;
        uint32_t init_block_count = 0;
        if (launch_init_failure_blocked_locked(scfg.command, now_ms(), init_block_reason, init_block_remaining_ms, init_block_generation, init_block_count))
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = "camoufox reverse-MCP launch blocked after immediate process initialization failure; retry after " +
                std::to_string(init_block_remaining_ms) + "ms";
            session->last_launch_diagnostics = {
                {"status", "blocked"},
                {"phase", "process_initialization_failure_backoff"},
                {"session_id", sid},
                {"blocked_generation", init_block_generation},
                {"remaining_ms", init_block_remaining_ms},
                {"count", init_block_count},
                {"exit_code", "0xC0000142"},
                {"command", scfg.command},
                {"reason", init_block_reason}
            };
            diag::log_tagged_fmt("camoufox", "managed_start launch_init_failure_blocked session_id=%s blocked_generation=%llu remaining_ms=%llu count=%lu command=%s reason=%s",
                sid.c_str(),
                static_cast<unsigned long long>(init_block_generation),
                static_cast<unsigned long long>(init_block_remaining_ms),
                static_cast<unsigned long>(init_block_count),
                scfg.command.empty() ? "<empty>" : scfg.command.c_str(),
                init_block_reason.c_str());
            return false;
        }
    }
    diag::log_tagged_fmt("camoufox", "managed_start connect session_id=%s mode=%s command=%s module=%s args=%zu cwd=%s workdir=%s profile_root=%s debug_log=%s timeout_ms=%d env_browser=%d env_workdir=%d env_profile=%d create_flags=0x%08lX inherited_error_mode=%d process_error_mode_before=0x%08lX desired_child_error_mode=0x%08lX",
        sid.c_str(),
        "python",
        scfg.command.c_str(),
        scfg.args.size() > 2 ? scfg.args[2].c_str() : "<missing>",
        scfg.args.size(),
        cwd_log.empty() ? "<empty>" : cwd_log.c_str(),
        workdir_it == scfg.env.end() ? "<empty>" : workdir_it->second.c_str(),
        profile_it == scfg.env.end() ? "<empty>" : profile_it->second.c_str(),
        child_debug_log.c_str(),
        effective_cfg.launch_timeout_ms,
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_EXECUTABLE") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT") != scfg.env.end()),
        static_cast<unsigned long>(mcp_create_flags),
        (mcp_create_flags & CREATE_DEFAULT_ERROR_MODE) == 0 ? 1 : 0,
        static_cast<unsigned long>(current_error_mode()),
        static_cast<unsigned long>(current_error_mode() | kBridgeChildErrorMode));
    bool managed_connect_ok = false;
    const uint64_t connect_start_ms = now_ms();
    {
        scoped_child_error_mode_t mcp_child_error_mode("managed_start_mcp_connect", mcp_create_flags, scfg.command.c_str());
        managed_connect_ok = cli->connect(scfg);
    }
    connect_ms = now_ms() - connect_start_ms;
    if (!managed_connect_ok)
    {
        const std::string connect_error = cli->last_error();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = std::string("managed client connect failed: ") + connect_error;
        diag::log_tagged_fmt("camoufox", "managed_start connect_failed session_id=%s generation=%llu err=%s",
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            session->last_error.c_str());
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=connect session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> glk(sg().mtx);
        reset_launch_init_failure_block_locked("managed_start_mcp_connect_success");
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client = cli;
        session->server_command = python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
        session->child_pid = cli->child_process_id();
        session->launched_ms = now_ms();
        session->active_cfg = effective_cfg;
    }
    diag::log_tagged_fmt("camoufox", "managed_start connected session_id=%s mode=%s child_pid=%lu command=%s args=%zu cwd=%s workdir=%s profile_root=%s debug_log=%s timeout_ms=%d",
        sid.c_str(),
        "python",
        static_cast<unsigned long>(cli->child_process_id()),
        python_path.c_str(),
        scfg.args.size(),
        cwd_log.empty() ? "<empty>" : cwd_log.c_str(),
        workdir_it == scfg.env.end() ? "<empty>" : workdir_it->second.c_str(),
        profile_it == scfg.env.end() ? "<empty>" : profile_it->second.c_str(),
        child_debug_log.c_str(),
        effective_cfg.launch_timeout_ms);
    const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(effective_cfg);
    int launch_wait_ms = effective_launch_wait_ms(effective_cfg, bundled_visible_launch);
    launch_wait_ms = apply_visible_readiness_budget_ms(launch_wait_ms, bundled_visible_launch, t0, "managed_start_pre_launch", managed_generation, cli->child_process_id());
    if (bundled_visible_launch && launch_wait_ms < kLaunchWaitMinMs)
    {
        const uint32_t pid = cli->child_process_id();
        const uint64_t elapsed_ms = now_ms() - t0;
        const std::string debug_tail = read_file_tail_for_log(child_debug_log, 4000);
        const std::vector<process_tree_entry_t> budget_tree_entries = pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(pid);
        {
            std::lock_guard<std::recursive_mutex> glk(sg().mtx);
            block_auto_restart_locked("managed_visible_readiness_budget_exhausted", managed_generation, kAutoRestartBlockMs);
        }
        log_managed_failure_diagnostics("visible_readiness_budget_exhausted", pid, "managed visible readiness budget exhausted before launch_browser", debug_tail);
        cleanup_managed_process("visible_readiness_budget_exhausted", pid, std::string("managed_visible_readiness_budget_exhausted_") + sid);
        cli->disconnect();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = "camoufox managed visible readiness budget exhausted before launch_browser";
        session->last_launch_ms = elapsed_ms;
        session->last_launch_diagnostics = {
            {"status", "timeout"},
            {"phase", "visible_readiness_budget"},
            {"transport_phase", "pre_launch"},
            {"caller", "managed_start"},
            {"cancellation_source", "visible_readiness_budget_exhausted"},
            {"generation", managed_generation},
            {"session_id", sid},
            {"child_pid", pid},
            {"child_alive", pid != 0 && process_alive(pid)},
            {"elapsed_ms", elapsed_ms},
            {"requested_ms", cfg.launch_timeout_ms},
            {"effective_ms", launch_wait_ms},
            {"visible_readiness_max_ms", kBundledVisibleReadinessMaxMs},
            {"process_tree", compact_process_tree_with_exit(budget_tree_entries)},
            {"process_tree_count", budget_tree_entries.size()},
            {"debug_tail_len", debug_tail.size()},
            {"stderr_last_frame", debug_tail},
            {"stderr_last_frame_len", debug_tail.size()}
        };
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=visible_readiness_budget session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    if (effective_cfg.launch_timeout_ms != launch_wait_ms || testlab_fast_probe)
    {
        diag::log_tagged_fmt("camoufox", "managed_start launch_timeout_clamped session_id=%s requested_ms=%d effective_ms=%d bundled_visible=%d testlab_fast_probe=%d",
            sid.c_str(), effective_cfg.launch_timeout_ms, launch_wait_ms,
            bundled_visible_launch ? 1 : 0, testlab_fast_probe ? 1 : 0);
    }
    int tool_wait_ms = std::min<int>(std::max<int>(launch_wait_ms / 4, 5000), kToolListWaitMaxMs);
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        managed_generation = session->generation;
    }
    std::string managed_missing_tools;
    std::string managed_tool_inventory;
    const uint64_t tools_start_ms = now_ms();
    if (!wait_for_required_reverse_tools(
            cli.get(),
            tool_wait_ms,
            "managed_start",
            "python",
            scfg.command,
            sid,
            managed_generation,
            managed_missing_tools,
            managed_tool_inventory))
    {
        tools_ms = now_ms() - tools_start_ms;
        const uint32_t pid = cli->child_process_id();
        const std::string managed_inner = cli->last_error();
        log_required_reverse_tools_missing_launch_skip(
            "managed_start",
            "python",
            scfg.command,
            sid,
            managed_generation,
            pid,
            managed_missing_tools,
            managed_tool_inventory,
            managed_inner);
        log_managed_failure_diagnostics("required_tools_missing", pid, managed_inner, managed_tool_inventory);
        cleanup_managed_process("required_tools_missing", pid, std::string("managed_required_reverse_tools_missing_") + sid);
        cli->disconnect();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = std::string("camoufox managed MCP server did not expose required reverse tools: ") +
            (managed_missing_tools.empty() ? std::string("<unknown>") : managed_missing_tools) +
            "; inventory=" + (managed_tool_inventory.empty() ? std::string("<empty>") : managed_tool_inventory) +
            "; mcp last_error=" + managed_inner;
        session->last_launch_ms = now_ms() - t0;
        session->last_launch_diagnostics = {
            {"status", "error"},
            {"phase", "required_reverse_tools_missing"},
            {"generation", managed_generation},
            {"session_id", sid},
            {"child_pid", pid},
            {"missing_tools", managed_missing_tools},
            {"inventory", managed_tool_inventory},
            {"mcp_last_error", managed_inner},
            {"elapsed_ms", session->last_launch_ms}
        };
        const nlohmann::json sticky = set_sticky_setup_failure(
            setup_ctx,
            "required_reverse_tools_missing",
            session->last_error,
            managed_generation,
            pid,
            child_debug_log,
            session->last_launch_ms,
            session->last_launch_diagnostics);
        attach_sticky_setup_failure(session->last_launch_diagnostics, sticky);
        session->last_error = sticky_setup_failure_error_text("required_reverse_tools_missing", session->last_error);
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=required_tools session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    tools_ms = now_ms() - tools_start_ms;
    effective_cfg.launch_timeout_ms = launch_wait_ms;
    nlohmann::json args = build_launch_args(effective_cfg);
    const uint64_t managed_launch_attempt_ms = now_ms();
    args["bridge_generation"] = managed_generation;
    args["bridge_session_id"] = sid;
    args["bridge_attempt_id"] = std::to_string(managed_generation) + "-" + std::to_string(managed_launch_attempt_ms);
    const std::string managed_launch_ua_policy = args.value("ua_policy", std::string("camoufox_native"));
    const std::string managed_launch_service_workers = args.value("service_workers", std::string("allow"));
    const std::string managed_launch_policy_marker = args.value("aida_launch_policy_marker", std::string());
    diag::log_tagged_fmt("camoufox", "managed_start launch_request session_id=%s ua_policy=%s ua_override_len=%zu persistent_context=%d profile_dir=%d user_data_dir=%d block_webrtc=%d block_service_workers=%d service_workers=%s fast_visible_fallback=%d marker=%s",
        sid.c_str(),
        managed_launch_ua_policy.c_str(),
        effective_cfg.user_agent.size(),
        args.value("persistent_context", false) ? 1 : 0,
        args.contains("profile_dir") ? 1 : 0,
        args.contains("user_data_dir") ? 1 : 0,
        args.value("block_webrtc", true) ? 1 : 0,
        args.value("block_service_workers", false) ? 1 : 0,
        managed_launch_service_workers.c_str(),
        args.value("aida_fast_visible_launch", false) ? 1 : 0,
        managed_launch_policy_marker.c_str());
    const uint64_t launch_rpc_start_ms = now_ms();
    call_result_t launch = managed_call_with_deadline(session, "launch_browser", args, launch_wait_ms, true);
    launch_rpc_ms = now_ms() - launch_rpc_start_ms;
    if (!launch.ok)
    {
        const uint32_t pid = cli->child_process_id();
        std::string managed_launch_error_text = launch.error.empty() ? launch.text : launch.error;
        nlohmann::json failed_launch_payload = launch.data;
        if (!failed_launch_payload.is_object())
            parse_text_to_json(launch.text, failed_launch_payload);
        if (failed_launch_payload.is_object())
        {
            const nlohmann::json failed_launch_diag = launch_diagnostics_from_response(failed_launch_payload);
            const std::string managed_failure_text = sidecar_failure_text(failed_launch_payload, failed_launch_diag, launch.error.empty() ? launch.text : launch.error);
            managed_launch_error_text = managed_failure_text;
            nlohmann::json managed_failed_diag;
            {
                std::lock_guard<std::recursive_mutex> lk(session->mtx);
                session->last_launch_diagnostics = managed_launch_failure_diagnostics_snapshot(
                    *session,
                    failed_launch_diag,
                    "error",
                    json_string_or(failed_launch_diag, "phase", std::string("mcp_transport")).c_str(),
                    managed_generation,
                    args.value("bridge_attempt_id", std::string()),
                    pid,
                    cfg.launch_timeout_ms,
                    launch_wait_ms,
                    now_ms() - managed_launch_attempt_ms,
                    managed_failure_text,
                    launch.text);
                session->last_launch_diagnostics["sidecar_error_type"] = json_string_or(failed_launch_diag, "error_type", std::string());
                session->last_launch_diagnostics["sidecar_error_kind"] = json_string_or(failed_launch_diag, "error_kind", std::string());
                session->last_launch_diagnostics["sidecar_error_summary"] = json_string_or(failed_launch_diag, "error_summary", managed_failure_text);
                managed_failed_diag = session->last_launch_diagnostics;
            }
            diag::log_tagged_fmt("camoufox", "managed_launch failed_payload session_id=%s generation=%llu attempt_id=%s child_pid=%lu child_alive=%d phase=%s timeout_phase=%s sidecar_error_type=%s sidecar_error_kind=%s last_event=%s diag_generation=%s remaining_ms=%d error_len=%zu error_tail=%.900s response_tail=%.900s process_tree_count=%zu bridge_state=%s browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d last_launch_diag=%s",
                sid.c_str(),
                static_cast<unsigned long long>(managed_generation),
                args.value("bridge_attempt_id", std::string()).c_str(),
                static_cast<unsigned long>(pid),
                managed_failed_diag.value("child_alive", false) ? 1 : 0,
                json_string_or(managed_failed_diag, "phase", std::string()).c_str(),
                json_string_or(managed_failed_diag, "timeout_phase", std::string()).c_str(),
                json_string_or(managed_failed_diag, "sidecar_error_type", std::string()).c_str(),
                json_string_or(managed_failed_diag, "sidecar_error_kind", std::string()).c_str(),
                json_string_or(managed_failed_diag, "last_debug_event_name", std::string()).c_str(),
                json_string_or(managed_failed_diag, "generation", std::string()).c_str(),
                json_int_or(managed_failed_diag, "remaining_ms", -1),
                managed_failure_text.size(),
                compact_child_output_tail(managed_failure_text, 900).c_str(),
                compact_child_output_tail(launch.text, 900).c_str(),
                static_cast<size_t>(managed_failed_diag.value("process_tree_count", 0)),
                bridge_state_name(session->state),
                session->browser_open ? 1 : 0,
                session->page_verified ? 1 : 0,
                session->privacy_verified ? 1 : 0,
                session->cleanup_pending ? 1 : 0,
                managed_failed_diag.dump().c_str());
        }
        else
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->last_launch_diagnostics = managed_launch_failure_diagnostics_snapshot(
                *session,
                nlohmann::json::object(),
                "error",
                "mcp_transport",
                managed_generation,
                args.value("bridge_attempt_id", std::string()),
                pid,
                cfg.launch_timeout_ms,
                launch_wait_ms,
                now_ms() - managed_launch_attempt_ms,
                managed_launch_error_text,
                launch.text);
        }
        nlohmann::json managed_sticky;
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            managed_sticky = maybe_set_sticky_setup_failure(
                setup_ctx,
                managed_launch_error_text,
                session->last_launch_diagnostics,
                managed_generation,
                pid,
                child_debug_log,
                now_ms() - t0);
            if (managed_sticky.is_object() && !managed_sticky.empty())
                attach_sticky_setup_failure(session->last_launch_diagnostics, managed_sticky);
        }
        log_managed_failure_diagnostics("launch_browser_failed", pid, managed_launch_error_text, launch.text);
        {
            std::lock_guard<std::recursive_mutex> glk(sg().mtx);
            block_auto_restart_locked("managed_launch_browser_failed", managed_generation, kAutoRestartBlockMs);
        }
        cleanup_managed_process("launch_browser_failed", pid, std::string("managed_launch_failed_") + sid);
        cli->disconnect();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = managed_launch_error_text.empty() ? std::string("camoufox managed launch_browser failed") : managed_launch_error_text;
        if (managed_sticky.is_object() && !managed_sticky.empty())
            session->last_error = sticky_setup_failure_error_text(json_string_or(managed_sticky, "category", std::string()), session->last_error);
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=launch_rpc session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    nlohmann::json launch_payload = launch.data;
    if (!launch_payload.is_object())
        parse_text_to_json(launch.text, launch_payload);
    if (launch_payload.is_object())
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->last_launch_diagnostics = launch_diagnostics_from_response(launch_payload);
    }
    if (launch_payload.is_object() && launch_payload.contains("error") && launch_payload["error"].is_string())
    {
        const uint32_t pid = cli->child_process_id();
        const std::string err = launch_payload["error"].get<std::string>();
        const nlohmann::json launch_diag = launch_diagnostics_from_response(launch_payload);
        const std::string failure_text = sidecar_failure_text(launch_payload, launch_diag, "launch_browser returned empty error field");
        nlohmann::json managed_error_diag;
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->last_launch_diagnostics = managed_launch_failure_diagnostics_snapshot(
                *session,
                launch_diag,
                json_string_or(launch_diag, "status", std::string("error")).c_str(),
                json_string_or(launch_diag, "phase", std::string("sidecar_returned_error")).c_str(),
                managed_generation,
                args.value("bridge_attempt_id", std::string()),
                pid,
                cfg.launch_timeout_ms,
                launch_wait_ms,
                now_ms() - managed_launch_attempt_ms,
                failure_text,
                launch.text);
            session->last_launch_diagnostics["sidecar_error_empty"] = err.empty();
            session->last_launch_diagnostics["sidecar_error_type"] = json_string_or(launch_diag, "error_type", std::string());
            session->last_launch_diagnostics["sidecar_error_kind"] = json_string_or(launch_diag, "error_kind", std::string());
            session->last_launch_diagnostics["sidecar_error_summary"] = json_string_or(launch_diag, "error_summary", failure_text);
            managed_error_diag = session->last_launch_diagnostics;
        }
        diag::log_tagged_fmt("camoufox", "managed_launch returned_error session_id=%s generation=%llu attempt_id=%s child_pid=%lu child_alive=%d phase=%s timeout_phase=%s sidecar_error_type=%s sidecar_error_kind=%s last_event=%s diag_generation=%s remaining_ms=%d err_len=%zu err_tail=%.900s response_tail=%.900s process_tree_count=%zu bridge_state=%s browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d last_launch_diag=%s",
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            args.value("bridge_attempt_id", std::string()).c_str(),
            static_cast<unsigned long>(pid),
            managed_error_diag.value("child_alive", false) ? 1 : 0,
            json_string_or(managed_error_diag, "phase", std::string()).c_str(),
            json_string_or(managed_error_diag, "timeout_phase", std::string()).c_str(),
            json_string_or(managed_error_diag, "sidecar_error_type", std::string()).c_str(),
            json_string_or(managed_error_diag, "sidecar_error_kind", std::string()).c_str(),
            json_string_or(managed_error_diag, "last_debug_event_name", std::string()).c_str(),
            json_string_or(managed_error_diag, "generation", std::string()).c_str(),
            json_int_or(managed_error_diag, "remaining_ms", -1),
            failure_text.size(),
            compact_child_output_tail(failure_text, 900).c_str(),
            compact_child_output_tail(launch.text, 900).c_str(),
            static_cast<size_t>(managed_error_diag.value("process_tree_count", 0)),
            bridge_state_name(session->state),
            session->browser_open ? 1 : 0,
            session->page_verified ? 1 : 0,
            session->privacy_verified ? 1 : 0,
            session->cleanup_pending ? 1 : 0,
            managed_error_diag.dump().c_str());
        nlohmann::json managed_sticky;
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            managed_sticky = maybe_set_sticky_setup_failure(
                setup_ctx,
                failure_text,
                session->last_launch_diagnostics,
                managed_generation,
                pid,
                child_debug_log,
                now_ms() - t0);
            if (managed_sticky.is_object() && !managed_sticky.empty())
                attach_sticky_setup_failure(session->last_launch_diagnostics, managed_sticky);
        }
        log_managed_failure_diagnostics("launch_browser_returned_error", pid, failure_text, launch.text);
        {
            std::lock_guard<std::recursive_mutex> glk(sg().mtx);
            block_auto_restart_locked("managed_launch_browser_returned_error", managed_generation, kAutoRestartBlockMs);
        }
        cleanup_managed_process("launch_browser_returned_error", pid, std::string("managed_launch_returned_error_") + sid);
        cli->disconnect();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = std::string("camoufox managed launch_browser returned error: ") + failure_text;
        if (managed_sticky.is_object() && !managed_sticky.empty())
            session->last_error = sticky_setup_failure_error_text(json_string_or(managed_sticky, "category", std::string()), session->last_error);
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=launch_returned_error session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    bool managed_privacy_failed = false;
    uint32_t managed_privacy_failed_pid = 0;
    if (launch_payload.is_object())
    {
        const nlohmann::json managed_launch_diag = launch_diagnostics_from_response(launch_payload);
        const nlohmann::json managed_phase_timings = managed_launch_diag.contains("phase_timings") && managed_launch_diag["phase_timings"].is_object()
            ? managed_launch_diag["phase_timings"] : nlohmann::json::object();
        const nlohmann::json managed_process_diag = managed_launch_diag.contains("process") && managed_launch_diag["process"].is_object()
            ? managed_launch_diag["process"] : nlohmann::json::object();
        const nlohmann::json managed_selected_page = managed_launch_diag.contains("selected_page") && managed_launch_diag["selected_page"].is_object()
            ? managed_launch_diag["selected_page"] : nlohmann::json::object();
        diag::log_tagged_fmt("camoufox", "managed_launch diagnostics session_id=%s generation=%llu child_pid=%lu diag_generation=%s attempt_id=%s phase=%s remaining_ms=%d phase_count=%zu process_pid=%d descendants=%zu selected_page=%s selected_url_len=%d selected_title_len=%d timeout_phase=%s exception_type=%s",
            sid.c_str(),
            static_cast<unsigned long long>(managed_generation),
            static_cast<unsigned long>(cli->child_process_id()),
            json_string_or(managed_launch_diag, "generation", std::string()).c_str(),
            json_string_or(managed_launch_diag, "attempt_id", std::string()).c_str(),
            json_string_or(managed_launch_diag, "phase", std::string()).c_str(),
            json_int_or(managed_launch_diag, "remaining_ms", -1),
            managed_phase_timings.size(),
            json_int_or(managed_process_diag, "pid", -1),
            json_array_size_or_zero(managed_process_diag, "descendants"),
            json_string_or(managed_selected_page, "page_id", std::string()).c_str(),
            json_int_or(managed_selected_page, "url_len", -1),
            json_int_or(managed_selected_page, "title_len", -1),
            json_string_or(managed_launch_diag, "timeout_phase", std::string()).c_str(),
            json_string_or(managed_launch_diag, "exception_type", std::string()).c_str());
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        const std::string parsed_profile_dir = launch_profile_dir_from_response(launch_payload);
        if (!parsed_profile_dir.empty())
        {
            session->active_profile_dir = parsed_profile_dir;
            session->active_profile_generated = launch_profile_generated_from_response(launch_payload);
        }
        else
        {
            session->active_profile_generated = false;
        }
        update_privacy_from_response_locked(*session, launch_payload, "managed_launch_browser");
        if (!session->privacy_verified)
        {
            managed_privacy_failed = true;
            managed_privacy_failed_pid = cli->child_process_id();
            session->client.reset();
            session->child_pid = 0;
            session->state = bridge_state_t::error;
            session->last_error = "camoufox managed launch privacy verification diagnostics missing or failed";
            clear_privacy_locked(*session);
            session->active_profile_dir.clear();
            session->active_profile_generated = false;
        }
    }
    if (managed_privacy_failed)
    {
        log_managed_failure_diagnostics("launch_privacy_not_verified", managed_privacy_failed_pid, "privacy verification failed", launch.text);
        cleanup_managed_process("launch_privacy_not_verified", managed_privacy_failed_pid, std::string("managed_launch_privacy_not_verified_") + sid);
        cli->disconnect();
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=privacy session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    const uint64_t readiness_probe_start_ms = now_ms();
    call_result_t page = managed_call_with_deadline(session, "get_page_info", nlohmann::json::object(), kReadinessProbeTimeoutMs, true);
    readiness_probe_ms = now_ms() - readiness_probe_start_ms;
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        const uint32_t pid = cli->child_process_id();
        log_managed_failure_diagnostics("readiness_failed", pid, page.error, page.text);
        cleanup_managed_process("readiness_failed", pid, std::string("managed_readiness_failed_") + sid);
        cli->disconnect();
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = page.error.empty() ? std::string("camoufox managed readiness probe failed") : page.error;
        diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=readiness_probe session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
            sid.c_str(),
            static_cast<unsigned long long>(preflight_ms),
            static_cast<unsigned long long>(connect_ms),
            static_cast<unsigned long long>(tools_ms),
            static_cast<unsigned long long>(launch_rpc_ms),
            static_cast<unsigned long long>(readiness_probe_ms),
            static_cast<unsigned long long>(visible_window_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        update_page_cache_from_json_locked(*session, page.data, "managed_readiness");
        if (session->active_page_url.empty()) session->active_page_url = page.data["url"].get<std::string>();
        if (session->active_page_title.empty()) session->active_page_title = json_string_or(page.data, "title", std::string());
        session->browser_open = true;
        session->page_verified = true;
        session->last_verified_ms = now_ms();
        session->last_launch_ms = now_ms() - t0;
        const uint64_t visible_window_start_ms = now_ms();
        const visible_window_snapshot_t ready_visible = sample_visible_window_proof(session->child_pid);
        visible_window_ms = now_ms() - visible_window_start_ms;
        session->last_launch_diagnostics["visible_window_proof"] = visible_window_proof_json(ready_visible, session->child_pid, managed_generation, "managed_launch_ready");
        session->last_launch_diagnostics["cpp_stage_timings"] = {
            {"preflight_ms", preflight_ms},
            {"connect_ms", connect_ms},
            {"required_tools_ms", tools_ms},
            {"launch_rpc_ms", launch_rpc_ms},
            {"readiness_probe_ms", readiness_probe_ms},
            {"visible_window_ms", visible_window_ms},
            {"total_ms", now_ms() - t0}
        };
        log_visible_window_proof("managed_launch_ready", managed_generation, session->child_pid, ready_visible);
        if (!effective_cfg.headless && ready_visible.visible_window_count == 0)
        {
            const uint32_t failed_pid = session->child_pid;
            session->client.reset();
            session->child_pid = 0;
            session->state = bridge_state_t::error;
            session->last_error = "camoufox managed launch visible window proof missing after readiness";
            session->browser_open = false;
            session->page_verified = false;
            session->pages.clear();
            clear_privacy_locked(*session);
            session->active_page_id.clear();
            session->active_page_url.clear();
            session->active_page_title.clear();
            diag::log_tagged_fmt("camoufox", "managed_start visible_window_missing session_id=%s generation=%llu child_pid=%lu child_processes=%u browser_processes=%u process_pids=%s elapsed_ms=%llu",
                sid.c_str(),
                static_cast<unsigned long long>(managed_generation),
                static_cast<unsigned long>(failed_pid),
                static_cast<unsigned>(ready_visible.child_process_count),
                static_cast<unsigned>(ready_visible.browser_process_count),
                ready_visible.process_pids.empty() ? "<empty>" : ready_visible.process_pids.c_str(),
                static_cast<unsigned long long>(session->last_launch_ms));
            log_managed_failure_diagnostics("visible_window_missing", failed_pid, "visible window proof missing after readiness", launch.text);
            cleanup_managed_process("visible_window_missing", failed_pid, std::string("managed_visible_window_missing_") + sid);
            cli->disconnect();
            diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=0 phase=visible_window session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu",
                sid.c_str(),
                static_cast<unsigned long long>(preflight_ms),
                static_cast<unsigned long long>(connect_ms),
                static_cast<unsigned long long>(tools_ms),
                static_cast<unsigned long long>(launch_rpc_ms),
                static_cast<unsigned long long>(readiness_probe_ms),
                static_cast<unsigned long long>(visible_window_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            return false;
        }
        session->state = bridge_state_t::ready;
        session->last_error.clear();
    }
    diag::log_tagged_fmt("camoufox", "managed_start ready session_id=%s child_pid=%lu elapsed_ms=%llu",
        sid.c_str(), static_cast<unsigned long>(cli->child_process_id()), static_cast<unsigned long long>(now_ms() - t0));
    diag::log_tagged_fmt("camoufox", "managed_start stage_timing ok=1 phase=ready session_id=%s preflight_ms=%llu connect_ms=%llu tools_ms=%llu launch_rpc_ms=%llu readiness_probe_ms=%llu visible_window_ms=%llu total_ms=%llu child_pid=%lu",
        sid.c_str(),
        static_cast<unsigned long long>(preflight_ms),
        static_cast<unsigned long long>(connect_ms),
        static_cast<unsigned long long>(tools_ms),
        static_cast<unsigned long long>(launch_rpc_ms),
        static_cast<unsigned long long>(readiness_probe_ms),
        static_cast<unsigned long long>(visible_window_ms),
        static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long>(cli->child_process_id()));
    clear_sticky_setup_failure("managed_start_ready");
    managed_launch_guard.committed = true;
    return true;
}

bool stop_managed_bridge(const std::string& session_id, const char* reason)
{
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
        return false;
    const std::string sid = normalize_session_id(session_id);
    auto session = get_managed_session(sid, false);
    if (!session) return true;
    const uint64_t t0 = now_ms();
    const char* stop_reason = safe_reason(reason);
    std::unique_lock<std::recursive_mutex> op_lk(session->operation_mtx);
    std::shared_ptr<mcp_client::client_t> cli;
    uint32_t child_pid = 0;
    std::string cleanup_profile_dir;
    bool cleanup_profile_generated = false;
    uint64_t cleanup_generation = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        if (session->cleanup_pending)
        {
            session->cleanup_diagnostics["status"] = "pending_reap_stop_ignored";
            diag::log_tagged_critical_fmt("camoufox", "managed_stop_cleanup_pending session_id=%s generation=%llu cleanup_generation=%llu child_pid=%lu profile_dir=%s",
                sid.c_str(), static_cast<unsigned long long>(session->generation),
                static_cast<unsigned long long>(session->cleanup_generation),
                static_cast<unsigned long>(session->cleanup_child_pid),
                session->cleanup_profile_dir.empty() ? "<empty>" : session->cleanup_profile_dir.c_str());
            return false;
        }
        cli = session->client;
        child_pid = session->child_pid;
    }
    if (cli)
    {
        (void)managed_call_with_deadline(session, "close_browser", nlohmann::json::object(), 10000);
        cli->disconnect();
    }
    {
        std::unique_lock<std::recursive_mutex> lk(session->mtx);
        const uint64_t stop_generation = ++session->generation;
        cleanup_generation = stop_generation;
        cleanup_profile_dir = session->active_profile_dir;
        cleanup_profile_generated = session->active_profile_generated;
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::stopped;
        session->browser_open = false;
        session->page_verified = false;
        session->pages.clear();
        clear_privacy_locked(*session);
        session->active_page_id.clear();
        session->active_page_url.clear();
        session->active_page_title.clear();
        session->last_error.clear();
        session->cleanup_pending = child_pid != 0 || cli != nullptr;
        session->cleanup_generation = stop_generation;
        session->cleanup_started_ms = session->cleanup_pending ? now_ms() : 0;
        session->cleanup_child_pid = child_pid;
        session->cleanup_profile_dir = cleanup_profile_dir;
        session->cleanup_profile_generated = cleanup_profile_generated;
        session->cleanup_reason = std::string("managed_stop_bridge:") + stop_reason;
        session->cleanup_diagnostics = {
            {"status", session->cleanup_pending ? "pending" : "finished"},
            {"generation", stop_generation},
            {"child_pid", child_pid},
            {"reason", session->cleanup_reason}
        };
        session->last_cleanup_ms = 0;
        const uint64_t managed_launch_token = session->launch_admission_token;
        session->launch_admission_token = 0;
        lk.unlock();
        release_launch_admission(managed_launch_token, stop_reason, sid);
    }
    clear_sticky_setup_failure("managed_stop_bridge");
    process_tree_reap_result_t reap;
    if (child_pid != 0)
        reap = terminate_process_tree_sync(child_pid, std::string("managed_stop_") + sid + "_" + stop_reason);
    const bool reap_complete = child_pid == 0 || reap.alive_after == 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->last_cleanup_ms = now_ms() - t0;
        if (session->cleanup_generation == session->generation)
        {
            session->cleanup_pending = !reap_complete;
            session->cleanup_started_ms = reap_complete ? 0 : session->cleanup_started_ms;
            session->cleanup_child_pid = reap_complete ? 0 : child_pid;
            if (reap_complete)
            {
                session->cleanup_profile_dir.clear();
                session->cleanup_profile_generated = false;
                if (session->active_profile_dir == cleanup_profile_dir)
                {
                    session->active_profile_dir.clear();
                    session->active_profile_generated = false;
                }
            }
            session->cleanup_diagnostics["status"] = reap_complete ? "finished" : "pending_reap";
            session->cleanup_diagnostics["process_reap"] = cleanup_reap_json(reap);
            session->cleanup_diagnostics["elapsed_ms"] = session->last_cleanup_ms;
            session->cleanup_diagnostics["deferred_cleanup"] = !reap_complete;
        }
    }
    if (reap_complete && cleanup_profile_generated)
        purge_generated_profile_dir(cleanup_profile_dir, std::string("managed_stop_") + sid + "_" + stop_reason);
    if (!reap_complete)
    {
        auto deferred_cleanup = [session, child_pid, cleanup_profile_dir, cleanup_profile_generated, stop_reason_text = std::string(stop_reason), cleanup_generation]() {
            const uint64_t deferred_start_ms = now_ms();
            process_tree_reap_result_t deferred_reap;
            bool complete = false;
            while (now_ms() - deferred_start_ms < kCleanupDrainWaitMs)
            {
                deferred_reap = terminate_process_tree_sync(child_pid, std::string("managed_stop_deferred_") + session->session_id + "_" + stop_reason_text);
                if (deferred_reap.alive_after == 0)
                {
                    complete = true;
                    break;
                }
                Sleep(static_cast<DWORD>(kCleanupDrainPollMs));
            }
            {
                std::lock_guard<std::recursive_mutex> lk(session->mtx);
                if (session->cleanup_generation == cleanup_generation)
                {
                    session->last_cleanup_ms = now_ms() - deferred_start_ms;
                    session->cleanup_diagnostics["process_reap_deferred"] = cleanup_reap_json(deferred_reap);
                    session->cleanup_diagnostics["deferred_elapsed_ms"] = session->last_cleanup_ms;
                    session->cleanup_diagnostics["status"] = complete ? "finished" : "pending_reap";
                    if (complete)
                    {
                        session->cleanup_pending = false;
                        session->cleanup_started_ms = 0;
                        session->cleanup_child_pid = 0;
                        session->cleanup_profile_dir.clear();
                        session->cleanup_profile_generated = false;
                        if (session->active_profile_dir == cleanup_profile_dir)
                        {
                            session->active_profile_dir.clear();
                            session->active_profile_generated = false;
                        }
                    }
                }
            }
            if (complete && cleanup_profile_generated)
                purge_generated_profile_dir(cleanup_profile_dir, std::string("managed_stop_deferred_") + session->session_id + "_" + stop_reason_text);
            diag::log_tagged_fmt("camoufox", "managed_stop_deferred session_id=%s generation=%llu child_pid=%lu alive_after=%zu complete=%d elapsed_ms=%llu",
                session->session_id.c_str(), static_cast<unsigned long long>(cleanup_generation),
                static_cast<unsigned long>(child_pid), deferred_reap.alive_after, complete ? 1 : 0,
                static_cast<unsigned long long>(now_ms() - deferred_start_ms));
        };
        if (!post_bridge_task("camoufox.managed_stop_deferred", deferred_cleanup))
            deferred_cleanup();
    }
    diag::log_tagged_fmt("camoufox", "managed_stop session_id=%s reason=%s child_pid=%lu elapsed_ms=%llu",
        sid.c_str(), stop_reason, static_cast<unsigned long>(child_pid), static_cast<unsigned long long>(now_ms() - t0));
    return true;
}

bridge_status_t get_status()
{
    bridge_status_t s;
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        s.state = bridge_state_t::starting;
        s.last_error = "camoufox bridge state is busy";
        s.child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
        s.child_alive = process_alive(s.child_pid);
        s.total_calls = sg().total_calls.load(std::memory_order_relaxed);
        s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
        s.session_id = "default";
        s.active_session_id = "default";
        s.session_count = managed_session_count();
        s.phase = "state_busy";
        s.readiness_phase = "starting";
        s.last_debug_event = "get_status_busy";
        populate_child_process_identity(s);
        populate_process_counts(s);
        diag::log_tagged_fmt("camoufox", "get_status busy child_pid=%lu child_alive=%d calls=%llu errors=%llu readiness_phase=%s",
            static_cast<unsigned long>(s.child_pid), s.child_alive ? 1 : 0,
            static_cast<unsigned long long>(s.total_calls),
            static_cast<unsigned long long>(s.total_errors),
            s.readiness_phase.c_str());
        return s;
    }
    s.state           = sg().state;
    s.session_id      = sg().session_id.empty() ? std::string("default") : sg().session_id;
    s.active_session_id = s.session_id;
    s.session_count   = managed_session_count();
    s.last_error      = sg().last_error;
    s.server_command  = sg().server_command;
    s.child_pid       = sg().child_pid;
    s.launched_ms     = sg().launched_ms;
    s.attempt_started_ms = sg().attempt_started_ms;
    s.attempt_elapsed_ms = sg().attempt_elapsed_ms;
    s.last_attempt_elapsed_ms = sg().last_attempt_elapsed_ms;
    s.last_call_ms    = sg().last_call_ms;
    s.total_calls     = sg().total_calls.load(std::memory_order_relaxed);
    s.total_errors    = sg().total_errors.load(std::memory_order_relaxed);
    s.browser_open    = sg().browser_open;
    s.active_page_id  = sg().active_page_id;
    s.active_page_url = sg().active_page_url;
    s.active_page_title = sg().active_page_title;
    s.pages           = sg().pages;
    s.page_count      = static_cast<uint32_t>(sg().pages.size());
    s.active_profile_dir = sg().active_profile_dir;
    s.active_profile_generated = sg().active_profile_generated;
    s.effective_ua_policy = sg().effective_ua_policy;
    s.ua_override_string = sg().ua_override_string;
    s.ua_override = sg().ua_override;
    s.webrtc_blocked = sg().webrtc_blocked;
    s.privacy_verified = sg().privacy_verified;
    s.privacy_diagnostics = sg().privacy_diagnostics;
    s.last_launch_diagnostics = sg().last_launch_diagnostics;
    s.page_verified   = sg().page_verified;
    s.cleanup_pending = sg().cleanup_pending;
    s.cleanup_generation = sg().cleanup_generation;
    s.cleanup_started_ms = sg().cleanup_started_ms;
    s.cleanup_child_pid = sg().cleanup_child_pid;
    s.cleanup_reason = sg().cleanup_reason;
    s.cleanup_diagnostics = sg().cleanup_diagnostics;
    s.generation      = sg().generation;
    s.last_launch_ms  = sg().last_launch_ms;
    s.last_nav_ms     = sg().last_nav_ms;
    s.last_cleanup_ms = sg().last_cleanup_ms;
    s.last_verified_ms = sg().last_verified_ms;
    s.child_alive     = process_alive(s.child_pid);
    populate_child_process_identity(s);
    populate_process_counts(s);
    bool client_connected = sg().client != nullptr;
    std::shared_ptr<mcp_client::client_t> cleanup_client;
    uint32_t cleanup_child_pid = 0;
    uint64_t cleanup_generation = 0;
    std::string cleanup_reason;
    std::string state_error;
    const bool ready_status_failed = s.state == bridge_state_t::ready &&
        (is_driver_closed_error(s.last_error) ||
            !client_connected ||
            !s.child_alive ||
            !s.browser_open ||
            !s.page_verified ||
            !s.privacy_verified ||
            !usable_browser_process_count(s.browser_process_count));
    if (ready_status_failed)
    {
        std::string reason;
        if (is_driver_closed_error(s.last_error))
            reason = "driver transport is closed";
        else if (!client_connected)
            reason = "mcp client is detached";
        else if (!s.child_alive)
            reason = "sidecar process exited";
        else if (!usable_browser_process_count(s.browser_process_count))
            reason = "browser process tree empty";
        else if (!s.browser_open)
            reason = "browser is not open";
        else if (!s.page_verified)
            reason = "page is not verified";
        else if (!s.privacy_verified)
            reason = "privacy is not verified";
        else
            reason = "status readiness verification failed";
        const bridge_health_snapshot_t health = sample_bridge_health(s.child_pid, true);
        if (invalidate_default_ready_bridge_locked(
                "get_status",
                reason,
                health,
                cleanup_client,
                cleanup_child_pid,
                cleanup_generation,
                cleanup_reason,
                state_error))
        {
            s.state = sg().state;
            s.last_error = sg().last_error;
            s.child_pid = sg().child_pid;
            s.browser_open = sg().browser_open;
            s.active_page_id = sg().active_page_id;
            s.active_page_url = sg().active_page_url;
            s.active_page_title = sg().active_page_title;
            s.pages = sg().pages;
            s.page_count = static_cast<uint32_t>(sg().pages.size());
            s.active_profile_dir = sg().active_profile_dir;
            s.active_profile_generated = sg().active_profile_generated;
            s.privacy_verified = sg().privacy_verified;
            s.page_verified = sg().page_verified;
            s.cleanup_pending = sg().cleanup_pending;
            s.cleanup_generation = sg().cleanup_generation;
            s.cleanup_started_ms = sg().cleanup_started_ms;
            s.cleanup_child_pid = sg().cleanup_child_pid;
            s.cleanup_reason = sg().cleanup_reason;
            s.cleanup_diagnostics = sg().cleanup_diagnostics;
            s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
            s.child_alive = false;
            s.browser_instance_count = 0;
            s.child_process_count = 0;
            s.browser_process_count = 0;
            client_connected = sg().client != nullptr;
        }
    }
    if (s.state == bridge_state_t::ready && is_driver_closed_error(s.last_error))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_id.clear();
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.pages.clear();
        s.page_count = 0;
        s.active_profile_dir.clear();
        s.active_profile_generated = false;
        s.privacy_verified = false;
        s.page_verified = false;
    }
    if (s.state == bridge_state_t::ready && (!s.child_alive || !s.browser_open || !s.page_verified || !s.privacy_verified))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_id.clear();
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.pages.clear();
        s.page_count = 0;
        s.active_profile_dir.clear();
        s.active_profile_generated = false;
        s.privacy_verified = false;
        s.page_verified = false;
        if (s.last_error.empty())
            s.last_error = "camoufox bridge readiness verification failed";
    }
    if (s.state == bridge_state_t::ready && !usable_browser_process_count(s.browser_process_count))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_id.clear();
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.pages.clear();
        s.page_count = 0;
        s.active_profile_dir.clear();
        s.active_profile_generated = false;
        s.privacy_verified = false;
        s.page_verified = false;
        if (s.last_error.empty())
            s.last_error = "camoufox browser process tree empty";
    }
    else if (s.state == bridge_state_t::ready && reduced_browser_process_tree(s.browser_process_count))
    {
        diag::log_tagged_fmt("camoufox", "reduced_process_tree_accepted source=get_status session_id=%s generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u min_browser_processes=%u client=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d",
            s.session_id.c_str(),
            static_cast<unsigned long long>(s.generation),
            static_cast<unsigned long>(s.child_pid),
            s.child_alive ? 1 : 0,
            static_cast<unsigned>(s.child_process_count),
            static_cast<unsigned>(s.browser_process_count),
            static_cast<unsigned>(kMinReadyBrowserProcessCount),
            client_connected ? 1 : 0,
            s.browser_open ? 1 : 0,
            s.page_verified ? 1 : 0,
            s.privacy_verified ? 1 : 0,
            s.cleanup_pending ? 1 : 0);
    }
    const bool status_ready =
        s.state == bridge_state_t::ready &&
        client_connected &&
        s.child_alive &&
        s.browser_open &&
        s.page_verified &&
        s.privacy_verified &&
        !s.cleanup_pending &&
        usable_browser_process_count(s.browser_process_count) &&
        !is_driver_closed_error(s.last_error);
    if (!status_ready && s.last_error.empty())
    {
        s.last_error = cleanup_status_error_locked("get_status");
        if (sg().last_error.empty() && s.state != bridge_state_t::ready)
            sg().last_error = s.last_error;
    }
    populate_status_diagnostic_fields(s, now_ms(), client_connected);
    const url_log_t u = summarize_url_for_log(s.active_page_url);
    diag::log_tagged_fmt("camoufox", "get_status session_id=%s state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d privacy_verified=%d cleanup_pending=%d cleanup_generation=%llu cleanup_child_pid=%lu cleanup_reason=%s calls=%llu errors=%llu phase=%s readiness_phase=%s error_type=%s error_kind=%s protocol_schema_viewport=%d attempt_started_ms=%llu attempt_elapsed_ms=%llu last_attempt_elapsed_ms=%llu status_age_ms=%llu last_debug_event=%s profile_dir=%s profile_generated=%d active_page_id=%s page_count=%u browser_instances=%u child_processes=%u browser_processes=%u ua_policy=%s ua_override=%d webrtc_blocked=%d active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu err_len=%zu",
        s.session_id.c_str(),
        static_cast<int>(s.state), static_cast<unsigned long long>(s.generation),
        static_cast<unsigned long>(s.child_pid), static_cast<int>(s.child_alive),
        static_cast<int>(s.browser_open), static_cast<int>(s.page_verified), static_cast<int>(s.privacy_verified), static_cast<int>(s.cleanup_pending),
        static_cast<unsigned long long>(s.cleanup_generation),
        static_cast<unsigned long>(s.cleanup_child_pid),
        s.cleanup_reason.empty() ? "<empty>" : s.cleanup_reason.c_str(),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors),
        s.phase.empty() ? "<empty>" : s.phase.c_str(),
        s.readiness_phase.empty() ? "<empty>" : s.readiness_phase.c_str(),
        s.error_type.empty() ? "<empty>" : s.error_type.c_str(),
        s.error_kind.empty() ? "<empty>" : s.error_kind.c_str(),
        s.protocol_schema_viewport ? 1 : 0,
        static_cast<unsigned long long>(s.attempt_started_ms),
        static_cast<unsigned long long>(s.attempt_elapsed_ms),
        static_cast<unsigned long long>(s.last_attempt_elapsed_ms),
        static_cast<unsigned long long>(s.status_age_ms),
        s.last_debug_event.empty() ? "<empty>" : s.last_debug_event.c_str(),
        s.active_profile_dir.empty() ? "<empty>" : s.active_profile_dir.c_str(),
        s.active_profile_generated ? 1 : 0,
        s.active_page_id.c_str(), static_cast<unsigned>(s.page_count),
        static_cast<unsigned>(s.browser_instance_count),
        static_cast<unsigned>(s.child_process_count),
        static_cast<unsigned>(s.browser_process_count),
        s.effective_ua_policy.c_str(),
        s.ua_override ? 1 : 0,
        s.webrtc_blocked ? 1 : 0,
        u.host.c_str(), u.path.c_str(),
        static_cast<int>(u.has_query), u.length, s.active_page_title.size(), s.last_error.size());
    lk.unlock();
    if (cleanup_generation != 0)
        finish_default_ready_bridge_invalidation(cleanup_client, cleanup_child_pid, cleanup_generation, cleanup_reason, state_error);
    return s;
}

bridge_status_t get_status(const std::string& session_id)
{
    if (is_default_session_id(session_id))
        return get_status();
    return managed_status(get_managed_session(session_id, false));
}

bool start_bridge(const launch_config_t& cfg, const std::string& session_id)
{
    const std::string sid = normalize_session_id(session_id.empty() ? cfg.session_id : session_id);
    if (is_default_session_id(sid))
    {
        launch_config_t effective = cfg;
        effective.session_id = "default";
        return start_bridge(effective);
    }
    return start_managed_bridge(cfg, sid);
}

bool stop_bridge(const std::string& session_id, const char* reason)
{
    if (is_default_session_id(session_id))
        return stop_bridge(reason);
    return stop_managed_bridge(session_id, reason);
}

bool force_cleanup(const std::string& session_id, const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* cleanup_reason = safe_reason(reason);
    lifecycle_guard_t cleanup_guard;
    if (!cleanup_guard.acquired)
    {
        diag::log_tagged_critical_fmt("camoufox", "force_cleanup_already_in_progress reason=%s session_id=%s wait_ms=%llu elapsed_ms=%llu caller_pid=%lu caller_tid=%lu",
            cleanup_reason,
            session_id.empty() ? "default" : session_id.c_str(),
            static_cast<unsigned long long>(kLifecycleLockWaitMs),
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_guard_acquired session_id=%s reason=%s wait_elapsed_ms=%llu caller_pid=%lu caller_tid=%lu",
        session_id.empty() ? "default" : session_id.c_str(),
        cleanup_reason,
        static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (is_default_session_id(session_id))
        return force_cleanup_default_impl(reason);
    return stop_managed_bridge(session_id, reason ? reason : "force_cleanup");
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    const uint64_t pre_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t pre_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto op_identity = build_camoufox_op_identity(tool_name.c_str(), "default", pre_admission_generation, pre_admission_child_pid);
    camoufox_op_admission_t op_admission(op_identity);
    if (!op_admission.admitted())
    {
        call_result_t rejected;
        rejected.ok = false;
        rejected.error = "CAMOUFOX-LONGOP-REJECT: " + op_admission.rejection().reason;
        rejected.data = mcp_standalone::downstream::rejection_json(op_admission.rejection(), op_admission.id());
        diag::log_tagged_fmt("camoufox", "call_tool longop_rejected tool=%s session=default reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            tool_name.c_str(),
            op_admission.rejection().reason.c_str(),
            op_admission.rejection().quota_name.c_str(),
            op_admission.rejection().quota_scope.c_str(),
            op_admission.rejection().observed,
            op_admission.rejection().limit);
        return rejected;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t call_start_ms = now_ms();
    const uint64_t request_id = next_request_id();
    nlohmann::json safe_args = args.is_null() ? nlohmann::json::object() : args;
    stamp_aida_operation_id(safe_args, tool_name, request_id);
    const action_snapshot_t entry = action_snapshot();
    diag::log_tagged_fmt("camoufox", "call_tool entry request_id=%llu tool=%s timeout_ms=%d args_shape=%s generation=%llu child_pid=%lu state=%s browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms, json_shape(safe_args).c_str(),
        static_cast<unsigned long long>(entry.generation), static_cast<unsigned long>(entry.child_pid),
        bridge_state_name(entry.state), static_cast<int>(entry.browser_open), static_cast<int>(entry.page_verified),
        static_cast<int>(entry.child_alive), static_cast<int>(entry.cleanup_pending));
    call_result_t r;
    const std::string requested_page_id = json_string_or(safe_args, "page_id", std::string());
    const bridge_health_snapshot_t entry_health = sample_bridge_health(entry.child_pid, true);
    diag::log_tagged_fmt("camoufox", "call_tool health_entry request_id=%llu tool=%s session_id=default page_id=%s caller_pid=%lu caller_tid=%lu timeout_ms=%d generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u process_tree=%s",
        static_cast<unsigned long long>(request_id),
        tool_name.c_str(),
        requested_page_id.c_str(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        timeout_ms,
        static_cast<unsigned long long>(entry.generation),
        static_cast<unsigned long>(entry.child_pid),
        entry_health.child_alive ? 1 : 0,
        entry_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(entry_health.exit_code_valid ? entry_health.exit_code : 0),
        static_cast<unsigned long>(entry_health.exit_query_gle),
        static_cast<unsigned>(entry_health.child_process_count),
        static_cast<unsigned>(entry_health.browser_process_count),
        entry_health.process_tree.empty() ? "<empty>" : entry_health.process_tree.c_str());
    std::string restore_page_id;
    bool legacy_page_target_selected = false;
    if (!requested_page_id.empty() && !tool_accepts_page_id_directly(tool_name))
    {
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            restore_page_id = sg().active_page_id;
        }
        const int select_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json select_args;
        select_args["page_id"] = requested_page_id;
        diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_select request_id=%llu tool=%s page_id=%s restore_page_id=%s timeout_ms=%d",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(), select_timeout_ms);
        call_result_t select_result = call_with_deadline("select_page", select_args, select_timeout_ms);
        if (!select_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_select_failed request_id=%llu tool=%s page_id=%s err=%s data_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(),
                select_result.error.c_str(), json_shape(select_result.data).c_str());
            return page_target_select_failure(tool_name, "default", requested_page_id, select_result);
        }
        if (select_result.data.is_object())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            update_page_cache_from_json_locked(select_result.data, "legacy_page_target_select");
        }
        safe_args.erase("page_id");
        legacy_page_target_selected = true;
    }
    const bool has_page_target = !requested_page_id.empty() && tool_accepts_page_id_directly(tool_name);
    if (tool_name == "click" && !has_page_target)
    {
        r = dispatch_dom_click_action(json_string_or(safe_args, "selector", std::string()), timeout_ms, request_id);
    }
    else if (tool_name == "type_text" && !has_page_target)
    {
        const std::string selector = json_string_or(safe_args, "selector", std::string());
        if (!safe_args.is_object() || !safe_args.contains("text") || !safe_args["text"].is_string())
        {
            r = direct_action_fail("type_text", request_id, selector, timeout_ms, 0, now_ms(), "validate_text", "type_text: text is required");
        }
        else
        {
            r = dispatch_dom_type_text_action(
                selector,
                safe_args["text"].get<std::string>(),
                timeout_ms,
                json_int_or(safe_args, "delay", 0),
                request_id);
        }
    }
    else if (tool_name == "wait_for" && !has_page_target)
    {
        const std::string selector = json_string_or(safe_args, "selector", std::string());
        const std::string url_pattern = json_string_or(safe_args, "url_pattern", std::string());
        if (!selector.empty())
        {
            const int selector_timeout = json_int_or(safe_args, "timeout", timeout_ms > 0 ? timeout_ms : 5000);
            r = dispatch_dom_wait_for_selector_action(selector, selector_timeout, request_id);
        }
        else if (url_pattern.empty())
        {
            r = direct_action_fail("wait_for", request_id, std::string(), timeout_ms, 0, now_ms(), "validate_target", "wait_for: selector or url_pattern is required");
        }
        else
        {
            r = call_with_deadline(tool_name, safe_args, timeout_ms, request_id);
        }
    }
    else
    {
        r = call_with_deadline(tool_name, safe_args, timeout_ms, request_id);
    }
    if (r.ok && r.data.is_object())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(r.data, tool_name.c_str());
    }
    if (r.ok && tool_name == "navigate")
    {
        uint64_t nav_generation = 0;
        uint32_t nav_child_pid = 0;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            nav_generation = sg().generation;
            nav_child_pid = sg().child_pid;
        }
        call_result_t stability_failure;
        const url_log_t requested_url = summarize_url_for_log(json_string_or(safe_args, "url", std::string()));
        if (!verify_default_navigation_stability(
                "call_tool.navigate",
                request_id,
                requested_url,
                nav_generation,
                nav_child_pid,
                call_start_ms,
                stability_failure,
                entry_health.process_tree))
        {
            r = std::move(stability_failure);
        }
    }
    if (r.ok && legacy_page_target_selected && !restore_page_id.empty() && restore_page_id != requested_page_id)
    {
        const int restore_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json restore_args;
        restore_args["page_id"] = restore_page_id;
        call_result_t restore_result = call_with_deadline("select_page", restore_args, restore_timeout_ms);
        if (restore_result.ok && restore_result.data.is_object())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            update_page_cache_from_json_locked(restore_result.data, "legacy_page_target_restore");
        }
        else if (!restore_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_restore_failed request_id=%llu tool=%s requested_page_id=%s restore_page_id=%s err=%s data_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(),
                restore_result.error.c_str(), json_shape(restore_result.data).c_str());
        }
    }
    const action_snapshot_t exit = action_snapshot();
    const bridge_health_snapshot_t exit_health = sample_bridge_health(exit.child_pid, true);
    attach_bridge_call_metadata(
        r,
        "default",
        tool_name,
        request_id,
        timeout_ms,
        now_ms() - call_start_ms,
        exit.generation,
        exit.child_pid,
        requested_page_id,
        exit.state == bridge_state_t::error ? "call_tool_error" : "call_tool_exit",
        false,
        exit.child_alive,
        exit.browser_open,
        exit.page_verified,
        exit.cleanup_pending);
    diag::log_tagged_fmt("camoufox", "call_tool health_exit request_id=%llu tool=%s session_id=default page_id=%s caller_pid=%lu caller_tid=%lu ok=%d elapsed_ms=%llu generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u process_tree=%s",
        static_cast<unsigned long long>(request_id),
        tool_name.c_str(),
        requested_page_id.c_str(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<int>(r.ok),
        static_cast<unsigned long long>(now_ms() - call_start_ms),
        static_cast<unsigned long long>(exit.generation),
        static_cast<unsigned long>(exit.child_pid),
        exit_health.child_alive ? 1 : 0,
        exit_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(exit_health.exit_code_valid ? exit_health.exit_code : 0),
        static_cast<unsigned long>(exit_health.exit_query_gle),
        static_cast<unsigned>(exit_health.child_process_count),
        static_cast<unsigned>(exit_health.browser_process_count),
        exit_health.process_tree.empty() ? "<empty>" : exit_health.process_tree.c_str());
    diag::log_tagged_fmt("camoufox", "call_tool result request_id=%llu tool=%s ok=%d data_shape=%s text_len=%zu error_len=%zu generation=%llu child_pid=%lu state=%s browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(r.ok), json_shape(r.data).c_str(), r.text.size(), r.error.size(),
        static_cast<unsigned long long>(exit.generation), static_cast<unsigned long>(exit.child_pid),
        bridge_state_name(exit.state), static_cast<int>(exit.browser_open), static_cast<int>(exit.page_verified),
        static_cast<int>(exit.child_alive), static_cast<int>(exit.cleanup_pending));
    if (op_admission.is_stale(exit.generation))
    {
        diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-TOMBSTONE tool=%s session=default request_id=%llu admit_generation=%llu exit_generation=%llu ok=%d reason=generation_changed_discard",
            tool_name.c_str(), static_cast<unsigned long long>(request_id),
            static_cast<unsigned long long>(op_admission.generation_at_admit),
            static_cast<unsigned long long>(exit.generation),
            static_cast<int>(r.ok));
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
        opts.label = "camoufox_longop_tombstone";
        opts.reason = "generation_changed_discard";
        opts.owner_subsystem = "camoufox_bridge";
        opts.tool_or_request_id = tool_name.c_str();
        opts.session_or_target = "default";
        opts.generation = exit.generation;
        opts.status_code = 1;
        aida::diagnostics::emit(std::move(opts));
        call_result_t tombstoned;
        tombstoned.ok = false;
        tombstoned.error = "CAMOUFOX-LONGOP-TOMBSTONE: result arrived after bridge generation changed; discarded";
        tombstoned.data = nlohmann::json{{"tombstoned", true}, {"admit_generation", op_admission.generation_at_admit}, {"exit_generation", exit.generation}, {"tool", tool_name}};
        return tombstoned;
    }
    return r;
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, const std::string& session_id)
{
    if (is_default_session_id(session_id))
        return call_tool(tool_name, args, timeout_ms);
    auto session = get_managed_session(session_id, false);
    if (!session)
    {
        call_result_t out;
        out.ok = false;
        out.error = std::string("camoufox session is not running: ") + normalize_session_id(session_id);
        out.data = nlohmann::json{{"error", out.error}, {"session_id", normalize_session_id(session_id)}};
        return out;
    }
    const std::string managed_sid = session->session_id;
    uint64_t managed_admission_generation = 0;
    uint32_t managed_admission_child_pid = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        managed_admission_generation = session->generation;
        managed_admission_child_pid = session->child_pid;
    }
    auto op_identity = build_camoufox_op_identity(tool_name.c_str(), managed_sid, managed_admission_generation, managed_admission_child_pid);
    camoufox_op_admission_t op_admission(op_identity);
    if (!op_admission.admitted())
    {
        call_result_t rejected;
        rejected.ok = false;
        rejected.error = "CAMOUFOX-LONGOP-REJECT: " + op_admission.rejection().reason;
        rejected.data = mcp_standalone::downstream::rejection_json(op_admission.rejection(), op_admission.id());
        diag::log_tagged_fmt("camoufox", "call_tool longop_rejected tool=%s session=%s reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            tool_name.c_str(), managed_sid.c_str(),
            op_admission.rejection().reason.c_str(),
            op_admission.rejection().quota_name.c_str(),
            op_admission.rejection().quota_scope.c_str(),
            op_admission.rejection().observed,
            op_admission.rejection().limit);
        return rejected;
    }
    std::lock_guard<std::recursive_mutex> op_lk(session->operation_mtx);
    nlohmann::json safe_args = args.is_null() ? nlohmann::json::object() : args;
    const std::string requested_page_id = json_string_or(safe_args, "page_id", std::string());
    std::string restore_page_id;
    bool legacy_page_target_selected = false;
    if (!requested_page_id.empty() && !tool_accepts_page_id_directly(tool_name))
    {
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            restore_page_id = session->active_page_id;
        }
        const int select_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json select_args;
        select_args["page_id"] = requested_page_id;
        diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_select session_id=%s tool=%s page_id=%s restore_page_id=%s timeout_ms=%d",
            session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(), select_timeout_ms);
        call_result_t select_result = managed_call_with_deadline(session, "select_page", select_args, select_timeout_ms);
        if (!select_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_select_failed session_id=%s tool=%s page_id=%s err=%s data_shape=%s",
                session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(),
                select_result.error.c_str(), json_shape(select_result.data).c_str());
            return page_target_select_failure(tool_name, session->session_id, requested_page_id, select_result);
        }
        safe_args.erase("page_id");
        legacy_page_target_selected = true;
    }
    call_result_t r = managed_call_with_deadline(session, tool_name, safe_args, timeout_ms);
    if (legacy_page_target_selected && !restore_page_id.empty() && restore_page_id != requested_page_id)
    {
        const int restore_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json restore_args;
        restore_args["page_id"] = restore_page_id;
        call_result_t restore_result = managed_call_with_deadline(session, "select_page", restore_args, restore_timeout_ms);
        if (!restore_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_restore_failed session_id=%s tool=%s requested_page_id=%s restore_page_id=%s err=%s data_shape=%s",
                session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(),
                restore_result.error.c_str(), json_shape(restore_result.data).c_str());
        }
    }
    uint64_t managed_exit_generation = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        managed_exit_generation = session->generation;
    }
    if (op_admission.is_stale(managed_exit_generation))
    {
        diag::log_tagged_fmt("camoufox", "CAMOUFOX-LONGOP-TOMBSTONE tool=%s session=%s admit_generation=%llu exit_generation=%llu ok=%d reason=generation_changed_discard",
            tool_name.c_str(), managed_sid.c_str(),
            static_cast<unsigned long long>(op_admission.generation_at_admit),
            static_cast<unsigned long long>(managed_exit_generation),
            static_cast<int>(r.ok));
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
        opts.label = "camoufox_longop_tombstone";
        opts.reason = "generation_changed_discard";
        opts.owner_subsystem = "camoufox_bridge";
        opts.tool_or_request_id = tool_name.c_str();
        opts.session_or_target = managed_sid.c_str();
        opts.generation = managed_exit_generation;
        opts.status_code = 1;
        aida::diagnostics::emit(std::move(opts));
        call_result_t tombstoned;
        tombstoned.ok = false;
        tombstoned.error = "CAMOUFOX-LONGOP-TOMBSTONE: result arrived after session generation changed; discarded";
        tombstoned.data = nlohmann::json{{"tombstoned", true}, {"admit_generation", op_admission.generation_at_admit}, {"exit_generation", managed_exit_generation}, {"tool", tool_name}, {"session_id", managed_sid}};
        return tombstoned;
    }
    return r;
}

bool launch_browser(const launch_config_t& cfg)
{
    diag::log_tagged_fmt("camoufox", "launch_browser entry headless=%d", static_cast<int>(cfg.headless));
    return start_bridge(cfg);
}

bool close_browser(const char* reason)
{
    diag::log_tagged_fmt("camoufox", "close_browser entry reason=%s caller_pid=%lu caller_tid=%lu",
        safe_reason(reason), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return stop_bridge(reason);
}

call_result_t list_pages(const std::string& session_id)
{
    return call_tool("list_pages", nlohmann::json::object(), 15000, session_id);
}

nlohmann::json new_page_bridge_status_diagnostics(const bridge_status_t& st)
{
    const bridge_health_snapshot_t health = sample_bridge_health(st.child_pid, true);
    nlohmann::json out = {
        {"session_id", st.session_id},
        {"active_session_id", st.active_session_id},
        {"state", bridge_state_name(st.state)},
        {"generation", st.generation},
        {"child_pid", st.child_pid},
        {"child_alive", health.child_alive},
        {"phase", st.phase},
        {"error_type", st.error_type},
        {"error_kind", st.error_kind},
        {"readiness_phase", st.readiness_phase},
        {"last_debug_event", st.last_debug_event},
        {"protocol_schema_viewport", st.protocol_schema_viewport},
        {"attempt_started_ms", st.attempt_started_ms},
        {"attempt_elapsed_ms", st.attempt_elapsed_ms},
        {"last_attempt_elapsed_ms", st.last_attempt_elapsed_ms},
        {"status_age_ms", st.status_age_ms},
        {"browser_open", st.browser_open},
        {"page_verified", st.page_verified},
        {"page_count", st.page_count},
        {"active_page_id", st.active_page_id},
        {"cleanup_pending", st.cleanup_pending},
        {"cleanup_generation", st.cleanup_generation},
        {"cleanup_child_pid", st.cleanup_child_pid},
        {"cleanup_reason", st.cleanup_reason},
        {"child_process_count", health.child_process_count},
        {"browser_process_count", health.browser_process_count},
        {"process_tree", health.process_tree},
        {"last_error", st.last_error}
    };
    if (st.last_launch_diagnostics.is_object())
        out["last_launch_diagnostics"] = st.last_launch_diagnostics;
    if (st.cleanup_diagnostics.is_object())
        out["cleanup_diagnostics"] = st.cleanup_diagnostics;
    return out;
}

bool call_result_reports_new_page_timeout(const call_result_t& r)
{
    std::string evidence = ascii_lower_copy(r.error);
    if (!r.text.empty())
    {
        const size_t n = std::min<size_t>(r.text.size(), 4000);
        evidence += "\n";
        evidence += ascii_lower_copy(r.text.substr(0, n));
    }
    if (r.data.is_object())
    {
        const char* keys[] = {
            "status", "phase", "timeout_phase", "sidecar_timeout_phase", "transport_phase",
            "tool", "last_debug_event_name", "readiness_sub_step", "error"
        };
        for (const char* key : keys)
        {
            const std::string value = json_string_or(r.data, key, std::string());
            if (!value.empty())
            {
                evidence += "\n";
                evidence += ascii_lower_copy(value);
            }
        }
        auto event_it = r.data.find("last_debug_event");
        if (event_it != r.data.end() && event_it->is_object())
        {
            const std::string event_name = json_string_or(*event_it, "event", std::string());
            const std::string event_phase = json_string_or(*event_it, "phase", std::string());
            if (!event_name.empty())
            {
                evidence += "\n";
                evidence += ascii_lower_copy(event_name);
            }
            if (!event_phase.empty())
            {
                evidence += "\n";
                evidence += ascii_lower_copy(event_phase);
            }
        }
    }
    const bool timeout_like = evidence.find("timeout") != std::string::npos ||
                              evidence.find("timed out") != std::string::npos;
    const bool page_like = evidence.find("new_page") != std::string::npos ||
                           evidence.find("page_creation") != std::string::npos ||
                           evidence.find("pending_page") != std::string::npos;
    return timeout_like && page_like;
}

bool call_result_reports_pending_page_stuck(const call_result_t& r)
{
    if (!r.data.is_object())
        return false;
    const int pending_queue_len = json_int_or(r.data, "pending_queue_len", json_int_or(r.data, "queue_len", -1));
    if (pending_queue_len > 0 || json_bool_or(r.data, "pending_page_task", false))
        return true;
    const std::string sidecar_phase = ascii_lower_copy(json_string_or(r.data, "sidecar_timeout_phase", std::string()));
    const std::string timeout_phase = ascii_lower_copy(json_string_or(r.data, "timeout_phase", std::string()));
    const std::string event_name = ascii_lower_copy(json_string_or(r.data, "last_debug_event_name", std::string()));
    if (sidecar_phase.find("page_creation") != std::string::npos || timeout_phase.find("page_creation") != std::string::npos)
        return true;
    if (event_name.find("pending_page_queued") != std::string::npos || event_name.find("new_page_timeout") != std::string::npos)
        return true;
    auto event_it = r.data.find("last_debug_event");
    if (event_it != r.data.end() && event_it->is_object())
    {
        const std::string nested_event = ascii_lower_copy(json_string_or(*event_it, "event", std::string()));
        if (nested_event.find("pending_page_queued") != std::string::npos || nested_event.find("new_page_timeout") != std::string::npos)
            return true;
        const int nested_pending = json_int_or(*event_it, "pending_queue_len", json_int_or(*event_it, "queue_len", -1));
        if (nested_pending > 0 || json_bool_or(*event_it, "pending_page_task", false))
            return true;
    }
    return false;
}

bool new_page_requires_clean_relaunch(const call_result_t& r, const bridge_status_t& status_after)
{
    return !r.ok &&
           status_after.browser_open &&
           status_after.page_count == 0 &&
           call_result_reports_new_page_timeout(r) &&
           call_result_reports_pending_page_stuck(r);
}

void attach_new_page_recovery(call_result_t& r, const nlohmann::json& recovery)
{
    if (!r.data.is_object())
        r.data = nlohmann::json::object();
    r.data["new_page_clean_relaunch"] = recovery;
}

call_result_t new_page(const std::string& session_id, const std::string& page_id, const std::string& url, bool make_active)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    if (!url.empty()) args["url"] = url;
    args["make_active"] = make_active;
    call_result_t r = call_tool("new_page", args, 30000, session_id);
    bool clean_relaunch_attempted = false;
    if (!r.ok && is_default_session_id(session_id))
    {
        const bridge_status_t timeout_status = get_status(session_id);
        if (new_page_requires_clean_relaunch(r, timeout_status))
        {
            clean_relaunch_attempted = true;
            const nlohmann::json original_data = r.data.is_object() ? r.data : nlohmann::json::object();
            nlohmann::json recovery = {
                {"trigger", "browser_open_zero_pages_pending_new_page_timeout"},
                {"session_id", normalize_session_id(session_id)},
                {"requested_page_id", page_id},
                {"requested_url", url},
                {"make_active", make_active},
                {"original_error", r.error},
                {"original_data", original_data},
                {"bridge_before_teardown", new_page_bridge_status_diagnostics(timeout_status)}
            };
            diag::log_tagged_fmt("camoufox", "new_page clean_relaunch_begin session_id=%s page_id=%s browser_open=%d page_count=%u generation=%llu child_pid=%lu err=%s",
                normalize_session_id(session_id).c_str(),
                page_id.c_str(),
                timeout_status.browser_open ? 1 : 0,
                static_cast<unsigned>(timeout_status.page_count),
                static_cast<unsigned long long>(timeout_status.generation),
                static_cast<unsigned long>(timeout_status.child_pid),
                r.error.c_str());
            bool stopped = stop_bridge("new_page_page_creation_timeout_clean_relaunch");
            bool force_cleanup_ok = true;
            if (!stopped)
            {
                force_cleanup_ok = force_cleanup("new_page_page_creation_timeout_clean_relaunch_stop_failed");
                stopped = force_cleanup_ok;
            }
            const bridge_status_t after_stop = get_status(session_id);
            recovery["teardown_ok"] = stopped;
            recovery["force_cleanup_ok"] = force_cleanup_ok;
            recovery["bridge_after_teardown"] = new_page_bridge_status_diagnostics(after_stop);
            bool ready = false;
            if (stopped)
                ready = ensure_ready();
            const bridge_status_t after_ready = get_status(session_id);
            recovery["relaunch_ready"] = ready;
            recovery["bridge_after_relaunch"] = new_page_bridge_status_diagnostics(after_ready);
            if (ready)
            {
                r = call_tool("new_page", args, 30000, session_id);
                recovery["retry_ok"] = r.ok;
                recovery["retry_error"] = r.error;
                recovery["bridge_after_retry"] = new_page_bridge_status_diagnostics(get_status(session_id));
            }
            else
            {
                recovery["retry_ok"] = false;
                recovery["retry_error"] = after_ready.last_error;
            }
            attach_new_page_recovery(r, recovery);
            diag::log_tagged_fmt("camoufox", "new_page clean_relaunch_result session_id=%s page_id=%s stopped=%d ready=%d retry_ok=%d generation=%llu child_pid=%lu err=%s",
                normalize_session_id(session_id).c_str(),
                page_id.c_str(),
                stopped ? 1 : 0,
                ready ? 1 : 0,
                r.ok ? 1 : 0,
                static_cast<unsigned long long>(get_status(session_id).generation),
                static_cast<unsigned long>(get_status(session_id).child_pid),
                r.error.c_str());
        }
    }
    if (!r.ok && !clean_relaunch_attempted && is_default_session_id(session_id) && is_bridge_relaunchable_error(r.error))
    {
        const bridge_status_t before = get_status(session_id);
        const bridge_health_snapshot_t before_health = sample_bridge_health(before.child_pid, true);
        diag::log_tagged_fmt("camoufox", "new_page relaunch_retry_begin session_id=%s page_id=%s make_active=%d generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u err=%s process_tree=%s",
            normalize_session_id(session_id).c_str(),
            page_id.c_str(),
            make_active ? 1 : 0,
            static_cast<unsigned long long>(before.generation),
            static_cast<unsigned long>(before.child_pid),
            before_health.child_alive ? 1 : 0,
            static_cast<unsigned>(before_health.child_process_count),
            static_cast<unsigned>(before_health.browser_process_count),
            r.error.c_str(),
            before_health.process_tree.empty() ? "<empty>" : before_health.process_tree.c_str());
        if (ensure_ready())
        {
            r = call_tool("new_page", args, 30000, session_id);
            const bridge_status_t after = get_status(session_id);
            const bridge_health_snapshot_t after_health = sample_bridge_health(after.child_pid, true);
            diag::log_tagged_fmt("camoufox", "new_page relaunch_retry_result session_id=%s page_id=%s ok=%d generation=%llu child_pid=%lu child_alive=%d child_processes=%u browser_processes=%u err=%s process_tree=%s",
                normalize_session_id(session_id).c_str(),
                page_id.c_str(),
                r.ok ? 1 : 0,
                static_cast<unsigned long long>(after.generation),
                static_cast<unsigned long>(after.child_pid),
                after_health.child_alive ? 1 : 0,
                static_cast<unsigned>(after_health.child_process_count),
                static_cast<unsigned>(after_health.browser_process_count),
                r.error.c_str(),
                after_health.process_tree.empty() ? "<empty>" : after_health.process_tree.c_str());
        }
        else
        {
            const bridge_status_t after = get_status(session_id);
            diag::log_tagged_fmt("camoufox", "new_page relaunch_retry_not_ready session_id=%s page_id=%s generation=%llu child_pid=%lu last_error=%s",
                normalize_session_id(session_id).c_str(),
                page_id.c_str(),
                static_cast<unsigned long long>(after.generation),
                static_cast<unsigned long>(after.child_pid),
                after.last_error.c_str());
        }
    }
    return r;
}

call_result_t select_page(const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    args["page_id"] = page_id;
    return call_tool("select_page", args, 15000, session_id);
}

call_result_t close_page(const std::string& session_id, const std::string& page_id)
{
    lifecycle_guard_t lifecycle;
    if (!lifecycle.acquired)
    {
        call_result_t result;
        result.ok = false;
        result.error = "camoufox lifecycle operation already active";
        return result;
    }
    nlohmann::json args;
    args["page_id"] = page_id;
    return call_tool("close_page", args, 15000, session_id);
}

bool navigate(const std::string& url, const std::string& wait_until, int timeout_ms, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return navigate(url, wait_until, timeout_ms);
    const uint64_t targeted_nav_start_ms = now_ms();
    const bridge_status_t before = get_status(session_id);
    const bridge_health_snapshot_t before_health = sample_bridge_health(before.child_pid, true);
    const url_log_t requested = summarize_url_for_log(url);
    diag::log_tagged_fmt("camoufox", "navigate targeted_entry session_id=%s page_id=%s generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu browser_open=%d page_verified=%d child_processes=%u browser_processes=%u host=%s path=%s timeout_ms=%d caller_pid=%lu caller_tid=%lu process_tree=%s",
        normalize_session_id(session_id).c_str(),
        page_id.c_str(),
        static_cast<unsigned long long>(before.generation),
        static_cast<unsigned long>(before.child_pid),
        before_health.child_alive ? 1 : 0,
        before_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(before_health.exit_code_valid ? before_health.exit_code : 0),
        static_cast<unsigned long>(before_health.exit_query_gle),
        before.browser_open ? 1 : 0,
        before.page_verified ? 1 : 0,
        static_cast<unsigned>(before_health.child_process_count),
        static_cast<unsigned>(before_health.browser_process_count),
        requested.host.c_str(),
        requested.path.c_str(),
        timeout_ms,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        before_health.process_tree.empty() ? "<empty>" : before_health.process_tree.c_str());
    nlohmann::json args;
    args["url"] = url;
    args["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    args["collect_response_chain"] = true;
    args["clear_network_capture"] = true;
    args["include_title"] = false;
    if (!page_id.empty()) args["page_id"] = page_id;
    const int call_timeout = clamp_navigation_call_wait_ms(timeout_ms);
    diag::log_tagged_fmt("camoufox", "navigate targeted phase=before_call_tool session_id=%s page_id=%s host=%s path=%s query=%d wait_until=%s requested_timeout_ms=%d call_timeout_ms=%d generation=%llu child_pid=%lu",
        normalize_session_id(session_id).c_str(),
        page_id.empty() ? "<empty>" : page_id.c_str(),
        requested.host.c_str(),
        requested.path.c_str(),
        requested.has_query ? 1 : 0,
        json_string_or(args, "wait_until", std::string()).c_str(),
        timeout_ms,
        call_timeout,
        static_cast<unsigned long long>(before.generation),
        static_cast<unsigned long>(before.child_pid));
    call_result_t r = call_tool("navigate", args, call_timeout, session_id);
    {
        const int response_status = json_int_or(r.data, "final_status", json_int_or(r.data, "initial_status", json_int_or(r.data, "status", json_int_or(r.data, "response_status", -1))));
        const bool navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false) || json_bool_or(r.data, "timed_out", false);
        const url_log_t response_url = summarize_url_for_log(json_string_or(r.data, "url", json_string_or(r.data, "final_url", json_string_or(r.data, "active_url", std::string()))));
        diag::log_tagged_fmt("camoufox", "navigate targeted phase=after_call_tool session_id=%s page_id=%s ok=%d response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu data_shape=%s error_len=%zu elapsed_ms=%llu",
            normalize_session_id(session_id).c_str(),
            page_id.empty() ? "<empty>" : page_id.c_str(),
            r.ok ? 1 : 0,
            response_status,
            navigation_timed_out ? 1 : 0,
            response_url.host.c_str(),
            response_url.path.c_str(),
            response_url.has_query ? 1 : 0,
            response_url.length,
            json_shape(r.data).c_str(),
            r.error.size(),
            static_cast<unsigned long long>(now_ms() - targeted_nav_start_ms));
    }
    if (!r.ok)
    {
        const bridge_status_t after = get_status(session_id);
        const bridge_health_snapshot_t after_health = sample_bridge_health(after.child_pid, true);
        diag::log_tagged_fmt("camoufox", "navigate targeted_failed session_id=%s page_id=%s generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu browser_open=%d page_verified=%d child_processes=%u browser_processes=%u err=%s data_shape=%s process_tree=%s",
            normalize_session_id(session_id).c_str(), page_id.c_str(),
            static_cast<unsigned long long>(after.generation),
            static_cast<unsigned long>(after.child_pid),
            after_health.child_alive ? 1 : 0,
            after_health.exit_code_valid ? 1 : 0,
            static_cast<unsigned long>(after_health.exit_code_valid ? after_health.exit_code : 0),
            static_cast<unsigned long>(after_health.exit_query_gle),
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            static_cast<unsigned>(after_health.child_process_count),
            static_cast<unsigned>(after_health.browser_process_count),
            r.error.c_str(),
            json_shape(r.data).c_str(),
            after_health.process_tree.empty() ? "<empty>" : after_health.process_tree.c_str());
        return false;
    }
    const bridge_status_t after = get_status(session_id);
    const bridge_health_snapshot_t after_health = sample_bridge_health(after.child_pid, true);
    diag::log_tagged_fmt("camoufox", "navigate targeted_exit session_id=%s page_id=%s generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu browser_open=%d page_verified=%d child_processes=%u browser_processes=%u data_shape=%s process_tree=%s",
        normalize_session_id(session_id).c_str(), page_id.c_str(),
        static_cast<unsigned long long>(after.generation),
        static_cast<unsigned long>(after.child_pid),
        after_health.child_alive ? 1 : 0,
        after_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(after_health.exit_code_valid ? after_health.exit_code : 0),
        static_cast<unsigned long>(after_health.exit_query_gle),
        after.browser_open ? 1 : 0,
        after.page_verified ? 1 : 0,
        static_cast<unsigned>(after_health.child_process_count),
        static_cast<unsigned>(after_health.browser_process_count),
        json_shape(r.data).c_str(),
        after_health.process_tree.empty() ? "<empty>" : after_health.process_tree.c_str());
    return true;
}

bool reload(const std::string& wait_until, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return reload(wait_until);
    nlohmann::json args;
    args["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("reload", args, 35000, session_id).ok;
}

call_result_t evaluate_js(const std::string& expression, bool await_promise, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return evaluate_js(expression, await_promise);
    nlohmann::json args;
    args["expression"] = expression;
    args["await_promise"] = await_promise;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("evaluate_js", args, 60000, session_id);
}

call_result_t get_page_info(const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return get_page_info();
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("get_page_info", args, 15000, session_id);
}

call_result_t get_console_logs(size_t max_records, const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("get_console_logs", args, 15000, session_id);
    if (r.ok)
        r.data = normalize_console_log_data(r.data);
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    return r;
}

call_result_t list_network_requests(size_t max_records, const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("list_network_requests", args, 30000, session_id);
    if (r.ok && r.data.is_object())
    {
        auto it = r.data.find("requests");
        if (it != r.data.end() && it->is_array())
            r.data = *it;
    }
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    return r;
}

bool navigate(const std::string& url, const std::string& wait_until, int timeout_ms)
{
    const uint64_t nav_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t nav_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto nav_identity = build_camoufox_op_identity("navigate", "default", nav_admission_generation, nav_admission_child_pid);
    camoufox_op_admission_t nav_admission(nav_identity);
    if (!nav_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + nav_admission.rejection().reason);
        diag::log_tagged_fmt("camoufox", "navigate longop_rejected session=default reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            nav_admission.rejection().reason.c_str(),
            nav_admission.rejection().quota_name.c_str(),
            nav_admission.rejection().quota_scope.c_str(),
            nav_admission.rejection().observed,
            nav_admission.rejection().limit);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t nav_start_ms = now_ms();
    const url_log_t u = summarize_url_for_log(url);
    diag::log_tagged_fmt("camoufox", "navigate entry host=%s path=%s query=%d fragment=%d url_len=%zu wait_until=%s timeout_ms=%d",
        u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), static_cast<int>(u.has_fragment), u.length, wait_until.c_str(), timeout_ms);
    if (url.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("navigate: url is empty");
        return false;
    }
    if (!ensure_ready())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        if (sg().last_error.empty()) set_error_locked("navigate: camoufox bridge not ready");
        return false;
    }
    uint64_t nav_generation = 0;
    uint32_t nav_child_pid = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        nav_generation = sg().generation;
        nav_child_pid = sg().child_pid;
    }
    const bridge_health_snapshot_t nav_entry_health = sample_bridge_health(nav_child_pid, true);
    diag::log_tagged_fmt("camoufox", "navigate health_entry session_id=default generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u caller_pid=%lu caller_tid=%lu host=%s path=%s query=%d process_tree=%s",
        static_cast<unsigned long long>(nav_generation),
        static_cast<unsigned long>(nav_child_pid),
        nav_entry_health.child_alive ? 1 : 0,
        nav_entry_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(nav_entry_health.exit_code_valid ? nav_entry_health.exit_code : 0),
        static_cast<unsigned long>(nav_entry_health.exit_query_gle),
        static_cast<unsigned>(nav_entry_health.child_process_count),
        static_cast<unsigned>(nav_entry_health.browser_process_count),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        u.host.c_str(),
        u.path.c_str(),
        static_cast<int>(u.has_query),
        nav_entry_health.process_tree.empty() ? "<empty>" : nav_entry_health.process_tree.c_str());
    nlohmann::json a;
    a["url"]                  = url;
    a["wait_until"]           = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    a["collect_response_chain"] = true;
    a["clear_network_capture"]  = true;
    a["include_title"]          = false;
    int call_timeout = clamp_navigation_call_wait_ms(timeout_ms);
    if (timeout_ms > 0 && call_timeout != timeout_ms + 5000)
    {
        diag::log_tagged_fmt("camoufox", "navigate timeout_clamped requested_ms=%d call_timeout_ms=%d generation=%llu child_pid=%lu",
            timeout_ms, call_timeout, static_cast<unsigned long long>(nav_generation),
            static_cast<unsigned long>(nav_child_pid));
    }
    diag::log_tagged_fmt("camoufox", "navigate dispatch generation=%llu child_pid=%lu call_timeout_ms=%d",
        static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid), call_timeout);
    const uint64_t nav_request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "navigate phase=before_call_with_deadline request_id=%llu host=%s path=%s query=%d wait_until=%s requested_timeout_ms=%d call_timeout_ms=%d generation=%llu child_pid=%lu",
        static_cast<unsigned long long>(nav_request_id),
        u.host.c_str(),
        u.path.c_str(),
        u.has_query ? 1 : 0,
        json_string_or(a, "wait_until", std::string()).c_str(),
        timeout_ms,
        call_timeout,
        static_cast<unsigned long long>(nav_generation),
        static_cast<unsigned long>(nav_child_pid));
    call_result_t r = call_with_deadline("navigate", a, call_timeout, nav_request_id);
    {
        const int response_status = json_int_or(r.data, "final_status", json_int_or(r.data, "initial_status", json_int_or(r.data, "status", json_int_or(r.data, "response_status", -1))));
        const bool navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false) || json_bool_or(r.data, "timed_out", false);
        const url_log_t response_url = summarize_url_for_log(json_string_or(r.data, "url", json_string_or(r.data, "final_url", json_string_or(r.data, "active_url", std::string()))));
        diag::log_tagged_fmt("camoufox", "navigate phase=after_call_with_deadline request_id=%llu ok=%d response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu data_shape=%s error_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_request_id),
            r.ok ? 1 : 0,
            response_status,
            navigation_timed_out ? 1 : 0,
            response_url.host.c_str(),
            response_url.path.c_str(),
            response_url.has_query ? 1 : 0,
            response_url.length,
            json_shape(r.data).c_str(),
            r.error.size(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
    }
    if (!r.ok && is_driver_closed_error(r.error))
    {
        diag::log_tagged_fmt("camoufox", "navigate driver_closed_retry host=%s path=%s err=%s",
            u.host.c_str(), u.path.c_str(), r.error.c_str());
        if (ensure_ready())
        {
            {
                std::lock_guard<std::recursive_mutex> lk(sg().mtx);
                nav_generation = sg().generation;
                nav_child_pid = sg().child_pid;
            }
            const uint64_t retry_request_id = next_request_id();
            diag::log_tagged_fmt("camoufox", "navigate phase=before_retry_call_with_deadline request_id=%llu host=%s path=%s query=%d wait_until=%s call_timeout_ms=%d generation=%llu child_pid=%lu",
                static_cast<unsigned long long>(retry_request_id),
                u.host.c_str(),
                u.path.c_str(),
                u.has_query ? 1 : 0,
                json_string_or(a, "wait_until", std::string()).c_str(),
                call_timeout,
                static_cast<unsigned long long>(nav_generation),
                static_cast<unsigned long>(nav_child_pid));
            r = call_with_deadline("navigate", a, call_timeout, retry_request_id);
            const int retry_response_status = json_int_or(r.data, "final_status", json_int_or(r.data, "initial_status", json_int_or(r.data, "status", json_int_or(r.data, "response_status", -1))));
            const bool retry_navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false) || json_bool_or(r.data, "timed_out", false);
            const url_log_t retry_response_url = summarize_url_for_log(json_string_or(r.data, "url", json_string_or(r.data, "final_url", json_string_or(r.data, "active_url", std::string()))));
            diag::log_tagged_fmt("camoufox", "navigate phase=after_retry_call_with_deadline request_id=%llu ok=%d response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu data_shape=%s error_len=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(retry_request_id),
                r.ok ? 1 : 0,
                retry_response_status,
                retry_navigation_timed_out ? 1 : 0,
                retry_response_url.host.c_str(),
                retry_response_url.path.c_str(),
                retry_response_url.has_query ? 1 : 0,
                retry_response_url.length,
                json_shape(r.data).c_str(),
                r.error.size(),
                static_cast<unsigned long long>(now_ms() - nav_start_ms));
        }
    }
    if (!r.ok)
    {
        const bridge_health_snapshot_t fail_health = sample_bridge_health(nav_child_pid, true);
        diag::log_tagged_fmt("camoufox", "navigate failed generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u host=%s path=%s err=%s elapsed_ms=%llu process_tree=%s",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            fail_health.child_alive ? 1 : 0,
            fail_health.exit_code_valid ? 1 : 0,
            static_cast<unsigned long>(fail_health.exit_code_valid ? fail_health.exit_code : 0),
            static_cast<unsigned long>(fail_health.exit_query_gle),
            static_cast<unsigned>(fail_health.child_process_count),
            static_cast<unsigned>(fail_health.browser_process_count),
            u.host.c_str(), u.path.c_str(), r.error.c_str(), static_cast<unsigned long long>(now_ms() - nav_start_ms),
            fail_health.process_tree.empty() ? "<empty>" : fail_health.process_tree.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("navigate failed: ") + r.error);
        sg().last_nav_ms = now_ms() - nav_start_ms;
        return false;
    }
    if (r.data.is_object())
    {
        const std::string response_url = json_string_or(r.data, "url", std::string());
        const std::string response_title = json_string_or(r.data, "title", std::string());
        const int initial_status = json_int_or(r.data, "initial_status", -1);
        const int final_status = json_int_or(r.data, "final_status", -1);
        const bool navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false);
        const std::string title_error = json_string_or(r.data, "title_error", std::string());
        const size_t warning_count = json_array_size_or_zero(r.data, "warnings");
        if (!response_url.empty())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            update_page_cache_from_json_locked(r.data, "navigate_response");
            if (sg().active_page_url.empty()) sg().active_page_url = response_url;
            if (sg().active_page_title.empty()) sg().active_page_title = response_title;
            sg().page_verified = true;
            sg().last_verified_ms = now_ms();
            sg().last_nav_ms = now_ms() - nav_start_ms;
            const url_log_t f = summarize_url_for_log(sg().active_page_url);
            diag::log_tagged_fmt("camoufox", "navigate ok_from_response generation=%llu child_pid=%lu final_host=%s final_path=%s query=%d url_len=%zu title_len=%zu initial_status=%d final_status=%d nav_timeout=%d warnings=%zu title_error_len=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                f.host.c_str(), f.path.c_str(), static_cast<int>(f.has_query), f.length,
                sg().active_page_title.size(), initial_status, final_status,
                navigation_timed_out ? 1 : 0, warning_count, title_error.size(),
                static_cast<unsigned long long>(sg().last_nav_ms));
            call_result_t stability_failure;
            if (!verify_default_navigation_stability(
                    "navigate_response",
                    0,
                    u,
                    nav_generation,
                    nav_child_pid,
                    nav_start_ms,
                    stability_failure,
                    nav_entry_health.process_tree))
            {
                diag::log_tagged_fmt("camoufox", "navigate post_stability_failed generation=%llu child_pid=%lu host=%s path=%s err=%s data_shape=%s elapsed_ms=%llu",
                    static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
                    u.host.c_str(), u.path.c_str(), stability_failure.error.c_str(), json_shape(stability_failure.data).c_str(),
                    static_cast<unsigned long long>(now_ms() - nav_start_ms));
                return false;
            }
            const bridge_health_snapshot_t ok_health = sample_bridge_health(nav_child_pid, true);
            diag::log_tagged_fmt("camoufox", "navigate health_exit session_id=default result=ok_from_response generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u final_host=%s final_path=%s status=%d elapsed_ms=%llu process_tree=%s",
                static_cast<unsigned long long>(nav_generation),
                static_cast<unsigned long>(nav_child_pid),
                ok_health.child_alive ? 1 : 0,
                ok_health.exit_code_valid ? 1 : 0,
                static_cast<unsigned long>(ok_health.exit_code_valid ? ok_health.exit_code : 0),
                static_cast<unsigned long>(ok_health.exit_query_gle),
                static_cast<unsigned>(ok_health.child_process_count),
                static_cast<unsigned>(ok_health.browser_process_count),
                f.host.c_str(),
                f.path.c_str(),
                final_status,
                static_cast<unsigned long long>(now_ms() - nav_start_ms),
                ok_health.process_tree.empty() ? "<empty>" : ok_health.process_tree.c_str());
            return true;
        }
        diag::log_tagged_fmt("camoufox", "navigate response_missing_url generation=%llu child_pid=%lu host=%s path=%s data_shape=%s initial_status=%d final_status=%d nav_timeout=%d warnings=%zu title_error_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), json_shape(r.data).c_str(), initial_status, final_status,
            navigation_timed_out ? 1 : 0, warning_count, title_error.size(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "navigate response_unusable generation=%llu child_pid=%lu host=%s path=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), json_shape(r.data).c_str(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
    }
    call_result_t page = get_page_info();
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("post-navigation page verification did not return URL") : page.error;
        diag::log_tagged_fmt("camoufox", "navigate page_verify_failed generation=%llu child_pid=%lu host=%s path=%s err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), err.c_str(), json_shape(page.data).c_str(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().page_verified = false;
        sg().last_nav_ms = now_ms() - nav_start_ms;
        set_error_locked(std::string("navigate page verification failed: ") + err);
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(page.data, "navigate_verify");
        if (sg().active_page_url.empty()) sg().active_page_url = page.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(page.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        sg().last_nav_ms = now_ms() - nav_start_ms;
        const url_log_t f = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "navigate ok generation=%llu child_pid=%lu final_host=%s final_path=%s query=%d url_len=%zu title_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(sg().child_pid),
            f.host.c_str(), f.path.c_str(), static_cast<int>(f.has_query), f.length,
            sg().active_page_title.size(), static_cast<unsigned long long>(sg().last_nav_ms));
    }
    call_result_t stability_failure;
    if (!verify_default_navigation_stability(
            "navigate_verify",
            0,
            u,
            nav_generation,
            nav_child_pid,
            nav_start_ms,
            stability_failure,
            nav_entry_health.process_tree))
    {
        diag::log_tagged_fmt("camoufox", "navigate post_verify_stability_failed generation=%llu child_pid=%lu host=%s path=%s err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), stability_failure.error.c_str(), json_shape(stability_failure.data).c_str(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
        return false;
    }
    const bridge_health_snapshot_t ok_health = sample_bridge_health(nav_child_pid, true);
    diag::log_tagged_fmt("camoufox", "navigate health_exit session_id=default result=ok_verify generation=%llu child_pid=%lu child_alive=%d exit_valid=%d exit_code=%lu exit_gle=%lu child_processes=%u browser_processes=%u host=%s path=%s elapsed_ms=%llu process_tree=%s",
        static_cast<unsigned long long>(nav_generation),
        static_cast<unsigned long>(nav_child_pid),
        ok_health.child_alive ? 1 : 0,
        ok_health.exit_code_valid ? 1 : 0,
        static_cast<unsigned long>(ok_health.exit_code_valid ? ok_health.exit_code : 0),
        static_cast<unsigned long>(ok_health.exit_query_gle),
        static_cast<unsigned>(ok_health.child_process_count),
        static_cast<unsigned>(ok_health.browser_process_count),
        u.host.c_str(),
        u.path.c_str(),
        static_cast<unsigned long long>(now_ms() - nav_start_ms),
        ok_health.process_tree.empty() ? "<empty>" : ok_health.process_tree.c_str());
    return true;
}

bool reload(const std::string& wait_until)
{
    const uint64_t reload_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t reload_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto reload_identity = build_camoufox_op_identity("reload", "default", reload_admission_generation, reload_admission_child_pid);
    camoufox_op_admission_t reload_admission(reload_identity);
    if (!reload_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + reload_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "reload entry wait_until=%s", wait_until.c_str());
    nlohmann::json a;
    a["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    call_result_t r = call_with_deadline("reload", a, 35000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "reload failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("reload failed: ") + r.error);
        return false;
    }
    call_result_t page = get_page_info();
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("post-reload page verification did not return URL") : page.error;
        diag::log_tagged_fmt("camoufox", "reload page_verify_failed err=%s data_shape=%s",
            err.c_str(), json_shape(page.data).c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().page_verified = false;
        set_error_locked(std::string("reload page verification failed: ") + err);
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(page.data, "reload_verify");
        if (sg().active_page_url.empty()) sg().active_page_url = page.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(page.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "reload ok generation=%llu child_pid=%lu host=%s path=%s query=%d url_len=%zu title_len=%zu",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length, sg().active_page_title.size());
    }
    return true;
}

call_result_t evaluate_js(const std::string& expression, bool await_promise)
{
    const uint64_t eval_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t eval_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto eval_identity = build_camoufox_op_identity("evaluate_js", "default", eval_admission_generation, eval_admission_child_pid);
    camoufox_op_admission_t eval_admission(eval_identity);
    if (!eval_admission.admitted())
    {
        call_result_t rejected;
        rejected.ok = false;
        rejected.error = "CAMOUFOX-LONGOP-REJECT: " + eval_admission.rejection().reason;
        rejected.data = mcp_standalone::downstream::rejection_json(eval_admission.rejection(), eval_admission.id());
        diag::log_tagged_fmt("camoufox", "evaluate_js longop_rejected session=default reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            eval_admission.rejection().reason.c_str(),
            eval_admission.rejection().quota_name.c_str(),
            eval_admission.rejection().quota_scope.c_str(),
            eval_admission.rejection().observed,
            eval_admission.rejection().limit);
        return rejected;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "evaluate_js entry expr_len=%zu await=%d",
        expression.size(), static_cast<int>(await_promise));
    nlohmann::json a;
    a["expression"]    = expression;
    a["await_promise"] = await_promise;
    call_result_t r = call_with_deadline("evaluate_js", a, 60000);
    diag::log_tagged_fmt("camoufox", "evaluate_js result ok=%d", static_cast<int>(r.ok));
    return r;
}

bool add_init_script(const std::string& js)
{
    const uint64_t ais_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t ais_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto ais_identity = build_camoufox_op_identity("add_init_script", "default", ais_admission_generation, ais_admission_child_pid);
    camoufox_op_admission_t ais_admission(ais_identity);
    if (!ais_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + ais_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "add_init_script entry js_len=%zu", js.size());
    if (js.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("add_init_script: script body is empty");
        return false;
    }

    static const char* const kPresetNames[] = {
        "xhr", "fetch", "crypto", "websocket", "debugger_bypass",
        "cookie", "runtime_probe", "xss_sentinel", "alert_capture",
        "eval_capture", "function_capture", "setTimeout_capture",
        "location_capture"
    };
    for (const char* name : kPresetNames)
    {
        if (js == name)
        {
            diag::log_tagged_fmt("camoufox", "add_init_script preset=%s", name);
            nlohmann::json a;
            a["preset"]     = name;
            a["persistent"] = true;
            call_result_t r = call_with_deadline("inject_hook_preset", a, 30000);
            if (!r.ok)
            {
                diag::log_tagged_fmt("camoufox", "add_init_script preset_failed preset=%s err=%s",
                    name, r.error.c_str());
                std::lock_guard<std::recursive_mutex> lk(sg().mtx);
                set_error_locked(std::string("add_init_script (preset) failed: ") + r.error);
                return false;
            }
            diag::log_tagged_fmt("camoufox", "add_init_script preset_ok preset=%s", name);
            return true;
        }
    }

    diag::log_tagged_fmt("camoufox", "add_init_script inline_script js_len=%zu", js.size());
    nlohmann::json a;
    a["script"] = js;
    a["name"] = init_script_name(js);
    call_result_t r = call_with_deadline("add_init_script", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "add_init_script inline_failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("add_init_script failed: ") + r.error);
        return false;
    }
    std::string warning_text;
    if (r.data.is_object() && r.data.contains("warning") && r.data["warning"].is_string())
    {
        warning_text = r.data["warning"].get<std::string>();
    }
    diag::log_tagged_fmt("camoufox", "add_init_script inline_ok data_shape=%s text_len=%zu warning=%s",
        json_shape(r.data).c_str(), r.text.size(), warning_text.c_str());
    return true;
}

call_result_t get_console_logs(size_t max_records)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "get_console_logs entry max_records=%zu", max_records);
    nlohmann::json a;
    if (max_records == 0) max_records = 200;
    call_result_t r = call_with_deadline("get_console_logs", a, 15000);
    if (r.ok)
        r.data = normalize_console_log_data(r.data);
    if (r.ok && r.data.is_array() && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    diag::log_tagged_fmt("camoufox", "get_console_logs result ok=%d count=%zu data_shape=%s",
        static_cast<int>(r.ok), r.data.is_array() ? r.data.size() : static_cast<size_t>(0),
        json_shape(r.data).c_str());
    return r;
}

call_result_t list_network_requests(size_t max_records)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "list_network_requests entry max_records=%zu", max_records);
    nlohmann::json a;
    call_result_t r = call_with_deadline("list_network_requests", a, 30000);
    if (r.ok && r.data.is_object())
    {
        for (const char* key : {"requests", "items", "records", "data", "result"})
        {
            auto it = r.data.find(key);
            if (it != r.data.end() && it->is_array())
            {
                r.data = *it;
                break;
            }
        }
    }
    if (r.ok && (!r.data.is_array() || r.data.empty()))
    {
        static const char* kPerfEntriesJs = R"JS((function(){
var out=[];
try {
var nav=performance.getEntriesByType('navigation') || [];
var res=performance.getEntriesByType('resource') || [];
function push(e, kind) {
out.push({
url: String(e.name || location.href || ''),
entry_type: kind,
initiator_type: String(e.initiatorType || kind),
start_time: Number(e.startTime || 0),
duration: Number(e.duration || 0),
transfer_size: Number(e.transferSize || 0)
});
}
for (var i=0;i<nav.length;i++) push(nav[i], 'navigation');
for (var j=0;j<res.length;j++) push(res[j], 'resource');
} catch(e) {}
return JSON.stringify(out);
})())JS";
        call_result_t fb = evaluate_js(kPerfEntriesJs, true);
        nlohmann::json records = nlohmann::json::array();
        if (fb.ok)
        {
            if (fb.data.is_array())
            {
                records = fb.data;
            }
            else if (fb.data.is_string())
            {
                nlohmann::json parsed;
                parse_text_to_json(fb.data.get<std::string>(), parsed);
                if (parsed.is_array()) records = std::move(parsed);
            }
            else if (fb.data.is_object())
            {
                for (const char* key : {"value", "result", "data"})
                {
                    auto it = fb.data.find(key);
                    if (it == fb.data.end())
                        continue;
                    if (it->is_array())
                    {
                        records = *it;
                        break;
                    }
                    if (it->is_string())
                    {
                        nlohmann::json parsed;
                        parse_text_to_json(it->get<std::string>(), parsed);
                        if (parsed.is_array())
                        {
                            records = std::move(parsed);
                            break;
                        }
                    }
                }
            }
        }
        if (!records.empty())
        {
            diag::log_tagged_fmt("camoufox", "list_network_requests performance_fallback count=%zu", records.size());
            r.data = std::move(records);
        }
        else
        {
            diag::log_tagged_fmt("camoufox", "list_network_requests performance_fallback empty ok=%d err=%s",
                static_cast<int>(fb.ok), fb.error.c_str());
        }
    }
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    diag::log_tagged_fmt("camoufox", "list_network_requests result ok=%d count=%zu",
        static_cast<int>(r.ok), r.data.is_array() ? r.data.size() : static_cast<size_t>(0));
    return r;
}

call_result_t get_page_info()
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "get_page_info entry");
    nlohmann::json a;
    call_result_t r = call_with_deadline("get_page_info", a, 15000);
    if (r.ok && r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(r.data, "get_page_info");
        if (sg().active_page_url.empty()) sg().active_page_url = r.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(r.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        const nlohmann::json bounds = r.data.contains("window_bounds") && r.data["window_bounds"].is_object()
            ? r.data["window_bounds"] : nlohmann::json::object();
        diag::log_tagged_fmt("camoufox", "get_page_info ok generation=%llu child_pid=%lu host=%s path=%s query=%d url_len=%zu title_len=%zu viewport=%dx%d inner=%dx%d outer=%dx%d pos=%d,%d screen=%dx%d avail=%dx%d dpr=%.2f",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length,
            sg().active_page_title.size(),
            json_int_or(r.data, "viewport_width", -1), json_int_or(r.data, "viewport_height", -1),
            json_int_or(bounds, "innerWidth", -1), json_int_or(bounds, "innerHeight", -1),
            json_int_or(bounds, "outerWidth", -1), json_int_or(bounds, "outerHeight", -1),
            json_int_or(bounds, "screenX", -1), json_int_or(bounds, "screenY", -1),
            json_int_or(bounds, "screenWidth", -1), json_int_or(bounds, "screenHeight", -1),
            json_int_or(bounds, "availWidth", -1), json_int_or(bounds, "availHeight", -1),
            json_double_or(bounds, "devicePixelRatio", 0.0));
    }
    else if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "get_page_info failed err=%s data_shape=%s text_len=%zu",
            r.error.c_str(), json_shape(r.data).c_str(), r.text.size());
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "get_page_info missing_url data_shape=%s text_len=%zu",
            json_shape(r.data).c_str(), r.text.size());
    }
    return r;
}

bool take_screenshot(const std::string& output_path, bool full_page)
{
    const uint64_t ss_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t ss_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto ss_identity = build_camoufox_op_identity("take_screenshot", "default", ss_admission_generation, ss_admission_child_pid);
    camoufox_op_admission_t ss_admission(ss_identity);
    if (!ss_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + ss_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "take_screenshot entry path=%s full_page=%d",
        output_path.c_str(), static_cast<int>(full_page));
    if (output_path.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("take_screenshot: output_path is empty");
        return false;
    }
    nlohmann::json a;
    a["full_page"] = full_page;
    call_result_t r = call_with_deadline("take_screenshot", a, 45000);
    if (!r.ok)
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot failed: ") + r.error);
        return false;
    }
    if (!r.data.is_object() || !r.data.contains("screenshot_base64") || !r.data["screenshot_base64"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("take_screenshot: missing screenshot_base64 in response");
        return false;
    }

    const std::string& b64 = r.data["screenshot_base64"].get_ref<const std::string&>();
    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> decoded;
    decoded.reserve((b64.size() / 4) * 3);
    int buf_val = 0;
    int buf_bits = 0;
    for (char c : b64)
    {
        unsigned uc = static_cast<unsigned char>(c);
        int v = decode_table[uc];
        if (v == -2) break;
        if (v < 0) continue;
        buf_val = (buf_val << 6) | v;
        buf_bits += 6;
        if (buf_bits >= 8)
        {
            buf_bits -= 8;
            decoded.push_back(static_cast<uint8_t>((buf_val >> buf_bits) & 0xFF));
        }
    }

    std::wstring wpath = utf8_to_wide(output_path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot: cannot create file ") + output_path);
        return false;
    }
    DWORD written = 0;
    BOOL wrote_ok = WriteFile(h, decoded.data(), static_cast<DWORD>(decoded.size()), &written, nullptr);
    CloseHandle(h);
    if (!wrote_ok || written != decoded.size())
    {
        diag::log_tagged_fmt("camoufox", "take_screenshot write_failed path=%s written=%lu decoded=%zu",
            output_path.c_str(), static_cast<unsigned long>(written), decoded.size());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot: write failed for ") + output_path);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "take_screenshot ok path=%s bytes=%zu", output_path.c_str(), decoded.size());
    return true;
}

bool take_snapshot(std::string& out_text)
{
    const uint64_t snap_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t snap_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto snap_identity = build_camoufox_op_identity("take_snapshot", "default", snap_admission_generation, snap_admission_child_pid);
    camoufox_op_admission_t snap_admission(snap_identity);
    if (!snap_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + snap_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "take_snapshot entry");
    out_text.clear();
    nlohmann::json a;
    call_result_t r = call_with_deadline("take_snapshot", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "take_snapshot failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_snapshot failed: ") + r.error);
        return false;
    }
    if (r.data.is_object() && r.data.contains("snapshot"))
    {
        out_text = r.data["snapshot"].dump(2);
        diag::log_tagged_fmt("camoufox", "take_snapshot ok snapshot_len=%zu", out_text.size());
        return true;
    }
    out_text = r.text;
    diag::log_tagged_fmt("camoufox", "take_snapshot ok text_len=%zu", out_text.size());
    return true;
}

bool click(const std::string& selector)
{
    const uint64_t click_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t click_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto click_identity = build_camoufox_op_identity("click", "default", click_admission_generation, click_admission_child_pid);
    camoufox_op_admission_t click_admission(click_identity);
    if (!click_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + click_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "click entry request_id=%llu selector=%s", static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    call_result_t r = dispatch_dom_click_action(selector, 5000, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "click failed request_id=%llu selector=%s err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "click ok request_id=%llu selector=%s", static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return true;
}

bool type_text(const std::string& selector, const std::string& text)
{
    const uint64_t tt_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t tt_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto tt_identity = build_camoufox_op_identity("type_text", "default", tt_admission_generation, tt_admission_child_pid);
    camoufox_op_admission_t tt_admission(tt_identity);
    if (!tt_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + tt_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "type_text entry request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    call_result_t r = dispatch_dom_type_text_action(selector, text, 5000, 0, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "type_text failed request_id=%llu selector=%s err=%s text_len=%zu",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str(), text.size());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "type_text ok request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    return true;
}

bool wait_for(const std::string& selector, int timeout_ms)
{
    const uint64_t wf_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t wf_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto wf_identity = build_camoufox_op_identity("wait_for", "default", wf_admission_generation, wf_admission_child_pid);
    camoufox_op_admission_t wf_admission(wf_identity);
    if (!wf_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + wf_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "wait_for entry request_id=%llu selector=%s timeout_ms=%d",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), timeout_ms);
    call_result_t r = dispatch_dom_wait_for_selector_action(selector, timeout_ms, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "wait_for failed request_id=%llu selector=%s err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "wait_for ok request_id=%llu selector=%s",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return true;
}

bool take_screenshot(const std::string& output_path, bool full_page, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return take_screenshot(output_path, full_page);
    if (output_path.empty())
        return false;
    nlohmann::json args;
    args["full_page"] = full_page;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("take_screenshot", args, 45000, session_id);
    if (!r.ok || !r.data.is_object() || !r.data.contains("screenshot_base64") || !r.data["screenshot_base64"].is_string())
        return false;
    const std::string b64 = r.data["screenshot_base64"].get<std::string>();
    std::vector<uint8_t> decoded;
    decoded.reserve((b64.size() / 4) * 3);
    int val = 0;
    int bits = -8;
    auto decode_char = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    for (unsigned char c : b64)
    {
        if (c == '=') break;
        int d = decode_char(c);
        if (d < 0) continue;
        val = (val << 6) + d;
        bits += 6;
        if (bits >= 0)
        {
            decoded.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    std::wstring wpath = utf8_to_wide(output_path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, decoded.data(), static_cast<DWORD>(decoded.size()), &written, nullptr);
    CloseHandle(h);
    return ok && static_cast<size_t>(written) == decoded.size();
}

bool take_snapshot(std::string& out_text, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return take_snapshot(out_text);
    out_text.clear();
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("take_snapshot", args, 30000, session_id);
    if (!r.ok)
        return false;
    if (r.data.is_object() && r.data.contains("snapshot"))
        out_text = r.data["snapshot"].dump(2);
    else
        out_text = r.text;
    return true;
}

bool click(const std::string& selector, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return click(selector);
    nlohmann::json args;
    args["selector"] = selector;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("click", args, 30000, session_id).ok;
}

bool type_text(const std::string& selector, const std::string& text, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return type_text(selector, text);
    nlohmann::json args;
    args["selector"] = selector;
    args["text"] = text;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("type_text", args, 30000, session_id).ok;
}

bool wait_for(const std::string& selector, int timeout_ms, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return wait_for(selector, timeout_ms);
    nlohmann::json args;
    args["selector"] = selector;
    args["timeout"] = timeout_ms;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("wait_for", args, timeout_ms > 0 ? timeout_ms + 5000 : 45000, session_id).ok;
}

bool reset_browser_state()
{
    const uint64_t rbs_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t rbs_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto rbs_identity = build_camoufox_op_identity("reset_browser_state", "default", rbs_admission_generation, rbs_admission_child_pid);
    camoufox_op_admission_t rbs_admission(rbs_identity);
    if (!rbs_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + rbs_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "reset_browser_state entry");
    std::string restore_page_id;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        restore_page_id = sg().active_page_id;
    }
    nlohmann::json a;
    a["clear_persistent_hooks"] = true;
    a["clear_network_capture"]  = true;
    a["clear_active_routes"]    = true;
    a["clear_cookies"]          = false;
    a["clear_storage"]          = false;
    a["close_page_prefix"]      = "dom_xss_";
    a["close_empty_contexts"]   = true;
    if (!restore_page_id.empty())
        a["restore_page_id"] = restore_page_id;
    call_result_t r = call_with_deadline("reset_browser_state", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "reset_browser_state failed restore_page_id=%s err=%s data_shape=%s",
            restore_page_id.c_str(), r.error.c_str(), json_shape(r.data).c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("reset_browser_state failed: ") + r.error);
        return false;
    }
    if (r.data.is_object())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(r.data, "reset_browser_state");
    }
    diag::log_tagged_fmt("camoufox", "reset_browser_state ok restore_page_id=%s data_shape=%s text_len=%zu",
        restore_page_id.c_str(), json_shape(r.data).c_str(), r.text.size());
    return true;
}

bool inject_hook_preset(const std::string& preset_name)
{
    const uint64_t ihp_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t ihp_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto ihp_identity = build_camoufox_op_identity("inject_hook_preset", "default", ihp_admission_generation, ihp_admission_child_pid);
    camoufox_op_admission_t ihp_admission(ihp_identity);
    if (!ihp_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + ihp_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "inject_hook_preset entry preset=%s", preset_name.c_str());
    if (preset_name.empty())
    {
        diag::log_tagged_fmt("camoufox", "inject_hook_preset empty_preset");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("inject_hook_preset: preset_name is empty");
        return false;
    }
    nlohmann::json a;
    a["preset"]     = preset_name;
    a["persistent"] = true;
    call_result_t r = call_with_deadline("inject_hook_preset", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "inject_hook_preset failed preset=%s err=%s", preset_name.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("inject_hook_preset failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "inject_hook_preset ok preset=%s", preset_name.c_str());
    return true;
}

bool hook_function(const std::string& target, const std::string& mode)
{
    const uint64_t hf_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t hf_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto hf_identity = build_camoufox_op_identity("hook_function", "default", hf_admission_generation, hf_admission_child_pid);
    camoufox_op_admission_t hf_admission(hf_identity);
    if (!hf_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + hf_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "hook_function entry target=%s mode=%s", target.c_str(), mode.c_str());
    if (target.empty())
    {
        diag::log_tagged_fmt("camoufox", "hook_function empty_target");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("hook_function: target is empty");
        return false;
    }
    nlohmann::json a;
    a["function_path"] = target;
    a["mode"]          = mode.empty() ? std::string("trace") : mode;
    call_result_t r = call_with_deadline("hook_function", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "hook_function failed target=%s err=%s", target.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("hook_function failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "hook_function ok target=%s mode=%s", target.c_str(), mode.empty() ? "trace" : mode.c_str());
    return true;
}

bool remove_hooks()
{
    const uint64_t rh_admission_generation = [&] { std::lock_guard<std::recursive_mutex> lk(sg().mtx); return sg().generation; }();
    const uint32_t rh_admission_child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    auto rh_identity = build_camoufox_op_identity("remove_hooks", "default", rh_admission_generation, rh_admission_child_pid);
    camoufox_op_admission_t rh_admission(rh_identity);
    if (!rh_admission.admitted())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("CAMOUFOX-LONGOP-REJECT: ") + rh_admission.rejection().reason);
        return false;
    }
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "remove_hooks entry");
    nlohmann::json a;
    a["keep_persistent"] = false;
    call_result_t r = call_with_deadline("remove_hooks", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "remove_hooks failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("remove_hooks failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "remove_hooks ok");
    return true;
}

std::string last_error()
{
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "last_error queried busy");
        return "camoufox bridge state is busy";
    }
    std::string e = sg().last_error;
    diag::log_tagged_fmt("camoufox", "last_error queried val=%s", e.c_str());
    return e;
}

nlohmann::json get_downstream_snapshot()
{
    nlohmann::json snapshot = mcp_standalone::downstream::governor_t::instance().snapshot_json();
    nlohmann::json camoufox_kind = nlohmann::json::object();
    if (snapshot.contains("by_kind") && snapshot["by_kind"].is_array())
    {
        for (const auto& entry : snapshot["by_kind"])
        {
            if (entry.is_object() && entry.value("kind", std::string()) == "camoufox_longop")
            {
                camoufox_kind = entry;
                break;
            }
        }
    }
    nlohmann::json out;
    out["producer_kind"] = "camoufox_longop";
    out["kind_snapshot"] = camoufox_kind;
    out["global_active"] = camoufox_kind.value("active", 0);
    out["total_admitted"] = camoufox_kind.value("total_admitted", static_cast<uint64_t>(0));
    out["total_rejected"] = camoufox_kind.value("total_rejected", static_cast<uint64_t>(0));
    out["total_released"] = camoufox_kind.value("total_released", static_cast<uint64_t>(0));
    out["oldest_active_ms"] = camoufox_kind.value("oldest_active_ms", static_cast<uint64_t>(0));
    out["quotas"] = mcp_standalone::downstream::governor_t::instance().quota_json()["camoufox_longop"];
    out["governor_total_active"] = snapshot.value("total_active", 0);
    out["governor_shutdown_pending"] = snapshot.value("shutdown_pending", 0);
    diag::log_tagged_fmt("camoufox", "get_downstream_snapshot active=%zu admitted=%llu rejected=%llu released=%llu",
        static_cast<size_t>(out["global_active"].get<uint64_t>()),
        static_cast<unsigned long long>(out["total_admitted"].get<uint64_t>()),
        static_cast<unsigned long long>(out["total_rejected"].get<uint64_t>()),
        static_cast<unsigned long long>(out["total_released"].get<uint64_t>()));
    return out;
}

}
}
}
