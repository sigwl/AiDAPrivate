#include "camoufox_bridge_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "burp_events.hpp"
#include "../../settings/standalone_compat.hpp"
#include "../../mcp/downstream_producer_governor.hpp"

#ifdef small
#undef small
#endif

#include "../../../helpers/diag_log.hpp"
#include "../../diagnostics/metadata_ring.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <initializer_list>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida {
namespace burp {

namespace {

using mcp_standalone::tool_result_t;
using nlohmann::json;

struct camoufox_mcp_op_admission_t
{
    mcp_standalone::downstream::admission_result_t result;
    mcp_standalone::downstream::producer_identity_t identity;
    bool held = false;

    explicit camoufox_mcp_op_admission_t(
        const char* tool_name,
        const std::string& session_id,
        uint64_t generation,
        uint32_t child_pid)
        : identity({})
    {
        identity.kind = mcp_standalone::downstream::producer_kind_t::camoufox_longop;
        identity.principal_id = "camoufox_mcp";
        identity.session_id = session_id.empty() ? std::string("default") : session_id;
        identity.generation = generation;
        identity.child_pid = child_pid;
        identity.tool_name = tool_name ? std::string(tool_name) : std::string();
        identity.command_label = tool_name ? std::string(tool_name) : std::string();
        const char* diag_id = mcp_standalone::current_call_diag_id();
        const char* req_id = mcp_standalone::current_call_request_id();
        if (diag_id && diag_id[0]) identity.diagnostic_id = diag_id;
        if (req_id && req_id[0]) identity.request_id = req_id;
        identity.deadline_ms = mcp_standalone::current_call_deadline_ms();

        result = mcp_standalone::downstream::governor_t::instance().try_admit(identity);
        held = result.admitted;
        if (held)
        {
            diag::log_tagged_fmt("mcp_burp", "CAMOUFOX-LONGOP-ADMIT tool=%s session=%s generation=%llu child_pid=%lu token=%llu source=mcp_passthrough",
                identity.tool_name.c_str(), identity.session_id.c_str(),
                static_cast<unsigned long long>(identity.generation),
                static_cast<unsigned long>(identity.child_pid),
                static_cast<unsigned long long>(result.admission_token));
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
            opts.label = "camoufox_mcp_admit";
            opts.reason = "mcp_passthrough_start";
            opts.owner_subsystem = "camoufox_bridge_mcp";
            opts.tool_or_request_id = identity.tool_name.c_str();
            opts.session_or_target = identity.session_id.c_str();
            opts.lease_token = result.admission_token;
            opts.generation = identity.generation;
            opts.status_code = 0;
            aida::diagnostics::emit(std::move(opts));
        }
        else
        {
            diag::log_tagged_fmt("mcp_burp", "CAMOUFOX-LONGOP-REJECT tool=%s session=%s generation=%llu child_pid=%lu reason=%s quota=%s scope=%s observed=%zu limit=%zu source=mcp_passthrough",
                identity.tool_name.c_str(), identity.session_id.c_str(),
                static_cast<unsigned long long>(identity.generation),
                static_cast<unsigned long>(identity.child_pid),
                result.reason.c_str(), result.quota_name.c_str(), result.quota_scope.c_str(),
                result.observed, result.limit);
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
            opts.label = "camoufox_mcp_reject";
            opts.reason = "mcp_passthrough_rejected";
            opts.owner_subsystem = "camoufox_bridge_mcp";
            opts.tool_or_request_id = identity.tool_name.c_str();
            opts.session_or_target = identity.session_id.c_str();
            opts.generation = identity.generation;
            opts.status_code = 1;
            aida::diagnostics::emit(std::move(opts));
        }
    }

    ~camoufox_mcp_op_admission_t()
    {
        release("scope_exit");
    }

    camoufox_mcp_op_admission_t(const camoufox_mcp_op_admission_t&) = delete;
    camoufox_mcp_op_admission_t& operator=(const camoufox_mcp_op_admission_t&) = delete;

    void release(const char* reason)
    {
        if (!held) return;
        diag::log_tagged_fmt("mcp_burp", "CAMOUFOX-LONGOP-RELEASE reason=%s tool=%s session=%s token=%llu source=mcp_passthrough",
            reason ? reason : "completed",
            identity.tool_name.c_str(), identity.session_id.c_str(),
            static_cast<unsigned long long>(result.admission_token));
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::camoufox;
        opts.label = "camoufox_mcp_release";
        opts.reason = reason ? reason : "completed";
        opts.owner_subsystem = "camoufox_bridge_mcp";
        opts.tool_or_request_id = identity.tool_name.c_str();
        opts.session_or_target = identity.session_id.c_str();
        opts.lease_token = result.admission_token;
        opts.generation = identity.generation;
        opts.status_code = 0;
        aida::diagnostics::emit(std::move(opts));
        mcp_standalone::downstream::governor_t::instance().release(result.admission_token, reason ? reason : "completed");
        held = false;
    }

    bool admitted() const noexcept { return held; }
    const mcp_standalone::downstream::admission_result_t& rejection() const noexcept { return result; }
    const mcp_standalone::downstream::producer_identity_t& id() const noexcept { return identity; }
};

constexpr uint32_t kMinReadyBrowserProcessCount = 2;

const char* state_label(camoufox::bridge_state_t s)
{
    switch (s)
    {
        case camoufox::bridge_state_t::stopped:  return "stopped";
        case camoufox::bridge_state_t::starting: return "starting";
        case camoufox::bridge_state_t::ready:    return "ready";
        case camoufox::bridge_state_t::error:    return "error";
    }
    return "unknown";
}

bool bridge_process_tree_ready(const camoufox::bridge_status_t& s)
{
    return s.browser_process_count > 0;
}

bool bridge_reduced_process_tree_accepted(const camoufox::bridge_status_t& s)
{
    return s.state == camoufox::bridge_state_t::ready &&
        s.browser_open &&
        s.page_verified &&
        s.privacy_verified &&
        s.child_alive &&
        s.browser_process_count > 0 &&
        s.browser_process_count < kMinReadyBrowserProcessCount &&
        !s.cleanup_pending;
}

json visible_window_proof_from_status(const camoufox::bridge_status_t& s)
{
    if (!s.last_launch_diagnostics.is_object())
        return json::object();
    const auto it = s.last_launch_diagnostics.find("visible_window_proof");
    if (it == s.last_launch_diagnostics.end() || !it->is_object())
        return json::object();
    return *it;
}

int visible_window_count_from_proof(const json& proof)
{
    if (!proof.is_object())
        return -1;
    const char* keys[] = {"visible_window_count", "visible_windows"};
    for (const char* key : keys)
    {
        const auto it = proof.find(key);
        if (it == proof.end())
            continue;
        if (it->is_number_integer() || it->is_number_unsigned())
            return it->get<int>();
        if (it->is_boolean())
            return it->get<bool>() ? 1 : 0;
    }
    return -1;
}

bool bridge_visible_window_ready(const camoufox::bridge_status_t& s)
{
    return visible_window_count_from_proof(visible_window_proof_from_status(s)) > 0;
}

json status_to_json(const camoufox::bridge_status_t& s)
{
    json j;
    const json visible_window_proof = visible_window_proof_from_status(s);
    const int visible_window_count = visible_window_count_from_proof(visible_window_proof);
    j["session_id"]       = s.session_id;
    j["active_session_id"] = s.active_session_id;
    j["state"]            = state_label(s.state);
    j["last_error"]       = s.last_error;
    j["server_command"]   = s.server_command;
    j["child_pid"]        = s.child_pid;
    j["child_process_image_path"] = s.child_process_image_path;
    j["child_process_creation_time_100ns"] = s.child_process_creation_time_100ns;
    j["child_process_identity_gle"] = s.child_process_identity_gle;
    j["child_process_identity_available"] = s.child_process_identity_available;
    j["launched_ms"]      = s.launched_ms;
    j["attempt_started_ms"] = s.attempt_started_ms;
    j["attempt_elapsed_ms"] = s.attempt_elapsed_ms;
    j["last_attempt_elapsed_ms"] = s.last_attempt_elapsed_ms;
    j["status_age_ms"]    = s.status_age_ms;
    j["last_call_ms"]     = s.last_call_ms;
    j["total_calls"]      = s.total_calls;
    j["total_errors"]     = s.total_errors;
    j["phase"]            = s.phase;
    j["error_type"]       = s.error_type;
    j["error_kind"]       = s.error_kind;
    j["readiness_phase"]  = s.readiness_phase;
    j["last_debug_event"] = s.last_debug_event;
    j["protocol_schema_viewport"] = s.protocol_schema_viewport;
    j["browser_open"]     = s.browser_open;
    j["active_page_id"]   = s.active_page_id;
    j["active_page_url"]  = s.active_page_url;
    j["active_page_title"] = s.active_page_title;
    j["page_count"]       = s.page_count;
    j["session_count"]    = s.session_count;
    j["browser_instance_count"] = s.browser_instance_count;
    j["child_process_count"] = s.child_process_count;
    j["browser_process_count"] = s.browser_process_count;
    j["pages"]            = json::array();
    for (const auto& p : s.pages)
    {
        j["pages"].push_back({
            {"page_id", p.page_id},
            {"context_id", p.context_id},
            {"url", p.url},
            {"title", p.title},
            {"guid", p.guid},
            {"active", p.active},
            {"closed", p.closed},
            {"created_ms", p.created_ms},
            {"last_used_ms", p.last_used_ms},
        });
    }
    j["active_profile_dir"] = s.active_profile_dir;
    j["active_profile_generated"] = s.active_profile_generated;
    j["effective_ua_policy"] = s.effective_ua_policy;
    j["ua_override"] = s.ua_override;
    j["ua_override_string"] = s.ua_override_string;
    j["webrtc_blocked"] = s.webrtc_blocked;
    j["privacy_verified"] = s.privacy_verified;
    j["privacy_diagnostics"] = s.privacy_diagnostics.is_object() ? s.privacy_diagnostics : json::object();
    j["last_launch_diagnostics"] = s.last_launch_diagnostics.is_object() ? s.last_launch_diagnostics : json::object();
    j["visible_window_proof"] = visible_window_proof;
    j["visible_window_count"] = visible_window_count;
    j["visible_window_verified"] = visible_window_count > 0;
    j["reduced_process_tree_accepted"] = bridge_reduced_process_tree_accepted(s);
    j["min_ready_browser_process_count"] = kMinReadyBrowserProcessCount;
    j["page_verified"]    = s.page_verified;
    j["child_alive"]      = s.child_alive;
    j["cleanup_pending"]  = s.cleanup_pending;
    j["cleanup_generation"] = s.cleanup_generation;
    j["cleanup_started_ms"] = s.cleanup_started_ms;
    j["cleanup_child_pid"] = s.cleanup_child_pid;
    j["cleanup_reason"] = s.cleanup_reason;
    j["cleanup_diagnostics"] = s.cleanup_diagnostics.is_object() ? s.cleanup_diagnostics : json::object();
    j["generation"]       = s.generation;
    j["last_launch_ms"]   = s.last_launch_ms;
    j["last_nav_ms"]      = s.last_nav_ms;
    j["last_cleanup_ms"]  = s.last_cleanup_ms;
    j["last_verified_ms"] = s.last_verified_ms;
    j["ready"]            = s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.privacy_verified && s.child_alive && bridge_process_tree_ready(s) && bridge_visible_window_ready(s) && !s.cleanup_pending;
    return j;
}

bool bridge_ready(const camoufox::bridge_status_t& s)
{
    return s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.privacy_verified && s.child_alive && bridge_process_tree_ready(s) && bridge_visible_window_ready(s) && !s.cleanup_pending;
}

bool browser_is_loopback_fixture_url(const std::string& url)
{
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const size_t scheme = lower.find("://");
    if (scheme == std::string::npos)
        return false;
    const size_t host_start = scheme + 3;
    if (host_start >= lower.size())
        return false;
    std::string host;
    if (lower[host_start] == '[')
    {
        const size_t host_end = lower.find(']', host_start + 1);
        if (host_end == std::string::npos)
            return false;
        host = lower.substr(host_start, host_end - host_start + 1);
    }
    else
    {
        const size_t host_end = lower.find_first_of("/:?#", host_start);
        host = lower.substr(host_start, host_end == std::string::npos ? std::string::npos : host_end - host_start);
    }
    return host == "localhost" || host == "[::1]" || host == "::1" || host.rfind("127.", 0) == 0;
}

bool json_bool_param(const json& params, const char* name, bool fallback);

bool browser_diagnostic_mode(const json& params)
{
    return json_bool_param(params, "diagnostic", false) ||
        json_bool_param(params, "diagnostics", false) ||
        json_bool_param(params, "include_diagnostics", false);
}

void attach_privacy_status(tool_result_t& out, const camoufox::bridge_status_t& s)
{
    if (!out.data.is_object())
        out.data = json{{"value", out.data}};
    json privacy = json::object();
    privacy["effective_ua_policy"] = s.effective_ua_policy;
    privacy["ua_override"] = s.ua_override;
    privacy["ua_override_string"] = s.ua_override_string;
    privacy["webrtc_blocked"] = s.webrtc_blocked;
    privacy["privacy_verified"] = s.privacy_verified;
    privacy["page_verified"] = s.page_verified;
    privacy["active_profile_generated"] = s.active_profile_generated;
    privacy["browser_instance_count"] = s.browser_instance_count;
    privacy["child_process_count"] = s.child_process_count;
    privacy["browser_process_count"] = s.browser_process_count;
    privacy["reduced_process_tree_accepted"] = bridge_reduced_process_tree_accepted(s);
    privacy["min_ready_browser_process_count"] = kMinReadyBrowserProcessCount;
    privacy["visible_window_proof"] = visible_window_proof_from_status(s);
    privacy["visible_window_count"] = visible_window_count_from_proof(privacy["visible_window_proof"]);
    privacy["visible_window_verified"] = privacy["visible_window_count"].get<int>() > 0;
    privacy["diagnostics"] = s.privacy_diagnostics.is_object() ? s.privacy_diagnostics : json::object();
    out.data["aida_privacy"] = std::move(privacy);
}

std::string json_string_field(const json& obj, const char* key)
{
    if (!obj.is_object())
        return {};
    auto it = obj.find(key);
    if (it != obj.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

int json_int_field(const json& obj, const char* key, int fallback = 0)
{
    if (!obj.is_object())
        return fallback;
    auto it = obj.find(key);
    if (it == obj.end())
        return fallback;
    try
    {
        if (it->is_number_integer())
            return it->get<int>();
        if (it->is_number())
            return static_cast<int>(it->get<double>());
    }
    catch (...) {}
    return fallback;
}

std::string lower_ascii_copy(std::string s);
std::string json_shape(const json& j, size_t max_keys = 12);

bool json_error_mentions_timeout(const json& obj)
{
    const std::string error = lower_ascii_copy(json_string_field(obj, "error"));
    const std::string timeout_status = lower_ascii_copy(json_string_field(obj, "timeout_status"));
    const std::string instrumentation_status = lower_ascii_copy(json_string_field(obj, "instrumentation_status"));
    return error.find("timeout") != std::string::npos ||
        timeout_status.find("timeout") != std::string::npos ||
        instrumentation_status.find("timeout") != std::string::npos;
}

int compare_env_result_count(const json& data)
{
    const int existing = json_int_field(data, "result_property_count", -1);
    if (existing >= 0)
        return existing;
    if (!data.is_object())
        return 0;
    int total = 0;
    const char* keys[] = {"navigator", "screen", "canvas", "webgl", "audio", "timing", "misc", "custom"};
    for (const char* key : keys)
    {
        auto it = data.find(key);
        if (it != data.end() && it->is_object())
            total += static_cast<int>(it->size());
    }
    return total;
}

std::string status_string_for_log(const json& data)
{
    std::string status = json_string_field(data, "status");
    if (status.empty())
        status = json_string_field(data, "instrumentation_status");
    if (status.empty() && data.is_object() && data.contains("error"))
        status = "error";
    if (status.empty())
        status = "ok";
    return status;
}

bool payload_reports_semantic_failure(const json& data, std::string& reason)
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
    const std::string status = lower_ascii_copy(json_string_field(data, "status"));
    if (status == "failed" || status == "error" || status == "timeout" || status == "cancelled")
    {
        reason = std::string("payload_status_") + status;
        return true;
    }
    return false;
}

void preserve_semantic_failure(tool_result_t& out)
{
    std::string reason;
    if (!out.success || !payload_reports_semantic_failure(out.data, reason))
        return;
    out.success = false;
    if (out.text.empty() || out.text == out.data.dump(2))
        out.text = reason.empty() ? std::string("camoufox payload reports semantic failure") : reason;
    if (out.data.is_object())
    {
        out.data["semantic_failure"] = true;
        if (!reason.empty())
            out.data["semantic_failure_reason"] = reason;
    }
}

bool json_has_key(const json& data, const char* key)
{
    return data.is_object() && data.find(key) != data.end();
}

int json_int_param(const json& params, const char* name, int fallback);
bool json_bool_param(const json& params, const char* name, bool fallback);
std::string json_string_param(const json& params, const char* name, const std::string& fallback);

tool_result_t annotate_initiator_contract_result(const json& forwarded, tool_result_t out)
{
    const std::string requested_page_id = json_string_param(forwarded, "page_id", std::string());
    const std::string requested_marker = json_string_param(forwarded, "marker", std::string());
    const bool contract_sensitive = !requested_page_id.empty() || !requested_marker.empty();
    if (!contract_sensitive)
        return out;
    if (!out.data.is_object())
        out.data = json{{"raw_text_len", out.text.size()}};
    const bool has_contract_marker = json_string_field(out.data, "initiator_contract") == "aida_initiator_contract_v2_page_marker";
    const bool has_page_fields = json_has_key(out.data, "request_page_id") && json_has_key(out.data, "resolved_page_id") && json_has_key(out.data, "active_page_id");
    const bool has_marker_fields = json_has_key(out.data, "request_marker") && json_has_key(out.data, "hook_counts_before") && json_has_key(out.data, "hook_counts_after") && json_has_key(out.data, "fetch_initiator_log_count");
    if (has_contract_marker && has_page_fields && has_marker_fields)
        return out;
    out.success = false;
    out.text = "stale camoufox reverse MCP sidecar missing browser_network.initiator page_id/marker contract";
    out.data["success"] = false;
    out.data["status"] = "failed";
    out.data["error"] = "stale_camoufox_reverse_mcp_initiator_contract";
    out.data["initiator_contract_required"] = "aida_initiator_contract_v2_page_marker";
    out.data["requested_page_id"] = requested_page_id;
    out.data["requested_marker"] = requested_marker;
    out.data["has_contract_marker"] = has_contract_marker;
    out.data["has_page_fields"] = has_page_fields;
    out.data["has_marker_fields"] = has_marker_fields;
    out.data["data_shape"] = json_shape(out.data);
    diag::log_tagged_fmt("mcp_burp", "browser_network_initiator stale_contract request_id=%d page_id=%s marker_len=%zu has_contract=%d has_page_fields=%d has_marker_fields=%d data_shape=%s text_len=%zu",
        json_int_param(forwarded, "request_id", -1),
        requested_page_id.c_str(),
        requested_marker.size(),
        has_contract_marker ? 1 : 0,
        has_page_fields ? 1 : 0,
        has_marker_fields ? 1 : 0,
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

void annotate_instrumentation_response(const std::string& tool_name, tool_result_t& out, int timeout_ms, long long elapsed_ms)
{
    if (!out.data.is_object())
        out.data = json{{"value", out.data}};
    out.data["bridge_rpc_timeout_ms"] = timeout_ms;
    out.data["bridge_rpc_elapsed_ms"] = elapsed_ms;
    if (tool_name == "compare_env")
    {
        out.data["result_property_count"] = compare_env_result_count(out.data);
        if (json_error_mentions_timeout(out.data))
        {
            if (json_string_field(out.data, "status").empty())
                out.data["status"] = "degraded";
            out.data["instrumentation_status"] = "timeout";
            out.data["timeout_status"] = "controlled_timeout";
        }
        else if (json_string_field(out.data, "instrumentation_status").empty())
        {
            out.data["instrumentation_status"] = "complete";
        }
    }
    else if (tool_name == "check_environment")
    {
        if (json_error_mentions_timeout(out.data))
        {
            if (json_string_field(out.data, "status").empty())
                out.data["status"] = "degraded";
            out.data["instrumentation_status"] = "timeout";
            out.data["timeout_status"] = "controlled_timeout";
        }
        else if (json_string_field(out.data, "instrumentation_status").empty())
        {
            out.data["instrumentation_status"] = json_string_field(out.data, "status").empty() ? "complete" : json_string_field(out.data, "status");
        }
    }
    else if (tool_name == "hook_jsvmp_interpreter")
    {
        if (json_string_field(out.data, "instrumentation_status").empty())
            out.data["instrumentation_status"] = json_string_field(out.data, "status").empty() ? "unknown" : json_string_field(out.data, "status");
    }
    else if (tool_name == "trace_property_access")
    {
        if (json_string_field(out.data, "instrumentation_status").empty())
            out.data["instrumentation_status"] = json_string_field(out.data, "status") == "js_fallback" ? "js_fallback" : "complete";
        if (json_string_field(out.data, "fallback_evidence").empty() && json_string_field(out.data, "fallback_trace_file").empty())
            out.data["fallback_evidence"] = out.data.contains("events") || out.data.contains("by_property") ? "returned_payload" : "none";
    }
}

camoufox::bridge_status_t wait_for_ready_status(int timeout_ms)
{
    if (timeout_ms < 0)
        timeout_ms = 0;
    const auto start = std::chrono::steady_clock::now();
    camoufox::bridge_status_t s = camoufox::get_status();
    while (!bridge_ready(s))
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout_ms)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        s = camoufox::get_status();
    }
    return s;
}

const char* json_type_name(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const json& j, size_t max_keys)
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


int json_int_param(const json& params, const char* name, int fallback)
{
    if (!params.is_object() || !params.contains(name))
        return fallback;
    const json& v = params[name];
    try
    {
        if (v.is_number_integer())
            return v.get<int>();
        if (v.is_number())
            return static_cast<int>(v.get<double>());
    }
    catch (...) {}
    return fallback;
}

bool json_bool_param(const json& params, const char* name, bool fallback)
{
    if (!params.is_object() || !params.contains(name) || !params[name].is_boolean())
        return fallback;
    return params[name].get<bool>();
}

bool json_bool_param_present(const json& params, const char* name)
{
    return params.is_object() && params.contains(name) && params[name].is_boolean();
}

std::string json_string_param(const json& params, const char* name, const std::string& fallback = std::string())
{
    if (!params.is_object() || !params.contains(name) || !params[name].is_string())
        return fallback;
    return params[name].get<std::string>();
}

std::string lower_ascii_copy(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::wstring utf8_to_wide_local(const std::string& s)
{
    if (s.empty())
        return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0)
        return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

bool decode_base64_string(const std::string& b64, std::vector<unsigned char>& decoded)
{
    static const signed char table[256] = {
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
    decoded.clear();
    decoded.reserve((b64.size() / 4) * 3);
    int value = 0;
    int bits = 0;
    bool saw_data = false;
    for (char c : b64)
    {
        const unsigned char uc = static_cast<unsigned char>(c);
        const int v = table[uc];
        if (v == -2)
            break;
        if (v < 0)
            continue;
        saw_data = true;
        value = (value << 6) | v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            decoded.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
        }
    }
    return saw_data && !decoded.empty();
}

uint32_t read_be_u32(const std::vector<unsigned char>& bytes, size_t offset)
{
    if (bytes.size() < offset + 4)
        return 0;
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

json png_dimensions(const std::vector<unsigned char>& bytes)
{
    static const unsigned char sig[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    json out = json::object();
    if (bytes.size() < 24 || !std::equal(sig, sig + 8, bytes.begin()))
        return out;
    out["width"] = read_be_u32(bytes, 16);
    out["height"] = read_be_u32(bytes, 20);
    return out;
}

uint64_t epoch_now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::atomic<uint64_t>& browser_exchange_ids()
{
    static std::atomic<uint64_t> ids{5000000000ULL};
    return ids;
}

struct browser_url_t
{
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;
    std::string query;
};

struct burp_publish_summary_t
{
    size_t candidates = 0;
    size_t published = 0;
    size_t skipped = 0;
    size_t duplicates = 0;
    std::string source = "browser";
    bool publish_enabled = true;
    bool fallback_used = false;
    std::vector<uint64_t> exchange_ids;

    json to_json() const
    {
        json out;
        out["published"] = static_cast<uint64_t>(published);
        out["candidates"] = static_cast<uint64_t>(candidates);
        out["skipped"] = static_cast<uint64_t>(skipped);
        out["duplicates"] = static_cast<uint64_t>(duplicates);
        out["source"] = source;
        out["publish_enabled"] = publish_enabled;
        out["fallback_used"] = fallback_used;
        out["exchange_ids"] = json::array();
        for (uint64_t id : exchange_ids)
            out["exchange_ids"].push_back(id);
        return out;
    }
};

std::string json_string_from_any(const json& v)
{
    try
    {
        if (v.is_string())
            return v.get<std::string>();
        if (v.is_number_integer())
            return std::to_string(v.get<int64_t>());
        if (v.is_number_unsigned())
            return std::to_string(v.get<uint64_t>());
        if (v.is_number_float())
        {
            std::ostringstream oss;
            oss << v.get<double>();
            return oss.str();
        }
        if (v.is_boolean())
            return v.get<bool>() ? "true" : "false";
    }
    catch (...) {}
    return {};
}

std::string json_first_string_field(const json& obj, std::initializer_list<const char*> keys)
{
    if (!obj.is_object())
        return {};
    for (const char* key : keys)
    {
        auto it = obj.find(key);
        if (it != obj.end())
        {
            std::string value = json_string_from_any(*it);
            if (!value.empty())
                return value;
        }
    }
    return {};
}

int json_first_int_field(const json& obj, std::initializer_list<const char*> keys, int fallback = 0)
{
    if (!obj.is_object())
        return fallback;
    for (const char* key : keys)
    {
        auto it = obj.find(key);
        if (it == obj.end())
            continue;
        try
        {
            if (it->is_number_integer())
                return it->get<int>();
            if (it->is_number_unsigned())
                return static_cast<int>((std::min<uint64_t>)(it->get<uint64_t>(), static_cast<uint64_t>(INT_MAX)));
            if (it->is_number_float())
                return static_cast<int>(it->get<double>());
            if (it->is_string())
                return std::stoi(it->get<std::string>());
        }
        catch (...) {}
    }
    return fallback;
}

uint64_t json_first_u64_field(const json& obj, std::initializer_list<const char*> keys, uint64_t fallback = 0)
{
    if (!obj.is_object())
        return fallback;
    for (const char* key : keys)
    {
        auto it = obj.find(key);
        if (it == obj.end())
            continue;
        try
        {
            if (it->is_number_unsigned())
                return it->get<uint64_t>();
            if (it->is_number_integer())
            {
                const int64_t v = it->get<int64_t>();
                if (v >= 0)
                    return static_cast<uint64_t>(v);
            }
            if (it->is_number_float())
            {
                const double v = it->get<double>();
                if (v >= 0.0)
                    return static_cast<uint64_t>(v);
            }
            if (it->is_string())
                return static_cast<uint64_t>(std::stoull(it->get<std::string>()));
        }
        catch (...) {}
    }
    return fallback;
}

std::string uppercase_ascii_copy(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

bool parse_browser_url(const std::string& url, browser_url_t& out)
{
    out = browser_url_t{};
    if (url.empty())
        return false;
    if (std::any_of(url.begin(), url.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; }))
        return false;
    size_t scheme_pos = url.find("://");
    size_t authority_start = 0;
    if (scheme_pos != std::string::npos)
    {
        out.scheme = lower_ascii_copy(url.substr(0, scheme_pos));
        authority_start = scheme_pos + 3;
    }
    else
    {
        out.scheme = "http";
    }
    size_t authority_end = url.find_first_of("/?#", authority_start);
    if (authority_end == std::string::npos)
        authority_end = url.size();
    std::string authority = url.substr(authority_start, authority_end - authority_start);
    if (authority.empty() || authority.find(' ') != std::string::npos)
        return false;
    if (!authority.empty() && authority.front() == '[')
    {
        size_t close = authority.find(']');
        if (close == std::string::npos)
            return false;
        out.host = authority.substr(0, close + 1);
        if (close + 1 < authority.size() && authority[close + 1] == ':')
        {
            try
            {
                const std::string port_text = authority.substr(close + 2);
                size_t consumed = 0;
                const unsigned long parsed = std::stoul(port_text, &consumed, 10);
                if (consumed != port_text.size() || parsed == 0 || parsed > 65535)
                    return false;
                out.port = static_cast<uint16_t>(parsed);
            }
            catch (...) { return false; }
        }
    }
    else
    {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon)
        {
            out.host = authority.substr(0, colon);
            try
            {
                const std::string port_text = authority.substr(colon + 1);
                size_t consumed = 0;
                const unsigned long parsed = std::stoul(port_text, &consumed, 10);
                if (consumed != port_text.size() || parsed == 0 || parsed > 65535)
                    return false;
                out.port = static_cast<uint16_t>(parsed);
            }
            catch (...) { return false; }
        }
        else
        {
            out.host = authority;
        }
    }
    if (out.host.empty())
        return false;
    if (out.port == 0)
        out.port = out.scheme == "https" ? 443 : 80;
    size_t path_start = url.find('/', authority_start);
    size_t query_start = url.find('?', authority_start);
    size_t fragment_start = url.find('#', authority_start);
    size_t path_end = url.size();
    if (query_start != std::string::npos)
        path_end = query_start;
    if (fragment_start != std::string::npos && fragment_start < path_end)
        path_end = fragment_start;
    if (path_start != std::string::npos && path_start < path_end)
        out.path = url.substr(path_start, path_end - path_start);
    if (out.path.empty())
        out.path = "/";
    if (query_start != std::string::npos)
    {
        size_t query_end = fragment_start == std::string::npos ? url.size() : fragment_start;
        if (query_end > query_start + 1)
            out.query = url.substr(query_start + 1, query_end - query_start - 1);
    }
    return out.scheme == "http" || out.scheme == "https" || out.scheme == "ws" || out.scheme == "wss";
}

void append_header_pair(std::vector<std::pair<std::string, std::string>>& headers, const std::string& name, const std::string& value)
{
    if (name.empty())
        return;
    headers.emplace_back(name, value);
}

void append_header_pairs_from_json(const json& value, std::vector<std::pair<std::string, std::string>>& headers)
{
    if (value.is_object())
    {
        for (auto it = value.begin(); it != value.end(); ++it)
            append_header_pair(headers, it.key(), json_string_from_any(it.value()));
        return;
    }
    if (value.is_array())
    {
        for (const json& entry : value)
        {
            if (entry.is_object())
            {
                std::string name = json_first_string_field(entry, {"name", "key", "header", "field"});
                std::string val = json_first_string_field(entry, {"value", "val", "content"});
                append_header_pair(headers, name, val);
            }
            else if (entry.is_array() && entry.size() >= 2)
            {
                append_header_pair(headers, json_string_from_any(entry[0]), json_string_from_any(entry[1]));
            }
            else if (entry.is_string())
            {
                std::string line = entry.get<std::string>();
                size_t colon = line.find(':');
                if (colon != std::string::npos)
                {
                    size_t value_start = colon + 1;
                    while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t'))
                        ++value_start;
                    append_header_pair(headers, line.substr(0, colon), line.substr(value_start));
                }
            }
        }
        return;
    }
    if (value.is_string())
    {
        std::string block = value.get<std::string>();
        size_t pos = 0;
        while (pos < block.size())
        {
            size_t end = block.find('\n', pos);
            std::string line = block.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            size_t colon = line.find(':');
            if (colon != std::string::npos)
            {
                size_t value_start = colon + 1;
                while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t'))
                    ++value_start;
                append_header_pair(headers, line.substr(0, colon), line.substr(value_start));
            }
            if (end == std::string::npos)
                break;
            pos = end + 1;
        }
    }
}

void append_headers_from_keys(const json& obj, std::initializer_list<const char*> keys, std::vector<std::pair<std::string, std::string>>& headers)
{
    if (!obj.is_object())
        return;
    for (const char* key : keys)
    {
        auto it = obj.find(key);
        if (it != obj.end())
            append_header_pairs_from_json(*it, headers);
    }
}

void assign_body_from_keys(const json& obj, std::initializer_list<const char*> keys, std::vector<uint8_t>& body)
{
    if (!obj.is_object())
        return;
    for (const char* key : keys)
    {
        auto it = obj.find(key);
        if (it == obj.end())
            continue;
        std::string value = json_string_from_any(*it);
        if (!value.empty())
        {
            body.assign(value.begin(), value.end());
            return;
        }
    }
}

void add_candidates_from_array_key(const json& data, const char* key, std::vector<json>& out)
{
    if (!data.is_object())
        return;
    auto it = data.find(key);
    if (it == data.end() || !it->is_array())
        return;
    for (const json& entry : *it)
        out.push_back(entry);
}

std::vector<json> collect_browser_exchange_candidates(const std::string& tool_name, const json& data)
{
    std::vector<json> out;
    if (tool_name == "navigate")
    {
        add_candidates_from_array_key(data, "response_chain", out);
        add_candidates_from_array_key(data, "responses", out);
        add_candidates_from_array_key(data, "chain", out);
        if (data.is_object())
        {
            auto capture_it = data.find("network_capture");
            if (capture_it != data.end() && capture_it->is_object())
            {
                for (const char* key : {"requests", "items", "records", "network_requests", "entries", "data", "result"})
                    add_candidates_from_array_key(*capture_it, key, out);
            }
        }
        if (data.is_object())
            out.push_back(data);
        return out;
    }
    if (data.is_array())
    {
        for (const json& entry : data)
            out.push_back(entry);
        return out;
    }
    if (data.is_object())
    {
        for (const char* key : {"requests", "items", "records", "network_requests", "entries", "data", "result"})
            add_candidates_from_array_key(data, key, out);
        if (tool_name == "get_network_request")
            out.push_back(data);
    }
    return out;
}

size_t browser_exchange_candidate_count(const std::string& tool_name, const json& data)
{
    return collect_browser_exchange_candidates(tool_name, data).size();
}

std::string browser_record_url(const json& record, const json& params);

int bounded_browser_list_limit(const json& params)
{
    int limit = json_int_param(params, "limit", json_int_param(params, "max_records", 200));
    if (limit <= 0)
        limit = 200;
    if (limit > 500)
        limit = 500;
    return limit;
}

int bounded_browser_list_offset(const json& params)
{
    int offset = json_int_param(params, "offset", 0);
    return offset < 0 ? 0 : offset;
}

bool string_starts_with_ascii(const std::string& value, const std::string& prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool browser_network_record_matches_params(const json& record, const json& params)
{
    const std::string url = browser_record_url(record, params);
    const std::string url_filter = json_string_param(params, "url_filter", std::string());
    const std::string url_prefix = json_string_param(params, "url_prefix", std::string());
    const std::string url_contains_domain = json_string_param(params, "url_contains_domain", std::string());
    if (!url_filter.empty() && url.find(url_filter) == std::string::npos)
        return false;
    if (!url_prefix.empty() && !string_starts_with_ascii(url, url_prefix))
        return false;
    if (!url_contains_domain.empty() && url.find(url_contains_domain) == std::string::npos)
        return false;
    const std::string method = uppercase_ascii_copy(json_string_param(params, "method", std::string()));
    if (!method.empty() && uppercase_ascii_copy(json_first_string_field(record, {"method", "request_method"})) != method)
        return false;
    const std::string resource_type = json_string_param(params, "resource_type", std::string());
    if (!resource_type.empty() && json_first_string_field(record, {"resource_type", "type"}) != resource_type)
        return false;
    const int status_code = json_int_param(params, "status_code", -1);
    if (status_code >= 0 && json_first_int_field(record, {"status", "status_code", "response_status"}, -1) != status_code)
        return false;
    return true;
}

json compact_browser_network_record(json record, bool include_headers, bool include_body)
{
    if (!record.is_object())
        return record;
    if (!include_headers)
    {
        record.erase("request_headers");
        record.erase("response_headers");
        record.erase("headers");
        record.erase("requestHeaders");
        record.erase("responseHeaders");
    }
    if (!include_body)
    {
        record.erase("request_body");
        record.erase("requestBody");
        record.erase("post_data");
        record.erase("postData");
        record.erase("response_body");
        record.erase("responseBody");
        record.erase("body_text");
        record.erase("bodyText");
        record.erase("response_text");
    }
    return record;
}

void normalize_browser_network_list_response(tool_result_t& out, const json& params)
{
    if (!out.success || out.data.is_null())
        return;
    const int limit = bounded_browser_list_limit(params);
    const int requested_offset = bounded_browser_list_offset(params);
    const bool upstream_paged = out.data.is_object() &&
        (out.data.contains("returned_count") || out.data.contains("filtered_count") || out.data.contains("has_more"));
    const int effective_offset = upstream_paged ? 0 : requested_offset;
    const bool include_headers = json_bool_param(params, "include_headers", false);
    const bool include_body = json_bool_param(params, "include_body", false);
    std::vector<json> candidates = collect_browser_exchange_candidates("list_network_requests", out.data);
    std::vector<json> filtered;
    filtered.reserve(candidates.size());
    for (const json& candidate : candidates)
    {
        if (browser_network_record_matches_params(candidate, params))
            filtered.push_back(compact_browser_network_record(candidate, include_headers, include_body));
    }
    const size_t total = filtered.size();
    const size_t start = (std::min)(static_cast<size_t>(effective_offset), total);
    const size_t end = (std::min)(start + static_cast<size_t>(limit), total);
    json requests = json::array();
    for (size_t i = start; i < end; ++i)
        requests.push_back(std::move(filtered[i]));
    if (!out.data.is_object())
        out.data = json::object();
    const uint64_t source_total_count = upstream_paged ? json_first_u64_field(out.data, {"total_count"}, static_cast<uint64_t>(total)) : static_cast<uint64_t>(total);
    const uint64_t filtered_count = upstream_paged ? json_first_u64_field(out.data, {"filtered_count"}, source_total_count) : static_cast<uint64_t>(total);
    const int reported_offset = upstream_paged ? json_int_param(out.data, "offset", requested_offset) : requested_offset;
    const int reported_limit = upstream_paged ? json_int_param(out.data, "limit", limit) : limit;
    const bool upstream_has_more = upstream_paged && json_bool_param(out.data, "has_more", false);
    out.data["status"] = json_string_field(out.data, "status").empty() ? "ok" : json_string_field(out.data, "status");
    out.data["requests"] = std::move(requests);
    out.data["count"] = static_cast<uint64_t>(out.data["requests"].size());
    out.data["returned_count"] = static_cast<uint64_t>(out.data["requests"].size());
    out.data["filtered_count"] = filtered_count;
    out.data["total_count"] = source_total_count;
    out.data["offset"] = reported_offset;
    out.data["limit"] = reported_limit;
    out.data["has_more"] = upstream_has_more || end < total;
    out.data["truncated"] = upstream_has_more || end < total;
    out.data["include_headers"] = include_headers;
    out.data["include_body"] = include_body;
    out.text = out.data.dump(2);
}

std::string browser_record_url(const json& record, const json& params)
{
    std::string url = json_first_string_field(record, {"url", "request_url", "final_url", "target_url", "name"});
    if (url.empty())
        url = json_first_string_field(params, {"url", "request_url", "target_url"});
    return url;
}

bool browser_record_to_exchange(const json& record, const json& params, const std::string& source, exchange_observed_t& ex)
{
    const std::string url = browser_record_url(record, params);
    browser_url_t parsed;
    if (!parse_browser_url(url, parsed))
        return false;
    ex = exchange_observed_t{};
    ex.id = browser_exchange_ids().fetch_add(1, std::memory_order_relaxed);
    ex.timestamp_ms = json_first_u64_field(record, {"timestamp_ms", "ts", "time_ms", "started_ms", "created_ms"}, 0);
    if (ex.timestamp_ms == 0)
        ex.timestamp_ms = epoch_now_ms();
    ex.method = uppercase_ascii_copy(json_first_string_field(record, {"method", "request_method"}));
    if (ex.method.empty())
        ex.method = uppercase_ascii_copy(json_first_string_field(params, {"method"}));
    if (ex.method.empty())
        ex.method = "GET";
    ex.scheme = parsed.scheme == "wss" ? "https" : (parsed.scheme == "ws" ? "http" : parsed.scheme);
    ex.host = parsed.host;
    ex.port = parsed.port;
    ex.path = parsed.path;
    ex.query = parsed.query;
    ex.status_code = json_first_int_field(record, {"status", "status_code", "response_status", "final_status", "initial_status"}, 0);
    ex.reason_phrase = json_first_string_field(record, {"status_text", "statusText", "reason", "reason_phrase"});
    append_headers_from_keys(record, {"request_headers", "requestHeaders", "headers"}, ex.req_headers);
    append_headers_from_keys(record, {"response_headers", "responseHeaders", "headers_response"}, ex.resp_headers);
    assign_body_from_keys(record, {"request_body", "requestBody", "post_data", "postData"}, ex.req_body);
    assign_body_from_keys(record, {"response_body", "responseBody", "body_text", "bodyText", "response_text"}, ex.resp_body);
    ex.latency_ms = json_first_u64_field(record, {"latency_ms", "duration_ms", "elapsed_ms"}, 0);
    if (ex.latency_ms == 0)
        ex.latency_ms = json_first_u64_field(record, {"duration"}, 0);
    ex.is_websocket = parsed.scheme == "ws" || parsed.scheme == "wss" || lower_ascii_copy(json_first_string_field(record, {"resource_type", "type"})) == "websocket";
    ex.alpn = json_first_string_field(record, {"alpn"});
    ex.tls_version = json_first_string_field(record, {"tls_version", "tls"});
    ex.source = source.empty() ? "browser" : source;
    return !ex.host.empty();
}

bool browser_record_has_body_payload(const json& record)
{
    if (!record.is_object())
        return false;
    for (const char* key : {"request_body", "requestBody", "post_data", "postData", "response_body", "responseBody", "body_text", "bodyText", "response_text"})
    {
        auto it = record.find(key);
        if (it != record.end() && it->is_string() && !it->get<std::string>().empty())
            return true;
    }
    return false;
}

bool browser_record_body_hydration_wanted(const json& record, const json& params)
{
    if (browser_record_has_body_payload(record))
        return false;
    if (json_bool_param_present(params, "include_body"))
        return json_bool_param(params, "include_body", false);
    if (json_bool_param_present(params, "capture_body"))
        return json_bool_param(params, "capture_body", false);
    if (json_bool_param(params, "publish_to_burp", true))
        return true;
    if (json_bool_param(record, "response_body_available", false))
        return true;
    return json_first_u64_field(record, {"response_body_length", "body_length", "size", "request_body_length"}, 0) > 0;
}

json hydrate_browser_exchange_candidate(const json& record, const json& params, const std::string& session_id)
{
    if (!record.is_object() || !browser_record_body_hydration_wanted(record, params))
        return record;
    const uint64_t request_id = json_first_u64_field(record, {"request_id", "id", "network_request_id"}, 0);
    if (request_id == 0)
        return record;
    json args = json::object();
    args["request_id"] = request_id;
    args["include_body"] = true;
    args["include_headers"] = true;
    args["max_body_size"] = json_int_param(params, "max_body_size", -1);
    const std::string page_id = json_first_string_field(record, {"page_id", "request_page_id"});
    const std::string marker = json_string_param(params, "marker", std::string());
    if (!page_id.empty())
        args["page_id"] = page_id;
    if (!marker.empty())
        args["marker"] = marker;
    camoufox::call_result_t detail = camoufox::call_tool("get_network_request", args, 15000, session_id);
    if (!detail.ok || !detail.data.is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "browser_burp_body_hydrate_failed request_id=%llu ok=%d err=%s shape=%s",
            static_cast<unsigned long long>(request_id), detail.ok ? 1 : 0, detail.error.c_str(), json_shape(detail.data).c_str());
        return record;
    }
    json merged = record;
    for (auto it = detail.data.begin(); it != detail.data.end(); ++it)
        merged[it.key()] = it.value();
    diag::log_tagged_fmt("mcp_burp", "browser_burp_body_hydrate_ok request_id=%llu response_body_len=%zu request_body_len=%zu",
        static_cast<unsigned long long>(request_id),
        json_first_string_field(merged, {"response_body", "responseBody", "body_text", "bodyText", "response_text"}).size(),
        json_first_string_field(merged, {"request_body", "requestBody", "post_data", "postData"}).size());
    return merged;
}

std::string browser_dedupe_key(const json& record, const json& params, const exchange_observed_t& ex)
{
    const std::string rid = json_first_string_field(record, {"request_id", "id", "network_request_id"});
    const std::string session_id = json_first_string_field(params, {"session_id"});
    const std::string page_id = json_first_string_field(record, {"page_id", "page"});
    if (!rid.empty())
        return std::string("id|") + session_id + "|" + page_id + "|" + rid;
    std::string url = ex.scheme + "://" + ex.host;
    if ((ex.scheme == "https" && ex.port != 443) || (ex.scheme == "http" && ex.port != 80))
        url += ":" + std::to_string(ex.port);
    url += ex.path;
    if (!ex.query.empty())
        url += "?" + ex.query;
    return std::string("url|") + session_id + "|" + ex.method + "|" + std::to_string(ex.status_code) + "|" + url;
}

bool browser_record_is_navigation_document(const json& record)
{
    const std::string resource_type = lower_ascii_copy(json_first_string_field(record, {"resource_type", "type"}));
    if (resource_type == "document" || resource_type == "navigation")
        return true;
    if (!resource_type.empty() && resource_type != "other")
        return false;
    if (!record.is_object())
        return false;
    return record.contains("final_status") ||
        record.contains("initial_status") ||
        record.contains("response_chain") ||
        record.contains("redirect_chain") ||
        record.contains("navigation_timed_out") ||
        record.contains("title");
}

std::string browser_dedupe_document_url_key(const json& record, const json& params, const exchange_observed_t& ex)
{
    if (!browser_record_is_navigation_document(record))
        return {};
    std::string url = ex.scheme + "://" + ex.host;
    if ((ex.scheme == "https" && ex.port != 443) || (ex.scheme == "http" && ex.port != 80))
        url += ":" + std::to_string(ex.port);
    url += ex.path;
    if (!ex.query.empty())
        url += "?" + ex.query;
    return std::string("document_url|") + json_first_string_field(params, {"session_id"}) + "|" + ex.method + "|" + std::to_string(ex.status_code) + "|" + url;
}

bool remember_browser_exchange_keys(const std::string& primary_key, const std::string& document_url_key)
{
    static std::mutex m;
    static std::unordered_set<std::string> seen;
    static std::deque<std::string> order;
    std::lock_guard<std::mutex> lk(m);
    if (primary_key.empty() && document_url_key.empty())
        return true;
    if (!primary_key.empty() && seen.find(primary_key) != seen.end())
        return false;
    if (!document_url_key.empty() && document_url_key != primary_key && seen.find(document_url_key) != seen.end())
        return false;
    if (!primary_key.empty())
    {
        seen.insert(primary_key);
        order.push_back(primary_key);
    }
    if (!document_url_key.empty() && document_url_key != primary_key)
    {
        seen.insert(document_url_key);
        order.push_back(document_url_key);
    }
    while (order.size() > 4096)
    {
        seen.erase(order.front());
        order.pop_front();
    }
    return true;
}

burp_publish_summary_t publish_browser_exchanges(const std::string& tool_name, const json& params, const json& data)
{
    burp_publish_summary_t summary;
    summary.publish_enabled = json_bool_param(params, "publish_to_burp", true);
    summary.source = json_string_param(params, "burp_source", "browser");
    if (summary.source.empty())
        summary.source = "browser";
    const std::vector<json> candidates = collect_browser_exchange_candidates(tool_name, data);
    summary.candidates = candidates.size();
    if (!summary.publish_enabled)
    {
        summary.skipped = candidates.size();
        return summary;
    }
    for (const json& candidate : candidates)
    {
        json hydrated_candidate = hydrate_browser_exchange_candidate(candidate, params, json_string_param(params, "session_id", "default"));
        exchange_observed_t ex;
        if (!browser_record_to_exchange(hydrated_candidate, params, summary.source, ex))
        {
            ++summary.skipped;
            continue;
        }
        const std::string key = browser_dedupe_key(hydrated_candidate, params, ex);
        const std::string document_url_key = browser_dedupe_document_url_key(hydrated_candidate, params, ex);
        if (!remember_browser_exchange_keys(key, document_url_key))
        {
            ++summary.duplicates;
            continue;
        }
        aida::events::publish(kExchangeObservedEvent, ex);
        summary.exchange_ids.push_back(ex.id);
        ++summary.published;
    }
    diag::log_tagged_fmt("mcp_burp", "browser_burp_publish tool=%s enabled=%d source=%s candidates=%zu published=%zu skipped=%zu duplicates=%zu",
        tool_name.c_str(), summary.publish_enabled ? 1 : 0, summary.source.c_str(),
        summary.candidates, summary.published, summary.skipped, summary.duplicates);
    return summary;
}

void attach_burp_bridge_summary(tool_result_t& out, const burp_publish_summary_t& summary)
{
    if (!out.data.is_object())
    {
        json original = out.data;
        out.data = json::object();
        out.data["result"] = std::move(original);
    }
    out.data["burp_bridge"] = summary.to_json();
    out.text = out.data.dump(2);
}

void attach_bridge_rpc_timing(tool_result_t& out, const std::string& tool_name, int timeout_ms, long long rpc_elapsed_ms, long long total_elapsed_ms)
{
    const bool success = out.success;
    if (!out.data.is_object())
    {
        json original = out.data;
        out.data = json::object();
        out.data["result"] = std::move(original);
    }
    out.data["bridge_rpc_timing"] = {
        {"tool", tool_name},
        {"rpc_elapsed_ms", rpc_elapsed_ms},
        {"rpc_timeout_ms", timeout_ms},
        {"wrapper_elapsed_ms", total_elapsed_ms}
    };
    if (success)
        out.text = out.data.dump(2);
}

json page_ids_json(const camoufox::bridge_status_t& status)
{
    json out = json::array();
    for (const auto& page : status.pages)
        out.push_back(page.page_id);
    return out;
}

bool bridge_status_has_page(const camoufox::bridge_status_t& status, const std::string& page_id)
{
    if (page_id.empty())
        return false;
    for (const auto& page : status.pages)
        if (page.page_id == page_id && !page.closed)
            return true;
    return false;
}

json browser_file_probe_json(const std::string& path, long long elapsed_ms)
{
    json out;
    out["path"] = path;
    out["path_provided"] = !path.empty();
    out["checked"] = !path.empty();
    out["elapsed_ms"] = elapsed_ms;
    if (path.empty())
    {
        out["exists"] = false;
        out["size"] = 0;
        out["error"] = "path_not_available";
        return out;
    }
    std::error_code ec;
    const std::filesystem::path fs_path = std::filesystem::u8path(path);
    const bool exists = std::filesystem::exists(fs_path, ec);
    out["exists"] = exists && !ec;
    if (ec)
    {
        out["size"] = 0;
        out["error"] = ec.message();
        return out;
    }
    if (exists)
    {
        const auto size = std::filesystem::file_size(fs_path, ec);
        out["size"] = ec ? 0 : static_cast<uint64_t>(size);
        if (ec)
            out["error"] = ec.message();
    }
    else
    {
        out["size"] = 0;
        out["error"] = "file_not_found";
    }
    return out;
}

std::string first_path_field(const json& params, const json& data, std::initializer_list<const char*> keys)
{
    for (const char* key : keys)
    {
        const std::string from_params = json_string_param(params, key, std::string());
        if (!from_params.empty())
            return from_params;
    }
    if (data.is_object())
    {
        for (const char* key : keys)
        {
            auto it = data.find(key);
            if (it != data.end() && it->is_string())
                return it->get<std::string>();
        }
    }
    return {};
}

uint64_t first_u64_field(const json& data, std::initializer_list<const char*> keys)
{
    if (!data.is_object())
        return 0;
    for (const char* key : keys)
    {
        auto it = data.find(key);
        if (it == data.end())
            continue;
        if (it->is_number_unsigned())
            return it->get<uint64_t>();
        if (it->is_number_integer())
            return static_cast<uint64_t>((std::max<int64_t>)(it->get<int64_t>(), 0));
        if (it->is_string())
        {
            try { return static_cast<uint64_t>(std::stoull(it->get<std::string>())); } catch (...) {}
        }
    }
    return 0;
}

void attach_browser_handle_contract(tool_result_t& out,
                                    const std::string& tool_name,
                                    const json& params,
                                    const std::string& session_id,
                                    const camoufox::bridge_status_t& before,
                                    const camoufox::bridge_status_t& after,
                                    long long total_elapsed_ms)
{
    if (tool_name != "export_state" && tool_name != "import_state" && tool_name != "network_capture")
        return;
    if (!out.data.is_object())
    {
        json original = out.data;
        out.data = json::object();
        if (!original.is_null())
            out.data["result"] = std::move(original);
    }
    const std::string requested_page_id = json_string_param(params, "page_id", std::string());
    const std::string effective_page_id = requested_page_id.empty() ? after.active_page_id : requested_page_id;
    json handles;
    handles["session_id"] = session_id.empty() ? std::string("default") : session_id;
    handles["tool"] = tool_name;
    handles["action"] = json_string_param(params, "action", json_string_param(params, "operation", std::string()));
    handles["requested_page_id"] = requested_page_id;
    handles["effective_page_id"] = effective_page_id;
    handles["page_exists_before"] = bridge_status_has_page(before, effective_page_id);
    handles["page_exists_after"] = bridge_status_has_page(after, effective_page_id);
    handles["active_page_id_before"] = before.active_page_id;
    handles["active_page_id_after"] = after.active_page_id;
    handles["known_page_ids_before"] = page_ids_json(before);
    handles["known_page_ids_after"] = page_ids_json(after);
    handles["page_count_before"] = before.page_count;
    handles["page_count_after"] = after.page_count;
    handles["bridge_generation_before"] = before.generation;
    handles["bridge_generation_after"] = after.generation;
    handles["child_pid_before"] = before.child_pid;
    handles["child_pid_after"] = after.child_pid;
    handles["child_alive_before"] = before.child_alive;
    handles["child_alive_after"] = after.child_alive;
    handles["browser_open_before"] = before.browser_open;
    handles["browser_open_after"] = after.browser_open;
    handles["page_verified_before"] = before.page_verified;
    handles["page_verified_after"] = after.page_verified;
    handles["cleanup_pending_before"] = before.cleanup_pending;
    handles["cleanup_pending_after"] = after.cleanup_pending;
    handles["elapsed_ms"] = total_elapsed_ms;
    if (tool_name == "network_capture")
    {
        const uint64_t capture_id = first_u64_field(out.data, {"capture_id", "capture_session_id", "session_id", "id"});
        handles["capture_id"] = capture_id;
        handles["capture_id_present"] = capture_id != 0;
        handles["capture_stop_target_valid"] = effective_page_id.empty() || bridge_status_has_page(after, effective_page_id) || capture_id != 0;
    }
    if (tool_name == "export_state")
    {
        const std::string path = first_path_field(params, out.data, {"save_path", "state_path", "path", "output_path", "artifact_path"});
        handles["file"] = browser_file_probe_json(path, total_elapsed_ms);
        handles["export_file_exists"] = handles["file"].value("exists", false);
        handles["export_file_size"] = handles["file"].value("size", 0ull);
    }
    if (tool_name == "import_state")
    {
        const std::string path = first_path_field(params, out.data, {"state_path", "save_path", "path", "input_path", "artifact_path"});
        handles["file"] = browser_file_probe_json(path, total_elapsed_ms);
        handles["import_file_exists"] = handles["file"].value("exists", false);
        handles["import_file_size"] = handles["file"].value("size", 0ull);
    }
    out.data["browser_handle_contract"] = std::move(handles);
    if (out.success)
        out.text = out.data.dump(2);
}

void compact_local_fixture_navigation_success(tool_result_t& out, const std::string& session_id, long long elapsed_ms)
{
    if (!out.success || !out.data.is_object())
        return;
    const size_t before_len = out.text.size();
    size_t response_chain_count = 0;
    if (out.data.contains("response_chain") && out.data["response_chain"].is_array())
    {
        response_chain_count = out.data["response_chain"].size();
        out.data.erase("response_chain");
        out.data["response_chain_count"] = static_cast<uint64_t>(response_chain_count);
    }
    size_t network_request_count = 0;
    if (out.data.contains("network_capture") && out.data["network_capture"].is_object())
    {
        json& capture = out.data["network_capture"];
        if (capture.contains("requests") && capture["requests"].is_array())
        {
            network_request_count = capture["requests"].size();
            capture.erase("requests");
            capture["request_count"] = static_cast<uint64_t>(network_request_count);
            capture["requests_compacted"] = true;
        }
    }
    out.data["local_fixture"] = true;
    out.data["diagnostics_compact"] = true;
    out.data["compact_success_reason"] = "loopback_fixture_navigation";
    out.text = out.data.dump(2);
    diag::log_tagged_fmt("mcp_burp",
        "browser_navigation compact_success session_id=%s elapsed_ms=%lld response_chain_count=%zu network_request_count=%zu before_text_len=%zu after_text_len=%zu",
        session_id.c_str(),
        elapsed_ms,
        response_chain_count,
        network_request_count,
        before_len,
        out.text.size());
}

bool is_burp_publish_tool(const std::string& tool_name)
{
    return tool_name == "navigate" ||
        tool_name == "list_network_requests" ||
        tool_name == "get_network_request" ||
        tool_name == "network_capture";
}

bool is_default_browser_session(const std::string& session_id)
{
    return session_id.empty() || lower_ascii_copy(session_id) == "default";
}

bool parse_json_text_array(const std::string& text, json& out)
{
    try
    {
        json parsed = json::parse(text);
        if (parsed.is_array())
        {
            out = std::move(parsed);
            return true;
        }
    }
    catch (...) {}
    return false;
}

json network_performance_fallback_records(const std::string& session_id, const std::string& page_id, std::string& error)
{
    static const char* kPerfEntriesJs = R"JS((function(){
var out=[];
try {
var nav=performance.getEntriesByType('navigation') || [];
var res=performance.getEntriesByType('resource') || [];
function push(e, kind) {
out.push({
url: String(e.name || location.href || ''),
method: 'GET',
status: 0,
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
    camoufox::call_result_t fb = camoufox::evaluate_js(kPerfEntriesJs, true, session_id, page_id);
    if (!fb.ok)
    {
        error = fb.error;
        return json::array();
    }
    if (fb.data.is_array())
        return fb.data;
    if (fb.data.is_string())
    {
        json parsed = json::array();
        if (parse_json_text_array(fb.data.get<std::string>(), parsed))
            return parsed;
    }
    if (fb.data.is_object())
    {
        for (const char* key : {"value", "result", "data"})
        {
            auto it = fb.data.find(key);
            if (it == fb.data.end())
                continue;
            if (it->is_array())
                return *it;
            if (it->is_string())
            {
                json parsed = json::array();
                if (parse_json_text_array(it->get<std::string>(), parsed))
                    return parsed;
            }
        }
    }
    error = "performance fallback produced no array";
    return json::array();
}

std::filesystem::path screenshot_artifact_root()
{
    char temp[MAX_PATH] = {};
    DWORD len = GetTempPathA(static_cast<DWORD>(sizeof(temp)), temp);
    std::filesystem::path root = (len > 0 && len < static_cast<DWORD>(sizeof(temp)))
        ? std::filesystem::path(temp)
        : std::filesystem::temp_directory_path();
    return root / "AiDA" / "camoufox-screenshots";
}

bool write_binary_file_utf8(const std::string& path, const std::vector<unsigned char>& bytes, std::string& error)
{
    if (path.empty())
    {
        error = "empty path";
        return false;
    }
    std::error_code ec;
    const std::filesystem::path root = std::filesystem::weakly_canonical(screenshot_artifact_root(), ec);
    if (ec)
    {
        error = "artifact root resolution failed";
        return false;
    }
    const std::filesystem::path candidate = std::filesystem::u8path(path);
    const std::filesystem::path parent = std::filesystem::weakly_canonical(candidate.parent_path(), ec);
    if (ec || parent.empty())
    {
        error = "artifact parent resolution failed";
        return false;
    }
    const std::filesystem::path relative = parent.lexically_relative(root);
    const bool outside_root = relative == ".." || (!relative.empty() && *relative.begin() == "..");
    if (outside_root)
    {
        error = "artifact path outside screenshot directory";
        return false;
    }
    if (!std::filesystem::create_directories(parent, ec) && ec)
    {
        error = "artifact parent creation failed";
        return false;
    }
    std::wstring wpath = utf8_to_wide_local(path);
    if (wpath.empty())
    {
        error = "path conversion failed";
        return false;
    }
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        error = "CreateFileW failed gle=" + std::to_string(GetLastError());
        return false;
    }
    size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size())
    {
        const size_t remaining = bytes.size() - offset;
        const DWORD chunk = static_cast<DWORD>((std::min)(remaining, static_cast<size_t>(1 << 20)));
        DWORD written = 0;
        if (!WriteFile(h, bytes.data() + offset, chunk, &written, nullptr) || written != chunk)
        {
            error = "WriteFile failed gle=" + std::to_string(GetLastError());
            ok = false;
            break;
        }
        offset += written;
    }
    CloseHandle(h);
    return ok;
}

std::string default_screenshot_path()
{
    char temp[MAX_PATH] = {};
    DWORD len = GetTempPathA(static_cast<DWORD>(sizeof(temp)), temp);
    std::filesystem::path root = (len > 0 && len < static_cast<DWORD>(sizeof(temp))) ? std::filesystem::path(temp) : std::filesystem::temp_directory_path();
    root = screenshot_artifact_root();
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    char name[128] = {};
    std::snprintf(name, sizeof(name), "camoufox_%lu_%lu_%llu.png",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(GetTickCount64()));
    return (root / name).string();
}

int screenshot_inline_limit(const json& params)
{
    int limit = json_int_param(params, "max_base64_chars", 4096);
    if (limit < 0)
        limit = 0;
    if (limit > 16384)
        limit = 16384;
    return limit;
}

void compact_screenshot_response(tool_result_t& out, const json& params)
{
    if (!out.success || !out.data.is_object())
        return;
    auto b64_it = out.data.find("screenshot_base64");
    if (b64_it == out.data.end() || !b64_it->is_string())
        return;
    const std::string b64 = b64_it->get<std::string>();
    std::vector<unsigned char> bytes;
    const bool decoded = decode_base64_string(b64, bytes);
    out.data["screenshot_base64_total_chars"] = b64.size();
    out.data["screenshot_inline_policy"] = "compact_by_default";
    if (decoded)
    {
        out.data["screenshot_bytes"] = bytes.size();
        json dims = png_dimensions(bytes);
        if (!dims.empty())
            out.data["image"] = dims;
        std::string save_path = json_string_param(params, "save_path", std::string());
        if (save_path.empty())
            save_path = default_screenshot_path();
        std::string write_error;
        if (write_binary_file_utf8(save_path, bytes, write_error))
        {
            out.data["artifact_path"] = save_path;
        }
        else
        {
            out.data["artifact_write_error"] = write_error;
        }
    }
    const bool include_base64 = json_bool_param(params, "include_base64", false);
    const int max_chars = screenshot_inline_limit(params);
    if (include_base64 && max_chars > 0)
    {
        const size_t returned = (std::min)(b64.size(), static_cast<size_t>(max_chars));
        out.data["screenshot_base64"] = b64.substr(0, returned);
        out.data["screenshot_base64_returned_chars"] = returned;
        out.data["screenshot_base64_truncated"] = returned < b64.size();
    }
    else
    {
        out.data.erase("screenshot_base64");
        out.data["screenshot_base64_omitted"] = true;
        out.data["screenshot_base64_returned_chars"] = 0;
    }
    out.text = out.data.dump(2);
}

std::string evaluate_js_hint_for_error(const std::string& error)
{
    const std::string low = lower_ascii_copy(error);
    if (low.find("takes exactly") != std::string::npos && low.find("argument") != std::string::npos)
        return "The JavaScript expression or browser callback was invoked with the wrong arity. The MCP tool itself expects arguments {expression:string, await_promise?:boolean, session_id?:string, page_id?:string}; inspect the target function's name and length before calling it, or call it with the required parameters inside an IIFE.";
    if (low.find("expected expression") != std::string::npos || low.find("unexpected token") != std::string::npos)
        return "Playwright evaluate expects one JavaScript expression. Wrap statements in an IIFE such as (() => { const x = 1; return x; })().";
    if (low.find("not serializable") != std::string::npos || low.find("serialize") != std::string::npos || low.find("cloneable") != std::string::npos)
        return "Return primitives, arrays, or plain JSON objects. Convert DOM nodes, Symbols, functions, and circular objects to strings or explicit fields.";
    if (low.find("timeout") != std::string::npos || low.find("exceeded") != std::string::npos)
        return "The page did not finish the evaluation before the timeout. Check page responsiveness, reduce the expression, or keep await_promise enabled for Promise-returning code.";
    return "evaluate_js expects {expression:string, await_promise?:boolean}. Use a single expression and return serializable data.";
}

tool_result_t validate_evaluate_js_params(const json& params)
{
    if (!params.is_object())
        return tool_result_t::error("evaluate_js expects an arguments object with `expression` as a string.");
    auto it = params.find("expression");
    if (it == params.end() || !it->is_string() || it->get<std::string>().empty())
    {
        json data;
        data["error"] = "missing_expression";
        data["expected_arguments"] = json::array({"expression", "await_promise", "session_id", "page_id"});
        data["schema"] = json{{"expression", "string"}, {"await_promise", "boolean"}, {"session_id", "string"}, {"page_id", "string"}};
        data["hint"] = "Call evaluate_js with arguments like {\"expression\":\"document.title\",\"await_promise\":true}.";
        return {false, "evaluate_js missing required string argument `expression`.", data};
    }
    return tool_result_t::ok(json{{"status", "ok"}});
}

void enrich_evaluate_js_response(tool_result_t& out)
{
    if (out.success)
        return;
    std::string error = out.text;
    if (error.empty() && out.data.is_object())
    {
        auto it = out.data.find("error");
        if (it != out.data.end() && it->is_string())
            error = it->get<std::string>();
    }
    if (out.data.is_null() || !out.data.is_object())
        out.data = json::object();
    out.data["error"] = error.empty() ? std::string("evaluate_js failed") : error;
    if (!out.data.contains("hint") || out.data["hint"].is_null() || (out.data["hint"].is_string() && out.data["hint"].get<std::string>().empty()))
        out.data["hint"] = evaluate_js_hint_for_error(error);
    const std::string low = lower_ascii_copy(error);
    if (low.find("timeout") != std::string::npos || low.find("exceeded") != std::string::npos)
    {
        out.data["status"] = "degraded";
        out.data["instrumentation_status"] = "timeout";
        out.data["timeout_status"] = "controlled_timeout";
    }
    else if (!out.data.contains("status"))
    {
        out.data["status"] = "error";
        out.data["instrumentation_status"] = "error";
    }
    out.data["playwright_evaluate_signature"] = "page.evaluate(expression, arg?)";
    out.data["mcp_arguments"] = json::array({"expression", "await_promise", "session_id", "page_id"});
}

void set_scripts_contract_error(
    tool_result_t& out,
    const json& params,
    const std::string& session_id,
    const camoufox::bridge_status_t& status,
    const std::string& action,
    const std::string& error_code,
    const std::string& error_text)
{
    json data = json::object();
    data["status"] = "error";
    data["action"] = action;
    data["error_code"] = error_code;
    data["error"] = error_text;
    data["session_id"] = session_id;
    data["requested_page_id"] = json_string_param(params, "page_id", std::string());
    data["bridge"] = status_to_json(status);
    data["raw_shape"] = json_shape(out.data);
    if (out.data.is_object() && !out.data.empty())
        data["raw_result"] = out.data;
    else if (out.data.is_array() && out.data.size() <= 8)
        data["raw_result"] = out.data;
    out.success = false;
    out.data = std::move(data);
    out.text = out.data.dump(2);
    diag::log_tagged_fmt("mcp_burp", "camoufox_scripts_contract_error action=%s error_code=%s error=%s session_id=%s state=%s page_id=%s data_shape=%s",
        action.c_str(), error_code.c_str(), error_text.c_str(), session_id.c_str(), state_label(status.state),
        json_string_param(params, "page_id", std::string()).c_str(), out.data.value("raw_shape", std::string()).c_str());
}

void normalize_scripts_response(tool_result_t& out, const json& params, const std::string& session_id, const camoufox::bridge_status_t& status)
{
    std::string action = lower_ascii_copy(json_string_param(params, "action", "list"));
    if (action.empty())
        action = "list";
    if (!out.success)
    {
        if (out.data.is_object())
        {
            out.data["bridge"] = status_to_json(status);
            out.data["session_id"] = session_id;
            if (!out.data.contains("status"))
                out.data["status"] = "error";
            if (!out.data.contains("action"))
                out.data["action"] = action;
            out.text = out.data.dump(2);
        }
        return;
    }
    if (out.data.is_array())
    {
        for (const auto& item : out.data)
        {
            if (item.is_object() && item.contains("error") && item["error"].is_string() && !item["error"].get<std::string>().empty())
            {
                set_scripts_contract_error(out, params, session_id, status, action, "scripts_legacy_array_error", item["error"].get<std::string>());
                return;
            }
        }
        json scripts = out.data;
        out.data = json::object();
        out.data["status"] = "ok";
        out.data["action"] = action;
        out.data["scripts"] = std::move(scripts);
        out.data["count"] = static_cast<uint64_t>(out.data["scripts"].size());
        out.data["session_id"] = session_id;
        out.data["requested_page_id"] = json_string_param(params, "page_id", std::string());
        out.data["bridge"] = status_to_json(status);
        out.text = out.data.dump(2);
        return;
    }
    if (!out.data.is_object())
    {
        set_scripts_contract_error(out, params, session_id, status, action, "scripts_invalid_result_shape", "scripts returned a non-object result");
        return;
    }
    if (out.data.empty())
    {
        set_scripts_contract_error(out, params, session_id, status, action, "scripts_empty_result", "scripts returned an empty object");
        return;
    }
    if (out.data.contains("error") && out.data["error"].is_string() && !out.data["error"].get<std::string>().empty())
    {
        const std::string error_text = out.data["error"].get<std::string>();
        if (lower_ascii_copy(json_string_field(out.data, "status")) != "ok")
        {
            std::string error_code = json_string_field(out.data, "error_code");
            if (error_code.empty())
                error_code = "scripts_error";
            set_scripts_contract_error(out, params, session_id, status, action, error_code, error_text);
        }
        return;
    }
    if (action == "list")
    {
        auto scripts_it = out.data.find("scripts");
        if (scripts_it == out.data.end() || !scripts_it->is_array())
        {
            set_scripts_contract_error(out, params, session_id, status, action, "scripts_missing_scripts_array", "scripts list response omitted scripts array");
            return;
        }
        out.data["count"] = static_cast<uint64_t>(scripts_it->size());
    }
    else if (action == "get")
    {
        auto source_it = out.data.find("source");
        if (source_it == out.data.end() || !source_it->is_string())
        {
            set_scripts_contract_error(out, params, session_id, status, action, "scripts_missing_source", "scripts get response omitted source string");
            return;
        }
        out.data["length"] = static_cast<uint64_t>(source_it->get<std::string>().size());
    }
    else if (action == "save")
    {
        const std::string status_text = lower_ascii_copy(json_string_field(out.data, "status"));
        if (status_text != "saved" && status_text != "ok")
        {
            set_scripts_contract_error(out, params, session_id, status, action, "scripts_save_not_confirmed", "scripts save response did not confirm saved status");
            return;
        }
    }
    if (!out.data.contains("status"))
        out.data["status"] = action == "save" ? "saved" : "ok";
    if (!out.data.contains("action"))
        out.data["action"] = action;
    out.data["session_id"] = session_id;
    out.data["requested_page_id"] = json_string_param(params, "page_id", std::string());
    out.data["bridge"] = status_to_json(status);
    out.text = out.data.dump(2);
}

bool reverse_tool_needs_action(const std::string& tool_name)
{
    return tool_name == "network_capture" ||
        tool_name == "cookies" ||
        tool_name == "instrumentation" ||
        tool_name == "intercept_request" ||
        tool_name == "browser_service_worker" ||
        tool_name == "browser_fingerprint_spoof" ||
        tool_name == "scripts";
}

json camoufox_args(const json& params, bool preserve_action)
{
    json args = params.is_object() ? params : json::object();
    args.erase("binary_id");
    args.erase("session_id");
    args.erase("call_timeout_ms");
    args.erase("timeout_ms");
    args.erase("evaluate_timeout_ms");
    args.erase("tool_timeout_ms");
    args.erase("deadline_ms");
    args.erase("launch_timeout_ms");
    args.erase("python_executable");
    args.erase("browser_executable");
    args.erase("server_module");
    args.erase("publish_to_burp");
    args.erase("burp_source");
    if (!preserve_action)
        args.erase("action");
    args.erase("operation");
    args.erase("payload");
    return args;
}

int camoufox_timeout_ms(const json& params, int fallback)
{
    int timeout_ms = fallback > 0 ? fallback : 30000;
    timeout_ms = json_int_param(params, "call_timeout_ms", timeout_ms);
    timeout_ms = json_int_param(params, "timeout_ms", timeout_ms);
    const int evaluate_timeout = json_int_param(params, "evaluate_timeout_ms", 0);
    if (evaluate_timeout > 0)
        timeout_ms = (std::max)(timeout_ms, evaluate_timeout + 5000);
    const int timeout = json_int_param(params, "timeout", 0);
    if (timeout > 0)
        timeout_ms = (std::max)(timeout_ms, timeout + 5000);
    const int duration = json_int_param(params, "duration", 0);
    if (duration > 0)
        timeout_ms = (std::max)(timeout_ms, duration * 1000 + 15000);
    if (timeout_ms < 5000) timeout_ms = 5000;
    if (timeout_ms > 300000) timeout_ms = 300000;
    return timeout_ms;
}

int camoufox_evaluate_timeout_ms(const json& params, int outer_timeout_ms)
{
    int timeout_ms = 30000;
    timeout_ms = json_int_param(params, "call_timeout_ms", timeout_ms);
    timeout_ms = json_int_param(params, "timeout_ms", timeout_ms);
    timeout_ms = json_int_param(params, "evaluate_timeout_ms", timeout_ms);
    if (timeout_ms < 1000)
        timeout_ms = 1000;
    if (timeout_ms > 120000)
        timeout_ms = 120000;
    if (outer_timeout_ms > 2000 && timeout_ms >= outer_timeout_ms)
        timeout_ms = outer_timeout_ms - 1000;
    if (timeout_ms < 1000)
        timeout_ms = 1000;
    return timeout_ms;
}

tool_result_t bridge_result_to_tool_result(const camoufox::call_result_t& r)
{
    tool_result_t out;
    if (r.ok)
    {
        if (!r.data.is_null())
        {
            out.success = true;
            out.data = r.data;
            out.text = r.data.dump(2);
        }
        else if (!r.text.empty())
        {
            out.success = true;
            out.text = r.text;
        }
        else
        {
            out.success = true;
            out.data = json{{"status", "ok"}};
            out.text = out.data.dump(2);
        }
        preserve_semantic_failure(out);
        return out;
    }

    out.success = false;
    out.text = r.error.empty() ? (r.text.empty() ? std::string("camoufox tool failed") : r.text) : r.error;
    if (!r.data.is_null())
        out.data = r.data;
    return out;
}

tool_result_t tool_camoufox_click(const json& params, int timeout_ms)
{
    if (timeout_ms <= 0) timeout_ms = 30000;
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    const std::string selector = params["selector"].get<std::string>();
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_click_direct entry selector=%s timeout_ms=%d state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        timeout_ms,
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("click", args, timeout_ms, session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_click_direct exit selector=%s success=%d elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

tool_result_t tool_camoufox_type_text(const json& params, int timeout_ms)
{
    if (timeout_ms <= 0) timeout_ms = 30000;
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    if (!params.contains("text") || !params["text"].is_string())
        return tool_result_t::error("missing_text");
    const std::string selector = params["selector"].get<std::string>();
    const std::string text = params["text"].get<std::string>();
    const int delay = json_int_param(params, "delay", 0);
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_type_direct entry selector=%s text_len=%zu delay=%d timeout_ms=%d state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        text.size(),
        delay,
        timeout_ms,
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    args["text"] = text;
    args["delay"] = delay;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("type_text", args, timeout_ms, session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_type_direct exit selector=%s success=%d text_len=%zu elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s out_text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        text.size(),
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

tool_result_t tool_camoufox_wait_for_selector(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    const std::string selector = params["selector"].get<std::string>();
    int timeout_ms = json_int_param(params, "timeout", 5000);
    if (timeout_ms < 1) timeout_ms = 5000;
    if (timeout_ms > 60000) timeout_ms = 60000;
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_wait_direct entry selector=%s timeout_ms=%d state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        timeout_ms,
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    args["timeout"] = timeout_ms;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("wait_for", args, std::max(timeout_ms + 5000, 15000), session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_wait_direct exit selector=%s success=%d timeout_ms=%d elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        timeout_ms,
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

camoufox::launch_config_t launch_config_from_mcp_params(const json& params)
{
    camoufox::launch_config_t cfg;
    cfg.session_id = json_string_param(params, "session_id", cfg.session_id);
    cfg.headless = json_bool_param(params, "headless", cfg.headless);
    cfg.proxy = json_string_param(params, "proxy", cfg.proxy);
    cfg.os = json_string_param(params, "os_type", json_string_param(params, "os", cfg.os));
    cfg.os = "windows";
    cfg.locale = json_string_param(params, "locale", cfg.locale);
    cfg.humanize = json_bool_param(params, "humanize", cfg.humanize);
    cfg.geoip = json_bool_param(params, "geoip", cfg.geoip);
    cfg.block_images = json_bool_param(params, "block_images", cfg.block_images);
    cfg.block_webrtc = json_bool_param(params, "block_webrtc", cfg.block_webrtc);
    cfg.block_webrtc = true;
    cfg.user_agent = json_string_param(params, "user_agent", json_string_param(params, "userAgent", cfg.user_agent));
    cfg.ua_policy = json_string_param(params, "ua_policy",
        json_string_param(params, "user_agent_profile",
            json_string_param(params, "user_agent_mode", cfg.ua_policy)));
    cfg.persistent_context = json_bool_param(params, "persistent_context", cfg.persistent_context);
    cfg.profile_dir = json_string_param(params, "profile_dir", cfg.profile_dir);
    cfg.user_data_dir = json_string_param(params, "user_data_dir", cfg.user_data_dir);
    cfg.enable_trace = json_bool_param(params, "enable_trace", cfg.enable_trace);
    cfg.python_executable = json_string_param(params, "python_executable", cfg.python_executable);
    cfg.browser_executable = json_string_param(params, "browser_executable", cfg.browser_executable);
    cfg.launch_timeout_ms = json_int_param(params, "launch_timeout_ms", cfg.launch_timeout_ms);
    cfg.window_width = json_int_param(params, "window_width", json_int_param(params, "width", cfg.window_width));
    cfg.window_height = json_int_param(params, "window_height", json_int_param(params, "height", cfg.window_height));
    cfg.testlab_fast_probe = json_bool_param(params, "aida_testlab_fast_probe", json_bool_param(params, "testlab_fast_probe", cfg.testlab_fast_probe));
    return cfg;
}

tool_result_t tool_launch_browser(const json& params)
{
    camoufox::launch_config_t cfg = launch_config_from_mcp_params(params);
    bool ok = camoufox::start_bridge(cfg);
    auto status = camoufox::get_status(cfg.session_id);
    json j = status_to_json(status);
    if (!ok)
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox launch_browser failed"));
        out.data = j;
        return out;
    }
    if (!bridge_ready(status))
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox launch_browser did not become ready"));
        out.data = j;
        return out;
    }
    return tool_result_t::ok(j);
}

tool_result_t tool_close_browser(const json& params)
{
    const std::string session_id = json_string_param(params, "session_id", "default");
    const auto before = camoufox::get_status(session_id);
    diag::log_tagged_fmt("mcp_burp", "camoufox_close_browser entry session_id=%s state=%s generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d browser_processes=%u child_processes=%u cleanup_pending=%d",
        session_id.c_str(), state_label(before.state), static_cast<unsigned long long>(before.generation),
        static_cast<unsigned long>(before.child_pid), static_cast<int>(before.child_alive),
        static_cast<int>(before.browser_open), static_cast<int>(before.page_verified),
        static_cast<unsigned>(before.browser_process_count), static_cast<unsigned>(before.child_process_count),
        static_cast<int>(before.cleanup_pending));
    bool ok = camoufox::stop_bridge(session_id, "camoufox_mcp.close_browser");
    const auto after = camoufox::get_status(session_id);
    diag::log_tagged_fmt("mcp_burp", "camoufox_close_browser exit session_id=%s ok=%d state=%s generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d browser_processes=%u child_processes=%u cleanup_pending=%d err=%s",
        session_id.c_str(), static_cast<int>(ok), state_label(after.state), static_cast<unsigned long long>(after.generation),
        static_cast<unsigned long>(after.child_pid), static_cast<int>(after.child_alive),
        static_cast<int>(after.browser_open), static_cast<int>(after.page_verified),
        static_cast<unsigned>(after.browser_process_count), static_cast<unsigned>(after.child_process_count),
        static_cast<int>(after.cleanup_pending), after.last_error.c_str());
    json j = status_to_json(after);
    if (!ok)
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox close_browser failed"));
        out.data = j;
        return out;
    }
    return tool_result_t::ok(j);
}

tool_result_t tool_camoufox_passthrough(const std::string& tool_name, const json& params, int default_timeout_ms)
{
    json args = camoufox_args(params, reverse_tool_needs_action(tool_name));
    int timeout_ms = camoufox_timeout_ms(params, default_timeout_ms);
    const std::string session_id = json_string_param(params, "session_id", "default");
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    const bool environment_probe = tool_name == "compare_env" || tool_name == "check_environment";
    const bool instrumentation_probe = environment_probe ||
        tool_name == "hook_jsvmp_interpreter" ||
        tool_name == "trace_property_access";
    diag::log_tagged_fmt("mcp_burp", "camoufox_passthrough entry tool=%s timeout_ms=%d args_shape=%s bridge_state=%s child_pid=%lu browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        tool_name.c_str(), timeout_ms, json_shape(args).c_str(), state_label(before.state),
        static_cast<unsigned long>(before.child_pid), static_cast<int>(before.browser_open),
        static_cast<int>(before.page_verified), static_cast<int>(before.child_alive), static_cast<int>(before.cleanup_pending));
    if (environment_probe)
    {
        const url_log_t active_url = summarize_url_for_log(before.active_page_url);
        diag::log_tagged_fmt("mcp_burp", "camoufox_environment_probe entry tool=%s session_id=%s timeout_ms=%d active_page_id=%s active_url_host=%s active_url_path=%s active_url_len=%zu page_count=%lu title_len=%zu",
            tool_name.c_str(), session_id.c_str(), timeout_ms, before.active_page_id.c_str(),
            active_url.host.c_str(), active_url.path.c_str(), active_url.length,
            static_cast<unsigned long>(before.page_count), before.active_page_title.size());
    }
    if (tool_name == "click")
        return tool_camoufox_click(params, timeout_ms);
    if (tool_name == "type_text")
        return tool_camoufox_type_text(params, timeout_ms);
    if (tool_name == "wait_for" && params.is_object() && params.contains("selector") && params["selector"].is_string())
        return tool_camoufox_wait_for_selector(params);
    if (tool_name == "add_init_script")
        args.erase("keep_persistent");
    if (tool_name == "remove_hooks")
        args.erase("persistent");
    if (tool_name == "browser_service_worker" && params.is_object() && params.contains("payload") && !args.contains("payload"))
        args["payload"] = params["payload"];
    if (tool_name == "evaluate_js")
    {
        tool_result_t validation = validate_evaluate_js_params(params);
        if (!validation.success)
            return validation;
        args["timeout_ms"] = camoufox_evaluate_timeout_ms(params, timeout_ms);
    }
    if (tool_name == "instrumentation" && lower_ascii_copy(json_string_param(args, "action", std::string())) == "reload")
        args["timeout_ms"] = timeout_ms;
    json capture_info = json::object();
    bool navigation_capture_body = false;
    bool navigation_capture_from_start = false;
    bool navigation_publish_to_burp = false;
    bool navigation_publish_explicit = false;
    bool navigation_local_fixture = false;
    bool navigation_diagnostic = false;
    std::string navigation_capture_pattern;
    if (tool_name == "take_screenshot")
    {
        args.erase("include_base64");
        args.erase("max_base64_chars");
        args.erase("save_path");
    }
    if (tool_name == "navigate")
    {
        const std::string request_url = json_string_param(args, "url", json_string_param(params, "url", std::string()));
        navigation_local_fixture = browser_is_loopback_fixture_url(request_url);
        navigation_diagnostic = browser_diagnostic_mode(params);
        navigation_publish_explicit = json_bool_param_present(params, "publish_to_burp");
        const bool default_publish_to_burp = !(navigation_local_fixture && !navigation_diagnostic);
        const bool publish_to_burp = json_bool_param(params, "publish_to_burp", default_publish_to_burp);
        const bool requested_capture_from_start = json_bool_param(params, "capture_from_start", false);
        const bool capture_from_start = requested_capture_from_start || publish_to_burp;
        const bool capture_body = json_bool_param(params, "capture_body", publish_to_burp);
        navigation_capture_body = capture_body;
        navigation_capture_from_start = capture_from_start;
        navigation_publish_to_burp = publish_to_burp;
        const std::string capture_pattern = json_string_param(params, "capture_url_pattern", "**/*");
        navigation_capture_pattern = capture_pattern.empty() ? std::string("**/*") : capture_pattern;
        const std::string capture_page_id = json_string_param(params, "page_id", std::string());
        if (capture_from_start)
        {
            args["capture_from_start"] = true;
            args["capture_body"] = capture_body;
            args["capture_url_pattern"] = navigation_capture_pattern;
            capture_info["requested"] = true;
            capture_info["requested_explicitly"] = requested_capture_from_start;
            capture_info["auto_for_burp_publish"] = publish_to_burp && !requested_capture_from_start;
            capture_info["pattern"] = args["capture_url_pattern"];
            capture_info["capture_body"] = capture_body;
            capture_info["page_id"] = capture_page_id;
            capture_info["delegated_to_navigate"] = true;
            capture_info["cpp_pre_capture_rpc"] = false;
        }
        else if (navigation_local_fixture && !navigation_diagnostic && !navigation_publish_explicit)
        {
            capture_info["requested"] = false;
            capture_info["auto_compact_local_fixture"] = true;
            capture_info["publish_to_burp_default_suppressed"] = true;
            capture_info["delegated_to_navigate"] = false;
            capture_info["cpp_pre_capture_rpc"] = false;
        }
    }
    if (tool_name == "navigate")
    {
        const std::string page_id = json_string_param(args, "page_id", json_string_param(params, "page_id", std::string()));
        const std::string wait_until = json_string_param(args, "wait_until", json_string_param(params, "wait_until", std::string()));
        const std::string request_url = json_string_param(args, "url", json_string_param(params, "url", std::string()));
        const url_log_t request_url_log = summarize_url_for_log(request_url);
        const url_log_t active_url = summarize_url_for_log(before.active_page_url);
        const int args_timeout = json_int_param(args, "timeout", -1);
        diag::log_tagged_fmt("mcp_burp", "browser_navigation phase=before_call_tool session_id=%s page_id=%s active_page_id=%s request_host=%s request_path=%s request_query=%d request_url_len=%zu active_host=%s active_path=%s wait_until=%s timeout_ms=%d args_timeout=%d capture_from_start=%d capture_body=%d publish_to_burp=%d publish_explicit=%d local_fixture=%d diagnostic=%d capture_pattern=%s args_shape=%s bridge_state=%s child_pid=%lu child_alive=%d page_verified=%d",
            session_id.c_str(),
            page_id.empty() ? "<empty>" : page_id.c_str(),
            before.active_page_id.empty() ? "<empty>" : before.active_page_id.c_str(),
            request_url_log.host.c_str(),
            request_url_log.path.c_str(),
            request_url_log.has_query ? 1 : 0,
            request_url_log.length,
            active_url.host.c_str(),
            active_url.path.c_str(),
            wait_until.empty() ? "<empty>" : wait_until.c_str(),
            timeout_ms,
            args_timeout,
            navigation_capture_from_start ? 1 : 0,
            navigation_capture_body ? 1 : 0,
            navigation_publish_to_burp ? 1 : 0,
            navigation_publish_explicit ? 1 : 0,
            navigation_local_fixture ? 1 : 0,
            navigation_diagnostic ? 1 : 0,
            navigation_capture_pattern.empty() ? "<empty>" : navigation_capture_pattern.c_str(),
            json_shape(args).c_str(),
            state_label(before.state),
            static_cast<unsigned long>(before.child_pid),
            before.child_alive ? 1 : 0,
            before.page_verified ? 1 : 0);
        const bool nav_page_exists = bridge_status_has_page(before, page_id);
        diag::log_tagged_fmt("mcp_burp", "browser_navigation page_target_select_pre_flight session_id=%s page_id=%s page_exists=%d active_page_id=%s page_count=%lu known_pages=%s generation=%llu bridge_state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d",
            session_id.c_str(),
            page_id.empty() ? "<empty>" : page_id.c_str(),
            nav_page_exists ? 1 : 0,
            before.active_page_id.empty() ? "<empty>" : before.active_page_id.c_str(),
            static_cast<unsigned long>(before.page_count),
            page_ids_json(before).dump().c_str(),
            static_cast<unsigned long long>(before.generation),
            state_label(before.state),
            static_cast<unsigned long>(before.child_pid),
            before.child_alive ? 1 : 0,
            before.browser_open ? 1 : 0,
            before.page_verified ? 1 : 0);
    }
    if (tool_name == "hook_jsvmp_interpreter")
    {
        const std::string jsvmp_page_id = json_string_param(args, "page_id", json_string_param(params, "page_id", std::string()));
        if (!jsvmp_page_id.empty() && jsvmp_page_id != "default")
        {
            const bool jsvmp_page_exists = bridge_status_has_page(before, jsvmp_page_id);
            if (!jsvmp_page_exists)
            {
                const bool jsvmp_default_exists = bridge_status_has_page(before, std::string("default"));
                const std::string jsvmp_fallback_page_id = jsvmp_default_exists ? std::string("default") : before.active_page_id;
                if (!jsvmp_fallback_page_id.empty() && jsvmp_fallback_page_id != jsvmp_page_id)
                {
                    args["page_id"] = jsvmp_fallback_page_id;
                    diag::log_tagged_fmt("mcp_burp", "browser_instrumentation jsvmp page_fallback requested_page_id=%s fallback_page_id=%s reason=requested_page_not_found default_exists=%d active_page_id=%s page_count=%lu known_pages=%s generation=%llu bridge_state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d",
                        jsvmp_page_id.c_str(),
                        jsvmp_fallback_page_id.c_str(),
                        jsvmp_default_exists ? 1 : 0,
                        before.active_page_id.empty() ? "<empty>" : before.active_page_id.c_str(),
                        static_cast<unsigned long>(before.page_count),
                        page_ids_json(before).dump().c_str(),
                        static_cast<unsigned long long>(before.generation),
                        state_label(before.state),
                        static_cast<unsigned long>(before.child_pid),
                        before.child_alive ? 1 : 0,
                        before.browser_open ? 1 : 0,
                        before.page_verified ? 1 : 0);
                }
            }
        }
    }
    int effective_rpc_timeout_ms = timeout_ms;
    if (tool_name == "navigate" && effective_rpc_timeout_ms > 25000)
    {
        diag::log_tagged_fmt("mcp_burp", "browser_navigation rpc_deadline_capped session_id=%s requested_timeout_ms=%d capped_timeout_ms=%d deadline_source=navigate_watchdog_guard",
            session_id.c_str(),
            timeout_ms,
            25000);
        effective_rpc_timeout_ms = 25000;
    }
    const auto rpc_start = std::chrono::steady_clock::now();
    const uint64_t rpc_send_unix_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    if (tool_name == "navigate")
    {
        diag::log_tagged_fmt("mcp_burp", "browser_navigation rpc_send session_id=%s rpc_send_unix_ms=%llu rpc_timeout_ms=%d effective_rpc_timeout_ms=%d bridge_state=%s child_pid=%lu child_alive=%d",
            session_id.c_str(),
            static_cast<unsigned long long>(rpc_send_unix_ms),
            timeout_ms,
            effective_rpc_timeout_ms,
            state_label(before.state),
            static_cast<unsigned long>(before.child_pid),
            before.child_alive ? 1 : 0);
    }
    camoufox_mcp_op_admission_t mcp_admission(
        tool_name.c_str(),
        session_id,
        before.generation,
        before.child_pid);
    if (!mcp_admission.admitted())
    {
        json rejection = mcp_standalone::downstream::rejection_json(mcp_admission.rejection(), mcp_admission.id());
        tool_result_t out = tool_result_t::error(
            "CAMOUFOX-LONGOP-REJECT: " + mcp_admission.rejection().reason,
            "MCP_DOWNSTREAM_CAPACITY_REJECT",
            rejection);
        diag::log_tagged_fmt("mcp_burp", "camoufox_passthrough longop_rejected tool=%s session=%s reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            tool_name.c_str(), session_id.c_str(),
            mcp_admission.rejection().reason.c_str(),
            mcp_admission.rejection().quota_name.c_str(),
            mcp_admission.rejection().quota_scope.c_str(),
            mcp_admission.rejection().observed,
            mcp_admission.rejection().limit);
        return out;
    }
    camoufox::call_result_t bridge_result = camoufox::call_tool(tool_name, args, effective_rpc_timeout_ms, session_id);
    const auto rpc_end = std::chrono::steady_clock::now();
    const uint64_t rpc_recv_unix_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const auto rpc_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        rpc_end - rpc_start).count();
    if (tool_name == "navigate")
    {
        diag::log_tagged_fmt("mcp_burp", "browser_navigation rpc_recv session_id=%s rpc_send_unix_ms=%llu rpc_recv_unix_ms=%llu rpc_elapsed_ms=%lld rpc_timeout_ms=%d effective_rpc_timeout_ms=%d ok=%d error_len=%zu data_shape=%s",
            session_id.c_str(),
            static_cast<unsigned long long>(rpc_send_unix_ms),
            static_cast<unsigned long long>(rpc_recv_unix_ms),
            static_cast<long long>(rpc_elapsed_ms),
            timeout_ms,
            effective_rpc_timeout_ms,
            bridge_result.ok ? 1 : 0,
            bridge_result.error.size(),
            json_shape(bridge_result.data).c_str());
    }
    if (tool_name == "navigate")
    {
        const std::string page_id = json_string_param(args, "page_id", json_string_param(params, "page_id", std::string()));
        const std::string wait_until = json_string_param(args, "wait_until", json_string_param(params, "wait_until", std::string()));
        const int response_status = json_first_int_field(bridge_result.data, {"final_status", "initial_status", "status", "response_status"}, -1);
        const bool navigation_timed_out = json_bool_param(bridge_result.data, "navigation_timed_out", false) ||
            json_bool_param(bridge_result.data, "timed_out", false);
        const std::string response_url = json_first_string_field(bridge_result.data, {"url", "final_url", "active_url", "page_url"});
        const url_log_t response_url_log = summarize_url_for_log(response_url);
        const auto mid = camoufox::get_status(session_id);
        diag::log_tagged_fmt("mcp_burp", "browser_navigation phase=after_call_tool session_id=%s page_id=%s wait_until=%s ok=%d rpc_elapsed_ms=%lld response_status=%d navigation_timed_out=%d response_host=%s response_path=%s response_query=%d response_url_len=%zu data_shape=%s error_len=%zu bridge_state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d",
            session_id.c_str(),
            page_id.empty() ? "<empty>" : page_id.c_str(),
            wait_until.empty() ? "<empty>" : wait_until.c_str(),
            bridge_result.ok ? 1 : 0,
            static_cast<long long>(rpc_elapsed_ms),
            response_status,
            navigation_timed_out ? 1 : 0,
            response_url_log.host.c_str(),
            response_url_log.path.c_str(),
            response_url_log.has_query ? 1 : 0,
            response_url_log.length,
            json_shape(bridge_result.data).c_str(),
            bridge_result.error.size(),
            state_label(mid.state),
            static_cast<unsigned long>(mid.child_pid),
            mid.child_alive ? 1 : 0,
            mid.browser_open ? 1 : 0,
            mid.page_verified ? 1 : 0,
            mid.cleanup_pending ? 1 : 0);
    }
    tool_result_t out = bridge_result_to_tool_result(bridge_result);
    if (tool_name == "list_network_requests" && out.success && browser_exchange_candidate_count(tool_name, out.data) == 0)
    {
        const std::string page_id = json_string_param(params, "page_id", std::string());
        size_t max_records = static_cast<size_t>((std::max)(json_int_param(params, "max_records", json_int_param(params, "limit", 200)), 1));
        camoufox::call_result_t fallback_result = is_default_browser_session(session_id)
            ? camoufox::list_network_requests(max_records)
            : camoufox::list_network_requests(max_records, session_id, page_id);
        size_t fallback_candidates = fallback_result.ok ? browser_exchange_candidate_count(tool_name, fallback_result.data) : 0;
        bool performance_fallback_used = false;
        std::string performance_fallback_error;
        if (fallback_candidates == 0)
        {
            json perf_records = network_performance_fallback_records(session_id, page_id, performance_fallback_error);
            if (perf_records.is_array() && !perf_records.empty())
            {
                fallback_result.ok = true;
                fallback_result.error.clear();
                fallback_result.data = std::move(perf_records);
                fallback_candidates = browser_exchange_candidate_count(tool_name, fallback_result.data);
                performance_fallback_used = fallback_candidates > 0;
            }
        }
        if (fallback_candidates > 0)
        {
            if (!out.data.is_object())
                out.data = json::object();
            if (fallback_result.data.is_array())
            {
                out.data["requests"] = fallback_result.data;
            }
            else if (fallback_result.data.is_object())
            {
                out.data["requests"] = json::array();
                for (const char* key : {"requests", "items", "records", "network_requests", "entries", "data", "result"})
                {
                    auto it = fallback_result.data.find(key);
                    if (it != fallback_result.data.end() && it->is_array())
                    {
                        out.data["requests"] = *it;
                        break;
                    }
                }
                out.data["fallback_result"] = fallback_result.data;
            }
            out.data["count"] = static_cast<uint64_t>(fallback_candidates);
            out.data["fallback"] = performance_fallback_used ? "browser_performance_entries" : "camoufox_bridge_list_network_requests";
            out.text = out.data.dump(2);
            diag::log_tagged_fmt("mcp_burp", "browser_network list fallback used session_id=%s page_id=%s candidates=%zu performance=%d",
                session_id.c_str(), page_id.c_str(), fallback_candidates, performance_fallback_used ? 1 : 0);
        }
        else
        {
            diag::log_tagged_fmt("mcp_burp", "browser_network list fallback empty session_id=%s ok=%d err=%s perf_err=%s data_shape=%s",
                session_id.c_str(), static_cast<int>(fallback_result.ok), fallback_result.error.c_str(), performance_fallback_error.c_str(), json_shape(fallback_result.data).c_str());
        }
    }
    if (tool_name == "list_network_requests")
        normalize_browser_network_list_response(out, params);
    if (tool_name == "take_screenshot")
        compact_screenshot_response(out, params);
    if (tool_name == "evaluate_js")
        enrich_evaluate_js_response(out);
    if (tool_name == "navigate" && !capture_info.empty() && !capture_info.value("requested", false) && out.success)
    {
        if (out.data.is_null() || !out.data.is_object())
            out.data = json::object();
        out.data["network_capture"] = capture_info;
        out.text = out.data.dump(2);
    }
    if (tool_name == "navigate" && !capture_info.empty() && capture_info.value("requested", false))
    {
        if (out.data.is_null() || !out.data.is_object())
            out.data = json::object();
        if (out.success)
        {
            const std::string page_id = json_string_param(params, "page_id", std::string());
            json list_args = json::object();
            list_args["limit"] = 200;
            list_args["include_headers"] = true;
            list_args["include_body"] = navigation_capture_body;
            list_args["max_body_size"] = json_int_param(params, "max_body_size", -1);
            if (!page_id.empty())
                list_args["page_id"] = page_id;
            camoufox::call_result_t captured = camoufox::call_tool("list_network_requests", list_args, 30000, session_id);
            capture_info["post_navigation_list_ok"] = captured.ok;
            capture_info["post_navigation_data_shape"] = json_shape(captured.data);
            if (!captured.ok)
                capture_info["post_navigation_error"] = captured.error;
            const size_t captured_candidates = captured.ok ? browser_exchange_candidate_count("list_network_requests", captured.data) : 0;
            capture_info["post_navigation_candidates"] = static_cast<uint64_t>(captured_candidates);
            if (captured.ok && captured_candidates > 0)
            {
                if (captured.data.is_array())
                    capture_info["requests"] = captured.data;
                else if (captured.data.is_object())
                {
                    for (const char* key : {"requests", "items", "records", "network_requests", "entries", "data", "result"})
                    {
                        auto it = captured.data.find(key);
                        if (it != captured.data.end() && it->is_array())
                        {
                            capture_info["requests"] = *it;
                            break;
                        }
                    }
                }
            }
            diag::log_tagged_fmt("mcp_burp", "browser_navigation post_capture_list session_id=%s page_id=%s ok=%d candidates=%zu err=%s",
                session_id.c_str(), page_id.c_str(), static_cast<int>(captured.ok), captured_candidates, captured.error.c_str());
        }
        auto existing_capture = out.data.find("network_capture");
        if (existing_capture != out.data.end() && existing_capture->is_object())
        {
            (*existing_capture)["wrapper"] = capture_info;
        }
        else
        {
            out.data["network_capture"] = capture_info;
        }
        out.text = out.data.dump(2);
    }
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    attach_bridge_rpc_timing(out, tool_name, effective_rpc_timeout_ms, static_cast<long long>(rpc_elapsed_ms), static_cast<long long>(elapsed_ms));
    if (tool_name == "navigate" && out.success && navigation_local_fixture && !navigation_diagnostic && !navigation_publish_to_burp)
        compact_local_fixture_navigation_success(out, session_id, static_cast<long long>(elapsed_ms));
    if (instrumentation_probe)
        annotate_instrumentation_response(tool_name, out, timeout_ms, static_cast<long long>(elapsed_ms));
    auto after = camoufox::get_status(session_id);
    attach_browser_handle_contract(out, tool_name, params, session_id, before, after, static_cast<long long>(elapsed_ms));
    if (tool_name == "scripts")
        normalize_scripts_response(out, params, session_id, after);
    if (tool_name == "compare_env" || tool_name == "check_environment")
        attach_privacy_status(out, after);
    preserve_semantic_failure(out);
    if (out.success && is_burp_publish_tool(tool_name))
    {
        json publish_params = params.is_object() ? params : json::object();
        if (tool_name == "navigate")
        {
            if (!json_bool_param_present(publish_params, "publish_to_burp"))
                publish_params["publish_to_burp"] = navigation_publish_to_burp;
            if (!json_bool_param_present(publish_params, "capture_body"))
                publish_params["capture_body"] = navigation_capture_body;
        }
        burp_publish_summary_t burp_summary = publish_browser_exchanges(tool_name, publish_params, out.data);
        if (tool_name == "list_network_requests" && out.data.is_object() && !json_string_field(out.data, "fallback").empty())
            burp_summary.fallback_used = true;
        attach_burp_bridge_summary(out, burp_summary);
    }
    if (tool_name == "navigate")
    {
        const std::string page_id = json_string_param(args, "page_id", json_string_param(params, "page_id", std::string()));
        const std::string wait_until = json_string_param(args, "wait_until", json_string_param(params, "wait_until", std::string()));
        const int response_status = json_first_int_field(out.data, {"final_status", "initial_status", "status", "response_status"}, -1);
        const bool navigation_timed_out = json_bool_param(out.data, "navigation_timed_out", false) ||
            json_bool_param(out.data, "timed_out", false);
        const std::string response_url = json_first_string_field(out.data, {"url", "final_url", "active_url", "page_url"});
        const url_log_t response_url_log = summarize_url_for_log(response_url);
        diag::log_tagged_fmt("mcp_burp", "browser_navigation phase=exit session_id=%s page_id=%s wait_until=%s success=%d elapsed_ms=%lld rpc_timeout_ms=%d response_status=%d navigation_timed_out=%d status=%s response_host=%s response_path=%s response_query=%d response_url_len=%zu data_shape=%s text_len=%zu bridge_state=%s child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d",
            session_id.c_str(),
            page_id.empty() ? "<empty>" : page_id.c_str(),
            wait_until.empty() ? "<empty>" : wait_until.c_str(),
            out.success ? 1 : 0,
            static_cast<long long>(elapsed_ms),
            timeout_ms,
            response_status,
            navigation_timed_out ? 1 : 0,
            status_string_for_log(out.data).c_str(),
            response_url_log.host.c_str(),
            response_url_log.path.c_str(),
            response_url_log.has_query ? 1 : 0,
            response_url_log.length,
            json_shape(out.data).c_str(),
            out.text.size(),
            state_label(after.state),
            static_cast<unsigned long>(after.child_pid),
            after.child_alive ? 1 : 0,
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            after.cleanup_pending ? 1 : 0);
    }
    if (environment_probe)
    {
        const url_log_t active_url = summarize_url_for_log(after.active_page_url);
        diag::log_tagged_fmt("mcp_burp", "camoufox_environment_probe exit tool=%s success=%d elapsed_ms=%lld rpc_timeout_ms=%d status=%s instrumentation_status=%s timeout_status=%s result_property_count=%d active_page_id=%s active_url_host=%s active_url_path=%s active_url_len=%zu page_count=%lu data_shape=%s",
            tool_name.c_str(), static_cast<int>(out.success), static_cast<long long>(elapsed_ms), timeout_ms,
            status_string_for_log(out.data).c_str(),
            json_string_field(out.data, "instrumentation_status").c_str(),
            json_string_field(out.data, "timeout_status").c_str(),
            compare_env_result_count(out.data),
            after.active_page_id.c_str(), active_url.host.c_str(), active_url.path.c_str(), active_url.length,
            static_cast<unsigned long>(after.page_count), json_shape(out.data).c_str());
    }
    else if (instrumentation_probe)
    {
        diag::log_tagged_fmt("mcp_burp", "camoufox_instrumentation_probe exit tool=%s success=%d elapsed_ms=%lld rpc_timeout_ms=%d status=%s instrumentation_status=%s timeout_status=%s data_shape=%s",
            tool_name.c_str(), static_cast<int>(out.success), static_cast<long long>(elapsed_ms), timeout_ms,
            status_string_for_log(out.data).c_str(),
            json_string_field(out.data, "instrumentation_status").c_str(),
            json_string_field(out.data, "timeout_status").c_str(),
            json_shape(out.data).c_str());
    }
    std::string failure_phase;
    try
    {
        if (!out.success && out.data.is_object())
        {
            auto it = out.data.find("phase");
            if (it != out.data.end() && it->is_string())
                failure_phase = it->get<std::string>();
        }
    }
    catch (...) {}
    diag::log_tagged_fmt("mcp_burp", "camoufox_passthrough exit tool=%s success=%d elapsed_ms=%lld data_shape=%s text_len=%zu failure_phase=%s bridge_state=%s child_pid=%lu browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        tool_name.c_str(), static_cast<int>(out.success), static_cast<long long>(elapsed_ms),
        json_shape(out.data).c_str(), out.text.size(), failure_phase.c_str(), state_label(after.state),
        static_cast<unsigned long>(after.child_pid), static_cast<int>(after.browser_open),
        static_cast<int>(after.page_verified), static_cast<int>(after.child_alive), static_cast<int>(after.cleanup_pending));
    return out;
}

struct camoufox_action_entry_t
{
    const char* action;
    const char* internal_tool;
    int default_timeout_ms;
};

const camoufox_action_entry_t* find_camoufox_action(
    const std::string& action,
    const camoufox_action_entry_t* entries,
    size_t entry_count)
{
    for (size_t i = 0; i < entry_count; ++i)
    {
        if (action == entries[i].action)
            return &entries[i];
    }
    return nullptr;
}

json camoufox_group_payload(const json& params)
{
    json out = params.is_object() ? params : json::object();
    out.erase("action");
    out.erase("operation");
    out.erase("payload");
    if (params.contains("payload") && params["payload"].is_object())
    {
        for (auto it = params["payload"].begin(); it != params["payload"].end(); ++it)
            out[it.key()] = it.value();
    }
    return out;
}

void normalize_camoufox_group_payload(
    const char* group_name,
    const std::string& group_action,
    const char* internal_tool,
    const json& params,
    json& forwarded)
{
    const std::string internal = internal_tool ? internal_tool : "";
    if (internal == "cookies")
    {
        const std::string cookie_action = json_string_param(forwarded, "cookie_action",
            json_string_param(params, "cookie_action", std::string()));
        if (!cookie_action.empty())
            forwarded["action"] = cookie_action;
        else if (!forwarded.contains("action") || !forwarded["action"].is_string())
            forwarded["action"] = group_action == "cookies" ? "get" : group_action;
        forwarded.erase("cookie_action");
        return;
    }
    if (internal == "network_capture" && (!forwarded.contains("action") || !forwarded["action"].is_string()))
        forwarded["action"] = "status";
    if (std::string(group_name) == "browser_network" && internal == "intercept_request")
    {
        if (forwarded.contains("intercept_action") && forwarded["intercept_action"].is_string() &&
            (!forwarded.contains("action") || !forwarded["action"].is_string()))
        {
            forwarded["action"] = forwarded["intercept_action"];
        }
        if (group_action == "delay" && (!forwarded.contains("action") || !forwarded["action"].is_string()))
            forwarded["action"] = "delay";
        else if (group_action == "conditional_intercept" && (!forwarded.contains("action") || !forwarded["action"].is_string()))
            forwarded["action"] = "log";
        forwarded.erase("intercept_action");
    }
    if (std::string(group_name) == "browser_network" && internal == "search_network_bodies")
    {
        if (!forwarded.contains("query") && forwarded.contains("search_query"))
            forwarded["query"] = forwarded["search_query"];
        if (!forwarded.contains("query") && forwarded.contains("body_search"))
            forwarded["query"] = forwarded["body_search"];
    }
    if (std::string(group_name) == "browser_network" && group_action == "list")
    {
        if (!forwarded.contains("limit") && !forwarded.contains("max_records"))
            forwarded["limit"] = bounded_browser_list_limit(params);
        if (!forwarded.contains("offset"))
            forwarded["offset"] = bounded_browser_list_offset(params);
    }
}

tool_result_t dispatch_camoufox_browser_group(
    const json& params,
    const char* group_name,
    const camoufox_action_entry_t* actions,
    size_t action_count)
{
    std::string action = lower_ascii_copy(json_string_param(params, "action", ""));
    if (action.empty())
        action = lower_ascii_copy(json_string_param(params, "operation", ""));
    if (action.empty())
        return tool_result_t::error(std::string(group_name) + " requires action");

    const camoufox_action_entry_t* action_spec = find_camoufox_action(action, actions, action_count);
    if (!action_spec)
        return tool_result_t::error("Unsupported " + std::string(group_name) + " action: " + action);

    json forwarded = camoufox_group_payload(params);
    normalize_camoufox_group_payload(group_name, action, action_spec->internal_tool, params, forwarded);
    if (std::string(action_spec->internal_tool) == "launch_browser")
        return tool_launch_browser(forwarded);
    if (std::string(action_spec->internal_tool) == "close_browser")
        return tool_close_browser(forwarded);

    const std::string internal_tool_name = action_spec->internal_tool ? action_spec->internal_tool : "";
    const bool needs_timeout_propagation =
        internal_tool_name == "navigate" ||
        internal_tool_name == "reload" ||
        internal_tool_name == "wait_for" ||
        internal_tool_name == "diagnose_navigation" ||
        internal_tool_name == "diagnose_bloxflip_matrix";
    if (needs_timeout_propagation)
    {
        const bool caller_supplied_params_timeout = params.is_object() && params.contains("timeout") && params["timeout"].is_number();
        const bool caller_supplied_forwarded_timeout = forwarded.is_object() && forwarded.contains("timeout") && forwarded["timeout"].is_number();
        if (!caller_supplied_params_timeout && !caller_supplied_forwarded_timeout)
        {
            int synthesised_timeout_ms = action_spec->default_timeout_ms - 5000;
            if (synthesised_timeout_ms < 1000)
                synthesised_timeout_ms = 1000;
            forwarded["timeout"] = synthesised_timeout_ms;
            diag::log_tagged_fmt("mcp_burp",
                "dispatch_camoufox_browser_group timeout_synthesised group=%s action=%s tool=%s default_timeout_ms=%d synthesised_timeout_ms=%d source=action_default",
                group_name,
                action.c_str(),
                internal_tool_name.c_str(),
                action_spec->default_timeout_ms,
                synthesised_timeout_ms);
        }
        else
        {
            const int caller_timeout = caller_supplied_forwarded_timeout
                ? json_int_param(forwarded, "timeout", 0)
                : json_int_param(params, "timeout", 0);
            diag::log_tagged_fmt("mcp_burp",
                "dispatch_camoufox_browser_group timeout_caller_supplied group=%s action=%s tool=%s default_timeout_ms=%d caller_timeout_ms=%d source=%s",
                group_name,
                action.c_str(),
                internal_tool_name.c_str(),
                action_spec->default_timeout_ms,
                caller_timeout,
                caller_supplied_forwarded_timeout ? "forwarded" : "params");
        }
    }

    if (internal_tool_name == "network_capture")
    {
        const std::string requested_page_id = json_string_param(forwarded, "page_id", std::string());
        if (!requested_page_id.empty())
        {
            const std::string session_id = json_string_param(params, "session_id", "default");
            auto pre_flight_status = camoufox::get_status(session_id);
            if (!bridge_status_has_page(pre_flight_status, requested_page_id))
            {
                diag::log_tagged_fmt("mcp_burp", "dispatch_camoufox_browser_group network_capture_page_not_found group=%s page_id=%s active_page_id=%s generation=%llu child_pid=%lu known_pages=%s",
                    group_name,
                    requested_page_id.c_str(),
                    pre_flight_status.active_page_id.c_str(),
                    static_cast<unsigned long long>(pre_flight_status.generation),
                    static_cast<unsigned long>(pre_flight_status.child_pid),
                    page_ids_json(pre_flight_status).dump().c_str());
                json err_data = json::object();
                err_data["error"] = "browser_network_capture_page_not_found";
                err_data["requested_page_id"] = requested_page_id;
                err_data["available_page_ids"] = page_ids_json(pre_flight_status);
                err_data["active_page_id"] = pre_flight_status.active_page_id;
                err_data["bridge_generation"] = pre_flight_status.generation;
                err_data["bridge_state"] = state_label(pre_flight_status.state);
                tool_result_t err = tool_result_t::error("browser_network_capture_page_not_found");
                err.data = std::move(err_data);
                return err;
            }
        }
    }

    tool_result_t out = tool_camoufox_passthrough(
        action_spec->internal_tool,
        forwarded,
        action_spec->default_timeout_ms);
    if (std::string(group_name) == "browser_network" && std::string(action_spec->internal_tool) == "get_request_initiator")
        return annotate_initiator_contract_result(forwarded, std::move(out));
    return out;
}

tool_result_t tool_browser_lifecycle(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"launch", "launch_browser", 60000},
        {"close", "close_browser", 30000},
        {"list", "list_pages", 15000},
        {"new", "new_page", 30000},
        {"select", "select_page", 15000},
        {"close_page", "close_page", 15000},
    };
    return dispatch_camoufox_browser_group(params, "browser_lifecycle",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_navigation(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"navigate", "navigate", 60000},
        {"diagnose", "diagnose_navigation", 60000},
        {"matrix", "diagnose_bloxflip_matrix", 180000},
        {"reload", "reload", 45000},
        {"wait", "wait_for", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_navigation",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_interaction(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"click", "click", 30000},
        {"type", "type_text", 30000},
        {"evaluate", "evaluate_js", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_interaction",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_inspect(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"screenshot", "take_screenshot", 60000},
        {"snapshot", "take_snapshot", 30000},
        {"info", "get_page_info", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_inspect",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_state(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"cookies", "cookies", 30000},
        {"storage", "get_storage", 30000},
        {"export", "export_state", 30000},
        {"import", "import_state", 60000},
        {"reset", "reset_browser_state", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_state",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_network(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"capture", "network_capture", 30000},
        {"list", "list_network_requests", 30000},
        {"get", "get_network_request", 30000},
        {"initiator", "get_request_initiator", 30000},
        {"intercept", "intercept_request", 30000},
        {"conditional_intercept", "intercept_request", 30000},
        {"delay", "intercept_request", 30000},
        {"search", "search_network_bodies", 30000},
        {"search_bodies", "search_network_bodies", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_network",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_hooks(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"hook", "hook_function", 45000},
        {"init_script", "add_init_script", 30000},
        {"preset", "inject_hook_preset", 30000},
        {"remove", "remove_hooks", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_hooks",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_instrumentation(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"manage", "instrumentation", 60000},
        {"jsvmp", "hook_jsvmp_interpreter", 60000},
        {"trace", "trace_property_access", 120000},
        {"list_files", "list_trace_files", 30000},
        {"query_file", "query_trace_file", 60000},
    };
    return dispatch_camoufox_browser_group(params, "browser_instrumentation",
        actions, sizeof(actions) / sizeof(actions[0]));
}

}

void register_camoufox_reverse_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "browser_lifecycle", "camoufox_reverse",
        "Consolidated Camoufox lifecycle management. Set action to launch, close, list, new, select, or close_page.",
            {{"action", "string", "launch|close|list|new|select|close_page", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"url", "string", "Optional URL for a new page", false},
             {"make_active", "boolean", "Make a new page active", false},
             {"headless", "boolean", "Run in headless mode", false},
             {"os_type", "string", "Windows only; non-Windows values are normalized to windows", false},
             {"locale", "string", "Browser locale such as en-US", false},
             {"proxy", "string", "Proxy URL such as http://127.0.0.1:8443", false},
             {"humanize", "boolean", "Enable humanized mouse movement", false},
             {"geoip", "boolean", "Infer geolocation from proxy IP", false},
             {"block_images", "boolean", "Block image loading", false},
             {"block_webrtc", "boolean", "Force WebRTC blocking; AiDA enforces this on", false},
             {"user_agent", "string", "Custom Camoufox user agent", false},
             {"userAgent", "string", "Alias for user_agent", false},
             {"ua_policy", "string", "camoufox_native, auto, native, or custom with user_agent", false},
             {"user_agent_profile", "string", "Alias for ua_policy", false},
             {"user_agent_mode", "string", "Alias for ua_policy", false},
             {"persistent_context", "boolean", "Use a persistent Camoufox browser context", false},
             {"profile_dir", "string", "Persistent Camoufox profile directory", false},
             {"user_data_dir", "string", "Alias for persistent profile directory", false},
             {"enable_trace", "boolean", "Enable engine-level property access tracing", false},
             {"python_executable", "string", "Optional Python path for developer sessions", false},
             {"browser_executable", "string", "Optional camoufox.exe path", false},
             {"launch_timeout_ms", "number", "Requested launch timeout in milliseconds", false},
             {"window_width", "number", "Initial browser window width", false},
             {"window_height", "number", "Initial browser window height", false}},
        tool_browser_lifecycle,
        false
    });
    register_compat(srv, {
        "browser_navigation", "camoufox_reverse",
        "Consolidated Camoufox navigation operations. Set action to navigate, diagnose, matrix, reload, or wait.",
            {{"action", "string", "navigate|diagnose|matrix|reload|wait", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"url", "string", "Target URL", false},
             {"diagnostic_label", "string", "Diagnostic navigation label such as bloxflip", false},
             {"include_screenshot_metadata", "boolean", "Collect bounded screenshot metadata for diagnostic navigation", false},
             {"restore_browser", "boolean", "Restore the previous Camoufox session after the diagnostic matrix", false},
             {"wait_until", "string", "load, domcontentloaded, or networkidle", false},
             {"selector", "string", "CSS selector to wait for", false},
             {"url_pattern", "string", "URL pattern to wait for", false},
             {"timeout", "number", "Wait timeout in milliseconds", false},
             {"pre_inject_hooks", "array", "Hook preset names to register before navigation", false},
             {"collect_response_chain", "boolean", "Record response chain", false},
             {"clear_network_capture", "boolean", "Clear stale network capture before navigating", false},
             {"capture_from_start", "boolean", "Start network capture before navigation", false},
             {"capture_body", "boolean", "Capture response bodies", false},
             {"capture_url_pattern", "string", "Network capture URL glob", false},
             {"include_title", "boolean", "Return page title when available", false},
             {"publish_to_burp", "boolean", "Publish observed browser traffic to the Burp event bus; defaults to true", false},
             {"burp_source", "string", "Source label for published browser exchanges; defaults to browser", false}},
        tool_browser_navigation,
        false
    });
    register_compat(srv, {
        "browser_interaction", "camoufox_reverse",
        "Consolidated Camoufox interaction operations. Set action to click, type, or evaluate.",
            {{"action", "string", "click|type|evaluate", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"selector", "string", "CSS selector", false},
             {"text", "string", "Text to type", false},
             {"delay", "number", "Delay between key presses in milliseconds", false},
             {"expression", "string", "JavaScript expression", false},
             {"await_promise", "boolean", "Await promise return values", false},
             {"evaluate_timeout_ms", "number", "Python-side JavaScript evaluation timeout in milliseconds", false},
             {"call_timeout_ms", "number", "End-to-end browser tool timeout in milliseconds, capped by AiDA's browser tool limit", false},
             {"timeout_ms", "number", "Alias for the end-to-end browser tool timeout", false}},
        tool_browser_interaction,
        false
    });
    register_compat(srv, {
        "browser_inspect", "camoufox_reverse",
        "Consolidated Camoufox inspection operations. Set action to screenshot, snapshot, or info.",
            {{"action", "string", "screenshot|snapshot|info", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"full_page", "boolean", "Capture the full scrollable page", false},
             {"selector", "string", "CSS selector for an element screenshot", false},
             {"save_path", "string", "Optional PNG file path", false},
             {"include_base64", "boolean", "Return bounded inline base64", false},
             {"max_base64_chars", "number", "Maximum inline base64 characters", false}},
        tool_browser_inspect,
        false
    });
    register_compat(srv, {
        "browser_state", "camoufox_reverse",
        "Consolidated Camoufox state operations. Set action to cookies, storage, export, import, or reset.",
            {{"action", "string", "cookies|storage|export|import|reset", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"domain", "string", "Cookie domain filter", false},
             {"cookie_action", "string", "Cookie operation for action=cookies: get, set, or delete; defaults to get", false},
             {"cookies_list", "array", "Cookie objects to set", false},
             {"name", "string", "Cookie name", false},
             {"storage_type", "string", "local or session", false},
             {"save_path", "string", "Destination JSON path", false},
             {"state_path", "string", "Source JSON path", false},
             {"clear_persistent_hooks", "boolean", "Remove persistent init scripts", false},
             {"clear_network_capture", "boolean", "Clear network capture buffer and stop captures", false},
             {"clear_active_routes", "boolean", "Clear instrumentation routes", false},
             {"clear_cookies", "boolean", "Clear browser cookies", false},
             {"clear_storage", "boolean", "Clear localStorage and sessionStorage", false}},
        tool_browser_state,
        false
    });
    register_compat(srv, {
        "browser_network", "camoufox_reverse",
        "Consolidated Camoufox network operations. Set action to capture, list, get, initiator, intercept, conditional_intercept, delay, search, or search_bodies.",
            {{"action", "string", "capture|list|get|initiator|intercept|conditional_intercept|delay|search|search_bodies", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted; use payload.action for capture start, stop, clear, or status", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"marker", "string", "Deterministic request marker used to clear and match hook logs", false},
             {"request_id", "number", "Captured request id", false},
             {"url_pattern", "string", "URL glob pattern", false},
             {"url_filter", "string", "Substring filter for URLs", false},
             {"url_prefix", "string", "Prefix filter for request URLs", false},
             {"url_contains_domain", "string", "Domain substring filter", false},
             {"url_contains", "string", "Request URL substring predicate for conditional interception", false},
             {"initiator_contains", "string", "Initiator or frame URL substring predicate for conditional interception", false},
             {"initiator_url_contains", "string", "Alias for initiator_contains", false},
             {"frame_url_contains", "string", "Frame URL substring predicate for conditional interception", false},
             {"frame_url_prefix", "string", "Frame URL prefix predicate for conditional interception", false},
             {"method", "string", "HTTP method filter", false},
             {"resource_type", "string", "Resource type filter", false},
             {"status_code", "number", "HTTP status code filter", false},
             {"conditions", "object", "Conditional interception predicates for URL, method, resource type, page, session, initiator/frame URL, headers, status, and bounded request/response body matches", false},
             {"intercept_action", "string", "Route action for conditional_intercept: log, delay, block, modify, mock, or stop", false},
             {"delay_ms", "number", "Bounded delay to inject before continuing or fulfilling a matched route", false},
             {"max_delay_ms", "number", "Maximum accepted delay cap; the reverse side clamps to its hard upper bound", false},
             {"search_query", "string", "Request/response body search query", false},
             {"body_search", "string", "Alias for search_query", false},
             {"body_sha256", "string", "SHA-256 digest of the bounded body prefix to match", false},
             {"search_scope", "string", "Body search scope: request, response, or both", false},
             {"scope", "string", "Alias for search_scope in search actions", false},
             {"case_sensitive", "boolean", "Use case-sensitive body and header matching", false},
             {"hash_only", "boolean", "Return only body hashes and match metadata without snippets for search actions", false},
             {"snippet_chars", "number", "Maximum redacted snippet characters around a search hit", false},
             {"max_matches", "number", "Maximum body-search matches to return", false},
             {"header_contains", "object", "Request or response header substring predicates for search and interception", false},
             {"response_header_contains", "object", "Response header substring predicates for conditional interception", false},
             {"request_body_contains", "string", "Request body predicate for conditional interception", false},
             {"response_body_contains", "string", "Response body predicate for conditional interception", false},
             {"limit", "number", "Maximum list results to return, default 200 and capped at 500", false},
             {"offset", "number", "Zero-based list result offset", false},
             {"max_records", "number", "Alias for limit", false},
             {"capture_body", "boolean", "Capture response bodies", false},
             {"include_body", "boolean", "Include response body", false},
             {"include_headers", "boolean", "Include request and response headers", false},
             {"max_body_size", "number", "Maximum body characters", false},
             {"publish_to_burp", "boolean", "Publish observed browser traffic to the Burp event bus; defaults to true", false},
             {"burp_source", "string", "Source label for published browser exchanges; defaults to browser", false},
             {"modify_headers", "object", "Headers to add or override", false},
             {"modify_body", "string", "Replacement request body", false},
             {"mock_response", "object", "Mock response object", false}},
        tool_browser_network,
        false
    });
    register_compat(srv, {
        "browser_hooks", "camoufox_reverse",
        "Consolidated Camoufox hook operations. Set action to hook, init_script, preset, or remove.",
            {{"action", "string", "hook|init_script|preset|remove", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"function_path", "string", "Path such as window.encrypt", false},
             {"mode", "string", "intercept or trace", false},
             {"hook_code", "string", "Custom hook code", false},
             {"position", "string", "before, after, or replace", false},
             {"non_overridable", "boolean", "Install a non-overridable descriptor", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"log_args", "boolean", "Capture function arguments", false},
             {"log_return", "boolean", "Capture return values", false},
             {"log_stack", "boolean", "Capture stack traces", false},
             {"max_captures", "number", "Maximum captures to keep", false},
             {"script", "string", "JavaScript source", false},
             {"name", "string", "Optional script or preset name", false},
             {"preset", "string", "Built-in hook preset", false},
             {"keep_persistent", "boolean", "Keep persistent init scripts registered", false}},
        tool_browser_hooks,
        false
    });
    register_compat(srv, {
        "browser_instrumentation", "camoufox_reverse",
        "Consolidated Camoufox instrumentation operations. Set action to manage, jsvmp, trace, list_files, or query_file.",
            {{"action", "string", "manage|jsvmp|trace|list_files|query_file", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted; use payload.action for instrumentation install, status, log, stop, or reload", false},
             {"session_id", "string", "Browser session id", false},
             {"script_url", "string", "Optional script URL focus", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"mode", "string", "Instrumentation or trace mode", false},
             {"track_calls", "boolean", "Track calls", false},
             {"track_props", "boolean", "Track property access", false},
             {"track_reflect", "boolean", "Track Reflect APIs", false},
             {"proxy_objects", "array", "Global objects to proxy", false},
             {"max_entries", "number", "Maximum log entries", false},
             {"url_pattern", "string", "URL glob to instrument", false},
             {"tag", "string", "Instrumentation tag", false},
             {"rewrite_member_access", "boolean", "Rewrite member property access", false},
             {"rewrite_calls", "boolean", "Rewrite calls", false},
             {"max_rewrites", "number", "Maximum rewrites", false},
             {"fallback_on_error", "boolean", "Fall back when AST rewrite fails", false},
             {"ignore_csp", "boolean", "Bypass CSP for injected scripts", false},
             {"clear_log", "boolean", "Clear log before reload", false},
             {"wait_until", "string", "Navigation wait state for reload", false},
             {"tag_filter", "string", "Filter instrumentation log by tag", false},
             {"type_filter", "string", "Filter instrumentation log by event type", false},
             {"key_filter", "string", "Filter instrumentation log by key", false},
             {"limit", "number", "Maximum events or files", false},
             {"clear", "boolean", "Clear log after retrieval", false},
             {"filter_property_names", "array", "Property-name allowlist", false},
             {"filter_object_names", "array", "Object-name allowlist", false},
             {"max_file_size", "number", "Maximum script size to rewrite", false},
             {"on_oversized", "string", "Oversized script policy", false},
             {"duration", "number", "Trace duration in seconds", false},
             {"filter_object", "string", "Trace object filter", false},
             {"search_query", "string", "Trace search query", false},
             {"bucket_ms", "number", "Timeline bucket size", false},
             {"collect_values", "boolean", "Collect property values", false},
             {"file_path", "string", "Trace JSONL path", false}},
        tool_browser_instrumentation,
        false
    });
    register_compat(srv, {
        "browser_service_worker", "camoufox_reverse",
        "Camoufox service-worker diagnostics. Set action to list, get_source, unregister, diagnostic_route, or diagnostic_post_message.",
            {{"action", "string", "list|get_source|unregister|diagnostic_route|diagnostic_post_message", true},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"script_url", "string", "Service-worker script URL substring or source URL", false},
             {"url_pattern", "string", "URL glob for diagnostic page/context route", false},
             {"intercept_action", "string", "Diagnostic route action: log, block, modify, mock, or stop", false},
             {"modify_headers", "object", "Headers to add or override for diagnostic_route modify", false},
             {"modify_body", "string", "Replacement request body for diagnostic_route modify", false},
             {"mock_response", "object", "Mock response for diagnostic_route mock", false},
             {"payload", "object", "Diagnostic postMessage payload", false},
             {"payload_json", "object", "Alias for diagnostic postMessage payload", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("browser_service_worker", params, 30000);
        },
        false
    });
    register_compat(srv, {
        "browser_fingerprint_spoof", "camoufox_reverse",
        "Camoufox fingerprint spoofing and verification for canvas, WebGL, audio, fonts, timezone, geolocation, screen/viewport, battery, sensors, and navigator consistency.",
            {{"action", "string", "canvas_spoof|webgl_spoof|audio_spoof|font_spoof|timezone_spoof|geolocation_spoof|screen_viewport_spoof|battery_spoof|sensors_spoof|navigator_spoof|verify", true},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"mode", "string", "noise, block, or custom for canvas/audio spoofing", false},
             {"noise_level", "number", "Noise level for canvas/audio spoofing", false},
             {"renderer", "string", "Spoofed WebGL renderer", false},
             {"vendor", "string", "Spoofed WebGL or navigator vendor", false},
             {"unmasked_renderer", "string", "Spoofed unmasked WebGL renderer", false},
             {"unmasked_vendor", "string", "Spoofed unmasked WebGL vendor", false},
             {"block_fonts", "array", "Font names to block", false},
             {"allow_fonts", "array", "Font names to allow", false},
             {"timezone", "string", "IANA timezone identifier", false},
             {"latitude", "number", "Spoofed geolocation latitude", false},
             {"longitude", "number", "Spoofed geolocation longitude", false},
             {"accuracy", "number", "Spoofed geolocation accuracy", false},
             {"width", "number", "Screen and viewport width", false},
             {"height", "number", "Screen and viewport height", false},
             {"avail_width", "number", "Available screen width", false},
             {"avail_height", "number", "Available screen height", false},
             {"color_depth", "number", "Screen color depth", false},
             {"pixel_depth", "number", "Screen pixel depth", false},
             {"device_scale_factor", "number", "Device pixel ratio", false},
             {"charging", "boolean", "Battery charging state", false},
             {"level", "number", "Battery level between 0 and 1", false},
             {"charging_time", "number", "Battery charging time seconds", false},
             {"discharging_time", "number", "Battery discharging time seconds", false},
             {"sensor_permission", "string", "Sensor permission state: granted, denied, or prompt", false},
             {"acceleration_x", "number", "DeviceMotion acceleration X", false},
             {"acceleration_y", "number", "DeviceMotion acceleration Y", false},
             {"acceleration_z", "number", "DeviceMotion acceleration Z", false},
             {"alpha", "number", "DeviceOrientation alpha", false},
             {"beta", "number", "DeviceOrientation beta", false},
             {"gamma", "number", "DeviceOrientation gamma", false},
             {"languages", "array", "Navigator languages array", false},
             {"platform", "string", "Navigator platform", false},
             {"device_memory", "number", "Navigator deviceMemory", false},
             {"hardware_concurrency", "number", "Navigator hardwareConcurrency", false},
             {"plugins", "array", "Navigator plugin names", false},
             {"mime_types", "array", "Navigator MIME types", false},
             {"connection_type", "string", "Navigator connection type", false},
             {"effective_type", "string", "Navigator connection effectiveType", false},
             {"downlink", "number", "Navigator connection downlink", false},
             {"rtt", "number", "Navigator connection RTT", false},
             {"save_data", "boolean", "Navigator connection saveData", false},
             {"custom", "object", "Action-specific custom spoof configuration", false},
             {"persistent", "boolean", "Persist init script across navigations", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("browser_fingerprint_spoof", params, 45000);
        },
        false
    });
    register_compat(srv, {
        "get_console_logs", "camoufox_reverse",
        "Return console output collected from Camoufox pages.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id filter", false},
             {"level", "string", "Filter by log, warn, error, or info", false},
             {"keyword", "string", "Filter logs containing this text", false},
             {"clear", "boolean", "Clear the log buffer after retrieval", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("get_console_logs", params, 30000);
        },
        true
    });
    register_compat(srv, {
        "scripts", "camoufox_reverse",
        "List loaded scripts, get source for one script, or save a script to disk.",
            {{"action", "string", "list, get, or save", true},
             {"url", "string", "Script URL for get or save", false},
             {"save_path", "string", "Destination path for save", false},
             {"page_id", "string", "Stable AiDA page id", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("scripts", params, 30000);
        },
        false
    });
    register_compat(srv, {
        "search_code", "camoufox_reverse",
        "Search loaded scripts for a keyword.",
            {{"keyword", "string", "Keyword to search for", true},
             {"script_url", "string", "Optional script URL to limit the search", false},
             {"context_chars", "number", "Characters of context around matches", false},
             {"context_lines", "number", "Lines of context around matches", false},
             {"max_results", "number", "Maximum matches", false},
             {"page_id", "string", "Stable AiDA page id", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("search_code", params, 30000);
        },
        true
    });
    register_compat(srv, {
        "compare_env", "camoufox_reverse",
        "Collect browser environment fingerprint data for comparison.",
        {{"properties", "array", "Specific properties to check", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("compare_env", params, 65000);
        },
        true
    });
    register_compat(srv, {
        "check_environment", "camoufox_reverse",
        "Run reverse-MCP dependency, browser, privacy, and runtime state checks.",
        {{"session_id", "string", "Browser session id", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("check_environment", params, 30000);
        },
        true
    });
    register_compat(srv, {
        "verify_signer_offline", "camoufox_reverse",
        "Verify a candidate JavaScript signing function against captured samples offline.",
            {{"signer_code", "string", "Candidate signer source", true},
             {"samples", "array", "Request/signature samples", true},
             {"compare_params", "array", "Parameter names to compare", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("verify_signer_offline", params, 30000);
        },
        true
    });
    register_compat(srv, {
        "analyze_cookie_sources", "camoufox_reverse",
        "Attribute observed cookies to HTTP headers or JavaScript writes.",
            {{"name_filter", "string", "Optional cookie-name filter", false},
             {"page_id", "string", "Stable AiDA page id", false}},
        [](const json& params) -> tool_result_t {
            return tool_camoufox_passthrough("analyze_cookie_sources", params, 30000);
        },
        true
    });
}

void register_camoufox_tools(mcp_standalone::server_t& srv)
{
    register_camoufox_reverse_tools(srv);
}

}
}
