#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <intrin.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#include "mcp_standalone.hpp"
#include "compat/c03_compatibility_registration.hpp"
#include "mcp_capacity_governor_diag.hpp"
#include "downstream_producer_governor.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "sandbox.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../network/burp/audit_trail.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../session/analysis_session.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../tools/command_sessions.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../../helpers/diag_log.hpp"
#include <httplib.h>
#include <sstream>
#include <fstream>
#include <random>
#include <set>
#include <queue>
#include <deque>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <future>
#include <limits>
#include <memory>
#include <map>
#include <shared_mutex>
#include <thread>
#include <vector>
#include "../diagnostics/metadata_ring.hpp"
#include "../diagnostics/diagnostic_snapshot.hpp"
#include "../diagnostics/wer_correlation.hpp"
#include "../infra/executor.hpp"
#include "../infra/taskflow_evaluation.hpp"

namespace mcp_standalone
{
static std::string json_dump_safe(const json& j, int indent = -1);
static std::string sanitize_utf8(const std::string& input);

namespace
{
    static std::uint64_t mcp_now_ms();
    std::atomic<bool> g_ide_lifecycle_ready{false};
    constexpr std::uint64_t kMcpDefaultToolTimeoutMs = 45000;
    constexpr std::uint64_t kMcpMinToolTimeoutMs = 500;
    constexpr std::uint64_t kMcpMaxToolTimeoutMs = 120000;
    constexpr std::uint64_t kMcpBrowserToolMaxTimeoutMs = 300000;
    constexpr std::uint64_t kMcpBrowserLongActionTimeoutMs = 180000;
    constexpr std::uint64_t kMcpBrowserCleanupGraceMs = 30000;
    constexpr std::uint64_t kMcpBatchWaitTimeoutMs = 60000;
    constexpr std::uint64_t kMcpPolicyLockMaxWaitMs = 5000;
    constexpr std::uint64_t kMcpPolicyLockPollMs = 25;
    constexpr std::uint64_t kMcpPolicyLockLogEveryMs = 500;
    constexpr std::size_t kMcpMaxBatchItems = 4096;
    constexpr std::size_t kMcpPayloadMaxLength = 64u * 1024u * 1024u;
    constexpr std::size_t kMcpValidationTextMaxBytes = 384;
    constexpr std::size_t kMcpValidationErrorCodeMaxBytes = 96;
    constexpr std::size_t kMcpValidationJsonMaxDepth = 6;
    constexpr std::size_t kMcpValidationJsonMaxEntries = 16;
    constexpr std::size_t kMcpValidationJsonMaxNodes = 64;
    constexpr std::size_t kMcpValidationDataMaxBytes = 768;
    constexpr std::size_t kMcpValidationDetailsMaxBytes = 768;
    constexpr std::size_t kMcpValidationFailureDetailsMaxBytes = 2048;
    constexpr std::size_t kSseMaxQueuedEvents = 4096;
    constexpr DWORD kSseSessionMaxAgeMs = 60u * 60u * 1000u;
    std::atomic<std::uint64_t> g_http_request_seq{0};
    std::atomic<int> g_active_http_requests{0};
    std::atomic<std::uint64_t> g_mcp_batch_seq{0};
    std::atomic<std::uint64_t> g_tool_call_seq{0};
    std::atomic<std::uint64_t> g_stream_seq{0};
    std::atomic<int> g_active_streams{0};
    std::atomic<size_t> g_cached_external_tool_count{0};
    std::atomic<bool> g_cached_health_ready{false};
    thread_local std::uint64_t tls_http_request_id = 0;
    thread_local std::uint64_t tls_http_request_start_tick = 0;
    thread_local bool tls_http_request_counted = false;
    thread_local bool tls_local_capability_authenticated = false;
    std::mutex g_pre_dispatch_validation_hook_mtx;
    tool_validation_hook_t g_pre_dispatch_validation_hook;
    thread_local std::size_t tls_pre_dispatch_validation_depth = 0;

    class scoped_pre_dispatch_validation_t
    {
    public:
        explicit scoped_pre_dispatch_validation_t(bool active)
            : active_(active)
        {
            if (active_)
                ++tls_pre_dispatch_validation_depth;
        }

        ~scoped_pre_dispatch_validation_t()
        {
            if (active_)
                --tls_pre_dispatch_validation_depth;
        }

        scoped_pre_dispatch_validation_t(const scoped_pre_dispatch_validation_t&) = delete;
        scoped_pre_dispatch_validation_t& operator=(const scoped_pre_dispatch_validation_t&) = delete;

    private:
        bool active_ = false;
    };

    static bool pre_dispatch_validation_active()
    {
        return tls_pre_dispatch_validation_depth != 0;
    }

    static std::string normalize_validation_text(const std::string& value,
                                                 const char* fallback,
                                                 std::size_t maximum)
    {
        const std::size_t source_limit = maximum / 3;
        std::string normalized = sanitize_utf8(value.substr(0, source_limit));
        return normalized.empty() ? std::string(fallback) : normalized;
    }

    static std::string normalize_validation_error_code(const std::string& value)
    {
        std::string normalized;
        normalized.reserve(std::min(value.size(), kMcpValidationErrorCodeMaxBytes));
        for (const unsigned char ch : value) {
            if (normalized.size() == kMcpValidationErrorCodeMaxBytes)
                break;
            if (std::isalnum(ch))
                normalized.push_back(static_cast<char>(std::toupper(ch)));
            else if (ch == '_' || ch == '-')
                normalized.push_back('_');
        }
        return normalized.empty() ? std::string("MCP_TOOL_INPUT_VALIDATION_FAILED") : normalized;
    }

    static json normalize_validation_json_node(const json& value,
                                               std::size_t& remaining_nodes,
                                               std::size_t depth)
    {
        json normalized;
        if (remaining_nodes == 0) {
            normalized = json{{"truncated", true}, {"reason", "node_limit"}};
        } else if (depth >= kMcpValidationJsonMaxDepth) {
            normalized = json{{"truncated", true}, {"reason", "depth_limit"}};
        } else {
            --remaining_nodes;
            if (value.is_object()) {
                normalized = json::object();
                std::size_t emitted = 0;
                for (auto it = value.begin(); it != value.end(); ++it) {
                    if (emitted == kMcpValidationJsonMaxEntries) {
                        normalized["truncated"] = true;
                        break;
                    }
                    normalized[normalize_validation_text(it.key(), "field", 96)] =
                        normalize_validation_json_node(it.value(), remaining_nodes, depth + 1);
                    ++emitted;
                }
            } else if (value.is_array()) {
                normalized = json::array();
                std::size_t emitted = 0;
                for (const auto& element : value) {
                    if (emitted == kMcpValidationJsonMaxEntries) {
                        normalized.push_back(json{{"truncated", true}});
                        break;
                    }
                    normalized.push_back(normalize_validation_json_node(element, remaining_nodes, depth + 1));
                    ++emitted;
                }
            } else if (value.is_string()) {
                normalized = normalize_validation_text(value.get_ref<const std::string&>(), "", kMcpValidationTextMaxBytes);
            } else if (value.is_boolean() || value.is_number() || value.is_null()) {
                normalized = value;
            } else {
                normalized = json{{"truncated", true}, {"reason", "unsupported_value"}};
            }
        }
        return normalized;
    }

    static json normalize_validation_json(const json& value,
                                          std::size_t maximum_bytes)
    {
        std::size_t remaining_nodes = kMcpValidationJsonMaxNodes;
        json normalized = normalize_validation_json_node(value, remaining_nodes, 0);
        try {
            if (normalized.dump().size() <= maximum_bytes)
                return normalized;
        } catch (...) {
        }
        return json{{"truncated", true}, {"reason", "size_limit"}};
    }

    static tool_result_t validation_failure_result(const tool_def_t& tool,
                                                   const char* reason,
                                                   const char* text,
                                                   const char* code)
    {
        return tool_result_t::error(
            text,
            code,
            json{{"tool", normalize_validation_text(tool.name, "unknown", 128)},
                 {"reason", reason},
                 {"disposition", "not_started"}});
    }

    static tool_result_t normalize_validation_rejection(const tool_def_t& tool,
                                                        const tool_result_t& result)
    {
        const json data = normalize_validation_json(result.data, kMcpValidationDataMaxBytes);
        const json details = normalize_validation_json(result.error_details, kMcpValidationDetailsMaxBytes);
        json envelope = {
            {"tool", normalize_validation_text(tool.name, "unknown", 128)},
            {"reason", "validator_rejected"},
            {"disposition", "not_started"},
            {"validator_data", data},
            {"validator_details", details}
        };
        envelope = normalize_validation_json(envelope, kMcpValidationFailureDetailsMaxBytes);
        return {false,
                normalize_validation_text(result.text, "Tool input validation failed.", kMcpValidationTextMaxBytes),
                data,
                normalize_validation_error_code(result.error_code),
                envelope};
    }

    static bool validation_cancelled_or_expired(const tool_def_t& tool,
                                                tool_result_t* failure)
    {
        const std::uint64_t deadline = current_call_deadline_ms();
        if (deadline != 0 && mcp_now_ms() >= deadline) {
            if (failure) {
                *failure = validation_failure_result(
                    tool,
                    "deadline_exceeded",
                    "Tool input validation deadline expired before dispatch.",
                    "MCP_TOOL_INPUT_VALIDATION_DEADLINE_EXCEEDED");
            }
            return true;
        }
        if (current_call_cancelled()) {
            if (failure) {
                *failure = validation_failure_result(
                    tool,
                    "cancelled",
                    "Tool input validation was cancelled before dispatch.",
                    "MCP_TOOL_INPUT_VALIDATION_CANCELLED");
            }
            return true;
        }
        return false;
    }

    static bool supplied_tool_arguments_are_non_object(const json& params)
    {
        return params.is_object() && params.contains("arguments") && !params["arguments"].is_object();
    }

    static tool_result_t non_object_tool_arguments_failure()
    {
        return tool_result_t::error(
            "Tool arguments must be a JSON object.",
            "MCP_TOOL_ARGUMENTS_MUST_BE_OBJECT",
            json{{"reason", "arguments_must_be_object"}, {"disposition", "not_started"}});
    }

    static bool validate_pre_dispatch_tool_input(const tool_def_t& tool,
                                                  const json& arguments,
                                                  tool_result_t* failure,
                                                  bool* hook_invoked = nullptr)
    {
        if (hook_invoked)
            *hook_invoked = false;
        if (tool.input_schema.is_null())
            return true;

        if (validation_cancelled_or_expired(tool, failure))
            return false;

        tool_validation_hook_t hook;
        {
            std::lock_guard<std::mutex> lk(g_pre_dispatch_validation_hook_mtx);
            hook = g_pre_dispatch_validation_hook;
        }
        if (!hook) {
            if (failure) {
                *failure = validation_failure_result(
                    tool,
                    "validator_unavailable",
                    "Tool input validation is unavailable.",
                    "MCP_TOOL_INPUT_VALIDATION_UNAVAILABLE");
            }
            return false;
        }
        if (validation_cancelled_or_expired(tool, failure))
            return false;
        if (hook_invoked)
            *hook_invoked = true;

        try {
            tool_result_t result = hook(tool, arguments);
            if (validation_cancelled_or_expired(tool, failure))
                return false;
            if (result.success) {
                return true;
            }
            if (failure)
                *failure = normalize_validation_rejection(tool, result);
            return false;
        } catch (...) {
            if (failure) {
                *failure = validation_failure_result(
                    tool,
                    "validator_exception",
                    "Tool input validation failed.",
                    "MCP_TOOL_INPUT_VALIDATION_FAILED");
            }
            return false;
        }
    }

    struct mcp_route_identity_t
    {
        std::uint64_t http_request_id = 0;
        std::string surface;
        std::string route;
        std::string path;
        std::string http_method;
        std::string transport;
        std::string remote;
        std::string principal_id;
        std::string principal_source;
        std::string session_id;
        std::string session_hash;
        std::string session_source;
        std::string user_agent;
        std::string origin;
        std::string accept;
        std::string content_type;
        std::string protocol_version;
        bool authorization_present = false;
        std::size_t body_len = 0;
    };

    thread_local mcp_route_identity_t tls_route_identity;

    struct server_worker_lifetime_t {
        aida::infra::win_thread::joinable_thread_t thread;
        std::atomic<std::uint32_t> worker_tid{0};
        std::mutex mtx;
        std::condition_variable cv;
        bool start_completed = false;
        bool start_succeeded = false;
    };

    struct server_worker_lifetime_registry_t {
        std::mutex mtx;
        std::map<server_t*, std::shared_ptr<server_worker_lifetime_t>> lifetimes;
    };

    static server_worker_lifetime_registry_t& server_worker_lifetime_registry()
    {
        static auto* registry = new server_worker_lifetime_registry_t();
        return *registry;
    }

    static std::shared_ptr<server_worker_lifetime_t> find_server_worker_lifetime(server_t* owner)
    {
        auto& registry = server_worker_lifetime_registry();
        std::lock_guard<std::mutex> lk(registry.mtx);
        auto it = registry.lifetimes.find(owner);
        return it == registry.lifetimes.end() ? nullptr : it->second;
    }

    static bool install_server_worker_lifetime(server_t* owner, const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        auto& registry = server_worker_lifetime_registry();
        std::lock_guard<std::mutex> lk(registry.mtx);
        auto inserted = registry.lifetimes.emplace(owner, state);
        return inserted.second;
    }

    static void erase_server_worker_lifetime(server_t* owner, const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        auto& registry = server_worker_lifetime_registry();
        std::lock_guard<std::mutex> lk(registry.mtx);
        auto it = registry.lifetimes.find(owner);
        if (it != registry.lifetimes.end() && it->second == state)
            registry.lifetimes.erase(it);
    }

    static void erase_server_worker_lifetime(const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        auto& registry = server_worker_lifetime_registry();
        std::lock_guard<std::mutex> lk(registry.mtx);
        for (auto it = registry.lifetimes.begin(); it != registry.lifetimes.end(); ++it) {
            if (it->second == state) {
                registry.lifetimes.erase(it);
                return;
            }
        }
    }

    static void mark_server_worker_start(const std::shared_ptr<server_worker_lifetime_t>& state, bool succeeded)
    {
        if (!state)
            return;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->start_succeeded = succeeded;
            state->start_completed = true;
        }
        state->cv.notify_all();
    }

    static bool wait_server_worker_start(const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        if (!state)
            return false;
        std::unique_lock<std::mutex> lk(state->mtx);
        return state->cv.wait_for(lk, std::chrono::seconds(10), [state]() { return state->start_completed; }) && state->start_succeeded;
    }

    static bool server_worker_is_current(server_t* owner)
    {
        const auto state = find_server_worker_lifetime(owner);
        return state && state->worker_tid.load(std::memory_order_acquire) == static_cast<std::uint32_t>(GetCurrentThreadId());
    }

    static std::uint64_t mcp_now_ms()
    {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    static std::string fnv1a64_hex(const std::string& value)
    {
        std::uint64_t h = 1469598103934665603ull;
        for (unsigned char c : value) {
            h ^= static_cast<std::uint64_t>(c);
            h *= 1099511628211ull;
        }
        char buf[17] = {};
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%016llx", static_cast<unsigned long long>(h));
        return std::string(buf);
    }

    static const char* current_mcp_principal()
    {
        return tls_route_identity.principal_id.empty() ? "<none>" : tls_route_identity.principal_id.c_str();
    }

    static const char* current_mcp_session_hash()
    {
        return tls_route_identity.session_hash.empty() ? "<none>" : tls_route_identity.session_hash.c_str();
    }

    static const char* current_mcp_transport()
    {
        return tls_route_identity.transport.empty() ? "<none>" : tls_route_identity.transport.c_str();
    }

    static const char* current_mcp_route()
    {
        return tls_route_identity.route.empty() ? "<none>" : tls_route_identity.route.c_str();
    }

    class scoped_mcp_route_identity_t
    {
    public:
        explicit scoped_mcp_route_identity_t(const mcp_route_identity_t& identity)
            : previous_(tls_route_identity)
        {
            tls_route_identity = identity;
        }

        ~scoped_mcp_route_identity_t()
        {
            tls_route_identity = previous_;
        }

        scoped_mcp_route_identity_t(const scoped_mcp_route_identity_t&) = delete;
        scoped_mcp_route_identity_t& operator=(const scoped_mcp_route_identity_t&) = delete;

    private:
        mcp_route_identity_t previous_;
    };

    struct mcp_concurrency_config_t
    {
        std::size_t http_worker_threads = 16;
        std::size_t http_max_queued_requests = 4096;
        std::size_t batch_worker_threads = 8;
        std::size_t batch_max_queued_requests = 4096;
        std::size_t tool_worker_threads = 8;
        std::size_t tool_max_queued_requests = 4096;
        std::size_t max_concurrent_streams = 16;
        std::size_t max_concurrent_streams_per_principal = 4;
        std::size_t hardware_threads = 16;
    };

    static std::size_t mcp_hardware_threads()
    {
        const unsigned n = std::thread::hardware_concurrency();
        return n == 0 ? std::size_t{16} : static_cast<std::size_t>(n);
    }

    static std::size_t clamp_size_value(std::uint64_t value, std::size_t min_value, std::size_t max_value)
    {
        if (max_value < min_value)
            max_value = min_value;
        if (value < static_cast<std::uint64_t>(min_value))
            return min_value;
        if (value > static_cast<std::uint64_t>(max_value))
            return max_value;
        return static_cast<std::size_t>(value);
    }

    static std::size_t scaled_worker_count(std::size_t floor_value, std::size_t per_core, std::size_t cap_value)
    {
        const std::size_t hw = mcp_hardware_threads();
        std::size_t scaled = cap_value;
        if (per_core != 0 && hw <= cap_value / per_core)
            scaled = hw * per_core;
        return clamp_size_value((std::max)(floor_value, scaled), floor_value, cap_value);
    }

    static std::size_t read_size_env_or_default(const char* name, std::size_t fallback, std::size_t min_value, std::size_t max_value)
    {
        if (!name || !name[0])
            return clamp_size_value(fallback, min_value, max_value);
        char buf[64] = {};
        const DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
        if (n == 0 || n >= static_cast<DWORD>(sizeof(buf)))
            return clamp_size_value(fallback, min_value, max_value);
        try {
            const std::uint64_t parsed = static_cast<std::uint64_t>(std::stoull(std::string(buf), nullptr, 0));
            return clamp_size_value(parsed, min_value, max_value);
        } catch (...) {
            return clamp_size_value(fallback, min_value, max_value);
        }
    }

    static mcp_concurrency_config_t build_mcp_concurrency_config()
    {
        mcp_concurrency_config_t cfg;
        cfg.hardware_threads = mcp_hardware_threads();
        cfg.http_worker_threads = read_size_env_or_default("AIDA_MCP_HTTP_WORKERS", scaled_worker_count(8, 2, 32), 1, 1024);
        cfg.http_max_queued_requests = read_size_env_or_default("AIDA_MCP_HTTP_QUEUE", 4096, 64, 262144);
        cfg.batch_worker_threads = read_size_env_or_default("AIDA_MCP_BATCH_WORKERS", scaled_worker_count(4, 1, 16), 1, 768);
        cfg.batch_max_queued_requests = read_size_env_or_default("AIDA_MCP_BATCH_QUEUE", 4096, 64, 262144);
        cfg.tool_worker_threads = read_size_env_or_default("AIDA_MCP_TOOL_WORKERS", scaled_worker_count(4, 1, 16), 1, 768);
        cfg.tool_max_queued_requests = read_size_env_or_default("AIDA_MCP_TOOL_QUEUE", 4096, 64, 262144);
        const std::size_t stream_cap = (std::max)(std::size_t{16}, (std::min)(std::size_t{512}, cfg.http_worker_threads));
        const std::size_t stream_floor = (std::min)(std::size_t{16}, stream_cap);
        const std::size_t stream_scaled = cfg.hardware_threads <= stream_cap / 2 ? cfg.hardware_threads * 2 : stream_cap;
        const std::size_t stream_fallback = clamp_size_value((std::max)(stream_floor, stream_scaled), 1, stream_cap);
        cfg.max_concurrent_streams = read_size_env_or_default("AIDA_MCP_MAX_STREAMS", stream_fallback, 1, stream_cap);
        const std::size_t principal_stream_fallback = clamp_size_value((std::min<std::size_t>)(4, cfg.max_concurrent_streams), 1, cfg.max_concurrent_streams);
        cfg.max_concurrent_streams_per_principal = read_size_env_or_default("AIDA_MCP_MAX_STREAMS_PER_PRINCIPAL", principal_stream_fallback, 1, cfg.max_concurrent_streams);
        return cfg;
    }

    static const mcp_concurrency_config_t& mcp_concurrency_config()
    {
        static const mcp_concurrency_config_t cfg = build_mcp_concurrency_config();
        return cfg;
    }

    struct mcp_ingress_principal_counts_t
    {
        std::size_t active = 0;
        std::size_t queued = 0;
        std::size_t streams = 0;
    };

    struct mcp_ingress_snapshot_t
    {
        std::size_t global_active = 0;
        std::size_t global_queued = 0;
        std::size_t global_streams = 0;
        std::size_t principal_active = 0;
        std::size_t principal_queued = 0;
        std::size_t principal_streams = 0;
        bool lock_busy = false;
    };

    std::mutex g_mcp_ingress_capacity_mtx;
    std::condition_variable g_mcp_ingress_capacity_cv;
    std::map<std::string, mcp_ingress_principal_counts_t> g_mcp_ingress_by_principal;
    std::map<std::string, mcp_ingress_principal_counts_t> g_mcp_ingress_by_route;
    std::map<std::string, mcp_ingress_principal_counts_t> g_mcp_ingress_by_route_principal;
    std::map<std::string, std::uint64_t> g_mcp_ingress_rejections_by_route_reason;
    std::atomic<std::size_t> g_mcp_ingress_active{0};
    std::atomic<std::size_t> g_mcp_ingress_queued{0};
    std::atomic<std::size_t> g_mcp_ingress_streams{0};
    std::atomic<std::uint64_t> g_mcp_ingress_rejections_total{0};
    constexpr std::uint64_t kMcpIngressQueueWaitMs = 25;

    static std::string mcp_ingress_principal_key(const std::string& principal)
    {
        return principal.empty() || principal == "<none>" ? std::string("external_mcp") : capacity_diag::clean_label(principal, 160);
    }

    static std::string mcp_ingress_route_key(const std::string& route)
    {
        return route.empty() ? std::string("<unknown>") : capacity_diag::clean_label(route, 120);
    }

    static std::string mcp_ingress_route_principal_key(const std::string& route, const std::string& principal)
    {
        return mcp_ingress_route_key(route) + "\x1f" + mcp_ingress_principal_key(principal);
    }

    static void mcp_ingress_drop_empty_locked(std::map<std::string, mcp_ingress_principal_counts_t>& counts, const std::string& key)
    {
        auto it = counts.find(key);
        if (it != counts.end() && it->second.active == 0 && it->second.queued == 0 && it->second.streams == 0)
            counts.erase(it);
    }

    static void mcp_ingress_record_rejection(const std::string& route, const std::string& reason)
    {
        g_mcp_ingress_rejections_total.fetch_add(1u, std::memory_order_acq_rel);
        std::lock_guard<std::mutex> lk(g_mcp_ingress_capacity_mtx);
        ++g_mcp_ingress_rejections_by_route_reason[mcp_ingress_route_key(route) + "|" + (reason.empty() ? std::string("rejected") : capacity_diag::clean_label(reason, 96))];
    }

    class mcp_ingress_admission_t
    {
    public:
        mcp_ingress_admission_t(std::uint64_t request_id,
                                std::string route,
                                std::string method,
                                std::string transport,
                                std::string principal,
                                bool stream)
            : request_id_(request_id)
            , route_(std::move(route))
            , method_(std::move(method))
            , transport_(std::move(transport))
            , principal_(std::move(principal))
            , stream_(stream)
            , admitted_ms_(mcp_now_ms())
        {
        }

        mcp_ingress_admission_t(const mcp_ingress_admission_t&) = delete;
        mcp_ingress_admission_t& operator=(const mcp_ingress_admission_t&) = delete;

        ~mcp_ingress_admission_t()
        {
            release("destructor");
        }

        std::uint64_t request_id() const
        {
            return request_id_;
        }

        const std::string& principal() const
        {
            return principal_;
        }

        const std::string& route() const
        {
            return route_;
        }

        const std::string& method() const
        {
            return method_;
        }

        const std::string& transport() const
        {
            return transport_;
        }

        bool stream() const
        {
            return stream_;
        }

        void mark_active()
        {
            active_.store(true, std::memory_order_release);
        }

        void release(const char* reason)
        {
            bool expected = true;
            if (!active_.compare_exchange_strong(expected, false, std::memory_order_acq_rel))
                return;
            std::size_t global_active = 0;
            std::size_t global_queued = 0;
            std::size_t global_streams = 0;
            std::size_t principal_active = 0;
            std::size_t principal_queued = 0;
            std::size_t principal_streams = 0;
            std::size_t route_active = 0;
            std::size_t route_queued = 0;
            std::size_t route_principal_active = 0;
            std::size_t route_principal_queued = 0;
            {
                std::lock_guard<std::mutex> lk(g_mcp_ingress_capacity_mtx);
                const std::size_t current_active = g_mcp_ingress_active.load(std::memory_order_acquire);
                g_mcp_ingress_active.store(current_active == 0 ? 0 : current_active - 1, std::memory_order_release);
                if (stream_) {
                    const std::size_t current_streams = g_mcp_ingress_streams.load(std::memory_order_acquire);
                    g_mcp_ingress_streams.store(current_streams == 0 ? 0 : current_streams - 1, std::memory_order_release);
                }
                const std::string principal_key = mcp_ingress_principal_key(principal_);
                const std::string route_key = mcp_ingress_route_key(route_);
                const std::string route_principal_key = mcp_ingress_route_principal_key(route_, principal_);
                auto it = g_mcp_ingress_by_principal.find(principal_key);
                if (it != g_mcp_ingress_by_principal.end()) {
                    if (it->second.active != 0)
                        --it->second.active;
                    if (stream_ && it->second.streams != 0)
                        --it->second.streams;
                    principal_active = it->second.active;
                    principal_queued = it->second.queued;
                    principal_streams = it->second.streams;
                    if (it->second.active == 0 && it->second.queued == 0 && it->second.streams == 0)
                        g_mcp_ingress_by_principal.erase(it);
                }
                auto route_it = g_mcp_ingress_by_route.find(route_key);
                if (route_it != g_mcp_ingress_by_route.end()) {
                    if (route_it->second.active != 0)
                        --route_it->second.active;
                    if (stream_ && route_it->second.streams != 0)
                        --route_it->second.streams;
                    route_active = route_it->second.active;
                    route_queued = route_it->second.queued;
                    if (route_it->second.active == 0 && route_it->second.queued == 0 && route_it->second.streams == 0)
                        g_mcp_ingress_by_route.erase(route_it);
                }
                auto rp_it = g_mcp_ingress_by_route_principal.find(route_principal_key);
                if (rp_it != g_mcp_ingress_by_route_principal.end()) {
                    if (rp_it->second.active != 0)
                        --rp_it->second.active;
                    if (stream_ && rp_it->second.streams != 0)
                        --rp_it->second.streams;
                    route_principal_active = rp_it->second.active;
                    route_principal_queued = rp_it->second.queued;
                    if (rp_it->second.active == 0 && rp_it->second.queued == 0 && rp_it->second.streams == 0)
                        g_mcp_ingress_by_route_principal.erase(rp_it);
                }
                global_active = g_mcp_ingress_active.load(std::memory_order_acquire);
                global_queued = g_mcp_ingress_queued.load(std::memory_order_acquire);
                global_streams = g_mcp_ingress_streams.load(std::memory_order_acquire);
            }
            g_mcp_ingress_capacity_cv.notify_all();
            diag::log_tagged_fmt("mcp_srv",
                "MCP-CAPACITY-RELEASE request_id=%llu route=%s method=%s transport=%s principal='%s' stream=%d reason=%s elapsed_ms=%llu global_active=%zu global_queued=%zu global_streams=%zu principal_active=%zu principal_queued=%zu principal_streams=%zu route_active=%zu route_queued=%zu route_principal_active=%zu route_principal_queued=%zu decision=release",
                static_cast<unsigned long long>(request_id_),
                route_.c_str(),
                method_.c_str(),
                transport_.c_str(),
                principal_.c_str(),
                stream_ ? 1 : 0,
                reason ? reason : "",
                static_cast<unsigned long long>(mcp_now_ms() >= admitted_ms_ ? mcp_now_ms() - admitted_ms_ : 0),
                global_active,
                global_queued,
                global_streams,
                principal_active,
                principal_queued,
                principal_streams,
                route_active,
                route_queued,
                route_principal_active,
                route_principal_queued);
        }

    private:
        std::uint64_t request_id_ = 0;
        std::string route_;
        std::string method_;
        std::string transport_;
        std::string principal_;
        bool stream_ = false;
        std::uint64_t admitted_ms_ = 0;
        std::atomic<bool> active_{false};
    };

    thread_local std::shared_ptr<mcp_ingress_admission_t> tls_http_ingress_admission;

    static mcp_ingress_snapshot_t mcp_ingress_snapshot_for(const std::string& principal)
    {
        mcp_ingress_snapshot_t out;
        std::unique_lock<std::mutex> lk(g_mcp_ingress_capacity_mtx, std::try_to_lock);
        out.global_active = g_mcp_ingress_active.load(std::memory_order_acquire);
        out.global_queued = g_mcp_ingress_queued.load(std::memory_order_acquire);
        out.global_streams = g_mcp_ingress_streams.load(std::memory_order_acquire);
        if (!lk.owns_lock()) {
            out.lock_busy = true;
            return out;
        }
        const auto it = g_mcp_ingress_by_principal.find(mcp_ingress_principal_key(principal));
        if (it != g_mcp_ingress_by_principal.end()) {
            out.principal_active = it->second.active;
            out.principal_queued = it->second.queued;
            out.principal_streams = it->second.streams;
        }
        return out;
    }

    static json mcp_ingress_counts_json(const mcp_ingress_principal_counts_t& counts)
    {
        return {
            {"active", counts.active},
            {"queued", counts.queued},
            {"streams", counts.streams}
        };
    }

    static json mcp_ingress_map_json(const std::map<std::string, mcp_ingress_principal_counts_t>& counts, std::size_t max_items)
    {
        json rows = json::array();
        std::size_t emitted = 0;
        for (const auto& item : counts) {
            if (emitted >= max_items)
                break;
            json row = mcp_ingress_counts_json(item.second);
            row["key"] = item.first;
            rows.push_back(std::move(row));
            ++emitted;
        }
        return rows;
    }

    static json mcp_ingress_route_principal_json(std::size_t max_items)
    {
        json rows = json::array();
        std::size_t emitted = 0;
        for (const auto& item : g_mcp_ingress_by_route_principal) {
            if (emitted >= max_items)
                break;
            const auto split = item.first.find('\x1f');
            json row = mcp_ingress_counts_json(item.second);
            row["route"] = split == std::string::npos ? item.first : item.first.substr(0, split);
            row["principal"] = split == std::string::npos ? std::string() : item.first.substr(split + 1);
            rows.push_back(std::move(row));
            ++emitted;
        }
        return rows;
    }

    static json mcp_ingress_rejection_counters_json(std::size_t max_items)
    {
        json rows = json::array();
        std::size_t emitted = 0;
        for (const auto& item : g_mcp_ingress_rejections_by_route_reason) {
            if (emitted >= max_items)
                break;
            const auto split = item.first.find('|');
            rows.push_back({
                {"route", split == std::string::npos ? item.first : item.first.substr(0, split)},
                {"reason", split == std::string::npos ? std::string() : item.first.substr(split + 1)},
                {"count", item.second}
            });
            ++emitted;
        }
        return rows;
    }

    static json mcp_ingress_health_snapshot(const capacity_diag::quota_set_t& quotas)
    {
        json out;
        out["global_active"] = g_mcp_ingress_active.load(std::memory_order_acquire);
        out["global_queued"] = g_mcp_ingress_queued.load(std::memory_order_acquire);
        out["global_streams"] = g_mcp_ingress_streams.load(std::memory_order_acquire);
        out["caps"] = {
            {"global_active", quotas.global_ingress_active_requests},
            {"global_queued", quotas.global_ingress_queued_requests},
            {"per_principal_active", quotas.per_principal_ingress_active_requests},
            {"per_principal_queued", quotas.per_principal_ingress_queued_requests},
            {"global_streams", quotas.global_ingress_streams},
            {"per_principal_streams", quotas.per_principal_ingress_streams}
        };
        out["rejections_total"] = g_mcp_ingress_rejections_total.load(std::memory_order_acquire);
        std::unique_lock<std::mutex> lk(g_mcp_ingress_capacity_mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            out["lock_busy"] = true;
            return out;
        }
        out["lock_busy"] = false;
        out["per_principal"] = mcp_ingress_map_json(g_mcp_ingress_by_principal, 32);
        out["per_route"] = mcp_ingress_map_json(g_mcp_ingress_by_route, 16);
        out["per_route_principal"] = mcp_ingress_route_principal_json(32);
        out["rejection_counters"] = mcp_ingress_rejection_counters_json(32);
        return out;
    }

    enum class mcp_reserved_lane_t
    {
        health = 0,
        cancellation = 1,
        liveness = 2,
        shutdown = 3
    };

    struct mcp_reserved_lane_counters_t
    {
        std::atomic<std::size_t> active{0};
        std::atomic<std::size_t> high_water{0};
        std::atomic<std::uint64_t> acquired{0};
        std::atomic<std::uint64_t> released{0};
        std::atomic<std::uint64_t> rejected{0};
    };

    constexpr std::size_t kMcpReservedLaneCount = 4;
    mcp_reserved_lane_counters_t g_mcp_reserved_lanes[kMcpReservedLaneCount];

    static std::size_t mcp_reserved_lane_index(mcp_reserved_lane_t lane)
    {
        const auto index = static_cast<std::size_t>(lane);
        return index < kMcpReservedLaneCount ? index : 0;
    }

    static const char* mcp_reserved_lane_name(mcp_reserved_lane_t lane)
    {
        switch (lane) {
        case mcp_reserved_lane_t::health: return "health";
        case mcp_reserved_lane_t::cancellation: return "cancellation";
        case mcp_reserved_lane_t::liveness: return "liveness";
        case mcp_reserved_lane_t::shutdown: return "shutdown";
        default: return "health";
        }
    }

    static std::size_t mcp_reserved_lane_limit(mcp_reserved_lane_t lane)
    {
        const auto& cfg = mcp_concurrency_config();
        const std::size_t workers = (std::max<std::size_t>)(cfg.http_worker_threads, std::size_t{1});
        switch (lane) {
        case mcp_reserved_lane_t::health:
            return (std::max<std::size_t>)(std::size_t{2}, (std::min<std::size_t>)(std::size_t{16}, workers / std::size_t{2}));
        case mcp_reserved_lane_t::cancellation:
            return (std::max<std::size_t>)(std::size_t{4}, (std::min<std::size_t>)(std::size_t{64}, workers));
        case mcp_reserved_lane_t::liveness:
            return (std::max<std::size_t>)(std::size_t{2}, (std::min<std::size_t>)(std::size_t{32}, workers / std::size_t{2}));
        case mcp_reserved_lane_t::shutdown:
            return (std::max<std::size_t>)(std::size_t{2}, (std::min<std::size_t>)(std::size_t{16}, workers / std::size_t{4}));
        default:
            return std::size_t{2};
        }
    }

    static void mcp_reserved_lane_update_high_water(mcp_reserved_lane_counters_t& counters, std::size_t value)
    {
        std::size_t observed = counters.high_water.load(std::memory_order_acquire);
        while (value > observed && !counters.high_water.compare_exchange_weak(observed, value, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }
    }

    class mcp_reserved_lane_scope_t
    {
    public:
        mcp_reserved_lane_scope_t(mcp_reserved_lane_t lane,
                                  std::string phase,
                                  std::string principal,
                                  std::string route,
                                  std::string method,
                                  std::string request_id)
            : lane_(lane)
            , phase_(std::move(phase))
            , principal_(std::move(principal))
            , route_(std::move(route))
            , method_(std::move(method))
            , request_id_(std::move(request_id))
            , acquired_ms_(mcp_now_ms())
        {
        }

        ~mcp_reserved_lane_scope_t()
        {
            release("scope_exit");
        }

        mcp_reserved_lane_scope_t(const mcp_reserved_lane_scope_t&) = delete;
        mcp_reserved_lane_scope_t& operator=(const mcp_reserved_lane_scope_t&) = delete;

        void activate()
        {
            active_.store(true, std::memory_order_release);
        }

        void release(const char* reason)
        {
            if (!active_.exchange(false, std::memory_order_acq_rel))
                return;
            auto& counters = g_mcp_reserved_lanes[mcp_reserved_lane_index(lane_)];
            const std::size_t active_before = counters.active.fetch_sub(1, std::memory_order_acq_rel);
            const std::size_t active_after = active_before == 0 ? 0 : active_before - 1;
            if (active_before == 0)
                counters.active.store(0, std::memory_order_release);
            const std::uint64_t released = counters.released.fetch_add(1, std::memory_order_acq_rel) + 1;
            const std::uint64_t elapsed = mcp_now_ms() >= acquired_ms_ ? mcp_now_ms() - acquired_ms_ : 0;
            diag::log_tagged_fmt("mcp_srv",
                "MCP-PHASE3-RESERVED-LANE-RELEASE phase=%s lane=%s request_id=%s route=%s method=%s principal='%s' reason=%s elapsed_ms=%llu active=%zu limit=%zu acquired=%llu released=%llu rejected=%llu",
                phase_.c_str(),
                mcp_reserved_lane_name(lane_),
                request_id_.c_str(),
                route_.c_str(),
                method_.c_str(),
                principal_.c_str(),
                reason ? reason : "",
                static_cast<unsigned long long>(elapsed),
                active_after,
                mcp_reserved_lane_limit(lane_),
                static_cast<unsigned long long>(counters.acquired.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(released),
                static_cast<unsigned long long>(counters.rejected.load(std::memory_order_acquire)));
        }

        mcp_reserved_lane_t lane() const
        {
            return lane_;
        }

    private:
        mcp_reserved_lane_t lane_;
        std::string phase_;
        std::string principal_;
        std::string route_;
        std::string method_;
        std::string request_id_;
        std::uint64_t acquired_ms_ = 0;
        std::atomic<bool> active_{false};
    };

    thread_local std::shared_ptr<mcp_reserved_lane_scope_t> tls_reserved_control_lane;

    class scoped_reserved_lane_tls_t
    {
    public:
        explicit scoped_reserved_lane_tls_t(std::shared_ptr<mcp_reserved_lane_scope_t> lane)
            : previous_(tls_reserved_control_lane)
        {
            tls_reserved_control_lane = std::move(lane);
        }

        ~scoped_reserved_lane_tls_t()
        {
            tls_reserved_control_lane = std::move(previous_);
        }

        scoped_reserved_lane_tls_t(const scoped_reserved_lane_tls_t&) = delete;
        scoped_reserved_lane_tls_t& operator=(const scoped_reserved_lane_tls_t&) = delete;

    private:
        std::shared_ptr<mcp_reserved_lane_scope_t> previous_;
    };

    static std::size_t mcp_reserved_lane_active(mcp_reserved_lane_t lane)
    {
        return g_mcp_reserved_lanes[mcp_reserved_lane_index(lane)].active.load(std::memory_order_acquire);
    }

    static bool mcp_try_acquire_reserved_lane(mcp_reserved_lane_t lane,
                                              const char* phase,
                                              const std::string& principal,
                                              const std::string& route,
                                              const std::string& method,
                                              const std::string& request_id,
                                              std::shared_ptr<mcp_reserved_lane_scope_t>& out)
    {
        auto scope = std::make_shared<mcp_reserved_lane_scope_t>(lane,
            phase ? phase : "",
            principal.empty() ? std::string("external_mcp") : principal,
            route,
            method,
            request_id);
        auto& counters = g_mcp_reserved_lanes[mcp_reserved_lane_index(lane)];
        const std::size_t limit = mcp_reserved_lane_limit(lane);
        std::size_t observed = counters.active.load(std::memory_order_acquire);
        while (observed < limit) {
            if (counters.active.compare_exchange_weak(observed, observed + 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
                scope->activate();
                const std::uint64_t acquired = counters.acquired.fetch_add(1, std::memory_order_acq_rel) + 1;
                mcp_reserved_lane_update_high_water(counters, observed + 1);
                out = std::move(scope);
                diag::log_tagged_fmt("mcp_srv",
                    "MCP-PHASE3-RESERVED-LANE-ADMISSION phase=%s lane=%s request_id=%s route=%s method=%s principal='%s' active=%zu limit=%zu acquired=%llu rejected=%llu decision=admit",
                    phase ? phase : "",
                    mcp_reserved_lane_name(lane),
                    request_id.c_str(),
                    route.c_str(),
                    method.c_str(),
                    principal.empty() ? "external_mcp" : principal.c_str(),
                    observed + 1,
                    limit,
                    static_cast<unsigned long long>(acquired),
                    static_cast<unsigned long long>(counters.rejected.load(std::memory_order_acquire)));
                return true;
            }
        }
        const std::uint64_t rejected = counters.rejected.fetch_add(1, std::memory_order_acq_rel) + 1;
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAPACITY-REJECT family=phase3_reserved_lane phase=%s lane=%s request_id=%s route=%s method=%s principal='%s' active=%zu limit=%zu rejected=%llu decision=reject reason=reserved_lane_exhausted disposition=not_started",
            phase ? phase : "",
            mcp_reserved_lane_name(lane),
            request_id.c_str(),
            route.c_str(),
            method.c_str(),
            principal.empty() ? "external_mcp" : principal.c_str(),
            observed,
            limit,
            static_cast<unsigned long long>(rejected));
        return false;
    }

    static json mcp_reserved_lane_json(mcp_reserved_lane_t lane)
    {
        const auto& counters = g_mcp_reserved_lanes[mcp_reserved_lane_index(lane)];
        const std::size_t active = counters.active.load(std::memory_order_acquire);
        const std::size_t limit = mcp_reserved_lane_limit(lane);
        return {
            {"limit", limit},
            {"active", active},
            {"available", active < limit},
            {"available_slots", limit > active ? limit - active : 0},
            {"high_water", counters.high_water.load(std::memory_order_acquire)},
            {"acquired", counters.acquired.load(std::memory_order_acquire)},
            {"released", counters.released.load(std::memory_order_acquire)},
            {"rejected", counters.rejected.load(std::memory_order_acquire)}
        };
    }

    static json mcp_reserved_lanes_health_snapshot()
    {
        const bool health_available = mcp_reserved_lane_active(mcp_reserved_lane_t::health) < mcp_reserved_lane_limit(mcp_reserved_lane_t::health);
        const bool cancellation_available = mcp_reserved_lane_active(mcp_reserved_lane_t::cancellation) < mcp_reserved_lane_limit(mcp_reserved_lane_t::cancellation);
        const bool liveness_available = mcp_reserved_lane_active(mcp_reserved_lane_t::liveness) < mcp_reserved_lane_limit(mcp_reserved_lane_t::liveness);
        const bool shutdown_available = mcp_reserved_lane_active(mcp_reserved_lane_t::shutdown) < mcp_reserved_lane_limit(mcp_reserved_lane_t::shutdown);
        return {
            {"phase", "phase3_reserved_lanes"},
            {"enforcement_enabled", true},
            {"lanes", {
                {"health", mcp_reserved_lane_json(mcp_reserved_lane_t::health)},
                {"cancellation", mcp_reserved_lane_json(mcp_reserved_lane_t::cancellation)},
                {"liveness", mcp_reserved_lane_json(mcp_reserved_lane_t::liveness)},
                {"shutdown", mcp_reserved_lane_json(mcp_reserved_lane_t::shutdown)}
            }},
            {"availability", {
                {"health", health_available},
                {"cancellation", cancellation_available},
                {"liveness", liveness_available},
                {"shutdown", shutdown_available},
                {"p0", health_available && cancellation_available && liveness_available && shutdown_available}
            }}
        };
    }

    static json mcp_reserved_lane_rejection_body(mcp_reserved_lane_t lane,
                                                 const std::string& request_id,
                                                 const std::string& route,
                                                 const std::string& method,
                                                 const std::string& principal)
    {
        const std::size_t active = mcp_reserved_lane_active(lane);
        const std::size_t limit = mcp_reserved_lane_limit(lane);
        return {
            {"status", "rejected"},
            {"error", "mcp reserved control lane exhausted"},
            {"code", "MCP_RESERVED_LANE_REJECT"},
            {"disposition", "not_started"},
            {"retry_after_ms", 100},
            {"request_id", request_id},
            {"principal_id", principal},
            {"route", route},
            {"method", method},
            {"lane", mcp_reserved_lane_name(lane)},
            {"reason", "reserved_lane_exhausted"},
            {"active", active},
            {"limit", limit},
            {"available", active < limit},
            {"capacity", mcp_reserved_lanes_health_snapshot()}
        };
    }

    class scoped_mcp_route_dispatch_diag_t
    {
    public:
        scoped_mcp_route_dispatch_diag_t(const std::string& method,
                                         const std::string& request_id,
                                         const std::string& tool_name)
            : method_(method)
            , request_id_(request_id)
            , tool_name_(tool_name)
            , started_ms_(mcp_now_ms())
        {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-ROUTE-ENTRY request_id=%s method=%s tool=%s route=%s transport=%s principal=%s session_hash=%s batch=%d cancelled=%d pid=%lu tid=%lu",
                request_id_.c_str(),
                method_.c_str(),
                tool_name_.empty() ? "<none>" : tool_name_.c_str(),
                current_mcp_route(),
                current_mcp_transport(),
                current_mcp_principal(),
                current_mcp_session_hash(),
                tls_http_request_id == 0 ? 0 : 1,
                current_call_cancelled() ? 1 : 0,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }

        ~scoped_mcp_route_dispatch_diag_t()
        {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-ROUTE-EXIT request_id=%s method=%s tool=%s route=%s transport=%s elapsed_ms=%llu cancelled=%d deadline_ms=%llu pid=%lu tid=%lu",
                request_id_.c_str(),
                method_.c_str(),
                tool_name_.empty() ? "<none>" : tool_name_.c_str(),
                current_mcp_route(),
                current_mcp_transport(),
                static_cast<unsigned long long>(mcp_now_ms() >= started_ms_ ? mcp_now_ms() - started_ms_ : 0),
                current_call_cancelled() ? 1 : 0,
                static_cast<unsigned long long>(current_call_deadline_ms()),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }

        scoped_mcp_route_dispatch_diag_t(const scoped_mcp_route_dispatch_diag_t&) = delete;
        scoped_mcp_route_dispatch_diag_t& operator=(const scoped_mcp_route_dispatch_diag_t&) = delete;

    private:
        std::string method_;
        std::string request_id_;
        std::string tool_name_;
        std::uint64_t started_ms_ = 0;
    };

    struct runtime_queue_stats_t
    {
        bool alive = false;
        bool shutting_down = false;
        int pool_size = 0;
        std::size_t workers = 0;
        std::size_t pending = 0;
        std::uint32_t active = 0;
        std::uint64_t post_attempts = 0;
        std::uint64_t posted = 0;
        std::uint64_t rejected = 0;
        std::uint64_t started = 0;
        std::uint64_t finished = 0;
        std::uint64_t oldest_active_ms = 0;
        std::uint32_t active_label_count = 0;
        std::uint32_t healthy_long_lived = 0;
        std::uint32_t hot_workers = 0;
        std::uint32_t not_queryable_workers = 0;
        std::string active_labels;
        std::string top_cpu_labels;
    };

    enum class runtime_queue_family_t
    {
        general,
        service,
        critical
    };

    static void append_limited_runtime_text(std::string& dst, const std::string& src, std::size_t limit)
    {
        if (src.empty() || dst.size() >= limit)
            return;
        if (!dst.empty() && dst.size() + 1 < limit)
            dst.push_back(';');
        const std::size_t remaining = dst.size() < limit ? limit - dst.size() : 0;
        if (remaining != 0)
            dst.append(src, 0, remaining);
    }

    static void accumulate_runtime_domain_stats(runtime_queue_stats_t& out,
                                                aida::infra::taskflow_runtime::executor_domain_t domain)
    {
        auto& pool = aida::infra::taskflow_runtime::domain_pool(domain);
        const auto stats = aida::infra::taskflow_runtime::stats_for(
            pool,
            pool.configured_pool_size,
            aida::infra::taskflow_runtime::domain_name(domain));
        out.alive = out.alive || stats.alive;
        out.shutting_down = out.shutting_down || stats.shutting_down;
        out.pool_size += stats.pool_size;
        out.workers += stats.workers;
        out.pending += stats.pending;
        out.active += stats.active;
        out.post_attempts += stats.post_attempts;
        out.posted += stats.posted;
        out.rejected += stats.rejected;
        out.started += stats.started;
        out.finished += stats.finished;
        if (stats.oldest_active_ms > out.oldest_active_ms)
            out.oldest_active_ms = stats.oldest_active_ms;
        out.active_label_count += stats.active_label_count;
        out.healthy_long_lived += stats.healthy_long_lived;
        out.hot_workers += stats.hot_workers;
        out.not_queryable_workers += stats.not_queryable_workers;
        append_limited_runtime_text(out.active_labels, stats.active_labels, 900);
        append_limited_runtime_text(out.top_cpu_labels, stats.top_cpu_labels, 900);
    }

    static runtime_queue_stats_t runtime_queue_stats(runtime_queue_family_t family)
    {
        using domain_t = aida::infra::taskflow_runtime::executor_domain_t;
        runtime_queue_stats_t out;
        switch (family) {
        case runtime_queue_family_t::service:
            accumulate_runtime_domain_stats(out, domain_t::service);
            accumulate_runtime_domain_stats(out, domain_t::long_running);
            break;
        case runtime_queue_family_t::critical:
            accumulate_runtime_domain_stats(out, domain_t::critical);
            accumulate_runtime_domain_stats(out, domain_t::security_liveness);
            break;
        case runtime_queue_family_t::general:
        default:
            accumulate_runtime_domain_stats(out, domain_t::general);
            accumulate_runtime_domain_stats(out, domain_t::ui_dispatch);
            accumulate_runtime_domain_stats(out, domain_t::external_tool);
            accumulate_runtime_domain_stats(out, domain_t::feature_worker);
            accumulate_runtime_domain_stats(out, domain_t::diagnostics);
            break;
        }
        return out;
    }

    static void log_runtime_executor_stats(const char* context)
    {
        const auto general = runtime_queue_stats(runtime_queue_family_t::general);
        const auto critical = runtime_queue_stats(runtime_queue_family_t::critical);
        const auto service = runtime_queue_stats(runtime_queue_family_t::service);
        const auto exec = aida::infra::executor::active_snapshot();
        diag::log_tagged_fmt("mcp_srv",
            "%s runtime_general alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu oldest_ms=%llu labels=%.420s exec_total_active=%u exec_oldest_ms=%llu",
            context ? context : "runtime_general",
            general.alive ? 1 : 0,
            general.shutting_down ? 1 : 0,
            general.pool_size,
            general.workers,
            general.pending,
            static_cast<unsigned>(general.active),
            static_cast<unsigned long long>(general.post_attempts),
            static_cast<unsigned long long>(general.posted),
            static_cast<unsigned long long>(general.rejected),
            static_cast<unsigned long long>(general.started),
            static_cast<unsigned long long>(general.finished),
            static_cast<unsigned long long>(general.oldest_active_ms),
            general.active_labels.empty() ? "<none>" : general.active_labels.c_str(),
            static_cast<unsigned>(exec.total_active),
            static_cast<unsigned long long>(exec.oldest_active_ms));
        diag::log_tagged_fmt("mcp_srv",
            "%s runtime_critical alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu oldest_ms=%llu labels=%.420s",
            context ? context : "runtime_critical",
            critical.alive ? 1 : 0,
            critical.shutting_down ? 1 : 0,
            critical.pool_size,
            critical.workers,
            critical.pending,
            static_cast<unsigned>(critical.active),
            static_cast<unsigned long long>(critical.post_attempts),
            static_cast<unsigned long long>(critical.posted),
            static_cast<unsigned long long>(critical.rejected),
            static_cast<unsigned long long>(critical.started),
            static_cast<unsigned long long>(critical.finished),
            static_cast<unsigned long long>(critical.oldest_active_ms),
            critical.active_labels.empty() ? "<none>" : critical.active_labels.c_str());
        diag::log_tagged_fmt("mcp_srv",
            "%s runtime_service alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu oldest_ms=%llu labels=%.420s",
            context ? context : "runtime_service",
            service.alive ? 1 : 0,
            service.shutting_down ? 1 : 0,
            service.pool_size,
            service.workers,
            service.pending,
            static_cast<unsigned>(service.active),
            static_cast<unsigned long long>(service.post_attempts),
            static_cast<unsigned long long>(service.posted),
            static_cast<unsigned long long>(service.rejected),
            static_cast<unsigned long long>(service.started),
            static_cast<unsigned long long>(service.finished),
            static_cast<unsigned long long>(service.oldest_active_ms),
            service.active_labels.empty() ? "<none>" : service.active_labels.c_str());
    }

    struct mcp_executor_task_meta_t
    {
        mutable std::mutex mtx;
        std::uint64_t executor_seq = 0;
        std::uint64_t queued_at = 0;
        std::uint64_t active_at = 0;
        std::uint64_t deadline_ms = 0;
        std::uint64_t queue_wait_ms = 0;
        DWORD worker_tid = 0;
        std::string request_id;
        std::string method;
        std::string tool;
        std::string domain;
        std::string lane;
        std::string payload_shape;
        std::string route;
        std::string principal_id;
        std::string session_hash;
        std::string transport;
        std::string action;
        std::string target_id;
        std::uint32_t target_pid = 0;
        std::uint64_t batch_id = 0;
        std::size_t batch_index = 0;
        std::size_t batch_size = 0;
        bool external_tool = false;
        bool read_only = true;
        bool mutating = false;
        bool long_running = false;
        bool background_command = false;
        bool driver_debugger = false;
        cancel_token_ptr_t cancel_token;
    };

    constexpr std::uint64_t kMcpCapacityLongRunningMs = 30000;
    constexpr std::size_t kMcpCapacityMaxQueuedSamples = 4096;
    constexpr std::size_t kMcpCapacityMaxActiveSamples = 1024;
    constexpr std::size_t kMcpCapacityMaxMapEntries = 96;
    constexpr std::size_t kMcpCapacityMaxContributors = 16;

    struct mcp_capacity_counts_t
    {
        std::uint64_t active = 0;
        std::uint64_t queued = 0;
        std::uint64_t read_active = 0;
        std::uint64_t read_queued = 0;
        std::uint64_t mutate_active = 0;
        std::uint64_t mutate_queued = 0;
        std::uint64_t long_active = 0;
        std::uint64_t long_queued = 0;
        std::uint64_t driver_debugger_active = 0;
        std::uint64_t driver_debugger_queued = 0;
        std::uint64_t batch_active = 0;
        std::uint64_t batch_queued = 0;
        std::uint64_t background_active = 0;
        std::uint64_t background_queued = 0;
        std::uint64_t oldest_active_ms = 0;
        std::uint64_t oldest_queued_ms = 0;
    };

    struct mcp_pressure_contributor_t
    {
        std::string state;
        std::string executor;
        std::string principal;
        std::string session_id;
        std::string target_id;
        std::string domain;
        std::string tool;
        std::string lane;
        std::uint64_t age_ms = 0;
        std::uint64_t queued_age_ms = 0;
        std::uint64_t active_age_ms = 0;
        std::uint64_t batch_id = 0;
        std::uint32_t target_pid = 0;
        bool read_only = true;
        bool long_running = false;
        bool driver_debugger = false;
        bool background_command = false;
    };

    struct mcp_capacity_snapshot_state_t
    {
        std::uint64_t timestamp_ms = 0;
        mcp_capacity_counts_t global;
        std::map<std::string, mcp_capacity_counts_t> principals;
        std::map<std::string, mcp_capacity_counts_t> sessions;
        std::map<std::string, mcp_capacity_counts_t> domains;
        std::map<std::string, mcp_capacity_counts_t> driver_targets;
        std::vector<mcp_pressure_contributor_t> contributors;
        std::size_t executor_count = 0;
        std::size_t executor_snapshot_busy = 0;
        std::size_t executor_registry_busy = 0;
        std::size_t task_meta_busy = 0;
        std::size_t queued_samples = 0;
        std::size_t active_samples = 0;
        std::size_t queued_samples_truncated = 0;
        std::size_t active_samples_truncated = 0;
    };

    static std::string capacity_clean_key(const std::string& value, const char* fallback, std::size_t max_len = 96)
    {
        std::string out;
        out.reserve(std::min(value.size(), max_len));
        for (char ch : value) {
            const unsigned char c = static_cast<unsigned char>(ch);
            out.push_back((c < 0x20 || c == 0x7f) ? '_' : ch);
            if (out.size() >= max_len)
                break;
        }
        if (out.empty() && fallback)
            out = fallback;
        return out;
    }

    static std::string capacity_domain_key(const std::string& domain)
    {
        return capacity_clean_key(domain.empty() ? std::string("misc") : domain, "misc", 64);
    }

    static void capacity_bump(mcp_capacity_counts_t& counts,
                              bool active,
                              bool read_only,
                              bool long_running,
                              bool driver_debugger,
                              bool batch_child,
                              bool background_command,
                              std::uint64_t age_ms)
    {
        if (active) {
            ++counts.active;
            if (read_only)
                ++counts.read_active;
            else
                ++counts.mutate_active;
            if (long_running)
                ++counts.long_active;
            if (driver_debugger)
                ++counts.driver_debugger_active;
            if (batch_child)
                ++counts.batch_active;
            if (background_command)
                ++counts.background_active;
            if (counts.oldest_active_ms < age_ms)
                counts.oldest_active_ms = age_ms;
            return;
        }
        ++counts.queued;
        if (read_only)
            ++counts.read_queued;
        else
            ++counts.mutate_queued;
        if (long_running)
            ++counts.long_queued;
        if (driver_debugger)
            ++counts.driver_debugger_queued;
        if (batch_child)
            ++counts.batch_queued;
        if (background_command)
            ++counts.background_queued;
        if (counts.oldest_queued_ms < age_ms)
            counts.oldest_queued_ms = age_ms;
    }

    static void capacity_bump_map(std::map<std::string, mcp_capacity_counts_t>& map,
                                  const std::string& key,
                                  bool active,
                                  bool read_only,
                                  bool long_running,
                                  bool driver_debugger,
                                  bool batch_child,
                                  bool background_command,
                                  std::uint64_t age_ms)
    {
        const std::string clean = capacity_clean_key(key, "unknown");
        auto it = map.find(clean);
        if (it == map.end()) {
            if (map.size() >= kMcpCapacityMaxMapEntries)
                return;
            it = map.emplace(clean, mcp_capacity_counts_t{}).first;
        }
        capacity_bump(it->second, active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
    }

    static void capacity_add_contributor(mcp_capacity_snapshot_state_t& state, mcp_pressure_contributor_t item)
    {
        if (item.age_ms == 0 && !item.long_running && !item.driver_debugger && !item.background_command)
            return;
        state.contributors.push_back(std::move(item));
        std::sort(state.contributors.begin(), state.contributors.end(),
            [](const mcp_pressure_contributor_t& a, const mcp_pressure_contributor_t& b) {
                if (a.age_ms != b.age_ms)
                    return a.age_ms > b.age_ms;
                if (a.driver_debugger != b.driver_debugger)
                    return a.driver_debugger;
                return a.tool < b.tool;
            });
        if (state.contributors.size() > kMcpCapacityMaxContributors)
            state.contributors.resize(kMcpCapacityMaxContributors);
    }

    static void record_capacity_item(mcp_capacity_snapshot_state_t& state,
                                     const std::string& executor,
                                     const std::string& item_state,
                                     const std::string& principal,
                                     const std::string& session_id,
                                     const std::string& target_id,
                                     const std::string& domain,
                                     const std::string& tool,
                                     const std::string& lane,
                                     bool active,
                                     bool read_only,
                                     bool long_running,
                                     bool driver_debugger,
                                     bool batch_child,
                                     bool background_command,
                                     std::uint64_t age_ms,
                                     std::uint64_t queued_age_ms,
                                     std::uint64_t active_age_ms,
                                     std::uint64_t batch_id,
                                     std::uint32_t target_pid)
    {
        capacity_bump(state.global, active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
        capacity_bump_map(state.principals, principal.empty() ? std::string("unknown") : principal, active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
        capacity_bump_map(state.sessions, session_id.empty() ? std::string("active_session") : session_id, active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
        capacity_bump_map(state.domains, capacity_domain_key(domain), active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
        if (driver_debugger)
            capacity_bump_map(state.driver_targets, target_id.empty() ? std::string("target_unknown") : target_id, active, read_only, long_running, driver_debugger, batch_child, background_command, age_ms);
        mcp_pressure_contributor_t contributor;
        contributor.state = item_state;
        contributor.executor = capacity_clean_key(executor, "executor", 96);
        contributor.principal = capacity_clean_key(principal, "unknown", 96);
        contributor.session_id = capacity_clean_key(session_id, "active_session", 96);
        contributor.target_id = capacity_clean_key(target_id, "target_unknown", 96);
        contributor.domain = capacity_domain_key(domain);
        contributor.tool = capacity_clean_key(tool, "unknown", 96);
        contributor.lane = capacity_clean_key(lane, "unknown", 96);
        contributor.age_ms = age_ms;
        contributor.queued_age_ms = queued_age_ms;
        contributor.active_age_ms = active_age_ms;
        contributor.batch_id = batch_id;
        contributor.target_pid = target_pid;
        contributor.read_only = read_only;
        contributor.long_running = long_running;
        contributor.driver_debugger = driver_debugger;
        contributor.background_command = background_command;
        capacity_add_contributor(state, std::move(contributor));
    }

    struct mcp_executor_counts_t
    {
        std::size_t snapshotted = 0;
        std::size_t snapshot_busy = 0;
        std::size_t workers = 0;
        std::size_t queued = 0;
        std::uint64_t active = 0;
        std::uint64_t enqueued = 0;
        std::uint64_t started = 0;
        std::uint64_t finished = 0;
        std::uint64_t rejected = 0;
        std::uint64_t worker_failures = 0;
        std::uint64_t oldest_active_ms = 0;
        std::uint64_t active_long_running = 0;
        std::uint64_t queued_long_running = 0;
        std::string active_summary;
        std::string queue_summary;
    };

    static bool contains_ci_ascii(const std::string& value, const char* needle)
    {
        if (!needle || !needle[0])
            return false;
        std::string hay = value;
        std::string ndl = needle;
        std::transform(hay.begin(), hay.end(), hay.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(ndl.begin(), ndl.end(), ndl.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return hay.find(ndl) != std::string::npos;
    }

    static bool is_long_running_tool_diagnostic(const std::string& tool,
                                                const std::string& domain,
                                                const std::string& lane,
                                                std::uint64_t queued_at,
                                                std::uint64_t deadline_ms)
    {
        if (deadline_ms != 0 && queued_at != 0 && deadline_ms > queued_at &&
            deadline_ms - queued_at > kMcpDefaultToolTimeoutMs)
            return true;
        const std::string joined = tool + " " + domain + " " + lane;
        static const char* const tokens[] = {
            "api_monitor", "browser", "burp", "camoufox", "command", "decompile",
            "debug", "driver", "find_references", "find_strings", "intruder",
            "network", "sandbox", "scan", "scanner", "thread_classify"
        };
        for (const char* token : tokens) {
            if (contains_ci_ascii(joined, token))
                return true;
        }
        return false;
    }

    struct mcp_pressure_counts_t
    {
        std::uint64_t queued = 0;
        std::uint64_t active = 0;
        std::uint64_t queued_long_running = 0;
        std::uint64_t active_long_running = 0;
        std::uint64_t enqueued = 0;
        std::uint64_t started = 0;
        std::uint64_t finished = 0;
    };

    struct mcp_pressure_record_t
    {
        std::string executor;
        std::string principal_id;
        std::string session_hash;
        std::string domain;
        std::string lane;
        bool long_running = false;
    };

    struct mcp_pressure_snapshot_t
    {
        bool lock_busy = false;
        std::size_t principal_count = 0;
        std::size_t session_count = 0;
        std::uint64_t queued = 0;
        std::uint64_t active = 0;
        std::uint64_t queued_long_running = 0;
        std::uint64_t active_long_running = 0;
        std::string principal_summary;
        std::string session_summary;
        std::string domain_summary;
        std::string lane_summary;
        std::string executor_summary;
    };

    std::mutex g_mcp_pressure_mtx;
    std::map<std::string, mcp_pressure_counts_t> g_mcp_pressure_by_principal;
    std::map<std::string, mcp_pressure_counts_t> g_mcp_pressure_by_session;
    std::map<std::string, mcp_pressure_counts_t> g_mcp_pressure_by_domain;
    std::map<std::string, mcp_pressure_counts_t> g_mcp_pressure_by_lane;
    std::map<std::string, mcp_pressure_counts_t> g_mcp_pressure_by_executor;

    static void decrement_pressure_value(std::uint64_t& value)
    {
        if (value != 0)
            --value;
    }

    static void pressure_enqueue(mcp_pressure_counts_t& c, bool long_running)
    {
        ++c.queued;
        ++c.enqueued;
        if (long_running)
            ++c.queued_long_running;
    }

    static void pressure_start(mcp_pressure_counts_t& c, bool long_running)
    {
        decrement_pressure_value(c.queued);
        ++c.active;
        ++c.started;
        if (long_running) {
            decrement_pressure_value(c.queued_long_running);
            ++c.active_long_running;
        }
    }

    static void pressure_finish(mcp_pressure_counts_t& c, bool long_running)
    {
        decrement_pressure_value(c.active);
        ++c.finished;
        if (long_running)
            decrement_pressure_value(c.active_long_running);
    }

    template <typename Fn>
    static void update_pressure_maps(const mcp_pressure_record_t& record, Fn&& fn)
    {
        const std::string principal = record.principal_id.empty() ? "<none>" : record.principal_id;
        const std::string session = record.session_hash.empty() ? "<none>" : record.session_hash;
        const std::string domain = record.domain.empty() ? "<none>" : record.domain;
        const std::string lane = record.lane.empty() ? "<none>" : record.lane;
        const std::string executor = record.executor.empty() ? "<none>" : record.executor;
        fn(g_mcp_pressure_by_principal[principal], record.long_running);
        fn(g_mcp_pressure_by_session[session], record.long_running);
        fn(g_mcp_pressure_by_domain[domain], record.long_running);
        fn(g_mcp_pressure_by_lane[lane], record.long_running);
        fn(g_mcp_pressure_by_executor[executor], record.long_running);
    }

    static void record_pressure_enqueue(const mcp_pressure_record_t& record)
    {
        try {
            std::lock_guard<std::mutex> lk(g_mcp_pressure_mtx);
            update_pressure_maps(record, pressure_enqueue);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=enqueue executor=%s err='%s'",
                record.executor.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=enqueue executor=%s err='<unknown>'",
                record.executor.c_str());
        }
    }

    static void record_pressure_start(const mcp_pressure_record_t& record)
    {
        try {
            std::lock_guard<std::mutex> lk(g_mcp_pressure_mtx);
            update_pressure_maps(record, pressure_start);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=start executor=%s err='%s'",
                record.executor.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=start executor=%s err='<unknown>'",
                record.executor.c_str());
        }
    }

    static void record_pressure_finish(const mcp_pressure_record_t& record)
    {
        try {
            std::lock_guard<std::mutex> lk(g_mcp_pressure_mtx);
            update_pressure_maps(record, pressure_finish);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=finish executor=%s err='%s'",
                record.executor.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "mcp_pressure_record_failed phase=finish executor=%s err='<unknown>'",
                record.executor.c_str());
        }
    }

    static void append_pressure_summary_item(std::string& out, const std::string& key, const mcp_pressure_counts_t& c)
    {
        if (out.size() >= 900)
            return;
        char item[320] = {};
        _snprintf_s(item, sizeof(item), _TRUNCATE,
            "%s%s:q=%llu:a=%llu:lq=%llu:la=%llu:enq=%llu:start=%llu:fin=%llu",
            out.empty() ? "" : ";",
            key.c_str(),
            static_cast<unsigned long long>(c.queued),
            static_cast<unsigned long long>(c.active),
            static_cast<unsigned long long>(c.queued_long_running),
            static_cast<unsigned long long>(c.active_long_running),
            static_cast<unsigned long long>(c.enqueued),
            static_cast<unsigned long long>(c.started),
            static_cast<unsigned long long>(c.finished));
        out += item;
    }

    static std::string pressure_summary_for(const std::map<std::string, mcp_pressure_counts_t>& counts, std::size_t max_items)
    {
        std::vector<std::pair<std::string, mcp_pressure_counts_t>> items;
        items.reserve(counts.size());
        for (const auto& kv : counts)
            items.push_back(kv);
        std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
            const auto ap = a.second.active + a.second.queued + a.second.active_long_running + a.second.queued_long_running;
            const auto bp = b.second.active + b.second.queued + b.second.active_long_running + b.second.queued_long_running;
            if (ap != bp)
                return ap > bp;
            return a.first < b.first;
        });
        std::string out;
        std::size_t emitted = 0;
        for (const auto& item : items) {
            if (emitted >= max_items)
                break;
            if (item.second.active == 0 && item.second.queued == 0 && item.second.active_long_running == 0 && item.second.queued_long_running == 0)
                continue;
            append_pressure_summary_item(out, item.first, item.second);
            ++emitted;
        }
        return out;
    }

    static mcp_pressure_snapshot_t mcp_pressure_snapshot()
    {
        mcp_pressure_snapshot_t out;
        std::unique_lock<std::mutex> lk(g_mcp_pressure_mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            out.lock_busy = true;
            return out;
        }
        for (const auto& kv : g_mcp_pressure_by_principal) {
            if (kv.first == "<none>")
                continue;
            if (kv.second.active != 0 || kv.second.queued != 0 || kv.second.active_long_running != 0 || kv.second.queued_long_running != 0)
                ++out.principal_count;
        }
        for (const auto& kv : g_mcp_pressure_by_session) {
            if (kv.first == "<none>")
                continue;
            if (kv.second.active != 0 || kv.second.queued != 0 || kv.second.active_long_running != 0 || kv.second.queued_long_running != 0)
                ++out.session_count;
        }
        for (const auto& kv : g_mcp_pressure_by_executor) {
            out.queued += kv.second.queued;
            out.active += kv.second.active;
            out.queued_long_running += kv.second.queued_long_running;
            out.active_long_running += kv.second.active_long_running;
        }
        out.principal_summary = pressure_summary_for(g_mcp_pressure_by_principal, 8);
        out.session_summary = pressure_summary_for(g_mcp_pressure_by_session, 6);
        out.domain_summary = pressure_summary_for(g_mcp_pressure_by_domain, 8);
        out.lane_summary = pressure_summary_for(g_mcp_pressure_by_lane, 8);
        out.executor_summary = pressure_summary_for(g_mcp_pressure_by_executor, 8);
        return out;
    }

    static mcp_pressure_record_t make_pressure_record(const std::string& executor,
                                                      const std::shared_ptr<mcp_executor_task_meta_t>& meta,
                                                      bool long_running)
    {
        mcp_pressure_record_t record;
        record.executor = executor;
        record.long_running = long_running;
        if (!meta)
            return record;
        std::lock_guard<std::mutex> lk(meta->mtx);
        record.principal_id = meta->principal_id;
        record.session_hash = meta->session_hash;
        record.domain = meta->domain;
        record.lane = meta->lane;
        return record;
    }

    class mcp_owned_executor_t;

    std::mutex g_mcp_executor_registry_mtx;
    std::vector<mcp_owned_executor_t*> g_mcp_executor_registry;
    thread_local mcp_executor_task_meta_t* tls_executor_task_meta = nullptr;

    static void register_mcp_executor(mcp_owned_executor_t* executor)
    {
        std::lock_guard<std::mutex> lk(g_mcp_executor_registry_mtx);
        g_mcp_executor_registry.push_back(executor);
    }

    static void unregister_mcp_executor(mcp_owned_executor_t* executor)
    {
        std::lock_guard<std::mutex> lk(g_mcp_executor_registry_mtx);
        g_mcp_executor_registry.erase(
            std::remove(g_mcp_executor_registry.begin(), g_mcp_executor_registry.end(), executor),
            g_mcp_executor_registry.end());
    }

    static std::shared_ptr<mcp_executor_task_meta_t> make_executor_task_meta()
    {
        return std::make_shared<mcp_executor_task_meta_t>();
    }

    static void update_current_executor_task_http(std::uint64_t request_id, const std::string& method, const std::string& route)
    {
        auto* meta = tls_executor_task_meta;
        if (!meta)
            return;
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->request_id = std::to_string(request_id);
        meta->method = method;
        meta->route = route;
        meta->principal_id = tls_route_identity.principal_id;
        meta->session_hash = tls_route_identity.session_hash;
        meta->transport = tls_route_identity.transport;
        if (meta->lane.empty())
            meta->lane = "http_request";
    }

    static void update_executor_task_lane(const std::shared_ptr<mcp_executor_task_meta_t>& meta, const std::string& lane)
    {
        if (!meta)
            return;
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->lane = lane;
    }

    class mcp_owned_executor_t
    {
    public:
        mcp_owned_executor_t(const char* name, std::size_t worker_count, std::size_t max_queued_requests)
            : _state(std::make_shared<state_t>(name, worker_count, max_queued_requests))
        {
            register_mcp_executor(this);
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_config name=%s workers=%zu max_queue=%zu",
                _state->name.c_str(),
                _state->worker_count,
                _state->max_queued_requests);
            start_runtime_executor();
        }

        mcp_owned_executor_t(const mcp_owned_executor_t&) = delete;
        mcp_owned_executor_t& operator=(const mcp_owned_executor_t&) = delete;

        ~mcp_owned_executor_t()
        {
            shutdown();
            unregister_mcp_executor(this);
        }

        bool enqueue(std::function<void()> fn, std::shared_ptr<mcp_executor_task_meta_t> meta = nullptr)
        {
            auto state = _state;
            if (!fn) {
                if (state)
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                return false;
            }
            if (!state)
                return false;

            auto task = std::make_shared<task_t>();
            task->fn = std::move(fn);
            task->meta = meta ? std::move(meta) : make_executor_task_meta();
            const std::uint64_t queued_at = mcp_now_ms();
            const std::uint64_t seq = state->enqueued.fetch_add(1u, std::memory_order_acq_rel) + 1u;
            task->seq = seq;
            {
                std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                task->meta->queued_at = queued_at;
                task->meta->executor_seq = seq;
            }
            {
                std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                task->long_running = is_long_running_tool_diagnostic(
                    task->meta->tool,
                    task->meta->domain,
                    task->meta->lane,
                    task->meta->queued_at,
                    task->meta->deadline_ms);
            }
            task->pressure = make_pressure_record(state->name, task->meta, task->long_running);
            const mcp_pressure_record_t pressure_record = task->pressure;
            const bool pressure_long_running = task->long_running;

            std::string request_id;
            std::string session_id;
            std::string target_id;
            std::string diagnostic_id;
            std::string label = state->name + "#" + std::to_string(seq);
            std::uint64_t deadline_ms = 0;
            std::uint32_t target_pid = 0;
            {
                std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                request_id = task->meta->request_id;
                session_id = task->meta->session_hash;
                target_id = task->meta->target_id;
                diagnostic_id = task->meta->action;
                deadline_ms = task->meta->deadline_ms;
                target_pid = task->meta->target_pid;
            }

            aida::infra::taskflow_runtime::task_descriptor_t desc;
            desc.owner_subsystem = state->name.c_str();
            desc.label = label.c_str();
            desc.thread_class = "mcp_runtime";
            desc.domain = runtime_domain_for_executor_name(state->name);
            desc.priority = task->long_running ? 2 : 3;
            desc.deadline_ms = deadline_ms;
            desc.session_id = session_id.empty() ? nullptr : session_id.c_str();
            desc.target_id = target_id.empty() ? nullptr : target_id.c_str();
            desc.target_pid = target_pid;
            desc.diagnostic_id = diagnostic_id.empty() ? nullptr : diagnostic_id.c_str();
            desc.request_id = request_id.empty() ? nullptr : request_id.c_str();
            desc.failure_policy = "reject_not_started";
            desc.shutdown_policy = "cancel_or_drain";
            desc.no_capacity_reason = "mcp_executor_runtime_rejected";
            desc.cancel_hook = [state, task]() {
                cancel_queued_task(state, task, "runtime_cancel_hook");
            };
            desc.cancellable_body = [state, task](const aida::infra::taskflow_runtime::cancellation_token_t& token) {
                execute_task(state, task, token);
            };

            bool pressure_recorded = false;
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                const std::size_t workers = state->worker_count_snapshot.load(std::memory_order_acquire);
                if (state->shutdown.load(std::memory_order_acquire) || workers == 0) {
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=%s workers=%zu queued=%zu active=%u",
                        state->name.c_str(),
                        state->shutdown.load(std::memory_order_acquire) ? "shutdown" : "no_workers",
                        workers,
                        state->queued_tasks.size(),
                        static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
                    return false;
                }
                if (state->max_queued_requests > 0 && state->queued_tasks.size() >= state->max_queued_requests) {
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=full queued=%zu max=%zu active=%u",
                        state->name.c_str(),
                        state->queued_tasks.size(),
                        state->max_queued_requests,
                        static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
                    return false;
                }
                try {
                    state->queued_tasks.push_back(task);
                    if (pressure_long_running)
                        state->queued_long_running.fetch_add(1u, std::memory_order_acq_rel);
                } catch (...) {
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=exception queued=%zu active=%u",
                        state->name.c_str(),
                        state->queued_tasks.size(),
                        static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
                    return false;
                }
                try {
                    record_pressure_enqueue(pressure_record);
                    pressure_recorded = true;
                } catch (const std::exception& ex) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_pressure_record_failed phase=enqueue executor=%s err='%s'",
                        state->name.c_str(),
                        ex.what());
                } catch (...) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_pressure_record_failed phase=enqueue executor=%s err='<unknown>'",
                        state->name.c_str());
                }
                try {
                    auto submit_result = aida::infra::taskflow_runtime::submit(std::move(desc));
                    if (!submit_result.submitted) {
                        remove_queued_task_locked(*state, task);
                        state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                        diag::log_tagged_fmt("mcp_srv",
                            "mcp_executor_enqueue_rejected name=%s reason=runtime_submit_rejected runtime_reason='%s' queued=%zu active=%u",
                            state->name.c_str(),
                            submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str(),
                            state->queued_tasks.size(),
                            static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
                        if (pressure_recorded)
                            balance_rejected_pressure(pressure_record);
                        return false;
                    }
                    task->runtime_job_id.store(submit_result.handle.id, std::memory_order_release);
                    state->outstanding_tasks[seq] = task;
                } catch (const std::exception& ex) {
                    remove_queued_task_locked(*state, task);
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=runtime_submit_exception queued=%zu active=%u err='%s'",
                        state->name.c_str(),
                        state->queued_tasks.size(),
                        static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                        ex.what());
                    if (pressure_recorded)
                        balance_rejected_pressure(pressure_record);
                    return false;
                } catch (...) {
                    remove_queued_task_locked(*state, task);
                    state->rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=runtime_submit_exception queued=%zu active=%u err='<unknown>'",
                        state->name.c_str(),
                        state->queued_tasks.size(),
                        static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
                    if (pressure_recorded)
                        balance_rejected_pressure(pressure_record);
                    return false;
                }
            }
            return true;
        }

        bool try_snapshot_json(json& out, mcp_capacity_snapshot_state_t* capacity)
        {
            auto state = _state;
            if (!state)
                return false;
            const std::uint64_t now = mcp_now_ms();
            std::vector<std::shared_ptr<task_t>> active_tasks;
            std::vector<std::shared_ptr<task_t>> queued_tasks;
            std::size_t queued = 0;
            std::size_t workers = 0;
            {
                std::unique_lock<std::mutex> lk(state->mtx, std::try_to_lock);
                if (!lk.owns_lock()) {
                    out = json::object();
                    out["name"] = state->name;
                    out["snapshot_lock_busy"] = true;
                    out["workers"] = state->worker_count_snapshot.load(std::memory_order_acquire);
                    out["max_queue"] = state->max_queued_requests;
                    out["queued"] = 0;
                    out["active"] = state->active.load(std::memory_order_acquire);
                    out["queued_long_running"] = state->queued_long_running.load(std::memory_order_acquire);
                    out["active_long_running"] = state->active_long_running.load(std::memory_order_acquire);
                    out["enqueued"] = state->enqueued.load(std::memory_order_acquire);
                    out["started"] = state->started.load(std::memory_order_acquire);
                    out["finished"] = state->finished.load(std::memory_order_acquire);
                    out["rejected"] = state->rejected.load(std::memory_order_acquire);
                    out["worker_failures"] = state->worker_failures.load(std::memory_order_acquire);
                    if (capacity)
                        ++capacity->executor_snapshot_busy;
                    return false;
                }
                queued = state->queued_tasks.size();
                workers = state->worker_count_snapshot.load(std::memory_order_acquire);
                active_tasks = state->active_tasks;
                queued_tasks.reserve(std::min<std::size_t>(queued, kMcpCapacityMaxQueuedSamples));
                std::size_t sampled = 0;
                for (const auto& job : state->queued_tasks) {
                    if (sampled >= kMcpCapacityMaxQueuedSamples)
                        break;
                    queued_tasks.push_back(job);
                    ++sampled;
                }
                if (capacity && queued > sampled)
                    capacity->queued_samples_truncated += queued - sampled;
            }

            json active = json::array();
            std::size_t active_sampled = 0;
            for (const auto& active_task : active_tasks) {
                const auto meta = active_task ? active_task->meta : nullptr;
                if (!meta)
                    continue;
                if (active_sampled >= kMcpCapacityMaxActiveSamples) {
                    if (capacity)
                        ++capacity->active_samples_truncated;
                    continue;
                }
                ++active_sampled;
                json item;
                {
                    std::unique_lock<std::mutex> lk(meta->mtx, std::try_to_lock);
                    if (!lk.owns_lock()) {
                        item["meta_lock_busy"] = true;
                        if (capacity)
                            ++capacity->task_meta_busy;
                        active.push_back(std::move(item));
                        continue;
                    }
                    const std::uint64_t queued_age_ms = meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0;
                    const std::uint64_t active_age_ms = meta->active_at != 0 && now >= meta->active_at ? now - meta->active_at : 0;
                    const bool long_running = meta->long_running || active_age_ms >= kMcpCapacityLongRunningMs;
                    const bool batch_child = meta->batch_id != 0 || meta->lane == "jsonrpc_batch_item";
                    item["executor_seq"] = meta->executor_seq;
                    item["request_id"] = meta->request_id;
                    item["method"] = meta->method;
                    item["tool"] = meta->tool;
                    item["domain"] = meta->domain;
                    item["lane"] = meta->lane;
                    item["route"] = meta->route;
                    item["transport"] = meta->transport;
                    item["principal"] = meta->principal_id;
                    item["session"] = meta->session_hash;
                    item["target_id"] = meta->target_id;
                    item["target_pid"] = meta->target_pid;
                    item["read_only"] = meta->read_only;
                    item["mutating"] = meta->mutating;
                    item["long_running"] = long_running;
                    item["driver_debugger"] = meta->driver_debugger;
                    item["background_command"] = meta->background_command;
                    if (meta->batch_id != 0) {
                        item["batch_id"] = meta->batch_id;
                        item["batch_index"] = meta->batch_index;
                        item["batch_size"] = meta->batch_size;
                    }
                    item["worker_tid"] = static_cast<std::uint32_t>(meta->worker_tid);
                    item["queued_age_ms"] = queued_age_ms;
                    item["active_age_ms"] = active_age_ms;
                    item["deadline_ms"] = meta->deadline_ms;
                    item["deadline_remaining_ms"] = meta->deadline_ms != 0 && now < meta->deadline_ms ? meta->deadline_ms - now : 0;
                    item["cancelled"] = meta->cancel_token && meta->cancel_token->load(std::memory_order_acquire);
                    if (!meta->payload_shape.empty())
                        item["payload_shape"] = meta->payload_shape;
                    if (capacity && meta->external_tool) {
                        ++capacity->active_samples;
                        record_capacity_item(*capacity,
                            state->name,
                            "active",
                            meta->principal_id,
                            meta->session_hash,
                            meta->target_id,
                            meta->domain,
                            meta->tool,
                            meta->lane,
                            true,
                            meta->read_only,
                            long_running,
                            meta->driver_debugger,
                            batch_child,
                            meta->background_command,
                            active_age_ms,
                            queued_age_ms,
                            active_age_ms,
                            meta->batch_id,
                            meta->target_pid);
                    }
                }
                active.push_back(std::move(item));
            }

            json queued_items = json::array();
            for (const auto& queued_task : queued_tasks) {
                const auto meta = queued_task ? queued_task->meta : nullptr;
                if (!meta)
                    continue;
                json item;
                std::unique_lock<std::mutex> lk(meta->mtx, std::try_to_lock);
                if (!lk.owns_lock()) {
                    item["meta_lock_busy"] = true;
                    if (capacity)
                        ++capacity->task_meta_busy;
                    queued_items.push_back(std::move(item));
                    continue;
                }
                const std::uint64_t queued_age_ms = meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0;
                const bool long_running = meta->long_running || (meta->deadline_ms != 0 && meta->deadline_ms > meta->queued_at && (meta->deadline_ms - meta->queued_at) >= kMcpCapacityLongRunningMs);
                const bool batch_child = meta->batch_id != 0 || meta->lane == "jsonrpc_batch_item";
                item["executor_seq"] = meta->executor_seq;
                item["request_id"] = meta->request_id;
                item["method"] = meta->method;
                item["tool"] = meta->tool;
                item["domain"] = meta->domain;
                item["lane"] = meta->lane;
                item["route"] = meta->route;
                item["transport"] = meta->transport;
                item["principal"] = meta->principal_id;
                item["session"] = meta->session_hash;
                item["target_id"] = meta->target_id;
                item["target_pid"] = meta->target_pid;
                item["read_only"] = meta->read_only;
                item["mutating"] = meta->mutating;
                item["long_running"] = long_running;
                item["driver_debugger"] = meta->driver_debugger;
                item["background_command"] = meta->background_command;
                if (meta->batch_id != 0) {
                    item["batch_id"] = meta->batch_id;
                    item["batch_index"] = meta->batch_index;
                    item["batch_size"] = meta->batch_size;
                }
                item["queued_age_ms"] = queued_age_ms;
                item["deadline_ms"] = meta->deadline_ms;
                item["deadline_remaining_ms"] = meta->deadline_ms != 0 && now < meta->deadline_ms ? meta->deadline_ms - now : 0;
                item["cancelled"] = meta->cancel_token && meta->cancel_token->load(std::memory_order_acquire);
                if (!meta->payload_shape.empty())
                    item["payload_shape"] = meta->payload_shape;
                if (capacity && meta->external_tool) {
                    ++capacity->queued_samples;
                    record_capacity_item(*capacity,
                        state->name,
                        "queued",
                        meta->principal_id,
                        meta->session_hash,
                        meta->target_id,
                        meta->domain,
                        meta->tool,
                        meta->lane,
                        false,
                        meta->read_only,
                        long_running,
                        meta->driver_debugger,
                        batch_child,
                        meta->background_command,
                        queued_age_ms,
                        queued_age_ms,
                        0,
                        meta->batch_id,
                        meta->target_pid);
                }
                queued_items.push_back(std::move(item));
            }

            out = json::object();
            out["name"] = state->name;
            out["snapshot_lock_busy"] = false;
            out["workers"] = workers;
            out["max_queue"] = state->max_queued_requests;
            out["queued"] = queued;
            out["active"] = state->active.load(std::memory_order_acquire);
            out["queued_long_running"] = state->queued_long_running.load(std::memory_order_acquire);
            out["active_long_running"] = state->active_long_running.load(std::memory_order_acquire);
            out["enqueued"] = state->enqueued.load(std::memory_order_acquire);
            out["started"] = state->started.load(std::memory_order_acquire);
            out["finished"] = state->finished.load(std::memory_order_acquire);
            out["rejected"] = state->rejected.load(std::memory_order_acquire);
            out["worker_failures"] = state->worker_failures.load(std::memory_order_acquire);
            out["active_tasks"] = std::move(active);
            out["queued_tasks_sampled"] = std::move(queued_items);
            return true;
        }

        json snapshot_json()
        {
            json out;
            (void)try_snapshot_json(out, nullptr);
            return out;
        }

        bool try_snapshot_counts(mcp_executor_counts_t& out)
        {
            auto state = _state;
            if (!state)
                return false;
            const std::uint64_t now = mcp_now_ms();
            std::vector<std::shared_ptr<task_t>> active_tasks;
            std::size_t queued = 0;
            std::size_t workers = 0;
            {
                std::unique_lock<std::mutex> lk(state->mtx, std::try_to_lock);
                if (!lk.owns_lock())
                    return false;
                queued = state->queued_tasks.size();
                workers = state->worker_count_snapshot.load(std::memory_order_acquire);
                active_tasks = state->active_tasks;
            }

            ++out.snapshotted;
            out.workers += workers;
            out.queued += queued;
            out.active += state->active.load(std::memory_order_acquire);
            out.enqueued += state->enqueued.load(std::memory_order_acquire);
            out.started += state->started.load(std::memory_order_acquire);
            out.finished += state->finished.load(std::memory_order_acquire);
            out.rejected += state->rejected.load(std::memory_order_acquire);
            out.worker_failures += state->worker_failures.load(std::memory_order_acquire);
            out.queued_long_running += state->queued_long_running.load(std::memory_order_acquire);
            out.active_long_running += state->active_long_running.load(std::memory_order_acquire);
            if (out.queue_summary.size() < 900) {
                char item[260] = {};
                _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s%s:workers=%zu:queued=%zu:active=%u:long_queued=%llu:long_active=%llu",
                    out.queue_summary.empty() ? "" : ";",
                    state->name.c_str(),
                    workers,
                    queued,
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(state->queued_long_running.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(state->active_long_running.load(std::memory_order_acquire)));
                out.queue_summary += item;
            }

            for (const auto& active_task : active_tasks) {
                const auto meta = active_task ? active_task->meta : nullptr;
                if (!meta)
                    continue;
                std::unique_lock<std::mutex> meta_lk(meta->mtx, std::try_to_lock);
                if (!meta_lk.owns_lock()) {
                    if (out.active_summary.size() < 900)
                        out.active_summary += out.active_summary.empty() ? "meta_lock_busy" : ";meta_lock_busy";
                    continue;
                }
                const std::uint64_t active_age_ms = meta->active_at != 0 && now >= meta->active_at ? now - meta->active_at : 0;
                if (out.oldest_active_ms < active_age_ms)
                    out.oldest_active_ms = active_age_ms;
                if (out.active_summary.size() < 900) {
                    char item[520] = {};
                    _snprintf_s(item, sizeof(item), _TRUNCATE,
                        "%s%s#%llu:transport=%s:principal=%s:session=%s:tool=%s:lane=%s:tid=%lu:queued_age_ms=%llu:active_age_ms=%llu:deadline_ms=%llu:cancelled=%d",
                        out.active_summary.empty() ? "" : ";",
                        state->name.c_str(),
                        static_cast<unsigned long long>(meta->executor_seq),
                        meta->transport.empty() ? "<none>" : meta->transport.c_str(),
                        meta->principal_id.empty() ? "<none>" : meta->principal_id.c_str(),
                        meta->session_hash.empty() ? "<none>" : meta->session_hash.c_str(),
                        meta->tool.empty() ? "<none>" : meta->tool.c_str(),
                        meta->lane.empty() ? "<none>" : meta->lane.c_str(),
                        static_cast<unsigned long>(meta->worker_tid),
                        static_cast<unsigned long long>(meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0),
                        static_cast<unsigned long long>(active_age_ms),
                        static_cast<unsigned long long>(meta->deadline_ms),
                        meta->cancel_token && meta->cancel_token->load(std::memory_order_acquire) ? 1 : 0);
                    out.active_summary += item;
                }
            }
            return true;
        }

        void shutdown()
        {
            auto state = _state;
            if (!state)
                return;
            bool expected = false;
            if (!state->shutdown.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                return;

            const std::uint64_t begin = mcp_now_ms();
            std::size_t queued = 0;
            std::size_t workers = 0;
            std::vector<std::shared_ptr<task_t>> outstanding;
            std::uint64_t current_seq = 0;
            if (tls_executor_task_meta)
                current_seq = tls_executor_task_meta->executor_seq;
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                queued = state->queued_tasks.size();
                workers = state->worker_count_snapshot.load(std::memory_order_acquire);
                outstanding.reserve(state->outstanding_tasks.size());
                for (const auto& kv : state->outstanding_tasks) {
                    if (kv.second)
                        outstanding.push_back(kv.second);
                }
            }
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_shutdown_begin name=%s workers=%zu queued=%zu active=%u outstanding=%zu enqueued=%llu finished=%llu rejected=%llu",
                state->name.c_str(),
                workers,
                queued,
                static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                outstanding.size(),
                static_cast<unsigned long long>(state->enqueued.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(state->finished.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(state->rejected.load(std::memory_order_acquire)));

            if (outstanding.empty()) {
                log_shutdown_done(*state, begin);
                return;
            }

            for (const auto& task : outstanding) {
                if (!task)
                    continue;
                request_task_cancel(task);
                const std::uint64_t job_id = task->runtime_job_id.load(std::memory_order_acquire);
                if (job_id != 0)
                    (void)aida::infra::taskflow_runtime::cancel(aida::infra::taskflow_runtime::job_handle_t{job_id});
            }

            const std::uint64_t deadline = begin + 10000ULL;
            bool skipped_current_task = false;
            bool wait_timed_out = false;
            for (const auto& task : outstanding) {
                if (!task)
                    continue;
                if (task->seq == current_seq && current_seq != 0) {
                    skipped_current_task = true;
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_shutdown_self_wait_skipped name=%s seq=%llu job_id=%llu tid=%u",
                        state->name.c_str(),
                        static_cast<unsigned long long>(task->seq),
                        static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                        static_cast<unsigned>(GetCurrentThreadId()));
                    continue;
                }
                const std::uint64_t job_id = task->runtime_job_id.load(std::memory_order_acquire);
                if (job_id == 0)
                    continue;
                const std::uint64_t now = mcp_now_ms();
                if (now >= deadline)
                    break;
                const std::uint32_t wait_ms = static_cast<std::uint32_t>((std::min<std::uint64_t>)(deadline - now, 250ULL));
                auto wait_result = aida::infra::taskflow_runtime::wait_for(aida::infra::taskflow_runtime::job_handle_t{job_id}, wait_ms);
                if (wait_result.timed_out) {
                    wait_timed_out = true;
                    break;
                }
            }

            if (wait_timed_out || !executor_drained(state)) {
                std::size_t remaining_queued = 0;
                std::size_t remaining_outstanding = 0;
                std::string live_summary;
                {
                    std::lock_guard<std::mutex> lk(state->mtx);
                    remaining_queued = state->queued_tasks.size();
                    remaining_outstanding = state->outstanding_tasks.size();
                    live_summary = live_task_summary_locked(*state, 16);
                }
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_shutdown_wait_timeout name=%s elapsed_ms=%llu queued=%zu active=%u outstanding=%zu finished=%llu skipped_current=%d wait_timed_out=%d live='%s'",
                    state->name.c_str(),
                    static_cast<unsigned long long>(mcp_now_ms() - begin),
                    remaining_queued,
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                    remaining_outstanding,
                    static_cast<unsigned long long>(state->finished.load(std::memory_order_acquire)),
                    skipped_current_task ? 1 : 0,
                    wait_timed_out ? 1 : 0,
                    live_summary.c_str());
                log_shutdown_done(*state, begin);
                return;
            }

            {
                std::lock_guard<std::mutex> lk(state->mtx);
                state->queued_tasks.clear();
                state->active_tasks.clear();
                state->outstanding_tasks.clear();
            }

            log_shutdown_done(*state, begin);
        }

    private:
        struct task_t {
            std::uint64_t seq = 0;
            std::function<void()> fn;
            std::shared_ptr<mcp_executor_task_meta_t> meta;
            mcp_pressure_record_t pressure;
            bool long_running = false;
            std::atomic<std::uint64_t> runtime_job_id{0};
            std::atomic<bool> queued_cancel_finalized{false};
        };

        struct state_t {
            const std::string name;
            const std::size_t worker_count;
            const std::size_t max_queued_requests;
            std::deque<std::shared_ptr<task_t>> queued_tasks;
            std::vector<std::shared_ptr<task_t>> active_tasks;
            std::map<std::uint64_t, std::shared_ptr<task_t>> outstanding_tasks;
            std::mutex mtx;
            std::atomic<bool> shutdown{false};
            std::atomic<std::uint32_t> active{0};
            std::atomic<std::uint64_t> enqueued{0};
            std::atomic<std::uint64_t> rejected{0};
            std::atomic<std::uint64_t> started{0};
            std::atomic<std::uint64_t> finished{0};
            std::atomic<std::uint64_t> worker_failures{0};
            std::atomic<std::uint64_t> queued_long_running{0};
            std::atomic<std::uint64_t> active_long_running{0};
            std::atomic<std::size_t> worker_count_snapshot{0};

            state_t(const char* name_in, std::size_t worker_count_in, std::size_t max_queued_requests_in)
                : name(name_in && *name_in ? name_in : "mcp_executor")
                , worker_count(worker_count_in)
                , max_queued_requests(max_queued_requests_in)
            {
            }
        };

        static aida::infra::taskflow_runtime::executor_domain_t runtime_domain_for_executor_name(const std::string& name)
        {
            using domain_t = aida::infra::taskflow_runtime::executor_domain_t;
            if (name.rfind("mcp_http", 0) == 0)
                return domain_t::critical;
            if (name.rfind("mcp_jsonrpc_batch", 0) == 0 || name.rfind("mcp_tool", 0) == 0 || name.rfind("mcp_domain_", 0) == 0)
                return domain_t::external_tool;
            return domain_t::external_tool;
        }

        void start_runtime_executor()
        {
            auto state = _state;
            if (!state)
                return;
            std::lock_guard<std::mutex> lk(state->mtx);
            if (state->worker_count == 0) {
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_workers_ready name=%s requested=%zu active_workers=%zu failures=%llu runtime=central_taskflow",
                    state->name.c_str(),
                    state->worker_count,
                    static_cast<std::size_t>(0),
                    static_cast<unsigned long long>(state->worker_failures.load(std::memory_order_acquire)));
                return;
            }
            state->active_tasks.reserve(state->worker_count);
            state->worker_count_snapshot.store(state->worker_count, std::memory_order_release);
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_workers_ready name=%s requested=%zu active_workers=%zu failures=%llu runtime=central_taskflow",
                state->name.c_str(),
                state->worker_count,
                state->worker_count_snapshot.load(std::memory_order_acquire),
                static_cast<unsigned long long>(state->worker_failures.load(std::memory_order_acquire)));
        }

        static void decrement_counter_if_nonzero(std::atomic<std::uint64_t>& value)
        {
            std::uint64_t current = value.load(std::memory_order_acquire);
            while (current != 0 &&
                   !value.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
            }
        }

        static bool remove_queued_task_locked(state_t& state, const std::shared_ptr<task_t>& task)
        {
            if (!task)
                return false;
            auto it = std::find_if(state.queued_tasks.begin(), state.queued_tasks.end(),
                [&task](const std::shared_ptr<task_t>& item) {
                    return item && item->seq == task->seq;
                });
            if (it == state.queued_tasks.end())
                return false;
            state.queued_tasks.erase(it);
            if (task->long_running)
                decrement_counter_if_nonzero(state.queued_long_running);
            return true;
        }

        static void remove_active_task_locked(state_t& state, const std::shared_ptr<task_t>& task)
        {
            if (!task)
                return;
            state.active_tasks.erase(
                std::remove_if(state.active_tasks.begin(), state.active_tasks.end(),
                    [&task](const std::shared_ptr<task_t>& item) {
                        return item && item->seq == task->seq;
                    }),
                state.active_tasks.end());
        }

        static void remove_outstanding_task_locked(state_t& state, const std::shared_ptr<task_t>& task)
        {
            if (task)
                state.outstanding_tasks.erase(task->seq);
        }

        static void balance_rejected_pressure(const mcp_pressure_record_t& pressure_record)
        {
            record_pressure_start(pressure_record);
            record_pressure_finish(pressure_record);
        }

        static void request_task_cancel(const std::shared_ptr<task_t>& task)
        {
            if (!task || !task->meta)
                return;
            std::shared_ptr<std::atomic<bool>> token;
            {
                std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                token = task->meta->cancel_token;
            }
            if (token)
                token->store(true, std::memory_order_release);
        }

        static bool cancel_queued_task(const std::shared_ptr<state_t>& state, const std::shared_ptr<task_t>& task, const char* reason)
        {
            if (!state || !task)
                return false;
            request_task_cancel(task);
            bool removed = false;
            std::size_t queued_after = 0;
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                removed = remove_queued_task_locked(*state, task);
                if (removed)
                    remove_outstanding_task_locked(*state, task);
                queued_after = state->queued_tasks.size();
            }
            if (!removed)
                return false;
            if (!task->queued_cancel_finalized.exchange(true, std::memory_order_acq_rel)) {
                task->fn = {};
                state->finished.fetch_add(1u, std::memory_order_acq_rel);
                balance_rejected_pressure(task->pressure);
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_queued_task_cancelled name=%s seq=%llu job_id=%llu reason=%s queued=%zu active=%u finished=%llu",
                    state->name.c_str(),
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                    reason ? reason : "cancelled",
                    queued_after,
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(state->finished.load(std::memory_order_acquire)));
            }
            return true;
        }

        static bool executor_drained(const std::shared_ptr<state_t>& state)
        {
            if (!state)
                return true;
            std::lock_guard<std::mutex> lk(state->mtx);
            return state->queued_tasks.empty() &&
                   state->active.load(std::memory_order_acquire) == 0 &&
                   state->outstanding_tasks.empty();
        }

        static std::string live_task_summary_locked(const state_t& state, std::size_t max_items)
        {
            std::string out;
            std::size_t emitted = 0;
            auto append_task = [&](const char* phase, const std::shared_ptr<task_t>& task) {
                if (!task || emitted >= max_items || out.size() >= 900)
                    return;
                std::string tool;
                std::string lane;
                std::uint64_t queued_at = 0;
                std::uint64_t active_at = 0;
                DWORD tid = 0;
                if (task->meta) {
                    std::unique_lock<std::mutex> meta_lk(task->meta->mtx, std::try_to_lock);
                    if (meta_lk.owns_lock()) {
                        tool = task->meta->tool;
                        lane = task->meta->lane;
                        queued_at = task->meta->queued_at;
                        active_at = task->meta->active_at;
                        tid = task->meta->worker_tid;
                    }
                }
                char item[360] = {};
                const std::uint64_t now = mcp_now_ms();
                _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s%s#%llu:job=%llu:tool=%s:lane=%s:queued_age=%llu:active_age=%llu:tid=%lu",
                    out.empty() ? "" : ";",
                    phase ? phase : "task",
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                    tool.empty() ? "<none>" : tool.c_str(),
                    lane.empty() ? "<none>" : lane.c_str(),
                    static_cast<unsigned long long>(queued_at != 0 && now >= queued_at ? now - queued_at : 0),
                    static_cast<unsigned long long>(active_at != 0 && now >= active_at ? now - active_at : 0),
                    static_cast<unsigned long>(tid));
                out += item;
                ++emitted;
            };
            for (const auto& task : state.active_tasks)
                append_task("active", task);
            for (const auto& task : state.queued_tasks)
                append_task("queued", task);
            return out;
        }

        static void log_shutdown_done(state_t& state, std::uint64_t begin)
        {
            std::size_t queued = 0;
            std::size_t active_entries = 0;
            std::size_t outstanding = 0;
            {
                std::lock_guard<std::mutex> lk(state.mtx);
                queued = state.queued_tasks.size();
                active_entries = state.active_tasks.size();
                outstanding = state.outstanding_tasks.size();
            }
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_shutdown_done name=%s elapsed_ms=%llu queued=%zu active_entries=%zu outstanding=%zu enqueued=%llu started=%llu finished=%llu rejected=%llu",
                state.name.c_str(),
                static_cast<unsigned long long>(mcp_now_ms() - begin),
                queued,
                active_entries,
                outstanding,
                static_cast<unsigned long long>(state.enqueued.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(state.started.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(state.finished.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(state.rejected.load(std::memory_order_acquire)));
        }

        static bool begin_task_execution(const std::shared_ptr<state_t>& state,
                                         const std::shared_ptr<task_t>& task,
                                         std::size_t& active_slot,
                                         std::size_t& queued_after_pop)
        {
            if (!state || !task)
                return false;
            std::lock_guard<std::mutex> lk(state->mtx);
            if (task->queued_cancel_finalized.load(std::memory_order_acquire))
                return false;
            const bool removed = remove_queued_task_locked(*state, task);
            queued_after_pop = state->queued_tasks.size();
            if (!removed) {
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_start_missing_queued_record name=%s seq=%llu job_id=%llu queued=%zu active=%u",
                    state->name.c_str(),
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                    state->queued_tasks.size(),
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)));
            }
            state->active_tasks.push_back(task);
            active_slot = state->active_tasks.size() - 1u;
            return true;
        }

        static void execute_task(std::shared_ptr<state_t> state,
                                 std::shared_ptr<task_t> task,
                                 const aida::infra::taskflow_runtime::cancellation_token_t& runtime_token)
        {
            if (!state || !task)
                return;
            if (!task->meta)
                task->meta = make_executor_task_meta();

            if (runtime_token.requested.load(std::memory_order_acquire) || task->queued_cancel_finalized.load(std::memory_order_acquire)) {
                if (cancel_queued_task(state, task, "cancelled_before_start"))
                    return;
                if (task->queued_cancel_finalized.load(std::memory_order_acquire))
                    return;
            }

            std::size_t worker_index = (std::numeric_limits<std::size_t>::max)();
            std::size_t queued_after_pop = 0;
            if (!begin_task_execution(state, task, worker_index, queued_after_pop))
                return;
            state->active.fetch_add(1u, std::memory_order_acq_rel);
            if (task->long_running)
                state->active_long_running.fetch_add(1u, std::memory_order_acq_rel);
            record_pressure_start(task->pressure);
            state->started.fetch_add(1u, std::memory_order_acq_rel);

            struct finish_guard_t {
                std::shared_ptr<state_t> state;
                std::shared_ptr<task_t> task;
                std::size_t worker_index = (std::numeric_limits<std::size_t>::max)();
                mcp_executor_task_meta_t* previous_tls = nullptr;
                ~finish_guard_t()
                {
                    tls_executor_task_meta = previous_tls;
                    if (!state)
                        return;
                    {
                        std::lock_guard<std::mutex> lk(state->mtx);
                        remove_active_task_locked(*state, task);
                        remove_outstanding_task_locked(*state, task);
                    }
                    state->finished.fetch_add(1u, std::memory_order_acq_rel);
                    if (task)
                        record_pressure_finish(task->pressure);
                    if (task && task->long_running)
                        decrement_counter_if_nonzero(state->active_long_running);
                    if (task)
                        task->fn = {};
                    state->active.fetch_sub(1u, std::memory_order_acq_rel);
                }
            } finish_guard{state, task, worker_index, tls_executor_task_meta};

            const std::uint64_t now = mcp_now_ms();
            std::uint64_t wait_ms = 0;
            std::string method;
            std::string tool;
            std::string lane;
            bool meta_cancelled = false;
            {
                std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                wait_ms = task->meta->queued_at != 0 && now >= task->meta->queued_at ? now - task->meta->queued_at : 0;
                task->meta->queue_wait_ms = wait_ms;
                task->meta->active_at = now;
                task->meta->worker_tid = GetCurrentThreadId();
                method = task->meta->method;
                tool = task->meta->tool;
                lane = task->meta->lane;
                meta_cancelled = task->meta->cancel_token && task->meta->cancel_token->load(std::memory_order_acquire);
            }
            if (wait_ms > 100) {
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_dispatch_delay name=%s runtime_slot=%zu seq=%llu job_id=%llu wait_ms=%llu queued=%zu active=%u method='%s' tool='%s' lane='%s'",
                    state->name.c_str(),
                    worker_index,
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(wait_ms),
                    queued_after_pop,
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                    method.c_str(),
                    tool.c_str(),
                    lane.c_str());
            }

            tls_executor_task_meta = task->meta.get();
            DWORD task_seh = 0;
            if (runtime_token.requested.load(std::memory_order_acquire) || meta_cancelled) {
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_task_cancelled_before_invoke name=%s runtime_slot=%zu seq=%llu job_id=%llu method='%s' tool='%s' lane='%s'",
                    state->name.c_str(),
                    worker_index,
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long long>(task->runtime_job_id.load(std::memory_order_acquire)),
                    method.c_str(),
                    tool.c_str(),
                    lane.c_str());
            } else {
                try {
                    task_seh = aida::infra::win_thread::run_function_seh_guarded(task->fn);
                } catch (const std::exception& ex) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_task_exception name=%s runtime_slot=%zu seq=%llu err='%s'",
                        state->name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(task->seq),
                        ex.what());
                } catch (...) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_task_exception name=%s runtime_slot=%zu seq=%llu err='<unknown>'",
                        state->name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(task->seq));
                }
            }
            if (task_seh != 0) {
                const std::uint64_t task_now = mcp_now_ms();
                std::uint64_t active_age_ms = 0;
                std::uint64_t deadline_snapshot = 0;
                {
                    std::lock_guard<std::mutex> meta_lk(task->meta->mtx);
                    active_age_ms = task->meta->active_at != 0 && task_now >= task->meta->active_at ? task_now - task->meta->active_at : 0;
                    deadline_snapshot = task->meta->deadline_ms;
                    method = task->meta->method;
                    tool = task->meta->tool;
                    lane = task->meta->lane;
                }
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_task_seh name=%s runtime_slot=%zu seq=%llu tid=%lu code=0x%08lX active_age_ms=%llu queued_after_pop=%zu active=%u started=%llu finished=%llu method='%s' tool='%s' lane='%s' deadline_ms=%llu shutdown=%d",
                    state->name.c_str(),
                    worker_index,
                    static_cast<unsigned long long>(task->seq),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    static_cast<unsigned long>(task_seh),
                    static_cast<unsigned long long>(active_age_ms),
                    queued_after_pop,
                    static_cast<unsigned>(state->active.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(state->started.load(std::memory_order_acquire)),
                    static_cast<unsigned long long>(state->finished.load(std::memory_order_acquire)),
                    method.c_str(),
                    tool.c_str(),
                    lane.c_str(),
                    static_cast<unsigned long long>(deadline_snapshot),
                    state->shutdown.load(std::memory_order_acquire) ? 1 : 0);
            }
        }

        std::shared_ptr<state_t> _state;
    };

    static json mcp_executor_health_snapshot(mcp_capacity_snapshot_state_t* capacity = nullptr)
    {
        std::vector<mcp_owned_executor_t*> executors;
        {
            std::unique_lock<std::mutex> lk(g_mcp_executor_registry_mtx, std::try_to_lock);
            if (!lk.owns_lock()) {
                if (capacity)
                    ++capacity->executor_registry_busy;
                return json::array();
            }
            executors = g_mcp_executor_registry;
        }
        if (capacity)
            capacity->executor_count = executors.size();
        json arr = json::array();
        for (auto* executor : executors) {
            if (!executor)
                continue;
            json item;
            (void)executor->try_snapshot_json(item, capacity);
            arr.push_back(std::move(item));
        }
        return arr;
    }

    class mcp_request_task_queue final : public httplib::TaskQueue
    {
    public:
        mcp_request_task_queue()
            : _executor("mcp_http_requests", mcp_concurrency_config().http_worker_threads, mcp_concurrency_config().http_max_queued_requests)
        {
        }

        bool enqueue(std::function<void()> fn) override
        {
            return _executor.enqueue(std::move(fn));
        }

        void shutdown() override
        {
            _executor.shutdown();
        }

    private:
        mcp_owned_executor_t _executor;
    };

    static mcp_owned_executor_t& mcp_batch_executor()
    {
        static mcp_owned_executor_t executor("mcp_jsonrpc_batch", mcp_concurrency_config().batch_worker_threads, mcp_concurrency_config().batch_max_queued_requests);
        return executor;
    }

    static mcp_owned_executor_t& mcp_tool_executor()
    {
        static mcp_owned_executor_t executor("mcp_tool_calls", mcp_concurrency_config().tool_worker_threads, mcp_concurrency_config().tool_max_queued_requests);
        return executor;
    }

    static std::string normalized_domain_key(const std::string& domain)
    {
        return domain.empty() ? std::string("misc") : domain;
    }

    static bool is_exclusive_domain_lane(const std::string& lane)
    {
        return lane.rfind("exclusive_domain_", 0) == 0;
    }

    static mcp_owned_executor_t& mcp_domain_tool_executor(const std::string& domain)
    {
        static std::mutex mtx;
        static std::map<std::string, std::shared_ptr<mcp_owned_executor_t>> executors;
        const std::string key = normalized_domain_key(domain);
        std::lock_guard<std::mutex> lk(mtx);
        auto it = executors.find(key);
        if (it != executors.end() && it->second)
            return *it->second;
        const std::string name = "mcp_domain_" + key;
        auto executor = std::make_shared<mcp_owned_executor_t>(name.c_str(), 1, mcp_concurrency_config().tool_max_queued_requests);
        auto* ptr = executor.get();
        executors.emplace(key, std::move(executor));
        return *ptr;
    }

    static std::string remote_endpoint(const httplib::Request& req)
    {
        std::string endpoint = req.remote_addr.empty() ? "<unknown>" : req.remote_addr;
        endpoint += ":";
        endpoint += std::to_string(req.remote_port);
        return endpoint;
    }

    static std::string mcp_identity_sanitize(const std::string& value, std::size_t max_len = 160)
    {
        std::string out;
        out.reserve((std::min)(value.size(), max_len));
        for (char ch : value) {
            if (out.size() >= max_len)
                break;
            const unsigned char c = static_cast<unsigned char>(ch);
            if (std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '/' || c == '@')
                out.push_back(static_cast<char>(c));
            else
                out.push_back('_');
        }
        return out.empty() ? std::string("<none>") : out;
    }

    static std::uint64_t mcp_identity_hash64(const std::string& value)
    {
        std::uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : value) {
            h ^= static_cast<std::uint64_t>(c);
            h *= 1099511628211ULL;
        }
        return h;
    }

    static std::string mcp_identity_hash_text(const std::string& value)
    {
        if (value.empty())
            return "<none>";
        char buf[32] = {};
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%016llx", static_cast<unsigned long long>(mcp_identity_hash64(value)));
        return buf;
    }

    static std::string mcp_request_transport(const httplib::Request& req)
    {
        if (req.path == "/mcp")
            return "JSON-RPC /mcp";
        if (req.path == "/sse" && req.method == "GET")
            return "/sse";
        if (req.path == "/sse")
            return "JSON-RPC /sse";
        if (req.path == "/message")
            return "JSON-RPC /message";
        if (req.path == "/api/tools")
            return "REST /api/tools";
        if (req.path == "/api/tools/call")
            return "REST /api/tools/call";
        if (req.path == "/health")
            return "/health";
        return mcp_identity_sanitize(req.method + " " + req.path, 120);
    }

    static mcp_route_identity_t make_mcp_route_identity(const httplib::Request& req, std::uint64_t request_id)
    {
        mcp_route_identity_t id;
        id.http_request_id = request_id;
        id.path = mcp_identity_sanitize(req.path, 120);
        id.http_method = mcp_identity_sanitize(req.method, 16);
        id.route = mcp_identity_sanitize(req.matched_route.empty() ? req.path : req.matched_route, 120);
        id.transport = mcp_request_transport(req);
        id.surface = id.transport.find("REST") != std::string::npos ? "REST" :
            (id.transport.find("JSON-RPC") != std::string::npos ? "JSON-RPC" : id.transport);
        id.remote = mcp_identity_sanitize(remote_endpoint(req), 120);
        std::string session_value = req.get_header_value("Mcp-Session-Id");
        id.session_source = session_value.empty() ? "" : "header:Mcp-Session-Id";
        if (session_value.empty()) {
            session_value = req.get_param_value("sessionId");
            id.session_source = session_value.empty() ? "" : "query:sessionId";
        }
        if (session_value.empty()) {
            session_value = req.get_param_value("session_id");
            id.session_source = session_value.empty() ? "" : "query:session_id";
        }
        id.session_id = mcp_identity_sanitize(session_value, 128);
        id.session_hash = mcp_identity_hash_text(session_value);
        if (id.session_source.empty())
            id.session_source = "missing";
        id.user_agent = mcp_identity_sanitize(req.get_header_value("User-Agent"), 120);
        id.origin = mcp_identity_sanitize(req.get_header_value("Origin"), 120);
        id.accept = mcp_identity_sanitize(req.get_header_value("Accept"), 120);
        id.content_type = mcp_identity_sanitize(req.get_header_value("Content-Type"), 120);
        id.protocol_version = mcp_identity_sanitize(req.get_header_value("MCP-Protocol-Version"), 48);
        id.authorization_present = !req.get_header_value("Authorization").empty();
        const bool loopback = req.remote_addr == "127.0.0.1" || req.remote_addr == "::1" || req.remote_addr == "localhost";
        if (!session_value.empty()) {
            id.principal_id = std::string(loopback ? "local-session:" : "remote-session:") + id.session_hash;
            id.principal_source = id.session_source;
        } else {
            const std::string principal_seed = req.remote_addr + "|" + req.get_header_value("User-Agent") + "|" + req.get_header_value("Origin");
            id.principal_id = std::string(loopback ? "local-client:" : "remote-client:") + fnv1a64_hex(principal_seed);
            id.principal_source = "remote_addr_user_agent_origin";
        }
        id.body_len = req.body.size();
        return id;
    }

    static bool request_connection_closed(const httplib::Request& req)
    {
        try {
            return req.is_connection_closed ? req.is_connection_closed() : false;
        } catch (...) {
            return false;
        }
    }

    static bool connection_closed_now(const std::function<bool()>& fn)
    {
        try {
            return fn ? fn() : false;
        } catch (...) {
            return false;
        }
    }

    thread_local const std::function<bool()>* tls_mcp_connection_closed_probe = nullptr;

    class scoped_mcp_connection_closed_probe_t
    {
    public:
        explicit scoped_mcp_connection_closed_probe_t(const std::function<bool()>& probe) noexcept
            : previous_(tls_mcp_connection_closed_probe)
        {
            tls_mcp_connection_closed_probe = &probe;
        }

        ~scoped_mcp_connection_closed_probe_t()
        {
            tls_mcp_connection_closed_probe = previous_;
        }

        scoped_mcp_connection_closed_probe_t(const scoped_mcp_connection_closed_probe_t&) = delete;
        scoped_mcp_connection_closed_probe_t& operator=(const scoped_mcp_connection_closed_probe_t&) = delete;

    private:
        const std::function<bool()>* previous_ = nullptr;
    };

    static bool current_mcp_connection_closed()
    {
        return tls_mcp_connection_closed_probe && connection_closed_now(*tls_mcp_connection_closed_probe);
    }

    struct mcp_stream_state_t
    {
        std::uint64_t id = 0;
        const char* route = "";
        std::string remote;
        std::string principal_id;
        std::string principal_source;
        std::string session_hash;
        std::string transport;
        std::uint64_t http_request_id = 0;
        std::uint64_t opened_tick = 0;
        std::atomic<bool> released{false};
        std::atomic<bool> done_called{false};
        std::mutex reason_mtx;
        std::string terminal_reason;
    };

    struct mcp_stream_bucket_t
    {
        std::size_t active = 0;
        std::uint64_t oldest_opened_tick = 0;
        std::uint64_t latest_opened_tick = 0;
    };

    std::mutex g_stream_slots_mtx;
    std::map<std::string, mcp_stream_bucket_t> g_stream_principal_buckets;
    std::map<std::uint64_t, std::shared_ptr<mcp_stream_state_t>> g_stream_active_slots;

    static std::size_t stream_active_count_unlocked()
    {
        const int active = g_active_streams.load(std::memory_order_acquire);
        return active < 0 ? std::size_t{0} : static_cast<std::size_t>(active);
    }

    static std::string stream_principal_id_for_request(const httplib::Request& req)
    {
        if (!tls_route_identity.principal_id.empty())
            return tls_route_identity.principal_id;
        return make_mcp_route_identity(req, tls_http_request_id).principal_id;
    }

    static std::string stream_principal_source_for_request(const httplib::Request& req)
    {
        if (!tls_route_identity.principal_source.empty())
            return tls_route_identity.principal_source;
        return make_mcp_route_identity(req, tls_http_request_id).principal_source;
    }

    static std::string stream_session_hash_for_request(const httplib::Request& req)
    {
        if (!tls_route_identity.session_hash.empty())
            return tls_route_identity.session_hash;
        return make_mcp_route_identity(req, tls_http_request_id).session_hash;
    }

    static std::string stream_transport_for_request(const httplib::Request& req)
    {
        if (!tls_route_identity.transport.empty())
            return tls_route_identity.transport;
        return make_mcp_route_identity(req, tls_http_request_id).transport;
    }

    static void mark_stream_terminal_reason(mcp_stream_state_t* state, const char* reason)
    {
        if (!state || !reason || !reason[0])
            return;
        std::lock_guard<std::mutex> lk(state->reason_mtx);
        if (state->terminal_reason.empty())
            state->terminal_reason = reason;
    }

    static void mark_stream_terminal_reason(const std::shared_ptr<mcp_stream_state_t>& state, const char* reason)
    {
        mark_stream_terminal_reason(state.get(), reason);
    }

    static std::string stream_terminal_reason(const std::shared_ptr<mcp_stream_state_t>& state, const char* fallback)
    {
        if (!state)
            return fallback && fallback[0] ? fallback : "";
        std::lock_guard<std::mutex> lk(state->reason_mtx);
        return state->terminal_reason.empty() ? std::string(fallback && fallback[0] ? fallback : "") : state->terminal_reason;
    }

    static std::string stream_terminal_reason(mcp_stream_state_t* state, const char* fallback)
    {
        if (!state)
            return fallback && fallback[0] ? fallback : "";
        std::lock_guard<std::mutex> lk(state->reason_mtx);
        return state->terminal_reason.empty() ? std::string(fallback && fallback[0] ? fallback : "") : state->terminal_reason;
    }

    static void set_stream_rejection_response(httplib::Response& res,
                                              const char* code,
                                              const char* message,
                                              const char* route,
                                              const std::string& principal_id,
                                              const std::string& session_hash,
                                              const std::string& scope,
                                              std::size_t observed,
                                              std::size_t limit,
                                              std::size_t active_streams,
                                              std::size_t principal_streams)
    {
        json body;
        body["error"] = {
            {"code", code ? code : "mcp_stream_rejected"},
            {"message", message ? message : "MCP SSE stream was not started."},
            {"data", {
                {"disposition", "not_started"},
                {"route", route ? route : "<unknown>"},
                {"principal_id", principal_id},
                {"session_hash", session_hash},
                {"scope", scope},
                {"observed", observed},
                {"limit", limit},
                {"active_streams", active_streams},
                {"principal_active_streams", principal_streams}
            }}
        };
        res.status = 503;
        res.set_header("Retry-After", "2");
        res.set_content(json_dump_safe(body), "application/json");
    }

    static void set_stream_setup_closed_response(httplib::Response& res,
                                                 const char* route,
                                                 const std::string& principal_id,
                                                 const std::string& session_hash)
    {
        json body;
        body["error"] = {
            {"code", "mcp_stream_setup_closed"},
            {"message", "MCP SSE stream setup stopped because the client connection closed."},
            {"data", {
                {"disposition", "not_started"},
                {"route", route ? route : "<unknown>"},
                {"principal_id", principal_id},
                {"session_hash", session_hash}
            }}
        };
        res.status = 499;
        res.set_content(json_dump_safe(body), "application/json");
    }

    static void release_stream_slot(const std::shared_ptr<mcp_stream_state_t>& state, bool success, const char* reason);

    static std::shared_ptr<mcp_stream_state_t> acquire_stream_slot(const char* route, const httplib::Request& req, httplib::Response& res)
    {
        const auto& cfg = mcp_concurrency_config();
        const std::size_t max_streams = cfg.max_concurrent_streams;
        const std::size_t max_principal_streams = cfg.max_concurrent_streams_per_principal;
        const char* route_name = route ? route : "<unknown>";
        const std::string remote = remote_endpoint(req);
        const std::string principal_id = stream_principal_id_for_request(req);
        const std::string principal_source = stream_principal_source_for_request(req);
        const std::string session_hash = stream_session_hash_for_request(req);
        const std::string transport = stream_transport_for_request(req);
        const std::uint64_t request_id = tls_http_request_id;
        std::size_t active_streams = 0;
        std::size_t principal_streams = 0;
        if (request_connection_closed(req)) {
            {
                std::lock_guard<std::mutex> lk(g_stream_slots_mtx);
                active_streams = stream_active_count_unlocked();
                auto it = g_stream_principal_buckets.find(principal_id);
                principal_streams = it == g_stream_principal_buckets.end() ? std::size_t{0} : it->second.active;
            }
            diag::log_tagged_fmt("mcp_srv",
                "MCP-STREAM-REJECT route=%s transport=%s principal=%s principal_source=%s session_hash=%s remote=%s reason=connection_closed_before_admission scope=connection observed=0 limit=0 active_streams=%zu principal_active_streams=%zu max_streams=%zu per_principal_limit=%zu request_id=%llu pid=%lu tid=%lu active_requests=%d disposition=not_started",
                route_name,
                transport.c_str(),
                principal_id.c_str(),
                principal_source.c_str(),
                session_hash.c_str(),
                remote.c_str(),
                active_streams,
                principal_streams,
                max_streams,
                max_principal_streams,
                static_cast<unsigned long long>(request_id),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                g_active_http_requests.load(std::memory_order_acquire));
            set_stream_setup_closed_response(res, route_name, principal_id, session_hash);
            return {};
        }

        std::shared_ptr<mcp_stream_state_t> state;
        std::string reject_scope;
        std::size_t reject_observed = 0;
        std::size_t reject_limit = 0;
        {
            std::lock_guard<std::mutex> lk(g_stream_slots_mtx);
            active_streams = stream_active_count_unlocked();
            auto bucket_it = g_stream_principal_buckets.find(principal_id);
            principal_streams = bucket_it == g_stream_principal_buckets.end() ? std::size_t{0} : bucket_it->second.active;
            if (active_streams >= max_streams) {
                reject_scope = "global";
                reject_observed = active_streams;
                reject_limit = max_streams;
            } else if (principal_streams >= max_principal_streams) {
                reject_scope = "principal";
                reject_observed = principal_streams;
                reject_limit = max_principal_streams;
            } else {
                const std::uint64_t now = mcp_now_ms();
                state = std::make_shared<mcp_stream_state_t>();
                state->id = g_stream_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
                state->route = route_name;
                state->remote = remote;
                state->principal_id = principal_id;
                state->principal_source = principal_source;
                state->session_hash = session_hash;
                state->transport = transport;
                state->http_request_id = request_id;
                state->opened_tick = now;
                auto& bucket = g_stream_principal_buckets[principal_id];
                if (bucket.active == 0)
                    bucket.oldest_opened_tick = now;
                bucket.latest_opened_tick = now;
                ++bucket.active;
                ++active_streams;
                ++principal_streams;
                g_active_streams.store(static_cast<int>(active_streams), std::memory_order_release);
                g_stream_active_slots[state->id] = state;
            }
        }

        if (!state) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-STREAM-REJECT route=%s transport=%s principal=%s principal_source=%s session_hash=%s remote=%s reason=capacity_unavailable scope=%s observed=%zu limit=%zu active_streams=%zu principal_active_streams=%zu max_streams=%zu per_principal_limit=%zu request_id=%llu pid=%lu tid=%lu active_requests=%d disposition=not_started",
                route_name,
                transport.c_str(),
                principal_id.c_str(),
                principal_source.c_str(),
                session_hash.c_str(),
                remote.c_str(),
                reject_scope.c_str(),
                reject_observed,
                reject_limit,
                active_streams,
                principal_streams,
                max_streams,
                max_principal_streams,
                static_cast<unsigned long long>(request_id),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                g_active_http_requests.load(std::memory_order_acquire));
            set_stream_rejection_response(res,
                "mcp_stream_capacity_exhausted",
                "MCP SSE stream capacity exhausted; stream was not started.",
                route_name,
                principal_id,
                session_hash,
                reject_scope,
                reject_observed,
                reject_limit,
                active_streams,
                principal_streams);
            return {};
        }

        diag::log_tagged_fmt("mcp_srv",
            "MCP-STREAM-ADMIT id=%llu route=%s transport=%s principal=%s principal_source=%s session_hash=%s remote=%s request_id=%llu active_streams=%zu principal_active_streams=%zu max_streams=%zu per_principal_limit=%zu pid=%lu tid=%lu active_requests=%d",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            state->transport.c_str(),
            state->principal_id.c_str(),
            state->principal_source.c_str(),
            state->session_hash.c_str(),
            state->remote.c_str(),
            static_cast<unsigned long long>(state->http_request_id),
            active_streams,
            principal_streams,
            max_streams,
            max_principal_streams,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_active_http_requests.load(std::memory_order_acquire));

        if (request_connection_closed(req)) {
            mark_stream_terminal_reason(state, "setup_connection_closed");
            release_stream_slot(state, false, "setup_connection_closed");
            set_stream_setup_closed_response(res, route_name, principal_id, session_hash);
            return {};
        }

        return state;
    }

    static void release_stream_slot(mcp_stream_state_t* state, bool success, const char* reason)
    {
        if (!state)
            return;
        if (state->released.exchange(true, std::memory_order_acq_rel))
            return;
        mark_stream_terminal_reason(state, reason);
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = now >= state->opened_tick ? now - state->opened_tick : 0;
        std::size_t active_after = 0;
        std::size_t principal_after = 0;
        {
            std::lock_guard<std::mutex> lk(g_stream_slots_mtx);
            const std::size_t active_before = stream_active_count_unlocked();
            active_after = active_before == 0 ? std::size_t{0} : active_before - 1u;
            g_active_streams.store(static_cast<int>(active_after), std::memory_order_release);
            g_stream_active_slots.erase(state->id);
            auto bucket_it = g_stream_principal_buckets.find(state->principal_id);
            if (bucket_it != g_stream_principal_buckets.end()) {
                if (bucket_it->second.active != 0)
                    --bucket_it->second.active;
                principal_after = bucket_it->second.active;
                if (bucket_it->second.active == 0)
                    g_stream_principal_buckets.erase(bucket_it);
            }
        }
        const std::string final_reason = stream_terminal_reason(state, reason ? reason : "");
        diag::log_tagged_fmt("mcp_srv",
            "MCP-STREAM-RELEASE id=%llu route=%s transport=%s principal=%s session_hash=%s remote=%s success=%d reason=%s elapsed_ms=%llu request_id=%llu pid=%lu tid=%lu active_streams=%zu principal_active_streams=%zu active_requests=%d",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            state->transport.c_str(),
            state->principal_id.c_str(),
            state->session_hash.c_str(),
            state->remote.c_str(),
            success ? 1 : 0,
            final_reason.c_str(),
            static_cast<unsigned long long>(elapsed),
            static_cast<unsigned long long>(state->http_request_id),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            principal_after,
            g_active_http_requests.load(std::memory_order_acquire));
    }

    static void release_stream_slot(const std::shared_ptr<mcp_stream_state_t>& state, bool success, const char* reason)
    {
        release_stream_slot(state.get(), success, reason);
    }

    static void release_all_stream_slots(const char* reason)
    {
        std::vector<std::shared_ptr<mcp_stream_state_t>> streams;
        {
            std::lock_guard<std::mutex> lk(g_stream_slots_mtx);
            for (const auto& item : g_stream_active_slots) {
                if (item.second)
                    streams.push_back(item.second);
            }
        }
        for (const auto& stream : streams)
            release_stream_slot(stream, false, reason ? reason : "shutdown");
    }

    static json stream_capacity_health_snapshot()
    {
        const auto& cfg = mcp_concurrency_config();
        const std::uint64_t now = mcp_now_ms();
        json buckets = json::object();
        std::size_t emitted = 0;
        std::size_t truncated = 0;
        std::size_t active_streams = 0;
        std::size_t active_slot_records = 0;
        {
            std::lock_guard<std::mutex> lk(g_stream_slots_mtx);
            active_streams = stream_active_count_unlocked();
            active_slot_records = g_stream_active_slots.size();
            for (const auto& item : g_stream_principal_buckets) {
                if (emitted >= 32) {
                    ++truncated;
                    continue;
                }
                const auto& bucket = item.second;
                const std::uint64_t oldest_age = bucket.oldest_opened_tick != 0 && now >= bucket.oldest_opened_tick ? now - bucket.oldest_opened_tick : 0;
                const std::uint64_t latest_age = bucket.latest_opened_tick != 0 && now >= bucket.latest_opened_tick ? now - bucket.latest_opened_tick : 0;
                buckets[item.first] = {
                    {"active", bucket.active},
                    {"oldest_active_ms", oldest_age},
                    {"latest_open_age_ms", latest_age}
                };
                ++emitted;
            }
        }
        return {
            {"active", active_streams},
            {"active_slot_records", active_slot_records},
            {"global_limit", cfg.max_concurrent_streams},
            {"per_principal_limit", cfg.max_concurrent_streams_per_principal},
            {"bucket_count", emitted + truncated},
            {"buckets_truncated", truncated},
            {"per_principal", buckets}
        };
    }

    static void finish_stream_cleanly(mcp_stream_state_t* state, httplib::DataSink& sink, const char* reason, bool success = true)
    {
        if (!state || state->done_called.exchange(true, std::memory_order_acq_rel))
            return;
        mark_stream_terminal_reason(state, reason);
        diag::log_tagged_fmt("mcp_srv",
            "stream_done id=%llu route=%s reason=%s remote=%s pid=%lu tid=%lu",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            reason ? reason : "",
            state->remote.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        release_stream_slot(state, success, reason);
        if (sink.done)
            sink.done();
    }

    static void finish_stream_cleanly(const std::shared_ptr<mcp_stream_state_t>& state, httplib::DataSink& sink, const char* reason, bool success = true)
    {
        finish_stream_cleanly(state.get(), sink, reason, success);
    }
}

    std::size_t active_http_request_count() noexcept
    {
        return static_cast<std::size_t>(std::max(0, g_active_http_requests.load(std::memory_order_acquire)));
    }

    static void format_active_session_owner_diagnostic_snapshot(char* out, std::size_t cap) noexcept;

    void format_runtime_diagnostic_snapshot(char* out, std::size_t cap) noexcept
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    try {
        char owner_snapshot[900] = {};
        format_active_session_owner_diagnostic_snapshot(owner_snapshot, sizeof(owner_snapshot));
        mcp_executor_counts_t counts;
        std::size_t executor_count = 0;
        bool registry_lock_busy = false;
        {
            std::unique_lock<std::mutex> lk(g_mcp_executor_registry_mtx, std::try_to_lock);
            if (lk.owns_lock()) {
                executor_count = g_mcp_executor_registry.size();
                for (auto* executor : g_mcp_executor_registry) {
                    if (!executor)
                        continue;
                    if (!executor->try_snapshot_counts(counts))
                        ++counts.snapshot_busy;
                }
            } else {
                registry_lock_busy = true;
            }
        }
        const auto command_stats = command_sessions::stats();
        _snprintf_s(out, cap, _TRUNCATE,
            "mcp{active_requests=%d active_streams=%d cached_tools=%zu health_ready=%d executors=%zu registry_lock_busy=%d snapshotted=%zu snapshot_busy=%zu workers=%zu active=%llu queued=%zu long_active=%llu long_queued=%llu oldest_active_ms=%llu enqueued=%llu started=%llu finished=%llu rejected=%llu worker_failures=%llu command_total=%zu command_running=%zu command_reader_active=%zu command_timed_out=%zu command_oldest_ms=%llu owner=%.760s queue_summary=%.700s active_summary=%.900s}",
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire),
            g_cached_external_tool_count.load(std::memory_order_acquire),
            g_cached_health_ready.load(std::memory_order_acquire) ? 1 : 0,
            executor_count,
            registry_lock_busy ? 1 : 0,
            counts.snapshotted,
            counts.snapshot_busy,
            counts.workers,
            static_cast<unsigned long long>(counts.active),
            counts.queued,
            static_cast<unsigned long long>(counts.active_long_running),
            static_cast<unsigned long long>(counts.queued_long_running),
            static_cast<unsigned long long>(counts.oldest_active_ms),
            static_cast<unsigned long long>(counts.enqueued),
            static_cast<unsigned long long>(counts.started),
            static_cast<unsigned long long>(counts.finished),
            static_cast<unsigned long long>(counts.rejected),
            static_cast<unsigned long long>(counts.worker_failures),
            command_stats.total,
            command_stats.running,
            command_stats.reader_active,
            command_stats.timed_out,
            static_cast<unsigned long long>(command_stats.oldest_running_ms),
            owner_snapshot[0] ? owner_snapshot : "owner{empty=1}",
            counts.queue_summary.empty() ? "<none>" : counts.queue_summary.c_str(),
            counts.active_summary.empty() ? "<none>" : counts.active_summary.c_str());
    } catch (...) {
        _snprintf_s(out, cap, _TRUNCATE,
            "mcp{snapshot_exception=1 active_requests=%d active_streams=%d}",
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire));
    }
}

static std::string json_dump_safe(const json& j, int indent)
{
    try { return j.dump(indent, '\t', false, nlohmann::json::error_handler_t::replace); }
    catch (const std::exception& e) {
        diag::log_tagged_fmt("mcp_srv", "json_dump_safe exception what='%s' type=json_dump", e.what());
        return "{}";
    } catch (...) {
        diag::log_tagged_fmt("mcp_srv", "json_dump_safe unknown_exception type=json_dump");
        return "{}";
    }
}

void set_ide_lifecycle_ready(bool ready) noexcept
{
    g_ide_lifecycle_ready.store(ready, std::memory_order_release);
}

void set_pre_dispatch_validation_hook(tool_validation_hook_t hook)
{
    std::lock_guard<std::mutex> lk(g_pre_dispatch_validation_hook_mtx);
    g_pre_dispatch_validation_hook = std::move(hook);
}

bool lifecycle_authorized(std::string* reason)
{
    if (reason) *reason = "authorized";
    return true;
}

static std::string generate_secure_token(std::string_view prefix, std::size_t byte_count)
{
    if (byte_count == 0 || byte_count > 64)
        return {};
    std::array<unsigned char, 64> random_bytes{};
    const NTSTATUS status = BCryptGenRandom(
        nullptr, random_bytes.data(), static_cast<ULONG>(byte_count),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        RtlSecureZeroMemory(random_bytes.data(), random_bytes.size());
        return {};
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(prefix.size() + byte_count * 2U);
    token.append(prefix.data(), prefix.size());
    for (std::size_t index = 0; index < byte_count; ++index) {
        token.push_back(hex[random_bytes[index] >> 4U]);
        token.push_back(hex[random_bytes[index] & 0x0fU]);
    }
    RtlSecureZeroMemory(random_bytes.data(), random_bytes.size());
    return token;
}

static std::string generate_session_id()
{
    return generate_secure_token("sa-", 32);
}

static bool constant_time_equal_bounded(std::string_view supplied,
                                        std::string_view expected,
                                        std::size_t maximum) noexcept
{
    const std::size_t compared = (std::min)(expected.size(), maximum);
    std::size_t difference = supplied.size() ^ expected.size();
    difference |= expected.size() > maximum ? 1U : 0U;
    for (std::size_t index = 0; index < compared; ++index) {
        const unsigned char actual = index < supplied.size()
            ? static_cast<unsigned char>(supplied[index]) : 0U;
        difference |= static_cast<std::size_t>(
            actual ^ static_cast<unsigned char>(expected[index]));
    }
    return difference == 0;
}

class scoped_secret_string_t final
{
public:
    explicit scoped_secret_string_t(std::string& value) noexcept : value_(&value) {}
    ~scoped_secret_string_t()
    {
        if (value_ != nullptr && !value_->empty())
            RtlSecureZeroMemory(value_->data(), value_->size());
    }
    scoped_secret_string_t(const scoped_secret_string_t&) = delete;
    scoped_secret_string_t& operator=(const scoped_secret_string_t&) = delete;

private:
    std::string* value_ = nullptr;
};

static local_request_auth_result_t authorize_local_request_impl(
    const local_request_auth_input_t& input,
    std::string_view expected_capability,
    std::string_view expected_run_binding)
{
    local_request_auth_result_t result;
    const bool loopback = input.remote_address == "127.0.0.1" ||
        input.remote_address == "::1" || input.remote_address == "localhost";
    const std::string expected_host = "127.0.0.1:" + std::to_string(input.bound_port);
    const std::string expected_localhost = "localhost:" + std::to_string(input.bound_port);
    std::string normalized_host;
    normalized_host.reserve((std::min)(input.host.size(), std::size_t{128}));
    for (const unsigned char value : input.host) {
        if (normalized_host.size() == 128U)
            break;
        normalized_host.push_back(static_cast<char>(std::tolower(value)));
    }
    const bool host_valid = input.host.size() == normalized_host.size() &&
        (normalized_host == expected_host || normalized_host == expected_localhost);
    std::string expected_authorization = "Bearer " + std::string(expected_capability);
    scoped_secret_string_t expected_authorization_guard(expected_authorization);
    (void)expected_authorization_guard;
    const bool capability_valid = constant_time_equal_bounded(
        input.authorization, expected_authorization, 160U);
    const bool run_binding_valid = constant_time_equal_bounded(
        input.run_binding, expected_run_binding, 160U);

    if (!loopback) {
        result.status = local_request_auth_status_t::invalid_remote;
        return result;
    }
    if (!host_valid || input.bound_port <= 0 || input.bound_port > 65535) {
        result.status = local_request_auth_status_t::invalid_host;
        return result;
    }
    if (!input.origin.empty()) {
        result.status = local_request_auth_status_t::browser_origin_forbidden;
        return result;
    }
    if (input.method == "GET" && input.path == "/health") {
        result.status = local_request_auth_status_t::health_read_only;
        result.allowed = true;
        return result;
    }
    if (input.authorization.empty()) {
        result.status = local_request_auth_status_t::capability_missing;
        return result;
    }
    if (expected_capability.empty() || !capability_valid) {
        result.status = local_request_auth_status_t::capability_rejected;
        return result;
    }
    if (input.run_binding.empty()) {
        result.status = local_request_auth_status_t::run_binding_missing;
        return result;
    }
    if (expected_run_binding.empty() || !run_binding_valid) {
        result.status = local_request_auth_status_t::run_binding_rejected;
        return result;
    }
    result.status = local_request_auth_status_t::allowed;
    result.allowed = true;
    result.capability_authenticated = true;
    return result;
}

local_request_auth_result_t authorize_local_request(
    const local_request_auth_input_t& input,
    std::string_view expected_capability,
    std::string_view expected_run_binding) noexcept
{
    try {
        return authorize_local_request_impl(
            input, expected_capability, expected_run_binding);
    } catch (...) {
        return {};
    }
}

static bool route_secret_equal(std::string_view supplied,
                               std::string_view prefix,
                               std::string_view expected) noexcept
{
    std::size_t difference = supplied.size() ^ (prefix.size() + expected.size());
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        const unsigned char actual = index < supplied.size()
            ? static_cast<unsigned char>(supplied[index]) : 0U;
        difference |= static_cast<std::size_t>(
            actual ^ static_cast<unsigned char>(prefix[index]));
    }
    for (std::size_t reverse = expected.size(); reverse != 0; --reverse) {
        const std::size_t index = reverse - 1U;
        const std::size_t supplied_index = prefix.size() + index;
        const unsigned char actual = supplied_index < supplied.size()
            ? static_cast<unsigned char>(supplied[supplied_index]) : 0U;
        difference |= static_cast<std::size_t>(
            actual ^ static_cast<unsigned char>(expected[index]));
    }
    return difference == 0 && !expected.empty();
}

bool verify_local_route_capability(
    std::string_view authorization,
    std::string_view run_binding,
    std::string_view origin,
    std::string_view expected_capability,
    std::string_view expected_run_binding) noexcept
{
    const bool capability_valid = route_secret_equal(
        authorization, "Bearer ", expected_capability);
    const bool run_binding_valid = route_secret_equal(
        run_binding, std::string_view{}, expected_run_binding);
    return capability_valid && run_binding_valid && origin.empty();
}

static bool require_local_http_capability(
    const httplib::Request& request,
    httplib::Response& response,
    std::string_view expected_capability,
    std::string_view expected_run_binding)
{
    if (tls_local_capability_authenticated && verify_local_route_capability(
            request.get_header_value("Authorization"),
            request.get_header_value("X-AiDA-MCP-Run-Id"),
            request.get_header_value("Origin"),
            expected_capability, expected_run_binding))
        return true;
    response.status = 403;
    response.set_header("Cache-Control", "no-store");
    response.set_content(R"({"status":"rejected","error":"MCP local authorization failed","code":"MCP_LOCAL_AUTH_REQUIRED","disposition":"not_started"})", "application/json");
    return false;
}

static std::string read_env_var(const char* name)
{
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value)
        return {};
    std::string result(value);
    free(value);
    return result;
}

static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size(); )
    {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i+1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; result += input[i+3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string result;
    bool cap = true;
    for (char c : name) {
        if (c == '_') {
            result += ' ';
            cap = true;
        } else {
            result += cap ? static_cast<char>(toupper(c)) : c;
            cap = false;
        }
    }
    return result;
}

static std::string lower_ascii(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

static bool json_bool_param(const json& params, const char* name)
{
    if (!params.is_object() || !params.contains(name))
        return false;
    const auto& value = params[name];
    if (value.is_boolean())
        return value.get<bool>();
    if (value.is_string()) {
        const std::string v = lower_ascii(value.get<std::string>());
        return v == "1" || v == "true" || v == "yes" || v == "full";
    }
    return false;
}

static bool wants_full_tool_list(const json& params)
{
    if (!params.is_object())
        return false;
    if (json_bool_param(params, "full") ||
        json_bool_param(params, "includeDescriptions") ||
        json_bool_param(params, "include_descriptions") ||
        json_bool_param(params, "includeSchema") ||
        json_bool_param(params, "include_schema")) {
        return true;
    }
    if (params.contains("detail") && params["detail"].is_string()) {
        const std::string detail = lower_ascii(params["detail"].get<std::string>());
        return detail == "full" || detail == "description" ||
               detail == "descriptions" || detail == "schema" ||
               detail == "schemas";
    }
    return false;
}

static bool schema_enum_char(unsigned char c)
{
    return std::isalnum(c) || c == '_' || c == '-' || c == '|';
}

static std::string trim_schema_token(std::string token)
{
    while (!token.empty() && !schema_enum_char(static_cast<unsigned char>(token.front())))
        token.erase(token.begin());
    while (!token.empty() && !schema_enum_char(static_cast<unsigned char>(token.back())))
        token.pop_back();
    return token;
}

static json enum_values_from_description(const std::string& description)
{
    json out = json::array();
    const size_t pipe = description.find('|');
    if (pipe == std::string::npos)
        return out;

    size_t start = pipe;
    while (start > 0 && schema_enum_char(static_cast<unsigned char>(description[start - 1])))
        --start;
    size_t end = pipe + 1;
    while (end < description.size() && schema_enum_char(static_cast<unsigned char>(description[end])))
        ++end;

    std::string segment = description.substr(start, end - start);
    std::vector<std::string> values;
    size_t cursor = 0;
    while (cursor <= segment.size()) {
        const size_t next = segment.find('|', cursor);
        std::string token = trim_schema_token(segment.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor));
        if (token.empty() || token.size() > 64)
            return json::array();
        values.push_back(std::move(token));
        if (next == std::string::npos)
            break;
        cursor = next + 1;
    }

    if (values.size() < 2 || values.size() > 64)
        return json::array();
    for (const auto& value : values)
        out.push_back(value);
    return out;
}

static json build_input_schema(const tool_def_t& tool)
{
    json input_schema;
    input_schema["type"] = "object";
    json properties = json::object();
    json required_arr = json::array();

    for (const auto& p : tool.params) {
        json desc;
        desc["description"] = p.description;
        if (p.type.find('|') != std::string::npos) {
            json one_of = json::array();
            size_t start = 0;
            while (start <= p.type.size()) {
                size_t end = p.type.find('|', start);
                if (end == std::string::npos)
                    end = p.type.size();
                std::string type_name = p.type.substr(start, end - start);
                if (!type_name.empty())
                    one_of.push_back(json{{"type", type_name}});
                if (end == p.type.size())
                    break;
                start = end + 1;
            }
            desc["oneOf"] = std::move(one_of);
        } else {
            desc["type"] = p.type;
        }
        json enum_values = enum_values_from_description(p.description);
        if (!enum_values.empty())
            desc["enum"] = std::move(enum_values);
        properties[p.name] = desc;
        if (p.required)
            required_arr.push_back(p.name);
    }

    input_schema["properties"] = properties;
    if (!required_arr.empty())
        input_schema["required"] = required_arr;
    return input_schema;
}

static const char* visibility_name(tool_visibility_t visibility)
{
    switch (visibility) {
    case tool_visibility_t::external_visible:
        return "external_visible";
    case tool_visibility_t::internal_only:
        return "internal_only";
    case tool_visibility_t::ide_chat_only:
        return "ide_chat_only";
    default:
        return "unknown";
    }
}

static bool is_camoufox_browser_tool_name(const std::string& name);

static std::string infer_tool_domain(const std::string& name)
{
    if (name.rfind("browser_", 0) == 0)
        return "browser";
    if (name == "burp_scanner_manage")
        return "scanner";
    if (name.rfind("burp_", 0) == 0)
        return "burp";
    if (name.rfind("network_", 0) == 0)
        return "network";
    if (name.rfind("net_security_", 0) == 0)
        return "network_security";
    if (name.rfind("net_proto_", 0) == 0)
        return "network_protocol";
    const size_t underscore = name.find('_');
    if (underscore == std::string::npos || underscore == 0)
        return {};
    return name.substr(0, underscore);
}

static bool tool_group_noise_token(const std::string& token)
{
    static const char* const noise[] = {
        "aida", "aidastandalone", "all", "complete", "description", "descriptions",
        "every", "full", "group", "groups", "mcp", "pack", "packs", "schema",
        "schemas", "standalone", "tool", "tools"
    };
    for (const char* n : noise) {
        if (token == n)
            return true;
    }
    return false;
}

static std::string normalize_tool_group_name(const std::string& text)
{
    std::string lowered = lower_ascii(text);
    std::vector<std::string> tokens;
    std::string current;
    for (char c : lowered) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc)) {
            current.push_back(static_cast<char>(uc));
        } else {
            if (!current.empty()) {
                if (!tool_group_noise_token(current))
                    tokens.push_back(current);
                current.clear();
            }
        }
    }
    if (!current.empty() && !tool_group_noise_token(current))
        tokens.push_back(current);

    if (tokens.size() == 1) {
        const std::string& token = tokens[0];
        if (token == "browser" || token == "browsers" || token == "camoufox")
            return "browser";
        if (token == "network" || token == "networks" || token == "networking")
            return "network";
        if (token == "burp" || token == "burpsuite")
            return "burp";
    }
    if (tokens.size() == 2 && tokens[0] == "burp" && tokens[1] == "suite")
        return "burp";
    return {};
}

static bool tool_matches_description_group(const tool_def_t& tool, const std::string& group)
{
    const std::string name_l = lower_ascii(tool.name);
    const std::string desc_l = lower_ascii(tool.description);
    const std::string domain = infer_tool_domain(tool.name);

    if (group == "browser") {
        return domain == "browser" ||
               is_camoufox_browser_tool_name(tool.name) ||
               name_l.find("browser") != std::string::npos ||
               name_l.find("camoufox") != std::string::npos ||
               desc_l.find("browser") != std::string::npos ||
               desc_l.find("camoufox") != std::string::npos;
    }
    if (group == "network") {
        return domain == "network" ||
               domain == "network_security" ||
               domain == "network_protocol" ||
               name_l.rfind("network_", 0) == 0 ||
               name_l.rfind("net_security_", 0) == 0 ||
               name_l.rfind("net_proto_", 0) == 0 ||
               name_l.find("_network") != std::string::npos;
    }
    if (group == "burp") {
        return domain == "burp" ||
               tool.name == "burp_scanner_manage" ||
               name_l.rfind("burp_", 0) == 0 ||
               desc_l.find("burp") != std::string::npos;
    }
    return false;
}

static const char* json_type_label(const json& value)
{
    if (value.is_object()) return "object";
    if (value.is_array()) return "array";
    if (value.is_string()) return "string";
    if (value.is_boolean()) return "boolean";
    if (value.is_number_integer()) return "integer";
    if (value.is_number_unsigned()) return "unsigned";
    if (value.is_number_float()) return "float";
    if (value.is_null()) return "null";
    return "unknown";
}

static std::string payload_shape_summary(const json& value)
{
    std::ostringstream oss;
    if (!value.is_object()) {
        oss << json_type_label(value);
        if (value.is_array())
            oss << "[len=" << value.size() << "]";
        if (value.is_string())
            oss << "[chars=" << value.get_ref<const std::string&>().size() << "]";
        return oss.str();
    }
    oss << "object[keys=" << value.size() << "]";
    std::size_t emitted = 0;
    for (auto it = value.begin(); it != value.end() && emitted < 16; ++it, ++emitted) {
        oss << (emitted == 0 ? ":" : ",") << it.key() << "=" << json_type_label(it.value());
        if (it.value().is_array())
            oss << "[" << it.value().size() << "]";
        else if (it.value().is_object())
            oss << "{" << it.value().size() << "}";
        else if (it.value().is_string())
            oss << "(" << it.value().get_ref<const std::string&>().size() << ")";
    }
    if (value.size() > emitted)
        oss << ",...";
    std::string out = oss.str();
    if (out.size() > 384)
        out.resize(384);
    return out;
}

static std::string request_id_string(const json& id)
{
    if (id.is_null())
        return "null";
    if (id.is_string())
        return id.get<std::string>();
    if (id.is_number_integer())
        return std::to_string(id.get<std::int64_t>());
    if (id.is_number_unsigned())
        return std::to_string(id.get<std::uint64_t>());
    std::string dumped = json_dump_safe(id);
    if (dumped.size() > 160)
        dumped.resize(160);
    return dumped;
}

static std::uint32_t target_pid_from_args(const json& args)
{
    if (!args.is_object())
        return 0;
    for (const char* key : {"target_pid", "process_id", "pid"}) {
        if (!args.contains(key))
            continue;
        const auto& v = args[key];
        try {
            if (v.is_number_unsigned())
                return static_cast<std::uint32_t>(v.get<std::uint64_t>());
            if (v.is_number_integer()) {
                const auto s = v.get<std::int64_t>();
                return s > 0 ? static_cast<std::uint32_t>(s) : 0;
            }
            if (v.is_string()) {
                const std::string s = v.get<std::string>();
                if (!s.empty())
                    return static_cast<std::uint32_t>(std::stoul(s, nullptr, 0));
            }
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

static std::string audit_session_id_from_args(const json& args)
{
    if (args.is_object() && args.contains("session_id") && args["session_id"].is_string())
        return args["session_id"].get<std::string>();
    return {};
}

static std::uint64_t audit_scan_id_from_args(const json& args)
{
    if (!args.is_object() || !args.contains("scan_id"))
        return 0;
    const auto& v = args["scan_id"];
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        const auto signed_value = v.get<std::int64_t>();
        return signed_value > 0 ? static_cast<std::uint64_t>(signed_value) : 0;
    }
    if (v.is_string()) {
        try {
            const std::string text = v.get<std::string>();
            size_t used = 0;
            const std::uint64_t parsed = std::stoull(text, &used);
            return used == text.size() ? parsed : 0;
        } catch (...) {
        }
    }
    return 0;
}

static json audit_result_payload(const std::string& status,
                                 bool success,
                                 const json& result,
                                 const std::string& diagnostic_id,
                                 const std::string& request_id)
{
    json out = json::object();
    out["status"] = status;
    out["success"] = success;
    out["diagnostic_id"] = diagnostic_id;
    out["request_id"] = request_id;
    if (result.is_object() || result.is_array())
        out["result"] = result;
    else if (!result.is_null())
        out["result"] = result;
    return out;
}

static void record_tool_audit_event(const std::string& tool_name,
                                    const json& arguments,
                                    const std::string& status,
                                    bool success,
                                    const json& result,
                                    const std::string& error_message,
                                    std::uint64_t started_ms,
                                    const std::string& diagnostic_id,
                                    const std::string& request_id) noexcept
{
    try {
        aida::burp::audit_trail::event_t event;
        event.session_id = audit_session_id_from_args(arguments);
        event.scan_id = audit_scan_id_from_args(arguments);
        event.timestamp_ms = started_ms == 0 ? mcp_now_ms() : started_ms;
        event.tool_name = tool_name.empty() ? std::string("<unknown>") : tool_name;
        event.parameters_json = arguments.is_object() ? arguments : json::object();
        event.result_json = audit_result_payload(status, success, result, diagnostic_id, request_id);
        const std::uint64_t end = mcp_now_ms();
        event.duration_ms = end >= event.timestamp_ms ? end - event.timestamp_ms : 0;
        event.caller = "external_mcp";
        event.success = success;
        event.error_message = error_message;
        aida::burp::audit_trail::record(event, nullptr);
    } catch (...) {
    }
}

struct tool_timeout_resolution_t
{
    std::uint64_t requested_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t effective_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t default_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t max_ms = kMcpMaxToolTimeoutMs;
    bool explicit_timeout = false;
    bool action_aware = false;
    std::string action;
    std::string source = "default";
};

static bool json_positive_u64(const json& v, std::uint64_t& out)
{
    try {
        if (v.is_number_unsigned()) {
            const auto n = v.get<std::uint64_t>();
            if (n > 0) {
                out = n;
                return true;
            }
        } else if (v.is_number_integer()) {
            const auto n = v.get<std::int64_t>();
            if (n > 0) {
                out = static_cast<std::uint64_t>(n);
                return true;
            }
        } else if (v.is_string()) {
            const std::string s = v.get<std::string>();
            if (!s.empty()) {
                const auto n = static_cast<std::uint64_t>(std::stoull(s, nullptr, 0));
                if (n > 0) {
                    out = n;
                    return true;
                }
            }
        }
    } catch (...) {
    }
    return false;
}

static bool json_positive_u64_field(const json& obj, const char* key, std::uint64_t& out)
{
    if (!obj.is_object() || !obj.contains(key))
        return false;
    return json_positive_u64(obj[key], out);
}

static const json* payload_object(const json& args)
{
    if (!args.is_object() || !args.contains("payload") || !args["payload"].is_object())
        return nullptr;
    return &args["payload"];
}

static std::string browser_action_from_args(const json& args)
{
    if (args.is_object()) {
        for (const char* key : {"action", "operation"}) {
            if (args.contains(key) && args[key].is_string())
                return lower_ascii(args[key].get<std::string>());
        }
    }
    if (const json* payload = payload_object(args)) {
        for (const char* key : {"action", "operation"}) {
            if (payload->contains(key) && (*payload)[key].is_string())
                return lower_ascii((*payload)[key].get<std::string>());
        }
    }
    return {};
}

static bool browser_arg_timeout_ms(const json& args, const char* key, std::uint64_t& out)
{
    if (json_positive_u64_field(args, key, out))
        return true;
    if (const json* payload = payload_object(args))
        return json_positive_u64_field(*payload, key, out);
    return false;
}

static bool browser_long_action(const std::string& tool_name, const std::string& action)
{
    if (tool_name == "browser_lifecycle")
        return action == "launch";
    if (tool_name == "browser_navigation")
        return action == "navigate" || action == "diagnose" || action == "matrix";
    return false;
}

static std::uint64_t browser_timeout_with_grace(std::uint64_t timeout_ms)
{
    if (timeout_ms > kMcpBrowserToolMaxTimeoutMs - kMcpBrowserCleanupGraceMs)
        return kMcpBrowserToolMaxTimeoutMs;
    return timeout_ms + kMcpBrowserCleanupGraceMs;
}

static std::uint64_t browser_duration_timeout_with_grace(std::uint64_t duration_s)
{
    const std::uint64_t max_seconds = (kMcpBrowserToolMaxTimeoutMs - kMcpBrowserCleanupGraceMs) / 1000ULL;
    if (duration_s > max_seconds)
        return kMcpBrowserToolMaxTimeoutMs;
    return duration_s * 1000ULL + kMcpBrowserCleanupGraceMs;
}

static tool_timeout_resolution_t resolve_tool_timeout(const std::string& tool_name, const json& args)
{
    tool_timeout_resolution_t r;
    const bool browser_tool = is_camoufox_browser_tool_name(tool_name);
    if (browser_tool) {
        r.max_ms = kMcpBrowserToolMaxTimeoutMs;
        r.action = browser_action_from_args(args);
        if (browser_long_action(tool_name, r.action)) {
            r.default_ms = kMcpBrowserLongActionTimeoutMs + kMcpBrowserCleanupGraceMs;
            r.action_aware = true;
            r.source = "browser_action_default";
        } else if (tool_name == "compare_env") {
            r.default_ms = 95000;
            r.action_aware = true;
            r.source = "browser_probe_default";
        } else if (tool_name == "browser_instrumentation" && r.action == "trace") {
            r.default_ms = 150000;
            r.action_aware = true;
            r.source = "browser_trace_default";
        }
    }
    r.requested_ms = r.default_ms;
    const char* const timeout_keys[] = {"tool_timeout_ms", "timeout_ms", "deadline_ms"};
    for (const char* key : timeout_keys) {
        std::uint64_t parsed = 0;
        if (json_positive_u64_field(args, key, parsed)) {
            r.requested_ms = parsed;
            r.explicit_timeout = true;
            r.source = std::string("explicit_") + key;
            break;
        }
    }
    if (browser_tool && !r.explicit_timeout) {
        std::uint64_t parsed = 0;
        if (browser_arg_timeout_ms(args, "call_timeout_ms", parsed)) {
            r.requested_ms = parsed;
            r.explicit_timeout = true;
            r.source = "explicit_call_timeout_ms";
        }
    }
    if (browser_tool) {
        std::uint64_t operation_timeout = 0;
        if (browser_arg_timeout_ms(args, "launch_timeout_ms", operation_timeout) ||
            browser_arg_timeout_ms(args, "timeout", operation_timeout)) {
            r.requested_ms = (std::max)(r.requested_ms, browser_timeout_with_grace(operation_timeout));
            r.action_aware = true;
            if (!r.explicit_timeout)
                r.source = "browser_operation_timeout";
        }
        std::uint64_t duration_s = 0;
        if (browser_arg_timeout_ms(args, "duration", duration_s)) {
            r.requested_ms = (std::max)(r.requested_ms, browser_duration_timeout_with_grace(duration_s));
            r.action_aware = true;
            if (!r.explicit_timeout)
                r.source = "browser_duration";
        }
        if (r.action_aware && r.requested_ms < r.default_ms) {
            r.requested_ms = r.default_ms;
            r.source += "_action_floor";
        }
    }
    r.effective_ms = std::clamp<std::uint64_t>(r.requested_ms, kMcpMinToolTimeoutMs, r.max_ms);
    return r;
}

static std::uint64_t saturated_deadline_ms(std::uint64_t start_ms, std::uint64_t timeout_ms)
{
    const std::uint64_t max_value = (std::numeric_limits<std::uint64_t>::max)();
    if (timeout_ms > max_value - start_ms)
        return max_value;
    return start_ms + timeout_ms;
}

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";
    result += "\n";
    return result;
}

struct sse_session_t
{
    std::string id;
    std::mutex  mtx;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};
    std::uint64_t opened_tick = mcp_now_ms();
    std::atomic<std::uint64_t> last_activity_tick{0};

    void push_event(const std::string& event)
    {
        last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
        std::lock_guard<std::mutex> lk(mtx);
        if (events.size() >= kSseMaxQueuedEvents) {
            diag::log_tagged_fmt("mcp_srv",
                "sse_session_queue_trim session=%s queued=%zu max=%zu",
                id.c_str(),
                events.size(),
                kSseMaxQueuedEvents);
            events.pop();
        }
        events.push(event);
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        const DWORD start_tick = GetTickCount();
        const DWORD timeout = static_cast<DWORD>(timeout_ms < 0 ? 0 : timeout_ms);
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lk(mtx);
                if (closed.load(std::memory_order_acquire))
                    return false;
                if (!events.empty()) {
                    out = std::move(events.front());
                    events.pop();
                    last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
                    return true;
                }
            }
            const DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= timeout)
                return false;
            const DWORD remaining = timeout - elapsed;
            Sleep(remaining < 50u ? remaining : 50u);
        }
    }

    void close() { closed.store(true, std::memory_order_release); }
};

static bool sse_provider_step_impl(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed)
{
    if (offset == 0) {
        std::string evt = format_sse_event("endpoint",
            "/message?sessionId=" + session->id);
        if (!sink->write(evt.c_str(), evt.size())) {
            mark_stream_terminal_reason(stream_state, "data_sink_endpoint_write_failed");
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=endpoint",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            release_stream_slot(stream_state, false, "data_sink_endpoint_write_failed");
            return false;
        }
    }
    if (connection_closed_now(connection_closed)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "connection_closed", false);
        return true;
    }
    std::string event;
    if (session->wait_event(event, 2000)) {
        if (!sink->write(event.c_str(), event.size())) {
            mark_stream_terminal_reason(stream_state, "data_sink_event_write_failed");
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=event",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            release_stream_slot(stream_state, false, "data_sink_event_write_failed");
            return false;
        }
    } else if (session->closed.load(std::memory_order_acquire)) {
        finish_stream_cleanly(stream_state, *sink, "session_closed", true);
        return true;
    } else if (stop_requested && stop_requested->load(std::memory_order_acquire)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "server_stop", true);
        return true;
    } else {
        const char ka[] = ": keepalive\n\n";
        if (sink->is_writable && !sink->is_writable()) {
            mark_stream_terminal_reason(stream_state, "data_sink_not_writable");
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            release_stream_slot(stream_state, false, "data_sink_not_writable");
            return false;
        }
        if (!sink->write(ka, sizeof(ka) - 1u)) {
            mark_stream_terminal_reason(stream_state, "data_sink_keepalive_write_failed");
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            release_stream_slot(stream_state, false, "data_sink_keepalive_write_failed");
            return false;
        }
    }
    return !session->closed.load(std::memory_order_acquire);
}

__declspec(noinline) static DWORD seh_sse_provider_step(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed,
    bool* out_continue)
{
    *out_continue = false;
    __try {
        *out_continue = sse_provider_step_impl(session, sink, offset, stop_requested, stream_state, connection_closed);
        return 0;
    } __except (aida::infra::win_thread::non_cpp_seh_filter(GetExceptionCode())) {
        return GetExceptionCode();
    }
}

static std::size_t mcp_lease_registry_signal_cancel_by_request_id_string(const std::string& request_id, const char* reason);

namespace
{
    class mcp_batch_child_reservation_t;
    static bool signal_batch_reservation_cancels(const json& id) noexcept;
    static void register_batch_reservation_cancel(const json& id, const std::shared_ptr<mcp_batch_child_reservation_t>& reservation) noexcept;
    static void unregister_batch_reservation_cancel(const json& id, std::uint64_t reservation_id) noexcept;

    std::mutex                                                       g_in_flight_mutex;
    std::map<std::string, std::vector<cancel_token_ptr_t>>            g_in_flight_cancels;

    std::string cancel_key_for_id(const json& id)
    {
        std::string key = tls_route_identity.session_hash.empty()
            ? tls_route_identity.principal_id
            : tls_route_identity.session_hash;
        if (key.empty())
            key = "<none>";
        key.push_back('\x1f');
        if (id.is_null())              key += "null";
        else if (id.is_string())       key += std::string{"s:"} + id.get<std::string>();
        else if (id.is_number_integer()) key += std::string{"i:"} + std::to_string(id.get<long long>());
        else if (id.is_number_unsigned()) key += std::string{"u:"} + std::to_string(id.get<unsigned long long>());
        else if (id.is_number_float()) key += std::string{"f:"} + std::to_string(id.get<double>());
        else                            key += std::string{"j:"} + id.dump();
        return key;
    }

    void register_in_flight_call_token(const json& id, const cancel_token_ptr_t& token)
    {
        if (!token)
            return;
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        auto& tokens = g_in_flight_cancels[cancel_key_for_id(id)];
        tokens.erase(std::remove_if(tokens.begin(), tokens.end(), [](const cancel_token_ptr_t& item) {
            return !item;
        }), tokens.end());
        tokens.push_back(token);
    }

    cancel_token_ptr_t register_in_flight_call(const json& id)
    {
        auto token = make_call_cancel_token(false);
        register_in_flight_call_token(id, token);
        return token;
    }

    void unregister_in_flight_call_token(const json& id, const cancel_token_ptr_t& token)
    {
        if (!token)
            return;
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        auto it = g_in_flight_cancels.find(cancel_key_for_id(id));
        if (it == g_in_flight_cancels.end())
            return;
        auto& tokens = it->second;
        tokens.erase(std::remove_if(tokens.begin(), tokens.end(), [&token](const cancel_token_ptr_t& item) {
            return !item || item == token;
        }), tokens.end());
        if (tokens.empty())
            g_in_flight_cancels.erase(it);
    }

    bool signal_in_flight_cancel(const json& id)
    {
        std::vector<cancel_token_ptr_t> tokens;
        {
            std::lock_guard<std::mutex> lk(g_in_flight_mutex);
            auto it = g_in_flight_cancels.find(cancel_key_for_id(id));
            if (it == g_in_flight_cancels.end()) return false;
            tokens = it->second;
        }
        bool signalled = false;
        for (const auto& token : tokens) {
            if (!token)
                continue;
            signal_call_cancel_token(token);
            signalled = true;
        }
        if (mcp_lease_registry_signal_cancel_by_request_id_string(request_id_string(id), "jsonrpc_cancel") != 0)
            signalled = true;
        if (signal_batch_reservation_cancels(id))
            signalled = true;
        return signalled;
    }

    void signal_all_in_flight_cancels() noexcept
    {
        std::vector<cancel_token_ptr_t> tokens;
        try {
            std::lock_guard<std::mutex> lk(g_in_flight_mutex);
            for (const auto& entry : g_in_flight_cancels)
                tokens.insert(tokens.end(), entry.second.begin(), entry.second.end());
            g_in_flight_cancels.clear();
        } catch (...) {
            return;
        }
        for (const auto& token : tokens)
            signal_call_cancel_token(token);
    }

    struct cancel_scope_t
    {
        json               id;
        cancel_token_ptr_t token;
        scoped_call_cancel_t scoped;

        cancel_scope_t(const json& request_id)
            : id(request_id)
            , token(register_in_flight_call(id))
            , scoped(token)
        {
        }

        cancel_scope_t(const cancel_scope_t&) = delete;
        cancel_scope_t& operator=(const cancel_scope_t&) = delete;

        ~cancel_scope_t()
        {
            unregister_in_flight_call_token(id, token);
        }
    };

    struct registered_call_scope_t
    {
        json id;
        cancel_token_ptr_t token;
        bool active = false;

        explicit registered_call_scope_t(const json& request_id)
            : id(request_id)
            , token(register_in_flight_call(id))
            , active(true)
        {
        }

        registered_call_scope_t(const registered_call_scope_t&) = delete;
        registered_call_scope_t& operator=(const registered_call_scope_t&) = delete;

        ~registered_call_scope_t()
        {
            release();
        }

        void cancel() const noexcept
        {
            signal_call_cancel_token(token);
        }

        void release() noexcept
        {
            if (!active)
                return;
            unregister_in_flight_call_token(id, token);
            active = false;
        }
    };

    struct mcp_batch_reservation_counts_t
    {
        std::size_t queued = 0;
        std::size_t active = 0;
    };

    enum class mcp_batch_reservation_state_t : unsigned char
    {
        pending = 0,
        queued = 1,
        active = 2,
        released = 3
    };

    std::mutex g_mcp_batch_reservation_mtx;
    std::map<std::string, mcp_batch_reservation_counts_t> g_mcp_batch_reservations_by_principal;
    std::atomic<std::uint64_t> g_mcp_batch_reservation_seq{0};
    std::atomic<std::uint64_t> g_mcp_batch_children_rejected{0};
    std::atomic<std::uint64_t> g_mcp_batch_children_reserved{0};

    static std::string mcp_batch_reservation_principal_key(const std::string& principal)
    {
        if (principal.empty() || principal == "<none>")
            return "external_mcp";
        return capacity_diag::clean_label(principal, 160);
    }

    class mcp_batch_child_reservation_t : public std::enable_shared_from_this<mcp_batch_child_reservation_t>
    {
    public:
        mcp_batch_child_reservation_t(std::string principal,
                                      std::size_t active_limit,
                                      std::size_t queued_limit)
            : id_(g_mcp_batch_reservation_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u)
            , principal_(mcp_batch_reservation_principal_key(principal))
            , active_limit_(active_limit)
            , queued_limit_(queued_limit)
            , cancel_token_(make_call_cancel_token(false))
        {
        }

        ~mcp_batch_child_reservation_t()
        {
            cancel();
            release("destruct");
            if (batch_cancel_registered_.load(std::memory_order_acquire))
                unregister_batch_reservation_cancel(request_id_, id_);
            unregister_request_token();
        }

        mcp_batch_child_reservation_t(const mcp_batch_child_reservation_t&) = delete;
        mcp_batch_child_reservation_t& operator=(const mcp_batch_child_reservation_t&) = delete;

        void bind_child(const json& request_id, bool has_request_id)
        {
            request_id_ = request_id;
            if (has_request_id && cancel_token_) {
                try {
                    register_in_flight_call_token(request_id_, cancel_token_);
                    cancel_registered_.store(true, std::memory_order_release);
                    register_batch_reservation_cancel(request_id_, shared_from_this());
                    batch_cancel_registered_.store(true, std::memory_order_release);
                } catch (...) {
                }
            }
        }

        void mark_queued_locked()
        {
            state_ = mcp_batch_reservation_state_t::queued;
        }

        bool try_start(std::string& reason)
        {
            std::lock_guard<std::mutex> lk(g_mcp_batch_reservation_mtx);
            if (state_ != mcp_batch_reservation_state_t::queued) {
                reason = "reservation_not_queued";
                return false;
            }
            if (cancelled_locked()) {
                release_locked();
                reason = "cancelled_before_dispatch";
                return false;
            }
            auto it = g_mcp_batch_reservations_by_principal.find(principal_);
            if (it == g_mcp_batch_reservations_by_principal.end()) {
                state_ = mcp_batch_reservation_state_t::released;
                reason = "reservation_counter_missing";
                return false;
            }
            if (it->second.active >= active_limit_) {
                release_locked(it);
                reason = "active_batch_children_per_principal";
                return false;
            }
            if (it->second.queued != 0)
                --it->second.queued;
            ++it->second.active;
            state_ = mcp_batch_reservation_state_t::active;
            ever_started_.store(true, std::memory_order_release);
            return true;
        }

        void cancel() noexcept
        {
            signal_call_cancel_token(cancel_token_);
        }

        void release(const char*) noexcept
        {
            try {
                std::lock_guard<std::mutex> lk(g_mcp_batch_reservation_mtx);
                release_locked();
            } catch (...) {
            }
        }

        bool cancelled() const noexcept
        {
            return cancel_token_ && cancel_token_->load(std::memory_order_acquire);
        }

        bool started() const noexcept
        {
            return ever_started_.load(std::memory_order_acquire);
        }

        cancel_token_ptr_t cancel_token() const noexcept
        {
            return cancel_token_;
        }

        std::uint64_t id() const noexcept
        {
            return id_;
        }

        std::size_t active_limit() const noexcept
        {
            return active_limit_;
        }

        std::size_t queued_limit() const noexcept
        {
            return queued_limit_;
        }

    private:
        bool cancelled_locked() const noexcept
        {
            return cancel_token_ && cancel_token_->load(std::memory_order_acquire);
        }

        void unregister_request_token() noexcept
        {
            if (!cancel_registered_.exchange(false, std::memory_order_acq_rel))
                return;
            try {
                unregister_in_flight_call_token(request_id_, cancel_token_);
            } catch (...) {
            }
        }

        void release_locked()
        {
            auto it = g_mcp_batch_reservations_by_principal.find(principal_);
            release_locked(it);
        }

        void release_locked(std::map<std::string, mcp_batch_reservation_counts_t>::iterator it)
        {
            if (state_ == mcp_batch_reservation_state_t::released ||
                state_ == mcp_batch_reservation_state_t::pending) {
                state_ = mcp_batch_reservation_state_t::released;
                return;
            }
            if (it != g_mcp_batch_reservations_by_principal.end()) {
                if (state_ == mcp_batch_reservation_state_t::queued) {
                    if (it->second.queued != 0)
                        --it->second.queued;
                } else if (state_ == mcp_batch_reservation_state_t::active) {
                    if (it->second.active != 0)
                        --it->second.active;
                }
                if (it->second.queued == 0 && it->second.active == 0)
                    g_mcp_batch_reservations_by_principal.erase(it);
            }
            state_ = mcp_batch_reservation_state_t::released;
        }

        const std::uint64_t id_;
        const std::string principal_;
        const std::size_t active_limit_;
        const std::size_t queued_limit_;
        cancel_token_ptr_t cancel_token_;
        json request_id_;
        std::atomic<bool> cancel_registered_{false};
        std::atomic<bool> batch_cancel_registered_{false};
        std::atomic<bool> ever_started_{false};
        mcp_batch_reservation_state_t state_ = mcp_batch_reservation_state_t::pending;
    };

    struct mcp_batch_cancel_entry_t
    {
        std::uint64_t reservation_id = 0;
        std::weak_ptr<mcp_batch_child_reservation_t> reservation;
    };

    std::mutex g_mcp_batch_cancel_mtx;
    std::map<std::string, std::vector<mcp_batch_cancel_entry_t>> g_mcp_batch_cancel_reservations;

    static void register_batch_reservation_cancel(const json& id, const std::shared_ptr<mcp_batch_child_reservation_t>& reservation) noexcept
    {
        if (!reservation)
            return;
        try {
            std::lock_guard<std::mutex> lk(g_mcp_batch_cancel_mtx);
            auto& entries = g_mcp_batch_cancel_reservations[cancel_key_for_id(id)];
            const std::uint64_t reservation_id = reservation->id();
            entries.erase(std::remove_if(entries.begin(), entries.end(), [reservation_id](const mcp_batch_cancel_entry_t& entry) {
                return entry.reservation.expired() || entry.reservation_id == reservation_id;
            }), entries.end());
            entries.push_back(mcp_batch_cancel_entry_t{reservation_id, reservation});
        } catch (...) {
        }
    }

    static void unregister_batch_reservation_cancel(const json& id, std::uint64_t reservation_id) noexcept
    {
        if (reservation_id == 0)
            return;
        try {
            std::lock_guard<std::mutex> lk(g_mcp_batch_cancel_mtx);
            auto it = g_mcp_batch_cancel_reservations.find(cancel_key_for_id(id));
            if (it == g_mcp_batch_cancel_reservations.end())
                return;
            auto& entries = it->second;
            entries.erase(std::remove_if(entries.begin(), entries.end(), [reservation_id](const mcp_batch_cancel_entry_t& entry) {
                return entry.reservation.expired() || entry.reservation_id == reservation_id;
            }), entries.end());
            if (entries.empty())
                g_mcp_batch_cancel_reservations.erase(it);
        } catch (...) {
        }
    }

    static bool signal_batch_reservation_cancels(const json& id) noexcept
    {
        std::vector<std::shared_ptr<mcp_batch_child_reservation_t>> reservations;
        try {
            std::lock_guard<std::mutex> lk(g_mcp_batch_cancel_mtx);
            auto it = g_mcp_batch_cancel_reservations.find(cancel_key_for_id(id));
            if (it == g_mcp_batch_cancel_reservations.end())
                return false;
            auto& entries = it->second;
            for (auto entry_it = entries.begin(); entry_it != entries.end(); ) {
                if (auto reservation = entry_it->reservation.lock()) {
                    reservations.push_back(std::move(reservation));
                    ++entry_it;
                } else {
                    entry_it = entries.erase(entry_it);
                }
            }
            if (entries.empty())
                g_mcp_batch_cancel_reservations.erase(it);
        } catch (...) {
            return false;
        }
        bool signalled = false;
        for (const auto& reservation : reservations) {
            if (!reservation)
                continue;
            reservation->cancel();
            reservation->release("client_cancelled");
            signalled = true;
        }
        return signalled;
    }

    struct scoped_mcp_batch_reservation_release_t
    {
        std::shared_ptr<mcp_batch_child_reservation_t> reservation;
        const char* reason = "scope_exit";

        ~scoped_mcp_batch_reservation_release_t()
        {
            if (reservation)
                reservation->release(reason);
        }
    };

    struct mcp_batch_child_admission_context_t
    {
        bool active = false;
        std::uint64_t batch_id = 0;
        std::size_t batch_index = 0;
        std::size_t batch_size = 0;
        std::uint64_t reservation_id = 0;
        std::size_t active_limit = 0;
        std::size_t queued_limit = 0;
        cancel_token_ptr_t cancel_token;
    };

    thread_local mcp_batch_child_admission_context_t tls_mcp_batch_child_admission;

    static mcp_batch_child_admission_context_t current_mcp_batch_child_admission_context()
    {
        return tls_mcp_batch_child_admission;
    }

    class scoped_mcp_batch_child_admission_t
    {
    public:
        scoped_mcp_batch_child_admission_t(std::uint64_t batch_id,
                                           std::size_t batch_index,
                                           std::size_t batch_size,
                                           const std::shared_ptr<mcp_batch_child_reservation_t>& reservation)
            : previous_(tls_mcp_batch_child_admission)
        {
            tls_mcp_batch_child_admission.active = reservation != nullptr;
            tls_mcp_batch_child_admission.batch_id = batch_id;
            tls_mcp_batch_child_admission.batch_index = batch_index;
            tls_mcp_batch_child_admission.batch_size = batch_size;
            tls_mcp_batch_child_admission.reservation_id = reservation ? reservation->id() : 0;
            tls_mcp_batch_child_admission.active_limit = reservation ? reservation->active_limit() : 0;
            tls_mcp_batch_child_admission.queued_limit = reservation ? reservation->queued_limit() : 0;
            tls_mcp_batch_child_admission.cancel_token = reservation ? reservation->cancel_token() : cancel_token_ptr_t{};
        }

        ~scoped_mcp_batch_child_admission_t()
        {
            tls_mcp_batch_child_admission = std::move(previous_);
        }

        scoped_mcp_batch_child_admission_t(const scoped_mcp_batch_child_admission_t&) = delete;
        scoped_mcp_batch_child_admission_t& operator=(const scoped_mcp_batch_child_admission_t&) = delete;

    private:
        mcp_batch_child_admission_context_t previous_;
    };

    struct mcp_batch_reservation_snapshot_t
    {
        std::size_t queued = 0;
        std::size_t active = 0;
        bool lock_busy = false;
    };

    struct mcp_batch_reservation_result_t
    {
        std::vector<std::shared_ptr<mcp_batch_child_reservation_t>> reservations;
        std::string principal;
        std::string reason = "within_batch_quota";
        std::size_t requested = 0;
        std::size_t admitted = 0;
        std::size_t rejected = 0;
        std::size_t observed_queued = 0;
        std::size_t observed_active = 0;
        std::size_t queued_limit = 0;
        std::size_t active_limit = 0;
    };

    static mcp_batch_reservation_snapshot_t mcp_batch_reservation_snapshot_for_principal(const std::string& principal)
    {
        mcp_batch_reservation_snapshot_t out;
        std::unique_lock<std::mutex> lk(g_mcp_batch_reservation_mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            out.lock_busy = true;
            return out;
        }
        const std::string key = mcp_batch_reservation_principal_key(principal);
        auto it = g_mcp_batch_reservations_by_principal.find(key);
        if (it != g_mcp_batch_reservations_by_principal.end()) {
            out.queued = it->second.queued;
            out.active = it->second.active;
        }
        return out;
    }

    static mcp_batch_reservation_result_t reserve_mcp_batch_children(const std::string& principal,
                                                                     std::size_t requested)
    {
        mcp_batch_reservation_result_t result;
        const auto& cfg = mcp_concurrency_config();
        const auto quotas = capacity_diag::make_quota_set(cfg.tool_worker_threads);
        result.principal = mcp_batch_reservation_principal_key(principal);
        result.requested = requested;
        result.queued_limit = (std::min)(quotas.queued_batch_children_per_principal, cfg.batch_max_queued_requests);
        result.active_limit = quotas.active_batch_children_per_principal;
        const std::size_t candidate_count = (std::min)(requested, result.queued_limit);
        std::vector<std::shared_ptr<mcp_batch_child_reservation_t>> candidates;
        candidates.reserve(candidate_count);
        for (std::size_t i = 0; i < candidate_count; ++i)
            candidates.push_back(std::make_shared<mcp_batch_child_reservation_t>(result.principal, result.active_limit, result.queued_limit));

        {
            std::lock_guard<std::mutex> lk(g_mcp_batch_reservation_mtx);
            auto& counts = g_mcp_batch_reservations_by_principal[result.principal];
            result.observed_queued = counts.queued;
            result.observed_active = counts.active;
            const std::size_t in_use = counts.queued + counts.active;
            const std::size_t available = result.queued_limit > in_use ? result.queued_limit - in_use : 0;
            result.admitted = (std::min)(candidate_count, available);
            if (result.admitted != 0) {
                counts.queued += result.admitted;
                for (std::size_t i = 0; i < result.admitted; ++i)
                    candidates[i]->mark_queued_locked();
            }
            if (counts.queued == 0 && counts.active == 0)
                g_mcp_batch_reservations_by_principal.erase(result.principal);
        }

        candidates.resize(result.admitted);
        result.rejected = requested - result.admitted;
        if (result.admitted != 0)
            g_mcp_batch_children_reserved.fetch_add(result.admitted, std::memory_order_acq_rel);
        if (result.rejected != 0)
            g_mcp_batch_children_rejected.fetch_add(result.rejected, std::memory_order_acq_rel);
        if (result.rejected != 0)
            result.reason = result.admitted == 0 ? "queued_batch_children_per_principal" : "partial_batch_child_reservation";
        result.reservations = std::move(candidates);
        return result;
    }

}

struct server_t::shared_state_t
{
    tool_registry_t registry;
    std::atomic<bool> server_done{true};
    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};
    void* active_server = nullptr;
    std::mutex server_mtx;
    std::atomic<std::uint32_t> server_worker_tid{0};
    std::mutex local_capability_mtx;
    std::string local_capability;
    std::string local_run_binding;
    std::atomic<int> port{0};
};

server_t::server_t()
    : server_t(std::make_shared<shared_state_t>(), true)
{
}

server_t::server_t(std::shared_ptr<shared_state_t> state, bool owns_lifecycle)
    : _state(std::move(state))
    , _owns_lifecycle(owns_lifecycle)
    , _registry(_state->registry)
    , _server_done(_state->server_done)
    , _running(_state->running)
    , _stop_requested(_state->stop_requested)
    , _active_server(_state->active_server)
    , _server_mtx(_state->server_mtx)
    , _server_worker_tid(_state->server_worker_tid)
    , _local_capability_mtx(_state->local_capability_mtx)
    , _local_capability(_state->local_capability)
    , _local_run_binding(_state->local_run_binding)
    , _port(_state->port)
{
}

server_t::~server_t()
{
    if (!_owns_lifecycle)
        return;
    stop();
}

void register_c03_compatibility_tools(server_t& server)
{
    set_pre_dispatch_validation_hook(c03_compatibility_validation_hook());
    register_c03_compatibility_tools(
        server.registry(), make_application_c03_compatibility_runtime_config());
}

bool server_t::rotate_local_capability() noexcept
{
    try {
        std::string capability = generate_secure_token("", 32);
        std::string run_binding = generate_secure_token("run-", 32);
        if (capability.size() != 64U || run_binding.size() != 68U) {
            if (!capability.empty())
                RtlSecureZeroMemory(capability.data(), capability.size());
            if (!run_binding.empty())
                RtlSecureZeroMemory(run_binding.data(), run_binding.size());
            return false;
        }
        std::lock_guard<std::mutex> lock(_local_capability_mtx);
        if (!_local_capability.empty())
            RtlSecureZeroMemory(_local_capability.data(), _local_capability.size());
        if (!_local_run_binding.empty())
            RtlSecureZeroMemory(_local_run_binding.data(), _local_run_binding.size());
        _local_capability = std::move(capability);
        _local_run_binding = std::move(run_binding);
        return true;
    } catch (...) {
        return false;
    }
}

void server_t::clear_local_capability() noexcept
{
    std::lock_guard<std::mutex> lock(_local_capability_mtx);
    if (!_local_capability.empty())
        RtlSecureZeroMemory(_local_capability.data(), _local_capability.size());
    if (!_local_run_binding.empty())
        RtlSecureZeroMemory(_local_run_binding.data(), _local_run_binding.size());
    _local_capability.clear();
    _local_run_binding.clear();
}

bool server_t::snapshot_local_capability(std::string& capability,
                                         std::string& run_binding) const
{
    std::lock_guard<std::mutex> lock(_local_capability_mtx);
    if (_local_capability.size() != 64U || _local_run_binding.size() != 68U)
        return false;
    capability = _local_capability;
    run_binding = _local_run_binding;
    return true;
}

static bool is_camoufox_reverse_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect", "browser_state",
        "browser_network", "browser_hooks", "browser_instrumentation",
        "browser_service_worker", "browser_fingerprint_spoof",
        "get_console_logs", "scripts", "search_code", "compare_env", "check_environment",
        "verify_signer_offline", "analyze_cookie_sources"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_camoufox_browser_tool_name(const std::string& name)
{
    return is_camoufox_reverse_tool_name(name);
}

static bool is_standalone_internal_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "apply_diff", "apply_patch", "codebase_search", "read_command_output",
        "search_workspace", "run_command", "cancel_command", "list_commands"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_standalone_ide_chat_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "switch_agent", "plan_enter", "plan_exit", "list_agents", "ask_followup_question",
        "attempt_completion", "update_todo_list", "save_checkpoint", "restore_checkpoint",
        "list_checkpoints", "checkpoint_list", "skill", "run_slash_command", "get_context",
        "workflow_status", "task"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_external_mcp_tool(const tool_def_t& tool)
{
    return tool.visibility == tool_visibility_t::external_visible &&
           !is_standalone_ide_chat_only_tool_name(tool.name) &&
           !is_standalone_internal_only_tool_name(tool.name);
}

static bool is_driver_bridge_dependent_tool(const tool_def_t& tool)
{
    const std::string name = lower_ascii(tool.name);
    if (name.rfind("driver_", 0) != 0)
        return false;
    const std::string desc = lower_ascii(tool.description);
    if (desc.find("does not require the kernel driver") != std::string::npos ||
        desc.find("purely from usermode") != std::string::npos)
        return false;
    static const char* const driver_needles[] = {
        "requires driver connected",
        "requires kernel driver",
        "requires driver",
        "via kernel driver",
        "using kernel memory",
        "kernel memory reads",
        "kernel-level",
        "dtb solved",
        "kernel driver backend"
    };
    for (const char* needle : driver_needles) {
        if (desc.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

static std::string capacity_session_identity_from_args(const json& args)
{
    if (!args.is_object())
        return current_mcp_session_hash();
    for (const char* key : {"binary_id", "session_id"}) {
        if (args.contains(key) && args[key].is_string()) {
            const std::string value = args[key].get<std::string>();
            if (!value.empty())
                return std::string(key) + ":" + fnv1a64_hex(value);
        }
    }
    if (args.contains("file_path") && args["file_path"].is_string()) {
        const std::string value = args["file_path"].get<std::string>();
        if (!value.empty())
            return "file:" + fnv1a64_hex(value);
    }
    const char* current = current_mcp_session_hash();
    return current && std::strcmp(current, "<none>") != 0 ? std::string(current) : std::string("active_session");
}

static std::string capacity_target_identity_from_args(const json& args, std::uint32_t target_pid)
{
    if (target_pid != 0)
        return "pid:" + std::to_string(target_pid);
    if (args.is_object()) {
        for (const char* key : {"binary_id", "session_id"}) {
            if (args.contains(key) && args[key].is_string()) {
                const std::string value = args[key].get<std::string>();
                if (!value.empty())
                    return std::string(key) + ":" + fnv1a64_hex(value);
            }
        }
        if (args.contains("file_path") && args["file_path"].is_string()) {
            const std::string value = args["file_path"].get<std::string>();
            if (!value.empty())
                return "file:" + fnv1a64_hex(value);
        }
    }
    return "target_unknown";
}

static bool capacity_background_command_hint(const std::string& tool_name, const json& args)
{
    if (tool_name != "run_command")
        return false;
    if (!args.is_object())
        return false;
    if (args.contains("wait") && args["wait"].is_boolean() && !args["wait"].get<bool>())
        return true;
    return args.contains("session_id") && args["session_id"].is_string() && !args["session_id"].get<std::string>().empty();
}

static bool capacity_driver_debugger_hint(const tool_def_t& tool, const std::string& domain)
{
    if (is_driver_bridge_dependent_tool(tool))
        return true;
    const std::string name = lower_ascii(tool.name);
    return domain == "dbg" || domain == "debugger" || domain == "driver" ||
           name.rfind("dbg_", 0) == 0 ||
           name.rfind("debugger_", 0) == 0 ||
           name.find("debugger") != std::string::npos;
}

static bool capacity_long_running_hint(const std::string& tool_name,
                                       const std::string& domain,
                                       std::uint64_t timeout_ms,
                                       bool driver_debugger,
                                       bool background_command)
{
    if (timeout_ms >= kMcpCapacityLongRunningMs)
        return true;
    if (driver_debugger || background_command || is_camoufox_browser_tool_name(tool_name))
        return true;
    return domain == "browser" || domain == "scanner" || domain == "decompiler" || domain == "pdb" || domain == "network";
}

static bool is_analysis_session_management_tool(const std::string& name);

static void populate_executor_tool_capacity_meta(const std::shared_ptr<mcp_executor_task_meta_t>& meta,
                                                 const tool_def_t& tool,
                                                 const json& args,
                                                 const std::string& domain,
                                                 const std::string& lane,
                                                 std::uint64_t timeout_ms,
                                                 std::uint64_t deadline_ms,
                                                 const std::string& action,
                                                 std::uint32_t target_pid,
                                                 std::uint64_t batch_id,
                                                 std::size_t batch_index,
                                                 std::size_t batch_size,
                                                 const cancel_token_ptr_t& cancel_token)
{
    if (!meta)
        return;
    const bool background_command = capacity_background_command_hint(tool.name, args);
    const bool driver_debugger = capacity_driver_debugger_hint(tool, domain);
    const bool long_running = capacity_long_running_hint(tool.name, domain, timeout_ms, driver_debugger, background_command);
    std::lock_guard<std::mutex> lk(meta->mtx);
    meta->tool = tool.name;
    meta->domain = domain;
    meta->lane = lane;
    meta->principal_id = current_mcp_principal();
    meta->session_hash = capacity_session_identity_from_args(args);
    meta->transport = current_mcp_transport();
    meta->action = action;
    meta->target_pid = target_pid;
    meta->target_id = capacity_target_identity_from_args(args, target_pid);
    meta->deadline_ms = deadline_ms;
    meta->external_tool = is_external_mcp_tool(tool);
    meta->read_only = tool.read_only;
    meta->mutating = !tool.read_only || is_analysis_session_management_tool(tool.name);
    meta->long_running = long_running;
    meta->background_command = background_command;
    meta->driver_debugger = driver_debugger;
    meta->batch_id = batch_id;
    meta->batch_index = batch_index;
    meta->batch_size = batch_size;
    meta->cancel_token = cancel_token;
    if (meta->payload_shape.empty())
        meta->payload_shape = payload_shape_summary(args);
}

class active_session_lease_lock_t
{
public:
    active_session_lease_lock_t() = default;

    bool try_acquire_exclusive(std::uint64_t token)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (exclusive_owner_token_ == 0 && shared_count_ == 0)
        {
            exclusive_owner_token_ = token;
            return true;
        }
        return false;
    }

    bool try_acquire_shared(std::uint64_t token)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (exclusive_owner_token_ == 0)
        {
            shared_owners_.push_back({token});
            ++shared_count_;
            return true;
        }
        return false;
    }

    void release_exclusive(std::uint64_t token)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (exclusive_owner_token_ == token)
        {
            exclusive_owner_token_ = 0;
        }
    }

    void release_shared(std::uint64_t token)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = std::find_if(shared_owners_.begin(), shared_owners_.end(),
            [token](const shared_owner_entry_t& e) { return e.token == token; });
        if (it != shared_owners_.end())
        {
            shared_owners_.erase(it);
            --shared_count_;
        }
    }

private:
    struct shared_owner_entry_t
    {
        std::uint64_t token = 0;
    };

    mutable std::mutex mtx_;
    std::uint64_t exclusive_owner_token_ = 0;
    std::vector<shared_owner_entry_t> shared_owners_;
    std::size_t shared_count_ = 0;
};

static active_session_lease_lock_t& active_session_lease_lock()
{
    static active_session_lease_lock_t lock;
    return lock;
}

static std::string sanitize_owner_field(const std::string& value, std::size_t max_len = 160)
{
    std::string clean = sanitize_utf8(value);
    std::string out;
    out.reserve(std::min(clean.size(), max_len));
    for (char ch : clean) {
        unsigned char c = static_cast<unsigned char>(ch);
        out.push_back((c < 0x20 || c == 0x7f) ? '_' : ch);
        if (out.size() >= max_len)
            break;
    }
    return out;
}

static std::string hex32_string(DWORD code)
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(code));
    return buf;
}

struct mcp_lease_registry_record_t
{
    std::uint64_t lease_token = 0;
    std::uint64_t registry_generation = 0;
    std::uint64_t operation_generation = 0;
    std::string diagnostic_id;
    std::string request_id;
    std::string tool;
    std::string route;
    std::string transport;
    std::string principal_bucket;
    std::string principal_id;
    std::string session_id;
    std::string session_hash;
    std::string target_id;
    std::uint32_t target_pid = 0;
    std::string lane;
    std::string priority;
    bool read_only = true;
    bool mutating = false;
    bool session_manager = false;
    bool domain_mutating = false;
    std::string domain;
    std::string phase;
    DWORD process_pid = 0;
    DWORD worker_tid = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t cancellation_signalled_ms = 0;
    std::uint64_t stale_marked_ms = 0;
    std::uint64_t fenced_ms = 0;
    std::uint64_t tombstoned_ms = 0;
    std::uint64_t released_ms = 0;
    bool cancellation_signalled = false;
    bool stale = false;
    bool fenced = false;
    bool tombstoned = false;
    bool released = false;
    bool commit_eligible = true;
    std::string external_process_kind;
    std::uint32_t external_process_pid = 0;
    std::string external_process_identity;
    std::string external_process_session;
    std::uint64_t external_process_generation = 0;
    std::string external_expected_executable_path;
    std::uint64_t external_process_creation_time_100ns = 0;
    std::string external_sidecar_ownership_marker;
    bool external_force_cleanup_eligible = false;
    std::atomic<bool>* cancel_token = nullptr;
};

struct mcp_lease_registry_acquire_t
{
    std::uint64_t lease_token = 0;
    std::string diagnostic_id;
    std::string request_id;
    std::string tool;
    std::string lane;
    std::string domain;
    std::string priority;
    std::string phase;
    std::string session_id;
    std::string target_id;
    std::uint32_t target_pid = 0;
    bool read_only = true;
    bool mutating = false;
    bool session_manager = false;
    bool domain_mutating = false;
    std::uint64_t deadline_ms = 0;
    std::atomic<bool>* cancel_token = nullptr;
    std::string external_process_kind;
    std::uint32_t external_process_pid = 0;
    std::string external_process_identity;
    std::string external_process_session;
    std::uint64_t external_process_generation = 0;
    std::string external_expected_executable_path;
    std::uint64_t external_process_creation_time_100ns = 0;
    std::string external_sidecar_ownership_marker;
    bool external_force_cleanup_eligible = false;
};

struct mcp_lease_registry_snapshot_t
{
    bool present = false;
    bool lock_busy = false;
    std::uint64_t lease_token = 0;
    std::uint64_t registry_generation = 0;
    std::uint64_t operation_generation = 0;
    std::string diagnostic_id;
    std::string request_id;
    std::string tool;
    std::string route;
    std::string transport;
    std::string principal_bucket;
    std::string session_id;
    std::string session_hash;
    std::string target_id;
    std::uint32_t target_pid = 0;
    std::string lane;
    std::string priority;
    bool read_only = true;
    bool mutating = false;
    bool session_manager = false;
    bool domain_mutating = false;
    std::string domain;
    std::string phase;
    DWORD process_pid = 0;
    DWORD worker_tid = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t owner_age_ms = 0;
    std::uint64_t deadline_ms = 0;
    bool cancellation_signalled = false;
    bool stale = false;
    bool fenced = false;
    bool tombstoned = false;
    bool released = false;
    bool commit_eligible = true;
    std::string external_process_kind;
    std::uint32_t external_process_pid = 0;
    std::string external_process_identity;
    std::string external_process_session;
    std::uint64_t external_process_generation = 0;
    std::string external_expected_executable_path;
    std::uint64_t external_process_creation_time_100ns = 0;
    std::string external_sidecar_ownership_marker;
    bool external_force_cleanup_eligible = false;
};

static std::mutex& mcp_lease_registry_mutex()
{
    static std::mutex m;
    return m;
}

static std::map<std::uint64_t, mcp_lease_registry_record_t>& mcp_lease_registry_active()
{
    static std::map<std::uint64_t, mcp_lease_registry_record_t> records;
    return records;
}

static std::deque<mcp_lease_registry_record_t>& mcp_lease_registry_tombstones()
{
    static std::deque<mcp_lease_registry_record_t> records;
    return records;
}

static std::atomic<std::uint64_t>& mcp_lease_registry_generation_source()
{
    static std::atomic<std::uint64_t> source{0};
    return source;
}

static std::atomic<std::uint64_t>& mcp_lease_operation_generation_source()
{
    static std::atomic<std::uint64_t> source{0};
    return source;
}

bounded_diag_snapshot_t bounded_diagnostic_snapshot() noexcept
{
    bounded_diag_snapshot_t snap;
    snap.active_requests = active_http_request_count();

    try {
        const std::uint64_t now = mcp_now_ms();
        std::unique_lock<std::mutex> lk(mcp_lease_registry_mutex(), std::try_to_lock);
        if (lk.owns_lock()) {
            const auto& active = mcp_lease_registry_active();
            snap.active_leases = active.size();
            std::size_t stale_count = 0;
            std::size_t fenced_count = 0;
            std::size_t tombstoned_active = 0;
            std::size_t cancellation_count = 0;
            const mcp_lease_registry_record_t* oldest = nullptr;
            for (const auto& kv : active) {
                const auto& rec = kv.second;
                if (rec.stale) ++stale_count;
                if (rec.fenced) ++fenced_count;
                if (rec.tombstoned) ++tombstoned_active;
                if (rec.cancellation_signalled) ++cancellation_count;
                if (oldest == nullptr ||
                    (rec.started_ms != 0 && oldest->started_ms != 0 && rec.started_ms < oldest->started_ms))
                    oldest = &rec;
            }
            snap.stale_leases = stale_count;
            snap.fenced_leases = fenced_count;
            snap.tombstoned_active = tombstoned_active;
            snap.pending_cancellations = cancellation_count;
            if (oldest != nullptr) {
                const std::uint64_t age_ms = oldest->started_ms != 0 && now >= oldest->started_ms
                    ? now - oldest->started_ms : 0;
                _snprintf_s(snap.oldest_owner, sizeof(snap.oldest_owner), _TRUNCATE,
                    "tool=%.96s lane=%.48s age_ms=%llu",
                    oldest->tool.empty() ? "<none>" : oldest->tool.c_str(),
                    oldest->lane.empty() ? "<none>" : oldest->lane.c_str(),
                    static_cast<unsigned long long>(age_ms));
            }
            _snprintf_s(snap.lease_registry_snapshot, sizeof(snap.lease_registry_snapshot), _TRUNCATE,
                "lease{active=%zu stale=%zu fenced=%zu tombstoned_active=%zu cancellations=%zu gen=%llu}",
                snap.active_leases,
                stale_count,
                fenced_count,
                tombstoned_active,
                cancellation_count,
                static_cast<unsigned long long>(mcp_lease_registry_generation_source().load(std::memory_order_acquire)));
        } else {
            snap.lease_lock_busy = true;
            _snprintf_s(snap.lease_registry_snapshot, sizeof(snap.lease_registry_snapshot), _TRUNCATE,
                "lease{lock_busy=1}");
        }
    } catch (...) {
        _snprintf_s(snap.lease_registry_snapshot, sizeof(snap.lease_registry_snapshot), _TRUNCATE,
            "lease{snapshot_exception=1}");
    }

    try {
        const auto exec_snap = aida::infra::executor::active_snapshot();
        const auto general = runtime_queue_stats(runtime_queue_family_t::general);
        const auto service = runtime_queue_stats(runtime_queue_family_t::service);
        const auto critical = runtime_queue_stats(runtime_queue_family_t::critical);
        _snprintf_s(snap.capacity_snapshot, sizeof(snap.capacity_snapshot), _TRUNCATE,
            "exec{total_active=%u wq=%u svc=%u crit=%u wq_pending=%llu svc_pending=%llu crit_pending=%llu oldest_ms=%llu labels=%.360s} "
            "runtime{general_alive=%d general_active=%u general_pending=%zu service_alive=%d service_active=%u service_pending=%zu critical_alive=%d critical_active=%u critical_pending=%zu}",
            static_cast<unsigned>(exec_snap.total_active),
            static_cast<unsigned>(exec_snap.work_queue_active),
            static_cast<unsigned>(exec_snap.service_queue_active),
            static_cast<unsigned>(exec_snap.critical_queue_active),
            static_cast<unsigned long long>(exec_snap.work_queue_pending),
            static_cast<unsigned long long>(exec_snap.service_queue_pending),
            static_cast<unsigned long long>(exec_snap.critical_queue_pending),
            static_cast<unsigned long long>(exec_snap.oldest_active_ms),
            exec_snap.labels_under_pressure.empty() ? "<none>" : exec_snap.labels_under_pressure.c_str(),
            general.alive ? 1 : 0, static_cast<unsigned>(general.active), general.pending,
            service.alive ? 1 : 0, static_cast<unsigned>(service.active), service.pending,
            critical.alive ? 1 : 0, static_cast<unsigned>(critical.active), critical.pending);
    } catch (...) {
        _snprintf_s(snap.capacity_snapshot, sizeof(snap.capacity_snapshot), _TRUNCATE,
            "exec{snapshot_exception=1}");
    }

    try {
        const auto ds = mcp_standalone::downstream::governor_t::instance().try_snapshot_bounded();
        snap.camoufox_longop_active = ds.camoufox_longop_active;
        if (ds.lock_busy) {
            _snprintf_s(snap.downstream_snapshot, sizeof(snap.downstream_snapshot), _TRUNCATE,
                "downstream{lock_busy=1}");
        } else {
            _snprintf_s(snap.downstream_snapshot, sizeof(snap.downstream_snapshot), _TRUNCATE,
                "downstream{total_active=%zu total_rejected=%llu camoufox_longop=%zu background_cmd=%zu shutdown=%d}",
                ds.total_active,
                static_cast<unsigned long long>(ds.total_rejected),
                ds.camoufox_longop_active,
                ds.background_command_active,
                ds.shutdown_pending ? 1 : 0);
        }
    } catch (...) {
        _snprintf_s(snap.downstream_snapshot, sizeof(snap.downstream_snapshot), _TRUNCATE,
            "downstream{snapshot_exception=1}");
    }

    return snap;
}

static std::atomic<std::uint64_t>& mcp_lease_late_result_discard_count()
{
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

static std::atomic<std::uint64_t>& mcp_lease_camoufox_cleanup_attempt_count()
{
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

static std::atomic<std::uint64_t>& mcp_lease_camoufox_cleanup_rejected_count()
{
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

static std::atomic<std::uint64_t>& mcp_lease_lock_conflict_count()
{
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}

struct mcp_lease_conflict_counter_map_t
{
    std::mutex mtx;
    std::map<std::string, std::uint64_t> by_lane;
};

static mcp_lease_conflict_counter_map_t& mcp_lease_conflict_counters()
{
    static mcp_lease_conflict_counter_map_t map;
    return map;
}

static void mcp_lease_record_lock_conflict(const std::string& lane)
{
    mcp_lease_lock_conflict_count().fetch_add(1u, std::memory_order_acq_rel);
    if (!lane.empty()) {
        std::lock_guard<std::mutex> lk(mcp_lease_conflict_counters().mtx);
        ++mcp_lease_conflict_counters().by_lane[lane];
    }
}

static json mcp_lease_conflict_counters_json()
{
    json out;
    std::lock_guard<std::mutex> lk(mcp_lease_conflict_counters().mtx);
    for (const auto& kv : mcp_lease_conflict_counters().by_lane)
        out[kv.first] = kv.second;
    return out;
}

static std::string mcp_lease_request_id()
{
    const char* request_id = current_call_request_id();
    if (request_id && request_id[0])
        return sanitize_owner_field(request_id, 160);
    if (tls_route_identity.http_request_id != 0)
        return std::to_string(tls_route_identity.http_request_id);
    const char* diag_id = current_call_diag_id();
    return diag_id && diag_id[0] ? sanitize_owner_field(diag_id, 160) : std::string("request_unknown");
}

static std::string mcp_lease_principal_bucket(const std::string& principal)
{
    return principal.empty() || principal == "<none>" ? std::string("principal_none") : std::string("principal_") + fnv1a64_hex(principal);
}

static std::string mcp_lease_priority_for(const std::string& tool,
                                          const std::string& lane,
                                          const std::string& domain,
                                          bool read_only,
                                          bool mutating,
                                          bool session_manager)
{
    const std::string name = lower_ascii(tool);
    const std::string lane_l = lower_ascii(lane);
    if (session_manager || lane_l.find("session_manager") != std::string::npos || lane_l.find("target_switch") != std::string::npos)
        return "P1";
    if (is_camoufox_browser_tool_name(tool) || domain == "browser" || domain == "scanner" || domain == "decompiler" || domain == "network" || domain == "pdb")
        return "P3";
    if (name == "run_command" || lane_l.find("background") != std::string::npos)
        return "P5";
    if (mutating || !read_only)
        return "P1";
    return "P2";
}

static std::uint32_t mcp_external_process_pid_from_args(const json& args, std::uint32_t fallback)
{
    if (!args.is_object())
        return fallback;
    static const char* const keys[] = {
        "external_pid", "sidecar_pid", "browser_pid", "process_id", "target_pid", "pid"
    };
    for (const char* key : keys) {
        auto it = args.find(key);
        if (it == args.end())
            continue;
        if (it->is_number_unsigned())
            return static_cast<std::uint32_t>(it->get<std::uint64_t>());
        if (it->is_number_integer()) {
            const auto v = it->get<std::int64_t>();
            if (v > 0)
                return static_cast<std::uint32_t>(v);
        }
    }
    return fallback;
}

static std::string mcp_camoufox_browser_session_id_from_args(const json& args)
{
    if (!args.is_object())
        return "default";
    auto read_string = [](const json& object, const char* key) -> std::string {
        auto it = object.find(key);
        return it != object.end() && it->is_string() ? it->get<std::string>() : std::string();
    };
    std::string sid = read_string(args, "session_id");
    if (sid.empty())
        sid = read_string(args, "browser_session_id");
    auto payload = args.find("payload");
    if (sid.empty() && payload != args.end() && payload->is_object())
        sid = read_string(*payload, "session_id");
    auto params = args.find("params");
    if (sid.empty() && params != args.end() && params->is_object())
        sid = read_string(*params, "session_id");
    if (sid.empty())
        sid = "default";
    return sanitize_owner_field(sid, 96);
}

static std::string mcp_sidecar_executable_path_from_command(std::string command)
{
    while (!command.empty() && std::isspace(static_cast<unsigned char>(command.front())))
        command.erase(command.begin());
    while (!command.empty() && std::isspace(static_cast<unsigned char>(command.back())))
        command.pop_back();
    if (command.empty())
        return {};
    if (command.front() == '"' || command.front() == '\'') {
        const char quote = command.front();
        const std::size_t end = command.find(quote, 1);
        if (end != std::string::npos && end > 1)
            return command.substr(1, end - 1);
    }
    const std::string lower = lower_ascii(command);
    const std::size_t exe = lower.find(".exe");
    if (exe != std::string::npos)
        return command.substr(0, exe + 4);
    const std::size_t space = command.find_first_of(" \t\r\n");
    return space == std::string::npos ? command : command.substr(0, space);
}

static void mcp_populate_camoufox_external_sidecar(const std::string& tool_name,
                                                   const json& args,
                                                   mcp_lease_registry_acquire_t& req)
{
    if (!is_camoufox_browser_tool_name(tool_name))
        return;
    const std::string bridge_session_id = mcp_camoufox_browser_session_id_from_args(args);
    const aida::burp::camoufox::bridge_status_t status = aida::burp::camoufox::get_status(bridge_session_id);
    const std::string expected_path = mcp_sidecar_executable_path_from_command(status.server_command);
    req.external_process_kind = "camoufox_reverse_mcp_sidecar";
    req.external_process_pid = status.child_pid;
    req.external_process_session = status.session_id.empty() ? bridge_session_id : sanitize_owner_field(status.session_id, 96);
    req.external_process_generation = status.generation;
    req.external_expected_executable_path = sanitize_owner_field(expected_path, 1024);
    req.external_process_creation_time_100ns = status.child_process_creation_time_100ns;
    req.external_sidecar_ownership_marker = "camoufox_status:" +
        sanitize_owner_field(status.session_id.empty() ? bridge_session_id : status.session_id, 96) +
        ":pid:" + std::to_string(status.child_pid) +
        ":generation:" + std::to_string(status.generation);
    req.external_process_identity = req.external_process_kind +
        ":session:" + req.external_process_session +
        ":pid:" + std::to_string(status.child_pid) +
        ":generation:" + std::to_string(status.generation) +
        ":ctime:" + std::to_string(status.child_process_creation_time_100ns);
    req.external_force_cleanup_eligible =
        status.child_pid != 0 &&
        status.generation != 0 &&
        !expected_path.empty() &&
        status.child_process_creation_time_100ns != 0 &&
        status.child_process_identity_available;
}

static mcp_lease_registry_acquire_t mcp_lease_acquire_request_for_tool(const tool_def_t& tool,
                                                                       const json& args,
                                                                       const std::string& lane,
                                                                       bool read_only,
                                                                       bool session_manager,
                                                                       bool explicit_target,
                                                                       std::uint64_t lease_token,
                                                                       std::uint64_t deadline_ms,
                                                                       std::atomic<bool>* cancel_token)
{
    const std::string domain = infer_tool_domain(tool.name);
    const bool mutating = !read_only || session_manager;
    const std::uint32_t target_pid = target_pid_from_args(args);
    mcp_lease_registry_acquire_t req;
    req.lease_token = lease_token;
    req.diagnostic_id = sanitize_owner_field(current_call_diag_id() ? current_call_diag_id() : "", 160);
    req.request_id = mcp_lease_request_id();
    req.tool = sanitize_owner_field(tool.name, 160);
    req.lane = sanitize_owner_field(lane, 96);
    req.domain = capacity_domain_key(domain);
    req.priority = mcp_lease_priority_for(tool.name, req.lane, req.domain, read_only, mutating, session_manager);
    req.phase = "acquired";
    req.session_id = capacity_session_identity_from_args(args);
    if (req.session_id.empty() || req.session_id == "session_unknown")
        req.session_id = tls_route_identity.session_id.empty() ? std::string("session_unknown") : sanitize_owner_field(tls_route_identity.session_id, 128);
    req.target_id = capacity_target_identity_from_args(args, target_pid);
    if (req.target_id.empty())
        req.target_id = explicit_target ? std::string("target_explicit") : std::string("active_session");
    req.target_pid = target_pid;
    req.read_only = read_only;
    req.mutating = mutating;
    req.session_manager = session_manager;
    req.domain_mutating = mutating && !session_manager;
    req.deadline_ms = deadline_ms;
    req.cancel_token = cancel_token;
    req.external_process_pid = mcp_external_process_pid_from_args(args, target_pid);
    if (req.external_process_pid != 0) {
        req.external_process_kind = is_camoufox_browser_tool_name(tool.name) ? "camoufox_or_target_process" : "target_process";
        req.external_process_identity = req.external_process_kind + ":" + std::to_string(req.external_process_pid);
        req.external_process_session = req.session_id;
        req.external_process_generation = lease_token;
        req.external_force_cleanup_eligible = is_camoufox_browser_tool_name(tool.name);
    }
    mcp_populate_camoufox_external_sidecar(tool.name, args, req);
    return req;
}

static json mcp_lease_record_json(const mcp_lease_registry_record_t& record, std::uint64_t now)
{
    const std::uint64_t age_ms = record.started_ms != 0 && now >= record.started_ms ? now - record.started_ms : 0;
    return {
        {"lease_token", record.lease_token},
        {"registry_generation", record.registry_generation},
        {"operation_generation", record.operation_generation},
        {"diagnostic_id", record.diagnostic_id},
        {"request_id", record.request_id},
        {"tool", record.tool},
        {"route", record.route},
        {"transport", record.transport},
        {"principal_bucket", record.principal_bucket},
        {"session_id", record.session_id},
        {"session_hash", record.session_hash},
        {"target_id", record.target_id},
        {"target_pid", record.target_pid},
        {"lane", record.lane},
        {"priority", record.priority},
        {"read_only", record.read_only},
        {"mutating", record.mutating},
        {"session_manager", record.session_manager},
        {"domain_mutating", record.domain_mutating},
        {"domain", record.domain},
        {"phase", record.phase},
        {"process_pid", record.process_pid},
        {"worker_tid", record.worker_tid},
        {"started_ms", record.started_ms},
        {"age_ms", age_ms},
        {"deadline_ms", record.deadline_ms},
        {"cancellation_signalled", record.cancellation_signalled},
        {"stale", record.stale},
        {"fenced", record.fenced},
        {"tombstoned", record.tombstoned},
        {"released", record.released},
        {"commit_eligible", record.commit_eligible},
        {"external_process_kind", record.external_process_kind},
        {"external_process_pid", record.external_process_pid},
        {"external_process_identity", record.external_process_identity},
        {"external_process_session", record.external_process_session},
        {"external_process_generation", record.external_process_generation},
        {"external_expected_executable_path", record.external_expected_executable_path},
        {"external_process_creation_time_100ns", record.external_process_creation_time_100ns},
        {"external_sidecar_ownership_marker", record.external_sidecar_ownership_marker},
        {"external_force_cleanup_eligible", record.external_force_cleanup_eligible}
    };
}

static void mcp_lease_log_event(const char* event_name,
                                const mcp_lease_registry_record_t& record,
                                const char* reason,
                                bool found,
                                std::uint64_t now)
{
    const std::uint64_t age_ms = record.started_ms != 0 && now >= record.started_ms ? now - record.started_ms : 0;
    diag::log_tagged_fmt("mcp_srv",
        "%s token=%llu registry_generation=%llu operation_generation=%llu reason=%s found=%d diag_id=%s request_id='%s' tool='%s' route=%s transport=%s principal_bucket=%s session_id='%s' session_hash=%s target_id='%s' target_pid=%u lane=%s priority=%s read_only=%d mutating=%d session_manager=%d domain_mutating=%d domain=%s phase=%s worker_tid=%lu start_ms=%llu deadline_ms=%llu age_ms=%llu cancellation_signalled=%d stale=%d fenced=%d tombstoned=%d released=%d commit_eligible=%d external_kind=%s external_pid=%u external_identity=%s external_session=%s external_generation=%llu external_expected_path=%s external_ctime=%llu external_marker=%s force_cleanup_eligible=%d pid=%lu tid=%lu",
        event_name ? event_name : "MCP-LEASE-EVENT",
        static_cast<unsigned long long>(record.lease_token),
        static_cast<unsigned long long>(record.registry_generation),
        static_cast<unsigned long long>(record.operation_generation),
        reason ? reason : "",
        found ? 1 : 0,
        record.diagnostic_id.c_str(),
        record.request_id.c_str(),
        record.tool.c_str(),
        record.route.c_str(),
        record.transport.c_str(),
        record.principal_bucket.c_str(),
        record.session_id.c_str(),
        record.session_hash.c_str(),
        record.target_id.c_str(),
        record.target_pid,
        record.lane.c_str(),
        record.priority.c_str(),
        record.read_only ? 1 : 0,
        record.mutating ? 1 : 0,
        record.session_manager ? 1 : 0,
        record.domain_mutating ? 1 : 0,
        record.domain.c_str(),
        record.phase.c_str(),
        static_cast<unsigned long>(record.worker_tid),
        static_cast<unsigned long long>(record.started_ms),
        static_cast<unsigned long long>(record.deadline_ms),
        static_cast<unsigned long long>(age_ms),
        record.cancellation_signalled ? 1 : 0,
        record.stale ? 1 : 0,
        record.fenced ? 1 : 0,
        record.tombstoned ? 1 : 0,
        record.released ? 1 : 0,
        record.commit_eligible ? 1 : 0,
        record.external_process_kind.c_str(),
        record.external_process_pid,
        record.external_process_identity.c_str(),
        record.external_process_session.c_str(),
        static_cast<unsigned long long>(record.external_process_generation),
        record.external_expected_executable_path.c_str(),
        static_cast<unsigned long long>(record.external_process_creation_time_100ns),
        record.external_sidecar_ownership_marker.c_str(),
        record.external_force_cleanup_eligible ? 1 : 0,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

static void mcp_lease_registry_add_tombstone_locked(mcp_lease_registry_record_t record, const char* reason, std::uint64_t now)
{
    record.tombstoned = true;
    record.tombstoned_ms = now;
    if (record.released_ms == 0)
        record.released_ms = now;
    record.released = true;
    record.commit_eligible = false;
    record.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    auto& tombstones = mcp_lease_registry_tombstones();
    tombstones.push_front(record);
    while (tombstones.size() > 128u)
        tombstones.pop_back();
    mcp_lease_log_event("MCP-LEASE-TOMBSTONE", record, reason, true, now);
}

static mcp_lease_registry_snapshot_t mcp_lease_registry_acquire(const mcp_lease_registry_acquire_t& req)
{
    const std::uint64_t now = mcp_now_ms();
    mcp_lease_registry_record_t record;
    record.lease_token = req.lease_token;
    record.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    record.operation_generation = mcp_lease_operation_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    record.diagnostic_id = sanitize_owner_field(req.diagnostic_id.empty() ? std::string("diag_unknown") : req.diagnostic_id, 160);
    record.request_id = sanitize_owner_field(req.request_id.empty() ? mcp_lease_request_id() : req.request_id, 160);
    record.tool = sanitize_owner_field(req.tool.empty() ? std::string("tool_unknown") : req.tool, 160);
    record.route = sanitize_owner_field(current_mcp_route(), 96);
    record.transport = sanitize_owner_field(current_mcp_transport(), 96);
    record.principal_id = sanitize_owner_field(current_mcp_principal(), 160);
    record.principal_bucket = mcp_lease_principal_bucket(record.principal_id);
    record.session_id = sanitize_owner_field(req.session_id.empty() ? std::string("session_unknown") : req.session_id, 128);
    record.session_hash = sanitize_owner_field(current_mcp_session_hash(), 128);
    record.target_id = sanitize_owner_field(req.target_id.empty() ? std::string("target_unknown") : req.target_id, 128);
    record.target_pid = req.target_pid;
    record.lane = sanitize_owner_field(req.lane.empty() ? std::string("unknown_lane") : req.lane, 96);
    record.priority = sanitize_owner_field(req.priority.empty() ? std::string("P4") : req.priority, 16);
    record.read_only = req.read_only;
    record.mutating = req.mutating;
    record.session_manager = req.session_manager;
    record.domain_mutating = req.domain_mutating;
    record.domain = capacity_domain_key(req.domain);
    record.phase = sanitize_owner_field(req.phase.empty() ? std::string("acquired") : req.phase, 96);
    record.process_pid = GetCurrentProcessId();
    record.worker_tid = GetCurrentThreadId();
    record.started_ms = now;
    record.deadline_ms = req.deadline_ms;
    record.commit_eligible = true;
    record.cancel_token = req.cancel_token;
    record.external_process_kind = sanitize_owner_field(req.external_process_kind, 64);
    record.external_process_pid = req.external_process_pid;
    record.external_process_identity = sanitize_owner_field(req.external_process_identity, 128);
    record.external_process_session = sanitize_owner_field(req.external_process_session, 128);
    record.external_process_generation = req.external_process_generation;
    record.external_expected_executable_path = sanitize_owner_field(req.external_expected_executable_path, 1024);
    record.external_process_creation_time_100ns = req.external_process_creation_time_100ns;
    record.external_sidecar_ownership_marker = sanitize_owner_field(req.external_sidecar_ownership_marker, 160);
    record.external_force_cleanup_eligible = req.external_force_cleanup_eligible;

    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        auto& active = mcp_lease_registry_active();
        auto it = active.find(record.lease_token);
        if (it != active.end()) {
            mcp_lease_registry_add_tombstone_locked(it->second, "token_reused", now);
            active.erase(it);
        }
        active[record.lease_token] = record;
    }

    mcp_lease_log_event("MCP-LEASE-ACQUIRE", record, "acquire", true, now);
    aida::diagnostics::metadata_ring::emit(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::mcp_lease,
        "mcp_lease_acquired", nullptr, false);
    mcp_lease_registry_snapshot_t snap;
    snap.present = true;
    snap.lease_token = record.lease_token;
    snap.registry_generation = record.registry_generation;
    snap.operation_generation = record.operation_generation;
    snap.diagnostic_id = record.diagnostic_id;
    snap.request_id = record.request_id;
    snap.tool = record.tool;
    snap.route = record.route;
    snap.transport = record.transport;
    snap.principal_bucket = record.principal_bucket;
    snap.session_id = record.session_id;
    snap.session_hash = record.session_hash;
    snap.target_id = record.target_id;
    snap.target_pid = record.target_pid;
    snap.lane = record.lane;
    snap.priority = record.priority;
    snap.read_only = record.read_only;
    snap.mutating = record.mutating;
    snap.session_manager = record.session_manager;
    snap.domain_mutating = record.domain_mutating;
    snap.domain = record.domain;
    snap.phase = record.phase;
    snap.process_pid = record.process_pid;
    snap.worker_tid = record.worker_tid;
    snap.started_ms = record.started_ms;
    snap.deadline_ms = record.deadline_ms;
    snap.commit_eligible = record.commit_eligible;
    snap.external_process_kind = record.external_process_kind;
    snap.external_process_pid = record.external_process_pid;
    snap.external_process_identity = record.external_process_identity;
    snap.external_process_session = record.external_process_session;
    snap.external_process_generation = record.external_process_generation;
    snap.external_expected_executable_path = record.external_expected_executable_path;
    snap.external_process_creation_time_100ns = record.external_process_creation_time_100ns;
    snap.external_sidecar_ownership_marker = record.external_sidecar_ownership_marker;
    snap.external_force_cleanup_eligible = record.external_force_cleanup_eligible;
    return snap;
}

static bool mcp_lease_registry_set_phase(std::uint64_t token, std::uint64_t generation, const std::string& phase)
{
    std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
    auto& active = mcp_lease_registry_active();
    auto it = active.find(token);
    if (it == active.end())
        return false;
    if (generation != 0 && it->second.operation_generation != generation)
        return false;
    it->second.phase = sanitize_owner_field(phase, 96);
    it->second.worker_tid = GetCurrentThreadId();
    it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    return true;
}

static bool mcp_lease_registry_commit_eligible(std::uint64_t token, std::uint64_t generation, mcp_lease_registry_snapshot_t* out = nullptr);

static bool mcp_lease_registry_set_phase_checked(std::uint64_t token,
                                                 std::uint64_t generation,
                                                 std::uint64_t expected_registry_generation,
                                                 const std::string& phase,
                                                 mcp_lease_registry_snapshot_t* out)
{
    bool updated = false;
    bool refresh = false;
    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        auto& active = mcp_lease_registry_active();
        auto it = active.find(token);
        if (it == active.end())
            return false;
        if (generation != 0 && it->second.operation_generation != generation)
            return false;
        if (expected_registry_generation != 0 && it->second.registry_generation != expected_registry_generation) {
            refresh = true;
        } else if (!it->second.commit_eligible ||
                   it->second.cancellation_signalled ||
                   it->second.stale ||
                   it->second.fenced ||
                   it->second.tombstoned ||
                   it->second.released) {
            refresh = true;
        } else {
            it->second.phase = sanitize_owner_field(phase, 96);
            it->second.worker_tid = GetCurrentThreadId();
            it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
            updated = true;
        }
    }
    if (updated || refresh)
        (void)mcp_lease_registry_commit_eligible(token, generation, out);
    return updated;
}

static bool mcp_lease_registry_set_lane(std::uint64_t token, std::uint64_t generation, const std::string& lane)
{
    std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
    auto& active = mcp_lease_registry_active();
    auto it = active.find(token);
    if (it == active.end())
        return false;
    if (generation != 0 && it->second.operation_generation != generation)
        return false;
    it->second.lane = sanitize_owner_field(lane, 96);
    it->second.worker_tid = GetCurrentThreadId();
    it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    return true;
}

static bool mcp_lease_registry_commit_eligible(std::uint64_t token, std::uint64_t generation, mcp_lease_registry_snapshot_t* out)
{
    const std::uint64_t now = mcp_now_ms();
    std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
    auto it = mcp_lease_registry_active().find(token);
    if (it == mcp_lease_registry_active().end())
        return false;
    const auto& r = it->second;
    if (generation != 0 && r.operation_generation != generation)
        return false;
    if (out) {
        out->present = true;
        out->lease_token = r.lease_token;
        out->registry_generation = r.registry_generation;
        out->operation_generation = r.operation_generation;
        out->diagnostic_id = r.diagnostic_id;
        out->request_id = r.request_id;
        out->tool = r.tool;
        out->route = r.route;
        out->transport = r.transport;
        out->principal_bucket = r.principal_bucket;
        out->session_id = r.session_id;
        out->session_hash = r.session_hash;
        out->target_id = r.target_id;
        out->target_pid = r.target_pid;
        out->lane = r.lane;
        out->priority = r.priority;
        out->read_only = r.read_only;
        out->mutating = r.mutating;
        out->session_manager = r.session_manager;
        out->domain_mutating = r.domain_mutating;
        out->domain = r.domain;
        out->phase = r.phase;
        out->process_pid = r.process_pid;
        out->worker_tid = r.worker_tid;
        out->started_ms = r.started_ms;
        out->owner_age_ms = r.started_ms != 0 && now >= r.started_ms ? now - r.started_ms : 0;
        out->deadline_ms = r.deadline_ms;
        out->cancellation_signalled = r.cancellation_signalled;
        out->stale = r.stale;
        out->fenced = r.fenced;
        out->tombstoned = r.tombstoned;
        out->released = r.released;
        out->commit_eligible = r.commit_eligible;
        out->external_process_kind = r.external_process_kind;
        out->external_process_pid = r.external_process_pid;
        out->external_process_identity = r.external_process_identity;
        out->external_process_session = r.external_process_session;
        out->external_process_generation = r.external_process_generation;
        out->external_expected_executable_path = r.external_expected_executable_path;
        out->external_process_creation_time_100ns = r.external_process_creation_time_100ns;
        out->external_sidecar_ownership_marker = r.external_sidecar_ownership_marker;
        out->external_force_cleanup_eligible = r.external_force_cleanup_eligible;
    }
    return r.commit_eligible && !r.cancellation_signalled && !r.stale && !r.fenced && !r.tombstoned && !r.released;
}

static bool signal_owner_cancel_token_locked(mcp_lease_registry_record_t& record,
                                             std::uint64_t now,
                                             bool* out_was_cancelled = nullptr,
                                             bool* out_cancel_token_present = nullptr)
{
    const bool was_cancelled = record.cancellation_signalled;
    if (out_was_cancelled)
        *out_was_cancelled = was_cancelled;
    if (out_cancel_token_present)
        *out_cancel_token_present = record.cancel_token != nullptr;
    record.cancellation_signalled = true;
    record.cancellation_signalled_ms = now;
    record.commit_eligible = false;
    record.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
    if (record.cancel_token)
        record.cancel_token->store(true, std::memory_order_release);
    return !was_cancelled;
}

static bool mcp_lease_registry_signal_cancel(std::uint64_t token,
                                             std::uint64_t generation,
                                             const char* reason,
                                             bool* out_was_cancelled = nullptr,
                                             bool* out_cancel_token_present = nullptr)
{
    const std::uint64_t now = mcp_now_ms();
    mcp_lease_registry_record_t record;
    bool found = false;
    bool signalled_now = false;
    if (out_was_cancelled)
        *out_was_cancelled = false;
    if (out_cancel_token_present)
        *out_cancel_token_present = false;
    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        auto& active = mcp_lease_registry_active();
        auto it = active.find(token);
        if (it != active.end() && (generation == 0 || it->second.operation_generation == generation)) {
            found = true;
            signalled_now = signal_owner_cancel_token_locked(it->second, now, out_was_cancelled, out_cancel_token_present);
            record = it->second;
        }
    }
    if (found)
        mcp_lease_log_event("MCP-LEASE-CANCEL-SIGNAL", record, reason, true, now);
    return found && signalled_now;
}

template <typename Predicate>
static std::size_t mcp_lease_registry_for_each_matching(Predicate&& predicate, const char* action, const char* reason)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> matches;
    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        for (const auto& kv : mcp_lease_registry_active()) {
            if (predicate(kv.second))
                matches.push_back({kv.second.lease_token, kv.second.operation_generation});
        }
    }
    for (const auto& item : matches) {
        if (strcmp(action, "cancel") == 0)
            mcp_lease_registry_signal_cancel(item.first, item.second, reason);
        else if (strcmp(action, "stale") == 0) {
            const std::uint64_t now = mcp_now_ms();
            mcp_lease_registry_record_t record;
            bool found = false;
            {
                std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
                auto it = mcp_lease_registry_active().find(item.first);
                if (it != mcp_lease_registry_active().end() && it->second.operation_generation == item.second) {
                    it->second.stale = true;
                    it->second.stale_marked_ms = now;
                    it->second.commit_eligible = false;
                    it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
                    record = it->second;
                    found = true;
                }
            }
            if (found)
                mcp_lease_log_event("MCP-LEASE-STALE", record, reason, true, now);
        } else if (strcmp(action, "fence") == 0) {
            const std::uint64_t now = mcp_now_ms();
            mcp_lease_registry_record_t record;
            bool found = false;
            {
                std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
                auto it = mcp_lease_registry_active().find(item.first);
                if (it != mcp_lease_registry_active().end() && it->second.operation_generation == item.second) {
                    it->second.fenced = true;
                    it->second.fenced_ms = now;
                    it->second.commit_eligible = false;
                    it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
                    record = it->second;
                    found = true;
                }
            }
            if (found)
                mcp_lease_log_event("MCP-LEASE-FENCED", record, reason, true, now);
        }
    }
    return matches.size();
}

static bool mcp_lease_registry_mark_stale(std::uint64_t token, std::uint64_t generation, const char* reason)
{
    return mcp_lease_registry_for_each_matching(
        [token, generation](const mcp_lease_registry_record_t& r) {
            return r.lease_token == token && (generation == 0 || r.operation_generation == generation);
        },
        "stale",
        reason) != 0;
}

static bool mcp_lease_registry_fence(std::uint64_t token, std::uint64_t generation, const char* reason)
{
    return mcp_lease_registry_for_each_matching(
        [token, generation](const mcp_lease_registry_record_t& r) {
            return r.lease_token == token && (generation == 0 || r.operation_generation == generation);
        },
        "fence",
        reason) != 0;
}

static std::size_t mcp_lease_registry_signal_cancel_by_diagnostic(const std::string& diagnostic_id, const char* reason)
{
    const std::string diag_id = sanitize_owner_field(diagnostic_id, 160);
    return mcp_lease_registry_for_each_matching(
        [&diag_id](const mcp_lease_registry_record_t& r) {
            return r.diagnostic_id == diag_id;
        },
        "cancel",
        reason);
}

static std::size_t mcp_lease_registry_signal_cancel_by_request_id_string(const std::string& request_id, const char* reason)
{
    const std::string clean_request_id = sanitize_owner_field(request_id, 160);
    return mcp_lease_registry_for_each_matching(
        [&clean_request_id](const mcp_lease_registry_record_t& r) {
            return r.request_id == clean_request_id;
        },
        "cancel",
        reason);
}

static std::size_t mcp_lease_registry_mark_stale_by_diagnostic(const std::string& diagnostic_id, const char* reason)
{
    const std::string diag_id = sanitize_owner_field(diagnostic_id, 160);
    return mcp_lease_registry_for_each_matching(
        [&diag_id](const mcp_lease_registry_record_t& r) {
            return r.diagnostic_id == diag_id;
        },
        "stale",
        reason);
}

static std::size_t mcp_lease_registry_fence_by_diagnostic(const std::string& diagnostic_id, const char* reason)
{
    const std::string diag_id = sanitize_owner_field(diagnostic_id, 160);
    return mcp_lease_registry_for_each_matching(
        [&diag_id](const mcp_lease_registry_record_t& r) {
            return r.diagnostic_id == diag_id;
        },
        "fence",
        reason);
}

static bool mcp_lease_registry_release(std::uint64_t token, std::uint64_t generation, const char* reason)
{
    const std::uint64_t now = mcp_now_ms();
    mcp_lease_registry_record_t record;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        auto& active = mcp_lease_registry_active();
        auto it = active.find(token);
        if (it != active.end() && (generation == 0 || it->second.operation_generation == generation)) {
            it->second.released = true;
            it->second.released_ms = now;
            it->second.cancel_token = nullptr;
            it->second.commit_eligible = false;
            it->second.registry_generation = mcp_lease_registry_generation_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
            record = it->second;
            active.erase(it);
            mcp_lease_registry_add_tombstone_locked(record, reason, now);
            found = true;
        }
    }
    if (found)
        mcp_lease_log_event("MCP-LEASE-RELEASE", record, reason, true, now);
    return found;
}

static json mcp_lease_registry_bounded_snapshot(std::size_t max_active, std::size_t max_tombstones)
{
    const std::uint64_t now = mcp_now_ms();
    json out;
    out["timestamp_ms"] = now;
    out["phase"] = "phase5_generation_aware_lease_registry";
    out["lock_busy"] = false;
    std::unique_lock<std::mutex> lk(mcp_lease_registry_mutex(), std::try_to_lock);
    if (!lk.owns_lock()) {
        out["lock_busy"] = true;
        return out;
    }
    const auto& active = mcp_lease_registry_active();
    const auto& tombstones = mcp_lease_registry_tombstones();
    out["active_count"] = active.size();
    out["tombstone_count"] = tombstones.size();
    out["registry_generation"] = mcp_lease_registry_generation_source().load(std::memory_order_acquire);
    out["operation_generation"] = mcp_lease_operation_generation_source().load(std::memory_order_acquire);

    std::map<std::string, std::size_t> by_lane;
    std::map<std::string, std::size_t> by_tool;
    std::map<std::string, std::size_t> by_session;
    std::map<std::string, std::size_t> by_target;
    std::map<std::string, std::size_t> by_principal;
    std::size_t stale_count = 0;
    std::size_t fenced_count = 0;
    std::size_t tombstoned_active_count = 0;
    std::size_t overdue_count = 0;
    std::size_t cancellation_signalled_count = 0;
    std::uint64_t oldest_age_ms = 0;
    bool stale_owners_present = false;

    json active_items = json::array();
    std::vector<mcp_lease_registry_record_t> active_sorted;
    active_sorted.reserve(active.size());
    for (const auto& kv : active)
        active_sorted.push_back(kv.second);
    std::sort(active_sorted.begin(), active_sorted.end(), [](const auto& a, const auto& b) {
        return a.started_ms < b.started_ms;
    });
    for (const auto& record : active_sorted) {
        const std::uint64_t age_ms = record.started_ms != 0 && now >= record.started_ms ? now - record.started_ms : 0;
        if (age_ms > oldest_age_ms)
            oldest_age_ms = age_ms;
        ++by_lane[record.lane];
        ++by_tool[record.tool];
        ++by_session[record.session_id];
        ++by_target[record.target_id];
        ++by_principal[record.principal_bucket];
        if (record.stale) {
            ++stale_count;
            stale_owners_present = true;
        }
        if (record.fenced)
            ++fenced_count;
        if (record.tombstoned)
            ++tombstoned_active_count;
        if (record.cancellation_signalled)
            ++cancellation_signalled_count;
        if (record.deadline_ms != 0 && now >= record.deadline_ms)
            ++overdue_count;
        if (active_items.size() < max_active)
            active_items.push_back(mcp_lease_record_json(record, now));
    }

    json top_owners = json::array();
    std::vector<mcp_lease_registry_record_t> by_age_desc = active_sorted;
    std::sort(by_age_desc.begin(), by_age_desc.end(), [now](const auto& a, const auto& b) {
        const std::uint64_t age_a = a.started_ms != 0 && now >= a.started_ms ? now - a.started_ms : 0;
        const std::uint64_t age_b = b.started_ms != 0 && now >= b.started_ms ? now - b.started_ms : 0;
        return age_a > age_b;
    });
    for (const auto& record : by_age_desc) {
        if (top_owners.size() >= 8)
            break;
        const std::uint64_t age_ms = record.started_ms != 0 && now >= record.started_ms ? now - record.started_ms : 0;
        top_owners.push_back({
            {"lease_token", record.lease_token},
            {"tool", record.tool},
            {"lane", record.lane},
            {"phase", record.phase},
            {"age_ms", age_ms},
            {"deadline_ms", record.deadline_ms},
            {"diagnostic_id", record.diagnostic_id},
            {"session_id", record.session_id},
            {"target_id", record.target_id},
            {"priority", record.priority},
            {"cancellation_signalled", record.cancellation_signalled},
            {"stale", record.stale},
            {"fenced", record.fenced},
            {"commit_eligible", record.commit_eligible}
        });
    }

    json tombstone_items = json::array();
    for (const auto& record : tombstones) {
        if (tombstone_items.size() >= max_tombstones)
            break;
        tombstone_items.push_back(mcp_lease_record_json(record, now));
    }

    json lane_counts = json::object();
    for (const auto& kv : by_lane)
        lane_counts[kv.first] = kv.second;
    json tool_counts = json::object();
    for (const auto& kv : by_tool)
        tool_counts[kv.first] = kv.second;
    json session_counts = json::object();
    for (const auto& kv : by_session)
        session_counts[kv.first] = kv.second;
    json target_counts = json::object();
    for (const auto& kv : by_target)
        target_counts[kv.first] = kv.second;
    json principal_counts = json::object();
    for (const auto& kv : by_principal)
        principal_counts[kv.first] = kv.second;

    out["active_leases_by_lane"] = lane_counts;
    out["active_leases_by_tool"] = tool_counts;
    out["active_leases_by_session"] = session_counts;
    out["active_leases_by_target"] = target_counts;
    out["active_leases_by_principal"] = principal_counts;
    out["stale_count"] = stale_count;
    out["fenced_count"] = fenced_count;
    out["tombstoned_active_count"] = tombstoned_active_count;
    out["overdue_owners_count"] = overdue_count;
    out["cancellation_signalled_count"] = cancellation_signalled_count;
    out["oldest_active_owner_age_ms"] = oldest_age_ms;
    out["stale_owners_present"] = stale_owners_present;
    out["top_lock_owners_by_age"] = top_owners;
    out["active"] = std::move(active_items);
    out["recent_tombstones"] = std::move(tombstone_items);
    lk.unlock();

    out["conflict_counters_by_lane"] = mcp_lease_conflict_counters_json();
    out["late_result_discard_count"] = mcp_lease_late_result_discard_count().load(std::memory_order_acquire);
    out["camoufox_cleanup_attempt_count"] = mcp_lease_camoufox_cleanup_attempt_count().load(std::memory_order_acquire);
    out["camoufox_cleanup_rejected_count"] = mcp_lease_camoufox_cleanup_rejected_count().load(std::memory_order_acquire);
    out["lock_conflict_count"] = mcp_lease_lock_conflict_count().load(std::memory_order_acquire);
    return out;
}

static mcp_lease_registry_snapshot_t mcp_lease_registry_lock_owner_diagnostics()
{
    const std::uint64_t now = mcp_now_ms();
    mcp_lease_registry_snapshot_t snap;
    std::unique_lock<std::mutex> lk(mcp_lease_registry_mutex(), std::try_to_lock);
    if (!lk.owns_lock()) {
        snap.lock_busy = true;
        return snap;
    }
    const mcp_lease_registry_record_t* oldest = nullptr;
    for (const auto& kv : mcp_lease_registry_active()) {
        const auto& record = kv.second;
        if (!oldest || record.started_ms < oldest->started_ms)
            oldest = &record;
    }
    if (!oldest)
        return snap;
    snap.present = true;
    snap.lease_token = oldest->lease_token;
    snap.registry_generation = oldest->registry_generation;
    snap.operation_generation = oldest->operation_generation;
    snap.diagnostic_id = oldest->diagnostic_id;
    snap.request_id = oldest->request_id;
    snap.tool = oldest->tool;
    snap.route = oldest->route;
    snap.transport = oldest->transport;
    snap.principal_bucket = oldest->principal_bucket;
    snap.session_id = oldest->session_id;
    snap.session_hash = oldest->session_hash;
    snap.target_id = oldest->target_id;
    snap.target_pid = oldest->target_pid;
    snap.lane = oldest->lane;
    snap.priority = oldest->priority;
    snap.read_only = oldest->read_only;
    snap.mutating = oldest->mutating;
    snap.session_manager = oldest->session_manager;
    snap.domain_mutating = oldest->domain_mutating;
    snap.domain = oldest->domain;
    snap.phase = oldest->phase;
    snap.process_pid = oldest->process_pid;
    snap.worker_tid = oldest->worker_tid;
    snap.started_ms = oldest->started_ms;
    snap.owner_age_ms = oldest->started_ms != 0 && now >= oldest->started_ms ? now - oldest->started_ms : 0;
    snap.deadline_ms = oldest->deadline_ms;
    snap.cancellation_signalled = oldest->cancellation_signalled;
    snap.stale = oldest->stale;
    snap.fenced = oldest->fenced;
    snap.tombstoned = oldest->tombstoned;
    snap.released = oldest->released;
    snap.commit_eligible = oldest->commit_eligible;
    snap.external_process_kind = oldest->external_process_kind;
    snap.external_process_pid = oldest->external_process_pid;
    snap.external_process_identity = oldest->external_process_identity;
    snap.external_process_session = oldest->external_process_session;
    snap.external_process_generation = oldest->external_process_generation;
    snap.external_expected_executable_path = oldest->external_expected_executable_path;
    snap.external_process_creation_time_100ns = oldest->external_process_creation_time_100ns;
    snap.external_sidecar_ownership_marker = oldest->external_sidecar_ownership_marker;
    snap.external_force_cleanup_eligible = oldest->external_force_cleanup_eligible;
    return snap;
}

static json mcp_lease_registry_lock_owner_diagnostics_json()
{
    const mcp_lease_registry_snapshot_t snap = mcp_lease_registry_lock_owner_diagnostics();
    if (snap.lock_busy)
        return json{{"lock_busy", true}, {"present", false}};
    if (!snap.present)
        return json{{"lock_busy", false}, {"present", false}};
    return {
        {"lock_busy", false},
        {"present", true},
        {"lease_token", snap.lease_token},
        {"registry_generation", snap.registry_generation},
        {"operation_generation", snap.operation_generation},
        {"diagnostic_id", snap.diagnostic_id},
        {"request_id", snap.request_id},
        {"tool", snap.tool},
        {"route", snap.route},
        {"transport", snap.transport},
        {"principal_bucket", snap.principal_bucket},
        {"session_id", snap.session_id},
        {"session_hash", snap.session_hash},
        {"target_id", snap.target_id},
        {"target_pid", snap.target_pid},
        {"lane", snap.lane},
        {"priority", snap.priority},
        {"read_only", snap.read_only},
        {"mutating", snap.mutating},
        {"session_manager", snap.session_manager},
        {"domain_mutating", snap.domain_mutating},
        {"domain", snap.domain},
        {"phase", snap.phase},
        {"process_pid", snap.process_pid},
        {"worker_tid", static_cast<std::uint32_t>(snap.worker_tid)},
        {"started_ms", snap.started_ms},
        {"owner_age_ms", snap.owner_age_ms},
        {"deadline_ms", snap.deadline_ms},
        {"cancellation_signalled", snap.cancellation_signalled},
        {"stale", snap.stale},
        {"fenced", snap.fenced},
        {"tombstoned", snap.tombstoned},
        {"released", snap.released},
        {"commit_eligible", snap.commit_eligible},
        {"external_process_kind", snap.external_process_kind},
        {"external_process_pid", snap.external_process_pid},
        {"external_process_identity", snap.external_process_identity},
        {"external_process_session", snap.external_process_session},
        {"external_process_generation", snap.external_process_generation},
        {"external_expected_executable_path", snap.external_expected_executable_path},
        {"external_process_creation_time_100ns", snap.external_process_creation_time_100ns},
        {"external_sidecar_ownership_marker", snap.external_sidecar_ownership_marker},
        {"external_force_cleanup_eligible", snap.external_force_cleanup_eligible}
    };
}

static void mcp_lease_registry_shutdown_cleanup(const char* reason)
{
    const std::uint64_t now = mcp_now_ms();
    std::vector<mcp_lease_registry_record_t> records;
    {
        std::lock_guard<std::mutex> lk(mcp_lease_registry_mutex());
        auto& active = mcp_lease_registry_active();
        for (auto& kv : active) {
            kv.second.cancellation_signalled = true;
            kv.second.cancellation_signalled_ms = now;
            kv.second.stale = true;
            kv.second.stale_marked_ms = now;
            kv.second.fenced = true;
            kv.second.fenced_ms = now;
            kv.second.commit_eligible = false;
            if (kv.second.cancel_token)
                kv.second.cancel_token->store(true, std::memory_order_release);
            kv.second.cancel_token = nullptr;
            records.push_back(kv.second);
        }
        for (const auto& record : records)
            mcp_lease_registry_add_tombstone_locked(record, reason ? reason : "shutdown_cleanup", now);
        active.clear();
    }
    for (const auto& record : records) {
        mcp_lease_log_event("MCP-LEASE-CANCEL-SIGNAL", record, reason ? reason : "shutdown_cleanup", true, now);
        mcp_lease_log_event("MCP-LEASE-STALE", record, reason ? reason : "shutdown_cleanup", true, now);
        mcp_lease_log_event("MCP-LEASE-FENCED", record, reason ? reason : "shutdown_cleanup", true, now);
        mcp_lease_log_event("MCP-LEASE-RELEASE", record, reason ? reason : "shutdown_cleanup", true, now);
    }
}

static json mcp_lease_snapshot_json(const mcp_lease_registry_snapshot_t& snap)
{
    return {
        {"present", snap.present},
        {"lock_busy", snap.lock_busy},
        {"lease_token", snap.lease_token},
        {"registry_generation", snap.registry_generation},
        {"operation_generation", snap.operation_generation},
        {"diagnostic_id", snap.diagnostic_id},
        {"request_id", snap.request_id},
        {"tool", snap.tool},
        {"route", snap.route},
        {"transport", snap.transport},
        {"principal_bucket", snap.principal_bucket},
        {"session_id", snap.session_id},
        {"session_hash", snap.session_hash},
        {"target_id", snap.target_id},
        {"target_pid", snap.target_pid},
        {"lane", snap.lane},
        {"priority", snap.priority},
        {"domain", snap.domain},
        {"phase", snap.phase},
        {"started_ms", snap.started_ms},
        {"owner_age_ms", snap.owner_age_ms},
        {"deadline_ms", snap.deadline_ms},
        {"cancellation_signalled", snap.cancellation_signalled},
        {"stale", snap.stale},
        {"fenced", snap.fenced},
        {"tombstoned", snap.tombstoned},
        {"released", snap.released},
        {"commit_eligible", snap.commit_eligible},
        {"external_process_kind", snap.external_process_kind},
        {"external_process_pid", snap.external_process_pid},
        {"external_process_identity", snap.external_process_identity},
        {"external_process_session", snap.external_process_session},
        {"external_process_generation", snap.external_process_generation},
        {"external_expected_executable_path", snap.external_expected_executable_path},
        {"external_process_creation_time_100ns", snap.external_process_creation_time_100ns},
        {"external_sidecar_ownership_marker", snap.external_sidecar_ownership_marker},
        {"external_force_cleanup_eligible", snap.external_force_cleanup_eligible}
    };
}

static std::vector<std::string> mcp_camoufox_cleanup_missing_fields(const mcp_lease_registry_snapshot_t& snap)
{
    std::vector<std::string> missing;
    if (!snap.present)
        missing.push_back("lease_snapshot");
    if (snap.lease_token == 0)
        missing.push_back("lease_token");
    if (snap.registry_generation == 0)
        missing.push_back("registry_generation");
    if (snap.operation_generation == 0)
        missing.push_back("operation_generation");
    if (snap.principal_bucket.empty())
        missing.push_back("principal_bucket");
    if (snap.session_id.empty())
        missing.push_back("session_id");
    if (snap.session_hash.empty())
        missing.push_back("session_hash");
    if (snap.external_process_kind != "camoufox_reverse_mcp_sidecar")
        missing.push_back("external_process_kind");
    if (snap.external_process_pid == 0)
        missing.push_back("external_process_pid");
    if (snap.external_process_session.empty())
        missing.push_back("external_process_session");
    if (snap.external_process_generation == 0)
        missing.push_back("external_process_generation");
    if (snap.external_expected_executable_path.empty())
        missing.push_back("external_expected_executable_path");
    if (snap.external_process_creation_time_100ns == 0)
        missing.push_back("external_process_creation_time_100ns");
    if (snap.external_sidecar_ownership_marker.empty())
        missing.push_back("external_sidecar_ownership_marker");
    if (!snap.external_force_cleanup_eligible)
        missing.push_back("external_force_cleanup_eligible");
    return missing;
}

static json mcp_camoufox_stale_cleanup_rejected(const mcp_lease_registry_snapshot_t& snap,
                                                const std::vector<std::string>& missing,
                                                const std::string& diag_id,
                                                const std::string& request_id,
                                                const std::string& tool_name,
                                                const std::string& action)
{
    json out = {
        {"result", "rejected"},
        {"reason", "missing_or_incomplete_proof"},
        {"missing", missing},
        {"lease", mcp_lease_snapshot_json(snap)}
    };
    std::ostringstream missing_text;
    for (std::size_t i = 0; i < missing.size(); ++i) {
        if (i)
            missing_text << ",";
        missing_text << missing[i];
    }
    const std::string missing_compact = missing_text.str();
    diag::log_tagged_fmt("mcp_srv",
        "MCP-CAMOUFOX-STALE-CLEANUP-REJECTED reason=missing_or_incomplete_proof missing=%s diag_id=%s request_id=%s tool=%s action=%s lease_token=%llu operation_generation=%llu registry_generation=%llu external_pid=%u external_session=%s external_generation=%llu external_expected_path=%s external_ctime=%llu marker=%s",
        missing_compact.empty() ? "<none>" : missing_compact.c_str(),
        diag_id.c_str(),
        request_id.c_str(),
        tool_name.c_str(),
        action.c_str(),
        static_cast<unsigned long long>(snap.lease_token),
        static_cast<unsigned long long>(snap.operation_generation),
        static_cast<unsigned long long>(snap.registry_generation),
        snap.external_process_pid,
        snap.external_process_session.c_str(),
        static_cast<unsigned long long>(snap.external_process_generation),
        snap.external_expected_executable_path.c_str(),
        static_cast<unsigned long long>(snap.external_process_creation_time_100ns),
        snap.external_sidecar_ownership_marker.c_str());
    return out;
}

static json mcp_camoufox_cleanup_stale_sidecar(const mcp_lease_registry_snapshot_t& snap,
                                               const std::string& diag_id,
                                               const std::string& request_id,
                                               const std::string& tool_name,
                                               const std::string& action)
{
    const std::vector<std::string> missing = mcp_camoufox_cleanup_missing_fields(snap);
    if (!missing.empty()) {
        mcp_lease_camoufox_cleanup_rejected_count().fetch_add(1u, std::memory_order_acq_rel);
        return mcp_camoufox_stale_cleanup_rejected(snap, missing, diag_id, request_id, tool_name, action);
    }

    mcp_lease_camoufox_cleanup_attempt_count().fetch_add(1u, std::memory_order_acq_rel);

    aida::burp::camoufox::stale_sidecar_cleanup_proof_t proof;
    proof.diagnostic_id = diag_id;
    proof.request_id = request_id;
    proof.tool = tool_name;
    proof.action = action;
    proof.bridge_session_id = snap.external_process_session;
    proof.mcp_session_id = snap.session_id;
    proof.mcp_session_hash = snap.session_hash;
    proof.principal_bucket = snap.principal_bucket;
    proof.expected_executable_path = snap.external_expected_executable_path;
    proof.expected_sidecar_pid = snap.external_process_pid;
    proof.expected_bridge_generation = snap.external_process_generation;
    proof.expected_process_creation_time_100ns = snap.external_process_creation_time_100ns;
    proof.lease_token = snap.lease_token;
    proof.registry_generation = snap.registry_generation;
    proof.operation_generation = snap.operation_generation;
    proof.sidecar_ownership_marker = snap.external_sidecar_ownership_marker;

    aida::burp::camoufox::stale_sidecar_cleanup_result_t cleanup = aida::burp::camoufox::cleanup_stale_sidecar_if_owned(proof);
    json out = cleanup.diagnostics.is_object() ? cleanup.diagnostics : json::object();
    out["attempted"] = cleanup.attempted;
    out["cleaned"] = cleanup.cleaned;
    out["rejected"] = cleanup.rejected;
    out["reason"] = cleanup.reason;
    out["lease"] = mcp_lease_snapshot_json(snap);
    if (cleanup.rejected) {
        mcp_lease_camoufox_cleanup_rejected_count().fetch_add(1u, std::memory_order_acq_rel);
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAMOUFOX-STALE-CLEANUP-REJECTED reason=%s diag_id=%s request_id=%s tool=%s action=%s lease_token=%llu operation_generation=%llu registry_generation=%llu external_pid=%u external_session=%s external_generation=%llu external_expected_path=%s external_ctime=%llu marker=%s",
            cleanup.reason.c_str(),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            action.c_str(),
            static_cast<unsigned long long>(snap.lease_token),
            static_cast<unsigned long long>(snap.operation_generation),
            static_cast<unsigned long long>(snap.registry_generation),
            snap.external_process_pid,
            snap.external_process_session.c_str(),
            static_cast<unsigned long long>(snap.external_process_generation),
            snap.external_expected_executable_path.c_str(),
            static_cast<unsigned long long>(snap.external_process_creation_time_100ns),
            snap.external_sidecar_ownership_marker.c_str());
    } else {
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAMOUFOX-STALE-CLEANUP result=%s cleaned=%d diag_id=%s request_id=%s tool=%s action=%s lease_token=%llu operation_generation=%llu registry_generation=%llu external_pid=%u external_session=%s external_generation=%llu external_expected_path=%s external_ctime=%llu marker=%s",
            cleanup.reason.c_str(),
            cleanup.cleaned ? 1 : 0,
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            action.c_str(),
            static_cast<unsigned long long>(snap.lease_token),
            static_cast<unsigned long long>(snap.operation_generation),
            static_cast<unsigned long long>(snap.registry_generation),
            snap.external_process_pid,
            snap.external_process_session.c_str(),
            static_cast<unsigned long long>(snap.external_process_generation),
            snap.external_expected_executable_path.c_str(),
            static_cast<unsigned long long>(snap.external_process_creation_time_100ns),
            snap.external_sidecar_ownership_marker.c_str());
    }
    return out;
}

struct active_session_owner_record_t
{
    bool active = false;
    bool exclusive = false;
    bool read_only = false;
    bool explicit_target = false;
    bool cancelled = false;
    std::uint64_t token = 0;
    std::uint64_t registry_generation = 0;
    std::uint64_t operation_generation = 0;
    std::uint64_t acquired_ms = 0;
    std::uint64_t deadline_ms = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::string tool;
    std::string lane;
    std::string diag_id;
    std::string request_id;
    std::string route;
    std::string transport;
    std::string principal_bucket;
    std::string session_id;
    std::string session_hash;
    std::string target_id;
    std::string priority;
    std::string domain;
    std::string phase;
    std::uint32_t target_pid = 0;
    bool mutating = false;
    bool session_manager = false;
    bool domain_mutating = false;
    bool stale = false;
    bool fenced = false;
    bool tombstoned = false;
    bool released = false;
    bool commit_eligible = true;
    std::string external_process_kind;
    std::uint32_t external_process_pid = 0;
    std::string external_process_identity;
    std::string external_process_session;
    std::uint64_t external_process_generation = 0;
    std::string external_expected_executable_path;
    std::uint64_t external_process_creation_time_100ns = 0;
    std::string external_sidecar_ownership_marker;
    bool external_force_cleanup_eligible = false;
};

struct active_session_owner_snapshot_t
{
    bool present = false;
    bool exclusive = false;
    bool cancelled = false;
    bool read_only = false;
    bool explicit_target = false;
    std::size_t shared_owner_count = 0;
    std::uint64_t token = 0;
    std::uint64_t registry_generation = 0;
    std::uint64_t operation_generation = 0;
    std::uint64_t acquired_ms = 0;
    std::uint64_t owner_age_ms = 0;
    std::uint64_t deadline_ms = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::string tool;
    std::string lane;
    std::string diag_id;
    std::string request_id;
    std::string route;
    std::string transport;
    std::string principal_bucket;
    std::string session_id;
    std::string session_hash;
    std::string target_id;
    std::string priority;
    std::string domain;
    std::string phase;
    std::uint32_t target_pid = 0;
    bool mutating = false;
    bool session_manager = false;
    bool domain_mutating = false;
    bool stale = false;
    bool fenced = false;
    bool tombstoned = false;
    bool released = false;
    bool commit_eligible = true;
    std::string external_process_kind;
    std::uint32_t external_process_pid = 0;
    std::string external_process_identity;
    std::string external_process_session;
    std::uint64_t external_process_generation = 0;
    std::string external_expected_executable_path;
    std::uint64_t external_process_creation_time_100ns = 0;
    std::string external_sidecar_ownership_marker;
    bool external_force_cleanup_eligible = false;
};

static std::mutex& active_session_owner_mutex()
{
    static std::mutex m;
    return m;
}

static active_session_owner_record_t& active_session_exclusive_owner()
{
    static active_session_owner_record_t owner;
    return owner;
}

static std::vector<active_session_owner_record_t>& active_session_shared_owners()
{
    static std::vector<active_session_owner_record_t> owners;
    return owners;
}

static std::atomic<std::uint64_t>& active_session_owner_token_source()
{
    static std::atomic<std::uint64_t> source{0};
    return source;
}

static active_session_owner_snapshot_t active_session_owner_snapshot_from_record(const active_session_owner_record_t& record, std::size_t shared_count, std::uint64_t now)
{
    active_session_owner_snapshot_t snap;
    snap.present = record.active;
    snap.exclusive = record.exclusive;
    snap.cancelled = record.cancelled;
    snap.read_only = record.read_only;
    snap.explicit_target = record.explicit_target;
    snap.shared_owner_count = shared_count;
    snap.token = record.token;
    snap.registry_generation = record.registry_generation;
    snap.operation_generation = record.operation_generation;
    snap.acquired_ms = record.acquired_ms;
    snap.owner_age_ms = record.acquired_ms != 0 && now >= record.acquired_ms ? now - record.acquired_ms : 0;
    snap.deadline_ms = record.deadline_ms;
    snap.pid = record.pid;
    snap.tid = record.tid;
    snap.tool = sanitize_owner_field(record.tool);
    snap.lane = sanitize_owner_field(record.lane);
    snap.diag_id = sanitize_owner_field(record.diag_id);
    snap.request_id = sanitize_owner_field(record.request_id);
    snap.route = sanitize_owner_field(record.route);
    snap.transport = sanitize_owner_field(record.transport);
    snap.principal_bucket = sanitize_owner_field(record.principal_bucket);
    snap.session_id = sanitize_owner_field(record.session_id);
    snap.session_hash = sanitize_owner_field(record.session_hash);
    snap.target_id = sanitize_owner_field(record.target_id);
    snap.priority = sanitize_owner_field(record.priority);
    snap.domain = sanitize_owner_field(record.domain);
    snap.phase = sanitize_owner_field(record.phase);
    snap.registry_generation = record.registry_generation;
    snap.operation_generation = record.operation_generation;
    snap.target_pid = record.target_pid;
    snap.mutating = record.mutating;
    snap.session_manager = record.session_manager;
    snap.domain_mutating = record.domain_mutating;
    snap.stale = record.stale;
    snap.fenced = record.fenced;
    snap.tombstoned = record.tombstoned;
    snap.released = record.released;
    snap.commit_eligible = record.commit_eligible;
    snap.external_process_kind = sanitize_owner_field(record.external_process_kind);
    snap.external_process_pid = record.external_process_pid;
    snap.external_process_identity = sanitize_owner_field(record.external_process_identity);
    snap.external_process_session = sanitize_owner_field(record.external_process_session);
    snap.external_process_generation = record.external_process_generation;
    snap.external_expected_executable_path = sanitize_owner_field(record.external_expected_executable_path, 1024);
    snap.external_process_creation_time_100ns = record.external_process_creation_time_100ns;
    snap.external_sidecar_ownership_marker = sanitize_owner_field(record.external_sidecar_ownership_marker, 160);
    snap.external_force_cleanup_eligible = record.external_force_cleanup_eligible;
    return snap;
}

static active_session_owner_snapshot_t active_session_owner_snapshot()
{
    const std::uint64_t now = mcp_now_ms();
    active_session_owner_record_t selected;
    bool selected_present = false;
    std::size_t shared_count = 0;
    {
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        auto& exclusive_owner = active_session_exclusive_owner();
        auto& shared_owners = active_session_shared_owners();
        shared_count = shared_owners.size();
        if (exclusive_owner.active) {
            selected = exclusive_owner;
            selected_present = true;
        } else {
            const active_session_owner_record_t* oldest = nullptr;
            for (const auto& owner : shared_owners) {
                if (!owner.active)
                    continue;
                if (!oldest || owner.acquired_ms < oldest->acquired_ms)
                    oldest = &owner;
            }
            if (oldest) {
                selected = *oldest;
                selected_present = true;
            }
        }
    }
    if (selected_present) {
        active_session_owner_snapshot_t snap = active_session_owner_snapshot_from_record(selected, shared_count, now);
        mcp_lease_registry_snapshot_t lease_snap;
        if (mcp_lease_registry_commit_eligible(selected.token, selected.operation_generation, &lease_snap) || lease_snap.present) {
            snap.registry_generation = lease_snap.registry_generation;
            snap.operation_generation = lease_snap.operation_generation;
            snap.request_id = lease_snap.request_id;
            snap.route = lease_snap.route;
            snap.transport = lease_snap.transport;
            snap.principal_bucket = lease_snap.principal_bucket;
            snap.session_id = lease_snap.session_id;
            snap.session_hash = lease_snap.session_hash;
            snap.target_id = lease_snap.target_id;
            snap.target_pid = lease_snap.target_pid;
            snap.lane = lease_snap.lane;
            snap.priority = lease_snap.priority;
            snap.domain = lease_snap.domain;
            snap.phase = lease_snap.phase;
            snap.cancelled = lease_snap.cancellation_signalled;
            snap.read_only = lease_snap.read_only;
            snap.mutating = lease_snap.mutating;
            snap.session_manager = lease_snap.session_manager;
            snap.domain_mutating = lease_snap.domain_mutating;
            snap.stale = lease_snap.stale;
            snap.fenced = lease_snap.fenced;
            snap.tombstoned = lease_snap.tombstoned;
            snap.released = lease_snap.released;
            snap.commit_eligible = lease_snap.commit_eligible;
            snap.external_process_kind = lease_snap.external_process_kind;
            snap.external_process_pid = lease_snap.external_process_pid;
            snap.external_process_identity = lease_snap.external_process_identity;
            snap.external_process_session = lease_snap.external_process_session;
            snap.external_process_generation = lease_snap.external_process_generation;
            snap.external_force_cleanup_eligible = lease_snap.external_force_cleanup_eligible;
        }
        return snap;
    }
    active_session_owner_snapshot_t snap;
    snap.shared_owner_count = shared_count;
    return snap;
}

static void format_active_session_owner_diagnostic_snapshot(char* out, std::size_t cap) noexcept
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    try {
        const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
        _snprintf_s(out, cap, _TRUNCATE,
            "owner{present=%d mode=%s shared_count=%zu tool=%.160s lane=%.96s diag_id=%.128s request_id=%.128s generation=%llu registry_generation=%llu phase=%.96s pid=%lu tid=%lu target_pid=%u session=%.96s target=%.96s priority=%s domain=%s age_ms=%llu acquired_ms=%llu deadline_ms=%llu token=%llu cancelled=%d stale=%d fenced=%d tombstoned=%d released=%d commit_eligible=%d read_only=%d mutating=%d session_manager=%d explicit_target=%d}",
            owner.present ? 1 : 0,
            owner.present ? (owner.exclusive ? "exclusive" : "shared") : "none",
            owner.shared_owner_count,
            owner.present ? owner.tool.c_str() : "",
            owner.present ? owner.lane.c_str() : "",
            owner.present ? owner.diag_id.c_str() : "",
            owner.present ? owner.request_id.c_str() : "",
            owner.present ? static_cast<unsigned long long>(owner.operation_generation) : 0ULL,
            owner.present ? static_cast<unsigned long long>(owner.registry_generation) : 0ULL,
            owner.present ? owner.phase.c_str() : "",
            owner.present ? static_cast<unsigned long>(owner.pid) : 0UL,
            owner.present ? static_cast<unsigned long>(owner.tid) : 0UL,
            owner.present ? owner.target_pid : 0u,
            owner.present ? owner.session_id.c_str() : "",
            owner.present ? owner.target_id.c_str() : "",
            owner.present ? owner.priority.c_str() : "",
            owner.present ? owner.domain.c_str() : "",
            owner.present ? static_cast<unsigned long long>(owner.owner_age_ms) : 0ULL,
            owner.present ? static_cast<unsigned long long>(owner.acquired_ms) : 0ULL,
            owner.present ? static_cast<unsigned long long>(owner.deadline_ms) : 0ULL,
            owner.present ? static_cast<unsigned long long>(owner.token) : 0ULL,
            owner.present && owner.cancelled ? 1 : 0,
            owner.present && owner.stale ? 1 : 0,
            owner.present && owner.fenced ? 1 : 0,
            owner.present && owner.tombstoned ? 1 : 0,
            owner.present && owner.released ? 1 : 0,
            owner.present && owner.commit_eligible ? 1 : 0,
            owner.present && owner.read_only ? 1 : 0,
            owner.present && owner.mutating ? 1 : 0,
            owner.present && owner.session_manager ? 1 : 0,
            owner.present && owner.explicit_target ? 1 : 0);
    } catch (...) {
        _snprintf_s(out, cap, _TRUNCATE, "owner{snapshot_exception=1}");
    }
}

static void append_active_session_owner_fields(json& details, const active_session_owner_snapshot_t& owner)
{
    details["owner_present"] = owner.present;
    details["owner_mode"] = owner.present ? (owner.exclusive ? "exclusive" : "shared") : "";
    details["owner_tool"] = owner.present ? owner.tool : "";
    details["owner_diag_id"] = owner.present ? owner.diag_id : "";
    details["owner_request_id"] = owner.present ? owner.request_id : "";
    details["owner_lane"] = owner.present ? owner.lane : "";
    details["owner_route"] = owner.present ? owner.route : "";
    details["owner_transport"] = owner.present ? owner.transport : "";
    details["owner_principal_bucket"] = owner.present ? owner.principal_bucket : "";
    details["owner_session_id"] = owner.present ? owner.session_id : "";
    details["owner_session_hash"] = owner.present ? owner.session_hash : "";
    details["owner_target_id"] = owner.present ? owner.target_id : "";
    details["owner_target_pid"] = owner.present ? owner.target_pid : 0;
    details["owner_token"] = owner.present ? owner.token : 0;
    details["owner_priority"] = owner.present ? owner.priority : "";
    details["owner_domain"] = owner.present ? owner.domain : "";
    details["owner_pid"] = owner.present ? owner.pid : 0;
    details["owner_tid"] = owner.present ? owner.tid : 0;
    details["owner_age_ms"] = owner.present ? owner.owner_age_ms : 0;
    details["owner_deadline_ms"] = owner.present ? owner.deadline_ms : 0;
    details["owner_cancelled"] = owner.present ? owner.cancelled : false;
    details["owner_stale"] = owner.present ? owner.stale : false;
    details["owner_fenced"] = owner.present ? owner.fenced : false;
    details["owner_tombstoned"] = owner.present ? owner.tombstoned : false;
    details["owner_released"] = owner.present ? owner.released : false;
    details["owner_commit_eligible"] = owner.present ? owner.commit_eligible : false;
    details["owner_phase"] = owner.present ? owner.phase : "";
    details["owner_read_only"] = owner.present ? owner.read_only : false;
    details["owner_mutating"] = owner.present ? owner.mutating : false;
    details["owner_session_manager"] = owner.present ? owner.session_manager : false;
    details["owner_domain_mutating"] = owner.present ? owner.domain_mutating : false;
    details["owner_explicit_target"] = owner.present ? owner.explicit_target : false;
    details["owner_registry_generation"] = owner.present ? owner.registry_generation : 0;
    details["owner_operation_generation"] = owner.present ? owner.operation_generation : 0;
    details["owner_external_process_kind"] = owner.present ? owner.external_process_kind : "";
    details["owner_external_process_pid"] = owner.present ? owner.external_process_pid : 0;
    details["owner_external_process_identity"] = owner.present ? owner.external_process_identity : "";
    details["owner_external_process_session"] = owner.present ? owner.external_process_session : "";
    details["owner_external_process_generation"] = owner.present ? owner.external_process_generation : 0;
    details["owner_external_expected_executable_path"] = owner.present ? owner.external_expected_executable_path : "";
    details["owner_external_process_creation_time_100ns"] = owner.present ? owner.external_process_creation_time_100ns : 0;
    details["owner_external_sidecar_ownership_marker"] = owner.present ? owner.external_sidecar_ownership_marker : "";
    details["owner_external_force_cleanup_eligible"] = owner.present ? owner.external_force_cleanup_eligible : false;
    details["shared_owner_count"] = owner.shared_owner_count;
    details["exclusive_owner"] = owner.present && owner.exclusive;
}

json active_session_policy_debug_snapshot()
{
    json out;
    out["phase"] = "phase5_active_session_policy";
    out["lock_model"] = "bounded_wait_no_expired_owner_steal";
    out["ui_thread_blocking_wait"] = false;
    out["timestamp_ms"] = mcp_now_ms();
    const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
    append_active_session_owner_fields(out, owner);
    out["lease_registry"] = mcp_lease_registry_bounded_snapshot(16, 16);
    return out;
}

static void log_active_session_owner_stale_if_needed(const active_session_owner_snapshot_t& owner,
                                                     const char* reason,
                                                     const std::string& waiter_tool,
                                                     const char* waiter_lane,
                                                     std::uint64_t waiter_wait_ms,
                                                     std::uint64_t waiter_budget_ms)
{
    if (!owner.present)
        return;
    const std::uint64_t now = mcp_now_ms();
    const bool deadline_expired = owner.deadline_ms != 0 && now >= owner.deadline_ms;
    const bool budget_exceeded = waiter_budget_ms != 0 && waiter_wait_ms >= waiter_budget_ms;
    if (!deadline_expired && !budget_exceeded)
        return;
    if (!owner.stale)
        mcp_lease_registry_mark_stale(owner.token, owner.operation_generation, reason ? reason : "owner_wait_stale");
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lock_owner_stale reason=%s waiter_tool='%s' waiter_lane=%s waiter_wait_ms=%llu waiter_budget_ms=%llu owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_request_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_target_pid=%u owner_session='%s' owner_target='%s' owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_stale=%d owner_fenced=%d owner_commit_eligible=%d owner_phase=%s owner_generation=%llu owner_registry_generation=%llu shared_owner_count=%zu",
        reason ? reason : "",
        waiter_tool.c_str(),
        waiter_lane ? waiter_lane : "",
        static_cast<unsigned long long>(waiter_wait_ms),
        static_cast<unsigned long long>(waiter_budget_ms),
        owner.tool.c_str(),
        owner.lane.c_str(),
        owner.diag_id.c_str(),
        owner.request_id.c_str(),
        owner.exclusive ? "exclusive" : "shared",
        static_cast<unsigned long>(owner.pid),
        static_cast<unsigned long>(owner.tid),
        owner.target_pid,
        owner.session_id.c_str(),
        owner.target_id.c_str(),
        static_cast<unsigned long long>(owner.owner_age_ms),
        static_cast<unsigned long long>(owner.deadline_ms),
        owner.cancelled ? 1 : 0,
        owner.stale ? 1 : 0,
        owner.fenced ? 1 : 0,
        owner.commit_eligible ? 1 : 0,
        owner.phase.c_str(),
        static_cast<unsigned long long>(owner.operation_generation),
        static_cast<unsigned long long>(owner.registry_generation),
        owner.shared_owner_count);
    diag::log_tagged_fmt("mcp_srv",
        "MCP-STALE-LEASE reason=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_request_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_target_pid=%u owner_session='%s' owner_target='%s' owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_stale=%d owner_fenced=%d owner_commit_eligible=%d owner_phase=%s token=%llu operation_generation=%llu registry_generation=%llu shared_owner_count=%zu waiter_tool='%s' waiter_lane=%s waiter_wait_ms=%llu waiter_budget_ms=%llu",
        reason ? reason : "",
        owner.tool.c_str(),
        owner.lane.c_str(),
        owner.diag_id.c_str(),
        owner.request_id.c_str(),
        owner.exclusive ? "exclusive" : "shared",
        static_cast<unsigned long>(owner.pid),
        static_cast<unsigned long>(owner.tid),
        owner.target_pid,
        owner.session_id.c_str(),
        owner.target_id.c_str(),
        static_cast<unsigned long long>(owner.owner_age_ms),
        static_cast<unsigned long long>(owner.deadline_ms),
        owner.cancelled ? 1 : 0,
        owner.stale ? 1 : 0,
        owner.fenced ? 1 : 0,
        owner.commit_eligible ? 1 : 0,
        owner.phase.c_str(),
        static_cast<unsigned long long>(owner.token),
        static_cast<unsigned long long>(owner.operation_generation),
        static_cast<unsigned long long>(owner.registry_generation),
        owner.shared_owner_count,
        waiter_tool.c_str(),
        waiter_lane ? waiter_lane : "",
        static_cast<unsigned long long>(waiter_wait_ms),
        static_cast<unsigned long long>(waiter_budget_ms));
}

static bool active_session_owner_request_eviction(const active_session_owner_snapshot_t& owner, const char* reason)
{
    if (!owner.present || owner.token == 0)
        return false;
    bool was_cancelled = false;
    bool cancel_token_present = false;
    const bool signalled = mcp_lease_registry_signal_cancel(owner.token, owner.operation_generation, reason ? reason : "owner_eviction_requested", &was_cancelled, &cancel_token_present);
    mcp_lease_registry_mark_stale(owner.token, owner.operation_generation, reason ? reason : "owner_eviction_requested");
    {
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        auto& exclusive_owner = active_session_exclusive_owner();
        if (exclusive_owner.active && exclusive_owner.token == owner.token) {
            exclusive_owner.cancelled = true;
            exclusive_owner.stale = true;
            exclusive_owner.commit_eligible = false;
        }
        auto& shared_owners = active_session_shared_owners();
        for (auto& record : shared_owners) {
            if (record.active && record.token == owner.token) {
                record.cancelled = true;
                record.stale = true;
                record.commit_eligible = false;
            }
        }
    }
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lock_eviction_requested reason=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_request_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_target_pid=%u owner_session='%s' owner_target='%s' owner_age_ms=%llu owner_deadline_ms=%llu owner_phase=%s token=%llu operation_generation=%llu registry_generation=%llu cancel_token_present=%d signalled_now=%d already_cancelled=%d stale=1 commit_eligible=0 shared_owner_count=%zu",
        reason ? reason : "",
        owner.tool.c_str(),
        owner.lane.c_str(),
        owner.diag_id.c_str(),
        owner.request_id.c_str(),
        owner.exclusive ? "exclusive" : "shared",
        static_cast<unsigned long>(owner.pid),
        static_cast<unsigned long>(owner.tid),
        owner.target_pid,
        owner.session_id.c_str(),
        owner.target_id.c_str(),
        static_cast<unsigned long long>(owner.owner_age_ms),
        static_cast<unsigned long long>(owner.deadline_ms),
        owner.phase.c_str(),
        static_cast<unsigned long long>(owner.token),
        static_cast<unsigned long long>(owner.operation_generation),
        static_cast<unsigned long long>(owner.registry_generation),
        cancel_token_present ? 1 : 0,
        signalled ? 1 : 0,
        owner.cancelled || was_cancelled ? 1 : 0,
        owner.shared_owner_count);
    return signalled;
}

class active_session_owner_guard_t
{
public:
    active_session_owner_guard_t(const tool_def_t& tool,
                                 const json& arguments,
                                 const char* lane,
                                 bool exclusive,
                                 bool read_only,
                                 bool explicit_target,
                                 std::uint64_t pre_generated_token = 0,
                                 std::uint64_t pre_generated_deadline = 0,
                                 bool pre_generated_deadline_set = false)
        : tool_(sanitize_owner_field(tool.name))
        , lane_(sanitize_owner_field(lane ? lane : ""))
        , diag_id_(sanitize_owner_field(current_call_diag_id() ? current_call_diag_id() : ""))
        , request_id_(mcp_lease_request_id())
        , exclusive_(exclusive)
        , read_only_(read_only)
        , session_manager_(is_analysis_session_management_tool(tool.name))
        , mutating_(!read_only || is_analysis_session_management_tool(tool.name))
        , explicit_target_(explicit_target)
        , token_(pre_generated_token != 0 ? pre_generated_token : active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u)
        , acquired_ms_(mcp_now_ms())
        , deadline_ms_(pre_generated_deadline_set ? pre_generated_deadline : current_call_deadline_ms())
        , pid_(GetCurrentProcessId())
        , tid_(GetCurrentThreadId())
        , cancel_token_at_acquire_(current_cancel_token())
    {
        mcp_lease_registry_acquire_t lease_request = mcp_lease_acquire_request_for_tool(
            tool,
            arguments,
            lane_,
            read_only_,
            session_manager_,
            explicit_target_,
            token_,
            deadline_ms_,
            cancel_token_at_acquire_);
        lease_snapshot_ = mcp_lease_registry_acquire(lease_request);
        operation_generation_ = lease_snapshot_.operation_generation;
        registry_generation_ = lease_snapshot_.registry_generation;
        route_ = lease_snapshot_.route;
        transport_ = lease_snapshot_.transport;
        principal_bucket_ = lease_snapshot_.principal_bucket;
        session_id_ = lease_snapshot_.session_id;
        session_hash_ = lease_snapshot_.session_hash;
        target_id_ = lease_snapshot_.target_id;
        target_pid_ = lease_snapshot_.target_pid;
        priority_ = lease_snapshot_.priority;
        domain_ = lease_snapshot_.domain;
        domain_mutating_ = lease_snapshot_.domain_mutating;
        external_process_kind_ = lease_snapshot_.external_process_kind;
        external_process_pid_ = lease_snapshot_.external_process_pid;
        external_process_identity_ = lease_snapshot_.external_process_identity;
        external_process_session_ = lease_snapshot_.external_process_session;
        external_process_generation_ = lease_snapshot_.external_process_generation;
        external_expected_executable_path_ = lease_snapshot_.external_expected_executable_path;
        external_process_creation_time_100ns_ = lease_snapshot_.external_process_creation_time_100ns;
        external_sidecar_ownership_marker_ = lease_snapshot_.external_sidecar_ownership_marker;
        external_force_cleanup_eligible_ = lease_snapshot_.external_force_cleanup_eligible;
        record("acquired");
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_begin tool='%s' lane=%s mode=%s diag_id=%s request_id=%s generation=%llu registry_generation=%llu pid=%lu tid=%lu target_pid=%u session='%s' target='%s' priority=%s domain=%s deadline_ms=%llu cancelled=%d shared_owner_count=%zu token=%llu cancel_token_bound=%d commit_eligible=%d",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            request_id_.c_str(),
            static_cast<unsigned long long>(operation_generation_),
            static_cast<unsigned long long>(registry_generation_),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            target_pid_,
            session_id_.c_str(),
            target_id_.c_str(),
            priority_.c_str(),
            domain_.c_str(),
            static_cast<unsigned long long>(deadline_ms_),
            current_call_cancelled() ? 1 : 0,
            active_session_owner_snapshot().shared_owner_count,
            static_cast<unsigned long long>(token_),
            cancel_token_at_acquire_ ? 1 : 0,
            lease_snapshot_.commit_eligible ? 1 : 0);
    }

    active_session_owner_guard_t(const active_session_owner_guard_t&) = delete;
    active_session_owner_guard_t& operator=(const active_session_owner_guard_t&) = delete;

    ~active_session_owner_guard_t()
    {
        release("scope_exit");
    }

    void set_phase(const char* phase)
    {
        if (!active_)
            return;
        phase_ = sanitize_owner_field(phase ? phase : "");
        mcp_lease_registry_set_phase(token_, operation_generation_, phase_);
        mcp_lease_registry_snapshot_t snap;
        if (mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap))
            refresh_from_snapshot(snap);
        else if (snap.present)
            refresh_from_snapshot(snap);
        const std::uint64_t now_ms = mcp_now_ms();
        const std::uint64_t elapsed_ms = now_ms >= acquired_ms_ ? now_ms - acquired_ms_ : 0;
        const std::int64_t deadline_remaining_ms = deadline_ms_ == 0
            ? std::int64_t(0)
            : (static_cast<std::int64_t>(deadline_ms_) - static_cast<std::int64_t>(now_ms));
        {
            std::lock_guard<std::mutex> lk(active_session_owner_mutex());
            if (exclusive_) {
                auto& owner = active_session_exclusive_owner();
                if (owner.active && owner.token == token_) {
                    owner.phase = phase_;
                    owner.cancelled = current_call_cancelled();
                    owner.registry_generation = registry_generation_;
                    owner.operation_generation = operation_generation_;
                    owner.stale = stale_;
                    owner.fenced = fenced_;
                    owner.tombstoned = tombstoned_;
                    owner.released = released_;
                    owner.commit_eligible = commit_eligible_;
                }
            } else {
                auto& shared_owners = active_session_shared_owners();
                for (auto& owner : shared_owners) {
                    if (owner.active && owner.token == token_) {
                        owner.phase = phase_;
                        owner.cancelled = current_call_cancelled();
                        owner.registry_generation = registry_generation_;
                        owner.operation_generation = operation_generation_;
                        owner.stale = stale_;
                        owner.fenced = fenced_;
                        owner.tombstoned = tombstoned_;
                        owner.released = released_;
                        owner.commit_eligible = commit_eligible_;
                        break;
                    }
                }
            }
        }
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_owner_phase token=%llu generation=%llu registry_generation=%llu tool='%s' lane=%s mode=%s phase=%s elapsed_ms=%llu cancelled=%d stale=%d fenced=%d commit_eligible=%d deadline_remaining_ms=%lld diag_id=%s request_id=%s pid=%lu tid=%lu target_pid=%u session='%s' target='%s'",
            static_cast<unsigned long long>(token_),
            static_cast<unsigned long long>(operation_generation_),
            static_cast<unsigned long long>(registry_generation_),
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            phase_.c_str(),
            static_cast<unsigned long long>(elapsed_ms),
            current_call_cancelled() ? 1 : 0,
            stale_ ? 1 : 0,
            fenced_ ? 1 : 0,
            commit_eligible_ ? 1 : 0,
            static_cast<long long>(deadline_remaining_ms),
            diag_id_.c_str(),
            request_id_.c_str(),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            target_pid_,
            session_id_.c_str(),
            target_id_.c_str());
    }

    void set_lane(const char* lane)
    {
        if (!active_)
            return;
        lane_ = sanitize_owner_field(lane ? lane : "");
        mcp_lease_registry_set_lane(token_, operation_generation_, lane_);
        mcp_lease_registry_snapshot_t snap;
        if (mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap) || snap.present)
            refresh_from_snapshot(snap);
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        if (exclusive_) {
            auto& owner = active_session_exclusive_owner();
            if (owner.active && owner.token == token_) {
                owner.lane = lane_;
                owner.registry_generation = registry_generation_;
                owner.operation_generation = operation_generation_;
                owner.stale = stale_;
                owner.fenced = fenced_;
                owner.commit_eligible = commit_eligible_;
            }
            return;
        }
        auto& shared_owners = active_session_shared_owners();
        for (auto& owner : shared_owners) {
            if (owner.active && owner.token == token_) {
                owner.lane = lane_;
                owner.registry_generation = registry_generation_;
                owner.operation_generation = operation_generation_;
                owner.stale = stale_;
                owner.fenced = fenced_;
                owner.commit_eligible = commit_eligible_;
                return;
            }
        }
    }

    void note_seh(DWORD code, std::uint64_t elapsed_ms)
    {
        if (!active_)
            return;
        set_phase("handler_seh");
        const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_seh tool='%s' lane=%s mode=%s diag_id=%s code=0x%08lX elapsed_ms=%llu pid=%lu tid=%lu deadline_ms=%llu cancelled=%d owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu token=%llu",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            static_cast<unsigned long>(code),
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            static_cast<unsigned long long>(deadline_ms_),
            current_call_cancelled() ? 1 : 0,
            owner.tool.c_str(),
            owner.lane.c_str(),
            owner.diag_id.c_str(),
            static_cast<unsigned long>(owner.pid),
            static_cast<unsigned long>(owner.tid),
            static_cast<unsigned long long>(owner.owner_age_ms),
            owner.phase.c_str(),
            owner.shared_owner_count,
            static_cast<unsigned long long>(token_));
    }

    bool commit_eligible(const char* reason)
    {
        if (!active_)
            return false;
        mcp_lease_registry_snapshot_t snap;
        const bool eligible = mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap);
        if (snap.present)
            refresh_from_snapshot(snap);
        {
            std::lock_guard<std::mutex> lk(active_session_owner_mutex());
            if (exclusive_) {
                auto& owner = active_session_exclusive_owner();
                if (owner.active && owner.token == token_) {
                    owner.cancelled = current_call_cancelled() || cancellation_signalled_;
                    owner.stale = stale_;
                    owner.fenced = fenced_;
                    owner.tombstoned = tombstoned_;
                    owner.released = released_;
                    owner.commit_eligible = eligible;
                    owner.registry_generation = registry_generation_;
                    owner.operation_generation = operation_generation_;
                    owner.phase = phase_;
                }
            } else {
                auto& shared_owners = active_session_shared_owners();
                for (auto& owner : shared_owners) {
                    if (owner.active && owner.token == token_) {
                        owner.cancelled = current_call_cancelled() || cancellation_signalled_;
                        owner.stale = stale_;
                        owner.fenced = fenced_;
                        owner.tombstoned = tombstoned_;
                        owner.released = released_;
                        owner.commit_eligible = eligible;
                        owner.registry_generation = registry_generation_;
                        owner.operation_generation = operation_generation_;
                        owner.phase = phase_;
                        break;
                    }
                }
            }
        }
        if (!eligible) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_commit_ineligible reason=%s token=%llu generation=%llu registry_generation=%llu tool='%s' lane=%s diag_id=%s request_id=%s phase=%s cancelled=%d stale=%d fenced=%d tombstoned=%d released=%d pid=%lu tid=%lu target_pid=%u session='%s' target='%s'",
                reason ? reason : "",
                static_cast<unsigned long long>(token_),
                static_cast<unsigned long long>(operation_generation_),
                static_cast<unsigned long long>(registry_generation_),
                tool_.c_str(),
                lane_.c_str(),
                diag_id_.c_str(),
                request_id_.c_str(),
                phase_.c_str(),
                (current_call_cancelled() || cancellation_signalled_) ? 1 : 0,
                stale_ ? 1 : 0,
                fenced_ ? 1 : 0,
                tombstoned_ ? 1 : 0,
                released_ ? 1 : 0,
                static_cast<unsigned long>(pid_),
                static_cast<unsigned long>(tid_),
                target_pid_,
                session_id_.c_str(),
                target_id_.c_str());
        }
        return eligible;
    }

    void release(const char* reason)
    {
        if (!active_)
            return;
        mcp_lease_registry_snapshot_t release_snapshot;
        const bool eligible_before_release = mcp_lease_registry_commit_eligible(token_, operation_generation_, &release_snapshot);
        if (release_snapshot.present)
            refresh_from_snapshot(release_snapshot);
        const std::uint64_t elapsed_ms = mcp_now_ms() >= acquired_ms_ ? mcp_now_ms() - acquired_ms_ : 0;
        std::size_t shared_count = 0;
        bool exclusive_active = false;
        bool was_cancelled_record = false;
        {
            std::lock_guard<std::mutex> lk(active_session_owner_mutex());
            if (exclusive_) {
                auto& owner = active_session_exclusive_owner();
                if (owner.active && owner.token == token_) {
                    was_cancelled_record = owner.cancelled;
                    owner = {};
                }
            } else {
                auto& shared_owners = active_session_shared_owners();
                for (const auto& owner : shared_owners) {
                    if (owner.token == token_ && owner.cancelled) {
                        was_cancelled_record = true;
                        break;
                    }
                }
                shared_owners.erase(std::remove_if(shared_owners.begin(), shared_owners.end(),
                    [this](const active_session_owner_record_t& owner) {
                        return owner.token == token_;
                    }), shared_owners.end());
            }
            shared_count = active_session_shared_owners().size();
            exclusive_active = active_session_exclusive_owner().active;
        }
        mcp_lease_registry_release(token_, operation_generation_, reason ? reason : "scope_exit");
        const bool current_cancelled_flag = current_call_cancelled();
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_end tool='%s' lane=%s mode=%s diag_id=%s request_id=%s generation=%llu registry_generation=%llu reason=%s elapsed_ms=%llu pid=%lu tid=%lu target_pid=%u session='%s' target='%s' deadline_ms=%llu cancelled=%d stale=%d fenced=%d tombstoned=%d released=%d commit_eligible_before_release=%d phase=%s shared_owner_count=%zu exclusive_owner=%d token=%llu",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            request_id_.c_str(),
            static_cast<unsigned long long>(operation_generation_),
            static_cast<unsigned long long>(registry_generation_),
            reason ? reason : "",
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            target_pid_,
            session_id_.c_str(),
            target_id_.c_str(),
            static_cast<unsigned long long>(deadline_ms_),
            current_cancelled_flag ? 1 : 0,
            stale_ ? 1 : 0,
            fenced_ ? 1 : 0,
            tombstoned_ ? 1 : 0,
            released_ ? 1 : 0,
            eligible_before_release ? 1 : 0,
            phase_.c_str(),
            shared_count,
            exclusive_active ? 1 : 0,
            static_cast<unsigned long long>(token_));
        if (was_cancelled_record || current_cancelled_flag) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_hold_end_evicted tool='%s' lane=%s mode=%s diag_id=%s request_id=%s generation=%llu reason=%s elapsed_ms=%llu phase=%s pid=%lu tid=%lu deadline_ms=%llu owner_cancelled_record=%d current_cancelled=%d stale=%d fenced=%d commit_eligible_before_release=%d token=%llu",
                tool_.c_str(),
                lane_.c_str(),
                exclusive_ ? "exclusive" : "shared",
                diag_id_.c_str(),
                request_id_.c_str(),
                static_cast<unsigned long long>(operation_generation_),
                reason ? reason : "",
                static_cast<unsigned long long>(elapsed_ms),
                phase_.c_str(),
                static_cast<unsigned long>(pid_),
                static_cast<unsigned long>(tid_),
                static_cast<unsigned long long>(deadline_ms_),
                was_cancelled_record ? 1 : 0,
                current_cancelled_flag ? 1 : 0,
                stale_ ? 1 : 0,
                fenced_ ? 1 : 0,
                eligible_before_release ? 1 : 0,
                static_cast<unsigned long long>(token_));
        }
        if (exclusive_)
            active_session_lease_lock().release_exclusive(token_);
        else
            active_session_lease_lock().release_shared(token_);
        active_ = false;
    }

private:
    void refresh_from_snapshot(const mcp_lease_registry_snapshot_t& snap)
    {
        if (!snap.present || snap.lease_token != token_ || snap.operation_generation != operation_generation_)
            return;
        lease_snapshot_ = snap;
        registry_generation_ = snap.registry_generation;
        route_ = snap.route;
        transport_ = snap.transport;
        principal_bucket_ = snap.principal_bucket;
        session_id_ = snap.session_id;
        session_hash_ = snap.session_hash;
        target_id_ = snap.target_id;
        target_pid_ = snap.target_pid;
        lane_ = snap.lane.empty() ? lane_ : snap.lane;
        priority_ = snap.priority;
        domain_ = snap.domain;
        phase_ = snap.phase.empty() ? phase_ : snap.phase;
        cancellation_signalled_ = snap.cancellation_signalled;
        stale_ = snap.stale;
        fenced_ = snap.fenced;
        tombstoned_ = snap.tombstoned;
        released_ = snap.released;
        commit_eligible_ = snap.commit_eligible;
        external_process_kind_ = snap.external_process_kind;
        external_process_pid_ = snap.external_process_pid;
        external_process_identity_ = snap.external_process_identity;
        external_process_session_ = snap.external_process_session;
        external_process_generation_ = snap.external_process_generation;
        external_expected_executable_path_ = snap.external_expected_executable_path;
        external_process_creation_time_100ns_ = snap.external_process_creation_time_100ns;
        external_sidecar_ownership_marker_ = snap.external_sidecar_ownership_marker;
        external_force_cleanup_eligible_ = snap.external_force_cleanup_eligible;
    }

    void record(const char* phase)
    {
        phase_ = sanitize_owner_field(phase ? phase : "");
        active_session_owner_record_t record;
        record.active = true;
        record.exclusive = exclusive_;
        record.read_only = read_only_;
        record.explicit_target = explicit_target_;
        record.cancelled = current_call_cancelled();
        record.token = token_;
        record.acquired_ms = acquired_ms_;
        record.deadline_ms = deadline_ms_;
        record.pid = pid_;
        record.tid = tid_;
        record.tool = tool_;
        record.lane = lane_;
        record.diag_id = diag_id_;
        record.request_id = request_id_;
        record.route = route_;
        record.transport = transport_;
        record.principal_bucket = principal_bucket_;
        record.session_id = session_id_;
        record.session_hash = session_hash_;
        record.target_id = target_id_;
        record.priority = priority_;
        record.domain = domain_;
        record.phase = phase_;
        record.registry_generation = registry_generation_;
        record.operation_generation = operation_generation_;
        record.target_pid = target_pid_;
        record.mutating = mutating_;
        record.session_manager = session_manager_;
        record.domain_mutating = domain_mutating_;
        record.stale = stale_;
        record.fenced = fenced_;
        record.tombstoned = tombstoned_;
        record.released = released_;
        record.commit_eligible = commit_eligible_;
        record.external_process_kind = external_process_kind_;
        record.external_process_pid = external_process_pid_;
        record.external_process_identity = external_process_identity_;
        record.external_process_session = external_process_session_;
        record.external_process_generation = external_process_generation_;
        record.external_expected_executable_path = external_expected_executable_path_;
        record.external_process_creation_time_100ns = external_process_creation_time_100ns_;
        record.external_sidecar_ownership_marker = external_sidecar_ownership_marker_;
        record.external_force_cleanup_eligible = external_force_cleanup_eligible_;
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        if (exclusive_) {
            active_session_exclusive_owner() = std::move(record);
        } else {
            auto& shared_owners = active_session_shared_owners();
            if (shared_owners.size() < 64u) {
                shared_owners.push_back(std::move(record));
            } else {
                diag::log_tagged_fmt("mcp_srv",
                    "tool_policy_lock_owner_shared_overflow tool='%s' lane=%s diag_id=%s tid=%lu shared_owner_count=%zu",
                    tool_.c_str(),
                    lane_.c_str(),
                    diag_id_.c_str(),
                    static_cast<unsigned long>(tid_),
                    shared_owners.size());
            }
        }
        active_ = true;
    }

    std::string tool_;
    std::string lane_;
    std::string diag_id_;
    std::string request_id_;
    std::string route_;
    std::string transport_;
    std::string principal_bucket_;
    std::string session_id_;
    std::string session_hash_;
    std::string target_id_;
    std::string priority_;
    std::string domain_;
    std::string phase_;
    bool exclusive_ = false;
    bool read_only_ = false;
    bool mutating_ = false;
    bool session_manager_ = false;
    bool domain_mutating_ = false;
    bool explicit_target_ = false;
    bool active_ = false;
    bool cancellation_signalled_ = false;
    bool stale_ = false;
    bool fenced_ = false;
    bool tombstoned_ = false;
    bool released_ = false;
    bool commit_eligible_ = true;
    std::uint64_t token_ = 0;
    std::uint64_t registry_generation_ = 0;
    std::uint64_t operation_generation_ = 0;
    std::uint64_t acquired_ms_ = 0;
    std::uint64_t deadline_ms_ = 0;
    std::uint32_t target_pid_ = 0;
    DWORD pid_ = 0;
    DWORD tid_ = 0;
    std::atomic<bool>* cancel_token_at_acquire_ = nullptr;
    std::string external_process_kind_;
    std::uint32_t external_process_pid_ = 0;
    std::string external_process_identity_;
    std::string external_process_session_;
    std::uint64_t external_process_generation_ = 0;
    std::string external_expected_executable_path_;
    std::uint64_t external_process_creation_time_100ns_ = 0;
    std::string external_sidecar_ownership_marker_;
    bool external_force_cleanup_eligible_ = false;
    mcp_lease_registry_snapshot_t lease_snapshot_;
};

static bool tool_args_select_session_target(const json& args);

class mcp_operation_registry_scope_t
{
public:
    mcp_operation_registry_scope_t(const tool_def_t& tool,
                                   const json& arguments,
                                   const std::string& lane,
                                   bool read_only)
        : tool_(sanitize_owner_field(tool.name))
        , lane_(sanitize_owner_field(lane, 96))
        , diag_id_(sanitize_owner_field(current_call_diag_id() ? current_call_diag_id() : "", 160))
        , request_id_(mcp_lease_request_id())
        , token_(active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u)
        , acquired_ms_(mcp_now_ms())
        , deadline_ms_(current_call_deadline_ms())
    {
        const bool session_manager = is_analysis_session_management_tool(tool.name);
        mcp_lease_registry_acquire_t req = mcp_lease_acquire_request_for_tool(
            tool,
            arguments,
            lane_,
            read_only,
            session_manager,
            tool_args_select_session_target(arguments),
            token_,
            deadline_ms_,
            current_cancel_token());
        req.phase = "acquired";
        lease_snapshot_ = mcp_lease_registry_acquire(req);
        operation_generation_ = lease_snapshot_.operation_generation;
        registry_generation_ = lease_snapshot_.registry_generation;
        active_ = true;
    }

    mcp_operation_registry_scope_t(const mcp_operation_registry_scope_t&) = delete;
    mcp_operation_registry_scope_t& operator=(const mcp_operation_registry_scope_t&) = delete;

    ~mcp_operation_registry_scope_t()
    {
        release("scope_exit");
    }

    void set_phase(const char* phase)
    {
        if (!active_)
            return;
        phase_ = sanitize_owner_field(phase ? phase : "", 96);
        mcp_lease_registry_set_phase(token_, operation_generation_, phase_);
        mcp_lease_registry_snapshot_t snap;
        if (mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap) || snap.present)
            refresh_from_snapshot(snap);
        diag::log_tagged_fmt("mcp_srv",
            "MCP-LEASE-PHASE token=%llu generation=%llu registry_generation=%llu tool='%s' lane=%s phase=%s diag_id=%s request_id=%s cancelled=%d stale=%d fenced=%d commit_eligible=%d",
            static_cast<unsigned long long>(token_),
            static_cast<unsigned long long>(operation_generation_),
            static_cast<unsigned long long>(registry_generation_),
            tool_.c_str(),
            lane_.c_str(),
            phase_.c_str(),
            diag_id_.c_str(),
            request_id_.c_str(),
            current_call_cancelled() ? 1 : 0,
            stale_ ? 1 : 0,
            fenced_ ? 1 : 0,
            commit_eligible_ ? 1 : 0);
    }

    bool commit_eligible(const char* reason)
    {
        if (!active_)
            return false;
        mcp_lease_registry_snapshot_t snap;
        const bool eligible = mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap);
        if (snap.present)
            refresh_from_snapshot(snap);
        if (!eligible) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-LEASE-COMMIT-INELIGIBLE reason=%s token=%llu generation=%llu registry_generation=%llu tool='%s' lane=%s phase=%s diag_id=%s request_id=%s cancelled=%d stale=%d fenced=%d tombstoned=%d released=%d",
                reason ? reason : "",
                static_cast<unsigned long long>(token_),
                static_cast<unsigned long long>(operation_generation_),
                static_cast<unsigned long long>(registry_generation_),
                tool_.c_str(),
                lane_.c_str(),
                phase_.c_str(),
                diag_id_.c_str(),
                request_id_.c_str(),
                current_call_cancelled() ? 1 : 0,
                stale_ ? 1 : 0,
                fenced_ ? 1 : 0,
                tombstoned_ ? 1 : 0,
                released_ ? 1 : 0);
        }
        return eligible;
    }

    void release(const char* reason)
    {
        if (!active_)
            return;
        mcp_lease_registry_snapshot_t snap;
        if (mcp_lease_registry_commit_eligible(token_, operation_generation_, &snap) || snap.present)
            refresh_from_snapshot(snap);
        mcp_lease_registry_release(token_, operation_generation_, reason ? reason : "scope_exit");
        const std::uint64_t now = mcp_now_ms();
        diag::log_tagged_fmt("mcp_srv",
            "MCP-LEASE-SCOPE-END token=%llu generation=%llu registry_generation=%llu reason=%s tool='%s' lane=%s phase=%s diag_id=%s request_id=%s age_ms=%llu cancelled=%d stale=%d fenced=%d commit_eligible_before_release=%d",
            static_cast<unsigned long long>(token_),
            static_cast<unsigned long long>(operation_generation_),
            static_cast<unsigned long long>(registry_generation_),
            reason ? reason : "scope_exit",
            tool_.c_str(),
            lane_.c_str(),
            phase_.c_str(),
            diag_id_.c_str(),
            request_id_.c_str(),
            static_cast<unsigned long long>(now >= acquired_ms_ ? now - acquired_ms_ : 0),
            current_call_cancelled() ? 1 : 0,
            stale_ ? 1 : 0,
            fenced_ ? 1 : 0,
            commit_eligible_ ? 1 : 0);
        active_ = false;
    }

private:
    void refresh_from_snapshot(const mcp_lease_registry_snapshot_t& snap)
    {
        if (!snap.present || snap.lease_token != token_ || snap.operation_generation != operation_generation_)
            return;
        lease_snapshot_ = snap;
        registry_generation_ = snap.registry_generation;
        lane_ = snap.lane.empty() ? lane_ : snap.lane;
        phase_ = snap.phase.empty() ? phase_ : snap.phase;
        stale_ = snap.stale;
        fenced_ = snap.fenced;
        tombstoned_ = snap.tombstoned;
        released_ = snap.released;
        commit_eligible_ = snap.commit_eligible;
    }

    std::string tool_;
    std::string lane_;
    std::string diag_id_;
    std::string request_id_;
    std::string phase_ = "acquired";
    std::uint64_t token_ = 0;
    std::uint64_t operation_generation_ = 0;
    std::uint64_t registry_generation_ = 0;
    std::uint64_t acquired_ms_ = 0;
    std::uint64_t deadline_ms_ = 0;
    bool active_ = false;
    bool stale_ = false;
    bool fenced_ = false;
    bool tombstoned_ = false;
    bool released_ = false;
    bool commit_eligible_ = true;
    mcp_lease_registry_snapshot_t lease_snapshot_;
};

static std::mutex& domain_lane_mutex(const std::string& domain)
{
    static std::mutex map_mutex;
    static std::map<std::string, std::shared_ptr<std::mutex>> lanes;
    const std::string key = domain.empty() ? std::string("misc") : domain;
    std::lock_guard<std::mutex> lk(map_mutex);
    auto it = lanes.find(key);
    if (it != lanes.end())
        return *it->second;
    auto lane = std::make_shared<std::mutex>();
    auto* ptr = lane.get();
    lanes.emplace(key, std::move(lane));
    return *ptr;
}

struct tool_invocation_metrics_t
{
    std::string lane;
    std::uint64_t lock_wait_ms = 0;
    std::uint64_t handler_elapsed_ms = 0;
    bool resolved_target = false;
};

static json tool_diagnostics_json(
    std::uint64_t seq,
    const std::string& diag_id,
    const std::string& request_id,
    const std::string& tool_name,
    const std::string& domain,
    bool read_only,
    std::uint32_t target_pid,
    std::uint64_t timeout_ms,
    std::uint64_t deadline_ms,
    const std::string& payload_shape,
    const std::string& validation_status,
    const std::string& dependency_status,
    const tool_invocation_metrics_t& metrics,
    const std::shared_ptr<mcp_executor_task_meta_t>& meta,
    bool cancelled);

static void set_tool_metrics_lane(tool_invocation_metrics_t* metrics, const std::string& lane, std::uint64_t lock_wait_ms)
{
    if (!metrics)
        return;
    metrics->lane = lane;
    metrics->lock_wait_ms += lock_wait_ms;
}

enum class policy_lock_status_t
{
    acquired,
    cancelled,
    busy
};

struct policy_lock_wait_t
{
    policy_lock_status_t status = policy_lock_status_t::busy;
    std::uint64_t wait_ms = 0;
    bool eviction_requested = false;
    bool owner_deadline_expired = false;
    std::uint64_t owner_age_over_deadline_ms = 0;
    active_session_owner_snapshot_t owner;
};

static std::uint64_t policy_lock_wait_budget_ms()
{
    const std::uint64_t now = mcp_now_ms();
    const std::uint64_t deadline = current_call_deadline_ms();
    if (deadline != 0 && deadline > now)
        return std::min<std::uint64_t>(kMcpPolicyLockMaxWaitMs, deadline - now);
    if (deadline != 0 && deadline <= now)
        return 0;
    return kMcpPolicyLockMaxWaitMs;
}

template <typename Lock, typename TryLockFn>
static policy_lock_wait_t wait_policy_lock(Lock& lock,
                                           TryLockFn&& try_lock,
                                           const std::string& tool_name,
                                           const char* lane,
                                           const char* mode,
                                           bool read_only,
                                           bool explicit_target)
{
    const std::uint64_t started = mcp_now_ms();
    const std::uint64_t budget = policy_lock_wait_budget_ms();
    std::uint64_t last_log = started;
    bool eviction_requested = false;
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lock_wait_begin tool='%s' lane=%s mode=%s read_only=%d explicit_target=%d budget_ms=%llu diag_id=%s",
        tool_name.c_str(),
        lane ? lane : "",
        mode ? mode : "",
        read_only ? 1 : 0,
        explicit_target ? 1 : 0,
        static_cast<unsigned long long>(budget),
        current_call_diag_id());

    for (;;)
    {
        if (try_lock(lock))
        {
            const std::uint64_t waited = mcp_now_ms() - started;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_acquired tool='%s' lane=%s mode=%s wait_ms=%llu diag_id=%s eviction_requested=%d",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_diag_id(),
                eviction_requested ? 1 : 0);
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::acquired;
            result.wait_ms = waited;
            result.eviction_requested = eviction_requested;
            return result;
        }

        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t waited = now >= started ? now - started : 0;

        if (!eviction_requested) {
            const active_session_owner_snapshot_t owner_for_evict = active_session_owner_snapshot();
            if (owner_for_evict.present && owner_for_evict.deadline_ms != 0 &&
                now >= owner_for_evict.deadline_ms &&
                (!owner_for_evict.cancelled || !owner_for_evict.stale || owner_for_evict.commit_eligible)) {
                active_session_owner_request_eviction(owner_for_evict, "owner_deadline_expired");
                eviction_requested = true;
            }
        }

        if (current_call_cancelled())
        {
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_cancelled tool='%s' lane=%s mode=%s wait_ms=%llu diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu eviction_requested=%d",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                owner.phase.c_str(),
                owner.shared_owner_count,
                eviction_requested ? 1 : 0);
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::cancelled;
            result.wait_ms = waited;
            result.eviction_requested = eviction_requested;
            result.owner = owner;
            result.owner_deadline_expired = owner.present && owner.deadline_ms != 0 && now >= owner.deadline_ms;
            if (owner.present && owner.deadline_ms != 0 && owner.acquired_ms != 0 && owner.deadline_ms >= owner.acquired_ms) {
                const std::uint64_t owner_budget = owner.deadline_ms - owner.acquired_ms;
                if (owner.owner_age_ms > owner_budget)
                    result.owner_age_over_deadline_ms = owner.owner_age_ms - owner_budget;
            }
            return result;
        }

        const std::uint64_t deadline = current_call_deadline_ms();
        if ((budget == 0 || waited >= budget) || (deadline != 0 && now >= deadline))
        {
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            const bool owner_deadline_expired_now = owner.present && owner.deadline_ms != 0 && now >= owner.deadline_ms;
            std::uint64_t owner_age_over_deadline = 0;
            if (owner.present && owner.deadline_ms != 0 && owner.acquired_ms != 0 && owner.deadline_ms >= owner.acquired_ms) {
                const std::uint64_t owner_budget = owner.deadline_ms - owner.acquired_ms;
                if (owner.owner_age_ms > owner_budget)
                    owner_age_over_deadline = owner.owner_age_ms - owner_budget;
            }
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_busy tool='%s' lane=%s mode=%s wait_ms=%llu budget_ms=%llu diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s shared_owner_count=%zu eviction_requested=%d owner_deadline_expired=%d owner_age_over_deadline_ms=%llu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                static_cast<unsigned long long>(budget),
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                static_cast<unsigned long long>(owner.deadline_ms),
                owner.cancelled ? 1 : 0,
                owner.phase.c_str(),
                owner.shared_owner_count,
                eviction_requested ? 1 : 0,
                owner_deadline_expired_now ? 1 : 0,
                static_cast<unsigned long long>(owner_age_over_deadline));
            log_active_session_owner_stale_if_needed(owner, "wait_busy", tool_name, lane, waited, budget);
            mcp_lease_record_lock_conflict(lane ? lane : "");
            diag::log_tagged_fmt("mcp_srv",
                "MCP-LOCK-CONFLICT waiter_tool='%s' waiter_lane=%s waiter_mode=%s waiter_wait_ms=%llu waiter_budget_ms=%llu waiter_diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s owner_token=%llu owner_operation_generation=%llu owner_registry_generation=%llu owner_commit_eligible=%d shared_owner_count=%zu eviction_requested=%d owner_deadline_expired=%d owner_age_over_deadline_ms=%llu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                static_cast<unsigned long long>(budget),
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                static_cast<unsigned long long>(owner.deadline_ms),
                owner.cancelled ? 1 : 0,
                owner.phase.c_str(),
                static_cast<unsigned long long>(owner.token),
                static_cast<unsigned long long>(owner.operation_generation),
                static_cast<unsigned long long>(owner.registry_generation),
                owner.commit_eligible ? 1 : 0,
                owner.shared_owner_count,
                eviction_requested ? 1 : 0,
                owner_deadline_expired_now ? 1 : 0,
                static_cast<unsigned long long>(owner_age_over_deadline));
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::busy;
            result.wait_ms = waited;
            result.eviction_requested = eviction_requested;
            result.owner = owner;
            result.owner_deadline_expired = owner_deadline_expired_now;
            result.owner_age_over_deadline_ms = owner_age_over_deadline;
            return result;
        }

        if (now - last_log >= kMcpPolicyLockLogEveryMs)
        {
            last_log = now;
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_state tool='%s' lane=%s mode=%s wait_ms=%llu cancelled=%d diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s shared_owner_count=%zu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_cancelled() ? 1 : 0,
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                static_cast<unsigned long long>(owner.deadline_ms),
                owner.cancelled ? 1 : 0,
                owner.phase.c_str(),
                owner.shared_owner_count);
            log_active_session_owner_stale_if_needed(owner, "wait_state", tool_name, lane, waited, budget);
        }
        Sleep(static_cast<DWORD>(kMcpPolicyLockPollMs));
    }
}

static policy_lock_wait_t acquire_policy_unique_lock(active_session_lease_lock_t& lock,
                                                     const std::string& tool_name,
                                                     const char* lane,
                                                     bool read_only,
                                                     bool explicit_target,
                                                     std::uint64_t token)
{
    return wait_policy_lock(lock,
        [token](active_session_lease_lock_t& l) { return l.try_acquire_exclusive(token); },
        tool_name,
        lane,
        "exclusive",
        read_only,
        explicit_target);
}

static policy_lock_wait_t acquire_policy_shared_lock(active_session_lease_lock_t& lock,
                                                     const std::string& tool_name,
                                                     const char* lane,
                                                     bool explicit_target,
                                                     std::uint64_t token)
{
    return wait_policy_lock(lock,
        [token](active_session_lease_lock_t& l) { return l.try_acquire_shared(token); },
        tool_name,
        lane,
        "shared",
        true,
        explicit_target);
}

static const char* policy_lock_status_name(policy_lock_status_t status)
{
    switch (status) {
    case policy_lock_status_t::acquired: return "acquired";
    case policy_lock_status_t::cancelled: return "cancelled";
    case policy_lock_status_t::busy: return "busy";
    }
    return "busy";
}

static std::string policy_lane_class_name(const std::string& tool_name, const char* lane)
{
    (void)tool_name;
    const std::string l = lower_ascii(lane ? lane : "");
    if (l == "shared_active")
        return "shared_active_session_read";
    if (l == "exclusive_session_manager")
        return "exclusive_session_manager";
    if (l == "exclusive_mutating")
        return "exclusive_mutating";
    if (l == "independent_unlocked" || l == "self_contained_unlocked")
        return "independent_read_only";
    if (l == "exclusive_independent_mutating" || l.rfind("exclusive_domain_", 0) == 0)
        return "independent_domain_mutating";
    return l.empty() ? std::string("unclassified") : l;
}

static std::string policy_tool_class_name(const std::string& tool_name)
{
    const std::string name = lower_ascii(tool_name);
    const std::string domain = infer_tool_domain(tool_name);
    if (is_camoufox_browser_tool_name(tool_name))
        return "browser_camoufox_long_operation";
    if (name == "run_command")
        return "background_command";
    if (domain == "debugger" || domain == "driver" || name.rfind("dbg_", 0) == 0 || name.rfind("driver_", 0) == 0 || name.rfind("thread_", 0) == 0)
        return "driver_debugger_target";
    if (domain.empty())
        return "general_tool";
    return domain;
}

static const char* policy_conflict_disposition(policy_lock_status_t status)
{
    return status == policy_lock_status_t::cancelled ? "cancelled" : "busy";
}

static std::string policy_conflict_rule_for_lane(const char* lane)
{
    const std::string l = lower_ascii(lane ? lane : "");
    if (l == "independent_unlocked" || l == "self_contained_unlocked")
        return "no_active_session_lock";
    if (l.rfind("exclusive_domain_", 0) == 0 || l == "exclusive_independent_mutating")
        return "bounded_domain_mutex_no_ui_wait";
    if (l == "shared_active")
        return "bounded_wait_on_exclusive_owner_no_expired_steal";
    if (l == "exclusive_session_manager" || l == "exclusive_mutating")
        return "bounded_wait_signal_stale_owner_no_expired_steal";
    return "bounded_policy_wait_no_expired_steal";
}

static policy_lock_wait_t acquire_domain_policy_lock(std::unique_lock<std::mutex>& lk,
                                                     const std::string& tool_name,
                                                     const std::string& lane,
                                                     const std::string& domain,
                                                     bool read_only,
                                                     bool explicit_target)
{
    const std::uint64_t started = mcp_now_ms();
    const std::uint64_t budget = policy_lock_wait_budget_ms();
    std::uint64_t last_log = started;
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_domain_lock_wait_begin tool='%s' lane=%s domain=%s read_only=%d explicit_target=%d budget_ms=%llu diag_id=%s",
        tool_name.c_str(),
        lane.c_str(),
        domain.c_str(),
        read_only ? 1 : 0,
        explicit_target ? 1 : 0,
        static_cast<unsigned long long>(budget),
        current_call_diag_id());
    for (;;) {
        if (lk.try_lock()) {
            const std::uint64_t waited = mcp_now_ms() - started;
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::acquired;
            result.wait_ms = waited;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_domain_lock_wait_acquired tool='%s' lane=%s domain=%s wait_ms=%llu diag_id=%s",
                tool_name.c_str(),
                lane.c_str(),
                domain.c_str(),
                static_cast<unsigned long long>(waited),
                current_call_diag_id());
            return result;
        }
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t waited = now >= started ? now - started : 0;
        if (current_call_cancelled()) {
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::cancelled;
            result.wait_ms = waited;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_domain_lock_wait_cancelled tool='%s' lane=%s domain=%s wait_ms=%llu diag_id=%s",
                tool_name.c_str(),
                lane.c_str(),
                domain.c_str(),
                static_cast<unsigned long long>(waited),
                current_call_diag_id());
            return result;
        }
        const std::uint64_t deadline = current_call_deadline_ms();
        if ((budget == 0 || waited >= budget) || (deadline != 0 && now >= deadline)) {
            policy_lock_wait_t result;
            result.status = policy_lock_status_t::busy;
            result.wait_ms = waited;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_domain_lock_wait_busy tool='%s' lane=%s domain=%s wait_ms=%llu budget_ms=%llu diag_id=%s",
                tool_name.c_str(),
                lane.c_str(),
                domain.c_str(),
                static_cast<unsigned long long>(waited),
                static_cast<unsigned long long>(budget),
                current_call_diag_id());
            return result;
        }
        if (now - last_log >= kMcpPolicyLockLogEveryMs) {
            last_log = now;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_domain_lock_wait_state tool='%s' lane=%s domain=%s wait_ms=%llu cancelled=%d diag_id=%s",
                tool_name.c_str(),
                lane.c_str(),
                domain.c_str(),
                static_cast<unsigned long long>(waited),
                current_call_cancelled() ? 1 : 0,
                current_call_diag_id());
        }
        Sleep(static_cast<DWORD>(kMcpPolicyLockPollMs));
    }
}

static tool_result_t policy_lock_error_result(const std::string& tool_name,
                                              const char* lane,
                                              const policy_lock_wait_t& wait)
{
    const active_session_owner_snapshot_t owner = wait.owner;
    const char* status_name = policy_lock_status_name(wait.status);
    json details = {
        {"tool", tool_name},
        {"lane", lane ? lane : ""},
        {"lane_class", policy_lane_class_name(tool_name, lane)},
        {"tool_class", policy_tool_class_name(tool_name)},
        {"conflict_policy", policy_conflict_rule_for_lane(lane)},
        {"policy_status", status_name},
        {"disposition", policy_conflict_disposition(wait.status)},
        {"late_result_disposition", "not_started"},
        {"work_started", false},
        {"ui_thread_blocking_wait", false},
        {"lock_wait_ms", wait.wait_ms},
        {"diagnostic_id", current_call_diag_id()},
        {"request_id", current_call_request_id()},
        {"cancelled", wait.status == policy_lock_status_t::cancelled},
        {"busy", wait.status == policy_lock_status_t::busy},
        {"owner_eviction_requested", wait.eviction_requested},
        {"owner_deadline_expired", wait.owner_deadline_expired},
        {"owner_age_over_deadline_ms", wait.owner_age_over_deadline_ms}
    };
    append_active_session_owner_fields(details, owner);
    if (wait.status == policy_lock_status_t::cancelled) {
        if (owner.present)
            return tool_result_t::error("MCP tool call cancelled while waiting for active-session policy lock.", "cancelled", details);
        return tool_result_t::error("MCP tool call cancelled while waiting for policy lane.", "cancelled", details);
    }
    if (owner.present)
        return tool_result_t::error("MCP active-session policy lock is busy; a prior tool is still draining.", "busy", details);
    return tool_result_t::error("MCP tool policy lane is busy; a conflicting tool is still draining.", "busy", details);
}

static json mcp_late_result_evidence_json(const mcp_lease_registry_snapshot_t& snap,
                                          const char* reason,
                                          const char* disposition,
                                          const char* path,
                                          std::uint64_t expected_generation,
                                          std::uint64_t expected_registry_generation = 0)
{
    json out;
    out["late_result"] = true;
    out["reason"] = reason ? reason : "";
    out["disposition"] = disposition ? disposition : "";
    out["path"] = path ? path : "";
    out["lease_token"] = snap.lease_token;
    out["registry_generation"] = snap.registry_generation;
    out["operation_generation"] = snap.operation_generation;
    out["expected_operation_generation"] = expected_generation;
    out["expected_registry_generation"] = expected_registry_generation;
    out["operation_generation_match"] = expected_generation == 0 || snap.operation_generation == expected_generation;
    out["registry_generation_match"] = expected_registry_generation == 0 || snap.registry_generation == expected_registry_generation;
    out["diagnostic_id"] = snap.diagnostic_id;
    out["request_id"] = snap.request_id;
    out["tool"] = snap.tool;
    out["route"] = snap.route;
    out["transport"] = snap.transport;
    out["principal_bucket"] = snap.principal_bucket;
    out["session_id"] = snap.session_id;
    out["session_hash"] = snap.session_hash;
    out["target_id"] = snap.target_id;
    out["target_pid"] = snap.target_pid;
    out["lane"] = snap.lane;
    out["priority"] = snap.priority;
    out["read_only"] = snap.read_only;
    out["mutating"] = snap.mutating;
    out["session_manager"] = snap.session_manager;
    out["domain_mutating"] = snap.domain_mutating;
    out["domain"] = snap.domain;
    out["phase"] = snap.phase;
    out["process_pid"] = snap.process_pid;
    out["worker_tid"] = snap.worker_tid;
    out["started_ms"] = snap.started_ms;
    out["owner_age_ms"] = snap.owner_age_ms;
    out["deadline_ms"] = snap.deadline_ms;
    out["cancellation_signalled"] = snap.cancellation_signalled;
    out["stale"] = snap.stale;
    out["fenced"] = snap.fenced;
    out["tombstoned"] = snap.tombstoned;
    out["released"] = snap.released;
    out["commit_eligible"] = snap.commit_eligible;
    out["phase_commit_eligible"] = snap.commit_eligible && !snap.cancellation_signalled && !snap.stale && !snap.fenced && !snap.tombstoned && !snap.released;
    out["external_process_kind"] = snap.external_process_kind;
    out["external_process_pid"] = snap.external_process_pid;
    out["external_process_identity"] = snap.external_process_identity;
    out["external_process_session"] = snap.external_process_session;
    out["external_process_generation"] = snap.external_process_generation;
    out["external_expected_executable_path"] = snap.external_expected_executable_path;
    out["external_process_creation_time_100ns"] = snap.external_process_creation_time_100ns;
    out["external_sidecar_ownership_marker"] = snap.external_sidecar_ownership_marker;
    out["external_force_cleanup_eligible"] = snap.external_force_cleanup_eligible;
    return out;
}

static void mcp_log_late_result_discarded(const json& evidence)
{
    mcp_lease_late_result_discard_count().fetch_add(1u, std::memory_order_acq_rel);
    diag::log_tagged_fmt("mcp_srv",
        "MCP-LATE-RESULT-DISCARDED reason=%s disposition=%s path=%s tool='%s' diag_id=%s request_id='%s' lease_token=%llu registry_generation=%llu expected_registry_generation=%llu operation_generation=%llu expected_operation_generation=%llu registry_generation_match=%d operation_generation_match=%d phase=%s phase_commit_eligible=%d session_id='%s' session_hash=%s target_id='%s' target_pid=%u cancelled=%d stale=%d fenced=%d tombstoned=%d released=%d commit_eligible=%d",
        evidence.value("reason", std::string()).c_str(),
        evidence.value("disposition", std::string()).c_str(),
        evidence.value("path", std::string()).c_str(),
        evidence.value("tool", std::string()).c_str(),
        evidence.value("diagnostic_id", std::string()).c_str(),
        evidence.value("request_id", std::string()).c_str(),
        static_cast<unsigned long long>(evidence.value("lease_token", 0ull)),
        static_cast<unsigned long long>(evidence.value("registry_generation", 0ull)),
        static_cast<unsigned long long>(evidence.value("expected_registry_generation", 0ull)),
        static_cast<unsigned long long>(evidence.value("operation_generation", 0ull)),
        static_cast<unsigned long long>(evidence.value("expected_operation_generation", 0ull)),
        evidence.value("registry_generation_match", false) ? 1 : 0,
        evidence.value("operation_generation_match", false) ? 1 : 0,
        evidence.value("phase", std::string()).c_str(),
        evidence.value("phase_commit_eligible", false) ? 1 : 0,
        evidence.value("session_id", std::string()).c_str(),
        evidence.value("session_hash", std::string()).c_str(),
        evidence.value("target_id", std::string()).c_str(),
        static_cast<unsigned>(evidence.value("target_pid", 0u)),
        evidence.value("cancellation_signalled", false) ? 1 : 0,
        evidence.value("stale", false) ? 1 : 0,
        evidence.value("fenced", false) ? 1 : 0,
        evidence.value("tombstoned", false) ? 1 : 0,
        evidence.value("released", false) ? 1 : 0,
        evidence.value("commit_eligible", false) ? 1 : 0);
}

static tool_result_t mcp_late_result_error_result(const json& evidence)
{
    return tool_result_t::error("MCP late tool result was fenced and discarded before delivery.", "MCP_LATE_RESULT_DISCARDED", evidence);
}

class mcp_broker_delivery_fence_t
{
public:
    mcp_broker_delivery_fence_t(const tool_def_t& tool,
                                const json& arguments,
                                const std::string& lane,
                                bool explicit_target,
                                std::uint64_t deadline_ms,
                                std::atomic<bool>* cancel_token,
                                const std::string& diagnostic_id,
                                const std::string& request_id)
        : token_(active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u)
    {
        mcp_lease_registry_acquire_t req = mcp_lease_acquire_request_for_tool(
            tool,
            arguments,
            lane,
            tool.read_only,
            is_analysis_session_management_tool(tool.name),
            explicit_target,
            token_,
            deadline_ms,
            cancel_token);
        req.diagnostic_id = sanitize_owner_field(diagnostic_id, 160);
        req.request_id = sanitize_owner_field(request_id, 160);
        req.phase = "broker_queued";
        snapshot_ = mcp_lease_registry_acquire(req);
        generation_ = snapshot_.operation_generation;
        registry_generation_ = snapshot_.registry_generation;
        expected_session_id_ = snapshot_.session_id;
        expected_session_hash_ = snapshot_.session_hash;
        expected_target_id_ = snapshot_.target_id;
        expected_target_pid_ = snapshot_.target_pid;
        active_ = snapshot_.present;
    }

    ~mcp_broker_delivery_fence_t()
    {
        release("broker_fence_scope_exit");
    }

    mcp_broker_delivery_fence_t(const mcp_broker_delivery_fence_t&) = delete;
    mcp_broker_delivery_fence_t& operator=(const mcp_broker_delivery_fence_t&) = delete;

    void set_phase(const char* phase)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_)
            return;
        mcp_lease_registry_snapshot_t snap;
        const bool updated = mcp_lease_registry_set_phase_checked(token_, generation_, registry_generation_, phase ? phase : "", &snap);
        if (snap.present) {
            snapshot_ = snap;
            if (updated)
                registry_generation_ = snap.registry_generation;
        }
    }

    json mark_timeout(const char* reason, const char* disposition)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_)
            return json::object();
        mcp_lease_registry_signal_cancel(token_, generation_, reason ? reason : "timeout");
        mcp_lease_registry_mark_stale(token_, generation_, reason ? reason : "timeout");
        mcp_lease_registry_fence(token_, generation_, reason ? reason : "timeout");
        mcp_lease_registry_set_phase(token_, generation_, "timed_out");
        mcp_lease_registry_snapshot_t snap;
        (void)mcp_lease_registry_commit_eligible(token_, generation_, &snap);
        if (snap.present) {
            snapshot_ = snap;
            registry_generation_ = snap.registry_generation;
        }
        json evidence = mcp_late_result_evidence_json(snapshot_, reason ? reason : "timeout", disposition ? disposition : "fenced_after_timeout", "timeout", generation_, registry_generation_);
        return evidence;
    }

    bool validate_handler_return(const char* path, json* evidence)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_)
            return true;
        mcp_lease_registry_snapshot_t snap;
        const bool phase_updated = mcp_lease_registry_set_phase_checked(token_, generation_, registry_generation_, "handler_returned", &snap);
        const bool eligible = phase_updated && mcp_lease_registry_commit_eligible(token_, generation_, &snap);
        if (snap.present) {
            snapshot_ = snap;
            if (phase_updated)
                registry_generation_ = snap.registry_generation;
        }
        if (!eligible || !context_matches(snapshot_, "handler_returned")) {
            json local = mcp_late_result_evidence_json(snapshot_, "handler_return_ineligible", late_disposition(), path ? path : "handler_returned", generation_, registry_generation_);
            if (evidence)
                *evidence = local;
            mcp_log_late_result_discarded(local);
            release_locked("handler_return_discarded");
            return false;
        }
        if (evidence)
            *evidence = mcp_late_result_evidence_json(snapshot_, "validated", "handler_return_valid", path ? path : "handler_returned", generation_, registry_generation_);
        return true;
    }

    bool claim_delivery(const char* path, json* evidence)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_)
            return true;
        mcp_lease_registry_snapshot_t snap;
        const bool phase_updated = mcp_lease_registry_set_phase_checked(token_, generation_, registry_generation_, "delivery_commit", &snap);
        const bool eligible = phase_updated && mcp_lease_registry_commit_eligible(token_, generation_, &snap);
        if (snap.present) {
            snapshot_ = snap;
            if (phase_updated)
                registry_generation_ = snap.registry_generation;
        }
        const bool context_ok = context_matches(snapshot_, "delivery_commit");
        json local = mcp_late_result_evidence_json(snapshot_,
            eligible && context_ok ? "validated" : "delivery_ineligible",
            eligible && context_ok ? "delivered" : late_disposition(),
            path ? path : "delivery",
            generation_,
            registry_generation_);
        if (evidence)
            *evidence = local;
        if (!eligible || !context_ok) {
            mcp_log_late_result_discarded(local);
            release_locked("delivery_discarded");
            return false;
        }
        release_locked("delivery_committed");
        return true;
    }

    void release(const char* reason)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        release_locked(reason);
    }

    mcp_lease_registry_snapshot_t snapshot() const
    {
        std::lock_guard<std::mutex> lk(mtx_);
        return snapshot_;
    }

    std::uint64_t token() const noexcept
    {
        return token_;
    }

    std::uint64_t generation() const noexcept
    {
        return generation_;
    }

private:
    void release_locked(const char* reason)
    {
        if (!active_)
            return;
        mcp_lease_registry_release(token_, generation_, reason ? reason : "broker_delivery_fence_release");
        active_ = false;
    }

    bool context_matches(const mcp_lease_registry_snapshot_t& snap, const char* expected_phase) const
    {
        if (!snap.present)
            return false;
        if (snap.lease_token != token_ || snap.operation_generation != generation_)
            return false;
        if (snap.session_id != expected_session_id_ || snap.session_hash != expected_session_hash_ || snap.target_id != expected_target_id_)
            return false;
        if (expected_target_pid_ != 0 && snap.target_pid != expected_target_pid_)
            return false;
        if (expected_phase && *expected_phase && snap.phase != expected_phase)
            return false;
        return true;
    }

    const char* late_disposition() const
    {
        if (snapshot_.fenced)
            return snapshot_.cancellation_signalled ? "fenced_after_timeout" : "fenced_late_result";
        if (snapshot_.stale || snapshot_.tombstoned || snapshot_.released)
            return "discarded_late_result";
        if (snapshot_.cancellation_signalled)
            return "cancelled_before_delivery";
        return "discarded_late_result";
    }

    std::uint64_t token_ = 0;
    std::uint64_t generation_ = 0;
    std::uint64_t registry_generation_ = 0;
    std::string expected_session_id_;
    std::string expected_session_hash_;
    std::string expected_target_id_;
    std::uint32_t expected_target_pid_ = 0;
    bool active_ = false;
    mcp_lease_registry_snapshot_t snapshot_;
    mutable std::mutex mtx_;
};

static bool tool_args_select_session_target(const json& args)
{
    if (!args.is_object())
        return false;
    static const char* const keys[] = {
        "binary_id", "session_id", "bin_name", "file_path", "target_pid", "process_id", "pid"
    };
    for (const char* key : keys) {
        if (args.contains(key) && !args[key].is_null())
            return true;
    }
    return false;
}

static bool tool_declares_param_named(const tool_def_t& tool, const char* name)
{
    for (const auto& param : tool.params) {
        if (param.name == name)
            return true;
    }
    return false;
}

static const json& target_resolution_args_for_tool(const tool_def_t& tool, const json& arguments, json& storage, bool emit_log)
{
    if (!arguments.is_object() ||
        !tool_declares_param_named(tool, "session_id") ||
        !arguments.contains("session_id") ||
        arguments.contains("binary_id")) {
        return arguments;
    }

    std::size_t session_id_len = 0;
    const auto it = arguments.find("session_id");
    if (it != arguments.end() && it->is_string())
        session_id_len = it->get<std::string>().size();

    storage = arguments;
    storage.erase("session_id");
    if (emit_log) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_target_args local_session_id tool='%s' session_id_len=%zu binary_id_present=0",
            tool.name.c_str(),
            session_id_len);
    }
    return storage;
}

struct workspace_resolution_t
{
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::string code;
    std::string message;
    json details = json::object();
};

static std::mutex& workspace_policy_map_mutex()
{
    static std::mutex value;
    return value;
}

static std::map<std::string, std::weak_ptr<std::shared_timed_mutex>>& workspace_policy_map()
{
    static std::map<std::string, std::weak_ptr<std::shared_timed_mutex>> value;
    return value;
}

static std::shared_ptr<std::shared_timed_mutex> workspace_policy_mutex(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    const std::string key = workspace->identity().binary_id().to_hex();
    std::lock_guard<std::mutex> lock(workspace_policy_map_mutex());
    auto& policies = workspace_policy_map();
    if (policies.size() > 256) {
        for (auto iterator = policies.begin(); iterator != policies.end();) {
            if (iterator->second.expired())
                iterator = policies.erase(iterator);
            else
                ++iterator;
        }
    }
    auto& weak = policies[key];
    auto value = weak.lock();
    if (!value) {
        value = std::make_shared<std::shared_timed_mutex>();
        weak = value;
    }
    return value;
}

static bool parse_workspace_pid(const json& value, std::uint32_t& pid)
{
    std::uint64_t parsed = 0;
    if (value.is_number_unsigned()) {
        parsed = value.get<std::uint64_t>();
    } else if (value.is_number_integer()) {
        const std::int64_t signed_value = value.get<std::int64_t>();
        if (signed_value <= 0)
            return false;
        parsed = static_cast<std::uint64_t>(signed_value);
    } else if (value.is_string()) {
        const std::string text = value.get<std::string>();
        if (text.empty())
            return false;
        try {
            std::size_t consumed = 0;
            parsed = std::stoull(text, &consumed, 0);
            if (consumed != text.size())
                return false;
        } catch (...) {
            return false;
        }
    } else {
        return false;
    }
    if (parsed == 0 || parsed > std::numeric_limits<std::uint32_t>::max())
        return false;
    pid = static_cast<std::uint32_t>(parsed);
    return true;
}

static workspace_resolution_t workspace_resolution_error(
    const aida::analysis::workspace_error_t& error)
{
    workspace_resolution_t result;
    result.code = error.stable_code();
    result.message = error.message;
    result.details["phase"] = error.phase;
    if (error.offset)
        result.details["offset"] = *error.offset;
    if (error.size)
        result.details["size"] = *error.size;
    for (const auto& detail : error.details)
        result.details[detail.first] = detail.second;
    return result;
}

static workspace_resolution_t resolve_workspace_direct(const json& args)
{
    using namespace aida::analysis;
    target_selector_t selector;
    const bool object = args.is_object();
    const bool has_binary = object && args.contains("binary_id") && !args["binary_id"].is_null();
    const bool has_session = object && args.contains("session_id") && !args["session_id"].is_null();
    const bool has_name = object && args.contains("bin_name") && !args["bin_name"].is_null();
    const bool has_path = object && args.contains("file_path") && !args["file_path"].is_null();
    const unsigned pid_alias_count = object
        ? static_cast<unsigned>(args.contains("pid") && !args["pid"].is_null()) +
          static_cast<unsigned>(args.contains("target_pid") && !args["target_pid"].is_null()) +
          static_cast<unsigned>(args.contains("process_id") && !args["process_id"].is_null())
        : 0;
    const bool has_pid = object && ((args.contains("pid") && !args["pid"].is_null()) ||
        (args.contains("target_pid") && !args["target_pid"].is_null()) ||
        (args.contains("process_id") && !args["process_id"].is_null()));
    const unsigned selector_count = static_cast<unsigned>(has_binary || has_session) +
                                    static_cast<unsigned>(has_name || has_path) +
                                    static_cast<unsigned>(has_pid);
    if (selector_count > 1 || pid_alias_count > 1 ||
        (has_binary && has_session) || (has_name && has_path)) {
        return workspace_resolution_error(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "only one workspace selector may be supplied", "mcp_workspace_resolve"));
    }

    if (has_binary || has_session) {
        const char* field = has_binary ? "binary_id" : "session_id";
        if (!args[field].is_string()) {
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                std::string(field) + " must be a string", "mcp_workspace_resolve"));
        }
        const std::string text = args[field].get<std::string>();
        if (auto parsed = binary_id_t::from_hex(text)) {
            selector.binary_id = *parsed;
        } else {
            auto workspace = analysis_session::workspace_for_session_id(text);
            if (workspace)
                return {std::move(workspace), {}, {}, json::object()};
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::target_not_found,
                "workspace binary/session identity was not found", "mcp_workspace_resolve"));
        }
    } else if (has_path) {
        if (!args["file_path"].is_string()) {
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "file_path must be a string", "mcp_workspace_resolve"));
        }
        auto normalized_path = normalize_utf8_path(args["file_path"].get<std::string>(), false);
        if (!normalized_path)
            return workspace_resolution_error(normalized_path.error());
        const std::string expected_path = normalize_target_name(normalized_path.value());
        std::vector<std::shared_ptr<analysis_workspace_t>> matches;
        for (const auto& workspace : workspace_registry().list()) {
            if (!workspace || workspace->closing() || workspace->closed())
                continue;
            if (normalize_target_name(workspace->identity().normalized_source_path()) == expected_path)
                matches.push_back(workspace);
        }
        if (matches.size() == 1)
            return {std::move(matches.front()), {}, {}, json::object()};
        if (matches.empty()) {
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::target_not_found,
                "file path target was not found", "mcp_workspace_resolve"));
        }
        auto error = make_workspace_error(
            workspace_error_code_t::target_ambiguous,
            "file path selector matches more than one workspace", "mcp_workspace_resolve");
        error.details.emplace_back("candidate_count", std::to_string(matches.size()));
        return workspace_resolution_error(error);
    } else if (has_name) {
        if (!args["bin_name"].is_string()) {
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "bin_name must be a string", "mcp_workspace_resolve"));
        }
        selector.bin_name = args["bin_name"].get<std::string>();
    } else if (has_pid) {
        std::uint32_t pid = 0;
        const char* pid_field = args.contains("pid") && !args["pid"].is_null() ? "pid" :
            (args.contains("target_pid") && !args["target_pid"].is_null() ? "target_pid" : "process_id");
        if (!parse_workspace_pid(args[pid_field], pid)) {
            return workspace_resolution_error(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "pid must be a positive 32-bit process id", "mcp_workspace_resolve"));
        }
        selector.pid = pid;
    }

    target_resolution_options_t options;
    options.allow_unique_substring = has_name;
    options.require_selector_when_multiple = true;
    auto resolved = workspace_registry().resolve(selector, options);
    if (!resolved)
        return workspace_resolution_error(resolved.error());
    return {resolved.take_value(), {}, {}, json::object()};
}

static const char* workspace_kind_name(aida::analysis::target_kind_t kind)
{
    return kind == aida::analysis::target_kind_t::live_snapshot ? "live" : "static";
}

static json workspace_provenance(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    const auto& identity = workspace->identity();
    const auto progress = workspace->progress();
    bool snapshot_stale = false;
    if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        const auto provider = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
            workspace->provider_handle());
        snapshot_stale = !provider || !provider->validate_current_identity();
    }
    json result;
    result["binary_id"] = identity.binary_id().to_hex();
    result["bin_name"] = identity.bin_name();
    result["kind"] = workspace_kind_name(identity.target_kind());
    result["pid"] = identity.process()
        ? json(identity.process()->pid)
        : json(nullptr);
    result["address_space"] = identity.target_kind() == aida::analysis::target_kind_t::live_snapshot
        ? "live_virtual"
        : "virtual_address";
    result["generation"] = workspace->generation();
    result["analysis_revision"] = workspace->analysis_revision();
    result["overlay_revision"] = workspace->overlay_revision();
    result["readiness"] = static_cast<unsigned>(progress.readiness);
    result["snapshot_stale"] = snapshot_stale;
    result["analysis_error"] = progress.error.has_value();
    return result;
}

static tool_result_t add_workspace_provenance(
    tool_result_t result,
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    if (!result.meta.is_object())
        result.meta = json::object();
    if (!result.meta.contains("aida") || !result.meta["aida"].is_object())
        result.meta["aida"] = json::object();
    result.meta["aida"].update(workspace_provenance(workspace));
    return result;
}

static bool tool_args_have_explicit_pid(const json& args)
{
    if (!args.is_object())
        return false;
    for (const char* key : {"target_pid", "process_id", "pid"}) {
        if (args.contains(key) && !args[key].is_null())
            return true;
    }
    return false;
}

static bool is_analysis_session_management_tool(const std::string& name)
{
    return name.rfind("sessions_", 0) == 0;
}

static bool is_active_session_independent_tool(const std::string& name)
{
    if (name == "get_tool_descriptions" ||
        name == "list_instances" ||
        name == "vm_bridge_manage" ||
        name == "list_processes" ||
        name == "disassemble_file" ||
        name == "sandbox_execute" ||
        is_camoufox_browser_tool_name(name)) {
        return true;
    }
    if (name.rfind("burp_", 0) == 0 ||
        name.rfind("browser_", 0) == 0 ||
        name.rfind("gameproto_", 0) == 0 ||
        name.rfind("net_proto_", 0) == 0 ||
        name.rfind("net_security_", 0) == 0 ||
        name.rfind("workflow_", 0) == 0) {
        return true;
    }
    return false;
}

static std::string predicted_tool_lane(const tool_def_t& tool, const json& arguments)
{
    const bool session_manager = is_analysis_session_management_tool(tool.name);
    const bool session_independent = tool.target_independent ||
        is_active_session_independent_tool(tool.name);
    json target_arguments_storage;
    const json& target_arguments = target_resolution_args_for_tool(tool, arguments, target_arguments_storage, false);
    const bool explicit_target = tool_args_select_session_target(target_arguments);
    if (session_independent && tool.read_only && !session_manager)
        return "independent_unlocked";
    if (session_independent && !tool.read_only && !session_manager) {
        const std::string domain = infer_tool_domain(tool.name);
        return "exclusive_domain_" + (domain.empty() ? std::string("misc") : domain);
    }
    if (session_manager)
        return "exclusive_session_manager";
    if (!tool.read_only)
        return "exclusive_mutating";
    if (!explicit_target)
        return "shared_active";
    return "shared_explicit_or_target_switch";
}

static mcp_executor_counts_t snapshot_mcp_executor_counts(std::size_t* executor_count = nullptr, bool* registry_lock_busy = nullptr)
{
    mcp_executor_counts_t counts;
    if (executor_count)
        *executor_count = 0;
    if (registry_lock_busy)
        *registry_lock_busy = false;
    std::unique_lock<std::mutex> lk(g_mcp_executor_registry_mtx, std::try_to_lock);
    if (!lk.owns_lock()) {
        if (registry_lock_busy)
            *registry_lock_busy = true;
        return counts;
    }
    if (executor_count)
        *executor_count = g_mcp_executor_registry.size();
    for (auto* executor : g_mcp_executor_registry) {
        if (!executor)
            continue;
        if (!executor->try_snapshot_counts(counts))
            ++counts.snapshot_busy;
    }
    return counts;
}

static std::string capacity_arg_scalar_to_string(const json& value)
{
    try {
        if (value.is_string())
            return value.get<std::string>();
        if (value.is_number_unsigned())
            return std::to_string(value.get<std::uint64_t>());
        if (value.is_number_integer())
            return std::to_string(value.get<std::int64_t>());
    } catch (...) {
    }
    return {};
}

static std::string capacity_session_id_from_args(const json& args)
{
    if (!args.is_object())
        return {};
    for (const char* key : {"binary_id", "session_id"}) {
        if (!args.contains(key))
            continue;
        std::string value = capacity_arg_scalar_to_string(args[key]);
        if (!value.empty())
            return std::string(key) + ":" + fnv1a64_hex(value);
    }
    return {};
}

static std::string capacity_target_id_from_args(const json& args, std::uint32_t target_pid)
{
    if (target_pid != 0)
        return "pid:" + std::to_string(target_pid);
    const std::string session_id = capacity_session_id_from_args(args);
    if (!session_id.empty())
        return "session:" + session_id;
    if (args.is_object() && args.contains("file_path") && args["file_path"].is_string())
        return "file:" + fnv1a64_hex(args["file_path"].get<std::string>());
    return {};
}

static bool capacity_background_command_tool(const std::string& tool_name, const json& args)
{
    if (tool_name != "run_command")
        return false;
    if (!args.is_object())
        return false;
    if (args.contains("wait") && args["wait"].is_boolean())
        return !args["wait"].get<bool>();
    if (args.contains("session_id") && args["session_id"].is_string() && !args["session_id"].get<std::string>().empty())
        return true;
    return false;
}

static bool capacity_driver_debugger_tool(const tool_def_t& tool, const std::string& domain)
{
    const std::string name = lower_ascii(tool.name);
    if (domain == "driver" || domain == "debugger")
        return true;
    if (name.rfind("driver_", 0) == 0 || name.rfind("dbg_", 0) == 0 || name.rfind("thread_", 0) == 0)
        return true;
    if (name.find("api_monitor") != std::string::npos)
        return true;
    return is_driver_bridge_dependent_tool(tool);
}

static bool capacity_scanner_tool(const std::string& tool_name, const std::string& domain)
{
    const std::string name = lower_ascii(tool_name);
    return domain == "scanner" ||
           name.find("scanner") != std::string::npos ||
           name.find("_scan") != std::string::npos ||
           name.find("scan_") != std::string::npos;
}

static bool capacity_decompiler_tool(const std::string& tool_name, const std::string& domain)
{
    const std::string name = lower_ascii(tool_name);
    return domain == "decompile" ||
           domain == "decompiler" ||
           name.find("decompile") != std::string::npos ||
           name.find("reconstruct") != std::string::npos;
}

static bool capacity_network_tool(const std::string& tool_name, const std::string& domain)
{
    const std::string name = lower_ascii(tool_name);
    return domain == "network" ||
           domain == "network_security" ||
           domain == "network_protocol" ||
           domain == "burp" ||
           name.rfind("network_", 0) == 0 ||
           name.rfind("net_", 0) == 0 ||
           name.rfind("burp_", 0) == 0;
}

static bool capacity_list_or_schema_tool(const std::string& method, const std::string& tool_name)
{
    const std::string m = lower_ascii(method);
    const std::string t = lower_ascii(tool_name);
    return m == "tools/list" ||
           m == "resources/list" ||
           m == "prompts/list" ||
           t == "get_tool_descriptions" ||
           t == "list_processes" ||
           t == "list_commands" ||
           t.find("schema") != std::string::npos ||
           t.find("list_") == 0;
}

static capacity_diag::activity_counters_t mcp_tool_capacity_activity_for_context(const capacity_diag::request_context_t& ctx);

static capacity_diag::pressure_snapshot_t capacity_pressure_snapshot(const capacity_diag::request_context_t& ctx)
{
    const auto& cfg = mcp_concurrency_config();
    const mcp_executor_counts_t executor_counts = snapshot_mcp_executor_counts();
    const capacity_diag::activity_counters_t active = capacity_diag::counters_for_context(ctx);
    const capacity_diag::activity_counters_t tool_active = mcp_tool_capacity_activity_for_context(ctx);
    const mcp_batch_reservation_snapshot_t batch_reservations = mcp_batch_reservation_snapshot_for_principal(ctx.principal_id);
    capacity_diag::pressure_snapshot_t pressure;
    pressure.tool_workers = cfg.tool_worker_threads;
    pressure.tool_queue_limit = cfg.tool_max_queued_requests;
    pressure.batch_workers = cfg.batch_worker_threads;
    pressure.batch_queue_limit = cfg.batch_max_queued_requests;
    pressure.active_http_requests = static_cast<std::size_t>((std::max)(0, g_active_http_requests.load(std::memory_order_acquire)));
    pressure.active_streams = static_cast<std::size_t>((std::max)(0, g_active_streams.load(std::memory_order_acquire)));
    const mcp_ingress_snapshot_t ingress = mcp_ingress_snapshot_for(ctx.principal_id);
    pressure.global_ingress_active_requests = ingress.global_active;
    pressure.global_ingress_queued_requests = ingress.global_queued;
    pressure.per_principal_ingress_active_requests = ingress.principal_active;
    pressure.per_principal_ingress_queued_requests = ingress.principal_queued;
    pressure.global_ingress_streams = ingress.global_streams;
    pressure.per_principal_ingress_streams = ingress.principal_streams;
    pressure.global_external_active_tools = static_cast<std::size_t>(executor_counts.active) + active.active_total + tool_active.active_total;
    pressure.global_external_queued_tools = executor_counts.queued;
    pressure.batch_active_children = (std::max)(active.active_batch_children + tool_active.active_batch_children, batch_reservations.active);
    pressure.batch_queued_children = batch_reservations.lock_busy && ctx.batch_child ? executor_counts.queued : batch_reservations.queued;
    pressure.per_principal_active_normal_tools = active.active_normal + tool_active.active_normal;
    pressure.per_principal_active_long_running_tools = active.active_long_running + tool_active.active_long_running;
    pressure.per_principal_queued_normal_tools = ctx.batch_child ? 0 : executor_counts.queued;
    pressure.per_principal_queued_long_running_tools = ctx.batch_child || ctx.effective_timeout_ms >= 60000 ? executor_counts.queued : 0;
    pressure.per_session_active_mutations = active.active_session_mutations + tool_active.active_session_mutations;
    pressure.per_session_active_read_only_tools = active.active_session_read_only + tool_active.active_session_read_only;
    pressure.per_target_driver_debugger_active_tools = active.active_target_driver_debugger + tool_active.active_target_driver_debugger;
    pressure.per_domain_mutating_active_tools = active.active_domain_mutating + tool_active.active_domain_mutating;
    pressure.active_background_command_sessions_per_principal = active.active_background_command_sessions + tool_active.active_background_command_sessions;
    const auto command_stats = command_sessions::stats();
    pressure.global_active_background_command_sessions = (std::max)(active.active_background_command_sessions + tool_active.active_background_command_sessions, command_stats.running);
    pressure.background_command_sessions_total = command_stats.total;
    pressure.background_command_sessions_running = command_stats.running;
    pressure.background_command_sessions_reader_active = command_stats.reader_active;
    pressure.background_command_sessions_timed_out = command_stats.timed_out;
    pressure.background_command_oldest_running_ms = command_stats.oldest_running_ms;
    const auto executor_snapshot = aida::infra::executor::active_snapshot();
    pressure.downstream_general_pending = static_cast<std::size_t>(executor_snapshot.work_queue_pending);
    pressure.downstream_general_active = static_cast<std::size_t>(executor_snapshot.work_queue_active);
    pressure.downstream_service_pending = static_cast<std::size_t>(executor_snapshot.service_queue_pending);
    pressure.downstream_service_active = static_cast<std::size_t>(executor_snapshot.service_queue_active);
    pressure.downstream_critical_pending = static_cast<std::size_t>(executor_snapshot.critical_queue_pending);
    pressure.downstream_critical_active = static_cast<std::size_t>(executor_snapshot.critical_queue_active);
    return pressure;
}

static capacity_diag::request_context_t capacity_tool_context(const char* transport,
                                                              const char* route,
                                                              const char* method,
                                                              const std::string& principal_id,
                                                              const std::string& diagnostic_id,
                                                              const std::string& request_id,
                                                              const tool_def_t& tool,
                                                              const json& arguments,
                                                              const tool_timeout_resolution_t& timeout_resolution,
                                                              const std::string& lane,
                                                              const std::string& payload_shape,
                                                              std::uint32_t target_pid,
                                                              bool batch_child = false,
                                                              std::size_t batch_size = 0,
                                                              std::size_t batch_index = 0)
{
    capacity_diag::request_context_t ctx;
    ctx.diagnostic_id = capacity_diag::clean_label(diagnostic_id, 160);
    ctx.request_id = capacity_diag::clean_label(request_id, 160);
    ctx.transport = transport ? transport : "";
    ctx.route = route ? route : "";
    ctx.method = method ? method : "tools/call";
    ctx.principal_id = principal_id.empty() ? std::string("external_mcp") : capacity_diag::clean_label(principal_id, 160);
    ctx.tool_name = capacity_diag::clean_label(tool.name, 160);
    ctx.domain = capacity_diag::clean_label(infer_tool_domain(tool.name), 96);
    ctx.lane = capacity_diag::clean_label(lane, 128);
    ctx.action = capacity_diag::clean_label(timeout_resolution.action, 96);
    ctx.payload_shape = capacity_diag::clean_label(payload_shape, 384);
    ctx.tool_known = true;
    ctx.read_only = tool.read_only;
    ctx.session_manager = is_analysis_session_management_tool(tool.name);
    json target_arguments_storage;
    const json& target_arguments = target_resolution_args_for_tool(tool, arguments, target_arguments_storage, false);
    ctx.explicit_target = tool_args_select_session_target(target_arguments);
    ctx.session_id = capacity_session_id_from_args(target_arguments);
    ctx.target_id = capacity_target_id_from_args(target_arguments, target_pid);
    ctx.browser_tool = is_camoufox_browser_tool_name(tool.name);
    ctx.driver_debugger_tool = capacity_driver_debugger_tool(tool, ctx.domain);
    ctx.scanner_tool = capacity_scanner_tool(tool.name, ctx.domain);
    ctx.decompiler_tool = capacity_decompiler_tool(tool.name, ctx.domain);
    ctx.network_tool = capacity_network_tool(tool.name, ctx.domain);
    ctx.background_command = capacity_background_command_tool(tool.name, arguments);
    ctx.list_or_schema = capacity_list_or_schema_tool(ctx.method, tool.name);
    ctx.batch_child = batch_child;
    ctx.target_pid = target_pid;
    ctx.requested_timeout_ms = timeout_resolution.requested_ms;
    ctx.effective_timeout_ms = timeout_resolution.effective_ms;
    ctx.batch_size = batch_size;
    ctx.batch_index = batch_index;
    return ctx;
}

static capacity_diag::request_context_t capacity_route_context(const std::string& transport,
                                                               const std::string& route,
                                                               const std::string& method,
                                                               const std::string& principal_id,
                                                               const std::string& diagnostic_id,
                                                               const std::string& request_id,
                                                               const std::string& tool_name = {},
                                                               const std::string& payload_shape = {},
                                                               bool batch_child = false,
                                                               std::size_t batch_size = 0,
                                                               std::size_t batch_index = 0)
{
    capacity_diag::request_context_t ctx;
    ctx.diagnostic_id = capacity_diag::clean_label(diagnostic_id, 160);
    ctx.request_id = capacity_diag::clean_label(request_id, 160);
    ctx.transport = transport;
    ctx.route = route;
    ctx.method = method;
    ctx.principal_id = principal_id.empty() ? std::string("external_mcp") : capacity_diag::clean_label(principal_id, 160);
    ctx.tool_name = capacity_diag::clean_label(tool_name, 160);
    ctx.domain = capacity_diag::clean_label(tool_name.empty() ? std::string() : infer_tool_domain(tool_name), 96);
    ctx.lane = batch_child ? "jsonrpc_batch_item" : route;
    ctx.payload_shape = capacity_diag::clean_label(payload_shape, 384);
    ctx.tool_known = tool_name.empty();
    ctx.read_only = true;
    ctx.browser_tool = is_camoufox_browser_tool_name(tool_name);
    ctx.scanner_tool = capacity_scanner_tool(tool_name, ctx.domain);
    ctx.decompiler_tool = capacity_decompiler_tool(tool_name, ctx.domain);
    ctx.network_tool = capacity_network_tool(tool_name, ctx.domain);
    ctx.list_or_schema = capacity_list_or_schema_tool(ctx.method, ctx.tool_name);
    ctx.batch_child = batch_child;
    ctx.batch_size = batch_size;
    ctx.batch_index = batch_index;
    ctx.effective_timeout_ms = batch_child ? kMcpBatchWaitTimeoutMs : 0;
    ctx.requested_timeout_ms = ctx.effective_timeout_ms;
    return ctx;
}

static const char* capacity_pressure_source_name(const capacity_diag::prediction_t& prediction,
                                                 const mcp_executor_counts_t& executor_counts,
                                                 const command_sessions::stats_t& command_stats,
                                                 const mcp_pressure_snapshot_t& pressure_registry)
{
    if (prediction.pressure.active_http_requests >= 100 ||
        prediction.pressure.active_streams >= 100 ||
        pressure_registry.principal_count >= 100)
        return "hundred_plus_client_pressure";
    if (prediction.context.batch_size >= 100)
        return "large_batch_fanout";
    if (pressure_registry.principal_count <= 1 &&
        (prediction.context.batch_size > 1 ||
         prediction.long_running ||
         prediction.context.background_command ||
         executor_counts.queued != 0 ||
         command_stats.running != 0))
        return "single_principal_amplification";
    if (command_stats.running != 0 || command_stats.reader_active != 0)
        return "background_commands";
    if (executor_counts.active_long_running != 0 || executor_counts.queued_long_running != 0)
        return "long_running_tools";
    if (prediction.pressure.downstream_critical_pending != 0 ||
        prediction.pressure.downstream_service_pending != 0 ||
        prediction.pressure.downstream_general_pending != 0)
        return "downstream_work_queues";
    if (executor_counts.queued != 0)
        return "mcp_executor_queue";
    return "within_observed_capacity";
}

static void log_capacity_snapshot_events(const char* phase, const capacity_diag::prediction_t& prediction)
{
    std::size_t executor_count = 0;
    bool executor_registry_busy = false;
    const mcp_executor_counts_t executor_counts = snapshot_mcp_executor_counts(&executor_count, &executor_registry_busy);
    const auto command_stats = command_sessions::stats();
    const auto general = runtime_queue_stats(runtime_queue_family_t::general);
    const auto service = runtime_queue_stats(runtime_queue_family_t::service);
    const auto critical = runtime_queue_stats(runtime_queue_family_t::critical);
    const mcp_pressure_snapshot_t pressure_registry = mcp_pressure_snapshot();
    char owner_snapshot[900] = {};
    format_active_session_owner_diagnostic_snapshot(owner_snapshot, sizeof(owner_snapshot));
    const bool single_principal_amplification =
        pressure_registry.principal_count <= 1 &&
        (prediction.context.batch_size > 1 ||
         prediction.long_running ||
         prediction.context.background_command ||
         executor_counts.queued != 0 ||
         command_stats.running != 0);
    const bool hundred_plus_client_pressure =
        prediction.pressure.active_http_requests >= 100 ||
        prediction.pressure.active_streams >= 100 ||
        pressure_registry.principal_count >= 100;
    const char* pressure_source = capacity_pressure_source_name(prediction, executor_counts, command_stats, pressure_registry);

    diag::log_tagged_fmt("mcp_srv",
        "MCP-CAPACITY-SNAPSHOT phase=%s diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' tool='%s' domain='%s' lane=%s priority=%s cost=%u diagnostics_only=%d enforcement_enabled=%d would_accept=%d would_reject=%d reason=%s quota=%s observed=%zu limit=%zu single_principal_amplification=%d hundred_plus_client_pressure=%d pressure_source=%s active_requests=%zu active_streams=%zu ingress_active=%zu ingress_queued=%zu principal_ingress_active=%zu principal_ingress_queued=%zu ingress_streams=%zu principal_ingress_streams=%zu executors=%zu executor_registry_busy=%d executor_snapshot_busy=%zu executor_workers=%zu executor_active=%llu executor_queued=%zu executor_long_active=%llu executor_long_queued=%llu executor_oldest_active_ms=%llu batch_active=%zu batch_queued=%zu command_total=%zu command_running=%zu command_reader_active=%zu command_timed_out=%zu command_oldest_ms=%llu owner=%.760s principal_pressure=%.760s session_pressure=%.520s domain_pressure=%.520s lane_pressure=%.520s executor_pressure=%.520s",
        phase ? phase : "",
        prediction.context.diagnostic_id.c_str(),
        prediction.context.request_id.c_str(),
        prediction.context.transport.c_str(),
        prediction.context.route.c_str(),
        prediction.context.method.c_str(),
        prediction.context.principal_id.c_str(),
        prediction.context.session_id.c_str(),
        prediction.context.target_id.c_str(),
        prediction.context.tool_name.c_str(),
        prediction.context.domain.c_str(),
        prediction.lane.c_str(),
        prediction.priority_name.c_str(),
        prediction.cost_units,
        prediction.diagnostics_only ? 1 : 0,
        prediction.enforcement_enabled ? 1 : 0,
        prediction.decision.would_accept ? 1 : 0,
        prediction.decision.would_accept ? 0 : 1,
        prediction.decision.reason.c_str(),
        prediction.decision.quota_name.c_str(),
        prediction.decision.observed,
        prediction.decision.limit,
        single_principal_amplification ? 1 : 0,
        hundred_plus_client_pressure ? 1 : 0,
        pressure_source,
        prediction.pressure.active_http_requests,
        prediction.pressure.active_streams,
        prediction.pressure.global_ingress_active_requests,
        prediction.pressure.global_ingress_queued_requests,
        prediction.pressure.per_principal_ingress_active_requests,
        prediction.pressure.per_principal_ingress_queued_requests,
        prediction.pressure.global_ingress_streams,
        prediction.pressure.per_principal_ingress_streams,
        executor_count,
        executor_registry_busy ? 1 : 0,
        executor_counts.snapshot_busy,
        executor_counts.workers,
        static_cast<unsigned long long>(executor_counts.active),
        executor_counts.queued,
        static_cast<unsigned long long>(executor_counts.active_long_running),
        static_cast<unsigned long long>(executor_counts.queued_long_running),
        static_cast<unsigned long long>(executor_counts.oldest_active_ms),
        prediction.pressure.batch_active_children,
        prediction.pressure.batch_queued_children,
        command_stats.total,
        command_stats.running,
        command_stats.reader_active,
        command_stats.timed_out,
        static_cast<unsigned long long>(command_stats.oldest_running_ms),
        owner_snapshot[0] ? owner_snapshot : "owner{empty=1}",
        pressure_registry.principal_summary.empty() ? "<none>" : pressure_registry.principal_summary.c_str(),
        pressure_registry.session_summary.empty() ? "<none>" : pressure_registry.session_summary.c_str(),
        pressure_registry.domain_summary.empty() ? "<none>" : pressure_registry.domain_summary.c_str(),
        pressure_registry.lane_summary.empty() ? "<none>" : pressure_registry.lane_summary.c_str(),
        pressure_registry.executor_summary.empty() ? "<none>" : pressure_registry.executor_summary.c_str());

    diag::log_tagged_fmt("mcp_srv",
        "MCP-DOWNSTREAM-PRESSURE phase=%s diag_id=%s request_id='%s' pressure_source=%s tool='%s' domain='%s' lane=%s general_alive=%d general_pending=%zu general_active=%u general_oldest_ms=%llu general_labels=%.420s service_alive=%d service_pending=%zu service_active=%u service_oldest_ms=%llu service_labels=%.420s critical_alive=%d critical_pending=%zu critical_active=%u critical_oldest_ms=%llu critical_labels=%.420s executor_active=%llu executor_queued=%zu executor_long_active=%llu executor_long_queued=%llu executor_queue_summary=%.700s executor_active_summary=%.700s command_total=%zu command_running=%zu command_finished=%zu command_reader_active=%zu command_timed_out=%zu command_oldest_ms=%llu command_summary=%.700s active_session=%.700s",
        phase ? phase : "",
        prediction.context.diagnostic_id.c_str(),
        prediction.context.request_id.c_str(),
        pressure_source,
        prediction.context.tool_name.c_str(),
        prediction.context.domain.c_str(),
        prediction.lane.c_str(),
        general.alive ? 1 : 0,
        general.pending,
        static_cast<unsigned>(general.active),
        static_cast<unsigned long long>(general.oldest_active_ms),
        general.active_labels.empty() ? "<none>" : general.active_labels.c_str(),
        service.alive ? 1 : 0,
        service.pending,
        static_cast<unsigned>(service.active),
        static_cast<unsigned long long>(service.oldest_active_ms),
        service.active_labels.empty() ? "<none>" : service.active_labels.c_str(),
        critical.alive ? 1 : 0,
        critical.pending,
        static_cast<unsigned>(critical.active),
        static_cast<unsigned long long>(critical.oldest_active_ms),
        critical.active_labels.empty() ? "<none>" : critical.active_labels.c_str(),
        static_cast<unsigned long long>(executor_counts.active),
        executor_counts.queued,
        static_cast<unsigned long long>(executor_counts.active_long_running),
        static_cast<unsigned long long>(executor_counts.queued_long_running),
        executor_counts.queue_summary.empty() ? "<none>" : executor_counts.queue_summary.c_str(),
        executor_counts.active_summary.empty() ? "<none>" : executor_counts.active_summary.c_str(),
        command_stats.total,
        command_stats.running,
        command_stats.finished,
        command_stats.reader_active,
        command_stats.timed_out,
        static_cast<unsigned long long>(command_stats.oldest_running_ms),
        command_stats.active_summary.empty() ? "<none>" : command_stats.active_summary.c_str(),
        owner_snapshot[0] ? owner_snapshot : "owner{empty=1}");

    {
        const json ds_snap = mcp_standalone::downstream::governor_t::instance().snapshot_json();
        char ds_kind_summary[768] = {};
        std::size_t ds_offset = 0;
        if (ds_snap.contains("by_kind") && ds_snap["by_kind"].is_array()) {
            for (const auto& entry : ds_snap["by_kind"]) {
                if (ds_offset >= sizeof(ds_kind_summary) - 64) break;
                const int written = _snprintf_s(
                    ds_kind_summary + ds_offset, sizeof(ds_kind_summary) - ds_offset, _TRUNCATE,
                    "%s%s=%zu/%zu",
                    ds_offset == 0 ? "" : ";",
                    entry.value("kind", std::string()).c_str(),
                    entry.value("active", std::size_t{0}),
                    entry.value("rejected", std::size_t{0}));
                if (written < 0) break;
                ds_offset += static_cast<std::size_t>(written);
            }
        }
        char ds_principal_summary[512] = {};
        std::size_t ds_p_offset = 0;
        if (ds_snap.contains("per_principal") && ds_snap["per_principal"].is_array()) {
            for (const auto& entry : ds_snap["per_principal"]) {
                if (ds_p_offset >= sizeof(ds_principal_summary) - 64) break;
                const int written = _snprintf_s(
                    ds_principal_summary + ds_p_offset, sizeof(ds_principal_summary) - ds_p_offset, _TRUNCATE,
                    "%s%s=%zu",
                    ds_p_offset == 0 ? "" : ";",
                    entry.value("principal", std::string()).c_str(),
                    entry.value("active", std::size_t{0}));
                if (written < 0) break;
                ds_p_offset += static_cast<std::size_t>(written);
            }
        }
        std::uint64_t ds_oldest = 0;
        if (ds_snap.contains("by_kind") && ds_snap["by_kind"].is_array()) {
            for (const auto& entry : ds_snap["by_kind"]) {
                const auto age = entry.value("oldest_active_ms", 0ULL);
                if (age > ds_oldest) ds_oldest = age;
            }
        }
        diag::log_tagged_fmt("mcp_srv",
            "MCP-DOWNSTREAM-SNAPSHOT phase=%s total_active=%zu total_rejected=%zu shutdown_pending=%zu "
            "p0_reserve=%zu p1_reserve=%zu oldest_active_ms=%llu kind_summary=%.760s principal_summary=%.500s",
            phase ? phase : "",
            ds_snap.value("total_active", 0),
            ds_snap.value("total_rejected", 0),
            ds_snap.value("shutdown_pending", 0),
            ds_snap.value("p0_reserve_available", 0),
            ds_snap.value("p1_reserve_available", 0),
            static_cast<unsigned long long>(ds_oldest),
            ds_kind_summary[0] ? ds_kind_summary : "<none>",
            ds_principal_summary[0] ? ds_principal_summary : "<none>");
        std::size_t fwg_feature = 0, fwg_scanner = 0, fwg_decompiler = 0,
            fwg_pdb = 0, fwg_broad = 0, fwg_burp = 0, fwg_api = 0;
        if (ds_snap.contains("by_kind") && ds_snap["by_kind"].is_array()) {
            for (const auto& entry : ds_snap["by_kind"]) {
                const std::string kind = entry.value("kind", std::string());
                const auto active = entry.value("active", 0);
                if (kind == "feature_worker") fwg_feature = active;
                else if (kind == "scanner") fwg_scanner = active;
                else if (kind == "decompiler") fwg_decompiler = active;
                else if (kind == "pdb_parser") fwg_pdb = active;
                else if (kind == "broad_enumeration") fwg_broad = active;
                else if (kind == "burp_network") fwg_burp = active;
                else if (kind == "api_monitor") fwg_api = active;
            }
        }
        diag::log_tagged_fmt("mcp_srv",
            "FEATURE-WORKER-GROUP-SNAPSHOT total_active=%zu feature_worker=%zu scanner=%zu "
            "decompiler=%zu pdb=%zu broad_enum=%zu burp_network=%zu api_monitor=%zu oldest_ms=%llu",
            ds_snap.value("total_active", 0),
            fwg_feature, fwg_scanner, fwg_decompiler, fwg_pdb,
            fwg_broad, fwg_burp, fwg_api,
            static_cast<unsigned long long>(ds_oldest));
    }
}

static std::string batch_count_summary(const std::map<std::string, std::size_t>& counts, std::size_t max_items)
{
    std::vector<std::pair<std::string, std::size_t>> items;
    items.reserve(counts.size());
    for (const auto& kv : counts)
        items.push_back(kv);
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second)
            return a.second > b.second;
        return a.first < b.first;
    });
    std::string out;
    std::size_t emitted = 0;
    for (const auto& item : items) {
        if (emitted >= max_items)
            break;
        char buf[220] = {};
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "%s%s=%zu",
            out.empty() ? "" : ";",
            item.first.c_str(),
            item.second);
        out += buf;
        ++emitted;
    }
    return out;
}

static void log_mcp_batch_fanout_diagnostic(const char* phase,
                                            std::uint64_t batch_id,
                                            const json& batch,
                                            std::size_t responses,
                                            std::size_t overload,
                                            bool complete,
                                            std::uint64_t elapsed_ms,
                                            const capacity_diag::prediction_t& prediction)
{
    std::size_t items = batch.is_array() ? batch.size() : 0;
    std::size_t tools_call = 0;
    std::size_t notifications = 0;
    std::size_t invalid = 0;
    std::size_t long_running = 0;
    std::size_t browser = 0;
    std::size_t driver_debugger = 0;
    std::size_t background_command = 0;
    std::map<std::string, std::size_t> method_counts;
    std::map<std::string, std::size_t> tool_counts;
    std::map<std::string, std::size_t> domain_counts;
    if (batch.is_array()) {
        for (const auto& item : batch) {
            if (!item.is_object()) {
                ++invalid;
                ++method_counts["invalid"];
                continue;
            }
            if (!item.contains("id"))
                ++notifications;
            const std::string method = item.value("method", std::string());
            ++method_counts[method.empty() ? std::string("<empty>") : capacity_clean_key(method, "method", 96)];
            if (method != "tools/call" || !item.contains("params") || !item["params"].is_object())
                continue;
            ++tools_call;
            const json& params = item["params"];
            const std::string tool = params.contains("name") && params["name"].is_string()
                ? params["name"].get<std::string>() : std::string("<missing>");
            const std::string domain = tool == "<missing>" ? std::string("unknown") : infer_tool_domain(tool);
            ++tool_counts[capacity_clean_key(tool, "tool", 96)];
            ++domain_counts[capacity_domain_key(domain)];
            const json args = params.contains("arguments") && params["arguments"].is_object() ? params["arguments"] : json::object();
            const bool bg = capacity_background_command_tool(tool, args);
            const bool drv = contains_ci_ascii(tool, "driver") || contains_ci_ascii(tool, "dbg_") ||
                contains_ci_ascii(tool, "debug") || contains_ci_ascii(tool, "thread_") ||
                contains_ci_ascii(tool, "api_monitor");
            const bool br = is_camoufox_browser_tool_name(tool);
            const bool lr = bg || drv || br || is_long_running_tool_diagnostic(tool, domain, std::string(), 0, kMcpCapacityLongRunningMs + 1);
            if (bg)
                ++background_command;
            if (drv)
                ++driver_debugger;
            if (br)
                ++browser;
            if (lr)
                ++long_running;
        }
    }
    const mcp_pressure_snapshot_t pressure_registry = mcp_pressure_snapshot();
    const bool single_principal_amplification = pressure_registry.principal_count <= 1 && (items > 1 || long_running != 0 || background_command != 0);
    const bool hundred_plus_client_pressure = prediction.pressure.active_http_requests >= 100 || prediction.pressure.active_streams >= 100 || pressure_registry.principal_count >= 100;
    diag::log_tagged_fmt("mcp_srv",
        "MCP-BATCH-FANOUT-DIAGNOSTIC phase=%s batch=%llu diag_id=%s principal='%s' session='%s' route=%s transport=%s items=%zu responses=%zu overload=%zu complete=%d elapsed_ms=%llu tools_call=%zu notifications=%zu invalid=%zu unique_methods=%zu unique_tools=%zu unique_domains=%zu long_running_items=%zu browser_items=%zu driver_debugger_items=%zu background_command_items=%zu would_accept=%d would_reject=%d reason=%s single_principal_amplification=%d hundred_plus_client_pressure=%d active_requests=%zu active_streams=%zu method_summary=%.520s tool_summary=%.700s domain_summary=%.520s principal_pressure=%.700s",
        phase ? phase : "",
        static_cast<unsigned long long>(batch_id),
        prediction.context.diagnostic_id.c_str(),
        prediction.context.principal_id.c_str(),
        prediction.context.session_id.c_str(),
        prediction.context.route.c_str(),
        prediction.context.transport.c_str(),
        items,
        responses,
        overload,
        complete ? 1 : 0,
        static_cast<unsigned long long>(elapsed_ms),
        tools_call,
        notifications,
        invalid,
        method_counts.size(),
        tool_counts.size(),
        domain_counts.size(),
        long_running,
        browser,
        driver_debugger,
        background_command,
        prediction.decision.would_accept ? 1 : 0,
        prediction.decision.would_accept ? 0 : 1,
        prediction.decision.reason.c_str(),
        single_principal_amplification ? 1 : 0,
        hundred_plus_client_pressure ? 1 : 0,
        prediction.pressure.active_http_requests,
        prediction.pressure.active_streams,
        batch_count_summary(method_counts, 8).c_str(),
        batch_count_summary(tool_counts, 10).c_str(),
        batch_count_summary(domain_counts, 8).c_str(),
        pressure_registry.principal_summary.empty() ? "<none>" : pressure_registry.principal_summary.c_str());
}

static capacity_diag::prediction_t diagnose_capacity(const char* phase, const capacity_diag::request_context_t& ctx, bool enforcement_enabled = false)
{
    const auto& cfg = mcp_concurrency_config();
    const capacity_diag::quota_set_t quotas = capacity_diag::make_quota_set(cfg.tool_worker_threads, cfg.http_worker_threads, cfg.http_max_queued_requests, cfg.max_concurrent_streams, cfg.max_concurrent_streams_per_principal);
    const capacity_diag::pressure_snapshot_t pressure = capacity_pressure_snapshot(ctx);
    capacity_diag::prediction_t prediction = capacity_diag::predict(ctx, quotas, pressure);
    prediction.diagnostics_only = !enforcement_enabled;
    prediction.enforcement_enabled = enforcement_enabled;
    capacity_diag::remember_prediction(prediction);
    log_capacity_snapshot_events(phase, prediction);
    diag::log_tagged_fmt("mcp_srv",
        "MCP-CAPACITY-DIAGNOSTIC phase=%s diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' tool='%s' domain='%s' priority=%s lane=%s cost=%u long_running=%d class=%s read_only=%d mutating=%d session_manager=%d browser=%d driver_debugger=%d background_command=%d batch_child=%d batch_size=%zu batch_index=%zu target_pid=%u would_accept=%d would_reject=%d reason=%s quota=%s scope=%s observed=%zu limit=%zu global_active=%zu global_queued=%zu ingress_active=%zu ingress_queued=%zu principal_ingress_active=%zu principal_ingress_queued=%zu ingress_streams=%zu principal_ingress_streams=%zu per_principal_active_normal=%zu per_principal_active_long=%zu per_session_mutations=%zu per_session_read_only=%zu target_driver_debugger=%zu domain_mutating=%zu downstream_general_pending=%zu downstream_service_pending=%zu downstream_critical_pending=%zu phase2_enforced=%d",
        phase ? phase : "",
        prediction.context.diagnostic_id.c_str(),
        prediction.context.request_id.c_str(),
        prediction.context.transport.c_str(),
        prediction.context.route.c_str(),
        prediction.context.method.c_str(),
        prediction.context.principal_id.c_str(),
        prediction.context.tool_name.c_str(),
        prediction.context.domain.c_str(),
        prediction.priority_name.c_str(),
        prediction.lane.c_str(),
        prediction.cost_units,
        prediction.long_running ? 1 : 0,
        prediction.classification.c_str(),
        prediction.read_only ? 1 : 0,
        prediction.mutating ? 1 : 0,
        prediction.session_manager ? 1 : 0,
        prediction.context.browser_tool ? 1 : 0,
        prediction.context.driver_debugger_tool ? 1 : 0,
        prediction.context.background_command ? 1 : 0,
        prediction.context.batch_child ? 1 : 0,
        prediction.context.batch_size,
        prediction.context.batch_index,
        prediction.context.target_pid,
        prediction.decision.would_accept ? 1 : 0,
        prediction.decision.would_accept ? 0 : 1,
        prediction.decision.reason.c_str(),
        prediction.decision.quota_name.c_str(),
        prediction.decision.quota_scope.c_str(),
        prediction.decision.observed,
        prediction.decision.limit,
        prediction.pressure.global_external_active_tools,
        prediction.pressure.global_external_queued_tools,
        prediction.pressure.global_ingress_active_requests,
        prediction.pressure.global_ingress_queued_requests,
        prediction.pressure.per_principal_ingress_active_requests,
        prediction.pressure.per_principal_ingress_queued_requests,
        prediction.pressure.global_ingress_streams,
        prediction.pressure.per_principal_ingress_streams,
        prediction.pressure.per_principal_active_normal_tools,
        prediction.pressure.per_principal_active_long_running_tools,
        prediction.pressure.per_session_active_mutations,
        prediction.pressure.per_session_active_read_only_tools,
        prediction.pressure.per_target_driver_debugger_active_tools,
        prediction.pressure.per_domain_mutating_active_tools,
        prediction.pressure.downstream_general_pending,
        prediction.pressure.downstream_service_pending,
        prediction.pressure.downstream_critical_pending,
        prediction.enforcement_enabled ? 1 : 0);
    return prediction;
}

static bool mcp_ingress_is_governed_route(const httplib::Request& req)
{
    return req.path == "/mcp" || req.path == "/message" || req.path == "/sse" || req.path == "/api/tools" || req.path == "/api/tools/call";
}

static bool mcp_ingress_is_sse_stream_request(const httplib::Request& req)
{
    if (req.method != "GET")
        return false;
    if (req.path == "/sse")
        return true;
    if (req.path != "/mcp")
        return false;
    return req.get_header_value("Accept").find("text/event-stream") != std::string::npos;
}

static bool mcp_reserved_jsonrpc_method(const std::string& method)
{
    return method == "initialize" ||
           method == "notifications/initialized" ||
           method == "ping" ||
           method == "notifications/cancelled" ||
           method == "shutdown" ||
           method == "logging/setLevel";
}

static mcp_reserved_lane_t mcp_reserved_lane_for_jsonrpc_method(const std::string& method,
                                                                const std::string& tool)
{
    if (method == "notifications/cancelled" || tool == "cancel_command")
        return mcp_reserved_lane_t::cancellation;
    if (method == "shutdown")
        return mcp_reserved_lane_t::shutdown;
    return mcp_reserved_lane_t::liveness;
}

static mcp_reserved_lane_t mcp_reserved_lane_for_jsonrpc_method(const std::string& method)
{
    static const std::string empty_tool;
    return mcp_reserved_lane_for_jsonrpc_method(method, empty_tool);
}

static mcp_reserved_lane_t mcp_reserved_lane_join(mcp_reserved_lane_t current, mcp_reserved_lane_t next)
{
    if (current == mcp_reserved_lane_t::cancellation || next == mcp_reserved_lane_t::cancellation)
        return mcp_reserved_lane_t::cancellation;
    if (current == mcp_reserved_lane_t::shutdown || next == mcp_reserved_lane_t::shutdown)
        return mcp_reserved_lane_t::shutdown;
    if (current == mcp_reserved_lane_t::health || next == mcp_reserved_lane_t::health)
        return mcp_reserved_lane_t::health;
    return mcp_reserved_lane_t::liveness;
}

static bool mcp_jsonrpc_item_uses_reserved_lane(const json& value);

static mcp_reserved_lane_t mcp_reserved_lane_for_jsonrpc_item(const json& value)
{
    if (!value.is_object())
        return mcp_reserved_lane_t::liveness;
    const std::string method = value.value("method", std::string());
    if (method == "tools/call" && value.contains("params") && value["params"].is_object()) {
        const std::string tool = value["params"].value("name", std::string());
        if (tool == "cancel_command")
            return mcp_reserved_lane_t::cancellation;
    }
    if (value.value("name", std::string()) == "cancel_command")
        return mcp_reserved_lane_t::cancellation;
    return mcp_reserved_lane_for_jsonrpc_method(method);
}

static mcp_reserved_lane_t mcp_reserved_lane_for_control_json(const json& value)
{
    if (value.is_object())
        return mcp_reserved_lane_for_jsonrpc_item(value);
    if (!value.is_array() || value.empty())
        return mcp_reserved_lane_t::liveness;
    mcp_reserved_lane_t lane = mcp_reserved_lane_t::liveness;
    for (const auto& item : value) {
        if (mcp_jsonrpc_item_uses_reserved_lane(item))
            lane = mcp_reserved_lane_join(lane, mcp_reserved_lane_for_jsonrpc_item(item));
    }
    return lane;
}

static std::string mcp_reserved_request_method_label(const httplib::Request& req)
{
    if (req.path == "/health")
        return "health";
    if (req.method == "OPTIONS")
        return "OPTIONS";
    if (req.method == "DELETE")
        return "shutdown";
    if (req.method == "POST" && !req.body.empty() && req.body.size() <= 65536) {
        json parsed = json::parse(req.body, nullptr, false);
        if (parsed.is_object())
            return parsed.value("method", std::string("reserved_control"));
        if (parsed.is_array()) {
            const mcp_reserved_lane_t lane = mcp_reserved_lane_for_control_json(parsed);
            if (lane == mcp_reserved_lane_t::cancellation)
                return "notifications/cancelled";
            if (lane == mcp_reserved_lane_t::shutdown)
                return "shutdown";
            return "ping";
        }
    }
    return req.method;
}

static mcp_reserved_lane_t mcp_reserved_lane_for_request(const httplib::Request& req)
{
    if (req.path == "/health")
        return mcp_reserved_lane_t::health;
    if (req.method == "DELETE" && (req.path == "/mcp" || req.path == "/sse"))
        return mcp_reserved_lane_t::shutdown;
    if (req.method == "POST" && !req.body.empty() && req.body.size() <= 65536) {
        json parsed = json::parse(req.body, nullptr, false);
        if (!parsed.is_discarded())
            return mcp_reserved_lane_for_control_json(parsed);
    }
    return mcp_reserved_lane_t::liveness;
}

static bool mcp_jsonrpc_item_uses_reserved_lane(const json& value)
{
    if (!value.is_object())
        return false;
    const std::string method = value.value("method", std::string());
    if (mcp_reserved_jsonrpc_method(method))
        return true;
    if (method == "tools/call" && value.contains("params") && value["params"].is_object())
        return value["params"].value("name", std::string()) == "cancel_command";
    return value.value("name", std::string()) == "cancel_command";
}

static bool mcp_reserved_control_json(const json& value)
{
    if (value.is_object()) {
        return mcp_jsonrpc_item_uses_reserved_lane(value);
    }
    if (!value.is_array() || value.empty())
        return false;
    for (const auto& item : value) {
        if (!mcp_reserved_control_json(item))
            return false;
    }
    return true;
}

static bool mcp_ingress_is_reserved_control_request(const httplib::Request& req)
{
    if (req.path == "/health" || req.method == "OPTIONS")
        return true;
    if (req.method == "DELETE" && (req.path == "/mcp" || req.path == "/sse"))
        return true;
    if (req.method != "POST" || req.body.empty() || req.body.size() > 65536)
        return false;
    if (req.body.find("notifications/cancelled") == std::string::npos &&
        req.body.find("\"initialize\"") == std::string::npos &&
        req.body.find("notifications/initialized") == std::string::npos &&
        req.body.find("\"ping\"") == std::string::npos &&
        req.body.find("\"shutdown\"") == std::string::npos &&
        req.body.find("logging/setLevel") == std::string::npos &&
        req.body.find("cancel_command") == std::string::npos)
        return false;
    json parsed = json::parse(req.body, nullptr, false);
    if (parsed.is_discarded())
        return false;
    return mcp_reserved_control_json(parsed);
}

static void mcp_ingress_set_reject(capacity_diag::prediction_t& prediction,
                                   const char* reason,
                                   const char* quota,
                                   const char* scope,
                                   std::size_t observed,
                                   std::size_t limit)
{
    prediction.decision.would_accept = false;
    prediction.decision.reason = reason ? reason : "reject";
    prediction.decision.quota_name = quota ? quota : "";
    prediction.decision.quota_scope = scope ? scope : "";
    prediction.decision.observed = observed;
    prediction.decision.limit = limit;
}

static void mcp_ingress_write_pressure(capacity_diag::prediction_t& prediction,
                                       std::size_t global_active,
                                       std::size_t global_queued,
                                       std::size_t global_streams,
                                       std::size_t principal_active,
                                       std::size_t principal_queued,
                                       std::size_t principal_streams)
{
    prediction.pressure.global_ingress_active_requests = global_active;
    prediction.pressure.global_ingress_queued_requests = global_queued;
    prediction.pressure.global_ingress_streams = global_streams;
    prediction.pressure.per_principal_ingress_active_requests = principal_active;
    prediction.pressure.per_principal_ingress_queued_requests = principal_queued;
    prediction.pressure.per_principal_ingress_streams = principal_streams;
}

static bool mcp_ingress_try_activate_locked(const std::shared_ptr<mcp_ingress_admission_t>& admission,
                                            capacity_diag::prediction_t& prediction)
{
    const auto& q = prediction.quotas;
    const std::string principal = mcp_ingress_principal_key(admission->principal());
    const std::string route = mcp_ingress_route_key(admission->route());
    const std::string route_principal = mcp_ingress_route_principal_key(admission->route(), admission->principal());
    auto& principal_counts = g_mcp_ingress_by_principal[principal];
    auto& route_counts = g_mcp_ingress_by_route[route];
    auto& route_principal_counts = g_mcp_ingress_by_route_principal[route_principal];
    const std::size_t global_active = g_mcp_ingress_active.load(std::memory_order_acquire);
    const std::size_t global_queued = g_mcp_ingress_queued.load(std::memory_order_acquire);
    const std::size_t global_streams = g_mcp_ingress_streams.load(std::memory_order_acquire);
    mcp_ingress_write_pressure(prediction, global_active, global_queued, global_streams, principal_counts.active, principal_counts.queued, principal_counts.streams);
    if (admission->stream() && global_streams >= q.global_ingress_streams) {
        mcp_ingress_set_reject(prediction, "reject_global_ingress_streams", "global_ingress_streams", "ingress_stream_global", global_streams, q.global_ingress_streams);
        return false;
    }
    if (admission->stream() && principal_counts.streams >= q.per_principal_ingress_streams) {
        mcp_ingress_set_reject(prediction, "reject_per_principal_ingress_streams", "per_principal_ingress_streams", "ingress_stream_principal", principal_counts.streams, q.per_principal_ingress_streams);
        return false;
    }
    if (global_active >= q.global_ingress_active_requests) {
        mcp_ingress_set_reject(prediction, "reject_global_ingress_active_requests", "global_ingress_active_requests", "ingress_global", global_active, q.global_ingress_active_requests);
        return false;
    }
    if (route_counts.active >= q.global_ingress_active_requests) {
        mcp_ingress_set_reject(prediction, "reject_route_ingress_active_requests", "global_ingress_active_requests", "ingress_route", route_counts.active, q.global_ingress_active_requests);
        return false;
    }
    if (principal_counts.active >= q.per_principal_ingress_active_requests) {
        mcp_ingress_set_reject(prediction, "reject_per_principal_ingress_active_requests", "per_principal_ingress_active_requests", "ingress_principal", principal_counts.active, q.per_principal_ingress_active_requests);
        return false;
    }
    if (route_principal_counts.active >= q.per_principal_ingress_active_requests) {
        mcp_ingress_set_reject(prediction, "reject_route_principal_ingress_active_requests", "per_principal_ingress_active_requests", "ingress_route_principal", route_principal_counts.active, q.per_principal_ingress_active_requests);
        return false;
    }
    g_mcp_ingress_active.store(global_active + 1, std::memory_order_release);
    ++principal_counts.active;
    ++route_counts.active;
    ++route_principal_counts.active;
    if (admission->stream()) {
        g_mcp_ingress_streams.store(global_streams + 1, std::memory_order_release);
        ++principal_counts.streams;
        ++route_counts.streams;
        ++route_principal_counts.streams;
    }
    admission->mark_active();
    mcp_ingress_write_pressure(prediction,
        global_active + 1,
        global_queued,
        admission->stream() ? global_streams + 1 : global_streams,
        principal_counts.active,
        principal_counts.queued,
        principal_counts.streams);
    prediction.decision.would_accept = true;
    prediction.decision.reason = "accepted_http_ingress_capacity";
    prediction.decision.quota_name.clear();
    prediction.decision.quota_scope.clear();
    prediction.decision.observed = admission->stream() ? principal_counts.streams : principal_counts.active;
    prediction.decision.limit = admission->stream() ? q.per_principal_ingress_streams : q.per_principal_ingress_active_requests;
    return true;
}

static void mcp_ingress_drop_empty_principal_locked(const std::string& principal)
{
    mcp_ingress_drop_empty_locked(g_mcp_ingress_by_principal, principal);
}

static bool mcp_ingress_try_admit(capacity_diag::prediction_t& prediction,
                                  const std::shared_ptr<mcp_ingress_admission_t>& admission,
                                  std::uint64_t* wait_ms)
{
    if (wait_ms)
        *wait_ms = 0;
    const std::string principal = mcp_ingress_principal_key(admission->principal());
    const std::string route = mcp_ingress_route_key(admission->route());
    const std::string route_principal = mcp_ingress_route_principal_key(admission->route(), admission->principal());
    const std::uint64_t begin = mcp_now_ms();
    std::unique_lock<std::mutex> lk(g_mcp_ingress_capacity_mtx);
    if (mcp_ingress_try_activate_locked(admission, prediction))
        return true;
    if (admission->stream()) {
        mcp_ingress_drop_empty_principal_locked(principal);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
        return false;
    }

    auto& principal_counts = g_mcp_ingress_by_principal[principal];
    auto& route_counts = g_mcp_ingress_by_route[route];
    auto& route_principal_counts = g_mcp_ingress_by_route_principal[route_principal];
    const std::size_t global_queued = g_mcp_ingress_queued.load(std::memory_order_acquire);
    if (global_queued >= prediction.quotas.global_ingress_queued_requests) {
        mcp_ingress_set_reject(prediction, "reject_global_ingress_queued_requests", "global_ingress_queued_requests", "ingress_global", global_queued, prediction.quotas.global_ingress_queued_requests);
        mcp_ingress_drop_empty_principal_locked(principal);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
        return false;
    }
    if (route_counts.queued >= prediction.quotas.global_ingress_queued_requests) {
        mcp_ingress_set_reject(prediction, "reject_route_ingress_queued_requests", "global_ingress_queued_requests", "ingress_route", route_counts.queued, prediction.quotas.global_ingress_queued_requests);
        mcp_ingress_drop_empty_principal_locked(principal);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
        return false;
    }
    if (principal_counts.queued >= prediction.quotas.per_principal_ingress_queued_requests) {
        mcp_ingress_set_reject(prediction, "reject_per_principal_ingress_queued_requests", "per_principal_ingress_queued_requests", "ingress_principal", principal_counts.queued, prediction.quotas.per_principal_ingress_queued_requests);
        mcp_ingress_drop_empty_principal_locked(principal);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
        return false;
    }
    if (route_principal_counts.queued >= prediction.quotas.per_principal_ingress_queued_requests) {
        mcp_ingress_set_reject(prediction, "reject_route_principal_ingress_queued_requests", "per_principal_ingress_queued_requests", "ingress_route_principal", route_principal_counts.queued, prediction.quotas.per_principal_ingress_queued_requests);
        mcp_ingress_drop_empty_principal_locked(principal);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
        mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
        return false;
    }

    g_mcp_ingress_queued.store(global_queued + 1, std::memory_order_release);
    ++principal_counts.queued;
    ++route_counts.queued;
    ++route_principal_counts.queued;
    mcp_ingress_write_pressure(prediction,
        g_mcp_ingress_active.load(std::memory_order_acquire),
        global_queued + 1,
        g_mcp_ingress_streams.load(std::memory_order_acquire),
        principal_counts.active,
        principal_counts.queued,
        principal_counts.streams);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kMcpIngressQueueWaitMs);
    bool admitted = false;
    do {
        if (g_mcp_ingress_capacity_cv.wait_until(lk, deadline) == std::cv_status::timeout)
            break;
        if (mcp_ingress_try_activate_locked(admission, prediction)) {
            admitted = true;
            break;
        }
    } while (std::chrono::steady_clock::now() < deadline);

    auto it = g_mcp_ingress_by_principal.find(principal);
    if (it != g_mcp_ingress_by_principal.end() && it->second.queued != 0)
        --it->second.queued;
    auto route_it = g_mcp_ingress_by_route.find(route);
    if (route_it != g_mcp_ingress_by_route.end() && route_it->second.queued != 0)
        --route_it->second.queued;
    auto rp_it = g_mcp_ingress_by_route_principal.find(route_principal);
    if (rp_it != g_mcp_ingress_by_route_principal.end() && rp_it->second.queued != 0)
        --rp_it->second.queued;
    const std::size_t current_global_queued = g_mcp_ingress_queued.load(std::memory_order_acquire);
    g_mcp_ingress_queued.store(current_global_queued == 0 ? 0 : current_global_queued - 1, std::memory_order_release);
    if (admitted) {
        if (it != g_mcp_ingress_by_principal.end())
            mcp_ingress_write_pressure(prediction,
                g_mcp_ingress_active.load(std::memory_order_acquire),
                g_mcp_ingress_queued.load(std::memory_order_acquire),
                g_mcp_ingress_streams.load(std::memory_order_acquire),
                it->second.active,
                it->second.queued,
                it->second.streams);
        if (wait_ms)
            *wait_ms = mcp_now_ms() >= begin ? mcp_now_ms() - begin : 0;
        return true;
    }
    if (it != g_mcp_ingress_by_principal.end()) {
        mcp_ingress_write_pressure(prediction,
            g_mcp_ingress_active.load(std::memory_order_acquire),
            g_mcp_ingress_queued.load(std::memory_order_acquire),
            g_mcp_ingress_streams.load(std::memory_order_acquire),
            it->second.active,
            it->second.queued,
            it->second.streams);
    }
    mcp_ingress_drop_empty_principal_locked(principal);
    mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route, route);
    mcp_ingress_drop_empty_locked(g_mcp_ingress_by_route_principal, route_principal);
    if (wait_ms)
        *wait_ms = mcp_now_ms() >= begin ? mcp_now_ms() - begin : 0;
    if (prediction.decision.would_accept)
        mcp_ingress_set_reject(prediction, "reject_ingress_queue_wait_timeout", "per_principal_ingress_active_requests", "ingress_principal", prediction.pressure.per_principal_ingress_active_requests, prediction.quotas.per_principal_ingress_active_requests);
    return false;
}

static capacity_diag::request_context_t mcp_http_ingress_context(const httplib::Request& req, bool reserved_lane)
{
    capacity_diag::request_context_t ctx = capacity_route_context(current_mcp_transport(),
        req.path,
        req.method,
        current_mcp_principal(),
        "http-ingress-" + std::to_string(tls_http_request_id),
        std::to_string(tls_http_request_id),
        {},
        "body_bytes=" + std::to_string(req.body.size()));
    ctx.http_ingress = true;
    ctx.sse_stream = mcp_ingress_is_sse_stream_request(req);
    ctx.reserved_lane = reserved_lane;
    if (reserved_lane) {
        ctx.method = mcp_reserved_request_method_label(req);
        ctx.lane = "reserved_control";
    } else {
        ctx.lane = ctx.sse_stream ? std::string("sse_stream") : std::string("http_ingress");
    }
    return ctx;
}

static json mcp_http_capacity_rejection_body(const capacity_diag::prediction_t& prediction, std::uint64_t wait_ms)
{
    json body;
    body["status"] = "rejected";
    body["error"] = "mcp ingress capacity exhausted";
    body["code"] = "MCP_CAPACITY_REJECT";
    body["disposition"] = "not_started";
    body["retry_after_ms"] = 250;
    body["request_id"] = prediction.context.request_id;
    body["principal_id"] = prediction.context.principal_id;
    body["route"] = prediction.context.route;
    body["transport"] = prediction.context.transport;
    body["method"] = prediction.context.method;
    body["decision"] = "reject";
    body["reason"] = prediction.decision.reason;
    body["quota"] = prediction.decision.quota_name;
    body["scope"] = prediction.decision.quota_scope;
    body["active"] = prediction.pressure.global_ingress_active_requests;
    body["queued"] = prediction.pressure.global_ingress_queued_requests;
    body["principal_active"] = prediction.pressure.per_principal_ingress_active_requests;
    body["principal_queued"] = prediction.pressure.per_principal_ingress_queued_requests;
    body["streams"] = prediction.pressure.global_ingress_streams;
    body["principal_streams"] = prediction.pressure.per_principal_ingress_streams;
    body["cap"] = prediction.decision.limit;
    body["observed"] = prediction.decision.observed;
    body["queue_wait_ms"] = wait_ms;
    body["capacity"] = capacity_diag::prediction_json(prediction);
    return body;
}

static bool mcp_try_admit_http_ingress(const httplib::Request& req, httplib::Response& res)
{
    if (!mcp_ingress_is_governed_route(req))
        return true;
    const bool reserved_lane = mcp_ingress_is_reserved_control_request(req);
    capacity_diag::prediction_t prediction = diagnose_capacity("http_ingress_pre_route", mcp_http_ingress_context(req, reserved_lane));
    if (reserved_lane) {
        const mcp_reserved_lane_t lane = mcp_reserved_lane_for_request(req);
        std::shared_ptr<mcp_reserved_lane_scope_t> scope;
        if (!mcp_try_acquire_reserved_lane(lane,
                "http_ingress_pre_route",
                prediction.context.principal_id,
                prediction.context.route,
                prediction.context.method,
                prediction.context.request_id,
                scope)) {
            res.status = 429;
            res.set_header("Retry-After", "1");
            res.set_content(json_dump_safe(mcp_reserved_lane_rejection_body(lane,
                prediction.context.request_id,
                prediction.context.route,
                prediction.context.method,
                prediction.context.principal_id)), "application/json");
            capacity_diag::remember_prediction(prediction);
            mcp_ingress_record_rejection(prediction.context.route, "reserved_lane_exhausted");
            return false;
        }
        tls_reserved_control_lane = scope;
        capacity_diag::remember_prediction(prediction);
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAPACITY-ADMIT request_id=%s route=%s method=%s transport=%s principal='%s' active=%zu queued=%zu cap=%zu decision=admit reason=reserved_lane lane=%s reserved_active=%zu reserved_limit=%zu stream=%d",
            prediction.context.request_id.c_str(),
            prediction.context.route.c_str(),
            prediction.context.method.c_str(),
            prediction.context.transport.c_str(),
            prediction.context.principal_id.c_str(),
            prediction.pressure.global_ingress_active_requests,
            prediction.pressure.global_ingress_queued_requests,
            prediction.quotas.global_ingress_active_requests,
            mcp_reserved_lane_name(lane),
            mcp_reserved_lane_active(lane),
            mcp_reserved_lane_limit(lane),
            prediction.context.sse_stream ? 1 : 0);
        return true;
    }

    auto admission = std::make_shared<mcp_ingress_admission_t>(
        tls_http_request_id,
        req.path,
        req.method,
        current_mcp_transport(),
        current_mcp_principal(),
        prediction.context.sse_stream);
    std::uint64_t wait_ms = 0;
    const bool admitted = mcp_ingress_try_admit(prediction, admission, &wait_ms);
    capacity_diag::remember_prediction(prediction);
    if (admitted) {
        tls_http_ingress_admission = admission;
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAPACITY-ADMIT request_id=%s route=%s method=%s transport=%s principal='%s' active=%zu queued=%zu principal_active=%zu principal_queued=%zu streams=%zu principal_streams=%zu cap=%zu decision=admit reason=%s stream=%d queue_wait_ms=%llu",
            prediction.context.request_id.c_str(),
            prediction.context.route.c_str(),
            prediction.context.method.c_str(),
            prediction.context.transport.c_str(),
            prediction.context.principal_id.c_str(),
            prediction.pressure.global_ingress_active_requests,
            prediction.pressure.global_ingress_queued_requests,
            prediction.pressure.per_principal_ingress_active_requests,
            prediction.pressure.per_principal_ingress_queued_requests,
            prediction.pressure.global_ingress_streams,
            prediction.pressure.per_principal_ingress_streams,
            prediction.decision.limit,
            prediction.decision.reason.c_str(),
            prediction.context.sse_stream ? 1 : 0,
            static_cast<unsigned long long>(wait_ms));
        return true;
    }

    mcp_ingress_record_rejection(prediction.context.route, prediction.decision.reason);
    res.status = 429;
    res.set_header("Retry-After", "1");
    res.set_content(json_dump_safe(mcp_http_capacity_rejection_body(prediction, wait_ms)), "application/json");
    diag::log_tagged_fmt("mcp_srv",
        "MCP-CAPACITY-REJECT request_id=%s route=%s method=%s transport=%s principal='%s' active=%zu queued=%zu principal_active=%zu principal_queued=%zu streams=%zu principal_streams=%zu cap=%zu observed=%zu decision=reject reason=%s quota=%s scope=%s stream=%d queue_wait_ms=%llu status=429",
        prediction.context.request_id.c_str(),
        prediction.context.route.c_str(),
        prediction.context.method.c_str(),
        prediction.context.transport.c_str(),
        prediction.context.principal_id.c_str(),
        prediction.pressure.global_ingress_active_requests,
        prediction.pressure.global_ingress_queued_requests,
        prediction.pressure.per_principal_ingress_active_requests,
        prediction.pressure.per_principal_ingress_queued_requests,
        prediction.pressure.global_ingress_streams,
        prediction.pressure.per_principal_ingress_streams,
        prediction.decision.limit,
        prediction.decision.observed,
        prediction.decision.reason.c_str(),
        prediction.decision.quota_name.c_str(),
        prediction.decision.quota_scope.c_str(),
        prediction.context.sse_stream ? 1 : 0,
        static_cast<unsigned long long>(wait_ms));
    if (prediction.context.sse_stream) {
        diag::log_tagged_fmt("mcp_srv",
            "MCP-STREAM-REJECT route=%s transport=%s principal=%s principal_source=ingress session_hash=%s remote=%s reason=capacity_unavailable scope=%s observed=%zu limit=%zu active_streams=%zu principal_active_streams=%zu max_streams=%zu per_principal_limit=%zu request_id=%s pid=%lu tid=%lu active_requests=%d disposition=not_started",
            prediction.context.route.c_str(),
            prediction.context.transport.c_str(),
            prediction.context.principal_id.c_str(),
            current_mcp_session_hash(),
            remote_endpoint(req).c_str(),
            prediction.decision.quota_scope.c_str(),
            prediction.decision.observed,
            prediction.decision.limit,
            prediction.pressure.global_ingress_streams,
            prediction.pressure.per_principal_ingress_streams,
            prediction.quotas.global_ingress_streams,
            prediction.quotas.per_principal_ingress_streams,
            prediction.context.request_id.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_active_http_requests.load(std::memory_order_acquire));
    }
    return false;
}

static json mcp_capacity_counts_json(const mcp_capacity_counts_t& c)
{
    return {
        {"active", c.active},
        {"queued", c.queued},
        {"read_active", c.read_active},
        {"read_queued", c.read_queued},
        {"mutate_active", c.mutate_active},
        {"mutate_queued", c.mutate_queued},
        {"long_active", c.long_active},
        {"long_queued", c.long_queued},
        {"driver_debugger_active", c.driver_debugger_active},
        {"driver_debugger_queued", c.driver_debugger_queued},
        {"batch_active", c.batch_active},
        {"batch_queued", c.batch_queued},
        {"background_active", c.background_active},
        {"background_queued", c.background_queued},
        {"oldest_active_ms", c.oldest_active_ms},
        {"oldest_queued_ms", c.oldest_queued_ms}
    };
}

static json mcp_capacity_counts_map_json(const std::map<std::string, mcp_capacity_counts_t>& counts, std::size_t max_items)
{
    std::vector<std::pair<std::string, mcp_capacity_counts_t>> items;
    items.reserve(counts.size());
    for (const auto& kv : counts)
        items.push_back(kv);
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        const std::uint64_t ap = a.second.active + a.second.queued + a.second.long_active + a.second.long_queued + a.second.driver_debugger_active + a.second.driver_debugger_queued;
        const std::uint64_t bp = b.second.active + b.second.queued + b.second.long_active + b.second.long_queued + b.second.driver_debugger_active + b.second.driver_debugger_queued;
        if (ap != bp)
            return ap > bp;
        return a.first < b.first;
    });
    json arr = json::array();
    std::size_t emitted = 0;
    for (const auto& item : items) {
        if (emitted >= max_items)
            break;
        if (item.second.active == 0 && item.second.queued == 0)
            continue;
        json row = mcp_capacity_counts_json(item.second);
        row["key"] = item.first;
        arr.push_back(std::move(row));
        ++emitted;
    }
    return arr;
}

static json mcp_capacity_contributors_json(const std::vector<mcp_pressure_contributor_t>& contributors)
{
    json arr = json::array();
    for (const auto& c : contributors) {
        arr.push_back({
            {"state", c.state},
            {"executor", c.executor},
            {"principal", c.principal},
            {"session", c.session_id},
            {"target_id", c.target_id},
            {"target_pid", c.target_pid},
            {"domain", c.domain},
            {"tool", c.tool},
            {"lane", c.lane},
            {"age_ms", c.age_ms},
            {"queued_age_ms", c.queued_age_ms},
            {"active_age_ms", c.active_age_ms},
            {"batch_id", c.batch_id},
            {"read_only", c.read_only},
            {"long_running", c.long_running},
            {"driver_debugger", c.driver_debugger},
            {"background_command", c.background_command}
        });
    }
    return arr;
}

struct mcp_tool_capacity_counts_t
{
    std::uint64_t active = 0;
    std::uint64_t rejected = 0;
    std::uint64_t read_active = 0;
    std::uint64_t read_rejected = 0;
    std::uint64_t mutate_active = 0;
    std::uint64_t mutate_rejected = 0;
    std::uint64_t long_active = 0;
    std::uint64_t long_rejected = 0;
    std::uint64_t driver_debugger_active = 0;
    std::uint64_t driver_debugger_rejected = 0;
    std::uint64_t browser_active = 0;
    std::uint64_t browser_rejected = 0;
    std::uint64_t scanner_active = 0;
    std::uint64_t scanner_rejected = 0;
    std::uint64_t decompiler_active = 0;
    std::uint64_t decompiler_rejected = 0;
    std::uint64_t network_active = 0;
    std::uint64_t network_rejected = 0;
    std::uint64_t background_active = 0;
    std::uint64_t background_rejected = 0;
    std::uint64_t oldest_active_ms = 0;
};

struct mcp_tool_capacity_record_t
{
    std::uint64_t lease_id = 0;
    std::uint64_t admitted_ms = 0;
    std::string diagnostic_id;
    std::string request_id;
    std::string transport;
    std::string route;
    std::string method;
    std::string principal;
    std::string session;
    std::string target;
    std::string domain;
    std::string lane;
    std::string priority;
    std::string tool;
    std::string classification;
    std::string action;
    std::uint32_t target_pid = 0;
    std::uint32_t cost = 0;
    DWORD admitted_tid = 0;
    bool read_only = true;
    bool mutating = false;
    bool long_running = false;
    bool session_manager = false;
    bool driver_debugger = false;
    bool browser = false;
    bool scanner = false;
    bool decompiler = false;
    bool network = false;
    bool background = false;
    bool batch_child = false;
};

struct mcp_tool_capacity_snapshot_t
{
    std::uint64_t timestamp_ms = 0;
    bool lock_busy = false;
    std::uint64_t leases_acquired = 0;
    std::uint64_t leases_released = 0;
    std::uint64_t rejected_total = 0;
    mcp_tool_capacity_counts_t global;
    mcp_tool_capacity_counts_t rejected_global;
    std::map<std::string, mcp_tool_capacity_counts_t> principals;
    std::map<std::string, mcp_tool_capacity_counts_t> sessions;
    std::map<std::string, mcp_tool_capacity_counts_t> targets;
    std::map<std::string, mcp_tool_capacity_counts_t> domains;
    std::map<std::string, mcp_tool_capacity_counts_t> lanes;
    std::map<std::string, mcp_tool_capacity_counts_t> priorities;
    std::map<std::string, mcp_tool_capacity_counts_t> tools;
    std::map<std::string, mcp_tool_capacity_counts_t> classes;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_principals;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_sessions;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_targets;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_domains;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_lanes;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_priorities;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_tools;
    std::map<std::string, mcp_tool_capacity_counts_t> rejected_classes;
    std::vector<mcp_pressure_contributor_t> contributors;
};

std::mutex g_mcp_tool_capacity_mtx;
std::map<std::uint64_t, mcp_tool_capacity_record_t> g_mcp_tool_active_leases;
std::set<std::uint64_t> g_mcp_tool_cleanup_released_leases;

    std::size_t active_tool_lease_count() noexcept
    {
        std::unique_lock<std::mutex> lk(g_mcp_tool_capacity_mtx, std::try_to_lock);
        if (!lk.owns_lock())
            return 0;
        return g_mcp_tool_active_leases.size();
    }
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_principal;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_session;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_target;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_domain;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_lane;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_priority;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_tool;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_by_class;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_principal;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_session;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_target;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_domain;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_lane;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_priority;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_tool;
std::map<std::string, mcp_tool_capacity_counts_t> g_mcp_tool_rejected_by_class;
mcp_tool_capacity_counts_t g_mcp_tool_global_counts;
mcp_tool_capacity_counts_t g_mcp_tool_rejected_global_counts;
std::atomic<std::uint64_t> g_mcp_tool_capacity_seq{0};
std::atomic<std::uint64_t> g_mcp_tool_leases_acquired{0};
std::atomic<std::uint64_t> g_mcp_tool_leases_released{0};
std::atomic<std::uint64_t> g_mcp_tool_calls_rejected{0};

static bool mcp_tool_is_scanner_domain(const std::string& domain, const std::string& tool)
{
    const std::string d = lower_ascii(domain);
    const std::string t = lower_ascii(tool);
    return d == "scanner" || d == "static_analysis" || contains_ci_ascii(t, "scan");
}

static bool mcp_tool_is_decompiler_domain(const std::string& domain, const std::string& tool)
{
    const std::string d = lower_ascii(domain);
    const std::string t = lower_ascii(tool);
    return d == "decompile" || d == "decompiler" || contains_ci_ascii(t, "decompile");
}

static bool mcp_tool_is_network_domain(const std::string& domain, const std::string& tool)
{
    const std::string d = lower_ascii(domain);
    const std::string t = lower_ascii(tool);
    return d == "network" || d == "network_security" || d == "burp" || contains_ci_ascii(t, "network") || contains_ci_ascii(t, "burp");
}

static std::string mcp_tool_principal_key(const std::string& value)
{
    return capacity_clean_key(value.empty() || value == "<none>" ? std::string("external_mcp") : value, "external_mcp", 96);
}

static std::string mcp_tool_session_key(const std::string& value)
{
    return capacity_clean_key(value.empty() ? std::string("active_session") : value, "active_session", 96);
}

static std::string mcp_tool_target_key(const std::string& value, std::uint32_t pid)
{
    if (!value.empty())
        return capacity_clean_key(value, "target_unknown", 96);
    if (pid != 0)
        return std::string("pid:") + std::to_string(pid);
    return "target_unknown";
}

static std::string mcp_tool_lane_key(const std::string& value)
{
    return capacity_clean_key(value.empty() ? std::string("unclassified") : value, "unclassified", 96);
}

static std::string mcp_tool_priority_key(const std::string& value)
{
    return capacity_clean_key(value.empty() ? std::string("P4") : value, "P4", 16);
}

static void mcp_tool_bump_counts(mcp_tool_capacity_counts_t& counts, const mcp_tool_capacity_record_t& record, bool rejected, std::uint64_t age_ms)
{
    if (rejected) {
        ++counts.rejected;
        if (record.read_only)
            ++counts.read_rejected;
        if (record.mutating)
            ++counts.mutate_rejected;
        if (record.long_running)
            ++counts.long_rejected;
        if (record.driver_debugger)
            ++counts.driver_debugger_rejected;
        if (record.browser)
            ++counts.browser_rejected;
        if (record.scanner)
            ++counts.scanner_rejected;
        if (record.decompiler)
            ++counts.decompiler_rejected;
        if (record.network)
            ++counts.network_rejected;
        if (record.background)
            ++counts.background_rejected;
        return;
    }
    ++counts.active;
    if (record.read_only)
        ++counts.read_active;
    if (record.mutating)
        ++counts.mutate_active;
    if (record.long_running)
        ++counts.long_active;
    if (record.driver_debugger)
        ++counts.driver_debugger_active;
    if (record.browser)
        ++counts.browser_active;
    if (record.scanner)
        ++counts.scanner_active;
    if (record.decompiler)
        ++counts.decompiler_active;
    if (record.network)
        ++counts.network_active;
    if (record.background)
        ++counts.background_active;
    if (counts.oldest_active_ms < age_ms)
        counts.oldest_active_ms = age_ms;
}

static void mcp_tool_decrement_counts(mcp_tool_capacity_counts_t& counts, const mcp_tool_capacity_record_t& record)
{
    auto dec = [](std::uint64_t& v) {
        if (v != 0)
            --v;
    };
    dec(counts.active);
    if (record.read_only)
        dec(counts.read_active);
    if (record.mutating)
        dec(counts.mutate_active);
    if (record.long_running)
        dec(counts.long_active);
    if (record.driver_debugger)
        dec(counts.driver_debugger_active);
    if (record.browser)
        dec(counts.browser_active);
    if (record.scanner)
        dec(counts.scanner_active);
    if (record.decompiler)
        dec(counts.decompiler_active);
    if (record.network)
        dec(counts.network_active);
    if (record.background)
        dec(counts.background_active);
}

static bool mcp_tool_counts_has_pressure(const mcp_tool_capacity_counts_t& counts)
{
    return counts.active != 0 || counts.rejected != 0 || counts.read_active != 0 || counts.read_rejected != 0 ||
        counts.mutate_active != 0 || counts.mutate_rejected != 0 || counts.long_active != 0 || counts.long_rejected != 0 ||
        counts.driver_debugger_active != 0 || counts.driver_debugger_rejected != 0 || counts.browser_active != 0 ||
        counts.browser_rejected != 0 || counts.scanner_active != 0 || counts.scanner_rejected != 0 ||
        counts.decompiler_active != 0 || counts.decompiler_rejected != 0 || counts.network_active != 0 ||
        counts.network_rejected != 0 || counts.background_active != 0 || counts.background_rejected != 0;
}

static void mcp_tool_bump_map(std::map<std::string, mcp_tool_capacity_counts_t>& map,
                              const std::string& key,
                              const mcp_tool_capacity_record_t& record,
                              bool rejected,
                              std::uint64_t age_ms)
{
    const std::string clean = capacity_clean_key(key, "unknown", 96);
    auto it = map.find(clean);
    if (it == map.end()) {
        if (map.size() >= kMcpCapacityMaxMapEntries)
            return;
        it = map.emplace(clean, mcp_tool_capacity_counts_t{}).first;
    }
    mcp_tool_bump_counts(it->second, record, rejected, age_ms);
}

static void mcp_tool_decrement_map(std::map<std::string, mcp_tool_capacity_counts_t>& map,
                                   const std::string& key,
                                   const mcp_tool_capacity_record_t& record)
{
    const std::string clean = capacity_clean_key(key, "unknown", 96);
    auto it = map.find(clean);
    if (it == map.end())
        return;
    mcp_tool_decrement_counts(it->second, record);
    if (!mcp_tool_counts_has_pressure(it->second))
        map.erase(it);
}

template <typename Fn>
static void mcp_tool_each_class(const mcp_tool_capacity_record_t& record, Fn&& fn)
{
    if (record.long_running)
        fn(std::string("long_running"));
    if (record.driver_debugger)
        fn(std::string("driver_debugger"));
    if (record.browser)
        fn(std::string("browser"));
    if (record.scanner)
        fn(std::string("scanner"));
    if (record.decompiler)
        fn(std::string("decompiler"));
    if (record.network)
        fn(std::string("network"));
    if (record.background)
        fn(std::string("background"));
    if (record.mutating)
        fn(std::string("mutating"));
    if (record.read_only)
        fn(std::string("read_only"));
}

static void mcp_tool_add_active_locked(const mcp_tool_capacity_record_t& record)
{
    g_mcp_tool_active_leases[record.lease_id] = record;
    mcp_tool_bump_counts(g_mcp_tool_global_counts, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_principal, record.principal, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_session, record.session, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_target, record.target, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_domain, record.domain, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_lane, record.lane, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_priority, record.priority, record, false, 0);
    mcp_tool_bump_map(g_mcp_tool_by_tool, record.tool, record, false, 0);
    mcp_tool_each_class(record, [&](const std::string& key) {
        mcp_tool_bump_map(g_mcp_tool_by_class, key, record, false, 0);
    });
}

static void mcp_tool_remove_active_locked(const mcp_tool_capacity_record_t& record)
{
    mcp_tool_decrement_counts(g_mcp_tool_global_counts, record);
    mcp_tool_decrement_map(g_mcp_tool_by_principal, record.principal, record);
    mcp_tool_decrement_map(g_mcp_tool_by_session, record.session, record);
    mcp_tool_decrement_map(g_mcp_tool_by_target, record.target, record);
    mcp_tool_decrement_map(g_mcp_tool_by_domain, record.domain, record);
    mcp_tool_decrement_map(g_mcp_tool_by_lane, record.lane, record);
    mcp_tool_decrement_map(g_mcp_tool_by_priority, record.priority, record);
    mcp_tool_decrement_map(g_mcp_tool_by_tool, record.tool, record);
    mcp_tool_each_class(record, [&](const std::string& key) {
        mcp_tool_decrement_map(g_mcp_tool_by_class, key, record);
    });
}

static void mcp_tool_add_rejected_locked(const mcp_tool_capacity_record_t& record)
{
    mcp_tool_bump_counts(g_mcp_tool_rejected_global_counts, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_principal, record.principal, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_session, record.session, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_target, record.target, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_domain, record.domain, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_lane, record.lane, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_priority, record.priority, record, true, 0);
    mcp_tool_bump_map(g_mcp_tool_rejected_by_tool, record.tool, record, true, 0);
    mcp_tool_each_class(record, [&](const std::string& key) {
        mcp_tool_bump_map(g_mcp_tool_rejected_by_class, key, record, true, 0);
    });
}

static void mcp_tool_add_contributor(mcp_tool_capacity_snapshot_t& snap, mcp_pressure_contributor_t item)
{
    if (item.age_ms == 0 && !item.long_running && !item.driver_debugger && !item.background_command)
        return;
    snap.contributors.push_back(std::move(item));
    std::sort(snap.contributors.begin(), snap.contributors.end(),
        [](const mcp_pressure_contributor_t& a, const mcp_pressure_contributor_t& b) {
            if (a.age_ms != b.age_ms)
                return a.age_ms > b.age_ms;
            if (a.driver_debugger != b.driver_debugger)
                return a.driver_debugger;
            return a.tool < b.tool;
        });
    if (snap.contributors.size() > kMcpCapacityMaxContributors)
        snap.contributors.resize(kMcpCapacityMaxContributors);
}

static mcp_tool_capacity_counts_t mcp_tool_counts_for(const std::map<std::string, mcp_tool_capacity_counts_t>& map, const std::string& key)
{
    const auto it = map.find(capacity_clean_key(key, "unknown", 96));
    return it == map.end() ? mcp_tool_capacity_counts_t{} : it->second;
}

static mcp_tool_capacity_record_t mcp_tool_record_from_prediction(const capacity_diag::prediction_t& prediction, std::uint64_t admitted_ms)
{
    const auto& ctx = prediction.context;
    mcp_tool_capacity_record_t record;
    record.lease_id = g_mcp_tool_capacity_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    record.admitted_ms = admitted_ms == 0 ? mcp_now_ms() : admitted_ms;
    record.diagnostic_id = capacity_clean_key(ctx.diagnostic_id, "tool-diag", 160);
    record.request_id = capacity_clean_key(ctx.request_id, "tool-request", 160);
    record.transport = capacity_clean_key(ctx.transport, "unknown_transport", 64);
    record.route = capacity_clean_key(ctx.route, "unknown_route", 96);
    record.method = capacity_clean_key(ctx.method, "tools/call", 96);
    record.principal = mcp_tool_principal_key(ctx.principal_id);
    record.session = mcp_tool_session_key(ctx.session_id);
    record.target = mcp_tool_target_key(ctx.target_id, ctx.target_pid);
    record.domain = capacity_domain_key(ctx.domain);
    record.lane = mcp_tool_lane_key(prediction.lane.empty() ? ctx.lane : prediction.lane);
    record.priority = mcp_tool_priority_key(prediction.priority_name);
    record.tool = capacity_clean_key(ctx.tool_name, "unknown_tool", 96);
    record.classification = capacity_clean_key(prediction.classification, "unclassified", 64);
    record.action = capacity_clean_key(ctx.action, "default", 96);
    record.target_pid = ctx.target_pid;
    record.cost = prediction.cost_units;
    record.admitted_tid = GetCurrentThreadId();
    record.read_only = prediction.read_only;
    record.mutating = prediction.mutating;
    record.long_running = prediction.long_running;
    record.session_manager = prediction.session_manager;
    record.driver_debugger = ctx.driver_debugger_tool;
    record.browser = ctx.browser_tool;
    record.scanner = ctx.scanner_tool || mcp_tool_is_scanner_domain(record.domain, record.tool);
    record.decompiler = ctx.decompiler_tool || mcp_tool_is_decompiler_domain(record.domain, record.tool);
    record.network = ctx.network_tool || mcp_tool_is_network_domain(record.domain, record.tool);
    record.background = ctx.background_command;
    record.batch_child = ctx.batch_child;
    return record;
}

static json mcp_tool_record_json(const mcp_tool_capacity_record_t& record)
{
    return {
        {"lease_id", record.lease_id},
        {"diagnostic_id", record.diagnostic_id},
        {"request_id", record.request_id},
        {"transport", record.transport},
        {"route", record.route},
        {"method", record.method},
        {"principal", record.principal},
        {"session", record.session},
        {"target", record.target},
        {"target_pid", record.target_pid},
        {"domain", record.domain},
        {"lane", record.lane},
        {"priority", record.priority},
        {"tool", record.tool},
        {"classification", record.classification},
        {"action", record.action},
        {"cost", record.cost},
        {"admitted_ms", record.admitted_ms},
        {"admitted_tid", static_cast<std::uint32_t>(record.admitted_tid)},
        {"read_only", record.read_only},
        {"mutating", record.mutating},
        {"long_running", record.long_running},
        {"session_manager", record.session_manager},
        {"driver_debugger", record.driver_debugger},
        {"browser", record.browser},
        {"scanner", record.scanner},
        {"decompiler", record.decompiler},
        {"network", record.network},
        {"background", record.background},
        {"batch_child", record.batch_child}
    };
}

struct mcp_tool_capacity_rejection_t
{
    bool rejected = false;
    std::string reason = "within_tool_capacity";
    std::string quota = "tool_admission";
    std::string scope = "global";
    std::uint64_t observed = 0;
    std::uint64_t limit = 0;
};

static void mcp_tool_mark_reject(mcp_tool_capacity_rejection_t& out,
                                 const char* reason,
                                 const char* quota,
                                 const char* scope,
                                 std::uint64_t observed,
                                 std::uint64_t limit)
{
    if (out.rejected)
        return;
    out.rejected = true;
    out.reason = reason ? reason : "tool_capacity_rejected";
    out.quota = quota ? quota : "tool_admission";
    out.scope = scope ? scope : "global";
    out.observed = observed;
    out.limit = limit;
}

static mcp_tool_capacity_rejection_t mcp_tool_evaluate_locked(const capacity_diag::prediction_t& prediction,
                                                              const mcp_tool_capacity_record_t& record)
{
    mcp_tool_capacity_rejection_t out;
    const auto& quotas = prediction.quotas;
    const bool p0 = prediction.priority == capacity_diag::priority_t::p0;
    const bool p1 = prediction.priority == capacity_diag::priority_t::p1;
    if (p0)
        return out;

    const auto principal_counts = mcp_tool_counts_for(g_mcp_tool_by_principal, record.principal);
    const auto session_counts = mcp_tool_counts_for(g_mcp_tool_by_session, record.session);
    const auto target_counts = mcp_tool_counts_for(g_mcp_tool_by_target, record.target);
    const auto domain_counts = mcp_tool_counts_for(g_mcp_tool_by_domain, record.domain);
    const auto class_counts = mcp_tool_counts_for(g_mcp_tool_by_class, "background");

    if (!p1) {
        if (g_mcp_tool_global_counts.active >= quotas.global_external_active_tools)
            mcp_tool_mark_reject(out, "global_external_active_tools", "global_external_active_tools", "global", g_mcp_tool_global_counts.active, quotas.global_external_active_tools);
        if (record.long_running) {
            if (principal_counts.long_active >= quotas.per_principal_active_long_running_tools)
                mcp_tool_mark_reject(out, "per_principal_active_long_running_tools", "per_principal_active_long_running_tools", "principal", principal_counts.long_active, quotas.per_principal_active_long_running_tools);
        } else if (principal_counts.active >= quotas.per_principal_active_normal_tools) {
            mcp_tool_mark_reject(out, "per_principal_active_normal_tools", "per_principal_active_normal_tools", "principal", principal_counts.active, quotas.per_principal_active_normal_tools);
        }
    }
    if (record.mutating && session_counts.mutate_active >= quotas.per_session_active_mutations)
        mcp_tool_mark_reject(out, "per_session_active_mutations", "per_session_active_mutations", "session", session_counts.mutate_active, quotas.per_session_active_mutations);
    if (record.read_only && session_counts.read_active >= quotas.per_session_active_read_only_tools)
        mcp_tool_mark_reject(out, "per_session_active_read_only_tools", "per_session_active_read_only_tools", "session", session_counts.read_active, quotas.per_session_active_read_only_tools);
    if (record.driver_debugger && target_counts.driver_debugger_active >= quotas.per_target_driver_debugger_active_tools)
        mcp_tool_mark_reject(out, "per_target_driver_debugger_active_tools", "per_target_driver_debugger_active_tools", "target", target_counts.driver_debugger_active, quotas.per_target_driver_debugger_active_tools);
    if (record.mutating && domain_counts.mutate_active >= quotas.per_domain_mutating_active_tools)
        mcp_tool_mark_reject(out, "per_domain_mutating_active_tools", "per_domain_mutating_active_tools", "domain", domain_counts.mutate_active, quotas.per_domain_mutating_active_tools);
    if (record.background) {
        if (principal_counts.background_active >= quotas.active_background_command_sessions_per_principal)
            mcp_tool_mark_reject(out, "active_background_command_sessions_per_principal", "active_background_command_sessions_per_principal", "principal_background_command", principal_counts.background_active, quotas.active_background_command_sessions_per_principal);
        if (class_counts.background_active >= quotas.global_active_background_command_sessions)
            mcp_tool_mark_reject(out, "global_active_background_command_sessions", "global_active_background_command_sessions", "global_background_command", class_counts.background_active, quotas.global_active_background_command_sessions);
    }
    return out;
}

static json mcp_tool_rejection_json(const capacity_diag::prediction_t& prediction,
                                    const mcp_tool_capacity_record_t& record,
                                    const mcp_tool_capacity_rejection_t& rejection)
{
    json capacity = capacity_diag::prediction_json(prediction);
    capacity["phase4_enforced"] = true;
    capacity["diagnostics_only"] = false;
    capacity["enforcement_enabled"] = true;
    capacity["tool_admission"] = {
        {"decision", "reject"},
        {"disposition", "not_started"},
        {"reason", rejection.reason},
        {"quota", rejection.quota},
        {"scope", rejection.scope},
        {"observed", rejection.observed},
        {"limit", rejection.limit},
        {"lease_candidate", mcp_tool_record_json(record)}
    };
    return {
        {"code", "MCP_TOOL_CAPACITY_REJECT"},
        {"message", "MCP tool capacity exhausted; tool was not started."},
        {"disposition", "not_started"},
        {"retry_after_ms", 100},
        {"reason", rejection.reason},
        {"quota", rejection.quota},
        {"scope", rejection.scope},
        {"observed", rejection.observed},
        {"limit", rejection.limit},
        {"diagnostic_id", record.diagnostic_id},
        {"request_id", record.request_id},
        {"principal", record.principal},
        {"session", record.session},
        {"target", record.target},
        {"target_pid", record.target_pid},
        {"domain", record.domain},
        {"lane", record.lane},
        {"priority", record.priority},
        {"tool", record.tool},
        {"capacity", std::move(capacity)}
    };
}

class mcp_tool_capacity_lease_t
{
public:
    mcp_tool_capacity_lease_t() = default;
    mcp_tool_capacity_lease_t(const mcp_tool_capacity_lease_t&) = delete;
    mcp_tool_capacity_lease_t& operator=(const mcp_tool_capacity_lease_t&) = delete;

    mcp_tool_capacity_lease_t(mcp_tool_capacity_lease_t&& other) noexcept
    {
        move_from(other);
    }

    mcp_tool_capacity_lease_t& operator=(mcp_tool_capacity_lease_t&& other) noexcept
    {
        if (this != &other) {
            release("move_assign");
            move_from(other);
        }
        return *this;
    }

    ~mcp_tool_capacity_lease_t()
    {
        release("scope_exit");
    }

    bool active() const noexcept
    {
        return active_;
    }

    std::uint64_t id() const noexcept
    {
        return record_.lease_id;
    }

    json identity_json() const
    {
        return mcp_tool_record_json(record_);
    }

    void activate(mcp_tool_capacity_record_t record) noexcept
    {
        record_ = std::move(record);
        active_ = true;
    }

    void release(const char* reason) noexcept
    {
        if (!active_)
            return;
        mcp_tool_capacity_record_t record = record_;
        bool found = false;
        bool cleanup_released = false;
        {
            std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx);
            auto it = g_mcp_tool_active_leases.find(record.lease_id);
            if (it != g_mcp_tool_active_leases.end()) {
                record = it->second;
                mcp_tool_remove_active_locked(record);
                g_mcp_tool_active_leases.erase(it);
                found = true;
            } else {
                auto cleanup_it = g_mcp_tool_cleanup_released_leases.find(record.lease_id);
                if (cleanup_it != g_mcp_tool_cleanup_released_leases.end()) {
                    g_mcp_tool_cleanup_released_leases.erase(cleanup_it);
                    cleanup_released = true;
                }
            }
        }
        active_ = false;
        if (cleanup_released)
            return;
        if (found)
            g_mcp_tool_leases_released.fetch_add(1u, std::memory_order_acq_rel);
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t age = now >= record.admitted_ms ? now - record.admitted_ms : 0;
        diag::log_tagged_fmt("mcp_srv",
            "MCP-TOOL-LEASE-RELEASE lease=%llu reason=%s found=%d diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' target_pid=%u tool='%s' domain='%s' lane=%s priority=%s cost=%u read_only=%d mutating=%d long_running=%d driver_debugger=%d browser=%d scanner=%d decompiler=%d network=%d background=%d age_ms=%llu pid=%lu tid=%lu",
            static_cast<unsigned long long>(record.lease_id),
            reason ? reason : "scope_exit",
            found ? 1 : 0,
            record.diagnostic_id.c_str(),
            record.request_id.c_str(),
            record.transport.c_str(),
            record.route.c_str(),
            record.method.c_str(),
            record.principal.c_str(),
            record.session.c_str(),
            record.target.c_str(),
            record.target_pid,
            record.tool.c_str(),
            record.domain.c_str(),
            record.lane.c_str(),
            record.priority.c_str(),
            record.cost,
            record.read_only ? 1 : 0,
            record.mutating ? 1 : 0,
            record.long_running ? 1 : 0,
            record.driver_debugger ? 1 : 0,
            record.browser ? 1 : 0,
            record.scanner ? 1 : 0,
            record.decompiler ? 1 : 0,
            record.network ? 1 : 0,
            record.background ? 1 : 0,
            static_cast<unsigned long long>(age),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }

private:
    void move_from(mcp_tool_capacity_lease_t& other) noexcept
    {
        record_ = std::move(other.record_);
        active_ = other.active_;
        other.active_ = false;
    }

    mcp_tool_capacity_record_t record_;
    bool active_ = false;
};

static void mcp_tool_log_cleanup_release(const mcp_tool_capacity_record_t& record, const char* reason) noexcept
{
    const std::uint64_t now = mcp_now_ms();
    const std::uint64_t age = now >= record.admitted_ms ? now - record.admitted_ms : 0;
    diag::log_tagged_fmt("mcp_srv",
        "MCP-TOOL-LEASE-RELEASE lease=%llu reason=%s found=1 diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' target_pid=%u tool='%s' domain='%s' lane=%s priority=%s cost=%u read_only=%d mutating=%d long_running=%d driver_debugger=%d browser=%d scanner=%d decompiler=%d network=%d background=%d age_ms=%llu pid=%lu tid=%lu",
        static_cast<unsigned long long>(record.lease_id),
        reason ? reason : "shutdown_cleanup",
        record.diagnostic_id.c_str(),
        record.request_id.c_str(),
        record.transport.c_str(),
        record.route.c_str(),
        record.method.c_str(),
        record.principal.c_str(),
        record.session.c_str(),
        record.target.c_str(),
        record.target_pid,
        record.tool.c_str(),
        record.domain.c_str(),
        record.lane.c_str(),
        record.priority.c_str(),
        record.cost,
        record.read_only ? 1 : 0,
        record.mutating ? 1 : 0,
        record.long_running ? 1 : 0,
        record.driver_debugger ? 1 : 0,
        record.browser ? 1 : 0,
        record.scanner ? 1 : 0,
        record.decompiler ? 1 : 0,
        record.network ? 1 : 0,
        record.background ? 1 : 0,
        static_cast<unsigned long long>(age),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

static void mcp_tool_release_all_capacity_leases(const char* reason) noexcept
{
    std::vector<mcp_tool_capacity_record_t> records;
    {
        std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx);
        records.reserve(g_mcp_tool_active_leases.size());
        for (const auto& kv : g_mcp_tool_active_leases) {
            records.push_back(kv.second);
            mcp_tool_remove_active_locked(kv.second);
            g_mcp_tool_cleanup_released_leases.insert(kv.first);
        }
        g_mcp_tool_active_leases.clear();
    }
    if (records.empty())
        return;
    g_mcp_tool_leases_released.fetch_add(static_cast<std::uint64_t>(records.size()), std::memory_order_acq_rel);
    for (const auto& record : records)
        mcp_tool_log_cleanup_release(record, reason);
}

static bool mcp_tool_try_acquire_capacity(const capacity_diag::prediction_t& prediction,
                                          std::uint64_t admitted_ms,
                                          mcp_tool_capacity_lease_t* out,
                                          json* rejection_json)
{
    if (!out)
        return false;
    mcp_tool_capacity_record_t record = mcp_tool_record_from_prediction(prediction, admitted_ms);
    mcp_tool_capacity_rejection_t rejection;
    std::uint64_t active_global_after = 0;
    {
        std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx);
        rejection = mcp_tool_evaluate_locked(prediction, record);
        if (rejection.rejected) {
            mcp_tool_add_rejected_locked(record);
            g_mcp_tool_calls_rejected.fetch_add(1u, std::memory_order_acq_rel);
        } else {
            mcp_tool_add_active_locked(record);
            active_global_after = g_mcp_tool_global_counts.active;
            g_mcp_tool_leases_acquired.fetch_add(1u, std::memory_order_acq_rel);
        }
    }
    if (rejection.rejected) {
        json data = mcp_tool_rejection_json(prediction, record, rejection);
        if (rejection_json)
            *rejection_json = data;
        diag::log_tagged_fmt("mcp_srv",
            "MCP-TOOL-REJECT lease_candidate=%llu diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' target_pid=%u tool='%s' domain='%s' lane=%s priority=%s cost=%u reason=%s quota=%s scope=%s observed=%llu limit=%llu disposition=not_started read_only=%d mutating=%d long_running=%d driver_debugger=%d browser=%d scanner=%d decompiler=%d network=%d background=%d pid=%lu tid=%lu",
            static_cast<unsigned long long>(record.lease_id),
            record.diagnostic_id.c_str(),
            record.request_id.c_str(),
            record.transport.c_str(),
            record.route.c_str(),
            record.method.c_str(),
            record.principal.c_str(),
            record.session.c_str(),
            record.target.c_str(),
            record.target_pid,
            record.tool.c_str(),
            record.domain.c_str(),
            record.lane.c_str(),
            record.priority.c_str(),
            record.cost,
            rejection.reason.c_str(),
            rejection.quota.c_str(),
            rejection.scope.c_str(),
            static_cast<unsigned long long>(rejection.observed),
            static_cast<unsigned long long>(rejection.limit),
            record.read_only ? 1 : 0,
            record.mutating ? 1 : 0,
            record.long_running ? 1 : 0,
            record.driver_debugger ? 1 : 0,
            record.browser ? 1 : 0,
            record.scanner ? 1 : 0,
            record.decompiler ? 1 : 0,
            record.network ? 1 : 0,
            record.background ? 1 : 0,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    out->activate(record);
    diag::log_tagged_fmt("mcp_srv",
        "MCP-TOOL-ADMIT lease=%llu diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' target_pid=%u tool='%s' domain='%s' lane=%s priority=%s cost=%u read_only=%d mutating=%d long_running=%d session_manager=%d driver_debugger=%d browser=%d scanner=%d decompiler=%d network=%d background=%d batch_child=%d active_global=%llu limit_global=%zu pid=%lu tid=%lu",
        static_cast<unsigned long long>(record.lease_id),
        record.diagnostic_id.c_str(),
        record.request_id.c_str(),
        record.transport.c_str(),
        record.route.c_str(),
        record.method.c_str(),
        record.principal.c_str(),
        record.session.c_str(),
        record.target.c_str(),
        record.target_pid,
        record.tool.c_str(),
        record.domain.c_str(),
        record.lane.c_str(),
        record.priority.c_str(),
        record.cost,
        record.read_only ? 1 : 0,
        record.mutating ? 1 : 0,
        record.long_running ? 1 : 0,
        record.session_manager ? 1 : 0,
        record.driver_debugger ? 1 : 0,
        record.browser ? 1 : 0,
        record.scanner ? 1 : 0,
        record.decompiler ? 1 : 0,
        record.network ? 1 : 0,
        record.background ? 1 : 0,
        record.batch_child ? 1 : 0,
        static_cast<unsigned long long>(active_global_after),
        prediction.quotas.global_external_active_tools,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

static void mcp_tool_bypass_audit(const capacity_diag::prediction_t& prediction, const char* reason)
{
    const mcp_tool_capacity_record_t record = mcp_tool_record_from_prediction(prediction, mcp_now_ms());
    diag::log_tagged_fmt("mcp_srv",
        "MCP-TOOL-BYPASS-AUDIT reason=%s diag_id=%s request_id='%s' transport=%s route=%s method=%s principal='%s' session='%s' target='%s' target_pid=%u tool='%s' domain='%s' lane=%s priority=%s cost=%u external=0 source_visible=internal_trusted_callsite_contract user_input_consulted=0 broker_admission=bypassed disposition=handler_inline read_only=%d mutating=%d long_running=%d driver_debugger=%d browser=%d scanner=%d decompiler=%d network=%d background=%d pid=%lu tid=%lu",
        reason ? reason : "internal_trusted_call",
        record.diagnostic_id.c_str(),
        record.request_id.c_str(),
        record.transport.c_str(),
        record.route.c_str(),
        record.method.c_str(),
        record.principal.c_str(),
        record.session.c_str(),
        record.target.c_str(),
        record.target_pid,
        record.tool.c_str(),
        record.domain.c_str(),
        record.lane.c_str(),
        record.priority.c_str(),
        record.cost,
        record.read_only ? 1 : 0,
        record.mutating ? 1 : 0,
        record.long_running ? 1 : 0,
        record.driver_debugger ? 1 : 0,
        record.browser ? 1 : 0,
        record.scanner ? 1 : 0,
        record.decompiler ? 1 : 0,
        record.network ? 1 : 0,
        record.background ? 1 : 0,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

static const char* mcp_tool_release_reason_from_result(const tool_result_t& tr, bool cancelled)
{
    if (cancelled)
        return "cancellation";
    const std::string code = lower_ascii(tr.error_code);
    const std::string text = lower_ascii(tr.text);
    if (code.find("seh") != std::string::npos)
        return "seh";
    if (code.find("timeout") != std::string::npos || code.find("deadline") != std::string::npos ||
        text.find("timed out") != std::string::npos || text.find("expired") != std::string::npos)
        return "timeout";
    if (code.find("cancel") != std::string::npos || text.find("cancel") != std::string::npos)
        return "cancellation";
    return tr.success ? "success" : "failure";
}

static capacity_diag::activity_counters_t mcp_tool_capacity_activity_for_context(const capacity_diag::request_context_t& ctx)
{
    capacity_diag::activity_counters_t counters;
    std::unique_lock<std::mutex> lk(g_mcp_tool_capacity_mtx, std::try_to_lock);
    if (!lk.owns_lock()) {
        counters.registry_lock_busy = true;
        return counters;
    }
    const std::string principal = ctx.principal_id.empty() ? std::string() : mcp_tool_principal_key(ctx.principal_id);
    const std::string session = ctx.session_id.empty() ? std::string() : mcp_tool_session_key(ctx.session_id);
    const std::string target = ctx.target_id.empty() && ctx.target_pid == 0 ? std::string() : mcp_tool_target_key(ctx.target_id, ctx.target_pid);
    const std::string domain = ctx.domain.empty() ? std::string() : capacity_domain_key(ctx.domain);
    for (const auto& item : g_mcp_tool_active_leases) {
        const auto& record = item.second;
        if (!principal.empty() && record.principal != principal)
            continue;
        ++counters.active_total;
        if (record.long_running)
            ++counters.active_long_running;
        else
            ++counters.active_normal;
        if (record.batch_child)
            ++counters.active_batch_children;
        if (record.background)
            ++counters.active_background_command_sessions;
        if (record.mutating && (session.empty() || record.session == session))
            ++counters.active_session_mutations;
        if (record.read_only && !session.empty() && record.session == session)
            ++counters.active_session_read_only;
        if (record.driver_debugger && !target.empty() && record.target == target)
            ++counters.active_target_driver_debugger;
        if (record.mutating && !domain.empty() && record.domain == domain)
            ++counters.active_domain_mutating;
    }
    return counters;
}

static json mcp_tool_counts_json(const mcp_tool_capacity_counts_t& c)
{
    return {
        {"active", c.active},
        {"rejected", c.rejected},
        {"read_active", c.read_active},
        {"read_rejected", c.read_rejected},
        {"mutate_active", c.mutate_active},
        {"mutate_rejected", c.mutate_rejected},
        {"long_active", c.long_active},
        {"long_rejected", c.long_rejected},
        {"driver_debugger_active", c.driver_debugger_active},
        {"driver_debugger_rejected", c.driver_debugger_rejected},
        {"browser_active", c.browser_active},
        {"browser_rejected", c.browser_rejected},
        {"scanner_active", c.scanner_active},
        {"scanner_rejected", c.scanner_rejected},
        {"decompiler_active", c.decompiler_active},
        {"decompiler_rejected", c.decompiler_rejected},
        {"network_active", c.network_active},
        {"network_rejected", c.network_rejected},
        {"background_active", c.background_active},
        {"background_rejected", c.background_rejected},
        {"oldest_active_ms", c.oldest_active_ms}
    };
}

static json mcp_tool_counts_map_json(const std::map<std::string, mcp_tool_capacity_counts_t>& counts, std::size_t max_items)
{
    std::vector<std::pair<std::string, mcp_tool_capacity_counts_t>> items;
    items.reserve(counts.size());
    for (const auto& kv : counts)
        items.push_back(kv);
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        const std::uint64_t ap = a.second.active + a.second.rejected + a.second.long_active + a.second.long_rejected + a.second.driver_debugger_active + a.second.driver_debugger_rejected + a.second.background_active + a.second.background_rejected;
        const std::uint64_t bp = b.second.active + b.second.rejected + b.second.long_active + b.second.long_rejected + b.second.driver_debugger_active + b.second.driver_debugger_rejected + b.second.background_active + b.second.background_rejected;
        if (ap != bp)
            return ap > bp;
        return a.first < b.first;
    });
    json arr = json::array();
    std::size_t emitted = 0;
    for (const auto& item : items) {
        if (emitted >= max_items)
            break;
        if (!mcp_tool_counts_has_pressure(item.second))
            continue;
        json row = mcp_tool_counts_json(item.second);
        row["key"] = item.first;
        arr.push_back(std::move(row));
        ++emitted;
    }
    return arr;
}

static mcp_tool_capacity_snapshot_t mcp_tool_capacity_snapshot()
{
    mcp_tool_capacity_snapshot_t out;
    out.timestamp_ms = mcp_now_ms();
    out.leases_acquired = g_mcp_tool_leases_acquired.load(std::memory_order_acquire);
    out.leases_released = g_mcp_tool_leases_released.load(std::memory_order_acquire);
    out.rejected_total = g_mcp_tool_calls_rejected.load(std::memory_order_acquire);
    std::unique_lock<std::mutex> lk(g_mcp_tool_capacity_mtx, std::try_to_lock);
    if (!lk.owns_lock()) {
        out.lock_busy = true;
        return out;
    }
    out.global = g_mcp_tool_global_counts;
    out.rejected_global = g_mcp_tool_rejected_global_counts;
    out.principals = g_mcp_tool_by_principal;
    out.sessions = g_mcp_tool_by_session;
    out.targets = g_mcp_tool_by_target;
    out.domains = g_mcp_tool_by_domain;
    out.lanes = g_mcp_tool_by_lane;
    out.priorities = g_mcp_tool_by_priority;
    out.tools = g_mcp_tool_by_tool;
    out.classes = g_mcp_tool_by_class;
    out.rejected_principals = g_mcp_tool_rejected_by_principal;
    out.rejected_sessions = g_mcp_tool_rejected_by_session;
    out.rejected_targets = g_mcp_tool_rejected_by_target;
    out.rejected_domains = g_mcp_tool_rejected_by_domain;
    out.rejected_lanes = g_mcp_tool_rejected_by_lane;
    out.rejected_priorities = g_mcp_tool_rejected_by_priority;
    out.rejected_tools = g_mcp_tool_rejected_by_tool;
    out.rejected_classes = g_mcp_tool_rejected_by_class;
    for (const auto& kv : g_mcp_tool_active_leases) {
        const auto& r = kv.second;
        const std::uint64_t age_ms = out.timestamp_ms >= r.admitted_ms ? out.timestamp_ms - r.admitted_ms : 0;
        if (out.global.oldest_active_ms < age_ms)
            out.global.oldest_active_ms = age_ms;
        mcp_pressure_contributor_t contributor;
        contributor.state = "active_tool_lease";
        contributor.executor = "tool_admission_broker";
        contributor.principal = r.principal;
        contributor.session_id = r.session;
        contributor.target_id = r.target;
        contributor.domain = r.domain;
        contributor.tool = r.tool;
        contributor.lane = r.lane;
        contributor.age_ms = age_ms;
        contributor.active_age_ms = age_ms;
        contributor.target_pid = r.target_pid;
        contributor.read_only = r.read_only;
        contributor.long_running = r.long_running;
        contributor.driver_debugger = r.driver_debugger;
        contributor.background_command = r.background;
        mcp_tool_add_contributor(out, std::move(contributor));
    }
    return out;
}

static json mcp_tool_capacity_health_snapshot(const capacity_diag::quota_set_t& quotas)
{
    const mcp_tool_capacity_snapshot_t snap = mcp_tool_capacity_snapshot();
    const auto p1_it = snap.priorities.find("P1");
    const auto p4_it = snap.priorities.find("P4");
    const auto p5_it = snap.priorities.find("P5");
    const std::uint64_t p1_active = p1_it == snap.priorities.end() ? 0 : p1_it->second.active;
    const std::uint64_t p4_active = p4_it == snap.priorities.end() ? 0 : p4_it->second.active;
    const std::uint64_t p5_active = p5_it == snap.priorities.end() ? 0 : p5_it->second.active;
    const bool p1_available = p1_active < static_cast<std::uint64_t>(quotas.p1_reserved_foreground_slots + quotas.per_principal_active_normal_tools);
    json out;
    out["phase"] = "phase4_tool_admission_enforced";
    out["lock_busy"] = snap.lock_busy;
    out["timestamp_ms"] = snap.timestamp_ms;
    out["rejected_total"] = snap.rejected_total;
    out["leases"] = {
        {"active", snap.global.active},
        {"acquired_total", snap.leases_acquired},
        {"released_total", snap.leases_released},
        {"rejected_total", snap.rejected_total},
        {"oldest_active_ms", snap.global.oldest_active_ms}
    };
    out["global"] = mcp_tool_counts_json(snap.global);
    out["rejected_global"] = mcp_tool_counts_json(snap.rejected_global);
    out["by_principal"] = mcp_tool_counts_map_json(snap.principals, 16);
    out["by_session"] = mcp_tool_counts_map_json(snap.sessions, 16);
    out["by_target"] = mcp_tool_counts_map_json(snap.targets, 16);
    out["by_domain"] = mcp_tool_counts_map_json(snap.domains, 16);
    out["by_lane"] = mcp_tool_counts_map_json(snap.lanes, 16);
    out["by_priority"] = mcp_tool_counts_map_json(snap.priorities, 8);
    out["by_tool"] = mcp_tool_counts_map_json(snap.tools, 16);
    out["by_class"] = mcp_tool_counts_map_json(snap.classes, 12);
    out["rejected_by_principal"] = mcp_tool_counts_map_json(snap.rejected_principals, 16);
    out["rejected_by_session"] = mcp_tool_counts_map_json(snap.rejected_sessions, 16);
    out["rejected_by_target"] = mcp_tool_counts_map_json(snap.rejected_targets, 16);
    out["rejected_by_domain"] = mcp_tool_counts_map_json(snap.rejected_domains, 16);
    out["rejected_by_lane"] = mcp_tool_counts_map_json(snap.rejected_lanes, 16);
    out["rejected_by_priority"] = mcp_tool_counts_map_json(snap.rejected_priorities, 8);
    out["rejected_by_tool"] = mcp_tool_counts_map_json(snap.rejected_tools, 16);
    out["rejected_by_class"] = mcp_tool_counts_map_json(snap.rejected_classes, 12);
    out["domain_classes"] = {
        {"long_running", {{"active", snap.global.long_active}, {"rejected", snap.global.long_rejected}}},
        {"driver_debugger", {{"active", snap.global.driver_debugger_active}, {"rejected", snap.global.driver_debugger_rejected}}},
        {"browser", {{"active", snap.global.browser_active}, {"rejected", snap.global.browser_rejected}}},
        {"scanner", {{"active", snap.global.scanner_active}, {"rejected", snap.global.scanner_rejected}}},
        {"decompiler", {{"active", snap.global.decompiler_active}, {"rejected", snap.global.decompiler_rejected}}},
        {"network", {{"active", snap.global.network_active}, {"rejected", snap.global.network_rejected}}},
        {"background", {{"active", snap.global.background_active}, {"rejected", snap.global.background_rejected}}}
    };
    out["top_pressure_contributors"] = mcp_capacity_contributors_json(snap.contributors);
    out["availability"] = {
        {"p0", true},
        {"p1", p1_available},
        {"p1_reserved_foreground_slots", quotas.p1_reserved_foreground_slots},
        {"p4_active", p4_active},
        {"p5_active", p5_active},
        {"p4_p5_active", p4_active + p5_active},
        {"p0_p1_protected_from_p4_p5", true}
    };
    diag::log_tagged_fmt("mcp_srv",
        "MCP-TOOL-LEASE-SNAPSHOT active=%llu rejected=%llu acquired=%llu released=%llu lock_busy=%d oldest_active_ms=%llu p1_available=%d p4_p5_active=%llu pid=%lu tid=%lu",
        static_cast<unsigned long long>(snap.global.active),
        static_cast<unsigned long long>(snap.rejected_total),
        static_cast<unsigned long long>(snap.leases_acquired),
        static_cast<unsigned long long>(snap.leases_released),
        snap.lock_busy ? 1 : 0,
        static_cast<unsigned long long>(snap.global.oldest_active_ms),
        p1_available ? 1 : 0,
        static_cast<unsigned long long>(p4_active + p5_active),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return out;
}

static json mcp_pressure_registry_json(const mcp_pressure_snapshot_t& p)
{
    return {
        {"lock_busy", p.lock_busy},
        {"principal_count", p.principal_count},
        {"session_count", p.session_count},
        {"queued", p.queued},
        {"active", p.active},
        {"queued_long_running", p.queued_long_running},
        {"active_long_running", p.active_long_running},
        {"principal_summary", p.principal_summary},
        {"session_summary", p.session_summary},
        {"domain_summary", p.domain_summary},
        {"lane_summary", p.lane_summary},
        {"executor_summary", p.executor_summary}
    };
}

template <typename QueueStats>
static json queue_stats_json(const QueueStats& s)
{
    return {
        {"alive", s.alive},
        {"shutting_down", s.shutting_down},
        {"pool_size", s.pool_size},
        {"workers", s.workers},
        {"pending", s.pending},
        {"active", s.active},
        {"post_attempts", s.post_attempts},
        {"posted", s.posted},
        {"rejected", s.rejected},
        {"started", s.started},
        {"finished", s.finished},
        {"oldest_active_ms", s.oldest_active_ms},
        {"active_labels", s.active_labels},
        {"top_cpu_labels", s.top_cpu_labels},
        {"healthy_long_lived", s.healthy_long_lived},
        {"hot_workers", s.hot_workers},
        {"not_queryable_workers", s.not_queryable_workers}
    };
}

static json command_stats_json(const command_sessions::stats_t& s)
{
    return {
        {"registry_lock_busy", s.registry_lock_busy},
        {"total", s.total},
        {"running", s.running},
        {"finished", s.finished},
        {"reader_active", s.reader_active},
        {"reader_done", s.reader_done},
        {"timed_out", s.timed_out},
        {"oldest_running_ms", s.oldest_running_ms},
        {"oldest_reader_active_ms", s.oldest_reader_active_ms},
        {"active_summary", s.active_summary}
    };
}

static json capacity_health_snapshot(const std::string& principal_id,
                                     const std::string& server_session_id,
                                     int port,
                                     const mcp_capacity_snapshot_state_t& executor_capacity)
{
    capacity_diag::request_context_t ctx = capacity_route_context("http", "/health", "health", principal_id, "mcp-health-capacity", "health");
    const auto& cfg = mcp_concurrency_config();
    const capacity_diag::quota_set_t quotas = capacity_diag::make_quota_set(cfg.tool_worker_threads, cfg.http_worker_threads, cfg.http_max_queued_requests, cfg.max_concurrent_streams, cfg.max_concurrent_streams_per_principal);
    const capacity_diag::pressure_snapshot_t pressure = capacity_pressure_snapshot(ctx);
    capacity_diag::prediction_t prediction = capacity_diag::predict(ctx, quotas, pressure);
    log_capacity_snapshot_events("health_capacity_snapshot", prediction);
    const std::uint64_t now = executor_capacity.timestamp_ms != 0 ? executor_capacity.timestamp_ms : mcp_now_ms();
    const auto command_stats = command_sessions::stats();
    const auto general = runtime_queue_stats(runtime_queue_family_t::general);
    const auto service = runtime_queue_stats(runtime_queue_family_t::service);
    const auto critical = runtime_queue_stats(runtime_queue_family_t::critical);
    const mcp_pressure_snapshot_t pressure_registry = mcp_pressure_snapshot();
    const json activity = capacity_diag::activity_snapshot_json(now);
    const bool downstream_pressure =
        general.pending > (std::max<std::size_t>)(general.workers * 4u, 8u) ||
        service.pending > (std::max<std::size_t>)(service.workers * 4u, 8u) ||
        critical.pending > (std::max<std::size_t>)(critical.workers * 4u, 4u) ||
        (general.pending != 0 && general.active >= general.workers && general.workers != 0) ||
        (service.pending != 0 && service.active >= service.workers && service.workers != 0) ||
        (critical.pending != 0 && critical.active >= critical.workers && critical.workers != 0);
    const json downstream_snapshot_json =
        mcp_standalone::downstream::governor_t::instance().snapshot_json();
    const json downstream_quota_json =
        mcp_standalone::downstream::governor_t::instance().quota_json();
    auto downstream_kind_active = [&downstream_snapshot_json](const char* kind_name) -> std::size_t {
        if (!downstream_snapshot_json.contains("by_kind") || !downstream_snapshot_json["by_kind"].is_array())
            return 0;
        for (const auto& entry : downstream_snapshot_json["by_kind"]) {
            if (entry.value("kind", std::string()) == kind_name)
                return entry.value("active", 0);
        }
        return 0;
    };
    auto downstream_kind_limit = [&downstream_quota_json](const char* kind_name) -> std::size_t {
        if (!downstream_quota_json.contains(kind_name))
            return 0;
        return downstream_quota_json[kind_name].value("global_active", 0);
    };
    json out;
    out["phase"] = "phase7_downstream_producer_governance";
    out["enforcement_enabled"] = true;
    out["phase2_diagnostics"] = {
        {"phase", "phase2_diagnostics_only"},
        {"enforcement_enabled", false}
    };
    out["identity"] = {
        {"timestamp_ms", now},
        {"pid", static_cast<std::uint32_t>(GetCurrentProcessId())},
        {"tid", static_cast<std::uint32_t>(GetCurrentThreadId())},
        {"server", SERVER_NAME},
        {"version", SERVER_VERSION},
        {"port", port},
        {"server_session_hash", mcp_identity_hash_text(server_session_id)},
        {"request_principal", principal_id},
        {"request_session_hash", current_mcp_session_hash()},
        {"request_transport", current_mcp_transport()},
        {"request_route", current_mcp_route()}
    };
    out["quotas"] = capacity_diag::quotas_json(quotas);
    out["pressure"] = capacity_diag::pressure_json(pressure);
    out["executor_pressure"] = {
        {"executor_count", executor_capacity.executor_count},
        {"executor_registry_busy", executor_capacity.executor_registry_busy},
        {"executor_snapshot_busy", executor_capacity.executor_snapshot_busy},
        {"task_meta_busy", executor_capacity.task_meta_busy},
        {"queued_samples", executor_capacity.queued_samples},
        {"active_samples", executor_capacity.active_samples},
        {"queued_samples_truncated", executor_capacity.queued_samples_truncated},
        {"active_samples_truncated", executor_capacity.active_samples_truncated},
        {"global", mcp_capacity_counts_json(executor_capacity.global)},
        {"per_principal", mcp_capacity_counts_map_json(executor_capacity.principals, 16)},
        {"per_session", mcp_capacity_counts_map_json(executor_capacity.sessions, 16)},
        {"per_domain", mcp_capacity_counts_map_json(executor_capacity.domains, 16)},
        {"per_target_driver_debugger", mcp_capacity_counts_map_json(executor_capacity.driver_targets, 16)}
    };
    out["global_external_tools"] = {
        {"active", pressure.global_external_active_tools},
        {"queued", pressure.global_external_queued_tools},
        {"executor_sampled_active", executor_capacity.global.active},
        {"executor_sampled_queued", executor_capacity.global.queued}
    };
    const json ingress_admission = mcp_ingress_health_snapshot(quotas);
    out["http_ingress"] = {
        {"global_active", pressure.global_ingress_active_requests},
        {"global_queued", pressure.global_ingress_queued_requests},
        {"per_principal_active", pressure.per_principal_ingress_active_requests},
        {"per_principal_queued", pressure.per_principal_ingress_queued_requests},
        {"global_streams", pressure.global_ingress_streams},
        {"per_principal_streams", pressure.per_principal_ingress_streams},
        {"active_cap", quotas.global_ingress_active_requests},
        {"queued_cap", quotas.global_ingress_queued_requests},
        {"per_principal_active_cap", quotas.per_principal_ingress_active_requests},
        {"per_principal_queued_cap", quotas.per_principal_ingress_queued_requests},
        {"global_stream_cap", quotas.global_ingress_streams},
        {"per_principal_stream_cap", quotas.per_principal_ingress_streams}
    };
    out["http_ingress"]["per_route"] = ingress_admission.value("per_route", json::array());
    out["http_ingress"]["per_route_principal"] = ingress_admission.value("per_route_principal", json::array());
    out["ingress_admission"] = ingress_admission;
    const json tool_admission = mcp_tool_capacity_health_snapshot(quotas);
    out["tool_admission"] = tool_admission;
    const json reserved_lanes = mcp_reserved_lanes_health_snapshot();
    out["reserved_lanes"] = reserved_lanes;
    out["availability"] = {
        {"health", reserved_lanes["availability"].value("health", false)},
        {"cancellation", reserved_lanes["availability"].value("cancellation", false)},
        {"liveness", reserved_lanes["availability"].value("liveness", false)},
        {"shutdown", reserved_lanes["availability"].value("shutdown", false)},
        {"p0", reserved_lanes["availability"].value("p0", false)}
    };
    out["reserved_lane_availability"] = out["availability"];
    out["rejection_counters"] = {
        {"ingress", ingress_admission.value("rejection_counters", json::array())},
        {"ingress_total", ingress_admission.value("rejections_total", 0)},
        {"tool_admission_total", tool_admission.value("rejected_total", 0)},
        {"batch_children", g_mcp_batch_children_rejected.load(std::memory_order_acquire)},
        {"reserved_lanes", {
            {"health", reserved_lanes["lanes"]["health"].value("rejected", 0)},
            {"cancellation", reserved_lanes["lanes"]["cancellation"].value("rejected", 0)},
            {"liveness", reserved_lanes["lanes"]["liveness"].value("rejected", 0)},
            {"shutdown", reserved_lanes["lanes"]["shutdown"].value("rejected", 0)}
        }}
    };
    {
        const std::uint64_t ds_total_rejected = downstream_snapshot_json.value("total_rejected", 0ULL);
        out["rejection_counters"]["downstream_total"] = ds_total_rejected;
        json ds_kind_rejections = json::array();
        if (downstream_snapshot_json.contains("by_kind") && downstream_snapshot_json["by_kind"].is_array()) {
            for (const auto& entry : downstream_snapshot_json["by_kind"]) {
                ds_kind_rejections.push_back({
                    {"kind", entry.value("kind", std::string())},
                    {"rejected", entry.value("rejected", 0)},
                    {"total_rejected", entry.value("total_rejected", 0ULL)}
                });
            }
        }
        out["rejection_counters"]["downstream_by_kind"] = ds_kind_rejections;
        if (downstream_snapshot_json.contains("rejection_by_reason") && downstream_snapshot_json["rejection_by_reason"].is_array()) {
            out["rejection_counters"]["downstream_by_reason"] = downstream_snapshot_json["rejection_by_reason"];
        } else {
            out["rejection_counters"]["downstream_by_reason"] = json::array();
        }
    }
    out["streams"] = stream_capacity_health_snapshot();
    out["long_running"] = {
        {"activity_active", activity.value("active_long_running", 0)},
        {"executor_active", executor_capacity.global.long_active},
        {"executor_queued", executor_capacity.global.long_queued},
        {"registry_active", pressure_registry.active_long_running},
        {"registry_queued", pressure_registry.queued_long_running}
    };
    out["batch_fanout"] = {
        {"batches_seen", g_mcp_batch_seq.load(std::memory_order_acquire)},
        {"active_children", pressure.batch_active_children},
        {"queued_children", pressure.batch_queued_children},
        {"reserved_children_total", g_mcp_batch_children_reserved.load(std::memory_order_acquire)},
        {"rejected_children_total", g_mcp_batch_children_rejected.load(std::memory_order_acquire)},
        {"executor_active_children", executor_capacity.global.batch_active},
        {"executor_queued_children", executor_capacity.global.batch_queued}
    };
    out["background_commands"] = command_stats_json(command_stats);
    out["downstream_queues"] = {
        {"general", queue_stats_json(general)},
        {"service", queue_stats_json(service)},
        {"critical", queue_stats_json(critical)}
    };
    out["downstream_producers"] = {
        {"snapshot", downstream_snapshot_json},
        {"quotas", downstream_quota_json}
    };
    out["pressure_registry"] = mcp_pressure_registry_json(pressure_registry);
    out["oldest_age_ms"] = {
        {"active", executor_capacity.global.oldest_active_ms},
        {"queued", executor_capacity.global.oldest_queued_ms},
        {"background_command_running", command_stats.oldest_running_ms},
        {"background_reader_active", command_stats.oldest_reader_active_ms},
        {"downstream_general_active", general.oldest_active_ms},
        {"downstream_service_active", service.oldest_active_ms},
        {"downstream_critical_active", critical.oldest_active_ms},
        {"downstream_oldest_active", downstream_snapshot_json.value("total_active", 0) > 0
            ? [&]() -> std::uint64_t {
                std::uint64_t oldest = 0;
                if (downstream_snapshot_json.contains("by_kind") && downstream_snapshot_json["by_kind"].is_array()) {
                    for (const auto& entry : downstream_snapshot_json["by_kind"]) {
                        const auto age = entry.value("oldest_active_ms", 0ULL);
                        if (age > oldest) oldest = age;
                    }
                }
                return oldest;
            }() : 0ULL}
    };
    out["overload_flags"] = {
        {"global_external_active", pressure.global_external_active_tools >= quotas.global_external_active_tools},
        {"global_external_queued", pressure.global_external_queued_tools >= quotas.global_external_queued_tools},
        {"http_ingress_active", pressure.global_ingress_active_requests >= quotas.global_ingress_active_requests},
        {"http_ingress_queued", pressure.global_ingress_queued_requests >= quotas.global_ingress_queued_requests},
        {"http_ingress_principal_active", pressure.per_principal_ingress_active_requests >= quotas.per_principal_ingress_active_requests},
        {"http_ingress_principal_queued", pressure.per_principal_ingress_queued_requests >= quotas.per_principal_ingress_queued_requests},
        {"http_ingress_streams", pressure.global_ingress_streams >= quotas.global_ingress_streams || pressure.per_principal_ingress_streams >= quotas.per_principal_ingress_streams},
        {"long_running", pressure_registry.active_long_running >= quotas.per_principal_active_long_running_tools || executor_capacity.global.long_active >= quotas.per_principal_active_long_running_tools},
        {"batch_fanout", pressure.batch_active_children >= quotas.active_batch_children_per_principal || pressure.batch_queued_children >= quotas.queued_batch_children_per_principal},
        {"background_commands", command_stats.running >= quotas.global_active_background_command_sessions || command_stats.reader_active >= quotas.global_active_background_command_sessions},
        {"driver_debugger_target", executor_capacity.global.driver_debugger_active >= quotas.per_target_driver_debugger_active_tools},
        {"downstream_queue_pressure", downstream_pressure},
        {"http_stream_pressure", pressure.active_streams >= cfg.max_concurrent_streams},
        {"snapshot_partial", executor_capacity.executor_registry_busy != 0 || executor_capacity.executor_snapshot_busy != 0 || executor_capacity.task_meta_busy != 0 || command_stats.registry_lock_busy || pressure_registry.lock_busy || activity.value("registry_lock_busy", false)}
    };
    out["overload_flags"]["downstream_background_commands"] =
        downstream_kind_active("background_command") >= downstream_kind_limit("background_command");
    out["overload_flags"]["downstream_camoufox_longops"] =
        downstream_kind_active("camoufox_longop") >= downstream_kind_limit("camoufox_longop");
    out["overload_flags"]["downstream_driver_debugger"] =
        downstream_kind_active("driver_debugger") >= downstream_kind_limit("driver_debugger");
    out["overload_flags"]["downstream_scanner"] =
        downstream_kind_active("scanner") >= downstream_kind_limit("scanner");
    out["overload_flags"]["downstream_decompiler"] =
        downstream_kind_active("decompiler") >= downstream_kind_limit("decompiler");
    out["overload_flags"]["downstream_pdb"] =
        downstream_kind_active("pdb_parser") >= downstream_kind_limit("pdb_parser");
    out["overload_flags"]["downstream_broad_enum"] =
        downstream_kind_active("broad_enumeration") >= downstream_kind_limit("broad_enumeration");
    out["overload_flags"]["downstream_burp_network"] =
        downstream_kind_active("burp_network") >= downstream_kind_limit("burp_network");
    out["overload_flags"]["downstream_api_monitor"] =
        downstream_kind_active("api_monitor") >= downstream_kind_limit("api_monitor");
    out["top_pressure_contributors"] = mcp_capacity_contributors_json(executor_capacity.contributors);
    {
        json ds_contributors = json::array();
        if (downstream_snapshot_json.contains("per_principal") && downstream_snapshot_json["per_principal"].is_array()) {
            for (const auto& entry : downstream_snapshot_json["per_principal"]) {
                ds_contributors.push_back({
                    {"scope", "downstream_principal"},
                    {"id", entry.value("principal", std::string())},
                    {"active", entry.value("active", 0)}
                });
            }
        }
        if (downstream_snapshot_json.contains("per_target") && downstream_snapshot_json["per_target"].is_array()) {
            for (const auto& entry : downstream_snapshot_json["per_target"]) {
                ds_contributors.push_back({
                    {"scope", "downstream_target"},
                    {"id", entry.value("target", std::string())},
                    {"active", entry.value("active", 0)}
                });
            }
        }
        if (downstream_snapshot_json.contains("per_domain") && downstream_snapshot_json["per_domain"].is_array()) {
            for (const auto& entry : downstream_snapshot_json["per_domain"]) {
                ds_contributors.push_back({
                    {"scope", "downstream_domain"},
                    {"id", entry.value("domain", std::string())},
                    {"active", entry.value("active", 0)}
                });
            }
        }
        out["downstream_pressure_contributors"] = ds_contributors;
        if (out["top_pressure_contributors"].is_array()) {
            for (const auto& c : ds_contributors)
                out["top_pressure_contributors"].push_back(c);
        }
    }
    out["health_lane_prediction"] = capacity_diag::prediction_json(prediction);
    out["activity"] = activity;
    out["recent_predictions"] = capacity_diag::recent_snapshot_json();
    return out;
}

static tool_result_t invoke_tool_handler_unlocked(
    const std::string& tool_name,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics = nullptr)
{
    const std::uint64_t start = mcp_now_ms();
    try {
        tool_result_t result = handler(arguments);
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        return result;
    } catch (const std::exception& e) {
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call exception tool='%s' what='%s'",
            tool_name.c_str(), e.what());
        return tool_result_t::error(std::string("Tool threw exception: ") + e.what());
    } catch (...) {
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_exception tool='%s'", tool_name.c_str());
        return tool_result_t::error("Tool threw unknown exception");
    }
}

static tool_result_t invoke_tool_handler_guarded(
    const std::string& tool_name,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics,
    const char* lane,
    active_session_owner_guard_t* owner_guard = nullptr)
{
    const std::uint64_t start = mcp_now_ms();
    tool_result_t result;
    bool completed = false;
    if (owner_guard)
        owner_guard->set_phase("handler_enter");
    std::function<void()> guarded = [&]() {
        result = invoke_tool_handler_unlocked(tool_name, arguments, handler, metrics);
        completed = true;
    };
    const DWORD seh_code = aida::infra::win_thread::run_function_seh_guarded(guarded);
    if (seh_code != 0) {
        const std::uint64_t elapsed_ms = mcp_now_ms() >= start ? mcp_now_ms() - start : 0;
        if (metrics)
            metrics->handler_elapsed_ms += elapsed_ms;
        if (owner_guard)
            owner_guard->note_seh(seh_code, elapsed_ms);
        json details = {
            {"tool", tool_name},
            {"lane", lane ? lane : ""},
            {"diagnostic_id", current_call_diag_id()},
            {"seh_code", static_cast<std::uint32_t>(seh_code)},
            {"seh_code_hex", hex32_string(seh_code)},
            {"pid", GetCurrentProcessId()},
            {"tid", GetCurrentThreadId()},
            {"handler_elapsed_ms", elapsed_ms},
            {"deadline_ms", current_call_deadline_ms()},
            {"cancelled", current_call_cancelled()},
            {"completed", completed}
        };
        const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
        append_active_session_owner_fields(details, owner);
        diag::log_tagged_fmt("mcp_srv",
            "handle_tools_call_seh tool='%s' lane=%s diag_id=%s code=0x%08lX elapsed_ms=%llu pid=%lu tid=%lu deadline_ms=%llu cancelled=%d owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu completed=%d",
            tool_name.c_str(),
            lane ? lane : "",
            current_call_diag_id(),
            static_cast<unsigned long>(seh_code),
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(current_call_deadline_ms()),
            current_call_cancelled() ? 1 : 0,
            owner.tool.c_str(),
            owner.lane.c_str(),
            owner.diag_id.c_str(),
            static_cast<unsigned long>(owner.pid),
            static_cast<unsigned long>(owner.tid),
            static_cast<unsigned long long>(owner.owner_age_ms),
            owner.phase.c_str(),
            owner.shared_owner_count,
            completed ? 1 : 0);
        return tool_result_t::error("Tool handler raised a structured exception and was contained fail-closed.", "tool_handler_seh", details);
    }
    if (owner_guard)
        owner_guard->set_phase("handler_exit");
    if (owner_guard && !owner_guard->commit_eligible("handler_exit")) {
        const std::uint64_t elapsed_ms = mcp_now_ms() >= start ? mcp_now_ms() - start : 0;
        json details = {
            {"tool", tool_name},
            {"lane", lane ? lane : ""},
            {"diagnostic_id", current_call_diag_id()},
            {"request_id", current_call_request_id()},
            {"handler_elapsed_ms", elapsed_ms},
            {"deadline_ms", current_call_deadline_ms()},
            {"cancelled", current_call_cancelled()},
            {"disposition", "discarded_after_fence"}
        };
        append_active_session_owner_fields(details, active_session_owner_snapshot());
        diag::log_tagged_fmt("mcp_srv",
            "MCP-LATE-RESULT-DISCARDED tool='%s' lane=%s diag_id=%s request_id=%s elapsed_ms=%llu cancelled=%d disposition=discarded_after_fence",
            tool_name.c_str(),
            lane ? lane : "",
            current_call_diag_id(),
            current_call_request_id(),
            static_cast<unsigned long long>(elapsed_ms),
            current_call_cancelled() ? 1 : 0);
        return tool_result_t::error("MCP tool result discarded because the operation lease is stale, cancelled, fenced, or released.", "MCP_LATE_RESULT_DISCARDED", details);
    }
    return result;
}

static bool active_session_policy_testlab_diag()
{
    const char* diag_id = current_call_diag_id();
    return diag_id && std::strncmp(diag_id, "testlab-", 8) == 0;
}

static std::uint64_t active_session_policy_testlab_hold_ms(const std::string& tool_name, const json& arguments)
{
    if (tool_name != "thread_classify" || !active_session_policy_testlab_diag() || !arguments.is_object())
        return 0;
    auto it = arguments.find("__aida_test_policy_hold_target_resolve_ms");
    if (it == arguments.end())
        return 0;
    std::uint64_t hold_ms = 0;
    if (it->is_number_unsigned())
        hold_ms = it->get<std::uint64_t>();
    else if (it->is_number_integer()) {
        const auto value = it->get<std::int64_t>();
        if (value > 0)
            hold_ms = static_cast<std::uint64_t>(value);
    }
    return std::min<std::uint64_t>(hold_ms, 15000);
}

static void active_session_policy_apply_testlab_hold(const std::string& tool_name, const json& arguments, const char* phase)
{
    const std::uint64_t hold_ms = active_session_policy_testlab_hold_ms(tool_name, arguments);
    if (hold_ms == 0)
        return;
    const std::uint64_t started = mcp_now_ms();
    const std::uint64_t until = started + hold_ms;
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_testlab_hold_begin tool='%s' phase=%s hold_ms=%llu diag_id=%s request_id=%s",
        tool_name.c_str(),
        phase ? phase : "",
        static_cast<unsigned long long>(hold_ms),
        current_call_diag_id(),
        current_call_request_id());
    for (;;) {
        const std::uint64_t now = mcp_now_ms();
        if (now >= until)
            break;
        const std::uint64_t remain = until - now;
        Sleep(static_cast<DWORD>(std::min<std::uint64_t>(remain, kMcpPolicyLockPollMs)));
    }
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_testlab_hold_end tool='%s' phase=%s elapsed_ms=%llu cancelled=%d diag_id=%s request_id=%s",
        tool_name.c_str(),
        phase ? phase : "",
        static_cast<unsigned long long>(mcp_now_ms() - started),
        current_call_cancelled() ? 1 : 0,
        current_call_diag_id(),
        current_call_request_id());
}

static json active_session_policy_strip_testlab_args(const json& arguments)
{
    if (!arguments.is_object() || !arguments.contains("__aida_test_policy_hold_target_resolve_ms"))
        return arguments;
    json stripped = arguments;
    stripped.erase("__aida_test_policy_hold_target_resolve_ms");
    return stripped;
}

static tool_result_t mcp_late_result_discarded_result(const tool_def_t& tool,
                                                      const std::string& lane,
                                                      const char* reason)
{
    json details = {
        {"tool", tool.name},
        {"lane", lane},
        {"diagnostic_id", current_call_diag_id()},
        {"request_id", current_call_request_id()},
        {"reason", reason ? reason : ""},
        {"disposition", "discarded_after_fence"},
        {"lease_registry", mcp_lease_registry_bounded_snapshot(8, 8)}
    };
    return tool_result_t::error("MCP tool result discarded because the operation lease is stale, cancelled, fenced, or released.", "MCP_LATE_RESULT_DISCARDED", details);
}

static tool_result_t invoke_tool_with_registry_scope(const tool_def_t& tool,
                                                     const json& arguments,
                                                     const std::function<tool_result_t(const json&)>& handler,
                                                     tool_invocation_metrics_t* metrics,
                                                     const std::string& lane)
{
    mcp_operation_registry_scope_t registry_scope(tool, arguments, lane, tool.read_only);
    registry_scope.set_phase("handler_enter");
    tool_result_t tr = invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, lane.c_str());
    registry_scope.set_phase("handler_exit");
    if (!registry_scope.commit_eligible("handler_exit")) {
        registry_scope.release("late_result_discarded");
        return mcp_late_result_discarded_result(tool, lane, "registry_scope_ineligible");
    }
    registry_scope.release(mcp_tool_release_reason_from_result(tr, current_call_cancelled()));
    return tr;
}

static tool_result_t invoke_workspace_tool(
    const tool_def_t& tool,
    const json& arguments,
    tool_invocation_metrics_t* metrics)
{
    workspace_resolution_t resolution = resolve_workspace_direct(arguments);
    if (!resolution.workspace) {
        if (metrics)
            metrics->resolved_target = false;
        return tool_result_t::error(
            resolution.message.empty() ? std::string("Unable to resolve workspace target") : resolution.message,
            resolution.code.empty() ? std::string("TARGET_NOT_FOUND") : resolution.code,
            resolution.details);
    }
    if (metrics)
        metrics->resolved_target = true;
    auto workspace_mutex = workspace_policy_mutex(resolution.workspace);
    const std::string lane = tool.read_only ? "workspace_shared" : "workspace_exclusive";
    const auto invoke = [&](const json& params) {
        const std::uint64_t wait_started = static_cast<std::uint64_t>(GetTickCount64());
        const auto wait_failure = [&]() -> std::optional<tool_result_t> {
            const std::uint64_t deadline = current_call_deadline_ms();
            const bool deadline_exceeded = deadline != 0 &&
                static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
            if (!deadline_exceeded && !current_call_cancelled()) return std::nullopt;
            const std::uint64_t wait_ms = static_cast<std::uint64_t>(GetTickCount64()) - wait_started;
            set_tool_metrics_lane(metrics, lane, wait_ms);
            return add_workspace_provenance(tool_result_t::error(
                deadline_exceeded ? "Workspace policy-lock deadline expired before dispatch" :
                    "Workspace request was cancelled before dispatch",
                deadline_exceeded ? "DEADLINE_EXCEEDED" : "CANCELLED",
                json{{"disposition", "not_started"}, {"lock_wait_ms", wait_ms},
                    {"lane", lane}}), resolution.workspace);
        };
        if (auto failure = wait_failure()) return std::move(*failure);
        workspace_request_context_t context;
        context.workspace = resolution.workspace;
        context.kind = resolution.workspace->target_kind();
        context.binary_id = resolution.workspace->identity().binary_id();
        if (resolution.workspace->identity().process())
            context.pid = resolution.workspace->identity().process()->pid;
        context.analysis_revision = resolution.workspace->analysis_revision();
        context.overlay_revision = resolution.workspace->overlay_revision();
        context.cancellation = current_cancel_token();
        context.deadline_ms = current_call_deadline_ms();
        context.diagnostic_id = current_call_diag_id();
        context.request_id = current_call_request_id();
        context.tool_name = current_call_tool_name();
        tool_result_t result;
        if (tool.read_only) {
            std::shared_lock<std::shared_timed_mutex> lock(*workspace_mutex, std::defer_lock);
            while (!lock.try_lock_for(std::chrono::milliseconds(10))) {
                if (auto failure = wait_failure()) return std::move(*failure);
                if (resolution.workspace->closing() || resolution.workspace->closed())
                    return add_workspace_provenance(tool_result_t::error(
                        "Workspace closed while waiting for shared policy access",
                        "TARGET_CLOSED", json{{"disposition", "not_started"}, {"lane", lane}}),
                        resolution.workspace);
            }
            if (auto failure = wait_failure()) return std::move(*failure);
            if (resolution.workspace->closing() || resolution.workspace->closed())
                return add_workspace_provenance(tool_result_t::error(
                    "Workspace closed before shared handler dispatch", "TARGET_CLOSED",
                    json{{"disposition", "not_started"}, {"lane", lane}}),
                    resolution.workspace);
            set_tool_metrics_lane(metrics, lane,
                static_cast<std::uint64_t>(GetTickCount64()) - wait_started);
            result = tool.workspace_handler(params, context);
        } else {
            std::unique_lock<std::shared_timed_mutex> lock(*workspace_mutex, std::defer_lock);
            while (!lock.try_lock_for(std::chrono::milliseconds(10))) {
                if (auto failure = wait_failure()) return std::move(*failure);
                if (resolution.workspace->closing() || resolution.workspace->closed())
                    return add_workspace_provenance(tool_result_t::error(
                        "Workspace closed while waiting for exclusive policy access",
                        "TARGET_CLOSED", json{{"disposition", "not_started"}, {"lane", lane}}),
                        resolution.workspace);
            }
            if (auto failure = wait_failure()) return std::move(*failure);
            if (resolution.workspace->closing() || resolution.workspace->closed())
                return add_workspace_provenance(tool_result_t::error(
                    "Workspace closed before exclusive handler dispatch", "TARGET_CLOSED",
                    json{{"disposition", "not_started"}, {"lane", lane}}),
                    resolution.workspace);
            set_tool_metrics_lane(metrics, lane,
                static_cast<std::uint64_t>(GetTickCount64()) - wait_started);
            result = tool.workspace_handler(params, context);
        }
        return add_workspace_provenance(std::move(result), resolution.workspace);
    };
    set_tool_metrics_lane(metrics, lane, 0);
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lane tool='%s' lane=%s read_only=%d binary_id='%s' ui_thread_blocking_wait=0",
        tool.name.c_str(), lane.c_str(), tool.read_only ? 1 : 0,
        resolution.workspace->identity().binary_id().to_hex().c_str());
    return invoke_tool_with_registry_scope(
        tool, arguments, invoke, metrics, lane);
}

static tool_result_t target_scope_error_result(
    const target_scope_t& scope,
    const std::string& fallback)
{
    return tool_result_t::error(
        scope.err.empty() ? fallback : scope.err,
        scope.error_code.empty() ? std::string("TARGET_NOT_FOUND") : scope.error_code,
        scope.error_details.is_object() ? scope.error_details : json::object());
}

static tool_result_t invoke_tool_with_concurrency_policy(
    const tool_def_t& tool,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics = nullptr)
{
    if (tool.production_registry_dispatch) {
        direct_dispatch_options_t options;
        options.external_visible_only = false;
        if (auto* token = current_cancel_token())
            options.cancellation = cancel_token_ptr_t(token, [](std::atomic<bool>*) {});
        options.deadline_ms = current_call_deadline_ms();
        options.request_id = current_call_request_id();
        options.diagnostic_id = current_call_diag_id();
        return invoke_registered_tool_definition(tool, arguments, options);
    }
    const bool session_manager = is_analysis_session_management_tool(tool.name);
    const bool session_independent = tool.target_independent ||
        is_active_session_independent_tool(tool.name);
    json target_arguments_storage;
    const json& target_arguments = target_resolution_args_for_tool(tool, arguments, target_arguments_storage, true);
    const bool explicit_target = tool_args_select_session_target(target_arguments);
    const std::string domain = infer_tool_domain(tool.name);

    if (tool.workspace_handler)
        return invoke_workspace_tool(tool, arguments, metrics);

    if (session_independent && tool.read_only && !session_manager) {
        set_tool_metrics_lane(metrics, "independent_unlocked", 0);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=independent_unlocked lane_class=%s tool_class=%s conflict_policy=%s read_only=1 explicit_target=%d lock_wait_ms=0 ui_thread_blocking_wait=0",
            tool.name.c_str(),
            policy_lane_class_name(tool.name, "independent_unlocked").c_str(),
            policy_tool_class_name(tool.name).c_str(),
            policy_conflict_rule_for_lane("independent_unlocked").c_str(),
            explicit_target ? 1 : 0);
        return invoke_tool_with_registry_scope(tool, arguments, handler, metrics, "independent_unlocked");
    }

    if (session_independent && !tool.read_only && !session_manager) {
        const std::string lane = "exclusive_domain_" + (domain.empty() ? std::string("misc") : domain);
        std::unique_lock<std::mutex> lk(domain_lane_mutex(domain), std::defer_lock);
        const policy_lock_wait_t wait = acquire_domain_policy_lock(lk, tool.name, lane, domain.empty() ? std::string("misc") : domain, tool.read_only, explicit_target);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, lane, wait.wait_ms);
            return policy_lock_error_result(tool.name, lane.c_str(), wait);
        }
        const std::uint64_t wait_ms = wait.wait_ms;
        set_tool_metrics_lane(metrics, lane, wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=%s lane_class=%s tool_class=%s conflict_policy=%s read_only=0 explicit_target=%d lock_wait_ms=%llu ui_thread_blocking_wait=0",
            tool.name.c_str(),
            lane.c_str(),
            policy_lane_class_name(tool.name, lane.c_str()).c_str(),
            policy_tool_class_name(tool.name).c_str(),
            policy_conflict_rule_for_lane(lane.c_str()).c_str(),
            explicit_target ? 1 : 0,
            static_cast<unsigned long long>(wait_ms));
        return invoke_tool_with_registry_scope(tool, arguments, handler, metrics, lane);
    }

    if (explicit_target && !session_manager) {
        set_tool_metrics_lane(metrics, "explicit_target_workspace_handler_required", 0);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=explicit_target_workspace_handler_required read_only=%d explicit_target=1 workspace_handler=0 target_shape='%s' disposition=not_started",
            tool.name.c_str(),
            tool.read_only ? 1 : 0,
            payload_shape_summary(target_arguments).c_str());
        return tool_result_t::error(
            "Explicit workspace targets require a workspace_handler; migrate this tool before targeting a workspace.",
            "TARGET_WORKSPACE_HANDLER_REQUIRED",
            json{{"tool", tool.name},
                 {"target_routing", "workspace_handler_required"},
                 {"migration", "workspace_handler"},
                 {"disposition", "not_started"}});
    }

    if (!session_manager && !session_independent && !explicit_target && !tool_args_have_explicit_pid(arguments)) {
        set_tool_metrics_lane(metrics, "self_contained_unlocked", 0);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=self_contained_unlocked lane_class=%s tool_class=%s conflict_policy=%s read_only=%d explicit_target=0 lock_wait_ms=0 ui_thread_blocking_wait=0",
            tool.name.c_str(),
            policy_lane_class_name(tool.name, "self_contained_unlocked").c_str(),
            policy_tool_class_name(tool.name).c_str(),
            policy_conflict_rule_for_lane("self_contained_unlocked").c_str(),
            tool.read_only ? 1 : 0);
        return invoke_tool_with_registry_scope(tool, arguments, handler, metrics, "self_contained_unlocked");
    }

    if (session_manager || !tool.read_only) {
        const char* lane = session_manager ? "exclusive_session_manager" :
            (session_independent ? "exclusive_independent_mutating" : "exclusive_mutating");
        const std::uint64_t owner_token = active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
        const std::uint64_t owner_deadline = current_call_deadline_ms();
        const policy_lock_wait_t wait = acquire_policy_unique_lock(active_session_lease_lock(), tool.name, lane, tool.read_only, explicit_target, owner_token);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, lane, wait.wait_ms);
            return policy_lock_error_result(tool.name, lane, wait);
        }
        const std::uint64_t wait_ms = wait.wait_ms;
        set_tool_metrics_lane(metrics, lane, wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=%s lane_class=%s tool_class=%s conflict_policy=%s read_only=%d explicit_target=%d lock_wait_ms=%llu ui_thread_blocking_wait=0",
            tool.name.c_str(),
            lane,
            policy_lane_class_name(tool.name, lane).c_str(),
            policy_tool_class_name(tool.name).c_str(),
            policy_conflict_rule_for_lane(lane).c_str(),
            tool.read_only ? 1 : 0,
            explicit_target ? 1 : 0,
            static_cast<unsigned long long>(wait_ms));
        active_session_owner_guard_t owner_guard(tool, target_arguments, lane, true, tool.read_only, explicit_target, owner_token, owner_deadline, true);
        if (!session_manager && !session_independent) {
            owner_guard.set_phase("target_resolve");
            active_session_policy_apply_testlab_hold(tool.name, arguments, "target_resolve");
            std::string scope_err;
            target_scope_t scope = resolve_target(target_arguments, &scope_err);
            if (!scope.ok) {
                owner_guard.set_phase("target_resolve_failed");
                return target_scope_error_result(scope, "Unable to resolve target session");
            }
            if (metrics)
                metrics->resolved_target = true;
            const json handler_arguments = active_session_policy_strip_testlab_args(arguments);
            return invoke_tool_handler_guarded(tool.name, handler_arguments, handler, metrics, lane, &owner_guard);
        }
        const json handler_arguments = active_session_policy_strip_testlab_args(arguments);
        return invoke_tool_handler_guarded(tool.name, handler_arguments, handler, metrics, lane, &owner_guard);
    }

    if (!explicit_target) {
        const std::uint64_t owner_token = active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
        const std::uint64_t owner_deadline = current_call_deadline_ms();
        const policy_lock_wait_t wait = acquire_policy_shared_lock(active_session_lease_lock(), tool.name, "shared_active", false, owner_token);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, "shared_active", wait.wait_ms);
            return policy_lock_error_result(tool.name, "shared_active", wait);
        }
        const std::uint64_t wait_ms = wait.wait_ms;
        set_tool_metrics_lane(metrics, "shared_active", wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=shared_active lane_class=%s tool_class=%s conflict_policy=%s read_only=1 explicit_target=0 lock_wait_ms=%llu ui_thread_blocking_wait=0",
            tool.name.c_str(),
            policy_lane_class_name(tool.name, "shared_active").c_str(),
            policy_tool_class_name(tool.name).c_str(),
            policy_conflict_rule_for_lane("shared_active").c_str(),
            static_cast<unsigned long long>(wait_ms));
        active_session_owner_guard_t owner_guard(tool, target_arguments, "shared_active", false, true, false, owner_token, owner_deadline, true);
        owner_guard.set_phase("target_resolve");
        std::string scope_err;
        target_scope_t scope = resolve_target(target_arguments, &scope_err);
        if (!scope.ok) {
            owner_guard.set_phase("target_resolve_failed");
            return target_scope_error_result(scope, "Unable to resolve target session");
        }
        if (metrics)
            metrics->resolved_target = true;
        return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, "shared_active", &owner_guard);
    }

    return tool_result_t::error(
        "Explicit workspace targets require a workspace_handler; migrate this tool before targeting a workspace.",
        "TARGET_WORKSPACE_HANDLER_REQUIRED",
        json{{"tool", tool.name},
             {"target_routing", "workspace_handler_required"},
             {"migration", "workspace_handler"},
             {"disposition", "not_started"}});
}

bool server_t::register_tool(tool_def_t tool)
{
    if (is_standalone_ide_chat_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::ide_chat_only;
    else if (is_standalone_internal_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::internal_only;

    if (!tool.input_schema.is_null() && !tool.input_schema.is_object()) {
        diag::log_tagged_fmt("mcp_srv",
            "register_tool rejected name='%s' reason=input_schema_not_object",
            tool.name.c_str());
        return false;
    }
    if (!tool.output_schema.is_null() && !tool.output_schema.is_object()) {
        diag::log_tagged_fmt("mcp_srv",
            "register_tool rejected name='%s' reason=output_schema_not_object",
            tool.name.c_str());
        return false;
    }
    if (!tool.annotations.is_null() && !tool.annotations.is_object()) {
        diag::log_tagged_fmt("mcp_srv",
            "register_tool rejected name='%s' reason=annotations_not_object",
            tool.name.c_str());
        return false;
    }

    bool already_has_binary_id = false;
    for (const auto& p : tool.params) {
        if (p.name == "binary_id") { already_has_binary_id = true; break; }
    }
    bool is_targetless_tool = tool.target_independent ||
                              tool.name.rfind("sessions_", 0) == 0 ||
                              tool.name == "list_instances" ||
                              tool.name == "get_tool_descriptions" ||
                              is_camoufox_browser_tool_name(tool.name);
    if (!already_has_binary_id && !is_targetless_tool) {
        tool.params.push_back(tool_param_t{
            "binary_id",
            "string",
            tool.workspace_handler
                ? "Optional immutable workspace binary id. When all selectors are omitted exactly one open workspace must exist; otherwise TARGET_REQUIRED is returned."
                : "Optional session id to target (returned by `sessions_manage` action=list). When omitted the active session is used.",
            false
        });
    }
    if (tool.workspace_handler) {
        bool has_bin_name = false;
        bool has_pid = false;
        for (const auto& param : tool.params) {
            has_bin_name = has_bin_name || param.name == "bin_name";
            has_pid = has_pid || param.name == "pid";
        }
        if (!has_bin_name) {
            tool.params.push_back(tool_param_t{
                "bin_name", "string",
                "Optional exact workspace name or unique substring. Mutually exclusive with binary_id and pid.",
                false});
        }
        if (!has_pid) {
            tool.params.push_back(tool_param_t{
                "pid", "integer",
                "Optional positive live target PID. Mutually exclusive with binary_id and bin_name.",
                false});
        }
    }
    const std::string name = tool.name;
    const tool_visibility_t visibility = tool.visibility;
    const auto existing = _registry.find_tool(name, false);
    const bool registered = _registry.register_tool(std::move(tool));
    if (!registered && existing) {
        diag::log_tagged_fmt("mcp_srv",
            "register_tool duplicate skipped name='%s' existing_visibility=%d new_visibility=%d",
            name.c_str(), static_cast<int>(existing->visibility),
            static_cast<int>(visibility));
    }
    return registered;
}

bool server_t::register_tool(
    tool_def_t tool,
    std::function<tool_result_t(
        const json&,
        const std::shared_ptr<aida::analysis::analysis_workspace_t>&)> handler)
{
    if (!handler)
        return false;
    tool.workspace_handler = [handler = std::move(handler)](
        const json& params,
        const workspace_request_context_t& context) {
        return handler(params, context.workspace);
    };
    tool.handler = {};
    return register_tool(std::move(tool));
}

bool server_t::register_tool(
    tool_def_t tool,
    std::function<tool_result_t(
        const json&,
        const workspace_request_context_t&)> handler)
{
    if (!handler)
        return false;
    tool.workspace_handler = std::move(handler);
    tool.handler = {};
    return register_tool(std::move(tool));
}

tool_result_t server_t::call_registered_tool(const std::string& name, const json& arguments, bool external_visible_only)
{
    const std::uint64_t seq = g_tool_call_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    const std::string request_id = "call-registered-tool-" + std::to_string(seq);
    const std::string diag_id = request_id;
    const std::uint64_t call_begin = mcp_now_ms();
    auto rejection_details = [&](const std::string& reason, const std::string& tool_name) {
        json details;
        details["reason"] = reason;
        details["disposition"] = "not_started";
        details["diagnostic_id"] = diag_id;
        details["request_id"] = request_id;
        details["tool"] = tool_name.empty() ? std::string("<missing>") : tool_name;
        details["external_visible_only"] = external_visible_only;
        details["source"] = "call_registered_tool";
        details["user_input_consulted_for_bypass"] = false;
        return details;
    };

    if (name.empty()) {
        json details = rejection_details("missing_name", "<missing>");
        auto tr = tool_result_t::error("Missing tool name", "MCP_TOOL_CALL_REJECTED", details);
        record_tool_audit_event("<missing>", arguments, "rejected", false, details, tr.text, call_begin, diag_id, request_id);
        return tr;
    }

    tool_def_t found;
    bool found_tool = false;
    std::function<tool_result_t(const json&)> handler_copy;
    const auto registered = _registry.find_tool(name, false);
    if (registered) {
        if (external_visible_only && !is_external_mcp_tool(*registered)) {
            json details = rejection_details("not_external", name);
            auto tr = tool_result_t::error("Unknown tool: " + name, "MCP_TOOL_CALL_REJECTED", details);
            record_tool_audit_event(name, arguments, "rejected", false, details, tr.text, call_begin, diag_id, request_id);
            return tr;
        }
        found = *registered;
        handler_copy = registered->handler;
        found_tool = true;
    }

    if (!found_tool) {
        json details = rejection_details("unknown_tool", name);
        auto tr = tool_result_t::error("Unknown tool: " + name, "MCP_TOOL_CALL_REJECTED", details);
        record_tool_audit_event(name, arguments, "rejected", false, details, tr.text, call_begin, diag_id, request_id);
        return tr;
    }
    if (!handler_copy && !found.workspace_handler) {
        json details = rejection_details("handler_missing", name);
        auto tr = tool_result_t::error("Tool has no handler: " + name, "MCP_TOOL_HANDLER_MISSING", details);
        record_tool_audit_event(name, arguments, "rejected", false, details, tr.text, call_begin, diag_id, request_id);
        return tr;
    }
    tool_result_t validation_failure;
    if (!validate_pre_dispatch_tool_input(found, arguments, &validation_failure)) {
        json details = {
            {"code", validation_failure.error_code},
            {"message", validation_failure.text},
            {"details", validation_failure.error_details},
            {"disposition", "not_started"}
        };
        record_tool_audit_event(name, arguments, "rejected", false, details, validation_failure.text, call_begin, diag_id, request_id);
        return validation_failure;
    }
    tool_invocation_metrics_t metrics;
    metrics.lane = predicted_tool_lane(found, arguments);
    const tool_timeout_resolution_t timeout_resolution = resolve_tool_timeout(name, arguments);
    const std::uint64_t timeout_ms = timeout_resolution.effective_ms;
    const std::uint64_t requested_deadline_ms = saturated_deadline_ms(call_begin, timeout_resolution.requested_ms);
    const std::uint64_t deadline_ms = saturated_deadline_ms(call_begin, timeout_ms);
    const std::string payload_shape = payload_shape_summary(arguments);
    const std::uint32_t target_pid = target_pid_from_args(arguments);
    const std::string target_id = capacity_target_identity_from_args(arguments, target_pid);
    const char* direct_transport = external_visible_only ? "direct external call_registered_tool" : "internal/downstream producer";
    const std::string direct_principal = external_visible_only
        ? (tls_route_identity.principal_id.empty() ? std::string("local-direct-external") : tls_route_identity.principal_id)
        : std::string("internal-downstream");
    const std::string domain = infer_tool_domain(name);
    const capacity_diag::prediction_t capacity_prediction = diagnose_capacity("direct_registered_tool_pre_admission",
        capacity_tool_context(direct_transport,
            "call_registered_tool",
            "tools/call",
            direct_principal,
            diag_id,
            request_id,
            found,
            arguments,
            timeout_resolution,
            metrics.lane,
            payload_shape,
            target_pid));
    capacity_diag::scoped_activity_t capacity_activity(capacity_prediction, call_begin);
    json capacity_prediction_data = capacity_diag::prediction_json(capacity_prediction);

    auto record_result = [&](const tool_result_t& tr, const tool_invocation_metrics_t& result_metrics, const json& diagnostics) {
        json result;
        result["success"] = tr.success;
        if (!tr.text.empty())
            result["text"] = tr.text;
        if (!tr.data.is_null() && !tr.data.empty())
            result["data"] = tr.data;
        if (!tr.error_code.empty())
            result["error_code"] = tr.error_code;
        if (!tr.error_details.is_null() && !tr.error_details.empty())
            result["error_details"] = tr.error_details;
        result["metrics"] = {
            {"lane", result_metrics.lane},
            {"lock_wait_ms", result_metrics.lock_wait_ms},
            {"handler_elapsed_ms", result_metrics.handler_elapsed_ms}
        };
        result["capacity"] = capacity_prediction_data;
        result["target_id"] = target_id;
        if (!diagnostics.is_null() && !diagnostics.empty())
            result["diagnostics"] = diagnostics;
        record_tool_audit_event(name,
                                arguments,
                                tr.success ? std::string("completed") : std::string("failed"),
                                tr.success,
                                result,
                                tr.success ? std::string() : tr.text,
                                call_begin,
                                diag_id,
                                request_id);
    };

    if (!external_visible_only) {
        mcp_tool_bypass_audit(capacity_prediction, "source_visible_internal_callsite_contract");
        const bool internal_explicit_target = tool_args_select_session_target(arguments) || target_pid != 0;
        mcp_broker_delivery_fence_t delivery_fence(found,
            arguments,
            metrics.lane,
            internal_explicit_target,
            deadline_ms,
            current_cancel_token(),
            diag_id,
            request_id);
        delivery_fence.set_phase("handler_started");
        tool_result_t tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &metrics);
        json delivery_evidence = json::object();
        if (!delivery_fence.claim_delivery("internal_call_registered_tool", &delivery_evidence))
            tr = mcp_late_result_error_result(delivery_evidence);
        json diagnostics;
        diagnostics["broker_admission"] = "bypassed";
        diagnostics["bypass_reason"] = "source_visible_internal_callsite_contract";
        diagnostics["bypass_audit"] = "MCP-TOOL-BYPASS-AUDIT";
        diagnostics["disposition"] = "handler_inline";
        diagnostics["late_result_disposition"] = delivery_evidence.value("disposition", tr.success ? std::string("delivered") : std::string("discarded_late_result"));
        diagnostics["late_result_fence"] = delivery_evidence;
        diagnostics["user_input_consulted_for_bypass"] = false;
        diagnostics["external_visible_only"] = false;
        record_result(tr, metrics, diagnostics);
        return tr;
    }

    mcp_tool_capacity_lease_t tool_capacity_lease;
    json admission_rejection;
    if (!mcp_tool_try_acquire_capacity(capacity_prediction, call_begin, &tool_capacity_lease, &admission_rejection)) {
        auto tr = tool_result_t::error("MCP tool capacity exhausted; tool was not started.", "MCP_TOOL_CAPACITY_REJECT", admission_rejection);
        record_tool_audit_event(name, arguments, "rejected", false, admission_rejection, tr.text, call_begin, diag_id, request_id);
        return tr;
    }
    capacity_prediction_data["tool_admission"] = tool_capacity_lease.identity_json();

    mcp_route_identity_t direct_identity;
    direct_identity.http_request_id = seq;
    direct_identity.surface = "DIRECT";
    direct_identity.route = "call_registered_tool";
    direct_identity.path = "call_registered_tool";
    direct_identity.http_method = "DIRECT";
    direct_identity.transport = direct_transport;
    direct_identity.remote = "in_process";
    direct_identity.principal_id = direct_principal;
    direct_identity.principal_source = "source:external_visible_only_true";
    direct_identity.session_source = "none";
    direct_identity.session_hash = "direct-call";
    direct_identity.body_len = payload_shape.size();

    registered_call_scope_t call_scope{json(request_id)};
    auto meta = make_executor_task_meta();
    {
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->request_id = request_id;
        meta->method = "tools/call";
        meta->payload_shape = payload_shape;
        meta->route = "call_registered_tool";
    }
    std::shared_ptr<mcp_broker_delivery_fence_t> delivery_fence;
    {
        scoped_mcp_route_identity_t route_identity(direct_identity);
        populate_executor_tool_capacity_meta(meta,
            found,
            arguments,
            domain,
            metrics.lane,
            timeout_ms,
            deadline_ms,
            timeout_resolution.action,
            target_pid,
            0,
            0,
            0,
            call_scope.token);
        const bool explicit_delivery_target = tool_args_select_session_target(arguments) || target_pid != 0;
        delivery_fence = std::make_shared<mcp_broker_delivery_fence_t>(found,
            arguments,
            metrics.lane,
            explicit_delivery_target,
            deadline_ms,
            call_scope.token.get(),
            diag_id,
            request_id);
    }
    const bool use_domain_executor = is_exclusive_domain_lane(metrics.lane);
    const std::string queue_owner = use_domain_executor
        ? std::string("domain_executor_") + normalized_domain_key(domain)
        : std::string("tool_executor");
    const std::string queue_full_status = use_domain_executor
        ? std::string("domain_executor_queue_full")
        : std::string("tool_executor_queue_full");
    mcp_owned_executor_t& selected_executor = use_domain_executor
        ? mcp_domain_tool_executor(domain)
        : mcp_tool_executor();

    struct direct_tool_call_state_t
    {
        std::promise<tool_result_t> promise;
        std::atomic<bool> started{false};
        std::atomic<bool> finished{false};
        std::atomic<bool> timed_out{false};
        std::mutex mtx;
        tool_invocation_metrics_t metrics;
    };

    auto state = std::make_shared<direct_tool_call_state_t>();
    auto future = state->promise.get_future();
    diag::log_tagged_fmt("mcp_srv",
        "direct_registered_tool_enqueue seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu payload_shape='%s' broker_admission=required",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        name.c_str(),
        timeout_resolution.action.c_str(),
        domain.c_str(),
        metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(timeout_resolution.requested_ms),
        static_cast<unsigned long long>(timeout_ms),
        static_cast<unsigned long long>(requested_deadline_ms),
        static_cast<unsigned long long>(deadline_ms),
        payload_shape.c_str());

    auto task = [state,
                 meta,
                 call_token = call_scope.token,
                 found,
                 arguments,
                 handler_copy,
                 seq,
                 diag_id,
                 request_id,
                 tool_name = name,
                 domain,
                 queue_owner,
                 timeout_ms,
                 deadline_ms,
                 requested_timeout_ms = timeout_resolution.requested_ms,
                 requested_deadline_ms,
                 timeout_action = timeout_resolution.action,
                 timeout_source = timeout_resolution.source,
                 timeout_max_ms = timeout_resolution.max_ms,
                 timeout_action_aware = timeout_resolution.action_aware,
                 payload_shape,
                 target_pid,
                 call_begin,
                 direct_identity,
                 delivery_fence]() mutable {
        scoped_mcp_route_identity_t route_identity(direct_identity);
        state->started.store(true, std::memory_order_release);
        scoped_call_cancel_t scoped_cancel(call_token);
        scoped_call_metadata_t scoped_metadata(diag_id, request_id, tool_name, deadline_ms);
        tool_invocation_metrics_t task_metrics;
        {
            std::lock_guard<std::mutex> lk(meta->mtx);
            task_metrics.lane = meta->lane;
        }
        if (delivery_fence)
            delivery_fence->set_phase("handler_started");
        diag::log_tagged_fmt("mcp_srv",
            "direct_registered_tool_handler_begin seq=%llu diag_id=%s request_id='%s' tool='%s' domain='%s' lane='%s' queue_owner=%s deadline_ms=%llu cancelled=%d",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            domain.c_str(),
            task_metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(deadline_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0);
        const bool cancelled_before_dispatch = call_token && call_token->load(std::memory_order_acquire);
        const std::uint64_t dispatch_ms = mcp_now_ms();
        const bool expired_before_dispatch = deadline_ms != 0 && dispatch_ms >= deadline_ms;
        tool_result_t tr;
        if (cancelled_before_dispatch || expired_before_dispatch) {
            json stale;
            stale["diagnostic_id"] = diag_id;
            stale["request_id"] = request_id;
            stale["tool"] = tool_name;
            stale["action"] = timeout_action;
            stale["domain"] = domain;
            stale["lane"] = task_metrics.lane;
            stale["queue_owner"] = queue_owner;
            stale["requested_timeout_ms"] = requested_timeout_ms;
            stale["effective_timeout_ms"] = timeout_ms;
            stale["requested_deadline_ms"] = requested_deadline_ms;
            stale["effective_deadline_ms"] = deadline_ms;
            stale["dispatch_ms"] = dispatch_ms;
            stale["expired_before_dispatch"] = expired_before_dispatch;
            stale["cancelled_before_dispatch"] = cancelled_before_dispatch;
            stale["timeout_source"] = timeout_source;
            stale["timeout_max_ms"] = timeout_max_ms;
            stale["action_aware_timeout"] = timeout_action_aware;
            stale["payload_shape"] = payload_shape;
            stale["target_pid"] = target_pid;
            stale["disposition"] = "not_started";
            const char* stale_code = expired_before_dispatch ? "MCP_TOOL_DISPATCH_DEADLINE_EXPIRED" : "MCP_TOOL_DISPATCH_CANCELLED";
            tr = tool_result_t::error(expired_before_dispatch
                ? std::string("MCP direct tool call expired before handler dispatch.")
                : std::string("MCP direct tool call was cancelled before handler dispatch."),
                stale_code,
                stale);
            state->timed_out.store(true, std::memory_order_release);
            diag::log_tagged_fmt("mcp_srv",
                "direct_registered_tool_handler_skip seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s expired=%d cancelled=%d dispatch_delay_ms=%llu elapsed_ms=%llu disposition=not_started",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                tool_name.c_str(),
                timeout_action.c_str(),
                domain.c_str(),
                task_metrics.lane.c_str(),
                queue_owner.c_str(),
                expired_before_dispatch ? 1 : 0,
                cancelled_before_dispatch ? 1 : 0,
                static_cast<unsigned long long>(dispatch_ms >= call_begin ? dispatch_ms - call_begin : 0),
                static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        } else {
            tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &task_metrics);
        }
        update_executor_task_lane(meta, task_metrics.lane);
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->metrics = task_metrics;
        }
        state->finished.store(true, std::memory_order_release);
        const bool timed_out = state->timed_out.load(std::memory_order_acquire);
        if (delivery_fence) {
            json late_evidence = json::object();
            if (!delivery_fence->validate_handler_return("direct_registered_tool_handler_return", &late_evidence))
                tr = mcp_late_result_error_result(late_evidence);
        }
        diag::log_tagged_fmt("mcp_srv",
            "direct_registered_tool_handler_done seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' success=%d lane='%s' queue_owner=%s lock_wait_ms=%llu handler_elapsed_ms=%llu cancelled=%d timed_out=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_action.c_str(),
            tr.success ? 1 : 0,
            task_metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(task_metrics.lock_wait_ms),
            static_cast<unsigned long long>(task_metrics.handler_elapsed_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0,
            timed_out ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        if (timed_out) {
            mcp_lease_registry_signal_cancel_by_diagnostic(diag_id, "direct_late_result_after_timeout");
            mcp_lease_registry_mark_stale_by_diagnostic(diag_id, "direct_late_result_after_timeout");
            mcp_lease_registry_fence_by_diagnostic(diag_id, "direct_late_result_after_timeout");
        }
        try {
            state->promise.set_value(std::move(tr));
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "direct_registered_tool_promise_set_failed seq=%llu diag_id=%s tool='%s' err='%s'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "direct_registered_tool_promise_set_failed seq=%llu diag_id=%s tool='%s' err='<unknown>'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str());
        }
    };

    if (!selected_executor.enqueue(std::move(task), meta)) {
        call_scope.cancel();
        tool_capacity_lease.release("enqueue_failure");
        json details = tool_diagnostics_json(
            seq, diag_id, request_id, name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, "params_ok", queue_full_status,
            metrics, meta, true);
        details["action"] = timeout_resolution.action;
        details["queue_owner"] = queue_owner;
        details["requested_timeout_ms"] = timeout_resolution.requested_ms;
        details["effective_timeout_ms"] = timeout_ms;
        details["requested_deadline_ms"] = requested_deadline_ms;
        details["effective_deadline_ms"] = deadline_ms;
        details["timeout_source"] = timeout_resolution.source;
        details["timeout_max_ms"] = timeout_resolution.max_ms;
        details["action_aware_timeout"] = timeout_resolution.action_aware;
        details["explicit_timeout"] = timeout_resolution.explicit_timeout;
        details["broker_admission"] = "rejected";
        details["disposition"] = "not_started";
        details["late_result_disposition"] = "not_started";
        details["capacity"] = capacity_prediction_data;
        diag::log_tagged_fmt("mcp_srv",
            "MCP-CAPACITY-REJECT family=direct_call_registered_tool phase=direct_registered_tool_broker_admission seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' queue_owner=%s reason=%s decision=reject disposition=not_started elapsed_ms=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            name.c_str(),
            timeout_resolution.action.c_str(),
            queue_owner.c_str(),
            queue_full_status.c_str(),
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        auto tr = tool_result_t::error("MCP direct tool broker admission rejected; tool was not started.", "MCP_TOOL_ADMISSION_REJECTED", details);
        record_tool_audit_event(name, arguments, "rejected", false, details, tr.text, call_begin, diag_id, request_id);
        return tr;
    }

    diag::log_tagged_fmt("mcp_srv",
        "MCP-TOOL-BROKER-ADMIT seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' queue_owner=%s lane=%s broker_admission=admitted disposition=queued",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        name.c_str(),
        timeout_resolution.action.c_str(),
        queue_owner.c_str(),
        metrics.lane.c_str());
    aida::diagnostics::metadata_ring::emit(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::mcp_tool_call,
        "mcp_tool_admitted", nullptr, false);

    const auto wait_status = future.wait_for(std::chrono::milliseconds(timeout_ms));
    if (wait_status != std::future_status::ready) {
        state->timed_out.store(true, std::memory_order_release);
        call_scope.cancel();
        const std::size_t timeout_cancelled = mcp_lease_registry_signal_cancel_by_diagnostic(diag_id, "direct_registered_tool_timeout");
        const std::size_t timeout_stale = mcp_lease_registry_mark_stale_by_diagnostic(diag_id, "direct_registered_tool_timeout");
        const std::size_t timeout_fenced = mcp_lease_registry_fence_by_diagnostic(diag_id, "direct_registered_tool_timeout");
        json late_evidence = json::object();
        if (delivery_fence) {
            late_evidence = delivery_fence->mark_timeout("direct_registered_tool_timeout", "fenced_after_timeout");
            if (!late_evidence.empty())
                mcp_log_late_result_discarded(late_evidence);
        }
        json camoufox_stale_cleanup = json::object();
        if (is_camoufox_browser_tool_name(name) && delivery_fence) {
            const mcp_lease_registry_snapshot_t cleanup_snapshot = delivery_fence->snapshot();
            delivery_fence->release("direct_registered_tool_camoufox_pre_cleanup_tombstone");
            camoufox_stale_cleanup = mcp_camoufox_cleanup_stale_sidecar(
                cleanup_snapshot,
                diag_id,
                request_id,
                name,
                timeout_resolution.action);
            camoufox_stale_cleanup["lease_tombstoned_before_cleanup"] = true;
        }
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            metrics = state->metrics;
            if (metrics.lane.empty())
                metrics.lane = predicted_tool_lane(found, arguments);
        }
        json details = tool_diagnostics_json(
            seq, diag_id, request_id, name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, "params_ok", "timeout",
            metrics, meta, true);
        details["started"] = state->started.load(std::memory_order_acquire);
        details["finished"] = state->finished.load(std::memory_order_acquire);
        details["action"] = timeout_resolution.action;
        details["queue_owner"] = queue_owner;
        details["requested_timeout_ms"] = timeout_resolution.requested_ms;
        details["effective_timeout_ms"] = timeout_ms;
        details["requested_deadline_ms"] = requested_deadline_ms;
        details["effective_deadline_ms"] = deadline_ms;
        details["timeout_source"] = timeout_resolution.source;
        details["timeout_max_ms"] = timeout_resolution.max_ms;
        details["action_aware_timeout"] = timeout_resolution.action_aware;
        details["explicit_timeout"] = timeout_resolution.explicit_timeout;
        details["broker_admission"] = "admitted";
        details["target_id"] = target_id;
        details["late_result_disposition"] = "fenced_after_timeout";
        details["disposition"] = "fenced_after_timeout";
        details["late_result_fence"] = late_evidence;
        if (!camoufox_stale_cleanup.empty())
            details["camoufox_stale_cleanup"] = camoufox_stale_cleanup;
        details["lease_cancelled_count"] = timeout_cancelled;
        details["lease_stale_count"] = timeout_stale;
        details["lease_fenced_count"] = timeout_fenced;
        details["lease_registry"] = mcp_lease_registry_bounded_snapshot(8, 8);
        details["capacity"] = capacity_prediction_data;
        tool_capacity_lease.release("timeout");
        diag::log_tagged_fmt("mcp_srv",
            "direct_registered_tool_timeout seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s timeout_ms=%llu started=%d finished=%d cancelled=1 elapsed_ms=%llu late_result_disposition=fenced_after_timeout lease_token=%llu operation_generation=%llu registry_generation=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            name.c_str(),
            timeout_resolution.action.c_str(),
            domain.c_str(),
            metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(timeout_ms),
            state->started.load(std::memory_order_acquire) ? 1 : 0,
            state->finished.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin),
            static_cast<unsigned long long>(late_evidence.value("lease_token", 0ull)),
            static_cast<unsigned long long>(late_evidence.value("operation_generation", 0ull)),
            static_cast<unsigned long long>(late_evidence.value("registry_generation", 0ull)));
        auto tr = tool_result_t::error("MCP direct tool call timed out; cancellation was signalled and late delivery was fenced.", "MCP_TOOL_TIMEOUT", details);
        record_tool_audit_event(name, arguments, "timed_out", false, details, tr.text, call_begin, diag_id, request_id);
        return tr;
    }

    tool_result_t tr = future.get();
    {
        std::lock_guard<std::mutex> lk(state->mtx);
        metrics = state->metrics;
        if (metrics.lane.empty())
            metrics.lane = predicted_tool_lane(found, arguments);
    }
    const bool cancelled = call_scope.token && call_scope.token->load(std::memory_order_acquire);
    json diagnostics = tool_diagnostics_json(
        seq, diag_id, request_id, name, domain, found.read_only, target_pid,
        timeout_ms, deadline_ms, payload_shape, "params_ok", "broker_admitted",
        metrics, meta, cancelled);
    diagnostics["action"] = timeout_resolution.action;
    diagnostics["queue_owner"] = queue_owner;
    diagnostics["requested_timeout_ms"] = timeout_resolution.requested_ms;
    diagnostics["effective_timeout_ms"] = timeout_ms;
    diagnostics["requested_deadline_ms"] = requested_deadline_ms;
    diagnostics["effective_deadline_ms"] = deadline_ms;
    diagnostics["timeout_source"] = timeout_resolution.source;
    diagnostics["timeout_max_ms"] = timeout_resolution.max_ms;
    diagnostics["action_aware_timeout"] = timeout_resolution.action_aware;
    diagnostics["explicit_timeout"] = timeout_resolution.explicit_timeout;
    diagnostics["broker_admission"] = "admitted";
    diagnostics["capacity"] = capacity_prediction_data;
    json delivery_evidence = json::object();
    if (delivery_fence && !delivery_fence->claim_delivery("direct_call_registered_tool", &delivery_evidence)) {
        diagnostics["late_result_disposition"] = delivery_evidence.value("disposition", std::string("discarded_late_result"));
        diagnostics["late_result_fence"] = delivery_evidence;
        tool_result_t late = mcp_late_result_error_result(delivery_evidence);
        tool_capacity_lease.release("late_result_discarded");
        record_result(late, metrics, diagnostics);
        return late;
    }
    diagnostics["late_result_disposition"] = delivery_evidence.value("disposition", cancelled ? std::string("cancelled_before_delivery") : std::string("delivered"));
    diagnostics["late_result_fence"] = delivery_evidence;
    tool_capacity_lease.release(mcp_tool_release_reason_from_result(tr, cancelled));
    diag::log_tagged_fmt("mcp_srv",
        "direct_registered_tool_result seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' success=%d domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu elapsed_ms=%llu broker_admission=admitted disposition=%s",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        name.c_str(),
        timeout_resolution.action.c_str(),
        tr.success ? 1 : 0,
        domain.c_str(),
        metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(diagnostics.value("queue_wait_ms", 0ull)),
        static_cast<unsigned long long>(metrics.lock_wait_ms),
        static_cast<unsigned long long>(metrics.handler_elapsed_ms),
        static_cast<unsigned long long>(mcp_now_ms() - call_begin),
        cancelled ? "cancelled_before_delivery" : "delivered");
    record_result(tr, metrics, diagnostics);
    return tr;
}

json server_t::make_result(const json& id, const json& result)
{
    json r;
    r["jsonrpc"] = "2.0";
    r["id"]      = id;
    r["result"]  = result;
    return r;
}

json server_t::make_error(const json& id, int code, const std::string& msg)
{
    json r;
    r["jsonrpc"]          = "2.0";
    r["id"]               = id;
    r["error"]["code"]    = code;
    r["error"]["message"] = msg;
    return r;
}

json server_t::tool_schema(const tool_def_t& tool, bool compact) const
{
    json generated_input_schema;
    const json* input_schema = &tool.input_schema;
    if (input_schema->is_null()) {
        generated_input_schema = build_input_schema(tool);
        input_schema = &generated_input_schema;
    }
    json annotations = tool.annotations;
    if (annotations.is_null()) {
        annotations = json::object();
        annotations["title"]           = snake_to_title(tool.name);
        annotations["readOnlyHint"]    = tool.read_only;
        annotations["destructiveHint"] = (!tool.read_only);
        annotations["idempotentHint"]  = tool.read_only;
        annotations["openWorldHint"]   = (tool.name == "sandbox_execute");
    }

    if (compact && tool.name != "get_tool_descriptions") {
        json t;
        t["name"]        = tool.name;
        t["description"] = tool.description;
        t["inputSchema"] = *input_schema;
        if (!tool.output_schema.is_null())
            t["outputSchema"] = tool.output_schema;
        t["read_only"]   = tool.read_only;
        t["visibility"]  = visibility_name(tool.visibility);
        const std::string domain = infer_tool_domain(tool.name);
        if (!domain.empty())
            t["domain"] = domain;
        t["annotations"] = annotations;
        return t;
    }

    json t;
    t["name"]        = tool.name;
    t["description"] = tool.description;
    t["inputSchema"] = *input_schema;
    if (!tool.output_schema.is_null())
        t["outputSchema"] = tool.output_schema;
    t["annotations"] = annotations;
    t["read_only"]   = tool.read_only;
    t["visibility"]  = visibility_name(tool.visibility);
    const std::string domain = infer_tool_domain(tool.name);
    if (!domain.empty())
        t["domain"] = domain;
    return t;
}

static bool has_structured_tool_error(const tool_result_t& tr)
{
    return !tr.success && (!tr.error_code.empty() || (!tr.error_details.is_null() && !tr.error_details.empty()));
}

static json structured_tool_error(const tool_result_t& tr)
{
    json err = json::object();
    err["message"] = tr.text;
    if (!tr.error_code.empty())
        err["code"] = tr.error_code;
    if (!tr.error_details.is_null() && !tr.error_details.empty())
        err["details"] = tr.error_details;
    return err;
}

static json tool_diagnostics_json(
    std::uint64_t seq,
    const std::string& diag_id,
    const std::string& request_id,
    const std::string& tool_name,
    const std::string& domain,
    bool read_only,
    std::uint32_t target_pid,
    std::uint64_t timeout_ms,
    std::uint64_t deadline_ms,
    const std::string& payload_shape,
    const std::string& validation_status,
    const std::string& dependency_status,
    const tool_invocation_metrics_t& metrics,
    const std::shared_ptr<mcp_executor_task_meta_t>& meta,
    bool cancelled)
{
    std::uint64_t queue_wait_ms = 0;
    std::uint64_t queued_age_ms = 0;
    std::uint64_t active_age_ms = 0;
    std::uint64_t batch_id = 0;
    std::size_t batch_index = 0;
    std::size_t batch_size = 0;
    const std::uint64_t now = mcp_now_ms();
    if (meta) {
        std::lock_guard<std::mutex> lk(meta->mtx);
        queue_wait_ms = meta->queue_wait_ms;
        queued_age_ms = meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0;
        active_age_ms = meta->active_at != 0 && now >= meta->active_at ? now - meta->active_at : 0;
        batch_id = meta->batch_id;
        batch_index = meta->batch_index;
        batch_size = meta->batch_size;
    }
    json d;
    d["seq"] = seq;
    d["diagnostic_id"] = diag_id;
    d["request_id"] = request_id;
    d["method"] = "tools/call";
    d["tool"] = tool_name;
    d["domain"] = domain;
    d["lane"] = metrics.lane;
    d["read_only"] = read_only;
    d["target_pid"] = target_pid;
    d["queue_wait_ms"] = queue_wait_ms;
    d["queued_age_ms"] = queued_age_ms;
    d["active_age_ms"] = active_age_ms;
    d["lock_wait_ms"] = metrics.lock_wait_ms;
    d["handler_elapsed_ms"] = metrics.handler_elapsed_ms;
    d["timeout_ms"] = timeout_ms;
    d["deadline_ms"] = deadline_ms;
    d["deadline_remaining_ms"] = deadline_ms != 0 && now < deadline_ms ? deadline_ms - now : 0;
    d["cancelled"] = cancelled;
    d["payload_shape"] = payload_shape;
    d["validation_status"] = validation_status;
    d["dependency_status"] = dependency_status;
    d["resolved_target"] = metrics.resolved_target;
    if (batch_id != 0) {
        d["batch_id"] = batch_id;
        d["batch_index"] = batch_index;
        d["batch_size"] = batch_size;
    }
    return d;
}

tool_result_t server_t::describe_tools(const json& params)
{
    const std::uint64_t begin_ms = mcp_now_ms();
    std::vector<std::string> names;
    if (params.is_object()) {
        if (params.contains("names") && params["names"].is_array()) {
            for (const auto& n : params["names"]) {
                if (n.is_string())
                    names.push_back(n.get<std::string>());
            }
        } else if (params.contains("names") && params["names"].is_string()) {
            names.push_back(params["names"].get<std::string>());
        }
        if (params.contains("name") && params["name"].is_string())
            names.push_back(params["name"].get<std::string>());
    }

    std::string prefix;
    std::string query;
    std::string group;
    std::string group_source;
    bool include_schema = true;
    int limit = 40;
    bool explicit_limit = false;
    if (params.is_object()) {
        if (params.contains("prefix") && params["prefix"].is_string())
            prefix = params["prefix"].get<std::string>();
        if (params.contains("query") && params["query"].is_string())
            query = params["query"].get<std::string>();
        if (params.contains("group") && params["group"].is_string()) {
            group_source = params["group"].get<std::string>();
            group = normalize_tool_group_name(group_source);
        }
        if (params.contains("include_schema") && params["include_schema"].is_boolean())
            include_schema = params["include_schema"].get<bool>();
        if (params.contains("limit") && params["limit"].is_number_integer()) {
            limit = params["limit"].get<int>();
            explicit_limit = true;
        }
    }
    if (names.empty() && prefix.empty() && group.empty() && !query.empty()) {
        const std::string query_group = normalize_tool_group_name(query);
        if (!query_group.empty()) {
            group = query_group;
            group_source = query;
        }
    }
    if (!group.empty() && !explicit_limit)
        limit = 100;
    limit = (std::max)(1, (std::min)(limit, 100));

    std::vector<tool_def_t> matches;
    const auto registered_tools = _registry.snapshot_tools();
    {
        if (!names.empty()) {
            for (const auto& wanted : names) {
                for (const auto& tool : registered_tools) {
                    if (!is_external_mcp_tool(tool))
                        continue;
                    if (tool.name == wanted) {
                        auto dup = std::find_if(matches.begin(), matches.end(),
                            [&](const tool_def_t& existing) { return existing.name == tool.name; });
                        if (dup == matches.end())
                            matches.push_back(tool);
                        break;
                    }
                }
            }
        } else if (!group.empty()) {
            for (const auto& tool : registered_tools) {
                if (current_call_cancelled())
                    return tool_result_t::error("Tool description query cancelled.");
                if (!is_external_mcp_tool(tool))
                    continue;
                if (tool_matches_description_group(tool, group))
                    matches.push_back(tool);
            }
            std::sort(matches.begin(), matches.end(), [](const tool_def_t& a, const tool_def_t& b) {
                return a.name < b.name;
            });
        } else if (!prefix.empty() || !query.empty()) {
            const std::string prefix_l = lower_ascii(prefix);
            const std::string query_l = lower_ascii(query);
            for (const auto& tool : registered_tools) {
                if (current_call_cancelled())
                    return tool_result_t::error("Tool description query cancelled.");
                if (!is_external_mcp_tool(tool))
                    continue;
                const std::string name_l = lower_ascii(tool.name);
                const std::string desc_l = lower_ascii(tool.description);
                bool ok = true;
                if (!prefix_l.empty())
                    ok = name_l.rfind(prefix_l, 0) == 0;
                if (ok && !query_l.empty())
                    ok = name_l.find(query_l) != std::string::npos ||
                         desc_l.find(query_l) != std::string::npos;
                if (ok)
                    matches.push_back(tool);
            }
        }
    }

    if (names.empty() && prefix.empty() && query.empty() && group.empty())
        return tool_result_t::ok("Pass `names`, `name`, `prefix`, `query`, or `group` to retrieve full tool descriptions.");

    if (matches.empty()) {
        json data;
        data["tools"] = json::array();
        data["matched_count"] = 0;
        data["returned_count"] = 0;
        data["limit"] = limit;
        if (!group.empty()) {
            const std::uint64_t elapsed_ms = mcp_now_ms() - begin_ms;
            data["group"] = group;
            data["diagnostics"] = {
                {"group", group},
                {"matched_before_limit", 0},
                {"matched_after_limit", 0},
                {"limit", limit},
                {"elapsed_ms", elapsed_ms}
            };
            diag::log_tagged_fmt("mcp_srv",
                "tool_descriptions_group group='%s' source_len=%zu matched_before_limit=0 matched_after_limit=0 limit=%d elapsed_ms=%llu",
                group.c_str(),
                group_source.size(),
                limit,
                static_cast<unsigned long long>(elapsed_ms));
        }
        return tool_result_t::ok("No matching tools found.", data);
    }

    const size_t shown = (std::min)(matches.size(), static_cast<size_t>(limit));
    json data;
    data["tools"] = json::array();
    data["matched_count"] = matches.size();
    data["returned_count"] = shown;
    data["limit"] = limit;
    data["include_schema"] = include_schema;
    if (!group.empty())
        data["group"] = group;
    for (size_t i = 0; i < shown; ++i) {
        if (current_call_cancelled())
            return tool_result_t::error("Tool description query cancelled.");
        const auto& tool = matches[i];
        if (include_schema) {
            data["tools"].push_back(tool_schema(tool, false));
        } else {
            json t;
            t["name"] = tool.name;
            t["description"] = tool.description;
            t["read_only"] = tool.read_only;
            t["visibility"] = visibility_name(tool.visibility);
            const std::string domain = infer_tool_domain(tool.name);
            if (!domain.empty())
                t["domain"] = domain;
            data["tools"].push_back(std::move(t));
        }
    }
    if (!group.empty()) {
        const std::uint64_t elapsed_ms = mcp_now_ms() - begin_ms;
        data["diagnostics"] = {
            {"group", group},
            {"matched_before_limit", matches.size()},
            {"matched_after_limit", shown},
            {"limit", limit},
            {"elapsed_ms", elapsed_ms}
        };
        diag::log_tagged_fmt("mcp_srv",
            "tool_descriptions_group group='%s' source_len=%zu matched_before_limit=%zu matched_after_limit=%zu limit=%d elapsed_ms=%llu",
            group.c_str(),
            group_source.size(),
            matches.size(),
            shown,
            limit,
            static_cast<unsigned long long>(elapsed_ms));
    }

    std::string result;
    result.reserve(shown * 256);
    if (matches.size() > shown) {
        result += "Showing " + std::to_string(shown) + " of " +
                  std::to_string(matches.size()) +
                  " matching tools. Refine with `name`, `names`, `prefix`, `query`, or `group`.\n\n";
    }
    if (!group.empty()) {
        result += "Group: " + group + "\n";
        result += "Matched: " + std::to_string(matches.size()) + ", returned: " + std::to_string(shown) + ", limit: " + std::to_string(limit) + "\n\n";
    }
    for (size_t i = 0; i < shown; ++i) {
        if (current_call_cancelled())
            return tool_result_t::error("Tool description query cancelled.");
        const auto& tool = matches[i];
        result += "### " + tool.name + "\n";
        if (!tool.description.empty())
            result += tool.description + "\n";
        result += std::string("Read-only: ") + (tool.read_only ? "true" : "false") + "\n";
        if (include_schema) {
            if (!tool.input_schema.is_null()) {
                result += "Input schema:\n```json\n";
                result += tool.input_schema.dump(2);
                result += "\n```\n";
            } else if (tool.params.empty()) {
                result += "Parameters: none\n";
            } else {
                result += "Parameters:\n";
                for (const auto& p : tool.params) {
                    result += "- `" + p.name + "` (" + p.type;
                    if (p.required)
                        result += ", required";
                    result += ")";
                    if (!p.description.empty())
                        result += ": " + p.description;
                    result += "\n";
                }
            }
        }
        result += "\n";
    }
    return tool_result_t::ok(result, data);
}

json server_t::handle_initialize(const json& id, const json&)
{
    diag::log_tagged_fmt("mcp_srv", "handle_initialize entry");
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"]    = SERVER_NAME;
    server_info["version"] = SERVER_VERSION;

    static const char* instructions =
        "AiDAStandalone MCP is self-describing. Do not expect external markdown files such as TOOLS.md; shipped users normally receive only AiDAStandalone.exe and AiDA.dll. Learn the available surface from this initialize response, `tools/list`, and targeted `get_tool_descriptions` calls.\n\n"
        "You are connected to AiDAStandalone, a reverse-engineering assistant "
        "for standalone static binary sessions, live process/runtime inspection, "
        "kernel-backed debugger/memory workflows, Windows Sandbox sample execution, "
        "and browser/network reversing through bundled Camoufox MCP tools.\n\n"
        "## Capabilities\n"
        "- Open and analyze PE/ELF/Mach-O/SYS files as standalone static sessions\n"
        "- Read live process memory from an attached process\n"
        "- Disassemble x64 code at live addresses or from files\n"
        "- Attach to or detach from running processes when runtime access is required\n"
        "- Execute untrusted binaries in Windows Sandbox when explicitly requested\n"
        "- Convert integers, endian bytes, ASCII, signed/unsigned views, IEEE-754 values, alignment, VA, RVA, module-relative, and PE file-offset references\n"
        "- Use bundled Camoufox reverse-engineering browser tools through grouped actions exposed as `browser_lifecycle`, `browser_navigation`, `browser_interaction`, `browser_inspect`, `browser_state`, `browser_network`, `browser_hooks`, and `browser_instrumentation`\n\n"
        "## First-use workflow\n"
        "- Use `get_tool_descriptions` with `names`, `prefix`, or `query` for only the tools you plan to call; do not spam broad discovery calls\n"
        "- For standalone static binaries, use `sessions_manage` action `open_file`, then `analysis_query` action `binary_map_overview` or `disasm_get_section_info`, `disasm_list_functions`, and targeted disassembly/decompilation tools\n"
        "- For live runtime work, use `sessions_manage` action `attach_pid` for session attachment, then memory/disassembly tools.\n"
        "- When a VM bridge is active, pass `target: \"guest\"` or `target: \"host\"` explicitly whenever host/VM memory matters\n"
        "- Use `vm_bridge_manage` to activate and inspect custom VMware, VirtualBox, QEMU, Hyper-V, or manually managed Windows VM bridges\n"
        "- Custom VM workflows use a private shared-folder bridge: keep AiDAStandalone.exe on the host and run only the sample plus AiDAGuestAgent.exe in the guest\n"
        "- Do not bind AiDA's MCP endpoint directly to a guest, LAN, or untrusted adapter; use `vm_bridge_manage` plus the file-backed bridge instead\n"
        "- Cache session IDs, binary IDs, module bases, function bounds, xrefs, scan state, and decompiler output; avoid duplicate calls with identical parameters\n"
        "- Prefer batch or paginated tools over repeated one-off calls; set limits before large scans\n\n"
        "## Address and conversion rules\n"
        "- Prefer hex strings such as `0x140001000`\n"
        "- Live/debugger addresses are process VAs; stable references should include module+RVA when module context is known\n"
        "- Static file tools may return image base, section RVA, and raw file-offset context; carry that context forward\n"
        "- Use `convert_number` for all number, byte, signedness, float, VA/RVA, module-base, and PE file-offset conversions; never hand-convert offsets or byte values\n\n"
        "## Safety and mutation rules\n"
        "- `read_only=true` tools inspect state; `read_only=false` tools may mutate process memory, debugger state, files, browser state, proxy state, sandbox state, or analysis/session state\n"
        "- Only call mutating tools when the user asked for that action and the target is clear\n"
        "- Runtime, debugger, sandbox, browser interception, and filesystem tools are local trust-boundary tools even though the server binds to localhost\n\n"
        "## Browser/runtime shortcuts\n"
        "- For browser tasks, call `browser_lifecycle` with `action=launch` first when no Camoufox session is running, then call `browser_navigation` with `action=navigate` and a fully-qualified URL\n"
        "- Do not call session/driver attach or list helpers before browser-only work unless the user asks for diagnostics or runtime access\n"
        "- For runtime inspection, open or verify the process target with `sessions_manage` (`action=list` or `action=attach_pid`) and then use `query_memory`, `read_memory`, or `disassemble_zydis` as needed\n"
        "- Use `list_processes` if you need PID and process context before `sessions_manage` attachment\n"
        "- Use `disassemble_zydis` for live memory; `disassemble_file` for PE files\n"
        "- Use `sandbox_execute` for running untrusted binaries safely when the user requests execution\n";

    json result;
    result["protocolVersion"] = PROTOCOL_VERSION;
    result["capabilities"]    = capabilities;
    result["serverInfo"]      = server_info;
    result["instructions"]    = instructions;
    return make_result(id, result);
}

json server_t::handle_ping(const json& id, const json&)
{
    return make_result(id, json::object());
}

json server_t::handle_tools_list(const json& id, const json& params)
{
    json tools_arr = json::array();
    const bool compact = !wants_full_tool_list(params);
    for (const auto& t : _registry.snapshot_tools()) {
        if (!is_external_mcp_tool(t)) continue;
        tools_arr.push_back(tool_schema(t, compact));
    }
    diag::log_tagged_fmt("mcp_srv", "handle_tools_list compact=%d count=%zu",
        compact ? 1 : 0, tools_arr.size());
    json result;
    result["tools"] = tools_arr;
    result["_meta"] = {
        {"aidaToolListMode", compact ? "compact" : "full"},
        {"aidaToolDetailTool", "get_tool_descriptions"}
    };
    return make_result(id, result);
}

json server_t::handle_tools_call(const json& id, const json& params)
{
    const std::uint64_t seq = g_tool_call_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    const std::string request_id = request_id_string(id);
    const std::string diag_id = "mcp-tool-" + std::to_string(seq);
    const std::uint64_t call_begin = mcp_now_ms();

    if (!params.contains("name") || !params["name"].is_string()) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s request_id='%s' reason=missing_name payload_shape='%s'",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            payload_shape_summary(params).c_str());
        json args = params.contains("arguments") && params["arguments"].is_object() ? params["arguments"] : json::object();
        record_tool_audit_event("<missing>", args, "rejected", false, json{{"reason", "missing_name"}}, "Missing required field: 'name'", call_begin, diag_id, request_id);
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");
    }

    if (supplied_tool_arguments_are_non_object(params)) {
        const std::string rejected_tool_name = params["name"].get<std::string>();
        const tool_result_t validation_failure = non_object_tool_arguments_failure();
        json err = make_error(id, JSONRPC_INVALID_PARAMS, validation_failure.text);
        err["error"]["data"] = structured_tool_error(validation_failure);
        err["error"]["data"]["tool"] = rejected_tool_name;
        err["error"]["data"]["diagnostic_id"] = diag_id;
        err["error"]["data"]["request_id"] = request_id;
        err["error"]["data"]["disposition"] = "not_started";
        record_tool_audit_event(rejected_tool_name,
            params["arguments"],
            "rejected",
            false,
            err["error"],
            validation_failure.text,
            call_begin,
            diag_id,
            request_id);
        return err;
    }

    const std::string early_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("mcp_srv",
        "handle_tools_call seq=%llu diag_id=%s request_id='%s' tool='%s'",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        early_name.c_str());

    std::string tool_name = early_name;
    json arguments = params.contains("arguments") ? params["arguments"] : json::object();
    const std::string payload_shape = payload_shape_summary(arguments);
    const std::uint32_t target_pid = target_pid_from_args(arguments);
    const tool_timeout_resolution_t timeout_resolution = resolve_tool_timeout(tool_name, arguments);
    const std::uint64_t timeout_ms = timeout_resolution.effective_ms;
    const std::uint64_t requested_deadline_ms = saturated_deadline_ms(call_begin, timeout_resolution.requested_ms);
    const std::uint64_t deadline_ms = saturated_deadline_ms(call_begin, timeout_ms);
    std::string validation_status = "params_ok";
    std::string dependency_status = "not_checked";

    if (is_standalone_ide_chat_only_tool_name(tool_name) || is_standalone_internal_only_tool_name(tool_name)) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=not_external payload_shape='%s'",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str(),
            payload_shape.c_str());
        record_tool_audit_event(tool_name, arguments, "rejected", false, json{{"reason", "not_external"}}, "Unknown tool: " + tool_name, call_begin, diag_id, request_id);
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }

    tool_def_t found;
    bool found_tool = false;
    std::function<tool_result_t(const json&)> handler_copy;
    const auto registered_tool = _registry.find_tool(tool_name, false);
    if (registered_tool) {
        if (!is_external_mcp_tool(*registered_tool)) {
            record_tool_audit_event(tool_name, arguments, "rejected", false, json{{"reason", "not_external"}}, "Unknown tool: " + tool_name, call_begin, diag_id, request_id);
            return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
        }
        found = *registered_tool;
        handler_copy = registered_tool->handler;
        found_tool = true;
    }

    if (!found_tool)
    {
        validation_status = "unknown_tool";
        diag::log_tagged_fmt("mcp_srv",
            "handle_tools_call unknown_tool='%s' seq=%llu diag_id=%s payload_shape='%s'",
            tool_name.c_str(),
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            payload_shape.c_str());
        record_tool_audit_event(tool_name, arguments, "rejected", false, json{{"reason", "unknown_tool"}}, "Unknown tool: " + tool_name, call_begin, diag_id, request_id);
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }
    if (!handler_copy && !found.workspace_handler) {
        validation_status = "handler_missing";
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=handler_missing",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str());
        record_tool_audit_event(tool_name, arguments, "failed", false, json{{"reason", "handler_missing"}}, "Tool has no handler: " + tool_name, call_begin, diag_id, request_id);
        return make_error(id, JSONRPC_INTERNAL_ERROR, "Tool has no handler: " + tool_name);
    }

    if (!pre_dispatch_validation_active()) {
        tool_result_t validation_failure;
        if (!validate_pre_dispatch_tool_input(found, arguments, &validation_failure)) {
            validation_status = "schema_rejected";
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=schema_validation",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str());
            json err = make_error(id,
                JSONRPC_INVALID_PARAMS,
                validation_failure.text.empty() ? std::string("Tool input validation failed.") : validation_failure.text);
            err["error"]["data"] = structured_tool_error(validation_failure);
            err["error"]["data"]["tool"] = tool_name;
            err["error"]["data"]["diagnostic_id"] = diag_id;
            err["error"]["data"]["request_id"] = request_id;
            err["error"]["data"]["disposition"] = "not_started";
            record_tool_audit_event(tool_name, arguments, "rejected", false, err["error"], validation_failure.text, call_begin, diag_id, request_id);
            return err;
        }
    }

    if (is_driver_bridge_dependent_tool(found)) {
        std::string driver_reason;
        if (!driver_bridge::kernel_session_available(&driver_reason)) {
            dependency_status = "driver_unavailable";
            std::string detail = driver_bridge::last_error();
            if (detail.empty())
                detail = driver_bridge::status();
            diag::log_tagged_fmt("mcp_srv",
                "tool_driver_unavailable seq=%llu diag_id=%s tool='%s' reason='%s' detail='%.160s'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str(),
                driver_reason.empty() ? "<empty>" : driver_reason.c_str(),
                detail.c_str());
            std::string message = "Kernel driver bridge unavailable for tool '" + tool_name + "'";
            if (!driver_reason.empty())
                message += " (" + driver_reason + ")";
            message += ". Driver-backed capabilities are degraded while reconnect is pending.";
            if (!detail.empty())
                message += " Driver status: " + detail;
            json err = make_error(id, -32051, message);
            err["error"]["data"] = {
                {"diagnostic_id", diag_id},
                {"seq", seq},
                {"tool", tool_name},
                {"dependency_status", dependency_status},
                {"driver_reason", driver_reason},
                {"target_pid", target_pid},
                {"payload_shape", payload_shape}
            };
            record_tool_audit_event(tool_name, arguments, "rejected", false, err["error"], message, call_begin, diag_id, request_id);
            return err;
        }
        dependency_status = "driver_ok";
    } else {
        dependency_status = "not_driver_dependent";
    }

    const std::string domain = infer_tool_domain(tool_name);
    tool_invocation_metrics_t dispatch_metrics;
    dispatch_metrics.lane = predicted_tool_lane(found, arguments);
    const mcp_batch_child_admission_context_t batch_ctx = current_mcp_batch_child_admission_context();
    auto meta = make_executor_task_meta();
    {
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->request_id = request_id;
        meta->method = "tools/call";
        meta->payload_shape = payload_shape;
        meta->route = current_mcp_route();
    }
    populate_executor_tool_capacity_meta(meta,
        found,
        arguments,
        domain,
        dispatch_metrics.lane,
        timeout_ms,
        deadline_ms,
        timeout_resolution.action,
        target_pid,
        batch_ctx.active ? batch_ctx.batch_id : 0,
        batch_ctx.active ? batch_ctx.batch_index : 0,
        batch_ctx.active ? batch_ctx.batch_size : 0,
        nullptr);
    const bool use_domain_executor = is_exclusive_domain_lane(dispatch_metrics.lane);
    const std::string queue_owner = use_domain_executor
        ? std::string("domain_executor_") + normalized_domain_key(domain)
        : std::string("tool_executor");
    const std::string queue_full_status = use_domain_executor
        ? std::string("domain_executor_queue_full")
        : std::string("tool_executor_queue_full");
    capacity_diag::prediction_t capacity_prediction = diagnose_capacity("tools_call_pre_admission",
        capacity_tool_context(current_mcp_transport(), current_mcp_route(), "tools/call", current_mcp_principal(), diag_id, request_id,
            found,
            arguments,
            timeout_resolution,
            dispatch_metrics.lane,
            payload_shape,
            target_pid,
            batch_ctx.active,
            batch_ctx.active ? batch_ctx.batch_size : 0,
            batch_ctx.active ? batch_ctx.batch_index : 0),
        true);
    if (batch_ctx.active) {
        capacity_prediction.decision.would_accept = true;
        capacity_prediction.decision.reason = "accepted_phase3_batch_child_reservation";
        capacity_prediction.decision.quota_name = "active_batch_children_per_principal";
        capacity_prediction.decision.quota_scope = "principal_batch";
        capacity_prediction.decision.observed = batch_ctx.batch_index + 1;
        capacity_prediction.decision.limit = batch_ctx.active_limit;
    }
    json capacity_prediction_data = capacity_diag::prediction_json(capacity_prediction);
    mcp_tool_capacity_lease_t tool_capacity_lease;
    json tool_admission_rejection;
    if (!mcp_tool_try_acquire_capacity(capacity_prediction, call_begin, &tool_capacity_lease, &tool_admission_rejection)) {
        json err = make_error(id, -32079, "MCP tool capacity exhausted; tool was not started.");
        err["error"]["data"] = tool_admission_rejection;
        err["error"]["data"]["started"] = false;
        err["error"]["data"]["finished"] = false;
        err["error"]["data"]["late_result_disposition"] = "not_started";
        err["error"]["data"]["diagnostics"] = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, dependency_status,
            dispatch_metrics, meta, false);
        err["error"]["data"]["diagnostics"]["action"] = timeout_resolution.action;
        err["error"]["data"]["diagnostics"]["queue_owner"] = queue_owner;
        err["error"]["data"]["diagnostics"]["requested_timeout_ms"] = timeout_resolution.requested_ms;
        err["error"]["data"]["diagnostics"]["effective_timeout_ms"] = timeout_ms;
        err["error"]["data"]["diagnostics"]["requested_deadline_ms"] = requested_deadline_ms;
        err["error"]["data"]["diagnostics"]["effective_deadline_ms"] = deadline_ms;
        err["error"]["data"]["diagnostics"]["timeout_source"] = timeout_resolution.source;
        err["error"]["data"]["diagnostics"]["timeout_max_ms"] = timeout_resolution.max_ms;
        err["error"]["data"]["diagnostics"]["action_aware_timeout"] = timeout_resolution.action_aware;
        err["error"]["data"]["diagnostics"]["explicit_timeout"] = timeout_resolution.explicit_timeout;
        err["error"]["data"]["diagnostics"]["started"] = false;
        err["error"]["data"]["diagnostics"]["finished"] = false;
        err["error"]["data"]["diagnostics"]["disposition"] = "not_started";
        err["error"]["data"]["diagnostics"]["late_result_disposition"] = "not_started";
        record_tool_audit_event(tool_name, arguments, "rejected", false, err["error"], "MCP tool capacity exhausted; tool was not started.", call_begin, diag_id, request_id);
        return err;
    }
    capacity_prediction_data["tool_admission"] = tool_capacity_lease.identity_json();
    if (batch_ctx.active) {
        capacity_prediction_data["batch_admission_source"] = "phase3_batch_child_reservation";
        capacity_prediction_data["batch_id"] = batch_ctx.batch_id;
        capacity_prediction_data["batch_index"] = batch_ctx.batch_index;
        capacity_prediction_data["batch_size"] = batch_ctx.batch_size;
        capacity_prediction_data["batch_reservation_id"] = batch_ctx.reservation_id;
    }
    if (current_mcp_connection_closed()) {
        json err = make_error(id, -32080, "MCP client disconnected before tool start; tool was not started.");
        err["error"]["data"] = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, "client_disconnected_before_start",
            dispatch_metrics, meta, true);
        err["error"]["data"]["action"] = timeout_resolution.action;
        err["error"]["data"]["queue_owner"] = queue_owner;
        err["error"]["data"]["requested_timeout_ms"] = timeout_resolution.requested_ms;
        err["error"]["data"]["effective_timeout_ms"] = timeout_ms;
        err["error"]["data"]["requested_deadline_ms"] = requested_deadline_ms;
        err["error"]["data"]["effective_deadline_ms"] = deadline_ms;
        err["error"]["data"]["timeout_source"] = timeout_resolution.source;
        err["error"]["data"]["timeout_max_ms"] = timeout_resolution.max_ms;
        err["error"]["data"]["action_aware_timeout"] = timeout_resolution.action_aware;
        err["error"]["data"]["explicit_timeout"] = timeout_resolution.explicit_timeout;
        err["error"]["data"]["started"] = false;
        err["error"]["data"]["finished"] = false;
        err["error"]["data"]["reason"] = "client_disconnect_before_start";
        err["error"]["data"]["disposition"] = "not_started";
        err["error"]["data"]["late_result_disposition"] = "not_started";
        err["error"]["data"]["capacity"] = capacity_prediction_data;
        tool_capacity_lease.release("client_disconnect_before_start");
        record_tool_audit_event(tool_name, arguments, "rejected", false, err["error"], "MCP client disconnected before tool start; tool was not started.", call_begin, diag_id, request_id);
        return err;
    }
    registered_call_scope_t call_scope(id);
    populate_executor_tool_capacity_meta(meta,
        found,
        arguments,
        domain,
        dispatch_metrics.lane,
        timeout_ms,
        deadline_ms,
        timeout_resolution.action,
        target_pid,
        batch_ctx.active ? batch_ctx.batch_id : 0,
        batch_ctx.active ? batch_ctx.batch_index : 0,
        batch_ctx.active ? batch_ctx.batch_size : 0,
        call_scope.token);
    const bool broker_explicit_target = tool_args_select_session_target(arguments) || target_pid != 0;
    auto delivery_fence = std::make_shared<mcp_broker_delivery_fence_t>(found,
        arguments,
        dispatch_metrics.lane,
        broker_explicit_target,
        deadline_ms,
        call_scope.token.get(),
        diag_id,
        request_id);
    mcp_owned_executor_t& selected_executor = use_domain_executor
        ? mcp_domain_tool_executor(domain)
        : mcp_tool_executor();

    struct async_tool_call_state_t
    {
        std::promise<tool_result_t> promise;
        std::atomic<bool> started{false};
        std::atomic<bool> finished{false};
        std::atomic<bool> timed_out{false};
        std::mutex mtx;
        tool_invocation_metrics_t metrics;
        bool browser_external_lease_active = false;
        mcp_lease_registry_snapshot_t browser_external_lease;
    };

    auto state = std::make_shared<async_tool_call_state_t>();
    auto future = state->promise.get_future();
    const mcp_route_identity_t tool_call_identity = tls_route_identity;
    const bool browser_tool_call = is_camoufox_browser_tool_name(tool_name);
    if (browser_tool_call) {
        const std::uint64_t browser_lease_token = active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u;
        mcp_lease_registry_acquire_t browser_lease_request = mcp_lease_acquire_request_for_tool(
            found,
            arguments,
            dispatch_metrics.lane,
            found.read_only,
            is_analysis_session_management_tool(found.name),
            false,
            browser_lease_token,
            deadline_ms,
            call_scope.token.get());
        browser_lease_request.diagnostic_id = sanitize_owner_field(diag_id, 160);
        browser_lease_request.request_id = sanitize_owner_field(request_id, 160);
        browser_lease_request.phase = "camoufox_external_sidecar_acquired";
        mcp_lease_registry_snapshot_t browser_lease = mcp_lease_registry_acquire(browser_lease_request);
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->browser_external_lease_active = browser_lease.present;
            state->browser_external_lease = browser_lease;
        }
        capacity_prediction_data["camoufox_external_lease"] = mcp_lease_snapshot_json(browser_lease);
        diag::log_tagged_fmt("mcp_srv",
            "browser_tool_external_lease_acquired seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' token=%llu operation_generation=%llu registry_generation=%llu external_pid=%u external_session=%s external_generation=%llu external_expected_path=%s external_ctime=%llu marker=%s cleanup_eligible=%d",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_resolution.action.c_str(),
            static_cast<unsigned long long>(browser_lease.lease_token),
            static_cast<unsigned long long>(browser_lease.operation_generation),
            static_cast<unsigned long long>(browser_lease.registry_generation),
            browser_lease.external_process_pid,
            browser_lease.external_process_session.c_str(),
            static_cast<unsigned long long>(browser_lease.external_process_generation),
            browser_lease.external_expected_executable_path.c_str(),
            static_cast<unsigned long long>(browser_lease.external_process_creation_time_100ns),
            browser_lease.external_sidecar_ownership_marker.c_str(),
            browser_lease.external_force_cleanup_eligible ? 1 : 0);
    }
    diag::log_tagged_fmt("mcp_srv",
        "tool_call_enqueue seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d payload_shape='%s' validation=%s dependency=%s",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        tool_name.c_str(),
        timeout_resolution.action.c_str(),
        domain.c_str(),
        dispatch_metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(timeout_resolution.requested_ms),
        static_cast<unsigned long long>(timeout_ms),
        static_cast<unsigned long long>(requested_deadline_ms),
        static_cast<unsigned long long>(deadline_ms),
        timeout_resolution.source.c_str(),
        static_cast<unsigned long long>(timeout_resolution.max_ms),
        timeout_resolution.action_aware ? 1 : 0,
        payload_shape.c_str(),
        validation_status.c_str(),
        dependency_status.c_str());

    auto task = [state, meta, call_token = call_scope.token, found, arguments, handler_copy, seq, diag_id, request_id, tool_name, domain, queue_owner, timeout_ms, deadline_ms, requested_timeout_ms = timeout_resolution.requested_ms, requested_deadline_ms, timeout_action = timeout_resolution.action, timeout_source = timeout_resolution.source, timeout_max_ms = timeout_resolution.max_ms, timeout_action_aware = timeout_resolution.action_aware, payload_shape, validation_status, dependency_status, target_pid, call_begin, tool_call_identity, delivery_fence]() mutable {
        scoped_mcp_route_identity_t route_identity(tool_call_identity);
        state->started.store(true, std::memory_order_release);
        scoped_call_cancel_t scoped_cancel(call_token);
        scoped_call_metadata_t scoped_metadata(diag_id, request_id, tool_name, deadline_ms);
        tool_invocation_metrics_t metrics;
        {
            std::lock_guard<std::mutex> lk(meta->mtx);
            metrics.lane = meta->lane;
        }
        if (delivery_fence)
            delivery_fence->set_phase("handler_started");
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_handler_begin seq=%llu diag_id=%s request_id='%s' tool='%s' domain='%s' lane='%s' deadline_ms=%llu cancelled=%d",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            domain.c_str(),
            metrics.lane.c_str(),
            static_cast<unsigned long long>(deadline_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0);
        const bool cancelled_before_dispatch = call_token && call_token->load(std::memory_order_acquire);
        const std::uint64_t dispatch_ms = mcp_now_ms();
        const bool expired_before_dispatch = deadline_ms != 0 && dispatch_ms >= deadline_ms;
        tool_result_t tr;
        if (cancelled_before_dispatch || expired_before_dispatch) {
            json stale;
            stale["diagnostic_id"] = diag_id;
            stale["request_id"] = request_id;
            stale["tool"] = tool_name;
            stale["action"] = timeout_action;
            stale["domain"] = domain;
            stale["lane"] = metrics.lane;
            stale["queue_owner"] = queue_owner;
            stale["requested_timeout_ms"] = requested_timeout_ms;
            stale["effective_timeout_ms"] = timeout_ms;
            stale["requested_deadline_ms"] = requested_deadline_ms;
            stale["effective_deadline_ms"] = deadline_ms;
            stale["dispatch_ms"] = dispatch_ms;
            stale["expired_before_dispatch"] = expired_before_dispatch;
            stale["cancelled_before_dispatch"] = cancelled_before_dispatch;
            stale["timeout_source"] = timeout_source;
            stale["timeout_max_ms"] = timeout_max_ms;
            stale["action_aware_timeout"] = timeout_action_aware;
            const char* stale_code = expired_before_dispatch ? "tool_dispatch_deadline_expired" : "tool_dispatch_cancelled";
            tr = tool_result_t::error(expired_before_dispatch
                ? std::string("Tool call expired before handler dispatch.")
                : std::string("Tool call was cancelled before handler dispatch."),
                stale_code,
                stale);
            state->timed_out.store(true, std::memory_order_release);
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_handler_skip seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s expired=%d cancelled=%d dispatch_delay_ms=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                tool_name.c_str(),
                timeout_action.c_str(),
                domain.c_str(),
                metrics.lane.c_str(),
                queue_owner.c_str(),
                expired_before_dispatch ? 1 : 0,
                cancelled_before_dispatch ? 1 : 0,
                static_cast<unsigned long long>(dispatch_ms >= call_begin ? dispatch_ms - call_begin : 0),
                static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        } else {
            tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &metrics);
        }
        update_executor_task_lane(meta, metrics.lane);
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->metrics = metrics;
        }
        state->finished.store(true, std::memory_order_release);
        const bool timed_out = state->timed_out.load(std::memory_order_acquire);
        if (delivery_fence) {
            json late_evidence = json::object();
            if (!delivery_fence->validate_handler_return("tools_call_handler_return", &late_evidence))
                tr = mcp_late_result_error_result(late_evidence);
        }
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_handler_done seq=%llu diag_id=%s tool='%s' action='%s' success=%d lane='%s' queue_owner=%s lock_wait_ms=%llu handler_elapsed_ms=%llu cancelled=%d timed_out=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str(),
            timeout_action.c_str(),
            tr.success ? 1 : 0,
            metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(metrics.lock_wait_ms),
            static_cast<unsigned long long>(metrics.handler_elapsed_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0,
            timed_out ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        if (timed_out) {
            mcp_lease_registry_signal_cancel_by_diagnostic(diag_id, "tool_call_late_result_after_timeout");
            mcp_lease_registry_mark_stale_by_diagnostic(diag_id, "tool_call_late_result_after_timeout");
            mcp_lease_registry_fence_by_diagnostic(diag_id, "tool_call_late_result_after_timeout");
        }
        if (timed_out && is_camoufox_browser_tool_name(tool_name))
        {
            diag::log_tagged_fmt("mcp_srv",
                "browser_tool_late_result_disposition seq=%llu diag_id=%s request_id='%s' queue_owner=%s tool='%s' action='%s' lane='%s' success=%d requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d elapsed_ms=%llu cancelled=%d disposition=discarded_after_timeout",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                queue_owner.c_str(),
                tool_name.c_str(),
                timeout_action.c_str(),
                metrics.lane.c_str(),
                tr.success ? 1 : 0,
                static_cast<unsigned long long>(requested_timeout_ms),
                static_cast<unsigned long long>(timeout_ms),
                static_cast<unsigned long long>(requested_deadline_ms),
                static_cast<unsigned long long>(deadline_ms),
                timeout_source.c_str(),
                static_cast<unsigned long long>(timeout_max_ms),
                timeout_action_aware ? 1 : 0,
                static_cast<unsigned long long>(mcp_now_ms() - call_begin),
                call_token && call_token->load(std::memory_order_acquire) ? 1 : 0);
        }
        try {
            state->promise.set_value(std::move(tr));
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_promise_set_failed seq=%llu diag_id=%s tool='%s' err='%s'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_promise_set_failed seq=%llu diag_id=%s tool='%s' err='<unknown>'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str());
        }
    };

    if (!selected_executor.enqueue(std::move(task), meta)) {
        call_scope.cancel();
        if (delivery_fence)
            delivery_fence->release("enqueue_failure");
        dispatch_metrics.lane = predicted_tool_lane(found, arguments);
        json err = make_error(id, -32072, "MCP executor queue is full; tool was not started.");
        err["error"]["data"] = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, queue_full_status,
            dispatch_metrics, meta, true);
        err["error"]["data"]["action"] = timeout_resolution.action;
        err["error"]["data"]["queue_owner"] = queue_owner;
        err["error"]["data"]["requested_timeout_ms"] = timeout_resolution.requested_ms;
        err["error"]["data"]["effective_timeout_ms"] = timeout_ms;
        err["error"]["data"]["requested_deadline_ms"] = requested_deadline_ms;
        err["error"]["data"]["effective_deadline_ms"] = deadline_ms;
        err["error"]["data"]["timeout_source"] = timeout_resolution.source;
        err["error"]["data"]["timeout_max_ms"] = timeout_resolution.max_ms;
        err["error"]["data"]["action_aware_timeout"] = timeout_resolution.action_aware;
        err["error"]["data"]["explicit_timeout"] = timeout_resolution.explicit_timeout;
        err["error"]["data"]["disposition"] = "not_started";
        err["error"]["data"]["late_result_disposition"] = "not_started";
        err["error"]["data"]["capacity"] = capacity_prediction_data;
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_enqueue_failed seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' queue_owner=%s reason=%s requested_timeout_ms=%llu effective_timeout_ms=%llu elapsed_ms=%llu late_result_disposition=not_started",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_resolution.action.c_str(),
            queue_owner.c_str(),
            queue_full_status.c_str(),
            static_cast<unsigned long long>(timeout_resolution.requested_ms),
            static_cast<unsigned long long>(timeout_ms),
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        if (browser_tool_call) {
            mcp_lease_registry_snapshot_t browser_lease;
            bool release_browser_lease = false;
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                browser_lease = state->browser_external_lease;
                release_browser_lease = state->browser_external_lease_active;
                state->browser_external_lease_active = false;
            }
            if (release_browser_lease)
                mcp_lease_registry_release(browser_lease.lease_token, browser_lease.operation_generation, "enqueue_failure");
        }
        tool_capacity_lease.release("enqueue_failure");
        record_tool_audit_event(tool_name, arguments, "rejected", false, err["error"], "MCP executor queue is full; tool was not started.", call_begin, diag_id, request_id);
        return err;
    }

    const auto wait_status = future.wait_for(std::chrono::milliseconds(timeout_ms));
    if (wait_status != std::future_status::ready) {
        state->timed_out.store(true, std::memory_order_release);
        call_scope.cancel();
        const std::size_t timeout_cancelled = mcp_lease_registry_signal_cancel_by_diagnostic(diag_id, "tool_call_timeout");
        const std::size_t timeout_stale = mcp_lease_registry_mark_stale_by_diagnostic(diag_id, "tool_call_timeout");
        const std::size_t timeout_fenced = mcp_lease_registry_fence_by_diagnostic(diag_id, "tool_call_timeout");
        json late_evidence = json::object();
        if (delivery_fence) {
            late_evidence = delivery_fence->mark_timeout("tool_call_timeout", "fenced_after_timeout");
            if (!late_evidence.empty())
                mcp_log_late_result_discarded(late_evidence);
        }
        json camoufox_stale_cleanup = json::object();
        if (browser_tool_call) {
            mcp_lease_registry_snapshot_t browser_lease;
            bool cleanup_browser_lease = false;
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                browser_lease = state->browser_external_lease;
                cleanup_browser_lease = state->browser_external_lease_active;
                state->browser_external_lease_active = false;
            }
            if (cleanup_browser_lease) {
                mcp_lease_registry_signal_cancel(browser_lease.lease_token, browser_lease.operation_generation, "tool_call_timeout_camoufox_sidecar");
                mcp_lease_registry_mark_stale(browser_lease.lease_token, browser_lease.operation_generation, "tool_call_timeout_camoufox_sidecar");
                mcp_lease_registry_fence(browser_lease.lease_token, browser_lease.operation_generation, "tool_call_timeout_camoufox_sidecar");
                mcp_lease_registry_snapshot_t refreshed_browser_lease;
                if (mcp_lease_registry_commit_eligible(browser_lease.lease_token, browser_lease.operation_generation, &refreshed_browser_lease) || refreshed_browser_lease.present)
                    browser_lease = refreshed_browser_lease;
                const bool tombstoned_before_cleanup = mcp_lease_registry_release(
                    browser_lease.lease_token,
                    browser_lease.operation_generation,
                    "tool_call_timeout_camoufox_sidecar_pre_cleanup_tombstone");
                if (tombstoned_before_cleanup) {
                    camoufox_stale_cleanup = mcp_camoufox_cleanup_stale_sidecar(
                        browser_lease,
                        diag_id,
                        request_id,
                        tool_name,
                        timeout_resolution.action);
                } else {
                    camoufox_stale_cleanup = mcp_camoufox_stale_cleanup_rejected(
                        browser_lease,
                        std::vector<std::string>{"lease_tombstone"},
                        diag_id,
                        request_id,
                        tool_name,
                        timeout_resolution.action);
                }
                camoufox_stale_cleanup["lease_tombstoned_before_cleanup"] = tombstoned_before_cleanup;
            } else {
                mcp_lease_registry_snapshot_t empty_lease;
                camoufox_stale_cleanup = mcp_camoufox_stale_cleanup_rejected(
                    empty_lease,
                    std::vector<std::string>{"browser_external_lease"},
                    diag_id,
                    request_id,
                    tool_name,
                    timeout_resolution.action);
            }
        }
        {
            const active_session_owner_snapshot_t stuck_owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_timeout_lock_owner seq=%llu diag_id=%s request_id='%s' tool='%s' owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_request_id=%s owner_pid=%lu owner_tid=%lu owner_target_pid=%u owner_session='%s' owner_target='%s' owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_stale=%d owner_fenced=%d owner_commit_eligible=%d owner_phase=%s owner_token=%llu owner_generation=%llu owner_registry_generation=%llu lease_cancelled=%zu lease_stale=%zu lease_fenced=%zu",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                tool_name.c_str(),
                stuck_owner.tool.c_str(),
                stuck_owner.lane.c_str(),
                stuck_owner.diag_id.c_str(),
                stuck_owner.request_id.c_str(),
                static_cast<unsigned long>(stuck_owner.pid),
                static_cast<unsigned long>(stuck_owner.tid),
                stuck_owner.target_pid,
                stuck_owner.session_id.c_str(),
                stuck_owner.target_id.c_str(),
                static_cast<unsigned long long>(stuck_owner.owner_age_ms),
                static_cast<unsigned long long>(stuck_owner.deadline_ms),
                stuck_owner.cancelled ? 1 : 0,
                stuck_owner.stale ? 1 : 0,
                stuck_owner.fenced ? 1 : 0,
                stuck_owner.commit_eligible ? 1 : 0,
                stuck_owner.phase.c_str(),
                static_cast<unsigned long long>(stuck_owner.token),
                static_cast<unsigned long long>(stuck_owner.operation_generation),
                static_cast<unsigned long long>(stuck_owner.registry_generation),
                timeout_cancelled,
                timeout_stale,
                timeout_fenced);
        }
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            dispatch_metrics = state->metrics;
            if (dispatch_metrics.lane.empty())
                dispatch_metrics.lane = predicted_tool_lane(found, arguments);
        }
        json diag = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, dependency_status,
            dispatch_metrics, meta, true);
        diag["started"] = state->started.load(std::memory_order_acquire);
        diag["finished"] = state->finished.load(std::memory_order_acquire);
        diag["action"] = timeout_resolution.action;
        diag["queue_owner"] = queue_owner;
        diag["requested_timeout_ms"] = timeout_resolution.requested_ms;
        diag["effective_timeout_ms"] = timeout_ms;
        diag["requested_deadline_ms"] = requested_deadline_ms;
        diag["effective_deadline_ms"] = deadline_ms;
        diag["timeout_source"] = timeout_resolution.source;
        diag["timeout_max_ms"] = timeout_resolution.max_ms;
        diag["action_aware_timeout"] = timeout_resolution.action_aware;
        diag["explicit_timeout"] = timeout_resolution.explicit_timeout;
        diag["late_result_disposition"] = "fenced_after_timeout";
        diag["late_result_fence"] = late_evidence;
        if (!camoufox_stale_cleanup.empty()) {
            diag["camoufox_stale_cleanup"] = camoufox_stale_cleanup;
            const bool cleanup_cleaned = camoufox_stale_cleanup.value("cleaned", false);
            const bool cleanup_rejected = camoufox_stale_cleanup.value("rejected", false);
            diag["late_result_disposition"] = cleanup_cleaned
                ? "tombstoned_external_sidecar_cleanup"
                : (cleanup_rejected ? "tombstoned_cleanup_rejected" : "tombstoned_cleanup_incomplete");
            diag["residual"] = cleanup_cleaned
                ? "operation lease tombstoned; proven Camoufox reverse-MCP sidecar process tree was reaped"
                : "operation lease tombstoned; external sidecar cleanup was not performed without complete proof or did not fully reap";
        } else {
            diag["residual"] = "cooperative cancellation requested; late result delivery is fenced by lease generation";
        }
        diag["lease_cancelled_count"] = timeout_cancelled;
        diag["lease_stale_count"] = timeout_stale;
        diag["lease_fenced_count"] = timeout_fenced;
        diag["lease_registry"] = mcp_lease_registry_bounded_snapshot(8, 8);
        diag["capacity"] = capacity_prediction_data;
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_timeout seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s timeout_ms=%llu requested_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu started=%d finished=%d cancelled=1 elapsed_ms=%llu late_result_disposition=%s lease_token=%llu operation_generation=%llu registry_generation=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_resolution.action.c_str(),
            domain.c_str(),
            dispatch_metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(timeout_ms),
            static_cast<unsigned long long>(timeout_resolution.requested_ms),
            static_cast<unsigned long long>(requested_deadline_ms),
            static_cast<unsigned long long>(deadline_ms),
            static_cast<unsigned long long>(diag.value("queue_wait_ms", 0ull)),
            static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
            static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
            state->started.load(std::memory_order_acquire) ? 1 : 0,
            state->finished.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin),
            diag.value("late_result_disposition", std::string("fenced_after_timeout")).c_str(),
            static_cast<unsigned long long>(late_evidence.value("lease_token", 0ull)),
            static_cast<unsigned long long>(late_evidence.value("operation_generation", 0ull)),
            static_cast<unsigned long long>(late_evidence.value("registry_generation", 0ull)));
        if (is_camoufox_browser_tool_name(tool_name))
        {
            diag::log_tagged_fmt("mcp_srv",
                "browser_tool_timeout seq=%llu diag_id=%s request_id='%s' queue_owner=%s tool='%s' action='%s' domain='%s' lane='%s' requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d explicit_timeout=%d queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu started=%d finished=%d cancel_state=signalled elapsed_ms=%llu late_result_disposition=%s",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                queue_owner.c_str(),
                tool_name.c_str(),
                timeout_resolution.action.c_str(),
                domain.c_str(),
                dispatch_metrics.lane.c_str(),
                static_cast<unsigned long long>(timeout_resolution.requested_ms),
                static_cast<unsigned long long>(timeout_ms),
                static_cast<unsigned long long>(requested_deadline_ms),
                static_cast<unsigned long long>(deadline_ms),
                timeout_resolution.source.c_str(),
                static_cast<unsigned long long>(timeout_resolution.max_ms),
                timeout_resolution.action_aware ? 1 : 0,
                timeout_resolution.explicit_timeout ? 1 : 0,
                static_cast<unsigned long long>(diag.value("queue_wait_ms", 0ull)),
                static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
                static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
                state->started.load(std::memory_order_acquire) ? 1 : 0,
                state->finished.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(mcp_now_ms() - call_begin),
                diag.value("late_result_disposition", std::string("fenced_after_timeout")).c_str());
        }
        json err = make_error(id, -32070, "MCP tool call timed out; cancellation was signalled and late delivery was fenced. Diagnostic id: " + diag_id);
        err["error"]["data"] = std::move(diag);
        tool_capacity_lease.release("timeout");
        record_tool_audit_event(tool_name, arguments, "timed_out", false, err["error"], "MCP tool call timed out; cancellation was signalled and late delivery was fenced.", call_begin, diag_id, request_id);
        return err;
    }

    tool_result_t tr = future.get();
    {
        std::lock_guard<std::mutex> lk(state->mtx);
        dispatch_metrics = state->metrics;
        if (dispatch_metrics.lane.empty())
            dispatch_metrics.lane = predicted_tool_lane(found, arguments);
    }
    const bool cancelled = call_scope.token && call_scope.token->load(std::memory_order_acquire);
    json diagnostics = tool_diagnostics_json(
        seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
        timeout_ms, deadline_ms, payload_shape, validation_status, dependency_status,
        dispatch_metrics, meta, cancelled);
    diagnostics["action"] = timeout_resolution.action;
    diagnostics["queue_owner"] = queue_owner;
    diagnostics["requested_timeout_ms"] = timeout_resolution.requested_ms;
    diagnostics["effective_timeout_ms"] = timeout_ms;
    diagnostics["requested_deadline_ms"] = requested_deadline_ms;
    diagnostics["effective_deadline_ms"] = deadline_ms;
    diagnostics["timeout_source"] = timeout_resolution.source;
    diagnostics["timeout_max_ms"] = timeout_resolution.max_ms;
    diagnostics["action_aware_timeout"] = timeout_resolution.action_aware;
    diagnostics["explicit_timeout"] = timeout_resolution.explicit_timeout;
    diagnostics["capacity"] = capacity_prediction_data;
    auto release_browser_external_lease = [&](const char* reason) {
        if (!browser_tool_call)
            return;
        mcp_lease_registry_snapshot_t browser_lease;
        bool release_browser_lease = false;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            browser_lease = state->browser_external_lease;
            release_browser_lease = state->browser_external_lease_active;
            state->browser_external_lease_active = false;
        }
        if (release_browser_lease) {
            diagnostics["browser_external_lease"] = mcp_lease_snapshot_json(browser_lease);
            mcp_lease_registry_release(browser_lease.lease_token, browser_lease.operation_generation, reason ? reason : "scope_exit");
        }
    };
    json delivery_evidence = json::object();
    if (delivery_fence && !delivery_fence->claim_delivery("jsonrpc_tools_call", &delivery_evidence)) {
        diagnostics["late_result_disposition"] = delivery_evidence.value("disposition", std::string("discarded_late_result"));
        diagnostics["late_result_fence"] = delivery_evidence;
        json stale_result;
        stale_result["content"] = json::array({
            json{{"type", "text"}, {"text", "MCP late tool result was fenced and discarded before delivery."}}
        });
        stale_result["isError"] = true;
        stale_result["_meta"]["diagnostics"] = diagnostics;
        stale_result["_meta"]["error"] = json{
            {"code", "MCP_LATE_RESULT_DISCARDED"},
            {"message", "MCP late tool result was fenced and discarded before delivery."},
            {"details", delivery_evidence}
        };
        release_browser_external_lease("late_result_discarded");
        stale_result["_meta"]["diagnostics"] = diagnostics;
        record_tool_audit_event(tool_name, arguments, "discarded", false, stale_result, "MCP late tool result was fenced and discarded before delivery.", call_begin, diag_id, request_id);
        tool_capacity_lease.release("late_result_discarded");
        return make_result(id, stale_result);
    }
    diagnostics["late_result_disposition"] = delivery_evidence.value("disposition", cancelled ? std::string("cancelled_before_delivery") : std::string("delivered"));
    diagnostics["late_result_fence"] = delivery_evidence;
    diag::log_tagged_fmt("mcp_srv",
        "handle_tools_call result seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' success=%d domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu cancelled=%d elapsed_ms=%llu late_result_disposition=%s",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        tool_name.c_str(),
        timeout_resolution.action.c_str(),
        tr.success ? 1 : 0,
        domain.c_str(),
        dispatch_metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(timeout_resolution.requested_ms),
        static_cast<unsigned long long>(timeout_ms),
        static_cast<unsigned long long>(requested_deadline_ms),
        static_cast<unsigned long long>(deadline_ms),
        static_cast<unsigned long long>(diagnostics.value("queue_wait_ms", 0ull)),
        static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
        static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
        cancelled ? 1 : 0,
        static_cast<unsigned long long>(mcp_now_ms() - call_begin),
        cancelled ? "cancelled_before_delivery" : "delivered");

    if (cancelled) {
        json cancel_result;
        cancel_result["content"] = json::array({
            json{{"type", "text"}, {"text", "Tool call cancelled by client request."}}
        });
        cancel_result["isError"] = true;
        cancel_result["_meta"]["diagnostics"] = diagnostics;
        release_browser_external_lease("cancellation");
        cancel_result["_meta"]["diagnostics"] = diagnostics;
        record_tool_audit_event(tool_name, arguments, "cancelled", false, cancel_result, "Tool call cancelled by client request.", call_begin, diag_id, request_id);
        tool_capacity_lease.release("cancellation");
        return make_result(id, cancel_result);
    }

    json content = json::array();
    if (!tr.text.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(tr.text)}});
    }
    if (!tr.data.is_null() && !tr.data.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(json_dump_safe(tr.data, 2))}});
    }
    if (content.empty()) {
        content.push_back({{"type", "text"}, {"text", tr.success
            ? "Tool executed successfully (no output)."
            : "Tool execution failed (no details)."}});
    }

    json result;
    result["content"] = content;
    if (tr.success)
        result["structuredContent"] = tr.data.is_null() ? json::object() : tr.data;
    if (!tr.success) {
        result["isError"] = true;
        if (has_structured_tool_error(tr)) {
            json err = structured_tool_error(tr);
            result["_meta"]["error"] = err;
        }
    }
    if (tr.meta.is_object()) {
        for (const auto& entry : tr.meta.items())
            result["_meta"][entry.key()] = entry.value();
    }
    release_browser_external_lease(mcp_tool_release_reason_from_result(tr, false));
    result["_meta"]["diagnostics"] = diagnostics;
    tool_capacity_lease.release(mcp_tool_release_reason_from_result(tr, false));
    record_tool_audit_event(tool_name,
                            arguments,
                            tr.success ? std::string("completed") : std::string("failed"),
                            tr.success,
                            result,
                            tr.success ? std::string() : tr.text,
                            call_begin,
                            diag_id,
                            request_id);
    return make_result(id, result);
}

json server_t::handle_resources_list(const json& id, const json&)
{
    json resources = json::array();

    resources.push_back({
        {"uri",         "standalone://driver-status"},
        {"name",        "Driver Status"},
        {"description", "Current driver and process attachment state"},
        {"mimeType",    "application/json"}
    });

    resources.push_back({
        {"uri",         "standalone://loaded-file"},
        {"name",        "Loaded File Info"},
        {"description", "Information about the currently loaded PE file"},
        {"mimeType",    "application/json"}
    });

    json result;
    result["resources"] = resources;
    return make_result(id, result);
}

json server_t::handle_resources_read(const json& id, const json& params)
{
    if (!params.contains("uri") || !params["uri"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params["uri"].get<std::string>();
    json text_content;

    if (uri == "standalone://driver-status") {
        json status;
        status["ready"]       = driver_bridge::is_loaded();
        status["attached_pid"]= driver_bridge::attached_pid();
        status["status"]      = driver_bridge::status();
        text_content = status;
    }
    else if (uri == "standalone://loaded-file") {
        text_content = json{{"info", "Use disassemble_file tool to load and inspect PE files."}};
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);
    }

    json contents = json::array();
    contents.push_back({
        {"uri",      uri},
        {"mimeType", "application/json"},
        {"text",     json_dump_safe(text_content, 2)}
    });

    json result;
    result["contents"] = contents;
    return make_result(id, result);
}

json server_t::handle_prompts_list(const json& id, const json&)
{
    json prompts = json::array();

    prompts.push_back({
        {"name",        "analyze_memory"},
        {"description", "Read and analyze memory at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to analyze"}, {"required", true}},
            {{"name", "size"},    {"description", "Number of bytes to read (default 256)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "disassemble_region"},
        {"description", "Disassemble code at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to disassemble"}, {"required", true}},
            {{"name", "count"},   {"description", "Max instructions (default 50)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "sandbox_analysis"},
        {"description", "Run a binary in Windows Sandbox and analyze its output"},
        {"arguments",   json::array({
            {{"name", "path"}, {"description", "Path to the executable to analyze"}, {"required", true}}
        })}
    });

    json result;
    result["prompts"] = prompts;
    return make_result(id, result);
}

json server_t::handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params["name"].get<std::string>();
    json arguments = params.value("arguments", json::object());

    json messages = json::array();

    if (name == "analyze_memory") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Read and analyze the memory at address " + addr + " in the attached process.\n"
            "Use the read_memory tool to fetch the bytes, then:\n"
            "1. Show a hex dump of the data\n"
            "2. Identify any strings or recognizable patterns\n"
            "3. Disassemble if the region appears to contain code\n"
            "4. Note any pointers or interesting values\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "disassemble_region") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Disassemble the code at address " + addr + " in the attached process.\n"
            "Use the disassemble_zydis tool, then:\n"
            "1. Identify the function's purpose\n"
            "2. Analyze control flow (branches, loops, calls)\n"
            "3. Note any system calls, API calls, or string references\n"
            "4. Look for security-relevant patterns\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "sandbox_analysis") {
        std::string path = arguments.value("path", "");
        if (path.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'path'");

        std::string prompt =
            "Execute the binary at '" + path + "' in Windows Sandbox.\n"
            "Use the sandbox_execute tool, then:\n"
            "1. Examine the stdout/stderr output\n"
            "2. Check if the process timed out or was killed\n"
            "3. Note the peak memory usage\n"
            "4. Investigate any suspicious behavior indicators\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);
    }

    json result;
    result["description"] = name;
    result["messages"]    = messages;
    return make_result(id, result);
}

json server_t::route_request(const json& msg)
{
    if (tls_http_request_id != 0 && !tls_local_capability_authenticated)
        return make_error(
            msg.is_object() && msg.contains("id") ? msg["id"] : json(nullptr),
            JSONRPC_INVALID_REQUEST,
            "MCP local capability transport authentication is required.");

    if (!msg.is_object())
        return make_error(nullptr, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");

    std::string method = msg.value("method", "");
    diag::log_tagged_fmt("mcp_srv", "route_request method='%s' request_id='%s' params_type='%s' payload_bytes=%zu",
        method.c_str(), request_id_string(msg.contains("id") ? msg["id"] : json(nullptr)).c_str(),
        payload_shape_summary(msg.value("params", json::object())).c_str(), msg.dump().size());
    json id     = msg.contains("id") ? msg["id"] : json(nullptr);
    json params = msg.value("params", json::object());
    bool is_notification = !msg.contains("id");
    if (!params.is_object() && !params.is_null()) {
        diag::log_tagged_fmt("mcp_srv", "route_request invalid_params_type method='%s' request_id='%s' params_type='%s' payload_bytes=%zu",
            method.c_str(), request_id_string(id).c_str(), payload_shape_summary(params).c_str(), msg.dump().size());
        if (is_notification)
            return json();
        return make_error(id, JSONRPC_INVALID_PARAMS, "The 'params' field must be a JSON object.");
    }
    std::string route_tool_name;
    if (method == "tools/call" && params.is_object() && params.contains("name") && params["name"].is_string())
        route_tool_name = params["name"].get<std::string>();
    scoped_mcp_route_dispatch_diag_t route_diag(method, request_id_string(id), route_tool_name);
    if (method.empty()) {
        (void)diagnose_capacity("jsonrpc_route_invalid",
            capacity_route_context(current_mcp_transport(),
                current_mcp_route(),
                "missing_method",
                current_mcp_principal(),
                "jsonrpc-missing-method",
                request_id_string(id),
                {},
                payload_shape_summary(msg)));
        return make_error(msg.value("id", json(nullptr)), JSONRPC_INVALID_REQUEST, "Missing 'method' field");
    }

    std::string routed_tool_name;
    std::string routed_payload_shape = payload_shape_summary(params);
    if (method == "tools/call" && params.is_object() && params.contains("name") && params["name"].is_string()) {
        routed_tool_name = params["name"].get<std::string>();
        if (params.contains("arguments"))
            routed_payload_shape = payload_shape_summary(params["arguments"]);
    }
    if (method == "tools/call" && supplied_tool_arguments_are_non_object(params)) {
        const json& rejected_arguments = params["arguments"];
        const tool_result_t validation_failure = non_object_tool_arguments_failure();
        const std::string validation_request_id = request_id_string(id);
        const std::string validation_diag_id = "mcp-validation-" + validation_request_id;
        json err = make_error(id, JSONRPC_INVALID_PARAMS, validation_failure.text);
        err["error"]["data"] = structured_tool_error(validation_failure);
        err["error"]["data"]["tool"] = routed_tool_name.empty() ? std::string("<unknown>") : routed_tool_name;
        err["error"]["data"]["diagnostic_id"] = validation_diag_id;
        err["error"]["data"]["request_id"] = validation_request_id;
        err["error"]["data"]["disposition"] = "not_started";
        record_tool_audit_event(routed_tool_name.empty() ? std::string("<unknown>") : routed_tool_name,
            rejected_arguments,
            "rejected",
            false,
            err["error"],
            validation_failure.text,
            mcp_now_ms(),
            validation_diag_id,
            validation_request_id);
        return is_notification ? json() : err;
    }
    bool pre_dispatch_validated_here = false;
    if (method == "tools/call" && !routed_tool_name.empty() &&
        !pre_dispatch_validation_active()) {
        tool_def_t validation_tool;
        bool validation_tool_found = false;
        const auto registered_tool = _registry.find_tool(routed_tool_name, true);
        if (registered_tool) {
            validation_tool = *registered_tool;
            validation_tool_found = true;
        }
        if (validation_tool_found && !validation_tool.input_schema.is_null()) {
            const json routed_arguments = params.contains("arguments")
                ? params["arguments"] : json::object();
            tool_result_t validation_failure;
            bool hook_invoked = false;
            if (!validate_pre_dispatch_tool_input(validation_tool, routed_arguments, &validation_failure, &hook_invoked)) {
                const std::string validation_request_id = request_id_string(id);
                const std::string validation_diag_id = "mcp-validation-" + validation_request_id;
                json err = make_error(id,
                    JSONRPC_INVALID_PARAMS,
                    validation_failure.text.empty() ? std::string("Tool input validation failed.") : validation_failure.text);
                err["error"]["data"] = structured_tool_error(validation_failure);
                err["error"]["data"]["tool"] = routed_tool_name;
                err["error"]["data"]["diagnostic_id"] = validation_diag_id;
                err["error"]["data"]["request_id"] = validation_request_id;
                err["error"]["data"]["disposition"] = "not_started";
                record_tool_audit_event(routed_tool_name,
                    routed_arguments,
                    "rejected",
                    false,
                    err["error"],
                    validation_failure.text,
                    mcp_now_ms(),
                    validation_diag_id,
                    validation_request_id);
                return is_notification ? json() : err;
            }
            pre_dispatch_validated_here = hook_invoked;
        }
    }
    scoped_pre_dispatch_validation_t validation_scope(pre_dispatch_validated_here);
    std::shared_ptr<mcp_reserved_lane_scope_t> route_reserved_lane;
    const bool route_uses_reserved_lane = mcp_reserved_jsonrpc_method(method) || (method == "tools/call" && routed_tool_name == "cancel_command");
    if (route_uses_reserved_lane && !tls_reserved_control_lane) {
        const mcp_reserved_lane_t lane = mcp_reserved_lane_for_jsonrpc_method(method, routed_tool_name);
        if (!mcp_try_acquire_reserved_lane(lane,
                "jsonrpc_route_dispatch",
                current_mcp_principal(),
                current_mcp_route(),
                method,
                request_id_string(id),
                route_reserved_lane)) {
            if (is_notification)
                return json();
            json err = make_error(id, -32078, "Reserved MCP control lane exhausted.");
            err["error"]["data"] = mcp_reserved_lane_rejection_body(lane,
                request_id_string(id),
                current_mcp_route(),
                method,
                current_mcp_principal());
            return err;
        }
    }
    const capacity_diag::prediction_t route_capacity_prediction = diagnose_capacity("jsonrpc_route_pre_dispatch",
        capacity_route_context(current_mcp_transport(),
            current_mcp_route(),
            method.c_str(),
            current_mcp_principal(),
            "jsonrpc-route-" + request_id_string(id),
            request_id_string(id),
            routed_tool_name,
            routed_payload_shape));
    capacity_diag::scoped_activity_t route_capacity_activity;
    if (method != "tools/call")
        route_capacity_activity = capacity_diag::scoped_activity_t(route_capacity_prediction, mcp_now_ms());

    if (method == "initialize")               return handle_initialize(id, params);
    if (method == "notifications/initialized") return json();
    if (method == "ping")                     return handle_ping(id, params);
    if (method == "tools/list")               return handle_tools_list(id, params);
    if (method == "tools/call")               return handle_tools_call(id, params);
    if (method == "resources/list")           return handle_resources_list(id, params);
    if (method == "resources/read")           return handle_resources_read(id, params);
    if (method == "prompts/list")             return handle_prompts_list(id, params);
    if (method == "prompts/get")              return handle_prompts_get(id, params);
    if (method == "notifications/cancelled") {
        bool signalled = false;
        if (params.is_object() && params.contains("requestId"))
            signalled = signal_in_flight_cancel(params["requestId"]);
        diag::log_tagged_fmt("mcp_srv", "cancel_notification request_id='%s' has_request_id=%d signalled=%d params_type='%s'",
            request_id_string(params.is_object() && params.contains("requestId") ? params["requestId"] : json(nullptr)).c_str(),
            params.is_object() && params.contains("requestId") ? 1 : 0, signalled ? 1 : 0,
            payload_shape_summary(params).c_str());
        return json();
    }
    if (method == "logging/setLevel")
        return json();
    if (method == "shutdown")
        return make_result(id, json::object());
    if (is_notification)                      return json();

    return make_error(id, JSONRPC_METHOD_NOT_FOUND, "Unknown method: " + method);
}

std::string handle_body(server_t* self, const std::string& body, const std::function<bool()>& connection_closed)
{
    scoped_mcp_connection_closed_probe_t connection_probe(connection_closed);
    json parsed;
    try { parsed = json::parse(body); }
    catch (const json::parse_error& e) {
        diag::log_tagged_fmt("mcp_srv", "json_parse_error body_bytes=%zu byte=%zu what='%s'",
            body.size(), static_cast<std::size_t>(e.byte), e.what());
        return json_dump_safe(self->make_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array()) {
        if (parsed.empty())
            return json_dump_safe(self->make_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));

        const std::uint64_t batch_id = g_mcp_batch_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
        const std::size_t batch_size = parsed.size();
        const std::string batch_request_id = "jsonrpc-batch-" + std::to_string(batch_id);
        const capacity_diag::prediction_t batch_parent_capacity = diagnose_capacity("jsonrpc_batch_pre_expand",
            capacity_route_context(current_mcp_transport(),
                current_mcp_route(),
                "batch",
                current_mcp_principal(),
                batch_request_id,
                batch_request_id,
                {},
                payload_shape_summary(parsed),
                false,
                batch_size,
                0));
        capacity_diag::scoped_activity_t batch_parent_activity(batch_parent_capacity, mcp_now_ms());
        log_mcp_batch_fanout_diagnostic("pre_expand", batch_id, parsed, 0, 0, false, 0, batch_parent_capacity);
        if (batch_size > kMcpMaxBatchItems) {
            json err = self->make_error(nullptr, -32073, "JSON-RPC batch item limit exceeded.");
            err["error"]["data"] = {
                {"batch_id", batch_id},
                {"items", batch_size},
                {"max_items", kMcpMaxBatchItems}
            };
            diag::log_tagged_fmt("mcp_srv",
                "jsonrpc_batch_rejected batch=%llu items=%zu max_items=%zu reason=item_limit",
                static_cast<unsigned long long>(batch_id),
                batch_size,
                kMcpMaxBatchItems);
            g_mcp_batch_children_rejected.fetch_add(batch_size, std::memory_order_acq_rel);
            log_mcp_batch_fanout_diagnostic("rejected_item_limit", batch_id, parsed, 0, 0, false, 0, batch_parent_capacity);
            return json_dump_safe(err);
        }
        const std::uint64_t batch_start = mcp_now_ms();
        const auto& mcp_cfg = mcp_concurrency_config();
        diag::log_tagged_fmt("mcp_srv",
            "jsonrpc_batch_begin batch=%llu items=%zu workers=%zu max_queue=%zu",
            static_cast<unsigned long long>(batch_id),
            batch_size,
            mcp_cfg.batch_worker_threads,
            mcp_cfg.batch_max_queued_requests);

        struct batch_state_t {
            std::vector<json> responses;
            std::vector<unsigned char> has_response;
            std::vector<unsigned char> completed_items;
            std::vector<std::shared_ptr<mcp_batch_child_reservation_t>> reservations;
            std::size_t completed = 0;
            std::mutex mtx;
            std::condition_variable cv;
        };

        auto state = std::make_shared<batch_state_t>();
        state->responses.resize(batch_size);
        state->has_response.resize(batch_size, 0);
        state->completed_items.resize(batch_size, 0);
        state->reservations.resize(batch_size);
        std::atomic<std::size_t> overload_count{0};
        const mcp_route_identity_t batch_identity = tls_route_identity;
        std::vector<json> batch_prevalidation_errors(batch_size);
        std::vector<unsigned char> batch_prevalidation_failed(batch_size, 0);
        std::vector<unsigned char> batch_prevalidated(batch_size, 0);
        auto reject_batch_prevalidation = [&](std::size_t index,
                                              const json& item,
                                              const std::string& tool_name,
                                              const json& arguments,
                                              const tool_result_t& validation_failure) {
            batch_prevalidation_failed[index] = 1;
            const json item_id = item.contains("id") ? item["id"] : json(nullptr);
            const std::string validation_request_id = request_id_string(item_id);
            const std::string validation_diag_id = "mcp-batch-validation-" + std::to_string(batch_id) + "-" + std::to_string(index);
            json error_data = structured_tool_error(validation_failure);
            error_data["tool"] = tool_name;
            error_data["diagnostic_id"] = validation_diag_id;
            error_data["request_id"] = validation_request_id;
            error_data["batch_id"] = batch_id;
            error_data["batch_index"] = index;
            error_data["disposition"] = "not_started";
            record_tool_audit_event(tool_name,
                arguments,
                "rejected",
                false,
                error_data,
                validation_failure.text,
                mcp_now_ms(),
                validation_diag_id,
                validation_request_id);
            if (item.contains("id")) {
                json err = self->make_error(item_id,
                    JSONRPC_INVALID_PARAMS,
                    validation_failure.text.empty() ? std::string("Tool input validation failed.") : validation_failure.text);
                err["error"]["data"] = std::move(error_data);
                batch_prevalidation_errors[index] = std::move(err);
            }
        };
        for (std::size_t i = 0; i < batch_size; ++i) {
            const json& item = parsed[i];
            if (!item.is_object() || item.value("method", std::string()) != "tools/call" ||
                !item.contains("params") || !item["params"].is_object())
                continue;
            const json& call_params = item["params"];
            if (!call_params.contains("name") || !call_params["name"].is_string())
                continue;
            const std::string tool_name = call_params["name"].get<std::string>();
            if (supplied_tool_arguments_are_non_object(call_params)) {
                reject_batch_prevalidation(i,
                    item,
                    tool_name,
                    call_params["arguments"],
                    non_object_tool_arguments_failure());
                continue;
            }
            tool_def_t validation_tool;
            bool validation_tool_found = false;
            const auto registered_tool = self->_registry.find_tool(tool_name, true);
            if (registered_tool) {
                validation_tool = *registered_tool;
                validation_tool_found = true;
            }
            if (!validation_tool_found)
                continue;
            if (validation_tool.input_schema.is_null())
                continue;
            const json arguments = call_params.contains("arguments") ? call_params["arguments"] : json::object();
            tool_result_t validation_failure;
            bool hook_invoked = false;
            if (validate_pre_dispatch_tool_input(validation_tool, arguments, &validation_failure, &hook_invoked)) {
                batch_prevalidated[i] = hook_invoked ? 1 : 0;
                continue;
            }

            reject_batch_prevalidation(i, item, tool_name, arguments, validation_failure);
        }
        std::size_t reserved_control_batch_items = 0;
        std::size_t reservable_batch_items = 0;
        for (std::size_t i = 0; i < batch_size; ++i) {
            if (batch_prevalidation_failed[i])
                continue;
            if (mcp_jsonrpc_item_uses_reserved_lane(parsed[i]))
                ++reserved_control_batch_items;
            else
                ++reservable_batch_items;
        }
        mcp_batch_reservation_result_t batch_reservation;
        try {
            batch_reservation = reserve_mcp_batch_children(batch_identity.principal_id, reservable_batch_items);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-BATCH-REJECT phase=reservation_exception batch=%llu principal='%s' items=%zu reason='%s' disposition=not_started",
                static_cast<unsigned long long>(batch_id),
                batch_identity.principal_id.c_str(),
                batch_size,
                ex.what());
            g_mcp_batch_children_rejected.fetch_add(batch_size, std::memory_order_acq_rel);
            json responses = json::array();
            for (std::size_t i = 0; i < batch_size; ++i) {
                if (batch_prevalidation_failed[i]) {
                    if (!batch_prevalidation_errors[i].is_null())
                        responses.push_back(std::move(batch_prevalidation_errors[i]));
                    continue;
                }
                const json& item = parsed[i];
                if (!item.is_object() || !item.contains("id"))
                    continue;
                json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                json err = self->make_error(item_id, -32074, "JSON-RPC batch reservation failed; item was not started.");
                err["error"]["data"] = {
                    {"batch_id", batch_id},
                    {"index", i},
                    {"items", batch_size},
                    {"method", item.is_object() ? item.value("method", std::string()) : std::string("invalid")},
                    {"queue_owner", "mcp_jsonrpc_batch_reservation"},
                    {"reason", "reservation_exception"},
                    {"disposition", "not_started"}
                };
                responses.push_back(std::move(err));
            }
            return json_dump_safe(responses);
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-BATCH-REJECT phase=reservation_exception batch=%llu principal='%s' items=%zu reason='<unknown>' disposition=not_started",
                static_cast<unsigned long long>(batch_id),
                batch_identity.principal_id.c_str(),
                batch_size);
            g_mcp_batch_children_rejected.fetch_add(batch_size, std::memory_order_acq_rel);
            json responses = json::array();
            for (std::size_t i = 0; i < batch_size; ++i) {
                if (batch_prevalidation_failed[i]) {
                    if (!batch_prevalidation_errors[i].is_null())
                        responses.push_back(std::move(batch_prevalidation_errors[i]));
                    continue;
                }
                const json& item = parsed[i];
                if (!item.is_object() || !item.contains("id"))
                    continue;
                json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                json err = self->make_error(item_id, -32074, "JSON-RPC batch reservation failed; item was not started.");
                err["error"]["data"] = {
                    {"batch_id", batch_id},
                    {"index", i},
                    {"items", batch_size},
                    {"method", item.is_object() ? item.value("method", std::string()) : std::string("invalid")},
                    {"queue_owner", "mcp_jsonrpc_batch_reservation"},
                    {"reason", "reservation_exception"},
                    {"disposition", "not_started"}
                };
                responses.push_back(std::move(err));
            }
            return json_dump_safe(responses);
        }
        diag::log_tagged_fmt("mcp_srv",
            "MCP-BATCH-ADMIT phase=pre_expand batch=%llu principal='%s' requested=%zu reserved_control=%zu reservable=%zu admitted=%zu rejected=%zu observed_queued=%zu observed_active=%zu queued_limit=%zu active_limit=%zu reason=%s",
            static_cast<unsigned long long>(batch_id),
            batch_reservation.principal.c_str(),
            batch_size,
            reserved_control_batch_items,
            batch_reservation.requested,
            batch_reservation.admitted,
            batch_reservation.rejected,
            batch_reservation.observed_queued,
            batch_reservation.observed_active,
            batch_reservation.queued_limit,
            batch_reservation.active_limit,
            batch_reservation.reason.c_str());

        auto complete_item = [state](std::size_t index, json response) {
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                if (index >= state->completed_items.size() || state->completed_items[index])
                    return;
                state->completed_items[index] = 1;
                if (!response.is_null()) {
                    state->responses[index] = std::move(response);
                    state->has_response[index] = 1;
                }
                ++state->completed;
            }
            state->cv.notify_one();
        };

        auto log_batch_reject = [batch_id, batch_size, &batch_identity](const char* phase,
                                                                        std::size_t index,
                                                                        const std::string& method,
                                                                        const std::string& tool,
                                                                        const char* reason,
                                                                        const char* quota,
                                                                        std::size_t observed,
                                                                        std::size_t limit,
                                                                        std::uint64_t reservation_id,
                                                                        bool started) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-BATCH-REJECT phase=%s batch=%llu index=%zu items=%zu reservation=%llu principal='%s' route=%s transport=%s method='%s' tool='%s' reason=%s quota=%s observed=%zu limit=%zu started=%d disposition=%s",
                phase ? phase : "",
                static_cast<unsigned long long>(batch_id),
                index,
                batch_size,
                static_cast<unsigned long long>(reservation_id),
                batch_identity.principal_id.c_str(),
                batch_identity.route.c_str(),
                batch_identity.transport.c_str(),
                method.c_str(),
                tool.c_str(),
                reason ? reason : "batch_rejected",
                quota ? quota : "",
                observed,
                limit,
                started ? 1 : 0,
                started ? "after_start_incomplete" : "not_started");
        };

        auto log_batch_admit = [batch_id, batch_size, &batch_identity](const char* phase,
                                                                       std::size_t index,
                                                                       const std::string& method,
                                                                       const std::string& tool,
                                                                       const std::shared_ptr<mcp_batch_child_reservation_t>& reservation) {
            diag::log_tagged_fmt("mcp_srv",
                "MCP-BATCH-ADMIT phase=%s batch=%llu index=%zu items=%zu reservation=%llu principal='%s' route=%s transport=%s method='%s' tool='%s' active_limit=%zu queued_limit=%zu disposition=reserved",
                phase ? phase : "",
                static_cast<unsigned long long>(batch_id),
                index,
                batch_size,
                static_cast<unsigned long long>(reservation ? reservation->id() : 0),
                batch_identity.principal_id.c_str(),
                batch_identity.route.c_str(),
                batch_identity.transport.c_str(),
                method.c_str(),
                tool.c_str(),
                reservation ? reservation->active_limit() : 0,
                reservation ? reservation->queued_limit() : 0);
        };

        auto make_batch_not_started_error = [self, batch_id, batch_size](const json& item_id,
                                                                         std::size_t index,
                                                                         const std::string& method,
                                                                         const std::string& tool,
                                                                         const std::string& reason,
                                                                         const char* queue_owner,
                                                                         const json& capacity_data,
                                                                         std::uint64_t reservation_id,
                                                                         std::size_t observed,
                                                                         std::size_t limit) {
            json err = self->make_error(item_id, -32074, "JSON-RPC batch item was rejected before start.");
            err["error"]["data"] = {
                {"batch_id", batch_id},
                {"index", index},
                {"items", batch_size},
                {"method", method},
                {"tool", tool},
                {"queue_owner", queue_owner ? queue_owner : "mcp_jsonrpc_batch"},
                {"reservation_id", reservation_id},
                {"reason", reason},
                {"observed", observed},
                {"limit", limit},
                {"disposition", "not_started"}
            };
            if (!capacity_data.is_null())
                err["error"]["data"]["capacity"] = capacity_data;
            return err;
        };

        auto execute_item = [self, complete_item, log_batch_reject, make_batch_not_started_error, batch_id, batch_size, batch_identity, batch_start](std::size_t index,
                                                                                                                                       json item,
                                                                                                                                       std::shared_ptr<mcp_batch_child_reservation_t> reservation,
                                                                                                                                       json capacity_data,
                                                                                                                                       bool pre_dispatch_validated) {
            scoped_mcp_route_identity_t route_identity(batch_identity);
            const json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
            const std::string item_method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
            const std::string item_tool = item.is_object() && item.value("method", std::string()) == "tools/call" && item.contains("params") && item["params"].is_object() && item["params"].contains("name") && item["params"]["name"].is_string() ? item["params"]["name"].get<std::string>() : std::string();
            if (!reservation) {
                log_batch_reject("missing_reservation", index, item_method, item_tool, "missing_batch_reservation", "queued_batch_children_per_principal", 0, 0, 0, false);
                complete_item(index, make_batch_not_started_error(item_id, index, item_method, item_tool, "missing_batch_reservation", "mcp_jsonrpc_batch", capacity_data, 0, 0, 0));
                return;
            }
            std::string start_reason;
            if (!reservation->try_start(start_reason)) {
                reservation->cancel();
                log_batch_reject("start_rejected", index, item_method, item_tool, start_reason.c_str(), "active_batch_children_per_principal", 0, reservation->active_limit(), reservation->id(), false);
                complete_item(index, make_batch_not_started_error(item_id, index, item_method, item_tool, start_reason, "mcp_jsonrpc_batch", capacity_data, reservation->id(), 0, reservation->active_limit()));
                return;
            }
            scoped_mcp_batch_reservation_release_t reservation_release{reservation, "handler_exit"};
            scoped_call_cancel_t scoped_cancel(reservation->cancel_token());
            if (reservation->cancelled() || current_call_cancelled()) {
                log_batch_reject("cancelled_before_route", index, item_method, item_tool, "cancelled_before_dispatch", "batch_child_reserved_lane", 0, reservation->queued_limit(), reservation->id(), false);
                complete_item(index, make_batch_not_started_error(item_id, index, item_method, item_tool, "cancelled_before_dispatch", "mcp_jsonrpc_batch", capacity_data, reservation->id(), 0, reservation->queued_limit()));
                return;
            }
            if (mcp_now_ms() - batch_start >= kMcpBatchWaitTimeoutMs) {
                reservation->cancel();
                log_batch_reject("deadline_before_route", index, item_method, item_tool, "batch_deadline_expired_before_dispatch", "batch_child_reserved_lane", 0, reservation->queued_limit(), reservation->id(), false);
                complete_item(index, make_batch_not_started_error(item_id, index, item_method, item_tool, "batch_deadline_expired_before_dispatch", "mcp_jsonrpc_batch", capacity_data, reservation->id(), 0, reservation->queued_limit()));
                return;
            }
            scoped_mcp_batch_child_admission_t batch_child_admission(batch_id, index, batch_size, reservation);
            scoped_pre_dispatch_validation_t validation_scope(pre_dispatch_validated);
            try {
                json response = self->route_request(item);
                if (!item.contains("id"))
                    response = json();
                complete_item(index, std::move(response));
            } catch (const std::exception& ex) {
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_item_exception batch=%llu index=%zu err='%s'",
                    static_cast<unsigned long long>(batch_id),
                    index,
                    ex.what());
                if (item.is_object() && item.contains("id"))
                    complete_item(index, self->make_error(item["id"], JSONRPC_INTERNAL_ERROR, std::string("Request failed: ") + ex.what()));
            } catch (...) {
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_item_exception batch=%llu index=%zu err='<unknown>'",
                    static_cast<unsigned long long>(batch_id),
                    index);
                if (item.is_object() && item.contains("id"))
                    complete_item(index, self->make_error(item["id"], JSONRPC_INTERNAL_ERROR, "Request failed"));
            }
        };

        auto& executor = mcp_batch_executor();
        std::size_t reservation_cursor = 0;
        for (std::size_t i = 0; i < batch_size; ++i) {
            if (batch_prevalidation_failed[i]) {
                const json& rejected_item = parsed[i];
                const std::string rejected_method = rejected_item.is_object() ? rejected_item.value("method", std::string()) : std::string("invalid");
                const std::string rejected_tool = rejected_item.is_object() && rejected_item.value("method", std::string()) == "tools/call" && rejected_item.contains("params") && rejected_item["params"].is_object() && rejected_item["params"].contains("name") && rejected_item["params"]["name"].is_string() ? rejected_item["params"]["name"].get<std::string>() : std::string();
                log_batch_reject("schema_validation", i, rejected_method, rejected_tool, "schema_validation_failed", "pre_dispatch_validation", 0, 0, 0, false);
                complete_item(i, std::move(batch_prevalidation_errors[i]));
                continue;
            }
            json item = parsed[i];
            const bool item_prevalidated = batch_prevalidated[i] != 0;
            const bool item_reserved_control = mcp_jsonrpc_item_uses_reserved_lane(item);
            auto meta = make_executor_task_meta();
            std::shared_ptr<mcp_batch_child_reservation_t> reservation;
            if (!item_reserved_control && reservation_cursor < batch_reservation.reservations.size())
                reservation = batch_reservation.reservations[reservation_cursor++];
            {
                std::lock_guard<std::mutex> lk(meta->mtx);
                meta->request_id = item.is_object() && item.contains("id") ? request_id_string(item["id"]) : "notification";
                meta->method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
                if (item.is_object() && item.value("method", std::string()) == "tools/call" &&
                    item.contains("params") && item["params"].is_object() &&
                    item["params"].contains("name") && item["params"]["name"].is_string()) {
                    meta->tool = item["params"]["name"].get<std::string>();
                    meta->domain = infer_tool_domain(meta->tool);
                    if (item["params"].contains("arguments"))
                        meta->payload_shape = payload_shape_summary(item["params"]["arguments"]);
                }
                meta->lane = item_reserved_control ? "jsonrpc_batch_reserved_control" : "jsonrpc_batch_item";
                meta->deadline_ms = batch_start + kMcpBatchWaitTimeoutMs;
                meta->route = batch_identity.route;
                meta->transport = batch_identity.transport;
                meta->principal_id = batch_identity.principal_id;
                meta->session_hash = batch_identity.session_hash;
                meta->batch_id = batch_id;
                meta->batch_index = i;
                meta->batch_size = batch_size;
                meta->external_tool = true;
                if (reservation)
                    meta->cancel_token = reservation->cancel_token();
            }
            json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
            const bool item_has_id = item.is_object() && item.contains("id");
            const std::string item_method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
            const std::string item_tool = item.is_object() && item.value("method", std::string()) == "tools/call" && item.contains("params") && item["params"].is_object() && item["params"].contains("name") && item["params"]["name"].is_string() ? item["params"]["name"].get<std::string>() : std::string();
            if (reservation) {
                reservation->bind_child(item_id, item_has_id);
                state->reservations[i] = reservation;
            }
            capacity_diag::request_context_t batch_capacity_ctx = capacity_route_context(batch_identity.transport.c_str(),
                batch_identity.route.c_str(),
                item_method.c_str(),
                batch_identity.principal_id,
                "mcp-batch-" + std::to_string(batch_id) + "-" + std::to_string(i),
                meta->request_id,
                item_tool,
                meta->payload_shape,
                true,
                batch_size,
                i);
            if (item_method == "tools/call" && !item_tool.empty() && item.is_object() && item.contains("params") && item["params"].is_object()) {
                tool_def_t batch_tool;
                bool batch_tool_found = false;
                const auto registered_tool = self->_registry.find_tool(item_tool, true);
                if (registered_tool) {
                    batch_tool = *registered_tool;
                    batch_tool_found = true;
                }
                const json batch_arguments = item["params"].contains("arguments") && item["params"]["arguments"].is_object()
                    ? item["params"]["arguments"] : json::object();
                if (batch_tool_found) {
                    const tool_timeout_resolution_t batch_timeout = resolve_tool_timeout(item_tool, batch_arguments);
                    const std::string batch_payload_shape = payload_shape_summary(batch_arguments);
                    const std::uint32_t batch_target_pid = target_pid_from_args(batch_arguments);
                    const std::string batch_lane = predicted_tool_lane(batch_tool, batch_arguments);
                    batch_capacity_ctx = capacity_tool_context(batch_identity.transport.c_str(),
                        batch_identity.route.c_str(),
                        "tools/call",
                        batch_identity.principal_id,
                        "mcp-batch-" + std::to_string(batch_id) + "-" + std::to_string(i),
                        meta->request_id,
                        batch_tool,
                        batch_arguments,
                        batch_timeout,
                        batch_lane,
                        batch_payload_shape,
                        batch_target_pid,
                        true,
                        batch_size,
                        i);
                    {
                        std::lock_guard<std::mutex> lk(meta->mtx);
                        meta->lane = batch_lane;
                        meta->payload_shape = batch_payload_shape;
                        meta->target_pid = batch_target_pid;
                        meta->target_id = capacity_target_id_from_args(batch_arguments, batch_target_pid);
                        meta->read_only = batch_tool.read_only;
                        meta->mutating = !batch_tool.read_only || is_analysis_session_management_tool(batch_tool.name);
                        meta->driver_debugger = capacity_driver_debugger_tool(batch_tool, infer_tool_domain(batch_tool.name));
                        meta->background_command = capacity_background_command_tool(batch_tool.name, batch_arguments);
                        meta->long_running = capacity_diag::classify_long_running(batch_capacity_ctx);
                        meta->action = batch_timeout.action;
                    }
                } else {
                    batch_capacity_ctx.tool_known = false;
                }
            }
            if (item_reserved_control) {
                batch_capacity_ctx.reserved_lane = true;
                batch_capacity_ctx.lane = "reserved_control";
            }
            const capacity_diag::prediction_t batch_capacity_prediction = diagnose_capacity("jsonrpc_batch_child_pre_enqueue", batch_capacity_ctx);
            const json batch_capacity_data = capacity_diag::prediction_json(batch_capacity_prediction);
            if (item_reserved_control) {
                const mcp_reserved_lane_t reserved_lane = mcp_reserved_lane_for_jsonrpc_item(item);
                std::shared_ptr<mcp_reserved_lane_scope_t> reserved_scope = tls_reserved_control_lane;
                bool reserved_acquired_here = false;
                if (!reserved_scope) {
                    if (!mcp_try_acquire_reserved_lane(reserved_lane,
                            "jsonrpc_batch_reserved_inline",
                            batch_identity.principal_id,
                            batch_identity.route,
                            item_method,
                            meta->request_id,
                            reserved_scope)) {
                        overload_count.fetch_add(1u, std::memory_order_acq_rel);
                        log_batch_reject("reserved_lane_rejected",
                            i,
                            item_method,
                            item_tool,
                            "reserved_lane_exhausted",
                            mcp_reserved_lane_name(reserved_lane),
                            mcp_reserved_lane_active(reserved_lane),
                            mcp_reserved_lane_limit(reserved_lane),
                            0,
                            false);
                        g_mcp_batch_children_rejected.fetch_add(1u, std::memory_order_acq_rel);
                        complete_item(i, make_batch_not_started_error(item_id,
                            i,
                            item_method,
                            item_tool,
                            "reserved_lane_exhausted",
                            "mcp_jsonrpc_batch_reserved_lane",
                            batch_capacity_data,
                            0,
                            mcp_reserved_lane_active(reserved_lane),
                            mcp_reserved_lane_limit(reserved_lane)));
                        continue;
                    }
                    reserved_acquired_here = true;
                }
                log_batch_admit("reserved_inline", i, item_method, item_tool, nullptr);
                capacity_diag::scoped_activity_t batch_capacity_activity(batch_capacity_prediction, mcp_now_ms());
                {
                    scoped_reserved_lane_tls_t reserved_lane_tls(reserved_scope);
                    scoped_pre_dispatch_validation_t validation_scope(item_prevalidated);
                    try {
                        scoped_mcp_route_identity_t route_identity(batch_identity);
                        json response = self->route_request(item);
                        if (!item.contains("id"))
                            response = json();
                        complete_item(i, std::move(response));
                    } catch (const std::exception& ex) {
                        diag::log_tagged_fmt("mcp_srv",
                            "jsonrpc_batch_reserved_item_exception batch=%llu index=%zu err='%s'",
                            static_cast<unsigned long long>(batch_id),
                            i,
                            ex.what());
                        complete_item(i, self->make_error(item_id, JSONRPC_INTERNAL_ERROR, std::string("Request failed: ") + ex.what()));
                    } catch (...) {
                        diag::log_tagged_fmt("mcp_srv",
                            "jsonrpc_batch_reserved_item_exception batch=%llu index=%zu err='<unknown>'",
                            static_cast<unsigned long long>(batch_id),
                            i);
                        complete_item(i, self->make_error(item_id, JSONRPC_INTERNAL_ERROR, "Request failed"));
                    }
                }
                if (reserved_acquired_here && reserved_scope)
                    reserved_scope->release("reserved_inline_complete");
                continue;
            }
            if (!reservation) {
                overload_count.fetch_add(1u, std::memory_order_acq_rel);
                log_batch_reject("reservation_rejected", i, item_method, item_tool, batch_reservation.reason.c_str(), "queued_batch_children_per_principal", batch_reservation.observed_queued + batch_reservation.observed_active + i, batch_reservation.queued_limit, 0, false);
                complete_item(i, make_batch_not_started_error(item_id,
                    i,
                    item_method,
                    item_tool,
                    batch_reservation.reason,
                    "mcp_jsonrpc_batch_reservation",
                    batch_capacity_data,
                    0,
                    batch_reservation.observed_queued + batch_reservation.observed_active + i,
                    batch_reservation.queued_limit));
                continue;
            }
            log_batch_admit("child_pre_enqueue", i, item_method, item_tool, reservation);
            if (!executor.enqueue([execute_item, i, item = std::move(item), batch_capacity_prediction, reservation, batch_capacity_data, item_prevalidated]() mutable {
                capacity_diag::scoped_activity_t batch_capacity_activity(batch_capacity_prediction, mcp_now_ms());
                execute_item(i, std::move(item), reservation, std::move(batch_capacity_data), item_prevalidated);
            }, meta)) {
                reservation->cancel();
                reservation->release("enqueue_rejected");
                overload_count.fetch_add(1u, std::memory_order_acq_rel);
                g_mcp_batch_children_rejected.fetch_add(1u, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_enqueue_rejected batch=%llu index=%zu items=%zu disposition=item_error",
                    static_cast<unsigned long long>(batch_id),
                    i,
                    batch_size);
                log_batch_reject("executor_enqueue_rejected", i, item_method, item_tool, "executor_queue_full", "mcp_jsonrpc_batch", 0, mcp_cfg.batch_max_queued_requests, reservation->id(), false);
                log_mcp_batch_fanout_diagnostic("item_enqueue_rejected", batch_id, parsed, 0, overload_count.load(std::memory_order_acquire), false, mcp_now_ms() - batch_start, batch_parent_capacity);
                json err = self->make_error(item_id, -32074, "JSON-RPC batch executor queue is full; item was not started.");
                err["error"]["data"] = {
                    {"batch_id", batch_id},
                    {"index", i},
                    {"items", batch_size},
                    {"method", item_method},
                    {"tool", item_tool},
                    {"queue_owner", "mcp_jsonrpc_batch"},
                    {"reservation_id", reservation->id()},
                    {"disposition", "not_started"}
                };
                err["error"]["data"]["capacity"] = batch_capacity_data;
                complete_item(i, std::move(err));
            }
        }

        bool batch_complete = false;
        std::string batch_incomplete_reason;
        {
            std::unique_lock<std::mutex> lk(state->mtx);
            const std::uint64_t wait_deadline = batch_start + kMcpBatchWaitTimeoutMs;
            while (state->completed < batch_size) {
                if (connection_closed_now(connection_closed)) {
                    batch_incomplete_reason = "connection_closed";
                    break;
                }
                if (current_call_cancelled()) {
                    batch_incomplete_reason = "cancelled";
                    diag::log_tagged_fmt("mcp_srv",
                        "MCP-BATCH-CANCEL batch=%llu items=%zu completed=%zu elapsed_ms=%llu reason=caller_cancelled",
                        static_cast<unsigned long long>(batch_id),
                        batch_size,
                        state->completed,
                        static_cast<unsigned long long>(mcp_now_ms() - batch_start));
                    break;
                }
                if (self->_stop_requested.load(std::memory_order_acquire)) {
                    batch_incomplete_reason = "shutdown";
                    break;
                }
                const std::uint64_t now = mcp_now_ms();
                if (now >= wait_deadline) {
                    batch_incomplete_reason = "timeout";
                    break;
                }
                const std::uint64_t remaining = wait_deadline - now;
                const std::uint64_t slice = (std::min<std::uint64_t>)(remaining, 250);
                state->cv.wait_for(lk, std::chrono::milliseconds(slice));
            }
            batch_complete = state->completed >= batch_size;
            if (!batch_complete) {
                diag::log_tagged_fmt("mcp_srv",
                    "MCP-BATCH-INCOMPLETE batch=%llu items=%zu completed=%zu reason=%s elapsed_ms=%llu disposition=cancelled_or_not_started",
                    static_cast<unsigned long long>(batch_id),
                    batch_size,
                    state->completed,
                    batch_incomplete_reason.empty() ? "incomplete" : batch_incomplete_reason.c_str(),
                    static_cast<unsigned long long>(mcp_now_ms() - batch_start));
                for (std::size_t i = 0; i < batch_size; ++i) {
                    if (state->completed_items[i])
                        continue;
                    const json& item = parsed[i];
                    json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                    auto reservation = i < state->reservations.size() ? state->reservations[i] : nullptr;
                    const bool started = reservation && reservation->started();
                    if (reservation) {
                        reservation->cancel();
                        reservation->release(batch_incomplete_reason.empty() ? "incomplete" : batch_incomplete_reason.c_str());
                    }
                    const std::string method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
                    const std::string tool = item.is_object() && item.value("method", std::string()) == "tools/call" && item.contains("params") && item["params"].is_object() && item["params"].contains("name") && item["params"]["name"].is_string() ? item["params"]["name"].get<std::string>() : std::string();
                    log_batch_reject(batch_incomplete_reason.empty() ? "incomplete" : batch_incomplete_reason.c_str(),
                        i,
                        method,
                        tool,
                        started ? "batch_item_incomplete_after_start" : "batch_item_not_started_before_completion",
                        "batch_child_reserved_lane",
                        0,
                        reservation ? reservation->queued_limit() : batch_reservation.queued_limit,
                        reservation ? reservation->id() : 0,
                        started);
                    json err = self->make_error(item_id, started ? -32071 : -32074, started ? "JSON-RPC batch item timed out before producing a response." : "JSON-RPC batch item was not started before the batch ended.");
                    err["error"]["data"] = {
                        {"batch_id", batch_id},
                        {"index", i},
                        {"timeout_ms", kMcpBatchWaitTimeoutMs},
                        {"elapsed_ms", mcp_now_ms() - batch_start},
                        {"method", method},
                        {"tool", tool},
                        {"reason", batch_incomplete_reason.empty() ? "incomplete" : batch_incomplete_reason},
                        {"reservation_id", reservation ? reservation->id() : 0},
                        {"disposition", started ? "timeout_or_cancelled_after_start" : "not_started"}
                    };
                    state->responses[i] = std::move(err);
                    state->has_response[i] = 1;
                    state->completed_items[i] = 1;
                    ++state->completed;
                }
            }
        }

        json responses = json::array();
        for (std::size_t i = 0; i < batch_size; ++i) {
            if (state->has_response[i])
                responses.push_back(std::move(state->responses[i]));
        }
        diag::log_tagged_fmt("mcp_srv",
            "jsonrpc_batch_done batch=%llu items=%zu responses=%zu overload=%zu complete=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(batch_id),
            batch_size,
            responses.size(),
            overload_count.load(std::memory_order_acquire),
            batch_complete ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - batch_start));
        log_mcp_batch_fanout_diagnostic("done", batch_id, parsed, responses.size(), overload_count.load(std::memory_order_acquire), batch_complete, mcp_now_ms() - batch_start, batch_parent_capacity);
        if (responses.empty()) return "";
        return json_dump_safe(responses);
    }

    json response = self->route_request(parsed);
    if (response.is_null()) return "";
    return json_dump_safe(response);
}

bool server_t::start(int port)
{
    diag::log_tagged_fmt("mcp_srv", "start entry port=%d", port);
    if (_running.load())
    {
        diag::log_tagged_fmt("mcp_srv", "start already running port=%d", port);
        return true;
    }

    if (auto prior = find_server_worker_lifetime(this)) {
        if (!_server_done.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("mcp_srv", "start rejected server worker already starting port=%d", port);
            return false;
        }
        if (prior->thread.joinable() && !prior->thread.join_for(10000)) {
            diag::log_tagged_fmt("mcp_srv", "start prior worker join deadline exceeded worker_tid=%u running=%d disposition=restart_rejected_worker_lifetime_retained",
                static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                _running.load(std::memory_order_acquire) ? 1 : 0);
            return false;
        }
        erase_server_worker_lifetime(this, prior);
    }

    _stop_requested = false;
    _port = 0;

    if (!rotate_local_capability()) {
        diag::log_tagged("mcp_srv", "start rejected local capability generation failed");
        return false;
    }

    if (!_server_done.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("mcp_srv", "start rejected server worker already starting port=%d", port);
        log_runtime_executor_stats("start rejected");
        clear_local_capability();
        return false;
    }

    auto worker_lifetime = std::make_shared<server_worker_lifetime_t>();
    _server_done.store(false, std::memory_order_release);
    if (!install_server_worker_lifetime(this, worker_lifetime)) {
        _server_done.store(true, std::memory_order_release);
        diag::log_tagged_fmt("mcp_srv", "start rejected server worker lifetime already installed port=%d", port);
        clear_local_capability();
        return false;
    }

    auto worker_owner = std::shared_ptr<server_t>(new server_t(_state, false));
    auto worker_body = [worker_owner, port, worker_lifetime]() {
        server_t* self = worker_owner.get();
        const auto cleanup = [self, worker_lifetime]() {
            self->_running.store(false, std::memory_order_release);
            self->clear_local_capability();
            self->_server_worker_tid.store(0, std::memory_order_release);
            self->_server_done.store(true, std::memory_order_release);
            worker_lifetime->worker_tid.store(0, std::memory_order_release);
            erase_server_worker_lifetime(worker_lifetime);
        };
        const DWORD tid = GetCurrentThreadId();
        worker_lifetime->worker_tid.store(static_cast<std::uint32_t>(tid), std::memory_order_release);
        self->_server_worker_tid.store(static_cast<std::uint32_t>(tid), std::memory_order_release);
        diag::log_tagged_fmt("mcp_srv", "server_worker starting port=%d tid=%lu", port, static_cast<unsigned long>(tid));
        log_runtime_executor_stats("server_worker entry");
        if (self->_stop_requested.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("mcp_srv", "server_worker cancelled before listen port=%d tid=%lu", port, static_cast<unsigned long>(tid));
            cleanup();
            return;
        }
        try {
            self->server_thread_func(port);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='%s'", port, ex.what());
            self->_running.store(false, std::memory_order_release);
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='<unknown>'", port);
            self->_running.store(false, std::memory_order_release);
        }
        diag::log_tagged_fmt("mcp_srv", "server_worker exited port=%d tid=%lu", port, static_cast<unsigned long>(GetCurrentThreadId()));
        cleanup();
    };
    std::string worker_err;
    mcp_standalone::downstream::governor_t::instance().clear_shutdown();
    bool started = worker_lifetime->thread.start(worker_body, &worker_err, aida::infra::win_thread::default_stack_reserve, "mcp_server_worker");
    if (!started) {
        diag::log_tagged_fmt("mcp_srv", "start server worker native start failed err='%s'", worker_err.empty() ? "<none>" : worker_err.c_str());
        log_runtime_executor_stats("start native_worker_failed");
    }
    if (!started) {
        mark_server_worker_start(worker_lifetime, false);
        erase_server_worker_lifetime(this, worker_lifetime);
        _server_done.store(true, std::memory_order_release);
        mcp_standalone::downstream::governor_t::instance().request_shutdown();
        clear_local_capability();
        return false;
    }
    mark_server_worker_start(worker_lifetime, true);
    diag::log_tagged_fmt("mcp_srv", "start server worker accepted port=%d", port);

    for (int i = 0; i < 500 && !_running.load() && !_server_done.load(std::memory_order_acquire) && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    diag::log_tagged_fmt("mcp_srv", "start result running=%d port=%d",
        (int)_running.load(), _port.load(std::memory_order_acquire));
    if (!_running.load(std::memory_order_acquire))
        mcp_standalone::downstream::governor_t::instance().request_shutdown();
    return _running.load();
}

void server_t::stop()
{
    diag::log_tagged_fmt("mcp_srv", "stop entry running=%d", (int)_running.load());
    const std::uint32_t current_tid = static_cast<std::uint32_t>(GetCurrentThreadId());
    const bool on_server_worker = _server_worker_tid.load(std::memory_order_acquire) == current_tid;
    if (!_running.load() && _server_done.load(std::memory_order_acquire))
    {
        mcp_standalone::downstream::governor_t::instance().request_shutdown();
        release_all_stream_slots("stop_already_stopped");
        mcp_lease_registry_shutdown_cleanup("stop_already_stopped");
        mcp_tool_release_all_capacity_leases("stop_already_stopped");
        command_sessions::release_all_for_shutdown("stop_already_stopped");
        if (auto worker_lifetime = find_server_worker_lifetime(this)) {
            if (worker_lifetime->thread.joinable() && !worker_lifetime->thread.join_for(10000)) {
                diag::log_tagged_fmt("mcp_srv", "stop already_stopped join timeout worker_tid=%u running=%d",
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                log_runtime_executor_stats("stop already_stopped join timeout");
                return;
            }
            erase_server_worker_lifetime(this, worker_lifetime);
        }
        clear_local_capability();
        diag::log_tagged_fmt("mcp_srv", "stop already stopped");
        return;
    }
    _stop_requested = true;
    signal_all_in_flight_cancels();
    mcp_standalone::downstream::governor_t::instance().request_shutdown();
    release_all_stream_slots("stop_requested");
    mcp_lease_registry_shutdown_cleanup("stop_requested");
    mcp_tool_release_all_capacity_leases("stop_requested");
    command_sessions::release_all_for_shutdown("stop_requested");
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_active_server)
            static_cast<httplib::Server*>(_active_server)->stop();
    }
    auto worker_lifetime = find_server_worker_lifetime(this);
    if (!worker_lifetime) {
        const std::uint64_t wait_start = mcp_now_ms();
        bool timeout_logged = false;
        while (!_server_done.load(std::memory_order_acquire)) {
            const std::uint64_t elapsed = mcp_now_ms() - wait_start;
            if (elapsed >= 10000 && !timeout_logged) {
                timeout_logged = true;
                diag::log_tagged_fmt("mcp_srv", "stop bounded wait expired elapsed_ms=%llu worker_tid=%u running=%d active_requests=%d active_streams=%d disposition=shutdown_timeout",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0,
                    g_active_http_requests.load(std::memory_order_acquire),
                    g_active_streams.load(std::memory_order_acquire));
                log_runtime_executor_stats("stop bounded wait expired");
                return;
            }
            if ((elapsed % 10000) < 2) {
                diag::log_tagged_fmt("mcp_srv", "stop waiting_no_worker elapsed_ms=%llu worker_tid=%u running=%d",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                log_runtime_executor_stats("stop waiting_no_worker");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        diag::log_tagged_fmt("mcp_srv", "stop done");
        return;
    }
    const bool started = wait_server_worker_start(worker_lifetime);
    if (!started) {
        diag::log_tagged_fmt("mcp_srv", "stop worker start wait expired worker_tid=%u disposition=lifetime_retained",
            static_cast<unsigned>(worker_lifetime->worker_tid.load(std::memory_order_acquire)));
        log_runtime_executor_stats("stop worker start wait expired");
        return;
    }
    if (!on_server_worker && worker_lifetime->thread.joinable()) {
        if (!worker_lifetime->thread.join_for(10000)) {
            diag::log_tagged_fmt("mcp_srv", "stop join deadline exceeded worker_tid=%u running=%d disposition=lifetime_retained",
                static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                _running.load(std::memory_order_acquire) ? 1 : 0);
            log_runtime_executor_stats("stop join timeout");
            return;
        }
        erase_server_worker_lifetime(this, worker_lifetime);
    }
    diag::log_tagged_fmt("mcp_srv", "stop done");
}

void server_t::server_thread_func(int port)
{
    diag::log_tagged_fmt("mcp_srv", "server_thread_func entry port=%d", port);
    const auto& mcp_cfg = mcp_concurrency_config();
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func concurrency_config hardware_threads=%zu http_workers=%zu http_queue=%zu batch_workers=%zu batch_queue=%zu tool_workers=%zu tool_queue=%zu max_streams=%zu max_streams_per_principal=%zu env_names=AIDA_MCP_HTTP_WORKERS,AIDA_MCP_HTTP_QUEUE,AIDA_MCP_BATCH_WORKERS,AIDA_MCP_BATCH_QUEUE,AIDA_MCP_TOOL_WORKERS,AIDA_MCP_TOOL_QUEUE,AIDA_MCP_MAX_STREAMS,AIDA_MCP_MAX_STREAMS_PER_PRINCIPAL",
        mcp_cfg.hardware_threads,
        mcp_cfg.http_worker_threads,
        mcp_cfg.http_max_queued_requests,
        mcp_cfg.batch_worker_threads,
        mcp_cfg.batch_max_queued_requests,
        mcp_cfg.tool_worker_threads,
        mcp_cfg.tool_max_queued_requests,
        mcp_cfg.max_concurrent_streams,
        mcp_cfg.max_concurrent_streams_per_principal);
    g_cached_health_ready.store(false, std::memory_order_release);
    g_cached_external_tool_count.store(0, std::memory_order_release);
    httplib::Server svr;
    svr.new_task_queue = [] {
        return new mcp_request_task_queue();
    };
    svr.set_payload_max_length(kMcpPayloadMaxLength);
    (void)mcp_batch_executor();
    (void)mcp_tool_executor();
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func executors_prewarmed batch_workers=%zu tool_workers=%zu",
        mcp_cfg.batch_worker_threads,
        mcp_cfg.tool_worker_threads);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func mcp_owned_http_dispatch workers=%zu max_queue=%zu",
        mcp_cfg.http_worker_threads,
        mcp_cfg.http_max_queued_requests);
    svr.set_keep_alive_max_count(64);
    svr.set_keep_alive_timeout(2);
    svr.set_read_timeout(5, 0);
    svr.set_write_timeout(10, 0);
    svr.set_idle_interval(0, 100000);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func http_limits keep_alive_max=64 keep_alive_timeout_sec=2 read_timeout_sec=5 write_timeout_sec=10 idle_interval_us=100000 max_streams=%zu max_streams_per_principal=%zu payload_max=%zu batch_max_items=%zu sse_max_events=%zu",
        mcp_cfg.max_concurrent_streams,
        mcp_cfg.max_concurrent_streams_per_principal,
        kMcpPayloadMaxLength,
        kMcpMaxBatchItems,
        kSseMaxQueuedEvents);
    std::string local_capability;
    std::string run_binding;
    if (!snapshot_local_capability(local_capability, run_binding))
        throw std::runtime_error("MCP local capability state is unavailable");
    scoped_secret_string_t local_capability_guard(local_capability);
    (void)local_capability_guard;
    scoped_secret_string_t run_binding_guard(run_binding);
    (void)run_binding_guard;
    std::string session_id = run_binding;
    scoped_secret_string_t session_id_guard(session_id);
    (void)session_id_guard;
    diag::log_tagged_fmt("mcp_srv", "server_thread_func session_hash='%s'", mcp_identity_hash_text(session_id).c_str());

    svr.set_default_headers({
        {"Cache-Control", "no-store"},
        {"Pragma", "no-cache"},
        {"X-Content-Type-Options", "nosniff"}
    });

    svr.set_pre_routing_handler([this, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        tls_http_ingress_admission.reset();
        tls_reserved_control_lane.reset();
        tls_http_request_counted = false;
        tls_local_capability_authenticated = false;
        tls_http_request_id = g_http_request_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
        tls_http_request_start_tick = mcp_now_ms();
        update_current_executor_task_http(tls_http_request_id, req.method, req.path);
        local_request_auth_input_t auth_input;
        auth_input.method = req.method;
        auth_input.path = req.path;
        auth_input.remote_address = req.remote_addr;
        auth_input.host = req.get_header_value("Host");
        auth_input.origin = req.get_header_value("Origin");
        auth_input.authorization = req.get_header_value("Authorization");
        auth_input.run_binding = req.get_header_value("X-AiDA-MCP-Run-Id");
        auth_input.bound_port = _port.load(std::memory_order_acquire);
        const auto auth = authorize_local_request(
            auth_input, local_capability, run_binding);
        if (!auth_input.authorization.empty())
            RtlSecureZeroMemory(auth_input.authorization.data(), auth_input.authorization.size());
        if (!auth_input.run_binding.empty())
            RtlSecureZeroMemory(auth_input.run_binding.data(), auth_input.run_binding.size());
        if (!auth.allowed) {
            tls_route_identity = mcp_route_identity_t{};
            tls_route_identity.http_request_id = tls_http_request_id;
            tls_route_identity.path = mcp_identity_sanitize(req.path, 120);
            tls_route_identity.http_method = mcp_identity_sanitize(req.method, 16);
            tls_route_identity.route = tls_route_identity.path;
            tls_route_identity.transport = "HTTP-REJECTED";
            tls_route_identity.surface = "AUTH";
            tls_route_identity.remote = mcp_identity_sanitize(remote_endpoint(req), 120);
            tls_route_identity.principal_id = "unauthorized-local-client";
            tls_route_identity.principal_source = "local_capability_gate";
            res.status = 403;
            res.set_header("Cache-Control", "no-store");
            res.set_content(R"({"status":"rejected","error":"MCP local authorization failed","code":"MCP_LOCAL_AUTH_REQUIRED","disposition":"not_started"})", "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "local_auth_rejected id=%llu method=%s path=%s status=%u remote=%s",
                static_cast<unsigned long long>(tls_http_request_id),
                req.method.c_str(), req.path.c_str(),
                static_cast<unsigned>(auth.status), remote_endpoint(req).c_str());
            return httplib::Server::HandlerResponse::Handled;
        }
        tls_local_capability_authenticated = auth.capability_authenticated;
        tls_route_identity = make_mcp_route_identity(req, tls_http_request_id);
        try {
            if (!mcp_try_admit_http_ingress(req, res))
                return httplib::Server::HandlerResponse::Handled;
        } catch (const std::exception& ex) {
            tls_http_ingress_admission.reset();
            tls_reserved_control_lane.reset();
            res.status = 503;
            res.set_content(R"({"status":"rejected","error":"mcp ingress admission failed","code":"MCP_CAPACITY_GATE_FAILURE","disposition":"not_started"})", "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "MCP-CAPACITY-REJECT request_id=%llu route=%s method=%s transport=%s principal='%s' active=0 queued=0 cap=0 decision=reject reason=admission_exception status=503 err='%.160s'",
                static_cast<unsigned long long>(tls_http_request_id),
                req.path.c_str(),
                req.method.c_str(),
                tls_route_identity.transport.c_str(),
                tls_route_identity.principal_id.c_str(),
                ex.what());
            return httplib::Server::HandlerResponse::Handled;
        } catch (...) {
            tls_http_ingress_admission.reset();
            tls_reserved_control_lane.reset();
            res.status = 503;
            res.set_content(R"({"status":"rejected","error":"mcp ingress admission failed","code":"MCP_CAPACITY_GATE_FAILURE","disposition":"not_started"})", "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "MCP-CAPACITY-REJECT request_id=%llu route=%s method=%s transport=%s principal='%s' active=0 queued=0 cap=0 decision=reject reason=admission_unknown_exception status=503",
                static_cast<unsigned long long>(tls_http_request_id),
                req.path.c_str(),
                req.method.c_str(),
                tls_route_identity.transport.c_str(),
                tls_route_identity.principal_id.c_str());
            return httplib::Server::HandlerResponse::Handled;
        }
        const int active = g_active_http_requests.fetch_add(1, std::memory_order_acq_rel) + 1;
        tls_http_request_counted = true;
        diag::log_tagged_fmt("mcp_srv",
            "request_entry id=%llu method=%s path=%s matched=%s transport=%s principal=%s session_hash=%s session_source=%s auth_present=%d remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            tls_route_identity.transport.c_str(),
            tls_route_identity.principal_id.c_str(),
            tls_route_identity.session_hash.c_str(),
            tls_route_identity.session_source.c_str(),
            tls_route_identity.authorization_present ? 1 : 0,
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        aida::diagnostics::metadata_ring::emit(
            aida::diagnostics::metadata_ring::breadcrumb_category_t::mcp_ingress,
            "mcp_request_entry", nullptr, false);
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = (tls_http_request_start_tick != 0 && now >= tls_http_request_start_tick) ? (now - tls_http_request_start_tick) : 0;
        int active_after = g_active_http_requests.load(std::memory_order_acquire);
        if (tls_http_request_counted) {
            active_after = g_active_http_requests.fetch_sub(1, std::memory_order_acq_rel) - 1;
            if (active_after < 0) {
                g_active_http_requests.store(0, std::memory_order_release);
                active_after = 0;
            }
        }
        diag::log_tagged_fmt("mcp_srv",
            "request_exit id=%llu method=%s path=%s matched=%s transport=%s principal=%s session_hash=%s status=%d elapsed_ms=%llu remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            tls_route_identity.transport.c_str(),
            tls_route_identity.principal_id.c_str(),
            tls_route_identity.session_hash.c_str(),
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        if (tls_http_ingress_admission) {
            tls_http_ingress_admission->release(res.status >= 400 ? "http_error" : "http_complete");
            tls_http_ingress_admission.reset();
        }
        if (tls_reserved_control_lane) {
            tls_reserved_control_lane->release(res.status >= 400 ? "http_error" : "http_complete");
            tls_reserved_control_lane.reset();
        }
        tls_http_request_id = 0;
        tls_http_request_start_tick = 0;
        tls_http_request_counted = false;
        tls_local_capability_authenticated = false;
        tls_route_identity = mcp_route_identity_t{};
    });

    svr.Options(".*", [&local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        diag::log_tagged_fmt("mcp_srv",
            "OPTIONS path=%s acrm=%s acrh=%s",
            req.path.c_str(),
            req.get_header_value("Access-Control-Request-Method").c_str(),
            req.get_header_value("Access-Control-Request-Headers").c_str());
        res.status = 204;
    });

    svr.Post("/mcp", [this, &session_id, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_post_mcp",
            capacity_route_context(current_mcp_transport(), "/mcp", "POST", current_mcp_principal(),
                "http-post-mcp-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id),
                {},
                "body_bytes=" + std::to_string(req.body.size())));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        diag::log_tagged_fmt("mcp_srv",
            "POST /mcp body_len=%zu accept=%s content_type=%s protocol=%s session_hash=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("Content-Type").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            mcp_identity_hash_text(req.get_header_value("Mcp-Session-Id")).c_str());
        std::string response_body = handle_body(this, req.body, [&req]() { return request_connection_closed(req); });
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Get("/mcp", [this, &session_id, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_get_mcp",
            capacity_route_context(current_mcp_transport(), "/mcp", "GET", current_mcp_principal(),
                "http-get-mcp-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id)));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        diag::log_tagged_fmt("mcp_srv",
            "GET /mcp accept=%s protocol=%s session_hash=%s",
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            mcp_identity_hash_text(req.get_header_value("Mcp-Session-Id")).c_str());
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse) {
            auto stream_state = acquire_stream_slot("GET /mcp", req, res);
            if (!stream_state)
                return;
            auto connection_closed = req.is_connection_closed;
            try {
                if (request_connection_closed(req)) {
                    mark_stream_terminal_reason(stream_state, "setup_connection_closed");
                    release_stream_slot(stream_state, false, "setup_connection_closed");
                    set_stream_setup_closed_response(res, stream_state->route, stream_state->principal_id, stream_state->session_hash);
                    return;
                }
                res.set_header("Cache-Control", "no-cache");
                res.set_chunked_content_provider(
                    "text/event-stream",
                    [this, stream_state, connection_closed](size_t offset, httplib::DataSink& sink) -> bool {
                        if (connection_closed_now(connection_closed)) {
                            finish_stream_cleanly(stream_state, sink, "connection_closed", false);
                            return true;
                        }
                        if (offset == 0) {
                            const char connected[] = ": connected\n\n";
                            if (!sink.write(connected, sizeof(connected) - 1u)) {
                                mark_stream_terminal_reason(stream_state, "data_sink_connected_write_failed");
                                diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=connected",
                                    static_cast<unsigned long long>(stream_state->id),
                                    stream_state->route ? stream_state->route : "<unknown>");
                                release_stream_slot(stream_state, false, "data_sink_connected_write_failed");
                                return false;
                            }
                        }
                        const char ka[] = ": keepalive\n\n";
                        for (int i = 0; i < 6; ++i) {
                            for (int slice = 0; slice < 50; ++slice) {
                                if (_stop_requested.load(std::memory_order_acquire)) {
                                    finish_stream_cleanly(stream_state, sink, "server_stop", true);
                                    return true;
                                }
                                if (connection_closed_now(connection_closed)) {
                                    finish_stream_cleanly(stream_state, sink, "connection_closed", false);
                                    return true;
                                }
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            }
                            if (_stop_requested.load(std::memory_order_acquire)) {
                                finish_stream_cleanly(stream_state, sink, "server_stop", true);
                                return true;
                            }
                            if (connection_closed_now(connection_closed)) {
                                finish_stream_cleanly(stream_state, sink, "connection_closed", false);
                                return true;
                            }
                            if (sink.is_writable && !sink.is_writable()) {
                                mark_stream_terminal_reason(stream_state, "data_sink_not_writable");
                                diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                                    static_cast<unsigned long long>(stream_state->id),
                                    stream_state->route ? stream_state->route : "<unknown>");
                                release_stream_slot(stream_state, false, "data_sink_not_writable");
                                return false;
                            }
                            if (!sink.write(ka, sizeof(ka) - 1u)) {
                                mark_stream_terminal_reason(stream_state, "data_sink_keepalive_write_failed");
                                diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                                    static_cast<unsigned long long>(stream_state->id),
                                    stream_state->route ? stream_state->route : "<unknown>");
                                release_stream_slot(stream_state, false, "data_sink_keepalive_write_failed");
                                return false;
                            }
                        }
                        return true;
                    },
                    [stream_state](bool success) {
                        const std::string reason = stream_terminal_reason(stream_state, success ? "provider_complete" : "provider_failed");
                        release_stream_slot(stream_state, success, reason.c_str());
                    });
            } catch (const std::exception& ex) {
                mark_stream_terminal_reason(stream_state, "setup_exception");
                release_stream_slot(stream_state, false, "setup_exception");
                diag::log_tagged_fmt("mcp_srv",
                    "stream_setup_exception id=%llu route=%s err='%s'",
                    static_cast<unsigned long long>(stream_state->id),
                    stream_state->route ? stream_state->route : "<unknown>",
                    ex.what());
                json body;
                body["error"] = {
                    {"code", "mcp_stream_setup_failed"},
                    {"message", "MCP SSE stream setup failed; stream was not started."},
                    {"data", {{"disposition", "not_started"}, {"route", stream_state->route ? stream_state->route : "<unknown>"}, {"principal_id", stream_state->principal_id}, {"session_hash", stream_state->session_hash}}}
                };
                res.status = 500;
                res.set_content(json_dump_safe(body), "application/json");
            } catch (...) {
                mark_stream_terminal_reason(stream_state, "setup_exception");
                release_stream_slot(stream_state, false, "setup_exception");
                diag::log_tagged_fmt("mcp_srv",
                    "stream_setup_exception id=%llu route=%s err='<unknown>'",
                    static_cast<unsigned long long>(stream_state->id),
                    stream_state->route ? stream_state->route : "<unknown>");
                json body;
                body["error"] = {
                    {"code", "mcp_stream_setup_failed"},
                    {"message", "MCP SSE stream setup failed; stream was not started."},
                    {"data", {{"disposition", "not_started"}, {"route", stream_state->route ? stream_state->route : "<unknown>"}, {"principal_id", stream_state->principal_id}, {"session_hash", stream_state->session_hash}}}
                };
                res.status = 500;
                res.set_content(json_dump_safe(body), "application/json");
            }
        } else {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_delete_mcp",
            capacity_route_context(current_mcp_transport(), "/mcp", "DELETE", current_mcp_principal(),
                "http-delete-mcp-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id)));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Post("/ida-plugin-auth", [this, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const std::uint64_t t0 = mcp_now_ms();
        diag::log_tagged_fmt("mcp_srv",
            "ida_plugin_auth_entry remote=%s pid=%lu tid=%lu body_len=%zu",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            req.body.size());

        json request = json::parse(req.body, nullptr, false);
        if (request.is_discarded() || !request.is_object())
        {
            res.status = 400;
            res.set_content(R"({"status":"error","reason":"invalid_json"})", "application/json");
            return;
        }

        uint32_t plugin_pid = 0;
        if (request.contains("plugin_pid") && request["plugin_pid"].is_number_unsigned())
            plugin_pid = request["plugin_pid"].get<uint32_t>();
        else if (request.contains("plugin_pid") && request["plugin_pid"].is_number_integer())
        {
            int64_t signed_pid = request["plugin_pid"].get<int64_t>();
            if (signed_pid > 0 && signed_pid <= 0xFFFFFFFFll)
                plugin_pid = static_cast<uint32_t>(signed_pid);
        }

        const uint64_t now_tick = static_cast<uint64_t>(GetTickCount64());
        json proof;
        proof["status"] = "ok";
        proof["proof_version"] = 1;
        proof["server"] = "aida-pro-mcp";
        proof["challenge"] = request.value("challenge", std::string());
        proof["plugin_pid"] = plugin_pid;
        proof["standalone_pid"] = static_cast<uint32_t>(GetCurrentProcessId());
        proof["mcp_port"] = static_cast<uint32_t>(_port.load(std::memory_order_acquire));
        proof["issued_tick_ms"] = now_tick;
        proof["expires_tick_ms"] = now_tick + 15000ull;
        proof["lifecycle_ready"] = g_ide_lifecycle_ready.load(std::memory_order_acquire);
        const std::string proof_json = proof.dump();

        res.status = 200;
        res.set_content(proof_json, "application/json");
        diag::log_tagged_fmt("mcp_srv",
            "ida_plugin_auth_exit status=%d elapsed_ms=%llu remote=%s",
            res.status,
            static_cast<unsigned long long>(mcp_now_ms() - t0),
            remote_endpoint(req).c_str());
    });

    svr.Get("/health", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        const std::uint64_t t0 = mcp_now_ms();
        const std::string health_request_id = "http-health-" + std::to_string(tls_http_request_id);
        std::shared_ptr<mcp_reserved_lane_scope_t> health_lane;
        if (!mcp_try_acquire_reserved_lane(mcp_reserved_lane_t::health,
                "health_route",
                current_mcp_principal(),
                "/health",
                "GET",
                health_request_id,
                health_lane)) {
            res.status = 503;
            res.set_header("Retry-After", "1");
            res.set_content(json_dump_safe(mcp_reserved_lane_rejection_body(mcp_reserved_lane_t::health,
                health_request_id,
                "/health",
                "GET",
                current_mcp_principal())), "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "health_exit status=%d elapsed_ms=%llu remote=%s active_requests=%d active_streams=%d reason=reserved_lane_exhausted",
                res.status,
                static_cast<unsigned long long>(mcp_now_ms() - t0),
                remote_endpoint(req).c_str(),
                g_active_http_requests.load(std::memory_order_acquire),
                g_active_streams.load(std::memory_order_acquire));
            return;
        }
        diag::log_tagged_fmt("mcp_srv",
            "health_entry remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire));
        json health;
        const bool lifecycle_ready = g_ide_lifecycle_ready.load(std::memory_order_acquire);
        health["status"]      = "ok";
        health["server"]      = SERVER_NAME;
        health["version"]     = SERVER_VERSION;
        health["pid"]         = static_cast<std::uint32_t>(GetCurrentProcessId());
        health["port"]        = _port.load(std::memory_order_acquire);
        health["authenticated"] = lifecycle_ready;
        health["lifecycle_ready"] = lifecycle_ready;
        health["tools_count"] = g_cached_external_tool_count.load(std::memory_order_acquire);
        health["cache_ready"] = g_cached_health_ready.load(std::memory_order_acquire);
        health["active_requests"] = g_active_http_requests.load(std::memory_order_acquire);
        health["active_streams"] = g_active_streams.load(std::memory_order_acquire);
        const auto& health_mcp_cfg = mcp_concurrency_config();
        health["stream_limit"] = health_mcp_cfg.max_concurrent_streams;
        health["stream_limit_per_principal"] = health_mcp_cfg.max_concurrent_streams_per_principal;
        health["concurrency"]["hardware_threads"] = health_mcp_cfg.hardware_threads;
        health["concurrency"]["http_workers"] = health_mcp_cfg.http_worker_threads;
        health["concurrency"]["http_queue"] = health_mcp_cfg.http_max_queued_requests;
        health["concurrency"]["batch_workers"] = health_mcp_cfg.batch_worker_threads;
        health["concurrency"]["batch_queue"] = health_mcp_cfg.batch_max_queued_requests;
        health["concurrency"]["tool_workers"] = health_mcp_cfg.tool_worker_threads;
        health["concurrency"]["tool_queue"] = health_mcp_cfg.tool_max_queued_requests;
        health["concurrency"]["max_streams"] = health_mcp_cfg.max_concurrent_streams;
        health["concurrency"]["max_streams_per_principal"] = health_mcp_cfg.max_concurrent_streams_per_principal;
        health["limits"]["payload_max_bytes"] = kMcpPayloadMaxLength;
        health["limits"]["batch_max_items"] = kMcpMaxBatchItems;
        health["limits"]["sse_max_queued_events"] = kSseMaxQueuedEvents;
        mcp_capacity_snapshot_state_t capacity_state;
        capacity_state.timestamp_ms = mcp_now_ms();
        health["executors"] = mcp_executor_health_snapshot(&capacity_state);
        health["capacity"] = capacity_health_snapshot(current_mcp_principal(), session_id, _port.load(std::memory_order_acquire), capacity_state);
        health["lease_registry"] = mcp_lease_registry_bounded_snapshot(16, 16);
        health["lease_registry_owner"] = mcp_lease_registry_lock_owner_diagnostics_json();
        health["reserved_lanes"] = mcp_reserved_lanes_health_snapshot();
        health["p0_available"] = health["reserved_lanes"]["availability"].value("p0", false);
        health["health_available"] = health["reserved_lanes"]["availability"].value("health", false);
        health["cancellation_available"] = health["reserved_lanes"]["availability"].value("cancellation", false);
        {
            const bool stale_owners = health["lease_registry"].value("stale_owners_present", false);
            const bool p0_avail = health["p0_available"].get<bool>();
            const bool p1_avail = health["reserved_lanes"]["availability"].value("p1", false);
            json p0p1_stale;
            p0p1_stale["stale_owners_present"] = stale_owners;
            p0p1_stale["p0_available"] = p0_avail;
            p0p1_stale["p1_available"] = p1_avail;
            p0p1_stale["p0_p1_available_while_stale"] = !stale_owners || (p0_avail && p1_avail);
            health["lease_registry"]["p0_p1_availability"] = p0p1_stale;
        }
        {
            char ui_dispatch_raw[1600] = {};
            aida::ui_thread::format_snapshot(ui_dispatch_raw, sizeof(ui_dispatch_raw));
            const bool ui_ready = aida::ui_thread::owner_tid() != 0;
            const char* ui_state = "not_ready";
            if (ui_dispatch_raw[0] && std::strstr(ui_dispatch_raw, "destroying=1"))
                ui_state = "destroying";
            else if (ui_dispatch_raw[0] && std::strstr(ui_dispatch_raw, "shutdown=1"))
                ui_state = "shutdown";
            else if (ui_ready)
                ui_state = "ready";
            std::uint64_t oldest_age = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "oldest_age_ms=")) {
                p += std::strlen("oldest_age_ms=");
                oldest_age = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t rejected_count = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "rejected=")) {
                p += std::strlen("rejected=");
                rejected_count = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t drained_count = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "executed=")) {
                p += std::strlen("executed=");
                drained_count = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t wake_posted = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "wake_posted=")) {
                p += std::strlen("wake_posted=");
                wake_posted = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t wake_coalesced = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "wake_coalesced=")) {
                p += std::strlen("wake_coalesced=");
                wake_coalesced = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t wake_failed = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "wake_failed=")) {
                p += std::strlen("wake_failed=");
                wake_failed = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t budget_hits = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "budget_hits=")) {
                p += std::strlen("budget_hits=");
                budget_hits = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t drain_calls = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "drain_calls=")) {
                p += std::strlen("drain_calls=");
                drain_calls = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t drain_cancelled = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "drain_cancelled=")) {
                p += std::strlen("drain_cancelled=");
                drain_cancelled = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t enqueued = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "enqueued=")) {
                p += std::strlen("enqueued=");
                enqueued = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t discarded = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "discarded=")) {
                p += std::strlen("discarded=");
                discarded = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t max_depth = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "max_depth=")) {
                p += std::strlen("max_depth=");
                max_depth = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t last_drain_ms = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "last_drain_ms=")) {
                p += std::strlen("last_drain_ms=");
                last_drain_ms = std::strtoull(p, nullptr, 10);
            }
            std::uint64_t active_task = 0;
            if (const char* p = std::strstr(ui_dispatch_raw, "active_task=")) {
                p += std::strlen("active_task=");
                active_task = std::strtoull(p, nullptr, 10);
            }
            json ui_disp;
            ui_disp["ui_owner_tid"] = static_cast<std::uint64_t>(aida::ui_thread::owner_tid());
            ui_disp["state"] = ui_state;
            ui_disp["queue_depth"] = static_cast<std::uint64_t>(aida::ui_thread::pending_count());
            ui_disp["rejected_count"] = rejected_count;
            ui_disp["drained_count"] = drained_count;
            ui_disp["oldest_queued_age_ms"] = oldest_age;
            ui_disp["last_drain_timestamp"] = aida::ui_thread::last_drain_timestamp();
            ui_disp["last_wake_timestamp"] = aida::ui_thread::last_wake_timestamp();
            ui_disp["wake_pending"] = ui_dispatch_raw[0] && std::strstr(ui_dispatch_raw, "wake_pending=1") ? true : false;
            ui_disp["task_budget_hit_count"] = aida::ui_thread::task_budget_hit_count();
            ui_disp["time_budget_hit_count"] = aida::ui_thread::time_budget_hit_count();
            ui_disp["affinity_violation_count"] = aida::ui_thread::affinity_violation_count();
            ui_disp["top_queued_labels"] = aida::ui_thread::top_queued_labels(8);
            ui_disp["enqueued"] = enqueued;
            ui_disp["discarded"] = discarded;
            ui_disp["max_depth"] = max_depth;
            ui_disp["budget_hits"] = budget_hits;
            ui_disp["drain_calls"] = drain_calls;
            ui_disp["drain_cancelled"] = drain_cancelled;
            ui_disp["wake_posted"] = wake_posted;
            ui_disp["wake_coalesced"] = wake_coalesced;
            ui_disp["wake_failed"] = wake_failed;
            ui_disp["last_drain_ms"] = last_drain_ms;
            ui_disp["active_task"] = active_task;
            ui_disp["snapshot_raw"] = std::string(ui_dispatch_raw);
            health["ui_dispatcher"] = ui_disp;
        }
        const bool diag_requested = aida::diagnostics::health::is_diagnostics_requested(req.target.c_str());
        if (diag_requested) {
            try {
                aida::diagnostics::health::diagnostic_state_t diag_state;
                diag_state.generation = 1;
                diag_state.pid = GetCurrentProcessId();
                diag_state.tid = GetCurrentThreadId();
                diag_state.timestamp_ms = mcp_now_ms();
                diag_state.elapsed_ms = aida::diagnostics::metadata_ring::elapsed_ms();
                diag_state.mcp_active_requests = g_active_http_requests.load(std::memory_order_acquire);
                const auto& lr = health["lease_registry"];
                auto lease_size = [&](const char* key) -> std::size_t {
                    if (lr.contains(key) && lr[key].is_number())
                        return lr[key].get<std::size_t>();
                    return 0;
                };
                auto lease_u64 = [&](const char* key) -> std::uint64_t {
                    if (lr.contains(key) && lr[key].is_number())
                        return lr[key].get<std::uint64_t>();
                    return 0;
                };
                diag_state.mcp_active_leases = lease_size("active_count");
                diag_state.mcp_stale_leases = lease_size("stale_count");
                diag_state.mcp_fenced_leases = lease_size("fenced_count");
                diag_state.mcp_tombstoned_leases = lease_size("tombstoned_active_count");
                diag_state.mcp_late_result_discards = lease_u64("late_result_discard_count");
                diag_state.mcp_pending_cancellations = lease_size("cancellation_signalled_count");
                if (health["capacity"].contains("overload_flags") && health["capacity"]["overload_flags"].is_object()) {
                    const auto& of = health["capacity"]["overload_flags"];
                    for (auto it = of.begin(); it != of.end(); ++it) {
                        if (it.value().is_boolean() && it.value().get<bool>()) {
                            diag_state.overload_flag = true;
                            break;
                        }
                    }
                }
                char capacity_buf[1024] = {};
                _snprintf_s(capacity_buf, sizeof(capacity_buf), _TRUNCATE,
                    "executors=%zu active=%llu queued=%llu long_active=%llu busy=%zu|%zu|%zu overload=%d",
                    capacity_state.executor_count,
                    static_cast<unsigned long long>(capacity_state.global.active),
                    static_cast<unsigned long long>(capacity_state.global.queued),
                    static_cast<unsigned long long>(capacity_state.global.long_active),
                    capacity_state.executor_registry_busy,
                    capacity_state.executor_snapshot_busy,
                    capacity_state.task_meta_busy,
                    diag_state.overload_flag ? 1 : 0);
                diag_state.capacity_snapshot = capacity_buf;
                char ingress_buf[512] = {};
                if (health["capacity"].contains("http_ingress")) {
                    const auto& hi = health["capacity"]["http_ingress"];
                    _snprintf_s(ingress_buf, sizeof(ingress_buf), _TRUNCATE,
                        "global_active=%llu global_queued=%llu streams=%llu",
                        static_cast<unsigned long long>(hi.value("global_active", 0ULL)),
                        static_cast<unsigned long long>(hi.value("global_queued", 0ULL)),
                        static_cast<unsigned long long>(hi.value("global_streams", 0ULL)));
                    diag_state.ingress_admission = ingress_buf;
                }
                char tool_adm_buf[512] = {};
                if (health["capacity"].contains("tool_admission")) {
                    const auto& ta = health["capacity"]["tool_admission"];
                    _snprintf_s(tool_adm_buf, sizeof(tool_adm_buf), _TRUNCATE,
                        "active=%llu rejected=%llu acquired=%llu",
                        static_cast<unsigned long long>(ta.value("active", 0ULL)),
                        static_cast<unsigned long long>(ta.value("rejected_total", 0ULL)),
                        static_cast<unsigned long long>(ta.value("acquired_total", 0ULL)));
                    diag_state.tool_admission = tool_adm_buf;
                }
                const json ds_snap = downstream::governor_t::instance().snapshot_json();
                char downstream_buf[512] = {};
                _snprintf_s(downstream_buf, sizeof(downstream_buf), _TRUNCATE,
                    "total_active=%llu total_rejected=%llu",
                    static_cast<unsigned long long>(ds_snap.value("total_active", 0ULL)),
                    static_cast<unsigned long long>(ds_snap.value("total_rejected", 0ULL)));
                diag_state.downstream_snapshot = downstream_buf;
                char ui_diag_buf[1600] = {};
                aida::ui_thread::format_snapshot(ui_diag_buf, sizeof(ui_diag_buf));
                diag_state.ui_dispatcher_snapshot = ui_diag_buf;
                char general_buf[1024] = {};
                char service_buf[1024] = {};
                char critical_buf[1024] = {};
                const auto wq_stats = runtime_queue_stats(runtime_queue_family_t::general);
                _snprintf_s(general_buf, sizeof(general_buf), _TRUNCATE,
                    "alive=%d active=%u pending=%zu started=%llu finished=%llu rejected=%llu oldest_ms=%llu",
                    wq_stats.alive ? 1 : 0, wq_stats.active, wq_stats.pending,
                    static_cast<unsigned long long>(wq_stats.started),
                    static_cast<unsigned long long>(wq_stats.finished),
                    static_cast<unsigned long long>(wq_stats.rejected),
                    static_cast<unsigned long long>(wq_stats.oldest_active_ms));
                const auto svc_stats = runtime_queue_stats(runtime_queue_family_t::service);
                _snprintf_s(service_buf, sizeof(service_buf), _TRUNCATE,
                    "alive=%d active=%u pending=%zu started=%llu finished=%llu rejected=%llu oldest_ms=%llu",
                    svc_stats.alive ? 1 : 0, svc_stats.active, svc_stats.pending,
                    static_cast<unsigned long long>(svc_stats.started),
                    static_cast<unsigned long long>(svc_stats.finished),
                    static_cast<unsigned long long>(svc_stats.rejected),
                    static_cast<unsigned long long>(svc_stats.oldest_active_ms));
                const auto crit_stats = runtime_queue_stats(runtime_queue_family_t::critical);
                _snprintf_s(critical_buf, sizeof(critical_buf), _TRUNCATE,
                    "alive=%d active=%u pending=%zu started=%llu finished=%llu rejected=%llu oldest_ms=%llu",
                    crit_stats.alive ? 1 : 0, crit_stats.active, crit_stats.pending,
                    static_cast<unsigned long long>(crit_stats.started),
                    static_cast<unsigned long long>(crit_stats.finished),
                    static_cast<unsigned long long>(crit_stats.rejected),
                    static_cast<unsigned long long>(crit_stats.oldest_active_ms));
                diag_state.work_queue_snapshot = general_buf;
                diag_state.service_queue_snapshot = service_buf;
                diag_state.critical_queue_snapshot = critical_buf;
                char thread_classes_buf[1600] = {};
                _snprintf_s(thread_classes_buf, sizeof(thread_classes_buf), _TRUNCATE,
                    "general_active=%zu healthy=%u hot=%u not_queryable=%u labels=%.800s; critical_active=%zu labels=%.700s",
                    static_cast<std::size_t>(wq_stats.active_label_count),
                    wq_stats.healthy_long_lived,
                    wq_stats.hot_workers,
                    wq_stats.not_queryable_workers,
                    wq_stats.active_labels.c_str(),
                    static_cast<std::size_t>(crit_stats.active_label_count),
                    crit_stats.active_labels.c_str());
                diag_state.thread_runtime_classes = thread_classes_buf;
                const std::string ring_summary = aida::diagnostics::metadata_ring::category_summary_string();
                diag_state.metadata_ring_summary = ring_summary.c_str();
                const std::string wer_summary = aida::diagnostics::wer::correlation_summary_string();
                diag_state.wer_correlation = wer_summary.c_str();
                const std::string executor_snap = aida::infra::executor::snapshot_json_string();
                diag_state.executor_snapshot = executor_snap.c_str();
                diag_state.taskflow_evaluation = aida::infra::taskflow_eval::kTaskflowEvaluationStatus;
                const std::string diag_json = aida::diagnostics::health::build_diagnostics_json(diag_state);
                health["diagnostics"] = json::parse(diag_json)["diagnostics"];
                char mcp_snap_buf[1400] = {};
                _snprintf_s(mcp_snap_buf, sizeof(mcp_snap_buf), _TRUNCATE,
                    "active_requests=%zu active_leases=%zu stale=%zu fenced=%zu tombstoned=%zu late_discards=%llu cancellations=%zu ring=%s",
                    diag_state.mcp_active_requests,
                    diag_state.mcp_active_leases,
                    diag_state.mcp_stale_leases,
                    diag_state.mcp_fenced_leases,
                    diag_state.mcp_tombstoned_leases,
                    static_cast<unsigned long long>(diag_state.mcp_late_result_discards),
                    diag_state.mcp_pending_cancellations,
                    ring_summary.c_str());
                aida::diagnostics::health::log_mcp_diagnostic_snapshot(mcp_snap_buf);
                aida::diagnostics::health::log_queue_diagnostic_snapshot(general_buf, service_buf, critical_buf);
                aida::diagnostics::health::log_thread_runtime_diagnostic_snapshot(thread_classes_buf);
            } catch (...) {
                aida::diagnostics::health::log_diagnostic_snapshot_failed("health_diagnostics_build_exception");
            }
        }
        res.status = 200;
        res.set_content(json_dump_safe(health), "application/json");
        const std::uint64_t elapsed = mcp_now_ms() - t0;
        if (health_lane)
            health_lane->release("health_complete");
        diag::log_tagged_fmt("mcp_srv",
            "health_exit status=%d elapsed_ms=%llu remote=%s active_requests=%d active_streams=%d executors=%zu",
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire),
            health["executors"].size());
    });

    svr.Get("/", [this, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        json health;
        health["status"] = "ok";
        health["server"] = SERVER_NAME;
        health["mcp"] = "/mcp";
        health["sse"] = "/sse";
        health["health"] = "/health";
        size_t external_tools = 0;
        for (const auto& t : _registry.snapshot_tools())
            if (is_external_mcp_tool(t)) ++external_tools;
        health["tools_count"] = external_tools;
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [this, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_api_tools",
            capacity_route_context(current_mcp_transport(), "/api/tools", "GET", current_mcp_principal(),
                "http-api-tools-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id)));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        json tools_arr = json::array();
        for (const auto& t : _registry.snapshot_tools()) {
            if (!is_external_mcp_tool(t)) continue;
            tools_arr.push_back(tool_schema(t, false));
        }
        res.set_content(json_dump_safe(tools_arr, 2), "application/json");
    });

    svr.Post("/api/tools/call", [this, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_api_tools_call",
            capacity_route_context(current_mcp_transport(), "/api/tools/call", "POST", current_mcp_principal(),
                "http-api-tools-call-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id),
                {},
                "body_bytes=" + std::to_string(req.body.size())));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        diag::log_tagged_fmt("mcp_srv", "POST /api/tools/call body_len=%zu", req.body.size());
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());
        const std::uint64_t api_call_begin = mcp_now_ms();
        const std::string api_request_id = "api-tools-call-" + std::to_string(tls_http_request_id);
        const std::string api_diag_id = api_request_id;

        if (tool_name.empty()) {
            record_tool_audit_event("<missing>", arguments, "rejected", false, json{{"reason", "missing_name"}}, "Missing 'name' field", api_call_begin, api_diag_id, api_request_id);
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        tool_def_t found;
        bool found_tool = false;
        std::function<tool_result_t(const json&)> handler_copy;
        const auto registered_tool = _registry.find_tool(tool_name, false);
        if (registered_tool) {
            if (!is_external_mcp_tool(*registered_tool)) {
                record_tool_audit_event(tool_name, arguments, "rejected", false, json{{"reason", "not_external"}}, "Unknown tool: " + tool_name, api_call_begin, api_diag_id, api_request_id);
                res.status = 404;
                res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
                return;
            }
            found = *registered_tool;
            handler_copy = registered_tool->handler;
            found_tool = true;
        }

        if (!found_tool) {
            record_tool_audit_event(tool_name, arguments, "rejected", false, json{{"reason", "unknown_tool"}}, "Unknown tool: " + tool_name, api_call_begin, api_diag_id, api_request_id);
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
            return;
        }

        tool_result_t validation_failure;
        if (!validate_pre_dispatch_tool_input(found, arguments, &validation_failure)) {
            json error = structured_tool_error(validation_failure);
            error["tool"] = tool_name;
            error["diagnostic_id"] = api_diag_id;
            error["request_id"] = api_request_id;
            error["disposition"] = "not_started";
            json body = {
                {"success", false},
                {"output", sanitize_utf8(validation_failure.text.empty() ? std::string("Tool input validation failed.") : validation_failure.text)},
                {"error", error}
            };
            if (!validation_failure.error_code.empty())
                body["error_code"] = validation_failure.error_code;
            record_tool_audit_event(tool_name, arguments, "rejected", false, body, validation_failure.text, api_call_begin, api_diag_id, api_request_id);
            res.status = 400;
            res.set_content(json_dump_safe(body, 2), "application/json");
            return;
        }

        tool_invocation_metrics_t api_metrics;
        api_metrics.lane = predicted_tool_lane(found, arguments);
        const tool_timeout_resolution_t api_timeout_resolution = resolve_tool_timeout(tool_name, arguments);
        const std::uint64_t api_timeout_ms = api_timeout_resolution.effective_ms;
        const std::uint64_t api_deadline_ms = saturated_deadline_ms(api_call_begin, api_timeout_ms);
        const std::string api_payload_shape = payload_shape_summary(arguments);
        const std::uint32_t api_target_pid = target_pid_from_args(arguments);
        capacity_diag::prediction_t api_capacity_prediction = diagnose_capacity("api_tools_call_pre_admission",
            capacity_tool_context(current_mcp_transport(),
                "/api/tools/call",
                "tools/call",
                current_mcp_principal(),
                api_diag_id,
                api_request_id,
                found,
                arguments,
                api_timeout_resolution,
                api_metrics.lane,
                api_payload_shape,
                api_target_pid),
            true);
        mcp_tool_capacity_lease_t api_tool_capacity_lease;
        json api_capacity_data;
        if (!mcp_tool_try_acquire_capacity(api_capacity_prediction, api_call_begin, &api_tool_capacity_lease, &api_capacity_data)) {
            res.status = 429;
            res.set_header("Retry-After", "1");
            json body = api_capacity_data.is_object() ? api_capacity_data : json{
                {"code", "MCP_TOOL_CAPACITY_REJECT"},
                {"message", "MCP tool capacity exhausted; tool was not started."},
                {"disposition", "not_started"},
                {"retry_after_ms", 100},
                {"reason", api_capacity_prediction.decision.reason},
                {"quota", api_capacity_prediction.decision.quota_name},
                {"scope", api_capacity_prediction.decision.quota_scope},
                {"observed", api_capacity_prediction.decision.observed},
                {"limit", api_capacity_prediction.decision.limit},
                {"diagnostic_id", api_diag_id},
                {"request_id", api_request_id},
                {"tool", tool_name},
                {"capacity", capacity_diag::prediction_json(api_capacity_prediction)}
            };
            body["status"] = "rejected";
            body["error"] = body.value("message", std::string("MCP tool capacity exhausted; tool was not started."));
            res.set_content(json_dump_safe(body, 2), "application/json");
            return;
        }
        api_capacity_data = capacity_diag::prediction_json(api_capacity_prediction);
        api_capacity_data["phase4_enforced"] = true;
        api_capacity_data["diagnostics_only"] = false;
        api_capacity_data["enforcement_enabled"] = true;
        api_capacity_data["tool_admission"] = {
            {"decision", "admit"},
            {"disposition", "started"},
            {"lease", api_tool_capacity_lease.identity_json()}
        };
        if (request_connection_closed(req)) {
            api_tool_capacity_lease.release("client_disconnect_before_start");
            json body = {
                {"status", "rejected"},
                {"error", "MCP client disconnected before tool start; tool was not started."},
                {"code", "MCP_TOOL_CLIENT_DISCONNECTED"},
                {"disposition", "not_started"},
                {"reason", "client_disconnect_before_start"},
                {"diagnostic_id", api_diag_id},
                {"request_id", api_request_id},
                {"tool", tool_name},
                {"capacity", api_capacity_data}
            };
            record_tool_audit_event(tool_name, arguments, "rejected", false, body, "MCP client disconnected before tool start; tool was not started.", api_call_begin, api_diag_id, api_request_id);
            res.status = 499;
            res.set_content(json_dump_safe(body, 2), "application/json");
            return;
        }
        const bool api_explicit_target = tool_args_select_session_target(arguments) || api_target_pid != 0;
        mcp_broker_delivery_fence_t api_delivery_fence(found,
            arguments,
            api_metrics.lane,
            api_explicit_target,
            api_deadline_ms,
            current_cancel_token(),
            api_diag_id,
            api_request_id);
        api_delivery_fence.set_phase("handler_started");
        tool_result_t tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &api_metrics);
        json api_delivery_evidence = json::object();
        if (!api_delivery_fence.claim_delivery("api_tools_call", &api_delivery_evidence)) {
            api_tool_capacity_lease.release("late_result_discarded");
            json body = {
                {"success", false},
                {"output", "MCP late tool result was fenced and discarded before delivery."},
                {"error_code", "MCP_LATE_RESULT_DISCARDED"},
                {"error", {
                    {"code", "MCP_LATE_RESULT_DISCARDED"},
                    {"message", "MCP late tool result was fenced and discarded before delivery."},
                    {"details", api_delivery_evidence}
                }},
                {"diagnostics", {
                    {"lane", api_metrics.lane},
                    {"lock_wait_ms", api_metrics.lock_wait_ms},
                    {"handler_elapsed_ms", api_metrics.handler_elapsed_ms},
                    {"late_result_disposition", api_delivery_evidence.value("disposition", std::string("discarded_late_result"))},
                    {"late_result_fence", api_delivery_evidence},
                    {"capacity", api_capacity_data}
                }}
            };
            record_tool_audit_event(tool_name, arguments, "discarded", false, body, "MCP late tool result was fenced and discarded before delivery.", api_call_begin, api_diag_id, api_request_id);
            res.status = 409;
            res.set_content(json_dump_safe(body, 2), "application/json");
            return;
        }
        api_tool_capacity_lease.release(mcp_tool_release_reason_from_result(tr, false));

        json resp;
        resp["success"] = tr.success;
        resp["output"]  = sanitize_utf8(tr.text);
        resp["diagnostics"] = {
            {"lane", api_metrics.lane},
            {"lock_wait_ms", api_metrics.lock_wait_ms},
            {"handler_elapsed_ms", api_metrics.handler_elapsed_ms}
        };
        resp["diagnostics"]["capacity"] = api_capacity_data;
        resp["diagnostics"]["late_result_disposition"] = api_delivery_evidence.value("disposition", std::string("delivered"));
        resp["diagnostics"]["late_result_fence"] = api_delivery_evidence;
        if (!tr.data.is_null() && !tr.data.empty()) resp["data"] = tr.data;
        if (tr.meta.is_object() && !tr.meta.empty()) resp["_meta"] = tr.meta;
        if (has_structured_tool_error(tr)) {
            json err = structured_tool_error(tr);
            resp["error"] = err;
            if (err.contains("code"))
                resp["error_code"] = err["code"];
            if (err.contains("details"))
                resp["error_details"] = err["details"];
        }
        record_tool_audit_event(tool_name,
                                arguments,
                                tr.success ? std::string("completed") : std::string("failed"),
                                tr.success,
                                resp,
                                tr.success ? std::string() : tr.text,
                                api_call_begin,
                                api_diag_id,
                                api_request_id);
        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    auto cleanup_sse_sessions = [&sse_sessions, &sse_mtx](const char* reason) {
        const std::uint64_t now = mcp_now_ms();
        size_t removed = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            for (auto it = sse_sessions.begin(); it != sse_sessions.end(); ) {
                const auto& session = it->second;
                const bool aged = session && now >= session->opened_tick && (now - session->opened_tick) > kSseSessionMaxAgeMs;
                if (!session || session->closed.load(std::memory_order_acquire) || aged) {
                    if (session)
                        session->close();
                    it = sse_sessions.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
        }
        if (removed != 0) {
            diag::log_tagged_fmt("mcp_srv",
                "sse_session_cleanup reason=%s removed=%zu active_streams=%d active_requests=%d",
                reason ? reason : "",
                removed,
                g_active_streams.load(std::memory_order_acquire),
                g_active_http_requests.load(std::memory_order_acquire));
        }
    };

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions,
                     &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_get_sse",
            capacity_route_context(current_mcp_transport(), "/sse", "GET", current_mcp_principal(),
                "http-get-sse-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id)));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        cleanup_sse_sessions("before_open");
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();
        session->remote_address = req.remote_addr;
        session->principal_id = current_mcp_principal();
        if (session->id.empty()) {
            res.status = 503;
            res.set_content(R"({"status":"rejected","error":"MCP session entropy unavailable","code":"MCP_SESSION_ENTROPY_UNAVAILABLE","disposition":"not_started"})", "application/json");
            diag::log_tagged("mcp_srv", "sse_session_open_rejected entropy_unavailable");
            return;
        }
        auto stream_state = acquire_stream_slot("GET /sse", req, res);
        if (!stream_state)
            return;
        auto connection_closed = req.is_connection_closed;
        if (request_connection_closed(req)) {
            mark_stream_terminal_reason(stream_state, "setup_connection_closed");
            release_stream_slot(stream_state, false, "setup_connection_closed");
            set_stream_setup_closed_response(res, stream_state->route, stream_state->principal_id, stream_state->session_hash);
            return;
        }
        size_t session_count = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            sse_sessions[session->id] = session;
            session_count = sse_sessions.size();
        }
        diag::log_tagged_fmt("mcp_srv",
            "sse_session_open session=%s stream_id=%llu remote=%s sessions=%zu",
            session->id.c_str(),
            static_cast<unsigned long long>(stream_state->id),
            stream_state->remote.c_str(),
            session_count);

        try {
            if (request_connection_closed(req)) {
                session->close();
                {
                    std::lock_guard<std::mutex> lk(sse_mtx);
                    sse_sessions.erase(session->id);
                }
                mark_stream_terminal_reason(stream_state, "setup_connection_closed");
                release_stream_slot(stream_state, false, "setup_connection_closed");
                set_stream_setup_closed_response(res, stream_state->route, stream_state->principal_id, stream_state->session_hash);
                return;
            }
            res.set_header("Cache-Control", "no-cache");
            res.set_header("Connection", "keep-alive");
            res.set_header("X-Accel-Buffering", "no");

            std::atomic<bool>* stop_ptr = &_stop_requested;
            res.set_chunked_content_provider(
                "text/event-stream",
                [session, stop_ptr, stream_state, connection_closed, &sse_sessions, &sse_mtx](size_t offset, httplib::DataSink& sink) -> bool {
                    auto erase_closed_session = [&]() {
                        if (session->closed.load(std::memory_order_acquire)) {
                            std::lock_guard<std::mutex> lk(sse_mtx);
                            sse_sessions.erase(session->id);
                        }
                    };
                    bool cont = false;
                    DWORD seh = 0;
                    try {
                        seh = seh_sse_provider_step(session.get(), &sink, offset, stop_ptr, stream_state.get(), connection_closed, &cont);
                    } catch (const std::exception& ex) {
                        mark_stream_terminal_reason(stream_state, "provider_exception");
                        release_stream_slot(stream_state, false, "provider_exception");
                        diag::log_tagged_fmt("mcp_srv",
                            "stream_provider_exception id=%llu route=%s err='%s'",
                            static_cast<unsigned long long>(stream_state->id),
                            stream_state->route ? stream_state->route : "<unknown>",
                            ex.what());
                        session->close();
                        erase_closed_session();
                        return false;
                    } catch (...) {
                        mark_stream_terminal_reason(stream_state, "provider_exception");
                        release_stream_slot(stream_state, false, "provider_exception");
                        diag::log_tagged_fmt("mcp_srv",
                            "stream_provider_exception id=%llu route=%s err='<unknown>'",
                            static_cast<unsigned long long>(stream_state->id),
                            stream_state->route ? stream_state->route : "<unknown>");
                        session->close();
                        erase_closed_session();
                        return false;
                    }
                    if (seh != 0) {
                        mark_stream_terminal_reason(stream_state, "provider_seh");
                        release_stream_slot(stream_state, false, "provider_seh");
                        diag::log_tagged_fmt("mcp_srv",
                            "stream_provider_seh id=%llu route=%s code=0x%08lX",
                            static_cast<unsigned long long>(stream_state->id),
                            stream_state->route ? stream_state->route : "<unknown>",
                            static_cast<unsigned long>(seh));
                        session->close();
                        erase_closed_session();
                        return false;
                    }
                    erase_closed_session();
                    return cont;
                },
                [session, &sse_sessions, &sse_mtx, stream_state](bool success) {
                    session->close();
                    size_t remaining = 0;
                    {
                        std::lock_guard<std::mutex> lk(sse_mtx);
                        sse_sessions.erase(session->id);
                        remaining = sse_sessions.size();
                    }
                    diag::log_tagged_fmt("mcp_srv",
                        "sse_session_close session=%s stream_id=%llu success=%d remaining=%zu",
                        session->id.c_str(),
                        static_cast<unsigned long long>(stream_state->id),
                        success ? 1 : 0,
                        remaining);
                    const std::string reason = stream_terminal_reason(stream_state, success ? "provider_complete" : "provider_failed");
                    release_stream_slot(stream_state, success, reason.c_str());
                });
        } catch (const std::exception& ex) {
            session->close();
            size_t remaining = 0;
            {
                std::lock_guard<std::mutex> lk(sse_mtx);
                sse_sessions.erase(session->id);
                remaining = sse_sessions.size();
            }
            mark_stream_terminal_reason(stream_state, "setup_exception");
            release_stream_slot(stream_state, false, "setup_exception");
            diag::log_tagged_fmt("mcp_srv",
                "stream_setup_exception id=%llu route=%s session=%s remaining=%zu err='%s'",
                static_cast<unsigned long long>(stream_state->id),
                stream_state->route ? stream_state->route : "<unknown>",
                session->id.c_str(),
                remaining,
                ex.what());
            json body;
            body["error"] = {
                {"code", "mcp_stream_setup_failed"},
                {"message", "MCP SSE stream setup failed; stream was not started."},
                {"data", {{"disposition", "not_started"}, {"route", stream_state->route ? stream_state->route : "<unknown>"}, {"principal_id", stream_state->principal_id}, {"session_hash", stream_state->session_hash}}}
            };
            res.status = 500;
            res.set_content(json_dump_safe(body), "application/json");
        } catch (...) {
            session->close();
            size_t remaining = 0;
            {
                std::lock_guard<std::mutex> lk(sse_mtx);
                sse_sessions.erase(session->id);
                remaining = sse_sessions.size();
            }
            mark_stream_terminal_reason(stream_state, "setup_exception");
            release_stream_slot(stream_state, false, "setup_exception");
            diag::log_tagged_fmt("mcp_srv",
                "stream_setup_exception id=%llu route=%s session=%s remaining=%zu err='<unknown>'",
                static_cast<unsigned long long>(stream_state->id),
                stream_state->route ? stream_state->route : "<unknown>",
                session->id.c_str(),
                remaining);
            json body;
            body["error"] = {
                {"code", "mcp_stream_setup_failed"},
                {"message", "MCP SSE stream setup failed; stream was not started."},
                {"data", {{"disposition", "not_started"}, {"route", stream_state->route ? stream_state->route : "<unknown>"}, {"principal_id", stream_state->principal_id}, {"session_hash", stream_state->session_hash}}}
            };
            res.status = 500;
            res.set_content(json_dump_safe(body), "application/json");
        }
    });

    svr.Post("/message", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions,
                          &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_post_message",
            capacity_route_context(current_mcp_transport(), "/message", "POST", current_mcp_principal(),
                "http-post-message-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id),
                {},
                "body_bytes=" + std::to_string(req.body.size())));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        cleanup_sse_sessions("before_message");
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe(make_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")), "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        { std::lock_guard<std::mutex> lk(sse_mtx);
          auto it = sse_sessions.find(sid);
          if (it == sse_sessions.end() || !it->second || it->second->closed.load(std::memory_order_acquire)) {
              if (it != sse_sessions.end())
                  sse_sessions.erase(it);
              res.status = 404;
              res.set_content(json_dump_safe(make_error(nullptr,
                  JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)), "application/json");
              return;
          }
          if (it->second->remote_address != req.remote_addr ||
              it->second->principal_id != current_mcp_principal()) {
              res.status = 403;
              res.set_content(json_dump_safe(make_error(nullptr,
                  JSONRPC_INVALID_REQUEST, "SSE session is bound to another local client")), "application/json");
              return;
          }
          session = it->second;
        }

        std::string response_body = handle_body(this, req.body, [&req]() { return request_connection_closed(req); });
        if (!response_body.empty()) {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }
        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [this, &session_id, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_post_sse",
            capacity_route_context(current_mcp_transport(), "/sse", "POST", current_mcp_principal(),
                "http-post-sse-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id),
                {},
                "body_bytes=" + std::to_string(req.body.size())));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        diag::log_tagged_fmt("mcp_srv",
            "POST /sse body_len=%zu accept=%s protocol=%s session_hash=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            mcp_identity_hash_text(req.get_header_value("Mcp-Session-Id")).c_str());
        std::string response_body = handle_body(this, req.body, [&req]() { return request_connection_closed(req); });
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty()) res.status = 202;
        else res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id, &local_capability, &run_binding](const httplib::Request& req, httplib::Response& res) {
        if (!require_local_http_capability(req, res, local_capability, run_binding))
            return;
        const capacity_diag::prediction_t ingress_capacity = diagnose_capacity("http_ingress_delete_sse",
            capacity_route_context(current_mcp_transport(), "/sse", "DELETE", current_mcp_principal(),
                "http-delete-sse-" + std::to_string(tls_http_request_id),
                std::to_string(tls_http_request_id)));
        capacity_diag::scoped_activity_t ingress_activity(ingress_capacity, mcp_now_ms());
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_stop_requested.load(std::memory_order_acquire))
            return;
        _active_server = &svr;
    }
    int bound_port = 0;
    try {
        if (port > 0 && svr.bind_to_port("127.0.0.1", port))
            bound_port = port;
        if (bound_port <= 0)
            bound_port = svr.bind_to_any_port("127.0.0.1");
    } catch (...) {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        throw;
    }

    if (bound_port <= 0) {
        diag::log_tagged_fmt("mcp_srv", "server_thread_func bind fail port=%d", port);
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        _stop_requested = true;
        return;
    }

    _port = bound_port;
    _running = true;
    size_t external_tools = 0;
    for (const auto& t : _registry.snapshot_tools())
        if (is_external_mcp_tool(t)) ++external_tools;
    g_cached_external_tool_count.store(external_tools, std::memory_order_release);
    g_cached_health_ready.store(true, std::memory_order_release);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listening bound_port=%d endpoints=/mcp,/sse,/health external_tools=%zu",
        bound_port, external_tools);

    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listen_after_bind_enter port=%d pid=%lu tid=%lu",
        bound_port,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    try {
        svr.listen_after_bind();
    } catch (...) {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        throw;
    }

    diag::log_tagged_fmt("mcp_srv", "server_thread_func listen_after_bind returned port=%d", bound_port);
    { std::lock_guard<std::mutex> lk(_server_mtx); _active_server = nullptr; }
    cleanup_sse_sessions("listen_after_bind_returned");
    mcp_standalone::downstream::governor_t::instance().request_shutdown();
    release_all_stream_slots("listen_after_bind_returned");
    mcp_lease_registry_shutdown_cleanup("listen_after_bind_returned");
    mcp_tool_release_all_capacity_leases("listen_after_bind_returned");
    command_sessions::release_all_for_shutdown("listen_after_bind_returned");
    g_cached_health_ready.store(false, std::memory_order_release);
    _running = false;
}

static std::string get_home_dir()
{
    std::string env_home = read_env_var("USERPROFILE");
    if (!env_home.empty())
        return env_home;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string get_appdata_dir()
{
    std::string env_appdata = read_env_var("APPDATA");
    if (!env_appdata.empty())
        return env_appdata;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string expand_path(const char* tmpl)
{
    if (!tmpl || !*tmpl) return "";
    std::string path(tmpl);

    if (path.size() >= 1 && path[0] == '~') {
        std::string home = get_home_dir();
        if (home.empty()) return "";
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos) {
        std::string appdata = get_appdata_dir();
        if (appdata.empty()) return "";
        path.replace(pos, 9, appdata);
    }

    for (auto& c : path) if (c == '/') c = '\\';
    return path;
}

static bool ensure_dir(const std::string& dir)
{
    if (dir.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return std::filesystem::is_directory(dir, ec);
}

static bool ensure_parent_dir(const std::string& path)
{
    auto p = std::filesystem::path(path).parent_path();
    if (p.empty()) return true;
    return ensure_dir(p.string());
}

static bool read_file_to_string(const std::string& path, std::string& out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

static bool write_string_to_file(const std::string& path, const std::string& content)
{
    if (!ensure_parent_dir(path))
        return false;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    DWORD token_bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &token_bytes);
    if (token_bytes == 0) {
        CloseHandle(token);
        return false;
    }
    std::vector<std::uint8_t> token_buffer(token_bytes);
    if (!GetTokenInformation(
            token, TokenUser, token_buffer.data(), token_bytes, &token_bytes)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);
    const auto* token_user = reinterpret_cast<const TOKEN_USER*>(token_buffer.data());
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_sid{};
    DWORD system_sid_bytes = static_cast<DWORD>(system_sid.size());
    if (!CreateWellKnownSid(
            WinLocalSystemSid, nullptr, system_sid.data(), &system_sid_bytes))
        return false;

    std::array<EXPLICIT_ACCESSW, 2> access{};
    access[0].grfAccessPermissions = GENERIC_ALL;
    access[0].grfAccessMode = SET_ACCESS;
    access[0].grfInheritance = NO_INHERITANCE;
    access[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    access[0].Trustee.ptstrName = static_cast<LPWSTR>(token_user->User.Sid);
    access[1].grfAccessPermissions = GENERIC_ALL;
    access[1].grfAccessMode = SET_ACCESS;
    access[1].grfInheritance = NO_INHERITANCE;
    access[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_sid.data());
    PACL acl = nullptr;
    if (SetEntriesInAclW(
            static_cast<ULONG>(access.size()), access.data(), nullptr, &acl) != ERROR_SUCCESS)
        return false;

    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE)) {
        LocalFree(acl);
        return false;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = &descriptor;
    const std::filesystem::path target(path);
    static std::atomic<std::uint64_t> write_sequence{0};
    const std::uint64_t sequence = write_sequence.fetch_add(1, std::memory_order_acq_rel) + 1U;
    const std::filesystem::path temporary = target.wstring() + L".aida-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(sequence) + L".tmp";
    HANDLE file = CreateFileW(
        temporary.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LocalFree(acl);
        return false;
    }
    bool written = true;
    std::size_t offset = 0;
    while (offset < content.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(
            content.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD completed = 0;
        if (!WriteFile(file, content.data() + offset, chunk, &completed, nullptr) ||
            completed != chunk) {
            written = false;
            break;
        }
        offset += completed;
    }
    if (written)
        written = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (written) {
        written = MoveFileExW(
            temporary.c_str(), target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (written) {
        written = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(target.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS;
    }
    if (!written)
        DeleteFileW(temporary.c_str());
    LocalFree(acl);
    return written;
}

static std::string strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    bool in_string = false, in_line = false, in_block = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (in_line)  { if (c == '\n') { in_line = false; result += '\n'; } continue; }
        if (in_block) { if (c == '*' && i+1 < input.size() && input[i+1] == '/') { in_block = false; ++i; } continue; }
        if (in_string) { result += c; if (c == '\\' && i+1 < input.size()) result += input[++i]; else if (c == '"') in_string = false; continue; }
        if (c == '"') { in_string = true; result += c; continue; }
        if (c == '/' && i+1 < input.size()) {
            if (input[i+1] == '/') { in_line = true; ++i; continue; }
            if (input[i+1] == '*') { in_block = true; ++i; continue; }
        }
        if (c == ',') {
            size_t j = i+1;
            while (j < input.size() && (input[j]==' '||input[j]=='\t'||input[j]=='\n'||input[j]=='\r')) ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']')) continue;
        }
        result += c;
    }
    return result;
}

static bool parse_json_file(const std::string& path, json& out, bool allow_jsonc)
{
    std::string raw;
    if (!read_file_to_string(path, raw)) return false;
    try { out = json::parse(raw); return true; }
    catch (const json::parse_error&) {
        if (!allow_jsonc) return false;
    }
    try { out = json::parse(strip_jsonc(raw)); return true; }
    catch (const json::parse_error&) { return false; }
}

static bool write_json_file(const std::string& path, const json& data)
{
    return write_string_to_file(path, json_dump_safe(data, 2) + "\n");
}

static const char* MCP_NAME = "aida-standalone-mcp";

struct client_cfg_t {
    const char* name;
    enum { URL, SERVERURL, OPENCODE, VSCODE, VSCODE_JSON, CLINE, ZED, CODEX, CLAUDE_CODE } format;
    const char* win_path;
};

struct client_handoff_t {
    std::string authorization;
    std::string run_binding;

    json headers() const {
        return json{
            {"Authorization", authorization},
            {"X-AiDA-MCP-Run-Id", run_binding},
        };
    }
};

static const client_cfg_t g_clients[] = {
    { "Cline",           client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" },
    { "Roo Code",        client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" },
    { "Kilo Code",       client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json" },
    { "Claude",          client_cfg_t::URL,          "%APPDATA%/Claude/claude_desktop_config.json" },
    { "Cursor",          client_cfg_t::URL,          "~/.cursor/mcp.json" },
    { "Windsurf",        client_cfg_t::URL,          "~/.codeium/windsurf/mcp_config.json" },
    { "Claude Code",     client_cfg_t::CLAUDE_CODE,  "~/.claude.json" },
    { "LM Studio",       client_cfg_t::URL,          "~/.lmstudio/mcp.json" },
    { "Codex",           client_cfg_t::CODEX,        "~/.codex/config.toml" },
    { "Zed",             client_cfg_t::ZED,          "%APPDATA%/Zed/settings.json" },
    { "Gemini CLI",      client_cfg_t::URL,          "~/.gemini/settings.json" },
    { "Qwen Coder",      client_cfg_t::URL,          "~/.qwen/settings.json" },
    { "Copilot CLI",     client_cfg_t::URL,          "~/.copilot/mcp-config.json" },
    { "Crush",           client_cfg_t::URL,          "~/crush.json" },
    { "Augment Code",    client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Qodo Gen",        client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Antigravity IDE", client_cfg_t::SERVERURL,    "~/.gemini/antigravity/mcp_config.json" },
    { "Warp",            client_cfg_t::URL,          "~/.warp/mcp_config.json" },
    { "Amazon Q",        client_cfg_t::URL,          "~/.aws/amazonq/mcp_config.json" },
    { "Opencode",        client_cfg_t::OPENCODE,     "~/.config/opencode/opencode.json" },
    { "Kiro",            client_cfg_t::URL,          "~/.kiro/settings/mcp.json" },
    { "Kiro Legacy",     client_cfg_t::URL,          "~/.kiro/mcp_config.json" },
    { "Trae",            client_cfg_t::URL,          "~/.trae/mcp_config.json" },
    { "VS Code",         client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "VS Code Insiders",client_cfg_t::VSCODE,       "%APPDATA%/Code - Insiders/User/settings.json" },
    { "VS Code (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code/User/mcp.json" },
    { "VS Code Insiders (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code - Insiders/User/mcp.json" },
};

static bool is_managed_key(const std::string& key)
{
    return key == MCP_NAME ||
           key == "AiDA-Pro-MCP" ||
           key == "aida-pro-mcp" ||
           key == "aida-standalone-mcp" ||
           key == "camoufox-reverse-mcp" ||
           key == "camoufox_reverse_mcp" ||
           key == "camoufox-reverse";
}

static void erase_managed_keys(json& root)
{
    if (!root.is_object())
        return;
    std::vector<std::string> keys;
    for (auto it = root.begin(); it != root.end(); ++it) {
        if (is_managed_key(it.key()))
            keys.push_back(it.key());
    }
    for (const auto& key : keys)
        root.erase(key);
}

static bool write_mcpservers(const std::string& path, const std::string& url,
                             const char* key, const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = json::object();
    config["mcpServers"][MCP_NAME]["type"] = "http";
    config["mcpServers"][MCP_NAME][key] = url;
    config["mcpServers"][MCP_NAME]["headers"] = handoff.headers();
    return write_json_file(path, config);
}

static bool write_opencode(const std::string& path, const std::string& url,
                           const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();
    erase_managed_keys(config["mcp"]);
    config["mcp"][MCP_NAME] = {
        {"type", "remote"}, {"url", url}, {"headers", handoff.headers()}};
    return write_json_file(path, config);
}

static bool write_vscode(const std::string& path, const std::string& url,
                         const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object()) config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();
    erase_managed_keys(config["mcp"]["servers"]);
    config["mcp"]["servers"][MCP_NAME] = {
        {"type", "http"}, {"url", url}, {"headers", handoff.headers()}};
    return write_json_file(path, config);
}

static bool write_vscode_json(const std::string& path, const std::string& url,
                              const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();
    erase_managed_keys(config["servers"]);
    config["servers"][MCP_NAME] = {
        {"type", "http"}, {"url", url}, {"headers", handoff.headers()}};
    return write_json_file(path, config);
}

static bool write_cline(const std::string& path, const std::string& url,
                        const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    json entry;
    entry["type"] = "http";
    entry["url"] = url;
    entry["headers"] = handoff.headers();
    config["mcpServers"][MCP_NAME] = entry;
    return write_json_file(path, config);
}

static bool write_zed(const std::string& path, const std::string& url,
                      const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();
    erase_managed_keys(config["context_servers"]);
    config["context_servers"][MCP_NAME] = {
        {"settings", {{"url", url}, {"headers", handoff.headers()}}}};
    return write_json_file(path, config);
}

static bool write_codex(const std::string& path, const std::string& url,
                        const client_handoff_t& handoff)
{
    std::string content;
    if (std::filesystem::exists(path)) read_file_to_string(path, content);
    auto strip_section = [](std::string& doc, const std::string& marker) {
        size_t pos = doc.find(marker);
        while (pos != std::string::npos) {
            size_t end = doc.find("\n[", pos + marker.size());
            if (end == std::string::npos) end = doc.size(); else end += 1;
            doc.erase(pos, end - pos);
            pos = doc.find(marker);
        }
    };
    strip_section(content, "[mcp_servers.aida-standalone-mcp]");
    strip_section(content, "[mcp_servers.aida-pro-mcp]");
    strip_section(content, "[mcp_servers.AiDA-Pro-MCP]");
    strip_section(content, "[mcp_servers.camoufox-reverse-mcp]");
    strip_section(content, "[mcp_servers.camoufox_reverse_mcp]");
    strip_section(content, "[mcp_servers.camoufox-reverse]");
    strip_section(content, std::string("[mcp_servers.") + MCP_NAME + "]");
    if (!content.empty() && content.back() != '\n') {
        content += "\n";
    }
    content += "\n[mcp_servers." + std::string(MCP_NAME) + "]\nurl = \"" + url + "\"\n";
    content += "http_headers = { Authorization = \"" + handoff.authorization +
        "\", \"X-AiDA-MCP-Run-Id\" = \"" + handoff.run_binding + "\" }\n";
    return write_string_to_file(path, content);
}

static bool write_claude_code(const std::string& path, const std::string& url,
                              const client_handoff_t& handoff)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = {
        {"type", "http"}, {"url", url}, {"headers", handoff.headers()}};
    return write_json_file(path, config);
}

void server_t::write_client_configs() const
{
    if (!_running.load()) {
        diag::log_tagged("mcp_config", "write_client_configs_skipped_not_running");
        return;
    }

    std::string port_str = std::to_string(_port.load(std::memory_order_acquire));
    std::string http_url = "http://127.0.0.1:" + port_str + "/mcp";
    std::string sse_url = "http://127.0.0.1:" + port_str + "/sse";
    std::string capability;
    std::string run_binding;
    if (!snapshot_local_capability(capability, run_binding)) {
        diag::log_tagged("mcp_config", "write_client_configs_skipped_capability_unavailable");
        return;
    }
    scoped_secret_string_t capability_guard(capability);
    (void)capability_guard;
    scoped_secret_string_t run_binding_guard(run_binding);
    (void)run_binding_guard;
    client_handoff_t handoff{
        "Bearer " + capability,
        run_binding,
    };
    scoped_secret_string_t authorization_guard(handoff.authorization);
    (void)authorization_guard;
    scoped_secret_string_t handoff_run_binding_guard(handoff.run_binding);
    (void)handoff_run_binding_guard;
    diag::log_tagged_fmt("mcp_config", "write_client_configs_start url='%s' sse='%s'", http_url.c_str(), sse_url.c_str());

    std::set<std::string> written;
    int ok = 0, skip = 0, fail = 0;

    for (const auto& def : g_clients) {
        try {
            std::string path = expand_path(def.win_path);
            if (path.empty()) {
                diag::log_tagged_fmt("mcp_config", "client_skip_empty name='%s'", def.name);
                ++skip;
                continue;
            }
            if (written.count(path)) {
                diag::log_tagged_fmt("mcp_config", "client_skip_duplicate name='%s' path='%s'", def.name, path.c_str());
                continue;
            }

            if (path.find("globalStorage") != std::string::npos) {
                auto parent = std::filesystem::path(path).parent_path();
                std::error_code ec;
                if (!std::filesystem::is_directory(parent, ec)) {
                    diag::log_tagged_fmt("mcp_config", "client_optional_storage_absent name='%s' path='%s'", def.name, path.c_str());
                    ++skip;
                    continue;
                }
            }

            diag::log_tagged_fmt("mcp_config", "client_write_start name='%s' path='%s'", def.name, path.c_str());
            bool success = false;
            switch (def.format) {
            case client_cfg_t::URL:          success = write_mcpservers(path, http_url, "url", handoff); break;
            case client_cfg_t::SERVERURL:    success = write_mcpservers(path, http_url, "serverUrl", handoff); break;
            case client_cfg_t::OPENCODE:     success = write_opencode(path, http_url, handoff); break;
            case client_cfg_t::VSCODE:       success = write_vscode(path, http_url, handoff); break;
            case client_cfg_t::VSCODE_JSON:  success = write_vscode_json(path, http_url, handoff); break;
            case client_cfg_t::CLINE:        success = write_cline(path, http_url, handoff); break;
            case client_cfg_t::ZED:          success = write_zed(path, http_url, handoff); break;
            case client_cfg_t::CODEX:        success = write_codex(path, http_url, handoff); break;
            case client_cfg_t::CLAUDE_CODE:  success = write_claude_code(path, http_url, handoff); break;
            }

            if (success) {
                diag::log_tagged_fmt("mcp_config", "client_write_ok name='%s' path='%s'", def.name, path.c_str());
                written.insert(path);
                ++ok;
            }
            else {
                diag::log_tagged_fmt("mcp_config", "client_write_fail name='%s' path='%s'", def.name, path.c_str());
                ++fail;
            }
        } catch (const std::exception& e) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='%.180s'", def.name, e.what());
            ++fail;
        } catch (...) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='<unknown>'", def.name);
            ++fail;
        }
    }
    diag::log_tagged_fmt("mcp_config", "write_client_configs_done ok=%d skip=%d fail=%d", ok, skip, fail);
}


target_scope_t resolve_target(const json& args, std::string* out_err)
{
    target_scope_t scope;
    const bool explicit_selector = tool_args_select_session_target(args);
    workspace_resolution_t resolution;
    if (explicit_selector) {
        resolution = resolve_workspace_direct(args);
    } else {
        resolution.workspace = analysis_session::active_workspace();
        if (!resolution.workspace)
            resolution.workspace = aida::analysis::workspace_registry().selected_for_ui();
        if (!resolution.workspace) {
            resolution.code = "TARGET_NOT_FOUND";
            resolution.message = "No active target workspace is available";
            resolution.details = json{{"ui_selection_changed", false}};
        }
    }
    if (!resolution.workspace) {
        scope.err = resolution.message.empty()
            ? std::string("Unable to resolve target workspace")
            : resolution.message;
        scope.error_code = resolution.code.empty() ? "TARGET_NOT_FOUND" : resolution.code;
        scope.error_details = resolution.details;
        if (out_err)
            *out_err = scope.err;
        return scope;
    }

    scope.ok = true;
    scope.resolved = true;
    scope.workspace = std::move(resolution.workspace);
    scope.resolved_id = scope.workspace->identity().binary_id().to_hex();
    const auto sessions = analysis_session::list_session_summaries();
    for (std::size_t index = 0; index < sessions.size(); ++index) {
        if (sessions[index].binary_id == scope.resolved_id || sessions[index].id == scope.resolved_id) {
            scope.target_idx = index;
            break;
        }
    }
    diag::log_tagged_fmt("mcp_standalone",
        "resolve_target binary_id='%s' target_idx=%llu explicit_selector=%d ui_selection_changed=0",
        scope.resolved_id.c_str(),
        static_cast<unsigned long long>(scope.target_idx),
        explicit_selector ? 1 : 0);
    return scope;
}


}
