#pragma once
#include <string>
#include <string_view>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <functional>
#include <vector>

#include <nlohmann/json.hpp>
#include <optional>
#include "registry/tool_registry.hpp"

namespace aida::analysis
{
    class analysis_workspace_t;
}

namespace mcp_standalone
{
    using json = nlohmann::json;

    static constexpr int JSONRPC_PARSE_ERROR      = -32700;
    static constexpr int JSONRPC_INVALID_REQUEST  = -32600;
    static constexpr int JSONRPC_METHOD_NOT_FOUND = -32601;
    static constexpr int JSONRPC_INVALID_PARAMS   = -32602;
    static constexpr int JSONRPC_INTERNAL_ERROR   = -32603;

    static constexpr const char* PROTOCOL_VERSION = "2025-06-18";
    static constexpr const char* SERVER_NAME      = "aida-pro-mcp";
    static constexpr const char* SERVER_VERSION   = "1.0.0";

    void set_ide_lifecycle_ready(bool ready) noexcept;
    bool lifecycle_authorized(std::string* reason = nullptr);
    void format_runtime_diagnostic_snapshot(char* out, std::size_t cap) noexcept;
    std::size_t active_http_request_count() noexcept;
    std::size_t active_tool_lease_count() noexcept;

    struct bounded_diag_snapshot_t {
        std::size_t active_requests = 0;
        std::size_t active_leases = 0;
        std::size_t pending_cancellations = 0;
        std::size_t stale_leases = 0;
        std::size_t fenced_leases = 0;
        std::size_t tombstoned_active = 0;
        bool lease_lock_busy = false;
        char oldest_owner[160] = {};
        char capacity_snapshot[1024] = {};
        char lease_registry_snapshot[1400] = {};
        char downstream_snapshot[512] = {};
        std::size_t camoufox_longop_active = 0;
    };
    bounded_diag_snapshot_t bounded_diagnostic_snapshot() noexcept;

    json active_session_policy_debug_snapshot();

    enum class local_request_auth_status_t : std::uint8_t
    {
        allowed = 0,
        health_read_only,
        invalid_remote,
        invalid_host,
        browser_origin_forbidden,
        capability_missing,
        capability_rejected,
        run_binding_missing,
        run_binding_rejected
    };

    struct local_request_auth_input_t
    {
        std::string method;
        std::string path;
        std::string remote_address;
        std::string host;
        std::string origin;
        std::string authorization;
        std::string run_binding;
        int bound_port = 0;
    };

    struct local_request_auth_result_t
    {
        local_request_auth_status_t status = local_request_auth_status_t::capability_rejected;
        bool allowed = false;
        bool capability_authenticated = false;
    };

    local_request_auth_result_t authorize_local_request(
        const local_request_auth_input_t& input,
        std::string_view expected_capability,
        std::string_view expected_run_binding) noexcept;

    bool verify_local_route_capability(
        std::string_view authorization,
        std::string_view run_binding,
        std::string_view origin,
        std::string_view expected_capability,
        std::string_view expected_run_binding) noexcept;

    class server_t
    {
    public:
        server_t();
        ~server_t();

        bool start(int port);
        void stop();
        bool is_running() const { return _running.load(); }
        int  get_port() const { return _port.load(std::memory_order_acquire); }
        bool register_tool(tool_def_t tool);
        bool register_tool(
            tool_def_t tool,
            std::function<tool_result_t(
                const json&,
                const std::shared_ptr<aida::analysis::analysis_workspace_t>&)> handler);
        bool register_tool(
            tool_def_t tool,
            std::function<tool_result_t(
                const json&,
                const workspace_request_context_t&)> handler);
        tool_result_t call_registered_tool(const std::string& name, const json& arguments, bool external_visible_only);
        tool_result_t describe_tools(const json& params);
        void write_client_configs() const;
        const std::vector<tool_def_t>& get_tools() const noexcept {
            return _registry.tools_view();
        }
        tool_registry_t& registry() noexcept { return _registry; }
        const tool_registry_t& registry() const noexcept { return _registry; }

    private:
        struct shared_state_t;
        explicit server_t(std::shared_ptr<shared_state_t> state, bool owns_lifecycle);
        friend std::string handle_body(server_t*, const std::string&, const std::function<bool()>&);
        void server_thread_func(int port);
        json handle_initialize(const json& id, const json& params);
        json handle_tools_list(const json& id, const json& params);
        json handle_tools_call(const json& id, const json& params);
        json handle_resources_list(const json& id, const json& params);
        json handle_resources_read(const json& id, const json& params);
        json handle_prompts_list(const json& id, const json& params);
        json handle_prompts_get(const json& id, const json& params);
        json handle_ping(const json& id, const json& params);
        json route_request(const json& request);
        json make_result(const json& id, const json& result);
        json make_error(const json& id, int code, const std::string& msg);
        json tool_schema(const tool_def_t& tool, bool compact) const;
        bool rotate_local_capability() noexcept;
        void clear_local_capability() noexcept;
        bool snapshot_local_capability(std::string& capability,
                                       std::string& run_binding) const;
        std::shared_ptr<shared_state_t> _state;
        bool _owns_lifecycle = true;
        tool_registry_t& _registry;
        std::atomic<bool>& _server_done;
        std::atomic<bool>& _running;
        std::atomic<bool>& _stop_requested;
        void*& _active_server;
        std::mutex& _server_mtx;
        std::atomic<std::uint32_t>& _server_worker_tid;
        std::mutex& _local_capability_mtx;
        std::string& _local_capability;
        std::string& _local_run_binding;
        std::atomic<int>& _port;
    };

    void register_standalone_tools(server_t& server);
    tool_result_t read_live_struct(const json& params);
    void register_c03_compatibility_tools(server_t& server);
    void register_c03_compatibility_tools(tool_registry_t& registry);
    std::string handle_body(server_t* self, const std::string& body, const std::function<bool()>& connection_closed = {});

    struct target_scope_t
    {
        bool        ok = false;
        bool        resolved = false;
        size_t      target_idx      = static_cast<size_t>(-1);
        std::string resolved_id;
        std::string err;
        std::string error_code;
        json        error_details;
        std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;

        target_scope_t() = default;
        target_scope_t(const target_scope_t&) = delete;
        target_scope_t& operator=(const target_scope_t&) = delete;
        target_scope_t(target_scope_t&&) noexcept = default;
        target_scope_t& operator=(target_scope_t&&) noexcept = default;
        ~target_scope_t() = default;
    };

    target_scope_t resolve_target(const json& args, std::string* out_err);

}
