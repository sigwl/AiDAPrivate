#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../analysis/workspace/workspace_types.hpp"

namespace aida::analysis {
class analysis_workspace_t;
}

namespace mcp_standalone {

using json = nlohmann::json;

struct tool_result_t {
    bool success = true;
    std::string text;
    json data;
    std::string error_code;
    json error_details;
    json meta = json::object();

    static tool_result_t ok(const char* text) {
        return {true, std::string(text), {}, {}, {}, {}};
    }
    static tool_result_t ok(const std::string& text) {
        return {true, text, {}, {}, {}, {}};
    }
    static tool_result_t ok(const json& value) {
        return {true, value.dump(2), value, {}, {}, {}};
    }
    static tool_result_t ok(const std::string& text, const json& value) {
        return {true, text, value, {}, {}, {}};
    }
    static tool_result_t error(const std::string& text) {
        return {false, text, {}, {}, {}, {}};
    }
    static tool_result_t error(const std::string& text, const json& details) {
        return {false, text, {}, "MCP_TOOL_ERROR", details, {}};
    }
    static tool_result_t error(const std::string& text, const std::string& code,
                               const json& details = json::object()) {
        return {false, text, details, code, details, {}};
    }
};

struct tool_param_t {
    std::string name;
    std::string type;
    std::string description;
    bool required = false;
};

enum class tool_visibility_t : int {
    external_visible = 0,
    internal_only = 1,
    ide_chat_only = 2
};

using cancel_token_ptr_t = std::shared_ptr<std::atomic<bool>>;

cancel_token_ptr_t make_call_cancel_token(bool cancelled = false);
void signal_call_cancel_token(const cancel_token_ptr_t& token) noexcept;
std::atomic<bool>* current_cancel_token() noexcept;
bool current_call_cancelled() noexcept;
const char* current_call_diag_id() noexcept;
const char* current_call_request_id() noexcept;
const char* current_call_tool_name() noexcept;
std::uint64_t current_call_deadline_ms() noexcept;

class scoped_call_cancel_t {
public:
    scoped_call_cancel_t() = default;
    explicit scoped_call_cancel_t(cancel_token_ptr_t token);
    ~scoped_call_cancel_t();
    scoped_call_cancel_t(const scoped_call_cancel_t&) = delete;
    scoped_call_cancel_t& operator=(const scoped_call_cancel_t&) = delete;
    scoped_call_cancel_t(scoped_call_cancel_t&& other) noexcept;
    scoped_call_cancel_t& operator=(scoped_call_cancel_t&& other) noexcept;
    void cancel() noexcept;
    cancel_token_ptr_t token() const noexcept { return token_; }

private:
    void release() noexcept;
    cancel_token_ptr_t token_;
    std::atomic<bool>* previous_ = nullptr;
    bool active_ = false;
};

class scoped_call_metadata_t {
public:
    scoped_call_metadata_t(const std::string& diagnostic_id,
                           const std::string& tool_name,
                           std::uint64_t deadline_ms);
    scoped_call_metadata_t(const std::string& diagnostic_id,
                           const std::string& request_id,
                           const std::string& tool_name,
                           std::uint64_t deadline_ms);
    ~scoped_call_metadata_t();
    scoped_call_metadata_t(const scoped_call_metadata_t&) = delete;
    scoped_call_metadata_t& operator=(const scoped_call_metadata_t&) = delete;

private:
    std::string previous_diagnostic_id_;
    std::string previous_request_id_;
    std::string previous_tool_name_;
    std::uint64_t previous_deadline_ms_ = 0;
    bool active_ = false;
};

struct workspace_request_context_t {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::analysis::target_kind_t kind =
        aida::analysis::target_kind_t::static_file;
    aida::analysis::binary_id_t binary_id;
    std::optional<std::uint32_t> pid;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::atomic<bool>* cancellation = nullptr;
    std::uint64_t deadline_ms = 0;
    std::string diagnostic_id;
    std::string request_id;
    std::string tool_name;

    bool cancellation_requested() const noexcept {
        return cancellation && cancellation->load(std::memory_order_acquire);
    }
};

struct tool_def_t {
    std::string name;
    std::string description;
    std::vector<tool_param_t> params;
    bool read_only = true;
    std::function<tool_result_t(const json& params)> handler;
    tool_visibility_t visibility = tool_visibility_t::external_visible;
    std::function<tool_result_t(
        const json& params,
        const workspace_request_context_t& context)> workspace_handler;
    json input_schema;
    json output_schema;
    json annotations;
    bool target_independent = false;
    bool production_registry_dispatch = false;
};

using tool_validation_hook_t =
    std::function<tool_result_t(const tool_def_t&, const json&)>;

void set_pre_dispatch_validation_hook(tool_validation_hook_t hook);

}
