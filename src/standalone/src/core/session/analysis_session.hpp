#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../analysis/workspace/analysis_workspace.hpp"
#include "../infra/taskflow_runtime.hpp"

namespace symbol_store {
class workspace_state_t;
}

namespace analysis_session {

struct pdb_session_state_t;

static constexpr size_t kMaxSessions = 16;

enum class session_kind_t : int {
    static_file = 0,
    live_attach = 1,
};

enum class session_load_state_t : std::uint8_t {
    opening = 0,
    analyzing = 1,
    ready = 2,
    failed = 3,
    closing = 4,
    closed = 5,
};

struct analysis_session_t {
    std::string id;
    std::string path;
    std::string filename;
    std::string session_name;
    std::uint64_t session_created_ms = 0;
    std::uint64_t last_active_steady_ms = 0;
    bool ui_selected = false;
    std::uint32_t attached_pid = 0;
    std::wstring process_name;
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::shared_ptr<symbol_store::workspace_state_t> symbols;
    std::shared_ptr<pdb_session_state_t> pdb_state;
    aida::analysis::cancellation_source_t load_cancellation;
    std::optional<std::uint64_t> open_task_id;
    std::optional<aida::infra::taskflow_runtime::job_handle_t> baseline_job;
    std::uint64_t load_generation = 1;
    session_load_state_t load_state = session_load_state_t::opening;
    std::optional<aida::analysis::workspace_error_t> load_error;
};

struct session_summary_t {
    std::string id;
    session_kind_t kind = session_kind_t::static_file;
    std::string path;
    std::string filename;
    std::uint32_t pid = 0;
    std::string process_name;
    bool is_active = false;
    bool is_alive = true;
    std::uint64_t last_active_steady_ms = 0;
    session_load_state_t load_state = session_load_state_t::opening;
    std::string binary_id;
    std::uint64_t process_creation_time_100ns = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    aida::analysis::workspace_readiness_t readiness =
        aida::analysis::workspace_readiness_t::created;
    bool pdb_remote_pending = false;
    bool pdb_local_pending = false;
    bool pdb_loading = false;
    bool pdb_failed = false;
    std::string pdb_status;
    std::uint64_t pdb_bytes_received = 0;
    std::uint64_t pdb_bytes_total = 0;
    int pdb_progress_percent = 0;
    std::uint64_t symbol_revision = 0;
    std::optional<aida::analysis::workspace_error_t> error;
};

struct static_workspace_acquisition_t {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::optional<aida::infra::taskflow_runtime::job_handle_t> analysis_job;
    bool analysis_started = false;
    bool joined_existing = false;
};

struct pdb_prompt_snapshot_t {
    std::string binary_id;
    bool remote_pending = false;
    bool local_pending = false;
    bool loading = false;
    bool failed = false;
    bool declined = false;
    bool load_types = true;
    bool load_names = true;
    std::string module_name;
    std::string pdb_name;
    std::string pdb_guid;
    std::uint32_t pdb_age = 0;
    std::string symbol_server;
    std::string local_candidate;
    std::string reason;
    std::string status;
    std::uint64_t bytes_received = 0;
    std::uint64_t bytes_total = 0;
    int progress_percent = 0;
    std::uint64_t symbol_revision = 0;
};

bool open_session(const std::string& path);
aida::analysis::workspace_result_t<static_workspace_acquisition_t>
acquire_static_workspace(
    const std::string& path,
    const aida::analysis::cancellation_token_t& cancel = {});
bool open_attach_session(
    std::uint32_t pid,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel = {});
bool reattach_session_exact(
    const std::string& session_id,
    std::uint32_t expected_pid,
    std::uint64_t expected_process_creation_time_100ns,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel = {});
bool switch_session(size_t idx);
bool close_session(size_t idx);
bool cancel_session(size_t idx);
size_t active_session_idx();
size_t session_count();
const analysis_session_t* session_at(size_t idx);
std::shared_ptr<const analysis_session_t> session_handle_at(size_t idx);
std::shared_ptr<aida::analysis::analysis_workspace_t> active_workspace();
bool try_active_workspace(std::shared_ptr<aida::analysis::analysis_workspace_t>& output);
std::shared_ptr<aida::analysis::analysis_workspace_t> workspace_for_session(size_t idx);
std::shared_ptr<aida::analysis::analysis_workspace_t>
workspace_for_session_id(const std::string& session_id);
std::shared_ptr<symbol_store::workspace_state_t> symbols_for_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
aida::analysis::workspace_result_t<pdb_prompt_snapshot_t> pdb_prompt_snapshot(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
aida::analysis::workspace_result_t<void> approve_remote_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    bool load_types, bool load_names);
aida::analysis::workspace_result_t<void> approve_local_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const std::string& path, bool load_types, bool load_names);
aida::analysis::workspace_result_t<void> decline_remote_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
aida::analysis::workspace_result_t<void> decline_local_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
aida::analysis::workspace_result_t<void> cancel_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
bool find_session_by_path(const std::string& path, size_t* out_idx);
bool find_session_by_pid(std::uint32_t pid, size_t* out_idx);
bool find_session_by_id(const std::string& session_id, size_t* out_idx);
bool active_live_session_matches(std::uint32_t pid, const std::string& session_id);
void prune_lru(size_t max_keep);
const char* last_error();
bool has_active_target();
std::vector<session_summary_t> list_session_summaries();
session_summary_t summarize_session_at(size_t idx);

}
