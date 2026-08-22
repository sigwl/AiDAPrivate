#include "analysis_session.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../../preview/workspace_preview_fixture.hpp"
#include "../analysis/workspace/workspace_registry.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <utility>

namespace analysis_session {
namespace {

struct preview_session_state_t final {
    std::mutex mutex;
    std::vector<std::shared_ptr<analysis_session_t>> sessions;
    std::size_t active = 0;
    std::uint64_t sequence = 1;
    std::string error;
};

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string filename_from_path(const std::string& path) {
    const auto separator = path.find_last_of("/\\");
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

std::shared_ptr<analysis_session_t> make_session(
    preview_session_state_t& state, const std::string& path) {
    const auto& fixture = aida::preview::workspace_preview_fixture();
    auto session = std::make_shared<analysis_session_t>();
    session->id = state.sequence == 1
        ? fixture.session_id
        : fixture.session_id + "_" + std::to_string(state.sequence);
    ++state.sequence;
    session->path = path.empty() ? fixture.source_path : path;
    session->filename = filename_from_path(session->path);
    session->session_name = session->filename;
    session->session_created_ms = now_ms();
    session->last_active_steady_ms = session->session_created_ms;
    session->ui_selected = true;
    session->workspace = fixture.workspace;
    if (fixture.workspace) {
        const auto process = fixture.workspace->identity().process();
        if (process) {
            session->attached_pid = process->pid;
            session->process_name.assign(
                fixture.filename.begin(), fixture.filename.end());
        }
    }
    session->load_state = fixture.workspace
        ? session_load_state_t::ready : session_load_state_t::failed;
    if (!fixture.workspace)
        session->load_error = aida::analysis::make_workspace_error(
            aida::analysis::workspace_error_code_t::integrity_failure,
            "preview analysis workspace fixture failed validation",
            "preview_session");
    return session;
}

preview_session_state_t& state() {
    static preview_session_state_t value;
    static const bool initialized = [&] {
        value.sessions.push_back(make_session(value, {}));
        if (value.sessions.front()->workspace)
            aida::analysis::workspace_registry().bind_preview_workspace(
                value.sessions.front()->workspace);
        return true;
    }();
    static_cast<void>(initialized);
    return value;
}

void select_locked(preview_session_state_t& value, std::size_t index) {
    value.active = index;
    for (std::size_t current = 0; current < value.sessions.size(); ++current)
        value.sessions[current]->ui_selected = current == index;
    if (index < value.sessions.size()) {
        value.sessions[index]->last_active_steady_ms = now_ms();
        aida::analysis::workspace_registry().bind_preview_workspace(
            value.sessions[index]->workspace);
    }
}

bool same_path(const std::string& left, const std::string& right) {
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        auto lhs = left[index] == '/' ? '\\' : left[index];
        auto rhs = right[index] == '/' ? '\\' : right[index];
        if (lhs >= 'A' && lhs <= 'Z')
            lhs = static_cast<char>(lhs - 'A' + 'a');
        if (rhs >= 'A' && rhs <= 'Z')
            rhs = static_cast<char>(rhs - 'A' + 'a');
        if (lhs != rhs)
            return false;
    }
    return true;
}

session_summary_t summarize(const analysis_session_t& session, bool active) {
    session_summary_t summary;
    summary.id = session.id;
    summary.kind = session.attached_pid == 0
        ? session_kind_t::static_file : session_kind_t::live_attach;
    summary.path = session.path;
    summary.filename = session.filename;
    summary.pid = session.attached_pid;
    summary.process_name.assign(session.process_name.begin(),
                                session.process_name.end());
    summary.is_active = active;
    summary.last_active_steady_ms = session.last_active_steady_ms;
    summary.load_state = session.load_state;
    summary.error = session.load_error;
    if (session.workspace) {
        summary.binary_id = session.workspace->identity().binary_id().to_hex();
        if (const auto process = session.workspace->identity().process())
            summary.process_creation_time_100ns = process->creation_time_100ns;
        summary.analysis_revision = session.workspace->analysis_revision();
        summary.overlay_revision = session.workspace->overlay_revision();
        summary.readiness = session.workspace->progress().readiness;
    }
    summary.pdb_status = "Symbols indexed from deterministic preview data";
    summary.symbol_revision = 3;
    return summary;
}

aida::analysis::workspace_result_t<void> pdb_action(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    if (!workspace)
        return aida::analysis::workspace_result_t<void>::failure(
            aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::target_required,
                "preview PDB action requires a workspace", "preview_pdb"));
    return aida::analysis::workspace_result_t<void>::success();
}

}

bool open_session(const std::string& path) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (path.empty()) {
        value.error = "A file path is required";
        return false;
    }
    for (std::size_t index = 0; index < value.sessions.size(); ++index) {
        if (same_path(value.sessions[index]->path, path)) {
            select_locked(value, index);
            value.error.clear();
            return true;
        }
    }
    if (value.sessions.size() >= kMaxSessions) {
        value.error = "The preview session limit was reached";
        return false;
    }
    value.sessions.push_back(make_session(value, path));
    select_locked(value, value.sessions.size() - 1);
    value.error.clear();
    return value.sessions.back()->workspace != nullptr;
}

aida::analysis::workspace_result_t<static_workspace_acquisition_t>
acquire_static_workspace(const std::string& path,
                         const aida::analysis::cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return aida::analysis::workspace_result_t<static_workspace_acquisition_t>::failure(
            aida::analysis::make_workspace_error(
                cancel.deadline_exceeded()
                    ? aida::analysis::workspace_error_code_t::deadline_exceeded
                    : aida::analysis::workspace_error_code_t::cancelled,
                "preview workspace acquisition was cancelled",
                "preview_session"));
    if (!path.empty())
        static_cast<void>(open_session(path));
    static_workspace_acquisition_t result;
    result.workspace = active_workspace();
    result.joined_existing = true;
    if (!result.workspace)
        return aida::analysis::workspace_result_t<static_workspace_acquisition_t>::failure(
            aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::target_required,
                "preview workspace is unavailable", "preview_session"));
    return aida::analysis::workspace_result_t<static_workspace_acquisition_t>::success(
        std::move(result));
}

bool open_attach_session(
    std::uint32_t pid,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        const std::string error = cancel.deadline_exceeded()
            ? "deadline_exceeded" : "cancelled";
        if (out_err)
            *out_err = error;
        auto& value = state();
        std::lock_guard lock(value.mutex);
        value.error = error;
        return false;
    }
    const std::string error = pid == 0
        ? "A process identifier is required"
        : "Live process attachment is unavailable in the UI-only preview";
    if (out_err)
        *out_err = error;
    auto& value = state();
    std::lock_guard lock(value.mutex);
    value.error = error;
    return false;
}

bool reattach_session_exact(
    const std::string& session_id,
    std::uint32_t expected_pid,
    std::uint64_t expected_process_creation_time_100ns,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        const std::string error = cancel.deadline_exceeded()
            ? "deadline_exceeded" : "cancelled";
        if (out_err) *out_err = error;
        return false;
    }
    auto& value = state();
    std::lock_guard lock(value.mutex);
    const auto found = std::find_if(value.sessions.begin(), value.sessions.end(),
        [&](const std::shared_ptr<analysis_session_t>& session) {
            return session && session->id == session_id;
        });
    const std::string error = found == value.sessions.end()
        ? "session_not_found"
        : ((*found)->attached_pid != expected_pid || expected_pid == 0 ||
            expected_process_creation_time_100ns == 0)
            ? "TARGET_STALE: retained process identity does not match the session"
            : "Live process reattachment is unavailable in the UI-only preview";
    value.error = error;
    if (out_err) *out_err = error;
    return false;
}

bool switch_session(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (index >= value.sessions.size())
        return false;
    select_locked(value, index);
    return true;
}

bool close_session(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (index >= value.sessions.size())
        return false;
    value.sessions.erase(value.sessions.begin() +
                         static_cast<std::ptrdiff_t>(index));
    if (value.sessions.empty()) {
        value.active = 0;
        aida::analysis::workspace_registry().clear_preview_workspaces();
        return true;
    }
    select_locked(value, (std::min)(value.active,
                                    value.sessions.size() - 1));
    return true;
}

bool cancel_session(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (index >= value.sessions.size())
        return false;
    if (value.sessions[index]->load_state == session_load_state_t::ready)
        return true;
    value.sessions[index]->load_cancellation.request_cancel();
    value.sessions[index]->load_state = session_load_state_t::closed;
    return true;
}

std::size_t active_session_idx() {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return value.sessions.empty() ? 0 : value.active;
}

std::size_t session_count() {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return value.sessions.size();
}

const analysis_session_t* session_at(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return index < value.sessions.size() ? value.sessions[index].get() : nullptr;
}

std::shared_ptr<const analysis_session_t> session_handle_at(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return index < value.sessions.size() ? value.sessions[index] : nullptr;
}

std::shared_ptr<aida::analysis::analysis_workspace_t> active_workspace() {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return value.sessions.empty() ? nullptr
                                  : value.sessions[value.active]->workspace;
}

bool try_active_workspace(std::shared_ptr<aida::analysis::analysis_workspace_t>& output) {
	auto& value = state();
	std::unique_lock lock(value.mutex, std::try_to_lock);
	if (!lock.owns_lock()) return false;
	output = value.sessions.empty() ? nullptr : value.sessions[value.active]->workspace;
	return true;
}

std::shared_ptr<aida::analysis::analysis_workspace_t>
workspace_for_session(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return index < value.sessions.size() ? value.sessions[index]->workspace
                                         : nullptr;
}

std::shared_ptr<aida::analysis::analysis_workspace_t>
workspace_for_session_id(const std::string& session_id) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    const auto found = std::find_if(value.sessions.begin(), value.sessions.end(),
        [&](const auto& session) { return session->id == session_id; });
    return found == value.sessions.end() ? nullptr : (*found)->workspace;
}

std::shared_ptr<symbol_store::workspace_state_t> symbols_for_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    for (const auto& session : value.sessions)
        if (session->workspace == workspace)
            return session->symbols;
    return nullptr;
}

aida::analysis::workspace_result_t<pdb_prompt_snapshot_t> pdb_prompt_snapshot(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    if (!workspace)
        return aida::analysis::workspace_result_t<pdb_prompt_snapshot_t>::failure(
            aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::target_required,
                "preview PDB state requires a workspace", "preview_pdb"));
    pdb_prompt_snapshot_t result;
    result.binary_id = workspace->identity().binary_id().to_hex();
    result.module_name = workspace->identity().bin_name();
    result.pdb_name = "AiDA_Target.pdb";
    result.pdb_guid = "A1DA7B4294114C2DA870455972E3018D";
    result.pdb_age = 1;
    result.status = "Symbols loaded";
    result.progress_percent = 100;
    result.symbol_revision = 3;
    return aida::analysis::workspace_result_t<pdb_prompt_snapshot_t>::success(
        std::move(result));
}

aida::analysis::workspace_result_t<void> approve_remote_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    bool load_types, bool load_names) {
    static_cast<void>(load_types);
    static_cast<void>(load_names);
    return pdb_action(workspace);
}

aida::analysis::workspace_result_t<void> approve_local_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const std::string& path, bool load_types, bool load_names) {
    static_cast<void>(path);
    static_cast<void>(load_types);
    static_cast<void>(load_names);
    return pdb_action(workspace);
}

aida::analysis::workspace_result_t<void> decline_remote_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    return pdb_action(workspace);
}

aida::analysis::workspace_result_t<void> decline_local_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    return pdb_action(workspace);
}

aida::analysis::workspace_result_t<void> cancel_pdb(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    return pdb_action(workspace);
}

bool find_session_by_path(const std::string& path, std::size_t* out_idx) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    for (std::size_t index = 0; index < value.sessions.size(); ++index) {
        if (!same_path(value.sessions[index]->path, path))
            continue;
        if (out_idx)
            *out_idx = index;
        return true;
    }
    return false;
}

bool find_session_by_pid(std::uint32_t pid, std::size_t* out_idx) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    for (std::size_t index = 0; index < value.sessions.size(); ++index) {
        if (value.sessions[index]->attached_pid != pid || pid == 0)
            continue;
        if (out_idx)
            *out_idx = index;
        return true;
    }
    return false;
}

bool find_session_by_id(const std::string& session_id, std::size_t* out_idx) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    for (std::size_t index = 0; index < value.sessions.size(); ++index) {
        if (value.sessions[index]->id != session_id)
            continue;
        if (out_idx)
            *out_idx = index;
        return true;
    }
    return false;
}

bool active_live_session_matches(std::uint32_t pid, const std::string& session_id) {
    if (pid == 0 || session_id.empty())
        return false;
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (value.active >= value.sessions.size())
        return false;
    const auto& session = value.sessions[value.active];
    return session && session->attached_pid == pid && session->id == session_id &&
        session->load_state == session_load_state_t::ready && session->workspace;
}

void prune_lru(std::size_t max_keep) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    max_keep = (std::max<std::size_t>)(1, max_keep);
    while (value.sessions.size() > max_keep) {
        std::size_t oldest = 0;
        for (std::size_t index = 1; index < value.sessions.size(); ++index)
            if (value.sessions[index]->last_active_steady_ms <
                value.sessions[oldest]->last_active_steady_ms)
                oldest = index;
        value.sessions.erase(value.sessions.begin() +
                             static_cast<std::ptrdiff_t>(oldest));
    }
    select_locked(value, (std::min)(value.active, value.sessions.size() - 1));
}

const char* last_error() {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return value.error.c_str();
}

bool has_active_target() {
    return active_workspace() != nullptr;
}

std::vector<session_summary_t> list_session_summaries() {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    std::vector<session_summary_t> result;
    result.reserve(value.sessions.size());
    for (std::size_t index = 0; index < value.sessions.size(); ++index)
        result.push_back(summarize(*value.sessions[index], index == value.active));
    return result;
}

session_summary_t summarize_session_at(std::size_t index) {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return index < value.sessions.size()
        ? summarize(*value.sessions[index], index == value.active)
        : session_summary_t{};
}

}

#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include "../analysis/analysis_budget.hpp"
#include "../analysis/mapped_window_cache.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../analysis/pdb_downloader.hpp"
#include "../analysis/symbol_store.hpp"
#include "../analysis/workspace/analysis_metrics.hpp"
#include "../analysis/workspace/baseline_pipeline.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/search_index.hpp"
#include "../analysis/workspace/workspace_database.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../analysis/decompiler/decompile_batch_orchestrator.hpp"
#include "../analysis/decompiler/managed_entity_binding.hpp"
#include "../infra/executor.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/standalone_driver_identity.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#include "../ui/loading_binary_overlay.hpp"
#include "../../helpers/diag_log.hpp"

namespace analysis_session {

struct pdb_expected_identity_t {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t signature = 0;
    std::uint32_t age = 0;
    bool uses_guid = false;
};

struct pdb_session_state_t {
    std::mutex mutex;
    std::mutex publication_mutex;
    aida::analysis::binary_id_t binary_id;
    std::string module_name;
    std::string pdb_name;
    std::string pdb_guid;
    std::uint32_t pdb_age = 0;
    std::vector<pdb_expected_identity_t> expected_identities;
    std::string symbol_server = "https://msdl.microsoft.com/download/symbols";
    std::string local_candidate;
    std::string reason;
    std::string status;
    bool remote_pending = false;
    bool local_pending = false;
    bool loading = false;
    bool failed = false;
    bool declined = false;
    bool committing = false;
    bool operation_remote = false;
    bool load_types = true;
    bool load_names = true;
    std::uint64_t bytes_received = 0;
    std::uint64_t bytes_total = 0;
    int progress_percent = 0;
    std::uint64_t workspace_generation = 0;
    std::uint64_t generation = 0;
    std::optional<std::uint64_t> task_id;
    std::shared_ptr<std::atomic<bool>> parser_cancel;
    std::shared_ptr<std::atomic<float>> parser_progress;
};

namespace {

using aida::analysis::analysis_metrics_t;
using aida::analysis::analysis_workspace_t;
using aida::analysis::baseline_analysis_service_t;
using aida::analysis::baseline_analysis_settings_t;
using aida::analysis::cancellation_token_t;
using aida::analysis::decompile_batch_orchestrator_t;
using aida::analysis::decompiler_service_t;
using aida::analysis::make_workspace_error;
using aida::analysis::open_live_workspace_request_t;
using aida::analysis::open_static_workspace_request_t;
using aida::analysis::overlay_journal_t;
using aida::analysis::persisted_search_products_t;
using aida::analysis::search_index_t;
using aida::analysis::workspace_database_options_t;
using aida::analysis::workspace_database_t;
using aida::analysis::workspace_database_versions_t;
using aida::analysis::workspace_error_code_t;
using aida::analysis::workspace_error_t;
using aida::analysis::workspace_readiness_t;
using aida::analysis::workspace_registry;
using aida::analysis::workspace_result_t;

struct live_session_binding_t {
    driver_bridge::identity::live_target_identity_t source_identity;
    std::uint64_t capture_time_100ns = 0;
    std::uint64_t capture_size = 0;
    std::string capture_hash;
    bool stale = false;
    std::string stale_code;
    std::string stale_detail;
};

struct session_state_t {
    std::vector<std::shared_ptr<analysis_session_t>> sessions;
    std::unordered_map<std::string, live_session_binding_t> live_bindings;
    int active_idx = -1;
    std::uint64_t id_counter = 0;
    std::mutex mutex;
    std::recursive_mutex activation_mutex;
    std::string last_error;
};

session_state_t& state()
{
    static session_state_t value;
    return value;
}

struct static_workspace_gate_registry_t {
    std::mutex mutex;
    std::unordered_map<std::string, std::weak_ptr<std::timed_mutex>> gates;
};

static_workspace_gate_registry_t& static_workspace_gates()
{
    static static_workspace_gate_registry_t value;
    return value;
}

std::shared_ptr<std::timed_mutex> static_workspace_gate(const std::string& binary_id)
{
    auto& registry = static_workspace_gates();
    std::lock_guard<std::mutex> lock(registry.mutex);
    auto found = registry.gates.find(binary_id);
    if (found != registry.gates.end()) {
        if (auto existing = found->second.lock()) return existing;
        registry.gates.erase(found);
    }
    if (registry.gates.size() >= 4096) {
        for (auto it = registry.gates.begin(); it != registry.gates.end();) {
            if (it->second.expired()) it = registry.gates.erase(it);
            else ++it;
        }
    }
    auto created = std::make_shared<std::timed_mutex>();
    registry.gates.emplace(binary_id, created);
    return created;
}

std::uint64_t now_steady_ms()
{
    const auto value = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(value).count());
}

std::string derive_filename(const std::string& path)
{
    const size_t separator = path.find_last_of("/\\");
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

std::string make_session_id(std::uint64_t counter)
{
    char text[40]{};
    std::snprintf(text, sizeof(text), "as_%016llx",
                  static_cast<unsigned long long>(counter));
    return text;
}

bool paths_equal(const std::string& lhs, const std::string& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t index = 0; index < lhs.size(); ++index) {
        char left = lhs[index] == '/' ? '\\' : lhs[index];
        char right = rhs[index] == '/' ? '\\' : rhs[index];
        if (left >= 'A' && left <= 'Z') left = static_cast<char>(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z') right = static_cast<char>(right - 'A' + 'a');
        if (left != right) return false;
    }
    return true;
}

std::wstring widen_utf8(const std::string& text)
{
    if (text.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring result(static_cast<size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
            static_cast<int>(text.size()), result.data(), required) != required)
        return {};
    return result;
}

std::string narrow_utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(),
            static_cast<int>(text.size()), result.data(), required, nullptr, nullptr) != required)
        return {};
    return result;
}

workspace_database_versions_t database_versions(const analysis_workspace_t& workspace)
{
    workspace_database_versions_t versions;
    versions.engine_version = "aida-pe-workspace-engine-1";
    versions.specification_version = "pe-x86-zydis-4.1.1-ghidra-native-1";
    versions.analysis_settings_hash = workspace.identity().load_profile_hash().to_hex();
    return versions;
}

const aida::analysis::adaptive_analysis_budget_fields_t& adaptive_budget_fields()
{
    static const aida::analysis::adaptive_analysis_budget_fields_t fields = [] {
        const auto envelope = aida::analysis::host_memory_envelope();
        const auto computed = aida::analysis::adaptive_analysis_budget_fields(envelope);
        aida::analysis::mapped_window_cache_t::set_adaptive_window_ceiling(
            computed.window_cache_per_file_bytes, computed.window_cache_global_bytes);
        diag::log_tagged_fmt("analysis_session",
            "adaptive_budget total_phys=%llu avail_phys=%llu reserve_os=%llu usable=%llu max_analysis_memory=%llu staging_budget=%llu generation_quota=%llu window_cache_file=%llu window_cache_global=%llu pdb_persistence_cap=%llu reopen_range_budget=%llu low_memory=%d",
            static_cast<unsigned long long>(envelope.total_phys),
            static_cast<unsigned long long>(envelope.avail_phys),
            static_cast<unsigned long long>(envelope.reserve_os_bytes),
            static_cast<unsigned long long>(envelope.usable_bytes),
            static_cast<unsigned long long>(computed.max_analysis_memory_bytes),
            static_cast<unsigned long long>(computed.packed_staging_memory_budget_bytes),
            static_cast<unsigned long long>(computed.packed_generation_quota_bytes),
            static_cast<unsigned long long>(computed.window_cache_per_file_bytes),
            static_cast<unsigned long long>(computed.window_cache_global_bytes),
            static_cast<unsigned long long>(computed.pdb_persistence_total_bytes),
            static_cast<unsigned long long>(computed.reopen_range_budget_bytes),
            computed.low_memory ? 1 : 0);
        return computed;
    }();
    return fields;
}

workspace_result_t<void> install_workspace_services(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::shared_ptr<workspace_database_t>& database_out)
{
    workspace_database_options_t expected;
    expected.identity = workspace->identity_handle();
    expected.versions = database_versions(*workspace);
    const auto& adaptive = adaptive_budget_fields();
    expected.packed_generation_quota_bytes = adaptive.packed_generation_quota_bytes;
    expected.packed_staging_memory_budget_bytes = adaptive.packed_staging_memory_budget_bytes;
    expected.reopen_range_budget_bytes = adaptive.reopen_range_budget_bytes;
    expected.pdb_persistence_max_stored_bytes = adaptive.pdb_persistence_total_bytes;
    auto validate_database = [&](const std::shared_ptr<workspace_database_t>& database)
        -> workspace_result_t<void> {
        if (!database || !database->options().identity ||
            database->options().identity->binary_id() !=
                workspace->identity().binary_id()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "Installed database identity does not match its workspace",
                "analysis_session.services.database"));
        }
        const auto& actual = database->options().versions;
        if (actual.engine_version != expected.versions.engine_version ||
            actual.specification_version != expected.versions.specification_version ||
            actual.analysis_settings_hash !=
                expected.versions.analysis_settings_hash) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "Installed database versions do not match the workspace engine",
                "analysis_session.services.database"));
        }
        return workspace_result_t<void>::success();
    };

    diag::log_tagged("analysis_session", "install_workspace_services begin");
    auto database = workspace->database();
    if (!database) {
        diag::log_tagged("analysis_session", "install_workspace_services opening database");
        auto opened = workspace_database_t::open(expected);
        diag::log_tagged_fmt("analysis_session", "install_workspace_services database opened ok=%d", opened ? 1 : 0);
        if (!opened)
            return workspace_result_t<void>::failure(opened.error());
        auto registered = workspace->register_lifecycle_participant(opened.value());
        if (!registered) return registered;
        auto installed = workspace->install_database(opened.value());
        if (!installed) {
            database = workspace->database();
            if (!database)
                return installed;
        } else {
            database = opened.take_value();
        }
    }
    auto database_valid = validate_database(database);
    if (!database_valid) return database_valid;

    auto database_queue = database->queue();
    if (!database_queue) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "Workspace database did not provide its persistence queue",
            "analysis_session.services.queue"));
    }
    auto installed_queue = workspace->persistence_queue();
    if (!installed_queue) {
        auto registered = workspace->register_lifecycle_participant(database_queue);
        if (!registered) return registered;
        auto installed = workspace->install_persistence_queue(database_queue);
        if (!installed) {
            installed_queue = workspace->persistence_queue();
            if (!installed_queue) return installed;
        } else {
            installed_queue = database_queue;
        }
    }
    if (installed_queue != database_queue) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "Installed persistence queue is not owned by the workspace database",
            "analysis_session.services.queue"));
    }

    diag::log_tagged("analysis_session", "install_workspace_services overlay begin");
    if (!workspace->overlay()) {
        auto opened = overlay_journal_t::open(workspace, database);
        diag::log_tagged_fmt("analysis_session", "install_workspace_services overlay opened ok=%d", opened ? 1 : 0);
        if (!opened && !workspace->overlay())
            return workspace_result_t<void>::failure(opened.error());
    }
    if (!workspace->overlay()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::service_conflict,
            "Workspace overlay installation did not publish a service",
            "analysis_session.services.overlay"));
    }

    diag::log_tagged("analysis_session", "install_workspace_services decompiler begin");
    if (!workspace->decompiler()) {
        auto created = decompiler_service_t::create(
            workspace, database, expected.versions);
        diag::log_tagged_fmt("analysis_session", "install_workspace_services decompiler created ok=%d", created ? 1 : 0);
        if (!created && !workspace->decompiler())
            return workspace_result_t<void>::failure(created.error());
    }
    if (!workspace->decompiler()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::service_conflict,
            "Workspace decompiler installation did not publish a service",
            "analysis_session.services.decompiler"));
    }
    diag::log_tagged("analysis_session", "install_workspace_services batch_orchestrator begin");
    if (!workspace->background_decompile()) {
        (void)decompile_batch_orchestrator_t::create(workspace, workspace->background_metrics());
    }
    diag::log_tagged("analysis_session", "install_workspace_services end");
    database_out = std::move(database);
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> reopen_persisted_analysis(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<workspace_database_t>& database,
    const cancellation_token_t& cancel)
{
    diag::log_tagged("analysis_session", "reopen_persisted load_snapshot begin");
    auto loaded = database->load_snapshot(workspace->normalized_image(), workspace->image(), cancel);
    diag::log_tagged_fmt("analysis_session", "reopen_persisted load_snapshot ok=%d has_value=%d",
        loaded ? 1 : 0, (loaded && loaded.value()) ? 1 : 0);
    if (!loaded)
        return workspace_result_t<bool>::failure(loaded.error());
    if (!loaded.value())
        return workspace_result_t<bool>::success(false);
    const auto& snapshot = loaded.value();
    if (snapshot->functions.empty() && snapshot->strings.empty()) {
        diag::log_tagged("analysis_session", "reopen_persisted snapshot has 0 functions and 0 strings — ignoring stale DB, starting fresh baseline");
        return workspace_result_t<bool>::success(false);
    }
    const auto current_publication = workspace->analysis_publication();
    if (!current_publication || !current_publication->provider)
        return workspace_result_t<bool>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "Workspace provider is unavailable during managed reopen",
            "analysis_session.reopen"));
    auto managed = database->load_managed_publication(
        current_publication->provider, snapshot->generation,
        snapshot->analysis_revision, snapshot->overlay_revision, cancel);
    if (!managed)
        return workspace_result_t<bool>::failure(managed.error());
    auto managed_publication = managed.take_value();
    if (workspace->analysis_revision() >
        (std::numeric_limits<std::uint64_t>::max)() - 2ULL)
        return workspace_result_t<bool>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "Workspace analysis revision cannot advance during reopen",
            "analysis_session.reopen"));
    if (managed_publication &&
        snapshot->analysis_revision == workspace->analysis_revision() + 2ULL) {
        auto admission = aida::analysis::rebind_managed_artifact_publication(
            *managed_publication, workspace->identity(),
            *current_publication->provider, snapshot->image,
            snapshot->generation, workspace->analysis_revision() + 1ULL,
            snapshot->overlay_revision, cancel);
        if (!admission)
            return workspace_result_t<bool>::failure(admission.error());
        auto admitted = workspace->publish_managed_artifacts(
            workspace->generation(), workspace->analysis_revision(),
            admission.take_value(), true);
        if (!admitted)
            return workspace_result_t<bool>::failure(admitted.error());
    }
    if (snapshot->generation != workspace->generation() ||
        snapshot->analysis_revision != workspace->analysis_revision() + 1 ||
        snapshot->overlay_revision != workspace->overlay_revision()) {
        return workspace_result_t<bool>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "Persisted analysis generation or revision does not match the reopened workspace",
            "analysis_session.reopen"));
    }
    auto products = database->load_search_products(snapshot->generation,
        snapshot->analysis_revision, snapshot->overlay_revision, cancel);
    if (!products)
        return workspace_result_t<bool>::failure(products.error());
    auto metrics = std::make_shared<analysis_metrics_t>(snapshot->generation);
    auto persisted_products = products.take_value();
    workspace_result_t<std::shared_ptr<search_index_t>> index =
        persisted_products.search_index_blob.empty()
            ? search_index_t::build(
                  snapshot, std::move(persisted_products.data_candidates),
                  std::move(persisted_products.switches),
                  std::move(persisted_products.types), metrics, {}, cancel)
            : restore_persisted_search_index(
                  snapshot, std::move(persisted_products), metrics, {}, cancel);
    if (!index)
        return workspace_result_t<bool>::failure(index.error());
    if (cancel.stop_requested()) {
        return workspace_result_t<bool>::failure(make_workspace_error(
            workspace_error_code_t::cancelled,
            "Persisted analysis reopen was cancelled before publication",
            "analysis_session.reopen"));
    }
    auto published = workspace->publish_analysis_bundle(workspace->generation(),
        workspace->analysis_revision(), snapshot, index.take_value(),
        snapshot->baseline_complete);
    if (!published)
        return workspace_result_t<bool>::failure(published.error());
    if (managed_publication) {
        const auto reopened = workspace->analysis_publication();
        if (!reopened || !reopened->managed_artifacts) {
            auto managed_published = workspace->publish_managed_artifacts(
                snapshot->generation, snapshot->analysis_revision,
                managed_publication, false);
            if (!managed_published)
                return workspace_result_t<bool>::failure(
                    managed_published.error());
        } else if (!reopened->managed_artifacts->coherent_with(
                       workspace->identity(), *reopened->provider,
                       snapshot->generation, snapshot->analysis_revision,
                       snapshot->overlay_revision)) {
            return workspace_result_t<bool>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "Managed publication is incoherent after warm reopen",
                "analysis_session.reopen"));
        }
    }
    return workspace_result_t<bool>::success(true);
}

void record_load_failure(const std::string& session_id,
                         std::uint64_t load_generation,
                         workspace_error_t error)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    for (const auto& session : state().sessions) {
        if (session->id != session_id || session->load_generation != load_generation ||
            session->load_cancellation.token().stop_requested()) continue;
        session->open_task_id.reset();
        session->load_state = session_load_state_t::failed;
        session->load_error = std::move(error);
        state().last_error = session->load_error->stable_code() + ": " +
                             session->load_error->message;
        return;
    }
}

std::vector<std::string> local_pdb_candidates(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    constexpr std::size_t kMaximumCandidates = 64;
    constexpr std::uint64_t kMaximumPdbBytes =
        2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::vector<std::filesystem::path> candidates;
    const std::filesystem::path source(workspace->identity().normalized_source_path());
    const std::filesystem::path parent = source.parent_path();
    if (!source.empty()) {
        auto sibling = source;
        sibling.replace_extension(".pdb");
        candidates.push_back(std::move(sibling));
    }
    if (const auto image = workspace->image()) {
        for (const auto& record : image->codeview_records()) {
            if (record.pdb_path.empty()) continue;
            if (candidates.size() == kMaximumCandidates) break;
            std::filesystem::path recorded(record.pdb_path);
            if (!parent.empty())
                candidates.push_back(parent / recorded.filename());
        }
    }
    std::set<std::string> unique;
    std::vector<std::string> result;
    for (const auto& candidate : candidates) {
        if (result.size() == kMaximumCandidates) break;
        std::error_code error;
        auto absolute = std::filesystem::absolute(candidate, error);
        if (error) absolute = candidate;
        if (!std::filesystem::is_regular_file(absolute, error) || error)
            continue;
        const auto size = std::filesystem::file_size(absolute, error);
        if (error || size == 0 || size > kMaximumPdbBytes) continue;
        std::string key = absolute.lexically_normal().string();
        if (key.empty() || key.size() > 32768 ||
            key.find('\0') != std::string::npos)
            continue;
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        if (unique.insert(key).second)
            result.push_back(absolute.string());
    }
    return result;
}

struct pdb_binding_t {
    std::string session_id;
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<symbol_store::workspace_state_t> symbols;
    std::shared_ptr<pdb_session_state_t> prompt;
};

struct handle_closer_t {
    void operator()(void* handle) const noexcept
    {
        if (handle && handle != INVALID_HANDLE_VALUE)
            CloseHandle(static_cast<HANDLE>(handle));
    }
};

using unique_handle_t = std::unique_ptr<void, handle_closer_t>;

struct msf_superblock_t {
    std::array<char, 32> magic{};
    std::uint32_t block_size = 0;
    std::uint32_t free_block_map = 0;
    std::uint32_t block_count = 0;
    std::uint32_t directory_bytes = 0;
    std::uint32_t unknown = 0;
    std::uint32_t block_map = 0;
};

struct pdb_info_header_t {
    std::uint32_t version = 0;
    std::uint32_t signature = 0;
    std::uint32_t age = 0;
    std::array<std::uint8_t, 16> guid{};
};

static_assert(sizeof(msf_superblock_t) == 56);
static_assert(sizeof(pdb_info_header_t) == 28);

bool read_file_exact(HANDLE file, std::uint64_t offset, void* destination,
    std::size_t size, const std::shared_ptr<std::atomic<bool>>& cancel)
{
    if (file == INVALID_HANDLE_VALUE || !destination || size == 0 ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
        return false;
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) return false;
    auto* output = static_cast<std::uint8_t*>(destination);
    std::size_t consumed = 0;
    while (consumed < size) {
        if (cancel && cancel->load(std::memory_order_acquire)) return false;
        const DWORD requested = static_cast<DWORD>((std::min<std::size_t>)(
            size - consumed, 1024 * 1024));
        DWORD received = 0;
        if (!ReadFile(file, output + consumed, requested, &received, nullptr) ||
            received != requested)
            return false;
        consumed += received;
    }
    return true;
}

bool parse_pdb_file_identity(HANDLE file, std::uint64_t file_size,
    const std::shared_ptr<std::atomic<bool>>& cancel,
    pdb_info_header_t& identity, std::string& failure)
{
    constexpr std::array<char, 32> kMagic = {
        'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ',
        'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1a', 'D', 'S', '\0', '\0', '\0'};
    constexpr std::uint64_t kMaximumDirectoryBytes = 64ULL * 1024ULL * 1024ULL;
    constexpr std::uint32_t kMaximumStreams = 1024 * 1024;
    auto reject = [&failure](std::string message) {
        failure = std::move(message);
        return false;
    };
    msf_superblock_t superblock;
    if (!read_file_exact(file, 0, &superblock, sizeof(superblock), cancel))
        return reject(cancel && cancel->load(std::memory_order_acquire)
            ? "PDB identity read was cancelled" : "PDB superblock is unreadable");
    if (superblock.magic != kMagic)
        return reject("PDB uses an unsupported or malformed MSF container");
    switch (superblock.block_size) {
    case 512:
    case 1024:
    case 2048:
    case 4096:
    case 8192:
    case 16384:
    case 32768:
        break;
    default:
        return reject("PDB block size is unsupported");
    }
    if (superblock.free_block_map != 1 && superblock.free_block_map != 2)
        return reject("PDB free-block map is malformed");
    if (superblock.block_count == 0 ||
        static_cast<std::uint64_t>(superblock.block_count) * superblock.block_size !=
            file_size)
        return reject("PDB block count does not match its immutable file size");
    if (superblock.directory_bytes == 0 ||
        superblock.directory_bytes > kMaximumDirectoryBytes ||
        (superblock.directory_bytes % sizeof(std::uint32_t)) != 0)
        return reject("PDB directory size is invalid or exceeds its budget");
    const std::uint64_t directory_block_count =
        (static_cast<std::uint64_t>(superblock.directory_bytes) +
            superblock.block_size - 1) / superblock.block_size;
    if (directory_block_count == 0 ||
        directory_block_count > superblock.block_size / sizeof(std::uint32_t) ||
        superblock.block_map == 0 || superblock.block_map >= superblock.block_count)
        return reject("PDB directory block map is malformed");
    auto free_map_block = [&superblock](std::uint32_t block) {
        const std::uint32_t interval = block % superblock.block_size;
        return interval == 1 || interval == 2;
    };
    if (free_map_block(superblock.block_map))
        return reject("PDB directory block map overlaps a reserved block");
    auto reserved_block = [&superblock, &free_map_block](std::uint32_t block) {
        return block == 0 || block == superblock.block_map || free_map_block(block);
    };
    std::vector<std::uint32_t> directory_blocks(
        static_cast<std::size_t>(directory_block_count));
    const std::uint64_t block_map_offset =
        static_cast<std::uint64_t>(superblock.block_map) * superblock.block_size;
    if (!read_file_exact(file, block_map_offset, directory_blocks.data(),
            directory_blocks.size() * sizeof(std::uint32_t), cancel))
        return reject(cancel && cancel->load(std::memory_order_acquire)
            ? "PDB identity read was cancelled" : "PDB directory block map is unreadable");
    std::unordered_set<std::uint32_t> occupied_blocks;
    occupied_blocks.reserve(directory_blocks.size() * 2 + 8);
    occupied_blocks.insert(0);
    occupied_blocks.insert(superblock.free_block_map);
    occupied_blocks.insert(3U - superblock.free_block_map);
    occupied_blocks.insert(superblock.block_map);
    std::vector<std::uint8_t> directory(superblock.directory_bytes);
    std::size_t directory_offset = 0;
    for (const std::uint32_t block : directory_blocks) {
        if (block >= superblock.block_count || reserved_block(block) ||
            !occupied_blocks.insert(block).second)
            return reject("PDB directory contains an overlapping or invalid block");
        const std::size_t take = (std::min<std::size_t>)(
            superblock.block_size, directory.size() - directory_offset);
        if (!read_file_exact(file,
                static_cast<std::uint64_t>(block) * superblock.block_size,
                directory.data() + directory_offset, take, cancel))
            return reject(cancel && cancel->load(std::memory_order_acquire)
                ? "PDB identity read was cancelled" : "PDB directory block is unreadable");
        directory_offset += take;
    }
    if (directory_offset != directory.size())
        return reject("PDB directory is incomplete");
    std::size_t cursor = 0;
    auto read_u32 = [&directory, &cursor](std::uint32_t& value) {
        if (cursor > directory.size() || directory.size() - cursor < sizeof(value))
            return false;
        std::memcpy(&value, directory.data() + cursor, sizeof(value));
        cursor += sizeof(value);
        return true;
    };
    std::uint32_t stream_count = 0;
    if (!read_u32(stream_count) || stream_count < 2 || stream_count > kMaximumStreams)
        return reject("PDB stream count is invalid or exceeds its budget");
    if (static_cast<std::uint64_t>(stream_count) * sizeof(std::uint32_t) >
        directory.size() - cursor)
        return reject("PDB stream-size table is truncated");
    std::vector<std::uint32_t> stream_sizes(stream_count);
    std::memcpy(stream_sizes.data(), directory.data() + cursor,
        stream_sizes.size() * sizeof(std::uint32_t));
    cursor += stream_sizes.size() * sizeof(std::uint32_t);
    std::vector<std::uint32_t> info_blocks;
    for (std::uint32_t stream = 0; stream < stream_count; ++stream) {
        const std::uint32_t stream_size = stream_sizes[stream];
        const std::uint64_t block_count = stream_size == UINT32_MAX || stream_size == 0
            ? 0
            : (static_cast<std::uint64_t>(stream_size) + superblock.block_size - 1) /
                superblock.block_size;
        if (block_count > (directory.size() - cursor) / sizeof(std::uint32_t))
            return reject("PDB stream block map is truncated");
        if (stream == 1) info_blocks.reserve(static_cast<std::size_t>(block_count));
        for (std::uint64_t block_index = 0; block_index < block_count; ++block_index) {
            std::uint32_t block = 0;
            if (!read_u32(block) || block >= superblock.block_count ||
                reserved_block(block) ||
                !occupied_blocks.insert(block).second)
                return reject("PDB streams contain an overlapping or invalid block");
            if (stream == 1) info_blocks.push_back(block);
        }
    }
    if (cursor != directory.size())
        return reject("PDB directory contains trailing unaccounted data");
    if (stream_sizes[1] < sizeof(pdb_info_header_t) || info_blocks.empty())
        return reject("PDB information stream is missing or truncated");
    std::array<std::uint8_t, sizeof(pdb_info_header_t)> header_bytes{};
    std::size_t header_offset = 0;
    for (const std::uint32_t block : info_blocks) {
        if (header_offset == header_bytes.size()) break;
        const std::size_t take = (std::min<std::size_t>)(
            superblock.block_size, header_bytes.size() - header_offset);
        if (!read_file_exact(file,
                static_cast<std::uint64_t>(block) * superblock.block_size,
                header_bytes.data() + header_offset, take, cancel))
            return reject(cancel && cancel->load(std::memory_order_acquire)
                ? "PDB identity read was cancelled" : "PDB information stream is unreadable");
        header_offset += take;
    }
    if (header_offset != header_bytes.size())
        return reject("PDB information stream header is incomplete");
    std::memcpy(&identity, header_bytes.data(), sizeof(identity));
    switch (identity.version) {
    case 20000404:
    case 20030901:
    case 20091201:
    case 20140508:
        break;
    default:
        return reject("PDB information stream version is unsupported");
    }
    return true;
}

bool pdb_identity_matches(const pdb_info_header_t& actual,
    const std::vector<pdb_expected_identity_t>& expected)
{
    for (const auto& candidate : expected) {
        if (candidate.age != actual.age) continue;
        if (candidate.uses_guid) {
            if (candidate.guid == actual.guid) return true;
        } else if (candidate.signature != 0 && candidate.signature == actual.signature) {
            return true;
        }
    }
    return false;
}

std::string lowered_module_key(const std::string& module_name)
{
    std::string key = module_name;
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return key;
}

std::optional<aida::analysis::pdb_symbol_module_record_t> build_pdb_persistence_record(
    const symbol_store::module_symbols_t& module,
    const pdb_info_header_t& pdb_identity,
    const BY_HANDLE_FILE_INFORMATION& file_identity,
    std::uint64_t file_size)
{
    if (module.module_name.empty() || module.size == 0 ||
        module.pdb.symbols.size() > 4 * 1024 * 1024 ||
        module.pdb.structs.size() > 1024 * 1024 ||
        module.pdb.enums.size() > 1024 * 1024) {
        diag::log_tagged_fmt("analysis_session",
            "pdb_persistence_store_skipped reason=module_invariants module=%s",
            module.module_name.c_str());
        return std::nullopt;
    }
    std::array<std::uint8_t, 16> file_id{};
    std::memcpy(file_id.data(), &file_identity.nFileIndexLow,
        sizeof(file_identity.nFileIndexLow));
    std::memcpy(file_id.data() + sizeof(file_identity.nFileIndexLow),
        &file_identity.nFileIndexHigh, sizeof(file_identity.nFileIndexHigh));
    const std::uint64_t last_write_100ns =
        (static_cast<std::uint64_t>(file_identity.ftLastWriteTime.dwHighDateTime) << 32) |
        static_cast<std::uint64_t>(file_identity.ftLastWriteTime.dwLowDateTime);
    const std::uint32_t source_line_count = module.pdb.source_lines
        ? static_cast<std::uint32_t>(module.pdb.source_lines->lines.size()) : 0;
    symbol_store::pdb_module_persist_header_t header;
    header.module_name = module.module_name;
    header.base = module.base;
    header.size = module.size;
    header.pdb_guid = pdb_identity.guid;
    header.pdb_age = pdb_identity.age;
    header.pdb_path = module.pdb_path;
    header.pdb_file_size = file_size;
    header.pdb_volume_serial = static_cast<std::uint64_t>(file_identity.dwVolumeSerialNumber);
    header.pdb_file_id = file_id;
    header.pdb_last_write_100ns = last_write_100ns;
    header.symbol_count = static_cast<std::uint32_t>(module.pdb.symbols.size());
    header.struct_count = static_cast<std::uint32_t>(module.pdb.structs.size());
    header.enum_count = static_cast<std::uint32_t>(module.pdb.enums.size());
    header.source_line_count = source_line_count;
    auto payload = symbol_store::serialize_module(header, module, false);
    if (!payload) {
        diag::log_tagged_fmt("analysis_session",
            "pdb_persistence_store_skipped reason=serialize_failed module=%s",
            module.module_name.c_str());
        return std::nullopt;
    }
    aida::analysis::pdb_symbol_module_record_t record;
    record.module_key = lowered_module_key(module.module_name);
    record.module_name = module.module_name;
    record.base = module.base;
    record.size = module.size;
    record.pdb_guid = pdb_identity.guid;
    record.pdb_age = pdb_identity.age;
    record.pdb_path = module.pdb_path;
    record.pdb_file_size = file_size;
    record.pdb_volume_serial = header.pdb_volume_serial;
    record.pdb_file_id = file_id;
    record.pdb_last_write_100ns = last_write_100ns;
    record.symbol_count = header.symbol_count;
    record.struct_count = header.struct_count;
    record.enum_count = header.enum_count;
    record.payload = std::move(*payload);
    if (module.pdb.source_lines) {
        auto source_lines =
            symbol_store::serialize_module_source_lines(*module.pdb.source_lines);
        if (!source_lines) {
            diag::log_tagged_fmt("analysis_session",
                "pdb_persistence_store_skipped reason=serialize_source_lines_failed module=%s",
                module.module_name.c_str());
            return std::nullopt;
        }
        record.source_lines = std::move(*source_lines);
    }
    return record;
}

void enqueue_pdb_persistence_record(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    aida::analysis::pdb_symbol_module_record_t record)
{
    if (!workspace) return;
    auto database = workspace->database();
    if (!database) {
        diag::log_tagged_fmt("analysis_session",
            "pdb_persistence_store_skipped reason=no_database module=%s",
            record.module_name.c_str());
        return;
    }
    const std::uint64_t payload_bytes =
        static_cast<std::uint64_t>(record.payload.size());
    const std::uint64_t source_line_bytes = record.source_lines
        ? static_cast<std::uint64_t>(record.source_lines->size()) : 0;
    const std::string module_name = record.module_name;
    database->store_pdb_symbol_modules(std::move(record),
        workspace->cancellation_token());
    diag::log_tagged_fmt("analysis_session",
        "pdb_persistence_store_submitted module=%s payload_bytes=%llu source_line_bytes=%llu",
        module_name.c_str(),
        static_cast<unsigned long long>(payload_bytes),
        static_cast<unsigned long long>(source_line_bytes));
}

std::optional<pdb_binding_t> pdb_binding_for_workspace(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace) return std::nullopt;
    std::lock_guard<std::mutex> lock(state().mutex);
    for (const auto& session : state().sessions) {
        if (session->workspace != workspace || !session->symbols || !session->pdb_state)
            continue;
        if (session->symbols->binary_id() != workspace->identity().binary_id() ||
            session->pdb_state->binary_id != workspace->identity().binary_id())
            return std::nullopt;
        return pdb_binding_t{session->id, workspace, session->symbols, session->pdb_state};
    }
    return std::nullopt;
}

std::string format_codeview_guid(const std::array<std::uint8_t, 16>& guid)
{
    std::uint32_t data1 = 0;
    std::uint16_t data2 = 0;
    std::uint16_t data3 = 0;
    std::memcpy(&data1, guid.data(), sizeof(data1));
    std::memcpy(&data2, guid.data() + 4, sizeof(data2));
    std::memcpy(&data3, guid.data() + 6, sizeof(data3));
    char text[40]{};
    std::snprintf(text, sizeof(text),
        "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        data1, data2, data3, guid[8], guid[9], guid[10], guid[11], guid[12],
        guid[13], guid[14], guid[15]);
    return text;
}

bool valid_remote_pdb_name(const std::string& name)
{
    if (name.empty() || name.size() > 260 || name == "." || name == "..") return false;
    for (unsigned char value : name) {
        if ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-')
            continue;
        return false;
    }
    return true;
}

bool valid_codeview_guid(const std::string& guid)
{
    if (guid.size() != 32) return false;
    bool nonzero = false;
    for (unsigned char value : guid) {
        const bool hex = (value >= '0' && value <= '9') ||
            (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
        if (!hex) return false;
        if (value != '0') nonzero = true;
    }
    return nonzero;
}

void initialize_pdb_prompt(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<pdb_session_state_t>& prompt)
{
    if (!workspace || !prompt) return;
    std::string pdb_name;
    std::string pdb_guid;
    std::uint32_t pdb_age = 0;
    std::vector<pdb_expected_identity_t> expected_identities;
    bool remote_identity_selected = false;
    if (const auto image = workspace->image()) {
        for (const auto& record : image->codeview_records()) {
            if (record.pdb_path.empty()) continue;
            pdb_expected_identity_t expected;
            expected.guid = record.guid;
            expected.signature = record.timestamp;
            expected.age = record.age;
            expected.uses_guid = std::any_of(record.guid.begin(), record.guid.end(),
                [](std::uint8_t value) { return value != 0; });
            if (expected_identities.size() < 64)
                expected_identities.push_back(expected);
            const std::string candidate_name =
                std::filesystem::path(record.pdb_path).filename().string();
            const std::string candidate_guid = format_codeview_guid(record.guid);
            const bool remote_capable = expected.uses_guid && record.age != 0 &&
                valid_remote_pdb_name(candidate_name) &&
                valid_codeview_guid(candidate_guid);
            if (pdb_name.empty() || (!remote_identity_selected && remote_capable)) {
                pdb_name = candidate_name;
                pdb_guid = candidate_guid;
                pdb_age = record.age;
                remote_identity_selected = remote_capable;
            }
        }
    }
    const auto candidates = local_pdb_candidates(workspace);
    std::lock_guard<std::mutex> lock(prompt->mutex);
    prompt->binary_id = workspace->identity().binary_id();
    prompt->workspace_generation = workspace->generation();
    prompt->module_name = workspace->identity().bin_name();
    prompt->pdb_name = std::move(pdb_name);
    prompt->pdb_guid = std::move(pdb_guid);
    prompt->pdb_age = pdb_age;
    prompt->expected_identities = std::move(expected_identities);
    prompt->committing = false;
    prompt->parser_progress.reset();
    prompt->local_candidate = candidates.empty() ? std::string() : candidates.front();
    prompt->remote_pending = prompt->local_candidate.empty() &&
        valid_remote_pdb_name(prompt->pdb_name) &&
        valid_codeview_guid(prompt->pdb_guid) && prompt->pdb_age != 0;
    prompt->local_pending = prompt->local_candidate.empty() &&
        !prompt->remote_pending && !prompt->pdb_name.empty();
    prompt->reason = prompt->remote_pending
        ? "The workspace references debug symbols available from the configured symbol server."
        : (prompt->local_pending
            ? "The workspace references a PDB that was not found beside the binary."
            : std::string());
    prompt->status = prompt->local_candidate.empty()
        ? (prompt->remote_pending ? "Awaiting symbol download approval"
            : (prompt->local_pending ? "Awaiting a local PDB path" : "No external PDB requested"))
        : "Loading local PDB";
}

struct pdb_task_request_t {
    bool remote = false;
    bool load_types = true;
    bool load_names = true;
    std::string local_path;
};

workspace_result_t<void> submit_pdb_task(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    pdb_task_request_t request)
{
    auto binding = pdb_binding_for_workspace(workspace);
    if (!binding) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "PDB operation requires an open workspace session",
            "analysis_session.pdb"));
    }
    if (workspace->target_kind() != aida::analysis::target_kind_t::static_file ||
        workspace->closing() || workspace->closed()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "PDB operation requires an open static workspace",
            "analysis_session.pdb"));
    }
    if (!request.load_types && !request.load_names) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "At least one PDB fact family must be selected",
            "analysis_session.pdb"));
    }
    constexpr std::uint64_t kMaximumPdbBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    const auto workspace_binary_id = workspace->identity().binary_id();
    const std::uint64_t workspace_generation = workspace->generation();
    std::uint64_t generation = 0;
    std::string module_name;
    std::string pdb_name;
    std::string pdb_guid;
    std::uint32_t pdb_age = 0;
    std::string symbol_server;
    std::vector<pdb_expected_identity_t> expected_identities;
    auto parser_cancel = std::make_shared<std::atomic<bool>>(false);
    auto parser_progress = std::make_shared<std::atomic<float>>(0.0f);
    {
        std::lock_guard<std::mutex> lock(binding->prompt->mutex);
        if (binding->prompt->loading) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::analysis_in_progress,
                "A PDB operation is already active for this workspace",
                "analysis_session.pdb"));
        }
        if (binding->prompt->binary_id != workspace_binary_id ||
            binding->prompt->workspace_generation != workspace_generation ||
            binding->symbols->binary_id() != workspace_binary_id) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "PDB state identity does not match the selected workspace",
                "analysis_session.pdb"));
        }
        if (request.remote && (!valid_remote_pdb_name(binding->prompt->pdb_name) ||
            !valid_codeview_guid(binding->prompt->pdb_guid) ||
            binding->prompt->pdb_age == 0)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "The workspace has no valid CodeView symbol-server identity",
                "analysis_session.pdb"));
        }
        if (binding->prompt->generation == UINT64_MAX) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "PDB operation generation overflowed",
                "analysis_session.pdb"));
        }
        generation = ++binding->prompt->generation;
        binding->prompt->loading = true;
        binding->prompt->failed = false;
        binding->prompt->declined = false;
        binding->prompt->committing = false;
        binding->prompt->operation_remote = request.remote;
        binding->prompt->remote_pending = false;
        binding->prompt->local_pending = false;
        binding->prompt->load_types = request.load_types;
        binding->prompt->load_names = request.load_names;
        binding->prompt->bytes_received = 0;
        binding->prompt->bytes_total = 0;
        binding->prompt->progress_percent = 0;
        binding->prompt->status = request.remote ? "Resolving PDB" : "Parsing local PDB";
        binding->prompt->parser_cancel = parser_cancel;
        binding->prompt->parser_progress = parser_progress;
        module_name = binding->prompt->module_name;
        pdb_name = binding->prompt->pdb_name;
        pdb_guid = binding->prompt->pdb_guid;
        pdb_age = binding->prompt->pdb_age;
        symbol_server = binding->prompt->symbol_server;
        expected_identities = binding->prompt->expected_identities;
    }
    const bool remote_operation = request.remote;
    auto fail = [prompt = binding->prompt, generation, remote_operation](std::string message,
        bool cancelled = false) {
        std::lock_guard<std::mutex> lock(prompt->mutex);
        if (prompt->generation != generation || !prompt->loading) return;
        if (prompt->committing) {
            prompt->status = "Finishing PDB publication";
            return;
        }
        prompt->loading = false;
        prompt->failed = !cancelled;
        prompt->remote_pending = remote_operation;
        prompt->local_pending = !remote_operation;
        prompt->status = std::move(message);
        prompt->parser_cancel.reset();
        prompt->parser_progress.reset();
        prompt->task_id.reset();
    };
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "analysis_session";
    submission.label = request.remote
        ? "analysis_session.workspace_pdb_remote"
        : "analysis_session.workspace_pdb_local";
    submission.thread_class = "external_tool";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 2;
    submission.generation = generation;
    submission.target_id = binding->session_id.c_str();
    submission.failure_policy = "reject_not_started";
    submission.deadline_ms = aida::infra::executor::now_ms() + 240000;
    submission.cancel_hook = [parser_cancel, fail]() {
        parser_cancel->store(true, std::memory_order_release);
        fail("PDB operation cancelled or deadline exceeded", true);
    };
    submission.body = [workspace, symbols = binding->symbols, prompt = binding->prompt,
        request = std::move(request), module_name = std::move(module_name),
        pdb_name = std::move(pdb_name), pdb_guid = std::move(pdb_guid), pdb_age,
        symbol_server = std::move(symbol_server), parser_cancel, parser_progress,
        generation, fail,
        workspace_binary_id, workspace_generation,
        expected_identities = std::move(expected_identities)]() mutable {
        auto current = [&]() {
            if (parser_cancel->load(std::memory_order_acquire) ||
                workspace->cancellation_token().stop_requested() ||
                workspace->closing() || workspace->closed() ||
                workspace->generation() != workspace_generation ||
                workspace->identity().binary_id() != workspace_binary_id ||
                symbols->binary_id() != workspace_binary_id ||
                analysis_session::symbols_for_workspace(workspace) != symbols)
                return false;
            std::lock_guard<std::mutex> lock(prompt->mutex);
            return prompt->generation == generation && prompt->loading &&
                prompt->binary_id == workspace_binary_id &&
                prompt->workspace_generation == workspace_generation;
        };
        if (!current()) {
            fail("PDB operation cancelled", true);
            return;
        }
        std::string local_path = request.local_path;
        if (request.remote) {
            const auto paths = symbols->path_snapshot();
            if (paths.truncated || paths.cache_dir.empty()) {
                fail("Workspace symbol cache path is unavailable");
                return;
            }
            pdb_downloader::download_request_t download;
            download.pdb_name = pdb_name;
            download.pdb_guid = pdb_guid;
            download.pdb_age = pdb_age;
            download.server_base = symbol_server;
            download.cache_root = paths.cache_dir;
            pdb_downloader::download_result_t result;
            auto download_limit_exceeded = std::make_shared<std::atomic<bool>>(false);
            auto progress = [prompt, parser_cancel, generation,
                download_limit_exceeded, kMaximumPdbBytes](
                const pdb_downloader::progress_t& value) {
                if (parser_cancel->load(std::memory_order_acquire)) return;
                if (value.bytes_received > kMaximumPdbBytes ||
                    value.bytes_total > kMaximumPdbBytes) {
                    download_limit_exceeded->store(true, std::memory_order_release);
                    parser_cancel->store(true, std::memory_order_release);
                }
                std::lock_guard<std::mutex> lock(prompt->mutex);
                if (prompt->generation != generation || !prompt->loading) return;
                prompt->bytes_received = value.bytes_received;
                prompt->bytes_total = value.bytes_total;
                prompt->progress_percent = (std::max)(0, (std::min)(100, value.percent));
                prompt->status = download_limit_exceeded->load(std::memory_order_acquire)
                    ? "PDB download exceeds the workspace byte budget"
                    : "Downloading PDB";
            };
            if (!pdb_downloader::download_pdb_sync(download, progress,
                parser_cancel.get(), result) || !result.ok) {
                const bool limit_exceeded =
                    download_limit_exceeded->load(std::memory_order_acquire);
                fail(limit_exceeded
                        ? "PDB download exceeds the 2 GiB workspace budget"
                        : (parser_cancel->load(std::memory_order_acquire)
                            ? "PDB download cancelled"
                            : "PDB download failed: " + result.error),
                    !limit_exceeded &&
                        parser_cancel->load(std::memory_order_acquire));
                return;
            }
            if (result.bytes_downloaded > kMaximumPdbBytes) {
                fail("PDB download exceeds the 2 GiB workspace budget");
                return;
            }
            local_path = result.local_path;
        }
        if (!current()) {
            fail("PDB operation cancelled", true);
            return;
        }
        if (local_path.empty() || local_path.size() > 32768 ||
            local_path.find('\0') != std::string::npos) {
            fail("PDB path is empty or exceeds the workspace path budget");
            return;
        }
        std::error_code error;
        auto absolute = std::filesystem::absolute(std::filesystem::path(local_path), error);
        if (error || !std::filesystem::is_regular_file(absolute, error) || error) {
            fail("PDB path is not a readable regular file");
            return;
        }
        HANDLE raw_file = CreateFileW(absolute.c_str(),
            GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
        if (raw_file == INVALID_HANDLE_VALUE) {
            fail("PDB file could not be opened with an immutable read lease");
            return;
        }
        unique_handle_t file_guard(raw_file);
        LARGE_INTEGER file_size_value{};
        BY_HANDLE_FILE_INFORMATION file_identity{};
        if (!GetFileSizeEx(raw_file, &file_size_value) ||
            file_size_value.QuadPart <= 0 ||
            static_cast<std::uint64_t>(file_size_value.QuadPart) > kMaximumPdbBytes ||
            !GetFileInformationByHandle(raw_file, &file_identity)) {
            fail("PDB file size is outside the 2 GiB workspace budget");
            return;
        }
        const std::uint64_t file_size =
            static_cast<std::uint64_t>(file_size_value.QuadPart);
        pdb_info_header_t pdb_identity;
        std::string identity_failure;
        if (!parse_pdb_file_identity(raw_file, file_size, parser_cancel,
                pdb_identity, identity_failure)) {
            fail(identity_failure.empty()
                ? "PDB identity validation failed" : std::move(identity_failure),
                parser_cancel->load(std::memory_order_acquire));
            return;
        }
        if (expected_identities.empty() ||
            !pdb_identity_matches(pdb_identity, expected_identities)) {
            fail("PDB identity does not match this workspace's CodeView record");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(prompt->mutex);
            if (prompt->generation != generation || !prompt->loading) return;
            prompt->status = "Parsing PDB";
            prompt->progress_percent = 0;
        }
        pdb_parser::pdb_info_t information;
        parser_progress->store(0.0f, std::memory_order_release);
        const std::filesystem::path source(workspace->identity().normalized_source_path());
        const bool parsed = pdb_parser::parse_pdb_bounded(absolute.string(),
            source.parent_path().string(), information, parser_progress.get(), parser_cancel.get(),
            symbol_store::k_explicit_pdb_load_timeout_ms);
        if (!parsed || !information.loaded) {
            fail(parser_cancel->load(std::memory_order_acquire)
                ? "PDB parse cancelled" : "PDB parse failed",
                parser_cancel->load(std::memory_order_acquire));
            return;
        }
        BY_HANDLE_FILE_INFORMATION current_identity{};
        LARGE_INTEGER current_size{};
        if (!GetFileInformationByHandle(raw_file, &current_identity) ||
            !GetFileSizeEx(raw_file, &current_size) ||
            current_size.QuadPart != file_size_value.QuadPart ||
            current_identity.dwVolumeSerialNumber != file_identity.dwVolumeSerialNumber ||
            current_identity.nFileIndexHigh != file_identity.nFileIndexHigh ||
            current_identity.nFileIndexLow != file_identity.nFileIndexLow ||
            current_identity.ftLastWriteTime.dwHighDateTime !=
                file_identity.ftLastWriteTime.dwHighDateTime ||
            current_identity.ftLastWriteTime.dwLowDateTime !=
                file_identity.ftLastWriteTime.dwLowDateTime) {
            fail("PDB file changed during parsing");
            return;
        }
        if (information.symbols.size() > 4 * 1024 * 1024 ||
            information.structs.size() > 1024 * 1024 ||
            information.enums.size() > 1024 * 1024) {
            fail("PDB metadata exceeds workspace record budgets");
            return;
        }
        if (!request.load_names) {
            information.symbols.clear();
            information.symbol_by_name.clear();
            information.symbol_by_rva.clear();
        }
        if (!request.load_types) {
            information.structs.clear();
            information.enums.clear();
            information.struct_by_name.clear();
            information.struct_by_ti.clear();
        }
        symbol_store::module_symbols_t module;
        module.module_name = module_name;
        module.base = workspace->identity().image_base();
        module.size = workspace->image() ? workspace->image()->image_size() : 0;
        module.pdb = std::move(information);
        module.pdb_path = absolute.string();
        module.pdb_file_size = file_size;
        module.parse_completed = true;
        module.parse_progress = 1.0f;
        module.status_text = "Loaded workspace PDB";
        {
            const bool symbols_current =
                analysis_session::symbols_for_workspace(workspace) == symbols;
            std::lock_guard<std::mutex> publication_lock(prompt->publication_mutex);
            {
                std::lock_guard<std::mutex> lock(prompt->mutex);
                if (prompt->generation != generation || !prompt->loading)
                    return;
                const bool cancelled = parser_cancel->load(std::memory_order_acquire) ||
                    workspace->cancellation_token().stop_requested() ||
                    workspace->closing() || workspace->closed();
                const bool identity_mismatch =
                    prompt->binary_id != workspace_binary_id ||
                    prompt->workspace_generation != workspace_generation ||
                    workspace->generation() != workspace_generation ||
                    workspace->identity().binary_id() != workspace_binary_id ||
                    symbols->binary_id() != workspace_binary_id || !symbols_current;
                if (cancelled || identity_mismatch) {
                    prompt->loading = false;
                    prompt->failed = identity_mismatch;
                    prompt->remote_pending = !identity_mismatch && request.remote;
                    prompt->local_pending = !identity_mismatch && !request.remote;
                    prompt->status = identity_mismatch
                        ? "PDB publication identity no longer matches its workspace"
                        : "PDB operation cancelled before publication";
                    prompt->parser_cancel.reset();
                    prompt->parser_progress.reset();
                    prompt->task_id.reset();
                    return;
                }
                prompt->committing = true;
                prompt->status = "Publishing PDB";
            }
            auto persistence_record = build_pdb_persistence_record(
                module, pdb_identity, file_identity, file_size);
            const bool published = symbols->upsert_module(std::move(module));
            if (published && persistence_record) {
                enqueue_pdb_persistence_record(workspace,
                    std::move(*persistence_record));
            }
            std::lock_guard<std::mutex> lock(prompt->mutex);
            prompt->committing = false;
            if (prompt->generation != generation || !prompt->loading ||
                prompt->binary_id != workspace_binary_id ||
                prompt->workspace_generation != workspace_generation)
                return;
            if (!published) {
                prompt->loading = false;
                prompt->failed = true;
                prompt->remote_pending = request.remote;
                prompt->local_pending = !request.remote;
                prompt->status = "PDB metadata exceeds workspace symbol-store budgets";
                prompt->parser_cancel.reset();
                prompt->parser_progress.reset();
                prompt->task_id.reset();
                return;
            }
            prompt->loading = false;
            prompt->failed = false;
            prompt->declined = false;
            prompt->local_candidate = absolute.string();
            prompt->progress_percent = 100;
            prompt->status = "Loaded workspace PDB";
            prompt->parser_cancel.reset();
            prompt->parser_progress.reset();
            prompt->task_id.reset();
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        fail("Failed to queue workspace PDB operation");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::service_conflict,
            "Failed to queue workspace PDB operation: " + submitted.reject_reason,
            "analysis_session.pdb"));
    }
    {
        std::lock_guard<std::mutex> lock(binding->prompt->mutex);
        if (binding->prompt->generation == generation && binding->prompt->loading)
            binding->prompt->task_id = submitted.task_id;
    }
    return workspace_result_t<void>::success();
}

void submit_pdb_restore(const std::string& session_id,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<symbol_store::workspace_state_t>& symbols,
    const std::shared_ptr<pdb_session_state_t>& pdb_state,
    std::string local_candidate)
{
    auto submit_local_parse = [&]() {
        if (local_candidate.empty() || !workspace) return;
        pdb_task_request_t request;
        request.local_path = std::move(local_candidate);
        const auto queued = submit_pdb_task(workspace, std::move(request));
        if (!queued) {
            diag::log_tagged_fmt("analysis_session",
                "local_pdb_submit_failed session=%s code=%s message=%s",
                session_id.c_str(), queued.error().stable_code().c_str(),
                queued.error().message.c_str());
        }
    };
    auto database = workspace ? workspace->database() : nullptr;
    if (!workspace || !database || !symbols || !pdb_state) {
        submit_local_parse();
        return;
    }
    std::vector<pdb_expected_identity_t> expected_identities;
    const std::uint64_t image_base = workspace->identity().image_base();
    std::uint64_t image_size = 0;
    if (const auto image = workspace->image()) {
        image_size = image->image_size();
        for (const auto& record : image->codeview_records()) {
            if (record.pdb_path.empty()) continue;
            pdb_expected_identity_t expected;
            expected.guid = record.guid;
            expected.signature = record.timestamp;
            expected.age = record.age;
            expected.uses_guid = std::any_of(record.guid.begin(), record.guid.end(),
                [](std::uint8_t value) { return value != 0; });
            if (expected_identities.size() < 64)
                expected_identities.push_back(expected);
        }
    }
    const auto binary_id = workspace->identity().binary_id();
    const std::uint64_t workspace_generation = workspace->generation();
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "analysis_session";
    submission.label = "analysis_session.workspace_pdb_restore";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.body = [workspace, database, symbols, pdb_state, session_id,
        local_candidate, expected_identities = std::move(expected_identities),
        image_base, image_size, binary_id, workspace_generation]() mutable {
        auto submit_local = [&]() {
            if (local_candidate.empty()) return;
            pdb_task_request_t request;
            request.local_path = std::move(local_candidate);
            const auto queued = submit_pdb_task(workspace, std::move(request));
            if (!queued) {
                diag::log_tagged_fmt("analysis_session",
                    "local_pdb_submit_failed session=%s code=%s message=%s",
                    session_id.c_str(), queued.error().stable_code().c_str(),
                    queued.error().message.c_str());
            }
        };
        auto current = [&]() {
            return !workspace->cancellation_token().stop_requested() &&
                !workspace->closing() && !workspace->closed() &&
                workspace->generation() == workspace_generation &&
                workspace->identity().binary_id() == binary_id &&
                symbols->binary_id() == binary_id &&
                analysis_session::symbols_for_workspace(workspace) == symbols;
        };
        if (!current()) return;
        std::uint64_t rows = 0;
        std::uint64_t restored = 0;
        std::uint64_t skipped = 0;
        auto loaded = database->load_pdb_symbol_modules(workspace->cancellation_token());
        if (loaded) {
            rows = loaded.value().size();
            for (auto& record : loaded.value()) {
                if (!current()) break;
                if (record.module_key.empty() ||
                    record.module_key != lowered_module_key(record.module_name) ||
                    record.size == 0 || record.base != image_base ||
                    record.size != image_size) {
                    ++skipped;
                    continue;
                }
                pdb_info_header_t actual{};
                actual.age = record.pdb_age;
                actual.guid = record.pdb_guid;
                if (!pdb_identity_matches(actual, expected_identities)) {
                    ++skipped;
                    continue;
                }
                symbol_store::pdb_persist_reader_t reader(record.payload);
                symbol_store::pdb_module_persist_header_t persisted_header;
                auto module = symbol_store::deserialize_module(reader, &persisted_header);
                if (!module ||
                    persisted_header.module_name != record.module_name ||
                    persisted_header.base != record.base ||
                    persisted_header.size != record.size ||
                    persisted_header.pdb_guid != record.pdb_guid ||
                    persisted_header.pdb_age != record.pdb_age ||
                    persisted_header.symbol_count != record.symbol_count ||
                    persisted_header.struct_count != record.struct_count ||
                    persisted_header.enum_count != record.enum_count) {
                    ++skipped;
                    continue;
                }
                if (record.source_lines) {
                    symbol_store::pdb_persist_reader_t lines_reader(*record.source_lines);
                    auto source_lines =
                        symbol_store::deserialize_module_source_lines(lines_reader);
                    if (!source_lines || !*source_lines ||
                        (*source_lines)->lines.size() !=
                            persisted_header.source_line_count) {
                        ++skipped;
                        continue;
                    }
                    module->pdb.source_lines = std::move(*source_lines);
                } else if (persisted_header.source_line_count != 0) {
                    ++skipped;
                    continue;
                }
                module->status_text = "Restored persisted workspace PDB";
                if (!symbols->upsert_module(std::move(*module))) {
                    ++skipped;
                    continue;
                }
                ++restored;
            }
        }
        diag::log_tagged_fmt("analysis_session",
            "pdb_persistence_restore session=%s binary_id=%s rows=%llu restored=%llu skipped=%llu",
            session_id.c_str(), binary_id.to_hex().c_str(),
            static_cast<unsigned long long>(rows),
            static_cast<unsigned long long>(restored),
            static_cast<unsigned long long>(skipped));
        if (restored != 0) {
            if (current()) {
                std::lock_guard<std::mutex> lock(pdb_state->mutex);
                if (pdb_state->binary_id == binary_id &&
                    pdb_state->workspace_generation == workspace_generation &&
                    !pdb_state->loading) {
                    pdb_state->remote_pending = false;
                    pdb_state->local_pending = false;
                    pdb_state->failed = false;
                    pdb_state->declined = false;
                    pdb_state->progress_percent = 100;
                    pdb_state->status = "Restored persisted workspace PDB";
                    pdb_state->reason.clear();
                }
            }
            return;
        }
        submit_local();
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        diag::log_tagged_fmt("analysis_session",
            "pdb_persistence_restore_submit_failed session=%s reason=%s",
            session_id.c_str(), submitted.reject_reason.c_str());
        submit_local_parse();
    }
}

bool bind_workspace(const std::string& session_id,
                    std::uint64_t load_generation,
                    const std::shared_ptr<analysis_workspace_t>& workspace,
                    std::optional<aida::infra::taskflow_runtime::job_handle_t> baseline_job,
                    session_load_state_t load_state)
{
    bool selected = false;
    bool merged = false;
    std::string merged_session_id;
    std::shared_ptr<symbol_store::workspace_state_t> symbols;
    std::shared_ptr<pdb_session_state_t> pdb_state;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        size_t target_index = static_cast<size_t>(-1);
        for (size_t index = 0; index < state().sessions.size(); ++index) {
            if (state().sessions[index]->id == session_id &&
                state().sessions[index]->load_generation == load_generation &&
                !state().sessions[index]->load_cancellation.token().stop_requested()) {
                target_index = index;
                break;
            }
        }
        if (target_index == static_cast<size_t>(-1)) return false;
        for (size_t index = 0; index < state().sessions.size(); ++index) {
            if (index == target_index) continue;
            auto& existing = state().sessions[index];
            if (!existing->workspace || !existing->symbols || !existing->pdb_state ||
                existing->workspace->closing() || existing->workspace->closed() ||
                existing->workspace->identity().binary_id() !=
                    workspace->identity().binary_id())
                continue;
            selected = state().active_idx == static_cast<int>(target_index);
            if (selected) {
                state().active_idx = static_cast<int>(index);
                for (auto& s : state().sessions)
                    s->ui_selected = false;
                existing->ui_selected = true;
            }
            existing->last_active_steady_ms = now_steady_ms();
            merged_session_id = state().sessions[target_index]->id;
            state().sessions.erase(state().sessions.begin() +
                static_cast<std::ptrdiff_t>(target_index));
            if (state().active_idx > static_cast<int>(target_index))
                --state().active_idx;
            merged = true;
            break;
        }
        if (!merged) {
            auto& session = state().sessions[target_index];
            session->workspace = workspace;
            session->symbols = std::make_shared<symbol_store::workspace_state_t>(
                workspace->identity().binary_id());
            symbols = session->symbols;
            session->pdb_state = std::make_shared<pdb_session_state_t>();
            session->pdb_state->binary_id = workspace->identity().binary_id();
            pdb_state = session->pdb_state;
            session->open_task_id.reset();
            session->baseline_job = baseline_job;
            session->load_state = load_state;
            session->load_error.reset();
            selected = state().active_idx == static_cast<int>(target_index);
        }
    }
    if (!merged) {
        std::lock_guard<std::mutex> lock(state().mutex);
        const auto current = std::find_if(state().sessions.begin(), state().sessions.end(),
            [&](const auto& session) {
                return session->id == session_id &&
                    session->load_generation == load_generation &&
                    !session->load_cancellation.token().stop_requested();
            });
        if (current == state().sessions.end()) return false;
    }
    if (merged) {
        loading_binary_overlay::release_session(merged_session_id);
        if (selected) {
            const auto selection = workspace_registry().select_for_ui(
                workspace->identity().binary_id());
            if (!selection) {
                std::lock_guard<std::mutex> lock(state().mutex);
                state().last_error = selection.error().stable_code() + ": " +
                    selection.error().message;
            }
        }
        return true;
    }
    {
        aida::workbench::workbench_shell_workspace_context_t workbench_context;
        const auto workbench_attached =
            aida::workbench::workbench_shell_runtime_t::instance()
                .attach_analysis_workspace(workspace, workbench_context);
        if (!workbench_attached) {
            diag::log_tagged_fmt(
                "analysis_session",
                "workbench_attach_deferred session=%s binary_id=%s code=%u subject=%llu",
                session_id.c_str(),
                workspace->identity().binary_id().to_hex().c_str(),
                static_cast<unsigned>(workbench_attached.code),
                static_cast<unsigned long long>(workbench_attached.subject));
        }
    }
    if (symbols && pdb_state) {
        const std::filesystem::path source(workspace->identity().normalized_source_path());
        std::vector<std::string> search_paths;
        if (!source.parent_path().empty())
            search_paths.push_back(source.parent_path().string());
        if (!symbols->configure_paths(std::move(search_paths),
                symbol_store::detail::get_cache_dir().string())) {
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "Workspace symbol paths exceed bounded storage limits",
                "analysis_session.bind_workspace");
            record_load_failure(session_id, load_generation, std::move(error));
            return false;
        }
        initialize_pdb_prompt(workspace, pdb_state);
        std::string local_candidate;
        {
            std::lock_guard<std::mutex> lock(pdb_state->mutex);
            local_candidate = pdb_state->local_candidate;
        }
        submit_pdb_restore(session_id, workspace, symbols, pdb_state,
            std::move(local_candidate));
    }
    if (selected) {
        const auto selection = workspace_registry().select_for_ui(
            workspace->identity().binary_id());
        if (!selection) {
            record_load_failure(session_id, load_generation, selection.error());
            return false;
        }
    }
    return workspace_for_session_id(session_id) != nullptr;
}

void static_open_worker(std::string session_id, std::uint64_t load_generation,
                        std::string path,
                        cancellation_token_t cancel)
{
    auto acquired = acquire_static_workspace(path, cancel);
    if (!acquired) {
        record_load_failure(session_id, load_generation, acquired.error());
        return;
    }
    auto result = acquired.take_value();
    const auto readiness = result.workspace->progress().readiness;
    const auto load_state =
        readiness == workspace_readiness_t::baseline_ready ||
        readiness == workspace_readiness_t::partial
            ? session_load_state_t::ready
            : session_load_state_t::analyzing;
    if (!bind_workspace(session_id, load_generation, result.workspace,
                        std::move(result.analysis_job), load_state)) {
        if (!workspace_for_session_id(session_id) && !result.joined_existing) {
            static_cast<void>(
                aida::workbench::workbench_shell_runtime_t::instance()
                    .close_analysis_workspace(result.workspace));
            result.workspace->request_cancel();
            (void)workspace_registry().close(result.workspace->identity().binary_id(),
                std::chrono::steady_clock::now() + std::chrono::seconds(10));
        }
        diag::log_tagged_fmt("analysis_session",
            "static_workspace_bind_skipped session=%s binary_id=%s started=%d joined=%d",
            session_id.c_str(),
            result.workspace->identity().binary_id().to_hex().c_str(),
            result.analysis_started ? 1 : 0,
            result.joined_existing ? 1 : 0);
    }
}

bool inspect_live_pe(std::uint32_t pid, std::uint64_t base,
                     bool& is_64_bit)
{
    std::vector<std::uint8_t> header;
    if (!driver_bridge::read_memory_for(pid, base, 4096, header) ||
        header.size() < sizeof(IMAGE_DOS_HEADER))
        return false;
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, header.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        return false;
    const std::uint64_t nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
    const std::uint64_t required = nt_offset + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
    if (required > header.size()) {
        if (required > (1ull << 20)) return false;
        if (!driver_bridge::read_memory_for(pid, base, static_cast<size_t>(required), header) ||
            header.size() < required)
            return false;
    }
    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    WORD optional_magic = 0;
    std::memcpy(&signature, header.data() + nt_offset, sizeof(signature));
    std::memcpy(&file_header, header.data() + nt_offset + sizeof(DWORD),
                sizeof(file_header));
    std::memcpy(&optional_magic,
        header.data() + nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
        sizeof(optional_magic));
    if (signature != IMAGE_NT_SIGNATURE) return false;
    const bool pe32 = file_header.Machine == IMAGE_FILE_MACHINE_I386 &&
        optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    const bool pe64 = file_header.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (!pe32 && !pe64) return false;
    is_64_bit = pe64;
    return true;
}

bool make_live_session_binding(
    const driver_bridge::identity::live_target_identity_t& source_identity,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    live_session_binding_t& out, std::string& out_error)
{
    const auto provider = workspace
        ? std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
            workspace->provider_handle())
        : nullptr;
    if (!provider) {
        out_error = "TARGET_STALE: live workspace has no immutable snapshot provider";
        return false;
    }
    const auto& metadata = provider->metadata();
    if (metadata.process.pid != source_identity.process.pid ||
        metadata.process.creation_time_100ns != source_identity.process.creation_time_100ns ||
        metadata.process.normalized_process_path !=
            source_identity.process.normalized_process_path ||
        metadata.module.base != source_identity.module.base ||
        metadata.module.size != source_identity.module.size ||
        metadata.module.normalized_name != source_identity.module.normalized_name ||
        metadata.module.normalized_path != source_identity.module.normalized_path) {
        out_error = "TARGET_STALE: snapshot metadata does not match live target identity";
        return false;
    }
    out = {};
    out.source_identity = source_identity;
    out.capture_time_100ns = metadata.capture_time_100ns;
    out.capture_size = metadata.capture_size;
    out.capture_hash = metadata.capture_hash.to_hex();
    return true;
}

void mark_live_session_stale(const std::string& session_id,
                             const live_session_binding_t& binding,
                             const std::string& code,
                             const std::string& detail)
{
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        const auto found = state().live_bindings.find(session_id);
        if (found != state().live_bindings.end()) {
            found->second.stale = true;
            found->second.stale_code = code;
            found->second.stale_detail = detail;
        }
        for (const auto& session : state().sessions) {
            if (session->id != session_id) continue;
            session->load_error = make_workspace_error(workspace_error_code_t::target_stale,
                detail, "analysis_session.live_identity");
            break;
        }
        state().last_error = code + ": " + detail;
    }
    diag::log_tagged_fmt("analysis_session",
        "live_session_stale session=%s source_pid=%u process_creation_100ns=%llu module_base=0x%llX module_size=%llu capture_time_100ns=%llu capture_sha256=%s stale_code=%s detail=%s",
        session_id.c_str(),
        binding.source_identity.process.pid,
        static_cast<unsigned long long>(binding.source_identity.process.creation_time_100ns),
        static_cast<unsigned long long>(binding.source_identity.module.base),
        static_cast<unsigned long long>(binding.source_identity.module.size),
        static_cast<unsigned long long>(binding.capture_time_100ns),
        binding.capture_hash.c_str(), code.c_str(), detail.c_str());
}

bool validate_live_session_binding(const std::string& session_id,
                                   const std::shared_ptr<analysis_workspace_t>& workspace,
                                   live_session_binding_t* out_binding,
                                   std::string& out_error)
{
    live_session_binding_t binding;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        const auto found = state().live_bindings.find(session_id);
        if (found == state().live_bindings.end()) {
            out_error = "TARGET_STALE: live session identity binding is missing";
            return false;
        }
        binding = found->second;
    }
    const auto target_validation = driver_bridge::identity::validate_live_target_identity(
        binding.source_identity);
    if (!target_validation.matches) {
        out_error = std::string(driver_bridge::identity::staleness_code(
            target_validation.staleness)) + ": " + target_validation.detail;
        mark_live_session_stale(session_id, binding,
            driver_bridge::identity::staleness_code(target_validation.staleness), out_error);
        return false;
    }
    const auto provider = workspace
        ? std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
            workspace->provider_handle())
        : nullptr;
    if (!provider) {
        out_error = "TARGET_STALE: live workspace has no immutable snapshot provider";
        mark_live_session_stale(session_id, binding, "TARGET_PROVIDER_MISSING", out_error);
        return false;
    }
    const auto provider_validation = provider->validate_current_identity();
    if (!provider_validation) {
        out_error = provider_validation.error().stable_code() + ": " +
            provider_validation.error().message;
        mark_live_session_stale(session_id, binding, "TARGET_SNAPSHOT_STALE", out_error);
        return false;
    }
    const auto& metadata = provider->metadata();
    if (metadata.process.pid != binding.source_identity.process.pid ||
        metadata.process.creation_time_100ns !=
            binding.source_identity.process.creation_time_100ns ||
        metadata.process.normalized_process_path !=
            binding.source_identity.process.normalized_process_path ||
        metadata.module.base != binding.source_identity.module.base ||
        metadata.module.size != binding.source_identity.module.size ||
        metadata.module.normalized_name != binding.source_identity.module.normalized_name ||
        metadata.module.normalized_path != binding.source_identity.module.normalized_path ||
        metadata.capture_time_100ns != binding.capture_time_100ns ||
        metadata.capture_size != binding.capture_size ||
        metadata.capture_hash.to_hex() != binding.capture_hash) {
        out_error = "TARGET_STALE: immutable snapshot metadata changed";
        mark_live_session_stale(session_id, binding, "TARGET_SNAPSHOT_METADATA_CHANGED", out_error);
        return false;
    }
    if (out_binding) *out_binding = std::move(binding);
    return true;
}

bool attached_pid_contains(std::uint32_t pid)
{
    const auto pids = driver_bridge::attached_pids();
    return std::find(pids.begin(), pids.end(), pid) != pids.end();
}

void restore_driver_active_pid(std::uint32_t previous_pid)
{
    if (previous_pid != 0 && attached_pid_contains(previous_pid)) {
        (void)driver_bridge::set_active_pid(previous_pid);
    } else {
        (void)driver_bridge::clear_active_pid();
    }
}

bool ensure_driver_active_for_session(
    std::uint32_t pid,
    bool& attached_by_transaction,
    std::string& out_error,
    const driver_bridge::identity::live_target_identity_t* identity = nullptr)
{
    attached_by_transaction = false;
    if (pid == 0 || pid == static_cast<std::uint32_t>(GetCurrentProcessId())) {
        out_error = pid == static_cast<std::uint32_t>(GetCurrentProcessId())
            ? "SELF_TARGET_REFUSED"
            : "invalid_pid";
        return false;
    }
    if (!attached_pid_contains(pid)) {
        const auto attached = driver_bridge::attached_pids();
        const bool added = attached.empty()
            ? driver_bridge::attach(pid)
            : driver_bridge::attach_additional(pid);
        if (!added) {
            out_error = "attach_failed: " + driver_bridge::last_error();
            return false;
        }
        attached_by_transaction = true;
    }
    if (identity) {
        const auto attached_identity =
            driver_bridge::identity::validate_attached_target_identity(*identity);
        if (!attached_identity.matches) {
            std::string identity_error;
            if (!driver_bridge::identity::refresh_attached_target_identity(*identity,
                                                                           &identity_error)) {
                out_error = identity_error.empty()
                    ? "TARGET_DRIVER_CONTEXT_REFRESH_FAILED"
                    : identity_error;
                return false;
            }
            attached_by_transaction = true;
            const auto rebound_identity =
                driver_bridge::identity::validate_attached_target_identity(*identity);
            if (!rebound_identity.matches) {
                out_error = std::string(driver_bridge::identity::staleness_code(
                    rebound_identity.staleness)) + ": " + rebound_identity.detail;
                return false;
            }
        }
    }
    if (!driver_bridge::set_active_pid(pid)) {
        out_error = "activate_failed: " + driver_bridge::last_error();
        return false;
    }
    return true;
}

bool may_detach_live_identity(
    std::uint32_t pid,
    const driver_bridge::identity::live_target_identity_t* identity,
    const char* reason)
{
    if (pid == 0 || !identity)
        return false;
    const auto validation = driver_bridge::identity::validate_live_target_identity(*identity);
    if (validation.matches)
        return true;
    diag::log_tagged_fmt("analysis_session",
        "live_session_detach_skipped reason=%s source_pid=%u process_creation_100ns=%llu module_base=0x%llX module_size=%llu stale_code=%s detail=%s",
        reason, pid,
        static_cast<unsigned long long>(identity->process.creation_time_100ns),
        static_cast<unsigned long long>(identity->module.base),
        static_cast<unsigned long long>(identity->module.size),
        driver_bridge::identity::staleness_code(validation.staleness),
        validation.detail.c_str());
    return false;
}

void rollback_driver_activation(
    std::uint32_t pid,
    std::uint32_t previous_pid,
    bool attached_by_transaction,
    const driver_bridge::identity::live_target_identity_t* identity = nullptr)
{
    if (attached_by_transaction &&
        may_detach_live_identity(pid, identity, "analysis_session.rollback"))
        (void)driver_bridge::detach_one(pid);
    if (driver_bridge::attached_pid() != previous_pid)
        restore_driver_active_pid(previous_pid);
}

bool activate_session_transaction(size_t idx, std::string* out_error)
{
    std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex);
    std::shared_ptr<analysis_session_t> session;
    std::shared_ptr<analysis_workspace_t> workspace;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (idx >= state().sessions.size()) {
            state().last_error = "idx_out_of_range";
            if (out_error) *out_error = state().last_error;
            return false;
        }
        session = state().sessions[idx];
        workspace = session->workspace;
    }
    if (!workspace) {
        const std::string error = "workspace_unavailable";
        std::lock_guard<std::mutex> lock(state().mutex);
        state().last_error = error;
        if (out_error) *out_error = error;
        return false;
    }

    const bool live = session->attached_pid != 0;
    const std::uint32_t previous_driver_pid = driver_bridge::attached_pid();
    bool attached_by_transaction = false;
    live_session_binding_t live_binding;
    std::string error;
    if (live && !validate_live_session_binding(session->id, workspace, &live_binding, error)) {
        if (out_error) *out_error = error;
        return false;
    }
    if (live && !ensure_driver_active_for_session(session->attached_pid,
                                                   attached_by_transaction, error,
                                                   &live_binding.source_identity)) {
        rollback_driver_activation(session->attached_pid, previous_driver_pid,
                                   attached_by_transaction, &live_binding.source_identity);
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_error) *out_error = error;
        return false;
    }
    if (live && !validate_live_session_binding(session->id, workspace, &live_binding, error)) {
        rollback_driver_activation(session->attached_pid, previous_driver_pid,
                                   attached_by_transaction, &live_binding.source_identity);
        if (out_error) *out_error = error;
        return false;
    }

    const auto selected = workspace_registry().select_for_ui(workspace->identity().binary_id());
    if (!selected) {
        error = selected.error().stable_code() + ": " + selected.error().message;
        if (live)
            rollback_driver_activation(session->attached_pid, previous_driver_pid,
                                       attached_by_transaction, &live_binding.source_identity);
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_error) *out_error = error;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (idx >= state().sessions.size() || state().sessions[idx] != session) {
            error = "session_changed_during_activation";
            state().last_error = error;
        } else {
            for (auto& candidate : state().sessions)
                candidate->ui_selected = false;
            session->ui_selected = true;
            session->last_active_steady_ms = now_steady_ms();
            state().active_idx = static_cast<int>(idx);
            state().last_error.clear();
            return true;
        }
    }
    if (live)
        rollback_driver_activation(session->attached_pid, previous_driver_pid,
                                   attached_by_transaction, &live_binding.source_identity);
    if (out_error) *out_error = error;
    return false;
}

bool may_detach_live_binding(std::uint32_t pid,
                             const std::optional<live_session_binding_t>& binding,
                             const char* reason)
{
    if (pid == 0 || !binding)
        return false;
    const auto validation = driver_bridge::identity::validate_live_target_identity(binding->source_identity);
    if (validation.matches)
        return true;
    diag::log_tagged_fmt("analysis_session",
        "live_session_detach_skipped reason=%s source_pid=%u process_creation_100ns=%llu module_base=0x%llX module_size=%llu capture_sha256=%s stale_code=%s detail=%s",
        reason, pid,
        static_cast<unsigned long long>(binding->source_identity.process.creation_time_100ns),
        static_cast<unsigned long long>(binding->source_identity.module.base),
        static_cast<unsigned long long>(binding->source_identity.module.size),
        binding->capture_hash.c_str(),
        driver_bridge::identity::staleness_code(validation.staleness),
        validation.detail.c_str());
    return false;
}

void close_workspace_async(std::shared_ptr<analysis_workspace_t> workspace,
                           std::uint32_t pid,
                           std::optional<live_session_binding_t> binding = {})
{
    auto fallback_workspace = workspace;
    auto fallback_binding = binding;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "analysis_session";
    submission.label = "analysis_session.close_workspace";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.target_pid = pid;
    submission.body = [workspace = std::move(workspace), pid, binding = std::move(binding)]() {
        if (workspace) {
            const auto workbench_closed =
                aida::workbench::workbench_shell_runtime_t::instance()
                    .close_analysis_workspace(workspace);
            if (!workbench_closed) {
                diag::log_tagged_fmt(
                    "analysis_session",
                    "workbench_close_failed binary_id=%s code=%u subject=%llu",
                    workspace->identity().binary_id().to_hex().c_str(),
                    static_cast<unsigned>(workbench_closed.code),
                    static_cast<unsigned long long>(workbench_closed.subject));
            }
            workspace->request_cancel();
            const auto closed = workspace_registry().close(workspace->identity().binary_id(),
                std::chrono::steady_clock::now() + std::chrono::seconds(10));
            if (!closed) {
                diag::log_tagged_fmt("analysis_session",
                    "workspace_close_failed binary_id=%s code=%s message=%s",
                    workspace->identity().binary_id().to_hex().c_str(),
                    closed.error().stable_code().c_str(), closed.error().message.c_str());
            }
        }
        if (may_detach_live_binding(pid, binding, "analysis_session.close")) {
            stealth_engine::disable_for_detach(pid, "analysis_session.close");
            (void)driver_bridge::detach_one(pid);
        }
    };
    if (!aida::infra::executor::submit(std::move(submission)).submitted) {
        if (fallback_workspace) {
            const auto workbench_closed =
                aida::workbench::workbench_shell_runtime_t::instance()
                    .close_analysis_workspace(fallback_workspace);
            if (!workbench_closed) {
                diag::log_tagged_fmt(
                    "analysis_session",
                    "workbench_close_fallback_failed binary_id=%s code=%u subject=%llu",
                    fallback_workspace->identity().binary_id().to_hex().c_str(),
                    static_cast<unsigned>(workbench_closed.code),
                    static_cast<unsigned long long>(workbench_closed.subject));
            }
            fallback_workspace->request_cancel();
            (void)workspace_registry().close(
                fallback_workspace->identity().binary_id(),
                std::chrono::steady_clock::now());
        }
        if (may_detach_live_binding(pid, fallback_binding, "analysis_session.close_submit_failed")) {
            stealth_engine::disable_for_detach(pid, "analysis_session.close_submit_failed");
            (void)driver_bridge::detach_one(pid);
        }
    }
}

void refresh_load_state(analysis_session_t& session)
{
    if (!session.workspace || session.load_state == session_load_state_t::closed)
        return;
    const auto progress = session.workspace->progress();
    if (progress.error) session.load_error = progress.error;
    switch (progress.readiness) {
    case workspace_readiness_t::baseline_ready:
    case workspace_readiness_t::partial:
        session.load_state = session_load_state_t::ready;
        break;
    case workspace_readiness_t::failed:
        session.load_state = session_load_state_t::failed;
        break;
    case workspace_readiness_t::closing:
    case workspace_readiness_t::cancelling:
        session.load_state = session_load_state_t::closing;
        break;
    case workspace_readiness_t::closed:
        session.load_state = session_load_state_t::closed;
        break;
    default:
        session.load_state = session_load_state_t::analyzing;
        break;
    }
}

session_summary_t make_summary(const analysis_session_t& session, bool active)
{
    session_summary_t summary;
    summary.id = session.id;
    summary.kind = session.attached_pid == 0
        ? session_kind_t::static_file
        : session_kind_t::live_attach;
    summary.path = session.path;
    summary.filename = session.filename;
    summary.pid = session.attached_pid;
    summary.process_name = narrow_utf8(session.process_name);
    summary.is_active = active;
    summary.is_alive = session.workspace
        ? !session.workspace->closed()
        : session.load_state != session_load_state_t::closed;
    summary.last_active_steady_ms = session.last_active_steady_ms;
    summary.load_state = session.load_state;
    summary.error = session.load_error;
    if (session.workspace) {
        const auto publication = session.workspace->analysis_publication();
        summary.binary_id = session.workspace->identity().binary_id().to_hex();
        summary.process_creation_time_100ns = session.workspace->identity().process()
            ? session.workspace->identity().process()->creation_time_100ns
            : 0;
        summary.analysis_revision = publication ? publication->analysis_revision : 0;
        summary.overlay_revision = session.workspace->overlay_revision();
        summary.readiness = session.workspace->progress().readiness;
    }
    if (session.pdb_state) {
        std::lock_guard<std::mutex> lock(session.pdb_state->mutex);
        if (!session.workspace ||
            session.pdb_state->workspace_generation == session.workspace->generation()) {
            summary.pdb_remote_pending = session.pdb_state->remote_pending;
            summary.pdb_local_pending = session.pdb_state->local_pending;
            summary.pdb_loading = session.pdb_state->loading;
            summary.pdb_failed = session.pdb_state->failed;
            summary.pdb_status = session.pdb_state->status;
            summary.pdb_bytes_received = session.pdb_state->bytes_received;
            summary.pdb_bytes_total = session.pdb_state->bytes_total;
            summary.pdb_progress_percent = session.pdb_state->progress_percent;
            if (session.pdb_state->parser_progress) {
                const int parser_percent = static_cast<int>((std::clamp)(
                    session.pdb_state->parser_progress->load(std::memory_order_acquire),
                    0.0f, 1.0f) * 100.0f);
                summary.pdb_progress_percent = (std::max)(
                    summary.pdb_progress_percent, parser_percent);
            }
        }
    }
    if (session.symbols) summary.symbol_revision = session.symbols->revision();
    return summary;
}

}

aida::analysis::workspace_result_t<static_workspace_acquisition_t>
acquire_static_workspace(const std::string& path,
                         const aida::analysis::cancellation_token_t& cancel)
{
    auto fail = [](workspace_error_t error) {
        return workspace_result_t<static_workspace_acquisition_t>::failure(
            std::move(error));
    };
    if (path.empty()) {
        return fail(make_workspace_error(workspace_error_code_t::invalid_argument,
            "Static workspace path is empty", "analysis_session.acquire_static"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                : workspace_error_code_t::cancelled,
            cancel.deadline_exceeded() ? "Static workspace acquisition deadline expired"
                : "Static workspace acquisition was cancelled",
            "analysis_session.acquire_static");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return fail(std::move(error));
    }
    baseline_analysis_settings_t settings;
    const auto& adaptive = adaptive_budget_fields();
    settings.max_analysis_memory_bytes = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    if (adaptive.low_memory) {
        const std::uint32_t hardware_lanes = std::thread::hardware_concurrency();
        settings.decode_worker_lanes = (std::clamp)(hardware_lanes / 2u, 2u, 8u);
        settings.overlap_strings_with_decode = false;
        diag::log_tagged_fmt("analysis_session",
            "adaptive_budget_low_memory decode_worker_lanes=%u overlap_strings_with_decode=0 hardware_concurrency=%u (memory budget overridden to 16GB default for settings compatibility)",
            settings.decode_worker_lanes, hardware_lanes);
    }
    open_static_workspace_request_t request;
    request.source_path = path;
    request.bin_name = derive_filename(path);
    const std::string profile = "aida-pe-workspace-engine-1|" +
        settings.canonical_json();
    request.load_profile.assign(profile.begin(), profile.end());
    auto opened = workspace_registry().open_static(request, cancel);
    if (!opened) return fail(opened.error());
    auto workspace = opened.take_value();
    auto gate = static_workspace_gate(workspace->identity().binary_id().to_hex());
    std::unique_lock<std::timed_mutex> gate_lock(*gate, std::defer_lock);
    while (!gate_lock.try_lock_for(std::chrono::milliseconds(10))) {
        if (cancel.stop_requested()) {
            auto error = make_workspace_error(
                cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                cancel.deadline_exceeded()
                    ? "Static workspace gate deadline expired"
                    : "Static workspace gate wait was cancelled",
                "analysis_session.acquire_static.gate");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return fail(std::move(error));
        }
        if (workspace->closing() || workspace->closed()) {
            return fail(make_workspace_error(workspace_error_code_t::workspace_closing,
                "Static workspace closed while waiting for its acquisition gate",
                "analysis_session.acquire_static.gate"));
        }
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                : workspace_error_code_t::cancelled,
            cancel.deadline_exceeded() ? "Static workspace acquisition deadline expired"
                : "Static workspace acquisition was cancelled",
            "analysis_session.acquire_static");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return fail(std::move(error));
    }
    if (workspace->closing() || workspace->closed()) {
        return fail(make_workspace_error(workspace_error_code_t::workspace_closing,
            "Static workspace is closing", "analysis_session.acquire_static"));
    }
    const bool had_services = workspace->database() != nullptr;
    std::shared_ptr<workspace_database_t> database;
    auto services = install_workspace_services(workspace, database);
    if (!services) return fail(services.error());
    auto progress = workspace->progress();
    static_workspace_acquisition_t result;
    result.workspace = workspace;
    result.joined_existing = had_services ||
        progress.readiness == workspace_readiness_t::analyzing ||
        progress.readiness == workspace_readiness_t::baseline_ready ||
        progress.readiness == workspace_readiness_t::partial;
    if (progress.readiness == workspace_readiness_t::analyzing ||
        progress.readiness == workspace_readiness_t::baseline_ready ||
        progress.readiness == workspace_readiness_t::partial) {
        return workspace_result_t<static_workspace_acquisition_t>::success(
            std::move(result));
    }
    diag::log_tagged("analysis_session", "acquire_static reopen_persisted begin");
    auto reopened = reopen_persisted_analysis(workspace, database, cancel);
    diag::log_tagged_fmt("analysis_session", "acquire_static reopen_persisted ok=%d value=%d",
        reopened ? 1 : 0, (reopened && reopened.value()) ? 1 : 0);
    if (!reopened) return fail(reopened.error());
    if (reopened.value()) {
        diag::log_tagged("analysis_session", "acquire_static skipping baseline (reopen returned true)");
        result.joined_existing = true;
        return workspace_result_t<static_workspace_acquisition_t>::success(
            std::move(result));
    }
    progress = workspace->progress();
    diag::log_tagged_fmt("analysis_session", "acquire_static readiness=%u after reopen",
        static_cast<unsigned>(progress.readiness));
    if (progress.readiness == workspace_readiness_t::analyzing ||
        progress.readiness == workspace_readiness_t::baseline_ready ||
        progress.readiness == workspace_readiness_t::partial) {
        diag::log_tagged("analysis_session", "acquire_static skipping baseline (already analyzing/ready)");
        result.joined_existing = true;
        return workspace_result_t<static_workspace_acquisition_t>::success(
            std::move(result));
    }
    diag::log_tagged("analysis_session", "acquire_static starting baseline_analysis_service_t::start");
    auto started = baseline_analysis_service_t::start(workspace, settings,
        cancel.deadline());
    diag::log_tagged_fmt("analysis_session", "acquire_static baseline start ok=%d",
        started ? 1 : 0);
    if (!started) {
        if (started.error().code == workspace_error_code_t::analysis_in_progress) {
            progress = workspace->progress();
            if (progress.readiness == workspace_readiness_t::analyzing ||
                progress.readiness == workspace_readiness_t::baseline_ready ||
                progress.readiness == workspace_readiness_t::partial) {
                result.joined_existing = true;
                return workspace_result_t<static_workspace_acquisition_t>::success(
                    std::move(result));
            }
        }
        return fail(started.error());
    }
    result.analysis_job = started.take_value();
    result.analysis_started = true;
    return workspace_result_t<static_workspace_acquisition_t>::success(
        std::move(result));
}

bool open_session(const std::string& path)
{
    if (path.empty()) {
        std::lock_guard<std::mutex> lock(state().mutex);
        state().last_error = "empty_path";
        return false;
    }
    std::string session_id;
    std::uint64_t load_generation = 0;
    cancellation_token_t cancel;
    bool existing_session = false;
    size_t existing_index = 0;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        for (size_t index = 0; index < state().sessions.size(); ++index) {
            if (!paths_equal(state().sessions[index]->path, path)) continue;
            existing_session = true;
            existing_index = index;
            break;
        }
        if (!existing_session) {
            if (state().sessions.size() >= kMaxSessions) {
                state().last_error = "session_limit";
                return false;
            }
            auto session = std::make_shared<analysis_session_t>();
            session->id = make_session_id(++state().id_counter);
            session->path = path;
            session->filename = derive_filename(path);
            session->session_name = session->filename;
            session->session_created_ms = now_steady_ms();
            session->last_active_steady_ms = now_steady_ms();
            session->ui_selected = true;
            session_id = session->id;
            load_generation = session->load_generation;
            cancel = session->load_cancellation.token();
            for (auto& existing_session : state().sessions)
                existing_session->ui_selected = false;
            state().sessions.push_back(std::move(session));
            state().active_idx = static_cast<int>(state().sessions.size()) - 1;
        }
    }
    if (existing_session) {
        return activate_session_transaction(existing_index, nullptr);
    }
    loading_binary_overlay::track_session(session_id, path,
        loading_binary_overlay::completion_action_t::switch_to_disassembly_or_hex);
    if (cancel.stop_requested()) {
        loading_binary_overlay::release_session(session_id);
        return false;
    }
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "analysis_session";
    submission.label = "analysis_session.open_static";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.body = [session_id, load_generation, path, cancel]() mutable {
        static_open_worker(std::move(session_id), load_generation,
            std::move(path), std::move(cancel));
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        auto error = make_workspace_error(workspace_error_code_t::provider_unavailable,
            "Static workspace open task was rejected", "analysis_session.open");
        error.details.emplace_back("reason", submitted.reject_reason);
        record_load_failure(session_id, load_generation, std::move(error));
        return false;
    }
    bool session_present = false;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        for (const auto& session : state().sessions) {
            if (session->id != session_id) continue;
            session_present = true;
            if (!session->workspace &&
                session->load_state == session_load_state_t::opening)
                session->open_task_id = submitted.task_id;
            break;
        }
    }
    if (!session_present) {
        (void)aida::infra::executor::cancel(submitted.task_id);
        loading_binary_overlay::release_session(session_id);
        return false;
    }
    return true;
}

bool open_attach_session(
    std::uint32_t pid,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel)
{
    std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex);
    const auto publish_cancellation = [&]() {
        if (!cancel.stop_requested())
            return false;
        const std::string error = cancel.deadline_exceeded()
            ? "deadline_exceeded" : "cancelled";
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_err) *out_err = error;
        return true;
    };
    if (publish_cancellation())
        return false;
    if (pid == 0 || pid == GetCurrentProcessId()) {
        const std::string error = pid == GetCurrentProcessId()
            ? "SELF_TARGET_REFUSED"
            : "invalid_pid";
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_err) *out_err = error;
        return false;
    }
    size_t existing = 0;
    if (find_session_by_pid(pid, &existing)) {
        const auto workspace = workspace_for_session(existing);
        std::string existing_session_id;
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            if (existing < state().sessions.size())
                existing_session_id = state().sessions[existing]->id;
        }
        std::string existing_error;
        if (!existing_session_id.empty() && validate_live_session_binding(
                existing_session_id, workspace, nullptr, existing_error)) {
            if (publish_cancellation())
                return false;
            const bool activated = activate_session_transaction(existing, out_err);
            if (!activated && out_err && out_err->empty()) *out_err = last_error();
            return activated;
        }
        if (!close_session(existing)) {
            const std::string error = "stale_session_close_failed";
            {
                std::lock_guard<std::mutex> lock(state().mutex);
                state().last_error = error;
            }
            if (out_err) *out_err = error;
            return false;
        }
        if (publish_cancellation())
            return false;
    }

    driver_bridge::identity::live_target_identity_t source_identity;
    std::string identity_error;
    if (!driver_bridge::identity::capture_live_target_identity(pid, 0, source_identity,
                                                               &identity_error)) {
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = identity_error;
        }
        if (out_err) *out_err = identity_error;
        return false;
    }
    if (publish_cancellation())
        return false;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (state().sessions.size() >= kMaxSessions) {
            state().last_error = "session_limit";
            if (out_err) *out_err = state().last_error;
            return false;
        }
    }
    const std::uint32_t previous_pid = driver_bridge::attached_pid();
    bool attached_by_transaction = false;
    std::string driver_error;
    if (!ensure_driver_active_for_session(pid, attached_by_transaction, driver_error,
                                          &source_identity)) {
        rollback_driver_activation(pid, previous_pid, attached_by_transaction, &source_identity);
        const std::string error = std::move(driver_error);
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_err) *out_err = error;
        return false;
    }
    auto rollback_attach = [previous_pid, pid, attached_by_transaction, source_identity](
        const std::shared_ptr<analysis_workspace_t>& workspace = {}) {
        if (workspace) {
            static_cast<void>(
                aida::workbench::workbench_shell_runtime_t::instance()
                    .close_analysis_workspace(workspace));
            workspace->request_cancel();
            (void)workspace_registry().close(workspace->identity().binary_id(),
                std::chrono::steady_clock::now() + std::chrono::seconds(2));
        }
        rollback_driver_activation(pid, previous_pid, attached_by_transaction, &source_identity);
    };
    if (publish_cancellation()) {
        rollback_attach();
        return false;
    }
    bool is_64_bit = true;
    if (!inspect_live_pe(pid, source_identity.module.base, is_64_bit)) {
        const std::string error = "MALFORMED_PE: live module header is invalid";
        if (out_err) *out_err = error;
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        rollback_attach();
        return false;
    }
    if (publish_cancellation()) {
        rollback_attach();
        return false;
    }
    open_live_workspace_request_t request;
    request.bin_name = source_identity.module.normalized_name;
    request.snapshot.pid = pid;
    request.snapshot.module_base = source_identity.module.base;
    request.snapshot.module_size = source_identity.module.size;
    request.snapshot.module_name = source_identity.module.normalized_name;
    request.snapshot.module_path = source_identity.module.normalized_path;
    request.snapshot.capture_address.space = aida::analysis::address_space_id_t::live_virtual;
    request.snapshot.capture_address.value = source_identity.module.base;
    request.snapshot.capture_address.architecture = is_64_bit
        ? aida::analysis::architecture_id_t::x86_64
        : aida::analysis::architecture_id_t::x86;
    request.snapshot.capture_address.mode = is_64_bit
        ? aida::analysis::architecture_mode_t::x86_64
        : aida::analysis::architecture_mode_t::x86_32;
    request.snapshot.capture_size = (std::min<std::uint64_t>)(source_identity.module.size,
                                                               4ull * 1024ull * 1024ull);
    request.snapshot.maximum_capture_size = 4ull * 1024ull * 1024ull;
    request.format = is_64_bit
        ? aida::analysis::format_id_t::pe32_plus
        : aida::analysis::format_id_t::pe32;
    request.architecture = request.snapshot.capture_address.architecture;
    request.abi = is_64_bit
        ? aida::analysis::abi_id_t::windows_x64
        : aida::analysis::abi_id_t::windows_x86;
    request.image_base = source_identity.module.base;
    const std::string profile = "aida-live-header-snapshot-v1";
    request.capture_profile.assign(profile.begin(), profile.end());
    auto opened = workspace_registry().open_live(request);
    if (!opened) {
        const std::string error = opened.error().stable_code() + ": " + opened.error().message;
        if (out_err) *out_err = error;
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        rollback_attach();
        return false;
    }
    auto workspace = opened.take_value();
    if (publish_cancellation()) {
        rollback_attach(workspace);
        return false;
    }
    std::shared_ptr<workspace_database_t> database;
    auto services = install_workspace_services(workspace, database);
    if (!services) {
        const std::string error = services.error().stable_code() + ": " + services.error().message;
        if (out_err) *out_err = error;
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        rollback_attach(workspace);
        return false;
    }
    if (publish_cancellation()) {
        rollback_attach(workspace);
        return false;
    }
    live_session_binding_t binding;
    std::string binding_error;
    if (!make_live_session_binding(source_identity, workspace, binding, binding_error)) {
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = binding_error;
        }
        if (out_err) *out_err = binding_error;
        rollback_attach(workspace);
        return false;
    }
    if (publish_cancellation()) {
        rollback_attach(workspace);
        return false;
    }
    const auto current_identity = driver_bridge::identity::validate_live_target_identity(
        source_identity);
    const auto provider = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
        workspace->provider_handle());
    const auto provider_identity = provider
        ? provider->validate_current_identity()
        : workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_stale,
            "Live workspace has no immutable snapshot provider",
            "analysis_session.open_attach"));
    if (!current_identity.matches || !provider_identity) {
        const std::string error = !current_identity.matches
            ? std::string(driver_bridge::identity::staleness_code(current_identity.staleness)) +
                ": " + current_identity.detail
            : provider_identity.error().stable_code() + ": " + provider_identity.error().message;
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_err) *out_err = error;
        rollback_attach(workspace);
        return false;
    }
    if (publish_cancellation()) {
        rollback_attach(workspace);
        return false;
    }
    diag::log_tagged("analysis_session", "open_attach workbench attach begin");
    {
        aida::workbench::workbench_shell_workspace_context_t workbench_context;
        const auto workbench_attached =
            aida::workbench::workbench_shell_runtime_t::instance()
                .attach_analysis_workspace(workspace, workbench_context);
        diag::log_tagged_fmt("analysis_session", "open_attach workbench attach done ok=%d", workbench_attached ? 1 : 0);
        if (!workbench_attached) {
            diag::log_tagged_fmt(
                "analysis_session",
                "live_workbench_attach_deferred pid=%u binary_id=%s code=%u subject=%llu",
                pid, workspace->identity().binary_id().to_hex().c_str(),
                static_cast<unsigned>(workbench_attached.code),
                static_cast<unsigned long long>(workbench_attached.subject));
        }
    }
    diag::log_tagged("analysis_session", "open_attach session create begin");
    auto session = std::make_shared<analysis_session_t>();
    bool session_limit_reached = false;
    size_t session_index = static_cast<size_t>(-1);
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (state().sessions.size() >= kMaxSessions) {
            state().last_error = "session_limit";
            session_limit_reached = true;
        } else {
            session->id = make_session_id(++state().id_counter);
            session->attached_pid = pid;
            session->process_name = widen_utf8(
                derive_filename(source_identity.process.normalized_process_path));
            session->filename = request.bin_name.empty()
                ? "PID " + std::to_string(pid)
                : request.bin_name;
            session->session_name = session->filename;
            session->session_created_ms = now_steady_ms();
            session->path = "live://pid/" + std::to_string(pid);
            session->last_active_steady_ms = now_steady_ms();
            session->ui_selected = false;
            session->workspace = workspace;
            session->symbols = std::make_shared<symbol_store::workspace_state_t>(
                workspace->identity().binary_id());
            session->load_state = session_load_state_t::ready;
            state().sessions.push_back(session);
            state().live_bindings.emplace(session->id, binding);
            session_index = state().sessions.size() - 1;
        }
    }
    if (session_limit_reached) {
        if (out_err) *out_err = "session_limit";
        rollback_attach(workspace);
        return false;
    }
    if (publish_cancellation()) {
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            const auto iterator = std::find(state().sessions.begin(), state().sessions.end(), session);
            if (iterator != state().sessions.end())
                state().sessions.erase(iterator);
            state().live_bindings.erase(session->id);
        }
        rollback_attach(workspace);
        return false;
    }
    std::string activation_error;
    diag::log_tagged("analysis_session", "open_attach activate_session begin");
    if (!activate_session_transaction(session_index, &activation_error)) {
        diag::log_tagged_fmt("analysis_session", "open_attach activate_session failed error='%s'", activation_error.c_str());
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            const auto iterator = std::find(state().sessions.begin(), state().sessions.end(), session);
            if (iterator != state().sessions.end())
                state().sessions.erase(iterator);
            state().live_bindings.erase(session->id);
            state().last_error = activation_error;
        }
        if (out_err) *out_err = activation_error;
        rollback_attach(workspace);
        return false;
    }
    diag::log_tagged("analysis_session", "open_attach activate_session done");
    const bool stealth = stealth_engine::ensure_default_enabled(pid,
        "analysis_session.open_attach");
    diag::log_tagged_fmt("analysis_session", "open_attach stealth done stealth=%d", stealth ? 1 : 0);
    diag::log_tagged_fmt("analysis_session",
        "open_attach_session session=%s source_pid=%u process_creation_100ns=%llu process_path=%s module_name=%s module_path=%s module_base=0x%llX module_size=%llu capture_time_100ns=%llu capture_size=%llu capture_sha256=%s staleness=NONE stealth=%d",
        session->id.c_str(), pid,
        static_cast<unsigned long long>(binding.source_identity.process.creation_time_100ns),
        binding.source_identity.process.normalized_process_path.c_str(),
        binding.source_identity.module.normalized_name.c_str(),
        binding.source_identity.module.normalized_path.c_str(),
        static_cast<unsigned long long>(binding.source_identity.module.base),
        static_cast<unsigned long long>(binding.source_identity.module.size),
        static_cast<unsigned long long>(binding.capture_time_100ns),
        static_cast<unsigned long long>(binding.capture_size), binding.capture_hash.c_str(),
        stealth ? 1 : 0);
    return true;
}

bool reattach_session_exact(
    const std::string& session_id,
    std::uint32_t expected_pid,
    std::uint64_t expected_process_creation_time_100ns,
    std::string* out_err,
    const aida::analysis::cancellation_token_t& cancel)
{
    std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex);
    const auto fail = [&](std::string error) {
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = error;
        }
        if (out_err) *out_err = std::move(error);
        return false;
    };
    if (cancel.stop_requested())
        return fail(cancel.deadline_exceeded() ? "deadline_exceeded" : "cancelled");
    if (session_id.empty() || expected_pid == 0 ||
        expected_process_creation_time_100ns == 0)
        return fail("TARGET_STALE: retained live-session identity is incomplete");

    std::size_t session_index = static_cast<std::size_t>(-1);
    std::shared_ptr<analysis_session_t> session;
    live_session_binding_t binding;
    bool binding_found = false;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        for (std::size_t index = 0; index < state().sessions.size(); ++index) {
            if (!state().sessions[index] || state().sessions[index]->id != session_id)
                continue;
            session_index = index;
            session = state().sessions[index];
            break;
        }
        if (session) {
            const auto binding_it = state().live_bindings.find(session_id);
            if (binding_it != state().live_bindings.end()) {
                binding = binding_it->second;
                binding_found = true;
            }
        }
    }
    if (!session)
        return fail("session_not_found");
    if (!binding_found)
        return fail("TARGET_STALE: retained live-session identity binding is missing");
    if (session->attached_pid != expected_pid || !session->workspace ||
        binding.source_identity.process.pid != expected_pid ||
        binding.source_identity.process.creation_time_100ns !=
            expected_process_creation_time_100ns)
        return fail("TARGET_STALE: retained process identity does not match the session");

    std::string validation_error;
    live_session_binding_t validated_binding;
    if (!validate_live_session_binding(session_id, session->workspace,
            &validated_binding, validation_error))
        return fail(validation_error.empty()
            ? "TARGET_STALE: retained process identity validation failed"
            : std::move(validation_error));
    if (validated_binding.source_identity.process.pid != expected_pid ||
        validated_binding.source_identity.process.creation_time_100ns !=
            expected_process_creation_time_100ns)
        return fail("TARGET_STALE: live process identity changed before reattach");
    if (cancel.stop_requested())
        return fail(cancel.deadline_exceeded() ? "deadline_exceeded" : "cancelled");

    std::string activation_error;
    if (!activate_session_transaction(session_index, &activation_error))
        return fail(activation_error.empty() ? "session_reattach_failed" : activation_error);
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        state().last_error.clear();
    }
    if (out_err) out_err->clear();
    return true;
}

bool switch_session(size_t idx)
{
    return activate_session_transaction(idx, nullptr);
}

bool cancel_session(size_t idx)
{
    std::shared_ptr<analysis_workspace_t> workspace;
    std::optional<std::uint64_t> open_task_id;
    std::optional<aida::infra::taskflow_runtime::job_handle_t> baseline_job;
    std::optional<std::uint64_t> pdb_task_id;
    std::shared_ptr<std::atomic<bool>> pdb_cancel;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (idx >= state().sessions.size()) {
            state().last_error = "idx_out_of_range";
            return false;
        }
        auto& session = *state().sessions[idx];
        session.load_cancellation.request_cancel();
        if (session.load_generation != UINT64_MAX)
            ++session.load_generation;
        workspace = session.workspace;
        open_task_id = session.open_task_id;
        baseline_job = session.baseline_job;
        session.open_task_id.reset();
        session.baseline_job.reset();
        if (!workspace) {
            auto error = make_workspace_error(workspace_error_code_t::cancelled,
                "Workspace open was cancelled", "analysis_session.cancel");
            error.cancellation = true;
            session.load_state = session_load_state_t::failed;
            session.load_error = error;
            state().last_error = error.stable_code() + ": " + error.message;
        }
        if (session.pdb_state) {
            std::lock_guard<std::mutex> pdb_lock(session.pdb_state->mutex);
            auto& prompt = *session.pdb_state;
            pdb_cancel = prompt.parser_cancel;
            pdb_task_id = prompt.task_id;
            if (prompt.committing) {
                prompt.status = "Finishing PDB publication before session cancellation";
            } else {
                if (prompt.generation != UINT64_MAX) ++prompt.generation;
                prompt.loading = false;
                prompt.parser_cancel.reset();
                prompt.parser_progress.reset();
                prompt.task_id.reset();
                prompt.status = "PDB operation cancelled with session";
            }
            prompt.remote_pending = false;
            prompt.local_pending = false;
        }
    }
    if (pdb_cancel) pdb_cancel->store(true, std::memory_order_release);
    if (pdb_task_id) (void)aida::infra::executor::cancel(*pdb_task_id);
    if (open_task_id) (void)aida::infra::executor::cancel(*open_task_id);
    if (baseline_job) (void)aida::infra::taskflow_runtime::cancel(*baseline_job);
    if (workspace) workspace->request_cancel();
    return true;
}

bool close_session(size_t idx)
{
    std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex);
    std::shared_ptr<analysis_workspace_t> workspace;
    std::uint32_t pid = 0;
    std::optional<std::uint64_t> open_task_id;
    std::optional<aida::infra::taskflow_runtime::job_handle_t> baseline_job;
    std::optional<std::uint64_t> pdb_task_id;
    std::shared_ptr<std::atomic<bool>> pdb_cancel;
    std::string session_id;
    std::optional<live_session_binding_t> live_binding;
    std::optional<size_t> successor_index;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        if (idx >= state().sessions.size()) {
            state().last_error = "idx_out_of_range";
            return false;
        }
        auto session = state().sessions[idx];
        session->load_cancellation.request_cancel();
        if (session->load_generation != UINT64_MAX)
            ++session->load_generation;
        session->load_state = session_load_state_t::closing;
        workspace = session->workspace;
        pid = session->attached_pid;
        session_id = session->id;
        const auto binding = state().live_bindings.find(session_id);
        if (binding != state().live_bindings.end())
            live_binding = binding->second;
        open_task_id = session->open_task_id;
        baseline_job = session->baseline_job;
        if (session->pdb_state) {
            std::lock_guard<std::mutex> pdb_lock(session->pdb_state->mutex);
            pdb_cancel = session->pdb_state->parser_cancel;
            pdb_task_id = session->pdb_state->task_id;
            if (session->pdb_state->generation != UINT64_MAX)
                ++session->pdb_state->generation;
            session->pdb_state->loading = false;
            session->pdb_state->remote_pending = false;
            session->pdb_state->local_pending = false;
            session->pdb_state->status = "PDB operation cancelled with session close";
            session->pdb_state->parser_cancel.reset();
            session->pdb_state->parser_progress.reset();
            session->pdb_state->task_id.reset();
        }
        const bool was_active = state().active_idx == static_cast<int>(idx);
        state().sessions.erase(state().sessions.begin() + static_cast<std::ptrdiff_t>(idx));
        state().live_bindings.erase(session_id);
        if (state().sessions.empty()) {
            state().active_idx = -1;
        } else if (was_active) {
            state().active_idx = -1;
            for (auto& s : state().sessions)
                s->ui_selected = false;
            successor_index = (std::min)(idx, state().sessions.size() - 1);
        } else if (state().active_idx > static_cast<int>(idx)) {
            --state().active_idx;
        }
    }
    if (pdb_cancel) pdb_cancel->store(true, std::memory_order_release);
    if (pdb_task_id) (void)aida::infra::executor::cancel(*pdb_task_id);
    if (open_task_id) (void)aida::infra::executor::cancel(*open_task_id);
    if (baseline_job) (void)aida::infra::taskflow_runtime::cancel(*baseline_job);
    loading_binary_overlay::release_session(session_id);
    close_workspace_async(std::move(workspace), pid, std::move(live_binding));
    if (successor_index) {
        std::string activation_error;
        if (!activate_session_transaction(*successor_index, &activation_error)) {
            std::lock_guard<std::mutex> lock(state().mutex);
            state().last_error = activation_error;
        }
    }
    return true;
}

size_t active_session_idx()
{
    std::lock_guard<std::mutex> lock(state().mutex);
    return state().active_idx < 0
        ? static_cast<size_t>(-1)
        : static_cast<size_t>(state().active_idx);
}

size_t session_count()
{
    std::lock_guard<std::mutex> lock(state().mutex);
    return state().sessions.size();
}

std::shared_ptr<const analysis_session_t> session_handle_at(size_t idx)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    if (idx >= state().sessions.size()) return {};
    refresh_load_state(*state().sessions[idx]);
    return std::make_shared<const analysis_session_t>(*state().sessions[idx]);
}

const analysis_session_t* session_at(size_t idx)
{
    thread_local std::shared_ptr<const analysis_session_t> snapshot;
    snapshot = session_handle_at(idx);
    return snapshot.get();
}

std::shared_ptr<analysis_workspace_t> active_workspace()
{
    std::lock_guard<std::mutex> lock(state().mutex);
    if (state().active_idx < 0 ||
        state().active_idx >= static_cast<int>(state().sessions.size()))
        return {};
    return state().sessions[static_cast<size_t>(state().active_idx)]->workspace;
}

bool try_active_workspace(std::shared_ptr<analysis_workspace_t>& output)
{
    auto& current = state();
    std::unique_lock<std::mutex> lock(current.mutex, std::try_to_lock);
    if (!lock.owns_lock())
        return false;
    if (current.active_idx < 0 ||
        current.active_idx >= static_cast<int>(current.sessions.size())) {
        output.reset();
        return true;
    }
    output = current.sessions[static_cast<size_t>(current.active_idx)]->workspace;
    return true;
}

std::shared_ptr<analysis_workspace_t> workspace_for_session(size_t idx)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    return idx < state().sessions.size() ? state().sessions[idx]->workspace : nullptr;
}

std::shared_ptr<analysis_workspace_t>
workspace_for_session_id(const std::string& session_id)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    for (const auto& session : state().sessions) {
        if (session->id == session_id) return session->workspace;
    }
    return {};
}

std::shared_ptr<symbol_store::workspace_state_t> symbols_for_workspace(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace) return {};
    std::lock_guard<std::mutex> lock(state().mutex);
    for (const auto& session : state().sessions) {
        if (session->workspace != workspace || !session->symbols) continue;
        if (session->symbols->binary_id() != workspace->identity().binary_id())
            return {};
        return session->symbols;
    }
    return {};
}

workspace_result_t<pdb_prompt_snapshot_t> pdb_prompt_snapshot(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto binding = pdb_binding_for_workspace(workspace);
    if (!binding) {
        return workspace_result_t<pdb_prompt_snapshot_t>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                "PDB state requires an open workspace session",
                "analysis_session.pdb_snapshot"));
    }
    {
        std::lock_guard<std::mutex> lock(binding->prompt->mutex);
        if (binding->prompt->workspace_generation != workspace->generation()) {
            return workspace_result_t<pdb_prompt_snapshot_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "PDB prompt generation does not match the workspace",
                    "analysis_session.pdb_snapshot"));
        }
    }
    pdb_prompt_snapshot_t output;
    {
        std::lock_guard<std::mutex> lock(binding->prompt->mutex);
        output.binary_id = binding->prompt->binary_id.to_hex();
        output.remote_pending = binding->prompt->remote_pending;
        output.local_pending = binding->prompt->local_pending;
        output.loading = binding->prompt->loading;
        output.failed = binding->prompt->failed;
        output.declined = binding->prompt->declined;
        output.load_types = binding->prompt->load_types;
        output.load_names = binding->prompt->load_names;
        output.module_name = binding->prompt->module_name;
        output.pdb_name = binding->prompt->pdb_name;
        output.pdb_guid = binding->prompt->pdb_guid;
        output.pdb_age = binding->prompt->pdb_age;
        output.symbol_server = binding->prompt->symbol_server;
        output.local_candidate = binding->prompt->local_candidate;
        output.reason = binding->prompt->reason;
        output.status = binding->prompt->status;
        output.bytes_received = binding->prompt->bytes_received;
        output.bytes_total = binding->prompt->bytes_total;
        output.progress_percent = binding->prompt->progress_percent;
        if (binding->prompt->parser_progress) {
            const int parser_percent = static_cast<int>((std::clamp)(
                binding->prompt->parser_progress->load(std::memory_order_acquire),
                0.0f, 1.0f) * 100.0f);
            output.progress_percent = (std::max)(output.progress_percent,
                parser_percent);
        }
    }
    output.symbol_revision = binding->symbols->revision();
    return workspace_result_t<pdb_prompt_snapshot_t>::success(std::move(output));
}

workspace_result_t<void> approve_remote_pdb(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    bool load_types, bool load_names)
{
    pdb_task_request_t request;
    request.remote = true;
    request.load_types = load_types;
    request.load_names = load_names;
    return submit_pdb_task(workspace, std::move(request));
}

workspace_result_t<void> approve_local_pdb(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::string& path, bool load_types, bool load_names)
{
    if (path.empty() || path.size() > 32768 || path.find('\0') != std::string::npos) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "Local PDB path is empty or exceeds the path budget",
            "analysis_session.pdb_local"));
    }
    pdb_task_request_t request;
    request.load_types = load_types;
    request.load_names = load_names;
    request.local_path = path;
    return submit_pdb_task(workspace, std::move(request));
}

workspace_result_t<void> decline_remote_pdb(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto binding = pdb_binding_for_workspace(workspace);
    if (!binding) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "PDB state requires an open workspace session",
            "analysis_session.pdb_remote_decline"));
    }
    std::lock_guard<std::mutex> lock(binding->prompt->mutex);
    if (binding->prompt->loading) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::analysis_in_progress,
            "A PDB operation is already active for this workspace",
            "analysis_session.pdb_remote_decline"));
    }
    binding->prompt->remote_pending = false;
    binding->prompt->local_pending = !binding->prompt->pdb_name.empty();
    binding->prompt->failed = false;
    binding->prompt->declined = true;
    binding->prompt->status = binding->prompt->local_pending
        ? "Remote PDB declined; awaiting a local PDB path"
        : "Remote PDB declined";
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decline_local_pdb(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto binding = pdb_binding_for_workspace(workspace);
    if (!binding) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "PDB state requires an open workspace session",
            "analysis_session.pdb_local_decline"));
    }
    std::lock_guard<std::mutex> lock(binding->prompt->mutex);
    if (binding->prompt->loading) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::analysis_in_progress,
            "A PDB operation is already active for this workspace",
            "analysis_session.pdb_local_decline"));
    }
    binding->prompt->local_pending = false;
    binding->prompt->failed = false;
    binding->prompt->declined = true;
    binding->prompt->status = "Local PDB selection declined";
    return workspace_result_t<void>::success();
}

workspace_result_t<void> cancel_pdb(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto binding = pdb_binding_for_workspace(workspace);
    if (!binding) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "PDB state requires an open workspace session",
            "analysis_session.pdb_cancel"));
    }
    std::shared_ptr<std::atomic<bool>> cancel;
    std::optional<std::uint64_t> task_id;
    {
        std::lock_guard<std::mutex> lock(binding->prompt->mutex);
        if (!binding->prompt->loading) return workspace_result_t<void>::success();
        cancel = binding->prompt->parser_cancel;
        task_id = binding->prompt->task_id;
        if (binding->prompt->committing) {
            binding->prompt->status = "Finishing PDB publication";
        } else {
            if (binding->prompt->generation != UINT64_MAX)
                ++binding->prompt->generation;
            binding->prompt->loading = false;
            binding->prompt->failed = false;
            binding->prompt->remote_pending = binding->prompt->operation_remote;
            binding->prompt->local_pending = !binding->prompt->operation_remote;
            binding->prompt->status = "PDB operation cancelled";
            binding->prompt->parser_cancel.reset();
            binding->prompt->parser_progress.reset();
            binding->prompt->task_id.reset();
        }
    }
    if (cancel) cancel->store(true, std::memory_order_release);
    if (task_id) (void)aida::infra::executor::cancel(*task_id);
    return workspace_result_t<void>::success();
}

bool find_session_by_path(const std::string& path, size_t* out_idx)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    for (size_t index = 0; index < state().sessions.size(); ++index) {
        if (!paths_equal(state().sessions[index]->path, path)) continue;
        if (out_idx) *out_idx = index;
        return true;
    }
    return false;
}

bool find_session_by_pid(std::uint32_t pid, size_t* out_idx)
{
    if (pid == 0) return false;
    std::lock_guard<std::mutex> lock(state().mutex);
    for (size_t index = 0; index < state().sessions.size(); ++index) {
        const auto& session = state().sessions[index];
        if (session->attached_pid != pid) continue;
        if (session->workspace && session->workspace->identity().process() &&
            session->workspace->identity().process()->pid != pid)
            continue;
        if (out_idx) *out_idx = index;
        return true;
    }
    return false;
}

bool find_session_by_id(const std::string& session_id, size_t* out_idx)
{
    if (session_id.empty()) return false;
    std::lock_guard<std::mutex> lock(state().mutex);
    for (size_t index = 0; index < state().sessions.size(); ++index) {
        const auto& session = state().sessions[index];
        const bool matches_session = session->id == session_id;
        const bool matches_binary = session->workspace &&
            session->workspace->identity().binary_id().to_hex() == session_id;
        if (!matches_session && !matches_binary) continue;
        if (out_idx) *out_idx = index;
        return true;
    }
    return false;
}

bool active_live_session_matches(std::uint32_t pid, const std::string& session_id)
{
    if (pid == 0 || session_id.empty()) return false;
    std::lock_guard<std::mutex> lock(state().mutex);
    if (state().active_idx < 0 ||
        static_cast<size_t>(state().active_idx) >= state().sessions.size())
        return false;
    const auto& session = state().sessions[static_cast<size_t>(state().active_idx)];
    if (!session || session->attached_pid != pid || session->id != session_id ||
        session->load_state != session_load_state_t::ready || !session->workspace)
        return false;
    const auto process_identity = session->workspace->identity().process();
    return process_identity && process_identity->pid == pid;
}

void prune_lru(size_t max_keep)
{
    if (max_keep == 0) max_keep = 1;
    for (;;) {
        size_t victim = static_cast<size_t>(-1);
        {
            std::lock_guard<std::mutex> lock(state().mutex);
            if (state().sessions.size() <= max_keep) return;
            std::uint64_t oldest = (std::numeric_limits<std::uint64_t>::max)();
            for (size_t index = 0; index < state().sessions.size(); ++index) {
                if (state().active_idx == static_cast<int>(index)) continue;
                if (state().sessions[index]->last_active_steady_ms >= oldest) continue;
                oldest = state().sessions[index]->last_active_steady_ms;
                victim = index;
            }
        }
        if (victim == static_cast<size_t>(-1) || !close_session(victim)) return;
    }
}

const char* last_error()
{
    thread_local std::string snapshot;
    std::lock_guard<std::mutex> lock(state().mutex);
    snapshot = state().last_error;
    return snapshot.c_str();
}

bool has_active_target()
{
    return active_workspace() != nullptr;
}

std::vector<session_summary_t> list_session_summaries()
{
    std::vector<session_summary_t> result;
    std::lock_guard<std::mutex> lock(state().mutex);
    result.reserve(state().sessions.size());
    for (size_t index = 0; index < state().sessions.size(); ++index) {
        refresh_load_state(*state().sessions[index]);
        result.push_back(make_summary(*state().sessions[index],
            state().active_idx == static_cast<int>(index)));
    }
    return result;
}

session_summary_t summarize_session_at(size_t idx)
{
    std::lock_guard<std::mutex> lock(state().mutex);
    if (idx >= state().sessions.size()) return {};
    refresh_load_state(*state().sessions[idx]);
    return make_summary(*state().sessions[idx],
        state().active_idx == static_cast<int>(idx));
}

}

#endif
