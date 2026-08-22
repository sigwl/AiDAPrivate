#include "network_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_adapter.hpp"
#include "../../preview/studio_semantics.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_executor.hpp"
#else
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "executor_status.hpp"
#endif
#include "../ui/task_center.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/design_system.hpp"
#include "../ai/standalone_chat.hpp"
#include "standalone_driver.hpp"

#include "protocol_parser.hpp"
#include "mitm_proxy.hpp"
#include "flow_serializer.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_certificates.hpp"
#else
#include "cert_pin_bypass.hpp"
#include "cert_generator.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_ssl_keylog.hpp"
#else
#include "ssl_keylog.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_tools.hpp"
#else
#include "script_engine.hpp"
#include "decoder_pipeline.hpp"
#endif
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../ui/theme.hpp"
#include "../ui/clock.hpp"
#include "../ui/motion.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/metrics.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/no_target_overlay.hpp"
#include "../ui/responsive.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../helpers/helpers.h"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_services.hpp"
#else
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../session/analysis_session.hpp"
#endif

#include "burp/burp_module.hpp"
#include "burp/site_map.hpp"
#include "burp/scope.hpp"
#include "burp/cookie_jar.hpp"
#include "burp/scanner_view.hpp"
#include "burp/issue.hpp"
#include "burp/recon_view.hpp"
#include "burp/intruder_view.hpp"
#include "burp/collaborator_view.hpp"
#include "burp/sequencer_view.hpp"
#include "burp/comparer_view.hpp"
#include "burp/comparer.hpp"
#include "burp/jwt_lab_view.hpp"
#include "burp/match_replace_view.hpp"
#include "burp/session_handler_view.hpp"
#include "burp/api_view.hpp"
#include "burp/ws_editor_view.hpp"
#include "burp/h2_editor_view.hpp"
#include "burp/burp_logger_view.hpp"
#include "burp/csp_view.hpp"
#include "burp/upstream_view.hpp"
#include "burp/browser_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_browser.hpp"
#else
#include "burp/browser_launch.hpp"
#endif
#include "burp/report_view.hpp"
#include "burp/headless_view.hpp"
#ifndef AIDA_IMGUI_STUDIO_PREVIEW
#include "burp/offensive/api_security_engine.hpp"
#include "burp/offensive/auth_attack_engine.hpp"
#include "burp/offensive/business_logic_engine.hpp"
#include "burp/offensive/client_attack_engine.hpp"
#include "burp/offensive/fuzzing_engine.hpp"
#include "burp/offensive/js_analysis_engine.hpp"
#include "burp/offensive/recon_engine.hpp"
#include "burp/offensive/server_attack_engine.hpp"
#include "burp/offensive/sqli_engine.hpp"
#include "burp/offensive/xss_engine.hpp"
#endif
#ifndef AIDA_IMGUI_STUDIO_PREVIEW
#include "intercept/cert_profile_manager.hpp"
#include "intercept/diagnostics.hpp"
#include "intercept/instrumentation_provider.hpp"
#include "intercept/script_handoff.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "human_request_editor.hpp"

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
#include "../workbench/workbench_shell_integration.hpp"
#endif

#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <charconv>
#include <climits>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <system_error>
#include <utility>
#include <vector>

#ifdef AIDA_IMGUI_STUDIO_PREVIEW
namespace network_open_dialog = aida::preview::network_dialog;
#else
namespace network_open_dialog = win32_dialog;
#endif

namespace network_view {

static constexpr std::size_t k_max_repeater_entries = 128;

using json = nlohmann::json;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
static std::string semantic_artifact_id(std::string_view kind,
                                        const artifact_identity_t& identity) {
    std::string retained = identity.id;
    retained.push_back(':');
    retained.append(std::to_string(identity.timestamp));
    retained.push_back(':');
    retained.append(std::to_string(identity.revision));
    retained.push_back(':');
    retained.append(std::to_string(identity.content_hash));
    retained.push_back(':');
    retained.append(std::to_string(identity.content_size));
    return aida::preview::semantics::stable_id(
        "aida.network", std::string(kind) + "-" +
            aida::preview::semantics::entity_token(retained));
}

static void register_network_last_item(const std::string& id,
                                       std::string_view type,
                                       std::string_view parent = {},
                                       bool disabled = false) {
    if (ImGui::IsItemVisible())
        aida::preview::semantics::register_last_item(
            id, type, false, disabled, parent);
}
#endif

static aida::ui::pill_kind_t tcp_state_to_pill(uint8_t st) {
    switch (st) {
        case 4:  return aida::ui::pill_kind_t::success;
        case 1:  return aida::ui::pill_kind_t::info;
        case 2:  return aida::ui::pill_kind_t::accent;
        case 3:  return aida::ui::pill_kind_t::accent;
        case 5:  return aida::ui::pill_kind_t::warning;
        case 6:  return aida::ui::pill_kind_t::warning;
        case 7:  return aida::ui::pill_kind_t::warning;
        case 8:  return aida::ui::pill_kind_t::warning;
        case 9:  return aida::ui::pill_kind_t::warning;
        case 10: return aida::ui::pill_kind_t::info;
        case 0:  return aida::ui::pill_kind_t::error;
        case 11: return aida::ui::pill_kind_t::error;
        default: return aida::ui::pill_kind_t::neutral;
    }
}

static ImU32 protocol_stripe_color(const std::string& label) {
    const auto& t = aida::ui::resolved();
    if (label == "HTTP") return t.info;
    if (label == "TLS")  return t.success;
    if (label == "DNS")  return t.warning;
    if (label == "QUIC") return t.accent_u32;
    if (label == "TCP")  return t.text_dim;
    if (label == "UDP")  return t.info_soft;
    return t.text_dim;
}

struct capture_row_snapshot_t {
    int packet_index = -1;
    uint64_t timestamp = 0;
    std::string src;
    std::string dst;
    std::string protocol_label;
    std::string summary;
};

struct capture_table_snapshot_t {
    size_t total_count = 0;
    int selected_index = -1;
    std::vector<capture_row_snapshot_t> rows;
};

struct capture_context_t {
    int packet_index = -1;
    uint64_t timestamp = 0;
    bool open_requested = false;
    aida::ui::context_menu_open_origin_t origin =
        aida::ui::context_menu_open_origin_t::pointer;
};

enum class network_exchange_action_t : std::uint8_t {
    repeater,
    fuzzer,
    intruder,
    scanner,
    comparer,
    compare_request_response,
    session_handling,
    cookies,
    match_replace,
    decoder,
    sequencer,
    camoufox,
    copy_url,
    copy_method,
    copy_status,
    copy_request,
    copy_response,
    copy_headers,
    copy_body,
    copy_artifact,
    scope_include,
    scope_exclude,
    save_export,
    create_issue,
    chat,
    agent,
    replay_live,
    remove
};

struct network_exchange_action_descriptor_t {
    network_exchange_action_t action;
    const char* id;
};

struct exchange_context_runtime_t {
    artifact_identity_t primary;
    artifact_identity_t related;
    bool primary_current = false;
    std::string unavailable_reason;
};

struct intercept_runtime_snapshot_t;

static bool execute_retained_exchange_toolbar_action(
    const char* action_id, artifact_identity_t primary,
    artifact_identity_t related, std::string& unavailable_reason);
static void reset_common_exchange_actions();

static capture_context_t s_capture_context;
static std::atomic<std::uint64_t> s_repeater_artifact_sequence{1};
static std::unordered_map<std::uint64_t, artifact_kind_t>
    s_repeater_selected_artifact_kinds;
static std::atomic<std::uint64_t> s_network_operation_sequence{1};
static std::atomic<bool> s_accept_ui_completions{false};
static std::mutex s_ui_completion_mutex;
static std::deque<std::function<void()>> s_ui_completions;

static std::uint64_t network_now_ms() {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return aida::preview::network::monotonic_ms();
#else
    return static_cast<std::uint64_t>(GetTickCount64());
#endif
}

struct operational_review_binding_t {
    bool prepared = false;
    operational_command_t command = operational_command_t::capture_start;
    std::size_t retained_count = 0;
    filter_entry_t retained_rule;
    std::vector<std::uint32_t> retained_rule_ids;
    std::vector<std::uint64_t> retained_exchange_ids;
    ssl_keylog::retained_set_token retained_keylog_token;
    int filter_action = 0;
    int filter_direction = 0;
    int filter_protocol = 0;
    std::string filter_pid;
    std::string filter_port;
    std::string filter_ip;
};

static operational_review_binding_t s_operational_review;

static bool invoke_global_network_action(const char* action_id) {
    return aida::ui::application_ui::execute_action(
        action_id, aida::ui::action_invocation_source_t::toolbar).executed();
}

static bool enqueue_ui_completion(std::function<void()> completion) {
    if (!completion || !s_accept_ui_completions.load(std::memory_order_acquire))
        return false;
    std::lock_guard<std::mutex> lock(s_ui_completion_mutex);
    if (!s_accept_ui_completions.load(std::memory_order_relaxed) || s_ui_completions.size() >= 256)
        return false;
    s_ui_completions.push_back(std::move(completion));
    return true;
}

static void drain_ui_completions() {
    std::deque<std::function<void()>> pending;
    {
        std::lock_guard<std::mutex> lock(s_ui_completion_mutex);
        const std::size_t count = (std::min)(s_ui_completions.size(), static_cast<std::size_t>(32));
        for (std::size_t i = 0; i < count; ++i) {
            pending.push_back(std::move(s_ui_completions.front()));
            s_ui_completions.pop_front();
        }
    }
    for (auto& completion : pending)
        completion();
}

static std::string register_network_operation(const char* action, const char* label,
                                              const char* owner_view, std::string target) {
    const std::string id = "network.operation." +
        std::to_string(s_network_operation_sequence.fetch_add(1, std::memory_order_acq_rel));
    aida::ui::task_center::task_registration_t registration;
    registration.id = id;
    registration.source = "human";
    registration.owner = "network";
    registration.owner_view = owner_view ? owner_view : "view.network.connections";
    registration.owner_action = action ? action : "network.operation";
    registration.target = std::move(target);
    registration.label = label ? label : "Network operation";
    registration.stage = "Queued";
    registration.progress = -1.0f;
    registration.cancellation_is_safe = false;
    registration.callbacks.focus = [view = registration.owner_view] {
        (void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(view));
    };
    if (!aida::ui::task_center::register_task(std::move(registration)))
        return {};
    return id;
}

static void finish_network_operation(const std::string& id, bool success,
                                     std::string stage, std::string summary) {
    if (id.empty())
        return;
    (void)aida::ui::task_center::update_task(
        id,
        success ? aida::ui::task_center::task_state_t::completed
                : aida::ui::task_center::task_state_t::failed,
        1.0f, std::move(stage), std::move(summary));
}

std::uint64_t artifact_content_hash(const std::vector<std::uint8_t>& bytes) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const std::uint8_t value : bytes) {
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint64_t>(bytes.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

static std::uint64_t artifact_hash(const std::vector<std::uint8_t>& bytes) {
    return artifact_content_hash(bytes);
}

static std::uint64_t artifact_hash(std::string_view text) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char character : text) {
        const auto value = static_cast<unsigned char>(character);
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint64_t>(text.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

static artifact_identity_t exchange_artifact_identity(const mitm_proxy::http_exchange& exchange,
                                                       artifact_kind_t kind) {
    artifact_identity_t identity;
    identity.kind = kind;
    identity.source_id = exchange.id;
    identity.timestamp = exchange.timestamp;
    identity.target_host = exchange.target_host;
    identity.target_port = exchange.target_port;
    identity.use_tls = exchange.is_tls;
    identity.parent_id = "network.exchange." + std::to_string(exchange.id);
    const bool response = kind == artifact_kind_t::response;
    identity.id = identity.parent_id + (response ? ".response" : ".request");
    identity.source_view_id = kind == artifact_kind_t::intercept_request
        ? "view.network.intercept" : "view.network.proxy";
    identity.label = std::string(response ? "Response #" : "Request #") + std::to_string(exchange.id);
    const auto& bytes = response ? exchange.raw_response : exchange.raw_request;
    identity.content_size = bytes.size();
    identity.content_hash = artifact_hash(bytes);
    return identity;
}

static artifact_identity_t repeater_artifact_identity(const repeater_entry_t& entry,
                                                       artifact_kind_t kind) {
    artifact_identity_t identity;
    const bool response = kind == artifact_kind_t::repeater_response;
    identity.kind = kind;
    identity.source_id = entry.id;
    identity.timestamp = response ? entry.response_timestamp : 0;
    identity.revision = entry.request_revision;
    identity.target_host = entry.host;
    identity.target_port = entry.port;
    identity.use_tls = entry.use_tls;
    identity.parent_id = entry.source_artifact_id;
    identity.session_id = entry.source_session_id;
    identity.id = "network.repeater." + std::to_string(entry.id) +
        (response ? ".response." + std::to_string(entry.response_timestamp)
                  : ".request." + std::to_string(entry.request_revision));
    identity.source_view_id = "view.network.repeater";
    identity.label = std::string(response ? "Repeater response #" : "Repeater request #") +
        std::to_string(entry.id);
    const std::string& text = response ? entry.raw_response : entry.raw_request;
    identity.content_size = text.size();
    const std::uint64_t retained_hash = response
        ? entry.response_hash : entry.request_hash;
    identity.content_hash = text.empty() ? 0
        : retained_hash != 0 ? retained_hash : artifact_hash(std::string_view(text));
    return identity;
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
struct network_selection_publication_t {
    std::weak_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::uint64_t workspace_generation = 0;
    aida::workbench::document_id_t document;
    std::string entity_key;
    std::string source_view_id;
    std::string analysis_session_id;
    std::string binary_id;
};

static network_selection_publication_t s_network_selection_publication;

struct network_artifact_workspace_binding_t {
    std::string analysis_session_id;
    std::string binary_id;
};

static std::unordered_map<std::string, network_artifact_workspace_binding_t>
    s_network_artifact_workspace_bindings;
static constexpr std::size_t k_max_network_artifact_workspace_bindings = 4096;

static std::string network_analysis_session_id(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    if (!workspace)
        return {};
    const auto count = analysis_session::session_count();
    for (std::size_t index = 0; index < count; ++index) {
        const auto session = analysis_session::session_handle_at(index);
        if (session && session->workspace == workspace)
            return session->id;
    }
    return {};
}

static std::string network_artifact_binding_key(const artifact_identity_t& identity) {
    std::string key;
    key.reserve(identity.source_view_id.size() + identity.parent_id.size() + identity.id.size() + 48);
    key.append(identity.source_view_id);
    key.push_back('|');
    key.append(identity.session_id);
    key.push_back('|');
    key.append(identity.parent_id.empty() ? identity.id : identity.parent_id);
    key.push_back('|');
    key.append(std::to_string(identity.source_id));
    key.push_back('|');
    key.append(std::to_string(
        identity.kind == artifact_kind_t::repeater_request ||
        identity.kind == artifact_kind_t::repeater_response
            ? 0 : identity.timestamp));
    return key;
}

static bool bind_network_artifact_workspace(
    const artifact_identity_t& identity,
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    std::string& session_id,
    std::string& binary_id) {
    if (!workspace)
        return false;
    session_id = network_analysis_session_id(workspace);
    binary_id = workspace->identity().binary_id().to_hex();
    if (session_id.empty() || binary_id.empty())
        return false;
    const std::string key = network_artifact_binding_key(identity);
    auto found = s_network_artifact_workspace_bindings.find(key);
    if (found != s_network_artifact_workspace_bindings.end())
        return found->second.analysis_session_id == session_id &&
            found->second.binary_id == binary_id;
    if (s_network_artifact_workspace_bindings.size() >=
        k_max_network_artifact_workspace_bindings)
        return false;
    s_network_artifact_workspace_bindings.emplace(key,
        network_artifact_workspace_binding_t{session_id, binary_id});
    return true;
}

static std::string network_selection_entity_key(const artifact_identity_t& identity) {
    std::string key = "network.artifact|";
    const auto append_component = [&](std::string_view value) {
        key.append(std::to_string(value.size()));
        key.push_back(':');
        key.append(value);
        key.push_back('|');
    };
    append_component(identity.source_view_id);
    append_component(identity.id);
    append_component(identity.session_id);
    key.append(std::to_string(static_cast<unsigned>(identity.kind)));
    key.push_back('|');
    key.append(std::to_string(identity.source_id));
    key.push_back('|');
    key.append(std::to_string(identity.timestamp));
    key.push_back('|');
    key.append(std::to_string(identity.revision));
    key.push_back('|');
    key.append(std::to_string(identity.content_hash));
    key.push_back('|');
    key.append(std::to_string(identity.content_size));
    key.push_back('|');
    key.append(std::to_string(identity.target_port));
    key.push_back('|');
    key.push_back(identity.use_tls ? '1' : '0');
    key.push_back('|');
    key.push_back(identity.raw_protocol ? '1' : '0');
    if (key.size() <= aida::workbench::k_max_document_key_bytes)
        return key;
    return "network.artifact.hash|" + std::to_string(artifact_hash(key));
}

static bool publish_workbench_network_selection(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::selection_context_t& selection,
    aida::workbench::document_id_t requested_document,
    aida::workbench::document_id_t& published_document) {
    if (!workspace || workspace->closing() || workspace->closed())
        return false;
    aida::workbench::document_local_cursor_t cursor;
    aida::workbench::workbench_shell_workspace_context_t output;
    auto& runtime = aida::workbench::workbench_shell_runtime_t::instance();
    const auto result = requested_document.value != 0
        ? runtime.publish_document_selection(workspace, requested_document, selection, cursor,
            aida::workbench::navigation_origin_t::user, output)
        : runtime.publish_selection(workspace, selection, cursor,
            aida::workbench::navigation_origin_t::user, output);
    if (!result)
        return false;
    if (requested_document.value != 0) {
        published_document = requested_document;
        return true;
    }
    const auto focused = std::find_if(output.persistence.views.begin(),
        output.persistence.views.end(), [](const auto& view) { return view.focused; });
    if (focused == output.persistence.views.end() || focused->document.value == 0)
        return false;
    published_document = focused->document;
    return true;
}

static bool document_workbench_selection_matches(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::document_id_t document_id,
    std::string_view entity_key) {
    if (!workspace || document_id.value == 0 || entity_key.empty())
        return false;
    aida::workbench::workbench_shell_workspace_context_t context;
    if (!aida::workbench::workbench_shell_runtime_t::instance()
            .workspace_context(workspace, context))
        return false;
    const auto document = std::find_if(context.persistence.documents.begin(),
        context.persistence.documents.end(), [&](const auto& candidate) {
            return candidate.id == document_id;
        });
    return document != context.persistence.documents.end() &&
        document->local_state.selection.kind == aida::workbench::selection_kind_t::entity &&
        document->local_state.selection.entity_key == entity_key;
}

static void clear_owned_network_selection() {
    auto publication = std::move(s_network_selection_publication);
    s_network_selection_publication = {};
    auto workspace = publication.workspace.lock();
    if (!workspace || workspace->closing() || workspace->closed() ||
        publication.document.value == 0 ||
        !document_workbench_selection_matches(
            workspace, publication.document, publication.entity_key))
        return;
    aida::workbench::selection_context_t empty;
    aida::workbench::document_id_t ignored;
    static_cast<void>(publish_workbench_network_selection(
        workspace, empty, publication.document, ignored));
}

static void clear_stale_network_selection(std::string_view source_view_id) {
    if (s_network_selection_publication.source_view_id != source_view_id)
        return;
    clear_owned_network_selection();
}

static void publish_network_selection(const artifact_identity_t& identity, bool force = false) {
    if (!identity.valid() || identity.source_view_id.empty()) {
        clear_owned_network_selection();
        return;
    }
    auto workspace = analysis_session::active_workspace();
    if (!workspace || workspace->closing() || workspace->closed()) {
        clear_owned_network_selection();
        return;
    }
    std::string analysis_session_id;
    std::string binary_id;
    if (!bind_network_artifact_workspace(
            identity, workspace, analysis_session_id, binary_id)) {
        clear_owned_network_selection();
        return;
    }
    const auto generation = workspace->generation();
    const std::string entity_key = network_selection_entity_key(identity);
    auto previous_workspace = s_network_selection_publication.workspace.lock();
    const bool same_publication = previous_workspace.get() == workspace.get() &&
        s_network_selection_publication.workspace_generation == generation &&
        s_network_selection_publication.analysis_session_id == analysis_session_id &&
        s_network_selection_publication.binary_id == binary_id &&
        s_network_selection_publication.entity_key == entity_key &&
        s_network_selection_publication.document.value != 0;
    if (same_publication && !force)
        return;
    const aida::workbench::document_id_t requested_document = same_publication
        ? s_network_selection_publication.document : aida::workbench::document_id_t{};
    if (!same_publication && s_network_selection_publication.document.value != 0)
        clear_owned_network_selection();
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::entity;
    selection.entity_key = entity_key;
    aida::workbench::document_id_t published_document;
    if (!publish_workbench_network_selection(
            workspace, selection, requested_document, published_document)) {
        clear_owned_network_selection();
        return;
    }
    s_network_selection_publication.workspace = workspace;
    s_network_selection_publication.workspace_generation = generation;
    s_network_selection_publication.document = published_document;
    s_network_selection_publication.entity_key = entity_key;
    s_network_selection_publication.source_view_id = identity.source_view_id;
    s_network_selection_publication.analysis_session_id = std::move(analysis_session_id);
    s_network_selection_publication.binary_id = std::move(binary_id);
}
#else
static void clear_stale_network_selection(std::string_view) {}
static void publish_network_selection(const artifact_identity_t&, bool = false) {}
#endif

struct repeater_artifact_publication_t {
    std::vector<std::shared_ptr<const artifact_snapshot_t>> requests;
};

static std::shared_ptr<const repeater_artifact_publication_t>
    s_repeater_artifact_publication;
static std::atomic<bool> s_repeater_artifact_publication_ready{false};

static void publish_repeater_request_artifacts(const state_t& state) noexcept {
    const auto previous = std::atomic_load_explicit(
        &s_repeater_artifact_publication, std::memory_order_acquire);
    s_repeater_artifact_publication_ready.store(false, std::memory_order_release);
    std::atomic_store_explicit(&s_repeater_artifact_publication,
        std::shared_ptr<const repeater_artifact_publication_t>{},
        std::memory_order_release);
    try {
        auto next = std::make_shared<repeater_artifact_publication_t>();
        next->requests.reserve(state.repeater_entries.size());
        std::unordered_map<std::uint64_t,
            std::shared_ptr<const artifact_snapshot_t>> previous_by_source;
        if (previous) {
            previous_by_source.reserve(previous->requests.size());
            for (const auto& candidate : previous->requests) {
                if (candidate)
                    previous_by_source.emplace(
                        candidate->identity.source_id, candidate);
            }
        }
        for (const auto& entry : state.repeater_entries) {
            if (!entry || entry->id == 0 || entry->raw_request.empty())
                continue;
            const artifact_identity_t identity = repeater_artifact_identity(
                *entry, artifact_kind_t::repeater_request);
            if (!identity.valid())
                continue;
            std::shared_ptr<const artifact_snapshot_t> retained;
            const auto previous_found = previous_by_source.find(identity.source_id);
            if (previous_found != previous_by_source.end()) {
                const auto& candidate = previous_found->second;
                if (candidate && candidate->identity.id == identity.id &&
                    candidate->identity.revision == identity.revision &&
                    candidate->identity.content_size == identity.content_size &&
                    candidate->identity.content_hash == identity.content_hash &&
                    candidate->identity.target_host == identity.target_host &&
                    candidate->identity.target_port == identity.target_port &&
                    candidate->identity.use_tls == identity.use_tls &&
                    candidate->identity.parent_id == identity.parent_id)
                    retained = candidate;
            }
            if (!retained) {
                auto snapshot = std::make_shared<artifact_snapshot_t>();
                snapshot->identity = identity;
                snapshot->bytes.assign(entry->raw_request.begin(), entry->raw_request.end());
                if (snapshot->identity.content_size != snapshot->bytes.size() ||
                    snapshot->identity.content_hash != artifact_hash(snapshot->bytes))
                    continue;
                retained = std::move(snapshot);
            }
            next->requests.push_back(std::move(retained));
        }
        std::shared_ptr<const repeater_artifact_publication_t> immutable =
            std::move(next);
        std::atomic_store_explicit(&s_repeater_artifact_publication,
            std::move(immutable), std::memory_order_release);
        s_repeater_artifact_publication_ready.store(true, std::memory_order_release);
    } catch (...) {
    }
}

static artifact_identity_t websocket_artifact_identity(const state_t::ws_frame_entry_t& frame) {
    artifact_identity_t identity;
    identity.kind = artifact_kind_t::websocket_frame;
    identity.id = "network.websocket." + std::to_string(frame.exchange_id) + "." +
        std::to_string(frame.timestamp) + (frame.is_outbound ? ".out" : ".in");
    identity.parent_id = "network.exchange." + std::to_string(frame.exchange_id);
    identity.source_view_id = "view.network.websocket";
    identity.source_id = frame.exchange_id;
    identity.timestamp = frame.timestamp;
    identity.content_size = frame.payload.size();
    identity.content_hash = artifact_hash(frame.payload);
    identity.label = std::string(frame.is_outbound ? "Outbound" : "Inbound") +
        " WebSocket frame";
    identity.target_host = frame.host;
    identity.target_port = frame.port;
    return identity;
}

static ImU32 status_code_color(int code) {
    const auto& t = aida::ui::resolved();
    if (code >= 200 && code < 300) return t.success;
    if (code >= 300 && code < 400) return t.info;
    if (code >= 400 && code < 500) return t.warning;
    if (code >= 500)               return t.error;
    return t.text_dim;
}

struct row_entrance_state_t {
    std::vector<float> spawn_time;
};
static row_entrance_state_t s_conn_rows;
static row_entrance_state_t s_cap_rows;
static row_entrance_state_t s_dns_rows;
static row_entrance_state_t s_proxy_rows;
static row_entrance_state_t s_kl_rows;

static void compute_row_entrance(row_entrance_state_t& rs, size_t total, float& alpha_out, float& off_out, int row_index) {
    if (rs.spawn_time.size() < total) {
        float now = aida::ui::clock::seconds();
        float stagger = 0.012f;
        size_t base = rs.spawn_time.size();
        for (size_t i = base; i < total; ++i)
            rs.spawn_time.push_back(now + static_cast<float>(i - base) * stagger);
    } else if (rs.spawn_time.size() > total) {
        rs.spawn_time.resize(total);
    }
    if (row_index < 0 || static_cast<size_t>(row_index) >= rs.spawn_time.size()) {
        alpha_out = 1.f; off_out = 0.f; return;
    }
    float age = aida::ui::clock::seconds() - rs.spawn_time[static_cast<size_t>(row_index)];
    float dur = 0.180f;
    if (age >= dur) { alpha_out = 1.f; off_out = 0.f; return; }
    if (age < 0.f) { alpha_out = 0.f; off_out = 8.f; return; }
    float t01 = age / dur;
    float eased = aida::motion::ease::out_cubic(t01);
    alpha_out = eased;
    off_out = (1.f - eased) * 8.f;
}


struct intercept_ui_state_t {
    int     prev_held_count = 0;
    aida::ui::flash_t border_flash;
    aida::ui::flash_t label_flash;
};
static intercept_ui_state_t s_intercept_ui;


struct proxy_history_chart_t {
    static constexpr int N = 32;
    float values[N] = {};
    int   head = 0;
    uint64_t last_total = 0;
    float    last_sample_time = 0.f;
};
static proxy_history_chart_t s_proxy_chart;

static void proxy_chart_tick(uint64_t total_requests) {
    float now = aida::ui::clock::seconds();
    if (s_proxy_chart.last_sample_time == 0.f) {
        s_proxy_chart.last_total = total_requests;
        s_proxy_chart.last_sample_time = now;
        return;
    }
    float dt = now - s_proxy_chart.last_sample_time;
    if (dt < 0.5f) return;
    uint64_t diff = total_requests - s_proxy_chart.last_total;
    float rate = (dt > 0.f) ? static_cast<float>(diff) / dt : 0.f;
    s_proxy_chart.values[s_proxy_chart.head] = rate;
    s_proxy_chart.head = (s_proxy_chart.head + 1) % proxy_history_chart_t::N;
    s_proxy_chart.last_total = total_requests;
    s_proxy_chart.last_sample_time = now;
}


struct capture_rate_smooth_t {
    float displayed = 0.f;
    float velocity  = 0.f;
    float ema       = 0.f;
    float last_sample_time = 0.f;
    size_t last_count = 0;
};
static capture_rate_smooth_t s_cap_rate;
static std::mutex s_capture_control_mutex;
static std::string s_capture_control_status;

static void set_capture_control_status(const char* text) {
    std::lock_guard<std::mutex> lock(s_capture_control_mutex);
    s_capture_control_status = text ? text : "";
}

static std::string capture_control_status() {
    std::lock_guard<std::mutex> lock(s_capture_control_mutex);
    return s_capture_control_status;
}

template <typename Fn>
static bool post_network_task(const char* name,
                              aida::infra::executor::domain_t domain,
                              const char* thread_class,
                              Fn&& fn,
                              bool register_with_task_center = true) {
    try {
        std::string task_name = name ? name : "?";
        std::function<void()> task(std::forward<Fn>(fn));
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "network.view";
        sub.label = name ? name : "network.task";
        sub.thread_class = thread_class ? thread_class : "bounded_task";
        sub.domain = domain;
        sub.priority = 3;
        sub.body = [task_name, task = std::move(task), domain]() mutable {
            diag::log_tagged_fmt("network",
                "executor_task_enter name=%s domain=%s tid=%lu",
                task_name.c_str(),
                aida::infra::executor::domain_name(domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
            task();
            diag::log_tagged_fmt("network",
                "executor_task_exit name=%s domain=%s tid=%lu",
                task_name.c_str(),
                aida::infra::executor::domain_name(domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
        };
        auto submit_result = aida::infra::executor::submit(std::move(sub));
        bool ok = submit_result.submitted;
        if (ok && submit_result.task_id != 0 && register_with_task_center) {
            const std::string task_label = [&task_name] {
                std::string label;
                label.reserve(task_name.size());
                bool capitalize = true;
                for (const char character : task_name) {
                    if (character == '_' || character == '.') {
                        label.push_back(' ');
                        capitalize = true;
                    } else {
                        label.push_back(capitalize
                            ? static_cast<char>(std::toupper(static_cast<unsigned char>(character)))
                            : character);
                        capitalize = false;
                    }
                }
                return label.empty() ? std::string("Network task") : label;
            }();
            std::string owner_view = "view.network.connections";
            if (task_name.find("capture") != std::string::npos) owner_view = "view.network.capture";
            else if (task_name.find("repeater") != std::string::npos) owner_view = "view.network.repeater";
            else if (task_name.find("fuzzer") != std::string::npos) owner_view = "view.network.fuzzer";
            else if (task_name.find("offensive") != std::string::npos) owner_view = "view.network.offensive";
            else if (task_name.find("pcap") != std::string::npos) owner_view = "view.network.pcap";
            else if (task_name.find("har") != std::string::npos) owner_view = "view.network.proxy";
            else if (task_name.find("script") != std::string::npos) owner_view = "view.network.scripting";
            aida::ui::task_center::task_registration_t registration;
            registration.owner = "network";
            registration.owner_view = owner_view;
            registration.owner_action = task_name;
            registration.label = task_label;
            registration.stage = "Queued";
            registration.cancellation_is_safe = false;
            registration.callbacks.focus = [owner_view] {
                (void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(owner_view));
            };
            (void)aida::ui::task_center::register_executor_job(submit_result.task_id, std::move(registration));
        }
        diag::log_tagged_fmt("network", "executor_post name=%s domain=%s ok=%d reject=%s",
            name ? name : "?",
            aida::infra::executor::domain_name(domain),
            ok ? 1 : 0,
            submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str());
        return ok;
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "executor_post_cpp_exception name=%s what=%s",
            name ? name : "?", e.what());
        return false;
    } catch (...) {
        diag::log_tagged_fmt("network", "executor_post_unknown_exception name=%s",
            name ? name : "?");
        return false;
    }
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static bool initialize_executor_for_network() {
    try {
        const auto snap = aida::infra::taskflow_runtime::active_snapshot(0);
        const auto work = aida::network::executor_status::work_stats();
        const auto service = aida::network::executor_status::service_stats();
        const auto critical = aida::network::executor_status::critical_stats();
        const bool accepting = snap.accepting && !snap.shutting_down;
        diag::log_tagged_fmt("network",
            "executor_runtime_status accepting=%d shutting_down=%d total_active=%u executor_work_pending=%llu executor_service_pending=%llu executor_critical_pending=%llu",
            snap.accepting ? 1 : 0,
            snap.shutting_down ? 1 : 0,
            static_cast<unsigned>(snap.total_active),
            static_cast<unsigned long long>(work.pending),
            static_cast<unsigned long long>(service.pending),
            static_cast<unsigned long long>(critical.pending));
        return accepting;
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "executor_runtime_status_cpp_exception what=%s", e.what());
        return false;
    } catch (...) {
        diag::log_tagged("network", "executor_runtime_status_unknown_exception");
        return false;
    }
}
#endif

static float capture_rate_tick(size_t total_packets) {
    float now = aida::ui::clock::seconds();
    if (s_cap_rate.last_sample_time == 0.f) {
        s_cap_rate.last_sample_time = now;
        s_cap_rate.last_count = total_packets;
        return 0.f;
    }
    float dt = now - s_cap_rate.last_sample_time;
    if (dt >= 0.25f) {
        size_t diff = total_packets >= s_cap_rate.last_count ? total_packets - s_cap_rate.last_count : 0;
        float rate = (dt > 0.f) ? static_cast<float>(diff) / dt : 0.f;
        float a = 0.35f;
        s_cap_rate.ema = s_cap_rate.ema * (1.f - a) + rate * a;
        s_cap_rate.last_count = total_packets;
        s_cap_rate.last_sample_time = now;
    }
    s_cap_rate.displayed = aida::motion::critically_damped_step(
        s_cap_rate.displayed, s_cap_rate.ema, s_cap_rate.velocity, 0.18f, aida::ui::clock::dt());
    if (s_cap_rate.displayed < 0.f) s_cap_rate.displayed = 0.f;
    return s_cap_rate.displayed;
}


static aida::ui::transition_t s_tab_content_in;
static int s_last_active_tab = -1;

struct cert_diagnostics_ui_t {
    int target_pid = 0;
    bool has_report = false;
    cert_intercept::process_diagnostics_t report;
    std::vector<cert_intercept::provider_status_t> providers;
    std::string status;
    std::string handoff_status;
};
static cert_diagnostics_ui_t s_cert_diag_ui;
static std::atomic<bool> s_cert_diagnostics_pending{false};
static std::atomic<bool> s_cert_handoff_pending{false};
static std::atomic<std::uint64_t> s_cert_diagnostics_serial{0};
static std::atomic<std::uint64_t> s_cert_handoff_serial{0};

static std::string cert_diag_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static bool cert_diag_has_any(const std::string& value, std::initializer_list<const char*> needles) {
    const std::string lowered = cert_diag_lower(value);
    for (const char* needle : needles) {
        if (lowered.find(needle) != std::string::npos) return true;
    }
    return false;
}

static void cert_diag_apply_proxy_observations(cert_intercept::diagnostic_context_t& context) {
    auto observations = mitm_proxy::get_tls_observations(64);
    for (const auto& obs : observations) {
        std::string evidence = std::string(mitm_proxy::to_string(obs.kind)) + " host=" + obs.target_host;
        if (!obs.sni.empty()) evidence += " sni=" + obs.sni;
        if (!obs.alpn.empty()) evidence += " alpn=" + obs.alpn;
        if (!obs.detail.empty()) evidence += " detail=" + obs.detail;
        switch (obs.kind) {
        case mitm_proxy::tls_observation_kind_t::http_tls:
            context.interception_observed = true;
            break;
        case mitm_proxy::tls_observation_kind_t::sni_authority_mismatch:
            context.hostname_san_mismatch_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        case mitm_proxy::tls_observation_kind_t::client_handshake_failed:
            if (cert_diag_has_any(obs.detail, {"certificate", "unknown ca", "bad certificate", "required", "alert"})) {
                context.browser_trust_policy_or_ct_block = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::upstream_handshake_failed:
            if (cert_diag_has_any(obs.detail, {"certificate required", "bad certificate", "handshake failure", "alert certificate"})) {
                context.mutual_tls_requested = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::non_http_tls:
            context.non_http_tls_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        default:
            break;
        }
    }
}

static std::string format_ip(const uint8_t* addr, uint8_t af) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (af == 2) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            static_cast<unsigned>(addr[0]), static_cast<unsigned>(addr[1]),
            static_cast<unsigned>(addr[2]), static_cast<unsigned>(addr[3]));
    } else if (af == 23) {
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    }
    return buf;
}

static const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "???";
    }
}

static const char* tcp_state_name(uint8_t state) {
    static const char* names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    };
    if (state < 12) return names[state];
    return "UNKNOWN";
}

static std::string format_bytes(uint64_t bytes) {
    char buf[64];
    if (bytes < 1024)
        snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    else if (bytes < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

static std::string format_rate(float bytes_per_sec) {
    if (bytes_per_sec < 1024.f) return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
    return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

static std::string format_timestamp(uint64_t ts) {
    uint64_t sec = ts / 1000;
    uint64_t ms = ts % 1000;
    uint64_t h = (sec / 3600) % 24;
    uint64_t m = (sec / 60) % 60;
    uint64_t s = sec % 60;
    char buf[32];
    snprintf(buf, sizeof(buf), "%02llu:%02llu:%02llu.%03llu",
        static_cast<unsigned long long>(h), static_cast<unsigned long long>(m),
        static_cast<unsigned long long>(s), static_cast<unsigned long long>(ms));
    return buf;
}

static bool filter_text_match(const char* filter, const std::string& text) {
    if (!filter || !filter[0]) return true;

    std::string lower_filter(filter);
    std::string lower_text = text;
    for (auto& c : lower_filter) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_text) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lower_text.find(lower_filter) != std::string::npos;
}

static void publish_connection_snapshot(state_t& state, const std::vector<connection_entry_t>& entries) {
    std::atomic_store_explicit(&state.connection_snapshot,
        std::shared_ptr<const std::vector<connection_entry_t>>(
            std::make_shared<std::vector<connection_entry_t>>(entries)),
        std::memory_order_release);
}

static void publish_capture_snapshot_locked(state_t& state) {
    auto snapshot = std::make_shared<std::vector<packet_entry_t>>();
    snapshot->assign(state.captured_packets.begin(), state.captured_packets.end());
    std::atomic_store_explicit(&state.capture_snapshot,
        std::shared_ptr<const std::vector<packet_entry_t>>(std::move(snapshot)),
        std::memory_order_release);
}

static void publish_dns_snapshot_locked(state_t& state) {
    auto snapshot = std::make_shared<std::vector<dns_entry_t>>();
    snapshot->assign(state.dns_entries.begin(), state.dns_entries.end());
    std::atomic_store_explicit(&state.dns_snapshot,
        std::shared_ptr<const std::vector<dns_entry_t>>(std::move(snapshot)),
        std::memory_order_release);
}

static void publish_bandwidth_snapshot(state_t& state, const std::vector<bw_entry_t>& entries) {
    std::atomic_store_explicit(&state.bandwidth_snapshot,
        std::shared_ptr<const std::vector<bw_entry_t>>(
            std::make_shared<std::vector<bw_entry_t>>(entries)),
        std::memory_order_release);
}

static void shift_capture_selection_after_front_pop_locked(state_t& state) {
    int selected = state.cap_selected.load(std::memory_order_acquire);
    if (selected > 0)
        state.cap_selected.store(selected - 1, std::memory_order_release);
    else if (selected == 0)
        state.cap_selected.store(-1, std::memory_order_release);
}

static std::string capture_row_info_text(const std::string& summary) {
    if (summary.size() <= 200)
        return summary;
    return summary.substr(0, 197) + "...";
}

static capture_table_snapshot_t& snapshot_capture_table(state_t& state, const char* filter_text) {
    static capture_table_snapshot_t snapshot;
    static std::shared_ptr<const std::vector<packet_entry_t>> cached_packets;
    static std::string cached_filter;
    const auto packets = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
    std::string filter = filter_text ? filter_text : "";
    const int selected = state.cap_selected.load(std::memory_order_acquire);
    if (packets == cached_packets && filter == cached_filter) {
        snapshot.selected_index = selected;
        return snapshot;
    }
    cached_packets = packets;
    cached_filter = filter;
    snapshot = {};
    if (!packets) {
        snapshot.selected_index = -1;
        return snapshot;
    }
    snapshot.total_count = packets->size();
    snapshot.selected_index = selected;
    snapshot.rows.reserve(packets->size());

    bool selected_visible = snapshot.selected_index < 0;
    for (size_t i = 0; i < packets->size(); ++i) {
        const packet_entry_t& p = (*packets)[i];
        std::string src = format_ip(p.src_addr, 2) + ":" + std::to_string(p.src_port);
        std::string dst = format_ip(p.dst_addr, 2) + ":" + std::to_string(p.dst_port);

        if (!filter.empty()) {
            std::string all = src + " " + dst + " " + p.protocol_label + " " + p.summary;
            if (!filter_text_match(filter.c_str(), all))
                continue;
        }

        capture_row_snapshot_t row;
        row.packet_index = static_cast<int>(i);
        row.timestamp = p.timestamp;
        row.src = std::move(src);
        row.dst = std::move(dst);
        row.protocol_label = p.protocol_label;
        row.summary = capture_row_info_text(p.summary);
        if (row.packet_index == snapshot.selected_index)
            selected_visible = true;
        snapshot.rows.push_back(std::move(row));
    }

    if (!selected_visible) {
        if (snapshot.rows.empty()) {
            state.cap_selected = -1;
        } else {
            auto it = std::lower_bound(snapshot.rows.begin(), snapshot.rows.end(), snapshot.selected_index,
                [](const capture_row_snapshot_t& row, int selected) {
                    return row.packet_index < selected;
                });
            if (it == snapshot.rows.end()) {
                it = snapshot.rows.end();
                --it;
            }
            state.cap_selected = it->packet_index;
        }
        snapshot.selected_index = state.cap_selected.load(std::memory_order_acquire);
    }

    return snapshot;
}

static bool driver_feature_ready(const char* feature, int iter = -1) {
    bool drv_ok = driver_bridge::using_kernel_driver();
    if (!drv_ok && (iter < 0 || iter <= 3 || (iter % 60) == 0)) {
        diag::log_tagged_fmt("network", "%s_driver_gate drv_ok=%d iter=%d",
            feature ? feature : "network",
            drv_ok ? 1 : 0,
            iter);
    }
    if (!drv_ok)
        return false;
    return true;
}


#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static void connection_poll_thread(state_t& state) {
    diag::log_tagged_fmt("network", "connection_poll_thread_started auto_refresh=%d filter_pid=%u filter_proto=%u",
        state.conn_auto_refresh_enabled.load(std::memory_order_acquire) ? 1 : 0, state.conn_filter_pid, state.conn_filter_protocol);
    int poll_iter = 0;
    while (state.conn_polling.load()) {
        bool drv_ok = driver_feature_ready("connection_poll", poll_iter);
        ++poll_iter;
        const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
        const uint64_t last_render_ms = state.last_render_tick_ms.load(std::memory_order_acquire);
        const bool rendered_recently = last_render_ms != 0 && now_ms >= last_render_ms && (now_ms - last_render_ms) <= 2500ULL;
        const bool auto_refresh = state.conn_auto_refresh_enabled.load(std::memory_order_acquire);
        if (drv_ok && auto_refresh && rendered_recently) {
            auto raw_conns = driver_bridge::enumerate_connections(
                state.conn_filter_pid, state.conn_filter_protocol);

            std::vector<connection_entry_t> entries;
            entries.reserve(raw_conns.size());
            for (auto& c : raw_conns) {
                connection_entry_t e;
                e.pid = c.pid;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                e.protocol = static_cast<uint8_t>((std::min)(c.protocol, static_cast<uint32_t>(UINT8_MAX)));
                e.state = static_cast<uint8_t>((std::min)(c.state, static_cast<uint32_t>(UINT8_MAX)));
                e.local_port = static_cast<uint16_t>((std::min)(c.local_port, static_cast<uint32_t>(UINT16_MAX)));
                e.remote_port = static_cast<uint16_t>((std::min)(c.remote_port, static_cast<uint32_t>(UINT16_MAX)));
                e.address_family = static_cast<uint8_t>((std::min)(c.address_family, static_cast<uint32_t>(UINT8_MAX)));
#else
                e.protocol = c.protocol;
                e.state = c.state;
                e.local_port = c.local_port;
                e.remote_port = c.remote_port;
                e.address_family = c.address_family;
#endif
                memcpy(e.local_addr, c.local_addr, 16);
                memcpy(e.remote_addr, c.remote_addr, 16);
                entries.push_back(std::move(e));
            }

            size_t count = entries.size();
            publish_connection_snapshot(state, entries);
            {
                std::lock_guard<std::mutex> lock(state.conn_mutex);
                state.connections = std::move(entries);
            }
            if (poll_iter <= 3 || (poll_iter % 60) == 0) {
                diag::log_tagged_fmt("network", "connection_poll iter=%d drv_ok=1 count=%zu", poll_iter, count);
            }
        } else if (poll_iter <= 3 || (poll_iter % 60) == 0) {
            diag::log_tagged_fmt("network", "connection_poll iter=%d drv_ok=%d auto_refresh=%d rendered_recently=%d skipped",
                poll_iter, drv_ok ? 1 : 0, auto_refresh ? 1 : 0, rendered_recently ? 1 : 0);
        }

        std::unique_lock<std::mutex> lk(state.conn_cv_mutex);
        state.conn_cv.wait_for(lk, std::chrono::milliseconds(1000), [&state]() {
            return !state.conn_polling.load();
        });
    }
    diag::log_tagged("network", "connection_poll_thread_exited");
}
#endif

static void capture_poll_thread(state_t& state) {
    diag::log_tagged("network", "capture_poll_thread_started");
    state.cap_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.cap_cv_mutex);
            state.cap_cv.wait(lk, [&state]() {
                return state.cap_polling.load() || !state.cap_thread_alive.load();
            });
        }
        if (!state.cap_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "capture_poll_loop_armed");
        while (state.cap_polling.load()) {
            bool drv_ok = driver_feature_ready("capture_poll", poll_iter);
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                diag::log_tagged_fmt("network", "capture_poll iter=%d drv_ok=%d", poll_iter, drv_ok ? 1 : 0);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_packets = driver_bridge::get_captured_packets(64);

                if (!raw_packets.empty()) {
                    size_t batch_n = raw_packets.size();
                    std::lock_guard<std::mutex> lock(state.cap_mutex);
                    for (auto& p : raw_packets) {
                        packet_entry_t entry;
                        entry.timestamp = p.timestamp;
                        entry.pid = p.pid;
                        entry.protocol = static_cast<uint8_t>(p.protocol);
                        entry.direction = static_cast<uint8_t>(p.direction);
                        entry.src_port = static_cast<uint16_t>(p.local_port);
                        entry.dst_port = static_cast<uint16_t>(p.remote_port);
                        memcpy(entry.src_addr, p.local_addr, 16);
                        memcpy(entry.dst_addr, p.remote_addr, 16);
                        entry.payload_size = p.payload_size;
                        entry.payload = p.payload;

                        auto det = protocol_parser::detect_protocol(
                            p.payload.data(), p.payload.size(),
                            static_cast<uint16_t>(p.local_port), static_cast<uint16_t>(p.remote_port),
                            p.protocol);
                        entry.protocol_label = det.label;
                        entry.summary = det.summary;

                        state.captured_packets.push_back(std::move(entry));
                        while (state.captured_packets.size() > state.cap_max_packets) {
                            shift_capture_selection_after_front_pop_locked(state);
                            state.captured_packets.pop_front();
                        }
                    }
                    if (poll_iter <= 5 || (poll_iter % 50) == 0) {
                        diag::log_tagged_fmt("network", "capture_poll_batch packets=%zu total_buffered=%zu",
                            batch_n, state.captured_packets.size());
                    }
                    publish_capture_snapshot_locked(state);
                }
            }

            for (int i = 0; i < 10 && state.cap_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "capture_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "capture_poll_thread_exited");
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static void dns_poll_thread(state_t& state) {
    diag::log_tagged("network", "dns_poll_thread_started");
    state.dns_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.dns_cv_mutex);
            state.dns_cv.wait(lk, [&state]() {
                return state.dns_polling.load() || !state.dns_thread_alive.load();
            });
        }
        if (!state.dns_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "dns_poll_loop_armed");
        while (state.dns_polling.load()) {
            bool drv_ok = driver_feature_ready("dns_poll", poll_iter);
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                diag::log_tagged_fmt("network", "dns_poll iter=%d drv_ok=%d filter_pid=%u",
                    poll_iter, drv_ok ? 1 : 0, state.dns_filter_pid);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_dns = driver_bridge::get_dns_queries(state.dns_filter_pid);

                if (!raw_dns.empty()) {
                    size_t added = 0;
                    std::lock_guard<std::mutex> lock(state.dns_mutex);
                    for (auto& d : raw_dns) {
                        bool duplicate = false;
                        const auto recent_count = static_cast<std::ptrdiff_t>((std::min)(
                            static_cast<std::size_t>(256), state.dns_entries.size()));
                        for (auto it = state.dns_entries.rbegin();
                             it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + recent_count;
                             ++it) {
                            if (it->timestamp == d.timestamp && it->domain == d.domain && it->pid == d.pid) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            dns_entry_t e;
                            e.timestamp = d.timestamp;
                            e.pid = d.pid;
                            e.query_type = static_cast<uint16_t>(d.query_type);
                            e.domain = d.domain;
                            e.resolved_addr = format_ip(d.resolved_addr, 2);
                            e.response_code = d.response_code;
                            e.ttl = d.ttl;
                            state.dns_entries.push_back(std::move(e));
                            ++added;
                        }
                    }
                    while (state.dns_entries.size() > state.dns_max_entries)
                        state.dns_entries.pop_front();
                    publish_dns_snapshot_locked(state);
                    if (added > 0) {
                        diag::log_tagged_fmt("network", "dns_poll_batch raw=%zu added=%zu total=%zu",
                            raw_dns.size(), added, state.dns_entries.size());
                    }
                }
            }

            for (int i = 0; i < 50 && state.dns_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "dns_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "dns_poll_thread_exited");
}

static void bandwidth_poll_thread(state_t& state) {
    diag::log_tagged("network", "bandwidth_poll_thread_started");
    state.bw_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.bw_cv_mutex);
            state.bw_cv.wait(lk, [&state]() {
                return state.bw_polling.load() || !state.bw_thread_alive.load();
            });
        }
        if (!state.bw_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "bandwidth_poll_loop_armed");
        while (state.bw_polling.load()) {
            ++poll_iter;
            if (driver_bridge::using_kernel_driver()) {
                auto raw_bw = driver_bridge::get_bw_per_process();
                if (poll_iter <= 3 || (poll_iter % 60) == 0) {
                    diag::log_tagged_fmt("network", "bandwidth_poll iter=%d processes=%zu", poll_iter, raw_bw.size());
                }

            std::vector<bw_entry_t> old_entries;
            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                old_entries = state.bw_entries;
            }

            std::vector<bw_entry_t> entries;
            entries.reserve(raw_bw.size());
            for (auto& b : raw_bw) {
                bw_entry_t e;
                e.pid = b.pid;
                e.bytes_in = b.bytes_recv;
                e.bytes_out = b.bytes_sent;
                e.rate_in = 0.f;
                e.rate_out = 0.f;

                for (auto& old : old_entries) {
                    if (old.pid == b.pid) {
                        if (old.bytes_in > 0 || old.bytes_out > 0) {
                            float dt = 0.5f;
                            e.rate_in = static_cast<float>(b.bytes_recv > old.bytes_in ? b.bytes_recv - old.bytes_in : 0) / dt;
                            e.rate_out = static_cast<float>(b.bytes_sent > old.bytes_out ? b.bytes_sent - old.bytes_out : 0) / dt;
                        }
                        memcpy(e.rate_history, old.rate_history, sizeof(e.rate_history));
                        e.history_index = old.history_index;
                        break;
                    }
                }

                e.rate_history[e.history_index % 64] = e.rate_in + e.rate_out;
                e.history_index++;

                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                state.bw_entries = std::move(entries);
                publish_bandwidth_snapshot(state, state.bw_entries);
            }
            }


            for (int i = 0; i < 50 && state.bw_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "bandwidth_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "bandwidth_poll_thread_exited");
}
#endif


#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static void run_fuzzer_thread(state_t& state);
static void finish_fuzzer_task(state_t& state,
                               aida::ui::task_center::task_state_t task_state,
                               std::string stage,
                               std::string summary);

static bool start_connection_worker(state_t& state) {
    if (!state.conn_thread_done.load(std::memory_order_acquire))
        return true;
    state.conn_polling.store(true);
    state.conn_thread_done.store(false, std::memory_order_release);
    if (post_network_task("connection_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                connection_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "connection_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "connection_poll_unknown_exception");
            }
            g_state.conn_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.conn_polling.store(false);
    state.conn_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "connection_worker_post_failed");
    return false;
}
#endif

static bool start_capture_worker(state_t& state) {
    if (!state.cap_thread_done.load(std::memory_order_acquire) &&
        state.cap_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.cap_thread_alive.store(true, std::memory_order_release);
    state.cap_thread_done.store(false, std::memory_order_release);
    if (post_network_task("capture_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                capture_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "capture_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "capture_poll_unknown_exception");
            }
            g_state.cap_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.cap_thread_alive.store(false, std::memory_order_release);
    state.cap_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "capture_worker_post_failed");
    return false;
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static bool start_dns_worker(state_t& state) {
    if (!state.dns_thread_done.load(std::memory_order_acquire) &&
        state.dns_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.dns_thread_alive.store(true, std::memory_order_release);
    state.dns_thread_done.store(false, std::memory_order_release);
    if (post_network_task("dns_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                dns_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "dns_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "dns_poll_unknown_exception");
            }
            g_state.dns_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.dns_thread_alive.store(false, std::memory_order_release);
    state.dns_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "dns_worker_post_failed");
    return false;
}

static bool start_bandwidth_worker(state_t& state) {
    if (!state.bw_thread_done.load(std::memory_order_acquire) &&
        state.bw_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.bw_thread_alive.store(true, std::memory_order_release);
    state.bw_thread_done.store(false, std::memory_order_release);
    if (post_network_task("bandwidth_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                bandwidth_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "bandwidth_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "bandwidth_poll_unknown_exception");
            }
            g_state.bw_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.bw_thread_alive.store(false, std::memory_order_release);
    state.bw_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "bandwidth_worker_post_failed");
    return false;
}

static bool start_fuzzer_worker(state_t& state) {
    if (!state.fuzz_thread_done.load(std::memory_order_acquire) &&
        state.fuzz_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.fuzz_thread_alive.store(true, std::memory_order_release);
    state.fuzz_thread_done.store(false, std::memory_order_release);
    if (post_network_task("fuzzer", aida::infra::executor::domain_t::long_running, "long_running", []() {
            try {
                diag::log_tagged("network", "fuzzer_thread_started");
                while (true) {
                    {
                        std::unique_lock<std::mutex> lk(g_state.fuzz_cv_mutex);
                        g_state.fuzz_cv.wait(lk, []() {
                            return g_state.fuzz_running.load() || !g_state.fuzz_thread_alive.load();
                        });
                    }
                    if (!g_state.fuzz_thread_alive.load())
                        break;
                    run_fuzzer_thread(g_state);
                }
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "fuzzer_cpp_exception what=%s", e.what());
                finish_fuzzer_task(g_state, aida::ui::task_center::task_state_t::failed,
                    "Execution failed", e.what());
            } catch (...) {
                diag::log_tagged("network", "fuzzer_unknown_exception");
                finish_fuzzer_task(g_state, aida::ui::task_center::task_state_t::failed,
                    "Execution failed", "Unexpected fuzzer worker failure");
            }
            g_state.fuzz_thread_alive.store(false, std::memory_order_release);
            g_state.fuzz_thread_done.store(true, std::memory_order_release);
            g_state.fuzz_cv.notify_all();
            diag::log_tagged("network", "fuzzer_thread_exited");
        }, false)) {
        return true;
    }
    state.fuzz_thread_alive.store(false, std::memory_order_release);
    state.fuzz_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "fuzzer_thread_post_failed");
    return false;
}
#endif

static void publish_initial_snapshots(state_t& state) {
    {
        std::lock_guard<std::mutex> lock(state.conn_mutex);
        publish_connection_snapshot(state, state.connections);
    }
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        publish_capture_snapshot_locked(state);
    }
    {
        std::lock_guard<std::mutex> lock(state.dns_mutex);
        publish_dns_snapshot_locked(state);
    }
    {
        std::lock_guard<std::mutex> lock(state.bw_mutex);
        publish_bandwidth_snapshot(state, state.bw_entries);
    }
    publish_repeater_request_artifacts(state);
}

static std::atomic<bool> s_driver_available_snapshot{false};
static std::atomic<bool> s_driver_available_snapshot_pending{false};
static std::atomic<std::uint64_t> s_driver_available_snapshot_requested_ms{0};

static void request_driver_available_snapshot(bool force = false) {
    const std::uint64_t now = network_now_ms();
    const std::uint64_t last = s_driver_available_snapshot_requested_ms.load(std::memory_order_acquire);
    if (!force && last != 0 && now >= last && now - last < 500)
        return;
    bool expected = false;
    if (!s_driver_available_snapshot_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    s_driver_available_snapshot_requested_ms.store(now, std::memory_order_release);
    const bool posted = post_network_task(
        "driver_availability_snapshot", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        []() {
            bool available = false;
            try {
                available = driver_bridge::using_kernel_driver();
            } catch (...) {
            }
            s_driver_available_snapshot.store(available, std::memory_order_release);
            s_driver_available_snapshot_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted)
        s_driver_available_snapshot_pending.store(false, std::memory_order_release);
}

void initialize() {
    reset_common_exchange_actions();
    s_accept_ui_completions.store(true, std::memory_order_release);
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    aida::preview::network::initialize(g_state);
    publish_initial_snapshots(g_state);
    return;
#else
    g_state.active = true;
    publish_initial_snapshots(g_state);
    diag::log_tagged("network", "initialize_begin");
    diag::log_tagged("net_audit", "[net_audit] network_view initialize begin");

    bool executor_ready = initialize_executor_for_network();

    mitm_proxy::set_ws_frame_callback([](const mitm_proxy::ws_frame_observed_t& frame) {
        state_t::ws_frame_entry_t entry;
        entry.timestamp = frame.timestamp;
        entry.exchange_id = frame.exchange_id;
        entry.host = frame.host;
        entry.port = frame.port;
        entry.is_outbound = frame.is_outbound;
        entry.is_text = frame.is_text;
        entry.opcode = frame.opcode;
        entry.payload = frame.payload;
        if (frame.is_text && !frame.payload.empty()) {
            size_t preview_len = frame.payload.size() < 96 ? frame.payload.size() : 96;
            entry.preview.assign(frame.payload.begin(), frame.payload.begin() + static_cast<ptrdiff_t>(preview_len));
            for (auto& ch : entry.preview) {
                unsigned char uc = static_cast<unsigned char>(ch);
                if (uc < 32 || uc == 127) ch = '.';
            }
        } else if (!frame.payload.empty()) {
            char buf[16];
            entry.preview.clear();
            size_t cap = frame.payload.size() < 16 ? frame.payload.size() : 16;
            for (size_t bi = 0; bi < cap; ++bi) {
                snprintf(buf, sizeof(buf), bi == 0 ? "%02X" : " %02X",
                    static_cast<unsigned>(frame.payload[bi]));
                entry.preview += buf;
            }
            if (frame.payload.size() > cap) entry.preview += " ...";
        }
        {
            std::lock_guard<std::mutex> lock(g_state.ws_mutex);
            g_state.ws_frames.push_back(std::move(entry));
            while (g_state.ws_frames.size() > g_state.ws_max_frames)
                g_state.ws_frames.pop_front();
        }
    });
    diag::log_tagged("net_audit", "[net_audit] websocket ws_frame_callback installed");

    if (executor_ready) {
        start_connection_worker(g_state);
        start_capture_worker(g_state);
        start_dns_worker(g_state);
        start_bandwidth_worker(g_state);
        start_fuzzer_worker(g_state);
    } else {
        g_state.conn_polling.store(false);
        g_state.conn_thread_done.store(true, std::memory_order_release);
        g_state.cap_thread_alive.store(false, std::memory_order_release);
        g_state.cap_thread_done.store(true, std::memory_order_release);
        g_state.dns_thread_alive.store(false, std::memory_order_release);
        g_state.dns_thread_done.store(true, std::memory_order_release);
        g_state.bw_thread_alive.store(false, std::memory_order_release);
        g_state.bw_thread_done.store(true, std::memory_order_release);
        g_state.fuzz_thread_alive.store(false, std::memory_order_release);
        g_state.fuzz_thread_done.store(true, std::memory_order_release);
        diag::log_tagged("network", "initialize_continuing_without_poll_workers");
    }

    try {
        diag::log_tagged("network", "burp_initialize_begin");
        bool burp_ok = aida::burp::initialize();
        diag::log_tagged_fmt("network", "burp_initialize_result ok=%d", burp_ok ? 1 : 0);
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "burp_initialize_cpp_exception what=%s", e.what());
    } catch (...) {
        diag::log_tagged("network", "burp_initialize_unknown_exception");
    }

    diag::log_tagged("network", "initialize_complete");
#endif
}

void shutdown() {
    s_accept_ui_completions.store(false, std::memory_order_release);
    reset_common_exchange_actions();
    {
        std::lock_guard<std::mutex> lock(s_ui_completion_mutex);
        s_ui_completions.clear();
    }
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    aida::preview::network::shutdown(g_state);
    return;
#else
    diag::log_tagged("network", "shutdown_begin");
    diag::log_tagged("net_audit", "[net_audit] network_view shutdown begin");
    mitm_proxy::set_ws_frame_callback(nullptr);
    g_state.conn_polling.store(false);
    g_state.conn_cv.notify_all();
    g_state.bw_polling.store(false);
    g_state.bw_thread_alive.store(false);
    g_state.bw_cv.notify_all();

    g_state.cap_polling.store(false);
    g_state.cap_running.store(false, std::memory_order_release);
    g_state.cap_start_pending.store(false, std::memory_order_release);
    g_state.cap_stop_pending.store(false, std::memory_order_release);
    g_state.cap_thread_alive.store(false);
    g_state.cap_cv.notify_all();

    g_state.dns_polling.store(false);
    g_state.dns_thread_alive.store(false);
    g_state.dns_cv.notify_all();

    g_state.fuzz_cancel_requested.store(true, std::memory_order_release);
    g_state.fuzz_running.store(false);
    g_state.fuzz_thread_alive.store(false);
    g_state.fuzz_cv.notify_all();

    auto wait_done = [](const char* name, const std::atomic<bool>& done_flag) {
        const uint64_t begin = static_cast<uint64_t>(GetTickCount64());
        while (!done_flag.load(std::memory_order_acquire)) {
            const uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - begin;
            if (elapsed >= 2500) {
                diag::log_tagged_fmt("network", "shutdown_wait_timeout worker=%s elapsed_ms=%llu",
                    name ? name : "<unnamed>",
                    static_cast<unsigned long long>(elapsed));
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        diag::log_tagged_fmt("network", "shutdown_wait_done worker=%s elapsed_ms=%llu",
            name ? name : "<unnamed>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - begin));
    };
    auto wait_done_before_dependency_teardown = [](const char* name,
                                                   const std::atomic<bool>& done_flag) {
        const uint64_t begin = static_cast<uint64_t>(GetTickCount64());
        uint64_t next_report = 2500;
        while (!done_flag.load(std::memory_order_acquire)) {
            const uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - begin;
            if (elapsed >= next_report) {
                diag::log_tagged_fmt("network",
                    "shutdown_dependency_drain_pending worker=%s elapsed_ms=%llu",
                    name ? name : "<unnamed>",
                    static_cast<unsigned long long>(elapsed));
                next_report = elapsed + 2500;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        diag::log_tagged_fmt("network",
            "shutdown_dependency_drain_done worker=%s elapsed_ms=%llu",
            name ? name : "<unnamed>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - begin));
    };
    wait_done("conn", g_state.conn_thread_done);
    wait_done("capture", g_state.cap_thread_done);
    wait_done("dns", g_state.dns_thread_done);
    wait_done("bandwidth", g_state.bw_thread_done);
    wait_done_before_dependency_teardown("fuzzer", g_state.fuzz_thread_done);

    aida::burp::shutdown();

    mitm_proxy::shutdown();
    ssl_keylog::stop_watching();
    g_state.active = false;
    diag::log_tagged("network", "shutdown_complete");
#endif
}


static const char* tab_names[] = {
    "Connections", "Capture", "Intercept", "Proxy",
    "DNS", "Filters", "Bandwidth", "Repeater", "KeyLog",
    "PCAP", "Fuzzer", "Offensive", "WebSocket", "Scripting", "Decoder",
    "Site Map", "Scope", "Cookies", "Scanner", "Recon",
    "Intruder", "Collaborator", "Sequencer", "Comparer",
    "JWT Lab", "Match/Replace", "Session", "API",
    "WS Editor", "H/2 Editor", "Logger", "CSP",
    "Upstream", "Browser", "Reports", "Headless"
};

static const char* tab_short_names[] = {
    "Conn", "Cap", "Int", "Prx",
    "DNS", "Filt", "BW", "Rep", "KL",
    "PCAP", "Fuz", "Off", "WS", "Scr", "Dec",
    "Site", "Scope", "Cook", "Scan", "Recon",
    "Intr", "Collab", "Seq", "Cmp",
    "JWT", "M/R", "Sess", "API",
    "WSe", "H2e", "Log", "CSP",
    "Up", "Brw", "Rpt", "HL"
};

static const sub_tab_t k_monitor_tabs[] = {
    sub_tab_t::connections,
    sub_tab_t::capture,
    sub_tab_t::dns,
    sub_tab_t::filters,
    sub_tab_t::bandwidth,
    sub_tab_t::keylog,
    sub_tab_t::pcap_export
};

static const sub_tab_t k_proxy_tabs[] = {
    sub_tab_t::proxy,
    sub_tab_t::intercept,
    sub_tab_t::repeater,
    sub_tab_t::logger,
    sub_tab_t::scope,
    sub_tab_t::cookies,
    sub_tab_t::upstream
};

static const sub_tab_t k_web_tabs[] = {
    sub_tab_t::browser,
    sub_tab_t::headless,
    sub_tab_t::sitemap,
    sub_tab_t::recon,
    sub_tab_t::scanner,
    sub_tab_t::reports,
    sub_tab_t::csp
};

static const sub_tab_t k_api_tabs[] = {
    sub_tab_t::api
};

static const sub_tab_t k_attack_tabs[] = {
    sub_tab_t::intruder,
    sub_tab_t::fuzzer,
    sub_tab_t::offensive,
    sub_tab_t::jwt,
    sub_tab_t::mr,
    sub_tab_t::session,
    sub_tab_t::collab,
    sub_tab_t::sequencer,
    sub_tab_t::comparer
};

static const sub_tab_t k_protocol_tabs[] = {
    sub_tab_t::websocket,
    sub_tab_t::ws_edit,
    sub_tab_t::h2_edit,
    sub_tab_t::decoder
};

static const sub_tab_t k_automation_tabs[] = {
    sub_tab_t::scripting
};

struct nav_group_t {
    const char* label;
    const char* short_label;
    const char* status;
    const sub_tab_t* tabs;
    int tab_count;
};

static const nav_group_t k_nav_groups[] = {
    { "Monitor", "Mon", "Driver capture and packet evidence", k_monitor_tabs, static_cast<int>(sizeof(k_monitor_tabs) / sizeof(k_monitor_tabs[0])) },
    { "Proxy", "Proxy", "MITM, intercept, replay, logs, and scope", k_proxy_tabs, static_cast<int>(sizeof(k_proxy_tabs) / sizeof(k_proxy_tabs[0])) },
    { "Web", "Web", "Camoufox-only browser automation and web scans", k_web_tabs, static_cast<int>(sizeof(k_web_tabs) / sizeof(k_web_tabs[0])) },
    { "API", "API", "API request workbench", k_api_tabs, static_cast<int>(sizeof(k_api_tabs) / sizeof(k_api_tabs[0])) },
    { "Attack", "Attack", "Fuzzing, sessions, tokens, and comparison tools", k_attack_tabs, static_cast<int>(sizeof(k_attack_tabs) / sizeof(k_attack_tabs[0])) },
    { "Protocol", "Proto", "WebSocket, HTTP/2, and decoding tools", k_protocol_tabs, static_cast<int>(sizeof(k_protocol_tabs) / sizeof(k_protocol_tabs[0])) },
    { "Automation", "Auto", "Network scripting and workflow automation", k_automation_tabs, static_cast<int>(sizeof(k_automation_tabs) / sizeof(k_automation_tabs[0])) }
};

static int nav_group_count() {
    return static_cast<int>(sizeof(k_nav_groups) / sizeof(k_nav_groups[0]));
}

static int nav_group_for_tab(sub_tab_t tab) {
    for (int g = 0; g < nav_group_count(); ++g) {
        const nav_group_t& group = k_nav_groups[g];
        for (int i = 0; i < group.tab_count; ++i) {
            if (group.tabs[i] == tab) return g;
        }
    }
    return 0;
}

static int tab_index_in_group(const nav_group_t& group, sub_tab_t tab) {
    for (int i = 0; i < group.tab_count; ++i) {
        if (group.tabs[i] == tab) return i;
    }
    return 0;
}

static bool tab_requires_target(sub_tab_t tab) {
    switch (tab) {
        case sub_tab_t::connections:
        case sub_tab_t::capture:
        case sub_tab_t::dns:
        case sub_tab_t::filters:
        case sub_tab_t::bandwidth:
        case sub_tab_t::keylog:
        case sub_tab_t::pcap_export:
            return true;
        default:
            return false;
    }
}

static float estimate_chip_w(const char* label, float pad) {
    return ImGui::CalcTextSize(label ? label : "").x + pad;
}

static bool same_line_if_fits(float next_w, float spacing = 8.f) {
    if (ImGui::GetContentRegionAvail().x >= next_w + spacing) {
        ImGui::SameLine(0.f, spacing);
        return true;
    }
    return false;
}

static void clipped_text(const char* text, ImU32 color, float max_w = 0.f) {
    const char* safe = text ? text : "";
    bool clipped = max_w > 0.f && ImGui::CalcTextSize(safe).x > max_w;
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(color));
    ImGui::TextUnformatted(safe);
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered() && clipped) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(safe);
        ImGui::EndTooltip();
    }
}

static void table_text(const std::string& text, ImU32 color) {
    clipped_text(text.c_str(), color, ImGui::GetContentRegionAvail().x);
}

static void table_text(const char* text, ImU32 color) {
    clipped_text(text ? text : "", color, ImGui::GetContentRegionAvail().x);
}

static std::string payload_display_text(const std::vector<uint8_t>& bytes, size_t cap = 262144) {
    std::string out;
    size_t n = std::min(bytes.size(), cap);
    out.reserve(n + 64);
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = bytes[i];
        if (b == '\r' || b == '\n' || b == '\t' || (b >= 32 && b < 127))
            out.push_back(static_cast<char>(b));
        else
            out.push_back('.');
    }
    if (bytes.size() > n) {
        out += "\n[truncated ";
        out += std::to_string(bytes.size() - n);
        out += " bytes]";
    }
    return out;
}

static void render_payload_box(const char* id, const char* title, const std::string& meta,
                               const std::string& text, ImVec2 size,
                               const aida::ui::theme_t& th, float alpha) {
    ImGui::BeginChild(id, size, true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(title ? title : "");
    if (!meta.empty()) {
        ImGui::SameLine();
        ImGui::TextUnformatted(meta.c_str());
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy")) {
        ImGui::SetClipboardText(text.c_str());
    }
    ImGui::Separator();
    ImFont* code_font = aida::ui::fonts::code();
    bool pushed = false;
    if (code_font) {
        ImGui::PushFont(code_font);
        pushed = true;
    }
    ImGui::TextUnformatted(text.empty() ? "(empty)" : text.c_str());
    if (pushed)
        ImGui::PopFont();
    ImGui::EndChild();
}

static float render_no_target_banner(float x, float y, float w, float alpha) {
    (void)alpha;
    const char* msg = w < 620.f
        ? "Driver capture is unavailable. Web, proxy, API, protocol, and Camoufox tools remain ready."
        : "Driver capture and native process diagnostics are unavailable. Web, proxy, API, protocol, and Camoufox tools remain ready.";
    ImGui::SetCursorPos(ImVec2(x, y));
    aida::ui::components::inline_notice("network_no_target_notice", "No target attached", msg,
        aida::ui::components::status_kind_t::warning);
    return 60.f;
}

static float render_tab_bar(state_t& state, float x, float y, float w, float alpha,
                            float ar, float ag, float ab, float dt) {
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();

    const float primary_h = aida::ui::metrics::tab::primary_h;
    const float secondary_h = aida::ui::metrics::tab::inner_h;
    const float gap_h = aida::ui::metrics::spacing::xs;
    const float nav_h = primary_h + secondary_h + gap_h;
    const int group_count = nav_group_count();
    const int active_group_idx = nav_group_for_tab(state.active_tab);
    const nav_group_t& active_group = k_nav_groups[active_group_idx];

    float nav_x0 = origin.x + x;
    float nav_x1 = origin.x + x + w;
    float nav_y0 = origin.y + y;
    float nav_y1 = origin.y + y + primary_h;
    float second_y0 = nav_y1 + gap_h;
    float second_y1 = second_y0 + secondary_h;

    (void)ar;
    (void)ag;
    (void)ab;
    dl->AddRectFilled(ImVec2(nav_x0, nav_y0), ImVec2(nav_x1, second_y1),
        aida::ui::with_alpha(th.bg_elevated, alpha), aida::ui::metrics::radius::md);
    dl->AddRect(ImVec2(nav_x0, nav_y0), ImVec2(nav_x1, second_y1),
        aida::ui::with_alpha(th.border_subtle, alpha), aida::ui::metrics::radius::md, 0,
        aida::ui::metrics::panel::border);

    float primary_total = 0.f;
    float primary_full[16] = {};
    float primary_short[16] = {};
    for (int i = 0; i < group_count; ++i) {
        primary_full[i] = std::max(64.f, ImGui::CalcTextSize(k_nav_groups[i].label).x + 26.f);
        primary_short[i] = std::max(44.f, ImGui::CalcTextSize(k_nav_groups[i].short_label).x + 20.f);
        primary_total += primary_full[i];
    }
    const bool primary_equal = primary_total > w;
    const bool primary_short_labels = primary_equal || w < 720.f;
    float gx = nav_x0;
    static aida::ui::hover_state_t s_group_hover[16];
    static aida::ui::press_state_t s_group_press[16];
    for (int i = 0; i < group_count; ++i) {
        float gw = primary_equal ? w / static_cast<float>(group_count)
                                 : primary_full[i];
        if (i == group_count - 1)
            gw = nav_x1 - gx;
        bool active = i == active_group_idx;
        ImVec2 a(gx, nav_y0 + 3.f);
        ImVec2 b(gx + gw - 2.f, nav_y1 - 3.f);
        ImGui::SetCursorScreenPos(a);
        ImGui::PushID(0x4E475250 + i);
        ImGui::InvisibleButton("##network_group", ImVec2(std::max(1.f, b.x - a.x), std::max(1.f, b.y - a.y)));
        bool hovered = ImGui::IsItemHovered();
        bool pressed = hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            sub_tab_t next_tab = k_nav_groups[i].tabs[0];
            if (state.active_tab != next_tab) {
                state.prev_tab = state.active_tab;
                state.content_fade = 0.f;
            }
            state.active_tab = next_tab;
        }
        ImGui::PopID();

        float hv = s_group_hover[i].tick(hovered, dt, aida::motion::spring::balanced);
        float pv = s_group_press[i].tick(pressed, dt);
        if (active) {
            dl->AddRectFilled(a, b, aida::ui::with_alpha(th.selection, alpha), aida::ui::metrics::radius::sm);
            dl->AddRect(a, b, aida::ui::with_alpha(th.accent_u32, alpha * 0.55f), aida::ui::metrics::radius::sm, 0, 1.f);
        } else if (hv > 0.001f) {
            dl->AddRectFilled(a, b, aida::ui::with_alpha(th.hover_wash, alpha * hv), 7.f);
        }
        const char* label = primary_short_labels ? k_nav_groups[i].short_label : k_nav_groups[i].label;
        ImVec2 ts = ImGui::CalcTextSize(label);
        ImU32 text_col = active
            ? aida::ui::with_alpha(th.text_primary, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha * (0.70f + 0.25f * hv));
        ImVec2 ta(a.x + std::max(8.f, (gw - ts.x) * 0.5f), a.y + (b.y - a.y - ts.y) * 0.5f - pv * 0.5f);
        dl->PushClipRect(a, b, true);
        dl->AddText(ta, text_col, label);
        dl->PopClipRect();
        if (hovered) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(k_nav_groups[i].label);
            ImGui::TextUnformatted(k_nav_groups[i].status);
            ImGui::EndTooltip();
        }
        gx += gw;
    }

    if (w >= 760.f) {
        const char* status = active_group.status;
        ImVec2 ss = ImGui::CalcTextSize(status);
        float sx = nav_x1 - ss.x - 12.f;
        if (sx > nav_x0 + primary_total + 16.f) {
            dl->AddText(ImVec2(sx, nav_y0 + (primary_h - ss.y) * 0.5f),
                        aida::ui::with_alpha(th.text_dim, alpha), status);
        }
    }
    dl->AddLine(ImVec2(nav_x0, nav_y1), ImVec2(nav_x1, nav_y1),
                aida::ui::with_alpha(th.border_subtle, alpha));

    dl->AddRectFilled(ImVec2(nav_x0 + 1.f, second_y0), ImVec2(nav_x1 - 1.f, second_y1 - 1.f),
                      aida::ui::with_alpha(th.panel_bg, alpha * 0.62f));

    const int count = active_group.tab_count;
    float total_w = 0.f;
    float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
    float tab_offsets[static_cast<int>(sub_tab_t::COUNT)];
    for (int i = 0; i < count; i++) {
        int tab_idx = static_cast<int>(active_group.tabs[i]);
        const char* full = tab_names[tab_idx];
        const char* short_name = tab_short_names[tab_idx];
        bool use_short_preview = (w < 520.f);
        const char* lbl = use_short_preview ? short_name : full;
        tab_widths[i] = ImGui::CalcTextSize(lbl).x + (use_short_preview ? 18.f : 22.f);
        tab_offsets[i] = total_w;
        total_w += tab_widths[i] + 2.f;
    }

    float view_x0 = nav_x0;
    float view_x1 = nav_x1;
    if (total_w > w) {
        view_x0 += 28.f;
        view_x1 -= 28.f;
    }
    float view_w = std::max(1.f, view_x1 - view_x0);

    static int s_last_group_idx = -1;
    if (s_last_group_idx != active_group_idx) {
        state.tab_scroll_x = 0.f;
        state.tab_target_scroll_x = 0.f;
        state.tab_last_ensured = -1;
        s_last_group_idx = active_group_idx;
    }

    if (ImGui::IsMouseHoveringRect(ImVec2(view_x0, second_y0), ImVec2(view_x1, second_y1), false)) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            state.tab_target_scroll_x -= wheel * 60.f;
    }

    float max_scroll = std::max(0.f, total_w - view_w);
    state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
    state.tab_scroll_x = ui_anim::smooth_lerp(state.tab_scroll_x, state.tab_target_scroll_x, 14.f, dt);

    int active_idx = tab_index_in_group(active_group, state.active_tab);
    int active_tab_int = static_cast<int>(state.active_tab);
    if (state.tab_last_ensured != active_tab_int) {
        float active_left = tab_offsets[active_idx] - state.tab_scroll_x;
        float active_right = active_left + tab_widths[active_idx];
        if (active_left < 0.f)
            state.tab_target_scroll_x = tab_offsets[active_idx];
        else if (active_right > view_w)
            state.tab_target_scroll_x = tab_offsets[active_idx] + tab_widths[active_idx] - view_w;
        state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
        state.tab_last_ensured = active_tab_int;
    }

    float target_ux = view_x0 + tab_offsets[active_idx] - state.tab_scroll_x + 6.f;
    float target_uw = tab_widths[active_idx] - 12.f;
    if (state.underline_w < 0.1f) {
        state.underline_x = target_ux;
        state.underline_w = target_uw;
    }
    state.underline_x = ui_anim::spring_interp(state.underline_x, target_ux, state.underline_vel, 280.f, 22.f, dt);
    state.underline_w = ui_anim::smooth_lerp(state.underline_w, target_uw, 16.f, dt);

    ImGui::PushClipRect(ImVec2(view_x0, second_y0), ImVec2(view_x1, second_y1), true);

    static aida::ui::hover_state_t s_tab_hover[static_cast<int>(sub_tab_t::COUNT)];
    static aida::ui::press_state_t s_tab_press[static_cast<int>(sub_tab_t::COUNT)];

    for (int i = 0; i < count; i++) {
        int tab_idx = static_cast<int>(active_group.tabs[i]);
        float bx0 = view_x0 + tab_offsets[i] - state.tab_scroll_x;
        float bx1 = bx0 + tab_widths[i];
        float by0 = second_y0;
        float by1 = second_y1;
        bool is_active = active_group.tabs[i] == state.active_tab;

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);
        bool pressed = hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (state.active_tab != active_group.tabs[i]) {
                state.prev_tab = state.active_tab;
                state.content_fade = 0.f;
            }
            state.active_tab = active_group.tabs[i];
        }

        float hov_v = s_tab_hover[tab_idx].tick(hovered, dt, aida::motion::spring::balanced);
        float prs_v = s_tab_press[tab_idx].tick(pressed, dt);
        float scale = 1.f - (1.f - 0.96f) * prs_v;
        float pad_x = (1.f - scale) * tab_widths[i] * 0.5f;
        float pad_y = (1.f - scale) * secondary_h * 0.5f;

        if (is_active) {
            ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, 0.22f * alpha);
            ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, 0.16f * alpha);
            dl->AddRectFilledMultiColor(
                ImVec2(bx0 + pad_x + 4.f, by0 + pad_y + 4.f),
                ImVec2(bx1 - pad_x - 4.f, by1 - pad_y - 4.f),
                fill_top, fill_top, fill_bot, fill_bot);
        } else if (hov_v > 0.001f) {
            dl->AddRectFilled(
                ImVec2(bx0 + pad_x + 4.f, by0 + pad_y + 4.f),
                ImVec2(bx1 - pad_x - 4.f, by1 - pad_y - 4.f),
                aida::ui::with_alpha(th.hover_wash, hov_v * alpha), 8.f);
        }

        bool use_short = (w < 520.f);
        const char* draw_label = use_short ? tab_short_names[tab_idx] : tab_names[tab_idx];
        ImVec2 ts = ImGui::CalcTextSize(draw_label);
        ImU32 text_col = is_active
            ? aida::ui::with_alpha(th.text_primary, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha * (0.65f + 0.30f * hov_v));
        dl->AddText(ImVec2(bx0 + (tab_widths[i] - ts.x) * 0.5f, by0 + (secondary_h - ts.y) * 0.5f - prs_v * 0.5f),
            text_col, draw_label);

        if (use_short && hovered) {
            if (ImGui::BeginTooltip()) {
                ImGui::TextUnformatted(tab_names[tab_idx]);
                ImGui::EndTooltip();
            }
        }
    }

    ui_anim::render_tab_underline_glow(dl, state.underline_x, state.underline_w,
        second_y1 - 3.f, alpha);

    ImGui::PopClipRect();

    if (state.tab_scroll_x > 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(view_x0, second_y0), ImVec2(view_x0 + 30.f, second_y1),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f));
    }
    if (state.tab_scroll_x < max_scroll - 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(view_x1 - 30.f, second_y0), ImVec2(view_x1, second_y1),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, 0.f));
    }

    if (max_scroll > 1.f) {
        ImGui::SetCursorScreenPos(ImVec2(nav_x0 + 2.f, second_y0 + 2.f));
        ImGui::PushID("net_tabs_left");
        ImGui::BeginDisabled(state.tab_target_scroll_x <= 1.f);
        if (ImGui::InvisibleButton("##left", ImVec2(22.f, secondary_h - 4.f)))
            state.tab_target_scroll_x = std::max(0.f, state.tab_target_scroll_x - view_w * 0.6f);
        ImGui::EndDisabled();
        ImGui::PopID();
        dl->AddText(ImVec2(nav_x0 + 10.f, second_y0 + 7.f),
                    aida::ui::with_alpha(state.tab_target_scroll_x <= 1.f ? th.text_dim : th.text_secondary, alpha), "<");

        ImGui::SetCursorScreenPos(ImVec2(nav_x1 - 24.f, second_y0 + 2.f));
        ImGui::PushID("net_tabs_right");
        ImGui::BeginDisabled(state.tab_target_scroll_x >= max_scroll - 1.f);
        if (ImGui::InvisibleButton("##right", ImVec2(22.f, secondary_h - 4.f)))
            state.tab_target_scroll_x = std::min(max_scroll, state.tab_target_scroll_x + view_w * 0.6f);
        ImGui::EndDisabled();
        ImGui::PopID();
        dl->AddText(ImVec2(nav_x1 - 16.f, second_y0 + 7.f),
                    aida::ui::with_alpha(state.tab_target_scroll_x >= max_scroll - 1.f ? th.text_dim : th.text_secondary, alpha), ">");
    }

    dl->AddLine(
        ImVec2(origin.x + x, second_y1),
        ImVec2(origin.x + x + w, second_y1),
        aida::ui::with_alpha(th.border_subtle, alpha));

    return nav_h;
}


template <typename RawConnections>
static std::vector<connection_entry_t> convert_connection_entries(RawConnections&& raw_connections) {
    std::vector<connection_entry_t> entries;
    entries.reserve(raw_connections.size());
    for (auto& connection : raw_connections) {
        connection_entry_t entry;
        entry.pid = connection.pid;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        entry.protocol = static_cast<std::uint8_t>((std::min)(connection.protocol, static_cast<std::uint32_t>(UINT8_MAX)));
        entry.state = static_cast<std::uint8_t>((std::min)(connection.state, static_cast<std::uint32_t>(UINT8_MAX)));
        entry.local_port = static_cast<std::uint16_t>((std::min)(connection.local_port, static_cast<std::uint32_t>(UINT16_MAX)));
        entry.remote_port = static_cast<std::uint16_t>((std::min)(connection.remote_port, static_cast<std::uint32_t>(UINT16_MAX)));
        entry.address_family = static_cast<std::uint8_t>((std::min)(connection.address_family, static_cast<std::uint32_t>(UINT8_MAX)));
#else
        entry.protocol = connection.protocol;
        entry.state = connection.state;
        entry.local_port = connection.local_port;
        entry.remote_port = connection.remote_port;
        entry.address_family = connection.address_family;
#endif
        std::memcpy(entry.local_addr, connection.local_addr, sizeof(entry.local_addr));
        std::memcpy(entry.remote_addr, connection.remote_addr, sizeof(entry.remote_addr));
        entries.push_back(std::move(entry));
    }
    return entries;
}

static void request_connection_refresh(state_t& state) {
    bool expected = false;
    if (!state.conn_refresh_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.conn_refresh_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint32_t filter_pid = state.conn_filter_pid;
    const std::uint8_t filter_protocol = state.conn_filter_protocol;
    const std::string task_id = register_network_operation(
        "network.connections.refresh", "Refresh network connections",
        "view.network.connections", "driver connection table");
    const bool posted = post_network_task(
        "connection_refresh", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, filter_pid, filter_protocol, task_id]() {
            bool success = false;
            std::string error;
            std::vector<connection_entry_t> entries;
            try {
                if (!driver_feature_ready("connection_refresh")) {
                    error = "Driver connection enumeration is unavailable";
                } else {
                    auto raw = driver_bridge::enumerate_connections(filter_pid, filter_protocol);
                    entries = convert_connection_entries(std::move(raw));
                    success = true;
                }
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Connection enumeration failed";
            }
            if (success && g_state.conn_refresh_serial.load(std::memory_order_acquire) == serial)
                publish_connection_snapshot(g_state, entries);
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(entries.size()) + " connections published" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.conn_refresh_serial.load(std::memory_order_acquire) != serial)
                    return;
                g_state.conn_refresh_pending.store(false, std::memory_order_release);
                if (!success)
                    toast_notification::push(error.empty() ? "Connection refresh failed" : error,
                        toast_notification::toast_type_t::error);
            });
        }, false);
    if (!posted) {
        state.conn_refresh_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected connection refresh");
    }
}

static void render_connections(state_t& state, float x, float y, float w, float h,
                                 float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_conn", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_driver_available_snapshot();
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);

    float conn_toolbar_avail = ImGui::GetContentRegionAvail().x;
    bool conn_toolbar_narrow = (conn_toolbar_avail < 560.f);
    float search_w = conn_toolbar_narrow
        ? (std::max)(conn_toolbar_avail - 240.f, 140.f)
        : 280.f;
    aida::ui::input_text("##conn_search", state.conn_filter_text, sizeof(state.conn_filter_text),
                          "Filter by PID, host, port...", false, ImVec2(search_w, 32.f));
    if (conn_toolbar_narrow && conn_toolbar_avail < 360.f) {
        static bool s_logged_conn_narrow = false;
        if (!s_logged_conn_narrow) {
            s_logged_conn_narrow = true;
            ::diag::log_tagged_fmt("responsive",
                "network_view connections toolbar avail=%.0f wrap=1", conn_toolbar_avail);
        }
    }
    ImGui::SameLine();
    if (!driver_ok) ImGui::BeginDisabled();
    bool prev_auto = state.conn_auto_refresh;
    aida::ui::toggle_switch("Auto refresh##conn_auto", &state.conn_auto_refresh);
    state.conn_auto_refresh_enabled.store(state.conn_auto_refresh, std::memory_order_release);
    if (prev_auto != state.conn_auto_refresh) {
        diag::log_tagged_fmt("network", "connections_auto_refresh_toggled enabled=%d",
            state.conn_auto_refresh ? 1 : 0);
        state.conn_cv.notify_all();
    }
    ImGui::SameLine();
    const bool refresh_pending = state.conn_refresh_pending.load(std::memory_order_acquire);
    if (aida::ui::button(refresh_pending ? "Refreshing...##conn_refresh" : "Refresh##conn_refresh",
                         aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), refresh_pending)) {
        diag::log_tagged_fmt("network", "connections_refresh_clicked drv_ok=%d filter_pid=%u filter_proto=%u",
            driver_ok ? 1 : 0, state.conn_filter_pid, state.conn_filter_protocol);
        if (driver_ok)
            request_connection_refresh(state);
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    const auto connections = std::atomic_load_explicit(&state.connection_snapshot, std::memory_order_acquire);
    const size_t conn_count = connections ? connections->size() : 0;
    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%zu connections", conn_count);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "%s", count_buf);

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;


    float col_pid = 64.f, col_proto = 50.f, col_state = 110.f;
    float remain_w = w - col_pid - col_proto - col_state - 24.f;
    if (remain_w < 120.f) {
        if (w < 280.f) {
            col_proto = 40.f;
            col_state = 70.f;
        }
        remain_w = w - col_pid - col_proto - col_state - 24.f;
        if (remain_w < 80.f) remain_w = 80.f;
    }
    float col_local = remain_w * 0.5f;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");    cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Proto");  cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "State");  cx += col_state;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Local");  cx += col_local;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Remote");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);


    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##conn_list", ImVec2(w - 4.f, list_h), false,
                      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_AlwaysVerticalScrollbar);

    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);
    int conn_visible_row = 0;

    if (!connections || connections->empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        ImGui::SetCursorPos(ImVec2(x, ImGui::GetCursorPos().y - list_h));
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No active connections";
        cfg.body  = driver_ok
            ? "Connections will appear once the kernel driver enumerates them."
            : "Kernel driver not attached. Some features are unavailable.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, 0.f));
        ImGui::EndChild();
        return;
    }

    static std::shared_ptr<const std::vector<connection_entry_t>> filtered_snapshot;
    static std::string filtered_query;
    static std::vector<int> filtered_indices;
    const std::string current_query(state.conn_filter_text);
    if (filtered_snapshot != connections || filtered_query != current_query) {
        filtered_snapshot = connections;
        filtered_query = current_query;
        filtered_indices.clear();
        filtered_indices.reserve(connections->size());
        for (int i = 0; i < static_cast<int>(connections->size()); ++i) {
            const auto& connection = (*connections)[static_cast<std::size_t>(i)];
            if (connection.pid == 0 && connection.protocol == 0 && connection.local_port == 0 && connection.remote_port == 0)
                continue;
            if (!current_query.empty()) {
                const std::string local = format_ip(connection.local_addr, connection.address_family) + ":" + std::to_string(connection.local_port);
                const std::string remote = format_ip(connection.remote_addr, connection.address_family) + ":" + std::to_string(connection.remote_port);
                const std::string searchable = std::to_string(connection.pid) + " " + protocol_name(connection.protocol) + " " +
                    tcp_state_name(connection.state) + " " + local + " " + remote;
                if (!filter_text_match(current_query.c_str(), searchable))
                    continue;
            }
            filtered_indices.push_back(i);
        }
    }
    ImGuiListClipper connection_clipper;
    connection_clipper.Begin(static_cast<int>(filtered_indices.size()), row_h);
    while (connection_clipper.Step()) {
    for (int visible_index = connection_clipper.DisplayStart; visible_index < connection_clipper.DisplayEnd; ++visible_index) {
        const int i = filtered_indices[static_cast<std::size_t>(visible_index)];
        const auto& c = (*connections)[static_cast<size_t>(i)];

        std::string local_str = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        std::string remote_str = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);

        float row_alpha = 1.f;
        float row_xoff = 0.f;
        compute_row_entrance(s_conn_rows, filtered_indices.size(), row_alpha, row_xoff, visible_index);
        float r_alpha = alpha * row_alpha;

        float abs_ry = ImGui::GetCursorScreenPos().y;

        if (conn_visible_row & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.35f));

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.conn_selected == i);

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, r_alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 2.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_dim, r_alpha));
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.conn_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);

        cx = list_org.x + 8.f + row_xoff;
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%u", c.pid);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, pid_buf);                            cx += col_pid;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, protocol_name(c.protocol));          cx += col_proto;


        aida::ui::pill_kind_t state_kind = tcp_state_to_pill(c.state);
        ImU32 pill_col;
        switch (state_kind) {
            case aida::ui::pill_kind_t::success: pill_col = th.success; break;
            case aida::ui::pill_kind_t::warning: pill_col = th.warning; break;
            case aida::ui::pill_kind_t::error:   pill_col = th.error;   break;
            case aida::ui::pill_kind_t::info:    pill_col = th.info;    break;
            case aida::ui::pill_kind_t::accent:  pill_col = th.accent_u32; break;
            default:                              pill_col = th.text_secondary; break;
        }
        const char* sname = tcp_state_name(c.state);
        ImFont* pill_font = ImGui::GetFont();
        float pill_fs = ImGui::GetFontSize() - 2.f;
        ImVec2 ts = pill_font->CalcTextSizeA(pill_fs, FLT_MAX, 0.f, sname);
        float pill_pad = 7.f;
        float pill_h = pill_fs + 4.f;
        float pill_w = ts.x + pill_pad * 2.f;
        float pill_x = cx;
        float pill_y = abs_ry + (row_h - pill_h) * 0.5f;
        dl->AddRectFilled(ImVec2(pill_x, pill_y), ImVec2(pill_x + pill_w, pill_y + pill_h),
                          aida::ui::with_alpha(pill_col, 0.20f * r_alpha), pill_h * 0.5f);
        dl->AddRect(ImVec2(pill_x, pill_y), ImVec2(pill_x + pill_w, pill_y + pill_h),
                     aida::ui::with_alpha(pill_col, 0.55f * r_alpha), pill_h * 0.5f, 0, 1.f);
        dl->AddText(pill_font, pill_fs, ImVec2(pill_x + pill_pad, pill_y + (pill_h - pill_fs) * 0.5f),
                     aida::ui::with_alpha(pill_col, r_alpha), sname);
        cx += col_state;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, local_str.c_str());                  cx += col_local;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, remote_str.c_str());

        conn_visible_row++;
        ImGui::Dummy(ImVec2(1.f, (std::max)(1.f, row_h - ImGui::GetStyle().ItemSpacing.y)));
    }
    }

    ImGui::Dummy(ImVec2(0.f, 0.f));
    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void request_capture_start(state_t& state) {
    bool expected = false;
    if (!state.cap_start_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged("network", "start_capture_ignored_already_pending");
        return;
    }
    set_capture_control_status("Starting capture...");
    uint32_t filter_pid = state.cap_filter_pid;
    uint32_t filter_port = static_cast<uint32_t>(state.cap_filter_port);
    uint32_t filter_protocol = state.cap_filter_protocol;
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);
    if (!driver_ok) {
        set_capture_control_status("Capture unavailable until the kernel driver is ready");
        state.cap_start_pending.store(false, std::memory_order_release);
        return;
    }
    bool poll_ready = start_capture_worker(state);
    diag::log_tagged_fmt("network",
        "start_capture_requested filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d poll_ready=%d cap_thread_done=%d cap_thread_alive=%d",
        filter_pid, filter_port, filter_protocol,
        driver_ok ? 1 : 0,
        poll_ready ? 1 : 0,
        state.cap_thread_done.load(std::memory_order_acquire) ? 1 : 0,
        state.cap_thread_alive.load(std::memory_order_acquire) ? 1 : 0);
    if (!poll_ready) {
        set_capture_control_status("Capture worker unavailable");
        state.cap_start_pending.store(false, std::memory_order_release);
        return;
    }

    if (!post_network_task("capture_start_control", aida::infra::executor::domain_t::feature_worker, "bounded_task", [filter_pid, filter_port, filter_protocol]() {
            ULONGLONG t0 = GetTickCount64();
            bool ok = false;
            try {
                ok = driver_feature_ready("start_capture_async") &&
                     driver_bridge::start_capture(filter_pid, filter_port, filter_protocol, nullptr);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "start_capture_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "start_capture_unknown_exception");
            }
            ULONGLONG elapsed = GetTickCount64() - t0;
            if (ok) {
                g_state.cap_running.store(true, std::memory_order_release);
                g_state.cap_polling.store(true, std::memory_order_release);
                g_state.cap_cv.notify_all();
                set_capture_control_status("Capture running");
                diag::log_tagged_fmt("network", "start_capture_ok async elapsed_ms=%llu poll_thread_signaled=%d",
                    static_cast<unsigned long long>(elapsed),
                    g_state.cap_thread_alive.load(std::memory_order_acquire) ? 1 : 0);
                diag::log_tagged("net_audit",
                    "[net_audit] capture started ok");
            } else {
                set_capture_control_status("Capture start failed");
                diag::log_tagged_fmt("network", "start_capture_failed async elapsed_ms=%llu kernel_mode=%d",
                    static_cast<unsigned long long>(elapsed),
                    driver_bridge::using_kernel_driver() ? 1 : 0);
                diag::log_tagged("net_audit",
                    "[net_audit] capture start FAILED driver call returned false");
            }
            g_state.cap_start_pending.store(false, std::memory_order_release);
        })) {
        set_capture_control_status("Capture start queue failed");
        state.cap_start_pending.store(false, std::memory_order_release);
    }
}

static void request_capture_stop(state_t& state) {
    bool expected = false;
    if (!state.cap_stop_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged("network", "stop_capture_ignored_already_pending");
        return;
    }
    set_capture_control_status("Stopping capture...");
    diag::log_tagged("network", "stop_capture_requested");
    if (!post_network_task("capture_stop_control", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            ULONGLONG t0 = GetTickCount64();
            bool ok = false;
            try {
                ok = driver_bridge::stop_capture();
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "stop_capture_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "stop_capture_unknown_exception");
            }
            ULONGLONG elapsed = GetTickCount64() - t0;
            g_state.cap_running.store(false, std::memory_order_release);
            g_state.cap_polling.store(false, std::memory_order_release);
            set_capture_control_status(ok ? "Capture stopped" : "Capture stop failed");
            diag::log_tagged_fmt("network", "stop_capture_complete ok=%d elapsed_ms=%llu",
                ok ? 1 : 0,
                static_cast<unsigned long long>(elapsed));
            diag::log_tagged("net_audit",
                ok ? "[net_audit] capture stopped by user" : "[net_audit] capture stop FAILED driver call returned false");
            g_state.cap_stop_pending.store(false, std::memory_order_release);
        })) {
        set_capture_control_status("Capture stop queue failed");
        state.cap_stop_pending.store(false, std::memory_order_release);
    }
}


static void render_capture(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_cap", ImVec2(w, h), false,
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::SetScrollY(0.f);

    request_driver_available_snapshot();
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);
    bool cap_running = state.cap_running.load(std::memory_order_acquire);
    bool cap_start_pending = state.cap_start_pending.load(std::memory_order_acquire);
    bool cap_stop_pending = state.cap_stop_pending.load(std::memory_order_acquire);

    const auto packet_snapshot = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
    const size_t pkt_count = packet_snapshot ? packet_snapshot->size() : 0;
    float live_rate = capture_rate_tick(pkt_count);

    char live_buf[64];
    if (cap_running) {
        snprintf(live_buf, sizeof(live_buf), "LIVE  -  %.1f pkt/s", live_rate);
    } else if (cap_start_pending || cap_stop_pending) {
        snprintf(live_buf, sizeof(live_buf), "%s", cap_start_pending ? "STARTING" : "STOPPING");
    } else {
        snprintf(live_buf, sizeof(live_buf), "PAUSED");
    }
    const float live_text_w = ImGui::CalcTextSize(live_buf).x;
    const float live_dot_d = 18.f;
    const float live_pad_x = 10.f;
    const float live_badge_w = live_dot_d + live_text_w + live_pad_x * 2.f + 4.f;

    if (!driver_ok) ImGui::BeginDisabled();
    if (cap_start_pending || cap_stop_pending) ImGui::BeginDisabled();
    if (!cap_running) {
        if (aida::ui::button("Start Capture", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "start_capture_clicked filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d",
                state.cap_filter_pid, state.cap_filter_port, state.cap_filter_protocol,
                driver_ok ? 1 : 0);
            invoke_global_network_action("network.capture.start");
        }
    } else {
        if (aida::ui::button("Stop Capture", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged("network", "stop_capture_clicked");
            invoke_global_network_action("network.capture.stop");
        }
    }
    if (cap_start_pending || cap_stop_pending) ImGui::EndDisabled();
    if (!driver_ok) ImGui::EndDisabled();

    same_line_if_fits(live_badge_w, 8.f);
    {
        ImDrawList* hdr_dl = ImGui::GetWindowDrawList();
        ImVec2 dpos = ImGui::GetCursorScreenPos();
        float bx = dpos.x;
        float by = dpos.y + 4.f;
        float bh = 24.f;

        ImU32 fill_col = cap_running
            ? aida::ui::with_alpha(th.error, 0.18f * alpha)
            : aida::ui::with_alpha(th.text_dim, 0.18f * alpha);
        ImU32 border_col = cap_running
            ? aida::ui::with_alpha(th.error, 0.55f * alpha)
            : aida::ui::with_alpha(th.text_dim, 0.55f * alpha);
        hdr_dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + live_badge_w, by + bh), fill_col, bh * 0.5f);
        hdr_dl->AddRect(ImVec2(bx, by), ImVec2(bx + live_badge_w, by + bh), border_col, bh * 0.5f, 0, 1.f);

        if (cap_running) {
            float pulse = aida::ui::clock::pulse(0.8f, 0.45f, 1.0f);
            ImU32 dot_col = aida::ui::with_alpha(th.error, alpha);
            ImU32 halo_col = aida::ui::with_alpha(th.error, alpha * 0.35f * pulse);
            hdr_dl->AddCircleFilled(ImVec2(bx + live_pad_x + 5.f, by + bh * 0.5f), 6.f, halo_col, 18);
            hdr_dl->AddCircleFilled(ImVec2(bx + live_pad_x + 5.f, by + bh * 0.5f), 4.f, dot_col, 16);
        } else {
            ImU32 dot_col = aida::ui::with_alpha(th.text_dim, alpha);
            hdr_dl->AddCircleFilled(ImVec2(bx + live_pad_x + 5.f, by + bh * 0.5f), 4.f, dot_col, 16);
        }
        ImU32 text_col = cap_running
            ? aida::ui::with_alpha(th.error, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha);
        hdr_dl->AddText(ImVec2(bx + live_pad_x + live_dot_d, by + (bh - ImGui::GetTextLineHeight()) * 0.5f),
                        text_col, live_buf);
        ImGui::Dummy(ImVec2(live_badge_w, bh + 4.f));
    }

    std::string capture_status = capture_control_status();
    if (!capture_status.empty()) {
        same_line_if_fits(std::min(360.f, ImGui::CalcTextSize(capture_status.c_str()).x), 10.f);
        ImGui::AlignTextToFramePadding();
        clipped_text(capture_status.c_str(), aida::ui::with_alpha(th.text_secondary, alpha),
            ImGui::GetContentRegionAvail().x);
    }

    ImGui::Spacing();
    const ImVec4 secondary = ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha));
    const float field_gap = 6.f;
    ImGui::BeginGroup();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(secondary, "PID:");
    ImGui::SameLine(0.f, field_gap);
    {
        int pid_v = static_cast<int>(state.cap_filter_pid);
        ImGui::SetNextItemWidth(80.f);
        if (ImGui::InputInt("##cap_filter_pid", &pid_v, 0, 0, ImGuiInputTextFlags_CharsDecimal)) {
            if (pid_v < 0) pid_v = 0;
            state.cap_filter_pid = static_cast<uint32_t>(pid_v);
        }
    }
    ImGui::EndGroup();

    same_line_if_fits(ImGui::CalcTextSize("Port:").x + field_gap + 70.f, 10.f);
    ImGui::BeginGroup();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(secondary, "Port:");
    ImGui::SameLine(0.f, field_gap);
    {
        int port_v = static_cast<int>(state.cap_filter_port);
        ImGui::SetNextItemWidth(70.f);
        if (ImGui::InputInt("##cap_filter_port", &port_v, 0, 0, ImGuiInputTextFlags_CharsDecimal)) {
            if (port_v < 0) port_v = 0;
            if (port_v > 65535) port_v = 65535;
            state.cap_filter_port = static_cast<uint16_t>(port_v);
        }
    }
    ImGui::EndGroup();

    same_line_if_fits(ImGui::CalcTextSize("Proto:").x + field_gap + 80.f, 10.f);
    ImGui::BeginGroup();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(secondary, "Proto:");
    ImGui::SameLine(0.f, field_gap);
    {
        const char* cap_proto_items[] = { "All", "TCP", "UDP" };
        int cap_proto_idx = state.cap_filter_protocol == 6 ? 1 :
                             state.cap_filter_protocol == 17 ? 2 : 0;
        ImGui::SetNextItemWidth(80.f);
        if (ImGui::Combo("##cap_filter_proto", &cap_proto_idx, cap_proto_items, 3)) {
            state.cap_filter_protocol = cap_proto_idx == 1 ? 6 :
                                         cap_proto_idx == 2 ? 17 : 0;
        }
    }
    ImGui::EndGroup();

    same_line_if_fits(64.f, 10.f);
    if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        size_t prev = state.captured_packets.size();
        state.captured_packets.clear();
        state.cap_selected = -1;
        publish_capture_snapshot_locked(state);
        diag::log_tagged_fmt("network", "capture_cleared prev_packet_count=%zu", prev);
    }

    ImGui::Spacing();
    {
        char count_buf[32];
        snprintf(count_buf, sizeof(count_buf), "%zu packets", pkt_count);
        float count_w = ImGui::CalcTextSize(count_buf).x;
        float row_avail = ImGui::GetContentRegionAvail().x;
        const float gap = 10.f;
        const bool count_on_row = row_avail >= count_w + gap + 140.f;
        const float input_w = std::max(1.f, std::min(640.f,
            count_on_row ? row_avail - count_w - gap : row_avail));
        aida::ui::input_text("##cap_filter", state.cap_filter_text, sizeof(state.cap_filter_text),
                              "Filter packets...", false, ImVec2(input_w, 28.f));
        if (count_on_row) {
            ImGui::SameLine(0.f, gap);
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", count_buf);
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", count_buf);
        }
    }

    ImGui::Spacing();
    capture_table_snapshot_t& cap_snapshot = snapshot_capture_table(state, state.cap_filter_text);
    const float list_top = ImGui::GetCursorPosY();
    const float remaining_h = std::max(1.f, h - list_top);
    float list_h = remaining_h;
    float detail_h = 0.f;
    if (cap_snapshot.total_count > 0 && remaining_h > 96.f) {
        const float separator_h = std::min(16.f, remaining_h * 0.10f);
        const float usable_h = std::max(2.f, remaining_h - separator_h);
        const float desired_list_h = h * state.detail_ratio - list_top;
        const float min_list_h = std::min(80.f, usable_h * 0.42f);
        const float min_detail_h = std::min(96.f, usable_h * 0.42f);
        const float max_list_h = std::max(min_list_h, usable_h - min_detail_h);
        list_h = std::clamp(desired_list_h, min_list_h, max_list_h);
        detail_h = std::max(1.f, usable_h - list_h);
    }

    ImGui::BeginChild("##cap_list", ImVec2(std::max(1.f, w - 4.f), list_h), false,
                      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

    if (cap_snapshot.total_count == 0) {
        ImVec2 list_org = ImGui::GetWindowPos();
        ImVec2 list_sz  = ImGui::GetWindowSize();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = cap_running ? "Waiting for packets..." : "Capture not running";
        cfg.body  = cap_running
            ? "Packets will stream in here as they are observed by the kernel driver."
            : "Start driver-backed capture to begin recording network traffic.";
        aida::ui::empty_state::action_t action;
        action.id = cap_running ? "network.capture.stop" : "network.capture.start";
        action.label = cap_running ? "Stop Capture" : "Start Capture";
        action.kind = cap_running
            ? aida::ui::components::button_kind_t::destructive
            : aida::ui::components::button_kind_t::primary;
        action.disabled = cap_start_pending || cap_stop_pending || !driver_ok;
        if (cap_start_pending || cap_stop_pending)
            action.tooltip = "Capture state is already changing.";
        else if (!s_driver_available_snapshot.load(std::memory_order_acquire))
            action.tooltip = "The driver is unavailable.";
        cfg.actions.push_back(std::move(action));
        const auto result = aida::ui::empty_state::render(
            ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        if (result.action_id == "network.capture.start") {
            diag::log_tagged_fmt("network", "start_capture_clicked filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d",
                state.cap_filter_pid, state.cap_filter_port, state.cap_filter_protocol,
                driver_ok ? 1 : 0);
            invoke_global_network_action("network.capture.start");
        } else if (result.action_id == "network.capture.stop") {
            diag::log_tagged("network", "stop_capture_clicked");
            invoke_global_network_action("network.capture.stop");
        }
        ImGui::Dummy(ImVec2(0.f, 0.f));
        ImGui::EndChild();
        ImGui::Dummy(ImVec2(0.f, 0.f));
        ImGui::EndChild();
        return;
    }

    if (cap_snapshot.rows.empty()) {
        ImVec2 list_org = ImGui::GetWindowPos();
        ImVec2 list_sz  = ImGui::GetWindowSize();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No packets match filter";
        cfg.body  = "Captured packets remain buffered; clear the text filter to show them again.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, list_h));
    } else {

        ImGuiTableFlags table_flags =
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Reorderable |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_NoSavedSettings |
            ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_PadOuterX |
            ImGuiTableFlags_ScrollY;

        bool table_open = ImGui::BeginTable("##cap_table", 6, table_flags, ImVec2(0.f, 0.f));
        int pending_selection = -1;
        if (table_open) {
            ImGui::TableSetupColumn("#",     ImGuiTableColumnFlags_WidthFixed,   48.f);
            ImGui::TableSetupColumn("Time",  ImGuiTableColumnFlags_WidthFixed,   110.f);
            ImGui::TableSetupColumn("Src",   ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Dst",   ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed,   64.f);
            ImGui::TableSetupColumn("Info",  ImGuiTableColumnFlags_WidthStretch, 0.60f);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            ImDrawList* table_dl = ImGui::GetWindowDrawList();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(cap_snapshot.rows.size()));
            while (clipper.Step()) {
                for (int visible_i = clipper.DisplayStart; visible_i < clipper.DisplayEnd; ++visible_i) {
                    const capture_row_snapshot_t& row = cap_snapshot.rows[static_cast<size_t>(visible_i)];

                    float row_alpha = 1.f;
                    float row_yoff = 0.f;
                    compute_row_entrance(s_cap_rows, cap_snapshot.total_count, row_alpha, row_yoff, row.packet_index);
                    (void)row_yoff;
                    float r_alpha = alpha * row_alpha;

                    ImGui::TableNextRow();

                    bool selected = (cap_snapshot.selected_index == row.packet_index);
                    ImU32 proto_col = protocol_stripe_color(row.protocol_label);
                    if (selected) {
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.selection, r_alpha * 0.55f));
                    }

                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(row.packet_index);
                    ImGuiSelectableFlags sel_flags =
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowItemOverlap;
                    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, r_alpha);
                    float row_h = ImGui::GetTextLineHeight() + ImGui::GetStyle().CellPadding.y * 2.f;
                    if (ImGui::Selectable("##row_select", selected, sel_flags, ImVec2(0.f, row_h))) {
                        pending_selection = row.packet_index;
                        cap_snapshot.selected_index = row.packet_index;
                        selected = true;
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.selection, r_alpha * 0.55f));
                    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    if (packet_snapshot && row.packet_index >= 0 &&
                        row.packet_index < static_cast<int>(packet_snapshot->size())) {
                        const auto& packet = (*packet_snapshot)[static_cast<std::size_t>(row.packet_index)];
                        artifact_identity_t identity;
                        identity.id = "network.packet." + std::to_string(packet.timestamp) + "." +
                            std::to_string(row.packet_index);
                        identity.timestamp = packet.timestamp;
                        identity.content_size = packet.payload.size();
                        identity.content_hash = artifact_hash(packet.payload);
                        register_network_last_item(
                            semantic_artifact_id("packet", identity), "network-packet-row",
                            "aida.dock-window.view.network.capture");
                    }
#endif
                    if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                        s_capture_context.packet_index = row.packet_index;
                        s_capture_context.timestamp = row.timestamp;
                        s_capture_context.open_requested = true;
                        s_capture_context.origin =
                            aida::ui::context_menu_open_origin_t::pointer;
                        pending_selection = row.packet_index;
                    }
                    bool hovered = ImGui::IsItemHovered();

                    if (hovered && !selected) {
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.hover_wash, r_alpha * 0.45f));
                    }

                    ImVec2 row_min = ImGui::GetItemRectMin();
                    ImVec2 row_max = ImGui::GetItemRectMax();
                    ImVec2 stripe_min(row_min.x, row_min.y);
                    ImVec2 stripe_max(row_min.x + 3.f, row_max.y);
                    table_dl->PushClipRect(stripe_min, ImVec2(stripe_max.x, stripe_max.y), true);
                    table_dl->AddRectFilled(stripe_min, stripe_max,
                                            aida::ui::with_alpha(proto_col, r_alpha));
                    table_dl->PopClipRect();

                    ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
                    ImGui::SetCursorScreenPos(ImVec2(row_min.x + 8.f, row_min.y + ImGui::GetStyle().CellPadding.y));
                    ImGui::Text("%d", row.packet_index + 1);

                    ImGui::TableSetColumnIndex(1);
                    table_text(format_timestamp(row.timestamp), dim_col);

                    ImGui::TableSetColumnIndex(2);
                    table_text(row.src, txt_col);

                    ImGui::TableSetColumnIndex(3);
                    table_text(row.dst, txt_col);

                    ImGui::TableSetColumnIndex(4);
                    table_text(row.protocol_label, aida::ui::with_alpha(proto_col, r_alpha));

                    ImGui::TableSetColumnIndex(5);
                    ImU32 info_col = aida::ui::with_alpha(th.text_secondary, r_alpha);
                    if (!row.summary.empty()) {
                        const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "};
                        for (auto* m : methods) {
                            if (row.summary.compare(0, strlen(m), m) == 0) {
                                info_col = ui_anim::http_method_color(m, r_alpha);
                                break;
                            }
                        }
                    }
                    table_text(row.summary, info_col);

                    ImGui::PopID();
                }
            }

            if (state.cap_auto_scroll && !cap_snapshot.rows.empty()) {
                float scroll_max_y = ImGui::GetScrollMaxY();
                float scroll_y = ImGui::GetScrollY();
                bool at_bottom = (scroll_max_y <= 0.f) || ((scroll_max_y - scroll_y) <= 4.f);
                bool user_scrolling = (ImGui::GetIO().MouseWheel != 0.f) ||
                                      ImGui::IsMouseDragging(ImGuiMouseButton_Left, 1.f);
                if (at_bottom && !user_scrolling)
                    ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndTable();
        }

        const bool capture_menu_key = cap_snapshot.selected_index >= 0 &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::IsKeyPressed(ImGuiKey_Menu, false);
        const bool capture_shift_f10 = !capture_menu_key && cap_snapshot.selected_index >= 0 &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
        if (capture_menu_key || capture_shift_f10) {
            const auto selected_row = std::find_if(cap_snapshot.rows.begin(), cap_snapshot.rows.end(),
                [&](const capture_row_snapshot_t& row) {
                    return row.packet_index == cap_snapshot.selected_index;
                });
            if (selected_row != cap_snapshot.rows.end()) {
                s_capture_context.packet_index = selected_row->packet_index;
                s_capture_context.timestamp = selected_row->timestamp;
                s_capture_context.open_requested = true;
                s_capture_context.origin = capture_menu_key
                    ? aida::ui::context_menu_open_origin_t::menu_key
                    : aida::ui::context_menu_open_origin_t::shift_f10;
            }
        }

        if (s_capture_context.open_requested) {
            s_capture_context.open_requested = false;
            packet_entry_t packet;
            bool current = false;
            const auto current_packets = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
            if (current_packets && s_capture_context.packet_index >= 0 &&
                s_capture_context.packet_index < static_cast<int>(current_packets->size())) {
                const auto& candidate = (*current_packets)[static_cast<size_t>(s_capture_context.packet_index)];
                if (candidate.timestamp == s_capture_context.timestamp) {
                    packet = candidate;
                    current = true;
                }
            }
            if (current) {
                const std::string src = format_ip(packet.src_addr, 2) + ":" + std::to_string(packet.src_port);
                const std::string dst = format_ip(packet.dst_addr, 2) + ":" + std::to_string(packet.dst_port);
                aida::ui::application_ui::retained_entity_context_t context;
                context.owner_id = "network.capture.packet";
                context.entity_id = std::to_string(packet.timestamp) + ":" +
                    std::to_string(s_capture_context.packet_index);
                context.entity_generation = packet.timestamp;
                context.active_view = aida::ui::stable_view_id_t("view.network.capture");
                const auto retained_index = s_capture_context.packet_index;
                const auto retained_timestamp = packet.timestamp;
                const auto retained_size = packet.payload.size();
                context.validate_identity = [&state, retained_index, retained_timestamp, retained_size] {
                    const auto live = std::atomic_load_explicit(
                        &state.capture_snapshot, std::memory_order_acquire);
                    if (!live || retained_index < 0 ||
                        retained_index >= static_cast<int>(live->size()))
                        return aida::ui::capability_state_t::unavailable(
                            "The bounded capture buffer advanced; select a current packet");
                    const auto& candidate = (*live)[static_cast<std::size_t>(retained_index)];
                    return candidate.timestamp == retained_timestamp &&
                            candidate.payload.size() == retained_size
                        ? aida::ui::capability_state_t::available()
                        : aida::ui::capability_state_t::unavailable(
                            "The captured packet was replaced; select it again");
                };
                const auto add = [&context](const char* id, bool enabled, const char* reason,
                        std::function<aida::ui::action_handler_result_t()> invoke) {
                    aida::ui::application_ui::retained_entity_action_t action;
                    action.action_id = id;
                    action.capability = enabled
                        ? aida::ui::capability_state_t::available()
                        : aida::ui::capability_state_t::unavailable(reason);
                    action.invoke = std::move(invoke);
                    context.actions.push_back(std::move(action));
                };
                const auto summary = packet.summary;
                add("network.capture.copy_summary", !summary.empty(),
                    "The captured packet has no summary", [summary] {
                    ImGui::SetClipboardText(summary.c_str());
                    return aida::ui::action_handler_result_t::completed();
                });
                add("network.capture.copy_source", true, "", [src] {
                    ImGui::SetClipboardText(src.c_str());
                    return aida::ui::action_handler_result_t::completed();
                });
                add("network.capture.copy_destination", true, "", [dst] {
                    ImGui::SetClipboardText(dst.c_str());
                    return aida::ui::action_handler_result_t::completed();
                });
                const std::string payload = payload_display_text(packet.payload, 262144);
                add("network.capture.copy_payload", !packet.payload.empty(),
                    "The captured packet has no payload", [payload] {
                    ImGui::SetClipboardText(payload.c_str());
                    return aida::ui::action_handler_result_t::completed();
                });
                artifact_identity_t packet_identity;
                packet_identity.kind = artifact_kind_t::packet;
                packet_identity.id = "network.packet." + std::to_string(packet.timestamp) + "." +
                    std::to_string(s_capture_context.packet_index);
                packet_identity.source_view_id = "view.network.capture";
                packet_identity.source_id = static_cast<std::uint64_t>(s_capture_context.packet_index + 1);
                packet_identity.timestamp = packet.timestamp;
                packet_identity.content_size = packet.payload.size();
                packet_identity.content_hash = artifact_hash(packet.payload);
                packet_identity.label = packet.protocol_label + " packet";
                add("network.capture.send_comparer", !packet.payload.empty(),
                    "The captured packet has no payload", [packet_identity] {
                    std::string reason;
                    return send_artifact_to_comparer(packet_identity, reason)
                        ? aida::ui::action_handler_result_t::completed()
                        : aida::ui::action_handler_result_t::failed(reason);
                });
                add("network.capture.send_chat", !packet.payload.empty(),
                    "The captured packet has no payload", [packet_identity] {
                    std::string reason;
                    return add_artifact_to_chat(packet_identity, reason)
                        ? aida::ui::action_handler_result_t::completed()
                        : aida::ui::action_handler_result_t::failed(reason);
                });
                add("network.capture.assign_agent", !packet.payload.empty(),
                    "The captured packet has no payload", [packet_identity] {
                    std::string reason;
                    return assign_artifact_to_agent(packet_identity, reason)
                        ? aida::ui::action_handler_result_t::completed()
                        : aida::ui::action_handler_result_t::failed(reason);
                });
                add("network.capture.filter_pid", packet.pid != 0,
                    "The captured packet has no process identity", [&state, pid = packet.pid] {
                    state.cap_filter_pid = pid;
                    return aida::ui::action_handler_result_t::completed();
                });
                add("network.capture.filter_protocol", packet.protocol != 0,
                    "The captured packet has no protocol discriminator",
                    [&state, protocol = packet.protocol] {
                    state.cap_filter_protocol = protocol;
                    return aida::ui::action_handler_result_t::completed();
                });
                add("network.capture.toggle_follow", true, "", [&state] {
                    state.cap_auto_scroll = !state.cap_auto_scroll;
                    return aida::ui::action_handler_result_t::completed();
                });
                add("network.capture.send_repeater", false,
                    "A raw driver packet is not necessarily a complete HTTP request; use Proxy history for safe request reconstruction", {});
                add("network.capture.replay", false,
                    "Raw packet replay has no capability-backed human handler in this view", {});
                aida::ui::application_ui::open_retained_entity_context_menu(
                    std::move(context), s_capture_context.origin);
            }
        }
        aida::ui::application_ui::render_retained_entity_context_menu(
            "network.capture.packet");

        if (pending_selection >= 0) {
            const auto current_packets = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
            if (current_packets && pending_selection < static_cast<int>(current_packets->size()))
                state.cap_selected = pending_selection;
            else
                state.cap_selected = current_packets && !current_packets->empty()
                    ? static_cast<int>(current_packets->size()) - 1 : -1;
        }
    }

    ImGui::EndChild();

    if (detail_h > 30.f) {
        ImGui::Spacing();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wp = ImGui::GetWindowPos();
        dl->AddLine(ImVec2(wp.x + 2.f, wp.y + ImGui::GetCursorPosY()),
                    ImVec2(wp.x + w - 2.f, wp.y + ImGui::GetCursorPosY()),
                    aida::ui::with_alpha(th.border_subtle, alpha));
        ImGui::Spacing();
        ImGui::BeginChild("##cap_detail", ImVec2(std::max(1.f, w - 4.f), detail_h), false,
            ImGuiWindowFlags_NoBackground);

        const auto detail_packets = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
        int selected_packet = state.cap_selected.load(std::memory_order_acquire);
        if (detail_packets && selected_packet >= static_cast<int>(detail_packets->size())) {
            selected_packet = detail_packets->empty() ? -1 : static_cast<int>(detail_packets->size()) - 1;
            state.cap_selected.store(selected_packet, std::memory_order_release);
        }
        if (detail_packets && selected_packet >= 0 && selected_packet < static_cast<int>(detail_packets->size())) {
            const auto& p = (*detail_packets)[static_cast<size_t>(selected_packet)];

            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Packet #%d  -  %s", selected_packet + 1, p.protocol_label.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                "%s:%u -> %s:%u  -  PID: %u  -  %u bytes  -  %s",
                format_ip(p.src_addr, 2).c_str(), static_cast<unsigned>(p.src_port),
                format_ip(p.dst_addr, 2).c_str(), static_cast<unsigned>(p.dst_port),
                static_cast<unsigned>(p.pid), static_cast<unsigned>(p.payload_size),
                p.direction == 0 ? "Inbound" : "Outbound");

            if (!p.summary.empty())
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                    "%s", p.summary.c_str());

            ImGui::Spacing();


            if (!p.payload.empty()) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                    "Payload (%u bytes):", static_cast<unsigned>(p.payload_size));
                ImGui::BeginChild("##cap_hex", ImVec2(0, 0), false, ImGuiWindowFlags_NoBackground);

                ImFont* mono_font = aida::ui::fonts::code();
                bool pushed_font = false;
                if (mono_font) { ImGui::PushFont(mono_font); pushed_font = true; }

                size_t display_size = std::min(p.payload.size(), static_cast<size_t>(4096));
                for (size_t off = 0; off < display_size; off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04X  ", static_cast<unsigned>(off));

                    size_t end = std::min(off + 16, display_size);
                    for (size_t j = off; j < off + 16; j++) {
                        if (j < end)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02X ",
                                static_cast<unsigned>(p.payload[j]));
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                        if (j == off + 7)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
                    }
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " |");
                    for (size_t j = off; j < end; j++) {
                        char c = static_cast<char>(p.payload[j]);
                        line[pos++] = (c >= 32 && c < 127) ? c : '.';
                    }
                    line[pos++] = '|';
                    line[pos] = '\0';

                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                        "%s", line);
                }

                if (display_size < p.payload.size()) {
                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                        "... %zu more bytes", p.payload.size() - display_size);
                }

                if (pushed_font) ImGui::PopFont();

                ImGui::EndChild();
            }
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                "Select a packet to view details");
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


template <typename RawDns>
static std::size_t merge_dns_entries(state_t& state, RawDns&& raw_dns) {
    std::size_t added = 0;
    std::lock_guard<std::mutex> lock(state.dns_mutex);
    for (auto& query : raw_dns) {
        bool duplicate = false;
        const auto recent_count = static_cast<std::ptrdiff_t>((std::min)(
            static_cast<std::size_t>(256), state.dns_entries.size()));
        for (auto it = state.dns_entries.rbegin();
             it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + recent_count; ++it) {
            if (it->timestamp == query.timestamp && it->domain == query.domain && it->pid == query.pid) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;
        dns_entry_t entry;
        entry.timestamp = query.timestamp;
        entry.pid = query.pid;
        entry.query_type = static_cast<std::uint16_t>(query.query_type);
        entry.domain = query.domain;
        entry.resolved_addr = format_ip(query.resolved_addr, 2);
        entry.response_code = query.response_code;
        entry.ttl = query.ttl;
        state.dns_entries.push_back(std::move(entry));
        ++added;
    }
    while (state.dns_entries.size() > state.dns_max_entries)
        state.dns_entries.pop_front();
    publish_dns_snapshot_locked(state);
    return added;
}

static void request_dns_refresh(state_t& state) {
    bool expected = false;
    if (!state.dns_refresh_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.dns_refresh_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint32_t filter_pid = state.dns_filter_pid;
    const std::string task_id = register_network_operation(
        "network.dns.refresh", "Refresh DNS observations", "view.network.dns",
        filter_pid == 0 ? "all processes" : "PID " + std::to_string(filter_pid));
    const bool posted = post_network_task(
        "dns_refresh", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, filter_pid, task_id]() {
            bool success = false;
            std::size_t raw_count = 0;
            std::size_t added = 0;
            std::string error;
            try {
                if (!driver_feature_ready("dns_refresh")) {
                    error = "Driver DNS observations are unavailable";
                } else {
                    auto raw = driver_bridge::get_dns_queries(filter_pid);
                    raw_count = raw.size();
                    if (g_state.dns_refresh_serial.load(std::memory_order_acquire) == serial)
                        added = merge_dns_entries(g_state, std::move(raw));
                    success = g_state.dns_refresh_serial.load(std::memory_order_acquire) == serial;
                    if (!success)
                        error = "DNS refresh was superseded";
                }
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "DNS refresh failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(added) + " new of " + std::to_string(raw_count) + " observations" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.dns_refresh_serial.load(std::memory_order_acquire) != serial)
                    return;
                g_state.dns_refresh_pending.store(false, std::memory_order_release);
                if (!success)
                    toast_notification::push(error.empty() ? "DNS refresh failed" : error,
                        toast_notification::toast_type_t::error);
            });
        }, false);
    if (!posted) {
        state.dns_refresh_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected DNS refresh");
    }
}

static void render_dns(state_t& state, float x, float y, float w, float h,
                        float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_dns", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_driver_available_snapshot();
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);

    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.dns_polling.load()) {
        if (aida::ui::button("Start DNS Monitor", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "dns_monitor_start_clicked filter_pid=%u drv_ok=%d",
                state.dns_filter_pid, driver_ok ? 1 : 0);
            state.dns_polling.store(true);
            state.dns_cv.notify_all();
        }
    } else {
        if (aida::ui::button("Stop DNS Monitor", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged("network", "dns_monitor_stop_clicked");
            state.dns_polling.store(false);
        }
    }
    ImGui::SameLine();
    const bool refresh_pending = state.dns_refresh_pending.load(std::memory_order_acquire);
    if (aida::ui::button(refresh_pending ? "Refreshing...##dns_refresh" : "Refresh##dns_refresh",
                         aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), refresh_pending)) {
        diag::log_tagged_fmt("network", "dns_refresh_clicked drv_ok=%d filter_pid=%u",
            driver_ok ? 1 : 0, state.dns_filter_pid);
        if (driver_ok)
            request_dns_refresh(state);
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    aida::ui::input_text("##dns_filter", state.dns_filter_text, sizeof(state.dns_filter_text),
                          "Filter by domain or address...", false, ImVec2(280.f, 28.f));

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 64.f, col_type = 60.f, col_rcode = 64.f, col_ttl = 56.f;
    float remaining = w - col_pid - col_type - col_rcode - col_ttl - 24.f;
    float col_domain = remaining * 0.55f;
    float col_addr = remaining * 0.45f;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");     cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Type");    cx += col_type;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Domain");  cx += col_domain;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Address"); cx += col_addr;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "RCode");   cx += col_rcode;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "TTL");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##dns_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    const auto dns_entries = std::atomic_load_explicit(&state.dns_snapshot, std::memory_order_acquire);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 dns_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + dns_list_sz.x, list_org.y + dns_list_sz.y), true);

    if (!dns_entries || dns_entries->empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = state.dns_polling.load() ? "Listening for DNS queries" : "DNS monitor idle";
        cfg.body  = state.dns_polling.load()
            ? "Resolved queries will appear here as the kernel observes DNS traffic."
            : "Click Start DNS Monitor to begin tracking queries.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(dns_list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    static std::shared_ptr<const std::vector<dns_entry_t>> filtered_snapshot;
    static std::string filtered_query;
    static std::vector<int> filtered_indices;
    const std::string current_query(state.dns_filter_text);
    if (filtered_snapshot != dns_entries || filtered_query != current_query) {
        filtered_snapshot = dns_entries;
        filtered_query = current_query;
        filtered_indices.clear();
        filtered_indices.reserve(dns_entries->size());
        for (int i = 0; i < static_cast<int>(dns_entries->size()); ++i) {
            const auto& entry = (*dns_entries)[static_cast<std::size_t>(i)];
            if (!current_query.empty()) {
                const std::string searchable = entry.domain + " " + entry.resolved_addr + " " + std::to_string(entry.pid);
                if (!filter_text_match(current_query.c_str(), searchable))
                    continue;
            }
            filtered_indices.push_back(i);
        }
    }
    const int total_visible_rows = static_cast<int>(filtered_indices.size());

    float scroll_y = ImGui::GetScrollY();
    float viewport_top = scroll_y;
    float viewport_bot = scroll_y + dns_list_sz.y;

    const int first_visible = (std::max)(0, static_cast<int>(viewport_top / row_h) - 1);
    const int last_visible = (std::min)(total_visible_rows,
        static_cast<int>(viewport_bot / row_h) + 2);
    for (int dns_visible_row = first_visible; dns_visible_row < last_visible; ++dns_visible_row) {
        const int i = filtered_indices[static_cast<std::size_t>(dns_visible_row)];
        const auto& d = (*dns_entries)[static_cast<size_t>(i)];
        float ry = static_cast<float>(dns_visible_row) * row_h;

        float row_alpha = 1.f;
        float row_yoff = 0.f;
        compute_row_entrance(s_dns_rows, filtered_indices.size(), row_alpha, row_yoff, dns_visible_row);
        float r_alpha = alpha * row_alpha;

        float abs_ry = list_org.y + ry - scroll_y;
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.dns_selected == i);

        if (dns_visible_row & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, r_alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.dns_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
        cx = list_org.x + 8.f;
        char buf[16];

        snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(d.pid));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += col_pid;

        const char* qtype = d.query_type == 1 ? "A" : d.query_type == 28 ? "AAAA" : d.query_type == 5 ? "CNAME" : "?";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.info, r_alpha), qtype);
        cx += col_type;


        std::string domain = d.domain;
        if (domain.size() > 40) domain = domain.substr(0, 37) + "...";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.accent_u32, r_alpha),
                     domain.c_str()); cx += col_domain;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, d.resolved_addr.c_str()); cx += col_addr;

        snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(d.response_code));
        ImU32 rcode_col = d.response_code == 0
            ? aida::ui::with_alpha(th.success, r_alpha)
            : aida::ui::with_alpha(th.error, r_alpha);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), rcode_col, buf); cx += col_rcode;

        snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(d.ttl));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_dim, r_alpha), buf);

    }

    dl->PopClipRect();
    ImGui::Dummy(ImVec2(1.f, static_cast<float>(total_visible_rows) * row_h));
    ImGui::EndChild();
    ImGui::EndChild();
}


struct proxy_runtime_snapshot_t {
    mitm_proxy::proxy_stats stats;
    std::vector<mitm_proxy::http_exchange> history;
    bool ca_ready = false;
    bool ca_installed = false;
    std::string spki_prefix;
    bool controlled_browser_running = false;
    bool bypass_active = false;
    std::size_t bypass_count = 0;
};

static std::shared_ptr<const proxy_runtime_snapshot_t> s_proxy_runtime_snapshot;
static std::atomic<bool> s_proxy_snapshot_pending{false};
static std::atomic<std::uint64_t> s_proxy_snapshot_requested_ms{0};
static std::atomic<bool> s_proxy_operation_pending{false};
static std::atomic<std::uint64_t> s_proxy_operation_serial{0};
static std::size_t s_bypass_review_count = 0;
static std::uint64_t s_proxy_selected_exchange_id = 0;

static void request_proxy_runtime_snapshot(bool force = false) {
    const std::uint64_t now = network_now_ms();
    const std::uint64_t last = s_proxy_snapshot_requested_ms.load(std::memory_order_acquire);
    if (!force && last != 0 && now >= last && now - last < 350)
        return;
    bool expected = false;
    if (!s_proxy_snapshot_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    s_proxy_snapshot_requested_ms.store(now, std::memory_order_release);
    const bool posted = post_network_task(
        "proxy_snapshot", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        []() {
            try {
                auto snapshot = std::make_shared<proxy_runtime_snapshot_t>();
                snapshot->stats = mitm_proxy::get_stats();
                snapshot->history = mitm_proxy::get_history(4096);
                snapshot->ca_ready = cert_generator::is_ready();
                if (snapshot->ca_ready) {
                    const auto& root = cert_generator::get_root_ca();
                    snapshot->ca_installed = cert_generator::is_root_ca_installed(root);
                    snapshot->spki_prefix = aida::burp::browser::spki_hash_prefix(
                        cert_generator::spki_sha256_base64(root));
                }
                const auto browsers = aida::burp::browser::list_running();
                snapshot->controlled_browser_running = std::any_of(browsers.begin(), browsers.end(),
                    [](const auto& browser) { return browser.running; });
                snapshot->bypass_active = cert_pin_bypass::is_bypass_active();
                if (snapshot->bypass_active)
                    snapshot->bypass_count = cert_pin_bypass::get_active_bypasses().size();
                std::atomic_store_explicit(&s_proxy_runtime_snapshot,
                    std::shared_ptr<const proxy_runtime_snapshot_t>(std::move(snapshot)),
                    std::memory_order_release);
            } catch (...) {
            }
            s_proxy_snapshot_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted)
        s_proxy_snapshot_pending.store(false, std::memory_order_release);
}

static void request_proxy_control(state_t& state, bool start) {
    bool expected = false;
    if (!s_proxy_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_proxy_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    mitm_proxy::proxy_config config;
    config.bind_addr = state.proxy_bind_addr;
    config.bind_port = static_cast<std::uint16_t>((std::max)(1, (std::min)(state.proxy_port, 65535)));
    config.decode_tls = state.proxy_decode_tls;
    const std::string target = config.bind_addr + ":" + std::to_string(config.bind_port) +
        (config.decode_tls ? " TLS interception" : " plaintext only");
    const std::string task_id = register_network_operation(
        start ? "network.proxy.start" : "network.proxy.stop",
        start ? "Start interception proxy" : "Stop interception proxy",
        "view.network.proxy", target);
    const bool posted = post_network_task(
        start ? "proxy_start" : "proxy_stop",
        start ? aida::infra::executor::domain_t::long_running
              : aida::infra::executor::domain_t::feature_worker,
        start ? "long_running" : "bounded_task",
        [serial, start, config = std::move(config), task_id]() {
            bool success = true;
            std::string error;
            try {
                if (start)
                    success = mitm_proxy::start(config);
                else
                    mitm_proxy::stop();
                if (success != mitm_proxy::is_running()) {
                    if (!start && !mitm_proxy::is_running())
                        success = true;
                    else if (start)
                        success = false;
                }
                if (!success)
                    error = start ? "Proxy did not enter the running state" : "Proxy did not stop";
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = start ? "Proxy start failed" : "Proxy stop failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? (start ? "Proxy is running" : "Proxy is stopped") : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (s_proxy_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Proxy control failed" : error,
                        toast_notification::toast_type_t::error);
                s_proxy_operation_pending.store(false, std::memory_order_release);
                request_proxy_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_proxy_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected proxy control");
    }
}

static void request_proxy_history_clear(std::size_t reviewed_count,
                                        std::vector<std::uint64_t> reviewed_ids) {
    bool expected = false;
    if (!s_proxy_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_proxy_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.proxy.history.clear", "Clear proxy history", "view.network.proxy",
        std::to_string(reviewed_count) + " reviewed exchanges");
    const bool posted = post_network_task(
        "proxy_history_clear", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, reviewed_count, reviewed_ids = std::move(reviewed_ids), task_id]() {
            bool success = true;
            std::string error;
            try {
                success = mitm_proxy::clear_history_if_exact(reviewed_ids);
                if (!success) {
                    error = "Proxy history changed after confirmation; review the current retained exchanges again";
                }
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = "Proxy history clear failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(reviewed_count) + " exchanges cleared" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (s_proxy_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success)
                    g_state.proxy_selected = -1;
                else
                    toast_notification::push(error.empty() ? "Proxy history clear failed" : error,
                        toast_notification::toast_type_t::error);
                s_proxy_operation_pending.store(false, std::memory_order_release);
                request_proxy_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_proxy_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected proxy history clear");
    }
}

static void request_ca_trust_repair() {
    bool expected = false;
    if (!s_proxy_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_proxy_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.proxy.ca_trust_repair", "Repair AiDA interception CA trust", "view.network.proxy",
        "current user trust store");
    const bool posted = post_network_task(
        "proxy_ca_repair", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, task_id]() {
            bool success = false;
            std::string error;
            try {
                success = cert_generator::initialize();
                if (success && cert_generator::is_ready())
                    success = cert_generator::install_root_ca(cert_generator::get_root_ca());
                if (!success)
                    error = "AiDA CA trust repair failed";
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "AiDA CA trust repair failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "AiDA CA is installed in the current user trust store" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (s_proxy_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                toast_notification::push(success ? "AiDA CA trust repaired."
                    : (error.empty() ? "AiDA CA trust repair failed." : error),
                    success ? toast_notification::toast_type_t::success : toast_notification::toast_type_t::error);
                s_proxy_operation_pending.store(false, std::memory_order_release);
                request_proxy_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_proxy_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected CA trust repair");
    }
}

static void request_legacy_bypass_revert(std::size_t reviewed_count) {
    bool expected = false;
    if (!s_proxy_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_proxy_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.proxy.legacy_bypass.revert", "Revert legacy certificate bypass patches",
        "view.network.proxy", std::to_string(reviewed_count) + " live patches");
    const bool posted = post_network_task(
        "proxy_legacy_bypass_revert", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, reviewed_count, task_id]() {
            bool success = false;
            int reverted = 0;
            std::string error;
            try {
                reverted = cert_pin_bypass::revert_all_bypasses();
                success = reverted >= 0 && !cert_pin_bypass::is_bypass_active();
                if (!success)
                    error = "One or more legacy certificate patches remain active";
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Legacy certificate patch reversion failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(reverted) + " of " + std::to_string(reviewed_count) + " patches reverted" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (s_proxy_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Legacy certificate patch reversion failed" : error,
                        toast_notification::toast_type_t::error);
                s_proxy_operation_pending.store(false, std::memory_order_release);
                request_proxy_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_proxy_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected legacy bypass reversion");
    }
}

static void request_certificate_diagnostics(std::uint32_t target_pid,
                                            cert_intercept::diagnostic_context_t context) {
    bool expected = false;
    if (!s_cert_diagnostics_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_cert_diagnostics_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.proxy.certificate_diagnostics", "Diagnose target TLS interception",
        "view.network.proxy", "PID " + std::to_string(target_pid));
    const bool posted = post_network_task(
        "proxy_certificate_diagnostics", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, target_pid, context = std::move(context), task_id]() mutable {
            bool success = false;
            cert_intercept::process_diagnostics_t report;
            std::vector<cert_intercept::provider_status_t> providers;
            std::string error;
            try {
                cert_diag_apply_proxy_observations(context);
                report = cert_intercept::diagnose_process(target_pid, context);
                providers = cert_intercept::provider_registry_t::instance().evaluate(target_pid, report);
                success = true;
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Target TLS diagnostics failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? cert_intercept::to_string(report.primary) + " - " + report.summary : error);
            enqueue_ui_completion([serial, success, report = std::move(report),
                                   providers = std::move(providers), error = std::move(error)]() mutable {
                if (s_cert_diagnostics_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    s_cert_diag_ui.report = std::move(report);
                    s_cert_diag_ui.providers = std::move(providers);
                    s_cert_diag_ui.has_report = true;
                    s_cert_diag_ui.status = cert_intercept::to_string(s_cert_diag_ui.report.primary) +
                        " - " + s_cert_diag_ui.report.summary;
                    s_cert_diag_ui.handoff_status.clear();
                } else {
                    s_cert_diag_ui.has_report = false;
                    s_cert_diag_ui.providers.clear();
                    s_cert_diag_ui.status = error.empty() ? "Target TLS diagnostics failed" : error;
                }
                s_cert_diagnostics_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        s_cert_diagnostics_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected target TLS diagnostics");
        s_cert_diag_ui.status = "Executor rejected target TLS diagnostics";
    }
}

static void request_certificate_handoff(cert_intercept::process_diagnostics_t report,
                                        std::vector<cert_intercept::provider_status_t> providers,
                                        std::string proxy_endpoint) {
    bool expected = false;
    if (!s_cert_handoff_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_cert_handoff_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string target_label = report.process_name.empty() ? "target" : report.process_name;
    const std::string task_id = register_network_operation(
        "network.proxy.certificate_handoff", "Generate TLS interception handoff",
        "view.network.proxy", target_label);
    const bool posted = post_network_task(
        "proxy_certificate_handoff", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, report = std::move(report), providers = std::move(providers),
         proxy_endpoint = std::move(proxy_endpoint), target_label, task_id]() mutable {
            bool success = false;
            std::string status;
            try {
                cert_intercept::profiles::public_ca_export_t exported;
                if (cert_generator::initialize() && cert_generator::is_ready())
                    exported = cert_intercept::profiles::export_public_ca_files(cert_generator::get_root_ca());
                if (!exported.ok) {
                    status = exported.error.empty() ? "ca_export_failed" : exported.error;
                } else {
                    cert_intercept::handoff_request_t request;
                    request.diagnostics = std::move(report);
                    request.provider_statuses = std::move(providers);
                    request.target_label = target_label;
                    request.proxy_endpoint = proxy_endpoint;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    request.ca_cert_pem_path = aida::preview::network::filesystem_path_utf8(exported.pem_path);
                    request.ca_cert_der_path = aida::preview::network::filesystem_path_utf8(exported.der_path);
#else
                    request.ca_cert_pem_path = exported.pem_path.u8string();
                    request.ca_cert_der_path = exported.der_path.u8string();
#endif
                    auto handoff = cert_intercept::generate_handoff(request);
                    success = handoff.ok;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    status = success ? aida::preview::network::filesystem_path_utf8(handoff.metadata_path)
                                     : handoff.error;
#else
                    status = success ? handoff.metadata_path.u8string() : handoff.error;
#endif
                }
            } catch (const std::exception& exception) {
                status = exception.what();
            } catch (...) {
                status = "TLS interception handoff generation failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed", status);
            enqueue_ui_completion([serial, success, status = std::move(status)]() mutable {
                if (s_cert_handoff_serial.load(std::memory_order_acquire) != serial)
                    return;
                s_cert_diag_ui.handoff_status = status.empty()
                    ? (success ? "Handoff generated" : "TLS interception handoff generation failed")
                    : std::move(status);
                s_cert_handoff_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        s_cert_handoff_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected TLS interception handoff generation");
        s_cert_diag_ui.handoff_status = "Executor rejected TLS interception handoff generation";
    }
}

static void render_proxy(state_t& state, float x, float y, float w, float h,
                          float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_proxy", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_proxy_runtime_snapshot();
    const auto proxy_snapshot = std::atomic_load_explicit(&s_proxy_runtime_snapshot, std::memory_order_acquire);
    const bool running = proxy_snapshot && proxy_snapshot->stats.running;
    const bool proxy_pending = s_proxy_operation_pending.load(std::memory_order_acquire);

    ImGui::PushID("proxy_toolbar");
    if (!running) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Bind:");
        same_line_if_fits(140.f);
        aida::ui::input_text("##proxy_addr", state.proxy_bind_addr, sizeof(state.proxy_bind_addr),
                              "127.0.0.1", false, ImVec2(std::min(180.f, std::max(128.f, w * 0.22f)), 28.f));
        same_line_if_fits(56.f);
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Port:");
        same_line_if_fits(82.f);
        aida::ui::input_int("##proxy_port", &state.proxy_port, ImVec2(80.f, 28.f));
        same_line_if_fits(96.f);
        aida::ui::toggle_switch("##proxy_tls", &state.proxy_decode_tls);
        same_line_if_fits(72.f);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "TLS MITM");
        same_line_if_fits(110.f);

        if (aida::ui::button(proxy_pending ? "Starting...##proxy_start" : "Start Proxy##proxy_start",
                             aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), proxy_pending)) {
            diag::log_tagged_fmt("network", "proxy_start_clicked bind=%s:%u decode_tls=%d",
                state.proxy_bind_addr, state.proxy_port, state.proxy_decode_tls ? 1 : 0);
            invoke_global_network_action("network.proxy.start");
        }
    } else {
        const auto& stats = proxy_snapshot->stats;
        proxy_chart_tick(stats.total_requests);

        char run_buf[64];
        snprintf(run_buf, sizeof(run_buf), "Proxy running  %s:%d", state.proxy_bind_addr, state.proxy_port);
        aida::ui::pill_kind(run_buf, aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, true);

        same_line_if_fits(112.f);
        ImDrawList* dl_top = ImGui::GetWindowDrawList();
        ImVec2 sp_pos = ImGui::GetCursorScreenPos();
        float sp_w = 96.f, sp_h = 22.f;
        float ordered[proxy_history_chart_t::N];
        for (int i = 0; i < proxy_history_chart_t::N; i++) {
            int idx = (s_proxy_chart.head + i) % proxy_history_chart_t::N;
            ordered[i] = s_proxy_chart.values[idx];
        }
        ImU32 spark_line = aida::ui::with_alpha(th.accent_u32, alpha);
        ImU32 spark_fill = aida::ui::with_alpha(th.accent_glow, alpha * 0.6f);
        ui_anim::render_sparkline(dl_top, sp_pos.x, sp_pos.y + 4.f, sp_w, sp_h,
                                   ordered, proxy_history_chart_t::N, spark_line, spark_fill);
        ImGui::Dummy(ImVec2(sp_w + 8.f, sp_h + 6.f));

        char stats_buf[192];
        snprintf(stats_buf, sizeof(stats_buf), "%llu req  %u active  In %s  Out %s",
            static_cast<unsigned long long>(stats.total_requests),
            static_cast<unsigned>(stats.active_connections),
            format_bytes(stats.total_bytes_in).c_str(),
            format_bytes(stats.total_bytes_out).c_str());
        same_line_if_fits(estimate_chip_w(stats_buf, 10.f));
        clipped_text(stats_buf, aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);

        same_line_if_fits(64.f);
        if (aida::ui::button(proxy_pending ? "Stopping...##proxy_stop" : "Stop##proxy_stop",
                             aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), proxy_pending)) {
            diag::log_tagged("network", "proxy_stop_clicked");
            invoke_global_network_action("network.proxy.stop");
        }
        same_line_if_fits(112.f);
        if (aida::ui::button("Clear History", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), proxy_pending || proxy_snapshot->history.empty())) {
            invoke_global_network_action("network.proxy.history.clear");
        }
    }

    same_line_if_fits(230.f);
    aida::ui::input_text("##proxy_filter", state.proxy_filter_text, sizeof(state.proxy_filter_text),
                          "Filter requests...", false, ImVec2(220.f, 28.f));
    ImGui::PopID();

    ImGui::Spacing();
    const bool ca_installed = proxy_snapshot && proxy_snapshot->ca_installed;
    const std::string spki_prefix = proxy_snapshot ? proxy_snapshot->spki_prefix : std::string();
    const bool controlled_browser_running = proxy_snapshot && proxy_snapshot->controlled_browser_running;

    bool first_pill = true;
    auto readiness_pill = [&](const char* label, aida::ui::pill_kind_t kind) {
        if (!first_pill)
            same_line_if_fits(estimate_chip_w(label, 24.f));
        aida::ui::pill_kind(label, kind, aida::ui::size_t_::sm, false);
        first_pill = false;
    };
    readiness_pill("Interception readiness", aida::ui::pill_kind_t::info);
    aida::ui::pill_kind(running ? "Proxy running" : "Proxy stopped",
        running ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::warning,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w(ca_installed ? "AiDA CA trusted" : "AiDA CA not trusted", 24.f));
    aida::ui::pill_kind(ca_installed ? "AiDA CA trusted" : "AiDA CA not trusted",
        ca_installed ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::warning,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w(controlled_browser_running ? "Controlled active" : "Controlled ready", 24.f));
    aida::ui::pill_kind(controlled_browser_running ? "Controlled active" : "Controlled ready",
        controlled_browser_running ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::neutral,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("Camoufox only", 24.f));
    aida::ui::pill_kind("Camoufox only", aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("WebRTC blocked", 24.f));
    aida::ui::pill_kind("WebRTC blocked", aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("QUIC disabled", 24.f));
    aida::ui::pill_kind("QUIC disabled", aida::ui::pill_kind_t::info, aida::ui::size_t_::sm, false);
    if (!spki_prefix.empty()) {
        char spki_buf[64];
        snprintf(spki_buf, sizeof(spki_buf), "SPKI %s", spki_prefix.c_str());
        same_line_if_fits(estimate_chip_w(spki_buf, 24.f));
        aida::ui::pill_kind(spki_buf, aida::ui::pill_kind_t::neutral, aida::ui::size_t_::sm, false);
    }
    ImGui::Spacing();
    if (aida::ui::button("Prepare controlled browser", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        state.prev_tab = state.active_tab;
        state.active_tab = sub_tab_t::browser;
    }
    same_line_if_fits(92.f);
    if (aida::ui::button(proxy_pending ? "Repairing...##ca_repair" : "Repair trust##ca_repair",
                         aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), proxy_pending))
        invoke_global_network_action("network.proxy.ca_trust_repair");
    same_line_if_fits(154.f);
    if (aida::ui::button("Open Camoufox controls", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        state.prev_tab = state.active_tab;
        state.active_tab = sub_tab_t::browser;
        toast_notification::push("Camoufox is the only supported browser.", toast_notification::toast_type_t::info);
    }
    if (proxy_snapshot && proxy_snapshot->bypass_active) {
        char legacy_buf[96];
        snprintf(legacy_buf, sizeof(legacy_buf), "Legacy cleanup  -  %zu patches", proxy_snapshot->bypass_count);
        same_line_if_fits(estimate_chip_w(legacy_buf, 24.f));
        aida::ui::pill_kind(legacy_buf, aida::ui::pill_kind_t::warning, aida::ui::size_t_::sm, false);
        same_line_if_fits(142.f);
        if (aida::ui::button("Revert legacy patches", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "cert_pin_revert_clicked patches=%zu",
                proxy_snapshot->bypass_count);
            s_bypass_review_count = proxy_snapshot->bypass_count;
            ImGui::OpenPopup("Review Legacy Patch Reversion");
        }
    }

    if (aida::ui::design::begin_dialog_exact("Review Legacy Patch Reversion",
        ImVec2(520.f, 260.f), ImVec2(400.f, 220.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Confirm Revert");
        if (aida::ui::design::begin_dialog_body("legacy_patch_reversion_body", footer)) {
            ImGui::Text("Revert %zu live certificate bypass patches?", s_bypass_review_count);
            ImGui::TextWrapped("The worker will restore reviewed process memory and verify that no bypass remains active.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "legacy_patch_reversion_footer", "Confirm Revert", s_bypass_review_count != 0, true);
        if (result.confirmed) {
            request_legacy_bypass_revert(s_bypass_review_count);
            s_bypass_review_count = 0;
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled) {
            s_bypass_review_count = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
        "Target PID:");
    same_line_if_fits(112.f);
    ImGui::SetNextItemWidth(110.f);
    ImGui::InputInt("##cert_diag_pid", &s_cert_diag_ui.target_pid, 1, 100, ImGuiInputTextFlags_CharsDecimal);
    if (s_cert_diag_ui.target_pid < 0) s_cert_diag_ui.target_pid = 0;
    same_line_if_fits(118.f);
    const bool certificate_diagnostics_pending = s_cert_diagnostics_pending.load(std::memory_order_acquire);
    if (aida::ui::button(certificate_diagnostics_pending ? "Diagnosing...##cert_diag" : "Diagnose target##cert_diag",
                         aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), certificate_diagnostics_pending)) {
        cert_intercept::diagnostic_context_t context;
        context.proxy_running = running;
        context.ca_trusted = ca_installed;
        context.controlled_browser = controlled_browser_running;
        context.proxy_endpoint = std::string(state.proxy_bind_addr) + ":" + std::to_string(state.proxy_port);
        if (s_cert_diag_ui.target_pid > 0) {
            request_certificate_diagnostics(static_cast<std::uint32_t>(s_cert_diag_ui.target_pid), std::move(context));
        } else {
            s_cert_diag_ui.has_report = false;
            s_cert_diag_ui.status = "Select a live PID before diagnostics";
        }
    }
    if (!s_cert_diag_ui.status.empty()) {
        same_line_if_fits(std::min(360.f, ImGui::CalcTextSize(s_cert_diag_ui.status.c_str()).x + 8.f));
        clipped_text(s_cert_diag_ui.status.c_str(), aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);
    }
    if (s_cert_diag_ui.has_report) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "Recommended tier: %s", s_cert_diag_ui.report.recommended_tier.c_str());
        int shown = 0;
        for (const auto& finding : s_cert_diag_ui.report.findings) {
            if (shown++ >= 3) break;
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "%s: %s", cert_intercept::to_string(finding.severity).c_str(), finding.title.c_str());
            clipped_text(finding.next_action.c_str(), aida::ui::with_alpha(th.text_dim, alpha * th.disabled_alpha), ImGui::GetContentRegionAvail().x);
        }
        if (!s_cert_diag_ui.providers.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                "Providers:");
            bool first_provider = true;
            for (const auto& provider : s_cert_diag_ui.providers) {
                char provider_buf[160];
                snprintf(provider_buf, sizeof(provider_buf), "%s:%s",
                    provider.descriptor.provider_id.c_str(),
                    cert_intercept::to_string(provider.state).c_str());
                if (!first_provider)
                    same_line_if_fits(estimate_chip_w(provider_buf, 24.f));
                aida::ui::pill_kind(provider_buf,
                    provider.state == cert_intercept::provider_state_t::available ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::neutral,
                    aida::ui::size_t_::sm, false);
                first_provider = false;
            }
        }
        bool can_handoff = s_cert_diag_ui.report.primary == cert_intercept::classification_t::true_pinning ||
            s_cert_diag_ui.report.primary == cert_intercept::classification_t::app_specific_tls_stack;
        if (can_handoff) {
            const bool handoff_pending = s_cert_handoff_pending.load(std::memory_order_acquire);
            if (aida::ui::button(handoff_pending ? "Generating...##cert_handoff" : "Generate handoff##cert_handoff",
                                 aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                                 ImVec2(0.f, 0.f), handoff_pending))
                request_certificate_handoff(s_cert_diag_ui.report, s_cert_diag_ui.providers,
                    std::string(state.proxy_bind_addr) + ":" + std::to_string(state.proxy_port));
            if (!s_cert_diag_ui.handoff_status.empty()) {
                same_line_if_fits(std::min(360.f, ImGui::CalcTextSize(s_cert_diag_ui.handoff_status.c_str()).x + 8.f));
                clipped_text(s_cert_diag_ui.handoff_status.c_str(), aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);
            }
        }
    }
    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    float cursor_y = ImGui::GetCursorPosY();
    float list_h = std::max(120.f, (h - cursor_y - 16.f) * 0.58f);
    static const std::vector<mitm_proxy::http_exchange> empty_history;
    const auto& history = proxy_snapshot ? proxy_snapshot->history : empty_history;

    if (history.empty()) {
        state.proxy_selected = -1;
        s_proxy_selected_exchange_id = 0;
        clear_stale_network_selection("view.network.proxy");
        ImVec2 list_org = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = running ? "Awaiting requests" : "Proxy idle";
        cfg.body  = running
            ? "Configure a client to use this proxy. Captured exchanges will appear here."
            : "Start the proxy to intercept and inspect HTTP/S traffic.";
        aida::ui::empty_state::render(list_org, ImVec2(w - 4.f, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, list_h));
        ImGui::EndChild();
        return;
    }

    if (s_proxy_selected_exchange_id != 0) {
        const auto selected = std::find_if(history.begin(), history.end(), [](const auto& exchange) {
            return exchange.id == s_proxy_selected_exchange_id;
        });
        if (selected == history.end()) {
            state.proxy_selected = -1;
            s_proxy_selected_exchange_id = 0;
            clear_stale_network_selection("view.network.proxy");
        } else {
            state.proxy_selected = static_cast<int>(std::distance(history.begin(), selected));
        }
    } else if (state.proxy_selected >= 0 &&
               state.proxy_selected < static_cast<int>(history.size())) {
        s_proxy_selected_exchange_id =
            history[static_cast<std::size_t>(state.proxy_selected)].id;
    } else {
        state.proxy_selected = -1;
    }

    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerH |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable |
        ImGuiTableFlags_SizingStretchProp;

    static std::vector<int> filtered_history_indices;
    static std::shared_ptr<const proxy_runtime_snapshot_t> filtered_proxy_snapshot;
    static std::string filtered_proxy_query;
    const std::string current_proxy_query(state.proxy_filter_text);
    if (filtered_proxy_snapshot != proxy_snapshot || filtered_proxy_query != current_proxy_query) {
        filtered_proxy_snapshot = proxy_snapshot;
        filtered_proxy_query = current_proxy_query;
        filtered_history_indices.clear();
        filtered_history_indices.reserve(history.size());
        for (int index = 0; index < static_cast<int>(history.size()); ++index) {
            const auto& exchange = history[static_cast<size_t>(index)];
            if (!current_proxy_query.empty()) {
                const std::string searchable = exchange.target_host + " " + exchange.request.method + " " + exchange.request.uri;
                if (!filter_text_match(current_proxy_query.c_str(), searchable))
                    continue;
            }
            filtered_history_indices.push_back(index);
        }
    }

    int visible_rows = static_cast<int>(filtered_history_indices.size());
    if (ImGui::BeginTable("##proxy_history_table", 8, table_flags, ImVec2(w - 4.f, list_h))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 54.f);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 72.f);
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.75f);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.35f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 76.f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.f);
        ImGui::TableSetupColumn("TLS", ImGuiTableColumnFlags_WidthFixed, 48.f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered_history_indices.size()), 24.f);
        while (clipper.Step()) {
        for (int visible_index = clipper.DisplayStart; visible_index < clipper.DisplayEnd; ++visible_index) {
            const int i = filtered_history_indices[static_cast<size_t>(visible_index)];
            auto& ex = history[static_cast<size_t>(i)];

            float row_alpha = 1.f;
            float row_yoff = 0.f;
            compute_row_entrance(s_proxy_rows, history.size(), row_alpha, row_yoff, i);
            (void)row_yoff;
            float r_alpha = alpha * row_alpha;
            bool selected = (state.proxy_selected == i);
            ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
            ImU32 dim_col = aida::ui::with_alpha(th.text_dim, r_alpha);

            ImGui::TableNextRow(ImGuiTableRowFlags_None, 24.f);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(i);
            char buf[64];
            snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(ex.id));
            if (ImGui::Selectable(buf, selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                  ImVec2(0.f, 22.f))) {
                state.proxy_selected = i;
                s_proxy_selected_exchange_id = ex.id;
                publish_network_selection(
                    exchange_artifact_identity(ex, artifact_kind_t::request), true);
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const auto proxy_request_identity =
                exchange_artifact_identity(ex, artifact_kind_t::request);
            const std::string proxy_artifact_id =
                semantic_artifact_id("exchange", proxy_request_identity);
            register_network_last_item(
                proxy_artifact_id, "network-exchange-row",
                "aida.dock-window.view.network.proxy");
#endif
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                state.proxy_selected = i;
                s_proxy_selected_exchange_id = ex.id;
                publish_network_selection(
                    exchange_artifact_identity(ex, artifact_kind_t::request), true);
                open_exchange_context(
                    exchange_artifact_identity(ex, artifact_kind_t::request),
                    exchange_artifact_identity(ex, artifact_kind_t::response),
                    exchange_context_origin_t::pointer);
            }
            ImGui::PopID();

            ImGui::TableSetColumnIndex(1);
            table_text(ex.request.method, ui_anim::http_method_color(ex.request.method.c_str(), r_alpha));

            ImGui::TableSetColumnIndex(2);
            table_text(ex.target_host, txt_col);

            ImGui::TableSetColumnIndex(3);
            table_text(ex.request.uri, txt_col);

            ImGui::TableSetColumnIndex(4);
            if (ex.response.status_code > 0) {
                snprintf(buf, sizeof(buf), "%d", ex.response.status_code);
                table_text(buf, aida::ui::with_alpha(status_code_color(ex.response.status_code), r_alpha));
            } else {
                const char* st = "...";
                ImU32 st_col = dim_col;
                if (ex.state == mitm_proxy::http_exchange::state_t::dropped) {
                    st = "DROP";
                    st_col = aida::ui::with_alpha(th.error, r_alpha);
                } else if (ex.state == mitm_proxy::http_exchange::state_t::error) {
                    st = "ERR";
                    st_col = aida::ui::with_alpha(th.error, r_alpha);
                }
                table_text(st, st_col);
            }

            ImGui::TableSetColumnIndex(5);
            snprintf(buf, sizeof(buf), "%llums", static_cast<unsigned long long>(ex.latency_ms));
            table_text(buf, txt_col);

            ImGui::TableSetColumnIndex(6);
            table_text(format_bytes(ex.response_size), txt_col);

            ImGui::TableSetColumnIndex(7);
            table_text(ex.is_tls ? "TLS" : "-", ex.is_tls ? aida::ui::with_alpha(th.success, r_alpha)
                                                          : dim_col);
        }
        }
        ImGui::EndTable();
    }

    const bool proxy_menu_key = state.proxy_selected >= 0 &&
        state.proxy_selected < static_cast<int>(history.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool proxy_shift_f10 = !proxy_menu_key && state.proxy_selected >= 0 &&
        state.proxy_selected < static_cast<int>(history.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
        ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (proxy_menu_key || proxy_shift_f10) {
        const auto& selected = history[static_cast<size_t>(state.proxy_selected)];
        open_exchange_context(
            exchange_artifact_identity(selected, artifact_kind_t::request),
            exchange_artifact_identity(selected, artifact_kind_t::response),
            proxy_menu_key
                ? exchange_context_origin_t::menu_key
                : exchange_context_origin_t::shift_f10);
    }

    if (visible_rows == 0) {
        ImVec2 empty_pos = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No matching requests";
        cfg.body = "Clear or adjust the proxy filter to show captured exchanges.";
        aida::ui::empty_state::render(empty_pos, ImVec2(w - 4.f, 80.f), cfg);
        ImGui::Dummy(ImVec2(0.f, 80.f));
    }


    float detail_h = h - ImGui::GetCursorPosY() - 8.f;
    if (detail_h > 30.f && state.proxy_selected >= 0 && state.proxy_selected < static_cast<int>(history.size())) {
        dl->AddLine(ImVec2(org.x + 2.f, org.y + ImGui::GetCursorPosY()),
                    ImVec2(org.x + w - 2.f, org.y + ImGui::GetCursorPosY()),
                    aida::ui::with_alpha(th.border_subtle, alpha));
        ImGui::Spacing();
        ImGui::BeginChild("##proxy_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        auto& ex = history[static_cast<size_t>(state.proxy_selected)];
        publish_network_selection(exchange_artifact_identity(ex, artifact_kind_t::request));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const auto proxy_request_identity =
            exchange_artifact_identity(ex, artifact_kind_t::request);
        const auto proxy_response_identity =
            exchange_artifact_identity(ex, artifact_kind_t::response);
        const std::string proxy_artifact_id =
            semantic_artifact_id("exchange", proxy_request_identity);
        const std::string proxy_request_id =
            semantic_artifact_id("request", proxy_request_identity);
        const std::string proxy_response_id =
            semantic_artifact_id("response", proxy_response_identity);
#endif
        ImU32 method_col = ui_anim::http_method_color(ex.request.method.c_str(), alpha);

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(method_col), "%s", ex.request.method.c_str());
        same_line_if_fits(std::min(520.f, ImGui::CalcTextSize(ex.request.uri.c_str()).x + 8.f));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                            "%s", ex.request.uri.c_str());

        char meta_buf[256];
        snprintf(meta_buf, sizeof(meta_buf), "%s:%u  %s  %llums  req=%s  resp=%s",
            ex.target_host.c_str(), static_cast<unsigned>(ex.target_port),
            ex.is_tls ? "TLS" : "Plain",
            static_cast<unsigned long long>(ex.latency_ms),
            format_bytes(ex.raw_request.size()).c_str(),
            format_bytes(ex.response_size).c_str());
        clipped_text(meta_buf, aida::ui::with_alpha(th.text_secondary, alpha), ImGui::GetContentRegionAvail().x);

        const bool send_to_repeater = aida::ui::button(
            "Send to Repeater", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            proxy_artifact_id + ".action.send-to-repeater", "network-artifact-action",
            proxy_artifact_id);
#endif
        if (send_to_repeater) {
            std::string unavailable;
            static_cast<void>(execute_retained_exchange_toolbar_action(
                "network.exchange.repeater",
                exchange_artifact_identity(ex, artifact_kind_t::request),
                exchange_artifact_identity(ex, artifact_kind_t::response), unavailable));
        }
        same_line_if_fits(96.f);
        const bool copy_proxy_url = aida::ui::button(
            "Copy URL", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            proxy_artifact_id + ".action.copy-url", "network-artifact-action",
            proxy_artifact_id);
#endif
        if (copy_proxy_url) {
            std::string unavailable;
            static_cast<void>(execute_retained_exchange_toolbar_action(
                "network.exchange.copy_url",
                exchange_artifact_identity(ex, artifact_kind_t::request),
                exchange_artifact_identity(ex, artifact_kind_t::response), unavailable));
        }

        ImGui::Spacing();
        std::string request_text = payload_display_text(ex.raw_request);
        std::string response_text = payload_display_text(ex.raw_response);
        char req_meta[96];
        snprintf(req_meta, sizeof(req_meta), "%zu headers  %s",
            ex.request.headers.size(), format_bytes(ex.raw_request.size()).c_str());
        char resp_meta[128];
        if (ex.response.status_code > 0) {
            snprintf(resp_meta, sizeof(resp_meta), "%d %s  %zu headers  %s",
                ex.response.status_code,
                ex.response.reason.c_str(),
                ex.response.headers.size(),
                format_bytes(ex.raw_response.size()).c_str());
        } else {
            snprintf(resp_meta, sizeof(resp_meta), "pending  %s", format_bytes(ex.raw_response.size()).c_str());
        }
        float pane_h = std::max(80.f, detail_h - ImGui::GetCursorPosY() - 6.f);
        if (w >= 900.f) {
            float pane_w = (w - 16.f) * 0.5f;
            render_payload_box("##proxy_request_payload", "Request", req_meta, request_text,
                               ImVec2(pane_w, pane_h), th, alpha);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            register_network_last_item(
                proxy_request_id, "network-request-editor", proxy_artifact_id);
#endif
            ImGui::SameLine();
            render_payload_box("##proxy_response_payload", "Response", resp_meta, response_text,
                               ImVec2(pane_w, pane_h), th, alpha);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            register_network_last_item(
                proxy_response_id, "network-response-editor", proxy_artifact_id);
#endif
        } else {
            float each_h = std::max(72.f, (pane_h - 6.f) * 0.5f);
            render_payload_box("##proxy_request_payload", "Request", req_meta, request_text,
                               ImVec2(w - 8.f, each_h), th, alpha);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            register_network_last_item(
                proxy_request_id, "network-request-editor", proxy_artifact_id);
#endif
            render_payload_box("##proxy_response_payload", "Response", resp_meta, response_text,
                               ImVec2(w - 8.f, each_h), th, alpha);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            register_network_last_item(
                proxy_response_id, "network-response-editor", proxy_artifact_id);
#endif
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static std::string driver_failure_text(const char* fallback) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return fallback ? fallback : "Driver operation failed";
#else
    const std::string detail = driver_bridge::last_error();
    return detail.empty() ? (fallback ? fallback : "Driver operation failed") : detail;
#endif
}

static void request_filter_add(state_t& state) {
    bool expected = false;
    if (!state.filter_mutation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    char* end = nullptr;
    errno = 0;
    const unsigned long parsed_pid = state.nf_pid[0] ? std::strtoul(state.nf_pid, &end, 10) : 0;
    if (errno != 0 || (state.nf_pid[0] && (!end || *end != '\0')) || parsed_pid > UINT32_MAX) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        toast_notification::push("PID must be an unsigned 32-bit integer", toast_notification::toast_type_t::error);
        return;
    }
    end = nullptr;
    errno = 0;
    const unsigned long parsed_port = state.nf_port[0] ? std::strtoul(state.nf_port, &end, 10) : 0;
    if (errno != 0 || (state.nf_port[0] && (!end || *end != '\0')) || parsed_port > UINT16_MAX) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        toast_notification::push("Port must be between 0 and 65535", toast_notification::toast_type_t::error);
        return;
    }
    std::array<std::uint8_t, 16> ip_bytes{};
    const std::string ip_text(state.nf_ip);
    if (!ip_text.empty() && inet_pton(AF_INET, ip_text.c_str(), ip_bytes.data()) != 1) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        toast_notification::push("Filter IP address is not valid IPv4", toast_notification::toast_type_t::error);
        return;
    }
    const std::uint32_t action = static_cast<std::uint32_t>(state.nf_action);
    const std::uint32_t direction = static_cast<std::uint32_t>(state.nf_direction);
    const std::uint32_t protocol = static_cast<std::uint32_t>(state.nf_protocol);
    const std::uint32_t pid = static_cast<std::uint32_t>(parsed_pid);
    const std::uint16_t port = static_cast<std::uint16_t>(parsed_port);
    const std::uint64_t serial = state.filter_mutation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string target = "action=" + std::to_string(action) + " direction=" +
        std::to_string(direction) + " protocol=" + std::to_string(protocol) +
        " pid=" + std::to_string(pid) + " port=" + std::to_string(port) +
        (ip_text.empty() ? std::string() : " ip=" + ip_text);
    const std::string task_id = register_network_operation(
        "network.filters.add", "Add network filter rule", "view.network.filters", target);
    const bool posted = post_network_task(
        "filter_add", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, action, direction, protocol, pid, port, ip_bytes, ip_text, task_id]() {
            std::uint32_t rule_id = 0;
            bool success = false;
            std::string error;
            try {
                success = driver_feature_ready("filter_add") && driver_bridge::add_filter_rule(
                    action, direction, protocol, pid, port, ip_bytes.data(), nullptr, &rule_id);
                if (!success)
                    error = driver_failure_text("Failed to add filter rule");
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Failed to add filter rule";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "Rule #" + std::to_string(rule_id) + " applied" : error);
            enqueue_ui_completion([serial, success, rule_id, action, direction, protocol, pid, port,
                                   ip_text, error = std::move(error)]() {
                if (g_state.filter_mutation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    filter_entry_t entry;
                    entry.rule_id = rule_id;
                    entry.action = static_cast<std::uint8_t>(action);
                    entry.direction = static_cast<std::uint8_t>(direction);
                    entry.protocol = static_cast<std::uint8_t>(protocol);
                    entry.pid = pid;
                    entry.port = port;
                    entry.ip_addr = ip_text;
                    entry.active = true;
                    g_state.filters.push_back(std::move(entry));
                    toast_notification::push("Filter rule added", toast_notification::toast_type_t::info);
                } else {
                    toast_notification::push(error.empty() ? "Failed to add filter rule" : error,
                        toast_notification::toast_type_t::error);
                }
                g_state.filter_mutation_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected filter mutation");
    }
}

static void request_filter_clear(state_t& state) {
    bool expected = false;
    if (!state.filter_mutation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.filter_mutation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::size_t reviewed_count = state.filters.size();
    const std::string task_id = register_network_operation(
        "network.filters.clear", "Clear all network filter rules", "view.network.filters",
        std::to_string(reviewed_count) + " reviewed rules");
    const bool posted = post_network_task(
        "filter_clear", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, reviewed_count, task_id]() {
            bool success = false;
            std::string error;
            try {
                success = driver_feature_ready("filter_clear") && driver_bridge::clear_filter_rules();
                if (!success)
                    error = driver_failure_text("Failed to clear filter rules");
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Failed to clear filter rules";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(reviewed_count) + " rules cleared" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.filter_mutation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    g_state.filters.clear();
                    g_state.filter_selected = -1;
                } else
                    toast_notification::push(error.empty() ? "Failed to clear filter rules" : error,
                        toast_notification::toast_type_t::error);
                g_state.filter_mutation_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected filter mutation");
    }
}

static void request_filter_remove(state_t& state, std::uint32_t rule_id) {
    bool expected = false;
    if (!state.filter_mutation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.filter_mutation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.filters.remove_selected", "Remove network filter rule", "view.network.filters",
        "rule #" + std::to_string(rule_id));
    const bool posted = post_network_task(
        "filter_remove", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, rule_id, task_id]() {
            bool success = false;
            std::string error;
            try {
                success = driver_feature_ready("filter_remove") && driver_bridge::remove_filter_rule(rule_id);
                if (!success)
                    error = driver_failure_text("Failed to remove filter rule");
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Failed to remove filter rule";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "Rule #" + std::to_string(rule_id) + " removed" : error);
            enqueue_ui_completion([serial, rule_id, success, error = std::move(error)]() {
                if (g_state.filter_mutation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    g_state.filters.erase(std::remove_if(g_state.filters.begin(), g_state.filters.end(),
                        [rule_id](const filter_entry_t& entry) { return entry.rule_id == rule_id; }),
                        g_state.filters.end());
                    g_state.filter_selected = -1;
                } else {
                    toast_notification::push(error.empty() ? "Failed to remove filter rule" : error,
                        toast_notification::toast_type_t::error);
                }
                g_state.filter_mutation_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        state.filter_mutation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected filter mutation");
    }
}

static void render_filters(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab; (void)w; (void)h;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_filters", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_driver_available_snapshot();
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Add Filter Rule");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Action:");
    ImGui::SameLine();
    aida::ui::radio_button("Block", &state.nf_action, 0); ImGui::SameLine();
    aida::ui::radio_button("Allow", &state.nf_action, 1);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Direction:");
    ImGui::SameLine();
    aida::ui::radio_button("In", &state.nf_direction, 0); ImGui::SameLine();
    aida::ui::radio_button("Out", &state.nf_direction, 1); ImGui::SameLine();
    aida::ui::radio_button("Both", &state.nf_direction, 2);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Protocol:");
    ImGui::SameLine();
    aida::ui::radio_button("Any", &state.nf_protocol, 0); ImGui::SameLine();
    aida::ui::radio_button("TCP##f", &state.nf_protocol, 6); ImGui::SameLine();
    aida::ui::radio_button("UDP##f", &state.nf_protocol, 17);

    aida::ui::input_text("##nf_pid_in", state.nf_pid, sizeof(state.nf_pid), "PID",
                          false, ImVec2(110.f, 28.f));
    ImGui::SameLine();
    aida::ui::input_text("##nf_port_in", state.nf_port, sizeof(state.nf_port), "Port",
                          false, ImVec2(110.f, 28.f));
    ImGui::SameLine();
    aida::ui::input_text("##nf_ip_in", state.nf_ip, sizeof(state.nf_ip), "IP Address",
                          false, ImVec2(180.f, 28.f));
    ImGui::SameLine();

    const bool mutation_pending = state.filter_mutation_pending.load(std::memory_order_acquire);
    if (!driver_ok || mutation_pending) ImGui::BeginDisabled();
    if (aida::ui::button(mutation_pending ? "Applying...##filter_add" : "Add Rule##filter_add",
                         aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
        invoke_global_network_action("network.filters.add");

    ImGui::SameLine();
    if (aida::ui::button("Clear All", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
        invoke_global_network_action("network.filters.clear");
    if (!driver_ok || mutation_pending) ImGui::EndDisabled();

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Active Rules:");
    ImGui::Spacing();

    if (state.filters.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "No active filter rules.");
    }

    std::uint32_t remove_rule_id = 0;
    ImGuiListClipper filter_clipper;
    filter_clipper.Begin(static_cast<int>(state.filters.size()));
    while (filter_clipper.Step()) {
    for (int i = filter_clipper.DisplayStart; i < filter_clipper.DisplayEnd; i++) {
        auto& f = state.filters[static_cast<size_t>(i)];
        char rule_buf[192];
        snprintf(rule_buf, sizeof(rule_buf), "#%u  %s  %s %s  PID:%u  Port:%u  %s",
                 static_cast<unsigned>(f.rule_id),
                 f.action == 0 ? "BLOCK" : "ALLOW",
                 f.direction == 0 ? "IN" : f.direction == 1 ? "OUT" : "BOTH",
                 f.protocol == 6 ? "TCP" : f.protocol == 17 ? "UDP" : "ANY",
                 static_cast<unsigned>(f.pid), static_cast<unsigned>(f.port), f.ip_addr.c_str());
        aida::ui::pill_kind_t kind = (f.action == 0)
            ? aida::ui::pill_kind_t::error
            : aida::ui::pill_kind_t::success;
        aida::ui::pill_kind(rule_buf, kind, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        ImGui::PushID(i);
        ImGui::BeginDisabled(mutation_pending);
        if (aida::ui::button("Remove", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            state.filter_selected = i;
            remove_rule_id = f.rule_id;
        }
        ImGui::EndDisabled();
        ImGui::PopID();
    }
    }
    if (remove_rule_id != 0) {
        invoke_global_network_action("network.filters.remove_selected");
    }

    ImGui::EndChild();
}


static void request_bandwidth_control(state_t& state, bool start) {
    bool expected = false;
    if (!state.bw_control_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.bw_control_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        start ? "network.bandwidth.start" : "network.bandwidth.stop",
        start ? "Start bandwidth monitor" : "Stop bandwidth monitor",
        "view.network.bandwidth", "kernel bandwidth telemetry");
    const bool posted = post_network_task(
        start ? "bandwidth_start" : "bandwidth_stop",
        aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, start, task_id]() {
            bool success = false;
            std::string error;
            try {
                success = driver_feature_ready(start ? "bandwidth_start" : "bandwidth_stop") &&
                    driver_bridge::bw_monitor_op(start ? 0U : 1U);
                if (!success)
                    error = driver_failure_text(start ? "Failed to start bandwidth monitor"
                                                      : "Failed to stop bandwidth monitor");
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = start ? "Failed to start bandwidth monitor" : "Failed to stop bandwidth monitor";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? (start ? "Bandwidth telemetry started" : "Bandwidth telemetry stopped") : error);
            enqueue_ui_completion([serial, start, success, error = std::move(error)]() {
                if (g_state.bw_control_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    g_state.bw_monitoring = start;
                    g_state.bw_polling.store(start, std::memory_order_release);
                    if (start)
                        g_state.bw_cv.notify_one();
                } else {
                    toast_notification::push(error.empty()
                        ? (start ? "Failed to start bandwidth monitor" : "Failed to stop bandwidth monitor")
                        : error, toast_notification::toast_type_t::error);
                }
                g_state.bw_control_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        state.bw_control_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected bandwidth control");
    }
}

static void render_bandwidth(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_bw", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_driver_available_snapshot();
    const bool driver_ok = s_driver_available_snapshot.load(std::memory_order_acquire);

    const bool control_pending = state.bw_control_pending.load(std::memory_order_acquire);
    if (!driver_ok || control_pending) ImGui::BeginDisabled();

    if (!state.bw_polling.load()) {
        if (aida::ui::button("Start Monitoring", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            request_bandwidth_control(state, true);
        }
    } else {
        if (aida::ui::button("Stop Monitoring", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            request_bandwidth_control(state, false);
        }
    }

    if (!driver_ok || control_pending) ImGui::EndDisabled();
    if (control_pending) {
        ImGui::SameLine();
        ImGui::TextDisabled("Applying driver state...");
    }
    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 26.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 64.f, col_name = 160.f, col_spark = 130.f;
    float col_in = (w - col_pid - col_name - col_spark - 24.f) * 0.25f;
    float col_out = col_in, col_rin = col_in, col_rout = col_in;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");       cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Process");   cx += col_name;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "In");        cx += col_in;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Out");       cx += col_out;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "In Rate");   cx += col_rin;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Out Rate");  cx += col_rout;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Trend");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##bw_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    const auto bandwidth_entries = std::atomic_load_explicit(&state.bandwidth_snapshot, std::memory_order_acquire);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 bw_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + bw_list_sz.x, list_org.y + bw_list_sz.y), true);

    if (!bandwidth_entries || bandwidth_entries->empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = state.bw_polling.load() ? "Collecting metrics" : "Bandwidth monitor idle";
        cfg.body  = state.bw_polling.load()
            ? "Per-process bandwidth statistics will appear shortly."
            : "Click Start Monitoring above to track per-process bandwidth.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(bw_list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    ImGuiListClipper bandwidth_clipper;
    bandwidth_clipper.Begin(static_cast<int>(bandwidth_entries->size()), row_h);
    while (bandwidth_clipper.Step()) {
    for (int i = bandwidth_clipper.DisplayStart; i < bandwidth_clipper.DisplayEnd; i++) {
        const auto& b = (*bandwidth_entries)[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.bw_selected == i);

        if (i & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha * 0.30f));

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.bw_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, alpha);
        cx = list_org.x + 8.f;

        char buf[32];
        snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(b.pid));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += col_pid;

        std::string name = b.process_name.empty() ? "-" : b.process_name;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, name.c_str()); cx += col_name;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.info, alpha),
            format_bytes(b.bytes_in).c_str()); cx += col_in;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.warning, alpha),
            format_bytes(b.bytes_out).c_str()); cx += col_out;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, format_rate(b.rate_in).c_str()); cx += col_rin;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, format_rate(b.rate_out).c_str()); cx += col_rout;

        int hist_count = std::min(b.history_index, 64);
        if (hist_count > 1) {
            float ordered[64];
            float max_v = 0.0001f;
            int peak_idx = 0;
            for (int hi = 0; hi < hist_count; hi++) {
                int idx = (b.history_index - hist_count + hi) % 64;
                if (idx < 0) idx += 64;
                ordered[hi] = b.rate_history[idx];
                if (ordered[hi] > max_v) { max_v = ordered[hi]; peak_idx = hi; }
            }
            float spark_x = cx;
            float spark_y = abs_ry + 4.f;
            float spark_w = col_spark - 8.f;
            float spark_h = row_h - 8.f;
            ImU32 spark_line = aida::ui::with_alpha(th.accent_u32, alpha);
            ImU32 spark_fill = aida::ui::with_alpha(th.accent_glow, alpha * 0.55f);
            ui_anim::render_sparkline(dl, spark_x, spark_y, spark_w, spark_h,
                                      ordered, hist_count, spark_line, spark_fill);

            float step = spark_w / static_cast<float>(hist_count - 1);
            float peak_x = spark_x + step * static_cast<float>(peak_idx);
            float peak_y = spark_y + spark_h - (ordered[peak_idx] / max_v) * spark_h;
            dl->AddCircleFilled(ImVec2(peak_x, peak_y), 2.5f,
                                 aida::ui::with_alpha(th.warning, alpha), 12);
            dl->AddCircle(ImVec2(peak_x, peak_y), 4.5f,
                           aida::ui::with_alpha(th.warning, alpha * 0.55f), 14, 1.f);

            ImVec2 mp = ImGui::GetMousePos();
            if (mp.x >= spark_x && mp.x <= spark_x + spark_w &&
                mp.y >= spark_y && mp.y <= spark_y + spark_h) {
                int hi = static_cast<int>((mp.x - spark_x) / step + 0.5f);
                if (hi < 0) hi = 0;
                if (hi >= hist_count) hi = hist_count - 1;
                float vx = spark_x + step * static_cast<float>(hi);
                float vy = spark_y + spark_h - (ordered[hi] / max_v) * spark_h;
                dl->AddLine(ImVec2(vx, spark_y), ImVec2(vx, spark_y + spark_h),
                             aida::ui::with_alpha(th.accent_u32, alpha * 0.6f), 1.f);
                dl->AddCircleFilled(ImVec2(vx, vy), 3.f,
                                     aida::ui::with_alpha(th.accent_u32, alpha), 12);
                ImGui::SetCursorScreenPos(ImVec2(mp.x + 12.f, mp.y - 6.f));
                char tip[64];
                snprintf(tip, sizeof(tip), "%s", format_rate(ordered[hi]).c_str());
                ImGui::SetTooltip("%s", tip);
            }
        }

        ImGui::SetCursorPosY(ry + row_h);
    }
    }

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_repeater(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    static std::unordered_map<std::uint64_t, human_request_editor::state_t> request_editors;
    const auto& th = aida::ui::resolved();
    for (auto editor = request_editors.begin(); editor != request_editors.end();) {
        const bool retained = std::any_of(state.repeater_entries.begin(),
            state.repeater_entries.end(), [&](const auto& entry) {
                return entry && entry->id == editor->first;
            });
        editor = retained ? std::next(editor) : request_editors.erase(editor);
    }
    for (auto selected = s_repeater_selected_artifact_kinds.begin();
         selected != s_repeater_selected_artifact_kinds.end();) {
        const bool retained = std::any_of(state.repeater_entries.begin(),
            state.repeater_entries.end(), [&](const auto& entry) {
                return entry && entry->id == selected->first;
            });
        selected = retained ? std::next(selected)
                            : s_repeater_selected_artifact_kinds.erase(selected);
    }
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_rep", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Host:");
    ImGui::SameLine();
    aida::ui::input_text("##rep_host", state.rep_host, sizeof(state.rep_host),
                          "example.com", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Port:");
    ImGui::SameLine();
    aida::ui::input_int("##rep_port", &state.rep_port, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##rep_tls", &state.rep_use_tls);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "TLS");
    ImGui::SameLine();

    const bool repeater_capacity_full =
        state.repeater_entries.size() >= k_max_repeater_entries;
    if (aida::ui::button("New", aida::ui::button_kind_t::primary,
            aida::ui::size_t_::sm, ImVec2(0.f, 0.f), repeater_capacity_full)) {
        auto rep = std::make_shared<repeater_entry_t>();
        rep->id = s_repeater_artifact_sequence.fetch_add(1, std::memory_order_relaxed);
        rep->host = state.rep_host;
        rep->port = static_cast<uint16_t>(state.rep_port);
        rep->use_tls = state.rep_use_tls;
        rep->raw_request = "GET / HTTP/1.1\r\nHost: " + std::string(state.rep_host) + "\r\n\r\n";
        rep->request_hash = artifact_hash(std::string_view(rep->raw_request));
        diag::log_tagged_fmt("network", "repeater_new_entry host=%s:%d tls=%d",
            state.rep_host, state.rep_port, state.rep_use_tls ? 1 : 0);
        state.repeater_entries.push_back(std::move(rep));
        publish_repeater_request_artifacts(state);
        state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
        s_repeater_selected_artifact_kinds[state.repeater_entries.back()->id] =
            artifact_kind_t::repeater_request;
    }


    if (!state.repeater_entries.empty()) {
        ImGui::Spacing();
        for (int i = 0; i < static_cast<int>(state.repeater_entries.size()); i++) {
            if (i > 0) ImGui::SameLine();
            bool is_sel = (state.repeater_selected == i);
            char label[32];
            snprintf(label, sizeof(label), "#%d##rep_tab", i + 1);
            aida::ui::button_kind_t kk = is_sel
                ? aida::ui::button_kind_t::primary
                : aida::ui::button_kind_t::secondary;
            const bool select_repeater_entry =
                aida::ui::button(label, kk, aida::ui::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const auto& semantic_entry = *state.repeater_entries[static_cast<std::size_t>(i)];
            const auto semantic_identity = repeater_artifact_identity(
                semantic_entry, artifact_kind_t::repeater_request);
            register_network_last_item(
                semantic_artifact_id("exchange", semantic_identity),
                "network-exchange-row", "aida.dock-window.view.network.repeater");
#endif
            if (select_repeater_entry) {
                if (state.repeater_selected != i)
                    diag::log_tagged_fmt("network", "repeater_tab_switched from=%d to=%d",
                        state.repeater_selected, i);
                state.repeater_selected = i;
                s_repeater_selected_artifact_kinds[
                    state.repeater_entries[static_cast<std::size_t>(i)]->id] =
                    artifact_kind_t::repeater_request;
                publish_network_selection(repeater_artifact_identity(
                    *state.repeater_entries[static_cast<std::size_t>(i)],
                    artifact_kind_t::repeater_request), true);
            }
        }

        ImGui::SameLine();
        if (state.repeater_selected >= 0 &&
            state.repeater_selected < static_cast<int>(state.repeater_entries.size())) {
            if (aida::ui::button("Close##rep_close", aida::ui::button_kind_t::ghost,
                                  aida::ui::size_t_::sm)) {
                int idx = state.repeater_selected;
                const auto removed_id = state.repeater_entries[static_cast<std::size_t>(idx)]->id;
                diag::log_tagged_fmt("network", "repeater_entry_closed idx=%d", idx);
                state.repeater_entries.erase(
                    state.repeater_entries.begin() + static_cast<ptrdiff_t>(idx));
                request_editors.erase(removed_id);
                s_repeater_selected_artifact_kinds.erase(removed_id);
                publish_repeater_request_artifacts(state);
                if (state.repeater_selected >= static_cast<int>(state.repeater_entries.size()))
                    state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
            }
        }

        ImGui::Spacing();

        if (state.repeater_selected >= 0 && state.repeater_selected < static_cast<int>(state.repeater_entries.size())) {
            auto rep_ptr = state.repeater_entries[static_cast<size_t>(state.repeater_selected)];
            auto& rep = *rep_ptr;
            if (rep.id == 0) {
                rep.id = s_repeater_artifact_sequence.fetch_add(1, std::memory_order_relaxed);
                publish_repeater_request_artifacts(state);
            }

            if (rep.reviewed_draft) {
                ImGui::SameLine();
                ImGui::TextDisabled("AI REVIEWED DRAFT");
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Source hash: 0x%016llX\nProvenance: %s",
                        static_cast<unsigned long long>(rep.reviewed_source_hash),
                        rep.review_provenance.c_str());
            }

            const bool stack_editors = w < 760.f;
            float half_w = (w - 8.f) * 0.5f;
            float panel_h = h - ImGui::GetCursorPosY() - 40.f;
            if (panel_h < 160.f) panel_h = 160.f;
            float req_w = stack_editors ? std::max(120.f, w - 4.f) : half_w;
            float resp_w = req_w;
            float req_h = panel_h;
            float resp_h = panel_h;
            if (stack_editors) {
                req_h = std::max(124.f, (panel_h - 8.f) * 0.5f);
                resp_h = std::max(124.f, panel_h - req_h - 8.f);
            }


            ImGui::BeginChild("##rep_req", ImVec2(req_w, req_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Request");
            const auto request_identity = repeater_artifact_identity(
                rep, artifact_kind_t::repeater_request);
            const auto selected_kind_found =
                s_repeater_selected_artifact_kinds.find(rep.id);
            const artifact_kind_t selected_kind =
                selected_kind_found != s_repeater_selected_artifact_kinds.end()
                    ? selected_kind_found->second
                    : artifact_kind_t::repeater_request;
            const auto selected_identity = repeater_artifact_identity(rep, selected_kind);
            if (selected_identity.valid())
                publish_network_selection(selected_identity);
            else if (request_identity.valid())
                publish_network_selection(request_identity);
            else
                clear_stale_network_selection("view.network.repeater");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string request_editor_parent =
                semantic_artifact_id("exchange", request_identity);
#endif
            const std::string editor_identity = "repeater." + std::to_string(rep.id);
            auto& request_editor = request_editors[rep.id];
            human_request_editor::render_config_t editor_config;
            editor_config.stable_id = "repeater-request";
            editor_config.size = ImVec2(req_w - 4.f, std::max(72.f, req_h - 70.f));
            editor_config.max_bytes = 1U << 18;
            editor_config.editable = !rep.in_progress.load(std::memory_order_acquire);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            editor_config.semantic_parent_id = request_editor_parent.c_str();
#endif
            ImGui::BeginChild("##rep_request_editor_surface", editor_config.size, false,
                ImGuiWindowFlags_NoBackground);
            editor_config.size = ImGui::GetContentRegionAvail();
            const auto editor_result = human_request_editor::render(
                request_editor, editor_identity, rep.raw_request, editor_config);
            const bool request_menu_key = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool request_shift_f10 = !request_menu_key &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
            ImGui::EndChild();
            const bool request_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const bool request_pointer_select = ImGui::IsItemClicked(ImGuiMouseButton_Left);
            if (request_pointer_select) {
                s_repeater_selected_artifact_kinds[rep.id] = artifact_kind_t::repeater_request;
                publish_network_selection(request_identity, true);
            }
            if (editor_result.authority_changed) {
                s_repeater_selected_artifact_kinds[rep.id] = artifact_kind_t::repeater_request;
                ++rep.request_revision;
                rep.request_hash = artifact_hash(std::string_view(rep.raw_request));
                rep.reviewed_draft = false;
                rep.reviewed_source_hash = 0;
                rep.review_provenance.clear();
                publish_repeater_request_artifacts(state);
                const auto changed_identity = repeater_artifact_identity(
                    rep, artifact_kind_t::repeater_request);
                if (changed_identity.valid())
                    publish_network_selection(changed_identity, true);
                else
                    clear_stale_network_selection("view.network.repeater");
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const auto repeater_request_identity = repeater_artifact_identity(
                rep, artifact_kind_t::repeater_request);
            const std::string repeater_artifact_id =
                request_editor_parent;
            const std::string repeater_request_id =
                semantic_artifact_id("request", repeater_request_identity);
            register_network_last_item(
                repeater_request_id, "network-request-editor", repeater_artifact_id);
#endif
            const bool request_context = request_pointer_context || request_menu_key || request_shift_f10;
            if (request_context) {
                s_repeater_selected_artifact_kinds[rep.id] = artifact_kind_t::repeater_request;
                publish_network_selection(repeater_artifact_identity(
                    rep, artifact_kind_t::repeater_request), true);
                const auto origin = request_pointer_context
                    ? exchange_context_origin_t::pointer
                    : request_menu_key
                    ? exchange_context_origin_t::menu_key
                    : exchange_context_origin_t::shift_f10;
                open_exchange_context(
                    repeater_artifact_identity(rep, artifact_kind_t::repeater_request),
                    repeater_artifact_identity(rep, artifact_kind_t::repeater_response), origin);
            }

            if (!rep.in_progress.load()) {
                const bool send_disabled = !editor_result.valid ||
                    editor_result.has_unapplied_pretty;
                const bool send_repeater_request = aida::ui::button(
                    "Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                    ImVec2(0.f, 0.f), send_disabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                register_network_last_item(
                    repeater_artifact_id + ".action.send", "network-artifact-action",
                    repeater_artifact_id);
#endif
                if (send_repeater_request) {
                    s_repeater_selected_artifact_kinds[rep.id] = artifact_kind_t::repeater_request;
                    publish_network_selection(repeater_artifact_identity(
                        rep, artifact_kind_t::repeater_request), true);
                    human_request_editor::mark_clean(request_editor);
                    rep.in_progress.store(true);
                    std::shared_ptr<repeater_entry_t> entry = rep_ptr;
                    diag::log_tagged_fmt("network", "repeater_send_clicked host=%s:%u tls=%d req_size=%zu",
                        entry->host.c_str(), entry->port, entry->use_tls ? 1 : 0,
                        entry->raw_request.size());
                    diag::log_tagged("net_audit",
                        (std::string("[net_audit] repeater send host=") + entry->host + ":" +
                         std::to_string(entry->port) + " tls=" + (entry->use_tls ? "1" : "0")).c_str());
                    const bool posted = post_network_task("repeater_send", aida::infra::executor::domain_t::external_tool, "bounded_task", [entry]() {
                        std::vector<uint8_t> raw(entry->raw_request.begin(), entry->raw_request.end());
                        auto t0 = GetTickCount64();
                        auto result = mitm_proxy::repeat_request(
                            entry->host, entry->port, entry->use_tls, raw);
                        uint64_t elapsed = GetTickCount64() - t0;
                        if (result.success) {
                            entry->raw_response = std::string(result.exchange.raw_response.begin(),
                                result.exchange.raw_response.end());
                            entry->status_code = result.exchange.response.status_code;
                            entry->latency_ms = result.exchange.latency_ms;
                            entry->response_timestamp = result.exchange.timestamp;
                            entry->response_hash = artifact_hash(result.exchange.raw_response);
                            diag::log_tagged_fmt("network", "repeater_send_ok host=%s:%u status=%d size=%zu latency_ms=%llu wall_ms=%llu",
                                entry->host.c_str(), entry->port, entry->status_code,
                                entry->raw_response.size(),
                                static_cast<unsigned long long>(entry->latency_ms),
                                static_cast<unsigned long long>(elapsed));
                        } else {
                            entry->raw_response = "Error: " + result.error;
                            entry->status_code = 0;
                            diag::log_tagged_fmt("network", "repeater_send_failed host=%s:%u err='%s' wall_ms=%llu",
                                entry->host.c_str(), entry->port, result.error.c_str(),
                                static_cast<unsigned long long>(elapsed));
                            diag::log_tagged("net_audit",
                                (std::string("[net_audit] repeater send FAILED err='") + result.error + "'").c_str());
                        }
                        entry->in_progress.store(false);
                    });
                    if (!posted) {
                        entry->raw_response = "Error: executor rejected repeater_send";
                        entry->status_code = 0;
                        entry->in_progress.store(false);
                    }
                }
                if (ImGui::IsItemHovered()) {
                    if (send_disabled)
                        ImGui::SetTooltip("Resolve the request editor error or apply/discard Pretty edits before sending raw bytes");
                    else
                        ImGui::SetTooltip("Sends the authoritative raw request to %s:%u over %s; this creates live network activity",
                            rep.host.c_str(), static_cast<unsigned>(rep.port), rep.use_tls ? "TLS" : "plain TCP");
                }
            } else {
                aida::ui::pill_kind("Sending...", aida::ui::pill_kind_t::accent,
                                     aida::ui::size_t_::sm, true);
            }

            ImGui::EndChild();

            if (stack_editors) {
                ImGui::Dummy(ImVec2(0.f, 8.f));
            } else {
                ImGui::SameLine();
            }


            ImGui::BeginChild("##rep_resp", ImVec2(resp_w, resp_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Response");

            if (rep.status_code > 0) {
                ImGui::SameLine();
                ImU32 sc_col = aida::ui::with_alpha(status_code_color(rep.status_code), alpha);
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(sc_col), " %d", rep.status_code);
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                    " %llums", static_cast<unsigned long long>(rep.latency_ms));
            }

            ImGui::InputTextMultiline("##rep_resp_view", rep.raw_response.data(),
                rep.raw_response.size() + 1,
                ImVec2(resp_w - 4.f, std::max(72.f, resp_h - 78.f)),
                ImGuiInputTextFlags_ReadOnly);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const auto repeater_response_identity = repeater_artifact_identity(
                rep, artifact_kind_t::repeater_response);
            register_network_last_item(
                semantic_artifact_id("response", repeater_response_identity),
                "network-response-editor", repeater_artifact_id,
                !repeater_response_identity.valid());
#endif
            const bool response_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const bool response_menu_key = ImGui::IsItemFocused() &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool response_shift_f10 = !response_menu_key && ImGui::IsItemFocused() &&
                ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
            const bool response_context = response_pointer_context || response_menu_key || response_shift_f10;
            if (response_context) {
                const auto origin = response_pointer_context
                    ? exchange_context_origin_t::pointer
                    : response_menu_key
                    ? exchange_context_origin_t::menu_key
                    : exchange_context_origin_t::shift_f10;
                const auto response_identity = repeater_artifact_identity(
                    rep, artifact_kind_t::repeater_response);
                if (response_identity.valid())
                    publish_network_selection(response_identity, true);
                s_repeater_selected_artifact_kinds[rep.id] = artifact_kind_t::repeater_response;
                open_exchange_context(
                    response_identity,
                    repeater_artifact_identity(rep, artifact_kind_t::repeater_request), origin);
            }

            ImGui::EndChild();
        } else {
            clear_stale_network_selection("view.network.repeater");
        }
    } else {
        clear_stale_network_selection("view.network.repeater");
        ImVec2 region_pos = ImGui::GetCursorScreenPos();
        ImVec2 region_size = ImVec2(w, h - ImGui::GetCursorPosY() - 8.f);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No repeater entries";
        cfg.body  = "Use New to create one, or Send to Repeater from proxy history.";
        aida::ui::empty_state::render(region_pos, region_size, cfg);
    }

    ImGui::EndChild();
}


struct intercept_runtime_snapshot_t {
    std::uint64_t generation = 0;
    bool running = false;
    bool enabled = false;
    std::vector<mitm_proxy::http_exchange> held;
};

struct intercept_target_identity_t {
    std::uint64_t publication_generation = 0;
    std::uint64_t exchange_id = 0;
    std::uint64_t timestamp = 0;
    std::uint64_t content_hash = 0;
    std::size_t content_size = 0;

    bool valid() const noexcept {
        return publication_generation != 0 && exchange_id != 0 &&
            content_hash != 0;
    }
};

static constexpr std::size_t k_intercept_editor_capacity = 65536U;

struct intercept_modified_draft_t {
    intercept_target_identity_t source;
    std::string raw_request;
    std::uint64_t content_hash = 0;
    bool loaded = false;
    bool editable = false;
    std::string unavailable_reason;
};

enum class intercept_operation_t {
    set_enabled,
    forward_all,
    drop_all,
    forward_one,
    drop_one,
    forward_modified
};

struct intercept_drop_review_t {
    bool open = false;
    bool all = false;
    intercept_target_identity_t target;
    std::size_t reviewed_count = 0;
    std::shared_ptr<const intercept_runtime_snapshot_t> reviewed_publication;
};

static std::shared_ptr<const intercept_runtime_snapshot_t> s_intercept_runtime_snapshot;
static std::atomic<bool> s_intercept_snapshot_pending{false};
static std::atomic<std::uint64_t> s_intercept_snapshot_requested_ms{0};
static std::atomic<std::uint64_t> s_intercept_snapshot_generation{0};
static std::atomic<bool> s_intercept_operation_pending{false};
static std::atomic<std::uint64_t> s_intercept_operation_serial{0};
static intercept_drop_review_t s_intercept_drop_review;
static std::uint64_t s_intercept_selected_exchange_id = 0;
static intercept_modified_draft_t s_intercept_modified_draft;
static human_request_editor::state_t s_intercept_request_editor;
static human_request_editor::state_t s_intercept_original_editor;

static intercept_target_identity_t intercept_target_identity(
    const intercept_runtime_snapshot_t& publication,
    const mitm_proxy::http_exchange& exchange) {
    return {publication.generation, exchange.id, exchange.timestamp,
        artifact_hash(exchange.raw_request), exchange.raw_request.size()};
}

static bool intercept_exchange_matches(const mitm_proxy::http_exchange& exchange,
                                       const intercept_target_identity_t& target) {
    return target.valid() && exchange.id == target.exchange_id &&
        exchange.timestamp == target.timestamp &&
        exchange.raw_request.size() == target.content_size &&
        artifact_hash(exchange.raw_request) == target.content_hash;
}

static bool intercept_target_matches(const intercept_target_identity_t& lhs,
                                     const intercept_target_identity_t& rhs,
                                     bool include_generation) {
    return lhs.exchange_id == rhs.exchange_id && lhs.timestamp == rhs.timestamp &&
        lhs.content_hash == rhs.content_hash && lhs.content_size == rhs.content_size &&
        (!include_generation || lhs.publication_generation == rhs.publication_generation);
}

static bool intercept_editor_compatible(const std::vector<std::uint8_t>& bytes,
                                        std::string& unavailable_reason) {
    if (bytes.empty()) {
        unavailable_reason = "The retained request is empty and cannot be edited or forwarded.";
        return false;
    }
    if (bytes.size() >= k_intercept_editor_capacity) {
        unavailable_reason = "The retained request exceeds the 65535-byte reviewed editor limit; use a binary-safe external workflow.";
        return false;
    }
    const char* cursor = reinterpret_cast<const char*>(bytes.data());
    const char* const end = cursor + bytes.size();
    while (cursor < end) {
        unsigned int codepoint = 0;
        const int consumed = ImTextCharFromUtf8(&codepoint, cursor, end);
        if (consumed <= 0 || cursor + consumed > end ||
            codepoint == IM_UNICODE_CODEPOINT_INVALID) {
            unavailable_reason = "The retained request contains invalid UTF-8 or binary bytes that the text editor cannot represent safely.";
            return false;
        }
        if ((codepoint < 0x20U && codepoint != '\r' && codepoint != '\n' && codepoint != '\t') ||
            codepoint == 0x7FU) {
            unavailable_reason = "The retained request contains binary control bytes that the text editor cannot represent safely.";
            return false;
        }
        cursor += consumed;
    }
    unavailable_reason.clear();
    return true;
}

static bool refresh_intercept_modified_draft(std::string& unavailable_reason) {
    if (!s_intercept_modified_draft.loaded || !s_intercept_modified_draft.editable) {
        unavailable_reason = s_intercept_modified_draft.unavailable_reason.empty()
            ? "The selected request has no editable retained draft."
            : s_intercept_modified_draft.unavailable_reason;
        return false;
    }
    if (s_intercept_modified_draft.raw_request.size() >= k_intercept_editor_capacity) {
        unavailable_reason = "The modified request exceeded its bounded editor capacity.";
        s_intercept_modified_draft.unavailable_reason = unavailable_reason;
        return false;
    }
    if (s_intercept_modified_draft.raw_request.empty()) {
        unavailable_reason = "The modified request is empty and cannot be forwarded.";
        s_intercept_modified_draft.unavailable_reason = unavailable_reason;
        return false;
    }
    s_intercept_modified_draft.content_hash = artifact_hash(std::string_view(
        s_intercept_modified_draft.raw_request));
    s_intercept_modified_draft.unavailable_reason.clear();
    unavailable_reason.clear();
    return true;
}

static void retain_intercept_modified_draft(
    const intercept_runtime_snapshot_t& publication,
    const mitm_proxy::http_exchange& exchange) {
    const auto target = intercept_target_identity(publication, exchange);
    if (s_intercept_modified_draft.loaded &&
        intercept_target_matches(s_intercept_modified_draft.source, target, false)) {
        s_intercept_modified_draft.source.publication_generation = publication.generation;
        return;
    }
    s_intercept_modified_draft = {};
    s_intercept_modified_draft.loaded = true;
    s_intercept_modified_draft.source = target;
    s_intercept_modified_draft.editable = intercept_editor_compatible(
        exchange.raw_request, s_intercept_modified_draft.unavailable_reason);
    if (!s_intercept_modified_draft.editable)
        return;
    s_intercept_modified_draft.raw_request.assign(
        exchange.raw_request.begin(), exchange.raw_request.end());
    s_intercept_modified_draft.content_hash = artifact_hash(exchange.raw_request);
}

static void publish_intercept_runtime_snapshot() {
    auto snapshot = std::make_shared<intercept_runtime_snapshot_t>();
    snapshot->generation = s_intercept_snapshot_generation.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    snapshot->running = mitm_proxy::is_running();
    snapshot->enabled = mitm_proxy::is_intercept_enabled();
    snapshot->held = mitm_proxy::get_held_exchanges();
    std::atomic_store_explicit(&s_intercept_runtime_snapshot,
        std::shared_ptr<const intercept_runtime_snapshot_t>(std::move(snapshot)),
        std::memory_order_release);
}

static void request_intercept_runtime_snapshot(bool force = false) {
    const std::uint64_t now = network_now_ms();
    const std::uint64_t last = s_intercept_snapshot_requested_ms.load(std::memory_order_acquire);
    if (!force && last != 0 && now >= last && now - last < 200)
        return;
    bool expected = false;
    if (!s_intercept_snapshot_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    s_intercept_snapshot_requested_ms.store(now, std::memory_order_release);
    const bool posted = post_network_task(
        "intercept_snapshot", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        []() {
            try {
                publish_intercept_runtime_snapshot();
            } catch (...) {
            }
            s_intercept_snapshot_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted)
        s_intercept_snapshot_pending.store(false, std::memory_order_release);
}

static bool request_intercept_operation(intercept_operation_t operation, bool enabled,
                                        intercept_target_identity_t target,
                                        std::vector<std::uint8_t> modified_request,
                                        std::uint64_t modified_content_hash,
                                        std::size_t reviewed_count,
                                        std::shared_ptr<const intercept_runtime_snapshot_t>
                                            reviewed_publication = {}) {
    bool expected = false;
    if (!s_intercept_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return false;
    const std::uint64_t serial = s_intercept_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const char* action = "network.intercept.forward_selected";
    const char* label = "Forward held exchange";
    std::string target_summary = target.exchange_id == 0
        ? std::to_string(reviewed_count) + " held exchanges"
        : "exchange " + std::to_string(target.exchange_id);
    switch (operation) {
    case intercept_operation_t::set_enabled:
        action = "network.intercept.toggle_enabled";
        label = enabled ? "Enable request interception" : "Disable request interception";
        target_summary = enabled ? "interception enabled" : "interception disabled";
        break;
    case intercept_operation_t::forward_all:
        action = "network.intercept.forward_all";
        label = "Forward all held exchanges";
        break;
    case intercept_operation_t::drop_all:
        action = "network.intercept.drop_all";
        label = "Drop all held exchanges";
        break;
    case intercept_operation_t::drop_one:
        action = "network.intercept.drop_selected";
        label = "Drop held exchange";
        break;
    case intercept_operation_t::forward_modified:
        action = "network.intercept.forward_modified";
        label = "Forward modified exchange";
        break;
    default:
        break;
    }
    const std::string task_id = register_network_operation(
        action, label, "view.network.intercept", target_summary);
    const bool posted = post_network_task(
        "intercept_mutation", aida::infra::executor::domain_t::feature_worker, "bounded_task",
        [serial, operation, enabled, target, modified_request = std::move(modified_request),
         modified_content_hash, reviewed_count,
         reviewed_publication = std::move(reviewed_publication), task_id]() {
            bool success = false;
            std::string error;
            try {
                std::vector<mitm_proxy::http_exchange> live_held;
                const auto validate_selected = [&]() -> const mitm_proxy::http_exchange* {
                    if (!reviewed_publication || !target.valid() ||
                        target.publication_generation != reviewed_publication->generation) {
                        error = "The exact reviewed Intercept publication is unavailable";
                        return nullptr;
                    }
                    const auto reviewed = std::find_if(reviewed_publication->held.begin(),
                        reviewed_publication->held.end(), [&](const auto& exchange) {
                            return intercept_exchange_matches(exchange, target);
                        });
                    if (reviewed == reviewed_publication->held.end()) {
                        error = "The reviewed held exchange identity does not match its immutable publication";
                        return nullptr;
                    }
                    live_held = mitm_proxy::get_held_exchanges();
                    const auto live = std::find_if(live_held.begin(), live_held.end(),
                        [&](const auto& exchange) {
                            return intercept_exchange_matches(exchange, target);
                        });
                    if (live == live_held.end()) {
                        error = "The held exchange changed after review; select and review it again";
                        return nullptr;
                    }
                    return &*reviewed;
                };
                const auto validate_all = [&]() {
                    if (!reviewed_publication || reviewed_publication->generation == 0 ||
                        reviewed_count == 0 ||
                        reviewed_count != reviewed_publication->held.size()) {
                        error = "The exact reviewed Intercept publication is unavailable";
                        return false;
                    }
                    live_held = mitm_proxy::get_held_exchanges();
                    for (const auto& reviewed : reviewed_publication->held) {
                        const auto reviewed_target = intercept_target_identity(
                            *reviewed_publication, reviewed);
                        const bool current = std::any_of(live_held.begin(), live_held.end(),
                            [&](const auto& exchange) {
                                return intercept_exchange_matches(exchange, reviewed_target);
                            });
                        if (!current) {
                            error = "A held exchange changed after review; review the current publication again";
                            return false;
                        }
                    }
                    return true;
                };
                switch (operation) {
                case intercept_operation_t::set_enabled:
                    mitm_proxy::set_intercept_enabled(enabled);
                    success = mitm_proxy::is_intercept_enabled() == enabled;
                    break;
                case intercept_operation_t::forward_all:
                    if (!validate_all()) break;
                    for (const auto& exchange : reviewed_publication->held)
                        mitm_proxy::forward_exchange(exchange.id);
                    success = true;
                    break;
                case intercept_operation_t::drop_all:
                    if (!validate_all()) break;
                    for (const auto& exchange : reviewed_publication->held)
                        mitm_proxy::drop_exchange(exchange.id);
                    success = true;
                    break;
                case intercept_operation_t::forward_one:
                    if (!validate_selected()) break;
                    mitm_proxy::forward_exchange(target.exchange_id);
                    success = true;
                    break;
                case intercept_operation_t::drop_one:
                    if (!validate_selected()) break;
                    mitm_proxy::drop_exchange(target.exchange_id);
                    success = true;
                    break;
                case intercept_operation_t::forward_modified: {
                    const auto* reviewed = validate_selected();
                    if (!reviewed) break;
                    if (modified_request.empty() ||
                        modified_request.size() >= k_intercept_editor_capacity ||
                        modified_content_hash == 0 ||
                        artifact_hash(modified_request) != modified_content_hash) {
                        error = "The modified request draft changed after review or exceeded its bounded size";
                        break;
                    }
                    artifact_identity_t canonical_source;
                    if (!validate_reviewed_request(
                            exchange_artifact_identity(*reviewed,
                                artifact_kind_t::intercept_request),
                            modified_request, canonical_source, error))
                        break;
                    mitm_proxy::forward_modified(target.exchange_id, modified_request);
                    success = true;
                    break;
                }
                }
                publish_intercept_runtime_snapshot();
                const auto snapshot = std::atomic_load_explicit(&s_intercept_runtime_snapshot, std::memory_order_acquire);
                if (success && target.exchange_id != 0 && snapshot) {
                    success = std::none_of(snapshot->held.begin(), snapshot->held.end(),
                        [target](const auto& exchange) {
                            return exchange.id == target.exchange_id;
                        });
                } else if (success && reviewed_publication && snapshot &&
                    (operation == intercept_operation_t::forward_all ||
                     operation == intercept_operation_t::drop_all)) {
                    std::vector<std::uint64_t> remaining_ids;
                    remaining_ids.reserve(snapshot->held.size());
                    for (const auto& exchange : snapshot->held)
                        remaining_ids.push_back(exchange.id);
                    std::sort(remaining_ids.begin(), remaining_ids.end());
                    success = std::none_of(reviewed_publication->held.begin(),
                        reviewed_publication->held.end(), [&remaining_ids](const auto& exchange) {
                            return std::binary_search(remaining_ids.begin(), remaining_ids.end(),
                                exchange.id);
                        });
                }
                if (!success && error.empty())
                    error = "The requested intercept state could not be verified";
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Intercept operation failed";
            }
            const std::string detail = success
                ? (reviewed_count > 0 ? std::to_string(reviewed_count) + " exchanges processed" : "Completed")
                : error;
            finish_network_operation(task_id, success, success ? "Completed" : "Failed", detail);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (s_intercept_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Intercept operation failed" : error,
                        toast_notification::toast_type_t::error);
                s_intercept_operation_pending.store(false, std::memory_order_release);
                request_intercept_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_intercept_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected intercept operation");
        return false;
    }
    return true;
}

static bool selected_intercept_command(intercept_command_t command) {
    return command == intercept_command_t::forward_selected ||
        command == intercept_command_t::drop_selected ||
        command == intercept_command_t::forward_modified;
}

static intercept_command_capability_t intercept_command_capability_for(
    intercept_command_t command,
    const std::shared_ptr<const intercept_runtime_snapshot_t>& publication,
    const intercept_target_identity_t& target) {
    if (!publication)
        return {false, "The immutable Intercept publication is still loading"};
    if (!publication->running)
        return {false, "Start the MITM proxy before using Intercept commands"};
    if (s_intercept_operation_pending.load(std::memory_order_acquire))
        return {false, "Wait for the current Intercept operation to finish"};
    if (publication->held.empty())
        return {false, "No held exchanges are available"};
    if (selected_intercept_command(command)) {
        if (!target.valid())
            return {false, "Select a held exchange first"};
        const bool reviewed_exists = target.publication_generation == publication->generation &&
            std::any_of(publication->held.begin(), publication->held.end(),
            [&](const auto& exchange) {
                return intercept_exchange_matches(exchange, target);
            });
        if (!reviewed_exists)
            return {false, "The reviewed held exchange changed; select it again"};
        const auto current = std::atomic_load_explicit(
            &s_intercept_runtime_snapshot, std::memory_order_acquire);
        const bool selected_current = current && current->running &&
            std::any_of(current->held.begin(), current->held.end(),
                [&](const auto& exchange) {
                    return intercept_exchange_matches(exchange, target);
                });
        if (!selected_current)
            return {false, "The selected held exchange changed; select it again"};
        if (command == intercept_command_t::forward_modified) {
            if (!s_intercept_modified_draft.loaded ||
                !intercept_target_matches(
                    s_intercept_modified_draft.source, target, false))
                return {false, "The selected exchange has no retained modified draft"};
            std::string draft_reason;
            if (!refresh_intercept_modified_draft(draft_reason))
                return {false, s_intercept_modified_draft.unavailable_reason.empty()
                    ? "The retained modified draft is unavailable"
                    : s_intercept_modified_draft.unavailable_reason};
            if (s_intercept_request_editor.pretty_dirty)
                return {false, "Apply or discard the pending Pretty edits before forwarding raw bytes"};
            if (s_intercept_request_editor.oversized || s_intercept_request_editor.binary ||
                !s_intercept_request_editor.error.empty())
                return {false, s_intercept_request_editor.error.empty()
                    ? "The retained modified request is not safely editable"
                    : s_intercept_request_editor.error};
        }
    }
    return {true, {}};
}

intercept_command_capability_t intercept_command_capability(intercept_command_t command) {
    const auto publication = std::atomic_load_explicit(
        &s_intercept_runtime_snapshot, std::memory_order_acquire);
    intercept_target_identity_t target;
    if (publication && selected_intercept_command(command)) {
        const auto selected = std::find_if(publication->held.begin(), publication->held.end(),
            [](const auto& exchange) {
                return exchange.id == s_intercept_selected_exchange_id;
            });
        if (selected != publication->held.end())
            target = intercept_target_identity(*publication, *selected);
    }
    return intercept_command_capability_for(command, publication, target);
}

static bool execute_reviewed_intercept_command(
    intercept_command_t command,
    const std::shared_ptr<const intercept_runtime_snapshot_t>& publication,
    const intercept_target_identity_t& target,
    std::string* error) {
    const auto capability = intercept_command_capability_for(command, publication, target);
    if (!capability.enabled) {
        if (error) *error = capability.disabled_reason.empty()
            ? "The Intercept command is unavailable"
            : capability.disabled_reason;
        return false;
    }
    switch (command) {
    case intercept_command_t::forward_selected:
        if (!request_intercept_operation(intercept_operation_t::forward_one, false,
                target, {}, 0, 1, publication)) {
            if (error) *error = "The Intercept executor rejected the selected forward operation";
            return false;
        }
        break;
    case intercept_command_t::drop_selected:
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.intercept")); !opened.ok()) {
            if (error) *error = opened.detail.empty()
                ? "The Intercept review surface could not be opened" : opened.detail;
            return false;
        }
        s_intercept_drop_review = {true, false, target, 1, publication};
        break;
    case intercept_command_t::forward_modified: {
        std::string draft_reason;
        if (!refresh_intercept_modified_draft(draft_reason) ||
            !intercept_target_matches(s_intercept_modified_draft.source, target, false)) {
            if (error) *error = draft_reason.empty()
                ? "The retained modified draft no longer matches the selected exchange"
                : draft_reason;
            return false;
        }
        const auto reviewed = std::find_if(publication->held.begin(), publication->held.end(),
            [&](const auto& exchange) {
                return intercept_exchange_matches(exchange, target);
            });
        if (reviewed == publication->held.end()) {
            if (error) *error = "The selected exchange changed before modified forwarding";
            return false;
        }
        std::vector<std::uint8_t> modified_request(
            s_intercept_modified_draft.raw_request.begin(),
            s_intercept_modified_draft.raw_request.end());
        artifact_identity_t canonical_source;
        if (!validate_reviewed_request(
                exchange_artifact_identity(*reviewed, artifact_kind_t::intercept_request),
                modified_request, canonical_source, draft_reason)) {
            if (error) *error = draft_reason.empty()
                ? "The modified request failed reviewed HTTP validation" : draft_reason;
            return false;
        }
        if (!request_intercept_operation(intercept_operation_t::forward_modified, false,
                target, std::move(modified_request),
                s_intercept_modified_draft.content_hash, 1, publication)) {
            if (error) *error = "The Intercept executor rejected the modified forward operation";
            return false;
        }
        break;
    }
    case intercept_command_t::forward_all:
        if (!request_intercept_operation(intercept_operation_t::forward_all, false,
                {}, {}, 0, publication->held.size(), publication)) {
            if (error) *error = "The Intercept executor rejected the forward-all operation";
            return false;
        }
        break;
    case intercept_command_t::drop_all:
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.intercept")); !opened.ok()) {
            if (error) *error = opened.detail.empty()
                ? "The Intercept review surface could not be opened" : opened.detail;
            return false;
        }
        s_intercept_drop_review = {true, true, {}, publication->held.size(), publication};
        break;
    }
    if (error) error->clear();
    return true;
}

bool execute_intercept_command(intercept_command_t command, std::string* error) {
    const auto publication = std::atomic_load_explicit(
        &s_intercept_runtime_snapshot, std::memory_order_acquire);
    intercept_target_identity_t target;
    if (publication && selected_intercept_command(command)) {
        const auto selected = std::find_if(publication->held.begin(), publication->held.end(),
            [](const auto& exchange) {
                return exchange.id == s_intercept_selected_exchange_id;
            });
        if (selected != publication->held.end())
            target = intercept_target_identity(*publication, *selected);
    }
    return execute_reviewed_intercept_command(command, publication, target, error);
}

static void render_intercept(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_intercept", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_intercept_runtime_snapshot();
    const auto intercept_snapshot = std::atomic_load_explicit(
        &s_intercept_runtime_snapshot, std::memory_order_acquire);
    const bool running = intercept_snapshot && intercept_snapshot->running;
    const bool intercept_pending = s_intercept_operation_pending.load(std::memory_order_acquire);
    if (!running) {
        clear_stale_network_selection("view.network.intercept");
        ImVec2 region = ImVec2(w, h);
        ImVec2 region_pos = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::shield;
        cfg.title = "Proxy not running";
        cfg.body  = "Start the MITM proxy first to use intercept mode.";
        aida::ui::empty_state::render(region_pos, region, cfg);
        ImGui::EndChild();
        return;
    }

    state.intercept_enabled = intercept_snapshot->enabled;
    bool requested_intercept_enabled = state.intercept_enabled;
    if (intercept_pending) ImGui::BeginDisabled();
    bool intercept_changed = aida::ui::toggle_switch("##intercept_en", &requested_intercept_enabled);
    if (intercept_pending) ImGui::EndDisabled();
    if (intercept_changed) {
        diag::log_tagged_fmt("network", "intercept_enabled_toggled new=%d",
            requested_intercept_enabled ? 1 : 0);
        invoke_global_network_action("network.intercept.toggle_enabled");
    }
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                       "Intercept Enabled");
    ImGui::SameLine();

    const auto& held = intercept_snapshot->held;
    const auto forward_all_action = aida::ui::application_ui::present_action(
        "network.intercept.forward_all");
    const auto drop_all_action = aida::ui::application_ui::present_action(
        "network.intercept.drop_all");
    if (aida::ui::button(intercept_pending ? "Working...##intercept_forward_all" : "Forward All##intercept_forward_all",
                         aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), !forward_all_action.enabled)) {
        diag::log_tagged("network", "intercept_forward_all_clicked");
        static_cast<void>(aida::ui::application_ui::execute_action(
            "network.intercept.forward_all",
            aida::ui::action_invocation_source_t::toolbar));
    }
    if (!forward_all_action.shortcut.empty()) {
        ImGui::SameLine();
        aida::ui::kbd_chip(forward_all_action.shortcut.c_str());
    }
    ImGui::SameLine();
    if (aida::ui::button("Drop All##intercept_drop_all", aida::ui::button_kind_t::destructive,
                         aida::ui::size_t_::sm, ImVec2(0.f, 0.f), !drop_all_action.enabled)) {
        diag::log_tagged("network", "intercept_drop_all_clicked");
        static_cast<void>(aida::ui::application_ui::execute_action(
            "network.intercept.drop_all",
            aida::ui::action_invocation_source_t::toolbar));
    }
    if (!drop_all_action.shortcut.empty()) {
        ImGui::SameLine();
        aida::ui::kbd_chip(drop_all_action.shortcut.c_str());
    }

    if (intercept_snapshot->enabled) {
        ImGui::SameLine();
        aida::ui::pill_kind("INTERCEPTING", aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
    }

    ImGui::Spacing();
    int held_count = static_cast<int>(held.size());
    if (s_intercept_selected_exchange_id != 0) {
        const auto selected = std::find_if(held.begin(), held.end(), [](const auto& exchange) {
            return exchange.id == s_intercept_selected_exchange_id;
        });
        if (selected == held.end()) {
            state.intercept_selected = -1;
            s_intercept_selected_exchange_id = 0;
            clear_stale_network_selection("view.network.intercept");
        } else {
            state.intercept_selected = static_cast<int>(std::distance(held.begin(), selected));
        }
    } else if (state.intercept_selected >= 0 && state.intercept_selected < held_count) {
        s_intercept_selected_exchange_id =
            held[static_cast<std::size_t>(state.intercept_selected)].id;
    } else {
        state.intercept_selected = -1;
        clear_stale_network_selection("view.network.intercept");
    }
    if (held_count > s_intercept_ui.prev_held_count) {
        s_intercept_ui.border_flash.trigger();
        s_intercept_ui.label_flash.trigger();
    }
    s_intercept_ui.prev_held_count = held_count;

    float lbl_pulse = s_intercept_ui.label_flash.tick(aida::ui::clock::dt(), 1.6f);
    ImU32 lbl_col = aida::ui::mix(aida::ui::with_alpha(th.text_secondary, alpha),
                                   aida::ui::with_alpha(th.accent_u32, alpha),
                                   lbl_pulse);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(lbl_col),
                       "Held: %d", held_count);

    if (s_intercept_drop_review.open) {
        s_intercept_drop_review.open = false;
        ImGui::OpenPopup("Review Intercept Drop");
    }
    if (aida::ui::design::begin_dialog_exact("Review Intercept Drop",
        ImVec2(520.f, 260.f), ImVec2(400.f, 220.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Confirm Drop");
        if (aida::ui::design::begin_dialog_body("intercept_drop_review_body", footer)) {
            if (s_intercept_drop_review.all)
                ImGui::Text("Drop all %zu currently held exchanges?", s_intercept_drop_review.reviewed_count);
            else
                ImGui::Text("Drop held exchange %llu?",
                    static_cast<unsigned long long>(
                        s_intercept_drop_review.target.exchange_id));
            ImGui::TextWrapped("Dropped exchanges are not forwarded to their upstream destination.");
        }
        aida::ui::design::end_dialog_body();
        const bool retained_target = s_intercept_drop_review.reviewed_publication &&
            s_intercept_drop_review.reviewed_count != 0 &&
            (s_intercept_drop_review.all ||
                s_intercept_drop_review.target.valid());
        const auto result = aida::ui::design::dialog_footer(
            "intercept_drop_review_footer", "Confirm Drop", retained_target, true);
        if (result.confirmed) {
            const bool accepted = request_intercept_operation(
                s_intercept_drop_review.all ? intercept_operation_t::drop_all : intercept_operation_t::drop_one,
                false, s_intercept_drop_review.target, {}, 0,
                s_intercept_drop_review.reviewed_count,
                s_intercept_drop_review.reviewed_publication);
            if (accepted) {
                s_intercept_drop_review = {};
                ImGui::CloseCurrentPopup();
            } else {
                toast_notification::push("The Intercept executor rejected the reviewed drop operation",
                    toast_notification::toast_type_t::error);
            }
        }
        if (result.cancelled) {
            s_intercept_drop_review = {};
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::Spacing();


    float split_y = h * 0.45f;
    ImDrawList* dl_outer = ImGui::GetWindowDrawList();
    ImVec2 outer_pos = ImGui::GetCursorScreenPos();

    float border_v = s_intercept_ui.border_flash.tick(aida::ui::clock::dt(), 0.5f);

    ImGui::BeginChild("##held_list", ImVec2(w - 4.f, split_y), false, ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;

    dl->AddRectFilled(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                      aida::ui::with_alpha(th.panel_bg, alpha * 0.75f), 8.f);
    dl->AddRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                 aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);
    if (border_v > 0.001f) {
        ImU32 glow = aida::ui::with_alpha(th.accent_u32, border_v * alpha);
        dl->AddRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                     glow, 8.f, 0, 2.f);
        for (int gi = 1; gi <= 3; ++gi) {
            const float glow_offset = static_cast<float>(gi);
            float ga = (0.18f - glow_offset * 0.05f) * border_v * alpha;
            dl->AddRect(ImVec2(list_org.x - glow_offset, list_org.y - glow_offset),
                         ImVec2(list_org.x + list_sz.x + glow_offset, list_org.y + list_sz.y + glow_offset),
                         aida::ui::with_alpha(th.accent_glow, ga), 8.f + glow_offset, 0, 1.f);
        }
    }


    float cx = list_org.x + 8.f;
    float cy = list_org.y + ImGui::GetCursorPosY() + 4.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    float col_id = 50.f, col_method = 64.f, col_host = 200.f, col_path = 260.f;

    dl->AddText(ImVec2(cx, cy), hdr_col, "ID"); cx += col_id;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Method"); cx += col_method;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Host"); cx += col_host;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Path"); cx += col_path;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Size");
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);

    if (held.empty()) {
        ImGui::Dummy(ImVec2(list_sz.x - 16.f, split_y - 60.f));
        ImU32 dim = aida::ui::with_alpha(th.text_dim, alpha);
        const char* msg = "No exchanges held. Toggle Intercept Enabled to start capturing.";
        ImVec2 ts = ImGui::CalcTextSize(msg);
        dl->AddText(ImVec2(list_org.x + (list_sz.x - ts.x) * 0.5f,
                           list_org.y + split_y * 0.5f), dim, msg);
    }

    ImGuiListClipper held_clipper;
    held_clipper.Begin(static_cast<int>(held.size()), row_h);
    while (held_clipper.Step()) {
    for (int i = held_clipper.DisplayStart; i < held_clipper.DisplayEnd; i++) {
        auto& ex = held[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool is_sel = (state.intercept_selected == i);

        if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x + 2.f, abs_ry), ImVec2(list_org.x + list_sz.x - 2.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x + 2.f, abs_ry), ImVec2(list_org.x + 4.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        const bool row_hovered = mouse.x >= list_org.x &&
            mouse.x < list_org.x + list_sz.x - 4.f &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const auto intercept_identity = exchange_artifact_identity(
            ex, artifact_kind_t::intercept_request);
        const std::string intercept_artifact_id =
            semantic_artifact_id("exchange", intercept_identity);
        ImGui::PushID(i);
        const ImGuiID intercept_row_id = ImGui::GetID("##intercept_exchange_row");
        ImGui::PopID();
        aida::preview::semantics::register_region(
            intercept_artifact_id, "network-exchange-row", intercept_row_id,
            ImVec2(list_org.x, abs_ry),
            ImVec2(list_org.x + list_sz.x - 4.f, abs_ry + row_h), false, false,
            "aida.dock-window.view.network.intercept");
#endif
        if (row_hovered && (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
            ImGui::IsMouseClicked(ImGuiMouseButton_Right))) {
            state.intercept_selected = i;
            s_intercept_selected_exchange_id = ex.id;
            publish_network_selection(
                exchange_artifact_identity(ex, artifact_kind_t::intercept_request), true);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                retain_intercept_modified_draft(*intercept_snapshot, ex);
                open_exchange_context(
                    exchange_artifact_identity(ex, artifact_kind_t::intercept_request), {},
                    exchange_context_origin_t::pointer, true);
            }
        }

        ImU32 txt_col = aida::ui::with_alpha(is_sel ? th.text_primary : th.text_secondary, alpha);
        cx = list_org.x + 8.f;

        char id_buf[16];
        snprintf(id_buf, sizeof(id_buf), "%llu", static_cast<unsigned long long>(ex.id));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, id_buf); cx += col_id;

        ImU32 method_col = ui_anim::http_method_color(ex.request.method.c_str(), alpha);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), method_col, ex.request.method.c_str()); cx += col_method;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, ex.target_host.c_str()); cx += col_host;

        std::string path_display = ex.request.uri.size() > 50 ? ex.request.uri.substr(0, 47) + "..." : ex.request.uri;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, path_display.c_str()); cx += col_path;

        char size_buf[32];
        snprintf(size_buf, sizeof(size_buf), "%zu B", ex.raw_request.size());
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_dim, alpha), size_buf);

        ImGui::SetCursorPosY(ry + row_h);
    }
    }
    const bool intercept_menu_key = state.intercept_selected >= 0 &&
        state.intercept_selected < static_cast<int>(held.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool intercept_shift_f10 = !intercept_menu_key &&
        state.intercept_selected >= 0 &&
        state.intercept_selected < static_cast<int>(held.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
        ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (intercept_menu_key || intercept_shift_f10) {
        const auto& selected = held[static_cast<std::size_t>(state.intercept_selected)];
        publish_network_selection(
            exchange_artifact_identity(selected, artifact_kind_t::intercept_request), true);
        retain_intercept_modified_draft(*intercept_snapshot, selected);
        open_exchange_context(
            exchange_artifact_identity(selected, artifact_kind_t::intercept_request), {},
            intercept_menu_key ? exchange_context_origin_t::menu_key
                               : exchange_context_origin_t::shift_f10,
            true);
    }
    ImGui::EndChild();
    (void)dl_outer; (void)outer_pos;


    if (state.intercept_selected >= 0 && state.intercept_selected < static_cast<int>(held.size())) {
        auto& sel = held[static_cast<size_t>(state.intercept_selected)];
        retain_intercept_modified_draft(*intercept_snapshot, sel);
        publish_network_selection(
            exchange_artifact_identity(sel, artifact_kind_t::intercept_request));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const auto intercept_identity = exchange_artifact_identity(
            sel, artifact_kind_t::intercept_request);
        const std::string intercept_artifact_id =
            semantic_artifact_id("exchange", intercept_identity);
        const std::string intercept_request_id =
            semantic_artifact_id("request", intercept_identity);
#endif

        ImGui::Spacing();
        const auto forward_selected_action = aida::ui::application_ui::present_action(
            "network.intercept.forward_selected");
        const auto drop_selected_action = aida::ui::application_ui::present_action(
            "network.intercept.drop_selected");
        const auto forward_modified_action = aida::ui::application_ui::present_action(
            "network.intercept.forward_modified");
        const bool forward_intercept = aida::ui::button(
            "Forward", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
            ImVec2(0.f, 0.f), !forward_selected_action.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_artifact_id + ".action.forward", "network-artifact-action",
            intercept_artifact_id, !forward_selected_action.enabled);
#endif
        if (forward_intercept) {
            diag::log_tagged_fmt("network", "intercept_forward_clicked id=%llu",
                static_cast<unsigned long long>(sel.id));
            static_cast<void>(aida::ui::application_ui::execute_action(
                "network.intercept.forward_selected",
                aida::ui::action_invocation_source_t::toolbar));
        }
        if (!forward_selected_action.shortcut.empty()) {
            ImGui::SameLine();
            aida::ui::kbd_chip(forward_selected_action.shortcut.c_str());
        }
        ImGui::SameLine();
        const bool drop_intercept = aida::ui::button(
            "Drop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm,
            ImVec2(0.f, 0.f), !drop_selected_action.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_artifact_id + ".action.drop", "network-artifact-action",
            intercept_artifact_id, !drop_selected_action.enabled);
#endif
        if (drop_intercept) {
            diag::log_tagged_fmt("network", "intercept_drop_clicked id=%llu",
                static_cast<unsigned long long>(sel.id));
            static_cast<void>(aida::ui::application_ui::execute_action(
                "network.intercept.drop_selected",
                aida::ui::action_invocation_source_t::toolbar));
        }
        if (!drop_selected_action.shortcut.empty()) {
            ImGui::SameLine();
            aida::ui::kbd_chip(drop_selected_action.shortcut.c_str());
        }
        ImGui::SameLine();
        const bool forward_modified_intercept = aida::ui::button(
            "Forward Modified", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm, ImVec2(0.f, 0.f), !forward_modified_action.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_artifact_id + ".action.forward-modified",
            "network-artifact-action", intercept_artifact_id,
            !forward_modified_action.enabled);
#endif
        if (forward_modified_intercept) {
            static_cast<void>(aida::ui::application_ui::execute_action(
                "network.intercept.forward_modified",
                aida::ui::action_invocation_source_t::toolbar));
        }
        if (!forward_modified_action.shortcut.empty()) {
            ImGui::SameLine();
            aida::ui::kbd_chip(forward_modified_action.shortcut.c_str());
        }
        ImGui::SameLine();
        const bool send_intercept_to_repeater = aida::ui::button(
            "Send to Repeater", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_artifact_id + ".action.send-to-repeater",
            "network-artifact-action", intercept_artifact_id);
#endif
        if (send_intercept_to_repeater) {
            std::string unavailable;
            static_cast<void>(execute_retained_exchange_toolbar_action(
                "network.exchange.repeater",
                exchange_artifact_identity(sel, artifact_kind_t::intercept_request), {},
                unavailable));
        }
        ImGui::SameLine();
        const bool send_intercept_to_fuzzer = aida::ui::button(
            "Send to Fuzzer", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_artifact_id + ".action.send-to-fuzzer",
            "network-artifact-action", intercept_artifact_id);
#endif
        if (send_intercept_to_fuzzer) {
            std::string unavailable;
            static_cast<void>(execute_retained_exchange_toolbar_action(
                "network.exchange.fuzzer",
                exchange_artifact_identity(sel, artifact_kind_t::intercept_request), {},
                unavailable));
        }

        ImGui::Spacing();


        const bool stack_editors = w < 760.f;
        float detail_h = h - ImGui::GetCursorPosY() + y - 8.f;
        if (detail_h < 170.f) detail_h = 170.f;
        ImGui::BeginChild("##intercept_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        float half_w = (w - 12.f) * 0.5f;
        float pane_w = stack_editors ? std::max(120.f, w - 8.f) : half_w;
        float pane_h = stack_editors ? std::max(128.f, (detail_h - 12.f) * 0.5f) : detail_h - 4.f;
        float edit_pane_h = stack_editors ? std::max(128.f, detail_h - pane_h - 12.f) : detail_h - 4.f;

        ImGui::BeginChild("##int_req_pane", ImVec2(pane_w, pane_h), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Original Request");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "%zu bytes", sel.raw_request.size());

        const std::string original_editor_identity =
            "intercept.original." + std::to_string(sel.id) + "." +
            std::to_string(sel.timestamp) + "." +
            std::to_string(artifact_hash(sel.raw_request));
        static std::string original_raw;
        if (s_intercept_original_editor.identity != original_editor_identity)
            original_raw.assign(sel.raw_request.begin(), sel.raw_request.end());
        human_request_editor::render_config_t original_config;
        original_config.stable_id = "intercept-original-request";
        original_config.size = ImVec2(pane_w - 4.f, std::max(72.f, pane_h - 50.f));
        original_config.max_bytes = k_intercept_editor_capacity - 1;
        original_config.editable = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        original_config.semantic_parent_id = intercept_artifact_id.c_str();
#endif
        ImGui::BeginChild("##int_req_orig", original_config.size, true,
            ImGuiWindowFlags_NoBackground);
        original_config.size = ImGui::GetContentRegionAvail();
        static_cast<void>(human_request_editor::render(
            s_intercept_original_editor,
            original_editor_identity,
            original_raw, original_config));
        const bool original_menu_key = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::IsKeyPressed(ImGuiKey_Menu, false);
        const bool original_shift_f10 = !original_menu_key &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
        ImGui::EndChild();
        const bool original_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
        if (original_pointer_context || original_menu_key || original_shift_f10) {
            publish_network_selection(
                exchange_artifact_identity(sel, artifact_kind_t::intercept_request), true);
            open_exchange_context(
                exchange_artifact_identity(sel, artifact_kind_t::intercept_request), {},
                original_pointer_context ? exchange_context_origin_t::pointer
                    : original_menu_key ? exchange_context_origin_t::menu_key
                                        : exchange_context_origin_t::shift_f10,
                true);
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        register_network_last_item(
            intercept_request_id, "network-request-editor", intercept_artifact_id);
#endif
        ImGui::EndChild();

        if (stack_editors) {
            ImGui::Dummy(ImVec2(0.f, 8.f));
        } else {
            ImGui::SameLine();
        }

        ImGui::BeginChild("##int_req_edit_pane", ImVec2(pane_w, edit_pane_h), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Modified Request");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "%s", s_intercept_modified_draft.editable
                               ? "Bounded reviewed text draft"
                               : "Text editing unavailable for this retained request");
        if (s_intercept_modified_draft.editable) {
            human_request_editor::render_config_t modified_config;
            modified_config.stable_id = "intercept-modified-request";
            modified_config.size = ImVec2(pane_w - 4.f,
                std::max(72.f, edit_pane_h - 50.f));
            modified_config.max_bytes = k_intercept_editor_capacity - 1;
            modified_config.editable = !intercept_pending;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            modified_config.semantic_parent_id = intercept_request_id.c_str();
#endif
            ImGui::BeginChild("##int_req_modified_editor", modified_config.size, false,
                ImGuiWindowFlags_NoBackground);
            modified_config.size = ImGui::GetContentRegionAvail();
            const auto modified_result = human_request_editor::render(
                s_intercept_request_editor,
                "intercept.modified." + std::to_string(sel.id) + "." +
                    std::to_string(sel.timestamp) + "." +
                    std::to_string(artifact_hash(sel.raw_request)),
                s_intercept_modified_draft.raw_request, modified_config);
            const bool modified_menu_key = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool modified_shift_f10 = !modified_menu_key &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
            ImGui::EndChild();
            const bool modified_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            if (modified_pointer_context || modified_menu_key || modified_shift_f10) {
                publish_network_selection(
                    exchange_artifact_identity(sel, artifact_kind_t::intercept_request), true);
                open_exchange_context(
                    exchange_artifact_identity(sel, artifact_kind_t::intercept_request), {},
                    modified_pointer_context ? exchange_context_origin_t::pointer
                        : modified_menu_key ? exchange_context_origin_t::menu_key
                                            : exchange_context_origin_t::shift_f10,
                    true);
            }
            if (modified_result.authority_changed) {
                std::string draft_reason;
                if (!refresh_intercept_modified_draft(draft_reason))
                    s_intercept_modified_draft.unavailable_reason = std::move(draft_reason);
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            register_network_last_item(
                intercept_request_id + ".draft", "network-request-editor",
                intercept_request_id);
#endif
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
                aida::ui::with_alpha(th.error, alpha)));
            ImGui::TextWrapped("%s", s_intercept_modified_draft.unavailable_reason.c_str());
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(pane_w - 4.f, std::max(32.f, edit_pane_h - 86.f)));
        }
        ImGui::EndChild();

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


struct keylog_runtime_snapshot_t {
    bool watching = false;
    std::string path;
    std::size_t entry_count = 0;
    std::vector<ssl_keylog::keylog_entry> entries;
};

enum class keylog_operation_t {
    launch_and_watch,
    watch_file,
    stop_watching,
    clear_entries
};

static std::shared_ptr<const keylog_runtime_snapshot_t> s_keylog_runtime_snapshot;
static std::atomic<bool> s_keylog_snapshot_pending{false};
static std::atomic<std::uint64_t> s_keylog_snapshot_requested_ms{0};
static std::atomic<bool> s_keylog_operation_pending{false};
static std::atomic<std::uint64_t> s_keylog_operation_serial{0};

static void publish_keylog_runtime_snapshot(const std::string& known_path = {}) {
    auto snapshot = std::make_shared<keylog_runtime_snapshot_t>();
    snapshot->watching = ssl_keylog::is_watching();
    snapshot->entries = ssl_keylog::get_entries(500);
    snapshot->entry_count = ssl_keylog::entry_count();
    if (!known_path.empty()) {
        snapshot->path = known_path;
    } else {
        const auto previous = std::atomic_load_explicit(&s_keylog_runtime_snapshot, std::memory_order_acquire);
        if (previous)
            snapshot->path = previous->path;
    }
    if (!snapshot->watching)
        snapshot->path.clear();
    std::atomic_store_explicit(&s_keylog_runtime_snapshot,
        std::shared_ptr<const keylog_runtime_snapshot_t>(std::move(snapshot)),
        std::memory_order_release);
}

static void request_keylog_runtime_snapshot(bool force = false) {
    const std::uint64_t now = network_now_ms();
    const std::uint64_t last = s_keylog_snapshot_requested_ms.load(std::memory_order_acquire);
    if (!force && last != 0 && now >= last && now - last < 250)
        return;
    bool expected = false;
    if (!s_keylog_snapshot_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    s_keylog_snapshot_requested_ms.store(now, std::memory_order_release);
    const bool posted = post_network_task(
        "keylog_snapshot", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        []() {
            try {
                publish_keylog_runtime_snapshot();
            } catch (...) {
            }
            s_keylog_snapshot_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted)
        s_keylog_snapshot_pending.store(false, std::memory_order_release);
}

static void request_keylog_operation(keylog_operation_t operation, std::string path,
                                     std::string arguments, std::size_t reviewed_count,
                                     ssl_keylog::retained_set_token reviewed_token = {}) {
    bool expected = false;
    if (!s_keylog_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = s_keylog_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const char* action = "network.keylog.watch";
    const char* label = "Watch TLS keylog file";
    std::string target = path;
    switch (operation) {
    case keylog_operation_t::launch_and_watch:
        action = "network.keylog.launch";
        label = "Launch target with TLS key logging";
        break;
    case keylog_operation_t::stop_watching:
        action = "network.keylog.stop";
        label = "Stop TLS keylog watcher";
        break;
    case keylog_operation_t::clear_entries:
        action = "network.keylog.clear";
        label = "Clear captured TLS keys";
        target = std::to_string(reviewed_count) + " captured keys";
        break;
    default:
        break;
    }
    const std::string task_id = register_network_operation(action, label, "view.network.keylog", target);
    const bool posted = post_network_task(
        "keylog_mutation",
        operation == keylog_operation_t::launch_and_watch
            ? aida::infra::executor::domain_t::external_tool
            : aida::infra::executor::domain_t::feature_worker,
        "bounded_task",
        [serial, operation, path = std::move(path), arguments = std::move(arguments),
         reviewed_count, reviewed_token, task_id]() mutable {
            bool success = false;
            std::string effective_path = path;
            std::string error;
            std::uint32_t launched_pid = 0;
            try {
                switch (operation) {
                case keylog_operation_t::launch_and_watch: {
                    auto result = ssl_keylog::launch_with_keylog(path, arguments);
                    success = result.success;
                    launched_pid = result.pid;
                    effective_path = result.keylog_path;
                    if (success) {
                        ssl_keylog::start_watching(effective_path);
                        success = ssl_keylog::is_watching();
                    }
                    if (!success)
                        error = result.error.empty() ? "TLS keylog watcher did not start" : result.error;
                    break;
                }
                case keylog_operation_t::watch_file:
                    ssl_keylog::start_watching(path);
                    success = ssl_keylog::is_watching();
                    if (!success) error = "TLS keylog watcher did not start";
                    break;
                case keylog_operation_t::stop_watching:
                    ssl_keylog::stop_watching();
                    success = !ssl_keylog::is_watching();
                    if (!success) error = "TLS keylog watcher did not stop";
                    break;
                case keylog_operation_t::clear_entries:
                    if (reviewed_token.count != reviewed_count ||
                        !ssl_keylog::clear_entries_if_exact(reviewed_token)) {
                        error = "TLS secrets changed after confirmation; review the current retained set again";
                    } else {
                        success = ssl_keylog::entry_count() == 0;
                        if (!success) error = "Captured TLS keys remained after clear";
                    }
                    break;
                }
                publish_keylog_runtime_snapshot(success ? effective_path : std::string());
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "TLS keylog operation failed";
            }
            std::string detail;
            if (success && operation == keylog_operation_t::launch_and_watch)
                detail = "PID " + std::to_string(launched_pid) + "; watching " + effective_path;
            else if (success && operation == keylog_operation_t::clear_entries)
                detail = std::to_string(reviewed_count) + " captured keys cleared";
            else
                detail = success ? "Completed" : error;
            finish_network_operation(task_id, success, success ? "Completed" : "Failed", detail);
            enqueue_ui_completion([serial, operation, success, effective_path = std::move(effective_path),
                                   error = std::move(error)]() mutable {
                if (s_keylog_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success && operation == keylog_operation_t::clear_entries)
                    g_state.kl_selected = -1;
                if (success && operation == keylog_operation_t::launch_and_watch)
                    toast_notification::push("Process launched; TLS keylog watcher is active",
                        toast_notification::toast_type_t::info);
                else if (!success)
                    toast_notification::push(error.empty() ? "TLS keylog operation failed" : error,
                        toast_notification::toast_type_t::error);
                s_keylog_operation_pending.store(false, std::memory_order_release);
                request_keylog_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        s_keylog_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected TLS keylog operation");
    }
}

static std::string filter_draft_error(const state_t& state) {
    char* end = nullptr;
    errno = 0;
    const unsigned long pid = state.nf_pid[0] ? std::strtoul(state.nf_pid, &end, 10) : 0;
    if (errno != 0 || (state.nf_pid[0] && (!end || *end != '\0')) || pid > UINT32_MAX)
        return "PID must be an unsigned 32-bit integer";
    end = nullptr;
    errno = 0;
    const unsigned long port = state.nf_port[0] ? std::strtoul(state.nf_port, &end, 10) : 0;
    if (errno != 0 || (state.nf_port[0] && (!end || *end != '\0')) || port > UINT16_MAX)
        return "Port must be between 0 and 65535";
    std::array<std::uint8_t, 16> bytes{};
    if (state.nf_ip[0] && inet_pton(AF_INET, state.nf_ip, bytes.data()) != 1)
        return "Filter IP address is not valid IPv4";
    if (state.nf_action < 0 || state.nf_action > 1)
        return "Choose Block or Allow for the filter action";
    if (state.nf_direction < 0 || state.nf_direction > 2)
        return "Choose In, Out, or Both for the filter direction";
    if (state.nf_protocol != 0 && state.nf_protocol != 6 && state.nf_protocol != 17)
        return "Choose Any, TCP, or UDP for the filter protocol";
    return {};
}

static std::string filter_rule_summary(const filter_entry_t& rule) {
    std::string summary = "rule #" + std::to_string(rule.rule_id) + " " +
        (rule.action == 0 ? "BLOCK" : "ALLOW") + " " +
        (rule.direction == 0 ? "IN" : rule.direction == 1 ? "OUT" : "BOTH") + " " +
        (rule.protocol == 6 ? "TCP" : rule.protocol == 17 ? "UDP" : "ANY") +
        " PID " + std::to_string(rule.pid) + " port " + std::to_string(rule.port);
    if (!rule.ip_addr.empty()) summary.append(" IP ").append(rule.ip_addr);
    return summary;
}

static bool command_requires_confirmation(operational_command_t command) noexcept {
    return command == operational_command_t::proxy_history_clear ||
        command == operational_command_t::proxy_ca_trust_repair ||
        command == operational_command_t::filter_add ||
        command == operational_command_t::filter_remove_selected ||
        command == operational_command_t::filter_clear ||
        command == operational_command_t::keylog_clear;
}

operational_command_capability_t operational_command_capability(
    operational_command_t command) {
    operational_command_capability_t capability;
    capability.checked = false;
    if (!g_state.active) {
        capability.disabled_reason = "The Network runtime is not initialized";
        return capability;
    }
    const bool capture_pending = g_state.cap_start_pending.load(std::memory_order_acquire) ||
        g_state.cap_stop_pending.load(std::memory_order_acquire);
    const bool capture_running = g_state.cap_running.load(std::memory_order_acquire);
    const bool proxy_pending = s_proxy_operation_pending.load(std::memory_order_acquire);
    const bool filter_pending = g_state.filter_mutation_pending.load(std::memory_order_acquire);
    const bool keylog_pending = s_keylog_operation_pending.load(std::memory_order_acquire);
    const auto proxy = std::atomic_load_explicit(&s_proxy_runtime_snapshot, std::memory_order_acquire);
    const auto intercept = std::atomic_load_explicit(&s_intercept_runtime_snapshot, std::memory_order_acquire);
    const auto keylog = std::atomic_load_explicit(&s_keylog_runtime_snapshot, std::memory_order_acquire);
    switch (command) {
    case operational_command_t::capture_start:
        request_driver_available_snapshot();
        if (capture_pending) capability.disabled_reason = "A capture state change is already in progress";
        else if (capture_running) capability.disabled_reason = "Packet capture is already running";
        else if (!s_driver_available_snapshot.load(std::memory_order_acquire))
            capability.disabled_reason = "Driver-backed packet capture is unavailable";
        else capability.enabled = true;
        capability.target_summary = "PID " + std::to_string(g_state.cap_filter_pid) +
            ", port " + std::to_string(g_state.cap_filter_port) +
            ", protocol " + std::to_string(g_state.cap_filter_protocol);
        break;
    case operational_command_t::capture_stop:
        if (capture_pending) capability.disabled_reason = "A capture state change is already in progress";
        else if (!capture_running) capability.disabled_reason = "Packet capture is not running";
        else capability.enabled = true;
        capability.target_summary = "the active driver-backed packet capture";
        break;
    case operational_command_t::proxy_start:
        if (proxy_pending) capability.disabled_reason = "A Proxy state change is already in progress";
        else if (mitm_proxy::is_running()) capability.disabled_reason = "The interception Proxy is already running";
        else if (g_state.proxy_bind_addr[0] == '\0') capability.disabled_reason = "Enter a Proxy bind address first";
        else if (g_state.proxy_port < 1 || g_state.proxy_port > 65535) capability.disabled_reason = "Proxy port must be between 1 and 65535";
        else capability.enabled = true;
        capability.target_summary = std::string(g_state.proxy_bind_addr) + ":" +
            std::to_string(g_state.proxy_port) +
            (g_state.proxy_decode_tls ? " with TLS interception" : " without TLS interception");
        break;
    case operational_command_t::proxy_stop:
        if (proxy_pending) capability.disabled_reason = "A Proxy state change is already in progress";
        else if (!mitm_proxy::is_running()) capability.disabled_reason = "The interception Proxy is not running";
        else capability.enabled = true;
        capability.target_summary = "the active interception Proxy listener";
        break;
    case operational_command_t::proxy_history_clear:
        request_proxy_runtime_snapshot();
        if (proxy_pending) capability.disabled_reason = "A Proxy operation is already in progress";
        else if (!proxy) capability.disabled_reason = "Proxy history is still loading";
        else if (proxy->history.empty()) capability.disabled_reason = "Proxy history is already empty";
        else capability.enabled = true;
        capability.target_summary = proxy
            ? std::to_string(proxy->history.size()) + " retained exchanges, including requests, responses, annotations, and evidence"
            : "the retained Proxy history";
        break;
    case operational_command_t::proxy_ca_trust_repair:
        request_proxy_runtime_snapshot();
        if (proxy_pending) capability.disabled_reason = "A Proxy operation is already in progress";
        else if (!proxy) capability.disabled_reason = "CA trust status is still loading";
        else if (proxy->ca_installed) capability.disabled_reason = "The AiDA interception CA is already trusted for the current user";
        else capability.enabled = true;
        capability.target_summary = "the current-user root trust store for controlled Camoufox interception";
        break;
    case operational_command_t::filter_add: {
        request_driver_available_snapshot();
        const std::string validation = filter_draft_error(g_state);
        if (filter_pending) capability.disabled_reason = "A network filter mutation is already in progress";
        else if (!s_driver_available_snapshot.load(std::memory_order_acquire))
            capability.disabled_reason = "Driver-backed filter control is unavailable";
        else if (!validation.empty()) capability.disabled_reason = validation;
        else capability.enabled = true;
        capability.target_summary = std::string(g_state.nf_action == 0 ? "BLOCK" : "ALLOW") + " " +
            (g_state.nf_direction == 0 ? "IN" : g_state.nf_direction == 1 ? "OUT" : "BOTH") + " " +
            (g_state.nf_protocol == 6 ? "TCP" : g_state.nf_protocol == 17 ? "UDP" : "ANY") +
            " PID " + (g_state.nf_pid[0] ? g_state.nf_pid : "0") + " port " +
            (g_state.nf_port[0] ? g_state.nf_port : "0") +
            (g_state.nf_ip[0] ? std::string(" IP ") + g_state.nf_ip : std::string());
        break;
    }
    case operational_command_t::filter_remove_selected:
        request_driver_available_snapshot();
        if (filter_pending) capability.disabled_reason = "A network filter mutation is already in progress";
        else if (!s_driver_available_snapshot.load(std::memory_order_acquire))
            capability.disabled_reason = "Driver-backed filter control is unavailable";
        else if (g_state.filter_selected < 0 ||
                 g_state.filter_selected >= static_cast<int>(g_state.filters.size()))
            capability.disabled_reason = "Select a retained network filter rule first";
        else capability.enabled = true;
        capability.target_summary = capability.enabled
            ? filter_rule_summary(g_state.filters[static_cast<std::size_t>(g_state.filter_selected)])
            : "the selected retained network filter rule";
        break;
    case operational_command_t::filter_clear:
        request_driver_available_snapshot();
        if (filter_pending) capability.disabled_reason = "A network filter mutation is already in progress";
        else if (!s_driver_available_snapshot.load(std::memory_order_acquire))
            capability.disabled_reason = "Driver-backed filter control is unavailable";
        else if (g_state.filters.empty()) capability.disabled_reason = "There are no retained network filter rules to clear";
        else capability.enabled = true;
        capability.target_summary = std::to_string(g_state.filters.size()) + " retained live kernel traffic rules";
        break;
    case operational_command_t::intercept_toggle:
        request_intercept_runtime_snapshot();
        if (s_intercept_operation_pending.load(std::memory_order_acquire))
            capability.disabled_reason = "An Intercept operation is already in progress";
        else if (!intercept) capability.disabled_reason = "Intercept state is still loading";
        else capability.enabled = true;
        capability.checked = intercept && intercept->enabled;
        capability.target_summary = capability.checked
            ? "disable request interception while preserving held exchanges"
            : "enable request interception for new Proxy exchanges";
        break;
    case operational_command_t::keylog_launch:
        request_keylog_runtime_snapshot();
        if (keylog_pending) capability.disabled_reason = "A TLS keylog operation is already in progress";
        else if (keylog && keylog->watching) capability.disabled_reason = "A TLS keylog source is already being watched";
        else if (g_state.kl_exe_path[0] == '\0') capability.disabled_reason = "Choose an executable to launch first";
        else capability.enabled = true;
        capability.target_summary = std::string(g_state.kl_exe_path) +
            (g_state.kl_args[0] ? std::string(" ") + g_state.kl_args : std::string());
        break;
    case operational_command_t::keylog_watch:
        request_keylog_runtime_snapshot();
        if (keylog_pending) capability.disabled_reason = "A TLS keylog operation is already in progress";
        else if (keylog && keylog->watching) capability.disabled_reason = "A TLS keylog source is already being watched";
        else if (g_state.kl_watch_path[0] == '\0') capability.disabled_reason = "Choose or enter a TLS keylog file first";
        else capability.enabled = true;
        capability.target_summary = g_state.kl_watch_path;
        break;
    case operational_command_t::keylog_stop:
        request_keylog_runtime_snapshot();
        if (keylog_pending) capability.disabled_reason = "A TLS keylog operation is already in progress";
        else if (!keylog || !keylog->watching) capability.disabled_reason = "No TLS keylog source is being watched";
        else capability.enabled = true;
        capability.target_summary = keylog && !keylog->path.empty()
            ? keylog->path : "the active TLS keylog source";
        break;
    case operational_command_t::keylog_clear:
        request_keylog_runtime_snapshot();
        {
        const auto token = ssl_keylog::retained_token();
        if (keylog_pending) capability.disabled_reason = "A TLS keylog operation is already in progress";
        else if (token.count == 0) capability.disabled_reason = "There are no captured TLS secrets to clear";
        else capability.enabled = true;
        capability.target_summary = std::to_string(token.count) + " retained TLS secrets";
        }
        break;
    }
    return capability;
}

bool prepare_operational_command_confirmation(operational_command_t command,
                                              std::string* error) {
    if (error) error->clear();
    if (!command_requires_confirmation(command)) {
        if (error) *error = "This Network command does not require confirmation";
        return false;
    }
    const auto capability = operational_command_capability(command);
    if (!capability.enabled) {
        if (error) *error = capability.disabled_reason;
        return false;
    }
    operational_review_binding_t binding;
    binding.prepared = true;
    binding.command = command;
    if (command == operational_command_t::proxy_history_clear) {
        const auto proxy = std::atomic_load_explicit(&s_proxy_runtime_snapshot, std::memory_order_acquire);
        if (!proxy) {
            if (error) *error = "Proxy history changed before review could be prepared";
            return false;
        }
        binding.retained_count = proxy->history.size();
        binding.retained_exchange_ids.reserve(proxy->history.size());
        for (const auto& exchange : proxy->history)
            binding.retained_exchange_ids.push_back(exchange.id);
    } else if (command == operational_command_t::filter_add) {
        binding.filter_action = g_state.nf_action;
        binding.filter_direction = g_state.nf_direction;
        binding.filter_protocol = g_state.nf_protocol;
        binding.filter_pid = g_state.nf_pid;
        binding.filter_port = g_state.nf_port;
        binding.filter_ip = g_state.nf_ip;
    } else if (command == operational_command_t::filter_remove_selected) {
        binding.retained_rule = g_state.filters[static_cast<std::size_t>(g_state.filter_selected)];
    } else if (command == operational_command_t::filter_clear) {
        binding.retained_count = g_state.filters.size();
        binding.retained_rule_ids.reserve(g_state.filters.size());
        for (const auto& rule : g_state.filters)
            binding.retained_rule_ids.push_back(rule.rule_id);
    } else if (command == operational_command_t::keylog_clear) {
        const auto keylog = std::atomic_load_explicit(&s_keylog_runtime_snapshot, std::memory_order_acquire);
        if (!keylog) {
            if (error) *error = "TLS keylog state changed before review could be prepared";
            return false;
        }
        binding.retained_keylog_token = ssl_keylog::retained_token();
        binding.retained_count = binding.retained_keylog_token.count;
        if (binding.retained_count == 0) {
            if (error) *error = "There are no captured TLS secrets to clear";
            return false;
        }
    }
    s_operational_review = std::move(binding);
    return true;
}

void cancel_operational_command_confirmation(operational_command_t command) noexcept {
    if (s_operational_review.prepared && s_operational_review.command == command)
        s_operational_review = {};
}

bool execute_operational_command(operational_command_t command, std::string* error) {
    if (error) error->clear();
    const auto capability = operational_command_capability(command);
    if (!capability.enabled) {
        if (error) *error = capability.disabled_reason;
        return false;
    }
    if (command_requires_confirmation(command) &&
        (!s_operational_review.prepared || s_operational_review.command != command)) {
        if (error) *error = "The reviewed Network target is unavailable; review the command again";
        return false;
    }
    if (command == operational_command_t::proxy_history_clear) {
        const auto proxy = std::atomic_load_explicit(&s_proxy_runtime_snapshot, std::memory_order_acquire);
        std::vector<std::uint64_t> current;
        if (proxy) {
            current.reserve(proxy->history.size());
            for (const auto& exchange : proxy->history) current.push_back(exchange.id);
        }
        if (!proxy || current != s_operational_review.retained_exchange_ids) {
            s_operational_review = {};
            if (error) *error = "Proxy history changed after review; review the current retained exchanges again";
            return false;
        }
        const std::size_t count = s_operational_review.retained_count;
        auto reviewed_ids = std::move(s_operational_review.retained_exchange_ids);
        s_operational_review = {};
        request_proxy_history_clear(count, std::move(reviewed_ids));
        return s_proxy_operation_pending.load(std::memory_order_acquire);
    }
    if (command == operational_command_t::filter_add) {
        const bool unchanged = s_operational_review.filter_action == g_state.nf_action &&
            s_operational_review.filter_direction == g_state.nf_direction &&
            s_operational_review.filter_protocol == g_state.nf_protocol &&
            s_operational_review.filter_pid == g_state.nf_pid &&
            s_operational_review.filter_port == g_state.nf_port &&
            s_operational_review.filter_ip == g_state.nf_ip;
        s_operational_review = {};
        if (!unchanged) {
            if (error) *error = "The network filter draft changed after review; review the current rule again";
            return false;
        }
        request_filter_add(g_state);
        return g_state.filter_mutation_pending.load(std::memory_order_acquire);
    }
    if (command == operational_command_t::filter_remove_selected) {
        const filter_entry_t reviewed = s_operational_review.retained_rule;
        const auto found = std::find_if(g_state.filters.begin(), g_state.filters.end(),
            [&reviewed](const filter_entry_t& rule) {
                return rule.rule_id == reviewed.rule_id && rule.action == reviewed.action &&
                    rule.direction == reviewed.direction && rule.protocol == reviewed.protocol &&
                    rule.pid == reviewed.pid && rule.port == reviewed.port &&
                    rule.ip_addr == reviewed.ip_addr && rule.active == reviewed.active;
            });
        s_operational_review = {};
        if (found == g_state.filters.end()) {
            if (error) *error = "The retained network filter rule changed after review; select it again";
            return false;
        }
        request_filter_remove(g_state, reviewed.rule_id);
        return g_state.filter_mutation_pending.load(std::memory_order_acquire);
    }
    if (command == operational_command_t::filter_clear) {
        std::vector<std::uint32_t> current;
        current.reserve(g_state.filters.size());
        for (const auto& rule : g_state.filters) current.push_back(rule.rule_id);
        if (current != s_operational_review.retained_rule_ids) {
            s_operational_review = {};
            if (error) *error = "The retained network filter set changed after review; review it again";
            return false;
        }
        s_operational_review = {};
        request_filter_clear(g_state);
        return g_state.filter_mutation_pending.load(std::memory_order_acquire);
    }
    if (command == operational_command_t::keylog_clear) {
        const auto current_token = ssl_keylog::retained_token();
        const auto reviewed_token = s_operational_review.retained_keylog_token;
        if (current_token.generation != reviewed_token.generation ||
            current_token.count != reviewed_token.count) {
            s_operational_review = {};
            if (error) *error = "The retained TLS secret set changed after review; review it again";
            return false;
        }
        const std::size_t count = s_operational_review.retained_count;
        s_operational_review = {};
        request_keylog_operation(keylog_operation_t::clear_entries, {}, {}, count,
            reviewed_token);
        return s_keylog_operation_pending.load(std::memory_order_acquire);
    }
    if (command == operational_command_t::proxy_ca_trust_repair) {
        s_operational_review = {};
        request_ca_trust_repair();
        return s_proxy_operation_pending.load(std::memory_order_acquire);
    }
    switch (command) {
    case operational_command_t::capture_start: request_capture_start(g_state); return g_state.cap_start_pending.load(std::memory_order_acquire);
    case operational_command_t::capture_stop: request_capture_stop(g_state); return g_state.cap_stop_pending.load(std::memory_order_acquire);
    case operational_command_t::proxy_start: request_proxy_control(g_state, true); return s_proxy_operation_pending.load(std::memory_order_acquire);
    case operational_command_t::proxy_stop: request_proxy_control(g_state, false); return s_proxy_operation_pending.load(std::memory_order_acquire);
    case operational_command_t::intercept_toggle: {
        const auto intercept = std::atomic_load_explicit(&s_intercept_runtime_snapshot, std::memory_order_acquire);
        if (!intercept) {
            if (error) *error = "Intercept state is no longer retained";
            return false;
        }
        return request_intercept_operation(
            intercept_operation_t::set_enabled, !intercept->enabled,
            {}, {}, 0, 0);
    }
    case operational_command_t::keylog_launch:
        request_keylog_operation(keylog_operation_t::launch_and_watch,
            g_state.kl_exe_path, g_state.kl_args, 0);
        return s_keylog_operation_pending.load(std::memory_order_acquire);
    case operational_command_t::keylog_watch:
        request_keylog_operation(keylog_operation_t::watch_file,
            g_state.kl_watch_path, {}, 0);
        return s_keylog_operation_pending.load(std::memory_order_acquire);
    case operational_command_t::keylog_stop: {
        const auto keylog = std::atomic_load_explicit(&s_keylog_runtime_snapshot, std::memory_order_acquire);
        request_keylog_operation(keylog_operation_t::stop_watching,
            keylog ? keylog->path : std::string(), {}, keylog ? keylog->entry_count : 0);
        return s_keylog_operation_pending.load(std::memory_order_acquire);
    }
    default:
        break;
    }
    if (error) *error = "The Network command could not be dispatched";
    return false;
}

static void render_keylog(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_keylog", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    request_keylog_runtime_snapshot();
    const auto keylog_snapshot = std::atomic_load_explicit(&s_keylog_runtime_snapshot, std::memory_order_acquire);
    const bool keylog_watching = keylog_snapshot && keylog_snapshot->watching;
    const bool keylog_pending = s_keylog_operation_pending.load(std::memory_order_acquire);
    static const std::vector<ssl_keylog::keylog_entry> empty_keylog_entries;
    const auto& entries = keylog_snapshot ? keylog_snapshot->entries : empty_keylog_entries;
    const std::size_t keylog_entry_count = keylog_snapshot ? keylog_snapshot->entry_count : 0;
    if (state.kl_selected >= static_cast<int>(entries.size()))
        state.kl_selected = entries.empty() ? -1 : static_cast<int>(entries.size()) - 1;


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "SSL Key Logger");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Executable:");
    ImGui::SameLine();
    aida::ui::input_text("##kl_exe", state.kl_exe_path, sizeof(state.kl_exe_path),
                          "C:\\path\\to\\target.exe", false, ImVec2(360.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Browse...##kl_browse", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        char path_buf[MAX_PATH] = {};
        static const char k_exe_open_filter[] =
            "Executable (*.exe)\0*.exe\0"
            "All files (*.*)\0*.*\0\0";
        if (network_open_dialog::show_open_file_dialog(g_hwnd,
                "Select Target Executable",
                k_exe_open_filter,
                path_buf, sizeof(path_buf),
                "network_view::keylog_exe")) {
            snprintf(state.kl_exe_path, sizeof(state.kl_exe_path), "%s", path_buf);
            diag::log_tagged_fmt("network", "keylog_exe_picked path='%s'", path_buf);
            diag::log_tagged("net_audit",
                (std::string("[net_audit] keylog exe picked path='") + path_buf + "'").c_str());
        }
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Arguments:");
    ImGui::SameLine();
    aida::ui::input_text("##kl_args", state.kl_args, sizeof(state.kl_args),
                          "Arguments to pass...", false, ImVec2(360.f, 28.f));

    ImGui::Spacing();

    if (!keylog_watching) {
        const bool can_launch = state.kl_exe_path[0] != '\0';
        if (aida::ui::button(keylog_pending ? "Launching...##keylog_launch" : "Launch & Watch##keylog_launch",
                             aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), keylog_pending || !can_launch)) {
            diag::log_tagged_fmt("network", "keylog_launch_clicked exe='%s' args='%s'",
                state.kl_exe_path, state.kl_args);
            invoke_global_network_action("network.keylog.launch");
        }
        ImGui::SameLine();
        if (aida::ui::button("Watch File...", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), keylog_pending)) {
            char path_buf[MAX_PATH] = {};
            static const char k_keylog_open_filter[] =
                "SSL Keylog (*.log;*.keylog;*.txt)\0*.log;*.keylog;*.txt\0"
                "All files (*.*)\0*.*\0\0";
            if (network_open_dialog::show_open_file_dialog(g_hwnd,
                    "Watch SSLKEYLOGFILE",
                    k_keylog_open_filter,
                    path_buf, sizeof(path_buf),
                    "network_view::keylog_watch")) {
                snprintf(state.kl_watch_path, sizeof(state.kl_watch_path), "%s", path_buf);
                diag::log_tagged_fmt("network", "keylog_watch_dialog_pick path='%s'", path_buf);
                diag::log_tagged("net_audit",
                    (std::string("[net_audit] keylog watch dialog path='") + path_buf + "'").c_str());
                invoke_global_network_action("network.keylog.watch");
            } else {
                diag::log_tagged("network", "keylog_watch_dialog_cancelled");
            }
        }
        ImGui::SameLine();
        aida::ui::input_text("##kl_watch_path", state.kl_watch_path, sizeof(state.kl_watch_path),
                              "or paste a keylog path...", false, ImVec2(260.f, 28.f));
        ImGui::SameLine();
        bool can_use_typed = state.kl_watch_path[0] != '\0';
        if (aida::ui::button("Watch", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), keylog_pending || !can_use_typed) && can_use_typed) {
            diag::log_tagged_fmt("network", "keylog_watch_typed path='%s'", state.kl_watch_path);
            diag::log_tagged("net_audit",
                (std::string("[net_audit] keylog watch typed path='") + state.kl_watch_path + "'").c_str());
            invoke_global_network_action("network.keylog.watch");
        }
    } else {
        char watch_buf[640];
        snprintf(watch_buf, sizeof(watch_buf), "Watching: %s",
            keylog_snapshot->path.empty() ? "active TLS keylog source" : keylog_snapshot->path.c_str());
        aida::ui::pill_kind(watch_buf, aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        if (aida::ui::button(keylog_pending ? "Stopping...##keylog_stop" : "Stop Watching##keylog_stop",
                             aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), keylog_pending)) {
            diag::log_tagged_fmt("network", "keylog_stop_watching path='%s' entries=%zu",
                keylog_snapshot->path.c_str(), keylog_entry_count);
            invoke_global_network_action("network.keylog.stop");
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                             ImVec2(0.f, 0.f), keylog_pending || keylog_entry_count == 0)) {
            invoke_global_network_action("network.keylog.clear");
        }
    }

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Captured Keys: %zu", keylog_entry_count);

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_h = std::max(28.f, ImGui::GetFontSize() + 9.f);
    float hdr_y = org.y + cursor.y;

    float col_time = 100.f, col_label = 220.f, col_cr = 220.f, col_sec_min = 220.f;
    (void)col_sec_min;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + hdr_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, hdr_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    float hdr_text_y = hdr_y + (hdr_h - ImGui::GetFontSize()) * 0.5f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Time");          cx += col_time;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Label");         cx += col_label;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Client Random"); cx += col_cr;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Secret");

    ImGui::SetCursorPosY(cursor.y + hdr_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + hdr_h - 1.f), ImVec2(org.x + w, hdr_y + hdr_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + hdr_h + 12.f);
    ImGui::BeginChild("##kl_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);

    if (entries.empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::key;
        cfg.title = "No keys captured";
        cfg.body  = "Launch a target executable or watch a SSLKEYLOGFILE to start collecting TLS secrets.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, 0.f));
        ImGui::EndChild();
        return;
    }

    ImGuiListClipper keylog_clipper;
    keylog_clipper.Begin(static_cast<int>(entries.size()), row_h);
    while (keylog_clipper.Step()) {
    for (int visible_index = keylog_clipper.DisplayStart;
         visible_index < keylog_clipper.DisplayEnd; ++visible_index) {
        const int i = static_cast<int>(entries.size()) - 1 - visible_index;
        auto& e = entries[static_cast<size_t>(i)];

        float row_alpha = 1.f;
        float row_yoff = 0.f;
        compute_row_entrance(s_kl_rows, entries.size(), row_alpha, row_yoff,
                              static_cast<int>(entries.size()) - 1 - i);
        float r_alpha = alpha * row_alpha;

        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool is_sel = (state.kl_selected == i);

        if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + list_sz.x, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        ImVec2 mouse = ImGui::GetMousePos();
        bool hov = (mouse.x >= list_org.x && mouse.x < list_org.x + list_sz.x &&
                    mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        if (hov && !is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + list_sz.x, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
        }
        if (hov && ImGui::IsMouseClicked(0))
            state.kl_selected = i;


        std::string cr_short = e.client_random_hex.substr(0, 24) + "...";
        std::string sec_short = e.secret_hex.size() > 24 ? e.secret_hex.substr(0, 24) + "..." : e.secret_hex;

        ImU32 label_col;
        if (e.label == "CLIENT_RANDOM")
            label_col = aida::ui::with_alpha(th.info, r_alpha);
        else if (e.label.find("HANDSHAKE") != std::string::npos)
            label_col = aida::ui::with_alpha(th.warning, r_alpha);
        else
            label_col = aida::ui::with_alpha(th.success, r_alpha);

        cx = list_org.x + 8.f;
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_dim, r_alpha),
                     format_timestamp(e.timestamp).c_str());
        cx += col_time;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), label_col, e.label.c_str());
        cx += col_label;

        ImFont* mono_font = aida::ui::fonts::code();
        bool pushed = false;
        if (mono_font) {
            ImGui::PushFont(mono_font);
            pushed = true;
        }
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_secondary, r_alpha), cr_short.c_str());
        cx += col_cr;
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_secondary, r_alpha), sec_short.c_str());
        if (pushed) ImGui::PopFont();

        ImGui::SetCursorPosY(ry + row_h);
    }
    }
    dl->PopClipRect();

    if (state.kl_auto_scroll && !entries.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    if (state.kl_selected >= 0 && state.kl_selected < static_cast<int>(entries.size())) {
        auto& e = entries[static_cast<size_t>(state.kl_selected)];
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                            "Selected: %s  -  %s", e.label.c_str(), format_timestamp(e.timestamp).c_str());
        if (aida::ui::button("Copy Client Random", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            ImGui::SetClipboardText(e.client_random_hex.c_str());
        }
        ImGui::SameLine();
        if (aida::ui::button("Copy Secret", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            ImGui::SetClipboardText(e.secret_hex.c_str());
        }
        ImGui::SameLine();
        if (aida::ui::button("Copy Line", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            std::string line = e.label + " " + e.client_random_hex + " " + e.secret_hex;
            ImGui::SetClipboardText(line.c_str());
        }
    }

    ImGui::EndChild();
}


static constexpr std::size_t k_network_export_limit = 256ULL * 1024ULL * 1024ULL;

template <typename Value>
static bool append_export_value(std::vector<std::uint8_t>& output, const Value& value) {
    if (output.size() > k_network_export_limit - sizeof(Value))
        return false;
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(Value));
    return true;
}

static bool append_export_bytes(std::vector<std::uint8_t>& output, const std::uint8_t* data,
                                std::size_t size) {
    if ((size != 0 && !data) || size > k_network_export_limit ||
        output.size() > k_network_export_limit - size)
        return false;
    if (size == 0)
        return true;
    output.insert(output.end(), data, data + size);
    return true;
}

static bool serialize_pcap(const std::vector<packet_entry_t>& packets, std::uint32_t filter_pid,
                           std::uint8_t filter_protocol, std::vector<std::uint8_t>& output,
                           std::uint32_t& written, std::string& error) {
    output.clear();
    output.reserve((std::min)(k_network_export_limit, static_cast<std::size_t>(24 + packets.size() * 128)));
    const std::uint32_t magic = 0xa1b2c3d4;
    const std::uint16_t major = 2;
    const std::uint16_t minor = 4;
    const std::int32_t timezone = 0;
    const std::uint32_t sigfigs = 0;
    const std::uint32_t snaplen = 65535;
    const std::uint32_t linktype = 1;
    if (!append_export_value(output, magic) || !append_export_value(output, major) ||
        !append_export_value(output, minor) || !append_export_value(output, timezone) ||
        !append_export_value(output, sigfigs) || !append_export_value(output, snaplen) ||
        !append_export_value(output, linktype)) {
        error = "PCAP header exceeds export limit";
        return false;
    }
    written = 0;
    for (const auto& packet : packets) {
        if (filter_pid != 0 && packet.pid != filter_pid)
            continue;
        if (filter_protocol != 0 && packet.protocol != filter_protocol)
            continue;
        const std::uint32_t transport_size = packet.protocol == 6 ? 20U : 8U;
        const std::size_t protocol_payload_limit = 65535U - 20U - transport_size;
        const std::size_t payload_size = (std::min)({packet.payload.size(),
            static_cast<std::size_t>(packet.payload_size), protocol_payload_limit});
        const std::uint32_t ip_size = static_cast<std::uint32_t>(20U + transport_size + payload_size);
        const std::uint32_t frame_size = 14U + ip_size;
        if (output.size() > k_network_export_limit - 16U - frame_size) {
            error = "PCAP export exceeds the 256 MiB safety limit";
            return false;
        }
        std::vector<std::uint8_t> frame(frame_size, 0);
        frame[12] = 0x08;
        frame[13] = 0x00;
        std::uint8_t* ip = frame.data() + 14;
        ip[0] = 0x45;
        ip[2] = static_cast<std::uint8_t>((ip_size >> 8) & 0xff);
        ip[3] = static_cast<std::uint8_t>(ip_size & 0xff);
        ip[8] = 64;
        ip[9] = packet.protocol;
        if (packet.direction == 1) {
            std::memcpy(ip + 12, packet.src_addr, 4);
            std::memcpy(ip + 16, packet.dst_addr, 4);
        } else {
            std::memcpy(ip + 12, packet.dst_addr, 4);
            std::memcpy(ip + 16, packet.src_addr, 4);
        }
        std::uint32_t checksum = 0;
        for (int index = 0; index < 20; index += 2)
            checksum += (static_cast<std::uint32_t>(ip[index]) << 8) | ip[index + 1];
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        const std::uint16_t ip_checksum = static_cast<std::uint16_t>(~checksum);
        ip[10] = static_cast<std::uint8_t>(ip_checksum >> 8);
        ip[11] = static_cast<std::uint8_t>(ip_checksum & 0xff);
        std::uint8_t* transport = ip + 20;
        const std::uint16_t source_port = packet.direction == 1 ? packet.src_port : packet.dst_port;
        const std::uint16_t destination_port = packet.direction == 1 ? packet.dst_port : packet.src_port;
        transport[0] = static_cast<std::uint8_t>(source_port >> 8);
        transport[1] = static_cast<std::uint8_t>(source_port & 0xff);
        transport[2] = static_cast<std::uint8_t>(destination_port >> 8);
        transport[3] = static_cast<std::uint8_t>(destination_port & 0xff);
        if (packet.protocol == 6) {
            transport[12] = 0x50;
            transport[13] = 0x18;
        } else {
            const std::uint16_t udp_size = static_cast<std::uint16_t>(8U + payload_size);
            transport[4] = static_cast<std::uint8_t>(udp_size >> 8);
            transport[5] = static_cast<std::uint8_t>(udp_size & 0xff);
        }
        if (payload_size != 0)
            std::memcpy(transport + transport_size, packet.payload.data(), payload_size);
        const std::uint32_t seconds = static_cast<std::uint32_t>(packet.timestamp / 1000);
        const std::uint32_t microseconds = static_cast<std::uint32_t>((packet.timestamp % 1000) * 1000);
        if (!append_export_value(output, seconds) || !append_export_value(output, microseconds) ||
            !append_export_value(output, frame_size) || !append_export_value(output, frame_size) ||
            !append_export_bytes(output, frame.data(), frame.size())) {
            error = "PCAP export exceeds the 256 MiB safety limit";
            return false;
        }
        ++written;
    }
    return true;
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static bool atomic_write_export(const std::string& destination, const std::uint8_t* data,
                                std::size_t size, std::string& error) {
    if (destination.empty() || (size != 0 && !data) || size > k_network_export_limit) {
        error = "Export destination or payload is invalid";
        return false;
    }
    const std::string temporary = destination + ".aida-tmp-" +
        std::to_string(GetCurrentProcessId()) + "-" +
        std::to_string(s_network_operation_sequence.fetch_add(1, std::memory_order_acq_rel));
    HANDLE file = CreateFileA(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "Cannot create temporary export file (Win32 " + std::to_string(GetLastError()) + ")";
        return false;
    }
    bool success = true;
    std::size_t offset = 0;
    while (offset < size) {
        const DWORD chunk = static_cast<DWORD>((std::min)(size - offset, static_cast<std::size_t>(1024 * 1024)));
        DWORD wrote = 0;
        if (!WriteFile(file, data + offset, chunk, &wrote, nullptr) || wrote != chunk) {
            error = "Export write failed or was partial (Win32 " + std::to_string(GetLastError()) + ")";
            success = false;
            break;
        }
        offset += wrote;
    }
    LARGE_INTEGER exact_size{};
    if (success && (!FlushFileBuffers(file) || !GetFileSizeEx(file, &exact_size) ||
                    exact_size.QuadPart != static_cast<LONGLONG>(size))) {
        error = "Export flush or size verification failed (Win32 " + std::to_string(GetLastError()) + ")";
        success = false;
    }
    CloseHandle(file);
    if (success && !MoveFileExA(temporary.c_str(), destination.c_str(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = "Atomic export replacement failed (Win32 " + std::to_string(GetLastError()) + ")";
        success = false;
    }
    if (!success)
        DeleteFileA(temporary.c_str());
    return success;
}
#endif

static bool serialize_har_bounded(const std::vector<mitm_proxy::http_exchange>& history,
                                  std::string& serialized, std::string& error) {
    if (history.size() > 4096) {
        error = "HAR history exceeds the 4096-exchange safety limit";
        return false;
    }
    std::size_t source_bytes = 0;
    for (const auto& exchange : history) {
        const std::size_t exchange_bytes = exchange.raw_request.size() + exchange.raw_response.size();
        if (exchange_bytes > k_network_export_limit || source_bytes > k_network_export_limit - exchange_bytes) {
            error = "HAR source history exceeds the 256 MiB safety limit";
            return false;
        }
        source_bytes += exchange_bytes;
    }
    try {
        serialized = flow_serializer::export_har_1_2(history).dump(2);
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
    if (serialized.size() > k_network_export_limit) {
        serialized.clear();
        error = "Serialized HAR exceeds the 256 MiB safety limit";
        return false;
    }
    return true;
}

static void render_pcap_export(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab; (void)w; (void)h;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_pcap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "PCAP Export");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Output File:");
    ImGui::SameLine();
    aida::ui::input_text("##pcap_path", state.pcap_path, sizeof(state.pcap_path),
                          "C:\\path\\to\\capture.pcap", false, ImVec2(420.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Browse...##pcap_browse", aida::ui::button_kind_t::secondary,
                          aida::ui::size_t_::sm)) {
        char path_buf[MAX_PATH] = {};
        if (state.pcap_path[0])
            snprintf(path_buf, sizeof(path_buf), "%s", state.pcap_path);
        static const char k_pcap_save_filter[] =
            "Packet Capture (*.pcap)\0*.pcap\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_save_file_dialog(g_hwnd,
                "Save PCAP",
                k_pcap_save_filter,
                "pcap",
                path_buf, sizeof(path_buf),
                "network_view::pcap_save")) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
            aida::preview::network::record_receipt("Save PCAP", path_buf);
#endif
            snprintf(state.pcap_path, sizeof(state.pcap_path), "%s", path_buf);
            diag::log_tagged_fmt("network", "pcap_path_picked path='%s'", path_buf);
            diag::log_tagged("net_audit",
                (std::string("[net_audit] pcap path picked path='") + path_buf + "'").c_str());
        }
    }

    if (state.pcap_path[0] == '\0') {
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        snprintf(state.pcap_path, sizeof(state.pcap_path), "%saida_capture.pcap", temp);
    }

    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Filter PID:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.f);
    int fpid = static_cast<int>(state.pcap_filter_pid);
    if (ImGui::InputInt("##pcap_fpid", &fpid, 0, 0))
        state.pcap_filter_pid = static_cast<uint32_t>(std::max(0, fpid));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "(0 = all)");

    ImGui::SameLine(0, 20.f);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Protocol:");
    ImGui::SameLine();
    const char* proto_names[] = { "All", "TCP", "UDP" };
    int proto_idx = state.pcap_filter_protocol == 6 ? 1 : (state.pcap_filter_protocol == 17 ? 2 : 0);
    ImGui::SetNextItemWidth(100.f);
    if (ImGui::Combo("##pcap_proto", &proto_idx, proto_names, 3)) {
        state.pcap_filter_protocol = proto_idx == 1 ? 6 : (proto_idx == 2 ? 17 : 0);
    }

    ImGui::Spacing();

    const auto export_packets = std::atomic_load_explicit(&state.capture_snapshot, std::memory_order_acquire);
    const size_t cap_count = export_packets ? export_packets->size() : 0;

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Captured packets available: %zu", cap_count);

    ImGui::Spacing();

    if (!state.pcap_writing.load()) {
        bool can_export = state.pcap_path[0] != '\0' && cap_count > 0;
        if (aida::ui::button("Export to PCAP", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), !can_export)) {
            state.pcap_writing.store(true);
            state.pcap_written_count.store(0);
            {
                std::lock_guard<std::mutex> status_lock(state.pcap_error_mutex);
                state.pcap_last_error.clear();
                state.pcap_last_path.clear();
            }

            const auto path = std::string(state.pcap_path);
            const auto filter_pid = state.pcap_filter_pid;
            const auto filter_proto = state.pcap_filter_protocol;
            const std::string task_id = register_network_operation(
                "network.pcap.export", "Export packet capture", "view.network.pcap",
                path + " pid=" + std::to_string(filter_pid) + " protocol=" + std::to_string(filter_proto));

            diag::log_tagged_fmt("network", "pcap_export_clicked path='%s' filter_pid=%u filter_proto=%u source_packets=%zu",
                path.c_str(), filter_pid, filter_proto, export_packets ? export_packets->size() : 0);
            diag::log_tagged("net_audit",
                ("[net_audit] pcap export start path='" + path + "'").c_str());

            const bool posted = post_network_task("pcap_export", aida::infra::executor::domain_t::diagnostics, "bounded_task",
                [packets = export_packets, path, filter_pid, filter_proto, task_id]() {
                bool success = false;
                std::uint32_t count = 0;
                std::string error;
                std::vector<std::uint8_t> bytes;
                if (!packets) {
                    error = "The capture snapshot is no longer available";
                } else {
                    success = serialize_pcap(*packets, filter_pid, filter_proto, bytes, count, error);
                }
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
                if (success)
                    aida::preview::network::record_receipt("PCAP export",
                        path + " " + std::to_string(count) + " packets " + std::to_string(bytes.size()) + " bytes");
#else
                if (success)
                    success = atomic_write_export(path, bytes.data(), bytes.size(), error);
#endif
                finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                    success ? std::to_string(count) + " packets written atomically to " + path : error);
                enqueue_ui_completion([success, count, path, error = std::move(error)]() {
                    {
                        std::lock_guard<std::mutex> status_lock(g_state.pcap_error_mutex);
                        g_state.pcap_last_error = success ? std::string() : error;
                        g_state.pcap_last_path = success ? path : std::string();
                    }
                    g_state.pcap_written_count.store(success ? count : 0, std::memory_order_release);
                    g_state.pcap_writing.store(false, std::memory_order_release);
                });
            }, false);
            if (!posted) {
                std::lock_guard<std::mutex> elock(state.pcap_error_mutex);
                state.pcap_last_error = "Executor rejected PCAP export";
                state.pcap_writing.store(false);
                finish_network_operation(task_id, false, "Rejected", state.pcap_last_error);
            }
        }
        if (!can_export) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Capture some packets first or set a valid output path.");
        }
    } else {
        aida::ui::pill_kind("Writing PCAP file...", aida::ui::pill_kind_t::accent,
                             aida::ui::size_t_::sm, true);
    }

    {
        std::string err_copy;
        {
            std::lock_guard<std::mutex> elock(state.pcap_error_mutex);
            err_copy = state.pcap_last_error;
        }
        if (!err_copy.empty()) {
            ImGui::Spacing();
            aida::ui::pill_kind(err_copy.c_str(), aida::ui::pill_kind_t::error,
                                 aida::ui::size_t_::sm, true);
        }
    }

    uint32_t exported_count = state.pcap_written_count.load();
    if (exported_count > 0 && !state.pcap_writing.load()) {
        std::string exported_path;
        {
            std::lock_guard<std::mutex> status_lock(state.pcap_error_mutex);
            exported_path = state.pcap_last_path;
        }
        ImGui::Spacing();
        char done_buf[640];
        snprintf(done_buf, sizeof(done_buf), "Exported %u packets to %s",
                 exported_count, exported_path.c_str());
        aida::ui::pill_kind(done_buf, aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    }


    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Export Proxy History");
    ImGui::Spacing();

    request_proxy_runtime_snapshot();
    const auto proxy_export_snapshot = std::atomic_load_explicit(
        &s_proxy_runtime_snapshot, std::memory_order_acquire);
    const std::size_t proxy_count = proxy_export_snapshot ? proxy_export_snapshot->history.size() : 0;
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Proxy exchanges available: %zu", proxy_count);

    const bool har_writing = state.har_writing.load(std::memory_order_acquire);
    if (aida::ui::button(har_writing ? "Exporting HAR...##har_export" : "Export Proxy as HAR##har_export",
                         aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 0.f), har_writing || proxy_count == 0)) {
        char har_buf[MAX_PATH] = {};
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        snprintf(har_buf, sizeof(har_buf), "%saida_proxy_export.har", temp);
        static const char k_har_save_filter[] =
            "HTTP Archive (*.har)\0*.har\0"
            "JSON (*.json)\0*.json\0"
            "All files (*.*)\0*.*\0\0";
        if (!win32_dialog::show_save_file_dialog(g_hwnd,
                "Export HAR",
                k_har_save_filter,
                "har",
                har_buf, sizeof(har_buf),
                "network_view::har_save")) {
            diag::log_tagged("network", "har_export_dialog_cancelled");
            diag::log_tagged("net_audit",
                "[net_audit] HAR export dialog cancelled");
        } else {
        const std::string har_path(har_buf);
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        aida::preview::network::record_receipt("Export HAR", har_path);
#endif
        state.har_writing.store(true, std::memory_order_release);
        state.har_written_count.store(0, std::memory_order_release);
        {
            std::lock_guard<std::mutex> status_lock(state.har_status_mutex);
            state.har_last_error.clear();
            state.har_last_path.clear();
        }
        const std::string task_id = register_network_operation(
            "network.har.export", "Export proxy history as HAR", "view.network.proxy", har_path);
        diag::log_tagged_fmt("network", "har_export_clicked path='%s' history_count=%zu",
            har_path.c_str(), proxy_count);
        diag::log_tagged("net_audit",
            (std::string("[net_audit] HAR export path='") + har_path + "' count=" +
             std::to_string(proxy_count)).c_str());
        const bool posted = post_network_task(
            "har_export", aida::infra::executor::domain_t::diagnostics, "bounded_task",
            [har_path, task_id]() {
            bool success = false;
            std::size_t count = 0;
            std::string serialized;
            std::string error;
            try {
                auto history = mitm_proxy::get_history(4096);
                count = history.size();
                success = serialize_har_bounded(history, serialized, error);
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
                if (success)
                    aida::preview::network::record_receipt("HAR export", har_path + " " +
                        std::to_string(count) + " exchanges " + std::to_string(serialized.size()) + " bytes");
#else
                if (success)
                    success = atomic_write_export(har_path,
                        reinterpret_cast<const std::uint8_t*>(serialized.data()), serialized.size(), error);
#endif
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = "HAR export failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(count) + " exchanges written atomically to " + har_path : error);
            enqueue_ui_completion([success, count, har_path, error = std::move(error)]() {
                {
                    std::lock_guard<std::mutex> status_lock(g_state.har_status_mutex);
                    g_state.har_last_error = success ? std::string() : error;
                    g_state.har_last_path = success ? har_path : std::string();
                }
                g_state.har_written_count.store(success ? static_cast<std::uint32_t>(count) : 0,
                                                std::memory_order_release);
                g_state.har_writing.store(false, std::memory_order_release);
            });
        }, false);
        if (!posted) {
            state.har_writing.store(false, std::memory_order_release);
            {
                std::lock_guard<std::mutex> status_lock(state.har_status_mutex);
                state.har_last_error = "Executor rejected HAR export";
            }
            finish_network_operation(task_id, false, "Rejected", "Executor rejected HAR export");
        }
        }
    }

    {
        std::string har_error;
        std::string har_path;
        {
            std::lock_guard<std::mutex> status_lock(state.har_status_mutex);
            har_error = state.har_last_error;
            har_path = state.har_last_path;
        }
        if (!har_error.empty()) {
            ImGui::Spacing();
            aida::ui::pill_kind(har_error.c_str(), aida::ui::pill_kind_t::error,
                                aida::ui::size_t_::sm, true);
        } else if (!har_path.empty() && state.har_written_count.load(std::memory_order_acquire) > 0) {
            ImGui::Spacing();
            const std::string receipt = "Exported " +
                std::to_string(state.har_written_count.load(std::memory_order_acquire)) +
                " exchanges to " + har_path;
            aida::ui::pill_kind(receipt.c_str(), aida::ui::pill_kind_t::success,
                                aida::ui::size_t_::sm, false);
        }
    }

    ImGui::EndChild();
}


static constexpr std::size_t k_fuzzer_page_size = 128;
static constexpr std::uint64_t k_fuzzer_absolute_request_limit = 1000000;
static constexpr std::size_t k_fuzzer_payload_set_limit = 64;

struct fuzzer_template_shape_t {
    std::string marker;
    std::size_t positions = 0;
    std::string error;
};

static fuzzer_template_shape_t analyze_fuzzer_template(std::string_view request) {
    fuzzer_template_shape_t shape;
    const std::string_view value_marker = "$value$";
    const std::string_view fuzz_marker = "FUZZ";
    auto count = [&](std::string_view marker) {
        std::size_t result = 0;
        std::size_t offset = 0;
        while ((offset = request.find(marker, offset)) != std::string_view::npos) {
            ++result;
            offset += marker.size();
        }
        return result;
    };
    const std::size_t values = count(value_marker);
    const std::size_t fuzzes = count(fuzz_marker);
    if (values != 0 && fuzzes != 0) {
        shape.error = "Mixed marker syntax is invalid: found " + std::to_string(values) +
            " $value$ markers and " + std::to_string(fuzzes) + " FUZZ markers.";
        return shape;
    }
    std::string residue(request);
    std::size_t complete = 0;
    while ((complete = residue.find(value_marker, complete)) != std::string::npos)
        residue.erase(complete, value_marker.size());
    std::string folded_residue = residue;
    std::transform(folded_residue.begin(), folded_residue.end(), folded_residue.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (folded_residue.find("$value") != std::string::npos ||
        folded_residue.find("value$") != std::string::npos) {
        shape.error = "Malformed injection marker: use the exact case-sensitive marker $value$ or FUZZ.";
        return shape;
    }
    shape.marker = values != 0 ? std::string(value_marker) : std::string(fuzz_marker);
    shape.positions = values != 0 ? values : fuzzes;
    if (shape.positions == 0)
        shape.error = "Add at least one $value$ or FUZZ injection marker.";
    else if (shape.positions > k_fuzzer_payload_set_limit)
        shape.error = "The request has " + std::to_string(shape.positions) +
            " injection positions; the hard limit is 64.";
    return shape;
}

static void publish_fuzzer_results_locked(state_t& state) {
    auto snapshot = std::make_shared<state_t::fuzzer_results_snapshot_t>();
    snapshot->pages.reserve(state.fuzz_result_pages.size() +
        (state.fuzz_result_pending.empty() ? 0U : 1U));
    for (const auto& page : state.fuzz_result_pages)
        snapshot->pages.push_back(page);
    if (!state.fuzz_result_pending.empty())
        snapshot->pages.push_back(std::make_shared<const state_t::fuzzer_result_page_t>(
            state_t::fuzzer_result_page_t{state.fuzz_result_pending, state.fuzz_pending_bytes}));
    snapshot->payload_catalog = state.fuzz_payload_catalog;
    snapshot->retained_count = state.fuzz_retained_count;
    snapshot->dropped_count = state.fuzz_dropped_count;
    snapshot->retained_bytes = state.fuzz_retained_bytes;
    snapshot->generation = ++state.fuzz_results_generation;
    snapshot->maximum_payload_columns = state.fuzz_maximum_payload_columns;
    snapshot->has_extracted_values = state.fuzz_has_extracted_values;
    snapshot->has_failures = state.fuzz_has_failures;
    std::atomic_store_explicit(&state.fuzz_results_snapshot,
        std::static_pointer_cast<const state_t::fuzzer_results_snapshot_t>(snapshot),
        std::memory_order_release);
}

static void clear_fuzzer_results_locked(state_t& state) {
    state.fuzz_result_pages.clear();
    state.fuzz_result_pending.clear();
    state.fuzz_retained_count = 0;
    state.fuzz_dropped_count = 0;
    state.fuzz_retained_bytes = 0;
    state.fuzz_pending_bytes = 0;
    state.fuzz_payload_catalog.reset();
    state.fuzz_maximum_payload_columns = 1;
    state.fuzz_has_extracted_values = false;
    state.fuzz_has_failures = false;
    state.fuzz_has_selection = false;
    publish_fuzzer_results_locked(state);
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static constexpr std::uint64_t k_fuzzer_retained_result_limit = 32768;
static constexpr std::uint64_t k_fuzzer_retained_byte_limit = 16ULL * 1024ULL * 1024ULL;
static constexpr std::uint64_t k_fuzzer_decoded_payload_budget = 64ULL * 1024ULL * 1024ULL;
static constexpr std::size_t k_fuzzer_match_input_limit = 1024ULL * 1024ULL;
static constexpr std::size_t k_fuzzer_extract_input_limit = 65536;

static void append_fuzzer_result(state_t& state, state_t::fuzzer_result_t result) {
    std::lock_guard<std::mutex> lock(state.fuzz_mutex);
    const std::uint64_t result_bytes = sizeof(state_t::fuzzer_result_t) +
        static_cast<std::uint64_t>(result.payload_indices.size()) * sizeof(std::uint32_t) +
        static_cast<std::uint64_t>(result.response_preview.size()) +
        static_cast<std::uint64_t>(result.extracted_value.size()) +
        static_cast<std::uint64_t>(result.error.size());
    while (!state.fuzz_result_pages.empty() &&
           (state.fuzz_retained_count >= k_fuzzer_retained_result_limit ||
            result_bytes > k_fuzzer_retained_byte_limit - state.fuzz_retained_bytes)) {
        const std::uint64_t removed = static_cast<std::uint64_t>(
            state.fuzz_result_pages.front()->rows.size());
        const std::uint64_t removed_bytes = state.fuzz_result_pages.front()->retained_bytes;
        state.fuzz_result_pages.pop_front();
        state.fuzz_retained_count -= removed;
        state.fuzz_dropped_count += removed;
        state.fuzz_retained_bytes -= removed_bytes;
    }
    if (state.fuzz_retained_count >= k_fuzzer_retained_result_limit ||
        result_bytes > k_fuzzer_retained_byte_limit - state.fuzz_retained_bytes) {
        ++state.fuzz_dropped_count;
        return;
    }
    state.fuzz_maximum_payload_columns = (std::max)(
        state.fuzz_maximum_payload_columns, result.payload_indices.size());
    state.fuzz_has_extracted_values = state.fuzz_has_extracted_values ||
        !result.extracted_value.empty();
    state.fuzz_has_failures = state.fuzz_has_failures || !result.error.empty();
    state.fuzz_result_pending.push_back(std::move(result));
    state.fuzz_pending_bytes += result_bytes;
    state.fuzz_retained_bytes += result_bytes;
    ++state.fuzz_retained_count;
    if (state.fuzz_result_pending.size() == k_fuzzer_page_size) {
        state.fuzz_result_pages.push_back(std::make_shared<const state_t::fuzzer_result_page_t>(
            state_t::fuzzer_result_page_t{
                std::move(state.fuzz_result_pending), state.fuzz_pending_bytes}));
        state.fuzz_result_pending.clear();
        state.fuzz_result_pending.reserve(k_fuzzer_page_size);
        state.fuzz_pending_bytes = 0;
    }
    if (state.fuzz_result_pending.size() == 1 ||
        state.fuzz_result_pending.size() % 32 == 0)
        publish_fuzzer_results_locked(state);
}

static void finish_fuzzer_task(state_t& state,
                               aida::ui::task_center::task_state_t task_state,
                               std::string stage,
                               std::string summary) {
    std::string task_id;
    {
        std::lock_guard<std::mutex> lock(state.fuzz_mutex);
        publish_fuzzer_results_locked(state);
        task_id = state.fuzz_task_id;
        state.fuzz_last_stage = stage;
        state.fuzz_last_error =
            task_state == aida::ui::task_center::task_state_t::failed ||
            task_state == aida::ui::task_center::task_state_t::partial
                ? summary : std::string();
    }
    const std::uint64_t total = state.fuzz_total.load(std::memory_order_acquire);
    const std::uint64_t progress = state.fuzz_progress.load(std::memory_order_acquire);
    const float fraction = total == 0 ? 0.0f : static_cast<float>(
        static_cast<double>(progress) / static_cast<double>(total));
    if (!task_id.empty())
        (void)aida::ui::task_center::update_task(
            task_id, task_state, fraction, std::move(stage), std::move(summary));
    state.fuzz_running.store(false, std::memory_order_release);
    state.fuzz_cv.notify_all();
}

static void run_fuzzer_thread(state_t& state) {
    state_t::fuzzer_entry_t cfg;
    std::string task_id;
    {
        std::lock_guard<std::mutex> lock(state.fuzz_mutex);
        cfg = state.fuzz_active_config;
        task_id = state.fuzz_task_id;
    }


    std::uint64_t decoded_payload_bytes = 0;
    auto append_payload = [&](std::vector<std::string>& values,
                              std::string value,
                              std::string& error) {
        const std::uint64_t bytes = static_cast<std::uint64_t>(value.size());
        if (bytes > k_fuzzer_decoded_payload_budget - decoded_payload_bytes) {
            error = "Decoded payload data exceeds the 64 MiB preparation budget";
            return false;
        }
        decoded_payload_bytes += bytes;
        values.push_back(std::move(value));
        return true;
    };

    auto load_set = [&](const payload_set_t& ps, std::string& error) -> std::vector<std::string> {
        std::vector<std::string> lines;
        auto push_line = [&](std::istream& is) {
            std::string line;
            while (std::getline(is, line)) {
                if (state.fuzz_cancel_requested.load(std::memory_order_acquire))
                    break;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.size() > 65535) {
                    error = "A payload exceeds the 65,535-byte request-editor limit";
                    break;
                }
                if (!line.empty() && !append_payload(lines, std::move(line), error))
                    break;
                if (lines.size() > cfg.maximum_requests) {
                    error = "Payload set exceeds the reviewed request maximum";
                    break;
                }
            }
        };
        if (ps.type == 0) {
            std::ifstream f(ps.source);
            if (!f.is_open()) error = "Unable to open payload wordlist: " + ps.source;
            else push_line(f);
        } else {
            std::istringstream ss(ps.source);
            push_line(ss);
        }
        return lines;
    };


    auto load_legacy_set = [&](std::string& error) -> std::vector<std::string> {
        payload_set_t tmp;
        tmp.type   = cfg.payload_type;
        tmp.source = cfg.payload_source;
        if (cfg.payload_type == 1) {
            std::vector<std::string> nums;
            long long start_n = 0, end_n = 100;
            if (sscanf(cfg.payload_source.c_str(), "%lld-%lld", &start_n, &end_n) < 1 ||
                end_n < start_n) {
                error = "Sequential payload range is invalid";
                return nums;
            }
            nums.reserve(static_cast<std::size_t>((std::min)(cfg.maximum_requests, 4096ULL)));
            for (long long n = start_n;;) {
                if (nums.size() >= cfg.maximum_requests) {
                    error = "Sequential payload range exceeds the reviewed request maximum";
                    nums.clear();
                    return nums;
                }
                if (!append_payload(nums, std::to_string(n), error)) {
                    nums.clear();
                    return nums;
                }
                if (n == end_n) break;
                if (n == (std::numeric_limits<long long>::max)()) {
                    error = "Sequential payload range overflowed";
                    nums.clear();
                    return nums;
                }
                ++n;
            }
            return nums;
        } else if (cfg.payload_type == 2) {
            std::string charset = cfg.payload_source.empty()
                ? "abcdefghijklmnopqrstuvwxyz0123456789" : cfg.payload_source;
            std::vector<std::string> v;
            const std::uint64_t chars = static_cast<std::uint64_t>(charset.size());
            if (chars != 0 && chars > (std::numeric_limits<std::uint64_t>::max)() / chars) {
                error = "Charset payload count overflowed";
                return v;
            }
            const std::uint64_t pairs = chars * chars;
            if (pairs > (std::numeric_limits<std::uint64_t>::max)() - chars) {
                error = "Charset payload count overflowed";
                return v;
            }
            const std::uint64_t count = chars + pairs;
            if (count > cfg.maximum_requests) {
                error = "Charset payloads exceed the reviewed request maximum";
                return v;
            }
            v.reserve(static_cast<std::size_t>(count));
            for (char c : charset)
                if (!append_payload(v, std::string(1, c), error)) return {};
            for (char a : charset)
                for (char b : charset)
                    if (!append_payload(v, std::string(1, a) + b, error)) return {};
            return v;
        }
        return load_set(tmp, error);
    };


    auto make_request_multi = [](const std::string& tmpl,
                                 const std::vector<std::string>& payloads,
                                 std::string_view marker,
                                 fuzzer_attack_mode_t mode,
                                 std::size_t active_position,
                                 std::string& result,
                                 std::string& error) {
        constexpr std::size_t maximum_request_bytes = 65535;
        result.clear();
        result.reserve((std::min)(maximum_request_bytes, tmpl.size()));
        auto append = [&](std::string_view value) {
            if (value.size() > maximum_request_bytes - result.size()) {
                error = "Expanded request exceeds the 65,535-byte request limit";
                return false;
            }
            result.append(value.data(), value.size());
            return true;
        };
        size_t pos = 0;
        size_t pi  = 0;
        while (pos < tmpl.size()) {
            size_t s = tmpl.find(marker, pos);
            if (s == std::string::npos) {
                if (!append(std::string_view(tmpl).substr(pos))) return false;
                break;
            }
            if (!append(std::string_view(tmpl).substr(pos, s - pos))) return false;
            const bool selected = mode != fuzzer_attack_mode_t::sniper || pi == active_position;
            const std::size_t payload_index = mode == fuzzer_attack_mode_t::sniper ? 0 : pi;
            if (selected && payload_index < payloads.size() &&
                !append(payloads[payload_index])) return false;
            pi++;
            pos = s + marker.size();
        }
        return true;
    };

    const std::string extract_literal(cfg.extract_literal);
    auto do_grep_extract = [&](const std::string& body) -> std::string {
        if (extract_literal.empty()) return {};
        const std::string_view bounded(body.data(),
            (std::min)(body.size(), k_fuzzer_extract_input_limit));
        if (bounded.find(extract_literal) != std::string_view::npos)
            return extract_literal;
        return {};
    };


    auto check_match = [&](int sc, std::string_view body, size_t len) -> bool {
        if (cfg.match_status > 0 && sc != cfg.match_status) return false;
        if (!cfg.match_body.empty() && body.find(cfg.match_body) == std::string::npos) return false;
        if (cfg.match_size_op != 0 && cfg.match_size < 0) return false;
        const std::size_t expected_size = static_cast<std::size_t>(cfg.match_size);
        if (cfg.match_size_op == 1 && len != expected_size) return false;
        if (cfg.match_size_op == 2 && len <= expected_size) return false;
        if (cfg.match_size_op == 3 && len >= expected_size) return false;
        return true;
    };


    using combo_t = std::vector<std::string>;
    std::vector<std::vector<std::string>> sets;
    std::string preparation_error;
    std::uint64_t total = 0;
    const fuzzer_template_shape_t template_shape = analyze_fuzzer_template(cfg.base_request);
    if (!cfg.maximum_requests_reviewed)
        preparation_error = "The maximum request count was not explicitly reviewed.";
    if (preparation_error.empty() &&
        (cfg.maximum_requests == 0 || cfg.maximum_requests > k_fuzzer_absolute_request_limit))
        preparation_error = "Reviewed request maximum is " +
            std::to_string(cfg.maximum_requests) + "; the supported range is 1 to 1,000,000.";
    if (preparation_error.empty() && cfg.payload_sets.size() > k_fuzzer_payload_set_limit)
        preparation_error = "Payload set count is " + std::to_string(cfg.payload_sets.size()) +
            "; the hard limit is 64.";
    if (extract_literal.size() > 255)
        preparation_error = "Global extraction literal exceeds 255 bytes.";
    if (preparation_error.empty() && !template_shape.error.empty())
        preparation_error = template_shape.error;
    if (preparation_error.empty() && cfg.attack_mode == fuzzer_attack_mode_t::sniper &&
        cfg.payload_sets.size() != 1)
        preparation_error = "Sniper requires exactly 1 payload set; " +
            std::to_string(cfg.payload_sets.size()) + " are configured.";
    if (preparation_error.empty() && cfg.attack_mode != fuzzer_attack_mode_t::sniper &&
        cfg.payload_sets.size() != template_shape.positions)
        preparation_error = "This mode requires exactly " +
            std::to_string(template_shape.positions) + " nonempty payload sets for " +
            std::to_string(template_shape.positions) + " injection positions; " +
            std::to_string(cfg.payload_sets.size()) + " are configured.";
    if (preparation_error.empty() && cfg.attack_mode == fuzzer_attack_mode_t::sniper &&
        (cfg.payload_type < 0 || cfg.payload_type > 2))
        preparation_error = "Sniper payload type " + std::to_string(cfg.payload_type) +
            " is invalid; supported values are 0 to 2.";
    if (preparation_error.empty() && cfg.attack_mode == fuzzer_attack_mode_t::sniper &&
        cfg.payload_type != 2 && cfg.payload_source.empty())
        preparation_error = "The Sniper payload source is empty.";
    if (preparation_error.empty() && cfg.attack_mode != fuzzer_attack_mode_t::sniper) {
        const auto empty_set = std::find_if(cfg.payload_sets.begin(), cfg.payload_sets.end(),
            [](const payload_set_t& set) { return set.source.empty(); });
        if (empty_set != cfg.payload_sets.end())
            preparation_error = "Payload set " + std::to_string(static_cast<std::size_t>(
                std::distance(cfg.payload_sets.begin(), empty_set)) + 1) +
                " has an empty source; every configured set must be nonempty.";
        const auto invalid_set = std::find_if(cfg.payload_sets.begin(), cfg.payload_sets.end(),
            [](const payload_set_t& set) { return set.type < 0 || set.type > 1; });
        if (preparation_error.empty() && invalid_set != cfg.payload_sets.end())
            preparation_error = "Payload set " + std::to_string(static_cast<std::size_t>(
                std::distance(cfg.payload_sets.begin(), invalid_set)) + 1) +
                " has an invalid source type; supported values are 0 and 1.";
    }

    if (preparation_error.empty()) switch (cfg.attack_mode) {

        case fuzzer_attack_mode_t::sniper: {
            sets.push_back(load_legacy_set(preparation_error));
            const std::uint64_t payload_count = static_cast<std::uint64_t>(sets.front().size());
            const std::uint64_t positions = static_cast<std::uint64_t>(template_shape.positions);
            if (preparation_error.empty()) {
                if (payload_count == 0)
                    preparation_error = "The Sniper payload source produced 0 nonempty payloads.";
                else if (positions != 0 && payload_count > cfg.maximum_requests / positions)
                    preparation_error = "Sniper cardinality is " + std::to_string(payload_count) +
                        " payloads x " + std::to_string(positions) +
                        " positions, which exceeds the reviewed maximum of " +
                        std::to_string(cfg.maximum_requests) + " requests.";
                else
                    total = payload_count * positions;
            }
            break;
        }

        case fuzzer_attack_mode_t::pitchfork: {
            if (cfg.payload_sets.empty()) preparation_error = "Pitchfork requires a payload set";
            sets.reserve(cfg.payload_sets.size());
            for (std::size_t set_index = 0; set_index < cfg.payload_sets.size(); ++set_index) {
                if (!preparation_error.empty()) break;
                sets.push_back(load_set(cfg.payload_sets[set_index], preparation_error));
                if (sets.back().empty() && preparation_error.empty())
                    preparation_error = "Pitchfork payload set " +
                        std::to_string(set_index + 1) + " produced 0 nonempty payloads.";
            }
            if (preparation_error.empty() && !sets.empty()) {
                for (std::size_t set_index = 1; set_index < sets.size(); ++set_index) {
                    if (sets[set_index].size() != sets.front().size()) {
                        preparation_error = "Pitchfork payload cardinality mismatch: set 1 has " +
                            std::to_string(sets.front().size()) + " nonempty payloads, but set " +
                            std::to_string(set_index + 1) + " has " +
                            std::to_string(sets[set_index].size()) + ".";
                        break;
                    }
                }
                if (preparation_error.empty())
                    total = static_cast<std::uint64_t>(sets.front().size());
            }
            break;
        }

        case fuzzer_attack_mode_t::clusterbomb: {
            if (cfg.payload_sets.empty()) preparation_error = "Clusterbomb requires a payload set";
            sets.reserve(cfg.payload_sets.size());
            for (std::size_t set_index = 0; set_index < cfg.payload_sets.size(); ++set_index) {
                if (!preparation_error.empty()) break;
                sets.push_back(load_set(cfg.payload_sets[set_index], preparation_error));
                if (sets.back().empty() && preparation_error.empty())
                    preparation_error = "Clusterbomb payload set " +
                        std::to_string(set_index + 1) + " produced 0 nonempty payloads.";
            }
            if (preparation_error.empty()) {
                total = 1;
                for (std::size_t set_index = 0; set_index < sets.size(); ++set_index) {
                    const auto& set = sets[set_index];
                    const std::uint64_t width = static_cast<std::uint64_t>(set.size());
                    if (width != 0 && total > cfg.maximum_requests / width) {
                        preparation_error = "Clusterbomb cardinality exceeds the reviewed maximum of " +
                            std::to_string(cfg.maximum_requests) + " requests at set " +
                            std::to_string(set_index + 1) + " with " +
                            std::to_string(width) + " nonempty payloads.";
                        break;
                    }
                    total *= width;
                }
            }
            break;
        }
    }

    if (state.fuzz_cancel_requested.load(std::memory_order_acquire)) {
        finish_fuzzer_task(state, aida::ui::task_center::task_state_t::cancelled,
            "Cancelled", "Cancelled while loading payload sets");
        return;
    }
    if (preparation_error.empty() && total == 0)
        preparation_error = "No payload combinations were produced";
    if (preparation_error.empty() && total > cfg.maximum_requests)
        preparation_error = "Payload combinations exceed the reviewed request maximum";
    if (!preparation_error.empty()) {
        diag::log_tagged_fmt("network", "fuzzer_prepare_failed mode=%d reason=%s",
            static_cast<int>(cfg.attack_mode), preparation_error.c_str());
        finish_fuzzer_task(state, aida::ui::task_center::task_state_t::failed,
            "Preparation failed", preparation_error);
        return;
    }

    state.fuzz_total.store(total);
    state.fuzz_progress.store(0);
    const auto payload_catalog =
        std::make_shared<const std::vector<std::vector<std::string>>>(std::move(sets));
    {
        std::lock_guard<std::mutex> lock(state.fuzz_mutex);
        state.fuzz_payload_catalog = payload_catalog;
        publish_fuzzer_results_locked(state);
    }
    const auto& retained_sets = *payload_catalog;

    if (!task_id.empty())
        (void)aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::running, 0.0f,
            "Sending reviewed requests", std::to_string(total) + " requests approved");

    struct generated_combination_t {
        combo_t payloads;
        std::vector<std::uint32_t> indices;
        std::uint32_t active_position = 0;
    };
    auto combination_at = [&](std::uint64_t index) {
        generated_combination_t result;
        result.payloads.reserve(retained_sets.size());
        result.indices.reserve(retained_sets.size());
        if (cfg.attack_mode == fuzzer_attack_mode_t::sniper) {
            const std::uint64_t positions = static_cast<std::uint64_t>(template_shape.positions);
            const std::uint64_t payload_index = index / positions;
            result.active_position = static_cast<std::uint32_t>(index % positions);
            result.payloads.push_back(retained_sets.front()[static_cast<std::size_t>(payload_index)]);
            result.indices.push_back(static_cast<std::uint32_t>(payload_index));
        } else if (cfg.attack_mode == fuzzer_attack_mode_t::pitchfork) {
            for (const auto& set : retained_sets) {
                result.payloads.push_back(set[static_cast<std::size_t>(index)]);
                result.indices.push_back(static_cast<std::uint32_t>(index));
            }
        } else {
            result.payloads.resize(retained_sets.size());
            result.indices.resize(retained_sets.size());
            for (std::size_t reverse = retained_sets.size(); reverse != 0; --reverse) {
                const std::size_t set_index = reverse - 1;
                const std::uint64_t width = static_cast<std::uint64_t>(retained_sets[set_index].size());
                const std::uint64_t payload_index = index % width;
                result.payloads[set_index] = retained_sets[set_index][static_cast<std::size_t>(payload_index)];
                result.indices[set_index] = static_cast<std::uint32_t>(payload_index);
                index /= width;
            }
        }
        return result;
    };

    std::atomic<std::uint64_t> next_index{0};
    std::atomic<std::uint64_t> matches{0};
    std::atomic<std::uint64_t> request_failures{0};
    std::atomic<std::uint64_t> last_task_update_ms{0};
    std::atomic<bool> execution_failed{false};
    std::mutex execution_error_mutex;
    std::string execution_error;
    int threads = std::min(std::max(cfg.thread_count, 1), 32);
    diag::log_tagged_fmt("network", "fuzzer_run_start host=%s:%u tls=%d mode=%d combos=%llu threads=%d",
        cfg.host.c_str(), static_cast<unsigned>(cfg.port), cfg.use_tls ? 1 : 0,
        static_cast<int>(cfg.attack_mode), static_cast<unsigned long long>(total), threads);

    auto worker = [&]() {
        while (!state.fuzz_cancel_requested.load(std::memory_order_acquire)) {
            const std::uint64_t idx = next_index.fetch_add(1, std::memory_order_acq_rel);
            if (idx >= total) break;

            generated_combination_t combo = combination_at(idx);
            std::string req_s;
            std::string request_error;
            if (!make_request_multi(cfg.base_request, combo.payloads, template_shape.marker,
                cfg.attack_mode, combo.active_position, req_s, request_error)) {
                bool expected = false;
                if (execution_failed.compare_exchange_strong(expected, true,
                    std::memory_order_acq_rel)) {
                    std::lock_guard<std::mutex> error_lock(execution_error_mutex);
                    execution_error = std::move(request_error);
                }
                state.fuzz_cancel_requested.store(true, std::memory_order_release);
                state.fuzz_cv.notify_all();
                break;
            }
            std::vector<uint8_t> raw_req(req_s.begin(), req_s.end());

            auto t0 = GetTickCount64();
            auto res = mitm_proxy::repeat_request(cfg.host, cfg.port, cfg.use_tls, raw_req);
            auto elapsed = GetTickCount64() - t0;

            state_t::fuzzer_result_t fr;
            fr.index     = idx;
            fr.payload_indices = std::move(combo.indices);
            fr.active_position = combo.active_position;
            fr.latency_ms = elapsed;

            if (res.success) {
                fr.status_code  = res.exchange.response.status_code;
                fr.response_len = res.exchange.raw_response.size();
                const std::size_t inspection_size = (std::min)(
                    res.exchange.raw_response.size(), k_fuzzer_match_input_limit);
                std::string body(res.exchange.raw_response.begin(),
                    res.exchange.raw_response.begin() + inspection_size);
                fr.response_preview = body.substr(0, (std::min)(std::size_t{200}, body.size()));
                fr.match = check_match(fr.status_code, body, fr.response_len);


                if (!extract_literal.empty()) {
                    fr.extracted_value = do_grep_extract(body);
                }
            } else {
                fr.error = res.error.empty() ? "Request failed without an error detail" : res.error;
                if (fr.error.size() > 160) fr.error.resize(160);
                request_failures.fetch_add(1, std::memory_order_acq_rel);
            }

            const bool matched = fr.match;
            if (matched)
                matches.fetch_add(1, std::memory_order_acq_rel);
            append_fuzzer_result(state, std::move(fr));
            const std::uint64_t completed = state.fuzz_progress.fetch_add(
                1, std::memory_order_acq_rel) + 1;
            const std::uint64_t now = network_now_ms();
            std::uint64_t prior = last_task_update_ms.load(std::memory_order_acquire);
            if (!task_id.empty() && (completed == total || now - prior >= 200) &&
                last_task_update_ms.compare_exchange_strong(prior, now, std::memory_order_acq_rel)) {
                const float fraction = static_cast<float>(
                    static_cast<double>(completed) / static_cast<double>(total));
                (void)aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::running, fraction,
                    "Sending reviewed requests",
                    std::to_string(completed) + " of " + std::to_string(total));
            }

            if (cfg.stop_on_match && matched) {
                state.fuzz_cancel_requested.store(true, std::memory_order_release);
                state.fuzz_cv.notify_all();
                break;
            }
            if (cfg.delay_ms > 0) {
                std::unique_lock<std::mutex> delay_lock(state.fuzz_cv_mutex);
                state.fuzz_cv.wait_for(delay_lock, std::chrono::milliseconds(cfg.delay_ms), [&state] {
                    return state.fuzz_cancel_requested.load(std::memory_order_acquire) ||
                           !state.fuzz_thread_alive.load(std::memory_order_acquire);
                });
            }
        }
    };

    auto guarded_worker = [&]() noexcept {
        try {
            worker();
        } catch (const std::exception& e) {
            bool expected = false;
            if (execution_failed.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
                std::lock_guard<std::mutex> error_lock(execution_error_mutex);
                execution_error = e.what();
            }
            state.fuzz_cancel_requested.store(true, std::memory_order_release);
            state.fuzz_cv.notify_all();
        } catch (...) {
            bool expected = false;
            if (execution_failed.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
                std::lock_guard<std::mutex> error_lock(execution_error_mutex);
                execution_error = "Unexpected fuzzer request worker failure";
            }
            state.fuzz_cancel_requested.store(true, std::memory_order_release);
            state.fuzz_cv.notify_all();
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(threads - 1));
    try {
        for (int t = 1; t < threads; ++t)
            workers.emplace_back(guarded_worker);
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "fuzzer_worker_creation_limited requested=%d created=%zu reason=%s",
            threads, workers.size() + 1, e.what());
    }
    guarded_worker();
    for (auto& thread : workers)
        if (thread.joinable()) thread.join();

    const std::uint64_t final_progress = state.fuzz_progress.load(std::memory_order_acquire);
    std::uint64_t retained_count = 0;
    std::uint64_t dropped_count = 0;
    {
        std::lock_guard<std::mutex> lk(state.fuzz_mutex);
        publish_fuzzer_results_locked(state);
        retained_count = state.fuzz_retained_count;
        dropped_count = state.fuzz_dropped_count;
    }
    const std::uint64_t match_count = matches.load(std::memory_order_acquire);
    const std::uint64_t failure_count = request_failures.load(std::memory_order_acquire);
    diag::log_tagged_fmt("network", "fuzzer_run_complete combos=%llu processed=%llu retained=%llu dropped=%llu matches=%llu failures=%llu cancelled=%d",
        static_cast<unsigned long long>(total),
        static_cast<unsigned long long>(final_progress),
        static_cast<unsigned long long>(retained_count),
        static_cast<unsigned long long>(dropped_count),
        static_cast<unsigned long long>(match_count),
        static_cast<unsigned long long>(failure_count),
        state.fuzz_cancel_requested.load(std::memory_order_acquire) ? 1 : 0);

    const bool stop_on_match = cfg.stop_on_match && match_count != 0;
    const bool failed = execution_failed.load(std::memory_order_acquire);
    const bool cancelled = state.fuzz_cancel_requested.load(std::memory_order_acquire) &&
        !stop_on_match && !failed;
    const std::string summary = std::to_string(final_progress) + " processed, " +
        std::to_string(match_count) + " matched, " + std::to_string(failure_count) + " failed, " +
        std::to_string(retained_count) + " retained" +
        (dropped_count == 0 ? std::string() :
            ", " + std::to_string(dropped_count) + " older results discarded");
    if (failed) {
        std::string failure;
        {
            std::lock_guard<std::mutex> error_lock(execution_error_mutex);
            failure = execution_error;
        }
        finish_fuzzer_task(state,
            final_progress == 0 ? aida::ui::task_center::task_state_t::failed
                                : aida::ui::task_center::task_state_t::partial,
            "Request expansion failed", failure + "; " + summary);
    } else if (!cancelled && !stop_on_match && failure_count != 0) {
        finish_fuzzer_task(state, aida::ui::task_center::task_state_t::partial,
            "Completed with request failures", summary);
    } else {
        finish_fuzzer_task(state,
            cancelled ? aida::ui::task_center::task_state_t::cancelled
                      : aida::ui::task_center::task_state_t::completed,
            cancelled ? "Cancelled after in-flight request" :
                (stop_on_match ? "Stopped on match" : "Completed"),
            summary);
    }
}
#endif

static void render_fuzzer(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_fuzzer", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Fuzzer / Intruder");
    ImGui::Spacing();

    auto& cfg = state.fuzz_config;


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Host:");
    ImGui::SameLine();
    static char fuzz_host[256] = {};
    if (cfg.host.size() < sizeof(fuzz_host)) { memcpy(fuzz_host, cfg.host.c_str(), cfg.host.size() + 1); }
    if (aida::ui::input_text("##fuzz_host", fuzz_host, sizeof(fuzz_host),
                              "target.example.com", false, ImVec2(220.f, 28.f)))
        cfg.host = fuzz_host;
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Port:");
    ImGui::SameLine();
    int fp = cfg.port;
    if (aida::ui::input_int("##fuzz_port", &fp, ImVec2(80.f, 28.f)))
        cfg.port = static_cast<uint16_t>(std::max(1, std::min(65535, fp)));
    ImGui::SameLine();
    aida::ui::toggle_switch("##fuzz_tls", &cfg.use_tls);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "TLS");

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Attack Mode:");
    ImGui::SameLine();
    int am = static_cast<int>(cfg.attack_mode);
    if (aida::ui::radio_button("Sniper##fuzz",      &am, 0)) cfg.attack_mode = fuzzer_attack_mode_t::sniper;
    ImGui::SameLine();
    if (aida::ui::radio_button("Pitchfork##fuzz",   &am, 1)) cfg.attack_mode = fuzzer_attack_mode_t::pitchfork;
    ImGui::SameLine();
    if (aida::ui::radio_button("Clusterbomb##fuzz", &am, 2)) cfg.attack_mode = fuzzer_attack_mode_t::clusterbomb;

    ImGui::Spacing();


    if (cfg.attack_mode == fuzzer_attack_mode_t::sniper) {

        const char* payload_types[] = { "Wordlist File", "Sequential Numbers", "Charset Brute" };
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Payload Type:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180.f);
        ImGui::Combo("##fuzz_pt", &cfg.payload_type, payload_types, 3);

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Payload Source:");
        ImGui::SameLine();
        static char pl_src[512] = {};
        if (cfg.payload_source.size() < sizeof(pl_src)) {
            memcpy(pl_src, cfg.payload_source.c_str(), cfg.payload_source.size() + 1);
        }
        if (aida::ui::input_text("##fuzz_src", pl_src, sizeof(pl_src), "Source...", false, ImVec2(320.f, 28.f)))
            cfg.payload_source = pl_src;
        ImGui::SameLine();
        const char* hint = cfg.payload_type == 0 ? "(path to wordlist)"
                            : cfg.payload_type == 1 ? "(start-end)" : "(charset)";
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "%s", hint);

        if (cfg.payload_sets.empty()) cfg.payload_sets.emplace_back();

    } else {

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Payload Sets");
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "(one set per exact $value$ or FUZZ marker)");
        ImGui::SameLine();
        if (aida::ui::button("+", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
            ImVec2(0.f, 0.f), cfg.payload_sets.size() >= k_fuzzer_payload_set_limit))
            cfg.payload_sets.emplace_back();
        if (cfg.payload_sets.size() >= k_fuzzer_payload_set_limit) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
                aida::ui::with_alpha(th.text_dim, alpha)),
                "64 of 64 payload sets configured");
        }
        ImGui::SameLine();
        if (aida::ui::button("-", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)
            && cfg.payload_sets.size() > 1)
            cfg.payload_sets.pop_back();

        float sets_h = std::min(h * 0.35f, 200.f);
        ImGui::BeginChild("##fuzz_sets_panel", ImVec2(w - 8.f, sets_h), true,
                          ImGuiWindowFlags_NoBackground);

        const char* set_type_items[] = { "Wordlist File", "Inline List" };

        for (int si = 0; si < static_cast<int>(cfg.payload_sets.size()); si++) {
            auto& ps = cfg.payload_sets[static_cast<size_t>(si)];
            ImGui::PushID(si);


            char set_label[32];
            snprintf(set_label, sizeof(set_label), "Set %d", si + 1);
            if (ImGui::CollapsingHeader(set_label)) {
                ImGui::Indent(12.f);

                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Name:");
                ImGui::SameLine();
                char name_buf[128] = {};
                if (ps.name.size() < sizeof(name_buf))
                    memcpy(name_buf, ps.name.c_str(), ps.name.size() + 1);
                if (aida::ui::input_text("##ps_name", name_buf, sizeof(name_buf), "Set name", false, ImVec2(180.f, 28.f)))
                    ps.name = name_buf;

                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Type:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(140.f);
                ImGui::Combo("##ps_type", &ps.type, set_type_items, 2);

                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Source:");
                ImGui::SameLine();
                char src_buf[512] = {};
                if (ps.source.size() < sizeof(src_buf))
                    memcpy(src_buf, ps.source.c_str(), ps.source.size() + 1);
                if (ps.type == 0) {
                    if (aida::ui::input_text("##ps_src", src_buf, sizeof(src_buf), "Path to file", false, ImVec2(w - 180.f, 28.f)))
                        ps.source = src_buf;
                } else {
                    ImGui::SetNextItemWidth(w - 180.f);
                    if (ImGui::InputTextMultiline("##ps_src_ml", src_buf, sizeof(src_buf),
                                                  ImVec2(w - 180.f, 60.f)))
                        ps.source = src_buf;
                }


                ImGui::Unindent(12.f);
            }

            ImGui::PopID();
        }

        ImGui::EndChild();
    }

    ImGui::Spacing();


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Threads:");
    ImGui::SameLine();
    {
        int v = cfg.thread_count;
        if (aida::ui::input_int("##fuzz_threads", &v, ImVec2(120.f, 32.f))) cfg.thread_count = v;
    }
    cfg.thread_count = std::max(1, std::min(32, cfg.thread_count));
    ImGui::SameLine(0.f, 18.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Delay (ms):");
    ImGui::SameLine();
    {
        int v = cfg.delay_ms;
        if (aida::ui::input_int("##fuzz_delay", &v, ImVec2(120.f, 32.f))) cfg.delay_ms = v;
    }
    cfg.delay_ms = std::max(0, cfg.delay_ms);

    ImGui::SameLine(0.f, 18.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Maximum requests:");
    ImGui::SameLine();
    std::uint64_t reviewed_maximum = cfg.maximum_requests;
    ImGui::SetNextItemWidth(140.f);
    if (ImGui::InputScalar("##fuzz_maximum_requests", ImGuiDataType_U64, &reviewed_maximum)) {
        cfg.maximum_requests = (std::max)(1ULL,
            (std::min)(reviewed_maximum, k_fuzzer_absolute_request_limit));
        cfg.maximum_requests_reviewed = false;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Reviewed##fuzz_maximum_reviewed", &cfg.maximum_requests_reviewed);


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Match Status:");
    ImGui::SameLine();
    {
        int v = cfg.match_status;
        if (aida::ui::input_int("##fuzz_ms", &v, ImVec2(120.f, 32.f))) cfg.match_status = v;
    }
    ImGui::SameLine(0.f, 10.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "(0=any)");
    ImGui::SameLine(0.f, 18.f);
    aida::ui::toggle_switch("##fuzz_stop_match", &cfg.stop_on_match);
    ImGui::SameLine(0.f, 10.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Stop on match");

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Request Template");
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Exact injection marker: $value$ or FUZZ (case-sensitive; do not mix)");
    ImGui::Spacing();

    float tmpl_h = std::min(h * 0.22f, 180.f);
    static human_request_editor::state_t request_editor;
    human_request_editor::render_config_t request_config;
    request_config.stable_id = "network-fuzzer-template";
    request_config.size = ImVec2(w - 8.f, tmpl_h);
    request_config.max_bytes = 65535;
    request_config.editable = !state.fuzz_running.load(std::memory_order_acquire);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    request_config.semantic_parent_id = "aida.dock-window.view.network.fuzzer";
#endif
    const auto request_editor_result = human_request_editor::render(
        request_editor,
        "network.fuzzer.request-template." + std::to_string(state.fuzz_request_revision),
        cfg.base_request,
        request_config);

    ImGui::Spacing();


    if (!state.fuzz_running.load()) {
        const fuzzer_template_shape_t template_shape = analyze_fuzzer_template(cfg.base_request);
        std::string start_unavailable_reason;
        if (cfg.host.empty() || cfg.port == 0)
            start_unavailable_reason = "Set a valid target host and port.";
        else if (cfg.base_request.empty() || !request_editor_result.valid ||
            request_editor_result.has_unapplied_pretty)
            start_unavailable_reason = "Apply a valid raw request template before starting.";
        else if (!template_shape.error.empty())
            start_unavailable_reason = template_shape.error;
        else if (cfg.payload_sets.empty() || cfg.payload_sets.size() > k_fuzzer_payload_set_limit)
            start_unavailable_reason = "Configure 1 to 64 payload sets; " +
                std::to_string(cfg.payload_sets.size()) + " are configured.";
        else if (cfg.attack_mode == fuzzer_attack_mode_t::sniper && cfg.payload_sets.size() != 1)
            start_unavailable_reason = "Sniper requires exactly 1 payload set; " +
                std::to_string(cfg.payload_sets.size()) + " are configured.";
        else if (cfg.attack_mode != fuzzer_attack_mode_t::sniper &&
            cfg.payload_sets.size() != template_shape.positions)
            start_unavailable_reason = "This mode requires exactly " +
                std::to_string(template_shape.positions) + " payload sets for " +
                std::to_string(template_shape.positions) + " injection positions; " +
                std::to_string(cfg.payload_sets.size()) + " are configured.";
        else if (cfg.attack_mode == fuzzer_attack_mode_t::sniper &&
            cfg.payload_type != 2 && cfg.payload_source.empty())
            start_unavailable_reason = "Configure a nonempty Sniper payload source.";
        else if (cfg.attack_mode != fuzzer_attack_mode_t::sniper &&
            std::any_of(cfg.payload_sets.begin(), cfg.payload_sets.end(),
                [](const payload_set_t& set) { return set.source.empty(); }))
            start_unavailable_reason = "Every configured payload set requires a nonempty source; set " +
                std::to_string(static_cast<std::size_t>(std::distance(
                    cfg.payload_sets.begin(), std::find_if(cfg.payload_sets.begin(), cfg.payload_sets.end(),
                        [](const payload_set_t& set) { return set.source.empty(); }))) + 1) +
                " is empty.";
        else if (cfg.maximum_requests == 0 ||
            cfg.maximum_requests > k_fuzzer_absolute_request_limit ||
            !cfg.maximum_requests_reviewed)
            start_unavailable_reason = "Review a maximum request count between 1 and 1,000,000.";
        bool fuzz_can_start = !cfg.host.empty() && cfg.port > 0 &&
            start_unavailable_reason.empty();
#ifndef AIDA_IMGUI_STUDIO_PREVIEW
        const bool fuzz_worker_available =
            state.fuzz_thread_alive.load(std::memory_order_acquire) &&
            !state.fuzz_thread_done.load(std::memory_order_acquire);
        const char* fuzz_worker_unavailable_reason = "Network fuzzer worker is unavailable.";
#else
        const bool fuzz_worker_available = false;
        const char* fuzz_worker_unavailable_reason =
            "Live execution requires the native network authority.";
#endif
        fuzz_can_start = fuzz_can_start && fuzz_worker_available;
        if (aida::ui::button("Start Fuzzer", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), !fuzz_can_start)) {
            const std::uint64_t generation = state.fuzz_run_generation.fetch_add(
                1, std::memory_order_acq_rel) + 1;
            const std::string task_id = "network.fuzzer." + std::to_string(generation);
            {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                clear_fuzzer_results_locked(state);
                state.fuzz_active_config = cfg;
                state.fuzz_task_id = task_id;
                state.fuzz_last_stage = "Loading payload sets";
                state.fuzz_last_error.clear();
            }
            state.fuzz_progress.store(0);
            state.fuzz_total.store(0);
            state.fuzz_cancel_requested.store(false, std::memory_order_release);
            aida::ui::task_center::task_registration_t registration;
            registration.id = task_id;
            registration.source = "human";
            registration.owner = "network";
            registration.owner_view = "view.network.fuzzer";
            registration.owner_action = "network.fuzzer.start";
            registration.target = cfg.host + ":" + std::to_string(cfg.port);
            registration.label = "Network fuzzer";
            registration.stage = "Loading payload sets";
            registration.started_ms = network_now_ms();
            registration.progress = 0.0f;
            registration.cancellation_is_safe = true;
            registration.callbacks.cancel = [generation] {
                if (g_state.fuzz_run_generation.load(std::memory_order_acquire) != generation)
                    return false;
                g_state.fuzz_cancel_requested.store(true, std::memory_order_release);
                g_state.fuzz_cv.notify_all();
                return true;
            };
            registration.callbacks.focus = [] {
                (void)aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("view.network.fuzzer"));
            };
            const bool registered = aida::ui::task_center::register_task(std::move(registration));
            diag::log_tagged_fmt("network", "fuzzer_start_clicked host=%s:%u tls=%d mode=%d threads=%d delay_ms=%d match_status=%d stop_on_match=%d sets=%zu",
                cfg.host.c_str(), cfg.port, cfg.use_tls ? 1 : 0,
                static_cast<int>(cfg.attack_mode), cfg.thread_count, cfg.delay_ms,
                cfg.match_status, cfg.stop_on_match ? 1 : 0, cfg.payload_sets.size());
            {
                char buf[256];
                snprintf(buf, sizeof(buf),
                    "[net_audit] fuzzer start host=%s:%u tls=%d mode=%d threads=%d sets=%zu",
                    cfg.host.c_str(), static_cast<unsigned>(cfg.port), cfg.use_tls ? 1 : 0,
                    static_cast<int>(cfg.attack_mode), cfg.thread_count, cfg.payload_sets.size());
                diag::log_tagged("net_audit", buf);
            }
            if (registered) {
                state.fuzz_running.store(true, std::memory_order_release);
                state.fuzz_cv.notify_one();
            } else {
                std::lock_guard<std::mutex> lock(state.fuzz_mutex);
                state.fuzz_task_id.clear();
                state.fuzz_last_stage = "Start rejected";
                state.fuzz_last_error = "Task Center rejected the fuzzer operation before execution";
            }
        }
        if (!fuzz_can_start) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "%s", !fuzz_worker_available
                    ? fuzz_worker_unavailable_reason
                    : start_unavailable_reason.c_str());
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear Results", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            std::lock_guard<std::mutex> lk(state.fuzz_mutex);
            const std::uint64_t previous = state.fuzz_retained_count;
            clear_fuzzer_results_locked(state);
            diag::log_tagged_fmt("network", "fuzzer_results_cleared prev=%llu",
                static_cast<unsigned long long>(previous));
        }
    } else {
        const std::uint64_t prog = state.fuzz_progress.load();
        const std::uint64_t tot = state.fuzz_total.load();
        {
            static float fuzz_spin_time = 0.f;
            fuzz_spin_time += ImGui::GetIO().DeltaTime;
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 spos = ImGui::GetCursorScreenPos();
            ui_anim::render_spinner(sdl, spos.x + 8.f, spos.y + 8.f, 6.f, 2.f,
                                    aida::ui::with_alpha(th.accent_u32, alpha), fuzz_spin_time);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 22.f);
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Running: %llu / %llu",
                           static_cast<unsigned long long>(prog),
                           static_cast<unsigned long long>(tot));
        float frac = tot > 0 ? static_cast<float>(
            static_cast<double>(prog) / static_cast<double>(tot)) : 0.f;
        ImVec2 pb_pos = ImGui::GetCursorScreenPos();
        aida::ui::render_progress_bar(pb_pos, 320.f, 8.f, frac, false, true);
        ImGui::Dummy(ImVec2(320.f, 12.f));
        ImGui::SameLine();
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "fuzzer_stop_clicked progress=%llu total=%llu",
                static_cast<unsigned long long>(prog),
                static_cast<unsigned long long>(tot));
            std::string task_id;
            {
                std::lock_guard<std::mutex> lock(state.fuzz_mutex);
                task_id = state.fuzz_task_id;
            }
            if (task_id.empty() || !aida::ui::task_center::request_cancel(task_id)) {
                state.fuzz_cancel_requested.store(true, std::memory_order_release);
                state.fuzz_cv.notify_all();
            }
        }
    }

    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Global extract literal (first 64 KiB of response):");
    ImGui::SameLine();
    aida::ui::input_text("##fuzz_extract_literal", cfg.extract_literal,
        sizeof(cfg.extract_literal), "bounded literal match (optional)", false,
        ImVec2(320.f, 28.f));

    ImGui::Spacing();

    std::string last_stage;
    std::string last_error;
    {
        std::lock_guard<std::mutex> lock(state.fuzz_mutex);
        last_stage = state.fuzz_last_stage;
        last_error = state.fuzz_last_error;
    }
    if (!last_error.empty()) {
        aida::ui::pill_kind(last_error.c_str(), aida::ui::pill_kind_t::error,
                            aida::ui::size_t_::sm, false);
    } else if (!last_stage.empty() && !state.fuzz_running.load(std::memory_order_acquire)) {
        aida::ui::pill_kind(last_stage.c_str(), aida::ui::pill_kind_t::neutral,
                            aida::ui::size_t_::sm, false);
    }

    ImGui::Spacing();


    const auto results_snapshot = std::atomic_load_explicit(
        &state.fuzz_results_snapshot, std::memory_order_acquire);
    const std::uint64_t retained_count = results_snapshot
        ? results_snapshot->retained_count : 0;
    const std::uint64_t dropped_count = results_snapshot
        ? results_snapshot->dropped_count : 0;
    const std::size_t max_cols = results_snapshot
        ? results_snapshot->maximum_payload_columns : 1;
    const bool show_extract = results_snapshot && results_snapshot->has_extracted_values;
    const bool show_failures = results_snapshot && results_snapshot->has_failures;

    if (dropped_count == 0) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Results: %llu", static_cast<unsigned long long>(retained_count));
    } else {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Results: %llu retained (%llu older discarded)",
                           static_cast<unsigned long long>(retained_count),
                           static_cast<unsigned long long>(dropped_count));
    }

    const float c_idx = 72.f;
    const float c_payload = 160.f;
    const float c_status = 72.f;
    const float c_len = 88.f;
    const float c_time = 88.f;
    const float c_match = 64.f;
    const float c_extract = show_extract ? 160.f : 0.f;
    const float c_error = show_failures ? 220.f : 0.f;
    const float table_width = 24.f + c_idx +
        c_payload * static_cast<float>((std::max)(std::size_t{1}, max_cols)) +
        c_status + c_len + c_time + c_match + c_extract + c_error;
    float results_h = h - ImGui::GetCursorPosY() + y - 8.f;
    ImGui::SetNextWindowContentSize(ImVec2(table_width, 0.f));
    ImGui::BeginChild("##fuzz_results", ImVec2(w - 4.f, results_h), false,
                      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_HorizontalScrollbar);

    ImDrawList* dl   = ImGui::GetWindowDrawList();
    ImVec2 list_org  = ImGui::GetWindowPos();
    float row_h      = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    const float table_left = list_org.x - ImGui::GetScrollX();


    float cy  = list_org.y + ImGui::GetCursorPosY();
    float cx0 = table_left + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);

    dl->AddRectFilled(ImVec2(table_left, cy - 4.f),
                      ImVec2(table_left + table_width, cy + row_h - 4.f),
                      aida::ui::with_alpha(th.panel_header, alpha));

    {
        float cx = cx0;
        char hbuf[32];
        float hdr_ty = cy - 4.f + (row_h - ImGui::GetTextLineHeight()) * 0.5f;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "#"); cx += c_idx;
        for (size_t pi = 0; pi < max_cols; pi++) {
            snprintf(hbuf, sizeof(hbuf), "Payload %zu", pi + 1);
            dl->AddText(ImVec2(cx, hdr_ty), hdr_col, hbuf); cx += c_payload;
        }
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Status");  cx += c_status;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Length");  cx += c_len;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Time");    cx += c_time;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Match");   cx += c_match;
        if (show_extract) {
            dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Extracted");
            cx += c_extract;
        }
        if (show_failures) dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Error");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);
    }

    ImGuiListClipper result_clipper;
    result_clipper.Begin(static_cast<int>((std::min)(retained_count,
        static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))), row_h);
    while (result_clipper.Step()) {
        for (int display_index = result_clipper.DisplayStart;
             display_index < result_clipper.DisplayEnd; ++display_index) {
            const std::size_t page_index = static_cast<std::size_t>(display_index) / k_fuzzer_page_size;
            const std::size_t row_index = static_cast<std::size_t>(display_index) % k_fuzzer_page_size;
            if (!results_snapshot || page_index >= results_snapshot->pages.size() ||
                !results_snapshot->pages[page_index] ||
                row_index >= results_snapshot->pages[page_index]->rows.size())
                continue;
            const auto& fr = results_snapshot->pages[page_index]->rows[row_index];
            float ry     = ImGui::GetCursorPosY();
            float abs_ry = ImGui::GetCursorScreenPos().y;
            bool is_sel = state.fuzz_has_selection && state.fuzz_selected == fr.index;

            if (fr.match) {
                dl->AddRectFilled(ImVec2(table_left, abs_ry),
                              ImVec2(table_left + table_width, abs_ry + row_h),
                              aida::ui::with_alpha(th.success_soft, alpha * 4.f));
                dl->AddRectFilled(ImVec2(table_left, abs_ry), ImVec2(table_left + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.success, alpha));
            } else if (is_sel) {
                dl->AddRectFilled(ImVec2(table_left, abs_ry),
                              ImVec2(table_left + table_width, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha));
            }

            ImVec2 mouse = ImGui::GetMousePos();
            if (mouse.x >= table_left && mouse.x < table_left + table_width &&
                mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0)) {
                state.fuzz_selected = fr.index;
                state.fuzz_has_selection = true;
            }

        ImU32 txt_col = aida::ui::with_alpha(is_sel ? th.text_primary : th.text_secondary, alpha);
        float cx = cx0;
        char buf[64];

        snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(fr.index));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_idx;


        for (size_t pi = 0; pi < max_cols; pi++) {
            std::string pl;
            if (results_snapshot->payload_catalog &&
                pi < fr.payload_indices.size() &&
                pi < results_snapshot->payload_catalog->size() &&
                fr.payload_indices[pi] < (*results_snapshot->payload_catalog)[pi].size()) {
                const auto& payload = (*results_snapshot->payload_catalog)[pi][fr.payload_indices[pi]];
                pl = payload.size() > 28 ? payload.substr(0, 28) + ".." : payload;
            }
            dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, pl.c_str()); cx += c_payload;
        }


        ImU32 sc_col = aida::ui::with_alpha(fr.error.empty()
            ? status_code_color(fr.status_code) : th.error, alpha);
        if (fr.error.empty()) snprintf(buf, sizeof(buf), "%d", fr.status_code);
        else snprintf(buf, sizeof(buf), "ERR");
        dl->AddText(ImVec2(cx, abs_ry + text_oy), sc_col, buf); cx += c_status;

        snprintf(buf, sizeof(buf), "%zu", fr.response_len);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_len;

        snprintf(buf, sizeof(buf), "%llums",
                 static_cast<unsigned long long>(fr.latency_ms));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_time;

        if (fr.match)
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                         aida::ui::with_alpha(th.success, alpha), "YES");
        cx += c_match;

        if (show_extract && !fr.extracted_value.empty()) {
            std::string ev = fr.extracted_value.size() > 20
                ? fr.extracted_value.substr(0, 20) + ".." : fr.extracted_value;
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                         aida::ui::with_alpha(th.warning, alpha), ev.c_str());
        }
        if (show_extract) cx += c_extract;
        if (show_failures && !fr.error.empty()) {
            std::string error = fr.error.size() > 32
                ? fr.error.substr(0, 32) + ".." : fr.error;
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                         aida::ui::with_alpha(th.error, alpha), error.c_str());
        }

        ImGui::SetCursorPosY(ry + row_h);
        }
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

enum class offensive_workflow_kind_t : int {
    sqli_detect,
    sqli_fingerprint,
    xss_detect,
    xss_dom,
    auth_bruteforce,
    auth_idor,
    server_ssrf,
    server_ssti,
    server_cmdi,
    server_traversal,
    server_xxe,
    server_smuggle,
    api_param_fuzz,
    api_authz_matrix,
    client_cors,
    client_csrf,
    client_postmessage,
    business_race,
    fuzz_start,
    fuzz_mutate,
    js_secrets,
    js_endpoints,
    recon_fingerprint,
    recon_waf
};

struct offensive_workflow_t {
    const char* label;
    offensive_workflow_kind_t kind;
};

static const offensive_workflow_t k_offensive_workflows[] = {
    { "SQLi Detect", offensive_workflow_kind_t::sqli_detect },
    { "SQLi Fingerprint", offensive_workflow_kind_t::sqli_fingerprint },
    { "XSS Detect", offensive_workflow_kind_t::xss_detect },
    { "XSS DOM", offensive_workflow_kind_t::xss_dom },
    { "Auth Brute Force", offensive_workflow_kind_t::auth_bruteforce },
    { "Auth IDOR", offensive_workflow_kind_t::auth_idor },
    { "SSRF", offensive_workflow_kind_t::server_ssrf },
    { "SSTI", offensive_workflow_kind_t::server_ssti },
    { "CMDi", offensive_workflow_kind_t::server_cmdi },
    { "Path Traversal", offensive_workflow_kind_t::server_traversal },
    { "XXE", offensive_workflow_kind_t::server_xxe },
    { "Request Smuggling", offensive_workflow_kind_t::server_smuggle },
    { "API Param Fuzz", offensive_workflow_kind_t::api_param_fuzz },
    { "API Auth Matrix", offensive_workflow_kind_t::api_authz_matrix },
    { "Client CORS", offensive_workflow_kind_t::client_cors },
    { "Client CSRF", offensive_workflow_kind_t::client_csrf },
    { "Client PostMessage", offensive_workflow_kind_t::client_postmessage },
    { "Business Race", offensive_workflow_kind_t::business_race },
    { "Fuzz Start", offensive_workflow_kind_t::fuzz_start },
    { "Fuzz Mutate", offensive_workflow_kind_t::fuzz_mutate },
    { "JS Secrets", offensive_workflow_kind_t::js_secrets },
    { "JS Endpoints", offensive_workflow_kind_t::js_endpoints },
    { "Recon Fingerprint", offensive_workflow_kind_t::recon_fingerprint },
    { "Recon WAF", offensive_workflow_kind_t::recon_waf }
};

struct offensive_run_result_t {
    bool success = false;
    std::string message;
    std::string code;
    json data = json::object();
};

static int offensive_workflow_count() {
    return static_cast<int>(sizeof(k_offensive_workflows) / sizeof(k_offensive_workflows[0]));
}

static int clamp_offensive_workflow_index(int idx) {
    return std::max(0, std::min(idx, offensive_workflow_count() - 1));
}

static const offensive_workflow_t& offensive_workflow_at(int idx) {
    return k_offensive_workflows[clamp_offensive_workflow_index(idx)];
}

static std::string lower_ascii_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool offensive_sensitive_key(const std::string& key) {
    const std::string k = lower_ascii_copy(key);
    return k.find("password") != std::string::npos ||
           k.find("passwd") != std::string::npos ||
           k.find("pwd") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("secret") != std::string::npos ||
           k.find("cookie") != std::string::npos ||
           k.find("authorization") != std::string::npos ||
           k.find("api_key") != std::string::npos ||
           k.find("apikey") != std::string::npos ||
           k.find("private_key") != std::string::npos ||
           k.find("session") != std::string::npos ||
           k.find("credential") != std::string::npos ||
           k.find("bearer") != std::string::npos ||
           k == "jwt";
}

static json offensive_redact_json(const json& src) {
    if (src.is_object()) {
        json out = json::object();
        std::string named_value_key;
        if (src.contains("name") && src["name"].is_string())
            named_value_key = src["name"].get<std::string>();
        for (auto it = src.begin(); it != src.end(); ++it) {
            if (offensive_sensitive_key(it.key()) || (it.key() == "value" && offensive_sensitive_key(named_value_key)))
                out[it.key()] = "[redacted]";
            else
                out[it.key()] = offensive_redact_json(it.value());
        }
        return out;
    }
    if (src.is_array()) {
        json out = json::array();
        for (const auto& item : src)
            out.push_back(offensive_redact_json(item));
        return out;
    }
    return src;
}

static bool offensive_parse_json_object(const char* text, json& out, std::string& err) {
    std::string raw = text ? std::string(text) : std::string();
    if (raw.empty()) {
        out = json::object();
        return true;
    }
    bool all_space = true;
    for (char c : raw) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            all_space = false;
            break;
        }
    }
    if (all_space) {
        out = json::object();
        return true;
    }
    json parsed = json::parse(raw, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        err = "Payload JSON must be an object";
        return false;
    }
    out = std::move(parsed);
    return true;
}

static void offensive_apply_base_payload(state_t& state, json& payload) {
    const int timeout_ms = std::max(1000, std::min(state.off_timeout_ms, 120000));
    const int max_payloads = std::max(1, std::min(state.off_max_payloads, 256));
    const int max_requests = std::max(1, std::min(state.off_max_requests, 1000));
    state.off_timeout_ms = timeout_ms;
    state.off_max_payloads = max_payloads;
    state.off_max_requests = max_requests;
    if (state.off_target_url[0] != '\0') {
        payload["url"] = state.off_target_url;
        if (!payload.contains("base_url"))
            payload["base_url"] = state.off_target_url;
    }
    if (state.off_target_param[0] != '\0') {
        payload["param"] = state.off_target_param;
        payload["param_target"] = state.off_target_param;
        payload["param_name"] = state.off_target_param;
    }
    if (state.off_raw_request[0] != '\0' && !payload.contains("raw_request"))
        payload["raw_request"] = state.off_raw_request;
    payload["scope_only"] = state.off_scope_only;
    payload["enforce_scope"] = state.off_scope_only;
    payload["timeout_ms"] = timeout_ms;
    payload["max_payloads"] = max_payloads;
    payload["max_requests"] = max_requests;
    if (!payload.contains("max_attempts"))
        payload["max_attempts"] = max_requests;
    if (!payload.contains("request_count"))
        payload["request_count"] = max_requests;
    if (!payload.contains("max_params"))
        payload["max_params"] = max_payloads;
    if (!payload.contains("max_variants"))
        payload["max_variants"] = max_payloads;
    if (!payload.contains("max_payloads_per_set"))
        payload["max_payloads_per_set"] = max_payloads;
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
static bool offensive_json_bool(const json& obj, const char* primary, const char* secondary, bool fallback) {
    if (obj.is_object() && obj.contains(primary) && obj[primary].is_boolean())
        return obj[primary].get<bool>();
    if (obj.is_object() && obj.contains(secondary) && obj[secondary].is_boolean())
        return obj[secondary].get<bool>();
    return fallback;
}

static offensive_run_result_t offensive_from_tool_result(const mcp_standalone::tool_result_t& tr) {
    offensive_run_result_t out;
    out.success = tr.success;
    out.message = tr.text;
    out.code = tr.error_code;
    if (!tr.data.is_null() && !(tr.data.is_object() && tr.data.empty()))
        out.data = tr.data;
    else if (!tr.error_details.is_null() && !(tr.error_details.is_object() && tr.error_details.empty()))
        out.data = tr.error_details;
    else
        out.data = json{{"text", tr.text}};
    return out;
}

static offensive_run_result_t offensive_from_json_result(const json& result, const std::string& fallback_message) {
    offensive_run_result_t out;
    out.data = result;
    out.success = offensive_json_bool(result, "ok", "success", true);
    out.message = result.is_object() && result.contains("message") && result["message"].is_string()
        ? result["message"].get<std::string>() : fallback_message;
    out.code = result.is_object() && result.contains("error_code") && result["error_code"].is_string()
        ? result["error_code"].get<std::string>() : std::string();
    if (out.code.empty() && result.is_object() && result.contains("code") && result["code"].is_string())
        out.code = result["code"].get<std::string>();
    return out;
}

static offensive_run_result_t offensive_from_auth_result(const aida::burp::offensive::auth_attack::result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.error_code, r.data};
}

static offensive_run_result_t offensive_from_business_result(const aida::burp::offensive::business_logic::result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.error_code, r.data};
}

static offensive_run_result_t offensive_from_server_result(const aida::burp::offensive::server_attack::action_result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.code, r.data};
}

static offensive_run_result_t offensive_from_sqli_result(const aida::burp::offensive::sqli::engine_result_t& r) {
    return offensive_run_result_t{r.ok, r.message, r.code, r.data};
}

static offensive_run_result_t offensive_from_xss_result(const aida::burp::offensive::xss::engine_result_t& r) {
    return offensive_run_result_t{r.ok, r.message, r.code, r.data};
}
#endif

static offensive_run_result_t offensive_dispatch(const offensive_workflow_t& workflow, json payload) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    json data = {
        {"workflow", workflow.label},
        {"target", payload.value("url", payload.value("target_url", std::string("preview target")))},
        {"requests", 12},
        {"findings", json::array({
            {{"severity", "high"}, {"title", "Authorization boundary bypass"}, {"confidence", 0.94}},
            {{"severity", "medium"}, {"title", "Response behavior differs across roles"}, {"confidence", 0.81}}
        })},
        {"receipt", "Studio preview executed the deterministic workflow fixture"}
    };
    aida::preview::network::record_receipt("Offensive workflow", workflow.label);
    return offensive_run_result_t{true, "Deterministic preview workflow completed", std::string(), std::move(data)};
#else
    using namespace aida::burp::offensive;
    switch (workflow.kind) {
        case offensive_workflow_kind_t::sqli_detect:
            return offensive_from_sqli_result(sqli::detect(payload));
        case offensive_workflow_kind_t::sqli_fingerprint:
            return offensive_from_sqli_result(sqli::fingerprint_db(payload));
        case offensive_workflow_kind_t::xss_detect:
            return offensive_from_xss_result(xss::detect(payload));
        case offensive_workflow_kind_t::xss_dom:
            return offensive_from_xss_result(xss::dom_analyze(payload));
        case offensive_workflow_kind_t::auth_bruteforce:
            return offensive_from_auth_result(auth_attack::handle_action("brute_force", payload));
        case offensive_workflow_kind_t::auth_idor:
            return offensive_from_auth_result(auth_attack::handle_action("idor_test", payload));
        case offensive_workflow_kind_t::server_ssrf:
            return offensive_from_server_result(server_attack::handle_action("ssrf_exploit", payload));
        case offensive_workflow_kind_t::server_ssti:
            return offensive_from_server_result(server_attack::handle_action("ssti_exploit", payload));
        case offensive_workflow_kind_t::server_cmdi:
            return offensive_from_server_result(server_attack::handle_action("cmdi_exploit", payload));
        case offensive_workflow_kind_t::server_traversal:
            return offensive_from_server_result(server_attack::handle_action("path_traversal_exploit", payload));
        case offensive_workflow_kind_t::server_xxe:
            return offensive_from_server_result(server_attack::handle_action("xxe_exploit", payload));
        case offensive_workflow_kind_t::server_smuggle:
            return offensive_from_server_result(server_attack::handle_action("smuggle_exploit", payload));
        case offensive_workflow_kind_t::api_param_fuzz:
            return offensive_from_tool_result(api_security::param_fuzz(payload));
        case offensive_workflow_kind_t::api_authz_matrix:
            return offensive_from_tool_result(api_security::authz_matrix(payload));
        case offensive_workflow_kind_t::client_cors:
            return offensive_from_tool_result(client_attack::cors_exploit(payload));
        case offensive_workflow_kind_t::client_csrf:
            return offensive_from_tool_result(client_attack::csrf_test(payload));
        case offensive_workflow_kind_t::client_postmessage:
            return offensive_from_tool_result(client_attack::postmessage_scan(payload));
        case offensive_workflow_kind_t::business_race:
            return offensive_from_business_result(business_logic::handle_action("race_test", payload));
        case offensive_workflow_kind_t::fuzz_start:
            return offensive_from_tool_result(fuzzing::start(payload));
        case offensive_workflow_kind_t::fuzz_mutate:
            return offensive_from_tool_result(fuzzing::mutate(payload));
        case offensive_workflow_kind_t::js_secrets:
            return offensive_from_json_result(js_analysis::extract_secrets(payload), "JavaScript secret extraction completed");
        case offensive_workflow_kind_t::js_endpoints:
            return offensive_from_json_result(js_analysis::extract_endpoints(payload), "JavaScript endpoint extraction completed");
        case offensive_workflow_kind_t::recon_fingerprint:
            return offensive_from_json_result(recon::fingerprint(payload), "Recon fingerprint completed");
        case offensive_workflow_kind_t::recon_waf:
            return offensive_from_json_result(recon::waf_detect(payload), "Recon WAF detection completed");
    }
    return offensive_run_result_t{false, "Unsupported offensive workflow", "unsupported_workflow", json::object()};
#endif
}

static void collect_offensive_issue_ids(const json& node, std::vector<uint64_t>& ids) {
    if (node.is_object()) {
        for (auto it = node.begin(); it != node.end(); ++it) {
            const std::string key = lower_ascii_copy(it.key());
            if ((key == "issue_id" || key == "issue" || key == "id") && it.value().is_number_unsigned()) {
                const uint64_t id = it.value().get<uint64_t>();
                if (id != 0 && std::find(ids.begin(), ids.end(), id) == ids.end())
                    ids.push_back(id);
            }
            collect_offensive_issue_ids(it.value(), ids);
        }
    } else if (node.is_array()) {
        for (const auto& item : node)
            collect_offensive_issue_ids(item, ids);
    }
}

static void render_offensive_issue_links(state_t& state, const std::string& result, float alpha) {
    json parsed = json::parse(result, nullptr, false);
    if (parsed.is_discarded())
        return;
    std::vector<uint64_t> ids;
    collect_offensive_issue_ids(parsed, ids);
    if (ids.empty())
        return;
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Issues:");
    ImGui::SameLine();
    for (size_t i = 0; i < ids.size() && i < 8; ++i) {
        if (i > 0) ImGui::SameLine();
        char label[48];
        snprintf(label, sizeof(label), "#%llu##off_issue_%zu", static_cast<unsigned long long>(ids[i]), i);
        if (aida::ui::button(label, aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
            state.active_tab = sub_tab_t::scanner;
    }
}

static bool start_offensive_workflow(state_t& state, const offensive_workflow_t& workflow) {
    json payload;
    std::string err;
    if (!offensive_parse_json_object(state.off_payload_json, payload, err)) {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = err;
        state.off_result = json{{"success", false}, {"error", err}}.dump(2);
        return false;
    }
    offensive_apply_base_payload(state, payload);
    const uint64_t run_id = state.off_run_id.fetch_add(1, std::memory_order_acq_rel) + 1;
    state.off_running.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = std::string("Running ") + workflow.label;
        state.off_result.clear();
    }
    const int workflow_index = clamp_offensive_workflow_index(state.off_workflow);
    const bool posted = post_network_task("offensive_workflow", aida::infra::executor::domain_t::long_running, "long_running", [payload = std::move(payload), workflow_index, run_id]() mutable {
        const offensive_workflow_t workflow_copy = offensive_workflow_at(workflow_index);
        offensive_run_result_t result;
        const uint64_t begin = static_cast<uint64_t>(GetTickCount64());
        try {
            result = offensive_dispatch(workflow_copy, std::move(payload));
        } catch (const std::exception& e) {
            result.success = false;
            result.message = "Offensive workflow failed";
            result.code = "exception";
            result.data = json{{"exception_len", std::string(e.what()).size()}};
        } catch (...) {
            result.success = false;
            result.message = "Offensive workflow failed";
            result.code = "unknown_exception";
            result.data = json::object();
        }
        const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - begin;
        json out;
        out["run_id"] = run_id;
        out["workflow"] = workflow_copy.label;
        out["success"] = result.success;
        out["message"] = result.message;
        out["code"] = result.code;
        out["elapsed_ms"] = elapsed_ms;
        out["data"] = offensive_redact_json(result.data);
        if (workflow_copy.kind == offensive_workflow_kind_t::fuzz_start && result.success && result.data.is_object()) {
            uint64_t job_id = 0;
            if (result.data.contains("job_id") && result.data["job_id"].is_number_unsigned())
                job_id = result.data["job_id"].get<uint64_t>();
            if (job_id != 0)
                g_state.off_active_fuzz_job_id.store(job_id, std::memory_order_release);
        }
        {
            std::lock_guard<std::mutex> lk(g_state.off_mutex);
            g_state.off_status = result.message.empty() ? (result.success ? "Completed" : "Failed") : result.message;
            g_state.off_result = out.dump(2);
        }
        g_state.off_running.store(false, std::memory_order_release);
    });
    if (!posted) {
        state.off_running.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Network work queue unavailable";
        state.off_result = json{{"success", false}, {"error", "network_executor_unavailable"}}.dump(2);
        return false;
    }
    return true;
}

static void stop_offensive_fuzz_job(state_t& state) {
    const uint64_t job_id = state.off_active_fuzz_job_id.exchange(0, std::memory_order_acq_rel);
    if (job_id == 0)
        return;
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Stopping fuzz job";
    }
    const bool posted = post_network_task("offensive_fuzz_stop", aida::infra::executor::domain_t::feature_worker, "bounded_task", [job_id]() {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        json out;
        out["workflow"] = "Fuzz Stop";
        out["success"] = true;
        out["message"] = "Deterministic preview fuzz job stopped";
        out["data"] = json{{"job_id", job_id}, {"state", "stopped"}};
        aida::preview::network::record_receipt("Fuzz job stopped", std::to_string(job_id));
        std::lock_guard<std::mutex> lk(g_state.off_mutex);
        g_state.off_status = "Fuzz job stopped";
        g_state.off_result = out.dump(2);
#else
        auto result = aida::burp::offensive::fuzzing::stop(json{{"job_id", job_id}});
        json out;
        out["workflow"] = "Fuzz Stop";
        out["success"] = result.success;
        out["message"] = result.text;
        out["data"] = offensive_redact_json(result.data);
        std::lock_guard<std::mutex> lk(g_state.off_mutex);
        g_state.off_status = result.success ? "Fuzz job stopped" : result.text;
        g_state.off_result = out.dump(2);
#endif
    });
    if (!posted) {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Network work queue unavailable";
    }
}

static void render_offensive(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_offensive", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    const offensive_workflow_t& wf = offensive_workflow_at(state.off_workflow);
    const bool compact_controls = w < 1120.f;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Workflow:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::min(260.f, std::max(160.f, w * 0.28f)));
    if (ImGui::BeginCombo("##off_workflow", wf.label)) {
        for (int i = 0; i < offensive_workflow_count(); ++i) {
            const bool selected = state.off_workflow == i;
            if (ImGui::Selectable(k_offensive_workflows[i].label, selected))
                state.off_workflow = i;
            if (selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    aida::ui::toggle_switch("##off_scope", &state.off_scope_only);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Scope");
    if (compact_controls)
        ImGui::Spacing();
    else
        ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Timeout:");
    ImGui::SameLine();
    aida::ui::input_int("##off_timeout", &state.off_timeout_ms, ImVec2(100.f, 28.f));
    state.off_timeout_ms = std::max(1000, std::min(state.off_timeout_ms, 120000));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Payloads:");
    ImGui::SameLine();
    aida::ui::input_int("##off_payloads", &state.off_max_payloads, ImVec2(86.f, 28.f));
    state.off_max_payloads = std::max(1, std::min(state.off_max_payloads, 256));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Requests:");
    ImGui::SameLine();
    aida::ui::input_int("##off_requests", &state.off_max_requests, ImVec2(86.f, 28.f));
    state.off_max_requests = std::max(1, std::min(state.off_max_requests, 1000));

    ImGui::Spacing();
    const bool compact_target = w < 760.f;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Target:");
    ImGui::SameLine();
    const float target_w = compact_target ? std::max(180.f, w - 92.f) : std::max(180.f, std::min(520.f, w - 260.f));
    aida::ui::input_text("##off_url", state.off_target_url, sizeof(state.off_target_url),
                         "https://target.example/path?name=value", false, ImVec2(target_w, 28.f));
    if (compact_target)
        ImGui::Spacing();
    else
        ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Param:");
    ImGui::SameLine();
    aida::ui::input_text("##off_param", state.off_target_param, sizeof(state.off_target_param),
                         "name", false, ImVec2(150.f, 28.f));

    ImGui::Spacing();
    const float split_gap = 10.f;
    const bool stacked = w < 940.f;
    const float pane_w = stacked ? std::max(220.f, w - 6.f) : std::max(220.f, (w - split_gap - 6.f) * 0.5f);
    const float editor_h = std::max(110.f, std::min(220.f, h * 0.26f));
    ImGui::BeginChild("##off_payload_pane", ImVec2(pane_w, editor_h + 26.f), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Payload JSON");
    ImGui::InputTextMultiline("##off_payload_json", state.off_payload_json, sizeof(state.off_payload_json),
                              ImVec2(pane_w - 4.f, editor_h), ImGuiInputTextFlags_AllowTabInput);
    ImGui::EndChild();
    if (stacked)
        ImGui::Dummy(ImVec2(0.f, 8.f));
    else
        ImGui::SameLine(0.f, split_gap);
    ImGui::BeginChild("##off_raw_pane", ImVec2(pane_w, editor_h + 26.f), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Raw Request");
    static human_request_editor::fixed_state_t request_editor;
    human_request_editor::render_config_t request_config;
    request_config.stable_id = "offensive-raw-request";
    request_config.size = ImVec2(pane_w - 4.f, editor_h);
    request_config.max_bytes = sizeof(state.off_raw_request) - 1;
    request_config.editable = !state.off_running.load(std::memory_order_acquire);
    request_config.allow_empty = true;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    request_config.semantic_parent_id = "aida.dock-window.view.network.offensive";
#endif
    const auto request_editor_result = human_request_editor::render_fixed(
        request_editor, "network.offensive.raw-request", state.off_raw_request,
        request_config);
    ImGui::EndChild();

    ImGui::Spacing();
    const bool running = state.off_running.load(std::memory_order_acquire);
    const uint64_t fuzz_job = state.off_active_fuzz_job_id.load(std::memory_order_acquire);
    if (!running) {
        const bool raw_request_present = state.off_raw_request[0] != '\0';
        const bool run_disabled = raw_request_present &&
            (!request_editor_result.valid || request_editor_result.has_unapplied_pretty);
        if (aida::ui::button("Run", aida::ui::button_kind_t::primary,
                aida::ui::size_t_::sm, ImVec2(0.f, 0.f), run_disabled)) {
            const offensive_workflow_t& run_wf = offensive_workflow_at(state.off_workflow);
            diag::log_tagged_fmt("network", "offensive_run_clicked workflow=%s scope_only=%d timeout_ms=%d max_payloads=%d max_requests=%d url_len=%zu raw_len=%zu",
                run_wf.label, state.off_scope_only ? 1 : 0, state.off_timeout_ms, state.off_max_payloads, state.off_max_requests,
                strlen(state.off_target_url), strlen(state.off_raw_request));
            start_offensive_workflow(state, run_wf);
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            std::lock_guard<std::mutex> lk(state.off_mutex);
            state.off_status = "Idle";
            state.off_result.clear();
        }
        if (fuzz_job != 0) {
            ImGui::SameLine();
            if (aida::ui::button("Stop Job", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
                stop_offensive_fuzz_job(state);
        }
    } else {
        aida::ui::pill_kind("Running", aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        ImGui::BeginDisabled();
        static_cast<void>(aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
            aida::ui::size_t_::sm));
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("This backend operation has no cooperative cancellation contract. It must finish before another workflow can start.");
    }

    std::string status;
    std::string result;
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        status = state.off_status;
        result = state.off_result;
    }
    ImGui::SameLine();
    aida::ui::pill_kind(status.c_str(), running ? aida::ui::pill_kind_t::accent : aida::ui::pill_kind_t::neutral,
                        aida::ui::size_t_::sm, true);

    ImGui::Spacing();
    if (!result.empty())
        render_offensive_issue_links(state, result, alpha);
    const float result_h = std::max(120.f, h - ImGui::GetCursorPosY() + y - 10.f);
    static char empty_result[1] = {};
    char* result_buf = result.empty() ? empty_result : result.data();
    ImGui::InputTextMultiline("##off_result", result_buf,
                              result.empty() ? 1 : result.size() + 1,
                              ImVec2(w - 6.f, result_h), ImGuiInputTextFlags_ReadOnly);
    ImGui::EndChild();
}

static void render_websocket(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##ws_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = aida::ui::with_alpha(th.text_primary, alpha);
    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, alpha);


    float ty = 4.f;
    ImGui::SetCursorPos(ImVec2(8.f, ty));
    aida::ui::input_text("##ws_filter", state.ws_filter_text, sizeof(state.ws_filter_text),
                          "Filter...", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 28.f))) {
        std::lock_guard<std::mutex> lock(state.ws_mutex);
        size_t prev = state.ws_frames.size();
        state.ws_frames.clear();
        state.ws_selected = -1;
        diag::log_tagged_fmt("network", "ws_frames_cleared prev=%zu", prev);
    }
    ImGui::SameLine();
    aida::ui::toggle_switch("##ws_auto", &state.ws_auto_scroll);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Auto-scroll");

    float header_y = ty + 38.f;

    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    dl->AddRectFilled(ImVec2(origin.x, origin.y + header_y - 4.f),
                      ImVec2(origin.x + w, origin.y + header_y + row_h - 4.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, origin.x, origin.y + header_y - 4.f, w, row_h, ar, ag, ab, alpha * 0.30f);

    float c_dir = 36.f, c_host = 220.f, c_opcode = 70.f, c_size = 80.f;
    float cx = 8.f;
    float ws_hdr_ty = origin.y + header_y - 4.f + text_oy;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Dir"); cx += c_dir;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Host"); cx += c_host;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Opcode"); cx += c_opcode;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Size"); cx += c_size;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Preview");

    float list_y = header_y + row_h;
    float list_h = h * 0.55f;
    ImGui::SetCursorPos(ImVec2(0.f, list_y));
    ImGui::BeginChild("##ws_list", ImVec2(w, list_h), false);
    dl = ImGui::GetWindowDrawList();

    std::lock_guard<std::mutex> lock(state.ws_mutex);
    std::string filter(state.ws_filter_text);

    if (state.ws_frames.empty()) {
        ImGui::EndChild();
        ImGui::SetCursorPos(ImVec2(0.f, list_y));
        ImGui::BeginChild("##ws_empty", ImVec2(w, list_h), false);
        ImVec2 ep = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No WebSocket frames";
        cfg.body  = "Frames captured by the proxy will appear here.";
        aida::ui::empty_state::render(ep, ImVec2(w, list_h), cfg);
        ImGui::EndChild();
        ImGui::EndChild();
        return;
    }

    static std::vector<size_t> filtered_frame_indices;
    filtered_frame_indices.clear();
    filtered_frame_indices.reserve(state.ws_frames.size());
    for (size_t index = 0; index < state.ws_frames.size(); ++index) {
        const auto& frame = state.ws_frames[index];
        if (!filter.empty() && frame.host.find(filter) == std::string::npos &&
            frame.preview.find(filter) == std::string::npos)
            continue;
        filtered_frame_indices.push_back(index);
    }

    ImGuiListClipper frame_clipper;
    frame_clipper.Begin(static_cast<int>(filtered_frame_indices.size()), row_h);
    while (frame_clipper.Step()) {
    for (int visible_idx = frame_clipper.DisplayStart; visible_idx < frame_clipper.DisplayEnd; ++visible_idx) {
        const size_t i = filtered_frame_indices[static_cast<size_t>(visible_idx)];
        const auto& fr = state.ws_frames[i];

        float ry = static_cast<float>(visible_idx) * row_h;
        float abs_ry = ImGui::GetWindowPos().y + ry - ImGui::GetScrollY();

        bool is_selected = (state.ws_selected == static_cast<int>(i));
        if (is_selected) {
            dl->AddRectFilled(ImVec2(ImGui::GetWindowPos().x, abs_ry),
                ImVec2(ImGui::GetWindowPos().x + w, abs_ry + row_h),
                aida::ui::with_alpha(th.selection, alpha));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        const bool hovered = mouse.x >= ImGui::GetWindowPos().x && mouse.x < ImGui::GetWindowPos().x + w &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const auto websocket_identity = websocket_artifact_identity(fr);
        const std::string websocket_artifact_id =
            semantic_artifact_id("websocket-frame", websocket_identity);
        ImGui::PushID(static_cast<int>(i));
        const ImGuiID websocket_row_id = ImGui::GetID("##websocket_frame_row");
        ImGui::PopID();
        aida::preview::semantics::register_region(
            websocket_artifact_id, "network-websocket-frame", websocket_row_id,
            ImVec2(ImGui::GetWindowPos().x, abs_ry),
            ImVec2(ImGui::GetWindowPos().x + w, abs_ry + row_h), false, false,
            "aida.dock-window.view.network.websocket");
#endif
        if (hovered && ImGui::IsMouseClicked(0))
            state.ws_selected = static_cast<int>(i);
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            state.ws_selected = static_cast<int>(i);
            open_exchange_context(websocket_artifact_identity(fr), {},
                                  exchange_context_origin_t::pointer);
        }

        cx = 8.f;
        ImU32 dir_col = fr.is_outbound
            ? aida::ui::with_alpha(th.warning, alpha)
            : aida::ui::with_alpha(th.info, alpha);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dir_col,
            fr.is_outbound ? "\xe2\x86\x91" : "\xe2\x86\x93"); cx += c_dir;

        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%u", fr.host.c_str(), static_cast<unsigned>(fr.port));
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), txt_col, buf); cx += c_host;

        snprintf(buf, sizeof(buf), "0x%02X", static_cast<unsigned>(fr.opcode));
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dim_col, buf); cx += c_opcode;

        snprintf(buf, sizeof(buf), "%zu", fr.payload.size());
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), txt_col, buf); cx += c_size;

        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dim_col,
            fr.preview.empty() ? "(empty)" : fr.preview.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }
    }

    const bool websocket_menu_key = state.ws_selected >= 0 &&
        state.ws_selected < static_cast<int>(state.ws_frames.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool websocket_shift_f10 = !websocket_menu_key && state.ws_selected >= 0 &&
        state.ws_selected < static_cast<int>(state.ws_frames.size()) &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (websocket_menu_key || websocket_shift_f10) {
        const auto& frame = state.ws_frames[static_cast<size_t>(state.ws_selected)];
        open_exchange_context(websocket_artifact_identity(frame), {},
            websocket_menu_key
                ? exchange_context_origin_t::menu_key
                : exchange_context_origin_t::shift_f10);
    }

    if (state.ws_auto_scroll && !state.ws_frames.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();


    float detail_y = list_y + list_h + 4.f;
    float detail_h = h - detail_y;
    ImGui::SetCursorPos(ImVec2(0.f, detail_y));
    ImGui::BeginChild("##ws_detail", ImVec2(w, detail_h), false);

    if (state.ws_selected >= 0 && state.ws_selected < static_cast<int>(state.ws_frames.size())) {
        const auto& fr = state.ws_frames[static_cast<size_t>(state.ws_selected)];
        dl = ImGui::GetWindowDrawList();
        ImVec2 dp = ImGui::GetWindowPos();

        ImFont* mono_font = aida::ui::fonts::code();
        bool pushed = false;
        if (mono_font) { ImGui::PushFont(mono_font); pushed = true; }

        float dy = 4.f;
        for (size_t off = 0; off < fr.payload.size() && dy < detail_h - 14.f; off += 16) {
            char line[128];
            int pos = snprintf(line, sizeof(line), "%04zx  ", off);
            for (size_t j = 0; j < 16; j++) {
                if (off + j < fr.payload.size())
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02x ",
                        static_cast<unsigned>(fr.payload[off + j]));
                else
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
            }
            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
            for (size_t j = 0; j < 16 && off + j < fr.payload.size(); j++) {
                uint8_t c = fr.payload[off + j];
                line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
            }
            line[pos] = '\0';
            dl->AddText(ImVec2(dp.x + 8.f, dp.y + dy), aida::ui::with_alpha(th.text_secondary, alpha), line);
            dy += 14.f;
        }

        if (pushed) ImGui::PopFont();
    }

        ImGui::EndChild();

    ImGui::EndChild();
}


namespace scripting_detail {

    struct panel_frame_t {
        ImVec2 origin;
        ImVec2 body_min;
        ImVec2 body_max;
        float  header_h;
    };

    static panel_frame_t panel_begin(ImVec2 pos, ImVec2 size,
                                     float alpha, const char* title,
                                     aida::ui::empty_state::glyph_t glyph,
                                     bool use_glyph) {
        const auto& th = aida::ui::resolved();

        ImDrawList* pdl = ImGui::GetWindowDrawList();
        ImVec2 win = ImGui::GetWindowPos();
        ImVec2 a = ImVec2(win.x + pos.x, win.y + pos.y);
        ImVec2 b = ImVec2(a.x + size.x, a.y + size.y);
        float radius = 10.f;
        float header_h = std::max(34.f, ImGui::GetFontSize() + 16.f);

        pdl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.92f), radius);
        pdl->AddRectFilledMultiColor(
            ImVec2(a.x, a.y), ImVec2(b.x, a.y + header_h),
            aida::ui::with_alpha(th.panel_header, alpha * 0.95f),
            aida::ui::with_alpha(th.panel_header, alpha * 0.95f),
            aida::ui::with_alpha(th.panel_bg, alpha * 0.55f),
            aida::ui::with_alpha(th.panel_bg, alpha * 0.55f));
        pdl->AddLine(ImVec2(a.x + 1.f, a.y + header_h),
                     ImVec2(b.x - 1.f, a.y + header_h),
                     aida::ui::with_alpha(th.border_subtle, alpha), 1.f);
        pdl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), radius, 0, 1.f);

        float gx = a.x + 14.f;
        float text_cy = a.y + (header_h - ImGui::GetFontSize()) * 0.5f;
        if (use_glyph) {
            float gs = ImGui::GetFontSize() * 1.4f;
            ImVec2 gc = ImVec2(a.x + 14.f + gs * 0.5f, a.y + header_h * 0.5f);
            aida::ui::empty_state::render_glyph(glyph, pdl, gc, gs,
                aida::ui::with_alpha(th.accent_u32, alpha), 1.f);
            gx = a.x + 14.f + gs + 8.f;
        }

        ImFont* hf = aida::ui::fonts::body_strong();
        if (hf)
            pdl->AddText(hf, ImGui::GetFontSize(), ImVec2(gx, text_cy),
                         aida::ui::with_alpha(th.text_primary, alpha), title);
        else
            pdl->AddText(ImVec2(gx, text_cy),
                         aida::ui::with_alpha(th.text_primary, alpha), title);

        panel_frame_t pf;
        pf.origin   = a;
        pf.body_min = ImVec2(a.x, a.y + header_h);
        pf.body_max = b;
        pf.header_h = header_h;
        return pf;
    }

    static void panel_header_meta(const panel_frame_t& pf, float alpha,
                                  const char* meta, ImU32 col) {
        ImDrawList* pdl = ImGui::GetWindowDrawList();
        ImFont* mf = aida::ui::fonts::caption();
        float fs = aida::ui::fonts::size_or(mf, ImGui::GetFontSize());
        float tw = mf ? mf->CalcTextSizeA(fs, FLT_MAX, 0.f, meta).x
                      : ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, meta).x;
        float tx = pf.body_max.x - 14.f - tw;
        float ty = pf.origin.y + (pf.header_h - fs) * 0.5f;
        if (mf)
            pdl->AddText(mf, fs, ImVec2(tx, ty), aida::ui::with_alpha(col, alpha), meta);
        else
            pdl->AddText(ImVec2(tx, ty), aida::ui::with_alpha(col, alpha), meta);
    }

    static ImU32 log_level_color(script_engine::log_level lv, float alpha) {
        const auto& th = aida::ui::resolved();
        switch (lv) {
            case script_engine::log_level::error:
                return aida::ui::with_alpha(th.error, alpha);
            case script_engine::log_level::warn:
                return aida::ui::with_alpha(th.warning, alpha);
            case script_engine::log_level::output:
                return aida::ui::with_alpha(th.success, alpha);
            case script_engine::log_level::command:
                return aida::ui::with_alpha(th.accent_u32, alpha);
            case script_engine::log_level::debug:
                return aida::ui::with_alpha(th.text_dim, alpha);
            case script_engine::log_level::info:
            default:
                return aida::ui::with_alpha(th.text_secondary, alpha);
        }
    }

    static const char* log_level_tag(script_engine::log_level lv) {
        switch (lv) {
            case script_engine::log_level::error:   return "ERR ";
            case script_engine::log_level::warn:    return "WARN";
            case script_engine::log_level::output:  return "OUT ";
            case script_engine::log_level::command: return "CMD ";
            case script_engine::log_level::debug:   return "DBG ";
            case script_engine::log_level::info:
            default:                                return "INFO";
        }
    }

    static void format_log_timestamp(uint64_t wall_seconds, char* out, size_t out_size) {
        if (out_size == 0) return;
        time_t t = static_cast<time_t>(wall_seconds);
        std::tm tm_buf{};
        bool ok = localtime_s(&tm_buf, &t) == 0;
        if (!ok) {
            snprintf(out, out_size, "--:--:--");
            return;
        }
        snprintf(out, out_size, "%02d:%02d:%02d",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    }

}

struct script_runtime_snapshot_t {
    bool initialized = false;
    std::size_t hook_count = 0;
    std::vector<script_engine::log_entry> log;
};

static std::shared_ptr<const script_runtime_snapshot_t> s_script_runtime_snapshot;
static std::atomic<bool> s_script_snapshot_pending{false};
static std::atomic<std::uint64_t> s_script_snapshot_requested_ms{0};

static void request_script_runtime_snapshot(bool force = false) {
    const std::uint64_t now = network_now_ms();
    const std::uint64_t last = s_script_snapshot_requested_ms.load(std::memory_order_acquire);
    if (!force && last != 0 && now >= last && now - last < 250)
        return;
    bool expected = false;
    if (!s_script_snapshot_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    s_script_snapshot_requested_ms.store(now, std::memory_order_release);
    const bool posted = post_network_task(
        "script_snapshot", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        []() {
            auto snapshot = std::make_shared<script_runtime_snapshot_t>();
            try {
                snapshot->initialized = script_engine::is_initialized();
                snapshot->hook_count = script_engine::registered_hook_count();
                snapshot->log = script_engine::get_log(2048);
                std::atomic_store_explicit(&s_script_runtime_snapshot,
                    std::shared_ptr<const script_runtime_snapshot_t>(std::move(snapshot)),
                    std::memory_order_release);
            } catch (...) {
            }
            s_script_snapshot_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted)
        s_script_snapshot_pending.store(false, std::memory_order_release);
}

static void request_script_load(state_t& state, std::string path) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.scripts.load", "Load network automation script", "view.network.scripting", path);
    const bool posted = post_network_task(
        "script_load", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, path = std::move(path), task_id]() {
            bool success = false;
            std::string error;
            std::string name;
            try {
                success = script_engine::load_script(path);
                name = std::filesystem::path(path).stem().string();
                if (!success)
                    error = "Script engine rejected the selected file";
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Script load failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "Loaded " + name : error);
            enqueue_ui_completion([serial, success, path, name, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (success) {
                    const auto found = std::find_if(g_state.scripts.begin(), g_state.scripts.end(),
                        [&name](const state_t::script_entry_t& entry) { return entry.name == name; });
                    if (found != g_state.scripts.end()) {
                        found->path = path;
                        found->loaded = true;
                        found->enabled = true;
                        g_state.script_selected = static_cast<int>(std::distance(g_state.scripts.begin(), found));
                    } else {
                        state_t::script_entry_t entry;
                        entry.name = name;
                        entry.path = path;
                        entry.enabled = true;
                        entry.loaded = true;
                        g_state.scripts.push_back(std::move(entry));
                        g_state.script_selected = static_cast<int>(g_state.scripts.size()) - 1;
                    }
                    toast_notification::push("Loaded script: " + name, toast_notification::toast_type_t::info);
                } else {
                    toast_notification::push(error.empty() ? "Script load failed" : error,
                        toast_notification::toast_type_t::error);
                }
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script load");
    }
}

static void request_script_unload(state_t& state, std::string name) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.scripts.unload", "Unload network automation script", "view.network.scripting", name);
    const bool posted = post_network_task(
        "script_unload", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, name = std::move(name), task_id]() {
            bool success = false;
            std::string error;
            try {
                success = script_engine::unload_script(name);
                if (!success)
                    error = "Script engine did not unload " + name;
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Script unload failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "Unloaded " + name : error);
            enqueue_ui_completion([serial, name, success, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                const auto found = std::find_if(g_state.scripts.begin(), g_state.scripts.end(),
                    [&name](const state_t::script_entry_t& entry) { return entry.name == name; });
                if (success && found != g_state.scripts.end()) {
                    found->loaded = false;
                    found->enabled = false;
                } else if (!success) {
                    toast_notification::push(error.empty() ? "Script unload failed" : error,
                        toast_notification::toast_type_t::error);
                }
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script unload");
    }
}

static void request_script_toggle(state_t& state, std::string name, bool enable) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        enable ? "network.scripts.enable" : "network.scripts.pause",
        enable ? "Enable network automation script" : "Pause network automation script",
        "view.network.scripting", name);
    const bool posted = post_network_task(
        enable ? "script_enable" : "script_pause",
        aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, name = std::move(name), enable, task_id]() {
            bool success = true;
            std::string error;
            try {
                script_engine::set_script_enabled(name, enable);
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = "Script state change failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? name + (enable ? " enabled" : " paused") : error);
            enqueue_ui_completion([serial, name, enable, success, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                const auto found = std::find_if(g_state.scripts.begin(), g_state.scripts.end(),
                    [&name](const state_t::script_entry_t& entry) { return entry.name == name; });
                if (success && found != g_state.scripts.end())
                    found->enabled = enable;
                else if (!success)
                    toast_notification::push(error.empty() ? "Script state change failed" : error,
                        toast_notification::toast_type_t::error);
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script state change");
    }
}

static void request_script_evaluate(state_t& state, std::string source) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::size_t source_size = source.size();
    const std::string task_id = register_network_operation(
        "network.scripts.evaluate", "Evaluate network automation script", "view.network.scripting",
        std::to_string(source_size) + " bytes");
    const bool posted = post_network_task(
        "script_editor_run", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, source = std::move(source), source_size, task_id]() {
            bool success = false;
            std::string error;
            try {
                success = script_engine::load_script_source("_editor_", source);
                if (!success)
                    error = "Script engine rejected the editor source";
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Script evaluation failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(source_size) + " bytes evaluated" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Script evaluation failed" : error,
                        toast_notification::toast_type_t::error);
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script evaluation");
    }
}

static void request_script_console(state_t& state, std::string command) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.scripts.console", "Execute network script console command", "view.network.scripting",
        std::to_string(command.size()) + " bytes");
    const bool posted = post_network_task(
        "script_console_exec", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, command = std::move(command), task_id]() {
            bool success = true;
            std::string output;
            std::string error;
            try {
                output = script_engine::execute(command);
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = "Script console execution failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(output.size()) + " output bytes" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Script console execution failed" : error,
                        toast_notification::toast_type_t::error);
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script console command");
    }
}

static bool read_script_file_exact(const std::string& path, std::string& contents, std::string& error) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    static_cast<void>(error);
    contents = "function onRequest(request) {\n  request.headers.remove('Authorization');\n  return request;\n}\n\nfunction onResponse(response) {\n  if (response.status >= 500) response.tags.add('server-error');\n  return response;\n}";
    aida::preview::network::record_receipt("Script opened in editor", path);
    return true;
#else
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "Cannot open script file (Win32 " + std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER size{};
    bool success = GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart < 32768;
    if (!success)
        error = size.QuadPart >= 32768 ? "Script is larger than the 32 KiB inline editor limit"
                                      : "Cannot determine script size";
    if (success) {
        contents.resize(static_cast<std::size_t>(size.QuadPart));
        std::size_t offset = 0;
        while (offset < contents.size()) {
            const DWORD chunk = static_cast<DWORD>((std::min)(contents.size() - offset, static_cast<std::size_t>(32768)));
            DWORD read = 0;
            if (!ReadFile(file, contents.data() + offset, chunk, &read, nullptr) || read != chunk) {
                error = "Script read failed or was partial (Win32 " + std::to_string(GetLastError()) + ")";
                success = false;
                break;
            }
            offset += read;
        }
    }
    CloseHandle(file);
    if (success && contents.find('\0') != std::string::npos) {
        contents.clear();
        error = "Script contains embedded NUL bytes and cannot be opened in the text editor";
        success = false;
    }
    return success;
#endif
}

static void request_script_open(state_t& state, std::string path) {
    bool expected = false;
    if (!state.script_open_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::string task_id = register_network_operation(
        "network.scripts.open", "Open network script in editor", "view.network.scripting", path);
    const bool posted = post_network_task(
        "script_open", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [path = std::move(path), task_id]() {
            std::string contents;
            std::string error;
            const bool success = read_script_file_exact(path, contents, error);
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? std::to_string(contents.size()) + " bytes loaded" : error);
            enqueue_ui_completion([success, contents = std::move(contents), error = std::move(error)]() {
                if (success) {
                    std::memcpy(g_state.script_editor_buf, contents.data(), contents.size());
                    g_state.script_editor_buf[contents.size()] = '\0';
                } else {
                    toast_notification::push(error.empty() ? "Script open failed" : error,
                        toast_notification::toast_type_t::error);
                }
                g_state.script_open_pending.store(false, std::memory_order_release);
            });
        }, false);
    if (!posted) {
        state.script_open_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script open");
    }
}

static void request_script_log_clear(state_t& state) {
    bool expected = false;
    if (!state.script_operation_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const std::uint64_t serial = state.script_operation_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = register_network_operation(
        "network.scripts.log.clear", "Clear network script log", "view.network.scripting", "engine log");
    const bool posted = post_network_task(
        "script_log_clear", aida::infra::executor::domain_t::diagnostics, "bounded_task",
        [serial, task_id]() {
            bool success = true;
            std::string error;
            try {
                script_engine::clear_log();
            } catch (const std::exception& exception) {
                success = false;
                error = exception.what();
            } catch (...) {
                success = false;
                error = "Script log clear failed";
            }
            finish_network_operation(task_id, success, success ? "Completed" : "Failed",
                success ? "Script log cleared" : error);
            enqueue_ui_completion([serial, success, error = std::move(error)]() {
                if (g_state.script_operation_serial.load(std::memory_order_acquire) != serial)
                    return;
                if (!success)
                    toast_notification::push(error.empty() ? "Script log clear failed" : error,
                        toast_notification::toast_type_t::error);
                g_state.script_operation_pending.store(false, std::memory_order_release);
                request_script_runtime_snapshot(true);
            });
        }, false);
    if (!posted) {
        state.script_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected", "Executor rejected script log clear");
    }
}

static void render_scripting(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    using namespace scripting_detail;
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##script_tab", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();

    auto load_script_from_dialog = [&state]() {
        char path_buf[MAX_PATH] = {};
        static const char k_lua_open_filter[] =
            "Lua Scripts (*.lua)\0*.lua\0"
            "All files (*.*)\0*.*\0\0";
        if (!network_open_dialog::show_open_file_dialog(g_hwnd,
                "Load Lua Script",
                k_lua_open_filter,
                path_buf, sizeof(path_buf),
                "network_view::load_script")) {
            return;
        }

        std::string path_str(path_buf);
        diag::log_tagged_fmt("network", "script_load_dialog_pick path='%s'", path_str.c_str());
        request_script_load(state, std::move(path_str));
    };

    request_script_runtime_snapshot();
    const auto runtime_snapshot = std::atomic_load_explicit(&s_script_runtime_snapshot, std::memory_order_acquire);
    const bool engine_up = runtime_snapshot && runtime_snapshot->initialized;
    const size_t hook_count = runtime_snapshot ? runtime_snapshot->hook_count : 0;

    float pad = 2.f;
    float content_y = 0.f;
    float content_h = h;
    float rail_w = std::min(264.f, std::max(220.f, w * 0.24f));

    {
        panel_frame_t lib = panel_begin(ImVec2(0.f, content_y),
            ImVec2(rail_w, content_h), alpha, "Script Library",
            aida::ui::empty_state::glyph_t::layers, true);

        {
            ImFont* mf = aida::ui::fonts::caption();
            float mfs = aida::ui::fonts::size_or(mf, ImGui::GetFontSize());
            char lib_meta[40];
            snprintf(lib_meta, sizeof(lib_meta), "%zu hooks", hook_count);
            float meta_w = mf ? mf->CalcTextSizeA(mfs, FLT_MAX, 0.f, lib_meta).x
                              : ImGui::GetFont()->CalcTextSizeA(mfs, FLT_MAX, 0.f, lib_meta).x;
            float meta_x = lib.body_max.x - 14.f - meta_w;
            float meta_y = lib.origin.y + (lib.header_h - mfs) * 0.5f;
            if (mf)
                dl->AddText(mf, mfs, ImVec2(meta_x, meta_y),
                            aida::ui::with_alpha(th.text_dim, alpha), lib_meta);
            else
                dl->AddText(ImVec2(meta_x, meta_y),
                            aida::ui::with_alpha(th.text_dim, alpha), lib_meta);

            ImVec2 dot_c = ImVec2(meta_x - 12.f, lib.origin.y + lib.header_h * 0.5f);
            aida::ui::status_dot(dot_c, 3.f,
                aida::ui::with_alpha(engine_up ? th.success : th.error, alpha),
                engine_up, 1.1f);
        }

        float footer_h = 116.f;
        float list_top = lib.header_h + 6.f;
        float list_h = std::max(48.f, content_h - list_top - footer_h);

        ImGui::SetCursorPos(ImVec2(0.f, content_y + list_top));
        ImGui::BeginChild("##script_lib_list", ImVec2(rail_w, list_h), false,
                          ImGuiWindowFlags_NoBackground);
        ImDrawList* ldl = ImGui::GetWindowDrawList();
        ImVec2 lwin = ImGui::GetWindowPos();
        ImVec2 lsz = ImGui::GetWindowSize();

        if (state.scripts.empty()) {
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
            cfg.title = "No scripts loaded";
            cfg.body  = "Load a .lua file to register request, response and packet hooks.";
            cfg.max_width = rail_w - 32.f;
            aida::ui::empty_state::render(lwin, lsz, cfg);
        } else {
            float row_h = std::max(46.f, ImGui::GetFontSize() * 2.6f);
            float gap = 6.f;
            ldl->PushClipRect(lwin, ImVec2(lwin.x + lsz.x, lwin.y + lsz.y), true);

            const float script_stride = row_h + gap;
            const std::size_t first_script = static_cast<std::size_t>((std::max)(0,
                static_cast<int>(ImGui::GetScrollY() / script_stride) - 1));
            const std::size_t last_script = (std::min)(state.scripts.size(),
                static_cast<std::size_t>(ImGui::GetScrollY() / script_stride + lsz.y / script_stride + 3));
            for (size_t i = first_script; i < last_script; i++) {
                auto& s = state.scripts[i];
                float ry = static_cast<float>(i) * (row_h + gap);
                float abs_ry = lwin.y + ry - ImGui::GetScrollY();
                bool sel = (state.script_selected == static_cast<int>(i));

                ImVec2 ra = ImVec2(lwin.x + 6.f, abs_ry);
                ImVec2 rb = ImVec2(lwin.x + lsz.x - 6.f, abs_ry + row_h);

                ImVec2 mouse = ImGui::GetMousePos();
                bool hovered = (mouse.x >= ra.x && mouse.x < rb.x &&
                                mouse.y >= ra.y && mouse.y < rb.y);

                ImU32 card_fill = sel
                    ? aida::ui::with_alpha(th.selection, alpha)
                    : (hovered ? aida::ui::with_alpha(th.hover_wash, alpha)
                               : aida::ui::with_alpha(th.bg_elevated, alpha * 0.55f));
                ldl->AddRectFilled(ra, rb, card_fill, 8.f);
                ImU32 card_border = sel
                    ? aida::ui::with_alpha(th.accent_dim, alpha)
                    : aida::ui::with_alpha(th.border_subtle, alpha);
                ldl->AddRect(ra, rb, card_border, 8.f, 0, 1.f);

                if (sel) {
                    ldl->AddRectFilled(ra, ImVec2(ra.x + 3.f, rb.y),
                        aida::ui::with_alpha(th.accent_u32, alpha), 8.f,
                        ImDrawFlags_RoundCornersLeft);
                }

                if (hovered && ImGui::IsMouseClicked(0))
                    state.script_selected = static_cast<int>(i);

                ImU32 dot_col = !s.loaded
                    ? aida::ui::with_alpha(th.text_dim, alpha)
                    : (s.enabled ? aida::ui::with_alpha(th.success, alpha)
                                 : aida::ui::with_alpha(th.warning, alpha));
                ImVec2 dot_c = ImVec2(ra.x + 16.f, ra.y + row_h * 0.5f - ImGui::GetFontSize() * 0.32f);
                ldl->AddCircleFilled(dot_c, 4.f, dot_col, 16);
                ldl->AddCircle(dot_c, 6.f, aida::ui::with_alpha(dot_col, alpha * 0.4f), 16, 1.f);

                ImFont* nf = aida::ui::fonts::body_em();
                float nfs = aida::ui::fonts::size_or(nf, ImGui::GetFontSize());
                ImU32 name_col = s.enabled
                    ? aida::ui::with_alpha(th.text_primary, alpha)
                    : aida::ui::with_alpha(th.text_secondary, alpha);
                if (nf)
                    ldl->AddText(nf, nfs, ImVec2(ra.x + 30.f, ra.y + 7.f), name_col, s.name.c_str());
                else
                    ldl->AddText(ImVec2(ra.x + 30.f, ra.y + 7.f), name_col, s.name.c_str());

                const char* state_label = !s.loaded ? "UNLOADED"
                                          : (s.enabled ? "ENABLED" : "PAUSED");
                ImU32 badge_col = !s.loaded ? th.text_dim
                                  : (s.enabled ? th.success : th.warning);
                ImFont* cf = aida::ui::fonts::caption();
                float cfs = cf ? aida::ui::fonts::size_or(cf, ImGui::GetFontSize()) * 0.92f
                               : ImGui::GetFontSize() * 0.82f;
                float bw = (cf ? cf->CalcTextSizeA(cfs, FLT_MAX, 0.f, state_label).x
                               : ImGui::GetFont()->CalcTextSizeA(cfs, FLT_MAX, 0.f, state_label).x)
                           + 14.f;
                ImVec2 ba = ImVec2(ra.x + 30.f, ra.y + 7.f + nfs + 4.f);
                ImVec2 bb = ImVec2(ba.x + bw, ba.y + cfs + 6.f);
                ldl->AddRectFilled(ba, bb, aida::ui::with_alpha(badge_col, alpha * 0.18f),
                                   (cfs + 6.f) * 0.5f);
                ldl->AddRect(ba, bb, aida::ui::with_alpha(badge_col, alpha * 0.5f),
                             (cfs + 6.f) * 0.5f, 0, 1.f);
                if (cf)
                    ldl->AddText(cf, cfs, ImVec2(ba.x + 7.f, ba.y + 3.f),
                                 aida::ui::with_alpha(badge_col, alpha), state_label);
                else
                    ldl->AddText(ImVec2(ba.x + 7.f, ba.y + 3.f),
                                 aida::ui::with_alpha(badge_col, alpha), state_label);

                if (!s.path.empty()) {
                    std::filesystem::path fp(s.path);
                    std::string fname = fp.filename().string();
                    float fnx = bb.x + 8.f;
                    if (cf && fnx < rb.x - 8.f) {
                        ldl->PushClipRect(ImVec2(fnx, ba.y), ImVec2(rb.x - 8.f, bb.y), true);
                        ldl->AddText(cf, cfs, ImVec2(fnx, ba.y + 3.f),
                                     aida::ui::with_alpha(th.text_dim, alpha), fname.c_str());
                        ldl->PopClipRect();
                    }
                }
            }

            ldl->PopClipRect();
            ImGui::Dummy(ImVec2(rail_w - 12.f,
                static_cast<float>(state.scripts.size()) * script_stride));
        }
        ImGui::EndChild();

        bool has_sel = state.script_selected >= 0 &&
                       state.script_selected < static_cast<int>(state.scripts.size());

        float footer_y = content_y + list_top + list_h + 6.f;
        ImVec2 fa = ImVec2(lib.origin.x + 8.f, lib.origin.y + list_top + list_h + 2.f);
        ImVec2 fb = ImVec2(lib.body_max.x - 8.f, lib.body_max.y - 8.f);
        dl->AddLine(ImVec2(fa.x, fa.y - 4.f), ImVec2(fb.x, fa.y - 4.f),
                    aida::ui::with_alpha(th.border_subtle, alpha), 1.f);

        ImGui::SetCursorPos(ImVec2(8.f, footer_y));
        const bool script_pending = state.script_operation_pending.load(std::memory_order_acquire);
        if (aida::ui::button("Load Script", aida::ui::button_kind_t::primary,
                             aida::ui::size_t_::sm, ImVec2(rail_w - 16.f, 30.f), script_pending))
            load_script_from_dialog();

        float fbtn_w = (rail_w - 16.f - 8.f) * 0.5f;
        ImGui::SetCursorPos(ImVec2(8.f, footer_y + 36.f));
        bool can_unload = has_sel && state.scripts[static_cast<size_t>(state.script_selected)].loaded;
        if (aida::ui::button(can_unload ? "Unload" : "Unloaded",
                             aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm,
                             ImVec2(fbtn_w, 30.f), !can_unload || script_pending) && can_unload) {
            const auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            diag::log_tagged_fmt("network", "script_unload_clicked name='%s'", s.name.c_str());
            request_script_unload(state, s.name);
        }
        ImGui::SameLine(0.f, 8.f);
        bool sel_enabled = has_sel && state.scripts[static_cast<size_t>(state.script_selected)].enabled;
        if (aida::ui::button(sel_enabled ? "Pause" : "Enable",
                             aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                             ImVec2(fbtn_w, 30.f), !has_sel || script_pending) && has_sel) {
            const auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            const bool enable = !s.enabled;
            diag::log_tagged_fmt("network", "script_toggle_enabled name='%s' enabled=%d",
                s.name.c_str(), enable ? 1 : 0);
            request_script_toggle(state, s.name, enable);
        }

        ImGui::SetCursorPos(ImVec2(8.f, footer_y + 72.f));
        bool can_edit = has_sel && !state.scripts[static_cast<size_t>(state.script_selected)].path.empty();
        const bool open_pending = state.script_open_pending.load(std::memory_order_acquire);
        if (aida::ui::button("Open in Editor", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(rail_w - 16.f, 30.f),
                             !can_edit || open_pending) && can_edit) {
            const auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            request_script_open(state, s.path);
        }
    }

    float right_x = rail_w + pad * 2.f;
    float right_w = w - right_x;

    float console_field_h = std::max(30.f, ImGui::GetFontSize() + 14.f);
    float console_inner_pad = 8.f;
    float console_header_h = std::max(34.f, ImGui::GetFontSize() + 16.f);
    float console_h = console_header_h + console_field_h + console_inner_pad * 2.f;
    float editor_h = std::max(180.f, (content_h - console_h - pad * 4.f) * 0.52f);
    float log_h = std::max(150.f, content_h - editor_h - console_h - pad * 4.f);

    {
        panel_frame_t ed = panel_begin(
            ImVec2(right_x, content_y), ImVec2(right_w, editor_h), alpha,
            "Editor", aida::ui::empty_state::glyph_t::message, true);

        size_t char_count = strnlen(state.script_editor_buf, sizeof(state.script_editor_buf));
        int line_count = 1;
        for (size_t i = 0; i < char_count; i++)
            if (state.script_editor_buf[i] == '\n') line_count++;
        char ed_meta[64];
        snprintf(ed_meta, sizeof(ed_meta), "%d lines  -  %zu chars", line_count, char_count);
        panel_header_meta(ed, alpha, ed_meta, th.text_dim);

        float action_h = 38.f;
        float inner_pad = 8.f;
        float field_top = content_y + ed.header_h + inner_pad;
        float field_h = editor_h - ed.header_h - inner_pad * 2.f - action_h;

        ImVec2 fa = ImVec2(ed.origin.x + inner_pad, ed.body_min.y + inner_pad);
        ImVec2 fb = ImVec2(ed.body_max.x - inner_pad, fa.y + field_h);
        dl->AddRectFilled(fa, fb, aida::ui::with_alpha(th.bg_base, alpha * 0.85f), 8.f);

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.syn_identifier, alpha)));
        ImFont* code_font = aida::ui::fonts::code();
        bool code_pushed = false;
        if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad + 6.f, field_top + 5.f));
        ImGui::InputTextMultiline("##script_edit", state.script_editor_buf,
            sizeof(state.script_editor_buf),
            ImVec2(right_w - inner_pad * 2.f - 12.f, field_h - 10.f),
            ImGuiInputTextFlags_AllowTabInput);
        bool editor_active = ImGui::IsItemActive();

        if (code_pushed) ImGui::PopFont();
        ImGui::PopStyleColor();

        dl->AddRect(fa, fb, aida::ui::with_alpha(
            editor_active ? th.border_focus : th.border_subtle, alpha), 8.f, 0,
            editor_active ? 1.6f : 1.f);

        if (char_count == 0 && !editor_active) {
            ImFont* hint_font = aida::ui::fonts::code();
            float hfs = aida::ui::fonts::size_or(hint_font, ImGui::GetFontSize());
            const char* hint = "-- write a Lua hook, e.g. function on_request(req) ... end";
            if (hint_font)
                dl->AddText(hint_font, hfs, ImVec2(fa.x + 12.f, fa.y + 8.f),
                            aida::ui::with_alpha(th.text_dim, alpha), hint);
            else
                dl->AddText(ImVec2(fa.x + 12.f, fa.y + 8.f),
                            aida::ui::with_alpha(th.text_dim, alpha), hint);
        }

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad,
            field_top + field_h + inner_pad - 4.f));
        bool has_src = char_count > 0;
        if (aida::ui::button("Run Script", aida::ui::button_kind_t::primary,
                             aida::ui::size_t_::sm, ImVec2(112.f, 30.f),
                             !has_src || state.script_operation_pending.load(std::memory_order_acquire)) && has_src) {
            std::string src(state.script_editor_buf);
            diag::log_tagged_fmt("network", "script_editor_run size=%zu", src.size());
            request_script_evaluate(state, std::move(src));
        }
        ImGui::SameLine(0.f, 8.f);
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary,
                             aida::ui::size_t_::sm, ImVec2(82.f, 30.f), !has_src) && has_src)
            memset(state.script_editor_buf, 0, sizeof(state.script_editor_buf));
        ImGui::SameLine(0.f, 8.f);
        if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(72.f, 30.f), !has_src) && has_src)
            ImGui::SetClipboardText(state.script_editor_buf);
    }

    float console_y = content_y + editor_h + pad * 2.f;
    {
        panel_frame_t cs = panel_begin(
            ImVec2(right_x, console_y), ImVec2(right_w, console_h), alpha,
            "Console", aida::ui::empty_state::glyph_t::dots, true);

        panel_header_meta(cs, alpha, "Lua REPL", th.text_dim);

        float btn_w = 88.f;
        float field_h = console_field_h;

        ImVec2 fa = ImVec2(cs.origin.x + console_inner_pad, cs.body_min.y + console_inner_pad);
        ImVec2 fb = ImVec2(cs.body_max.x - console_inner_pad - btn_w - 8.f, fa.y + field_h);
        dl->AddRectFilled(fa, fb, aida::ui::with_alpha(th.bg_base, alpha * 0.85f), 8.f);

        ImFont* code_font = aida::ui::fonts::code();
        float prompt_fs = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
        if (code_font)
            dl->AddText(code_font, prompt_fs, ImVec2(fa.x + 10.f, fa.y + (field_h - prompt_fs) * 0.5f),
                        aida::ui::with_alpha(th.accent_u32, alpha), ">");
        else
            dl->AddText(ImVec2(fa.x + 10.f, fa.y + (field_h - prompt_fs) * 0.5f),
                        aida::ui::with_alpha(th.accent_u32, alpha), ">");

        bool code_pushed = false;
        if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }

        ImGui::SetCursorScreenPos(ImVec2(fa.x + 26.f,
            fa.y + (field_h - ImGui::GetFontSize()) * 0.5f));
        ImGui::SetNextItemWidth(fb.x - fa.x - 36.f);
        bool enter = ImGui::InputTextWithHint("##scr_input", "print(2 + 2)",
            state.script_console_buf, sizeof(state.script_console_buf),
            ImGuiInputTextFlags_EnterReturnsTrue);
        bool console_active = ImGui::IsItemActive();

        if (code_pushed) ImGui::PopFont();

        dl->AddRect(fa, fb, aida::ui::with_alpha(
            console_active ? th.border_focus : th.border_subtle, alpha), 8.f, 0,
            console_active ? 1.6f : 1.f);

        ImGui::SetCursorScreenPos(ImVec2(fb.x + 8.f, fa.y + (field_h - 30.f) * 0.5f));
        bool exec = aida::ui::button("Exec", aida::ui::button_kind_t::primary,
                                     aida::ui::size_t_::sm, ImVec2(btn_w, 30.f),
                                     state.script_operation_pending.load(std::memory_order_acquire));
        if (exec || enter) {
            std::string cmd(state.script_console_buf);
            if (!cmd.empty()) {
                diag::log_tagged_fmt("network", "script_console_exec size=%zu", cmd.size());
                request_script_console(state, std::move(cmd));
                memset(state.script_console_buf, 0, sizeof(state.script_console_buf));
            }
        }
    }

    float log_y = console_y + console_h + pad * 2.f;
    {
        panel_frame_t lg = panel_begin(
            ImVec2(right_x, log_y), ImVec2(right_w, log_h), alpha,
            "Engine Log", aida::ui::empty_state::glyph_t::memory, true);

        static const std::vector<script_engine::log_entry> empty_log;
        const auto& entries = runtime_snapshot ? runtime_snapshot->log : empty_log;
        const size_t log_size = entries.size();

        float ctrl_w = 200.f;
        ImGui::SetCursorScreenPos(ImVec2(lg.body_max.x - ctrl_w - 12.f,
            lg.origin.y + (lg.header_h - 22.f) * 0.5f));
        aida::ui::toggle_switch("Auto-scroll##scriptlog", &state.script_log_auto_scroll);
        ImGui::SameLine(0.f, 10.f);
        if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(64.f, 24.f),
                             log_size == 0 || state.script_operation_pending.load(std::memory_order_acquire)) &&
            log_size > 0)
            request_script_log_clear(state);

        float inner_pad = 8.f;
        float scroll_top = log_y + lg.header_h + inner_pad;
        float scroll_h = log_h - lg.header_h - inner_pad * 2.f;
        if (scroll_h < 24.f) scroll_h = 24.f;

        ImVec2 sa = ImVec2(lg.origin.x + inner_pad, lg.body_min.y + inner_pad);
        ImVec2 sb = ImVec2(lg.body_max.x - inner_pad, lg.body_max.y - inner_pad);
        dl->AddRectFilled(sa, sb, aida::ui::with_alpha(th.bg_base, alpha * 0.7f), 8.f);
        dl->AddRect(sa, sb, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad + 4.f, scroll_top + 4.f));
        ImGui::BeginChild("##script_log_scroll",
            ImVec2(right_w - inner_pad * 2.f - 8.f, scroll_h - 8.f), false,
            ImGuiWindowFlags_NoBackground);

        if (log_size == 0) {
            ImVec2 ewin = ImGui::GetWindowPos();
            ImVec2 esz = ImGui::GetWindowSize();
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::memory;
            cfg.title = "Log is empty";
            cfg.body  = "Output from print(), hook events and the REPL appears here.";
            cfg.max_width = std::min(360.f, esz.x - 32.f);
            aida::ui::empty_state::render(ewin, esz, cfg);
        } else {
            ImFont* code_font = aida::ui::fonts::code();
            bool code_pushed = false;
            if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 swin = ImGui::GetWindowPos();
            float fs = ImGui::GetFontSize();
            float line_h = ImGui::GetTextLineHeightWithSpacing();
            float avail_w = right_w - inner_pad * 2.f - 16.f;
            float ts_w = ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, "00:00:00").x + 8.f;
            float tag_w = ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, "WARN").x + 8.f;

            const float scroll_y = ImGui::GetScrollY();
            const float viewport_height = ImGui::GetWindowSize().y;
            const std::size_t first_log = static_cast<std::size_t>((std::max)(0,
                static_cast<int>(scroll_y / line_h) - 1));
            const std::size_t last_log = (std::min)(log_size,
                static_cast<std::size_t>(scroll_y / line_h + viewport_height / line_h + 3));
            for (std::size_t log_index = first_log; log_index < last_log; ++log_index) {
                const auto& e = entries[log_index];
                float row_y = swin.y + static_cast<float>(log_index) * line_h - scroll_y;
                ImU32 lvl_col = log_level_color(e.level, alpha);

                char ts_buf[16];
                format_log_timestamp(e.wall_seconds, ts_buf, sizeof(ts_buf));
                sdl->AddText(ImVec2(swin.x + 4.f, row_y),
                             aida::ui::with_alpha(th.text_dim, alpha), ts_buf);

                sdl->AddText(ImVec2(swin.x + 4.f + ts_w, row_y),
                             lvl_col, log_level_tag(e.level));

                float text_x = swin.x + 4.f + ts_w + tag_w;
                float text_right = swin.x + avail_w;

                std::string body;
                if (!e.script_name.empty() && e.script_name != "console" &&
                    e.script_name != "engine")
                    body = "[" + e.script_name + "] ";
                body += e.message;

                std::string repeat_badge;
                if (e.repeat_count > 1) {
                    char rb[24];
                    snprintf(rb, sizeof(rb), "  x%u", static_cast<unsigned>(e.repeat_count));
                    repeat_badge = rb;
                }

                float badge_w = repeat_badge.empty()
                    ? 0.f
                    : ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f,
                          repeat_badge.c_str()).x;

                sdl->PushClipRect(ImVec2(text_x, row_y),
                                  ImVec2(text_right - badge_w, row_y + line_h), true);
                sdl->AddText(ImVec2(text_x, row_y), lvl_col, body.c_str());
                sdl->PopClipRect();

                if (!repeat_badge.empty()) {
                    sdl->AddText(ImVec2(text_right - badge_w, row_y),
                                 aida::ui::with_alpha(th.text_dim, alpha),
                                 repeat_badge.c_str());
                }
            }
            ImGui::Dummy(ImVec2(avail_w, static_cast<float>(log_size) * line_h));

            if (code_pushed) ImGui::PopFont();

            if (state.script_log_auto_scroll)
                ImGui::SetScrollHereY(1.0f);
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_decoder(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##decoder_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = aida::ui::with_alpha(th.text_primary, alpha);
    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, alpha);
    (void)origin; (void)dim_col;


    float pipe_w = w * 0.3f;
    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##dec_pipeline", ImVec2(pipe_w, h), false);

    dl = ImGui::GetWindowDrawList();
    ImVec2 pp = ImGui::GetWindowPos();
    dl->AddText(ImVec2(pp.x + 8.f, pp.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Pipeline");


    ImGui::SetCursorPos(ImVec2(4.f, 24.f));
    auto& reg = decoder_pipeline::registry::instance();
    auto transforms = reg.all();


    static std::string combo_str;
    static size_t combo_str_count = 0;
    if (combo_str.empty() || combo_str_count != transforms.size()) {
        combo_str.clear();
        for (const auto& t : transforms) {
            combo_str += t->name;
            combo_str += '\0';
        }
        combo_str += '\0';
        combo_str_count = transforms.size();
    }

    ImGui::PushItemWidth(pipe_w - 90.f);
    ImGui::Combo("##dec_add", &state.decoder_add_transform, combo_str.c_str());
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Add", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        if (state.decoder_add_transform >= 0 &&
            state.decoder_add_transform < static_cast<int>(transforms.size())) {
            state_t::decoder_step_t step;
            step.transform_name = transforms[static_cast<size_t>(state.decoder_add_transform)]->id;
            diag::log_tagged_fmt("network", "decoder_step_added name='%s' pipeline_size=%zu",
                step.transform_name.c_str(), state.decoder_pipeline.size() + 1);
            state.decoder_pipeline.push_back(std::move(step));
        }
    }


    float py = 50.f;
    for (size_t i = 0; i < state.decoder_pipeline.size(); i++) {
        auto& step = state.decoder_pipeline[i];
        float abs_py = pp.y + py;
        bool sel = (state.decoder_selected_step == static_cast<int>(i));

        if (sel) {
            dl->AddRectFilled(ImVec2(pp.x + 4.f, abs_py), ImVec2(pp.x + pipe_w - 4.f, abs_py + 22.f),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= pp.x && mouse.x < pp.x + pipe_w &&
            mouse.y >= abs_py && mouse.y < abs_py + 22.f && ImGui::IsMouseClicked(0))
            state.decoder_selected_step = static_cast<int>(i);

        char label[256];
        snprintf(label, sizeof(label), "%zu. %s", i + 1, step.transform_name.c_str());
        dl->AddText(ImVec2(pp.x + 12.f, abs_py + 4.f), txt_col, label);


        ImGui::SetCursorPos(ImVec2(pipe_w - 28.f, py + 2.f));
        ImGui::PushID(static_cast<int>(i));
        if (aida::ui::button("X", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            state.decoder_pipeline.erase(state.decoder_pipeline.begin() + static_cast<ptrdiff_t>(i));
            if (state.decoder_selected_step >= static_cast<int>(i))
                state.decoder_selected_step--;
            ImGui::PopID();
            break;
        }
        ImGui::PopID();

        if (i + 1 < state.decoder_pipeline.size()) {
            float arrow_base_y = pp.y + py + 22.f;
            float arrow_cx = pp.x + pipe_w * 0.5f;
            ImU32 arrow_col = aida::ui::with_alpha(th.accent_u32, alpha * 0.6f);
            dl->AddLine(ImVec2(arrow_cx, arrow_base_y + 2.f), ImVec2(arrow_cx, arrow_base_y + 12.f), arrow_col, 1.5f);
            dl->AddTriangleFilled(
                ImVec2(arrow_cx - 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx + 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx, arrow_base_y + 16.f),
                arrow_col);
            py += 40.f;
        } else {
            py += 24.f;
        }
    }

    ImGui::SetCursorPos(ImVec2(4.f, py + 8.f));
    if (aida::ui::button("Clear Pipeline", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        diag::log_tagged_fmt("network", "decoder_pipeline_cleared prev_size=%zu",
            state.decoder_pipeline.size());
        state.decoder_pipeline.clear();
        state.decoder_selected_step = -1;
    }
    ImGui::SameLine();
    if (aida::ui::button("Execute", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {

        std::vector<uint8_t> data(state.decoder_input,
            state.decoder_input + state.decoder_input_size);
        diag::log_tagged_fmt("network", "decoder_execute steps=%zu input_size=%zu",
            state.decoder_pipeline.size(), data.size());

        bool failed = false;
        for (const auto& step : state.decoder_pipeline) {

            std::map<std::string, std::string> params;
            for (const auto& p : step.params)
                params[p.first] = p.second;
            auto result = decoder_pipeline::apply_single(step.transform_name, data, params);
            if (result.success)
                data = std::move(result.data);
            else {
                state.decoder_output = "Error at '" + step.transform_name + "': " + result.error;
                diag::log_tagged_fmt("network", "decoder_execute_step_failed step='%s' err='%s'",
                    step.transform_name.c_str(), result.error.c_str());
                data.clear();
                failed = true;
                break;
            }
        }
        if (!failed) {
            diag::log_tagged_fmt("network", "decoder_execute_done out_size=%zu", data.size());
        }

        if (!data.empty()) {

            bool printable = true;
            for (uint8_t b : data) {
                if (b != '\n' && b != '\r' && b != '\t' && (b < 32 || b > 126)) {
                    printable = false;
                    break;
                }
            }
            if (printable) {
                state.decoder_output.assign(data.begin(), data.end());
            } else {

                state.decoder_output.clear();
                for (size_t off = 0; off < data.size(); off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04zx  ", off);
                    for (size_t j = 0; j < 16; j++) {
                        if (off + j < data.size())
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos),
                                "%02x ", static_cast<unsigned>(data[off + j]));
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                    }
                    for (size_t j = 0; j < 16 && off + j < data.size(); j++) {
                        uint8_t c = data[off + j];
                        line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
                    }
                    line[pos] = '\0';
                    state.decoder_output += line;
                    state.decoder_output += '\n';
                }
            }
        }
    }

    ImGui::EndChild();


    float right_x = pipe_w + 2.f;
    float right_w = w - right_x;
    float input_h = h * 0.45f;
    float output_h = h - input_h;


    float dec_label_h = ImGui::GetFontSize() + 12.f;

    ImGui::SetCursorPos(ImVec2(right_x, 0.f));
    ImGui::BeginChild("##dec_input", ImVec2(right_w, input_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 ip = ImGui::GetWindowPos();
    dl->AddText(ImVec2(ip.x + 8.f, ip.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Input");

    ImGui::SetCursorPos(ImVec2(4.f, dec_label_h));
    if (ImGui::InputTextMultiline("##dec_in", state.decoder_input, sizeof(state.decoder_input),
            ImVec2(right_w - 8.f, input_h - dec_label_h - 6.f),
            ImGuiInputTextFlags_AllowTabInput))
        state.decoder_input_size = std::strlen(state.decoder_input);
    {
        ImVec2 bmin = ImGui::GetItemRectMin();
        ImVec2 bmax = ImGui::GetItemRectMax();
        if (ImGui::IsItemActive())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha), 6.f, 0, 1.8f);
        else if (ImGui::IsItemHovered())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha * 0.55f), 6.f, 0, 1.f);
    }
    ImGui::EndChild();


    ImGui::SetCursorPos(ImVec2(right_x, input_h));
    ImGui::BeginChild("##dec_output", ImVec2(right_w, output_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 op = ImGui::GetWindowPos();
    dl->AddText(ImVec2(op.x + 8.f, op.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Output");

    ImGui::SetCursorPos(ImVec2(4.f, dec_label_h));
    ImGui::InputTextMultiline("##dec_out",
        state.decoder_output.data(),
        state.decoder_output.size() + 1,
        ImVec2(right_w - 8.f, output_h - dec_label_h - 6.f),
        ImGuiInputTextFlags_ReadOnly);
    {
        ImVec2 bmin = ImGui::GetItemRectMin();
        ImVec2 bmax = ImGui::GetItemRectMax();
        if (ImGui::IsItemActive())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha), 6.f, 0, 1.8f);
        else if (ImGui::IsItemHovered())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha * 0.55f), 6.f, 0, 1.f);
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

static void render_tab_content(sub_tab_t tab, state_t& state, float x, float y, float w, float h,
                               float alpha, float ar, float ag, float ab) {
    switch (tab) {
        case sub_tab_t::connections: render_connections(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::capture: render_capture(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::intercept: render_intercept(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::proxy: render_proxy(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::dns: render_dns(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::filters: render_filters(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::bandwidth: render_bandwidth(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::repeater: render_repeater(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::keylog: render_keylog(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::pcap_export: render_pcap_export(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::fuzzer: render_fuzzer(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::offensive: render_offensive(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::websocket: render_websocket(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::scripting: render_scripting(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::decoder: render_decoder(state, x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::sitemap: aida::burp::sitemap::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::scope: aida::burp::scope::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::cookies: aida::burp::cookie_jar::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::scanner: aida::burp::scanner_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::recon: aida::burp::recon_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::intruder: aida::burp::intruder_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::collab: aida::burp::collaborator_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::sequencer: aida::burp::sequencer_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::comparer: aida::burp::comparer_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::jwt: aida::burp::jwt_lab_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::mr: aida::burp::match_replace_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::session: aida::burp::session_handler_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::api: aida::burp::api_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::ws_edit: aida::burp::ws_editor_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::h2_edit: aida::burp::h2_editor_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::logger: aida::burp::logger_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::csp: aida::burp::csp::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::upstream: aida::burp::upstream::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::browser: aida::burp::browser::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::reports: aida::burp::report_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::headless: aida::burp::headless_view::render(x, y, w, h, alpha, ar, ag, ab); break;
        case sub_tab_t::COUNT: break;
    }
    render_exchange_context();
}

static aida::ui::components::status_kind_t network_header_status(const state_t& state,
                                                                 bool has_target) {
    if (!has_target)
        return aida::ui::components::status_kind_t::warning;
    if (state.cap_start_pending.load(std::memory_order_acquire) ||
        state.cap_stop_pending.load(std::memory_order_acquire))
        return aida::ui::components::status_kind_t::info;
    if (state.cap_running.load(std::memory_order_acquire))
        return aida::ui::components::status_kind_t::success;
    return aida::ui::components::status_kind_t::neutral;
}

static void render_network_status_bar(state_t& state, ImVec2 pos, float width, bool has_target) {
    ImGui::SetCursorPos(pos);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    bool region_visible = ImGui::BeginChild("##network_status_region",
        ImVec2(width, aida::ui::metrics::status_bar::height), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    if (region_visible) {
        ImGui::SetCursorPos(ImVec2(0.f, 0.f));
        bool visible = aida::ui::components::begin_status_bar("##network_status_bar");
        if (visible) {
            uint32_t attached_pid = driver_bridge::attached_pid();
            char pid_text[24] = {};
            if (attached_pid != 0)
                std::snprintf(pid_text, sizeof(pid_text), "%u", static_cast<unsigned>(attached_pid));
            else
                std::snprintf(pid_text, sizeof(pid_text), "none");

            bool capture_running = state.cap_running.load(std::memory_order_acquire);
            bool capture_pending = state.cap_start_pending.load(std::memory_order_acquire) ||
                                   state.cap_stop_pending.load(std::memory_order_acquire);
            const char* capture_text = capture_pending ? "transitioning" : capture_running ? "running" : "idle";
            aida::ui::components::status_kind_t capture_kind = capture_pending
                ? aida::ui::components::status_kind_t::info
                : capture_running ? aida::ui::components::status_kind_t::success
                                  : aida::ui::components::status_kind_t::neutral;

            const auto capture_snapshot = std::atomic_load_explicit(
                &state.capture_snapshot, std::memory_order_acquire);
            const std::size_t packet_count = capture_snapshot ? capture_snapshot->size() : 0;
            char packet_text[32] = {};
            std::snprintf(packet_text, sizeof(packet_text), "%zu", packet_count);

            aida::ui::components::status_item("target", "Target", pid_text,
                has_target ? aida::ui::components::status_kind_t::success
                           : aida::ui::components::status_kind_t::warning);
            aida::ui::components::status_item("capture", "Capture", capture_text, capture_kind);
            if (width >= 620.f)
                aida::ui::components::status_item("packets", "Packets", packet_text,
                    packet_count > 0 ? aida::ui::components::status_kind_t::info
                                     : aida::ui::components::status_kind_t::neutral);
            if (width >= 820.f) {
                int tab_index = std::clamp(static_cast<int>(state.active_tab), 0,
                    static_cast<int>(sub_tab_t::COUNT) - 1);
                aida::ui::components::status_item("tool", "Tool", tab_names[tab_index],
                    aida::ui::components::status_kind_t::accent, false, false);
            }
        }
        aida::ui::components::end_status_bar();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
}


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    drain_ui_completions();
    float dt = ImGui::GetIO().DeltaTime;
    const auto& th = aida::ui::resolved();
    const bool has_target = analysis_session::has_active_target();
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    g_state.last_render_tick_ms.store(aida::preview::network::monotonic_ms(), std::memory_order_release);
#else
    g_state.last_render_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
#endif

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    bool root_visible = ImGui::BeginChild("##network_view_root", ImVec2(width, height), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    if (!root_visible) {
        ImGui::EndChild();
        return;
    }

    ImVec2 root_size = ImGui::GetWindowSize();
    ImVec2 root_screen = ImGui::GetWindowPos();
    ImGui::GetWindowDrawList()->AddRectFilled(root_screen,
        ImVec2(root_screen.x + root_size.x, root_screen.y + root_size.y),
        aida::ui::with_alpha(th.bg_base, alpha));

    const float kNetMinWidth = 320.f;
    const float kNetMinHeight = 260.f;
    if (root_size.x < kNetMinWidth || root_size.y < kNetMinHeight) {
        static bool s_logged_net_clamp = false;
        if (!s_logged_net_clamp) {
            s_logged_net_clamp = true;
            ::diag::log_tagged_fmt("responsive",
                "network_view clamp_overlay width=%.0f height=%.0f min_width=%.0f min_height=%.0f",
                root_size.x, root_size.y, kNetMinWidth, kNetMinHeight);
        }
        aida::ui::responsive::draw_clamp_overlay(
            root_screen, root_size,
            "Widen or raise the panel to view network tools");
        ImGui::EndChild();
        return;
    }

    const float outer_pad = aida::ui::metrics::spacing::md;
    const float inner_width = std::max(1.f, root_size.x - outer_pad * 2.f);
    const bool capture_running = g_state.cap_running.load(std::memory_order_acquire);
    const bool capture_busy = g_state.cap_start_pending.load(std::memory_order_acquire) ||
                              g_state.cap_stop_pending.load(std::memory_order_acquire);
    const int active_group_idx = nav_group_for_tab(g_state.active_tab);
    const char* subtitle = root_size.x >= 620.f
        ? k_nav_groups[active_group_idx].status
        : tab_names[std::clamp(static_cast<int>(g_state.active_tab), 0,
            static_cast<int>(sub_tab_t::COUNT) - 1)];
    const char* primary_action = has_target && !capture_busy && root_size.x >= 680.f
        ? (capture_running ? "Stop capture" : "Start capture")
        : nullptr;
    const char* secondary_action = root_size.x >= 840.f && g_state.active_tab != sub_tab_t::capture
        ? "Open Capture"
        : nullptr;

    ImGui::SetCursorPos(ImVec2(outer_pad, outer_pad));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    bool header_visible = ImGui::BeginChild("##network_header_region",
        ImVec2(inner_width, aida::ui::metrics::panel::view_header_h), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    aida::ui::components::view_header_result_t header;
    if (header_visible) {
        ImGui::SetCursorPos(ImVec2(0.f, 0.f));
        header = aida::ui::components::view_header(
            "Network", subtitle, primary_action, secondary_action,
            network_header_status(g_state, has_target));
        ImGui::Dummy(ImVec2(0.f, 0.f));
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    if (header.primary_clicked) {
        if (capture_running)
            invoke_global_network_action("network.capture.stop");
        else
            invoke_global_network_action("network.capture.start");
    }
    if (header.secondary_clicked) {
        g_state.prev_tab = g_state.active_tab;
        g_state.active_tab = sub_tab_t::capture;
        g_state.content_fade = 0.f;
    }

    const float nav_y = outer_pad + aida::ui::metrics::panel::view_header_h +
        aida::ui::metrics::spacing::sm;
    const float status_h = aida::ui::metrics::status_bar::height;
    const float status_y = root_size.y - outer_pad - status_h;
    const float content_bottom = status_y - aida::ui::metrics::spacing::sm;

    float tab_h = render_tab_bar(g_state, outer_pad, nav_y, inner_width, alpha,
        accent_r, accent_g, accent_b, dt);

    g_state.content_fade = ui_anim::smooth_lerp(g_state.content_fade, 1.f, 14.f, dt);
    float ca = alpha * std::max(g_state.content_fade, 0.3f);

    float content_y = nav_y + tab_h + aida::ui::metrics::spacing::sm;
    float content_h = std::max(0.f, content_bottom - content_y);
    if (!has_target && tab_requires_target(g_state.active_tab)) {
        aida::ui::no_target_overlay::render(
            ImVec2(root_screen.x + outer_pad, root_screen.y + content_y),
            ImVec2(inner_width, content_h),
            "No target attached",
            "This Network tool needs an attached process for driver-backed capture, PID filtering, TLS key capture, or PCAP export. Attach or launch a target to enable it.",
            alpha, aida::ui::empty_state::glyph_t::network);
        render_network_status_bar(g_state, ImVec2(outer_pad, status_y), inner_width, has_target);
        ImGui::EndChild();
        return;
    }
    if (!has_target) {
        float banner_h = render_no_target_banner(outer_pad, content_y, inner_width, ca);
        content_y += banner_h;
        content_h = std::max(0.f, content_h - banner_h);
    }

    int active_now = static_cast<int>(g_state.active_tab);
    if (active_now != s_last_active_tab) {
        diag::log_tagged_fmt("network", "tab_switch from=%d to=%d", s_last_active_tab, active_now);
        s_tab_content_in.start(0.220f, aida::motion::ease::out_cubic);
        s_last_active_tab = active_now;
    }
    s_tab_content_in.tick(dt);

    switch (g_state.active_tab) {
        case sub_tab_t::connections:
            render_connections(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::capture:
            render_capture(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intercept:
            render_intercept(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::proxy:
            render_proxy(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::dns:
            render_dns(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::filters:
            render_filters(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::bandwidth:
            render_bandwidth(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::repeater:
            render_repeater(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::keylog:
            render_keylog(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::pcap_export:
            render_pcap_export(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::fuzzer:
            render_fuzzer(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::offensive:
            render_offensive(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::websocket:
            render_websocket(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scripting:
            render_scripting(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::decoder:
            render_decoder(g_state, outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::sitemap:
            aida::burp::sitemap::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scope:
            aida::burp::scope::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::cookies:
            aida::burp::cookie_jar::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scanner:
            aida::burp::scanner_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::recon:
            aida::burp::recon_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intruder:
            aida::burp::intruder_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::collab:
            aida::burp::collaborator_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::sequencer:
            aida::burp::sequencer_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::comparer:
            aida::burp::comparer_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::jwt:
            aida::burp::jwt_lab_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::mr:
            aida::burp::match_replace_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::session:
            aida::burp::session_handler_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::api:
            aida::burp::api_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::ws_edit:
            aida::burp::ws_editor_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::h2_edit:
            aida::burp::h2_editor_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::logger:
            aida::burp::logger_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::csp:
            aida::burp::csp::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::upstream:
            aida::burp::upstream::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::browser:
            aida::burp::browser::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::reports:
            aida::burp::report_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::headless:
            aida::burp::headless_view::render(outer_pad, content_y, inner_width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        default:
            break;
    }

    render_network_status_bar(g_state, ImVec2(outer_pad, status_y), inner_width, has_target);
    ImGui::EndChild();
}

const char* tab_name(sub_tab_t tab) noexcept {
    const int index = static_cast<int>(tab);
    if (index < 0 || index >= static_cast<int>(sub_tab_t::COUNT))
        return "Network";
    return tab_names[index];
}

void render_pane(sub_tab_t tab, float pos_x, float pos_y, float width, float height,
                 float alpha, float accent_r, float accent_g, float accent_b) {
    drain_ui_completions();
    const int index = static_cast<int>(tab);
    if (index < 0 || index >= static_cast<int>(sub_tab_t::COUNT))
        return;
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    g_state.last_render_tick_ms.store(aida::preview::network::monotonic_ms(), std::memory_order_release);
#else
    g_state.last_render_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
#endif
    ImGui::PushID(index);
    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    const bool visible = ImGui::BeginChild("##network_independent_pane", ImVec2(width, height), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    if (visible) {
        const ImVec2 size = ImGui::GetWindowSize();
        const ImVec2 screen = ImGui::GetWindowPos();
        ImGui::GetWindowDrawList()->AddRectFilled(screen,
            ImVec2(screen.x + size.x, screen.y + size.y),
            aida::ui::with_alpha(aida::ui::resolved().bg_base, alpha));
        const bool has_target = analysis_session::has_active_target();
        if (!has_target && tab_requires_target(tab)) {
            aida::ui::no_target_overlay::render(screen, size, "No target attached",
                "Attach or launch a target to enable this driver-backed Network pane.",
                alpha, aida::ui::empty_state::glyph_t::network);
        } else {
            render_tab_content(tab, g_state, 0.f, 0.f, size.x, size.y, alpha,
                accent_r, accent_g, accent_b);
        }
    }
    ImGui::EndChild();
    ImGui::PopID();
}

static std::vector<std::uint8_t> sitemap_request_bytes(
    const aida::burp::exchange_observed_t& exchange) {
    std::string raw = exchange.method.empty() ? "GET" : exchange.method;
    raw.push_back(' ');
    raw.append(exchange.path.empty() ? "/" : exchange.path);
    if (!exchange.query.empty()) raw.append("?").append(exchange.query);
    raw.append(" HTTP/1.1\r\n");
    bool has_host = false;
    for (const auto& header : exchange.req_headers) {
        std::string name = header.first;
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        has_host = has_host || name == "host";
        raw.append(header.first).append(": ").append(header.second).append("\r\n");
    }
    if (!has_host) raw.append("Host: ").append(exchange.host).append("\r\n");
    raw.append("\r\n");
    raw.append(reinterpret_cast<const char*>(exchange.req_body.data()), exchange.req_body.size());
    return {raw.begin(), raw.end()};
}

static std::vector<std::uint8_t> sitemap_response_bytes(
    const aida::burp::exchange_observed_t& exchange) {
    std::string raw = "HTTP/1.1 " + std::to_string(exchange.status_code) + " " +
        exchange.reason_phrase + "\r\n";
    for (const auto& header : exchange.resp_headers)
        raw.append(header.first).append(": ").append(header.second).append("\r\n");
    raw.append("\r\n");
    raw.append(reinterpret_cast<const char*>(exchange.resp_body.data()), exchange.resp_body.size());
    return {raw.begin(), raw.end()};
}

bool make_sitemap_artifact(std::uint64_t exchange_id, artifact_kind_t kind,
                           artifact_identity_t& identity, std::string& unavailable_reason) {
    if (kind != artifact_kind_t::sitemap_request &&
        kind != artifact_kind_t::sitemap_response) {
        unavailable_reason = "Site Map artifacts must identify a request or response.";
        return false;
    }
    aida::burp::exchange_observed_t exchange;
    if (!aida::burp::sitemap::find_exchange(exchange_id, exchange)) {
        unavailable_reason = "The Site Map exchange is no longer retained.";
        return false;
    }
    const bool response = kind == artifact_kind_t::sitemap_response;
    if (response && exchange.status_code <= 0 && exchange.resp_headers.empty() &&
        exchange.resp_body.empty()) {
        identity = {};
        unavailable_reason = "No response has been retained for this Site Map exchange.";
        return false;
    }
    const auto bytes = response ? sitemap_response_bytes(exchange) : sitemap_request_bytes(exchange);
    identity = {};
    identity.kind = kind;
    identity.source_id = exchange.id;
    identity.timestamp = exchange.timestamp_ms;
    identity.target_host = exchange.host;
    identity.target_port = exchange.port;
    identity.use_tls = exchange.scheme == "https";
    identity.parent_id = "network.sitemap.exchange." + std::to_string(exchange.id);
    identity.id = identity.parent_id + (response ? ".response" : ".request");
    identity.source_view_id = "view.network.sitemap";
    identity.label = std::string(response ? "Site Map response #" : "Site Map request #") +
        std::to_string(exchange.id);
    identity.content_size = bytes.size();
    identity.content_hash = artifact_hash(bytes);
    unavailable_reason.clear();
    return true;
}

bool resolve_artifact(const artifact_identity_t& identity, artifact_snapshot_t& snapshot,
                      std::string& unavailable_reason) {
    snapshot = artifact_snapshot_t{};
    if (!identity.valid()) {
        unavailable_reason = "The network artifact identity is incomplete; select the item again.";
        return false;
    }
    snapshot.identity = identity;
    switch (identity.kind) {
    case artifact_kind_t::request:
    case artifact_kind_t::response:
    case artifact_kind_t::exchange: {
        const auto proxy_snapshot = std::atomic_load_explicit(
            &s_proxy_runtime_snapshot, std::memory_order_acquire);
        if (!proxy_snapshot) {
            unavailable_reason = "The proxy history snapshot is still loading; retry after the view refreshes.";
            return false;
        }
        const auto found = std::find_if(proxy_snapshot->history.begin(), proxy_snapshot->history.end(),
            [&](const mitm_proxy::http_exchange& exchange) {
            return exchange.id == identity.source_id && exchange.timestamp == identity.timestamp;
        });
        if (found == proxy_snapshot->history.end()) {
            unavailable_reason = "The captured exchange is no longer retained; select a current history item.";
            return false;
        }
        snapshot.identity.target_host = found->target_host;
        snapshot.identity.target_port = found->target_port;
        snapshot.identity.use_tls = found->is_tls;
        snapshot.bytes = identity.kind == artifact_kind_t::response ? found->raw_response : found->raw_request;
        break;
    }
    case artifact_kind_t::intercept_request: {
        const auto publication = std::atomic_load_explicit(
            &s_intercept_runtime_snapshot, std::memory_order_acquire);
        if (!publication) {
            unavailable_reason = "The immutable Intercept publication is still loading; select the held request again.";
            return false;
        }
        const auto found = std::find_if(publication->held.begin(), publication->held.end(),
            [&](const mitm_proxy::http_exchange& exchange) {
                return exchange.id == identity.source_id &&
                    exchange.timestamp == identity.timestamp;
            });
        if (found == publication->held.end()) {
            unavailable_reason = "The held request is no longer retained; select a current Intercept row.";
            return false;
        }
        snapshot.identity.target_host = found->target_host;
        snapshot.identity.target_port = found->target_port;
        snapshot.identity.use_tls = found->is_tls;
        snapshot.bytes = found->raw_request;
        break;
    }
    case artifact_kind_t::packet: {
        const auto capture_snapshot = std::atomic_load_explicit(
            &g_state.capture_snapshot, std::memory_order_acquire);
        if (!capture_snapshot) {
            unavailable_reason = "The capture snapshot is still loading; retry after the view refreshes.";
            return false;
        }
        const auto found = std::find_if(capture_snapshot->begin(), capture_snapshot->end(),
            [&](const packet_entry_t& packet) {
                return packet.timestamp == identity.timestamp && packet.payload.size() == identity.content_size;
            });
        if (found == capture_snapshot->end()) {
            unavailable_reason = "The captured packet rolled out of the bounded capture history; select a current packet.";
            return false;
        }
        snapshot.bytes = found->payload;
        break;
    }
    case artifact_kind_t::websocket_frame: {
        std::lock_guard<std::mutex> lock(g_state.ws_mutex);
        const auto found = std::find_if(g_state.ws_frames.begin(), g_state.ws_frames.end(),
            [&](const state_t::ws_frame_entry_t& frame) {
                return frame.exchange_id == identity.source_id && frame.timestamp == identity.timestamp &&
                    frame.payload.size() == identity.content_size;
            });
        if (found == g_state.ws_frames.end()) {
            unavailable_reason = "The WebSocket frame is no longer retained; select a current frame.";
            return false;
        }
        snapshot.bytes = found->payload;
        break;
    }
    case artifact_kind_t::repeater_request: {
        if (!s_repeater_artifact_publication_ready.load(std::memory_order_acquire)) {
            unavailable_reason = "The Repeater request publication is unavailable; select the request again after the view refreshes.";
            return false;
        }
        const auto publication = std::atomic_load_explicit(
            &s_repeater_artifact_publication, std::memory_order_acquire);
        if (!publication) {
            unavailable_reason = "The Repeater request snapshot is still loading; select the request again.";
            return false;
        }
        const auto found = std::find_if(publication->requests.begin(), publication->requests.end(),
            [&](const std::shared_ptr<const artifact_snapshot_t>& retained) {
                return retained && retained->identity.source_id == identity.source_id;
            });
        if (found == publication->requests.end()) {
            unavailable_reason = "The Repeater request is no longer retained; select a current request.";
            return false;
        }
        if ((*found)->identity.revision != identity.revision ||
            (*found)->identity.content_size != identity.content_size ||
            (*found)->identity.content_hash != identity.content_hash ||
            (*found)->identity.id != identity.id) {
            unavailable_reason = "The Repeater request generation changed; reopen actions on the current request.";
            return false;
        }
        snapshot = **found;
        break;
    }
    case artifact_kind_t::repeater_response: {
        const auto found = std::find_if(g_state.repeater_entries.begin(), g_state.repeater_entries.end(),
            [&](const std::shared_ptr<repeater_entry_t>& entry) {
                return entry && entry->id == identity.source_id;
            });
        if (found == g_state.repeater_entries.end()) {
            unavailable_reason = "The Repeater tab was closed; reopen or select another request.";
            return false;
        }
        if ((*found)->request_revision != identity.revision ||
            (*found)->response_timestamp != identity.timestamp) {
            unavailable_reason = "The Repeater request or response generation changed; reopen actions on the current artifact.";
            return false;
        }
        snapshot.identity.target_host = (*found)->host;
        snapshot.identity.target_port = (*found)->port;
        snapshot.identity.use_tls = (*found)->use_tls;
        snapshot.bytes.assign((*found)->raw_response.begin(), (*found)->raw_response.end());
        break;
    }
    case artifact_kind_t::sitemap_request:
    case artifact_kind_t::sitemap_response: {
        aida::burp::exchange_observed_t exchange;
        if (!aida::burp::sitemap::find_exchange(identity.source_id, exchange)) {
            unavailable_reason = "The Site Map exchange is no longer retained.";
            return false;
        }
        if (exchange.timestamp_ms != identity.timestamp) {
            unavailable_reason = "The Site Map exchange generation changed; select the current exchange.";
            return false;
        }
        snapshot.identity.target_host = exchange.host;
        snapshot.identity.target_port = exchange.port;
        snapshot.identity.use_tls = exchange.scheme == "https";
        snapshot.bytes = identity.kind == artifact_kind_t::sitemap_response
            ? sitemap_response_bytes(exchange) : sitemap_request_bytes(exchange);
        break;
    }
    case artifact_kind_t::api_request:
    case artifact_kind_t::api_response: {
        if (!aida::burp::api_view::resolve_retained_artifact(identity.source_id, identity.timestamp,
                identity.kind == artifact_kind_t::api_response, snapshot.bytes, unavailable_reason))
            return false;
        if (!aida::burp::api_view::resolve_retained_endpoint(identity.source_id,
                identity.timestamp, snapshot.identity.target_host,
                snapshot.identity.target_port, snapshot.identity.use_tls,
                unavailable_reason)) return false;
        break;
    }
    case artifact_kind_t::websocket_editor_frame:
        if (!aida::burp::ws_editor_view::resolve_retained_artifact(identity.source_id, identity.revision,
                snapshot.bytes, unavailable_reason)) return false;
        break;
    case artifact_kind_t::http2_request:
    case artifact_kind_t::http2_response:
        if (!aida::burp::h2_editor_view::resolve_retained_artifact(identity.source_id, identity.timestamp,
                identity.kind == artifact_kind_t::http2_response, snapshot.bytes, unavailable_reason))
            return false;
        break;
    case artifact_kind_t::intruder_response:
        if (!aida::burp::intruder_view::resolve_retained_artifact(identity.source_id,
                identity.revision, identity.timestamp, snapshot.bytes, unavailable_reason))
            return false;
        break;
    case artifact_kind_t::scanner_request:
    case artifact_kind_t::scanner_response:
        if (!aida::burp::scanner_view::resolve_retained_artifact(identity.source_id,
                identity.timestamp, identity.revision,
                identity.kind == artifact_kind_t::scanner_response,
                snapshot.bytes, unavailable_reason))
            return false;
        if (!aida::burp::scanner_view::resolve_retained_endpoint(identity.source_id,
                identity.timestamp, snapshot.identity.target_host,
                snapshot.identity.target_port, snapshot.identity.use_tls,
                unavailable_reason)) return false;
        break;
    }
    if (snapshot.bytes.size() != identity.content_size || artifact_hash(snapshot.bytes) != identity.content_hash) {
        unavailable_reason = "The network artifact changed after the action menu opened; review the current bytes and try again.";
        snapshot = artifact_snapshot_t{};
        return false;
    }
    unavailable_reason.clear();
    return true;
}

bool send_artifact_to_repeater(const artifact_identity_t& identity, std::string& unavailable_reason) {
    if (g_state.repeater_entries.size() >= k_max_repeater_entries) {
        unavailable_reason = "Repeater retains at most 128 reviewed tabs; close a tab before opening another.";
        return false;
    }
    if (identity.kind == artifact_kind_t::response ||
        identity.kind == artifact_kind_t::repeater_response ||
        identity.kind == artifact_kind_t::sitemap_response ||
        identity.kind == artifact_kind_t::api_response ||
        identity.kind == artifact_kind_t::http2_response ||
        identity.kind == artifact_kind_t::intruder_response ||
        identity.kind == artifact_kind_t::scanner_response) {
        unavailable_reason = "Responses cannot be replayed as requests; choose the corresponding request artifact.";
        return false;
    }
    if (identity.kind == artifact_kind_t::http2_request) {
        unavailable_reason = "HTTP/2 requests must remain in the HTTP/2 editor so frame and pseudo-header semantics are preserved.";
        return false;
    }
    if (identity.kind != artifact_kind_t::request &&
        identity.kind != artifact_kind_t::intercept_request &&
        identity.kind != artifact_kind_t::exchange &&
        identity.kind != artifact_kind_t::repeater_request &&
        identity.kind != artifact_kind_t::sitemap_request &&
        identity.kind != artifact_kind_t::api_request &&
        identity.kind != artifact_kind_t::scanner_request) {
        unavailable_reason = "Repeater accepts retained HTTP/1 request artifacts only.";
        return false;
    }
    artifact_snapshot_t snapshot;
    if (!resolve_artifact(identity, snapshot, unavailable_reason)) return false;
    if (snapshot.bytes.size() > 65535U) {
        unavailable_reason = "Repeater accepts reviewed requests of at most 65535 bytes.";
        return false;
    }
    if (!intercept_editor_compatible(snapshot.bytes, unavailable_reason))
        return false;
    auto entry = std::make_shared<repeater_entry_t>();
    entry->id = s_repeater_artifact_sequence.fetch_add(1, std::memory_order_relaxed);
    entry->source_artifact_id = identity.id;
    entry->source_session_id = identity.session_id;
    entry->host = identity.target_host;
    entry->port = identity.target_port == 0 ? 443 : identity.target_port;
    entry->use_tls = identity.use_tls;
    entry->raw_request.assign(snapshot.bytes.begin(), snapshot.bytes.end());
    entry->request_hash = artifact_hash(snapshot.bytes);
    g_state.repeater_entries.push_back(std::move(entry));
    publish_repeater_request_artifacts(g_state);
    g_state.repeater_selected = static_cast<int>(g_state.repeater_entries.size()) - 1;
    unavailable_reason.clear();
    (void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("view.network.repeater"));
    return true;
}

namespace {

static constexpr char k_line_separator[] = "\r\n";

bool http_token_character(std::uint8_t value) {
    if ((value >= '0' && value <= '9') ||
        (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z')) return true;
    switch (value) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default:
        return false;
    }
}

bool parse_decimal_size(std::string_view value, std::size_t& result) {
    if (value.empty() || value.size() > 20U) return false;
    result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result, 10);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
}

bool validate_chunked_body(const std::vector<std::uint8_t>& request,
                           std::size_t offset, std::string& reason) {
    while (offset < request.size()) {
        const auto line_end = std::search(request.begin() + static_cast<std::ptrdiff_t>(offset),
            request.end(), std::begin(k_line_separator), std::end(k_line_separator) - 1);
        if (line_end == request.end()) {
            reason = "The chunked request body has an unterminated chunk-size line.";
            return false;
        }
        const std::size_t line_end_offset = static_cast<std::size_t>(line_end - request.begin());
        std::string_view size_line(reinterpret_cast<const char*>(request.data() + offset),
            line_end_offset - offset);
        const auto extension = size_line.find(';');
        if (extension != std::string_view::npos) {
            const auto extension_text = size_line.substr(extension + 1U);
            if (extension_text.empty() ||
                !std::all_of(extension_text.begin(), extension_text.end(), [](unsigned char value) {
                    return value >= 0x20U && value != 0x7fU;
                })) {
                reason = "The chunked request contains an invalid chunk extension.";
                return false;
            }
            size_line = size_line.substr(0, extension);
        }
        if (size_line.empty() || size_line.size() > 16U) {
            reason = "The chunked request body has an invalid chunk size.";
            return false;
        }
        std::uint64_t chunk_size = 0;
        const auto parsed = std::from_chars(size_line.data(),
            size_line.data() + size_line.size(), chunk_size, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != size_line.data() + size_line.size() ||
            chunk_size > 65535U) {
            reason = "The chunked request body has an invalid or oversized chunk.";
            return false;
        }
        offset = line_end_offset + 2U;
        if (chunk_size == 0) {
            if (offset + 2U == request.size() && request[offset] == '\r' &&
                request[offset + 1U] == '\n') return true;
            while (offset < request.size()) {
                const auto trailer_end = std::search(
                    request.begin() + static_cast<std::ptrdiff_t>(offset), request.end(),
                    std::begin(k_line_separator), std::end(k_line_separator) - 1);
                if (trailer_end == request.end()) break;
                const std::size_t trailer_end_offset =
                    static_cast<std::size_t>(trailer_end - request.begin());
                if (trailer_end_offset == offset)
                    return trailer_end_offset + 2U == request.size();
                const auto colon = std::find(request.begin() + static_cast<std::ptrdiff_t>(offset),
                    trailer_end, static_cast<std::uint8_t>(':'));
                if (colon == trailer_end) break;
                for (auto it = request.begin() + static_cast<std::ptrdiff_t>(offset);
                     it != colon; ++it) {
                    if (!http_token_character(*it)) {
                        reason = "The chunked request contains an invalid trailer name.";
                        return false;
                    }
                }
                if (!std::all_of(colon + 1, trailer_end, [](std::uint8_t value) {
                        return value == '\t' || (value >= 0x20U && value != 0x7fU);
                    })) {
                    reason = "The chunked request contains an invalid trailer value.";
                    return false;
                }
                offset = trailer_end_offset + 2U;
            }
            reason = "The chunked request has invalid or trailing data after its final chunk.";
            return false;
        }
        if (chunk_size > request.size() - offset ||
            offset + static_cast<std::size_t>(chunk_size) + 2U > request.size()) {
            reason = "The chunked request body is shorter than its declared chunk size.";
            return false;
        }
        offset += static_cast<std::size_t>(chunk_size);
        if (request[offset] != '\r' || request[offset + 1U] != '\n') {
            reason = "The chunked request body has an invalid chunk terminator.";
            return false;
        }
        offset += 2U;
    }
    reason = "The chunked request body has no final zero-sized chunk.";
    return false;
}

bool validate_http1_request(const std::vector<std::uint8_t>& request,
                            std::string& reason) {
    if (request.empty() || request.size() > 65535U) {
        reason = "A reviewed HTTP/1 request must contain from 1 to 65,535 bytes.";
        return false;
    }
    static constexpr char separator_bytes[] = "\r\n\r\n";
    const auto separator = std::search(request.begin(), request.end(),
        std::begin(separator_bytes), std::end(separator_bytes) - 1);
    if (separator == request.end()) {
        reason = "The reviewed HTTP/1 request has no exact CRLF header/body separator.";
        return false;
    }
    const std::size_t header_end = static_cast<std::size_t>(separator - request.begin());
    for (std::size_t index = 0; index < header_end + 2U; ++index) {
        const std::uint8_t value = request[index];
        if (value == '\n' && (index == 0 || request[index - 1U] != '\r')) {
            reason = "The reviewed HTTP/1 headers contain a bare line-feed.";
            return false;
        }
        if (value == '\r' && (index + 1U >= request.size() || request[index + 1U] != '\n')) {
            reason = "The reviewed HTTP/1 headers contain a bare carriage-return.";
            return false;
        }
        if (value == 0 || (value < 0x20U && value != '\r' && value != '\n' && value != '\t') ||
            value == 0x7fU) {
            reason = "The reviewed HTTP/1 headers contain a prohibited control character.";
            return false;
        }
    }
    const auto first_line_end = std::search(request.begin(), separator,
        std::begin(k_line_separator), std::end(k_line_separator) - 1);
    const auto first_space = std::find(request.begin(), first_line_end,
        static_cast<std::uint8_t>(' '));
    const auto second_space = first_space == first_line_end ? first_line_end :
        std::find(first_space + 1, first_line_end, static_cast<std::uint8_t>(' '));
    if (first_space == request.begin() || first_space == first_line_end ||
        second_space == first_space + 1 || second_space == first_line_end ||
        std::find(second_space + 1, first_line_end, static_cast<std::uint8_t>(' ')) != first_line_end) {
        reason = "The reviewed request line must be METHOD SP target SP HTTP/1.x.";
        return false;
    }
    if (static_cast<std::size_t>(first_space - request.begin()) > 32U ||
        !std::all_of(request.begin(), first_space, http_token_character)) {
        reason = "The reviewed request method is not a bounded HTTP token.";
        return false;
    }
    if (static_cast<std::size_t>(second_space - first_space - 1) > 8192U ||
        !std::all_of(first_space + 1, second_space, [](std::uint8_t value) {
            return value > 0x20U && value != 0x7fU;
        })) {
        reason = "The reviewed request target is empty, oversized, or contains controls.";
        return false;
    }
    const std::string_view version(reinterpret_cast<const char*>(&*(second_space + 1)),
        static_cast<std::size_t>(first_line_end - second_space - 1));
    if (version != "HTTP/1.0" && version != "HTTP/1.1") {
        reason = "The reviewed request must use HTTP/1.0 or HTTP/1.1.";
        return false;
    }

    bool host_present = false;
    bool content_length_present = false;
    std::size_t content_length = 0;
    bool transfer_encoding_present = false;
    bool transfer_chunked = false;
    std::size_t line_begin = static_cast<std::size_t>(first_line_end - request.begin()) + 2U;
    while (line_begin < header_end) {
        const auto line_end = std::search(
            request.begin() + static_cast<std::ptrdiff_t>(line_begin), request.end(),
            std::begin(k_line_separator), std::end(k_line_separator) - 1);
        if (line_end == request.end() || line_end > separator) {
            reason = "The reviewed HTTP/1 header block is malformed.";
            return false;
        }
        const std::size_t line_end_offset = static_cast<std::size_t>(line_end - request.begin());
        if (line_end_offset - line_begin > 8192U || request[line_begin] == ' ' ||
            request[line_begin] == '\t') {
            reason = "Folded, empty, or oversized HTTP headers are not accepted.";
            return false;
        }
        const auto colon = std::find(request.begin() + static_cast<std::ptrdiff_t>(line_begin),
            line_end, static_cast<std::uint8_t>(':'));
        if (colon == line_end || colon == request.begin() + static_cast<std::ptrdiff_t>(line_begin) ||
            static_cast<std::size_t>(colon -
                (request.begin() + static_cast<std::ptrdiff_t>(line_begin))) > 256U ||
            !std::all_of(request.begin() + static_cast<std::ptrdiff_t>(line_begin), colon,
                http_token_character)) {
            reason = "The reviewed request contains an invalid HTTP header name.";
            return false;
        }
        std::string name(reinterpret_cast<const char*>(request.data() + line_begin),
            static_cast<std::size_t>(colon - (request.begin() + static_cast<std::ptrdiff_t>(line_begin))));
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        std::size_t value_begin = static_cast<std::size_t>(colon - request.begin()) + 1U;
        while (value_begin < line_end_offset &&
            (request[value_begin] == ' ' || request[value_begin] == '\t')) ++value_begin;
        std::size_t value_end = line_end_offset;
        while (value_end > value_begin &&
            (request[value_end - 1U] == ' ' || request[value_end - 1U] == '\t')) --value_end;
        const std::string_view value(reinterpret_cast<const char*>(request.data() + value_begin),
            value_end - value_begin);
        if (name == "host") {
            if (host_present || value.empty()) {
                reason = "The reviewed request must contain exactly one non-empty Host header.";
                return false;
            }
            host_present = true;
        }
        if (name == "content-length") {
            std::size_t parsed_length = 0;
            if (content_length_present || !parse_decimal_size(value, parsed_length)) {
                reason = "Content-Length must be one unambiguous bounded decimal value.";
                return false;
            }
            content_length_present = true;
            content_length = parsed_length;
        }
        if (name == "transfer-encoding") {
            std::string lower(value);
            std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char item) {
                return static_cast<char>(std::tolower(item));
            });
            if (transfer_encoding_present || lower != "chunked") {
                reason = "Reviewed requests support only one exact Transfer-Encoding: chunked header.";
                return false;
            }
            transfer_encoding_present = true;
            transfer_chunked = true;
        }
        line_begin = line_end_offset + 2U;
    }
    if (version == "HTTP/1.1" && !host_present) {
        reason = "HTTP/1.1 reviewed requests require a non-empty Host header.";
        return false;
    }
    if (content_length_present && transfer_encoding_present) {
        reason = "A reviewed request cannot combine Content-Length and Transfer-Encoding.";
        return false;
    }
    const std::size_t body_begin = header_end + 4U;
    const std::size_t body_size = request.size() - body_begin;
    if (content_length_present && content_length != body_size) {
        reason = "The request body length does not match Content-Length.";
        return false;
    }
    if (transfer_chunked && !validate_chunked_body(request, body_begin, reason)) return false;
    if (!content_length_present && !transfer_encoding_present && body_size != 0U) {
        reason = "A reviewed request body requires explicit Content-Length or chunked framing.";
        return false;
    }
    reason.clear();
    return true;
}

}

bool validate_reviewed_request(const artifact_identity_t& source,
                               const std::vector<std::uint8_t>& reviewed_request,
                               artifact_identity_t& canonical_source,
                               std::string& unavailable_reason) {
    canonical_source = {};
    artifact_snapshot_t current;
    if (!resolve_artifact(source, current, unavailable_reason)) return false;
    if (current.identity.target_host.empty() || current.identity.target_port == 0 ||
        source.target_host != current.identity.target_host ||
        source.target_port != current.identity.target_port ||
        source.use_tls != current.identity.use_tls) {
        unavailable_reason = "The proposal endpoint does not exactly match the canonical retained artifact endpoint.";
        return false;
    }
    if (!validate_http1_request(reviewed_request, unavailable_reason)) return false;
    canonical_source = current.identity;
    unavailable_reason.clear();
    return true;
}

bool stage_validated_reviewed_request(const artifact_identity_t& source,
                                      const std::vector<std::uint8_t>& reviewed_request,
                                      const std::string& provenance,
                                      artifact_identity_t& staged_identity,
                                      std::string& unavailable_reason) {
    staged_identity = {};
    if (g_state.repeater_entries.size() >= k_max_repeater_entries) {
        unavailable_reason = "Repeater retains at most 128 reviewed tabs; close a tab before staging another.";
        return false;
    }
    if (reviewed_request.empty() || reviewed_request.size() > 65535U) {
        unavailable_reason = "The prevalidated request payload is outside its bounded staging range.";
        return false;
    }
    if (!source.valid() || source.target_host.empty() || source.target_port == 0) {
        unavailable_reason = "The validated request has no canonical retained endpoint.";
        return false;
    }
    if (source.kind != artifact_kind_t::request &&
        source.kind != artifact_kind_t::intercept_request &&
        source.kind != artifact_kind_t::exchange &&
        source.kind != artifact_kind_t::repeater_request &&
        source.kind != artifact_kind_t::sitemap_request &&
        source.kind != artifact_kind_t::api_request &&
        source.kind != artifact_kind_t::scanner_request) {
        unavailable_reason = "Only canonical retained HTTP/1 request artifacts can be staged.";
        return false;
    }
    if (provenance.empty() || provenance.size() > 512U) {
        unavailable_reason = "The reviewed request has no bounded AI proposal provenance.";
        return false;
    }
    artifact_identity_t canonical_source;
    if (!validate_reviewed_request(source, reviewed_request,
            canonical_source, unavailable_reason))
        return false;
    auto entry = std::make_shared<repeater_entry_t>();
    entry->id = s_repeater_artifact_sequence.fetch_add(1, std::memory_order_relaxed);
    entry->source_artifact_id = canonical_source.id;
    entry->source_session_id = canonical_source.session_id;
    entry->host = canonical_source.target_host;
    entry->port = canonical_source.target_port;
    entry->use_tls = canonical_source.use_tls;
    entry->raw_request.assign(reviewed_request.begin(), reviewed_request.end());
    entry->request_hash = artifact_hash(reviewed_request);
    entry->reviewed_source_hash = canonical_source.content_hash;
    entry->review_provenance = provenance;
    entry->reviewed_draft = true;
    staged_identity = repeater_artifact_identity(*entry, artifact_kind_t::repeater_request);
    g_state.repeater_entries.push_back(std::move(entry));
    publish_repeater_request_artifacts(g_state);
    g_state.repeater_selected = static_cast<int>(g_state.repeater_entries.size()) - 1;
    const auto opened = aida::ui::application_views::open_or_focus(
        aida::ui::stable_view_id_t("view.network.repeater"));
    if (!opened.ok()) {
        g_state.repeater_entries.pop_back();
        publish_repeater_request_artifacts(g_state);
        g_state.repeater_selected = static_cast<int>(g_state.repeater_entries.size()) - 1;
        staged_identity = {};
        unavailable_reason = opened.detail.empty()
            ? "The reviewed request could not open Repeater." : opened.detail;
        return false;
    }
    unavailable_reason.clear();
    return true;
}

bool send_artifact_to_comparer(const artifact_identity_t& identity, std::string& unavailable_reason) {
    artifact_snapshot_t snapshot;
    if (!resolve_artifact(identity, snapshot, unavailable_reason)) return false;
    const std::uint64_t slot = aida::burp::comparer::add_slot_from_bytes(
        identity.label.empty() ? identity.id : identity.label, snapshot.bytes, identity.id);
    if (slot == 0) {
        unavailable_reason = "Comparer rejected the artifact: " + aida::burp::comparer::last_error();
        return false;
    }
    unavailable_reason.clear();
    (void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("view.network.comparer"));
    return true;
}

static bool handoff_artifact(const artifact_identity_t& identity, bool agent,
                             std::string& unavailable_reason) {
    artifact_snapshot_t snapshot;
    if (!resolve_artifact(identity, snapshot, unavailable_reason)) return false;
    constexpr std::size_t max_handoff_bytes = 64U * 1024U;
    const std::size_t count = (std::min)(snapshot.bytes.size(), max_handoff_bytes);
    std::string content(reinterpret_cast<const char*>(snapshot.bytes.data()), count);
    aida::automation_ui::evidence_envelope_t envelope;
    envelope.id = "evidence." + identity.id + "." + std::to_string(identity.content_hash);
    envelope.session_id = identity.session_id;
    envelope.source_view_id = identity.source_view_id;
    envelope.source_kind = "network";
    envelope.entity_id = identity.id;
    envelope.display_label = identity.label.empty() ? identity.id : identity.label;
    envelope.return_target = identity.id;
    envelope.excerpt = std::move(content);
    envelope.revision = identity.revision;
    envelope.generation = identity.timestamp;
    envelope.snapshot_hash = identity.content_hash;
    envelope.content_hash = identity.content_hash;
    envelope.truncated = snapshot.bytes.size() > count;
    const std::string evidence_id = aida::automation_ui::register_evidence(std::move(envelope));
    if (evidence_id.empty()) {
        unavailable_reason = "The evidence envelope was rejected because its source identity was incomplete.";
        return false;
    }
    return agent
        ? aida::automation_ui::queue_evidence_for_agent(evidence_id, unavailable_reason)
        : aida::automation_ui::queue_evidence_for_chat(evidence_id, unavailable_reason);
}

bool add_artifact_to_chat(const artifact_identity_t& identity, std::string& unavailable_reason) {
    return handoff_artifact(identity, false, unavailable_reason);
}

bool assign_artifact_to_agent(const artifact_identity_t& identity, std::string& unavailable_reason) {
    return handoff_artifact(identity, true, unavailable_reason);
}

namespace {

const network_exchange_action_descriptor_t k_exchange_actions[] = {
    {network_exchange_action_t::repeater, "network.exchange.repeater"},
    {network_exchange_action_t::fuzzer, "network.exchange.fuzzer"},
    {network_exchange_action_t::intruder, "network.exchange.intruder"},
    {network_exchange_action_t::scanner, "network.exchange.scanner"},
    {network_exchange_action_t::comparer, "network.exchange.comparer"},
    {network_exchange_action_t::compare_request_response, "network.exchange.compare_request_response"},
    {network_exchange_action_t::session_handling, "network.exchange.session_handling"},
    {network_exchange_action_t::cookies, "network.exchange.cookies"},
    {network_exchange_action_t::match_replace, "network.exchange.match_replace"},
    {network_exchange_action_t::decoder, "network.exchange.decoder"},
    {network_exchange_action_t::sequencer, "network.exchange.sequencer"},
    {network_exchange_action_t::camoufox, "network.exchange.camoufox"},
    {network_exchange_action_t::copy_url, "network.exchange.copy_url"},
    {network_exchange_action_t::copy_method, "network.exchange.copy_method"},
    {network_exchange_action_t::copy_status, "network.exchange.copy_status"},
    {network_exchange_action_t::copy_request, "network.exchange.copy_request"},
    {network_exchange_action_t::copy_response, "network.exchange.copy_response"},
    {network_exchange_action_t::copy_headers, "network.exchange.copy_headers"},
    {network_exchange_action_t::copy_body, "network.exchange.copy_body"},
    {network_exchange_action_t::copy_artifact, "network.exchange.copy_artifact"},
    {network_exchange_action_t::scope_include, "network.exchange.scope_include"},
    {network_exchange_action_t::scope_exclude, "network.exchange.scope_exclude"},
    {network_exchange_action_t::save_export, "network.exchange.save_export"},
    {network_exchange_action_t::create_issue, "network.exchange.create_issue"},
    {network_exchange_action_t::chat, "network.exchange.chat"},
    {network_exchange_action_t::agent, "network.exchange.agent"},
    {network_exchange_action_t::replay_live, "network.exchange.replay"},
    {network_exchange_action_t::remove, "network.exchange.remove"}
};

bool response_kind(artifact_kind_t kind) {
    return kind == artifact_kind_t::response ||
        kind == artifact_kind_t::repeater_response ||
        kind == artifact_kind_t::sitemap_response ||
        kind == artifact_kind_t::api_response ||
        kind == artifact_kind_t::http2_response ||
        kind == artifact_kind_t::intruder_response ||
        kind == artifact_kind_t::scanner_response;
}

bool request_kind(artifact_kind_t kind) {
    return kind == artifact_kind_t::request ||
        kind == artifact_kind_t::intercept_request ||
        kind == artifact_kind_t::exchange ||
        kind == artifact_kind_t::repeater_request ||
        kind == artifact_kind_t::sitemap_request ||
        kind == artifact_kind_t::api_request ||
        kind == artifact_kind_t::http2_request ||
        kind == artifact_kind_t::scanner_request;
}

std::string artifact_text(const artifact_snapshot_t& snapshot) {
    return std::string(reinterpret_cast<const char*>(snapshot.bytes.data()), snapshot.bytes.size());
}

std::string clipboard_text(const std::string& value) {
    const bool textual = std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7F);
    });
    if (textual) return value;
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string encoded = "hex:";
    encoded.reserve(4U + value.size() * 2U);
    for (const char byte : value) {
        const auto c = static_cast<unsigned char>(byte);
        encoded.push_back(hex[c >> 4U]);
        encoded.push_back(hex[c & 0x0FU]);
    }
    return encoded;
}

std::string request_method(const std::string& raw) {
    const auto end = raw.find(' ');
    return end == std::string::npos ? std::string() : raw.substr(0, end);
}

std::string request_target(const std::string& raw) {
    const auto first = raw.find(' ');
    if (first == std::string::npos) return {};
    const auto second = raw.find(' ', first + 1U);
    return second == std::string::npos ? std::string() : raw.substr(first + 1U, second - first - 1U);
}

std::string artifact_url(const artifact_identity_t& identity, const std::string& request) {
    if (identity.target_host.empty()) return {};
    const std::string target = request_target(request);
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) return target;
    std::string url = identity.use_tls ? "https://" : "http://";
    url.append(identity.target_host);
    const std::uint16_t default_port = identity.use_tls ? 443 : 80;
    if (identity.target_port != 0 && identity.target_port != default_port)
        url.append(":").append(std::to_string(identity.target_port));
    url.append(target.empty() ? "/" : target);
    return url;
}

std::pair<std::string, std::string> http_headers_body(const std::string& raw) {
    auto split = raw.find("\r\n\r\n");
    std::size_t delimiter = 4;
    if (split == std::string::npos) {
        split = raw.find("\n\n");
        delimiter = 2;
    }
    if (split == std::string::npos) return {raw, {}};
    const auto first_line = raw.find('\n');
    const std::size_t header_begin = first_line == std::string::npos ? 0 : first_line + 1U;
    return {raw.substr(header_begin, split - header_begin), raw.substr(split + delimiter)};
}

std::string curl_quote(const std::string& value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    for (const char c : value) {
        if (c == '"' || c == '\\') result.push_back('\\');
        result.push_back(c);
    }
    result.push_back('"');
    return result;
}

std::string curl_command(const artifact_identity_t& identity, const std::string& request) {
    const std::string method = request_method(request);
    const std::string url = artifact_url(identity, request);
    if (method.empty() || url.empty()) return {};
    std::string result = "curl -i -k -X " + method + " " + curl_quote(url);
    const auto parts = http_headers_body(request);
    std::size_t offset = 0;
    while (offset < parts.first.size()) {
        const auto end = parts.first.find('\n', offset);
        std::string line = parts.first.substr(offset,
            end == std::string::npos ? std::string::npos : end - offset);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (name != "host" && name != "content-length")
                result.append(" -H ").append(curl_quote(line));
        }
        if (end == std::string::npos) break;
        offset = end + 1U;
    }
    if (!parts.second.empty())
        result.append(" --data-binary ").append(curl_quote(parts.second));
    return result;
}

std::string response_status(const std::string& raw) {
    const auto first = raw.find(' ');
    if (first == std::string::npos) return {};
    const auto end = raw.find_first_of("\r\n", first + 1U);
    return raw.substr(first + 1U, end == std::string::npos ? std::string::npos : end - first - 1U);
}

bool snapshot_for(const artifact_identity_t& identity, artifact_snapshot_t& snapshot,
                  std::string& reason) {
    return identity.valid() && resolve_artifact(identity, snapshot, reason);
}

const artifact_identity_t* request_identity(const exchange_context_runtime_t& context) {
    if (request_kind(context.primary.kind)) return &context.primary;
    return request_kind(context.related.kind) ? &context.related : nullptr;
}

const artifact_identity_t* response_identity(const exchange_context_runtime_t& context) {
    if (response_kind(context.primary.kind) && context.primary.valid() &&
        context.primary.content_size != 0) return &context.primary;
    return response_kind(context.related.kind) && context.related.valid() &&
        context.related.content_size != 0 ? &context.related : nullptr;
}

bool matching_http1_pair(const artifact_identity_t& request,
                         const artifact_identity_t& response) {
    return request.valid() && response.valid() && request_kind(request.kind) &&
        response_kind(response.kind) && request.kind != artifact_kind_t::http2_request &&
        response.kind != artifact_kind_t::http2_response && !request.raw_protocol &&
        !response.raw_protocol && !request.parent_id.empty() &&
        request.parent_id == response.parent_id && request.source_view_id == response.source_view_id &&
        request.source_id == response.source_id && request.session_id == response.session_id &&
        request.target_host == response.target_host && request.target_port == response.target_port &&
        request.use_tls == response.use_tls;
}

std::string cookie_request_path(const std::string& raw_request) {
    std::string target = request_target(raw_request);
    const std::size_t scheme = target.find("://");
    if (scheme != std::string::npos) {
        const std::size_t slash = target.find('/', scheme + 3U);
        target = slash == std::string::npos ? "/" : target.substr(slash);
    }
    const std::size_t fragment = target.find('#');
    if (fragment != std::string::npos) target.resize(fragment);
    return target.empty() ? "/" : target;
}

enum class exchange_review_kind_t : std::uint8_t {
    none,
    create_issue,
    replay,
    remove
};

enum class exchange_remove_source_t : std::uint8_t {
    none,
    proxy,
    repeater
};

struct exchange_review_state_t {
    exchange_review_kind_t kind = exchange_review_kind_t::none;
    artifact_identity_t primary;
    artifact_identity_t related;
    bool open_requested = false;
    char issue_name[160]{};
    char issue_description[2048]{};
    char issue_remediation[2048]{};
    int issue_severity = static_cast<int>(aida::burp::severity_t::info);
    int issue_confidence = static_cast<int>(aida::burp::confidence_t::firm);
    std::string validation_error;
};

struct exchange_remove_undo_state_t {
    exchange_remove_source_t source = exchange_remove_source_t::none;
    mitm_proxy::http_exchange proxy_exchange;
    std::shared_ptr<repeater_entry_t> repeater_entry;
    std::size_t original_index = 0;
    bool open_requested = false;
    bool operation_pending = false;
    bool restored = false;
    std::string error;
};

static exchange_review_state_t s_exchange_review;
static exchange_remove_undo_state_t s_exchange_remove_undo;
static std::atomic<bool> s_common_exchange_operation_pending{false};
static std::atomic<int> s_remove_undo_completion_status{0};
static std::array<char, 512> s_remove_undo_completion_error{};
static constexpr std::size_t k_issue_evidence_limit = 1024U * 1024U;

static bool proxy_artifact_kind(artifact_kind_t kind) {
    return kind == artifact_kind_t::exchange || kind == artifact_kind_t::request ||
        kind == artifact_kind_t::response;
}

static bool repeater_artifact_kind(artifact_kind_t kind) {
    return kind == artifact_kind_t::repeater_request ||
        kind == artifact_kind_t::repeater_response;
}

static bool proxy_exchange_matches_identity(
    const mitm_proxy::http_exchange& exchange, const artifact_identity_t& identity) {
    if (exchange.id != identity.source_id || exchange.timestamp != identity.timestamp ||
        exchange.target_host != identity.target_host || exchange.target_port != identity.target_port ||
        exchange.is_tls != identity.use_tls)
        return false;
    const auto& bytes = identity.kind == artifact_kind_t::response
        ? exchange.raw_response : exchange.raw_request;
    return bytes.size() == identity.content_size && artifact_hash(bytes) == identity.content_hash;
}

static std::string bounded_export_filename(const artifact_identity_t& identity) {
    std::string name = identity.label.empty() ? "network-artifact" : identity.label;
    for (char& character : name) {
        const unsigned char value = static_cast<unsigned char>(character);
        if (!(std::isalnum(value) || character == '-' || character == '_'))
            character = '_';
    }
    if (name.size() > 96U)
        name.resize(96U);
    if (name.empty())
        name = "network-artifact";
    return name + ".bin";
}

static bool export_reviewed_artifact(const artifact_identity_t& identity,
                                     std::string& reason) {
    char path[MAX_PATH]{};
    const std::string filename = bounded_export_filename(identity);
    std::snprintf(path, sizeof(path), "%s", filename.c_str());
    static const char k_artifact_filter[] =
        "Network artifact (*.bin)\0*.bin\0"
        "HTTP message (*.http)\0*.http\0"
        "All files (*.*)\0*.*\0\0";
    if (!win32_dialog::show_save_file_dialog(g_hwnd,
            "Export reviewed network artifact", k_artifact_filter, "bin",
            path, sizeof(path), "network_view::artifact_export")) {
        reason = "Artifact export was cancelled.";
        return false;
    }
    artifact_snapshot_t snapshot;
    if (!snapshot_for(identity, snapshot, reason))
        return false;
    if (snapshot.bytes.size() > k_network_export_limit) {
        reason = "The reviewed artifact exceeds the 256 MiB export safety limit.";
        return false;
    }
    const std::string destination = path;
    const std::string task_id = register_network_operation(
        "network.exchange.save_export", "Export reviewed network artifact",
        identity.source_view_id.c_str(), destination);
    const bool posted = post_network_task(
        "network_artifact_export", aida::infra::executor::domain_t::diagnostics,
        "bounded_task",
        [bytes = std::move(snapshot.bytes), destination, task_id]() {
            bool success = false;
            std::string error;
            try {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
                aida::preview::network::record_receipt(
                    "Network artifact export",
                    destination + " " + std::to_string(bytes.size()) + " bytes");
                success = true;
#else
                success = atomic_write_export(destination, bytes.data(), bytes.size(), error);
#endif
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Reviewed artifact export failed";
            }
            if (!success && error.empty())
                error = "Reviewed artifact export failed without a destination receipt";
            finish_network_operation(task_id, success,
                success ? "Completed" : "Failed",
                success ? std::to_string(bytes.size()) +
                    " bytes written atomically to " + destination : error);
            enqueue_ui_completion([success, destination, error = std::move(error)] {
                toast_notification::push(success
                    ? "Exported reviewed artifact to " + destination
                    : (error.empty() ? "Artifact export failed" : error),
                    success ? toast_notification::toast_type_t::success
                            : toast_notification::toast_type_t::error);
            });
        }, false);
    if (!posted) {
        finish_network_operation(task_id, false, "Rejected",
            "Executor rejected reviewed artifact export");
        reason = "The Network executor rejected the artifact export.";
        return false;
    }
    reason.clear();
    return true;
}

static void stage_exchange_review(exchange_review_kind_t kind,
                                  const exchange_context_runtime_t& context) {
    s_exchange_review = {};
    s_exchange_review.kind = kind;
    s_exchange_review.primary = context.primary;
    s_exchange_review.related = context.related;
    s_exchange_review.open_requested = true;
    if (kind == exchange_review_kind_t::create_issue) {
        std::snprintf(s_exchange_review.issue_name,
            sizeof(s_exchange_review.issue_name), "Manual finding for %s",
            context.primary.label.empty() ? "network artifact"
                                          : context.primary.label.c_str());
        std::snprintf(s_exchange_review.issue_description,
            sizeof(s_exchange_review.issue_description),
            "Reviewed network evidence retained from %s.",
            context.primary.source_view_id.empty() ? "Network"
                                                   : context.primary.source_view_id.c_str());
    }
}

static bool submit_reviewed_issue(std::string& reason) {
    artifact_snapshot_t primary;
    if (!snapshot_for(s_exchange_review.primary, primary, reason))
        return false;
    artifact_snapshot_t related;
    if (s_exchange_review.related.valid() &&
        !snapshot_for(s_exchange_review.related, related, reason))
        return false;
    if (primary.bytes.size() > k_issue_evidence_limit ||
        related.bytes.size() > k_issue_evidence_limit) {
        reason = "Manual issue evidence is bounded to 1 MiB per retained artifact.";
        return false;
    }
    const artifact_identity_t primary_identity = s_exchange_review.primary;
    const artifact_identity_t related_identity = s_exchange_review.related;
    aida::burp::issue_t issue;
    issue.session_id = primary_identity.session_id;
    issue.type_key = "manual-network-artifact";
    issue.name = s_exchange_review.issue_name;
    issue.description = s_exchange_review.issue_description;
    issue.remediation = s_exchange_review.issue_remediation;
    issue.severity = static_cast<aida::burp::severity_t>(s_exchange_review.issue_severity);
    issue.confidence = static_cast<aida::burp::confidence_t>(s_exchange_review.issue_confidence);
    issue.scheme = primary_identity.use_tls ? "https" : "http";
    issue.host = primary_identity.target_host;
    issue.port = primary_identity.target_port;
    issue.src_exchange_id = primary_identity.source_id;
    issue.seen_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const artifact_identity_t* request = request_kind(primary_identity.kind)
        ? &primary_identity
        : request_kind(related_identity.kind) ? &related_identity : nullptr;
    if (request) {
        const artifact_snapshot_t& request_data = request->id == primary_identity.id
            ? primary : related;
        const std::string raw = artifact_text(request_data);
        issue.path = request_target(raw);
    }
    aida::burp::evidence_t evidence;
    if (request_kind(primary_identity.kind))
        evidence.request_raw = artifact_text(primary);
    else if (response_kind(primary_identity.kind))
        evidence.response_raw = artifact_text(primary);
    if (related_identity.valid()) {
        if (request_kind(related_identity.kind))
            evidence.request_raw = artifact_text(related);
        else if (response_kind(related_identity.kind))
            evidence.response_raw = artifact_text(related);
    }
    evidence.marker = primary_identity.id;
    issue.evidence.push_back(std::move(evidence));
    const std::string owner_view = primary_identity.source_view_id.empty()
        ? "view.network.scanner" : primary_identity.source_view_id;
    const std::string task_id = register_network_operation(
        "network.exchange.create_issue", "Create reviewed Network issue",
        owner_view.c_str(), issue.name);
    const bool posted = post_network_task(
        "network_issue_create", aida::infra::executor::domain_t::diagnostics,
        "bounded_task", [issue = std::move(issue), task_id]() mutable {
            bool retained = false;
            bool persisted = false;
            std::uint64_t issue_id = 0;
            std::string error;
            try {
                issue_id = aida::burp::issue_store::add(std::move(issue));
                retained = issue_id != 0;
                persisted = retained && aida::burp::issue_store::save_to_disk();
                if (!persisted)
                    error = aida::burp::issue_store::last_error();
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Manual Network issue creation failed";
            }
            if (persisted) {
                finish_network_operation(task_id, true, "Completed",
                    "Scanner issue #" + std::to_string(issue_id) +
                    " persisted with reviewed evidence");
            } else if (retained) {
                (void)aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::partial, 1.0f,
                    "Persistence failed",
                    "Scanner issue #" + std::to_string(issue_id) +
                    " remains in memory, but durable save failed: " +
                    (error.empty() ? "unknown storage error" : error));
            } else {
                finish_network_operation(task_id, false, "Failed",
                    error.empty() ? "Issue store rejected the finding" : error);
            }
            enqueue_ui_completion([retained, persisted, issue_id,
                                   error = std::move(error)] {
                if (retained) {
                    (void)aida::ui::application_views::open_or_focus(
                        aida::ui::stable_view_id_t("view.network.scanner"));
                    toast_notification::push(
                        persisted
                            ? "Created Scanner issue #" + std::to_string(issue_id)
                            : "Issue #" + std::to_string(issue_id) +
                                " remains in memory; durable save failed",
                        persisted ? toast_notification::toast_type_t::success
                                  : toast_notification::toast_type_t::warning);
                } else {
                    toast_notification::push(error.empty()
                        ? "Manual Network issue creation failed" : error,
                        toast_notification::toast_type_t::error);
                }
            });
        }, false);
    if (!posted) {
        finish_network_operation(task_id, false, "Rejected",
            "Executor rejected manual issue creation");
        reason = "The Network executor rejected manual issue creation.";
        return false;
    }
    reason.clear();
    return true;
}

static bool submit_reviewed_replay(std::string& reason) {
    const artifact_identity_t request_identity_value =
        request_kind(s_exchange_review.primary.kind)
            ? s_exchange_review.primary : s_exchange_review.related;
    artifact_snapshot_t request;
    if (!snapshot_for(request_identity_value, request, reason))
        return false;
    if (request.bytes.empty() || request.bytes.size() > 65535U ||
        request_identity_value.target_host.empty() ||
        request_identity_value.target_port == 0) {
        reason = "Live replay requires a bounded reviewed HTTP/1 request and verified target.";
        return false;
    }
    bool expected = false;
    if (!s_common_exchange_operation_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        reason = "Another reviewed Network artifact operation is still active.";
        return false;
    }
    const std::string target = request_identity_value.target_host + ":" +
        std::to_string(request_identity_value.target_port);
    const std::string task_id = register_network_operation(
        "network.exchange.replay", "Replay reviewed Network request",
        request_identity_value.source_view_id.c_str(), target);
    const bool posted = post_network_task(
        "network_exchange_replay", aida::infra::executor::domain_t::external_tool,
        "bounded_task",
        [identity = request_identity_value, bytes = std::move(request.bytes), task_id]() {
            bool success = false;
            int status = 0;
            std::uint64_t response_id = 0;
            std::string error;
            try {
                auto result = mitm_proxy::repeat_request(
                    identity.target_host, identity.target_port, identity.use_tls, bytes);
                success = result.success;
                status = result.exchange.response.status_code;
                response_id = result.exchange.id;
                error = std::move(result.error);
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Reviewed request replay failed";
            }
            finish_network_operation(task_id, success,
                success ? "Completed" : "Failed",
                success ? "Recorded replay exchange #" + std::to_string(response_id) +
                    " with HTTP status " + std::to_string(status)
                    : (error.empty() ? "The target returned no response" : error));
            const bool completion_queued = enqueue_ui_completion(
                [success, response_id, status, error = std::move(error)] {
                s_common_exchange_operation_pending.store(false, std::memory_order_release);
                request_proxy_runtime_snapshot(true);
                toast_notification::push(success
                    ? "Replay recorded as exchange #" + std::to_string(response_id) +
                        " (HTTP " + std::to_string(status) + ")"
                    : (error.empty() ? "Reviewed request replay failed" : error),
                    success ? toast_notification::toast_type_t::success
                            : toast_notification::toast_type_t::error);
            });
            if (!completion_queued)
                s_common_exchange_operation_pending.store(false, std::memory_order_release);
        }, false);
    if (!posted) {
        s_common_exchange_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected",
            "Executor rejected reviewed request replay");
        reason = "The Network executor rejected reviewed request replay.";
        return false;
    }
    reason.clear();
    return true;
}

static bool submit_reviewed_removal(std::string& reason) {
    artifact_snapshot_t current;
    if (!snapshot_for(s_exchange_review.primary, current, reason))
        return false;
    const artifact_identity_t identity = s_exchange_review.primary;
    if (repeater_artifact_kind(identity.kind)) {
        const auto found = std::find_if(g_state.repeater_entries.begin(),
            g_state.repeater_entries.end(), [&](const auto& entry) {
                return entry && entry->id == identity.source_id;
            });
        if (found == g_state.repeater_entries.end()) {
            reason = "The reviewed Repeater tab is no longer retained.";
            return false;
        }
        if ((*found)->in_progress.load(std::memory_order_acquire)) {
            reason = "Wait for the active Repeater send to finish before removing its tab.";
            return false;
        }
        const std::size_t index = static_cast<std::size_t>(
            std::distance(g_state.repeater_entries.begin(), found));
        s_exchange_remove_undo = {};
        s_exchange_remove_undo.source = exchange_remove_source_t::repeater;
        s_exchange_remove_undo.repeater_entry = *found;
        s_exchange_remove_undo.original_index = index;
        s_exchange_remove_undo.open_requested = true;
        const std::string task_id = register_network_operation(
            "network.exchange.remove", "Remove reviewed Repeater tab",
            "view.network.repeater", identity.label);
        g_state.repeater_entries.erase(found);
        s_repeater_selected_artifact_kinds.erase(identity.source_id);
        clear_stale_network_selection("view.network.repeater");
        publish_repeater_request_artifacts(g_state);
        g_state.repeater_selected = g_state.repeater_entries.empty() ? -1
            : static_cast<int>((std::min)(index, g_state.repeater_entries.size() - 1U));
        finish_network_operation(task_id, true, "Completed",
            "Repeater tab removed; recovery is available from the receipt");
        reason.clear();
        return true;
    }
    if (!proxy_artifact_kind(identity.kind) ||
        identity.source_view_id != "view.network.proxy") {
        reason = "This artifact source does not expose a reversible remove operation.";
        return false;
    }
    if (s_proxy_operation_pending.load(std::memory_order_acquire)) {
        reason = "Wait for the active Proxy operation before removing reviewed history.";
        return false;
    }
    bool expected = false;
    if (!s_common_exchange_operation_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        reason = "Another reviewed Network artifact operation is still active.";
        return false;
    }
    const std::string task_id = register_network_operation(
        "network.exchange.remove", "Remove reviewed proxy exchange",
        "view.network.proxy", identity.label);
    const bool posted = post_network_task(
        "network_exchange_remove", aida::infra::executor::domain_t::diagnostics,
        "bounded_task", [identity, task_id]() {
            bool success = false;
            std::size_t removed_index = 0;
            std::uint64_t previous_id = 0;
            std::uint64_t next_id = 0;
            mitm_proxy::http_exchange removed;
            std::string error;
            try {
                std::lock_guard<std::mutex> lock(mitm_proxy::g_state.history_mutex);
                auto found = std::find_if(mitm_proxy::g_state.history.begin(),
                    mitm_proxy::g_state.history.end(), [&](const auto& exchange) {
                        return exchange && proxy_exchange_matches_identity(*exchange, identity);
                    });
                if (found == mitm_proxy::g_state.history.end()) {
                    error = "Proxy history changed after review; select the current exchange again";
                } else {
                    removed_index = static_cast<std::size_t>(
                        std::distance(mitm_proxy::g_state.history.begin(), found));
                    if (found != mitm_proxy::g_state.history.begin()) {
                        const auto& previous = *(found - 1);
                        previous_id = previous ? previous->id : 0;
                    }
                    if (found + 1 != mitm_proxy::g_state.history.end()) {
                        const auto& next = *(found + 1);
                        next_id = next ? next->id : 0;
                    }
                    removed = **found;
                    mitm_proxy::g_state.history.erase(found);
                    success = true;
                }
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Reviewed proxy exchange removal failed";
            }
            if (!success) {
                finish_network_operation(task_id, false, "Failed",
                    error.empty() ? "Reviewed proxy exchange removal failed" : error);
                s_common_exchange_operation_pending.store(false, std::memory_order_release);
                enqueue_ui_completion([error] {
                    toast_notification::push(error.empty()
                        ? "Reviewed proxy exchange removal failed" : error,
                        toast_notification::toast_type_t::error);
                    request_proxy_runtime_snapshot(true);
                });
                return;
            }
            bool completion_queued = false;
            try {
                completion_queued = enqueue_ui_completion(
                    [removed_index, removed]() mutable {
                s_common_exchange_operation_pending.store(false, std::memory_order_release);
                s_exchange_remove_undo = {};
                s_exchange_remove_undo.source = exchange_remove_source_t::proxy;
                s_exchange_remove_undo.proxy_exchange = std::move(removed);
                s_exchange_remove_undo.original_index = removed_index;
                s_exchange_remove_undo.open_requested = true;
                s_proxy_selected_exchange_id = 0;
                g_state.proxy_selected = -1;
                clear_stale_network_selection("view.network.proxy");
                request_proxy_runtime_snapshot(true);
            });
            } catch (...) {
                completion_queued = false;
            }
            if (completion_queued) {
                finish_network_operation(task_id, true, "Completed",
                    "Proxy exchange removed; recovery is available from the receipt");
                return;
            }
            bool rolled_back = false;
            std::string rollback_error;
            try {
                std::lock_guard<std::mutex> lock(mitm_proxy::g_state.history_mutex);
                const bool duplicate = std::any_of(mitm_proxy::g_state.history.begin(),
                    mitm_proxy::g_state.history.end(), [&](const auto& current) {
                        return current && current->id == removed.id;
                    });
                const std::size_t insertion = (std::min)(
                    removed_index, mitm_proxy::g_state.history.size());
                const bool previous_matches = previous_id == 0 ||
                    (insertion > 0 && mitm_proxy::g_state.history[insertion - 1] &&
                     mitm_proxy::g_state.history[insertion - 1]->id == previous_id);
                const bool next_matches = next_id == 0 ||
                    (insertion < mitm_proxy::g_state.history.size() &&
                     mitm_proxy::g_state.history[insertion] &&
                     mitm_proxy::g_state.history[insertion]->id == next_id);
                if (duplicate) {
                    rollback_error = "Removed exchange identity was reused before rollback";
                } else if (!previous_matches || !next_matches) {
                    rollback_error = "Proxy history ordering changed before exact rollback";
                } else if (mitm_proxy::g_state.history.size() >=
                           mitm_proxy::g_state.config.max_history) {
                    rollback_error = "Proxy history reached capacity before exact rollback";
                } else {
                    mitm_proxy::g_state.history.insert(
                        mitm_proxy::g_state.history.begin() +
                            static_cast<std::ptrdiff_t>(insertion),
                        std::make_shared<mitm_proxy::http_exchange>(removed));
                    rolled_back = true;
                }
            } catch (const std::exception& exception) {
                rollback_error = exception.what();
            } catch (...) {
                rollback_error = "Exact proxy removal rollback failed";
            }
            s_common_exchange_operation_pending.store(false, std::memory_order_release);
            if (rolled_back) {
                finish_network_operation(task_id, false, "Reverted",
                    "Removal was rolled back because the recovery receipt could not be published");
            } else {
                (void)aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::partial, 1.0f,
                    "Recovery unavailable",
                    "Proxy exchange was removed, but its recovery receipt could not be published and exact rollback failed: " +
                    (rollback_error.empty() ? "unknown rollback error" : rollback_error));
            }
        }, false);
    if (!posted) {
        s_common_exchange_operation_pending.store(false, std::memory_order_release);
        finish_network_operation(task_id, false, "Rejected",
            "Executor rejected reviewed proxy exchange removal");
        reason = "The Network executor rejected reviewed proxy exchange removal.";
        return false;
    }
    reason.clear();
    return true;
}

static void apply_remove_undo_completion(bool success, std::string error) {
    s_common_exchange_operation_pending.store(false, std::memory_order_release);
    s_exchange_remove_undo.operation_pending = false;
    s_exchange_remove_undo.restored = success;
    s_exchange_remove_undo.error = success ? std::string() : error;
    if (success)
        publish_network_selection(exchange_artifact_identity(
            s_exchange_remove_undo.proxy_exchange,
            artifact_kind_t::request), true);
    request_proxy_runtime_snapshot(true);
    toast_notification::push(success
        ? "Removed proxy exchange restored"
        : (error.empty() ? "Proxy exchange recovery failed" : error),
        success ? toast_notification::toast_type_t::success
                : toast_notification::toast_type_t::error);
}

static void publish_remove_undo_completion_fallback(
    bool success, const std::string& error) noexcept {
    std::snprintf(s_remove_undo_completion_error.data(),
        s_remove_undo_completion_error.size(), "%s", error.c_str());
    s_remove_undo_completion_status.store(success ? 1 : 2,
        std::memory_order_release);
}

static void drain_remove_undo_completion_fallback() {
    const int status = s_remove_undo_completion_status.exchange(
        0, std::memory_order_acq_rel);
    if (status == 0)
        return;
    apply_remove_undo_completion(status == 1,
        status == 1 ? std::string()
                    : std::string(s_remove_undo_completion_error.data()));
    s_remove_undo_completion_error.fill('\0');
}

static bool submit_remove_undo(std::string& reason) {
    if (s_exchange_remove_undo.restored) {
        reason = "The removed artifact has already been restored.";
        return false;
    }
    if (s_exchange_remove_undo.source == exchange_remove_source_t::repeater) {
        const auto entry = s_exchange_remove_undo.repeater_entry;
        if (!entry || g_state.repeater_entries.size() >= k_max_repeater_entries) {
            reason = "Repeater has no capacity to restore the removed tab.";
            return false;
        }
        const bool duplicate = std::any_of(g_state.repeater_entries.begin(),
            g_state.repeater_entries.end(), [&](const auto& current) {
                return current && current->id == entry->id;
            });
        if (duplicate) {
            reason = "A Repeater tab with the removed identity already exists.";
            return false;
        }
        const std::size_t index = (std::min)(
            s_exchange_remove_undo.original_index, g_state.repeater_entries.size());
        g_state.repeater_entries.insert(
            g_state.repeater_entries.begin() + static_cast<std::ptrdiff_t>(index), entry);
        publish_repeater_request_artifacts(g_state);
        g_state.repeater_selected = static_cast<int>(index);
        s_repeater_selected_artifact_kinds[entry->id] = artifact_kind_t::repeater_request;
        publish_network_selection(repeater_artifact_identity(
            *entry, artifact_kind_t::repeater_request), true);
        const std::string task_id = register_network_operation(
            "network.exchange.remove.undo", "Restore removed Repeater tab",
            "view.network.repeater", std::to_string(entry->id));
        finish_network_operation(task_id, true, "Completed", "Repeater tab restored");
        s_exchange_remove_undo.restored = true;
        s_exchange_remove_undo.error.clear();
        reason.clear();
        return true;
    }
    if (s_exchange_remove_undo.source != exchange_remove_source_t::proxy ||
        s_exchange_remove_undo.proxy_exchange.id == 0) {
        reason = "No removed proxy exchange is available for recovery.";
        return false;
    }
    if (s_proxy_operation_pending.load(std::memory_order_acquire)) {
        reason = "Wait for the active Proxy operation before restoring reviewed history.";
        return false;
    }
    bool expected = false;
    if (!s_common_exchange_operation_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        reason = "Another reviewed Network artifact operation is still active.";
        return false;
    }
    s_exchange_remove_undo.operation_pending = true;
    s_remove_undo_completion_error.fill('\0');
    s_remove_undo_completion_status.store(0, std::memory_order_release);
    const auto exchange = s_exchange_remove_undo.proxy_exchange;
    const std::size_t original_index = s_exchange_remove_undo.original_index;
    const std::string task_id = register_network_operation(
        "network.exchange.remove.undo", "Restore removed proxy exchange",
        "view.network.proxy", std::to_string(exchange.id));
    const bool posted = post_network_task(
        "network_exchange_restore", aida::infra::executor::domain_t::diagnostics,
        "bounded_task", [exchange, original_index, task_id] {
            bool success = false;
            std::string error;
            try {
                std::lock_guard<std::mutex> lock(mitm_proxy::g_state.history_mutex);
                const bool duplicate = std::any_of(mitm_proxy::g_state.history.begin(),
                    mitm_proxy::g_state.history.end(), [&](const auto& current) {
                        return current && current->id == exchange.id;
                    });
                if (duplicate) {
                    error = "A proxy exchange with the removed identity already exists";
                } else if (mitm_proxy::g_state.history.size() >=
                           mitm_proxy::g_state.config.max_history) {
                    error = "Proxy history reached its configured capacity before recovery";
                } else {
                    const std::size_t index = (std::min)(
                        original_index, mitm_proxy::g_state.history.size());
                    mitm_proxy::g_state.history.insert(
                        mitm_proxy::g_state.history.begin() +
                            static_cast<std::ptrdiff_t>(index),
                        std::make_shared<mitm_proxy::http_exchange>(exchange));
                    std::uint64_t next = mitm_proxy::g_state.next_id.load(
                        std::memory_order_acquire);
                    while (next <= exchange.id &&
                           !mitm_proxy::g_state.next_id.compare_exchange_weak(
                               next, exchange.id + 1U, std::memory_order_acq_rel)) {
                    }
                    success = true;
                }
            } catch (const std::exception& exception) {
                error = exception.what();
            } catch (...) {
                error = "Proxy exchange recovery failed";
            }
            finish_network_operation(task_id, success,
                success ? "Completed" : "Failed",
                success ? "Proxy exchange restored at its reviewed position" : error);
            const bool completion_queued = enqueue_ui_completion(
                [success, error] {
                    apply_remove_undo_completion(success, error);
            });
            if (!completion_queued)
                publish_remove_undo_completion_fallback(success, error);
        }, false);
    if (!posted) {
        s_common_exchange_operation_pending.store(false, std::memory_order_release);
        s_exchange_remove_undo.operation_pending = false;
        finish_network_operation(task_id, false, "Rejected",
            "Executor rejected proxy exchange recovery");
        reason = "The Network executor rejected proxy exchange recovery.";
        return false;
    }
    reason.clear();
    return true;
}

static bool blank_text(const char* value) {
    if (!value || value[0] == '\0')
        return true;
    return std::all_of(value, value + std::strlen(value), [](unsigned char character) {
        return std::isspace(character) != 0;
    });
}

static void render_exchange_review_dialogs() {
    drain_remove_undo_completion_fallback();
    if (s_exchange_review.open_requested) {
        if (s_exchange_review.kind == exchange_review_kind_t::create_issue)
            aida::ui::design::open_dialog(
                "dialog.network.exchange.create_issue", "Create Network issue");
        else if (s_exchange_review.kind == exchange_review_kind_t::replay)
            aida::ui::design::open_dialog(
                "dialog.network.exchange.replay", "Review Network replay");
        else if (s_exchange_review.kind == exchange_review_kind_t::remove)
            aida::ui::design::open_dialog(
                "dialog.network.exchange.remove", "Review Network artifact removal");
        s_exchange_review.open_requested = false;
    }
    bool review_visible = false;
    if (s_exchange_review.kind == exchange_review_kind_t::create_issue) {
        review_visible = aida::ui::design::begin_dialog(
            "dialog.network.exchange.create_issue", "Create Network issue",
            ImVec2(560.f, 560.f), ImVec2(440.f, 280.f));
    } else if (s_exchange_review.kind == exchange_review_kind_t::replay) {
        review_visible = aida::ui::design::begin_dialog(
            "dialog.network.exchange.replay", "Review Network replay",
            ImVec2(560.f, 330.f), ImVec2(440.f, 280.f));
    } else if (s_exchange_review.kind == exchange_review_kind_t::remove) {
        review_visible = aida::ui::design::begin_dialog(
            "dialog.network.exchange.remove", "Review Network artifact removal",
            ImVec2(560.f, 330.f), ImVec2(440.f, 280.f));
    }
    if (review_visible) {
        const bool issue = s_exchange_review.kind == exchange_review_kind_t::create_issue;
        const char* confirm_label = issue ? "Create Issue"
            : s_exchange_review.kind == exchange_review_kind_t::replay
            ? "Send Request" : "Remove";
        const float footer = aida::ui::design::dialog_footer_reserve_height(confirm_label);
        if (aida::ui::design::begin_dialog_body("network_exchange_review_body", footer)) {
            if (issue) {
                ImGui::TextUnformatted("Create a persistent Scanner issue from the exact reviewed artifact.");
                ImGui::Spacing();
                ImGui::SetNextItemWidth(-1.f);
                ImGui::InputText("Name", s_exchange_review.issue_name,
                    sizeof(s_exchange_review.issue_name));
                ImGui::SetNextItemWidth(-1.f);
                ImGui::InputTextMultiline("Description",
                    s_exchange_review.issue_description,
                    sizeof(s_exchange_review.issue_description), ImVec2(-1.f, 96.f));
                ImGui::SetNextItemWidth(-1.f);
                ImGui::InputTextMultiline("Remediation",
                    s_exchange_review.issue_remediation,
                    sizeof(s_exchange_review.issue_remediation), ImVec2(-1.f, 72.f));
                ImGui::SetNextItemWidth(180.f);
                ImGui::Combo("Severity", &s_exchange_review.issue_severity,
                    "Information\0Low\0Medium\0High\0Critical\0");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(180.f);
                ImGui::Combo("Confidence", &s_exchange_review.issue_confidence,
                    "Tentative\0Firm\0Certain\0");
                ImGui::TextWrapped("Evidence: %s", s_exchange_review.primary.label.c_str());
            } else if (s_exchange_review.kind == exchange_review_kind_t::replay) {
                const auto* request = request_kind(s_exchange_review.primary.kind)
                    ? &s_exchange_review.primary : &s_exchange_review.related;
                ImGui::TextUnformatted("Send the exact reviewed request to its original target?");
                ImGui::Spacing();
                ImGui::Text("Target: %s:%u (%s)", request->target_host.c_str(),
                    request->target_port, request->use_tls ? "TLS" : "plaintext");
                ImGui::Text("Request: %zu bytes", request->content_size);
                ImGui::TextWrapped("The response will be retained as a new Proxy exchange. TLS verification and pin policy remain enforced.");
            } else {
                ImGui::Text("Remove %s?", s_exchange_review.primary.label.c_str());
                ImGui::Spacing();
                ImGui::TextWrapped("%s", repeater_artifact_kind(s_exchange_review.primary.kind)
                    ? "The whole reviewed Repeater tab, including its current request and response, will be removed."
                    : "The whole reviewed Proxy exchange, including request, response, tags, notes, and evidence identity, will be removed.");
                ImGui::TextWrapped("A one-step recovery receipt will remain available until it is dismissed or replaced by another removal.");
            }
            if (!s_exchange_review.validation_error.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
                    aida::ui::resolved().error), "%s",
                    s_exchange_review.validation_error.c_str());
            }
            aida::ui::design::end_dialog_body();
        }
        const bool confirm_enabled = !issue || !blank_text(s_exchange_review.issue_name);
        const auto result = aida::ui::design::dialog_footer(
            "network_exchange_review_footer", confirm_label,
            confirm_enabled, s_exchange_review.kind != exchange_review_kind_t::create_issue);
        if (result.confirmed) {
            std::string error;
            const bool accepted = issue ? submit_reviewed_issue(error)
                : s_exchange_review.kind == exchange_review_kind_t::replay
                ? submit_reviewed_replay(error) : submit_reviewed_removal(error);
            if (accepted) {
                ImGui::CloseCurrentPopup();
                s_exchange_review = {};
            } else {
                s_exchange_review.validation_error = error.empty()
                    ? "The reviewed operation was rejected." : std::move(error);
            }
        } else if (result.cancelled) {
            ImGui::CloseCurrentPopup();
            s_exchange_review = {};
        }
        ImGui::EndPopup();
    }

    if (s_exchange_remove_undo.open_requested) {
        aida::ui::design::open_dialog(
            "dialog.network.exchange.remove_receipt", "Network removal receipt");
        s_exchange_remove_undo.open_requested = false;
    }
    if (aida::ui::design::begin_dialog(
            "dialog.network.exchange.remove_receipt", "Network removal receipt",
            ImVec2(500.f, 270.f), ImVec2(420.f, 240.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height(
            "Undo Removal", "Close");
        if (aida::ui::design::begin_dialog_body(
                "network_exchange_remove_receipt_body", footer)) {
            ImGui::TextUnformatted(s_exchange_remove_undo.restored
                ? "The removed artifact was restored."
                : "The reviewed artifact was removed from its owning Network store.");
            ImGui::Spacing();
            ImGui::TextWrapped("%s", s_exchange_remove_undo.source == exchange_remove_source_t::proxy
                ? "Recovery restores the complete Proxy exchange at its reviewed position if its identity remains free and history has capacity."
                : "Recovery restores the complete Repeater tab at its reviewed position if its identity remains free and Repeater has capacity.");
            if (s_exchange_remove_undo.operation_pending)
                ImGui::TextUnformatted("Restoring reviewed artifact...");
            if (!s_exchange_remove_undo.error.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
                    aida::ui::resolved().error), "%s",
                    s_exchange_remove_undo.error.c_str());
            }
            aida::ui::design::end_dialog_body();
        }
        bool can_restore = !s_exchange_remove_undo.operation_pending &&
            !s_exchange_remove_undo.restored;
        if (s_exchange_remove_undo.source == exchange_remove_source_t::proxy)
            can_restore = can_restore &&
                !s_proxy_operation_pending.load(std::memory_order_acquire);
        if (s_exchange_remove_undo.source == exchange_remove_source_t::repeater)
            can_restore = can_restore &&
                g_state.repeater_entries.size() < k_max_repeater_entries;
        const auto result = aida::ui::design::dialog_footer(
            "network_exchange_remove_receipt_footer", "Undo Removal",
            can_restore, false, "Close", !s_exchange_remove_undo.operation_pending);
        if (result.confirmed) {
            std::string error;
            if (!submit_remove_undo(error))
                s_exchange_remove_undo.error = error.empty()
                    ? "The removed artifact could not be restored." : std::move(error);
        } else if (result.cancelled) {
            ImGui::CloseCurrentPopup();
            s_exchange_remove_undo = {};
        }
        ImGui::EndPopup();
    }
}

std::string capability_reason(network_exchange_action_t action,
                              const exchange_context_runtime_t& context) {
    if (!context.primary_current) return context.unavailable_reason.empty()
        ? "The selected artifact is stale; reopen the menu on a current row."
        : context.unavailable_reason;
    const auto* request = request_identity(context);
    const auto* response = response_identity(context);
    switch (action) {
    case network_exchange_action_t::repeater:
    case network_exchange_action_t::fuzzer:
    case network_exchange_action_t::intruder:
    case network_exchange_action_t::scanner:
    case network_exchange_action_t::sequencer: {
        if (!request) return "This action requires a retained HTTP request artifact.";
        if (request->kind == artifact_kind_t::http2_request)
            return "HTTP/2 requests must be reviewed and replayed in the HTTP/2 editor; HTTP/1 tools cannot preserve frame semantics.";
        if (request->target_host.empty() || request->target_port == 0)
            return "The request has no verified target host and port.";
        if ((action == network_exchange_action_t::intruder ||
             action == network_exchange_action_t::sequencer) &&
            (request->target_host.size() >= 256U ||
             human_request_editor::contains_binary_bytes(request->target_host)))
            return "The retained request host cannot be represented by the destination's bounded text field.";
        if (action == network_exchange_action_t::repeater)
            return g_state.repeater_entries.size() < k_max_repeater_entries
                ? std::string()
                : "Repeater retains at most 128 reviewed tabs; close a tab before opening another.";
        const std::size_t limit = action == network_exchange_action_t::sequencer
            ? 8191U : 65535U;
        if (request->content_size > limit)
            return "The retained request exceeds the destination editor's bounded capacity.";
        if (request->target_host.size() >= 256U)
            return "The retained request host exceeds the destination's bounded host field.";
        artifact_snapshot_t snapshot;
        std::string reason;
        if (!snapshot_for(*request, snapshot, reason))
            return reason.empty() ? "The retained request is no longer available." : reason;
        if (std::find(snapshot.bytes.begin(), snapshot.bytes.end(), 0) != snapshot.bytes.end())
            return "This text-based tool cannot accept a request containing embedded NUL bytes.";
        if (action == network_exchange_action_t::sequencer ||
            action == network_exchange_action_t::scanner) {
            const std::string raw = artifact_text(snapshot);
            const std::string url = artifact_url(*request, raw);
            if (url.size() >= 1024U || human_request_editor::contains_binary_bytes(url))
                return "The retained request URL cannot be represented by the destination's bounded text field.";
        }
        if (!intercept_editor_compatible(snapshot.bytes, reason))
            return reason;
        return {};
    }
    case network_exchange_action_t::session_handling: {
        if (!request) return "Session Handling requires a retained HTTP request artifact.";
        if (request->kind == artifact_kind_t::http2_request || request->raw_protocol)
            return "Session Handling accepts retained HTTP/1 requests only.";
        if (request->target_host.empty() || request->target_port == 0)
            return "The retained request has no verified target host and port.";
        if (request->target_host.size() >= 256U || request->content_size == 0 ||
            request->content_size >= 8192U)
            return "Session Handling requires a bounded target and request of at most 8191 bytes.";
        artifact_snapshot_t snapshot;
        std::string reason;
        if (!snapshot_for(*request, snapshot, reason))
            return reason.empty() ? "The retained request is no longer available." : reason;
        if (std::find(snapshot.bytes.begin(), snapshot.bytes.end(), 0) != snapshot.bytes.end())
            return "Session Handling cannot stage a request containing embedded NUL bytes.";
        return {};
    }
    case network_exchange_action_t::cookies: {
        if (!request) return "Cookie Jar context requires a retained HTTP request artifact.";
        if (request->kind == artifact_kind_t::http2_request || request->raw_protocol)
            return "Cookie Jar context accepts retained HTTP/1 requests only.";
        if (request->target_host.empty() || request->target_port == 0 ||
            request->target_host.size() >= 256U)
            return "The retained request has no bounded verified target.";
        artifact_snapshot_t snapshot;
        std::string reason;
        if (!snapshot_for(*request, snapshot, reason))
            return reason.empty() ? "The retained request is no longer available." : reason;
        const std::string path = cookie_request_path(artifact_text(snapshot));
        return path.size() <= 2048U ? std::string()
            : "The retained request path exceeds Cookie Jar's reviewed context limit.";
    }
    case network_exchange_action_t::match_replace: {
        const artifact_identity_t& source = context.primary;
        if ((!request_kind(source.kind) && !response_kind(source.kind)) || source.raw_protocol ||
            source.kind == artifact_kind_t::http2_request ||
            source.kind == artifact_kind_t::http2_response)
            return "Match and Replace context requires a retained HTTP/1 request or response.";
        if (source.target_host.empty() || source.target_port == 0 ||
            source.target_host.size() >= 256U)
            return "The retained artifact has no bounded verified target.";
        return {};
    }
    case network_exchange_action_t::compare_request_response:
        if (!request || !response)
            return "Request vs Response comparison requires both retained artifacts.";
        if (!matching_http1_pair(*request, *response))
            return "Request vs Response comparison requires a matching retained HTTP/1 exchange pair.";
        if (request->content_size > 16U * 1024U * 1024U ||
            response->content_size > 16U * 1024U * 1024U)
            return "Comparer pair handoff is bounded to 16 MiB per retained artifact.";
        if (aida::burp::comparer::list_slots().size() > 254U)
            return "Comparer retains at most 256 slots; remove a slot before adding this pair.";
        return {};
    case network_exchange_action_t::decoder: {
        if (context.primary.content_size >= sizeof(g_state.decoder_input))
            return "Decoder's reviewed input accepts at most 16383 bytes.";
        artifact_snapshot_t snapshot;
        std::string reason;
        if (!snapshot_for(context.primary, snapshot, reason))
            return reason.empty() ? "The retained artifact is no longer available." : reason;
        if (std::find(snapshot.bytes.begin(), snapshot.bytes.end(), 0) != snapshot.bytes.end())
            return "Decoder's text input cannot accept embedded NUL bytes.";
        const std::string_view decoder_text(
            snapshot.bytes.empty() ? "" :
                reinterpret_cast<const char*>(snapshot.bytes.data()),
            snapshot.bytes.size());
        if (human_request_editor::contains_binary_bytes(decoder_text))
            return "Decoder's text input requires valid UTF-8 without binary control bytes.";
        return {};
    }
    case network_exchange_action_t::camoufox:
    case network_exchange_action_t::copy_url:
    case network_exchange_action_t::copy_method:
    case network_exchange_action_t::scope_include:
    case network_exchange_action_t::scope_exclude:
        if (!request) return "The selected context has no retained HTTP request.";
        if (request->raw_protocol)
            return "Raw protocol frames have no verified HTTP URL or method; inspect or decode the artifact first.";
        return {};
    case network_exchange_action_t::copy_status:
    case network_exchange_action_t::copy_response:
        return response ? std::string() : "The selected context has no retained HTTP response.";
    case network_exchange_action_t::copy_request:
        return request ? std::string() : "The selected context has no retained HTTP request.";
    case network_exchange_action_t::copy_headers:
    case network_exchange_action_t::copy_body:
        if (context.primary.kind == artifact_kind_t::websocket_frame ||
            context.primary.kind == artifact_kind_t::websocket_editor_frame ||
            context.primary.kind == artifact_kind_t::packet || context.primary.raw_protocol)
            return "This artifact is a raw payload and has no HTTP header/body boundary.";
        return {};
    case network_exchange_action_t::save_export:
        return context.primary.content_size <= k_network_export_limit
            ? std::string()
            : "The selected artifact exceeds the 256 MiB export safety limit.";
    case network_exchange_action_t::create_issue: {
        if (context.primary.target_host.empty())
            return "Manual Scanner issues require a retained target host.";
        if (context.primary.content_size > k_issue_evidence_limit ||
            (context.related.valid() && context.related.content_size > k_issue_evidence_limit))
            return "Manual issue evidence is bounded to 1 MiB per retained artifact.";
        return {};
    }
    case network_exchange_action_t::replay_live: {
        if (!request)
            return "Live replay requires a retained HTTP request artifact.";
        if (request->kind == artifact_kind_t::http2_request)
            return "HTTP/2 replay requires the protocol editor to preserve stream semantics.";
        if (request->raw_protocol)
            return "Raw protocol payloads require their protocol-specific sender.";
        if (request->target_host.empty() || request->target_port == 0)
            return "Live replay requires a verified target host and port.";
        if (request->content_size == 0 || request->content_size > 65535U)
            return "Live replay accepts reviewed HTTP/1 requests from 1 to 65535 bytes.";
        if (s_common_exchange_operation_pending.load(std::memory_order_acquire))
            return "Another reviewed Network artifact operation is still active.";
        artifact_snapshot_t snapshot;
        std::string reason;
        if (!snapshot_for(*request, snapshot, reason))
            return reason.empty() ? "The retained request is no longer available." : reason;
        if (!intercept_editor_compatible(snapshot.bytes, reason))
            return reason;
        return {};
    }
    case network_exchange_action_t::remove:
        if (s_common_exchange_operation_pending.load(std::memory_order_acquire))
            return "Another reviewed Network artifact operation is still active.";
        if (proxy_artifact_kind(context.primary.kind) &&
            context.primary.source_view_id == "view.network.proxy")
            return s_proxy_operation_pending.load(std::memory_order_acquire)
                ? "Wait for the active Proxy operation before removing reviewed history."
                : std::string();
        if (repeater_artifact_kind(context.primary.kind)) {
            const auto found = std::find_if(g_state.repeater_entries.begin(),
                g_state.repeater_entries.end(), [&](const auto& entry) {
                    return entry && entry->id == context.primary.source_id;
                });
            if (found == g_state.repeater_entries.end())
                return "The reviewed Repeater tab is no longer retained.";
            return (*found)->in_progress.load(std::memory_order_acquire)
                ? "Wait for the active Repeater send to finish before removing its tab."
                : std::string();
        }
        return "This artifact source does not expose a reversible remove operation.";
    default:
        return {};
    }
}

bool execute_exchange_action(network_exchange_action_t action,
                             const exchange_context_runtime_t& context,
                             std::string& reason) {
    const auto* request = request_identity(context);
    const auto* response = response_identity(context);
    artifact_snapshot_t primary_snapshot;
    if (!snapshot_for(context.primary, primary_snapshot, reason)) return false;
    artifact_snapshot_t request_snapshot;
    artifact_snapshot_t response_snapshot;
    const bool needs_request = action == network_exchange_action_t::repeater ||
        action == network_exchange_action_t::fuzzer ||
        action == network_exchange_action_t::intruder ||
        action == network_exchange_action_t::scanner ||
        action == network_exchange_action_t::compare_request_response ||
        action == network_exchange_action_t::session_handling ||
        action == network_exchange_action_t::cookies ||
        action == network_exchange_action_t::sequencer ||
        action == network_exchange_action_t::camoufox ||
        action == network_exchange_action_t::copy_url ||
        action == network_exchange_action_t::copy_method ||
        action == network_exchange_action_t::copy_request ||
        action == network_exchange_action_t::scope_include ||
        action == network_exchange_action_t::scope_exclude ||
        action == network_exchange_action_t::replay_live;
    const bool needs_response = action == network_exchange_action_t::copy_status ||
        action == network_exchange_action_t::copy_response ||
        action == network_exchange_action_t::compare_request_response;
    if (needs_request && request && !snapshot_for(*request, request_snapshot, reason)) return false;
    if (needs_response && response && !snapshot_for(*response, response_snapshot, reason)) return false;
    const std::string request_raw = request ? artifact_text(request_snapshot) : std::string();
    const std::string response_raw = response ? artifact_text(response_snapshot) : std::string();
    const std::string url = request ? artifact_url(*request, request_raw) : std::string();
    const auto copy = [](const std::string& value) {
        const std::string safe = clipboard_text(value);
        ImGui::SetClipboardText(safe.c_str());
        return true;
    };
    switch (action) {
    case network_exchange_action_t::repeater:
        return request && send_artifact_to_repeater(*request, reason);
    case network_exchange_action_t::fuzzer:
        if (!request) {
            reason = "Fuzzer requires an exact retained HTTP/1 request artifact.";
            return false;
        }
        if (!intercept_editor_compatible(request_snapshot.bytes, reason))
            return false;
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.fuzzer")); !opened.ok()) {
            reason = opened.detail.empty()
                ? "The reviewed request could not open Fuzzer." : opened.detail;
            return false;
        }
        g_state.fuzz_config.host = request->target_host;
        g_state.fuzz_config.port = request->target_port;
        g_state.fuzz_config.use_tls = request->use_tls;
        g_state.fuzz_config.base_request.assign(
            request_snapshot.bytes.begin(), request_snapshot.bytes.end());
        if (++g_state.fuzz_request_revision == 0)
            ++g_state.fuzz_request_revision;
        g_state.active_tab = sub_tab_t::fuzzer;
        reason.clear();
        return true;
    case network_exchange_action_t::comparer:
        return send_artifact_to_comparer(context.primary, reason);
    case network_exchange_action_t::compare_request_response: {
        if (!request || !response || !matching_http1_pair(*request, *response)) {
            reason = "Request vs Response comparison requires a matching retained HTTP/1 exchange pair.";
            return false;
        }
        if (aida::burp::comparer::list_slots().size() > 254U) {
            reason = "Comparer retains at most 256 slots; remove a slot before adding this pair.";
            return false;
        }
        const std::string request_label = (request->label.empty() ? request->id : request->label) +
            " [Request]";
        const std::string response_label = (response->label.empty() ? response->id : response->label) +
            " [Response]";
        const std::uint64_t request_slot = aida::burp::comparer::add_slot_from_bytes(
            request_label, request_snapshot.bytes, request->id);
        if (request_slot == 0) {
            reason = "Comparer rejected the retained request: " + aida::burp::comparer::last_error();
            return false;
        }
        const std::uint64_t response_slot = aida::burp::comparer::add_slot_from_bytes(
            response_label, response_snapshot.bytes, response->id);
        if (response_slot == 0) {
            const std::string add_error = aida::burp::comparer::last_error();
            const bool request_removed = aida::burp::comparer::remove_slot(request_slot);
            reason = "Comparer rejected the retained response: " + add_error;
            if (!request_removed)
                reason += " The staged request slot remains in Comparer because rollback failed.";
            return false;
        }
        const auto opened = aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.comparer"));
        if (!opened.ok()) {
            const bool response_removed = aida::burp::comparer::remove_slot(response_slot);
            const bool request_removed = aida::burp::comparer::remove_slot(request_slot);
            reason = opened.detail.empty() ? "The reviewed pair could not open Comparer." : opened.detail;
            if (!request_removed || !response_removed) {
                reason += " Comparer rollback was incomplete; ";
                if (!request_removed && !response_removed)
                    reason += "both staged slots remain.";
                else if (!request_removed)
                    reason += "the staged request slot remains.";
                else
                    reason += "the staged response slot remains.";
            }
            return false;
        }
        reason.clear();
        return true;
    }
    case network_exchange_action_t::session_handling:
        if (!request) {
            reason = "Session Handling requires a retained HTTP/1 request.";
            return false;
        }
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.session")); !opened.ok()) {
            reason = opened.detail.empty() ? "The reviewed request could not open Session Handling." : opened.detail;
            return false;
        }
        return aida::burp::session_handler_view::stage_reviewed_context(*request, reason);
    case network_exchange_action_t::cookies:
        if (!request) {
            reason = "Cookie Jar context requires a retained HTTP/1 request.";
            return false;
        }
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.cookies")); !opened.ok()) {
            reason = opened.detail.empty() ? "The reviewed request could not open Cookie Jar." : opened.detail;
            return false;
        }
        return aida::burp::cookie_jar::stage_reviewed_context(
            *request, cookie_request_path(request_raw), reason);
    case network_exchange_action_t::match_replace:
        if (const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.match_replace")); !opened.ok()) {
            reason = opened.detail.empty() ? "The reviewed artifact could not open Match and Replace." : opened.detail;
            return false;
        }
        return aida::burp::match_replace_view::stage_reviewed_context(
            context.primary, response_kind(context.primary.kind), reason);
    case network_exchange_action_t::intruder:
        if (!request || request_raw.size() >= 65536U ||
            request_raw.find('\0') != std::string::npos) {
            reason = "Intruder requires a NUL-free reviewed request of at most 65535 bytes.";
            return false;
        }
        if (!intercept_editor_compatible(request_snapshot.bytes, reason))
            return false;
        if (!aida::burp::intruder_view::open_new_attack_with(request->target_host,
                request->target_port, request->use_tls, request_raw, reason)) return false;
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.intruder")).ok();
    case network_exchange_action_t::scanner:
        if (!request || request_raw.size() >= 65536U ||
            request_raw.find('\0') != std::string::npos) {
            reason = "Scanner requires a NUL-free reviewed request of at most 65535 bytes.";
            return false;
        }
        if (!intercept_editor_compatible(request_snapshot.bytes, reason))
            return false;
        if (!aida::burp::scanner_view::open_new_audit_with(url, request_raw)) {
            reason = "Scanner rejected the reviewed audit draft.";
            return false;
        }
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.scanner")).ok();
    case network_exchange_action_t::decoder:
        if (primary_snapshot.bytes.size() >= sizeof(g_state.decoder_input) ||
            std::find(primary_snapshot.bytes.begin(), primary_snapshot.bytes.end(), 0) !=
                primary_snapshot.bytes.end()) {
            reason = "Decoder requires NUL-free reviewed input of at most 16383 bytes.";
            return false;
        }
        {
            const std::string_view decoder_text(
                primary_snapshot.bytes.empty() ? "" :
                    reinterpret_cast<const char*>(primary_snapshot.bytes.data()),
                primary_snapshot.bytes.size());
            if (human_request_editor::contains_binary_bytes(decoder_text)) {
                reason = "Decoder's text input requires valid UTF-8 without binary control bytes.";
                return false;
            }
        }
        std::memcpy(g_state.decoder_input, primary_snapshot.bytes.data(), primary_snapshot.bytes.size());
        g_state.decoder_input[primary_snapshot.bytes.size()] = '\0';
        g_state.decoder_input_size = primary_snapshot.bytes.size();
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.decoder")).ok();
    case network_exchange_action_t::sequencer:
        if (!request || request_raw.size() >= 8192U ||
            request_raw.find('\0') != std::string::npos || url.size() >= 1024U) {
            reason = "Sequencer requires a bounded NUL-free URL and request of at most 8191 bytes.";
            return false;
        }
        if (!intercept_editor_compatible(request_snapshot.bytes, reason))
            return false;
        if (!aida::burp::sequencer_view::open_new_collection_with(url, request->target_host,
                request->target_port, request->use_tls, request_raw, reason)) return false;
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.sequencer")).ok();
    case network_exchange_action_t::camoufox:
        if (!aida::burp::browser::stage_camoufox_url(url, reason)) return false;
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.browser")).ok();
    case network_exchange_action_t::scope_include:
    case network_exchange_action_t::scope_exclude:
        if (!aida::burp::scope::stage_rule(url,
                action == network_exchange_action_t::scope_exclude
                    ? aida::burp::scope::rule_kind_t::exclude
                    : aida::burp::scope::rule_kind_t::include, reason)) return false;
        return aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.network.scope")).ok();
    case network_exchange_action_t::copy_url: return copy(url);
    case network_exchange_action_t::copy_method: return copy(request_method(request_raw));
    case network_exchange_action_t::copy_status: return copy(response_status(response_raw));
    case network_exchange_action_t::copy_request: return copy(request_raw);
    case network_exchange_action_t::copy_response: return copy(response_raw);
    case network_exchange_action_t::copy_headers:
        return copy(http_headers_body(artifact_text(primary_snapshot)).first);
    case network_exchange_action_t::copy_body:
        return copy(http_headers_body(artifact_text(primary_snapshot)).second);
    case network_exchange_action_t::copy_artifact:
        return copy(artifact_text(primary_snapshot));
    case network_exchange_action_t::save_export:
        return export_reviewed_artifact(context.primary, reason);
    case network_exchange_action_t::create_issue:
        stage_exchange_review(exchange_review_kind_t::create_issue, context);
        reason.clear();
        return true;
    case network_exchange_action_t::replay_live:
        stage_exchange_review(exchange_review_kind_t::replay, context);
        reason.clear();
        return true;
    case network_exchange_action_t::remove:
        stage_exchange_review(exchange_review_kind_t::remove, context);
        reason.clear();
        return true;
    case network_exchange_action_t::chat:
        return add_artifact_to_chat(context.primary, reason);
    case network_exchange_action_t::agent:
        return assign_artifact_to_agent(context.primary, reason);
    default:
        reason = capability_reason(action, context);
        return false;
    }
}

}

static void reset_common_exchange_actions() {
    s_exchange_review = {};
    s_exchange_remove_undo = {};
    s_common_exchange_operation_pending.store(false, std::memory_order_release);
    s_remove_undo_completion_status.store(0, std::memory_order_release);
}

static bool execute_retained_exchange_toolbar_action(
    const char* requested_action_id, artifact_identity_t primary,
    artifact_identity_t related, std::string& unavailable_reason) {
    if (!requested_action_id || requested_action_id[0] == '\0') {
        unavailable_reason = "The retained Network action identity is missing.";
        return false;
    }
    const auto descriptor = std::find_if(std::begin(k_exchange_actions),
        std::end(k_exchange_actions), [&](const auto& candidate) {
            return std::strcmp(candidate.id, requested_action_id) == 0;
        });
    if (descriptor == std::end(k_exchange_actions)) {
        unavailable_reason = "The retained Network action is not registered by the exchange provider.";
        return false;
    }
    exchange_context_runtime_t retained;
    retained.primary = std::move(primary);
    retained.related = std::move(related);
    artifact_snapshot_t snapshot;
    retained.primary_current = resolve_artifact(
        retained.primary, snapshot, retained.unavailable_reason);
    if (!retained.primary_current) {
        unavailable_reason = retained.unavailable_reason;
        return false;
    }
    const std::string capability = capability_reason(descriptor->action, retained);
    aida::ui::application_ui::retained_entity_context_t context;
    context.owner_id = "network.exchange.artifact";
    context.entity_id = retained.primary.id;
    context.entity_generation = retained.primary.timestamp ^ retained.primary.revision ^
        retained.primary.content_hash;
    context.active_view = aida::ui::stable_view_id_t(
        retained.primary.source_view_id.empty()
            ? "view.network" : retained.primary.source_view_id);
    const auto retained_identity = retained.primary;
    const auto retained_related_identity = retained.related;
    context.validate_identity = [retained_identity, retained_related_identity] {
        artifact_snapshot_t live;
        std::string reason;
        if (!resolve_artifact(retained_identity, live, reason))
            return aida::ui::capability_state_t::unavailable(reason.empty()
                ? "The network artifact was replaced; select it again" : reason);
        if (retained_related_identity.valid() &&
            !resolve_artifact(retained_related_identity, live, reason))
            return aida::ui::capability_state_t::unavailable(reason.empty()
                ? "The related network artifact was replaced; select it again" : reason);
        return aida::ui::capability_state_t::available();
    };
    aida::ui::application_ui::retained_entity_action_t action;
    action.action_id = descriptor->id;
    action.capability = capability.empty()
        ? aida::ui::capability_state_t::available()
        : aida::ui::capability_state_t::unavailable(capability);
    const auto operation = descriptor->action;
    action.invoke = [retained, operation] {
        std::string reason;
        return execute_exchange_action(operation, retained, reason)
            ? aida::ui::action_handler_result_t::completed()
            : aida::ui::action_handler_result_t::failed(reason.empty()
                ? "The retained Network operation was rejected" : reason);
    };
    context.actions.push_back(std::move(action));
    const auto result = aida::ui::application_ui::execute_retained_entity_action(
        requested_action_id, aida::ui::action_invocation_source_t::toolbar, context);
    if (!result.executed()) {
        unavailable_reason = result.message.empty()
            ? "The retained Network operation was rejected" : result.message;
        return false;
    }
    unavailable_reason.clear();
    return true;
}

void open_exchange_context(artifact_identity_t primary, artifact_identity_t related,
                           exchange_context_origin_t origin,
                           bool include_intercept_actions) {
    exchange_context_runtime_t retained;
    retained.primary = std::move(primary);
    retained.related = std::move(related);
    artifact_snapshot_t snapshot;
    retained.primary_current = resolve_artifact(
        retained.primary, snapshot, retained.unavailable_reason);
    if (!retained.primary_current) return;

    aida::ui::application_ui::retained_entity_context_t context;
    context.owner_id = "network.exchange.artifact";
    context.entity_id = retained.primary.id;
    context.entity_generation = retained.primary.timestamp ^ retained.primary.revision ^
        retained.primary.content_hash;
    context.active_view = aida::ui::stable_view_id_t(
        retained.primary.source_view_id.empty()
            ? "view.network" : retained.primary.source_view_id);
    const auto retained_identity = retained.primary;
    const auto retained_related_identity = retained.related;
    context.validate_identity = [retained_identity, retained_related_identity] {
        artifact_snapshot_t live;
        std::string reason;
        if (!resolve_artifact(retained_identity, live, reason))
            return aida::ui::capability_state_t::unavailable(reason.empty()
                ? "The network artifact was replaced; select it again" : reason);
        if (retained_related_identity.valid() &&
            !resolve_artifact(retained_related_identity, live, reason))
            return aida::ui::capability_state_t::unavailable(reason.empty()
                ? "The related network artifact was replaced; select it again" : reason);
        return aida::ui::capability_state_t::available();
    };
    const auto append = [&context](const char* id, bool enabled, const char* reason,
            std::function<aida::ui::action_handler_result_t()> invoke) {
        aida::ui::application_ui::retained_entity_action_t action;
        action.action_id = id;
        action.capability = enabled
            ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(reason);
        action.invoke = std::move(invoke);
        context.actions.push_back(std::move(action));
    };
    for (const auto& descriptor : k_exchange_actions) {
        aida::ui::application_ui::retained_entity_action_t action;
        action.action_id = descriptor.id;
        const std::string unavailable = capability_reason(descriptor.action, retained);
        action.capability = unavailable.empty()
            ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(unavailable);
        const auto operation = descriptor.action;
        action.invoke = [retained, operation] {
            std::string reason;
            return execute_exchange_action(operation, retained, reason)
                ? aida::ui::action_handler_result_t::completed()
                : aida::ui::action_handler_result_t::failed(reason.empty()
                    ? "The network operation was rejected" : reason);
        };
        context.actions.push_back(std::move(action));
    }
    if (include_intercept_actions &&
        retained.primary.kind == artifact_kind_t::intercept_request) {
        const auto publication = std::atomic_load_explicit(
            &s_intercept_runtime_snapshot, std::memory_order_acquire);
        intercept_target_identity_t target;
        if (publication) {
            const auto found = std::find_if(publication->held.begin(),
                publication->held.end(), [&](const auto& exchange) {
                    return exchange.id == retained.primary.source_id &&
                        exchange.timestamp == retained.primary.timestamp &&
                        exchange.raw_request.size() == retained.primary.content_size &&
                        artifact_hash(exchange.raw_request) == retained.primary.content_hash;
                });
            if (found != publication->held.end())
                target = intercept_target_identity(*publication, *found);
        }
        const auto append_intercept = [&](const char* id,
                                          intercept_command_t command) {
            const auto capability = intercept_command_capability_for(
                command, publication, target);
            append(id, capability.enabled,
                capability.disabled_reason.empty()
                    ? "The retained Intercept action is unavailable"
                    : capability.disabled_reason.c_str(),
                [command, publication, target] {
                    std::string reason;
                    return execute_reviewed_intercept_command(
                            command, publication, target, &reason)
                        ? aida::ui::action_handler_result_t::completed()
                        : aida::ui::action_handler_result_t::failed(reason.empty()
                            ? "The retained Intercept operation was rejected" : reason);
                });
        };
        append_intercept("network.intercept.forward_selected",
            intercept_command_t::forward_selected);
        append_intercept("network.intercept.drop_selected",
            intercept_command_t::drop_selected);
        append_intercept("network.intercept.forward_modified",
            intercept_command_t::forward_modified);
    }
    const auto* request = request_identity(retained);
    artifact_snapshot_t request_snapshot;
    std::string request_reason;
    const bool request_current = request &&
        snapshot_for(*request, request_snapshot, request_reason);
    const std::string request_raw = request_current
        ? artifact_text(request_snapshot) : std::string();
    const std::string curl = request_current
        ? curl_command(*request, request_raw) : std::string();
    append("network.exchange.copy_curl", !curl.empty(),
        request_reason.empty() ? "The retained context has no complete HTTP request"
                               : request_reason.c_str(), [curl] {
            ImGui::SetClipboardText(curl.c_str());
            return aida::ui::action_handler_result_t::completed();
        });

    if (retained.related.valid()) {
        const auto related = retained.related;
        append("network.exchange.related_comparer", true, "", [related] {
            std::string reason;
            return send_artifact_to_comparer(related, reason)
                ? aida::ui::action_handler_result_t::completed()
                : aida::ui::action_handler_result_t::failed(reason);
        });
        append("network.exchange.related_chat", true, "", [related] {
            std::string reason;
            return add_artifact_to_chat(related, reason)
                ? aida::ui::action_handler_result_t::completed()
                : aida::ui::action_handler_result_t::failed(reason);
        });
        append("network.exchange.related_agent", true, "", [related] {
            std::string reason;
            return assign_artifact_to_agent(related, reason)
                ? aida::ui::action_handler_result_t::completed()
                : aida::ui::action_handler_result_t::failed(reason);
        });
    }

    if (request && request->source_view_id == "view.network.proxy") {
        const std::string host = request->target_host;
        const std::string method = request_method(request_raw);
        append("network.proxy.filter_host", !host.empty(),
            "The retained request has no target host", [host] {
                std::snprintf(g_state.proxy_filter_text,
                    sizeof(g_state.proxy_filter_text), "%s", host.c_str());
                return aida::ui::action_handler_result_t::completed();
            });
        append("network.proxy.filter_method", !method.empty(),
            "The retained request has no HTTP method", [method] {
                std::snprintf(g_state.proxy_filter_text,
                    sizeof(g_state.proxy_filter_text), "%s", method.c_str());
                return aida::ui::action_handler_result_t::completed();
            });
        append("network.proxy.clear_filter", g_state.proxy_filter_text[0] != '\0',
            "The Proxy history filter is already clear", [] {
                g_state.proxy_filter_text[0] = '\0';
                return aida::ui::action_handler_result_t::completed();
            });
    }

    if (request && request->kind == artifact_kind_t::repeater_request) {
        const auto retained_request = *request;
        const bool can_duplicate = g_state.repeater_entries.size() < k_max_repeater_entries;
        append("network.repeater.duplicate", can_duplicate,
            "Repeater retains at most 128 reviewed tabs; close a tab before duplicating.",
            [retained_request] {
            const auto found = std::find_if(g_state.repeater_entries.begin(),
                g_state.repeater_entries.end(), [&](const auto& item) {
                    return item && item->id == retained_request.source_id;
                });
            if (found == g_state.repeater_entries.end())
                return aida::ui::action_handler_result_t::failed(
                    "The Repeater request was removed; select it again");
            const auto& source = **found;
            if (source.request_revision != retained_request.revision ||
                source.request_hash != retained_request.content_hash)
                return aida::ui::action_handler_result_t::failed(
                    "The Repeater request changed; review it again before duplicating");
            if (g_state.repeater_entries.size() >= k_max_repeater_entries)
                return aida::ui::action_handler_result_t::failed(
                    "Repeater capacity changed; close a tab before duplicating");
            auto duplicate = std::make_shared<repeater_entry_t>();
            duplicate->id = s_repeater_artifact_sequence.fetch_add(
                1, std::memory_order_relaxed);
            duplicate->source_artifact_id = retained_request.id;
            duplicate->source_session_id = retained_request.session_id;
            duplicate->host = source.host;
            duplicate->port = source.port;
            duplicate->use_tls = source.use_tls;
            duplicate->raw_request = source.raw_request;
            duplicate->request_hash = source.request_hash;
            duplicate->reviewed_source_hash = source.reviewed_source_hash;
            duplicate->review_provenance = source.review_provenance;
            duplicate->reviewed_draft = source.reviewed_draft;
            g_state.repeater_entries.push_back(std::move(duplicate));
            publish_repeater_request_artifacts(g_state);
            g_state.repeater_selected = static_cast<int>(
                g_state.repeater_entries.size()) - 1;
            return aida::ui::action_handler_result_t::completed();
        });
    }

    if (retained.primary.kind == artifact_kind_t::repeater_response) {
        const auto response = retained.primary;
        append("network.repeater.clear_response", response.content_size != 0,
            "Send the request and receive a response first", [response] {
                const auto found = std::find_if(g_state.repeater_entries.begin(),
                    g_state.repeater_entries.end(), [&](const auto& item) {
                        return item && item->id == response.source_id;
                    });
                if (found == g_state.repeater_entries.end())
                    return aida::ui::action_handler_result_t::failed(
                        "The Repeater response was removed; select it again");
                auto& entry = **found;
                if (entry.response_timestamp != response.timestamp ||
                    entry.response_hash != response.content_hash)
                    return aida::ui::action_handler_result_t::failed(
                        "The Repeater response changed; select it again");
                entry.raw_response.clear();
                entry.status_code = 0;
                entry.latency_ms = 0;
                entry.response_hash = 0;
                entry.response_timestamp = 0;
                return aida::ui::action_handler_result_t::completed();
            });
    }

    if (retained.primary.kind == artifact_kind_t::websocket_frame) {
        const std::string host = retained.primary.target_host;
        append("network.websocket.copy_host", !host.empty(),
            "The retained frame has no host", [host] {
                ImGui::SetClipboardText(host.c_str());
                return aida::ui::action_handler_result_t::completed();
            });
        append("network.websocket.filter_host", !host.empty(),
            "The retained frame has no host", [host] {
                std::snprintf(g_state.ws_filter_text,
                    sizeof(g_state.ws_filter_text), "%s", host.c_str());
                return aida::ui::action_handler_result_t::completed();
            });
        append("network.websocket.toggle_follow", true, "", [] {
            g_state.ws_auto_scroll = !g_state.ws_auto_scroll;
            return aida::ui::action_handler_result_t::completed();
        });
        append("network.websocket.open_editor", false,
            "The WebSocket Editor backend does not expose a capability-backed import operation for captured frames", {});
    }
    const auto retained_origin = origin == exchange_context_origin_t::pointer
        ? aida::ui::context_menu_open_origin_t::pointer
        : origin == exchange_context_origin_t::shift_f10
        ? aida::ui::context_menu_open_origin_t::shift_f10
        : aida::ui::context_menu_open_origin_t::menu_key;
    aida::ui::application_ui::open_retained_entity_context_menu(
        std::move(context), retained_origin);
}

void render_exchange_context() {
    aida::ui::application_ui::render_retained_entity_context_menu(
        "network.exchange.artifact");
    render_exchange_review_dialogs();
}

}
