#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/debugger_preview_runtime.hpp"
#include "../../preview/studio_semantics.hpp"
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "debugger_view.hpp"
#include "debugger_engine.hpp"
#include "debugger_interaction_context.hpp"
#include "source_debug_service.hpp"
#include "spawn_target_dialog.hpp"
#include "standalone_driver.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "zydis_disasm.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../helpers/diag_log.hpp"
#endif
#include "ui_anim.hpp"
#include "memory_map_view.hpp"
#include "../scanner/memory_interaction_context.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../scanner/pointer_scanner_view.hpp"
#include "../analysis/struct_dissector_view.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/design_system.hpp"
#include "../ui/task_center.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../ui/ui_thread_dispatcher.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "thread_view.hpp"
#endif
#include "module_view.hpp"
#include "seh_view.hpp"
#include "cfg_view.hpp"
#include "code_patcher.hpp"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "metrics.hpp"
#include "blur_layer.hpp"
#include "empty_state.hpp"
#include "no_target_overlay.hpp"
#include "responsive.hpp"
#include "skeleton.hpp"
#include "fonts.hpp"
#include "hex_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/executor.hpp"
#include "debugger_definition_store.hpp"
#else
#include "../../preview/ui_task_executor.hpp"
#endif
#include "toast_notification.hpp"
#include <fstream>
#include <filesystem>
#include <functional>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../session/analysis_session.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../helpers/win32_dialog.hpp"
#endif

#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cfloat>
#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>
#include <cmath>
#include <exception>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace debugger_view {

void open_debugger_entity_actions(const debugger_interaction::context_t& context,
	aida::ui::context_menu_open_origin_t origin);

namespace {

std::atomic<bool> g_execution_command_pending{false};
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::atomic<bool> g_target_mutation_pending{false};
#endif

constexpr std::size_t k_maximum_debugger_multi_selection = 4096;
std::array<int, static_cast<std::size_t>(debugger_interaction::kind_t::bookmark) + 1U>
	g_debugger_selection_anchors = [] {
		std::array<int, static_cast<std::size_t>(debugger_interaction::kind_t::bookmark) + 1U> value{};
		value.fill(-1);
		return value;
	}();

bool debugger_context_identity_equal(const debugger_interaction::context_t& left,
	const debugger_interaction::context_t& right) noexcept {
	return left.kind == right.kind && left.target_pid == right.target_pid &&
		left.process_creation_time_100ns == right.process_creation_time_100ns &&
		left.stop_generation == right.stop_generation && left.address == right.address &&
		left.value == right.value && left.extent == right.extent &&
		left.thread_id == right.thread_id && left.index == right.index &&
		left.primary_text == right.primary_text && left.secondary_text == right.secondary_text;
}

std::vector<debugger_interaction::context_t> debugger_action_contexts(
	const debugger_interaction::context_t& focused) {
	auto contexts = debugger_interaction::selected_set();
	const bool compatible = !contexts.empty() &&
		contexts.front().kind == focused.kind &&
		contexts.front().target_pid == focused.target_pid &&
		contexts.front().process_creation_time_100ns == focused.process_creation_time_100ns &&
		contexts.front().stop_generation == focused.stop_generation;
	if (!compatible)
		contexts.assign(1, focused);
	else if (std::none_of(contexts.begin(), contexts.end(), [&](const auto& item) {
		return debugger_context_identity_equal(item, focused);
	}))
		contexts.assign(1, focused);
	return contexts;
}

std::uint64_t debugger_action_set_hash(
	const std::vector<debugger_interaction::context_t>& contexts) noexcept {
	std::uint64_t hash = 1469598103934665603ULL;
	const auto mix = [&](std::uint64_t value) {
		hash ^= value;
		hash *= 1099511628211ULL;
	};
	for (const auto& context : contexts) {
		mix(static_cast<std::uint64_t>(context.kind));
		mix(context.target_pid);
		mix(context.process_creation_time_100ns);
		mix(context.stop_generation);
		mix(context.address);
		mix(context.value);
		mix(context.extent);
		mix(context.thread_id);
		mix(static_cast<std::uint64_t>(context.index));
		for (const char ch : context.primary_text)
			mix(static_cast<unsigned char>(ch));
		for (const char ch : context.secondary_text)
			mix(static_cast<unsigned char>(ch));
	}
	return hash;
}

std::string debugger_action_entity_id(
	const debugger_interaction::context_t& focused,
	const std::vector<debugger_interaction::context_t>& contexts) {
	return std::to_string(static_cast<int>(focused.kind)) + ":" +
		std::to_string(focused.address) + ":" + std::to_string(focused.index) + ":" +
		std::to_string(contexts.size()) + ":" +
		std::to_string(debugger_action_set_hash(contexts));
}

template <typename Factory>
void select_debugger_row(debugger_interaction::context_t context, int row_count,
	Factory&& factory, bool open_popup) {
	const auto slot = static_cast<std::size_t>(context.kind);
	if (context.kind == debugger_interaction::kind_t::none ||
		slot >= g_debugger_selection_anchors.size())
		return;
	auto existing = debugger_interaction::selected_set();
	const bool compatible = !existing.empty() &&
		existing.front().kind == context.kind &&
		existing.front().target_pid == context.target_pid &&
		existing.front().process_creation_time_100ns == context.process_creation_time_100ns &&
		existing.front().stop_generation == context.stop_generation;
	if (!compatible) {
		existing.clear();
		g_debugger_selection_anchors[slot] = -1;
	}
	if (open_popup) {
		if (std::none_of(existing.begin(), existing.end(), [&](const auto& item) {
			return debugger_context_identity_equal(item, context);
		}))
			existing.assign(1, context);
		debugger_interaction::select_set(std::move(existing), context);
		open_debugger_entity_actions(debugger_interaction::selected(),
			aida::ui::context_menu_open_origin_t::pointer);
		return;
	}
	const ImGuiIO& io = ImGui::GetIO();
	if (io.KeyShift && g_debugger_selection_anchors[slot] >= 0 && row_count > 0) {
		const int anchor = (std::clamp)(g_debugger_selection_anchors[slot], 0, row_count - 1);
		const int focus = (std::clamp)(context.index, 0, row_count - 1);
		const int direction = focus >= anchor ? 1 : -1;
		const std::size_t requested = static_cast<std::size_t>(
			focus >= anchor ? focus - anchor + 1 : anchor - focus + 1);
		const std::size_t retained = (std::min)(requested, k_maximum_debugger_multi_selection);
		std::vector<debugger_interaction::context_t> range;
		range.reserve(retained);
		int row = focus - direction * static_cast<int>(retained - 1U);
		for (std::size_t count = 0; count < retained; ++count, row += direction)
			range.push_back(factory(row));
		if (requested > retained)
			toast_notification::push("Debugger range selection is limited to 4,096 rows.",
				toast_notification::toast_type_t::warning);
		debugger_interaction::select_set(std::move(range), context);
		return;
	}
	if (io.KeyCtrl) {
		g_debugger_selection_anchors[slot] = context.index;
		const auto found = std::find_if(existing.begin(), existing.end(), [&](const auto& item) {
			return debugger_context_identity_equal(item, context);
		});
		if (found == existing.end()) {
			if (existing.size() >= k_maximum_debugger_multi_selection) {
				toast_notification::push("Debugger multi-selection is limited to 4,096 rows.",
					toast_notification::toast_type_t::warning);
				return;
			}
			existing.push_back(context);
		} else {
			existing.erase(found);
		}
		if (existing.empty()) {
			debugger_interaction::clear();
			g_debugger_selection_anchors[slot] = -1;
		} else {
			const auto focused = std::any_of(existing.begin(), existing.end(), [&](const auto& item) {
				return debugger_context_identity_equal(item, context);
			}) ? context : existing.back();
			debugger_interaction::select_set(std::move(existing), focused);
		}
		return;
	}
	g_debugger_selection_anchors[slot] = context.index;
	debugger_interaction::select(std::move(context));
}

bool debugger_row_selected(const debugger_interaction::context_t& context,
	bool scalar_fallback) {
	const auto& selected = debugger_interaction::selected_set();
	if (selected.empty() || selected.front().kind != context.kind ||
		selected.front().target_pid != context.target_pid ||
		selected.front().process_creation_time_100ns != context.process_creation_time_100ns ||
		selected.front().stop_generation != context.stop_generation)
		return scalar_fallback;
	return debugger_interaction::selected_in_set(context);
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string studio_debug_token_id(const char* entity, const std::string& identity) {
	std::string source(entity);
	source.push_back('-');
	source.append(aida::preview::semantics::entity_token(identity));
	return aida::preview::semantics::stable_id("aida.debug", source);
}

std::string studio_debug_entity_id(const char* entity,
	const debugger_interaction::context_t& context) {
	std::string identity;
	const ImGuiWindow* window = ImGui::GetCurrentWindowRead();
	const std::string_view window_name = window && window->Name ? window->Name : "";
	if (window_name.find("view.debug.registers") != std::string_view::npos)
		identity = "registers-pane:";
	else if (window_name.find("view.debug.stack") != std::string_view::npos)
		identity = "stack-pane:";
	identity += std::to_string(context.target_pid) + ":" +
		std::to_string(static_cast<unsigned>(context.kind)) + ":";
	switch (context.kind) {
	case debugger_interaction::kind_t::register_value:
	case debugger_interaction::kind_t::watch:
		identity.append(context.primary_text);
		break;
	case debugger_interaction::kind_t::thread:
		identity.append(std::to_string(context.thread_id));
		break;
	case debugger_interaction::kind_t::stack_frame:
	case debugger_interaction::kind_t::trace_record:
		identity.append(std::to_string(context.address)).append(":").append(
			std::to_string(context.index));
		break;
	case debugger_interaction::kind_t::breakpoint:
		identity.append(std::to_string(context.address)).append(":").append(
			std::to_string(context.extent)).append(":").append(
			std::to_string(context.index));
		break;
	case debugger_interaction::kind_t::handle:
		identity.append(std::to_string(context.value));
		break;
	default:
		identity.append(std::to_string(context.address));
		break;
	}
	return studio_debug_token_id(entity, identity);
}

const char* studio_debug_parent_id(const char* entity) noexcept {
	const std::string_view value(entity ? entity : "");
	const ImGuiWindow* window = ImGui::GetCurrentWindowRead();
	const std::string_view window_name = window && window->Name ? window->Name : "";
	if (value == "register" && window_name.find("view.debug.registers") != std::string_view::npos)
		return "aida.dock-window.view.debug.registers";
	if (value == "stack" && window_name.find("view.debug.stack") != std::string_view::npos)
		return "aida.dock-window.view.debug.stack";
	if (value == "instruction" || value == "register" || value == "stack")
		return "aida.dock-window.view.debug.cpu";
	if (value == "breakpoint") return "aida.dock-window.view.debug.breakpoints";
	if (value == "callstack") return "aida.dock-window.view.debug.call-stack";
	if (value == "thread") return "aida.dock-window.view.debug.threads";
	if (value == "watch") return "aida.dock-window.view.debug.watches";
	if (value == "trace") return "aida.dock-window.view.debug.trace";
	if (value == "string") return "aida.dock-window.view.debug.strings";
	if (value == "bookmark") return "aida.dock-window.view.debug.bookmarks";
	if (value == "handle") return "aida.dock-window.view.debug.handles";
	if (value == "patch") return "aida.dock-window.view.debug.patches";
	return "";
}

void register_studio_debug_entity(const char* entity, const char* semantic_type,
	const debugger_interaction::context_t& context, bool disabled = false) {
	aida::preview::semantics::register_last_item(
		studio_debug_entity_id(entity, context), semantic_type, false, disabled,
		studio_debug_parent_id(entity));
}

std::string studio_debug_execution_id(const char* action_id) {
	std::string action(action_id ? action_id : "action");
	constexpr const char prefix[] = "debugger.";
	if (action.rfind(prefix, 0) == 0)
		action.erase(0, sizeof(prefix) - 1);
	return aida::preview::semantics::stable_id("aida.debug", "execution-" + action);
}
#endif

struct code_cave_result_t {
	std::uint64_t address = 0;
	std::size_t size = 0;
	std::string module;
};

struct code_cave_publication_t {
	std::uint64_t generation = 0;
	std::uint32_t target_pid = 0;
	std::uint64_t target_stop_generation = 0;
	std::vector<code_cave_result_t> results;
	std::string detail;
};

struct code_cave_search_state_t {
	std::atomic<bool> pending{false};
	char module_filter[128] = {};
	char minimum_size[16] = "32";
	int selected = -1;
	bool open = false;
	std::uint64_t visible_generation = 0;
	std::string dialog_error;
};

code_cave_search_state_t g_code_cave_search;
std::atomic<std::uint64_t> g_code_cave_publication_sequence{1};
std::shared_ptr<const code_cave_publication_t> g_code_cave_publication =
	std::make_shared<const code_cave_publication_t>();

template <typename Fn>
bool post_debugger_ui(Fn&& fn, const char* label) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	fn();
	static_cast<void>(label);
	return true;
#else
	return aida::ui_thread::post(std::forward<Fn>(fn), "debugger", label,
		"worker_completion");
#endif
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
const char* execution_command_label(execution_command_t command) {
	switch (command) {
		case execution_command_t::launch: return "Launch target";
		case execution_command_t::run_continue: return "Continue target";
		case execution_command_t::pause: return "Pause target";
		case execution_command_t::step_over: return "Step over";
		case execution_command_t::step_into: return "Step into";
		case execution_command_t::step_out: return "Step out";
		case execution_command_t::stop: return "Stop target";
		case execution_command_t::restart: return "Restart target";
		case execution_command_t::detach: return "Detach target";
		case execution_command_t::toggle_breakpoint_at_instruction_pointer:
			return "Toggle instruction-pointer breakpoint";
	}
	return "Debugger command";
}
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool write_file_atomic_exact(const std::string& destination,
	const void* bytes, std::size_t size, std::string& error) {
	if (destination.empty() || (bytes == nullptr && size != 0)) {
		error = "Invalid export destination or payload";
		return false;
	}
	const std::filesystem::path final_path(destination);
	const std::filesystem::path temporary = final_path.wstring() + L".aida-tmp-" +
		std::to_wstring(GetCurrentProcessId()) + L"-" +
		std::to_wstring(GetTickCount64());
	HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		error = "Could not create the temporary export file (Win32 " +
			std::to_string(GetLastError()) + ")";
		return false;
	}
	const auto* cursor = static_cast<const std::uint8_t*>(bytes);
	std::size_t remaining = size;
	bool ok = true;
	while (remaining != 0) {
		const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1U << 20U));
		DWORD written = 0;
		if (!WriteFile(file, cursor, chunk, &written, nullptr) || written != chunk) {
			error = "The export write was incomplete (Win32 " +
				std::to_string(GetLastError()) + ")";
			ok = false;
			break;
		}
		cursor += written;
		remaining -= written;
	}
	if (ok && !FlushFileBuffers(file)) {
		error = "The export could not be flushed to disk (Win32 " +
			std::to_string(GetLastError()) + ")";
		ok = false;
	}
	CloseHandle(file);
	if (ok && !MoveFileExW(temporary.c_str(), final_path.c_str(),
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		error = "The completed export could not replace its destination (Win32 " +
			std::to_string(GetLastError()) + ")";
		ok = false;
	}
	if (!ok)
		static_cast<void>(DeleteFileW(temporary.c_str()));
	return ok;
}
#else
bool write_file_atomic_exact(const std::string& destination,
	const void*, std::size_t size, std::string& error) {
	if (destination.empty()) {
		error = "Preview export destination is empty";
		return false;
	}
	aida::preview::debugger::record("atomic_export",
		destination + ":" + std::to_string(size));
	return true;
}
#endif

}

bool dispatch_patch_panel_command(patch_panel_command_t command, std::string* error);

bool register_debugger_task(const aida::infra::executor::submit_result_t& submitted,
	const char* owner_view, const char* owner_action, const char* label,
	bool cancellable = false) {
	if (!submitted.submitted || submitted.task_id == 0)
		return false;
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "debugger";
	registration.owner_view = owner_view ? owner_view : "view.debug.cpu";
	registration.owner_action = owner_action ? owner_action : "debugger.task";
	registration.target = driver_bridge::attached_pid() == 0 ? std::string{} :
		"PID " + std::to_string(driver_bridge::attached_pid());
	registration.label = label ? label : "Debugger task";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.cancellation_is_safe = cancellable;
	const std::string focus_view = registration.owner_view;
	registration.callbacks.focus = [focus_view]() {
		static_cast<void>(post_debugger_ui([focus_view]() {
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(focus_view));
		}, "task_focus"));
	};
	return aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration));
}

struct debugger_task_admission_t {
	std::mutex mutex;
	std::condition_variable condition;
	unsigned state = 0;
};

aida::infra::executor::submit_result_t submit_owned_debugger_task(
	aida::infra::executor::submission_t submission, const char* owner_view,
	const char* owner_action, const char* label, bool cancellable = false) {
	auto admission = std::make_shared<debugger_task_admission_t>();
	auto body = std::move(submission.body);
	submission.body = [admission, body = std::move(body)]() mutable {
		std::unique_lock<std::mutex> lock(admission->mutex);
		admission->condition.wait(lock, [&admission] { return admission->state != 0U; });
		const bool admitted = admission->state == 1U;
		lock.unlock();
		if (admitted)
			body();
	};
	const auto publish_admission = [&admission](unsigned state) {
		{
			std::lock_guard<std::mutex> lock(admission->mutex);
			admission->state = state;
		}
		admission->condition.notify_one();
	};
	auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted)
		return submitted;
	bool registered = false;
	try {
		registered = register_debugger_task(
			submitted, owner_view, owner_action, label, cancellable);
	} catch (...) {
		registered = false;
	}
	if (!registered) {
		publish_admission(2U);
		submitted.submitted = false;
		submitted.reject_reason = "Task Center could not retain ownership";
		return submitted;
	}
	publish_admission(1U);
	return submitted;
}

static void refresh_patch_stage_parse_cache() {
	auto& ui = g_ui;
	ui.patch_stage_parsed_bytes.clear();
	ui.patch_stage_parse_valid = false;
	const char* cursor = ui.patch_stage_bytes_buf;
	while (*cursor != '\0') {
		while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n')
			++cursor;
		if (*cursor == '\0') break;
		if (cursor[1] == '\0' ||
			!std::isxdigit(static_cast<unsigned char>(cursor[0])) ||
			!std::isxdigit(static_cast<unsigned char>(cursor[1]))) {
			ui.patch_stage_parsed_bytes.clear();
			return;
		}
		char token[3] = {cursor[0], cursor[1], '\0'};
		ui.patch_stage_parsed_bytes.push_back(
			static_cast<std::uint8_t>(std::strtoul(token, nullptr, 16)));
		cursor += 2;
		if (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
			*cursor != '\r' && *cursor != '\n') {
			ui.patch_stage_parsed_bytes.clear();
			return;
		}
		if (ui.patch_stage_parsed_bytes.size() > 4096U) {
			ui.patch_stage_parsed_bytes.clear();
			return;
		}
	}
	ui.patch_stage_parse_valid = !ui.patch_stage_parsed_bytes.empty();
}

bool stage_patch_review(std::uint64_t address, std::uint64_t extent,
	const std::string& description, std::string* error) {
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address, 0, -1, 0, extent,
		description);
	return stage_patch_review(context, extent, description, error);
}

bool stage_patch_review(const debugger_interaction::context_t& expected_context,
	std::uint64_t extent, const std::string& description, std::string* error) {
	if (expected_context.address == 0) {
		if (error) *error = "The selected item has no usable address.";
		return false;
	}
	if ((expected_context.kind != debugger_interaction::kind_t::instruction &&
		expected_context.kind != debugger_interaction::kind_t::patch) ||
		!debugger_interaction::is_current(expected_context)) {
		if (error) *error =
			"The retained patch target, process identity, address, or debugger stop changed.";
		return false;
	}
	if (extent > 4096) {
		if (error) *error = "Patch review is limited to 4096 bytes per staged item.";
		return false;
	}
	g_ui.patch_stage_address = expected_context.address;
	g_ui.patch_stage_extent = extent;
	g_ui.patch_stage_bytes_buf[0] = '\0';
	g_ui.patch_stage_parsed_bytes.clear();
	g_ui.patch_stage_parse_valid = false;
	g_ui.patch_stage_exact = false;
	g_ui.patch_stage_context = expected_context;
	g_ui.patch_stage_context.extent = extent;
	g_ui.patch_stage_context.primary_text = description;
	g_ui.patch_stage_expected_before.clear();
	std::snprintf(g_ui.patch_stage_description_buf,
		sizeof(g_ui.patch_stage_description_buf), "%s", description.c_str());
	g_ui.patch_stage_open = true;
	return true;
}

bool stage_exact_patch_review(std::uint64_t address,
	const std::vector<std::uint8_t>& expected_before,
	const std::vector<std::uint8_t>& reviewed_after,
	std::uint32_t expected_pid,
	const std::string& description, std::string* error) {
	if (expected_before.empty() || reviewed_after.empty() ||
		expected_before.size() != reviewed_after.size() || reviewed_after.size() > 4096U) {
		if (error) *error = "An exact patch review requires matching before/after ranges from 1 to 4096 bytes.";
		return false;
	}
	if (expected_pid == 0 || !driver_bridge::is_loaded() ||
		driver_bridge::attached_pid() != expected_pid) {
		if (error) *error = "The proposal process is no longer the attached live patch target.";
		return false;
	}
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address, 0, -1, 0,
		reviewed_after.size(), description);
	if (context.target_pid != expected_pid) {
		if (error) *error = "The proposal process identity changed before patch review.";
		return false;
	}
	if (!stage_patch_review(context, reviewed_after.size(), description, error))
		return false;
	const std::string bytes = code_patcher::format_bytes(reviewed_after);
	std::snprintf(g_ui.patch_stage_bytes_buf, sizeof(g_ui.patch_stage_bytes_buf), "%s",
		bytes.c_str());
	refresh_patch_stage_parse_cache();
	g_ui.patch_stage_exact = true;
	g_ui.patch_stage_expected_before = expected_before;
	g_ui.active_tab = sub_tab_t::patches;
	return true;
}

bool stage_nop_review(std::uint64_t address, std::uint64_t extent,
	std::string* error) {
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address, 0, -1, 0, extent,
		"Reviewed NOP fill");
	return stage_nop_review(context, extent, error);
}

bool stage_nop_review(const debugger_interaction::context_t& expected_context,
	std::uint64_t extent, std::string* error) {
	if (extent == 0 || extent > 4096) {
		if (error) *error = "NOP review requires a selected instruction range from 1 to 4096 bytes.";
		return false;
	}
	if (!stage_patch_review(expected_context, extent, "Reviewed NOP fill", error))
		return false;
	std::string bytes;
	bytes.reserve(static_cast<std::size_t>(extent) * 3U);
	for (std::uint64_t index = 0; index < extent; ++index) {
		if (index != 0) bytes.push_back(' ');
		bytes.append("90");
	}
	std::snprintf(g_ui.patch_stage_bytes_buf, sizeof(g_ui.patch_stage_bytes_buf), "%s",
		bytes.c_str());
	refresh_patch_stage_parse_cache();
	return true;
}

bool stage_breakpoint_definition(
	const debugger_interaction::context_t& expected_context,
	breakpoint_definition_mode_t mode, std::string* error) {
	if (expected_context.kind != debugger_interaction::kind_t::breakpoint ||
		expected_context.address == 0) {
		if (error) *error = "The selected item has no usable address.";
		return false;
	}
	if (!debugger_interaction::is_current(expected_context)) {
		if (error) *error =
			"The target process identity or debugger stop changed before breakpoint review.";
		return false;
	}
	const auto capability = debugger_interaction::evaluate(
		debugger_interaction::capability_t::toggle_breakpoint, expected_context);
	if (!capability.enabled) {
		if (error) *error = capability.disabled_reason
			? capability.disabled_reason : "Breakpoint definition review is unavailable.";
		return false;
	}
	std::snprintf(g_ui.add_bp_addr_buf, sizeof(g_ui.add_bp_addr_buf), "%llX",
		static_cast<unsigned long long>(expected_context.address));
	g_ui.add_bp_staged = true;
	g_ui.add_bp_staged_mode = mode;
	g_ui.add_bp_staged_context = expected_context;
	g_ui.active_tab = sub_tab_t::breakpoints;
	if (error) error->clear();
	return true;
}

static constexpr float TAB_HEIGHT      = aida::ui::metrics::tab::primary_h;
static constexpr float ROW_HEIGHT      = aida::ui::metrics::table::row_h;
static constexpr float HEADER_H        = aida::ui::metrics::table::header_h;
static constexpr float TOOLBAR_H       = aida::ui::metrics::toolbar::height;
static constexpr int   TOOLBAR_BTN_COUNT = 8;

namespace {

struct toolbar_btn_t {
	const char* tooltip;
	int icon_id;
	bool enabled;
	bool primary;
};

inline ImU32 with_a(ImU32 c, float a) {
	return aida::ui::with_alpha(c, a);
}

inline void draw_icon(ImDrawList* dl, ImVec2 c, float r, int icon_id, ImU32 col, float thickness) {
	switch (icon_id) {
		case 0: {
			ImVec2 p0 = ImVec2(c.x - r * 0.55f, c.y - r * 0.7f);
			ImVec2 p1 = ImVec2(c.x - r * 0.55f, c.y + r * 0.7f);
			ImVec2 p2 = ImVec2(c.x + r * 0.75f, c.y);
			dl->AddTriangleFilled(p0, p1, p2, col);
			break;
		}
		case 1: {
			float bw = r * 0.32f;
			float bh = r * 0.85f;
			float gap = r * 0.20f;
			dl->AddRectFilled(ImVec2(c.x - bw - gap * 0.5f, c.y - bh),
			                  ImVec2(c.x - gap * 0.5f, c.y + bh), col, 1.5f);
			dl->AddRectFilled(ImVec2(c.x + gap * 0.5f, c.y - bh),
			                  ImVec2(c.x + gap * 0.5f + bw, c.y + bh), col, 1.5f);
			break;
		}
		case 2: {
			ImVec2 a = ImVec2(c.x - r * 0.85f, c.y - r * 0.55f);
			ImVec2 b = ImVec2(c.x + r * 0.30f, c.y - r * 0.55f);
			dl->AddLine(a, b, col, thickness);
			dl->PathLineTo(ImVec2(b.x - r * 0.30f, b.y - r * 0.30f));
			dl->PathLineTo(b);
			dl->PathLineTo(ImVec2(b.x - r * 0.30f, b.y + r * 0.30f));
			dl->PathStroke(col, 0, thickness);
			float cx = c.x + r * 0.55f;
			float cy = c.y + r * 0.30f;
			dl->AddCircleFilled(ImVec2(cx, cy), r * 0.34f, col, 16);
			dl->AddCircleFilled(ImVec2(cx, cy), r * 0.18f,
			                     IM_COL32(0, 0, 0, 200), 16);
			break;
		}
		case 3: {
			float ax0 = c.x - r * 0.85f;
			float ax1 = c.x + r * 0.30f;
			float ay1 = c.y - r * 0.55f;
			dl->AddLine(ImVec2(ax0, ay1), ImVec2(ax1, ay1), col, thickness);
			dl->PathLineTo(ImVec2(ax1 - r * 0.30f, ay1 - r * 0.30f));
			dl->PathLineTo(ImVec2(ax1, ay1));
			dl->PathLineTo(ImVec2(ax1 - r * 0.30f, ay1 + r * 0.30f));
			dl->PathStroke(col, 0, thickness);
			ImVec2 t0 = ImVec2(c.x + r * 0.40f, c.y + r * 0.10f);
			ImVec2 t1 = ImVec2(c.x + r * 0.40f, c.y + r * 0.85f);
			ImVec2 t2 = ImVec2(c.x - r * 0.20f, c.y + r * 0.475f);
			dl->AddTriangleFilled(t0, t1, t2, col);
			break;
		}
		case 4: {
			ImVec2 t0 = ImVec2(c.x - r * 0.55f, c.y + r * 0.30f);
			ImVec2 t1 = ImVec2(c.x + r * 0.55f, c.y + r * 0.30f);
			ImVec2 t2 = ImVec2(c.x, c.y - r * 0.40f);
			dl->AddTriangleFilled(t0, t1, t2, col);
			dl->AddRectFilled(ImVec2(c.x - r * 0.20f, c.y + r * 0.30f),
			                  ImVec2(c.x + r * 0.20f, c.y + r * 0.85f), col, 1.f);
			break;
		}
		case 5: {
			float s = r * 0.65f;
			dl->AddRectFilled(ImVec2(c.x - s, c.y - s),
			                  ImVec2(c.x + s, c.y + s), col, 2.f);
			break;
		}
		case 6: {
			float rad = r * 0.65f;
			float t = aida::ui::clock::seconds() * 1.4f;
			dl->PathArcTo(c, rad, 0.6f + t, 5.5f + t, 24);
			dl->PathStroke(col, 0, thickness);
			float ax = c.x + cosf(5.5f + t) * rad;
			float ay = c.y + sinf(5.5f + t) * rad;
			dl->AddTriangleFilled(
				ImVec2(ax - r * 0.20f, ay),
				ImVec2(ax + r * 0.10f, ay - r * 0.18f),
				ImVec2(ax + r * 0.10f, ay + r * 0.18f), col);
			break;
		}
		case 7: {
			float rad = r * 0.65f;
			dl->PathArcTo(c, rad, 0.5f, 5.4f, 26);
			dl->PathStroke(col, 0, thickness);
			float ax = c.x + cosf(0.5f) * rad;
			float ay = c.y + sinf(0.5f) * rad;
			dl->AddTriangleFilled(
				ImVec2(ax - r * 0.16f, ay - r * 0.20f),
				ImVec2(ax + r * 0.18f, ay),
				ImVec2(ax - r * 0.16f, ay + r * 0.20f), col);
			break;
		}
		case 8: {
			ImVec2 ll = ImVec2(c.x - r * 0.55f, c.y - r * 0.55f);
			ImVec2 lr = ImVec2(c.x + r * 0.55f, c.y + r * 0.55f);
			ImVec2 rl = ImVec2(c.x + r * 0.55f, c.y - r * 0.55f);
			ImVec2 rr = ImVec2(c.x - r * 0.55f, c.y + r * 0.55f);
			dl->AddLine(ll, lr, col, thickness);
			dl->AddLine(rl, rr, col, thickness);
			break;
		}
		default: break;
	}
}

inline ImU32 handle_type_color(const std::string& type, const aida::ui::theme_t& t) {
	if (type == "File")    return t.info;
	if (type == "Thread")  return t.warning;
	if (type == "Mutant")  return t.accent_u32;
	if (type == "Section") return t.error;
	if (type == "Key")     return t.success;
	if (type == "Event" || type == "Semaphore") return t.warning;
	return t.text_secondary;
}

inline void draw_glass_card(ImDrawList* dl, ImVec2 a, ImVec2 b, float radius,
                            float alpha, bool subtle_shadow = true) {
	const auto& t = aida::ui::resolved();
	if (subtle_shadow) {
		for (int i = 0; i < 4; ++i) {
			float s = static_cast<float>(i + 1) * 1.4f;
			float fa = 0.18f * alpha * (1.f - static_cast<float>(i) / 4.f);
			dl->AddRectFilled(
				ImVec2(a.x - s, a.y - s + 2.f),
				ImVec2(b.x + s, b.y + s + 2.f),
				IM_COL32(0, 0, 0, static_cast<int>(fa * 60.f)),
				radius + s);
		}
	}
	dl->AddRectFilled(a, b, with_a(t.panel_bg, alpha), radius);
	dl->AddRectFilled(a, b, with_a(t.glass_tint, alpha * 0.55f), radius);
	dl->AddRect(a, b, with_a(t.border_subtle, alpha), radius, 0, 1.f);
}

inline void draw_panel_header(ImDrawList* dl, float x, float y, float w,
                              const char* label, float alpha) {
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
	                  with_a(t.panel_header, alpha));
	dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
		with_a(t.accent_grad_top, alpha * 0.18f),
		with_a(t.accent_grad_top, alpha * 0.05f),
		with_a(t.accent_grad_bot, alpha * 0.05f),
		with_a(t.accent_grad_bot, alpha * 0.18f));
	dl->AddLine(ImVec2(x, y + HEADER_H - 0.5f),
	            ImVec2(x + w, y + HEADER_H - 0.5f),
	            with_a(t.border_subtle, alpha));
	ImFont* font = aida::ui::fonts::caption();
	if (!font) font = ImGui::GetFont();
	const float font_size = aida::ui::fonts::size_or(font, 13.5f);
	dl->AddText(font, font_size, ImVec2(x + 10.f, y + (HEADER_H - font_size) * 0.5f),
	            with_a(t.text_secondary, alpha), label);
}

inline void draw_table_header(ImDrawList* dl, float x, float y, float w,
                              const ui_anim::table_col_t* cols, int n,
                              float alpha) {
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
	                  with_a(t.panel_header, alpha));
	dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
		with_a(t.accent_grad_top, alpha * 0.10f),
		with_a(t.accent_grad_top, alpha * 0.04f),
		with_a(t.accent_grad_bot, alpha * 0.04f),
		with_a(t.accent_grad_bot, alpha * 0.10f));
	dl->AddLine(ImVec2(x, y + HEADER_H - 0.5f),
	            ImVec2(x + w, y + HEADER_H - 0.5f),
	            with_a(t.border_subtle, alpha));
	ImFont* font = aida::ui::fonts::caption();
	if (!font) font = ImGui::GetFont();
	const float font_size = aida::ui::fonts::size_or(font, 13.5f);
	float cx = x + 10.f;
	for (int i = 0; i < n; ++i) {
		ImVec2 sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, cols[i].label);
		dl->AddText(font, font_size,
			ImVec2(cx, y + (HEADER_H - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), cols[i].label);
		cx += cols[i].width;
		if (i < n - 1)
			dl->AddLine(ImVec2(cx - 4.f, y + 6.f),
			            ImVec2(cx - 4.f, y + HEADER_H - 6.f),
			            with_a(t.border_subtle, alpha * 0.6f));
	}
}

inline bool draw_row_bg(ImDrawList* dl, float x, float y, float w, float h,
                        bool selected, bool hovered, int idx,
                        float entrance, float alpha) {
	const auto& t = aida::ui::resolved();
	float ra = alpha * entrance;
	if (ra < 0.01f) return hovered;
	if (selected) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.selection, ra), 4.f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h),
		                  with_a(t.accent_u32, ra * 0.95f));
		for (int g = 0; g < 3; ++g) {
			float gw = 6.f + static_cast<float>(g) * 4.f;
			float ga = (0.10f - static_cast<float>(g) * 0.030f) * ra;
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + gw, y + h),
			                  with_a(t.accent_glow, ga * 6.f));
		}
	} else if (hovered) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.hover_wash, ra), 4.f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 2.f, y + h),
		                  with_a(t.accent_dim, ra));
	} else if (idx & 1) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.hover_wash, ra * 0.25f));
	}
	return hovered;
}

}

execution_capability_t execution_capability(execution_command_t command) {
	if (g_execution_command_pending.load(std::memory_order_acquire))
		return {false, "Another debugger execution command is still pending"};
	const std::uint32_t pid = driver_bridge::attached_pid();
	const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
	const bool attached = pid != 0;
	const bool running = status == debugger_engine::dbg_status_t::running;
	const bool paused = status == debugger_engine::dbg_status_t::paused ||
		status == debugger_engine::dbg_status_t::stepping;
	switch (command) {
		case execution_command_t::launch:
			return attached
				? execution_capability_t{false, "Detach or stop the current target before launching another process"}
				: execution_capability_t{true, nullptr};
		case execution_command_t::run_continue:
			return !attached || paused || status == debugger_engine::dbg_status_t::idle
				? execution_capability_t{true, nullptr}
				: execution_capability_t{false, running ? "The target is already running" : "The target cannot continue from its current state"};
		case execution_command_t::pause:
			return running ? execution_capability_t{true, nullptr}
				: execution_capability_t{false, attached ? "The target is not running" : "Attach or launch a target first"};
		case execution_command_t::step_over:
		case execution_command_t::step_into:
		case execution_command_t::step_out:
			return paused ? execution_capability_t{true, nullptr}
				: execution_capability_t{false, attached ? "Pause the target before stepping" : "Attach or launch a target first"};
		case execution_command_t::stop:
		case execution_command_t::detach:
			return attached ? execution_capability_t{true, nullptr}
				: execution_capability_t{false, "No live target is attached"};
		case execution_command_t::restart:
			return attached ? execution_capability_t{true, nullptr}
				: execution_capability_t{false, "Launch a target before using Restart"};
		case execution_command_t::toggle_breakpoint_at_instruction_pointer:
			if (!attached)
				return {false, "Attach or launch a target first"};
			if (!paused)
				return {false, "Pause the target before changing a breakpoint at RIP"};
			return debugger_engine::cached_registers().rip != 0
				? execution_capability_t{true, nullptr}
				: execution_capability_t{false, "The instruction pointer is unavailable"};
	}
	return {false, "Unknown debugger command"};
}

bool execute_command(execution_command_t command, std::string* error) {
	auto fail = [&](std::string detail) {
		if (error) *error = std::move(detail);
		return false;
	};
	if (error) error->clear();
	const auto capability = execution_capability(command);
	if (!capability.enabled)
		return fail(capability.disabled_reason ? capability.disabled_reason : "Debugger command is unavailable");

	const std::uint32_t pid = driver_bridge::attached_pid();
	const auto request_launch_dialog = [] {
		const auto context = disasm_view::capture_selected_workspace();
		const std::string path = context.workspace
			? context.workspace->identity().normalized_source_path() : std::string{};
		if (!path.empty())
			spawn_target_dialog::request_open(path);
		else
			spawn_target_dialog::request_open();
	};
	if (command == execution_command_t::launch ||
		(command == execution_command_t::run_continue && pid == 0)) {
		if (!spawn_target_dialog::is_open())
			request_launch_dialog();
		return true;
	}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool expected = false;
	if (!g_execution_command_pending.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel))
		return fail("Another debugger execution command is still pending");
	const std::uint64_t generation = debugger_interaction::current_stop_generation();
	struct command_result_t {
		bool ok = false;
		bool restart = false;
		debugger_engine::dbg_status_t final_status = debugger_engine::dbg_status_t::idle;
		std::string error;
	};
	auto result = std::make_shared<command_result_t>();
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = execution_command_label(command);
	submission.thread_class = "debugger_target_control";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.target_pid = pid;
	submission.generation = generation;
	submission.ui_access_policy = "post_completion_only";
	submission.failure_policy = "fail_closed";
	submission.body = [command, pid, generation, result]() {
		auto fail_worker = [&](std::string detail) {
			result->error = std::move(detail);
		};
		if (driver_bridge::attached_pid() != pid ||
			debugger_interaction::current_stop_generation() != generation) {
			fail_worker("The target changed before the debugger command started");
		} else {
			switch (command) {
				case execution_command_t::run_continue:
					result->ok = debugger_engine::run_target();
					break;
				case execution_command_t::pause:
					result->ok = debugger_engine::pause_target();
					break;
				case execution_command_t::step_over:
					result->ok = debugger_engine::step_over();
					break;
				case execution_command_t::step_into:
					result->ok = debugger_engine::step_into();
					break;
				case execution_command_t::step_out:
					result->ok = debugger_engine::step_out();
					break;
				case execution_command_t::stop:
				case execution_command_t::restart: {
					HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
					if (process == nullptr) {
						fail_worker("Windows denied access to terminate the target");
						break;
					}
					const BOOL terminated = TerminateProcess(process, 0xDEADu);
					const DWORD terminate_error = terminated ? ERROR_SUCCESS : GetLastError();
					if (terminated)
						static_cast<void>(WaitForSingleObject(process, 2000));
					CloseHandle(process);
					if (!terminated) {
						char detail[96];
						std::snprintf(detail, sizeof(detail),
							"Target termination failed (Win32 %lu)",
							static_cast<unsigned long>(terminate_error));
						fail_worker(detail);
						break;
					}
					stealth_engine::disable_for_detach(pid,
						command == execution_command_t::restart
							? "debugger_view.command_restart"
							: "debugger_view.command_stop");
					driver_bridge::detach();
					if (driver_bridge::attached_pid() != 0) {
						fail_worker("The target exited but the driver attachment did not clear");
						break;
					}
					result->ok = true;
					result->restart = command == execution_command_t::restart;
					result->final_status = debugger_engine::dbg_status_t::terminated;
					break;
				}
				case execution_command_t::detach:
					stealth_engine::disable_for_detach(pid, "debugger_view.command_detach");
					driver_bridge::detach();
					if (driver_bridge::attached_pid() != 0)
						fail_worker("The driver did not confirm target detachment");
					else {
						result->ok = true;
						result->final_status = debugger_engine::dbg_status_t::idle;
					}
					break;
				case execution_command_t::toggle_breakpoint_at_instruction_pointer: {
					const std::uint64_t rip = debugger_engine::cached_registers().rip;
					auto snapshot = debugger_engine::snapshot_breakpoints();
					int existing = -1;
					for (std::size_t index = 0; index < snapshot.size(); ++index) {
						if (!snapshot[index].is_internal && snapshot[index].address == rip &&
							snapshot[index].type == debugger_engine::bp_type_t::software) {
							existing = static_cast<int>(index);
							break;
						}
					}
					result->ok = existing >= 0 ? debugger_engine::remove_breakpoint(existing)
						: debugger_engine::add_breakpoint(rip) >= 0;
					break;
				}
				case execution_command_t::launch:
					break;
			}
			if (!result->ok && result->error.empty()) {
				result->error = debugger_engine::last_error();
				if (result->error.empty())
					result->error = "The debugger engine rejected the command";
			}
		}
		const bool posted = post_debugger_ui([result]() {
			if (result->ok) {
				if (result->final_status == debugger_engine::dbg_status_t::terminated ||
					result->final_status == debugger_engine::dbg_status_t::idle)
					debugger_engine::g_state.status.store(result->final_status,
						std::memory_order_release);
				debugger_interaction::advance_stop_generation();
				if (result->restart && !spawn_target_dialog::is_open()) {
					const auto context = disasm_view::capture_selected_workspace();
					const std::string path = context.workspace
						? context.workspace->identity().normalized_source_path() : std::string{};
					if (path.empty()) spawn_target_dialog::request_open();
					else spawn_target_dialog::request_open(path);
				}
			} else {
				toast_notification::push(result->error,
					toast_notification::toast_type_t::error);
			}
			g_execution_command_pending.store(false, std::memory_order_release);
		}, "execution_completion");
		if (!posted) {
			g_execution_command_pending.store(false, std::memory_order_release);
			throw std::runtime_error("Debugger command completion could not be published to the UI thread");
		}
		if (!result->ok)
			throw std::runtime_error(result->error.empty()
				? "Debugger command failed" : result->error);
	};
	const auto submitted = submit_owned_debugger_task(std::move(submission),
		"view.debug.cpu", "debugger.execution", execution_command_label(command), false);
	if (!submitted.submitted) {
		g_execution_command_pending.store(false, std::memory_order_release);
		return fail("The debugger executor rejected the command: " + submitted.reject_reason);
	}
	return true;
#else
	bool ok = false;
	switch (command) {
		case execution_command_t::launch:
			if (!spawn_target_dialog::is_open())
				request_launch_dialog();
			return true;
		case execution_command_t::run_continue:
			if (pid == 0) {
				if (!spawn_target_dialog::is_open())
					request_launch_dialog();
				return true;
			}
			ok = debugger_engine::run_target();
			break;
		case execution_command_t::pause:
			ok = debugger_engine::pause_target();
			break;
		case execution_command_t::step_over:
			ok = debugger_engine::step_over();
			break;
		case execution_command_t::step_into:
			ok = debugger_engine::step_into();
			break;
		case execution_command_t::step_out:
			ok = debugger_engine::step_out();
			break;
		case execution_command_t::stop:
		case execution_command_t::restart: {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			stealth_engine::disable_for_detach(pid, command == execution_command_t::restart
				? "debugger_view.command_restart" : "debugger_view.command_stop");
			driver_bridge::detach();
#else
			HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
			if (process == nullptr)
				return fail("Windows denied access to terminate the target");
			const BOOL terminated = TerminateProcess(process, 0xDEADu);
			const DWORD terminate_error = terminated ? ERROR_SUCCESS : GetLastError();
			if (terminated)
				WaitForSingleObject(process, 2000);
			CloseHandle(process);
			if (!terminated) {
				char detail[96];
				std::snprintf(detail, sizeof(detail), "Target termination failed (Win32 %lu)",
					static_cast<unsigned long>(terminate_error));
				return fail(detail);
			}
			stealth_engine::disable_for_detach(pid, command == execution_command_t::restart
				? "debugger_view.command_restart" : "debugger_view.command_stop");
			driver_bridge::detach();
#endif
			if (driver_bridge::attached_pid() != 0)
				return fail("The target exited but the driver attachment did not clear");
			debugger_engine::g_state.status.store(debugger_engine::dbg_status_t::terminated,
				std::memory_order_release);
			debugger_interaction::advance_stop_generation();
			if (command == execution_command_t::restart && !spawn_target_dialog::is_open())
				request_launch_dialog();
			return true;
		}
		case execution_command_t::detach:
			stealth_engine::disable_for_detach(pid, "debugger_view.command_detach");
			driver_bridge::detach();
			if (driver_bridge::attached_pid() != 0)
				return fail("The driver did not confirm target detachment");
			debugger_engine::g_state.status.store(debugger_engine::dbg_status_t::idle,
				std::memory_order_release);
			debugger_interaction::advance_stop_generation();
			return true;
		case execution_command_t::toggle_breakpoint_at_instruction_pointer: {
			const std::uint64_t rip = debugger_engine::cached_registers().rip;
			auto snapshot = debugger_engine::snapshot_breakpoints();
			int existing = -1;
			for (std::size_t index = 0; index < snapshot.size(); ++index) {
				if (!snapshot[index].is_internal && snapshot[index].address == rip &&
					snapshot[index].type == debugger_engine::bp_type_t::software) {
					existing = static_cast<int>(index);
					break;
				}
			}
			ok = existing >= 0 ? debugger_engine::remove_breakpoint(existing)
				: debugger_engine::add_breakpoint(rip) >= 0;
			break;
		}
	}
	if (!ok) {
		const std::string detail = debugger_engine::last_error();
		return fail(detail.empty() ? "The debugger engine rejected the command" : detail);
	}
	debugger_interaction::advance_stop_generation();
	return true;
#endif
}

execution_capability_t patch_panel_capability(patch_panel_command_t command) {
	if (command == patch_panel_command_t::stage)
		return debugger_engine::cached_registers().rip != 0
			? execution_capability_t{true, nullptr}
			: execution_capability_t{false, "No current instruction address is available"};
	if (command == patch_panel_command_t::find_code_caves) {
		if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0)
			return {false, "Attach a live target before searching for code caves"};
		if (debugger_engine::g_state.status.load(std::memory_order_acquire) !=
			debugger_engine::dbg_status_t::paused)
			return {false, "Pause the attached target before searching for code caves"};
		return g_code_cave_search.pending.load(std::memory_order_acquire)
			? execution_capability_t{false, "A code-cave search is already running"}
			: execution_capability_t{true, nullptr};
	}
	const auto snapshot = code_patcher::published_snapshot();
	if (!snapshot)
		return {false, "The immutable Patches publication is unavailable"};
	if (code_patcher::g_state.publication_failure_generation.load(
			std::memory_order_acquire) != 0)
		return {false, "The Patches publication could not be refreshed; preserve the authoritative patch state and retry after memory pressure clears"};
	switch (command) {
		case patch_panel_command_t::stage:
		case patch_panel_command_t::find_code_caves:
			break;
		case patch_panel_command_t::revert_all:
			if (snapshot->total_count == 0)
				return {false, "No patch definitions are available"};
			return snapshot->total_count <= 65536U
				? execution_capability_t{true, nullptr}
				: execution_capability_t{false, "The patch set exceeds the 65,536-entry review bound"};
		case patch_panel_command_t::save_patchset:
			if (snapshot->total_count == 0)
				return {false, "No patch definitions are available"};
			return snapshot->total_count <= 4096U
				? execution_capability_t{true, nullptr}
				: execution_capability_t{false, "The patch set exceeds the 4,096-entry export bound"};
	}
	return {false, "Unknown Patches panel action"};
}

bool execute_patch_panel_command(patch_panel_command_t command, std::string* error) {
	const auto capability = patch_panel_capability(command);
	if (!capability.enabled) {
		if (error) *error = capability.disabled_reason ? capability.disabled_reason
			: "The Patches panel action is unavailable";
		return false;
	}
	const bool was_open = aida::ui::application_views::is_open(
		aida::ui::stable_view_id_t("view.debug.patches"));
	const auto opened = aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("view.debug.patches"));
	if (!opened.ok()) {
		if (error) *error = opened.detail.empty()
			? "The canonical Patches view could not be opened"
			: opened.detail;
		return false;
	}
	if (dispatch_patch_panel_command(command, error))
		return true;
	if (!was_open)
		static_cast<void>(aida::ui::application_views::close(
			aida::ui::stable_view_id_t("view.debug.patches")));
	return false;
}

namespace {

inline float run_toolbar_height() {
	const auto metrics = aida::ui::design::metrics();
	return (std::max)(TOOLBAR_H,
		metrics.control_height + (std::max)(metrics.spacing_sm,
			aida::ui::scale_px(8.f, metrics.scale)));
}

inline void draw_run_toolbar(ImDrawList* dl, float ox, float oy, float width, float alpha) {
	if (width <= 0.f)
		return;
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;

	debugger_engine::dbg_status_t status = debugger_engine::g_state.status.load();
	bool running = (status == debugger_engine::dbg_status_t::running);
	bool paused  = (status == debugger_engine::dbg_status_t::paused
	             || status == debugger_engine::dbg_status_t::stepping);
	const bool command_pending = g_execution_command_pending.load(std::memory_order_acquire);

	static constexpr const char* action_ids[TOOLBAR_BTN_COUNT] = {
		"debugger.run_continue", "debugger.pause", "debugger.step_over",
		"debugger.step_into", "debugger.step_out", "debugger.stop",
		"debugger.restart", "debugger.detach"
	};
	std::array<aida::ui::application_ui::action_presentation_t, TOOLBAR_BTN_COUNT> presentations;
	std::array<std::string, TOOLBAR_BTN_COUNT> tooltips;
	toolbar_btn_t btns[TOOLBAR_BTN_COUNT]{};
	for (int i = 0; i < TOOLBAR_BTN_COUNT; ++i) {
		presentations[static_cast<std::size_t>(i)] =
			aida::ui::application_ui::present_action(action_ids[i]);
		const auto& presentation = presentations[static_cast<std::size_t>(i)];
		tooltips[static_cast<std::size_t>(i)] = presentation.label;
		if (!presentation.shortcut.empty()) {
			tooltips[static_cast<std::size_t>(i)].append(" (");
			tooltips[static_cast<std::size_t>(i)].append(presentation.shortcut);
			tooltips[static_cast<std::size_t>(i)].push_back(')');
		}
		if (!presentation.enabled && !presentation.disabled_reason.empty()) {
			tooltips[static_cast<std::size_t>(i)].append("\n");
			tooltips[static_cast<std::size_t>(i)].append(presentation.disabled_reason);
		}
		if (command_pending) {
			tooltips[static_cast<std::size_t>(i)].append(
				"\nAnother debugger execution command is pending.");
		}
		btns[i] = {tooltips[static_cast<std::size_t>(i)].c_str(), i,
			presentation.enabled && !command_pending, i == 0};
	}
	if (command_pending) {
		for (auto& button : btns)
			button.enabled = false;
	}

	const auto metrics = aida::ui::design::metrics();
	const float scale = metrics.scale;
	const float toolbar_height = run_toolbar_height();
	const float margin = (std::max)(metrics.spacing_sm, aida::ui::scale_px(8.f, scale));
	const float button_width = aida::ui::scale_px(38.f, scale);
	const float button_height = metrics.control_height;
	const float button_gap = metrics.spacing_xs;
	const float overflow_width = (std::max)(aida::ui::scale_px(48.f, scale),
		ImGui::CalcTextSize("More").x + metrics.spacing_lg * 2.f);
	float pad_y = (toolbar_height - button_height) * 0.5f;
	float bx = ox + margin;
	float by = oy + pad_y;

	ImFont* status_font = aida::ui::fonts::caption();
	if (!status_font) status_font = ImGui::GetFont();
	const float status_font_size = aida::ui::fonts::size_or(status_font, 13.5f);
	const char* status_label = "IDLE";
	aida::ui::pill_kind_t status_kind = aida::ui::pill_kind_t::neutral;
	if (running) {
		status_label = "RUNNING";
		status_kind = aida::ui::pill_kind_t::success;
	} else if (paused) {
		status_label = "PAUSED";
		status_kind = aida::ui::pill_kind_t::warning;
	} else if (status == debugger_engine::dbg_status_t::terminated) {
		status_label = "STOPPED";
		status_kind = aida::ui::pill_kind_t::error;
	}
	const ImVec2 status_size = status_font->CalcTextSizeA(
		status_font_size, FLT_MAX, 0.f, status_label);
	const float status_height = (std::max)(aida::ui::scale_px(16.f, scale),
		status_font_size + aida::ui::scale_px(2.f, scale));
	const float status_width = status_size.x + aida::ui::scale_px(22.f, scale);
	const bool show_status = width >= aida::ui::scale_px(260.f, scale);
	const float usable_width = (std::max)(1.f, width - margin * 2.f);
	const float status_reserve = show_status
		? status_width + button_gap : 0.f;
	const float action_budget = (std::max)(1.f, usable_width - status_reserve);
	const float all_actions_width =
		static_cast<float>(TOOLBAR_BTN_COUNT) * button_width +
		static_cast<float>(TOOLBAR_BTN_COUNT - 1) * button_gap;
	const bool has_overflow = all_actions_width > action_budget;
	const float effective_overflow_width = has_overflow
		? (std::min)(overflow_width, action_budget) : 0.f;
	int direct_count = TOOLBAR_BTN_COUNT;
	if (has_overflow) {
		const float direct_budget = (std::max)(0.f,
			action_budget - effective_overflow_width - button_gap);
		direct_count = 0;
		float used = 0.f;
		while (direct_count < TOOLBAR_BTN_COUNT) {
			const float candidate = used + (direct_count > 0 ? button_gap : 0.f) +
				button_width;
			if (candidate > direct_budget)
				break;
			used = candidate;
			++direct_count;
		}
	}
	const float direct_width = direct_count > 0
		? static_cast<float>(direct_count) * button_width +
			static_cast<float>(direct_count - 1) * button_gap
		: 0.f;
	const float action_strip_width = direct_width +
		(has_overflow ? (direct_count > 0 ? button_gap : 0.f) +
			effective_overflow_width : 0.f);
	const float card_pad = aida::ui::scale_px(4.f, scale);
	draw_glass_card(dl, ImVec2(bx - card_pad, by - card_pad),
		ImVec2(bx + action_strip_width + card_pad, by + button_height + card_pad),
		aida::ui::scale_px(10.f, scale), alpha);

	float dt = aida::ui::clock::dt();
	float pulse = running ? aida::ui::clock::pulse(1.5f, 0.f, 1.f) : 0.f;

	for (int i = 0; i < direct_count; ++i) {
		const auto& btn = btns[i];
		float btn_x = bx + static_cast<float>(i) * (button_width + button_gap);
		float btn_y = by;
		ImVec2 ba(btn_x, btn_y);
		ImVec2 bb(btn_x + button_width, btn_y + button_height);

		ImGui::SetCursorScreenPos(ba);
		ImGui::PushID(i);
		ImGui::InvisibleButton("##tbn", ImVec2(button_width, button_height));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			studio_debug_execution_id(action_ids[i]), "debugger-execution-action",
			false, !btn.enabled, "aida.dock-window.view.debug.cpu");
#endif
		const bool item_hovered = ImGui::IsItemHovered();
		bool hovered = item_hovered && btn.enabled;
		bool clicked = ImGui::IsItemClicked() && btn.enabled;
		bool held    = ImGui::IsItemActive()  && btn.enabled;
		ImGui::PopID();

		float h_v = ui.toolbar.hover[i].tick(hovered, dt, aida::motion::spring::balanced);
		float p_v = ui.toolbar.press[i].tick(held, dt);

		float press_scale = 1.f - (1.f - 0.95f) * p_v;
		float lift  = (h_v * 1.0f - p_v * 1.2f) * scale;
		float bw_h = button_width * 0.5f;
		float bh_h = button_height * 0.5f;
		ImVec2 ca(btn_x + bw_h - bw_h * press_scale,
			btn_y + bh_h - bh_h * press_scale - lift);
		ImVec2 cb(btn_x + bw_h + bw_h * press_scale,
			btn_y + bh_h + bh_h * press_scale - lift);

		float btn_alpha = btn.enabled ? alpha : alpha * 0.42f;

		ImU32 border;
		ImU32 icon_col;
		if (btn.primary) {
			float pulse_mod = running ? (pulse * 0.4f) : 0.f;
			ImU32 grad_t = aida::ui::mix(t.accent_grad_top, t.accent_hover, h_v * 0.5f + pulse_mod);
			ImU32 grad_b = aida::ui::mix(t.accent_grad_bot, t.accent_u32,   h_v * 0.5f + pulse_mod);
			dl->AddRectFilledMultiColor(ca, cb,
				with_a(grad_t, btn_alpha),
				with_a(grad_t, btn_alpha),
				with_a(grad_b, btn_alpha),
				with_a(grad_b, btn_alpha));
			border = with_a(t.accent_hover, btn_alpha);
			icon_col = with_a(IM_COL32(255, 255, 255, 245), btn_alpha);
			if (running) {
				float pa = pulse * 0.55f * btn_alpha;
				for (int g = 0; g < 4; ++g) {
					float spread = aida::ui::scale_px(
						1.5f + static_cast<float>(g) * 1.4f, scale);
					dl->AddRect(ImVec2(ca.x - spread, ca.y - spread),
					            ImVec2(cb.x + spread, cb.y + spread),
					            with_a(t.accent_glow, pa * (1.f - static_cast<float>(g) / 4.f)),
					            aida::ui::scale_px(8.f, scale) + spread, 0,
							(std::max)(1.f, scale));
				}
			}
		} else {
			ImU32 fill = aida::ui::mix(t.panel_header, t.accent_dim, h_v * 0.45f);
			border = aida::ui::mix(t.border_subtle, t.accent_dim, h_v * 0.65f);
			icon_col = aida::ui::mix(t.text_secondary, t.text_primary, h_v);
			dl->AddRectFilled(ca, cb, with_a(fill, btn_alpha),
				aida::ui::scale_px(8.f, scale));
		}

		dl->AddRect(ca, cb, with_a(border, btn_alpha * (0.6f + h_v * 0.4f)),
		            aida::ui::scale_px(8.f, scale), 0, (std::max)(1.f, scale));

		ImVec2 ic = ImVec2((ca.x + cb.x) * 0.5f, (ca.y + cb.y) * 0.5f);
		float ir = aida::ui::scale_px(9.f, scale) * press_scale;
		float thickness = aida::ui::scale_px(1.6f, scale);
		draw_icon(dl, ic, ir, btn.icon_id, icon_col, thickness);

		if (item_hovered)
			ImGui::SetTooltip("%s", btn.tooltip);

		if (clicked) {
			static_cast<void>(aida::ui::application_ui::execute_action(action_ids[i],
				aida::ui::action_invocation_source_t::toolbar));
		}
	}

	if (has_overflow) {
		const float overflow_x = bx + direct_width +
			(direct_count > 0 ? button_gap : 0.f);
		ImGui::SetCursorScreenPos(ImVec2(overflow_x, by));
		std::array<aida::ui::design::action_t, TOOLBAR_BTN_COUNT> overflow_actions{};
		std::size_t overflow_count = 0;
		for (int i = direct_count; i < TOOLBAR_BTN_COUNT; ++i) {
			const auto& presentation = presentations[static_cast<std::size_t>(i)];
			overflow_actions[overflow_count++] = {
				action_ids[i], presentation.label.c_str(), presentation.label.c_str(),
				btns[i].tooltip,
				presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str(),
				nullptr, aida::ui::button_kind_t::secondary,
				btns[i].enabled, false, true
			};
		}
		const auto overflow_action = aida::ui::design::render_toolbar(
			"debugger.execution.overflow", overflow_actions.data(), overflow_count,
			effective_overflow_width);
		if (overflow_action.invoked && overflow_action.id)
			static_cast<void>(aida::ui::application_ui::execute_action(
				overflow_action.id, aida::ui::action_invocation_source_t::toolbar));
	}

	if (show_status) {
		float sx = ox + width - margin - status_width;
		float sy = by + (button_height - status_height) * 0.5f;
		ImU32 col;
		switch (status_kind) {
			case aida::ui::pill_kind_t::success: col = t.success; break;
			case aida::ui::pill_kind_t::warning: col = t.warning; break;
			case aida::ui::pill_kind_t::error:   col = t.error;   break;
			default:                             col = t.text_secondary; break;
		}
		dl->AddRectFilled(ImVec2(sx, sy), ImVec2(sx + status_width, sy + status_height),
		                  with_a(col, alpha * 0.18f), status_height * 0.5f);
		dl->AddRect(ImVec2(sx, sy), ImVec2(sx + status_width, sy + status_height),
		            with_a(col, alpha * 0.55f), status_height * 0.5f, 0,
				(std::max)(1.f, scale));
		float dpulse = aida::ui::clock::pulse(1.6f, 0.55f, 1.f);
		dl->AddCircleFilled(ImVec2(sx + aida::ui::scale_px(8.f, scale),
			sy + status_height * 0.5f), aida::ui::scale_px(3.f, scale),
		                    with_a(col, alpha * dpulse), 14);
		dl->AddText(status_font, status_font_size,
			ImVec2(sx + aida::ui::scale_px(14.f, scale),
				sy + (status_height - status_font_size) * 0.5f),
		            with_a(col, alpha), status_label);
	}
}

inline bool jump_to_disasm(uint64_t addr) {
	if (addr == 0) return false;
	aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
	disasm_view::goto_address(addr, disasm_view::capture_selected_workspace());
	return true;
}

inline bool jump_to_hex(uint64_t addr, size_t bytes) {
	if (addr == 0) return false;
	const auto context = disasm_view::capture_selected_workspace();
	if (!context.workspace || !context.workspace->identity().process() ||
		bytes == 0 || bytes > (64ULL << 20))
		return false;
	if (!hex_view::request_live_memory(context, addr, bytes))
		return false;
	aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::record("jump_to_hex", std::to_string(addr) + ":" + std::to_string(bytes));
#endif
	return true;
}

inline void copy_to_clipboard(const char* s) {
	if (!s || !*s) return;
	ImGui::SetClipboardText(s);
}

inline void copy_addr_to_clipboard(uint64_t addr) {
	char buf[20];
	std::snprintf(buf, sizeof(buf), "0x%016" PRIX64, addr);
	copy_to_clipboard(buf);
}

enum class pending_context_mutation_t : uint8_t {
	none = 0,
	set_instruction_pointer,
	terminate_thread,
	close_handle,
	apply_patch,
	revert_patch,
	revert_all_patches,
	remove_patch,
	remove_watch,
	remove_bookmark
};

struct mutation_result_t {
	bool ok = false;
	bool verified = false;
	std::string detail;
};

bool queue_debugger_mutation(const char* label, const char* action,
	debugger_interaction::context_t context,
	std::function<mutation_result_t()> operation,
	bool advance_generation = true) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(label);
	static_cast<void>(action);
	static_cast<void>(context);
	const auto result = operation();
	toast_notification::push(result.verified ? "Debugger mutation verified."
		: result.detail.empty() ? "Debugger mutation failed or readback did not match."
			: result.detail,
		result.verified ? toast_notification::toast_type_t::success
			: toast_notification::toast_type_t::error);
	if (result.verified && advance_generation)
		debugger_interaction::advance_stop_generation();
	return result.verified;
#else
	bool expected = false;
	if (!g_target_mutation_pending.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) {
		toast_notification::push("Another live-target mutation is still pending.",
			toast_notification::toast_type_t::warning);
		return false;
	}
	auto result = std::make_shared<mutation_result_t>();
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = label;
	submission.thread_class = "debugger_target_mutation";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.target_pid = context.target_pid;
	submission.generation = context.stop_generation;
	submission.ui_access_policy = "post_completion_only";
	submission.failure_policy = "fail_closed";
	submission.body = [context, result,
		operation = std::move(operation), advance_generation]() mutable {
		if (context.target_pid != 0 && !debugger_interaction::is_current(context)) {
			result->detail = "The target or selected stop changed before the mutation started.";
		} else {
			try {
				*result = operation();
			} catch (const std::exception& exception) {
				result->detail = exception.what();
			} catch (...) {
				result->detail = "The debugger mutation failed with an unknown exception.";
			}
		}
		if (result->verified && context.target_pid != 0 &&
			!debugger_interaction::is_current(context)) {
			result->ok = false;
			result->verified = false;
			result->detail =
				"The mutation completed, but its target or stop generation changed before publication; the stale result was rejected.";
		}
		const bool posted = post_debugger_ui([context, result, advance_generation]() {
			if (result->verified && advance_generation)
				debugger_interaction::advance_stop_generation();
			const std::string message = result->verified ? "Debugger mutation verified."
				: result->detail.empty() ? "Debugger mutation failed or readback did not match."
					: result->detail;
			toast_notification::push(message,
				result->verified ? toast_notification::toast_type_t::success
					: toast_notification::toast_type_t::error);
			diag::log_tagged_critical_fmt("debugger_context",
				"async_mutation pid=%u generation=%llu address=0x%llx index=%d ok=%d verified=%d detail='%s'",
				static_cast<unsigned>(context.target_pid),
				static_cast<unsigned long long>(context.stop_generation),
				static_cast<unsigned long long>(context.address), context.index,
				result->ok ? 1 : 0, result->verified ? 1 : 0, result->detail.c_str());
			g_target_mutation_pending.store(false, std::memory_order_release);
		}, "mutation_completion");
		if (!posted) {
			if (result->verified && advance_generation)
				debugger_interaction::invalidate_stop_generation_async();
			g_target_mutation_pending.store(false, std::memory_order_release);
			throw std::runtime_error("Debugger mutation completion could not be published to the UI thread");
		}
		if (!result->verified)
			throw std::runtime_error(result->detail.empty()
				? "Debugger mutation failed or readback did not match" : result->detail);
	};
	const auto submitted = submit_owned_debugger_task(std::move(submission),
		"view.debug.cpu", action, label, false);
	if (!submitted.submitted) {
		g_target_mutation_pending.store(false, std::memory_order_release);
		toast_notification::push("The debugger mutation could not be admitted: " +
			submitted.reject_reason, toast_notification::toast_type_t::error);
		return false;
	}
	return true;
#endif
}

template <typename T>
struct render_snapshot_cache_t {
	std::vector<T> items;
	std::uint64_t generation = 0;
	std::uint64_t lock_busy_count = 0;
	std::uint64_t refresh_count = 0;
	std::uint64_t copied_items = 0;
	std::uint64_t copy_time_us = 0;
	double next_refresh_time = 0.0;
	double last_report_time = -1.0;
};

template <typename T>
const std::vector<T>& refresh_render_snapshot(render_snapshot_cache_t<T>& cache,
	std::mutex& mutex, const std::vector<T>& source, const std::atomic<std::uint64_t>& generation,
	const char* owner, double minimum_refresh_interval = 0.0) {
	const std::uint64_t current_generation = generation.load(std::memory_order_acquire);
	if (cache.generation == current_generation)
		return cache.items;
	const double now = ImGui::GetTime();
	if (now < cache.next_refresh_time)
		return cache.items;
	std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
	if (!lock.owns_lock()) {
		++cache.lock_busy_count;
		return cache.items;
	}
	const auto started = std::chrono::steady_clock::now();
	cache.items = source;
	lock.unlock();
	cache.generation = current_generation;
	cache.next_refresh_time = now + minimum_refresh_interval;
	const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - started).count();
	++cache.refresh_count;
	cache.copied_items += cache.items.size();
	cache.copy_time_us += elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (elapsed >= 2000 || cache.last_report_time < 0.0 || now - cache.last_report_time >= 5.0) {
		cache.last_report_time = now;
		diag::log_tagged_fmt("ui_perf",
			"debugger_snapshot owner=%s generation=%llu rows=%zu object_bytes=%zu copy_us=%lld copy_us_total=%llu refreshes=%llu lock_busy=%llu",
			owner, static_cast<unsigned long long>(current_generation), cache.items.size(),
			cache.items.size() * sizeof(T), static_cast<long long>(elapsed),
			static_cast<unsigned long long>(cache.copy_time_us), static_cast<unsigned long long>(cache.refresh_count),
			static_cast<unsigned long long>(cache.lock_busy_count));
	}
#else
	static_cast<void>(owner);
#endif
	return cache.items;
}

pending_context_mutation_t g_pending_context_mutation = pending_context_mutation_t::none;
debugger_interaction::context_t g_pending_context;
bool g_pending_context_mutation_open = false;

enum class context_retention_t : std::uint8_t {
	current,
	stale,
	busy
};

context_retention_t context_item_retention(const debugger_interaction::context_t& context);
inline std::uint64_t resolve_register_token(const std::string& token,
	const debugger_engine::register_set_t& registers);

std::uint64_t breakpoint_fingerprint(const debugger_engine::breakpoint_t& breakpoint) noexcept {
	std::uint64_t hash = 1469598103934665603ULL;
	const auto mix = [&](std::uint64_t value) {
		for (unsigned shift = 0; shift < 64; shift += 8) {
			hash ^= static_cast<std::uint8_t>(value >> shift);
			hash *= 1099511628211ULL;
		}
	};
	mix(breakpoint.address);
	mix(static_cast<std::uint64_t>(breakpoint.size));
	mix(static_cast<std::uint64_t>(breakpoint.type));
	mix(breakpoint.auto_continue ? 1U : 0U);
	for (const char value : breakpoint.name) mix(static_cast<unsigned char>(value));
	for (const char value : breakpoint.condition) mix(static_cast<unsigned char>(value));
	for (const char value : breakpoint.log_text) mix(static_cast<unsigned char>(value));
	return hash;
}

std::string g_consumed_debugger_action;
const char* g_debugger_context_owner_view = "view.debug.cpu";

enum class breakpoint_editor_focus_t : std::uint8_t {
	condition,
	log_message,
	auto_continue
};

breakpoint_editor_focus_t g_breakpoint_editor_focus = breakpoint_editor_focus_t::condition;

bool breakpoint_edit_identity_matches(const debugger_engine::breakpoint_t& breakpoint,
	std::uint64_t fingerprint, std::uint64_t address, std::uint64_t size, int type,
	const std::string& name, const std::string& condition, const std::string& log_text,
	bool auto_continue) {
	return breakpoint_fingerprint(breakpoint) == fingerprint &&
		breakpoint.address == address &&
		static_cast<std::uint64_t>(breakpoint.size) == size &&
		static_cast<int>(breakpoint.type) == type && breakpoint.name == name &&
		breakpoint.condition == condition && breakpoint.log_text == log_text &&
		breakpoint.auto_continue == auto_continue;
}

bool retain_breakpoint_edit(ui_state_t& ui, int index,
	const debugger_engine::breakpoint_t& breakpoint,
	const debugger_interaction::context_t& context,
	breakpoint_editor_focus_t focus) {
	if (index < 0 || context.kind != debugger_interaction::kind_t::breakpoint ||
		context.index != index || context.address != breakpoint.address ||
		context.value != breakpoint_fingerprint(breakpoint) ||
		!debugger_interaction::is_current(context))
		return false;
	std::lock_guard<std::mutex> lock(debugger_engine::g_state.bp_mutex);
	if (!debugger_interaction::is_current(context) ||
		index >= static_cast<int>(debugger_engine::g_state.breakpoints.size()))
		return false;
	const auto& retained = debugger_engine::g_state.breakpoints[static_cast<std::size_t>(index)];
	if (retained.address != context.address ||
		breakpoint_fingerprint(retained) != context.value)
		return false;
	ui.bp_edit_idx = index;
	ui.bp_edit_context = context;
	ui.bp_edit_breakpoints_generation = debugger_engine::g_state.breakpoints_generation.load(
		std::memory_order_acquire);
	ui.bp_edit_fingerprint = breakpoint_fingerprint(retained);
	ui.bp_edit_address = retained.address;
	ui.bp_edit_size = static_cast<std::uint64_t>(retained.size);
	ui.bp_edit_type = static_cast<int>(retained.type);
	ui.bp_edit_name = retained.name;
	ui.bp_edit_original_condition = retained.condition;
	ui.bp_edit_original_log = retained.log_text;
	ui.bp_edit_original_auto_continue = retained.auto_continue;
	std::snprintf(ui.bp_edit_condition_buf, sizeof(ui.bp_edit_condition_buf),
		"%s", retained.condition.c_str());
	std::snprintf(ui.bp_edit_log_buf, sizeof(ui.bp_edit_log_buf),
		"%s", retained.log_text.c_str());
	ui.bp_edit_auto_continue = retained.auto_continue;
	ui.bp_edit_identity_retained = true;
	g_breakpoint_editor_focus = focus;
	ui.bp_edit_popup_open = true;
	return true;
}

bool breakpoint_edit_is_current(const ui_state_t& ui, std::string& reason) {
	if (!ui.bp_edit_identity_retained || ui.bp_edit_idx < 0) {
		reason = "The reviewed breakpoint identity was not retained.";
		return false;
	}
	if (!debugger_interaction::is_current(ui.bp_edit_context)) {
		reason = "The target process identity or debugger stop changed while the editor was open.";
		return false;
	}
	if (debugger_engine::g_state.breakpoints_generation.load(std::memory_order_acquire) !=
		ui.bp_edit_breakpoints_generation) {
		reason = "The breakpoint collection changed while the editor was open.";
		return false;
	}
	std::unique_lock<std::mutex> lock(debugger_engine::g_state.bp_mutex, std::defer_lock);
	if (!lock.try_lock()) {
		reason = "Breakpoint state is updating; Apply is temporarily unavailable.";
		return false;
	}
	if (debugger_engine::g_state.breakpoints_generation.load(std::memory_order_acquire) !=
		ui.bp_edit_breakpoints_generation ||
		ui.bp_edit_idx >= static_cast<int>(debugger_engine::g_state.breakpoints.size()) ||
		!breakpoint_edit_identity_matches(
			debugger_engine::g_state.breakpoints[static_cast<std::size_t>(ui.bp_edit_idx)],
			ui.bp_edit_fingerprint, ui.bp_edit_address, ui.bp_edit_size, ui.bp_edit_type,
			ui.bp_edit_name, ui.bp_edit_original_condition, ui.bp_edit_original_log,
			ui.bp_edit_original_auto_continue)) {
		reason = "The breakpoint was removed, replaced, or modified while the editor was open.";
		return false;
	}
	return true;
}

const char* debugger_action_id(const char* label) {
	if (std::strcmp(label, "Open in Disassembly") == 0) return "debugger.entity.open_disassembly";
	if (std::strcmp(label, "Open in Hex View") == 0) return "debugger.entity.open_hex";
	if (std::strcmp(label, "Run to Here") == 0) return "debugger.instruction.run_to";
	if (std::strcmp(label, "Toggle Breakpoint") == 0) return "debugger.instruction.toggle_breakpoint";
	if (std::strcmp(label, "Set RIP to Here...") == 0) return "debugger.instruction.set_rip";
	if (std::strcmp(label, "Edit Register...") == 0) return "debugger.register.edit";
	if (std::strcmp(label, "Set to Zero...") == 0) return "debugger.register.zero";
	if (std::strcmp(label, "Enable / Disable") == 0) return "debugger.breakpoint.toggle_enabled";
	if (std::strcmp(label, "Edit Breakpoint...") == 0) return "debugger.breakpoint.edit";
	if (std::strcmp(label, "Edit Condition...") == 0) return "debugger.breakpoint.condition";
	if (std::strcmp(label, "Edit Log Message...") == 0) return "debugger.breakpoint.log_message";
	if (std::strcmp(label, "Configure Auto-continue...") == 0) return "debugger.breakpoint.auto_continue";
	if (std::strcmp(label, "Delete Breakpoint") == 0) return "debugger.breakpoint.delete";
	if (std::strcmp(label, "Change Protection...") == 0) return "debugger.memory.change_protection";
	if (std::strcmp(label, "Dump Region...") == 0) return "debugger.memory.dump";
	if (std::strcmp(label, "Suspend Thread") == 0) return "debugger.thread.suspend";
	if (std::strcmp(label, "Resume Thread") == 0) return "debugger.thread.resume";
	if (std::strcmp(label, "Terminate Thread...") == 0) return "debugger.thread.terminate";
	if (std::strcmp(label, "Close Handle...") == 0) return "debugger.handle.close";
	if (std::strcmp(label, "Apply Patch...") == 0) return "debugger.patch.apply";
	if (std::strcmp(label, "Revert Patch...") == 0) return "debugger.patch.revert";
	if (std::strcmp(label, "Remove Patch...") == 0) return "debugger.patch.remove";
	return "";
}

static aida::ui::application_ui::retained_entity_context_t
build_debugger_entity_actions(const debugger_interaction::context_t& context,
	bool include_selected_set = true) {
	aida::ui::application_ui::retained_entity_context_t retained;
	const auto action_contexts = include_selected_set
		? debugger_action_contexts(context)
		: std::vector<debugger_interaction::context_t>{context};
	const bool multiple = action_contexts.size() > 1;
	retained.owner_id = "debugger.entity";
	retained.entity_id = debugger_action_entity_id(context, action_contexts);
	retained.entity_generation = context.stop_generation;
	const char* owner_view = g_debugger_context_owner_view;
	switch (context.kind) {
		case debugger_interaction::kind_t::breakpoint: owner_view = "view.debug.breakpoints"; break;
		case debugger_interaction::kind_t::memory_region: owner_view = "view.debug.memory_map"; break;
		case debugger_interaction::kind_t::stack_frame: owner_view = "view.debug.call_stack"; break;
		case debugger_interaction::kind_t::thread: owner_view = "view.debug.threads"; break;
		case debugger_interaction::kind_t::module: owner_view = "view.debug.modules"; break;
		case debugger_interaction::kind_t::trace_record: owner_view = "view.debug.trace"; break;
		case debugger_interaction::kind_t::handle: owner_view = "view.debug.handles"; break;
		case debugger_interaction::kind_t::patch: owner_view = "view.debug.patches"; break;
		case debugger_interaction::kind_t::watch: owner_view = "view.debug.watches"; break;
		case debugger_interaction::kind_t::string_value: owner_view = "view.debug.strings"; break;
		case debugger_interaction::kind_t::bookmark: owner_view = "view.debug.bookmarks"; break;
		default: break;
	}
	retained.active_view = aida::ui::stable_view_id_t(owner_view);
	retained.validate_identity = [action_contexts]() {
		for (const auto& item : action_contexts) {
			const auto retention = context_item_retention(item);
			if (retention == context_retention_t::busy)
				return aida::ui::capability_state_t::unavailable("Debugger state is updating; retry when the refresh completes.");
			if (retention != context_retention_t::current || !debugger_interaction::is_current(item))
				return aida::ui::capability_state_t::unavailable("The selected debugger entity or stop generation changed.");
		}
		return aida::ui::capability_state_t::available();
	};
	auto add = [&](const char* id, bool enabled, const char* reason) {
		retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
			: aida::ui::capability_state_t::unavailable(reason),
			[]() { return aida::ui::action_handler_result_t::completed(); }});
	};
	auto add_handler = [&](const char* id, bool enabled, const char* reason,
		std::function<aida::ui::action_handler_result_t()> handler) {
		retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
			: aida::ui::capability_state_t::unavailable(reason), std::move(handler)});
	};
	auto add_capability = [&](const char* id, debugger_interaction::capability_t requested) {
		if (multiple) {
			add(id, false, "This action requires exactly one debugger row.");
			return;
		}
		const auto evaluated = debugger_interaction::evaluate(requested, context);
		add(id, evaluated.enabled, evaluated.disabled_reason ? evaluated.disabled_reason : "The debugger action is unavailable.");
	};
	const bool any_address = std::any_of(action_contexts.begin(), action_contexts.end(),
		[](const auto& item) { return item.address != 0 || item.value != 0; });
	const bool any_primary = std::any_of(action_contexts.begin(), action_contexts.end(),
		[](const auto& item) { return !item.primary_text.empty(); });
	const bool any_secondary = std::any_of(action_contexts.begin(), action_contexts.end(),
		[](const auto& item) { return !item.secondary_text.empty(); });
	add("debugger.entity.copy_address", any_address,
		"The selected item has no resolved address.");
	if (any_primary) add("debugger.entity.copy_primary", true, "");
	add_capability("debugger.entity.open_disassembly", debugger_interaction::capability_t::follow_disassembly);
	add_capability("debugger.entity.open_hex", debugger_interaction::capability_t::follow_memory);
	switch (context.kind) {
		case debugger_interaction::kind_t::instruction:
			add_capability("debugger.instruction.run_to", debugger_interaction::capability_t::run_to_address);
			add_capability("debugger.instruction.toggle_breakpoint", debugger_interaction::capability_t::toggle_breakpoint);
			add_capability("debugger.instruction.set_rip", debugger_interaction::capability_t::set_instruction_pointer);
			if (context.value != 0) add("debugger.instruction.follow_branch", !multiple,
				"Following a branch requires exactly one debugger row.");
			break;
		case debugger_interaction::kind_t::register_value:
			add("debugger.register.copy_decimal", !multiple,
				"Decimal copy requires exactly one debugger row.");
			add_capability("debugger.register.edit", debugger_interaction::capability_t::edit_register);
			add_capability("debugger.register.zero", debugger_interaction::capability_t::edit_register);
			add_handler("debugger.register.add_watch", !multiple && !context.primary_text.empty(),
				"Adding a watch requires one retained register with a stable name.", [context] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.debug.watches"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				if (context_item_retention(context) != context_retention_t::current ||
					!debugger_interaction::is_current(context))
					return aida::ui::action_handler_result_t::failed(
						"The retained register or debugger stop changed.");
				if (context.primary_text.size() >= sizeof(g_ui.add_watch_buf))
					return aida::ui::action_handler_result_t::failed(
						"The retained register expression exceeds the watch input bound.");
				std::snprintf(g_ui.add_watch_buf, sizeof(g_ui.add_watch_buf), "%s",
					context.primary_text.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
			add_handler("debugger.entity.interpret_structure", !multiple && context.value != 0,
				"Structure interpretation requires one retained nonzero register value.",
				[context, source_view = std::string(owner_view)] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.types.structures"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				struct_dissector_view::staged_target_context_t staged;
				staged.address = context.value;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.stop_generation;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.stop_generation;
				staged.live_process = true;
				staged.source_view = source_view;
				staged.source_identity = debugger_action_entity_id(context, {context});
				const auto epoch = staged.target_epoch;
				staged.validate = [context, epoch](std::string& reason) {
					const bool current = epoch == context.stop_generation &&
						context_item_retention(context) == context_retention_t::current &&
						debugger_interaction::is_current(context);
					if (!current) reason = "The retained register, target epoch, or debugger stop changed.";
					return current;
				};
				std::string error;
				if (!struct_dissector_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			});
			add_handler("debugger.entity.pointer_workflow", !multiple && context.value != 0,
				"Pointer scanning requires one retained nonzero register value.",
				[context, source_view = std::string(owner_view)] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.memory.pointers"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				pointer_scanner_view::staged_target_context_t staged;
				staged.address = context.value;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.stop_generation;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.stop_generation;
				staged.source_view = source_view;
				staged.source_identity = debugger_action_entity_id(context, {context});
				const auto epoch = staged.target_epoch;
				staged.validate = [context, epoch](std::string& reason) {
					const bool current = epoch == context.stop_generation &&
						context_item_retention(context) == context_retention_t::current &&
						debugger_interaction::is_current(context);
					if (!current) reason = "The retained register, target epoch, or debugger stop changed.";
					return current;
				};
				std::string error;
				if (!pointer_scanner_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			});
			break;
		case debugger_interaction::kind_t::stack_slot:
			add("debugger.stack.copy_qword", !multiple,
				"Qword copy requires exactly one debugger row.");
			add_handler("debugger.stack.add_watch", !multiple && context.address != 0,
				"Adding a watch requires one retained stack address.", [context] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.debug.watches"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				if (context_item_retention(context) != context_retention_t::current ||
					!debugger_interaction::is_current(context))
					return aida::ui::action_handler_result_t::failed(
						"The retained stack slot or debugger stop changed.");
				char expression[48]{};
				std::snprintf(expression, sizeof(expression), "[0x%016llX]",
					static_cast<unsigned long long>(context.address));
				std::snprintf(g_ui.add_watch_buf, sizeof(g_ui.add_watch_buf), "%s", expression);
				return aida::ui::action_handler_result_t::completed();
			});
			add_handler("debugger.entity.interpret_structure", !multiple && context.value != 0,
				"Structure interpretation requires one retained nonzero stack value.",
				[context, source_view = std::string(owner_view)] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.types.structures"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				struct_dissector_view::staged_target_context_t staged;
				staged.address = context.value;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.stop_generation;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.stop_generation;
				staged.live_process = true;
				staged.source_view = source_view;
				staged.source_identity = debugger_action_entity_id(context, {context});
				const auto epoch = staged.target_epoch;
				staged.validate = [context, epoch](std::string& reason) {
					const bool current = epoch == context.stop_generation &&
						context_item_retention(context) == context_retention_t::current &&
						debugger_interaction::is_current(context);
					if (!current) reason = "The retained stack slot, target epoch, or debugger stop changed.";
					return current;
				};
				std::string error;
				if (!struct_dissector_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			});
			add_handler("debugger.entity.pointer_workflow", !multiple && context.value != 0,
				"Pointer scanning requires one retained nonzero stack value.",
				[context, source_view = std::string(owner_view)] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.memory.pointers"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				pointer_scanner_view::staged_target_context_t staged;
				staged.address = context.value;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.stop_generation;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.stop_generation;
				staged.source_view = source_view;
				staged.source_identity = debugger_action_entity_id(context, {context});
				const auto epoch = staged.target_epoch;
				staged.validate = [context, epoch](std::string& reason) {
					const bool current = epoch == context.stop_generation &&
						context_item_retention(context) == context_retention_t::current &&
						debugger_interaction::is_current(context);
					if (!current) reason = "The retained stack slot, target epoch, or debugger stop changed.";
					return current;
				};
				std::string error;
				if (!pointer_scanner_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			});
			break;
		case debugger_interaction::kind_t::breakpoint:
			add_capability("debugger.breakpoint.toggle_enabled", debugger_interaction::capability_t::toggle_breakpoint);
			add_capability("debugger.breakpoint.edit", debugger_interaction::capability_t::edit_breakpoint);
			add_capability("debugger.breakpoint.condition", debugger_interaction::capability_t::edit_breakpoint);
			add_capability("debugger.breakpoint.log_message", debugger_interaction::capability_t::edit_breakpoint);
			add_capability("debugger.breakpoint.auto_continue", debugger_interaction::capability_t::edit_breakpoint);
			add_capability("debugger.breakpoint.delete", debugger_interaction::capability_t::remove_breakpoint);
			break;
		case debugger_interaction::kind_t::memory_region:
			add_capability("debugger.memory.change_protection", debugger_interaction::capability_t::change_memory_protection);
			add_capability("debugger.memory.dump", debugger_interaction::capability_t::dump_memory); break;
		case debugger_interaction::kind_t::thread:
			add_capability("debugger.thread.suspend", debugger_interaction::capability_t::suspend_thread);
			add_capability("debugger.thread.resume", debugger_interaction::capability_t::resume_thread);
			add_capability("debugger.thread.terminate", debugger_interaction::capability_t::terminate_thread); break;
		case debugger_interaction::kind_t::handle:
			add_capability("debugger.handle.close", debugger_interaction::capability_t::close_handle); break;
		case debugger_interaction::kind_t::patch:
			add_capability("debugger.patch.apply", debugger_interaction::capability_t::apply_patch);
			add_capability("debugger.patch.revert", debugger_interaction::capability_t::revert_patch);
			add_capability("debugger.patch.remove", debugger_interaction::capability_t::remove_patch); break;
		case debugger_interaction::kind_t::module:
			add_capability("debugger.module.unload", debugger_interaction::capability_t::unload_module); break;
		case debugger_interaction::kind_t::watch:
			if (any_secondary) add("debugger.entity.copy_secondary", true, "");
			add("debugger.watch.remove", !multiple,
				"Removing a watch requires exactly one debugger row."); break;
		case debugger_interaction::kind_t::string_value:
			if (any_secondary) add("debugger.entity.copy_secondary", true, ""); break;
		case debugger_interaction::kind_t::bookmark:
			add("debugger.bookmark.remove", !multiple,
				"Removing a bookmark requires exactly one debugger row."); break;
		default: break;
	}
	const char* evidence_kind = "debugger_entity";
	switch (context.kind) {
		case debugger_interaction::kind_t::instruction: evidence_kind = "debugger_instruction"; break;
		case debugger_interaction::kind_t::register_value: evidence_kind = "debugger_register"; break;
		case debugger_interaction::kind_t::stack_slot: evidence_kind = "debugger_stack_slot"; break;
		case debugger_interaction::kind_t::breakpoint: evidence_kind = "debugger_breakpoint"; break;
		case debugger_interaction::kind_t::memory_region: evidence_kind = "debugger_memory_region"; break;
		case debugger_interaction::kind_t::stack_frame: evidence_kind = "debugger_call_stack_frame"; break;
		case debugger_interaction::kind_t::thread: evidence_kind = "debugger_thread"; break;
		case debugger_interaction::kind_t::module: evidence_kind = "debugger_module"; break;
		case debugger_interaction::kind_t::trace_record: evidence_kind = "debugger_trace_record"; break;
		case debugger_interaction::kind_t::handle: evidence_kind = "debugger_handle"; break;
		case debugger_interaction::kind_t::patch: evidence_kind = "debugger_patch"; break;
		case debugger_interaction::kind_t::watch: evidence_kind = "debugger_watch"; break;
		case debugger_interaction::kind_t::string_value: evidence_kind = "debugger_string"; break;
		case debugger_interaction::kind_t::bookmark: evidence_kind = "debugger_bookmark"; break;
		default: break;
	}
	char address_text[24]{};
	char value_text[24]{};
	std::snprintf(address_text, sizeof(address_text), "0x%016llX",
		static_cast<unsigned long long>(context.address));
	std::snprintf(value_text, sizeof(value_text), "0x%016llX",
		static_cast<unsigned long long>(context.value));
	aida::automation_ui::entity_evidence::snapshot_t evidence;
	evidence.workspace_id = "pid:" + std::to_string(context.target_pid) + ":created:" +
		std::to_string(context.process_creation_time_100ns);
	evidence.source_view_id = owner_view;
	evidence.source_kind = evidence_kind;
	evidence.entity_id = retained.entity_id;
	evidence.display_label = context.primary_text.empty() ? evidence_kind : context.primary_text;
	evidence.excerpt = "PID: " + std::to_string(context.target_pid) +
		"\nProcess creation: " + std::to_string(context.process_creation_time_100ns) +
		"\nStop generation: " + std::to_string(context.stop_generation) +
		"\nSelected rows: " + std::to_string(action_contexts.size()) +
		"\nThread: " + std::to_string(context.thread_id) +
		"\nAddress: " + address_text + "\nValue: " + value_text +
		"\nExtent: " + std::to_string(context.extent) +
		"\nPrimary: " + context.primary_text +
		"\nSecondary: " + context.secondary_text;
	evidence.address = context.address;
	evidence.revision = context.stop_generation;
	evidence.generation = context.stop_generation;
	evidence.sensitive = true;
	const std::size_t evidence_rows = (std::min)(action_contexts.size(), std::size_t{256});
	for (std::size_t index = 0; index < evidence_rows; ++index) {
		const auto& item = action_contexts[index];
		char item_address[24]{};
		char item_value[24]{};
		std::snprintf(item_address, sizeof(item_address), "0x%016llX",
			static_cast<unsigned long long>(item.address));
		std::snprintf(item_value, sizeof(item_value), "0x%016llX",
			static_cast<unsigned long long>(item.value));
		evidence.excerpt += "\n[" + std::to_string(index + 1) + "] Address: " +
			item_address + " Value: " + item_value + " Primary: " + item.primary_text;
	}
	if (evidence_rows < action_contexts.size())
		evidence.excerpt += "\n... " + std::to_string(action_contexts.size() - evidence_rows) +
			" additional selected rows omitted from the excerpt.";
	evidence.return_to_source = [context, action_contexts, owner_view](std::string& reason) {
		for (const auto& item : action_contexts) {
			if (context_item_retention(item) != context_retention_t::current ||
				!debugger_interaction::is_current(item)) {
				reason = "The debugger target or stop generation changed; capture the entity again.";
				return false;
			}
		}
		debugger_interaction::select_set(action_contexts, context);
		const auto opened = aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t(owner_view));
		if (!opened.ok()) {
			reason = opened.detail;
			return false;
		}
		reason.clear();
		return true;
	};
	aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence),
		context.target_pid != 0 && context.kind != debugger_interaction::kind_t::none
			? aida::ui::capability_state_t::available()
			: aida::ui::capability_state_t::unavailable(
				"A retained stopped debugger target entity is required for evidence handoff."));
	return retained;
}

}

void open_debugger_entity_actions(const debugger_interaction::context_t& context,
	aida::ui::context_menu_open_origin_t origin) {
	aida::ui::application_ui::open_retained_entity_context_menu(
		build_debugger_entity_actions(context), origin);
}

namespace {

inline bool context_menu_item(const char* label, const char* shortcut,
	debugger_interaction::capability_t capability,
	const debugger_interaction::context_t& context) {
	const auto result = debugger_interaction::evaluate(capability, context);
	static_cast<void>(shortcut);
	return result.enabled && g_consumed_debugger_action == debugger_action_id(label);
}

inline void request_context_mutation(pending_context_mutation_t mutation,
	const debugger_interaction::context_t& context) {
	g_pending_context_mutation = mutation;
	g_pending_context = context;
	g_pending_context_mutation_open = true;
}

struct patch_transaction_result_t {
	bool ok = false;
	bool verified = false;
	bool rollback_attempted = false;
	bool rollback_verified = false;
	std::string detail;
};

bool same_patch_definition(const code_patcher::patch_entry_t& lhs,
	const code_patcher::patch_entry_t& rhs) {
	return lhs.address == rhs.address && lhs.original_bytes == rhs.original_bytes &&
		lhs.patched_bytes == rhs.patched_bytes && lhs.target_pid == rhs.target_pid &&
		lhs.target_process_creation_time_100ns ==
			rhs.target_process_creation_time_100ns;
}

bool read_patch_bytes_exact(uint64_t address, const std::vector<uint8_t>& expected,
	const debugger_interaction::context_t& context) {
	if (expected.empty() || !debugger_interaction::is_current(context)) return false;
	std::vector<uint8_t> observed;
	const bool read = driver_bridge::read_memory(address, expected.size(), observed);
	return debugger_interaction::is_current(context) && read && observed == expected;
}

patch_transaction_result_t transition_patch_exact(int index,
	const code_patcher::patch_entry_t& expected_patch, bool target_active,
	const debugger_interaction::context_t& context) {
	patch_transaction_result_t result;
	if (!debugger_interaction::is_current(context)) {
		result.detail = "The exact debugger target changed before the patch transaction.";
		return result;
	}
	std::lock_guard<std::mutex> lock(code_patcher::g_state.mtx);
	if (index < 0 || index >= static_cast<int>(code_patcher::g_state.patches.size()) ||
		!same_patch_definition(code_patcher::g_state.patches[static_cast<size_t>(index)],
			expected_patch)) {
		result.detail = "The selected patch changed before execution.";
		return result;
	}
	auto& patch = code_patcher::g_state.patches[static_cast<size_t>(index)];
	if (patch.target_pid != 0 && patch.target_pid != context.target_pid) {
		result.detail = "The patch belongs to a different target process.";
		return result;
	}
	if (patch.target_process_creation_time_100ns == 0 ||
		patch.target_process_creation_time_100ns !=
			context.process_creation_time_100ns) {
		result.detail = "The patch belongs to a different process creation identity.";
		return result;
	}
	const auto& source = target_active ? patch.original_bytes : patch.patched_bytes;
	const auto& destination = target_active ? patch.patched_bytes : patch.original_bytes;
	if (source.empty() || destination.empty() || source.size() != destination.size()) {
		result.detail = "The patch byte transaction is incomplete.";
		return result;
	}
	if (patch.active == target_active) {
		result.verified = read_patch_bytes_exact(patch.address, destination, context);
		result.ok = result.verified;
		if (!result.verified)
			result.detail = "The recorded patch state does not match live target memory.";
		return result;
	}
	if (!read_patch_bytes_exact(patch.address, source, context)) {
		result.detail = "The live bytes or exact target identity changed before the patch write.";
		return result;
	}
	if (!debugger_interaction::is_current(context)) {
		result.detail = "The exact debugger target changed immediately before the patch write.";
		return result;
	}
	const bool write_ok = driver_bridge::write_memory(patch.address, destination);
	const bool identity_after_write = debugger_interaction::is_current(context);
	if (write_ok && identity_after_write)
		result.verified = read_patch_bytes_exact(patch.address, destination, context);
	if (result.verified) {
		patch.active = target_active;
		code_patcher::publish_snapshot_locked();
		result.ok = true;
		return result;
	}
	result.detail = !identity_after_write
		? "The exact debugger target changed during the patch write; success cannot be verified."
		: "Patch write verification failed.";
	if (!debugger_interaction::is_current(context)) return result;
	result.rollback_attempted = true;
	const bool rollback_write = driver_bridge::write_memory(patch.address, source);
	const bool identity_after_rollback_write = debugger_interaction::is_current(context);
	if (rollback_write && identity_after_rollback_write)
		result.rollback_verified = read_patch_bytes_exact(patch.address, source, context);
	if (result.rollback_verified)
		result.detail += " The prior byte state was restored and verified.";
	else
		result.detail += " Restoration of the prior byte state could not be verified.";
	return result;
}

void render_context_mutation_confirmation() {
	if (g_pending_context_mutation_open) {
		ImGui::OpenPopup("Confirm Debugger Mutation##context");
		g_pending_context_mutation_open = false;
	}
	if (!aida::ui::design::begin_dialog_exact(
		"Confirm Debugger Mutation##context", ImVec2(620.0f, 460.0f),
		ImVec2(400.0f, 300.0f)))
		return;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Confirm", "Cancel");
	aida::ui::design::begin_dialog_body("debugger_context_mutation_body", footer_height);

	const auto context = g_pending_context;
	const char* scope = "the selected debugger item";
	const char* consequence = "This changes live target state.";
	debugger_interaction::capability_t capability =
		debugger_interaction::capability_t::copy;
	switch (g_pending_context_mutation) {
		case pending_context_mutation_t::set_instruction_pointer:
			scope = "the target instruction pointer";
			consequence = "Execution will resume from the selected address.";
			capability = debugger_interaction::capability_t::set_instruction_pointer;
			break;
		case pending_context_mutation_t::terminate_thread:
			scope = "the selected target thread";
			consequence = "Termination can corrupt locks and process state.";
			capability = debugger_interaction::capability_t::terminate_thread;
			break;
		case pending_context_mutation_t::close_handle:
			scope = "the selected target handle";
			consequence = "The target may fail if it still owns this resource.";
			capability = debugger_interaction::capability_t::close_handle;
			break;
		case pending_context_mutation_t::apply_patch:
			scope = "the selected live-memory patch";
			consequence = "Patched bytes will be written and read back before success is reported.";
			capability = debugger_interaction::capability_t::apply_patch;
			break;
		case pending_context_mutation_t::revert_patch:
			scope = "the selected live-memory patch";
			consequence = "Original bytes will be restored and read back before success is reported.";
			capability = debugger_interaction::capability_t::revert_patch;
			break;
		case pending_context_mutation_t::revert_all_patches:
			scope = "all active live-memory patches";
			consequence = "Each original byte sequence will be restored and verified before completion is reported.";
			capability = debugger_interaction::capability_t::revert_patch;
			break;
		case pending_context_mutation_t::remove_patch:
			scope = "the selected patch definition";
			consequence = "Any active patch will be verified reverted before its definition is removed.";
			capability = debugger_interaction::capability_t::remove_patch;
			break;
		case pending_context_mutation_t::remove_watch:
			scope = "the selected watch definition";
			consequence = "The watch will be removed from the debugger workspace; target memory is not modified.";
			break;
		case pending_context_mutation_t::remove_bookmark:
			scope = "the selected debugger bookmark";
			consequence = "The bookmark will be removed from the debugger workspace; target memory is not modified.";
			break;
		case pending_context_mutation_t::none:
			break;
	}

	ImGui::Text("Scope: %s", scope);
	ImGui::TextWrapped("%s", consequence);
	if (context.address != 0)
		ImGui::Text("Address: 0x%016" PRIX64, context.address);
	if (context.thread_id != 0)
		ImGui::Text("Thread: %u", static_cast<unsigned>(context.thread_id));
	const auto gate = debugger_interaction::evaluate(capability, context);
	const auto retention = context_item_retention(context);
	const bool retained = retention == context_retention_t::current;
	if (retention == context_retention_t::busy)
		ImGui::TextWrapped("Unavailable: debugger state is updating; retry when the current refresh completes.");
	else if (!retained)
		ImGui::TextWrapped("Unavailable: the selected debugger item changed; select a current row.");
	else if (!gate.enabled)
		ImGui::TextWrapped("Unavailable: %s", gate.disabled_reason);
	aida::ui::design::end_dialog_body();
	const auto footer = aida::ui::design::dialog_footer(
		"debugger_context_mutation_footer", "Confirm", gate.enabled && retained,
		true, "Cancel");
	if (footer.confirmed) {
		const auto mutation = g_pending_context_mutation;
		const bool advances = mutation != pending_context_mutation_t::remove_watch &&
			mutation != pending_context_mutation_t::remove_bookmark;
		static_cast<void>(queue_debugger_mutation("Apply reviewed debugger mutation",
			"debugger.context_mutation", context, [mutation, context]() {
			mutation_result_t result;
			switch (mutation) {
				case pending_context_mutation_t::set_instruction_pointer:
					result.ok = debugger_engine::set_register("rip", context.address);
					debugger_engine::request_refresh(0);
					result.verified = result.ok &&
						debugger_engine::get_registers().rip == context.address;
					break;
				case pending_context_mutation_t::terminate_thread:
					result.ok = driver_bridge::terminate_thread(context.thread_id, 0xDEADu);
					result.verified = result.ok;
					break;
				case pending_context_mutation_t::close_handle:
					result.ok = driver_bridge::close_process_handle(context.target_pid, context.value);
					result.verified = result.ok;
					break;
				case pending_context_mutation_t::apply_patch:
				case pending_context_mutation_t::revert_patch:
				case pending_context_mutation_t::remove_patch: {
					code_patcher::patch_entry_t patch;
					if (context.value == 0 || code_patcher::g_state.generation.load(
							std::memory_order_acquire) != context.value) {
						result.detail = "The patch set changed after review; reopen the action.";
						break;
					}
					{
						std::lock_guard<std::mutex> lock(code_patcher::g_state.mtx);
						if (context.index < 0 || context.index >=
							static_cast<int>(code_patcher::g_state.patches.size())) {
							result.detail = "The selected patch no longer exists.";
							break;
						}
						patch = code_patcher::g_state.patches[static_cast<size_t>(context.index)];
					}
					if (patch.address != context.address) {
						result.detail = "The selected patch changed before execution.";
						break;
					}
					const bool target_active = mutation == pending_context_mutation_t::apply_patch;
					const auto transaction = transition_patch_exact(context.index, patch,
						target_active, context);
					result.ok = transaction.ok;
					result.verified = transaction.verified;
					result.detail = transaction.detail;
					if (mutation == pending_context_mutation_t::remove_patch &&
						transaction.ok && transaction.verified) {
						std::lock_guard<std::mutex> lock(code_patcher::g_state.mtx);
						if (context.index < 0 || context.index >=
								static_cast<int>(code_patcher::g_state.patches.size()) ||
							!same_patch_definition(code_patcher::g_state.patches[
								static_cast<size_t>(context.index)], patch) ||
							code_patcher::g_state.patches[static_cast<size_t>(context.index)].active) {
							result.ok = result.verified = false;
							result.detail = "The patch definition changed before removal.";
						} else {
							code_patcher::g_state.patches.erase(code_patcher::g_state.patches.begin() +
								static_cast<std::vector<code_patcher::patch_entry_t>::difference_type>(
									context.index));
							code_patcher::publish_snapshot_locked();
						}
					}
					break;
				}
				case pending_context_mutation_t::revert_all_patches: {
					std::vector<code_patcher::patch_entry_t> patches;
					if (context.value == 0 || code_patcher::g_state.generation.load(
							std::memory_order_acquire) != context.value) {
						result.detail = "The patch set changed after review; reopen Revert All.";
						break;
					}
					{
						std::lock_guard<std::mutex> lock(code_patcher::g_state.mtx);
						if (code_patcher::g_state.patches.size() > 65536U) {
							result.detail = "The patch set exceeds the 65,536-entry safety bound.";
							break;
						}
						patches = code_patcher::g_state.patches;
					}
					result.ok = result.verified = true;
					for (size_t remaining = patches.size(); remaining > 0; --remaining) {
						const size_t index = remaining - 1;
						if (!patches[index].active) continue;
						const auto transaction = transition_patch_exact(static_cast<int>(index),
							patches[index], false, context);
						if (!transaction.ok || !transaction.verified) {
							result.ok = result.verified = false;
							result.detail = transaction.detail.empty()
								? "A patch rollback could not be verified."
								: transaction.detail;
							break;
						}
					}
					break;
				}
				case pending_context_mutation_t::remove_watch: {
					std::lock_guard<std::mutex> lock(debugger_engine::g_state.watch_mutex);
					if (context.index < 0 || context.index >=
						static_cast<int>(debugger_engine::g_state.watches.size())) break;
					const auto& watch = debugger_engine::g_state.watches[static_cast<size_t>(context.index)];
					const std::string& expression = watch.persistent_expression.empty()
						? watch.expression : watch.persistent_expression;
					if (expression != context.primary_text) break;
					debugger_engine::g_state.watches.erase(
						debugger_engine::g_state.watches.begin() + context.index);
					debugger_engine::g_state.watches_generation.fetch_add(1, std::memory_order_release);
					result.ok = result.verified = true;
					break;
				}
				case pending_context_mutation_t::remove_bookmark: {
					std::lock_guard<std::mutex> lock(debugger_engine::g_state.anno_mutex);
					const auto found = std::find(debugger_engine::g_state.bookmarks.begin(),
						debugger_engine::g_state.bookmarks.end(), context.address);
					if (found == debugger_engine::g_state.bookmarks.end()) break;
					debugger_engine::g_state.bookmarks.erase(found);
					result.ok = result.verified = true;
					break;
				}
				case pending_context_mutation_t::none:
					break;
			}
			return result;
		}, advances));
		g_pending_context_mutation = pending_context_mutation_t::none;
		g_pending_context = {};
		ImGui::CloseCurrentPopup();
	}
	if (footer.cancelled) {
		g_pending_context_mutation = pending_context_mutation_t::none;
		g_pending_context = {};
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

bool context_belongs_to_pane(debugger_interaction::kind_t kind, sub_tab_t pane) {
	switch (kind) {
		case debugger_interaction::kind_t::instruction:
		case debugger_interaction::kind_t::register_value:
		case debugger_interaction::kind_t::stack_slot:
			return pane == sub_tab_t::cpu;
		case debugger_interaction::kind_t::breakpoint:
			return pane == sub_tab_t::breakpoints;
		case debugger_interaction::kind_t::memory_region:
			return pane == sub_tab_t::memory_map;
		case debugger_interaction::kind_t::stack_frame:
			return pane == sub_tab_t::call_stack;
		case debugger_interaction::kind_t::thread:
			return pane == sub_tab_t::threads;
		case debugger_interaction::kind_t::module:
			return pane == sub_tab_t::modules;
		case debugger_interaction::kind_t::trace_record:
			return pane == sub_tab_t::trace_log;
		case debugger_interaction::kind_t::handle:
			return pane == sub_tab_t::handles;
		case debugger_interaction::kind_t::patch:
			return pane == sub_tab_t::patches;
		case debugger_interaction::kind_t::watch:
			return pane == sub_tab_t::watches;
		case debugger_interaction::kind_t::string_value:
			return pane == sub_tab_t::strings;
		case debugger_interaction::kind_t::bookmark:
			return pane == sub_tab_t::bookmarks;
		case debugger_interaction::kind_t::none:
			return false;
	}
	return false;
}

context_retention_t context_item_retention(const debugger_interaction::context_t& context) {
	switch (context.kind) {
		case debugger_interaction::kind_t::register_value: {
			const auto registers = debugger_engine::cached_registers();
			return !context.primary_text.empty() &&
				resolve_register_token(context.primary_text, registers) == context.value
				? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::stack_slot: {
			std::uint64_t base = 0;
			const auto bytes = debugger_engine::cached_stack_bytes(base);
			if (context.address < base || context.address - base > bytes.size() ||
				bytes.size() - static_cast<std::size_t>(context.address - base) < sizeof(std::uint64_t))
				return context_retention_t::stale;
			std::uint64_t value = 0;
			std::memcpy(&value, bytes.data() + static_cast<std::size_t>(context.address - base),
				sizeof(value));
			return value == context.value ? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::breakpoint: {
			const auto breakpoints = debugger_engine::snapshot_breakpoints();
			if (context.index < 0 || context.index >= static_cast<int>(breakpoints.size()))
				return context_retention_t::stale;
			const auto& breakpoint = breakpoints[static_cast<std::size_t>(context.index)];
			return breakpoint.address == context.address &&
				breakpoint_fingerprint(breakpoint) == context.value
				? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::watch: {
			std::unique_lock<std::mutex> lock(debugger_engine::g_state.watch_mutex,
				std::try_to_lock);
			if (!lock.owns_lock())
				return context_retention_t::busy;
			if (context.index < 0 || context.index >= static_cast<int>(debugger_engine::g_state.watches.size()))
				return context_retention_t::stale;
			const auto& watch = debugger_engine::g_state.watches[static_cast<std::size_t>(context.index)];
			const std::string& expression = watch.persistent_expression.empty()
				? watch.expression : watch.persistent_expression;
			return expression == context.primary_text
				? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::string_value: {
			std::unique_lock<std::mutex> lock(debugger_engine::g_state.strings_mutex,
				std::try_to_lock);
			if (!lock.owns_lock())
				return context_retention_t::busy;
			const bool retained = std::any_of(debugger_engine::g_state.strings.begin(), debugger_engine::g_state.strings.end(),
				[&](const debugger_engine::string_ref_t& item) {
					return item.address == context.address && item.value == context.primary_text;
				});
			return retained ? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::bookmark: {
			std::unique_lock<std::mutex> lock(debugger_engine::g_state.anno_mutex,
				std::try_to_lock);
			if (!lock.owns_lock())
				return context_retention_t::busy;
			const bool retained = std::find(debugger_engine::g_state.bookmarks.begin(),
				debugger_engine::g_state.bookmarks.end(), context.address) !=
				debugger_engine::g_state.bookmarks.end();
			return retained ? context_retention_t::current : context_retention_t::stale;
		}
		case debugger_interaction::kind_t::patch: {
			if (context.value == 0 || code_patcher::g_state.generation.load(
					std::memory_order_acquire) != context.value)
				return context_retention_t::stale;
			if (context.index < 0)
				return context_retention_t::current;
			std::unique_lock<std::mutex> lock(code_patcher::g_state.mtx, std::try_to_lock);
			if (!lock.owns_lock())
				return context_retention_t::busy;
			if (context.index >= static_cast<int>(code_patcher::g_state.patches.size()))
				return context_retention_t::stale;
			const auto& patch = code_patcher::g_state.patches[static_cast<std::size_t>(context.index)];
			return patch.address == context.address &&
				patch.patched_bytes.size() == context.extent &&
				patch.description == context.primary_text
				? context_retention_t::current : context_retention_t::stale;
		}
		default:
			return context_retention_t::current;
	}
}

void render_selected_context_menu(sub_tab_t pane) {
	const auto context = debugger_interaction::selected();
	const bool selected_here = context_belongs_to_pane(context.kind, pane);
	const bool pending_here = g_pending_context_mutation != pending_context_mutation_t::none &&
		context_belongs_to_pane(g_pending_context.kind, pane);
	if (!selected_here && !pending_here)
		return;
	const bool menu_key = selected_here && ImGui::IsKeyPressed(ImGuiKey_Menu, false);
	const bool shift_f10 = selected_here && ImGui::GetIO().KeyShift &&
		ImGui::IsKeyPressed(ImGuiKey_F10, false);
	if ((menu_key || shift_f10) && context.kind != debugger_interaction::kind_t::none)
		open_debugger_entity_actions(context, menu_key
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10);
	aida::ui::application_ui::render_retained_entity_context_menu("debugger.entity");
	const auto action_contexts = debugger_action_contexts(context);
	const std::string entity_id = debugger_action_entity_id(context, action_contexts);
	g_consumed_debugger_action = aida::ui::application_ui::consume_retained_entity_action(
		"debugger.entity", entity_id.c_str());
	if (selected_here && !g_consumed_debugger_action.empty()) {
		const uint64_t memory_value =
			(context.kind == debugger_interaction::kind_t::register_value ||
			 context.kind == debugger_interaction::kind_t::stack_slot)
				? context.value : context.address;
		const uint64_t navigation_address =
			(context.kind == debugger_interaction::kind_t::register_value ||
			 context.kind == debugger_interaction::kind_t::stack_slot)
				? context.value : context.address;
		if (g_consumed_debugger_action == "debugger.entity.copy_address") {
			if (action_contexts.size() == 1)
				copy_addr_to_clipboard(context.address != 0 ? context.address : context.value);
			else {
				std::ostringstream values;
				values << std::uppercase << std::hex << std::setfill('0');
				bool first = true;
				for (const auto& item : action_contexts) {
					const uint64_t value = item.address != 0 ? item.address : item.value;
					if (value == 0) continue;
					if (!first) values << '\n';
					values << "0x" << std::setw(16) << value;
					first = false;
				}
				copy_to_clipboard(values.str().c_str());
			}
		}
		if (g_consumed_debugger_action == "debugger.entity.copy_primary") {
			std::string values;
			for (const auto& item : action_contexts) {
				if (item.primary_text.empty()) continue;
				if (!values.empty()) values.push_back('\n');
				values.append(item.primary_text);
			}
			copy_to_clipboard(values.c_str());
		}
		if (g_consumed_debugger_action == "debugger.entity.copy_secondary") {
			std::string values;
			for (const auto& item : action_contexts) {
				if (item.secondary_text.empty()) continue;
				if (!values.empty()) values.push_back('\n');
				values.append(item.secondary_text);
			}
			copy_to_clipboard(values.c_str());
		}
		if (context_menu_item("Open in Disassembly", nullptr,
			debugger_interaction::capability_t::follow_disassembly, context) && navigation_address != 0)
			jump_to_disasm(navigation_address);
		if (context_menu_item("Open in Hex View", nullptr,
			debugger_interaction::capability_t::follow_memory, context) && memory_value != 0)
			jump_to_hex(memory_value, context.extent != 0 ? static_cast<size_t>(context.extent) : 256u);

		switch (context.kind) {
			case debugger_interaction::kind_t::instruction:
				if (context_menu_item("Run to Here", nullptr,
					debugger_interaction::capability_t::run_to_address, context))
					static_cast<void>(queue_debugger_mutation("Run to address",
						"debugger.run_to_address", context, [context]() {
							mutation_result_t result;
							result.ok = result.verified =
								debugger_engine::run_to_address(context.address, false);
							return result;
						}));
				if (context_menu_item("Toggle Breakpoint", "F9",
					debugger_interaction::capability_t::toggle_breakpoint, context))
					static_cast<void>(queue_debugger_mutation("Toggle breakpoint",
						"debugger.breakpoint_toggle", context, [context]() {
							mutation_result_t result;
							auto snapshot = debugger_engine::snapshot_breakpoints();
							int found = -1;
							for (size_t i = 0; i < snapshot.size(); ++i)
								if (!snapshot[i].is_internal && snapshot[i].address == context.address) {
									found = static_cast<int>(i);
									break;
								}
							result.ok = result.verified = found >= 0
								? debugger_engine::remove_breakpoint(found)
								: debugger_engine::add_breakpoint(context.address) >= 0;
							return result;
						}));
				if (context_menu_item("Set RIP to Here...", nullptr,
					debugger_interaction::capability_t::set_instruction_pointer, context))
					request_context_mutation(pending_context_mutation_t::set_instruction_pointer, context);
				if (g_consumed_debugger_action == "debugger.instruction.follow_branch")
					jump_to_disasm(context.value);
				break;
			case debugger_interaction::kind_t::register_value:
				if (g_consumed_debugger_action == "debugger.register.copy_decimal") {
					char decimal[32];
					std::snprintf(decimal, sizeof(decimal), "%llu",
						static_cast<unsigned long long>(context.value));
					copy_to_clipboard(decimal);
				}
				if (context_menu_item("Edit Register...", nullptr,
					debugger_interaction::capability_t::edit_register, context)) {
					g_ui.cpu_edit_reg_idx = context.index;
					g_ui.cpu_edit_context = context;
					std::snprintf(g_ui.cpu_edit_value_buf, sizeof(g_ui.cpu_edit_value_buf),
						"%016" PRIX64, context.value);
					g_ui.cpu_edit_popup_open = true;
				}
				if (context_menu_item("Set to Zero...", nullptr,
					debugger_interaction::capability_t::edit_register, context)) {
					g_ui.cpu_edit_reg_idx = context.index;
					g_ui.cpu_edit_context = context;
					std::snprintf(g_ui.cpu_edit_value_buf, sizeof(g_ui.cpu_edit_value_buf), "%016llX", 0ULL);
					g_ui.cpu_edit_popup_open = true;
				}
				break;
			case debugger_interaction::kind_t::stack_slot:
				if (g_consumed_debugger_action == "debugger.stack.copy_qword")
					copy_addr_to_clipboard(context.value);
				break;
			case debugger_interaction::kind_t::breakpoint:
				if (context_menu_item("Enable / Disable", nullptr,
					debugger_interaction::capability_t::toggle_breakpoint, context))
					static_cast<void>(queue_debugger_mutation("Toggle breakpoint state",
						"debugger.breakpoint_enable", context, [context]() {
							mutation_result_t result;
							result.ok = result.verified = debugger_engine::toggle_breakpoint(context.index);
							return result;
						}));
				if (context_menu_item("Edit Breakpoint...", nullptr,
					debugger_interaction::capability_t::edit_breakpoint, context) ||
					context_menu_item("Edit Condition...", nullptr,
						debugger_interaction::capability_t::edit_breakpoint, context) ||
					context_menu_item("Edit Log Message...", nullptr,
						debugger_interaction::capability_t::edit_breakpoint, context) ||
					context_menu_item("Configure Auto-continue...", nullptr,
						debugger_interaction::capability_t::edit_breakpoint, context)) {
					auto breakpoints = debugger_engine::snapshot_breakpoints();
					if (context.index >= 0 && context.index < static_cast<int>(breakpoints.size()) &&
						breakpoints[static_cast<size_t>(context.index)].address == context.address &&
						breakpoint_fingerprint(breakpoints[static_cast<size_t>(context.index)]) == context.value) {
						const auto& breakpoint = breakpoints[static_cast<size_t>(context.index)];
						const auto focus =
							g_consumed_debugger_action == "debugger.breakpoint.log_message"
								? breakpoint_editor_focus_t::log_message
								: g_consumed_debugger_action == "debugger.breakpoint.auto_continue"
								? breakpoint_editor_focus_t::auto_continue
								: breakpoint_editor_focus_t::condition;
						static_cast<void>(retain_breakpoint_edit(
							g_ui, context.index, breakpoint, context, focus));
					}
				}
				if (context_menu_item("Delete Breakpoint", "Delete",
					debugger_interaction::capability_t::remove_breakpoint, context))
					static_cast<void>(queue_debugger_mutation("Delete breakpoint",
						"debugger.breakpoint_delete", context, [context]() {
							mutation_result_t result;
							result.ok = result.verified = debugger_engine::remove_breakpoint(context.index);
							return result;
						}));
				break;
			case debugger_interaction::kind_t::memory_region:
				if (context_menu_item("Change Protection...", nullptr,
					debugger_interaction::capability_t::change_memory_protection, context)) {
					debugger_engine::memory_region_t region{};
					if (memory_map_view::find_region_by_base(context.address, region)) {
						memory_map_view::g_ui.change_protect_addr = region.base;
						memory_map_view::g_ui.change_protect_size = region.size;
						memory_map_view::g_ui.change_protect_choice = 0;
						memory_map_view::g_ui.change_protect_old = region.protect;
						memory_map_view::g_ui.change_protect_context = context;
						memory_map_view::g_ui.change_protect_open = true;
					} else toast_notification::push(
						"Memory map is updating; retry Change Protection in a moment.",
						toast_notification::toast_type_t::warning);
				}
				if (context_menu_item("Dump Region...", nullptr,
					debugger_interaction::capability_t::dump_memory, context)) {
					const uint64_t capped_size = context.extent;
					if (capped_size > 256ULL * 1024ULL * 1024ULL) {
						toast_notification::push("Region exceeds 256 MiB dump cap.",
							toast_notification::toast_type_t::warning);
						break;
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::debugger::record("memory_map_dump", std::to_string(context.address));
#else
					char path[MAX_PATH] = {};
					std::snprintf(path, sizeof(path), "dump_%016llX_%llu.bin",
						static_cast<unsigned long long>(context.address),
						static_cast<unsigned long long>(capped_size));
					static const char filter[] = "Binary (*.bin)\0*.bin\0All files (*.*)\0*.*\0\0";
					if (win32_dialog::show_save_file_dialog(g_hwnd, "Dump Region", filter, "bin",
						path, sizeof(path), "debugger_context.dump_region")) {
						auto result = std::make_shared<mutation_result_t>();
						const std::string destination(path);
						aida::infra::executor::submission_t submission;
						submission.owner_subsystem = "debugger";
						submission.label = "Dump memory region";
						submission.thread_class = "debugger_export";
						submission.domain = aida::infra::executor::domain_t::feature_worker;
						submission.priority = 2;
						submission.target_pid = context.target_pid;
						submission.generation = context.stop_generation;
						submission.ui_access_policy = "post_completion_only";
						submission.failure_policy = "fail_closed";
						submission.body = [context, capped_size, destination, result]() {
							if (driver_bridge::attached_pid() != context.target_pid ||
								debugger_interaction::current_stop_generation() != context.stop_generation) {
								result->detail = "The target changed before the region dump started.";
							} else {
								std::vector<uint8_t> bytes;
								result->ok = driver_bridge::read_memory_for(context.target_pid, context.address,
									static_cast<size_t>(capped_size), bytes) && bytes.size() == capped_size;
								if (!result->ok)
									result->detail = "Region dump read failed or returned a partial result.";
								else
									result->verified = write_file_atomic_exact(destination, bytes.data(),
										bytes.size(), result->detail);
							}
							const bool posted = post_debugger_ui([result]() {
								toast_notification::push(result->verified ? "Memory region dumped."
									: result->detail, result->verified
										? toast_notification::toast_type_t::success
										: toast_notification::toast_type_t::error);
							}, "region_dump_completion");
							if (!posted)
								throw std::runtime_error("Region-dump completion could not be published to the UI thread");
							if (!result->verified)
								throw std::runtime_error(result->detail.empty()
									? "Region dump failed" : result->detail);
						};
						const auto submitted = submit_owned_debugger_task(std::move(submission),
							"view.debug.memory_map", "debugger.dump_region", "Dump memory region", false);
						if (!submitted.submitted)
							toast_notification::push("Region dump queue rejected the task: " +
								submitted.reject_reason, toast_notification::toast_type_t::error);
					}
#endif
				}
				break;
			case debugger_interaction::kind_t::thread:
				if (context_menu_item("Suspend Thread", nullptr,
					debugger_interaction::capability_t::suspend_thread, context))
					static_cast<void>(queue_debugger_mutation("Suspend thread",
						"debugger.thread_suspend", context, [context]() {
							mutation_result_t result;
							result.ok = result.verified =
								driver_bridge::suspend_thread(context.thread_id, nullptr);
							return result;
						}));
				if (context_menu_item("Resume Thread", nullptr,
					debugger_interaction::capability_t::resume_thread, context))
					static_cast<void>(queue_debugger_mutation("Resume thread",
						"debugger.thread_resume", context, [context]() {
							mutation_result_t result;
							result.ok = result.verified =
								driver_bridge::resume_thread(context.thread_id, nullptr);
							return result;
						}));
				if (context_menu_item("Terminate Thread...", nullptr,
					debugger_interaction::capability_t::terminate_thread, context))
					request_context_mutation(pending_context_mutation_t::terminate_thread, context);
				break;
			case debugger_interaction::kind_t::handle:
				if (context_menu_item("Close Handle...", nullptr,
					debugger_interaction::capability_t::close_handle, context))
					request_context_mutation(pending_context_mutation_t::close_handle, context);
				break;
			case debugger_interaction::kind_t::patch:
				if (context_menu_item("Apply Patch...", nullptr,
					debugger_interaction::capability_t::apply_patch, context))
					request_context_mutation(pending_context_mutation_t::apply_patch, context);
				if (context_menu_item("Revert Patch...", nullptr,
					debugger_interaction::capability_t::revert_patch, context))
					request_context_mutation(pending_context_mutation_t::revert_patch, context);
				if (context_menu_item("Remove Patch...", nullptr,
					debugger_interaction::capability_t::remove_patch, context))
					request_context_mutation(pending_context_mutation_t::remove_patch, context);
				break;
			case debugger_interaction::kind_t::module:
				break;
			case debugger_interaction::kind_t::watch:
				if (g_consumed_debugger_action == "debugger.watch.remove")
					request_context_mutation(pending_context_mutation_t::remove_watch, context);
				break;
			case debugger_interaction::kind_t::string_value:
				break;
			case debugger_interaction::kind_t::bookmark:
				if (g_consumed_debugger_action == "debugger.bookmark.remove")
					request_context_mutation(pending_context_mutation_t::remove_bookmark, context);
				break;
			default:
				break;
		}
	}
	g_consumed_debugger_action.clear();
	render_context_mutation_confirmation();
}

inline uint64_t parse_hex_address(const char* s) {
	if (!s || !*s) return 0;
	while (*s == ' ' || *s == '\t') ++s;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
	uint64_t v = 0;
	for (; *s; ++s) {
		char c = *s;
		uint8_t d;
		if (c >= '0' && c <= '9') d = static_cast<uint8_t>(c - '0');
		else if (c >= 'a' && c <= 'f') d = static_cast<uint8_t>(10 + (c - 'a'));
		else if (c >= 'A' && c <= 'F') d = static_cast<uint8_t>(10 + (c - 'A'));
		else break;
		v = (v << 4) | d;
	}
	return v;
}

inline uint64_t resolve_register_token(const std::string& tok,
                                       const debugger_engine::register_set_t& r) {
	std::string n;
	n.reserve(tok.size());
	for (char c : tok) n.push_back(static_cast<char>(::toupper(static_cast<unsigned char>(c))));
	if (n == "RAX") return r.rax; if (n == "RBX") return r.rbx;
	if (n == "RCX") return r.rcx; if (n == "RDX") return r.rdx;
	if (n == "RSI") return r.rsi; if (n == "RDI") return r.rdi;
	if (n == "RBP") return r.rbp; if (n == "RSP") return r.rsp;
	if (n == "R8")  return r.r8;  if (n == "R9")  return r.r9;
	if (n == "R10") return r.r10; if (n == "R11") return r.r11;
	if (n == "R12") return r.r12; if (n == "R13") return r.r13;
	if (n == "R14") return r.r14; if (n == "R15") return r.r15;
	if (n == "RIP") return r.rip; if (n == "RFLAGS") return r.rflags;
	if (n == "CS")  return r.cs;  if (n == "SS")  return r.ss;
	if (n == "DS")  return r.ds;  if (n == "ES")  return r.es;
	if (n == "FS")  return r.fs;  if (n == "GS")  return r.gs;
	if (n == "DR0") return r.dr0; if (n == "DR1") return r.dr1;
	if (n == "DR2") return r.dr2; if (n == "DR3") return r.dr3;
	if (n == "DR6") return r.dr6; if (n == "DR7") return r.dr7;
	return 0;
}

inline uint64_t evaluate_watch_expression(const std::string& expr,
                                          const debugger_engine::register_set_t& r,
                                          bool& deref_out, bool& valid_out) {
	deref_out = false;
	valid_out = false;
	std::string s = expr;
	while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
	while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
	if (s.empty()) return 0;
	bool deref = false;
	if (s.front() == '[' && s.back() == ']') {
		deref = true;
		s = s.substr(1, s.size() - 2);
		while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
		while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
	}
	uint64_t total = 0;
	bool subtract = false;
	bool any_token = false;
	std::string cur;
	auto consume = [&]() {
		while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
		while (!cur.empty() && (cur.back()  == ' ' || cur.back()  == '\t')) cur.pop_back();
		if (cur.empty()) return;
		uint64_t v = 0;
		bool numeric = (cur[0] == '0' && (cur.size() > 1 && (cur[1] == 'x' || cur[1] == 'X')));
		if (!numeric) {
			bool all_hex_digits = true;
			for (char c : cur) {
				if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
					all_hex_digits = false; break;
				}
			}
			if (all_hex_digits && cur.size() >= 4) numeric = true;
		}
		if (numeric) v = parse_hex_address(cur.c_str());
		else v = resolve_register_token(cur, r);
		if (subtract) total -= v;
		else          total += v;
		any_token = true;
		cur.clear();
	};
	for (size_t i = 0; i < s.size(); ++i) {
		char c = s[i];
		if (c == '+') { consume(); subtract = false; continue; }
		if (c == '-') { consume(); subtract = true;  continue; }
		cur.push_back(c);
	}
	consume();
	if (!any_token) return 0;
	deref_out = deref;
	valid_out = true;
	return total;
}

}

static void render_tab_bar(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();

	struct visible_tab_entry_t { const char* name; const char* short_name; sub_tab_t tab; };
	static const visible_tab_entry_t visible_tabs[] = {
		{ "CPU",         "CPU", sub_tab_t::cpu },
		{ "Breakpoints", "BP",  sub_tab_t::breakpoints },
		{ "Memory Map",  "Mem", sub_tab_t::memory_map },
		{ "Call Stack",  "CS",  sub_tab_t::call_stack },
		{ "Threads",     "Thr", sub_tab_t::threads },
		{ "Watches",     "Wch", sub_tab_t::watches },
		{ "Handles",     "Hnd", sub_tab_t::handles },
		{ "Trace",       "Trc", sub_tab_t::trace_log },
		{ "Strings",     "Str", sub_tab_t::strings },
		{ "Bookmarks",   "Bm",  sub_tab_t::bookmarks },
		{ "Modules",     "Mod", sub_tab_t::modules },
		{ "Patches",     "Pat", sub_tab_t::patches },
		{ "SEH",         "SEH", sub_tab_t::seh_chain },
		{ "CFG",         "CFG", sub_tab_t::cfg },
		{ "Source",      "Src", sub_tab_t::source }
	};
	static const int visible_tab_count = static_cast<int>(sizeof(visible_tabs) / sizeof(visible_tabs[0]));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT),
	                  with_a(t.bg_elevated, a), aida::ui::metrics::radius::md);
	dl->AddRect(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT),
	            with_a(t.border_subtle, a), aida::ui::metrics::radius::md);
	dl->AddLine(ImVec2(ox, oy + TAB_HEIGHT - 1.f),
	            ImVec2(ox + w, oy + TAB_HEIGHT - 1.f),
	            with_a(t.border_subtle, a * 0.7f));
	{
		static bool s_dbg_strip_logged = false;
		if (!s_dbg_strip_logged) {
			s_dbg_strip_logged = true;
			diag::log_tagged("dbg_strip", "[dbg_strip] applied solid_line");
		}
	}

	int count = visible_tab_count;
	float tab_widths[16];
	float tab_positions[16];
	float total_tabs_w_full = 6.f;
	float total_tabs_w_short = 6.f;
	ImFont* tf = aida::ui::fonts::body_em();
	if (!tf) tf = ImGui::GetFont();
	const float tf_size = aida::ui::fonts::size_or(tf, 16.5f);
	for (int i = 0; i < count; ++i) {
		ImVec2 sz_full = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, visible_tabs[i].name);
		ImVec2 sz_short = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, visible_tabs[i].short_name);
		total_tabs_w_full += (sz_full.x + 22.f) + 2.f;
		total_tabs_w_short += (sz_short.x + 18.f) + 2.f;
	}
	total_tabs_w_full += 6.f;
	total_tabs_w_short += 6.f;

	const float reserved_check = 36.f;
	bool use_short_labels = (w - reserved_check) < total_tabs_w_full && (w - reserved_check) >= total_tabs_w_short;

	static bool s_logged_short = false;
	if (use_short_labels && !s_logged_short) {
		s_logged_short = true;
		::diag::log_tagged_fmt("responsive",
			"debugger_view tabs short_labels w=%.0f full_need=%.0f short_need=%.0f",
			w, total_tabs_w_full, total_tabs_w_short);
	} else if (!use_short_labels && s_logged_short) {
		s_logged_short = false;
	}

	float total_tabs_w = 6.f;
	for (int i = 0; i < count; ++i) {
		const char* lbl = use_short_labels ? visible_tabs[i].short_name : visible_tabs[i].name;
		ImVec2 sz = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, lbl);
		tab_widths[i] = sz.x + (use_short_labels ? 18.f : 22.f);
		tab_positions[i] = total_tabs_w;
		total_tabs_w += tab_widths[i] + 2.f;
	}
	total_tabs_w += 6.f;

	float reserved = 36.f;
	float visible_w = w - reserved;
	bool tabs_overflow = total_tabs_w > visible_w;

	if (tabs_overflow) {
		bool bar_hov = ImGui::IsMouseHoveringRect(ImVec2(ox, oy),
			ImVec2(ox + visible_w, oy + TAB_HEIGHT), false);
		if (bar_hov) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f)
				ui.tab_target_scroll_x -= wheel * 60.f;
		}

		float max_scroll = std::max(0.f, total_tabs_w - visible_w);
		ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
		ui.tab_scroll_x = ui_anim::smooth_lerp(ui.tab_scroll_x, ui.tab_target_scroll_x, 16.f, dt);
		if (std::abs(ui.tab_target_scroll_x - ui.tab_scroll_x) < 0.3f)
			ui.tab_scroll_x = ui.tab_target_scroll_x;

		int active_vis = 0;
		for (int vi = 0; vi < count; ++vi) {
			if (visible_tabs[vi].tab == ui.active_tab) { active_vis = vi; break; }
		}
		if (ui.tab_last_ensured != active_vis) {
			float active_left = tab_positions[active_vis] - ui.tab_scroll_x + ox;
			float active_right = active_left + tab_widths[active_vis];
			if (active_left < ox + 10.f)
				ui.tab_target_scroll_x = tab_positions[active_vis] - 10.f;
			else if (active_right > ox + visible_w - 10.f)
				ui.tab_target_scroll_x = tab_positions[active_vis] + tab_widths[active_vis] - visible_w + 10.f;
			ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
			ui.tab_last_ensured = active_vis;
		}
	} else {
		ui.tab_scroll_x = 0.f;
		ui.tab_target_scroll_x = 0.f;
		ui.tab_last_ensured = -1;
	}

	ImGui::PushClipRect(ImVec2(ox, oy), ImVec2(ox + visible_w, oy + TAB_HEIGHT), true);

	int active_idx = 0;
	for (int vi = 0; vi < count; ++vi) {
		if (visible_tabs[vi].tab == ui.active_tab) { active_idx = vi; break; }
	}
	float target_ul_x = ox + tab_positions[active_idx] - ui.tab_scroll_x + 6.f;
	float target_ul_w = tab_widths[active_idx] - 12.f;

	if (ui.underline_w < 0.01f) {
		ui.underline_x = target_ul_x;
		ui.underline_w = target_ul_w;
	}
	ui.underline_x = ui_anim::spring_interp(ui.underline_x, target_ul_x, ui.underline_vel, 280.f, 22.f, dt);
	ui.underline_w = ui_anim::smooth_lerp(ui.underline_w, target_ul_w, 16.f, dt);

	for (int i = 0; i < count; ++i) {
		auto tab = visible_tabs[i].tab;
		const char* tab_name_str = use_short_labels ? visible_tabs[i].short_name : visible_tabs[i].name;
		const char* tab_full_name = visible_tabs[i].name;
		bool active = (ui.active_tab == tab);
		float tx = ox + tab_positions[i] - ui.tab_scroll_x;
		float tw = tab_widths[i];
		float ty = oy + 2.f;
		float th = TAB_HEIGHT - 4.f;

		if (tx + tw < ox || tx > ox + visible_w) continue;

		bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx, ty), ImVec2(tx + tw, ty + th), false);

		int anim_slot = static_cast<int>(tab);
		float& tab_a = ui.tab_anim[anim_slot];
		float tab_target = active ? 1.f : (hov ? 0.55f : 0.f);
		tab_a = ui_anim::smooth_lerp(tab_a, tab_target, 14.f, dt);

		if (tab_a > 0.01f) {
			float ra = tab_a * a;
			ImU32 wash = aida::ui::mix(t.hover_wash, t.accent_glow, tab_a * 0.6f);
			dl->AddRectFilled(ImVec2(tx + 3.f, ty + 1.f),
			                  ImVec2(tx + tw - 3.f, ty + th - 1.f),
			                  with_a(wash, ra), aida::ui::metrics::radius::sm);
		}

		ImVec2 ts = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, tab_name_str);
		ImU32 col = active
			? with_a(t.accent_hover, a)
			: aida::ui::mix(t.text_secondary, t.text_primary, hov ? 0.6f : 0.f);
		col = with_a(col, a);

		dl->AddText(tf, tf_size,
			ImVec2(tx + (tw - ts.x) * 0.5f, ty + (th - ts.y) * 0.5f),
			col, tab_name_str);

		if (use_short_labels && hov) {
			if (ImGui::BeginTooltip()) {
				ImGui::TextUnformatted(tab_full_name);
				ImGui::EndTooltip();
			}
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (ui.active_tab != tab) {
				diag::log_tagged_fmt("dbg_view", "tab_switch: '%s' -> '%s'", visible_tabs[active_idx].name, tab_full_name);
				int prev_i = static_cast<int>(ui.active_tab);
				int next_i = static_cast<int>(tab);
				ui.tab_animator.direction = (next_i > prev_i) ? 1.f : -1.f;
				ui.tab_animator.slide.start(aida::motion::dur::md,
					aida::motion::ease::out_cubic);
				ui.prev_tab = ui.active_tab;
				ui.content_fade = 0.f;
			}
			ui.active_tab = tab;
		}
	}

	ui_anim::render_tab_underline_glow(dl, ui.underline_x, ui.underline_w,
		oy + TAB_HEIGHT - 3.f, a);

	ImGui::PopClipRect();

	if (tabs_overflow) {
		float max_scroll = total_tabs_w - visible_w;
		if (ui.tab_scroll_x > 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + static_cast<float>(f), oy),
					ImVec2(ox + static_cast<float>(f) + 1.f, oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
			}
			float ccx_l = ox + 10.f;
			float ccy_l = oy + TAB_HEIGHT * 0.5f;
			ImU32 chev_l = with_a(t.accent_u32, a * 0.95f);
			dl->AddTriangleFilled(ImVec2(ccx_l + 4.f, ccy_l - 6.f), ImVec2(ccx_l + 4.f, ccy_l + 6.f),
				ImVec2(ccx_l - 4.f, ccy_l), chev_l);
			if (ImGui::IsMouseHoveringRect(ImVec2(ccx_l - 10.f, oy), ImVec2(ccx_l + 12.f, oy + TAB_HEIGHT)) &&
				ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ui.tab_target_scroll_x -= 120.f;
				if (ui.tab_target_scroll_x < 0.f) ui.tab_target_scroll_x = 0.f;
			}
		}
		if (ui.tab_scroll_x < max_scroll - 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + visible_w - static_cast<float>(f) - 1.f, oy),
					ImVec2(ox + visible_w - static_cast<float>(f), oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
			}
			float ccx = ox + visible_w - 10.f;
			float ccy = oy + TAB_HEIGHT * 0.5f;
			ImU32 chev = with_a(t.accent_u32, a * 0.95f);
			dl->AddTriangleFilled(ImVec2(ccx - 4.f, ccy - 6.f), ImVec2(ccx - 4.f, ccy + 6.f),
				ImVec2(ccx + 4.f, ccy), chev);
			float pulse = 0.5f + 0.5f * std::sin(static_cast<float>(ImGui::GetTime()) * 3.f);
			dl->AddCircle(ImVec2(ccx, ccy), 11.f,
				with_a(t.accent_u32, a * 0.35f * pulse), 16, 1.2f);
			if (ImGui::IsMouseHoveringRect(ImVec2(ccx - 12.f, oy), ImVec2(ccx + 10.f, oy + TAB_HEIGHT)) &&
				ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ui.tab_target_scroll_x += 120.f;
				if (ui.tab_target_scroll_x > max_scroll) ui.tab_target_scroll_x = max_scroll;
			}
		}
	}

	for (int si = 0; si < 3; ++si) {
		float sa = (1.f - static_cast<float>(si) / 3.f) * 0.30f * a;
		dl->AddRectFilled(
			ImVec2(ox, oy + TAB_HEIGHT + static_cast<float>(si)),
			ImVec2(ox + w, oy + TAB_HEIGHT + static_cast<float>(si) + 1.f),
			IM_COL32(0, 0, 0, static_cast<int>(sa * 255.f)));
	}

	{
		static bool s_stealth_pill_removed_logged = false;
		if (!s_stealth_pill_removed_logged) {
			s_stealth_pill_removed_logged = true;
			diag::log_tagged("stealth_remove", "[stealth_remove] pill_removed=1");
		}
	}
}

bool is_visible_sub_tab(sub_tab_t tab) {
	switch (tab) {
		case sub_tab_t::cpu:
		case sub_tab_t::breakpoints:
		case sub_tab_t::memory_map:
		case sub_tab_t::call_stack:
		case sub_tab_t::threads:
		case sub_tab_t::watches:
		case sub_tab_t::handles:
		case sub_tab_t::trace_log:
		case sub_tab_t::strings:
		case sub_tab_t::bookmarks:
		case sub_tab_t::modules:
		case sub_tab_t::patches:
		case sub_tab_t::seh_chain:
		case sub_tab_t::cfg:
		case sub_tab_t::source:
			return true;
		case sub_tab_t::COUNT:
			return false;
	}
	return false;
}

int visible_sub_tab_count() {
	return static_cast<int>(sub_tab_t::COUNT);
}


namespace cpu_view_detail {

struct reg_row_t {
	const char* name;
	uint64_t    value;
	uint8_t     group;
	bool        editable;
};

inline ImU32 mnemonic_color(const AsmInstr& ins, const aida::ui::theme_t& t) {
	if (ins.is_call)   return t.syn_function;
	if (ins.is_branch) return t.warning;
	if (ins.is_ret)    return t.error;
	if (ins.is_priv)   return t.accent_u32;
	if (ins.is_nop)    return t.text_dim;
	return t.syn_keyword;
}

inline std::string lowercase_reg_name(const char* name) {
	std::string out;
	for (const char* p = name; *p; ++p)
		out.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(*p))));
	return out;
}

inline void open_edit_modal(int row_idx, uint64_t value) {
	auto& ui = g_ui;
	ui.cpu_edit_reg_idx = row_idx;
	ui.cpu_edit_context = debugger_interaction::capture(
		debugger_interaction::kind_t::register_value, 0, value, row_idx);
	std::snprintf(ui.cpu_edit_value_buf, sizeof(ui.cpu_edit_value_buf),
		"%016" PRIX64, value);
	ui.cpu_edit_popup_open = true;
}

inline bool is_likely_pointer(uint64_t v) {
	return v >= 0x00010000ULL && v < 0x00007FFFFFFFFFFFULL;
}

inline ImU32 register_value_color(uint64_t v, bool is_segment, bool is_debug,
                                  const aida::ui::theme_t& t) {
	if (v == 0)             return t.text_dim;
	if (is_debug)           return t.warning;
	if (is_segment)         return t.info;
	if (is_likely_pointer(v)) return t.text_address;
	return t.syn_number;
}

}

static void draw_cpu_reg_row(ImDrawList* dl, float x, float y, float w, float row_h,
                             int row_idx, const cpu_view_detail::reg_row_t& r,
                             float flash, bool selected, bool hovered, float alpha) {
	const auto& t = aida::ui::resolved();
	draw_row_bg(dl, x, y, w, row_h, selected, hovered, row_idx, 1.f, alpha);

	if (flash > 0.001f) {
		ImU32 flash_col = with_a(t.warning, alpha * flash * 0.55f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + row_h), flash_col, 4.f);
		ImU32 stripe = with_a(t.warning, alpha * flash * 0.85f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + row_h), stripe);
	}

	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, 16.5f);
	const float code_font_size = aida::ui::fonts::size_or(code_font, 14.5f);

	ImU32 name_col;
	switch (r.group) {
		case 1:  name_col = t.info;        break;
		case 2:  name_col = t.warning;     break;
		default: name_col = t.text_primary; break;
	}
	dl->AddText(body_font, body_font_size,
		ImVec2(x + 10.f, y + (row_h - body_font_size) * 0.5f),
		with_a(name_col, alpha), r.name);

	char vbuf[20];
	if (r.group == 1)
		std::snprintf(vbuf, sizeof(vbuf), "%04X", static_cast<unsigned>(r.value & 0xFFFFu));
	else
		std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, r.value);

	ImU32 vcol = cpu_view_detail::register_value_color(r.value,
		r.group == 1, r.group == 2, t);
	dl->AddText(code_font, code_font_size,
		ImVec2(x + 64.f, y + (row_h - code_font_size) * 0.5f),
		with_a(vcol, alpha), vbuf);
}

static void render_cpu_disasm_slice(ImDrawList* dl, float x, float y, float w, float h,
                                    uint64_t rip, float alpha) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	draw_glass_card(dl, ImVec2(x, y), ImVec2(x + w, y + h), 10.f, alpha);
	draw_panel_header(dl, x, y, w, "LIVE DISASM @ RIP", alpha);

	if (rip == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const float fnt_size = aida::ui::fonts::size_or(fnt, 13.5f);
		const char* msg = "RIP is zero (target not paused at a valid instruction).";
		ImVec2 sz = fnt->CalcTextSizeA(fnt_size, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt_size,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	debugger_engine::request_disasm_refresh(rip, 220);
	uint64_t base = 0;
	auto buf = debugger_engine::cached_disasm_window(base);
	if (buf.empty() || base == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const float fnt_size = aida::ui::fonts::size_or(fnt, 13.5f);
		const char* msg = "Fetching instruction stream...";
		ImVec2 sz = fnt->CalcTextSizeA(fnt_size, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt_size,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	float content_y = y + HEADER_H + 2.f;
	float content_h = h - HEADER_H - 4.f;
	if (content_h < 24.f) return;

	int max_rows = 256;
	struct decoded_row_t {
		uint64_t addr;
		int      len;
		AsmInstr ins;
	};
	std::vector<decoded_row_t> rows;
	rows.reserve(64);

	size_t offset = 0;
	if (rip > base && rip < base + buf.size()) {
		offset = static_cast<size_t>(rip - base);
		if (offset > 0x40) offset = static_cast<size_t>(rip - base) - 0x40;
		else offset = 0;
	}
	uint64_t cursor_va = base + offset;
	size_t cursor = offset;
	while (cursor < buf.size() && static_cast<int>(rows.size()) < max_rows) {
		int remaining = static_cast<int>(buf.size() - cursor);
		if (remaining <= 0) break;
		AsmInstr ins = zydis_decode_one(buf.data() + cursor, remaining, cursor_va);
		decoded_row_t row;
		row.addr = cursor_va;
		row.len = ins.len > 0 ? ins.len : 1;
		row.ins = ins;
		rows.push_back(row);
		cursor += static_cast<size_t>(row.len);
		cursor_va += static_cast<uint64_t>(row.len);
	}

	int rip_idx = -1;
	for (size_t i = 0; i < rows.size(); ++i) {
		if (rows[i].addr == rip) { rip_idx = static_cast<int>(i); break; }
	}

	float row_h = 20.f;
	float child_w = w - 4.f;

	ImGui::SetCursorScreenPos(ImVec2(x + 2.f, content_y));
	ImGui::PushID("##cpu_disasm_slice");
	ImGui::BeginChild("##cpu_disasm_child", ImVec2(child_w, content_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	if (rip_idx >= 0 && ui.cpu_disasm_anchor_rip != rip) {
		float target = static_cast<float>(rip_idx) * row_h - content_h * 0.35f;
		if (target < 0.f) target = 0.f;
		ImGui::SetScrollY(target);
		ui.cpu_disasm_anchor_rip = rip;
	}

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	const float code_font_size = aida::ui::fonts::size_or(code_font, 14.5f);

	ImGuiListClipper clipper;
	clipper.Begin(static_cast<int>(rows.size()), row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			const auto& dr = rows[static_cast<size_t>(i)];
			const auto row_context = debugger_interaction::capture(
				debugger_interaction::kind_t::instruction, dr.addr,
				dr.ins.branch_target, i, 0, static_cast<std::uint64_t>(dr.len),
				dr.ins.mnem, dr.ins.ops);
			const auto context_for_row = [&](int row) {
				const auto& item = rows[static_cast<std::size_t>(row)];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::instruction, item.addr,
					item.ins.branch_target, row, 0,
					static_cast<std::uint64_t>(item.len), item.ins.mnem, item.ins.ops);
			};
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();

			ImGui::SetCursorScreenPos(ImVec2(x + 4.f, ry));
			ImGui::PushID(i + 0xD0000);
			ImGui::InvisibleButton("##cpu_disasm_row", ImVec2(child_w - 8.f, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("instruction", "debugger-instruction-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::instruction, dr.addr,
					dr.ins.branch_target, i, 0, static_cast<std::uint64_t>(dr.len),
					dr.ins.mnem, dr.ins.ops));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			bool is_rip = (dr.addr == rip);
			bool is_sel = debugger_row_selected(row_context, ui.cpu_disasm_selected == i);

			if (is_rip) {
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + child_w - 2.f, ry + row_h),
					with_a(t.accent_glow, alpha * 0.30f), 3.f);
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + 4.f, ry + row_h),
					with_a(t.accent_u32, alpha));
				float pulse = aida::ui::clock::pulse(2.4f, 0.55f, 1.f);
				dl->AddTriangleFilled(
					ImVec2(x + 8.f, ry + row_h * 0.5f - 4.f),
					ImVec2(x + 8.f, ry + row_h * 0.5f + 4.f),
					ImVec2(x + 14.f, ry + row_h * 0.5f),
					with_a(t.accent_u32, alpha * pulse));
			} else if (is_sel) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, true, false, i, 1.f, alpha);
			} else if (hov) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, false, true, i, 1.f, alpha);
			}

			char addr_buf[20];
			std::snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64, dr.addr);
			dl->AddText(code_font, code_font_size,
				ImVec2(x + 18.f, ry + (row_h - code_font_size) * 0.5f),
				with_a(is_rip ? t.accent_hover : t.text_address, alpha), addr_buf);

			char bytes_buf[40] = {};
			int blen = dr.ins.len > 8 ? 8 : dr.ins.len;
			char* bp = bytes_buf;
			for (int b = 0; b < blen; ++b) {
				bp += std::snprintf(bp,
					sizeof(bytes_buf) - static_cast<std::size_t>(bp - bytes_buf),
					"%02X ", static_cast<unsigned>(dr.ins.raw[b]));
			}
			if (dr.ins.len > 8) {
				std::snprintf(bp,
					sizeof(bytes_buf) - static_cast<std::size_t>(bp - bytes_buf), "+");
			}
			dl->AddText(code_font, code_font_size,
				ImVec2(x + 160.f, ry + (row_h - code_font_size) * 0.5f),
				with_a(t.text_dim, alpha * 0.85f), bytes_buf);

			ImU32 mc = cpu_view_detail::mnemonic_color(dr.ins, t);
			dl->AddText(code_font, code_font_size,
				ImVec2(x + 300.f, ry + (row_h - code_font_size) * 0.5f),
				with_a(mc, alpha), dr.ins.mnem);

			if (dr.ins.ops[0] != 0) {
				dl->AddText(code_font, code_font_size,
					ImVec2(x + 360.f, ry + (row_h - code_font_size) * 0.5f),
					with_a(t.text_primary, alpha), dr.ins.ops);
			}

			if (clicked) {
				ui.cpu_disasm_selected = i;
				select_debugger_row(row_context, static_cast<int>(rows.size()),
					context_for_row, false);
			}
			if (dclicked && dr.ins.branch_target != 0) {
				diag::log_tagged_fmt("cpu_view",
					"disasm_dclick_follow target=0x%llx",
					static_cast<unsigned long long>(dr.ins.branch_target));
				jump_to_disasm(dr.ins.branch_target);
			}
			if (rclicked) {
				select_debugger_row(row_context, static_cast<int>(rows.size()),
					context_for_row, true);
				diag::log_tagged_fmt("cpu_view",
					"disasm_rclick addr=0x%llx target=0x%llx",
					static_cast<unsigned long long>(dr.addr),
					static_cast<unsigned long long>(dr.ins.branch_target));
			}
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();
}

static void render_source_debug(ImDrawList* dl, float x, float y, float w, float h,
	float alpha) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	const auto published = source_debug_service::snapshot();
	const bool has_current = published && published->current.valid;
	const bool has_source = has_current &&
		(published->current.source_state == source_debug_service::source_state_t::available ||
			(published->current.source_state == source_debug_service::source_state_t::truncated &&
				!published->current.excerpt.empty()));
	const bool operation_pending = published && published->operation_pending;
	auto report = [](bool accepted, const std::string& error,
		const char* accepted_text) {
		if (accepted) {
			toast_notification::push(accepted_text,
				toast_notification::toast_type_t::info);
		} else {
			toast_notification::push(error.empty() ? "The source-debug action was rejected" : error,
				toast_notification::toast_type_t::error);
		}
	};
	auto make_source_actions = [published](const source_debug_service::definition_t& definition) {
		aida::ui::application_ui::retained_entity_context_t retained;
		if (!published) return retained;
		retained.owner_id = "debugger.source.breakpoint";
		retained.entity_id = definition.id;
		retained.entity_generation = published->generation;
		retained.active_view = aida::ui::stable_view_id_t("view.debug.source");
		retained.validate_identity = [id = definition.id, generation = published->generation]() {
			const auto current = source_debug_service::snapshot();
			if (!current || current->generation != generation)
				return aida::ui::capability_state_t::unavailable("The source-debug publication changed; reopen the menu.");
			const bool exists = std::any_of(current->definitions.begin(), current->definitions.end(),
				[&](const auto& item) { return item.id == id; });
			return exists ? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable("The source breakpoint was removed.");
		};
		auto add = [&](const char* id, bool enabled, const char* reason) {
			retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(reason),
				[]() { return aida::ui::action_handler_result_t::completed(); }});
		};
		add("debugger.source.open", !definition.file_path.empty(), "The source breakpoint has no file path.");
		add("debugger.source.open_disassembly", !definition.locations.empty(), "The source breakpoint has no bound address.");
		add("debugger.source.copy_location", !definition.file_path.empty(), "The source breakpoint has no file path.");
		add("debugger.source.copy_address", !definition.locations.empty(), "The source breakpoint has no bound address.");
		add("debugger.source.rebind_all", !published->operation_pending, "A source-debug operation is already running.");
		add("debugger.source.remove", !published->operation_pending, "A source-debug operation is already running.");
		return retained;
	};
	auto open_source_actions = [&make_source_actions](
		const source_debug_service::definition_t& definition,
		aida::ui::context_menu_open_origin_t origin) {
		auto retained = make_source_actions(definition);
		if (!retained.owner_id.empty())
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), origin);
	};

	draw_glass_card(dl, ImVec2(x, y), ImVec2(x + w, y + h), 8.f, alpha);
	const float pad = 8.f;
	const float toolbar_h = 34.f;
	ImGui::SetCursorScreenPos(ImVec2(x + pad, y + 3.f));
	ImGui::PushID("source_debug_toolbar");
	std::string action_error;
	if (aida::ui::button("Open Source", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(100.f, 28.f), !has_source)) {
		action_error.clear();
		report(source_debug_service::request_open_current_source(&action_error),
			action_error, "Opened the exact stopped source location");
	}
	ImGui::SameLine(0.f, 5.f);
	if (aida::ui::button("Open Assembly", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(110.f, 28.f), !has_current)) {
		action_error.clear();
		report(source_debug_service::request_open_current_disassembly(&action_error),
			action_error, "Synchronized the disassembly view");
	}
	ImGui::SameLine(0.f, 5.f);
	if (aida::ui::button("Toggle BP  F9", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(108.f, 28.f), !has_current || operation_pending)) {
		action_error.clear();
		report(source_debug_service::request_toggle(published->current.file_path,
			published->current.line, &action_error), action_error,
			"Queued the source-breakpoint update");
	}
	ImGui::SameLine(0.f, 5.f);
	if (aida::ui::button("Rebind", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(76.f, 28.f), operation_pending)) {
		action_error.clear();
		report(source_debug_service::request_rebind(&action_error), action_error,
			"Queued exact PDB source rebinding");
	}
	ImGui::PopID();

	const float status_y = y + toolbar_h;
	const float status_h = 46.f;
	dl->AddRectFilled(ImVec2(x + pad, status_y), ImVec2(x + w - pad, status_y + status_h),
		with_a(t.bg_elevated, alpha * 0.82f), 4.f);
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	const float code_size = aida::ui::fonts::size_or(code_font, 13.f);
	const float body_size = aida::ui::fonts::size_or(body_font, 13.f);
	std::string location_text = "No stopped source location";
	std::string location_detail = published
		? (published->error.empty() ? published->current.detail : published->error)
		: "Source debugger is initializing";
	ImU32 state_color = t.text_dim;
	if (has_current) {
		location_text = published->current.file_path + ":" +
			std::to_string(published->current.line) + "  " + published->current.module_name;
		location_detail = published->current.detail;
		state_color = published->current.source_state ==
			source_debug_service::source_state_t::truncated ? t.warning
			: (has_source ? t.success : t.warning);
	}
	if (operation_pending) {
		location_detail = published->operation_label.empty()
			? "Source-debug operation is running" : published->operation_label;
		state_color = t.info;
	} else if (published && !published->error.empty()) {
		location_detail = published->error;
		state_color = t.error;
	}
	dl->AddCircleFilled(ImVec2(x + pad + 10.f, status_y + 14.f), 4.f,
		with_a(state_color, alpha));
	dl->AddText(code_font, code_size, ImVec2(x + pad + 20.f, status_y + 6.f),
		with_a(t.text_primary, alpha), location_text.c_str());
	dl->AddText(body_font, body_size, ImVec2(x + pad + 20.f, status_y + 25.f),
		with_a(state_color, alpha), location_detail.c_str());

	const float definitions_h = std::clamp(h * 0.31f, 145.f, 245.f);
	const float top_y = status_y + status_h + 7.f;
	const float definitions_y = y + h - definitions_h;
	const float top_h = std::max(70.f, definitions_y - top_y - 7.f);
	const bool side_by_side = w >= 820.f;
	const float source_w = side_by_side ? std::floor((w - pad * 3.f) * 0.46f) : w - pad * 2.f;
	const float source_h = side_by_side ? top_h : std::max(64.f, top_h * 0.48f);
	const float source_x = x + pad;
	const float source_y = top_y;
	const float disasm_x = side_by_side ? source_x + source_w + pad : source_x;
	const float disasm_y = side_by_side ? top_y : source_y + source_h + pad;
	const float disasm_w = side_by_side ? w - (disasm_x - x) - pad : source_w;
	const float disasm_h = side_by_side ? top_h : std::max(60.f, top_h - source_h - pad);

	draw_glass_card(dl, ImVec2(source_x, source_y),
		ImVec2(source_x + source_w, source_y + source_h), 6.f, alpha);
	draw_panel_header(dl, source_x, source_y, source_w, "SOURCE CONTEXT", alpha);
	const float excerpt_y = source_y + HEADER_H + 2.f;
	const float excerpt_h = std::max(1.f, source_h - HEADER_H - 4.f);
	ImGui::SetCursorScreenPos(ImVec2(source_x + 2.f, excerpt_y));
	ImGui::PushID("source_debug_excerpt");
	if (ImGui::BeginChild("##excerpt", ImVec2(source_w - 4.f, excerpt_h), false,
		ImGuiWindowFlags_HorizontalScrollbar)) {
		if (has_source && !published->current.excerpt.empty()) {
			for (const auto& line : published->current.excerpt) {
				ImGui::PushID(static_cast<int>(line.line));
				if (line.current) {
					const ImVec2 row_pos = ImGui::GetCursorScreenPos();
					dl->AddRectFilled(row_pos,
						ImVec2(row_pos.x + std::max(source_w - 8.f, ImGui::GetContentRegionAvail().x),
							row_pos.y + 20.f), with_a(t.accent_glow, alpha * 0.36f), 3.f);
				}
				ImGui::PushFont(code_font);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
					with_a(line.current ? t.accent_hover : t.text_dim, alpha)),
					"%5u", static_cast<unsigned>(line.line));
				ImGui::SameLine(0.f, 10.f);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
					with_a(t.text_primary, alpha)), "%s", line.text.c_str());
				ImGui::PopFont();
				ImGui::PopID();
			}
		} else {
			ImGui::Dummy(ImVec2(4.f, 6.f));
			ImGui::TextDisabled("%s", location_detail.c_str());
		}
	}
	ImGui::EndChild();
	ImGui::PopID();

	const std::uint64_t assembly_address = has_current ? published->current.address : 0;
	render_cpu_disasm_slice(dl, disasm_x, disasm_y, disasm_w, disasm_h,
		assembly_address, alpha);

	const float definitions_x = x + pad;
	const float definitions_w = w - pad * 2.f;
	draw_glass_card(dl, ImVec2(definitions_x, definitions_y),
		ImVec2(definitions_x + definitions_w, y + h - pad), 6.f, alpha);
	draw_panel_header(dl, definitions_x, definitions_y, definitions_w,
		"PERSISTENT SOURCE BREAKPOINTS", alpha);
	const float table_y = definitions_y + HEADER_H + 2.f;
	const float table_h = std::max(1.f, y + h - pad - table_y - 2.f);
	ImGui::SetCursorScreenPos(ImVec2(definitions_x + 2.f, table_y));
	ImGui::PushID("source_debug_definitions");
	bool table_focused = false;
	if (ImGui::BeginChild("##definitions", ImVec2(definitions_w - 4.f, table_h), false)) {
		table_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows);
		const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
			ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
		if (ImGui::BeginTable("##source_bp_table", 5, flags)) {
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 76.f);
			ImGui::TableSetupColumn("File : line", ImGuiTableColumnFlags_WidthStretch, 0.34f);
			ImGui::TableSetupColumn("Locations", ImGuiTableColumnFlags_WidthFixed, 74.f);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.f);
			ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.66f);
			ImGui::TableHeadersRow();
			const int count = published ? static_cast<int>(published->definitions.size()) : 0;
			ImGuiListClipper clipper;
			clipper.Begin(count, 22.f);
			while (clipper.Step()) {
				for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
					const auto& definition = published->definitions[static_cast<size_t>(i)];
					ImGui::PushID(i);
					ImGui::TableNextRow(ImGuiTableRowFlags_None, 22.f);
					ImGui::TableSetColumnIndex(0);
					ImU32 definition_color = t.warning;
					if (definition.state == source_debug_service::binding_state_t::bound)
						definition_color = t.success;
					else if (definition.state == source_debug_service::binding_state_t::error ||
						definition.state == source_debug_service::binding_state_t::stale)
						definition_color = t.error;
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(with_a(definition_color, alpha)),
						"%s", source_debug_service::binding_state_label(definition.state));
					ImGui::TableSetColumnIndex(1);
					const std::string file_line = definition.file_path + ":" +
						std::to_string(definition.line);
					const bool selected = ui.source_definition_selected == i;
					if (ImGui::Selectable(file_line.c_str(), selected,
						ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
						ImVec2(0.f, 20.f))) {
						ui.source_definition_selected = i;
						if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							action_error.clear();
							report(source_debug_service::request_open_source(definition.file_path,
								definition.line, &action_error), action_error,
								"Opened the source breakpoint location");
						}
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						studio_debug_token_id("source",
							definition.id),
						"debugger-source-row", false, false,
						"aida.dock-window.view.debug.source");
#endif
					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						ui.source_definition_selected = i;
						open_source_actions(definition,
							aida::ui::context_menu_open_origin_t::pointer);
					}
					ImGui::TableSetColumnIndex(2);
					ImGui::Text("%zu", definition.locations.size());
					ImGui::TableSetColumnIndex(3);
					if (definition.locations.empty()) ImGui::TextDisabled("unresolved");
					else ImGui::Text("0x%016" PRIX64, definition.locations.front().address);
					ImGui::TableSetColumnIndex(4);
					ImGui::TextUnformatted(definition.detail.c_str());
					ImGui::PopID();
				}
			}
			clipper.End();
			ImGui::EndTable();
		}
		if (!published || published->definitions.empty()) {
			ImGui::Dummy(ImVec2(4.f, 8.f));
			ImGui::TextDisabled("Press F9 on a path-backed source line to create a persistent breakpoint.");
		}
		const bool source_remove_key = ImGui::IsKeyPressed(ImGuiKey_Delete, false);
		const bool source_menu_key = ImGui::IsKeyPressed(ImGuiKey_Menu, false);
		const bool source_shift_f10 = ImGui::GetIO().KeyShift &&
			ImGui::IsKeyPressed(ImGuiKey_F10, false);
		if (published && ui.source_definition_selected >= 0 &&
			ui.source_definition_selected < static_cast<int>(published->definitions.size()) &&
			(source_remove_key || source_menu_key || source_shift_f10)) {
			const auto& definition = published->definitions[
				static_cast<size_t>(ui.source_definition_selected)];
			if (source_menu_key)
				open_source_actions(definition, aida::ui::context_menu_open_origin_t::menu_key);
			else if (source_shift_f10)
				open_source_actions(definition, aida::ui::context_menu_open_origin_t::shift_f10);
			else {
				auto retained = make_source_actions(definition);
				if (!retained.owner_id.empty())
					static_cast<void>(aida::ui::application_ui::execute_retained_entity_action(
						"debugger.source.remove",
						aida::ui::action_invocation_source_t::shortcut, retained));
			}
		}
		aida::ui::application_ui::render_retained_entity_context_menu(
			"debugger.source.breakpoint");
		std::string source_action;
		if (published && ui.source_definition_selected >= 0 &&
			ui.source_definition_selected < static_cast<int>(published->definitions.size()))
			source_action = aida::ui::application_ui::consume_retained_entity_action(
				"debugger.source.breakpoint", published->definitions[
					static_cast<size_t>(ui.source_definition_selected)].id.c_str());
		if (!source_action.empty()) {
			if (published && ui.source_definition_selected >= 0 &&
				ui.source_definition_selected < static_cast<int>(published->definitions.size())) {
				const auto& definition = published->definitions[
					static_cast<size_t>(ui.source_definition_selected)];
				if (source_action == "debugger.source.open") {
					action_error.clear();
					report(source_debug_service::request_open_source(definition.file_path,
						definition.line, &action_error), action_error,
						"Opened the source breakpoint location");
				}
				if (source_action == "debugger.source.open_disassembly") {
					const auto context = disasm_view::capture_selected_workspace();
					if (context) {
						disasm_view::goto_address(definition.locations.front().address, context);
						static_cast<void>(aida::ui::application_views::open_or_focus(
							aida::ui::stable_view_id_t("document.disassembly")));
					} else {
						toast_notification::push("Open the matching analysis workspace first.",
							toast_notification::toast_type_t::warning);
					}
				}
				if (source_action == "debugger.source.copy_location")
					ImGui::SetClipboardText((definition.file_path + ":" +
						std::to_string(definition.line)).c_str());
				if (source_action == "debugger.source.copy_address") {
					char address[24]{};
					std::snprintf(address, sizeof(address), "0x%016" PRIX64,
						definition.locations.front().address);
					ImGui::SetClipboardText(address);
				}
				if (source_action == "debugger.source.rebind_all") {
					action_error.clear();
					report(source_debug_service::request_rebind(&action_error), action_error,
						"Queued exact PDB source rebinding");
				}
				if (source_action == "debugger.source.remove") {
					action_error.clear();
					report(source_debug_service::request_remove(definition.id, &action_error),
						action_error, "Queued source-breakpoint removal");
				}
			}
		}
	}
	ImGui::EndChild();
	ImGui::PopID();
	static_cast<void>(table_focused);
}

static void render_cpu_stack_view(ImDrawList* dl, float x, float y, float w, float h,
                                  uint64_t rsp, float alpha) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	draw_glass_card(dl, ImVec2(x, y), ImVec2(x + w, y + h), 10.f, alpha);
	draw_panel_header(dl, x, y, w, "STACK @ RSP", alpha);

	if (rsp == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const float fnt_size = aida::ui::fonts::size_or(fnt, 13.5f);
		const char* msg = "RSP is zero (target not paused).";
		ImVec2 sz = fnt->CalcTextSizeA(fnt_size, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt_size,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	constexpr size_t kStackBytes = 0x100;
	debugger_engine::request_stack_refresh(rsp, kStackBytes, 220);
	uint64_t base = 0;
	auto buf = debugger_engine::cached_stack_bytes(base);

	float content_y = y + HEADER_H + 2.f;
	float content_h = h - HEADER_H - 4.f;
	if (content_h < 24.f) return;

	float row_h = 20.f;
	float child_w = w - 4.f;

	ImGui::SetCursorScreenPos(ImVec2(x + 2.f, content_y));
	ImGui::PushID("##cpu_stack");
	ImGui::BeginChild("##cpu_stack_child", ImVec2(child_w, content_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	if (buf.empty() || base != rsp) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const float fnt_size = aida::ui::fonts::size_or(fnt, 13.5f);
		const char* msg = "Reading stack frame...";
		ImVec2 sz = fnt->CalcTextSizeA(fnt_size, FLT_MAX, 0.f, msg);
		ImVec2 cp = ImGui::GetCursorScreenPos();
		dl->AddText(fnt, fnt_size,
			ImVec2(cp.x + (child_w - sz.x) * 0.5f, cp.y + 16.f),
			with_a(t.text_dim, alpha), msg);
		ImGui::EndChild();
		ImGui::PopID();
		return;
	}

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_font_size = aida::ui::fonts::size_or(code_font, 14.5f);

	size_t qword_count = buf.size() / 8;
	if (qword_count == 0) qword_count = 1;

	ImGuiListClipper clipper;
	clipper.Begin(static_cast<int>(qword_count), row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			uint64_t qaddr = rsp + static_cast<uint64_t>(i) * 8ULL;
			uint64_t qval = 0;
			size_t qoff = static_cast<size_t>(i) * 8u;
			if (qoff + 8 <= buf.size())
				std::memcpy(&qval, buf.data() + qoff, sizeof(uint64_t));
			const auto context_for_row = [&](int row) {
				const std::size_t offset = static_cast<std::size_t>(row) * 8U;
				std::uint64_t value = 0;
				if (offset + 8U <= buf.size())
					std::memcpy(&value, buf.data() + offset, sizeof(value));
				return debugger_interaction::capture(
					debugger_interaction::kind_t::stack_slot,
					rsp + static_cast<std::uint64_t>(row) * 8ULL, value, row);
			};
			const auto row_context = context_for_row(i);

			ImGui::SetCursorScreenPos(ImVec2(x + 4.f, ry));
			ImGui::PushID(i + 0xC0000);
			ImGui::InvisibleButton("##cpu_stack_row", ImVec2(child_w - 8.f, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("stack", "debugger-stack-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::stack_slot, qaddr, qval, i));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			bool is_top = (i == 0);
			bool is_sel = debugger_row_selected(row_context, ui.cpu_stack_selected == i);
			if (is_top) {
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + 4.f, ry + row_h),
					with_a(t.accent_u32, alpha));
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + child_w - 2.f, ry + row_h),
					with_a(t.accent_glow, alpha * 0.18f), 3.f);
			}
			if (is_sel && !is_top) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, true, false, i, 1.f, alpha);
			} else if (hov && !is_top) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, false, true, i, 1.f, alpha);
			}

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, qaddr);
			dl->AddText(code_font, code_font_size,
				ImVec2(x + 8.f, ry + (row_h - code_font_size) * 0.5f),
				with_a(is_top ? t.accent_hover : t.text_address, alpha), abuf);

			char vbuf[20];
			std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, qval);
			ImU32 vcol = cpu_view_detail::is_likely_pointer(qval) ? t.syn_function
				: (qval == 0 ? t.text_dim : t.syn_number);
			dl->AddText(code_font, code_font_size,
				ImVec2(x + 180.f, ry + (row_h - code_font_size) * 0.5f),
				with_a(vcol, alpha), vbuf);

			if (cpu_view_detail::is_likely_pointer(qval)) {
				ImFont* sf = aida::ui::fonts::caption();
				if (!sf) sf = ImGui::GetFont();
				const float sf_size = aida::ui::fonts::size_or(sf, 13.5f);
				const char* hint = "ptr";
				dl->AddText(sf, sf_size,
					ImVec2(x + 350.f, ry + (row_h - sf_size) * 0.5f),
					with_a(t.text_dim, alpha * 0.85f), hint);
			}

			if (clicked) {
				ui.cpu_stack_selected = i;
				select_debugger_row(row_context, static_cast<int>(qword_count),
					context_for_row, false);
			}
			if (dclicked && cpu_view_detail::is_likely_pointer(qval)) {
				diag::log_tagged_fmt("cpu_view",
					"stack_dclick_follow qaddr=0x%llx qval=0x%llx",
					static_cast<unsigned long long>(qaddr),
					static_cast<unsigned long long>(qval));
				jump_to_hex(qval, 256);
			}
			if (rclicked) {
				select_debugger_row(row_context, static_cast<int>(qword_count),
					context_for_row, true);
				diag::log_tagged_fmt("cpu_view",
					"stack_rclick qaddr=0x%llx qval=0x%llx",
					static_cast<unsigned long long>(qaddr),
					static_cast<unsigned long long>(qval));
			}
		}
	}
	clipper.End();

	if (std::abs(ImGui::GetScrollY() - ui.cpu_stack_scroll_y) > 0.5f) {
		ui.cpu_stack_scroll_y = ImGui::GetScrollY();
		diag::log_tagged_fmt("cpu_view",
			"stack_scroll y=%.1f",
			static_cast<double>(ui.cpu_stack_scroll_y));
	}

	ImGui::EndChild();
	ImGui::PopID();
}

enum class cpu_surface_t : std::uint8_t {
	integrated,
	registers,
	stack
};

static void render_cpu(ImDrawList* dl, float ox, float oy, float w, float h, float a,
	cpu_surface_t surface = cpu_surface_t::integrated) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] cpu enter ok=1");
			diag::log_tagged_critical_fmt("cpu_view",
				"cpu_pane_enter w=%.0f h=%.0f", static_cast<double>(w),
				static_cast<double>(h));
		}
	}

	uint32_t attached_pid = driver_bridge::attached_pid();
	if (attached_pid == 0) {
		aida::ui::no_target_overlay::render(ImVec2(ox + 4.f, oy + 4.f),
			ImVec2((std::max)(w - 8.f, 1.f), (std::max)(h - 8.f, 1.f)),
			"No debug target attached",
			surface == cpu_surface_t::stack
				? "Attach to a running process or launch a target to inspect the live stack."
				: "Attach to a running process or launch a target to inspect CPU registers and flags.",
			a, aida::ui::empty_state::glyph_t::shield, true,
			surface == cpu_surface_t::registers ? "no_target.debugger.registers" :
			surface == cpu_surface_t::stack ? "no_target.debugger.stack" :
			"no_target.debugger.cpu");
		return;
	}

	debugger_engine::request_refresh(120);
	auto regs = debugger_engine::cached_registers();
	if (surface == cpu_surface_t::stack) {
		render_cpu_stack_view(dl, ox + 4.f, oy + 4.f,
			(std::max)(w - 8.f, 1.f), (std::max)(h - 8.f, 1.f), regs.rsp, a);
		return;
	}

	cpu_view_detail::reg_row_t rows[] = {
		{"RAX", regs.rax, 0, true},
		{"RBX", regs.rbx, 0, true},
		{"RCX", regs.rcx, 0, true},
		{"RDX", regs.rdx, 0, true},
		{"RSI", regs.rsi, 0, true},
		{"RDI", regs.rdi, 0, true},
		{"RBP", regs.rbp, 0, true},
		{"RSP", regs.rsp, 0, true},
		{"R8",  regs.r8,  0, true},
		{"R9",  regs.r9,  0, true},
		{"R10", regs.r10, 0, true},
		{"R11", regs.r11, 0, true},
		{"R12", regs.r12, 0, true},
		{"R13", regs.r13, 0, true},
		{"R14", regs.r14, 0, true},
		{"R15", regs.r15, 0, true},
		{"RIP", regs.rip, 0, true},
		{"RFLAGS", regs.rflags, 0, true},
		{"CS", regs.cs, 1, false},
		{"SS", regs.ss, 1, false},
		{"DS", regs.ds, 1, false},
		{"ES", regs.es, 1, false},
		{"FS", regs.fs, 1, false},
		{"GS", regs.gs, 1, false},
		{"DR0", regs.dr0, 2, true},
		{"DR1", regs.dr1, 2, true},
		{"DR2", regs.dr2, 2, true},
		{"DR3", regs.dr3, 2, true},
		{"DR6", regs.dr6, 2, true},
		{"DR7", regs.dr7, 2, true},
	};
	int rows_n = static_cast<int>(sizeof(rows) / sizeof(rows[0]));

	if (!ui.cpu_prev_reg_initialized) {
		for (int i = 0; i < rows_n && i < 32; ++i)
			ui.cpu_prev_reg_values[i] = rows[i].value;
		ui.cpu_prev_reg_initialized = true;
		diag::log_tagged_fmt("cpu_view",
			"prev_reg_initialized rows=%d", rows_n);
	} else {
		for (int i = 0; i < rows_n && i < 32; ++i) {
			if (ui.cpu_prev_reg_values[i] != rows[i].value) {
				ui.cpu_reg_flash[i] = 1.f;
				ui.cpu_prev_reg_values[i] = rows[i].value;
				diag::log_tagged_fmt("cpu_view",
					"reg_change name=%s new=0x%llx",
					rows[i].name,
					static_cast<unsigned long long>(rows[i].value));
			}
			ui.cpu_reg_flash[i] *= std::exp(-3.0f * dt);
			if (ui.cpu_reg_flash[i] < 0.005f) ui.cpu_reg_flash[i] = 0.f;
		}
	}

	float pad = 10.f;
	const float kMinPanelW = 720.f;
	if (surface == cpu_surface_t::integrated && w < kMinPanelW) {
		static bool s_logged_cpu_narrow = false;
		if (!s_logged_cpu_narrow) {
			s_logged_cpu_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"debugger_view cpu_pane too_narrow w=%.0f min=%.0f overlay_shown=1",
				w, kMinPanelW);
		}
		float msg_y = oy + h * 0.5f - 24.f;
		float msg_w = std::min(w - 24.f, 520.f);
		float msg_x = ox + (w - msg_w) * 0.5f;
		ui_anim::render_inline_callout(dl, msg_x, msg_y, msg_w, 48.f,
			"Widen the debugger pane to view CPU registers, disassembly, and stack side-by-side.",
			ui_anim::callout_kind_t::info, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	float left_w = surface == cpu_surface_t::registers
		? (std::max)(w - 8.f, 1.f) : std::max(360.f, w * 0.40f);
	float right_w = w - left_w - pad * 3.f;
	if (surface == cpu_surface_t::integrated && right_w < 360.f) {
		right_w = std::max(360.f, w - left_w - pad * 2.f);
		if (right_w < 280.f) right_w = std::max(280.f, w - 200.f - pad * 2.f);
	}

	float left_x = surface == cpu_surface_t::registers ? ox + 4.f : ox + pad;
	float right_x = left_x + left_w + pad;
	float top_y = oy + 4.f;
	float bot_y = oy + h - 4.f;
	float total_h = bot_y - top_y;
	const bool show_flag_grid = surface == cpu_surface_t::integrated ||
		(total_h >= 340.f && left_w >= 300.f);
	float reg_h = show_flag_grid ? total_h * 0.62f : total_h;
	float flags_h = total_h - reg_h - pad;
	float disasm_h = total_h * 0.55f;
	float stack_h = total_h - disasm_h - pad;

	float reg_y0 = top_y;
	float reg_y1 = reg_y0 + reg_h;
	float flags_y0 = reg_y1 + pad;
	float flags_y1 = flags_y0 + flags_h;

	float disasm_y0 = top_y;
	float disasm_y1 = disasm_y0 + disasm_h;
	float stack_y0 = disasm_y1 + pad;

	draw_glass_card(dl, ImVec2(left_x, reg_y0),
		ImVec2(left_x + left_w, reg_y1), 10.f, a);
	{
		char hdr_buf[64];
		std::snprintf(hdr_buf, sizeof(hdr_buf), "REGISTERS  PID %u  TID %u",
			static_cast<unsigned>(attached_pid),
			static_cast<unsigned>(debugger_engine::g_state.active_tid));
		draw_panel_header(dl, left_x, reg_y0, left_w, hdr_buf, a);
	}

	float list_y = reg_y0 + HEADER_H + 2.f;
	float list_h = reg_y1 - 4.f - list_y;
	if (list_h < 80.f) list_h = 80.f;

	ImGui::SetCursorScreenPos(ImVec2(left_x + 2.f, list_y));
	ImGui::PushID("##cpu_reg_list");
	ImGui::BeginChild("##cpu_reg_list_child", ImVec2(left_w - 4.f, list_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	float row_h = 22.f;
	ImGuiListClipper clipper;
	clipper.Begin(rows_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = list_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			const auto& r = rows[static_cast<size_t>(i)];

			ImGui::SetCursorScreenPos(ImVec2(left_x + 4.f, ry));
			ImGui::PushID(i + 0xF0000);
			ImGui::InvisibleButton("##cpu_row", ImVec2(left_w - 8.f, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("register", "debugger-register-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::register_value, 0, r.value, i,
					0, 0, r.name));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			const auto context_for_row = [&](int row) {
				const auto& item = rows[static_cast<size_t>(row)];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::register_value, 0, item.value, row,
					0, 0, item.name);
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context, ui.cpu_panel.selected == i);
			float flash = (i < 32) ? ui.cpu_reg_flash[i] : 0.f;
			draw_cpu_reg_row(dl, left_x + 2.f, ry, left_w - 4.f, row_h,
				i, r, flash, sel, hov, a);

			if (clicked) {
				ui.cpu_panel.selected = i;
				select_debugger_row(row_context, rows_n, context_for_row, false);
				diag::log_tagged_fmt("cpu_view",
					"reg_click name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (dclicked && r.editable) {
				cpu_view_detail::open_edit_modal(i, r.value);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_dclick_edit name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (rclicked && r.editable) {
				select_debugger_row(row_context, rows_n, context_for_row, true);
				diag::log_tagged_fmt("cpu_view",
					"reg_rclick name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
		}
	}
	clipper.End();

	ui.cpu_reg_scroll_y = ImGui::GetScrollY();

	ImGui::EndChild();
	ImGui::PopID();

	if (show_flag_grid) {
	draw_glass_card(dl, ImVec2(left_x, flags_y0),
		ImVec2(left_x + left_w, flags_y1), 10.f, a);
	draw_panel_header(dl, left_x, flags_y0, left_w, "RFLAGS", a);

	struct flag_def_t {
		const char* short_name;
		const char* full_name;
		uint64_t    mask;
	};
	flag_def_t flag_defs[] = {
		{"CF", "Carry",      0x00000001ULL},
		{"PF", "Parity",     0x00000004ULL},
		{"AF", "Aux Carry",  0x00000010ULL},
		{"ZF", "Zero",       0x00000040ULL},
		{"SF", "Sign",       0x00000080ULL},
		{"OF", "Overflow",   0x00000800ULL},
		{"TF", "Trap",       0x00000100ULL},
		{"IF", "Interrupt",  0x00000200ULL},
		{"DF", "Direction",  0x00000400ULL},
		{"NT", "Nested",     0x00004000ULL},
		{"RF", "Resume",     0x00010000ULL},
		{"AC", "AlignCheck", 0x00040000ULL},
	};
	int flag_n = static_cast<int>(sizeof(flag_defs) / sizeof(flag_defs[0]));

	float fcols = 2.f;
	float frows = static_cast<float>((flag_n + 1) / 2);
	float fpad_inner = 8.f;
	float favail_w = left_w - fpad_inner * (fcols + 1.f);
	float fchip_w = favail_w / fcols;
	float favail_h = flags_y1 - (flags_y0 + HEADER_H + 6.f) - fpad_inner;
	float fchip_h = (favail_h - fpad_inner * (frows - 1.f)) / frows;
	if (fchip_h < 22.f) fchip_h = 22.f;
	if (fchip_h > 36.f) fchip_h = 36.f;

	for (int i = 0; i < flag_n; ++i) {
		int col = i % 2;
		int row = i / 2;
		bool set_bit = (regs.rflags & flag_defs[i].mask) != 0;
		float bx = left_x + fpad_inner + static_cast<float>(col) * (fchip_w + fpad_inner);
		float by = flags_y0 + HEADER_H + 6.f
		         + static_cast<float>(row) * (fchip_h + fpad_inner);

		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::PushID(i + 0xF1000);
		ImGui::InvisibleButton("##cpu_flag", ImVec2(fchip_w, fchip_h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		ImGui::PopID();

		ImU32 bg_col = set_bit ? aida::ui::mix(t.panel_header, t.success, 0.35f)
		                       : t.panel_header;
		if (hov) bg_col = aida::ui::mix(bg_col, t.hover_wash, 0.55f);
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + fchip_w, by + fchip_h),
			with_a(bg_col, a), 6.f);
		ImU32 border = set_bit ? aida::ui::mix(t.success, t.accent_u32, 0.25f)
		                       : t.border_subtle;
		dl->AddRect(ImVec2(bx, by), ImVec2(bx + fchip_w, by + fchip_h),
			with_a(border, a * (set_bit ? 0.95f : 0.65f)), 6.f, 0, 1.f);

		ImU32 led = set_bit ? t.success : t.text_dim;
		dl->AddCircleFilled(ImVec2(bx + 14.f, by + fchip_h * 0.5f), 5.f,
			with_a(led, a * 0.30f), 16);
		dl->AddCircleFilled(ImVec2(bx + 14.f, by + fchip_h * 0.5f), 3.f,
			with_a(led, a * (set_bit ? 1.f : 0.55f)), 16);

		ImFont* fnt = aida::ui::fonts::body_em();
		if (!fnt) fnt = ImGui::GetFont();
		const float fnt_size = aida::ui::fonts::size_or(fnt, 16.5f);
		dl->AddText(fnt, fnt_size,
			ImVec2(bx + 28.f, by + (fchip_h - fnt_size) * 0.5f),
			with_a(set_bit ? t.text_primary : t.text_secondary, a),
			flag_defs[i].short_name);

		ImFont* sf = aida::ui::fonts::caption();
		if (!sf) sf = ImGui::GetFont();
		const float sf_size = aida::ui::fonts::size_or(sf, 13.5f);
		float full_x = bx + 60.f;
		dl->AddText(sf, sf_size,
			ImVec2(full_x, by + (fchip_h - sf_size) * 0.5f),
			with_a(t.text_dim, a * 0.95f), flag_defs[i].full_name);

		ImFont* cf = aida::ui::fonts::code();
		if (!cf) cf = ImGui::GetFont();
		const float cf_size = aida::ui::fonts::size_or(cf, 14.5f);
		const char* bit_str = set_bit ? "1" : "0";
		ImVec2 bs = cf->CalcTextSizeA(cf_size, FLT_MAX, 0.f, bit_str);
		dl->AddText(cf, cf_size,
			ImVec2(bx + fchip_w - bs.x - 10.f, by + (fchip_h - bs.y) * 0.5f),
			with_a(set_bit ? t.success : t.text_dim, a), bit_str);

		if (clicked) {
			uint64_t new_rflags = regs.rflags ^ flag_defs[i].mask;
			ui.cpu_edit_reg_idx = 17;
			ui.cpu_edit_context = debugger_interaction::capture(
				debugger_interaction::kind_t::register_value, 0, regs.rflags, 17,
				0, 0, "RFLAGS", flag_defs[i].full_name);
			std::snprintf(ui.cpu_edit_value_buf, sizeof(ui.cpu_edit_value_buf),
				"%016" PRIX64, new_rflags);
			ui.cpu_edit_popup_open = true;
		}
	}
	}

	if (surface == cpu_surface_t::integrated) {
		render_cpu_disasm_slice(dl, right_x, disasm_y0, right_w, disasm_h, regs.rip, a);
		render_cpu_stack_view(dl, right_x, stack_y0, right_w, stack_h, regs.rsp, a);
	}

	if (ui.cpu_edit_popup_open) {
		ImGui::OpenPopup("Edit Register##cpu");
		ui.cpu_edit_popup_open = false;
		diag::log_tagged_fmt("cpu_view", "edit_modal_open idx=%d",
			ui.cpu_edit_reg_idx);
	}
	if (aida::ui::design::begin_dialog_exact("Edit Register##cpu",
		ImVec2(520.0f, 360.0f), ImVec2(360.0f, 260.0f))) {
		const bool valid_edit = ui.cpu_edit_reg_idx >= 0 && ui.cpu_edit_reg_idx < rows_n;
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			valid_edit ? "Apply" : "Close", valid_edit ? "Cancel" : nullptr);
		aida::ui::design::begin_dialog_body("debugger_register_edit_body", footer_height);
		if (valid_edit) {
			const auto& er = rows[static_cast<size_t>(ui.cpu_edit_reg_idx)];
			ImGui::Text("Register: %s", er.name);
			ImGui::Text("Current:  0x%016llX",
				static_cast<unsigned long long>(er.value));
			ImGui::Separator();
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::IsWindowAppearing() &&
				g_breakpoint_editor_focus == breakpoint_editor_focus_t::condition)
				ImGui::SetKeyboardFocusHere();
			const bool submitted = ImGui::InputText("##cpu_edit_val", ui.cpu_edit_value_buf,
				sizeof(ui.cpu_edit_value_buf),
				ImGuiInputTextFlags_CharsHexadecimal |
				ImGuiInputTextFlags_AutoSelectAll |
				ImGuiInputTextFlags_EnterReturnsTrue);
			const auto edit_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::edit_register, ui.cpu_edit_context);
			if (!edit_gate.enabled)
				ImGui::TextWrapped("Unavailable: %s", edit_gate.disabled_reason);
			aida::ui::design::end_dialog_body();
			const auto footer = aida::ui::design::dialog_footer(
				"debugger_register_edit_footer", "Apply", edit_gate.enabled,
				false, "Cancel");
			if (footer.confirmed || (submitted && edit_gate.enabled)) {
				uint64_t new_val = parse_hex_address(ui.cpu_edit_value_buf);
				std::string lname = cpu_view_detail::lowercase_reg_name(er.name);
				const auto edit_context = ui.cpu_edit_context;
				static_cast<void>(queue_debugger_mutation("Edit register",
					"debugger.register_edit", edit_context,
					[lname, new_val]() {
						mutation_result_t result;
						result.ok = debugger_engine::set_register(lname, new_val);
						result.verified = result.ok && resolve_register_token(lname,
							debugger_engine::get_registers()) == new_val;
						if (!result.verified)
							result.detail = result.ok ? "Register readback did not match."
								: "Edit register failed: " + debugger_engine::last_error();
						else
							debugger_engine::invalidate_cache();
						return result;
					}));
				ui.cpu_edit_reg_idx = -1;
				ImGui::CloseCurrentPopup();
			}
			if (footer.cancelled) {
				diag::log_tagged_fmt("cpu_view", "edit_modal_cancel");
				ui.cpu_edit_reg_idx = -1;
				ImGui::CloseCurrentPopup();
			}
		} else {
			ImGui::TextUnformatted("The selected register is no longer available.");
			aida::ui::design::end_dialog_body();
			const auto footer = aida::ui::design::dialog_footer(
				"debugger_register_edit_stale_footer", "Close", true, false, nullptr);
			if (footer.confirmed || footer.cancelled) {
				ui.cpu_edit_reg_idx = -1;
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}
}


static void render_cfg_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& ui = g_ui;
	(void)dl;
	(void)w;
	(void)a;

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] cfg enter ok=1");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_w = 140.f;
	float btn_gap = 6.f;

	uint64_t rip = debugger_engine::cached_registers().rip;
	bool can_build = rip != 0;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##cfg_overlay");
	bool build_clicked = aida::ui::button(
		can_build ? "Build CFG at RIP" : "Build CFG (no RIP)",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		!can_build);
	if (build_clicked && can_build) {
		cfg_view::build_cfg(rip);
		ui.cfg_last_built_addr = rip;
		diag::log_tagged_critical_fmt("cfg",
			"cfg_build_from_debugger rip=0x%llx",
			static_cast<unsigned long long>(rip));
		diag::log_tagged("dbg_audit",
			"[dbg_audit] cfg build_at_rip ok=1");
	}
	ImGui::SameLine(0.f, btn_gap);
	bool open_full = aida::ui::button("Open in Graph View",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(btn_w + 20.f, btn_h),
		!can_build && ui.cfg_last_built_addr == 0);
	if (open_full) {
		uint64_t target_addr = can_build ? rip : ui.cfg_last_built_addr;
		if (target_addr != 0) {
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.graph"));
			cfg_view::build_cfg(target_addr);
			ui.cfg_last_built_addr = target_addr;
			diag::log_tagged_critical_fmt("cfg",
				"cfg_open_graph_view target=0x%llx",
				static_cast<unsigned long long>(target_addr));
			diag::log_tagged("dbg_audit",
				"[dbg_audit] cfg open_full ok=1");
		} else {
			diag::log_tagged("dbg_audit",
				"[dbg_audit] cfg open_full fail reason=no_address");
		}
	}
	ImGui::PopID();
}

static void render_modules_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] modules enter ok=1");
		}
		static bool s_cap_logged_once = false;
		if (!s_cap_logged_once) {
			s_cap_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] modules capability_unavailable feature=modules_inject_dll reason=driver_bridge_has_no_LoadLibrary_helper");
			diag::log_tagged("dbg_audit",
				"[dbg_audit] modules capability_unavailable feature=modules_unload reason=driver_bridge_has_no_FreeLibrary_helper");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_w = 120.f;
	float btn_gap = 6.f;

	auto selected = module_view::selected_module_snapshot();
	bool attached = driver_bridge::attached_pid() != 0;
	bool selection_stale = (selected.base != 0 && !selected.present);
	bool can_dump = attached && selected.present && selected.size != 0;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##modules_overlay");
	bool dump_clicked = aida::ui::button("Dump Selected",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		!can_dump);
	if (dump_clicked) {
		auto dump_target = module_view::selected_module_snapshot();
		if (driver_bridge::attached_pid() == 0) {
			toast_notification::push("Attach to a target first.",
				toast_notification::toast_type_t::warning);
			diag::log_tagged("dbg_audit",
				"[dbg_audit] modules dump fail reason=no_attached_target");
		} else if (!dump_target.present || dump_target.base == 0 || dump_target.size == 0) {
			toast_notification::push(dump_target.base != 0
				? "Selected module is no longer loaded."
				: "Select a module first.",
				toast_notification::toast_type_t::warning);
			diag::log_tagged("dbg_audit",
				dump_target.base != 0
					? "[dbg_audit] modules dump fail reason=selected_module_unloaded"
					: "[dbg_audit] modules dump fail reason=no_selection");
		} else {
			const uint64_t cap = 256ULL * 1024ULL * 1024ULL;
			if (dump_target.size > cap) {
				toast_notification::push("Module exceeds 256 MiB dump cap.",
					toast_notification::toast_type_t::warning);
				diag::log_tagged("dbg_audit",
					"[dbg_audit] modules dump fail reason=cap_exceeded");
			} else {
				char default_name[160] = {};
				std::snprintf(default_name, sizeof(default_name),
					"%s_%016llX.bin",
					dump_target.name.empty() ? "module" : dump_target.name.c_str(),
					static_cast<unsigned long long>(dump_target.base));
				char path_buf[MAX_PATH] = {};
				std::strncpy(path_buf, default_name, sizeof(path_buf) - 1);
				static const char k_module_filter[] =
					"Binary (*.bin)\0*.bin\0DLL (*.dll)\0*.dll\0EXE (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
						"Dump Module",
						k_module_filter,
						"bin",
						path_buf, sizeof(path_buf),
						"debugger_view::modules_dump")) {
					uint64_t base_copy = dump_target.base;
					uint64_t size_copy = dump_target.size;
					std::string path_copy = path_buf;
					std::string name_copy = dump_target.name;
					const std::uint32_t target_pid = driver_bridge::attached_pid();
					const std::uint64_t target_generation =
						debugger_interaction::current_stop_generation();
					auto result = std::make_shared<mutation_result_t>();
					aida::infra::executor::submission_t sub;
					sub.owner_subsystem = "debugger";
					sub.label = "Dump selected module";
					sub.thread_class = "debugger_dump";
					sub.domain = aida::infra::executor::domain_t::feature_worker;
					sub.priority = 2;
					sub.target_pid = target_pid;
					sub.generation = target_generation;
					sub.ui_access_policy = "post_completion_only";
					sub.failure_policy = "fail_closed";
					sub.body = [base_copy, size_copy, path_copy, name_copy,
						target_pid, target_generation, result]() {
						std::vector<uint8_t> buf;
						if (driver_bridge::attached_pid() != target_pid ||
							debugger_interaction::current_stop_generation() != target_generation)
							result->detail = "The target changed before the module dump started.";
						else {
							result->ok = driver_bridge::read_memory_for(target_pid, base_copy,
								static_cast<size_t>(size_copy), buf) && buf.size() == size_copy;
							if (!result->ok)
								result->detail = "Module dump read failed or returned a partial result.";
							else
								result->verified = write_file_atomic_exact(path_copy, buf.data(),
									buf.size(), result->detail);
						}
						diag::log_tagged_critical_fmt("modules",
							"modules_dump name='%s' base=0x%llx size=%llu read=%d write=%d path='%s'",
							name_copy.c_str(),
							static_cast<unsigned long long>(base_copy),
							static_cast<unsigned long long>(size_copy),
							result->ok ? 1 : 0,
							result->verified ? 1 : 0,
							path_copy.c_str());
						diag::log_tagged("dbg_audit", result->verified
							? "[dbg_audit] modules dump ok=1"
							: "[dbg_audit] modules dump fail reason=read_or_write_failed");
						const bool posted = post_debugger_ui([result, count = buf.size(), name_copy]() {
							const std::string message = result->verified
								? "Dumped " + std::to_string(count) + " bytes from " + name_copy
								: result->detail.empty() ? "Module dump failed." : result->detail;
							toast_notification::push(message, result->verified
								? toast_notification::toast_type_t::success
								: toast_notification::toast_type_t::error);
						}, "module_dump_completion");
						if (!posted)
							throw std::runtime_error("Module-dump completion could not be published to the UI thread");
						if (!result->verified)
							throw std::runtime_error(result->detail.empty()
								? "Module dump failed" : result->detail);
					};
					const auto submitted = submit_owned_debugger_task(std::move(sub),
						"view.debug.modules", "debugger.module_dump", "Dump selected module", false);
					if (!submitted.submitted) {
						diag::log_tagged_critical_fmt("modules",
							"modules_dump_post_failed name='%s' base=0x%llx size=%llu path='%s'",
							name_copy.c_str(),
							static_cast<unsigned long long>(base_copy),
							static_cast<unsigned long long>(size_copy),
							path_copy.c_str());
						toast_notification::push("Module dump queue rejected the task.",
							toast_notification::toast_type_t::error);
					}
				}
			}
		}
	}
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::pill_kind(
		selected.present ? "Module selected" : (selection_stale ? "Selection unloaded" : "No module selected"),
		selected.present ? aida::ui::pill_kind_t::success :
			(selection_stale ? aida::ui::pill_kind_t::warning : aida::ui::pill_kind_t::neutral),
		aida::ui::size_t_::sm, false);
	if (ImGui::IsItemHovered() && selected.base != 0) {
		char tip[256];
		std::snprintf(tip, sizeof(tip), "%s base=0x%016llX",
			selected.name.empty() ? "Selected module" : selected.name.c_str(),
			static_cast<unsigned long long>(selected.base));
		ImGui::SetTooltip("%s", tip);
	}
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::pill_kind("Inject unavailable", aida::ui::pill_kind_t::warning,
		aida::ui::size_t_::sm, false);
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("Remote LoadLibrary is not exposed by driver_bridge in this build.");
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::pill_kind("Unload unavailable", aida::ui::pill_kind_t::warning,
		aida::ui::size_t_::sm, false);
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("Remote FreeLibrary is not exposed by driver_bridge in this build.");
	ImGui::PopID();

	float cb_y = oy + overlay_h + 2.f;
	float cb_h = 20.f;
	float cb_w = w - 24.f;
	const char* callout_text = selection_stale
		? "Selected module is no longer loaded. Refresh modules or choose another row."
		: "Dump uses kernel read_memory. Injection and unload require unavailable remote module helpers.";
	ui_anim::render_inline_callout(dl, ox + 12.f, cb_y, cb_w, cb_h,
		callout_text,
		ui_anim::callout_kind_t::info,
		t.accent.x, t.accent.y, t.accent.z, a);
}

static void render_seh_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] seh enter ok=1");
		}
		static bool s_cap_logged_once = false;
		if (!s_cap_logged_once) {
			s_cap_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] seh capability_unavailable feature=seh_break_on_exception reason=driver_bridge_has_no_debug_event_subscription");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_gap = 6.f;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##seh_overlay");
	aida::ui::pill_kind("SEH per active thread", aida::ui::pill_kind_t::info,
		aida::ui::size_t_::sm, false);
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("Refresh reads the chain for the active debugger thread.");
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::pill_kind("Debug-event break unavailable", aida::ui::pill_kind_t::warning,
		aida::ui::size_t_::sm, false);
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("driver_bridge does not expose a debug-event subscription in this build.");
	ImGui::PopID();

	float cb_y = oy + overlay_h + 2.f;
	float cb_h = 20.f;
	float cb_w = w - 24.f;
	ui_anim::render_inline_callout(dl, ox + 12.f, cb_y, cb_w, cb_h,
		"No debug-event channel is exposed. Use a hardware execute breakpoint on a handler address.",
		ui_anim::callout_kind_t::warn,
		t.accent.x, t.accent.y, t.accent.z, a);
}


static float render_breakpoint_actions(float ox, float oy, float w) {
	auto& ui = g_ui;
	const auto metrics = aida::ui::design::metrics();
	const float pad = (std::max)(6.f, metrics.spacing_sm);
	const float gap = (std::max)(4.f, metrics.spacing_xs);
	const float control_height = (std::max)(28.f, metrics.control_height);
	const bool stacked = w < aida::ui::scale_px(680.f, metrics.scale);
	const float bar_h = stacked
		? pad + control_height + gap + control_height + pad
		: (std::max)(40.f, control_height + pad * 2.f);
	const float input_w = stacked
		? (std::max)(1.f, w - pad * 2.f)
		: (std::clamp)(w * 0.42f, aida::ui::scale_px(170.f, metrics.scale),
			(std::max)(aida::ui::scale_px(170.f, metrics.scale),
				w - aida::ui::scale_px(290.f, metrics.scale)));
	const float actions_x = stacked ? ox + pad : ox + pad + input_w + gap;
	const float actions_y = stacked ? oy + pad + control_height + gap : oy + pad;
	const float actions_w = stacked
		? (std::max)(1.f, w - pad * 2.f)
		: (std::max)(1.f, w - (actions_x - ox) - pad);

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + pad));
	ImGui::PushID("##bp_actions");

	ImGui::SetNextItemWidth(input_w);
	aida::ui::input_text("##bp_addr", ui.add_bp_addr_buf, sizeof(ui.add_bp_addr_buf),
		"0x... breakpoint address",
		false, ImVec2(input_w, control_height));
	auto clear_staged_definition = [&ui](bool clear_address) {
		ui.add_bp_staged = false;
		ui.add_bp_staged_mode = breakpoint_definition_mode_t::software;
		ui.add_bp_staged_context = {};
		if (clear_address) ui.add_bp_addr_buf[0] = '\0';
	};
	if (ui.add_bp_staged &&
		!debugger_interaction::is_current(ui.add_bp_staged_context)) {
		clear_staged_definition(true);
		toast_notification::push(
			"The reviewed breakpoint target or debugger stop changed; stage the address again.",
			toast_notification::toast_type_t::warning);
	}
	const bool software_enabled = !ui.add_bp_staged ||
		ui.add_bp_staged_mode == breakpoint_definition_mode_t::software;
	const bool hardware_enabled = !ui.add_bp_staged ||
		ui.add_bp_staged_mode == breakpoint_definition_mode_t::hardware_execute;
	const char* software_tooltip = software_enabled
		? "Add a software breakpoint at the entered hexadecimal address"
		: "The retained reviewed handoff requires a hardware execute breakpoint";
	const char* hardware_tooltip = hardware_enabled
		? "Add a hardware execute breakpoint at the entered hexadecimal address"
		: "The retained reviewed handoff requires a software breakpoint";

	const aida::ui::design::action_t actions[] = {
		{"debugger.breakpoint_add_software", "Add Software Breakpoint", "Add SW",
			software_tooltip, nullptr, nullptr,
			aida::ui::button_kind_t::primary, software_enabled, true, true},
		{"debugger.breakpoint_add_hardware", "Add Hardware Execute Breakpoint", "Add HW",
			hardware_tooltip, nullptr, nullptr,
			aida::ui::button_kind_t::secondary, hardware_enabled, false, true},
		{"debugger.breakpoint_clear_all", "Clear All Breakpoints", "Clear",
			"Review removal of every breakpoint definition", nullptr,
			"Removes every breakpoint definition after reviewed execution.",
			aida::ui::button_kind_t::destructive, true, false, true}
	};
	ImGui::SetCursorScreenPos(ImVec2(actions_x, actions_y));
	const auto action = aida::ui::design::render_toolbar(
		"debugger.breakpoints.actions", actions, std::size(actions), actions_w);
	const std::string_view invoked = action.invoked && action.id
		? std::string_view(action.id) : std::string_view();
	auto retained_context = [&ui](breakpoint_definition_mode_t mode,
		std::uint64_t address, std::string& error)
		-> std::optional<debugger_interaction::context_t> {
		if (!ui.add_bp_staged)
			return debugger_interaction::capture(
				debugger_interaction::kind_t::breakpoint, address);
		if (ui.add_bp_staged_mode != mode) {
			error = "The staged breakpoint mode changed; stage the definition again.";
			return std::nullopt;
		}
		if (ui.add_bp_staged_context.address != address) {
			error = "The staged breakpoint address was edited; stage the definition again.";
			return std::nullopt;
		}
		if (!debugger_interaction::is_current(ui.add_bp_staged_context)) {
			error = "The staged breakpoint target or debugger stop changed; stage the definition again.";
			return std::nullopt;
		}
		return ui.add_bp_staged_context;
	};
	if (invoked == "debugger.breakpoint_add_software") {
		uint64_t addr = parse_hex_address(ui.add_bp_addr_buf);
		diag::log_tagged_critical_fmt("bp",
			"bp_add_sw_request raw='%s' parsed_addr=0x%llx",
			ui.add_bp_addr_buf,
			static_cast<unsigned long long>(addr));
		if (addr != 0) {
			std::string error;
			const auto context = retained_context(
				breakpoint_definition_mode_t::software, addr, error);
			if (!context) {
				clear_staged_definition(true);
				toast_notification::push(error, toast_notification::toast_type_t::warning);
			} else if (queue_debugger_mutation("Add software breakpoint",
				"debugger.breakpoint_add_software", *context, [addr]() {
					mutation_result_t result;
					result.ok = result.verified = debugger_engine::add_breakpoint(addr,
						debugger_engine::bp_type_t::software, "", "", 1) >= 0;
					if (!result.ok) result.detail = "Add software breakpoint failed: " +
						debugger_engine::last_error();
					return result;
				}))
				clear_staged_definition(true);
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	if (invoked == "debugger.breakpoint_add_hardware") {
		uint64_t addr = parse_hex_address(ui.add_bp_addr_buf);
		diag::log_tagged_critical_fmt("bp",
			"bp_add_hw_request raw='%s' parsed_addr=0x%llx",
			ui.add_bp_addr_buf,
			static_cast<unsigned long long>(addr));
		if (addr != 0) {
			std::string error;
			const auto context = retained_context(
				breakpoint_definition_mode_t::hardware_execute, addr, error);
			if (!context) {
				clear_staged_definition(true);
				toast_notification::push(error, toast_notification::toast_type_t::warning);
			} else if (queue_debugger_mutation("Add hardware execute breakpoint",
				"debugger.breakpoint_add_hardware", *context, [addr]() {
					mutation_result_t result;
					result.ok = result.verified = debugger_engine::add_breakpoint(addr,
						debugger_engine::bp_type_t::hardware_execute, "", "", 1) >= 0;
					if (!result.ok) result.detail = "Add hardware breakpoint failed: " +
						debugger_engine::last_error();
					return result;
				}))
				clear_staged_definition(true);
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	if (invoked == "debugger.breakpoint_clear_all") {
		const auto context = debugger_interaction::capture(
			debugger_interaction::kind_t::breakpoint);
		static_cast<void>(queue_debugger_mutation("Clear all breakpoints",
			"debugger.breakpoint_clear_all", context, []() {
				mutation_result_t result;
				const bool cleared = debugger_engine::clear_all_breakpoints();
				result.ok = result.verified = cleared &&
					debugger_engine::snapshot_breakpoints().empty();
				if (!result.ok)
					result.detail = "Clear all breakpoints did not verify: " +
						debugger_engine::last_error();
				return result;
			}));
	}

	ImGui::PopID();
	return bar_h;
}

static void render_breakpoints(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] breakpoints enter ok=1");
		}
	}

	const float bar_h = render_breakpoint_actions(ox, oy, w);
	const bool compact_rows = w < 760.f;
	const float breakpoint_row_height = compact_rows
		? (std::max)(40.f, ROW_HEIGHT + 14.f) : ROW_HEIGHT;

	float table_y = oy + bar_h;
	if (compact_rows) {
		ui_anim::table_col_t cols[] = {
			{"Breakpoint", (std::max)(1.f, w - 70.f)}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 2, a);
	} else {
		const float breakpoint_name_width = (std::max)(60.f, w - 700.f);
		ui_anim::table_col_t cols[] = {
			{"#", 32.f}, {"State", 90.f}, {"Address", 170.f},
			{"Type", 120.f}, {"Hits", 70.f}, {"Name", breakpoint_name_width},
			{"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 7, a);
	}

	static render_snapshot_cache_t<debugger_engine::breakpoint_t> snapshot_cache;
	const auto& snapshot = refresh_render_snapshot(snapshot_cache, st.bp_mutex, st.breakpoints,
		st.breakpoints_generation, "breakpoints");
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = (std::max)(1.f, h - bar_h - HEADER_H);

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##bp_list");
	ImGui::BeginChild("##bp_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, 16.5f);
	const float code_font_size = aida::ui::fonts::size_or(code_font, 14.5f);

	ImGuiListClipper clipper;
	clipper.Begin(total_n, breakpoint_row_height);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			auto& bp = snapshot[static_cast<size_t>(i)];
			ImGui::SetCursorScreenPos(ImVec2(ox,
				content_y + static_cast<float>(i) * breakpoint_row_height
				- ImGui::GetScrollY()));
			ImVec2 row_min = ImGui::GetCursorScreenPos();
			ImGui::PushID(i);
			ImGui::InvisibleButton("##br", ImVec2((std::max)(1.f,
				w - (compact_rows ? 68.f : 238.f)), breakpoint_row_height));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("breakpoint", "debugger-breakpoint-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::breakpoint, bp.address,
					breakpoint_fingerprint(bp), i, 0,
					static_cast<std::uint64_t>(bp.size), bp.name, bp.condition));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();

			float ry = row_min.y;
			const auto breakpoint_context = debugger_interaction::capture(
				debugger_interaction::kind_t::breakpoint, bp.address,
				breakpoint_fingerprint(bp), i, 0,
				static_cast<uint64_t>(bp.size), bp.name, bp.condition);
			const auto context_for_row = [&](int row) {
				const auto& item = snapshot[static_cast<size_t>(row)];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::breakpoint, item.address,
					breakpoint_fingerprint(item), row, 0,
					static_cast<uint64_t>(item.size), item.name, item.condition);
			};
			bool sel = debugger_row_selected(breakpoint_context,
				ui.bp_panel.selected == i);
			const auto breakpoint_edit_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::edit_breakpoint, breakpoint_context);
			const auto breakpoint_toggle_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::toggle_breakpoint, breakpoint_context);
			const auto breakpoint_remove_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::remove_breakpoint, breakpoint_context);

			draw_row_bg(dl, ox, ry, w, breakpoint_row_height, sel, hov, i, 1.f, a);

			bool compact_more_clicked = false;
			if (compact_rows) {
				char address_label[192];
				if (bp.persistent_definition && !bp.definition_module.empty())
					std::snprintf(address_label, sizeof(address_label), "%s+0x%" PRIX64,
						bp.definition_module.c_str(), bp.definition_module_offset);
				else
					std::snprintf(address_label, sizeof(address_label), "%016" PRIX64,
						bp.address);
				const bool enabled = bp.state == debugger_engine::bp_state_t::enabled;
				const bool unresolved = bp.persistent_definition && !bp.definition_resolved;
				const bool install_error = bp.install_state ==
					debugger_engine::breakpoint_install_state_t::error;
				const bool install_pending = bp.install_state ==
					debugger_engine::breakpoint_install_state_t::requested ||
					bp.install_state == debugger_engine::breakpoint_install_state_t::installing ||
					bp.install_state == debugger_engine::breakpoint_install_state_t::removing;
				const char* state_label = install_error ? "ERROR" :
					(install_pending ? "PENDING" : (unresolved ? "STALE" : (enabled ? "ON" : "OFF")));
				static const char* compact_type_names[] = {
					"SW", "HW EXEC", "HW WRITE", "HW READ", "MEM"
				};
				int type_index = static_cast<int>(bp.type);
				if (type_index < 0 || type_index >= 5)
					type_index = 0;
				const ImU32 state_color = install_error ? t.error :
					(install_pending ? t.warning : (unresolved ? t.warning :
					(enabled ? t.success : t.text_secondary)));
				const float action_pad = (std::min)(8.f, (std::max)(0.f, w * 0.08f));
				const float action_width = (std::max)(1.f,
					(std::min)(54.f, w - action_pad * 2.f));
				const float action_x = ox + (std::max)(0.f,
					w - action_pad - action_width);
				dl->PushClipRect(ImVec2(ox, ry),
					ImVec2((std::max)(ox + 1.f, action_x - 4.f),
						ry + breakpoint_row_height), true);
				dl->AddCircleFilled(ImVec2(ox + 14.f, ry + 11.f), 3.f,
					with_a(state_color, a), 12);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 26.f, ry + 3.f),
					with_a(t.text_address, a), address_label);
				std::string detail_line = state_label;
				detail_line.append("  ").append(compact_type_names[type_index]);
				detail_line.append("  Hits ").append(std::to_string(bp.hit_count));
				if (!bp.name.empty())
					detail_line.append("  ").append(bp.name);
				else if (unresolved && !bp.definition_status.empty())
					detail_line.append("  ").append(bp.definition_status);
				dl->AddText(body_font, body_font_size, ImVec2(ox + 26.f, ry + 21.f),
					with_a(unresolved ? t.warning : t.text_secondary, a),
					detail_line.c_str());
				dl->PopClipRect();
				ImGui::SetCursorScreenPos(ImVec2(action_x,
					ry + (breakpoint_row_height - 22.f) * 0.5f));
				ImGui::PushID(i + 0xC3000);
				compact_more_clicked = aida::ui::button(
					action_width < 42.f ? "..." : "More",
					aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
					ImVec2(action_width, 22.f));
				ImGui::PopID();
				if (ImGui::IsItemHovered())
					ImGui::SetTooltip("Open breakpoint actions");
				if (hov && (bp.persistent_definition || !bp.install_detail.empty())) {
					ImGui::BeginTooltip();
					if (bp.persistent_definition) {
						ImGui::Text("Persistent definition: %s+0x%" PRIX64,
							bp.definition_module.c_str(), bp.definition_module_offset);
						ImGui::TextWrapped("%s", bp.definition_status.empty()
							? "Module-relative definition" : bp.definition_status.c_str());
					}
					if (!bp.install_detail.empty())
						ImGui::TextWrapped("%s%s", bp.install_detail.c_str(),
							bp.readback_verified ? " (verified)" : "");
					ImGui::EndTooltip();
				}
			} else {
			char ibuf[8];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			dl->AddText(body_font, body_font_size, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_dim, a), ibuf);

			bool enabled = (bp.state == debugger_engine::bp_state_t::enabled);
			const bool unresolved = bp.persistent_definition && !bp.definition_resolved;
			const bool install_error = bp.install_state ==
				debugger_engine::breakpoint_install_state_t::error;
			const bool install_pending = bp.install_state ==
				debugger_engine::breakpoint_install_state_t::requested ||
				bp.install_state == debugger_engine::breakpoint_install_state_t::installing ||
				bp.install_state == debugger_engine::breakpoint_install_state_t::removing;
			ImU32 dot_col = install_error ? t.error :
				(install_pending ? t.warning : (unresolved ? t.warning : (enabled ? t.success : t.error)));
			float dot_pulse = enabled ? aida::ui::clock::pulse(1.4f, 0.55f, 1.f) : 0.55f;
			dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 5.f,
			                    with_a(dot_col, a * 0.20f), 16);
			dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 3.f,
			                    with_a(dot_col, a * dot_pulse), 16);

			const char* state_str = install_error ? "ERROR" :
				(install_pending ? "PENDING" : (unresolved ? "STALE" : (enabled ? "ON" : "OFF")));
			ImU32 pcol = install_error ? t.error :
				(install_pending ? t.warning : (unresolved ? t.warning : (enabled ? t.info : t.text_secondary)));
			ImVec2 sts = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, state_str);
			float pw = sts.x + 14.f;
			float ph = 16.f;
			float pyy = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 50.f, pyy),
			                  ImVec2(ox + 50.f + pw, pyy + ph),
			                  with_a(pcol, a * 0.25f), ph * 0.5f);
			dl->AddRect(ImVec2(ox + 50.f, pyy),
			            ImVec2(ox + 50.f + pw, pyy + ph),
			            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
			dl->AddText(body_font, body_font_size,
				ImVec2(ox + 57.f, pyy + (ph - 11.f) * 0.5f),
				with_a(pcol, a), state_str);

			char abuf[192];
			if (bp.persistent_definition && !bp.definition_module.empty())
				std::snprintf(abuf, sizeof(abuf), "%s+0x%" PRIX64,
					bp.definition_module.c_str(), bp.definition_module_offset);
			else
				std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, bp.address);
			const ImVec4 address_clip(ox + 126.f, ry, ox + 296.f, ry + ROW_HEIGHT);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 130.f, ry + 5.f),
			            with_a(t.text_address, a), abuf, nullptr, 0.f, &address_clip);

			static const char* type_names[] = {"SW", "HW_EXEC", "HW_WRITE", "HW_READ", "MEM"};
			int ti = static_cast<int>(bp.type);
			if (ti < 0 || ti >= 5) ti = 0;
			ImU32 type_col = t.accent_u32;
			switch (ti) {
				case 0: type_col = t.text_secondary; break;
				case 1: type_col = t.accent_u32;     break;
				case 2: type_col = t.warning;        break;
				case 3: type_col = t.info;           break;
				case 4: type_col = t.success;        break;
			}
			const char* lbl = type_names[ti];
			ImVec2 tssz = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, lbl);
			float bw = tssz.x + 12.f;
			float bh = 16.f;
			float bx = ox + 300.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * 0.85f), 4.f);
			dl->AddText(body_font, body_font_size,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				with_a(IM_COL32(255, 255, 255, 245), a), lbl);

			char hits_buf[16];
			std::snprintf(hits_buf, sizeof(hits_buf), "%d", bp.hit_count);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 420.f, ry + 5.f),
			            with_a(t.text_secondary, a), hits_buf);

			const float name_right = (std::max)(ox + 491.f, ox + w - 222.f);
			dl->PushClipRect(ImVec2(ox + 486.f, ry),
				ImVec2(name_right, ry + ROW_HEIGHT), true);
			if (!bp.name.empty())
				dl->AddText(body_font, body_font_size, ImVec2(ox + 490.f, ry + 5.f),
				            with_a(t.text_primary, a), bp.name.c_str());
			else if (unresolved)
				dl->AddText(body_font, body_font_size, ImVec2(ox + 490.f, ry + 5.f),
					with_a(t.warning, a), bp.definition_status.c_str());
			dl->PopClipRect();
			if (hov && bp.persistent_definition) {
				ImGui::BeginTooltip();
				ImGui::Text("Persistent definition: %s+0x%" PRIX64,
					bp.definition_module.c_str(), bp.definition_module_offset);
				ImGui::TextWrapped("%s", bp.definition_status.empty()
					? "Module-relative definition" : bp.definition_status.c_str());
				ImGui::EndTooltip();
			}

			float bp_act_btn_h = 18.f;
			float bp_act_btn_y = ry + (ROW_HEIGHT - bp_act_btn_h) * 0.5f;
			float bp_act_btn_w = 56.f;
			float bp_act_btn_gap = 4.f;
			float bp_act_x = ox + w - 218.f;

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x, bp_act_btn_y));
			ImGui::PushID(i + 0xC0000);
			bool bp_goto_clicked = aida::ui::button("Jump",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h));
			ImGui::PopID();
			if (bp_goto_clicked) {
				bool ok = jump_to_disasm(bp.address);
				diag::log_tagged_fmt("bp",
					"bp_jump idx=%d addr=0x%llx ok=%d",
					i,
					static_cast<unsigned long long>(bp.address),
					ok ? 1 : 0);
				diag::log_tagged("dbg_audit", ok
					? "[dbg_audit] bp jump ok=1"
					: "[dbg_audit] bp jump fail reason=zero_addr");
			}

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x + (bp_act_btn_w + bp_act_btn_gap),
				bp_act_btn_y));
			ImGui::PushID(i + 0xC1000);
			bool bp_edit_clicked = aida::ui::button("Edit",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h),
				!breakpoint_edit_gate.enabled);
			ImGui::PopID();
			if (bp_edit_clicked) {
				if (retain_breakpoint_edit(ui, i, bp, breakpoint_context,
					breakpoint_editor_focus_t::condition))
					diag::log_tagged("dbg_audit",
						"[dbg_audit] bp edit_open ok=1");
			}

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x + (bp_act_btn_w + bp_act_btn_gap) * 2.f,
				bp_act_btn_y));
			ImGui::PushID(i + 0xC2000);
			bool bp_del_clicked = aida::ui::button("Del",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h),
				!breakpoint_remove_gate.enabled);
			ImGui::PopID();
			if (bp_del_clicked) {
				static_cast<void>(queue_debugger_mutation("Delete breakpoint",
					"debugger.breakpoint_delete", breakpoint_context,
					[i]() {
						mutation_result_t result;
						result.ok = result.verified = debugger_engine::remove_breakpoint(i);
						if (!result.ok) result.detail = "Delete breakpoint failed: " +
							debugger_engine::last_error();
						return result;
					}));
				if (ui.bp_panel.selected == i)
					ui.bp_panel.selected = -1;
			}
			}
			if (compact_more_clicked) {
				ui.bp_panel.selected = i;
				select_debugger_row(breakpoint_context, total_n, context_for_row, false);
				open_debugger_entity_actions(breakpoint_context,
					aida::ui::context_menu_open_origin_t::pointer);
			}

			if (clicked) {
				ui.bp_panel.selected = i;
				select_debugger_row(breakpoint_context, total_n, context_for_row, false);
			}
			if (dclicked && breakpoint_toggle_gate.enabled) {
				static_cast<void>(queue_debugger_mutation("Toggle breakpoint state",
					"debugger.breakpoint_toggle", breakpoint_context, [i]() {
						mutation_result_t result;
						result.ok = result.verified = debugger_engine::toggle_breakpoint(i);
						if (!result.ok) result.detail = "Toggle breakpoint failed: " +
							debugger_engine::last_error();
						return result;
					}));
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(breakpoint_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::shield;
		es.title = "No breakpoints set";
		es.body  = "Type an address above and click Add to set a software breakpoint.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.bp_edit_popup_open) {
		ImGui::OpenPopup("Edit Breakpoint##bp");
		ui.bp_edit_popup_open = false;
	}
	if (aida::ui::design::begin_dialog_exact("Edit Breakpoint##bp",
		ImVec2(620.0f, 460.0f), ImVec2(400.0f, 300.0f))) {
		const bool valid_edit = ui.bp_edit_identity_retained && ui.bp_edit_idx >= 0;
		std::string edit_unavailable_reason;
		const bool edit_is_current = valid_edit &&
			breakpoint_edit_is_current(ui, edit_unavailable_reason);
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			valid_edit ? "Apply" : "Close", valid_edit ? "Cancel" : nullptr);
		aida::ui::design::begin_dialog_body("debugger_breakpoint_edit_body", footer_height);
		if (valid_edit) {
			ImGui::Text("Address: 0x%016llX",
				static_cast<unsigned long long>(ui.bp_edit_address));
			ImGui::Text("Type:    %s",
				ui.bp_edit_type == static_cast<int>(debugger_engine::bp_type_t::software) ? "Software"
					: ui.bp_edit_type == static_cast<int>(debugger_engine::bp_type_t::hardware_execute) ? "HW Exec"
					: ui.bp_edit_type == static_cast<int>(debugger_engine::bp_type_t::hardware_write)   ? "HW Write"
					: ui.bp_edit_type == static_cast<int>(debugger_engine::bp_type_t::hardware_read)    ? "HW Read"
					: "Memory");
			if (!edit_is_current)
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::resolved().error),
					"%s", edit_unavailable_reason.c_str());
			ImGui::Separator();
			ImGui::Text("Condition (evaluated when hit, 0 = skip):");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
			ImGui::InputText("##bp_cond_edit", ui.bp_edit_condition_buf,
				sizeof(ui.bp_edit_condition_buf));
			ImGui::Text("Log message (use {RAX}, {[RSP+8]} placeholders):");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::IsWindowAppearing() &&
				g_breakpoint_editor_focus == breakpoint_editor_focus_t::log_message)
				ImGui::SetKeyboardFocusHere();
			ImGui::InputText("##bp_log_edit", ui.bp_edit_log_buf,
				sizeof(ui.bp_edit_log_buf));
			if (ImGui::IsWindowAppearing() &&
				g_breakpoint_editor_focus == breakpoint_editor_focus_t::auto_continue)
				ImGui::SetKeyboardFocusHere();
			ImGui::Checkbox("Auto-continue after log", &ui.bp_edit_auto_continue);
			aida::ui::design::end_dialog_body();
			const auto footer = aida::ui::design::dialog_footer(
				"debugger_breakpoint_edit_footer", "Apply", edit_is_current, false, "Cancel");
			const bool submitted = ImGui::GetIO().KeyCtrl &&
				(ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
				 ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false));
			if (footer.confirmed || (submitted && edit_is_current)) {
				std::string final_reason;
				if (!breakpoint_edit_is_current(ui, final_reason)) {
					toast_notification::push(final_reason, toast_notification::toast_type_t::warning);
				} else {
				const int edit_index = ui.bp_edit_idx;
				const std::string condition(ui.bp_edit_condition_buf);
				const std::string log_text(ui.bp_edit_log_buf);
				const bool auto_continue = ui.bp_edit_auto_continue;
				const auto context = ui.bp_edit_context;
				const auto expected_generation = ui.bp_edit_breakpoints_generation;
				const auto expected_fingerprint = ui.bp_edit_fingerprint;
				const auto expected_address = ui.bp_edit_address;
				const auto expected_size = ui.bp_edit_size;
				const auto expected_type = ui.bp_edit_type;
				const auto expected_name = ui.bp_edit_name;
				const auto expected_condition = ui.bp_edit_original_condition;
				const auto expected_log = ui.bp_edit_original_log;
				const auto expected_auto_continue = ui.bp_edit_original_auto_continue;
				const bool queued = queue_debugger_mutation("Edit breakpoint",
					"debugger.breakpoint_edit", context,
					[edit_index, condition, log_text, auto_continue, context,
					 expected_generation, expected_fingerprint, expected_address,
					 expected_size, expected_type, expected_name, expected_condition,
					 expected_log, expected_auto_continue]() {
						mutation_result_t result;
						std::lock_guard<std::mutex> lock(debugger_engine::g_state.bp_mutex);
						if (!debugger_interaction::is_current(context) ||
							debugger_engine::g_state.breakpoints_generation.load(std::memory_order_acquire) !=
								expected_generation || edit_index < 0 ||
							edit_index >= static_cast<int>(debugger_engine::g_state.breakpoints.size()) ||
							!breakpoint_edit_identity_matches(
								debugger_engine::g_state.breakpoints[static_cast<std::size_t>(edit_index)],
								expected_fingerprint, expected_address, expected_size, expected_type,
								expected_name, expected_condition, expected_log,
								expected_auto_continue)) {
							result.detail = "Breakpoint edit rejected because the target, stop, index, or breakpoint identity changed.";
							return result;
						}
						auto& breakpoint = debugger_engine::g_state.breakpoints[static_cast<std::size_t>(edit_index)];
						breakpoint.condition = condition;
						breakpoint.log_text = log_text;
						breakpoint.auto_continue = auto_continue;
						debugger_engine::g_state.breakpoints_generation.fetch_add(1, std::memory_order_release);
						result.ok = result.verified = true;
						return result;
					});
				if (queued) {
					ui.bp_edit_idx = -1;
					ui.bp_edit_identity_retained = false;
					ImGui::CloseCurrentPopup();
				}
				}
			}
			if (footer.cancelled) {
				ui.bp_edit_idx = -1;
				ui.bp_edit_identity_retained = false;
				ImGui::CloseCurrentPopup();
			}
		} else {
			ImGui::Text("Selection no longer valid.");
			aida::ui::design::end_dialog_body();
			const auto footer = aida::ui::design::dialog_footer(
				"debugger_breakpoint_edit_stale_footer", "Close", true, false, nullptr);
			if (footer.confirmed || footer.cancelled) {
				ui.bp_edit_idx = -1;
				ui.bp_edit_identity_retained = false;
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}
}


static void render_memmap(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	(void)dl;
	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] memmap enter ok=1");
		}
	}
	memory_map_view::render(ox, oy, w, h, a,
		aida::ui::resolved().accent.x,
		aida::ui::resolved().accent.y,
		aida::ui::resolved().accent.z);
}


static void render_callstack(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] callstack enter ok=1");
		}
	}

	if (driver_bridge::attached_pid() == 0) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process and pause it to capture a call stack.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	{
		static std::atomic<uint64_t> s_last_refresh_ms{0};
		static std::atomic<bool> s_in_flight{false};
		uint64_t now_ms = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
		uint64_t last = s_last_refresh_ms.load(std::memory_order_acquire);
		bool busy = s_in_flight.load(std::memory_order_acquire);
		if (!busy && now_ms - last > 500) {
			bool expected = false;
			if (s_in_flight.compare_exchange_strong(expected, true)) {
				const std::uint32_t target_pid = driver_bridge::attached_pid();
				const std::uint64_t target_generation =
					debugger_interaction::current_stop_generation();
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "debugger";
				sub.label = "debugger.call_stack_refresh";
				sub.thread_class = "debugger_refresh";
				sub.domain = aida::infra::executor::domain_t::feature_worker;
				sub.priority = 3;
				sub.target_pid = target_pid;
				sub.generation = target_generation;
				sub.body = [now_ms, target_pid, target_generation]() {
					try {
						const std::uint64_t publication_generation =
							debugger_engine::g_state.call_stack_generation.load(std::memory_order_acquire);
						if (driver_bridge::attached_pid() == target_pid &&
							debugger_interaction::current_stop_generation() == target_generation) {
							static_cast<void>(debugger_engine::get_call_stack());
							if (driver_bridge::attached_pid() != target_pid ||
								debugger_interaction::current_stop_generation() != target_generation) {
								std::lock_guard<std::mutex> lock(debugger_engine::g_state.stack_mutex);
								if (debugger_engine::g_state.call_stack_generation.load(
										std::memory_order_acquire) == publication_generation + 1U) {
									debugger_engine::g_state.call_stack.clear();
									debugger_engine::g_state.call_stack_generation.fetch_add(
										1U, std::memory_order_release);
								}
							} else {
								s_last_refresh_ms.store(now_ms, std::memory_order_release);
							}
						}
					} catch (...) {
						s_in_flight.store(false, std::memory_order_release);
						throw;
					}
					s_in_flight.store(false, std::memory_order_release);
				};
				const auto submitted = submit_owned_debugger_task(std::move(sub),
					"view.debug.call_stack", "debugger.call_stack_refresh",
					"Refresh call stack", false);
				if (!submitted.submitted) {
					diag::log_tagged("debugger", "call_stack_refresh_post_failed");
					s_in_flight.store(false, std::memory_order_release);
				}
			}
		}
	}

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + HEADER_H),
	                  with_a(t.panel_header, a));
	ImFont* cap_font = aida::ui::fonts::caption();
	if (!cap_font) cap_font = ImGui::GetFont();
	const float cap_font_size = aida::ui::fonts::size_or(cap_font, 13.5f);
	dl->AddText(cap_font, cap_font_size, ImVec2(ox + 12.f, oy + (HEADER_H - cap_font_size) * 0.5f),
	            with_a(t.text_dim, a), "CALL STACK");
	const char* hint = "double-click to jump, right-click to copy address";
	ImVec2 hs = cap_font->CalcTextSizeA(cap_font_size, FLT_MAX, 0.f, hint);
	dl->AddText(cap_font, cap_font_size,
		ImVec2(ox + w - hs.x - 12.f, oy + (HEADER_H - cap_font_size) * 0.5f),
		with_a(t.text_dim, a * 0.8f), hint);
	dl->AddLine(ImVec2(ox, oy + HEADER_H - 0.5f),
	            ImVec2(ox + w, oy + HEADER_H - 0.5f),
	            with_a(t.border_subtle, a));

	static render_snapshot_cache_t<debugger_engine::stack_frame_t> snapshot_cache;
	const auto& snapshot = refresh_render_snapshot(snapshot_cache, st.stack_mutex, st.call_stack,
		st.call_stack_generation, "call_stack");

	float card_pad = 10.f;
	float card_h = 56.f;
	float gap = 6.f;
	float row_h = card_h + gap;
	float content_y = oy + HEADER_H + card_pad;
	float visible_h = h - HEADER_H - card_pad * 2.f;
	int total_n = static_cast<int>(snapshot.size());

	std::map<std::string, int> recurse_count;
	for (const auto& f : snapshot)
		++recurse_count[f.module_name + "!" + f.function_name];

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##cs_list");
	ImGui::BeginChild("##cs_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* dim_font = aida::ui::fonts::caption();
	if (!dim_font) dim_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, 16.5f);
	const float code_font_size = aida::ui::fonts::size_or(code_font, 14.5f);
	const float dim_font_size = aida::ui::fonts::size_or(dim_font, 13.5f);

	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			auto& f = snapshot[static_cast<size_t>(i)];
			float cy = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();

			float card_x = ox + 12.f;
			float card_w = w - 36.f;

			ImGui::SetCursorScreenPos(ImVec2(card_x, cy));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##cs_card", ImVec2(card_w, card_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("callstack", "debugger-callstack-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::stack_frame, f.address,
					f.return_addr, i, 0, f.module_size, f.function_name,
					f.module_name));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();

			const auto context_for_row = [&](int row) {
				const auto& item = snapshot[static_cast<size_t>(row)];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::stack_frame, item.address,
					item.return_addr, row, 0, item.module_size, item.function_name,
					item.module_name);
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context,
				ui.callstack_panel.selected == i);
			ImVec2 ca(card_x, cy);
			ImVec2 cb(card_x + card_w, cy + card_h);

			float lift = hov ? 2.f : 0.f;
			ca.y -= lift; cb.y -= lift;

			if (hov) {
				for (int g = 0; g < 4; ++g) {
					float spread = static_cast<float>(g + 1) * 1.5f;
					dl->AddRectFilled(
						ImVec2(ca.x - spread, ca.y - spread + 3.f),
						ImVec2(cb.x + spread, cb.y + spread + 3.f),
						IM_COL32(0, 0, 0, static_cast<int>(15 * a * (1.f - static_cast<float>(g) / 4.f))),
						8.f + spread);
				}
			}

			ImU32 fill = aida::ui::mix(t.panel_bg, t.accent_glow, hov ? 0.20f : 0.f);
			dl->AddRectFilled(ca, cb, with_a(fill, a * 0.95f), 8.f);
			dl->AddRectFilled(ca, cb, with_a(t.glass_tint, a * 0.55f), 8.f);
			ImU32 border = sel ? t.accent_u32 : t.border_subtle;
			dl->AddRect(ca, cb, with_a(border, a * (sel ? 0.95f : 0.7f)), 8.f, 0,
				sel ? 1.5f : 1.f);

			if (sel) {
				dl->AddRectFilled(ImVec2(ca.x, ca.y), ImVec2(ca.x + 3.f, cb.y),
				                  with_a(t.accent_u32, a), 1.f);
			}

			char idx_buf[12];
			std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i);
			dl->AddText(dim_font, dim_font_size, ImVec2(ca.x + 12.f, ca.y + 8.f),
			            with_a(t.text_dim, a), idx_buf);

			std::string mod_label = f.module_name.empty() ? std::string("<unknown>") : f.module_name;
			dl->AddText(body_font, body_font_size, ImVec2(ca.x + 44.f, ca.y + 6.f),
			            with_a(t.text_primary, a), mod_label.c_str());

			std::string func = f.function_name.empty() ? std::string("?") : f.function_name;
			char fn_buf[256];
			std::snprintf(fn_buf, sizeof(fn_buf), "%s + 0x%" PRIX64,
				func.c_str(), f.module_offset);
			dl->AddText(code_font, code_font_size, ImVec2(ca.x + 44.f, ca.y + 24.f),
			            with_a(t.syn_function, a), fn_buf);

			char abuf[24];
			std::snprintf(abuf, sizeof(abuf), "0x%016" PRIX64, f.address);
			dl->AddText(code_font, code_font_size, ImVec2(ca.x + 44.f, ca.y + 40.f),
			            with_a(t.text_address, a), abuf);

			std::string key = f.module_name + "!" + f.function_name;
			int rec = recurse_count[key];
			if (rec > 1) {
				char rec_buf[24];
				std::snprintf(rec_buf, sizeof(rec_buf), "x%d recursive", rec);
				ImVec2 rs = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, rec_buf);
				float rx = cb.x - rs.x - 22.f;
				float ry2 = ca.y + 6.f;
				dl->AddRectFilled(ImVec2(rx - 6.f, ry2 - 1.f),
				                  ImVec2(rx + rs.x + 6.f, ry2 + 14.f),
				                  with_a(t.warning, a * 0.18f), 4.f);
				dl->AddText(body_font, body_font_size, ImVec2(rx, ry2),
				            with_a(t.warning, a), rec_buf);
			}

			if (clicked) {
				ui.callstack_panel.selected = i;
				select_debugger_row(row_context, total_n, context_for_row, false);
			}
			if (dclicked) {
				diag::log_tagged_fmt("dbg_view", "callstack double-click: jump to frame addr=0x%llX module='%s'",
					static_cast<unsigned long long>(f.address), f.module_name.c_str());
				jump_to_disasm(f.address);
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(row_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		if (driver_bridge::attached_pid() == 0) {
			aida::ui::no_target_overlay::render(
				ImVec2(ox, content_y), ImVec2(w, visible_h),
				"No debug target attached",
				"Attach to a running process or launch a target to capture call stacks and live debugger state.",
				a, aida::ui::empty_state::glyph_t::shield);
		} else {
			aida::ui::empty_state::config_t es;
			es.glyph = aida::ui::empty_state::glyph_t::layers;
			es.title = "No call stack";
			es.body  = "Pause the target to capture the call stack.";
			aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
		}
	}
}


static void render_threads(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] threads enter ok=1");
		}
	}

	if (driver_bridge::attached_pid() == 0) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to enumerate, suspend, resume, or terminate its threads.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	{
		ui_anim::table_col_t cols[] = {
			{"TID", 90.f}, {"Priority", 80.f}, {"State", 110.f},
			{"RIP", 200.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 5, a);
	}

	auto& st = debugger_engine::g_state;
	debugger_engine::request_thread_refresh(250);
	static render_snapshot_cache_t<debugger_engine::cached_thread_t> thread_cache;
	const auto& threads = refresh_render_snapshot(thread_cache, st.cache_mtx, st.cached_threads,
		st.cached_threads_generation, "threads");
	int total_n = static_cast<int>(threads.size());
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##th_list");
	ImGui::BeginChild("##th_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	float row_h = ROW_HEIGHT + 4.f;

	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int ti = clipper.DisplayStart; ti < clipper.DisplayEnd; ++ti) {
			float ry = content_y + static_cast<float>(ti) * row_h - ImGui::GetScrollY();
			auto& th = threads[static_cast<size_t>(ti)];

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(ti);
			ImGui::InvisibleButton("##th_row", ImVec2(w - 18.f - 280.f, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("thread", "debugger-thread-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::thread, th.rip, 0, ti, th.tid));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();

			const auto thread_context = debugger_interaction::capture(
				debugger_interaction::kind_t::thread, th.rip, 0, ti, th.tid);
			const auto context_for_row = [&](int row) {
				const auto& item = threads[static_cast<size_t>(row)];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::thread, item.rip, 0, row, item.tid);
			};
			bool sel = debugger_row_selected(thread_context,
				ui.threads_panel.selected == ti);
			const auto suspend_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::suspend_thread, thread_context);
			const auto resume_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::resume_thread, thread_context);
			const auto switch_gate = debugger_interaction::evaluate(
				debugger_interaction::capability_t::switch_thread, thread_context);

			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, ti, 1.f, a);

			float thread_state_flash = 0.f;
			const bool has_thread_state_slot = ti >= 0 && ti < 256;
			if (has_thread_state_slot) {
				const size_t state_index = static_cast<size_t>(ti);
				if (th.state != ui.prev_thread_state[state_index]) {
					ui.thread_state_flash[state_index] = 1.f;
					ui.prev_thread_state[state_index] = th.state;
				}
				ui_anim::decay_flash(ui.thread_state_flash[state_index], 1.5f, dt);
				thread_state_flash = ui.thread_state_flash[state_index];
			}

			char tbuf[12];
			std::snprintf(tbuf, sizeof(tbuf), "%u", th.tid);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 8.f, ry + 7.f),
			            with_a(t.text_address, a), tbuf);

			char prbuf[12];
			std::snprintf(prbuf, sizeof(prbuf), "%d", th.priority);
			dl->AddText(body_font, body_font_size, ImVec2(ox + 100.f, ry + 7.f),
			            with_a(t.text_secondary, a), prbuf);

			const char* state_str;
			ImU32 pcol = t.text_secondary;
			switch (th.state) {
				case 0: state_str = "INITIALIZED"; pcol = t.info;    break;
				case 1: state_str = "READY";       pcol = t.info;    break;
				case 2: state_str = "RUNNING";     pcol = t.success; break;
				case 3: state_str = "STANDBY";     pcol = t.info;    break;
				case 4: state_str = "TERMINATED";  pcol = t.error;   break;
				case 5: state_str = "WAITING";     pcol = t.warning; break;
				case 6: state_str = "TRANSITION";  pcol = t.warning; break;
				default: state_str = "UNKNOWN";    pcol = t.text_secondary; break;
			}
			ImVec2 ss = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, state_str);
			float pw = ss.x + 22.f;
			float ph = 16.f;
			float pyy = ry + (row_h - ph) * 0.5f;
			float px = ox + 180.f;
			dl->AddRectFilled(ImVec2(px, pyy), ImVec2(px + pw, pyy + ph),
			                  with_a(pcol, a * 0.22f), ph * 0.5f);
			dl->AddRect(ImVec2(px, pyy), ImVec2(px + pw, pyy + ph),
			            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
			float dot_pulse = has_thread_state_slot ? (0.5f + thread_state_flash * 0.5f) : 0.55f;
			dot_pulse += aida::ui::clock::pulse(1.6f, 0.f, 0.4f);
			if (dot_pulse > 1.f) dot_pulse = 1.f;
			dl->AddCircleFilled(ImVec2(px + 9.f, pyy + ph * 0.5f), 3.f,
			                    with_a(pcol, a * dot_pulse), 14);
			dl->AddText(body_font, body_font_size,
				ImVec2(px + 16.f, pyy + (ph - 11.f) * 0.5f),
				with_a(pcol, a), state_str);

			if (th.rip != 0) {
				char rbuf[20];
				std::snprintf(rbuf, sizeof(rbuf), "0x%016" PRIX64, th.rip);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 300.f, ry + 7.f),
				            with_a(t.text_address, a * 0.85f), rbuf);
			}

			float actions_x = ox + 500.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			float btn_g = 4.f;

			float thread_btn_w = 48.f;
			ImGui::SetCursorScreenPos(ImVec2(actions_x, btn_y));
			ImGui::PushID(ti + 0x20000);
			bool susp = aida::ui::button("Susp", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h), !suspend_gate.enabled);
			ImGui::PopID();
			if (susp) {
				static_cast<void>(queue_debugger_mutation("Suspend thread",
					"debugger.thread_suspend", thread_context, [tid = th.tid]() {
						mutation_result_t result;
						std::uint32_t previous = 0;
						result.ok = result.verified = driver_bridge::suspend_thread(tid, &previous);
						return result;
					}));
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + thread_btn_w + btn_g, btn_y));
			ImGui::PushID(ti + 0x30000);
			bool res = aida::ui::button("Res",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h), !resume_gate.enabled);
			ImGui::PopID();
			if (res) {
				static_cast<void>(queue_debugger_mutation("Resume thread",
					"debugger.thread_resume", thread_context, [tid = th.tid]() {
						mutation_result_t result;
						std::uint32_t previous = 0;
						result.ok = result.verified = driver_bridge::resume_thread(tid, &previous);
						return result;
					}));
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + (thread_btn_w + btn_g) * 2.f, btn_y));
			ImGui::PushID(ti + 0x31000);
			bool switch_clicked = aida::ui::button("Switch",
				aida::ui::button_kind_t::primary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w + 12.f, btn_h),
				!switch_gate.enabled);
			ImGui::PopID();
			if (switch_clicked) {
				debugger_engine::g_state.active_tid = th.tid;
				debugger_engine::invalidate_cache();
				diag::log_tagged_critical_fmt("debugger",
					"thread_switch_context tid=%u", static_cast<unsigned>(th.tid));
				diag::log_tagged("dbg_audit",
					"[dbg_audit] threads switch ok=1");
				toast_notification::push("Active thread context switched.",
					toast_notification::toast_type_t::info);
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + (thread_btn_w + btn_g) * 3.f + 8.f, btn_y));
			ImGui::PushID(ti + 0x32000);
			bool kill_clicked = aida::ui::button("Kill",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h));
			ImGui::PopID();
			if (kill_clicked) {
				ui.thread_kill_idx = ti;
				ui.thread_kill_tid = th.tid;
				ui.thread_kill_context = debugger_interaction::capture(
					debugger_interaction::kind_t::thread, th.rip, 0, ti, th.tid);
				ui.thread_kill_popup_open = true;
				diag::log_tagged("dbg_audit",
					"[dbg_audit] threads kill_request ok=1");
			}

			if (clicked) {
				ui.threads_panel.selected = ti;
				select_debugger_row(thread_context, total_n, context_for_row, false);
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(thread_context, total_n, context_for_row, true);
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && th.rip != 0)
				jump_to_disasm(th.rip);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (threads.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::cpu;
		es.title = "No threads enumerated";
		es.body  = "Attach to a process to inspect its threads.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.thread_kill_popup_open) {
		ImGui::OpenPopup("Terminate Thread##th");
		ui.thread_kill_popup_open = false;
	}
	if (aida::ui::design::begin_dialog_exact("Terminate Thread##th",
		ImVec2(560.0f, 360.0f), ImVec2(380.0f, 280.0f))) {
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Terminate", "Cancel");
		aida::ui::design::begin_dialog_body("debugger_terminate_thread_body",
			footer_height);
		ImGui::TextWrapped(
			"Terminate thread %u with exit code 0xDEAD?",
			static_cast<unsigned>(ui.thread_kill_tid));
		const auto terminate_gate = debugger_interaction::evaluate(
			debugger_interaction::capability_t::terminate_thread,
			ui.thread_kill_context);
		if (!terminate_gate.enabled)
			ImGui::TextWrapped("Unavailable: %s", terminate_gate.disabled_reason);
		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"debugger_terminate_thread_footer", "Terminate", terminate_gate.enabled,
			true, "Cancel");
		if (footer.confirmed) {
			const std::uint32_t target_tid = ui.thread_kill_tid;
			const auto context = ui.thread_kill_context;
			static_cast<void>(queue_debugger_mutation("Terminate thread",
				"debugger.thread_terminate", context, [target_tid]() {
					mutation_result_t result;
					result.ok = driver_bridge::terminate_thread(target_tid, 0xDEADu);
					if (result.ok) {
						auto current_threads = driver_bridge::enumerate_threads();
						result.verified = std::none_of(current_threads.begin(), current_threads.end(),
							[target_tid](const auto& thread) { return thread.tid == target_tid; });
					}
					if (!result.verified)
						result.detail = result.ok ? "Thread termination could not be verified."
							: "Kernel thread termination failed: " + driver_bridge::last_error();
					return result;
				}));
			ui.thread_kill_idx = -1;
			ui.thread_kill_tid = 0;
			ImGui::CloseCurrentPopup();
		}
		if (footer.cancelled) {
			ui.thread_kill_idx = -1;
			ui.thread_kill_tid = 0;
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}


static void render_watches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] watches enter ok=1");
		}
	}

	const auto toolbar_metrics = aida::ui::design::metrics();
	const float toolbar_pad = (std::max)(6.f, toolbar_metrics.spacing_sm);
	const float toolbar_gap = (std::max)(4.f, toolbar_metrics.spacing_xs);
	const float control_height = (std::max)(28.f, toolbar_metrics.control_height);
	const bool stacked_toolbar = w < aida::ui::scale_px(600.f, toolbar_metrics.scale);
	const float bar_h = stacked_toolbar
		? toolbar_pad + control_height + toolbar_gap + control_height + toolbar_pad
		: (std::max)(40.f, control_height + toolbar_pad * 2.f);

	if (driver_bridge::attached_pid() == 0) {
		float cw = (std::max)(1.f, (std::min)(w - 20.f, 620.f));
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + bar_h + (h - bar_h) * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to evaluate register/memory watch expressions live.",
			ui_anim::callout_kind_t::info, t.accent.x, t.accent.y, t.accent.z, a);
	}

	const float input_w = stacked_toolbar
		? (std::max)(1.f, w - toolbar_pad * 2.f)
		: (std::clamp)(w * 0.55f, aida::ui::scale_px(170.f, toolbar_metrics.scale),
			(std::max)(aida::ui::scale_px(170.f, toolbar_metrics.scale),
				w - aida::ui::scale_px(210.f, toolbar_metrics.scale)));
	const float actions_x = stacked_toolbar
		? ox + toolbar_pad : ox + toolbar_pad + input_w + toolbar_gap;
	const float actions_y = stacked_toolbar
		? oy + toolbar_pad + control_height + toolbar_gap : oy + toolbar_pad;
	const float actions_w = stacked_toolbar
		? (std::max)(1.f, w - toolbar_pad * 2.f)
		: (std::max)(1.f, w - (actions_x - ox) - toolbar_pad);
	ImGui::SetCursorScreenPos(ImVec2(ox + toolbar_pad, oy + toolbar_pad));
	ImGui::PushID("##w_actions");
	aida::ui::input_text("##w_expr", ui.add_watch_buf, sizeof(ui.add_watch_buf),
		"watch: RAX, [RBX+0x10], or 0x...",
		false, ImVec2(input_w, control_height));
	const auto refresh_presentation = aida::ui::application_ui::present_action(
		"debugger.watch.refresh_all");
	std::string refresh_tooltip = refresh_presentation.description;
	if (!refresh_presentation.enabled && !refresh_presentation.disabled_reason.empty()) {
		refresh_tooltip.append("\n");
		refresh_tooltip.append(refresh_presentation.disabled_reason);
	}
	const bool can_add = ui.add_watch_buf[0] != '\0';
	const aida::ui::design::action_t actions[] = {
		{"debugger.watch.add", "Add Watch", "Add", can_add
			? "Add the entered register or memory expression"
			: "Enter a register or memory expression before adding a watch",
			nullptr, nullptr, aida::ui::button_kind_t::primary, can_add, true, true},
		{"debugger.watch.refresh_all", "Refresh All Watches", "Refresh",
			refresh_tooltip.c_str(), refresh_presentation.shortcut.c_str(), nullptr,
			aida::ui::button_kind_t::secondary, refresh_presentation.enabled, false, true}
	};
	ImGui::SetCursorScreenPos(ImVec2(actions_x, actions_y));
	const auto action = aida::ui::design::render_toolbar(
		"debugger.watches.actions", actions, std::size(actions), actions_w);
	const std::string_view invoked = action.invoked && action.id
		? std::string_view(action.id) : std::string_view();
	if (invoked == "debugger.watch.add") {
		int idx = debugger_engine::add_watch(ui.add_watch_buf);
		diag::log_tagged_critical_fmt("watches",
			"watch_add expr='%s' idx=%d",
			ui.add_watch_buf, idx);
		ui.add_watch_buf[0] = '\0';
	}
	if (invoked == "debugger.watch.refresh_all") {
		diag::log_tagged_fmt("watches", "watch_refresh_all_request");
		static_cast<void>(aida::ui::application_ui::execute_action(
			"debugger.watch.refresh_all",
			aida::ui::action_invocation_source_t::toolbar));
	}
	ImGui::PopID();

	const bool compact_rows = w < 700.f;
	float table_y = oy + bar_h;
	if (compact_rows) {
		ui_anim::table_col_t cols[] = {
			{"Watch", (std::max)(1.f, w - 70.f)}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 2, a);
	} else {
		const float value_column_width = (std::max)(100.f, w - 484.f);
		ui_anim::table_col_t cols[] = {
			{"Expression", 220.f}, {"Resolved Address", 180.f},
			{"Value", value_column_width}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 4, a);
	}

	static render_snapshot_cache_t<debugger_engine::watch_entry_t> snapshot_cache;
	const auto& snapshot = refresh_render_snapshot(snapshot_cache, st.watch_mutex, st.watches,
		st.watches_generation, "watches");
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = (std::max)(1.f, h - bar_h - HEADER_H);

	auto regs = debugger_engine::cached_registers();

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##w_list");
	ImGui::BeginChild("##w_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	float row_h = compact_rows ? (std::max)(42.f, ROW_HEIGHT + 16.f) : ROW_HEIGHT + 4.f;
	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			auto& w_entry = snapshot[static_cast<size_t>(i)];

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##w_row", ImVec2((std::max)(1.f,
				w - (compact_rows ? 68.f : 108.f)), row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();

			const std::string& display_expression = w_entry.persistent_expression.empty()
				? w_entry.expression : w_entry.persistent_expression;
			bool deref = false;
			bool ok = false;
			uint64_t resolved = w_entry.definition_resolved
				? evaluate_watch_expression(w_entry.expression, regs, deref, ok) : 0;
			char addr_buf[32];
			if (ok) {
				std::snprintf(addr_buf, sizeof(addr_buf), "%s0x%016" PRIX64,
					deref ? "[*] " : "", resolved);
			} else {
				std::snprintf(addr_buf, sizeof(addr_buf), "?");
			}
			ImU32 vcol = w_entry.valid ? t.success : t.error;
			const char* value_text = w_entry.valid
				? w_entry.value.c_str()
				: (w_entry.error.empty() ? "<error>" : w_entry.error.c_str());
			const auto watch_context = debugger_interaction::capture(
				debugger_interaction::kind_t::watch, ok ? resolved : 0, 0, i,
				0, 0, display_expression, value_text);
			const auto context_for_row = [&](int row) {
				const auto& item = snapshot[static_cast<size_t>(row)];
				bool item_deref = false;
				bool item_ok = false;
				const uint64_t item_address = item.definition_resolved
					? evaluate_watch_expression(item.expression, regs, item_deref, item_ok) : 0;
				const std::string& item_expression = item.persistent_expression.empty()
					? item.expression : item.persistent_expression;
				const char* item_value = item.valid ? item.value.c_str()
					: (item.error.empty() ? "<error>" : item.error.c_str());
				return debugger_interaction::capture(debugger_interaction::kind_t::watch,
					item_ok ? item_address : 0, 0, row, 0, 0, item_expression, item_value);
			};
			const bool sel = debugger_row_selected(watch_context,
				ui.watch_panel.selected == i);
			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, i, 1.f, a);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("watch", "debugger-watch-row", watch_context);
#endif
			const float action_pad = compact_rows
				? (std::min)(8.f, (std::max)(0.f, w * 0.08f)) : 20.f;
			float btn_w = compact_rows
				? (std::max)(1.f, (std::min)(54.f, w - action_pad * 2.f)) : 64.f;
			float btn_x = ox + (std::max)(0.f, w - btn_w - action_pad);
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			const float text_right = (std::max)(ox + 1.f, btn_x - 4.f);
			dl->PushClipRect(ImVec2(ox, ry), ImVec2(text_right, ry + row_h), true);
			if (compact_rows) {
				dl->AddText(body_font, body_font_size, ImVec2(ox + 10.f, ry + 3.f),
					with_a(w_entry.definition_resolved ? t.text_primary : t.warning, a),
					display_expression.c_str());
				dl->AddText(code_font, code_font_size, ImVec2(ox + 10.f, ry + 22.f),
					with_a(t.text_address, a), addr_buf);
				const float value_x = (std::max)(ox + 118.f,
					ox + (text_right - ox) * 0.52f);
				dl->AddText(code_font, code_font_size, ImVec2(value_x, ry + 22.f),
					with_a(vcol, a), value_text);
			} else {
				const ImVec4 expression_clip(ox, ry, ox + 226.f, ry + row_h);
				const ImVec4 address_clip(ox + 226.f, ry, ox + 406.f, ry + row_h);
				const ImVec4 value_clip(ox + 406.f, ry, text_right, ry + row_h);
				dl->AddText(body_font, body_font_size, ImVec2(ox + 10.f, ry + 7.f),
					with_a(w_entry.definition_resolved ? t.text_primary : t.warning, a),
					display_expression.c_str(), nullptr, 0.f, &expression_clip);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 230.f, ry + 7.f),
					with_a(t.text_address, a), addr_buf, nullptr, 0.f, &address_clip);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 410.f, ry + 7.f),
					with_a(vcol, a), value_text, nullptr, 0.f, &value_clip);
			}
			dl->PopClipRect();
			if (hov) {
				ImGui::BeginTooltip();
				ImGui::TextUnformatted(display_expression.c_str());
				ImGui::Text("Resolved: %s", addr_buf);
				ImGui::TextWrapped("Value: %s", value_text);
				if (w_entry.persistent_definition && !w_entry.definition_module.empty()) {
					ImGui::Separator();
					ImGui::Text("Persistent definition: %s+0x%" PRIX64,
						w_entry.definition_module.c_str(), w_entry.definition_module_offset);
					if (!w_entry.definition_resolved)
						ImGui::TextWrapped("%s", w_entry.error.c_str());
				}
				ImGui::EndTooltip();
			}
			ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
			ImGui::PushID(i + 0x40000);
			bool action_clicked = aida::ui::button(
				compact_rows ? (btn_w < 42.f ? "..." : "More") : "Remove",
				compact_rows ? aida::ui::button_kind_t::secondary : aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(btn_w, btn_h));
			ImGui::PopID();
			if (action_clicked && compact_rows) {
				ui.watch_panel.selected = i;
				select_debugger_row(watch_context, total_n, context_for_row, false);
				open_debugger_entity_actions(watch_context,
					aida::ui::context_menu_open_origin_t::pointer);
			} else if (action_clicked) {
				diag::log_tagged_fmt("watches",
					"watch_remove_review idx=%d expr='%s'",
					i, w_entry.expression.c_str());
				request_context_mutation(pending_context_mutation_t::remove_watch,
					watch_context);
			}

			if (clicked) {
				ui.watch_panel.selected = i;
				select_debugger_row(watch_context, total_n, context_for_row, false);
			}
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ok && resolved != 0)
				jump_to_hex(resolved, 256);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(watch_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No watches added";
		es.body  = "Add expressions like RAX, [RSP+8], or absolute addresses to monitor.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_trace(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] trace enter ok=1");
		}
	}

	float bar_h = 40.f;
	float input_w = (std::min)(w * 0.40f, (std::max)(120.0f, w - 430.0f));
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##tr_actions");
	aida::ui::input_text("##tr_filter", ui.trace_filter_buf, sizeof(ui.trace_filter_buf),
		"filter trace by mnemonic or hex address",
		false, ImVec2(input_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	ImGui::Checkbox("Freeze view", &ui.trace_freeze_display);
	ImGui::SameLine(0.f, btn_gap);
	bool tracing = st.tracing.load();
	bool trace_can_start = driver_bridge::attached_pid() != 0;
	bool start_clicked = aida::ui::button(tracing ? "Stop Trace" : "Start Trace",
		tracing ? aida::ui::button_kind_t::destructive : aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		!tracing && !trace_can_start);
	if (start_clicked) {
		const auto context = debugger_interaction::capture(
			debugger_interaction::kind_t::trace_record);
		static_cast<void>(queue_debugger_mutation(tracing ? "Stop trace" : "Start trace",
			tracing ? "debugger.trace_stop" : "debugger.trace_start", context,
			[tracing]() {
				mutation_result_t result;
				if (tracing) {
					debugger_engine::stop_trace();
					result.ok = result.verified =
						!debugger_engine::g_state.tracing.load(std::memory_order_acquire);
				} else {
					result.ok = debugger_engine::start_trace();
					result.verified = result.ok &&
						debugger_engine::g_state.tracing.load(std::memory_order_acquire);
				}
				return result;
			}, false));
	}
	ImGui::SameLine(0.f, btn_gap);
	bool clear_clicked = aida::ui::button("Clear",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (clear_clicked) {
		size_t before = 0;
		std::unique_lock<std::mutex> trace_lock(st.trace_mutex, std::try_to_lock);
		if (trace_lock.owns_lock()) {
			before = st.trace_log.size();
			st.trace_log.clear();
			st.trace_generation.fetch_add(1, std::memory_order_release);
			st.trace_dropped.store(0, std::memory_order_release);
			trace_lock.unlock();
			diag::log_tagged_fmt("trace", "trace_clear removed=%zu", before);
			diag::log_tagged("dbg_audit",
				"[dbg_audit] trace clear ok=1");
		} else
			toast_notification::push("Trace is updating; retry Clear in a moment.",
				toast_notification::toast_type_t::warning);
	}
	ImGui::SameLine(0.f, btn_gap);
	bool export_clicked = aida::ui::button("Export",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (export_clicked) {
		bool trace_empty = false;
		if (st.trace_mutex.try_lock()) {
			trace_empty = st.trace_log.empty();
			st.trace_mutex.unlock();
		}
		if (trace_empty) {
			toast_notification::push("Trace is empty.",
				toast_notification::toast_type_t::warning);
			diag::log_tagged("dbg_audit",
				"[dbg_audit] trace export fail reason=empty");
		} else {
			char path_buf[MAX_PATH] = "trace.csv";
			static const char k_trace_filter[] =
				"CSV (*.csv)\0*.csv\0Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
			if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Trace",
					k_trace_filter,
					"csv",
					path_buf, sizeof(path_buf),
					"debugger_view::trace_export")) {
				const std::string path(path_buf);
				auto cancelled = std::make_shared<std::atomic<bool>>(false);
				aida::infra::executor::submission_t submission;
				submission.owner_subsystem = "debugger.trace";
				submission.label = "trace.export";
				submission.thread_class = "bounded_task";
				submission.domain = aida::infra::executor::domain_t::diagnostics;
				submission.priority = 3;
				submission.cancel_hook = [cancelled]() {
					cancelled->store(true, std::memory_order_release);
				};
				auto export_result = std::make_shared<mutation_result_t>();
				submission.body = [path, cancelled, export_result]() {
					auto publish = [export_result]() {
						return post_debugger_ui([export_result]() {
							toast_notification::push(export_result->verified ? "Trace export completed."
								: export_result->detail,
								export_result->verified ? toast_notification::toast_type_t::success
									: toast_notification::toast_type_t::error);
						}, "trace_export_completion");
					};
					std::size_t written = 0;
					try {
						std::vector<debugger_engine::trace_record_t> trace_copy;
						{
							std::lock_guard<std::mutex> lock(debugger_engine::g_state.trace_mutex);
							const auto& source = debugger_engine::g_state.trace_log;
							if (source.size() > 50000U)
								export_result->detail = "Trace exceeds the 50,000-record export bound.";
							else {
								std::size_t text_bytes = 0;
								for (const auto& record : source) {
									text_bytes += record.disasm_text.size();
									if (text_bytes > 64U * 1024U * 1024U) {
										export_result->detail = "Trace text exceeds the 64 MiB export bound.";
										break;
									}
								}
								if (export_result->detail.empty()) trace_copy = source;
							}
						}
						if (cancelled->load(std::memory_order_acquire))
							export_result->detail = "Trace export cancelled.";
						if (export_result->detail.empty()) {
							std::string csv;
							csv.reserve(std::min<std::size_t>(64U * 1024U * 1024U,
								trace_copy.size() * 160U + 64U));
							csv.append("index,address,rip,rax,rcx,rdx,rsp,disasm\n");
							for (const auto& record : trace_copy) {
								if ((written & 0x3ffU) == 0U && cancelled->load(std::memory_order_acquire)) {
									export_result->detail = "Trace export cancelled.";
									break;
								}
								char line[512];
								std::snprintf(line, sizeof(line),
									"%d,0x%016llX,0x%016llX,0x%016llX,0x%016llX,0x%016llX,0x%016llX,",
									record.index,
									static_cast<unsigned long long>(record.address),
									static_cast<unsigned long long>(record.regs.rip),
									static_cast<unsigned long long>(record.regs.rax),
									static_cast<unsigned long long>(record.regs.rcx),
									static_cast<unsigned long long>(record.regs.rdx),
									static_cast<unsigned long long>(record.regs.rsp));
								csv.append(line);
								for (const char character : record.disasm_text)
									csv.push_back(character == ',' || character == '"' || character == '\n' || character == '\r' ? ' ' : character);
								csv.push_back('\n');
								if (csv.size() > 128U * 1024U * 1024U) {
									export_result->detail = "Encoded trace exceeds the 128 MiB export bound.";
									break;
								}
								++written;
							}
							if (export_result->detail.empty())
								export_result->ok = export_result->verified = write_file_atomic_exact(
									path, csv.data(), csv.size(), export_result->detail);
						}
					} catch (const std::exception& exception) {
						export_result->detail = std::string("Trace export failed: ") + exception.what();
					} catch (...) {
						export_result->detail = "Trace export failed with an unknown error.";
					}
					if (!export_result->verified && export_result->detail.empty())
						export_result->detail = "Trace export failed.";
					diag::log_tagged_critical_fmt("trace", "trace_export count=%zu ok=%d path='%s'",
						written, export_result->verified ? 1 : 0, path.c_str());
					if (!publish())
						throw std::runtime_error("Trace-export completion could not be published to the UI thread");
					if (!export_result->verified)
						throw std::runtime_error(export_result->detail);
				};
				const auto result = submit_owned_debugger_task(std::move(submission),
					"view.debug.trace", "debugger.trace_export", "Export debugger trace", true);
				if (!result.submitted)
					toast_notification::push("Trace export could not be queued: " +
						result.reject_reason, toast_notification::toast_type_t::error);
				else {
					toast_notification::push("Trace export queued in Background Tasks.", toast_notification::toast_type_t::info);
				}
			}
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {{"#", 60.f}, {"Address", 170.f}, {"Instruction", 360.f}};
		draw_table_header(dl, ox, table_y, w, cols, 3, a);
	}

	if (tracing) ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 1.f, 6.f, dt);
	else         ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 0.f, 4.f, dt);

	{
		const char* status = tracing ? "REC" : "STOPPED";
		ImU32 pcol = tracing ? t.error : t.text_secondary;
		ImFont* sf = aida::ui::fonts::body_em();
		if (!sf) sf = ImGui::GetFont();
		const float sf_size = aida::ui::fonts::size_or(sf, ImGui::GetFontSize());
		ImVec2 sts = sf->CalcTextSizeA(sf_size, FLT_MAX, 0.f, status);
		float pw = sts.x + 32.f;
		float ph = 18.f;
		float px = ox + w - pw - 10.f;
		float py = table_y + (HEADER_H - ph) * 0.5f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(pcol, a * 0.22f), ph * 0.5f);
		dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
		float pulse = aida::ui::clock::pulse(1.4f, 0.40f, 1.f);
		float dot_a = tracing ? pulse : 0.55f;
		float ring_progress = tracing ? aida::ui::clock::saw(2.0f) : 0.f;
		ImVec2 dc(px + 10.f, py + ph * 0.5f);
		dl->AddCircle(dc, 6.f, with_a(pcol, a * 0.30f), 18, 1.f);
		if (ring_progress > 0.001f) {
			float ang0 = -1.5707963f;
			float ang1 = ang0 + ring_progress * 6.2831853f;
			dl->PathArcTo(dc, 6.f, ang0, ang1, 24);
			dl->PathStroke(with_a(pcol, a), 0, 1.5f);
		}
		dl->AddCircleFilled(dc, 3.5f, with_a(pcol, a * dot_a), 16);
		dl->AddText(sf, sf_size,
			ImVec2(px + 22.f, py + (ph - 11.f) * 0.5f),
			with_a(pcol, a), status);
	}

	static render_snapshot_cache_t<debugger_engine::trace_record_t> trace_cache;
	const auto& trace_snapshot = ui.trace_freeze_display
		? trace_cache.items
		: refresh_render_snapshot(trace_cache, st.trace_mutex, st.trace_log,
			st.trace_generation, "trace", 0.100);
	const std::uint64_t dropped = st.trace_dropped.load(std::memory_order_acquire);
	if (dropped != 0) {
		char dropped_text[64];
		std::snprintf(dropped_text, sizeof(dropped_text), "Backpressure: %llu dropped",
			static_cast<unsigned long long>(dropped));
		ImFont* status_font = aida::ui::fonts::caption();
		if (!status_font) status_font = ImGui::GetFont();
		const float status_size = aida::ui::fonts::size_or(status_font, ImGui::GetFontSize());
		const ImVec2 status_extent = status_font->CalcTextSizeA(status_size, FLT_MAX, 0.0f, dropped_text);
		dl->AddText(status_font, status_size,
			ImVec2(ox + w - status_extent.x - 108.0f, table_y + (HEADER_H - status_size) * 0.5f),
			with_a(t.warning, a), dropped_text);
	}
	static std::vector<std::size_t> filtered_indices;
	static std::string applied_filter;
	static std::uint64_t filtered_generation = 0;
	std::string normalized_filter;
	for (const char c : std::string(ui.trace_filter_buf))
		normalized_filter.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
	if (filtered_generation != trace_cache.generation || applied_filter != normalized_filter) {
		applied_filter = normalized_filter;
		filtered_generation = trace_cache.generation;
		filtered_indices.clear();
		filtered_indices.reserve(trace_snapshot.size());
		for (std::size_t trace_index = 0; trace_index < trace_snapshot.size(); ++trace_index) {
			const auto& record = trace_snapshot[trace_index];
			bool matches = applied_filter.empty();
			if (!matches) {
				std::string text_lower;
				text_lower.reserve(record.disasm_text.size());
				for (const char c : record.disasm_text)
					text_lower.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
				char address[20];
				std::snprintf(address, sizeof(address), "%" PRIx64, record.address);
				matches = text_lower.find(applied_filter) != std::string::npos ||
					std::strstr(address, applied_filter.c_str()) != nullptr;
			}
			if (matches)
				filtered_indices.push_back(trace_index);
		}
	}

	int total_n = static_cast<int>(filtered_indices.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##tr_list");
	ImGui::BeginChild("##tr_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ImGui::GetScrollY();
			const auto& tr = trace_snapshot[filtered_indices[static_cast<std::size_t>(i)]];
			const auto context_for_row = [&](int row) {
				const auto& item = trace_snapshot[filtered_indices[static_cast<size_t>(row)]];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::trace_record, item.address, 0,
					row, 0, 0, item.disasm_text);
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context, ui.trace_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##tr_row", ImVec2(w - 18.f, ROW_HEIGHT));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("trace", "debugger-trace-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::trace_record, tr.address, 0,
					i, 0, 0, tr.disasm_text));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char ibuf[12];
			std::snprintf(ibuf, sizeof(ibuf), "%d", tr.index);
			dl->AddText(body_font, body_font_size, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_dim, a), ibuf);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, tr.address);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 70.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 240.f, ry + 5.f),
			            with_a(t.text_primary, a), tr.disasm_text.c_str());

			if (clicked) {
				ui.trace_panel.selected = i;
				select_debugger_row(row_context, total_n, context_for_row, false);
			}
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				jump_to_disasm(tr.address);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(row_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (filtered_indices.empty() && !tracing) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::flow;
		es.title = "Trace not recording";
		es.body  = "Click Start Trace to capture executed instructions.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_strings(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] strings enter ok=1");
		}
	}

	bool scanning = st.strings_scanning.load(std::memory_order_acquire);
	bool cancel_pending = st.strings_cancel.load(std::memory_order_acquire);

	float bar_h = 40.f;
	float input_w = w * 0.45f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##s_actions");
	aida::ui::input_text("##s_filter", ui.string_filter, sizeof(ui.string_filter),
		"filter strings by substring",
		false, ImVec2(input_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	const char* btn_label = scanning
		? (cancel_pending ? "Cancelling..." : "Cancel Scan")
		: "Scan Strings";
	aida::ui::button_kind_t btn_kind = scanning
		? aida::ui::button_kind_t::destructive
		: aida::ui::button_kind_t::primary;
	bool scan_clicked = aida::ui::button(btn_label,
		btn_kind,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		cancel_pending, nullptr, scanning && !cancel_pending);
	if (scan_clicked) {
		if (scanning) {
			diag::log_tagged_critical_fmt("strings",
				"strings_cancel_request pages_so_far=%llu found_so_far=%llu",
				static_cast<unsigned long long>(st.strings_pages_scanned.load()),
				static_cast<unsigned long long>(st.strings_found_so_far.load()));
			debugger_engine::request_strings_cancel();
		} else {
			size_t min_len = static_cast<size_t>(std::max(2, ui.string_min_len));
			diag::log_tagged_critical_fmt("strings",
				"strings_scan_request min_length=%zu attached_pid=%u",
				min_len,
				static_cast<unsigned>(driver_bridge::attached_pid()));
			debugger_engine::find_strings_async(min_len);
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Address", 170.f}, {"String", 480.f}, {"Module", 140.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 3, a);
	}

	static render_snapshot_cache_t<debugger_engine::string_ref_t> strings_cache;
	const auto& strings_snapshot = refresh_render_snapshot(strings_cache, st.strings_mutex, st.strings,
		st.strings_generation, "strings");
	static std::vector<std::size_t> filtered_indices;
	static std::string applied_filter;
	static std::uint64_t filtered_generation = 0;
	std::string normalized_filter;
	for (const char c : std::string(ui.string_filter))
		normalized_filter.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
	if (filtered_generation != strings_cache.generation || applied_filter != normalized_filter) {
		applied_filter = normalized_filter;
		filtered_generation = strings_cache.generation;
		filtered_indices.clear();
		filtered_indices.reserve(strings_snapshot.size());
		for (std::size_t string_index = 0; string_index < strings_snapshot.size(); ++string_index) {
			const auto& item = strings_snapshot[string_index];
			bool matches = applied_filter.empty();
			if (!matches) {
				std::string value_lower;
				value_lower.reserve(item.value.size());
				for (const char c : item.value)
					value_lower.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
				matches = value_lower.find(applied_filter) != std::string::npos;
			}
			if (matches)
				filtered_indices.push_back(string_index);
		}
	}

	int total_n = static_cast<int>(filtered_indices.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##s_list");
	ImGui::BeginChild("##s_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ImGui::GetScrollY();
			const auto& sr = strings_snapshot[filtered_indices[static_cast<std::size_t>(i)]];
			const auto context_for_row = [&](int row) {
				const auto& item = strings_snapshot[filtered_indices[static_cast<size_t>(row)]];
				return debugger_interaction::capture(
					debugger_interaction::kind_t::string_value, item.address, 0, row,
					0, item.value.size(), item.value, item.module_name);
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context, ui.strings_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##s_row", ImVec2(w - 18.f, ROW_HEIGHT));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("string", "debugger-string-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::string_value, sr.address, 0, i,
					0, sr.value.size(), sr.value, sr.module_name));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, sr.address);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);

			const std::size_t display_length = (std::min)(sr.value.size(), std::size_t{96});
			dl->AddText(code_font, code_font_size, ImVec2(ox + 180.f, ry + 5.f),
			            with_a(t.syn_string, a), sr.value.data(), sr.value.data() + display_length);
			if (display_length < sr.value.size())
				dl->AddText(code_font, code_font_size, ImVec2(ox + 180.f +
					code_font->CalcTextSizeA(code_font_size, FLT_MAX, 0.f, sr.value.data(),
						sr.value.data() + display_length).x, ry + 5.f), with_a(t.syn_string, a), "...");

			if (!sr.module_name.empty())
				dl->AddText(body_font, body_font_size, ImVec2(ox + w - 150.f, ry + 5.f),
				            with_a(t.text_dim, a), sr.module_name.c_str());

			if (clicked) {
				ui.strings_panel.selected = i;
				select_debugger_row(row_context, total_n, context_for_row, false);
			}
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
				diag::log_tagged_fmt("dbg_view", "strings double-click: jump to hex addr=0x%llX value='%.32s'", (unsigned long long)sr.address, sr.value.c_str());
				jump_to_hex(sr.address, 256);
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(row_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (scanning) {
		static float s_strings_spin_t = 0.f;
		s_strings_spin_t += ImGui::GetIO().DeltaTime * 5.f;
		float region_cx = ox + w * 0.5f;
		float region_cy = content_y + visible_h * 0.5f;
		ImU32 spin_col = with_a(t.accent_u32, a);
		ui_anim::render_spinner(dl, region_cx, region_cy - 18.f, 12.f, 2.5f,
			spin_col, s_strings_spin_t);

		uint64_t pages = st.strings_pages_scanned.load(std::memory_order_acquire);
		uint64_t found_count = st.strings_found_so_far.load(std::memory_order_acquire);
		char hdr_buf[96];
		std::snprintf(hdr_buf, sizeof(hdr_buf), "Scanning strings...");
		char prog_buf[160];
		std::snprintf(prog_buf, sizeof(prog_buf),
			"Scanning %llu pages... %llu strings found so far",
			static_cast<unsigned long long>(pages),
			static_cast<unsigned long long>(found_count));
		ImVec2 hdr_sz = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, hdr_buf);
		ImVec2 prog_sz = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, prog_buf);
		dl->AddText(body_font, body_font_size,
			ImVec2(region_cx - hdr_sz.x * 0.5f, region_cy + 6.f),
			with_a(t.text_primary, a), hdr_buf);
		dl->AddText(body_font, body_font_size,
			ImVec2(region_cx - prog_sz.x * 0.5f, region_cy + 6.f + hdr_sz.y + 4.f),
			with_a(t.text_dim, a), prog_buf);
	} else if (filtered_indices.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::search;
		es.title = "No strings indexed";
		es.body  = "Click Scan Strings to enumerate the target's printable strings.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_bookmarks(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] bookmarks enter ok=1");
		}
	}

	float bar_h = 40.f;
	float addr_w = w * 0.22f;
	float lbl_w  = w * 0.32f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##bm_actions");
	aida::ui::input_text("##bm_addr", ui.add_bookmark_buf, sizeof(ui.add_bookmark_buf),
		"0x... address",
		false, ImVec2(addr_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::input_text("##bm_label", ui.add_bookmark_label_buf,
		sizeof(ui.add_bookmark_label_buf),
		"label (optional)",
		false, ImVec2(lbl_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	bool add_clicked = aida::ui::button("Add Bookmark",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (add_clicked) {
		uint64_t addr = parse_hex_address(ui.add_bookmark_buf);
		diag::log_tagged_critical_fmt("bookmarks",
			"bookmark_add_request raw='%s' parsed_addr=0x%llx label='%s'",
			ui.add_bookmark_buf,
			static_cast<unsigned long long>(addr),
			ui.add_bookmark_label_buf);
		if (addr != 0) {
			const std::string label(ui.add_bookmark_label_buf);
			const auto context = debugger_interaction::capture(
				debugger_interaction::kind_t::bookmark, addr, 0, -1, 0, 0, label);
			if (queue_debugger_mutation("Add bookmark", "debugger.bookmark_add",
				context, [addr, label]() {
					mutation_result_t result;
					debugger_engine::toggle_bookmark(addr);
					if (!label.empty()) debugger_engine::set_label(addr, label);
					result.ok = result.verified = true;
					return result;
				}, false)) {
				ui.add_bookmark_buf[0] = '\0';
				ui.add_bookmark_label_buf[0] = '\0';
			}
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {{"#", 36.f}, {"Address", 200.f},
			{"Label", 280.f}, {"Actions", 0.f}};
		draw_table_header(dl, ox, table_y, w, cols, 4, a);
	}

	static std::vector<uint64_t> snapshot;
	static std::map<uint64_t, std::string> labels_snapshot;
	std::unique_lock<std::mutex> annotation_lock(st.anno_mutex, std::try_to_lock);
	if (annotation_lock.owns_lock() && st.bookmarks.size() <= 65536U &&
		st.labels.size() <= 65536U) {
		snapshot = st.bookmarks;
		labels_snapshot.clear();
		for (auto& kv : st.labels) labels_snapshot[kv.first] = kv.second.text;
	}
	if (annotation_lock.owns_lock()) annotation_lock.unlock();
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##bm_list");
	ImGui::BeginChild("##bm_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	float row_h = ROW_HEIGHT + 4.f;
	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			uint64_t addr = snapshot[static_cast<size_t>(i)];
			const auto context_for_row = [&](int row) {
				const uint64_t item_address = snapshot[static_cast<size_t>(row)];
				const auto label_it = labels_snapshot.find(item_address);
				return debugger_interaction::capture(debugger_interaction::kind_t::bookmark,
					item_address, 0, row, 0, 0,
					label_it != labels_snapshot.end() ? label_it->second : std::string());
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context,
				ui.bookmark_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##bm_row", ImVec2(w - 18.f - 84.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, i, 1.f, a);

			char ibuf[8], abuf[20];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
			dl->AddText(body_font, body_font_size, ImVec2(ox + 8.f, ry + 7.f),
			            with_a(t.text_dim, a), ibuf);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 46.f, ry + 7.f),
			            with_a(t.text_address, a), abuf);

			auto it = labels_snapshot.find(addr);
			if (it != labels_snapshot.end())
				dl->AddText(body_font, body_font_size, ImVec2(ox + 246.f, ry + 7.f),
				            with_a(t.text_primary, a), it->second.c_str());
			const std::string bookmark_label = it != labels_snapshot.end() ? it->second : std::string();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("bookmark", "debugger-bookmark-row",
				debugger_interaction::capture(
					debugger_interaction::kind_t::bookmark, addr, 0, i,
					0, 0, bookmark_label));
#endif

			float btn_x = ox + w - 84.f;
			float btn_w = 64.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
			ImGui::PushID(i + 0x50000);
			bool rm = aida::ui::button("Remove", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(btn_w, btn_h));
			ImGui::PopID();
			if (rm) {
				diag::log_tagged_fmt("bookmarks",
					"bookmark_remove_review addr=0x%llx",
					static_cast<unsigned long long>(addr));
				request_context_mutation(pending_context_mutation_t::remove_bookmark,
					debugger_interaction::capture(debugger_interaction::kind_t::bookmark,
						addr, 0, i, 0, 0, bookmark_label));
			}

			if (clicked) {
				ui.bookmark_panel.selected = i;
				select_debugger_row(row_context, total_n, context_for_row, false);
			}
			if (dclicked) {
				diag::log_tagged_fmt("dbg_view", "bookmark double-click: jump to addr=0x%llX", (unsigned long long)addr);
				jump_to_disasm(addr);
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(row_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No bookmarks";
		es.body  = "Add a bookmark by entering an address above.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_handles(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] handles enter ok=1");
		}
	}

	float bar_h = 40.f;
	bool attached_handles = driver_bridge::attached_pid() != 0;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##h_actions");
	bool refresh_clicked = aida::ui::button("Enumerate Handles",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		!attached_handles);
	if (refresh_clicked) {
		diag::log_tagged_critical_fmt("handles",
			"handles_enumerate_request attached_pid=%u",
			static_cast<unsigned>(driver_bridge::attached_pid()));
		diag::log_tagged("dbg_audit",
			"[dbg_audit] handles enumerate ok=1");
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "debugger";
		sub.label = "debugger.handles_enumerate";
		sub.thread_class = "debugger_refresh";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		const std::uint32_t target_pid = driver_bridge::attached_pid();
		const std::uint64_t target_generation = debugger_interaction::current_stop_generation();
		sub.target_pid = target_pid;
		sub.generation = target_generation;
		sub.body = [target_pid, target_generation]() {
			if (driver_bridge::attached_pid() != target_pid ||
				debugger_interaction::current_stop_generation() != target_generation)
				return;
			debugger_engine::enumerate_handles();
			size_t n = 0;
			{
				std::lock_guard<std::mutex> lk(
					debugger_engine::g_state.handle_mutex);
				n = debugger_engine::g_state.handles.size();
			}
			diag::log_tagged_fmt("handles",
				"handles_enumerate_done count=%zu", n);
		};
		const auto submitted = submit_owned_debugger_task(std::move(sub),
			"view.debug.handles", "debugger.handles_enumerate",
			"Enumerate target handles", false);
		if (!submitted.submitted)
			diag::log_tagged("handles", "handles_enumerate_post_failed");
	}
	ImGui::PopID();

	if (!attached_handles) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + bar_h + (h - bar_h) * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to enumerate or close its kernel handles.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Handle", 110.f}, {"Type", 160.f}, {"Access", 110.f}, {"Name", 250.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 5, a);
	}

	static render_snapshot_cache_t<debugger_engine::handle_info_t> snapshot_cache;
	const auto& snapshot = refresh_render_snapshot(snapshot_cache, st.handle_mutex, st.handles,
		st.handles_generation, "handles");
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##h_list");
	ImGui::BeginChild("##h_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int hi = clipper.DisplayStart; hi < clipper.DisplayEnd; ++hi) {
			float ry = content_y + static_cast<float>(hi) * ROW_HEIGHT - ImGui::GetScrollY();
			auto& he = snapshot[static_cast<size_t>(hi)];
			const auto context_for_row = [&](int row) {
				const auto& item = snapshot[static_cast<size_t>(row)];
				return debugger_interaction::capture(debugger_interaction::kind_t::handle,
					0, item.handle, row, 0, 0, item.name, item.type_name);
			};
			const auto row_context = context_for_row(hi);
			bool sel = debugger_row_selected(row_context,
				ui.handle_panel.selected == hi);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(hi);
			ImGui::InvisibleButton("##h_row", ImVec2(w - 18.f - 90.f, ROW_HEIGHT));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			register_studio_debug_entity("handle", "debugger-handle-row",
				debugger_interaction::capture(debugger_interaction::kind_t::handle,
					0, he.handle, hi, 0, 0, he.name, he.type_name));
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, hi, 1.f, a);

			char hbuf[12];
			std::snprintf(hbuf, sizeof(hbuf), "0x%X", static_cast<unsigned>(he.handle));
			dl->AddText(code_font, code_font_size, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_primary, a), hbuf);

			ImU32 type_col = handle_type_color(he.type_name, t);
			ImVec2 ts = body_font->CalcTextSizeA(body_font_size, FLT_MAX, 0.f, he.type_name.c_str());
			float bw = ts.x + 12.f;
			float bh = 16.f;
			float bx = ox + 120.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * 0.85f), 4.f);
			dl->AddText(body_font, body_font_size,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				with_a(IM_COL32(255, 255, 255, 245), a),
				he.type_name.c_str());

			char acc_buf[16];
			std::snprintf(acc_buf, sizeof(acc_buf), "0x%08X", he.access);
			dl->AddText(code_font, code_font_size, ImVec2(ox + 280.f, ry + 5.f),
			            with_a(t.text_secondary, a), acc_buf);

			float name_clip_w = w - 484.f;
			if (name_clip_w < 80.f) name_clip_w = 80.f;
			dl->PushClipRect(ImVec2(ox + 390.f, ry),
				ImVec2(ox + 390.f + name_clip_w, ry + ROW_HEIGHT), true);
			dl->AddText(body_font, body_font_size, ImVec2(ox + 390.f, ry + 5.f),
			            with_a(t.text_primary, a), he.name.c_str());
			dl->PopClipRect();

			float hbtn_h = 18.f;
			float hbtn_y = ry + (ROW_HEIGHT - hbtn_h) * 0.5f;
			float hbtn_x = ox + w - 78.f;
			ImGui::SetCursorScreenPos(ImVec2(hbtn_x, hbtn_y));
			ImGui::PushID(hi + 0xC3000);
			bool close_clicked = aida::ui::button("Close",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(60.f, hbtn_h));
			ImGui::PopID();
			if (close_clicked) {
				ui.handle_close_idx = hi;
				ui.handle_close_value = he.handle;
				ui.handle_close_type = he.type_name;
				ui.handle_close_name = he.name;
				ui.handle_close_context = debugger_interaction::capture(
					debugger_interaction::kind_t::handle, 0, he.handle, hi, 0, 0,
					he.name, he.type_name);
				ui.handle_close_popup_open = true;
				diag::log_tagged("dbg_audit",
					"[dbg_audit] handles close_request ok=1");
			}

			if (clicked) {
				ui.handle_panel.selected = hi;
				select_debugger_row(row_context, total_n, context_for_row, false);
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				select_debugger_row(row_context, total_n, context_for_row, true);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::key;
		es.title = "No handles enumerated";
		es.body  = "Click Enumerate Handles to capture the target's handle table.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.handle_close_popup_open) {
		ImGui::OpenPopup("Close Handle##hd");
		ui.handle_close_popup_open = false;
	}
	if (aida::ui::design::begin_dialog_exact("Close Handle##hd",
		ImVec2(580.0f, 380.0f), ImVec2(400.0f, 280.0f))) {
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Close Handle", "Cancel");
		aida::ui::design::begin_dialog_body("debugger_close_handle_body", footer_height);
		ImGui::TextWrapped(
			"Close handle 0x%X (%s) in target process?\nName: %s",
			static_cast<unsigned>(ui.handle_close_value),
			ui.handle_close_type.c_str(),
			ui.handle_close_name.empty() ? "(unnamed)" : ui.handle_close_name.c_str());
		const auto close_gate = debugger_interaction::evaluate(
			debugger_interaction::capability_t::close_handle,
			ui.handle_close_context);
		if (!close_gate.enabled)
			ImGui::TextWrapped("Unavailable: %s", close_gate.disabled_reason);
		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"debugger_close_handle_footer", "Close Handle", close_gate.enabled,
			true, "Cancel");
		if (footer.confirmed) {
			const std::uint64_t value = ui.handle_close_value;
			const auto context = ui.handle_close_context;
			static_cast<void>(queue_debugger_mutation("Close target handle",
				"debugger.handle_close", context, [context, value]() {
					mutation_result_t result;
					result.ok = driver_bridge::close_process_handle(context.target_pid, value);
					result.verified = result.ok;
					if (result.ok)
						debugger_engine::enumerate_handles();
					else
						result.detail = "Kernel handle close failed: " + driver_bridge::last_error();
					return result;
				}));
			ui.handle_close_idx = -1;
			ui.handle_close_value = 0;
			ui.handle_close_type.clear();
			ui.handle_close_name.clear();
			ImGui::CloseCurrentPopup();
		}
		if (footer.cancelled) {
			ui.handle_close_idx = -1;
			ui.handle_close_value = 0;
			ui.handle_close_type.clear();
			ui.handle_close_name.clear();
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}


static bool request_code_cave_search() {
	if (g_code_cave_search.pending.load(std::memory_order_acquire)) return false;
	const std::size_t minimum = static_cast<std::size_t>(
		std::strtoull(g_code_cave_search.minimum_size, nullptr, 10));
	if (minimum == 0 || minimum > (1U << 20U)) {
		g_code_cave_search.dialog_error =
			"Code-cave minimum must be between 1 byte and 1 MiB.";
		toast_notification::push(g_code_cave_search.dialog_error,
			toast_notification::toast_type_t::warning);
		return false;
	}
	const std::string filter(g_code_cave_search.module_filter);
	const std::uint32_t target_pid = driver_bridge::attached_pid();
	const std::uint64_t target_generation = debugger_interaction::current_stop_generation();
	if (target_pid == 0 || debugger_engine::g_state.status.load(
			std::memory_order_acquire) != debugger_engine::dbg_status_t::paused) {
		g_code_cave_search.dialog_error = "Attach a paused debugger target before searching for code caves.";
		return false;
	}
	g_code_cave_search.dialog_error.clear();
	g_code_cave_search.pending.store(true, std::memory_order_release);
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "Find code caves";
	submission.thread_class = "debugger_memory_scan";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.target_pid = target_pid;
	submission.generation = target_generation;
	submission.ui_access_policy = "post_completion_only";
	submission.failure_policy = "fail_closed";
	submission.body = [minimum, filter, target_pid, target_generation]() {
		struct pending_reset_t {
			~pending_reset_t() {
				g_code_cave_search.pending.store(false, std::memory_order_release);
			}
		} pending_reset;
		std::vector<code_cave_result_t> results;
		std::string error;
		bool terminal_failure = false;
		try {
			if (driver_bridge::attached_pid() != target_pid ||
				debugger_engine::g_state.status.load(std::memory_order_acquire) !=
					debugger_engine::dbg_status_t::paused ||
				debugger_interaction::current_stop_generation() != target_generation) {
				error = "The target changed before code-cave discovery started.";
				terminal_failure = true;
			} else {
				auto modules = driver_bridge::enumerate_modules();
				std::uint64_t scan_bytes = 0;
				for (const auto& module : modules) {
					if (!filter.empty()) {
						std::string candidate = module.name;
						std::string needle = filter;
						std::transform(candidate.begin(), candidate.end(), candidate.begin(),
							[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
						std::transform(needle.begin(), needle.end(), needle.begin(),
							[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
						if (candidate.find(needle) == std::string::npos) continue;
					}
					constexpr std::uint64_t scan_limit = 512ULL * 1024ULL * 1024ULL;
					if (module.size > scan_limit - scan_bytes) {
						error = "Matching modules exceed the 512 MiB code-cave scan bound; narrow the module filter.";
						break;
					}
					scan_bytes += module.size;
					const auto caves = code_patcher::find_code_caves(module.base, module.size, minimum);
					for (const auto& cave : caves) {
						if (results.size() >= 10000U) {
							error = "Code-cave results were truncated at 10,000 entries.";
							break;
						}
						results.push_back({cave.address, static_cast<std::size_t>(cave.size), cave.module_name});
					}
					if (results.size() >= 10000U) break;
				}
			}
		} catch (const std::exception& exception) {
			error = std::string("Code-cave discovery failed: ") + exception.what();
			terminal_failure = true;
		} catch (...) {
			error = "Code-cave discovery failed with an unknown error.";
			terminal_failure = true;
		}
		if (driver_bridge::attached_pid() != target_pid ||
			debugger_engine::g_state.status.load(std::memory_order_acquire) !=
				debugger_engine::dbg_status_t::paused ||
			debugger_interaction::current_stop_generation() != target_generation) {
			results.clear();
			error = "The target changed before code-cave discovery completed.";
			terminal_failure = true;
		}
		try {
			auto publication = std::make_shared<code_cave_publication_t>();
			publication->generation = g_code_cave_publication_sequence.fetch_add(
				1, std::memory_order_acq_rel);
			publication->target_pid = target_pid;
			publication->target_stop_generation = target_generation;
			publication->results = std::move(results);
			publication->detail = error;
			std::atomic_store_explicit(&g_code_cave_publication,
				std::shared_ptr<const code_cave_publication_t>(std::move(publication)),
				std::memory_order_release);
		} catch (const std::exception& exception) {
			error = std::string("Code-cave result publication failed: ") + exception.what();
			terminal_failure = true;
		} catch (...) {
			error = "Code-cave result publication failed with an unknown error.";
			terminal_failure = true;
		}
		bool posted = false;
		try {
			posted = post_debugger_ui([detail = error]() {
				if (!detail.empty())
					toast_notification::push(detail, toast_notification::toast_type_t::warning);
			}, "code_cave_completion");
		} catch (const std::exception& exception) {
			error = std::string("Code-cave completion publication failed: ") + exception.what();
			terminal_failure = true;
		} catch (...) {
			error = "Code-cave completion publication failed with an unknown error.";
			terminal_failure = true;
		}
		if (!posted) {
			if (error.empty())
				error = "Code-cave completion could not be published to the UI thread.";
			terminal_failure = true;
		}
		if (terminal_failure)
			throw std::runtime_error(error.empty()
				? "Code-cave discovery failed without a diagnostic." : error);
	};
	const auto submitted = submit_owned_debugger_task(std::move(submission),
		"view.debug.patches", "debugger.code_caves", "Find code caves", false);
	if (!submitted.submitted) {
		g_code_cave_search.pending.store(false, std::memory_order_release);
		g_code_cave_search.dialog_error = "Code-cave search queue rejected the task: " +
			submitted.reject_reason;
		toast_notification::push(g_code_cave_search.dialog_error,
			toast_notification::toast_type_t::error);
		return false;
	}
	return true;
}

static bool request_patchset_save(std::string* error) {
	char path_buf[MAX_PATH] = "patches.json";
	static const char k_patchset_filter[] =
		"JSON (*.json)\0*.json\0Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_save_file_dialog(g_hwnd, "Save Patchset",
			k_patchset_filter, "json", path_buf, sizeof(path_buf),
			"debugger_view::patches_save"))
		return true;
	const std::string destination(path_buf);
	auto cancelled = std::make_shared<std::atomic<bool>>(false);
	auto save_result = std::make_shared<mutation_result_t>();
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "Save patchset";
	submission.thread_class = "debugger_export";
	submission.domain = aida::infra::executor::domain_t::diagnostics;
	submission.priority = 3;
	submission.cancel_hook = [cancelled]() {
		cancelled->store(true, std::memory_order_release);
	};
	submission.ui_access_policy = "post_completion_only";
	submission.body = [destination, cancelled, save_result]() {
		std::vector<code_patcher::patch_entry_t> patches;
		{
			std::lock_guard<std::mutex> lock(code_patcher::g_state.mtx);
			if (code_patcher::g_state.patches.size() > 4096U)
				save_result->detail = "Patchset exceeds the 4,096-entry export bound.";
			else
				patches = code_patcher::g_state.patches;
		}
		if (save_result->detail.empty() && patches.empty())
			save_result->detail = "No patches to save.";
		std::string encoded;
		if (save_result->detail.empty()) {
			encoded = "{\n  \"patches\": [\n";
			for (size_t i = 0; i < patches.size(); ++i) {
				if ((i & 0x3fU) == 0U && cancelled->load(std::memory_order_acquire)) {
					save_result->detail = "Patchset export cancelled.";
					break;
				}
				const auto& p = patches[i];
				char line[256];
				std::snprintf(line, sizeof(line),
					"    {\n      \"index\": %zu,\n"
					"      \"address\": \"0x%016llX\",\n"
					"      \"timestamp\": %lld,\n"
					"      \"active\": %s,\n"
					"      \"description\": \"",
					i, static_cast<unsigned long long>(p.address),
					static_cast<long long>(p.timestamp), p.active ? "true" : "false");
				encoded.append(line);
				for (char c : p.description) {
					if (c == '"' || c == '\\') encoded.push_back('\\');
					encoded.push_back(c == '\n' || c == '\r' ? ' ' : c);
				}
				encoded.append("\",\n      \"original\": \"");
				encoded.append(code_patcher::format_bytes(p.original_bytes));
				encoded.append("\",\n      \"patched\": \"");
				encoded.append(code_patcher::format_bytes(p.patched_bytes));
				encoded.append("\"\n    }");
				if (i + 1 < patches.size()) encoded.push_back(',');
				encoded.push_back('\n');
				if (encoded.size() > 16U * 1024U * 1024U) {
					save_result->detail = "Encoded patchset exceeds the 16 MiB export bound.";
					break;
				}
			}
			if (save_result->detail.empty()) encoded.append("  ]\n}\n");
		}
		if (save_result->detail.empty())
			save_result->ok = save_result->verified = write_file_atomic_exact(destination,
				encoded.data(), encoded.size(), save_result->detail);
		const bool posted = post_debugger_ui([save_result, count = patches.size()]() {
			toast_notification::push(save_result->verified
				? "Saved " + std::to_string(count) + " patches." : save_result->detail,
				save_result->verified ? toast_notification::toast_type_t::success
					: toast_notification::toast_type_t::error);
		}, "patchset_save_completion");
		if (!posted)
			throw std::runtime_error("Patchset-export completion could not be published to the UI thread");
		if (!save_result->verified)
			throw std::runtime_error(save_result->detail.empty()
				? "Patchset export failed" : save_result->detail);
	};
	const auto submitted = submit_owned_debugger_task(std::move(submission),
		"view.debug.patches", "debugger.patchset_save", "Save patchset", true);
	if (!submitted.submitted) {
		if (error) *error = "Patchset export queue rejected the task: " + submitted.reject_reason;
		return false;
	}
	return true;
}

bool dispatch_patch_panel_command(patch_panel_command_t command, std::string* error) {
	const auto snapshot = code_patcher::published_snapshot();
	if (!snapshot) {
		if (error) *error = "The immutable Patches publication is unavailable";
		return false;
	}
	switch (command) {
		case patch_panel_command_t::stage: {
			const auto registers = debugger_engine::cached_registers();
			return stage_patch_review(registers.rip, 0, "Manual debugger patch", error);
		}
		case patch_panel_command_t::find_code_caves:
			g_code_cave_search.open = true;
			return true;
		case patch_panel_command_t::revert_all:
			request_context_mutation(pending_context_mutation_t::revert_all_patches,
				debugger_interaction::capture(debugger_interaction::kind_t::patch,
					0, snapshot->generation));
			return true;
		case patch_panel_command_t::save_patchset:
			return request_patchset_save(error);
	}
	if (error) *error = "Unknown Patches panel action";
	return false;
}

static void render_code_cave_dialog() {
	if (g_code_cave_search.open) {
		aida::ui::design::open_dialog("debugger.code_caves", "Find Code Caves");
		g_code_cave_search.open = false;
	}
	if (!aida::ui::design::begin_dialog("debugger.code_caves", "Find Code Caves",
			ImVec2(760.f, 620.f), ImVec2(420.f, 360.f))) return;
	const auto publication = std::atomic_load_explicit(
		&g_code_cave_publication, std::memory_order_acquire);
	static const code_cave_publication_t empty_publication;
	const auto& snapshot = publication ? *publication : empty_publication;
	if (snapshot.generation != g_code_cave_search.visible_generation) {
		g_code_cave_search.visible_generation = snapshot.generation;
		g_code_cave_search.selected = -1;
		g_code_cave_search.dialog_error.clear();
	}
	const bool pending = g_code_cave_search.pending.load(std::memory_order_acquire);
	const bool target_current = snapshot.target_pid != 0 &&
		driver_bridge::attached_pid() == snapshot.target_pid &&
		debugger_interaction::current_stop_generation() == snapshot.target_stop_generation &&
		debugger_engine::g_state.status.load(std::memory_order_acquire) ==
			debugger_engine::dbg_status_t::paused;
    const auto dialog_metrics = aida::ui::design::metrics();
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Stage Patch Review", "Close");
    aida::ui::design::begin_dialog_body("code_cave_body", footer_height);
	ImGui::TextWrapped("Discover bounded 00/CC filler runs in loaded modules. Every result retains the exact process and debugger stop generation that produced it.");
	ImGui::SetNextItemWidth((std::min)(aida::ui::scale_px(360.f, dialog_metrics.scale),
		ImGui::GetContentRegionAvail().x));
	ImGui::InputTextWithHint("Module filter##caves", "module name (optional)",
		g_code_cave_search.module_filter, sizeof(g_code_cave_search.module_filter));
	ImGui::SetNextItemWidth((std::min)(aida::ui::scale_px(180.f, dialog_metrics.scale),
		ImGui::GetContentRegionAvail().x));
	ImGui::InputText("Minimum bytes##caves", g_code_cave_search.minimum_size,
		sizeof(g_code_cave_search.minimum_size), ImGuiInputTextFlags_CharsDecimal);
	if (pending) ImGui::BeginDisabled();
	if (aida::ui::button(pending ? "Searching..." : "Search",
			aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
			ImVec2(aida::ui::scale_px(120.f, dialog_metrics.scale), 0.f)))
		static_cast<void>(request_code_cave_search());
	if (pending) ImGui::EndDisabled();
	if (snapshot.generation != 0)
		ImGui::TextDisabled("PID %u  |  stop generation %llu  |  publication %llu",
			snapshot.target_pid,
			static_cast<unsigned long long>(snapshot.target_stop_generation),
			static_cast<unsigned long long>(snapshot.generation));
	if (snapshot.generation != 0 && !target_current)
		aida::ui::inline_notice("code_cave_stale", "Code-cave results are stale",
			"The attached process or debugger stop generation changed. Search again before staging a patch review.",
			aida::ui::status_kind_t::warning);
	if (!snapshot.detail.empty())
		aida::ui::inline_notice("code_cave_detail", "Code-cave search detail",
			snapshot.detail.c_str(), aida::ui::status_kind_t::warning);
	if (!g_code_cave_search.dialog_error.empty())
		aida::ui::inline_notice("code_cave_error", "Code-cave workflow error",
			g_code_cave_search.dialog_error.c_str(), aida::ui::status_kind_t::error);
	ImGui::Separator();
	ImGui::Text("Results: %zu", snapshot.results.size());
	const float table_height = (std::max)(aida::ui::scale_px(120.f, dialog_metrics.scale),
		ImGui::GetContentRegionAvail().y);
	if (ImGui::BeginTable("##code_cave_results", 3,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_Resizable, ImVec2(-1.f, table_height))) {
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
			aida::ui::scale_px(180.f, dialog_metrics.scale));
		ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed,
			aida::ui::scale_px(90.f, dialog_metrics.scale));
		ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(snapshot.results.size()));
		while (clipper.Step())
			for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
				const auto& cave = snapshot.results[static_cast<std::size_t>(index)];
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				char label[64];
				std::snprintf(label, sizeof(label), "0x%016llX##cave%d",
					static_cast<unsigned long long>(cave.address), index);
				if (ImGui::Selectable(label, g_code_cave_search.selected == index,
					ImGuiSelectableFlags_SpanAllColumns))
					g_code_cave_search.selected = index;
				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%zu", cave.size);
				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(cave.module.c_str());
			}
		ImGui::EndTable();
	}
    aida::ui::design::end_dialog_body();
	const bool has_selection = g_code_cave_search.selected >= 0 &&
		g_code_cave_search.selected < static_cast<int>(snapshot.results.size());
	const auto footer = aida::ui::design::dialog_footer("code_cave_footer",
		"Stage Patch Review", has_selection && target_current && !pending, false, "Close");
	if (footer.confirmed) {
		const auto current = std::atomic_load_explicit(
			&g_code_cave_publication, std::memory_order_acquire);
		if (!current || current->generation != snapshot.generation ||
			current->target_pid != snapshot.target_pid ||
			current->target_stop_generation != snapshot.target_stop_generation ||
			driver_bridge::attached_pid() != snapshot.target_pid ||
			debugger_interaction::current_stop_generation() != snapshot.target_stop_generation ||
			debugger_engine::g_state.status.load(std::memory_order_acquire) !=
				debugger_engine::dbg_status_t::paused ||
			g_code_cave_search.selected < 0 ||
			g_code_cave_search.selected >= static_cast<int>(current->results.size())) {
			g_code_cave_search.dialog_error =
				"The exact process, stop generation, publication, or selected cave changed before staging.";
		} else {
			const auto& cave = current->results[
				static_cast<std::size_t>(g_code_cave_search.selected)];
			std::string error;
			if (stage_patch_review(cave.address, cave.size,
					"Code cave patch in " + cave.module, &error)) {
				g_code_cave_search.dialog_error.clear();
				ImGui::CloseCurrentPopup();
			} else {
				g_code_cave_search.dialog_error = error.empty()
					? "The exact code-cave patch review could not be staged." : std::move(error);
			}
		}
	}
	if (footer.cancelled) {
		g_code_cave_search.dialog_error.clear();
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

static void render_patches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	(void)t;
	const auto snapshot = code_patcher::published_snapshot();
	static const code_patcher::patch_snapshot_t empty_patch_snapshot;
	const auto& publication = snapshot ? *snapshot : empty_patch_snapshot;
	const auto& patch_rows = publication.rows;
	const std::uint64_t snapshot_generation = publication.generation;
	const std::uint64_t publication_failure_generation =
		code_patcher::g_state.publication_failure_generation.load(std::memory_order_acquire);
	if (!snapshot || publication_failure_generation != 0)
		aida::ui::inline_notice("debugger_patch_publication_failure",
			"Patch list publication unavailable",
			"The authoritative patch state was preserved, but the immutable UI snapshot could not be refreshed. Patch actions remain disabled until a later publication succeeds.",
			aida::ui::status_kind_t::error);

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			diag::log_tagged("dbg_audit",
				"[dbg_audit] patches enter ok=1");
		}
	}

	const auto toolbar_metrics = aida::ui::design::metrics();
	const float toolbar_pad = (std::max)(6.f, toolbar_metrics.spacing_sm);
	const float bar_h = (std::max)(40.f,
		toolbar_metrics.control_height + toolbar_pad * 2.f);
	ImGui::SetCursorScreenPos(ImVec2(ox + toolbar_pad, oy + toolbar_pad));
	const bool selected_available = ui.patches_panel.selected >= 0 &&
		ui.patches_panel.selected < static_cast<int>(patch_rows.size());
	static aida::ui::application_ui::retained_entity_context_t selected_patch_context;
	static debugger_interaction::context_t selected_patch_debugger_context;
	static std::uint64_t selected_patch_context_generation = 0;
	static std::uint64_t selected_patch_stop_generation = 0;
	static std::uint32_t selected_patch_target_pid = 0;
	static int selected_patch_context_index = -1;
	if (selected_available) {
		const auto& selected_patch =
			patch_rows[static_cast<std::size_t>(ui.patches_panel.selected)];
		const std::uint64_t stop_generation =
			debugger_interaction::current_stop_generation();
		const std::uint32_t target_pid = driver_bridge::attached_pid();
		if (selected_patch_context_generation != snapshot_generation ||
			selected_patch_stop_generation != stop_generation ||
			selected_patch_target_pid != target_pid ||
			selected_patch_context_index != ui.patches_panel.selected) {
			selected_patch_debugger_context =
				debugger_interaction::capture(debugger_interaction::kind_t::patch,
					selected_patch.address, snapshot_generation, ui.patches_panel.selected, 0,
					static_cast<std::uint64_t>(selected_patch.patched_size),
					selected_patch.description);
			selected_patch_context =
				build_debugger_entity_actions(selected_patch_debugger_context, false);
			selected_patch_context_generation = snapshot_generation;
			selected_patch_stop_generation = stop_generation;
			selected_patch_target_pid = target_pid;
			selected_patch_context_index = ui.patches_panel.selected;
		}
	} else {
		selected_patch_context_generation = 0;
		selected_patch_stop_generation = 0;
		selected_patch_target_pid = 0;
		selected_patch_context_index = -1;
	}
	static constexpr const char* patch_action_ids[] = {
		"debugger.patch.apply", "debugger.patch.stage", "debugger.patch.find_caves",
		"debugger.patch.revert_all", "debugger.patch.remove", "debugger.patch.save_set"
	};
	std::array<aida::ui::application_ui::action_presentation_t, std::size(patch_action_ids)>
		patch_presentations;
	std::array<std::string, std::size(patch_action_ids)> patch_tooltips;
	for (std::size_t index = 0; index < std::size(patch_action_ids); ++index) {
		const bool retained_selection_action = index == 0 || index == 4;
		patch_presentations[index] = retained_selection_action && selected_available
			? aida::ui::application_ui::present_retained_entity_action(
				patch_action_ids[index], selected_patch_context)
			: aida::ui::application_ui::present_action(patch_action_ids[index]);
		patch_tooltips[index] = patch_presentations[index].description;
		if (!patch_presentations[index].enabled &&
			!patch_presentations[index].disabled_reason.empty()) {
			patch_tooltips[index].append("\n");
			patch_tooltips[index].append(patch_presentations[index].disabled_reason);
		}
	}
	const aida::ui::design::action_t patch_actions[] = {
		{patch_action_ids[0], "Apply Selected", "Apply", patch_tooltips[0].c_str(),
			patch_presentations[0].shortcut.c_str(),
			"Writes the selected bytes to the attached process after confirmation and readback.",
			aida::ui::button_kind_t::primary,
			selected_available && patch_presentations[0].enabled, true, true},
		{patch_action_ids[1], "Stage Patch...", "Stage", patch_tooltips[1].c_str(),
			patch_presentations[1].shortcut.c_str(), nullptr,
			aida::ui::button_kind_t::secondary, patch_presentations[1].enabled, false, true},
		{patch_action_ids[2], "Find Caves...", "Caves", patch_tooltips[2].c_str(),
			patch_presentations[2].shortcut.c_str(), nullptr,
			aida::ui::button_kind_t::secondary, patch_presentations[2].enabled, false, true},
		{patch_action_ids[3], "Revert All", "Revert", patch_tooltips[3].c_str(),
			patch_presentations[3].shortcut.c_str(),
			"Restores captured original bytes only after explicit confirmation and readback.",
			aida::ui::button_kind_t::destructive, patch_presentations[3].enabled, false, true},
		{patch_action_ids[4], "Remove Selected", "Remove", patch_tooltips[4].c_str(),
			patch_presentations[4].shortcut.c_str(), nullptr,
			aida::ui::button_kind_t::secondary,
			selected_available && patch_presentations[4].enabled, false, true},
		{patch_action_ids[5], "Save Patchset", "Save", patch_tooltips[5].c_str(),
			patch_presentations[5].shortcut.c_str(), nullptr,
			aida::ui::button_kind_t::secondary, patch_presentations[5].enabled, false, true}
	};
	const auto patch_action = aida::ui::design::render_toolbar(
		"debugger.patches.actions", patch_actions, std::size(patch_actions),
		(std::max)(1.f, w - toolbar_pad * 2.f));
	const std::string_view invoked = patch_action.invoked && patch_action.id
		? std::string_view(patch_action.id) : std::string_view();
	if (!invoked.empty()) {
		const bool retained_selection_action = invoked == "debugger.patch.apply" ||
			invoked == "debugger.patch.remove";
		if (retained_selection_action && selected_available)
			debugger_interaction::select(selected_patch_debugger_context);
		const auto result = retained_selection_action && selected_available
			? aida::ui::application_ui::execute_retained_entity_action(
				patch_action.id, aida::ui::action_invocation_source_t::toolbar,
				selected_patch_context)
			: aida::ui::application_ui::execute_action(patch_action.id,
				aida::ui::action_invocation_source_t::toolbar);
		static_cast<void>(result);
	}
	const bool compact_rows = w < 820.f;
	const float patch_row_height = compact_rows
		? (std::max)(42.f, ROW_HEIGHT + 16.f) : ROW_HEIGHT;
	float table_y = oy + bar_h;
	if (compact_rows) {
		ui_anim::table_col_t cols[] = {
			{"Patch", (std::max)(1.f, w - 66.f)}, {"State", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 2, a);
	} else {
		const float description_column_width = (std::max)(170.f, w - 650.f);
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"Address", 164.f}, {"Original", 200.f},
			{"Patched", 200.f}, {"Description", description_column_width},
			{"Active", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 6, a);
	}

	int total_n = static_cast<int>(patch_rows.size());
	float content_y = table_y + HEADER_H;
	float visible_h = (std::max)(1.f, h - bar_h - HEADER_H);

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##p_list");
	ImGui::BeginChild("##p_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	ImGuiListClipper clipper;
	clipper.Begin(total_n, patch_row_height);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * patch_row_height - ImGui::GetScrollY();
			const auto& p = patch_rows[static_cast<size_t>(i)];
			const auto context_for_row = [&](int row) {
				const auto& item = patch_rows[static_cast<size_t>(row)];
				return debugger_interaction::capture(debugger_interaction::kind_t::patch,
					item.address, snapshot_generation, row, 0,
					static_cast<uint64_t>(item.patched_size), item.description);
			};
			const auto row_context = context_for_row(i);
			bool sel = debugger_row_selected(row_context,
				ui.patches_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##p_row", ImVec2((std::max)(1.f, w - 62.f),
				patch_row_height));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const auto patch_semantic_context = debugger_interaction::capture(
				debugger_interaction::kind_t::patch, p.address, snapshot_generation,
				i, 0, static_cast<std::uint64_t>(p.patched_size), p.description);
			const std::string patch_semantic_id = studio_debug_entity_id(
				"patch", patch_semantic_context);
			aida::preview::semantics::register_last_item(
				patch_semantic_id, "debugger-patch-row", false, false,
				"aida.dock-window.view.debug.patches");
#endif
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, patch_row_height, sel, hov, i, 1.f, a);

			char ibuf[8], abuf[20];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, p.address);
			ImU32 pc = p.active ? t.success : t.warning;
			bool active_state = p.active;
			float track_w = 28.f;
			float track_h = 14.f;
			float tx = ox + w - track_w - 16.f;
			float ty = ry + (patch_row_height - track_h) * 0.5f;
			const float text_right = (std::max)(ox + 1.f, tx - 8.f);
			if (compact_rows) {
				const ImVec4 top_clip(ox, ry, text_right, ry + patch_row_height * 0.5f);
				dl->AddText(body_font, body_font_size, ImVec2(ox + 8.f, ry + 3.f),
					with_a(t.text_dim, a), ibuf, nullptr, 0.f, &top_clip);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 34.f, ry + 3.f),
					with_a(t.text_address, a), abuf, nullptr, 0.f, &top_clip);
				const float bytes_x = ox + 34.f;
				const float bytes_width = (std::max)(1.f, text_right - bytes_x);
				const float midpoint = bytes_x + bytes_width * 0.5f;
				const ImVec4 original_clip(bytes_x, ry + 20.f,
					(std::max)(bytes_x + 1.f, midpoint - 10.f), ry + patch_row_height);
				const ImVec4 patched_clip(midpoint + 10.f, ry + 20.f,
					text_right, ry + patch_row_height);
				const ImVec4 transition_clip(midpoint - 6.f, ry + 20.f,
					midpoint + 8.f, ry + patch_row_height);
				dl->AddText(code_font, code_font_size, ImVec2(bytes_x, ry + 22.f),
					with_a(t.text_secondary, a), p.original.c_str(), nullptr, 0.f,
					&original_clip);
				dl->AddText(body_font, body_font_size, ImVec2(midpoint - 5.f, ry + 22.f),
					with_a(t.text_dim, a), ">", nullptr, 0.f, &transition_clip);
				dl->AddText(code_font, code_font_size, ImVec2(midpoint + 10.f, ry + 22.f),
					with_a(pc, a), p.patched.c_str(), nullptr, 0.f, &patched_clip);
			} else {
				dl->AddText(body_font, body_font_size, ImVec2(ox + 8.f, ry + 5.f),
					with_a(t.text_dim, a), ibuf);
				dl->AddText(code_font, code_font_size, ImVec2(ox + 36.f, ry + 5.f),
					with_a(t.text_address, a), abuf);
				const ImVec4 original_clip(ox + 196.f, ry, ox + 396.f,
					ry + patch_row_height);
				dl->PushClipRect(ImVec2(original_clip.x, original_clip.y),
					ImVec2(original_clip.z, original_clip.w), true);
				ImVec2 osz = code_font->CalcTextSizeA(
					code_font_size, FLT_MAX, 0.f, p.original.c_str());
				float bx = ox + 200.f;
				float by = ry + 3.f;
				dl->AddRectFilled(ImVec2(bx - 4.f, by),
					ImVec2(bx + osz.x + 8.f, by + 16.f),
					with_a(t.text_dim, a * 0.18f), 4.f);
				dl->AddText(code_font, code_font_size, ImVec2(bx, ry + 5.f),
					with_a(t.text_secondary, a), p.original.c_str());
				dl->PopClipRect();
				const ImVec4 patched_clip(ox + 396.f, ry, ox + 596.f,
					ry + patch_row_height);
				dl->PushClipRect(ImVec2(patched_clip.x, patched_clip.y),
					ImVec2(patched_clip.z, patched_clip.w), true);
				ImVec2 psz = code_font->CalcTextSizeA(
					code_font_size, FLT_MAX, 0.f, p.patched.c_str());
				float bx2 = ox + 400.f;
				dl->AddRectFilled(ImVec2(bx2 - 4.f, by),
					ImVec2(bx2 + psz.x + 8.f, by + 16.f),
					with_a(pc, a * 0.20f), 4.f);
				dl->AddText(code_font, code_font_size, ImVec2(bx2, ry + 5.f),
					with_a(pc, a), p.patched.c_str());
				dl->PopClipRect();
				const ImVec4 description_clip(ox + 596.f, ry,
					text_right, ry + patch_row_height);
				dl->AddText(body_font, body_font_size, ImVec2(ox + 600.f, ry + 5.f),
					with_a(t.text_primary, a), p.description.c_str(), nullptr, 0.f,
					&description_clip);
			}
			ImGui::SetCursorScreenPos(ImVec2(tx, ty));
			ImGui::PushID(i + 0x70000);
			ImGui::InvisibleButton("##patch_tog", ImVec2(track_w, track_h));
			bool tog_clicked = ImGui::IsItemClicked();
			bool tog_hovered = ImGui::IsItemHovered();
			ImGui::PopID();
			ImU32 track_col = aida::ui::mix(t.panel_header, t.accent_u32, active_state ? 1.f : 0.f);
			dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + track_w, ty + track_h),
			                  with_a(track_col, a), track_h * 0.5f);
			float knob_r = (track_h - 4.f) * 0.5f;
			float knob_x = tx + 2.f + knob_r + (track_w - 4.f - knob_r * 2.f) * (active_state ? 1.f : 0.f);
			float knob_y = (ty + ty + track_h) * 0.5f;
			dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
			                    with_a(IM_COL32(255, 255, 255, 240), a), 16);
			if (tog_hovered)
				ImGui::SetTooltip("%s this patch after explicit review and byte readback",
					active_state ? "Revert" : "Apply");
			if (hov) {
				ImGui::BeginTooltip();
				ImGui::Text("Address: 0x%016" PRIX64, p.address);
				ImGui::TextWrapped("%s", p.description.c_str());
				ImGui::Separator();
				ImGui::TextWrapped("Original: %s", p.original.c_str());
				ImGui::TextWrapped("Patched: %s", p.patched.c_str());
				ImGui::EndTooltip();
			}
			if (tog_clicked) {
				diag::log_tagged_critical_fmt("patches",
					"patch_toggle_review idx=%d addr=0x%llx new_active=%d desc='%s'",
					i,
					static_cast<unsigned long long>(p.address),
					active_state ? 0 : 1,
					p.description.c_str());
				request_context_mutation(active_state
						? pending_context_mutation_t::revert_patch
						: pending_context_mutation_t::apply_patch,
					debugger_interaction::capture(debugger_interaction::kind_t::patch,
						p.address, snapshot_generation, i, 0,
						static_cast<uint64_t>(p.patched_size), p.description));
			}

			if (clicked) {
				ui.patches_panel.selected = i;
				select_debugger_row(row_context, total_n, context_for_row, false);
				memory_interaction::runtime_t runtime;
				runtime.driver_loaded = driver_bridge::is_loaded();
				runtime.live_attached = driver_bridge::attached_pid() != 0;
				runtime.target_pid = driver_bridge::attached_pid();
				runtime.target_epoch = memory_scanner::g_state.target_epoch.load(
					std::memory_order_acquire);
				runtime.process_creation_time_100ns = row_context.process_creation_time_100ns;
				memory_interaction::select(memory_interaction::capture_patch(runtime,
					p.address, static_cast<std::uint64_t>(p.patched_size), i,
					p.description));
			}
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				jump_to_disasm(p.address);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
				select_debugger_row(row_context, total_n, context_for_row, true);
				memory_interaction::runtime_t runtime;
				runtime.driver_loaded = driver_bridge::is_loaded();
				runtime.live_attached = driver_bridge::attached_pid() != 0;
				runtime.target_pid = driver_bridge::attached_pid();
				runtime.target_epoch = memory_scanner::g_state.target_epoch.load(
					std::memory_order_acquire);
				runtime.process_creation_time_100ns = row_context.process_creation_time_100ns;
				memory_interaction::select(memory_interaction::capture_patch(runtime,
					p.address, static_cast<std::uint64_t>(p.patched_size), i,
					p.description));
			}
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (patch_rows.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::flask;
		es.title = "No patches applied";
		es.body  = "Use the patcher to modify the target's code.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
	render_code_cave_dialog();
}

static const char* debugger_status_label(debugger_engine::dbg_status_t status) {
	switch (status) {
		case debugger_engine::dbg_status_t::idle: return "Idle";
		case debugger_engine::dbg_status_t::running: return "Running";
		case debugger_engine::dbg_status_t::paused: return "Paused";
		case debugger_engine::dbg_status_t::stepping: return "Stepping";
		case debugger_engine::dbg_status_t::terminated: return "Terminated";
	}
	return "Unknown";
}

static aida::ui::components::status_kind_t debugger_status_kind(
	debugger_engine::dbg_status_t status, bool has_target) {
	if (!has_target)
		return aida::ui::components::status_kind_t::warning;
	switch (status) {
		case debugger_engine::dbg_status_t::idle:
			return aida::ui::components::status_kind_t::neutral;
		case debugger_engine::dbg_status_t::running:
			return aida::ui::components::status_kind_t::success;
		case debugger_engine::dbg_status_t::paused:
			return aida::ui::components::status_kind_t::info;
		case debugger_engine::dbg_status_t::stepping:
			return aida::ui::components::status_kind_t::accent;
		case debugger_engine::dbg_status_t::terminated:
			return aida::ui::components::status_kind_t::error;
	}
	return aida::ui::components::status_kind_t::neutral;
}

static const char* debugger_tab_label(sub_tab_t tab) {
	switch (tab) {
		case sub_tab_t::cpu: return "CPU";
		case sub_tab_t::breakpoints: return "Breakpoints";
		case sub_tab_t::memory_map: return "Memory Map";
		case sub_tab_t::call_stack: return "Call Stack";
		case sub_tab_t::threads: return "Threads";
		case sub_tab_t::watches: return "Watches";
		case sub_tab_t::handles: return "Handles";
		case sub_tab_t::trace_log: return "Trace";
		case sub_tab_t::strings: return "Strings";
		case sub_tab_t::bookmarks: return "Bookmarks";
		case sub_tab_t::modules: return "Modules";
		case sub_tab_t::patches: return "Patches";
		case sub_tab_t::seh_chain: return "SEH";
		case sub_tab_t::cfg: return "CFG";
		case sub_tab_t::source: return "Source / Assembly";
		case sub_tab_t::COUNT: return "Debugger";
	}
	return "Debugger";
}

static void render_debugger_status_bar(ImVec2 pos, float width,
	debugger_engine::dbg_status_t status, uint32_t pid, bool has_target) {
	ImGui::SetCursorPos(pos);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	bool region_visible = ImGui::BeginChild("##debugger_status_region",
		ImVec2(width, aida::ui::metrics::status_bar::height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	if (region_visible) {
		ImGui::SetCursorPos(ImVec2(0.f, 0.f));
		bool visible = aida::ui::components::begin_status_bar("##debugger_status_bar");
		if (visible) {
			char pid_text[24] = {};
			if (pid != 0)
				std::snprintf(pid_text, sizeof(pid_text), "%u", static_cast<unsigned>(pid));
			else
				std::snprintf(pid_text, sizeof(pid_text), "none");

			aida::ui::components::status_item("target", "Target", pid_text,
				has_target ? aida::ui::components::status_kind_t::success
				           : aida::ui::components::status_kind_t::warning);
			aida::ui::components::status_item("engine", "Engine", debugger_status_label(status),
				debugger_status_kind(status, has_target));
			if (width >= 620.f) {
				aida::ui::components::status_item("panel", "Panel",
					debugger_tab_label(g_ui.active_tab),
					aida::ui::components::status_kind_t::accent,
					false, width >= 820.f);
			}
			if (width >= 820.f) {
				uint64_t rip = debugger_engine::cached_registers().rip;
				char rip_text[24] = {};
				std::snprintf(rip_text, sizeof(rip_text), "0x%016" PRIX64, rip);
				aida::ui::components::status_item("rip", "RIP", rip_text,
					rip != 0 ? aida::ui::components::status_kind_t::info
					         : aida::ui::components::status_kind_t::neutral,
					false, false);
			}
		}
		aida::ui::components::end_status_bar();
	}
	ImGui::EndChild();
	ImGui::PopStyleVar();
}


execution_capability_t address_mutation_capability(std::uint64_t address,
	bool toggle_breakpoint, std::uint32_t expected_pid) {
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address);
	if (expected_pid == 0)
		return {false, "The analysis selection is not owned by a live process workspace"};
	if (context.target_pid != expected_pid)
		return {false, "Attach the debugger to the process that owns this analysis workspace"};
	return address_mutation_capability(context, toggle_breakpoint);
}

execution_capability_t address_mutation_capability(
	const debugger_interaction::context_t& expected_context,
	bool toggle_breakpoint) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (g_target_mutation_pending.load(std::memory_order_acquire))
		return {false, "Another live-target mutation is still pending"};
#endif
	if ((expected_context.kind != debugger_interaction::kind_t::instruction &&
		expected_context.kind != debugger_interaction::kind_t::breakpoint) ||
		expected_context.address == 0 ||
		!debugger_interaction::is_current(expected_context))
		return {false,
			"The retained debugger target, process identity, address, or stop changed"};
	const auto result = debugger_interaction::evaluate(toggle_breakpoint
		? debugger_interaction::capability_t::toggle_breakpoint
		: debugger_interaction::capability_t::run_to_address, expected_context);
	return {result.enabled, result.disabled_reason};
}

bool queue_run_to_address(std::uint64_t address, std::uint32_t expected_pid,
	std::string* error) {
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address);
	if (context.target_pid != expected_pid) {
		if (error) *error =
			"Attach the debugger to the process that owns this analysis workspace";
		return false;
	}
	return queue_run_to_address(context, error);
}

bool queue_run_to_address(const debugger_interaction::context_t& expected_context,
	std::string* error) {
	const auto capability = address_mutation_capability(expected_context, false);
	if (!capability.enabled) {
		if (error) *error = capability.disabled_reason
			? capability.disabled_reason : "Run to cursor is unavailable";
		return false;
	}
	const auto context = expected_context;
	const bool queued = queue_debugger_mutation("Run to cursor",
		"analysis.debug.run_to_cursor", context, [context]() {
			mutation_result_t result;
			if (!debugger_interaction::is_current(context)) {
				result.detail =
					"The retained Run to Cursor target changed before the final mutation.";
				return result;
			}
			result.ok = debugger_engine::run_to_address(context.address, false);
			result.verified = result.ok && debugger_interaction::is_current(context);
			if (!result.ok)
				result.detail = "The debugger engine rejected Run to Cursor.";
			else if (!result.verified)
				result.detail =
					"The Run to Cursor target changed before its postcondition was verified.";
			return result;
		});
	if (!queued && error) *error = "The debugger mutation queue rejected Run to Cursor";
	return queued;
}

bool queue_toggle_breakpoint(std::uint64_t address, std::uint32_t expected_pid,
	std::string* error) {
	const auto capability = address_mutation_capability(address, true, expected_pid);
	if (!capability.enabled) {
		if (error) *error = capability.disabled_reason
			? capability.disabled_reason : "Breakpoint toggle is unavailable";
		return false;
	}
	const auto context = debugger_interaction::capture(
		debugger_interaction::kind_t::instruction, address);
	return queue_toggle_breakpoint(context, error);
}

bool queue_toggle_breakpoint(const debugger_interaction::context_t& expected_context,
	std::string* error) {
	if ((expected_context.kind != debugger_interaction::kind_t::instruction &&
		expected_context.kind != debugger_interaction::kind_t::breakpoint) ||
		expected_context.address == 0 || !debugger_interaction::is_current(expected_context)) {
		if (error) *error =
			"The retained breakpoint target, process identity, address, or debugger stop changed.";
		return false;
	}
	const auto evaluated = debugger_interaction::evaluate(
		debugger_interaction::capability_t::toggle_breakpoint, expected_context);
	if (!evaluated.enabled) {
		if (error) *error = evaluated.disabled_reason
			? evaluated.disabled_reason : "Breakpoint toggle is unavailable";
		return false;
	}
	const auto context = expected_context;
	const bool queued = queue_debugger_mutation("Toggle breakpoint at analysis cursor",
		"analysis.debug.breakpoint", context, [context]() {
			mutation_result_t result;
			if (!debugger_interaction::is_current(context)) {
				result.detail =
					"The retained breakpoint target changed before the final mutation.";
				return result;
			}
			auto snapshot = debugger_engine::snapshot_breakpoints();
			int found = -1;
			for (std::size_t index = 0; index < snapshot.size(); ++index) {
				if (!snapshot[index].is_internal &&
					snapshot[index].address == context.address) {
					found = static_cast<int>(index);
					break;
				}
			}
			result.ok = found >= 0
				? debugger_engine::remove_breakpoint(found)
				: debugger_engine::add_breakpoint(context.address) >= 0;
			if (!result.ok) {
				result.detail = "The debugger engine rejected the retained breakpoint toggle.";
				return result;
			}
			if (!debugger_interaction::is_current(context)) {
				result.detail =
					"The breakpoint target changed before the final postcondition was verified.";
				return result;
			}
			const auto verified_snapshot = debugger_engine::snapshot_breakpoints();
			const bool present = std::any_of(verified_snapshot.begin(),
				verified_snapshot.end(), [context](const auto& breakpoint) {
					return !breakpoint.is_internal && breakpoint.address == context.address;
				});
			result.verified = found >= 0 ? !present : present;
			if (!result.verified)
				result.detail =
					"The retained breakpoint toggle did not satisfy its final postcondition.";
			return result;
		});
	if (!queued && error) *error = "The debugger mutation queue rejected the breakpoint toggle";
	return queued;
}

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::initialize_fixture();
#endif
	#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	debugger_definition_store::synchronize(ImGui::GetFrameCount());
	#endif
	(void)accent_r; (void)accent_g; (void)accent_b;
	const auto synchronized_status =
		debugger_engine::g_state.status.load(std::memory_order_acquire);
	debugger_interaction::synchronize_target(driver_bridge::attached_pid(),
		synchronized_status != debugger_engine::dbg_status_t::running);

	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	bool root_visible = ImGui::BeginChild("##debugger_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::PopStyleVar();
	if (!root_visible) {
		ImGui::EndChild();
		return;
	}

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 root_size = ImGui::GetWindowSize();
	float w = root_size.x;
	float h = root_size.y;
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(wp, ImVec2(wp.x + w, wp.y + h), with_a(t.bg_base, alpha));

	const float min_width = 320.f;
	const float min_height = 260.f;
	if (w < min_width || h < min_height) {
		static bool clamp_logged = false;
		if (!clamp_logged) {
			clamp_logged = true;
			::diag::log_tagged_fmt("responsive",
				"debugger_view clamp_overlay width=%.0f height=%.0f min_width=%.0f min_height=%.0f",
				w, h, min_width, min_height);
		}
		aida::ui::responsive::draw_clamp_overlay(
			wp, root_size, "Widen or raise the panel to view debugger tools");
		ImGui::EndChild();
		return;
	}

	const float outer_pad = aida::ui::metrics::spacing::md;
	const float inner_width = std::max(1.f, w - outer_pad * 2.f);
	const bool has_target = analysis_session::has_active_target();
	const uint32_t attached_pid = driver_bridge::attached_pid();
	const debugger_engine::dbg_status_t header_status =
		debugger_engine::g_state.status.load(std::memory_order_acquire);
	char header_subtitle[128] = {};
	if (has_target && attached_pid != 0) {
		std::snprintf(header_subtitle, sizeof(header_subtitle), "%s target | PID %u | %s",
			debugger_status_label(header_status), static_cast<unsigned>(attached_pid),
			debugger_tab_label(g_ui.active_tab));
	} else {
		std::snprintf(header_subtitle, sizeof(header_subtitle),
			"Attach or launch a target to begin a live debugging session");
	}

	ImGui::SetCursorPos(ImVec2(outer_pad, outer_pad));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	bool header_visible = ImGui::BeginChild("##debugger_header_region",
		ImVec2(inner_width, aida::ui::metrics::panel::view_header_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	if (header_visible) {
		ImGui::SetCursorPos(ImVec2(0.f, 0.f));
		aida::ui::components::view_header("Debugger", header_subtitle, nullptr, nullptr,
			debugger_status_kind(header_status, has_target));
	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	const float nav_y_local = outer_pad + aida::ui::metrics::panel::view_header_h +
		aida::ui::metrics::spacing::sm;
	const float status_h = aida::ui::metrics::status_bar::height;
	const float status_y_local = h - outer_pad - status_h;
	const float content_bottom = wp.y + status_y_local - aida::ui::metrics::spacing::sm;

	if (!has_target) {
		float empty_y = wp.y + nav_y_local;
		aida::ui::no_target_overlay::render(
			ImVec2(wp.x + outer_pad, empty_y),
			ImVec2(inner_width, std::max(1.f, content_bottom - empty_y)),
			"No target attached",
			"The debugger needs a target. Launch a binary with full isolation, attach to a running process, or open a static file to inspect imports, exports and sections.",
			alpha, aida::ui::empty_state::glyph_t::shield);
		render_debugger_status_bar(ImVec2(outer_pad, status_y_local), inner_width,
			header_status, attached_pid, has_target);
		ImGui::EndChild();
		return;
	}

	float ox = wp.x + outer_pad;
	float oy = wp.y + nav_y_local;
	float dt = aida::ui::clock::dt();

	auto& ui = g_ui;
	ui.content_fade = ui_anim::smooth_lerp(ui.content_fade, 1.f, 14.f, dt);
	ui.tab_animator.slide.tick(dt);

	float a = alpha * std::max(ui.content_fade, 0.3f);
	render_tab_bar(dl, ox, oy, inner_width, alpha);

	float content_y = oy + TAB_HEIGHT + aida::ui::metrics::spacing::sm;
	float content_h = std::max(1.f, content_bottom - content_y);

	float toolbar_y = content_y;
	bool tab_uses_toolbar =
		ui.active_tab != sub_tab_t::memory_map &&
		ui.active_tab != sub_tab_t::modules &&
		ui.active_tab != sub_tab_t::seh_chain &&
		ui.active_tab != sub_tab_t::cfg &&
		ui.active_tab != sub_tab_t::source;
	float panel_offset = 0.f;
	if (tab_uses_toolbar) {
		draw_run_toolbar(dl, ox, toolbar_y, inner_width, alpha);
		panel_offset = run_toolbar_height() + aida::ui::metrics::spacing::sm;
	}

	float panel_y = content_y + panel_offset;
	float panel_h = std::max(1.f, content_h - panel_offset);

	float slide_t = ui.tab_animator.slide.eased();
	float slide_offset = (1.f - slide_t) * ui.tab_animator.direction * 28.f;
	if (slide_t >= 0.999f) slide_offset = 0.f;

	ImGui::PushClipRect(ImVec2(ox, panel_y), ImVec2(ox + inner_width, panel_y + panel_h), true);
	float panel_x = ox + slide_offset;
	float panel_w = inner_width;
	float content_alpha = a * (slide_t < 0.999f ? (0.4f + slide_t * 0.6f) : 1.f);

	switch (ui.active_tab) {
		case sub_tab_t::cpu:
			render_cpu(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::breakpoints:
			render_breakpoints(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::memory_map:
			render_memmap(dl, panel_x, content_y, panel_w, content_h, content_alpha);
			break;
		case sub_tab_t::call_stack:
			render_callstack(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::threads:
			render_threads(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::watches:
			render_watches(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::handles:
			render_handles(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::trace_log:
			render_trace(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::strings:
			render_strings(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::bookmarks:
			render_bookmarks(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::modules: {
			float mod_overlay_h = 60.f;
			render_modules_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			module_view::render(panel_x, content_y + mod_overlay_h,
				panel_w, content_h - mod_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		case sub_tab_t::patches:
			render_patches(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::seh_chain: {
			float seh_overlay_h = 60.f;
			render_seh_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			seh_view::render(panel_x, content_y + seh_overlay_h,
				panel_w, content_h - seh_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		case sub_tab_t::cfg: {
			float cfg_overlay_h = 40.f;
			render_cfg_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			cfg_view::render(panel_x, content_y + cfg_overlay_h,
				panel_w, content_h - cfg_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		case sub_tab_t::source:
			render_source_debug(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		default:
			break;
	}
	ImGui::PopClipRect();
	render_selected_context_menu(ui.active_tab);

	render_debugger_status_bar(ImVec2(outer_pad, status_y_local), inner_width,
		debugger_engine::g_state.status.load(std::memory_order_acquire),
		driver_bridge::attached_pid(), analysis_session::has_active_target());

	ImGui::EndChild();
	}

void render_pane(sub_tab_t pane, float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b,
	bool show_execution_controls, bool show_status) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::initialize_fixture();
#endif
	#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	debugger_definition_store::synchronize(ImGui::GetFrameCount());
	#endif
	(void)accent_r;
	(void)accent_g;
	(void)accent_b;
	if (!is_visible_sub_tab(pane) || width <= 0.f || height <= 0.f)
		return;

	const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
	debugger_interaction::synchronize_target(driver_bridge::attached_pid(),
		status != debugger_engine::dbg_status_t::running);
	const sub_tab_t previous_tab = g_ui.active_tab;
	g_ui.active_tab = pane;

	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::PushID(static_cast<int>(pane));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	bool visible = ImGui::BeginChild("##debugger_independent_pane", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::PopStyleVar();
	if (visible) {
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const ImVec2 origin = ImGui::GetWindowPos();
		const ImVec2 size = ImGui::GetWindowSize();
		const auto& theme = aida::ui::resolved();
		dl->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y),
			with_a(theme.bg_base, alpha));

		const float status_h = show_status ? aida::ui::metrics::status_bar::height : 0.f;
		const bool has_controls = show_execution_controls &&
			pane != sub_tab_t::memory_map && pane != sub_tab_t::modules &&
			pane != sub_tab_t::seh_chain && pane != sub_tab_t::cfg &&
			pane != sub_tab_t::source;
		const float controls_h = has_controls ? run_toolbar_height() : 0.f;
		const float gap = has_controls ? aida::ui::metrics::spacing::xs : 0.f;
		const float body_h = std::max(1.f, size.y - status_h - controls_h - gap);
		if (has_controls)
			draw_run_toolbar(dl, origin.x, origin.y, size.x, alpha);
		const float body_y = origin.y + controls_h + gap;

		ImGui::PushClipRect(ImVec2(origin.x, body_y),
			ImVec2(origin.x + size.x, body_y + body_h), true);
		switch (pane) {
			case sub_tab_t::cpu:
				render_cpu(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::breakpoints:
				render_breakpoints(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::memory_map:
				render_memmap(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::call_stack:
				render_callstack(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::threads:
				render_threads(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::watches:
				render_watches(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::handles:
				render_handles(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::trace_log:
				render_trace(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::strings:
				render_strings(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::bookmarks:
				render_bookmarks(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::modules: {
				const float overlay_h = 60.f;
				render_modules_overlay(dl, origin.x, body_y + 4.f, size.x, alpha);
				module_view::render(origin.x, body_y + overlay_h, size.x,
					std::max(1.f, body_h - overlay_h), alpha,
					theme.accent.x, theme.accent.y, theme.accent.z);
				break;
			}
			case sub_tab_t::patches:
				render_patches(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::seh_chain: {
				const float overlay_h = 60.f;
				render_seh_overlay(dl, origin.x, body_y + 4.f, size.x, alpha);
				seh_view::render(origin.x, body_y + overlay_h, size.x,
					std::max(1.f, body_h - overlay_h), alpha,
					theme.accent.x, theme.accent.y, theme.accent.z);
				break;
			}
			case sub_tab_t::cfg: {
				const float overlay_h = 40.f;
				render_cfg_overlay(dl, origin.x, body_y + 4.f, size.x, alpha);
				cfg_view::render(origin.x, body_y + overlay_h, size.x,
					std::max(1.f, body_h - overlay_h), alpha,
					theme.accent.x, theme.accent.y, theme.accent.z);
				break;
			}
			case sub_tab_t::source:
				render_source_debug(dl, origin.x, body_y, size.x, body_h, alpha);
				break;
			case sub_tab_t::COUNT:
				break;
		}
		ImGui::PopClipRect();
		render_selected_context_menu(pane);
		if (show_status)
			render_debugger_status_bar(ImVec2(0.f, size.y - status_h), size.x,
				status, driver_bridge::attached_pid(), driver_bridge::attached_pid() != 0);
	}
	ImGui::EndChild();
	ImGui::PopID();
	g_ui.active_tab = previous_tab;
}

void render_global_dialogs() {
	auto& ui = g_ui;
	if (ui.patch_stage_open &&
		!ImGui::IsPopupOpen("Stage Patch Review###debugger_patch_stage"))
		aida::ui::design::open_dialog("debugger_patch_stage", "Stage Patch Review");
	if (!aida::ui::design::begin_dialog("debugger_patch_stage", "Stage Patch Review",
			ImVec2(620.f, 420.f), ImVec2(420.f, 300.f)))
		return;

    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Stage Inactive", "Cancel");
    aida::ui::design::begin_dialog_body("patch_stage_body", footer_height);
	ImGui::TextUnformatted("Review a patch definition");
	ImGui::TextDisabled("This stages an inactive definition. It does not write target memory.");
	ImGui::Separator();
	ImGui::Text("Address: 0x%016" PRIX64, ui.patch_stage_address);
	if (ui.patch_stage_extent != 0)
		ImGui::Text("Selected range: %" PRIu64 " bytes", ui.patch_stage_extent);
	ImGui::TextUnformatted("Replacement bytes (hex)");
	ImGui::SetNextItemWidth(-1.f);
	if (ImGui::InputTextWithHint("##patch_stage_bytes", "90 90 90",
			ui.patch_stage_bytes_buf, sizeof(ui.patch_stage_bytes_buf)))
		refresh_patch_stage_parse_cache();
	ImGui::TextUnformatted("Description");
	ImGui::SetNextItemWidth(-1.f);
	ImGui::InputText("##patch_stage_description", ui.patch_stage_description_buf,
		sizeof(ui.patch_stage_description_buf));

	bool valid = ui.patch_stage_parse_valid;
	if (!valid && ui.patch_stage_bytes_buf[0] != '\0')
		ImGui::TextColored(ImVec4(1.f, 0.45f, 0.35f, 1.f),
			"Enter complete two-digit hex bytes separated by whitespace (maximum 4096 bytes).");
	if (ui.patch_stage_extent != 0 && valid &&
		ui.patch_stage_parsed_bytes.size() > ui.patch_stage_extent) {
		valid = false;
		ImGui::TextColored(ImVec4(1.f, 0.45f, 0.35f, 1.f),
			"Replacement bytes exceed the retained selected range.");
	} else if (ui.patch_stage_extent != 0 && valid &&
		ui.patch_stage_parsed_bytes.size() < ui.patch_stage_extent)
		ImGui::TextColored(ImVec4(1.f, 0.72f, 0.25f, 1.f),
			"Replacement bytes cover only part of the retained selected range; review before staging.");
	if (ui.patch_stage_exact && valid &&
		ui.patch_stage_parsed_bytes.size() != ui.patch_stage_expected_before.size()) {
		valid = false;
		ImGui::TextColored(ImVec4(1.f, 0.45f, 0.35f, 1.f),
			"The reviewed replacement must preserve the exact proposal byte range.");
	}
	const bool target_ready = driver_bridge::is_loaded() &&
		debugger_interaction::is_current(ui.patch_stage_context) &&
		ui.patch_stage_context.address == ui.patch_stage_address;
	if (!target_ready)
		ImGui::TextDisabled("The reviewed live target or debugger stop is unavailable; cancel and capture a new patch review.");
    aida::ui::design::end_dialog_body();

	const auto footer = aida::ui::design::dialog_footer("debugger_patch_stage_footer",
		"Stage Inactive", valid && target_ready, false, "Cancel");
	if (footer.confirmed) {
		const std::uint64_t address = ui.patch_stage_address;
		const std::uint64_t extent = ui.patch_stage_extent;
		const std::string description(ui.patch_stage_description_buf);
		const bool exact = ui.patch_stage_exact;
		const auto expected_before = ui.patch_stage_expected_before;
		const auto parsed = ui.patch_stage_parsed_bytes;
		auto context = ui.patch_stage_context;
		context.extent = extent == 0
			? static_cast<std::uint64_t>(parsed.size()) : extent;
		context.primary_text = description;
		const bool queued = queue_debugger_mutation("Capture patch rollback bytes",
			"debugger.patch_stage", context,
			[address, parsed, description, exact, context, expected_before]() mutable {
				mutation_result_t result;
				if (!debugger_interaction::is_current(context)) {
					result.detail =
						"The retained patch target changed before rollback bytes were captured.";
					return result;
				}
				const int index = exact
					? code_patcher::create_patch_exact(address, expected_before,
						parsed, context.target_pid,
						context.process_creation_time_100ns, description)
					: code_patcher::create_patch(address, parsed, description,
						context.target_pid, context.process_creation_time_100ns);
				result.ok = result.verified = index >= 0 &&
					debugger_interaction::is_current(context);
				bool discarded = true;
				if (index >= 0 && !result.verified)
					discarded = code_patcher::discard_inactive_patch_exact(
						index, address, parsed, context.target_pid,
						context.process_creation_time_100ns);
				if (!result.verified)
					result.detail = index < 0
						? "Unable to capture exact rollback bytes; no patch was staged."
						: discarded
						? "The retained patch target changed during rollback capture; the exact inactive definition was discarded."
						: "The retained patch target changed during rollback capture, and the exact inactive definition could not be discarded.";
				else {
					const bool posted = post_debugger_ui([index]() {
						g_ui.patches_panel.selected = index;
						aida::ui::application_views::open_or_focus(
							aida::ui::stable_view_id_t("view.debug.patches"));
					}, "patch_stage_selection");
					if (!posted) {
						const bool publication_discarded =
							code_patcher::discard_inactive_patch_exact(
								index, address, parsed, context.target_pid,
								context.process_creation_time_100ns);
						result.ok = result.verified = false;
						result.detail = publication_discarded
							? "Patch staging could not publish its reviewed definition; the exact inactive definition was discarded."
							: "Patch staging could not publish its reviewed definition, and the exact inactive definition could not be discarded.";
					}
				}
				return result;
			}, false);
		if (queued) {
			ui.patch_stage_open = false;
			ui.patch_stage_exact = false;
			ui.patch_stage_context = {};
			ui.patch_stage_expected_before.clear();
			ui.patch_stage_parsed_bytes.clear();
			ui.patch_stage_parse_valid = false;
			ImGui::CloseCurrentPopup();
		}
	}
	if (footer.cancelled) {
		ui.patch_stage_open = false;
		ui.patch_stage_exact = false;
		ui.patch_stage_context = {};
		ui.patch_stage_expected_before.clear();
		ui.patch_stage_parsed_bytes.clear();
		ui.patch_stage_parse_valid = false;
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

void render_execution_controls(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b) {
	(void)accent_r;
	(void)accent_g;
	(void)accent_b;
	#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	debugger_definition_store::synchronize(ImGui::GetFrameCount());
	#endif
	if (width <= 0.f || height <= 0.f)
		return;
	const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
	debugger_interaction::synchronize_target(driver_bridge::attached_pid(),
		status != debugger_engine::dbg_status_t::running);
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	bool visible = ImGui::BeginChild("##debugger_execution_controls", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::PopStyleVar();
	if (visible) {
		const ImVec2 origin = ImGui::GetWindowPos();
		const ImVec2 size = ImGui::GetWindowSize();
		draw_run_toolbar(ImGui::GetWindowDrawList(), origin.x, origin.y, size.x, alpha);
		if (size.y >= run_toolbar_height() + aida::ui::metrics::status_bar::height)
			render_debugger_status_bar(ImVec2(0.f, size.y - aida::ui::metrics::status_bar::height),
				size.x, status, driver_bridge::attached_pid(), driver_bridge::attached_pid() != 0);
	}
	ImGui::EndChild();
	}

void render_global_target_dialog() {
	spawn_target_dialog::render();
	spawn_target_dialog::result_t spawn_result;
	if (!spawn_target_dialog::consume_result(spawn_result) || !spawn_result.accepted)
		return;
	run_target::launch_options_t options = spawn_result.launch_options;
	options.exe_path = std::move(spawn_result.exe_path);
	options.args = std::move(spawn_result.args);
	options.working_dir = std::move(spawn_result.working_dir);
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.spawn_attach";
	submission.thread_class = "debugger_launch";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.body = [options]() {
		uint32_t new_pid = 0;
		run_target::launch_result_t result{};
		const bool ok = debugger_engine::spawn_and_attach_target(options, &new_pid, &result);
		const std::wstring sandbox_dir = result.sandbox_dir;
		if (options.isolation == run_target::isolation_t::windows_sandbox)
			run_target::cleanup(result);
		std::string error;
		if (!ok) {
			error = debugger_engine::last_error();
			if (error.empty())
				error = "(no detail)";
		}
		const std::string task_error = error;
		const auto isolation = options.isolation;
		const bool posted = post_debugger_ui(
			[sandbox_dir, ok, error, new_pid, isolation] {
				if (!sandbox_dir.empty())
					spawn_target_dialog::detail::last_sandbox_dir() = sandbox_dir;
				if (!ok) {
					toast_notification::push("Launch failed: " + error,
						toast_notification::toast_type_t::error);
				} else if (isolation == run_target::isolation_t::windows_sandbox) {
					toast_notification::push("Launched interactive malware lab VM.",
						toast_notification::toast_type_t::success);
				} else {
					char message[160];
					std::snprintf(message, sizeof(message),
						"Host launch started PID %u (iso=%d)",
						static_cast<unsigned>(new_pid), static_cast<int>(isolation));
					toast_notification::push(message,
						toast_notification::toast_type_t::success);
				}
			}, "spawn_attach_completion");
		if (!posted)
			throw std::runtime_error(
				"Debugger launch completion could not be published to the UI thread");
		if (!ok)
			throw std::runtime_error("Debugger launch or attach failed: " + task_error);
	};
	const auto submitted = submit_owned_debugger_task(std::move(submission),
		"view.debug.cpu", "debugger.launch", "Launch and attach debugger target", false);
	if (!submitted.submitted)
		toast_notification::push("Launch queue rejected the task.",
			toast_notification::toast_type_t::error);
	}
#define AIDA_DEBUGGER_PANE_WRAPPER(name, pane_value) \
	void name(float pos_x, float pos_y, float width, float height, float alpha, \
		float accent_r, float accent_g, float accent_b) { \
		render_pane(pane_value, pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b, false, false); \
	}

AIDA_DEBUGGER_PANE_WRAPPER(render_cpu_pane, sub_tab_t::cpu)
AIDA_DEBUGGER_PANE_WRAPPER(render_breakpoints_pane, sub_tab_t::breakpoints)
AIDA_DEBUGGER_PANE_WRAPPER(render_memory_map_pane, sub_tab_t::memory_map)
AIDA_DEBUGGER_PANE_WRAPPER(render_call_stack_pane, sub_tab_t::call_stack)
AIDA_DEBUGGER_PANE_WRAPPER(render_threads_pane, sub_tab_t::threads)
AIDA_DEBUGGER_PANE_WRAPPER(render_watches_pane, sub_tab_t::watches)
AIDA_DEBUGGER_PANE_WRAPPER(render_handles_pane, sub_tab_t::handles)
AIDA_DEBUGGER_PANE_WRAPPER(render_trace_pane, sub_tab_t::trace_log)
AIDA_DEBUGGER_PANE_WRAPPER(render_strings_pane, sub_tab_t::strings)
AIDA_DEBUGGER_PANE_WRAPPER(render_bookmarks_pane, sub_tab_t::bookmarks)
AIDA_DEBUGGER_PANE_WRAPPER(render_modules_pane, sub_tab_t::modules)
AIDA_DEBUGGER_PANE_WRAPPER(render_patches_pane, sub_tab_t::patches)
AIDA_DEBUGGER_PANE_WRAPPER(render_seh_pane, sub_tab_t::seh_chain)
AIDA_DEBUGGER_PANE_WRAPPER(render_cfg_pane, sub_tab_t::cfg)
AIDA_DEBUGGER_PANE_WRAPPER(render_source_pane, sub_tab_t::source)

#undef AIDA_DEBUGGER_PANE_WRAPPER

static void render_cpu_surface_pane(cpu_surface_t surface, float pos_x, float pos_y,
	float width, float height, float alpha) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::initialize_fixture();
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	debugger_definition_store::synchronize(ImGui::GetFrameCount());
#endif
	if (width <= 0.f || height <= 0.f)
		return;
	const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
	debugger_interaction::synchronize_target(driver_bridge::attached_pid(),
		status != debugger_engine::dbg_status_t::running);
	const sub_tab_t previous_tab = g_ui.active_tab;
	const char* previous_owner_view = g_debugger_context_owner_view;
	g_debugger_context_owner_view = surface == cpu_surface_t::registers
		? "view.debug.registers" : "view.debug.stack";
	g_ui.active_tab = sub_tab_t::cpu;
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::PushID(surface == cpu_surface_t::registers ? "debugger_registers_pane" :
		"debugger_stack_pane");
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	const bool visible = ImGui::BeginChild("##debugger_cpu_surface",
		ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::PopStyleVar();
	if (visible) {
		ImDrawList* draw_list = ImGui::GetWindowDrawList();
		const ImVec2 origin = ImGui::GetWindowPos();
		const ImVec2 size = ImGui::GetWindowSize();
		const auto& theme = aida::ui::resolved();
		draw_list->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y),
			with_a(theme.bg_base, alpha));
		ImGui::PushClipRect(origin, ImVec2(origin.x + size.x, origin.y + size.y), true);
		render_cpu(draw_list, origin.x, origin.y, size.x, size.y, alpha, surface);
		ImGui::PopClipRect();
		render_selected_context_menu(sub_tab_t::cpu);
	}
	ImGui::EndChild();
	ImGui::PopID();
	g_ui.active_tab = previous_tab;
	g_debugger_context_owner_view = previous_owner_view;
}

void render_registers_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float, float, float) {
	render_cpu_surface_pane(cpu_surface_t::registers, pos_x, pos_y, width, height, alpha);
}

void render_stack_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float, float, float) {
	render_cpu_surface_pane(cpu_surface_t::stack, pos_x, pos_y, width, height, alpha);
}

}
