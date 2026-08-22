#include "helpers.h"
#include "globals.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview_platform.hpp"
#include "../preview/studio_semantics.hpp"
#else
#include "diag_log.hpp"
#include "win32_dialog.hpp"
#endif
#include "toast_notification.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#endif
#include <fstream>
#include <filesystem>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <cstring>
#include <cstdint>
#include <atomic>
#include <functional>
#include <thread>
#include <chrono>
#include <cctype>
#include <exception>
#include <utility>
#include <nlohmann/json.hpp>
#include "../assets/icons.h"
#include "../ide_icons.h"
#include "standalone_chat.hpp"
#include "standalone_settings.hpp"
#include "code_editor.hpp"
#include "disasm_view.hpp"
#include "cfg_view.hpp"
#include "hex_view.hpp"
#include "image_view.hpp"
#include "chat_render.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "standalone_driver.hpp"
#include "mcp_client.hpp"
#include "../core/auth/auth_browser_launch.hpp"
#include "sandbox.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "workspace_search.hpp"
#endif
#include "network_view.hpp"
#include "debugger_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "debugger_engine.hpp"
#endif
#include "spawn_target_dialog.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "run_target.hpp"
#endif
#include "pseudocode_view.hpp"
#include "scan_hub_view.hpp"
#include "types_hub_view.hpp"
#include "analysis_hub_view.hpp"
#include "source_reconstruct_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/infra/executor.hpp"
#include "../core/infra/taskflow_runtime.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"
#endif
#include "../core/workbench/workbench_shell_integration.hpp"
#include "binary_map_view.hpp"
#include "functions_panel.hpp"
#include "xref_db_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "function_index.hpp"
#include "xref_index.hpp"
#include "xref_db.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/testlab/test_lab_view.hpp"
#include "../core/testlab/test_all_features.hpp"
#include "../core/testlab/test_all_ui.h"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/network/burp/camoufox_bridge.hpp"
#endif
#include "ui_anim.hpp"
#include "agent_picker_view.hpp"
#include "initial_analysis.hpp"
#include "initial_analysis_view.hpp"
#include "loading_binary_overlay.hpp"
#include "analysis_session.hpp"
#include "empty_state.hpp"
#include "../core/ui/ide_shell.hpp"
#include "../core/ui/workspace_layout.hpp"
#include "../core/ui/application_ui_runtime.hpp"
#include "../core/ui/application_view_registry.hpp"
#include "../core/ui/programming_tasks.hpp"
#include "../core/ui/task_center.hpp"
#include "../core/settings/settings_persistence_service.hpp"
#include "../core/settings/theme_transfer_service.hpp"
#include "../core/ai/conversation_evidence_store.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview.hpp"
#endif
#include <atomic>
#include <cmath>
#include <mutex>
#include <optional>
#include <shared_mutex>

render_section_state_t            g_render_section;

namespace {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::atomic<bool>          g_chrome_shutdown_requested{false};
	std::mutex                 g_chrome_shutdown_mutex;

	bool claim_chrome_shutdown_admission_impl(const char* source)
	{
		std::lock_guard<std::mutex> shutdown_lock(g_chrome_shutdown_mutex);
		const bool already_requested = g_chrome_shutdown_requested.exchange(true, std::memory_order_acq_rel);
		diag::log_tagged_critical_fmt("chrome", "shutdown_admission source=%s already=%d",
			source ? source : "<null>", already_requested ? 1 : 0);
		return !already_requested;
	}

	aida::infra::executor::submit_result_t submit_helpers_executor_task(
		const char* owner_subsystem,
		const char* label,
		aida::infra::executor::domain_t domain,
		const char* thread_class,
		std::function<void()> body,
		int priority = 3)
	{
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = owner_subsystem;
		sub.label = label;
		sub.thread_class = thread_class;
		sub.domain = domain;
		sub.priority = priority;
		sub.body = std::move(body);
		return aida::infra::executor::submit(std::move(sub));
	}

	struct process_attach_request_t final {
		std::uint64_t generation = 0;
		std::uint64_t selection_epoch = 0;
		std::uint32_t pid = 0;
		std::string process_name;
		std::string process_path;
		std::string window_title;
	};

	struct process_attach_result_t final {
		process_attach_request_t request;
		bool attached = false;
		bool cancelled = false;
		bool cancellation_after_commit = false;
		bool module_available = false;
		std::string session_id;
		std::string detail;
		std::string module_name;
		std::uint64_t module_base = 0;
		std::uint64_t module_size = 0;
	};

	struct process_attach_operation_t final {
		process_attach_request_t request;
		std::string task_id;
		std::shared_ptr<aida::analysis::cancellation_source_t> cancellation;
		std::function<bool()> selection_is_current;
		std::function<void()> close_dialog;
		std::atomic<bool> commit_reached{false};
		std::atomic<bool> cancellation_after_commit{false};
		std::atomic<bool> terminal{false};
	};

	std::mutex g_process_attach_operation_mutex;
	std::shared_ptr<process_attach_operation_t> g_process_attach_operation;
	std::atomic<std::uint64_t> g_process_attach_generation{0};

	bool process_attach_active()
	{
		std::lock_guard<std::mutex> lock(g_process_attach_operation_mutex);
		return g_process_attach_operation &&
			!g_process_attach_operation->terminal.load(std::memory_order_acquire);
	}

	void clear_process_attach_operation(
		const std::shared_ptr<process_attach_operation_t>& operation)
	{
		std::lock_guard<std::mutex> lock(g_process_attach_operation_mutex);
		if (g_process_attach_operation == operation)
			g_process_attach_operation.reset();
	}

	void raise_process_attach_diagnostic(
		const std::shared_ptr<process_attach_operation_t>& operation,
		aida::ui::task_center::diagnostic_severity_t severity,
		std::string summary,
		std::string details)
	{
		aida::ui::task_center::diagnostic_registration_t diagnostic;
		diagnostic.id = operation->task_id + ".diagnostic";
		diagnostic.task_id = operation->task_id;
		diagnostic.owner = "Process Attach";
		diagnostic.target = "PID " + std::to_string(operation->request.pid);
		diagnostic.summary = std::move(summary);
		diagnostic.details = std::move(details);
		diagnostic.severity = severity;
		diagnostic.callbacks.focus = [] {
			static_cast<void>(aida::ui_thread::post([] {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.diagnostics")));
			}, "process_attach", "focus_diagnostic", "task_center_callback"));
		};
		static_cast<void>(aida::ui::task_center::raise_diagnostic(std::move(diagnostic)));
	}

	void complete_process_attach_on_ui(
		const std::shared_ptr<process_attach_operation_t>& operation,
		const std::shared_ptr<const process_attach_result_t>& result)
	{
		if (!aida::ui_thread::require_owner(
			"process_attach", "publish_completion", "executor_completion")) {
			if (!operation->terminal.exchange(true, std::memory_order_acq_rel)) {
				const auto terminal_state = result->cancelled
					? aida::ui::task_center::task_state_t::cancelled
					: result->attached
						? aida::ui::task_center::task_state_t::partial
						: aida::ui::task_center::task_state_t::failed;
				static_cast<void>(aida::ui::task_center::update_task(
					operation->task_id, terminal_state, 1.0f,
					"UI ownership fence rejected completion",
					result->attached
						? "The attach committed, but its UI completion was rejected"
						: result->cancelled
							? "The attach was cancelled and rolled back"
							: "The attach failed before its UI completion was rejected"));
			}
			clear_process_attach_operation(operation);
			return;
		}

		const std::uint64_t current_generation =
			g_process_attach_generation.load(std::memory_order_acquire);
		bool operation_is_current = false;
		{
			std::lock_guard<std::mutex> lock(g_process_attach_operation_mutex);
			operation_is_current = g_process_attach_operation == operation;
		}
		const bool generation_is_current = result->request.generation != 0 &&
			result->request.generation == current_generation &&
			result->request.generation == operation->request.generation;
		const bool selection_is_current = operation->selection_is_current &&
			operation->selection_is_current();

		const bool session_target_is_current = !result->attached ||
			analysis_session::active_live_session_matches(
				result->request.pid, result->session_id);

		if (operation->terminal.exchange(true, std::memory_order_acq_rel)) {
			clear_process_attach_operation(operation);
			return;
		}

		if (result->cancelled) {
			output_log::push(bottom_tab_t::output,
				"[Driver] Attach to PID " + std::to_string(result->request.pid) +
				" was cancelled and rolled back.\n");
			static_cast<void>(aida::ui::task_center::update_task(
				operation->task_id,
				aida::ui::task_center::task_state_t::cancelled,
				1.0f,
				"Cancelled and rolled back",
				"No reviewed attach transaction was committed"));
		} else if (!result->attached) {
			const std::string detail = result->detail.empty()
				? "Attach failed without diagnostic detail" : result->detail;
			output_log::push(bottom_tab_t::output,
				"[Driver] Failed to attach to PID " + std::to_string(result->request.pid) +
				": " + detail + "\n");
			static_cast<void>(aida::ui::task_center::update_task(
				operation->task_id,
				aida::ui::task_center::task_state_t::failed,
				1.0f,
				"Attach failed",
				detail,
				operation->task_id + ".diagnostic"));
			raise_process_attach_diagnostic(operation,
				aida::ui::task_center::diagnostic_severity_t::error,
				"Process attach failed", detail);
		} else if (result->cancellation_after_commit ||
			operation->cancellation_after_commit.load(std::memory_order_acquire)) {
			output_log::push(bottom_tab_t::output,
				"[Driver] Attach to PID " + std::to_string(result->request.pid) +
				" committed before cancellation was requested.\n");
			static_cast<void>(aida::ui::task_center::update_task(
				operation->task_id,
				aida::ui::task_center::task_state_t::completed,
				1.0f,
				"Attach committed before cancellation request",
				"The active session was retained because the transaction had crossed its commit boundary"));
		} else if (!operation_is_current || !generation_is_current ||
			!selection_is_current || !session_target_is_current) {
			std::string reason;
			if (!operation_is_current) reason = "operation ownership changed";
			else if (!generation_is_current) reason = "request generation changed";
			else if (!selection_is_current) reason = "reviewed process selection changed";
			else reason = "active session target changed";
			output_log::push(bottom_tab_t::output,
				"[Driver] Attached to PID " + std::to_string(result->request.pid) +
				", but discarded stale UI completion: " + reason + ".\n");
			static_cast<void>(aida::ui::task_center::update_task(
				operation->task_id,
				aida::ui::task_center::task_state_t::partial,
				1.0f,
				"Attach committed; stale UI completion discarded",
				reason));
		} else {
			if (!result->module_available) {
				output_log::push(bottom_tab_t::output,
					"[Driver] Attached to PID " + std::to_string(result->request.pid) +
					" but could not enumerate modules.\n");
			}
			static_cast<void>(aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.disassembly")));
			static_cast<void>(aida::ui::task_center::update_task(
				operation->task_id,
				aida::ui::task_center::task_state_t::completed,
				1.0f,
				result->module_available
					? "Attached; workspace module resolved"
					: "Attached; module list unavailable",
				"PID " + std::to_string(result->request.pid) + " is the active session target"));
		}

		if (operation->close_dialog)
			operation->close_dialog();
		clear_process_attach_operation(operation);
	}

	void run_process_attach(
		const std::shared_ptr<process_attach_operation_t>& operation)
	{
		diag::log_tagged_critical_fmt("attach",
			"worker_enter generation=%llu selection_epoch=%llu pid=%u name=%s path=%s",
			static_cast<unsigned long long>(operation->request.generation),
			static_cast<unsigned long long>(operation->request.selection_epoch),
			operation->request.pid, operation->request.process_name.c_str(),
			operation->request.process_path.c_str());
		driver_bridge::debug_log("ATTACH: attempting pid=%u name=%s\n",
			operation->request.pid, operation->request.process_name.c_str());
		static_cast<void>(aida::ui::task_center::update_task(
			operation->task_id,
			aida::ui::task_center::task_state_t::running,
			0.05f,
			"Validating reviewed process identity"));

		auto result = std::make_shared<process_attach_result_t>();
		result->request = operation->request;
		try {
			std::string session_error;
			result->attached = analysis_session::open_attach_session(
				operation->request.pid, &session_error, operation->cancellation->token());
			result->detail = std::move(session_error);
			result->cancelled = !result->attached &&
				operation->cancellation->token().stop_requested();
			diag::log_tagged_critical_fmt("attach",
				"session_transaction generation=%llu pid=%u attached=%d cancelled=%d detail=%s",
				static_cast<unsigned long long>(operation->request.generation),
				operation->request.pid, result->attached ? 1 : 0,
				result->cancelled ? 1 : 0, result->detail.c_str());
			if (result->attached) {
				operation->commit_reached.store(true, std::memory_order_release);
				if (operation->cancellation->token().stop_requested())
					operation->cancellation_after_commit.store(true, std::memory_order_release);
				std::size_t session_index = 0;
				if (analysis_session::find_session_by_pid(operation->request.pid, &session_index))
					result->session_id = analysis_session::summarize_session_at(session_index).id;
				static_cast<void>(aida::ui::task_center::update_task(
					operation->task_id,
					aida::ui::task_center::task_state_t::running,
					0.78f,
					"Attach committed; resolving target module"));
				auto modules = driver_bridge::enumerate_modules();
				diag::log_tagged_critical_fmt("attach",
					"module_snapshot generation=%llu pid=%u count=%llu",
					static_cast<unsigned long long>(operation->request.generation),
					operation->request.pid,
					static_cast<unsigned long long>(modules.size()));
				if (!modules.empty()) {
					std::string reviewed_name = operation->request.process_name;
					for (char& character : reviewed_name)
						character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
					const auto* target_module = &modules.front();
					for (const auto& module : modules) {
						std::string module_name = module.name;
						for (char& character : module_name)
							character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
						if (module_name == reviewed_name) {
							target_module = &module;
							break;
						}
					}
					result->module_available = true;
					result->module_name = target_module->name;
					result->module_base = target_module->base;
					result->module_size = target_module->size == 0
						? 0x100000 : target_module->size;
					driver_bridge::debug_log(
						"ATTACH: workspace snapshot pid=%u base=0x%llX size=0x%llX mod=%s\n",
						operation->request.pid,
						static_cast<unsigned long long>(result->module_base),
						static_cast<unsigned long long>(result->module_size),
						result->module_name.c_str());
				}
			}
		} catch (const std::exception& exception) {
			if (!result->attached)
				result->detail = exception.what();
			diag::log_tagged_critical_fmt("attach",
				"worker_exception pid=%u detail=%s",
				operation->request.pid, exception.what());
		} catch (...) {
			if (!result->attached)
				result->detail = "Unknown exception during process attach";
			diag::log_tagged_critical_fmt("attach",
				"worker_exception pid=%u detail=unknown", operation->request.pid);
		}

		static_cast<void>(aida::ui::task_center::update_task(
			operation->task_id,
			result->cancelled
				? aida::ui::task_center::task_state_t::cancellation_requested
				: aida::ui::task_center::task_state_t::running,
			0.95f,
			result->cancelled
				? "Rollback complete; publishing cancellation"
				: "Publishing immutable attach completion"));
		result->cancellation_after_commit =
			operation->cancellation_after_commit.load(std::memory_order_acquire);
		const std::shared_ptr<const process_attach_result_t> immutable_result = result;
		const bool posted = aida::ui_thread::post(
			[operation, immutable_result] {
				complete_process_attach_on_ui(operation, immutable_result);
			}, "process_attach", "publish_completion", "executor_completion");
		if (posted)
			return;
		diag::log_tagged_critical_fmt("attach",
			"ui_dispatch_failed generation=%llu pid=%u attached=%d cancelled=%d",
			static_cast<unsigned long long>(operation->request.generation),
			operation->request.pid, result->attached ? 1 : 0,
			result->cancelled ? 1 : 0);

		if (!operation->terminal.exchange(true, std::memory_order_acq_rel)) {
			if (result->cancelled) {
				static_cast<void>(aida::ui::task_center::update_task(
					operation->task_id,
					aida::ui::task_center::task_state_t::cancelled,
					1.0f,
					"Cancelled and rolled back; UI dispatch unavailable",
					"No reviewed attach transaction was committed"));
			} else if (result->attached) {
				static_cast<void>(aida::ui::task_center::update_task(
					operation->task_id,
					aida::ui::task_center::task_state_t::partial,
					1.0f,
					"Attach committed; UI dispatch failed",
					"The active session is valid, but its UI completion could not be delivered"));
				raise_process_attach_diagnostic(operation,
					aida::ui::task_center::diagnostic_severity_t::warning,
					"Attach UI completion was not delivered",
					"The process attach committed before the UI dispatcher rejected publication");
			} else {
				const std::string detail = result->detail.empty()
					? "Attach failed and UI completion dispatch was unavailable" : result->detail;
				static_cast<void>(aida::ui::task_center::update_task(
					operation->task_id,
					aida::ui::task_center::task_state_t::failed,
					1.0f,
					"Attach failed; UI dispatch unavailable",
					detail,
					operation->task_id + ".diagnostic"));
				raise_process_attach_diagnostic(operation,
					aida::ui::task_center::diagnostic_severity_t::error,
					"Process attach failed", detail);
			}
		}
		clear_process_attach_operation(operation);
	}

	bool begin_process_attach(
		process_attach_request_t request,
		std::function<bool()> selection_is_current,
		std::function<void()> close_dialog,
		std::string& error)
	{
		auto operation = std::make_shared<process_attach_operation_t>();
		{
			std::lock_guard<std::mutex> lock(g_process_attach_operation_mutex);
			if (g_process_attach_operation &&
				!g_process_attach_operation->terminal.load(std::memory_order_acquire)) {
				error = "A process attach transaction is already active";
				return false;
			}
			request.generation = g_process_attach_generation.fetch_add(
				1, std::memory_order_acq_rel) + 1;
			operation->request = std::move(request);
			operation->task_id = "process.attach." +
				std::to_string(operation->request.pid) + "." +
				std::to_string(operation->request.generation);
			operation->cancellation =
				std::make_shared<aida::analysis::cancellation_source_t>();
			operation->selection_is_current = std::move(selection_is_current);
			operation->close_dialog = std::move(close_dialog);
			g_process_attach_operation = operation;
		}

		aida::ui::task_center::task_registration_t registration;
		registration.id = operation->task_id;
		registration.source = "process_attach_dialog";
		registration.owner = "Process Attach";
		registration.owner_view = "document.disassembly";
		registration.owner_action = "session.attach_process";
		registration.target = "PID " + std::to_string(operation->request.pid);
		const std::string reviewed_label = !operation->request.process_name.empty()
			? operation->request.process_name
			: !operation->request.window_title.empty()
				? operation->request.window_title : registration.target;
		registration.label = "Attach to " + reviewed_label;
		registration.stage = "Reviewed request queued";
		registration.affected_entity = operation->request.process_path.empty()
			? registration.target : operation->request.process_path;
		registration.progress = 0.0f;
		registration.cancellation_is_safe = true;
		registration.callbacks.cancel = [weak = std::weak_ptr<process_attach_operation_t>(operation)] {
			const auto current = weak.lock();
			if (!current || current->terminal.load(std::memory_order_acquire))
				return false;
			if (current->commit_reached.load(std::memory_order_acquire))
				current->cancellation_after_commit.store(true, std::memory_order_release);
			else
				current->cancellation->request_cancel();
			return true;
		};
		registration.callbacks.focus = [] {
			static_cast<void>(aida::ui_thread::post([] {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.background_tasks")));
			}, "process_attach", "focus_task", "task_center_callback"));
		};
		if (!aida::ui::task_center::register_task(std::move(registration))) {
			error = "The Task Center rejected process attach ownership";
			operation->terminal.store(true, std::memory_order_release);
			clear_process_attach_operation(operation);
			return false;
		}

		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "process_attach";
		submission.label = "process_attach.transaction";
		submission.thread_class = "driver_session_transaction";
		submission.domain = aida::infra::executor::domain_t::feature_worker;
		submission.priority = 2;
		submission.target_pid = operation->request.pid;
		submission.generation = operation->request.generation;
		submission.ui_access_policy = "immutable_snapshots_only";
		submission.failure_policy = "typed_diagnostic";
		submission.shutdown_policy = "cancel";
		submission.cancel_hook = [weak = std::weak_ptr<process_attach_operation_t>(operation)] {
			if (const auto current = weak.lock())
				current->cancellation->request_cancel();
		};
		submission.body = [operation] { run_process_attach(operation); };
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (submitted.submitted)
			return true;

		error = submitted.reject_reason.empty()
			? "The process attach executor rejected dispatch" : submitted.reject_reason;
		operation->terminal.store(true, std::memory_order_release);
		static_cast<void>(aida::ui::task_center::update_task(
			operation->task_id,
			aida::ui::task_center::task_state_t::failed,
			1.0f,
			"Dispatch rejected before execution",
			error,
			operation->task_id + ".diagnostic"));
		raise_process_attach_diagnostic(operation,
			aida::ui::task_center::diagnostic_severity_t::error,
			"Process attach dispatch was rejected", error);
		clear_process_attach_operation(operation);
		return false;
	}

	bool request_active_process_attach_cancel()
	{
		std::shared_ptr<process_attach_operation_t> operation;
		{
			std::lock_guard<std::mutex> lock(g_process_attach_operation_mutex);
			operation = g_process_attach_operation;
		}
		if (!operation || operation->terminal.load(std::memory_order_acquire))
			return false;
		return aida::ui::task_center::request_cancel(operation->task_id);
	}

#endif

	void g_sa_settings_request_save()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#else
		static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
	}

	enum class workspace_review_t : std::uint8_t {
		none,
		overwrite,
		delete_saved,
		reset_all
	};

	struct workspace_dialog_state_t {
		bool save_as_open = false;
		bool manager_open = false;
		bool focus_save_name = false;
		bool focus_rename_name = false;
		char save_name[65]{};
		char rename_name[65]{};
		std::string selected_name;
		std::uint64_t selected_generation = 0;
		bool selection_requires_reselection = false;
		std::string status;
		workspace_review_t review = workspace_review_t::none;
	};

	workspace_dialog_state_t& workspace_dialog_state()
	{
		static workspace_dialog_state_t value;
		return value;
	}

	void copy_workspace_name(char (&target)[65], std::string_view value)
	{
		std::fill(std::begin(target), std::end(target), '\0');
		const std::size_t bytes = (std::min)(value.size(), sizeof(target) - 1U);
		if (bytes != 0)
			std::memcpy(target, value.data(), bytes);
	}

	const char* workspace_preset_display_name(aida::ui::workspace_layout::workspace_preset_t preset)
	{
		std::size_t count = 0;
		const auto* descriptors = aida::ui::workspace_layout::presets(count);
		for (std::size_t index = 0; index < count; ++index)
			if (descriptors[index].id == preset)
				return descriptors[index].display_name.data();
		return "Analysis";
	}

	bool workspace_request_succeeded(
		aida::ui::workspace_layout::workspace_request_result_t result) noexcept
	{
		using result_t = aida::ui::workspace_layout::workspace_request_result_t;
		return result == result_t::completed || result == result_t::queued ||
			result == result_t::unchanged;
	}

	std::string workspace_request_message(
		aida::ui::workspace_layout::workspace_request_result_t result,
		std::string_view operation)
	{
		using result_t = aida::ui::workspace_layout::workspace_request_result_t;
		if (result == result_t::completed) return std::string(operation) + " completed.";
		if (result == result_t::queued) return std::string(operation) + " queued in Background Tasks.";
		if (result == result_t::unchanged) return std::string(operation) + " made no changes.";
		if (result == result_t::busy) {
			const std::string status = aida::ui::workspace_layout::operation_status();
			return status.empty() ? "Another workspace transaction is already running." : status;
		}
		if (result == result_t::invalid_name)
			return "Use 1-64 ASCII letters, numbers, spaces, hyphens or underscores; spaces cannot lead, trail or repeat.";
		if (result == result_t::already_exists)
			return "A saved workspace with this exact name already exists.";
		if (result == result_t::not_found)
			return "The selected saved workspace no longer exists. The catalog will refresh automatically.";
		if (result == result_t::unavailable)
			return "This operation is unavailable until the DockSpace and persistence service are ready.";
		return std::string(operation) + " failed. Open Background Tasks or Diagnostics for the retained failure evidence.";
	}

	void register_workspace_semantic(std::string_view id, std::string_view type,
		bool disabled = false)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(aida::preview::semantics::register_last_item(id, type,
			false, disabled));
#else
		static_cast<void>(id);
		static_cast<void>(type);
		static_cast<void>(disabled);
#endif
	}

	void open_workspace_save_as_dialog()
	{
		auto& dialog = workspace_dialog_state();
		dialog.save_as_open = true;
		dialog.manager_open = false;
		dialog.review = workspace_review_t::none;
		dialog.status.clear();
		const auto identity = aida::ui::workspace_layout::active_identity();
		copy_workspace_name(dialog.save_name, identity.kind ==
			aida::ui::workspace_layout::workspace_identity_kind_t::user
			? identity.user_name : std::string_view{});
		dialog.focus_save_name = true;
	}

	void open_workspace_manager_dialog(std::string_view selected = {},
		std::uint64_t selected_generation = 0)
	{
		auto& dialog = workspace_dialog_state();
		dialog.manager_open = true;
		dialog.save_as_open = false;
		dialog.review = workspace_review_t::none;
		dialog.status.clear();
		dialog.selected_name.clear();
		dialog.selected_generation = 0;
		dialog.selection_requires_reselection = false;
		if (!selected.empty()) {
			dialog.selected_name.assign(selected);
			dialog.selected_generation = selected_generation;
			copy_workspace_name(dialog.rename_name, selected);
		}
	}

	aida::ui::capability_state_t named_workspace_load_capability(
		const aida::ui::workspace_layout::user_workspace_descriptor_t& retained)
	{
		if (!aida::ui::workspace_layout::user_layout_catalog_ready())
			return aida::ui::capability_state_t::unavailable(
				"The saved workspace catalog is still loading");
		const auto catalog = aida::ui::workspace_layout::user_layout_catalog();
		const auto current = catalog ? std::find_if(catalog->begin(), catalog->end(),
			[&retained](const auto& item) {
				return item.name == retained.name &&
					item.generation == retained.generation;
			}) : std::vector<aida::ui::workspace_layout::user_workspace_descriptor_t>::const_iterator{};
		if (!catalog || current == catalog->end())
			return aida::ui::capability_state_t::unavailable(
				"This saved workspace changed after it was presented; reopen the catalog");
		if (current->active)
			return aida::ui::capability_state_t::unavailable(
				"This saved workspace is already active");
		if (aida::ui::workspace_layout::operation_pending()) {
			const std::string status = aida::ui::workspace_layout::operation_status();
			return aida::ui::capability_state_t::unavailable(status.empty()
				? "Another workspace transaction is already running" : status);
		}
		return aida::ui::capability_state_t::available();
	}

	aida::ui::application_ui::retained_entity_context_t named_workspace_load_context(
		aida::ui::workspace_layout::user_workspace_descriptor_t retained)
	{
		aida::ui::application_ui::retained_entity_context_t context;
		context.owner_id = "workspace.saved";
		context.entity_id = retained.name;
		context.entity_generation = retained.generation;
		context.validate_identity = [retained] {
			return named_workspace_load_capability(retained);
		};
		aida::ui::application_ui::retained_entity_action_t action;
		action.action_id = "workspace.load_named";
		action.capability = named_workspace_load_capability(retained);
		action.invoke = [retained] {
			const auto capability = named_workspace_load_capability(retained);
			if (!capability.enabled)
				return aida::ui::action_handler_result_t::failed(
					capability.disabled_reason);
			const auto result = aida::ui::workspace_layout::load_user_layout_exact(
				retained.name, retained.generation);
			std::string detail = workspace_request_message(result, "Load workspace");
			if (result == aida::ui::workspace_layout::workspace_request_result_t::unavailable &&
				aida::ui::workspace_layout::user_layout_catalog_ready()) {
				const auto catalog = aida::ui::workspace_layout::user_layout_catalog();
				const bool exact_identity_exists = catalog && std::any_of(
					catalog->begin(), catalog->end(), [&retained](const auto& item) {
						return item.name == retained.name &&
							item.generation == retained.generation;
					});
				if (!exact_identity_exists)
					detail = "The selected saved workspace changed after it was presented. Reopen the catalog and select its current generation.";
			}
			return workspace_request_succeeded(result)
				? aida::ui::action_handler_result_t::completed(detail)
				: aida::ui::action_handler_result_t::failed(detail);
		};
		context.actions.push_back(std::move(action));
		return context;
	}

	aida::ui::action_execution_result_t execute_named_workspace_load(
		const aida::ui::workspace_layout::user_workspace_descriptor_t& retained,
		aida::ui::action_invocation_source_t source)
	{
		auto context = named_workspace_load_context(retained);
		return aida::ui::application_ui::execute_retained_entity_action(
			"workspace.load_named", source, context);
	}

	void load_workspace_from_menu(
		const aida::ui::workspace_layout::user_workspace_descriptor_t& retained)
	{
		const auto result = execute_named_workspace_load(retained,
			aida::ui::action_invocation_source_t::application_menu);
		if (result.executed())
			return;
		open_workspace_manager_dialog(retained.name, retained.generation);
		workspace_dialog_state().status = result.message.empty()
			? "The selected saved workspace could not be loaded."
			: result.message;
	}

	void open_workspace_reset_all_review()
	{
		open_workspace_manager_dialog();
		workspace_dialog_state().review = workspace_review_t::reset_all;
	}

	void render_workspace_dialogs()
	{
		auto& dialog = workspace_dialog_state();
		const auto place_window = [](float desired_width, float desired_height,
				float minimum_width, float minimum_height) {
			ImGuiViewport* viewport = ImGui::GetMainViewport();
			const ImVec2 work = viewport ? viewport->WorkSize : ImGui::GetIO().DisplaySize;
			const ImVec2 origin = viewport ? viewport->WorkPos : ImVec2(0.0f, 0.0f);
			const float scale = aida::ui::design::metrics().scale;
			const float margin = aida::ui::scale_px(24.0f, scale);
			const ImVec2 available((std::max)(1.0f, work.x - margin * 2.0f),
				(std::max)(1.0f, work.y - margin * 2.0f));
			const ImVec2 minimum(
				(std::min)(aida::ui::scale_px(minimum_width, scale), available.x),
				(std::min)(aida::ui::scale_px(minimum_height, scale), available.y));
			const ImVec2 desired(
				(std::clamp)(aida::ui::scale_px(desired_width, scale), minimum.x, available.x),
				(std::clamp)(aida::ui::scale_px(desired_height, scale), minimum.y, available.y));
			ImGui::SetNextWindowPos(ImVec2(origin.x + work.x * 0.5f,
				origin.y + work.y * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
			ImGui::SetNextWindowSize(desired, ImGuiCond_Appearing);
			ImGui::SetNextWindowSizeConstraints(minimum, available);
		};
		ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings;
#if defined(IMGUI_HAS_DOCK)
		flags |= ImGuiWindowFlags_NoDocking;
#endif

		if (dialog.save_as_open) {
			place_window(500.0f, dialog.review == workspace_review_t::overwrite ? 300.0f : 260.0f,
				380.0f, 220.0f);
			if (ImGui::Begin("Save Workspace As##workspace.save-as.dialog",
					&dialog.save_as_open, flags)) {
				const auto identity = aida::ui::workspace_layout::active_identity();
				ImGui::TextUnformatted("Create a named derivative of the current workspace");
				ImGui::TextDisabled("Base preset: %s", workspace_preset_display_name(identity.preset));
				ImGui::Spacing();
				ImGui::SetNextItemWidth(-1.0f);
				if (dialog.focus_save_name) {
					ImGui::SetKeyboardFocusHere();
					dialog.focus_save_name = false;
				}
				const bool submitted = ImGui::InputText("##workspace.save-as.name",
					dialog.save_name, sizeof(dialog.save_name),
					ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
				register_workspace_semantic("aida.workspace.save-as.name",
					"workspace-name-input");
				ImGui::TextDisabled("1-64 letters, numbers, spaces, hyphens or underscores");
				if (!dialog.status.empty())
					ImGui::TextWrapped("%s", dialog.status.c_str());
				const bool pending = aida::ui::workspace_layout::operation_pending();
				const bool catalog_ready = aida::ui::workspace_layout::user_layout_catalog_ready();
				if (!catalog_ready)
					ImGui::TextDisabled("Loading saved workspace catalog...");
				const bool empty = dialog.save_name[0] == '\0';
				ImGui::BeginDisabled(pending || !catalog_ready || empty ||
					dialog.review == workspace_review_t::overwrite);
				const bool save_clicked = ImGui::Button("Save##workspace.save-as.confirm",
					ImVec2(104.0f, 0.0f));
				register_workspace_semantic("aida.workspace.save-as.confirm",
					"workspace-save-as", pending || !catalog_ready || empty ||
					dialog.review == workspace_review_t::overwrite);
				ImGui::EndDisabled();
				if ((save_clicked || (submitted && !pending && catalog_ready && !empty)) &&
					dialog.review != workspace_review_t::overwrite) {
					const auto result = aida::ui::workspace_layout::save_user_layout(
						dialog.save_name, false);
					if (result == aida::ui::workspace_layout::workspace_request_result_t::already_exists) {
						dialog.review = workspace_review_t::overwrite;
						dialog.status = "This exact name already exists. Overwrite replaces its saved layout and visibility snapshot.";
					} else {
						dialog.status = workspace_request_message(result, "Save Workspace As");
						if (workspace_request_succeeded(result))
							dialog.save_as_open = false;
					}
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel##workspace.save-as.cancel", ImVec2(96.0f, 0.0f))) {
					dialog.review = workspace_review_t::none;
					dialog.save_as_open = false;
				}
				register_workspace_semantic("aida.workspace.save-as.cancel",
					"workspace-dialog-cancel");
				if (dialog.review == workspace_review_t::overwrite) {
					ImGui::Separator();
					ImGui::TextWrapped("Overwrite saved workspace \"%s\"? This cannot be undone.",
						dialog.save_name);
					ImGui::BeginDisabled(pending);
					if (ImGui::Button("Overwrite##workspace.save-as.overwrite", ImVec2(104.0f, 0.0f))) {
						const auto result = aida::ui::workspace_layout::save_user_layout(
							dialog.save_name, true);
						dialog.status = workspace_request_message(result, "Workspace overwrite");
						if (workspace_request_succeeded(result))
							dialog.save_as_open = false;
					}
					register_workspace_semantic("aida.workspace.save-as.overwrite",
						"workspace-overwrite-confirm", pending);
					ImGui::EndDisabled();
					ImGui::SameLine();
					if (ImGui::Button("Keep Existing##workspace.save-as.keep")) {
						dialog.review = workspace_review_t::none;
						dialog.status.clear();
						dialog.focus_save_name = true;
					}
					register_workspace_semantic("aida.workspace.save-as.keep",
						"workspace-overwrite-cancel");
				}
			}
			ImGui::End();
		}

		if (dialog.manager_open) {
			place_window(760.0f, 500.0f, 520.0f, 360.0f);
			if (ImGui::Begin("Saved Workspaces##workspace.manager.dialog",
					&dialog.manager_open, flags)) {
				const bool catalog_ready = aida::ui::workspace_layout::user_layout_catalog_ready();
				const auto catalog = aida::ui::workspace_layout::user_layout_catalog();
				const auto active = aida::ui::workspace_layout::active_identity();
				if (catalog_ready && !dialog.selected_name.empty()) {
					const auto retained = catalog ? std::find_if(catalog->begin(), catalog->end(),
						[&dialog](const auto& item) {
							return item.name == dialog.selected_name;
						}) : std::vector<aida::ui::workspace_layout::user_workspace_descriptor_t>::const_iterator{};
					const bool missing = !catalog || retained == catalog->end();
					const bool replaced = !missing && (dialog.selected_generation == 0 ||
						retained->generation != dialog.selected_generation);
					if (missing || replaced) {
						if (dialog.review != workspace_review_t::reset_all)
							dialog.status = missing
								? "The selected saved workspace no longer exists. Select another workspace."
								: "The selected saved workspace changed after selection. Select its current generation explicitly.";
						dialog.selected_name.clear();
						dialog.selected_generation = 0;
						dialog.selection_requires_reselection = true;
						dialog.review = dialog.review == workspace_review_t::reset_all
							? dialog.review : workspace_review_t::none;
					}
				}
				if (dialog.selected_name.empty() && !dialog.selection_requires_reselection &&
					catalog_ready && catalog && !catalog->empty()) {
					const auto selected = std::find_if(catalog->begin(), catalog->end(),
						[](const auto& item) { return item.active; });
					const auto& initial = selected == catalog->end()
						? catalog->front() : *selected;
					dialog.selected_name = initial.name;
					dialog.selected_generation = initial.generation;
					copy_workspace_name(dialog.rename_name, initial.name);
				}
				ImGui::TextUnformatted("Saved Workspaces");
				if (active.kind == aida::ui::workspace_layout::workspace_identity_kind_t::user)
					ImGui::TextDisabled("Active: %s / %s",
						workspace_preset_display_name(active.preset), active.user_name.c_str());
				else
					ImGui::TextDisabled("Active: %s / Built-in",
						workspace_preset_display_name(active.preset));
				ImGui::Separator();
				const float list_width = (std::min)(260.0f,
					(std::max)(160.0f, ImGui::GetContentRegionAvail().x * 0.38f));
				ImGui::BeginChild("##workspace.manager.catalog", ImVec2(list_width, -44.0f),
					true);
				if (!catalog_ready) {
					ImGui::TextWrapped("Loading saved workspace catalog...");
				} else if (!catalog || catalog->empty()) {
					ImGui::TextWrapped("No named workspaces yet. Use Save Workspace As to create one.");
				} else {
					for (const auto& item : *catalog) {
						ImGui::PushID(item.name.c_str());
						std::string label = item.name;
						if (item.active) label.append("  [Active]");
						const bool selected = dialog.selected_name == item.name &&
							dialog.selected_generation == item.generation;
						if (ImGui::Selectable((label + "##workspace.saved-row").c_str(), selected,
							ImGuiSelectableFlags_AllowDoubleClick)) {
							dialog.selected_name = item.name;
							dialog.selected_generation = item.generation;
							dialog.selection_requires_reselection = false;
							copy_workspace_name(dialog.rename_name, item.name);
							dialog.review = workspace_review_t::none;
							dialog.status.clear();
							if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !item.active &&
								!aida::ui::workspace_layout::operation_pending()) {
								const auto result = execute_named_workspace_load(item,
									aida::ui::action_invocation_source_t::toolbar);
								dialog.status = result.message;
								if (result.executed()) dialog.manager_open = false;
							}
						}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						register_workspace_semantic(aida::preview::semantics::stable_id(
							"aida.workspace.saved", item.name), "workspace-saved-row");
#endif
						ImGui::TextDisabled("%s  /  generation %llu",
							workspace_preset_display_name(item.base_preset),
							static_cast<unsigned long long>(item.generation));
						ImGui::PopID();
					}
				}
				ImGui::EndChild();
				ImGui::SameLine();
				ImGui::BeginChild("##workspace.manager.details", ImVec2(0.0f, -44.0f), true);
				const auto selected = catalog ? std::find_if(catalog->begin(), catalog->end(),
					[&dialog](const auto& item) {
						return item.name == dialog.selected_name &&
							item.generation == dialog.selected_generation;
					}) :
					std::vector<aida::ui::workspace_layout::user_workspace_descriptor_t>::const_iterator{};
				if (!catalog || selected == catalog->end()) {
					ImGui::TextWrapped("Select a saved workspace to load, rename or delete it.");
				} else {
					ImGui::Text("%s", selected->name.c_str());
					ImGui::TextDisabled("Base preset: %s", workspace_preset_display_name(selected->base_preset));
					ImGui::TextDisabled("Saved generation: %llu",
						static_cast<unsigned long long>(selected->generation));
					ImGui::Spacing();
					const bool pending = aida::ui::workspace_layout::operation_pending();
					const auto load_capability = named_workspace_load_capability(*selected);
					ImGui::BeginDisabled(!load_capability.enabled);
					if (ImGui::Button("Load##workspace.manager.load", ImVec2(96.0f, 0.0f))) {
						const auto result = execute_named_workspace_load(*selected,
							aida::ui::action_invocation_source_t::toolbar);
						dialog.status = result.message;
						if (result.executed()) dialog.manager_open = false;
					}
					register_workspace_semantic("aida.workspace.manager.load", "workspace-load",
						!load_capability.enabled);
					if (!load_capability.enabled && ImGui::IsItemHovered(
							ImGuiHoveredFlags_AllowWhenDisabled))
						ImGui::SetTooltip("%s", load_capability.disabled_reason.c_str());
					ImGui::EndDisabled();
					ImGui::SameLine();
					if (ImGui::Button("Save As Copy##workspace.manager.save-copy")) {
						copy_workspace_name(dialog.save_name, selected->name);
						dialog.manager_open = false;
						dialog.save_as_open = true;
						dialog.focus_save_name = true;
						dialog.review = workspace_review_t::none;
						dialog.status.clear();
					}
					register_workspace_semantic("aida.workspace.manager.save-copy",
						"workspace-save-copy");
					ImGui::Spacing();
					if (dialog.rename_name[0] == '\0' ||
						dialog.selected_name != selected->name)
						copy_workspace_name(dialog.rename_name, selected->name);
					if (dialog.focus_rename_name) {
						ImGui::SetKeyboardFocusHere();
						dialog.focus_rename_name = false;
					}
					ImGui::SetNextItemWidth(-1.0f);
					ImGui::InputText("##workspace.manager.rename-name", dialog.rename_name,
						sizeof(dialog.rename_name), ImGuiInputTextFlags_AutoSelectAll);
					register_workspace_semantic("aida.workspace.manager.rename-name",
						"workspace-rename-input");
					ImGui::BeginDisabled(pending || dialog.rename_name[0] == '\0' ||
						selected->name == dialog.rename_name);
					if (ImGui::Button("Rename##workspace.manager.rename", ImVec2(96.0f, 0.0f))) {
						const std::string old_name = selected->name;
						const auto result = aida::ui::workspace_layout::rename_user_layout(
							old_name, dialog.rename_name);
						dialog.status = workspace_request_message(result, "Rename workspace");
						if (workspace_request_succeeded(result)) {
							dialog.selected_name.clear();
							dialog.selected_generation = 0;
							dialog.selection_requires_reselection = true;
						}
					}
					register_workspace_semantic("aida.workspace.manager.rename",
						"workspace-rename", pending || dialog.rename_name[0] == '\0' ||
						selected->name == dialog.rename_name);
					ImGui::EndDisabled();
					ImGui::SameLine();
					ImGui::BeginDisabled(pending);
					if (ImGui::Button("Delete...##workspace.manager.delete", ImVec2(96.0f, 0.0f))) {
						dialog.review = workspace_review_t::delete_saved;
						dialog.status.clear();
					}
					register_workspace_semantic("aida.workspace.manager.delete",
						"workspace-delete-review", pending);
					ImGui::EndDisabled();
					if (dialog.review == workspace_review_t::delete_saved) {
						ImGui::Separator();
						ImGui::TextWrapped("Delete \"%s\"? The saved layout and its visibility snapshot will be removed. Open documents and jobs are not deleted.",
							selected->name.c_str());
						ImGui::BeginDisabled(pending);
						if (ImGui::Button("Delete Permanently##workspace.manager.delete-confirm")) {
							const auto result = aida::ui::workspace_layout::delete_user_layout(
								selected->name);
							dialog.status = workspace_request_message(result, "Delete workspace");
							if (workspace_request_succeeded(result)) {
								dialog.selected_name.clear();
								dialog.selected_generation = 0;
								dialog.selection_requires_reselection = true;
								dialog.review = workspace_review_t::none;
							}
						}
						register_workspace_semantic("aida.workspace.manager.delete-confirm",
							"workspace-delete-confirm", pending);
						ImGui::EndDisabled();
						ImGui::SameLine();
						if (ImGui::Button("Cancel Delete##workspace.manager.delete-cancel"))
							dialog.review = workspace_review_t::none;
						register_workspace_semantic("aida.workspace.manager.delete-cancel",
							"workspace-delete-cancel");
					}
				}
				if (!dialog.status.empty()) {
					ImGui::Separator();
					ImGui::TextWrapped("%s", dialog.status.c_str());
				}
				ImGui::EndChild();
				if (dialog.review == workspace_review_t::reset_all) {
					ImGui::Separator();
					ImGui::TextWrapped("Reset all layouts? Every built-in customization and every named workspace will be removed, then the factory Analysis workspace will open. Documents, analysis sessions and background jobs remain intact.");
					const bool pending = aida::ui::workspace_layout::operation_pending();
					ImGui::BeginDisabled(pending);
					if (ImGui::Button("Reset All Layouts##workspace.manager.reset-all-confirm")) {
						const auto result = aida::ui::workspace_layout::reset_all();
						dialog.status = workspace_request_message(result, "Reset all layouts");
						if (workspace_request_succeeded(result)) dialog.manager_open = false;
					}
					register_workspace_semantic("aida.workspace.manager.reset-all-confirm",
						"workspace-reset-all-confirm", pending);
					ImGui::EndDisabled();
					ImGui::SameLine();
					if (ImGui::Button("Cancel Reset##workspace.manager.reset-all-cancel"))
						dialog.review = workspace_review_t::none;
					register_workspace_semantic("aida.workspace.manager.reset-all-cancel",
						"workspace-reset-all-cancel");
				} else {
					if (ImGui::Button("Save Workspace As...##workspace.manager.save-as"))
						open_workspace_save_as_dialog();
					register_workspace_semantic("aida.workspace.manager.save-as",
						"workspace-save-as-open");
					ImGui::SameLine();
					if (ImGui::Button("Close##workspace.manager.close"))
						dialog.manager_open = false;
					register_workspace_semantic("aida.workspace.manager.close",
						"workspace-dialog-close");
				}
			}
			ImGui::End();
		}

		if ((dialog.save_as_open || dialog.manager_open) &&
			ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			dialog.save_as_open = false;
			dialog.manager_open = false;
			dialog.review = workspace_review_t::none;
		}
	}

	std::string& custom_theme_ui_error()
	{
		static std::string value;
		return value;
	}

	aida::theme_transfer::theme_t capture_theme_transfer(const CustomThemeData& theme)
	{
		aida::theme_transfer::theme_t captured;
		captured.name = theme.name;
		captured.accent = {theme.accent[0], theme.accent[1], theme.accent[2]};
		captured.bg_base = static_cast<std::uint32_t>(theme.bg_base);
		captured.panel_bg = static_cast<std::uint32_t>(theme.panel_bg);
		captured.panel_header = static_cast<std::uint32_t>(theme.panel_header);
		captured.title_bar = static_cast<std::uint32_t>(theme.title_bar);
		captured.text_primary = static_cast<std::uint32_t>(theme.text_primary);
		captured.text_secondary = static_cast<std::uint32_t>(theme.text_secondary);
		captured.text_dim = static_cast<std::uint32_t>(theme.text_dim);
		captured.icon_index = theme.icon_index;
		captured.icon_file_path = theme.icon_file_path;
		return captured;
	}

	CustomThemeData materialize_theme(const aida::theme_transfer::theme_t& theme)
	{
		CustomThemeData materialized;
		materialized.name = theme.name;
		materialized.accent[0] = theme.accent[0];
		materialized.accent[1] = theme.accent[1];
		materialized.accent[2] = theme.accent[2];
		materialized.bg_base = static_cast<ImU32>(theme.bg_base);
		materialized.panel_bg = static_cast<ImU32>(theme.panel_bg);
		materialized.panel_header = static_cast<ImU32>(theme.panel_header);
		materialized.title_bar = static_cast<ImU32>(theme.title_bar);
		materialized.text_primary = static_cast<ImU32>(theme.text_primary);
		materialized.text_secondary = static_cast<ImU32>(theme.text_secondary);
		materialized.text_dim = static_cast<ImU32>(theme.text_dim);
		materialized.icon_index = theme.icon_index;
		materialized.icon_file_path = theme.icon_file_path;
		return materialized;
	}

	bool validate_custom_theme(const CustomThemeData& theme, std::string& error)
	{
		if (theme.name.empty() ||
			theme.name.size() > aida::theme_transfer::maximum_theme_name_bytes ||
			theme.name.find('\0') != std::string::npos) {
			error = "Theme names must contain between 1 and 96 bytes.";
			return false;
		}
		for (const float channel : theme.accent) {
			if (!std::isfinite(channel) || channel < 0.0f || channel > 1.0f) {
				error = "Theme accent channels must be finite values between 0 and 1.";
				return false;
			}
		}
		if (theme.icon_index < -1 || theme.icon_index > 4095) {
			error = "The theme icon index is outside the supported range.";
			return false;
		}
		if (theme.icon_file_path.size() >
				aida::theme_transfer::maximum_icon_path_bytes ||
			theme.icon_file_path.find('\0') != std::string::npos) {
			error = "The theme icon path exceeds its exact bound or contains an embedded null.";
			return false;
		}
		error.clear();
		return true;
	}

	bool persist_custom_theme_catalog(std::string& error)
	{
		if (custom_themes::list.size() > aida::theme_transfer::maximum_theme_count) {
			error = "The custom theme catalog is limited to 128 themes.";
			return false;
		}
		nlohmann::json catalog = nlohmann::json::array();
		for (const auto& theme : custom_themes::list) {
			if (!validate_custom_theme(theme, error))
				return false;
			const auto captured = capture_theme_transfer(theme);
			catalog.push_back({
				{"schema_version", 1},
				{"name", captured.name},
				{"accent", {captured.accent[0], captured.accent[1], captured.accent[2]}},
				{"bg_base", captured.bg_base},
				{"panel_bg", captured.panel_bg},
				{"panel_header", captured.panel_header},
				{"title_bar", captured.title_bar},
				{"text_primary", captured.text_primary},
				{"text_secondary", captured.text_secondary},
				{"text_dim", captured.text_dim},
				{"icon_index", captured.icon_index},
				{"icon_file_path", captured.icon_file_path}
			});
		}
		std::string payload;
		try {
			payload = catalog.dump();
		} catch (...) {
			error = "The custom theme catalog could not be serialized.";
			return false;
		}
		if (payload.size() > 1024U * 1024U) {
			error = "The custom theme catalog exceeds its 1 MiB bound.";
			return false;
		}
		const std::string previous_payload = g_sa_settings.custom_themes_json;
		const int previous_active = g_sa_settings.active_custom_theme_idx;
		g_sa_settings.custom_themes_json = std::move(payload);
		g_sa_settings.active_custom_theme_idx = custom_themes::active_custom;
		const auto requested = aida::settings_persistence::request_save(g_sa_settings);
		if (!aida::settings_persistence::accepted(requested)) {
			g_sa_settings.custom_themes_json = previous_payload;
			g_sa_settings.active_custom_theme_idx = previous_active;
			error = "The immutable settings snapshot for the custom theme catalog was rejected.";
			return false;
		}
		error.clear();
		return true;
	}

	void process_theme_transfer_completion()
	{
		auto completion = aida::theme_transfer::take_completion();
		if (!completion || completion->operation !=
				aida::theme_transfer::operation_t::import_theme ||
			!completion->success)
			return;
		if (!completion->imported_theme) {
			custom_theme_ui_error() = "The validated theme import did not contain a theme.";
			aida::theme_transfer::acknowledge_import(completion->serial, false,
				custom_theme_ui_error());
			return;
		}
		if (custom_themes::list.size() >= aida::theme_transfer::maximum_theme_count) {
			custom_theme_ui_error() = "Delete a custom theme before importing another; the catalog limit is 128.";
			aida::theme_transfer::acknowledge_import(completion->serial, false,
				custom_theme_ui_error());
			return;
		}
		const int previous_active = custom_themes::active_custom;
		custom_themes::list.push_back(materialize_theme(*completion->imported_theme));
		custom_themes::active_custom = static_cast<int>(custom_themes::list.size()) - 1;
		std::string persistence_error;
		if (!persist_custom_theme_catalog(persistence_error)) {
			custom_themes::list.pop_back();
			custom_themes::active_custom = previous_active;
			custom_theme_ui_error() = std::move(persistence_error);
			aida::theme_transfer::acknowledge_import(completion->serial, false,
				custom_theme_ui_error());
			return;
		}
		themes::changed = true;
		custom_theme_ui_error().clear();
		aida::theme_transfer::acknowledge_import(completion->serial, true);
	}

	void request_chrome_shutdown_from_render(const char* source, const char* cleanup_reason)
	{
		if (!file_tabs::exit_review_committed) {
			const auto requested = file_tabs::request_exit_review();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (!requested.succeeded)
				diag::log_tagged_critical_fmt("chrome",
					"shutdown_review_rejected source=%s reason=%.512s",
					source ? source : "<null>", requested.detail.c_str());
#else
			static_cast<void>(requested);
#endif
			return;
		}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)cleanup_reason;
		aida::preview::record(aida::preview::shell_action_t::close_window, source ? source : "render");
#else
		std::lock_guard<std::mutex> shutdown_lock(g_chrome_shutdown_mutex);
		HWND hwnd = g_hwnd;
		BOOL is_window = hwnd ? ::IsWindow(hwnd) : FALSE;
		bool already_requested = g_chrome_shutdown_requested.exchange(true, std::memory_order_acq_rel);
		POINT cursor{};
		::GetCursorPos(&cursor);
		diag::log_tagged_critical_fmt("chrome",
			"shutdown_request source=%s hwnd=0x%llX is_window=%d already=%d cursor=%ld,%ld tid=%lu section=%s",
			source ? source : "<null>",
			(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
			is_window ? 1 : 0,
			already_requested ? 1 : 0,
			cursor.x,
			cursor.y,
			aida::shell_platform::thread_id(),
			g_render_section.c_str());
		if (already_requested) {
			return;
		}

		try {
			test_all_features::cancel_tests_for_shutdown();
			diag::log_tagged_fmt("chrome",
				"shutdown_testlab_cancel_requested source=%s cleanup_owner=testlab",
				source ? source : "<null>");
		} catch (...) {
			diag::log_tagged_critical_fmt("chrome",
				"shutdown_camoufox_cleanup_exception source=%s",
				source ? source : "<null>");
		}

		hwnd = g_hwnd;
		is_window = hwnd ? ::IsWindow(hwnd) : FALSE;
		if (hwnd && is_window) {
			::SetLastError(0);
			BOOL posted = ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
			DWORD gle = ::GetLastError();
			diag::log_tagged_critical_fmt("chrome",
				"shutdown_post_wm_close source=%s hwnd=0x%llX ok=%d gle=%lu",
				source ? source : "<null>",
				(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
				posted ? 1 : 0,
				(unsigned long)gle);
			if (posted) {
				return;
			}
		}

		diag::log_tagged_critical_fmt("chrome",
			"shutdown_post_quit_fallback source=%s hwnd=0x%llX is_window=%d",
			source ? source : "<null>",
			(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
			is_window ? 1 : 0);
		::PostQuitMessage(0);
#endif
	}

	bool shell_left_mouse_down()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return aida::preview::mouse_button_down(ImGuiMouseButton_Left);
#else
		return (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && GetForegroundWindow() == g_hwnd;
#endif
	}

	void shell_toggle_maximize()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		globals::ui::maximized = !globals::ui::maximized;
		aida::preview::record(aida::preview::shell_action_t::toggle_maximize,
			globals::ui::maximized ? "maximized" : "restored");
#else
		if (::IsZoomed(g_hwnd))
			::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_RESTORE, 0);
		else
			::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
#endif
	}

	void shell_minimize()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::record(aida::preview::shell_action_t::minimize_window, "title_bar");
#else
		::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
#endif
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	void shell_move_window(int x, int y)
	{
		SetWindowPos(g_hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	}
#endif

	void restore_workbench_center_view(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		static std::weak_ptr<aida::analysis::analysis_workspace_t> restored_workspace;
		const auto previous = restored_workspace.lock();
		if (!workspace) {
			restored_workspace.reset();
			return;
		}
		if (previous == workspace)
			return;
		aida::workbench::workbench_shell_workspace_context_t context;
		const auto restored =
			aida::workbench::workbench_shell_runtime_t::instance()
				.workspace_context(workspace, context);
		if (!restored) {
			static unsigned long long last_failure_ms = 0;
			const auto now_ms = aida::shell_platform::tick_ms();
			if (now_ms - last_failure_ms >= 5000ULL) {
				last_failure_ms = now_ms;
				diag::log_tagged_fmt(
					"workbench_shell",
					"ui_restore_deferred binary_id=%s code=%u subject=%llu",
					workspace->identity().binary_id().to_hex().c_str(),
					static_cast<unsigned>(restored.code),
					static_cast<unsigned long long>(restored.subject));
			}
			return;
		}
		restored_workspace = workspace;
		if (workspace->identity().target_kind() ==
			aida::analysis::target_kind_t::static_file)
			static_cast<void>(aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.disassembly")));
	}

	const aida::workbench::document_persistence_dto_t*
	workbench_document(const aida::workbench::workbench_persistence_dto_t& state,
		aida::workbench::document_id_t document)
	{
		const auto found = std::find_if(state.documents.begin(), state.documents.end(),
			[document](const auto& candidate) { return candidate.id == document; });
		return found == state.documents.end() ? nullptr : &*found;
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool custom_icon_path_render_safe(const std::string& path, uint64_t& size_out, DWORD& attr_out, DWORD& err_out)
	{
		size_out = 0;
		attr_out = 0;
		err_out = ERROR_SUCCESS;
		if (path.empty()) {
			err_out = ERROR_INVALID_PARAMETER;
			return false;
		}
		if (path.rfind("\\\\", 0) == 0 || path.rfind("//", 0) == 0) {
			err_out = ERROR_BAD_NET_NAME;
			return false;
		}
		if (path.size() > MAX_PATH * 4) {
			err_out = ERROR_BAD_LENGTH;
			return false;
		}
		if (path.size() >= 2 && path[1] == ':') {
			char root[4] = { path[0], ':', '\\', '\0' };
			if (GetDriveTypeA(root) == DRIVE_REMOTE) {
				err_out = ERROR_BAD_NET_NAME;
				return false;
			}
		}
		WIN32_FILE_ATTRIBUTE_DATA data{};
		if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
			err_out = GetLastError();
			return false;
		}
		attr_out = data.dwFileAttributes;
		if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			err_out = ERROR_DIRECTORY;
			return false;
		}
		size_out = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | static_cast<uint64_t>(data.nFileSizeLow);
		if (size_out == 0 || size_out > 32ull * 1024ull * 1024ull) {
			err_out = ERROR_BAD_LENGTH;
			return false;
		}
		return true;
	}
#endif

}

bool claim_chrome_shutdown_admission(const char* source)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)source;
	return true;
#else
	return claim_chrome_shutdown_admission_impl(source);
#endif
}

namespace ui_input_gate
{
	bool any_fake_modal_open()
	{
		if (menu_bar::suppress_frames > 0) {
			static int s_last_suppress_frame = -1;
			int frame = ImGui::GetFrameCount();
			if (s_last_suppress_frame != frame) {
				--menu_bar::suppress_frames;
				s_last_suppress_frame = frame;
			}
			return true;
		}
		return globals::ui::process_attach_open
			|| globals::ui::command_palette_open
			|| globals::ui::driver_status_open
			|| globals::ui::shortcuts_dialog_open
			|| workspace_dialog_state().save_as_open
			|| workspace_dialog_state().manager_open
			|| aida::agent_picker::is_open()
			|| menu_bar::any_open;
	}

	bool true_modal_open()
	{
		if (ImGui::GetTopMostPopupModal() != nullptr)
			return true;
		return false;
	}

	bool popup_blocks_background_input()
	{
		if (ImGui::GetTopMostPopupModal() != nullptr)
			return true;
		if (any_fake_modal_open())
			return true;
		return false;
	}

	bool chrome_input_blocked()
	{
		return false;
	}

	bool splitter_input_blocked()
	{
		return true_modal_open();
	}
}

static bool trusted_show_open_file(HWND owner,
	const char* title,
	const char* filter_pairs,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)owner;
	(void)title;
	(void)filter_pairs;
	(void)caller_name;
	return aida::preview::choose_open_file(out_path, out_path_capacity);
#else
	return win32_dialog::show_open_file_dialog(owner, title, filter_pairs,
		out_path, out_path_capacity, caller_name);
#endif
}

static bool trusted_show_save_file(HWND owner,
	const char* title,
	const char* filter_pairs,
	const char* default_ext,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)owner;
	(void)title;
	(void)filter_pairs;
	(void)default_ext;
	(void)caller_name;
	return aida::preview::choose_save_file(out_path, out_path_capacity);
#else
	return win32_dialog::show_save_file_dialog(owner, title, filter_pairs, default_ext,
		out_path, out_path_capacity, caller_name);
#endif
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
static bool trusted_show_folder(HWND owner,
	const wchar_t* title,
	std::string& out_path,
	const char* caller_name)
{
	return win32_dialog::show_open_folder_dialog(owner, title, out_path, caller_name);
}
#endif

namespace file_menu_deferred
{
	enum class action_t
	{
		none,
		open_file,
		open_folder
	};

	struct result_t
	{
		action_t action = action_t::none;
		bool ok = false;
		std::string path;
	};

	static std::atomic<int>& pending_action()
	{
		static std::atomic<int> value{ static_cast<int>(action_t::none) };
		return value;
	}

	static std::atomic<bool>& active()
	{
		static std::atomic<bool> value{ false };
		return value;
	}

	static std::atomic<std::uint64_t>& generation()
	{
		static std::atomic<std::uint64_t> value{ 0 };
		return value;
	}

	static std::atomic<std::uint64_t>& active_generation()
	{
		static std::atomic<std::uint64_t> value{ 0 };
		return value;
	}

	static const char* action_name(action_t action)
	{
		switch (action) {
		case action_t::none: return "none";
		case action_t::open_file: return "open_file";
		case action_t::open_folder: return "open_folder";
		}
		return "unknown";
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static void clear_active_generation_if_current(std::uint64_t token)
	{
		std::uint64_t expected = token;
		(void)active_generation().compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
	}

	static void store_result(std::uint64_t token, result_t result, const char* source)
	{
		std::string source_copy = source && source[0] ? source : "worker";
		const action_t action = result.action;
		const bool ok = result.ok;
		const std::string path_copy = result.path;
		const bool posted = aida::ui_thread::post([token, action, ok, path_copy, source_copy]() {
			if (!aida::ui_thread::require_owner("file_dialog", "publish_result", source_copy.c_str())) {
				clear_active_generation_if_current(token);
				return;
			}
			const std::uint64_t current = generation().load(std::memory_order_acquire);
			const std::uint64_t active_token = active_generation().load(std::memory_order_acquire);
			const bool stale = token == 0 || token != current;
			if (stale) {
				diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
					"discard_stale source=%s token=%llu current=%llu active_generation=%llu action=%s ok=%d path=%.260s",
					source_copy.c_str(),
					static_cast<unsigned long long>(token),
					static_cast<unsigned long long>(current),
					static_cast<unsigned long long>(active_token),
					action_name(action),
					ok ? 1 : 0,
					path_copy.c_str());
				clear_active_generation_if_current(token);
				return;
			}

			if (action == action_t::open_file) {
				if (ok && !path_copy.empty()) {
					diag::log_tagged_fmt("file_dialog", "deferred_open_file picked path=%.260s", path_copy.c_str());
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_file token=%llu source=%s path=%.260s",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						path_copy.c_str());
					file_browser::open_path(path_copy);
				} else {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_file_cancelled token=%llu source=%s ok=%d",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						ok ? 1 : 0);
					diag::log_tagged_critical("file_dialog", "deferred_open_file cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_file end");
			} else if (action == action_t::open_folder) {
				if (ok && !path_copy.empty()) {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_folder token=%llu source=%s path=%.260s",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						path_copy.c_str());
					std::string root_error;
					if (!file_browser::set_workspace_root(path_copy, &root_error))
						diag::log_tagged_fmt("file_dialog", "open_folder_root_transaction_failed path=%.260s error=%s",
							path_copy.c_str(), root_error.c_str());
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder picked path=%.260s", path_copy.c_str());
				} else {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_folder_cancelled token=%llu source=%s ok=%d",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						ok ? 1 : 0);
					diag::log_tagged_critical("file_dialog", "deferred_open_folder cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_folder end");
			} else {
				diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
					"discard_none token=%llu source=%s",
					static_cast<unsigned long long>(token),
					source_copy.c_str());
			}
			clear_active_generation_if_current(token);
		}, "file_dialog", "publish_result", source_copy.c_str());

		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"post_publish source=%s token=%llu action=%s ok=%d posted=%d dispatcher_pending=%zu path=%.260s",
			source_copy.c_str(),
			static_cast<unsigned long long>(token),
			action_name(action),
			ok ? 1 : 0,
			posted ? 1 : 0,
			aida::ui_thread::pending_count(),
			path_copy.c_str());
		if (!posted)
			clear_active_generation_if_current(token);
	}
#endif

	static void request(action_t action)
	{
		const std::uint64_t token = generation().fetch_add(1, std::memory_order_acq_rel) + 1;
		pending_action().store(static_cast<int>(action), std::memory_order_release);
		diag::log_tagged_fmt("file_dialog", "deferred_request action=%d active=%d", static_cast<int>(action), active().load(std::memory_order_acquire) ? 1 : 0);
		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"request token=%llu action=%s active=%d pending_raw=%d active_generation=%llu",
			static_cast<unsigned long long>(token),
			action_name(action),
			active().load(std::memory_order_acquire) ? 1 : 0,
			pending_action().load(std::memory_order_acquire),
			static_cast<unsigned long long>(active_generation().load(std::memory_order_acquire)));
	}
	static void run_pending()
	{
		if (active().load(std::memory_order_acquire))
			return;

		int raw = pending_action().exchange(static_cast<int>(action_t::none), std::memory_order_acq_rel);
		action_t action = static_cast<action_t>(raw);
		if (action == action_t::none)
			return;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (action == action_t::open_file) {
			aida::preview::record(aida::preview::shell_action_t::open_file, "file_menu_deferred");
			aida::preview::apply_open_file();
		} else if (action == action_t::open_folder) {
			aida::preview::record(aida::preview::shell_action_t::open_folder, "file_menu_deferred");
			aida::preview::apply_open_folder();
		}
		return;
#else

		const std::uint64_t token = generation().load(std::memory_order_acquire);
		active_generation().store(token, std::memory_order_release);
		active().store(true, std::memory_order_release);
		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"worker_start_post token=%llu action=%s active_generation=%llu dispatcher_pending=%zu",
			static_cast<unsigned long long>(token),
			action_name(action),
			static_cast<unsigned long long>(active_generation().load(std::memory_order_acquire)),
			aida::ui_thread::pending_count());
		auto task = [action, token]() {
			try {
				if (action == action_t::open_file) {
					diag::log_tagged_critical("file_dialog", "deferred_open_file worker_begin");
					char buf[MAX_PATH] = {};
					static const char k_open_file_filter[] =
						"All files (*.*)\0*.*\0"
						"C/C++ (*.c;*.cpp;*.h;*.hpp)\0*.c;*.cpp;*.h;*.hpp\0\0";
					bool ok = trusted_show_open_file(nullptr,
						"Open File",
						k_open_file_filter,
						buf, sizeof(buf),
						"file_menu_open");
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action, ok, ok ? std::string(buf) : std::string() }, "worker_open_file");
					diag::log_tagged_fmt("file_dialog", "deferred_open_file worker_end ok=%d", ok ? 1 : 0);
				} else if (action == action_t::open_folder) {
					diag::log_tagged_critical("file_dialog", "deferred_open_folder worker_begin");
					std::string folder;
					bool ok = trusted_show_folder(nullptr,
						L"Open Workspace Folder",
						folder,
						"workspace_open_folder");
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action, ok, ok ? folder : std::string() }, "worker_open_folder");
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder worker_end ok=%d", ok ? 1 : 0);
				} else {
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action_t::none, false, {} }, "worker_none");
				}
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("file_dialog", "deferred_worker exception=%s", ex.what());
				active().store(false, std::memory_order_release);
				store_result(token, result_t{ action, false, {} }, "worker_exception");
			} catch (...) {
				diag::log_tagged_critical("file_dialog", "deferred_worker unknown_exception");
				active().store(false, std::memory_order_release);
				store_result(token, result_t{ action, false, {} }, "worker_unknown_exception");
			}
		};
		bool queued = false;
		try {
			queued = submit_helpers_executor_task(
				"file_dialog",
				"file_dialog.deferred_worker",
				aida::infra::executor::domain_t::feature_worker,
				"bounded_task",
				std::move(task)).submitted;
		} catch (const std::exception& ex) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_fmt("file_dialog", "deferred_post exception=%s", ex.what());
			store_result(token, result_t{ action, false, {} }, "post_exception");
			return;
		} catch (...) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post unknown_exception");
			store_result(token, result_t{ action, false, {} }, "post_unknown_exception");
			return;
		}
		if (!queued) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post failed");
			store_result(token, result_t{ action, false, {} }, "post_failed");
		}
#endif
	}
}

ID3D11ShaderResourceView* helpers::theme_rias = nullptr;
ID3D11ShaderResourceView* helpers::theme_nagi = nullptr;
ID3D11ShaderResourceView* helpers::theme_mio = nullptr;
ID3D11ShaderResourceView* helpers::theme_kaneki = nullptr;
bool helpers::themes_loaded = false;


static ID3D11ShaderResourceView* g_bg_art_srv = nullptr;
static int g_bg_art_w = 0, g_bg_art_h = 0;
static ID3D11ShaderResourceView* g_aida_logo_srv = nullptr;
static int g_aida_logo_w = 0, g_aida_logo_h = 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
extern unsigned char background[];
extern unsigned char aidalogo[];
static bool g_bg_art_loaded = false;
static bool g_aida_logo_loaded = false;
static ID3D11ShaderResourceView* g_custom_theme_icon_srv = nullptr;
static int g_custom_theme_icon_w = 0;
static int g_custom_theme_icon_h = 0;
static std::string g_custom_theme_icon_path;
#endif

int helpers::active_tab = 0;
int helpers::active_subsection = 0;
bool helpers::init = false;
static float fadeout = 1.f;

ID3D11ShaderResourceView* helpers::icon_aim = nullptr;
ID3D11ShaderResourceView* helpers::icon_see = nullptr;
ID3D11ShaderResourceView* helpers::icon_misc = nullptr;
ID3D11ShaderResourceView* helpers::icon_settings = nullptr;
ID3D11ShaderResourceView* helpers::icon_player = nullptr;
ID3D11ShaderResourceView* helpers::icon_solitude = nullptr;

int helpers::icon_w = 0;
int helpers::icon_h = 0;
bool helpers::icons_loaded = false;

bool helpers::tab(const char* label, int index, ImVec2 pos, ImVec2 size)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 tab_min = ImVec2(wp.x + pos.x, wp.y + pos.y);
	ImVec2 tab_max = ImVec2(tab_min.x + size.x, tab_min.y + size.y);

	bool hovered = ImGui::IsMouseHoveringRect(tab_min, tab_max, false);
	bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	if (clicked) active_tab = index;
	bool active = active_tab == index;

	ImGuiStorage* storage = ImGui::GetStateStorage();
	const ImGuiID index_id = static_cast<ImGuiID>(index);
	const ImGuiID anim_id = ImGuiID{ 1000u } + index_id;
	const ImGuiID hover_id = ImGuiID{ 3000u } + index_id;

	float t = storage->GetFloat(anim_id, active ? 1.0f : 0.0f);
	float ht = storage->GetFloat(hover_id, 0.0f);

	float dt = aida::ui::clock::dt();
	t += ((active ? 1.0f : 0.0f) - t) * std::min(8.0f * dt, 1.0f);
	ht += ((hovered ? 1.0f : 0.0f) - ht) * std::min(12.0f * dt, 1.0f);

	storage->SetFloat(anim_id, t);
	storage->SetFloat(hover_id, ht);

	if (t > 0.01f)
	{
		for (int i = 4; i >= 1; i--)
		{
			const float spread = static_cast<float>(i) * 3.0f;
			dl->AddRectFilled(
				ImVec2(tab_min.x - spread, tab_min.y - spread),
				ImVec2(tab_max.x + spread, tab_max.y + spread),
				aida::ui::with_alpha(th.accent_glow,
					0.08f * t * static_cast<float>(5 - i)),
				6.f + spread);
		}
	}

	if (ht > 0.01f && t < 0.99f)
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.hover_wash, ht * (1.0f - t)), 6.f);

	if (t > 0.01f)
	{
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.selection_strong, t * 0.85f), 6.f);
		dl->AddRectFilled(tab_min, ImVec2(tab_max.x, tab_min.y + 1.f),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.08f * t), 6.f);
	}

	ImVec2 ts = ImGui::CalcTextSize(label);
	ImVec2 tp = ImVec2(
		tab_min.x + (size.x - ts.x) * 0.5f,
		tab_min.y + (size.y - ts.y) * 0.5f);

	ImU32 text_col = aida::ui::mix(
		aida::ui::mix(th.text_secondary, th.text_primary, ht),
		th.text_primary, t);

	dl->AddText(tp, text_col, label);

	return clicked;
}

void helpers::begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha, ImGuiWindowFlags flags)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();

	ImVec2 r_min = ImVec2(std::round(wp.x + pos.x), std::round(wp.y + pos.y));
	ImVec2 r_max = ImVec2(std::round(r_min.x + size.x), std::round(r_min.y + size.y));

	ImU32 pbg = aida::ui::resolved().panel_bg;
	int pr = (pbg >> 0) & 0xFF, pg = (pbg >> 8) & 0xFF, pb = (pbg >> 16) & 0xFF, pa = (pbg >> 24) & 0xFF;
	dl->AddRectFilled(r_min, r_max,
		IM_COL32(pr, pg, pb, static_cast<int>(static_cast<float>(pa) * alpha)), 8.f);

	bool has_label = str_id && str_id[0] != '\0';
	std::string uid = has_label ? str_id : std::string("##child_") + std::to_string((uintptr_t)&pos);
	float padding = 6;
	ImGui::SetCursorPos(ImVec2(pos.x + padding, pos.y + padding));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::BeginChild(uid.c_str(), ImVec2(size.x - (2 * padding), size.y - (2 * padding)), false,
		ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings | flags);

}

void helpers::end_child()
{
	ImGui::EndChild();
	ImGui::PopStyleVar();
}

int helpers::subsection(const char** labels, int count, ImVec2 pos)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	const float count_f = static_cast<float>(count);
	float btn_w     = (avail_w - spacing * static_cast<float>(count - 1)) / count_f;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),         std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),    std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			active_subsection = i;

		if (anim.find(i) == anim.end()) anim[i] = (active_subsection == i) ? 1.0f : 0.0f;
		float spd = 10.0f * ImGui::GetIO().DeltaTime;
		float tgt = (active_subsection == i) ? 1.0f : 0.0f;
		anim[i] += (tgt - anim[i]) * std::min(spd, 1.0f);
		float t = anim[i];


		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, aida::ui::resolved().hover_wash, 4.f);


		ImU32 text_col = aida::ui::with_alpha(
			aida::ui::mix(aida::ui::resolved().text_secondary, aida::ui::resolved().accent_u32, t),
			0.45f + 0.55f * t);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);


		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return active_subsection;
}

int helpers::subsection(const char** labels, int count, ImVec2 pos, int& state)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	const float count_f = static_cast<float>(count);
	float btn_w     = (avail_w - spacing * static_cast<float>(count - 1)) / count_f;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int*, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),       std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),  std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			state = i;

		if (anim.find(&state) == anim.end()) anim[&state] = (state == i) ? 1.0f : 0.0f;
		anim[&state] += ((state == i ? 1.0f : 0.0f) - anim[&state])
			* std::min(10.0f * ImGui::GetIO().DeltaTime, 1.0f);
		float t = anim[&state];

		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, aida::ui::resolved().hover_wash, 4.f);

		ImU32 text_col = aida::ui::with_alpha(
			aida::ui::mix(aida::ui::resolved().text_secondary, aida::ui::resolved().accent_u32, t),
			0.45f + 0.55f * t);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);

		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return state;
}

void helpers::add_key(const char* label, CKeybind* keybind)
{
	(void)label;
	ImDrawList* dl = ImGui::GetForegroundDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImU32 accent_col = IM_COL32(globals::ui::accent.x * 255, globals::ui::accent.y * 255, globals::ui::accent.z * 255, 255);

	static std::map<CKeybind*, bool>  menu_open;
	static std::map<CKeybind*, float> height_anim;
	static std::map<CKeybind*, float> width_anim;

	if (menu_open.find(keybind) == menu_open.end())   menu_open[keybind] = false;
	if (height_anim.find(keybind) == height_anim.end()) height_anim[keybind] = 0.0f;
	if (width_anim.find(keybind) == width_anim.end())  width_anim[keybind] = 0.0f;

	std::string key_name = keybind->waiting_for_input ? "..." : keybind->get_key_name();
	if (key_name == "lbutton")  key_name = "lmb";
	else if (key_name == "rbutton")  key_name = "rmb";
	else if (key_name == "mbutton")  key_name = "mmb";
	else if (key_name == "xbutton1") key_name = "xb1";
	else if (key_name == "xbutton2") key_name = "xb2";

	const char* options[] = { "Toggle", "Hold", "Always" };

	ImVec2 key_ts = ImGui::CalcTextSize(key_name.c_str());
	float max_opt_w = 0.0f;
	for (int i = 0; i < 3; i++) max_opt_w = std::max(max_opt_w, ImGui::CalcTextSize(options[i]).x);

	float min_w = 30.0f;
	float closed_w = std::max(min_w, key_ts.x + 8.0f);
	float open_w = std::max(min_w, max_opt_w + 14.0f);
	float closed_h = 13.0f;
	float open_h = 45.0f;

	ImVec2 cursor_pos = ImGui::GetCursorPos();
	float child_w = ImGui::GetCurrentWindow()->Size.x;
	float anim_spd = 10.0f * ImGui::GetIO().DeltaTime;
	float tgt = menu_open[keybind] ? 1.0f : 0.0f;

	if (height_anim[keybind] < tgt) height_anim[keybind] = std::min(height_anim[keybind] + anim_spd, tgt);
	else if (height_anim[keybind] > tgt) height_anim[keybind] = std::max(height_anim[keybind] - anim_spd, tgt);
	if (width_anim[keybind] < tgt) width_anim[keybind] = std::min(width_anim[keybind] + anim_spd, tgt);
	else if (width_anim[keybind] > tgt) width_anim[keybind] = std::max(width_anim[keybind] - anim_spd, tgt);

	float cur_w = closed_w + (open_w - closed_w) * width_anim[keybind];
	float cur_h = closed_h + (open_h - closed_h) * height_anim[keybind];
	float x_pos = child_w - cur_w - 5.0f + 5.0f;

	ImGui::SameLine();
	ImGui::SetCursorPosX(x_pos);

	ImVec2 btn_min = ImVec2(wp.x + x_pos, wp.y + cursor_pos.y);
	ImVec2 btn_max = ImVec2(btn_min.x + cur_w, btn_min.y + cur_h);

	bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
	bool left_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	bool right_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right);

	if (right_click) { menu_open[keybind] = !menu_open[keybind]; keybind->waiting_for_input = false; }
	if (left_click && !menu_open[keybind])
	{
		keybind->waiting_for_input = !keybind->waiting_for_input;
		if (!keybind->waiting_for_input) ImGui::ClearActiveID();
	}
	if (keybind->waiting_for_input && keybind->set_key())
	{
		keybind->waiting_for_input = false;
		ImGui::ClearActiveID();
	}

	float kb_radius = 3.0f;
	dl->AddRect(btn_min, btn_max, IM_COL32(0, 0, 0, 255), kb_radius);
	dl->AddRect(ImVec2(btn_min.x + 1, btn_min.y + 1), ImVec2(btn_max.x - 1, btn_max.y - 1), aida::ui::resolved().border_strong, kb_radius);
	ImU32 kb_fill_top = aida::ui::lighten(aida::ui::resolved().bg_base, aida::ui::is_dark() ? 14 : -6);
	ImU32 kb_fill_bot = aida::ui::darken(aida::ui::resolved().bg_base, aida::ui::is_dark() ? 4 : -2);
	ImU32 kb_fill_mix = aida::ui::mix(kb_fill_top, kb_fill_bot, 0.45f);
	dl->AddRectFilled(
		ImVec2(btn_min.x + 2, btn_min.y + 2), ImVec2(btn_max.x - 2, btn_max.y - 2),
		kb_fill_mix, kb_radius);

	float key_op = 1.0f - height_anim[keybind];
	if (key_op > 0.01f)
	{
		ImU32 tc = keybind->waiting_for_input ? accent_col : aida::ui::with_alpha(aida::ui::resolved().text_primary, key_op);
		ImVec2 tp = ImVec2(std::round(btn_min.x + (cur_w - key_ts.x) * 0.5f), std::round(btn_min.y + (closed_h - key_ts.y) * 0.5f - 1.0f));

		dl->AddText(tp, tc, key_name.c_str());
	}

	if (height_anim[keybind] > 0.01f)
	{
		float opt_h = 13.0f;
		for (int i = 0; i < 3; i++)
		{
			float oy = btn_min.y + 3.0f + static_cast<float>(i) * opt_h;
			if (oy + opt_h > btn_max.y) break;

			ImVec2 opt_min = ImVec2(btn_min.x + 2, oy + 2);
			ImVec2 opt_max = ImVec2(btn_max.x - 2, std::min(oy + opt_h, btn_max.y - 2));

			if (ImGui::IsMouseHoveringRect(opt_min, opt_max) && height_anim[keybind] > 0.99f && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			{
				keybind->type = static_cast<CKeybind::c_keybind_type>(i);
				menu_open[keybind] = false;
			}

			bool sel = keybind->type == i;
			ImVec2 ots = ImGui::CalcTextSize(options[i]);
			ImVec2 otp = ImVec2(std::round(btn_min.x + (cur_w - ots.x) * 0.5f), std::round(oy + (opt_h - ots.y) * 0.5f - 1.0f));
			float op = height_anim[keybind];
			ImU32 oc = sel ?
				IM_COL32((int)(globals::ui::accent.x * 255), (int)(globals::ui::accent.y * 255), (int)(globals::ui::accent.z * 255), (int)(255 * op)) :
				aida::ui::with_alpha(aida::ui::resolved().text_secondary, op);

			if (otp.y + ots.y <= btn_max.y - 2.0f)
			{
				dl->AddText(otp, oc, options[i]);
			}
		}
	}

	if (menu_open[keybind] && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !hovered)
		menu_open[keybind] = false;
}

namespace {

bool valid_conversation_id(std::string_view id)
{
	if (id.empty() || id.size() > 128U)
		return false;
	return std::all_of(id.begin(), id.end(), [](unsigned char value) {
		return std::isalnum(value) != 0 || value == '-' || value == '_';
	});
}

struct conversation_ui_transaction_t {
	std::uint64_t source_fingerprint = 0;
	std::uint64_t source_revision = 0;
	aida::conversation_store::operation_t operation =
		aida::conversation_store::operation_t::save;
	std::optional<aida::conversation_store::request_t> deferred_save;
};

conversation_ui_transaction_t& conversation_ui_transaction()
{
	static conversation_ui_transaction_t value;
	return value;
}

std::uint64_t conversation_fingerprint()
{
	std::uint64_t hash = 14695981039346656037ULL;
	auto append = [&](std::string_view value) {
		for (const char character : value) {
			hash ^= static_cast<unsigned char>(character);
			hash *= 1099511628211ULL;
		}
	};
	append(conversations::current_id);
	for (const auto& message : g_chat_messages) {
		append(message.text);
		append(message.thinking_text);
		append(message.model_id);
		hash ^= static_cast<std::uint64_t>(message.timestamp);
		hash *= 1099511628211ULL;
		hash ^= message.is_user ? 1ULL : 0ULL;
		hash *= 1099511628211ULL;
	}
	return hash;
}

aida::conversation_store::snapshot_t capture_conversation_snapshot(bool advance_revision)
{
	aida::conversation_store::snapshot_t snapshot;
	snapshot.id = conversations::current_id;
	const bool assigning_identity = snapshot.id.empty() && !g_chat_messages.empty();
	if (assigning_identity) {
		static std::uint64_t identity_sequence = 0;
		const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();
		snapshot.id = std::to_string(now);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		snapshot.id += "-" + std::to_string(::GetCurrentProcessId());
#endif
		snapshot.id += "-" + std::to_string(++identity_sequence);
		conversations::current_id = snapshot.id;
		conversations::current_identity_uncommitted = true;
	}
	snapshot.require_absent = conversations::current_identity_uncommitted;
	if (advance_revision && !snapshot.id.empty())
		++conversations::current_revision;
	snapshot.revision = conversations::current_revision;
	for (const auto& summary : conversations::history) {
		if (summary.id == snapshot.id) {
			snapshot.pinned = summary.pinned;
			snapshot.created = summary.created;
			snapshot.title = summary.title;
			break;
		}
	}
	if (snapshot.created == 0 && !g_chat_messages.empty())
		snapshot.created = g_chat_messages.front().timestamp;
	for (const auto& message : g_chat_messages) {
		if (snapshot.title.empty() && message.is_user && !message.text.empty())
			snapshot.title = message.text.substr(0, 80);
		aida::conversation_store::message_t persisted;
		persisted.text = message.text;
		persisted.thinking_text = message.thinking_text;
		persisted.is_user = message.is_user;
		persisted.has_thinking = message.has_thinking;
		persisted.timestamp = message.timestamp;
		persisted.input_tokens = message.input_tokens;
		persisted.output_tokens = message.output_tokens;
		persisted.cache_read_tokens = message.cache_read_tokens;
		persisted.cache_write_tokens = message.cache_write_tokens;
		persisted.model_id = message.model_id;
		snapshot.messages.push_back(std::move(persisted));
	}
	if (!snapshot.id.empty())
		snapshot.evidence = aida::automation_ui::persisted_evidence_snapshot(snapshot.id);
	snapshot.evidence_authoritative = snapshot.id.empty() ||
		aida::automation_ui::persisted_evidence_session_loaded(snapshot.id);
	return snapshot;
}

void publish_conversation_catalog()
{
	conversations::published_history =
		std::make_shared<const std::vector<ConversationSummary>>(conversations::history);
}

std::uint64_t summary_revision(std::string_view id)
{
	const auto found = std::find_if(conversations::history.begin(),
		conversations::history.end(), [&](const ConversationSummary& summary) {
			return summary.id == id;
		});
	return found == conversations::history.end() ? 0 : found->revision;
}

bool submit_conversation_request(aida::conversation_store::request_t request)
{
	conversation_ui_transaction_t& transaction = conversation_ui_transaction();
	const std::uint64_t fingerprint = conversation_fingerprint();
	const auto submitted = aida::conversation_store::submit(request);
	if (submitted == aida::conversation_store::request_result_t::busy &&
		request.operation == aida::conversation_store::operation_t::save) {
		transaction.deferred_save = std::move(request);
		return true;
	}
	const bool accepted = submitted == aida::conversation_store::request_result_t::queued ||
		submitted == aida::conversation_store::request_result_t::preview_recorded;
	if (accepted) {
		transaction.source_fingerprint = fingerprint;
		transaction.source_revision = request.current.revision;
		transaction.operation = request.operation;
	}
	return accepted;
}

}

void conversations::save_current()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (g_chat_messages.empty() && current_id.empty()) return;
	if (current_id.empty()) current_id = "preview-conversation";
	++current_revision;
	std::string title = "Untitled";
	for (const auto& message : g_chat_messages) {
		if (message.is_user && !message.text.empty()) {
			title = message.text.substr(0, 80);
			break;
		}
	}
	auto found = std::find_if(history.begin(), history.end(), [](const ConversationSummary& item) {
		return item.id == current_id;
	});
	if (g_chat_messages.empty() && found != history.end() && !found->title.empty())
		title = found->title;
	const bool pinned = found != history.end() && found->pinned;
	const std::int64_t created = !g_chat_messages.empty() ? g_chat_messages.front().timestamp :
		found != history.end() ? found->created : 0;
	ConversationSummary summary{ current_id, title, created,
		static_cast<int>(g_chat_messages.size()), pinned, current_revision };
	if (found == history.end()) history.insert(history.begin(), std::move(summary));
	else *found = std::move(summary);
	publish_conversation_catalog();
#else
	if (g_chat_messages.empty() && current_id.empty()) return;
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::save;
	request.current = capture_conversation_snapshot(true);
	request.catalog_generation = catalog_generation;
	static_cast<void>(submit_conversation_request(std::move(request)));
#endif
}

void conversations::load_conversation(const std::string& id)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!current_id.empty() && current_id != id)
		save_current();
	current_id = id;
	++current_revision;
	current_identity_uncommitted = false;
	g_chat_messages.clear();
	ChatMessage user_message;
	user_message.text = "Show the saved reverse-engineering findings.";
	user_message.is_user = true;
	user_message.timestamp = 1;
	g_chat_messages.push_back(std::move(user_message));
	ChatMessage assistant_message;
	assistant_message.text = "The deterministic Studio conversation fixture is active. All original chat controls and interaction states remain available.";
	assistant_message.timestamp = 2;
	g_chat_messages.push_back(std::move(assistant_message));
	g_chat_scroll_to_bottom = true;
#else
	if (!valid_conversation_id(id)) return;
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::switch_conversation;
	request.current = capture_conversation_snapshot(true);
	request.target_id = id;
	request.target_revision = summary_revision(id);
	request.catalog_generation = catalog_generation;
	static_cast<void>(submit_conversation_request(std::move(request)));
#endif
}

void conversations::new_chat()
{
	const auto persistence = aida::conversation_store::status();
	if (persistence.pending || persistence.failed || is_ai_busy()) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	save_current();
	g_chat_messages.clear();
	g_chat_buf[0] = '\0';
	current_id.clear();
	current_revision = 0;
	current_identity_uncommitted = false;
	g_chat_scroll_to_bottom = true;
	refresh_history();
#else
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::new_conversation;
	request.current = capture_conversation_snapshot(true);
	request.catalog_generation = catalog_generation;
	static_cast<void>(submit_conversation_request(std::move(request)));
#endif
}

void conversations::refresh_history()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (history.empty()) {
		history = {
			{ "fixture-analysis", "Entry point analysis", 3, 8 },
			{ "fixture-network", "Protocol reconstruction", 2, 12 },
			{ "fixture-unpack", "Packed sample notes", 1, 6 }
		};
	}
	publish_conversation_catalog();
#else
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::refresh_catalog;
	request.catalog_generation = catalog_generation;
	static_cast<void>(submit_conversation_request(std::move(request)));
#endif
}

void conversations::delete_conversation(const std::string& id,
	std::uint64_t reviewed_revision)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(reviewed_revision);
	history.erase(std::remove_if(history.begin(), history.end(), [&id](const ConversationSummary& item) {
		return item.id == id;
	}), history.end());
	if (current_id == id) {
		g_chat_messages.clear();
		g_chat_buf[0] = '\0';
		current_id.clear();
		current_revision = 0;
		current_identity_uncommitted = false;
		g_chat_scroll_to_bottom = true;
		aida::automation_ui::apply_persisted_evidence({}, {});
	}
	publish_conversation_catalog();
#else
	if (!valid_conversation_id(id)) return;
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::delete_conversation;
	request.target_id = id;
	request.target_revision = reviewed_revision;
	request.catalog_generation = catalog_generation;
	static_cast<void>(submit_conversation_request(std::move(request)));
#endif
}

bool conversations::set_pinned(const std::string& id, bool pinned)
{
	if (!valid_conversation_id(id)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const auto found = std::find_if(history.begin(), history.end(), [&](const ConversationSummary& item) {
		return item.id == id;
	});
	if (found == history.end()) return false;
	found->pinned = pinned;
	std::stable_sort(history.begin(), history.end(), [](const auto& a, const auto& b) {
		if (a.pinned != b.pinned) return a.pinned > b.pinned;
		return a.created > b.created;
	});
	publish_conversation_catalog();
	return true;
#else
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::set_pinned;
	request.target_id = id;
	request.target_revision = summary_revision(id);
	request.catalog_generation = catalog_generation;
	request.pinned = pinned;
	return submit_conversation_request(std::move(request));
#endif
}

bool conversations::fork_conversation(const std::string& id, std::string& forked_id)
{
	forked_id.clear();
	if (!valid_conversation_id(id)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const auto found = std::find_if(history.begin(), history.end(), [&](const ConversationSummary& item) {
		return item.id == id;
	});
	if (found == history.end()) return false;
	static std::uint64_t sequence = 1;
	forked_id = "preview-fork-" + std::to_string(sequence++);
	ConversationSummary forked = *found;
	forked.id = forked_id;
	forked.title = forked.title.empty() ? "Forked conversation" : forked.title + " (fork)";
	forked.created = static_cast<std::int64_t>(sequence);
	forked.pinned = false;
	history.insert(history.begin(), std::move(forked));
	publish_conversation_catalog();
	return true;
#else
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::fork_conversation;
	request.current = capture_conversation_snapshot(true);
	request.target_id = id;
	request.target_revision = id == request.current.id
		? request.current.revision : summary_revision(id);
	request.catalog_generation = catalog_generation;
	return submit_conversation_request(std::move(request));
#endif
}

bool conversations::export_markdown(const std::string& id, const std::string& output_path,
	std::string& error)
{
	error.clear();
	if (!valid_conversation_id(id) || output_path.empty()) {
		error = "The conversation identity or export path is invalid.";
		return false;
	}
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::export_markdown;
	request.current = capture_conversation_snapshot(true);
	request.target_id = id;
	request.target_revision = id == request.current.id
		? request.current.revision : summary_revision(id);
	request.catalog_generation = catalog_generation;
	request.output_path = output_path;
	const bool queued = submit_conversation_request(std::move(request));
	if (!queued) error = "The conversation export could not be queued.";
	return queued;
}

void conversations::process_store_completion(bool allow_deferred)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(allow_deferred);
	return;
#else
	auto submit_deferred_save = [] {
		auto& transaction = conversation_ui_transaction();
		if (!transaction.deferred_save || aida::conversation_store::status().pending)
			return;
		auto request = std::move(*transaction.deferred_save);
		transaction.deferred_save.reset();
		request.catalog_generation = conversations::catalog_generation;
		if (!submit_conversation_request(std::move(request)))
			conversations::persistence_error = "The deferred conversation snapshot could not be queued.";
	};
	auto completion = aida::conversation_store::take_completion();
	if (!completion) {
		if (allow_deferred) submit_deferred_save();
		return;
	}
	if (!completion->success) {
		persistence_error = completion->error.empty()
			? "The conversation transaction failed." : completion->error;
		return;
	}
	const bool replaces_conversation =
		completion->operation == aida::conversation_store::operation_t::switch_conversation ||
		completion->operation == aida::conversation_store::operation_t::new_conversation ||
		completion->operation == aida::conversation_store::operation_t::fork_conversation;
	if (replaces_conversation &&
		(conversation_fingerprint() != conversation_ui_transaction().source_fingerprint ||
		 completion->source_revision != conversation_ui_transaction().source_revision)) {
		persistence_error = "The active conversation changed before the loaded transaction could be published.";
		return;
	}
	std::string publication_error;
	const bool publishes_catalog =
		completion->operation == aida::conversation_store::operation_t::save ||
		completion->operation == aida::conversation_store::operation_t::switch_conversation ||
		completion->operation == aida::conversation_store::operation_t::new_conversation ||
		completion->operation == aida::conversation_store::operation_t::refresh_catalog ||
		completion->operation == aida::conversation_store::operation_t::delete_conversation ||
		completion->operation == aida::conversation_store::operation_t::set_pinned ||
		completion->operation == aida::conversation_store::operation_t::fork_conversation ||
		completion->operation == aida::conversation_store::operation_t::export_markdown;
	bool catalog_published = false;
	bool local_catalog_changed = false;
	auto upsert_local_summary = [&](const aida::conversation_store::summary_t& summary) {
		auto found = std::find_if(history.begin(), history.end(),
			[&](const ConversationSummary& current) { return current.id == summary.id; });
		ConversationSummary replacement{summary.id, summary.title, summary.created,
			summary.message_count, summary.pinned, summary.revision};
		if (found == history.end()) history.push_back(std::move(replacement));
		else *found = std::move(replacement);
		local_catalog_changed = true;
	};
	if (publishes_catalog && completion->catalog_authoritative) {
		if (completion->source_catalog_generation != catalog_generation) {
			publication_error = "Conversation history changed before the catalog result could be published.";
		} else {
			std::vector<ConversationSummary> replacement;
			replacement.reserve(completion->catalog.size());
			for (const auto& summary : completion->catalog) {
				replacement.push_back({summary.id, summary.title, summary.created,
					summary.message_count, summary.pinned, summary.revision});
			}
			history = std::move(replacement);
			publish_conversation_catalog();
			++catalog_generation;
			catalog_published = true;
		}
	}
	if (completion->committed_summary) {
		const auto& committed = *completion->committed_summary;
		if (committed.id == current_id) current_revision = committed.revision;
		if (committed.id == current_id) current_identity_uncommitted = false;
		if (!catalog_published) upsert_local_summary(committed);
	}
	if (completion->loaded) {
		const auto& loaded = *completion->loaded;
		if (completion->operation == aida::conversation_store::operation_t::load_evidence) {
			if (loaded.id == current_id)
				aida::automation_ui::apply_persisted_evidence(loaded.id, loaded.evidence);
		} else {
			if (!catalog_published && !loaded.id.empty()) {
				upsert_local_summary({loaded.id, loaded.title, loaded.created,
					static_cast<int>(loaded.messages.size()), loaded.pinned,
					loaded.revision});
			}
			std::vector<ChatMessage> messages;
			messages.reserve(loaded.messages.size());
			for (const auto& persisted : loaded.messages) {
				ChatMessage message;
				message.text = persisted.text;
				message.thinking_text = persisted.thinking_text;
				message.is_user = persisted.is_user;
				message.has_thinking = persisted.has_thinking;
				message.timestamp = persisted.timestamp;
				message.input_tokens = persisted.input_tokens;
				message.output_tokens = persisted.output_tokens;
				message.cache_read_tokens = persisted.cache_read_tokens;
				message.cache_write_tokens = persisted.cache_write_tokens;
				message.model_id = persisted.model_id;
				messages.push_back(std::move(message));
			}
			g_chat_messages = std::move(messages);
			current_id = loaded.id;
			current_revision = loaded.revision;
			current_identity_uncommitted = false;
			g_chat_buf[0] = '\0';
			g_chat_scroll_to_bottom = true;
			aida::automation_ui::apply_persisted_evidence(loaded.id, loaded.evidence);
			chat_bind_session(loaded.id);
		}
	}
	if (completion->operation == aida::conversation_store::operation_t::delete_conversation &&
		completion->target_id == current_id) {
		g_chat_messages.clear();
		current_id.clear();
		current_revision = 0;
		current_identity_uncommitted = false;
		g_chat_buf[0] = '\0';
		g_chat_scroll_to_bottom = true;
		aida::automation_ui::apply_persisted_evidence({}, {});
		chat_bind_session({});
	}
	if (!catalog_published &&
		completion->operation == aida::conversation_store::operation_t::delete_conversation) {
		const auto previous_size = history.size();
		history.erase(std::remove_if(history.begin(), history.end(),
			[&](const ConversationSummary& summary) {
				return summary.id == completion->target_id;
			}), history.end());
		local_catalog_changed = local_catalog_changed || history.size() != previous_size;
	}
	if (!catalog_published && local_catalog_changed) {
		std::stable_sort(history.begin(), history.end(), [](const auto& left,
			const auto& right) {
			if (left.pinned != right.pinned) return left.pinned > right.pinned;
			if (left.created != right.created) return left.created > right.created;
			return left.id < right.id;
		});
		publish_conversation_catalog();
		++catalog_generation;
	}
	persistence_error = !publication_error.empty() ? std::move(publication_error) :
		completion->partial ? completion->error : std::string{};
	if (allow_deferred) submit_deferred_save();
#endif
}

bool conversations::commit_shutdown(std::string& error)
{
	if (g_chat_messages.empty() && current_id.empty()) {
		error.clear();
		return true;
	}
	aida::conversation_store::request_t request;
	request.operation = aida::conversation_store::operation_t::save;
	request.current = capture_conversation_snapshot(true);
	request.catalog_generation = catalog_generation;
	return aida::conversation_store::commit_lifecycle(std::move(request), error);
}

std::shared_ptr<const std::vector<ConversationSummary>> conversations::catalog_snapshot()
{
	return published_history;
}

void helpers::render_title()
{
	g_render_section = "entry";
	float dt = ImGui::GetIO().DeltaTime;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	{
		auto& preview_controls = aida::preview::controls();
		static std::uint64_t applied_preview_revision = 0;
		if (applied_preview_revision != preview_controls.revision) {
			applied_preview_revision = preview_controls.revision;
			menu_bar::open_menu = preview_controls.open_menu;
			menu_bar::any_open = preview_controls.open_menu >= 0;
			menu_bar::open_request = preview_controls.open_menu >= 0;
			static std::uint64_t preview_view_request_revision = 0;
			if (preview_view_request_revision != preview_controls.revision) {
				preview_view_request_revision = preview_controls.revision;
				static_cast<void>(aida::preview::apply_requested_view(preview_controls));
			}
			if (preview_controls.bottom_tab >= 0 && preview_controls.bottom_tab < static_cast<int>(bottom_tab_t::COUNT)) {
				const char* view_id = preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::mcp_log)
					? "view.mcp_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::driver_log)
					? "view.driver_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::sandbox_log)
					? "view.sandbox_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::terminal)
					? "view.terminal" : "view.output";
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(view_id));
			}
			conversations::browser_open = preview_controls.chat_history_open;
			globals::ui::process_attach_open = preview_controls.process_dialog_open;
			globals::ui::driver_status_open = preview_controls.driver_dialog_open;
			globals::ui::shortcuts_dialog_open = preview_controls.shortcuts_dialog_open;
		}
	}

#endif
	const auto active_workspace_handle = analysis_session::active_workspace();
	restore_workbench_center_view(active_workspace_handle);
	const auto active_workspace_context = disasm_view::capture_workspace(active_workspace_handle);
	globals::ui::load_timer += dt;
	file_menu_deferred::run_pending();
	process_theme_transfer_completion();
	conversations::process_store_completion();
	const auto save_document_as = [](int index) -> file_tabs::save_result_t {
		if (!file_tabs::is_valid_tab_index(index))
			return {false, "The document is no longer open."};
		char buf[MAX_PATH] = {};
		const auto& tab = file_tabs::tabs[file_tabs::tab_index(index)];
		if (!tab.filename.empty())
			strncpy_s(buf, tab.filename.c_str(), _TRUNCATE);
		static const char k_save_as_filter[] = "All files (*.*)\0*.*\0\0";
		if (!trusted_show_save_file(g_hwnd, "Save As", k_save_as_filter, nullptr,
			buf, sizeof(buf), "file_menu_save_as"))
			return {false, "Save As was canceled."};
		return file_tabs::save_tab_as(index, buf);
	};
	aida::ui::application_ui::shell_callbacks_t application_callbacks;
	application_callbacks.open_file = [] {
		file_menu_deferred::request(file_menu_deferred::action_t::open_file);
	};
	application_callbacks.open_folder = [] {
		file_menu_deferred::request(file_menu_deferred::action_t::open_folder);
	};
	application_callbacks.save_as = [save_document_as] {
		const auto result = save_document_as(file_tabs::active_tab);
		file_tabs::shell_save_as_result = result;
	};
	application_callbacks.exit_application = [] {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		POINT cursor{};
		GetCursorPos(&cursor);
		diag::log_tagged_critical_fmt("chrome",
			"file_menu_exit_clicked hwnd=0x%llX cursor=%ld,%ld",
			(unsigned long long)reinterpret_cast<UINT_PTR>(g_hwnd), cursor.x, cursor.y);
#endif
		request_chrome_shutdown_from_render("file_menu_exit", "chrome.file_menu_exit");
	};
	application_callbacks.load_binary = [] {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::apply_open_file();
#else
		std::string fpath = disasm::open_file_dialog(g_hwnd);
		if (fpath.empty()) {
			diag::log_tagged("chrome", "load_pe cancelled");
			return;
		}
		const std::string fpath_copy = fpath;
		const bool posted = aida::ui_thread::post([fpath_copy]() {
			if (!aida::ui_thread::require_owner("analysis_session", "open_session", "load_pe_menu"))
				return;
			const bool ok = analysis_session::open_session(fpath_copy);
			char buf[700];
			if (ok) {
				_snprintf_s(buf, sizeof(buf), _TRUNCATE, "load_pe ok path=%s", fpath_copy.c_str());
			} else {
				const char* err = analysis_session::last_error();
				_snprintf_s(buf, sizeof(buf), _TRUNCATE, "load_pe failed path=%s err=%s",
					fpath_copy.c_str(), err ? err : "(none)");
			}
			diag::log_tagged("chrome", buf);
		}, "analysis_session", "open_session", "load_pe_menu");
		if (!posted) {
			diag::log_tagged_critical_fmt("analysis_session",
				"load_pe_dispatch_failed tid=%lu ui_tid=%lu path=%.260s",
				static_cast<unsigned long>(aida::shell_platform::thread_id()),
				static_cast<unsigned long>(aida::ui_thread::owner_tid()),
				fpath_copy.c_str());
		}
#endif
	};
	application_callbacks.attach_process = [] { globals::ui::process_attach_open = true; };
	application_callbacks.open_settings = [] {
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.settings"));
	};
	application_callbacks.toggle_maximize = [] { shell_toggle_maximize(); };
	application_callbacks.decompile_or_focus_pseudocode_capability =
		[active_workspace_handle, active_workspace_context] {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			return aida::ui::capability_state_t::available();
#endif
			if (active_workspace_handle &&
				active_workspace_handle->identity().target_kind() ==
					aida::analysis::target_kind_t::static_file) {
				aida::workbench::workbench_shell_workspace_context_t context;
				if (!aida::workbench::workbench_shell_runtime_t::instance()
						.workspace_context(active_workspace_handle, context) ||
					!context.pseudocode_document)
					return aida::ui::capability_state_t::unavailable(
						"The active Workbench has no pseudocode provider");
				const auto* active = workbench_document(context.persistence,
					context.persistence.active_document);
				if (!active)
					return aida::ui::capability_state_t::unavailable(
						"Select an analysis document and address first");
				if (active->local_state.selection.has_address ||
					(active->identity.kind == aida::workbench::document_kind_t::pseudocode &&
					 active->identity.has_address))
					return aida::ui::capability_state_t::available();
				const auto& encoded = active->identity.provider_key != "analysis"
					? active->identity.provider_key
					: active->local_state.selection.entity_key;
				const auto parsed = aida::workbench::pseudocode_document::
					parse_pseudocode_entity_locator(encoded);
				const auto canonical = parsed ? aida::workbench::pseudocode_document::
					canonical_pseudocode_entity_locator(*parsed) : std::nullopt;
				return canonical && *canonical == encoded
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"Select an analysis address or managed entity first");
			}
			return pseudocode_view::has_active_tab(active_workspace_context)
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"Open a binary with an available Pseudocode document first");
		};
	application_callbacks.decompile_or_focus_pseudocode =
		[active_workspace_handle, active_workspace_context] {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.pseudocode"));
			return opened.ok()
				? aida::ui::action_handler_result_t::completed()
				: aida::ui::action_handler_result_t::failed(
					"The Pseudocode document could not be activated");
#endif
			if (active_workspace_handle &&
				active_workspace_handle->identity().target_kind() ==
					aida::analysis::target_kind_t::static_file) {
				aida::workbench::workbench_shell_workspace_context_t context;
				const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
					.workspace_context(active_workspace_handle, context);
				const auto* active = loaded ? workbench_document(context.persistence,
					context.persistence.active_document) : nullptr;
				const auto address = active && active->local_state.selection.has_address
					? active->local_state.selection.address
					: active && active->identity.kind ==
						aida::workbench::document_kind_t::pseudocode && active->identity.has_address
						? active->identity.address : 0;
				std::optional<aida::analysis::decompiler_entity_locator_t> managed_locator;
				std::string managed_identity;
				if (active) {
					const auto& encoded = active->identity.provider_key != "analysis"
						? active->identity.provider_key
						: active->local_state.selection.entity_key;
					const auto parsed = aida::workbench::pseudocode_document::
						parse_pseudocode_entity_locator(encoded);
					const auto canonical = parsed ? aida::workbench::pseudocode_document::
						canonical_pseudocode_entity_locator(*parsed) : std::nullopt;
					if (canonical && *canonical == encoded) {
						managed_locator = *parsed;
						managed_identity = *canonical;
					}
				}
				if ((address == 0 && !managed_locator) || !context.pseudocode_document)
					return aida::ui::action_handler_result_t::failed(
						"The active Workbench selection cannot be decompiled");
				aida::workbench::workbench_shell_workspace_context_t activated;
				aida::workbench::workbench_error_t opened;
				if (managed_locator) {
					opened = aida::workbench::workbench_shell_runtime_t::instance()
						.activate_entity_document(active_workspace_handle,
							aida::workbench::document_kind_t::pseudocode,
							managed_identity, activated);
				} else {
					const auto document_address = active && active->identity.kind ==
						aida::workbench::document_kind_t::pseudocode && active->identity.has_address
						? active->identity.address : address;
					opened = aida::workbench::workbench_shell_runtime_t::instance()
						.activate_document(active_workspace_handle,
							aida::workbench::document_kind_t::pseudocode,
							document_address, activated);
				}
				if (!opened || !activated.pseudocode_document)
					return aida::ui::action_handler_result_t::failed(
						"The Pseudocode document could not be activated");
				aida::analysis::decompiler_entity_locator_t locator;
				if (managed_locator) {
					locator = *managed_locator;
				} else {
					locator.address = address;
				}
				std::uint64_t ticket = 0;
				const auto submitted = activated.pseudocode_document->request_async(
					locator, aida::analysis::decompiler_profile_id_t::balanced,
					aida::workbench::pseudocode_document::k_pseudocode_document_default_timeout_ms,
					false, ticket);
				if (submitted) {
					diag::log_tagged_fmt("ui", "workbench_f5 address=0x%llX managed=%d async=1 ticket=%llu",
						static_cast<unsigned long long>(address), managed_locator ? 1 : 0,
						static_cast<unsigned long long>(ticket));
					return aida::ui::action_handler_result_t::completed();
				}
				return aida::ui::action_handler_result_t::failed(
					"The decompiler rejected the active selection");
			}
			if (pseudocode_view::has_active_tab(active_workspace_context)) {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("document.pseudocode")));
				diag::log_tagged("ui", "view_switch to=pseudocode hotkey=F5");
				return aida::ui::action_handler_result_t::completed();
			}
			return aida::ui::action_handler_result_t::failed(
				"No Pseudocode document is available for the active workspace");
		};
	application_callbacks.open_driver_status = [] { globals::ui::driver_status_open = true; };
	application_callbacks.new_chat = [] { conversations::new_chat(); };
	application_callbacks.open_shortcuts = [] {
		globals::ui::shortcuts_dialog_open = true;
		diag::log_tagged("chrome", "shortcuts_popup open=true source=action");
	};
	application_callbacks.open_workspace_save_as = [] {
		open_workspace_save_as_dialog();
	};
	application_callbacks.open_workspace_manager = [] {
		open_workspace_manager_dialog();
	};
	application_callbacks.open_workspace_reset_all = [] {
		open_workspace_reset_all_review();
	};
	application_callbacks.persist_workspace = [] {
		g_sa_settings_request_save();
	};
	application_callbacks.action_executed = [](const char* action_id) {
		diag::log_tagged_fmt("ui", "action_executed id=%s", action_id ? action_id : "<null>");
	};
	aida::ui::application_ui::configure_shell_callbacks(std::move(application_callbacks));
	aida::ui::application_ui::begin_frame();

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static bool bg_completed = false;
	if (!bg_completed && globals::ui::bg_init_done && globals::ui::bg_init_done->load(std::memory_order_acquire)) {
		bg_completed = true;
	}
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const bool runtime_ready = aida::preview::runtime_ready();
#else
	const bool runtime_ready = true;
#endif

	g_render_section = "theme_resolve";
	if (custom_themes::active_custom >= 0 &&
		static_cast<std::size_t>(custom_themes::active_custom) < custom_themes::list.size()) {
		auto& ct = custom_themes::list[static_cast<std::size_t>(custom_themes::active_custom)];
		snprintf(themes::resolved_name_buf, sizeof(themes::resolved_name_buf), "%s", ct.name.c_str());
		themes::resolved.name          = themes::resolved_name_buf;
		themes::resolved.accent        = ImVec4(ct.accent[0], ct.accent[1], ct.accent[2], 1.f);
		themes::resolved.bg_base       = ct.bg_base;
		themes::resolved.panel_bg      = ct.panel_bg;
		themes::resolved.panel_header  = ct.panel_header;
		themes::resolved.title_bar     = ct.title_bar;
		themes::resolved.text_primary  = ct.text_primary;
		themes::resolved.text_secondary= ct.text_secondary;
		themes::resolved.text_dim      = ct.text_dim;
	} else {
		themes::resolved = themes::presets[themes::active];
	}
	globals::ui::accent = aida::ui::resolved().accent;

	{
		static int s_last_applied_theme_idx = -1;
		static int s_last_applied_custom_idx = -2;
		int target_custom = custom_themes::active_custom;
		int target_idx = themes::active;
		if (target_custom != s_last_applied_custom_idx || target_idx != s_last_applied_theme_idx) {
			bool first_apply = (s_last_applied_theme_idx == -1 && s_last_applied_custom_idx == -2);
			s_last_applied_custom_idx = target_custom;
			s_last_applied_theme_idx  = target_idx;
			if (target_custom >= 0 &&
				static_cast<std::size_t>(target_custom) < custom_themes::list.size()) {
				auto& ct = custom_themes::list[static_cast<std::size_t>(target_custom)];
				aida::ui::theme_t base = aida::ui::make_theme_for_index(target_idx);
				base.accent          = ImVec4(ct.accent[0], ct.accent[1], ct.accent[2], 1.f);
				int ar = (int)(ct.accent[0] * 255.f);
				int ag = (int)(ct.accent[1] * 255.f);
				int ab = (int)(ct.accent[2] * 255.f);
				base.accent_u32      = IM_COL32(ar, ag, ab, 255);
				base.accent_hover    = IM_COL32(
					(std::min)(ar + 24, 255),
					(std::min)(ag + 24, 255),
					(std::min)(ab + 24, 255), 255);
				base.accent_dim      = IM_COL32(ar, ag, ab, 130);
				base.accent_glow     = IM_COL32(ar, ag, ab, 50);
				base.accent_grad_top = IM_COL32(
					(std::min)(ar + 18, 255),
					(std::min)(ag + 14, 255),
					(std::min)(ab + 14, 255), 255);
				base.accent_grad_bot = IM_COL32(
					(std::max)(ar - 22, 0),
					(std::max)(ag - 18, 0),
					(std::max)(ab - 18, 0), 255);
				base.border_focus    = IM_COL32(ar, ag, ab, 210);
				base.selection       = IM_COL32(ar, ag, ab, 70);
				base.selection_strong= IM_COL32(ar, ag, ab, 130);
				base.bg_base         = ct.bg_base;
				base.panel_bg        = ct.panel_bg;
				base.panel_header    = ct.panel_header;
				base.title_bar       = ct.title_bar;
				base.text_primary    = ct.text_primary;
				base.text_secondary  = ct.text_secondary;
				base.text_dim        = ct.text_dim;
				base.name            = ct.name;
				if (first_apply) aida::ui::apply_immediate(base);
				else             aida::ui::apply(base);
			} else {
				aida::ui::apply_for_index(target_idx, !first_apply);
			}
		}
	}
	globals::ui::accent = aida::ui::resolved().accent;

	if (!ImGui::GetIO().WantTextInput) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const bool ctrl = ImGui::GetIO().KeyCtrl;
		const bool shift = ImGui::GetIO().KeyShift;
		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_T, false)) {
			test_all_features::post_hotkey_trigger("imgui_ctrl_shift_t");
		}
#endif



	}

	if (!helpers::themes_loaded) {
		helpers::theme_kaneki = nullptr;
		helpers::theme_rias = nullptr;
		helpers::theme_nagi = nullptr;
		helpers::theme_mio = nullptr;
		helpers::themes_loaded = true;
	}


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!g_bg_art_loaded && g_pd3dDevice) {
		icon_loader::load(background, 8640831, &g_bg_art_srv,
			&g_bg_art_w, &g_bg_art_h, false);
		g_bg_art_loaded = true;
	}

	if (!g_aida_logo_loaded && g_pd3dDevice) {
		icon_loader::load(aidalogo, 1273853, &g_aida_logo_srv,
			&g_aida_logo_w, &g_aida_logo_h, false);
		g_aida_logo_loaded = true;
	}

	std::string active_custom_icon_path;
	if (custom_themes::active_custom >= 0 &&
		static_cast<std::size_t>(custom_themes::active_custom) < custom_themes::list.size()) {
		active_custom_icon_path = custom_themes::list[
			static_cast<std::size_t>(custom_themes::active_custom)].icon_file_path;
	} else if (!g_sa_settings.custom_icon_path.empty()) {
		active_custom_icon_path = g_sa_settings.custom_icon_path;
	}

	static std::string s_last_rejected_custom_icon_path;
	static std::string s_last_checked_custom_icon_path;
	static bool s_last_checked_custom_icon_ok = false;
	static uint64_t s_last_checked_custom_icon_ms = 0;
	if (!active_custom_icon_path.empty()) {
		const uint64_t now_ms = static_cast<uint64_t>(aida::shell_platform::tick_ms());
		if (active_custom_icon_path != s_last_checked_custom_icon_path ||
			now_ms - s_last_checked_custom_icon_ms >= 5000) {
			uint64_t icon_file_size = 0;
			DWORD icon_file_attrs = 0;
			DWORD icon_file_error = ERROR_SUCCESS;
			s_last_checked_custom_icon_path = active_custom_icon_path;
			s_last_checked_custom_icon_ms = now_ms;
			s_last_checked_custom_icon_ok = custom_icon_path_render_safe(active_custom_icon_path, icon_file_size, icon_file_attrs, icon_file_error);
			if (!s_last_checked_custom_icon_ok &&
				s_last_rejected_custom_icon_path != active_custom_icon_path) {
				diag::log_tagged_critical_fmt("render",
					"custom_theme_icon_rejected path_len=%zu gle=%lu attrs=0x%08lX size=%llu",
					active_custom_icon_path.size(),
					static_cast<unsigned long>(icon_file_error),
					static_cast<unsigned long>(icon_file_attrs),
					static_cast<unsigned long long>(icon_file_size));
				s_last_rejected_custom_icon_path = active_custom_icon_path;
			}
		}
		if (!s_last_checked_custom_icon_ok)
			active_custom_icon_path.clear();
	}

	if (active_custom_icon_path.empty() && g_custom_theme_icon_srv) {
		g_custom_theme_icon_srv->Release();
		g_custom_theme_icon_srv = nullptr;
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		g_custom_theme_icon_path.clear();
	}

	if (!active_custom_icon_path.empty() &&
	    active_custom_icon_path != g_custom_theme_icon_path &&
	    g_pd3dDevice) {
		if (g_custom_theme_icon_srv) {
			g_custom_theme_icon_srv->Release();
			g_custom_theme_icon_srv = nullptr;
		}
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		if (icon_loader::load_file(active_custom_icon_path.c_str(), &g_custom_theme_icon_srv,
			&g_custom_theme_icon_w, &g_custom_theme_icon_h, false))
			g_custom_theme_icon_path = active_custom_icon_path;
		else
			g_custom_theme_icon_path.clear();
	}
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool loading = aida::preview::loading();
#else
	bool loading = !bg_completed || globals::ui::load_timer < 3.0f;
#endif

	g_render_section = loading ? "loading_screen" : "post_loading";
	{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool s_loading_wait_logged = false;
		static float s_loading_wait_last_log = 0.f;
		if (loading && globals::ui::load_timer >= 5.0f &&
		    (!s_loading_wait_logged || (globals::ui::load_timer - s_loading_wait_last_log) >= 5.0f)) {
			s_loading_wait_logged = true;
			s_loading_wait_last_log = globals::ui::load_timer;
			bool bg_done_value = globals::ui::bg_init_done &&
				globals::ui::bg_init_done->load(std::memory_order_acquire);
			diag::log_tagged_critical_fmt("render",
				"loading_screen_wait timer=%.2f bg_completed=%d bg_done_ptr=%d bg_done=%d bg_step=%d bg_total=%d",
				globals::ui::load_timer,
				bg_completed ? 1 : 0,
				globals::ui::bg_init_done ? 1 : 0,
				bg_done_value ? 1 : 0,
				globals::ui::bg_init_step.load(std::memory_order_acquire),
				globals::ui::bg_init_total.load(std::memory_order_acquire));
		}
		if (!loading) {
			s_loading_wait_logged = false;
			s_loading_wait_last_log = globals::ui::load_timer;
		}
#endif
	}

	if (!loading)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		globals::ui::window_w = ImGui::GetIO().DisplaySize.x > 0.f ? ImGui::GetIO().DisplaySize.x : globals::ui::window_w;
		globals::ui::window_h = ImGui::GetIO().DisplaySize.y > 0.f ? ImGui::GetIO().DisplaySize.y : globals::ui::window_h;
#else
		float tw, th;
		if (!globals::ui::welcome_done) {
			tw = 560.f; th = 360.f;
		} else {
			MONITORINFO mi = { sizeof(mi) };
			GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
			tw = static_cast<float>(mi.rcWork.right - mi.rcWork.left) * 0.75f;
			th = static_cast<float>(mi.rcWork.bottom - mi.rcWork.top) * 0.75f;
		}


		static bool initial_grow_done = false;
		if (!initial_grow_done) {
			if (globals::ui::welcome_done && runtime_ready) {
				initial_grow_done = true;
				MONITORINFO mi2 = { sizeof(mi2) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi2);
				float mw = static_cast<float>(mi2.rcWork.right - mi2.rcWork.left);
				float mh = static_cast<float>(mi2.rcWork.bottom - mi2.rcWork.top);
				float normal_w = mw * 0.75f;
				float normal_h = mh * 0.75f;
				if (normal_w < 1000.f && mw >= 1000.f) normal_w = (std::min)(mw, 1000.f);
				if (normal_h < 600.f && mh >= 600.f) normal_h = (std::min)(mh, 600.f);
				int restore_x = static_cast<int>(static_cast<float>(mi2.rcWork.left) + (mw - normal_w) * 0.5f);
				int restore_y = static_cast<int>(static_cast<float>(mi2.rcWork.top) + (mh - normal_h) * 0.5f);
				globals::ui::pre_max_x = static_cast<float>(restore_x);
				globals::ui::pre_max_y = static_cast<float>(restore_y);
				globals::ui::pre_max_w = normal_w;
				globals::ui::pre_max_h = normal_h;
				WINDOWPLACEMENT wp = { sizeof(wp) };
				if (::GetWindowPlacement(g_hwnd, &wp)) {
					wp.flags = 0;
					wp.showCmd = SW_SHOWMAXIMIZED;
					wp.rcNormalPosition.left   = restore_x;
					wp.rcNormalPosition.top    = restore_y;
					wp.rcNormalPosition.right  = restore_x + static_cast<int>(normal_w);
					wp.rcNormalPosition.bottom = restore_y + static_cast<int>(normal_h);
					::SetWindowPlacement(g_hwnd, &wp);
				}
				{
					RECT cr{};
					::GetClientRect(g_hwnd, &cr);
					float cw = static_cast<float>(cr.right - cr.left);
					float chh = static_cast<float>(cr.bottom - cr.top);
					if (cw >= 200.f && chh >= 200.f) {
						globals::ui::window_w = cw;
						globals::ui::window_h = chh;
					} else {
						globals::ui::window_w = normal_w;
						globals::ui::window_h = normal_h;
					}
					static bool disk_initial_geometry_logged = false;
					if (!disk_initial_geometry_logged) {
						disk_initial_geometry_logged = true;
						diag::log_tagged_critical_fmt("render",
							"disk_initial_ide_geometry target=%d,%d work=%d,%d cw=%d ch=%d maximized=1",
							static_cast<int>(normal_w),
							static_cast<int>(normal_h),
							static_cast<int>(mw),
							static_cast<int>(mh),
							static_cast<int>(cw),
							static_cast<int>(chh));
					}
				}
			} else {
				float spd = 12.f;
				float dw = tw - globals::ui::window_w;
				float dh = th - globals::ui::window_h;
				globals::ui::window_w += dw * std::min(spd * dt, 1.f);
				globals::ui::window_h += dh * std::min(spd * dt, 1.f);


				if (std::abs(dw) < 2.f) globals::ui::window_w = tw;
				if (std::abs(dh) < 2.f) globals::ui::window_h = th;

				if (globals::ui::load_timer > 5.0f && !globals::ui::welcome_done) {
					globals::ui::window_w = tw;
					globals::ui::window_h = th;
				}
			}
		}
#endif
	}


	bool welcome_ready = !loading && globals::ui::window_w >= 470.f && globals::ui::window_h >= 270.f;
	bool ui_ready      = globals::ui::window_w >= 1000.f && globals::ui::window_h >= 600.f;

	if (ui_ready && globals::ui::welcome_done && runtime_ready)
	{
		static float raw = 0.f;
		raw += dt;
		if (raw > 1.f) raw = 1.f;
		globals::ui::ui_alpha = raw * raw;
	}


	const bool ide_surface = globals::ui::welcome_done && runtime_ready;
	if (ide_surface)
		aida::ui::ide_shell::render_primary_surfaces();
	if (!ide_surface) {
		ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(globals::ui::window_w, globals::ui::window_h));
	}
	ImGuiWindowFlags legacy_root_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
#if defined(IMGUI_HAS_DOCK)
	legacy_root_flags |= ImGuiWindowFlags_NoDocking;
#endif
	if (ide_surface)
		aida::ui::ide_shell::begin_global_chrome_surface();
	else
		ImGui::Begin("##main", nullptr, legacy_root_flags);

	{
		ImVec2 bgwp = ImGui::GetWindowPos();
		const ImVec2 surface_size = ImGui::GetWindowSize();
		const auto& th = aida::ui::resolved();
		ImGui::GetWindowDrawList()->AddRectFilled(
			bgwp,
			ImVec2(bgwp.x + surface_size.x, bgwp.y + surface_size.y),
			th.bg_base, 8.f);
	}

	if (!globals::ui::welcome_done && (loading || !welcome_ready || fadeout > 0.f))
	{
		const auto& th = aida::ui::resolved();
		ImVec2 wp = ImGui::GetWindowPos();
		float ww_l = globals::ui::window_w;
		float wh_l = globals::ui::window_h;
		float cx   = wp.x + ww_l * 0.5f;
		float cy   = wp.y + wh_l * 0.5f - 8.f;
		ImDrawList* dl = ImGui::GetWindowDrawList();

		if (loading) {
			fadeout = 1.f;
		} else {
			fadeout -= dt * 1.5f;
			if (fadeout < 0.f) fadeout = 0.f;
		}
		float vis = loading ? 1.f : fadeout;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
			th.bg_base, 14.f);

		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float aspect_img = (float)g_bg_art_w / (float)g_bg_art_h;
			float aspect_win = ww_l / wh_l;
			float bg_w, bg_h;
			if (aspect_img > aspect_win) {
				bg_h = wh_l;
				bg_w = bg_h * aspect_img;
			} else {
				bg_w = ww_l;
				bg_h = bg_w / aspect_img;
			}
			float bg_x = wp.x + (ww_l - bg_w) * 0.5f;
			float bg_y = wp.y + (wh_l - bg_h) * 0.5f;
			ImU32 bg_tint = aida::ui::with_alpha(IM_COL32_WHITE, 0.42f * vis);
			dl->AddImageRounded((ImTextureID)g_bg_art_srv,
				ImVec2(bg_x, bg_y), ImVec2(bg_x + bg_w, bg_y + bg_h),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f),
				bg_tint, 14.f);
			dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
				aida::ui::with_alpha(th.bg_base, 0.55f * vis), 14.f);
		}

		float aura_r = ww_l * 0.55f;
		ImU32 aura = aida::ui::with_alpha(th.accent_glow, 0.45f * vis);
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 14.f;
			float fa = (1.f - (float)i / 5.f) * 0.55f;
			dl->AddCircleFilled(ImVec2(cx, cy), rr, aida::ui::with_alpha(aura, fa), 64);
		}

		float reveal_t = std::min(globals::ui::load_timer / 0.480f, 1.f);
		float reveal_eased = aida::motion::ease::out_back(reveal_t);
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 80.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, vis), nullptr);

		float logo_size = 96.f;
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float scale = reveal_eased;
			float ls = logo_size * (0.6f + 0.4f * scale);
			float lcx = cx;
			float lcy = cy - 18.f;
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, vis * (0.85f + 0.15f * pulse));
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(lcx - lw * 0.5f, lcy - lh * 0.5f),
				ImVec2(lcx + lw * 0.5f, lcy + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(
				dl, ImVec2(cx, cy - 18.f), logo_size,
				reveal_eased, pulse, vis);
		}

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_scale = 1.0f;
		float wm_size  = 32.f * wm_scale;
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, wm_scale);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + logo_size * 0.5f + 12.f;
		float wm_reveal = std::min((globals::ui::load_timer - 0.18f) / 0.62f, 1.f);
		if (wm_reveal < 0.f) wm_reveal = 0.f;
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), wm_scale,
			display_font, wm_reveal, vis);

		float tag_a = std::min(std::max(globals::ui::load_timer - 1.6f, 0.f) / 0.5f, 1.f) * vis;
		if (tag_a > 0.01f) {
			const char* tag = "Reverse engineering, reimagined.";
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float ts_x = body->CalcTextSizeA(18.f, FLT_MAX, 0.f, tag).x;
			dl->AddText(body, 18.f,
				ImVec2(cx - ts_x * 0.5f, wm_y + wm_size + 18.f),
				aida::ui::with_alpha(th.text_secondary, tag_a), tag);
		}

		float bar_w = std::min(ww_l * 0.55f, 280.f);
		float bar_h = 3.f;
		float bar_x = cx - bar_w * 0.5f;
		float bar_y = wp.y + wh_l - 60.f;

		int total_steps = globals::ui::bg_init_total.load(std::memory_order_acquire);
		int cur_step    = globals::ui::bg_init_step.load(std::memory_order_acquire);
		if (total_steps < 1) total_steps = 1;
		if (cur_step > total_steps) cur_step = total_steps;
		float prog = (float)cur_step / (float)total_steps;

		static float anim_prog = 0.f;
		anim_prog += (prog - anim_prog) * std::min(8.f * dt, 1.f);

		dl->AddRectFilled(ImVec2(bar_x, bar_y),
			ImVec2(bar_x + bar_w, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, 0.85f * vis), bar_h * 0.5f);

		float fw = bar_w * anim_prog;
		if (fw > 1.f) {
			dl->AddRectFilledMultiColor(
				ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis));

			float sweep_period = 1.4f;
			float ph = fmodf(aida::ui::clock::seconds() / sweep_period, 1.f);
			float sx = bar_x + fw * ph - fw * 0.18f;
			float sw = fw * 0.36f;
			if (sw > 4.f) {
				dl->PushClipRect(ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h), true);
				dl->AddRectFilledMultiColor(
					ImVec2(sx, bar_y), ImVec2(sx + sw * 0.5f, bar_y + bar_h),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0));
				dl->AddRectFilledMultiColor(
					ImVec2(sx + sw * 0.5f, bar_y), ImVec2(sx + sw, bar_y + bar_h),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis));
				dl->PopClipRect();
			}
		}

		static const char* k_phase_labels[] = {
			"Bootstrapping",
			"Initializing AiDA runtime core",
			"Probing network surface",
			"Arming memory scanner",
			"Spinning up MITM proxy",
			"Loading script engine",
			"Ready"
		};
		int phase_idx = cur_step;
		if (phase_idx < 0) phase_idx = 0;
		if (phase_idx > 6) phase_idx = 6;

		static int last_phase = -1;
		static aida::ui::transition_t phase_swap;
		static const char* prev_phase_label = k_phase_labels[0];
		static const char* cur_phase_label  = k_phase_labels[0];
		if (phase_idx != last_phase) {
			prev_phase_label = cur_phase_label;
			cur_phase_label  = k_phase_labels[phase_idx];
			phase_swap.start(0.140f, aida::motion::ease::out_cubic);
			last_phase = phase_idx;
		}
		phase_swap.tick(dt);
		float swap_e = phase_swap.eased();

		ImFont* cap = aida::ui::fonts::body();
		if (!cap) cap = ImGui::GetFont();
		float cap_size = aida::ui::fonts::size_or(cap, 16.f);
		float ph_y = bar_y - cap_size - 8.f;

		ImU32 ph_col = aida::ui::with_alpha(th.text_secondary, vis);
		if (!phase_swap.is_finished() && prev_phase_label) {
			float prev_a = (1.f - swap_e) * vis;
			float prev_y = ph_y - swap_e * 6.f;
			ImVec2 ts_p = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, prev_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_p.x * 0.5f, prev_y),
				aida::ui::with_alpha(th.text_secondary, prev_a), prev_phase_label);

			float cur_y = ph_y + (1.f - swap_e) * 6.f;
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, cur_y),
				aida::ui::with_alpha(th.text_secondary, swap_e * vis), cur_phase_label);
		} else {
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, ph_y), ph_col, cur_phase_label);
		}

		char step_buf[32];
		snprintf(step_buf, sizeof(step_buf), "%d / %d", cur_step, total_steps);
		float step_sz = cap_size;
		ImVec2 sb_ts = cap->CalcTextSizeA(step_sz, FLT_MAX, 0.f, step_buf);
		dl->AddText(cap, step_sz, ImVec2(cx + bar_w * 0.5f - sb_ts.x, bar_y + bar_h + 12.f),
			aida::ui::with_alpha(th.text_dim, vis), step_buf);

		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool preview_loading_dragging = false;
		bool preview_loading_drag = ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f);
		if (preview_loading_drag && !preview_loading_dragging)
			aida::preview::record(aida::preview::shell_action_t::move_window, "loading_surface");
		preview_loading_dragging = preview_loading_drag;
		#else
		static POINT drag_start_wnd   = {};
		static POINT drag_start_mouse = {};
		static bool  dragging  = false;
		static bool  last_lmb  = false;
		bool lmb = shell_left_mouse_down();
		if (lmb && !last_lmb) {
			POINT cp; GetCursorPos(&cp);
			RECT wr; GetWindowRect(g_hwnd, &wr);
			if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom) {
				dragging = true;
				drag_start_mouse = cp;
				drag_start_wnd = { wr.left, wr.top };
			}
		}
		if (!lmb) dragging = false;
		if (dragging) {
			POINT cp; GetCursorPos(&cp);
			int nx = drag_start_wnd.x + (cp.x - drag_start_mouse.x);
			int ny = drag_start_wnd.y + (cp.y - drag_start_mouse.y);
			shell_move_window(nx, ny);
		}
		last_lmb = lmb;
		#endif

		if (!loading && fadeout <= 0.001f && !globals::ui::welcome_done) {
			globals::ui::welcome_done = true;
			globals::ui::ui_alpha = 0.f;
			globals::ui::welcome_timer = 3.5f;
		}

		ImGui::End();
		return;
	}


	if (!globals::ui::welcome_done)
	{
		globals::ui::welcome_done = true;
		globals::ui::ui_alpha = 0.f;
		globals::ui::welcome_timer = 3.5f;
		const auto& th = aida::ui::resolved();
		globals::ui::welcome_timer += dt;
		if (globals::ui::welcome_timer >= 3.5f) { globals::ui::welcome_done = true; globals::ui::ui_alpha = 0.f; }

		ImVec2      wp  = ImGui::GetWindowPos();
		ImDrawList* dl  = ImGui::GetWindowDrawList();
		float       t   = globals::ui::welcome_timer;
		float       ww  = globals::ui::window_w;
		float       wh  = globals::ui::window_h;
		float       cx  = wp.x + ww * 0.5f;
		float       cy  = wp.y + wh * 0.5f - 4.f;

		float fade_in  = std::min(t / 0.6f, 1.f);
		float fade_out = t > 2.6f ? std::max(0.f, 1.f - (t - 2.6f) / 0.9f) : 1.f;
		float base_a   = fade_in * fade_out;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh), th.bg_base, 14.f);

		float aura_r = ww * 0.45f;
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 18.f;
			float fa = (1.f - (float)i / 5.f) * 0.40f * base_a;
			dl->AddCircleFilled(ImVec2(cx, cy),
				rr, aida::ui::with_alpha(th.accent_glow, fa), 64);
		}

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 92.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, base_a), nullptr);

		float reveal = aida::motion::ease::out_back(std::min(t / 0.480f, 1.f));
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		aida::ui::brand::render_logomark(dl, ImVec2(cx, cy - 26.f), 84.f,
			reveal, pulse, base_a);

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, 1.0f);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + 38.f;
		float wm_reveal = std::min(std::max(t - 0.18f, 0.f) / 0.62f, 1.f);
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), 1.0f,
			display_font, wm_reveal, base_a);

		float sub_a = std::min(std::max(t - 0.7f, 0.f) / 0.5f, 1.f) * fade_out;
		if (sub_a > 0.01f)
		{
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float tag_sz = aida::ui::fonts::size_or(body, 16.f);
			const char* tagline = "Reverse engineering, reimagined.";
			ImVec2 ts_t = body->CalcTextSizeA(tag_sz, FLT_MAX, 0.f, tagline);
			dl->AddText(body, tag_sz,
				ImVec2(cx - ts_t.x * 0.5f, wm_y + 32.f + tag_sz),
				aida::ui::with_alpha(th.text_secondary, sub_a), tagline);

			float msg_a = std::min(std::max(t - 1.4f, 0.f) / 0.5f, 1.f) * fade_out;
			if (msg_a > 0.01f)
			{
				const char* msg = "Your session is ready.";
				float msg_sz = aida::ui::fonts::size_or(body, 16.f);
				ImVec2 ts_m = body->CalcTextSizeA(msg_sz, FLT_MAX, 0.f, msg);
				dl->AddText(body, msg_sz,
					ImVec2(cx - ts_m.x * 0.5f, wm_y + 32.f + tag_sz + 28.f),
					aida::ui::with_alpha(th.text_dim, msg_a), msg);
			}
		}

		ImGui::End();
		return;
	}


	g_render_section = "ide_layout";
	float a = globals::ui::ui_alpha;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (aida::preview::controls().settle_animations) {
		a = 1.f;
		globals::ui::ui_alpha = 1.f;
	}
#endif


	const ImGuiViewport* shell_viewport = ImGui::GetMainViewport();
	const float shell_dpi_scale = shell_viewport && shell_viewport->DpiScale > 0.0f
		? shell_viewport->DpiScale : 1.0f;
	const auto metrics = aida::ui::shell_metrics(shell_dpi_scale);
	const float pad      = metrics.pad;
	const float gap      = metrics.gap;
	const float title_h  = metrics.title_h;
	const float menu_h   = metrics.menu_h;
	float ww = ide_surface ? ImGui::GetWindowSize().x : globals::ui::window_w;

	g_render_section = "title_bar";
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);


	{
		ImVec2 wp   = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th_tb = aida::ui::resolved();

		ImVec2 tb_a(wp.x, wp.y);
		ImVec2 tb_b(wp.x + ww, wp.y + title_h);

		aida::ui::blur::layer_request_t tb_req;
		tb_req.pos = tb_a;
		tb_req.size = ImVec2(ww, title_h);
		tb_req.radius = 0.f;
		tb_req.strength = 0.55f;
		tb_req.alpha = a;
		aida::ui::blur::schedule(tb_req);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.title_bar, a), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.glass_tint, a * 0.5f), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		dl->AddLine(ImVec2(wp.x, wp.y + title_h), ImVec2(wp.x + ww, wp.y + title_h),
			aida::ui::with_alpha(th_tb.border_subtle, a));

		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		ImVec2 logo_c(wp.x + pad + metrics.title_logo * 0.5f + gap, wp.y + title_h * 0.5f);
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float ls = metrics.title_logo * (0.95f + 0.05f * pulse);
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, a);
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(logo_c.x - lw * 0.5f, logo_c.y - lh * 0.5f),
				ImVec2(logo_c.x + lw * 0.5f, logo_c.y + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(dl, logo_c, metrics.title_logo, 1.0f, pulse, a);
		}

		ImFont* h2f = aida::ui::fonts::h2();
		if (!h2f) h2f = ImGui::GetFont();
		const char* app_name = "AiDA";
		const float title_font_sz = aida::ui::fonts::size_or(h2f, metrics.title_font);
		const float title_x = logo_c.x + metrics.title_logo * 0.5f + gap * 2.f;
		ImVec2 name_ts = h2f->CalcTextSizeA(title_font_sz, FLT_MAX, 0.f, app_name);
		dl->AddText(h2f, title_font_sz,
			ImVec2(title_x, wp.y + (title_h - title_font_sz) * 0.5f),
			aida::ui::with_alpha(th_tb.text_primary, a), app_name);

		{
			ImFont* body = aida::ui::fonts::caption();
			if (!body) body = ImGui::GetFont();
			const float bc_font_sz = aida::ui::fonts::size_or(body, metrics.caption_font);
			float bc_x = title_x + name_ts.x + gap * 2.f;
			float bc_y = wp.y + (title_h - bc_font_sz) * 0.5f;
			const float status_reserved_w = aida::ui::scale_px(164.f, metrics.scale);
			const float breadcrumb_clip_right = wp.x + ww - pad - gap * 10.f -
				metrics.title_control * 4.f - status_reserved_w;
			dl->PushClipRect(ImVec2(bc_x, wp.y),
				ImVec2((std::max)(bc_x, breadcrumb_clip_right), wp.y + title_h), true);
			std::vector<std::string> segs;
			const auto editor_document = code_editor_widget::document_state();
			if (active_workspace_context)
				segs.push_back(active_workspace_context.workspace->identity().bin_name());
			if (editor_document.active && !editor_document.filename.empty())
				segs.push_back(editor_document.filename);
			const auto focused_view = aida::ui::application_views::registry().focused_instance();
			if (focused_view) {
				const auto* descriptor = aida::ui::application_views::registry()
					.find_descriptor(focused_view->view);
				if (descriptor &&
					(focused_view->view.value() != "document.code" ||
					 editor_document.filename.empty()))
					segs.push_back(descriptor->display_name);
			}
			float sep_w = body->CalcTextSizeA(bc_font_sz, FLT_MAX, 0.f, ">").x;
			for (size_t si = 0; si < segs.size(); ++si) {
				dl->AddText(body, bc_font_sz, ImVec2(bc_x, bc_y),
					aida::ui::with_alpha(th_tb.text_dim, a), ">");
				bc_x += sep_w + gap * 1.5f;
				ImVec2 ss = body->CalcTextSizeA(bc_font_sz, FLT_MAX, 0.f, segs[si].c_str());
				ImVec2 sa(bc_x - gap, bc_y - 2.f);
				ImVec2 sb_pt(bc_x + ss.x + gap, bc_y + ss.y + 2.f);
				bool h_seg = ImGui::IsMouseHoveringRect(sa, sb_pt);
				if (h_seg) dl->AddRectFilled(sa, sb_pt, aida::ui::with_alpha(th_tb.hover_wash, a), metrics.control_radius);
				ImU32 col = (si == segs.size() - 1) ? th_tb.text_primary : th_tb.text_secondary;
				dl->AddText(body, bc_font_sz, ImVec2(bc_x, bc_y - (h_seg ? 1.f : 0.f)),
					aida::ui::with_alpha(col, a), segs[si].c_str());
				bc_x += ss.x + gap * 2.f;
			}
			dl->PopClipRect();
		}

		auto draw_ctl = [&](float right_offset, const char* tag) -> std::pair<ImVec2, ImVec2> {
			float ctl_sz = metrics.title_control;
			ImVec2 cp(wp.x + ww - right_offset - ctl_sz, wp.y + (title_h - ctl_sz) * 0.5f);
			ImVec2 ce(cp.x + ctl_sz, cp.y + ctl_sz);
			(void)tag;
			return {cp, ce};
		};

		float ctl_off = pad + gap;

		auto [close_a, close_b] = draw_ctl(ctl_off, "x");
		bool close_hov = ImGui::IsMouseHoveringRect(close_a, close_b);
		static aida::ui::hover_state_t close_h;
		float chv = close_h.tick(close_hov, dt, aida::motion::spring::balanced);
		if (chv > 0.01f) {
			dl->AddRectFilled(close_a, close_b,
				aida::ui::with_alpha(th_tb.error, 0.20f * chv * a), metrics.control_radius);
		}
		ImVec2 xc((close_a.x + close_b.x) * 0.5f, (close_a.y + close_b.y) * 0.5f);
		float xr = 5.f;
		ImU32 xcol = aida::ui::mix(th_tb.text_primary, aida::ui::lighten(th_tb.error, 30), chv);
		float xth = 1.7f + chv * 0.6f;
		dl->AddLine(ImVec2(xc.x - xr, xc.y - xr), ImVec2(xc.x + xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		dl->AddLine(ImVec2(xc.x + xr, xc.y - xr), ImVec2(xc.x - xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		if (close_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			POINT cursor{};
			GetCursorPos(&cursor);
			ImVec2 mouse = ImGui::GetIO().MousePos;
			diag::log_tagged_critical_fmt("chrome",
				"close_button_clicked hwnd=0x%llX cursor=%ld,%ld mouse=%.1f,%.1f rect=%.1f,%.1f,%.1f,%.1f blocked=%d",
				(unsigned long long)reinterpret_cast<UINT_PTR>(g_hwnd),
				cursor.x,
				cursor.y,
				mouse.x,
				mouse.y,
				close_a.x,
				close_a.y,
				close_b.x,
				close_b.y,
				ui_input_gate::chrome_input_blocked() ? 1 : 0);
#endif
			const auto requested = file_tabs::request_exit_review();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (!requested.succeeded)
				diag::log_tagged_critical_fmt("chrome",
					"close_button_review_rejected reason=%.512s",
					requested.detail.c_str());
#else
			static_cast<void>(requested);
#endif
		}
		ctl_off += metrics.title_control + gap * 1.5f;

		auto [max_a, max_b] = draw_ctl(ctl_off, "m");
		bool max_hov = ImGui::IsMouseHoveringRect(max_a, max_b);
		static aida::ui::hover_state_t max_h;
		float mhv = max_h.tick(max_hov, dt, aida::motion::spring::balanced);
		if (mhv > 0.01f) {
			dl->AddRectFilled(max_a, max_b,
				aida::ui::with_alpha(th_tb.hover_wash, mhv * a), metrics.control_radius);
		}
		ImVec2 mc((max_a.x + max_b.x) * 0.5f, (max_a.y + max_b.y) * 0.5f);
		float mr = 5.f;
		ImU32 mcol = th_tb.text_primary;
		if (globals::ui::maximized) {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr + 1.5f), ImVec2(mc.x + mr - 1.5f, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
			dl->AddRect(ImVec2(mc.x - mr + 1.5f, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr - 1.5f),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		} else {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		}
		if (max_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			shell_toggle_maximize();
		}
		ctl_off += metrics.title_control + gap * 1.5f;

		auto [min_a, min_b] = draw_ctl(ctl_off, "n");
		bool min_hov = ImGui::IsMouseHoveringRect(min_a, min_b);
		static aida::ui::hover_state_t min_hh;
		float mnv = min_hh.tick(min_hov, dt, aida::motion::spring::balanced);
		if (mnv > 0.01f) {
			dl->AddRectFilled(min_a, min_b,
				aida::ui::with_alpha(th_tb.hover_wash, mnv * a), metrics.control_radius);
		}
		ImU32 mncol = th_tb.text_primary;
		float minc_x = (min_a.x + min_b.x) * 0.5f;
		float minc_y = (min_a.y + min_b.y) * 0.5f + mnv * 2.f;
		dl->AddLine(ImVec2(minc_x - 5.f, minc_y), ImVec2(minc_x + 5.f, minc_y),
			aida::ui::with_alpha(mncol, a), 1.7f);
		if (min_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			shell_minimize();
		ctl_off += metrics.title_control + gap * 3.f;


		{
			float toggle_sz = metrics.title_control;
			ImVec2 tgl_a(wp.x + ww - ctl_off - toggle_sz, wp.y + (title_h - toggle_sz) * 0.5f);
			ImVec2 tgl_b(tgl_a.x + toggle_sz, tgl_a.y + toggle_sz);
			bool tgl_hov = ImGui::IsMouseHoveringRect(tgl_a, tgl_b);
			static aida::ui::hover_state_t tgl_h;
			float thv = tgl_h.tick(tgl_hov, dt, aida::motion::spring::balanced);
			if (thv > 0.01f) {
				dl->AddRectFilled(tgl_a, tgl_b,
					aida::ui::with_alpha(th_tb.hover_wash, thv * a), metrics.control_radius);
			}
			ImU32 tcol = aida::ui::mix(th_tb.text_secondary, th_tb.text_primary, thv);
			ImVec2 tcc((tgl_a.x + tgl_b.x) * 0.5f, (tgl_a.y + tgl_b.y) * 0.5f);
			bool currently_dark = aida::ui::is_dark();
			if (currently_dark) {
				dl->AddCircle(ImVec2(tcc.x, tcc.y), 6.f, aida::ui::with_alpha(tcol, a), 16, 1.5f);
				for (int ray = 0; ray < 8; ++ray) {
					float angle = static_cast<float>(ray) * 0.785398f;
					float cx = cosf(angle), cy = sinf(angle);
					dl->AddLine(ImVec2(tcc.x + cx * 8.f, tcc.y + cy * 8.f),
						ImVec2(tcc.x + cx * 9.5f, tcc.y + cy * 9.5f),
						aida::ui::with_alpha(tcol, a), 1.5f);
				}
			} else {
				dl->PathArcTo(ImVec2(tcc.x - 1.f, tcc.y), 7.f, 5.5f, 9.95f, 16);
				dl->PathStroke(aida::ui::with_alpha(tcol, a), 0, 1.5f);
			}
			if (tgl_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				int idx = g_sa_settings.active_theme_idx;
				int new_idx;
				switch (idx) {
					case 0: new_idx = 1; break;
					case 1: new_idx = 0; break;
					case 2: new_idx = 3; break;
					case 3: new_idx = 2; break;
					default: new_idx = currently_dark ? 1 : 0; break;
				}
				themes::active = new_idx;
				custom_themes::active_custom = -1;
				themes::changed = true;
				g_sa_settings.active_theme_idx = new_idx;
				g_sa_settings.active_custom_theme_idx = -1;
				aida::ui::apply_for_index(new_idx, true);
				g_sa_settings_request_save();
			}
			if (tgl_hov) ImGui::SetTooltip("Toggle dark/light mode");
			ctl_off += toggle_sz + gap * 2.f;
		}

		{
			const std::string_view status_text = aida::ui::workspace_layout::active_preset_name();
			const float status_w = aida::ui::scale_px(164.f, metrics.scale);
			const float status_h = aida::ui::scale_px(24.f, metrics.scale);
			ImVec2 status_b(wp.x + ww - ctl_off,
				wp.y + (title_h + status_h) * 0.5f);
			ImVec2 status_a(status_b.x - status_w, status_b.y - status_h);
			dl->AddRectFilled(status_a, status_b,
				aida::ui::with_alpha(th_tb.bg_elevated, 0.72f * a), status_h * 0.5f);
			dl->AddRect(status_a, status_b,
				aida::ui::with_alpha(th_tb.border_subtle, 0.92f * a), status_h * 0.5f);
			const ImU32 status_color = active_workspace_context
				? th_tb.accent_u32 : th_tb.success;
			dl->AddCircleFilled(ImVec2(status_a.x + 12.f, status_a.y + status_h * 0.5f),
				3.f, aida::ui::with_alpha(status_color, a), 16);
			ImFont* status_font = aida::ui::fonts::caption();
			if (!status_font) status_font = ImGui::GetFont();
			const float status_fs = aida::ui::fonts::size_or(status_font, metrics.caption_font);
			dl->AddText(status_font, status_fs,
				ImVec2(status_a.x + 22.f, status_a.y + (status_h - status_fs) * 0.5f),
				aida::ui::with_alpha(th_tb.text_secondary, a), status_text.data(),
				status_text.data() + status_text.size());
			ctl_off += status_w + gap * 2.f;
		}

		{
			static int theme_popup_open_frame = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static std::uint64_t preview_theme_revision = 0;
			if (aida::preview::controls().theme_popup_open && preview_theme_revision != aida::preview::controls().revision) {
				preview_theme_revision = aida::preview::controls().revision;
				theme_popup_open_frame = ImGui::GetFrameCount();
				ImGui::OpenPopup("##theme_popup");
			}
#endif
			ImVec2 th_pos(wp.x + ww - 200.f, wp.y + 8.f);
			(void)th_pos;
			ImVec2 fake_pos(wp.x + ww - ctl_off - metrics.title_control, wp.y + (title_h - metrics.title_control) * 0.5f);
			(void)fake_pos;
			bool dummy_hov = false;
			(void)dummy_hov;
			(void)theme_popup_open_frame;

			{
				float popup_x = std::min(th_pos.x - 100.f, wp.x + ww - 220.f - 8.f);
				popup_x = std::max(wp.x + 8.f, popup_x);
				ImGui::SetNextWindowPos(ImVec2(popup_x, wp.y + title_h + 2.f));
				ImGui::SetNextWindowBgAlpha(0.96f);
			const auto& th_tp = aida::ui::resolved();

			if (ImGui::BeginPopup("##theme_popup",
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
				{
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					float item_w = 200.f;
					float item_h = 22.f;
					bool popup_clicks_ok = (ImGui::GetFrameCount() > theme_popup_open_frame + 1);


					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.text_secondary), "Built-in Themes");
					ImGui::Spacing();
					for (int ti = 0; ti < themes::count; ti++) {
						auto& tp = themes::presets[ti];
						bool is_active = (custom_themes::active_custom < 0 && themes::active == ti);

						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);

						bool ti_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (ti_hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						if (is_active) pdl->AddRectFilled(rmin, rmax, th_tp.selection, 4.f);

						pdl->AddCircleFilled(
							ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
							IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255),
								(int)(tp.accent.z*255), 255));

						ImU32 name_col = is_active
							? IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255), (int)(tp.accent.z*255), 255)
							: th_tp.text_secondary;
						pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							name_col, tp.name);

						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && ti_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							themes::active = ti;
							custom_themes::active_custom = -1;
							themes::changed = true;
							g_sa_settings.active_theme_idx = ti;
							g_sa_settings.active_custom_theme_idx = -1;
							g_sa_settings_request_save();
							diag::log_tagged_fmt("ui", "theme_changed idx=%d name='%s'",
								ti, tp.name);
						}
					}


					if (!custom_themes::list.empty()) {
						ImGui::Dummy(ImVec2(0, 4));
						ImGui::Separator();
						ImGui::Dummy(ImVec2(0, 2));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.text_secondary), "Custom Themes");
						ImGui::Spacing();
						for (std::size_t ci = 0; ci < custom_themes::list.size(); ++ci) {
							auto& ct = custom_themes::list[ci];
							const int custom_index = static_cast<int>(ci);
							bool is_active = (custom_themes::active_custom == custom_index);

							ImVec2 cp = ImGui::GetCursorScreenPos();
							ImVec2 rmin = cp;
							ImVec2 rmax(cp.x + item_w, cp.y + item_h);

							bool ci_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
							if (ci_hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
							if (is_active) pdl->AddRectFilled(rmin, rmax, th_tp.selection, 4.f);

							pdl->AddCircleFilled(
								ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
								IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255),
									(int)(ct.accent[2]*255), 255));

							ImU32 nc = is_active
								? IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255), (int)(ct.accent[2]*255), 255)
								: th_tp.text_secondary;
							pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
								nc, ct.name.c_str());


							float edit_w = ImGui::CalcTextSize("Edit").x + 8.f;
							ImVec2 emin(cp.x + item_w - edit_w - 4.f, cp.y + 2.f);
							ImVec2 emax(emin.x + edit_w, cp.y + item_h - 2.f);
							bool ehov = ImGui::IsMouseHoveringRect(emin, emax);
							if (ehov) pdl->AddRectFilled(emin, emax, th_tp.selection, 3.f);
							pdl->AddText(ImVec2(emin.x + 4.f, emin.y + 1.f),
								aida::ui::with_alpha(th_tp.text_secondary, ehov ? 1.f : 0.66f), "Edit");
							if (popup_clicks_ok && ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::editing_idx = custom_index;
								custom_themes::editing_copy = ct;
								custom_themes::editor_open = true;
							}

							ImGui::Dummy(ImVec2(item_w, item_h));
							if (popup_clicks_ok && ci_hov && !ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::active_custom = custom_index;
								themes::changed = true;
								g_sa_settings.active_custom_theme_idx = custom_index;
								g_sa_settings_request_save();
							}
						}
					}


					ImGui::Dummy(ImVec2(0, 4));
					ImGui::Separator();
					ImGui::Dummy(ImVec2(0, 2));


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							aida::ui::with_alpha(th_tp.success, hov ? 1.f : 0.78f), "+ Create New Theme");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							custom_themes::editing_idx = -1;
							custom_themes::editing_copy = CustomThemeData{};
							custom_themes::editing_copy.name = "My Theme " + std::to_string(custom_themes::list.size() + 1);
							custom_themes::editor_open = true;
						}
					}


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							aida::ui::with_alpha(th_tp.info, hov ? 1.f : 0.78f), "Import Theme...");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							char buf[MAX_PATH] = {};
							static const char k_theme_import_filter[] =
								"AiDA Theme (*.json)\0*.json\0"
								"All files (*.*)\0*.*\0\0";
							if (trusted_show_open_file(g_hwnd,
									"Import Theme",
									k_theme_import_filter,
									buf, sizeof(buf),
									"theme_import")) {
								const auto requested = aida::theme_transfer::request_import(buf);
								if (requested == aida::theme_transfer::request_result_t::queued ||
									requested == aida::theme_transfer::request_result_t::preview_recorded)
									custom_theme_ui_error().clear();
								else if (requested == aida::theme_transfer::request_result_t::busy)
									custom_theme_ui_error() = "A theme file operation is already running.";
								else if (requested == aida::theme_transfer::request_result_t::rejected)
									custom_theme_ui_error() = "The theme import request was rejected.";
							}
						}
					}
					const auto theme_transfer_status = aida::theme_transfer::status();
					if (theme_transfer_status.pending || theme_transfer_status.failed ||
						!custom_theme_ui_error().empty()) {
						ImGui::Dummy(ImVec2(0.f, 3.f));
						ImGui::Separator();
						const std::string& displayed_error = !custom_theme_ui_error().empty()
							? custom_theme_ui_error() : theme_transfer_status.error;
						if (!displayed_error.empty()) {
							ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + item_w);
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.error),
								"%s", displayed_error.c_str());
							ImGui::PopTextWrapPos();
						} else
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.warning),
								"%s", theme_transfer_status.stage.c_str());
						if (theme_transfer_status.retryable &&
							ImGui::SmallButton("Retry theme operation##theme_retry_popup")) {
							if (aida::theme_transfer::request_retry())
								custom_theme_ui_error().clear();
						}
					}
				ImGui::EndPopup();
			}
			}


			static bool theme_editor_popup_requested = false;
			if (custom_themes::editor_open && !theme_editor_popup_requested) {
				aida::ui::design::open_dialog("theme_editor", "Theme Editor");
				theme_editor_popup_requested = true;
			}
			if (custom_themes::editor_open) {
				const auto& th_te = aida::ui::resolved();

				bool theme_editor_stay_open = custom_themes::editor_open;
				if (aida::ui::design::begin_dialog_exact("Theme Editor###theme_editor",
					ImVec2(420.f, 620.f), ImVec2(360.f, 420.f), &theme_editor_stay_open,
					ImGuiWindowFlags_NoCollapse))
				{
					auto& ed = custom_themes::editing_copy;
					float iw2 = (std::max)(120.f, ImGui::GetContentRegionAvail().x);

					ImGui::TextColored(aida::ui::resolved().accent,
						custom_themes::editing_idx < 0 ? "Create Theme" : "Edit Theme");
					ImGui::Dummy(ImVec2(0, 4));


					static char name_buf[128] = {};
					static bool name_init = false;
					static int name_editing_idx = -2;
					static int delete_review_index = -1;
					static std::string delete_review_name;
					if (!name_init || name_editing_idx != custom_themes::editing_idx ||
						ed.name != name_buf) {
						snprintf(name_buf, sizeof(name_buf), "%s", ed.name.c_str());
						name_init = true;
						name_editing_idx = custom_themes::editing_idx;
					}
					ImGui::Text("Name");
					ImGui::SetNextItemWidth(iw2);
					if (ImGui::InputText("##te_name", name_buf, sizeof(name_buf)))
						ed.name = name_buf;


					ImGui::Text("Accent Color");
					ImGui::SetNextItemWidth(iw2);
					ImGui::ColorEdit3("##te_accent", ed.accent, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);


					auto u32_edit = [&](const char* label, const char* id, ImU32& col) {
						ImGui::Text("%s", label);
						float c[4];
						c[0] = (float)((col >> 0) & 0xFF) / 255.f;
						c[1] = (float)((col >> 8) & 0xFF) / 255.f;
						c[2] = (float)((col >> 16) & 0xFF) / 255.f;
						c[3] = (float)((col >> 24) & 0xFF) / 255.f;
						ImGui::SetNextItemWidth(iw2);
						if (ImGui::ColorEdit4(id, c, ImGuiColorEditFlags_AlphaBar))
							col = IM_COL32((int)(c[0]*255), (int)(c[1]*255), (int)(c[2]*255), (int)(c[3]*255));
					};
					u32_edit("Background", "##te_bg", ed.bg_base);
					u32_edit("Panel Background", "##te_pbg", ed.panel_bg);
					u32_edit("Panel Header", "##te_phdr", ed.panel_header);
					u32_edit("Title Bar", "##te_tb", ed.title_bar);


					ImGui::Text("Theme Icon (optional)");
					ImGui::SetNextItemWidth(iw2);
					if (aida::ui::components::button("Choose Image File...##te_icon",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(iw2, 0.f))) {
						char icon_buf[MAX_PATH] = {};
						static const char k_theme_icon_filter[] =
							"Images (*.png;*.jpg;*.jpeg;*.bmp)\0*.png;*.jpg;*.jpeg;*.bmp\0"
							"All files (*.*)\0*.*\0\0";
						if (trusted_show_open_file(g_hwnd,
							"Choose Theme Icon",
							k_theme_icon_filter,
							icon_buf, sizeof(icon_buf),
							"theme_icon_pick")) {
							ed.icon_index = -1;
							ed.icon_file_path = icon_buf;
						}
					}
					if (!ed.icon_file_path.empty()) {
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_te.success), "File: %s",
							ed.icon_file_path.substr(ed.icon_file_path.find_last_of("\\/") + 1).c_str());
						if (aida::ui::components::button("Clear Icon##te_clear",
							aida::ui::components::button_kind_t::ghost,
							aida::ui::components::size_t_::sm)) {
							ed.icon_file_path.clear();
							ed.icon_index = -1;
						}
					}
					const auto editor_transfer_status = aida::theme_transfer::status();
					const std::string& editor_error = !custom_theme_ui_error().empty()
						? custom_theme_ui_error() : editor_transfer_status.error;
					if (!editor_error.empty()) {
						ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + iw2);
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_te.error),
							"%s", editor_error.c_str());
						ImGui::PopTextWrapPos();
					} else if (editor_transfer_status.pending) {
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_te.warning),
							"%s", editor_transfer_status.stage.c_str());
					}
					if (editor_transfer_status.retryable &&
						ImGui::SmallButton("Retry theme operation##theme_retry_editor")) {
						if (aida::theme_transfer::request_retry())
							custom_theme_ui_error().clear();
					}

					ImGui::Dummy(ImVec2(0, 8));


					float btn_w2 = 70.f;
					if (aida::ui::components::button("Save",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						ed.name = name_buf;
						std::string validation_error;
						const bool replacing = custom_themes::editing_idx >= 0 &&
							static_cast<std::size_t>(custom_themes::editing_idx) < custom_themes::list.size();
						if (!validate_custom_theme(ed, validation_error)) {
							custom_theme_ui_error() = std::move(validation_error);
						} else if (!replacing && custom_themes::editing_idx >= 0) {
							custom_theme_ui_error() = "The custom theme being edited no longer exists.";
						} else if (!replacing && custom_themes::list.size() >=
								aida::theme_transfer::maximum_theme_count) {
							custom_theme_ui_error() = "Delete a custom theme before creating another; the catalog limit is 128.";
						} else {
							const int previous_active = custom_themes::active_custom;
							const int previous_editing = custom_themes::editing_idx;
							CustomThemeData previous_theme;
							if (replacing) {
								previous_theme = custom_themes::list[
									static_cast<std::size_t>(custom_themes::editing_idx)];
								custom_themes::list[
									static_cast<std::size_t>(custom_themes::editing_idx)] = ed;
							} else {
								custom_themes::list.push_back(ed);
								custom_themes::editing_idx = static_cast<int>(custom_themes::list.size()) - 1;
							}
							custom_themes::active_custom = custom_themes::editing_idx;
							std::string persistence_error;
							if (!persist_custom_theme_catalog(persistence_error)) {
								if (replacing)
									custom_themes::list[static_cast<std::size_t>(previous_editing)] =
										std::move(previous_theme);
								else
									custom_themes::list.pop_back();
								custom_themes::editing_idx = previous_editing;
								custom_themes::active_custom = previous_active;
								custom_theme_ui_error() = std::move(persistence_error);
							} else {
								themes::changed = true;
								custom_themes::editor_open = false;
								custom_theme_ui_error().clear();
								name_init = false;
							}
						}
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						"aida.theme.editor.save", "theme-save");
#endif
					ImGui::SameLine();


					if (aida::ui::components::button("Export",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						char export_buf[MAX_PATH] = {};
						snprintf(export_buf, sizeof(export_buf), "%s.json", name_buf);
						static const char k_theme_export_filter[] =
							"AiDA Theme (*.json)\0*.json\0\0";
						if (trusted_show_save_file(g_hwnd,
							"Export Theme",
							k_theme_export_filter,
							"json",
							export_buf, sizeof(export_buf),
							"theme_export")) {
							CustomThemeData exported = ed;
							exported.name = name_buf;
							const auto requested = aida::theme_transfer::request_export(
								export_buf, capture_theme_transfer(exported));
							if (requested == aida::theme_transfer::request_result_t::queued ||
								requested == aida::theme_transfer::request_result_t::preview_recorded)
								custom_theme_ui_error().clear();
							else if (requested == aida::theme_transfer::request_result_t::busy)
								custom_theme_ui_error() = "A theme file operation is already running.";
							else if (requested == aida::theme_transfer::request_result_t::rejected)
								custom_theme_ui_error() = "The theme export request failed validation or scheduling.";
						}
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						"aida.theme.editor.export", "theme-export");
#endif
					ImGui::SameLine();


					if (custom_themes::editing_idx >= 0 &&
						static_cast<std::size_t>(custom_themes::editing_idx) <
							custom_themes::list.size()) {
						if (aida::ui::components::button("Delete",
							aida::ui::components::button_kind_t::destructive,
							aida::ui::components::size_t_::md,
							ImVec2(btn_w2, 26.f))) {
							delete_review_index = custom_themes::editing_idx;
							delete_review_name = custom_themes::list[
								static_cast<std::size_t>(delete_review_index)].name;
							aida::ui::design::open_dialog("theme_delete_confirm", "Delete Theme");
						}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						aida::preview::semantics::register_last_item(
							"aida.theme.editor.delete", "theme-delete-review");
#endif
						ImGui::SameLine();
					}

					if (aida::ui::components::button("Cancel",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						custom_themes::editor_open = false;
						name_init = false;
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						"aida.theme.editor.cancel", "dialog-cancel");
#endif

					if (aida::ui::design::begin_dialog("theme_delete_confirm", "Delete Theme",
							ImVec2(460.f, 270.f), ImVec2(340.f, 230.f))) {
						const bool target_current = delete_review_index >= 0 &&
							static_cast<std::size_t>(delete_review_index) < custom_themes::list.size() &&
							custom_themes::list[static_cast<std::size_t>(delete_review_index)].name == delete_review_name;
						const std::string delete_prerequisite = target_current
							? "The reviewed catalog entry is unchanged."
							: "The reviewed theme changed or no longer exists. Cancel and select it again.";
						aida::ui::design::confirmation_t confirmation;
						confirmation.verb = "Delete custom theme";
						confirmation.target = delete_review_name.c_str();
						confirmation.scope = "The persisted custom-theme catalog";
						confirmation.effect = "The theme is removed. If active, the custom-theme selection is cleared.";
						confirmation.reversibility = "Re-import or recreate the theme to restore it.";
						confirmation.prerequisite = delete_prerequisite.c_str();
						confirmation.confirm_label = "Delete";
						confirmation.destructive = true;
						confirmation.confirm_enabled = target_current;
						const auto result = aida::ui::design::confirmation_dialog(
							"theme_delete_confirm", confirmation);
						if (result.confirmed && target_current) {
							const int idx = delete_review_index;
							const int previous_active = custom_themes::active_custom;
							CustomThemeData removed = custom_themes::list[static_cast<std::size_t>(idx)];
							custom_themes::list.erase(custom_themes::list.begin() + idx);
							if (custom_themes::active_custom == idx) custom_themes::active_custom = -1;
							else if (custom_themes::active_custom > idx) custom_themes::active_custom--;
							std::string persistence_error;
							if (!persist_custom_theme_catalog(persistence_error)) {
								custom_themes::list.insert(custom_themes::list.begin() + idx,
									std::move(removed));
								custom_themes::active_custom = previous_active;
								custom_theme_ui_error() = std::move(persistence_error);
							} else {
								themes::changed = true;
								custom_themes::editor_open = false;
								custom_theme_ui_error().clear();
								name_init = false;
							}
							delete_review_index = -1;
							delete_review_name.clear();
							ImGui::CloseCurrentPopup();
						} else if (result.cancelled) {
							delete_review_index = -1;
							delete_review_name.clear();
							ImGui::CloseCurrentPopup();
						}
						ImGui::EndPopup();
					}
				}
			ImGui::EndPopup();
			if (!theme_editor_stay_open) {
					custom_themes::editor_open = false;
					theme_editor_popup_requested = false;
				}
			} else {
				theme_editor_popup_requested = false;
			}
		}

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static bool preview_title_dragging = false;
			bool preview_title_drag = ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f) &&
				ImGui::GetIO().MousePos.y >= wp.y && ImGui::GetIO().MousePos.y < wp.y + title_h;
			if (preview_title_drag && !preview_title_dragging)
				aida::preview::record(aida::preview::shell_action_t::move_window, "title_bar");
			preview_title_dragging = preview_title_drag;
			#else
			static POINT tb_drag_wnd = {};
			static POINT tb_drag_mouse = {};
			static bool  tb_dragging = false;
			static bool  tb_last_lmb = false;
			bool lmb = shell_left_mouse_down();
			if (lmb && !tb_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				int local_x = cp.x - wr.left;

				if (local_y >= 0 && local_y < (int)title_h && local_x >= 0 && local_x < (int)(ww - 140.f)) {
					tb_dragging = true;
					tb_drag_mouse = cp;
					tb_drag_wnd = { wr.left, wr.top };
				}
			}
			if (!lmb) tb_dragging = false;
			if (tb_dragging) {
				POINT cp; GetCursorPos(&cp);
				int nx = tb_drag_wnd.x + (cp.x - tb_drag_mouse.x);
				int ny = tb_drag_wnd.y + (cp.y - tb_drag_mouse.y);
			shell_move_window(nx, ny);
			}
			tb_last_lmb = lmb;
			#endif
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th_mb = aida::ui::resolved();
		float my0 = wp.y + title_h;
		float my1 = my0 + menu_h;

		aida::ui::blur::layer_request_t mb_req;
		mb_req.pos = ImVec2(wp.x, my0);
		mb_req.size = ImVec2(ww, menu_h);
		mb_req.radius = 0.f;
		mb_req.strength = 0.4f;
		mb_req.alpha = a;
		aida::ui::blur::schedule(mb_req);
		dl->AddRectFilled(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.panel_header, a));
		dl->AddLine(ImVec2(wp.x, my1), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.border_subtle, a));

		struct MenuItem {
			const char* label;
			int         id;
		};
		static const MenuItem menus[] = {
			{"File", 0}, {"Edit", 1}, {"View", 2}, {"Navigate", 3},
			{"Analysis", 4}, {"Debugger", 5}, {"Memory", 6}, {"Types", 7},
			{"Network", 8}, {"Workspace", 9}, {"Tools", 10}, {"AI", 11},
			{"Help", 12}, {"More", 13}
		};
		ImFont* mb_label_font = aida::ui::fonts::lg();
		if (!mb_label_font) mb_label_font = aida::ui::fonts::body();
		if (!mb_label_font) mb_label_font = ImGui::GetFont();
		const float mb_label_size = aida::ui::fonts::size_or(mb_label_font, metrics.menu_font);
		float complete_menu_width = metrics.menu_pad_x * 2.f;
		for (int menu_index = 0; menu_index <= 12; ++menu_index) {
			complete_menu_width += mb_label_font->CalcTextSizeA(
				mb_label_size, FLT_MAX, 0.f, menus[menu_index].label).x +
				metrics.menu_item_pad_x * 2.f;
		}
		const float available_menu_width = (std::max)(0.f,
			ww - metrics.menu_pad_x * 2.f);
		const bool compact_menu = complete_menu_width > available_menu_width;
		int keyboard_menu_request = -1;
		int compact_section_request = -1;
		const ImGuiIO& menu_io = ImGui::GetIO();
		if (menu_io.KeyAlt && !menu_io.KeyCtrl && !menu_io.KeyShift && !menu_io.KeySuper) {
			if (ImGui::IsKeyPressed(ImGuiKey_F, false)) keyboard_menu_request = 0;
			else if (ImGui::IsKeyPressed(ImGuiKey_E, false)) keyboard_menu_request = 1;
			else if (ImGui::IsKeyPressed(ImGuiKey_V, false)) keyboard_menu_request = 2;
			else if (ImGui::IsKeyPressed(ImGuiKey_N, false)) keyboard_menu_request = 3;
			else if (ImGui::IsKeyPressed(ImGuiKey_A, false)) keyboard_menu_request = 4;
			else if (ImGui::IsKeyPressed(ImGuiKey_D, false)) keyboard_menu_request = 5;
			else if (ImGui::IsKeyPressed(ImGuiKey_M, false)) keyboard_menu_request = 6;
			else if (ImGui::IsKeyPressed(ImGuiKey_Y, false)) keyboard_menu_request = 7;
			else if (ImGui::IsKeyPressed(ImGuiKey_K, false)) keyboard_menu_request = 8;
			else if (ImGui::IsKeyPressed(ImGuiKey_W, false)) keyboard_menu_request = 9;
			else if (ImGui::IsKeyPressed(ImGuiKey_T, false)) keyboard_menu_request = 10;
			else if (ImGui::IsKeyPressed(ImGuiKey_I, false)) keyboard_menu_request = 11;
			else if (ImGui::IsKeyPressed(ImGuiKey_H, false)) keyboard_menu_request = 12;
		}
		if (compact_menu && keyboard_menu_request >= 4 && keyboard_menu_request <= 12) {
			compact_section_request = keyboard_menu_request;
			keyboard_menu_request = 13;
		}
		float mx_cursor = wp.x + metrics.menu_pad_x;
		ImGuiStorage* mb_storage = ImGui::GetStateStorage();
		for (int i = 0; i < static_cast<int>(sizeof(menus) / sizeof(menus[0])); i++) {
			if ((compact_menu && i >= 4 && i <= 12) || (!compact_menu && i == 13))
				continue;
			ImVec2 ts = mb_label_font->CalcTextSizeA(mb_label_size, FLT_MAX, 0.f, menus[i].label);
			float btn_w = ts.x + metrics.menu_item_pad_x * 2.f;
			ImVec2 bmin(mx_cursor, my0 + gap * 0.75f);
			ImVec2 bmax(mx_cursor + btn_w, my1 - gap * 0.75f);
			bool is_open = (menu_bar::open_menu == i);

			ImGui::PushID(menus[i].label);
			ImGui::SetCursorScreenPos(bmin);
			if (keyboard_menu_request == i)
				ImGui::SetKeyboardFocusHere();
			const bool activated = ImGui::InvisibleButton(
				"##mb_top", ImVec2(btn_w, bmax.y - bmin.y),
				static_cast<ImGuiButtonFlags>(ImGuiButtonFlags_MouseButtonLeft) |
				static_cast<ImGuiButtonFlags>(ImGuiButtonFlags_PressedOnClick));
			bool hov = ImGui::IsItemHovered();
			bool clicked_btn = activated;
			bool focused = ImGui::IsItemFocused();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string menu_semantic_id = aida::preview::semantics::stable_id(
				"aida.menu", menus[i].label);
			aida::preview::semantics::register_last_item(
				menu_semantic_id, "application-menu-trigger");
#endif
			ImGui::PopID();

			ImGuiID mb_hov_id = ImGui::GetID(menus[i].label);
			float h_v = mb_storage->GetFloat(mb_hov_id, 0.f);
			float h_target = (hov || is_open) ? 1.f : 0.f;
			h_v += (h_target - h_v) * std::min(12.f * dt, 1.f);
			mb_storage->SetFloat(mb_hov_id, h_v);

			if (h_v > 0.01f) {
				ImU32 mfill = is_open ? th_mb.selection_strong : th_mb.hover_wash;
				dl->AddRectFilled(bmin, bmax, aida::ui::with_alpha(mfill, h_v * a), metrics.control_radius);
			}
			if (is_open) {
				dl->AddRectFilled(ImVec2(bmin.x + metrics.menu_item_pad_x, bmax.y - 2.f),
					ImVec2(bmax.x - metrics.menu_item_pad_x, bmax.y),
					aida::ui::with_alpha(th_mb.accent_u32, a), 1.f);
			}
			if (focused) {
				dl->AddRect(ImVec2(bmin.x - 1.f, bmin.y - 1.f),
					ImVec2(bmax.x + 1.f, bmax.y + 1.f),
					aida::ui::with_alpha(th_mb.border_focus, 0.82f * a),
					metrics.control_radius + 1.f, 0, 1.5f);
			}

			ImU32 tcol = (hov || is_open) ? th_mb.text_primary : th_mb.text_secondary;
			dl->AddText(mb_label_font, mb_label_size,
				ImVec2(mx_cursor + metrics.menu_item_pad_x, my0 + (menu_h - mb_label_size) * 0.5f),
				aida::ui::with_alpha(tcol, a), menus[i].label);

			bool need_open = false;
			const bool keyboard_open = keyboard_menu_request == i;
			if (keyboard_open) {
				menu_bar::open_menu = i;
				menu_bar::any_open = true;
				need_open = true;
			}
			if (clicked_btn && !keyboard_open) {
				bool was_open = is_open;
				menu_bar::open_menu = was_open ? -1 : i;
				menu_bar::any_open = (menu_bar::open_menu >= 0);
				if (!was_open) {
					need_open = true;
				} else {
					ImGuiContext& popup_context = *GImGui;
					ImGui::ClosePopupToLevel(popup_context.BeginPopupStack.Size, true);
				}
			}
			if (hov && menu_bar::any_open && !is_open) {
				menu_bar::open_menu = i;
				need_open = true;
			}
			is_open = (menu_bar::open_menu == i);


			if (is_open) {
				ImFont* popup_menu_font = aida::ui::fonts::lg();
				if (!popup_menu_font) popup_menu_font = aida::ui::fonts::body();
				if (!popup_menu_font) popup_menu_font = ImGui::GetFont();
				const float popup_menu_font_size = aida::ui::fonts::size_or(
					popup_menu_font, metrics.menu_font);
				const float popup_native_row_height = (std::max)(
					aida::ui::scale_px(34.f, metrics.scale),
					popup_menu_font_size + aida::ui::scale_px(12.f, metrics.scale));
				const float popup_native_spacing_y = (std::max)(0.f,
					popup_native_row_height - popup_menu_font_size);
			ImGui::SetNextWindowPos(ImVec2(bmin.x, my1 + gap));
			ImGui::SetNextWindowBgAlpha(1.0f);
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
				ImVec2(0.f, popup_native_spacing_y));
			ImGui::PushFont(popup_menu_font, popup_menu_font_size);

				char popup_id[32];
				snprintf(popup_id, sizeof(popup_id), "##menu_%d", i);
				bool escape_closed_menu_chain = false;
				if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
					ImGuiContext& popup_context = *GImGui;
					const ImGuiID application_popup_id = ImGui::GetID(popup_id);
					for (int popup_index = 0;
						popup_index < popup_context.OpenPopupStack.Size;
						++popup_index) {
						const ImGuiPopupData& popup = popup_context.OpenPopupStack[popup_index];
						if (popup.PopupId != application_popup_id || popup.Window == nullptr ||
							(popup.Window->Flags & ImGuiWindowFlags_Modal) != 0)
							continue;
						bool contains_modal = false;
						for (int descendant_index = popup_index + 1;
							descendant_index < popup_context.OpenPopupStack.Size;
							++descendant_index) {
							const ImGuiWindow* descendant =
								popup_context.OpenPopupStack[descendant_index].Window;
							if (descendant != nullptr &&
								(descendant->Flags & ImGuiWindowFlags_Modal) != 0) {
								contains_modal = true;
								break;
							}
						}
						if (!contains_modal) {
							ImGui::ClosePopupToLevel(popup_index, true);
							menu_bar::open_menu = -1;
							menu_bar::any_open = false;
							escape_closed_menu_chain = true;
						}
						break;
					}
				}
				if (!escape_closed_menu_chain && (need_open || menu_bar::open_request))
					ImGui::OpenPopup(popup_id);
				menu_bar::open_request = false;

				const float popup_max_height = (std::max)(aida::ui::scale_px(220.f, metrics.scale),
					ImGui::GetMainViewport()->WorkSize.y * 0.82f);
				ImGui::SetNextWindowSizeConstraints(
					ImVec2(aida::ui::scale_px(300.f, metrics.scale),
						i == 2 || i == 13 ? aida::ui::scale_px(240.f, metrics.scale) : 0.f),
					ImVec2(aida::ui::scale_px(440.f, metrics.scale), popup_max_height));
				if (!escape_closed_menu_chain && ImGui::BeginPopup(popup_id)) {
					if (keyboard_open)
						ImGui::SetKeyboardFocusHere();
					float mw = aida::ui::scale_px(280.f, metrics.scale);

					ImVec2 pwp = ImGui::GetWindowPos();
					ImVec2 pws = ImGui::GetWindowSize();
					ImVec2 pa(pwp.x, pwp.y);
					ImVec2 pb(pwp.x + pws.x, pwp.y + pws.y);
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					aida::ui::blur::layer_request_t pr;
					pr.pos = pa; pr.size = pws; pr.radius = metrics.corner_radius; pr.strength = 0.85f; pr.alpha = 1.f;
					aida::ui::blur::schedule(pr);
					aida::ui::blur::render_drop_shadow(pdl, pa, pb, metrics.corner_radius, 5, 0.55f, ImVec2(0.f, gap * 2.f));
					{
						const auto& th_pp = aida::ui::resolved();
						pdl->AddRectFilled(pa, pb,
							aida::ui::with_alpha(th_pp.panel_bg, 1.0f), metrics.corner_radius);
					}
					aida::ui::blur::render_glass_border(pdl, pa, pb, metrics.corner_radius, 1.f, 1.f);

					auto menu_item = [&](const char* label, const char* shortcut,
						bool enabled = true, const char* semantic_action_id = nullptr) -> bool {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImU32 tc = enabled ? th_p.text_primary : th_p.text_dim;
						ImFont* f_label = aida::ui::fonts::lg();
						if (!f_label) f_label = aida::ui::fonts::body();
						if (!f_label) f_label = ImGui::GetFont();
						ImFont* f_short = aida::ui::fonts::body();
						if (!f_short) f_short = f_label;
						const float label_sz = aida::ui::fonts::size_or(f_label, metrics.menu_font);
						const float short_sz = aida::ui::fonts::size_or(f_short, metrics.caption_font);
						const float item_h = (std::max)(aida::ui::scale_px(34.f, metrics.scale),
							(std::max)(label_sz, short_sz) + aida::ui::scale_px(12.f, metrics.scale));
						const float label_pad = aida::ui::scale_px(16.f, metrics.scale);
						const float shortcut_pad = aida::ui::scale_px(14.f, metrics.scale);
						float label_clip_right = cp.x + mw - shortcut_pad;
						if (shortcut && shortcut[0]) {
							ImVec2 sts = f_short->CalcTextSizeA(short_sz, FLT_MAX, 0.f, shortcut);
							label_clip_right = (std::max)(cp.x + label_pad, cp.x + mw - sts.x - shortcut_pad - aida::ui::scale_px(10.f, metrics.scale));
						}
						ImGui::PushID(label);
						if (!enabled)
							ImGui::BeginDisabled();
						ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
						const bool activated = ImGui::InvisibleButton(
							"##mi", ImVec2(mw, item_h));
						ImGui::PopStyleVar();
						if (!enabled)
							ImGui::EndDisabled();
						bool mhov = enabled && ImGui::IsItemHovered();
						bool mfocused = enabled && ImGui::IsItemFocused();
						bool clicked = enabled && activated;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						if (semantic_action_id && *semantic_action_id) {
							const std::string semantic_id = aida::preview::semantics::stable_id(
								"aida.menu.action", semantic_action_id);
							aida::preview::semantics::register_last_item(
								semantic_id, "application-menu-action", true, !enabled);
						}
#endif
						ImGui::PopID();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + mw, cp.y + item_h);
						ImDrawList* idl = ImGui::GetWindowDrawList();
						if (mhov || mfocused) idl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_p.hover_wash, 1.f),
							aida::ui::scale_px(aida::ui::metrics::radius::md, metrics.scale));
						if (mfocused) idl->AddRect(rmin, rmax,
							aida::ui::with_alpha(th_p.border_focus, 0.9f),
							aida::ui::scale_px(aida::ui::metrics::radius::md, metrics.scale),
							0, aida::ui::scale_px(1.5f, metrics.scale));
						ImVec4 label_clip(cp.x + label_pad, cp.y, label_clip_right, cp.y + item_h);
						idl->AddText(f_label, label_sz,
							ImVec2(cp.x + label_pad, cp.y + (item_h - label_sz) * 0.5f), tc, label, nullptr, 0.f, &label_clip);
						if (shortcut && shortcut[0]) {
							ImVec2 sts = f_short->CalcTextSizeA(short_sz, FLT_MAX, 0.f, shortcut);
							ImVec4 short_clip(cp.x + mw * 0.45f, cp.y, cp.x + mw - shortcut_pad, cp.y + item_h);
							idl->AddText(f_short, short_sz,
								ImVec2(cp.x + mw - sts.x - shortcut_pad, cp.y + (item_h - short_sz) * 0.5f),
								aida::ui::with_alpha(th_p.text_dim, 1.f), shortcut, nullptr, 0.f, &short_clip);
						}
						if (clicked) { menu_bar::open_menu = -1; menu_bar::any_open = false; menu_bar::suppress_frames = 2; ImGui::CloseCurrentPopup(); }
						return clicked;
					};

					auto menu_sep = [&]() {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImGui::GetWindowDrawList()->AddLine(
							ImVec2(cp.x + 12.f, cp.y + 6.f), ImVec2(cp.x + mw - 12.f, cp.y + 6.f),
							aida::ui::with_alpha(th_p.border_subtle, 1.f));
						ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
						ImGui::Dummy(ImVec2(mw, 12.f));
						ImGui::PopStyleVar();
					};

					auto action_menu_item = [&](const char* action_id,
						const char* = "",
						const char* label_override = nullptr) -> bool {
						auto presentation = aida::ui::application_ui::present_action(action_id);
						if (!presentation.visible)
							return false;
						const char* label = label_override && *label_override
							? label_override : presentation.label.c_str();
						const char* shortcut = presentation.shortcut.empty()
							? nullptr : presentation.shortcut.c_str();
						const bool selected = menu_item(label, shortcut,
							presentation.enabled, action_id);
						if (!presentation.enabled &&
							ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
							!presentation.disabled_reason.empty())
							ImGui::SetTooltip("%s", presentation.disabled_reason.c_str());
						if (selected)
							static_cast<void>(aida::ui::application_ui::execute_action(
								action_id, aida::ui::action_invocation_source_t::application_menu));
						return selected;
					};

					auto review_action_menu_item = [&](const char* action_id) -> bool {
						auto presentation =
							aida::ui::application_ui::present_editor_review_action(action_id);
						if (!presentation.visible)
							return false;
						const bool selected = menu_item(presentation.label.c_str(),
							presentation.shortcut.c_str(), presentation.enabled, action_id);
						if (!presentation.enabled &&
							ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
							!presentation.disabled_reason.empty())
							ImGui::SetTooltip("%s", presentation.disabled_reason.c_str());
						if (selected)
							static_cast<void>(aida::ui::application_ui::execute_action(
								action_id, aida::ui::action_invocation_source_t::application_menu));
						return selected;
					};

					auto begin_native_menu = [&](const char* label) -> bool {
						ImGui::SetNextWindowSizeConstraints(
							ImVec2(0.f, 0.f), ImVec2(FLT_MAX, popup_max_height));
						ImFont* submenu_font = aida::ui::fonts::lg();
						if (!submenu_font) submenu_font = aida::ui::fonts::body();
						if (!submenu_font) submenu_font = ImGui::GetFont();
						const float submenu_label_size =
							aida::ui::fonts::size_or(submenu_font, metrics.menu_font);
						const float submenu_label_pad =
							aida::ui::scale_px(16.f, metrics.scale);
						const float submenu_arrow_pad =
							aida::ui::scale_px(14.f, metrics.scale);
						ImDrawList* owner_draw = ImGui::GetWindowDrawList();
						std::string submenu_id = "##submenu_";
						submenu_id += label ? label : "menu";
						const bool opened = ImGui::BeginMenu(submenu_id.c_str());
						const ImVec2 item_min = ImGui::GetItemRectMin();
						const ImVec2 item_max = ImGui::GetItemRectMax();
						const float text_y = item_min.y +
							(item_max.y - item_min.y - submenu_label_size) * 0.5f;
						const ImVec4 text_clip(
							item_min.x + submenu_label_pad, item_min.y,
							(std::max)(item_min.x + submenu_label_pad,
								item_max.x - submenu_arrow_pad), item_max.y);
						owner_draw->AddText(
							submenu_font, submenu_label_size,
							ImVec2(item_min.x + submenu_label_pad, text_y),
							aida::ui::resolved().text_primary,
							label ? label : "", nullptr, 0.f, &text_clip);
						return opened;
					};

					auto begin_semantic_menu = [&](const char* label,
						const char* semantic_key) -> bool {
						const bool opened = begin_native_menu(label);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						const std::string semantic_id = aida::preview::semantics::stable_id(
							"aida.menu.submenu", semantic_key);
						aida::preview::semantics::register_last_item(
							semantic_id, "application-menu-submenu", true, false);
#endif
						return opened;
					};

					auto render_view_category = [&](aida::ui::view_category_t category) {
						aida::ui::application_views::for_each_menu_entry(
							[&](const aida::ui::application_views::menu_entry_t& entry) {
								if (entry.category != category)
									return;
								const std::string action_id =
									aida::ui::application_ui::view_action_id(entry.id);
								action_menu_item(action_id.c_str(), "", entry.label.c_str());
							});
					};

					auto render_native_view_entry = [&](
						const aida::ui::application_views::menu_entry_t& entry) {
						const std::string action_id =
							aida::ui::application_ui::view_action_id(entry.id);
						auto presentation =
							aida::ui::application_ui::present_action(action_id.c_str());
						const bool enabled = entry.enabled && presentation.enabled;
						ImGui::PushID(action_id.c_str());
						const bool selected = ImGui::MenuItem(entry.label.c_str(),
							presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str(),
							entry.open, enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						const std::string semantic_id = aida::preview::semantics::stable_id(
							"aida.menu.action", action_id);
						aida::preview::semantics::register_last_item(
							semantic_id, "application-menu-action", true, !enabled);
#endif
						if (!enabled && ImGui::IsItemHovered(
							ImGuiHoveredFlags_AllowWhenDisabled)) {
							const std::string& reason = !entry.disabled_reason.empty()
								? entry.disabled_reason : presentation.disabled_reason;
							if (!reason.empty()) ImGui::SetTooltip("%s", reason.c_str());
						}
						ImGui::PopID();
						if (selected) {
							static_cast<void>(aida::ui::application_ui::execute_action(
								action_id.c_str(),
								aida::ui::action_invocation_source_t::application_menu));
							menu_bar::open_menu = -1;
							menu_bar::any_open = false;
							menu_bar::suppress_frames = 2;
						}
					};

						struct menu_view_group_t {
							const char* label;
							const char* semantic_key;
							const char* const* ids;
							std::size_t count;
						};

						auto render_grouped_view_category = [&](aida::ui::view_category_t category,
							const menu_view_group_t* groups, std::size_t group_count,
							const char* other_label, const char* other_semantic_key) {
							std::vector<aida::ui::application_views::menu_entry_t> entries;
							aida::ui::application_views::for_each_menu_entry(
								[&](const aida::ui::application_views::menu_entry_t& entry) {
									if (entry.category == category) entries.push_back(entry);
								});
							auto find_entry = [&](const char* id) {
								return std::find_if(entries.begin(), entries.end(),
									[&](const auto& entry) { return entry.id.value() == id; });
							};
							auto grouped = [&](const std::string& id) {
								for (std::size_t group_index = 0; group_index < group_count; ++group_index)
									for (std::size_t index = 0; index < groups[group_index].count; ++index)
										if (id == groups[group_index].ids[index]) return true;
								return false;
							};
							for (std::size_t group_index = 0; group_index < group_count; ++group_index) {
								const auto& group = groups[group_index];
								if (begin_semantic_menu(group.label, group.semantic_key)) {
									for (std::size_t index = 0; index < group.count; ++index) {
										const auto found = find_entry(group.ids[index]);
										if (found != entries.end()) render_native_view_entry(*found);
									}
									ImGui::EndMenu();
								}
							}
							const bool has_other = std::any_of(entries.begin(), entries.end(),
								[&](const auto& entry) { return !grouped(entry.id.value()); });
							if (has_other && begin_semantic_menu(other_label, other_semantic_key)) {
								for (const auto& entry : entries)
									if (!grouped(entry.id.value())) render_native_view_entry(entry);
								ImGui::EndMenu();
							}
						};

						auto render_analysis_view_groups = [&]() {
							static const char* core_lists[] = {
								"view.analysis.functions", "view.analysis.imports", "view.analysis.exports",
								"view.analysis.names", "view.analysis.strings", "view.analysis.segments",
								"view.analysis.segment_registers", "view.analysis.local_types"
							};
							static const char* navigation_relationships[] = {
								"view.analysis.binary_map", "view.analysis.references", "view.analysis.proximity",
								"view.navigator", "view.inspector"
							};
							static const char* advanced_analysis[] = {
								"view.analysis.symbolic", "view.analysis.taint", "view.analysis.deobfuscation",
								"view.analysis.fuzzer", "view.analysis.protection"
							};
							static const menu_view_group_t groups[] = {
								{"Core Lists", "analysis.views.core-lists", core_lists, sizeof(core_lists) / sizeof(core_lists[0])},
								{"Navigation and Relationships", "analysis.views.navigation-relationships", navigation_relationships, sizeof(navigation_relationships) / sizeof(navigation_relationships[0])},
								{"Advanced Analysis", "analysis.views.advanced-analysis", advanced_analysis, sizeof(advanced_analysis) / sizeof(advanced_analysis[0])}
							};
							render_grouped_view_category(aida::ui::view_category_t::analysis,
								groups, sizeof(groups) / sizeof(groups[0]),
								"Other Analysis Views", "analysis.views.other");
						};

						auto render_debugger_view_groups = [&]() {
							static const char* execution[] = {
								"view.debug.cpu", "view.debug.breakpoints", "view.debug.threads",
								"view.debug.call_stack", "view.debug.watches", "view.debug.source",
								"view.debug.trace"
							};
							static const char* memory_system[] = {
								"view.debug.memory_map", "view.debug.modules", "view.debug.handles",
								"view.debug.seh", "view.debug.patches"
							};
							static const char* supporting[] = {
								"view.debug.bookmarks", "view.debug.strings", "view.debug.cfg"
							};
							static const menu_view_group_t groups[] = {
								{"Execution", "debugger.views.execution", execution, sizeof(execution) / sizeof(execution[0])},
								{"Memory and System", "debugger.views.memory-system", memory_system, sizeof(memory_system) / sizeof(memory_system[0])},
								{"Supporting Views", "debugger.views.supporting", supporting, sizeof(supporting) / sizeof(supporting[0])}
							};
							render_grouped_view_category(aida::ui::view_category_t::debugger,
								groups, sizeof(groups) / sizeof(groups[0]),
								"Other Debugger Views", "debugger.views.other");
						};

						auto render_network_category = [&]() {
						std::vector<aida::ui::application_views::menu_entry_t> entries;
						aida::ui::application_views::for_each_menu_entry(
							[&](const aida::ui::application_views::menu_entry_t& entry) {
								if (entry.category == aida::ui::view_category_t::network)
									entries.push_back(entry);
							});
						static const char* monitor_capture[] = {
							"view.network.connections", "view.network.capture", "view.network.dns",
							"view.network.bandwidth", "view.network.keylog", "view.network.pcap",
							"view.network.logger"
						};
						static const char* traffic_proxy[] = {
							"view.network.intercept", "view.network.proxy", "view.network.filters",
							"view.network.match_replace", "view.network.upstream", "view.network.browser",
							"view.network.headless"
						};
						static const char* request_tools[] = {
							"view.network.repeater", "view.network.decoder", "view.network.comparer",
							"view.network.sequencer", "view.network.session", "view.network.api"
						};
						static const char* testing_automation[] = {
							"view.network.fuzzer", "view.network.offensive", "view.network.scanner",
							"view.network.recon", "view.network.intruder", "view.network.collaborator",
							"view.network.scripting"
						};
						static const char* protocols_security[] = {
							"view.network.websocket", "view.network.ws_editor", "view.network.h2_editor",
							"view.network.jwt_lab", "view.network.csp", "view.network.cookies",
							"view.network.scope", "view.network.site_map", "view.network.reports"
						};
						struct network_group_t {
							const char* label;
							const char* const* ids;
							std::size_t count;
						};
						static const network_group_t groups[] = {
							{"Monitor and Capture", monitor_capture, sizeof(monitor_capture) / sizeof(monitor_capture[0])},
							{"Traffic and Proxy", traffic_proxy, sizeof(traffic_proxy) / sizeof(traffic_proxy[0])},
							{"Request Tools", request_tools, sizeof(request_tools) / sizeof(request_tools[0])},
							{"Testing and Automation", testing_automation, sizeof(testing_automation) / sizeof(testing_automation[0])},
							{"Protocols and Security", protocols_security, sizeof(protocols_security) / sizeof(protocols_security[0])}
						};
						auto find_entry = [&](const char* id) {
							return std::find_if(entries.begin(), entries.end(),
								[&](const auto& entry) { return entry.id.value() == id; });
						};
						auto grouped = [&](const std::string& id) {
							for (const auto& group : groups)
								for (std::size_t index = 0; index < group.count; ++index)
									if (id == group.ids[index]) return true;
							return false;
						};
						for (const auto& group : groups) {
							std::string semantic_key = "network.";
							semantic_key.append(group.label);
							if (begin_semantic_menu(group.label, semantic_key.c_str())) {
								for (std::size_t index = 0; index < group.count; ++index) {
									const auto found = find_entry(group.ids[index]);
									if (found != entries.end()) render_native_view_entry(*found);
								}
								ImGui::EndMenu();
							}
						}
						const bool has_other = std::any_of(entries.begin(), entries.end(),
							[&](const auto& entry) { return !grouped(entry.id.value()); });
						if (has_other && begin_semantic_menu(
							"Other Network Views", "network.other-views")) {
							for (const auto& entry : entries)
								if (!grouped(entry.id.value())) render_native_view_entry(entry);
							ImGui::EndMenu();
						}
					};

					auto render_network_menu = [&]() {
						action_menu_item("network.capture.start");
						action_menu_item("network.capture.stop");
						action_menu_item("network.proxy.start");
						action_menu_item("network.proxy.stop");
						const auto intercept_state = network_view::operational_command_capability(
							network_view::operational_command_t::intercept_toggle);
						action_menu_item("network.intercept.toggle_enabled", "",
							intercept_state.checked ? "Disable Intercept" : "Enable Intercept");
						if (begin_semantic_menu("Held Requests", "network.held-requests")) {
							action_menu_item("network.intercept.forward_selected");
							action_menu_item("network.intercept.drop_selected");
							action_menu_item("network.intercept.forward_modified");
							menu_sep();
							action_menu_item("network.intercept.forward_all");
							action_menu_item("network.intercept.drop_all");
							ImGui::EndMenu();
						}
						if (begin_semantic_menu("Traffic Policy and Trust", "network.traffic-policy-trust")) {
							action_menu_item("network.proxy.history.clear");
							action_menu_item("network.proxy.ca_trust_repair");
							menu_sep();
							action_menu_item("network.filters.add");
							action_menu_item("network.filters.remove_selected");
							action_menu_item("network.filters.clear");
							ImGui::EndMenu();
						}
						if (begin_semantic_menu("TLS Key Logging", "network.tls-key-logging")) {
							action_menu_item("network.keylog.launch");
							action_menu_item("network.keylog.watch");
							action_menu_item("network.keylog.stop");
							action_menu_item("network.keylog.clear");
							ImGui::EndMenu();
						}
						menu_sep();
						if (begin_semantic_menu("Network Views", "network.views")) {
							render_network_category();
							ImGui::EndMenu();
						}
					};

					auto render_analysis_menu = [&]() {
						action_menu_item("tools.load_binary");
						action_menu_item("analysis.decompile_or_focus_pseudocode");
						action_menu_item("analysis.toggle_graph_text");
						action_menu_item("analysis.navigate.follow");
						action_menu_item("analysis.navigate.xrefs");
						menu_sep();
						if (begin_semantic_menu("Modify Selection", "analysis.modify-selection")) {
							action_menu_item("analysis.modify.rename");
							action_menu_item("analysis.modify.retype");
							action_menu_item("analysis.modify.comment");
							action_menu_item("analysis.modify.bookmark");
							action_menu_item("analysis.modify.rebase");
							ImGui::EndMenu();
						}
						if (begin_semantic_menu("Debug Selection", "analysis.debug-selection")) {
							action_menu_item("analysis.debug.run_to_cursor");
							action_menu_item("analysis.debug.breakpoint");
							ImGui::EndMenu();
						}
						if (begin_semantic_menu("Overlay History", "analysis.overlay-history")) {
							action_menu_item("analysis.overlay.undo");
							action_menu_item("analysis.overlay.redo");
							ImGui::EndMenu();
						}
						if (begin_semantic_menu("Patching", "analysis.patching")) {
							action_menu_item("analysis.modify.patch");
							action_menu_item("analysis.modify.nop");
							action_menu_item("analysis.modify.assemble");
							ImGui::EndMenu();
						}
						action_menu_item("analysis.export.listing");
						menu_sep();
						if (begin_semantic_menu("Analysis Views", "analysis.views")) {
							render_analysis_view_groups();
							ImGui::EndMenu();
						}
					};

					auto render_debugger_menu = [&]() {
						action_menu_item("debugger.launch");
						action_menu_item("tools.attach_process");
						action_menu_item("debugger.run_continue");
						action_menu_item("debugger.pause");
						action_menu_item("debugger.step_over");
						action_menu_item("debugger.step_into");
						action_menu_item("debugger.step_out");
						action_menu_item("debugger.restart");
						action_menu_item("debugger.detach");
						action_menu_item("debugger.stop");
						action_menu_item("debugger.watch.refresh_all");
						menu_sep();
						if (begin_semantic_menu("Debugger Views", "debugger.views")) {
							render_debugger_view_groups();
							ImGui::EndMenu();
						}
					};

					auto render_memory_menu = [&]() {
						action_menu_item("memory.first_scan", "Ctrl+Alt+F");
						action_menu_item("memory.next_scan", "Ctrl+Alt+N");
						action_menu_item("memory.stop_scan", "Shift+Escape");
						action_menu_item("memory.undo_scan", "Ctrl+Alt+Z");
						action_menu_item("memory.new_scan", "Ctrl+Alt+R");
						menu_sep();
						render_view_category(aida::ui::view_category_t::memory);
					};

					switch (i) {
					case 0:
					{
						action_menu_item("file.new", "Ctrl+N");
						action_menu_item("file.open", "Ctrl+O");
						action_menu_item("file.open_folder", "Ctrl+K");
						action_menu_item("file.quick_open", "Ctrl+P");
						action_menu_item("view.focus.view.recent", "", "Recent Files and Sessions...");
						menu_sep();
						action_menu_item("tools.load_binary", "", "Open Binary...");
						action_menu_item("tools.attach_process", "", "Attach to Process...");
						action_menu_item("debugger.launch", "", "Launch Target...");
						action_menu_item("file.restore_previous_session");
						action_menu_item("file.reopen_closed_document");
						menu_sep();
						action_menu_item("file.save", "Ctrl+S");
						action_menu_item("file.save_as", "Ctrl+Shift+S");
						action_menu_item("file.save_all");
						action_menu_item("file.close", "Ctrl+W");
						action_menu_item("file.close_all");
						menu_sep();
						action_menu_item("file.exit", "Alt+F4");
						break;
					}
					case 1:
					{
						action_menu_item("edit.undo", "Ctrl+Z");
						action_menu_item("edit.redo", "Ctrl+Y");
						action_menu_item("analysis.overlay.undo");
						action_menu_item("analysis.overlay.redo");
						menu_sep();
						action_menu_item("edit.cut", "Ctrl+X");
						action_menu_item("edit.copy", "Ctrl+C");
						action_menu_item("edit.paste", "Ctrl+V");
						action_menu_item("edit.delete", "Del");
						action_menu_item("edit.select_all", "Ctrl+A");
						menu_sep();
						action_menu_item("edit.find", "Ctrl+F");
						action_menu_item("edit.replace", "Ctrl+H");
						action_menu_item("edit.goto_line", "Ctrl+G");
						menu_sep();
						action_menu_item("edit.preferences", "Ctrl+,");
						break;
					}
					case 2:
					{
						action_menu_item("view.command_palette", "Ctrl+Shift+P");
						action_menu_item("view.global_search", "Ctrl+Shift+F");
						action_menu_item("view.reopen_last_closed");
						action_menu_item("view.open_default_missing");
						action_menu_item("shell.toggle_maximize", "F11");
						action_menu_item("workspace.reset_current", "", "Reset Current Layout");
						action_menu_item("workspace.safe", "", "Activate Safe Layout");
						menu_sep();
						std::vector<aida::ui::application_views::menu_entry_t> view_entries;
						aida::ui::application_views::for_each_menu_entry(
							[&](const aida::ui::application_views::menu_entry_t& entry) {
								view_entries.push_back(entry);
							});
						std::size_t category_begin = 0;
						while (category_begin < view_entries.size()) {
							const auto category = view_entries[category_begin].category;
							std::size_t category_end = category_begin;
							std::size_t open_count = 0;
							while (category_end < view_entries.size() &&
								view_entries[category_end].category == category) {
								if (view_entries[category_end].open)
									++open_count;
								++category_end;
							}
							const std::size_t category_count = category_end - category_begin;
							std::string category_name =
								aida::ui::application_views::category_label(category);
							category_name.append("  (").append(std::to_string(open_count))
								.append("/").append(std::to_string(category_count)).append(")");
							if (begin_native_menu(category_name.c_str())) {
								auto render_view_entry = [&](std::size_t entry_index) {
									const auto& entry = view_entries[entry_index];
									const std::string action_id =
										aida::ui::application_ui::view_action_id(entry.id);
									auto presentation =
										aida::ui::application_ui::present_action(action_id.c_str());
									const bool enabled = entry.enabled && presentation.enabled;
									ImGui::PushID(action_id.c_str());
									const bool selected = ImGui::MenuItem(entry.label.c_str(),
										presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str(),
										entry.open, enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
									const std::string view_semantic_id =
										aida::preview::semantics::stable_id(
											"aida.menu.action", action_id);
									aida::preview::semantics::register_last_item(
										view_semantic_id, "application-menu-action", true, !enabled);
#endif
									if (!enabled && ImGui::IsItemHovered(
										ImGuiHoveredFlags_AllowWhenDisabled)) {
										const std::string& reason = !entry.disabled_reason.empty()
											? entry.disabled_reason : presentation.disabled_reason;
										if (!reason.empty())
											ImGui::SetTooltip("%s", reason.c_str());
									}
									ImGui::PopID();
									if (selected) {
										static_cast<void>(aida::ui::application_ui::execute_action(
											action_id.c_str(),
											aida::ui::action_invocation_source_t::application_menu));
										menu_bar::open_menu = -1;
										menu_bar::any_open = false;
									}
								};
								constexpr std::size_t maximum_entries_per_menu = 12;
								if (category_count <= maximum_entries_per_menu) {
									for (std::size_t entry_index = category_begin;
										entry_index < category_end; ++entry_index)
										render_view_entry(entry_index);
								} else {
									std::size_t page_begin = category_begin;
									while (page_begin < category_end) {
										const std::size_t page_end = (std::min)(
											page_begin + maximum_entries_per_menu, category_end);
										const std::size_t first = page_begin - category_begin + 1;
										const std::size_t last = page_end - category_begin;
										std::string page_label = "Views ";
										page_label.append(std::to_string(first)).append("-")
											.append(std::to_string(last));
										if (begin_native_menu(page_label.c_str())) {
											for (std::size_t entry_index = page_begin;
												entry_index < page_end; ++entry_index)
												render_view_entry(entry_index);
											ImGui::EndMenu();
										}
										page_begin = page_end;
									}
								}
								ImGui::EndMenu();
							}
							category_begin = category_end;
						}
						break;
					}
					case 3:
					{
						action_menu_item("analysis.navigate.back");
						action_menu_item("analysis.navigate.forward");
						action_menu_item("file.quick_open", "Ctrl+P");
						action_menu_item("navigate.previous_document_or_session");
						action_menu_item("navigate.next_document_or_session");
						menu_sep();
						action_menu_item("analysis.navigate.goto", "", "Go to Address...");
						action_menu_item("analysis.decompile_or_focus_pseudocode", nullptr, "Pseudocode");
						action_menu_item("analysis.toggle_graph_text", nullptr, "Graph / Text");
						action_menu_item("view.focus.document.hex", "", "Hex");
						action_menu_item("analysis.navigate.xrefs", nullptr, "Cross References");
						action_menu_item("view.focus.view.workspace_search", "Ctrl+Shift+F", "Workspace Search");
						menu_sep();
						action_menu_item("programming.language.definition", "F12");
						action_menu_item("programming.language.references", "Shift+F12");
						action_menu_item("programming.language.workspace_symbols");
						break;
					}
					case 4:
					{
						render_analysis_menu();
						break;
					}
					case 5:
					{
						render_debugger_menu();
						break;
					}
					case 6:
					{
						render_memory_menu();
						break;
					}
					case 7:
					{
						render_view_category(aida::ui::view_category_t::types);
						break;
					}
					case 8:
					{
						render_network_menu();
						break;
					}
					case 9:
					{
						const auto active = aida::ui::workspace_layout::active_identity();
						std::string active_label = "Active: ";
						active_label.append(workspace_preset_display_name(active.preset));
						active_label.append(" / ");
						active_label.append(active.kind ==
							aida::ui::workspace_layout::workspace_identity_kind_t::user
							? active.user_name : "Built-in");
						ImGui::MenuItem(active_label.c_str(), nullptr, false, false);
						menu_sep();
						std::size_t preset_count = 0;
						const auto* presets = aida::ui::workspace_layout::presets(preset_count);
						for (std::size_t preset_index = 0; preset_index < preset_count; ++preset_index) {
							const auto& preset = presets[preset_index];
							if (preset.id == aida::ui::workspace_layout::workspace_preset_t::safe)
								continue;
							std::string action_id = "workspace.switch.";
							action_id.append(preset.stable_id);
							action_menu_item(action_id.c_str(),
								active.kind == aida::ui::workspace_layout::workspace_identity_kind_t::built_in &&
								active.preset == preset.id ? "Active" : "",
								preset.display_name.data());
						}
						menu_sep();
						action_menu_item("workspace.lock", "", aida::ui::workspace_layout::layout_locked() ? "Unlock Layout" : "Lock Layout");
						action_menu_item("workspace.save_active");
						action_menu_item("workspace.save_as");
						const bool saved_workspaces_open = begin_native_menu("Saved Workspaces");
						register_workspace_semantic("aida.workspace.menu.saved-workspaces",
							"workspace-saved-menu");
						if (saved_workspaces_open) {
							const auto catalog = aida::ui::workspace_layout::user_layout_catalog();
							if (!catalog || catalog->empty())
								ImGui::MenuItem("No saved workspaces", nullptr, false, false);
							else {
								for (const auto& item : *catalog) {
									const char* detail = item.active ? "Active" :
										workspace_preset_display_name(item.base_preset);
									auto retained = named_workspace_load_context(item);
									const auto presentation =
										aida::ui::application_ui::present_retained_entity_action(
											"workspace.load_named", retained);
									const bool enabled = presentation.enabled;
									if (ImGui::MenuItem(item.name.c_str(), detail, false, enabled))
										load_workspace_from_menu(item);
									if (!enabled && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
										ImGui::SetTooltip("%s", presentation.disabled_reason.empty()
											? "The retained workspace action is unavailable."
											: presentation.disabled_reason.c_str());
									}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
									register_workspace_semantic(aida::preview::semantics::stable_id(
										"aida.workspace.menu.saved", item.name),
										"workspace-saved-menu-item", !enabled);
#endif
								}
							}
							menu_sep();
							action_menu_item("workspace.load_saved");
							ImGui::EndMenu();
						}
						action_menu_item("workspace.restore_builtin");
						action_menu_item("workspace.reset_current");
						action_menu_item("workspace.reset_all");
						action_menu_item("workspace.open_missing");
						action_menu_item("workspace.safe");
						break;
					}
					case 10:
					{
						action_menu_item("tools.load_binary");
						action_menu_item("tools.attach_process");
						menu_sep();
						action_menu_item("tools.settings", "", "MCP Servers");
						action_menu_item("tools.driver_status");
						menu_sep();
						action_menu_item("programming.index.rebuild");
						action_menu_item("programming.index.cancel");
						action_menu_item("programming.task.run");
						action_menu_item("programming.task.cancel");
						action_menu_item("programming.task.retry");
						action_menu_item("programming.task.configure");
						action_menu_item("programming.task.reload");
						action_menu_item("programming.show_problems");
						if (begin_native_menu("Language Services")) {
							action_menu_item("programming.language.completion", "Ctrl+Space");
							action_menu_item("programming.language.hover");
							action_menu_item("programming.language.signature_help");
							action_menu_item("programming.language.document_symbols", "Ctrl+Shift+O");
							action_menu_item("programming.language.workspace_symbols");
							action_menu_item("programming.language.diagnostics");
							action_menu_item("programming.language.definition", "F12");
							action_menu_item("programming.language.references", "Shift+F12");
							action_menu_item("programming.language.rename");
							action_menu_item("programming.language.format");
							action_menu_item("programming.language.code_actions");
							action_menu_item("programming.language.cancel_query");
							ImGui::EndMenu();
						}
						if (begin_native_menu("Code Review")) {
							review_action_menu_item("editor.ai.previous_pending_hunk");
							review_action_menu_item("editor.ai.next_pending_hunk");
							review_action_menu_item("editor.ai.accept_current_hunk");
							review_action_menu_item("editor.ai.reject_current_hunk");
							menu_sep();
							review_action_menu_item("editor.ai.accept_all");
							review_action_menu_item("editor.ai.reject_all");
							ImGui::EndMenu();
						}
						render_view_category(aida::ui::view_category_t::programming);
						break;
					}
					case 11:
					{
						action_menu_item("ai.new_chat", "Ctrl+L");
						action_menu_item("ai.model_settings");
						action_menu_item("ai.agent_picker.toggle");
						action_menu_item("ai.agent_mode.toggle_plan_build");
						menu_sep();
						render_view_category(aida::ui::view_category_t::automation);
						break;
					}
					case 12:
					{
						action_menu_item("help.shortcuts", "Ctrl+K, Ctrl+S");
						const std::string diagnostics_id =
							aida::ui::application_ui::view_action_id(
								aida::ui::stable_view_id_t("view.diagnostics"));
						action_menu_item(diagnostics_id.c_str(), "", "Diagnostics");
						break;
					}
					case 13:
					{
						auto begin_compact_section = [&](const char* label, int section) {
							const bool requested = compact_section_request == section;
							if (requested)
								ImGui::OpenPopup(label);
							const bool opened = begin_native_menu(label);
							if (opened && requested)
								ImGui::SetKeyboardFocusHere();
							return opened;
						};
						if (begin_compact_section("Analysis", 4)) {
							render_analysis_menu();
							ImGui::EndMenu();
						}
						if (begin_compact_section("Debugger", 5)) {
							render_debugger_menu();
							ImGui::EndMenu();
						}
						if (begin_compact_section("Memory", 6)) {
							render_memory_menu();
							ImGui::EndMenu();
						}
						if (begin_compact_section("Types and Structures", 7)) {
							render_view_category(aida::ui::view_category_t::types);
							ImGui::EndMenu();
						}
						if (begin_compact_section("Network", 8)) {
							render_network_menu();
							ImGui::EndMenu();
						}
						if (begin_compact_section("Workspace", 9)) {
							const auto active = aida::ui::workspace_layout::active_identity();
							std::string active_label = "Active: ";
							active_label.append(workspace_preset_display_name(active.preset));
							active_label.append(" / ");
							active_label.append(active.kind ==
								aida::ui::workspace_layout::workspace_identity_kind_t::user
								? active.user_name : "Built-in");
							ImGui::MenuItem(active_label.c_str(), nullptr, false, false);
							menu_sep();
							std::size_t preset_count = 0;
							const auto* presets = aida::ui::workspace_layout::presets(preset_count);
							for (std::size_t preset_index = 0; preset_index < preset_count; ++preset_index) {
								const auto& preset = presets[preset_index];
								if (preset.id == aida::ui::workspace_layout::workspace_preset_t::safe)
									continue;
								std::string action_id = "workspace.switch.";
								action_id.append(preset.stable_id);
								action_menu_item(action_id.c_str(),
									active.kind == aida::ui::workspace_layout::workspace_identity_kind_t::built_in &&
									active.preset == preset.id ? "Active" : "",
									preset.display_name.data());
							}
							menu_sep();
							action_menu_item("workspace.lock", "",
								aida::ui::workspace_layout::layout_locked() ? "Unlock Layout" : "Lock Layout");
							action_menu_item("workspace.save_active");
							action_menu_item("workspace.save_as");
							const bool saved_workspaces_open = begin_native_menu("Saved Workspaces");
							register_workspace_semantic("aida.workspace.compact.saved-workspaces",
								"workspace-saved-menu");
							if (saved_workspaces_open) {
								const auto catalog = aida::ui::workspace_layout::user_layout_catalog();
								if (!catalog || catalog->empty())
									ImGui::MenuItem("No saved workspaces", nullptr, false, false);
								else {
									for (const auto& item : *catalog) {
										const char* detail = item.active ? "Active" :
											workspace_preset_display_name(item.base_preset);
										auto retained = named_workspace_load_context(item);
										const auto presentation =
											aida::ui::application_ui::present_retained_entity_action(
												"workspace.load_named", retained);
										const bool enabled = presentation.enabled;
										if (ImGui::MenuItem(item.name.c_str(), detail, false, enabled))
											load_workspace_from_menu(item);
										if (!enabled && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
											ImGui::SetTooltip("%s", presentation.disabled_reason.empty()
												? "The retained workspace action is unavailable."
												: presentation.disabled_reason.c_str());
										}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
										register_workspace_semantic(aida::preview::semantics::stable_id(
											"aida.workspace.compact.saved", item.name),
											"workspace-saved-menu-item", !enabled);
#endif
									}
								}
								menu_sep();
								action_menu_item("workspace.load_saved");
								ImGui::EndMenu();
							}
							action_menu_item("workspace.restore_builtin");
							action_menu_item("workspace.reset_current");
							action_menu_item("workspace.reset_all");
							action_menu_item("workspace.open_missing");
							action_menu_item("workspace.safe");
							ImGui::EndMenu();
						}
						if (begin_compact_section("Tools", 10)) {
							action_menu_item("tools.load_binary");
							action_menu_item("tools.attach_process");
							action_menu_item("tools.settings", "", "MCP Servers");
							action_menu_item("tools.driver_status");
							action_menu_item("programming.index.rebuild");
							action_menu_item("programming.index.cancel");
							action_menu_item("programming.task.run");
							action_menu_item("programming.task.cancel");
							action_menu_item("programming.task.retry");
							action_menu_item("programming.task.configure");
							action_menu_item("programming.task.reload");
							action_menu_item("programming.show_problems");
							if (begin_native_menu("Language Services")) {
								action_menu_item("programming.language.completion", "Ctrl+Space");
								action_menu_item("programming.language.hover");
								action_menu_item("programming.language.signature_help");
								action_menu_item("programming.language.document_symbols", "Ctrl+Shift+O");
								action_menu_item("programming.language.workspace_symbols");
								action_menu_item("programming.language.diagnostics");
								action_menu_item("programming.language.definition", "F12");
								action_menu_item("programming.language.references", "Shift+F12");
								action_menu_item("programming.language.rename");
								action_menu_item("programming.language.format");
								action_menu_item("programming.language.code_actions");
								action_menu_item("programming.language.cancel_query");
								ImGui::EndMenu();
							}
							if (begin_native_menu("Code Review")) {
								review_action_menu_item("editor.ai.previous_pending_hunk");
								review_action_menu_item("editor.ai.next_pending_hunk");
								review_action_menu_item("editor.ai.accept_current_hunk");
								review_action_menu_item("editor.ai.reject_current_hunk");
								menu_sep();
								review_action_menu_item("editor.ai.accept_all");
								review_action_menu_item("editor.ai.reject_all");
								ImGui::EndMenu();
							}
							render_view_category(aida::ui::view_category_t::programming);
							ImGui::EndMenu();
						}
						if (begin_compact_section("AI", 11)) {
							action_menu_item("ai.new_chat", "Ctrl+L");
							action_menu_item("ai.model_settings");
							action_menu_item("ai.agent_picker.toggle");
							action_menu_item("ai.agent_mode.toggle_plan_build");
							render_view_category(aida::ui::view_category_t::automation);
							ImGui::EndMenu();
						}
						if (begin_compact_section("Help", 12)) {
							action_menu_item("help.shortcuts", "Ctrl+K, Ctrl+S");
							const std::string diagnostics_id =
								aida::ui::application_ui::view_action_id(
									aida::ui::stable_view_id_t("view.diagnostics"));
							action_menu_item(diagnostics_id.c_str(), "", "Diagnostics");
							ImGui::EndMenu();
						}
						break;
					}
					}
					ImGui::EndPopup();
				} else if (!ImGui::IsPopupOpen(popup_id)) {
					menu_bar::open_menu = -1;
					menu_bar::any_open = false;
				}
			ImGui::PopFont();
			ImGui::PopStyleVar(1);
			}

			mx_cursor += btn_w;
		}


	}

	if (!ide_surface) {
		ImGui::PopStyleVar();
		ImGui::End();
		aida::ui::application_ui::process_global_shortcuts();
		g_render_section = "done";
		return;
	}
	ImGui::PopStyleVar();
	aida::ui::ide_shell::end_global_chrome_surface();
	aida::ui::ide_shell::render_primary_surfaces();
	aida::ui::application_ui::render_action_confirmation();
	g_render_section = "popups_programming_tasks";
	aida::ui::programming_tasks::render_modals();
	debugger_view::render_global_target_dialog();
	g_render_section = "popups_workspace_management";
	render_workspace_dialogs();

	g_render_section = "file_tabs_popup";
	{
		if (file_tabs::pending_close_after_save_document_id != 0)
			file_tabs::resolve_pending_close_after_save();
		else if (!file_tabs::pending_close_all_document_ids.empty())
			file_tabs::advance_close_all();
		file_tabs::poll_exit_review();
		bool popup_active = (file_tabs::pending_close_idx >= 0);


		static std::uint64_t reviewed_close_document = 0;
		static bool close_dialog_requested = false;
		if (popup_active) {
			const int ci = file_tabs::pending_close_idx;
			const std::uint64_t current_document = file_tabs::is_valid_tab_index(ci)
				? file_tabs::tabs[file_tabs::tab_index(ci)].document_id : 0;
			if (!close_dialog_requested || current_document != reviewed_close_document) {
				reviewed_close_document = current_document;
				aida::ui::design::open_dialog("editor_dirty_close", "Unsaved Changes");
				close_dialog_requested = true;
			}
		}
		if (popup_active && aida::ui::design::begin_dialog("editor_dirty_close", "Unsaved Changes",
				ImVec2(560.f, 390.f), ImVec2(400.f, 280.f))) {
			const int ci = file_tabs::pending_close_idx;
			const bool target_current = file_tabs::is_valid_tab_index(ci) &&
				file_tabs::tabs[file_tabs::tab_index(ci)].document_id == reviewed_close_document;
			const std::string fname = target_current
				? file_tabs::tabs[file_tabs::tab_index(ci)].filename : "the reviewed document";
			const auto save_gate = target_current
				? file_tabs::verify_tab_save_gate(ci, false)
				: file_tabs::save_result_t{false, "The reviewed document is no longer current."};
			const bool save_disabled = !target_current || !save_gate.succeeded;
			const bool close_disabled = !target_current ||
				file_tabs::close_operation_pending(file_tabs::tabs[file_tabs::tab_index(ci)]);
			const bool stack_close_actions = ImGui::GetContentRegionAvail().x < 320.f;
			const float footer_height = stack_close_actions
				? 126.f : aida::ui::design::dialog_footer_reserve_height("Cancel", "") + 8.f;
			aida::ui::design::begin_dialog_body("editor_dirty_close_body", footer_height);
			ImGui::TextWrapped("Save changes to '%s' before closing?", fname.c_str());
			if (!file_tabs::close_confirm_error.empty())
				aida::ui::components::inline_notice("save_error", "Save failed",
					file_tabs::close_confirm_error.c_str(), aida::ui::components::status_kind_t::error);
			if (!target_current)
				aida::ui::components::inline_notice("stale_target", "Document changed",
					"The reviewed document is no longer current. Cancel and review the active close request.",
					aida::ui::components::status_kind_t::warning);
			else if (!save_gate.succeeded)
				aida::ui::components::inline_notice("save_unavailable", "Save unavailable",
					save_gate.detail.c_str(), aida::ui::components::status_kind_t::warning);
			if (!file_tabs::pending_close_all_document_ids.empty()) {
				ImGui::SeparatorText("Close queue");
				std::unordered_map<std::uint64_t, std::string> document_names;
				document_names.reserve(file_tabs::tabs.size());
				for (const auto& tab : file_tabs::tabs) {
					if (tab.document_id != 0)
						document_names.emplace(tab.document_id, tab.filename);
				}
				ImGuiListClipper queue_clipper;
				queue_clipper.Begin(static_cast<int>(file_tabs::pending_close_all_document_ids.size()));
				while (queue_clipper.Step()) {
					for (int queue_index = queue_clipper.DisplayStart;
						 queue_index < queue_clipper.DisplayEnd; ++queue_index) {
						const std::uint64_t document_id = file_tabs::pending_close_all_document_ids[
							static_cast<std::size_t>(queue_index)];
						const auto found = document_names.find(document_id);
						const std::string document_name = found != document_names.end() && !found->second.empty()
							? found->second : "Document " + std::to_string(document_id);
						const std::string document_token = std::to_string(document_id);
						ImGui::PushID(document_token.c_str());
						ImGui::BulletText("%s", document_name.c_str());
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						aida::preview::semantics::register_last_item(
							aida::preview::semantics::stable_id(
								"aida.editor.dirty-close.document", document_token),
							"dirty-document");
#endif
						ImGui::PopID();
					}
				}
				queue_clipper.End();
			}
			aida::ui::design::end_dialog_body();
			ImGui::Separator();
			const float action_width = stack_close_actions
				? ImGui::GetContentRegionAvail().x
				: (std::max)(92.f,
					(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 2.f) / 3.f);
			int action = -1;
			if (aida::ui::components::button("Save", aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md, ImVec2(action_width, 34.f), save_disabled))
				action = 0;
			if (!save_disabled)
				ImGui::SetItemDefaultFocus();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.editor.dirty-close.save", "dialog-action", false, save_disabled);
#endif
			if (!stack_close_actions)
				ImGui::SameLine();
			if (aida::ui::components::button("Don't Save", aida::ui::components::button_kind_t::destructive,
					aida::ui::components::size_t_::md, ImVec2(action_width, 34.f), close_disabled))
				action = 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.editor.dirty-close.discard", "dialog-action", false, close_disabled);
#endif
			if (!stack_close_actions)
				ImGui::SameLine();
			if (aida::ui::components::button("Cancel", aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md, ImVec2(action_width, 34.f)) ||
				ImGui::IsKeyPressed(ImGuiKey_Escape, false))
				action = 2;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.editor.dirty-close.cancel", "dialog-action");
#endif
			if (action == 0) {
				const std::uint64_t closing_document = file_tabs::is_valid_tab_index(ci)
					? file_tabs::tabs[file_tabs::tab_index(ci)].document_id : 0;
				const std::uint64_t closing_revision = file_tabs::is_valid_tab_index(ci)
					? file_tabs::tabs[file_tabs::tab_index(ci)].revision : 0;
				file_tabs::save_result_t saved{false, "The document is no longer open."};
				if (file_tabs::is_valid_tab_index(ci))
					saved = file_tabs::tabs[file_tabs::tab_index(ci)].filepath.empty()
						? save_document_as(ci)
						: file_tabs::save_tab_to_disk_result(ci);
				if (saved.succeeded) {
					file_tabs::pending_close_idx = -1;
					file_tabs::close_confirm_error.clear();
					if (file_tabs::is_valid_tab_index(ci) &&
						file_tabs::tabs[file_tabs::tab_index(ci)].save_in_progress) {
						file_tabs::pending_close_after_save_document_id = closing_document;
					} else if (file_tabs::exit_review_requested) {
						file_tabs::resolve_exit_review_document(closing_document,
							closing_revision, false);
					} else {
						file_tabs::close_tab(ci);
						file_tabs::finish_close_all_document(closing_document);
						file_tabs::advance_close_all();
					}
				} else {
					file_tabs::close_confirm_error = saved.detail;
				}
			} else if (action == 1) {
				const std::uint64_t closing_document = file_tabs::is_valid_tab_index(ci)
					? file_tabs::tabs[file_tabs::tab_index(ci)].document_id : 0;
				const std::uint64_t closing_revision = file_tabs::is_valid_tab_index(ci)
					? file_tabs::tabs[file_tabs::tab_index(ci)].revision : 0;
				if (!file_tabs::exit_review_requested)
					file_tabs::close_tab(ci, true);
				file_tabs::pending_close_idx = -1;
				file_tabs::close_confirm_error.clear();
				if (file_tabs::exit_review_requested)
					file_tabs::resolve_exit_review_document(closing_document,
						closing_revision, true);
				else {
					file_tabs::finish_close_all_document(closing_document);
					file_tabs::advance_close_all();
				}
			} else if (action == 2) {
				file_tabs::pending_close_idx = -1;
				file_tabs::close_confirm_error.clear();
				file_tabs::cancel_close_all();
			}
			if (action >= 0 && action != 0) {
				close_dialog_requested = false;
				reviewed_close_document = 0;
				ImGui::CloseCurrentPopup();
			} else if (action == 0 && file_tabs::pending_close_idx < 0) {
				close_dialog_requested = false;
				reviewed_close_document = 0;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		} else if (!popup_active) {
			close_dialog_requested = false;
			reviewed_close_document = 0;
			file_tabs::show_close_confirm = false;
		}
	}

	g_render_section = "post_bottom_tick_ai_chat";
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	tick_ai_chat();
	g_render_section = "post_bottom_poll_ai_chat";
	poll_ai_chat();
#endif
	g_render_section = "post_bottom_poll_ai_chat_done";

	g_render_section = "popups";


	g_render_section = "popups_attach_dialog";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	using shell_process_info_t = aida::preview::process_fixture_t;
#else
	using shell_process_info_t = driver_bridge::process_info_t;
#endif
	static int pa_open_frame = -1;
	static float pa_anim = 0.f;
	static bool pa_closing = false;
	static std::vector<shell_process_info_t> pa_proc_list;
	static int pa_selected = -1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static float pa_refresh_timer = 0.f;
	static std::mutex pa_proc_pending_mtx;
	static std::vector<shell_process_info_t> pa_pending_proc_list;
	static uint64_t pa_pending_epoch = 0;
	static std::atomic<bool> pa_refresh_inflight{false};
	static std::atomic<bool> pa_refresh_ready{false};
	static uint64_t pa_refresh_epoch = 0;
	static uint64_t pa_applied_epoch = 0;
	const bool pa_attach_inflight = process_attach_active();
#else
	const bool pa_attach_inflight = false;
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_process_revision = 0;
	if (preview_process_revision != aida::preview::controls().revision) {
		preview_process_revision = aida::preview::controls().revision;
		pa_proc_list = aida::preview::processes();
		pa_selected = (std::max)(0, (std::min)(aida::preview::controls().process_selection,
			static_cast<int>(pa_proc_list.size()) - 1));
		pa_closing = false;
		pa_anim = aida::preview::controls().process_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_pa = ImGui::GetIO().DeltaTime;
		float pa_target = (globals::ui::process_attach_open && !pa_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) pa_anim = pa_target;
		else
		#endif
		pa_anim += (pa_target - pa_anim) * (std::min)(dt_pa * 14.f, 1.f);
		if (std::abs(pa_anim - pa_target) < 0.003f) pa_anim = pa_target;

		if (pa_closing && pa_anim < 0.01f) {
			pa_closing = false;
			globals::ui::process_attach_open = false;
			pa_open_frame = -1;
			pa_anim = 0.f;
			pa_selected = -1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			pa_refresh_timer = 0.f;
#endif
			globals::ui::process_filter_buf[0] = '\0';
		}
	}

	bool pa_render = globals::ui::process_attach_open || pa_anim > 0.005f;
	if (pa_render) {
		if (pa_open_frame < 0) pa_open_frame = ImGui::GetFrameCount();

		const auto& th_pa = aida::ui::resolved();
		float ax_pa = globals::ui::accent.x, ay_pa = globals::ui::accent.y, az_pa = globals::ui::accent.z;

		ImGuiViewport* pa_viewport = ImGui::GetMainViewport();
		const ImVec2 pa_work_pos = pa_viewport ? pa_viewport->WorkPos : ImVec2(0.f, 0.f);
		const ImVec2 pa_work_size = pa_viewport ? pa_viewport->WorkSize : ImGui::GetIO().DisplaySize;
		const float pa_dpi = pa_viewport && pa_viewport->DpiScale > 0.f ? pa_viewport->DpiScale : 1.f;
		float pw = (std::min)(620.f * pa_dpi, (std::max)(1.f, pa_work_size.x - 32.f * pa_dpi));
		float ph = (std::min)(490.f * pa_dpi, (std::max)(1.f, pa_work_size.y - 32.f * pa_dpi));
		float pa_scale = 0.96f + 0.04f * pa_anim;
		float sw = pw * pa_scale, sh = ph * pa_scale;
		float px = pa_work_pos.x + (pa_work_size.x - sw) * 0.5f;
		float py = pa_work_pos.y + (pa_work_size.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !pa_closing) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (pa_attach_inflight)
				static_cast<void>(request_active_process_attach_cancel());
#endif
			pa_closing = true;
		}


		if (ImGui::GetFrameCount() > pa_open_frame + 1 && !pa_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				pa_closing = true;
		}


		ImGui::SetNextWindowPos({px, py});
		ImGui::SetNextWindowSize({sw, sh});
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

		ImGui::Begin("##pa_popup", nullptr,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			ImVec2 ws = ImGui::GetWindowSize();


			ImDrawList* bgdl = ImGui::GetBackgroundDrawList();
			for (int si = 4; si >= 0; --si) {
				float e = static_cast<float>(si) * 5.f;
				int sa = static_cast<int>(22.f * pa_anim * (1.f - static_cast<float>(si) * 0.2f));
				bgdl->AddRectFilled(ImVec2(wp.x - e, wp.y - e), ImVec2(wp.x + ws.x + e, wp.y + ws.y + e),
					IM_COL32(0, 0, 0, sa), 12.f + e);
			}


			float hdr_h = 44.f;
			dl->AddRectFilled({wp.x + 1, wp.y + 1}, {wp.x + ws.x - 1, wp.y + hdr_h},
				IM_COL32(static_cast<int>(ax_pa * 30), static_cast<int>(ay_pa * 30),
					static_cast<int>(az_pa * 30), static_cast<int>(220.f * pa_anim)),
				9.f, ImDrawFlags_RoundCornersTop);
			dl->AddLine({wp.x, wp.y + hdr_h}, {wp.x + ws.x, wp.y + hdr_h},
				aida::ui::with_alpha(th_pa.border_subtle, pa_anim));


			dl->AddText(ImVec2(wp.x + 18.f, wp.y + (hdr_h - ImGui::GetFontSize()) * 0.5f),
				aida::ui::with_alpha(th_pa.text_primary, pa_anim), "Attach to Process");


			{
				float xsz = 18.f;
				float xx = wp.x + ws.x - xsz - 14.f, xy = wp.y + (hdr_h - xsz) * 0.5f;
				ImVec2 mpos = ImGui::GetIO().MousePos;
				bool x_hov = mpos.x >= xx && mpos.x <= xx + xsz && mpos.y >= xy && mpos.y <= xy + xsz;
				if (x_hov)
					dl->AddRectFilled({xx - 3, xy - 3}, {xx + xsz + 3, xy + xsz + 3},
						aida::ui::with_alpha(th_pa.error, 0.14f * pa_anim), 4.f);
				float xc = xx + xsz * 0.5f, yc = xy + xsz * 0.5f;
				ImU32 x_col = aida::ui::with_alpha(x_hov ? th_pa.error : th_pa.text_secondary, pa_anim);
				dl->AddLine({xc - 4, yc - 4}, {xc + 4, yc + 4}, x_col, 1.5f);
				dl->AddLine({xc + 4, yc - 4}, {xc - 4, yc + 4}, x_col, 1.5f);
				if (x_hov && ImGui::IsMouseClicked(0) && !pa_closing && ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows)) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
					if (pa_attach_inflight)
						static_cast<void>(request_active_process_attach_cancel());
#endif
					pa_closing = true;
				}
			}


		ImGui::SetCursorPos(ImVec2(1.f, hdr_h + 1.f));
		ImGui::BeginChild("##pa_inner", ImVec2(ws.x - 2.f, ws.y - hdr_h - 2.f), false,
			ImGuiWindowFlags_NoBackground);
			{

			ImGui::SetNextItemWidth(-1);
			ImGui::InputTextWithHint("##pa_filter", "Search processes...",
				globals::ui::process_filter_buf, sizeof(globals::ui::process_filter_buf));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.process.attach.search", "process-search", true);
#endif
			ImGui::Spacing();


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				if (!pa_attach_inflight &&
					pa_refresh_ready.exchange(false, std::memory_order_acq_rel)) {
					std::lock_guard<std::mutex> lock(pa_proc_pending_mtx);
					if (pa_pending_epoch > pa_applied_epoch) {
						const std::uint32_t selected_pid = pa_selected >= 0 &&
							pa_selected < static_cast<int>(pa_proc_list.size())
							? pa_proc_list[static_cast<std::size_t>(pa_selected)].pid : 0;
						pa_proc_list = std::move(pa_pending_proc_list);
						pa_applied_epoch = pa_pending_epoch;
						pa_selected = -1;
						if (selected_pid != 0) {
							for (int index = 0; index < static_cast<int>(pa_proc_list.size()); ++index) {
								if (pa_proc_list[static_cast<std::size_t>(index)].pid == selected_pid) {
									pa_selected = index;
									break;
								}
							}
						}
					}
					pa_refresh_inflight.store(false, std::memory_order_release);
				}

				pa_refresh_timer -= ImGui::GetIO().DeltaTime;
				if (!pa_attach_inflight &&
					(pa_refresh_timer <= 0.f || pa_proc_list.empty()) &&
					!pa_refresh_inflight.exchange(true, std::memory_order_acq_rel)) {
					const uint64_t epoch = ++pa_refresh_epoch;
					const auto submit_result = submit_helpers_executor_task(
						"process_attach",
						"process_attach.enumerate_processes",
						aida::infra::executor::domain_t::feature_worker,
						"bounded_task",
						[epoch]() {
						std::vector<shell_process_info_t> list;
						try {
							list = driver_bridge::enumerate_processes();
						} catch (...) {
							OutputDebugStringA("AiDA Standalone: EXCEPTION in enumerate_processes()\n");
						}
						{
							std::lock_guard<std::mutex> lock(pa_proc_pending_mtx);
							pa_pending_proc_list = std::move(list);
							pa_pending_epoch = epoch;
						}
						pa_refresh_ready.store(true, std::memory_order_release);
					});
					if (!submit_result.submitted) {
						pa_refresh_inflight.store(false, std::memory_order_release);
						pa_refresh_timer = 1.f;
					} else {
						pa_refresh_timer = 2.f;
					}
				}
#endif


				std::string filt(globals::ui::process_filter_buf);
				for (auto& c : filt) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
				static std::string pa_cached_filter;
				static std::uint64_t pa_cached_filter_epoch = (std::numeric_limits<std::uint64_t>::max)();
				static std::vector<int> pa_filtered_indices;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::uint64_t pa_filter_epoch = preview_process_revision;
#else
				const std::uint64_t pa_filter_epoch = pa_applied_epoch;
#endif
				if (pa_cached_filter != filt || pa_cached_filter_epoch != pa_filter_epoch) {
					pa_cached_filter = filt;
					pa_cached_filter_epoch = pa_filter_epoch;
					pa_filtered_indices.clear();
					pa_filtered_indices.reserve(pa_proc_list.size());
					for (int i = 0; i < static_cast<int>(pa_proc_list.size()); ++i) {
						const auto& process = pa_proc_list[static_cast<std::size_t>(i)];
						bool matches = filt.empty();
						if (!matches) {
							std::string searchable = process.name + "\n" + process.window_title + "\n" +
								process.path + "\n" + std::to_string(process.pid);
							for (auto& character : searchable)
								character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
							matches = searchable.find(filt) != std::string::npos;
						}
						if (matches)
							pa_filtered_indices.push_back(i);
					}
				}


			float list_h = ws.y - hdr_h - 108.f;

			bool do_attach = false;
				if (ImGui::BeginTable("##pa_table", 3,
					ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
					ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
					ImVec2(-1, list_h))) {

					ImGui::TableSetupScrollFreeze(0, 1);
					ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 55.f);
					ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 175.f);
					ImGui::TableSetupColumn("Window Title", ImGuiTableColumnFlags_WidthStretch);
					ImGui::TableHeadersRow();

					ImGuiListClipper process_clipper;
					process_clipper.Begin(static_cast<int>(pa_filtered_indices.size()), 25.f);
					while (process_clipper.Step()) {
					for (int visible_index = process_clipper.DisplayStart;
						 visible_index < process_clipper.DisplayEnd; ++visible_index) {
						const int i = pa_filtered_indices[static_cast<std::size_t>(visible_index)];
						auto& p = pa_proc_list[static_cast<std::size_t>(i)];

						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::PushID(i);

						bool sel = (pa_selected == i);
						const bool row_clicked = ImGui::Selectable("##ps", sel,
							ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
							ImVec2(0, 20));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						aida::preview::semantics::register_last_item(
							aida::preview::semantics::stable_id(
								"aida.process.attach.row", std::to_string(p.pid)),
							"process-row", false, pa_attach_inflight);
#endif
						if (!pa_attach_inflight && row_clicked) {
							pa_selected = i;
						}
						if (!pa_attach_inflight && ImGui::IsItemHovered() &&
							ImGui::IsMouseDoubleClicked(0)) {
							pa_selected = i;
							do_attach = true;
						}

						ImGui::SameLine();
						ImGui::Text("%u", static_cast<unsigned>(p.pid));

						ImGui::TableSetColumnIndex(1);
						if (!p.window_title.empty())
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_primary), "%s", p.name.c_str());
						else
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_secondary), "%s", p.name.c_str());

						ImGui::TableSetColumnIndex(2);
						if (!p.window_title.empty())
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.accent_u32), "%s", p.window_title.c_str());
						else if (!p.path.empty()) {
							auto slash = p.path.find_last_of("\\/");
							std::string dir = (slash != std::string::npos) ? p.path.substr(0, slash) : p.path;
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_dim), "%s", dir.c_str());
						}
						ImGui::PopID();
					}
					}
					process_clipper.End();
				ImGui::EndTable();
			}

			ImGui::Spacing();


				bool can_attach = !pa_attach_inflight && pa_selected >= 0 &&
					pa_selected < static_cast<int>(pa_proc_list.size());
				float btn_w = 100.f, btn_h = 30.f;
				float total_btn_w = btn_w * 2.f + 12.f;
				ImGui::SetCursorPosX((ImGui::GetWindowWidth() - total_btn_w) * 0.5f);

				if (aida::ui::components::button("Attach",
					aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h),
					!can_attach) && can_attach) {
					do_attach = true;
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.process.attach.confirm", "process-attach", false, !can_attach);
#endif

				ImGui::SameLine(0, 12.f);
				if (aida::ui::components::button("Cancel",
					aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h))) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
					if (pa_attach_inflight)
						static_cast<void>(request_active_process_attach_cancel());
#endif
					pa_closing = true;
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.process.attach.cancel", "dialog-cancel");
#endif


				if (do_attach && can_attach) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::attach_process(
						pa_proc_list[static_cast<std::size_t>(pa_selected)]);
					pa_closing = true;
#else
					const std::size_t reviewed_index = static_cast<std::size_t>(pa_selected);
					const auto reviewed_process = pa_proc_list[reviewed_index];
					const std::uint64_t reviewed_epoch = pa_applied_epoch;
					process_attach_request_t request;
					request.selection_epoch = reviewed_epoch;
					request.pid = reviewed_process.pid;
					request.process_name = reviewed_process.name;
					request.process_path = reviewed_process.path;
					request.window_title = reviewed_process.window_title;
					std::string dispatch_error;
					const bool queued = begin_process_attach(
						std::move(request),
						[reviewed_index, reviewed_epoch, reviewed_pid = reviewed_process.pid] {
							return !pa_closing && pa_applied_epoch == reviewed_epoch &&
								pa_selected == static_cast<int>(reviewed_index) &&
								reviewed_index < pa_proc_list.size() &&
								pa_proc_list[reviewed_index].pid == reviewed_pid;
						},
						[] { pa_closing = true; },
						dispatch_error);
					if (!queued) {
						output_log::push(bottom_tab_t::output,
							"[Driver] Attach request was not queued: " + dispatch_error + "\n");
						diag::log_tagged_critical_fmt("attach",
							"dispatch_rejected pid=%u detail=%s",
							reviewed_process.pid, dispatch_error.c_str());
					}
#endif
				}
			}
		ImGui::EndChild();
	}
	ImGui::End();
	ImGui::PopStyleVar(1);
} else {
		pa_open_frame = -1;
	}


	g_render_section = "popups_driver_status";
	static int ds_open_frame = -1;
	static float ds_anim = 0.f;
	static bool ds_closing = false;
	static std::uint32_t ds_detach_review_pid = 0;
	static std::string ds_detach_review_name;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_driver_revision = 0;
	if (preview_driver_revision != aida::preview::controls().revision) {
		preview_driver_revision = aida::preview::controls().revision;
		ds_closing = false;
		ds_anim = aida::preview::controls().driver_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_ds = ImGui::GetIO().DeltaTime;
		float ds_target = (globals::ui::driver_status_open && !ds_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) ds_anim = ds_target;
		else
		#endif
		ds_anim += (ds_target - ds_anim) * (std::min)(dt_ds * 14.f, 1.f);
		if (std::abs(ds_anim - ds_target) < 0.003f) ds_anim = ds_target;

		if (ds_closing && ds_anim < 0.01f) {
			ds_closing = false;
			globals::ui::driver_status_open = false;
			ds_open_frame = -1;
			ds_anim = 0.f;
		}
	}

	if (globals::ui::driver_status_open || ds_anim > 0.005f) {
		if (ds_open_frame < 0) ds_open_frame = ImGui::GetFrameCount();

		ImGuiViewport* ds_viewport = ImGui::GetMainViewport();
		const ImVec2 ds_work_pos = ds_viewport ? ds_viewport->WorkPos : ImVec2(0.f, 0.f);
		const ImVec2 ds_work_size = ds_viewport ? ds_viewport->WorkSize : ImGui::GetIO().DisplaySize;
		const float ds_dpi = ds_viewport && ds_viewport->DpiScale > 0.f ? ds_viewport->DpiScale : 1.f;
		float pw = (std::min)(500.f * ds_dpi, (std::max)(1.f, ds_work_size.x - 32.f * ds_dpi));
		float ph = (std::min)(380.f * ds_dpi, (std::max)(1.f, ds_work_size.y - 32.f * ds_dpi));
		float ds_scale = 0.96f + 0.04f * ds_anim;
		float sw = pw * ds_scale, sh = ph * ds_scale;
		float px = ds_work_pos.x + (ds_work_size.x - sw) * 0.5f;
		float py = ds_work_pos.y + (ds_work_size.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !ds_closing)
			ds_closing = true;

		if (ImGui::GetFrameCount() > ds_open_frame + 1 && !ds_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				ds_closing = true;
		}

		const auto& th_ds = aida::ui::resolved();
		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();

		ImGui::Begin("Driver Status##drv_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			bool is_attached = aida::preview::attached_pid() != 0;
#else
			bool is_attached = driver_bridge::attached_pid() != 0;
#endif
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(is_attached ? th_ds.success : th_ds.text_secondary),
				is_attached ? "Status: Attached" : "Status: Detached");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.driver.status.summary", "driver-status");
#endif

			if (is_attached) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				ImGui::Text("Process: %s", aida::preview::attached_process_name().c_str());
				ImGui::Text("PID: %u", static_cast<unsigned>(aida::preview::attached_pid()));
#else
				ImGui::Text("Process: %s", driver_bridge::attached_process_name().c_str());
				ImGui::Text("PID: %u", (unsigned)driver_bridge::attached_pid());
#endif
				ImGui::Separator();

				static int drv_tab = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				using shell_module_info_t = aida::preview::module_fixture_t;
				using shell_thread_info_t = aida::preview::thread_fixture_t;
#else
				using shell_module_info_t = driver_bridge::module_info_t;
				using shell_thread_info_t = driver_bridge::thread_info_t;
#endif
				static std::vector<shell_module_info_t> ds_mods_cache;
				static std::vector<shell_thread_info_t>  ds_threads_cache;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				static long long                                  ds_mods_last_ms = 0;
				static long long                                  ds_threads_last_ms = 0;
				static uint32_t                                   ds_mods_cache_pid = 0;
				static uint32_t                                   ds_threads_cache_pid = 0;
				static std::shared_mutex                          ds_mods_mu;
				static std::shared_mutex                          ds_threads_mu;
				static std::atomic<bool>                          ds_mods_in_flight{false};
				static std::atomic<bool>                          ds_threads_in_flight{false};
				long long _ds_now_ms = static_cast<long long>(aida::shell_platform::tick_ms());
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				if (ds_mods_cache.empty()) ds_mods_cache = aida::preview::modules();
				if (ds_threads_cache.empty()) ds_threads_cache = aida::preview::threads();
				drv_tab = aida::preview::controls().driver_tab;
#endif
				ImGuiTabItemFlags modules_tab_flags = ImGuiTabItemFlags_None;
				ImGuiTabItemFlags threads_tab_flags = ImGuiTabItemFlags_None;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				modules_tab_flags = drv_tab == 0 ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
				threads_tab_flags = drv_tab == 1 ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
#endif
				if (ImGui::BeginTabBar("##drv_tabs")) {
					if (ImGui::BeginTabItem("Modules", nullptr, modules_tab_flags)) {
						drv_tab = 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
						uint32_t cur_pid = driver_bridge::attached_pid();
						bool need_refresh = false;
						{
							std::shared_lock<std::shared_mutex> lk(ds_mods_mu);
							if (ds_mods_cache_pid != cur_pid || (_ds_now_ms - ds_mods_last_ms) >= 2000)
								need_refresh = true;
						}
						if (need_refresh) {
							bool expected = false;
							if (ds_mods_in_flight.compare_exchange_strong(expected, true)) {
								const auto submit_result = submit_helpers_executor_task(
									"driver_state",
									"driver_state.enumerate_modules",
									aida::infra::executor::domain_t::feature_worker,
									"bounded_task",
									[cur_pid]() {
									std::vector<driver_bridge::module_info_t> fresh;
									try {
										fresh = driver_bridge::enumerate_modules();
									} catch (...) {
										fresh.clear();
									}
									{
										std::unique_lock<std::shared_mutex> lk(ds_mods_mu);
										ds_mods_cache = std::move(fresh);
										ds_mods_cache_pid = cur_pid;
										ds_mods_last_ms = static_cast<long long>(aida::shell_platform::tick_ms());
									}
									ds_mods_in_flight.store(false);
								});
								if (!submit_result.submitted)
									ds_mods_in_flight.store(false);
							}
						}
#endif
						std::vector<shell_module_info_t> mods_view;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						mods_view = ds_mods_cache;
#else
						{
							std::shared_lock<std::shared_mutex> lk(ds_mods_mu);
							mods_view = ds_mods_cache;
						}
#endif
						ImGui::BeginChild("##mod_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(mods_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& m = mods_view[static_cast<std::size_t>(i)];
								ImGui::Text("0x%llX  %s", (unsigned long long)m.base, m.name.c_str());
							}
						}
						clipper.End();
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("Threads", nullptr, threads_tab_flags)) {
						drv_tab = 1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
						uint32_t cur_pid = driver_bridge::attached_pid();
						bool need_refresh = false;
						{
							std::shared_lock<std::shared_mutex> lk(ds_threads_mu);
							if (ds_threads_cache_pid != cur_pid || (_ds_now_ms - ds_threads_last_ms) >= 2000)
								need_refresh = true;
						}
						if (need_refresh) {
							bool expected = false;
							if (ds_threads_in_flight.compare_exchange_strong(expected, true)) {
								const auto submit_result = submit_helpers_executor_task(
									"driver_state",
									"driver_state.enumerate_threads",
									aida::infra::executor::domain_t::feature_worker,
									"bounded_task",
									[cur_pid]() {
									std::vector<driver_bridge::thread_info_t> fresh;
									try {
										fresh = driver_bridge::enumerate_threads();
									} catch (...) {
										fresh.clear();
									}
									{
										std::unique_lock<std::shared_mutex> lk(ds_threads_mu);
										ds_threads_cache = std::move(fresh);
										ds_threads_cache_pid = cur_pid;
										ds_threads_last_ms = static_cast<long long>(aida::shell_platform::tick_ms());
									}
									ds_threads_in_flight.store(false);
								});
								if (!submit_result.submitted)
									ds_threads_in_flight.store(false);
							}
						}
#endif
						std::vector<shell_thread_info_t> threads_view;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						threads_view = ds_threads_cache;
#else
						{
							std::shared_lock<std::shared_mutex> lk(ds_threads_mu);
							threads_view = ds_threads_cache;
						}
#endif
						ImGui::BeginChild("##thr_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(threads_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& t = threads_view[static_cast<std::size_t>(i)];
								ImGui::Text("TID %u  Priority %d", (unsigned)t.tid, t.priority);
							}
						}
						clipper.End();
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					ImGui::EndTabBar();
				}
			}

			ImGui::Spacing();
			float btn_w = 80.f;
			if (is_attached) {
				if (aida::ui::components::button("Detach",
					aida::ui::components::button_kind_t::destructive,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, 26.f))) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					ds_detach_review_pid = aida::preview::attached_pid();
					ds_detach_review_name = aida::preview::attached_process_name();
#else
					ds_detach_review_pid = driver_bridge::attached_pid();
					ds_detach_review_name = driver_bridge::attached_process_name();
#endif
					aida::ui::design::open_dialog("driver_detach_confirm", "Detach Process");
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.driver.status.detach", "driver-detach-review");
#endif
				ImGui::SameLine();
			}
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(btn_w, 26.f))) {
				ds_closing = true;
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.driver.status.close", "dialog-close");
#endif

			if (aida::ui::design::begin_dialog("driver_detach_confirm", "Detach Process",
					ImVec2(460.f, 250.f), ImVec2(340.f, 220.f))) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::uint32_t current_pid = aida::preview::attached_pid();
#else
				const std::uint32_t current_pid = driver_bridge::attached_pid();
#endif
				const bool target_current = ds_detach_review_pid != 0 && current_pid == ds_detach_review_pid;
				const std::string detach_target =
					(ds_detach_review_name.empty() ? "Process" : ds_detach_review_name) +
					" (PID " + std::to_string(ds_detach_review_pid) + ")";
				const std::string detach_prerequisite = target_current
					? "The reviewed PID is still the active target."
					: "The reviewed target is no longer active. Cancel and review the current target.";
				aida::ui::design::confirmation_t confirmation;
				confirmation.verb = "Detach the active driver-backed session";
				confirmation.target = detach_target.c_str();
				confirmation.scope = "Debugger, live-memory, and target-specific inspection state";
				confirmation.effect = "The target process remains running, but live target state becomes unavailable.";
				confirmation.reversibility = "Attach again to create a new live session.";
				confirmation.prerequisite = detach_prerequisite.c_str();
				confirmation.confirm_label = "Detach";
				confirmation.destructive = true;
				confirmation.confirm_enabled = target_current;
				const auto result = aida::ui::design::confirmation_dialog(
					"driver_detach_confirm", confirmation);
				if (result.confirmed && target_current) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::detach_process();
#else
					driver_bridge::detach();
#endif
					ds_detach_review_pid = 0;
					ds_detach_review_name.clear();
					ImGui::CloseCurrentPopup();
				} else if (result.cancelled) {
					ds_detach_review_pid = 0;
					ds_detach_review_name.clear();
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}
		ImGui::End();
	}


	static int kb_open_frame = -1;
	static float kb_anim = 0.f;
	static bool kb_closing = false;
	static char kb_filter_buf[128] = {0};
	static bool kb_was_open = false;
	static std::string kb_edit_binding;
	static std::string kb_edit_label;
	static std::vector<ImGuiKeyChord> kb_edit_strokes;
	static std::vector<std::string> kb_edit_conflicts;
	static std::string kb_edit_status;
	static bool kb_reset_all_armed = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_shortcuts_revision = 0;
	if (preview_shortcuts_revision != aida::preview::controls().revision) {
		preview_shortcuts_revision = aida::preview::controls().revision;
		kb_closing = false;
		kb_anim = aida::preview::controls().shortcuts_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_kb = ImGui::GetIO().DeltaTime;
		float kb_target = (globals::ui::shortcuts_dialog_open && !kb_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) kb_anim = kb_target;
		else
		#endif
		kb_anim += (kb_target - kb_anim) * (std::min)(dt_kb * 14.f, 1.f);
		if (std::abs(kb_anim - kb_target) < 0.003f) kb_anim = kb_target;

		bool now_open = globals::ui::shortcuts_dialog_open;
		if (now_open && !kb_was_open) {
			kb_filter_buf[0] = '\0';
			kb_edit_binding.clear();
			kb_edit_label.clear();
			kb_edit_strokes.clear();
			kb_edit_conflicts.clear();
			kb_edit_status.clear();
			kb_reset_all_armed = false;
			diag::log_tagged("chrome", "shortcuts_popup open=true");
		} else if (!now_open && kb_was_open) {
			diag::log_tagged("chrome", "shortcuts_popup open=false");
		}
		kb_was_open = now_open;

		if (kb_closing && kb_anim < 0.01f) {
			kb_closing = false;
			globals::ui::shortcuts_dialog_open = false;
			kb_open_frame = -1;
			kb_anim = 0.f;
		}
	}
	aida::ui::application_ui::set_shortcut_capture_active(
		(globals::ui::shortcuts_dialog_open && !kb_edit_binding.empty()) ||
		workspace_dialog_state().save_as_open || workspace_dialog_state().manager_open);

	g_render_section = "popups_shortcuts";
	if (globals::ui::shortcuts_dialog_open || kb_anim > 0.005f) {
		if (kb_open_frame < 0) kb_open_frame = ImGui::GetFrameCount();

		ImGuiViewport* kb_viewport = ImGui::GetMainViewport();
		const ImVec2 kb_work_pos = kb_viewport ? kb_viewport->WorkPos : ImVec2(0.f, 0.f);
		const ImVec2 kb_work_size = kb_viewport ? kb_viewport->WorkSize : ImGui::GetIO().DisplaySize;
		const float kb_dpi = kb_viewport && kb_viewport->DpiScale > 0.f ? kb_viewport->DpiScale : 1.f;
		float pw = (std::min)(760.f * kb_dpi, (std::max)(1.f, kb_work_size.x - 32.f * kb_dpi));
		float ph = (std::min)(620.f * kb_dpi, (std::max)(1.f, kb_work_size.y - 32.f * kb_dpi));
		float kb_scale = 0.96f + 0.04f * kb_anim;
		float sw = pw * kb_scale, sh = ph * kb_scale;
		float px = kb_work_pos.x + (kb_work_size.x - sw) * 0.5f;
		float py = kb_work_pos.y + (kb_work_size.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !kb_closing) {
			if (!kb_edit_binding.empty()) {
				kb_edit_binding.clear();
				kb_edit_label.clear();
				kb_edit_strokes.clear();
				kb_edit_conflicts.clear();
				kb_edit_status = "Edit cancelled";
			} else {
				kb_closing = true;
			}
		}

		if (ImGui::GetFrameCount() > kb_open_frame + 1 && !kb_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				kb_closing = true;
		}

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		const auto& th_kb = aida::ui::resolved();

		ImGui::Begin("Keyboard Shortcuts##kb_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
			ImVec2 wpos = ImGui::GetWindowPos();
			ImVec2 wsize = ImGui::GetWindowSize();
			ImDrawList* kb_dl = ImGui::GetWindowDrawList();

			ImU32 accent_top = aida::ui::with_alpha(th_kb.accent_grad_top, 0.85f * kb_anim);
			ImU32 accent_bot = aida::ui::with_alpha(th_kb.accent_grad_bot, 0.0f * kb_anim);
			kb_dl->AddRectFilledMultiColor(
				ImVec2(wpos.x, wpos.y),
				ImVec2(wpos.x + wsize.x, wpos.y + 3.f),
				accent_top, accent_top, accent_bot, accent_bot);

			float close_sz = 22.f;
			float close_x0 = wpos.x + wsize.x - close_sz - 14.f;
			float close_y0 = wpos.y + 12.f;
			float close_x1 = close_x0 + close_sz;
			float close_y1 = close_y0 + close_sz;
			bool close_hov = ImGui::IsMouseHoveringRect(
				ImVec2(close_x0, close_y0), ImVec2(close_x1, close_y1), false);
			if (close_hov) {
				kb_dl->AddRectFilled(
					ImVec2(close_x0, close_y0), ImVec2(close_x1, close_y1),
					aida::ui::with_alpha(th_kb.error, 0.32f * kb_anim), 4.f);
			}
			ImU32 close_col = aida::ui::with_alpha(
				close_hov ? th_kb.text_primary : th_kb.text_secondary, kb_anim);
			float ccx = (close_x0 + close_x1) * 0.5f;
			float ccy = (close_y0 + close_y1) * 0.5f;
			float crr = 5.f;
			kb_dl->AddLine(ImVec2(ccx - crr, ccy - crr), ImVec2(ccx + crr, ccy + crr), close_col, 1.6f);
			kb_dl->AddLine(ImVec2(ccx + crr, ccy - crr), ImVec2(ccx - crr, ccy + crr), close_col, 1.6f);
			if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				kb_closing = true;

			ImGui::PushFont(ImGui::GetFont());
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
				aida::ui::with_alpha(th_kb.text_primary, kb_anim)),
				"Keyboard Shortcuts");
			ImGui::PopFont();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
				aida::ui::with_alpha(th_kb.text_secondary, 0.8f * kb_anim)),
				"Press ESC to close. Type to filter.");
			ImGui::Spacing();

			float ax_f = globals::ui::accent.x;
			float ay_f = globals::ui::accent.y;
			float az_f = globals::ui::accent.z;
			ui_anim::render_filter_input_chip(
				"##kb_filter", kb_filter_buf, sizeof(kb_filter_buf),
				"Search shortcuts...", wsize.x - 56.f,
				ax_f, ay_f, az_f, kb_anim);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.shortcuts.search", "shortcut-search");
#endif

			if (kb_reset_all_armed) {
				if (ImGui::SmallButton("Confirm reset all")) {
					const auto result = aida::ui::application_ui::reset_all_shortcut_overrides();
					kb_edit_status = result.detail;
					kb_reset_all_armed = false;
					kb_edit_binding.clear();
					kb_edit_strokes.clear();
					kb_edit_conflicts.clear();
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.shortcuts.reset-all.confirm", "shortcut-reset-all-confirm");
#endif
				ImGui::SameLine();
				if (ImGui::SmallButton("Cancel reset")) {
					kb_reset_all_armed = false;
					kb_edit_status = "Reset cancelled";
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.shortcuts.reset-all.cancel", "shortcut-reset-all-cancel");
#endif
			} else {
				if (ImGui::SmallButton("Reset all shortcuts")) {
					kb_reset_all_armed = true;
					kb_edit_status = "Confirm to restore every canonical default binding";
				}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::semantics::register_last_item(
					"aida.shortcuts.reset-all", "shortcut-reset-all");
#endif
			}

			if (!kb_edit_binding.empty()) {
				if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false) && !kb_edit_strokes.empty()) {
					kb_edit_strokes.pop_back();
					kb_edit_conflicts.clear();
				}
				if (kb_edit_conflicts.empty()) {
					const ImGuiIO& capture_io = ImGui::GetIO();
					for (int value = ImGuiKey_Tab; value < ImGuiKey_GamepadStart; ++value) {
						const ImGuiKey key = static_cast<ImGuiKey>(value);
						if (key == ImGuiKey_Escape || key == ImGuiKey_Enter ||
							key == ImGuiKey_KeypadEnter || key == ImGuiKey_Backspace ||
							!ImGui::IsKeyPressed(key, false))
							continue;
						if (kb_edit_strokes.size() >= 4) {
							kb_edit_status = "A chord may contain at most four strokes";
							break;
						}
						ImGuiKeyChord stroke = key;
						if (capture_io.KeyCtrl) stroke |= ImGuiMod_Ctrl;
						if (capture_io.KeyShift) stroke |= ImGuiMod_Shift;
						if (capture_io.KeyAlt) stroke |= ImGuiMod_Alt;
						if (capture_io.KeySuper) stroke |= ImGuiMod_Super;
						kb_edit_strokes.push_back(stroke);
						kb_edit_status = "Stroke captured; add another or apply";
						break;
					}
				}
				ImGui::Separator();
				ImGui::Text("Editing %s", kb_edit_label.c_str());
				const std::string draft = kb_edit_strokes.empty()
					? "Press a key combination"
					: aida::ui::application_ui::format_shortcut_sequence(kb_edit_strokes);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_kb.accent_u32),
					"%s", draft.c_str());
				if (kb_edit_conflicts.empty()) {
					ImGui::BeginDisabled(kb_edit_strokes.empty());
					if (ImGui::SmallButton("Apply binding")) {
						const auto result = aida::ui::application_ui::update_shortcut_override(
							kb_edit_binding.c_str(), kb_edit_strokes, false);
						kb_edit_status = result.detail;
						kb_edit_conflicts = result.conflicts;
						if (result.completed()) {
							kb_edit_binding.clear();
							kb_edit_label.clear();
							kb_edit_strokes.clear();
						}
					}
					ImGui::EndDisabled();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						"aida.shortcuts.apply", "shortcut-apply", false,
						kb_edit_strokes.empty());
#endif
				} else {
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_kb.warning),
						"Conflict with %zu binding%s in this focus scope",
						kb_edit_conflicts.size(), kb_edit_conflicts.size() == 1 ? "" : "s");
					for (std::size_t index = 0;
						 index < (std::min)(kb_edit_conflicts.size(), static_cast<std::size_t>(4));
						 ++index)
						ImGui::TextDisabled("%s", kb_edit_conflicts[index].c_str());
					if (kb_edit_conflicts.size() > 4)
						ImGui::TextDisabled("+%zu more", kb_edit_conflicts.size() - 4);
					if (ImGui::SmallButton("Replace conflicting bindings")) {
						const auto result = aida::ui::application_ui::update_shortcut_override(
							kb_edit_binding.c_str(), kb_edit_strokes, true);
						kb_edit_status = result.detail;
						if (result.completed()) {
							kb_edit_binding.clear();
							kb_edit_label.clear();
							kb_edit_strokes.clear();
							kb_edit_conflicts.clear();
						}
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						"aida.shortcuts.replace-conflicts", "shortcut-conflict-resolution");
#endif
				}
				ImGui::SameLine();
				if (ImGui::SmallButton("Cancel edit")) {
					kb_edit_binding.clear();
					kb_edit_label.clear();
					kb_edit_strokes.clear();
					kb_edit_conflicts.clear();
					kb_edit_status = "Edit cancelled";
				}
				ImGui::Separator();
			}
			if (!kb_edit_status.empty())
				ImGui::TextDisabled("%s", kb_edit_status.c_str());

			ImGui::Spacing();

			auto str_lower = [](const char* s) -> std::string {
				std::string out;
				out.reserve(s ? std::strlen(s) : 0);
				if (s) {
					for (const char* p = s; *p; ++p) {
						char c = *p;
						if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
						out.push_back(c);
					}
				}
				return out;
			};
			std::string filter_lower = str_lower(kb_filter_buf);
			bool has_filter = !filter_lower.empty();
			const auto shortcuts = aida::ui::application_ui::list_shortcuts();

			ImGui::BeginChild("##kb_scroll",
				ImVec2(-1, (std::max)(120.f, ImGui::GetContentRegionAvail().y - 42.f)),
				false, ImGuiWindowFlags_HorizontalScrollbar);

			int total_visible = 0;
			std::string active_category;
			for (std::size_t index = 0; index < shortcuts.size(); ++index) {
				const auto& shortcut = shortcuts[index];
				bool visible = true;
				if (has_filter) {
					const std::string category_lower = str_lower(shortcut.category.c_str());
					const std::string keys_lower = str_lower(shortcut.shortcut.c_str());
					const std::string label_lower = str_lower(shortcut.label.c_str());
					const std::string scope_lower = str_lower(shortcut.scope.c_str());
					visible = category_lower.find(filter_lower) != std::string::npos ||
						keys_lower.find(filter_lower) != std::string::npos ||
						label_lower.find(filter_lower) != std::string::npos ||
						scope_lower.find(filter_lower) != std::string::npos;
				}
				if (!visible)
					continue;
				++total_visible;
				if (active_category != shortcut.category) {
					active_category = shortcut.category;
					ImGui::Spacing();
					ImVec2 hcp = ImGui::GetCursorScreenPos();
					ImDrawList* idl = ImGui::GetWindowDrawList();
					idl->AddRectFilled(ImVec2(hcp.x, hcp.y + 6.f), ImVec2(hcp.x + 3.f, hcp.y + 18.f),
						aida::ui::with_alpha(th_kb.accent_u32, kb_anim), 1.f);
					ImGui::Dummy(ImVec2(8.f, 0.f));
					ImGui::SameLine();
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
						aida::ui::with_alpha(th_kb.text_primary, 0.94f * kb_anim)), "%s", active_category.c_str());
					ImVec2 sep_pos = ImGui::GetCursorScreenPos();
					float row_inner_w = ImGui::GetContentRegionAvail().x;
					idl->AddLine(ImVec2(sep_pos.x, sep_pos.y + 2.f), ImVec2(sep_pos.x + row_inner_w, sep_pos.y + 2.f),
						aida::ui::with_alpha(th_kb.border_subtle, 0.6f * kb_anim), 1.f);
					ImGui::Dummy(ImVec2(0.f, 6.f));
				}

				ImDrawList* idl = ImGui::GetWindowDrawList();
				ImVec2 rcp = ImGui::GetCursorScreenPos();
				float row_h_k = 30.f;
				float row_w = ImGui::GetContentRegionAvail().x;
				bool row_hov = ImGui::IsMouseHoveringRect(rcp, ImVec2(rcp.x + row_w, rcp.y + row_h_k), false);
				if (row_hov)
					idl->AddRectFilled(ImVec2(rcp.x - 2.f, rcp.y), ImVec2(rcp.x + row_w, rcp.y + row_h_k),
						aida::ui::with_alpha(th_kb.hover_wash, 0.5f * kb_anim), 4.f);
				const ImU32 label_color = shortcut.enabled ? th_kb.text_primary : th_kb.text_dim;
				idl->AddText(ImVec2(rcp.x + 6.f, rcp.y + 3.f),
					aida::ui::with_alpha(label_color, 0.92f * kb_anim), shortcut.label.c_str());
				std::string metadata = shortcut.scope;
				if (!shortcut.binding_enabled)
					metadata += " / Disabled";
				if (shortcut.customized)
					metadata += " / Customized";
				if (shortcut.conflict)
					metadata += " / Conflict";
				idl->AddText(ImVec2(rcp.x + 6.f, rcp.y + 16.f),
					aida::ui::with_alpha(shortcut.conflict ? th_kb.warning : th_kb.text_dim, 0.82f * kb_anim),
					metadata.c_str());
				ImVec2 chip_ts = ImGui::CalcTextSize(shortcut.shortcut.c_str());
				float chip_w_est = chip_ts.x + 12.f;
				float chip_x = rcp.x + row_w - chip_w_est - (shortcut.editable ? 202.f : 6.f);
				float chip_y = rcp.y + (row_h_k - (chip_ts.y + 4.f)) * 0.5f;
				ui_anim::render_kbd_chip(idl, chip_x, chip_y, shortcut.shortcut.c_str(), kb_anim);
				ImGui::Dummy(ImVec2(row_w, row_h_k));
				const ImVec2 next_row = ImGui::GetCursorScreenPos();
				if (shortcut.editable) {
					ImGui::PushID(shortcut.binding_id.c_str());
					ImGui::SetCursorScreenPos(ImVec2(rcp.x + row_w - 192.f, rcp.y + 5.f));
					if (ImGui::SmallButton("Edit")) {
						kb_edit_binding = shortcut.binding_id;
						kb_edit_label = shortcut.label;
						kb_edit_strokes.clear();
						kb_edit_conflicts.clear();
						kb_edit_status = "Press one or more key combinations";
						kb_reset_all_armed = false;
					}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::semantics::register_last_item(
						aida::preview::semantics::stable_id(
							"aida.shortcuts.edit", shortcut.binding_id),
						"shortcut-edit");
#endif
					if (shortcut.binding_enabled) {
						ImGui::SameLine();
						if (ImGui::SmallButton("Disable")) {
							const auto result = aida::ui::application_ui::disable_shortcut_override(
								shortcut.binding_id.c_str());
							kb_edit_status = result.detail;
							kb_edit_binding.clear();
							kb_edit_strokes.clear();
							kb_edit_conflicts.clear();
						}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						aida::preview::semantics::register_last_item(
							aida::preview::semantics::stable_id(
								"aida.shortcuts.disable", shortcut.binding_id),
							"shortcut-disable");
#endif
					}
					if (shortcut.customized) {
						ImGui::SameLine();
						if (ImGui::SmallButton("Reset")) {
							const auto result = aida::ui::application_ui::reset_shortcut_override(
								shortcut.binding_id.c_str());
							kb_edit_status = result.detail;
							kb_edit_binding.clear();
							kb_edit_strokes.clear();
							kb_edit_conflicts.clear();
						}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						aida::preview::semantics::register_last_item(
							aida::preview::semantics::stable_id(
								"aida.shortcuts.reset", shortcut.binding_id),
							"shortcut-reset");
#endif
					}
					ImGui::PopID();
					ImGui::SetCursorScreenPos(next_row);
				}
				if (row_hov) {
					if (shortcut.customized)
						ImGui::SetTooltip("Default: %s", shortcut.default_shortcut.c_str());
					else if (!shortcut.enabled && !shortcut.disabled_reason.empty())
						ImGui::SetTooltip("%s", shortcut.disabled_reason.c_str());
				}
			}

			if (has_filter && total_visible == 0) {
				ImGui::Spacing();
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
					aida::ui::with_alpha(th_kb.text_dim, 0.85f * kb_anim)),
					"No shortcuts match \"%s\".", kb_filter_buf);
			}

			ImGui::EndChild();

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(96.f, 26.f))) {
				kb_closing = true;
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				"aida.shortcuts.close", "dialog-close");
#endif
		}
		ImGui::End();
	}

	g_render_section = "popups_initial_analysis";
	initial_analysis_view::render_frame(active_workspace_context);

	g_render_section = "popups_loading_binary";
	loading_binary_overlay::render();

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_render_section = "popups_test_all_features";
	{
		ImGuiIO& io_ta = ImGui::GetIO();
		test_all_features::render_overlay(io_ta.DisplaySize.x, io_ta.DisplaySize.y);
	}
#endif

	g_render_section = "popups_open_binary_confirm";
	file_browser::render_pending_confirm_modal();

	g_render_section = "popups_tool_approval";
	render_tool_approval_dialog();

	g_render_section = "popups_chat_select_text";
	static bool chat_select_dialog_requested = false;
	static std::string chat_select_buffer_source;
	static std::vector<char> chat_select_buffer;
	if (chat_select_popup::open && !chat_select_dialog_requested) {
		aida::ui::design::open_dialog("chat_select_text", "Select & Copy Text");
		chat_select_dialog_requested = true;
	}
	if (chat_select_popup::open && aida::ui::design::begin_dialog(
			"chat_select_text", "Select & Copy Text", ImVec2(820.f, 640.f), ImVec2(420.f, 300.f))) {
		const float footer_height = aida::ui::design::dialog_footer_reserve_height("Copy All", "Close");
		aida::ui::design::begin_dialog_body("chat_select_text_body", footer_height);
		{
			ImGui::TextWrapped("Drag to select. Ctrl+C to copy. Ctrl+A selects all.");
			ImGui::Separator();
			if (chat_select_buffer_source != chat_select_popup::text) {
				chat_select_buffer_source = chat_select_popup::text;
				chat_select_buffer.assign(chat_select_buffer_source.size() + 1, 0);
				std::memcpy(chat_select_buffer.data(), chat_select_buffer_source.data(),
					chat_select_buffer_source.size());
			}
			const float avail_y = (std::max)(80.f, ImGui::GetContentRegionAvail().y);
			ImGui::InputTextMultiline("##chat_select_buf",
				chat_select_buffer.data(), chat_select_buffer.size(),
				ImVec2(-1.f, avail_y),
				ImGuiInputTextFlags_ReadOnly);
		}
		aida::ui::design::end_dialog_body();
		const auto result = aida::ui::design::dialog_footer(
			"chat_select_text_footer", "Copy All", !chat_select_popup::text.empty(), false,
			"Close", true, true);
		if (result.confirmed) {
			ImGui::SetClipboardText(chat_select_popup::text.c_str());
			toast_notification::push("Message copied to clipboard",
				toast_notification::toast_type_t::info, 2.5f);
		} else if (result.cancelled) {
			chat_select_popup::open = false;
			chat_select_popup::text.clear();
			chat_select_dialog_requested = false;
			chat_select_buffer_source.clear();
			chat_select_buffer.clear();
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	} else if (!chat_select_popup::open) {
		chat_select_dialog_requested = false;
	}

	aida::ui::application_ui::process_global_shortcuts();
	g_render_section = "done";
}
