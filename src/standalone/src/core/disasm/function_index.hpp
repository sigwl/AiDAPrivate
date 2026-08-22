#pragma once

#include <Zydis/Zydis.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "pe_parser.hpp"
#include "standalone_driver.hpp"
#include "symbol_classifier.hpp"
#include "symbol_store.hpp"
#include "zydis_disasm.hpp"
#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/publication_indexes.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../session/analysis_session.hpp"

#include "../../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../infra/fast_containers.hpp"

namespace function_index {

	enum class injection_t {
		function_banner,
		attributes_line,
		prototype_line,
		proc_header,
		var_decl,
		proc_endp,
		endp_separator,
		label_line,
		spacer_line,
		noreturn_separator
	};

	struct injection_row_t {
		injection_t kind;
		std::string text;
		uint64_t    addr = 0;
	};

	enum class directive_kind_t : uint8_t {
		none = 0,
		align = 1,
		db = 2
	};

	struct directive_override_t {
		directive_kind_t kind = directive_kind_t::none;
		uint8_t          value = 0;
	};

	inline aida::analysis::workspace_result_t<aida::analysis::address_t>
	normalize_workspace_address(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		if (!workspace) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::target_not_found,
				"Function query requires an explicit workspace",
				"function_index.address"));
		}
		if (address.architecture != architecture_id_t::unknown &&
			address.architecture != workspace->identity().architecture()) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::unsupported_address_space,
				"Function query architecture does not match the workspace",
				"function_index.address"));
		}
		auto image = workspace->image();
		address_t normalized = address;
		normalized.architecture = workspace->identity().architecture();
		normalized.mode = image ? image->architecture_mode() : address.mode;
		if (workspace->target_kind() == target_kind_t::live_snapshot) {
			const auto& module = workspace->identity().module();
			if (!module || module->size == 0 ||
				module->base > UINT64_MAX - module->size) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::target_stale,
					"Live function workspace has no valid module range",
					"function_index.address"));
			}
			if (address.space == address_space_id_t::relative_virtual) {
				if (module->base > UINT64_MAX - address.value ||
					address.value >= module->size) {
					return workspace_result_t<address_t>::failure(make_workspace_error(
						workspace_error_code_t::out_of_range,
						"Live function RVA is outside the captured module",
						"function_index.address"));
				}
				normalized.value = module->base + address.value;
			} else if (address.space == address_space_id_t::virtual_address ||
				address.space == address_space_id_t::live_virtual) {
				if (address.value < module->base ||
					address.value - module->base >= module->size) {
					return workspace_result_t<address_t>::failure(make_workspace_error(
						workspace_error_code_t::out_of_range,
						"Live function address is outside the captured module",
						"function_index.address"));
				}
			} else {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::unsupported_address_space,
					"Live function query requires a virtual address",
					"function_index.address"));
			}
			normalized.space = address_space_id_t::live_virtual;
			return workspace_result_t<address_t>::success(normalized);
		}
		if (!image) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::malformed_pe,
				"Static function query requires a normalized image",
				"function_index.address"));
		}
		if (address.space == address_space_id_t::relative_virtual) {
			if (address.value >= image->image_size()) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::out_of_range,
					"Function RVA is outside the normalized image",
					"function_index.address"));
			}
			normalized.space = address_space_id_t::relative_virtual;
		} else if (address.space == address_space_id_t::file_offset) {
			auto rva = image->file_offset_to_rva(address.value);
			if (!rva) return workspace_result_t<address_t>::failure(rva.error());
			normalized.space = address_space_id_t::relative_virtual;
			normalized.value = rva.value();
		} else if (address.space == address_space_id_t::virtual_address) {
			if (address.value < image->image_base() ||
				address.value - image->image_base() >= image->image_size()) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::out_of_range,
					"Function address is outside the normalized image",
					"function_index.address"));
			}
			normalized.space = address_space_id_t::relative_virtual;
			normalized.value = address.value - image->image_base();
		}
		else {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::unsupported_address_space,
				"Function query address space is unsupported",
				"function_index.address"));
		}
		return workspace_result_t<address_t>::success(normalized);
	}

	inline uint64_t workspace_display_address(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		if (!workspace) return 0;
		if (address.space == address_space_id_t::virtual_address ||
			address.space == address_space_id_t::live_virtual)
			return address.value;
		const auto image = workspace->image();
		if (!image) return 0;
		uint64_t rva = 0;
		if (address.space == address_space_id_t::relative_virtual) {
			rva = address.value;
		} else if (address.space == address_space_id_t::file_offset) {
			auto translated = image->file_offset_to_rva(address.value);
			if (!translated) return 0;
			rva = translated.value();
		} else {
			return 0;
		}
		if (rva >= image->image_size() || image->image_base() > UINT64_MAX - rva)
			return 0;
		return image->image_base() + rva;
	}

	inline aida::analysis::architecture_mode_t workspace_architecture_mode(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		if (!workspace) return aida::analysis::architecture_mode_t::unknown;
		if (const auto image = workspace->image()) return image->architecture_mode();
		switch (workspace->identity().architecture()) {
		case aida::analysis::architecture_id_t::x86:
			return aida::analysis::architecture_mode_t::x86_32;
		case aida::analysis::architecture_id_t::x86_64:
			return aida::analysis::architecture_mode_t::x86_64;
		default:
			return aida::analysis::architecture_mode_t::unknown;
		}
	}

	struct workspace_name_snapshot_t {
		std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
		std::shared_ptr<const aida::analysis::analysis_publication_t> publication;
		std::shared_ptr<symbol_store::workspace_state_t> debug_symbols;
		std::vector<std::pair<aida::analysis::address_t, std::string>> overlay_names;
	};

	inline workspace_name_snapshot_t workspace_name_snapshot(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		using namespace aida::analysis;
		workspace_name_snapshot_t output;
		output.workspace = workspace;
		if (!workspace) return output;
		output.publication = workspace->analysis_publication();
		if (output.publication &&
			(output.publication->binary_id != workspace->identity().binary_id() ||
			 output.publication->generation != workspace->generation()))
			output.publication.reset();
		output.debug_symbols = analysis_session::symbols_for_workspace(workspace);
		if (auto overlay = workspace->overlay()) {
			const auto snapshot = overlay->snapshot();
			if (snapshot.revision == workspace->overlay_revision()) {
				output.overlay_names.reserve(snapshot.items.size());
				for (const auto& item : snapshot.items) {
					const auto& operation = item.second;
					if (operation.kind != overlay_operation_kind_t::name ||
						operation.name.empty())
						continue;
					auto normalized = normalize_workspace_address(workspace,
						operation.address);
					if (!normalized) continue;
					output.overlay_names.emplace_back(normalized.take_value(),
						operation.name);
				}
				std::sort(output.overlay_names.begin(), output.overlay_names.end(),
					[](const auto& left, const auto& right) {
						if (left.first != right.first) return left.first < right.first;
						return left.second < right.second;
					});
				output.overlay_names.erase(std::unique(output.overlay_names.begin(),
					output.overlay_names.end(), [](const auto& left, const auto& right) {
						return left.first == right.first;
					}), output.overlay_names.end());
			}
		}
		return output;
	}

	inline std::string resolve_workspace_name_exact(
		const workspace_name_snapshot_t& names,
		const aida::analysis::address_t& address)
	{
		auto normalized = normalize_workspace_address(names.workspace, address);
		if (!normalized) return {};
		auto overlay = std::lower_bound(names.overlay_names.begin(),
			names.overlay_names.end(), normalized.value(),
			[](const auto& item, const auto& value) { return item.first < value; });
		if (overlay != names.overlay_names.end() &&
			overlay->first == normalized.value())
			return overlay->second;
		if (names.debug_symbols) {
			const uint64_t display = workspace_display_address(names.workspace,
				normalized.value());
			if (display != 0) {
				auto query = normalized.value();
				query.space = names.workspace->target_kind() ==
					aida::analysis::target_kind_t::live_snapshot
					? aida::analysis::address_space_id_t::live_virtual
					: aida::analysis::address_space_id_t::virtual_address;
				query.value = display;
				auto resolved = names.debug_symbols->resolve_exact(query);
				if (!resolved.empty()) return resolved;
			}
		}
		if (names.publication && names.publication->snapshot &&
			names.publication->generation == names.workspace->generation()) {
			const auto indexes = aida::analysis::publication_indexes::for_publication(
				names.publication, {});
			if (indexes) {
				const auto* symbol = indexes->symbol_exact_named(normalized.value());
				if (symbol)
					return symbol->name;
			}
		}
		return {};
	}

	inline std::string resolve_workspace_name_nearest(
		const workspace_name_snapshot_t& names,
		const aida::analysis::address_t& address,
		uint64_t maximum_distance = 0x10000)
	{
		auto exact = resolve_workspace_name_exact(names, address);
		if (!exact.empty()) return exact;
		auto normalized = normalize_workspace_address(names.workspace, address);
		if (!normalized) return {};
		auto overlay = std::upper_bound(names.overlay_names.begin(),
			names.overlay_names.end(), normalized.value(),
			[](const auto& value, const auto& item) { return value < item.first; });
		if (overlay != names.overlay_names.begin()) {
			--overlay;
			if (overlay->first.space == normalized.value().space &&
				overlay->first.value <= normalized.value().value) {
				const uint64_t distance = normalized.value().value - overlay->first.value;
				if (distance < maximum_distance) {
					if (distance == 0) return overlay->second;
					char suffix[32]{};
					std::snprintf(suffix, sizeof(suffix), "+0x%llX",
						static_cast<unsigned long long>(distance));
					if (overlay->second.size() <= (1u << 20) - std::strlen(suffix))
						return overlay->second + suffix;
				}
			}
		}
		if (!names.debug_symbols) return {};
		const uint64_t display = workspace_display_address(names.workspace,
			normalized.value());
		if (display == 0) return {};
		auto query = normalized.value();
		query.space = names.workspace->target_kind() ==
			aida::analysis::target_kind_t::live_snapshot
			? aida::analysis::address_space_id_t::live_virtual
			: aida::analysis::address_space_id_t::virtual_address;
		query.value = display;
		return names.debug_symbols->resolve_nearest(query, maximum_distance);
	}

	inline std::string synthetic_name(
		const workspace_name_snapshot_t& names,
		const aida::analysis::address_t& address)
	{
		auto normalized = normalize_workspace_address(names.workspace, address);
		if (!normalized) return {};
		auto resolved = resolve_workspace_name_exact(names, normalized.value());
		if (!resolved.empty()) return resolved;
		char text[32]{};
		const uint64_t display = workspace_display_address(names.workspace,
			normalized.value());
		std::snprintf(text, sizeof(text), "sub_%llX",
			static_cast<unsigned long long>(display != 0
				? display : normalized.value().value));
		return text;
	}

	inline std::shared_ptr<aida::analysis::analysis_workspace_t>
	legacy_live_workspace()
	{
		const uint32_t pid = driver_bridge::attached_pid();
		return pid == 0 ? nullptr : aida::analysis::workspace_registry().find_by_pid(pid);
	}

	inline std::string resolve_live_debugger_name_exact(uint64_t address)
	{
		auto workspace = legacy_live_workspace();
		if (workspace) {
			aida::analysis::address_t query;
			query.space = aida::analysis::address_space_id_t::live_virtual;
			query.value = address;
			query.architecture = workspace->identity().architecture();
			query.mode = workspace_architecture_mode(workspace);
			auto names = workspace_name_snapshot(workspace);
			auto resolved = resolve_workspace_name_exact(names, query);
			if (!resolved.empty()) return resolved;
		}
		return driver_bridge::attached_pid() == 0
			? std::string() : symbol_store::resolve_symbol_exact(address);
	}

	inline std::string resolve_live_debugger_name_nearest(uint64_t address)
	{
		auto workspace = legacy_live_workspace();
		if (workspace) {
			aida::analysis::address_t query;
			query.space = aida::analysis::address_space_id_t::live_virtual;
			query.value = address;
			query.architecture = workspace->identity().architecture();
			query.mode = workspace_architecture_mode(workspace);
			auto names = workspace_name_snapshot(workspace);
			auto resolved = resolve_workspace_name_nearest(names, query);
			if (!resolved.empty()) return resolved;
		}
		return driver_bridge::attached_pid() == 0
			? std::string() : symbol_store::resolve_symbol(address);
	}

	inline std::optional<symbol_store::module_symbols_t>
	legacy_live_module_symbols(const std::string& module_name)
	{
		auto workspace = legacy_live_workspace();
		if (workspace) {
			auto symbols = analysis_session::symbols_for_workspace(workspace);
			if (symbols) return symbols->module_snapshot(module_name);
		}
		if (driver_bridge::attached_pid() == 0) return std::nullopt;
		std::lock_guard<std::mutex> lock(symbol_store::g_state.mutex);
		auto found = symbol_store::g_state.modules.find(module_name);
		if (found == symbol_store::g_state.modules.end() ||
			found->second.pdb.symbols.size() > 4 * 1024 * 1024)
			return std::nullopt;
		return found->second;
	}

	inline aida::analysis::workspace_result_t<
		std::vector<aida::analysis::function_record_t>>
	workspace_functions(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		size_t offset = 0, size_t count = 1000)
	{
		using namespace aida::analysis;
		if (!workspace) {
			return workspace_result_t<std::vector<function_record_t>>::failure(
				make_workspace_error(workspace_error_code_t::target_not_found,
					"Function query requires an explicit workspace",
					"function_index.snapshot"));
		}
		if (workspace->target_kind() == target_kind_t::live_snapshot) {
			return workspace_result_t<std::vector<function_record_t>>::failure(
				make_workspace_error(
					workspace_error_code_t::live_target_bulk_analysis_unsupported,
					"A live target has no whole-module function index",
					"function_index.snapshot"));
		}
		if (count > 100000) {
			return workspace_result_t<std::vector<function_record_t>>::failure(
				make_workspace_error(workspace_error_code_t::limit_exceeded,
					"Function page exceeds 100000 records",
					"function_index.snapshot"));
		}
		auto publication = workspace->analysis_publication();
		if (!publication || !publication->snapshot) {
			return workspace_result_t<std::vector<function_record_t>>::failure(
				make_workspace_error(workspace_error_code_t::analysis_in_progress,
					"Function index is not published yet",
					"function_index.snapshot"));
		}
		const auto& source = publication->snapshot->functions;
		if (offset > source.size()) offset = source.size();
		const size_t available = source.size() - offset;
		const size_t take = (std::min)(available, count);
		std::vector<function_record_t> result;
		result.reserve(take);
		result.insert(result.end(), source.begin() + static_cast<std::ptrdiff_t>(offset),
			source.begin() + static_cast<std::ptrdiff_t>(offset + take));
		return workspace_result_t<std::vector<function_record_t>>::success(
			std::move(result));
	}

	inline aida::analysis::workspace_result_t<aida::analysis::function_record_t>
	workspace_function_for(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		auto normalized = normalize_workspace_address(workspace, address);
		if (!normalized)
			return workspace_result_t<function_record_t>::failure(normalized.error());
		auto publication = workspace->analysis_publication();
		auto snapshot = publication ? publication->snapshot : nullptr;
		if (!snapshot) {
			return workspace_result_t<function_record_t>::failure(make_workspace_error(
				workspace_error_code_t::analysis_in_progress,
				"Function index is not published yet", "function_index.lookup"));
		}
		auto indexes = aida::analysis::publication_indexes::for_publication_result(
			publication, {});
		if (!indexes)
			return workspace_result_t<function_record_t>::failure(indexes.error());
		if (const auto* function = indexes.value()->function_containing(normalized.value()))
			return workspace_result_t<function_record_t>::success(*function);
		auto error = make_workspace_error(workspace_error_code_t::target_not_found,
			"Address is not inside a published function", "function_index.lookup");
		error.address = normalized.value();
		return workspace_result_t<function_record_t>::failure(std::move(error));
	}

	inline std::string synthetic_name(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		auto normalized = normalize_workspace_address(workspace, address);
		if (!normalized) return {};
		auto names = workspace_name_snapshot(workspace);
		return synthetic_name(names, normalized.value());
	}

	inline bool func_extent(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address,
		aida::analysis::address_t* out_start,
		aida::analysis::address_t* out_end)
	{
		auto function = workspace_function_for(workspace, address);
		if (!function) return false;
		if (out_start) *out_start = function.value().start;
		if (out_end) *out_end = function.value().end;
		return true;
	}

	struct live_function_capture_t {
		std::shared_ptr<const aida::analysis::live_snapshot_provider_t> provider;
		std::shared_ptr<const aida::analysis::analysis_snapshot_t> snapshot;
		aida::analysis::address_t requested;
		aida::analysis::address_t function_start;
		aida::analysis::address_t function_end;
		aida::analysis::live_snapshot_metadata_t metadata;
		aida::analysis::fact_provenance_t provenance =
			aida::analysis::fact_provenance_t::unknown;
		uint64_t provider_origin_va = 0;
		uint8_t confidence = 0;
	};

	inline aida::analysis::workspace_result_t<live_function_capture_t>
	capture_live_function_range(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& requested,
		const aida::analysis::address_t& function_start,
		const aida::analysis::address_t& function_end,
		aida::analysis::fact_provenance_t provenance,
		uint8_t confidence,
		uint64_t maximum_capture_size = 64ULL * 1024ULL * 1024ULL,
		const aida::analysis::cancellation_token_t& cancel = {})
	{
		using namespace aida::analysis;
		auto fail = [](workspace_error_code_t code, std::string message) {
			auto error = make_workspace_error(code, std::move(message),
				"function_index.live_capture");
			error.cancellation = code == workspace_error_code_t::cancelled;
			error.deadline = code == workspace_error_code_t::deadline_exceeded;
			return workspace_result_t<live_function_capture_t>::failure(
				std::move(error));
		};
		if (!workspace || workspace->target_kind() != target_kind_t::live_snapshot)
			return fail(workspace_error_code_t::invalid_argument,
				"Live function capture requires an explicit live workspace");
		if (workspace->closing() || workspace->closed())
			return fail(workspace_error_code_t::workspace_closing,
				"Live function workspace is closing");
		if (workspace->cancellation_token().stop_requested())
			return fail(workspace_error_code_t::cancelled,
				"Live function workspace cancellation was requested");
		const auto captured_binary_id = workspace->identity().binary_id();
		const uint64_t captured_generation = workspace->generation();
		const uint64_t captured_analysis_revision = workspace->analysis_revision();
		const uint64_t captured_overlay_revision = workspace->overlay_revision();
		if (cancel.stop_requested()) {
			auto error = make_workspace_error(
				cancel.deadline_exceeded()
					? workspace_error_code_t::deadline_exceeded
					: workspace_error_code_t::cancelled,
				cancel.deadline_exceeded()
					? "Live function capture deadline expired"
					: "Live function capture was cancelled",
				"function_index.live_capture");
			error.deadline = cancel.deadline_exceeded();
			error.cancellation = !error.deadline;
			return workspace_result_t<live_function_capture_t>::failure(
				std::move(error));
		}
		auto normalized_requested = normalize_workspace_address(workspace, requested);
		auto normalized_start = normalize_workspace_address(workspace, function_start);
		auto normalized_end = normalize_workspace_address(workspace, function_end);
		if (!normalized_requested)
			return workspace_result_t<live_function_capture_t>::failure(
				normalized_requested.error());
		if (!normalized_start)
			return workspace_result_t<live_function_capture_t>::failure(
				normalized_start.error());
		if (!normalized_end)
			return workspace_result_t<live_function_capture_t>::failure(
				normalized_end.error());
		if (normalized_end.value().value <= normalized_start.value().value ||
			normalized_requested.value().value < normalized_start.value().value ||
			normalized_requested.value().value >= normalized_end.value().value) {
			return fail(workspace_error_code_t::out_of_range,
				"Requested address is outside the proven live function range");
		}
		constexpr uint64_t kHardMaximumCapture = 64ULL * 1024ULL * 1024ULL;
		if (maximum_capture_size == 0 || maximum_capture_size > kHardMaximumCapture)
			return fail(workspace_error_code_t::limit_exceeded,
				"Live function capture budget is invalid");
		const uint64_t capture_size = normalized_end.value().value -
			normalized_start.value().value;
		if (capture_size == 0 || capture_size > maximum_capture_size)
			return fail(workspace_error_code_t::limit_exceeded,
				"Live function range exceeds the capture budget");
		auto original = std::dynamic_pointer_cast<const live_snapshot_provider_t>(
			workspace->provider_handle());
		if (!original)
			return fail(workspace_error_code_t::provider_unavailable,
				"Live workspace has no immutable driver snapshot provider");
		auto current_identity = original->validate_current_identity();
		if (!current_identity)
			return workspace_result_t<live_function_capture_t>::failure(
				current_identity.error());
		const auto original_metadata = original->metadata();
		if (original_metadata.process.pid == GetCurrentProcessId())
			return fail(workspace_error_code_t::self_target_refused,
				"AiDA cannot capture its own process");
		if (!workspace->identity().process() || !workspace->identity().module() ||
			!(original_metadata.process == *workspace->identity().process()) ||
			!(original_metadata.module == *workspace->identity().module()))
			return fail(workspace_error_code_t::integrity_failure,
				"Live snapshot identity does not match its workspace");
		live_snapshot_request_t request;
		request.pid = original_metadata.process.pid;
		request.module_base = original_metadata.module.base;
		request.module_size = original_metadata.module.size;
		request.module_name = original_metadata.module.normalized_name;
		request.module_path = original_metadata.module.normalized_path;
		request.capture_address = normalized_start.value();
		request.capture_size = capture_size;
		request.maximum_capture_size = maximum_capture_size;
		auto captured = live_snapshot_provider_t::capture(request, cancel);
		if (!captured)
			return workspace_result_t<live_function_capture_t>::failure(
				captured.error());
		auto original_still_current = original->validate_current_identity();
		if (!original_still_current)
			return workspace_result_t<live_function_capture_t>::failure(
				original_still_current.error());
		const auto captured_metadata = captured.value()->metadata();
		if (!(captured_metadata.process == original_metadata.process) ||
			!(captured_metadata.module == original_metadata.module)) {
			return fail(workspace_error_code_t::target_stale,
				"Live process or module identity changed during function capture");
		}
		if (workspace->closing() || workspace->closed() ||
			workspace->cancellation_token().stop_requested())
			return fail(workspace_error_code_t::cancelled,
				"Live function workspace was cancelled during capture");
		if (workspace->identity().binary_id() != captured_binary_id ||
			workspace->generation() != captured_generation)
			return fail(workspace_error_code_t::stale_generation,
				"Live function workspace generation changed during capture");
		if (workspace->analysis_revision() != captured_analysis_revision ||
			workspace->overlay_revision() != captured_overlay_revision)
			return fail(workspace_error_code_t::revision_conflict,
				"Live function workspace revision changed during capture");
		auto ephemeral = std::make_shared<analysis_snapshot_t>();
		ephemeral->generation = captured_generation;
		ephemeral->analysis_revision = captured_analysis_revision;
		ephemeral->overlay_revision = captured_overlay_revision;
		ephemeral->baseline_complete = false;
		function_record_t function;
		function.id = normalized_start.value().value == 0
			? 1 : normalized_start.value().value;
		function.start = normalized_start.value();
		function.end = normalized_end.value();
		function.provenance = provenance;
		function.confidence = confidence;
		ephemeral->functions.push_back(function);
		live_function_capture_t result;
		result.provider = captured.take_value();
		result.snapshot = std::move(ephemeral);
		result.requested = normalized_requested.take_value();
		result.function_start = normalized_start.take_value();
		result.function_end = normalized_end.take_value();
		result.metadata = result.provider->metadata();
		result.provenance = provenance;
		result.provider_origin_va = result.function_start.value;
		result.confidence = confidence;
		return workspace_result_t<live_function_capture_t>::success(
			std::move(result));
	}

	inline aida::analysis::workspace_result_t<live_function_capture_t>
	capture_live_function_from_unwind(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& requested,
		uint64_t maximum_capture_size = 64ULL * 1024ULL * 1024ULL,
		const aida::analysis::cancellation_token_t& cancel = {})
	{
		using namespace aida::analysis;
		if (!workspace || workspace->target_kind() != target_kind_t::live_snapshot) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(workspace_error_code_t::invalid_argument,
					"Unwind-backed capture requires an explicit live workspace",
					"function_index.live_unwind"));
		}
		if (workspace->identity().architecture() != architecture_id_t::x86_64) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
					"Unwind-backed live capture currently requires x86-64 PE metadata",
					"function_index.live_unwind"));
		}
		auto normalized = normalize_workspace_address(workspace, requested);
		if (!normalized)
			return workspace_result_t<live_function_capture_t>::failure(
				normalized.error());
		auto original = std::dynamic_pointer_cast<const live_snapshot_provider_t>(
			workspace->provider_handle());
		if (!original) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(workspace_error_code_t::provider_unavailable,
					"Live workspace has no immutable header snapshot",
					"function_index.live_unwind"));
		}
		auto identity = original->validate_current_identity();
		if (!identity)
			return workspace_result_t<live_function_capture_t>::failure(
				identity.error());
		const auto metadata = original->metadata();
		pe_parser::parse_options_t options;
		options.include_imports_exports = false;
		auto deadline = cancel.deadline();
		if (deadline) options.deadline = &*deadline;
		pe_parser::pe_info_t pe;
		if (!pe_parser::parse_live(metadata.process.pid, metadata.module.base,
			pe, options)) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(cancel.stop_requested()
						? (cancel.deadline_exceeded()
							? workspace_error_code_t::deadline_exceeded
							: workspace_error_code_t::cancelled)
						: workspace_error_code_t::malformed_pe,
					cancel.stop_requested()
						? "Live unwind lookup was cancelled"
						: "Live PE metadata could not be parsed",
					"function_index.live_unwind"));
		}
		auto runtime = pe_parser::find_live_runtime_function(
			metadata.process.pid, metadata.module.base, pe,
			normalized.value().value, cancel);
		if (!runtime)
			return workspace_result_t<live_function_capture_t>::failure(
				runtime.error());
		if (!runtime.value()) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(workspace_error_code_t::decode_failure,
					"FUNCTION_BOUNDS_UNCERTAIN: no unwind function contains the requested address",
					"function_index.live_unwind"));
		}
		uint64_t start_va = 0;
		uint64_t end_va = 0;
		if (metadata.module.base > UINT64_MAX - runtime.value()->begin_rva ||
			metadata.module.base > UINT64_MAX - runtime.value()->end_rva) {
			return workspace_result_t<live_function_capture_t>::failure(
				make_workspace_error(workspace_error_code_t::range_overflow,
					"Unwind function virtual range overflowed",
					"function_index.live_unwind"));
		}
		start_va = metadata.module.base + runtime.value()->begin_rva;
		end_va = metadata.module.base + runtime.value()->end_rva;
		address_t start{address_space_id_t::live_virtual, start_va,
			architecture_id_t::x86_64, architecture_mode_t::x86_64};
		address_t end{address_space_id_t::live_virtual, end_va,
			architecture_id_t::x86_64, architecture_mode_t::x86_64};
		return capture_live_function_range(workspace, normalized.value(), start,
			end, fact_provenance_t::unwind_metadata, 255,
			maximum_capture_size, cancel);
	}

	inline std::vector<aida::analysis::address_t> call_targets_for(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		std::vector<aida::analysis::address_t> targets;
		auto function = workspace_function_for(workspace, address);
		auto publication = workspace ? workspace->analysis_publication() : nullptr;
		auto snapshot = publication ? publication->snapshot : nullptr;
		if (!function || !snapshot) return targets;
		auto indexes = aida::analysis::publication_indexes::for_publication(
			publication, {});
		if (!indexes) return targets;
		const auto range = indexes->call_edges_from(function.value());
		for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal) {
			const auto& edge = snapshot->edges[indexes->call_edge_entry(ordinal)];
			if (edge.kind != aida::analysis::edge_kind_t::call &&
				edge.kind != aida::analysis::edge_kind_t::tail_call)
				continue;
			targets.push_back(edge.target);
		}
		std::sort(targets.begin(), targets.end());
		targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
		return targets;
	}

	inline std::string iat_symbol_at(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		auto normalized = normalize_workspace_address(workspace, address);
		auto image = workspace ? workspace->image() : nullptr;
		if (!normalized || !image) return {};
		for (const auto& entry : image->imports()) {
			if (normalized.value().space != aida::analysis::address_space_id_t::relative_virtual ||
				entry.iat_rva != normalized.value().value) continue;
			if (entry.name) return *entry.name;
			if (entry.ordinal) return "Ordinal#" + std::to_string(*entry.ordinal);
		}
		return {};
	}

	inline std::string data_symbol_at(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		auto normalized = normalize_workspace_address(workspace, address);
		auto publication = workspace ? workspace->analysis_publication() : nullptr;
		auto snapshot = publication ? publication->snapshot : nullptr;
		if (!normalized || !snapshot) return {};
		const auto indexes = aida::analysis::publication_indexes::for_publication(
			publication, {});
		if (!indexes) return {};
		const auto* symbol = indexes->data_symbol_exact(normalized.value());
		return symbol ? symbol->name : std::string();
	}

	namespace detail {

		enum class func_state_t : uint32_t {
			idle = 0,
			building = 1,
			built = 2,
			failed = 3
		};

		enum class bounds_state_t : uint32_t {
			idle = 0,
			building = 1,
			ready = 2,
			failed = 3
		};

		enum class slot_kind_t : uint8_t {
			local_var = 0,
			stack_arg = 1,
			saved_reg = 2,
			saved_rbp_zero = 3,
			saved_ret_addr = 4
		};

		struct var_slot_t {
			int64_t     offset = 0;
			uint32_t    size = 4;
			slot_kind_t kind = slot_kind_t::local_var;
			std::string name;
			std::string reg_token;
			std::string prototype_name;
		};

		struct switch_table_t {
			uint64_t              jmp_va = 0;
			uint64_t              base_va = 0;
			uint64_t              table_va = 0;
			uint32_t              entry_size = 4;
			bool                  entries_are_offsets = true;
			uint64_t              default_addr = 0;
			std::vector<uint64_t> case_addrs;
		};

		struct align_run_t {
			uint64_t addr = 0;
			uint64_t end = 0;
			uint8_t  alignment = 16;
			uint8_t  fill_byte = 0xCC;
		};

		struct label_slot_t {
			uint64_t    addr = 0;
			bool        is_locret = false;
		};

		struct func_record_t {
			uint64_t                                  start = 0;
			uint64_t                                  end = 0;
			std::string                               section;
			std::string                               display_name;
			bool                                      bp_based = false;
			bool                                      sp_analysis_failed = false;
			std::vector<var_slot_t>                   vars;
			std::vector<label_slot_t>                 labels;
			std::unordered_set<uint64_t>              ret_addrs;
			uint64_t                                  last_insn_addr = 0;
			std::vector<injection_row_t>              before_first_insn;
			std::vector<injection_row_t>              after_last_insn;
			std::unordered_map<uint64_t, std::string> inline_labels;
			int64_t                                   entry_to_exit_sp_delta = 0;
			uint64_t                                  prologue_locals_size = 0;
			bool                                      sp_based = false;
			std::unordered_map<uint64_t, std::string> rsp_access_substitution;
			std::unordered_map<uint64_t, int64_t>     rsp_access_entry_relative;
			std::unordered_map<uint64_t, int64_t>     rsp_access_abs_offset;
			std::unordered_map<int64_t, std::string>  prototype_slot_names;
			std::unordered_map<uint64_t, std::string> insn_kind_override;
			bool                                      is_thunk = false;
			uint64_t                                  thunk_target = 0;
			uint64_t                                  thunk_iat_va = 0;
			std::string                               thunk_target_name;
			std::vector<switch_table_t>               switches;
			std::unordered_map<uint64_t, std::string> inline_comments;
			bool                                      is_entry_stub = false;
			bool                                      is_user_main = false;
			std::string                               user_main_kind;
			std::vector<uint64_t>                     call_targets;
			std::unordered_set<uint64_t>              noreturn_call_addrs;
			std::unordered_map<uint64_t, directive_override_t> directive_overrides;
			bool                                      always_noreturn = false;
			bool                                      is_library = false;
		};

		struct func_status_t {
			std::atomic<uint32_t> state{static_cast<uint32_t>(func_state_t::idle)};
		};

		struct iat_entry_t {
			std::string module_name;
			std::string function_name;
		};

		struct data_symbol_entry_t {
			std::string name;
			bool        is_function = false;
		};

		struct cache_t {
			std::shared_mutex                                              mutex;
			aida::infra::fast_flat_map<uint64_t, func_record_t,
				aida::infra::fast_u64_hash_t>                          by_start;
			aida::infra::fast_u64_map<std::shared_ptr<func_status_t>>    status_by_start;
			aida::infra::fast_u64_map<uint64_t>                          addr_to_func_start;
			std::vector<uint64_t>                                          sorted_starts;
			aida::infra::fast_u64_map<std::string>                       synthetic_names;
			aida::infra::fast_u64_map<align_run_t>                       align_runs_by_start;
			std::vector<uint64_t>                                          align_run_starts;
			aida::infra::fast_u64_map<iat_entry_t>                       iat_lookup;
			aida::infra::fast_u64_map<data_symbol_entry_t>               data_symbol_lookup;
			std::vector<uint8_t>                                           text_blob;
			uint64_t                                                       text_blob_va = 0;
			uint64_t                                                       cached_module_base = 0;
			uint32_t                                                       cached_module_size = 0;
			std::string                                                    cached_module_name;
			uint64_t                                                       cached_pid_token = 0;
			uint64_t                                                       cached_entry_point = 0;
			uint16_t                                                       cached_subsystem = 0;
			uint16_t                                                       cached_characteristics = 0;
			std::atomic<uint32_t>                                          bounds_state{static_cast<uint32_t>(bounds_state_t::idle)};
			std::atomic<uint64_t>                                          built_seq{0};
		};

		inline std::mutex& holder_swap_mtx() {
			static std::mutex m;
			return m;
		}

		inline std::shared_ptr<cache_t>& cache_holder_sp() {
			static std::shared_ptr<cache_t> h = std::make_shared<cache_t>();
			return h;
		}

		inline cache_t& cache() {
			std::lock_guard<std::mutex> lk(holder_swap_mtx());
			auto& holder = cache_holder_sp();
			if (!holder) {
				holder = std::make_shared<cache_t>();
			}
			return *holder;
		}

		inline std::string format_hex_upper(uint64_t v) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
			return std::string(buf);
		}

		inline std::string format_signed_hex(int64_t v) {
			char buf[32];
			if (v < 0) {
				std::snprintf(buf, sizeof(buf), "-%llXh", static_cast<unsigned long long>(-v));
			}
			else {
				std::snprintf(buf, sizeof(buf), " %llXh", static_cast<unsigned long long>(v));
			}
			return std::string(buf);
		}

		inline std::string ptr_word_for_size(uint32_t sz) {
			switch (sz) {
				case 1: return "byte ptr";
				case 2: return "word ptr";
				case 4: return "dword ptr";
				case 8: return "qword ptr";
				case 16: return "xmmword ptr";
				case 32: return "ymmword ptr";
				case 64: return "zmmword ptr";
				default: return "dword ptr";
			}
		}

		inline std::string make_synthetic_sub(uint64_t addr) {
			char buf[40];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline std::string strip_module_prefix(const std::string& s) {
			auto pos = s.find('!');
			if (pos == std::string::npos) return s;
			return s.substr(pos + 1);
		}

		inline std::string resolve_display_name(uint64_t addr) {
			std::string sym = resolve_live_debugger_name_exact(addr);
			if (!sym.empty()) return strip_module_prefix(sym);
			return make_synthetic_sub(addr);
		}

		inline std::string pad_right(const std::string& s, size_t width) {
			if (s.size() >= width) return s + " ";
			std::string out = s;
			out.append(width - s.size(), ' ');
			return out;
		}

		struct cached_module_entry_t {
			uint64_t    base = 0;
			uint64_t    end = 0;
			uint32_t    size = 0;
			std::string name;
		};

		struct cached_module_table_t {
			std::shared_mutex                    mu;
			uint32_t                             pid = 0;
			std::vector<cached_module_entry_t>   entries;
			std::atomic<uint64_t>                last_built_ms{0};
			std::atomic<bool>                    rebuild_in_flight{false};
		};

		inline cached_module_table_t& cached_module_table() {
			static cached_module_table_t t;
			return t;
		}

		inline uint64_t now_ms_steady() {
			using clock_t = std::chrono::steady_clock;
			auto tp = clock_t::now().time_since_epoch();
			return static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
		}

		inline bool cached_module_lookup_locked(const std::vector<cached_module_entry_t>& entries,
			uint64_t addr, uint64_t& out_base, uint32_t& out_size, std::string& out_name)
		{
			if (entries.empty()) return false;
			auto it = std::upper_bound(entries.begin(), entries.end(), addr,
				[](uint64_t a, const cached_module_entry_t& e) {
					return a < e.base;
				});
			if (it == entries.begin()) return false;
			--it;
			if (addr < it->base || addr >= it->end) return false;
			out_base = it->base;
			out_size = it->size;
			out_name = it->name;
			return true;
		}

		inline bool resolve_module_for_address_cached_only(uint64_t addr,
			uint64_t& out_base, uint32_t& out_size, std::string& out_name)
		{
			cached_module_table_t& t = cached_module_table();
			uint32_t pid_now = driver_bridge::attached_pid();
			if (pid_now == 0) return false;
			uint64_t built_ms = t.last_built_ms.load(std::memory_order_acquire);
			if (built_ms == 0) return false;
			uint64_t now = now_ms_steady();
			if (now - built_ms > 5000) return false;
			std::shared_lock<std::shared_mutex> lk(t.mu);
			if (t.pid != pid_now) return false;
			return cached_module_lookup_locked(t.entries, addr, out_base, out_size, out_name);
		}

		inline void rebuild_cached_module_table_offlock(uint32_t pid_now) {
			cached_module_table_t& t = cached_module_table();
			auto modules = driver_bridge::enumerate_modules();

			std::vector<cached_module_entry_t> staged;
			staged.reserve(modules.size());
			for (const auto& m : modules) {
				if (m.base == 0 || m.size == 0) continue;
				cached_module_entry_t e;
				e.base = m.base;
				e.end = m.base + m.size;
				e.size = m.size;
				e.name = m.name;
				staged.push_back(std::move(e));
			}
			std::sort(staged.begin(), staged.end(),
				[](const cached_module_entry_t& a, const cached_module_entry_t& b) {
					return a.base < b.base;
				});

			{
				std::scoped_lock<std::shared_mutex> w(t.mu);
				t.entries.swap(staged);
				t.pid = pid_now;
			}
			t.last_built_ms.store(now_ms_steady(), std::memory_order_release);
		}

		inline bool resolve_module_for_address(uint64_t addr, uint64_t& out_base,
			uint32_t& out_size, std::string& out_name)
		{
			if (!driver_bridge::is_loaded()) return false;
			uint32_t pid_now = driver_bridge::attached_pid();
			if (pid_now == 0) return false;

			cached_module_table_t& t = cached_module_table();
			uint64_t now = now_ms_steady();
			uint64_t built_ms = t.last_built_ms.load(std::memory_order_acquire);
			bool cache_hot = false;
			{
				std::shared_lock<std::shared_mutex> lk(t.mu);
				cache_hot = (t.pid == pid_now && built_ms != 0 && now - built_ms < 5000);
				if (cache_hot) {
					if (cached_module_lookup_locked(t.entries, addr, out_base, out_size, out_name)) {
						return true;
					}
				}
			}

			if (cache_hot) {
				return false;
			}

			bool expected = false;
			if (!t.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				std::shared_lock<std::shared_mutex> lk(t.mu);
				return cached_module_lookup_locked(t.entries, addr, out_base, out_size, out_name);
			}

			rebuild_cached_module_table_offlock(pid_now);
			t.rebuild_in_flight.store(false, std::memory_order_release);

			std::shared_lock<std::shared_mutex> lk(t.mu);
			return cached_module_lookup_locked(t.entries, addr, out_base, out_size, out_name);
		}

		inline bool fetch_active_module(uint64_t& out_base, uint32_t& out_size,
			std::string& out_name)
		{
			if (!driver_bridge::is_loaded()) return false;
			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) return false;

			const auto process_name = driver_bridge::attached_process_name();
			if (!process_name.empty()) {
				for (const auto& m : modules) {
					if (_stricmp(m.name.c_str(), process_name.c_str()) == 0) {
						if (m.base == 0 || m.size == 0) continue;
						out_base = m.base;
						out_size = m.size;
						out_name = m.name;
						return true;
					}
				}
			}

			const driver_bridge::module_info_t* best = nullptr;
			for (const auto& m : modules) {
				if (m.base == 0 || m.size == 0) continue;
				if (best == nullptr || m.base < best->base) {
					best = &m;
				}
			}
			if (best == nullptr) return false;
			out_base = best->base;
			out_size = best->size;
			out_name = best->name;
			return true;
		}

		inline bool static_pe_active() {
			auto workspace = aida::analysis::workspace_registry().selected_for_ui();
			return workspace &&
				workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
				workspace->image() && !workspace->closing() && !workspace->closed();
		}

		inline bool read_routed_bytes(uint64_t va, size_t len, std::vector<uint8_t>& out) {
			out.clear();
			const uint32_t pid = driver_bridge::attached_pid();
			if (pid == 0 || len == 0 || len > 64 * 1024 * 1024)
				return false;
			return driver_bridge::read_memory_for(pid, va, len, out) && out.size() == len;
		}

		inline bool read_live_runtime_function_table(uint64_t module_base,
			const pe_parser::pe_info_t& pe, std::vector<uint64_t>& starts,
			std::vector<uint32_t>& sizes)
		{
			starts.clear();
			sizes.clear();
			if (!pe.is_64bit || pe.exception_dir_rva == 0 ||
				pe.exception_dir_size == 0)
				return true;
			constexpr uint32_t kEntrySize = 12;
			constexpr uint64_t kMaximumEntries = 4ULL * 1024ULL * 1024ULL;
			if (pe.exception_dir_size % kEntrySize != 0 ||
				pe.exception_dir_rva >= pe.size_of_image ||
				pe.exception_dir_size > pe.size_of_image - pe.exception_dir_rva)
				return false;
			const uint64_t count = pe.exception_dir_size / kEntrySize;
			if (count == 0 || count > kMaximumEntries ||
				module_base > UINT64_MAX - pe.exception_dir_rva)
				return false;
			std::vector<uint8_t> table;
			if (!read_routed_bytes(module_base + pe.exception_dir_rva,
				pe.exception_dir_size, table))
				return false;
			starts.reserve(static_cast<size_t>(count));
			sizes.reserve(static_cast<size_t>(count));
			for (uint64_t index = 0; index < count; ++index) {
				uint32_t begin = 0;
				uint32_t end = 0;
				std::memcpy(&begin, table.data() + index * kEntrySize, sizeof(begin));
				std::memcpy(&end, table.data() + index * kEntrySize + 4, sizeof(end));
				if (begin >= end || end > pe.size_of_image ||
					module_base > UINT64_MAX - begin)
					return false;
				starts.push_back(module_base + begin);
				sizes.push_back(end - begin);
			}
			return true;
		}

		inline std::string section_name_for_va(const pe_parser::pe_info_t& pe,
			uint64_t module_base, uint64_t va)
		{
			if (va < module_base) return std::string();
			uint32_t rva = static_cast<uint32_t>(va - module_base);
			for (const auto& s : pe.sections) {
				if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
					return s.name;
				}
			}
			return std::string();
		}

		inline bool gap_is_padding(const std::vector<uint8_t>& blob, uint64_t blob_va,
			uint64_t lo_va, uint64_t hi_va, uint8_t& out_fill)
		{
			if (hi_va <= lo_va) return false;
			if (lo_va < blob_va) return false;
			size_t lo = static_cast<size_t>(lo_va - blob_va);
			size_t hi = static_cast<size_t>(hi_va - blob_va);
			if (hi > blob.size()) return false;
			if (hi <= lo) return false;
			size_t len = hi - lo;
			if (len > 0x10000) return false;
			bool all_cc = true;
			for (size_t i = lo; i < hi; ++i) {
				if (blob[i] != 0xCC) { all_cc = false; break; }
			}
			if (all_cc) { out_fill = 0xCC; return true; }
			bool all_90 = true;
			for (size_t i = lo; i < hi; ++i) {
				if (blob[i] != 0x90) { all_90 = false; break; }
			}
			if (all_90) { out_fill = 0x90; return true; }
			size_t i = lo;
			bool nop_seq = true;
			while (i < hi && nop_seq) {
				if (blob[i] == 0x90) { ++i; continue; }
				if (i + 1 < hi && blob[i] == 0x66 && blob[i + 1] == 0x90) { i += 2; continue; }
				if (i + 2 < hi && blob[i] == 0x0F && blob[i + 1] == 0x1F && blob[i + 2] == 0x00) {
					i += 3; continue;
				}
				if (i + 3 < hi && blob[i] == 0x0F && blob[i + 1] == 0x1F
					&& blob[i + 2] == 0x40 && blob[i + 3] == 0x00)
				{
					i += 4; continue;
				}
				if (i + 4 < hi && blob[i] == 0x0F && blob[i + 1] == 0x1F
					&& blob[i + 2] == 0x44 && blob[i + 3] == 0x00 && blob[i + 4] == 0x00)
				{
					i += 5; continue;
				}
				if (i + 5 < hi && blob[i] == 0x66 && blob[i + 1] == 0x0F
					&& blob[i + 2] == 0x1F && blob[i + 3] == 0x44
					&& blob[i + 4] == 0x00 && blob[i + 5] == 0x00)
				{
					i += 6; continue;
				}
				if (i + 6 < hi && blob[i] == 0x0F && blob[i + 1] == 0x1F
					&& blob[i + 2] == 0x80 && blob[i + 3] == 0x00 && blob[i + 4] == 0x00
					&& blob[i + 5] == 0x00 && blob[i + 6] == 0x00)
				{
					i += 7; continue;
				}
				if (i + 7 < hi && blob[i] == 0x0F && blob[i + 1] == 0x1F
					&& blob[i + 2] == 0x84 && blob[i + 3] == 0x00 && blob[i + 4] == 0x00
					&& blob[i + 5] == 0x00 && blob[i + 6] == 0x00 && blob[i + 7] == 0x00)
				{
					i += 8; continue;
				}
				nop_seq = false;
			}
			if (nop_seq && i == hi) { out_fill = 0x90; return true; }
			return false;
		}

		inline uint8_t pick_alignment_pow2(uint64_t next_start, uint64_t gap_size) {
			if (next_start == 0) return 16;
			static const uint8_t kCandidates[] = {64, 32, 16, 8, 4, 2};
			for (uint8_t a : kCandidates) {
				if ((next_start % a) == 0 && a >= gap_size) return a;
			}
			return 1;
		}

		struct prototype_entry_t {
			const char* name;
			const char* params[12];
		};

		inline const prototype_entry_t* lookup_prototype_entry(const std::string& callee_name) {
			if (callee_name.empty()) return nullptr;
			static const prototype_entry_t kTable[] = {
				{ "_invoke_watson",
					{ "Expression", "FunctionName", "FileName", "LineNo", "Reserved", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "_invalid_parameter",
					{ "Expression", "FunctionName", "FileName", "LineNo", "Reserved", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "_invalid_parameter_noinfo",
					{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "_invalid_parameter_noinfo_noreturn",
					{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "memcpy",
					{ "Dst", "Src", "Size", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "memmove",
					{ "Dst", "Src", "Size", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "memset",
					{ "Dst", "Val", "Size", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "memcmp",
					{ "Buf1", "Buf2", "Size", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strcpy",
					{ "Dst", "Src", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strncpy",
					{ "Dst", "Src", "Count", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strcpy_s",
					{ "Dst", "DstSize", "Src", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strncpy_s",
					{ "Dst", "DstSize", "Src", "Count", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "wcscpy",
					{ "Dst", "Src", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "wcsncpy",
					{ "Dst", "Src", "Count", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strlen",
					{ "Str", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "wcslen",
					{ "Str", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "strcmp",
					{ "Str1", "Str2", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "wcscmp",
					{ "Str1", "Str2", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "RaiseException",
					{ "dwExceptionCode", "dwExceptionFlags", "nNumberOfArguments", "lpArguments", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "RaiseFailFastException",
					{ "pExceptionRecord", "pContextRecord", "dwFlags", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__report_gsfailure",
					{ "StackCookie", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__report_rangecheckfailure",
					{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__report_securityfailure",
					{ "FailureCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__report_securityfailureEx",
					{ "FailureCode", "ReturnAddress", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__GSHandlerCheck",
					{ "ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__C_specific_handler",
					{ "ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__CxxFrameHandler",
					{ "ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__CxxFrameHandler3",
					{ "ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__CxxFrameHandler4",
					{ "ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "_CxxThrowException",
					{ "pExceptionObject", "pThrowInfo", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "__std_terminate",
					{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "ExitProcess",
					{ "uExitCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "ExitThread",
					{ "dwExitCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "TerminateProcess",
					{ "hProcess", "uExitCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "TerminateThread",
					{ "hThread", "dwExitCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "Sleep",
					{ "dwMilliseconds", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "SleepEx",
					{ "dwMilliseconds", "bAlertable", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "CreateFileW",
					{ "lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "CreateFileA",
					{ "lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "ReadFile",
					{ "hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "WriteFile",
					{ "hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "CloseHandle",
					{ "hObject", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "GetLastError",
					{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "SetLastError",
					{ "dwErrCode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "VirtualAlloc",
					{ "lpAddress", "dwSize", "flAllocationType", "flProtect", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "VirtualFree",
					{ "lpAddress", "dwSize", "dwFreeType", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "VirtualProtect",
					{ "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "LoadLibraryW",
					{ "lpLibFileName", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "LoadLibraryA",
					{ "lpLibFileName", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "GetProcAddress",
					{ "hModule", "lpProcName", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "GetModuleHandleW",
					{ "lpModuleName", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } },
				{ "GetModuleHandleA",
					{ "lpModuleName", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr } }
			};

			std::string lookup = callee_name;
			if (lookup.size() >= 6 && lookup.compare(0, 6, "__imp_") == 0) {
				lookup = lookup.substr(6);
			}
			for (const auto& e : kTable) {
				if (lookup == e.name) return &e;
			}
			if (callee_name.size() >= 14 && callee_name.compare(0, 14, "_invoke_watson") == 0) {
				for (const auto& e : kTable) {
					if (std::string("_invoke_watson") == e.name) return &e;
				}
			}
			if (callee_name.size() >= 19 && callee_name.compare(0, 19, "_invalid_parameter_") == 0) {
				for (const auto& e : kTable) {
					if (std::string("_invalid_parameter_noinfo") == e.name) return &e;
				}
			}
			return nullptr;
		}

		inline const char* prototype_param_name(const prototype_entry_t& proto, size_t idx) {
			if (idx >= sizeof(proto.params) / sizeof(proto.params[0])) return nullptr;
			return proto.params[idx];
		}

		inline bool name_is_noreturn(const std::string& name) {
			if (name.empty()) return false;
			static const char* const kExact[] = {
				"_invoke_watson",
				"_invalid_parameter",
				"_invalid_parameter_noinfo",
				"_invalid_parameter_noinfo_noreturn",
				"_CxxThrowException",
				"__report_gsfailure",
				"__report_rangecheckfailure",
				"__report_securityfailure",
				"__report_securityfailureEx",
				"__std_terminate",
				"terminate",
				"abort",
				"_abort",
				"exit",
				"_exit",
				"_purecall",
				"_unrecoverable_error",
				"RaiseException",
				"RaiseFailFastException",
				"ExitProcess",
				"ExitThread",
				"TerminateProcess",
				"TerminateThread",
				"FatalAppExit",
				"FatalAppExitA",
				"FatalAppExitW",
				"FatalExit",
				"__fastfail",
				"longjmp",
				"_longjmp",
				"siglongjmp",
				"__cxa_throw",
				"unhandled_exception",
				"abort_program",
				"_CRT_DEBUGGER_HOOK",
				"__chkstk_fail",
				"_CRT_RTC_INITW",
				"__GSHandlerCheckCommon",
				"AcrtTerminate"
			};
			for (const char* p : kExact) {
				if (name == p) return true;
			}
			if (name.size() >= 18 && name.compare(0, 18, "_invalid_parameter") == 0) return true;
			if (name.size() >= 8 && name.compare(0, 8, "__report") == 0) return true;
			if (name.size() >= 14 && name.compare(0, 14, "_invoke_watson") == 0) return true;
			return false;
		}

		inline bool name_is_library_function(const std::string& name) {
			if (name.empty()) return false;
			static const char* const kPrefixes[] = {
				"__security_",
				"__scrt_",
				"__std_",
				"__report_",
				"__acrt_",
				"__crt_",
				"__vcrt_",
				"_RTC_",
				"_CRT_",
				"__chkstk",
				"__C_specific_handler",
				"__GSHandlerCheck",
				"__CxxFrameHandler",
				"_initterm",
				"mainCRTStartup",
				"WinMainCRTStartup",
				"DllMainCRTStartup",
				"_DllMainCRTStartup",
				"_amsg_",
				"_alloca_probe",
				"__delayLoadHelper2",
				"_purecall",
				"memcpy",
				"memset",
				"memmove",
				"memcmp",
				"_chkstk",
				"__alloca_probe"
			};
			for (const char* p : kPrefixes) {
				size_t plen = std::strlen(p);
				if (name.size() >= plen && name.compare(0, plen, p) == 0) return true;
			}
			return false;
		}

		inline bool target_is_noreturn(uint64_t target_va, uint64_t iat_va) {
			if (target_va != 0) {
				std::string sym = resolve_live_debugger_name_exact(target_va);
				if (!sym.empty()) {
					std::string stripped = strip_module_prefix(sym);
					if (name_is_noreturn(stripped)) return true;
				}
				std::string near_sym = resolve_live_debugger_name_nearest(target_va);
				if (!near_sym.empty()) {
					std::string stripped = strip_module_prefix(near_sym);
					if (name_is_noreturn(stripped)) return true;
				}
			}
			if (iat_va != 0) {
				std::string iat_imp;
				if (symbol_classifier::lookup_import_by_iat(iat_va, iat_imp) && !iat_imp.empty()) {
					std::string stripped = strip_module_prefix(iat_imp);
					if (name_is_noreturn(stripped)) return true;
				}
				std::string iat_sym = resolve_live_debugger_name_exact(iat_va);
				if (!iat_sym.empty()) {
					std::string stripped = strip_module_prefix(iat_sym);
					if (stripped.size() >= 6 && stripped.compare(0, 6, "__imp_") == 0) {
						stripped = stripped.substr(6);
					}
					if (name_is_noreturn(stripped)) return true;
				}
				std::string iat_near = resolve_live_debugger_name_nearest(iat_va);
				if (!iat_near.empty()) {
					std::string stripped = strip_module_prefix(iat_near);
					if (stripped.size() >= 6 && stripped.compare(0, 6, "__imp_") == 0) {
						stripped = stripped.substr(6);
					}
					if (name_is_noreturn(stripped)) return true;
				}
			}
			return false;
		}

		inline uint8_t pick_intra_align(uint64_t next_code_va, uint64_t gap_size) {
			if (next_code_va == 0 || gap_size == 0) return 0;
			static const uint8_t kCandidates[] = {16, 8, 4, 2};
			for (uint8_t a : kCandidates) {
				if ((next_code_va % a) == 0 && a >= gap_size) return a;
			}
			return 0;
		}

		inline void rebuild_align_runs_locked(cache_t& c) {
			c.align_runs_by_start.clear();
			c.align_run_starts.clear();
			if (c.text_blob.empty() || c.text_blob_va == 0) return;
			if (c.sorted_starts.size() < 2) return;
			uint64_t blob_lo = c.text_blob_va;
			uint64_t blob_hi = blob_lo + c.text_blob.size();

			for (size_t i = 0; i + 1 < c.sorted_starts.size(); ++i) {
				uint64_t cur_start = c.sorted_starts[i];
				uint64_t next_start = c.sorted_starts[i + 1];
				auto rit = c.by_start.find(cur_start);
				if (rit == c.by_start.end()) continue;
				uint64_t cur_end = rit->second.end;
				if (cur_end >= next_start) continue;
				if (cur_end < blob_lo || next_start > blob_hi) continue;
				uint8_t fill = 0;
				if (!gap_is_padding(c.text_blob, c.text_blob_va, cur_end, next_start, fill)) {
					continue;
				}
				align_run_t a;
				a.addr = cur_end;
				a.end = next_start;
				a.fill_byte = fill;
				a.alignment = pick_alignment_pow2(next_start, next_start - cur_end);
				c.align_run_starts.push_back(cur_end);
				c.align_runs_by_start.emplace(cur_end, std::move(a));
			}
			std::sort(c.align_run_starts.begin(), c.align_run_starts.end());
		}

		inline bool entry_naming_should_skip(uint64_t va) {
			if (!resolve_live_debugger_name_exact(va).empty()) return true;
			return false;
		}

		inline void apply_entry_point_naming_locked(cache_t& c,
			const pe_parser::pe_info_t& pe)
		{
			uint64_t entry_va = pe.entry_point;
			if (entry_va == 0) return;
			auto eit = c.by_start.find(entry_va);
			if (eit == c.by_start.end()) return;
			if (entry_naming_should_skip(entry_va)) return;

			eit->second.display_name = "start";
			eit->second.is_entry_stub = true;
			c.synthetic_names[entry_va] = "start";

			std::string main_kind;
			if ((pe.characteristics & 0x2000u) != 0) {
				main_kind = "DllMain";
			}
			else if (pe.subsystem == 2) {
				main_kind = "WinMain";
			}
			else if (pe.subsystem == 3) {
				main_kind = "main";
			}
			else {
				main_kind = "main";
			}

			uint64_t cursor = entry_va;
			std::unordered_set<uint64_t> visited;
			visited.insert(entry_va);
			uint64_t selected = 0;
			for (int hop = 0; hop < 64; ++hop) {
				auto it = c.by_start.find(cursor);
				if (it == c.by_start.end()) break;
				const auto& cur = it->second;
				if (cur.call_targets.empty()) break;

				std::vector<uint64_t> candidates;
				candidates.reserve(cur.call_targets.size());
				for (uint64_t t : cur.call_targets) {
					if (t == 0) continue;
					if (visited.count(t)) continue;
					if (t < c.cached_module_base
						|| t >= c.cached_module_base + c.cached_module_size)
					{
						continue;
					}
					if (!c.by_start.count(t)) continue;
					std::string nm = resolve_live_debugger_name_exact(t);
					if (nm.empty()) {
						std::string near_sym = resolve_live_debugger_name_nearest(t);
						if (!near_sym.empty()) {
							std::string s = strip_module_prefix(near_sym);
							if (s.find("CRT") != std::string::npos
								|| s.find("crt") != std::string::npos
								|| s.find("security_init") != std::string::npos
								|| s.find("__scrt") != std::string::npos
								|| s.find("__chkstk") != std::string::npos)
							{
								continue;
							}
						}
					}
					else {
						if (nm.find("CRT") != std::string::npos
							|| nm.find("crt") != std::string::npos
							|| nm.find("__scrt") != std::string::npos
							|| nm.find("security_init") != std::string::npos
							|| nm.find("__chkstk") != std::string::npos)
						{
							continue;
						}
					}
					auto tit = c.by_start.find(t);
					if (tit != c.by_start.end() && tit->second.is_thunk) continue;
					candidates.push_back(t);
				}

				if (candidates.size() == 1) {
					selected = candidates[0];
					if (hop >= 3) break;
					visited.insert(selected);
					cursor = selected;
					continue;
				}
				if (candidates.empty()) break;
				selected = 0;
				break;
			}

			if (selected != 0) {
				if (entry_naming_should_skip(selected)) return;
				auto sit = c.by_start.find(selected);
				if (sit == c.by_start.end()) return;
				sit->second.display_name = main_kind;
				sit->second.is_user_main = true;
				sit->second.user_main_kind = main_kind;
				c.synthetic_names[selected] = main_kind;
			}
		}

		inline std::string normalize_pdb_symbol_name(const std::string& raw) {
			if (raw.empty()) return raw;
			auto bang = raw.find('!');
			if (bang == std::string::npos) return raw;
			return raw.substr(bang + 1);
		}

		inline bool is_pdb_function_at(const std::string& module_name, uint64_t va) {
			auto module = legacy_live_module_symbols(module_name);
			if (!module || !module->pdb.loaded || va < module->base ||
				va - module->base >= module->size)
				return false;
			const uint64_t rva = va - module->base;
			auto symbol = module->pdb.symbol_by_rva.find(rva);
			return symbol != module->pdb.symbol_by_rva.end() &&
				symbol->second < module->pdb.symbols.size() &&
				module->pdb.symbols[symbol->second].is_function;
		}

		inline void populate_pdb_symbols_into(aida::infra::fast_u64_map<data_symbol_entry_t>& out,
			const std::string& module_name)
		{
			auto module = legacy_live_module_symbols(module_name);
			if (!module || !module->pdb.loaded) return;
			const uint64_t base = module->base;
			for (const auto& sym : module->pdb.symbols) {
				if (sym.name.empty()) continue;
				if (sym.rva == 0) continue;
				if (base > UINT64_MAX - sym.rva) continue;
				uint64_t va = base + sym.rva;
				data_symbol_entry_t e;
				e.name = sym.name;
				e.is_function = sym.is_function;
				auto eit = out.find(va);
				if (eit == out.end()) {
					out.emplace(va, std::move(e));
				}
				else if (sym.is_function && !eit->second.is_function) {
					eit->second.is_function = true;
					eit->second.name = sym.name;
				}
			}
		}

		inline void populate_iat_from_imports_locked(cache_t& c,
			const std::vector<pe_parser::import_entry_t>& imports)
		{
			c.iat_lookup.clear();
			c.iat_lookup.reserve(imports.size());
			for (const auto& imp : imports) {
				if (imp.iat_address == 0) continue;
				if (imp.function_name.empty() && imp.ordinal == 0) continue;
				iat_entry_t e;
				e.module_name = imp.module_name;
				if (!imp.function_name.empty()) {
					e.function_name = imp.function_name;
				}
				else {
					char ord_buf[32];
					std::snprintf(ord_buf, sizeof(ord_buf), "Ordinal#%u",
						static_cast<unsigned>(imp.ordinal));
					e.function_name = ord_buf;
				}
				c.iat_lookup.emplace(imp.iat_address, std::move(e));
			}
		}

		inline void populate_data_symbols_locked(cache_t& c,
			const pe_parser::pe_info_t& pe,
			const std::string& module_name)
		{
			c.data_symbol_lookup.clear();
			populate_pdb_symbols_into(c.data_symbol_lookup, module_name);
			for (const auto& exp : pe.exports) {
				if (exp.address == 0) continue;
				if (exp.name.empty()) continue;
				if (exp.is_forwarded) continue;
				data_symbol_entry_t e;
				e.name = exp.name;
				e.is_function = true;
				auto it = c.data_symbol_lookup.find(exp.address);
				if (it == c.data_symbol_lookup.end()) {
					c.data_symbol_lookup.emplace(exp.address, std::move(e));
				}
			}
		}

		inline void rebuild_bounds_index(uint64_t module_base, uint32_t module_size,
			const std::string& module_name)
		{
			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(module_base, pe)) {
				cache_t& c = cache();
				std::unique_lock<std::shared_mutex> lk(c.mutex);
				c.by_start.clear();
				c.status_by_start.clear();
				c.addr_to_func_start.clear();
				c.sorted_starts.clear();
				c.synthetic_names.clear();
				c.align_runs_by_start.clear();
				c.align_run_starts.clear();
				c.iat_lookup.clear();
				c.data_symbol_lookup.clear();
				c.text_blob.clear();
				c.text_blob_va = 0;
				c.cached_module_base = module_base;
				c.cached_module_size = module_size;
				c.cached_module_name = module_name;
				c.cached_entry_point = 0;
				c.cached_subsystem = 0;
				c.cached_characteristics = 0;
				return;
			}

			std::vector<uint64_t> rf_starts;
			std::vector<uint32_t> rf_sizes;
			read_live_runtime_function_table(module_base, pe,
				rf_starts, rf_sizes);

			std::unordered_map<uint64_t, uint32_t> size_lookup;
			size_lookup.reserve(rf_starts.size());
			for (size_t i = 0; i < rf_starts.size(); ++i) {
				auto it = size_lookup.find(rf_starts[i]);
				if (it == size_lookup.end()) {
					size_lookup.emplace(rf_starts[i], rf_sizes[i]);
				}
				else {
					if (rf_sizes[i] > it->second) it->second = rf_sizes[i];
				}
			}

			std::vector<uint64_t> candidates;
			candidates.reserve(rf_starts.size() + pe.exports.size() + 64);
			for (uint64_t va : rf_starts) {
				if (va >= module_base && va < module_base + module_size) {
					candidates.push_back(va);
				}
			}
			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0) continue;
				if (exp.address < module_base) continue;
				if (exp.address >= module_base + module_size) continue;
				candidates.push_back(exp.address);
			}

			if (auto module = legacy_live_module_symbols(module_name);
				module && module->pdb.loaded) {
				for (const auto& sym : module->pdb.symbols) {
					if (!sym.is_function || sym.rva == 0 ||
						module->base > UINT64_MAX - sym.rva)
						continue;
					const uint64_t va = module->base + sym.rva;
					if (va < module_base || va - module_base >= module_size) continue;
					candidates.push_back(va);
				}
			}

			if (pe.entry_point >= module_base && pe.entry_point < module_base + module_size) {
				candidates.push_back(pe.entry_point);
			}

			std::sort(candidates.begin(), candidates.end());
			candidates.erase(std::unique(candidates.begin(), candidates.end()),
				candidates.end());

			aida::infra::fast_flat_map<uint64_t, func_record_t,
				aida::infra::fast_u64_hash_t>                        by_start;
			aida::infra::fast_u64_map<std::shared_ptr<func_status_t>>  status_by_start;
			aida::infra::fast_u64_map<std::string>                     synthetic_names;
			std::vector<uint64_t>                                        sorted_starts;
			by_start.reserve(candidates.size());
			status_by_start.reserve(candidates.size());
			synthetic_names.reserve(candidates.size());
			sorted_starts.reserve(candidates.size());

			for (size_t i = 0; i < candidates.size(); ++i) {
				uint64_t start = candidates[i];
				uint64_t next = (i + 1 < candidates.size())
					? candidates[i + 1]
					: (module_base + module_size);

				uint32_t pdata_size = 0;
				auto sit = size_lookup.find(start);
				if (sit != size_lookup.end()) {
					pdata_size = sit->second;
				}

				uint64_t end = start + (pdata_size > 0 ? pdata_size : 1);
				if (end > next) end = next;
				if (end <= start) end = start + 1;
				if (end > module_base + module_size) end = module_base + module_size;

				func_record_t r;
				r.start = start;
				r.end = end;
				r.section = section_name_for_va(pe, module_base, start);
				r.display_name = resolve_display_name(start);
				r.last_insn_addr = start;
				synthetic_names.emplace(start, r.display_name);
				by_start.emplace(start, std::move(r));
				status_by_start.emplace(start, std::make_shared<func_status_t>());
				sorted_starts.push_back(start);
			}

			aida::infra::fast_u64_map<uint64_t> addr_to_func_start;
			addr_to_func_start.reserve(by_start.size());
			for (const auto& kv : by_start) {
				addr_to_func_start.emplace(kv.first, kv.first);
			}

			std::vector<uint8_t> text_blob;
			uint64_t             text_blob_va = 0;
			for (const auto& s : pe.sections) {
				if (s.name == ".text" && s.virtual_size > 0) {
					uint64_t va = module_base + s.virtual_address;
					size_t   sz = static_cast<size_t>(s.virtual_size);
					if (sz > 0x4000000) sz = 0x4000000;
					std::vector<uint8_t> blob;
					if (driver_bridge::read_memory(va, sz, blob) && !blob.empty()) {
						text_blob = std::move(blob);
						text_blob_va = va;
					}
					break;
				}
			}

			cache_t& c = cache();
			std::unique_lock<std::shared_mutex> lk(c.mutex);
			c.by_start = std::move(by_start);
			c.status_by_start = std::move(status_by_start);
			c.addr_to_func_start = std::move(addr_to_func_start);
			c.sorted_starts = std::move(sorted_starts);
			c.synthetic_names = std::move(synthetic_names);
			c.text_blob = std::move(text_blob);
			c.text_blob_va = text_blob_va;
			c.align_runs_by_start.clear();
			c.align_run_starts.clear();
			c.cached_module_base = module_base;
			c.cached_module_size = module_size;
			c.cached_module_name = module_name;
			c.cached_entry_point = pe.entry_point;
			c.cached_subsystem = pe.subsystem;
			c.cached_characteristics = static_cast<uint16_t>(pe.characteristics);
			populate_iat_from_imports_locked(c, pe.imports);
			populate_data_symbols_locked(c, pe, module_name);
			rebuild_align_runs_locked(c);
			apply_entry_point_naming_locked(c, pe);
		}

		inline uint64_t lookup_function_start_for_addr(uint64_t addr) {
			cache_t& c = cache();
			std::shared_lock<std::shared_mutex> lk(c.mutex);
			if (c.sorted_starts.empty()) return 0;
			auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
			if (it == c.sorted_starts.begin()) return 0;
			--it;
			uint64_t start = *it;
			auto rit = c.by_start.find(start);
			if (rit == c.by_start.end()) return 0;
			if (addr < rit->second.start || addr >= rit->second.end) return 0;
			return start;
		}

		inline uint32_t pdb_var_size_hint(const std::string& module_name,
			const std::string& sym_name)
		{
			auto module = legacy_live_module_symbols(module_name);
			if (!module || !module->pdb.loaded) return 0;
			auto nit = module->pdb.symbol_by_name.find(sym_name);
			if (nit == module->pdb.symbol_by_name.end() ||
				nit->second >= module->pdb.symbols.size()) return 0;
			const auto& sym = module->pdb.symbols[nit->second];
			return sym.size;
		}

		inline uint32_t operand_size_bytes(const ZydisDecodedOperand& op,
			const ZydisDecodedInstruction& ins)
		{
			if (op.size > 0) return op.size / 8u;
			return ins.operand_width / 8u;
		}

		inline std::string canonical_register_name(ZydisRegister reg) {
			switch (reg) {
				case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX:
				case ZYDIS_REGISTER_AX:  case ZYDIS_REGISTER_AL:
				case ZYDIS_REGISTER_AH:  return "rax";
				case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX:
				case ZYDIS_REGISTER_BX:  case ZYDIS_REGISTER_BL:
				case ZYDIS_REGISTER_BH:  return "rbx";
				case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX:
				case ZYDIS_REGISTER_CX:  case ZYDIS_REGISTER_CL:
				case ZYDIS_REGISTER_CH:  return "rcx";
				case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX:
				case ZYDIS_REGISTER_DX:  case ZYDIS_REGISTER_DL:
				case ZYDIS_REGISTER_DH:  return "rdx";
				case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI:
				case ZYDIS_REGISTER_SI:  case ZYDIS_REGISTER_SIL: return "rsi";
				case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI:
				case ZYDIS_REGISTER_DI:  case ZYDIS_REGISTER_DIL: return "rdi";
				case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP:
				case ZYDIS_REGISTER_BP:  case ZYDIS_REGISTER_BPL: return "rbp";
				case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP:
				case ZYDIS_REGISTER_SP:  case ZYDIS_REGISTER_SPL: return "rsp";
				case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:
				case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return "r8";
				case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:
				case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return "r9";
				case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D:
				case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return "r10";
				case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D:
				case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return "r11";
				case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D:
				case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return "r12";
				case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D:
				case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return "r13";
				case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D:
				case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return "r14";
				case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D:
				case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return "r15";
				default: break;
			}
			if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				char buf[16];
				std::snprintf(buf, sizeof(buf), "xmm%u",
					static_cast<unsigned>(reg - ZYDIS_REGISTER_XMM0));
				return std::string(buf);
			}
			if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				char buf[16];
				std::snprintf(buf, sizeof(buf), "ymm%u",
					static_cast<unsigned>(reg - ZYDIS_REGISTER_YMM0));
				return std::string(buf);
			}
			if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				char buf[16];
				std::snprintf(buf, sizeof(buf), "zmm%u",
					static_cast<unsigned>(reg - ZYDIS_REGISTER_ZMM0));
				return std::string(buf);
			}
			return std::string();
		}

		inline bool is_rsp_family(ZydisRegister reg) {
			return reg == ZYDIS_REGISTER_RSP
				|| reg == ZYDIS_REGISTER_ESP
				|| reg == ZYDIS_REGISTER_SP
				|| reg == ZYDIS_REGISTER_SPL;
		}

		inline bool is_callee_saved_gp(ZydisRegister reg) {
			std::string c = canonical_register_name(reg);
			if (c == "rbx" || c == "rbp" || c == "rsi" || c == "rdi"
				|| c == "r12" || c == "r13" || c == "r14" || c == "r15")
			{
				return true;
			}
			return false;
		}

		inline bool is_callee_saved_xmm(ZydisRegister reg) {
			if (reg < ZYDIS_REGISTER_XMM0 || reg > ZYDIS_REGISTER_XMM15) return false;
			unsigned idx = static_cast<unsigned>(reg - ZYDIS_REGISTER_XMM0);
			return idx >= 6 && idx <= 15;
		}

		inline bool register_classes_match(ZydisRegister a, ZydisRegister b) {
			std::string ca = canonical_register_name(a);
			if (ca.empty()) return false;
			return ca == canonical_register_name(b);
		}

		inline bool memory_is_rip_relative(const ZydisDecodedOperand& op) {
			return op.type == ZYDIS_OPERAND_TYPE_MEMORY
				&& op.mem.base == ZYDIS_REGISTER_RIP
				&& op.mem.index == ZYDIS_REGISTER_NONE;
		}

		inline std::string lookup_thunk_target_name(uint64_t target_va, uint64_t iat_va) {
			std::string sym = resolve_live_debugger_name_exact(target_va);
			if (!sym.empty()) return strip_module_prefix(sym);
			if (iat_va != 0) {
				std::string iat_sym = resolve_live_debugger_name_exact(iat_va);
				if (!iat_sym.empty()) {
					std::string s = strip_module_prefix(iat_sym);
					if (!s.empty() && s.compare(0, 4, "__imp") == 0) {
						size_t p = s.find('_');
						if (p != std::string::npos && p + 1 < s.size()) {
							return s.substr(p + 1);
						}
					}
					return s;
				}
				std::string iat_near = resolve_live_debugger_name_nearest(iat_va);
				if (!iat_near.empty()) return strip_module_prefix(iat_near);
			}
			std::string near_sym = resolve_live_debugger_name_nearest(target_va);
			if (!near_sym.empty()) return strip_module_prefix(near_sym);
			char buf[40];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(target_va));
			return std::string(buf);
		}

		inline int x64_arg_register_index(ZydisRegister reg) {
			std::string c = canonical_register_name(reg);
			if (c == "rcx" || c == "ecx" || c == "cx" || c == "cl") return 0;
			if (c == "rdx" || c == "edx" || c == "dx" || c == "dl") return 1;
			if (c == "r8"  || c == "r8d" || c == "r8w" || c == "r8b") return 2;
			if (c == "r9"  || c == "r9d" || c == "r9w" || c == "r9b") return 3;
			return -1;
		}

		inline bool resolve_call_target(const ZydisDecodedInstruction& ins,
			const ZydisDecodedOperand* operands, uint64_t va, uint64_t& out_target,
			uint64_t& out_iat_va);

		inline std::string iat_lookup_function_locked(cache_t& c, uint64_t iat_va) {
			auto it = c.iat_lookup.find(iat_va);
			if (it == c.iat_lookup.end()) return std::string();
			return it->second.function_name;
		}

		inline const prototype_entry_t* lookup_prototype_for_call(
			const ZydisDecodedInstruction& call_ins,
			const ZydisDecodedOperand* call_operands,
			uint64_t call_va)
		{
			uint64_t target = 0;
			uint64_t iat_va = 0;
			if (!resolve_call_target(call_ins, call_operands, call_va, target, iat_va)) {
				return nullptr;
			}
			std::string name;
			if (iat_va != 0) {
				cache_t& c = cache();
				std::shared_lock<std::shared_mutex> lk(c.mutex);
				name = iat_lookup_function_locked(c, iat_va);
			}
			if (name.empty()) {
				std::string thunk_name = lookup_thunk_target_name(target, iat_va);
				if (!thunk_name.empty() && thunk_name.compare(0, 4, "sub_") != 0) {
					name = thunk_name;
				}
			}
			if (name.empty()) return nullptr;
			if (name.size() >= 6 && name.compare(0, 6, "__imp_") == 0) {
				name = name.substr(6);
			}
			return lookup_prototype_entry(name);
		}

		struct sp_tracker_state_t {
			int64_t                                   sp_delta = 0;
			int64_t                                   min_sp_delta = 0;
			int64_t                                   prologue_locals_size = 0;
			int64_t                                   chkstk_pending_imm = 0;
			bool                                      have_chkstk_pending = false;
			bool                                      saw_call_or_branch = false;
			bool                                      bp_assigned_from_sp = false;
			bool                                      sp_failed = false;
			bool                                      had_sp_op = false;
			std::unordered_map<int64_t, std::string>  saved_reg_at_offset;
		};

		struct lookback_entry_t {
			uint64_t                  va = 0;
			ZydisDecodedInstruction   ins{};
			ZydisDecodedOperand       operands[ZYDIS_MAX_OPERAND_COUNT]{};
			bool                      valid = false;
		};

		inline bool reg_is_chkstk_arg(ZydisRegister reg) {
			std::string c = canonical_register_name(reg);
			return c == "rax";
		}

		inline bool resolve_call_target(const ZydisDecodedInstruction& ins,
			const ZydisDecodedOperand* operands, uint64_t va, uint64_t& out_target,
			uint64_t& out_iat_va)
		{
			out_target = 0;
			out_iat_va = 0;
			for (uint8_t i = 0; i < ins.operand_count_visible; ++i) {
				const auto& op = operands[i];
				if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
					uint64_t tgt = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, va, &tgt))) {
						out_target = tgt;
						return true;
					}
				}
				if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
					&& op.mem.base == ZYDIS_REGISTER_RIP
					&& op.mem.index == ZYDIS_REGISTER_NONE)
				{
					uint64_t iat_va = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, va, &iat_va))) {
						out_iat_va = iat_va;
						std::vector<uint8_t> ind;
						if (read_routed_bytes(iat_va, 8, ind)
							&& ind.size() >= 8)
						{
							uint64_t ptr = 0;
							std::memcpy(&ptr, ind.data(), 8);
							if (ptr != 0) out_target = ptr;
						}
						return out_target != 0 || out_iat_va != 0;
					}
				}
			}
			return false;
		}

		inline bool detect_thunk(func_record_t& r, const std::vector<uint8_t>& bytes,
			const std::vector<lookback_entry_t>& decoded_seq)
		{
			if (decoded_seq.empty()) return false;
			size_t n = decoded_seq.size();
			if (n > 3) return false;
			if (n == 1) {
				const auto& e = decoded_seq[0];
				if (e.ins.meta.category != ZYDIS_CATEGORY_UNCOND_BR) return false;
				if (e.ins.mnemonic != ZYDIS_MNEMONIC_JMP) return false;
				uint64_t target = 0;
				uint64_t iat_va = 0;
				if (!resolve_call_target(e.ins, e.operands, e.va, target, iat_va)) return false;
				if (iat_va == 0 && target == 0) return false;
				r.is_thunk = true;
				r.thunk_target = target;
				r.thunk_iat_va = iat_va;
				r.thunk_target_name = lookup_thunk_target_name(target, iat_va);
				return true;
			}
			if (n == 2) {
				const auto& a = decoded_seq[0];
				const auto& b = decoded_seq[1];
				if (b.ins.mnemonic != ZYDIS_MNEMONIC_JMP) return false;
				if (b.ins.operand_count_visible == 0) return false;
				const auto& bop0 = b.operands[0];
				if (bop0.type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
				ZydisRegister jmp_reg = bop0.reg.value;
				uint64_t target = 0;
				uint64_t iat_va = 0;
				if (a.ins.mnemonic == ZYDIS_MNEMONIC_MOV) {
					if (a.ins.operand_count_visible < 2) return false;
					if (a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
					if (!register_classes_match(a.operands[0].reg.value, jmp_reg)) return false;
					if (a.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& !a.operands[1].imm.is_relative)
					{
						target = static_cast<uint64_t>(a.operands[1].imm.value.u);
					}
					else if (a.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						&& a.operands[1].mem.base == ZYDIS_REGISTER_RIP
						&& a.operands[1].mem.index == ZYDIS_REGISTER_NONE)
					{
						uint64_t computed_iat = 0;
						if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&a.ins, &a.operands[1],
							a.va, &computed_iat)))
						{
							return false;
						}
						iat_va = computed_iat;
						std::vector<uint8_t> ind;
						if (read_routed_bytes(iat_va, 8, ind)
							&& ind.size() >= 8)
						{
							std::memcpy(&target, ind.data(), 8);
						}
					}
					else {
						return false;
					}
				}
				else if (a.ins.mnemonic == ZYDIS_MNEMONIC_LEA) {
					if (a.ins.operand_count_visible < 2) return false;
					if (a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
					if (!register_classes_match(a.operands[0].reg.value, jmp_reg)) return false;
					if (a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) return false;
					if (a.operands[1].mem.base != ZYDIS_REGISTER_RIP) return false;
					uint64_t computed = 0;
					if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&a.ins, &a.operands[1],
						a.va, &computed)))
					{
						return false;
					}
					target = computed;
				}
				else {
					return false;
				}
				if (target == 0 && iat_va == 0) return false;
				r.is_thunk = true;
				r.thunk_target = target;
				r.thunk_iat_va = iat_va;
				r.thunk_target_name = lookup_thunk_target_name(target, iat_va);
				return true;
			}
			if (n == 3) {
				const auto& a = decoded_seq[0];
				const auto& b = decoded_seq[1];
				const auto& c = decoded_seq[2];
				if (b.ins.mnemonic != ZYDIS_MNEMONIC_NOP) return false;
				if (c.ins.mnemonic != ZYDIS_MNEMONIC_JMP) return false;
				if (a.ins.mnemonic != ZYDIS_MNEMONIC_MOV) return false;
				if (a.ins.operand_count_visible < 2) return false;
				if (c.ins.operand_count_visible == 0) return false;
				const auto& cop0 = c.operands[0];
				if (cop0.type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
				ZydisRegister jmp_reg = cop0.reg.value;
				if (a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
				if (!register_classes_match(a.operands[0].reg.value, jmp_reg)) return false;
				if (a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) return false;
				if (a.operands[1].mem.base != ZYDIS_REGISTER_RIP
					|| a.operands[1].mem.index != ZYDIS_REGISTER_NONE)
				{
					return false;
				}
				uint64_t iat_va = 0;
				uint64_t target = 0;
				if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&a.ins, &a.operands[1],
					a.va, &iat_va)))
				{
					return false;
				}
				std::vector<uint8_t> ind;
				if (read_routed_bytes(iat_va, 8, ind) && ind.size() >= 8) {
					std::memcpy(&target, ind.data(), 8);
				}
				if (target == 0 && iat_va == 0) return false;
				r.is_thunk = true;
				r.thunk_target = target;
				r.thunk_iat_va = iat_va;
				r.thunk_target_name = lookup_thunk_target_name(target, iat_va);
				(void)bytes;
				return true;
			}
			return false;
		}

		inline bool va_in_function_section(uint64_t va, uint64_t func_start, uint64_t func_end) {
			cache_t& c = cache();
			std::shared_lock<std::shared_mutex> lk(c.mutex);
			if (c.cached_module_size == 0) {
				if (va >= func_start && va < func_end + 0x100000) return true;
				return false;
			}
			uint64_t base = c.cached_module_base;
			uint64_t end = base + c.cached_module_size;
			return va >= base && va < end;
		}

		inline bool detect_switch_at(const std::vector<lookback_entry_t>& ring,
			size_t ring_size, size_t ring_pos,
			const ZydisDecodedInstruction& jmp_ins,
			const ZydisDecodedOperand* jmp_operands,
			uint64_t jmp_va, uint64_t func_start, uint64_t func_end,
			switch_table_t& out_sw)
		{
			(void)func_start;
			(void)func_end;
			if (jmp_ins.mnemonic != ZYDIS_MNEMONIC_JMP) return false;
			if (jmp_ins.operand_count_visible < 1) return false;
			const auto& jop = jmp_operands[0];
			ZydisRegister disp_reg = ZYDIS_REGISTER_NONE;
			ZydisRegister disp_index = ZYDIS_REGISTER_NONE;
			uint8_t       disp_scale = 0;
			int64_t       disp_imm = 0;
			bool          mem_indirect = false;
			bool          reg_indirect = false;
			ZydisRegister jmp_reg = ZYDIS_REGISTER_NONE;
			if (jop.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				mem_indirect = true;
				disp_reg = jop.mem.base;
				disp_index = jop.mem.index;
				disp_scale = static_cast<uint8_t>(jop.mem.scale);
				disp_imm = jop.mem.disp.value;
			}
			else if (jop.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				reg_indirect = true;
				jmp_reg = jop.reg.value;
			}
			else {
				return false;
			}
			if (!mem_indirect && !reg_indirect) return false;

			uint64_t default_addr = 0;
			uint32_t case_count = 0;
			uint64_t base_va = 0;
			uint64_t table_va = 0;
			uint32_t entry_size = 4;
			bool     entries_are_offsets = false;
			ZydisRegister bounds_reg = ZYDIS_REGISTER_NONE;

			size_t step = ring_size;
			if (step > ring.size()) step = ring.size();
			for (size_t k = 0; k < step; ++k) {
				size_t idx = (ring_pos + ring.size() - 1 - k) % ring.size();
				const auto& e = ring[idx];
				if (!e.valid) continue;

				if (e.ins.mnemonic == ZYDIS_MNEMONIC_JNBE
					|| e.ins.mnemonic == ZYDIS_MNEMONIC_JNB
					|| e.ins.mnemonic == ZYDIS_MNEMONIC_JBE
					|| e.ins.mnemonic == ZYDIS_MNEMONIC_JB)
				{
					if (e.ins.operand_count_visible >= 1
						&& e.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& e.operands[0].imm.is_relative)
					{
						uint64_t da = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&e.ins, &e.operands[0],
							e.va, &da)))
						{
							if (default_addr == 0) default_addr = da;
						}
					}
				}

				if (e.ins.mnemonic == ZYDIS_MNEMONIC_CMP
					&& e.ins.operand_count_visible >= 2)
				{
					if (e.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& e.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& !e.operands[1].imm.is_relative)
					{
						uint32_t imm_count = static_cast<uint32_t>(e.operands[1].imm.value.u);
						if (imm_count > 0 && imm_count <= 4096) {
							case_count = imm_count + 1;
							bounds_reg = e.operands[0].reg.value;
						}
					}
				}

				if ((e.ins.mnemonic == ZYDIS_MNEMONIC_LEA
					|| e.ins.mnemonic == ZYDIS_MNEMONIC_MOV)
					&& e.ins.operand_count_visible >= 2)
				{
					if (e.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& e.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						&& e.operands[1].mem.base == ZYDIS_REGISTER_RIP
						&& e.operands[1].mem.index == ZYDIS_REGISTER_NONE)
					{
						uint64_t computed = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&e.ins, &e.operands[1],
							e.va, &computed)))
						{
							if (table_va == 0) table_va = computed;
							if (base_va == 0) base_va = computed;
						}
					}
				}

				if ((e.ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD
					|| e.ins.mnemonic == ZYDIS_MNEMONIC_MOV)
					&& e.ins.operand_count_visible >= 2)
				{
					if (e.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						&& e.operands[1].mem.base != ZYDIS_REGISTER_NONE
						&& e.operands[1].mem.index != ZYDIS_REGISTER_NONE)
					{
						entries_are_offsets =
							(e.ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD
								|| e.operands[1].size == 32);
						if (e.operands[1].size == 32) entry_size = 4;
						else if (e.operands[1].size == 64) entry_size = 8;
					}
				}
			}

			if (case_count == 0) return false;
			if (table_va == 0 && mem_indirect && jop.mem.base == ZYDIS_REGISTER_RIP) {
				uint64_t computed = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&jmp_ins, &jop, jmp_va, &computed))) {
					table_va = computed;
					base_va = computed;
					if (jop.size == 64) {
						entry_size = 8;
						entries_are_offsets = false;
					}
					else {
						entry_size = 4;
						entries_are_offsets = false;
					}
				}
			}
			if (table_va == 0) return false;
			if (case_count > 4096) return false;
			if (entry_size != 4 && entry_size != 8) return false;

			std::vector<uint8_t> tbl;
			size_t needed = static_cast<size_t>(case_count) * entry_size;
			if (!read_routed_bytes(table_va, needed, tbl)) return false;
			if (tbl.size() < needed) return false;

			std::vector<uint64_t> case_addrs;
			case_addrs.reserve(case_count);
			for (uint32_t i = 0; i < case_count; ++i) {
				uint64_t case_va = 0;
				if (entry_size == 4) {
					int32_t v = 0;
					std::memcpy(&v, tbl.data() + i * 4, 4);
					if (entries_are_offsets) {
						case_va = base_va + static_cast<uint64_t>(static_cast<int64_t>(v));
					}
					else {
						case_va = static_cast<uint64_t>(static_cast<uint32_t>(v));
					}
				}
				else {
					uint64_t v = 0;
					std::memcpy(&v, tbl.data() + i * 8, 8);
					case_va = entries_are_offsets ? (base_va + v) : v;
				}
				if (case_va == 0) return false;
				if (!va_in_function_section(case_va, func_start, func_end)) return false;
				case_addrs.push_back(case_va);
			}

			out_sw.jmp_va = jmp_va;
			out_sw.base_va = base_va;
			out_sw.table_va = table_va;
			out_sw.entry_size = entry_size;
			out_sw.entries_are_offsets = entries_are_offsets;
			out_sw.default_addr = default_addr;
			out_sw.case_addrs = std::move(case_addrs);
			(void)disp_reg;
			(void)disp_index;
			(void)disp_scale;
			(void)disp_imm;
			(void)bounds_reg;
			(void)jmp_reg;
			return true;
		}

		inline void scan_function_body(func_record_t& r, const std::string& mod_name) {
			if (r.end <= r.start) return;
			size_t span = static_cast<size_t>(r.end - r.start);
			if (span > 0x100000) span = 0x100000;

			std::vector<uint8_t> bytes;
			if (!read_routed_bytes(r.start, span, bytes)) return;
			if (bytes.empty()) return;

			auto& decoder_contexts = zydis_detail::contexts();
			if (!decoder_contexts.ready) return;
			auto workspace = aida::analysis::workspace_registry().selected_for_ui();
			const bool is_64_bit = workspace && workspace->identity().architecture() ==
				aida::analysis::architecture_id_t::x86_64;
			ZydisDecoder& dec = is_64_bit
				? decoder_contexts.decoder64 : decoder_contexts.decoder32;

			std::unordered_map<int64_t, var_slot_t> var_map;
			std::unordered_set<uint64_t> branch_targets;
			std::unordered_set<uint64_t> ret_addrs;
			std::vector<uint64_t> call_targets;
			std::vector<lookback_entry_t> decoded_seq;
			decoded_seq.reserve(8);

			constexpr size_t kRingSize = 12;
			std::vector<lookback_entry_t> ring(kRingSize);
			size_t ring_pos = 0;

			sp_tracker_state_t sp;

			uint64_t last_insn_addr = r.start;
			uint32_t decoded_since_yield = 0;

			size_t off = 0;
			size_t insn_count = 0;
			while (off < bytes.size()) {
				size_t avail = bytes.size() - off;
				if (avail > 15) avail = 15;
				ZydisDecodedInstruction ins;
				ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
				if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes.data() + off,
					avail, &ins, operands)))
				{
					off += 1;
					continue;
				}

				if (++decoded_since_yield >= 4096) {
					decoded_since_yield = 0;
					std::this_thread::sleep_for(std::chrono::microseconds(50));
				}

				uint64_t va = r.start + off;
				last_insn_addr = va;
				++insn_count;

				if (insn_count <= 4) {
					lookback_entry_t le;
					le.va = va;
					le.ins = ins;
					std::memcpy(le.operands, operands, sizeof(operands));
					le.valid = true;
					decoded_seq.push_back(le);
				}

				lookback_entry_t& slot = ring[ring_pos];
				slot.va = va;
				slot.ins = ins;
				std::memcpy(slot.operands, operands, sizeof(operands));
				slot.valid = true;
				ring_pos = (ring_pos + 1) % kRingSize;

				if (ins.meta.category == ZYDIS_CATEGORY_RET) {
					ret_addrs.insert(va);
				}

				if (!sp.sp_failed) {
					if (ins.mnemonic == ZYDIS_MNEMONIC_PUSH) {
						sp.had_sp_op = true;
						sp.sp_delta -= 8;
						if (sp.sp_delta < sp.min_sp_delta) sp.min_sp_delta = sp.sp_delta;
						if (ins.operand_count_visible >= 1
							&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
						{
							std::string nm = canonical_register_name(operands[0].reg.value);
							if (!nm.empty()) {
								sp.saved_reg_at_offset[sp.sp_delta] = nm;
								if (!sp.saw_call_or_branch && is_callee_saved_gp(operands[0].reg.value)) {
									std::string ovr = "push";
									r.insn_kind_override[va] = ovr;
								}
							}
						}
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_POP) {
						sp.had_sp_op = true;
						if (ins.operand_count_visible >= 1
							&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
						{
							std::string nm = canonical_register_name(operands[0].reg.value);
							auto it = sp.saved_reg_at_offset.find(sp.sp_delta);
							if (it != sp.saved_reg_at_offset.end() && it->second == nm
								&& !nm.empty())
							{
								r.insn_kind_override[va] = std::string("r_") + nm;
							}
							sp.saved_reg_at_offset.erase(sp.sp_delta);
						}
						sp.sp_delta += 8;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_SUB
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& is_rsp_family(operands[0].reg.value)
						&& operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& !operands[1].imm.is_relative)
					{
						sp.had_sp_op = true;
						int64_t imm = static_cast<int64_t>(operands[1].imm.value.s);
						if (sp.have_chkstk_pending) {
							sp.have_chkstk_pending = false;
						}
						else {
							sp.sp_delta -= imm;
							if (!sp.saw_call_or_branch) {
								sp.prologue_locals_size += imm;
							}
						}
						if (sp.sp_delta < sp.min_sp_delta) sp.min_sp_delta = sp.sp_delta;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_ADD
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& is_rsp_family(operands[0].reg.value)
						&& operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& !operands[1].imm.is_relative)
					{
						sp.had_sp_op = true;
						int64_t imm = static_cast<int64_t>(operands[1].imm.value.s);
						sp.sp_delta += imm;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_LEA
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& is_rsp_family(operands[0].reg.value)
						&& operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
						&& is_rsp_family(operands[1].mem.base)
						&& operands[1].mem.index == ZYDIS_REGISTER_NONE)
					{
						sp.had_sp_op = true;
						int64_t disp = operands[1].mem.disp.value;
						sp.sp_delta += disp;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_LEAVE) {
						sp.had_sp_op = true;
						auto it = sp.saved_reg_at_offset.find(sp.sp_delta);
						if (it != sp.saved_reg_at_offset.end()) {
							sp.saved_reg_at_offset.erase(it);
						}
						sp.sp_delta = 0;
						sp.bp_assigned_from_sp = false;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_ENTER
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
					{
						sp.had_sp_op = true;
						sp.sp_delta -= 8;
						sp.saved_reg_at_offset[sp.sp_delta] = "rbp";
						sp.bp_assigned_from_sp = true;
						int64_t imm = static_cast<int64_t>(operands[0].imm.value.s);
						sp.sp_delta -= imm;
						if (!sp.saw_call_or_branch) sp.prologue_locals_size += imm;
						if (sp.sp_delta < sp.min_sp_delta) sp.min_sp_delta = sp.sp_delta;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_MOV
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& is_rsp_family(operands[0].reg.value))
					{
						if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
							&& !is_rsp_family(operands[1].reg.value))
						{
							sp.sp_failed = true;
						}
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_MOV
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& canonical_register_name(operands[0].reg.value) == "rax"
						&& operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
						&& !operands[1].imm.is_relative
						&& !sp.saw_call_or_branch)
					{
						sp.chkstk_pending_imm = static_cast<int64_t>(operands[1].imm.value.s);
						sp.have_chkstk_pending = true;
					}
					else if (ins.mnemonic == ZYDIS_MNEMONIC_MOV
						&& ins.operand_count_visible >= 2
						&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& canonical_register_name(operands[0].reg.value) == "rbp"
						&& operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
						&& is_rsp_family(operands[1].reg.value))
					{
						sp.bp_assigned_from_sp = true;
					}
				}

				if (ins.meta.category == ZYDIS_CATEGORY_CALL) {
					if (ins.operand_count_visible >= 1) {
						const auto& op = operands[0];
						if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
							uint64_t tgt = 0;
							if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, va, &tgt))) {
								call_targets.push_back(tgt);
								if (target_is_noreturn(tgt, 0)) {
									r.noreturn_call_addrs.insert(va);
								}
								if (sp.have_chkstk_pending) {
									std::string near_name = resolve_live_debugger_name_nearest(tgt);
									if (!near_name.empty()
										&& near_name.find("chkstk") != std::string::npos)
									{
										sp.sp_delta -= sp.chkstk_pending_imm;
										if (!sp.saw_call_or_branch) {
											sp.prologue_locals_size += sp.chkstk_pending_imm;
										}
										if (sp.sp_delta < sp.min_sp_delta) {
											sp.min_sp_delta = sp.sp_delta;
										}
									}
									sp.have_chkstk_pending = false;
								}
							}
						}
						else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
							uint64_t target = 0;
							uint64_t iat_va = 0;
							if (resolve_call_target(ins, operands, va, target, iat_va)) {
								if (target != 0) call_targets.push_back(target);
								if (target_is_noreturn(target, iat_va)) {
									r.noreturn_call_addrs.insert(va);
								}
							}
						}
						else {
							sp.have_chkstk_pending = false;
						}
					}

					const prototype_entry_t* proto = lookup_prototype_for_call(ins, operands, va);
					if (proto != nullptr) {
						bool reg_seen[4] = { false, false, false, false };
						for (size_t step = 1; step <= kRingSize; ++step) {
							size_t idx = (ring_pos + kRingSize - 1 - step) % kRingSize;
							const lookback_entry_t& prev = ring[idx];
							if (!prev.valid) continue;
							if (prev.va == va) continue;
							const ZydisDecodedInstruction& pins = prev.ins;
							if (pins.meta.category == ZYDIS_CATEGORY_CALL) break;
							if (pins.meta.category == ZYDIS_CATEGORY_RET) break;
							if (pins.operand_count_visible == 0) continue;
							const ZydisDecodedOperand& dst = prev.operands[0];
							if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
								int aidx = x64_arg_register_index(dst.reg.value);
								if (aidx >= 0 && aidx < 4 && !reg_seen[aidx]) {
									reg_seen[aidx] = true;
									const char* pname = prototype_param_name(*proto,
										static_cast<size_t>(aidx));
									if (pname && *pname && r.inline_comments.find(prev.va)
										== r.inline_comments.end())
									{
										r.inline_comments[prev.va] = std::string(pname);
									}
								}
							}
							else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY
								&& pins.mnemonic == ZYDIS_MNEMONIC_MOV
								&& is_rsp_family(dst.mem.base)
								&& dst.mem.index == ZYDIS_REGISTER_NONE
								&& dst.mem.disp.has_displacement
								&& !sp.sp_failed)
							{
								int64_t pdisp = dst.mem.disp.value;
								if (pdisp >= 0x20 && pdisp < 0x200) {
									int64_t slot_index = pdisp / 8;
									if (slot_index >= 4 && slot_index < 12) {
										const char* pname = prototype_param_name(*proto,
											static_cast<size_t>(slot_index));
										if (pname && *pname) {
											auto erit = r.rsp_access_entry_relative.find(prev.va);
											if (erit != r.rsp_access_entry_relative.end()) {
												int64_t entry_off = erit->second;
												r.rsp_access_substitution[prev.va] = pname;
												auto cmtit = r.inline_comments.find(prev.va);
												if (cmtit == r.inline_comments.end()) {
													r.inline_comments[prev.va] = std::string(pname);
												}
												r.prototype_slot_names[entry_off] = pname;
											}
										}
									}
								}
							}
						}
					}

					sp.saw_call_or_branch = true;
				}

				if (ins.meta.category == ZYDIS_CATEGORY_COND_BR
					|| ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR
					|| ins.meta.category == ZYDIS_CATEGORY_CALL)
				{
					for (uint8_t i = 0; i < ins.operand_count_visible; ++i) {
						const auto& op = operands[i];
						if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
						if (!op.imm.is_relative) continue;
						uint64_t tgt = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, va, &tgt))) {
							if (tgt > r.start && tgt < r.end) {
								branch_targets.insert(tgt);
							}
						}
					}
				}

				if (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR
					&& ins.mnemonic == ZYDIS_MNEMONIC_JMP)
				{
					switch_table_t sw;
					if (detect_switch_at(ring, kRingSize, ring_pos, ins, operands, va,
						r.start, r.end, sw))
					{
						char buf[96];
						std::snprintf(buf, sizeof(buf),
							"; switch(%u) cases", static_cast<unsigned>(sw.case_addrs.size()));
						r.inline_comments[va] = std::string(buf);
						for (size_t ci = 0; ci < sw.case_addrs.size(); ++ci) {
							std::string nm = "case_" + std::to_string(ci);
							r.inline_labels[sw.case_addrs[ci]] = std::move(nm);
						}
						if (sw.default_addr != 0) {
							std::string dn = "def_" + format_hex_upper(sw.default_addr);
							r.inline_labels[sw.default_addr] = std::move(dn);
						}
						r.switches.push_back(std::move(sw));
					}
					else if (ins.operand_count_visible >= 1) {
						const auto& jop = operands[0];
						if (jop.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && jop.imm.is_relative) {
							uint64_t jtgt = 0;
							if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &jop, va, &jtgt))) {
								if (jtgt < r.start || jtgt >= r.end) {
									if (target_is_noreturn(jtgt, 0)) {
										r.noreturn_call_addrs.insert(va);
									}
								}
							}
						}
						else if (jop.type == ZYDIS_OPERAND_TYPE_MEMORY) {
							uint64_t target = 0;
							uint64_t iat_va = 0;
							if (resolve_call_target(ins, operands, va, target, iat_va)) {
								if (target_is_noreturn(target, iat_va)) {
									r.noreturn_call_addrs.insert(va);
								}
							}
						}
					}
				}

				bool is_unconditional_branch = (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
				if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || is_unconditional_branch) {
					sp.saw_call_or_branch = true;
				}

				if (ins.mnemonic == ZYDIS_MNEMONIC_PUSH
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOV
					|| ins.mnemonic == ZYDIS_MNEMONIC_LEA
					|| ins.mnemonic == ZYDIS_MNEMONIC_ADD
					|| ins.mnemonic == ZYDIS_MNEMONIC_SUB
					|| ins.mnemonic == ZYDIS_MNEMONIC_CMP
					|| ins.mnemonic == ZYDIS_MNEMONIC_TEST
					|| ins.mnemonic == ZYDIS_MNEMONIC_OR
					|| ins.mnemonic == ZYDIS_MNEMONIC_AND
					|| ins.mnemonic == ZYDIS_MNEMONIC_XOR
					|| ins.mnemonic == ZYDIS_MNEMONIC_INC
					|| ins.mnemonic == ZYDIS_MNEMONIC_DEC
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVZX
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVSX
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD)
				{
					for (uint8_t i = 0; i < ins.operand_count_visible; ++i) {
						const auto& op = operands[i];
						if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
						if (op.mem.type != ZYDIS_MEMOP_TYPE_MEM
							&& op.mem.type != ZYDIS_MEMOP_TYPE_AGEN)
						{
							continue;
						}
						ZydisRegister base = op.mem.base;
						bool is_bp = (base == ZYDIS_REGISTER_RBP
							|| base == ZYDIS_REGISTER_EBP
							|| base == ZYDIS_REGISTER_BP);
						if (is_bp && op.mem.index == ZYDIS_REGISTER_NONE
							&& op.mem.disp.has_displacement)
						{
							int64_t disp = op.mem.disp.value;
							uint32_t sz = operand_size_bytes(op, ins);
							if (sz == 0) sz = 4;

							auto vit = var_map.find(disp);
							if (vit == var_map.end()) {
								var_slot_t v;
								v.offset = disp;
								v.size = sz;
								var_map.emplace(disp, std::move(v));
							}
							else {
								if (sz > vit->second.size) vit->second.size = sz;
							}

							r.bp_based = true;
						}

						if (!sp.sp_failed && is_rsp_family(base)
							&& op.mem.index == ZYDIS_REGISTER_NONE
							&& op.mem.disp.has_displacement)
						{
							int64_t disp = op.mem.disp.value;
							int64_t entry_relative = sp.sp_delta + disp;
							std::string label;
							if (entry_relative >= 0x08) {
								int64_t arg_idx = entry_relative - 0x08;
								char b[40];
								std::snprintf(b, sizeof(b), "arg_%llX",
									static_cast<unsigned long long>(arg_idx));
								label = b;
							}
							else if (entry_relative < 0) {
								auto sit = sp.saved_reg_at_offset.find(entry_relative);
								if (sit != sp.saved_reg_at_offset.end()) {
									label = std::string("s_") + sit->second;
								}
								else {
									char b[40];
									std::snprintf(b, sizeof(b), "var_%llX",
										static_cast<unsigned long long>(-entry_relative));
									label = b;
								}
							}

							if (!label.empty()) {
								r.rsp_access_substitution[va] = label;
								r.rsp_access_entry_relative[va] = entry_relative;
								r.rsp_access_abs_offset[va] = -sp.sp_delta;
							}
						}
					}
				}

				off += ins.length;
			}

			r.entry_to_exit_sp_delta = sp.sp_delta;
			r.prologue_locals_size = static_cast<uint64_t>(sp.prologue_locals_size > 0
				? sp.prologue_locals_size : 0);
			if (sp.sp_failed) {
				r.sp_analysis_failed = true;
				r.sp_based = false;
			}
			else if (sp.had_sp_op && !sp.bp_assigned_from_sp) {
				r.sp_based = true;
			}

			if (!r.is_thunk) {
				detect_thunk(r, bytes, decoded_seq);
			}

			r.call_targets = std::move(call_targets);

			r.ret_addrs = std::move(ret_addrs);
			r.last_insn_addr = last_insn_addr;

			if (!r.prototype_slot_names.empty()) {
				for (auto& kv : r.rsp_access_substitution) {
					auto erit = r.rsp_access_entry_relative.find(kv.first);
					if (erit == r.rsp_access_entry_relative.end()) continue;
					auto pit = r.prototype_slot_names.find(erit->second);
					if (pit == r.prototype_slot_names.end()) continue;
					if (pit->second.empty()) continue;
					kv.second = pit->second;
				}
			}

			std::vector<var_slot_t> vars;
			vars.reserve(var_map.size());
			for (auto& kv : var_map) {
				vars.push_back(std::move(kv.second));
			}
			std::sort(vars.begin(), vars.end(),
				[](const var_slot_t& a, const var_slot_t& b) {
					return a.offset < b.offset;
				});

			for (auto& v : vars) {
				if (v.offset < 0) {
					std::string nm = "var_" + format_hex_upper(static_cast<uint64_t>(-v.offset));
					if (!mod_name.empty()) {
						uint32_t hint = pdb_var_size_hint(mod_name, nm);
						if (hint > 0) v.size = hint;
					}
					v.kind = slot_kind_t::local_var;
					v.name = std::move(nm);
				}
				else if (v.offset > 0) {
					std::string nm = "arg_" + format_hex_upper(static_cast<uint64_t>(v.offset));
					if (!mod_name.empty()) {
						uint32_t hint = pdb_var_size_hint(mod_name, nm);
						if (hint > 0) v.size = hint;
					}
					v.kind = slot_kind_t::stack_arg;
					v.name = std::move(nm);
				}
				else {
					v.kind = slot_kind_t::saved_rbp_zero;
					v.name = "saved_bp";
				}
			}
			r.vars = std::move(vars);

			if (!r.sp_analysis_failed) {
				std::unordered_map<int64_t, uint32_t> rsp_sizes;
				for (const auto& kv : r.rsp_access_entry_relative) {
					int64_t off = kv.second;
					auto sk = sp.saved_reg_at_offset.find(off);
					if (sk != sp.saved_reg_at_offset.end()) continue;
					auto sz_it = rsp_sizes.find(off);
					if (sz_it == rsp_sizes.end()) rsp_sizes.emplace(off, 8u);
				}

				std::unordered_set<int64_t> have;
				for (const auto& v : r.vars) have.insert(v.offset);

				std::vector<var_slot_t> extra;
				extra.reserve(rsp_sizes.size());
				for (const auto& kv : rsp_sizes) {
					int64_t off = kv.first;
					if (have.count(off)) continue;
					var_slot_t v;
					v.offset = off;
					v.size = kv.second;
					auto pit = r.prototype_slot_names.find(off);
					if (pit != r.prototype_slot_names.end() && !pit->second.empty()) {
						v.prototype_name = pit->second;
					}
					if (!v.prototype_name.empty() && off < 0) {
						v.kind = slot_kind_t::local_var;
						v.name = v.prototype_name;
					}
					else if (!v.prototype_name.empty() && off >= 0x20) {
						v.kind = slot_kind_t::stack_arg;
						v.name = v.prototype_name;
					}
					else if (off < 0) {
						v.kind = slot_kind_t::local_var;
						v.name = "var_" + format_hex_upper(static_cast<uint64_t>(-off));
					}
					else if (off >= 0x08) {
						int64_t arg_idx = off - 0x08;
						v.kind = slot_kind_t::stack_arg;
						v.name = "arg_" + format_hex_upper(static_cast<uint64_t>(arg_idx));
					}
					else {
						continue;
					}
					if (!mod_name.empty()) {
						uint32_t hint = pdb_var_size_hint(mod_name, v.name);
						if (hint > 0) v.size = hint;
					}
					extra.push_back(std::move(v));
				}

				if (!extra.empty()) {
					r.vars.insert(r.vars.end(),
						std::make_move_iterator(extra.begin()),
						std::make_move_iterator(extra.end()));
					std::sort(r.vars.begin(), r.vars.end(),
						[](const var_slot_t& a, const var_slot_t& b) {
							return a.offset < b.offset;
						});
				}
			}

			std::vector<label_slot_t> labels;
			labels.reserve(branch_targets.size());
			for (uint64_t t : branch_targets) {
				if (t == r.start) continue;
				label_slot_t ls;
				ls.addr = t;
				ls.is_locret = (r.ret_addrs.find(t) != r.ret_addrs.end());
				labels.push_back(ls);
			}
			std::sort(labels.begin(), labels.end(),
				[](const label_slot_t& a, const label_slot_t& b) {
					return a.addr < b.addr;
				});
			r.labels = std::move(labels);

			std::unordered_map<uint64_t, std::string> existing_inline = std::move(r.inline_labels);
			r.inline_labels.clear();
			r.inline_labels.reserve(r.labels.size() + existing_inline.size());
			for (auto& kv : existing_inline) {
				r.inline_labels.emplace(kv.first, std::move(kv.second));
			}
			for (const auto& ls : r.labels) {
				std::string nm = ls.is_locret
					? std::string("locret_") + format_hex_upper(ls.addr) + ":"
					: std::string("loc_") + format_hex_upper(ls.addr) + ":";
				r.inline_labels.emplace(ls.addr, std::move(nm));
			}

			if (!r.display_name.empty()
				&& r.display_name.rfind("sub_", 0) != 0
				&& r.display_name.rfind("j_", 0) != 0
				&& name_is_library_function(r.display_name))
			{
				r.is_library = true;
			}

			if (!bytes.empty()) {
				size_t fn_span = bytes.size();
				if (r.end > r.start && (r.end - r.start) < fn_span) {
					fn_span = static_cast<size_t>(r.end - r.start);
				}
				if (r.ret_addrs.empty() && !r.noreturn_call_addrs.empty()) {
					r.always_noreturn = true;
				}

				for (uint64_t nc_va : r.noreturn_call_addrs) {
					if (nc_va < r.start || nc_va >= r.end) continue;
					size_t nc_off = static_cast<size_t>(nc_va - r.start);
					if (nc_off >= fn_span) continue;
					ZydisDecodedInstruction nins;
					ZydisDecodedOperand nops[ZYDIS_MAX_OPERAND_COUNT];
					size_t avail = fn_span - nc_off;
					if (avail > 15) avail = 15;
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,
						bytes.data() + nc_off, avail, &nins, nops)))
					{
						continue;
					}
					size_t after_off = nc_off + nins.length;
					size_t pad_start = after_off;
					size_t pad_end = pad_start;
					while (pad_end < fn_span && bytes[pad_end] == 0xCC) {
						++pad_end;
					}
					if (pad_end == pad_start) continue;

					uint64_t pad_start_va = r.start + static_cast<uint64_t>(pad_start);
					uint64_t pad_end_va   = r.start + static_cast<uint64_t>(pad_end);

					std::vector<uint8_t> lookahead_bytes;
					bool lookahead_loaded = false;
					if (pad_end_va > r.end) {
						read_routed_bytes(pad_end_va, 16, lookahead_bytes);
						lookahead_loaded = !lookahead_bytes.empty();
					}

					for (uint64_t cur = pad_start_va; cur < pad_end_va; ++cur) {
						uint64_t one_va = cur;
						uint64_t next_byte_va = cur + 1;
						bool next_is_cc = false;
						if (next_byte_va < pad_end_va) {
							next_is_cc = true;
						}
						else {
							size_t lookahead_off = static_cast<size_t>(next_byte_va - r.start);
							if (lookahead_off < bytes.size() && bytes[lookahead_off] == 0xCC) {
								next_is_cc = true;
							}
							else if (lookahead_loaded && next_byte_va >= pad_end_va) {
								size_t ext_off = static_cast<size_t>(next_byte_va - pad_end_va);
								if (ext_off < lookahead_bytes.size()
									&& lookahead_bytes[ext_off] == 0xCC)
								{
									next_is_cc = true;
								}
							}
						}
						directive_override_t ov;
						if (next_is_cc) {
							ov.kind = directive_kind_t::db;
							ov.value = 0xCC;
						}
						else {
							uint8_t a = pick_intra_align(next_byte_va, 1);
							if (a >= 2) {
								ov.kind = directive_kind_t::align;
								ov.value = a;
							}
							else {
								ov.kind = directive_kind_t::db;
								ov.value = 0xCC;
							}
						}
						r.directive_overrides[one_va] = ov;
					}
				}
			}
		}

		inline void build_before_after(func_record_t& r) {
			r.before_first_insn.clear();
			r.after_last_insn.clear();

			injection_row_t banner;
			banner.kind = injection_t::function_banner;
			banner.addr = r.start;
			banner.text =
				"; =============== S U B R O U T I N E =======================================";
			r.before_first_insn.push_back(std::move(banner));

			injection_row_t sp1;
			sp1.kind = injection_t::spacer_line;
			sp1.addr = r.start;
			r.before_first_insn.push_back(sp1);

			injection_row_t sp2 = sp1;
			r.before_first_insn.push_back(sp2);

			std::string attrs;
			auto append_attr = [&](const char* token) {
				if (!attrs.empty()) attrs += ' ';
				attrs += token;
			};
			if (r.bp_based) append_attr("bp-based frame");
			if (r.always_noreturn) append_attr("noreturn");
			if (r.is_thunk) append_attr("thunk");
			if (r.is_library) append_attr("library function");

			if (!attrs.empty()) {
				injection_row_t attr;
				attr.kind = injection_t::attributes_line;
				attr.addr = r.start;
				attr.text = "; Attributes: " + attrs;
				r.before_first_insn.push_back(std::move(attr));

				injection_row_t sp_after_attr = sp1;
				r.before_first_insn.push_back(sp_after_attr);
			}

			injection_row_t header;
			header.kind = injection_t::proc_header;
			header.addr = r.start;
			std::string name_padded = pad_right(r.display_name, 16);
			header.text = name_padded + "proc near";
			r.before_first_insn.push_back(std::move(header));

			injection_row_t sp_after_header = sp1;
			r.before_first_insn.push_back(sp_after_header);

			if (!r.vars.empty()) {
				for (const auto& v : r.vars) {
					injection_row_t row;
					row.kind = injection_t::var_decl;
					row.addr = r.start;
					std::string n_padded = pad_right(v.name, 16);
					std::string ptr_word = ptr_word_for_size(v.size);
					std::string disp = format_signed_hex(v.offset);
					row.text = n_padded + "= " + ptr_word + " " + disp;
					r.before_first_insn.push_back(std::move(row));
				}
				injection_row_t sp_after_vars = sp1;
				r.before_first_insn.push_back(sp_after_vars);
			}

			injection_row_t endp;
			endp.kind = injection_t::proc_endp;
			endp.addr = r.end;
			std::string name_padded2 = pad_right(r.display_name, 16);
			if (r.sp_analysis_failed) {
				endp.text = name_padded2 + "endp ; sp-analysis failed";
			}
			else {
				endp.text = name_padded2 + "endp";
			}
			r.after_last_insn.push_back(std::move(endp));

			injection_row_t sp_after_endp;
			sp_after_endp.kind = injection_t::spacer_line;
			sp_after_endp.addr = r.end;
			r.after_last_insn.push_back(sp_after_endp);

			injection_row_t sep;
			sep.kind = injection_t::endp_separator;
			sep.addr = r.end;
			sep.text =
				"; ---------------------------------------------------------------------------";
			r.after_last_insn.push_back(std::move(sep));
		}

		inline void schedule_function_build(uint64_t func_start,
			std::shared_ptr<func_status_t> status,
			const std::string& mod_name)
		{
			if (!status) return;
			uint32_t expected = static_cast<uint32_t>(func_state_t::idle);
			if (!status->state.compare_exchange_strong(expected,
				static_cast<uint32_t>(func_state_t::building),
				std::memory_order_acq_rel))
			{
				return;
			}

			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "disasm";
			sub.label = "disasm.function_index.build_function";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::feature_worker;
			sub.priority = 2;
			sub.body = [func_start, status, mod_name]() {
				bool live = (driver_bridge::attached_pid() != 0);
				bool static_loaded = static_pe_active();
				if (!live && !static_loaded) {
					status->state.store(static_cast<uint32_t>(func_state_t::idle),
						std::memory_order_release);
					return;
				}

				cache_t& c = cache();
				func_record_t snapshot;
				{
					std::shared_lock<std::shared_mutex> lk(c.mutex);
					auto it = c.by_start.find(func_start);
					if (it == c.by_start.end()) {
						status->state.store(static_cast<uint32_t>(func_state_t::failed),
							std::memory_order_release);
						return;
					}
					snapshot.start = it->second.start;
					snapshot.end = it->second.end;
					snapshot.section = it->second.section;
					snapshot.display_name = it->second.display_name;
				}

				snapshot.last_insn_addr = snapshot.start;
				if (snapshot.display_name.empty()
					|| snapshot.display_name.rfind("sub_", 0) == 0)
				{
					snapshot.display_name = resolve_display_name(snapshot.start);
				}

				scan_function_body(snapshot, mod_name);
				build_before_after(snapshot);

				{
					std::unique_lock<std::shared_mutex> lk(c.mutex);
					auto it = c.by_start.find(func_start);
					if (it == c.by_start.end()) {
						status->state.store(static_cast<uint32_t>(func_state_t::failed),
							std::memory_order_release);
						return;
					}
					it->second.bp_based = snapshot.bp_based;
					it->second.sp_analysis_failed = snapshot.sp_analysis_failed;
					it->second.sp_based = snapshot.sp_based;
					it->second.entry_to_exit_sp_delta = snapshot.entry_to_exit_sp_delta;
					it->second.prologue_locals_size = snapshot.prologue_locals_size;
					it->second.rsp_access_substitution = std::move(snapshot.rsp_access_substitution);
					it->second.rsp_access_entry_relative = std::move(snapshot.rsp_access_entry_relative);
					it->second.rsp_access_abs_offset = std::move(snapshot.rsp_access_abs_offset);
					it->second.prototype_slot_names = std::move(snapshot.prototype_slot_names);
					it->second.insn_kind_override = std::move(snapshot.insn_kind_override);
					it->second.is_thunk = snapshot.is_thunk;
					it->second.thunk_target = snapshot.thunk_target;
					it->second.thunk_iat_va = snapshot.thunk_iat_va;
					it->second.thunk_target_name = snapshot.thunk_target_name;
					it->second.switches = std::move(snapshot.switches);
					it->second.inline_comments = std::move(snapshot.inline_comments);
					it->second.call_targets = std::move(snapshot.call_targets);
					it->second.vars = std::move(snapshot.vars);
					it->second.labels = std::move(snapshot.labels);
					it->second.ret_addrs = std::move(snapshot.ret_addrs);
					it->second.last_insn_addr = snapshot.last_insn_addr;
					it->second.inline_labels = std::move(snapshot.inline_labels);
					it->second.before_first_insn = std::move(snapshot.before_first_insn);
					it->second.after_last_insn = std::move(snapshot.after_last_insn);
					it->second.noreturn_call_addrs = std::move(snapshot.noreturn_call_addrs);
					it->second.directive_overrides = std::move(snapshot.directive_overrides);
					it->second.always_noreturn = snapshot.always_noreturn;
					it->second.is_library = snapshot.is_library;
					std::string final_name = snapshot.display_name;
					if (it->second.is_thunk
						&& resolve_live_debugger_name_exact(func_start).empty()
						&& !it->second.thunk_target_name.empty())
					{
						final_name = std::string("j_") + it->second.thunk_target_name;
					}
					it->second.display_name = final_name;
					c.synthetic_names[func_start] = final_name;
				}

				status->state.store(static_cast<uint32_t>(func_state_t::built),
					std::memory_order_release);
				c.built_seq.fetch_add(1u, std::memory_order_acq_rel);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted) {
				status->state.store(static_cast<uint32_t>(func_state_t::failed),
					std::memory_order_release);
			}
		}

		inline void schedule_bounds_rebuild() {
			cache_t& c = cache();
			uint32_t cur = c.bounds_state.load(std::memory_order_acquire);
			if (cur == static_cast<uint32_t>(bounds_state_t::building)) return;

			uint32_t expected = cur;
			if (!c.bounds_state.compare_exchange_strong(expected,
				static_cast<uint32_t>(bounds_state_t::building),
				std::memory_order_acq_rel))
			{
				return;
			}

			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "disasm";
			sub.label = "disasm.function_index.bounds_rebuild";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::feature_worker;
			sub.priority = 2;
			sub.body = []() {
				cache_t& c2 = cache();
				bool live = (driver_bridge::attached_pid() != 0);
				if (!live) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::idle),
						std::memory_order_release);
					return;
				}

				uint64_t base = 0;
				uint32_t size = 0;
				std::string name;
				uint64_t pid_token = 0;
				if (!fetch_active_module(base, size, name)) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::failed),
						std::memory_order_release);
					return;
				}
				pid_token = static_cast<uint64_t>(driver_bridge::attached_pid())
					^ (static_cast<uint64_t>(size) << 32);

				bool same = false;
				{
					std::shared_lock<std::shared_mutex> lk(c2.mutex);
					same = (c2.cached_module_base == base
						&& c2.cached_module_size == size
						&& c2.cached_pid_token == pid_token
						&& !c2.sorted_starts.empty());
				}
				if (same) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::ready),
						std::memory_order_release);
					return;
				}

				const uint64_t t_rebuild_start_ns = static_cast<uint64_t>(
					std::chrono::duration_cast<std::chrono::nanoseconds>(
						std::chrono::steady_clock::now().time_since_epoch()).count());
				rebuild_bounds_index(base, size, name);
				const uint64_t t_rebuild_end_ns = static_cast<uint64_t>(
					std::chrono::duration_cast<std::chrono::nanoseconds>(
						std::chrono::steady_clock::now().time_since_epoch()).count());
				{
					char log_buf[256];
					size_t func_count = 0;
					{
						std::shared_lock<std::shared_mutex> lk(c2.mutex);
						func_count = c2.sorted_starts.size();
					}
					std::snprintf(log_buf, sizeof(log_buf),
						"phase=rebuild_bounds_index live=%d elapsed_ms=%llu funcs=%zu name=%s",
						live ? 1 : 0,
						static_cast<unsigned long long>((t_rebuild_end_ns - t_rebuild_start_ns) / 1000000ull),
						func_count,
						name.c_str());
					diag::log_tagged("function_index", log_buf);
					diag::log_tagged("function_index", log_buf);
				}
				{
					std::unique_lock<std::shared_mutex> lk(c2.mutex);
					c2.cached_pid_token = pid_token;
				}
				c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::ready),
					std::memory_order_release);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				c.bounds_state.store(static_cast<uint32_t>(bounds_state_t::failed),
					std::memory_order_release);
		}

		inline void reset_all() {
			cache_t& c = cache();
			{
				std::unique_lock<std::shared_mutex> lk(c.mutex);
				c.by_start.clear();
				c.status_by_start.clear();
				c.addr_to_func_start.clear();
				c.sorted_starts.clear();
				c.synthetic_names.clear();
				c.align_runs_by_start.clear();
				c.align_run_starts.clear();
				c.iat_lookup.clear();
				c.data_symbol_lookup.clear();
				c.text_blob.clear();
				c.text_blob_va = 0;
				c.cached_module_base = 0;
				c.cached_module_size = 0;
				c.cached_module_name.clear();
				c.cached_pid_token = 0;
				c.cached_entry_point = 0;
				c.cached_subsystem = 0;
				c.cached_characteristics = 0;
			}
			c.bounds_state.store(static_cast<uint32_t>(bounds_state_t::idle),
				std::memory_order_release);

			cached_module_table_t& t = cached_module_table();
			{
				std::scoped_lock<std::shared_mutex> w(t.mu);
				t.pid = 0;
				t.entries.clear();
			}
			t.last_built_ms.store(0, std::memory_order_release);
		}

	}

	inline std::string synthetic_name(uint64_t addr) {
		std::string name = resolve_live_debugger_name_exact(addr);
		if (!name.empty()) return detail::strip_module_prefix(name);

		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.synthetic_names.find(addr);
		if (it != c.synthetic_names.end() && !it->second.empty()) return it->second;
		return detail::make_synthetic_sub(addr);
	}

	inline std::string iat_symbol_at(uint64_t va) {
		if (va == 0) return std::string();
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.iat_lookup.find(va);
		if (it == c.iat_lookup.end()) return std::string();
		return it->second.function_name;
	}

	inline bool iat_entry_at(uint64_t va, std::string& out_module, std::string& out_function) {
		out_module.clear();
		out_function.clear();
		if (va == 0) return false;
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.iat_lookup.find(va);
		if (it == c.iat_lookup.end()) return false;
		out_module = it->second.module_name;
		out_function = it->second.function_name;
		return !out_function.empty();
	}

	inline std::string data_symbol_at(uint64_t va) {
		if (va == 0) return std::string();
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.data_symbol_lookup.find(va);
		if (it == c.data_symbol_lookup.end()) return std::string();
		return it->second.name;
	}

	inline bool data_symbol_entry_at(uint64_t va, std::string& out_name, bool& out_is_function) {
		out_name.clear();
		out_is_function = false;
		if (va == 0) return false;
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.data_symbol_lookup.find(va);
		if (it == c.data_symbol_lookup.end()) return false;
		out_name = it->second.name;
		out_is_function = it->second.is_function;
		return !out_name.empty();
	}

	inline bool static_bulk_in_progress() {
		for (const auto& workspace : aida::analysis::workspace_registry().list()) {
			if (!workspace || workspace->target_kind() !=
				aida::analysis::target_kind_t::static_file ||
				workspace->closing() || workspace->closed())
				continue;
			const auto progress = workspace->progress();
			if (progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
				progress.readiness == aida::analysis::workspace_readiness_t::cancelling)
				return true;
		}
		return false;
	}

	inline std::vector<injection_row_t> rows_before(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		std::vector<injection_row_t> rows;
		auto normalized = normalize_workspace_address(workspace, address);
		if (!normalized || !workspace) return rows;
		auto publication = workspace->analysis_publication();
		if (!publication || !publication->snapshot ||
			publication->generation != workspace->generation())
			return rows;
		const function_record_t* function = nullptr;
		const auto indexes = aida::analysis::publication_indexes::for_publication(
			publication, {});
		if (indexes)
			function = indexes->function_at_exact_start(normalized.value());
		if (!function) return rows;
		const uint64_t display_address = workspace_display_address(
			workspace, function->start);
		const uint64_t row_address = display_address != 0
			? display_address : function->start.value;
		const auto names = workspace_name_snapshot(workspace);
		std::string display_name = resolve_workspace_name_exact(names, function->start);
		std::string signature;
		if (auto overlay = workspace->overlay()) {
			const auto overlay_snapshot = overlay->snapshot();
			if (overlay_snapshot.revision == workspace->overlay_revision()) {
				for (const auto& item : overlay_snapshot.items) {
					const auto& operation = item.second;
					auto operation_address = normalize_workspace_address(
						workspace, operation.address);
					if (!operation_address ||
						operation_address.value().space != function->start.space ||
						operation_address.value().value != function->start.value)
						continue;
					if (operation.kind == overlay_operation_kind_t::type_application &&
						signature.empty() && !operation.signature.empty())
						signature = operation.signature;
				}
			}
		}
		if (display_name.empty())
			display_name = synthetic_name(workspace, function->start);
		rows.push_back(injection_row_t{injection_t::function_banner,
			"; =============== S U B R O U T I N E =======================================",
			row_address});
		rows.push_back(injection_row_t{injection_t::spacer_line, {}, row_address});
		rows.push_back(injection_row_t{injection_t::spacer_line, {}, row_address});
		std::string attributes;
		if (function->noreturn) attributes = "noreturn";
		if (function->thunk) {
			if (!attributes.empty()) attributes += ' ';
			attributes += "thunk";
		}
		if (!attributes.empty()) {
			rows.push_back(injection_row_t{injection_t::attributes_line,
				"; Attributes: " + attributes, row_address});
			rows.push_back(injection_row_t{injection_t::spacer_line, {}, row_address});
		}
		if (!signature.empty()) {
			rows.push_back(injection_row_t{injection_t::prototype_line,
				signature, row_address});
			rows.push_back(injection_row_t{injection_t::spacer_line, {}, row_address});
		}
		rows.push_back(injection_row_t{injection_t::proc_header,
			detail::pad_right(display_name, 16) + "proc near", row_address});
		rows.push_back(injection_row_t{injection_t::spacer_line, {}, row_address});
		return rows;
	}

	inline std::string inline_label_at(uint64_t addr) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto sit = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
		if (sit == c.sorted_starts.begin()) return std::string();
		--sit;
		uint64_t func_start = *sit;
		if (addr == func_start) return std::string();
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return std::string();
		const auto& rec = it->second;
		if (addr < rec.start || addr >= rec.end) return std::string();
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return std::string();
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return std::string();
		}
		auto lit = rec.inline_labels.find(addr);
		if (lit == rec.inline_labels.end()) return std::string();
		return lit->second;
	}

	inline uint64_t func_start_for(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return 0;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return 0;
		--it;
		uint64_t start = *it;
		auto rit = c.by_start.find(start);
		if (rit == c.by_start.end()) return 0;
		if (va < rit->second.start || va >= rit->second.end) return 0;
		return start;
	}

	inline uint64_t func_end_for(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return 0;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return 0;
		--it;
		uint64_t start = *it;
		auto rit = c.by_start.find(start);
		if (rit == c.by_start.end()) return 0;
		if (va < rit->second.start || va >= rit->second.end) return 0;
		return rit->second.end;
	}

	inline bool func_extent(uint64_t va, uint64_t* out_start, uint64_t* out_end) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return false;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return false;
		--it;
		uint64_t start = *it;
		auto rit = c.by_start.find(start);
		if (rit == c.by_start.end()) return false;
		if (va < rit->second.start || va >= rit->second.end) return false;
		if (out_start) *out_start = rit->second.start;
		if (out_end)   *out_end = rit->second.end;
		return true;
	}

	inline std::string rsp_substitution_at(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return std::string();
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return std::string();
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return std::string();
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return std::string();
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return std::string();
		}
		auto sub = rec.rsp_access_substitution.find(va);
		if (sub == rec.rsp_access_substitution.end()) return std::string();
		return sub->second;
	}

	inline bool rsp_entry_relative_at(uint64_t va, int64_t* out_entry_relative,
		uint64_t* out_func_start, uint64_t* out_locals_size)
	{
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return false;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return false;
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return false;
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return false;
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return false;
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return false;
		}
		auto er = rec.rsp_access_entry_relative.find(va);
		if (er == rec.rsp_access_entry_relative.end()) return false;
		if (out_entry_relative) *out_entry_relative = er->second;
		auto ao = rec.rsp_access_abs_offset.find(va);
		uint64_t abs_offset = ao != rec.rsp_access_abs_offset.end()
			? static_cast<uint64_t>(ao->second > 0 ? ao->second : 0)
			: rec.prologue_locals_size;
		if (out_func_start) *out_func_start = func_start;
		if (out_locals_size) *out_locals_size = abs_offset;
		return true;
	}

	inline uint64_t prologue_locals_size_for(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return 0;
		return it->second.prologue_locals_size;
	}

	inline std::string mnem_override_at(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return std::string();
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return std::string();
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return std::string();
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return std::string();
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return std::string();
		}
		auto sub = rec.insn_kind_override.find(va);
		if (sub == rec.insn_kind_override.end()) return std::string();
		return sub->second;
	}

	inline int64_t entry_to_exit_sp_delta(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return 0;
		return it->second.entry_to_exit_sp_delta;
	}

	struct frame_summary_t {
		int64_t  delta = 0;
		uint64_t prologue_locals_size = 0;
		uint32_t saved_reg_count = 0;
		bool     bp_based = false;
		bool     sp_based = false;
		bool     sp_analysis_failed = false;
	};

	inline bool frame_summary(uint64_t func_start, frame_summary_t* out) {
		if (!out) return false;
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return false;
		const auto& rec = it->second;
		out->delta = rec.entry_to_exit_sp_delta;
		out->prologue_locals_size = rec.prologue_locals_size;
		out->bp_based = rec.bp_based;
		out->sp_based = rec.sp_based;
		out->sp_analysis_failed = rec.sp_analysis_failed;
		uint32_t cnt = 0;
		for (const auto& kv : rec.insn_kind_override) {
			const std::string& s = kv.second;
			if (s.size() >= 2 && s[0] == 'r' && s[1] == '_') ++cnt;
		}
		out->saved_reg_count = cnt;
		return true;
	}

	inline std::string inline_comment_at(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return std::string();
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return std::string();
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return std::string();
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return std::string();
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return std::string();
		}
		auto cit = rec.inline_comments.find(va);
		if (cit == rec.inline_comments.end()) return std::string();
		return cit->second;
	}

	inline bool is_align_row_start(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		return c.align_runs_by_start.find(va) != c.align_runs_by_start.end();
	}

	inline bool align_run_at(uint64_t va, detail::align_run_t* out) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.align_runs_by_start.find(va);
		if (it == c.align_runs_by_start.end()) return false;
		if (out) *out = it->second;
		return true;
	}

	inline bool is_thunk(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return false;
		return it->second.is_thunk;
	}

	inline uint64_t thunk_target(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return 0;
		return it->second.thunk_target;
	}

	inline std::vector<detail::switch_table_t> switches_for(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return std::vector<detail::switch_table_t>();
		return it->second.switches;
	}

	inline std::vector<uint64_t> call_targets_for(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return std::vector<uint64_t>();
		return it->second.call_targets;
	}

	inline std::string thunk_target_name_for(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return std::string();
		if (!it->second.is_thunk) return std::string();
		return it->second.thunk_target_name;
	}

	inline std::string loc_label_for(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return std::string();
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return std::string();
		const auto& rec = rit->second;
		if (va <= rec.start || va >= rec.end) return std::string();
		char buf[40];
		std::snprintf(buf, sizeof(buf), "loc_%llX",
			static_cast<unsigned long long>(va));
		return std::string(buf);
	}

	inline bool is_inside_known_function(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return false;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return false;
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return false;
		const auto& rec = rit->second;
		return va > rec.start && va < rec.end;
	}

	inline bool is_noreturn_call_at(uint64_t va) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return false;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return false;
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return false;
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return false;
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return false;
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return false;
		}
		return rec.noreturn_call_addrs.count(va) != 0;
	}

	inline bool directive_override_at(uint64_t va, directive_override_t* out) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return false;
		auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), va);
		if (it == c.sorted_starts.begin()) return false;
		--it;
		uint64_t func_start = *it;
		auto rit = c.by_start.find(func_start);
		if (rit == c.by_start.end()) return false;
		const auto& rec = rit->second;
		if (va < rec.start || va >= rec.end) return false;
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return false;
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return false;
		}
		auto oit = rec.directive_overrides.find(va);
		if (oit == rec.directive_overrides.end()) return false;
		if (out) *out = oit->second;
		return true;
	}

	inline bool function_is_always_noreturn(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return false;
		return it->second.always_noreturn;
	}

	inline bool function_is_library(uint64_t func_start) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return false;
		return it->second.is_library;
	}

}
