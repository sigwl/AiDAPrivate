#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "c03_compatibility_registration.hpp"
#include "../ida_compat_mut.hpp"
#include "../ida_compat_read.hpp"
#include "../ida_compat_schemas.hpp"
#include "../schema_validator.hpp"
#include "debugger_lane.hpp"
#include "effect_policy.hpp"
#include "handlers/analysis.hpp"
#include "handlers/composite.hpp"
#include "handlers/core.hpp"
#include "handlers/debugger.hpp"
#include "handlers/memory.h"
#include "handlers/modify.hpp"
#include "handlers/python.hpp"
#include "handlers/routing_extensions.hpp"
#include "handlers/signatures.h"
#include "handlers/signature_operand_mask.hpp"
#include "handlers/stack.hpp"
#include "handlers/survey.hpp"
#include "handlers/types.hpp"
#include "live_routing_integration.hpp"
#include "mcp_server_integration.hpp"
#include "python_worker_host.hpp"
#include "../../analysis/decompiler/decompiler_ui_integration.hpp"
#include "../../analysis/provider_snapshot.hpp"
#include "../../analysis/workspace/live_snapshot_provider.hpp"
#include "../../analysis/workspace/overlay_journal.hpp"
#include "../../analysis/workspace/query_index.hpp"
#include "../../analysis/workspace/workspace_registry.hpp"
#include "../../workbench/adapters/pseudocode_document.hpp"
#include "../../infra/cancellation_watchdog.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace fs = std::filesystem;

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

std::string hex_addr(std::uint64_t value)
{
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%llX",
        static_cast<unsigned long long>(value));
    return buffer;
}

bool parse_addr(const std::string& text, std::uint64_t& output)
{
    try {
        if (text.size() > 2 && text[0] == '0' &&
            (text[1] == 'b' || text[1] == 'B')) {
            std::uint64_t value = 0;
            for (std::size_t index = 2; index < text.size(); ++index) {
                const char character = text[index];
                if (character != '0' && character != '1')
                    return false;
                value = (value << 1U) |
                    static_cast<std::uint64_t>(character == '1');
            }
            output = value;
            return true;
        }
        std::size_t consumed = 0;
        output = std::stoull(text, &consumed, 0);
        return consumed == text.size();
    } catch (...) {
        return false;
    }
}

tool_result_t workspace_tool_error(
    const aida::analysis::workspace_error_t& value)
{
    json details{{"phase", value.phase}, {"cancellation", value.cancellation},
        {"deadline", value.deadline}};
    if (value.offset)
        details["offset"] = std::to_string(*value.offset);
    if (value.size)
        details["size"] = std::to_string(*value.size);
    if (value.win32_status)
        details["win32_status"] = *value.win32_status;
    if (value.sqlite_status)
        details["sqlite_status"] = *value.sqlite_status;
    if (!value.details.empty()) {
        details["details"] = json::object();
        for (const auto& entry : value.details)
            details["details"][entry.first] = entry.second;
    }
    return tool_result_t::error(value.message, value.stable_code(), details);
}

}

namespace mcp_standalone
{
    namespace
    {
        namespace python_compat = aida::standalone::mcp::compat;

        class workspace_call_cancel_bridge_t final
        {
        public:
            workspace_call_cancel_bridge_t(
                std::optional<std::chrono::steady_clock::time_point> deadline,
                std::atomic<bool>* external)
                : source_(deadline)
            {
                if (external) {
                    aida::infra::cancellation_watchdog::watch_descriptor_t watch;
                    watch.external_flag = external;
                    watch.on_fire = [source_snapshot = source_]() mutable {
                        source_snapshot.request_cancel();
                    };
                    watch_id_ = aida::infra::cancellation_watchdog::register_watch(std::move(watch));
                }
            }

            ~workspace_call_cancel_bridge_t()
            {
                if (watch_id_.valid())
                    aida::infra::cancellation_watchdog::unregister_watch(watch_id_);
            }

            workspace_call_cancel_bridge_t(const workspace_call_cancel_bridge_t&) = delete;
            workspace_call_cancel_bridge_t& operator=(const workspace_call_cancel_bridge_t&) = delete;

            aida::analysis::cancellation_token_t token() const noexcept
            {
                return source_.token();
            }

        private:
            aida::analysis::cancellation_source_t source_;
            aida::infra::cancellation_watchdog::watch_id_t watch_id_;
        };

        std::optional<fs::path> standalone_package_root()
        {
            std::vector<wchar_t> path(32768U, L'\0');
            const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (length == 0 || length >= path.size())
                return std::nullopt;
            const fs::path executable(
                std::wstring(path.data(), static_cast<std::size_t>(length)));
            if (executable.parent_path().empty())
                return std::nullopt;
            return executable.parent_path();
        }

        std::optional<std::uint64_t> json_nonnegative_u64(const json& value)
        {
            if (value.is_number_unsigned())
                return value.get<std::uint64_t>();
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0)
                    return static_cast<std::uint64_t>(signed_value);
            }
            return std::nullopt;
        }

        python_compat::python_workspace_response_t isolated_python_workspace_error(
            std::string code, std::string message)
        {
            python_compat::python_workspace_response_t response;
            response.error_code = std::move(code);
            response.error_message = std::move(message);
            return response;
        }

        python_compat::python_workspace_response_t isolated_python_workspace_api(
            const python_compat::python_workspace_query_t& query,
            const workspace_request_context_t& context)
        {
            if (context.cancellation_requested())
                return isolated_python_workspace_error("CANCELLED", "workspace request was cancelled");
            if (!context.workspace || context.kind != aida::analysis::target_kind_t::static_file)
                return isolated_python_workspace_error("LIVE_TARGET_DENIED", "isolated Python worker requires a static workspace target");
            if (!query.arguments.is_object())
                return isolated_python_workspace_error("INVALID_ARGUMENTS", "workspace API arguments must be an object");
            tool_result_t tool_result;
            if (query.operation == "read_bytes") {
                const auto offset = query.arguments.find("offset");
                const auto size = query.arguments.find("size");
                if (query.arguments.size() != 2U || offset == query.arguments.end() || size == query.arguments.end())
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "read_bytes requires offset and size only");
                const auto offset_value = json_nonnegative_u64(*offset);
                const auto size_value = json_nonnegative_u64(*size);
                if (!offset_value || !size_value || *size_value == 0 || *size_value > 65536U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "read_bytes arguments exceed the approved limit");
                tool_result = ida_compat::tool_get_bytes(
                    json{{"address", "file:" + std::to_string(*offset_value)}, {"size", *size_value}}, context);
            } else if (query.operation == "find") {
                const auto text = query.arguments.find("query");
                const auto limit = query.arguments.find("limit");
                if ((query.arguments.size() != 1U && query.arguments.size() != 2U) || text == query.arguments.end() ||
                    !text->is_string() || text->get<std::string>().empty() || text->get<std::string>().size() > 4096U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "find requires a bounded query string");
                std::uint64_t limit_value = 100;
                if (limit != query.arguments.end()) {
                    const auto parsed = json_nonnegative_u64(*limit);
                    if (!parsed || *parsed == 0 || *parsed > 1000U)
                        return isolated_python_workspace_error("INVALID_ARGUMENTS", "find limit exceeds the approved limit");
                    limit_value = *parsed;
                }
                tool_result = ida_compat::tool_find(
                    json{{"query", text->get<std::string>()}, {"limit", limit_value}}, context);
            } else if (query.operation == "list_functions") {
                const auto offset = query.arguments.find("offset");
                const auto limit = query.arguments.find("limit");
                if ((query.arguments.size() != 0U && query.arguments.size() != 1U && query.arguments.size() != 2U) ||
                    (offset != query.arguments.end() && !json_nonnegative_u64(*offset)) ||
                    (limit != query.arguments.end() && !json_nonnegative_u64(*limit)))
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "list_functions arguments are invalid");
                const std::uint64_t offset_value = offset == query.arguments.end()
                    ? 0U : *json_nonnegative_u64(*offset);
                const std::uint64_t limit_value = limit == query.arguments.end()
                    ? 100U : *json_nonnegative_u64(*limit);
                if (limit_value == 0 || limit_value > 1000U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "list_functions limit exceeds the approved limit");
                tool_result = ida_compat::tool_list_funcs(
                    json{{"offset", offset_value}, {"limit", limit_value}}, context);
            } else {
                return isolated_python_workspace_error("WORKSPACE_OPERATION_DENIED", "workspace operation is not approved");
            }
            if (!tool_result.success)
                return isolated_python_workspace_error(
                    tool_result.error_code.empty() ? "WORKSPACE_API_REJECTED" : tool_result.error_code,
                    tool_result.text.empty() ? "approved workspace API rejected request" : tool_result.text);
            python_compat::python_workspace_response_t response;
            response.success = true;
            response.data = std::move(tool_result.data);
            return response;
        }

        json isolated_python_workspace_metadata(const workspace_request_context_t& context)
        {
            return {
                {"binary_id", context.binary_id.to_hex()},
                {"binary_name", context.workspace->identity().bin_name()},
                {"analysis_revision", context.analysis_revision},
                {"overlay_revision", context.overlay_revision},
                {"target_kind", "static_file"}
            };
        }

        namespace wave_c_compat = aida::standalone::mcp::compat;
        namespace wave_c_handlers = aida::standalone::mcp::compat::handlers;
        namespace wave_c_integration = aida::standalone::mcp::integration;
        namespace wave_c_protocol = aida::standalone::mcp::protocol;

        template <typename names_t>
        bool wave_c_name_in(const names_t& names, std::string_view name)
        {
            return std::find(names.begin(), names.end(), name) != names.end();
        }

        using wave_c_debugger_identity_result_t = wave_c_compat::debugger_adapter_result_t<
            wave_c_compat::debugger_target_identity_t>;
        using wave_c_debugger_response_result_t = wave_c_compat::debugger_adapter_result_t<
            wave_c_compat::debugger_adapter_response_t>;
        using wave_c_live_snapshot_result_t = wave_c_compat::adapter_result_t<
            wave_c_compat::bounded_live_snapshot_t>;
        using wave_c_survey_lease_result_t = wave_c_compat::adapter_result_t<
            wave_c_handlers::survey_generation_lease_t>;
        using wave_c_python_lease_result_t = wave_c_compat::adapter_result_t<
            wave_c_handlers::python_target_lease_t>;

        wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>
        wave_c_adapter_result(tool_result_t result)
        {
            if (!result.success) {
                const std::string& source_code = result.error_code;
                wave_c_compat::adapter_error_code_t adapter_code = wave_c_compat::adapter_error_code_t::backend_rejected;
                if (source_code == "cancelled" || source_code == "CANCELLED")
                    adapter_code = wave_c_compat::adapter_error_code_t::operation_not_permitted;
                else if (source_code == "MCP_TOOL_TIMEOUT" || source_code == "deadline_exceeded")
                    adapter_code = wave_c_compat::adapter_error_code_t::backend_unavailable;
                else if (source_code == "MCP_TOOL_ADMISSION_REJECTED" || source_code == "MCP_TOOL_CAPACITY_REJECT")
                    adapter_code = wave_c_compat::adapter_error_code_t::effect_lock_busy;
                diag::log_tagged_fmt("mcp_c03", "adapter_error source_code='%s' source_text_len=%zu source_details=%d mapped_code=%u",
                    source_code.empty() ? "<none>" : source_code.c_str(), result.text.size(),
                    result.error_details.is_object() && !result.error_details.empty() ? 1 : 0,
                    static_cast<unsigned int>(adapter_code));
                return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                    {adapter_code,
                     source_code.empty() ? "workspace_backend_rejected" :
                         (source_code == "cancelled" || source_code == "CANCELLED") ? "cancelled" :
                         (source_code == "MCP_TOOL_TIMEOUT" || source_code == "deadline_exceeded") ? "deadline_exceeded" :
                         (source_code == "MCP_TOOL_ADMISSION_REJECTED" || source_code == "MCP_TOOL_CAPACITY_REJECT") ? "capacity_rejected" :
                         "workspace_backend_rejected",
                     0, 0});
            }
            wave_c_compat::adapter_response_t response;
            response.payload = std::move(result.data).dump();
            return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::success(
                std::move(response));
        }

        std::optional<std::uint64_t> wave_c_address_value(const json& value)
        {
            if (value.is_number_unsigned())
                return value.get<std::uint64_t>();
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0)
                    return static_cast<std::uint64_t>(signed_value);
                return std::nullopt;
            }
            if (!value.is_string())
                return std::nullopt;
            std::uint64_t parsed = 0;
            return parse_addr(value.get_ref<const std::string&>(), parsed)
                ? std::optional<std::uint64_t>(parsed) : std::nullopt;
        }

        std::uint64_t wave_c_workspace_generation(
            const workspace_request_context_t& context) noexcept
        {
            return (std::max)(std::uint64_t{1}, context.workspace->generation());
        }

        std::optional<std::chrono::steady_clock::time_point> wave_c_deadline(
            const workspace_request_context_t& context) noexcept
        {
            if (context.deadline_ms == 0)
                return std::nullopt;
            const auto steady_now = std::chrono::steady_clock::now();
            const auto tick_now = static_cast<std::uint64_t>(GetTickCount64());
            if (context.deadline_ms <= tick_now)
                return steady_now;
            return steady_now + std::chrono::milliseconds(context.deadline_ms - tick_now);
        }

        wave_c_compat::target_selector_t wave_c_target_selector(
            const workspace_request_context_t& context)
        {
            wave_c_compat::target_selector_t selector;
            selector.pid = context.pid;
            selector.bin_name = context.workspace->identity().bin_name();
            return selector;
        }

        bool wave_c_adapter_symbol_matches(std::string_view name,
                                           std::string_view adapter_symbol)
        {
            return adapter_symbol ==
                "aida::standalone::mcp::compat::adapters::" + std::string(name);
        }

        wave_c_compat::target_record_t wave_c_target_record(
            const workspace_request_context_t& context)
        {
            wave_c_compat::target_record_t record;
            record.target_id = static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(context.workspace.get()));
            if (record.target_id == 0)
                record.target_id = 1;
            record.pid = context.pid.value_or(1U);
            record.bin_name = context.workspace->identity().bin_name();
            record.generation = wave_c_workspace_generation(context);
            record.attach_generation = (std::max)(std::uint64_t{1}, context.analysis_revision);
            record.process_creation_identity = static_cast<std::uint64_t>(
                aida::analysis::binary_id_hash_t{}(context.binary_id));
            if (record.process_creation_identity == 0)
                record.process_creation_identity = record.target_id;
            record.live = context.kind == aida::analysis::target_kind_t::live_snapshot;
            if (const auto& process = context.workspace->identity().process()) {
                record.pid = process->pid;
                record.process_creation_identity = process->creation_time_100ns;
            }
            if (record.live) {
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                if (provider) {
                    const auto& metadata = provider->metadata();
                    record.live_capture_base = metadata.capture_address;
                    record.live_capture_size = metadata.capture_size;
                    record.live_snapshot_permitted = metadata.capture_size != 0 &&
                        provider->validate_current_identity().has_value();
                    record.live_snapshot_maximum_bytes = record.live_snapshot_permitted
                        ? (std::min)(metadata.capture_size,
                            wave_c_compat::live_routing_limits_t{}
                                .maximum_snapshot_bytes)
                        : 0;
                    record.pid = metadata.process.pid;
                    record.process_creation_identity = metadata.process.creation_time_100ns;
                }
            }
            return record;
        }

        class wave_c_signature_source_t final
            : public wave_c_handlers::signature_source_t {
        public:
            explicit wave_c_signature_source_t(const workspace_request_context_t& context)
                : context_(context), snapshot_(context.workspace->snapshot()),
                  image_(context.workspace->normalized_image())
            {
                if (!image_)
                    return;
                relocation_facts_.reserve(image_->relocations.size());
                for (const auto& relocation : image_->relocations) {
                    relocation_facts_.emplace_back(
                        normalize_rva(relocation.address.value), relocation.type);
                }
                std::sort(relocation_facts_.begin(), relocation_facts_.end(),
                    [](const auto& lhs, const auto& rhs) {
                        return lhs.first < rhs.first ||
                            (lhs.first == rhs.first && lhs.second < rhs.second);
                    });
            }

            std::optional<std::uint64_t> resolve_address(
                std::string_view query) const override
            {
                std::uint64_t parsed = 0;
                if (parse_addr(std::string(query), parsed))
                    return normalize_rva(parsed);
                if (!snapshot_ || !image_)
                    return std::nullopt;
                const auto found = std::find_if(
                    snapshot_->symbols.begin(), snapshot_->symbols.end(),
                    [query](const auto& symbol) { return symbol.name == query; });
                return found == snapshot_->symbols.end()
                    ? std::nullopt
                    : std::optional<std::uint64_t>(found->address.value);
            }

            std::optional<wave_c_handlers::signature_instruction_t> instruction_at(
                std::uint64_t address) const override
            {
                if (!snapshot_)
                    return std::nullopt;
                address = normalize_rva(address);
                const auto found = std::find_if(
                    snapshot_->instructions.begin(), snapshot_->instructions.end(),
                    [address](const auto& instruction) {
                        return instruction.address.value == address;
                    });
                if (found == snapshot_->instructions.end() || found->length == 0)
                    return std::nullopt;
                wave_c_handlers::signature_instruction_t result;
                result.address = address;
                result.architecture = signature_architecture();
                result.mode = signature_mode();
                result.endian = image_->endian == aida::analysis::endian_t::big
                    ? wave_c_handlers::signature_endian_t::big
                    : wave_c_handlers::signature_endian_t::little;
                if (!read_bytes(address, found->length, result.bytes))
                    return std::nullopt;
                result.stable_mask.assign(result.bytes.size(), 0xffU);
                append_relocation_ranges(result);
                auto mask = wave_c_handlers::build_signature_operand_mask(result);
                if (mask.success) {
                    result.stable_mask = std::move(mask.stable_mask);
                    result.stable_mask_authoritative = true;
                } else {
                    result.stable_mask.clear();
                }
                return result;
            }

            std::optional<wave_c_handlers::signature_function_t> function_containing(
                std::uint64_t address) const override
            {
                if (!snapshot_)
                    return std::nullopt;
                address = normalize_rva(address);
                const auto found = std::find_if(
                    snapshot_->functions.begin(), snapshot_->functions.end(),
                    [address](const auto& function) {
                        return function.start.value <= address && address < function.end.value;
                    });
                if (found == snapshot_->functions.end())
                    return std::nullopt;
                wave_c_handlers::signature_function_t result;
                result.start = found->start.value;
                result.end = found->end.value;
                if (found->symbol_id) {
                    const auto symbol = std::find_if(
                        snapshot_->symbols.begin(), snapshot_->symbols.end(),
                        [id = *found->symbol_id](const auto& value) { return value.id == id; });
                    if (symbol != snapshot_->symbols.end())
                        result.name = symbol->name;
                }
                if (result.name.empty())
                    result.name = "sub_" + hex_addr(found->start.value).substr(2);
                return result;
            }

            std::vector<wave_c_handlers::signature_xref_t> xrefs_to(
                std::uint64_t address) const override
            {
                std::vector<wave_c_handlers::signature_xref_t> result;
                if (!snapshot_)
                    return result;
                address = normalize_rva(address);
                for (const auto& xref : snapshot_->xrefs) {
                    if (xref.target.value != address)
                        continue;
                    result.push_back({
                        xref.source.value,
                        xref.kind == aida::analysis::xref_kind_t::code ||
                            xref.kind == aida::analysis::xref_kind_t::call});
                }
                std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
                    return lhs.from < rhs.from;
                });
                return result;
            }

            bool read_bytes(std::uint64_t address, std::size_t size,
                            std::vector<std::uint8_t>& bytes) const override
            {
                if (!image_ || size == 0)
                    return false;
                const auto offset = file_offset_for(normalize_rva(address), size);
                if (!offset)
                    return false;
                const auto read = context_.workspace->provider().read_vector(
                    *offset, size, size);
                if (!read)
                    return false;
                bytes = read.value();
                return bytes.size() == size;
            }

            wave_c_handlers::signature_match_result_t find_matches(
                const std::vector<std::uint8_t>& bytes,
                const std::vector<std::uint8_t>& stable_mask,
                std::size_t maximum_results,
                const wave_c_protocol::cancellation_token_t& cancellation) const override
            {
                wave_c_handlers::signature_match_result_t result;
                if (!snapshot_ || bytes.empty() || bytes.size() != stable_mask.size() ||
                    maximum_results == 0)
                    return result;
                result.exhausted = false;
                for (const auto& instruction : snapshot_->instructions) {
                    if (cancellation.cancelled()) {
                        result.exhausted = true;
                        result.error = "cancelled";
                        return result;
                    }
                    std::vector<std::uint8_t> candidate;
                    if (!read_bytes(instruction.address.value, bytes.size(), candidate))
                        continue;
                    bool equal = true;
                    for (std::size_t index = 0; index < bytes.size(); ++index) {
                        if ((candidate[index] & stable_mask[index]) !=
                            (bytes[index] & stable_mask[index])) {
                            equal = false;
                            break;
                        }
                    }
                    if (!equal)
                        continue;
                    result.addresses.push_back(instruction.address.value);
                    if (result.addresses.size() >= maximum_results) {
                        result.exhausted = true;
                        break;
                    }
                }
                return result;
            }

        private:
            void append_relocation_ranges(
                wave_c_handlers::signature_instruction_t& result) const
            {
                if (!image_ || result.bytes.empty() ||
                    result.bytes.size() >
                        (std::numeric_limits<std::uint64_t>::max)() - result.address)
                    return;
                const std::uint64_t end = result.address + result.bytes.size();
                const std::size_t pointer_width = image_->address_width_bits == 0
                    ? (result.mode == wave_c_handlers::signature_mode_t::x86_16 ? 2U :
                       result.mode == wave_c_handlers::signature_mode_t::x86_32 ||
                       result.mode == wave_c_handlers::signature_mode_t::arm_a32 ||
                       result.mode == wave_c_handlers::signature_mode_t::arm_thumb ||
                       result.mode == wave_c_handlers::signature_mode_t::mips32 ||
                       result.mode == wave_c_handlers::signature_mode_t::ppc32 ||
                       result.mode == wave_c_handlers::signature_mode_t::riscv32 ? 4U : 8U)
                    : static_cast<std::size_t>(image_->address_width_bits / 8U);
                auto relocation = std::lower_bound(
                    relocation_facts_.begin(), relocation_facts_.end(), result.address,
                    [](const auto& fact, std::uint64_t address) {
                        return fact.first < address;
                    });
                for (; relocation != relocation_facts_.end(); ++relocation) {
                    const std::uint64_t relocation_address = relocation->first;
                    if (relocation_address >= end)
                        break;
                    if (relocation_address < result.address || relocation_address >= end)
                        continue;
                    std::size_t width = pointer_width;
                    if (image_->format == aida::analysis::format_id_t::pe32 ||
                        image_->format == aida::analysis::format_id_t::pe32_plus) {
                        if (relocation->second == 1U || relocation->second == 2U)
                            width = 2U;
                        else if (relocation->second == 3U)
                            width = 4U;
                        else if (relocation->second == 10U)
                            width = 8U;
                    }
                    const std::size_t offset = static_cast<std::size_t>(
                        relocation_address - result.address);
                    width = (std::min)(width, result.bytes.size() - offset);
                    if (width == 0 || offset > (std::numeric_limits<std::uint8_t>::max)() ||
                        width > (std::numeric_limits<std::uint8_t>::max)())
                        continue;
                    const auto duplicate = std::find_if(
                        result.relocation_ranges.begin(), result.relocation_ranges.end(),
                        [offset, width](const auto& range) {
                            return range.offset == offset && range.size == width;
                        });
                    if (duplicate == result.relocation_ranges.end()) {
                        result.relocation_ranges.push_back({
                            static_cast<std::uint8_t>(offset),
                            static_cast<std::uint8_t>(width)});
                    }
                }
            }

            std::uint64_t normalize_rva(std::uint64_t address) const noexcept
            {
                return image_ && image_->image_base != 0 && address >= image_->image_base
                    ? address - image_->image_base : address;
            }

            std::optional<std::uint64_t> file_offset_for(
                std::uint64_t rva, std::uint64_t size) const noexcept
            {
                if (!image_ || size > image_->provider_size)
                    return std::nullopt;
                if (rva <= image_->header_size && size <= image_->header_size - rva)
                    return rva;
                for (const auto& section : image_->sections) {
                    if (rva < section.virtual_address)
                        continue;
                    const std::uint64_t delta = rva - section.virtual_address;
                    if (delta <= section.file_size && size <= section.file_size - delta &&
                        section.file_offset <= image_->provider_size &&
                        delta <= image_->provider_size - section.file_offset &&
                        size <= image_->provider_size - section.file_offset - delta)
                        return section.file_offset + delta;
                }
                for (const auto& segment : image_->segments) {
                    if (rva < segment.virtual_address)
                        continue;
                    const std::uint64_t delta = rva - segment.virtual_address;
                    if (delta <= segment.file_size && size <= segment.file_size - delta &&
                        segment.file_offset <= image_->provider_size &&
                        delta <= image_->provider_size - segment.file_offset &&
                        size <= image_->provider_size - segment.file_offset - delta)
                        return segment.file_offset + delta;
                }
                return std::nullopt;
            }

            wave_c_handlers::signature_architecture_t signature_architecture() const noexcept
            {
                if (!image_)
                    return wave_c_handlers::signature_architecture_t::unknown;
                using architecture_t = aida::analysis::architecture_id_t;
                switch (image_->architecture) {
                case architecture_t::x86:
                    return wave_c_handlers::signature_architecture_t::x86;
                case architecture_t::x86_64:
                    return wave_c_handlers::signature_architecture_t::x64;
                case architecture_t::arm:
                    return image_->architecture_mode == aida::analysis::architecture_mode_t::arm_thumb
                        ? wave_c_handlers::signature_architecture_t::thumb
                        : wave_c_handlers::signature_architecture_t::arm;
                case architecture_t::aarch64:
                case architecture_t::arm64ec:
                    return wave_c_handlers::signature_architecture_t::aarch64;
                case architecture_t::mips:
                case architecture_t::mips64:
                    return wave_c_handlers::signature_architecture_t::mips;
                case architecture_t::ppc:
                case architecture_t::ppc64:
                    return wave_c_handlers::signature_architecture_t::ppc;
                case architecture_t::riscv:
                case architecture_t::riscv32:
                case architecture_t::riscv64:
                    return wave_c_handlers::signature_architecture_t::riscv;
                case architecture_t::jvm_bytecode:
                    return wave_c_handlers::signature_architecture_t::jvm;
                case architecture_t::dalvik_bytecode:
                    return wave_c_handlers::signature_architecture_t::dalvik;
                default:
                    return wave_c_handlers::signature_architecture_t::unknown;
                }
            }

            wave_c_handlers::signature_mode_t signature_mode() const noexcept
            {
                if (!image_)
                    return wave_c_handlers::signature_mode_t::unknown;
                using mode_t = aida::analysis::architecture_mode_t;
                switch (image_->architecture_mode) {
                case mode_t::x86_16: return wave_c_handlers::signature_mode_t::x86_16;
                case mode_t::x86_32: return wave_c_handlers::signature_mode_t::x86_32;
                case mode_t::x86_64: return wave_c_handlers::signature_mode_t::x86_64;
                case mode_t::arm_a32: return wave_c_handlers::signature_mode_t::arm_a32;
                case mode_t::arm_thumb: return wave_c_handlers::signature_mode_t::arm_thumb;
                case mode_t::aarch64: return wave_c_handlers::signature_mode_t::aarch64;
                case mode_t::mips32: return wave_c_handlers::signature_mode_t::mips32;
                case mode_t::mips64: return wave_c_handlers::signature_mode_t::mips64;
                case mode_t::ppc32: return wave_c_handlers::signature_mode_t::ppc32;
                case mode_t::ppc64: return wave_c_handlers::signature_mode_t::ppc64;
                case mode_t::riscv32: return wave_c_handlers::signature_mode_t::riscv32;
                case mode_t::riscv64: return wave_c_handlers::signature_mode_t::riscv64;
                case mode_t::jvm: return wave_c_handlers::signature_mode_t::jvm;
                case mode_t::dalvik: return wave_c_handlers::signature_mode_t::dalvik;
                default: break;
                }
                switch (image_->architecture) {
                case aida::analysis::architecture_id_t::x86:
                    return wave_c_handlers::signature_mode_t::x86_32;
                case aida::analysis::architecture_id_t::x86_64:
                    return wave_c_handlers::signature_mode_t::x86_64;
                case aida::analysis::architecture_id_t::arm:
                    return wave_c_handlers::signature_mode_t::arm_a32;
                case aida::analysis::architecture_id_t::aarch64:
                case aida::analysis::architecture_id_t::arm64ec:
                    return wave_c_handlers::signature_mode_t::aarch64;
                case aida::analysis::architecture_id_t::mips:
                    return wave_c_handlers::signature_mode_t::mips32;
                case aida::analysis::architecture_id_t::mips64:
                    return wave_c_handlers::signature_mode_t::mips64;
                case aida::analysis::architecture_id_t::ppc:
                    return wave_c_handlers::signature_mode_t::ppc32;
                case aida::analysis::architecture_id_t::ppc64:
                    return wave_c_handlers::signature_mode_t::ppc64;
                case aida::analysis::architecture_id_t::riscv32:
                    return wave_c_handlers::signature_mode_t::riscv32;
                case aida::analysis::architecture_id_t::riscv:
                case aida::analysis::architecture_id_t::riscv64:
                    return wave_c_handlers::signature_mode_t::riscv64;
                case aida::analysis::architecture_id_t::jvm_bytecode:
                    return wave_c_handlers::signature_mode_t::jvm;
                case aida::analysis::architecture_id_t::dalvik_bytecode:
                    return wave_c_handlers::signature_mode_t::dalvik;
                default:
                    return wave_c_handlers::signature_mode_t::unknown;
                }
            }

            const workspace_request_context_t& context_;
            std::shared_ptr<const aida::analysis::analysis_snapshot_t> snapshot_;
            std::shared_ptr<const aida::analysis::workspace_image_t> image_;
            std::vector<std::pair<std::uint64_t, std::uint64_t>> relocation_facts_;
        };

        wave_c_handlers::routing_extension_workspace_handlers_t
        wave_c_unavailable_extension_handlers()
        {
            const auto unavailable = [](
                const wave_c_compat::adapter_call_context_t&,
                const wave_c_compat::adapter_request_t&) {
                return wave_c_compat::adapter_result_t<
                    wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::backend_unavailable,
                         "targetless_extension_backend_unavailable", 0, 0});
            };
            wave_c_handlers::routing_extension_workspace_handlers_t handlers;
            handlers.analyze_funcs = unavailable;
            handlers.find_insns = unavailable;
            return handlers;
        }

        class wave_c_unavailable_debugger_adapter_t final
            : public wave_c_compat::debugger_adapter_t {
        public:
            wave_c_debugger_identity_result_t identity(
                const wave_c_protocol::cancellation_token_t& cancellation,
                std::chrono::steady_clock::time_point deadline) override
            {
                if (cancellation.cancelled())
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= deadline)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                return wave_c_debugger_identity_result_t::failure(
                    wave_c_compat::debugger_adapter_error_code_t::unavailable);
            }

            wave_c_debugger_response_result_t execute(
                const wave_c_compat::debugger_adapter_request_t& request) override
            {
                if (request.cancellation.cancelled())
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= request.deadline)
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                return wave_c_debugger_response_result_t::failure(
                    wave_c_compat::debugger_adapter_error_code_t::unavailable);
            }
        };

        class wave_c_adapter_runtime_t final {
        public:
            explicit wave_c_adapter_runtime_t(
                c03_compatibility_runtime_config_t config)
                : config_(std::move(config))
                , registry_schemas_(256)
                , targetless_workspace_(
                    targetless_resolver_, adapter_lock_manager_,
                    wave_c_compat::workspace_adapter_handlers_t{})
                , targetless_core_handlers_(targetless_workspace_, registry_schemas_)
                , registry_handlers_(
                    registry_resolver_, adapter_lock_manager_,
                    wave_c_unavailable_extension_handlers(), registry_schemas_)
            {
                for (auto definition : ida_compat::get_read_tool_defs())
                    read_handlers_.emplace(definition.name, std::move(definition.handler));
                for (auto definition : ida_compat::get_mutation_tool_defs())
                    mutation_handlers_.emplace(definition.name, std::move(definition.handler));
            }

            wave_c_protocol::mcp_result_t dispatch(
                const wave_c_integration::adapter_invocation_t& invocation)
            {
                if (!invocation.contract || !invocation.arguments || !invocation.cancellation)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::internal_error,
                        "Wave C adapter invocation is incomplete.");
                const std::string_view name = invocation.tool_name;
                if (!wave_c_adapter_symbol_matches(name, invocation.adapter_symbol))
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::invalid_contract,
                        "Wave C adapter symbol does not match the registered contract.",
                        json{{"tool", std::string(name)}}, invocation.aida_metadata);
                if (name == "int_convert") {
                    return targetless_core_handlers_.invoke(
                        name, *invocation.arguments, *invocation.cancellation,
                        {}, invocation.aida_metadata);
                }
                if (name == "list_instances")
                    return invoke_list_instances(invocation);
                if (name == "calculator" || name == "calculate") {
                    return registry_handlers_.invoke(name, *invocation.arguments,
                        *invocation.cancellation, {}, invocation.aida_metadata);
                }
                if (!invocation.workspace || !invocation.workspace->workspace)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::target_policy_rejected,
                        "Wave C adapter requires a resolved workspace target.",
                        json{{"tool", std::string(name)}}, invocation.aida_metadata);

                const auto& context = *invocation.workspace;
                wave_c_compat::target_resolver_t resolver;
                const auto target = wave_c_target_record(context);
                const auto published = resolver.publish(target);
                if (!published)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::target_policy_rejected,
                        "Resolved workspace target could not be published to the Wave C adapter.",
                        json{{"stable_code", std::string(published.error.stable_code)}},
                        invocation.aida_metadata);

                auto debugger_adapter = config_.debugger_adapter_factory
                    ? config_.debugger_adapter_factory(context)
                    : std::make_unique<wave_c_unavailable_debugger_adapter_t>();
                if (!debugger_adapter)
                    debugger_adapter =
                        std::make_unique<wave_c_unavailable_debugger_adapter_t>();
                wave_c_compat::debugger_lane_t debugger_lane(*debugger_adapter);
                wave_c_compat::live_routing_integration_t live_routing(
                    resolver, adapter_lock_manager_, debugger_lane,
                    wave_c_compat::live_routing_limits_t{},
                    [&context](
                        const wave_c_compat::adapter_call_context_t& call,
                        const wave_c_compat::bounded_live_snapshot_request_t& request) {
                        return capture_live_snapshot_backend(call, request, context);
                    });
                wave_c_compat::workspace_adapter_handlers_t adapter_handlers;
                const auto backend = [this, &context, &live_routing, &invocation](
                    const wave_c_compat::adapter_call_context_t& call,
                    const wave_c_compat::adapter_request_t& request) {
                    return invoke_workspace_backend(
                        call, request, context, live_routing,
                        *invocation.cancellation);
                };
                adapter_handlers.query = backend;
                adapter_handlers.overlay = backend;
                adapter_handlers.analysis = backend;
                adapter_handlers.decompilation = backend;
                adapter_handlers.checkpoint = backend;
                adapter_handlers.debugger = debugger_lane.workspace_handler();
                adapter_handlers.isolated_python = backend;
                adapter_handlers.live_snapshot = [&context](
                    const wave_c_compat::adapter_call_context_t& call,
                    const wave_c_compat::bounded_live_snapshot_request_t& request) {
                    return capture_live_snapshot_backend(call, request, context);
                };
                wave_c_compat::workspace_adapter_t workspace(
                    resolver, adapter_lock_manager_, std::move(adapter_handlers));
                wave_c_protocol::schema_runtime_t schemas(256);
                const auto generation = wave_c_workspace_generation(context);
                const auto deadline = wave_c_deadline(context);

                if (const auto* descriptor = wave_c_compat::find_contract(name)) {
                    const auto safety = live_routing.verify_static_mutation_safety(
                        name, descriptor->effect);
                    if (!safety)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::effect_policy_rejected,
                            "Wave C live-routing effect classification rejected the tool.",
                            json{{"stable_code", std::string(safety.error().stable_code)}},
                            invocation.aida_metadata);
                }

                if (name == "analyze_funcs" || name == "find_insns") {
                    wave_c_handlers::routing_extension_workspace_handlers_t extension_handlers;
                    extension_handlers.analyze_funcs = backend;
                    extension_handlers.find_insns = backend;
                    wave_c_handlers::routing_extensions_t handlers(
                        resolver, adapter_lock_manager_, std::move(extension_handlers), schemas);
                    wave_c_handlers::routing_extension_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }

                if (wave_c_name_in(wave_c_handlers::analysis_tool_names(), name)) {
                    wave_c_handlers::analysis_handlers_t handlers(workspace, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (name == "analyze_function" || name == "analyze_component" ||
                    name == "diff_before_after" || name == "trace_data_flow") {
                    wave_c_handlers::composite_handlers_t handlers(
                        [this, &context](const auto& call, const auto& request, const auto& cancellation) {
                            return invoke_composite_step(call, request, cancellation, context);
                        });
                    wave_c_handlers::composite_invocation_options_t options;
                    options.expected_workspace_generation = generation;
                    options.expected_overlay_generation = context.overlay_revision;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments, workspace, schemas,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::core_tool_names(), name)) {
                    wave_c_handlers::core_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::core_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::debugger_tool_names(), name)) {
                    wave_c_handlers::debugger_live_dispatch_t live_dispatch;
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        live_dispatch = [&live_routing, generation](
                            const wave_c_compat::live_routing_invocation_context_t& route_context,
                            const json& route_arguments) {
                            auto bound_context = route_context;
                            bound_context.expected_generation = generation;
                            return live_routing.dispatch_debugger(
                                bound_context, route_arguments);
                        };
                    }
                    wave_c_handlers::debugger_handlers_t handlers(
                        workspace, debugger_lane, schemas,
                        wave_c_handlers::debugger_handler_limits_t{},
                        std::move(live_dispatch));
                    wave_c_handlers::debugger_effect_approval_t approval;
                    approval.granted = true;
                    approval.approval_id = next_approval_id_.fetch_add(1, std::memory_order_relaxed);
                    if (approval.approval_id == 0)
                        approval.approval_id = next_approval_id_.fetch_add(1, std::memory_order_relaxed);
                    approval.source = "explicit_mcp_tool_invocation";
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, approval, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::memory_tool_names(), name)) {
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot &&
                        (name == "patch" || name == "put_int"))
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::effect_policy_rejected,
                            "Static overlay mutation is not permitted for a live target.",
                            json{{"stable_code", "static_overlay_live_target_denied"}},
                            invocation.aida_metadata);
                    wave_c_handlers::memory_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::memory_invocation_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        options.expected_live_identity =
                            wave_c_handlers::live_memory_identity_t{
                                target.target_id,
                                target.pid,
                                target.process_creation_identity,
                                target.live_capture_base,
                                target.live_capture_size,
                                target.attach_generation,
                            };
                    }
                    return handlers.invoke(
                        name, *invocation.arguments, *invocation.cancellation, options);
                }
                if (wave_c_name_in(wave_c_handlers::modify_tool_names(), name)) {
                    wave_c_handlers::modify_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::modify_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::python_tool_names(), name)) {
                    wave_c_handlers::python_handlers_t handlers(
                        [&context](const auto&, const auto&) {
                            return acquire_python_target(context);
                        },
                        [](const fs::path& script_root, const auto& request) {
                            return execute_python_worker(script_root, request);
                        }, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (wave_c_handlers::is_signature_tool_name(name)) {
                    wave_c_signature_source_t source(context);
                    wave_c_handlers::signature_handler_context_t signature_context;
                    signature_context.source = &source;
                    signature_context.schemas = &schemas;
                    signature_context.aida_metadata = invocation.aida_metadata;
                    if (name == "make_signature")
                        return wave_c_compat::adapters::make_signature(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    if (name == "make_signature_for_function")
                        return wave_c_compat::adapters::make_signature_for_function(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    if (name == "make_signature_for_range")
                        return wave_c_compat::adapters::make_signature_for_range(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    return wave_c_compat::adapters::find_xref_signatures(
                        signature_context, *invocation.arguments, *invocation.cancellation);
                }
                if (wave_c_name_in(wave_c_handlers::stack_tool_names(), name)) {
                    wave_c_handlers::stack_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::stack_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::survey_tool_names(), name)) {
                    wave_c_handlers::survey_handlers_t handlers(
                        [&context](const auto&, const auto&) {
                            return acquire_survey_generation(context);
                        }, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::types_tool_names(), name)) {
                    wave_c_handlers::types_handlers_t handlers(workspace, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                return wave_c_protocol::mcp_result_t::failure(
                    wave_c_protocol::result_error_code_t::invalid_contract,
                    "No Wave C adapter group owns the generated tool.",
                    json{{"tool", std::string(name)}}, invocation.aida_metadata);
            }

        private:
            std::optional<std::uint32_t> registry_pid_for(
                std::uint64_t target_id,
                const std::unordered_set<std::uint32_t>& reserved,
                std::unordered_set<std::uint32_t>& assigned)
            {
                const auto existing = registry_static_pids_.find(target_id);
                if (existing != registry_static_pids_.end() &&
                    reserved.find(existing->second) == reserved.end() &&
                    assigned.find(existing->second) == assigned.end()) {
                    assigned.insert(existing->second);
                    return existing->second;
                }
                while (next_registry_static_pid_ != 0 &&
                       (reserved.find(next_registry_static_pid_) != reserved.end() ||
                        assigned.find(next_registry_static_pid_) != assigned.end())) {
                    --next_registry_static_pid_;
                }
                if (next_registry_static_pid_ == 0)
                    return std::nullopt;
                const auto pid = next_registry_static_pid_;
                --next_registry_static_pid_;
                registry_static_pids_[target_id] = pid;
                assigned.insert(pid);
                return pid;
            }

            wave_c_protocol::mcp_result_t invoke_list_instances(
                const wave_c_integration::adapter_invocation_t& invocation)
            {
                std::lock_guard<std::mutex> lock(registry_mutex_);
                const auto workspaces = aida::analysis::workspace_registry().list();
                std::unordered_set<std::uint32_t> live_pids;
                for (const auto& workspace : workspaces) {
                    if (workspace && workspace->identity().process() &&
                        workspace->identity().process()->pid != 0)
                        live_pids.insert(workspace->identity().process()->pid);
                }

                std::unordered_set<std::uint32_t> assigned_static_pids;
                std::unordered_set<std::uint64_t> current_target_ids;
                for (const auto& workspace : workspaces) {
                    if (!workspace)
                        continue;
                    workspace_request_context_t context;
                    context.workspace = workspace;
                    context.kind = workspace->identity().target_kind();
                    context.binary_id = workspace->identity().binary_id();
                    context.analysis_revision = workspace->analysis_revision();
                    context.overlay_revision = workspace->overlay_revision();
                    const auto target_id = static_cast<std::uint64_t>(
                        reinterpret_cast<std::uintptr_t>(workspace.get()));
                    if (target_id == 0)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::internal_error,
                            "Workspace registry returned an invalid target identity.",
                            json{{"stable_code", "registry_target_identity_invalid"}},
                            invocation.aida_metadata);
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        if (!workspace->identity().process() ||
                            workspace->identity().process()->pid == 0)
                            return wave_c_protocol::mcp_result_t::failure(
                                wave_c_protocol::result_error_code_t::target_policy_rejected,
                                "Live workspace registry record has no process identity.",
                                json{{"stable_code", "registry_live_identity_invalid"}},
                                invocation.aida_metadata);
                        context.pid = workspace->identity().process()->pid;
                    } else {
                        const auto synthetic = registry_pid_for(
                            target_id, live_pids, assigned_static_pids);
                        if (!synthetic)
                            return wave_c_protocol::mcp_result_t::failure(
                                wave_c_protocol::result_error_code_t::internal_error,
                                "Static workspace routing identities are exhausted.",
                                json{{"stable_code", "registry_static_identity_exhausted"}},
                                invocation.aida_metadata);
                        context.pid = *synthetic;
                    }
                    auto record = wave_c_target_record(context);
                    const auto published = registry_resolver_.publish(record);
                    if (!published)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::target_policy_rejected,
                            "Workspace registry target could not be published.",
                            json{{"stable_code", std::string(published.error.stable_code)},
                                 {"target_id", record.target_id}},
                            invocation.aida_metadata);
                    current_target_ids.insert(record.target_id);
                }
                for (const auto target_id : registry_active_target_ids_) {
                    if (current_target_ids.find(target_id) == current_target_ids.end())
                        (void)registry_resolver_.retire(target_id);
                }
                registry_active_target_ids_ = std::move(current_target_ids);
                return registry_handlers_.invoke(
                    "list_instances", *invocation.arguments,
                    *invocation.cancellation, {}, invocation.aida_metadata);
            }

            tool_result_t invoke_legacy(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (const auto found = read_handlers_.find(std::string(name));
                    found != read_handlers_.end())
                    return found->second(arguments, context);
                if (const auto found = mutation_handlers_.find(std::string(name));
                    found != mutation_handlers_.end())
                    return found->second(arguments, context);
                return tool_result_t::error(
                    "No production workspace adapter is registered for " + std::string(name) + ".",
                    std::string("MCP_BACKEND_UNAVAILABLE"));
            }

            static json scalar_or_array_items(const json& value)
            {
                return value.is_array() ? value : json::array({value});
            }

            static bool managed_decompiler_selector(const json& value)
            {
                if (!value.is_string()) return false;
                auto text = value.get<std::string>();
                while (!text.empty() && std::isspace(
                           static_cast<unsigned char>(text.front())))
                    text.erase(text.begin());
                while (!text.empty() && std::isspace(
                           static_cast<unsigned char>(text.back())))
                    text.pop_back();
                const auto separator = text.find(':');
                if (separator == std::string::npos) return false;
                std::string prefix = text.substr(0, separator);
                std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                    [](unsigned char character) {
                        return static_cast<char>(std::tolower(character));
                    });
                return prefix == "cli" || prefix == "jvm" ||
                    prefix == "dalvik" || prefix == "token";
            }

            static std::string backend_error(const tool_result_t& result)
            {
                if (!result.error_code.empty())
                    return result.error_code;
                if (!result.text.empty())
                    return result.text;
                return "workspace_backend_rejected";
            }

            static json generated_function_summary(const json& function)
            {
                const std::string address = function.value(
                    "addr", function.value("address", std::string()));
                const std::string name = function.value("name", address);
                std::string size;
                if (const auto found = function.find("size"); found != function.end()) {
                    if (found->is_string())
                        size = found->get<std::string>();
                    else if (const auto value = json_nonnegative_u64(*found))
                        size = hex_addr(*value);
                }
                return json{{"addr", address}, {"name", name}, {"size", size}};
            }

            static json generated_import_summary(const json& item)
            {
                std::string imported_name;
                if (const auto name = item.find("name"); name != item.end() && name->is_string())
                    imported_name = name->get<std::string>();
                else if (const auto ordinal = item.find("ordinal"); ordinal != item.end())
                    imported_name = "ordinal_" + ordinal->dump();
                return json{
                    {"addr", item.value("address", std::string())},
                    {"imported_name", std::move(imported_name)},
                    {"module", item.value("library", std::string())},
                };
            }

            tool_result_t lookup_analysis_function(
                const json& target,
                const workspace_request_context_t& context) const
            {
                json request;
                request[wave_c_address_value(target) ? "address" : "name"] = target;
                return invoke_legacy("lookup_funcs", request, context);
            }

            static std::optional<json> first_generated_function(
                const tool_result_t& result)
            {
                if (!result.success)
                    return std::nullopt;
                const auto functions = result.data.find("functions");
                if (functions == result.data.end() || !functions->is_array() ||
                    functions->empty())
                    return std::nullopt;
                return generated_function_summary(functions->front());
            }

            static std::string xref_kind_name(aida::analysis::xref_kind_t kind)
            {
                switch (kind) {
                case aida::analysis::xref_kind_t::code: return "code";
                case aida::analysis::xref_kind_t::call: return "call";
                case aida::analysis::xref_kind_t::read: return "read";
                case aida::analysis::xref_kind_t::write: return "write";
                case aida::analysis::xref_kind_t::address: return "address";
                case aida::analysis::xref_kind_t::relocation: return "relocation";
                }
                return "unknown";
            }

            static bool code_xref(aida::analysis::xref_kind_t kind) noexcept
            {
                return kind == aida::analysis::xref_kind_t::code ||
                    kind == aida::analysis::xref_kind_t::call;
            }

            static json generated_xref(const json& value)
            {
                return {
                    {"addr", value.value("from", value.value("address", std::string()))},
                    {"type", value.value("kind", value.value("type", "unknown"))},
                    {"fn", nullptr},
                };
            }

            static std::optional<std::string> overlay_type_at(
                const workspace_request_context_t& context,
                std::string_view address)
            {
                const auto parsed = wave_c_address_value(json(address));
                const auto overlay = context.workspace->overlay();
                if (!parsed || !overlay)
                    return std::nullopt;
                const auto snapshot = overlay->snapshot();
                for (auto item = snapshot.items.rbegin(); item != snapshot.items.rend(); ++item) {
                    const auto& operation = item->second;
                    if ((operation.kind == aida::analysis::overlay_operation_kind_t::type_application ||
                         operation.kind == aida::analysis::overlay_operation_kind_t::type_update) &&
                        operation.address.value == *parsed && !operation.type.empty())
                        return operation.type;
                }
                return std::nullopt;
            }

            static json generated_basic_blocks(
                const json& legacy_blocks,
                const std::shared_ptr<const aida::analysis::analysis_snapshot_t>& snapshot)
            {
                json output = json::array();
                struct block_range_t final {
                    std::uint64_t start = 0;
                    std::uint64_t end = 0;
                    json value;
                };
                std::vector<block_range_t> ranges;
                if (!legacy_blocks.is_array())
                    return output;
                ranges.reserve(legacy_blocks.size());
                for (const auto& block : legacy_blocks) {
                    const auto start = wave_c_address_value(block.value("start", json()));
                    const auto end = wave_c_address_value(block.value("end", json()));
                    if (!start || !end || *end <= *start)
                        continue;
                    ranges.push_back({*start, *end, {
                        {"start", hex_addr(*start)}, {"end", hex_addr(*end)},
                        {"size", *end - *start}, {"type", 0},
                        {"successors", json::array()}, {"predecessors", json::array()},
                    }});
                }
                if (snapshot) {
                    const auto range_for = [&ranges](std::uint64_t address) -> std::optional<std::size_t> {
                        for (std::size_t index = 0; index < ranges.size(); ++index) {
                            if (address >= ranges[index].start && address < ranges[index].end)
                                return index;
                        }
                        return std::nullopt;
                    };
                    std::vector<std::unordered_set<std::uint64_t>> successors(ranges.size());
                    std::vector<std::unordered_set<std::uint64_t>> predecessors(ranges.size());
                    for (const auto& edge : snapshot->edges) {
                        const auto source = range_for(edge.source.value);
                        const auto target = range_for(edge.target.value);
                        if (!source || !target || *source == *target)
                            continue;
                        successors[*source].insert(ranges[*target].start);
                        predecessors[*target].insert(ranges[*source].start);
                    }
                    for (std::size_t index = 0; index < ranges.size(); ++index) {
                        std::vector<std::uint64_t> ordered_successors(
                            successors[index].begin(), successors[index].end());
                        std::vector<std::uint64_t> ordered_predecessors(
                            predecessors[index].begin(), predecessors[index].end());
                        std::sort(ordered_successors.begin(), ordered_successors.end());
                        std::sort(ordered_predecessors.begin(), ordered_predecessors.end());
                        for (const auto address : ordered_successors)
                            ranges[index].value["successors"].push_back(hex_addr(address));
                        for (const auto address : ordered_predecessors)
                            ranges[index].value["predecessors"].push_back(hex_addr(address));
                    }
                }
                for (auto& range : ranges)
                    output.push_back(std::move(range.value));
                return output;
            }

            static std::optional<std::pair<std::string, std::string>>
            wildcard_byte_pattern(std::string_view pattern)
            {
                std::string compact;
                compact.reserve(pattern.size());
                for (const unsigned char value : pattern) {
                    if (std::isspace(value) || value == '_' || value == '-')
                        continue;
                    if (!std::isxdigit(value) && value != '?')
                        return std::nullopt;
                    compact.push_back(static_cast<char>(value));
                }
                if (compact.empty() || (compact.size() & 1U) != 0U)
                    return std::nullopt;
                std::string bytes;
                std::string mask;
                for (std::size_t index = 0; index < compact.size(); index += 2U) {
                    if (!bytes.empty()) {
                        bytes.push_back(' ');
                        mask.push_back(' ');
                    }
                    const bool wildcard = compact[index] == '?' || compact[index + 1U] == '?';
                    bytes.append(wildcard ? "00" : compact.substr(index, 2U));
                    mask.append(wildcard ? "00" : "FF");
                }
                return std::pair<std::string, std::string>{
                    std::move(bytes), std::move(mask)};
            }

            struct wave_c_query_page_t final {
                std::vector<aida::analysis::search_hit_t> hits;
                std::uint64_t total = 0;
                bool total_is_exact = true;
                std::optional<aida::analysis::query_cursor_t> next;
            };

            struct wave_c_query_cursor_binding_t final {
                std::uint64_t sequence = 0;
            };

            static aida::analysis::workspace_error_t wave_c_query_error(
                std::string message, std::string phase)
            {
                return aida::analysis::make_workspace_error(
                    aida::analysis::workspace_error_code_t::invalid_argument,
                    std::move(message), std::move(phase));
            }

            static aida::analysis::workspace_result_t<
                aida::analysis::query_cursor_t> parse_query_cursor(const json& value)
            {
                if (!value.is_object())
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor must be an object.",
                                "mcp_wave_c_query_cursor"));
                const auto binary_id = value.contains("binary_id") &&
                        value.at("binary_id").is_string()
                    ? aida::analysis::binary_id_t::from_hex(
                        value.at("binary_id").get<std::string>())
                    : std::nullopt;
                const auto load_profile_hash = value.contains("load_profile_hash") &&
                        value.at("load_profile_hash").is_string()
                    ? aida::analysis::sha256_digest_t::from_hex(
                        value.at("load_profile_hash").get<std::string>())
                    : std::nullopt;
                std::optional<aida::analysis::sha256_digest_t> provider_content_hash;
                if (value.contains("provider_content_hash") &&
                    !value.at("provider_content_hash").is_null()) {
                    if (!value.at("provider_content_hash").is_string())
                        return aida::analysis::workspace_result_t<
                            aida::analysis::query_cursor_t>::failure(
                                wave_c_query_error(
                                    "Query cursor provider identity is invalid.",
                                    "mcp_wave_c_query_cursor"));
                    provider_content_hash = aida::analysis::sha256_digest_t::from_hex(
                        value.at("provider_content_hash").get<std::string>());
                    if (!provider_content_hash)
                        return aida::analysis::workspace_result_t<
                            aida::analysis::query_cursor_t>::failure(
                                wave_c_query_error(
                                    "Query cursor provider identity is invalid.",
                                    "mcp_wave_c_query_cursor"));
                }
                const auto generation = value.contains("generation")
                    ? json_nonnegative_u64(value.at("generation")) : std::nullopt;
                const auto analysis_revision = value.contains("analysis_revision")
                    ? json_nonnegative_u64(value.at("analysis_revision")) : std::nullopt;
                const auto overlay_revision = value.contains("overlay_revision")
                    ? json_nonnegative_u64(value.at("overlay_revision")) : std::nullopt;
                const auto provider_size = value.contains("provider_size")
                    ? json_nonnegative_u64(value.at("provider_size")) : std::nullopt;
                const auto query_fingerprint = value.contains("query_fingerprint")
                    ? json_nonnegative_u64(value.at("query_fingerprint")) : std::nullopt;
                const auto position = value.contains("position")
                    ? json_nonnegative_u64(value.at("position")) : std::nullopt;
                const auto matches_consumed = value.contains("matches_consumed")
                    ? json_nonnegative_u64(value.at("matches_consumed")) : std::nullopt;
                const auto integrity_tag = value.contains("integrity_tag")
                    ? json_nonnegative_u64(value.at("integrity_tag")) : std::nullopt;
                const auto next = value.contains("next")
                    ? json_nonnegative_u64(value.at("next")) : std::nullopt;
                if (!binary_id || !load_profile_hash || !generation ||
                    !analysis_revision || !overlay_revision || !provider_size ||
                    !query_fingerprint || !position || !matches_consumed ||
                    !integrity_tag || *generation == 0 || *integrity_tag == 0 ||
                    (value.contains("next") && (!next || *next != *position)) ||
                    (value.contains("done") &&
                     (!value.at("done").is_boolean() || value.at("done").get<bool>())) ||
                    (value.contains("cancelled") &&
                     (!value.at("cancelled").is_boolean() ||
                      value.at("cancelled").get<bool>()))) {
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor identity or integrity fields are invalid.",
                                "mcp_wave_c_query_cursor"));
                }
                aida::analysis::query_cursor_t cursor;
                cursor.generation.binary_id = *binary_id;
                cursor.generation.load_profile_hash = *load_profile_hash;
                cursor.generation.provider_content_hash = provider_content_hash;
                cursor.generation.generation = *generation;
                cursor.generation.analysis_revision = *analysis_revision;
                cursor.generation.overlay_revision = *overlay_revision;
                cursor.generation.provider_size = *provider_size;
                cursor.query_fingerprint = *query_fingerprint;
                cursor.position = *position;
                cursor.matches_consumed = *matches_consumed;
                cursor.integrity_tag = *integrity_tag;
                if (!cursor.generation.valid())
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor generation identity is incomplete.",
                                "mcp_wave_c_query_cursor"));
                return aida::analysis::workspace_result_t<
                    aida::analysis::query_cursor_t>::success(std::move(cursor));
            }

            static json query_cursor_response(const wave_c_query_page_t& page)
            {
                return json{
                    {"next", page.next ? json(page.next->position) : json(page.total)},
                    {"done", !page.next.has_value()},
                    {"cancelled", false},
                };
            }

            static const char* query_hit_kind_name(
                aida::analysis::search_entity_kind_t kind) noexcept
            {
                using kind_t = aida::analysis::search_entity_kind_t;
                switch (kind) {
                case kind_t::function: return "function";
                case kind_t::symbol: return "symbol";
                case kind_t::string: return "string";
                case kind_t::instruction: return "instruction";
                case kind_t::data_candidate: return "data";
                case kind_t::switch_dispatch: return "switch";
                case kind_t::type_candidate: return "type";
                case kind_t::byte_sequence: return "bytes";
                }
                return "unknown";
            }

            static bool query_address_is_executable(
                const aida::analysis::workspace_image_t* image,
                const aida::analysis::address_t& address) noexcept
            {
                if (!image)
                    return false;
                std::uint64_t rva = address.value;
                if (address.space ==
                        aida::analysis::address_space_id_t::virtual_address ||
                    address.space ==
                        aida::analysis::address_space_id_t::live_virtual) {
                    if (address.value < image->image_base)
                        return false;
                    rva = address.value - image->image_base;
                }
                const auto executable = [rva](const auto& region) {
                    return (region.permissions &
                            aida::analysis::image_permission_execute) != 0 &&
                        rva >= region.virtual_address &&
                        rva - region.virtual_address < region.virtual_size;
                };
                return std::any_of(
                           image->segments.begin(), image->segments.end(), executable) ||
                    std::any_of(
                           image->sections.begin(), image->sections.end(), executable);
            }

            bool validate_query_cursor_binding(
                std::uint64_t integrity_tag,
                std::string_view semantics) const
            {
                std::string key = std::to_string(integrity_tag);
                key.push_back('\0');
                key.append(semantics);
                std::lock_guard<std::mutex> lock(query_cursor_bindings_mutex_);
                return query_cursor_bindings_.find(key) !=
                    query_cursor_bindings_.end();
            }

            void remember_query_cursor_binding(
                std::uint64_t integrity_tag,
                std::string_view semantics) const
            {
                std::string key = std::to_string(integrity_tag);
                key.push_back('\0');
                key.append(semantics);
                std::lock_guard<std::mutex> lock(query_cursor_bindings_mutex_);
                auto found = query_cursor_bindings_.find(key);
                if (found == query_cursor_bindings_.end() &&
                    query_cursor_bindings_.size() >= k_query_cursor_binding_capacity) {
                    const auto oldest = (std::min_element)(
                        query_cursor_bindings_.begin(), query_cursor_bindings_.end(),
                        [](const auto& left, const auto& right) {
                            return left.second.sequence < right.second.sequence;
                        });
                    if (oldest != query_cursor_bindings_.end())
                        query_cursor_bindings_.erase(oldest);
                }
                if (query_cursor_binding_sequence_ ==
                    (std::numeric_limits<std::uint64_t>::max)()) {
                    query_cursor_binding_sequence_ = 0;
                    for (auto& entry : query_cursor_bindings_)
                        entry.second.sequence = 0;
                }
                const auto sequence = ++query_cursor_binding_sequence_;
                query_cursor_bindings_[std::move(key)] = {sequence};
            }

            aida::analysis::workspace_result_t<wave_c_query_page_t>
            execute_query_index(
                const workspace_request_context_t& context,
                const aida::analysis::search_query_t& query,
                std::uint64_t offset,
                std::uint64_t limit,
                const json* serialized_cursor,
                std::string_view route_semantics) const
            {
                const auto search = context.workspace->search_index();
                if (!search)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(
                            aida::analysis::make_workspace_error(
                                aida::analysis::workspace_error_code_t::provider_unavailable,
                                "Workspace search index is unavailable.",
                                "mcp_wave_c_query_index"));
                if (serialized_cursor && offset != 0)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(
                            wave_c_query_error(
                                "Query cursor and nonzero offset cannot be combined.",
                                "mcp_wave_c_query_index"));

                const auto deadline = wave_c_deadline(context);
                workspace_call_cancel_bridge_t cancellation(
                    deadline, context.cancellation);
                std::shared_ptr<const aida::analysis::provider_snapshot_t> provider;
                if (std::holds_alternative<
                        aida::analysis::byte_search_query_t>(query)) {
                    auto captured = aida::analysis::provider_snapshot_t::capture(
                        context.workspace->provider_handle(), search->generation(),
                        cancellation.token());
                    if (!captured)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(captured.error());
                    provider = captured.take_value();
                }
                auto built = aida::analysis::query_index_t::build(
                    search, std::move(provider));
                if (!built)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(built.error());
                auto index = built.take_value();

                std::optional<aida::analysis::query_cursor_t> cursor;
                if (serialized_cursor) {
                    auto parsed = parse_query_cursor(*serialized_cursor);
                    if (!parsed)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(parsed.error());
                    cursor = parsed.take_value();
                    if (!validate_query_cursor_binding(
                            cursor->integrity_tag, route_semantics)) {
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(
                                wave_c_query_error(
                                    "Query cursor is not valid for this route request.",
                                    "mcp_wave_c_query_cursor_binding"));
                    }
                }

                wave_c_query_page_t output;
                bool source_exhausted = false;
                std::uint64_t skip = offset;
                while (skip != 0) {
                    aida::analysis::query_page_request_t request;
                    request.limit = static_cast<std::uint32_t>((std::min)(
                        skip, static_cast<std::uint64_t>(index->limits().max_page_size)));
                    request.cursor = cursor;
                    auto page = index->query(query, request, cancellation.token());
                    if (!page)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(page.error());
                    auto value = page.take_value();
                    output.total = value.total;
                    output.total_is_exact = value.total_is_exact;
                    const auto consumed = static_cast<std::uint64_t>(value.hits.size());
                    skip = consumed >= skip ? 0 : skip - consumed;
                    cursor = value.next;
                    if (!cursor) {
                        source_exhausted = true;
                        break;
                    }
                }

                std::uint64_t remaining = limit;
                while (!source_exhausted && remaining != 0) {
                    aida::analysis::query_page_request_t request;
                    request.limit = static_cast<std::uint32_t>((std::min)(
                        remaining,
                        static_cast<std::uint64_t>(index->limits().max_page_size)));
                    request.cursor = cursor;
                    auto page = index->query(query, request, cancellation.token());
                    if (!page)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(page.error());
                    auto value = page.take_value();
                    output.total = value.total;
                    output.total_is_exact = value.total_is_exact;
                    const auto returned = static_cast<std::uint64_t>(value.hits.size());
                    output.hits.insert(
                        output.hits.end(),
                        std::make_move_iterator(value.hits.begin()),
                        std::make_move_iterator(value.hits.end()));
                    remaining = returned >= remaining ? 0 : remaining - returned;
                    cursor = value.next;
                    if (!cursor)
                        source_exhausted = true;
                }
                output.next = source_exhausted ? std::nullopt : cursor;
                if (output.next) {
                    remember_query_cursor_binding(
                        output.next->integrity_tag, route_semantics);
                }
                return aida::analysis::workspace_result_t<
                    wave_c_query_page_t>::success(std::move(output));
            }

            tool_result_t invoke_analysis_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                const auto cancelled = [&context]() {
                    return context.cancellation_requested() ||
                        (context.deadline_ms != 0 &&
                         static_cast<std::uint64_t>(GetTickCount64()) >=
                             context.deadline_ms);
                };
                if (name == "decompile") {
                    const auto legacy = invoke_legacy(
                        "decompile", json{{"address", arguments.at("addr")}}, context);
                    if (!legacy.success)
                        return tool_result_t::ok(json{
                            {"addr", arguments.at("addr")}, {"code", nullptr},
                            {"error", backend_error(legacy)}});
                    std::string code = legacy.data.value(
                        "pseudocode", std::string());
                    if (arguments.value("include_addresses", true) &&
                        legacy.data.contains("source_mappings") &&
                        legacy.data["source_mappings"].is_array()) {
                        constexpr std::size_t maximum_code_bytes = 512U * 1024U;
                        const auto& mappings = legacy.data["source_mappings"];
                        std::vector<std::size_t> line_starts;
                        std::vector<std::size_t> line_ends;
                        for (std::size_t begin = 0; begin < code.size();) {
                            if (cancelled())
                                return tool_result_t::error(
                                    "Decompile address annotation was interrupted.",
                                    std::string(context.cancellation_requested()
                                        ? "CANCELLED" : "DEADLINE_EXCEEDED"));
                            const auto newline = code.find('\n', begin);
                            line_starts.push_back(begin);
                            line_ends.push_back(newline == std::string::npos
                                ? code.size() : newline);
                            if (newline == std::string::npos) break;
                            begin = newline + 1U;
                        }
                        std::vector<std::string> line_addresses(line_starts.size());
                        std::vector<std::size_t> next_unassigned(
                            line_starts.size() + 1U);
                        std::iota(next_unassigned.begin(), next_unassigned.end(), 0U);
                        const auto find_unassigned = [&next_unassigned](
                            std::size_t index) {
                            std::size_t root = index;
                            while (next_unassigned[root] != root)
                                root = next_unassigned[root];
                            while (next_unassigned[index] != index) {
                                const auto parent = next_unassigned[index];
                                next_unassigned[index] = root;
                                index = parent;
                            }
                            return root;
                        };
                        std::size_t mapping_ordinal = 0;
                        for (const auto& mapping : mappings) {
                            if ((mapping_ordinal++ & 0x3FU) == 0U && cancelled())
                                return tool_result_t::error(
                                    "Decompile address annotation was interrupted.",
                                    std::string(context.cancellation_requested()
                                        ? "CANCELLED" : "DEADLINE_EXCEEDED"));
                            if (!mapping.is_object() ||
                                !mapping.contains("address") ||
                                !mapping["address"].is_string())
                                continue;
                            const auto begin = mapping.value(
                                "begin", (std::numeric_limits<std::uint64_t>::max)());
                            const auto end = mapping.value("end", std::uint64_t{0});
                            if (begin >= end || begin >= code.size() ||
                                line_starts.empty())
                                continue;
                            const auto upper = std::upper_bound(
                                line_starts.begin(), line_starts.end(),
                                static_cast<std::size_t>(begin));
                            std::size_t line = upper == line_starts.begin()
                                ? 0U : static_cast<std::size_t>(
                                    std::distance(line_starts.begin(), upper) - 1);
                            while (line < line_ends.size() &&
                                   line_ends[line] <= begin)
                                ++line;
                            line = find_unassigned(line);
                            while (line < line_starts.size() &&
                                   line_starts[line] < end) {
                                line_addresses[line] =
                                    mapping["address"].get<std::string>();
                                next_unassigned[line] = find_unassigned(line + 1U);
                                line = find_unassigned(line);
                            }
                            if (find_unassigned(0) == line_starts.size()) break;
                        }
                        std::string marked;
                        marked.reserve((std::min)(maximum_code_bytes,
                            code.size() + mappings.size() * 16U));
                        for (std::size_t line = 0;
                             line < line_starts.size() &&
                             marked.size() < maximum_code_bytes; ++line) {
                            if ((line & 0x3FU) == 0U && cancelled())
                                return tool_result_t::error(
                                    "Decompile address annotation was interrupted.",
                                    std::string(context.cancellation_requested()
                                        ? "CANCELLED" : "DEADLINE_EXCEEDED"));
                            const auto line_begin = line_starts[line];
                            const auto line_end = line_ends[line];
                            const auto available = maximum_code_bytes - marked.size();
                            const auto line_size = (std::min)(
                                line_end - line_begin, available);
                            marked.append(code, line_begin, line_size);
                            if (line_size != line_end - line_begin) break;
                            if (!line_addresses[line].empty()) {
                                const std::string marker =
                                    " /*" + line_addresses[line] + "*/";
                                if (marker.size() <= maximum_code_bytes - marked.size())
                                    marked += marker;
                            }
                            if (line + 1U < line_starts.size() &&
                                marked.size() < maximum_code_bytes)
                                marked.push_back('\n');
                        }
                        code = std::move(marked);
                    }
                    json refs = json::array();
                    for (const auto& callee : legacy.data.value("callees", json::array())) {
                        refs.push_back({
                            {"addr", callee.value("address", std::string())},
                            {"name", callee.value("name", std::string())},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"addr", legacy.data.value(
                            "address", arguments.at("addr").get<std::string>())},
                        {"code", std::move(code)},
                        {"refs", std::move(refs)},
                    });
                }

                if (name == "disasm") {
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto maximum = arguments.value("max_instructions", std::uint64_t{5000});
                    const auto requested = offset > (std::numeric_limits<std::uint64_t>::max)() - maximum
                        ? (std::numeric_limits<std::uint64_t>::max)() : offset + maximum;
                    const auto legacy = invoke_legacy(
                        "disasm", json{{"address", arguments.at("addr")},
                                   {"max_instructions", (std::min)(requested, std::uint64_t{4096})}},
                        context);
                    if (!legacy.success)
                        return tool_result_t::ok(json{
                            {"addr", arguments.at("addr")}, {"asm", nullptr},
                            {"error", backend_error(legacy)}});
                    const auto function = first_generated_function(
                        lookup_analysis_function(arguments.at("addr"), context));
                    json lines = json::array();
                    const auto instructions = legacy.data.value("instructions", json::array());
                    const std::size_t begin = (std::min)(
                        static_cast<std::size_t>(offset), instructions.size());
                    const std::size_t end = (std::min)(
                        instructions.size(), begin + static_cast<std::size_t>(maximum));
                    for (std::size_t index = begin; index < end; ++index) {
                        const auto& instruction = instructions[index];
                        json line{
                            {"addr", instruction.value("address", std::string())},
                            {"instruction", instruction.value(
                                "text", "db " + instruction.value("bytes", std::string()))},
                        };
                        if (const auto comment = instruction.find("comment");
                            comment != instruction.end() && comment->is_string())
                            line["comments"] = json::array({*comment});
                        lines.push_back(std::move(line));
                    }
                    const bool done = end >= instructions.size() &&
                        legacy.data.value("termination", std::string()) == "completed";
                    json assembly{
                        {"name", function ? function->value("name", std::string()) :
                            arguments.at("addr").get<std::string>()},
                        {"start_ea", function ? function->value("addr", std::string()) :
                            arguments.at("addr").get<std::string>()},
                        {"lines", std::move(lines)},
                    };
                    return tool_result_t::ok(json{
                        {"addr", assembly.at("start_ea")}, {"asm", std::move(assembly)},
                        {"instruction_count", end - begin},
                        {"total_instructions", arguments.value("include_total", false)
                            ? json(instructions.size()) : json(nullptr)},
                        {"cursor", json{{"next", end}, {"done", done}, {"cancelled", false}}},
                    });
                }

                if (name == "xrefs_to") {
                    json output = json::array();
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto legacy = invoke_legacy(
                            "xrefs_to", json{{"address", target},
                                       {"limit", arguments.value("limit", 100U)}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json xrefs = json::array();
                            for (const auto& value : legacy.data.value("xrefs", json::array()))
                                xrefs.push_back(generated_xref(value));
                            item["xref_count"] = xrefs.size();
                            item["more"] = xrefs.size() >= arguments.value("limit", 100U);
                            item["xrefs"] = std::move(xrefs);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "xrefs_to_field") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto legacy = invoke_legacy(
                            "xrefs_to_field", json{{"struct_name", query.at("struct")},
                                       {"field_name", query.at("field")}}, context);
                        json item{{"struct", query.at("struct")}, {"field", query.at("field")}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json xrefs = json::array();
                            for (const auto& value : legacy.data.value("xrefs", json::array()))
                                xrefs.push_back(generated_xref(value));
                            item["xrefs"] = std::move(xrefs);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "callees") {
                    json output = json::array();
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto legacy = invoke_legacy(
                            "callees", json{{"address", target}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json callees = json::array();
                            for (const auto& value : legacy.data.value("callees", json::array())) {
                                callees.push_back({
                                    {"addr", value.value("address", std::string())},
                                    {"name", value.value(
                                        "name", value.value("address", std::string()))},
                                    {"type", value.value("kind", "call")},
                                });
                                if (callees.size() >= arguments.value("limit", 200U))
                                    break;
                            }
                            item["callees"] = std::move(callees);
                            item["more"] = legacy.data.value("count", 0U) >
                                arguments.value("limit", 200U);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "func_profile") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::string target = query.value("addr", "*");
                        std::vector<json> functions;
                        std::string error;
                        if (!target.empty() && target != "*") {
                            const auto lookup = lookup_analysis_function(target, context);
                            if (!lookup.success) {
                                error = backend_error(lookup);
                            } else {
                                for (const auto& value : lookup.data.value("functions", json::array()))
                                    functions.push_back(value);
                            }
                        } else {
                            const auto listed = invoke_legacy(
                                "list_funcs", json{{"offset", 0}, {"limit", 10000},
                                                   {"filter", query.value("filter", std::string())}},
                                context);
                            if (!listed.success)
                                error = backend_error(listed);
                            else
                                for (const auto& value : listed.data.value("functions", json::array()))
                                    functions.push_back(value);
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(functions.begin(), functions.end(), [&sort_by](const json& lhs, const json& rhs) {
                            if (sort_by == "name")
                                return lhs.value("name", std::string()) < rhs.value("name", std::string());
                            if (sort_by == "size")
                                return json_nonnegative_u64(lhs.value("size", json(0))).value_or(0) <
                                    json_nonnegative_u64(rhs.value("size", json(0))).value_or(0);
                            return lhs.value("address", std::string()) < rhs.value("address", std::string());
                        });
                        if (query.value("descending", false))
                            std::reverse(functions.begin(), functions.end());
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 100, 10000));
                        const std::size_t begin = (std::min)(offset, functions.size());
                        const std::size_t end = (std::min)(functions.size(), begin + count);
                        json data = json::array();
                        for (std::size_t index = begin; index < end; ++index) {
                            const auto& value = functions[index];
                            auto item = generated_function_summary(value);
                            item["basic_block_count"] = value.value("blocks", 0U);
                            item["has_type"] = false;
                            item["error"] = nullptr;
                            if (query.value("include_prototype", false)) {
                                const auto prototype = overlay_type_at(
                                    context, item.value("addr", std::string()));
                                item["prototype"] = prototype ? json(*prototype) : json(nullptr);
                                item["has_type"] = prototype.has_value();
                            }
                            if (query.value("include_lists", false)) {
                                const auto maximum = query.value("max_items", 100U);
                                const auto related = invoke_legacy(
                                    "callees", json{{"address", item.at("addr")}}, context);
                                json callees = json::array();
                                if (related.success) {
                                    for (const auto& callee : related.data.value("callees", json::array())) {
                                        callees.push_back(callee);
                                        if (callees.size() >= maximum)
                                            break;
                                    }
                                }
                                item["callees"] = std::move(callees);
                                item["callee_count"] = item["callees"].size();
                                item["callees_truncated"] = related.success &&
                                    related.data.value("count", 0U) > maximum;
                                item["callers"] = json::array();
                                item["caller_count"] = 0;
                                item["callers_truncated"] = false;
                                item["strings"] = json::array();
                                item["string_ref_count"] = 0;
                                item["strings_truncated"] = false;
                                item["constants"] = json::array();
                                item["constant_count"] = 0;
                                item["constants_truncated"] = false;
                            }
                            data.push_back(std::move(item));
                        }
                        output.push_back({
                            {"target", target}, {"data", std::move(data)},
                            {"next_offset", end < functions.size() ? json(end) : json(nullptr)},
                            {"error", error.empty() ? json(nullptr) : json(error)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "analyze_batch") {
                    json output = json::array();
                    const auto snapshot = context.workspace->snapshot();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::string target = query.at("addr").get<std::string>();
                        const auto lookup = lookup_analysis_function(query.at("addr"), context);
                        const auto function = first_generated_function(lookup);
                        if (!function) {
                            if (query.value("include_decompile", false) &&
                                managed_decompiler_selector(query.at("addr"))) {
                                const auto decompiled = invoke_legacy(
                                    "decompile",
                                    json{{"address", query.at("addr")}}, context);
                                if (!decompiled.success) {
                                    output.push_back({
                                        {"target", target}, {"addr", nullptr},
                                        {"name", nullptr}, {"analysis", nullptr},
                                        {"error", backend_error(decompiled)},
                                    });
                                    continue;
                                }
                                json analysis{
                                    {"decompile", decompiled.data.value(
                                        "pseudocode", std::string())},
                                    {"decompile_error", nullptr},
                                    {"size", decompiled.data.value(
                                        "size", std::string("0"))},
                                };
                                std::vector<std::string> unavailable_sections;
                                if (query.value("include_proto", false))
                                    analysis["prototype"] = decompiled.data.contains("prototype")
                                        ? decompiled.data.at("prototype") : json(nullptr);
                                if (query.value("include_basic_blocks", false)) {
                                    analysis["basic_blocks"] = nullptr;
                                    unavailable_sections.emplace_back("basic_blocks");
                                }
                                if (query.value("include_callees", false)) {
                                    analysis["callees"] = nullptr;
                                    unavailable_sections.emplace_back("callees");
                                }
                                if (query.value("include_callers", false)) {
                                    analysis["callers"] = nullptr;
                                    unavailable_sections.emplace_back("callers");
                                }
                                if (query.value("include_xrefs", false)) {
                                    analysis["xrefs"] = nullptr;
                                    unavailable_sections.emplace_back("xrefs");
                                }
                                if (query.value("include_disasm", false)) {
                                    analysis["disasm"] = nullptr;
                                    unavailable_sections.emplace_back("disasm");
                                }
                                if (query.value("include_strings", false)) {
                                    analysis["strings"] = nullptr;
                                    unavailable_sections.emplace_back("strings");
                                }
                                if (query.value("include_constants", false)) {
                                    analysis["constants"] = nullptr;
                                    unavailable_sections.emplace_back("constants");
                                }
                                std::string section_error;
                                for (const auto& section : unavailable_sections) {
                                    if (!section_error.empty()) section_error.push_back(',');
                                    section_error += section;
                                }
                                if (!section_error.empty())
                                    section_error.insert(0,
                                        "managed_sections_unavailable:");
                                output.push_back({
                                    {"target", target},
                                    {"addr", decompiled.data.value(
                                        "address", target)},
                                    {"name", decompiled.data.value(
                                        "name", target)},
                                    {"analysis", std::move(analysis)},
                                    {"error", section_error.empty()
                                        ? json(nullptr) : json(section_error)},
                                });
                                continue;
                            }
                            output.push_back({
                                {"target", target}, {"addr", nullptr}, {"name", nullptr},
                                {"analysis", nullptr},
                                {"error", lookup.success
                                    ? std::string("function_not_found") : backend_error(lookup)},
                            });
                            continue;
                        }
                        json analysis{{"size", function->at("size")}};
                        if (query.value("include_proto", false)) {
                            const auto prototype = overlay_type_at(
                                context, function->value("addr", std::string()));
                            analysis["prototype"] = prototype ? json(*prototype) : json(nullptr);
                        }
                        if (query.value("include_basic_blocks", false)) {
                            const auto blocks = invoke_legacy(
                                "basic_blocks", json{{"address", function->at("addr")}}, context);
                            if (blocks.success) {
                                json values = generated_basic_blocks(
                                    blocks.data.value("blocks", json::array()), snapshot);
                                const auto maximum = query.value("max_blocks", 1000U);
                                const bool truncated = values.size() > maximum;
                                while (values.size() > maximum)
                                    values.erase(values.end() - 1);
                                analysis["basic_block_count"] = values.size();
                                analysis["basic_blocks"] = std::move(values);
                                analysis["basic_blocks_truncated"] = truncated;
                            } else {
                                analysis["basic_blocks"] = nullptr;
                            }
                        }
                        if (query.value("include_callees", false)) {
                            const auto related = invoke_legacy(
                                "callees", json{{"address", function->at("addr")}}, context);
                            json values = related.success
                                ? related.data.value("callees", json::array()) : json::array();
                            const auto maximum = query.value("max_callees", 200U);
                            const bool truncated = values.size() > maximum;
                            while (values.size() > maximum)
                                values.erase(values.end() - 1);
                            analysis["callees"] = std::move(values);
                            analysis["callee_count"] = analysis["callees"].size();
                            analysis["callees_truncated"] = truncated;
                        }
                        if (query.value("include_callers", false) ||
                            query.value("include_xrefs", false)) {
                            const auto incoming = invoke_legacy(
                                "xrefs_to", json{{"address", function->at("addr")},
                                                 {"limit", query.value("max_callers", 200U)}},
                                context);
                            json values = incoming.success
                                ? incoming.data.value("xrefs", json::array()) : json::array();
                            if (query.value("include_callers", false)) {
                                analysis["callers"] = values;
                                analysis["caller_count"] = values.size();
                                analysis["callers_truncated"] = incoming.success &&
                                    incoming.data.value("count", 0U) > values.size();
                            }
                            if (query.value("include_xrefs", false)) {
                                analysis["xrefs"] = {
                                    {"to", values}, {"from", json::array()},
                                    {"to_truncated", false}, {"from_truncated", false},
                                    {"to_count", values.size()}, {"from_count", 0},
                                };
                            }
                        }
                        if (query.value("include_decompile", false)) {
                            const auto decompiled = invoke_legacy(
                                "decompile", json{{"address", function->at("addr")}}, context);
                            analysis["decompile"] = decompiled.success
                                ? json(decompiled.data.value("pseudocode", std::string())) : json(nullptr);
                            analysis["decompile_error"] = decompiled.success
                                ? json(nullptr) : json(backend_error(decompiled));
                        }
                        if (query.value("include_disasm", false)) {
                            const auto disassembled = invoke_legacy(
                                "disasm", json{{"address", function->at("addr")},
                                               {"max_instructions", query.value(
                                                   "max_disasm_insns", 1000U)}}, context);
                            if (disassembled.success) {
                                json lines = json::array();
                                for (const auto& instruction :
                                     disassembled.data.value("instructions", json::array()))
                                    lines.push_back(instruction.value(
                                        "text", "db " + instruction.value("bytes", std::string())));
                                analysis["disasm"] = {
                                    {"lines", std::move(lines)},
                                    {"instruction_count", disassembled.data.value("count", 0U)},
                                    {"truncated", disassembled.data.value(
                                        "termination", std::string()) != "completed"},
                                };
                            } else {
                                analysis["disasm"] = nullptr;
                            }
                        }
                        if (query.value("include_strings", false)) {
                            analysis["strings"] = json::array();
                            analysis["string_ref_count"] = 0;
                            analysis["strings_truncated"] = false;
                        }
                        if (query.value("include_constants", false)) {
                            analysis["constants"] = json::array();
                            analysis["constant_count"] = 0;
                            analysis["constants_truncated"] = false;
                        }
                        output.push_back({
                            {"target", target}, {"addr", function->at("addr")},
                            {"name", function->at("name")}, {"analysis", std::move(analysis)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "xref_query") {
                    const auto snapshot = context.workspace->snapshot();
                    if (!snapshot)
                        return tool_result_t::error(
                            "Xref query requires an analysis snapshot.", std::string("NO_SNAPSHOT"));
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::string target = query.at("addr").get<std::string>();
                        auto address = wave_c_address_value(query.at("addr"));
                        if (!address) {
                            const auto function = first_generated_function(
                                lookup_analysis_function(query.at("addr"), context));
                            if (function)
                                address = wave_c_address_value(function->at("addr"));
                        }
                        if (!address) {
                            output.push_back({
                                {"target", target}, {"resolved_addr", nullptr},
                                {"data", json::array()}, {"total", 0},
                                {"next_offset", nullptr}, {"error", "target_not_found"},
                            });
                            continue;
                        }
                        const std::string direction = query.value("direction", "both");
                        const std::string type_filter = query.value("xref_type", "any");
                        std::vector<json> matches;
                        for (const auto& xref : snapshot->xrefs) {
                            const bool incoming = xref.target.value == *address;
                            const bool outgoing = xref.source.value == *address;
                            if ((direction == "to" && !incoming) ||
                                (direction == "from" && !outgoing) ||
                                (direction == "both" && !incoming && !outgoing))
                                continue;
                            if ((type_filter == "code" && !code_xref(xref.kind)) ||
                                (type_filter == "data" && code_xref(xref.kind)))
                                continue;
                            const std::string from = hex_addr(xref.source.value);
                            const std::string to = hex_addr(xref.target.value);
                            matches.push_back({
                                {"addr", incoming ? from : to}, {"from", from}, {"to", to},
                                {"type", xref_kind_name(xref.kind)},
                                {"direction", incoming ? "to" : "from"}, {"fn", nullptr},
                            });
                        }
                        if (query.value("dedup", false)) {
                            std::unordered_set<std::string> seen;
                            matches.erase(std::remove_if(matches.begin(), matches.end(), [&seen](const json& value) {
                                return !seen.insert(value.at("addr").get<std::string>() + "\n" +
                                    value.at("type").get<std::string>()).second;
                            }), matches.end());
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(matches.begin(), matches.end(), [&sort_by](const json& lhs, const json& rhs) {
                            return lhs.at(sort_by == "type" ? "type" : "addr").get<std::string>() <
                                rhs.at(sort_by == "type" ? "type" : "addr").get<std::string>();
                        });
                        if (query.value("descending", false))
                            std::reverse(matches.begin(), matches.end());
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 200, 5000));
                        const std::size_t begin = (std::min)(offset, matches.size());
                        const std::size_t end = (std::min)(matches.size(), begin + count);
                        json data = json::array();
                        for (std::size_t index = begin; index < end; ++index)
                            data.push_back(matches[index]);
                        output.push_back({
                            {"target", target}, {"resolved_addr", hex_addr(*address)},
                            {"direction", direction}, {"xref_type", type_filter},
                            {"data", std::move(data)}, {"total", matches.size()},
                            {"next_offset", end < matches.size() ? json(end) : json(nullptr)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find_bytes") {
                    json output = json::array();
                    const auto limit = arguments.value("limit", std::uint64_t{1000});
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto patterns = scalar_or_array_items(arguments.at("patterns"));
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end()) {
                        if (patterns.size() != 1)
                            return tool_result_t::error(
                                "A find_bytes cursor requires exactly one pattern.",
                                std::string("INVALID_QUERY_CURSOR"));
                        cursor = &*found;
                    }
                    for (const auto& pattern_value : patterns) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::string pattern = pattern_value.get<std::string>();
                        const auto translated = wildcard_byte_pattern(pattern);
                        if (!translated) {
                            output.push_back({
                                {"pattern", pattern}, {"matches", json::array()}, {"n", 0},
                                {"error", "invalid_byte_pattern"},
                            });
                            continue;
                        }
                        const auto bytes = decode_hex_bytes(translated->first);
                        const auto mask = decode_hex_bytes(translated->second);
                        if (!bytes || !mask)
                            return tool_result_t::error(
                                "Byte pattern normalization failed.",
                                std::string("INVALID_BYTE_PATTERN"));
                        aida::analysis::byte_search_query_t query;
                        query.pattern = *bytes;
                        query.mask = *mask;
                        const std::string route_semantics = json{
                            {"tool", "find_bytes"}, {"pattern", pattern}}.dump();
                        auto queried = execute_query_index(
                            context, aida::analysis::search_query_t{std::move(query)},
                            offset, limit, cursor, route_semantics);
                        if (!queried)
                            return workspace_tool_error(queried.error());
                        auto page = queried.take_value();
                        json matches = json::array();
                        for (const auto& hit : page.hits)
                            matches.push_back(hex_addr(hit.address.value));
                        output.push_back({
                            {"pattern", pattern}, {"n", matches.size()}, {"matches", matches},
                            {"cursor", query_cursor_response(page)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "basic_blocks") {
                    json output = json::array();
                    const auto snapshot = context.workspace->snapshot();
                    const std::size_t offset = arguments.value("offset", std::size_t{0});
                    const std::size_t maximum = arguments.value("max_blocks", std::size_t{1000});
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto legacy = invoke_legacy(
                            "basic_blocks", json{{"address", target}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            const json all_blocks = generated_basic_blocks(
                                legacy.data.value("blocks", json::array()), snapshot);
                            const std::size_t begin = (std::min)(offset, all_blocks.size());
                            const std::size_t end = (std::min)(all_blocks.size(), begin + maximum);
                            json blocks = json::array();
                            for (std::size_t index = begin; index < end; ++index)
                                blocks.push_back(all_blocks[index]);
                            item["blocks"] = std::move(blocks);
                            item["count"] = item["blocks"].size();
                            item["total_blocks"] = all_blocks.size();
                            item["cursor"] = {
                                {"next", end}, {"done", end >= all_blocks.size()},
                                {"cancelled", false},
                            };
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find") {
                    json output = json::array();
                    const std::string search_type = arguments.at("type").get<std::string>();
                    const auto limit = arguments.value("limit", std::uint64_t{1000});
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto snapshot = context.workspace->snapshot();
                    const auto targets = scalar_or_array_items(arguments.at("targets"));
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end()) {
                        if (targets.size() != 1)
                            return tool_result_t::error(
                                "A find cursor requires exactly one target.",
                                std::string("INVALID_QUERY_CURSOR"));
                        cursor = &*found;
                    }
                    for (const auto& target : targets) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::string route_semantics = json{
                            {"tool", "find"}, {"type", search_type},
                            {"target", target}}.dump();
                        json matches = json::array();
                        wave_c_query_page_t page;
                        if (search_type == "data_ref" || search_type == "code_ref") {
                            const auto address = wave_c_address_value(target);
                            if (!address || !snapshot) {
                                return tool_result_t::error(
                                    address ? "Analysis snapshot is unavailable." :
                                        "Reference target is invalid.",
                                    std::string(address ? "NO_SNAPSHOT" : "INVALID_REFERENCE_TARGET"));
                            }
                            std::unordered_set<std::uint64_t> sources;
                            for (const auto& xref : snapshot->xrefs) {
                                if (xref.target.value == *address &&
                                    (search_type == "code_ref") == code_xref(xref.kind))
                                    sources.insert(xref.source.value);
                            }
                            if (sources.empty()) {
                                if (cursor)
                                    return tool_result_t::error(
                                        "Reference query cursor has no current source set.",
                                        std::string("INVALID_QUERY_CURSOR"));
                            } else {
                                const auto bounds = (std::minmax_element)(
                                    sources.begin(), sources.end());
                                if (*bounds.second ==
                                    (std::numeric_limits<std::uint64_t>::max)()) {
                                    return tool_result_t::error(
                                        "Reference sources cannot be represented as an address range.",
                                        std::string("INVALID_REFERENCE_TARGET"));
                                }
                                aida::analysis::address_search_query_t address_query;
                                address_query.begin = {
                                    aida::analysis::address_space_id_t::relative_virtual,
                                    *bounds.first,
                                    context.workspace->identity().architecture(),
                                    context.workspace->identity().architecture_mode(),
                                };
                                address_query.end = address_query.begin;
                                address_query.end.value = *bounds.second + 1U;
                                auto queried = execute_query_index(
                                    context,
                                    aida::analysis::search_query_t{address_query},
                                    offset, limit, cursor, route_semantics);
                                if (!queried)
                                    return workspace_tool_error(queried.error());
                                page = queried.take_value();
                                std::unordered_set<std::uint64_t> emitted;
                                for (const auto& hit : page.hits) {
                                    if (sources.find(hit.address.value) != sources.end() &&
                                        emitted.insert(hit.address.value).second) {
                                        matches.push_back(hex_addr(hit.address.value));
                                    }
                                }
                            }
                        } else {
                            aida::analysis::search_query_t query;
                            if (search_type == "string") {
                                aida::analysis::literal_search_query_t literal;
                                literal.text = target.is_string()
                                    ? target.get<std::string>() : target.dump();
                                literal.case_sensitive = false;
                                query = std::move(literal);
                            } else {
                                const auto immediate = wave_c_address_value(target);
                                if (!immediate)
                                    return tool_result_t::error(
                                        "Immediate search target is invalid.",
                                        std::string("INVALID_IMMEDIATE_TARGET"));
                                aida::analysis::instruction_search_query_t instruction;
                                instruction.filter.immediate = *immediate;
                                query = std::move(instruction);
                            }
                            auto queried = execute_query_index(
                                context, query, offset, limit, cursor,
                                route_semantics);
                            if (!queried)
                                return workspace_tool_error(queried.error());
                            page = queried.take_value();
                            for (const auto& hit : page.hits) {
                                if (search_type == "string" && hit.kind !=
                                    aida::analysis::search_entity_kind_t::string)
                                    continue;
                                matches.push_back(hex_addr(hit.address.value));
                            }
                        }
                        output.push_back({
                            {"query", target}, {"matches", matches}, {"count", matches.size()},
                            {"cursor", query_cursor_response(page)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "insn_query") {
                    const auto snapshot = context.workspace->snapshot();
                    if (!snapshot)
                        return tool_result_t::error(
                            "Instruction query requires an analysis snapshot.", std::string("NO_SNAPSHOT"));
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 100, 5000));
                        std::optional<std::uint64_t> range_start;
                        std::optional<std::uint64_t> range_end;
                        if (const auto start = query.find("start"); start != query.end())
                            range_start = wave_c_address_value(*start);
                        if (const auto end = query.find("end"); end != query.end())
                            range_end = wave_c_address_value(*end);
                        if (const auto function = query.find("func");
                            function != query.end() && function->is_string()) {
                            const auto resolved = first_generated_function(
                                lookup_analysis_function(*function, context));
                            if (resolved) {
                                range_start = wave_c_address_value(resolved->at("addr"));
                                const auto size = wave_c_address_value(resolved->at("size"));
                                if (range_start && size && *size <=
                                    (std::numeric_limits<std::uint64_t>::max)() - *range_start)
                                    range_end = *range_start + *size;
                            }
                        }
                        json raw_matches = json::array();
                        std::size_t scanned = 0;
                        bool truncated = false;
                        std::string error;
                        const std::string mnemonic = query.value("mnem", std::string());
                        if (!mnemonic.empty()) {
                            std::string operand;
                            for (const char* field : {"op_any", "op0", "op1", "op2"}) {
                                const auto found = query.find(field);
                                if (found != query.end()) {
                                    operand = found->is_string()
                                        ? found->get<std::string>() : found->dump();
                                    break;
                                }
                            }
                            const auto legacy = invoke_legacy(
                                "find_insns", json{{"mnemonic", mnemonic},
                                                   {"operand_pattern", operand}, {"offset", 0},
                                                   {"limit", query.value("max_scan_insns", 50000U)}},
                                context);
                            if (!legacy.success) {
                                error = backend_error(legacy);
                            } else {
                                raw_matches = legacy.data.value("results", json::array());
                                scanned = legacy.data.value(
                                    "formatted", legacy.data.value("count", std::size_t{0}));
                                truncated = legacy.data.value("format_scan_truncated", false);
                            }
                        } else {
                            scanned = snapshot->instructions.size();
                            for (const auto& instruction : snapshot->instructions) {
                                raw_matches.push_back({
                                    {"address", hex_addr(instruction.address.value)},
                                    {"mnemonic_id", instruction.mnemonic_id},
                                });
                            }
                        }
                        json filtered = json::array();
                        for (const auto& value : raw_matches) {
                            const auto address = wave_c_address_value(
                                value.value("address", json()));
                            if (!address || (range_start && *address < *range_start) ||
                                (range_end && *address >= *range_end))
                                continue;
                            filtered.push_back(value);
                        }
                        const std::size_t begin = (std::min)(offset, filtered.size());
                        const std::size_t end = (std::min)(filtered.size(), begin + count);
                        json matches = json::array();
                        for (std::size_t index = begin; index < end; ++index) {
                            const auto& value = filtered[index];
                            json match{{"addr", value.value("address", std::string())}};
                            if (query.value("include_disasm", false))
                                match["disasm"] = value.value("text", std::string());
                            if (query.value("include_fn", false)) {
                                const auto function = first_generated_function(
                                    lookup_analysis_function(match.at("addr"), context));
                                match["fn"] = function ? json(*function) : json(nullptr);
                            }
                            matches.push_back(std::move(match));
                        }
                        json normalized_query = json::object();
                        for (const char* field : {
                                 "allow_broad", "count", "end", "func", "max_scan_insns",
                                 "mnem", "offset", "op0", "op1", "op2", "op_any",
                                 "segment", "start"}) {
                            if (query.contains(field))
                                normalized_query[field] = query.at(field);
                        }
                        json ranges = json::array();
                        if (range_start && range_end)
                            ranges.push_back({
                                {"start", hex_addr(*range_start)}, {"end", hex_addr(*range_end)}});
                        output.push_back({
                            {"query", std::move(normalized_query)}, {"matches", std::move(matches)},
                            {"count", end - begin}, {"scanned", scanned}, {"ranges", std::move(ranges)},
                            {"truncated", truncated || end < filtered.size()},
                            {"next_start", end < filtered.size()
                                ? json(filtered[end].value("address", std::string())) : json(nullptr)},
                            {"cursor", json{{"next", end}, {"done", end >= filtered.size()},
                                             {"cancelled", false}}},
                            {"error", error.empty() ? json(nullptr) : json(error)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "export_funcs") {
                    const std::string format = arguments.value("format", "json");
                    json functions = json::array();
                    std::string header;
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto lookup = lookup_analysis_function(target, context);
                        const auto function = first_generated_function(lookup);
                        if (!function) {
                            if (managed_decompiler_selector(target)) {
                                const auto decompiled = invoke_legacy(
                                    "decompile", json{{"address", target}}, context);
                                if (format == "c_header")
                                    return tool_result_t::error(
                                        "C header export is unavailable for managed entity locators.",
                                        std::string("MANAGED_C_HEADER_UNSUPPORTED"));
                                if (format == "json") {
                                    if (decompiled.success) {
                                        functions.push_back({
                                            {"addr", decompiled.data.value(
                                                "address", target.get<std::string>())},
                                            {"name", decompiled.data.value(
                                                "name", target.get<std::string>())},
                                            {"size", decompiled.data.value(
                                                "size", std::string("0"))},
                                            {"prototype", decompiled.data.contains("prototype")
                                                ? decompiled.data.at("prototype") : json(nullptr)},
                                            {"code", decompiled.data.value(
                                                "pseudocode", std::string())},
                                            {"decompile_error", nullptr},
                                        });
                                    } else {
                                        functions.push_back({
                                            {"addr", target.get<std::string>()},
                                            {"name", nullptr},
                                            {"code", nullptr},
                                            {"decompile_error", backend_error(decompiled)},
                                        });
                                    }
                                } else if (format == "prototypes") {
                                    json item{{"name", decompiled.success
                                        ? json(decompiled.data.value(
                                            "name", target.get<std::string>()))
                                        : json(nullptr)}};
                                    if (decompiled.success &&
                                        decompiled.data.contains("prototype") &&
                                        decompiled.data.at("prototype").is_string())
                                        item["prototype"] =
                                            decompiled.data.at("prototype");
                                    functions.push_back(std::move(item));
                                }
                                continue;
                            }
                            if (format == "json")
                                functions.push_back({
                                    {"addr", target.get<std::string>()},
                                    {"error", backend_error(lookup)},
                                });
                            else
                                functions.push_back({{"name", nullptr}});
                            continue;
                        }
                        const auto prototype = overlay_type_at(
                            context, function->value("addr", std::string()));
                        if (format == "c_header") {
                            if (prototype) {
                                header.append(*prototype);
                                if (header.empty() || header.back() != ';')
                                    header.push_back(';');
                                header.push_back('\n');
                            }
                            continue;
                        }
                        if (format == "prototypes") {
                            json item{{"name", function->at("name")}};
                            if (prototype)
                                item["prototype"] = *prototype;
                            functions.push_back(std::move(item));
                            continue;
                        }
                        json item{
                            {"addr", function->at("addr")}, {"name", function->at("name")},
                            {"size", function->at("size")},
                            {"prototype", prototype ? json(*prototype) : json(nullptr)},
                        };
                        const auto decompiled = invoke_legacy(
                            "decompile", json{{"address", function->at("addr")}}, context);
                        item["code"] = decompiled.success
                            ? json(decompiled.data.value("pseudocode", std::string())) : json(nullptr);
                        item["decompile_error"] = decompiled.success
                            ? json(nullptr) : json(backend_error(decompiled));
                        const auto disassembled = invoke_legacy(
                            "disasm", json{{"address", function->at("addr")},
                                           {"max_instructions", 4096}}, context);
                        if (disassembled.success) {
                            std::string assembly;
                            for (const auto& instruction :
                                 disassembled.data.value("instructions", json::array())) {
                                assembly.append(instruction.value("address", std::string()));
                                assembly.append("  ");
                                assembly.append(instruction.value(
                                    "text", "db " + instruction.value("bytes", std::string())));
                                assembly.push_back('\n');
                            }
                            item["asm"] = std::move(assembly);
                        }
                        functions.push_back(std::move(item));
                    }
                    if (format == "c_header")
                        return tool_result_t::ok(json{{"format", format}, {"content", std::move(header)}});
                    return tool_result_t::ok(json{{"format", format}, {"functions", std::move(functions)}});
                }

                if (name == "callgraph") {
                    json output = json::array();
                    const auto max_nodes = arguments.value("max_nodes", std::size_t{1000});
                    const auto max_edges = arguments.value("max_edges", std::size_t{5000});
                    for (const auto& root : scalar_or_array_items(arguments.at("roots"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", std::string("CANCELLED"));
                        const auto legacy = invoke_legacy(
                            "callgraph", json{{"address", root},
                                       {"depth", arguments.value("max_depth", 5U)},
                                       {"direction", "both"},
                                       {"limit", (std::min)(max_nodes, std::size_t{5000})}},
                            context);
                        if (!legacy.success) {
                            output.push_back({
                                {"root", root.get<std::string>()}, {"nodes", json::array()},
                                {"edges", json::array()}, {"truncated", false},
                                {"limit_reason", nullptr}, {"error", backend_error(legacy)},
                            });
                            continue;
                        }
                        json nodes = json::array();
                        for (const auto& value : legacy.data.value("nodes", json::array())) {
                            if (nodes.size() >= max_nodes)
                                break;
                            nodes.push_back({
                                {"addr", value.value("address", std::string())},
                                {"name", value.contains("name") ? value.at("name") : json(nullptr)},
                                {"depth", value.value("depth", 0)},
                            });
                        }
                        json edges = json::array();
                        for (const auto& value : legacy.data.value("edges", json::array())) {
                            if (edges.size() >= max_edges)
                                break;
                            edges.push_back({
                                {"from", value.value("from", std::string())},
                                {"to", value.value("to", std::string())},
                                {"type", value.value("kind", "call")},
                            });
                        }
                        const bool truncated = legacy.data.value("truncated", false) ||
                            legacy.data.value("node_count", nodes.size()) > nodes.size() ||
                            legacy.data.value("edge_count", edges.size()) > edges.size();
                        output.push_back({
                            {"root", root.get<std::string>()}, {"nodes", std::move(nodes)},
                            {"edges", std::move(edges)},
                            {"max_depth", arguments.value("max_depth", 5U)},
                            {"max_nodes", max_nodes}, {"max_edges", max_edges},
                            {"max_edges_per_func", arguments.value("max_edges_per_func", 200U)},
                            {"per_func_capped", false}, {"truncated", truncated},
                            {"limit_reason", truncated ? json("bounded_graph_limit") : json(nullptr)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                return tool_result_t::error(
                    "Analysis adapter is not registered for " + std::string(name) + ".",
                    std::string("MCP_BACKEND_UNAVAILABLE"));
            }

            static std::uint64_t query_count(
                const json& query, std::uint64_t fallback,
                std::uint64_t maximum)
            {
                const auto found = query.find("count");
                if (found == query.end())
                    return fallback;
                const auto value = json_nonnegative_u64(*found);
                if (!value || *value == 0)
                    return maximum;
                return (std::min)(*value, maximum);
            }

            tool_result_t invoke_core_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (name == "server_health") {
                    const auto snapshot = context.workspace->snapshot();
                    const auto image = context.workspace->normalized_image();
                    return tool_result_t::ok(json{
                        {"status", "ok"},
                        {"uptime_sec", static_cast<std::uint64_t>(GetTickCount64() / 1000ULL)},
                        {"idb_path", nullptr},
                        {"module", context.workspace->identity().bin_name()},
                        {"input_path", context.workspace->identity().normalized_source_path()},
                        {"imagebase", image ? hex_addr(image->image_base) : std::string("0x0")},
                        {"auto_analysis_ready", snapshot && snapshot->baseline_complete},
                        {"hexrays_ready", false},
                        {"strings_cache_ready", snapshot != nullptr},
                        {"strings_cache_size", snapshot ? snapshot->strings.size() : 0U},
                    });
                }
                if (name == "idb_save")
                    return checkpoint_workspace(context);

                if (name == "lookup_funcs") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const std::string query_text = query.get<std::string>();
                        json request;
                        request[wave_c_address_value(query) ? "address" : "name"] = query;
                        const auto legacy = invoke_legacy("lookup_funcs", request, context);
                        json item{{"query", query_text}, {"fn", nullptr}, {"error", nullptr}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            const auto functions = legacy.data.find("functions");
                            if (functions != legacy.data.end() && functions->is_array() &&
                                !functions->empty())
                                item["fn"] = generated_function_summary(functions->front());
                            else
                                item["error"] = "function_not_found";
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "list_funcs" || name == "list_globals") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const json request{
                            {"offset", offset}, {"limit", count},
                            {"filter", query.value("filter", std::string())},
                        };
                        const auto legacy = name == "list_funcs"
                            ? invoke_legacy("list_funcs", request, context)
                            : invoke_legacy("list_globals", request, context);
                        if (!legacy.success)
                            return legacy;
                        const char* collection = name == "list_funcs" ? "functions" : "globals";
                        json data = json::array();
                        const auto values = legacy.data.find(collection);
                        if (values != legacy.data.end() && values->is_array()) {
                            for (const auto& value : *values) {
                                if (name == "list_funcs") {
                                    data.push_back(generated_function_summary(value));
                                } else {
                                    data.push_back({
                                        {"addr", value.value("address", std::string())},
                                        {"name", value.value("name", std::string())},
                                    });
                                }
                            }
                        }
                        output.push_back({
                            {"data", std::move(data)},
                            {"next_offset", legacy.data.value("next_offset", json(nullptr))},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "func_query") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const auto legacy = invoke_legacy(
                            "list_funcs",
                            json{{"offset", 0}, {"limit", 10000},
                                 {"filter", query.value("filter", std::string())}},
                            context);
                        if (!legacy.success) {
                            output.push_back({
                                {"data", json::array()}, {"next_offset", nullptr},
                                {"error", backend_error(legacy)},
                            });
                            continue;
                        }
                        std::optional<std::regex> name_pattern;
                        if (const auto regex_value = query.find("name_regex");
                            regex_value != query.end() && regex_value->is_string() &&
                            !regex_value->get_ref<const std::string&>().empty()) {
                            try {
                                name_pattern.emplace(
                                    regex_value->get<std::string>(),
                                    std::regex::ECMAScript | std::regex::optimize);
                            } catch (const std::regex_error&) {
                                output.push_back({
                                    {"data", json::array()}, {"next_offset", nullptr},
                                    {"error", "invalid_name_regex"},
                                });
                                continue;
                            }
                        }
                        std::vector<json> matches;
                        for (const auto& value : legacy.data.value("functions", json::array())) {
                            const auto size = json_nonnegative_u64(value.value("size", json(0))).value_or(0);
                            const auto minimum = query.value("min_size", std::uint64_t{0});
                            const auto maximum = query.value(
                                "max_size", (std::numeric_limits<std::uint64_t>::max)());
                            const std::string function_name = value.value("name", std::string());
                            if (size < minimum || size > maximum ||
                                (name_pattern && !std::regex_search(function_name, *name_pattern)) ||
                                query.value("has_type", false))
                                continue;
                            auto item = generated_function_summary(value);
                            item["size_int"] = size;
                            item["has_type"] = false;
                            matches.push_back(std::move(item));
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(matches.begin(), matches.end(), [&sort_by](const json& lhs, const json& rhs) {
                            if (sort_by == "name")
                                return lhs.at("name").get_ref<const std::string&>() <
                                    rhs.at("name").get_ref<const std::string&>();
                            if (sort_by == "size")
                                return lhs.at("size_int").get<std::uint64_t>() <
                                    rhs.at("size_int").get<std::uint64_t>();
                            return lhs.at("addr").get_ref<const std::string&>() <
                                rhs.at("addr").get_ref<const std::string&>();
                        });
                        if (query.value("descending", false))
                            std::reverse(matches.begin(), matches.end());
                        json data = json::array();
                        const std::size_t begin = (std::min)(
                            static_cast<std::size_t>(offset), matches.size());
                        const std::size_t end = (std::min)(
                            matches.size(), begin + static_cast<std::size_t>(count));
                        for (std::size_t index = begin; index < end; ++index)
                            data.push_back(matches[index]);
                        output.push_back({
                            {"data", std::move(data)},
                            {"next_offset", end < matches.size() ? json(end) : json(nullptr)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "imports" || name == "imports_query") {
                    const auto execute = [this, &context](const json& query) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const auto legacy = invoke_legacy(
                            "imports",
                            json{{"offset", offset}, {"limit", count},
                                 {"module", query.value("module", std::string())}},
                            context);
                        if (!legacy.success)
                            return std::pair<tool_result_t, json>{legacy, json()};
                        json data = json::array();
                        const std::string filter = query.value("filter", std::string());
                        for (const auto& value : legacy.data.value("imports", json::array())) {
                            const auto item = generated_import_summary(value);
                            if (!filter.empty() &&
                                item.at("imported_name").get_ref<const std::string&>().find(filter) ==
                                    std::string::npos)
                                continue;
                            data.push_back(item);
                        }
                        return std::pair<tool_result_t, json>{
                            tool_result_t::ok(""),
                            json{{"data", std::move(data)},
                                 {"next_offset", legacy.data.value("next_offset", json(nullptr))}},
                        };
                    };
                    if (name == "imports") {
                        auto [status, value] = execute(arguments);
                        return status.success ? tool_result_t::ok(value) : status;
                    }
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        auto [status, value] = execute(query);
                        if (!status.success)
                            return status;
                        output.push_back(std::move(value));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "entity_query") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const std::string kind = query.at("kind").get<std::string>();
                        aida::analysis::entity_search_query_t entity_query;
                        using entity_kind_t = aida::analysis::search_entity_kind_t;
                        if (kind == "functions")
                            entity_query.filter.kind = entity_kind_t::function;
                        else if (kind == "globals")
                            entity_query.filter.kind = entity_kind_t::data_candidate;
                        else if (kind == "imports" || kind == "symbols")
                            entity_query.filter.kind = entity_kind_t::symbol;
                        else if (kind == "strings")
                            entity_query.filter.kind = entity_kind_t::string;
                        else if (kind == "types")
                            entity_query.filter.kind = entity_kind_t::type_candidate;
                        const std::string filter = query.value("filter", std::string());
                        const std::string regex_text = query.value("regex", std::string());
                        std::shared_ptr<const aida::analysis::regex_query_t> pattern;
                        if (!regex_text.empty()) {
                            auto compiled = aida::analysis::regex_query_t::compile(regex_text);
                            if (!compiled)
                                return workspace_tool_error(compiled.error());
                            pattern = compiled.take_value();
                        }
                        auto queried = execute_query_index(
                            context,
                            aida::analysis::search_query_t{std::move(entity_query)},
                            query.value("offset", std::uint64_t{0}),
                            query_count(query, 100, 10000), nullptr,
                            json{{"tool", "entity_query"}, {"query", query}}.dump());
                        if (!queried)
                            return workspace_tool_error(queried.error());
                        auto page = queried.take_value();
                        json data = json::array();
                        for (const auto& hit : page.hits) {
                            if (context.cancellation_requested())
                                return tool_result_t::error(
                                    "Entity query was cancelled.", std::string("CANCELLED"));
                            if (!filter.empty() && hit.text.find(filter) == std::string::npos)
                                continue;
                            if (pattern) {
                                auto matched = pattern->match(hit.text);
                                if (!matched)
                                    return workspace_tool_error(matched.error());
                                if (!matched.value().matched)
                                    continue;
                            }
                            if (kind == "strings") {
                                data.push_back({
                                    {"addr", hex_addr(hit.address.value)},
                                    {"value", hit.text},
                                    {"length", hit.text.size()},
                                });
                            } else {
                                data.push_back({
                                    {"addr", hex_addr(hit.address.value)},
                                    {kind == "imports" ? "imported_name" : "name", hit.text},
                                });
                            }
                        }
                        output.push_back({
                            {"kind", kind}, {"data", std::move(data)},
                            {"total", page.total},
                            {"next_offset", page.next
                                ? json(page.next->position) : json(nullptr)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find_regex") {
                    aida::analysis::regex_search_query_t query;
                    query.pattern = arguments.at("pattern").get<std::string>();
                    query.options.case_sensitive = false;
                    auto compiled = aida::analysis::regex_query_t::compile(
                        query.pattern, query.options);
                    if (!compiled)
                        return workspace_tool_error(compiled.error());
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end())
                        cursor = &*found;
                    auto queried = execute_query_index(
                        context,
                        aida::analysis::search_query_t{std::move(query)},
                        arguments.value("offset", std::uint64_t{0}),
                        arguments.value("limit", std::uint64_t{30}),
                        cursor,
                        json{{"tool", "find_regex"},
                             {"pattern", arguments.at("pattern")},
                             {"case_sensitive", false}}.dump());
                    if (!queried)
                        return workspace_tool_error(queried.error());
                    auto page = queried.take_value();
                    json matches = json::array();
                    for (const auto& hit : page.hits) {
                        if (hit.kind != aida::analysis::search_entity_kind_t::string)
                            continue;
                        matches.push_back({
                            {"address", hex_addr(hit.address.value)},
                            {"text", hit.text},
                            {"kind", query_hit_kind_name(hit.kind)},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"matches", matches}, {"n", matches.size()},
                        {"error", nullptr},
                        {"cursor", query_cursor_response(page)},
                    });
                }

                if (name == "search_text") {
                    const bool use_regex = arguments.value("regex", false);
                    const bool case_sensitive = arguments.value("case_sensitive", false);
                    const std::string pattern = arguments.at("pattern").get<std::string>();
                    aida::analysis::search_query_t query;
                    if (use_regex) {
                        aida::analysis::regex_search_query_t regex_query;
                        regex_query.pattern = pattern;
                        regex_query.options.case_sensitive = case_sensitive;
                        auto compiled = aida::analysis::regex_query_t::compile(
                            regex_query.pattern, regex_query.options);
                        if (!compiled)
                            return workspace_tool_error(compiled.error());
                        query = std::move(regex_query);
                    } else {
                        aida::analysis::literal_search_query_t literal;
                        literal.text = pattern;
                        literal.case_sensitive = case_sensitive;
                        query = std::move(literal);
                    }
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end())
                        cursor = &*found;
                    wave_c_signature_source_t address_source(context);
                    const auto resolve_bound = [&arguments, &address_source](
                        const char* key) -> std::optional<std::uint64_t> {
                        const auto found = arguments.find(key);
                        if (found == arguments.end() || found->is_null() ||
                            (found->is_string() && found->get_ref<
                                const std::string&>().empty()))
                            return std::nullopt;
                        if (found->is_string())
                            return address_source.resolve_address(
                                found->get_ref<const std::string&>());
                        return wave_c_address_value(*found);
                    };
                    const auto start = resolve_bound("start");
                    const auto end = resolve_bound("end");
                    if ((arguments.contains("start") &&
                         !arguments.at("start").is_null() &&
                         !(arguments.at("start").is_string() &&
                           arguments.at("start").get_ref<
                               const std::string&>().empty()) && !start) ||
                        (arguments.contains("end") &&
                         !arguments.at("end").is_null() &&
                         !(arguments.at("end").is_string() &&
                           arguments.at("end").get_ref<
                               const std::string&>().empty()) && !end) ||
                        (start && end && *end < *start)) {
                        return tool_result_t::error(
                            "Search text bounds are invalid.",
                            std::string("INVALID_SEARCH_RANGE"));
                    }
                    const bool code_only = arguments.value("code_only", true);
                    const std::string include_mode =
                        arguments.value("include", std::string("all"));
                    const std::string route_semantics = json{
                        {"tool", "search_text"}, {"pattern", pattern},
                        {"regex", use_regex}, {"case_sensitive", case_sensitive},
                        {"start", start ? json(*start) : json(nullptr)},
                        {"end", end ? json(*end) : json(nullptr)},
                        {"code_only", code_only}, {"include", include_mode}}.dump();
                    auto queried = execute_query_index(
                        context, query, 0,
                        arguments.value("limit", std::uint64_t{30}), cursor,
                        route_semantics);
                    if (!queried)
                        return workspace_tool_error(queried.error());
                    auto page = queried.take_value();
                    const auto image = context.workspace->normalized_image();
                    json hits = json::array();
                    for (const auto& hit : page.hits) {
                        const std::string kind = query_hit_kind_name(hit.kind);
                        const bool executable = query_address_is_executable(
                            image.get(), hit.address);
                        if ((start && hit.address.value < *start) ||
                            (end && hit.address.value >= *end) ||
                            (code_only && !executable) ||
                            (include_mode == "disasm" && !executable) ||
                            (include_mode == "comments" && hit.kind ==
                                aida::analysis::search_entity_kind_t::instruction))
                            continue;
                        hits.push_back({
                            {"addr", hex_addr(hit.address.value)},
                            {"matches", json::array({json{
                                {"kind", kind}, {"text", hit.text}}})},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"hits", hits}, {"n", hits.size()},
                        {"cursor", query_cursor_response(page)},
                    });
                }

                if (name == "int_convert")
                    return invoke_legacy("int_convert", arguments, context);
                return tool_result_t::error(
                    "Core adapter is not registered for " + std::string(name) + ".",
                    std::string("MCP_BACKEND_UNAVAILABLE"));
            }

            struct assembly_register_t final {
                int index = -1;
                std::uint8_t width = 0;
            };

            static std::string assembly_trim(std::string value)
            {
                const auto begin = value.find_first_not_of(" \t\r\n");
                if (begin == std::string::npos)
                    return {};
                const auto end = value.find_last_not_of(" \t\r\n");
                value = value.substr(begin, end - begin + 1U);
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::toupper(ch));
                });
                return value;
            }

            static std::optional<assembly_register_t> assembly_register(
                std::string value)
            {
                value = assembly_trim(std::move(value));
                static const std::array<const char*, 8> registers64{
                    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"};
                static const std::array<const char*, 8> registers32{
                    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
                static const std::array<const char*, 8> registers16{
                    "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"};
                static const std::array<const char*, 4> registers8{
                    "AL", "CL", "DL", "BL"};
                for (std::size_t index = 0; index < registers64.size(); ++index) {
                    if (value == registers64[index])
                        return assembly_register_t{static_cast<int>(index), 64};
                    if (value == registers32[index])
                        return assembly_register_t{static_cast<int>(index), 32};
                    if (value == registers16[index])
                        return assembly_register_t{static_cast<int>(index), 16};
                }
                for (std::size_t index = 0; index < registers8.size(); ++index) {
                    if (value == registers8[index])
                        return assembly_register_t{static_cast<int>(index), 8};
                }
                if (value.size() < 2U || value.front() != 'R' ||
                    value[1] < '8' || value[1] > '9')
                    return std::nullopt;
                std::size_t digit_end = 1U;
                while (digit_end < value.size() && std::isdigit(
                    static_cast<unsigned char>(value[digit_end])))
                    ++digit_end;
                int index = -1;
                try {
                    index = std::stoi(value.substr(1U, digit_end - 1U));
                } catch (...) {
                    return std::nullopt;
                }
                if (index < 8 || index > 15)
                    return std::nullopt;
                const std::string suffix = value.substr(digit_end);
                if (suffix.empty())
                    return assembly_register_t{index, 64};
                if (suffix == "D")
                    return assembly_register_t{index, 32};
                if (suffix == "W")
                    return assembly_register_t{index, 16};
                if (suffix == "B")
                    return assembly_register_t{index, 8};
                return std::nullopt;
            }

            static std::optional<std::int64_t> assembly_integer(std::string value)
            {
                value = assembly_trim(std::move(value));
                for (const std::string prefix : {"SHORT ", "NEAR ", "OFFSET "}) {
                    if (value.rfind(prefix, 0) == 0)
                        value.erase(0, prefix.size());
                }
                if (value.empty())
                    return std::nullopt;
                try {
                    std::size_t consumed = 0;
                    int base = 0;
                    if (value.size() > 1U && value.back() == 'H') {
                        value.pop_back();
                        base = 16;
                    }
                    const auto parsed = std::stoll(value, &consumed, base);
                    return consumed == value.size()
                        ? std::optional<std::int64_t>(parsed) : std::nullopt;
                } catch (...) {
                    return std::nullopt;
                }
            }

            static void append_little_endian(
                std::vector<std::uint8_t>& output,
                std::uint64_t value,
                std::size_t width)
            {
                for (std::size_t index = 0; index < width; ++index)
                    output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
            }

            static bool append_rex(
                std::vector<std::uint8_t>& output,
                std::uint8_t width,
                int reg,
                int base,
                bool force = false)
            {
                if (width == 16)
                    output.push_back(0x66U);
                if (width == 8 && (reg >= 4 || base >= 4) && reg < 8 && base < 8)
                    return false;
                std::uint8_t rex = 0x40U;
                if (width == 64)
                    rex |= 0x08U;
                if (reg >= 8)
                    rex |= 0x04U;
                if (base >= 8)
                    rex |= 0x01U;
                if (rex != 0x40U || force)
                    output.push_back(rex);
                return true;
            }

            static bool append_relative32(
                std::vector<std::uint8_t>& output,
                std::uint64_t target,
                std::uint64_t next)
            {
                const auto difference = target >= next
                    ? static_cast<std::uint64_t>(target - next)
                    : static_cast<std::uint64_t>(next - target);
                if (difference > static_cast<std::uint64_t>(
                    (std::numeric_limits<std::int32_t>::max)()) + (target < next ? 1ULL : 0ULL))
                    return false;
                const auto relative = target >= next
                    ? static_cast<std::int64_t>(difference)
                    : -static_cast<std::int64_t>(difference);
                append_little_endian(
                    output, static_cast<std::uint32_t>(static_cast<std::int32_t>(relative)), 4U);
                return true;
            }

            static std::optional<std::uint64_t> assembly_next_address(
                std::uint64_t base_address,
                std::size_t encoded_size,
                std::size_t trailing_size)
            {
                const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
                if (encoded_size > maximum - base_address)
                    return std::nullopt;
                const auto encoded_end = base_address + encoded_size;
                if (trailing_size > maximum - encoded_end)
                    return std::nullopt;
                return encoded_end + trailing_size;
            }

            static std::optional<std::vector<std::uint8_t>> assemble_x86_overlay(
                std::string assembly,
                std::uint64_t base_address,
                bool mode64,
                std::string& error)
            {
                std::replace(assembly.begin(), assembly.end(), ';', '\n');
                std::istringstream stream(assembly);
                std::vector<std::uint8_t> output;
                std::string line;
                std::size_t line_number = 0;
                while (std::getline(stream, line)) {
                    ++line_number;
                    line = assembly_trim(std::move(line));
                    if (line.empty())
                        continue;
                    const auto separator = line.find_first_of(" \t");
                    const std::string mnemonic = separator == std::string::npos
                        ? line : line.substr(0, separator);
                    const std::string operands = separator == std::string::npos
                        ? std::string() : assembly_trim(line.substr(separator + 1U));
                    std::vector<std::string> values;
                    std::size_t begin = 0;
                    while (begin <= operands.size() && !operands.empty()) {
                        const auto comma = operands.find(',', begin);
                        values.push_back(assembly_trim(operands.substr(
                            begin, comma == std::string::npos
                                ? operands.size() - begin : comma - begin)));
                        if (comma == std::string::npos)
                            break;
                        begin = comma + 1U;
                    }
                    const auto reject = [&error, line_number, &line](std::string reason) {
                        error = "assembly line " + std::to_string(line_number) +
                            " rejected: " + std::move(reason) + " [" + line + "]";
                        return std::optional<std::vector<std::uint8_t>>{};
                    };
                    if (mnemonic == "NOP" && values.empty()) {
                        output.push_back(0x90U);
                        continue;
                    }
                    if (mnemonic == "INT3" && values.empty()) {
                        output.push_back(0xCCU);
                        continue;
                    }
                    if (mnemonic == "UD2" && values.empty()) {
                        output.insert(output.end(), {0x0FU, 0x0BU});
                        continue;
                    }
                    if (mnemonic == "LEAVE" && values.empty()) {
                        output.push_back(0xC9U);
                        continue;
                    }
                    if (mnemonic == "SYSCALL" && values.empty() && mode64) {
                        output.insert(output.end(), {0x0FU, 0x05U});
                        continue;
                    }
                    if ((mnemonic == "RET" || mnemonic == "RETN") && values.size() <= 1U) {
                        if (values.empty()) {
                            output.push_back(0xC3U);
                        } else {
                            const auto immediate = assembly_integer(values.front());
                            if (!immediate || *immediate < 0 || *immediate > 0xFFFF)
                                return reject("RET immediate must fit uint16");
                            output.push_back(0xC2U);
                            append_little_endian(output, static_cast<std::uint64_t>(*immediate), 2U);
                        }
                        continue;
                    }
                    if (mnemonic == "DB" && !values.empty()) {
                        for (const auto& value : values) {
                            const auto byte = assembly_integer(value);
                            if (!byte || *byte < 0 || *byte > 0xFF)
                                return reject("DB values must fit uint8");
                            output.push_back(static_cast<std::uint8_t>(*byte));
                        }
                        continue;
                    }
                    if ((mnemonic == "PUSH" || mnemonic == "POP") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (reg) {
                            if ((mode64 && reg->width != 64) || (!mode64 && reg->width != 32) ||
                                (!mode64 && reg->index >= 8))
                                return reject("register width is incompatible with target mode");
                            if (reg->index >= 8)
                                output.push_back(0x41U);
                            output.push_back(static_cast<std::uint8_t>(
                                (mnemonic == "PUSH" ? 0x50U : 0x58U) + (reg->index & 7)));
                            continue;
                        }
                        if (mnemonic == "POP")
                            return reject("POP requires a register operand");
                        const auto immediate = assembly_integer(values.front());
                        if (!immediate || *immediate < (std::numeric_limits<std::int32_t>::min)() ||
                            *immediate > (std::numeric_limits<std::int32_t>::max)())
                            return reject("PUSH immediate must fit int32");
                        if (*immediate >= -128 && *immediate <= 127) {
                            output.push_back(0x6AU);
                            output.push_back(static_cast<std::uint8_t>(*immediate));
                        } else {
                            output.push_back(0x68U);
                            append_little_endian(output, static_cast<std::uint32_t>(*immediate), 4U);
                        }
                        continue;
                    }
                    if (mnemonic == "MOV" && values.size() == 2U) {
                        const auto destination = assembly_register(values[0]);
                        if (!destination || (!mode64 && destination->index >= 8) ||
                            (destination->width == 64 && !mode64))
                            return reject("MOV destination register is incompatible with target mode");
                        const auto source_register = assembly_register(values[1]);
                        if (source_register) {
                            if (source_register->width != destination->width ||
                                (!mode64 && source_register->index >= 8) ||
                                !append_rex(output, destination->width,
                                    source_register->index, destination->index))
                                return reject("MOV register operands are incompatible");
                            output.push_back(destination->width == 8 ? 0x88U : 0x89U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((source_register->index & 7) << 3) |
                                (destination->index & 7)));
                            continue;
                        }
                        const auto immediate = assembly_integer(values[1]);
                        if (!immediate)
                            return reject("MOV source must be a register or integer immediate");
                        if (!append_rex(output, destination->width, 0, destination->index))
                            return reject("MOV register encoding is unsupported");
                        output.push_back(static_cast<std::uint8_t>(
                            (destination->width == 8 ? 0xB0U : 0xB8U) +
                            (destination->index & 7)));
                        const std::size_t width = destination->width == 64
                            ? 8U : destination->width == 32 ? 4U : destination->width == 16 ? 2U : 1U;
                        const std::uint64_t maximum = width == 8U
                            ? (std::numeric_limits<std::uint64_t>::max)()
                            : (std::uint64_t{1} << (width * 8U)) - 1U;
                        const std::int64_t minimum = width == 8U
                            ? (std::numeric_limits<std::int64_t>::min)()
                            : -(std::int64_t{1} << (width * 8U - 1U));
                        if (*immediate < minimum)
                            return reject("MOV negative immediate exceeds destination width");
                        if (*immediate >= 0 && static_cast<std::uint64_t>(*immediate) > maximum)
                            return reject("MOV immediate exceeds destination width");
                        append_little_endian(output, static_cast<std::uint64_t>(*immediate), width);
                        continue;
                    }
                    if ((mnemonic == "XOR" || mnemonic == "ADD" || mnemonic == "SUB" ||
                         mnemonic == "CMP" || mnemonic == "TEST") && values.size() == 2U) {
                        const auto destination = assembly_register(values[0]);
                        const auto source = assembly_register(values[1]);
                        if (destination && source) {
                            if (destination->width != source->width ||
                                (destination->width == 64 && !mode64) ||
                                (!mode64 && (destination->index >= 8 || source->index >= 8)) ||
                                !append_rex(output, destination->width,
                                    source->index, destination->index))
                                return reject("binary register operands are incompatible");
                            const std::uint8_t opcode = destination->width == 8
                                ? mnemonic == "XOR" ? 0x30U : mnemonic == "ADD" ? 0x00U :
                                    mnemonic == "SUB" ? 0x28U : mnemonic == "CMP" ? 0x38U : 0x84U
                                : mnemonic == "XOR" ? 0x31U : mnemonic == "ADD" ? 0x01U :
                                    mnemonic == "SUB" ? 0x29U : mnemonic == "CMP" ? 0x39U : 0x85U;
                            output.push_back(opcode);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((source->index & 7) << 3) |
                                (destination->index & 7)));
                            continue;
                        }
                        if (!destination || mnemonic == "XOR" || mnemonic == "TEST" ||
                            (destination->width == 64 && !mode64) || destination->width == 8 ||
                            (!mode64 && destination->index >= 8))
                            return reject("immediate form is unsupported for this instruction");
                        const auto immediate = assembly_integer(values[1]);
                        const std::uint8_t immediate_width = destination->width == 16 ? 16 : 32;
                        const std::int64_t minimum = -(std::int64_t{1} << (immediate_width - 1U));
                        const std::uint64_t maximum = destination->width == 64
                            ? static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)())
                            : (std::uint64_t{1} << immediate_width) - 1U;
                        if (!immediate || *immediate < minimum ||
                            (*immediate >= 0 && static_cast<std::uint64_t>(*immediate) > maximum))
                            return reject("arithmetic immediate exceeds the encodable operand width");
                        if (!append_rex(output, destination->width, 0, destination->index))
                            return reject("arithmetic register encoding is unsupported");
                        const int extension = mnemonic == "ADD" ? 0 : mnemonic == "SUB" ? 5 : 7;
                        if (*immediate >= -128 && *immediate <= 127) {
                            output.push_back(0x83U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | (extension << 3) | (destination->index & 7)));
                            output.push_back(static_cast<std::uint8_t>(*immediate));
                        } else {
                            output.push_back(0x81U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | (extension << 3) | (destination->index & 7)));
                            append_little_endian(
                                output, static_cast<std::uint64_t>(*immediate),
                                destination->width == 16 ? 2U : 4U);
                        }
                        continue;
                    }
                    if ((mnemonic == "INC" || mnemonic == "DEC") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (!reg || (reg->width == 64 && !mode64) ||
                            (!mode64 && reg->index >= 8) ||
                            !append_rex(output, reg->width, 0, reg->index))
                            return reject("INC/DEC register is incompatible with target mode");
                        output.push_back(reg->width == 8 ? 0xFEU : 0xFFU);
                        output.push_back(static_cast<std::uint8_t>(
                            0xC0U | ((mnemonic == "DEC" ? 1 : 0) << 3) | (reg->index & 7)));
                        continue;
                    }
                    if ((mnemonic == "JMP" || mnemonic == "CALL") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (reg) {
                            if ((mode64 && reg->width != 64) || (!mode64 && reg->width != 32) ||
                                (!mode64 && reg->index >= 8))
                                return reject("indirect branch register is incompatible with target mode");
                            if (reg->index >= 8)
                                output.push_back(0x41U);
                            output.push_back(0xFFU);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((mnemonic == "CALL" ? 2 : 4) << 3) | (reg->index & 7)));
                            continue;
                        }
                        const auto target = assembly_integer(values.front());
                        if (!target || *target < 0)
                            return reject("direct branch target must be a non-negative address");
                        output.push_back(mnemonic == "CALL" ? 0xE8U : 0xE9U);
                        const auto next = assembly_next_address(base_address, output.size(), 4U);
                        if (!next)
                            return reject("direct branch address calculation overflowed");
                        if (!append_relative32(output, static_cast<std::uint64_t>(*target),
                            *next))
                            return reject("direct branch target exceeds rel32 range");
                        continue;
                    }
                    const auto conditional_opcode = mnemonic == "JE" || mnemonic == "JZ" ? 0x84 :
                        mnemonic == "JNE" || mnemonic == "JNZ" ? 0x85 :
                        mnemonic == "JA" ? 0x87 : mnemonic == "JAE" ? 0x83 :
                        mnemonic == "JB" ? 0x82 : mnemonic == "JBE" ? 0x86 : -1;
                    if (conditional_opcode >= 0 && values.size() == 1U) {
                        const auto target = assembly_integer(values.front());
                        if (!target || *target < 0)
                            return reject("conditional branch target must be a non-negative address");
                        output.insert(output.end(), {0x0FU, static_cast<std::uint8_t>(conditional_opcode)});
                        const auto next = assembly_next_address(base_address, output.size(), 4U);
                        if (!next)
                            return reject("conditional branch address calculation overflowed");
                        if (!append_relative32(output, static_cast<std::uint64_t>(*target),
                            *next))
                            return reject("conditional branch target exceeds rel32 range");
                        continue;
                    }
                    return reject("instruction form is not supported by the bounded overlay assembler");
                }
                if (output.empty()) {
                    error = "assembly patch contains no instructions";
                    return std::nullopt;
                }
                return output;
            }

            static std::optional<std::vector<std::uint8_t>> decode_hex_bytes(
                std::string_view encoded)
            {
                std::vector<std::uint8_t> bytes;
                int high_nibble = -1;
                for (std::size_t index = 0; index < encoded.size(); ++index) {
                    const unsigned char value = static_cast<unsigned char>(encoded[index]);
                    if (std::isspace(value) || value == ',' || value == ':' ||
                        value == '_' || value == '-') {
                        if (high_nibble != -1)
                            return std::nullopt;
                        continue;
                    }
                    if (value == '0' && index + 1 < encoded.size() &&
                        (encoded[index + 1] == 'x' || encoded[index + 1] == 'X') &&
                        high_nibble == -1) {
                        ++index;
                        continue;
                    }
                    if (!std::isxdigit(value))
                        return std::nullopt;
                    const int nibble = std::isdigit(value)
                        ? value - '0'
                        : std::tolower(value) - 'a' + 10;
                    if (high_nibble == -1) {
                        high_nibble = nibble;
                    } else {
                        bytes.push_back(static_cast<std::uint8_t>(
                            (high_nibble << 4) | nibble));
                        high_nibble = -1;
                    }
                }
                if (high_nibble != -1 || bytes.empty())
                    return std::nullopt;
                return bytes;
            }

            static std::string encode_hex_bytes(
                const std::vector<std::uint8_t>& bytes)
            {
                static constexpr char digits[] = "0123456789ABCDEF";
                std::string encoded;
                if (!bytes.empty())
                    encoded.reserve(bytes.size() * 3U - 1U);
                for (std::size_t index = 0; index < bytes.size(); ++index) {
                    if (index != 0)
                        encoded.push_back(' ');
                    encoded.push_back(digits[(bytes[index] >> 4U) & 0x0fU]);
                    encoded.push_back(digits[bytes[index] & 0x0fU]);
                }
                return encoded;
            }

            struct wave_c_snapshot_bytes_t final {
                std::vector<std::uint8_t> bytes;
                std::optional<wave_c_compat::live_routing_identity_binding_t> binding;
            };

            static std::optional<wave_c_snapshot_bytes_t> read_snapshot_bytes(
                const workspace_request_context_t& context,
                std::uint64_t address, std::size_t size,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation)
            {
                if (size == 0 || !context.workspace)
                    return std::nullopt;
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    wave_c_compat::live_routing_snapshot_request_t request;
                    request.target = wave_c_target_selector(context);
                    request.expected_generation = wave_c_workspace_generation(context);
                    request.address = address;
                    request.size = static_cast<std::uint64_t>(size);
                    request.cancellation = cancellation;
                    request.deadline = wave_c_deadline(context);
                    auto captured = live_routing.capture_bounded_snapshot(request);
                    if (!captured)
                        return std::nullopt;
                    auto snapshot = std::move(captured).take_value();
                    wave_c_snapshot_bytes_t result;
                    result.bytes = std::move(snapshot.bytes);
                    result.binding = snapshot.binding;
                    return result;
                }
                wave_c_signature_source_t source(context);
                wave_c_snapshot_bytes_t result;
                if (!source.read_bytes(address, size, result.bytes) ||
                    result.bytes.size() != size)
                    return std::nullopt;
                return result;
            }

            static bool live_snapshot_identity_current(
                const workspace_request_context_t& context)
            {
                if (context.kind != aida::analysis::target_kind_t::live_snapshot)
                    return true;
                if (context.cancellation_requested() ||
                    (context.deadline_ms != 0 &&
                     static_cast<std::uint64_t>(GetTickCount64()) >= context.deadline_ms))
                    return false;
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                return provider && provider->validate_current_identity().has_value();
            }

            static json memory_snapshot_receipt(
                const workspace_request_context_t& context,
                std::uint64_t bytes_read,
                const std::optional<
                    wave_c_compat::live_routing_identity_binding_t>& binding)
            {
                json receipt{
                    {"generation", binding
                        ? binding->workspace_generation
                        : wave_c_workspace_generation(context)},
                    {"bytes_read", bytes_read},
                    {"read_only", true},
                };
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    if (!binding)
                        return json::object();
                    receipt["source"] = "bounded_live_snapshot";
                    receipt["module_boundary_validated"] = true;
                    receipt["identity_revalidated"] = true;
                    receipt["target_id"] = binding->target_id;
                    receipt["pid"] = binding->pid;
                    receipt["process_creation_identity"] =
                        binding->process_creation_identity;
                    receipt["module_base"] = binding->module_base;
                    receipt["module_size"] = binding->module_size;
                    receipt["attach_generation"] = binding->attach_generation;
                } else {
                    receipt["source"] = "immutable_workspace_snapshot";
                    receipt["immutable"] = true;
                }
                return receipt;
            }

            tool_result_t invoke_memory_read_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory adapter intent is missing.", std::string("MCP_MEMORY_INTENT_INVALID"));
                if (!live_snapshot_identity_current(context))
                    return tool_result_t::error(
                        "Live snapshot identity is stale or unavailable.",
                        std::string("LIVE_SNAPSHOT_IDENTITY_INVALID"));
                const auto ranges = memory->find("ranges");
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    std::size_t requested = 0;
                    if (name == "get_global_value") {
                        const auto queries = arguments.find("queries");
                        if (queries != arguments.end())
                            requested = queries->is_array()
                                ? queries->size() : std::size_t{1};
                    } else if (ranges != memory->end()) {
                        requested = ranges->is_array()
                            ? ranges->size() : std::size_t{1};
                    }
                    if (requested >
                        live_routing.limits().maximum_snapshots_per_request) {
                        return tool_result_t::error(
                            "Live memory request exceeds the snapshot quota.",
                            std::string("LIVE_SNAPSHOT_BUDGET_EXCEEDED"));
                    }
                }
                json result = json::array();
                std::uint64_t bytes_read = 0;
                std::optional<wave_c_compat::live_routing_identity_binding_t> binding;
                const auto accept_binding = [&binding](
                    const std::optional<wave_c_compat::live_routing_identity_binding_t>& candidate) {
                    if (!candidate)
                        return true;
                    if (!binding) {
                        binding = candidate;
                        return true;
                    }
                    return binding->target_id == candidate->target_id &&
                        binding->pid == candidate->pid &&
                        binding->process_creation_identity ==
                            candidate->process_creation_identity &&
                        binding->module_base == candidate->module_base &&
                        binding->module_size == candidate->module_size &&
                        binding->attach_generation == candidate->attach_generation &&
                        binding->workspace_generation == candidate->workspace_generation;
                };
                const auto account_bytes = [&bytes_read](std::size_t count) {
                    const auto value = static_cast<std::uint64_t>(count);
                    if (value > (std::numeric_limits<std::uint64_t>::max)() - bytes_read)
                        return false;
                    bytes_read += value;
                    return true;
                };

                if (name == "get_global_value") {
                    const auto queries = arguments.find("queries");
                    if (queries == arguments.end())
                        return tool_result_t::error(
                            "Global value queries are missing.", std::string("MCP_MEMORY_INTENT_INVALID"));
                    const json values = queries->is_array()
                        ? *queries : json::array({*queries});
                    for (const auto& query : values) {
                        if (context.cancellation_requested())
                            return tool_result_t::error(
                                "Memory request was cancelled.", std::string("CANCELLED"));
                        const std::string query_text = query.get<std::string>();
                        if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                            auto address = wave_c_address_value(query);
                            if (!address) {
                                const auto snapshot = context.workspace->snapshot();
                                if (snapshot) {
                                    const auto symbol = std::find_if(
                                        snapshot->symbols.begin(), snapshot->symbols.end(),
                                        [&query_text](const auto& value) {
                                            return value.name == query_text;
                                        });
                                    if (symbol != snapshot->symbols.end()) {
                                        const auto provider = std::dynamic_pointer_cast<
                                            const aida::analysis::live_snapshot_provider_t>(
                                                context.workspace->provider_handle());
                                        if (provider && symbol->address.value <=
                                            (std::numeric_limits<std::uint64_t>::max)() -
                                                provider->metadata().capture_address)
                                            address = provider->metadata().capture_address +
                                                symbol->address.value;
                                    }
                                }
                            }
                            const auto snapshot_bytes = address
                                ? read_snapshot_bytes(
                                    context, *address, std::size_t{8},
                                    live_routing, cancellation)
                                : std::nullopt;
                            if (!snapshot_bytes ||
                                !accept_binding(snapshot_bytes->binding) ||
                                !account_bytes(snapshot_bytes->bytes.size())) {
                                result.push_back({
                                    {"query", query_text}, {"value", nullptr},
                                    {"error", "memory_read_failed"},
                                });
                            } else {
                                result.push_back({
                                    {"query", query_text},
                                    {"value", encode_hex_bytes(snapshot_bytes->bytes)},
                                });
                            }
                            continue;
                        }
                        auto item = invoke_legacy(
                            "get_global_value",
                            json{{"address", query_text}, {"size", 8}, {"as_type", "hex"}},
                            context);
                        if (!item.success) {
                            result.push_back({
                                {"query", query_text}, {"value", nullptr},
                                {"error", item.error_code.empty()
                                    ? "memory_read_failed" : item.error_code},
                            });
                        } else {
                            result.push_back({
                                {"query", query_text},
                                {"value", item.data.value("value", json(nullptr))},
                            });
                        }
                    }
                } else {
                    if (ranges == memory->end() || !ranges->is_array())
                        return tool_result_t::error(
                            "Memory ranges are missing.", std::string("MCP_MEMORY_INTENT_INVALID"));
                    for (const auto& range : *ranges) {
                        if (context.cancellation_requested())
                            return tool_result_t::error(
                                "Memory request was cancelled.", std::string("CANCELLED"));
                        const std::string address_text = range.at("addr").get<std::string>();
                        const auto address = range.at("address").get<std::uint64_t>();
                        const auto size = range.at("size").get<std::size_t>();
                        if (name == "get_string") {
                            if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                                const auto snapshot_bytes = read_snapshot_bytes(
                                    context, address, size, live_routing, cancellation);
                                if (!snapshot_bytes ||
                                    !accept_binding(snapshot_bytes->binding) ||
                                    !account_bytes(snapshot_bytes->bytes.size())) {
                                    result.push_back({
                                        {"addr", address_text}, {"value", nullptr},
                                        {"error", "memory_read_failed"},
                                    });
                                } else {
                                    std::string value;
                                    for (const auto byte : snapshot_bytes->bytes) {
                                        if (byte == 0)
                                            break;
                                        if (byte >= 0x20U && byte <= 0x7eU) {
                                            value.push_back(static_cast<char>(byte));
                                        } else {
                                            static constexpr char digits[] =
                                                "0123456789ABCDEF";
                                            value.append("\\x");
                                            value.push_back(digits[(byte >> 4U) & 0x0fU]);
                                            value.push_back(digits[byte & 0x0fU]);
                                        }
                                    }
                                    result.push_back({
                                        {"addr", address_text}, {"value", std::move(value)},
                                    });
                                }
                                continue;
                            }
                            auto item = invoke_legacy(
                                "get_string",
                                json{{"address", address_text},
                                     {"max_length", size}, {"encoding", "auto"}},
                                context);
                            if (!item.success) {
                                result.push_back({
                                    {"addr", address_text}, {"value", nullptr},
                                    {"error", item.error_code.empty()
                                        ? "memory_read_failed" : item.error_code},
                                });
                            } else {
                                result.push_back({
                                    {"addr", address_text},
                                    {"value", item.data.value("value", json(nullptr))},
                                });
                            }
                            continue;
                        }
                        const auto bytes = read_snapshot_bytes(
                            context, address, size, live_routing, cancellation);
                        if (!bytes || !accept_binding(bytes->binding) ||
                            !account_bytes(bytes->bytes.size())) {
                            result.push_back({
                                {"addr", address_text}, {"data", nullptr},
                                {"error", "memory_read_failed"},
                            });
                            continue;
                        }
                        result.push_back({
                            {"addr", address_text},
                            {"data", encode_hex_bytes(bytes->bytes)},
                        });
                    }
                }

                if (!live_snapshot_identity_current(context))
                    return tool_result_t::error(
                        "Live snapshot identity changed during the memory request.",
                        std::string("LIVE_SNAPSHOT_IDENTITY_CHANGED"));
                if (context.kind == aida::analysis::target_kind_t::live_snapshot && !binding)
                    return tool_result_t::error(
                        "Live memory response has no resolved target binding.",
                        std::string("LIVE_SNAPSHOT_BINDING_MISSING"));

                return tool_result_t::ok(json{
                    {"result", std::move(result)},
                    {"_aida_memory", json{{"snapshot",
                        memory_snapshot_receipt(context, bytes_read, binding)}}},
                });
            }

            tool_result_t invoke_memory_overlay_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                if (context.kind == aida::analysis::target_kind_t::live_snapshot)
                    return tool_result_t::error(
                        "Static overlay mutation is denied for live targets.",
                        std::string("STATIC_OVERLAY_LIVE_TARGET_DENIED"));
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory overlay intent is missing.", std::string("MCP_MEMORY_INTENT_INVALID"));
                const auto operations = memory->find("operations");
                if (operations == memory->end() || !operations->is_array() ||
                    operations->empty())
                    return tool_result_t::error(
                        "Memory overlay operations are missing.", std::string("MCP_MEMORY_INTENT_INVALID"));

                json legacy_items = json::array();
                json receipts = json::array();
                for (const auto& operation : *operations) {
                    if (context.cancellation_requested())
                        return tool_result_t::error(
                            "Memory overlay request was cancelled.", std::string("CANCELLED"));
                    const auto address = operation.at("address").get<std::uint64_t>();
                    const auto size = operation.at("size").get<std::size_t>();
                    const auto before = read_snapshot_bytes(
                        context, address, size, live_routing, cancellation);
                    const auto after = decode_hex_bytes(
                        operation.at("after").get_ref<const std::string&>());
                    if (!before || !after || after->size() != size)
                        return tool_result_t::error(
                            "Memory overlay bytes could not be captured.",
                            std::string("MCP_MEMORY_SNAPSHOT_FAILED"));
                    if (name == "patch") {
                        legacy_items.push_back({
                            {"address", operation.at("addr")},
                            {"bytes", operation.at("after")},
                        });
                    } else {
                        legacy_items.push_back({
                            {"address", operation.at("addr")},
                            {"ty", operation.at("ty")},
                            {"value", operation.at("value")},
                        });
                    }
                    receipts.push_back({
                        {"index", operation.at("index")},
                        {"kind", operation.at("kind")},
                        {"addr", operation.at("addr")},
                        {"size", size},
                        {"before", encode_hex_bytes(before->bytes)},
                        {"after", encode_hex_bytes(*after)},
                    });
                }

                json legacy_arguments{
                    {"items", std::move(legacy_items)},
                    {"aida_tx", json{{"expected_revision", context.overlay_revision}}},
                };
                if (name != "patch" && name != "put_int")
                    return tool_result_t::error(
                        "Memory overlay tool has no production handler.",
                        std::string("MCP_BACKEND_UNAVAILABLE"));
                auto committed = name == "patch"
                    ? invoke_legacy("patch", legacy_arguments, context)
                    : invoke_legacy("put_int", legacy_arguments, context);
                if (!committed.success)
                    return committed;
                const auto transaction_id = committed.data.find("transaction_id");
                const auto revision = committed.data.find("revision");
                if (transaction_id == committed.data.end() ||
                    revision == committed.data.end() ||
                    !transaction_id->is_number_unsigned() ||
                    !revision->is_number_unsigned())
                    return tool_result_t::error(
                        "Memory overlay receipt is incomplete.",
                        std::string("MCP_MEMORY_RECEIPT_INVALID"));
                const auto transaction_value = transaction_id->get<std::uint64_t>();
                const auto revision_after = revision->get<std::uint64_t>();
                if (transaction_value == 0 || revision_after <= context.overlay_revision)
                    return tool_result_t::error(
                        "Memory overlay revision did not advance.",
                        std::string("MCP_MEMORY_RECEIPT_INVALID"));

                committed.data["_aida_memory"]["transaction"] = {
                    {"transaction_id", std::to_string(transaction_value)},
                    {"committed", true},
                    {"reversible", true},
                    {"undo_supported", true},
                    {"undo_token", "overlay:" + std::to_string(transaction_value)},
                    {"live_write_performed", false},
                    {"generation", (std::max)(
                        std::uint64_t{1}, context.workspace->generation())},
                    {"overlay_revision_before", context.overlay_revision},
                    {"overlay_revision_after", revision_after},
                    {"operations", std::move(receipts)},
                };
                committed.text = committed.data.dump(2);
                return committed;
            }

            tool_result_t invoke_memory_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory adapter intent is missing.", std::string("MCP_MEMORY_INTENT_INVALID"));
                const std::string operation = memory->value("operation", std::string());
                if (operation == "read")
                    return invoke_memory_read_backend(
                        name, arguments, context, live_routing, cancellation);
                if (operation == "overlay_transaction")
                    return invoke_memory_overlay_backend(
                        name, arguments, context, live_routing, cancellation);
                return tool_result_t::error(
                    "Memory adapter operation is invalid.", std::string("MCP_MEMORY_INTENT_INVALID"));
            }

            static std::optional<aida::analysis::address_t> generated_overlay_address(
                const json& value, const workspace_request_context_t& context)
            {
                std::optional<std::uint64_t> parsed;
                bool explicit_va = false;
                if (value.is_string()) {
                    std::string text = value.get<std::string>();
                    if (text.rfind("rva:", 0) == 0 || text.rfind("RVA:", 0) == 0)
                        text.erase(0, 4);
                    else if (text.rfind("va:", 0) == 0 || text.rfind("VA:", 0) == 0) {
                        text.erase(0, 3);
                        explicit_va = true;
                    }
                    parsed = wave_c_address_value(text);
                } else {
                    parsed = wave_c_address_value(value);
                }
                if (!parsed)
                    return std::nullopt;
                const auto image = context.workspace->normalized_image();
                if (image && (explicit_va ||
                    (*parsed >= image->image_base && *parsed - image->image_base < image->image_size))) {
                    if (*parsed < image->image_base || *parsed - image->image_base >= image->image_size)
                        return std::nullopt;
                    *parsed -= image->image_base;
                }
                aida::analysis::address_t address;
                address.space = aida::analysis::address_space_id_t::relative_virtual;
                address.value = *parsed;
                address.architecture = context.workspace->identity().architecture();
                address.mode = context.workspace->identity().architecture_mode();
                return address;
            }

            static std::string canonical_overlay_address(
                const aida::analysis::address_t& address)
            {
                return hex_addr(address.value);
            }

            static std::optional<aida::analysis::address_t> generated_item_address(
                const json& item, const workspace_request_context_t& context)
            {
                const auto found = item.find("addr");
                return found == item.end()
                    ? std::nullopt : generated_overlay_address(*found, context);
            }

            static std::optional<aida::analysis::address_t> generated_item_end(
                const json& item, const workspace_request_context_t& context)
            {
                const auto found = item.find("end");
                return found == item.end()
                    ? std::nullopt : generated_overlay_address(*found, context);
            }

            static bool comment_contains_exact_line(
                std::string_view existing, std::string_view comment)
            {
                std::size_t begin = 0;
                while (begin <= existing.size()) {
                    const auto end = existing.find('\n', begin);
                    const auto line = existing.substr(
                        begin, end == std::string_view::npos ? existing.size() - begin : end - begin);
                    if (line == comment)
                        return true;
                    if (end == std::string_view::npos)
                        break;
                    begin = end + 1U;
                }
                return false;
            }

            static std::string existing_overlay_comment(
                const aida::analysis::overlay_snapshot_t& snapshot,
                const aida::analysis::address_t& address)
            {
                for (auto item = snapshot.items.rbegin(); item != snapshot.items.rend(); ++item) {
                    const auto& operation = item->second;
                    if ((operation.kind == aida::analysis::overlay_operation_kind_t::comment ||
                         operation.kind == aida::analysis::overlay_operation_kind_t::comment_update) &&
                        operation.address.space == address.space &&
                        operation.address.value == address.value)
                        return operation.text;
                }
                return {};
            }

            tool_result_t commit_generated_overlay(
                std::string_view name,
                std::vector<aida::analysis::overlay_operation_t> operations,
                json generated_output,
                const workspace_request_context_t& context,
                bool dry_run = false) const
            {
                if (context.kind != aida::analysis::target_kind_t::static_file)
                    return tool_result_t::error(
                        "Generated modify tools require a static analysis workspace.",
                        std::string("MCP_LIVE_MUTATION_DENIED"));
                const auto overlay = context.workspace->overlay();
                if (!overlay)
                    return tool_result_t::error(
                        "Reversible overlay journal is unavailable.", std::string("NO_OVERLAY"));
                if (operations.empty())
                    return tool_result_t::error(
                        "Generated modify transaction contains no operations.",
                        std::string("MCP_EMPTY_MUTATION"));
                const auto before = overlay->snapshot().revision;
                if (before != context.overlay_revision)
                    return tool_result_t::error(
                        "Overlay generation changed before the generated mutation committed.",
                        std::string("MCP_STALE_OVERLAY"));
                aida::analysis::overlay_transaction_request_t transaction;
                transaction.operations = std::move(operations);
                transaction.dry_run = dry_run;
                transaction.expected_revision = before;
                aida::analysis::cancellation_source_t cancellation;
                if (context.cancellation_requested())
                    cancellation.request_cancel();
                if (context.deadline_ms != 0) {
                    const auto now = static_cast<std::uint64_t>(GetTickCount64());
                    if (now >= context.deadline_ms)
                        return tool_result_t::error(
                            "Generated modify transaction deadline expired.",
                            std::string("DEADLINE_EXCEEDED"));
                    cancellation.set_deadline(
                        std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(context.deadline_ms - now));
                }
                auto committed = overlay->transact(transaction, cancellation.token());
                if (!committed)
                    return tool_result_t::error(
                        committed.error().message.empty()
                            ? "Generated modify transaction failed."
                            : committed.error().message,
                        std::string("MCP_OVERLAY_TRANSACTION_FAILED"));
                const auto& receipt = committed.value();
                if (receipt.operations.size() != transaction.operations.size())
                    return tool_result_t::error(
                        "Generated modify transaction returned an incomplete receipt.",
                        std::string("MCP_OVERLAY_RECEIPT_INVALID"));
                std::uint64_t transaction_id = receipt.transaction_id;
                if (transaction_id == 0) {
                    transaction_id = next_receipt_id_.fetch_add(1, std::memory_order_relaxed);
                    if (transaction_id == 0)
                        transaction_id = next_receipt_id_.fetch_add(1, std::memory_order_relaxed);
                }
                generated_output["committed"] = receipt.committed;
                generated_output["dry_run"] = receipt.dry_run;
                generated_output["item_count"] = transaction.operations.size();
                generated_output["items"] = json::array();
                generated_output["revision"] = receipt.revision;
                generated_output["transaction_id"] = transaction_id;
                generated_output["operations"] = receipt.operations.size();
                generated_output["_meta"]["aida"] = {
                    {"adapter", "ida_compat_mut"}, {"tool", std::string(name)},
                    {"mutation_mode", "reversible_overlay"},
                    {"target_binding", "workspace_request_context"},
                    {"ui_switched", false}, {"target_kind", "static_file"},
                    {"live_write", false}, {"target_file_write", false},
                    {"non_overlapping", true}, {"overlay_revision", before},
                };
                return tool_result_t::ok(std::move(generated_output));
            }

            tool_result_t invoke_modify_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (name == "add_bookmark") {
                    const auto address = generated_overlay_address(arguments.at("addr"), context);
                    if (!address)
                        return tool_result_t::error("Bookmark address is invalid.", std::string("INVALID_ADDRESS"));
                    const std::string prefix = arguments.value("prefix", "idaMCP: ");
                    const std::string title = prefix + arguments.at("name").get<std::string>();
                    aida::analysis::overlay_operation_t operation;
                    operation.kind = aida::analysis::overlay_operation_kind_t::bookmark;
                    operation.address = *address;
                    operation.name = title;
                    return commit_generated_overlay(
                        name, {std::move(operation)},
                        json{{"addr", canonical_overlay_address(*address)},
                             {"ea", canonical_overlay_address(*address)}, {"title", title},
                             {"prefix", prefix}, {"slot", nullptr}, {"ok", true}},
                        context);
                }

                if (name == "set_comments" || name == "append_comments") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    const auto overlay = context.workspace->overlay();
                    if (!overlay)
                        return tool_result_t::error(
                            "Reversible overlay journal is unavailable.", std::string("NO_OVERLAY"));
                    const auto snapshot = overlay->snapshot();
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error("Comment address is invalid.", std::string("INVALID_ADDRESS"));
                        const std::string comment = value.at("comment").get<std::string>();
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::comment_update;
                        operation.address = *address;
                        bool skipped = false;
                        if (name == "append_comments") {
                            const std::string existing = existing_overlay_comment(snapshot, *address);
                            skipped = value.value("dedupe", true) &&
                                comment_contains_exact_line(existing, comment);
                            operation.text = existing;
                            if (!skipped) {
                                if (!operation.text.empty())
                                    operation.text.push_back('\n');
                                operation.text.append(comment);
                            }
                            result.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"appended", !skipped}, {"skipped", skipped},
                                {"scope", value.value("scope", "auto")},
                            });
                        } else {
                            operation.text = comment;
                            result.push_back({{"addr", canonical_overlay_address(*address)}});
                        }
                        operations.push_back(std::move(operation));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "define_code" || name == "define_func" || name == "undefine") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Definition address is invalid.", std::string("INVALID_ADDRESS"));
                        auto end = generated_item_end(value, context);
                        if (!end && name != "define_func") {
                            const auto size = value.value("size", std::uint64_t{1});
                            if (size == 0 || size >
                                (std::numeric_limits<std::uint64_t>::max)() - address->value)
                                return tool_result_t::error(
                                    "Definition size is invalid.", std::string("INVALID_RANGE"));
                            end = *address;
                            end->value += size;
                        }
                        if (end && end->value <= address->value)
                            return tool_result_t::error(
                                "Definition range is not increasing.", std::string("INVALID_RANGE"));
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = name == "define_code"
                            ? aida::analysis::overlay_operation_kind_t::define_code
                            : name == "define_func"
                                ? aida::analysis::overlay_operation_kind_t::define_function
                                : aida::analysis::overlay_operation_kind_t::undefine;
                        operation.address = *address;
                        operation.end = end;
                        json item{
                            {"addr", canonical_overlay_address(*address)},
                            {"start", canonical_overlay_address(*address)},
                            {"ea", canonical_overlay_address(*address)},
                        };
                        if (end) {
                            item["end"] = canonical_overlay_address(*end);
                            item["size"] = end->value - address->value;
                            item["length"] = end->value - address->value;
                        }
                        operations.push_back(std::move(operation));
                        result.push_back(std::move(item));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "make_data") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address || !value.contains("type") || !value.at("type").is_string() ||
                            value.at("type").get_ref<const std::string&>().empty())
                            return tool_result_t::error(
                                "Data definition requires a valid address and type.",
                                std::string("INVALID_DATA_DEFINITION"));
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::define_data;
                        operation.address = *address;
                        operation.type = value.at("type").get<std::string>();
                        operation.name = value.value("name", std::string());
                        json item{
                            {"addr", canonical_overlay_address(*address)},
                            {"type", operation.type}, {"ok", true},
                        };
                        if (!operation.name.empty())
                            item["name"] = operation.name;
                        operations.push_back(std::move(operation));
                        result.push_back(std::move(item));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "patch_asm") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    const auto image = context.workspace->normalized_image();
                    if (!image)
                        return tool_result_t::error(
                            "Assembly patching requires a normalized image.",
                            std::string("ANALYSIS_UNAVAILABLE"));
                    using architecture_t = aida::analysis::architecture_id_t;
                    if (image->architecture != architecture_t::x86 &&
                        image->architecture != architecture_t::x86_64)
                        return tool_result_t::error(
                            "Assembly patching supports x86 and x86-64 workspaces only.",
                            std::string("UNSUPPORTED_ARCHITECTURE"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Assembly patch address is invalid.", std::string("INVALID_ADDRESS"));
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::assembly_patch;
                        operation.address = *address;
                        operation.assembly = value.at("asm").get<std::string>();
                        if (address->value >
                            (std::numeric_limits<std::uint64_t>::max)() - image->image_base)
                            return tool_result_t::error(
                                "Assembly patch address overflows the workspace image base.",
                                std::string("INVALID_ADDRESS"));
                        std::string assembly_error;
                        auto assembled = assemble_x86_overlay(
                            operation.assembly, image->image_base + address->value,
                            image->architecture == architecture_t::x86_64,
                            assembly_error);
                        if (!assembled)
                            return tool_result_t::error(
                                assembly_error.empty()
                                    ? "Assembly patch could not be encoded."
                                    : std::move(assembly_error),
                                std::string("ASSEMBLY_ENCODING_FAILED"));
                        operation.bytes = std::move(*assembled);
                        operations.push_back(std::move(operation));
                        result.push_back({{"addr", canonical_overlay_address(*address)}});
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "force_recompile") {
                    json values = arguments.contains("items") && !arguments.at("items").is_null()
                        ? scalar_or_array_items(arguments.at("items")) : json::array();
                    const bool full_workspace = values.empty();
                    if (full_workspace) {
                        json address = "0x0";
                        const auto snapshot = context.workspace->snapshot();
                        if (snapshot && !snapshot->functions.empty())
                            address = hex_addr(snapshot->functions.front().start.value);
                        values.push_back(json{{"addr", std::move(address)}});
                    }
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Recompile address is invalid.", std::string("INVALID_ADDRESS"));
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::reanalysis;
                        operation.address = *address;
                        operation.reanalysis_flags = full_workspace
                            ? (std::numeric_limits<std::uint32_t>::max)() : 0U;
                        operations.push_back(std::move(operation));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json::object(), context);
                }

                if (name == "set_op_type") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        const std::string kind = value.value("kind", std::string());
                        if (!address || kind.empty())
                            return tool_result_t::error(
                                "Operand type requires a valid address and kind.",
                                std::string("INVALID_OPERAND_TYPE"));
                        const auto operand = value.value("op_n", std::uint64_t{0});
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::type_update;
                        operation.address = *address;
                        operation.name = "operand_" + std::to_string(operand);
                        operation.variable = value.value("struct", std::string());
                        operation.type = kind;
                        if (value.contains("target_addr"))
                            operation.type.append(":" + value.at("target_addr").get<std::string>());
                        if (value.contains("delta"))
                            operation.type.append(":" + value.at("delta").dump());
                        operations.push_back(std::move(operation));
                        result.push_back({
                            {"addr", canonical_overlay_address(*address)},
                            {"kind", kind}, {"op_n", operand}, {"ok", true},
                        });
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "rename") {
                    const auto& batch = arguments.at("batch");
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json function_results = json::array();
                    json data_results = json::array();
                    json local_results = json::array();
                    json stack_results = json::array();
                    const auto append_functions = [&](const json& collection) -> bool {
                        for (const auto& value : scalar_or_array_items(collection)) {
                            const auto address = generated_item_address(value, context);
                            if (!address)
                                return false;
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::name;
                            operation.address = *address;
                            operation.name = value.at("name").get<std::string>();
                            operations.push_back(std::move(operation));
                            function_results.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"name", value.at("name")},
                                {"new", value.at("name")},
                                {"dry_run", batch.value("dry_run", false)},
                            });
                        }
                        return true;
                    };
                    if (batch.contains("func") && !append_functions(batch.at("func")))
                        return tool_result_t::error(
                            "Function rename address is invalid.", std::string("INVALID_ADDRESS"));
                    if (batch.contains("data")) {
                        const auto snapshot = context.workspace->snapshot();
                        if (!snapshot)
                            return tool_result_t::error(
                                "Data rename requires an analysis snapshot.", std::string("NO_SNAPSHOT"));
                        for (const auto& value : scalar_or_array_items(batch.at("data"))) {
                            const std::string old_name = value.at("old").get<std::string>();
                            const auto symbol = std::find_if(
                                snapshot->symbols.begin(), snapshot->symbols.end(),
                                [&old_name](const auto& candidate) {
                                    return candidate.name == old_name;
                                });
                            if (symbol == snapshot->symbols.end())
                                return tool_result_t::error(
                                    "Data rename source symbol was not found.", std::string("SYMBOL_NOT_FOUND"));
                            const auto address = generated_overlay_address(
                                hex_addr(symbol->address.value), context);
                            if (!address)
                                return tool_result_t::error(
                                    "Data rename address is invalid.", std::string("INVALID_ADDRESS"));
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::name;
                            operation.address = *address;
                            operation.name = value.at("new").get<std::string>();
                            operations.push_back(std::move(operation));
                            data_results.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"old", old_name}, {"new", value.at("new")},
                                {"dry_run", batch.value("dry_run", false)},
                            });
                        }
                    }
                    const auto append_scoped = [&](const json& collection, bool local) -> bool {
                        for (const auto& value : scalar_or_array_items(collection)) {
                            const auto function_address = generated_overlay_address(
                                value.at("func_addr"), context);
                            if (!function_address)
                                return false;
                            const std::string old_name = value.at("old").get<std::string>();
                            const auto frame = invoke_legacy(
                                "stack_frame", json{{"address", value.at("func_addr")}}, context);
                            if (!frame.success)
                                return false;
                            const auto slots = frame.data.find("slots");
                            if (slots == frame.data.end() || !slots->is_array())
                                return false;
                            const auto slot = std::find_if(
                                slots->begin(), slots->end(), [&old_name, local](const json& candidate) {
                                    return candidate.is_object() &&
                                        candidate.value("name", std::string()) == old_name &&
                                        (!local || candidate.value("is_local", false) ||
                                         candidate.value("source", std::string()).find("declared") !=
                                             std::string::npos);
                                });
                            if (slot == slots->end() || !slot->contains("offset") ||
                                !slot->at("offset").is_number_integer())
                                return false;
                            const std::string type = slot->value("type", std::string());
                            if (type.empty())
                                return false;
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::stack_variable;
                            operation.address = *function_address;
                            operation.stack_offset = slot->at("offset").get<std::int64_t>();
                            operation.variable = value.at("new").get<std::string>();
                            operation.type = type;
                            operations.push_back(std::move(operation));
                            json item{
                                {"func_addr", canonical_overlay_address(*function_address)},
                                {"old", old_name}, {"new", value.at("new")},
                                {"dry_run", batch.value("dry_run", false)},
                            };
                            (local ? local_results : stack_results).push_back(std::move(item));
                        }
                        return true;
                    };
                    if (batch.contains("local") &&
                        !append_scoped(batch.at("local"), true))
                        return tool_result_t::error(
                            "Local rename source has no stable declared stack-slot identity.",
                            std::string("MCP_LOCAL_RENAME_UNRESOLVED"));
                    if (batch.contains("stack") &&
                        !append_scoped(batch.at("stack"), false))
                        return tool_result_t::error(
                            "Stack rename source has no stable declared slot identity.",
                            std::string("MCP_STACK_RENAME_UNRESOLVED"));
                    json output{
                        {"func", std::move(function_results)}, {"data", std::move(data_results)},
                        {"local", std::move(local_results)}, {"stack", std::move(stack_results)},
                        {"global_alias", json::array()},
                    };
                    output["summary"] = {
                        {"total", operations.size()}, {"ok", operations.size()}, {"failed", 0},
                        {"dry_run", batch.value("dry_run", false)},
                        {"allow_overwrite", batch.value("allow_overwrite", false)},
                        {"stop_on_error", batch.value("stop_on_error", false)}, {"stopped", false},
                    };
                    return commit_generated_overlay(
                        name, std::move(operations), std::move(output), context,
                        batch.value("dry_run", false));
                }

                return tool_result_t::error(
                    "Modify adapter is not registered for " + std::string(name) + ".",
                    std::string("MCP_BACKEND_UNAVAILABLE"));
            }

            wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>
            invoke_workspace_backend(
                const wave_c_compat::adapter_call_context_t& call,
                const wave_c_compat::adapter_request_t& request,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                if (!call.contract)
                    return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::invalid_request,
                         "workspace_contract_missing", 0, 0});
                const auto current_generation = wave_c_workspace_generation(context);
                if (request.expected_generation &&
                    *request.expected_generation != current_generation)
                    return wave_c_compat::adapter_result_t<
                        wave_c_compat::adapter_response_t>::failure(
                            {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                             "workspace_generation_stale",
                             *request.expected_generation, current_generation});
                json arguments = json::parse(request.payload, nullptr, false);
                if (arguments.is_discarded() || !arguments.is_object())
                    return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::invalid_request,
                         "workspace_payload_invalid", 0, 0});
                if (wave_c_name_in(wave_c_handlers::types_tool_names(), call.contract->name)) {
                    return call.effect.mutates_workspace
                        ? types_store_.handle_overlay(call, request)
                        : types_store_.handle_query(call, request);
                }
                if (wave_c_name_in(wave_c_handlers::modify_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_modify_backend(call.contract->name, arguments, context));
                }
                if (wave_c_name_in(wave_c_handlers::memory_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_memory_backend(
                            call.contract->name, arguments, context,
                            live_routing, cancellation));
                }
                if (wave_c_name_in(wave_c_handlers::analysis_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_analysis_backend(call.contract->name, arguments, context));
                }
                if (wave_c_name_in(wave_c_handlers::core_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_core_backend(call.contract->name, arguments, context));
                }
                if (call.contract->name == "stack_frame")
                    return wave_c_adapter_result(
                        invoke_legacy("stack_frame", arguments, context));
                if (call.contract->name == "declare_stack")
                    return wave_c_adapter_result(
                        invoke_legacy("declare_stack", arguments, context));
                if (call.contract->name == "delete_stack")
                    return wave_c_adapter_result(
                        invoke_legacy("delete_stack", arguments, context));
                if (call.contract->name == "analyze_funcs")
                    return wave_c_adapter_result(
                        invoke_legacy("analyze_funcs", arguments, context));
                if (call.contract->name == "find_insns")
                    return wave_c_adapter_result(
                        invoke_legacy("find_insns", arguments, context));
                return wave_c_compat::adapter_result_t<
                    wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::backend_unavailable,
                         "workspace_adapter_group_unregistered", 0, 0});
            }

            static wave_c_compat::adapter_result_t<
                wave_c_compat::bounded_live_snapshot_t> capture_live_snapshot_backend(
                const wave_c_compat::adapter_call_context_t& call,
                const wave_c_compat::bounded_live_snapshot_request_t& request,
                const workspace_request_context_t& context)
            {
                if (!call.target || !call.target->target().live)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_denied,
                         "live_snapshot_target_unbound", 0, request.size});
                const auto& target = call.target->target();
                const auto generation_before = wave_c_workspace_generation(context);
                if (generation_before != target.generation)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                         "live_snapshot_generation_stale",
                         target.generation, generation_before});
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                if (!provider || request.size == 0)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_denied,
                         "live_snapshot_denied", 0, request.size});
                if (request.deadline &&
                    std::chrono::steady_clock::now() >= *request.deadline)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_deadline_exceeded", 0, request.size});
                const auto identity_before = provider->validate_current_identity();
                if (!identity_before)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_identity_invalid", 0, request.size});
                const auto& metadata = provider->metadata();
                if (metadata.process.pid != target.pid ||
                    metadata.process.creation_time_100ns !=
                        target.process_creation_identity ||
                    metadata.capture_address != target.live_capture_base ||
                    metadata.capture_size != target.live_capture_size)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_resolved_identity_mismatch",
                         target.process_creation_identity,
                         metadata.process.creation_time_100ns});
                if (request.address < metadata.capture_address ||
                    request.address - metadata.capture_address > metadata.capture_size ||
                    request.size > metadata.capture_size -
                        (request.address - metadata.capture_address))
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_bounds,
                         "live_snapshot_bounds", metadata.capture_size, request.size});
                const auto read = provider->read_vector(
                    request.address - metadata.capture_address,
                    request.size, request.size);
                if (!read || read.value().size() != request.size)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_invalid", request.size, 0});
                const auto identity_after = provider->validate_current_identity();
                if (!identity_after)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_identity_changed", request.size, 0});
                const auto generation_after = wave_c_workspace_generation(context);
                if (generation_after != target.generation)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                         "live_snapshot_generation_changed",
                         target.generation, generation_after});
                wave_c_compat::bounded_live_snapshot_t result;
                result.bytes = read.value();
                result.process_creation_identity = target.process_creation_identity;
                result.attach_generation = target.attach_generation;
                result.generation = target.generation;
                return wave_c_live_snapshot_result_t::success(std::move(result));
            }

            static wave_c_handlers::composite_step_response_t
            apply_managed_overlay_action(
                const wave_c_handlers::composite_step_request_t& request,
                const wave_c_protocol::cancellation_token_t& cancellation,
                const workspace_request_context_t& context)
            {
                wave_c_handlers::composite_step_response_t response;
                response.workspace_generation = wave_c_workspace_generation(context);
                response.observed_overlay_generation =
                    context.workspace->overlay_revision();
                const auto reject = [&response](
                    std::string code, std::string message) {
                    response.status =
                        wave_c_handlers::composite_step_status_t::rejected;
                    response.diagnostic_code = std::move(code);
                    response.diagnostic_message = std::move(message);
                    response.payload =
                        wave_c_handlers::composite_overlay_result_t{
                            false, std::string()};
                    return response;
                };
                if (request.expected_overlay_generation &&
                    *request.expected_overlay_generation !=
                        *response.observed_overlay_generation) {
                    return reject("overlay_generation_stale",
                        "Managed overlay revision no longer matches the request.");
                }
                if (cancellation.cancelled()) {
                    response.status =
                        wave_c_handlers::composite_step_status_t::cancelled;
                    response.diagnostic_code = "cancelled";
                    return response;
                }
                const auto entity = aida::workbench::
                    pseudocode_document::parse_pseudocode_entity_locator(
                        request.subject);
                if (!entity || entity->address || !entity->token ||
                    !entity->artifact_ordinal || !entity->expected_kind ||
                    *entity->expected_kind ==
                        aida::analysis::decompiler_entity_kind_t::native_function) {
                    return reject("managed_overlay_entity_invalid",
                        "Managed overlay action requires a canonical managed entity locator.");
                }
                aida::analysis::cancellation_source_t source(
                    wave_c_deadline(context));
                if (cancellation.cancelled())
                    source.request_cancel();
                auto integration = aida::analysis::decompiler_ui_integration_t::
                    production_for_workspace(context.workspace);
                if (!integration)
                    return reject(integration.error().stable_code(),
                        integration.error().message);
                auto binding = integration.value()->resolve_entity_at(
                    *entity, source.token());
                if (!binding)
                    return reject(binding.error().stable_code(),
                        binding.error().message);
                if (cancellation.cancelled()) {
                    source.request_cancel();
                    response.status =
                        wave_c_handlers::composite_step_status_t::cancelled;
                    response.diagnostic_code = "cancelled";
                    return response;
                }
                auto locator = aida::analysis::bind_managed_overlay_entity_v9(
                    *context.workspace, binding.value());
                if (!locator)
                    return reject(locator.error().stable_code(),
                        locator.error().message);
                auto journal = context.workspace->overlay();
                if (!journal)
                    return reject("WORKSPACE_OVERLAY_UNAVAILABLE",
                        "Workspace overlay journal is unavailable.");

                aida::analysis::overlay_operation_t operation;
                operation.target_discriminator =
                    aida::analysis::overlay_target_discriminator_v9_t::
                        managed_entity;
                operation.managed_locator = locator.value();
                if (request.action == "set_comment" &&
                    request.action_arguments.contains("comment") &&
                    request.action_arguments.at("comment").is_string()) {
                    operation.kind =
                        aida::analysis::overlay_operation_kind_t::comment;
                    operation.text = request.action_arguments.at("comment")
                        .get<std::string>();
                } else if (request.action == "rename_func" &&
                    request.action_arguments.contains("name") &&
                    request.action_arguments.at("name").is_string()) {
                    operation.kind =
                        aida::analysis::overlay_operation_kind_t::name;
                    operation.name = request.action_arguments.at("name")
                        .get<std::string>();
                } else if (request.action == "set_type" &&
                    request.action_arguments.contains("type") &&
                    request.action_arguments.at("type").is_string()) {
                    operation.kind = aida::analysis::
                        overlay_operation_kind_t::type_application;
                    operation.name = "entity";
                    operation.type = request.action_arguments.at("type")
                        .get<std::string>();
                } else {
                    return reject("unsupported_overlay_action",
                        "Managed overlay action is unsupported or malformed.");
                }

                const auto prior = journal->snapshot();
                const auto same_target = [&operation](const auto& item) {
                    const auto& existing = item.second;
                    return existing.target_discriminator ==
                            aida::analysis::overlay_target_discriminator_v9_t::
                                managed_entity &&
                        existing.managed_locator && operation.managed_locator &&
                        existing.managed_locator->stable_identity_equal(
                            *operation.managed_locator);
                };
                if (operation.kind ==
                        aida::analysis::overlay_operation_kind_t::comment &&
                    std::any_of(prior.items.begin(), prior.items.end(),
                        [&same_target](const auto& item) {
                            return same_target(item) &&
                                (item.second.kind == aida::analysis::
                                     overlay_operation_kind_t::comment ||
                                 item.second.kind == aida::analysis::
                                     overlay_operation_kind_t::comment_update);
                        })) {
                    operation.kind = aida::analysis::
                        overlay_operation_kind_t::comment_update;
                } else if (operation.kind == aida::analysis::
                               overlay_operation_kind_t::type_application &&
                    std::any_of(prior.items.begin(), prior.items.end(),
                        [&same_target](const auto& item) {
                            return same_target(item) &&
                                (item.second.kind == aida::analysis::
                                     overlay_operation_kind_t::type_application ||
                                 item.second.kind == aida::analysis::
                                     overlay_operation_kind_t::type_update);
                        })) {
                    operation.kind = aida::analysis::
                        overlay_operation_kind_t::type_update;
                }

                aida::analysis::overlay_transaction_request_t transaction;
                transaction.expected_revision =
                    *response.observed_overlay_generation;
                if (!context.request_id.empty()) {
                    transaction.idempotency_key = "mcp-managed-overlay:" +
                        aida::analysis::stable_serialization_hash(
                            context.request_id + ":" + request.action + ":" +
                            request.subject).to_hex();
                }
                transaction.operations.push_back(std::move(operation));
                if (cancellation.cancelled())
                    source.request_cancel();
                auto committed = journal->transact(transaction, source.token());
                if (!committed)
                    return reject(committed.error().stable_code(),
                        committed.error().message);
                if (!committed.value().committed ||
                    committed.value().revision <=
                        *response.observed_overlay_generation) {
                    return reject("overlay_commit_receipt_invalid",
                        "Managed overlay transaction did not publish a new revision.");
                }
                response.payload =
                    wave_c_handlers::composite_overlay_result_t{
                        true, request.action};
                response.status =
                    wave_c_handlers::composite_step_status_t::complete;
                response.committed_overlay_generation =
                    committed.value().revision;
                response.items_consumed = committed.value().operations.size();
                return response;
            }

            wave_c_handlers::composite_step_response_t invoke_composite_step(
                const wave_c_compat::adapter_call_context_t&,
                const wave_c_handlers::composite_step_request_t& request,
                const wave_c_protocol::cancellation_token_t& cancellation,
                const workspace_request_context_t& context) const
            {
                wave_c_handlers::composite_step_response_t response;
                response.workspace_generation = wave_c_workspace_generation(context);
                response.observed_overlay_generation =
                    context.workspace->overlay_revision();
                if (cancellation.cancelled()) {
                    response.status = wave_c_handlers::composite_step_status_t::cancelled;
                    response.diagnostic_code = "cancelled";
                    return response;
                }
                const auto snapshot = context.workspace->snapshot();
                const auto parsed = wave_c_address_value(request.subject);
                const std::uint64_t address = parsed.value_or(0);
                const bool managed_subject = managed_decompiler_selector(
                    json(request.subject));
                if (request.kind == wave_c_handlers::composite_step_kind_t::decompile_function ||
                    request.kind == wave_c_handlers::composite_step_kind_t::disassemble_function) {
                    const bool decompile = request.kind ==
                        wave_c_handlers::composite_step_kind_t::decompile_function;
                    auto result = decompile
                        ? invoke_legacy(
                            "decompile", json{{"address", request.subject}}, context)
                        : invoke_legacy(
                            "disasm", json{{"address", request.subject}}, context);
                    wave_c_handlers::composite_text_snapshot_t text;
                    if (result.success) {
                        const json& normalized = result.data;
                        if (decompile)
                            text.text = normalized.value(
                                "pseudocode", std::string());
                        else if (normalized.contains("instructions"))
                            text.text = normalized["instructions"].dump();
                        else
                            text.text = result.text;
                        text.truncated = decompile && normalized.value(
                            "pseudocode_truncated", false);
                        response.status = wave_c_handlers::composite_step_status_t::complete;
                    } else {
                        text.error = result.text;
                        response.status = wave_c_handlers::composite_step_status_t::unavailable;
                        response.diagnostic_code = result.error_code.empty()
                            ? "backend_unavailable" : result.error_code;
                    }
                    response.payload = std::move(text);
                    return response;
                }
                if (request.kind ==
                        wave_c_handlers::composite_step_kind_t::function_snapshot &&
                    managed_subject) {
                    const auto result = invoke_legacy(
                        "decompile", json{{"address", request.subject}}, context);
                    if (!result.success) {
                        response.status =
                            wave_c_handlers::composite_step_status_t::unavailable;
                        response.diagnostic_code = result.error_code.empty()
                            ? "managed_entity_unavailable" : result.error_code;
                        response.diagnostic_message = result.text;
                        return response;
                    }
                    wave_c_handlers::composite_function_snapshot_t value;
                    value.addr = result.data.value("address", request.subject);
                    value.name = result.data.value("name", request.subject);
                    value.prototype = result.data.contains("prototype") &&
                            result.data.at("prototype").is_string()
                        ? std::optional<std::string>(
                            result.data.at("prototype").get<std::string>())
                        : std::nullopt;
                    if (const auto size = wave_c_address_value(
                            result.data.value("size", json())))
                        value.size = *size;
                    for (const auto& callee :
                         result.data.value("callees", json::array())) {
                        if (!callee.is_object() ||
                            !callee.contains("address") ||
                            !callee.at("address").is_string())
                            continue;
                        value.callees.push_back(
                            callee.at("address").get<std::string>());
                        if (value.callees.size() >= request.max_items)
                            break;
                    }
                    response.payload = std::move(value);
                    response.status =
                        wave_c_handlers::composite_step_status_t::partial;
                    response.diagnostic_code =
                        "managed_native_facts_unavailable";
                    response.diagnostic_message =
                        "Native-only CFG, xref, string, and caller facts are unavailable for this managed entity.";
                    return response;
                }
                if (request.kind ==
                        wave_c_handlers::composite_step_kind_t::apply_overlay_action &&
                    managed_subject) {
                    return apply_managed_overlay_action(
                        request, cancellation, context);
                }
                if (!snapshot || !parsed) {
                    response.status = wave_c_handlers::composite_step_status_t::unavailable;
                    response.diagnostic_code = "snapshot_or_address_unavailable";
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::function_snapshot) {
                    const auto function = std::find_if(
                        snapshot->functions.begin(), snapshot->functions.end(),
                        [address](const auto& value) {
                            return value.start.value <= address && address < value.end.value;
                        });
                    if (function == snapshot->functions.end()) {
                        response.status = wave_c_handlers::composite_step_status_t::unavailable;
                        response.diagnostic_code = "function_not_found";
                        return response;
                    }
                    wave_c_handlers::composite_function_snapshot_t value;
                    value.addr = hex_addr(function->start.value);
                    value.name = "sub_" + value.addr.substr(2);
                    value.size = function->end.value - function->start.value;
                    value.basic_block_count = function->block_count;
                    value.comments = json::object();
                    for (const auto& edge : snapshot->edges) {
                        if (edge.source.value >= function->start.value &&
                            edge.source.value < function->end.value &&
                            (edge.kind == aida::analysis::edge_kind_t::call ||
                             edge.kind == aida::analysis::edge_kind_t::tail_call))
                            value.callees.push_back(hex_addr(edge.target.value));
                    }
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::xref_neighbors) {
                    wave_c_handlers::composite_xref_batch_t value;
                    for (const auto& xref : snapshot->xrefs) {
                        const bool outgoing = xref.source.value == address;
                        const bool incoming = xref.target.value == address;
                        if ((!outgoing && !incoming) ||
                            (request.direction == "out" && !outgoing) ||
                            (request.direction == "in" && !incoming))
                            continue;
                        value.neighbors.push_back({
                            hex_addr(outgoing ? xref.target.value : xref.source.value),
                            outgoing ? "out" : "in"});
                        if (request.max_items != 0 &&
                            value.neighbors.size() >= request.max_items)
                            break;
                    }
                    response.items_consumed = value.neighbors.size();
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::address_snapshot) {
                    wave_c_handlers::composite_address_snapshot_t value;
                    value.addr = hex_addr(address);
                    value.type = "address";
                    const auto function = std::find_if(
                        snapshot->functions.begin(), snapshot->functions.end(),
                        [address](const auto& item) {
                            return item.start.value <= address && address < item.end.value;
                        });
                    if (function != snapshot->functions.end())
                        value.function = "sub_" + hex_addr(function->start.value).substr(2);
                    const auto instruction = std::find_if(
                        snapshot->instructions.begin(), snapshot->instructions.end(),
                        [address](const auto& item) { return item.address.value == address; });
                    if (instruction != snapshot->instructions.end())
                        value.instruction = "mnemonic_" + std::to_string(instruction->mnemonic_id);
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::apply_overlay_action) {
                    if (request.expected_overlay_generation &&
                        *request.expected_overlay_generation !=
                            *response.observed_overlay_generation) {
                        response.status =
                            wave_c_handlers::composite_step_status_t::rejected;
                        response.diagnostic_code = "overlay_generation_stale";
                        return response;
                    }
                    json item{{"address", request.subject}};
                    if (request.action == "rename_func") {
                        item["name"] = request.action_arguments.at("name");
                    } else if (request.action == "set_type") {
                        item["type"] = request.action_arguments.at("type");
                    } else if (request.action == "set_comment") {
                        item["comment"] = request.action_arguments.at("comment");
                    } else {
                        response.status =
                            wave_c_handlers::composite_step_status_t::rejected;
                        response.diagnostic_code = "unsupported_overlay_action";
                        return response;
                    }
                    const json backend_arguments{
                        {"items", json::array({std::move(item)})},
                        {"aida_tx", json{{"expected_revision",
                            *response.observed_overlay_generation}}},
                    };
                    auto result = request.action == "rename_func"
                        ? invoke_legacy("rename", backend_arguments, context)
                        : request.action == "set_type"
                            ? invoke_legacy("set_type", backend_arguments, context)
                            : invoke_legacy(
                                "set_comments", backend_arguments, context);
                    response.payload = wave_c_handlers::composite_overlay_result_t{
                        result.success, request.action};
                    response.status = result.success
                        ? wave_c_handlers::composite_step_status_t::complete
                        : wave_c_handlers::composite_step_status_t::rejected;
                    response.diagnostic_message = result.text;
                    response.diagnostic_code = result.error_code;
                    if (result.success) {
                        const auto revision = result.data.contains("revision")
                            ? json_nonnegative_u64(result.data.at("revision"))
                            : std::nullopt;
                        if (!revision || *revision <=
                                *response.observed_overlay_generation) {
                            response.payload =
                                wave_c_handlers::composite_overlay_result_t{
                                    false, request.action};
                            response.status =
                                wave_c_handlers::composite_step_status_t::rejected;
                            response.diagnostic_code =
                                "overlay_commit_receipt_invalid";
                        } else {
                            response.committed_overlay_generation = *revision;
                            response.items_consumed = 1;
                        }
                    }
                    return response;
                }
                response.status = wave_c_handlers::composite_step_status_t::rejected;
                response.diagnostic_code = "unsupported_composite_step";
                return response;
            }

            static wave_c_compat::adapter_result_t<
                wave_c_handlers::survey_generation_lease_t> acquire_survey_generation(
                const workspace_request_context_t& context)
            {
                wave_c_handlers::survey_generation_lease_t lease;
                lease.owner = std::static_pointer_cast<const void>(context.workspace);
                lease.identity.workspace_id = context.binary_id.to_hex();
                lease.identity.pid = context.pid;
                lease.identity.bin_name = context.workspace->identity().bin_name();
                lease.identity.normalized_source_path =
                    context.workspace->identity().normalized_source_path();
                lease.identity.sha256 = context.binary_id.to_hex();
                lease.image = context.workspace->normalized_image();
                lease.analysis = context.workspace->snapshot();
                if (lease.analysis) {
                    lease.identity.generation = lease.analysis->generation;
                    lease.identity.analysis_revision = lease.analysis->analysis_revision;
                    lease.identity.overlay_revision = lease.analysis->overlay_revision;
                } else {
                    lease.identity.generation = wave_c_workspace_generation(context);
                    lease.identity.analysis_revision = context.analysis_revision;
                    lease.identity.overlay_revision = context.overlay_revision;
                }
                lease.identity.live =
                    context.kind == aida::analysis::target_kind_t::live_snapshot;
                if (lease.identity.live) {
                    const auto provider = std::dynamic_pointer_cast<
                        const aida::analysis::live_snapshot_provider_t>(
                            context.workspace->provider_handle());
                    lease.identity.live_snapshot_current = provider &&
                        provider->validate_current_identity().has_value();
                }
                lease.image = context.workspace->normalized_image();
                lease.analysis = context.workspace->snapshot();
                return wave_c_survey_lease_result_t::success(std::move(lease));
            }

            static wave_c_compat::adapter_result_t<
                wave_c_handlers::python_target_lease_t> acquire_python_target(
                const workspace_request_context_t& context)
            {
                wave_c_handlers::python_target_lease_t lease;
                lease.owner = std::static_pointer_cast<const void>(context.workspace);
                lease.workspace_id = context.binary_id.to_hex();
                lease.pid = context.pid;
                lease.bin_name = context.workspace->identity().bin_name();
                lease.normalized_source_path =
                    context.workspace->identity().normalized_source_path();
                lease.generation = context.workspace->generation();
                lease.analysis_revision = context.analysis_revision;
                lease.overlay_revision = context.overlay_revision;
                lease.live = context.kind == aida::analysis::target_kind_t::live_snapshot;
                lease.workspace_metadata = isolated_python_workspace_metadata(context);
                lease.workspace_api = [&context](const auto& query, const std::atomic<bool>*) {
                    return isolated_python_workspace_api(query, context);
                };
                return wave_c_python_lease_result_t::success(std::move(lease));
            }

            static python_compat::python_worker_execution_result_t execute_python_worker(
                const fs::path& script_root,
                const python_compat::python_worker_execution_request_t& request)
            {
                python_compat::python_worker_execution_result_t rejected;
                const auto package_root = standalone_package_root();
                if (!package_root) {
                    rejected.error_code = "PYTHON_WORKER_PACKAGE_REJECTED";
                    return rejected;
                }
                auto contract = python_compat::resolve_python_worker_launch_contract(
                    *package_root, script_root);
                if (!contract.valid() || !contract.value) {
                    rejected.error_code = contract.error.empty()
                        ? "PYTHON_WORKER_PACKAGE_REJECTED" : contract.error;
                    return rejected;
                }
                python_compat::python_worker_host_t host(std::move(*contract.value));
                return host.execute(request);
            }

            static tool_result_t checkpoint_workspace(
                const workspace_request_context_t& context)
            {
                const auto database = context.workspace->database();
                if (!database)
                    return tool_result_t::error(
                        "Workspace persistence is unavailable.", std::string("WORKSPACE_DATABASE_UNAVAILABLE"));
                auto ticket = database->checkpoint(false);
                if (!ticket.accepted || !ticket.completion.valid())
                    return tool_result_t::error(
                        "Workspace checkpoint was not accepted.", std::string("WORKSPACE_CHECKPOINT_REJECTED"));
                const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(30);
                if (ticket.completion.wait_until(deadline) != std::future_status::ready)
                    return tool_result_t::error(
                        "Workspace checkpoint exceeded its bounded deadline.",
                        std::string("WORKSPACE_CHECKPOINT_TIMEOUT"));
                const auto result = ticket.completion.get();
                if (!result)
                    return tool_result_t::error(
                        "Workspace checkpoint failed.", std::string("WORKSPACE_CHECKPOINT_FAILED"));
                return tool_result_t::ok(json{{"ok", true}, {"path", database->path()}});
            }

            c03_compatibility_runtime_config_t config_;
            std::unordered_map<std::string, ida_compat::read_handler_t> read_handlers_;
            std::unordered_map<std::string, ida_compat::mut_handler_t> mutation_handlers_;
            mutable wave_c_handlers::types_overlay_store_t types_store_;
            static constexpr std::size_t k_query_cursor_binding_capacity = 1024U;
            mutable std::mutex query_cursor_bindings_mutex_;
            mutable std::unordered_map<
                std::string, wave_c_query_cursor_binding_t> query_cursor_bindings_;
            mutable std::uint64_t query_cursor_binding_sequence_ = 0;
            wave_c_compat::effect_lock_manager_t adapter_lock_manager_;
            wave_c_compat::target_resolver_t targetless_resolver_;
            wave_c_compat::target_resolver_t registry_resolver_;
            wave_c_protocol::schema_runtime_t registry_schemas_;
            wave_c_compat::workspace_adapter_t targetless_workspace_;
            wave_c_handlers::core_handlers_t targetless_core_handlers_;
            wave_c_handlers::routing_extensions_t registry_handlers_;
            std::mutex registry_mutex_;
            std::unordered_map<std::uint64_t, std::uint32_t> registry_static_pids_;
            std::unordered_set<std::uint64_t> registry_active_target_ids_;
            std::uint32_t next_registry_static_pid_ =
                (std::numeric_limits<std::uint32_t>::max)();
            std::atomic<std::uint64_t> next_approval_id_{1};
            mutable std::atomic<std::uint64_t> next_receipt_id_{1};
        };

        std::optional<wave_c_integration::extension_tool_binding_t>
        wave_c_extension_binding(std::string_view name)
        {
            const json* input_schema = ida_compat::find_schema(std::string(name));
            if (!input_schema)
                return std::nullopt;
            wave_c_integration::extension_tool_binding_t binding;
            binding.contract.name = std::string(name);
            binding.contract.description = name == "analyze_funcs"
                ? "ida-pro-mcp compatible mutation: analyze_funcs"
                : name == "find_insns"
                    ? "ida-pro-mcp compatible: find_insns"
                    : name == "calculator"
                        ? "ida-pro-mcp compatible calculator."
                        : "Safe target-independent integer, bytes, hash, floating-point, and address mapping calculator";
            binding.contract.input_schema = *input_schema;
            binding.contract.output_schema = json{{"type", "object"}};
            binding.contract.annotations = json::object();
            binding.contract.effect_policy.unsafe = false;
            if (name == "analyze_funcs") {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::optional;
                binding.contract.target_policy.accepts_pid = true;
                binding.contract.target_policy.accepts_bin_name = true;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::workspace_overlay_mutation;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::workspace_overlay_transaction;
                binding.contract.effect_policy.read_only = false;
            } else if (name == "find_insns") {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::optional;
                binding.contract.target_policy.accepts_pid = true;
                binding.contract.target_policy.accepts_bin_name = true;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::workspace_read;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::workspace_shared;
                binding.contract.effect_policy.read_only = true;
            } else {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::independent;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::registry_read;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::registry_read;
                binding.contract.effect_policy.read_only = true;
            }
            binding.contract.annotations["readOnlyHint"] =
                binding.contract.effect_policy.read_only;
            binding.contract.annotations["destructiveHint"] =
                !binding.contract.effect_policy.read_only;
            binding.adapter_symbol =
                "aida::standalone::mcp::compat::adapters::" + std::string(name);
            return binding;
        }

        tool_validation_hook_t make_ida_compat_schema_validation()
        {
            ida_compat::register_schema_validator();
            return [](const tool_def_t& tool, const json& arguments) {
                const auto validation = ida_compat::validate_tool_args(
                    tool.name, arguments, tool.input_schema);
                if (validation.valid)
                    return tool_result_t::ok("");
                json errors = json::array();
                for (const auto& error : validation.errors) {
                    errors.push_back({
                        {"path", error.path},
                        {"message", error.message},
                        {"schema_fragment", error.schema_fragment}
                    });
                }
                return tool_result_t::error(validation.summary(),
                    "MCP_TOOL_INPUT_SCHEMA_INVALID", {{"errors", std::move(errors)}});
            };
        }

        void register_wave_c_compatibility_tools(
            tool_registry_t& registry,
            c03_compatibility_runtime_config_t runtime_config)
        {
            try {
                if (!wave_c_integration::mcp_server_integration_t::validate_union_count())
                    throw std::runtime_error("generated compatibility union cardinality is invalid");
                auto runtime = std::make_shared<wave_c_adapter_runtime_t>(
                    std::move(runtime_config));
                wave_c_integration::server_integration_config_t config;
                config.adapter_dispatcher = [runtime](const auto& invocation) {
                    return runtime->dispatch(invocation);
                };
                config.extension_binding_provider = wave_c_extension_binding;
                auto integration = wave_c_integration::mcp_server_integration_t::create(
                    registry, std::move(config));
                integration->register_generated_tools();
                integration->register_extension_tools();
                const auto names = integration->union_tool_names();
                const std::unordered_set<std::string> unique_names(names.begin(), names.end());
                if (names.size() != wave_c_compat::k_union_tool_count ||
                    unique_names.size() != wave_c_compat::k_union_tool_count ||
                    integration->registered_tool_count() != wave_c_compat::k_union_tool_count ||
                    unique_names.find("list_instances") == unique_names.end() ||
                    unique_names.find("py_eval") != unique_names.end())
                    throw std::runtime_error("generated compatibility registration inventory is invalid");
                diag::log_tagged_fmt(
                    "mcp_tools", "wave_c compatibility registration complete generated=%zu extensions=%zu union=%zu",
                    wave_c_compat::k_archive_tool_count,
                    wave_c_compat::k_aida_extension_count,
                    unique_names.size());
            } catch (const std::exception& error) {
                diag::log_tagged_fmt(
                    "mcp_tools", "wave_c compatibility registration failed error='%s'", error.what());
                throw;
            }
        }
    }

    tool_validation_hook_t c03_compatibility_validation_hook()
    {
        return make_ida_compat_schema_validation();
    }

    void register_c03_compatibility_tools(tool_registry_t& registry)
    {
        register_c03_compatibility_tools(
            registry, c03_compatibility_runtime_config_t{});
    }

    void register_c03_compatibility_tools(
        tool_registry_t& registry,
        c03_compatibility_runtime_config_t config)
    {
        registry.set_validation_hook(c03_compatibility_validation_hook());
        register_wave_c_compatibility_tools(registry, std::move(config));
    }
}
