


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "pro.h"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/kernel_symbols.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../../helpers/diag_log.hpp"
#include "../diagnostics/metadata_ring.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <Zydis/Zydis.h>
#include "zydis_disasm.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <regex>
#include <unordered_map>
#include <vector>
#include <process.h>

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace driver_tools
{

struct driver_debugger_quota_guard_t
{
    std::uint64_t token = 0;
    std::string tool_name;
    std::uint32_t target_pid = 0;

    driver_debugger_quota_guard_t() = default;
    driver_debugger_quota_guard_t(const driver_debugger_quota_guard_t&) = delete;
    driver_debugger_quota_guard_t& operator=(const driver_debugger_quota_guard_t&) = delete;
    driver_debugger_quota_guard_t(driver_debugger_quota_guard_t&& o) noexcept
        : token(o.token), tool_name(std::move(o.tool_name)), target_pid(o.target_pid)
    { o.token = 0; }
    driver_debugger_quota_guard_t& operator=(driver_debugger_quota_guard_t&& o) noexcept
    {
        if (this != &o) { release(); token = o.token; tool_name = std::move(o.tool_name); target_pid = o.target_pid; o.token = 0; }
        return *this;
    }
    ~driver_debugger_quota_guard_t() { release(); }
    void release()
    {
        if (token == 0) return;
        if (mcp_standalone::downstream::governor_t::instance().is_admitted(token))
        {
            diag::log_tagged_fmt("drv_tools",
                "DRIVER-DEBUGGER-QUOTA-RELEASE tool=%s target_pid=%u token=%llu",
                tool_name.c_str(), target_pid, static_cast<unsigned long long>(token));
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
            opts.label = "driver_debugger_release";
            opts.reason = "scope_exit";
            opts.owner_subsystem = "driver_tools";
            opts.tool_or_request_id = tool_name.c_str();
            opts.lease_token = token;
            opts.status_code = 0;
            aida::diagnostics::emit(std::move(opts));
            mcp_standalone::downstream::governor_t::instance().release(token, "driver_debugger_scope_exit");
        }
        else
        {
            diag::log_tagged_fmt("drv_tools",
                "DRIVER-DEBUGGER-QUOTA-STALE-RESULT tool=%s target_pid=%u token=%llu",
                tool_name.c_str(), target_pid, static_cast<unsigned long long>(token));
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
            opts.label = "driver_debugger_stale_result";
            opts.reason = "stale_result";
            opts.owner_subsystem = "driver_tools";
            opts.tool_or_request_id = tool_name.c_str();
            opts.lease_token = token;
            opts.status_code = 1;
            aida::diagnostics::emit(std::move(opts));
        }
        token = 0;
    }
};

static std::optional<tool_result_t> acquire_driver_debugger_quota(
    const char* tool_name, std::uint32_t target_pid,
    driver_debugger_quota_guard_t& guard)
{
    mcp_standalone::downstream::producer_identity_t id;
    id.kind = mcp_standalone::downstream::producer_kind_t::driver_debugger;
    id.tool_name = tool_name ? tool_name : "";
    id.target_pid = target_pid;
    id.target_id = target_pid != 0 ? ("pid:" + std::to_string(target_pid)) : "";
    id.principal_id = "standalone";
    const char* diag_id = mcp_standalone::current_call_diag_id();
    if (diag_id) id.diagnostic_id = diag_id;
    const char* req_id = mcp_standalone::current_call_request_id();
    if (req_id) id.request_id = req_id;
    id.deadline_ms = mcp_standalone::current_call_deadline_ms();

    auto result = mcp_standalone::downstream::governor_t::instance().try_admit(id);
    if (!result.admitted)
    {
        diag::log_tagged_fmt("drv_tools",
            "DRIVER-DEBUGGER-QUOTA-REJECT tool=%s target_pid=%u reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            id.tool_name.c_str(), id.target_pid,
            result.reason.c_str(), result.quota_name.c_str(),
            result.quota_scope.c_str(), result.observed, result.limit);
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
        opts.label = "driver_debugger_reject";
        opts.reason = "capacity_rejected";
        opts.owner_subsystem = "driver_tools";
        opts.tool_or_request_id = id.tool_name.c_str();
        opts.status_code = 1;
        aida::diagnostics::emit(std::move(opts));
        return tool_result_t::error(
            "Downstream driver/debugger capacity exhausted; work was not started.",
            "MCP_DOWNSTREAM_CAPACITY_REJECT",
            mcp_standalone::downstream::rejection_json(result, id));
    }

    diag::log_tagged_fmt("drv_tools",
        "DRIVER-DEBUGGER-QUOTA-ADMIT tool=%s target_pid=%u token=%llu",
        id.tool_name.c_str(), id.target_pid,
        static_cast<unsigned long long>(result.admission_token));

    aida::diagnostics::breadcrumb_options_t admit_opts{};
    admit_opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
    admit_opts.label = "driver_debugger_admit";
    admit_opts.reason = "operation_start";
    admit_opts.owner_subsystem = "driver_tools";
    admit_opts.tool_or_request_id = id.tool_name.c_str();
    admit_opts.session_or_target = id.target_id.c_str();
    admit_opts.lease_token = result.admission_token;
    admit_opts.status_code = 0;
    aida::diagnostics::emit(std::move(admit_opts));

    guard.token = result.admission_token;
    guard.tool_name = id.tool_name;
    guard.target_pid = id.target_pid;
    return std::nullopt;
}

static std::string to_lower_ascii_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

static bool full_test_mode_active()
{
    char buf[8] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", buf, static_cast<DWORD>(sizeof(buf)));
    return n > 0 && (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y');
}

static bool ranges_overlap(std::uint64_t a_start, std::uint64_t a_size, std::uint64_t b_start, std::uint64_t b_size)
{
    if (a_size == 0 || b_size == 0)
        return false;
    std::uint64_t a_end = a_start + a_size - 1;
    std::uint64_t b_end = b_start + b_size - 1;
    if (a_end < a_start)
        a_end = std::numeric_limits<std::uint64_t>::max();
    if (b_end < b_start)
        b_end = std::numeric_limits<std::uint64_t>::max();
    return a_start <= b_end && b_start <= a_end;
}

static bool range_intersects_system_module(std::uint64_t address, std::uint64_t size, std::string& module_name, std::string& module_path)
{
    const std::uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0)
        return false;
    for (const auto& mod : driver_bridge::enumerate_modules_for(pid))
    {
        const std::uint64_t start = mod.base;
        const std::uint64_t mod_size = static_cast<std::uint64_t>(mod.size);
        if (start == 0 || mod_size == 0 || !ranges_overlap(address, size, start, mod_size))
            continue;
        module_name = mod.name;
        module_path = mod.path;
        const std::string name = to_lower_ascii_copy(mod.name);
        const std::string path = to_lower_ascii_copy(mod.path);
        if (path.find("\\windows\\") != std::string::npos ||
            path.find("/windows/") != std::string::npos ||
            name == "ntdll.dll" ||
            name == "kernel32.dll" ||
            name == "kernelbase.dll" ||
            name == "apphelp.dll" ||
            name == "win32u.dll")
            return true;
        return false;
    }
    return false;
}

static std::optional<tool_result_t> reject_full_test_system_mutation(std::uint64_t address, std::uint64_t size, const char* tool_name)
{
    if (!full_test_mode_active())
        return std::nullopt;
    std::string module_name;
    std::string module_path;
    if (!range_intersects_system_module(address, size, module_name, module_path))
        return std::nullopt;
    diag::log_tagged_fmt("drv_tools",
        "%s rejected full-test system module mutation addr=0x%llX size=%llu module=%s path=%s",
        tool_name ? tool_name : "driver_tool",
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        module_name.c_str(),
        module_path.c_str());
    return tool_result_t::error(
        std::string("Full Test Lab refuses to mutate system module memory. Use a private target fixture address instead."));
}

static bool is_ida_host_process_name(const std::string& process_name)
{
    const std::string lower = to_lower_ascii_copy(process_name);
    return lower.find("ida.exe") != std::string::npos
        || lower.find("ida64.exe") != std::string::npos
        || lower.find("idat.exe") != std::string::npos
        || lower.find("idat64.exe") != std::string::npos;
}

static bool is_self_target_pid(uint32_t pid)
{
    return pid != 0 && pid == static_cast<uint32_t>(GetCurrentProcessId());
}

static std::string trim_ascii_copy(const std::string& text)
{
    const std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

static bool parse_u32_id_value(const json& value, std::uint32_t& out)
{
    if (value.is_number_unsigned())
    {
        const auto v = value.get<std::uint64_t>();
        if (v == 0 || v > 0xFFFFFFFFULL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (value.is_number_integer())
    {
        const auto v = value.get<std::int64_t>();
        if (v <= 0 || v > 0xFFFFFFFFLL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (!value.is_string())
        return false;

    std::string s = trim_ascii_copy(value.get<std::string>());
    if (s.empty())
        return false;

    try
    {
        std::size_t idx = 0;
        std::uint64_t parsed = 0;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            parsed = std::stoull(s, &idx, 16);
        else
            parsed = std::stoull(s, &idx, 10);

        if (idx != s.size() || parsed == 0 || parsed > 0xFFFFFFFFULL)
            return false;

        out = static_cast<std::uint32_t>(parsed);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

static bool parse_single_hex_byte_token(const std::string& raw_token, std::uint8_t& out)
{
    std::string token = trim_ascii_copy(raw_token);
    if (token.empty())
        return false;

    if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
        token = token.substr(2);

    if (token.empty())
        return false;

    const bool all_hex = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; });
    const bool has_hex_alpha = std::any_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isalpha(c) != 0; });

    if (all_hex)
    {
        try
        {
            std::uint64_t v16 = std::stoull(token, nullptr, 16);
            if (v16 <= 0xFFULL && (has_hex_alpha || token.size() <= 2))
            {
                out = static_cast<std::uint8_t>(v16);
                return true;
            }
        }
        catch (...) {}
    }

    const bool all_digits = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isdigit(c) != 0; });
    if (all_digits)
    {
        try
        {
            std::uint64_t v10 = std::stoull(token, nullptr, 10);
            if (v10 <= 0xFFULL)
            {
                out = static_cast<std::uint8_t>(v10);
                return true;
            }
        }
        catch (...) {}
    }

    return false;
}

static bool parse_byte_sequence(const json& bytes_value, std::vector<std::uint8_t>& out, std::string& error)
{
    out.clear();

    if (bytes_value.is_array())
    {
        for (std::size_t i = 0; i < bytes_value.size(); ++i)
        {
            const auto& item = bytes_value[i];
            if (item.is_number_integer())
            {
                const auto v = item.get<std::int64_t>();
                if (v < 0 || v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_number_unsigned())
            {
                const auto v = item.get<std::uint64_t>();
                if (v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_string())
            {
                std::uint8_t b = 0;
                if (!parse_single_hex_byte_token(item.get<std::string>(), b))
                {
                    error = "Invalid byte token at index " + std::to_string(i) + ".";
                    return false;
                }
                out.push_back(b);
                continue;
            }

            error = "Unsupported bytes array element type at index " + std::to_string(i) + ".";
            return false;
        }

        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (!bytes_value.is_string())
    {
        error = "'bytes' must be either a string or an array.";
        return false;
    }

    std::string text = trim_ascii_copy(bytes_value.get<std::string>());
    if (text.empty())
    {
        error = "No bytes were provided.";
        return false;
    }

    if (!text.empty() && text.front() == '[')
    {
        try
        {
            json parsed = json::parse(text);
            if (!parsed.is_array())
            {
                error = "String bytes payload starts with '[' but is not a valid array.";
                return false;
            }
            return parse_byte_sequence(parsed, out, error);
        }
        catch (...)
        {
            error = "Failed to parse bytes array string.";
            return false;
        }
    }

    std::string tokenized = text;
    std::replace(tokenized.begin(), tokenized.end(), ',', ' ');
    if (tokenized.find(' ') != std::string::npos || tokenized.find('\t') != std::string::npos ||
        tokenized.find('\n') != std::string::npos || tokenized.find('\r') != std::string::npos)
    {
        std::istringstream iss(tokenized);
        std::string token;
        std::size_t index = 0;
        while (iss >> token)
        {
            std::uint8_t b = 0;
            if (!parse_single_hex_byte_token(token, b))
            {
                error = "Invalid hex byte token '" + token + "' at position " + std::to_string(index) + ".";
                return false;
            }
            out.push_back(b);
            ++index;
        }
        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (tokenized.size() > 2 && tokenized[0] == '0' && (tokenized[1] == 'x' || tokenized[1] == 'X'))
        tokenized = tokenized.substr(2);

    if (tokenized.size() % 2 != 0)
    {
        error = "Packed hex string must contain an even number of hex digits.";
        return false;
    }

    if (!std::all_of(tokenized.begin(), tokenized.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; }))
    {
        error = "Packed hex string contains non-hex characters.";
        return false;
    }

    for (std::size_t i = 0; i < tokenized.size(); i += 2)
    {
        const std::string byte_str = tokenized.substr(i, 2);
        out.push_back(static_cast<std::uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }

    if (out.empty())
        error = "No bytes were provided.";

    return !out.empty();
}

static bool is_probably_kernel_address(std::uint64_t address);

struct kernel_pattern_t
{
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> masks;
    std::size_t anchor = 0;
};

static bool parse_kernel_pattern(const json& value, kernel_pattern_t& out, std::string& error)
{
    out = {};
    if (!value.is_string())
    {
        error = "'pattern' must be a hex string such as '48 8B ?? ?? 89' or '488B????89'.";
        return false;
    }

    std::string text = trim_ascii_copy(value.get<std::string>());
    if (text.empty())
    {
        error = "Pattern must not be empty.";
        return false;
    }

    auto append_token = [&](std::string token) -> bool {
        token = trim_ascii_copy(token);
        if (token == "?" || token == "??")
        {
            out.bytes.push_back(0);
            out.masks.push_back(0);
            return true;
        }
        if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
            token = token.substr(2);
        if (token.size() != 2 || !std::all_of(token.begin(), token.end(),
            [](unsigned char c) { return std::isxdigit(c) != 0; }))
            return false;
        out.bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
        out.masks.push_back(0xFF);
        return true;
    };

    const bool separated = text.find_first_of(" ,\t\r\n") != std::string::npos;
    if (separated)
    {
        std::replace(text.begin(), text.end(), ',', ' ');
        std::istringstream stream(text);
        std::string token;
        std::size_t index = 0;
        while (stream >> token)
        {
            if (!append_token(token))
            {
                error = "Invalid pattern token '" + token + "' at index " + std::to_string(index) + ".";
                return false;
            }
            ++index;
        }
    }
    else
    {
        if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
            text = text.substr(2);
        if (text.empty() || (text.size() % 2) != 0)
        {
            error = "Packed pattern must contain an even number of hex or wildcard characters.";
            return false;
        }
        for (std::size_t i = 0; i < text.size(); i += 2)
        {
            const std::string token = text.substr(i, 2);
            if (!append_token(token))
            {
                error = "Invalid packed pattern token '" + token + "' at byte index " + std::to_string(i / 2) + ".";
                return false;
            }
        }
    }

    if (out.bytes.empty())
    {
        error = "Pattern must contain at least one byte.";
        return false;
    }
    if (out.bytes.size() > 4096)
    {
        error = "Pattern exceeds the 4096-byte limit.";
        return false;
    }

    bool anchored = false;
    for (std::size_t i = out.masks.size(); i != 0; --i)
    {
        if (out.masks[i - 1] != 0)
        {
            out.anchor = i - 1;
            anchored = true;
            break;
        }
    }
    if (!anchored)
    {
        error = "Pattern must contain at least one concrete byte; all-wildcard searches are rejected.";
        return false;
    }
    return true;
}

static bool parse_kernel_size(const json& params, const char* key, std::uint64_t& out)
{
    out = 0;
    if (!params.contains(key))
        return false;
    const auto& value = params[key];
    if (value.is_number_unsigned())
    {
        out = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer())
    {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value < 0)
            return false;
        out = static_cast<std::uint64_t>(signed_value);
        return true;
    }
    if (value.is_string())
    {
        auto parsed = sa_parse_address(value.get<std::string>());
        if (parsed)
        {
            out = *parsed;
            return true;
        }
    }
    return false;
}

static bool validate_kernel_range(std::uint64_t address, std::uint64_t size, std::string& error)
{
    if (!is_probably_kernel_address(address))
    {
        error = "Address must be a canonical kernel virtual address at or above 0xFFFF000000000000.";
        return false;
    }
    if (size == 0)
    {
        error = "Size must be greater than zero.";
        return false;
    }
    if (size - 1 > std::numeric_limits<std::uint64_t>::max() - address)
    {
        error = "Kernel address range overflows the 64-bit virtual address space.";
        return false;
    }
    const std::uint64_t end = address + size - 1;
    if (!is_probably_kernel_address(end))
    {
        error = "Kernel address range crosses out of canonical kernel space.";
        return false;
    }
    return true;
}

static std::optional<tool_result_t> ensure_kernel_memory_context()
{
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error(std::string("Tool cancelled before the kernel operation started."));
    std::string reason;
    if (!driver_bridge::kernel_session_available(&reason))
    {
        json details;
        details["reason"] = reason;
        details["driver_status"] = driver_bridge::status();
        details["attached_pid"] = driver_bridge::attached_pid();
        return tool_result_t::error(
            std::string("Kernel driver session is unavailable: ") + reason,
            std::string("kernel_session_unavailable"), details);
    }
    if (device == nullptr || !device->is_connected())
        return tool_result_t::error(std::string("Kernel device is not connected."));
    if (device->get_kernel_dtb() == 0 && device->get_dtb() == 0)
        return tool_result_t::error(std::string("No kernel-capable DTB is resolved. Attach a live process before accessing kernel memory."));
    return std::nullopt;
}

static std::string kernel_bytes_hex(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    return out;
}

static std::string kernel_bytes_ascii(const std::vector<std::uint8_t>& bytes)
{
    std::string out;
    out.reserve(bytes.size());
    for (std::uint8_t byte : bytes)
        out.push_back(byte >= 32 && byte < 127 ? static_cast<char>(byte) : '.');
    return out;
}

static bool is_process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return false;

    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
    CloseHandle(h);

    return ok && exit_code == STILL_ACTIVE;
}

static std::optional<tool_result_t> ensure_attached_process_context(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    std::uint32_t requested_pid = 0;
    for (const char* key : {"target_pid", "process_id", "pid"})
    {
        if (!params.contains(key))
            continue;
        if (!parse_u32_id_value(params[key], requested_pid))
            return tool_result_t::error(std::string(std::string("Invalid ")) + key + std::string(". Expected a positive decimal PID or 0x-prefixed hex PID."));
        if (requested_pid != 0)
            break;
    }

    if (requested_pid != 0 && is_self_target_pid(requested_pid))
        return tool_result_t::error(std::string("Cannot target AiDA's own process."));

    const std::uint32_t current_pid = driver_bridge::attached_pid();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        if (!is_process_alive(requested_pid))
            return tool_result_t::error(std::string("target_pid ") + std::to_string(requested_pid) + std::string(" is not alive."));

        const auto attached = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : attached) { if (p == requested_pid) { in_map = true; break; } }
        if (!in_map)
        {
            if (!driver_bridge::attach_additional(requested_pid))
            {
                return tool_result_t::error(std::string("attach_additional failed for target_pid ") + std::to_string(requested_pid) +
                                            std::string(": ") + driver_bridge::last_error());
            }
        }

        if (current_pid != 0)
            stealth_engine::disable_for_detach(current_pid, "driver_tools.ensure_attached_context.replace");

        if (!driver_bridge::set_active_pid(requested_pid))
        {
            if (current_pid != 0 && driver_bridge::attached_pid() == current_pid)
                (void)stealth_engine::ensure_default_enabled(current_pid, "driver_tools.ensure_attached_context.restore_failed_switch");
            return tool_result_t::error(std::string("set_active_pid failed for target_pid ") + std::to_string(requested_pid) +
                                        std::string(": ") + driver_bridge::last_error());
        }

        (void)stealth_engine::ensure_default_enabled(requested_pid, "driver_tools.ensure_attached_context");

        if (device->get_dtb() == 0)
        {
            device->solve_dtb();
            if (device->get_dtb() == 0)
                return tool_result_t::error(std::string("Failed to solve DTB for target_pid ") + std::to_string(requested_pid) + std::string("."));
        }
    }

    if (driver_bridge::attached_pid() == 0)
        return tool_result_t::error(std::string("Not attached. Use sessions_manage action=attach_pid or pass target_pid."));

    if (!is_process_alive(driver_bridge::attached_pid()))
    {
        const std::uint32_t dead_pid = driver_bridge::attached_pid();
        device->clear_process_context();
        return tool_result_t::error(std::string("Attached process PID ") + std::to_string(dead_pid) + std::string(" is no longer alive. Reattach with sessions_manage action=attach_pid."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(std::string("Failed to solve DTB for the attached process."));
    }

    return std::nullopt;
}

static std::optional<std::uint32_t> parse_tid_param(const json& params)
{
    if (!params.contains("tid"))
        return std::nullopt;

    std::uint32_t tid = 0;
    if (!parse_u32_id_value(params["tid"], tid) || tid == 0)
        return std::nullopt;
    return tid;
}

struct teb_resolution_diagnostics_t
{
    std::uint32_t pid = 0;
    std::uint32_t tid = 0;
    bool context_available = false;
    bool context_valid = false;
    bool context_kernel = false;
    std::uint64_t context_candidate = 0;
    bool tqif_called = false;
    bool tqif_ok = false;
    std::uint32_t tqif_status = 0;
    std::uint32_t tqif_return_length = 0;
    bool tqif_valid = false;
    bool tqif_kernel = false;
    std::uint64_t tqif_candidate = 0;
    std::uint64_t tqif_client_process = 0;
    std::uint64_t tqif_client_thread = 0;
    std::string selected_source;
    std::string failure;
};

static json teb_resolution_diagnostics_to_json(const teb_resolution_diagnostics_t& diag)
{
    json out;
    out["process_id"] = diag.pid;
    out["thread_id"] = diag.tid;
    out["context_available"] = diag.context_available;
    out["context_teb_candidate"] = sa_format_address(static_cast<std::uint64_t>(diag.context_candidate));
    out["context_candidate_valid"] = diag.context_valid;
    out["context_candidate_kernel"] = diag.context_kernel;
    out["tqif_called"] = diag.tqif_called;
    out["tqif_ok"] = diag.tqif_ok;
    out["tqif_status"] = sa_format_address(static_cast<std::uint64_t>(diag.tqif_status));
    out["tqif_return_length"] = diag.tqif_return_length;
    out["tqif_teb_candidate"] = sa_format_address(static_cast<std::uint64_t>(diag.tqif_candidate));
    out["tqif_candidate_valid"] = diag.tqif_valid;
    out["tqif_candidate_kernel"] = diag.tqif_kernel;
    out["tqif_client_process"] = diag.tqif_client_process;
    out["tqif_client_thread"] = diag.tqif_client_thread;
    out["selected_source"] = diag.selected_source;
    out["failure"] = diag.failure;
    return out;
}

static bool resolve_teb_address_for_thread(std::uint32_t tid,
                                           const voyager::device_t::thread_context* ctx,
                                           std::uint64_t& out_teb,
                                           std::string& source,
                                           std::string& error,
                                           teb_resolution_diagnostics_t& diag)
{
    diag = {};
    diag.pid = device ? device->get_process_id() : 0;
    diag.tid = tid;
    out_teb = 0;
    source.clear();
    error.clear();

    if (ctx != nullptr)
    {
        diag.context_available = true;
        diag.context_candidate = ctx->kernel_gs_base;
        diag.context_kernel = diag.context_candidate != 0 && is_probably_kernel_address(diag.context_candidate);
        diag.context_valid = diag.context_candidate != 0 && !diag.context_kernel;
        diag::log_tagged_fmt("drv_tools",
            "teb_resolve_context pid=%u tid=%u candidate=0x%llX valid=%d kernel=%d",
            diag.pid,
            diag.tid,
            static_cast<unsigned long long>(diag.context_candidate),
            diag.context_valid ? 1 : 0,
            diag.context_kernel ? 1 : 0);

        if (diag.context_valid)
        {
            out_teb = diag.context_candidate;
            source = std::string("thread_context.kernel_gs_base");
            diag.selected_source = source;
            diag::log_tagged_fmt("drv_tools",
                "teb_resolve_selected pid=%u tid=%u source=%s address=0x%llX context_candidate=0x%llX tqif_candidate=0x%llX tqif_called=%d tqif_ok=%d tqif_status=0x%08X",
                diag.pid,
                diag.tid,
                diag.selected_source.c_str(),
                static_cast<unsigned long long>(out_teb),
                static_cast<unsigned long long>(diag.context_candidate),
                static_cast<unsigned long long>(diag.tqif_candidate),
                diag.tqif_called ? 1 : 0,
                diag.tqif_ok ? 1 : 0,
                diag.tqif_status);
            return true;
        }
    }
    else
    {
        diag::log_tagged_fmt("drv_tools",
            "teb_resolve_context pid=%u tid=%u candidate=0x0 valid=0 kernel=0 unavailable=1",
            diag.pid,
            diag.tid);
    }

    diag.tqif_called = true;
    voyager::detail::thread_query_information_request tqif{};
    diag.tqif_ok = device && device->query_thread_basic_information(tid, tqif);
    diag.tqif_status = tqif.status;
    diag.tqif_return_length = tqif.return_length;
    diag.tqif_candidate = tqif.teb_base;
    diag.tqif_client_process = tqif.client_process;
    diag.tqif_client_thread = tqif.client_thread;
    diag.tqif_kernel = diag.tqif_candidate != 0 && is_probably_kernel_address(diag.tqif_candidate);
    diag.tqif_valid = diag.tqif_ok && diag.tqif_candidate != 0 && !diag.tqif_kernel;
    diag::log_tagged_fmt("drv_tools",
        "teb_resolve_tqif pid=%u tid=%u ok=%d status=0x%08X return_length=%u candidate=0x%llX valid=%d kernel=%d client_pid=%llu client_tid=%llu",
        diag.pid,
        diag.tid,
        diag.tqif_ok ? 1 : 0,
        diag.tqif_status,
        diag.tqif_return_length,
        static_cast<unsigned long long>(diag.tqif_candidate),
        diag.tqif_valid ? 1 : 0,
        diag.tqif_kernel ? 1 : 0,
        static_cast<unsigned long long>(diag.tqif_client_process),
        static_cast<unsigned long long>(diag.tqif_client_thread));

    if (diag.tqif_valid)
    {
        out_teb = diag.tqif_candidate;
        source = std::string("thread_query_information.teb_base");
        diag.selected_source = source;
        diag::log_tagged_fmt("drv_tools",
            "teb_resolve_selected pid=%u tid=%u source=%s address=0x%llX context_candidate=0x%llX tqif_candidate=0x%llX tqif_called=%d tqif_ok=%d tqif_status=0x%08X",
            diag.pid,
            diag.tid,
            diag.selected_source.c_str(),
            static_cast<unsigned long long>(out_teb),
            static_cast<unsigned long long>(diag.context_candidate),
            static_cast<unsigned long long>(diag.tqif_candidate),
            diag.tqif_called ? 1 : 0,
            diag.tqif_ok ? 1 : 0,
            diag.tqif_status);
        return true;
    }

    std::string context_error;
    if (!diag.context_available)
        context_error = std::string("driver thread context was unavailable for TID ") + std::to_string(tid);
    else if (diag.context_kernel)
        context_error = std::string("driver thread context reported a kernel GS base instead of a user TEB for TID ") + std::to_string(tid);
    else
        context_error = std::string("driver thread context did not include a valid user TEB for TID ") + std::to_string(tid);

    std::string tqif_error;
    if (!diag.tqif_ok)
        tqif_error = std::string("TQIF failed with status ") + sa_format_address(static_cast<std::uint64_t>(diag.tqif_status));
    else if (diag.tqif_candidate == 0)
        tqif_error = std::string("TQIF returned a null TEB base");
    else
        tqif_error = std::string("TQIF returned a kernel address instead of a user TEB");

    error = context_error + std::string("; ") + tqif_error;
    diag.failure = error;
    diag::log_tagged_fmt("drv_tools",
        "teb_resolve_failed pid=%u tid=%u context_available=%d context_candidate=0x%llX context_valid=%d context_kernel=%d tqif_called=%d tqif_ok=%d tqif_status=0x%08X tqif_candidate=0x%llX tqif_valid=%d tqif_kernel=%d failure=%s",
        diag.pid,
        diag.tid,
        diag.context_available ? 1 : 0,
        static_cast<unsigned long long>(diag.context_candidate),
        diag.context_valid ? 1 : 0,
        diag.context_kernel ? 1 : 0,
        diag.tqif_called ? 1 : 0,
        diag.tqif_ok ? 1 : 0,
        diag.tqif_status,
        static_cast<unsigned long long>(diag.tqif_candidate),
        diag.tqif_valid ? 1 : 0,
        diag.tqif_kernel ? 1 : 0,
        diag.failure.c_str());
    return false;
}

static bool is_probably_kernel_address(std::uint64_t address)
{
    return address >= 0xFFFF000000000000ULL;
}

static std::string read_remote_unicode_ascii(voyager::device_t* dev,
                                             std::uint64_t ptr,
                                             std::uint16_t byte_len,
                                             std::uint16_t max_len)
{
    if (dev == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
        return {};

    std::vector<std::uint8_t> raw(byte_len, 0);
    if (dev->read_raw(ptr, raw.data(), byte_len) == 0)
        return {};

    std::string text;
    text.reserve(byte_len / 2);
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
    {
        const std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
        if (wc == 0)
            break;
        text += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
    }

    return text;
}

static bool resolve_loaded_module_base(const std::string& query,
                                       std::uint64_t& out_base,
                                       std::string& out_name)
{
    out_base = 0;
    out_name.clear();

    if (!device || !device->is_connected() || device->get_process_id() == 0 || query.empty())
        return false;

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return false;

    const std::string needle = to_lower_ascii_copy(query);
    const std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t current = device->read<std::uint64_t>(list_head);
    if (current == 0 || current == list_head)
        return false;

    auto basename_of_path = [](const std::string& path) {
        const std::size_t pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    };

    std::uint64_t partial_base = 0;
    std::string partial_name;
    int max_iter = 1024;

    while (current != list_head && current != 0 && max_iter-- > 0)
    {
        const std::uint64_t base = device->read<std::uint64_t>(current + 0x30);
        const std::string module_name = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x60),
            device->read<std::uint16_t>(current + 0x58),
            520);
        const std::string module_path = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x50),
            device->read<std::uint16_t>(current + 0x48),
            1024);

        const std::string lower_name = to_lower_ascii_copy(module_name);
        const std::string lower_path = to_lower_ascii_copy(module_path);
        const std::string lower_file = to_lower_ascii_copy(basename_of_path(module_path));

        const bool exact_match = (lower_name == needle || lower_path == needle || lower_file == needle);
        const bool partial_match = !exact_match &&
            (lower_name.find(needle) != std::string::npos ||
             lower_path.find(needle) != std::string::npos ||
             lower_file.find(needle) != std::string::npos);

        if (base != 0 && exact_match)
        {
            out_base = base;
            out_name = module_name.empty() ? module_path : module_name;
            return true;
        }

        if (base != 0 && partial_match && partial_base == 0)
        {
            partial_base = base;
            partial_name = module_name.empty() ? module_path : module_name;
        }

        const std::uint64_t next = device->read<std::uint64_t>(current);
        if (next == current || next == 0)
            break;
        current = next;
    }

    if (partial_base != 0)
    {
        out_base = partial_base;
        out_name = partial_name;
        return true;
    }

    return false;
}

static std::vector<voyager::detail::region_entry> enumerate_all_memory_regions_paginated(
    voyager::device_t* dev,
    std::uint64_t start,
    std::uint64_t end_addr,
    bool include_all)
{


    std::vector<voyager::detail::region_entry> all_regions;
    std::uint64_t current_start = start;
    constexpr int MAX_PAGINATION_ROUNDS = 256;

    for (int round = 0; round < MAX_PAGINATION_ROUNDS; round++)
    {
        if (current_start >= end_addr)
            break;

        auto batch = dev->enumerate_memory_regions(current_start, end_addr, include_all);
        if (batch.empty())
            break;

        std::uint64_t batch_max_end = 0;
        for (const auto& r : batch)
        {
            all_regions.push_back(r);
            std::uint64_t rend = r.base + r.size;
            if (rend > batch_max_end)
                batch_max_end = rend;
        }


        if (batch.size() < voyager::detail::MAX_ENUM_REGIONS)
            break;


        if (batch_max_end <= current_start)
            break;
        current_start = batch_max_end;
    }

    return all_regions;
}

tool_result_t driver_read_pointer_chain(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_pointer_chain entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_read_pointer_chain", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::string base_address;
    if (params.contains("address") && params["address"].is_string())
        base_address = params["address"].get<std::string>();
    else if (params.contains("base_address") && params["base_address"].is_string())
        base_address = params["base_address"].get<std::string>();

    auto ea_opt = sa_parse_address(base_address);
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address. Use address='0x...' (alias base_address is supported)."));

    std::vector<std::int64_t> offsets;
    if (params.contains("offsets") && params["offsets"].is_array())
    {
        for (const auto& off : params["offsets"])
        {
            if (off.is_number_integer())
                offsets.push_back(off.get<std::int64_t>());
            else if (off.is_string())
            {
                auto o = sa_parse_address(off.get<std::string>());
                if (o) offsets.push_back(static_cast<std::int64_t>(*o));
            }
        }
    }


    json chain = json::array();
    std::uint64_t current = *ea_opt;
    chain.push_back({{"step", 0}, {"address", sa_format_address(current)}, {"type", "base"}});

    for (std::size_t i = 0; i < offsets.size(); i++)
    {
        if (mcp_standalone::current_call_cancelled())
            return tool_result_t::error("Tool cancelled during pointer chain traversal.");

        std::uint64_t ptr = device->read<std::uint64_t>(current);
        if (ptr == 0)
        {
            chain.push_back({{"step", (int)(i + 1)}, {"error", "null pointer"}, {"offset", offsets[i]}});
            break;
        }
        std::uint64_t next = ptr + offsets[i];
        chain.push_back({{"step", (int)(i + 1)},
                         {"deref", sa_format_address(ptr)},
                         {"offset", offsets[i]},
                         {"address", sa_format_address(next)}});
        current = next;
    }

    std::uint64_t final_val = device->read<std::uint64_t>(current);

    json result;
    result["initial_address"]    = sa_format_address(*ea_opt);
    result["final_address"]      = sa_format_address(current);
    result["final_value"]        = sa_format_address(final_val);
    result["final_value_decimal"] = final_val;
    result["chain"]              = chain;
    return tool_result_t::ok(std::string("Pointer chain traversed"), result);
}

static std::string resolve_nt_path_to_win32(const std::string& nt_path)
{
    std::string result = nt_path;
    std::replace(result.begin(), result.end(), '/', '\\');

    if (result.size() >= 12)
    {
        std::string prefix_lower = result.substr(0, 12);
        std::transform(prefix_lower.begin(), prefix_lower.end(), prefix_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (prefix_lower == "\\systemroot\\")
        {
            char win_dir[MAX_PATH] = {};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            result = std::string(win_dir) + "\\" + result.substr(12);
        }
    }

    if (result.size() >= 4 && result.substr(0, 4) == "\\??\\")
        result = result.substr(4);

    return result;
}

struct sys_module_entry_t
{
    HANDLE   Section;
    PVOID    MappedBase;
    PVOID    ImageBase;
    ULONG    ImageSize;
    ULONG    Flags;
    USHORT   LoadOrderIndex;
    USHORT   InitOrderIndex;
    USHORT   LoadCount;
    USHORT   OffsetToFileName;
    UCHAR    FullPathName[256];
};

struct sys_module_info_t
{
    ULONG              NumberOfModules;
    sys_module_entry_t Modules[1];
};

static std::string bounded_kernel_module_path(const sys_module_entry_t& m)
{
    const char* p = reinterpret_cast<const char*>(m.FullPathName);
    std::size_t len = 0;
    while (len < sizeof(m.FullPathName) && p[len] != '\0')
        ++len;
    return std::string(p, len);
}

static std::string bounded_kernel_module_name(const sys_module_entry_t& m)
{
    std::string path = bounded_kernel_module_path(m);
    if (m.OffsetToFileName < path.size())
        return path.substr(m.OffsetToFileName);
    std::size_t slash = path.find_last_of("\\/");
    return (slash == std::string::npos) ? path : path.substr(slash + 1);
}

enum class kernel_module_query_fallback_policy
{
    primary_only,
    allow_readonly_kernel_base_evidence
};

struct kernel_module_query_diagnostics_t
{
    ULONG count = 0;
    std::size_t buffer_size = 0;
    std::size_t returned_length = 0;
    std::size_t abi_header_size = 0;
    std::size_t abi_entry_size = 0;
    std::size_t abi_min_size = 0;
    std::size_t zero_base_count = 0;
    std::size_t nonzero_base_count = 0;
    std::size_t resolved_zero_base_count = 0;
    std::size_t resolved_nonzero_base_count = 0;
    std::uint32_t initial_ntstatus = 0;
    std::uint32_t final_ntstatus = 0;
    DWORD win32_error = 0;
    bool primary_all_image_bases_zero = false;
    bool all_image_bases_zero = false;
    bool dependency_blocked = false;
    bool fallback_attempted = false;
    bool fallback_used = false;
    DWORD fallback_win32_error = 0;
    std::size_t fallback_bytes_returned = 0;
    std::size_t fallback_raw_count = 0;
    std::size_t fallback_named_count = 0;
    std::size_t fallback_accepted_count = 0;
    std::size_t fallback_rejected_count = 0;
    std::size_t fallback_name_query_failed_count = 0;
    std::size_t fallback_duplicate_name_count = 0;
    std::size_t fallback_match_count = 0;
    std::size_t fallback_missing_count = 0;
    std::size_t fallback_unmatched_primary_count = 0;
    std::size_t fallback_unmatched_psapi_count = 0;
    std::vector<std::string> samples;
    std::vector<std::string> fallback_samples;
    json token;
    json driver;
    std::string strict_fallback;
    std::string fallback_status;
    std::string fallback_reason;
    std::string base_source;
};

static const char* integrity_name_from_rid(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
        return "system";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)
        return "high";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
        return "medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)
        return "low";
    return "untrusted";
}

static json current_process_token_diagnostics()
{
    json out = json::object();
    DWORD session = 0xFFFFFFFFu;
    out["pid"] = GetCurrentProcessId();
    out["tid"] = GetCurrentThreadId();
    out["session_ok"] = ProcessIdToSessionId(GetCurrentProcessId(), &session) ? true : false;
    out["session"] = session;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        out["open_ok"] = false;
        out["open_error"] = static_cast<unsigned long>(GetLastError());
        return out;
    }

    out["open_ok"] = true;
    TOKEN_ELEVATION elevation{};
    DWORD ret = 0;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret))
        out["elevated"] = elevation.TokenIsElevated ? true : false;
    else
        out["elevation_error"] = static_cast<unsigned long>(GetLastError());

    TOKEN_ELEVATION_TYPE elevation_type = TokenElevationTypeDefault;
    ret = 0;
    if (GetTokenInformation(token, TokenElevationType, &elevation_type, sizeof(elevation_type), &ret))
        out["elevation_type"] = static_cast<unsigned long>(elevation_type);
    else
        out["elevation_type_error"] = static_cast<unsigned long>(GetLastError());

    ret = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &ret);
    if (ret != 0)
    {
        std::vector<unsigned char> buf(ret);
        if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), ret, &ret))
        {
            auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
            DWORD rid = 0;
            if (til->Label.Sid && IsValidSid(til->Label.Sid))
            {
                const DWORD count = *GetSidSubAuthorityCount(til->Label.Sid);
                if (count != 0)
                    rid = *GetSidSubAuthority(til->Label.Sid, count - 1);
            }
            out["integrity_rid"] = static_cast<unsigned long>(rid);
            out["integrity"] = integrity_name_from_rid(rid);
        }
        else
        {
            out["integrity_error"] = static_cast<unsigned long>(GetLastError());
        }
    }

    CloseHandle(token);
    return out;
}

static std::string module_sample_text(const std::vector<std::string>& samples)
{
    std::ostringstream ss;
    for (std::size_t i = 0; i < samples.size(); ++i)
    {
        if (i != 0)
            ss << ";";
        ss << samples[i];
    }
    return ss.str();
}

struct readonly_kernel_module_base_snapshot_t
{
    DWORD win32_error = 0;
    DWORD bytes_returned = 0;
    DWORD raw_count = 0;
    std::size_t named_count = 0;
    std::size_t accepted_count = 0;
    std::size_t rejected_count = 0;
    std::size_t name_query_failed_count = 0;
    std::size_t duplicate_name_count = 0;
    std::size_t noncanonical_base_count = 0;
    bool ok = false;
    bool truncated = false;
    std::string reason;
    std::unordered_map<std::string, std::uint64_t> bases_by_name;
    std::vector<std::string> samples;
};

static bool is_page_aligned_kernel_base(std::uint64_t base)
{
    return is_probably_kernel_address(base) && (base & 0xFFFULL) == 0;
}

static readonly_kernel_module_base_snapshot_t enumerate_readonly_kernel_module_bases_psapi(const char* reason)
{
    readonly_kernel_module_base_snapshot_t out;
    LPVOID drivers[4096] = {};
    DWORD cb_needed = 0;
    constexpr DWORD driver_buffer_bytes = static_cast<DWORD>(sizeof(drivers));
    if (!EnumDeviceDrivers(drivers, driver_buffer_bytes, &cb_needed))
    {
        out.win32_error = GetLastError();
        out.reason = "EnumDeviceDrivers_failed";
        diag::log_tagged_fmt("drv_tools",
            "kernel_module_base_fallback rejected reason=%s caller_reason=%s gle=%lu bytes_returned=%lu raw_count=0 accepted=0 rejected=0",
            out.reason.c_str(),
            reason ? reason : "<null>",
            static_cast<unsigned long>(out.win32_error),
            static_cast<unsigned long>(cb_needed));
        return out;
    }

    out.bytes_returned = cb_needed;
    out.raw_count = cb_needed / static_cast<DWORD>(sizeof(LPVOID));
    if (cb_needed > driver_buffer_bytes)
    {
        out.truncated = true;
        out.raw_count = static_cast<DWORD>(_countof(drivers));
    }
    out.samples.reserve((std::min)(static_cast<DWORD>(8), out.raw_count));

    for (DWORD i = 0; i < out.raw_count; ++i)
    {
        const std::uint64_t base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(drivers[i]));
        char name[MAX_PATH] = {};
        DWORD name_gle = 0;
        bool name_ok = false;
        if (drivers[i] != nullptr)
        {
            name_ok = GetDeviceDriverBaseNameA(drivers[i], name, static_cast<DWORD>(sizeof(name))) != 0;
            if (!name_ok)
                name_gle = GetLastError();
        }
        else
        {
            name_gle = 0;
        }

        if (out.samples.size() < 8)
        {
            std::ostringstream sample;
            sample << "index=" << i
                   << ",name=" << (name_ok ? name : "<name_query_failed>")
                   << ",base=" << sa_format_address(base);
            if (!name_ok)
                sample << ",gle=" << name_gle;
            out.samples.push_back(sample.str());
        }

        if (drivers[i] == nullptr)
        {
            ++out.rejected_count;
            continue;
        }
        if (!name_ok)
        {
            if (out.win32_error == 0)
                out.win32_error = name_gle;
            ++out.name_query_failed_count;
            ++out.rejected_count;
            continue;
        }
        ++out.named_count;
        if (!is_page_aligned_kernel_base(base))
        {
            ++out.noncanonical_base_count;
            ++out.rejected_count;
            continue;
        }

        const std::string key = to_lower_ascii_copy(name);
        auto inserted = out.bases_by_name.emplace(key, base);
        if (!inserted.second)
            ++out.duplicate_name_count;
        ++out.accepted_count;
    }

    if (out.truncated)
        out.reason = "EnumDeviceDrivers_truncated";
    else if (out.raw_count == 0)
        out.reason = "EnumDeviceDrivers_empty";
    else if (out.duplicate_name_count != 0)
        out.reason = "EnumDeviceDrivers_duplicate_module_name";
    else if (out.name_query_failed_count != 0)
        out.reason = "EnumDeviceDrivers_name_query_failed";
    else if (out.noncanonical_base_count != 0)
        out.reason = "EnumDeviceDrivers_rejected_noncanonical_base";
    else if (out.bases_by_name.empty())
        out.reason = "EnumDeviceDrivers_no_usable_bases";
    else
    {
        out.ok = true;
        out.reason = "EnumDeviceDrivers_unique_kernel_bases";
    }

    const std::string samples = module_sample_text(out.samples);
    diag::log_tagged_fmt("drv_tools",
        "kernel_module_base_fallback %s caller_reason=%s bytes_returned=%lu raw_count=%lu named=%zu accepted=%zu rejected=%zu name_query_failed=%zu duplicate_names=%zu noncanonical=%zu samples=%s",
        out.ok ? "accepted" : "rejected",
        reason ? reason : "<null>",
        static_cast<unsigned long>(out.bytes_returned),
        static_cast<unsigned long>(out.raw_count),
        out.named_count,
        out.accepted_count,
        out.rejected_count,
        out.name_query_failed_count,
        out.duplicate_name_count,
        out.noncanonical_base_count,
        samples.empty() ? "<none>" : samples.c_str());

    return out;
}

static void copy_readonly_fallback_diagnostics(
    const readonly_kernel_module_base_snapshot_t& fallback,
    kernel_module_query_diagnostics_t& diag_ref)
{
    diag_ref.fallback_win32_error = fallback.win32_error;
    diag_ref.fallback_bytes_returned = fallback.bytes_returned;
    diag_ref.fallback_raw_count = fallback.raw_count;
    diag_ref.fallback_named_count = fallback.named_count;
    diag_ref.fallback_accepted_count = fallback.accepted_count;
    diag_ref.fallback_rejected_count = fallback.rejected_count;
    diag_ref.fallback_name_query_failed_count = fallback.name_query_failed_count;
    diag_ref.fallback_duplicate_name_count = fallback.duplicate_name_count;
    diag_ref.fallback_unmatched_psapi_count = fallback.rejected_count;
    diag_ref.fallback_samples = fallback.samples;
}

static bool apply_readonly_kernel_module_base_fallback(
    sys_module_info_t* info,
    kernel_module_query_diagnostics_t& diag_ref,
    std::string& error_msg)
{
    diag_ref.fallback_attempted = true;
    diag_ref.strict_fallback = "EnumDeviceDrivers_readonly_kernel_module_base";
    diag_ref.fallback_status = "attempted";

    const readonly_kernel_module_base_snapshot_t fallback =
        enumerate_readonly_kernel_module_bases_psapi("SystemModuleInformation_all_image_bases_zero");
    copy_readonly_fallback_diagnostics(fallback, diag_ref);

    const std::string primary_samples = module_sample_text(diag_ref.samples);
    if (!fallback.ok)
    {
        diag_ref.dependency_blocked = true;
        diag_ref.token = current_process_token_diagnostics();
        diag_ref.fallback_status = "rejected";
        diag_ref.fallback_reason = fallback.reason;
        const std::string token_json = diag_ref.token.dump();
        const std::string driver_json = diag_ref.driver.dump();
        error_msg = std::string("dependency_blocked: NtQuerySystemInformation(SystemModuleInformation) returned ") +
            std::to_string(diag_ref.count) +
            std::string(" modules but every ImageBase is zero; read-only EnumDeviceDrivers fallback was rejected. sample_modules=") +
            (primary_samples.empty() ? std::string("<none>") : primary_samples) +
            std::string(" strict_fallback=") + diag_ref.strict_fallback +
            std::string(" fallback_reason=") + diag_ref.fallback_reason;
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules dependency_blocked reason=all_image_bases_zero fallback_status=rejected fallback_reason=%s primary_count=%lu fallback_raw=%lu fallback_named=%zu fallback_name_query_failed=%zu fallback_duplicate=%zu fallback_unmatched_psapi=%zu token=%s driver=%s strict_fallback=%s",
            diag_ref.fallback_reason.c_str(),
            static_cast<unsigned long>(diag_ref.count),
            static_cast<unsigned long>(diag_ref.fallback_raw_count),
            diag_ref.fallback_named_count,
            diag_ref.fallback_name_query_failed_count,
            diag_ref.fallback_duplicate_name_count,
            diag_ref.fallback_unmatched_psapi_count,
            token_json.c_str(),
            driver_json.c_str(),
            diag_ref.strict_fallback.c_str());
        return false;
    }

    std::vector<std::uint64_t> resolved_bases(diag_ref.count, 0);
    std::vector<std::string> missing_samples;
    missing_samples.reserve(8);
    std::unordered_map<std::string, ULONG> primary_name_counts;
    primary_name_counts.reserve(diag_ref.count);
    for (ULONG i = 0; i < diag_ref.count; ++i)
    {
        const std::string name = bounded_kernel_module_name(info->Modules[i]);
        const std::string key = to_lower_ascii_copy(name);
        if (!key.empty())
            ++primary_name_counts[key];
        else
            ++diag_ref.fallback_missing_count;
        const auto it = fallback.bases_by_name.find(key);
        if (it == fallback.bases_by_name.end() || !is_page_aligned_kernel_base(it->second))
        {
            if (!key.empty())
                ++diag_ref.fallback_missing_count;
            if (missing_samples.size() < 8)
                missing_samples.push_back(name.empty() ? std::string("<empty>") : name);
            continue;
        }
        resolved_bases[i] = it->second;
        ++diag_ref.fallback_match_count;
    }

    std::size_t ambiguous_primary_count = 0;
    for (const auto& kv : primary_name_counts)
    {
        if (kv.second > 1)
            ambiguous_primary_count += kv.second;
    }
    diag_ref.fallback_unmatched_primary_count = diag_ref.fallback_missing_count;
    diag_ref.fallback_unmatched_psapi_count = fallback.rejected_count;

    if (diag_ref.fallback_match_count != diag_ref.count ||
        diag_ref.fallback_missing_count != 0 ||
        ambiguous_primary_count != 0)
    {
        diag_ref.dependency_blocked = true;
        diag_ref.token = current_process_token_diagnostics();
        diag_ref.fallback_status = "rejected";
        diag_ref.fallback_reason = ambiguous_primary_count != 0
            ? "EnumDeviceDrivers_ambiguous_primary_module_names"
            : "EnumDeviceDrivers_did_not_match_every_SystemModuleInformation_entry";
        const std::string missing = module_sample_text(missing_samples);
        const std::string token_json = diag_ref.token.dump();
        const std::string driver_json = diag_ref.driver.dump();
        error_msg = std::string("dependency_blocked: NtQuerySystemInformation(SystemModuleInformation) returned ") +
            std::to_string(diag_ref.count) +
            std::string(" modules but every ImageBase is zero; read-only EnumDeviceDrivers fallback did not match every primary module. missing_modules=") +
            (missing.empty() ? std::string("<none>") : missing) +
            std::string(" strict_fallback=") + diag_ref.strict_fallback;
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules dependency_blocked reason=all_image_bases_zero fallback_status=rejected fallback_reason=%s primary_count=%lu primary_zero=%zu primary_nonzero=%zu fallback_raw=%lu fallback_named=%zu fallback_name_query_failed=%zu fallback_duplicate=%zu match_count=%zu unmatched_primary=%zu unmatched_psapi=%zu ambiguous_primary=%zu missing=%s token=%s driver=%s strict_fallback=%s base_source=%s",
            diag_ref.fallback_reason.c_str(),
            static_cast<unsigned long>(diag_ref.count),
            diag_ref.zero_base_count,
            diag_ref.nonzero_base_count,
            static_cast<unsigned long>(diag_ref.fallback_raw_count),
            diag_ref.fallback_named_count,
            diag_ref.fallback_name_query_failed_count,
            diag_ref.fallback_duplicate_name_count,
            diag_ref.fallback_match_count,
            diag_ref.fallback_unmatched_primary_count,
            diag_ref.fallback_unmatched_psapi_count,
            ambiguous_primary_count,
            missing.empty() ? "<none>" : missing.c_str(),
            token_json.c_str(),
            driver_json.c_str(),
            diag_ref.strict_fallback.c_str(),
            diag_ref.base_source.c_str());
        return false;
    }

    diag_ref.resolved_zero_base_count = 0;
    diag_ref.resolved_nonzero_base_count = 0;
    for (ULONG i = 0; i < diag_ref.count; ++i)
    {
        info->Modules[i].ImageBase = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(resolved_bases[i]));
        if (resolved_bases[i] == 0)
            ++diag_ref.resolved_zero_base_count;
        else
            ++diag_ref.resolved_nonzero_base_count;
    }

    diag_ref.all_image_bases_zero = diag_ref.count != 0 && diag_ref.resolved_nonzero_base_count == 0;
    diag_ref.dependency_blocked = false;
    diag_ref.fallback_used = true;
    diag_ref.fallback_status = "used";
    diag_ref.fallback_reason = "EnumDeviceDrivers_matched_all_SystemModuleInformation_entries";
    diag_ref.base_source = "EnumDeviceDrivers";
    const std::string fallback_samples = module_sample_text(diag_ref.fallback_samples);
    diag::log_tagged_fmt("drv_tools",
        "query_kernel_modules fallback_selected source=EnumDeviceDrivers primary_count=%lu primary_zero=%zu primary_nonzero=%zu fallback_raw=%lu fallback_named=%zu fallback_name_query_failed=%zu fallback_duplicate=%zu match_count=%zu unmatched_primary=%zu unmatched_psapi=%zu resolved_zero=%zu resolved_nonzero=%zu fallback_status=%s fallback_reason=%s primary_samples=%s fallback_samples=%s",
        static_cast<unsigned long>(diag_ref.count),
        diag_ref.zero_base_count,
        diag_ref.nonzero_base_count,
        static_cast<unsigned long>(diag_ref.fallback_raw_count),
        diag_ref.fallback_named_count,
        diag_ref.fallback_name_query_failed_count,
        diag_ref.fallback_duplicate_name_count,
        diag_ref.fallback_match_count,
        diag_ref.fallback_unmatched_primary_count,
        diag_ref.fallback_unmatched_psapi_count,
        diag_ref.resolved_zero_base_count,
        diag_ref.resolved_nonzero_base_count,
        diag_ref.fallback_status.c_str(),
        diag_ref.fallback_reason.c_str(),
        primary_samples.empty() ? "<none>" : primary_samples.c_str(),
        fallback_samples.empty() ? "<none>" : fallback_samples.c_str());
    return true;
}

static json kernel_module_query_diagnostics_json(const kernel_module_query_diagnostics_t& diag)
{
    json out = json::object();
    out["dependency_blocked"] = diag.dependency_blocked;
    out["module_count"] = diag.count;
    out["buffer_size"] = diag.buffer_size;
    out["returned_length"] = diag.returned_length;
    out["abi_header_size"] = diag.abi_header_size;
    out["abi_entry_size"] = diag.abi_entry_size;
    out["abi_min_size"] = diag.abi_min_size;
    out["zero_base_count"] = diag.zero_base_count;
    out["nonzero_base_count"] = diag.nonzero_base_count;
    out["primary_count"] = diag.count;
    out["primary_zero_bases"] = diag.zero_base_count;
    out["primary_nonzero_bases"] = diag.nonzero_base_count;
    out["resolved_zero_base_count"] = diag.resolved_zero_base_count;
    out["resolved_nonzero_base_count"] = diag.resolved_nonzero_base_count;
    out["all_image_bases_zero"] = diag.all_image_bases_zero;
    out["initial_ntstatus"] = sa_format_address(static_cast<std::uint64_t>(diag.initial_ntstatus));
    out["final_ntstatus"] = sa_format_address(static_cast<std::uint64_t>(diag.final_ntstatus));
    out["win32_error"] = static_cast<unsigned long>(diag.win32_error);
    out["primary_all_image_bases_zero"] = diag.primary_all_image_bases_zero;
    out["sample_modules"] = diag.samples;
    out["base_source"] = diag.base_source;
    out["fallback_attempted"] = diag.fallback_attempted;
    out["fallback_used"] = diag.fallback_used;
    out["fallback_status"] = diag.fallback_status;
    out["fallback_reason"] = diag.fallback_reason;
    out["fallback_win32_error"] = static_cast<unsigned long>(diag.fallback_win32_error);
    out["fallback_bytes_returned"] = diag.fallback_bytes_returned;
    out["fallback_raw_count"] = diag.fallback_raw_count;
    out["fallback_named_count"] = diag.fallback_named_count;
    out["fallback_accepted_count"] = diag.fallback_accepted_count;
    out["fallback_rejected_count"] = diag.fallback_rejected_count;
    out["fallback_name_query_failed_count"] = diag.fallback_name_query_failed_count;
    out["fallback_name_query_failed"] = diag.fallback_name_query_failed_count;
    out["fallback_duplicate_name_count"] = diag.fallback_duplicate_name_count;
    out["fallback_match_count"] = diag.fallback_match_count;
    out["fallback_missing_count"] = diag.fallback_missing_count;
    out["fallback_unmatched_primary_count"] = diag.fallback_unmatched_primary_count;
    out["fallback_unmatched_psapi_count"] = diag.fallback_unmatched_psapi_count;
    out["fallback_sample_modules"] = diag.fallback_samples;
    out["token"] = diag.token;
    out["driver"] = diag.driver;
    out["strict_fallback"] = diag.strict_fallback;
    return out;
}

static tool_result_t kernel_module_query_error_result(
    const std::string& error,
    const kernel_module_query_diagnostics_t& diag,
    std::string prefix = {})
{
    const std::string message = prefix.empty() ? error : prefix + error;
    if (diag.dependency_blocked)
        return tool_result_t::error(message, std::string("dependency_blocked"), kernel_module_query_diagnostics_json(diag));
    return tool_result_t::error(message);
}

typedef LONG(NTAPI* NtQuerySystemInformation_fn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static bool query_kernel_modules(
    std::vector<std::uint8_t>& out_buffer,
    sys_module_info_t*& out_info,
    std::string& error_msg,
    kernel_module_query_diagnostics_t* diagnostics = nullptr,
    kernel_module_query_fallback_policy fallback_policy = kernel_module_query_fallback_policy::primary_only)
{
    out_info = nullptr;
    error_msg.clear();
    if (diagnostics)
        *diagnostics = {};
    kernel_module_query_diagnostics_t local_diag{};
    auto& diag_ref = diagnostics ? *diagnostics : local_diag;
    diag_ref.abi_header_size = sizeof(ULONG);
    diag_ref.abi_entry_size = sizeof(sys_module_entry_t);
    diag_ref.base_source = "SystemModuleInformation";
    diag_ref.strict_fallback = fallback_policy == kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence
        ? "not_needed_primary_image_bases_nonzero"
        : "disabled_primary_only";
    diag_ref.fallback_status = "not_attempted";
    diag_ref.fallback_reason = "primary_source_not_yet_evaluated";

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        diag_ref.win32_error = GetLastError();
        error_msg = std::string("Cannot resolve ntdll.dll");
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules failed stage=resolve_ntdll gle=%lu abi_header=%zu abi_entry=%zu",
            static_cast<unsigned long>(diag_ref.win32_error),
            diag_ref.abi_header_size,
            diag_ref.abi_entry_size);
        return false;
    }

    auto pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation)
    {
        diag_ref.win32_error = GetLastError();
        error_msg = std::string("Cannot resolve NtQuerySystemInformation");
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules failed stage=resolve_NtQuerySystemInformation gle=%lu abi_header=%zu abi_entry=%zu",
            static_cast<unsigned long>(diag_ref.win32_error),
            diag_ref.abi_header_size,
            diag_ref.abi_entry_size);
        return false;
    }

    constexpr ULONG SystemModuleInformation = 11;
    ULONG needed = 0;
    diag::log_tagged_fmt("drv_tools",
        "query_kernel_modules entry fallback_policy=%s abi_header=%zu abi_entry=%zu pid=%lu tid=%lu",
        fallback_policy == kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence ? "allow_readonly_kernel_base_evidence" : "primary_only",
        diag_ref.abi_header_size,
        diag_ref.abi_entry_size,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    const LONG probe_status = pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    diag_ref.initial_ntstatus = static_cast<std::uint32_t>(probe_status);
    diag_ref.returned_length = needed;
    if (needed == 0)
        needed = 256 * 1024;
    needed += 16384;

    out_buffer.resize(needed, 0);
    LONG status = pNtQuerySystemInformation(
        SystemModuleInformation, out_buffer.data(),
        static_cast<ULONG>(out_buffer.size()), &needed);
    diag_ref.final_ntstatus = static_cast<std::uint32_t>(status);
    diag_ref.returned_length = needed;
    diag_ref.buffer_size = out_buffer.size();
    diag::log_tagged_fmt("drv_tools",
        "query_kernel_modules qsi probe_status=0x%08X final_status=0x%08X bytes_returned=%lu buffer_size=%zu abi_header=%zu abi_entry=%zu",
        static_cast<unsigned int>(diag_ref.initial_ntstatus),
        static_cast<unsigned int>(diag_ref.final_ntstatus),
        static_cast<unsigned long>(needed),
        out_buffer.size(),
        diag_ref.abi_header_size,
        diag_ref.abi_entry_size);

    if (status < 0)
    {
        error_msg = std::string("NtQuerySystemInformation(SystemModuleInformation) failed: NTSTATUS ")
            + sa_format_address(static_cast<uint64_t>(diag_ref.final_ntstatus));
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules failed stage=SystemModuleInformation status=0x%08X bytes_returned=%lu buffer_size=%zu",
            static_cast<unsigned int>(diag_ref.final_ntstatus),
            static_cast<unsigned long>(needed),
            out_buffer.size());
        return false;
    }

    out_info = reinterpret_cast<sys_module_info_t*>(out_buffer.data());
    if (out_buffer.size() < sizeof(ULONG))
    {
        error_msg = std::string("System module buffer is too small");
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules failed stage=buffer_too_small buffer_size=%zu abi_header=%zu",
            out_buffer.size(),
            diag_ref.abi_header_size);
        return false;
    }
    const ULONG count = out_info->NumberOfModules;
    const std::size_t min_size =
        sizeof(ULONG) + static_cast<std::size_t>(count) * sizeof(sys_module_entry_t);
    diag_ref.count = count;
    diag_ref.abi_min_size = min_size;
    if (count > 4096 || min_size > out_buffer.size())
    {
        error_msg = std::string("System module buffer failed bounds validation: count=") +
            std::to_string(count) + std::string(" buffer=") + std::to_string(out_buffer.size());
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules failed stage=bounds count=%lu min_size=%zu buffer_size=%zu bytes_returned=%zu abi_entry=%zu",
            static_cast<unsigned long>(count),
            min_size,
            out_buffer.size(),
            diag_ref.returned_length,
            diag_ref.abi_entry_size);
        return false;
    }
    diag_ref.samples.reserve((std::min)(static_cast<ULONG>(8), count));
    for (ULONG i = 0; i < count; ++i)
    {
        const auto& m = out_info->Modules[i];
        const std::uint64_t base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(m.ImageBase));
        if (base == 0)
            ++diag_ref.zero_base_count;
        else
            ++diag_ref.nonzero_base_count;
        if (diag_ref.samples.size() < 8)
        {
            std::ostringstream sample;
            sample << bounded_kernel_module_name(m)
                   << "@raw_base=" << sa_format_address(base)
                   << ",size=" << sa_format_address(static_cast<std::uint64_t>(m.ImageSize))
                   << ",offset=" << static_cast<unsigned long>(m.OffsetToFileName);
            diag_ref.samples.push_back(sample.str());
        }
    }
    diag_ref.primary_all_image_bases_zero = count != 0 && diag_ref.nonzero_base_count == 0;
    diag_ref.all_image_bases_zero = diag_ref.primary_all_image_bases_zero;
    diag_ref.resolved_zero_base_count = diag_ref.zero_base_count;
    diag_ref.resolved_nonzero_base_count = diag_ref.nonzero_base_count;
    diag_ref.fallback_reason = diag_ref.primary_all_image_bases_zero ? "primary_source_all_image_bases_zero" : "primary_source_has_nonzero_bases";
    std::string kernel_session_reason;
    const bool kernel_session_ok = driver_bridge::kernel_session_available(&kernel_session_reason);
    diag_ref.driver = json::object({
        {"using_kernel_driver", driver_bridge::using_kernel_driver()},
        {"kernel_session_available", kernel_session_ok},
        {"kernel_session_reason", kernel_session_reason},
        {"status", driver_bridge::status()},
        {"attached_pid", driver_bridge::attached_pid()}
    });
    const std::string samples = module_sample_text(diag_ref.samples);
    diag::log_tagged_fmt("drv_tools",
        "query_kernel_modules primary_ok count=%lu bytes=%zu returned=%zu zero_bases=%zu nonzero_bases=%zu all_zero=%d samples=%s driver_kernel=%d kernel_session=%d kernel_session_reason=%s",
        static_cast<unsigned long>(count),
        out_buffer.size(),
        diag_ref.returned_length,
        diag_ref.zero_base_count,
        diag_ref.nonzero_base_count,
        diag_ref.primary_all_image_bases_zero ? 1 : 0,
        samples.empty() ? "<none>" : samples.c_str(),
        driver_bridge::using_kernel_driver() ? 1 : 0,
        kernel_session_ok ? 1 : 0,
        kernel_session_reason.empty() ? "<empty>" : kernel_session_reason.c_str());

    if (diag_ref.primary_all_image_bases_zero)
    {
        if (fallback_policy == kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence)
            return apply_readonly_kernel_module_base_fallback(out_info, diag_ref, error_msg);

        diag_ref.dependency_blocked = true;
        diag_ref.token = current_process_token_diagnostics();
        if (diag_ref.fallback_status == "not_attempted")
        {
            diag_ref.strict_fallback = "disabled_for_primary_only_context";
            diag_ref.fallback_reason = "readonly_kernel_base_fallback_not_permitted_by_caller";
        }
        const std::string sample_value = samples.empty() ? std::string("<none>") : samples;
        error_msg = std::string("dependency_blocked: NtQuerySystemInformation(SystemModuleInformation) returned ") +
            std::to_string(count) +
            std::string(" modules but every ImageBase is zero; kernel module base resolution is unavailable for this context. sample_modules=") +
            sample_value +
            std::string(" strict_fallback=") + diag_ref.strict_fallback +
            std::string(" fallback_status=") + diag_ref.fallback_status +
            std::string(" fallback_reason=") + diag_ref.fallback_reason;
        const std::string token_json = diag_ref.token.dump();
        const std::string driver_json = diag_ref.driver.dump();
        diag::log_tagged_fmt("drv_tools",
            "query_kernel_modules dependency_blocked reason=all_image_bases_zero count=%lu token=%s driver=%s strict_fallback=%s fallback_status=%s fallback_reason=%s",
            static_cast<unsigned long>(count),
            token_json.c_str(),
            driver_json.c_str(),
            diag_ref.strict_fallback.c_str(),
            diag_ref.fallback_status.c_str(),
            diag_ref.fallback_reason.c_str());
        return false;
    }
    return true;
}

tool_result_t driver_enumerate_kernel_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_kernel_modules entry");

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_enumerate_kernel_modules", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
    {
        if (query_diag.dependency_blocked)
            return tool_result_t::error(err, std::string("dependency_blocked"), kernel_module_query_diagnostics_json(query_diag));
        return tool_result_t::error(err);
    }

    std::string filter;
    if (params.contains("filter") && params["filter"].is_string())
        filter = params["filter"].get<std::string>();

    int limit = params.value("limit", 500);

    json modules_arr = json::array();
    for (ULONG i = 0; i < info->NumberOfModules && static_cast<int>(modules_arr.size()) < limit; i++)
    {
        const auto& m = info->Modules[i];
        std::string full_path = bounded_kernel_module_path(m);
        std::string name = bounded_kernel_module_name(m);

        if (!filter.empty())
        {
            std::string lower_name = name;
            std::string lower_filter = filter;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower_name.find(lower_filter) == std::string::npos)
            {
                std::string lower_path = full_path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lower_path.find(lower_filter) == std::string::npos)
                    continue;
            }
        }

        std::string resolved_path = resolve_nt_path_to_win32(full_path);

        json entry;
        entry["name"]           = name;
        entry["nt_path"]        = full_path;
        entry["disk_path"]      = resolved_path;
        entry["base_address"]   = sa_format_address(
            static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(m.ImageBase)));
        entry["size"]           = m.ImageSize;
        entry["size_hex"]       = sa_format_address(static_cast<uint64_t>(m.ImageSize));
        entry["load_order"]     = m.LoadOrderIndex;
        modules_arr.push_back(entry);
    }

    json result;
    result["modules"]        = modules_arr;
    result["total_loaded"]   = info->NumberOfModules;
    result["returned"]       = modules_arr.size();
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);

    return tool_result_t::ok(
        std::string("Enumerated ") + std::to_string(modules_arr.size()) + std::string(" kernel modules") +
        (filter.empty() ? "" : std::string(" matching '") + filter + "'"), result);
}

static bool parse_kernel_address_param(const json& params, const char* key, std::uint64_t& out)
{
    out = 0;
    if (!params.contains(key))
        return false;
    const auto& value = params[key];
    if (value.is_string())
    {
        auto parsed = sa_parse_address(value.get<std::string>());
        if (parsed)
        {
            out = *parsed;
            return true;
        }
        return false;
    }
    if (value.is_number_unsigned())
    {
        out = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer())
    {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value >= 0)
        {
            out = static_cast<std::uint64_t>(signed_value);
            return true;
        }
    }
    return false;
}

static json kernel_symbols_status_json()
{
    const kernel_symbols::status_t st = kernel_symbols::status();
    json out;
    out["state"] = kernel_symbols::state_name(st.state);
    out["ready"] = st.state == kernel_symbols::state_t::ready;
    out["detail"] = st.detail;
    out["last_error"] = st.last_error;
    out["pdb_name"] = st.pdb_name;
    out["cache_path"] = st.cache_path;
    out["from_cache"] = st.from_cache;
    out["ntoskrnl_base"] = sa_format_address(st.ntoskrnl_base);
    out["ntoskrnl_size"] = st.ntoskrnl_size;
    out["function_count"] = st.function_count;
    out["global_count"] = st.global_count;
    out["struct_count"] = st.struct_count;
    out["load_duration_ms"] = st.load_duration_ms;
    return out;
}

static bool parse_kernel_address_or_symbol(const json& params, const char* key,
                                           std::uint64_t& out, std::string& err)
{
    err.clear();
    if (parse_kernel_address_param(params, key, out))
        return true;
    if (!params.contains(key))
    {
        err = std::string("Missing '") + key + "'.";
        return false;
    }
    const auto& value = params[key];
    if (!value.is_string())
    {
        err = std::string("'") + key + "' must be a kernel address or symbol expression.";
        return false;
    }
    const std::string expression = value.get<std::string>();
    kernel_symbols::ensure_started();
    if (auto resolved = kernel_symbols::resolve(expression))
    {
        out = *resolved;
        diag::log_tagged_fmt("drv_tools",
            "parse_kernel_address_or_symbol key=%s expr=\"%s\" -> 0x%llX",
            key, expression.c_str(), static_cast<unsigned long long>(out));
        return true;
    }
    const kernel_symbols::status_t st = kernel_symbols::status();
    err = std::string("Could not resolve '") + expression +
        "' as a kernel address or symbol expression (symbols state=" +
        kernel_symbols::state_name(st.state) +
        (st.detail.empty() ? "" : ", detail=" + st.detail) +
        (st.last_error.empty() ? "" : ", last_error=" + st.last_error) + ").";
    return false;
}


tool_result_t driver_read_kernel_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_kernel_memory entry");
    if (auto context_error = ensure_kernel_memory_context())
        return *context_error;

    std::uint64_t address = 0;
    std::string address_error;
    if (!parse_kernel_address_or_symbol(params, "address", address, address_error))
        return tool_result_t::error(std::string("Missing or invalid kernel address: ") + address_error);

    const bool annotate = !params.contains("annotate") || !params["annotate"].is_boolean() ||
        params["annotate"].get<bool>();
    std::string struct_name;
    if (params.contains("struct") && params["struct"].is_string())
        struct_name = params["struct"].get<std::string>();
    if (annotate || !struct_name.empty())
        kernel_symbols::ensure_started();

    std::uint64_t size64 = 0;
    if (!parse_kernel_size(params, "size", size64))
        return tool_result_t::error(std::string("Missing or invalid size."));
    constexpr std::uint64_t max_read_size = 1024ULL * 1024ULL;
    if (size64 > max_read_size)
        return tool_result_t::error(std::string("Kernel reads are capped at 1048576 bytes per call."));

    std::string range_error;
    if (!validate_kernel_range(address, size64, range_error))
        return tool_result_t::error(range_error);

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_error = acquire_driver_debugger_quota("driver_read_kernel_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_error;

    std::vector<std::uint8_t> bytes;
    const bool read_ok = driver_bridge::read_kernel_memory(address, static_cast<std::size_t>(size64), bytes);
    if (!read_ok || bytes.empty())
    {
        json details;
        details["address"] = sa_format_address(address);
        details["address_pretty"] = kernel_symbols::format(address);
        details["requested_size"] = size64;
        details["driver_status"] = driver_bridge::status();
        details["driver_error"] = driver_bridge::last_error();
        return tool_result_t::error(std::string("Kernel memory read failed."), std::string("kernel_read_failed"), details);
    }

    json result;
    result["address"] = sa_format_address(address);
    result["requested_size"] = size64;
    result["size"] = bytes.size();
    result["complete"] = bytes.size() == size64;
    result["hex"] = kernel_bytes_hex(bytes);
    result["ascii"] = kernel_bytes_ascii(bytes);
    result["kernel_dtb"] = sa_format_address(device->get_kernel_dtb() != 0 ? device->get_kernel_dtb() : device->get_dtb());
    result["address_pretty"] = kernel_symbols::format(address);
    result["symbols"] = kernel_symbols_status_json();

    if (annotate)
    {
        const bool symbols_ready = kernel_symbols::ready();
        constexpr std::size_t max_annotations = 256;
        std::size_t annotation_count = 0;
        json lines = json::array();
        for (std::size_t row = 0; row < bytes.size(); row += 16)
        {
            const std::size_t row_len = (std::min)(bytes.size() - row, static_cast<std::size_t>(16));
            const std::uint64_t row_address = address + row;
            const std::vector<std::uint8_t> row_bytes(bytes.begin() + row, bytes.begin() + row + row_len);
            json line;
            line["address"] = sa_format_address(row_address);
            line["pretty"] = kernel_symbols::format(row_address);
            line["hex"] = kernel_bytes_hex(row_bytes);
            line["ascii"] = kernel_bytes_ascii(row_bytes);
            if (symbols_ready && annotation_count < max_annotations && row_len >= 8)
            {
                json pointers = json::array();
                for (std::size_t off = 0; off + 8 <= row_len; off += 8)
                {
                    std::uint64_t pointer = 0;
                    std::memcpy(&pointer, bytes.data() + row + off, sizeof(pointer));
                    if (!is_probably_kernel_address(pointer))
                        continue;
                    if (!kernel_symbols::lookup(pointer))
                        continue;
                    json annotation;
                    annotation["offset"] = row + off;
                    annotation["value"] = sa_format_address(pointer);
                    annotation["pretty"] = kernel_symbols::format(pointer);
                    pointers.push_back(std::move(annotation));
                    if (++annotation_count >= max_annotations)
                        break;
                }
                if (!pointers.empty())
                    line["pointers"] = std::move(pointers);
            }
            lines.push_back(std::move(line));
        }
        result["annotated_lines"] = std::move(lines);
    }

    if (!struct_name.empty())
    {
        if (auto desc = kernel_symbols::describe_struct(struct_name))
        {
            json decoded;
            decoded["name"] = desc->name;
            decoded["size"] = desc->size;
            decoded["truncated"] = bytes.size() < desc->size;
            const auto fields = kernel_symbols::decode_struct_buffer(*desc, bytes, address);
            json field_array = json::array();
            for (const auto& field : fields)
            {
                json entry;
                entry["name"] = field.name;
                entry["type"] = field.type;
                entry["offset"] = field.offset;
                entry["size"] = field.size;
                entry["value"] = field.value;
                entry["truncated"] = field.truncated;
                if (!field.annotation.empty())
                    entry["annotation"] = field.annotation;
                field_array.push_back(std::move(entry));
            }
            decoded["fields"] = std::move(field_array);
            result["struct_decode"] = std::move(decoded);
        }
        else
        {
            json failure;
            failure["error"] = std::string("Struct '") + struct_name +
                "' was not found in the loaded kernel PDB (symbols state=" +
                kernel_symbols::state_name(kernel_symbols::status().state) + ").";
            failure["struct"] = struct_name;
            result["struct_decode"] = std::move(failure);
        }
    }

    diag::log_tagged_fmt("drv_tools",
        "driver_read_kernel_memory exit addr=0x%llX requested=%llu read=%zu complete=%d annotate=%d struct=\"%s\"",
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size64),
        bytes.size(), bytes.size() == size64 ? 1 : 0, annotate ? 1 : 0, struct_name.c_str());
    if (bytes.size() != size64)
        return tool_result_t::error(
            std::string("Kernel memory read was partial; exact-length reads are required."),
            std::string("kernel_read_partial"), result);
    return tool_result_t::ok(std::string("Read kernel memory."), result);
}

tool_result_t driver_write_kernel_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_write_kernel_memory entry");
    std::uint64_t address = 0;
    std::string address_error;
    if (!parse_kernel_address_or_symbol(params, "address", address, address_error))
        return tool_result_t::error(std::string("Missing or invalid kernel address: ") + address_error);

    if (!params.contains("bytes"))
        return tool_result_t::error(std::string("Missing bytes payload."));

    std::vector<std::uint8_t> bytes;
    std::string parse_error;
    if (!parse_byte_sequence(params["bytes"], bytes, parse_error))
        return tool_result_t::error(parse_error);
    constexpr std::size_t max_write_size = 1024 * 1024;
    if (bytes.size() > max_write_size)
        return tool_result_t::error(std::string("Kernel writes are capped at 1048576 bytes per call."));

    std::string range_error;
    if (!validate_kernel_range(address, bytes.size(), range_error))
        return tool_result_t::error(range_error);

    const bool dry_run = params.value("dry_run", false);
    if (!dry_run && !params.value("confirm_unsafe", false))
        return tool_result_t::error(
            std::string("driver_write_kernel_memory can corrupt kernel state or crash Windows. Re-run with confirm_unsafe=true, or use dry_run=true to validate the request without writing."));

    std::vector<std::uint8_t> expected;
    if (params.contains("expected_bytes"))
    {
        if (!parse_byte_sequence(params["expected_bytes"], expected, parse_error))
            return tool_result_t::error(std::string("Invalid expected_bytes: ") + parse_error);
        if (expected.size() != bytes.size())
            return tool_result_t::error(std::string("expected_bytes must have exactly the same length as bytes."));
    }

    if (auto context_error = ensure_kernel_memory_context())
        return *context_error;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_error = acquire_driver_debugger_quota("driver_write_kernel_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_error;

    std::vector<std::uint8_t> before;
    if (!driver_bridge::read_kernel_memory(address, bytes.size(), before) || before.size() != bytes.size())
    {
        json details;
        details["address"] = sa_format_address(address);
        details["requested_size"] = bytes.size();
        details["bytes_read"] = before.size();
        return tool_result_t::error(
            std::string("Pre-write kernel read failed or was partial; the write was not attempted."),
            std::string("kernel_prewrite_read_failed"), details);
    }

    if (!expected.empty() && !std::equal(expected.begin(), expected.end(), before.begin()))
    {
        json details;
        details["address"] = sa_format_address(address);
        details["expected_hex"] = kernel_bytes_hex(expected);
        details["actual_hex"] = kernel_bytes_hex(before);
        return tool_result_t::error(
            std::string("Kernel memory no longer matches expected_bytes; the write was not attempted."),
            std::string("kernel_compare_exchange_mismatch"), details);
    }

    if (dry_run)
    {
        json preview;
        preview["address"] = sa_format_address(address);
        preview["size"] = bytes.size();
        preview["before_hex"] = kernel_bytes_hex(before);
        preview["replacement_hex"] = kernel_bytes_hex(bytes);
        preview["expected_bytes_checked"] = !expected.empty();
        preview["written"] = false;
        return tool_result_t::ok(std::string("Validated kernel write dry-run; no memory was modified."), preview);
    }

    if (!driver_bridge::write_kernel_memory(address, bytes))
    {
        json details;
        details["address"] = sa_format_address(address);
        details["size"] = bytes.size();
        details["before_hex"] = kernel_bytes_hex(before);
        details["driver_error"] = driver_bridge::last_error();
        return tool_result_t::error(std::string("Kernel memory write failed or was partial."), std::string("kernel_write_failed"), details);
    }

    std::vector<std::uint8_t> after;
    const bool readback_ok = driver_bridge::read_kernel_memory(address, bytes.size(), after) && after.size() == bytes.size();
    const bool verified = readback_ok && std::equal(bytes.begin(), bytes.end(), after.begin());
    json result;
    result["address"] = sa_format_address(address);
    result["size"] = bytes.size();
    result["before_hex"] = kernel_bytes_hex(before);
    result["requested_hex"] = kernel_bytes_hex(bytes);
    result["readback_hex"] = kernel_bytes_hex(after);
    result["readback_complete"] = readback_ok;
    result["verified"] = verified;
    result["expected_bytes_checked"] = !expected.empty();
    diag::log_tagged_fmt("drv_tools",
        "driver_write_kernel_memory exit addr=0x%llX size=%zu readback_ok=%d verified=%d",
        static_cast<unsigned long long>(address), bytes.size(), readback_ok ? 1 : 0, verified ? 1 : 0);
    if (!verified)
        return tool_result_t::error(
            std::string("Kernel write completed but exact readback verification failed; kernel state may have changed and must be inspected."),
            std::string("kernel_write_verification_failed"), result);
    return tool_result_t::ok(std::string("Wrote and verified kernel memory."), result);
}

tool_result_t search_kernel_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "search_kernel_memory entry");
    if (auto context_error = ensure_kernel_memory_context())
        return *context_error;

    if (!params.contains("pattern"))
        return tool_result_t::error(std::string("Missing required pattern."));
    kernel_pattern_t pattern;
    std::string pattern_error;
    if (!parse_kernel_pattern(params["pattern"], pattern, pattern_error))
        return tool_result_t::error(pattern_error);

    std::uint64_t start = 0;
    std::uint64_t span = 0;
    std::string module_name;
    json module_diagnostics;
    const bool has_module = params.contains("module") && params["module"].is_string() &&
        !trim_ascii_copy(params["module"].get<std::string>()).empty();
    const bool has_address = params.contains("address") || params.contains("start_address");
    if (has_module && has_address)
        return tool_result_t::error(std::string("Specify either module or address/start_address, not both."));

    if (has_module)
    {
        const std::string query = to_lower_ascii_copy(trim_ascii_copy(params["module"].get<std::string>()));
        std::vector<std::uint8_t> module_buffer;
        sys_module_info_t* module_info = nullptr;
        std::string module_error;
        kernel_module_query_diagnostics_t query_diagnostics{};
        if (!query_kernel_modules(module_buffer, module_info, module_error, &query_diagnostics,
                kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
            return kernel_module_query_error_result(module_error, query_diagnostics, std::string("Cannot resolve kernel module scan range: "));
        module_diagnostics = kernel_module_query_diagnostics_json(query_diagnostics);

        std::vector<const sys_module_entry_t*> exact;
        std::vector<const sys_module_entry_t*> partial;
        for (ULONG i = 0; i < module_info->NumberOfModules; ++i)
        {
            const auto& entry = module_info->Modules[i];
            const std::string name = to_lower_ascii_copy(bounded_kernel_module_name(entry));
            const std::string path = to_lower_ascii_copy(bounded_kernel_module_path(entry));
            if (name == query || path == query)
                exact.push_back(&entry);
            else if (name.find(query) != std::string::npos || path.find(query) != std::string::npos)
                partial.push_back(&entry);
        }
        const auto& candidates = exact.empty() ? partial : exact;
        if (candidates.empty())
            return tool_result_t::error(std::string("No loaded kernel module matches '") + query + "'.");
        if (candidates.size() != 1)
            return tool_result_t::error(std::string("Kernel module query is ambiguous; use the exact module filename."));

        const auto& entry = *candidates.front();
        const std::uint64_t base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(entry.ImageBase));
        const std::uint64_t module_size = entry.ImageSize;
        std::uint64_t offset = 0;
        if (params.contains("offset") && !parse_kernel_size(params, "offset", offset))
            return tool_result_t::error(std::string("Invalid module offset."));
        if (offset >= module_size)
            return tool_result_t::error(std::string("Module offset is outside the loaded image."));
        start = base + offset;
        span = module_size - offset;
        if (params.contains("size"))
        {
            std::uint64_t requested_span = 0;
            if (!parse_kernel_size(params, "size", requested_span) || requested_span == 0)
                return tool_result_t::error(std::string("Invalid scan size."));
            if (requested_span > span)
                return tool_result_t::error(std::string("Requested scan size extends beyond the selected kernel module."));
            span = requested_span;
        }
        module_name = bounded_kernel_module_name(entry);
    }
    else
    {
        const char* address_key = params.contains("address") ? "address" : "start_address";
        std::string address_error;
        if (!parse_kernel_address_or_symbol(params, address_key, start, address_error))
            return tool_result_t::error(std::string("Missing or invalid address/start_address: ") + address_error);
        if (!parse_kernel_size(params, "size", span))
            return tool_result_t::error(std::string("Missing or invalid scan size."));
    }

    constexpr std::uint64_t max_scan_span = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    if (span > max_scan_span)
        return tool_result_t::error(std::string("Kernel searches are capped at 4294967296 bytes per call."));
    std::string range_error;
    if (!validate_kernel_range(start, span, range_error))
        return tool_result_t::error(range_error);
    if (span > std::numeric_limits<std::uint64_t>::max() - start)
        return tool_result_t::error(std::string("Kernel search end-exclusive address overflows the 64-bit virtual address space."));
    if (span < pattern.bytes.size())
        return tool_result_t::error(std::string("Scan range is smaller than the pattern."));

    std::uint64_t chunk_size64 = 64 * 1024;
    if (params.contains("chunk_size") && !parse_kernel_size(params, "chunk_size", chunk_size64))
        return tool_result_t::error(std::string("Invalid chunk_size."));
    if (chunk_size64 < 4096 || chunk_size64 > 1024 * 1024)
        return tool_result_t::error(std::string("chunk_size must be between 4096 and 1048576 bytes."));

    std::uint64_t max_results64 = 256;
    if (params.contains("max_results") && !parse_kernel_size(params, "max_results", max_results64))
        return tool_result_t::error(std::string("Invalid max_results."));
    if (max_results64 == 0 || max_results64 > 4096)
        return tool_result_t::error(std::string("max_results must be between 1 and 4096."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_error = acquire_driver_debugger_quota("search_kernel_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_error;

    const std::uint64_t end = start + span;
    std::uint64_t cursor = start;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t bytes_unreadable = 0;
    std::uint64_t read_failures = 0;
    bool result_limit_reached = false;
    std::vector<std::uint8_t> tail;
    json matches = json::array();

    while (cursor < end)
    {
        if (mcp_standalone::current_call_cancelled())
        {
            json details;
            details["start_address"] = sa_format_address(start);
            details["next_address"] = sa_format_address(cursor);
            details["bytes_scanned"] = bytes_scanned;
            details["bytes_unreadable"] = bytes_unreadable;
            details["matches"] = matches;
            return tool_result_t::error(std::string("Kernel memory search was cancelled."), std::string("cancelled"), details);
        }

        const std::uint64_t remaining = end - cursor;
        const std::size_t requested = static_cast<std::size_t>((std::min)(remaining, chunk_size64));
        std::vector<std::uint8_t> chunk;
        if (!driver_bridge::read_kernel_memory(cursor, requested, chunk) || chunk.empty())
        {
            tail.clear();
            const std::uint64_t page_remaining = 0x1000ULL - (cursor & 0xFFFULL);
            const std::uint64_t skipped = (std::min)(remaining, page_remaining);
            cursor += skipped;
            bytes_unreadable += skipped;
            ++read_failures;
            continue;
        }

        const std::size_t actual = chunk.size();
        std::vector<std::uint8_t> window;
        window.reserve(tail.size() + actual);
        window.insert(window.end(), tail.begin(), tail.end());
        window.insert(window.end(), chunk.begin(), chunk.end());
        const std::uint64_t window_base = cursor - tail.size();
        if (window.size() >= pattern.bytes.size())
        {
            const std::size_t final_start = window.size() - pattern.bytes.size();
            for (std::size_t offset = 0; offset <= final_start; ++offset)
            {
                if (window[offset + pattern.anchor] != pattern.bytes[pattern.anchor])
                    continue;
                bool matched = true;
                for (std::size_t i = 0; i < pattern.bytes.size(); ++i)
                {
                    if (pattern.masks[i] != 0 && window[offset + i] != pattern.bytes[i])
                    {
                        matched = false;
                        break;
                    }
                }
                if (!matched)
                    continue;
                const std::uint64_t match_address = window_base + offset;
                if (match_address < start || match_address + pattern.bytes.size() > end)
                    continue;
                matches.push_back(sa_format_address(match_address));
                if (matches.size() >= max_results64)
                {
                    result_limit_reached = true;
                    break;
                }
            }
        }

        bytes_scanned += actual;
        cursor += actual;
        if (result_limit_reached)
            break;
        const std::size_t tail_size = (std::min)(pattern.bytes.size() - 1, window.size());
        tail.assign(window.end() - static_cast<std::ptrdiff_t>(tail_size), window.end());
    }

    json result;
    result["start_address"] = sa_format_address(start);
    result["end_address_exclusive"] = sa_format_address(end);
    result["requested_size"] = span;
    result["bytes_scanned"] = bytes_scanned;
    result["bytes_unreadable"] = bytes_unreadable;
    result["read_failures"] = read_failures;
    result["matches"] = matches;
    result["match_count"] = matches.size();
    result["max_results"] = max_results64;
    result["result_limit_reached"] = result_limit_reached;
    result["complete"] = !result_limit_reached && cursor >= end;
    if (!module_name.empty())
    {
        result["module"] = module_name;
        result["module_base_diagnostics"] = module_diagnostics;
    }
    if (bytes_scanned == 0)
        return tool_result_t::error(
            std::string("No readable kernel memory was found in the requested range."),
            std::string("kernel_search_unreadable_range"), result);
    diag::log_tagged_fmt("drv_tools",
        "search_kernel_memory exit start=0x%llX span=%llu scanned=%llu unreadable=%llu failures=%llu matches=%zu limit=%d complete=%d",
        static_cast<unsigned long long>(start),
        static_cast<unsigned long long>(span),
        static_cast<unsigned long long>(bytes_scanned),
        static_cast<unsigned long long>(bytes_unreadable),
        static_cast<unsigned long long>(read_failures),
        matches.size(), result_limit_reached ? 1 : 0, cursor >= end ? 1 : 0);
    return tool_result_t::ok(std::string("Searched live kernel memory."), result);
}





tool_result_t driver_allocate_memory(const json& params)
{
    const DWORD host_pid = GetCurrentProcessId();
    const DWORD host_tid = GetCurrentThreadId();
    const auto t_entry = std::chrono::steady_clock::now();
    const std::uint32_t bridge_pid_before = driver_bridge::attached_pid();
    const bool bridge_alive_before = driver_bridge::using_kernel_driver();
    diag::log_tagged_fmt("drv_tools",
        "driver_allocate_memory ENTER host_pid=%lu host_tid=%lu bridge_pid=%u bridge_alive=%d driver_status=\"%s\" last_error=\"%s\"",
        static_cast<unsigned long>(host_pid),
        static_cast<unsigned long>(host_tid),
        bridge_pid_before,
        bridge_alive_before ? 1 : 0,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    if (auto ctx_err = ensure_attached_process_context(params))
    {
        diag::log_tagged_fmt("drv_tools",
            "driver_allocate_memory EXIT host_pid=%lu host_tid=%lu reason=ensure_attached_context_error elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            static_cast<unsigned long>(host_pid),
            static_cast<unsigned long>(host_tid),
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t_entry).count()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return *ctx_err;
    }

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_allocate_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::size_t size = 0;
    if (params.contains("size"))
    {
        if (params["size"].is_number())
            size = params["size"].get<std::size_t>();
        else if (params["size"].is_string())
        {
            auto addr = sa_parse_address(params["size"].get<std::string>());
            if (addr) size = static_cast<std::size_t>(*addr);
        }
    }
    if (size == 0 || size > 0x1000000)
    {
        diag::log_tagged_fmt("drv_tools",
            "driver_allocate_memory EXIT host_pid=%lu host_tid=%lu reason=invalid_size requested=%zu elapsed_us=%lld",
            static_cast<unsigned long>(host_pid),
            static_cast<unsigned long>(host_tid),
            size,
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t_entry).count()));
        return tool_result_t::error(std::string("Invalid size. Must be 1 to 16777216 (16MB)."));
    }

    const std::uint32_t bridge_pid_after_ctx = driver_bridge::attached_pid();
    const bool bridge_alive_after_ctx = driver_bridge::using_kernel_driver();
    const std::uint64_t dtb_after_ctx = device ? device->get_dtb() : 0;
    diag::log_tagged_fmt("drv_tools",
        "driver_allocate_memory KERNEL-CALL ENTER host_pid=%lu host_tid=%lu bridge_pid=%u bridge_alive=%d dtb=0x%016llX requested_size=%zu driver_status=\"%s\" last_error=\"%s\"",
        static_cast<unsigned long>(host_pid),
        static_cast<unsigned long>(host_tid),
        bridge_pid_after_ctx,
        bridge_alive_after_ctx ? 1 : 0,
        static_cast<unsigned long long>(dtb_after_ctx),
        size,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());

    SetLastError(0);
    const auto t_kernel = std::chrono::steady_clock::now();
    std::uint64_t allocated = device->allocate_memory(size);
    const DWORD kernel_gle = GetLastError();
    const long long kernel_us = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t_kernel).count());
    const std::uint32_t bridge_pid_after_call = driver_bridge::attached_pid();
    const bool bridge_alive_after_call = driver_bridge::using_kernel_driver();
    diag::log_tagged_fmt("drv_tools",
        "driver_allocate_memory KERNEL-CALL EXIT host_pid=%lu host_tid=%lu va=0x%016llX requested_size=%zu kernel_us=%lld gle=%lu bridge_pid_after=%u bridge_alive_after=%d driver_status=\"%s\" last_error=\"%s\"",
        static_cast<unsigned long>(host_pid),
        static_cast<unsigned long>(host_tid),
        static_cast<unsigned long long>(allocated),
        size,
        kernel_us,
        static_cast<unsigned long>(kernel_gle),
        bridge_pid_after_call,
        bridge_alive_after_call ? 1 : 0,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());

    if (allocated == 0)
    {
        diag::log_tagged_fmt("drv_tools",
            "driver_allocate_memory EXIT host_pid=%lu host_tid=%lu reason=allocate_returned_zero requested_size=%zu kernel_us=%lld gle=%lu elapsed_us=%lld bridge_pid=%u bridge_alive=%d driver_status=\"%s\" last_error=\"%s\"",
            static_cast<unsigned long>(host_pid),
            static_cast<unsigned long>(host_tid),
            size,
            kernel_us,
            static_cast<unsigned long>(kernel_gle),
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t_entry).count()),
            bridge_pid_after_call,
            bridge_alive_after_call ? 1 : 0,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return tool_result_t::error(std::string("Failed to allocate memory in target process."));
    }

    json result;
    result["address"]    = sa_format_address(static_cast<uint64_t>(allocated));
    result["size"]       = size;
    result["protection"] = "PAGE_EXECUTE_READWRITE";
    result["process_id"] = device->get_process_id();
    diag::log_tagged_fmt("drv_tools",
        "driver_allocate_memory EXIT host_pid=%lu host_tid=%lu reason=success va=0x%016llX size=%zu kernel_us=%lld elapsed_us=%lld",
        static_cast<unsigned long>(host_pid),
        static_cast<unsigned long>(host_tid),
        static_cast<unsigned long long>(allocated),
        size,
        kernel_us,
        static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t_entry).count()));
    return tool_result_t::ok(
        std::string("Allocated ") + std::to_string(size) + std::string(" bytes at ") +
        sa_format_address(static_cast<uint64_t>(allocated)), result);
}

tool_result_t driver_free_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_free_memory entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_free_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(std::string("Invalid address."));

    std::uint64_t address = static_cast<std::uint64_t>(*addr_opt);

    voyager::device_t::memory_region_info before{};
    const bool query_before_free = device->query_memory(address, before);

    bool ok = device->free_memory(address);

    json result;
    result["address"]    = sa_format_address(*addr_opt);
    result["freed"]      = ok;
    result["process_id"] = device->get_process_id();
    result["query_before_free"] = query_before_free;
    if (query_before_free)
    {
        result["region_base"] = sa_format_address(static_cast<uint64_t>(before.base));
        result["region_size"] = sa_format_address(static_cast<uint64_t>(before.size));
        result["region_protect"] = before.protect;
    }

    if (ok)
        return tool_result_t::ok(std::string("Memory freed at ") + sa_format_address(*addr_opt), result);
    else
        return tool_result_t::error(std::string("Failed to free memory at ") + sa_format_address(*addr_opt) +
            std::string(". If the region was modified through kernel-space writes, verify address space consistency and attached PID."));
}

tool_result_t driver_call_function(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_call_function entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto func_opt = sa_parse_address(params["address"].get<std::string>());
    if (!func_opt || *func_opt == 0)
        return tool_result_t::error(std::string("Invalid function address."));

    std::uint64_t func_addr = static_cast<std::uint64_t>(*func_opt);

    const bool dry_run = params.value("dry_run", false);
    const bool unsafe_confirmed =
        params.value("confirm_unsafe", false) ||
        params.value("allow_unsafe", false) ||
        params.value("unsafe", false);

    if (dry_run)
    {
        json preview;
        preview["function"] = sa_format_address(static_cast<uint64_t>(func_addr));
        preview["process_id"] = device->get_process_id();
        preview["note"] = "Dry-run only. No remote execution performed.";
        return tool_result_t::ok(std::string("driver_call_function dry-run completed."), preview);
    }

    if (!unsafe_confirmed)
    {
        return tool_result_t::error(
            std::string("driver_call_function is high-risk and may crash the target process. "
                   "Re-run with confirm_unsafe=true (or allow_unsafe=true) to execute, "
                   "or dry_run=true to preview only."));
    }

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_call_function", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::uint64_t args[4] = {0, 0, 0, 0};
    const char* arg_names[] = {"arg1", "arg2", "arg3", "arg4"};
    for (int i = 0; i < 4; ++i)
    {
        if (params.contains(arg_names[i]))
        {
            const auto& val = params[arg_names[i]];
            if (val.is_number())
                args[i] = val.get<std::uint64_t>();
            else if (val.is_string())
            {
                auto a = sa_parse_address(val.get<std::string>());
                if (a) args[i] = static_cast<std::uint64_t>(*a);
            }
        }
    }

    std::uint64_t ret = device->call_function(func_addr, args[0], args[1], args[2], args[3]);

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t crashed_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(std::string("Target process PID ") + std::to_string(crashed_pid) +
            std::string(" terminated during driver_call_function. Process context was detached for safety."));
    }

    json result;
    result["function"]   = sa_format_address(static_cast<uint64_t>(func_addr));
    result["arg1"]       = sa_format_address(static_cast<uint64_t>(args[0]));
    result["arg2"]       = sa_format_address(static_cast<uint64_t>(args[1]));
    result["arg3"]       = sa_format_address(static_cast<uint64_t>(args[2]));
    result["arg4"]       = sa_format_address(static_cast<uint64_t>(args[3]));
    result["return_value"] = sa_format_address(static_cast<uint64_t>(ret));
    result["return_decimal"] = ret;
    result["process_id"] = device->get_process_id();
    return tool_result_t::ok(
        std::string("Function at ") + sa_format_address(static_cast<uint64_t>(func_addr)) +
        std::string(" returned ") + sa_format_address(static_cast<uint64_t>(ret)), result);
}






tool_result_t driver_protect_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_protect_memory entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_protect_memory", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(std::string("Address is required"));

    std::uint64_t size = 0x1000;
    if (params.contains("size")) {
        if (params["size"].is_string())
            size = sa_parse_address(params["size"].get<std::string>()).value_or(0x1000);
        else
            size = params["size"].get<std::uint64_t>();
    }
    if (size == 0)
        return tool_result_t::error(std::string("Size is required"));

    std::uint32_t new_protect = 0x40;
    if (params.contains("protect")) {
        if (params["protect"].is_string())
            new_protect = static_cast<std::uint32_t>(sa_parse_address(params["protect"].get<std::string>()).value_or(0x40));
        else
            new_protect = params["protect"].get<std::uint32_t>();
    }

    if (auto reject = reject_full_test_system_mutation(address, size, "driver_protect_memory"))
        return *reject;

    std::uint32_t old_protect = 0;
    if (!device->protect_memory(address, size, new_protect, &old_protect))
        return tool_result_t::error(std::string("Failed to change protection at ") + sa_format_address(static_cast<uint64_t>(address)));

    json result;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["size"] = sa_format_address(static_cast<uint64_t>(size));
    result["new_protect"] = new_protect;
    result["old_protect"] = old_protect;
    return tool_result_t::ok(std::string("Memory protection changed"), result);
}


tool_result_t driver_read_peb(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_peb entry");
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_read_peb", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    voyager::device_t::peb_info info{};
    if (!device->read_peb(info))
        return tool_result_t::error(std::string("Failed to read PEB"));

    json result;
    result["peb_address"] = sa_format_address(static_cast<uint64_t>(info.peb_address));
    result["image_base"] = sa_format_address(static_cast<uint64_t>(info.image_base));
    result["being_debugged"] = info.being_debugged ? true : false;
    result["nt_global_flag"] = sa_format_address(static_cast<uint64_t>(info.nt_global_flag));
    result["ldr_address"] = sa_format_address(static_cast<uint64_t>(info.ldr_address));
    result["process_heap"] = sa_format_address(static_cast<uint64_t>(info.process_heap));
    result["number_of_heaps"] = info.number_of_heaps;
    result["max_heaps"] = info.max_heaps;
    result["process_heaps"] = sa_format_address(static_cast<uint64_t>(info.process_heaps));
    return tool_result_t::ok(std::string("PEB info for PID ") + std::to_string(device->get_process_id()), result);
}


tool_result_t driver_set_hw_breakpoint(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_set_hw_breakpoint entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_set_hw_breakpoint", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(std::string("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0) return tool_result_t::error(std::string("Address is required"));

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    int type = 0;
    if (params.contains("type")) {
        std::string t = params["type"].get<std::string>();
        if (t == "write") type = 1;
        else if (t == "readwrite" || t == "rw") type = 3;
        else type = 0;
    }

    int size = 0;
    if (params.contains("size")) {
        int s = params["size"].get<int>();
        if (s == 2) size = 1;
        else if (s == 4) size = 3;
        else if (s == 8) size = 2;
        else size = 0;
    }

    if (!device->set_hardware_breakpoint(tid, index, address, type, size))
        return tool_result_t::error(std::string("Failed to set hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["type"] = (type == 0) ? "execute" : (type == 1) ? "write" : "readwrite";
    return tool_result_t::ok(std::string("Hardware breakpoint set on DR") + std::to_string(index), result);
}

tool_result_t driver_clear_hw_breakpoint(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_clear_hw_breakpoint entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_clear_hw_breakpoint", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(std::string("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    if (!device->clear_hardware_breakpoint(tid, index))
        return tool_result_t::error(std::string("Failed to clear hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    return tool_result_t::ok(std::string("Hardware breakpoint cleared on DR") + std::to_string(index), result);
}

tool_result_t driver_resolve_export(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_resolve_export entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_resolve_export", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::string export_name;
    if (params.contains("name") && params["name"].is_string())
        export_name = trim_ascii_copy(params["name"].get<std::string>());
    else if (params.contains("export_name") && params["export_name"].is_string())
        export_name = trim_ascii_copy(params["export_name"].get<std::string>());

    if (export_name.empty())
        return tool_result_t::error(std::string("Export name is required. Use name='GetTickCount' (alias export_name is supported)."));

    std::uint64_t module_base = 0;
    std::string resolved_module_name;
    std::string module_query;
    bool explicit_module_param = false;

    if (params.contains("module_base") && params["module_base"].is_string())
    {
        explicit_module_param = true;
        module_base = sa_parse_address(params["module_base"].get<std::string>()).value_or(0);
    }

    if (module_base == 0 && params.contains("module"))
    {
        explicit_module_param = true;
        if (params["module"].is_string())
            module_query = trim_ascii_copy(params["module"].get<std::string>());
    }

    if (module_base == 0 && module_query.empty() && params.contains("module_name") && params["module_name"].is_string())
    {
        explicit_module_param = true;
        module_query = trim_ascii_copy(params["module_name"].get<std::string>());
    }

    if (module_base == 0 && !module_query.empty())
    {
        if (auto parsed = sa_parse_address(module_query))
            module_base = static_cast<std::uint64_t>(*parsed);
        else if (!resolve_loaded_module_base(module_query, module_base, resolved_module_name))
            return tool_result_t::error(std::string("Could not resolve module '") + module_query +
                std::string("'. Provide module_base='0x...' or a loaded module name/path."));
    }

    if (module_base == 0)
        module_base = device->get_base_address();
    if (module_base == 0)
        return tool_result_t::error(std::string("Module base required. Provide module_base or module/module_name."));


    std::uint64_t addr = device->resolve_export(module_base, export_name.c_str());
    if (addr == 0)
    {
        std::string detail = std::string("Export '") + export_name + std::string("' not found in module ") +
            sa_format_address(static_cast<uint64_t>(module_base));
        if (!module_query.empty())
            detail += std::string(" (query: '") + module_query + std::string("')");
        return tool_result_t::error(detail);
    }

    json result;
    result["export_name"] = export_name;
    result["module_base"] = sa_format_address(static_cast<uint64_t>(module_base));
    if (!module_query.empty())
        result["module_query"] = module_query;
    if (!resolved_module_name.empty())
        result["resolved_module_name"] = resolved_module_name;
    result["explicit_module_param"] = explicit_module_param;
    result["resolved_address"] = sa_format_address(static_cast<uint64_t>(addr));
    return tool_result_t::ok(std::string("Export resolved: ") + export_name + std::string(" -> ") + sa_format_address(static_cast<uint64_t>(addr)), result);
}

tool_result_t driver_virtual_to_physical(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_virtual_to_physical entry");
    if (!device->is_connected() || device->get_dtb() == 0)
        return tool_result_t::error(std::string("Driver not connected or DTB not solved"));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_virtual_to_physical", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::uint64_t vaddr = 0;
    if (params.contains("address"))
        vaddr = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (vaddr == 0) return tool_result_t::error(std::string("Address is required"));

    std::uint64_t paddr = device->virtual_to_physical(vaddr);
    if (paddr == 0)
        return tool_result_t::error(std::string("Translation failed for ") + sa_format_address(static_cast<uint64_t>(vaddr)));

    json result;
    result["virtual_address"] = sa_format_address(static_cast<uint64_t>(vaddr));
    result["physical_address"] = sa_format_address(static_cast<uint64_t>(paddr));
    return tool_result_t::ok(std::string("Virtual -> Physical translation"), result);
}


#ifndef idaapi
#define idaapi
#endif
#ifndef _SSIZE_T_DEFINED
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif
struct exec_request_t
{
    virtual ssize_t idaapi execute() { return 0; }
    virtual ~exec_request_t() = default;
};
static constexpr int MFF_READ  = 0;
static constexpr int MFF_WRITE = 1;
inline int execute_sync(exec_request_t& req, int )
{

    return static_cast<int>(req.execute());
}

enum class deferred_status
{
    pending,
    watching,
    triggered,
    completed,
    failed,
    cancelled,
    timed_out
};

struct deferred_action_result_t
{
    std::string action_type;
    bool        success = false;
    std::string message;
    json        data;
};

struct deferred_action_t
{
    struct queued_tool_call_t
    {
        std::string tool_name;
        json        params;
    };

    int                                     id = 0;
    std::chrono::steady_clock::time_point   created;
    std::chrono::steady_clock::time_point   triggered_at;
    std::string                             condition_type;
    std::string                             target_name;
    int                                     timeout_seconds   = 300;
    int                                     poll_interval_ms  = 50;
    std::vector<queued_tool_call_t>         tool_calls;
    std::vector<deferred_action_result_t>   results;
    std::atomic<deferred_status>            status{deferred_status::pending};
    std::atomic<bool>                       watcher_done{true};
    std::string                             trigger_info;
    std::string                             error;
};

struct deferred_action_snapshot_t
{
    int                                     id = 0;
    std::string                             condition_type;
    std::string                             target_name;
    int                                     timeout_seconds = 0;
    std::vector<deferred_action_t::queued_tool_call_t> tool_calls;
    std::vector<deferred_action_result_t>   results;
    deferred_status                         status = deferred_status::pending;
    std::string                             trigger_info;
    std::string                             error;
};

class DeferredActionManager
{
public:
    static DeferredActionManager& instance();
    ~DeferredActionManager();

    void shutdown();
    int  register_action(std::unique_ptr<deferred_action_t> action, bool& watcher_started, std::string* watcher_error = nullptr);
    bool cancel_action(int id);
    bool get_action_snapshot(int id, deferred_action_snapshot_t& out) const;
    std::vector<deferred_action_snapshot_t> get_all_action_snapshots() const;

    bool poll_kernel_module_load(const std::string& target,
                                 std::uint64_t& out_base,
                                 std::uint32_t& out_size,
                                 std::string& out_name,
                                 std::string& out_path,
                                 std::string* out_error = nullptr,
                                 json* out_diagnostics = nullptr,
                                 bool* out_dependency_blocked = nullptr);
    bool poll_process_start(const std::string& target, std::uint32_t& out_pid);

private:
    DeferredActionManager() = default;
    void watcher_thread_func(int action_id);
    void execute_deferred_tools(deferred_action_t& action, const json& context);
    std::string resolve_template(const std::string& value, const json& context);
    json resolve_params(const json& params, const json& context);

    std::map<int, std::unique_ptr<deferred_action_t>> _actions;
    mutable std::mutex                                _mutex;
    int                                               _next_id = 1;
    std::atomic<bool>                                 _shutdown{false};
};


static const std::vector<mcp_standalone::tool_def_t>* s_deferred_tool_list = nullptr;

static const mcp_standalone::tool_def_t* get_deferred_tool_def(const std::string& name)
{
    if (!s_deferred_tool_list) return nullptr;
    for (const auto& t : *s_deferred_tool_list)
        if (t.name == name && t.visibility != mcp_standalone::tool_visibility_t::ide_chat_only) return &t;
    return nullptr;
}

static tool_result_t execute_deferred_tool(const std::string& name, const json& params)
{
    const auto* def = get_deferred_tool_def(name);
    if (!def)
        return tool_result_t::error(std::string("Unknown deferred tool: ") + name);
    return def->handler(params);
}


DeferredActionManager& DeferredActionManager::instance()
{
    static DeferredActionManager mgr;
    return mgr;
}

DeferredActionManager::~DeferredActionManager()
{
    shutdown();
}

void DeferredActionManager::shutdown()
{
    _shutdown.store(true);
    std::vector<deferred_action_t*> actions_snapshot;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (auto& [id, action] : _actions)
        {
            auto st = action->status.load();
            if (st == deferred_status::pending || st == deferred_status::watching)
                action->status.store(deferred_status::cancelled);
            actions_snapshot.push_back(action.get());
        }
    }
    for (deferred_action_t* action : actions_snapshot)
    {
        while (!action->watcher_done.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int DeferredActionManager::register_action(std::unique_ptr<deferred_action_t> action, bool& watcher_started, std::string* watcher_error)
{
    watcher_started = false;
    if (watcher_error)
        watcher_error->clear();
    int id = 0;
    action->id = id;
    action->created = std::chrono::steady_clock::now();
    action->status.store(deferred_status::pending);
    action->watcher_done.store(false, std::memory_order_release);

    deferred_action_t* action_ptr = action.get();
    {
        std::lock_guard<std::mutex> lock(_mutex);
        id = _next_id++;
        action_ptr->id = id;
        _actions[id] = std::move(action);
    }

    bool posted = false;
    try
    {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "driver_tools";
        sub.label = "driver_tools.deferred_watcher";
        sub.thread_class = "blocking_deferred_watcher";
        sub.domain = aida::infra::executor::domain_t::long_running;
        sub.priority = 3;
        sub.body = [this, id, action_ptr]() {
            const DWORD tid = GetCurrentThreadId();
            const ULONGLONG start_ms = GetTickCount64();
            diag::log_tagged_fmt("drv_tools",
                "deferred_watcher_enter id=%d pid=%lu tid=%lu",
                id,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(tid));
            try
            {
                watcher_thread_func(id);
            }
            catch (const std::exception& ex)
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action_ptr->status.store(deferred_status::failed);
                action_ptr->error = std::string("Deferred watcher escaped exception: ") + ex.what();
            }
            catch (...)
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action_ptr->status.store(deferred_status::failed);
                action_ptr->error = "Deferred watcher escaped unknown exception";
            }
            diag::log_tagged_fmt("drv_tools",
                "deferred_watcher_exit id=%d tid=%lu status=%d elapsed_ms=%llu",
                id,
                static_cast<unsigned long>(tid),
                static_cast<int>(action_ptr->status.load()),
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            action_ptr->watcher_done.store(true, std::memory_order_release);
        };
        posted = aida::infra::executor::submit(std::move(sub)).submitted;
    }
    catch (...)
    {
        posted = false;
    }

    if (posted)
    {
        watcher_started = true;
        const auto qs = aida::infra::taskflow_runtime::active_snapshot();
        diag::log_tagged_fmt("drv_tools",
            "deferred_watcher_posted id=%d runtime_accepting=%d runtime_shutdown=%d service_pending=%llu service_active=%u total_submitted=%llu total_failed=%llu",
            id,
            qs.accepting ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            static_cast<unsigned long long>(qs.service_queue_pending),
            static_cast<unsigned>(qs.service_queue_active),
            static_cast<unsigned long long>(qs.total_submitted),
            static_cast<unsigned long long>(qs.total_failed));
    }
    else
    {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            action_ptr->status.store(deferred_status::failed);
            action_ptr->error = "Deferred watcher executor submit failed";
        }
        action_ptr->watcher_done.store(true, std::memory_order_release);
        const auto qs = aida::infra::taskflow_runtime::active_snapshot();
        diag::log_tagged_fmt("drv_tools",
            "deferred_watcher_post_failed id=%d runtime_accepting=%d runtime_shutdown=%d service_pending=%llu service_active=%u total_submitted=%llu total_rejected=%llu",
            id,
            qs.accepting ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            static_cast<unsigned long long>(qs.service_queue_pending),
            static_cast<unsigned>(qs.service_queue_active),
            static_cast<unsigned long long>(qs.total_submitted),
            static_cast<unsigned long long>(qs.total_rejected));
    }

    if (!watcher_started)
    {
        if (watcher_error)
            *watcher_error = action_ptr->error.empty() ? std::string("Deferred watcher executor submit failed") : action_ptr->error;
        std::lock_guard<std::mutex> lock(_mutex);
        _actions.erase(id);
        diag::log_tagged_fmt("drv_tools", "deferred_watcher_registration_removed_after_post_failure id=%d", id);
        return 0;
    }

    return id;
}

bool DeferredActionManager::cancel_action(int id)
{
    std::unique_lock<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    if (it == _actions.end())
        return false;

    auto st = it->second->status.load();
    if (st == deferred_status::pending || st == deferred_status::watching)
    {
        it->second->status.store(deferred_status::cancelled);
        deferred_action_t* action_ptr = it->second.get();
        lock.unlock();
        while (!action_ptr->watcher_done.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return true;
    }
    return false;
}

static deferred_action_snapshot_t make_deferred_action_snapshot(const deferred_action_t& action)
{
    deferred_action_snapshot_t snapshot;
    snapshot.id = action.id;
    snapshot.condition_type = action.condition_type;
    snapshot.target_name = action.target_name;
    snapshot.timeout_seconds = action.timeout_seconds;
    snapshot.tool_calls = action.tool_calls;
    snapshot.results = action.results;
    snapshot.status = action.status.load();
    snapshot.trigger_info = action.trigger_info;
    snapshot.error = action.error;
    return snapshot;
}

bool DeferredActionManager::get_action_snapshot(int id, deferred_action_snapshot_t& out) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    if (it == _actions.end())
        return false;
    out = make_deferred_action_snapshot(*it->second);
    return true;
}

std::vector<deferred_action_snapshot_t> DeferredActionManager::get_all_action_snapshots() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<deferred_action_snapshot_t> result;
    result.reserve(_actions.size());
    for (const auto& [id, action] : _actions)
        result.push_back(make_deferred_action_snapshot(*action));
    return result;
}

bool DeferredActionManager::poll_kernel_module_load(
    const std::string& target,
    std::uint64_t& out_base,
    std::uint32_t& out_size,
    std::string& out_name,
    std::string& out_path,
    std::string* out_error,
    json* out_diagnostics,
    bool* out_dependency_blocked)
{
    if (out_error)
        out_error->clear();
    if (out_diagnostics)
        *out_diagnostics = json::object();
    if (out_dependency_blocked)
        *out_dependency_blocked = false;

    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(buf, info, err, &query_diag))
    {
        const std::string diag_json = kernel_module_query_diagnostics_json(query_diag).dump();
        if (out_error)
            *out_error = err;
        if (out_diagnostics)
            *out_diagnostics = kernel_module_query_diagnostics_json(query_diag);
        if (out_dependency_blocked)
            *out_dependency_blocked = query_diag.dependency_blocked;
        diag::log_tagged_fmt("drv_tools",
            "poll_kernel_module_load query_failed target=%s err=%s dependency_blocked=%d diag=%s",
            target.c_str(),
            err.c_str(),
            query_diag.dependency_blocked ? 1 : 0,
            diag_json.c_str());
        return false;
    }

    std::string lower_target = target;
    std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& m = info->Modules[i];
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));
        std::string full_path(reinterpret_cast<const char*>(m.FullPathName));

        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (lower_name == lower_target || lower_name.find(lower_target) != std::string::npos)
        {
            out_base = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            out_size = m.ImageSize;
            out_name = name;
            out_path = full_path;
            diag::log_tagged_fmt("drv_tools",
                "poll_kernel_module_load match target=%s name=%s base=0x%llX size=0x%X count=%lu zero_bases=%zu",
                target.c_str(),
                name.c_str(),
                static_cast<unsigned long long>(out_base),
                static_cast<unsigned>(out_size),
                static_cast<unsigned long>(info->NumberOfModules),
                query_diag.zero_base_count);
            return true;
        }
    }
    const std::string samples = module_sample_text(query_diag.samples);
    diag::log_tagged_fmt("drv_tools",
        "poll_kernel_module_load not_found target=%s count=%lu samples=%s zero_bases=%zu nonzero_bases=%zu",
        target.c_str(),
        static_cast<unsigned long>(info->NumberOfModules),
        samples.empty() ? "<none>" : samples.c_str(),
        query_diag.zero_base_count,
        query_diag.nonzero_base_count);
    return false;
}

bool DeferredActionManager::poll_process_start(
    const std::string& target,
    std::uint32_t& out_pid)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(snapshot, &entry))
    {
        do {
            std::string exe_name;
            for (int i = 0; entry.szExeFile[i]; i++)
                exe_name.push_back(static_cast<char>(entry.szExeFile[i]));

            std::string lower_exe = exe_name;
            std::string lower_target = target;
            std::transform(lower_exe.begin(), lower_exe.end(), lower_exe.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (lower_exe == lower_target || lower_exe.find(lower_target) != std::string::npos)
            {
                out_pid = entry.th32ProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

std::string DeferredActionManager::resolve_template(const std::string& value, const json& context)
{
    std::string result = value;

    auto replace_all = [&](const std::string& placeholder, const std::string& replacement) {
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos)
        {
            result.replace(pos, placeholder.size(), replacement);
            pos += replacement.size();
        }
    };

    if (context.contains("module_base"))
        replace_all("${module_base}", context["module_base"].get<std::string>());
    if (context.contains("module_size"))
        replace_all("${module_size}", context["module_size"].get<std::string>());
    if (context.contains("module_name"))
        replace_all("${module_name}", context["module_name"].get<std::string>());
    if (context.contains("pid"))
        replace_all("${pid}", context["pid"].get<std::string>());
    if (context.contains("base_address"))
        replace_all("${base_address}", context["base_address"].get<std::string>());


    static const std::regex offset_re("0x([0-9A-Fa-f]+)\\+0x([0-9A-Fa-f]+)");
    std::smatch match;
    if (std::regex_match(result, match, offset_re))
    {
        std::uint64_t base_val = std::stoull(match[1].str(), nullptr, 16);
        std::uint64_t offset_val = std::stoull(match[2].str(), nullptr, 16);
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << (base_val + offset_val);
        result = ss.str();
    }

    return result;
}

json DeferredActionManager::resolve_params(const json& params, const json& context)
{
    if (params.is_string())
        return resolve_template(params.get<std::string>(), context);

    if (params.is_object())
    {
        json resolved = json::object();
        for (auto it = params.begin(); it != params.end(); ++it)
            resolved[it.key()] = resolve_params(it.value(), context);
        return resolved;
    }

    if (params.is_array())
    {
        json resolved = json::array();
        for (const auto& item : params)
            resolved.push_back(resolve_params(item, context));
        return resolved;
    }

    return params;
}

void DeferredActionManager::execute_deferred_tools(deferred_action_t& action, const json& context)
{
    std::vector<deferred_action_t::queued_tool_call_t> tool_calls;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        tool_calls = action.tool_calls;
    }
    std::vector<deferred_action_result_t> results;


    struct deferred_exec_request_t : public exec_request_t
    {
        std::string tool_name;
        json params;
        tool_result_t tool_result;

        ssize_t idaapi execute() override
        {
            tool_result = execute_deferred_tool(tool_name, params);
            return 0;
        }
    };

    for (const auto& tc : tool_calls)
    {
        json resolved_params = resolve_params(tc.params, context);
        deferred_action_result_t result;
        result.action_type = tc.tool_name;

        try
        {
            const auto* tool_def = get_deferred_tool_def(tc.tool_name);
            int mff_flag = (tool_def && tool_def->read_only) ? MFF_READ : MFF_WRITE;

            deferred_exec_request_t req;
            req.tool_name = tc.tool_name;
            req.params = resolved_params;


            execute_sync(req, mff_flag);

            result.success = req.tool_result.success;
            result.message = req.tool_result.text;
            result.data = req.tool_result.data;
        }
        catch (const std::exception& e)
        {
            result.success = false;
            result.message = std::string("Exception: ") + e.what();
        }

        results.push_back(std::move(result));
    }

    {
        std::lock_guard<std::mutex> lock(_mutex);
        action.results = std::move(results);
    }
}

void DeferredActionManager::watcher_thread_func(int action_id)
{
    deferred_action_t* action = nullptr;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _actions.find(action_id);
        if (it == _actions.end()) return;
        action = it->second.get();
        if (action->status.load() == deferred_status::cancelled)
            return;
        action->status.store(deferred_status::watching);
    }

    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(action->timeout_seconds);
    auto poll_interval = std::chrono::milliseconds(action->poll_interval_ms);

    msg("AiDA: Deferred action #%d watching for %s '%s' (timeout: %ds, poll: %dms)\n",
        action->id, action->condition_type.c_str(), action->target_name.c_str(),
        action->timeout_seconds, action->poll_interval_ms);

    json trigger_context;

    while (!_shutdown.load())
    {
        auto st = action->status.load();
        if (st == deferred_status::cancelled)
        {
            msg("AiDA: Deferred action #%d cancelled\n", action->id);
            return;
        }


        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= timeout)
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action->status.store(deferred_status::timed_out);
                action->error = std::string("Timed out waiting for ") + action->condition_type +
                    std::string(": ") + action->target_name;
            }
            msg("AiDA: Deferred action #%d timed out after %ds\n",
                action->id, action->timeout_seconds);
            return;
        }

        bool condition_met = false;

        if (action->condition_type == "kernel_module_load")
        {
            std::uint64_t base = 0;
            std::uint32_t size = 0;
            std::string name, path;
            std::string poll_error;
            json poll_diagnostics;
            bool dependency_blocked = false;
            if (poll_kernel_module_load(action->target_name, base, size, name, path,
                    &poll_error, &poll_diagnostics, &dependency_blocked))
            {
                condition_met = true;
                std::ostringstream base_ss, size_ss;
                base_ss << "0x" << std::hex << std::uppercase << base;
                size_ss << "0x" << std::hex << std::uppercase << size;

                trigger_context["module_base"] = base_ss.str();
                trigger_context["module_size"] = size_ss.str();
                trigger_context["module_name"] = name;
                trigger_context["module_path"] = path;

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    action->trigger_info = trigger_context.dump();
                }
            }
            else if (dependency_blocked)
            {
                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    action->status.store(deferred_status::failed);
                    action->error = poll_error.empty()
                        ? std::string(std::string("dependency_blocked: kernel module base resolution unavailable"))
                        : poll_error;
                    action->trigger_info = poll_diagnostics.dump();
                }
                const std::string poll_diag_text = poll_diagnostics.dump();
                diag::log_tagged_fmt("drv_tools",
                    "deferred_kernel_module_load dependency_blocked action_id=%d target=%s err=%s diag=%s",
                    action->id,
                    action->target_name.c_str(),
                    poll_error.c_str(),
                    poll_diag_text.c_str());
                return;
            }
        }
        else if (action->condition_type == "process_start")
        {
            std::uint32_t pid = 0;
            if (poll_process_start(action->target_name, pid))
            {
                trigger_context["pid"] = std::to_string(pid);


                if (device && !device->is_connected())
                    device->connect();

                if (device && device->is_connected())
                {
                    if (device->clear_process_context() && device->set_process_id(pid)) {
                        condition_met = true;
                        std::uint64_t img_base = device->find_image();
                        device->solve_dtb();

                        std::ostringstream base_ss;
                        base_ss << "0x" << std::hex << std::uppercase << img_base;
                        trigger_context["base_address"] = base_ss.str();
                        trigger_context["pid"] = std::to_string(device->get_process_id());
                    }
                }
                if (!device || !device->is_connected())
                    condition_met = true;

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    action->trigger_info = trigger_context.dump();
                }
            }
        }

        if (condition_met)
        {
            action->triggered_at = std::chrono::steady_clock::now();
            action->status.store(deferred_status::triggered);

            auto trigger_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                action->triggered_at - start_time).count();
            msg("AiDA: Deferred action #%d TRIGGERED! %s '%s' detected after %lldms. "
                "Executing %zu queued tool call(s) IMMEDIATELY...\n",
                action->id, action->condition_type.c_str(), action->target_name.c_str(),
                trigger_elapsed, action->tool_calls.size());


            execute_deferred_tools(*action, trigger_context);

            bool any_failed = false;
            std::vector<deferred_action_result_t> results_snapshot;
            {
                std::lock_guard<std::mutex> lock(_mutex);
                results_snapshot = action->results;
            }
            for (const auto& r : results_snapshot)
            {
                msg("AiDA: Deferred action #%d - %s: %s - %s\n",
                    action->id, r.action_type.c_str(),
                    r.success ? "OK" : "FAIL", r.message.c_str());
                if (!r.success) any_failed = true;
            }

            action->status.store(any_failed ? deferred_status::failed : deferred_status::completed);

            msg("AiDA: Deferred action #%d %s. %zu/%zu actions succeeded.\n",
                action->id,
                any_failed ? "completed with failures" : "completed successfully",
                std::count_if(results_snapshot.begin(), results_snapshot.end(),
                    [](const deferred_action_result_t& r) { return r.success; }),
                results_snapshot.size());

            return;
        }

        std::this_thread::sleep_for(poll_interval);
    }
}


static std::string deferred_status_to_string(deferred_status s)
{
    switch (s)
    {
        case deferred_status::pending:    return "pending";
        case deferred_status::watching:   return "watching";
        case deferred_status::triggered:  return "triggered";
        case deferred_status::completed:  return "completed";
        case deferred_status::failed:     return "failed";
        case deferred_status::cancelled:  return "cancelled";
        case deferred_status::timed_out:  return "timed_out";
        default: return "unknown";
    }
}

tool_result_t driver_defer_action(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_defer_action entry");

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_defer_action", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    json normalized = params;

    if (!normalized.contains("actions") && normalized.contains("action"))
    {
        json one = json::object();
        one["tool"] = normalized["action"];
        one["params"] = normalized.contains("params") ? normalized["params"] : json::object();
        normalized["actions"] = json::array({one});
    }

    if (normalized.contains("actions") && normalized["actions"].is_array())
    {
        for (auto& act : normalized["actions"])
        {
            if (act.is_object() && !act.contains("tool") && act.contains("action"))
                act["tool"] = act["action"];
            if (act.is_object() && !act.contains("params"))
                act["params"] = json::object();
        }
    }

    std::string wait_for;
    if (normalized.contains("wait_for"))
    {
        if (!normalized["wait_for"].is_string())
            return tool_result_t::error(std::string("'wait_for' must be a string enum: 'process_start' or 'kernel_module_load'."));
        wait_for = normalized["wait_for"].get<std::string>();
    }
    if (wait_for.empty())
        return tool_result_t::error(std::string("'wait_for' is required: 'kernel_module_load' or 'process_start'."));

    if (wait_for != "kernel_module_load" && wait_for != "process_start")
        return tool_result_t::error(std::string("Invalid 'wait_for'. Allowed values: 'kernel_module_load', 'process_start'."));

    std::string target;
    if (normalized.contains("target"))
    {
        if (!normalized["target"].is_string())
            return tool_result_t::error(std::string("'target' must be a string (module or process name)."));
        target = normalized["target"].get<std::string>();
    }
    if (target.empty())
        return tool_result_t::error(std::string("'target' is required: module or process name to watch for"));

    int timeout = normalized.value("timeout", 300);
    int poll_interval = normalized.value("poll_interval", 50);

    if (!normalized.contains("actions") || !normalized["actions"].is_array() || normalized["actions"].empty())
        return tool_result_t::error(std::string("'actions' array is required with at least one tool call. Format: [{\"tool\":\"read_memory\",\"params\":{...}}]."));

    auto action = std::make_unique<deferred_action_t>();
    action->condition_type = wait_for;
    action->target_name = target;
    action->timeout_seconds = timeout;
    action->poll_interval_ms = poll_interval;

    for (const auto& act : normalized["actions"])
    {
        if (!act.contains("tool") || !act["tool"].is_string())
            return tool_result_t::error(std::string("Each action must have a string 'tool' field (full tool name, e.g. 'read_memory')."));

        deferred_action_t::queued_tool_call_t tc;
        tc.tool_name = act["tool"].get<std::string>();
        tc.params = act.contains("params") ? act["params"] : json::object();


        if (!get_deferred_tool_def(tc.tool_name))
            return tool_result_t::error(std::string("Unknown tool: ") + tc.tool_name);

        action->tool_calls.push_back(std::move(tc));
    }


    bool already_met = false;
    if (wait_for == "kernel_module_load")
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        std::string name, path;
        std::string poll_error;
        json poll_diagnostics;
        bool dependency_blocked = false;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_kernel_module_load(target, base, size, name, path,
                &poll_error, &poll_diagnostics, &dependency_blocked))
            already_met = true;
        else if (dependency_blocked)
        {
            const std::string error_text = poll_error.empty()
                ? std::string(std::string("dependency_blocked: kernel module base resolution unavailable"))
                : poll_error;
            return tool_result_t::error(error_text, std::string("dependency_blocked"), poll_diagnostics);
        }
    }
    else if (wait_for == "process_start")
    {
        std::uint32_t pid = 0;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_process_start(target, pid))
            already_met = true;
    }

    const std::size_t queued_actions = action->tool_calls.size();
    bool watcher_started = false;
    std::string watcher_error;
    int action_id = DeferredActionManager::instance().register_action(std::move(action), watcher_started, &watcher_error);
    if (action_id == 0 || !watcher_started)
    {
        if (watcher_error.empty())
            watcher_error = "Deferred watcher thread start failed";
        diag::log_tagged_fmt("drv_tools", "driver_defer_action watcher_start_unavailable target='%s' err='%s'", target.c_str(), watcher_error.c_str());
        return tool_result_t::error(watcher_error);
    }
    deferred_action_snapshot_t registered_action;
    const bool have_registered_action = DeferredActionManager::instance().get_action_snapshot(action_id, registered_action);

    json result;
    result["action_id"] = action_id;
    result["condition"] = wait_for;
    result["target"] = target;
    result["timeout_seconds"] = timeout;
    result["poll_interval_ms"] = poll_interval;
    result["num_queued_actions"] = queued_actions;
    result["watcher_started"] = watcher_started;
    if (have_registered_action && registered_action.status == deferred_status::failed)
    {
        result["status"] = "failed";
        result["error"] = registered_action.error;
        return tool_result_t::error(std::string("Deferred action #") + std::to_string(action_id) +
            std::string(" watcher failed to start: ") + registered_action.error);
    }
    result["status"] = already_met ? "target_already_loaded_executing_now" : "watching";
    result["note"] = already_met
        ? std::string("Target '") + target + std::string("' is ALREADY loaded! Actions are being executed immediately.")
        : std::string("Background watcher started. Actions will execute THE INSTANT '") + target +
          std::string("' loads. Use driver_get_deferred_results with action_id=") +
          std::to_string(action_id) + std::string(" to check results.");

    return tool_result_t::ok(
        already_met
            ? std::string("Deferred action #") + std::to_string(action_id) + std::string(" - target already loaded, executing immediately!")
            : std::string("Deferred action #") + std::to_string(action_id) + std::string(" registered - watching for '") + target + "'",
        result);
}

tool_result_t driver_list_deferred_actions(const json&)
{
    diag::log_tagged_fmt("drv_tools", "driver_list_deferred_actions entry");
    auto actions = DeferredActionManager::instance().get_all_action_snapshots();

    json arr = json::array();
    for (const auto& action : actions)
    {
        json entry;
        entry["id"] = action.id;
        entry["condition"] = action.condition_type;
        entry["target"] = action.target_name;
        entry["status"] = deferred_status_to_string(action.status);
        entry["num_actions"] = action.tool_calls.size();
        entry["timeout_seconds"] = action.timeout_seconds;

        if (!action.trigger_info.empty())
        {
            try { entry["trigger_info"] = json::parse(action.trigger_info); }
            catch (...) { entry["trigger_info"] = action.trigger_info; }
        }

        if (!action.error.empty())
            entry["error"] = action.error;

        entry["num_results"] = action.results.size();
        int succeeded = 0;
        for (const auto& r : action.results)
            if (r.success) succeeded++;
        entry["succeeded"] = succeeded;
        entry["failed"] = static_cast<int>(action.results.size()) - succeeded;

        arr.push_back(entry);
    }

    json result;
    result["actions"] = arr;
    result["total"] = arr.size();
    return tool_result_t::ok(
        std::string("Found ") + std::to_string(arr.size()) + std::string(" deferred action(s)"), result);
}

tool_result_t driver_cancel_deferred_action(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_cancel_deferred_action entry");
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(std::string("'action_id' is required"));

    if (DeferredActionManager::instance().cancel_action(id))
    {
        json result;
        result["action_id"] = id;
        result["status"] = "cancelled";
        return tool_result_t::ok(std::string("Deferred action #") + std::to_string(id) + std::string(" cancelled"), result);
    }

    return tool_result_t::error(std::string("Cannot cancel action #") + std::to_string(id) +
        std::string(" - not found or already completed/triggered"));
}

tool_result_t driver_get_deferred_results(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_get_deferred_results entry");
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(std::string("'action_id' is required"));

    deferred_action_snapshot_t action;
    if (!DeferredActionManager::instance().get_action_snapshot(id, action))
        return tool_result_t::error(std::string("Action #") + std::to_string(id) + std::string(" not found"));

    json result;
    result["action_id"] = action.id;
    result["condition"] = action.condition_type;
    result["target"] = action.target_name;
    result["status"] = deferred_status_to_string(action.status);

    if (!action.trigger_info.empty())
    {
        try { result["trigger_info"] = json::parse(action.trigger_info); }
        catch (...) { result["trigger_info"] = action.trigger_info; }
    }

    if (!action.error.empty())
        result["error"] = action.error;

    json results_arr = json::array();
    for (const auto& r : action.results)
    {
        json rj;
        rj["tool"] = r.action_type;
        rj["success"] = r.success;
        rj["message"] = r.message;
        if (!r.data.is_null() && !r.data.empty())
            rj["data"] = r.data;
        results_arr.push_back(rj);
    }
    result["results"] = results_arr;

    int succeeded = 0;
    for (const auto& r : action.results)
        if (r.success) succeeded++;
    result["succeeded"] = succeeded;
    result["failed"] = static_cast<int>(action.results.size()) - succeeded;
    result["total_actions"] = action.tool_calls.size();

    std::string status_str = deferred_status_to_string(action.status);
    return tool_result_t::ok(
        std::string("Deferred action #") + std::to_string(id) + std::string(": ") + status_str, result);
}


static std::string reg_index_to_name(std::uint32_t idx) {
    static const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    if (idx < 16) return names[idx];
    return "reg" + std::to_string(idx);
}

static json sniff_captures_to_json(const std::vector<voyager::device_t::sniff_result>& captures)
{
    json arr = json::array();
    for (const auto& cap : captures) {
        json c;
        c["timestamp"] = cap.timestamp;
        c["thread_id"] = sa_format_address(static_cast<uint64_t>(cap.thread_id));
        c["size"] = cap.buffer.size();
        std::string hex;
        std::size_t show = (cap.buffer.size() < 256) ? cap.buffer.size() : 256;
        for (std::size_t i = 0; i < show; i++) {
            char hb[4];
            qsnprintf(hb, sizeof(hb), "%02X ", cap.buffer[i]);
            hex += hb;
            if ((i + 1) % 16 == 0) hex += "\n";
        }
        if (show < cap.buffer.size())
            hex += "... (" + std::to_string(cap.buffer.size() - show) + " more)";
        c["hex_dump"] = hex;
        std::string ascii;
        for (std::size_t i = 0; i < show; i++) {
            char ch = static_cast<char>(cap.buffer[i]);
            ascii += (ch >= 0x20 && ch < 0x7F) ? ch : '.';
        }
        c["ascii"] = ascii;
        arr.push_back(std::move(c));
    }
    return arr;
}

tool_result_t driver_sniff_network_buffers(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_sniff_network_buffers entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_sniff_network_buffers", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;


    if (params.contains("operation")) {
        std::string op = params["operation"].get<std::string>();

        if (op == "stop") {
            bool active_before = false;
            auto captures = device->sniff_net_buffers_get(active_before);
            if (!device->sniff_net_buffers_stop())
                return tool_result_t::error(std::string("Failed to stop sniff session"));
            bool active_after = false;
            (void)device->sniff_net_buffers_get(active_after);
            json result;
            result["operation"] = "stop";
            result["stopped"] = true;
            result["active"] = active_after;
            result["active_before_stop"] = active_before;
            result["capture_count"] = captures.size();
            result["captures"] = sniff_captures_to_json(captures);
            result["driver_error"] = driver_bridge::last_error();
            return tool_result_t::ok(std::string("Sniff session stopped"), result);
        }
        if (op == "store") {
            const json* bytes_value = nullptr;
            if (params.contains("bytes")) bytes_value = &params["bytes"];
            else if (params.contains("data")) bytes_value = &params["data"];
            else if (params.contains("hex")) bytes_value = &params["hex"];
            if (!bytes_value)
                return tool_result_t::error(std::string("'bytes', 'data', or 'hex' is required for store operation"));
            std::vector<std::uint8_t> bytes;
            std::string parse_error;
            if (!parse_byte_sequence(*bytes_value, bytes, parse_error))
                return tool_result_t::error(std::string("Invalid capture bytes: ") + parse_error);
            std::uint64_t timestamp = GetTickCount64();
            if (params.contains("timestamp")) {
                if (params["timestamp"].is_number_unsigned())
                    timestamp = params["timestamp"].get<std::uint64_t>();
                else if (params["timestamp"].is_number_integer())
                    timestamp = static_cast<std::uint64_t>(params["timestamp"].get<std::int64_t>());
                else if (params["timestamp"].is_string())
                    timestamp = sa_parse_address(params["timestamp"].get<std::string>()).value_or(timestamp);
            }
            std::uint64_t thread_id = GetCurrentThreadId();
            if (params.contains("thread_id")) {
                if (params["thread_id"].is_number_unsigned())
                    thread_id = params["thread_id"].get<std::uint64_t>();
                else if (params["thread_id"].is_number_integer())
                    thread_id = static_cast<std::uint64_t>(params["thread_id"].get<std::int64_t>());
                else if (params["thread_id"].is_string())
                    thread_id = sa_parse_address(params["thread_id"].get<std::string>()).value_or(thread_id);
            }
            if (!device->sniff_net_buffers_store(timestamp, thread_id, bytes.data(), static_cast<std::uint32_t>(bytes.size())))
                return tool_result_t::error(std::string("Failed to store sniff capture"));
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);
            json result;
            result["operation"] = "store";
            result["stored"] = true;
            result["active"] = active;
            result["capture_count"] = captures.size();
            result["stored_size"] = bytes.size();
            result["captures"] = sniff_captures_to_json(captures);
            result["driver_error"] = driver_bridge::last_error();
            return tool_result_t::ok(std::string("Sniff capture stored"), result);
        }
        if (op == "get" || op == "results") {
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);
            diag::log_tagged_fmt("drv_tools", "driver_sniff_network_buffers get active=%d captures=%zu",
                active ? 1 : 0, captures.size());

            json result;
            result["active"] = active;
            result["capture_count"] = captures.size();
            result["captures"] = sniff_captures_to_json(captures);

            return tool_result_t::ok(
                std::to_string(captures.size()) + std::string(" capture(s) retrieved"), result);
        }
    }


    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(std::string("Address of send/recv/encrypt function required"));


    auto reg_name_to_index = [](const std::string& name) -> std::uint32_t {
        static const std::pair<const char*, std::uint32_t> regs[] = {
            {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
            {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
            {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
            {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}
        };
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& [n, i] : regs)
            if (lower == n) return i;
        return 0;
    };

    std::uint32_t buf_reg = 1;
    if (params.contains("buffer_register"))
        buf_reg = reg_name_to_index(params["buffer_register"].get<std::string>());

    std::uint32_t size_reg = 2;
    if (params.contains("size_register"))
        size_reg = reg_name_to_index(params["size_register"].get<std::string>());

    std::uint32_t max_packets = params.value("max_packets", 1);
    if (max_packets > 16) max_packets = 16;

    std::uint32_t tid = 0;
    if (params.contains("tid"))
        tid = params["tid"].get<std::uint32_t>();

    std::uint32_t bp_index = params.value("bp_index", 0);
    if (bp_index > 3) bp_index = 0;

    if (!device->sniff_net_buffers_start(address, buf_reg, size_reg, max_packets, tid, bp_index))
        return tool_result_t::error(std::string("Failed to start sniff session"));
    diag::log_tagged_fmt("drv_tools",
        "driver_sniff_network_buffers start address=0x%llX buf_reg=%u size_reg=%u max_packets=%u tid=%u bp_index=%u",
        static_cast<unsigned long long>(address), buf_reg, size_reg, max_packets, tid, bp_index);

    json result;
    result["status"] = "started";
    result["target_address"] = sa_format_address(static_cast<uint64_t>(address));
    result["buffer_register"] = reg_index_to_name(buf_reg);
    result["size_register"] = reg_index_to_name(size_reg);
    result["max_captures"] = max_packets;
    result["bp_index"] = bp_index;
    result["note"] = std::string("Sniff session initialized. The HW breakpoint must be set separately via "
        "driver_set_hw_breakpoint on the target address. Then poll with operation='get' to retrieve captures. "
        "After each BP hit, read the buffer from memory using read_memory at the register value, "
        "then call this tool with operation='store' to record it.");

    return tool_result_t::ok(std::string("Sniff session started"), result);
}

static bool parse_ip_string(const std::string& ip, std::uint8_t* out16, std::uint32_t* af) {
    std::memset(out16, 0, 16);

    unsigned a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        out16[0] = static_cast<std::uint8_t>(a);
        out16[1] = static_cast<std::uint8_t>(b);
        out16[2] = static_cast<std::uint8_t>(c);
        out16[3] = static_cast<std::uint8_t>(d);
        if (af) *af = 2;
        return true;
    }

    if (ip.find(':') != std::string::npos) {
        if (af) *af = 23;

        unsigned vals[8] = {};
        int count = sscanf(ip.c_str(), "%x:%x:%x:%x:%x:%x:%x:%x",
            &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7]);
        for (int i = 0; i < count && i < 8; i++) {
            out16[i*2]   = static_cast<std::uint8_t>((vals[i] >> 8) & 0xFF);
            out16[i*2+1] = static_cast<std::uint8_t>(vals[i] & 0xFF);
        }
        return count > 0;
    }
    return false;
}

tool_result_t driver_reassemble_stream(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_reassemble_stream entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver not connected"));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_reassemble_stream", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::uint32_t op_code = 3;
    if (operation == "start") op_code = 0;
    else if (operation == "stop") op_code = 1;
    else if (operation == "get" || operation == "get_data") op_code = 2;
    else if (operation == "list") op_code = 3;
    else if (operation == "clear") op_code = 4;

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t pid = params.value("pid", 0u);
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, nullptr);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, nullptr);
    diag::log_tagged_fmt("drv_tools",
        "driver_reassemble_stream request operation=%s op_code=%u src_port=%u dst_port=%u pid=%u has_src_addr=%d has_dst_addr=%d",
        operation.c_str(), op_code, src_port, dst_port, pid,
        params.contains("src_addr") ? 1 : 0, params.contains("dst_addr") ? 1 : 0);

    std::vector<std::uint8_t> data;
    std::uint32_t packets = 0, truncated = 0;
    bool ok = device->stream_reassemble_op(op_code, src_port, dst_port, pid,
                                            src_addr, dst_addr, &data, &packets, &truncated);
    diag::log_tagged_fmt("drv_tools",
        "driver_reassemble_stream result ok=%d operation=%s bytes=%zu packets=%u truncated=%u",
        ok ? 1 : 0, operation.c_str(), data.size(), packets, truncated);
    if (!ok) return tool_result_t::error(std::string("Stream operation failed"));

    json result;
    result["operation"] = operation;
    result["total_packets"] = packets;
    result["stream_size"] = data.size();
    result["empty_evidence"] = data.empty() && packets == 0;
    if (truncated) result["truncated"] = true;
    if (!data.empty()) {
        std::string hex;
        size_t preview = (data.size() > 256) ? 256 : data.size();
        for (size_t i = 0; i < preview; i++) {
            char buf[4];
            qsnprintf(buf, sizeof(buf), "%02X ", data[i]);
            hex += buf;
        }
        result["hex_preview"] = hex;

        std::string ascii;
        for (size_t i = 0; i < preview; i++)
            ascii += (data[i] >= 0x20 && data[i] < 0x7f) ? static_cast<char>(data[i]) : '.';
        result["ascii_preview"] = ascii;
    }

    return tool_result_t::ok(std::string("Stream reassembly ") + operation + std::string(": ") +
        std::to_string(data.size()) + std::string(" bytes, ") + std::to_string(packets) + std::string(" packets"), result);
}

tool_result_t driver_enum_kernel_callbacks(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enum_kernel_callbacks entry");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(std::string("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_enum_kernel_callbacks", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(mod_buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
        return kernel_module_query_error_result(err, query_diag);


    std::uint64_t ntos_base = 0;
    std::uint64_t ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos ||
            lower.find("ntkrnlpa") != std::string::npos || lower.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }

    if (ntos_base == 0)
        return tool_result_t::error(std::string("Could not locate ntoskrnl.exe base via NtQuerySystemInformation"));

    json result;
    result["ntoskrnl_base"] = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["ntoskrnl_size"] = ntos_size;


    struct cb_type {
        const char* name;
        const char* export_name;
        int max_slots;
    };
    cb_type types[] = {
        {"PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutine", 64},
        {"PsSetCreateThreadNotifyRoutine",  "PsSetCreateThreadNotifyRoutine",  64},
        {"PsSetLoadImageNotifyRoutine",     "PsSetLoadImageNotifyRoutine",     64},
        {"CmRegisterCallback",              "CmRegisterCallbackEx",            64},
        {"ObRegisterCallbacks",             "ObRegisterCallbacks",             64},
    };

    json all_callbacks = json::array();
    std::size_t callback_type_exports_resolved = 0;
    std::size_t callback_array_refs_found = 0;
    std::size_t callbacks_observed = 0;
    for (const auto& t : types)
    {
        std::uint64_t fn_addr = device->resolve_export(ntos_base, t.export_name);
        if (fn_addr == 0) continue;
        ++callback_type_exports_resolved;

        json cb;
        cb["type"] = t.name;
        cb["registration_function"] = sa_format_address(static_cast<uint64_t>(fn_addr));


        std::uint8_t code[128] = {};
        device->read_kernel_raw(fn_addr, code, sizeof(code));

        json array_refs = json::array();
        for (int off = 0; off + 7 <= 128; ++off)
        {

            if ((code[off] == 0x48 || code[off] == 0x4C) &&
                code[off + 1] == 0x8D &&
                (code[off + 2] & 0xC7) == 0x05)
            {
                std::int32_t disp;
                std::memcpy(&disp, &code[off + 3], 4);
                std::uint64_t target = fn_addr + off + 7 + disp;

                if (is_probably_kernel_address(target))
                {
                    json ref;
                    ref["array_address"] = sa_format_address(static_cast<uint64_t>(target));
                    ref["instruction_offset"] = off;


                    json entries = json::array();
                    for (int slot = 0; slot < t.max_slots; ++slot)
                    {
                        std::uint64_t entry = 0;
                        device->read_kernel_raw(target + slot * 8, &entry, 8);
                        if (entry == 0) break;


                        std::uint64_t cb_body = entry & ~0xFULL;
                        if (!is_probably_kernel_address(cb_body)) continue;


                        std::uint64_t routine = 0;
                        device->read_kernel_raw(cb_body + 8, &routine, 8);

                        json e;
                        e["slot"]    = slot;
                        e["raw"]     = sa_format_address(static_cast<uint64_t>(entry));
                        e["block"]   = sa_format_address(static_cast<uint64_t>(cb_body));
                        e["routine"] = sa_format_address(static_cast<uint64_t>(routine));


                        if (is_probably_kernel_address(routine))
                        {
                            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                            {
                                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                                if (routine >= mb && routine < me)
                                {
                                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                                    auto slash = fp.find_last_of("\\/");
                                    e["owner_module"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                                    break;
                                }
                            }
                        }
                        entries.push_back(std::move(e));
                    }
                    const std::size_t entry_count = entries.size();
                    ++callback_array_refs_found;
                    callbacks_observed += entry_count;
                    ref["callbacks"] = std::move(entries);
                    ref["count"]     = entry_count;
                    array_refs.push_back(std::move(ref));
                }
            }
        }
        cb["arrays"] = std::move(array_refs);
        all_callbacks.push_back(std::move(cb));
    }

    result["callback_types"] = std::move(all_callbacks);
    const bool callback_enumeration_ran = callback_type_exports_resolved > 0;
    const bool zero_callbacks_clean = callback_enumeration_ran && callback_array_refs_found > 0 && callbacks_observed == 0;
    result["enumeration_ran"] = callback_enumeration_ran;
    result["clean_state"] = zero_callbacks_clean;
    result["zero_is_clean_state"] = zero_callbacks_clean;
    result["proof_count"] = callback_array_refs_found;
    result["callback_type_exports_resolved"] = callback_type_exports_resolved;
    result["callback_array_refs_found"] = callback_array_refs_found;
    result["callbacks_observed"] = callbacks_observed;
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);
    result["note"] = std::string("Kernel callbacks are used by anti-cheats (EAC/BattlEye/Vanguard) to monitor "
                            "process creation, thread creation, image loading, and registry access.");
    return tool_result_t::ok(std::string("Kernel callback enumeration complete"), result);
}


tool_result_t driver_detect_integrity_checks(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_integrity_checks entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(std::string("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_detect_integrity_checks", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(mod_buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
        return kernel_module_query_error_result(err, query_diag);


    std::uint64_t ntos_base = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(std::string("Could not locate ntoskrnl.exe base"));


    static const char* critical_exports[] = {
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",
        "NtCreateThreadEx", "NtDeviceIoControlFile", "NtQuerySystemInformation",
        "NtSetInformationThread", "NtClose", "NtDuplicateObject",
        "MmCopyVirtualMemory", "KeStackAttachProcess", "KeUnstackDetachProcess",
        "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
        "ObOpenObjectByPointer", "MmProbeAndLockPages",
        nullptr
    };

    int critical_export_count_entry = 0;
    for (int idx = 0; critical_exports[idx]; ++idx)
        ++critical_export_count_entry;
    diag::log_tagged_critical_fmt("drv_tools",
        "INTEGRITY_SCAN_ENTER ntoskrnl_base=0x%llX critical_export_count=%d device_pid=%u kernel_dtb=0x%llX",
        static_cast<unsigned long long>(ntos_base),
        critical_export_count_entry,
        device->get_process_id(),
        static_cast<unsigned long long>(device->get_kernel_dtb()));

    json hooks = json::array();
    json clean = json::array();
    int checked = 0;
    const ULONGLONG scan_entry_tick = GetTickCount64();

    for (int fi = 0; critical_exports[fi]; ++fi)
    {
        if (mcp_standalone::current_call_cancelled())
            return tool_result_t::error("Tool cancelled during integrity check scan.");
        std::uint64_t fn = device->resolve_export(ntos_base, critical_exports[fi]);
        if (fn == 0) {
            diag::log_tagged_fmt("drv_tools",
                "INTEGRITY_SCAN_EXPORT name=%s va=0x0 first8=0x0 classification=resolve_failed",
                critical_exports[fi]);
            continue;
        }
        ++checked;


        std::uint8_t bytes[16] = {};
        device->read_kernel_raw(fn, bytes, 16);
        std::uint64_t first8 = 0;
        std::memcpy(&first8, bytes, sizeof(first8));

        std::string hook_type;
        std::uint64_t hook_target = 0;


        if (bytes[0] == 0xE9)
        {
            std::int32_t rel;
            std::memcpy(&rel, &bytes[1], 4);
            hook_target = fn + 5 + rel;
            hook_type = "jmp_rel32";
        }
        else if (bytes[0] == 0xFF && bytes[1] == 0x25)
        {
            std::int32_t disp;
            std::memcpy(&disp, &bytes[2], 4);
            std::uint64_t ptr = fn + 6 + disp;
            device->read_kernel_raw(ptr, &hook_target, 8);
            hook_type = "jmp_indirect_rip";
        }
        else if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
        {
            std::memcpy(&hook_target, &bytes[2], 8);
            hook_type = "mov_rax_jmp_rax";
        }
        else if (bytes[0] == 0xCC)
        {
            hook_type = "int3_breakpoint";
        }

        diag::log_tagged_fmt("drv_tools",
            "INTEGRITY_SCAN_EXPORT name=%s va=0x%llX first8=0x%llX classification=%s",
            critical_exports[fi],
            static_cast<unsigned long long>(fn),
            static_cast<unsigned long long>(first8),
            hook_type.empty() ? "clean" : hook_type.c_str());
        if (!hook_type.empty())
        {
            json h;
            h["function"] = critical_exports[fi];
            h["address"]  = sa_format_address(static_cast<uint64_t>(fn));
            h["hook_type"] = hook_type;
            if (hook_target != 0)
            {
                h["target"] = sa_format_address(static_cast<uint64_t>(hook_target));

                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;
                    if (hook_target >= mb && hook_target < me)
                    {
                        std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                        auto slash = fp.find_last_of("\\/");
                        h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                        break;
                    }
                }
            }
            std::ostringstream hex;
            for (int b = 0; b < 16; ++b) { if (b) hex << " "; hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[b]); }
            h["prologue_bytes"] = hex.str();
            hooks.push_back(std::move(h));
        }
        else
        {
            json c;
            c["function"] = critical_exports[fi];
            c["address"]  = sa_format_address(static_cast<uint64_t>(fn));
            c["status"]   = "clean";
            clean.push_back(std::move(c));
        }
    }

    const std::size_t hook_count = hooks.size();
    const std::size_t clean_count = clean.size();
    const bool integrity_scan_ran = checked > 0;
    const bool zero_hooks_clean = integrity_scan_ran && hook_count == 0 && clean_count == static_cast<std::size_t>(checked);
    int critical_export_count = 0;
    for (int idx = 0; critical_exports[idx]; ++idx)
        ++critical_export_count;
    const ULONGLONG scan_elapsed_us = (GetTickCount64() - scan_entry_tick) * 1000ULL;
    diag::log_tagged_critical_fmt("drv_tools",
        "INTEGRITY_SCAN_EXIT functions_scanned=%d hooks_found=%zu status=0x%08lX elapsed_us=%llu critical_export_count=%d ntoskrnl_base=0x%llX",
        checked,
        hook_count,
        static_cast<unsigned long>(integrity_scan_ran ? 0u : 0xC0000001u),
        static_cast<unsigned long long>(scan_elapsed_us),
        critical_export_count,
        static_cast<unsigned long long>(ntos_base));
    diag::log_tagged_critical_fmt("drv_tools",
        "driver_detect_integrity_checks_done ntos_base=0x%llX critical_export_count=%d functions_scanned=%d hooks_found=%zu clean_count=%zu scan_ran=%d zero_hooks_clean=%d",
        static_cast<unsigned long long>(ntos_base),
        critical_export_count,
        checked,
        hook_count,
        clean_count,
        integrity_scan_ran ? 1 : 0,
        zero_hooks_clean ? 1 : 0);
    if (!integrity_scan_ran) {
        json failure;
        failure["ntoskrnl_base"]            = sa_format_address(static_cast<uint64_t>(ntos_base));
        failure["functions_scanned"]        = checked;
        failure["critical_export_count"]    = critical_export_count;
        failure["hooks_found"]              = hook_count;
        failure["scan_ran"]                 = false;
        failure["module_base_diagnostics"]  = kernel_module_query_diagnostics_json(query_diag);
        failure["reason"]                   = std::string("kernel_scanner_did_not_run: zero critical exports resolved");
        return tool_result_t::error(std::string("driver_detect_integrity_checks: kernel scanner returned 0 functions_scanned (scanner did not run)"), failure);
    }
    json result;
    result["ntoskrnl_base"]     = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["functions_checked"] = checked;
    result["functions_scanned"] = checked;
    result["critical_export_count"] = critical_export_count;
    result["hooks_found"]       = hook_count;
    result["scan_ran"]          = integrity_scan_ran;
    result["clean_state"]       = zero_hooks_clean;
    result["zero_is_clean_state"] = zero_hooks_clean;
    result["proof_count"]       = clean_count;
    result["clean_function_count"] = clean_count;
    result["hooked_functions"]  = std::move(hooks);
    result["clean_functions"]   = std::move(clean);
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);
    result["note"] = std::string("Kernel function hooks indicate anti-cheat monitoring. Hooked functions route through "
                            "the anti-cheat driver, which can block, log, or alter calls from target processes.");
    return tool_result_t::ok(std::string("Kernel integrity: ") + std::to_string(hook_count) +
                             std::string(" hooks in ") + std::to_string(checked) + std::string(" functions"), result);
}


tool_result_t driver_detect_ssdt_hooks(const json&)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(std::string("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_detect_ssdt_hooks", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence)) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks query_kernel_modules_failed err=%s", err.c_str());
        return kernel_module_query_error_result(err, query_diag, std::string("Failed to enumerate kernel modules: "));
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks modules=%lu kernel_dtb=0x%llX",
        static_cast<unsigned long>(info ? info->NumberOfModules : 0),
        static_cast<unsigned long long>(device->get_kernel_dtb()));

    std::uint64_t ntos_base = 0, ntos_size = 0;
    std::string ntos_path;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            ntos_path = reinterpret_cast<const char*>(info->Modules[i].FullPathName);
            break;
        }
    }
    if (ntos_base == 0) {
        for (ULONG i = 0; i < info->NumberOfModules && i < 12; ++i) {
            diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks module[%lu] base=0x%llX size=0x%lX path=%s",
                static_cast<unsigned long>(i),
                static_cast<unsigned long long>(reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase)),
                static_cast<unsigned long>(info->Modules[i].ImageSize),
                reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        }
        return tool_result_t::error(std::string("Could not find ntoskrnl base address"));
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ntos base=0x%llX size=0x%llX path=%s",
        static_cast<unsigned long long>(ntos_base),
        static_cast<unsigned long long>(ntos_size),
        ntos_path.c_str());

    struct ssdt_entry_t {
        std::uint64_t service_table;
        std::uint64_t counter_table;
        std::uint32_t num_services;
        std::uint32_t _pad;
        std::uint64_t param_table;
    };
    ssdt_entry_t ssdt{};

    std::uint64_t ssdt_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTable");
    const bool export_available = (ssdt_addr != 0);
    std::string ssdt_resolution_source = "export";
    std::uint64_t ssdt_lstar = 0;
    std::uint32_t ssdt_flags = 0;

    if (export_available) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ssdt_addr=0x%llX source=export",
            static_cast<unsigned long long>(ssdt_addr));

        size_t ssdt_read = device->read_kernel_raw(ssdt_addr, &ssdt, sizeof(ssdt));
        if (ssdt_read < sizeof(ssdt)) {
            diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks read_ssdt_failed addr=0x%llX read=%zu need=%zu",
                static_cast<unsigned long long>(ssdt_addr), ssdt_read, sizeof(ssdt));
            return tool_result_t::error(std::string("Failed to read SSDT structure"));
        }
    } else {
        std::uint64_t shadow_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTableShadow");
        std::uint64_t nt_close = device->resolve_export(ntos_base, "NtClose");
        std::uint64_t zw_close = device->resolve_export(ntos_base, "ZwClose");
        diag::log_tagged_fmt("drv_tools",
            "driver_detect_ssdt_hooks ssdt_export_missing ntos=0x%llX shadow=0x%llX NtClose=0x%llX ZwClose=0x%llX",
            static_cast<unsigned long long>(ntos_base),
            static_cast<unsigned long long>(shadow_addr),
            static_cast<unsigned long long>(nt_close),
            static_cast<unsigned long long>(zw_close));

        voyager::device_t::ssdt_info query{};
        if (!device->query_ssdt(query)) {
            diag::log_tagged_fmt("drv_tools",
                "driver_detect_ssdt_hooks ssdt_query_failed ntos=0x%llX kernel_dtb=0x%llX",
                static_cast<unsigned long long>(ntos_base),
                static_cast<unsigned long long>(device->get_kernel_dtb()));
            return tool_result_t::error(std::string("Could not resolve SSDT through export or syscall-entry fallback"));
        }

        ssdt_addr = query.descriptor_address;
        ssdt.service_table = query.service_table;
        ssdt.counter_table = query.counter_table;
        ssdt.num_services = query.service_limit;
        ssdt.param_table = query.argument_table;
        ssdt_lstar = query.lstar;
        ssdt_flags = query.flags;
        ssdt_resolution_source = "lstar_syscall_entry";

        diag::log_tagged_fmt("drv_tools",
            "driver_detect_ssdt_hooks ssdt_query_ok lstar=0x%llX desc=0x%llX table=0x%llX counter=0x%llX arg=0x%llX limit=%u flags=0x%X",
            static_cast<unsigned long long>(query.lstar),
            static_cast<unsigned long long>(query.descriptor_address),
            static_cast<unsigned long long>(query.service_table),
            static_cast<unsigned long long>(query.counter_table),
            static_cast<unsigned long long>(query.argument_table),
            query.service_limit,
            query.flags);
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ssdt service_table=0x%llX counter=0x%llX num=%u param=0x%llX",
        static_cast<unsigned long long>(ssdt.service_table),
        static_cast<unsigned long long>(ssdt.counter_table),
        ssdt.num_services,
        static_cast<unsigned long long>(ssdt.param_table));

    if (ssdt.num_services == 0 || ssdt.num_services > 2048) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks invalid_service_count=%u", ssdt.num_services);
        return tool_result_t::error(std::string("Invalid SSDT service count: ") + std::to_string(ssdt.num_services));
    }
    if (!is_probably_kernel_address(ssdt.service_table)) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks invalid_service_table=0x%llX",
            static_cast<unsigned long long>(ssdt.service_table));
        return tool_result_t::error(std::string("ServiceTableBase is not a valid kernel address"));
    }


    std::vector<std::int32_t> entries(ssdt.num_services);
    size_t read_sz = ssdt.num_services * sizeof(std::int32_t);
    size_t entries_read = device->read_kernel_raw(ssdt.service_table, entries.data(), read_sz);
    if (entries_read < read_sz) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks read_entries_failed table=0x%llX read=%zu need=%zu",
            static_cast<unsigned long long>(ssdt.service_table), entries_read, read_sz);
        return tool_result_t::error(std::string("Failed to read SSDT entries"));
    }

    json hooked = json::array();
    json clean_count_json;
    int hooks_found = 0, clean_count = 0;
    std::uint64_t ntos_end = ntos_base + ntos_size;

    for (std::uint32_t i = 0; i < ssdt.num_services; ++i)
    {

        std::uint64_t fn = ssdt.service_table + (static_cast<std::uint64_t>(entries[i]) >> 4);

        bool inside_ntos = (fn >= ntos_base && fn < ntos_end);
        if (!inside_ntos)
        {
            json h;
            h["syscall_id"]    = i;
            h["address"]       = sa_format_address(static_cast<uint64_t>(fn));
            h["status"]        = "hooked";


            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
            {
                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                if (fn >= mb && fn < me)
                {
                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                    auto slash = fp.find_last_of("\\/");
                    h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                    break;
                }
            }
            hooked.push_back(std::move(h));
            ++hooks_found;
        }
        else
        {
            ++clean_count;
        }
    }

    const bool ssdt_scan_ran = entries_read >= read_sz && ssdt.num_services > 0;
    const bool zero_ssdt_hooks_clean = ssdt_scan_ran && hooks_found == 0 && clean_count == static_cast<int>(ssdt.num_services);
    json result;
    result["ssdt_address"]      = sa_format_address(static_cast<uint64_t>(ssdt_addr));
    result["ssdt_descriptor_address"] = sa_format_address(static_cast<uint64_t>(ssdt_addr));
    result["ssdt_resolution_source"] = ssdt_resolution_source;
    result["export_available"] = export_available;
    result["lstar"] = sa_format_address(static_cast<uint64_t>(ssdt_lstar));
    result["ssdt_flags"] = ssdt_flags;
    result["service_table"]     = sa_format_address(static_cast<uint64_t>(ssdt.service_table));
    result["total_services"]    = ssdt.num_services;
    result["hooks_found"]       = hooks_found;
    result["clean_services"]    = clean_count;
    result["scan_ran"]          = ssdt_scan_ran;
    result["clean_state"]       = zero_ssdt_hooks_clean;
    result["zero_is_clean_state"] = zero_ssdt_hooks_clean;
    result["proof_count"]       = clean_count;
    result["entries_read_bytes"] = entries_read;
    result["ntoskrnl_range"]    = sa_format_address(static_cast<uint64_t>(ntos_base)) + " - " +
                                  sa_format_address(static_cast<uint64_t>(ntos_end));
    result["hooked_entries"]    = std::move(hooked);
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);
    result["note"] = std::string("SSDT hooks redirect syscalls to third-party kernel code. Anti-cheats commonly hook "
                            "NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess to intercept memory access.");

    return tool_result_t::ok(std::string("SSDT: ") + std::to_string(hooks_found) + std::string(" hooks in ") +
                             std::to_string(ssdt.num_services) + std::string(" services"), result);
}


tool_result_t driver_enum_minifilters(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enum_minifilters entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(std::string("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_enum_minifilters", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
        return kernel_module_query_error_result(err, query_diag, std::string("Failed to enumerate kernel modules: "));


    std::uint64_t fltmgr_base = 0, fltmgr_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("fltmgr.sys") != std::string::npos)
        {
            fltmgr_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            fltmgr_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (fltmgr_base == 0)
        return tool_result_t::error(std::string("Filter Manager (fltmgr.sys) not found in loaded modules"));


    uint8_t pe_hdr[0x1000];
    std::size_t pe_hdr_read = device->read_kernel_raw(fltmgr_base, pe_hdr, sizeof(pe_hdr));
    if (pe_hdr_read < 0x40) {
        json r;
        r["fltmgr_base"] = sa_format_address(fltmgr_base);
        r["bytes_read"] = static_cast<std::uint64_t>(pe_hdr_read);
        r["bytes_requested"] = static_cast<std::uint64_t>(sizeof(pe_hdr));
        return tool_result_t::error(std::string("fltmgr kernel memory read failed"), r);
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    if (pe_off + 0x18 + 0x70 > sizeof(pe_hdr))
        return tool_result_t::error(std::string("Invalid fltmgr PE header"));

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_off  = pe_off + 24 + opt_hdr_sz;

    std::uint64_t data_rva = 0, data_size = 0;
    for (int s = 0; s < num_sections && (section_off + 40 <= sizeof(pe_hdr)); ++s, section_off += 40)
    {
        char name[9] = {};
        std::memcpy(name, &pe_hdr[section_off], 8);
        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 12]);
        if (std::string(name) == ".data")
        {
            data_rva  = va;
            data_size = vs;
            break;
        }
    }
    if (data_rva == 0)
        return tool_result_t::error(std::string("Could not find fltmgr .data section"));


    std::uint64_t data_addr = fltmgr_base + data_rva;
    size_t scan_sz = static_cast<size_t>(std::min(data_size, std::uint64_t{0x20000}));
    std::vector<uint8_t> data_buf(scan_sz);
    device->read_kernel_raw(data_addr, data_buf.data(), scan_sz);


    json filters = json::array();
    std::set<std::uint64_t> visited;

    for (size_t off = 0; off + 16 <= scan_sz; off += 8)
    {
        std::uint64_t flink = *reinterpret_cast<std::uint64_t*>(&data_buf[off]);
        std::uint64_t blink = *reinterpret_cast<std::uint64_t*>(&data_buf[off + 8]);

        if (!is_probably_kernel_address(flink) || !is_probably_kernel_address(blink)) continue;

        std::uint64_t head = data_addr + off;
        if (flink == head) continue;
        if (visited.count(flink)) continue;


        std::uint64_t cur = flink;
        int walk_count = 0;
        bool valid_chain = true;
        std::vector<std::uint64_t> entries_found;

        while (cur != head && walk_count < 64)
        {
            if (!is_probably_kernel_address(cur)) { valid_chain = false; break; }
            entries_found.push_back(cur);
            visited.insert(cur);


            std::uint64_t next = 0;
            if (device->read_kernel_raw(cur, &next, 8) < 8) { valid_chain = false; break; }
            if (next == cur) { valid_chain = false; break; }
            cur = next;
            ++walk_count;
        }

        if (!valid_chain || entries_found.empty() || walk_count < 1) continue;


        for (auto& entry_addr : entries_found)
        {

            uint8_t block[0x200];
            if (device->read_kernel_raw(entry_addr, block, sizeof(block)) < sizeof(block)) continue;


            for (int noff : {0x28, 0x38, 0x48, 0x58, 0x68, 0x78})
            {
                if (noff + 16 > (int)sizeof(block)) break;
                std::uint16_t len     = *reinterpret_cast<std::uint16_t*>(&block[noff]);
                std::uint16_t max_len = *reinterpret_cast<std::uint16_t*>(&block[noff + 2]);
                std::uint64_t buf_ptr = *reinterpret_cast<std::uint64_t*>(&block[noff + 8]);

                if (len == 0 || len > 512 || max_len < len || !is_probably_kernel_address(buf_ptr)) continue;


                std::vector<wchar_t> name_buf(len / 2 + 1, 0);
                if (device->read_kernel_raw(buf_ptr, name_buf.data(), len) < len) continue;

                std::wstring wname(name_buf.data());
                if (wname.empty()) continue;


                bool looks_valid = true;
                for (auto wc : wname)
                {
                    if (wc == 0) break;
                    if (wc < 0x20 || wc > 0x7E) { looks_valid = false; break; }
                }
                if (!looks_valid) continue;

                std::string name_str;
                for (wchar_t wc : wname) { if (wc == 0) break; name_str += static_cast<char>(wc); }


                std::string altitude_str;
                if (noff + 0x20 + 16 <= (int)sizeof(block))
                {
                    std::uint16_t alen  = *reinterpret_cast<std::uint16_t*>(&block[noff + 0x10]);
                    std::uint64_t abuf  = *reinterpret_cast<std::uint64_t*>(&block[noff + 0x18]);
                    if (alen > 0 && alen <= 64 && is_probably_kernel_address(abuf))
                    {
                        std::vector<wchar_t> abuf_data(alen / 2 + 1, 0);
                        if (device->read_kernel_raw(abuf, abuf_data.data(), alen) >= alen)
                        {
                            std::wstring walt(abuf_data.data());
                            altitude_str.clear();
                            for (wchar_t wc : walt) altitude_str += static_cast<char>(wc);
                        }
                    }
                }

                json f;
                f["address"]  = sa_format_address(static_cast<uint64_t>(entry_addr));
                f["name"]     = name_str;
                if (!altitude_str.empty()) f["altitude"] = altitude_str;


                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;

                    for (int poff = 0; poff + 8 <= (int)sizeof(block); poff += 8)
                    {
                        std::uint64_t ptr = *reinterpret_cast<std::uint64_t*>(&block[poff]);
                        if (ptr >= mb && ptr < me)
                        {
                            std::string mpth(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                            auto slash = mpth.find_last_of("\\/");
                            f["owner_module"] = (slash != std::string::npos) ? mpth.substr(slash + 1) : mpth;
                            goto owner_found;
                        }
                    }
                }
                owner_found:


                bool dup = false;
                for (const auto& existing : filters)
                    if (existing["name"] == name_str) { dup = true; break; }
                if (!dup) filters.push_back(std::move(f));
                break;
            }
        }
    }

    json result;
    result["fltmgr_base"]     = sa_format_address(static_cast<uint64_t>(fltmgr_base));
    result["filter_count"]    = filters.size();
    result["filters"]         = std::move(filters);
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);
    result["note"] = std::string("Minifilter drivers intercept filesystem I/O. Anti-cheats use minifilters to monitor file access, "
                            "prevent dumps, and detect injection DLLs. Altitude determines callback priority order.");

    return tool_result_t::ok(std::string("Minifilters: ") + std::to_string(result["filter_count"].get<std::size_t>()) +
                             std::string(" registered filter drivers"), result);
}


tool_result_t driver_detect_etw_monitors(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_etw_monitors entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(std::string("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_detect_etw_monitors", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    kernel_module_query_diagnostics_t query_diag{};
    if (!query_kernel_modules(buf, info, err, &query_diag,
            kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
        return kernel_module_query_error_result(err, query_diag, std::string("Failed to enumerate kernel modules: "));

    std::uint64_t ntos_base = 0, ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(std::string("Could not find ntoskrnl base address"));


    std::uint64_t etw_threat_intel = device->resolve_export(ntos_base, "EtwThreatIntProvRegHandle");
    std::uint64_t etw_register     = device->resolve_export(ntos_base, "EtwRegister");

    json providers = json::array();
    std::size_t active_provider_count = 0;
    std::size_t known_guid_matches = 0;
    std::size_t etw_sections_scanned = 0;
    std::size_t etw_modules_scanned = 0;


    if (etw_threat_intel != 0)
    {

        std::uint64_t reg_handle = 0;
        device->read_kernel_raw(etw_threat_intel, &reg_handle, 8);

        json ti;
        ti["name"]    = "Microsoft-Windows-Threat-Intelligence";
        ti["address"] = sa_format_address(static_cast<uint64_t>(etw_threat_intel));
        ti["status"]  = (reg_handle != 0) ? "active" : "inactive";
        ti["note"]    = std::string("ETW-TI monitors process injection, executable memory allocation, and other "
                               "security-sensitive operations. Used by EDR and anti-cheat for real-time telemetry.");
        if (reg_handle != 0) {
            ti["reg_handle"] = sa_format_address(static_cast<uint64_t>(reg_handle));
            ++active_provider_count;
        }
        providers.push_back(std::move(ti));
    }


    struct known_guid_t {
        const char* name;
        uint8_t bytes[16];
    };
    static const known_guid_t known_guids[] = {
        {"Microsoft-Windows-Kernel-Audit-API-Calls",
         {0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}},
        {"Microsoft-Windows-Kernel-Process",
         {0x27, 0x09, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}},
    };


    uint8_t pe_hdr[0x1000];
    device->read_kernel_raw(ntos_base, pe_hdr, sizeof(pe_hdr));
    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_tbl  = pe_off + 24 + opt_hdr_sz;

    for (int s = 0; s < num_sections && (section_tbl + 40 <= sizeof(pe_hdr)); ++s, section_tbl += 40)
    {
        char sn[9] = {};
        std::memcpy(sn, &pe_hdr[section_tbl], 8);
        if (std::string(sn) != ".data" && std::string(sn) != ".rdata") continue;

        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 12]);
        std::uint64_t sec_addr = ntos_base + va;
        size_t sec_sz  = std::min(vs, (std::uint32_t)0x100000);

        std::vector<uint8_t> sec_data(sec_sz);
        size_t sec_read = device->read_kernel_raw(sec_addr, sec_data.data(), sec_sz);
        if (sec_read < 16) continue;
        ++etw_sections_scanned;
        const size_t sec_limit = std::min(sec_sz, sec_read);

        for (const auto& g : known_guids)
        {
            for (size_t off = 0; off + 16 <= sec_limit; ++off)
            {
                if (std::memcmp(&sec_data[off], g.bytes, 16) == 0)
                {
                    json prov;
                    prov["name"]    = g.name;
                    prov["address"] = sa_format_address(static_cast<uint64_t>(sec_addr + off));
                    prov["status"]  = "guid_found";
                    providers.push_back(std::move(prov));
                    ++known_guid_matches;
                    break;
                }
            }
        }
    }


    json etw_modules = json::array();
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::uint64_t mod_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        auto slash = fp.find_last_of("\\/");
        std::string mod_name = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;

        std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);

        if (mod_name.find("ntoskrnl") != std::string::npos || mod_name.find("ntkrnl") != std::string::npos ||
            mod_name.find("hal.dll") != std::string::npos || mod_name.find("ci.dll") != std::string::npos ||
            mod_name.find("fltmgr") != std::string::npos || mod_name.find("nt.") != std::string::npos)
            continue;


        uint8_t mod_hdr[0x400];
        if (device->read_kernel_raw(mod_base, mod_hdr, sizeof(mod_hdr)) < 0x100) continue;
        if (mod_hdr[0] != 'M' || mod_hdr[1] != 'Z') continue;

        std::uint32_t mod_pe_off = *reinterpret_cast<std::uint32_t*>(&mod_hdr[0x3C]);
        if (mod_pe_off + 0x90 > sizeof(mod_hdr)) continue;


        uint8_t scan_buf[0x1000];
        size_t scan_read = device->read_kernel_raw(mod_base, scan_buf, sizeof(scan_buf));
        if (scan_read < 16) continue;
        ++etw_modules_scanned;
        const size_t scan_limit = std::min(sizeof(scan_buf), scan_read);


        for (size_t off = 0; off + 11 < scan_limit; ++off)
        {
            if (std::memcmp(&scan_buf[off], "EtwRegis", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwWrite", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwEventW", 9) == 0)
            {
                json em;
                em["module"]  = mod_name;
                em["address"] = sa_format_address(static_cast<uint64_t>(mod_base));
                em["etw_api_found"] = std::string(reinterpret_cast<const char*>(&scan_buf[off]),
                                                   std::min((size_t)32, scan_limit - off));

                auto& s = em["etw_api_found"].get_ref<std::string&>();
                auto nul = s.find('\0');
                if (nul != std::string::npos) s.resize(nul);
                etw_modules.push_back(std::move(em));
                break;
            }
        }
    }

    json result;
    result["ntoskrnl_base"]     = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["etw_register"]      = (etw_register != 0) ? sa_format_address(static_cast<uint64_t>(etw_register)) : "not_found";
    result["threat_intel"]      = (etw_threat_intel != 0) ? sa_format_address(static_cast<uint64_t>(etw_threat_intel)) : "not_exported";
    const std::size_t provider_artifact_count = providers.size();
    const std::size_t consumer_module_count = etw_modules.size();
    const std::size_t monitor_count = active_provider_count + consumer_module_count;
    const bool etw_scan_ran = etw_sections_scanned > 0 || etw_modules_scanned > 0 || etw_threat_intel != 0 || etw_register != 0;
    const bool zero_monitors_clean = etw_scan_ran && monitor_count == 0;
    result["scan_ran"]          = etw_scan_ran;
    result["clean_state"]       = zero_monitors_clean;
    result["zero_is_clean_state"] = zero_monitors_clean;
    result["proof_count"]       = etw_sections_scanned + etw_modules_scanned + (etw_threat_intel != 0 ? 1u : 0u) + (etw_register != 0 ? 1u : 0u);
    result["active_provider_count"] = active_provider_count;
    result["known_guid_matches"] = known_guid_matches;
    result["provider_artifact_count"] = provider_artifact_count;
    result["monitor_count"] = monitor_count;
    result["sections_scanned"] = etw_sections_scanned;
    result["modules_scanned_for_etw"] = etw_modules_scanned;
    result["providers"]         = std::move(providers);
    result["etw_consumer_modules"] = std::move(etw_modules);
    result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diag);
    result["note"] = std::string("ETW (Event Tracing for Windows) provides kernel-level telemetry. The Threat Intelligence "
                            "provider detects process injection, executable memory allocation, and suspicious API sequences. "
                            "Anti-cheats and EDRs subscribe to these events for real-time detection.");

    return tool_result_t::ok(std::string("ETW monitors: ") + std::to_string(provider_artifact_count) +
                             std::string(" providers, ") + std::to_string(consumer_module_count) +
                             std::string(" consumer modules"), result);
}


tool_result_t driver_detect_hidden_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_hidden_modules entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_process_id() == 0)
        return tool_result_t::error(std::string("No target process attached. Use sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_detect_hidden_modules", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    bool scan_kernel = params.value("kernel", false);

    json hidden = json::array();
    json legitimate = json::array();
    json module_base_diagnostics = json::object();

    if (!scan_kernel)
    {


        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb))
            return tool_result_t::error(std::string("Failed to read PEB"));


        auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


        std::set<std::uint64_t> peb_bases;


        std::uint64_t peb_addr = 0;


        auto modules = device->enumerate_memory_regions(0x10000, 0x7FFFFFFFFFFF, false);


        struct known_module_t {
            std::uint64_t base;
            std::uint64_t size;
            std::string name;
        };
        std::vector<known_module_t> known_modules;


        std::uint64_t ldr = 0;
        device->read_raw(peb.peb_address + 0x18, &ldr, 8);
        if (ldr != 0 && ldr < 0x7FFFFFFFFFFF)
        {

            std::uint64_t head = ldr + 0x10;
            std::uint64_t flink = 0;
            device->read_raw(head, &flink, 8);

            std::uint64_t cur = flink;
            int count = 0;
            while (cur != head && cur != 0 && count < 1024)
            {

                std::uint64_t dll_base = 0;
                std::uint32_t dll_size = 0;
                device->read_raw(cur + 0x30, &dll_base, 8);
                device->read_raw(cur + 0x40, &dll_size, 4);


                std::uint16_t name_len = 0;
                std::uint64_t name_buf = 0;
                device->read_raw(cur + 0x48, &name_len, 2);
                device->read_raw(cur + 0x48 + 8, &name_buf, 8);

                std::string name_str;
                if (name_len > 0 && name_len < 1024 && name_buf != 0)
                {
                    std::vector<wchar_t> wbuf(name_len / 2 + 1, 0);
                    device->read_raw(name_buf, wbuf.data(), name_len);
                    std::wstring wname(wbuf.data());
                    for (wchar_t wc : wname) name_str += static_cast<char>(wc);
                }

                if (dll_base != 0)
                {
                    known_modules.push_back({dll_base, dll_size, name_str});
                    peb_bases.insert(dll_base);
                }


                device->read_raw(cur, &cur, 8);
                ++count;
            }
        }


        for (const auto& reg : regions)
        {
            if (reg.size < 0x1000) continue;


            uint8_t mz[2] = {};
            device->read_raw(reg.base, mz, 2);
            if (mz[0] != 'M' || mz[1] != 'Z') continue;


            if (peb_bases.count(reg.base) == 0)
            {

                json h;
                h["address"] = sa_format_address(static_cast<uint64_t>(reg.base));
                h["size"]    = reg.size;
                h["status"]  = "hidden_pe";


                uint8_t pe_buf[0x400];
                if (device->read_raw(reg.base, pe_buf, sizeof(pe_buf)) >= 0x100)
                {
                    std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                    if (pe_off2 + 0x90 <= sizeof(pe_buf))
                    {

                        std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                        if (export_rva > 0 && export_rva < 0x1000000)
                        {

                            uint8_t exp_dir[0x28];
                            if (device->read_raw(reg.base + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                            {
                                std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                                if (name_rva > 0 && name_rva < 0x1000000)
                                {
                                    char exp_name[128] = {};
                                    device->read_raw(reg.base + name_rva, exp_name, sizeof(exp_name) - 1);
                                    if (exp_name[0]) h["export_name"] = std::string(exp_name);
                                }
                            }
                        }

                        std::uint16_t chars = *reinterpret_cast<std::uint16_t*>(&pe_buf[pe_off2 + 0x16]);
                        h["is_dll"] = (chars & 0x2000) != 0;
                    }
                }

                hidden.push_back(std::move(h));
            }
            else
            {

                for (const auto& km : known_modules)
                {
                    if (km.base == reg.base)
                    {
                        json l;
                        l["address"] = sa_format_address(static_cast<uint64_t>(reg.base));
                        l["size"]    = km.size;
                        l["name"]    = km.name;
                        legitimate.push_back(std::move(l));
                        break;
                    }
                }
            }
        }
    }
    else
    {

        std::vector<uint8_t> mod_buf;
        sys_module_info_t* kinfo = nullptr;
        std::string kerr;
        kernel_module_query_diagnostics_t query_diag{};
        if (!query_kernel_modules(mod_buf, kinfo, kerr, &query_diag,
                kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
            return kernel_module_query_error_result(kerr, query_diag, std::string("Failed to enumerate kernel modules: "));
        module_base_diagnostics = kernel_module_query_diagnostics_json(query_diag);

        std::set<std::uint64_t> known_bases;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
            known_bases.insert(reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase));


        std::vector<std::pair<std::uint64_t, std::uint64_t>> scan_ranges;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
        {
            std::uint64_t base = reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase);
            std::uint64_t size = kinfo->Modules[i].ImageSize;

            if (base >= 0x10000)
                scan_ranges.push_back({base - 0x10000, base});
            scan_ranges.push_back({base + size, base + size + 0x10000});
        }

        int pages_scanned = 0;
        for (const auto& [start, end] : scan_ranges)
        {
            if (pages_scanned > 2048) break;
            for (std::uint64_t addr = start; addr < end; addr += 0x1000)
            {
                if (known_bases.count(addr)) continue;
                ++pages_scanned;

                uint8_t mz[2] = {};
                if (device->read_kernel_raw(addr, mz, 2) < 2) continue;
                if (mz[0] != 'M' || mz[1] != 'Z') continue;


                uint8_t pe_buf[0x400];
                if (device->read_kernel_raw(addr, pe_buf, sizeof(pe_buf)) < 0x100) continue;

                std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                if (pe_off2 > 0x300 || pe_off2 < 4) continue;
                if (pe_buf[pe_off2] != 'P' || pe_buf[pe_off2 + 1] != 'E') continue;

                json h;
                h["address"] = sa_format_address(static_cast<uint64_t>(addr));
                h["status"]  = "hidden_kernel_pe";
                h["mode"]    = "kernel";

                std::uint32_t img_size = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x50]);
                h["image_size"] = img_size;


                std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                if (export_rva > 0 && export_rva < img_size)
                {
                    uint8_t exp_dir[0x28];
                    if (device->read_kernel_raw(addr + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                    {
                        std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                        if (name_rva > 0 && name_rva < img_size)
                        {
                            char exp_name[128] = {};
                            device->read_kernel_raw(addr + name_rva, exp_name, sizeof(exp_name) - 1);
                            if (exp_name[0]) h["export_name"] = std::string(exp_name);
                        }
                    }
                }

                hidden.push_back(std::move(h));
            }
        }
    }

    json result;
    result["mode"]           = scan_kernel ? "kernel" : "usermode";
    result["hidden_count"]   = hidden.size();
    result["hidden_modules"] = std::move(hidden);
    if (!scan_kernel)
    {
        result["legitimate_count"]  = legitimate.size();
        result["legitimate_modules"] = std::move(legitimate);
    }
    else
    {
        result["module_base_diagnostics"] = std::move(module_base_diagnostics);
    }
    result["note"] = std::string("Hidden modules are PE images present in memory but not in the PEB module list (usermode) "
                            "or NtQuerySystemInformation module list (kernel). Common for manual-mapped DLLs, "
                            "anti-cheat drivers, and injected payloads.");

    return tool_result_t::ok(std::string("Hidden modules: ") + std::to_string(result["hidden_count"].get<std::size_t>()) +
                             std::string(" found"), result);
}


tool_result_t driver_walk_heap(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_walk_heap entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_walk_heap", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::uint32_t pid = device->get_process_id();
    const int max_entries = std::min(params.value("limit", 500), 5000);
    const std::uint64_t filter_min = params.contains("min_size") ? params["min_size"].get<std::uint64_t>() : 0;
    const std::uint64_t filter_max = params.contains("max_size") ? params["max_size"].get<std::uint64_t>() : 0;
    const bool free_only = params.value("free_only", false);

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb))
        return tool_result_t::error(std::string("Failed to read PEB"));

    const std::uint64_t peb_addr = peb.peb_address;
    if (peb_addr == 0)
        return tool_result_t::error(std::string("PEB address is null"));


    const std::uint32_t num_heaps = device->read<std::uint32_t>(peb_addr + 0xE8);
    const std::uint64_t heaps_ptr = device->read<std::uint64_t>(peb_addr + 0xF0);
    diag::log_tagged_fmt("drv_tools",
        "driver_walk_heap peb=0x%llX num_heaps=%u heaps_ptr=0x%llX limit=%d min=%llu max=%llu free_only=%d",
        static_cast<unsigned long long>(peb_addr),
        num_heaps,
        static_cast<unsigned long long>(heaps_ptr),
        max_entries,
        static_cast<unsigned long long>(filter_min),
        static_cast<unsigned long long>(filter_max),
        free_only ? 1 : 0);

    if (num_heaps == 0 || num_heaps > 256 || heaps_ptr == 0)
        return tool_result_t::error(std::string("No heaps found or invalid PEB heap data"));

    json heaps_arr = json::array();
    int total_entries = 0;

    for (std::uint32_t h = 0; h < num_heaps && total_entries < max_entries; ++h)
    {
        const std::uint64_t heap_base = device->read<std::uint64_t>(heaps_ptr + h * 8);
        if (heap_base == 0) continue;


        const std::uint32_t signature = device->read<std::uint32_t>(heap_base);
        const std::uint64_t total_free = device->read<std::uint64_t>(heap_base + 0x40);
        const std::uint64_t num_pages = device->read<std::uint64_t>(heap_base + 0x38);
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap heap[%u] base=0x%llX sig=0x%08X total_free=%llu pages=%llu",
            h,
            static_cast<unsigned long long>(heap_base),
            signature,
            static_cast<unsigned long long>(total_free),
            static_cast<unsigned long long>(num_pages));

        json heap_info;
        heap_info["heap_index"] = h;
        heap_info["heap_base"] = sa_format_address(static_cast<uint64_t>(heap_base));
        heap_info["signature"] = sa_format_address(static_cast<uint64_t>(signature));
        heap_info["total_free_size"] = total_free;
        heap_info["committed_pages"] = num_pages;


        const std::uint64_t seg_list_head = heap_base + 0x120;
        std::uint64_t seg_flink = device->read<std::uint64_t>(seg_list_head);

        json segments_arr = json::array();
        int seg_iter = 0;
        constexpr int MAX_SEGS = 64;

        while (seg_flink != 0 && seg_flink != seg_list_head && seg_iter++ < MAX_SEGS && total_entries < max_entries)
        {

            const std::uint64_t segment_base = seg_flink - 0x18;
            const std::uint64_t seg_base_addr = device->read<std::uint64_t>(segment_base + 0x0);
            const std::uint32_t seg_num_pages = device->read<std::uint32_t>(segment_base + 0x10);
            const std::uint64_t first_entry = device->read<std::uint64_t>(segment_base + 0x28);
            const std::uint64_t last_entry = device->read<std::uint64_t>(segment_base + 0x48);
            diag::log_tagged_fmt("drv_tools",
                "driver_walk_heap heap[%u] segment[%d] segment_base=0x%llX seg_base_addr=0x%llX pages=%u first=0x%llX last=0x%llX",
                h,
                seg_iter - 1,
                static_cast<unsigned long long>(segment_base),
                static_cast<unsigned long long>(seg_base_addr),
                seg_num_pages,
                static_cast<unsigned long long>(first_entry),
                static_cast<unsigned long long>(last_entry));


            std::uint64_t entry_addr = first_entry;
            int entry_iter = 0;
            constexpr int MAX_ENTRIES_PER_SEG = 2048;
            json entries_arr = json::array();

            while (entry_addr != 0 && entry_addr < last_entry && entry_iter++ < MAX_ENTRIES_PER_SEG && total_entries < max_entries)
            {


                std::uint16_t raw_size = device->read<std::uint16_t>(entry_addr);
                std::uint8_t flags = device->read<std::uint8_t>(entry_addr + 0x2);
                std::uint8_t unused_bytes = device->read<std::uint8_t>(entry_addr + 0x7);

                std::uint64_t block_size = static_cast<std::uint64_t>(raw_size) * 16;
                if (block_size == 0) break;

                bool is_busy = (flags & 0x01) != 0;
                bool is_extra = (flags & 0x02) != 0;
                bool is_fill = (flags & 0x04) != 0;
                bool is_virtual = (flags & 0x08) != 0;
                bool is_last = (flags & 0x10) != 0;

                bool include = true;
                if (free_only && is_busy) include = false;
                if (filter_min > 0 && block_size < filter_min) include = false;
                if (filter_max > 0 && block_size > filter_max) include = false;

                if (include)
                {
                    json entry;
                    entry["address"] = sa_format_address(static_cast<uint64_t>(entry_addr));
                    entry["user_address"] = sa_format_address(static_cast<uint64_t>(entry_addr + 0x10));
                    entry["block_size"] = block_size;
                    entry["user_size"] = block_size > unused_bytes ? block_size - unused_bytes - 0x10 : 0;
                    entry["flags"] = {
                        {"busy", is_busy}, {"extra", is_extra}, {"fill", is_fill},
                        {"virtual_alloc", is_virtual}, {"last_entry", is_last}
                    };
                    entries_arr.push_back(std::move(entry));
                    ++total_entries;
                }

                entry_addr += block_size;
                if (is_last) break;
            }

            json seg;
            seg["segment_base"] = sa_format_address(static_cast<uint64_t>(segment_base));
            seg["pages"] = seg_num_pages;
            seg["entries"] = std::move(entries_arr);
            segments_arr.push_back(std::move(seg));

            seg_flink = device->read<std::uint64_t>(seg_flink);
        }

        heap_info["segments"] = std::move(segments_arr);
        heaps_arr.push_back(std::move(heap_info));
    }

    json fallback_regions = json::array();
    std::string walk_mode = "heap_entries";
    if (total_entries == 0)
    {
        int fallback_count = 0;
        auto regions = enumerate_all_memory_regions_paginated(
            device.get(), 0x10000, 0x7FFFFFFFFFFF, false);
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap no_entries fallback_regions_scan regions=%zu",
            regions.size());
        for (const auto& region : regions)
        {
            if (fallback_count >= max_entries) break;
            if ((region.state & 0x1000) == 0) continue;
            if (region.type != 0x20000) continue;
            const std::uint32_t prot = region.protect & 0xFF;
            if ((prot & 0xCC) == 0) continue;
            if (filter_min > 0 && region.size < filter_min) continue;
            if (filter_max > 0 && region.size > filter_max) continue;
            json entry;
            entry["address"] = sa_format_address(static_cast<uint64_t>(region.base));
            entry["user_address"] = sa_format_address(static_cast<uint64_t>(region.base));
            entry["block_size"] = region.size;
            entry["user_size"] = region.size;
            entry["flags"] = {
                {"busy", true},
                {"extra", false},
                {"fill", false},
                {"virtual_alloc", true},
                {"last_entry", false}
            };
            entry["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
            entry["source"] = "committed_private_region_fallback";
            fallback_regions.push_back(std::move(entry));
            ++fallback_count;
        }
        total_entries = fallback_count;
        walk_mode = "committed_private_region_fallback";
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap fallback_done returned=%d",
            fallback_count);
    }

    json result;
    result["process_id"] = pid;
    result["heap_count"] = num_heaps;
    result["entries_returned"] = total_entries;
    result["walk_mode"] = walk_mode;
    result["heaps"] = std::move(heaps_arr);
    if (!fallback_regions.empty())
        result["fallback_regions"] = std::move(fallback_regions);
    return tool_result_t::ok(std::string("Walked ") + std::to_string(num_heaps) + std::string(" heaps, ") +
                             std::to_string(total_entries) + std::string(" entries"), result);
}

tool_result_t driver_enumerate_handles(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_handles entry");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_enumerate_handles", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::uint32_t filter_pid = params.value("pid", 0u);
    const std::string filter_type = params.value("type_filter", "");
    const int limit = std::min(params.value("limit", 500), 10000);


    typedef struct {
        ULONG NumberOfHandles;
    } SYSTEM_HANDLE_INFORMATION_HEAD;

    typedef struct {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO;


    auto type_name_from_index = [](std::uint8_t idx) -> std::string {
        switch (idx) {
            case 7:  return "Process";
            case 8:  return "Thread";
            case 5:  return "Token";
            case 37: return "Section";
            case 39: return "Key";
            case 36: return "File";
            case 28: return "Event";
            case 30: return "Mutant";
            case 31: return "Semaphore";
            case 32: return "Timer";
            case 44: return "Directory";
            case 45: return "SymbolicLink";
            default: return "Type_" + std::to_string(idx);
        }
    };

    ULONG bufsize = 1 << 22;
    std::vector<std::uint8_t> buffer(bufsize);
    NTSTATUS status;
    using NtQuerySystemInformationFn = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation)
        return tool_result_t::error(std::string("Failed to resolve NtQuerySystemInformation"));

    ULONG returned_length = 0;
    for (int attempt = 0; attempt < 5; ++attempt)
    {
        status = NtQuerySystemInformation(16 , buffer.data(),
                                          static_cast<ULONG>(buffer.size()), &returned_length);
        if (status == 0) break;
        if (status == 0xC0000004 )
        {
            bufsize = returned_length + (1 << 20);
            if (bufsize > (1u << 28))
                return tool_result_t::error(std::string("Handle table too large"));
            buffer.resize(bufsize);
            continue;
        }
        return tool_result_t::error(std::string("NtQuerySystemInformation failed: 0x") +
                                    sa_format_address(static_cast<uint64_t>(status)));
    }

    const auto* head = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_HEAD*>(buffer.data());
    const auto* entries = reinterpret_cast<const SYSTEM_HANDLE_TABLE_ENTRY_INFO*>(buffer.data() + sizeof(ULONG));
    const ULONG count = head->NumberOfHandles;

    const std::string filter_type_lower = to_lower_ascii_copy(filter_type);
    json handles_arr = json::array();
    int matched = 0;

    for (ULONG i = 0; i < count && matched < limit; ++i)
    {
        const auto& e = entries[i];
        if (filter_pid != 0 && e.UniqueProcessId != static_cast<USHORT>(filter_pid))
            continue;

        std::string type_name = type_name_from_index(e.ObjectTypeIndex);
        if (!filter_type_lower.empty())
        {
            std::string lower_type = to_lower_ascii_copy(type_name);
            if (lower_type.find(filter_type_lower) == std::string::npos)
                continue;
        }

        json h;
        h["pid"] = static_cast<std::uint32_t>(e.UniqueProcessId);
        h["handle"] = static_cast<std::uint32_t>(e.HandleValue);
        h["type"] = type_name;
        h["type_index"] = e.ObjectTypeIndex;
        h["object_address"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(e.Object)));
        h["access"] = sa_format_address(static_cast<uint64_t>(e.GrantedAccess));
        h["attributes"] = e.HandleAttributes;
        handles_arr.push_back(std::move(h));
        ++matched;
    }

    json result;
    result["total_system_handles"] = count;
    result["returned"] = matched;
    if (filter_pid != 0) result["filter_pid"] = filter_pid;
    if (!filter_type.empty()) result["filter_type"] = filter_type;
    result["handles"] = std::move(handles_arr);
    return tool_result_t::ok(std::to_string(matched) + std::string(" handles returned (") +
                             std::to_string(count) + std::string(" total system-wide)"), result);
}





tool_result_t driver_enumerate_windows(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_windows entry");
    if (!device->is_connected())
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_enumerate_windows", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::uint32_t filter_pid = params.value("pid", device->get_process_id());
    const bool include_children = params.value("include_children", true);
    const int limit = std::min(params.value("limit", 200), 2000);

    if (filter_pid == 0)
        return tool_result_t::error(std::string("No process attached and no pid specified."));

    struct window_info_t {
        HWND hwnd;
        HWND parent;
        DWORD pid;
        DWORD tid;
        char class_name[256];
        char title[512];
        RECT rect;
        bool visible;
        LONG style;
        LONG ex_style;
    };

    std::vector<window_info_t> windows;

    struct enum_ctx_t {
        std::vector<window_info_t>* windows;
        DWORD target_pid;
        int limit;
        bool include_children;
    };

    enum_ctx_t ctx_data;
    ctx_data.windows = &windows;
    ctx_data.target_pid = filter_pid;
    ctx_data.limit = limit;
    ctx_data.include_children = include_children;

    auto enum_proc = [](HWND hwnd, LPARAM lparam) -> BOOL {
        auto* ctx2 = reinterpret_cast<enum_ctx_t*>(lparam);
        if (static_cast<int>(ctx2->windows->size()) >= ctx2->limit)
            return FALSE;

        DWORD wnd_pid = 0;
        DWORD wnd_tid = GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid != ctx2->target_pid)
            return TRUE;

        window_info_t info{};
        info.hwnd = hwnd;
        info.parent = GetParent(hwnd);
        info.pid = wnd_pid;
        info.tid = wnd_tid;
        GetClassNameA(hwnd, info.class_name, sizeof(info.class_name));
        GetWindowTextA(hwnd, info.title, sizeof(info.title));
        GetWindowRect(hwnd, &info.rect);
        info.visible = IsWindowVisible(hwnd) != FALSE;
        info.style = GetWindowLongA(hwnd, GWL_STYLE);
        info.ex_style = GetWindowLongA(hwnd, GWL_EXSTYLE);
        ctx2->windows->push_back(info);
        return TRUE;
    };

    EnumWindows(enum_proc, reinterpret_cast<LPARAM>(&ctx_data));

    json windows_arr = json::array();
    for (const auto& w : windows)
    {
        json wj;
        wj["hwnd"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(w.hwnd)));
        wj["parent"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(w.parent)));
        wj["tid"] = w.tid;
        wj["class_name"] = w.class_name;
        wj["title"] = w.title;
        wj["visible"] = w.visible;
        wj["rect"] = { {"left", w.rect.left}, {"top", w.rect.top},
                       {"right", w.rect.right}, {"bottom", w.rect.bottom} };
        wj["style"] = sa_format_address(static_cast<uint64_t>(w.style));
        wj["ex_style"] = sa_format_address(static_cast<uint64_t>(w.ex_style));
        windows_arr.push_back(std::move(wj));
    }

    json result;
    result["pid"] = filter_pid;
    result["window_count"] = windows.size();
    result["windows"] = std::move(windows_arr);
    return tool_result_t::ok(std::to_string(windows.size()) + std::string(" windows found for PID ") +
                             std::to_string(filter_pid), result);
}


tool_result_t driver_assemble(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_assemble entry");
    const std::string assembly_text = params.value("assembly", "");
    if (assembly_text.empty())
        return tool_result_t::error(std::string("Missing required parameter: assembly"));

    const std::uint64_t address = [&]() -> std::uint64_t {
        if (params.contains("address"))
        {
            auto a = sa_parse_address(params["address"].get<std::string>());
            return a ? *a : 0x140000000ULL;
        }
        return 0x140000000ULL;
    }();

    std::vector<std::uint8_t> output;
    std::string error_msg;

    auto trim = [](const std::string& s) -> std::string {
        const auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
    };

    auto to_upper = [](std::string s) -> std::string {
        std::transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    };

    auto reg_to_idx = [](const std::string& reg) -> int {
        if (reg == "RAX" || reg == "EAX" || reg == "AX" || reg == "AL") return 0;
        if (reg == "RCX" || reg == "ECX" || reg == "CX" || reg == "CL") return 1;
        if (reg == "RDX" || reg == "EDX" || reg == "DX" || reg == "DL") return 2;
        if (reg == "RBX" || reg == "EBX" || reg == "BX" || reg == "BL") return 3;
        if (reg == "RSP" || reg == "ESP" || reg == "SP") return 4;
        if (reg == "RBP" || reg == "EBP" || reg == "BP") return 5;
        if (reg == "RSI" || reg == "ESI" || reg == "SI") return 6;
        if (reg == "RDI" || reg == "EDI" || reg == "DI") return 7;
        if (reg == "R8" || reg == "R8D" || reg == "R8W" || reg == "R8B") return 8;
        if (reg == "R9" || reg == "R9D") return 9;
        if (reg == "R10" || reg == "R10D") return 10;
        if (reg == "R11" || reg == "R11D") return 11;
        if (reg == "R12" || reg == "R12D") return 12;
        if (reg == "R13" || reg == "R13D") return 13;
        if (reg == "R14" || reg == "R14D") return 14;
        if (reg == "R15" || reg == "R15D") return 15;
        return -1;
    };

    auto is_reg64 = [](const std::string& reg) -> bool {
        return reg.size() >= 2 && (reg[0] == 'R' || (reg[0] == 'R' && std::isdigit(reg[1])));
    };


    std::istringstream stream(assembly_text);
    std::string line;
    int line_num = 0;
    std::uint64_t current_addr = address;

    while (std::getline(stream, line))
    {
        ++line_num;
        line = trim(line);
        if (line.empty() || line[0] == ';') continue;


        auto semi_pos = line.find(';');
        if (semi_pos != std::string::npos)
            line = trim(line.substr(0, semi_pos));

        std::string upper = to_upper(line);

        if (upper == "NOP")
        {
            output.push_back(0x90);
        }
        else if (upper == "RET" || upper == "RETN")
        {
            output.push_back(0xC3);
        }
        else if (upper == "INT3" || upper == "INT 3")
        {
            output.push_back(0xCC);
        }
        else if (upper.substr(0, 4) == "PUSH")
        {
            std::string operand = trim(upper.substr(4));
            int idx = reg_to_idx(operand);
            if (idx < 0) { error_msg = "Unknown register in PUSH at line " + std::to_string(line_num); break; }
            if (idx >= 8) { output.push_back(0x41); idx -= 8; }
            output.push_back(static_cast<std::uint8_t>(0x50 + idx));
        }
        else if (upper.substr(0, 3) == "POP")
        {
            std::string operand = trim(upper.substr(3));
            int idx = reg_to_idx(operand);
            if (idx < 0) { error_msg = "Unknown register in POP at line " + std::to_string(line_num); break; }
            if (idx >= 8) { output.push_back(0x41); idx -= 8; }
            output.push_back(static_cast<std::uint8_t>(0x58 + idx));
        }
        else if (upper.substr(0, 3) == "XOR")
        {

            auto comma = upper.find(',');
            if (comma == std::string::npos) { error_msg = "Invalid XOR at line " + std::to_string(line_num); break; }
            std::string op1 = trim(upper.substr(3, comma - 3));
            std::string op2 = trim(upper.substr(comma + 1));
            int r1 = reg_to_idx(op1), r2 = reg_to_idx(op2);
            if (r1 < 0 || r2 < 0) { error_msg = "Unknown register in XOR at line " + std::to_string(line_num); break; }

            if (is_reg64(op1))
            {
                std::uint8_t rex = 0x48;
                if (r1 >= 8) { rex |= 0x04; r1 -= 8; }
                if (r2 >= 8) { rex |= 0x01; r2 -= 8; }
                output.push_back(rex);
            }
            else
            {
                if (r1 >= 8 || r2 >= 8)
                {
                    std::uint8_t rex = 0x40;
                    if (r1 >= 8) { rex |= 0x04; r1 -= 8; }
                    if (r2 >= 8) { rex |= 0x01; r2 -= 8; }
                    output.push_back(rex);
                }
            }
            output.push_back(0x31);
            output.push_back(static_cast<std::uint8_t>(0xC0 | (r1 << 3) | r2));
        }
        else if (upper.substr(0, 3) == "MOV")
        {

            auto comma = upper.find(',');
            if (comma == std::string::npos) { error_msg = "Invalid MOV at line " + std::to_string(line_num); break; }
            std::string dest = trim(upper.substr(3, comma - 3));
            std::string src = trim(upper.substr(comma + 1));
            int rd = reg_to_idx(dest);
            if (rd < 0) { error_msg = "Unknown register in MOV at line " + std::to_string(line_num); break; }


            std::uint64_t imm = 0;
            try {
                if (src.size() > 2 && src[0] == '0' && (src[1] == 'X' || src[1] == 'x'))
                    imm = std::stoull(src.substr(2), nullptr, 16);
                else
                    imm = std::stoull(src, nullptr, 0);
            } catch (...) {
                error_msg = "Invalid immediate in MOV at line " + std::to_string(line_num);
                break;
            }

            if (is_reg64(dest))
            {

                std::uint8_t rex = 0x48;
                int r = rd;
                if (r >= 8) { rex |= 0x01; r -= 8; }
                output.push_back(rex);
                output.push_back(static_cast<std::uint8_t>(0xB8 + r));
                for (int b = 0; b < 8; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
            else
            {

                int r = rd;
                if (r >= 8) { output.push_back(0x41); r -= 8; }
                output.push_back(static_cast<std::uint8_t>(0xB8 + r));
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 3) == "JMP" || upper.substr(0, 4) == "CALL")
        {
            bool is_call = upper[0] == 'C';
            std::string operand = trim(upper.substr(is_call ? 4 : 3));


            int reg = reg_to_idx(operand);
            if (reg >= 0)
            {
                if (reg >= 8)
                {
                    output.push_back(0x41);
                    reg -= 8;
                }
                output.push_back(0xFF);
                output.push_back(static_cast<std::uint8_t>((is_call ? 0xD0 : 0xE0) + reg));
            }
            else
            {

                std::uint64_t target_addr = 0;
                try {
                    if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                        target_addr = std::stoull(operand.substr(2), nullptr, 16);
                    else
                        target_addr = std::stoull(operand, nullptr, 0);
                } catch (...) {
                    error_msg = std::string(is_call ? "CALL" : "JMP") + " invalid operand at line " + std::to_string(line_num);
                    break;
                }

                std::uint64_t next_rip = current_addr + output.size() + 5;
                std::int64_t rel = static_cast<std::int64_t>(target_addr) - static_cast<std::int64_t>(next_rip);
                if (rel < INT32_MIN || rel > INT32_MAX)
                {
                    error_msg = "Relative offset too large for " + std::string(is_call ? "CALL" : "JMP") +
                                " at line " + std::to_string(line_num);
                    break;
                }

                output.push_back(is_call ? 0xE8 : 0xE9);
                std::int32_t rel32 = static_cast<std::int32_t>(rel);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((rel32 >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 7) == "SUB RSP")
        {
            std::string operand = trim(upper.substr(8));
            std::uint32_t imm = 0;
            try {
                if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                    imm = static_cast<std::uint32_t>(std::stoul(operand.substr(2), nullptr, 16));
                else
                    imm = static_cast<std::uint32_t>(std::stoul(operand, nullptr, 0));
            } catch (...) { error_msg = "Invalid immediate in SUB RSP at line " + std::to_string(line_num); break; }

            output.push_back(0x48);
            if (imm <= 0x7F) {
                output.push_back(0x83);
                output.push_back(0xEC);
                output.push_back(static_cast<std::uint8_t>(imm));
            } else {
                output.push_back(0x81);
                output.push_back(0xEC);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 7) == "ADD RSP")
        {
            std::string operand = trim(upper.substr(8));
            std::uint32_t imm = 0;
            try {
                if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                    imm = static_cast<std::uint32_t>(std::stoul(operand.substr(2), nullptr, 16));
                else
                    imm = static_cast<std::uint32_t>(std::stoul(operand, nullptr, 0));
            } catch (...) { error_msg = "Invalid immediate in ADD RSP at line " + std::to_string(line_num); break; }

            output.push_back(0x48);
            if (imm <= 0x7F) {
                output.push_back(0x83);
                output.push_back(0xC4);
                output.push_back(static_cast<std::uint8_t>(imm));
            } else {
                output.push_back(0x81);
                output.push_back(0xC4);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else
        {
            error_msg = "Unsupported instruction at line " + std::to_string(line_num) + ": " + line +
                        ". Supported: NOP, RET, INT3, PUSH, POP, XOR, MOV, JMP, CALL, SUB RSP, ADD RSP.";
            break;
        }
    }

    if (!error_msg.empty())
        return tool_result_t::error(error_msg);

    if (output.empty())
        return tool_result_t::error(std::string("No instructions assembled"));


    std::ostringstream hex_ss;
    for (std::size_t i = 0; i < output.size(); ++i)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(output[i]);
    }

    json result;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["size"] = output.size();
    result["hex"] = hex_ss.str();
    result["bytes"] = json::array();
    for (auto b : output) result["bytes"].push_back(b);


    if (params.contains("write_to"))
    {
        driver_debugger_quota_guard_t quota_guard;
        if (auto quota_err = acquire_driver_debugger_quota("driver_assemble", driver_bridge::attached_pid(), quota_guard))
            return *quota_err;

        auto write_addr = sa_parse_address(params["write_to"].get<std::string>());
        if (write_addr && device->is_connected() && device->get_process_id() != 0)
        {

            std::size_t written = device->write_raw(*write_addr, output.data(), output.size());
            result["written_to"] = sa_format_address(static_cast<uint64_t>(*write_addr));
            result["bytes_written"] = written;
        }
    }

    return tool_result_t::ok(std::to_string(output.size()) + std::string(" bytes assembled"), result);
}


static std::map<std::string, std::vector<std::uint8_t>> s_memory_snapshots;
static std::mutex s_snapshot_mutex;


tool_result_t driver_find_references(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_find_references entry");
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("Tool cancelled before operation.");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_find_references", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::string target_str = params.value("target_address", "");
    if (target_str.empty())
        return tool_result_t::error(std::string("Missing required parameter: target_address"));

    auto target_opt = sa_parse_address(target_str);
    if (!target_opt) return tool_result_t::error(std::string("Invalid target_address"));

    const std::uint64_t target = *target_opt;
    const int limit = std::min(params.value("limit", 100), 5000);
    const bool scan_code = params.value("scan_code", true);
    const bool scan_data = params.value("scan_data", true);

    std::uint8_t target_bytes[8];
    std::memcpy(target_bytes, &target, 8);

    auto regions = enumerate_all_memory_regions_paginated(
        device.get(), 0x10000, 0x7FFFFFFFFFFF, false);

    json refs = json::array();
    int found = 0;

    for (const auto& region : regions)
    {
        if (found >= limit) break;
        if (mcp_standalone::current_call_cancelled())
            return tool_result_t::error("Tool cancelled during reference scan.");
        if (region.size == 0 || region.size > 0x10000000) continue;
        if ((region.state & 0x1000) == 0) continue;
        if ((region.protect & 0x01) || (region.protect & 0x100)) continue;

        bool is_exec = (region.protect & 0x10) || (region.protect & 0x20) ||
                       (region.protect & 0x40) || (region.protect & 0x80);

        if (is_exec && !scan_code) continue;
        if (!is_exec && !scan_data) continue;

        constexpr std::size_t CHUNK = 0x10000;
        for (std::uint64_t off3 = 0; off3 < region.size && found < limit; off3 += CHUNK)
        {
            const std::size_t to_read = std::min<std::size_t>(CHUNK, region.size - off3);
            if (to_read < 8) continue;

            std::vector<std::uint8_t> buf(to_read);
            if (device->read_raw(region.base + off3, buf.data(), to_read) == 0)
                continue;


            for (std::size_t i = 0; i + 8 <= to_read && found < limit; ++i)
            {
                if (std::memcmp(&buf[i], target_bytes, 8) == 0)
                {
                    json ref;
                    ref["address"] = sa_format_address(static_cast<uint64_t>(region.base + off3 + i));
                    ref["type"] = is_exec ? "code" : "data";
                    ref["region_base"] = sa_format_address(static_cast<uint64_t>(region.base));
                    ref["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
                    refs.push_back(std::move(ref));
                    ++found;
                }
            }


            if (is_exec && scan_code)
            {
                for (std::size_t i = 0; i + 4 <= to_read && found < limit; ++i)
                {
                    std::int32_t rel32;
                    std::memcpy(&rel32, &buf[i], 4);
                    std::uint64_t effective = region.base + off3 + i + 4 + rel32;
                    if (effective == target)
                    {

                        if (i >= 1)
                        {
                            std::uint8_t prev = buf[i - 1];

                            if (prev == 0x8D || prev == 0x8B || prev == 0x05 || prev == 0x0D ||
                                prev == 0x15 || prev == 0x1D || prev == 0x25 || prev == 0x2D ||
                                prev == 0x35 || prev == 0x3D)
                            {
                                json ref;
                                ref["address"] = sa_format_address(
                                    static_cast<uint64_t>(region.base + off3 + i - 1));
                                ref["type"] = "rip_relative";
                                ref["displacement"] = rel32;
                                refs.push_back(std::move(ref));
                                ++found;
                            }
                        }
                    }
                }
            }
        }
    }

    json result;
    result["target_address"] = sa_format_address(static_cast<uint64_t>(target));
    result["references_found"] = found;
    result["references"] = std::move(refs);
    return tool_result_t::ok(std::to_string(found) + std::string(" references to ") +
                             sa_format_address(static_cast<uint64_t>(target)), result);
}

tool_result_t driver_read_teb(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_teb entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_read_teb", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(std::string("Missing or invalid tid parameter."));

    const std::uint32_t tid = *tid_opt;
    const std::uint32_t pid = device ? device->get_process_id() : 0;

    voyager::device_t::thread_context ctx{};
    const bool got_context = device && device->get_thread_context(tid, ctx);
    if (!got_context)
    {
        diag::log_tagged_fmt("drv_tools",
            "driver_read_teb_tctx_failed pid=%u tid=%u",
            pid,
            tid);
    }

    std::uint64_t teb_addr = 0;
    std::string teb_source;
    std::string teb_error;
    teb_resolution_diagnostics_t resolution_diag{};
    if (!resolve_teb_address_for_thread(tid, got_context ? &ctx : nullptr, teb_addr, teb_source, teb_error, resolution_diag))
    {
        json failure;
        failure["process_id"] = pid;
        failure["thread_id"] = tid;
        failure["teb_resolution"] = teb_resolution_diagnostics_to_json(resolution_diag);
        return tool_result_t::error(std::string("TEB address unavailable for TID ") +
                                    std::to_string(tid) + std::string(": ") + teb_error, failure);
    }

    constexpr std::size_t teb_read_size = 0x1680;
    std::vector<std::uint8_t> teb_bytes(teb_read_size, 0);
    const std::size_t bytes_read = device->read_raw(teb_addr, teb_bytes.data(), teb_bytes.size());
    diag::log_tagged_fmt("drv_tools",
        "driver_read_teb_read pid=%u tid=%u source=%s address=0x%llX requested=%zu actual=%zu",
        pid,
        tid,
        teb_source.c_str(),
        static_cast<unsigned long long>(teb_addr),
        teb_bytes.size(),
        bytes_read);

    json read_diag;
    read_diag["address"] = sa_format_address(static_cast<std::uint64_t>(teb_addr));
    read_diag["requested_size"] = teb_bytes.size();
    read_diag["bytes_read"] = bytes_read;
    read_diag["source"] = teb_source;

    if (bytes_read < teb_bytes.size())
    {
        diag::log_tagged_fmt("drv_tools",
            "driver_read_teb_read_failed pid=%u tid=%u source=%s address=0x%llX requested=%zu actual=%zu",
            pid,
            tid,
            teb_source.c_str(),
            static_cast<unsigned long long>(teb_addr),
            teb_bytes.size(),
            bytes_read);
        json failure;
        failure["process_id"] = pid;
        failure["thread_id"] = tid;
        failure["teb_resolution"] = teb_resolution_diagnostics_to_json(resolution_diag);
        failure["teb_read"] = read_diag;
        return tool_result_t::error(std::string("Failed to read complete TEB at ") +
                                    sa_format_address(static_cast<std::uint64_t>(teb_addr)) +
                                    std::string(" for TID ") + std::to_string(tid), failure);
    }

    auto read_u64 = [&](std::size_t offset) -> std::uint64_t
    {
        std::uint64_t value = 0;
        std::memcpy(&value, teb_bytes.data() + offset, sizeof(value));
        return value;
    };

    auto read_u32 = [&](std::size_t offset) -> std::uint32_t
    {
        std::uint32_t value = 0;
        std::memcpy(&value, teb_bytes.data() + offset, sizeof(value));
        return value;
    };


    json teb;
    teb["teb_address"] = sa_format_address(static_cast<uint64_t>(teb_addr));
    teb["thread_id"] = tid;
    teb["teb_source"] = teb_source;


    teb["exception_list"] = sa_format_address(static_cast<uint64_t>(read_u64(0x00)));
    teb["stack_base"] = sa_format_address(static_cast<uint64_t>(read_u64(0x08)));
    teb["stack_limit"] = sa_format_address(static_cast<uint64_t>(read_u64(0x10)));
    teb["sub_system_tib"] = sa_format_address(static_cast<uint64_t>(read_u64(0x18)));
    teb["fiber_data"] = sa_format_address(static_cast<uint64_t>(read_u64(0x20)));
    teb["arbitrary_user_pointer"] = sa_format_address(static_cast<uint64_t>(read_u64(0x28)));
    teb["self"] = sa_format_address(static_cast<uint64_t>(read_u64(0x30)));


    teb["environment_pointer"] = sa_format_address(static_cast<uint64_t>(read_u64(0x38)));
    teb["client_id_process"] = read_u64(0x40);
    teb["client_id_thread"] = read_u64(0x48);
    teb["active_rpc_handle"] = sa_format_address(static_cast<uint64_t>(read_u64(0x50)));
    teb["tls_pointer"] = sa_format_address(static_cast<uint64_t>(read_u64(0x58)));
    teb["peb_address"] = sa_format_address(static_cast<uint64_t>(read_u64(0x60)));
    teb["last_error_value"] = read_u32(0x68);
    teb["count_of_owned_critical_sections"] = read_u32(0x6C);


    json tls_slots = json::array();
    for (int i = 0; i < 64; ++i)
    {
        std::uint64_t slot_val = read_u64(0x1480 + static_cast<std::size_t>(i) * 8);
        if (slot_val != 0)
        {
            json slot;
            slot["index"] = i;
            slot["value"] = sa_format_address(static_cast<uint64_t>(slot_val));
            tls_slots.push_back(std::move(slot));
        }
    }
    teb["active_tls_slots"] = std::move(tls_slots);


    std::uint64_t dealloc_stack = read_u64(0x1478);
    teb["deallocation_stack"] = sa_format_address(static_cast<uint64_t>(dealloc_stack));


    std::uint64_t stack_base_val = read_u64(0x08);
    std::uint64_t stack_limit_val = read_u64(0x10);
    if (stack_base_val > stack_limit_val)
        teb["stack_size"] = stack_base_val - stack_limit_val;

    json result;
    result["teb_resolution"] = teb_resolution_diagnostics_to_json(resolution_diag);
    result["teb_read"] = read_diag;
    result["teb"] = std::move(teb);
    return tool_result_t::ok(std::string("TEB read for TID ") + std::to_string(tid), result);
}

tool_result_t driver_map_peb_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_map_peb_modules entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_map_peb_modules", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::string order = params.value("order", "all");
    const std::string filter = to_lower_ascii_copy(params.value("filter", ""));

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return tool_result_t::error(std::string("Failed to read PEB or LDR address is null"));


    struct ldr_entry_offsets_t {
        std::uint64_t list_head_offset;
        std::uint64_t base_dll_field_offset;
        std::string name;
    };

    std::vector<ldr_entry_offsets_t> lists_to_walk;

    if (order == "load" || order == "all")
        lists_to_walk.push_back({0x10, 0x30, "InLoadOrder"});
    if (order == "memory" || order == "all")
        lists_to_walk.push_back({0x20, 0x20, "InMemoryOrder"});
    if (order == "init" || order == "all")
        lists_to_walk.push_back({0x30, 0x10, "InInitializationOrder"});

    json all_lists;

    for (const auto& list_info : lists_to_walk)
    {
        const std::uint64_t list_head = peb.ldr_address + list_info.list_head_offset;
        std::uint64_t current = device->read<std::uint64_t>(list_head);

        json modules_arr = json::array();
        int iter = 0;
        constexpr int MAX_ITER = 1024;

        while (current != 0 && current != list_head && iter++ < MAX_ITER)
        {


            std::uint64_t ldr_entry;
            if (list_info.list_head_offset == 0x10)
                ldr_entry = current;
            else if (list_info.list_head_offset == 0x20)
                ldr_entry = current - 0x10;
            else
                ldr_entry = current - 0x20;

            const std::uint64_t base = device->read<std::uint64_t>(ldr_entry + 0x30);
            const std::uint64_t entry_point = device->read<std::uint64_t>(ldr_entry + 0x38);
            const std::uint32_t size = device->read<std::uint32_t>(ldr_entry + 0x40);

            const std::string name = read_remote_unicode_ascii(device.get(),
                device->read<std::uint64_t>(ldr_entry + 0x60),
                device->read<std::uint16_t>(ldr_entry + 0x58), 520);

            const std::string path = read_remote_unicode_ascii(device.get(),
                device->read<std::uint64_t>(ldr_entry + 0x50),
                device->read<std::uint16_t>(ldr_entry + 0x48), 1024);

            const std::uint32_t flags = device->read<std::uint32_t>(ldr_entry + 0x68);
            const std::uint16_t load_count = device->read<std::uint16_t>(ldr_entry + 0x70);
            const std::uint16_t tls_index = device->read<std::uint16_t>(ldr_entry + 0x72);

            if (base == 0 && name.empty())
            {
                std::uint64_t next = device->read<std::uint64_t>(current);
                if (next == current) break;
                current = next;
                continue;
            }

            if (!filter.empty())
            {
                std::string lower_name = to_lower_ascii_copy(name);
                std::string lower_path = to_lower_ascii_copy(path);
                if (lower_name.find(filter) == std::string::npos &&
                    lower_path.find(filter) == std::string::npos)
                {
                    std::uint64_t next = device->read<std::uint64_t>(current);
                    if (next == current) break;
                    current = next;
                    continue;
                }
            }

            json mod;
            mod["order_index"] = iter - 1;
            mod["base_address"] = sa_format_address(static_cast<uint64_t>(base));
            mod["entry_point"] = sa_format_address(static_cast<uint64_t>(entry_point));
            mod["size"] = size;
            mod["name"] = name;
            mod["full_path"] = path;
            mod["flags"] = sa_format_address(static_cast<uint64_t>(flags));
            mod["load_count"] = load_count;
            mod["tls_index"] = tls_index;


            json flag_details;
            flag_details["packed_redirected"] = (flags & 0x00000002) != 0;
            flag_details["static_import"] = (flags & 0x00000020) != 0;
            flag_details["image_dll"] = (flags & 0x00000004) != 0;
            flag_details["load_in_progress"] = (flags & 0x00001000) != 0;
            flag_details["entry_processed"] = (flags & 0x00004000) != 0;
            flag_details["dont_call_for_threads"] = (flags & 0x00040000) != 0;
            flag_details["process_attach_called"] = (flags & 0x00080000) != 0;
            mod["flag_details"] = std::move(flag_details);

            modules_arr.push_back(std::move(mod));

            std::uint64_t next = device->read<std::uint64_t>(current);
            if (next == current) break;
            current = next;
        }

        all_lists[list_info.name] = std::move(modules_arr);
    }

    json result;
    result["peb_address"] = sa_format_address(static_cast<uint64_t>(peb.peb_address));
    result["ldr_address"] = sa_format_address(static_cast<uint64_t>(peb.ldr_address));
    result["image_base"] = sa_format_address(static_cast<uint64_t>(peb.image_base));
    result["lists"] = std::move(all_lists);
    if (!filter.empty()) result["filter"] = filter;
    return tool_result_t::ok(std::string("PEB LDR module lists enumerated"), result);
}

tool_result_t driver_set_page_guard(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_set_page_guard entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("driver_set_page_guard", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const std::string operation = params.value("operation", "set");

    if (!params.contains("address"))
        return tool_result_t::error(std::string("Missing required parameter: address"));

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt) return tool_result_t::error(std::string("Invalid address"));

    const std::uint64_t target_addr = *addr_opt;
    const std::size_t size = params.value("size", 4096);

    if (operation == "set")
    {

        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(std::string("Failed to query memory at ") +
                                        sa_format_address(static_cast<uint64_t>(target_addr)));

        std::uint32_t current_protect = region.protect;
        std::uint32_t new_protect = current_protect | 0x100;

        std::uint32_t old_protect = 0;
        if (!device->protect_memory(target_addr, size, new_protect, &old_protect))
            return tool_result_t::error(std::string("Failed to set PAGE_GUARD at ") +
                                        sa_format_address(static_cast<uint64_t>(target_addr)));

        json result;
        result["operation"] = "set";
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["size"] = size;
        result["old_protection"] = sa_format_address(static_cast<uint64_t>(old_protect));
        result["new_protection"] = sa_format_address(static_cast<uint64_t>(new_protect));
        result["note"] = std::string("PAGE_GUARD set. Next access triggers STATUS_GUARD_PAGE_VIOLATION (0x80000001). "
                                "Guard is automatically cleared after first hit. Re-apply as needed.");
        return tool_result_t::ok(std::string("PAGE_GUARD set at ") +
                                 sa_format_address(static_cast<uint64_t>(target_addr)), result);
    }
    else if (operation == "remove")
    {
        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(std::string("Failed to query memory"));

        std::uint32_t new_protect = region.protect & ~0x100u;
        std::uint32_t old_protect = 0;
        if (!device->protect_memory(target_addr, size, new_protect, &old_protect))
            return tool_result_t::error(std::string("Failed to remove PAGE_GUARD"));

        json result;
        result["operation"] = "remove";
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["old_protection"] = sa_format_address(static_cast<uint64_t>(old_protect));
        result["new_protection"] = sa_format_address(static_cast<uint64_t>(new_protect));
        return tool_result_t::ok(std::string("PAGE_GUARD removed at ") +
                                 sa_format_address(static_cast<uint64_t>(target_addr)), result);
    }
    else if (operation == "query")
    {
        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(std::string("Failed to query memory"));

        json result;
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["base_address"] = sa_format_address(static_cast<uint64_t>(region.base));
        result["region_size"] = region.size;
        result["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
        result["has_guard"] = (region.protect & 0x100) != 0;
        result["state"] = sa_format_address(static_cast<uint64_t>(region.state));
        return tool_result_t::ok(
            (region.protect & 0x100) ? std::string("PAGE_GUARD is active") : std::string("PAGE_GUARD is not set"),
            result);
    }

    return tool_result_t::error(std::string("Invalid operation. Use 'set', 'remove', or 'query'."));
}


tool_result_t driver_kernel_symbols(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_kernel_symbols entry");
    std::string action = "status";
    if (params.contains("action") && params["action"].is_string())
        action = params["action"].get<std::string>();
    std::transform(action.begin(), action.end(), action.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (action == "reload")
    {
        kernel_symbols::request_reload();
        json result;
        result["reloading"] = true;
        result["symbols"] = kernel_symbols_status_json();
        return tool_result_t::ok(std::string("Kernel symbol engine reload scheduled."), result);
    }

    kernel_symbols::ensure_started();

    if (action == "status")
    {
        json result = kernel_symbols_status_json();
        return tool_result_t::ok(std::string("Kernel symbol engine status."), result);
    }

    if (action == "resolve")
    {
        std::string expression;
        if (params.contains("expression") && params["expression"].is_string())
            expression = params["expression"].get<std::string>();
        if (expression.empty())
            return tool_result_t::error(std::string("Missing expression to resolve."));
        if (const auto value = kernel_symbols::resolve(expression))
        {
            json result;
            result["expression"] = expression;
            result["address"] = sa_format_address(*value);
            result["pretty"] = kernel_symbols::format(*value);
            result["symbols"] = kernel_symbols_status_json();
            return tool_result_t::ok(std::string("Resolved kernel symbol expression."), result);
        }
        json details;
        details["expression"] = expression;
        details["symbols"] = kernel_symbols_status_json();
        return tool_result_t::error(
            std::string("Could not resolve the kernel symbol expression."),
            std::string("symbol_resolve_failed"), details);
    }

    if (action == "lookup")
    {
        std::uint64_t address = 0;
        std::string address_error;
        if (!parse_kernel_address_or_symbol(params, "address", address, address_error))
            return tool_result_t::error(std::string("Missing or invalid address: ") + address_error);
        json result;
        result["address"] = sa_format_address(address);
        result["pretty"] = kernel_symbols::format(address);
        if (const auto hit = kernel_symbols::lookup(address))
        {
            json found;
            found["resolved"] = hit->resolved;
            found["module"] = hit->module;
            found["symbol"] = hit->symbol;
            found["symbol_base_va"] = sa_format_address(hit->symbol_base_va);
            found["offset"] = hit->offset;
            found["offset_hex"] = sa_format_address(hit->offset);
            found["exact"] = hit->exact;
            result["lookup"] = std::move(found);
        }
        else
        {
            result["lookup"] = nullptr;
        }
        result["symbols"] = kernel_symbols_status_json();
        return tool_result_t::ok(std::string("Looked up kernel address."), result);
    }

    if (action == "struct")
    {
        std::string name;
        if (params.contains("name") && params["name"].is_string())
            name = params["name"].get<std::string>();
        if (name.empty())
            return tool_result_t::error(std::string("Missing struct name."));
        if (const auto desc = kernel_symbols::describe_struct(name))
        {
            json result;
            result["name"] = desc->name;
            result["size"] = desc->size;
            json fields = json::array();
            for (const auto& field : desc->fields)
            {
                json entry;
                entry["name"] = field.name;
                entry["type"] = field.type;
                entry["offset"] = field.offset;
                entry["size"] = field.size;
                fields.push_back(std::move(entry));
            }
            result["fields"] = std::move(fields);
            result["symbols"] = kernel_symbols_status_json();
            return tool_result_t::ok(std::string("Described kernel struct layout."), result);
        }
        json details;
        details["struct"] = name;
        details["symbols"] = kernel_symbols_status_json();
        return tool_result_t::error(
            std::string("Struct was not found in the loaded kernel PDB."),
            std::string("struct_not_found"), details);
    }

    if (action == "modules")
    {
        std::vector<std::uint8_t> module_buffer;
        sys_module_info_t* info = nullptr;
        std::string module_error;
        kernel_module_query_diagnostics_t query_diagnostics{};
        if (!query_kernel_modules(module_buffer, info, module_error, &query_diagnostics,
                kernel_module_query_fallback_policy::allow_readonly_kernel_base_evidence))
            return kernel_module_query_error_result(module_error, query_diagnostics);
        json modules_arr = json::array();
        for (ULONG i = 0; i < info->NumberOfModules; ++i)
        {
            const auto& m = info->Modules[i];
            json entry;
            entry["name"] = bounded_kernel_module_name(m);
            entry["path"] = bounded_kernel_module_path(m);
            entry["base"] = sa_format_address(
                static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(m.ImageBase)));
            entry["size"] = m.ImageSize;
            entry["size_hex"] = sa_format_address(static_cast<uint64_t>(m.ImageSize));
            modules_arr.push_back(std::move(entry));
        }
        json result;
        result["modules"] = std::move(modules_arr);
        result["total_loaded"] = info->NumberOfModules;
        result["module_base_diagnostics"] = kernel_module_query_diagnostics_json(query_diagnostics);
        result["symbols"] = kernel_symbols_status_json();
        return tool_result_t::ok(
            std::string("Enumerated ") + std::to_string(info->NumberOfModules) + std::string(" loaded kernel modules."),
            result);
    }

    return tool_result_t::error(
        std::string("Invalid action. Use 'status', 'reload', 'resolve', 'lookup', 'struct', or 'modules'."));
}


void register_driver_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("drv_tools", "register_driver_tools entry");
    s_deferred_tool_list = &srv.get_tools();







    register_compat(srv, {
        std::string("driver_read_pointer_chain"), std::string("driver"),
        std::string("Follow a chain of pointer dereferences through target process memory via kernel driver. "
               "Useful for traversing linked lists, object hierarchies, and obfuscated data structures."),
        {{std::string("address"), std::string("string"), std::string("Starting virtual address"), false},
          {std::string("base_address"), std::string("string"), std::string("Alias for address."), false},
         {std::string("offsets"), std::string("array"),
          std::string("Array of byte offsets to apply after each dereference (e.g. [0, 48, 24])"), false, {},
           json::object({{"type", "number"}})},
          {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_read_pointer_chain, false});


    register_compat(srv, {
        std::string("driver_enumerate_kernel_modules"), std::string("driver"),
        std::string("Enumerate ALL loaded kernel drivers and modules via NtQuerySystemInformation. "
               "Returns each driver's name, NT path, resolved disk path, kernel base address, "
               "and image size. Does NOT require the kernel driver to be connected - works "
               "purely from usermode. Use filter to search for a specific driver "
               "(e.g. filter='EasyAntiCheat' or filter='eac')."),
        {{std::string("filter"), std::string("string"),
          std::string("Case-insensitive substring filter applied to module name and path (e.g. 'eac', 'ntfs')"), false},
         {std::string("limit"), std::string("number"),
          std::string("Maximum number of modules to return (default 500)"), false}},
        driver_enumerate_kernel_modules, false});

    register_compat(srv, {
        std::string("driver_read_kernel_memory"), std::string("driver"),
        std::string("Read an arbitrary canonical kernel virtual-address range using the live kernel DTB. "
               "This is independent of the attached process address space and is intended for ntoskrnl globals, "
               "driver globals, executive objects, pool allocations, and other live kernel structures. "
               "The address accepts plain hex/decimal values and kernel symbol expressions such as "
               "'nt!NtCreateFile+0x10' or 'PsInitialSystemProcess' once the kernel symbol engine is ready. "
               "Returns exact packed hex, ASCII rendering, byte counts, and whether the full request was readable. "
               "With annotate=true (default) also returns annotated_lines: 16-byte rows whose embedded qword "
               "pointers are resolved to 'nt!Symbol+0xN' or '<module>+0xN'. "
               "Pass struct='<PDB struct name>' (for example '_EPROCESS' or 'EPROCESS') to decode the read buffer "
               "field-by-field from the live kernel PDB."),
        {{std::string("address"), std::string("string"), std::string("Canonical kernel virtual address (0x...) or symbol expression such as 'nt!NtCreateFile+0x10'"), true},
         {std::string("size"), std::string("number"), std::string("Bytes to read, from 1 through 1048576"), true},
         {std::string("annotate"), std::string("boolean"), std::string("Attach symbolicated 16-byte annotated_lines with pointer resolution (default true)"), false},
         {std::string("struct"), std::string("string"), std::string("Optional PDB struct name used to decode the read buffer field-by-field"), false}},
        driver_read_kernel_memory, true});

    register_compat(srv, {
        std::string("driver_kernel_symbols"), std::string("driver"),
        std::string("Manage the in-memory kernel symbol engine (MemPDB over the live ntoskrnl debug directory, cached "
               "under the user profile, resolved through the Microsoft symbol server when missing). "
               "Actions: status (default) reports engine state, PDB name, cache path, symbol counts and ntoskrnl base; "
               "reload drops all state and re-downloads/re-parses after a driver reconnect; "
               "resolve (expression='nt!NtCreateFile+0x10' or bare 'PsInitialSystemProcess') maps a symbol expression to an address; "
               "lookup (address=0x... or symbol expression) maps an address to the nearest symbol or containing kernel module; "
               "struct (name='_EPROCESS') returns the PDB field layout; "
               "modules lists loaded kernel modules with base, size, and path."),
        {{std::string("action"), std::string("string"), std::string("status | reload | resolve | lookup | struct | modules"), false},
         {std::string("expression"), std::string("string"), std::string("Symbol expression for action=resolve, for example 'nt!NtCreateFile+0x10'"), false},
         {std::string("address"), std::string("string"), std::string("Kernel address or symbol expression for action=lookup"), false},
         {std::string("name"), std::string("string"), std::string("PDB struct name for action=struct (leading underscore optional)"), false}},
        driver_kernel_symbols, true});


    register_compat(srv, {
        std::string("driver_write_kernel_memory"), std::string("driver"),
        std::string("Write arbitrary canonical kernel virtual memory through the live kernel DTB. "
               "The operation fails closed unless the original range can be read completely, optionally compare-checks expected_bytes, "
               "requires confirm_unsafe=true for live mutation, and performs an exact readback verification. "
               "Use dry_run=true to validate the address, payload, and optional precondition without changing memory."),
        {{std::string("address"), std::string("string"), std::string("Canonical kernel virtual address to modify"), true},
         {std::string("bytes"), std::string("string"), std::string("Replacement bytes as packed hex or space/comma-separated hex bytes"), true},
         {std::string("expected_bytes"), std::string("string"), std::string("Optional exact current bytes required before the write is attempted"), false},
         {std::string("confirm_unsafe"), std::string("boolean"), std::string("Must be true for a live kernel write"), false},
         {std::string("dry_run"), std::string("boolean"), std::string("Validate and pre-read without modifying kernel memory"), false}},
        driver_write_kernel_memory, false});

    register_compat(srv, {
        std::string("search_kernel_memory"), std::string("driver"),
        std::string("Search a bounded live kernel virtual-address range for a byte pattern with ?? wildcards. "
               "Specify either address/start_address plus size, or a unique loaded kernel module name with optional offset and size. "
               "The scanner preserves overlap across partial and chunked reads, skips unreadable pages, honors cancellation, "
               "and reports scanned/unreadable byte counts and bounded match results."),
        {{std::string("pattern"), std::string("string"), std::string("Hex byte pattern such as '48 8B ?? ?? 89' or '488B????89'"), true},
         {std::string("address"), std::string("string"), std::string("Start of an explicit canonical kernel range; alias: start_address"), false},
         {std::string("start_address"), std::string("string"), std::string("Alias for address"), false},
         {std::string("size"), std::string("number"), std::string("Explicit range size, or optional module scan length; maximum 4294967296"), false},
         {std::string("module"), std::string("string"), std::string("Unique loaded kernel module filename or path used instead of address"), false},
         {std::string("offset"), std::string("number"), std::string("Offset into module where scanning begins; default 0"), false},
         {std::string("chunk_size"), std::string("number"), std::string("Read chunk size from 4096 through 1048576; default 65536"), false},
         {std::string("max_results"), std::string("number"), std::string("Maximum matches to return from 1 through 4096; default 256"), false}},
        search_kernel_memory, true});




    register_compat(srv, {
        std::string("driver_allocate_memory"), std::string("driver"),
        std::string("Allocate RWX memory in the attached target process. "
               "Uses kernel-level ZwAllocateVirtualMemory with PAGE_EXECUTE_READWRITE. "
               "Max 16MB per allocation. Useful for injecting shellcode, writing strings "
               "for function arguments, or setting up data structures remotely. "
               "Requires driver connected and process attached."),
        {{std::string("size"), std::string("string"),
                    std::string("Number of bytes to allocate (max 16777216 = 16MB)"), true},
                 {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_allocate_memory, false});

    register_compat(srv, {
        std::string("driver_free_memory"), std::string("driver"),
        std::string("Free previously allocated memory in the attached target process. "
               "Uses kernel-level ZwFreeVirtualMemory with MEM_RELEASE. "
               "Requires driver connected and process attached."),
        {{std::string("address"), std::string("string"),
                    std::string("Address of the memory block to free (hex string like '0x...')"), true},
                 {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_free_memory, false});

    register_compat(srv, {
        std::string("driver_call_function"), std::string("driver"),
        std::string("Execute ANY function inside the attached target process via thread hijack. "
               "Suspends a target thread, redirects execution to injected shellcode that calls "
               "the specified function with up to 4 arguments, polls for completion, restores "
               "original thread context. Call stack is spoofed via JMP-RBX gadget. "
               "WARNING: Calling incorrect addresses or wrong arguments can crash the process. "
               "Common patterns: call LoadLibraryA to load DLLs, call LdrGetProcedureAddress "
               "to resolve exports, call VirtualProtect to change protections, call any "
               "game/anticheat function to observe behavior. "
                             "Requires driver connected, process attached, DTB solved. "
                             "For safety, execution requires confirm_unsafe=true unless dry_run=true."),
        {{std::string("address"), std::string("string"),
          std::string("Address of the function to call in the target process (hex)"), true},
         {std::string("arg1"), std::string("string"),
          std::string("First argument (RCX). Hex address or integer. Default 0"), false},
         {std::string("arg2"), std::string("string"),
          std::string("Second argument (RDX). Hex address or integer. Default 0"), false},
         {std::string("arg3"), std::string("string"),
          std::string("Third argument (R8). Hex address or integer. Default 0"), false},
         {std::string("arg4"), std::string("string"),
                    std::string("Fourth argument (R9). Hex address or integer. Default 0"), false},
                 {std::string("confirm_unsafe"), std::string("boolean"), std::string("Required for live execution. Must be true unless dry_run=true."), false},
         {std::string("allow_unsafe"), std::string("boolean"), std::string("Alias of confirm_unsafe."), false},
         {std::string("unsafe"), std::string("boolean"), std::string("Alias of confirm_unsafe."), false},
                 {std::string("dry_run"), std::string("boolean"), std::string("Preview call metadata without executing."), false},
                 {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_call_function, false});








    register_compat(srv, {
        std::string("driver_protect_memory"), std::string("driver"),
        std::string("Change virtual memory protection in the attached process via kernel ZwProtectVirtualMemory. "
               "Bypasses usermode hooks on VirtualProtect. Can set any protection including executable. "
               "Returns the old protection value."),
        {{std::string("address"), std::string("string"), std::string("Virtual address"), true},
         {std::string("size"), std::string("string"), std::string("Region size (default 0x1000)"), false},
         {std::string("protect"), std::string("string"),
          std::string("New protection value: 0x40=PAGE_EXECUTE_READWRITE, 0x20=PAGE_EXECUTE_READ, "
             "0x04=PAGE_READWRITE, 0x02=PAGE_READONLY"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_protect_memory, false});


    register_compat(srv, {
        std::string("driver_read_peb"), std::string("driver"),
        std::string("Read the Process Environment Block (PEB) of the attached process via kernel. "
               "Returns PEB address, image base, BeingDebugged flag, NtGlobalFlag, "
               "loader data address, process heap, and heap info."),
        {{std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}}, driver_read_peb, true});


    register_compat(srv, {
        std::string("driver_set_hw_breakpoint"), std::string("driver"),
        std::string("Set a hardware breakpoint on a thread in the attached process using debug registers. "
               "Uses DR0-DR3 (4 breakpoints max per thread). Operates via kernel PsSetContextThread "
               "so it's invisible to usermode anti-debug. Types: execute (break on execution), "
               "write (break on memory write), readwrite (break on read or write). "
               "After setting, the thread will trigger a SINGLE_STEP exception when the breakpoint fires."),
        {{std::string("tid"), std::string("string"), std::string("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {std::string("address"), std::string("string"), std::string("Address to break on"), true},
         {std::string("index"), std::string("number"),
          std::string("Debug register index 0-3 (default 0). Each thread supports 4 HW breakpoints."), false},
         {std::string("type"), std::string("string"),
          std::string("Breakpoint type: execute (default), write, readwrite"), false,
          {std::string("execute"), std::string("write"), std::string("readwrite")}},
         {std::string("size"), std::string("number"),
                    std::string("Watched region size in bytes: 1 (default), 2, 4, or 8"), false},
                 {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_set_hw_breakpoint, false});

    register_compat(srv, {
        std::string("driver_clear_hw_breakpoint"), std::string("driver"),
        std::string("Clear a hardware breakpoint on a thread. Removes the address from the specified "
               "debug register and disables it in DR7."),
                {{std::string("tid"), std::string("string"), std::string("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {std::string("index"), std::string("number"),
                    std::string("Debug register index 0-3 to clear (default 0)"), false},
                 {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_clear_hw_breakpoint, false});

    register_compat(srv, {
        std::string("driver_resolve_export"), std::string("driver"),
        std::string("Resolve an export function address from a PE module in the attached process. "
               "Walks the PE export directory via physical memory reads. Useful for finding API "
               "addresses without relying on import tables (which may be obfuscated by packers)."),
        {{std::string("name"), std::string("string"), std::string("Export function name to resolve. Alias: export_name."), false},
          {std::string("export_name"), std::string("string"), std::string("Alias for name."), false},
         {std::string("module_base"), std::string("string"),
           std::string("Module base address (default: attached process image base)"), false},
          {std::string("module"), std::string("string"), std::string("Module name/path or base address string. Alias: module_name."), false},
          {std::string("module_name"), std::string("string"), std::string("Alias for module."), false},
          {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_resolve_export, true});

    register_compat(srv, {
        std::string("driver_virtual_to_physical"), std::string("driver"),
        std::string("Translate a virtual address to its physical address using the process DTB. "
               "Performs a full 4-level page table walk (PML4->PDPT->PD->PT) in kernel."),
        {{std::string("address"), std::string("string"), std::string("Virtual address to translate"), true}},
        driver_virtual_to_physical, true});


    register_compat(srv, {
        std::string("driver_defer_action"), std::string("driver"),
        std::string("PRE-SCHEDULE driver tool calls to execute THE INSTANT a kernel module loads "
               "or a process starts. This solves the critical timing problem: many drivers "
               "(EAC, BattlEye, Vanguard) wipe their IAT, decrypt code, or perform anti-RE "
               "operations during initialization. By the time you can manually react, the "
               "evidence is already destroyed. This tool lets you queue actions (read memory, "
               "set HW breakpoints, dump module, etc.) that fire IMMEDIATELY when the target "
               "appears - before its init routine runs. "
               "\n\nTemplate parameters in action params are resolved at trigger time:\n"
               "  ${module_base} - runtime kernel base address of the loaded module\n"
               "  ${module_size} - module image size\n"
               "  ${module_name} - resolved module filename\n"
               "  ${pid} - process ID (for process_start)\n"
               "  ${base_address} - process image base (for process_start)\n"
               "\nAddress arithmetic: '${module_base}+0x17C000' computes base+offset automatically.\n"
               "\nExample: to capture EAC's IAT before it's wiped:\n"
               "  wait_for='kernel_module_load', target='EasyAntiCheat_EOS.sys',\n"
               "  actions=[{tool:'driver_read_kernel_memory', params:{address:'${module_base}+0x17C000', size:64}}]"),
        {{std::string("wait_for"), std::string("string"),
          std::string("Condition type: 'kernel_module_load' or 'process_start'"), true, {},
          {std::string("kernel_module_load"), std::string("process_start")}},
         {std::string("target"), std::string("string"),
          std::string("Module or process name to watch for (case-insensitive substring match). "
                 "E.g. 'EasyAntiCheat_EOS.sys', 'BEService.exe'"), true},
         {std::string("actions"), std::string("array"),
          std::string("Array of tool calls to execute when condition is met. "
                 "Each entry: {\"tool\": \"tool_name\", \"params\": {...}}. "
                 "Compatibility aliases accepted: top-level {action, params} and per-entry {action, params}. "
             "Params may use ${module_base}, ${module_size}, ${pid}, ${base_address} templates."), false, {},
          json::object({{"type", "object"},
                        {"properties", json::object({
                            {"tool", json::object({{"type", "string"}})},
                            {"action", json::object({{"type", "string"}})},
                            {"params", json::object({{"type", "object"}})}
                        })}
          })},
         {std::string("timeout"), std::string("number"),
          std::string("Maximum seconds to wait for the condition (default 300 = 5 minutes)"), false},
         {std::string("poll_interval"), std::string("number"),
          std::string("Milliseconds between condition checks (default 50ms). Lower = faster reaction "
                 "but more CPU. For IAT capture, use 10-25ms."), false}},
        driver_defer_action, false});

    register_compat(srv, {
        std::string("driver_list_deferred_actions"), std::string("driver"),
        std::string("List all registered deferred actions and their current status "
               "(pending, watching, triggered, completed, failed, cancelled, timed_out). "
               "Shows condition, target, number of queued actions, trigger info, and result counts."),
        {},
        driver_list_deferred_actions, false});

    register_compat(srv, {
        std::string("driver_cancel_deferred_action"), std::string("driver"),
        std::string("Cancel a pending/watching deferred action by its action_id. "
               "Only works if the action hasn't been triggered yet."),
        {{std::string("action_id"), std::string("number"),
          std::string("The action ID returned by driver_defer_action"), true}},
        driver_cancel_deferred_action, false});

    register_compat(srv, {
        std::string("driver_get_deferred_results"), std::string("driver"),
        std::string("Get the detailed results of a deferred action after it has been triggered. "
               "Returns the trigger context (module base, PID, etc.), the status of each "
               "queued tool call (success/failure, output data), and timing information. "
               "Use this to retrieve data captured by pre-scheduled actions."),
        {{std::string("action_id"), std::string("number"),
          std::string("The action ID returned by driver_defer_action"), true}},
        driver_get_deferred_results, false});




    register_compat(srv, {
        std::string("driver_sniff_network_buffers"), std::string("driver"),
        std::string("Manage a kernel-level network buffer sniff session that works with hardware breakpoints to "
               "capture plaintext network buffers in memory BEFORE encryption. Wireshark only sees encrypted "
               "payloads; this tool captures the data before it reaches ws2_32.dll!send, "
               "afd.sys!AfdFastIoDeviceControl, or a custom game/malware encryption function.\n\n"
               "Workflow:\n"
               "1. Call with address + buffer_register + size_register to START session\n"
               "2. Set HW breakpoint on the address via driver_set_hw_breakpoint\n"
               "3. When BP fires, read thread context, read buffer from memory, call with operation='store'\n"
               "4. Call with operation='get' to retrieve all captured buffers\n"
               "5. Call with operation='stop' when done\n\n"
               "This is a composite tool that coordinates with driver_set_hw_breakpoint and read_memory."),
        {{std::string("address"), std::string("string"),
          std::string("Address of the send/recv/encrypt function (for 'start' operation)"), false},
         {std::string("buffer_register"), std::string("string"),
          std::string("Register containing the buffer pointer (e.g., 'rcx', 'rdx', 'r8')"), false},
         {std::string("size_register"), std::string("string"),
          std::string("Register containing the buffer size (e.g., 'rdx', 'r8', 'r9')"), false},
         {std::string("max_packets"), std::string("number"),
          std::string("Max captures before auto-stop (default 1, max 16)"), false},
         {std::string("operation"), std::string("string"),
          std::string("'start' (default), 'store', 'get'/'results', 'stop'"), false, {},
          {std::string("start"), std::string("store"), std::string("stop"), std::string("get"), std::string("results")}},
         {std::string("bytes"), std::string("string"),
          std::string("Capture bytes for operation='store' as hex bytes, hex string, or text"), false},
         {std::string("data"), std::string("string"),
          std::string("Alias for bytes when operation='store'"), false},
         {std::string("hex"), std::string("string"),
          std::string("Alias for bytes when operation='store'"), false},
         {std::string("timestamp"), std::string("number"),
          std::string("Capture timestamp for operation='store' (defaults to GetTickCount64)"), false},
         {std::string("thread_id"), std::string("number"),
          std::string("Capture thread id for operation='store' (defaults to current thread)"), false},
         {std::string("tid"), std::string("number"),
          std::string("Thread ID for breakpoint (default: 0 = first thread)"), false},
         {std::string("bp_index"), std::string("number"),
          std::string("Debug register index 0-3 (default: 0)"), false}},
        driver_sniff_network_buffers, false});






    register_compat(srv, {
        std::string("driver_reassemble_stream"), std::string("driver"),
        std::string("TCP stream reassembly engine. Like Wireshark's 'Follow TCP Stream' but from the kernel. "
               "Tracks TCP connections and reassembles the byte stream in order. Supports up to 8 "
               "concurrent streams, 64KB each. Operations: start, stop, get_data, list, clear."),
        {{std::string("operation"), std::string("string"), std::string("'start', 'stop', 'get'/'get_data', 'list', 'clear'"), false,
          {std::string("start"), std::string("stop"), std::string("get"), std::string("get_data"), std::string("list"), std::string("clear")}},
         {std::string("src_addr"), std::string("string"), std::string("Source IP of the connection to track"), false},
         {std::string("dst_addr"), std::string("string"), std::string("Destination IP"), false},
         {std::string("src_port"), std::string("number"), std::string("Source port"), false},
         {std::string("dst_port"), std::string("number"), std::string("Destination port"), false},
         {std::string("pid"), std::string("number"), std::string("Filter by PID"), false}},
        driver_reassemble_stream, false});









    register_compat(srv, {
        std::string("driver_enum_kernel_callbacks"), std::string("driver"),
        std::string("Enumerate kernel notification callbacks: process creation (PsSetCreateProcessNotifyRoutine), "
               "thread creation (PsSetCreateThreadNotifyRoutine), image load (PsSetLoadImageNotifyRoutine), "
               "registry (CmRegisterCallbackEx), object (ObRegisterCallbacks). Identifies which driver module "
               "registered each callback. Essential for understanding anti-cheat monitoring."),
        {},
        driver_enum_kernel_callbacks, true});

    register_compat(srv, {
        std::string("driver_detect_integrity_checks"), std::string("driver"),
        std::string("Check critical ntoskrnl exports for inline hooks (jmp, mov rax + jmp, int3). "
               "Scans NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess, MmCopyVirtualMemory, "
               "KeStackAttachProcess, and 14 other critical functions. Identifies hook owner module. "
               "Reveals which kernel functions anti-cheats are monitoring."),
        {},
        driver_detect_integrity_checks, true});

    register_compat(srv, {
        std::string("driver_detect_ssdt_hooks"), std::string("driver"),
        std::string("Detect SSDT (System Service Descriptor Table) hooks. Reads KeServiceDescriptorTable, "
               "resolves all syscall function pointers, and identifies entries redirected outside ntoskrnl. "
               "Anti-cheats hook SSDT to intercept NtReadVirtualMemory, NtOpenProcess, etc. "
               "Returns hooked syscall IDs, target addresses, and hook owner modules."),
        {},
        driver_detect_ssdt_hooks, true});

    register_compat(srv, {
        std::string("driver_enum_minifilters"), std::string("driver"),
        std::string("Enumerate registered filesystem minifilter drivers via Filter Manager (fltmgr.sys). "
               "Minifilters intercept file I/O - anti-cheats use them to monitor file access, "
               "prevent memory dumps, and detect injection DLLs. Returns filter names, altitudes, and owner modules."),
        {},
        driver_enum_minifilters, true});

    register_compat(srv, {
        std::string("driver_detect_etw_monitors"), std::string("driver"),
        std::string("Detect active ETW (Event Tracing for Windows) monitoring. Checks if the Threat Intelligence "
               "provider is active (monitors process injection, executable memory allocation). "
               "Scans for known security ETW provider GUIDs and identifies kernel modules that import EtwRegister/EtwWrite."),
        {},
        driver_detect_etw_monitors, true});

    register_compat(srv, {
        std::string("driver_detect_hidden_modules"), std::string("driver"),
        std::string("Detect manually mapped or hidden PE modules not in the PEB module list (usermode) or "
               "NtQuerySystemInformation list (kernel). Scans memory for PE headers at non-listed addresses. "
               "Finds injected DLLs, manual-mapped anti-cheat drivers, and stealth payloads. "
               "Returns hidden module addresses, sizes, and export names when available."),
        {{std::string("kernel"), std::string("boolean"), std::string("Scan kernel space instead of attached process (default: false)"), false}},
        driver_detect_hidden_modules, true});


    register_compat(srv, {
        std::string("driver_walk_heap"), std::string("driver"),
        std::string("Walk the NT heap structures of the attached process via kernel memory reads. "
               "Enumerates all process heaps from PEB.ProcessHeaps, walks segment chains, and lists "
               "heap entries with their addresses, sizes, and busy/free flags. Equivalent to Cheat Engine's "
               "dissect data/structures and x64dbg's heap view. Filter by min/max block size or free-only."),
        {{std::string("limit"), std::string("number"), std::string("Max heap entries to return (default 500, max 5000)"), false},
         {std::string("min_size"), std::string("number"), std::string("Only return entries >= this size in bytes"), false},
         {std::string("max_size"), std::string("number"), std::string("Only return entries <= this size in bytes"), false},
         {std::string("free_only"), std::string("boolean"), std::string("Only return free (non-busy) blocks (default false)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override"), false}},
        driver_walk_heap, true});

    register_compat(srv, {
        std::string("driver_enumerate_handles"), std::string("driver"),
        std::string("Enumerate kernel object handles system-wide or for a specific process via NtQuerySystemInformation. "
               "Returns handle values, types (Process, Thread, File, Section, Key, Event, Mutant, etc.), "
               "kernel object addresses, and granted access masks. Equivalent to x64dbg's Handles tab "
               "and Process Hacker's handle list. Filter by PID or object type name."),
        {{std::string("pid"), std::string("number"), std::string("Filter by process ID (0 = all processes)"), false},
         {std::string("type_filter"), std::string("string"), std::string("Filter by type name substring (e.g. 'Process', 'File')"), false},
         {std::string("limit"), std::string("number"), std::string("Max handles to return (default 500, max 10000)"), false}},
        driver_enumerate_handles, true});





    register_compat(srv, {
        std::string("driver_enumerate_windows"), std::string("driver"),
        std::string("List all windows (HWND) owned by a process. Returns window handle, parent, class name, "
               "title text, visibility, position/size rect, and style flags. Equivalent to x64dbg's "
               "Window tab and Spy++ functionality. Useful for finding game overlay windows, "
               "anti-cheat UI, hidden dialogs, and message-only windows."),
        {{std::string("pid"), std::string("number"), std::string("Target process ID (default: attached PID)"), false},
         {std::string("include_children"), std::string("boolean"), std::string("Include child windows (default true)"), false},
         {std::string("limit"), std::string("number"), std::string("Max windows (default 200, max 2000)"), false}},
        driver_enumerate_windows, true});


    register_compat(srv, {
        std::string("driver_assemble"), std::string("driver"),
        std::string("Assemble x86-64 instructions to machine code bytes. Supports common instructions: "
               "NOP, RET, INT3, PUSH/POP reg, MOV reg/imm64, XOR reg/reg, JMP/CALL (reg or address), "
               "SUB RSP/imm, ADD RSP/imm. Multi-line input (one instruction per line). "
               "Optionally writes assembled bytes to target process memory. "
               "Equivalent to x64dbg's built-in assembler and Cheat Engine's auto-assembler."),
        {{std::string("assembly"), std::string("string"), std::string("Assembly text (one instruction per line)"), true},
         {std::string("address"), std::string("string"), std::string("Base address for relative calculations (default 0x140000000)"), false},
         {std::string("write_to"), std::string("string"), std::string("If specified, write assembled bytes to this address in the attached process"), false}},
        driver_assemble, false});


    register_compat(srv, {
        std::string("driver_find_references"), std::string("driver"),
        std::string("Find all memory locations that reference a target address. Scans for both direct "
               "64-bit pointer matches and RIP-relative (rel32) references in code sections. "
               "Equivalent to x64dbg's 'Find References' and IDA's xrefs but in live runtime memory. "
               "Useful for finding vtable entries, function pointer tables, and cross-references "
               "that only exist at runtime."),
        {{std::string("target_address"), std::string("string"), std::string("Address to find references to (hex)"), true},
         {std::string("limit"), std::string("number"), std::string("Max references (default 100, max 5000)"), false},
         {std::string("scan_code"), std::string("boolean"), std::string("Scan executable regions (default true)"), false},
         {std::string("scan_data"), std::string("boolean"), std::string("Scan data regions (default true)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override"), false}},
        driver_find_references, true});

    register_compat(srv, {
        std::string("driver_read_teb"), std::string("driver"),
        std::string("Read the Thread Environment Block (TEB) for a thread via kernel driver. "
               "Extracts: NT_TIB (exception list, stack base/limit), TLS slots with values, "
               "PEB address, client ID, last error, critical section count, stack size. "
               "Equivalent to x64dbg's TEB view. Requires tid of the target thread."),
        {{std::string("tid"), std::string("string"), std::string("Thread ID"), true},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override"), false}},
        driver_read_teb, true});

    register_compat(srv, {
        std::string("driver_map_peb_modules"), std::string("driver"),
        std::string("Walk ALL three PEB LDR linked lists: InLoadOrder, InMemoryOrder, InInitializationOrder. "
               "Returns complete module details: base, entry point, size, name, full path, flags "
               "(static import, entry processed, process attach called, etc.), load count, TLS index. "
               "Order differences reveal manually mapped modules and load-order anomalies. "
               "More detailed than basic module enumeration - shows all three orderings and decoded flags."),
        {{std::string("order"), std::string("string"), std::string("Which list: load, memory, init, or all (default all)"), false,
          {std::string("load"), std::string("memory"), std::string("init"), std::string("all")}},
         {std::string("filter"), std::string("string"), std::string("Module name/path substring filter (case-insensitive)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override"), false}},
        driver_map_peb_modules, true});

    register_compat(srv, {
        std::string("driver_set_page_guard"), std::string("driver"),
        std::string("Set, remove, or query PAGE_GUARD protection on memory in the attached process. "
               "PAGE_GUARD triggers STATUS_GUARD_PAGE_VIOLATION exception on first access - "
               "equivalent to Cheat Engine's memory breakpoint / 'Break on Access'. "
               "The guard auto-clears after first hit. Operations: set, remove, query."),
        {{std::string("operation"), std::string("string"), std::string("'set', 'remove', or 'query'"), true,
          {std::string("set"), std::string("remove"), std::string("query")}},
         {std::string("address"), std::string("string"), std::string("Target memory address (hex)"), true},
         {std::string("size"), std::string("number"), std::string("Size of the guarded region in bytes (default 4096)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override"), false}},
        driver_set_page_guard, false});
    diag::log_tagged_fmt("drv_tools", "register_driver_tools done");
}

}
