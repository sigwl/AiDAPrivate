#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "mcp_standalone.hpp"
#include "../tools/standalone_tools_fwd.hpp"
#include "sandbox.hpp"
#include "standalone_driver.hpp"
#include "vm_guest_bridge.hpp"
#include "standalone_settings.hpp"
#include "zydis_disasm.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../infra/cancellation_watchdog.hpp"
#include "../session/analysis_session.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <future>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace
{
    std::string hex_addr(uint64_t value)
    {
        char buf[24];
        snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
        return buf;
    }

    bool parse_addr_literal(const std::string& text, uint64_t& out)
    {
        try {
            if (text.size() > 2 && text[0] == '0' && (text[1] == 'b' || text[1] == 'B')) {
                uint64_t value = 0;
                for (size_t i = 2; i < text.size(); ++i) {
                    const char c = text[i];
                    if (c != '0' && c != '1')
                        return false;
                    if (value > (std::numeric_limits<uint64_t>::max() >> 1))
                        return false;
                    value = (value << 1) | static_cast<uint64_t>(c == '1');
                }
                out = value;
                return true;
            }
            size_t idx = 0;
            out = std::stoull(text, &idx, 0);
            return idx == text.size();
        } catch (...) {
            return false;
        }
    }

    bool parse_addr(const std::string& text, uint64_t& out)
    {
        if (text.empty() || text.size() > 4096)
            return false;
        size_t pos = 0;
        auto skip_space = [&]() {
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
                ++pos;
        };

        skip_space();
        if (pos == text.size())
            return false;

        uint64_t result = 0;
        bool first = true;
        char operation = '+';
        while (pos < text.size()) {
            if (!first) {
                skip_space();
                if (pos == text.size() || (text[pos] != '+' && text[pos] != '-'))
                    return false;
                operation = text[pos++];
                skip_space();
                if (pos == text.size())
                    return false;
            }

            const size_t begin = pos;
            while (pos < text.size() && text[pos] != '+' && text[pos] != '-')
                ++pos;
            size_t end = pos;
            while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])))
                --end;
            if (end == begin)
                return false;

            uint64_t term = 0;
            if (!parse_addr_literal(text.substr(begin, end - begin), term))
                return false;
            if (first) {
                result = term;
                first = false;
                continue;
            }
            if (operation == '+') {
                if (term > std::numeric_limits<uint64_t>::max() - result)
                    return false;
                result += term;
            } else {
                if (term > result)
                    return false;
                result -= term;
            }
        }

        out = result;
        return !first;
    }

    bool parse_json_address(const json& value, uint64_t& out)
    {
        if (value.is_string())
            return parse_addr(value.get<std::string>(), out);
        if (value.is_number_unsigned()) {
            out = value.get<uint64_t>();
            return true;
        }
        if (value.is_number_integer()) {
            const int64_t signed_value = value.get<int64_t>();
            if (signed_value < 0)
                return false;
            out = static_cast<uint64_t>(signed_value);
            return true;
        }
        return false;
    }

    std::optional<uint64_t> parse_addr_opt(const json& params, const char* key)
    {
        if (!params.contains(key))
            return std::nullopt;
        uint64_t value = 0;
        if (!parse_json_address(params[key], value))
            return std::nullopt;
        return value;
    }

    fs::path active_workspace_root()
    {
        std::string root = g_sa_settings.workspace.root_path.empty()
            ? file_browser::current_dir
            : g_sa_settings.workspace.root_path;
        if (root.empty())
            return {};
        std::error_code ec;
        auto canonical = fs::weakly_canonical(fs::u8path(root), ec);
        if (!ec)
            return canonical;
        return fs::u8path(root).lexically_normal();
    }

    std::wstring normalized_path_key(const fs::path& p)
    {
        std::wstring s = p.lexically_normal().wstring();
        for (wchar_t& c : s) {
            if (c == L'/')
                c = L'\\';
        }
        while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/'))
            s.pop_back();
        std::transform(s.begin(), s.end(), s.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        return s;
    }

    bool path_within_workspace_root(const fs::path& p, const fs::path& workspace)
    {
        if (workspace.empty())
            return false;
        auto ws_str = normalized_path_key(workspace);
        auto p_str = normalized_path_key(p);
        if (ws_str == p_str)
            return true;
        if (!ws_str.empty() && ws_str.back() != L'\\')
            ws_str.push_back(L'\\');
        return p_str.rfind(ws_str, 0) == 0;
    }

    bool resolve_workspace_path_checked(const std::string& raw, fs::path& out, fs::path* workspace_out, std::string& err)
    {
        if (raw.empty()) {
            err = "Path is empty.";
            return false;
        }
        if (raw.find('\0') != std::string::npos) {
            err = "Path contains an embedded NUL byte.";
            return false;
        }
        fs::path workspace = active_workspace_root();
        if (workspace.empty()) {
            err = "No active workspace is open.";
            return false;
        }
        fs::path requested = fs::u8path(raw);
        if (requested.has_root_name() && !requested.is_absolute()) {
            err = "Drive-relative paths are not accepted.";
            return false;
        }
        fs::path candidate = requested.is_absolute() ? requested : workspace / requested;
        std::error_code ec;
        fs::path resolved = fs::weakly_canonical(candidate, ec);
        if (ec) {
            ec.clear();
            resolved = fs::absolute(candidate, ec);
            if (ec)
                resolved = candidate;
            resolved = resolved.lexically_normal();
        }
        if (!path_within_workspace_root(resolved, workspace)) {
            err = "Path is outside the active workspace.";
            return false;
        }
        out = resolved;
        if (workspace_out)
            *workspace_out = workspace;
        return true;
    }

    fs::path resolve_workspace_path(const std::string& raw)
    {
        fs::path resolved;
        std::string err;
        if (resolve_workspace_path_checked(raw, resolved, nullptr, err))
            return resolved;
        return fs::u8path(raw).lexically_normal();
    }

    bool path_within_current_workspace(const fs::path& p)
    {
        return path_within_workspace_root(p, active_workspace_root());
    }

    std::string trim(std::string text)
    {
        auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            return {};
        auto last = text.find_last_not_of(" \t\r\n");
        return text.substr(first, last - first + 1);
    }

    std::string to_lower(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }

    std::string web_tool_url_encode(const std::string& text)
    {
        std::string out;
        out.reserve(text.size() * 3);
        for (unsigned char c : text) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                out += static_cast<char>(c);
            } else if (c == ' ') {
                out += '+';
            } else {
                char hex[4];
                snprintf(hex, sizeof(hex), "%%%02X", c);
                out += hex;
            }
        }
        return out;
    }

    json camoufox_value_json(const aida::burp::camoufox::call_result_t& result)
    {
        if (result.data.is_object()) {
            auto value = result.data.find("value");
            if (value != result.data.end())
                return *value;
            auto raw = result.data.find("value_raw");
            if (raw != result.data.end() && raw->is_string()) {
                auto parsed = json::parse(raw->get<std::string>(), nullptr, false);
                if (!parsed.is_discarded())
                    return parsed;
            }
        }
        return result.data;
    }

    std::string json_string_field(const json& value, const char* key)
    {
        if (!value.is_object())
            return {};
        auto it = value.find(key);
        if (it == value.end() || !it->is_string())
            return {};
        return it->get<std::string>();
    }

    std::string wide_to_utf8_lossy(const std::wstring& text)
    {
        if (text.empty())
            return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) {
            const DWORD err = GetLastError();
            diag::log_tagged_fmt("mcp_tools", "wide_to_utf8 failed len=%zu err=%lu",
                text.size(), static_cast<unsigned long>(err));
            return {};
        }
        std::string out(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), len, nullptr, nullptr);
        return out;
    }

    std::wstring utf8_to_wide_lossy(const std::string& text)
    {
        if (text.empty())
            return {};
        int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
        if (len <= 0) {
            const DWORD err = GetLastError();
            diag::log_tagged_fmt("mcp_tools", "utf8_to_wide failed len=%zu err=%lu",
                text.size(), static_cast<unsigned long>(err));
            return {};
        }
        std::wstring out(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), len);
        return out;
    }

    std::string path_to_utf8(const fs::path& path)
    {
        return wide_to_utf8_lossy(path.native());
    }

    std::string current_cwd_utf8()
    {
        std::error_code ec;
        fs::path cwd = fs::current_path(ec);
        return ec ? std::string() : path_to_utf8(cwd);
    }

    size_t bounded_size_param(const json& params, const char* name, size_t fallback, size_t minimum, size_t maximum)
    {
        size_t value = fallback;
        auto it = params.find(name);
        if (it != params.end()) {
            if (it->is_number_unsigned()) {
                value = it->get<size_t>();
            } else if (it->is_number_integer()) {
                const int64_t signed_value = it->get<int64_t>();
                if (signed_value >= 0)
                    value = static_cast<size_t>(signed_value);
            }
        }
        if (value < minimum)
            return minimum;
        if (value > maximum)
            return maximum;
        return value;
    }

    uint32_t bounded_u32_param(const json& params, const char* name, uint32_t fallback, uint32_t minimum, uint32_t maximum)
    {
        uint32_t value = fallback;
        auto it = params.find(name);
        if (it != params.end()) {
            if (it->is_number_unsigned()) {
                const uint64_t unsigned_value = it->get<uint64_t>();
                value = unsigned_value > maximum ? maximum : static_cast<uint32_t>(unsigned_value);
            } else if (it->is_number_integer()) {
                const int64_t signed_value = it->get<int64_t>();
                if (signed_value >= 0)
                    value = signed_value > static_cast<int64_t>(maximum) ? maximum : static_cast<uint32_t>(signed_value);
            }
        }
        if (value < minimum)
            return minimum;
        if (value > maximum)
            return maximum;
        return value;
    }

    bool glob_has_wildcards(const std::string& pattern)
    {
        return pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos;
    }

    bool glob_match_ci(const std::string& text_raw, const std::string& pattern_raw)
    {
        std::string text = to_lower(text_raw);
        std::string pattern = to_lower(pattern_raw);
        std::replace(text.begin(), text.end(), '\\', '/');
        std::replace(pattern.begin(), pattern.end(), '\\', '/');
        if (!glob_has_wildcards(pattern))
            pattern = "*" + pattern + "*";

        size_t t = 0;
        size_t p = 0;
        size_t star = std::string::npos;
        size_t match = 0;
        while (t < text.size()) {
            if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
                ++t;
                ++p;
            } else if (p < pattern.size() && pattern[p] == '*') {
                star = p++;
                match = t;
            } else if (star != std::string::npos) {
                p = star + 1;
                t = ++match;
            } else {
                return false;
            }
        }
        while (p < pattern.size() && pattern[p] == '*')
            ++p;
        return p == pattern.size();
    }

    bool file_content_looks_binary(const std::string& content)
    {
        if (content.empty())
            return false;
        size_t control = 0;
        const size_t sample = (std::min)(content.size(), static_cast<size_t>(4096));
        for (size_t i = 0; i < sample; ++i) {
            const unsigned char c = static_cast<unsigned char>(content[i]);
            if (c == 0)
                return true;
            if (c < 0x09 || (c > 0x0D && c < 0x20))
                ++control;
        }
        return sample >= 128 && control * 100 > sample * 20;
    }

    std::string prot_string(uint32_t protect)
    {
        switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "R--";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_WRITECOPY:         return "RWC";
        case PAGE_EXECUTE:           return "--X";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RWXC";
        default: break;
        }
        return hex_addr(protect);
    }

    std::string state_string(uint32_t state)
    {
        switch (state) {
        case MEM_COMMIT: return "COMMIT";
        case MEM_FREE: return "FREE";
        case MEM_RESERVE: return "RESERVE";
        default: return "UNKNOWN";
        }
    }

    std::string file_to_utf8(const fs::path& path)
    {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open())
            return {};
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    tool_result_t error(const std::string& text)
    {
        return tool_result_t::error(text);
    }

    std::string requested_target(const json& params)
    {
        if (params.contains("target") && params["target"].is_string())
            return to_lower(params["target"].get<std::string>());
        return "auto";
    }

    bool wants_vm_target(const json& params)
    {
        if (!vm_guest_bridge::is_active())
            return false;
        const std::string target = requested_target(params);
        return target != "host";
    }

    uint32_t json_u32_param(const json& params, const char* key, uint32_t fallback, uint32_t cap)
    {
        if (!params.is_object() || !params.contains(key))
            return fallback;
        const auto& value = params[key];
        uint64_t raw = 0;
        bool have_value = false;
        if (value.is_number_unsigned()) {
            raw = value.get<uint64_t>();
            have_value = true;
        } else if (value.is_number_integer()) {
            const int64_t signed_raw = value.get<int64_t>();
            if (signed_raw >= 0) {
                raw = static_cast<uint64_t>(signed_raw);
                have_value = true;
            }
        }
        if (!have_value)
            return fallback;
        if (raw > cap)
            raw = cap;
        return static_cast<uint32_t>(raw);
    }

    bool json_bool_param(const json& params, const char* key, bool fallback)
    {
        if (!params.is_object() || !params.contains(key))
            return fallback;
        const auto& value = params[key];
        if (value.is_boolean())
            return value.get<bool>();
        return fallback;
    }

    uint32_t vm_bridge_timeout_ms(const json& params)
    {
        uint32_t timeout = 5000;
        if (params.contains("timeout_ms")) {
            const auto& value = params["timeout_ms"];
            uint64_t raw = 0;
            if (value.is_number_unsigned()) {
                raw = value.get<uint64_t>();
            } else if (value.is_number_integer()) {
                const int64_t signed_raw = value.get<int64_t>();
                if (signed_raw > 0)
                    raw = static_cast<uint64_t>(signed_raw);
            }
            if (raw > 0)
                timeout = static_cast<uint32_t>(raw > 300000 ? 300000 : raw);
        }
        return timeout;
    }

    json vm_bridge_params_from(const json& params)
    {
        json p = params.is_object() ? params : json::object();
        p.erase("target");
        p.erase("timeout_ms");
        return p;
    }

    void enrich_vm_bridge_data(json& data)
    {
        data["backend"] = "vm_bridge";
        auto session = vm_guest_bridge::current();
        data["sandbox_dir"] = wide_to_utf8_lossy(session.session_dir);
        data["vm_bridge_dir"] = wide_to_utf8_lossy(session.bridge_dir);
        if (data.contains("artifact_name") && data["artifact_name"].is_string()) {
            std::string host_path = vm_guest_bridge::artifact_host_path(data["artifact_name"].get<std::string>());
            if (!host_path.empty())
                data["host_artifact_path"] = host_path;
        }
    }

    tool_result_t vm_bridge_call(const std::string& command, const json& params, const std::string& message)
    {
        std::string err;
        json response = vm_guest_bridge::request(command, vm_bridge_params_from(params), vm_bridge_timeout_ms(params), &err);
        if (!err.empty())
            return error(err);
        json data = response.value("data", json::object());
        enrich_vm_bridge_data(data);
        return tool_result_t::ok(message, data);
    }

    std::string quote_guest_cli_arg(const std::string& value)
    {
        std::string out;
        out.reserve(value.size() + 2);
        out.push_back('"');
        for (char c : value) {
            if (c == '"') out += "\\\"";
            else out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    std::string join_guest_cli_path(std::string base, const std::string& leaf)
    {
        if (base.empty()) return leaf;
        while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
        return base + "\\" + leaf;
    }

    fs::path resolve_guest_agent_exe()
    {
        wchar_t module_path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return {};
        fs::path agent = fs::path(module_path).parent_path() / L"AiDAGuestAgent.exe";
        std::error_code ec;
        if (!fs::exists(agent, ec) || ec || fs::is_directory(agent, ec))
            return {};
        return agent;
    }

    bool stage_guest_agent(const fs::path& bridge_dir, std::string* error_out)
    {
        std::error_code ec;
        fs::path agent_dir = bridge_dir / L"agent";
        fs::create_directories(agent_dir, ec);
        if (ec) {
            if (error_out) *error_out = "failed to create bridge agent directory: " + ec.message();
            return false;
        }
        fs::path agent_src = resolve_guest_agent_exe();
        if (agent_src.empty()) {
            if (error_out) *error_out = "AiDAGuestAgent.exe is missing beside AiDAStandalone.exe";
            return false;
        }
        fs::copy_file(agent_src, agent_dir / L"AiDAGuestAgent.exe", fs::copy_options::overwrite_existing, ec);
        if (ec) {
            if (error_out) *error_out = "failed to stage AiDAGuestAgent.exe: " + ec.message();
            return false;
        }
        if (error_out) error_out->clear();
        return true;
    }

    bool stage_host_sample(const fs::path& bridge_dir,
                           const fs::path& host_sample,
                           std::string* filename_out,
                           std::string* error_out)
    {
        std::error_code ec;
        if (!fs::exists(host_sample, ec) || ec || fs::is_directory(host_sample, ec)) {
            if (error_out) *error_out = "host_sample is not a readable file";
            return false;
        }
        fs::path samples_dir = bridge_dir / L"samples";
        ec.clear();
        fs::create_directories(samples_dir, ec);
        if (ec) {
            if (error_out) *error_out = "failed to create bridge samples directory: " + ec.message();
            return false;
        }
        fs::path filename = host_sample.filename();
        if (filename.empty()) {
            if (error_out) *error_out = "host_sample filename is empty";
            return false;
        }
        ec.clear();
        fs::copy_file(host_sample, samples_dir / filename, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            if (error_out) *error_out = "failed to stage host_sample: " + ec.message();
            return false;
        }
        if (filename_out) *filename_out = path_to_utf8(filename);
        if (error_out) error_out->clear();
        return true;
    }

    json vm_bridge_status_payload()
    {
        json data = vm_guest_bridge::status_snapshot();
        if (data.contains("bridge_dir") && data["bridge_dir"].is_string())
            data["vm_bridge_dir"] = data["bridge_dir"];
        return data;
    }

    std::string vm_bridge_status_value(const json& data)
    {
        const bool active = data.contains("active") && data["active"].is_boolean() && data["active"].get<bool>();
        auto guest_it = data.find("guest_status");
        if (guest_it != data.end() && guest_it->is_object()) {
            std::string status = json_string_field(*guest_it, "status");
            if (!status.empty())
                return status;
            status = json_string_field(*guest_it, "state");
            if (!status.empty())
                return status;
        }
        return active ? "active" : "inactive";
    }

    void log_vm_bridge_status_action(const char* phase, const json& data)
    {
        const bool active = data.contains("active") && data["active"].is_boolean() && data["active"].get<bool>();
        const std::string bridge_kind = json_string_field(data, "bridge_kind");
        const std::string bridge_status = vm_bridge_status_value(data);
        diag::log_tagged_fmt("mcp_tools",
            "handle_vm_bridge_manage status_%s action=status active=%d bridge_kind='%s' bridge_status='%s'",
            phase, active ? 1 : 0, bridge_kind.c_str(), bridge_status.c_str());
    }

    bool hex_to_bytes_string(const std::string& hex, std::vector<uint8_t>& out)
    {
        out.clear();
        if (hex.size() % 2 != 0)
            return false;
        out.reserve(hex.size() / 2);
        auto nibble = [](char c, uint8_t& v) {
            if (c >= '0' && c <= '9') {
                v = static_cast<uint8_t>(c - '0');
                return true;
            }
            if (c >= 'a' && c <= 'f') {
                v = static_cast<uint8_t>(c - 'a' + 10);
                return true;
            }
            if (c >= 'A' && c <= 'F') {
                v = static_cast<uint8_t>(c - 'A' + 10);
                return true;
            }
            return false;
        };
        for (size_t i = 0; i < hex.size(); i += 2) {
            uint8_t hi = 0, lo = 0;
            if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo))
                return false;
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return true;
    }

    std::mutex& s_last_web_error_mtx()
    {
        static std::mutex m;
        return m;
    }

    std::string& s_last_web_error_ref()
    {
        static std::string s;
        return s;
    }

    void set_last_web_error(const std::string& text)
    {
        std::lock_guard<std::mutex> lk(s_last_web_error_mtx());
        s_last_web_error_ref() = text;
    }

tool_result_t handle_vm_bridge_attach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_attach entry");
        return vm_bridge_call("attach", params, "Attached to VM process.");
    }

    tool_result_t handle_vm_bridge_detach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_detach entry");
        return vm_bridge_call("detach", params, "Detached from VM process.");
    }

    tool_result_t handle_vm_bridge_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_list_processes entry");
        return vm_bridge_call("list_processes", params, "Enumerated VM processes.");
    }

    tool_result_t handle_vm_bridge_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_query_memory entry");
        return vm_bridge_call("query_memory", params, "Queried VM memory region.");
    }

    tool_result_t handle_vm_bridge_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_read_memory entry");
        return vm_bridge_call("read_memory", params, "Read VM process memory.");
    }

    tool_result_t handle_vm_bridge_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_read_string entry");
        return vm_bridge_call("read_string", params, "Read VM process string.");
    }

    tool_result_t handle_vm_bridge_enumerate_modules(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_enumerate_modules entry");
        return vm_bridge_call("modules", params, "Enumerated VM modules.");
    }

    tool_result_t handle_vm_bridge_enumerate_threads(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_enumerate_threads entry");
        return vm_bridge_call("threads", params, "Enumerated VM threads.");
    }

    tool_result_t handle_vm_bridge_manage(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_manage entry");
        std::string action = params.contains("action") && params["action"].is_string()
            ? to_lower(params["action"].get<std::string>())
            : std::string("status");
        if (action == "status") {
            json data = vm_bridge_status_payload();
            data["backend"] = "vm_bridge";
            data["action"] = "status";
            log_vm_bridge_status_action("entry", data);
            tool_result_t result = tool_result_t::ok("VM bridge status.", data);
            log_vm_bridge_status_action("exit", data);
            return result;
        }
        if (action == "activate") {
            if (!params.contains("bridge_dir") || !params["bridge_dir"].is_string())
                return error("bridge_dir is required for vm_bridge_manage action=activate");
            std::wstring bridge_dir = utf8_to_wide_lossy(params["bridge_dir"].get<std::string>());
            if (bridge_dir.empty())
                return error("bridge_dir is invalid");
            const fs::path bridge_path(bridge_dir);
            const std::string guest_bridge = params.contains("guest_bridge_dir") && params["guest_bridge_dir"].is_string()
                ? params["guest_bridge_dir"].get<std::string>()
                : std::string();
            std::wstring guest_sample;
            if (params.contains("guest_sample") && params["guest_sample"].is_string())
                guest_sample = utf8_to_wide_lossy(params["guest_sample"].get<std::string>());
            else if (params.contains("sample") && params["sample"].is_string())
                guest_sample = utf8_to_wide_lossy(params["sample"].get<std::string>());
            std::wstring args;
            if (params.contains("args") && params["args"].is_string())
                args = utf8_to_wide_lossy(params["args"].get<std::string>());
            const bool write_config = json_bool_param(params, "write_launch_config", true);
            const bool stage_agent = json_bool_param(params, "stage_agent", true);
            std::string err;
            std::string staged_sample_name;
            if (params.contains("host_sample") && params["host_sample"].is_string()) {
                std::wstring host_sample_w = utf8_to_wide_lossy(params["host_sample"].get<std::string>());
                if (host_sample_w.empty())
                    return error("host_sample is invalid");
                if (!stage_host_sample(bridge_path, fs::path(host_sample_w), &staged_sample_name, &err))
                    return tool_result_t::error("custom VM sample staging failed: " + err, vm_bridge_status_payload());
                if (guest_sample.empty() && !guest_bridge.empty()) {
                    std::string guest_sample_auto = join_guest_cli_path(join_guest_cli_path(guest_bridge, "samples"), staged_sample_name);
                    guest_sample = utf8_to_wide_lossy(guest_sample_auto);
                }
            }
            if (write_config && !vm_guest_bridge::prepare_bridge_directory(bridge_dir, guest_sample, args, &err))
                return tool_result_t::error("custom VM bridge setup failed: " + err, vm_bridge_status_payload());
            if (stage_agent && !stage_guest_agent(bridge_path, &err))
                return tool_result_t::error("custom VM guest agent staging failed: " + err, vm_bridge_status_payload());
            if (!vm_guest_bridge::activate_bridge(bridge_dir, bridge_dir, guest_sample, "custom_vm", &err))
                return tool_result_t::error("custom VM bridge activation failed: " + err, vm_bridge_status_payload());
            json data = vm_bridge_status_payload();
            if (!staged_sample_name.empty()) {
                data["staged_sample"] = true;
                data["staged_sample_name"] = staged_sample_name;
            }
            if (!guest_bridge.empty()) {
                data["guest_bridge_dir"] = guest_bridge;
                data["guest_command"] = quote_guest_cli_arg(join_guest_cli_path(guest_bridge, "agent\\AiDAGuestAgent.exe")) +
                    " --bridge " + quote_guest_cli_arg(guest_bridge);
            }
            return tool_result_t::ok("Custom VM bridge activated.", data);
        }
        if (action == "deactivate") {
            vm_guest_bridge::deactivate();
            return tool_result_t::ok("VM bridge deactivated.", vm_bridge_status_payload());
        }
        if (action == "ping" || action == "guest_status")
            return vm_bridge_call("status", params, "Read VM guest-agent status.");
        if (action == "attach")
            return handle_vm_bridge_attach(params);
        if (action == "detach")
            return handle_vm_bridge_detach(params);
        if (action == "list_processes")
            return handle_vm_bridge_list_processes(params);
        if (action == "modules")
            return handle_vm_bridge_enumerate_modules(params);
        if (action == "threads")
            return handle_vm_bridge_enumerate_threads(params);
        if (action == "memory_map")
            return vm_bridge_call("memory_map", params, "Enumerated VM memory map.");
        if (action == "query_memory")
            return handle_vm_bridge_query_memory(params);
        if (action == "read_memory")
            return handle_vm_bridge_read_memory(params);
        if (action == "read_string")
            return handle_vm_bridge_read_string(params);
        if (action == "dump_region")
            return vm_bridge_call("dump_region", params, "Dumped VM memory region.");
        if (action == "search_memory")
            return vm_bridge_call("search_memory", params, "Searched VM memory.");
        return error("vm_bridge_manage unknown action: " + action);
    }


    tool_result_t handle_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_list_processes entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_list_processes(params);
        const std::string filter = to_lower(params.value("filter", std::string()));
        json items = json::array();
        for (const auto& proc : driver_bridge::enumerate_processes()) {
            if (!filter.empty() && to_lower(proc.name).find(filter) == std::string::npos)
                continue;
            items.push_back({{"pid", proc.pid}, {"name", proc.name}});
        }
        const auto driver = driver_bridge::availability();
        return tool_result_t::ok("Enumerated processes", json{
            {"processes", items},
            {"driver_available", driver.device_connected && driver.kernel_backend},
            {"driver_state", driver.state},
            {"driver_reason", driver.reason},
            {"driver_detail", driver.detail}
        });
    }

    tool_result_t ensure_attached()
    {
        const auto driver = driver_bridge::availability();
        json details{
            {"driver_available", driver.device_connected && driver.kernel_backend},
            {"driver_state", driver.state},
            {"driver_reason", driver.reason},
            {"driver_detail", driver.detail},
            {"target_attached", driver.target_attached},
            {"target_pid", driver.target_pid}
        };
        if (!driver.device_connected || !driver.kernel_backend)
            return tool_result_t::error(
                "Kernel driver is unavailable: " + driver.reason + ".",
                "driver_unavailable", details);
        if (!driver.target_attached)
            return tool_result_t::error(
                "No process is attached. Use sessions_manage action=attach_pid first.",
                "driver_target_unavailable", details);
        return tool_result_t::ok("");
    }

    constexpr size_t k_max_memory_read_size = 1024 * 1024;
    constexpr size_t k_max_memory_batch_count = 256;
    constexpr size_t k_max_memory_batch_bytes = 16 * 1024 * 1024;
    constexpr size_t k_max_memory_field_count = 256;

    std::optional<size_t> fixed_typed_size(const std::string& value_type)
    {
        const std::string type = to_lower(value_type);
        if (type == "byte" || type == "uint8" || type == "int8")
            return 1;
        if (type == "int16" || type == "uint16")
            return 2;
        if (type == "float" || type == "int32" || type == "uint32" || type == "int" || type == "integer")
            return 4;
        if (type == "double" || type == "int64" || type == "uint64" || type == "pointer" || type == "ptr" || type == "address")
            return 8;
        return std::nullopt;
    }

    bool is_variable_typed_value(const std::string& value_type)
    {
        const std::string type = to_lower(value_type);
        return type == "ascii" || type == "string" || type == "str" ||
            type == "utf16" || type == "wstring" || type == "bytes" || type == "hex";
    }

    bool resolve_typed_read_size(const std::string& value_type, size_t requested, bool explicit_variable_size,
                                 size_t& out, std::string& err)
    {
        if (const auto fixed = fixed_typed_size(value_type)) {
            out = requested == 0 ? *fixed : requested;
        } else if (is_variable_typed_value(value_type)) {
            if (requested == 0 && explicit_variable_size) {
                err = "Variable-width field type '" + value_type + "' requires an explicit positive size.";
                return false;
            }
            out = requested == 0 ? 256 : requested;
        } else {
            err = "Unsupported value_type '" + value_type + "'.";
            return false;
        }
        if (out == 0 || out > k_max_memory_read_size) {
            err = "Memory read size must be between 1 and 1048576 bytes.";
            return false;
        }
        return true;
    }

    bool parse_memory_size(const json& value, size_t& out)
    {
        uint64_t parsed = 0;
        if (value.is_number_unsigned())
            parsed = value.get<uint64_t>();
        else if (value.is_number_integer()) {
            const int64_t signed_value = value.get<int64_t>();
            if (signed_value <= 0)
                return false;
            parsed = static_cast<uint64_t>(signed_value);
        } else if (value.is_string()) {
            if (!parse_addr(value.get<std::string>(), parsed))
                return false;
        } else {
            return false;
        }
        if (parsed == 0 || parsed > k_max_memory_read_size)
            return false;
        out = static_cast<size_t>(parsed);
        return true;
    }

    template <typename T>
    bool read_le_value(const std::vector<uint8_t>& bytes, T& out)
    {
        if (bytes.size() < sizeof(T))
            return false;
        std::memcpy(&out, bytes.data(), sizeof(T));
        return true;
    }

    json decode_typed_memory_value(const std::vector<uint8_t>& bytes, const std::string& value_type)
    {
        const std::string type = to_lower(value_type);
        json out;
        out["type"] = value_type;
        out["read_size"] = bytes.size();
        if (type == "byte" || type == "uint8") {
            if (!bytes.empty()) out["value"] = bytes[0];
            return out;
        }
        if (type == "int8") {
            if (!bytes.empty()) out["value"] = static_cast<int>(static_cast<int8_t>(bytes[0]));
            return out;
        }
        if (type == "int16") {
            int16_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint16") {
            uint16_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint32") {
            uint32_t v = 0;
            if (read_le_value(bytes, v)) {
                out["value"] = v;
                out["hex_value"] = hex_addr(v);
            }
            return out;
        }
        if (type == "int64") {
            int64_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint64") {
            uint64_t v = 0;
            if (read_le_value(bytes, v)) {
                out["value"] = v;
                out["hex_value"] = hex_addr(v);
            }
            return out;
        }
        if (type == "pointer" || type == "ptr" || type == "address") {
            uint64_t v = 0;
            if (read_le_value(bytes, v)) {
                out["value"] = v;
                out["hex_value"] = hex_addr(v);
            }
            out["normalized_type"] = "pointer";
            return out;
        }
        if (type == "float") {
            float v = 0.0f;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "double") {
            double v = 0.0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "ascii" || type == "string" || type == "str") {
            std::string text;
            for (uint8_t b : bytes) {
                if (b == 0)
                    break;
                text.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');
            }
            out["value"] = text;
            return out;
        }
        if (type == "utf16" || type == "wstring") {
            std::string text;
            for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
                const uint16_t ch = static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
                if (ch == 0)
                    break;
                text.push_back((ch >= 32 && ch < 127) ? static_cast<char>(ch) : '?');
            }
            out["value"] = text;
            out["encoding"] = "utf16le_ascii_preview";
            return out;
        }
        if (type == "bytes" || type == "hex") {
            std::string hex;
            hex.reserve(bytes.size() * 2);
            for (uint8_t b : bytes) {
                char chunk[3];
                snprintf(chunk, sizeof(chunk), "%02X", b);
                hex += chunk;
            }
            out["value"] = hex;
            out["encoding"] = "hex";
            return out;
        }
        int32_t v = 0;
        if (read_le_value(bytes, v))
            out["value"] = v;
        out["normalized_type"] = "int32";
        return out;
    }

    struct memory_field_t
    {
        std::string name;
        std::string type;
        size_t offset = 0;
        size_t size = 0;
    };

    bool parse_memory_fields(const json& value, std::vector<memory_field_t>& fields, size_t& span, std::string& err)
    {
        fields.clear();
        span = 0;
        if (!value.is_array() || value.empty()) {
            err = "fields must be a non-empty array.";
            return false;
        }
        if (value.size() > k_max_memory_field_count) {
            err = "fields is limited to 256 entries.";
            return false;
        }

        std::unordered_set<std::string> names;
        fields.reserve(value.size());
        for (size_t index = 0; index < value.size(); ++index) {
            const auto& item = value[index];
            if (!item.is_object()) {
                err = "fields[" + std::to_string(index) + "] must be an object.";
                return false;
            }
            if (!item.contains("name") || !item["name"].is_string() || item["name"].get<std::string>().empty() ||
                item["name"].get_ref<const std::string&>().size() > 256) {
                err = "fields[" + std::to_string(index) + "].name must contain 1 to 256 characters.";
                return false;
            }
            if (!item.contains("type") || !item["type"].is_string() || item["type"].get<std::string>().empty() ||
                item["type"].get_ref<const std::string&>().size() > 64) {
                err = "fields[" + std::to_string(index) + "].type must contain 1 to 64 characters.";
                return false;
            }
            memory_field_t field;
            field.name = item["name"].get<std::string>();
            field.type = item["type"].get<std::string>();
            if (!names.insert(field.name).second) {
                err = "Duplicate field name '" + field.name + "'.";
                return false;
            }
            if (!item.contains("offset")) {
                err = "fields[" + std::to_string(index) + "].offset is required.";
                return false;
            }
            uint64_t offset = 0;
            if (!parse_json_address(item["offset"], offset) || offset > k_max_memory_read_size) {
                err = "fields[" + std::to_string(index) + "].offset is invalid or out of range.";
                return false;
            }
            field.offset = static_cast<size_t>(offset);
            size_t requested_size = 0;
            if (item.contains("size") && !parse_memory_size(item["size"], requested_size)) {
                err = "fields[" + std::to_string(index) + "].size must be between 1 and 1048576 bytes.";
                return false;
            }
            if (const auto fixed = fixed_typed_size(field.type); fixed && requested_size != 0 && requested_size != *fixed) {
                err = "fields[" + std::to_string(index) + "].size must match the fixed width of type '" + field.type + "'.";
                return false;
            }
            if (!resolve_typed_read_size(field.type, requested_size, true, field.size, err)) {
                err = "fields[" + std::to_string(index) + "]: " + err;
                return false;
            }
            const std::string normalized_type = to_lower(field.type);
            if ((normalized_type == "utf16" || normalized_type == "wstring") && (field.size % 2) != 0) {
                err = "fields[" + std::to_string(index) + "].size must be even for UTF-16 data.";
                return false;
            }
            if (field.offset > k_max_memory_read_size - field.size) {
                err = "fields[" + std::to_string(index) + "] exceeds the 1048576-byte read limit.";
                return false;
            }
            span = std::max(span, field.offset + field.size);
            fields.push_back(std::move(field));
        }
        return true;
    }

    bool decode_memory_fields(const std::vector<uint8_t>& bytes, uint64_t base,
                              const std::vector<memory_field_t>& fields, json& items, json& view,
                              std::string& err)
    {
        items = json::array();
        view = json::object();
        for (const auto& field : fields) {
            if (field.offset > bytes.size() || field.size > bytes.size() - field.offset) {
                err = "Memory read returned too few bytes to decode field '" + field.name + "'.";
                return false;
            }
            std::vector<uint8_t> field_bytes(bytes.begin() + field.offset, bytes.begin() + field.offset + field.size);
            json decoded = decode_typed_memory_value(field_bytes, field.type);
            json item = decoded;
            item["name"] = field.name;
            item["offset"] = field.offset;
            item["address"] = hex_addr(base + field.offset);
            item["size"] = field.size;
            items.push_back(std::move(item));
            view[field.name] = std::move(decoded);
        }
        return true;
    }

    struct memory_read_request_t
    {
        uint64_t address = 0;
        size_t size = 0;
        std::string value_type;
        std::vector<memory_field_t> fields;
    };

    bool parse_single_memory_read_request(const json& params, memory_read_request_t& request, std::string& err)
    {
        if (!params.contains("address") || !parse_json_address(params["address"], request.address)) {
            err = "Missing or invalid address expression.";
            return false;
        }
        size_t requested_size = 0;
        if (params.contains("size") && !parse_memory_size(params["size"], requested_size)) {
            err = "size must be between 1 and 1048576 bytes.";
            return false;
        }
        if (params.contains("value_type")) {
            if (!params["value_type"].is_string() || params["value_type"].get_ref<const std::string&>().empty() ||
                params["value_type"].get_ref<const std::string&>().size() > 64) {
                err = "value_type must contain 1 to 64 characters.";
                return false;
            }
            request.value_type = params["value_type"].get<std::string>();
        }

        size_t field_span = 0;
        if (params.contains("fields")) {
            if (!request.value_type.empty()) {
                err = "value_type and fields cannot be combined; set each field's type in fields.";
                return false;
            }
            if (!parse_memory_fields(params["fields"], request.fields, field_span, err))
                return false;
        }

        if (!request.fields.empty()) {
            request.size = requested_size == 0 ? field_span : requested_size;
            if (request.size < field_span) {
                err = "size is smaller than the highest field boundary.";
                return false;
            }
        } else if (!request.value_type.empty()) {
            if (!resolve_typed_read_size(request.value_type, requested_size, false, request.size, err))
                return false;
        } else {
            request.size = requested_size == 0 ? 256 : requested_size;
        }
        if (request.address > std::numeric_limits<uint64_t>::max() - (request.size - 1)) {
            err = "The requested memory range overflows the address space.";
            return false;
        }
        return true;
    }

    bool parse_memory_read_requests(const json& params, std::vector<memory_read_request_t>& requests,
                                    bool& batch, std::string& err)
    {
        requests.clear();
        batch = params.contains("addresses");
        if (!batch) {
            memory_read_request_t request;
            if (!parse_single_memory_read_request(params, request, err))
                return false;
            requests.push_back(std::move(request));
            return true;
        }
        if (params.contains("address")) {
            err = "Use either address or addresses, not both.";
            return false;
        }
        if (!params["addresses"].is_array() || params["addresses"].empty()) {
            err = "addresses must be a non-empty array.";
            return false;
        }
        if (params["addresses"].size() > k_max_memory_batch_count) {
            err = "addresses is limited to 256 entries.";
            return false;
        }
        const size_t count = params["addresses"].size();
        for (const char* key : {"sizes", "value_types"}) {
            if (params.contains(key) && (!params[key].is_array() || params[key].size() != count)) {
                err = std::string(key) + " must be an array with one entry per address.";
                return false;
            }
        }

        size_t total_size = 0;
        requests.reserve(count);
        for (size_t index = 0; index < count; ++index) {
            json item = params;
            item.erase("addresses");
            item.erase("sizes");
            item.erase("value_types");
            const auto& address_item = params["addresses"][index];
            if (address_item.is_object()) {
                if (!address_item.contains("address")) {
                    err = "addresses[" + std::to_string(index) + "].address is required.";
                    return false;
                }
                item["address"] = address_item["address"];
                for (const char* key : {"size", "value_type", "fields"}) {
                    if (address_item.contains(key))
                        item[key] = address_item[key];
                }
            } else {
                item["address"] = address_item;
            }
            if (params.contains("sizes"))
                item["size"] = params["sizes"][index];
            if (params.contains("value_types"))
                item["value_type"] = params["value_types"][index];

            memory_read_request_t request;
            if (!parse_single_memory_read_request(item, request, err)) {
                err = "addresses[" + std::to_string(index) + "]: " + err;
                return false;
            }
            if (request.size > k_max_memory_batch_bytes - total_size) {
                err = "Batch reads are limited to 16777216 total bytes.";
                return false;
            }
            total_size += request.size;
            requests.push_back(std::move(request));
        }
        return true;
    }

    bool read_memory_backend(const json& params, bool vm_target, const memory_read_request_t& request,
                             std::vector<uint8_t>& bytes, json& metadata, std::string& err)
    {
        if (vm_target) {
            json vm_params = vm_bridge_params_from(params);
            vm_params.erase("addresses");
            vm_params.erase("sizes");
            vm_params.erase("value_types");
            vm_params.erase("fields");
            vm_params.erase("value_type");
            vm_params["address"] = hex_addr(request.address);
            vm_params["size"] = request.size;
            json response = vm_guest_bridge::request("read_memory", vm_params, vm_bridge_timeout_ms(params), &err);
            if (!err.empty())
                return false;
            if (!response.contains("data") || !response["data"].is_object()) {
                err = "VM bridge returned a memory-read payload without an object data field.";
                return false;
            }
            metadata = response["data"];
            if (!metadata.contains("hex") || !metadata["hex"].is_string() ||
                !hex_to_bytes_string(metadata["hex"].get<std::string>(), bytes)) {
                err = "VM bridge returned an invalid memory-read payload.";
                return false;
            }
            metadata.erase("hex");
            metadata.erase("ascii");
            metadata.erase("address");
            metadata.erase("size");
            enrich_vm_bridge_data(metadata);
            return true;
        }

        if (!driver_bridge::read_memory(request.address, request.size, bytes)) {
            err = "Memory read failed. Ensure the kernel driver is loaded and attached.";
            return false;
        }
        return true;
    }

    json memory_read_output(const memory_read_request_t& request, const std::vector<uint8_t>& bytes,
                            const json& metadata, std::string& err)
    {
        std::string hex;
        hex.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            char chunk[3];
            snprintf(chunk, sizeof(chunk), "%02X", b);
            hex += chunk;
        }

        std::string ascii;
        ascii.reserve(bytes.size());
        for (uint8_t b : bytes)
            ascii.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');

        json out = metadata.is_object() ? metadata : json::object();
        out["address"] = hex_addr(request.address);
        out["size"] = bytes.size();
        out["requested_size"] = request.size;
        out["complete"] = bytes.size() >= request.size;
        out["hex"] = std::move(hex);
        out["ascii"] = std::move(ascii);
        if (!request.value_type.empty()) {
            if (const auto width = fixed_typed_size(request.value_type); width && bytes.size() < *width) {
                err = "Memory read returned too few bytes for value_type '" + request.value_type + "'.";
                return json();
            }
            out["typed"] = decode_typed_memory_value(bytes, request.value_type);
            if (const auto width = fixed_typed_size(request.value_type); width && bytes.size() > *width) {
                json values = json::array();
                const size_t total_values = bytes.size() / *width;
                const size_t returned_values = std::min<size_t>(total_values, 4096);
                for (size_t index = 0; index < returned_values; ++index) {
                    const size_t offset = index * *width;
                    std::vector<uint8_t> element(bytes.begin() + offset, bytes.begin() + offset + *width);
                    json decoded = decode_typed_memory_value(element, request.value_type);
                    decoded["offset"] = offset;
                    decoded["address"] = hex_addr(request.address + offset);
                    values.push_back(std::move(decoded));
                }
                out["typed_values"] = std::move(values);
                out["typed_value_count"] = total_values;
                out["typed_values_truncated"] = returned_values < total_values;
            }
        }
        if (!request.fields.empty()) {
            json fields;
            json view;
            if (!decode_memory_fields(bytes, request.address, request.fields, fields, view, err))
                return json();
            out["fields"] = std::move(fields);
            out["struct"] = std::move(view);
        }
        return out;
    }

    tool_result_t handle_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_memory entry");
        std::vector<memory_read_request_t> requests;
        bool batch = false;
        std::string err;
        if (!parse_memory_read_requests(params, requests, batch, err))
            return error(err);

        const bool vm_target = wants_vm_target(params);
        if (!vm_target) {
            auto chk = ensure_attached();
            if (!chk.success)
                return chk;
        }

        json results = json::array();
        size_t succeeded = 0;
        size_t failed = 0;
        for (const auto& request : requests) {
            std::vector<uint8_t> bytes;
            json metadata = json::object();
            std::string item_error;
            if (!read_memory_backend(params, vm_target, request, bytes, metadata, item_error)) {
                if (!batch)
                    return error(item_error);
                results.push_back({{"address", hex_addr(request.address)}, {"requested_size", request.size},
                                   {"success", false}, {"error", item_error}});
                ++failed;
                continue;
            }
            json output = memory_read_output(request, bytes, metadata, item_error);
            if (!item_error.empty()) {
                if (!batch)
                    return error(item_error);
                results.push_back({{"address", hex_addr(request.address)}, {"requested_size", request.size},
                                   {"success", false}, {"error", item_error}});
                ++failed;
                continue;
            }
            if (batch)
                output["success"] = true;
            results.push_back(std::move(output));
            ++succeeded;
        }

        if (!batch)
            return tool_result_t::ok("Read process memory.", std::move(results.front()));

        json out{{"results", std::move(results)}, {"count", requests.size()},
                 {"succeeded", succeeded}, {"failed", failed}};
        if (succeeded == 0)
            return tool_result_t::error("All batch memory reads failed.", std::move(out));
        return tool_result_t::ok("Completed batch process-memory read.", std::move(out));
    }

    tool_result_t handle_read_struct(const json& params)
    {
        if (!params.contains("fields"))
            return error("fields is required for read_struct.");
        if (params.contains("addresses"))
            return error("read_struct accepts one address; use read_memory addresses with per-entry fields for batch struct reads.");
        if (params.contains("value_type"))
            return error("read_struct does not accept value_type; set each field's type in fields.");
        if (params.contains("struct_name"))
            return error("Use either fields for a live struct read or struct_name for a declared workspace struct, not both.");
        return handle_read_memory(params);
    }

    tool_result_t handle_fixed_typed_read(const json& params, const char* value_type, size_t size)
    {
        if (params.contains("fields"))
            return error("Typed read shortcuts do not accept fields; use read_struct or read_memory.");
        json request = params;
        request["value_type"] = value_type;
        request["size"] = size;
        if (request.contains("addresses") && request["addresses"].is_array()) {
            json sizes = json::array();
            json types = json::array();
            for (size_t index = 0; index < request["addresses"].size(); ++index) {
                sizes.push_back(size);
                types.push_back(value_type);
            }
            request["sizes"] = std::move(sizes);
            request["value_types"] = std::move(types);
        } else {
            request.erase("sizes");
            request.erase("value_types");
        }
        return handle_read_memory(request);
    }

    tool_result_t handle_read_bytes(const json& params)
    {
        bool item_sizes = params.contains("addresses") && params["addresses"].is_array() && !params["addresses"].empty();
        if (params.contains("addresses") && params["addresses"].is_array()) {
            for (const auto& item : params["addresses"]) {
                if (item.is_object() && (item.contains("fields") || item.contains("value_type")))
                    return error("read_bytes address entries cannot contain fields or value_type.");
                if (!item.is_object() || !item.contains("size")) {
                    item_sizes = false;
                }
            }
        }
        if (!params.contains("size") && !params.contains("sizes") && !item_sizes)
            return error("size or sizes is required for read_bytes.");
        if (params.contains("fields"))
            return error("read_bytes does not accept fields; use read_struct or read_memory.");
        json request = params;
        request.erase("value_type");
        request.erase("value_types");
        request.erase("fields");
        return handle_read_memory(request);
    }

    tool_result_t handle_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_string entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_read_string(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        std::string text;
        if (!driver_bridge::read_string(*address, static_cast<size_t>(params.value("max_length", 256)), text))
            return error("Could not read a string at the requested address.");

        return tool_result_t::ok("Read string.", json{{"address", hex_addr(*address)}, {"text", text}});
    }

    tool_result_t handle_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_query_memory entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_query_memory(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        driver_bridge::memory_region_t region;
        if (!driver_bridge::query_memory(*address, region))
            return error("Memory query failed. Ensure the kernel driver is loaded and attached.");

        json out;
        out["base"] = hex_addr(region.base);
        out["size"] = region.size;
        out["state"] = state_string(region.state);
        out["protect"] = prot_string(region.protect);
        out["type"] = hex_addr(region.type);
        return tool_result_t::ok("Queried memory region.", out);
    }

    class workspace_call_cancel_bridge_t
    {
    public:
        explicit workspace_call_cancel_bridge_t(
            std::optional<std::chrono::steady_clock::time_point> deadline,
            std::atomic<bool>* external = nullptr)
            : source_(deadline)
        {
            std::atomic<bool>* const observed = external ? external : mcp_standalone::current_cancel_token();
            if (observed) {
                aida::infra::cancellation_watchdog::watch_descriptor_t watch;
                watch.external_flag = observed;
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

    std::optional<std::chrono::steady_clock::time_point> current_workspace_deadline()
    {
        const std::uint64_t deadline_ms = mcp_standalone::current_call_deadline_ms();
        if (deadline_ms == 0)
            return std::nullopt;
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline_ms <= now_ms)
            return std::chrono::steady_clock::now();
        return std::chrono::steady_clock::now() +
            std::chrono::milliseconds(deadline_ms - now_ms);
    }

    tool_result_t workspace_tool_error(const aida::analysis::workspace_error_t& value)
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

    tool_result_t handle_disassemble_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_disassemble_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const auto path = params["path"].get<std::string>();
        if (path.empty() || path.size() > 32768)
            return tool_result_t::error("Path must contain between 1 and 32768 bytes.",
                std::string("INVALID_ARGUMENT"), json::object());
        std::uint64_t requested = 64;
        if (params.contains("count")) {
            if (params["count"].is_number_unsigned())
                requested = params["count"].get<std::uint64_t>();
            else if (params["count"].is_number_integer()) {
                const auto signed_count = params["count"].get<std::int64_t>();
                if (signed_count < 0)
                    return tool_result_t::error("count must be non-negative",
                        std::string("INVALID_ARGUMENT"), json::object());
                requested = static_cast<std::uint64_t>(signed_count);
            } else {
                return tool_result_t::error("count must be an integer",
                    std::string("INVALID_ARGUMENT"), json::object());
            }
        }
        if (requested > 50000)
            return tool_result_t::error("count exceeds the 50000-instruction limit",
                std::string("LIMIT_EXCEEDED"), json::object());
        const size_t limit = static_cast<size_t>(requested);
        const auto deadline = current_workspace_deadline();
        workspace_call_cancel_bridge_t cancellation(deadline);
        auto acquired = analysis_session::acquire_static_workspace(path, cancellation.token());
        std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
        bool joined_existing = false;
        std::optional<aida::infra::taskflow_runtime::job_handle_t> analysis_job;
        bool analysis_started = false;
        if (!acquired) {
            if (acquired.error().stable_code() == "SERVICE_CONFLICT") {
                auto candidates = aida::analysis::workspace_registry().find_by_exact_name_or_path(path);
                if (!candidates.empty()) {
                    workspace = candidates.front();
                    joined_existing = true;
                    const bool has_database = workspace->database() != nullptr;
                    const bool has_overlay = workspace->overlay() != nullptr;
                    const bool has_decompiler = workspace->decompiler() != nullptr;
                    const bool has_search_index = workspace->search_index() != nullptr;
                    diag::log_tagged_fmt("mcp_tools",
                        "handle_disassemble_file SERVICE_CONFLICT resolved_by_existing path='%s' binary_id='%s' "
                        "has_database=%d has_overlay=%d has_decompiler=%d has_search_index=%d readiness=%u",
                        path.c_str(),
                        workspace->identity().binary_id().to_hex().c_str(),
                        has_database ? 1 : 0, has_overlay ? 1 : 0,
                        has_decompiler ? 1 : 0, has_search_index ? 1 : 0,
                        static_cast<unsigned>(workspace->progress().readiness));
                    if (!has_database) {
                        diag::log_tagged_fmt("mcp_tools",
                            "handle_disassemble_file SERVICE_CONFLICT partial_installation path='%s' binary_id='%s' "
                            "database_missing=1 attempting_close_and_retry",
                            path.c_str(),
                            workspace->identity().binary_id().to_hex().c_str());
                        const auto close_deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(5);
                        auto closed = workspace->close(close_deadline);
                        if (closed) {
                            auto retry = analysis_session::acquire_static_workspace(path, cancellation.token());
                            if (retry) {
                                auto retry_acquisition = retry.take_value();
                                workspace = retry_acquisition.workspace;
                                joined_existing = retry_acquisition.joined_existing;
                                analysis_job = std::move(retry_acquisition.analysis_job);
                                analysis_started = retry_acquisition.analysis_started;
                                diag::log_tagged_fmt("mcp_tools",
                                    "handle_disassemble_file SERVICE_CONFLICT retry_succeeded path='%s' binary_id='%s'",
                                    path.c_str(),
                                    workspace->identity().binary_id().to_hex().c_str());
                            } else {
                                diag::log_tagged_fmt("mcp_tools",
                                    "handle_disassemble_file SERVICE_CONFLICT retry_failed path='%s' code='%s' message='%.160s'",
                                    path.c_str(),
                                    retry.error().stable_code().c_str(),
                                    retry.error().message.c_str());
                                workspace.reset();
                            }
                        } else {
                            diag::log_tagged_fmt("mcp_tools",
                                "handle_disassemble_file SERVICE_CONFLICT close_failed path='%s' code='%s'",
                                path.c_str(),
                                closed.error().stable_code().c_str());
                            workspace.reset();
                        }
                    }
                }
            }
            if (!workspace)
                return workspace_tool_error(acquired.error());
        } else {
            auto acquisition = acquired.take_value();
            workspace = acquisition.workspace;
            joined_existing = acquisition.joined_existing;
            analysis_job = std::move(acquisition.analysis_job);
            analysis_started = acquisition.analysis_started;
        }
        if (!workspace)
            return workspace_tool_error(aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::integrity_failure,
                "Static workspace acquisition returned no workspace",
                "disassemble_file.acquire"));
        for (;;) {
            const auto progress = workspace->progress();
            if ((progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
                 progress.readiness == aida::analysis::workspace_readiness_t::partial) &&
                workspace->snapshot())
                break;
            if (progress.error)
                return workspace_tool_error(*progress.error);
            if (cancellation.token().stop_requested()) {
                auto failure = aida::analysis::make_workspace_error(
                    cancellation.token().deadline_exceeded()
                        ? aida::analysis::workspace_error_code_t::deadline_exceeded
                        : aida::analysis::workspace_error_code_t::cancelled,
                    "Disassembly request stopped waiting for the shared analysis",
                    "disassemble_file.wait");
                failure.cancellation = !cancellation.token().deadline_exceeded();
                failure.deadline = cancellation.token().deadline_exceeded();
                return workspace_tool_error(failure);
            }
            if (analysis_job) {
                const auto waited = aida::infra::taskflow_runtime::wait_for(
                    *analysis_job, 25);
                if (waited.failed || waited.cancelled) {
                    const auto final_progress = workspace->progress();
                    if (final_progress.error)
                        return workspace_tool_error(*final_progress.error);
                    return workspace_tool_error(aida::analysis::make_workspace_error(
                        waited.cancelled ? aida::analysis::workspace_error_code_t::cancelled
                            : aida::analysis::workspace_error_code_t::integrity_failure,
                        waited.cancelled ? "Shared disassembly analysis was cancelled" :
                            "Shared disassembly analysis task graph failed",
                        "disassemble_file.wait"));
                }
                if (waited.completed) {
                    const auto final_progress = workspace->progress();
                    if ((final_progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
                         final_progress.readiness == aida::analysis::workspace_readiness_t::partial) &&
                        workspace->snapshot())
                        break;
                    return workspace_tool_error(aida::analysis::make_workspace_error(
                        aida::analysis::workspace_error_code_t::integrity_failure,
                        "Shared disassembly analysis completed without a publication",
                        "disassemble_file.wait"));
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
        const auto publication = workspace->analysis_publication();
        const auto image = workspace->image();
        if (!publication || !publication->snapshot || !image) {
            return workspace_tool_error(aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::integrity_failure,
                "Disassembly workspace has no immutable baseline publication",
                "disassemble_file.publish"));
        }
        std::vector<AsmInstr> formatted;
        formatted.reserve((std::min)(limit, publication->snapshot->instructions.size()));
        size_t offset = 0;
        while (offset < limit && offset < publication->snapshot->instructions.size()) {
            const size_t page_count = (std::min)({static_cast<size_t>(64), limit - offset,
                publication->snapshot->instructions.size() - offset});
            auto page = disasm::format_page(workspace, offset, page_count, cancellation.token());
            if (!page)
                return workspace_tool_error(page.error());
            auto values = page.take_value();
            formatted.insert(formatted.end(), values.begin(), values.end());
            offset += page_count;
        }
        std::uint64_t exec_sections = 0;
        std::uint64_t exec_bytes = 0;
        for (const auto& section : image->sections()) {
            if (section.executable) {
                ++exec_sections;
                exec_bytes += section.raw_size;
            }
        }
        json instructions = json::array();
        for (const auto& insn : formatted) {
            instructions.push_back({{"address", hex_addr(insn.addr)},
                {"mnemonic", insn.mnem}, {"operands", insn.ops}, {"length", insn.len}});
        }
        auto entry = image->rva_to_va(image->entry_rva());
        if (!entry)
            return workspace_tool_error(entry.error());
        json out;
        out["path"] = path;
        out["image_base"] = hex_addr(image->image_base());
        out["entry_point"] = hex_addr(entry.value());
        out["instruction_count"] = formatted.size();
        out["exec_section_count"] = exec_sections;
        out["exec_byte_count"] = exec_bytes;
        out["decode_limited"] = true;
        out["analysis_started"] = analysis_started;
        out["joined_existing"] = joined_existing;
        out["baseline_complete"] = publication->snapshot->baseline_complete;
        out["instructions"] = std::move(instructions);
        out["_meta"]["aida"] = json{{"binary_id", workspace->identity().binary_id().to_hex()},
            {"bin_name", workspace->identity().bin_name()}, {"kind", "static"},
            {"analysis_revision", workspace->analysis_revision()},
            {"overlay_revision", workspace->overlay_revision()}};
        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file complete path='%s' binary_id=%s instructions=%zu exec_sections=%llu exec_bytes=%llu",
            path.c_str(), workspace->identity().binary_id().to_hex().c_str(), formatted.size(),
            static_cast<unsigned long long>(exec_sections),
            static_cast<unsigned long long>(exec_bytes));
        return tool_result_t::ok("Disassembled PE file.", out);
    }

    tool_result_t handle_sandbox_execute(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_sandbox_execute entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const bool settings_enabled = g_sa_settings.sandbox.enabled;
        const bool feature_available = !sandbox::detail::windows_sandbox_exe().empty();
        if (!settings_enabled) {
            json out;
            out["dependency"] = "windows_sandbox";
            out["dependency_available"] = false;
            out["dependency_unavailable"] = true;
            out["dependency_blocked"] = true;
            out["settings_enabled"] = false;
            out["feature_available"] = feature_available;
            out["host_execution_attempted"] = false;
            out["reason"] = "sandbox_disabled_in_settings";
            return tool_result_t::error("Windows Sandbox execution is disabled in settings.", out);
        }
        if (!feature_available) {
            json out;
            out["dependency"] = "windows_sandbox";
            out["dependency_available"] = false;
            out["dependency_unavailable"] = true;
            out["dependency_blocked"] = true;
            out["settings_enabled"] = true;
            out["feature_available"] = false;
            out["host_execution_attempted"] = false;
            out["reason"] = "windows_sandbox_feature_unavailable";
            return tool_result_t::error("Windows Sandbox is unavailable. Enable the Windows Sandbox feature first.", out);
        }

        sandbox::config cfg;
        const auto exe_path = params["path"].get<std::string>();
        cfg.exe_path = std::wstring(exe_path.begin(), exe_path.end());
        if (params.contains("arguments") && params["arguments"].is_string()) {
            const auto arg_text = params["arguments"].get<std::string>();
            cfg.arguments = std::wstring(arg_text.begin(), arg_text.end());
        }
        if (params.contains("working_dir") && params["working_dir"].is_string()) {
            const auto work_dir = params["working_dir"].get<std::string>();
            cfg.working_dir = std::wstring(work_dir.begin(), work_dir.end());
        }
        cfg.timeout_ms = json_u32_param(params, "timeout_ms", g_sa_settings.sandbox.timeout_ms, 300000u);
        cfg.max_memory = static_cast<uint64_t>(g_sa_settings.sandbox.memory_limit_mb) * 1024ULL * 1024ULL;
        cfg.max_memory_mb = static_cast<uint32_t>(g_sa_settings.sandbox.memory_limit_mb);
        cfg.capture_stdout = json_bool_param(params, "capture_stdout", true);
        cfg.capture_stderr = json_bool_param(params, "capture_stderr", true);
        cfg.allow_network = g_sa_settings.sandbox.network_mode == "default";
        cfg.cancel_token = mcp_standalone::current_cancel_token();

        const auto run = sandbox::execute(cfg);
        if (run.cancelled)
            return error(run.error.empty() ? std::string("Sandbox execution cancelled by client request.") : run.error);
        if (!run.success && !run.timed_out)
            return error(run.error);

        json out;
        out["success"] = run.success;
        out["dependency"] = "windows_sandbox";
        out["dependency_available"] = true;
        out["dependency_unavailable"] = false;
        out["dependency_blocked"] = false;
        out["settings_enabled"] = settings_enabled;
        out["feature_available"] = feature_available;
        out["host_execution_attempted"] = true;
        out["exit_code"] = run.exit_code;
        out["pid"] = run.pid;
        out["timed_out"] = run.timed_out;
        out["killed"] = run.killed;
        out["cancelled"] = run.cancelled;
        out["elapsed_ms"] = run.elapsed_ms;
        out["session_dir"] = run.session_dir;
        out["wsb_path"] = run.wsb_path;
        if (!run.stdout_data.empty())
            out["stdout"] = run.stdout_data;
        if (!run.stderr_data.empty())
            out["stderr"] = run.stderr_data;
        return tool_result_t::ok("Executed sample inside Windows Sandbox.", out);
    }

    tool_result_t handle_convert_number(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_convert_number entry");
        auto value_text = [](const json& v) -> std::optional<std::string> {
            if (v.is_string())
                return v.get<std::string>();
            if (v.is_number_unsigned())
                return std::to_string(v.get<uint64_t>());
            if (v.is_number_integer())
                return std::to_string(v.get<int64_t>());
            return std::nullopt;
        };

        auto parse_radix = [](const json& root) -> int {
            const char* radix_key = root.contains("input_base") ? "input_base" : root.contains("from") ? "from" : nullptr;
            if (radix_key) {
                const auto& v = root[radix_key];
                if (v.is_number_integer())
                    return v.get<int>();
                if (v.is_string()) {
                    const auto s = to_lower(trim(v.get<std::string>()));
                    if (s == "auto")
                        return 0;
                    if (s == "hex" || s == "hexadecimal")
                        return 16;
                    if (s == "dec" || s == "decimal")
                        return 10;
                    if (s == "bin" || s == "binary")
                        return 2;
                    if (s == "oct" || s == "octal")
                        return 8;
                }
            }
            if (root.contains("base")) {
                const auto& v = root["base"];
                if (v.is_number_integer()) {
                    const int base = v.get<int>();
                    if (base == 0 || base == 2 || base == 8 || base == 10 || base == 16)
                        return base;
                }
                if (v.is_string()) {
                    const auto s = to_lower(trim(v.get<std::string>()));
                    if (s == "auto")
                        return 0;
                    if (s == "hex" || s == "hexadecimal")
                        return 16;
                    if (s == "dec" || s == "decimal")
                        return 10;
                    if (s == "bin" || s == "binary")
                        return 2;
                    if (s == "oct" || s == "octal")
                        return 8;
                    try {
                        const int base = std::stoi(s);
                        if (base == 0 || base == 2 || base == 8 || base == 10 || base == 16)
                            return base;
                    } catch (...) {
                    }
                }
            }
            return 0;
        };

        struct parsed_number_t {
            uint64_t value = 0;
            std::string normalized;
            std::string input_base;
            bool negative = false;
        };

        auto parse_number = [](std::string text, int forced_base) -> std::optional<parsed_number_t> {
            text = trim(text);
            if (text.empty())
                return std::nullopt;

            std::string compact;
            compact.reserve(text.size());
            for (char c : text) {
                if (c != '_' && c != '\'' && c != '`' && !std::isspace(static_cast<unsigned char>(c)))
                    compact.push_back(c);
            }
            if (compact.empty())
                return std::nullopt;

            bool negative = false;
            if (compact.front() == '+' || compact.front() == '-') {
                negative = compact.front() == '-';
                compact.erase(compact.begin());
            }
            if (compact.empty())
                return std::nullopt;

            int base = forced_base;
            if (base != 0 && base != 2 && base != 8 && base != 10 && base != 16)
                return std::nullopt;

            std::string digits = compact;
            if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
                if (base != 0 && base != 16)
                    return std::nullopt;
                base = 16;
                digits = digits.substr(2);
            } else if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'b' || digits[1] == 'B')) {
                if (base != 0 && base != 2)
                    return std::nullopt;
                base = 2;
                digits = digits.substr(2);
            } else if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'o' || digits[1] == 'O')) {
                if (base != 0 && base != 8)
                    return std::nullopt;
                base = 8;
                digits = digits.substr(2);
            } else if (!digits.empty()) {
                const char suffix = static_cast<char>(std::tolower(static_cast<unsigned char>(digits.back())));
                if (suffix == 'h' || suffix == 'b' || suffix == 'o' || suffix == 'd') {
                    const int suffix_base = suffix == 'h' ? 16 : suffix == 'b' ? 2 : suffix == 'o' ? 8 : 10;
                    if (base != 0 && base != suffix_base)
                        return std::nullopt;
                    base = suffix_base;
                    digits.pop_back();
                }
            }

            if (digits.empty())
                return std::nullopt;
            if (base == 0)
                base = (digits.size() > 1 && digits[0] == '0') ? 8 : 10;

            auto digit_value = [](char c) -> int {
                if (c >= '0' && c <= '9')
                    return c - '0';
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                return -1;
            };

            uint64_t magnitude = 0;
            for (char c : digits) {
                const int d = digit_value(c);
                if (d < 0 || d >= base)
                    return std::nullopt;
                const uint64_t ubase = static_cast<uint64_t>(base);
                if (magnitude > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(d)) / ubase)
                    return std::nullopt;
                magnitude = magnitude * ubase + static_cast<uint64_t>(d);
            }

            parsed_number_t parsed;
            parsed.value = negative ? (0ULL - magnitude) : magnitude;
            parsed.normalized = (negative ? "-" : "") + digits;
            parsed.input_base = base == 16 ? "hexadecimal" : base == 10 ? "decimal" : base == 8 ? "octal" : "binary";
            parsed.negative = negative;
            return parsed;
        };

        std::optional<std::string> input_opt;
        std::string inferred_kind;
        if (params.contains("value")) {
            input_opt = value_text(params["value"]);
        } else {
            for (const char* key : {"va", "rva", "file_offset", "foa"}) {
                if (!params.contains(key))
                    continue;
                input_opt = value_text(params[key]);
                inferred_kind = key;
                break;
            }
        }
        if (!input_opt)
            return error("Provide value, va, rva, file_offset, or foa as a string or integer.");

        const auto parsed = parse_number(*input_opt, parse_radix(params));
        if (!parsed)
            return error("Unable to parse the provided number.");

        const uint64_t value = parsed->value;

        auto mask_bits = [](int bits) -> uint64_t {
            return bits >= 64 ? std::numeric_limits<uint64_t>::max() : ((1ULL << bits) - 1ULL);
        };

        auto signed_value = [&](int bits) -> int64_t {
            const uint64_t mask = mask_bits(bits);
            const uint64_t masked = value & mask;
            if (bits >= 64)
                return static_cast<int64_t>(masked);
            const uint64_t sign = 1ULL << (bits - 1);
            if ((masked & sign) == 0)
                return static_cast<int64_t>(masked);
            const uint64_t magnitude = ((~masked) & mask) + 1ULL;
            return -static_cast<int64_t>(magnitude);
        };

        auto hex_width = [](uint64_t v, int digits) -> std::string {
            std::ostringstream ss;
            ss << "0x" << std::uppercase << std::hex << std::setw(digits) << std::setfill('0') << v;
            return ss.str();
        };

        auto octal_text = [](uint64_t v) -> std::string {
            std::ostringstream ss;
            ss << "0o" << std::oct << v;
            return ss.str();
        };

        auto binary_text = [](uint64_t v, int bits) -> std::string {
            std::string s;
            s.reserve(static_cast<size_t>(bits) + 2);
            for (int i = bits - 1; i >= 0; --i)
                s.push_back(((v >> i) & 1ULL) ? '1' : '0');
            const auto first = s.find_first_not_of('0');
            if (first == std::string::npos)
                s = "0";
            else
                s.erase(0, first);
            return "0b" + s;
        };

        auto bytes_hex = [&](uint64_t v, int bytes, bool little) -> std::string {
            std::ostringstream ss;
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                if (n)
                    ss << ' ';
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned int>((v >> (i * 8)) & 0xFFULL);
            }
            return ss.str();
        };

        auto byte_array = [&](uint64_t v, int bytes, bool little) -> json {
            json arr = json::array();
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                arr.push_back(static_cast<unsigned int>((v >> (i * 8)) & 0xFFULL));
            }
            return arr;
        };

        auto ascii_for = [&](uint64_t v, int bytes, bool little) -> std::string {
            std::string s;
            s.reserve(static_cast<size_t>(bytes));
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                const char c = static_cast<char>((v >> (i * 8)) & 0xFFULL);
                s.push_back(c >= 32 && c < 127 ? c : '.');
            }
            return s;
        };

        auto bit_count = [](uint64_t v) -> int {
            int n = 0;
            while (v) {
                v &= v - 1ULL;
                ++n;
            }
            return n;
        };

        auto low_bit_index = [](uint64_t v) -> int {
            if (!v)
                return -1;
            int i = 0;
            while ((v & 1ULL) == 0) {
                v >>= 1;
                ++i;
            }
            return i;
        };

        auto high_bit_index = [](uint64_t v) -> int {
            if (!v)
                return -1;
            int i = 63;
            while (((v >> i) & 1ULL) == 0)
                --i;
            return i;
        };

        auto align_down = [](uint64_t v, uint64_t a) -> uint64_t {
            return a ? (v / a) * a : v;
        };

        auto align_up = [](uint64_t v, uint64_t a) -> uint64_t {
            if (!a)
                return v;
            const uint64_t down = (v / a) * a;
            if (down == v)
                return v;
            if (down > std::numeric_limits<uint64_t>::max() - a)
                return std::numeric_limits<uint64_t>::max();
            return down + a;
        };

        auto min_bytes = [](uint64_t v) -> int {
            if (v <= 0xFFULL)
                return 1;
            if (v <= 0xFFFFULL)
                return 2;
            if (v <= 0xFFFFFFFFULL)
                return 4;
            return 8;
        };

        int display_bytes = min_bytes(value);
        if (params.contains("size") && params["size"].is_number_integer()) {
            const int requested = params["size"].get<int>();
            if (requested == 1 || requested == 2 || requested == 4 || requested == 8)
                display_bytes = requested;
        } else if (params.contains("bytes") && params["bytes"].is_number_integer()) {
            const int requested = params["bytes"].get<int>();
            if (requested == 1 || requested == 2 || requested == 4 || requested == 8)
                display_bytes = requested;
        } else if (params.contains("bits") && params["bits"].is_number_integer()) {
            const int requested = params["bits"].get<int>();
            if (requested == 8 || requested == 16 || requested == 32 || requested == 64)
                display_bytes = requested / 8;
        }

        json out;
        out["input"] = *input_opt;
        out["normalized_input"] = parsed->normalized;
        out["input_base"] = parsed->input_base;
        out["negative_input"] = parsed->negative;
        out["decimal"] = value;
        out["decimal_string"] = std::to_string(value);
        out["signed_decimal"] = static_cast<int64_t>(value);
        out["hex"] = hex_addr(value);
        out["hex_u64"] = hex_width(value, 16);
        out["octal"] = octal_text(value);
        out["binary"] = binary_text(value, std::max(1, high_bit_index(value) + 1));
        out["min_size_bytes"] = min_bytes(value);
        out["display_size_bytes"] = display_bytes;
        out["bytes_le"] = bytes_hex(value, display_bytes, true);
        out["bytes_be"] = bytes_hex(value, display_bytes, false);
        out["byte_array_le"] = byte_array(value, display_bytes, true);
        out["byte_array_be"] = byte_array(value, display_bytes, false);
        out["ascii"] = ascii_for(value, display_bytes, true);
        out["ascii_le"] = out["ascii"];
        out["ascii_be"] = ascii_for(value, display_bytes, false);

        json integers;
        for (int bits : {8, 16, 32, 64}) {
            const uint64_t masked = value & mask_bits(bits);
            json view;
            view["unsigned"] = masked;
            view["unsigned_hex"] = hex_width(masked, bits / 4);
            view["signed"] = signed_value(bits);
            view["bytes_le"] = bytes_hex(masked, bits / 8, true);
            view["bytes_be"] = bytes_hex(masked, bits / 8, false);
            integers["u" + std::to_string(bits)] = view;
        }
        out["integer_views"] = integers;
        out["u8"] = integers["u8"]["unsigned"];
        out["i8"] = integers["u8"]["signed"];
        out["u16"] = integers["u16"]["unsigned"];
        out["i16"] = integers["u16"]["signed"];
        out["u32"] = integers["u32"]["unsigned"];
        out["i32"] = integers["u32"]["signed"];
        out["u64"] = integers["u64"]["unsigned"];
        out["i64"] = integers["u64"]["signed"];

        json bits;
        bits["low8"] = value & 0xFFULL;
        bits["high8"] = (value >> 56) & 0xFFULL;
        bits["low16"] = value & 0xFFFFULL;
        bits["high16"] = (value >> 48) & 0xFFFFULL;
        bits["low32"] = value & 0xFFFFFFFFULL;
        bits["high32"] = (value >> 32) & 0xFFFFFFFFULL;
        bits["popcount"] = bit_count(value);
        bits["parity"] = bit_count(value) & 1;
        bits["lowest_set_bit"] = low_bit_index(value);
        bits["highest_set_bit"] = high_bit_index(value);
        bits["bit_length"] = value ? high_bit_index(value) + 1 : 0;
        bits["is_power_of_two"] = value != 0 && (value & (value - 1ULL)) == 0;
        bits["not"] = hex_addr(~value);
        out["bit_fields"] = bits;

        json floats;
        const uint32_t f_bits = static_cast<uint32_t>(value & 0xFFFFFFFFULL);
        float f = 0.0f;
        std::memcpy(&f, &f_bits, sizeof(f));
        if (std::isfinite(f))
            floats["float32"] = f;
        double d = 0.0;
        std::memcpy(&d, &value, sizeof(d));
        if (std::isfinite(d))
            floats["float64"] = d;
        out["floating_point"] = floats;

        json alignment;
        for (uint64_t a : {2ULL, 4ULL, 8ULL, 16ULL, 32ULL, 64ULL, 256ULL, 4096ULL}) {
            json view;
            view["down"] = hex_addr(align_down(value, a));
            view["up"] = hex_addr(align_up(value, a));
            view["offset"] = value % a;
            alignment[std::to_string(a)] = view;
        }
        out["alignment"] = alignment;

        auto parse_optional_value = [&](const char* key) -> std::optional<uint64_t> {
            if (!params.contains(key))
                return std::nullopt;
            const auto text = value_text(params[key]);
            if (!text)
                return std::nullopt;
            const auto parsed_value = parse_number(*text, 0);
            if (!parsed_value)
                return std::nullopt;
            return parsed_value->value;
        };

        std::optional<uint64_t> module_base = parse_optional_value("module_base");
        if (!module_base)
            module_base = parse_optional_value("image_base");
        std::optional<uint64_t> module_size = parse_optional_value("module_size");
        std::string module_name;
        if (params.contains("module_name") && params["module_name"].is_string()) {
            module_name = params["module_name"].get<std::string>();
            const auto target = to_lower(module_name);
            for (const auto& mod : driver_bridge::enumerate_modules()) {
                const auto name = to_lower(mod.name);
                const auto path = to_lower(mod.path);
                if (name == target || path.find(target) != std::string::npos) {
                    module_base = mod.base;
                    module_size = mod.size;
                    module_name = mod.name;
                    break;
                }
            }
        }

        if (!module_name.empty()) {
            const auto driver = driver_bridge::availability();
            out["driver_context"] = json{
                {"available", driver.device_connected && driver.kernel_backend && driver.target_attached},
                {"state", driver.state},
                {"reason", driver.reason},
                {"detail", driver.detail},
                {"target_pid", driver.target_pid}
            };
        }

        json address;
        if (module_base) {
            address["module_base"] = hex_addr(*module_base);
            if (module_size)
                address["module_size"] = *module_size;
            if (!module_name.empty())
                address["module_name"] = module_name;

            json as_va;
            as_va["va"] = hex_addr(value);
            if (value >= *module_base) {
                const uint64_t rva = value - *module_base;
                as_va["rva"] = hex_addr(rva);
                as_va["rva_decimal"] = rva;
                if (module_size)
                    as_va["inside_module"] = rva < *module_size;
                as_va["module_expr"] = (!module_name.empty() ? module_name : std::string("module")) + "+" + hex_addr(rva);
            } else {
                as_va["inside_module"] = false;
            }
            address["assuming_value_is_va"] = as_va;

            json as_rva;
            as_rva["rva"] = hex_addr(value);
            if (value <= std::numeric_limits<uint64_t>::max() - *module_base) {
                const uint64_t va = *module_base + value;
                as_rva["va"] = hex_addr(va);
                as_rva["va_decimal"] = va;
                if (module_size)
                    as_rva["inside_module"] = value < *module_size;
                as_rva["module_expr"] = (!module_name.empty() ? module_name : std::string("module")) + "+" + hex_addr(value);
            }
            address["assuming_value_is_rva"] = as_rva;

            const auto kind = !inferred_kind.empty()
                ? inferred_kind
                : params.contains("kind") && params["kind"].is_string()
                ? to_lower(trim(params["kind"].get<std::string>()))
                : params.contains("type") && params["type"].is_string()
                    ? to_lower(trim(params["type"].get<std::string>()))
                    : std::string();
            if (kind == "rva") {
                address["selected_kind"] = "rva";
                address["va"] = as_rva.value("va", "");
                address["rva"] = hex_addr(value);
            } else if (kind == "va") {
                address["selected_kind"] = "va";
                address["va"] = hex_addr(value);
                if (value >= *module_base)
                    address["rva"] = hex_addr(value - *module_base);
            }
        }

        const auto section_rva = parse_optional_value("section_rva").value_or(
            parse_optional_value("section_virtual_address").value_or(0));
        const auto section_va = parse_optional_value("section_va");
        const auto section_raw = parse_optional_value("section_raw").value_or(
            parse_optional_value("section_raw_offset").value_or(
                parse_optional_value("section_file_offset").value_or(0)));
        const auto section_virtual_size = parse_optional_value("section_virtual_size").value_or(0);
        const auto section_raw_size = parse_optional_value("section_raw_size").value_or(0);
        const uint64_t section_span = std::max<uint64_t>(section_virtual_size, section_raw_size);
        if ((section_rva || section_va) && section_span) {
            uint64_t base_rva = section_rva;
            if (section_va && module_base && *section_va >= *module_base)
                base_rva = *section_va - *module_base;

            auto in_range = [](uint64_t v, uint64_t start, uint64_t size) -> bool {
                return v >= start && v - start < size;
            };

            json pe;
            pe["section_rva"] = hex_addr(base_rva);
            pe["section_raw_offset"] = hex_addr(section_raw);
            pe["section_span"] = section_span;
            if (in_range(value, base_rva, section_span)) {
                const uint64_t file_offset = section_raw + (value - base_rva);
                pe["assuming_value_is_rva"] = json{{"file_offset", hex_addr(file_offset)}, {"file_offset_decimal", file_offset}};
            }
            if (module_base && value >= *module_base) {
                const uint64_t rva = value - *module_base;
                if (in_range(rva, base_rva, section_span)) {
                    const uint64_t file_offset = section_raw + (rva - base_rva);
                    pe["assuming_value_is_va"] = json{{"rva", hex_addr(rva)}, {"file_offset", hex_addr(file_offset)}, {"file_offset_decimal", file_offset}};
                }
            }
            if (in_range(value, section_raw, section_span)) {
                const uint64_t rva = base_rva + (value - section_raw);
                json foa{{"rva", hex_addr(rva)}, {"rva_decimal", rva}};
                if (module_base)
                    foa["va"] = hex_addr(*module_base + rva);
                pe["assuming_value_is_file_offset"] = foa;
            }
            out["pe_address_conversion"] = pe;
        }

        if (!address.empty())
            out["address_conversion"] = address;

        return tool_result_t::ok("Converted number.", out);
    }

    tool_result_t handle_read_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const fs::path path = params["path"].get<std::string>();
        if (!fs::exists(path) || !fs::is_regular_file(path))
            return error("File does not exist.");
        const auto content = file_to_utf8(path);
        return tool_result_t::ok("Read file.", json{{"path", path.string()}, {"content", content}});
    }

    tool_result_t handle_write_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_write_file entry");
        if (!params.contains("path") || !params["path"].is_string() ||
            !params.contains("content") || !params["content"].is_string())
            return error("Provide path and content.");
        const fs::path path = params["path"].get<std::string>();
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
            return error("Could not open the file for writing.");
        ofs << params["content"].get<std::string>();
        return tool_result_t::ok("Wrote file.", json{{"path", path.string()}});
    }

    tool_result_t handle_edit_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_edit_file entry");
        if (!params.contains("path") || !params["path"].is_string() ||
            !params.contains("find_text") || !params["find_text"].is_string() ||
            !params.contains("replace_text") || !params["replace_text"].is_string())
            return error("Provide path, find_text, and replace_text.");

        const fs::path path = params["path"].get<std::string>();
        auto content = file_to_utf8(path);
        if (content.empty() && !fs::exists(path))
            return error("Target file does not exist.");

        const std::string find_text = params["find_text"].get<std::string>();
        const std::string replace_text = params["replace_text"].get<std::string>();
        const bool replace_all = params.value("replace_all", true);

        size_t replacements = 0;
        size_t pos = 0;
        while ((pos = content.find(find_text, pos)) != std::string::npos) {
            content.replace(pos, find_text.size(), replace_text);
            pos += replace_text.size();
            ++replacements;
            if (!replace_all)
                break;
        }

        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
            return error("Could not open the file for editing.");
        ofs << content;
        return tool_result_t::ok("Edited file.", json{{"path", path.string()}, {"replacements", replacements}});
    }

    tool_result_t handle_delete_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_delete_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        std::error_code ec;
        const fs::path path = resolve_workspace_path(params["path"].get<std::string>());
        diag::log_tagged_fmt("mcp_tools", "handle_delete_file resolved=%s", path.string().c_str());
        if (!path_within_current_workspace(path))
            return error("Path is outside the workspace.");
        if (fs::is_directory(path, ec))
            return error("Path is a directory, not a file.");
        ec.clear();
        const auto removed = fs::remove(path, ec);
        if (!removed || ec)
            return error("Could not delete the requested file.");
        return tool_result_t::ok("Deleted file.", json{{"path", path.string()}});
    }

    tool_result_t handle_create_directory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_create_directory entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const std::string raw = params["path"].get<std::string>();
        fs::path workspace;
        fs::path path;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw, path, &workspace, resolve_error)) {
            json data{{"raw_path", raw},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_create_directory reject raw='%s' workspace='%s' cwd='%s' err='%s'",
                raw.c_str(),
                path_to_utf8(workspace).c_str(),
                current_cwd_utf8().c_str(),
                resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }
        std::error_code ec;
        const bool existed_before = fs::exists(path, ec);
        ec.clear();
        const bool created = fs::create_directories(path, ec);
        json data{{"raw_path", raw},
            {"resolved_path", path_to_utf8(path)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"existed_before", existed_before},
            {"created", created},
            {"error", ec ? ec.message() : std::string()}};
        diag::log_tagged_fmt("mcp_tools",
            "handle_create_directory done raw='%s' resolved='%s' workspace='%s' cwd='%s' existed=%d created=%d ec=%d err='%s'",
            raw.c_str(),
            path_to_utf8(path).c_str(),
            path_to_utf8(workspace).c_str(),
            current_cwd_utf8().c_str(),
            existed_before ? 1 : 0,
            created ? 1 : 0,
            ec ? 1 : 0,
            ec ? ec.message().c_str() : "");
        if (ec)
            return tool_result_t::error("Failed to create the requested directory.", data);
        return tool_result_t::ok("Created directory.", data);
    }

    tool_result_t handle_list_directory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_list_directory entry");
        const fs::path root = params.contains("path") && params["path"].is_string()
            ? fs::path(params["path"].get<std::string>())
            : fs::current_path();
        if (!fs::exists(root) || !fs::is_directory(root))
            return error("Directory does not exist.");

        json entries = json::array();
        for (const auto& entry : fs::directory_iterator(root)) {
            entries.push_back({
                {"name", entry.path().filename().string()},
                {"path", entry.path().string()},
                {"is_directory", entry.is_directory()},
                {"size", entry.is_regular_file() ? static_cast<uint64_t>(entry.file_size()) : 0ULL}
            });
        }
        return tool_result_t::ok("Listed directory.", json{{"path", root.string()}, {"entries", entries}});
    }

    tool_result_t handle_search_files(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_search_files entry");
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const std::string raw_root = params["root"].get<std::string>();
        const std::string pattern = params["pattern"].get<std::string>();
        fs::path workspace;
        fs::path root;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw_root, root, &workspace, resolve_error)) {
            json data{{"raw_root", raw_root},
                {"pattern", pattern},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_search_files reject raw_root='%s' pattern='%s' workspace='%s' cwd='%s' err='%s'",
                raw_root.c_str(), pattern.c_str(), path_to_utf8(workspace).c_str(),
                current_cwd_utf8().c_str(), resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }

        const size_t limit = bounded_size_param(params, "limit", 100, 1, 10000);
        const size_t max_visited = bounded_size_param(params, "max_visited", 200000, 1, 1000000);
        const uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 5000, 100, 60000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        diag::log_tagged_fmt("mcp_tools",
            "handle_search_files root_raw='%s' root='%s' workspace='%s' cwd='%s' pattern='%s' limit=%zu max_visited=%zu timeout_ms=%u",
            raw_root.c_str(), path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(),
            current_cwd_utf8().c_str(), pattern.c_str(), limit, max_visited,
            static_cast<unsigned>(timeout_ms));
        json matches = json::array();
        json errors = json::array();
        std::error_code ec;
        size_t visited = 0;
        size_t conversion_failures = 0;
        size_t outside_workspace_skips = 0;
        bool timed_out = false;
        bool cancelled = false;
        bool visit_limit_reached = false;
        bool match_limit_reached = false;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"error", ec ? ec.message() : std::string("Directory does not exist.")}};
            return tool_result_t::error("Directory does not exist.", data);
        }
        ec.clear();
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        if (ec) {
            errors.push_back(ec.message());
            ec.clear();
        }
        while (it != end) {
            if (mcp_standalone::current_call_cancelled()) {
                cancelled = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }
            if (visited >= max_visited) {
                visit_limit_reached = true;
                break;
            }
            if (ec) {
                diag::log_tagged_fmt("mcp_tools", "handle_search_files iterator_error after=%zu err=%s",
                    visited, ec.message().c_str());
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            const auto entry = *it;
            ++visited;
            fs::path resolved_entry = fs::weakly_canonical(entry.path(), ec);
            if (ec) {
                resolved_entry = entry.path().lexically_normal();
                errors.push_back(ec.message());
                ec.clear();
            }
            if (!path_within_workspace_root(resolved_entry, workspace)) {
                ++outside_workspace_skips;
                it.increment(ec);
                continue;
            }
            std::string filename = path_to_utf8(entry.path().filename());
            std::string full_path = path_to_utf8(entry.path());
            std::string relative_path;
            std::error_code rel_ec;
            relative_path = path_to_utf8(fs::relative(resolved_entry, workspace, rel_ec));
            if (rel_ec)
                relative_path = filename;
            if (filename.empty() && !entry.path().filename().empty()) {
                ++conversion_failures;
                diag::log_tagged_fmt("mcp_tools", "handle_search_files path_conversion_empty visited=%zu native_len=%zu",
                    visited, entry.path().native().size());
                continue;
            }
            if (glob_match_ci(filename, pattern) || glob_match_ci(relative_path, pattern)) {
                matches.push_back(json{{"path", full_path}, {"resolved_path", path_to_utf8(resolved_entry)}, {"relative_path", relative_path}});
                diag::log_tagged_fmt("mcp_tools", "handle_search_files match[%zu]='%s'",
                    matches.size(), full_path.c_str());
            }
            if (matches.size() >= limit) {
                match_limit_reached = true;
                break;
            }
            it.increment(ec);
        }
        if (ec) {
            diag::log_tagged_fmt("mcp_tools", "handle_search_files final_iterator_error visited=%zu matches=%zu err=%s",
                visited, matches.size(), ec.message().c_str());
            errors.push_back(ec.message());
        }
        diag::log_tagged_fmt("mcp_tools",
            "handle_search_files done root='%s' workspace='%s' cwd='%s' visited=%zu matches=%zu conversion_failures=%zu outside_workspace=%zu errors=%zu timed_out=%d cancelled=%d visit_limit=%d match_limit=%d",
            path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(),
            visited, matches.size(), conversion_failures, outside_workspace_skips, errors.size(),
            timed_out ? 1 : 0, cancelled ? 1 : 0, visit_limit_reached ? 1 : 0, match_limit_reached ? 1 : 0);
        return tool_result_t::ok("Searched files.", json{
            {"raw_root", raw_root},
            {"resolved_root", path_to_utf8(root)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"pattern", pattern},
            {"matches", matches},
            {"visited", visited},
            {"matched_count", matches.size()},
            {"conversion_failures", conversion_failures},
            {"outside_workspace_skips", outside_workspace_skips},
            {"limit", limit},
            {"max_visited", max_visited},
            {"timeout_ms", timeout_ms},
            {"timed_out", timed_out},
            {"cancelled", cancelled},
            {"visit_limit_reached", visit_limit_reached},
            {"match_limit_reached", match_limit_reached},
            {"errors", errors}
        });
    }

    tool_result_t handle_grep_in_files(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_grep_in_files entry");
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const std::string raw_root = params["root"].get<std::string>();
        const std::string pattern = params["pattern"].get<std::string>();
        const std::string file_pattern = params.value("file_pattern", std::string("*"));
        fs::path workspace;
        fs::path root;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw_root, root, &workspace, resolve_error)) {
            json data{{"raw_root", raw_root},
                {"pattern", pattern},
                {"file_pattern", file_pattern},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_grep_in_files reject raw_root='%s' workspace='%s' cwd='%s' err='%s'",
                raw_root.c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(), resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }
        std::regex rx;
        try {
            rx = std::regex(pattern, std::regex::icase);
        } catch (const std::regex_error& e) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"regex_error", e.what()}};
            return tool_result_t::error("Invalid regular expression.", data);
        }
        const size_t limit = bounded_size_param(params, "limit", 100, 1, 10000);
        const size_t max_visited = bounded_size_param(params, "max_visited", 100000, 1, 1000000);
        const size_t max_file_size = bounded_size_param(params, "max_file_size", 1024 * 1024, 1, 32 * 1024 * 1024);
        const uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 5000, 100, 60000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        json matches = json::array();
        json errors = json::array();

        std::error_code ec;
        size_t visited = 0;
        size_t files_considered = 0;
        size_t files_read = 0;
        size_t files_matched = 0;
        size_t binary_skips = 0;
        size_t oversized_skips = 0;
        size_t outside_workspace_skips = 0;
        size_t file_pattern_skips = 0;
        bool timed_out = false;
        bool cancelled = false;
        bool visit_limit_reached = false;
        bool match_limit_reached = false;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"error", ec ? ec.message() : std::string("Directory does not exist.")}};
            return tool_result_t::error("Directory does not exist.", data);
        }
        ec.clear();
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        if (ec) {
            errors.push_back(ec.message());
            ec.clear();
        }
        while (it != end) {
            if (mcp_standalone::current_call_cancelled()) {
                cancelled = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }
            if (visited >= max_visited) {
                visit_limit_reached = true;
                break;
            }
            if (ec) {
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            const auto entry = *it;
            ++visited;
            if (!entry.is_regular_file(ec))
            {
                ec.clear();
                it.increment(ec);
                continue;
            }
            ++files_considered;
            fs::path resolved_entry = fs::weakly_canonical(entry.path(), ec);
            if (ec) {
                resolved_entry = entry.path().lexically_normal();
                errors.push_back(ec.message());
                ec.clear();
            }
            if (!path_within_workspace_root(resolved_entry, workspace)) {
                ++outside_workspace_skips;
                it.increment(ec);
                continue;
            }
            std::string filename = path_to_utf8(entry.path().filename());
            std::string relative_path;
            std::error_code rel_ec;
            relative_path = path_to_utf8(fs::relative(resolved_entry, workspace, rel_ec));
            if (rel_ec)
                relative_path = filename;
            if (!glob_match_ci(filename, file_pattern) && !glob_match_ci(relative_path, file_pattern)) {
                ++file_pattern_skips;
                it.increment(ec);
                continue;
            }
            uintmax_t size = entry.file_size(ec);
            if (ec) {
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            if (size > max_file_size) {
                ++oversized_skips;
                it.increment(ec);
                continue;
            }
            const auto content = file_to_utf8(entry.path());
            if (size != 0 && content.empty()) {
                errors.push_back("read failed: " + path_to_utf8(entry.path()));
                it.increment(ec);
                continue;
            }
            if (file_content_looks_binary(content)) {
                ++binary_skips;
                it.increment(ec);
                continue;
            }
            ++files_read;
            std::smatch match;
            std::string::const_iterator search_start(content.cbegin());
            size_t line = 1;
            size_t offset = 0;
            bool file_had_match = false;
            while (std::regex_search(search_start, content.cend(), match, rx)) {
                offset = static_cast<size_t>(match.position(0) + std::distance(content.cbegin(), search_start));
                line = 1 + static_cast<size_t>(std::count(content.begin(), content.begin() + static_cast<long long>(offset), '\n'));
                matches.push_back({
                    {"path", path_to_utf8(entry.path())},
                    {"resolved_path", path_to_utf8(resolved_entry)},
                    {"relative_path", relative_path},
                    {"line", line},
                    {"match", match.str(0)}
                });
                file_had_match = true;
                search_start = match.suffix().first;
                if (matches.size() >= limit) {
                    match_limit_reached = true;
                    break;
                }
            }
            if (file_had_match)
                ++files_matched;
            if (match_limit_reached)
                break;
            it.increment(ec);
        }

        if (ec)
            errors.push_back(ec.message());
        diag::log_tagged_fmt("mcp_tools",
            "handle_grep_in_files done root='%s' workspace='%s' cwd='%s' visited=%zu considered=%zu read=%zu file_matches=%zu matches=%zu binary_skips=%zu oversized_skips=%zu outside_workspace=%zu file_pattern_skips=%zu errors=%zu timed_out=%d cancelled=%d visit_limit=%d match_limit=%d max_file_size=%zu",
            path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(),
            visited, files_considered, files_read, files_matched, matches.size(), binary_skips,
            oversized_skips, outside_workspace_skips, file_pattern_skips, errors.size(),
            timed_out ? 1 : 0, cancelled ? 1 : 0, visit_limit_reached ? 1 : 0,
            match_limit_reached ? 1 : 0, max_file_size);
        return tool_result_t::ok("Searched file contents.", json{
            {"raw_root", raw_root},
            {"resolved_root", path_to_utf8(root)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"pattern", pattern},
            {"file_pattern", file_pattern},
            {"matches", matches},
            {"visited", visited},
            {"files_considered", files_considered},
            {"files_read", files_read},
            {"files_matched", files_matched},
            {"matched_count", matches.size()},
            {"binary_skips", binary_skips},
            {"oversized_skips", oversized_skips},
            {"outside_workspace_skips", outside_workspace_skips},
            {"file_pattern_skips", file_pattern_skips},
            {"limit", limit},
            {"max_visited", max_visited},
            {"max_file_size", max_file_size},
            {"timeout_ms", timeout_ms},
            {"timed_out", timed_out},
            {"cancelled", cancelled},
            {"visit_limit_reached", visit_limit_reached},
            {"match_limit_reached", match_limit_reached},
            {"errors", errors}
        });
    }

    long long web_tool_elapsed_ms_since(const std::chrono::steady_clock::time_point& start)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
    }

    bool web_tool_is_loopback_fixture_url(const std::string& url)
    {
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const size_t scheme = lower.find("://");
        if (scheme == std::string::npos)
            return false;
        const size_t host_start = scheme + 3;
        if (host_start >= lower.size())
            return false;
        std::string host;
        if (lower[host_start] == '[') {
            const size_t host_end = lower.find(']', host_start + 1);
            if (host_end == std::string::npos)
                return false;
            host = lower.substr(host_start, host_end - host_start + 1);
        } else {
            const size_t host_end = lower.find_first_of("/:?#", host_start);
            host = lower.substr(host_start, host_end == std::string::npos ? std::string::npos : host_end - host_start);
        }
        return host == "localhost" || host == "[::1]" || host == "::1" || host.rfind("127.", 0) == 0;
    }

    bool web_tool_diagnostic_mode(const json& params)
    {
        return json_bool_param(params, "diagnostic", false)
            || json_bool_param(params, "diagnostics", false)
            || json_bool_param(params, "include_diagnostics", false);
    }

    json web_tool_navigation_summary(const aida::burp::camoufox::call_result_t& nav)
    {
        json summary;
        summary["ok"] = nav.ok;
        summary["error_length"] = nav.error.size();
        summary["text_length"] = nav.text.size();
        json payload = camoufox_value_json(nav);
        summary["payload_object"] = payload.is_object();
        if (payload.is_object()) {
            if (payload.contains("final_status"))
                summary["final_status"] = payload["final_status"];
            else if (payload.contains("status"))
                summary["final_status"] = payload["status"];
            if (payload.contains("navigation_timed_out"))
                summary["navigation_timed_out"] = payload["navigation_timed_out"];
            const std::string final_url = json_string_field(payload, "final_url");
            const std::string title = json_string_field(payload, "title");
            if (!final_url.empty())
                summary["final_url_length"] = final_url.size();
            if (!title.empty())
                summary["title_length"] = title.size();
            if (payload.contains("response_chain") && payload["response_chain"].is_array())
                summary["response_chain_count"] = payload["response_chain"].size();
        }
        return summary;
    }

    tool_result_t handle_web_search(const json& params)
    {
        const auto handler_start = std::chrono::steady_clock::now();
        diag::log_tagged_fmt("mcp_tools", "handle_web_search entry transport=camoufox");
        if (!params.contains("query") || !params["query"].is_string())
            return error("Provide a search query.");

        const std::string query = trim(params["query"].get<std::string>());
        if (query.empty())
            return error("Provide a non-empty search query.");
        const int max_results = std::clamp(params.value("max_results", 5), 1, 20);
        const int timeout_seconds = std::clamp(params.value("timeout", 15), 1, 60);
        const int timeout_ms = std::clamp(timeout_seconds * 1000 + 15000, 20000, 60000);
        const std::string encoded_query = web_tool_url_encode(query);

        const auto ready_start = std::chrono::steady_clock::now();
        if (!aida::burp::camoufox::ensure_ready()) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty())
                msg = "Camoufox browser is not ready for web_search.";
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_not_ready err=%s ready_ms=%lld total_ms=%lld",
                msg.c_str(),
                web_tool_elapsed_ms_since(ready_start),
                web_tool_elapsed_ms_since(handler_start));
            set_last_web_error(msg);
            return tool_result_t::error(msg);
        }
        const long long ready_ms = web_tool_elapsed_ms_since(ready_start);

        const std::string extract_js = R"JS((() => {
const maxResults = )JS" + std::to_string(max_results) + R"JS(;
const clean = (value) => String(value || '').replace(/\s+/g, ' ').trim();
const absolutize = (href) => { try { return new URL(href || '', location.href).href; } catch (_) { return ''; } };
const unwrapDuckDuckGo = (href) => {
  let url = absolutize(href);
  try {
    const parsed = new URL(url);
    if (parsed.hostname.endsWith('duckduckgo.com') && parsed.pathname.indexOf('/l/') === 0) {
      const target = parsed.searchParams.get('uddg');
      if (target) url = decodeURIComponent(target);
    }
  } catch (_) {}
  return url;
};
const blockedHost = (href) => {
  try {
    const host = new URL(href).hostname.toLowerCase();
    return host === location.hostname.toLowerCase() || host.endsWith('.duckduckgo.com') || host.endsWith('.bing.com') || host.endsWith('.microsoft.com/images');
  } catch (_) { return true; }
};
const resultContainer = (a) => a.closest('.result, .web-result, article, li.b_algo, li, div') || a.parentElement;
const readSnippet = (container, title) => {
  if (!container) return '';
  const selectors = ['.result__snippet', '.result__body', '.b_caption p', '[data-result="snippet"]', 'p', '.snippet'];
  for (const selector of selectors) {
    const node = container.querySelector(selector);
    const text = clean(node && node.innerText);
    if (text && text !== title) return text;
  }
  const text = clean(container.innerText);
  if (!text) return '';
  if (text.indexOf(title) === 0) return clean(text.slice(title.length));
  return text;
};
const anchors = Array.from(document.querySelectorAll('a.result__a, li.b_algo h2 a, article h2 a, [data-testid="result-title-a"], h2 a, a[href]'));
const results = [];
const seen = new Set();
for (const a of anchors) {
  if (results.length >= maxResults) break;
  const title = clean(a.innerText || a.textContent || a.getAttribute('aria-label'));
  let url = unwrapDuckDuckGo(a.getAttribute('href') || a.href || '');
  if (!title || !url || url.indexOf('javascript:') === 0 || url.indexOf('mailto:') === 0 || blockedHost(url)) continue;
  const key = url.replace(/#.*$/, '');
  if (seen.has(key)) continue;
  seen.add(key);
  const container = resultContainer(a);
  let snippet = readSnippet(container, title);
  if (!snippet) snippet = title;
  results.push({ title, snippet, url });
}
return { browser: 'camoufox', engine_url: location.href, page_title: document.title || '', candidates: anchors.length, results };
})())JS";

        struct provider_t { const char* name; std::string url; };
        const provider_t providers[] = {
            {"duckduckgo_html", "https://duckduckgo.com/html/?q=" + encoded_query},
            {"bing", "https://www.bing.com/search?q=" + encoded_query}
        };

        std::string failures;
        for (const auto& provider : providers) {
            const auto provider_start = std::chrono::steady_clock::now();
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("web_search cancelled by client request.");
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_begin provider=%s timeout_ms=%d query_len=%zu", provider.name, timeout_ms, query.size());
            json nav_args;
            nav_args["url"] = provider.url;
            nav_args["wait_until"] = "domcontentloaded";
            nav_args["collect_response_chain"] = true;
            nav_args["clear_network_capture"] = true;
            nav_args["include_title"] = true;
            const auto nav_start = std::chrono::steady_clock::now();
            auto nav = aida::burp::camoufox::call_tool("navigate", nav_args, timeout_ms);
            const long long nav_ms = web_tool_elapsed_ms_since(nav_start);
            if (!nav.ok) {
                std::string err = nav.error.empty() ? nav.text : nav.error;
                if (err.empty()) err = "navigate failed";
                diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_nav_failed provider=%s nav_ms=%lld err=%s", provider.name, nav_ms, err.c_str());
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": " + err;
                continue;
            }
            const auto eval_start = std::chrono::steady_clock::now();
            auto eval = aida::burp::camoufox::evaluate_js(extract_js, true);
            const long long eval_ms = web_tool_elapsed_ms_since(eval_start);
            if (!eval.ok) {
                std::string err = eval.error.empty() ? eval.text : eval.error;
                if (err.empty()) err = "evaluate_js failed";
                diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_eval_failed provider=%s nav_ms=%lld eval_ms=%lld err=%s", provider.name, nav_ms, eval_ms, err.c_str());
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": " + err;
                continue;
            }
            json payload = camoufox_value_json(eval);
            json results = json::array();
            if (payload.is_object() && payload.contains("results") && payload["results"].is_array())
                results = payload["results"];
            const size_t count = results.is_array() ? results.size() : 0;
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_result provider=%s results=%zu payload_object=%d final_url_len=%zu title_len=%zu",
                provider.name,
                count,
                payload.is_object() ? 1 : 0,
                json_string_field(payload, "engine_url").size(),
                json_string_field(payload, "page_title").size());
            if (count == 0) {
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": browser returned zero parseable results";
                continue;
            }
            if (results.size() > static_cast<size_t>(max_results))
                results.erase(results.begin() + max_results, results.end());
            json data;
            data["results"] = std::move(results);
            data["transport"] = "camoufox";
            data["browser"] = "camoufox";
            data["provider"] = provider.name;
            data["query"] = query;
            data["final_url"] = json_string_field(payload, "engine_url");
            data["page_title"] = json_string_field(payload, "page_title");
            data["candidate_links"] = payload.is_object() && payload.contains("candidates") ? payload["candidates"] : json(0);
            data["navigation_summary"] = web_tool_navigation_summary(nav);
            data["diagnostics_compact"] = true;
            data["timing_ms"] = {
                {"ready", ready_ms},
                {"navigation", nav_ms},
                {"evaluate", eval_ms},
                {"provider_total", web_tool_elapsed_ms_since(provider_start)},
                {"total", web_tool_elapsed_ms_since(handler_start)}
            };
            diag::log_tagged_fmt("mcp_tools",
                "handle_web_search camoufox_provider_timing provider=%s ready_ms=%lld nav_ms=%lld eval_ms=%lld provider_total_ms=%lld total_ms=%lld results=%zu",
                provider.name,
                ready_ms,
                nav_ms,
                eval_ms,
                web_tool_elapsed_ms_since(provider_start),
                web_tool_elapsed_ms_since(handler_start),
                count);
            return tool_result_t::ok("Found " + std::to_string(data["results"].size()) + " Camoufox browser result(s) for: " + query, data);
        }

        std::string msg = "Camoufox browser web_search returned no results for: " + query;
        if (!failures.empty())
            msg += " (" + failures + ")";
        set_last_web_error(msg);
        return tool_result_t::error(msg);
    }

    std::string webfetch_strip_blocks(const std::string& html)
    {
        std::string out = html;
        static const std::regex script_block("<script\\b[^>]*>[\\s\\S]*?</script>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex style_block("<style\\b[^>]*>[\\s\\S]*?</style>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex noscript_block("<noscript\\b[^>]*>[\\s\\S]*?</noscript>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex iframe_block("<iframe\\b[^>]*>[\\s\\S]*?</iframe>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex html_comment("<!--[\\s\\S]*?-->", std::regex::ECMAScript);
        out = std::regex_replace(out, script_block, "");
        out = std::regex_replace(out, style_block, "");
        out = std::regex_replace(out, noscript_block, "");
        out = std::regex_replace(out, iframe_block, "");
        out = std::regex_replace(out, html_comment, "");
        return out;
    }

    std::string webfetch_decode_entities(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        size_t i = 0;
        while (i < s.size()) {
            if (s[i] != '&') { out.push_back(s[i]); ++i; continue; }
            const auto semi = s.find(';', i + 1);
            if (semi == std::string::npos || semi - i > 12) { out.push_back(s[i]); ++i; continue; }
            const std::string entity = s.substr(i + 1, semi - i - 1);
            if (entity == "amp")        out.push_back('&');
            else if (entity == "lt")    out.push_back('<');
            else if (entity == "gt")    out.push_back('>');
            else if (entity == "quot")  out.push_back('"');
            else if (entity == "apos")  out.push_back('\'');
            else if (entity == "nbsp")  out.push_back(' ');
            else if (entity == "copy")  out.append("(c)");
            else if (entity == "reg")   out.append("(r)");
            else if (entity == "trade") out.append("(tm)");
            else if (entity == "hellip") out.append("...");
            else if (entity == "mdash") out.append("--");
            else if (entity == "ndash") out.append("-");
            else if (!entity.empty() && entity[0] == '#') {
                long codepoint = 0;
                bool ok = false;
                try {
                    if (entity.size() > 1 && (entity[1] == 'x' || entity[1] == 'X'))
                        codepoint = std::stol(entity.substr(2), nullptr, 16);
                    else
                        codepoint = std::stol(entity.substr(1), nullptr, 10);
                    ok = true;
                } catch (...) { ok = false; }
                if (ok && codepoint > 0 && codepoint <= 0x7F) {
                    out.push_back(static_cast<char>(codepoint));
                } else if (ok && codepoint > 0x7F && codepoint <= 0x7FF) {
                    out.push_back(static_cast<char>(0xC0 | ((codepoint >> 6) & 0x1F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else if (ok && codepoint > 0x7FF && codepoint <= 0xFFFF) {
                    out.push_back(static_cast<char>(0xE0 | ((codepoint >> 12) & 0x0F)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else if (ok && codepoint > 0xFFFF && codepoint <= 0x10FFFF) {
                    out.push_back(static_cast<char>(0xF0 | ((codepoint >> 18) & 0x07)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else {
                    out.append(s.substr(i, semi - i + 1));
                }
            } else {
                out.append(s.substr(i, semi - i + 1));
            }
            i = semi + 1;
        }
        return out;
    }

    std::string webfetch_collapse_whitespace(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        bool prev_blank = true;
        size_t consecutive_newlines = 0;
        for (char c : s) {
            if (c == '\r') continue;
            if (c == '\n') {
                if (consecutive_newlines < 2)
                    out.push_back('\n');
                ++consecutive_newlines;
                prev_blank = true;
                continue;
            }
            if (c == ' ' || c == '\t') {
                if (!prev_blank) out.push_back(' ');
                prev_blank = true;
                continue;
            }
            out.push_back(c);
            prev_blank = false;
            consecutive_newlines = 0;
        }
        while (!out.empty() && (out.back() == ' ' || out.back() == '\n')) out.pop_back();
        return out;
    }

    std::string webfetch_html_to_markdown(const std::string& html_in)
    {
        const std::string s = webfetch_strip_blocks(html_in);

        std::string out;
        out.reserve(s.size());
        const std::regex any_tag(
            "<(/?)([a-zA-Z][a-zA-Z0-9]*)\\b([^>]*)>",
            std::regex::ECMAScript);
        std::smatch match;
        std::string::const_iterator search_start = s.cbegin();
        std::string list_indent;
        bool in_pre = false;
        while (std::regex_search(search_start, s.cend(), match, any_tag)) {
            const auto prefix_begin = search_start;
            const auto prefix_end = match[0].first;
            std::string prefix(prefix_begin, prefix_end);
            out += prefix;

            const bool closing = match[1].length() == 1;
            std::string tag = match[2].str();
            std::string attrs = match[3].str();
            std::transform(tag.begin(), tag.end(), tag.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

            if (tag.size() == 2 && tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6') {
                if (!closing) {
                    out.append("\n\n");
                    const int level = tag[1] - '0';
                    out.append(static_cast<size_t>(level), '#');
                    out.push_back(' ');
                } else {
                    out.append("\n\n");
                }
            } else if (tag == "p" || tag == "div" || tag == "section" || tag == "article" ||
                       tag == "header" || tag == "footer" || tag == "main" || tag == "aside" ||
                       tag == "nav" || tag == "blockquote") {
                out.append("\n\n");
            } else if (tag == "br") {
                out.append("\n");
            } else if (tag == "hr") {
                out.append("\n\n---\n\n");
            } else if (tag == "ul" || tag == "ol") {
                if (!closing) list_indent.push_back('\t');
                else if (!list_indent.empty()) list_indent.pop_back();
                out.append("\n");
            } else if (tag == "li") {
                if (!closing) {
                    out.push_back('\n');
                    out.append(list_indent.empty() ? std::string() : list_indent.substr(1));
                    out.append("- ");
                }
            } else if (tag == "strong" || tag == "b") {
                out.append("**");
            } else if (tag == "em" || tag == "i") {
                out.push_back('*');
            } else if (tag == "code") {
                if (!in_pre) out.push_back('`');
            } else if (tag == "pre") {
                if (!closing) { out.append("\n\n```\n"); in_pre = true; }
                else { out.append("\n```\n\n"); in_pre = false; }
            } else if (tag == "a" && !closing) {
                std::string href;
                static const std::regex href_rx("href\\s*=\\s*\"([^\"]*)\"|href\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                std::smatch href_match;
                if (std::regex_search(attrs, href_match, href_rx)) {
                    href = href_match[1].matched ? href_match[1].str() : href_match[2].str();
                }
                out.append("__AIDA_A_OPEN__");
                out.append(href);
                out.append("__AIDA_A_HREF__");
            } else if (tag == "a" && closing) {
                out.append("__AIDA_A_CLOSE__");
            } else if (tag == "img" && !closing) {
                std::string alt, src;
                static const std::regex alt_rx("alt\\s*=\\s*\"([^\"]*)\"|alt\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                static const std::regex src_rx("src\\s*=\\s*\"([^\"]*)\"|src\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                std::smatch a_match, s_match;
                if (std::regex_search(attrs, a_match, alt_rx))
                    alt = a_match[1].matched ? a_match[1].str() : a_match[2].str();
                if (std::regex_search(attrs, s_match, src_rx))
                    src = s_match[1].matched ? s_match[1].str() : s_match[2].str();
                out.push_back('!');
                out.push_back('[');
                out.append(alt);
                out.append("](");
                out.append(src);
                out.push_back(')');
            }

            search_start = match[0].second;
        }
        out.append(search_start, s.cend());

        std::string final_out;
        final_out.reserve(out.size());
        size_t i = 0;
        while (i < out.size()) {
            const auto open_pos = out.find("__AIDA_A_OPEN__", i);
            if (open_pos == std::string::npos) {
                final_out.append(out, i, std::string::npos);
                break;
            }
            final_out.append(out, i, open_pos - i);
            const auto href_pos = out.find("__AIDA_A_HREF__", open_pos + 15);
            if (href_pos == std::string::npos) {
                final_out.append(out, open_pos, std::string::npos);
                break;
            }
            const auto close_pos = out.find("__AIDA_A_CLOSE__", href_pos + 15);
            std::string href = out.substr(open_pos + 15, href_pos - (open_pos + 15));
            std::string text;
            if (close_pos != std::string::npos)
                text = out.substr(href_pos + 15, close_pos - (href_pos + 15));
            else
                text = out.substr(href_pos + 15);
            const std::string trimmed_text = trim(text);
            if (!href.empty() && !trimmed_text.empty()) {
                final_out.push_back('[');
                final_out.append(trimmed_text);
                final_out.push_back(']');
                final_out.push_back('(');
                final_out.append(href);
                final_out.push_back(')');
            } else if (!trimmed_text.empty()) {
                final_out.append(trimmed_text);
            } else if (!href.empty()) {
                final_out.append(href);
            }
            i = (close_pos == std::string::npos) ? out.size() : close_pos + 16;
        }

        std::string decoded = webfetch_decode_entities(final_out);
        return webfetch_collapse_whitespace(decoded);
    }

    tool_result_t handle_webfetch(const json& params)
    {
        const auto handler_start = std::chrono::steady_clock::now();
        char trace_id[64] = {};
        _snprintf_s(trace_id, sizeof(trace_id), _TRUNCATE,
            "webfetch-%lu-%llu",
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(GetTickCount64()));
        const auto status_entry = aida::burp::camoufox::get_status();
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch entry transport=camoufox trace_id=%s bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu cleanup_pending=%d",
            trace_id,
            static_cast<int>(status_entry.state),
            status_entry.child_pid,
            status_entry.child_alive ? 1 : 0,
            status_entry.browser_open ? 1 : 0,
            status_entry.page_verified ? 1 : 0,
            status_entry.page_count,
            status_entry.active_page_url.size(),
            static_cast<unsigned long long>(status_entry.total_calls),
            static_cast<unsigned long long>(status_entry.total_errors),
            status_entry.cleanup_pending ? 1 : 0);
        if (!params.contains("url") || !params["url"].is_string())
            return error("Missing required parameter: url");

        if (mcp_standalone::current_call_cancelled())
            return error("webfetch cancelled by client request.");

        const std::string url = trim(params["url"].get<std::string>());
        if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0)
            return error("URL must start with http:// or https://");

        std::string format = "markdown";
        if (params.contains("format") && params["format"].is_string()) {
            const std::string requested = params["format"].get<std::string>();
            if (requested == "markdown" || requested == "text" || requested == "html")
                format = requested;
            else
                return error("format must be one of: markdown, text, html");
        }

        int timeout_sec = 30;
        if (params.contains("timeout")) {
            if (params["timeout"].is_number_integer())
                timeout_sec = params["timeout"].get<int>();
            else if (params["timeout"].is_number())
                timeout_sec = static_cast<int>(params["timeout"].get<double>());
        }
        timeout_sec = std::clamp(timeout_sec, 1, 120);
        const int timeout_ms = std::clamp(timeout_sec * 1000 + 10000, 15000, 130000);
        const bool local_fixture = web_tool_is_loopback_fixture_url(url);
        const bool diagnostic_mode = web_tool_diagnostic_mode(params);

        const auto ready_start = std::chrono::steady_clock::now();
        if (!aida::burp::camoufox::ensure_ready()) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty())
                msg = "Camoufox browser is not ready for webfetch.";
            const auto status_failed = aida::burp::camoufox::get_status();
            diag::log_tagged_fmt("mcp_tools", "handle_webfetch camoufox_not_ready err=%s ready_ms=%lld total_ms=%lld",
                msg.c_str(),
                web_tool_elapsed_ms_since(ready_start),
                web_tool_elapsed_ms_since(handler_start));
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_not_ready_status trace_id=%s bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu cleanup_pending=%d last_error_len=%zu",
                trace_id,
                static_cast<int>(status_failed.state),
                status_failed.child_pid,
                status_failed.child_alive ? 1 : 0,
                status_failed.browser_open ? 1 : 0,
                status_failed.page_verified ? 1 : 0,
                status_failed.page_count,
                status_failed.active_page_url.size(),
                static_cast<unsigned long long>(status_failed.total_calls),
                static_cast<unsigned long long>(status_failed.total_errors),
                status_failed.cleanup_pending ? 1 : 0,
                status_failed.last_error.size());
            return tool_result_t::error(msg);
        }
        const long long ready_ms = web_tool_elapsed_ms_since(ready_start);
        const auto status_ready = aida::burp::camoufox::get_status();

        const int nav_timeout_ms = local_fixture ? std::min(timeout_ms, 15000) : timeout_ms;
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_ready trace_id=%s ready_ms=%lld bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu cleanup_pending=%d",
            trace_id,
            ready_ms,
            static_cast<int>(status_ready.state),
            status_ready.child_pid,
            status_ready.child_alive ? 1 : 0,
            status_ready.browser_open ? 1 : 0,
            status_ready.page_verified ? 1 : 0,
            status_ready.page_count,
            status_ready.active_page_url.size(),
            status_ready.active_page_title.size(),
            static_cast<unsigned long long>(status_ready.total_calls),
            static_cast<unsigned long long>(status_ready.total_errors),
            static_cast<unsigned long long>(status_ready.last_call_ms),
            static_cast<unsigned long long>(status_ready.last_nav_ms),
            status_ready.cleanup_pending ? 1 : 0);
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_navigate_begin trace_id=%s url_len=%zu format=%s timeout_ms=%d nav_timeout_ms=%d local_fixture=%d diagnostic=%d wait_until=domcontentloaded collect_response_chain=%d clear_network_capture=%d fast_ready=%d",
            trace_id,
            url.size(),
            format.c_str(),
            timeout_ms,
            nav_timeout_ms,
            local_fixture ? 1 : 0,
            diagnostic_mode ? 1 : 0,
            (!local_fixture || diagnostic_mode) ? 1 : 0,
            (!local_fixture || diagnostic_mode) ? 1 : 0,
            (local_fixture && !diagnostic_mode) ? 1 : 0);
        json nav_args;
        nav_args["url"] = url;
        nav_args["wait_until"] = "domcontentloaded";
        nav_args["collect_response_chain"] = !local_fixture || diagnostic_mode;
        nav_args["clear_network_capture"] = !local_fixture || diagnostic_mode;
        nav_args["include_title"] = true;
        nav_args["diagnostic"] = diagnostic_mode;
        nav_args["aida_local_fixture_fast_ready"] = local_fixture && !diagnostic_mode;
        nav_args["aida_trace_id"] = trace_id;
        const auto nav_start = std::chrono::steady_clock::now();
        auto nav = aida::burp::camoufox::call_tool("navigate", nav_args, nav_timeout_ms);
        const long long nav_ms = web_tool_elapsed_ms_since(nav_start);
        const auto status_after_nav = aida::burp::camoufox::get_status();
        json nav_status_payload = camoufox_value_json(nav);
        if (!nav.ok) {
            std::string msg = nav.error.empty() ? nav.text : nav.error;
            if (msg.empty()) msg = "Camoufox navigation failed for webfetch.";
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_navigate_failed trace_id=%s err=%s ready_ms=%lld nav_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu payload_object=%d final_status_present=%d response_chain_count=%zu last_error_len=%zu",
                trace_id,
                msg.c_str(),
                ready_ms,
                nav_ms,
                web_tool_elapsed_ms_since(handler_start),
                local_fixture ? 1 : 0,
                static_cast<int>(status_after_nav.state),
                status_after_nav.child_pid,
                status_after_nav.child_alive ? 1 : 0,
                status_after_nav.browser_open ? 1 : 0,
                status_after_nav.page_verified ? 1 : 0,
                status_after_nav.page_count,
                status_after_nav.active_page_url.size(),
                status_after_nav.active_page_title.size(),
                static_cast<unsigned long long>(status_after_nav.total_calls),
                static_cast<unsigned long long>(status_after_nav.total_errors),
                static_cast<unsigned long long>(status_after_nav.last_call_ms),
                static_cast<unsigned long long>(status_after_nav.last_nav_ms),
                nav_status_payload.is_object() ? 1 : 0,
                nav_status_payload.is_object() && (nav_status_payload.contains("final_status") || nav_status_payload.contains("status")) ? 1 : 0,
                nav_status_payload.is_object() && nav_status_payload.contains("response_chain") && nav_status_payload["response_chain"].is_array() ? nav_status_payload["response_chain"].size() : 0,
                status_after_nav.last_error.size());
            return tool_result_t::error(msg);
        }
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_navigate_ok trace_id=%s ready_ms=%lld nav_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu payload_object=%d final_status_present=%d response_chain_count=%zu",
            trace_id,
            ready_ms,
            nav_ms,
            web_tool_elapsed_ms_since(handler_start),
            local_fixture ? 1 : 0,
            static_cast<int>(status_after_nav.state),
            status_after_nav.child_pid,
            status_after_nav.child_alive ? 1 : 0,
            status_after_nav.browser_open ? 1 : 0,
            status_after_nav.page_verified ? 1 : 0,
            status_after_nav.page_count,
            status_after_nav.active_page_url.size(),
            status_after_nav.active_page_title.size(),
            static_cast<unsigned long long>(status_after_nav.total_calls),
            static_cast<unsigned long long>(status_after_nav.total_errors),
            static_cast<unsigned long long>(status_after_nav.last_call_ms),
            static_cast<unsigned long long>(status_after_nav.last_nav_ms),
            nav_status_payload.is_object() ? 1 : 0,
            nav_status_payload.is_object() && (nav_status_payload.contains("final_status") || nav_status_payload.contains("status")) ? 1 : 0,
            nav_status_payload.is_object() && nav_status_payload.contains("response_chain") && nav_status_payload["response_chain"].is_array() ? nav_status_payload["response_chain"].size() : 0);

        const size_t max_browser_chars = 5u * 1024u * 1024u;
        const std::string extract_js = R"JS((() => {
const maxChars = )JS" + std::to_string(max_browser_chars) + R"JS(;
const root = document.documentElement;
const body = document.body;
let html = root ? root.outerHTML : '';
let text = body ? body.innerText : (root ? root.textContent : '');
let htmlTruncated = false;
let textTruncated = false;
if (html.length > maxChars) { html = html.slice(0, maxChars); htmlTruncated = true; }
if (text.length > maxChars) { text = text.slice(0, maxChars); textTruncated = true; }
const fixtureMarker = !!document.querySelector('[data-aida-fixture], [data-aida-fixture-ready], #aida-mcp-fixture, #aida-webfetch-fixture, [data-testid="aida-webfetch-fixture"]')
  || /AIDA_MCP_FIXTURE|AIDA_WEBFETCH_FIXTURE|aida-webfetch-fixture/i.test(text || '')
  || /AIDA_MCP_FIXTURE|AIDA_WEBFETCH_FIXTURE|aida-webfetch-fixture/i.test(html || '');
return {
  browser: 'camoufox',
  url: location.href,
  title: document.title || '',
  content_type: document.contentType || '',
  charset: document.characterSet || '',
  ready_state: document.readyState || '',
  html,
  text,
  body_length: text.length,
  html_length: html.length,
  fixture_marker: fixtureMarker,
  html_truncated: htmlTruncated,
  text_truncated: textTruncated
};
})())JS";

        const auto extract_start = std::chrono::steady_clock::now();
        auto extracted = aida::burp::camoufox::evaluate_js(extract_js, true);
        const long long extract_ms = web_tool_elapsed_ms_since(extract_start);
        const auto status_after_extract = aida::burp::camoufox::get_status();
        if (!extracted.ok) {
            std::string msg = extracted.error.empty() ? extracted.text : extracted.error;
            if (msg.empty()) msg = "Camoufox page extraction failed for webfetch.";
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_extract_failed trace_id=%s err=%s ready_ms=%lld nav_ms=%lld extract_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu",
                trace_id,
                msg.c_str(),
                ready_ms,
                nav_ms,
                extract_ms,
                web_tool_elapsed_ms_since(handler_start),
                local_fixture ? 1 : 0,
                static_cast<int>(status_after_extract.state),
                status_after_extract.child_pid,
                status_after_extract.child_alive ? 1 : 0,
                status_after_extract.browser_open ? 1 : 0,
                status_after_extract.page_verified ? 1 : 0,
                status_after_extract.page_count,
                status_after_extract.active_page_url.size(),
                status_after_extract.active_page_title.size(),
                static_cast<unsigned long long>(status_after_extract.total_calls),
                static_cast<unsigned long long>(status_after_extract.total_errors),
                static_cast<unsigned long long>(status_after_extract.last_call_ms),
                static_cast<unsigned long long>(status_after_extract.last_nav_ms));
            return tool_result_t::error(msg);
        }

        json payload = camoufox_value_json(extracted);
        if (!payload.is_object()) {
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_extract_unexpected payload_object=0 ready_ms=%lld nav_ms=%lld extract_ms=%lld total_ms=%lld",
                ready_ms,
                nav_ms,
                extract_ms,
                web_tool_elapsed_ms_since(handler_start));
            return tool_result_t::error("Camoufox page extraction returned an unexpected payload.");
        }

        const auto convert_start = std::chrono::steady_clock::now();
        std::string html = json_string_field(payload, "html");
        std::string page_text = json_string_field(payload, "text");
        const std::string final_url = json_string_field(payload, "url");
        const std::string title = json_string_field(payload, "title");
        const std::string content_type = json_string_field(payload, "content_type");
        if (html.empty() && page_text.empty())
            return tool_result_t::error("Camoufox webfetch extracted an empty page.");

        std::string output;
        if (format == "html") {
            output = std::move(html);
        } else if (format == "text") {
            output = std::move(page_text);
        } else {
            output = html.empty() ? page_text : webfetch_html_to_markdown(html);
        }

        constexpr size_t MAX_OUTPUT_BYTES = 200000u;
        bool truncated = false;
        if (output.size() > MAX_OUTPUT_BYTES) {
            output.resize(MAX_OUTPUT_BYTES);
            truncated = true;
        }
        const long long convert_ms = web_tool_elapsed_ms_since(convert_start);

        json nav_payload = nav_status_payload;
        json data;
        data["trace_id"] = trace_id;
        data["url"] = final_url.empty() ? url : final_url;
        data["requested_url"] = url;
        data["title"] = title;
        data["format"] = format;
        data["content_type"] = content_type;
        data["charset"] = json_string_field(payload, "charset");
        data["ready_state"] = json_string_field(payload, "ready_state");
        data["bytes"] = static_cast<int64_t>(output.size());
        data["truncated"] = truncated;
        data["transport"] = "camoufox";
        data["browser"] = "camoufox";
        data["status_source"] = "camoufox_response_chain";
        data["status"] = 0;
        if (nav_payload.is_object()) {
            if (nav_payload.contains("final_status") && nav_payload["final_status"].is_number_integer())
                data["status"] = nav_payload["final_status"];
            else if (nav_payload.contains("status") && nav_payload["status"].is_number_integer())
                data["status"] = nav_payload["status"];
            else
                data["status_source"] = "not_reported";
            if ((diagnostic_mode || !local_fixture) && nav_payload.contains("response_chain"))
                data["response_chain"] = nav_payload["response_chain"];
            else if (nav_payload.contains("response_chain") && nav_payload["response_chain"].is_array())
                data["response_chain_count"] = nav_payload["response_chain"].size();
        } else {
            data["status_source"] = "not_reported";
        }
        data["local_fixture"] = local_fixture;
        data["fixture_marker"] = payload.contains("fixture_marker") && payload["fixture_marker"].is_boolean() ? payload["fixture_marker"] : json(false);
        data["diagnostics_compact"] = local_fixture && !diagnostic_mode;
        data["navigation_summary"] = web_tool_navigation_summary(nav);
        data["timing_ms"] = {
            {"ready", ready_ms},
            {"navigation", nav_ms},
            {"extract", extract_ms},
            {"convert", convert_ms},
            {"total", web_tool_elapsed_ms_since(handler_start)}
        };
        data["camoufox_status"] = {
            {"bridge_state", static_cast<int>(status_after_extract.state)},
            {"child_pid", status_after_extract.child_pid},
            {"child_alive", status_after_extract.child_alive},
            {"browser_open", status_after_extract.browser_open},
            {"page_verified", status_after_extract.page_verified},
            {"page_count", status_after_extract.page_count},
            {"active_page_url_len", status_after_extract.active_page_url.size()},
            {"active_page_title_len", status_after_extract.active_page_title.size()},
            {"total_calls", status_after_extract.total_calls},
            {"total_errors", status_after_extract.total_errors},
            {"last_call_ms", status_after_extract.last_call_ms},
            {"last_nav_ms", status_after_extract.last_nav_ms},
            {"cleanup_pending", status_after_extract.cleanup_pending}
        };
        data["html_truncated_in_browser"] = payload.contains("html_truncated") && payload["html_truncated"].is_boolean() ? payload["html_truncated"] : json(false);
        data["text_truncated_in_browser"] = payload.contains("text_truncated") && payload["text_truncated"].is_boolean() ? payload["text_truncated"] : json(false);

        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_ok trace_id=%s final_url_len=%zu title_len=%zu format=%s bytes=%zu status=%lld status_source=%s truncated=%d local_fixture=%d fixture_marker=%d ready_ms=%lld nav_ms=%lld extract_ms=%lld convert_ms=%lld total_ms=%lld bridge_state=%d child_pid=%u child_alive=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu",
            trace_id,
            data["url"].is_string() ? data["url"].get<std::string>().size() : 0,
            title.size(),
            format.c_str(),
            output.size(),
            data["status"].is_number_integer() ? static_cast<long long>(data["status"].get<int64_t>()) : 0LL,
            json_string_field(data, "status_source").c_str(),
            truncated ? 1 : 0,
            local_fixture ? 1 : 0,
            data["fixture_marker"].is_boolean() && data["fixture_marker"].get<bool>() ? 1 : 0,
            ready_ms,
            nav_ms,
            extract_ms,
            convert_ms,
            web_tool_elapsed_ms_since(handler_start),
            static_cast<int>(status_after_extract.state),
            status_after_extract.child_pid,
            status_after_extract.child_alive ? 1 : 0,
            status_after_extract.page_count,
            status_after_extract.active_page_url.size(),
            static_cast<unsigned long long>(status_after_extract.total_calls),
            static_cast<unsigned long long>(status_after_extract.total_errors),
            static_cast<unsigned long long>(status_after_extract.last_call_ms),
            static_cast<unsigned long long>(status_after_extract.last_nav_ms));

        std::string text;
        text.reserve(output.size() + 160);
        text += "Fetched via Camoufox ";
        text += final_url.empty() ? url : final_url;
        text += " (";
        text += content_type.empty() ? std::string("browser-rendered") : content_type;
        text += ")\n\n";
        text += output;
        if (truncated)
            text += "\n\n[truncated to " + std::to_string(MAX_OUTPUT_BYTES) + " bytes]";

        return tool_result_t::ok(text, data);
    }

}

namespace mcp_standalone
{

    tool_result_t read_live_struct(const json& params)
    {
        return handle_read_struct(params);
    }

    void register_standalone_tools(server_t& srv)
    {
        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools entry");

        srv.register_tool({"get_tool_descriptions",
            "Return full descriptions and parameter schemas for selected MCP tool names or grouped packs such as browser, network, and burp.",
            {{"names", "array", "Tool names to describe", false},
             {"name", "string", "Single tool name to describe", false},
             {"prefix", "string", "Tool name prefix to search", false},
             {"query", "string", "Tool name or description search text; exact group aliases include all browser tools, all network tools, and all burp tools", false},
             {"group", "string", "Direct grouped pack name: browser|network|burp", false},
             {"limit", "number", "Maximum matching tools to return", false},
             {"include_schema", "boolean", "Include parameter names, types, and descriptions", false}},
            true,
            [&srv](const json& params) { return srv.describe_tools(params); }});

        srv.register_tool({"vm_bridge_manage", "Activate, inspect, and operate a custom VM shared-folder bridge. Use this for VMware, VirtualBox, QEMU, Hyper-V, or manually managed Windows VMs while keeping AiDAStandalone.exe on the host.",
            {{"action", "string", "status|activate|deactivate|ping|attach|detach|list_processes|modules|threads|memory_map|query_memory|read_memory|read_string|dump_region|search_memory", false},
             {"bridge_dir", "string", "Host path to the shared bridge folder for action=activate", false},
             {"guest_bridge_dir", "string", "Guest-visible path to the same bridge folder; returned in guest_command", false},
             {"host_sample", "string", "Optional host-side sample path copied into bridge\\samples during activation", false},
             {"guest_sample", "string", "Optional guest-visible sample path written to launch_config.json", false},
             {"sample", "string", "Alias for guest_sample", false},
             {"args", "string", "Optional sample arguments written to launch_config.json", false},
             {"write_launch_config", "boolean", "Write launch_config.json during activation (default true)", false},
             {"stage_agent", "boolean", "Copy AiDAGuestAgent.exe into bridge\\agent during activation (default true)", false},
             {"pid", "number", "Guest process id for attach or memory operations", false},
             {"process", "string", "Guest process name for action=attach", false},
             {"address", "string", "Guest process virtual address for memory operations", false},
             {"size", "number", "Byte count for read_memory or dump_region", false},
             {"pattern", "string", "Hex byte pattern for search_memory; use ?? wildcards", false},
             {"target", "string", "Accepted for consistency; VM bridge actions always address the guest", false},
             {"timeout_ms", "number", "Guest bridge timeout in milliseconds", false}},
            false, handle_vm_bridge_manage});

        srv.register_tool({"list_processes", "Enumerate processes. If a VM bridge is active this lists VM processes by default; pass target='host' for host processes.",
            {{"filter", "string", "Optional substring filter", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}}, true, handle_list_processes});
        srv.register_tool({"read_memory", "Read bytes or a typed scalar/string from the attached process. If a VM bridge is active this reads VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"size", "number", "Bytes to read", false},
             {"value_type", "string", "Optional typed decode: byte/int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double/ascii/utf16", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, handle_read_memory});
        srv.register_tool({"read_u8", "Read an unsigned 8-bit value from one address or an addresses batch.",
            {{"address", "string", "Target address or arithmetic expression", false}, {"addresses", "array", "Batch address expressions", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, [](const json& params) { return handle_fixed_typed_read(params, "uint8", 1); }});
        srv.register_tool({"read_u16", "Read an unsigned 16-bit value from one address or an addresses batch.",
            {{"address", "string", "Target address or arithmetic expression", false}, {"addresses", "array", "Batch address expressions", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, [](const json& params) { return handle_fixed_typed_read(params, "uint16", 2); }});
        srv.register_tool({"read_u32", "Read an unsigned 32-bit value from one address or an addresses batch.",
            {{"address", "string", "Target address or arithmetic expression", false}, {"addresses", "array", "Batch address expressions", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, [](const json& params) { return handle_fixed_typed_read(params, "uint32", 4); }});
        srv.register_tool({"read_u64", "Read an unsigned 64-bit value from one address or an addresses batch.",
            {{"address", "string", "Target address or arithmetic expression", false}, {"addresses", "array", "Batch address expressions", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, [](const json& params) { return handle_fixed_typed_read(params, "uint64", 8); }});
        srv.register_tool({"read_bytes", "Read an exact byte count from one address or an addresses batch without typed decoding.",
            {{"address", "string", "Target address or arithmetic expression", false}, {"addresses", "array", "Batch address expressions or objects with address and size", false},
             {"size", "number", "Shared byte count", false}, {"sizes", "array", "Batch byte counts with one entry per address", false},
             {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, handle_read_bytes});
        srv.register_tool({"read_string", "Read a UTF-8/ASCII string from the attached process. If a VM bridge is active this reads VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"max_length", "number", "Maximum bytes to inspect", false}, {"encoding", "string", "ascii|utf16 for VM reads", false}, {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, handle_read_string});
        srv.register_tool({"query_memory", "Query the memory region containing an address. If a VM bridge is active this queries VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}}, true, handle_query_memory});
        srv.register_tool({"disassemble_file", "Disassemble a PE file from disk using Zydis.",
            {{"path", "string", "Path to an EXE/DLL/SYS file", true}, {"count", "number", "Maximum instructions", false}},
            true, handle_disassemble_file});
        srv.register_tool({"sandbox_execute", "Run a binary inside Windows Sandbox and collect the execution artifacts.",
            {{"path", "string", "Path to the executable", true}, {"arguments", "string", "Optional argument string", false},
             {"working_dir", "string", "Optional working directory to stage into the sandbox", false},
             {"timeout_ms", "number", "Execution timeout in milliseconds", false},
             {"capture_stdout", "boolean", "Capture stdout", false}, {"capture_stderr", "boolean", "Capture stderr", false}},
            false, handle_sandbox_execute});
        srv.register_tool({"convert_number", "Convert a number across integer, endian, ASCII, IEEE-754, alignment, VA, RVA, and PE file-offset representations.",
            {{"value", "string", "Numeric literal or integer value: decimal, 0x hex, hex h suffix, 0b binary, 0o/0 octal, or negative", false},
             {"input_base", "string", "Optional input radix: auto, hex, decimal, binary, octal, or 2/8/10/16", false},
             {"from", "string", "Alias for input_base", false},
             {"size", "number", "Optional display byte width: 1, 2, 4, or 8", false},
             {"bits", "number", "Optional display bit width: 8, 16, 32, or 64", false},
             {"va", "string", "Virtual address input alias; infers kind=va", false},
             {"rva", "string", "Relative virtual address input alias; infers kind=rva", false},
             {"file_offset", "string", "Raw file offset input alias; infers kind=file_offset", false},
             {"foa", "string", "Alias for file_offset", false},
             {"module_base", "string", "Optional module/image base for VA/RVA conversion", false},
             {"image_base", "string", "Alias for module_base", false},
             {"module_size", "string", "Optional module size for inside-module checks", false},
             {"module_name", "string", "Optional attached-process module name to resolve base and size", false},
             {"kind", "string", "Optional selected address kind: va, rva, file_offset, or foa", false},
             {"section_rva", "string", "Optional PE section RVA for RVA/FOA conversion", false},
             {"section_va", "string", "Optional PE section VA for VA/FOA conversion", false},
             {"section_raw_offset", "string", "Optional PE section raw file offset", false},
             {"section_raw_size", "string", "Optional PE section raw size", false},
             {"section_virtual_size", "string", "Optional PE section virtual size", false}},
            true, handle_convert_number});
        srv.register_tool({"delete_file", "Delete a file on disk.", {{"path", "string", "Target path", true}}, false, handle_delete_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"create_directory", "Create a directory tree on disk.", {{"path", "string", "Target path", true}}, false, handle_create_directory, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"search_files", "Search for file names under a workspace-relative root directory with case-insensitive glob matching.",
            {{"root", "string", "Workspace-relative root directory", true}, {"pattern", "string", "Case-insensitive glob using * and ?", true}, {"limit", "number", "Maximum matches", false}, {"max_visited", "number", "Maximum entries to visit", false}, {"timeout_ms", "number", "Traversal deadline in milliseconds", false}},
            true, handle_search_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"grep_in_files", "Search workspace file contents with a regular expression, bounded traversal, file glob filtering, and binary-file skips.",
            {{"root", "string", "Workspace-relative root directory", true}, {"pattern", "string", "Regex pattern", true}, {"file_pattern", "string", "Case-insensitive file glob using * and ?", false}, {"limit", "number", "Maximum matches", false}, {"max_visited", "number", "Maximum entries to visit", false}, {"max_file_size", "number", "Maximum file size to read", false}, {"timeout_ms", "number", "Traversal deadline in milliseconds", false}},
            true, handle_grep_in_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"web_search", "Search the web through the bundled Camoufox browser and extract visible result links from rendered search pages.",
            {{"query", "string", "Search query text", true}, {"max_results", "number", "Maximum results to return (default 5)", false}, {"timeout", "number", "Browser navigation timeout in seconds (1-60, default 8)", false}, {"diagnostic", "boolean", "Preserve expanded browser diagnostics when available", false}},
            true, handle_web_search, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"webfetch",
            "Open a URL in the bundled Camoufox browser and return rendered markdown, plain text, or raw HTML. "
            "Uses browser navigation, redirects, cookies, scripts, and TLS behavior; strips script/style/noscript/iframe blocks before HTML conversion. "
            "Output capped at ~200 KB; max timeout 120 seconds.",
            {{"url", "string", "Absolute http:// or https:// URL", true},
             {"format", "string", "Output format: markdown (default), text, or html", false},
             {"timeout", "number", "Browser navigation timeout in seconds (1-120, default 30)", false},
             {"diagnostic", "boolean", "Preserve expanded browser diagnostics instead of compact local-fixture success summaries", false}},
            true, handle_webfetch, mcp_standalone::tool_visibility_t::internal_only});


        driver_tools::register_driver_tools(srv);
        network_tools::register_network_tools(srv);
        gameproto_tools::register_gameproto_tools(srv);
        net_proto_tools::register_net_proto_tools(srv);
        net_security_tools::register_net_security_tools(srv);
        emulation_tools::register_emulation_tools(srv);
        debugger_tools::register_debugger_tools(srv);
        thread_intel_tools::register_thread_intel_tools(srv);
        coding_tools::register_coding_tools(srv);
        re_tools::register_re_tools(srv);
        protected_re_tools::register_protected_re_tools(srv);
        workflow_tools::register_workflow_tools(srv);
        scanner_tools::register_scanner_tools(srv);
        analysis_tools::register_analysis_tools(srv);
        disasm_tools::register_disasm_tools(srv);
        decompile_tools::register_decompile_tools(srv);
        register_c03_compatibility_tools(srv);
        session_tools_ext::register_tools(srv);

        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools done");
    }
}
