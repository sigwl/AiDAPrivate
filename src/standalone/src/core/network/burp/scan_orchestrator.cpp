#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "scan_orchestrator.hpp"

#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "content_scanner.hpp"
#include "crawl_audit.hpp"
#include "crawler.hpp"
#include "findings_db.hpp"
#include "issue.hpp"
#include "passive_scanner.hpp"
#include "scanner_module.hpp"
#include "security_headers.hpp"
#include "tls_analyzer.hpp"
#include "vuln_taxonomy.hpp"

#include "../../infra/event_bus.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../../helpers/diag_log.hpp"
#include "../../infra/executor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scan_orchestrator {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

constexpr uint64_t kFirstScanId = 5000000000ULL;
constexpr size_t kMaxProfileArray = 128;
constexpr size_t kMaxReturnedFindings = 250;

inline constexpr aida::events::event_def_t<json> kScanStartedEvent{"aida.scan.started"};
inline constexpr aida::events::event_def_t<json> kScanProgressEvent{"aida.scan.progress"};
inline constexpr aida::events::event_def_t<json> kScanCompletedEvent{"aida.scan.completed"};

enum class scan_phase_t : int
{
    running = 0,
    stopping = 1,
    complete = 2,
    cancelled = 3,
    error = 4
};

struct scan_profile_t
{
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> module_ids;
    std::vector<std::string> defensive_checks;
    int crawl_depth = 2;
    size_t max_concurrent_requests = 16;
    size_t request_throttle_ms = 0;
    int timeout_ms = 15000;
    bool crawl_first = true;
    bool run_defensive = true;
    int estimated_minutes = 5;
    bool builtin = false;
};

struct defensive_status_t
{
    std::string check;
    std::string status = "pending";
    size_t findings = 0;
    std::string last_error;
    uint64_t started_ms = 0;
    uint64_t ended_ms = 0;
};

struct scan_runtime_t
{
    std::mutex mtx;
    uint64_t scan_id = 0;
    std::string target_url;
    std::string target_url_redacted;
    std::string profile_id;
    std::string session_id;
    std::vector<std::string> module_ids;
    std::vector<std::string> defensive_checks;
    bool crawl_first = true;
    bool run_defensive = true;
    bool scope_only = false;
    int crawl_depth = 0;
    size_t max_concurrent_requests = 16;
    size_t request_throttle_ms = 0;
    int timeout_ms = 15000;
    bool max_concurrent_explicit = false;
    bool request_throttle_explicit = false;
    scan_phase_t phase = scan_phase_t::running;
    uint64_t started_ms = 0;
    uint64_t ended_ms = 0;
    uint64_t active_audit_id = 0;
    uint64_t crawl_audit_job_id = 0;
    uint64_t crawler_id = 0;
    std::vector<uint64_t> audit_ids;
    std::vector<defensive_status_t> defensive;
    std::atomic<bool> cancel_requested{false};
    std::string last_error;
};

struct state_t
{
    std::mutex mtx;
    std::unordered_map<uint64_t, std::shared_ptr<scan_runtime_t>> scans;
    std::unordered_map<std::string, scan_profile_t> custom_profiles;
    std::atomic<uint64_t> next_scan_id{kFirstScanId};
    std::atomic<bool> initialized{false};
    std::mutex err_mtx;
    std::string last_error;
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t unix_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t tick_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

bool call_cancelled_or_deadline()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && tick_ms() >= deadline;
}

void set_error(const std::string& msg)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
}

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string trim_copy(const std::string& value)
{
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])))
        ++first;
    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])))
        --last;
    return value.substr(first, last - first);
}

std::string safe_display_string(std::string value, size_t limit = 2048)
{
    for (char& c : value) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 && c != '\t')
            c = ' ';
    }
    if (value.size() > limit)
        value = value.substr(0, limit) + "...";
    return value;
}

bool sensitive_name(const std::string& name)
{
    const std::string n = lower_ascii(name);
    return n.find("authorization") != std::string::npos ||
           n.find("cookie") != std::string::npos ||
           n.find("token") != std::string::npos ||
           n.find("secret") != std::string::npos ||
           n.find("password") != std::string::npos ||
           n.find("passwd") != std::string::npos ||
           n.find("api_key") != std::string::npos ||
           n.find("apikey") != std::string::npos ||
           n.find("access_key") != std::string::npos ||
           n.find("private_key") != std::string::npos ||
           n.find("license_key") != std::string::npos ||
           n.find("session_id") != std::string::npos ||
           n == "key";
}

std::string redact_text(std::string text, size_t limit = 2048)
{
    text = safe_display_string(std::move(text), limit * 2);
    try {
        text = std::regex_replace(text, std::regex(R"((Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+)", std::regex_constants::icase), "$1 <redacted>");
        text = std::regex_replace(text, std::regex(R"(AIDA-[A-Za-z0-9-]{8,})", std::regex_constants::icase), "<redacted-license-key>");
        text = std::regex_replace(text, std::regex(R"((password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|private[_-]?key|license[_-]?key|authorization|cookie|session[_-]?id)\s*[:=]\s*[^&\s,;}]+)", std::regex_constants::icase), "$1=<redacted>");
        text = std::regex_replace(text, std::regex(R"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)", std::regex_constants::icase), "<redacted-private-key>");
    } catch (...) {
    }
    if (text.size() > limit)
        text = text.substr(0, limit) + "...";
    return text;
}

std::string redact_query(const std::string& query)
{
    if (query.empty())
        return {};
    std::string out;
    size_t start = 0;
    while (start <= query.size()) {
        size_t amp = query.find('&', start);
        const size_t end = amp == std::string::npos ? query.size() : amp;
        std::string part = query.substr(start, end - start);
        const size_t eq = part.find('=');
        if (eq != std::string::npos && sensitive_name(part.substr(0, eq))) {
            part = part.substr(0, eq + 1) + "<redacted>";
        } else {
            part = redact_text(part, 256);
        }
        if (!out.empty())
            out.push_back('&');
        out += part;
        if (amp == std::string::npos)
            break;
        start = amp + 1;
    }
    return out;
}

std::string redact_url(const std::string& url)
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
        return redact_text(url, 512);
    std::string out = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        out += ":" + std::to_string(port);
    const size_t q = path.find('?');
    if (q == std::string::npos) {
        out += path.empty() ? "/" : path;
    } else {
        out += path.substr(0, q);
        out += "?";
        out += redact_query(path.substr(q + 1));
    }
    return safe_display_string(out, 512);
}

bool url_has_sensitive_query(const std::string& url)
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
        return false;
    const size_t q = path.find('?');
    if (q == std::string::npos)
        return false;
    const std::string query = path.substr(q + 1);
    size_t start = 0;
    while (start <= query.size()) {
        size_t amp = query.find('&', start);
        const size_t end = amp == std::string::npos ? query.size() : amp;
        const std::string part = query.substr(start, end - start);
        const size_t eq = part.find('=');
        if (eq != std::string::npos && sensitive_name(part.substr(0, eq)))
            return true;
        if (std::regex_search(part, std::regex(R"(AIDA-[A-Za-z0-9-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]+|-----BEGIN\s+)", std::regex_constants::icase)))
            return true;
        if (amp == std::string::npos)
            break;
        start = amp + 1;
    }
    return false;
}

bool valid_token_id(const std::string& id, size_t max_len)
{
    if (id.empty() || id.size() > max_len)
        return false;
    for (unsigned char c : id) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.')
            continue;
        return false;
    }
    return true;
}

bool json_string(const json& p, const char* key, std::string& out)
{
    if (!p.contains(key))
        return false;
    if (!p[key].is_string())
        return false;
    out = p[key].get<std::string>();
    return true;
}

bool json_bool(const json& p, const char* key, bool& out)
{
    if (!p.contains(key) || !p[key].is_boolean())
        return false;
    out = p[key].get<bool>();
    return true;
}

bool json_int_range(const json& p, const char* key, int min_value, int max_value, int& out)
{
    if (!p.contains(key) || !p[key].is_number_integer())
        return false;
    const int value = p[key].get<int>();
    out = std::clamp(value, min_value, max_value);
    return true;
}

bool json_size_range(const json& p, const char* key, size_t min_value, size_t max_value, size_t& out)
{
    if (!p.contains(key) || !p[key].is_number_unsigned())
        return false;
    const size_t value = p[key].get<size_t>();
    out = std::clamp(value, min_value, max_value);
    return true;
}

std::vector<std::string> json_string_array(const json& p, const char* key, size_t max_items)
{
    std::vector<std::string> out;
    if (!p.contains(key) || !p[key].is_array())
        return out;
    for (const auto& item : p[key]) {
        if (!item.is_string())
            continue;
        std::string value = trim_copy(item.get<std::string>());
        if (value.empty())
            continue;
        if (out.size() >= max_items)
            break;
        if (std::find(out.begin(), out.end(), value) == out.end())
            out.push_back(std::move(value));
    }
    return out;
}

std::vector<std::string> json_strings_from_array(const json& arr, size_t max_items)
{
    std::vector<std::string> out;
    if (!arr.is_array())
        return out;
    for (const auto& item : arr) {
        if (!item.is_string())
            continue;
        std::string value = trim_copy(item.get<std::string>());
        if (value.empty())
            continue;
        if (out.size() >= max_items)
            break;
        if (std::find(out.begin(), out.end(), value) == out.end())
            out.push_back(std::move(value));
    }
    return out;
}

std::string appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &known)) && known) {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            out.resize(static_cast<size_t>(needed - 1));
            WideCharToMultiByte(CP_UTF8, 0, known, -1, out.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        const DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH)
            out.assign(buf, len);
    }
    if (out.empty())
        out = "C:\\Users\\Public";
    return out;
}

std::string profile_storage_path()
{
    std::filesystem::path dir = std::filesystem::path(appdata_dir()) / "AiDA" / "Standalone" / "burp";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return (dir / "scan_profiles.json").string();
}

std::vector<std::string> default_full_module_ids()
{
    std::vector<std::string> out;
    for (const auto& mod : scanner::all_modules()) {
        if (!mod.id.empty())
            out.push_back(mod.id);
    }
    if (!out.empty())
        return out;
    return {
        "xss", "sqli", "nosqli", "cmdi", "cors", "csp", "csrf", "xxe", "ssrf", "ssti",
        "path_traversal", "open_redirect", "idor", "jwt_scan", "log4j", "ldap", "xpath",
        "dom_xss", "host_header", "smuggling", "race_condition", "deserial", "method_override",
        "param_miner", "protopol", "blind_ssrf", "cache_poisoning", "cache_deception",
        "dom_clobbering", "email_injection", "graphql", "subdomain_takeover"
    };
}

std::unordered_set<std::string> known_module_ids()
{
    std::unordered_set<std::string> out;
    for (const auto& mod : scanner::all_modules()) {
        if (!mod.id.empty())
            out.insert(mod.id);
    }
    if (out.empty()) {
        for (const auto& id : default_full_module_ids())
            out.insert(id);
    }
    return out;
}

const std::vector<std::string>& allowed_defensive_checks()
{
    static const std::vector<std::string> checks{
        "security_headers", "tls_config", "content_analysis", "info_disclosure", "cookie_audit"
    };
    return checks;
}

bool allowed_defensive_check(const std::string& check)
{
    const auto& checks = allowed_defensive_checks();
    return std::find(checks.begin(), checks.end(), check) != checks.end();
}

std::vector<std::string> normalize_modules(const std::vector<std::string>& modules, std::string& error)
{
    const auto known = known_module_ids();
    std::vector<std::string> out;
    for (auto id : modules) {
        id = trim_copy(id);
        if (!valid_token_id(id, 64)) {
            error = "invalid module id: " + redact_text(id, 128);
            return {};
        }
        if (!known.empty() && known.find(id) == known.end()) {
            error = "unknown module id: " + redact_text(id, 128);
            return {};
        }
        if (std::find(out.begin(), out.end(), id) == out.end())
            out.push_back(std::move(id));
    }
    return out;
}

std::vector<std::string> normalize_defensive_checks(const std::vector<std::string>& checks, std::string& error)
{
    std::vector<std::string> out;
    for (auto check : checks) {
        check = trim_copy(lower_ascii(check));
        if (!allowed_defensive_check(check)) {
            error = "unknown defensive check: " + redact_text(check, 128);
            return {};
        }
        if (std::find(out.begin(), out.end(), check) == out.end())
            out.push_back(std::move(check));
    }
    return out;
}

scan_profile_t quick_profile()
{
    scan_profile_t p;
    p.id = "quick";
    p.name = "Quick Scan";
    p.description = "Passive, crawl-light, and defensive checks";
    p.defensive_checks = {"security_headers", "tls_config", "content_analysis"};
    p.crawl_depth = 1;
    p.max_concurrent_requests = 4;
    p.request_throttle_ms = 125;
    p.timeout_ms = 10000;
    p.crawl_first = true;
    p.run_defensive = true;
    p.estimated_minutes = 2;
    p.builtin = true;
    return p;
}

scan_profile_t full_profile()
{
    scan_profile_t p;
    p.id = "full";
    p.name = "Full Audit";
    p.description = "All active modules, crawl, passive, and defensive checks";
    p.module_ids = default_full_module_ids();
    p.defensive_checks = {"security_headers", "tls_config", "content_analysis", "info_disclosure", "cookie_audit"};
    p.crawl_depth = 3;
    p.max_concurrent_requests = 16;
    p.request_throttle_ms = 0;
    p.timeout_ms = 15000;
    p.crawl_first = true;
    p.run_defensive = true;
    p.estimated_minutes = 30;
    p.builtin = true;
    return p;
}

scan_profile_t custom_base_profile()
{
    scan_profile_t p;
    p.id = "custom";
    p.name = "Custom Scan";
    p.description = "Caller-selected active modules and defensive checks";
    p.defensive_checks = {"security_headers", "tls_config", "content_analysis"};
    p.crawl_depth = 2;
    p.max_concurrent_requests = 16;
    p.request_throttle_ms = 0;
    p.timeout_ms = 15000;
    p.crawl_first = true;
    p.run_defensive = true;
    p.estimated_minutes = 10;
    p.builtin = true;
    return p;
}

json profile_to_json(const scan_profile_t& p, bool include_modules)
{
    json out;
    out["id"] = p.id;
    out["name"] = p.name;
    out["description"] = p.description;
    if (include_modules)
        out["module_ids"] = p.module_ids;
    out["defensive_checks"] = p.defensive_checks;
    out["crawl_depth"] = p.crawl_depth;
    out["crawl_first"] = p.crawl_first;
    out["run_defensive"] = p.run_defensive;
    out["max_concurrent_requests"] = p.max_concurrent_requests;
    out["request_throttle_ms"] = p.request_throttle_ms;
    out["timeout_ms"] = p.timeout_ms;
    out["estimated_minutes"] = p.estimated_minutes;
    out["builtin"] = p.builtin;
    return out;
}

json vector_to_json_array(const std::vector<std::string>& values)
{
    json arr = json::array();
    for (const auto& value : values)
        arr.push_back(value);
    return arr;
}

findings_db::scan_profile_t profile_to_db_profile(const scan_profile_t& profile)
{
    findings_db::scan_profile_t db;
    db.profile_id = profile.id;
    db.name = profile.name;
    db.description = profile.description;
    db.module_ids_json = vector_to_json_array(profile.module_ids);
    db.defensive_checks_json = vector_to_json_array(profile.defensive_checks);
    db.crawl_depth = profile.crawl_depth;
    db.max_concurrent = static_cast<int>(std::clamp(profile.max_concurrent_requests, size_t{1}, size_t{64}));
    db.created_ms = unix_ms();
    db.is_builtin = profile.builtin;
    return db;
}

std::optional<scan_profile_t> db_profile_to_profile(const findings_db::scan_profile_t& db)
{
    if (!valid_token_id(db.profile_id, 64) || db.profile_id == "quick" || db.profile_id == "full" || db.profile_id == "custom")
        return std::nullopt;
    scan_profile_t profile = custom_base_profile();
    profile.id = db.profile_id;
    profile.name = safe_display_string(trim_copy(db.name), 128);
    if (profile.name.empty())
        return std::nullopt;
    profile.description = redact_text(db.description, 512);
    profile.module_ids = json_strings_from_array(db.module_ids_json, kMaxProfileArray);
    profile.defensive_checks = json_strings_from_array(db.defensive_checks_json, kMaxProfileArray);
    std::string error;
    profile.module_ids = normalize_modules(profile.module_ids, error);
    if (!error.empty())
        return std::nullopt;
    error.clear();
    profile.defensive_checks = normalize_defensive_checks(profile.defensive_checks, error);
    if (!error.empty())
        return std::nullopt;
    profile.crawl_depth = std::clamp(db.crawl_depth, 0, 10);
    profile.max_concurrent_requests = static_cast<size_t>(std::clamp(db.max_concurrent, 1, 64));
    profile.builtin = false;
    return profile;
}

bool profile_from_json(const json& j, scan_profile_t& out)
{
    if (!j.is_object())
        return false;
    std::string id;
    std::string name;
    if (!json_string(j, "id", id) || !json_string(j, "name", name))
        return false;
    id = trim_copy(id);
    name = safe_display_string(trim_copy(name), 128);
    if (!valid_token_id(id, 64) || id == "quick" || id == "full" || id == "custom" || name.empty())
        return false;
    scan_profile_t p = custom_base_profile();
    p.id = id;
    p.name = name;
    json_string(j, "description", p.description);
    p.description = redact_text(p.description, 512);
    p.module_ids = json_string_array(j, "module_ids", kMaxProfileArray);
    p.defensive_checks = json_string_array(j, "defensive_checks", kMaxProfileArray);
    std::string error;
    p.module_ids = normalize_modules(p.module_ids, error);
    if (!error.empty())
        return false;
    error.clear();
    p.defensive_checks = normalize_defensive_checks(p.defensive_checks, error);
    if (!error.empty())
        return false;
    json_int_range(j, "crawl_depth", 0, 10, p.crawl_depth);
    json_size_range(j, "max_concurrent_requests", 1, 64, p.max_concurrent_requests);
    json_size_range(j, "request_throttle_ms", 0, 60000, p.request_throttle_ms);
    json_int_range(j, "timeout_ms", 1000, 120000, p.timeout_ms);
    json_bool(j, "crawl_first", p.crawl_first);
    json_bool(j, "run_defensive", p.run_defensive);
    json_int_range(j, "estimated_minutes", 1, 240, p.estimated_minutes);
    p.builtin = false;
    out = std::move(p);
    return true;
}

bool load_profiles()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    s.custom_profiles.clear();
    const std::string path = profile_storage_path();
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return true;
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (raw.empty())
        return true;
    try {
        json doc = json::parse(raw);
        const json* arr = nullptr;
        if (doc.is_object() && doc.contains("profiles") && doc["profiles"].is_array())
            arr = &doc["profiles"];
        if (!arr)
            return false;
        for (const auto& item : *arr) {
            scan_profile_t p;
            if (profile_from_json(item, p))
                s.custom_profiles[p.id] = std::move(p);
        }
        return true;
    } catch (...) {
        set_error("scan profile storage parse failed");
        return false;
    }
}

bool save_profiles()
{
    std::vector<scan_profile_t> profiles;
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);
        profiles.reserve(s.custom_profiles.size());
        for (const auto& kv : s.custom_profiles)
            profiles.push_back(kv.second);
    }
    std::sort(profiles.begin(), profiles.end(), [](const scan_profile_t& a, const scan_profile_t& b) { return a.id < b.id; });
    json arr = json::array();
    for (const auto& p : profiles)
        arr.push_back(profile_to_json(p, true));
    json doc;
    doc["version"] = 1;
    doc["profiles"] = std::move(arr);
    const std::string path = profile_storage_path();
    const std::string tmp = path + ".tmp";
    try {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            set_error("scan profile storage open failed");
            return false;
        }
        const std::string body = doc.dump(2);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        f.close();
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(path, ec);
            std::filesystem::rename(tmp, path, ec);
            if (ec) {
                set_error("scan profile storage rename failed");
                return false;
            }
        }
        return true;
    } catch (...) {
        set_error("scan profile storage save exception");
        return false;
    }
}

std::optional<scan_profile_t> find_profile(const std::string& id)
{
    if (id == "quick")
        return quick_profile();
    if (id == "full")
        return full_profile();
    if (id == "custom")
        return custom_base_profile();
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);
        auto it = s.custom_profiles.find(id);
        if (it != s.custom_profiles.end())
            return it->second;
    }
    if (findings_db::initialize()) {
        for (const auto& db_profile : findings_db::list_scan_profiles(false)) {
            if (db_profile.profile_id != id)
                continue;
            auto profile = db_profile_to_profile(db_profile);
            if (profile.has_value())
                return profile;
        }
    }
    return std::nullopt;
}

std::string phase_label(scan_phase_t phase)
{
    switch (phase) {
        case scan_phase_t::running: return "running";
        case scan_phase_t::stopping: return "cancelling";
        case scan_phase_t::complete: return "complete";
        case scan_phase_t::cancelled: return "cancelled";
        case scan_phase_t::error: return "error";
    }
    return "error";
}

std::string crawl_phase_label(crawler::crawl_status_phase_t phase)
{
    switch (phase) {
        case crawler::crawl_status_phase_t::pending: return "pending";
        case crawler::crawl_status_phase_t::running: return "running";
        case crawler::crawl_status_phase_t::stopping: return "stopping";
        case crawler::crawl_status_phase_t::complete: return "complete";
        case crawler::crawl_status_phase_t::error: return "error";
    }
    return "error";
}

std::string crawl_audit_phase_label(const std::string& phase)
{
    return phase.empty() ? "error" : phase;
}

bool crawl_audit_phase_running(const std::string& phase)
{
    return phase == "pending" || phase == "crawling" || phase == "auditing";
}

bool crawl_audit_phase_terminal(const std::string& phase)
{
    return phase == "complete" || phase == "error" || phase == "stopped" ||
           phase == "snapshot" || phase == "imported_snapshot";
}

bool build_get_request(const std::string& url, std::vector<uint8_t>& raw, std::string& error)
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "invalid target_url";
        return false;
    }
    if (scheme != "http" && scheme != "https") {
        error = "target_url scheme must be http or https";
        return false;
    }
    std::string host_header = host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        host_header += ":" + std::to_string(port);
    if (path.empty())
        path = "/";
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host_header + "\r\nUser-Agent: AiDA-Scan-Orchestrator/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
    raw.assign(req.begin(), req.end());
    return true;
}

bool fetch_target(const std::shared_ptr<scan_runtime_t>& job, exchange_observed_t& out, std::string& error)
{
    std::vector<uint8_t> raw;
    if (!build_get_request(job->target_url, raw, error))
        return false;
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(job->target_url, scheme, host, port, path)) {
        error = "invalid target_url";
        return false;
    }
    audit_http::send_options_t opt;
    opt.timeout_ms = job->timeout_ms;
    opt.follow_redirects = true;
    opt.max_redirects = 3;
    opt.return_first_redirect = false;
    opt.enforce_scope = job->scope_only;
    opt.publish_exchange = true;
    opt.exchange_source = "scan_orchestrator";
    auto result = audit_http::send(raw, host, port, scheme == "https", opt);
    if (!result.has_value()) {
        error = redact_text(audit_http::last_error(), 512);
        return false;
    }
    out = std::move(*result);
    return true;
}

std::string header_value_ci(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string target = lower_ascii(name);
    for (const auto& h : headers) {
        if (lower_ascii(h.first) == target)
            return h.second;
    }
    return {};
}

std::vector<std::string> header_values_ci(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string target = lower_ascii(name);
    std::vector<std::string> out;
    for (const auto& h : headers) {
        if (lower_ascii(h.first) == target)
            out.push_back(h.second);
    }
    return out;
}

std::string path_without_query(const std::string& path)
{
    const size_t q = path.find('?');
    if (q == std::string::npos)
        return path.empty() ? "/" : path;
    return path.substr(0, q).empty() ? "/" : path.substr(0, q);
}

uint64_t add_defensive_issue(const std::shared_ptr<scan_runtime_t>& job,
                             const exchange_observed_t& ex,
                             const std::string& type_key,
                             const std::string& name,
                             severity_t severity,
                             confidence_t confidence,
                             const std::vector<std::string>& cwe,
                             const std::string& parameter,
                             const std::string& description,
                             const std::string& remediation,
                             const std::string& evidence_summary)
{
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.description = description;
    iss.remediation = remediation;
    iss.cwe = cwe;
    iss.severity = severity;
    iss.confidence = confidence;
    iss.scheme = ex.scheme;
    iss.host = ex.host;
    iss.port = ex.port;
    iss.path = path_without_query(ex.path);
    iss.parameter = parameter;
    iss.insertion_point = parameter.empty() ? "defensive" : "defensive:" + parameter;
    iss.seen_ms = unix_ms();
    iss.src_exchange_id = ex.id;
    iss.audit_id = job->scan_id;
    iss.scan_id = job->scan_id;
    iss.session_id = job->session_id;
    evidence_t ev;
    ev.marker = redact_text(evidence_summary, 512);
    ev.request_raw = "request evidence summarized and sensitive fields redacted";
    ev.response_raw = "response evidence summarized and sensitive fields redacted";
    iss.evidence.push_back(std::move(ev));
    uint64_t issue_id = issue_store::add(iss);
    if (issue_id != 0)
        iss.id = issue_id;
    if (findings_db::initialize())
        findings_db::upsert(iss);
    return issue_id;
}

size_t run_security_headers(const std::shared_ptr<scan_runtime_t>& job, const exchange_observed_t& ex)
{
    size_t findings = 0;
    const bool https = lower_ascii(ex.scheme) == "https";
    const std::string hsts = header_value_ci(ex.resp_headers, "Strict-Transport-Security");
    const std::string csp = header_value_ci(ex.resp_headers, "Content-Security-Policy");
    const std::string xfo = header_value_ci(ex.resp_headers, "X-Frame-Options");
    const std::string xcto = header_value_ci(ex.resp_headers, "X-Content-Type-Options");
    const std::string referrer = header_value_ci(ex.resp_headers, "Referrer-Policy");
    const std::string permissions = header_value_ci(ex.resp_headers, "Permissions-Policy");
    const std::string coop = header_value_ci(ex.resp_headers, "Cross-Origin-Opener-Policy");
    if (https && hsts.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_hsts", "Missing Strict-Transport-Security", severity_t::medium, confidence_t::firm, {"CWE-319"}, "Strict-Transport-Security", "HTTPS response did not include HSTS.", "Send Strict-Transport-Security with a long max-age after validating HTTPS coverage.", "missing_header=Strict-Transport-Security");
    }
    if (csp.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_csp", "Missing Content-Security-Policy", severity_t::medium, confidence_t::firm, {"CWE-1021", "CWE-693"}, "Content-Security-Policy", "Response did not include a Content Security Policy.", "Deploy a restrictive Content-Security-Policy appropriate to the application.", "missing_header=Content-Security-Policy");
    } else {
        const std::string lc = lower_ascii(csp);
        if (lc.find("'unsafe-inline'") != std::string::npos || lc.find("*") != std::string::npos) {
            ++findings;
            add_defensive_issue(job, ex, "security_headers.weak_csp", "Weak Content-Security-Policy", severity_t::low, confidence_t::firm, {"CWE-1021", "CWE-693"}, "Content-Security-Policy", "Content Security Policy contains broad or inline script allowances.", "Remove unsafe-inline and broad wildcard allowances where possible.", "csp_policy_present=1 unsafe_or_wildcard=1");
        }
    }
    if (xfo.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_x_frame_options", "Missing X-Frame-Options", severity_t::low, confidence_t::firm, {"CWE-1021"}, "X-Frame-Options", "Response did not include clickjacking frame protection.", "Send X-Frame-Options DENY or SAMEORIGIN, or enforce frame-ancestors in CSP.", "missing_header=X-Frame-Options");
    }
    if (lower_ascii(xcto) != "nosniff") {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_x_content_type_options", "Missing X-Content-Type-Options nosniff", severity_t::low, confidence_t::firm, {"CWE-693"}, "X-Content-Type-Options", "Response did not require MIME sniffing protection.", "Send X-Content-Type-Options: nosniff.", "x_content_type_options_present=" + std::to_string(!xcto.empty()));
    }
    if (referrer.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_referrer_policy", "Missing Referrer-Policy", severity_t::info, confidence_t::firm, {"CWE-200"}, "Referrer-Policy", "Response did not declare referrer disclosure policy.", "Send Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.", "missing_header=Referrer-Policy");
    }
    if (permissions.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_permissions_policy", "Missing Permissions-Policy", severity_t::info, confidence_t::firm, {"CWE-693"}, "Permissions-Policy", "Response did not restrict browser feature permissions.", "Send a Permissions-Policy that disables unused browser features.", "missing_header=Permissions-Policy");
    }
    if (coop.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "security_headers.missing_coop", "Missing Cross-Origin-Opener-Policy", severity_t::info, confidence_t::firm, {"CWE-693"}, "Cross-Origin-Opener-Policy", "Response did not isolate top-level browsing context relationships.", "Send Cross-Origin-Opener-Policy where compatible with the application.", "missing_header=Cross-Origin-Opener-Policy");
    }
    return findings;
}

size_t run_tls_config(const std::shared_ptr<scan_runtime_t>& job, const exchange_observed_t& ex)
{
    if (lower_ascii(ex.scheme) == "https")
        return 0;
    return add_defensive_issue(job, ex, "tls_config.plain_http", "Target served over plaintext HTTP", severity_t::high, confidence_t::firm, {"CWE-319"}, "transport", "The scan target used HTTP rather than HTTPS.", "Serve authenticated and sensitive application surfaces over HTTPS only and redirect plaintext HTTP to HTTPS.", "scheme=http") != 0 ? 1 : 0;
}

size_t regex_count_limited(const std::string& body, const std::regex& pattern, size_t max_count)
{
    size_t count = 0;
    auto begin = std::sregex_iterator(body.begin(), body.end(), pattern);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end && count < max_count; ++it)
        ++count;
    return count;
}

std::string response_body_text_limited(const exchange_observed_t& ex)
{
    constexpr size_t max_body = 1024 * 1024;
    const size_t len = std::min(ex.resp_body.size(), max_body);
    std::string body;
    body.assign(reinterpret_cast<const char*>(ex.resp_body.data()), len);
    return body;
}

size_t run_content_analysis(const std::shared_ptr<scan_runtime_t>& job, const exchange_observed_t& ex)
{
    size_t findings = 0;
    const std::string body = response_body_text_limited(ex);
    if (body.empty())
        return 0;
    try {
        const size_t internal_ips = regex_count_limited(body, std::regex(R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b)"), 25);
        if (internal_ips > 0) {
            ++findings;
            add_defensive_issue(job, ex, "content_analysis.internal_ip_disclosure", "Internal IP address disclosure", severity_t::low, confidence_t::firm, {"CWE-200"}, "response_body", "Response body disclosed internal network address patterns.", "Remove internal topology details from client-visible responses.", "internal_ip_count=" + std::to_string(internal_ips));
        }
        const size_t email_count = regex_count_limited(body, std::regex(R"(\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)", std::regex_constants::icase), 50);
        if (email_count >= 5) {
            ++findings;
            add_defensive_issue(job, ex, "content_analysis.bulk_email_disclosure", "Bulk email address disclosure", severity_t::low, confidence_t::firm, {"CWE-200"}, "response_body", "Response body contained multiple email address patterns.", "Limit public exposure of personal data and avoid embedding internal contact lists in responses.", "email_pattern_count=" + std::to_string(email_count));
        }
        const size_t secret_markers = regex_count_limited(body, std::regex(R"((api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]+))", std::regex_constants::icase), 25);
        if (secret_markers > 0) {
            ++findings;
            add_defensive_issue(job, ex, "content_analysis.secret_pattern_disclosure", "Secret-like pattern disclosure", severity_t::critical, confidence_t::tentative, {"CWE-200", "CWE-798"}, "response_body", "Response body contained credential or API-key style markers. Values are not returned by this tool.", "Remove secrets from client-visible assets, rotate any exposed credentials, and enforce secret scanning in CI.", "secret_like_pattern_count=" + std::to_string(secret_markers) + "; values_redacted=1");
        }
        const size_t cc_candidates = regex_count_limited(body, std::regex(R"((\d[ -]*){13,19})"), 25);
        if (cc_candidates > 0) {
            ++findings;
            add_defensive_issue(job, ex, "content_analysis.payment_data_pattern", "Payment-card-like numeric pattern disclosure", severity_t::high, confidence_t::tentative, {"CWE-359", "CWE-200"}, "response_body", "Response body contained payment-card-length numeric patterns. Values are not returned by this tool.", "Avoid returning payment card data and verify PCI data handling controls.", "payment_card_like_pattern_count=" + std::to_string(cc_candidates) + "; values_redacted=1");
        }
    } catch (...) {
    }
    return findings;
}

size_t run_info_disclosure(const std::shared_ptr<scan_runtime_t>& job, const exchange_observed_t& ex)
{
    size_t findings = 0;
    const std::string server = header_value_ci(ex.resp_headers, "Server");
    const std::string powered = header_value_ci(ex.resp_headers, "X-Powered-By");
    if (!server.empty() || !powered.empty()) {
        ++findings;
        add_defensive_issue(job, ex, "info_disclosure.version_headers", "Technology disclosure through response headers", severity_t::info, confidence_t::firm, {"CWE-200"}, "response_headers", "Response exposed technology-identifying headers. Values are summarized only.", "Minimize version-bearing headers when they are not operationally required.", "server_header_present=" + std::to_string(!server.empty()) + " x_powered_by_present=" + std::to_string(!powered.empty()));
    }
    const std::string body = response_body_text_limited(ex);
    const std::string lc = lower_ascii(body);
    if (lc.find("stack trace") != std::string::npos ||
        lc.find("traceback (most recent call last)") != std::string::npos ||
        lc.find("sqlexception") != std::string::npos ||
        lc.find("fatal error") != std::string::npos ||
        lc.find("warning: ") != std::string::npos) {
        ++findings;
        add_defensive_issue(job, ex, "info_disclosure.verbose_error", "Verbose error disclosure", severity_t::medium, confidence_t::firm, {"CWE-209"}, "response_body", "Response body contained verbose error or stack-trace markers.", "Return generic client errors and send diagnostic details only to protected server-side logs.", "verbose_error_marker_present=1");
    }
    if (lc.find("<title>index of /") != std::string::npos || lc.find("directory listing for") != std::string::npos) {
        ++findings;
        add_defensive_issue(job, ex, "info_disclosure.directory_listing", "Directory listing exposed", severity_t::medium, confidence_t::firm, {"CWE-548"}, "response_body", "Response body appeared to expose a directory listing.", "Disable directory listing and serve explicit index files or access controls.", "directory_listing_marker_present=1");
    }
    return findings;
}

std::map<std::string, std::string> parse_cookie_attrs(const std::string& header, std::string& name)
{
    std::map<std::string, std::string> attrs;
    size_t start = 0;
    bool first = true;
    while (start <= header.size()) {
        size_t semi = header.find(';', start);
        std::string part = trim_copy(header.substr(start, semi == std::string::npos ? std::string::npos : semi - start));
        size_t eq = part.find('=');
        std::string key = lower_ascii(trim_copy(eq == std::string::npos ? part : part.substr(0, eq)));
        std::string value = eq == std::string::npos ? std::string() : trim_copy(part.substr(eq + 1));
        if (first) {
            name = eq == std::string::npos ? key : part.substr(0, eq);
        } else if (!key.empty()) {
            attrs[key] = value;
        }
        first = false;
        if (semi == std::string::npos)
            break;
        start = semi + 1;
    }
    return attrs;
}

size_t run_cookie_audit(const std::shared_ptr<scan_runtime_t>& job, const exchange_observed_t& ex)
{
    size_t findings = 0;
    const auto cookies = header_values_ci(ex.resp_headers, "Set-Cookie");
    for (const auto& header : cookies) {
        std::string cookie_name;
        const auto attrs = parse_cookie_attrs(header, cookie_name);
        cookie_name = redact_text(safe_display_string(cookie_name, 96), 96);
        if (cookie_name.empty())
            cookie_name = "<unnamed>";
        const bool secure = attrs.find("secure") != attrs.end();
        const bool http_only = attrs.find("httponly") != attrs.end();
        const bool same_site = attrs.find("samesite") != attrs.end();
        const bool broad_domain = attrs.find("domain") != attrs.end() && !attrs.at("domain").empty() && attrs.at("domain").front() == '.';
        std::vector<std::string> issues;
        if (!secure)
            issues.push_back("missing_secure");
        if (!http_only)
            issues.push_back("missing_httponly");
        if (!same_site)
            issues.push_back("missing_samesite");
        if (broad_domain)
            issues.push_back("broad_domain");
        if (cookie_name.rfind("__Host-", 0) == 0 && (!secure || attrs.find("domain") != attrs.end() || attrs.find("path") == attrs.end() || attrs.at("path") != "/"))
            issues.push_back("__host_prefix_violation");
        if (cookie_name.rfind("__Secure-", 0) == 0 && !secure)
            issues.push_back("__secure_prefix_violation");
        if (issues.empty())
            continue;
        ++findings;
        std::string evidence = "cookie_name=" + cookie_name + " issues=";
        for (size_t i = 0; i < issues.size(); ++i) {
            if (i)
                evidence += ",";
            evidence += issues[i];
        }
        add_defensive_issue(job, ex, "cookie_audit.insecure_cookie_flags", "Cookie missing recommended security attributes", secure ? severity_t::medium : severity_t::high, confidence_t::firm, {"CWE-614", "CWE-1004", "CWE-1275"}, cookie_name, "A response cookie lacked one or more recommended security attributes. Cookie values are not stored or returned.", "Use Secure, HttpOnly, SameSite, narrow Domain/Path scope, and prefix-compliant cookie names.", evidence + "; values_redacted=1");
    }
    return findings;
}

std::vector<std::string> content_categories_for_check(const std::string& check)
{
    if (check == "info_disclosure")
        return {"internal_ips", "error_messages", "debug_endpoints", "directory_listing", "source_code", "comments_leak"};
    return {"pii", "credit_cards", "api_keys", "internal_ips", "error_messages", "debug_endpoints", "backup_files", "source_code", "directory_listing", "secrets", "comments_leak"};
}

void invoke_shared_defensive_analyzer(const std::shared_ptr<scan_runtime_t>& job, const std::string& check, const exchange_observed_t* ex)
{
    if (!job || job->cancel_requested.load(std::memory_order_acquire))
        return;
    try {
        if (check == "security_headers" && ex) {
            auto result = security_headers::analyze_exchange(*ex, false);
            (void)result;
        } else if ((check == "content_analysis" || check == "info_disclosure") && ex) {
            auto result = content_scanner::scan_exchange(*ex, content_categories_for_check(check), false);
            (void)result;
        } else if (check == "cookie_audit") {
            std::string error;
            auto result = security_headers::audit_cookies_for_host(job->target_url, true, false, error);
            (void)result;
        } else if (check == "tls_config") {
            std::string scheme;
            std::string host;
            std::string path;
            uint16_t port = 0;
            if (audit_http::parse_url(job->target_url, scheme, host, port, path) && scheme == "https") {
                std::string error;
                auto result = tls_analyzer::analyze_host(host, port, true, true, false, error);
                (void)result;
            }
        }
    } catch (...) {
    }
}

void update_defensive_status(const std::shared_ptr<scan_runtime_t>& job,
                             const std::string& check,
                             const std::string& status,
                             size_t findings,
                             const std::string& error)
{
    if (!job)
        return;
    bool all_terminal = true;
    {
        std::lock_guard<std::mutex> lk(job->mtx);
        for (auto& st : job->defensive) {
            if (st.check == check) {
                st.status = status;
                st.findings = findings;
                st.last_error = redact_text(error, 512);
                if (st.started_ms == 0 && status == "running")
                    st.started_ms = unix_ms();
                if (status == "complete" || status == "cancelled" || status == "error")
                    st.ended_ms = unix_ms();
            }
            if (st.status != "complete" && st.status != "cancelled" && st.status != "error")
                all_terminal = false;
        }
        if (status == "error" && job->phase == scan_phase_t::running)
            job->last_error = redact_text(error, 512);
    }
    json payload;
    payload["scan_id"] = job->scan_id;
    payload["check"] = check;
    payload["status"] = status;
    payload["findings"] = findings;
    payload["target_url"] = job->target_url_redacted;
    aida::events::publish(kScanProgressEvent, payload);
    (void)all_terminal;
}

void run_defensive_check(std::shared_ptr<scan_runtime_t> job, std::string check)
{
    update_defensive_status(job, check, "running", 0, {});
    if (!job || job->cancel_requested.load(std::memory_order_acquire)) {
        update_defensive_status(job, check, "cancelled", 0, {});
        return;
    }
    exchange_observed_t ex;
    std::string error;
    size_t findings = 0;
    bool ok = true;
    if (check == "tls_config") {
        if (!fetch_target(job, ex, error)) {
            std::string scheme;
            std::string host;
            std::string path;
            uint16_t port = 0;
            if (audit_http::parse_url(job->target_url, scheme, host, port, path) && scheme == "https") {
                ok = false;
            } else {
                ex.scheme = scheme.empty() ? "http" : scheme;
                ex.host = host;
                ex.port = port;
                ex.path = path.empty() ? "/" : path;
            }
        }
        if (ok && !job->cancel_requested.load(std::memory_order_acquire))
            invoke_shared_defensive_analyzer(job, check, &ex);
        if (ok && !job->cancel_requested.load(std::memory_order_acquire))
            findings = run_tls_config(job, ex);
    } else {
        ok = fetch_target(job, ex, error);
        if (ok && !job->cancel_requested.load(std::memory_order_acquire)) {
            invoke_shared_defensive_analyzer(job, check, &ex);
            if (check == "security_headers")
                findings = run_security_headers(job, ex);
            else if (check == "content_analysis")
                findings = run_content_analysis(job, ex);
            else if (check == "info_disclosure")
                findings = run_info_disclosure(job, ex);
            else if (check == "cookie_audit")
                findings = run_cookie_audit(job, ex);
            else
                ok = false;
        }
    }
    if (job->cancel_requested.load(std::memory_order_acquire)) {
        update_defensive_status(job, check, "cancelled", findings, {});
    } else if (ok) {
        update_defensive_status(job, check, "complete", findings, {});
    } else {
        update_defensive_status(job, check, "error", findings, error.empty() ? "defensive check failed" : error);
    }
}

std::shared_ptr<scan_runtime_t> find_scan(uint64_t scan_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    auto it = s.scans.find(scan_id);
    return it == s.scans.end() ? std::shared_ptr<scan_runtime_t>() : it->second;
}

std::vector<uint64_t> audit_ids_for_scan_locked(const std::shared_ptr<scan_runtime_t>& job)
{
    std::vector<uint64_t> ids;
    if (!job)
        return ids;
    if (job->active_audit_id != 0)
        ids.push_back(job->active_audit_id);
    if (job->crawl_audit_job_id != 0) {
        const auto st = crawl_audit::status(job->crawl_audit_job_id);
        if (st.id != 0) {
            for (uint64_t id : st.audit_ids)
                ids.push_back(id);
        }
    }
    for (uint64_t id : job->audit_ids)
        ids.push_back(id);
    ids.push_back(job->scan_id);
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

std::vector<uint64_t> audit_ids_for_scan(const std::shared_ptr<scan_runtime_t>& job)
{
    if (!job)
        return {};
    std::lock_guard<std::mutex> lk(job->mtx);
    return audit_ids_for_scan_locked(job);
}

std::vector<issue_t> issues_for_scan_id(uint64_t scan_id)
{
    issue_store::initialize();
    auto job = find_scan(scan_id);
    if (!job) {
        issue_filter_t f;
        f.has_audit_id = true;
        f.audit_id = scan_id;
        return issue_store::list(f);
    }
    const auto ids = audit_ids_for_scan(job);
    std::unordered_set<uint64_t> id_set(ids.begin(), ids.end());
    issue_filter_t f;
    auto all = issue_store::list(f);
    std::vector<issue_t> out;
    for (const auto& issue : all) {
        if (id_set.find(issue.audit_id) != id_set.end())
            out.push_back(issue);
    }
    return out;
}

void mirror_scan_issues_to_findings_db(uint64_t scan_id)
{
    if (scan_id == 0 || !findings_db::initialize())
        return;
    auto job = find_scan(scan_id);
    std::string session_id;
    if (job) {
        std::lock_guard<std::mutex> lk(job->mtx);
        session_id = job->session_id;
    }
    for (auto issue : issues_for_scan_id(scan_id)) {
        issue.scan_id = scan_id;
        if (issue.session_id.empty())
            issue.session_id = session_id;
        findings_db::upsert(std::move(issue));
    }
}

json severity_counts_json(const std::vector<issue_t>& issues)
{
    json out = {{"critical", 0}, {"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}};
    for (const auto& issue : issues) {
        switch (issue.severity) {
            case severity_t::critical: out["critical"] = out["critical"].get<int>() + 1; break;
            case severity_t::high: out["high"] = out["high"].get<int>() + 1; break;
            case severity_t::medium: out["medium"] = out["medium"].get<int>() + 1; break;
            case severity_t::low: out["low"] = out["low"].get<int>() + 1; break;
            case severity_t::info: out["info"] = out["info"].get<int>() + 1; break;
        }
    }
    return out;
}

json defensive_status_json(const std::shared_ptr<scan_runtime_t>& job, size_t& done, size_t& total, size_t& findings)
{
    json arr = json::array();
    done = 0;
    total = 0;
    findings = 0;
    if (!job)
        return arr;
    std::lock_guard<std::mutex> lk(job->mtx);
    total = job->defensive.size();
    for (const auto& st : job->defensive) {
        if (st.status == "complete" || st.status == "cancelled" || st.status == "error")
            ++done;
        findings += st.findings;
        json item;
        item["check"] = st.check;
        item["status"] = st.status;
        item["findings"] = st.findings;
        item["started_ms"] = st.started_ms;
        item["ended_ms"] = st.ended_ms;
        if (!st.last_error.empty())
            item["last_error"] = st.last_error;
        arr.push_back(std::move(item));
    }
    return arr;
}

json module_progress_json(const std::vector<std::string>& modules, size_t total_probes, size_t completed_probes, size_t issue_count, const std::string& active_status)
{
    json arr = json::array();
    if (modules.empty())
        return arr;
    const size_t count = modules.size();
    const size_t base_total = count == 0 ? 0 : total_probes / count;
    const size_t remainder_total = count == 0 ? 0 : total_probes % count;
    size_t remaining_done = completed_probes;
    for (size_t i = 0; i < modules.size(); ++i) {
        const size_t mt = base_total + (i < remainder_total ? 1 : 0);
        const size_t md = std::min(mt, remaining_done);
        remaining_done = remaining_done > md ? remaining_done - md : 0;
        json item;
        item["id"] = modules[i];
        item["status"] = active_status == "complete" ? "complete" : (md == 0 && active_status == "running" ? "pending" : active_status);
        item["probes_done"] = md;
        item["probes_total"] = mt;
        if (issue_count == 0)
            item["issues"] = 0;
        else
            item["issues"] = nullptr;
        arr.push_back(std::move(item));
    }
    return arr;
}

bool audit_terminal(const active_scanner::audit_status_t& st)
{
    return !st.running && (st.drained || st.ended_ms != 0 || st.cancelled || st.cancel_requested || st.completed_probes >= st.total_probes);
}

struct scan_aggregate_t
{
    size_t total_probes = 0;
    size_t completed_probes = 0;
    size_t active_workers = 0;
    size_t queued_workers = 0;
    size_t in_flight = 0;
    size_t responses_received = 0;
    size_t transport_failures = 0;
    bool active_present = false;
    bool active_done = true;
    bool active_error = false;
    bool crawl_present = false;
    bool crawl_done = true;
    std::string active_status = "complete";
    uint64_t crawl_id = 0;
    uint64_t crawl_audit_job_id = 0;
    json crawl = json::object();
};

scan_aggregate_t collect_scan_aggregate(const std::shared_ptr<scan_runtime_t>& job)
{
    scan_aggregate_t agg;
    if (!job)
        return agg;
    uint64_t active_audit_id = 0;
    uint64_t crawl_audit_job_id = 0;
    uint64_t crawler_id = 0;
    {
        std::lock_guard<std::mutex> lk(job->mtx);
        active_audit_id = job->active_audit_id;
        crawl_audit_job_id = job->crawl_audit_job_id;
        crawler_id = job->crawler_id;
    }
    if (active_audit_id != 0) {
        agg.active_present = true;
        active_scanner::audit_status_t st;
        if (active_scanner::get_status(active_audit_id, st)) {
            agg.total_probes += st.total_probes;
            agg.completed_probes += std::min(st.completed_probes, st.total_probes);
            agg.active_workers += st.active_workers;
            agg.queued_workers += st.queued_workers;
            agg.in_flight += st.in_flight_requests;
            agg.responses_received += st.responses_received;
            agg.transport_failures += st.transport_failures;
            agg.active_done = audit_terminal(st);
            agg.active_status = st.running ? "running" : (st.cancelled || st.cancel_requested ? "cancelled" : "complete");
        } else {
            agg.active_error = true;
            agg.active_done = true;
            agg.active_status = "error";
        }
    }
    if (crawl_audit_job_id != 0) {
        agg.active_present = true;
        agg.crawl_present = true;
        agg.crawl_audit_job_id = crawl_audit_job_id;
        const auto st = crawl_audit::status(crawl_audit_job_id);
        if (st.id != 0) {
            agg.crawl_id = st.crawl_id;
            agg.crawl_done = crawl_audit_phase_terminal(st.phase);
            agg.active_status = crawl_audit_phase_running(st.phase) ? "running" : crawl_audit_phase_label(st.phase);
            json audit_ids = json::array();
            size_t completed_audits = 0;
            for (uint64_t id : st.audit_ids) {
                audit_ids.push_back(id);
                active_scanner::audit_status_t ast;
                if (active_scanner::get_status(id, ast)) {
                    agg.total_probes += ast.total_probes;
                    agg.completed_probes += std::min(ast.completed_probes, ast.total_probes);
                    agg.active_workers += ast.active_workers;
                    agg.queued_workers += ast.queued_workers;
                    agg.in_flight += ast.in_flight_requests;
                    agg.responses_received += ast.responses_received;
                    agg.transport_failures += ast.transport_failures;
                    if (audit_terminal(ast))
                        completed_audits++;
                    else
                        agg.active_done = false;
                }
            }
            const int failed_enqueue = (std::max)(0, st.pages_discovered - st.audits_started);
            agg.active_done = agg.active_done && agg.crawl_done;
            agg.crawl = {
                {"job_id", st.id},
                {"crawl_id", st.crawl_id},
                {"phase", crawl_audit_phase_label(st.phase)},
                {"discovered_urls", st.pages_discovered},
                {"pages_discovered", st.pages_discovered},
                {"pending_urls", 0},
                {"queued_audits", st.audit_ids.size() > completed_audits ? st.audit_ids.size() - completed_audits : 0},
                {"completed_audits", completed_audits},
                {"audits_started", st.audits_started},
                {"issues_found", st.issues_found},
                {"failed_enqueue", failed_enqueue},
                {"last_error", redact_text(st.last_error, 512)},
                {"audit_ids", std::move(audit_ids)}
            };
        } else {
            agg.active_error = true;
            agg.active_done = true;
            agg.active_status = "error";
        }
    } else if (crawler_id != 0) {
        agg.crawl_present = true;
        agg.crawl_id = crawler_id;
        const auto st = crawler::status(crawler_id);
        agg.crawl_done = st.phase == crawler::crawl_status_phase_t::complete || st.phase == crawler::crawl_status_phase_t::error;
        agg.crawl = {
            {"crawl_id", st.id},
            {"phase", crawl_phase_label(st.phase)},
            {"queue_depth", st.queue_depth},
            {"pages_visited", st.pages_visited},
            {"pages_failed", st.pages_failed},
            {"urls_found", st.urls_found},
            {"in_flight", st.in_flight},
            {"last_url", redact_url(st.last_url)},
            {"last_error", redact_text(st.last_error, 512)}
        };
        agg.active_done = true;
    }
    if (!agg.active_present)
        agg.active_done = true;
    if (!agg.crawl_present)
        agg.crawl_done = true;
    return agg;
}

uint64_t json_u64_or(const json& obj, const char* key, uint64_t fallback)
{
    if (!obj.is_object() || !obj.contains(key))
        return fallback;
    if (obj[key].is_number_unsigned())
        return obj[key].get<uint64_t>();
    if (obj[key].is_number_integer()) {
        const auto value = obj[key].get<int64_t>();
        return value > 0 ? static_cast<uint64_t>(value) : fallback;
    }
    return fallback;
}

std::string json_string_or(const json& obj, const char* key, const std::string& fallback)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_string())
        return fallback;
    return obj[key].get<std::string>();
}

void persist_scan_run_status(const std::shared_ptr<scan_runtime_t>& job, const json& status)
{
    if (!job || !findings_db::initialize())
        return;
    mirror_scan_issues_to_findings_db(job->scan_id);
    findings_db::scan_run_t run;
    run.scan_id = job->scan_id;
    run.status = json_string_or(status, "status", "running");
    run.total_probes = json_u64_or(status, "total_probes", 0);
    run.completed_probes = json_u64_or(status, "completed_probes", 0);
    run.issues_found = json_u64_or(status, "issues_found", 0);
    if (status.contains("modules") && status["modules"].is_array())
        run.modules_json = status["modules"];
    if (status.contains("defensive_status") && status["defensive_status"].is_array())
        run.defensive_json = status["defensive_status"];
    run.started_ms = json_u64_or(status, "started_ms", 0);
    run.ended_ms = json_u64_or(status, "ended_ms", 0);
    run.error_message = json_string_or(status, "last_error", std::string());
    {
        std::lock_guard<std::mutex> lk(job->mtx);
        run.session_id = job->session_id;
        run.target_url = job->target_url_redacted;
        run.profile = job->profile_id;
        run.config_json = {
            {"crawl_first", job->crawl_first},
            {"run_defensive", job->run_defensive},
            {"scope_only", job->scope_only},
            {"crawl_depth", job->crawl_depth},
            {"max_concurrent_requests", job->max_concurrent_requests},
            {"request_throttle_ms", job->request_throttle_ms},
            {"timeout_ms", job->timeout_ms}
        };
    }
    findings_db::upsert_scan_run(run);
    if (run.modules_json.is_array()) {
        for (const auto& item : run.modules_json) {
            if (!item.is_object())
                continue;
            const std::string id = json_string_or(item, "id", std::string());
            if (id.empty())
                continue;
            findings_db::scan_module_status_t mod;
            mod.scan_id = job->scan_id;
            mod.module_id = id;
            mod.status = json_string_or(item, "status", "pending");
            mod.probes_done = json_u64_or(item, "probes_done", 0);
            mod.probes_total = json_u64_or(item, "probes_total", 0);
            mod.issues_found = json_u64_or(item, "issues", 0);
            mod.started_ms = run.started_ms;
            mod.ended_ms = run.ended_ms;
            findings_db::update_scan_module(mod);
        }
    }
    if (run.defensive_json.is_array()) {
        for (const auto& item : run.defensive_json) {
            if (!item.is_object())
                continue;
            const std::string check = json_string_or(item, "check", std::string());
            if (check.empty())
                continue;
            findings_db::scan_module_status_t mod;
            mod.scan_id = job->scan_id;
            mod.module_id = "defensive:" + check;
            mod.status = json_string_or(item, "status", "pending");
            mod.probes_done = mod.status == "complete" || mod.status == "cancelled" || mod.status == "error" ? 1 : 0;
            mod.probes_total = 1;
            mod.issues_found = json_u64_or(item, "findings", 0);
            mod.started_ms = json_u64_or(item, "started_ms", run.started_ms);
            mod.ended_ms = json_u64_or(item, "ended_ms", run.ended_ms);
            mod.error_message = json_string_or(item, "last_error", std::string());
            findings_db::update_scan_module(mod);
        }
    }
}

json scan_status_json(const std::shared_ptr<scan_runtime_t>& job)
{
    if (!job)
        return json::object();
    size_t defensive_done = 0;
    size_t defensive_total = 0;
    size_t defensive_findings = 0;
    json defensive = defensive_status_json(job, defensive_done, defensive_total, defensive_findings);
    scan_aggregate_t agg = collect_scan_aggregate(job);
    auto issues = issues_for_scan_id(job->scan_id);
    const size_t issue_count = issues.size();
    uint64_t started = 0;
    uint64_t ended = 0;
    bool cancel_requested = false;
    scan_phase_t phase = scan_phase_t::running;
    std::string target_url_redacted;
    std::string profile_id;
    std::vector<std::string> modules;
    std::string last_error;
    {
        std::lock_guard<std::mutex> lk(job->mtx);
        started = job->started_ms;
        ended = job->ended_ms;
        cancel_requested = job->cancel_requested.load(std::memory_order_acquire);
        phase = job->phase;
        target_url_redacted = job->target_url_redacted;
        profile_id = job->profile_id;
        modules = job->module_ids;
        last_error = job->last_error;
    }
    const bool defensive_done_all = defensive_done >= defensive_total;
    const bool all_done = agg.active_done && agg.crawl_done && defensive_done_all;
    if (phase != scan_phase_t::error) {
        if (cancel_requested && all_done)
            phase = scan_phase_t::cancelled;
        else if (cancel_requested)
            phase = scan_phase_t::stopping;
        else if (all_done)
            phase = scan_phase_t::complete;
        else
            phase = scan_phase_t::running;
    }
    if ((phase == scan_phase_t::complete || phase == scan_phase_t::cancelled || phase == scan_phase_t::error) && ended == 0) {
        ended = unix_ms();
        std::lock_guard<std::mutex> lk(job->mtx);
        job->phase = phase;
        job->ended_ms = ended;
    }
    size_t total_units = agg.total_probes + defensive_total;
    size_t done_units = std::min(agg.completed_probes, agg.total_probes) + defensive_done;
    if (agg.crawl_present && !agg.active_present) {
        ++total_units;
        if (agg.crawl_done)
            ++done_units;
    }
    int progress = 0;
    if (total_units == 0)
        progress = all_done ? 100 : 0;
    else
        progress = static_cast<int>(std::min<size_t>(100, (done_units * 100) / total_units));
    if (phase == scan_phase_t::complete || phase == scan_phase_t::cancelled)
        progress = 100;
    const uint64_t now = unix_ms();
    const uint64_t elapsed = started == 0 ? 0 : ((ended != 0 ? ended : now) > started ? (ended != 0 ? ended : now) - started : 0);
    uint64_t remaining = 0;
    if (progress > 0 && progress < 100)
        remaining = static_cast<uint64_t>((static_cast<double>(elapsed) * (100.0 - progress)) / static_cast<double>(progress));
    json out;
    out["scan_id"] = job->scan_id;
    out["status"] = phase_label(phase);
    out["profile"] = profile_id;
    out["target_url"] = target_url_redacted;
    out["progress_pct"] = progress;
    out["total_probes"] = agg.total_probes + defensive_total;
    out["completed_probes"] = std::min(agg.completed_probes, agg.total_probes) + defensive_done;
    out["issues_found"] = issue_count;
    out["defensive_findings"] = defensive_findings;
    out["issues_by_severity"] = severity_counts_json(issues);
    out["modules"] = module_progress_json(modules, agg.total_probes, agg.completed_probes, issue_count, agg.active_status);
    out["defensive_status"] = std::move(defensive);
    out["started_ms"] = started;
    out["ended_ms"] = ended;
    out["elapsed_ms"] = elapsed;
    out["estimated_remaining_ms"] = remaining;
    out["active_workers"] = agg.active_workers;
    out["queued_workers"] = agg.queued_workers;
    out["in_flight_requests"] = agg.in_flight;
    out["responses_received"] = agg.responses_received;
    out["transport_failures"] = agg.transport_failures;
    out["cancel_requested"] = cancel_requested;
    if (!agg.crawl.is_null() && !agg.crawl.empty())
        out["crawl"] = agg.crawl;
    if (!last_error.empty())
        out["last_error"] = last_error;
    persist_scan_run_status(job, out);
    return out;
}

void publish_scan_started(const std::shared_ptr<scan_runtime_t>& job)
{
    json payload;
    payload["scan_id"] = job->scan_id;
    payload["status"] = "running";
    payload["target_url"] = job->target_url_redacted;
    payload["profile"] = job->profile_id;
    payload["started_ms"] = job->started_ms;
    aida::events::publish(kScanStartedEvent, payload);
}

void publish_scan_completed_if_terminal(const std::shared_ptr<scan_runtime_t>& job, const json& status)
{
    const std::string st = status.value("status", std::string());
    if (st == "complete" || st == "cancelled" || st == "error")
        aida::events::publish(kScanCompletedEvent, status);
}

json modules_array_json(const std::vector<std::string>& modules)
{
    json arr = json::array();
    for (const auto& m : modules)
        arr.push_back(m);
    return arr;
}

int estimate_requests(const scan_profile_t& profile)
{
    const size_t module_count = profile.module_ids.size();
    const size_t crawl_factor = profile.crawl_first ? static_cast<size_t>(std::max(1, profile.crawl_depth + 1)) : 1;
    const size_t active = module_count == 0 ? 0 : module_count * 8 * crawl_factor;
    return static_cast<int>(std::min<size_t>(100000, active + profile.defensive_checks.size()));
}

tool_result_t param_error(const std::string& message, const std::string& parameter, const std::string& code = "invalid_param")
{
    return tool_result_t::error(message, code, {{"parameter", parameter}, {"success", false}});
}

tool_result_t tool_orchestrate(const json& params)
{
    if (call_cancelled_or_deadline())
        return tool_result_t::error("scan orchestration cancelled", std::string("cancelled"), json::object());
    std::string target_url;
    if (!json_string(params, "target_url", target_url) || trim_copy(target_url).empty())
        return param_error("missing target_url", "target_url", "missing_required");
    target_url = trim_copy(target_url);
    if (url_has_sensitive_query(target_url))
        return param_error("target_url contains sensitive query parameters; use a non-secret URL for scan orchestration", "target_url", "sensitive_url_rejected");
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path) || (scheme != "http" && scheme != "https"))
        return param_error("target_url must be a valid http or https URL", "target_url");
    std::string profile_id = "quick";
    json_string(params, "profile", profile_id);
    profile_id = trim_copy(profile_id.empty() ? std::string("quick") : profile_id);
    std::optional<scan_profile_t> maybe_profile = find_profile(profile_id);
    if (!maybe_profile.has_value())
        return param_error("unknown scan profile", "profile", "profile_not_found");
    scan_profile_t profile = *maybe_profile;
    if (profile_id == "custom") {
        std::string saved_profile_id;
        if (json_string(params, "profile_id", saved_profile_id)) {
            auto saved = find_profile(trim_copy(saved_profile_id));
            if (saved.has_value()) {
                profile = *saved;
                profile_id = profile.id;
            }
        }
    }
    std::string error;
    if (params.contains("module_ids")) {
        profile.module_ids = normalize_modules(json_string_array(params, "module_ids", kMaxProfileArray), error);
        if (!error.empty())
            return param_error(error, "module_ids");
    }
    if (params.contains("defensive_checks")) {
        profile.defensive_checks = normalize_defensive_checks(json_string_array(params, "defensive_checks", kMaxProfileArray), error);
        if (!error.empty())
            return param_error(error, "defensive_checks");
    }
    json_bool(params, "crawl_first", profile.crawl_first);
    json_bool(params, "run_defensive", profile.run_defensive);
    json_int_range(params, "crawl_depth", 0, 10, profile.crawl_depth);
    profile.max_concurrent_requests = std::clamp(profile.max_concurrent_requests, size_t{1}, size_t{64});
    profile.request_throttle_ms = std::min(profile.request_throttle_ms, size_t{60000});
    profile.timeout_ms = std::clamp(profile.timeout_ms, 1000, 120000);
    const bool max_concurrent_explicit = json_size_range(params, "max_concurrent_requests", 1, 64, profile.max_concurrent_requests);
    const bool throttle_explicit = json_size_range(params, "request_throttle_ms", 0, 60000, profile.request_throttle_ms);
    json_int_range(params, "timeout_ms", 1000, 120000, profile.timeout_ms);
    if (!profile.run_defensive)
        profile.defensive_checks.clear();
    if (!profile.crawl_first)
        profile.crawl_depth = 0;
    bool scope_only = false;
    json_bool(params, "scope_only", scope_only);
    std::string session_id;
    json_string(params, "session_id", session_id);
    session_id = redact_text(safe_display_string(session_id, 128), 128);
    if (profile.module_ids.empty() && profile.defensive_checks.empty() && (!profile.crawl_first || profile.crawl_depth == 0))
        return tool_result_t::error("selected scan profile has no active, crawl, or defensive work", std::string("empty_scan_profile"), json::object());
    issue_store::initialize();
    findings_db::initialize();
    passive_scanner::initialize();
    active_scanner::initialize();
    crawler::initialize();
    crawl_audit::initialize();
    auto job = std::make_shared<scan_runtime_t>();
    job->scan_id = state().next_scan_id.fetch_add(1, std::memory_order_acq_rel);
    job->target_url = target_url;
    job->target_url_redacted = redact_url(target_url);
    job->profile_id = profile.id;
    job->session_id = session_id;
    job->module_ids = profile.module_ids;
    job->defensive_checks = profile.defensive_checks;
    job->crawl_first = profile.crawl_first;
    job->run_defensive = profile.run_defensive;
    job->scope_only = scope_only;
    job->crawl_depth = profile.crawl_depth;
    job->max_concurrent_requests = profile.max_concurrent_requests;
    job->request_throttle_ms = profile.request_throttle_ms;
    job->timeout_ms = profile.timeout_ms;
    job->max_concurrent_explicit = max_concurrent_explicit;
    job->request_throttle_explicit = throttle_explicit;
    job->started_ms = unix_ms();
    for (const auto& check : profile.defensive_checks) {
        defensive_status_t st;
        st.check = check;
        job->defensive.push_back(std::move(st));
    }
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        state().scans[job->scan_id] = job;
    }
    bool active_started = false;
    if (!profile.module_ids.empty()) {
        active_scanner::audit_config_t cfg;
        cfg.session_id = job->session_id;
        cfg.scan_id = job->scan_id;
        cfg.scope_only = scope_only;
        cfg.enabled_modules = profile.module_ids;
        cfg.max_concurrent_requests = profile.max_concurrent_requests;
        cfg.request_throttle_ms = profile.request_throttle_ms;
        cfg.timeout_ms = profile.timeout_ms;
        cfg.max_concurrent_explicit = max_concurrent_explicit;
        cfg.request_throttle_explicit = throttle_explicit;
        if (profile.crawl_first && profile.crawl_depth > 0) {
            crawl_audit::pipeline_config_t crawl_cfg;
            crawl_cfg.start_urls.push_back(target_url);
            crawl_cfg.session_id = job->session_id;
            crawl_cfg.scan_id = job->scan_id;
            crawl_cfg.max_depth = profile.crawl_depth;
            crawl_cfg.same_host_only = true;
            crawl_cfg.scope_only = scope_only;
            crawl_cfg.max_pages = profile.id == "full" ? 500 : 200;
            crawl_cfg.max_concurrent = static_cast<int>(std::min<size_t>(profile.max_concurrent_requests, 16));
            crawl_cfg.throttle_ms = static_cast<int>(std::min<size_t>(profile.request_throttle_ms, 60000));
            crawl_cfg.audit_after_crawl = true;
            crawl_cfg.enabled_modules = profile.module_ids;
            const uint64_t crawl_job_id = crawl_audit::start(crawl_cfg);
            if (crawl_job_id == 0) {
                std::string err = "crawl audit start failed";
                {
                    std::lock_guard<std::mutex> lk(job->mtx);
                    job->phase = scan_phase_t::error;
                    job->last_error = err;
                    job->ended_ms = unix_ms();
                }
                return tool_result_t::error(err, std::string("crawl_audit_start_failed"), json::object());
            }
            {
                std::lock_guard<std::mutex> lk(job->mtx);
                job->crawl_audit_job_id = crawl_job_id;
            }
            active_started = true;
        } else {
            std::vector<uint8_t> raw;
            std::string err;
            if (!build_get_request(target_url, raw, err))
                return param_error(err, "target_url");
            const uint64_t audit_id = active_scanner::enqueue_target(raw, target_url, cfg);
            if (audit_id == 0) {
                err = redact_text(active_scanner::last_error(), 512);
                {
                    std::lock_guard<std::mutex> lk(job->mtx);
                    job->phase = scan_phase_t::error;
                    job->last_error = err;
                    job->ended_ms = unix_ms();
                }
                return tool_result_t::error(err.empty() ? "active scanner enqueue failed" : err, std::string("active_scanner_enqueue_failed"), json::object());
            }
            {
                std::lock_guard<std::mutex> lk(job->mtx);
                job->active_audit_id = audit_id;
                job->audit_ids.push_back(audit_id);
            }
            active_started = true;
        }
    } else if (profile.crawl_first && profile.crawl_depth > 0) {
        crawler::crawl_config_t cfg;
        cfg.start_urls.push_back(target_url);
        cfg.max_depth = profile.crawl_depth;
        cfg.same_host_only = true;
        cfg.scope_only = scope_only;
        cfg.request_timeout_ms = profile.timeout_ms;
        cfg.max_pages = profile.id == "quick" ? 50 : 200;
        cfg.concurrency = static_cast<int>(std::min<size_t>(profile.max_concurrent_requests, 8));
        cfg.rate_per_host = profile.request_throttle_ms == 0 ? 10 : std::max(1, static_cast<int>(1000 / std::max<size_t>(profile.request_throttle_ms, 1)));
        const uint64_t crawl_id = crawler::start(cfg);
        if (crawl_id == 0) {
            const std::string err = redact_text(crawler::last_error(), 512);
            {
                std::lock_guard<std::mutex> lk(job->mtx);
                job->phase = scan_phase_t::error;
                job->last_error = err;
                job->ended_ms = unix_ms();
            }
            return tool_result_t::error(err.empty() ? "crawler start failed" : err, std::string("crawler_start_failed"), json::object());
        }
        {
            std::lock_guard<std::mutex> lk(job->mtx);
            job->crawler_id = crawl_id;
        }
    }
    for (const auto& check : profile.defensive_checks) {
        mcp_standalone::downstream::producer_identity_t def_id;
        def_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
        def_id.tool_name = "scan_orchestrator.run_defensive_check";
        def_id.command_label = check;
        def_id.domain = job->target_url_redacted;
        auto def_admission = mcp_standalone::downstream::scoped_admission_t::acquire(def_id);
        if (!def_admission.active()) {
            diag::log_tagged_fmt("scan_orchestrator", "BURP-NETWORK-WORKER-REJECT check=%s scan_id=%llu reason=%s quota=%s scope=%s observed=%zu limit=%zu",
                check.c_str(),
                static_cast<unsigned long long>(job->scan_id),
                def_admission.result().reason.c_str(),
                def_admission.result().quota_name.c_str(),
                def_admission.result().quota_scope.c_str(),
                def_admission.result().observed, def_admission.result().limit);
            update_defensive_status(job, check, "error", 0, "downstream capacity exhausted");
            continue;
        }
        const uint64_t def_token = def_admission.token();
        diag::log_tagged_fmt("scan_orchestrator", "BURP-NETWORK-WORKER-ADMIT check=%s scan_id=%llu token=%llu",
            check.c_str(),
            static_cast<unsigned long long>(job->scan_id),
            static_cast<unsigned long long>(def_token));
        auto def_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(def_admission));
        const bool posted = [&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.scan_orchestrator";
            sub.label = "scan.defensive_check";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::feature_worker;
            sub.priority = 3;
            sub.body = [job, check, def_admission_ptr, def_token]() {
            run_defensive_check(job, check);
            diag::log_tagged_fmt("scan_orchestrator", "BURP-NETWORK-WORKER-RELEASE check=%s scan_id=%llu token=%llu reason=completed",
                check.c_str(),
                static_cast<unsigned long long>(job->scan_id),
                static_cast<unsigned long long>(def_token));
            def_admission_ptr->release("completed");
        };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }();
        if (!posted)
            update_defensive_status(job, check, "error", 0, "executor unavailable");
    }
    publish_scan_started(job);
    json initial_status = scan_status_json(job);
    json out;
    out["scan_id"] = job->scan_id;
    out["status"] = initial_status.value("status", std::string("running"));
    out["profile"] = profile.id;
    out["target_url"] = job->target_url_redacted;
    out["progress_pct"] = initial_status.value("progress_pct", 0);
    out["modules_enabled"] = modules_array_json(profile.module_ids);
    out["defensive_checks"] = profile.defensive_checks;
    out["estimated_requests"] = estimate_requests(profile);
    out["started_ms"] = job->started_ms;
    out["crawl_first"] = profile.crawl_first;
    out["crawl_depth"] = profile.crawl_depth;
    out["active_started"] = active_started;
    if (job->crawl_audit_job_id != 0)
        out["crawl_audit_job_id"] = job->crawl_audit_job_id;
    if (job->crawler_id != 0)
        out["crawl_id"] = job->crawler_id;
    if (job->active_audit_id != 0)
        out["audit_id"] = job->active_audit_id;
    return tool_result_t::ok("scan orchestrated", out);
}

tool_result_t tool_profile_list(const json& params)
{
    const bool include_modules = !params.contains("include_modules") || !params["include_modules"].is_boolean() || params["include_modules"].get<bool>();
    std::map<std::string, scan_profile_t> by_id;
    auto add_profile = [&](scan_profile_t p) {
        by_id[p.id] = std::move(p);
    };
    add_profile(quick_profile());
    add_profile(full_profile());
    add_profile(custom_base_profile());
    bool db_available = findings_db::initialize();
    if (db_available) {
        for (const auto& db_profile : findings_db::list_scan_profiles(false)) {
            auto profile = db_profile_to_profile(db_profile);
            if (profile.has_value())
                add_profile(*profile);
        }
    }
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        for (const auto& kv : state().custom_profiles)
            add_profile(kv.second);
    }
    std::vector<scan_profile_t> profiles;
    profiles.reserve(by_id.size());
    for (auto& kv : by_id)
        profiles.push_back(std::move(kv.second));
    std::sort(profiles.begin(), profiles.end(), [](const scan_profile_t& a, const scan_profile_t& b) {
        if (a.builtin != b.builtin)
            return a.builtin > b.builtin;
        return a.id < b.id;
    });
    json arr = json::array();
    for (const auto& p : profiles)
        arr.push_back(profile_to_json(p, include_modules));
    return tool_result_t::ok({{"profiles", std::move(arr)}, {"count", profiles.size()}, {"storage", db_available ? "findings_db+json_appdata" : "json_appdata"}});
}

tool_result_t tool_profile_save(const json& params)
{
    std::string id;
    std::string name;
    if (!json_string(params, "profile_id", id) || trim_copy(id).empty())
        return param_error("missing profile_id", "profile_id", "missing_required");
    if (!json_string(params, "name", name) || trim_copy(name).empty())
        return param_error("missing name", "name", "missing_required");
    id = trim_copy(id);
    if (!valid_token_id(id, 64) || id == "quick" || id == "full" || id == "custom")
        return param_error("profile_id must be a non-reserved alphanumeric id", "profile_id");
    scan_profile_t profile = custom_base_profile();
    profile.id = id;
    profile.name = safe_display_string(trim_copy(name), 128);
    json_string(params, "description", profile.description);
    profile.description = redact_text(profile.description, 512);
    std::string error;
    profile.module_ids = normalize_modules(json_string_array(params, "module_ids", kMaxProfileArray), error);
    if (!error.empty())
        return param_error(error, "module_ids");
    profile.defensive_checks = normalize_defensive_checks(json_string_array(params, "defensive_checks", kMaxProfileArray), error);
    if (!error.empty())
        return param_error(error, "defensive_checks");
    json_int_range(params, "crawl_depth", 0, 10, profile.crawl_depth);
    json_size_range(params, "max_concurrent_requests", 1, 64, profile.max_concurrent_requests);
    json_size_range(params, "request_throttle_ms", 0, 60000, profile.request_throttle_ms);
    json_int_range(params, "timeout_ms", 1000, 120000, profile.timeout_ms);
    json_bool(params, "crawl_first", profile.crawl_first);
    json_bool(params, "run_defensive", profile.run_defensive);
    if (!profile.run_defensive)
        profile.defensive_checks.clear();
    if (profile.module_ids.empty() && profile.defensive_checks.empty() && (!profile.crawl_first || profile.crawl_depth == 0))
        return tool_result_t::error("profile must include active modules, defensive checks, or crawl work", std::string("empty_profile"), json::object());
    profile.builtin = false;
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        state().custom_profiles[profile.id] = profile;
    }
    if (!save_profiles()) {
        std::string last;
        {
            std::lock_guard<std::mutex> lk(state().err_mtx);
            last = state().last_error;
        }
        return tool_result_t::error("failed to save scan profile", "profile_save_failed", {{"error", redact_text(last, 512)}});
    }
    const bool db_available = findings_db::initialize();
    bool db_saved = false;
    if (db_available) {
        db_saved = findings_db::save_scan_profile(profile_to_db_profile(profile));
        if (!db_saved)
            return tool_result_t::error("failed to save scan profile to findings database", "profile_db_save_failed", {{"error", redact_text(findings_db::last_error(), 512)}, {"json_storage_path", profile_storage_path()}});
    }
    return tool_result_t::ok("scan profile saved", {{"profile", profile_to_json(profile, true)}, {"json_storage_path", profile_storage_path()}, {"findings_db_persisted", db_saved}, {"findings_db_storage_path", db_saved ? findings_db::storage_path() : std::string()}});
}

tool_result_t tool_status(const json& params)
{
    if (!params.contains("scan_id") || !params["scan_id"].is_number_unsigned())
        return param_error("missing scan_id", "scan_id", "missing_required");
    auto job = find_scan(params["scan_id"].get<uint64_t>());
    if (!job)
        return tool_result_t::error("scan not found", std::string("scan_not_found"), json::object());
    json status = scan_status_json(job);
    publish_scan_completed_if_terminal(job, status);
    return tool_result_t::ok(status);
}

tool_result_t tool_cancel(const json& params)
{
    if (!params.contains("scan_id") || !params["scan_id"].is_number_unsigned())
        return param_error("missing scan_id", "scan_id", "missing_required");
    auto job = find_scan(params["scan_id"].get<uint64_t>());
    if (!job)
        return tool_result_t::error("scan not found", std::string("scan_not_found"), json::object());
    std::vector<uint64_t> audit_ids;
    uint64_t crawl_audit_job_id = 0;
    uint64_t crawler_id = 0;
    {
        std::lock_guard<std::mutex> lk(job->mtx);
        job->cancel_requested.store(true, std::memory_order_release);
        if (job->phase == scan_phase_t::running)
            job->phase = scan_phase_t::stopping;
        audit_ids = audit_ids_for_scan_locked(job);
        crawl_audit_job_id = job->crawl_audit_job_id;
        crawler_id = job->crawler_id;
    }
    if (crawl_audit_job_id != 0)
        crawl_audit::stop(crawl_audit_job_id);
    if (crawler_id != 0)
        crawler::stop(crawler_id);
    for (uint64_t id : audit_ids) {
        if (id != job->scan_id)
            active_scanner::cancel_audit(id);
    }
    const uint64_t wait_deadline = tick_ms() + 2000;
    bool drained = false;
    for (uint64_t id : audit_ids) {
        if (id == job->scan_id)
            continue;
        const uint64_t now = tick_ms();
        if (now >= wait_deadline)
            break;
        drained = active_scanner::wait_for_audit_idle(id, static_cast<uint32_t>(std::min<uint64_t>(500, wait_deadline - now))) || drained;
        if (call_cancelled_or_deadline())
            break;
    }
    json status = scan_status_json(job);
    json out;
    out["scan_id"] = job->scan_id;
    out["cancelled"] = true;
    out["partial_issues_saved"] = issues_for_scan_id(job->scan_id).size();
    out["drained_workers"] = drained ? audit_ids.size() : 0;
    out["status"] = status;
    return tool_result_t::ok("scan cancellation requested", out);
}

std::vector<uint64_t> scan_ids_for_session(const std::string& session_id)
{
    std::vector<uint64_t> ids;
    if (session_id.empty())
        return ids;
    std::lock_guard<std::mutex> lk(state().mtx);
    for (const auto& kv : state().scans) {
        if (!kv.second)
            continue;
        std::lock_guard<std::mutex> job_lk(kv.second->mtx);
        if (kv.second->session_id == session_id)
            ids.push_back(kv.first);
    }
    return ids;
}

bool findings_filter_from_params(const json& params, findings_db::finding_filter_t& filter, std::string& error, std::string& parameter)
{
    filter.limit = kMaxReturnedFindings;
    if (params.contains("scan_id")) {
        if (!params["scan_id"].is_number_unsigned()) {
            error = "scan_id must be a positive integer";
            parameter = "scan_id";
            return false;
        }
        filter.has_scan_id = true;
        filter.scan_id = params["scan_id"].get<uint64_t>();
    }
    if (params.contains("audit_id")) {
        if (!params["audit_id"].is_number_unsigned()) {
            error = "audit_id must be a positive integer";
            parameter = "audit_id";
            return false;
        }
        filter.has_audit_id = true;
        filter.audit_id = params["audit_id"].get<uint64_t>();
    }
    std::string session_id;
    if (json_string(params, "session_id", session_id))
        filter.session_id = redact_text(safe_display_string(trim_copy(session_id), 128), 128);
    if (params.contains("min_severity")) {
        if (!params["min_severity"].is_string()) {
            error = "min_severity must be a string";
            parameter = "min_severity";
            return false;
        }
        severity_t min_severity = severity_t::info;
        if (!parse_severity(params["min_severity"].get<std::string>(), min_severity)) {
            error = "min_severity must be info, low, medium, high, or critical";
            parameter = "min_severity";
            return false;
        }
        filter.has_severity_min = true;
        filter.severity_min = min_severity;
    }
    if (params.contains("include_suppressed")) {
        if (!params["include_suppressed"].is_boolean()) {
            error = "include_suppressed must be boolean";
            parameter = "include_suppressed";
            return false;
        }
        filter.include_suppressed = params["include_suppressed"].get<bool>();
    }
    return true;
}

bool prepare_findings_database(uint64_t scan_id, const std::string& session_id, std::string& error)
{
    issue_store::initialize();
    if (!findings_db::initialize()) {
        error = findings_db::last_error();
        if (error.empty())
            error = "findings database initialization failed";
        return false;
    }
    if (!findings_db::mirror_issue_store(false)) {
        error = findings_db::last_error();
        if (error.empty())
            error = "findings database mirror failed";
        return false;
    }
    if (scan_id != 0)
        mirror_scan_issues_to_findings_db(scan_id);
    for (uint64_t id : scan_ids_for_session(session_id))
        mirror_scan_issues_to_findings_db(id);
    return true;
}

json redacted_result_json(json value)
{
    if (value.is_string())
        return redact_text(value.get<std::string>(), 1024);
    if (value.is_array()) {
        json arr = json::array();
        for (const auto& item : value)
            arr.push_back(redacted_result_json(item));
        return arr;
    }
    if (value.is_object()) {
        json out = json::object();
        for (auto it = value.begin(); it != value.end(); ++it) {
            const std::string key = lower_ascii(it.key());
            if (key == "request_raw" || key == "response_raw" || key == "raw" || key == "body" || key == "evidence") {
                if (it.value().is_array())
                    out[it.key()] = {{"count", it.value().size()}, {"redacted", true}};
                else
                    out[it.key()] = "redacted";
            } else {
                out[it.key()] = redacted_result_json(it.value());
            }
        }
        return out;
    }
    return value;
}

tool_result_t tool_deduplicate(const json& params)
{
    if (call_cancelled_or_deadline())
        return tool_result_t::error("deduplicate cancelled", std::string("cancelled"), json::object());
    const bool merge_evidence = !params.contains("merge_evidence") || !params["merge_evidence"].is_boolean() || params["merge_evidence"].get<bool>();
    findings_db::finding_filter_t filter;
    std::string error;
    std::string parameter;
    if (!findings_filter_from_params(params, filter, error, parameter))
        return param_error(error, parameter);
    filter.limit = 0;
    const uint64_t scan_id = filter.has_scan_id ? filter.scan_id : 0;
    if (!prepare_findings_database(scan_id, filter.session_id, error))
        return tool_result_t::error("findings database unavailable", "findings_db_unavailable", {{"error", redact_text(error, 512)}});
    if (call_cancelled_or_deadline())
        return tool_result_t::error("deduplicate cancelled", std::string("cancelled"), json::object());
    const auto result = findings_db::deduplicate(filter, merge_evidence);
    return tool_result_t::ok({
        {"before_count", result.before_count},
        {"after_count", result.after_count},
        {"merged", result.merged},
        {"duplicates_removed", result.duplicates_removed},
        {"merge_evidence", merge_evidence},
        {"storage", "findings_db"}
    });
}

tool_result_t tool_correlate(const json& params)
{
    if (call_cancelled_or_deadline())
        return tool_result_t::error("correlation cancelled", std::string("cancelled"), json::object());
    findings_db::finding_filter_t filter;
    std::string error;
    std::string parameter;
    if (!findings_filter_from_params(params, filter, error, parameter))
        return param_error(error, parameter);
    if (!filter.has_severity_min) {
        filter.has_severity_min = true;
        filter.severity_min = severity_t::low;
    }
    filter.limit = 0;
    const uint64_t scan_id = filter.has_scan_id ? filter.scan_id : 0;
    if (!prepare_findings_database(scan_id, filter.session_id, error))
        return tool_result_t::error("findings database unavailable", "findings_db_unavailable", {{"error", redact_text(error, 512)}});
    if (call_cancelled_or_deadline())
        return tool_result_t::error("correlation cancelled", std::string("cancelled"), json::object());
    json result = findings_db::correlate(filter, false);
    return tool_result_t::ok(redacted_result_json(std::move(result)));
}

tool_result_t tool_score(const json& params)
{
    if (call_cancelled_or_deadline())
        return tool_result_t::error("scoring cancelled", std::string("cancelled"), json::object());
    std::string override_vector;
    json_string(params, "cvss_vector_override", override_vector);
    override_vector = trim_copy(override_vector);
    if (!override_vector.empty()) {
        const auto cvss = vuln_taxonomy::calculate_cvss31(override_vector);
        if (!cvss.valid)
            return param_error("invalid cvss_vector_override", "cvss_vector_override");
    }
    findings_db::finding_filter_t filter;
    std::string error;
    std::string parameter;
    if (!findings_filter_from_params(params, filter, error, parameter))
        return param_error(error, parameter);
    uint64_t finding_id = 0;
    if (params.contains("finding_id")) {
        if (!params["finding_id"].is_number_unsigned())
            return param_error("finding_id must be a positive integer", "finding_id");
        finding_id = params["finding_id"].get<uint64_t>();
    }
    const uint64_t scan_id = filter.has_scan_id ? filter.scan_id : 0;
    if (!prepare_findings_database(scan_id, filter.session_id, error))
        return tool_result_t::error("findings database unavailable", "findings_db_unavailable", {{"error", redact_text(error, 512)}});
    if (call_cancelled_or_deadline())
        return tool_result_t::error("scoring cancelled", std::string("cancelled"), json::object());
    json result = findings_db::score(filter, finding_id, override_vector, false);
    const uint64_t scored_count = json_u64_or(result, "count", 0);
    if (finding_id != 0 && scored_count == 0)
        return tool_result_t::error("finding not found", std::string("finding_not_found"), json::object());
    if (filter.limit > 0)
        result["truncated"] = scored_count >= static_cast<uint64_t>(filter.limit);
    return tool_result_t::ok(redacted_result_json(std::move(result)));
}

void register_tool(mcp_standalone::server_t& srv,
                   std::string name,
                   std::string description,
                   std::vector<mcp_standalone::tool_param_t> params,
                   bool read_only,
                   std::function<tool_result_t(const json&)> handler)
{
    mcp_standalone::tool_def_t tool;
    tool.name = std::move(name);
    tool.description = std::move(description);
    tool.params = std::move(params);
    tool.read_only = read_only;
    tool.handler = std::move(handler);
    tool.visibility = mcp_standalone::tool_visibility_t::external_visible;
    srv.register_tool(std::move(tool));
}

}

bool initialize()
{
    bool expected = false;
    if (!state().initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return true;
    issue_store::initialize();
    passive_scanner::initialize();
    active_scanner::initialize();
    crawler::initialize();
    crawl_audit::initialize();
    load_profiles();
    return true;
}

void shutdown()
{
    if (!state().initialized.exchange(false, std::memory_order_acq_rel))
        return;
    std::vector<std::shared_ptr<scan_runtime_t>> scans;
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        for (auto& kv : state().scans)
            scans.push_back(kv.second);
    }
    for (const auto& job : scans) {
        if (!job)
            continue;
        job->cancel_requested.store(true, std::memory_order_release);
        std::vector<uint64_t> ids;
        uint64_t crawl_audit_job_id = 0;
        uint64_t crawler_id = 0;
        {
            std::lock_guard<std::mutex> lk(job->mtx);
            ids = audit_ids_for_scan_locked(job);
            crawl_audit_job_id = job->crawl_audit_job_id;
            crawler_id = job->crawler_id;
        }
        if (crawl_audit_job_id != 0)
            crawl_audit::stop(crawl_audit_job_id);
        if (crawler_id != 0)
            crawler::stop(crawler_id);
        for (uint64_t id : ids) {
            if (id != job->scan_id)
                active_scanner::cancel_audit(id);
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool shutdown_drained = false;
    while (std::chrono::steady_clock::now() < deadline) {
        bool all_done = true;
        for (const auto& job : scans) {
            if (!job)
                continue;
            for (const uint64_t id : audit_ids_for_scan(job)) {
                if (id != job->scan_id && !active_scanner::wait_for_audit_idle(id, 0))
                    all_done = false;
            }
            std::lock_guard<std::mutex> lk(job->mtx);
            for (const auto& status : job->defensive) {
                if (status.status != "complete" && status.status != "cancelled" && status.status != "error") {
                    all_done = false;
                    break;
                }
            }
        }
        if (all_done) {
            shutdown_drained = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    if (shutdown_drained) {
        std::lock_guard<std::mutex> lk(state().mtx);
        state().scans.clear();
    }
    save_profiles();
}

void register_tools(mcp_standalone::server_t& srv)
{
    initialize();
    using p = mcp_standalone::tool_param_t;
    register_tool(srv,
        "aida.web.scan.orchestrate",
        "Launch a coordinated web vulnerability scan with profile selection, optional crawl, active modules, defensive checks, progress, and cancellation.",
        {
            p{"target_url", "string", "Root URL to scan.", true},
            p{"profile", "string", "quick|full|custom or a saved custom profile id.", false},
            p{"profile_id", "string", "Saved custom profile id when profile is custom.", false},
            p{"module_ids", "array", "Active scanner module ids for custom scans.", false},
            p{"defensive_checks", "array", "security_headers|tls_config|content_analysis|info_disclosure|cookie_audit.", false},
            p{"crawl_first", "boolean", "Crawl before active audit when active modules are enabled.", false},
            p{"crawl_depth", "number", "Crawl depth from 0 to 10.", false},
            p{"max_concurrent_requests", "number", "Request concurrency cap from 1 to 64.", false},
            p{"request_throttle_ms", "number", "Request throttle in milliseconds.", false},
            p{"timeout_ms", "number", "Per-request timeout in milliseconds.", false},
            p{"run_defensive", "boolean", "Run defensive checks.", false},
            p{"scope_only", "boolean", "Constrain scanner and crawler requests to Burp scope.", false},
            p{"session_id", "string", "Optional audit session identifier.", false}
        },
        false,
        tool_orchestrate);
    register_tool(srv,
        "aida.web.scan.profile.list",
        "List built-in and custom scan profiles.",
        {p{"include_modules", "boolean", "Include module ids in the response.", false}},
        true,
        tool_profile_list);
    register_tool(srv,
        "aida.web.scan.profile.save",
        "Save a durable custom scan profile.",
        {
            p{"profile_id", "string", "Custom profile id.", true},
            p{"name", "string", "Display name.", true},
            p{"description", "string", "Profile description.", false},
            p{"module_ids", "array", "Active scanner module ids.", false},
            p{"defensive_checks", "array", "Defensive check ids.", false},
            p{"crawl_depth", "number", "Default crawl depth.", false},
            p{"max_concurrent_requests", "number", "Default concurrency.", false},
            p{"request_throttle_ms", "number", "Default throttle.", false},
            p{"timeout_ms", "number", "Default timeout.", false},
            p{"crawl_first", "boolean", "Default crawl-first behavior.", false},
            p{"run_defensive", "boolean", "Run defensive checks by default.", false}
        },
        false,
        tool_profile_save);
    register_tool(srv,
        "aida.web.scan.status",
        "Return status, progress, issue counts, active module progress, and defensive check state for a scan.",
        {p{"scan_id", "number", "Orchestrator scan id.", true}},
        true,
        tool_status);
    register_tool(srv,
        "aida.web.scan.cancel",
        "Cancel a running scan and preserve partial findings.",
        {p{"scan_id", "number", "Orchestrator scan id.", true}},
        false,
        tool_cancel);
    register_tool(srv,
        "aida.web.scan.findings.deduplicate",
        "Deduplicate findings by type, host, path, and parameter, optionally merging evidence.",
        {
            p{"scan_id", "number", "Optional scan id; omitted means all stored findings.", false},
            p{"merge_evidence", "boolean", "Merge duplicate evidence into the kept finding.", false}
        },
        false,
        tool_deduplicate);
    register_tool(srv,
        "aida.web.scan.findings.correlate",
        "Correlate findings across scans, sessions, hosts, endpoints, and vulnerability classes.",
        {
            p{"session_id", "string", "Optional orchestrator session id.", false},
            p{"scan_id", "number", "Optional scan id.", false},
            p{"min_severity", "string", "info|low|medium|high|critical.", false}
        },
        true,
        tool_correlate);
    register_tool(srv,
        "aida.web.scan.findings.score",
        "Compute CVSS 3.1 scores and OWASP/CWE mappings for one finding or a scan.",
        {
            p{"finding_id", "number", "Optional finding id.", false},
            p{"scan_id", "number", "Optional scan id.", false},
            p{"cvss_vector_override", "string", "Optional CVSS 3.1 base vector.", false}
        },
        true,
        tool_score);
    diag::log_tagged("scan_orchestrator", "scan_orchestrator_tools_registered");
}

}

void register_scan_orchestrator_tools(mcp_standalone::server_t& srv)
{
    scan_orchestrator::register_tools(srv);
}

}
}
