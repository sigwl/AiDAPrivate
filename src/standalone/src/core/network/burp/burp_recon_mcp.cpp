#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_recon_mcp.hpp"

#include "crawler.hpp"
#include "content_discovery.hpp"
#include "subdomain_enum.hpp"
#include "payload_library.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

template <typename T>
T get_or(const json& j, const std::string& key, T def)
{
    if (!j.is_object() || !j.contains(key)) return def;
    try { return j.at(key).get<T>(); } catch (...) { return def; }
}

uint64_t unix_ms_now()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::vector<std::string> get_string_array(const json& j, const std::string& key)
{
    std::vector<std::string> out;
    if (!j.is_object() || !j.contains(key)) return out;
    const json& a = j.at(key);
    if (!a.is_array()) return out;
    for (const auto& e : a) if (e.is_string()) out.push_back(e.get<std::string>());
    return out;
}

std::vector<int> get_int_array(const json& j, const std::string& key)
{
    std::vector<int> out;
    if (!j.is_object() || !j.contains(key)) return out;
    const json& a = j.at(key);
    if (!a.is_array()) return out;
    for (const auto& e : a) if (e.is_number_integer()) out.push_back(e.get<int>());
    return out;
}

json crawler_status_to_json(const crawler::crawl_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case crawler::crawl_status_phase_t::pending: phase = "pending"; break;
        case crawler::crawl_status_phase_t::running: phase = "running"; break;
        case crawler::crawl_status_phase_t::stopping: phase = "stopping"; break;
        case crawler::crawl_status_phase_t::complete: phase = "complete"; break;
        case crawler::crawl_status_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["queue_depth"] = s.queue_depth;
    j["pages_visited"] = s.pages_visited;
    j["pages_failed"] = s.pages_failed;
    j["urls_found"] = s.urls_found;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    j["last_progress_unix_ms"] = s.last_progress_unix_ms;
    const uint64_t now = unix_ms_now();
    j["ms_since_last_progress"] = s.last_progress_unix_ms != 0 && now >= s.last_progress_unix_ms ? now - s.last_progress_unix_ms : 0;
    j["pages_per_sec"] = s.pages_per_sec;
    j["in_flight"] = s.in_flight;
    j["finished"] = s.finished;
    j["cancelled"] = s.cancelled;
    j["last_url"] = s.last_url;
    j["last_error"] = s.last_error;
    return j;
}

json disc_status_to_json(const content_discovery::disc_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case content_discovery::disc_phase_t::pending: phase = "pending"; break;
        case content_discovery::disc_phase_t::calibrating: phase = "calibrating"; break;
        case content_discovery::disc_phase_t::running: phase = "running"; break;
        case content_discovery::disc_phase_t::stopping: phase = "stopping"; break;
        case content_discovery::disc_phase_t::complete: phase = "complete"; break;
        case content_discovery::disc_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["attempts"] = s.attempts;
    j["total"] = s.total;
    j["hits"] = s.hits;
    j["filtered"] = s.filtered;
    j["errors"] = s.errors;
    j["calibrated_size_lo"] = s.calibrated_size_lo;
    j["calibrated_size_hi"] = s.calibrated_size_hi;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    j["finished"] = s.finished;
    j["cancelled"] = s.cancelled;
    j["last_error"] = s.last_error;
    j["last_url"] = s.last_url;
    return j;
}

bool crawler_phase_active(crawler::crawl_status_phase_t phase)
{
    return phase == crawler::crawl_status_phase_t::pending
        || phase == crawler::crawl_status_phase_t::running
        || phase == crawler::crawl_status_phase_t::stopping;
}

bool disc_phase_active(content_discovery::disc_phase_t phase)
{
    return phase == content_discovery::disc_phase_t::pending
        || phase == content_discovery::disc_phase_t::calibrating
        || phase == content_discovery::disc_phase_t::running
        || phase == content_discovery::disc_phase_t::stopping;
}

json crawler_stop_state_to_json(const crawler::crawl_status_t& s)
{
    json j = crawler_status_to_json(s);
    j["running"] = s.id != 0 && crawler_phase_active(s.phase);
    j["target_count"] = s.id != 0 ? s.config.max_pages : 0;
    j["start_url_count"] = s.id != 0 ? static_cast<uint64_t>(s.config.start_urls.size()) : 0;
    j["collected_count"] = s.id != 0 ? s.urls_found : 0;
    j["discovered_count"] = s.id != 0 ? static_cast<uint64_t>(s.discovered.size()) : 0;
    j["fetched_count"] = s.id != 0 ? s.pages_visited : 0;
    return j;
}

json disc_stop_state_to_json(const content_discovery::disc_status_t& s)
{
    json j = disc_status_to_json(s);
    j["running"] = s.id != 0 && disc_phase_active(s.phase);
    j["target_count"] = s.total;
    j["collected_count"] = s.hits;
    j["hit_count"] = static_cast<uint64_t>(s.hits_list.size());
    return j;
}

json crawler_ids_json(const std::vector<crawler::crawl_status_t>& jobs)
{
    json arr = json::array();
    for (const auto& job : jobs) arr.push_back(job.id);
    return arr;
}

json disc_ids_json(const std::vector<content_discovery::disc_status_t>& jobs)
{
    json arr = json::array();
    for (const auto& job : jobs) arr.push_back(job.id);
    return arr;
}

json sub_status_to_json(const subdomain_enum::enum_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case subdomain_enum::enum_phase_t::pending: phase = "pending"; break;
        case subdomain_enum::enum_phase_t::passive: phase = "passive"; break;
        case subdomain_enum::enum_phase_t::brute: phase = "brute"; break;
        case subdomain_enum::enum_phase_t::stopping: phase = "stopping"; break;
        case subdomain_enum::enum_phase_t::complete: phase = "complete"; break;
        case subdomain_enum::enum_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["passive_count"] = s.passive_count;
    j["brute_attempts"] = s.brute_attempts;
    j["brute_resolved"] = s.brute_resolved;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    j["last_error"] = s.last_error;
    j["domain"] = s.config.domain;
    j["results_count"] = static_cast<int>(s.results.size());
    return j;
}

bool sub_status_can_settle(const subdomain_enum::enum_status_t& s)
{
    return s.id != 0 &&
        s.results.empty() &&
        s.phase != subdomain_enum::enum_phase_t::complete &&
        s.phase != subdomain_enum::enum_phase_t::error &&
        s.phase != subdomain_enum::enum_phase_t::stopping;
}

subdomain_enum::enum_status_t settle_subdomain_status(uint64_t id, subdomain_enum::enum_status_t s)
{
    for (int poll = 0; poll < 10 && sub_status_can_settle(s); ++poll) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        auto next = subdomain_enum::status(id);
        if (next.id == 0) break;
        diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status settle id=%llu poll=%d phase=%d prev_results=%zu next_results=%zu prev_resolved=%zu next_resolved=%zu",
            static_cast<unsigned long long>(id),
            poll + 1,
            static_cast<int>(next.phase),
            s.results.size(),
            next.results.size(),
            static_cast<size_t>(std::max(0, s.brute_resolved)),
            static_cast<size_t>(std::max(0, next.brute_resolved)));
        s = std::move(next);
    }
    return s;
}

tool_result_t crawler_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "crawler_start entry start_urls_count=%zu", get_string_array(p, "start_urls").size() + (p.contains("url") && p["url"].is_string() ? 1 : 0));
    crawler::crawl_config_t cfg;
    cfg.start_urls = get_string_array(p, "start_urls");
    if (cfg.start_urls.empty() && p.contains("url") && p["url"].is_string())
        cfg.start_urls.push_back(p["url"].get<std::string>());
    if (cfg.start_urls.empty()) return tool_result_t::error("start_urls required");
    cfg.max_depth         = get_or<int>(p, "max_depth", 3);
    cfg.same_host_only    = get_or<bool>(p, "same_host_only", true);
    cfg.scope_only        = get_or<bool>(p, "scope_only", false);
    cfg.respect_robots_txt = get_or<bool>(p, "respect_robots", true);
    cfg.parse_js          = get_or<bool>(p, "parse_js", true);
    cfg.max_pages         = get_or<int>(p, "max_pages", 500);
    cfg.concurrency       = get_or<int>(p, "concurrency", 8);
    cfg.rate_per_host     = get_or<int>(p, "rate_per_host", 10);
    cfg.user_agent        = get_or<std::string>(p, "user_agent", std::string("AiDA-Crawler/1.0"));
    cfg.exclude_extensions = get_string_array(p, "exclude_extensions");
    cfg.exclude_patterns  = get_string_array(p, "exclude_patterns");
    uint64_t id = crawler::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "crawler_start failed err=%s", crawler::last_error().c_str()); return tool_result_t::error(crawler::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "crawler_start ok crawl_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["crawl_id"] = id;
    return tool_result_t::ok("crawl started id=" + std::to_string(id), r);
}

tool_result_t crawler_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "crawl_id", 0);
    diag::log_tagged_fmt("mcp_burp", "crawler_status crawl_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("crawl_id required");
    auto s = crawler::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "crawler_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    json j = crawler_status_to_json(s);
    json urls = json::array();
    int cap = get_or<int>(p, "max_urls", 200);
    int n = 0;
    for (auto& d : s.discovered)
    {
        if (n++ >= cap) break;
        json e;
        e["url"] = d.url;
        e["status"] = d.status;
        e["body_bytes"] = d.body_bytes;
        e["content_type"] = d.content_type;
        e["depth"] = d.depth;
        urls.push_back(e);
    }
    j["urls"] = urls;
    diag::log_tagged_fmt("mcp_burp", "crawler_status ok id=%llu urls=%d queue_depth=%d in_flight=%d pages_per_sec=%.3f last_progress_unix_ms=%llu last_error=%s",
        static_cast<unsigned long long>(id),
        n,
        s.queue_depth,
        s.in_flight,
        s.pages_per_sec,
        static_cast<unsigned long long>(s.last_progress_unix_ms),
        s.last_error.c_str());
    return tool_result_t::ok("crawler status id=" + std::to_string(id) + " urls=" + std::to_string(urls.size()), j);
}

tool_result_t crawler_stop_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "crawl_id", 0);
    diag::log_tagged_fmt("mcp_burp", "crawler_stop crawl_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("crawl_id required");
    auto before = crawler::status(id);
    auto before_list = crawler::list();
    if (!crawler::stop(id)) { diag::log_tagged_fmt("mcp_burp", "crawler_stop failed err=%s", crawler::last_error().c_str()); return tool_result_t::error(crawler::last_error()); }
    auto after = crawler::status(id);
    auto after_list = crawler::list();
    json out;
    out["id"] = id;
    out["crawl_id"] = id;
    out["stop_requested"] = true;
    out["stopped"] = after.id != 0 && !crawler_phase_active(after.phase);
    out["before_running"] = before.id != 0 && crawler_phase_active(before.phase);
    out["after_running"] = after.id != 0 && crawler_phase_active(after.phase);
    out["target_count_before"] = before.id != 0 ? before.config.max_pages : 0;
    out["target_count_after"] = after.id != 0 ? after.config.max_pages : 0;
    out["collected_count_before"] = before.id != 0 ? before.urls_found : 0;
    out["collected_count_after"] = after.id != 0 ? after.urls_found : 0;
    out["queue_depth_before"] = before.id != 0 ? before.queue_depth : 0;
    out["queue_depth_after"] = after.id != 0 ? after.queue_depth : 0;
    out["before_job_count"] = static_cast<uint64_t>(before_list.size());
    out["remaining_job_count"] = static_cast<uint64_t>(after_list.size());
    out["remaining_ids"] = crawler_ids_json(after_list);
    out["before"] = crawler_stop_state_to_json(before);
    out["after"] = crawler_stop_state_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "crawler_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("stop requested", out);
}

tool_result_t crawler_list_(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "crawler_list entry");
    auto v = crawler::list();
    json arr = json::array();
    for (auto& s : v) arr.push_back(crawler_status_to_json(s));
    json out;
    out["crawls"] = arr;
    int total_queue_depth = 0;
    int total_in_flight = 0;
    double total_pages_per_sec = 0.0;
    uint64_t newest_progress = 0;
    std::string last_error;
    for (const auto& s : v) {
        total_queue_depth += s.queue_depth;
        total_in_flight += s.in_flight;
        total_pages_per_sec += s.pages_per_sec;
        if (s.last_progress_unix_ms > newest_progress) newest_progress = s.last_progress_unix_ms;
        if (!s.last_error.empty()) last_error = s.last_error;
    }
    out["queue_depth"] = total_queue_depth;
    out["in_flight"] = total_in_flight;
    out["pages_per_sec"] = total_pages_per_sec;
    out["last_progress_unix_ms"] = newest_progress;
    out["last_error"] = last_error;
    diag::log_tagged_fmt("mcp_burp", "crawler_list ok count=%zu queue_depth=%d in_flight=%d pages_per_sec=%.3f last_progress_unix_ms=%llu last_error=%s",
        v.size(),
        total_queue_depth,
        total_in_flight,
        total_pages_per_sec,
        static_cast<unsigned long long>(newest_progress),
        last_error.c_str());
    return tool_result_t::ok("crawler list count=" + std::to_string(v.size()), out);
}

tool_result_t cd_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "content_discovery_start target=%s", get_or<std::string>(p, "target_url", std::string()).c_str());
    content_discovery::config_t cfg;
    cfg.target_url        = get_or<std::string>(p, "target_url", std::string());
    if (cfg.target_url.empty()) return tool_result_t::error("target_url required");
    cfg.wordlist_id       = get_or<std::string>(p, "wordlist_id", std::string());
    cfg.wordlist_file     = get_or<std::string>(p, "wordlist_file", std::string());
    if (cfg.wordlist_id.empty() && cfg.wordlist_file.empty()) {
        cfg.wordlist_id = "dirs/common-100";
        diag::log_tagged_fmt("mcp_burp", "content_discovery_start default_wordlist id=%s", cfg.wordlist_id.c_str());
    }
    cfg.extensions        = get_string_array(p, "extensions");
    cfg.concurrency       = get_or<int>(p, "concurrency", 25);
    cfg.delay_ms          = get_or<int>(p, "delay_ms", 0);
    cfg.request_timeout_ms = get_or<int>(p, "request_timeout_ms", 8000);
    cfg.match_status      = get_int_array(p, "match_status");
    cfg.filter_status     = get_int_array(p, "filter_status");
    cfg.filter_size_min   = get_or<size_t>(p, "filter_size_min", static_cast<size_t>(0));
    cfg.filter_size_max   = get_or<size_t>(p, "filter_size_max", static_cast<size_t>(0));
    cfg.filter_words_regex = get_or<std::string>(p, "filter_words_regex", std::string());
    cfg.recurse           = get_or<bool>(p, "recurse", false);
    cfg.recurse_depth     = get_or<int>(p, "recurse_depth", 1);
    cfg.method            = get_or<std::string>(p, "method", std::string("GET"));
    cfg.cookie_header     = get_or<std::string>(p, "cookie", std::string());
    cfg.user_agent        = get_or<std::string>(p, "user_agent", std::string("AiDA-ContentDiscovery/1.0"));
    cfg.follow_redirects  = get_or<bool>(p, "follow_redirects", false);
    cfg.auto_calibrate    = get_or<bool>(p, "auto_calibrate", true);

    if (p.contains("extra_headers") && p["extra_headers"].is_object())
    {
        for (auto it = p["extra_headers"].begin(); it != p["extra_headers"].end(); ++it)
            if (it.value().is_string()) cfg.extra_headers.emplace_back(it.key(), it.value().get<std::string>());
    }
    uint64_t id = content_discovery::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "content_discovery_start failed err=%s", content_discovery::last_error().c_str()); return tool_result_t::error(content_discovery::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "content_discovery_start ok disc_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["disc_id"] = id;
    return tool_result_t::ok("discovery started id=" + std::to_string(id), r);
}

tool_result_t cd_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_status disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    auto s = content_discovery::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "content_discovery_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    diag::log_tagged_fmt("mcp_burp", "content_discovery_status ok id=%llu hits=%zu", static_cast<unsigned long long>(id), s.hits);
    return tool_result_t::ok("discovery status id=" + std::to_string(id) + " hits=" + std::to_string(s.hits) + " attempts=" + std::to_string(s.attempts), disc_status_to_json(s));
}

tool_result_t cd_results_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_results disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    int cap = get_or<int>(p, "max_results", 500);
    auto hits = content_discovery::results(id);
    json arr = json::array();
    int n = 0;
    for (auto& h : hits)
    {
        if (n++ >= cap) break;
        json e;
        e["url"] = h.url;
        e["payload"] = h.payload;
        e["status"] = h.status;
        e["body_bytes"] = h.body_bytes;
        e["latency_ms"] = h.latency_ms;
        e["content_type"] = h.content_type;
        e["redirect_to"] = h.redirect_to;
        e["depth"] = h.depth;
        arr.push_back(e);
    }
    json out;
    out["hits"] = arr;
    out["total"] = static_cast<int>(hits.size());
    out["returned"] = n;
    diag::log_tagged_fmt("mcp_burp", "content_discovery_results ok id=%llu returned=%d", static_cast<unsigned long long>(id), n);
    return tool_result_t::ok("discovery results returned=" + std::to_string(n) + " total=" + std::to_string(hits.size()), out);
}

tool_result_t cd_stop_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_stop disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    auto before = content_discovery::status(id);
    auto before_list = content_discovery::list();
    if (!content_discovery::stop(id)) { diag::log_tagged_fmt("mcp_burp", "content_discovery_stop failed err=%s", content_discovery::last_error().c_str()); return tool_result_t::error(content_discovery::last_error()); }
    auto after = content_discovery::status(id);
    auto after_list = content_discovery::list();
    json out;
    out["id"] = id;
    out["disc_id"] = id;
    out["stop_requested"] = true;
    out["stopped"] = after.id != 0 && !disc_phase_active(after.phase);
    out["before_running"] = before.id != 0 && disc_phase_active(before.phase);
    out["after_running"] = after.id != 0 && disc_phase_active(after.phase);
    out["target_count_before"] = before.id != 0 ? before.total : 0;
    out["target_count_after"] = after.id != 0 ? after.total : 0;
    out["collected_count_before"] = before.id != 0 ? before.hits : 0;
    out["collected_count_after"] = after.id != 0 ? after.hits : 0;
    out["attempt_count_before"] = before.id != 0 ? before.attempts : 0;
    out["attempt_count_after"] = after.id != 0 ? after.attempts : 0;
    out["before_job_count"] = static_cast<uint64_t>(before_list.size());
    out["remaining_job_count"] = static_cast<uint64_t>(after_list.size());
    out["remaining_ids"] = disc_ids_json(after_list);
    out["before"] = disc_stop_state_to_json(before);
    out["after"] = disc_stop_state_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("stop requested", out);
}

tool_result_t sub_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start domain=%s", get_or<std::string>(p, "domain", std::string()).c_str());
    subdomain_enum::config_t cfg;
    cfg.domain                = get_or<std::string>(p, "domain", std::string());
    if (cfg.domain.empty()) return tool_result_t::error("domain required");
    cfg.brute_wordlist_id     = get_or<std::string>(p, "brute_wordlist_id", std::string("subdomains/top1000"));
    cfg.brute_wordlist_file   = get_or<std::string>(p, "brute_wordlist_file", std::string());
    cfg.resolver_concurrency  = get_or<int>(p, "concurrency", 32);
    cfg.request_timeout_ms    = get_or<int>(p, "request_timeout_ms", 6000);
    cfg.run_passive           = get_or<bool>(p, "run_passive", true);
    cfg.run_brute             = get_or<bool>(p, "run_brute", true);
    cfg.bypass_dns_cache      = get_or<bool>(p, "bypass_dns_cache", true);
    cfg.user_agent            = get_or<std::string>(p, "user_agent", std::string("AiDA-SubdomainEnum/1.0"));
    cfg.passive_sources       = get_string_array(p, "sources");
    uint64_t id = subdomain_enum::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start failed err=%s", subdomain_enum::last_error().c_str()); return tool_result_t::error(subdomain_enum::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start ok sub_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["sub_id"] = id;
    return tool_result_t::ok("enum started id=" + std::to_string(id), r);
}

tool_result_t sub_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "sub_id", 0);
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status sub_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("sub_id required");
    auto s = subdomain_enum::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    s = settle_subdomain_status(id, std::move(s));
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status ok id=%llu passive=%zu brute_resolved=%zu", static_cast<unsigned long long>(id), static_cast<size_t>(std::max(0, s.passive_count)), static_cast<size_t>(std::max(0, s.brute_resolved)));
    return tool_result_t::ok("subdomain status id=" + std::to_string(id) + " results=" + std::to_string(s.results.size()) + " resolved=" + std::to_string(s.brute_resolved), sub_status_to_json(s));
}

tool_result_t sub_results_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "sub_id", 0);
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_results sub_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("sub_id required");
    int cap = get_or<int>(p, "max_results", 1000);
    auto v = subdomain_enum::results(id);
    json arr = json::array();
    int n = 0;
    for (auto& s : v)
    {
        if (n++ >= cap) break;
        json e;
        e["fqdn"] = s.fqdn;
        e["resolves"] = s.resolves;
        e["ips"] = s.ips;
        e["sources"] = s.sources;
        arr.push_back(e);
    }
    json out;
    out["subdomains"] = arr;
    out["total"] = static_cast<int>(v.size());
    out["returned"] = n;
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_results ok id=%llu returned=%d", static_cast<unsigned long long>(id), n);
    return tool_result_t::ok("subdomain results returned=" + std::to_string(n) + " total=" + std::to_string(v.size()), out);
}

tool_result_t payloads_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "payloads_list entry");
    auto v = payloads::list_summaries();
    json arr = json::array();
    for (auto& p : v)
    {
        const auto* full = payloads::get(p.id);
        size_t cnt = full ? full->entries.size() : 0;
        json e;
        e["id"] = p.id;
        e["label"] = p.label;
        e["description"] = p.description;
        e["builtin"] = p.builtin;
        e["entry_count"] = cnt;
        arr.push_back(e);
    }
    json out;
    out["sets"] = arr;
    diag::log_tagged_fmt("mcp_burp", "payloads_list ok count=%zu", v.size());
    return tool_result_t::ok("payload sets count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_get_(const json& p)
{
    std::string id = get_or<std::string>(p, "set_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_get set_id=%s", id.c_str());
    if (id.empty()) return tool_result_t::error("set_id required");
    int cap = get_or<int>(p, "max", 500);
    auto v = payloads::entries(id, static_cast<size_t>(std::max(0, cap)));
    const auto* full = payloads::get(id);
    if (!full) { diag::log_tagged_fmt("mcp_burp", "payloads_get not_found set_id=%s", id.c_str()); return tool_result_t::error("not found"); }
    json out;
    out["id"] = id;
    out["total"] = static_cast<int>(full->entries.size());
    out["returned"] = static_cast<int>(v.size());
    out["entries"] = v;
    diag::log_tagged_fmt("mcp_burp", "payloads_get ok set_id=%s returned=%zu", id.c_str(), v.size());
    return tool_result_t::ok("payload entries count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_search_(const json& p)
{
    std::string q = get_or<std::string>(p, "query", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_search query=%s", q.c_str());
    if (q.empty()) return tool_result_t::error("query required");
    std::string set_id = get_or<std::string>(p, "set_id", std::string());
    int cap = get_or<int>(p, "max", 200);
    auto v = payloads::search(q, set_id);
    if (cap > 0 && static_cast<int>(v.size()) > cap) v.resize(cap);
    json out;
    out["matches"] = v;
    out["returned"] = static_cast<int>(v.size());
    diag::log_tagged_fmt("mcp_burp", "payloads_search ok query=%s returned=%zu", q.c_str(), v.size());
    return tool_result_t::ok("payload search results count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_add_(const json& p)
{
    std::string id = get_or<std::string>(p, "set_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_add_custom set_id=%s", id.c_str());
    if (id.empty()) return tool_result_t::error("set_id required");
    std::string label = get_or<std::string>(p, "label", std::string());
    std::string desc  = get_or<std::string>(p, "description", std::string());
    auto entries = get_string_array(p, "entries");
    if (entries.empty()) return tool_result_t::error("entries required");
    if (!payloads::add_custom_set(id, label, desc, entries)) { diag::log_tagged_fmt("mcp_burp", "payloads_add_custom failed err=%s", payloads::last_error().c_str()); return tool_result_t::error(payloads::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "payloads_add_custom ok set_id=%s count=%zu", id.c_str(), entries.size());
    json out;
    out["set_id"] = id;
    out["count"] = static_cast<int>(entries.size());
    return tool_result_t::ok("custom set added", out);
}

}

void register_recon_tools(mcp_standalone::server_t& srv)
{
    crawler::initialize();
    content_discovery::initialize();
    subdomain_enum::initialize();
    payloads::initialize();

    register_compat(srv, {
        "burp_crawler_manage", "burp",
        "Manage recursive crawl jobs. Actions: start, status, stop, list.",
        {{"action", "string", "start|status|stop|list", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return crawler_start(p);
            if (action == "status") return crawler_status_(p);
            if (action == "stop") return crawler_stop_(p);
            if (action == "list") return crawler_list_(p);
            return compat_unknown_action("burp_crawler_manage", action);
        },
        false
    });

    register_compat(srv, {
        "burp_content_discovery_manage", "burp",
        "Manage directory and file discovery jobs. Actions: start, status, results, stop.",
        {{"action", "string", "start|status|results|stop", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return cd_start(p);
            if (action == "status") return cd_status_(p);
            if (action == "results") return cd_results_(p);
            if (action == "stop") return cd_stop_(p);
            return compat_unknown_action("burp_content_discovery_manage", action);
        },
        false
    });

    register_compat(srv, {
        "burp_subdomain_enum_manage", "burp",
        "Manage passive and brute-force subdomain enumeration jobs. Actions: start, status, results.",
        {{"action", "string", "start|status|results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return sub_start(p);
            if (action == "status") return sub_status_(p);
            if (action == "results") return sub_results_(p);
            return compat_unknown_action("burp_subdomain_enum_manage", action);
        },
        false
    });

    register_compat(srv, {
        "burp_payloads_list", "burp",
        "List available payload sets (id, label, entry count).",
        {},
        payloads_list, true
    });

    register_compat(srv, {
        "burp_payloads_get", "burp",
        "Return entries from a payload set (capped).",
        {
            {"set_id", "string", "Payload set id (e.g. xss/polyglot).", true},
            {"max", "number", "Max entries returned (default 500).", false},
        },
        payloads_get_, true
    });

    register_compat(srv, {
        "burp_payloads_search", "burp",
        "Substring search across payload sets.",
        {
            {"query", "string", "Substring to search for.", true},
            {"set_id", "string", "Restrict to one set (optional).", false},
            {"max", "number", "Cap returned matches (default 200).", false},
        },
        payloads_search_, true
    });

    register_compat(srv, {
        "burp_payloads_add_custom", "burp",
        "Create or replace a custom payload set (persisted to %APPDATA%/AiDA/Standalone/burp/payloads/).",
        {
            {"set_id", "string", "Set id (must not collide with a builtin).", true},
            {"label", "string", "Friendly label.", false},
            {"description", "string", "Description.", false},
            {"entries", "array", "Array of payload strings.", true},
        },
        payloads_add_, false
    });
}

}
}
