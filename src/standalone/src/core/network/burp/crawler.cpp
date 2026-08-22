#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "crawler.hpp"
#include "audit_http.hpp"
#include "scope.hpp"
#include "burp_events.hpp"
#include "site_map.hpp"

#include "helpers/diag_log.hpp"
#include "../../infra/event_bus.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../infra/executor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida {
namespace burp {
namespace crawler {

namespace {

struct queue_item_t
{
    std::string url;
    int         depth = 0;
    std::string parent;
};

struct host_rate_t
{
    std::mutex                            mtx;
    std::deque<std::chrono::steady_clock::time_point> stamps;
    std::vector<std::string>              robots_disallow;
    bool                                  robots_fetched = false;
};

struct crawl_t
{
    uint64_t                            id = 0;
    crawl_config_t                      config;
    std::mutex                          mtx;
    std::atomic<bool>                   stop_flag{false};
    std::atomic<bool>                   finished{false};
    crawl_status_phase_t                phase = crawl_status_phase_t::pending;
    std::deque<queue_item_t>            queue;
    std::unordered_set<std::string>     seen;
    std::vector<discovered_url_t>       discovered;
    std::vector<std::string>            log;
    std::unordered_map<std::string, std::shared_ptr<host_rate_t>> host_rates;
    int                                 pages_visited = 0;
    int                                 pages_failed = 0;
    std::string                         last_url;
    std::string                         last_error;
    uint64_t                            started_unix_ms = 0;
    uint64_t                            finished_unix_ms = 0;
    uint64_t                            last_progress_unix_ms = 0;
    std::atomic<int>                    in_flight{0};
    std::atomic<uint64_t>               next_request_seq{1};
};

struct registry_t
{
    std::mutex                                            mtx;
    std::unordered_map<uint64_t, std::shared_ptr<crawl_t>> by_id;
    std::atomic<uint64_t>                                 next_id{1};
    std::atomic<bool>                                     init_done{false};
    std::mutex                                            err_mtx;
    std::string                                           last_err;
};

registry_t& reg() { static registry_t r; return r; }

void set_err(const std::string& m)
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.err_mtx);
    r.last_err = m;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string to_lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

struct parsed_url_t
{
    std::string scheme;
    std::string host;
    uint16_t    port = 0;
    std::string path;
    std::string query;
    std::string fragment;
    bool        valid = false;
};

parsed_url_t parse_url(const std::string& url)
{
    parsed_url_t p;
    std::string work = url;
    auto colon = work.find("://");
    if (colon == std::string::npos) return p;
    p.scheme = to_lower(work.substr(0, colon));
    work = work.substr(colon + 3);
    auto frag = work.find('#');
    if (frag != std::string::npos)
    {
        p.fragment = work.substr(frag + 1);
        work = work.substr(0, frag);
    }
    auto q = work.find('?');
    if (q != std::string::npos)
    {
        p.query = work.substr(q + 1);
        work = work.substr(0, q);
    }
    auto slash = work.find('/');
    std::string host_part;
    if (slash != std::string::npos)
    {
        host_part = work.substr(0, slash);
        p.path = work.substr(slash);
    }
    else
    {
        host_part = work;
        p.path = "/";
    }
    auto pcolon = host_part.find(':');
    if (pcolon != std::string::npos)
    {
        try
        {
            p.port = static_cast<uint16_t>(std::stoi(host_part.substr(pcolon + 1)));
            host_part = host_part.substr(0, pcolon);
        }
        catch (...)
        {
            return p;
        }
    }
    else
    {
        p.port = (p.scheme == "https") ? 443 : 80;
    }
    p.host = to_lower(host_part);
    if (p.scheme != "http" && p.scheme != "https") return p;
    if (p.host.empty()) return p;
    p.valid = true;
    return p;
}

std::string canonicalize(const parsed_url_t& p)
{
    if (!p.valid) return std::string();
    std::ostringstream os;
    os << p.scheme << "://" << p.host;
    const uint16_t default_port = (p.scheme == "https") ? 443 : 80;
    if (p.port != default_port) os << ':' << p.port;
    os << (p.path.empty() ? std::string("/") : p.path);
    if (!p.query.empty()) os << '?' << p.query;
    return os.str();
}

std::string resolve_relative(const std::string& base_url, const std::string& href)
{
    if (href.empty()) return std::string();
    if (href.find("://") != std::string::npos) return href;
    if (href[0] == '#') return std::string();
    if (href.rfind("javascript:", 0) == 0) return std::string();
    if (href.rfind("mailto:", 0) == 0) return std::string();
    if (href.rfind("tel:", 0) == 0) return std::string();
    if (href.rfind("data:", 0) == 0) return std::string();

    parsed_url_t b = parse_url(base_url);
    if (!b.valid) return std::string();

    if (href.rfind("//", 0) == 0)
    {
        return b.scheme + ":" + href;
    }
    if (!href.empty() && href[0] == '/')
    {
        std::ostringstream os;
        os << b.scheme << "://" << b.host;
        const uint16_t default_port = (b.scheme == "https") ? 443 : 80;
        if (b.port != default_port) os << ':' << b.port;
        os << href;
        return os.str();
    }

    std::string base_dir = b.path;
    auto last_slash = base_dir.find_last_of('/');
    if (last_slash != std::string::npos) base_dir = base_dir.substr(0, last_slash + 1);
    else base_dir = "/";

    std::string combined = base_dir + href;

    std::vector<std::string> segments;
    std::string cur;
    for (char c : combined)
    {
        if (c == '/') { if (!cur.empty()) { segments.push_back(cur); cur.clear(); } segments.push_back("/"); }
        else cur.push_back(c);
    }
    if (!cur.empty()) segments.push_back(cur);

    std::vector<std::string> resolved;
    for (auto& s : segments)
    {
        if (s == "/") { if (resolved.empty() || resolved.back() != "/") resolved.push_back("/"); }
        else if (s == ".") { }
        else if (s == "..")
        {
            if (!resolved.empty()) { resolved.pop_back(); if (!resolved.empty() && resolved.back() == "/") resolved.pop_back(); }
        }
        else { resolved.push_back(s); }
    }

    std::string final_path;
    for (auto& s : resolved) final_path += s;
    if (final_path.empty()) final_path = "/";

    std::ostringstream os;
    os << b.scheme << "://" << b.host;
    const uint16_t default_port = (b.scheme == "https") ? 443 : 80;
    if (b.port != default_port) os << ':' << b.port;
    os << final_path;
    return os.str();
}

bool extract_html_links(const std::string& base_url, const std::string& body, std::vector<std::string>& out)
{
    static const std::regex href_re(R"((?:href|src|action|data-src|data-url)\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>'\"]+)))", std::regex::icase);
    auto begin = std::sregex_iterator(body.begin(), body.end(), href_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
    {
        std::string match;
        if (!(*it)[1].str().empty()) match = (*it)[1].str();
        else if (!(*it)[2].str().empty()) match = (*it)[2].str();
        else if (!(*it)[3].str().empty()) match = (*it)[3].str();
        if (match.empty()) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }

    static const std::regex meta_re(R"(<meta[^>]+http-equiv\s*=\s*[\"']refresh[\"'][^>]+content\s*=\s*[\"'][^\"']*url\s*=\s*([^\"']+)[\"'])", std::regex::icase);
    auto m_begin = std::sregex_iterator(body.begin(), body.end(), meta_re);
    for (auto it = m_begin; it != end; ++it)
    {
        std::string match = (*it)[1].str();
        if (match.empty()) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }
    return true;
}

bool extract_js_urls(const std::string& base_url, const std::string& body, std::vector<std::string>& out)
{
    static const std::regex js_re(R"([\"']((?:https?:\/\/[^\"'<>\s]+)|(?:\/[a-zA-Z0-9_\-\./%\?=&]+))[\"'])");
    auto begin = std::sregex_iterator(body.begin(), body.end(), js_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
    {
        std::string match = (*it)[1].str();
        if (match.empty()) continue;
        if (match.size() < 2) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }
    return true;
}

bool parse_robots_txt(const std::string& body, std::vector<std::string>& disallows)
{
    std::istringstream iss(body);
    std::string line;
    bool current_applies = false;
    while (std::getline(iss, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = to_lower(line.substr(0, pos));
        std::string val = line.substr(pos + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.pop_back();
        if (key == "user-agent")
        {
            current_applies = (val == "*");
        }
        else if (key == "disallow" && current_applies)
        {
            if (!val.empty()) disallows.push_back(val);
        }
    }
    return true;
}

bool path_disallowed(const std::vector<std::string>& disallows, const std::string& path)
{
    for (const auto& d : disallows)
    {
        if (path.rfind(d, 0) == 0) return true;
    }
    return false;
}

std::string header_safe(std::string s)
{
    for (char& c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F)
            c = '_';
    }
    return s;
}

bool fetch_url(const std::string& url, const std::string& user_agent, int timeout_ms,
               int& out_status, std::string& out_body, std::string& out_content_type,
               std::vector<std::pair<std::string,std::string>>& out_resp_headers,
               uint64_t& out_latency_ms,
               std::string& out_err)
{
    out_status = 0;
    out_body.clear();
    out_content_type.clear();
    out_resp_headers.clear();
    out_latency_ms = 0;

    parsed_url_t p = parse_url(url);
    if (!p.valid) { out_err = "invalid url"; return false; }

    std::string path_with_query = p.path;
    if (!p.query.empty()) path_with_query += "?" + p.query;

    std::string host_header = p.host;
    if ((p.scheme == "https" && p.port != 443) || (p.scheme != "https" && p.port != 80)) {
        host_header += ":";
        host_header += std::to_string(p.port);
    }

    std::string req;
    req.reserve(256 + path_with_query.size() + user_agent.size() + host_header.size());
    req += "GET ";
    req += path_with_query.empty() ? "/" : path_with_query;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(host_header);
    req += "\r\nUser-Agent: ";
    req += header_safe(user_agent);
    req += "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
    std::vector<uint8_t> raw(req.begin(), req.end());

    auto t0 = std::chrono::steady_clock::now();
    audit_http::send_options_t opt;
    opt.timeout_ms = timeout_ms;
    opt.follow_redirects = false;
    opt.return_first_redirect = true;
    opt.enforce_scope = false;
    opt.publish_exchange = true;
    opt.exchange_source = "crawler";
    auto res = audit_http::send(raw, p.host, p.port, p.scheme == "https", opt);
    auto t1 = std::chrono::steady_clock::now();
    out_latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    if (!res)
    {
        out_err = "transport error; audit_http=" + audit_http::last_error();
        diag::log_tagged_fmt("crawler", "fetch_url transport_failed url=%s host=%s port=%u tls=%d req_len=%zu err=%s",
            url.c_str(), p.host.c_str(), static_cast<unsigned>(p.port), p.scheme == "https" ? 1 : 0, raw.size(), out_err.c_str());
        return false;
    }
    out_status = res->status_code;
    out_body.assign(reinterpret_cast<const char*>(res->resp_body.data()), res->resp_body.size());
    out_resp_headers = res->resp_headers;
    out_latency_ms = res->latency_ms;
    for (auto& h : out_resp_headers)
    {
        if (to_lower(h.first) == "content-type") out_content_type = h.second;
    }
    diag::log_tagged_fmt("crawler", "fetch_url audit_http_ok url=%s status=%d body=%zu headers=%zu latency_ms=%llu tls_version=%s alpn=%s source=%s",
        url.c_str(), out_status, out_body.size(), out_resp_headers.size(), static_cast<unsigned long long>(out_latency_ms),
        res->tls_version.c_str(), res->alpn.c_str(), res->source.c_str());
    return true;
}

bool host_rate_acquire(host_rate_t& hr, int rate_per_host, std::atomic<bool>& stop_flag)
{
    while (!stop_flag.load())
    {
        auto now = std::chrono::steady_clock::now();
        std::unique_lock<std::mutex> lk(hr.mtx);
        while (!hr.stamps.empty() && (now - hr.stamps.front()) > std::chrono::seconds(1))
            hr.stamps.pop_front();
        if (static_cast<int>(hr.stamps.size()) < rate_per_host)
        {
            hr.stamps.push_back(now);
            return true;
        }
        lk.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void log_line(crawl_t& c, const std::string& line)
{
    std::lock_guard<std::mutex> lk(c.mtx);
    if (c.log.size() >= 4000) c.log.erase(c.log.begin(), c.log.begin() + 1000);
    c.log.push_back(line);
}

bool should_skip_extension(const std::string& path, const std::vector<std::string>& exts)
{
    if (exts.empty()) return false;
    std::string lower = to_lower(path);
    for (auto& e : exts)
    {
        std::string el = to_lower(e);
        if (lower.size() >= el.size() && lower.compare(lower.size() - el.size(), el.size(), el) == 0)
            return true;
    }
    return false;
}

bool matches_any_pattern(const std::string& url, const std::vector<std::string>& patterns)
{
    for (const auto& p : patterns)
    {
        if (p.empty()) continue;
        try { std::regex r(p); if (std::regex_search(url, r)) return true; } catch (...) {}
    }
    return false;
}

using admission_ptr_t = std::shared_ptr<mcp_standalone::downstream::scoped_admission_t>;

bool run_crawl(std::shared_ptr<crawl_t> ctx, admission_ptr_t admission);

bool terminalize(const std::shared_ptr<crawl_t>& ctx, crawl_status_phase_t phase,
                 const std::string& reason, bool cancelled)
{
    if (!ctx) return false;
    const uint64_t finished_ms = now_ms();
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->finished.load(std::memory_order_acquire)) return false;
        ctx->stop_flag.store(cancelled || phase == crawl_status_phase_t::error, std::memory_order_release);
        ctx->queue.clear();
        ctx->phase = phase;
        if (!reason.empty()) ctx->last_error = reason;
        ctx->finished_unix_ms = finished_ms;
        ctx->last_progress_unix_ms = finished_ms;
        ctx->finished.store(true, std::memory_order_release);
    }
    aida::events::publish(kJobStateChangedEvent, job_state_changed_t{
        "crawler", ctx->id,
        phase == crawl_status_phase_t::error ? "error" : "complete",
        reason, finished_ms, cancelled, true});
    diag::log_tagged_fmt("burp.crawler", "crawl_terminalized id=%llu phase=%d cancelled=%d reason=%s queued=0 in_flight=%d",
        static_cast<unsigned long long>(ctx->id), static_cast<int>(phase), cancelled ? 1 : 0,
        reason.empty() ? "<none>" : reason.c_str(), ctx->in_flight.load(std::memory_order_acquire));
    return true;
}

bool schedule_crawl(std::shared_ptr<crawl_t> ctx, admission_ptr_t admission,
                    const char* phase, std::chrono::milliseconds delay)
{
    const uint64_t token = admission->token();
    diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-TRANSFER id=%llu token=%llu phase=%s",
        static_cast<unsigned long long>(ctx->id), static_cast<unsigned long long>(token), phase);
    ::aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "burp.crawler";
    sub.label = delay.count() > 0 ? "crawler.wait" : "crawler.run_crawl";
    sub.thread_class = "bounded_task";
    sub.domain = aida::infra::executor::domain_t::feature_worker;
    sub.priority = 3;
    sub.body = [ctx, admission, token, phase, delay]() {
        if (delay.count() > 0)
            std::this_thread::sleep_for(delay);
        const bool transferred = run_crawl(ctx, admission);
        if (!transferred) {
            diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed phase=%s",
                static_cast<unsigned long long>(ctx->id), static_cast<unsigned long long>(token), phase);
            admission->release("completed");
        }
    };
    if (::aida::infra::executor::submit(std::move(sub)).submitted)
        return true;
    diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=executor_unavailable phase=%s",
        static_cast<unsigned long long>(ctx->id), static_cast<unsigned long long>(token), phase);
    const bool cancelled = ctx->stop_flag.load(std::memory_order_acquire);
    terminalize(ctx, cancelled ? crawl_status_phase_t::complete : crawl_status_phase_t::error,
        std::string(phase) + " executor submission rejected", cancelled);
    return false;
}

void enqueue_url(crawl_t& c, const std::string& url, int depth, const std::string& parent)
{
    if (c.finished.load(std::memory_order_acquire)) return;
    if (static_cast<int>(c.discovered.size()) >= c.config.max_pages) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu max_pages_reached url=%s", static_cast<unsigned long long>(c.id), url.c_str());
        return;
    }
    parsed_url_t p = parse_url(url);
    if (!p.valid) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu invalid_url=%s", static_cast<unsigned long long>(c.id), url.c_str());
        return;
    }
    std::string canonical = canonicalize(p);
    if (canonical.empty()) return;
    if (c.seen.find(canonical) != c.seen.end()) return;
    if (c.config.same_host_only && !c.config.start_urls.empty())
    {
        bool host_ok = false;
        for (const auto& s : c.config.start_urls)
        {
            parsed_url_t sp = parse_url(s);
            if (sp.valid && sp.host == p.host) { host_ok = true; break; }
        }
        if (!host_ok) {
            diag::log_tagged_fmt("crawler", "enqueue_url id=%llu same_host_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
            return;
        }
    }
    if (c.config.scope_only)
    {
        if (!aida::burp::scope::in_scope_components(p.scheme, p.host, p.port, p.path)) {
            diag::log_tagged_fmt("crawler", "enqueue_url id=%llu scope_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
            return;
        }
    }
    if (should_skip_extension(p.path, c.config.exclude_extensions)) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu ext_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
        return;
    }
    if (matches_any_pattern(canonical, c.config.exclude_patterns)) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu pattern_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
        return;
    }

    c.seen.insert(canonical);
    queue_item_t q;
    q.url = canonical;
    q.depth = depth;
    q.parent = parent;
    c.queue.push_back(std::move(q));
    c.last_progress_unix_ms = now_ms();
    diag::log_tagged_fmt("crawler", "enqueue_url id=%llu queued url=%s depth=%d queue_size=%zu",
        static_cast<unsigned long long>(c.id), canonical.c_str(), depth, c.queue.size());
}

bool worker_step(std::shared_ptr<crawl_t> ctx, queue_item_t item, admission_ptr_t admission)
{
    diag::log_tagged_fmt("crawler", "worker_step id=%llu url=%s depth=%d",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), item.depth);
    auto& c = *ctx;
    if (c.stop_flag.load()) {
        diag::log_tagged_fmt("crawler", "worker_step id=%llu stopped url=%s", static_cast<unsigned long long>(ctx->id), item.url.c_str());
        ctx->in_flight.fetch_sub(1);
        return schedule_crawl(ctx, std::move(admission), "continuation", std::chrono::milliseconds(0));
    }

    parsed_url_t p = parse_url(item.url);
    if (!p.valid) {
        ctx->in_flight.fetch_sub(1);
        return schedule_crawl(ctx, std::move(admission), "continuation", std::chrono::milliseconds(0));
    }

    std::shared_ptr<host_rate_t> hr;
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        auto it = c.host_rates.find(p.host);
        if (it == c.host_rates.end())
        {
            hr = std::make_shared<host_rate_t>();
            c.host_rates[p.host] = hr;
        }
        else hr = it->second;
    }

    if (c.config.respect_robots_txt)
    {
        bool need_fetch_robots = false;
        {
            std::lock_guard<std::mutex> lk(hr->mtx);
            if (!hr->robots_fetched) need_fetch_robots = true;
        }
        if (need_fetch_robots)
        {
            std::string robots_url = p.scheme + "://" + p.host + ":" + std::to_string(p.port) + "/robots.txt";
            int rs = 0;
            std::string rbody, rct, rerr;
            std::vector<std::pair<std::string,std::string>> rhdr;
            uint64_t rlat = 0;
            fetch_url(robots_url, c.config.user_agent, c.config.request_timeout_ms, rs, rbody, rct, rhdr, rlat, rerr);
            std::vector<std::string> disallows;
            if (rs >= 200 && rs < 300) parse_robots_txt(rbody, disallows);
            {
                std::lock_guard<std::mutex> lk(hr->mtx);
                hr->robots_fetched = true;
                hr->robots_disallow = std::move(disallows);
            }
        }
        bool blocked = false;
        {
            std::lock_guard<std::mutex> lk(hr->mtx);
            blocked = path_disallowed(hr->robots_disallow, p.path);
        }
        if (blocked)
        {
            log_line(c, "robots-blocked: " + item.url);
            ctx->in_flight.fetch_sub(1);
            return schedule_crawl(ctx, std::move(admission), "continuation", std::chrono::milliseconds(0));
        }
    }

    if (!host_rate_acquire(*hr, std::max(1, c.config.rate_per_host), c.stop_flag))
    {
        ctx->in_flight.fetch_sub(1);
        return schedule_crawl(ctx, std::move(admission), "continuation", std::chrono::milliseconds(0));
    }

    int status = 0;
    std::string body, content_type, err;
    std::vector<std::pair<std::string,std::string>> resp_headers;
    uint64_t lat = 0;
    diag::log_tagged_fmt("crawler", "worker_step fetching id=%llu url=%s timeout=%d",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), c.config.request_timeout_ms);
    bool ok = fetch_url(item.url, c.config.user_agent, c.config.request_timeout_ms,
                        status, body, content_type, resp_headers, lat, err);
    diag::log_tagged_fmt("crawler", "worker_step fetch_result id=%llu url=%s ok=%d status=%d body=%zu lat=%llu err=%s",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), ok ? 1 : 0,
        status, body.size(), static_cast<unsigned long long>(lat), err.c_str());
    if (ctx->finished.load(std::memory_order_acquire)) {
        ctx->in_flight.fetch_sub(1, std::memory_order_acq_rel);
        return false;
    }

    discovered_url_t d;
    d.url = item.url;
    d.status = status;
    d.body_bytes = body.size();
    d.content_type = content_type;
    d.depth = item.depth;
    d.source_url = item.parent;
    d.fetched_unix_ms = now_ms();

    {
        std::lock_guard<std::mutex> lk(c.mtx);
        c.discovered.push_back(d);
        c.last_url = item.url;
        c.last_progress_unix_ms = d.fetched_unix_ms;
        if (!ok)
        {
            c.pages_failed++;
            c.last_error = err;
        }
        else
        {
            c.pages_visited++;
        }
    }

    if (ok)
    {
        if (status >= 300 && status < 400)
        {
            for (auto& h : resp_headers)
            {
                if (to_lower(h.first) == "location")
                {
                    std::string next = resolve_relative(item.url, h.second);
                    if (!next.empty() && item.depth + 1 <= c.config.max_depth)
                    {
                        std::lock_guard<std::mutex> lk(c.mtx);
                        enqueue_url(c, next, item.depth + 1, item.url);
                    }
                }
            }
        }

        if (status >= 200 && status < 300 && item.depth < c.config.max_depth)
        {
            std::vector<std::string> links;
            std::string lower_ct = to_lower(content_type);
            if (lower_ct.find("html") != std::string::npos || lower_ct.find("xml") != std::string::npos || lower_ct.empty())
                extract_html_links(item.url, body, links);
            if (c.config.parse_js)
            {
                if (lower_ct.find("javascript") != std::string::npos || lower_ct.find("json") != std::string::npos
                    || lower_ct.find("html") != std::string::npos)
                    extract_js_urls(item.url, body, links);
            }

            std::lock_guard<std::mutex> lk(c.mtx);
            for (auto& url : links) enqueue_url(c, url, item.depth + 1, item.url);
        }
    }
    else
    {
        log_line(c, std::string("fetch_failed url=") + item.url + " err=" + err);
    }

    ctx->in_flight.fetch_sub(1);
    if (ctx->finished.load(std::memory_order_acquire)) return false;
    return schedule_crawl(ctx, std::move(admission), "continuation", std::chrono::milliseconds(0));
}

bool run_crawl(std::shared_ptr<crawl_t> ctx, admission_ptr_t admission)
{
    auto& c = *ctx;
    if (c.finished.load()) return false;
    if (c.stop_flag.load())
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        if (!c.queue.empty()) c.queue.clear();
    }

    queue_item_t next;
    bool has = false;
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        if (!c.queue.empty())
        {
            next = std::move(c.queue.front());
            c.queue.pop_front();
            c.in_flight.fetch_add(1, std::memory_order_acq_rel);
            has = true;
        }
    }
    if (has)
    {
        return worker_step(ctx, next, std::move(admission));
    }

    if (ctx->in_flight.load() == 0)
    {
        const bool cancelled = c.stop_flag.load(std::memory_order_acquire);
        if (terminalize(ctx, crawl_status_phase_t::complete,
                cancelled ? "cancelled" : std::string(), cancelled)) {
            diag::log_tagged_fmt("burp.crawler", "crawl_finished id=%llu visited=%d failed=%d found=%d",
                static_cast<unsigned long long>(c.id), c.pages_visited, c.pages_failed, static_cast<int>(c.discovered.size()));
        }
        return false;
    }

    return schedule_crawl(ctx, std::move(admission), "wait", std::chrono::milliseconds(50));
}

}

bool initialize()
{
    diag::log_tagged_fmt("crawler", "initialize called");
    auto& r = reg();
    bool expected = false;
    if (!r.init_done.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("crawler", "initialize already_done");
        return true;
    }
    sitemap::initialize();
    diag::log_tagged_fmt("crawler", "initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("crawler", "shutdown called");
    auto& r = reg();
    if (!r.init_done.exchange(false)) {
        diag::log_tagged_fmt("crawler", "shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<crawl_t>> snapshots;
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        snapshots.reserve(r.by_id.size());
        for (auto& kv : r.by_id) { kv.second->stop_flag.store(true); snapshots.push_back(kv.second); }
    }
    diag::log_tagged_fmt("crawler", "shutdown stopping %zu crawls", snapshots.size());
    for (int i = 0; i < 40; ++i)
    {
        bool all_done = true;
        for (auto& c : snapshots) if (!c->finished.load() || c->in_flight.load() > 0) { all_done = false; break; }
        if (all_done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        r.by_id.clear();
    }
    diag::log_tagged_fmt("crawler", "shutdown complete");
}

uint64_t start(const crawl_config_t& config)
{
    if (!reg().init_done.load()) initialize();
    if (config.start_urls.empty()) { set_err("no start urls"); return 0; }
    auto ctx = std::make_shared<crawl_t>();
    ctx->id = reg().next_id.fetch_add(1);
    ctx->config = config;
    ctx->phase = crawl_status_phase_t::running;
    ctx->started_unix_ms = now_ms();
    ctx->last_progress_unix_ms = ctx->started_unix_ms;
    for (auto& u : config.start_urls)
    {
        parsed_url_t p = parse_url(u);
        if (!p.valid) continue;
        std::string canon = canonicalize(p);
        if (canon.empty()) continue;
        if (ctx->seen.insert(canon).second)
        {
            queue_item_t q; q.url = canon; q.depth = 0; q.parent = std::string();
            ctx->queue.push_back(std::move(q));
        }
    }
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id[ctx->id] = ctx;
    }
    diag::log_tagged_fmt("burp.crawler", "crawl_start id=%llu seeds=%zu max_depth=%d max_pages=%d",
        static_cast<unsigned long long>(ctx->id), config.start_urls.size(), config.max_depth, config.max_pages);

    int kick = std::max(1, std::min(config.concurrency, 32));
    int posted_kicks = 0;
    for (int i = 0; i < kick; ++i) {
        mcp_standalone::downstream::producer_identity_t kick_id;
        kick_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
        kick_id.tool_name = "crawler.run_crawl_kick";
        kick_id.domain = config.start_urls.empty() ? std::string() : config.start_urls.front();
        auto kick_admission = mcp_standalone::downstream::scoped_admission_t::acquire(kick_id);
        if (!kick_admission.active()) {
            diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-REJECT id=%llu reason=%s quota=%s observed=%zu limit=%zu phase=kick",
                static_cast<unsigned long long>(ctx->id),
                kick_admission.result().reason.c_str(),
                kick_admission.result().quota_name.c_str(),
                kick_admission.result().observed, kick_admission.result().limit);
            continue;
        }
        const uint64_t kick_token = kick_admission.token();
        diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-ADMIT id=%llu token=%llu phase=kick",
            static_cast<unsigned long long>(ctx->id),
            static_cast<unsigned long long>(kick_token));
        auto kick_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(kick_admission));
        if ([&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.crawler";
            sub.label = "crawler.kick";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::feature_worker;
            sub.priority = 3;
            sub.body = [ctx, kick_admission_ptr, kick_token]() {
            const bool transferred = run_crawl(ctx, kick_admission_ptr);
            if (!transferred) {
                diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed phase=kick",
                    static_cast<unsigned long long>(ctx->id),
                    static_cast<unsigned long long>(kick_token));
                kick_admission_ptr->release("completed");
            }
        };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }()) {
            ++posted_kicks;
        } else {
            diag::log_tagged_fmt("burp.crawler", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=executor_unavailable phase=kick",
                static_cast<unsigned long long>(ctx->id),
                static_cast<unsigned long long>(kick_token));
        }
    }
    if (posted_kicks == 0) {
        const std::string error = "crawler worker admission or submission rejected";
        terminalize(ctx, crawl_status_phase_t::error, error, false);
        set_err(error);
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id.erase(ctx->id);
        return 0;
    }
    return ctx->id;
}

bool stop(uint64_t crawl_id)
{
    diag::log_tagged_fmt("crawler", "stop id=%llu", static_cast<unsigned long long>(crawl_id));
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("crawler", "stop id=%llu not_found", static_cast<unsigned long long>(crawl_id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->phase == crawl_status_phase_t::running) ctx->phase = crawl_status_phase_t::stopping;
    }
    if (ctx->in_flight.load(std::memory_order_acquire) == 0)
        terminalize(ctx, crawl_status_phase_t::complete, "cancelled", true);
    diag::log_tagged_fmt("burp.crawler", "crawl_stop id=%llu", static_cast<unsigned long long>(crawl_id));
    return true;
}

crawl_status_t status(uint64_t crawl_id)
{
    crawl_status_t out;
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) return out;
        ctx = it->second;
    }
    std::lock_guard<std::mutex> lk(ctx->mtx);
    out.id = ctx->id;
    out.phase = ctx->phase;
    out.queue_depth = static_cast<int>(ctx->queue.size());
    out.pages_visited = ctx->pages_visited;
    out.pages_failed = ctx->pages_failed;
    out.urls_found = static_cast<int>(ctx->discovered.size());
    out.started_unix_ms = ctx->started_unix_ms;
    out.finished_unix_ms = ctx->finished_unix_ms;
    out.last_progress_unix_ms = ctx->last_progress_unix_ms;
    out.in_flight = ctx->in_flight.load();
    out.finished = ctx->finished.load(std::memory_order_acquire);
    out.cancelled = out.finished && ctx->stop_flag.load(std::memory_order_acquire) &&
        ctx->phase == crawl_status_phase_t::complete;
    const uint64_t elapsed_end = ctx->finished_unix_ms != 0 ? ctx->finished_unix_ms : now_ms();
    const uint64_t elapsed_ms = elapsed_end > ctx->started_unix_ms ? elapsed_end - ctx->started_unix_ms : 0;
    out.pages_per_sec = elapsed_ms > 0 ? (static_cast<double>(ctx->pages_visited) * 1000.0) / static_cast<double>(elapsed_ms) : 0.0;
    out.last_url = ctx->last_url;
    out.last_error = ctx->last_error;
    out.config = ctx->config;
    out.discovered = ctx->discovered;
    out.log = ctx->log;
    diag::log_tagged_fmt("crawler", "status id=%llu phase=%d queue_depth=%d in_flight=%d pages_visited=%d pages_failed=%d urls_found=%d pages_per_sec=%.3f last_progress_unix_ms=%llu last_url=%s last_error=%s",
        static_cast<unsigned long long>(out.id),
        static_cast<int>(out.phase),
        out.queue_depth,
        out.in_flight,
        out.pages_visited,
        out.pages_failed,
        out.urls_found,
        out.pages_per_sec,
        static_cast<unsigned long long>(out.last_progress_unix_ms),
        out.last_url.c_str(),
        out.last_error.c_str());
    return out;
}

std::vector<crawl_status_t> list()
{
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        ids.reserve(reg().by_id.size());
        for (auto& kv : reg().by_id) ids.push_back(kv.first);
    }
    std::sort(ids.begin(), ids.end());
    std::vector<crawl_status_t> out;
    out.reserve(ids.size());
    for (auto id : ids) out.push_back(status(id));
    return out;
}

bool remove(uint64_t crawl_id)
{
    diag::log_tagged_fmt("crawler", "remove id=%llu", static_cast<unsigned long long>(crawl_id));
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("crawler", "remove id=%llu not_found", static_cast<unsigned long long>(crawl_id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    for (int i = 0; i < 40; ++i)
    {
        if (ctx->finished.load() && ctx->in_flight.load() == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id.erase(crawl_id);
    }
    diag::log_tagged_fmt("crawler", "remove id=%llu complete", static_cast<unsigned long long>(crawl_id));
    return true;
}

std::string last_error()
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.err_mtx);
    return r.last_err;
}

}
}
}
