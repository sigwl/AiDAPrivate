#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "content_discovery.hpp"
#include "audit_http.hpp"
#include "payload_library.hpp"
#include "burp_events.hpp"
#include "site_map.hpp"

#include "helpers/diag_log.hpp"
#include "../../infra/event_bus.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../infra/executor.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida {
namespace burp {
namespace content_discovery {

namespace {

struct candidate_t
{
    std::string url;
    std::string payload;
    int         depth = 0;
};

struct disc_t
{
    uint64_t                            id = 0;
    config_t                            config;
    std::timed_mutex                    mtx;
    std::atomic<bool>                   stop_flag{false};
    std::atomic<bool>                   finished{false};
    std::atomic<disc_phase_t>           phase{disc_phase_t::pending};
    std::vector<candidate_t>            queue;
    std::unordered_set<std::string>     seen;
    std::vector<hit_t>                  hits_list;
    std::atomic<int>                    attempts{0};
    std::atomic<int>                    errors{0};
    std::atomic<int>                    filtered{0};
    std::atomic<int>                    hits_count{0};
    std::atomic<int>                    in_flight{0};
    std::atomic<int>                    total{0};
    std::atomic<uint64_t>               started_unix_ms{0};
    std::atomic<uint64_t>               finished_unix_ms{0};
    std::atomic<size_t>                 calibrated_lo{0};
    std::atomic<size_t>                 calibrated_hi{0};
    std::string                         last_error;
    std::string                         last_url;
    std::regex                          compiled_filter_words;
    bool                                has_filter_words = false;
};

struct registry_t
{
    std::timed_mutex                                     mtx;
    std::unordered_map<uint64_t, std::shared_ptr<disc_t>> by_id;
    std::atomic<uint64_t>                                next_id{1};
    std::atomic<bool>                                    init_done{false};
    std::mutex                                           err_mtx;
    std::string                                          last_err;
};

registry_t& reg() { static registry_t r; return r; }

constexpr int kRegistryLockTimeoutMs = 250;
constexpr int kRunLockTimeoutMs = 250;
constexpr int kListLockTimeoutMs = 25;

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

struct parsed_t { std::string scheme; std::string host; uint16_t port = 0; std::string path; std::string query; bool valid=false; };

parsed_t parse_url(const std::string& url)
{
    parsed_t p;
    std::string work = url;
    auto colon = work.find("://");
    if (colon == std::string::npos) return p;
    p.scheme = to_lower(work.substr(0, colon));
    work = work.substr(colon + 3);
    auto q = work.find('?');
    if (q != std::string::npos) { p.query = work.substr(q + 1); work = work.substr(0, q); }
    auto slash = work.find('/');
    std::string host_part;
    if (slash != std::string::npos) { host_part = work.substr(0, slash); p.path = work.substr(slash); }
    else { host_part = work; p.path = "/"; }
    auto pc = host_part.find(':');
    if (pc != std::string::npos)
    {
        try { p.port = static_cast<uint16_t>(std::stoi(host_part.substr(pc + 1))); host_part = host_part.substr(0, pc); }
        catch (...) { return p; }
    }
    else p.port = (p.scheme == "https") ? 443 : 80;
    p.host = to_lower(host_part);
    if (p.scheme != "http" && p.scheme != "https") return p;
    if (p.host.empty()) return p;
    p.valid = true;
    return p;
}

bool is_loopback_host(const std::string& host)
{
    std::string h = to_lower(host);
    return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]";
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

std::string upper_method(std::string method)
{
    if (method.empty())
        method = "GET";
    std::transform(method.begin(), method.end(), method.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return method;
}

bool audit_http_fallback(const parsed_t& p, const config_t& cfg, const std::string& path_with_query,
                         int& out_status, size_t& out_body_bytes, std::string& out_body,
                         std::string& out_content_type, std::string& out_redirect,
                         std::vector<std::pair<std::string,std::string>>& out_resp_headers,
                         uint64_t& out_latency_ms, std::string& out_err)
{
    const std::string method = upper_method(cfg.method);
    std::string req;
    req.reserve(1024);
    req += method;
    req += " ";
    req += path_with_query.empty() ? "/" : path_with_query;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(p.host);
    req += ":";
    req += std::to_string(p.port);
    req += "\r\nUser-Agent: ";
    req += header_safe(cfg.user_agent);
    req += "\r\nAccept: */*\r\nAccept-Encoding: identity\r\n";
    if (!cfg.cookie_header.empty()) {
        req += "Cookie: ";
        req += header_safe(cfg.cookie_header);
        req += "\r\n";
    }
    for (const auto& h : cfg.extra_headers) {
        if (!h.first.empty()) {
            req += header_safe(h.first);
            req += ": ";
            req += header_safe(h.second);
            req += "\r\n";
        }
    }
    if (method == "POST") {
        req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n";
    } else if (method == "PUT") {
        req += "Content-Type: application/octet-stream\r\nContent-Length: 0\r\n";
    }
    req += "Connection: close\r\n\r\n";
    std::vector<uint8_t> raw(req.begin(), req.end());
    audit_http::send_options_t opts;
    opts.timeout_ms = cfg.request_timeout_ms;
    opts.follow_redirects = cfg.follow_redirects;
    opts.enforce_scope = false;
    auto ex = audit_http::send(raw, p.host, p.port, p.scheme == "https", opts);
    if (!ex) {
        out_err = "transport error; audit_http fallback=" + audit_http::last_error();
        return false;
    }
    out_status = ex->status_code;
    out_body.assign(reinterpret_cast<const char*>(ex->resp_body.data()), ex->resp_body.size());
    out_body_bytes = ex->resp_body.size();
    out_resp_headers = ex->resp_headers;
    out_content_type.clear();
    out_redirect.clear();
    for (auto& h : out_resp_headers)
    {
        std::string ln = to_lower(h.first);
        if (ln == "content-type") out_content_type = h.second;
        else if (ln == "location") out_redirect = h.second;
    }
    out_latency_ms = ex->latency_ms;
    diag::log_tagged_fmt("content_discovery", "audit_http_fallback ok host=%s port=%u method=%s status=%d body=%zu latency_ms=%llu",
        p.host.c_str(),
        static_cast<unsigned>(p.port),
        method.c_str(),
        out_status,
        out_body_bytes,
        static_cast<unsigned long long>(out_latency_ms));
    return true;
}

std::vector<std::string> load_wordlist(const config_t& cfg, std::string& err)
{
    std::vector<std::string> out;
    if (!cfg.wordlist_id.empty())
    {
        auto v = payloads::entries(cfg.wordlist_id, 0);
        if (v.empty())
        {
            err = "wordlist id not found: " + cfg.wordlist_id;
            return {};
        }
        return v;
    }
    if (!cfg.wordlist_file.empty())
    {
        std::ifstream f(cfg.wordlist_file, std::ios::binary);
        if (!f) { err = "wordlist file open failed"; return {}; }
        std::string line;
        while (std::getline(f, line))
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (!line.empty()) out.push_back(line);
        }
        if (out.empty()) err = "wordlist file empty";
        return out;
    }
    err = "no wordlist provided";
    return {};
}

std::string build_target_url(const std::string& base_template, const std::string& payload)
{
    std::string out;
    out.reserve(base_template.size() + payload.size());
    const std::string marker = "FUZZ";
    size_t pos = 0;
    while (pos < base_template.size())
    {
        size_t found = base_template.find(marker, pos);
        if (found == std::string::npos) { out.append(base_template, pos, std::string::npos); break; }
        out.append(base_template, pos, found - pos);
        out.append(payload);
        pos = found + marker.size();
    }
    return out;
}

bool perform_request(const std::string& url, const config_t& cfg,
                     int& out_status, size_t& out_body_bytes, std::string& out_body,
                     std::string& out_content_type, std::string& out_redirect,
                     std::vector<std::pair<std::string,std::string>>& out_resp_headers,
                     uint64_t& out_latency_ms, std::string& out_err)
{
    out_status = 0;
    out_body_bytes = 0;
    out_body.clear();
    out_content_type.clear();
    out_redirect.clear();
    out_resp_headers.clear();
    out_latency_ms = 0;

    parsed_t p = parse_url(url);
    if (!p.valid) { out_err = "invalid url"; return false; }

    std::string path_with_query = p.path;
    if (!p.query.empty()) path_with_query += "?" + p.query;

    const std::string base = p.scheme + "://" + p.host + ":" + std::to_string(p.port);
    httplib::Client cli(base);
    cli.set_connection_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_write_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_follow_location(cfg.follow_redirects);
    cli.enable_server_certificate_verification(false);

    httplib::Headers headers;
    headers.emplace("User-Agent", cfg.user_agent);
    headers.emplace("Accept", "*/*");
    headers.emplace("Accept-Encoding", "identity");
    if (!cfg.cookie_header.empty()) headers.emplace("Cookie", cfg.cookie_header);
    for (auto& h : cfg.extra_headers) headers.emplace(h.first, h.second);

    auto t0 = std::chrono::steady_clock::now();
    httplib::Result res;
    const std::string method = to_lower(cfg.method);
    if (method == "post") res = cli.Post(path_with_query.c_str(), headers, std::string(), "application/x-www-form-urlencoded");
    else if (method == "head") res = cli.Head(path_with_query.c_str(), headers);
    else if (method == "put") res = cli.Put(path_with_query.c_str(), headers, std::string(), "application/octet-stream");
    else if (method == "delete") res = cli.Delete(path_with_query.c_str(), headers);
    else if (method == "options") res = cli.Options(path_with_query.c_str(), headers);
    else res = cli.Get(path_with_query.c_str(), headers);
    auto t1 = std::chrono::steady_clock::now();
    out_latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    if (!res) {
        const std::string httplib_err = httplib::to_string(res.error());
        diag::log_tagged_fmt("content_discovery", "perform_request transport_error url=%s host=%s port=%u method=%s err=%s loopback=%d elapsed_ms=%llu",
            url.c_str(),
            p.host.c_str(),
            static_cast<unsigned>(p.port),
            method.c_str(),
            httplib_err.c_str(),
            is_loopback_host(p.host) ? 1 : 0,
            static_cast<unsigned long long>(out_latency_ms));
        if (is_loopback_host(p.host) &&
            audit_http_fallback(p, cfg, path_with_query, out_status, out_body_bytes, out_body, out_content_type, out_redirect, out_resp_headers, out_latency_ms, out_err)) {
            return true;
        }
        out_err = "transport error (" + httplib_err + ")";
        return false;
    }
    out_status = res->status;
    out_body = res->body;
    out_body_bytes = res->body.size();
    for (auto& h : res->headers)
    {
        out_resp_headers.emplace_back(h.first, h.second);
        std::string ln = to_lower(h.first);
        if (ln == "content-type") out_content_type = h.second;
        else if (ln == "location") out_redirect = h.second;
    }
    return true;
}

bool status_in_set(int status, const std::vector<int>& set)
{
    for (int v : set) if (v == status) return true;
    return false;
}

void publish_exchange(const std::string& url, int status, const std::string& body,
                      const std::string& content_type,
                      const std::vector<std::pair<std::string,std::string>>& resp_headers,
                      const config_t& cfg, uint64_t latency)
{
    parsed_t p = parse_url(url);
    if (!p.valid) return;
    exchange_observed_t ev;
    ev.id = static_cast<uint64_t>(now_ms());
    ev.timestamp_ms = now_ms();
    ev.method = cfg.method;
    ev.scheme = p.scheme;
    ev.host = p.host;
    ev.port = p.port;
    ev.path = p.path;
    ev.query = p.query;
    ev.req_headers.emplace_back("Host", p.host);
    ev.req_headers.emplace_back("User-Agent", cfg.user_agent);
    if (!cfg.cookie_header.empty()) ev.req_headers.emplace_back("Cookie", cfg.cookie_header);
    for (auto& h : cfg.extra_headers) ev.req_headers.emplace_back(h.first, h.second);
    ev.status_code = status;
    ev.resp_headers = resp_headers;
    ev.resp_body.assign(body.begin(), body.end());
    ev.latency_ms = latency;
    if (!content_type.empty())
    {
        bool have = false;
        for (auto& h : ev.resp_headers) if (to_lower(h.first) == "content-type") { have = true; break; }
        if (!have) ev.resp_headers.emplace_back("Content-Type", content_type);
    }
    aida::events::publish(kExchangeObservedEvent, ev);
    sitemap::ingest_exchange(ev);
}

using admission_ptr_t = std::shared_ptr<mcp_standalone::downstream::scoped_admission_t>;

bool run_disc(std::shared_ptr<disc_t> ctx, admission_ptr_t admission);

bool terminalize(const std::shared_ptr<disc_t>& ctx, disc_phase_t phase,
                 const std::string& reason, bool cancelled)
{
    if (!ctx) return false;
    const uint64_t finished_ms = now_ms();
    {
        std::lock_guard<std::timed_mutex> lk(ctx->mtx);
        if (ctx->finished.load(std::memory_order_acquire)) return false;
        ctx->stop_flag.store(cancelled || phase == disc_phase_t::error, std::memory_order_release);
        ctx->queue.clear();
        ctx->phase.store(phase, std::memory_order_release);
        if (!reason.empty()) ctx->last_error = reason;
        ctx->finished_unix_ms.store(finished_ms, std::memory_order_release);
        ctx->finished.store(true, std::memory_order_release);
    }
    aida::events::publish(kJobStateChangedEvent, job_state_changed_t{
        "content_discovery", ctx->id,
        phase == disc_phase_t::error ? "error" : "complete",
        reason, finished_ms, cancelled, true});
    diag::log_tagged_fmt("burp.content_discovery", "disc_terminalized id=%llu phase=%d cancelled=%d reason=%s queued=0 in_flight=%d",
        static_cast<unsigned long long>(ctx->id), static_cast<int>(phase), cancelled ? 1 : 0,
        reason.empty() ? "<none>" : reason.c_str(), ctx->in_flight.load(std::memory_order_acquire));
    return true;
}

bool worker_one(std::shared_ptr<disc_t> ctx, candidate_t cand, admission_ptr_t admission)
{
    diag::log_tagged_fmt("content_discovery", "worker_one id=%llu url=%s depth=%d",
        static_cast<unsigned long long>(ctx->id), cand.url.c_str(), cand.depth);
    auto& d = *ctx;

    int status = 0;
    size_t body_bytes = 0;
    std::string body, content_type, redirect, err;
    std::vector<std::pair<std::string,std::string>> hdr;
    uint64_t lat = 0;
    bool ok = perform_request(cand.url, d.config, status, body_bytes, body, content_type, redirect, hdr, lat, err);
    diag::log_tagged_fmt("content_discovery", "worker_one result id=%llu url=%s ok=%d status=%d body=%zu lat=%llu err=%s",
        static_cast<unsigned long long>(ctx->id), cand.url.c_str(), ok ? 1 : 0,
        status, body_bytes, static_cast<unsigned long long>(lat), err.c_str());
    if (d.finished.load(std::memory_order_acquire)) {
        d.in_flight.fetch_sub(1, std::memory_order_acq_rel);
        return false;
    }

    d.attempts.fetch_add(1);
    if (!ok) {
        d.errors.fetch_add(1);
        diag::log_tagged_fmt("content_discovery", "worker_one error id=%llu url=%s err=%s", static_cast<unsigned long long>(ctx->id), cand.url.c_str(), err.c_str());
    }
    else
    {
        {
            std::lock_guard<std::timed_mutex> lk(d.mtx);
            d.last_url = cand.url;
        }
        bool match = status_in_set(status, d.config.match_status);
        if (status_in_set(status, d.config.filter_status)) match = false;
        diag::log_tagged_fmt("content_discovery", "worker_one filter_check id=%llu url=%s status=%d match=%d", static_cast<unsigned long long>(ctx->id), cand.url.c_str(), status, match ? 1 : 0);
        if (match && d.config.filter_size_max > 0)
        {
            if (body_bytes >= d.config.filter_size_min && body_bytes <= d.config.filter_size_max) match = false;
        }
        const size_t calibrated_lo = d.calibrated_lo.load(std::memory_order_acquire);
        const size_t calibrated_hi = d.calibrated_hi.load(std::memory_order_acquire);
        if (match && calibrated_lo > 0 && calibrated_hi > 0)
        {
            if (body_bytes >= calibrated_lo && body_bytes <= calibrated_hi) match = false;
        }
        if (match && d.has_filter_words)
        {
            if (std::regex_search(body, d.compiled_filter_words)) match = false;
        }

        if (match)
        {
            diag::log_tagged_fmt("content_discovery", "worker_one hit id=%llu url=%s status=%d body=%zu payload=%s",
                static_cast<unsigned long long>(ctx->id), cand.url.c_str(), status, body_bytes, cand.payload.c_str());
            hit_t h;
            h.url = cand.url;
            h.payload = cand.payload;
            h.status = status;
            h.body_bytes = body_bytes;
            h.latency_ms = lat;
            h.content_type = content_type;
            h.redirect_to = redirect;
            h.depth = cand.depth;
            {
                std::lock_guard<std::timed_mutex> lk(d.mtx);
                d.hits_list.push_back(std::move(h));
                d.hits_count.store(static_cast<int>(d.hits_list.size()), std::memory_order_release);
            }
            publish_exchange(cand.url, status, body, content_type, hdr, d.config, lat);

            if (d.config.recurse && cand.depth < d.config.recurse_depth && status >= 200 && status < 300)
            {
                std::string next_base = cand.url;
                if (next_base.back() != '/') next_base += "/";
                next_base += "FUZZ";
                auto wl_err = std::string();
                auto entries = load_wordlist(d.config, wl_err);
                if (entries.empty() && !wl_err.empty()) {
                    diag::log_tagged_fmt("content_discovery", "worker_one recurse_wordlist_empty id=%llu url=%s err=%s",
                        static_cast<unsigned long long>(ctx->id),
                        cand.url.c_str(),
                        wl_err.c_str());
                }
                if (!entries.empty())
                {
                    std::lock_guard<std::timed_mutex> lk(d.mtx);
                    if (!d.finished.load(std::memory_order_acquire)) for (auto& e : entries)
                    {
                        if (d.config.extensions.empty())
                        {
                            std::string nu = build_target_url(next_base, e);
                            if (d.seen.insert(nu).second)
                            {
                                candidate_t c; c.url = nu; c.payload = e; c.depth = cand.depth + 1;
                                d.queue.push_back(std::move(c));
                            }
                        }
                        else
                        {
                            for (auto& x : d.config.extensions)
                            {
                                std::string nu = build_target_url(next_base, e + x);
                                if (d.seen.insert(nu).second)
                                {
                                    candidate_t c; c.url = nu; c.payload = e + x; c.depth = cand.depth + 1;
                                    d.queue.push_back(std::move(c));
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            d.filtered.fetch_add(1);
        }
    }

    if (d.config.delay_ms > 0 && !d.stop_flag.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(d.config.delay_ms));

    d.in_flight.fetch_sub(1);
    if (d.finished.load(std::memory_order_acquire)) return false;
    {
        const uint64_t cont_token = admission->token();
        diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-TRANSFER id=%llu token=%llu phase=continuation",
            static_cast<unsigned long long>(d.id),
            static_cast<unsigned long long>(cont_token));
        if (![&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.content_discovery";
            sub.label = "content_discovery.run_disc";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::feature_worker;
            sub.priority = 3;
            sub.body = [ctx, admission, cont_token]() {
            const bool transferred = run_disc(ctx, admission);
            if (!transferred) {
                diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed",
                    static_cast<unsigned long long>(ctx->id),
                    static_cast<unsigned long long>(cont_token));
                admission->release("completed");
            }
        };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }()) {
            diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=executor_unavailable",
                static_cast<unsigned long long>(d.id),
                static_cast<unsigned long long>(cont_token));
            const bool cancelled = ctx->stop_flag.load(std::memory_order_acquire);
            terminalize(ctx, cancelled ? disc_phase_t::complete : disc_phase_t::error,
                "continuation executor submission rejected", cancelled);
            return false;
        }
        return true;
    }
}

bool run_disc(std::shared_ptr<disc_t> ctx, admission_ptr_t admission)
{
    auto& d = *ctx;
    if (d.finished.load()) return false;
    if (d.stop_flag.load())
    {
        std::lock_guard<std::timed_mutex> lk(d.mtx);
        d.queue.clear();
    }
    candidate_t next;
    bool has = false;
    {
        std::lock_guard<std::timed_mutex> lk(d.mtx);
        if (!d.queue.empty())
        {
            next = std::move(d.queue.back());
            d.queue.pop_back();
            d.in_flight.fetch_add(1, std::memory_order_acq_rel);
            has = true;
        }
    }
    if (has)
    {
        return worker_one(ctx, next, std::move(admission));
    }
    if (d.in_flight.load() == 0)
    {
        const bool cancelled = d.stop_flag.load(std::memory_order_acquire);
        if (terminalize(ctx, disc_phase_t::complete,
                cancelled ? "cancelled" : std::string(), cancelled))
            diag::log_tagged_fmt("burp.content_discovery", "disc_finished id=%llu attempts=%d hits=%d errors=%d filtered=%d",
                static_cast<unsigned long long>(d.id), d.attempts.load(), d.hits_count.load(), d.errors.load(), d.filtered.load());
        return false;
    }
    {
        const uint64_t wait_token = admission->token();
        diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-TRANSFER id=%llu token=%llu phase=wait",
            static_cast<unsigned long long>(d.id),
            static_cast<unsigned long long>(wait_token));
        if (![&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.content_discovery";
            sub.label = "content_discovery.wait";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::feature_worker;
            sub.priority = 3;
            sub.body = [ctx, admission, wait_token]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            const bool transferred = run_disc(ctx, admission);
            if (!transferred) {
                diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed",
                    static_cast<unsigned long long>(ctx->id),
                    static_cast<unsigned long long>(wait_token));
                admission->release("completed");
            }
        };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }()) {
            diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=executor_unavailable",
                static_cast<unsigned long long>(d.id),
                static_cast<unsigned long long>(wait_token));
            const bool cancelled = ctx->stop_flag.load(std::memory_order_acquire);
            terminalize(ctx, cancelled ? disc_phase_t::complete : disc_phase_t::error,
                "wait executor submission rejected", cancelled);
            return false;
        }
        return true;
    }
}

bool auto_calibrate(disc_t& d)
{
    diag::log_tagged_fmt("content_discovery", "auto_calibrate id=%llu target=%s", static_cast<unsigned long long>(d.id), d.config.target_url.c_str());
    static const char* k = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dist(0, 35);
    std::vector<size_t> sizes;
    for (int i = 0; i < 3 && !d.stop_flag.load(); ++i)
    {
        std::string junk;
        for (int j = 0; j < 16; ++j) junk.push_back(k[dist(rng)]);
        std::string url = build_target_url(d.config.target_url, junk + "_aida_calib");
        int status = 0;
        size_t body_bytes = 0;
        std::string body, ct, redir, err;
        std::vector<std::pair<std::string,std::string>> hdr;
        uint64_t lat = 0;
        if (perform_request(url, d.config, status, body_bytes, body, ct, redir, hdr, lat, err)) {
            diag::log_tagged_fmt("content_discovery", "auto_calibrate probe id=%llu url=%s status=%d body=%zu", static_cast<unsigned long long>(d.id), url.c_str(), status, body_bytes);
            sizes.push_back(body_bytes);
        } else {
            diag::log_tagged_fmt("content_discovery", "auto_calibrate probe_failed id=%llu url=%s err=%s", static_cast<unsigned long long>(d.id), url.c_str(), err.c_str());
        }
    }
    if (sizes.empty()) {
        diag::log_tagged_fmt("content_discovery", "auto_calibrate failed id=%llu no_samples", static_cast<unsigned long long>(d.id));
        return false;
    }
    std::sort(sizes.begin(), sizes.end());
    size_t lo = sizes.front();
    size_t hi = sizes.back();
    if (hi > 0) hi += hi / 20 + 8;
    if (lo > 8) lo -= 8;
    d.calibrated_lo.store(lo, std::memory_order_release);
    d.calibrated_hi.store(hi, std::memory_order_release);
    diag::log_tagged_fmt("content_discovery", "auto_calibrate result id=%llu lo=%zu hi=%zu samples=%zu",
        static_cast<unsigned long long>(d.id), lo, hi, sizes.size());
    return true;
}

}

bool initialize()
{
    diag::log_tagged_fmt("content_discovery", "initialize called");
    auto& r = reg();
    bool expected = false;
    if (!r.init_done.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("content_discovery", "initialize already_done");
        return true;
    }
    payloads::initialize();
    diag::log_tagged_fmt("content_discovery", "initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("content_discovery", "shutdown called");
    auto& r = reg();
    if (!r.init_done.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("content_discovery", "shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<disc_t>> snaps;
    {
        std::unique_lock<std::timed_mutex> lk(r.mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs))) {
            diag::log_tagged_fmt("content_discovery", "shutdown_registry_lock_timeout phase=snapshot timeout_ms=%d", kRegistryLockTimeoutMs);
            set_err("registry lock timeout");
            return;
        }
        r.init_done.store(false, std::memory_order_release);
        snaps.reserve(r.by_id.size());
        for (auto& kv : r.by_id) { kv.second->stop_flag.store(true); snaps.push_back(kv.second); }
    }
    diag::log_tagged_fmt("content_discovery", "shutdown stopping %zu jobs", snaps.size());
    for (int i = 0; i < 40; ++i)
    {
        bool done = true;
        for (auto& d : snaps) if (!d->finished.load() || d->in_flight.load() > 0) { done = false; break; }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::unique_lock<std::timed_mutex> lk(r.mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs))) {
            diag::log_tagged_fmt("content_discovery", "shutdown_registry_lock_timeout phase=clear timeout_ms=%d", kRegistryLockTimeoutMs);
            set_err("registry lock timeout");
            return;
        }
        r.by_id.clear();
    }
    diag::log_tagged_fmt("content_discovery", "shutdown complete");
}

uint64_t start(const config_t& cfg)
{
    if (!reg().init_done.load()) initialize();
    if (cfg.target_url.empty() || cfg.target_url.find("FUZZ") == std::string::npos)
    {
        set_err("target_url must contain FUZZ marker");
        return 0;
    }
    std::string err;
    auto entries = load_wordlist(cfg, err);
    if (entries.empty())
    {
        set_err(err.empty() ? "wordlist empty" : err);
        return 0;
    }
    auto ctx = std::make_shared<disc_t>();
    ctx->id = reg().next_id.fetch_add(1);
    ctx->config = cfg;
    if (ctx->config.match_status.empty()) ctx->config.match_status = {200, 201, 204, 301, 302, 401, 403, 500};
    if (!cfg.filter_words_regex.empty())
    {
        try { ctx->compiled_filter_words = std::regex(cfg.filter_words_regex); ctx->has_filter_words = true; }
        catch (...) { ctx->has_filter_words = false; }
    }
    ctx->phase.store(disc_phase_t::calibrating, std::memory_order_release);
    ctx->started_unix_ms.store(now_ms(), std::memory_order_release);

    {
        std::lock_guard<std::timed_mutex> lk(ctx->mtx);
        for (auto& e : entries)
        {
            if (cfg.extensions.empty())
            {
                std::string url = build_target_url(cfg.target_url, e);
                if (ctx->seen.insert(url).second)
                {
                    candidate_t c; c.url = url; c.payload = e; c.depth = 0;
                    ctx->queue.push_back(std::move(c));
                }
            }
            else
            {
                for (auto& x : cfg.extensions)
                {
                    std::string url = build_target_url(cfg.target_url, e + x);
                    if (ctx->seen.insert(url).second)
                    {
                        candidate_t c; c.url = url; c.payload = e + x; c.depth = 0;
                        ctx->queue.push_back(std::move(c));
                    }
                }
            }
        }
        ctx->total.store(static_cast<int>(ctx->queue.size()), std::memory_order_release);
    }

    {
        std::unique_lock<std::timed_mutex> lk(reg().mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs))) {
            diag::log_tagged_fmt("content_discovery", "start_registry_lock_timeout id=%llu target=%s timeout_ms=%d",
                static_cast<unsigned long long>(ctx->id),
                cfg.target_url.c_str(),
                kRegistryLockTimeoutMs);
            set_err("registry lock timeout");
            return 0;
        }
        reg().by_id[ctx->id] = ctx;
    }
    diag::log_tagged_fmt("burp.content_discovery", "disc_start id=%llu target=%s total=%d conc=%d delay=%d",
        static_cast<unsigned long long>(ctx->id), cfg.target_url.c_str(), ctx->total.load(std::memory_order_acquire), cfg.concurrency, cfg.delay_ms);

    mcp_standalone::downstream::producer_identity_t start_id;
    start_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
    start_id.tool_name = "content_discovery.start";
    start_id.domain = cfg.target_url;
    auto start_admission = mcp_standalone::downstream::scoped_admission_t::acquire(start_id);
    if (!start_admission.active()) {
        diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-REJECT id=%llu reason=%s quota=%s observed=%zu limit=%zu phase=start",
            static_cast<unsigned long long>(ctx->id),
            start_admission.result().reason.c_str(),
            start_admission.result().quota_name.c_str(),
            start_admission.result().observed, start_admission.result().limit);
        terminalize(ctx, disc_phase_t::error, "downstream capacity exhausted", false);
        set_err("downstream capacity exhausted");
        std::unique_lock<std::timed_mutex> reg_lk(reg().mtx, std::defer_lock);
        if (reg_lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs)))
            reg().by_id.erase(ctx->id);
        return 0;
    }
    const uint64_t start_token = start_admission.token();
    diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-ADMIT id=%llu token=%llu phase=start",
        static_cast<unsigned long long>(ctx->id),
        static_cast<unsigned long long>(start_token));

    auto start_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(start_admission));
    bool posted = [&]() {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.content_discovery";
        sub.label = "content_discovery.start";
        sub.thread_class = "long_running";
        sub.domain = aida::infra::executor::domain_t::long_running;
        sub.priority = 3;
        sub.body = [ctx, start_admission_ptr, start_token]() {
        if (ctx->config.auto_calibrate) auto_calibrate(*ctx);
        if (ctx->finished.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=terminal_during_calibration phase=start_outer",
                static_cast<unsigned long long>(ctx->id),
                static_cast<unsigned long long>(start_token));
            start_admission_ptr->release("terminal_during_calibration");
            return;
        }
        if (ctx->stop_flag.load(std::memory_order_acquire)) {
            terminalize(ctx, disc_phase_t::complete, "cancelled", true);
            diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=cancelled_during_calibration phase=start_outer",
                static_cast<unsigned long long>(ctx->id),
                static_cast<unsigned long long>(start_token));
            start_admission_ptr->release("cancelled_during_calibration");
            return;
        }
        {
            std::unique_lock<std::timed_mutex> lk(ctx->mtx, std::defer_lock);
            if (lk.try_lock_for(std::chrono::milliseconds(kRunLockTimeoutMs)))
                ctx->phase.store(disc_phase_t::running, std::memory_order_release);
            else
                diag::log_tagged_fmt("content_discovery", "start_phase_lock_timeout id=%llu timeout_ms=%d",
                    static_cast<unsigned long long>(ctx->id),
                    kRunLockTimeoutMs);
        }
        int kick = std::max(1, std::min(ctx->config.concurrency, 64));
        int posted_kicks = 0;
        bool start_admission_transferred = false;
        for (int i = 0; i < kick; ++i) {
            admission_ptr_t kick_admission_ptr;
            if (!start_admission_transferred) {
                kick_admission_ptr = start_admission_ptr;
                diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-TRANSFER id=%llu token=%llu phase=start_to_kick",
                    static_cast<unsigned long long>(ctx->id),
                    static_cast<unsigned long long>(start_token));
            } else {
                mcp_standalone::downstream::producer_identity_t kick_id;
                kick_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
                kick_id.tool_name = "content_discovery.run_disc_kick";
                kick_id.domain = ctx->config.target_url;
                auto kick_admission = mcp_standalone::downstream::scoped_admission_t::acquire(kick_id);
                if (!kick_admission.active()) {
                    diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-REJECT id=%llu reason=%s quota=%s observed=%zu limit=%zu phase=kick",
                        static_cast<unsigned long long>(ctx->id),
                        kick_admission.result().reason.c_str(),
                        kick_admission.result().quota_name.c_str(),
                        kick_admission.result().observed, kick_admission.result().limit);
                    continue;
                }
                kick_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(kick_admission));
            }
            const uint64_t kick_token = kick_admission_ptr->token();
            const bool kick_posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.content_discovery";
                sub.label = "content_discovery.kick";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::feature_worker;
                sub.priority = 3;
                sub.body = [ctx, kick_admission_ptr, kick_token]() {
                    const bool transferred = run_disc(ctx, kick_admission_ptr);
                    if (!transferred) {
                        diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed phase=kick",
                            static_cast<unsigned long long>(ctx->id),
                            static_cast<unsigned long long>(kick_token));
                        kick_admission_ptr->release("completed");
                    }
                };
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
            if (kick_posted) {
                ++posted_kicks;
                if (kick_admission_ptr == start_admission_ptr)
                    start_admission_transferred = true;
            }
        }
        if (posted_kicks == 0) {
            terminalize(ctx, disc_phase_t::error, "worker admission or executor submission rejected", false);
            diag::log_tagged_fmt("content_discovery", "start_worker_posts_failed id=%llu kick=%d",
                static_cast<unsigned long long>(ctx->id),
                kick);
        }
        if (!start_admission_transferred) {
            diag::log_tagged_fmt("burp.content_discovery", "BURP-NETWORK-WORKER-RELEASE id=%llu token=%llu reason=completed phase=start_outer",
                static_cast<unsigned long long>(ctx->id),
                static_cast<unsigned long long>(start_token));
            start_admission_ptr->release("completed");
        }
    };
        return ::aida::infra::executor::submit(std::move(sub)).submitted;
    }();
    if (!posted) {
        terminalize(ctx, disc_phase_t::error, "executor post failed", false);
        set_err("executor post failed");
        diag::log_tagged_fmt("content_discovery", "start_post_failed id=%llu target=%s",
            static_cast<unsigned long long>(ctx->id),
            cfg.target_url.c_str());
        std::unique_lock<std::timed_mutex> reg_lk(reg().mtx, std::defer_lock);
        if (reg_lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs)))
            reg().by_id.erase(ctx->id);
        return 0;
    }

    return ctx->id;
}

disc_status_t snapshot_contention_status(const std::shared_ptr<disc_t>& ctx, const char* op, int timeout_ms)
{
    disc_status_t out;
    if (!ctx)
        return out;
    out.id = ctx->id;
    out.phase = ctx->phase.load(std::memory_order_acquire);
    out.attempts = ctx->attempts.load(std::memory_order_acquire);
    out.total = ctx->total.load(std::memory_order_acquire);
    out.hits = ctx->hits_count.load(std::memory_order_acquire);
    out.filtered = ctx->filtered.load(std::memory_order_acquire);
    out.errors = ctx->errors.load(std::memory_order_acquire);
    out.started_unix_ms = ctx->started_unix_ms.load(std::memory_order_acquire);
    out.finished_unix_ms = ctx->finished_unix_ms.load(std::memory_order_acquire);
    out.finished = ctx->finished.load(std::memory_order_acquire);
    out.cancelled = out.finished && ctx->stop_flag.load(std::memory_order_acquire) &&
        out.phase == disc_phase_t::complete;
    out.calibrated_size_lo = ctx->calibrated_lo.load(std::memory_order_acquire);
    out.calibrated_size_hi = ctx->calibrated_hi.load(std::memory_order_acquire);
    out.config = ctx->config;
    out.last_error = "status snapshot lock timeout";
    diag::log_tagged_fmt("content_discovery", "status_lock_timeout op=%s id=%llu phase=%d attempts=%d total=%d hits=%d errors=%d filtered=%d in_flight=%d finished=%d stop=%d timeout_ms=%d",
        op ? op : "<null>",
        static_cast<unsigned long long>(ctx->id),
        static_cast<int>(out.phase),
        out.attempts,
        out.total,
        out.hits,
        out.errors,
        out.filtered,
        ctx->in_flight.load(std::memory_order_acquire),
        ctx->finished.load(std::memory_order_acquire) ? 1 : 0,
        ctx->stop_flag.load(std::memory_order_acquire) ? 1 : 0,
        timeout_ms);
    return out;
}

void fill_status_locked(const std::shared_ptr<disc_t>& ctx, disc_status_t& out)
{
    out.id = ctx->id;
    out.phase = ctx->phase.load(std::memory_order_acquire);
    out.attempts = ctx->attempts.load(std::memory_order_acquire);
    out.total = ctx->total.load(std::memory_order_acquire);
    out.hits = ctx->hits_count.load(std::memory_order_acquire);
    out.filtered = ctx->filtered.load(std::memory_order_acquire);
    out.errors = ctx->errors.load(std::memory_order_acquire);
    out.started_unix_ms = ctx->started_unix_ms.load(std::memory_order_acquire);
    out.finished_unix_ms = ctx->finished_unix_ms.load(std::memory_order_acquire);
    out.finished = ctx->finished.load(std::memory_order_acquire);
    out.cancelled = out.finished && ctx->stop_flag.load(std::memory_order_acquire) &&
        out.phase == disc_phase_t::complete;
    out.calibrated_size_lo = ctx->calibrated_lo.load(std::memory_order_acquire);
    out.calibrated_size_hi = ctx->calibrated_hi.load(std::memory_order_acquire);
    out.last_error = ctx->last_error;
    out.last_url = ctx->last_url;
    out.config = ctx->config;
    out.hits_list = ctx->hits_list;
}

bool try_get_context(uint64_t id, std::shared_ptr<disc_t>& ctx, const char* op)
{
    std::unique_lock<std::timed_mutex> lk(reg().mtx, std::defer_lock);
    if (!lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs)))
    {
        diag::log_tagged_fmt("content_discovery", "registry_lock_timeout op=%s id=%llu timeout_ms=%d",
            op ? op : "<null>",
            static_cast<unsigned long long>(id),
            kRegistryLockTimeoutMs);
        set_err("registry lock timeout");
        return false;
    }
    auto it = reg().by_id.find(id);
    if (it == reg().by_id.end())
        return false;
    ctx = it->second;
    return true;
}

bool stop(uint64_t id)
{
    diag::log_tagged_fmt("content_discovery", "stop id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<disc_t> ctx;
    if (!try_get_context(id, ctx, "stop")) {
        diag::log_tagged_fmt("content_discovery", "stop id=%llu not_found_or_busy", static_cast<unsigned long long>(id));
        set_err("not found");
        return false;
    }
    ctx->stop_flag.store(true);
    {
        std::unique_lock<std::timed_mutex> lk(ctx->mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kRunLockTimeoutMs))) {
            diag::log_tagged_fmt("content_discovery", "stop_phase_lock_timeout id=%llu timeout_ms=%d",
                static_cast<unsigned long long>(id),
                kRunLockTimeoutMs);
            diag::log_tagged_fmt("burp.content_discovery", "disc_stop id=%llu phase_deferred=1", static_cast<unsigned long long>(id));
            return true;
        }
        if (ctx->phase.load(std::memory_order_acquire) != disc_phase_t::complete)
            ctx->phase.store(disc_phase_t::stopping, std::memory_order_release);
    }
    if (ctx->in_flight.load(std::memory_order_acquire) == 0)
        terminalize(ctx, disc_phase_t::complete, "cancelled", true);
    diag::log_tagged_fmt("burp.content_discovery", "disc_stop id=%llu", static_cast<unsigned long long>(id));
    return true;
}

disc_status_t status(uint64_t id)
{
    disc_status_t out;
    std::shared_ptr<disc_t> ctx;
    if (!try_get_context(id, ctx, "status"))
        return out;
    std::unique_lock<std::timed_mutex> lk(ctx->mtx, std::defer_lock);
    if (!lk.try_lock_for(std::chrono::milliseconds(kRunLockTimeoutMs)))
        return snapshot_contention_status(ctx, "status", kRunLockTimeoutMs);
    fill_status_locked(ctx, out);
    return out;
}

std::vector<disc_status_t> list()
{
    std::vector<std::shared_ptr<disc_t>> snaps;
    {
        std::unique_lock<std::timed_mutex> lk(reg().mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kListLockTimeoutMs)))
        {
            diag::log_tagged_fmt("content_discovery", "registry_lock_timeout op=list timeout_ms=%d", kListLockTimeoutMs);
            set_err("registry lock timeout");
            return {};
        }
        snaps.reserve(reg().by_id.size());
        for (auto& kv : reg().by_id) snaps.push_back(kv.second);
    }
    std::sort(snaps.begin(), snaps.end(), [](const std::shared_ptr<disc_t>& a, const std::shared_ptr<disc_t>& b) {
        const uint64_t aid = a ? a->id : 0;
        const uint64_t bid = b ? b->id : 0;
        return aid < bid;
    });
    std::vector<disc_status_t> out;
    out.reserve(snaps.size());
    for (auto& ctx : snaps) {
        if (!ctx)
            continue;
        std::unique_lock<std::timed_mutex> lk(ctx->mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kListLockTimeoutMs))) {
            out.push_back(snapshot_contention_status(ctx, "list", kListLockTimeoutMs));
            continue;
        }
        disc_status_t st;
        fill_status_locked(ctx, st);
        out.push_back(std::move(st));
    }
    return out;
}

std::vector<hit_t> results(uint64_t id)
{
    std::shared_ptr<disc_t> ctx;
    if (!try_get_context(id, ctx, "results"))
        return {};
    std::unique_lock<std::timed_mutex> lk(ctx->mtx, std::defer_lock);
    if (!lk.try_lock_for(std::chrono::milliseconds(kRunLockTimeoutMs))) {
        diag::log_tagged_fmt("content_discovery", "results_lock_timeout id=%llu timeout_ms=%d",
            static_cast<unsigned long long>(id),
            kRunLockTimeoutMs);
        set_err("results lock timeout");
        return {};
    }
    return ctx->hits_list;
}

bool remove(uint64_t id)
{
    diag::log_tagged_fmt("content_discovery", "remove id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<disc_t> ctx;
    if (!try_get_context(id, ctx, "remove")) {
        diag::log_tagged_fmt("content_discovery", "remove id=%llu not_found_or_busy", static_cast<unsigned long long>(id));
        set_err("not found");
        return false;
    }
    ctx->stop_flag.store(true);
    for (int i = 0; i < 40; ++i)
    {
        if (ctx->finished.load() && ctx->in_flight.load() == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::unique_lock<std::timed_mutex> lk(reg().mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(kRegistryLockTimeoutMs))) {
            diag::log_tagged_fmt("content_discovery", "remove_registry_lock_timeout id=%llu timeout_ms=%d",
                static_cast<unsigned long long>(id),
                kRegistryLockTimeoutMs);
            set_err("registry lock timeout");
            return false;
        }
        reg().by_id.erase(id);
    }
    diag::log_tagged_fmt("content_discovery", "remove id=%llu complete", static_cast<unsigned long long>(id));
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
