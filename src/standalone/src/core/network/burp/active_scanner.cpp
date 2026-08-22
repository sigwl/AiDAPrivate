#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "insertion_points.hpp"
#include "issue.hpp"
#include "scope.hpp"

#include "../../infra/executor.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace active_scanner {

namespace {

constexpr size_t kMaxActiveAudits = 2;
constexpr size_t kMaxGlobalInFlightRequests = 16;
constexpr size_t kMaxPerAuditInFlightRequests = 8;
constexpr size_t kExternalDefaultMaxConcurrentRequests = 2;
constexpr size_t kExternalDefaultThrottleMs = 125;
constexpr size_t kMaxTransportBackoffMs = 1500;
constexpr size_t kWsaEnobufsPreinitCircuitThreshold = 4;
constexpr uint32_t kWsaEnobufsCode = 10055;

struct audit_runtime_t
{
    audit_status_t              status;
    audit_config_t              config;
    std::vector<uint8_t>        raw_request;
    std::atomic<bool>           cancel_flag{false};
    std::atomic<size_t>         in_flight{0};
    std::atomic<size_t>         active_workers{0};
    std::atomic<size_t>         queued_workers{0};
    std::atomic<bool>           audit_worker_active{false};
    std::atomic<bool>           capacity_owned{false};
    std::atomic<bool>           drain_finalizing{false};
    std::atomic<size_t>         module_request_count{0};
    std::atomic<size_t>         transport_backoff_ms{0};
    std::atomic<size_t>         wsaenobufs_preinit_hits{0};
    std::atomic<bool>           transport_circuit_breaker_open{false};
    std::map<std::string, std::atomic<size_t>> per_module_count;
    std::mutex                  pmc_mtx;
    std::mutex                  status_mtx;
    std::condition_variable     cancel_cv;
    std::shared_ptr<mcp_standalone::downstream::scoped_admission_t> admission;
    uint64_t                    admission_token = 0;
};

struct state_t
{
    std::mutex                                                            lifecycle_mtx;
    std::mutex                                                            audits_mtx;
    std::unordered_map<uint64_t, std::shared_ptr<audit_runtime_t>>        audits;
    std::atomic<uint64_t>                                                 next_id{1};
    std::atomic<size_t>                                                   global_in_flight{0};
    std::atomic<bool>                                                     initialized{false};
    std::atomic<bool>                                                     shutting_down{false};
    std::mutex                                                            err_mtx;
    std::string                                                           last_error;
    std::string                                                           last_error_code;
};

state_t& state()
{
    static state_t* s = new state_t();
    return *s;
}

void set_err(const std::string& msg, const std::string& code = std::string())
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
    s.last_error_code = code;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

scanner_load_t collect_load_snapshot()
{
    auto& s = state();
    scanner_load_t load;
    load.max_active_audits = kMaxActiveAudits;
    load.shutting_down = s.shutting_down.load(std::memory_order_acquire);
    load.in_flight_requests = s.global_in_flight.load(std::memory_order_acquire);
    std::lock_guard<std::mutex> lk(s.audits_mtx);
    load.active_audits = s.audits.size();
    for (auto& kv : s.audits) {
        const auto& rt = kv.second;
        if (!rt)
            continue;
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        load.active_workers += active_workers;
        load.queue_depth += rt->queued_workers.load(std::memory_order_acquire);
        if (rt->capacity_owned.load(std::memory_order_acquire))
            ++load.running_audits;
    }
    return load;
}

size_t increment_pmc(audit_runtime_t& rt, const std::string& mod_id)
{
    std::lock_guard<std::mutex> lk(rt.pmc_mtx);
    auto it = rt.per_module_count.find(mod_id);
    if (it == rt.per_module_count.end()) {
        rt.per_module_count[mod_id].store(0);
        it = rt.per_module_count.find(mod_id);
    }
    return it->second.fetch_add(1) + 1;
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool parse_ipv4_parts(const std::string& host, unsigned parts[4])
{
    size_t start = 0;
    for (size_t i = 0; i < 4; ++i) {
        size_t dot = (i == 3) ? std::string::npos : host.find('.', start);
        size_t end = (dot == std::string::npos) ? host.size() : dot;
        if (end <= start || end - start > 3)
            return false;
        unsigned value = 0;
        for (size_t p = start; p < end; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(host[p])))
                return false;
            value = value * 10 + static_cast<unsigned>(host[p] - '0');
            if (value > 255)
                return false;
        }
        parts[i] = value;
        if (i < 3) {
            if (dot == std::string::npos)
                return false;
            start = dot + 1;
        }
    }
    return true;
}

bool is_local_or_private_host(const std::string& host)
{
    std::string h = lower_ascii(host);
    if (!h.empty() && h.front() == '[' && h.back() == ']')
        h = h.substr(1, h.size() - 2);
    if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1")
        return true;
    if (h.size() > 10 && h.compare(h.size() - 10, 10, ".localhost") == 0)
        return true;
    unsigned parts[4]{};
    if (!parse_ipv4_parts(h, parts))
        return false;
    if (parts[0] == 10 || parts[0] == 127)
        return true;
    if (parts[0] == 192 && parts[1] == 168)
        return true;
    if (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31)
        return true;
    if (parts[0] == 169 && parts[1] == 254)
        return true;
    return false;
}

std::string sanitize_transport_error(std::string error)
{
    for (char& c : error) {
        if (c == '\r' || c == '\n' || c == '\t')
            c = ' ';
    }
    if (error.size() > 1024)
        error.resize(1024);
    return error;
}

bool transport_error_is_pressure(const std::string& error)
{
    const std::string e = lower_ascii(error);
    return e.find("10055") != std::string::npos ||
           e.find("wsaenobufs") != std::string::npos ||
           e.find("no buffer") != std::string::npos ||
           e.find("buffer space") != std::string::npos;
}

uint32_t transport_error_code_from_error(const std::string& error)
{
    const std::string e = lower_ascii(error);
    if (e.find("transport_error_code=10055") != std::string::npos ||
        e.find("last_connect_err=10055") != std::string::npos ||
        e.find("connect_err=10055") != std::string::npos ||
        e.find("wsaenobufs") != std::string::npos)
        return kWsaEnobufsCode;
    return 0;
}

std::string transport_error_class_from_error(const std::string& error)
{
    const std::string e = lower_ascii(error);
    if (e.find("transport_error_class=wsaenobufs_preinit") != std::string::npos ||
        e.find("wsaenobufs_preinit") != std::string::npos)
        return "wsaenobufs_preinit";
    if (transport_error_is_pressure(error))
        return "transport_pressure";
    return {};
}

bool transport_error_is_wsaenobufs_preinit(const std::string& error)
{
    const std::string e = lower_ascii(error);
    if (e.find("transport_error_class=wsaenobufs_preinit") != std::string::npos ||
        e.find("wsaenobufs_preinit") != std::string::npos)
        return true;
    return transport_error_code_from_error(error) == kWsaEnobufsCode &&
           (e.find("before_would_block=1") != std::string::npos ||
            e.find("connect_stage=connect_immediate_failure") != std::string::npos ||
            e.find("connect_stage=socket_create") != std::string::npos);
}

void raise_transport_backoff(audit_runtime_t& rt, const std::string& error)
{
    if (!transport_error_is_pressure(error))
        return;
    size_t current = rt.transport_backoff_ms.load(std::memory_order_acquire);
    while (current < kMaxTransportBackoffMs) {
        const size_t next = current == 0 ? 250 : (std::min)(current * 2, kMaxTransportBackoffMs);
        if (rt.transport_backoff_ms.compare_exchange_weak(current, next, std::memory_order_acq_rel)) {
            std::lock_guard<std::mutex> lk(rt.status_mtx);
            rt.status.transport_backoff_ms = next;
            rt.status.effective_throttle_ms = rt.config.request_throttle_ms + next;
            diag::log_tagged_fmt("scanner", "transport_backoff_raise audit=%llu backoff_ms=%zu error=%s",
                static_cast<unsigned long long>(rt.status.id), next, error.c_str());
            return;
        }
    }
}

void record_transport_result(const std::shared_ptr<audit_runtime_t>& rt_ptr,
                             bool got_response,
                             const std::string& transport_error,
                             const char* phase,
                             const std::string& mod_id)
{
    if (!rt_ptr)
        return;
    const std::string safe_error = sanitize_transport_error(transport_error);
    const uint32_t transport_code = safe_error.empty() ? 0 : transport_error_code_from_error(safe_error);
    const std::string transport_class = safe_error.empty() ? std::string() : transport_error_class_from_error(safe_error);
    bool notify_circuit = false;
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.transport_backoff_ms = rt_ptr->transport_backoff_ms.load(std::memory_order_acquire);
        rt_ptr->status.effective_throttle_ms = rt_ptr->config.request_throttle_ms + rt_ptr->status.transport_backoff_ms;
        rt_ptr->status.transport_circuit_breaker_threshold = kWsaEnobufsPreinitCircuitThreshold;
        rt_ptr->status.transport_circuit_breaker_hits = rt_ptr->wsaenobufs_preinit_hits.load(std::memory_order_acquire);
        rt_ptr->status.transport_circuit_breaker_open = rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire);
        if (got_response) {
            rt_ptr->status.responses_received++;
        } else {
            rt_ptr->status.no_response_count++;
            if (!safe_error.empty()) {
                rt_ptr->status.transport_failures++;
                rt_ptr->status.last_transport_error = safe_error;
                if (transport_code != 0)
                    rt_ptr->status.transport_error_code = transport_code;
                if (!transport_class.empty())
                    rt_ptr->status.transport_error_class = transport_class;
                if (transport_error_is_wsaenobufs_preinit(safe_error) && rt_ptr->status.responses_received == 0) {
                    const size_t hits = rt_ptr->wsaenobufs_preinit_hits.fetch_add(1, std::memory_order_acq_rel) + 1;
                    rt_ptr->status.transport_circuit_breaker_hits = hits;
                    rt_ptr->status.transport_error_code = kWsaEnobufsCode;
                    rt_ptr->status.transport_error_class = "wsaenobufs_preinit";
                    if (hits >= kWsaEnobufsPreinitCircuitThreshold) {
                        const bool was_open = rt_ptr->transport_circuit_breaker_open.exchange(true, std::memory_order_acq_rel);
                        rt_ptr->status.transport_circuit_breaker_open = true;
                        if (!was_open) {
                            notify_circuit = true;
                            diag::log_tagged_fmt("scanner", "transport_circuit_open audit=%llu class=wsaenobufs_preinit code=%u hits=%zu threshold=%zu responses=%zu no_response=%zu failures=%zu last_error=%s",
                                static_cast<unsigned long long>(rt_ptr->status.id),
                                kWsaEnobufsCode,
                                hits,
                                kWsaEnobufsPreinitCircuitThreshold,
                                rt_ptr->status.responses_received,
                                rt_ptr->status.no_response_count,
                                rt_ptr->status.transport_failures,
                                rt_ptr->status.last_transport_error.c_str());
                        }
                    }
                }
            }
        }
        diag::log_tagged_fmt("scanner", "transport_result audit=%llu phase=%s module=%s got_response=%d responses=%zu no_response=%zu failures=%zu transport_error_code=%u transport_error_class=%s circuit_open=%d circuit_hits=%zu last_error=%s",
            static_cast<unsigned long long>(rt_ptr->status.id),
            phase ? phase : "",
            mod_id.c_str(),
            got_response ? 1 : 0,
            rt_ptr->status.responses_received,
            rt_ptr->status.no_response_count,
            rt_ptr->status.transport_failures,
            rt_ptr->status.transport_error_code,
            rt_ptr->status.transport_error_class.c_str(),
            rt_ptr->status.transport_circuit_breaker_open ? 1 : 0,
            rt_ptr->status.transport_circuit_breaker_hits,
            rt_ptr->status.last_transport_error.c_str());
    }
    if (notify_circuit)
        rt_ptr->cancel_cv.notify_all();
    if (!got_response && !safe_error.empty())
        raise_transport_backoff(*rt_ptr, safe_error);
}

bool wait_for_inflight_slot(audit_runtime_t& rt, size_t cap)
{
    auto& s = state();
    const size_t per_audit_cap = (std::max)(static_cast<size_t>(1), (std::min)(cap, kMaxPerAuditInFlightRequests));
    while (true) {
        if (rt.cancel_flag.load() || rt.transport_circuit_breaker_open.load(std::memory_order_acquire) || s.shutting_down.load(std::memory_order_acquire)) return false;
        size_t cur = rt.in_flight.load();
        size_t global_cur = s.global_in_flight.load(std::memory_order_acquire);
        if (cur < per_audit_cap && global_cur < kMaxGlobalInFlightRequests) {
            if (!rt.in_flight.compare_exchange_weak(cur, cur + 1))
                continue;
            while (true) {
                global_cur = s.global_in_flight.load(std::memory_order_acquire);
                if (global_cur >= kMaxGlobalInFlightRequests) {
                    rt.in_flight.fetch_sub(1, std::memory_order_acq_rel);
                    break;
                }
                if (s.global_in_flight.compare_exchange_weak(global_cur, global_cur + 1, std::memory_order_acq_rel))
                    return true;
            }
            continue;
        }
        std::unique_lock<std::mutex> lk(rt.status_mtx);
        rt.cancel_cv.wait_for(lk, std::chrono::milliseconds(10), [&rt, &s, per_audit_cap]() {
            return rt.cancel_flag.load(std::memory_order_acquire) ||
                   rt.transport_circuit_breaker_open.load(std::memory_order_acquire) ||
                   s.shutting_down.load(std::memory_order_acquire) ||
                   (rt.in_flight.load(std::memory_order_acquire) < per_audit_cap &&
                    s.global_in_flight.load(std::memory_order_acquire) < kMaxGlobalInFlightRequests);
        });
    }
}

void release_inflight(audit_runtime_t& rt)
{
    rt.in_flight.fetch_sub(1, std::memory_order_acq_rel);
    state().global_in_flight.fetch_sub(1, std::memory_order_acq_rel);
    rt.cancel_cv.notify_all();
}

struct inflight_guard_t
{
    audit_runtime_t* rt = nullptr;
    bool active = false;

    ~inflight_guard_t()
    {
        if (active)
            release_inflight(*rt);
    }
};

size_t issue_count_for_audit(uint64_t audit_id)
{
    issue_store::initialize();
    issue_filter_t filter;
    filter.has_audit_id = true;
    filter.audit_id = audit_id;
    return issue_store::list(filter).size();
}

void sync_issue_count_from_store(const std::shared_ptr<audit_runtime_t>& rt_ptr, const char* reason)
{
    if (!rt_ptr)
        return;
    const size_t stored = issue_count_for_audit(rt_ptr->status.id);
    std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
    if (stored > rt_ptr->status.issues_found) {
        diag::log_tagged_fmt("scanner", "issue_count_sync audit=%llu reason=%s runtime=%zu stored=%zu",
            static_cast<unsigned long long>(rt_ptr->status.id),
            reason ? reason : "",
            rt_ptr->status.issues_found,
            stored);
        rt_ptr->status.issues_found = stored;
    }
}

scanner::send_fn_t make_send_fn(std::shared_ptr<audit_runtime_t> rt_ptr,
                                const std::string& mod_id,
                                bool count_completed,
                                bool acquire_slot)
{
    return [rt_ptr, mod_id, count_completed, acquire_slot](const std::vector<uint8_t>& raw_req, const scanner::probe_t& probe) -> std::optional<exchange_observed_t> {
        (void)probe;
        if (rt_ptr->cancel_flag.load()) return std::nullopt;
        if (rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("scanner", "send_fn circuit_open audit=%llu module=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str());
            return std::nullopt;
        }
        if (rt_ptr->config.per_module_request_cap > 0 &&
            increment_pmc(*rt_ptr, mod_id) > rt_ptr->config.per_module_request_cap) return std::nullopt;
        const size_t throttle_ms = rt_ptr->config.request_throttle_ms + rt_ptr->transport_backoff_ms.load(std::memory_order_acquire);
        if (throttle_ms > 0) {
            std::unique_lock<std::mutex> lk(rt_ptr->status_mtx);
            if (rt_ptr->cancel_cv.wait_for(lk, std::chrono::milliseconds(throttle_ms), [rt_ptr]() {
                    return rt_ptr->cancel_flag.load(std::memory_order_acquire) ||
                           rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire);
                }))
                return std::nullopt;
        }
        bool slot_acquired = false;
        if (acquire_slot) {
            slot_acquired = wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests);
            if (!slot_acquired) {
                diag::log_tagged_fmt("scanner", "send_fn slot_wait_failed audit=%llu module=%s req_len=%zu tid=%lu",
                    static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(), static_cast<unsigned long>(GetCurrentThreadId()));
                return std::nullopt;
            }
        }
        inflight_guard_t slot_guard{rt_ptr.get(), slot_acquired};
        audit_http::send_options_t opt;
        opt.timeout_ms = rt_ptr->config.timeout_ms;
        opt.follow_redirects = rt_ptr->config.follow_redirects;
        opt.return_first_redirect = true;
        opt.enforce_scope = rt_ptr->config.scope_only;
        opt.publish_exchange = true;
        opt.exchange_source = "scanner";
        const uint64_t started = now_ms();
        const auto before = collect_load_snapshot();
        diag::log_tagged_fmt("scanner", "send_fn begin audit=%llu module=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(),
            before.active_audits, before.running_audits, before.queue_depth, before.in_flight_requests,
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto observed = audit_http::send(raw_req, rt_ptr->status.host, rt_ptr->status.port,
                                         rt_ptr->status.tls, opt);
        const uint64_t elapsed = now_ms() - started;
        if (observed.has_value()) {
            record_transport_result(rt_ptr, true, std::string(), "probe", mod_id);
            diag::log_tagged_fmt("scanner", "send_fn done audit=%llu module=%s status=%d body=%zu elapsed_ms=%llu tid=%lu",
                static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), observed->status_code, observed->resp_body.size(),
                static_cast<unsigned long long>(elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
        } else {
            const std::string socket_error = audit_http::last_error();
            record_transport_result(rt_ptr, false, socket_error, "probe", mod_id);
            diag::log_tagged_fmt("scanner", "send_fn failed audit=%llu module=%s req_len=%zu socket_error=%s elapsed_ms=%llu tid=%lu",
                static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(), socket_error.c_str(),
                static_cast<unsigned long long>(elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
        }
        if (count_completed) {
            std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
            rt_ptr->status.completed_probes++;
        }
        return observed;
    };
}

void emit_issue_safe(std::shared_ptr<audit_runtime_t> rt_ptr, issue_t iss)
{
    iss.audit_id = rt_ptr->status.id;
    if (iss.session_id.empty())
        iss.session_id = rt_ptr->status.session_id;
    if (iss.scan_id == 0)
        iss.scan_id = rt_ptr->status.scan_id != 0 ? rt_ptr->status.scan_id : rt_ptr->status.id;
    iss.host = rt_ptr->status.host;
    iss.port = rt_ptr->status.port;
    iss.scheme = rt_ptr->status.tls ? "https" : "http";
    issue_store::add(std::move(iss));
    std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
    rt_ptr->status.issues_found++;
}

void run_module_for_point(std::shared_ptr<audit_runtime_t> rt_ptr,
                          const scanner::module_t& mod,
                          const insertion_point_t& ip)
{
    diag::log_tagged_fmt("scanner", "run_module_for_point audit=%llu module=%s ip_kind=%s ip_name=%s",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), ip.kind.c_str(), ip.name.c_str());
    if (rt_ptr->cancel_flag.load()) {
        diag::log_tagged_fmt("scanner", "run_module_for_point cancelled early audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        return;
    }
    if (rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("scanner", "run_module_for_point circuit_open early audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        return;
    }

    scanner::module_context_t ctx;
    ctx.audit_id = rt_ptr->status.id;
    ctx.session_id = rt_ptr->status.session_id;
    ctx.scan_id = rt_ptr->status.scan_id != 0 ? rt_ptr->status.scan_id : rt_ptr->status.id;
    ctx.host = rt_ptr->status.host;
    ctx.port = rt_ptr->status.port;
    ctx.tls = rt_ptr->status.tls;
    ctx.url = rt_ptr->status.url;
    ctx.timeout_ms = rt_ptr->config.timeout_ms;
    ctx.follow_redirects = rt_ptr->config.follow_redirects;
    ctx.cancelled = [rt_ptr]() {
        return rt_ptr->cancel_flag.load(std::memory_order_acquire) ||
               rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire);
    };

    audit_http::send_options_t base_opt;
    base_opt.timeout_ms = rt_ptr->config.timeout_ms;
    base_opt.follow_redirects = rt_ptr->config.follow_redirects;
    base_opt.return_first_redirect = true;
    base_opt.enforce_scope = rt_ptr->config.scope_only;
    base_opt.publish_exchange = true;
    base_opt.exchange_source = "scanner";
    if (!wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests)) {
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline_slot_wait_failed audit=%llu module=%s req_len=%zu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), rt_ptr->raw_request.size(), static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    }
    inflight_guard_t baseline_slot_guard{rt_ptr.get(), true};
    const uint64_t baseline_started = now_ms();
    const size_t baseline_throttle_ms = rt_ptr->config.request_throttle_ms + rt_ptr->transport_backoff_ms.load(std::memory_order_acquire);
    if (baseline_throttle_ms > 0) {
        std::unique_lock<std::mutex> lk(rt_ptr->status_mtx);
        if (rt_ptr->cancel_cv.wait_for(lk, std::chrono::milliseconds(baseline_throttle_ms), [rt_ptr]() {
                return rt_ptr->cancel_flag.load(std::memory_order_acquire) ||
                       rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire) ||
                       state().shutting_down.load(std::memory_order_acquire);
            }))
            return;
    }
    const auto baseline_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "run_module_for_point baseline_begin audit=%llu module=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), rt_ptr->raw_request.size(),
        baseline_load.active_audits, baseline_load.running_audits, baseline_load.queue_depth, baseline_load.in_flight_requests,
        static_cast<unsigned long>(GetCurrentThreadId()));
    auto baseline = audit_http::send(rt_ptr->raw_request, rt_ptr->status.host,
                                     rt_ptr->status.port, rt_ptr->status.tls, base_opt);
    release_inflight(*rt_ptr);
    baseline_slot_guard.active = false;
    const uint64_t baseline_elapsed = now_ms() - baseline_started;
    if (baseline.has_value()) {
        record_transport_result(rt_ptr, true, std::string(), "baseline", mod.id);
        ctx.baseline_latency_ms = baseline->latency_ms;
        ctx.baseline_response_body = baseline->resp_body;
        ctx.baseline_response_headers = baseline->resp_headers;
        ctx.baseline_status_code = baseline->status_code;
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline audit=%llu module=%s status=%d latency=%llu body=%zu elapsed_ms=%llu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(),
            baseline->status_code, static_cast<unsigned long long>(baseline->latency_ms), baseline->resp_body.size(),
            static_cast<unsigned long long>(baseline_elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
    } else {
        const std::string socket_error = audit_http::last_error();
        record_transport_result(rt_ptr, false, socket_error, "baseline", mod.id);
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline_failed audit=%llu module=%s socket_error=%s elapsed_ms=%llu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), socket_error.c_str(),
            static_cast<unsigned long long>(baseline_elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
        if (rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("scanner", "run_module_for_point circuit_open after_baseline audit=%llu module=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
            return;
        }
    }

    auto send_fn = make_send_fn(rt_ptr, mod.id, false, false);

    if (mod.custom_run) {
        diag::log_tagged_fmt("scanner", "run_module_for_point custom_run audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        auto custom_send_fn = make_send_fn(rt_ptr, mod.id, true, true);
        mod.custom_run(ip, ctx, custom_send_fn);
        sync_issue_count_from_store(rt_ptr, "custom_run");
        if (rt_ptr->cancel_flag.load() || rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) return;
        if (!mod.probes || !mod.detect) return;
    }

    if (!mod.probes || !mod.detect) {
        diag::log_tagged_fmt("scanner", "run_module_for_point no_probes_or_detect audit=%llu module=%s", static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        return;
    }
    auto probes = mod.probes(ip, ctx);
    int probe_cap = mod.max_probes_per_point > 0 ? mod.max_probes_per_point : 6;
    diag::log_tagged_fmt("scanner", "run_module_for_point probes_generated audit=%llu module=%s ip=%s/%s probe_count=%zu cap=%d",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(),
        ip.kind.c_str(), ip.name.c_str(), probes.size(), probe_cap);
    int issued = 0;
    for (const auto& p : probes) {
        if (rt_ptr->cancel_flag.load() || rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_loop cancelled audit=%llu module=%s issued=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued);
            return;
        }
        if (issued >= probe_cap) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_cap_reached audit=%llu module=%s cap=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), probe_cap);
            break;
        }
        if (!wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests)) {
            diag::log_tagged_fmt("scanner", "run_module_for_point inflight_wait_failed audit=%llu module=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
            return;
        }
        inflight_guard_t probe_slot_guard{rt_ptr.get(), true};

        diag::log_tagged_fmt("scanner", "run_module_for_point sending_probe audit=%llu module=%s probe_idx=%d payload_len=%zu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued, p.payload.size());
        auto built = ip.build ? ip.build(p.payload) : std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
        auto resp = send_fn(built, p);
        release_inflight(*rt_ptr);
        probe_slot_guard.active = false;
        {
            std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
            rt_ptr->status.completed_probes++;
        }
        ++issued;
        if (!resp.has_value()) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_no_response audit=%llu module=%s probe_idx=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued - 1);
            continue;
        }
        diag::log_tagged_fmt("scanner", "run_module_for_point probe_response audit=%llu module=%s probe_idx=%d status=%d body=%zu latency=%llu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued - 1,
            resp->status_code, resp->resp_body.size(), static_cast<unsigned long long>(resp->latency_ms));
        auto maybe = mod.detect(ip, p, *resp, ctx);
        if (maybe.has_value()) {
            diag::log_tagged_fmt("scanner", "run_module_for_point issue_found audit=%llu module=%s type=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), maybe->type_key.c_str());
            emit_issue_safe(rt_ptr, *maybe);
            sync_issue_count_from_store(rt_ptr, "detect");
            break;
        }
    }
    diag::log_tagged_fmt("scanner", "run_module_for_point done audit=%llu module=%s ip=%s/%s issued=%d",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), ip.kind.c_str(), ip.name.c_str(), issued);
}

void terminalize_audit(const std::shared_ptr<audit_runtime_t>& rt_ptr, const char* reason)
{
    if (!rt_ptr)
        return;
    rt_ptr->cancel_flag.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.cancel_requested = true;
        rt_ptr->status.cancelled = true;
    }
    rt_ptr->cancel_cv.notify_all();
    diag::log_tagged_fmt("scanner", "active_scanner audit_terminalized id=%llu reason=%s active_workers=%zu queued_workers=%zu in_flight=%zu",
        static_cast<unsigned long long>(rt_ptr->status.id),
        reason ? reason : "unknown",
        rt_ptr->active_workers.load(std::memory_order_acquire),
        rt_ptr->queued_workers.load(std::memory_order_acquire),
        rt_ptr->in_flight.load(std::memory_order_acquire));
}

void complete_drain_if_ready(const std::shared_ptr<audit_runtime_t>& rt_ptr, const char* reason)
{
    if (!rt_ptr || rt_ptr->audit_worker_active.load(std::memory_order_acquire) ||
        rt_ptr->queued_workers.load(std::memory_order_acquire) != 0 ||
        rt_ptr->active_workers.load(std::memory_order_acquire) != 0 ||
        rt_ptr->in_flight.load(std::memory_order_acquire) != 0)
        return;

    bool expected = false;
    if (!rt_ptr->drain_finalizing.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    sync_issue_count_from_store(rt_ptr, "audit_drained");
    std::shared_ptr<mcp_standalone::downstream::scoped_admission_t> admission;
    uint64_t admission_token = 0;
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.running = false;
        rt_ptr->status.cancel_requested = rt_ptr->status.cancel_requested || rt_ptr->cancel_flag.load(std::memory_order_acquire);
        rt_ptr->status.cancelled = rt_ptr->cancel_flag.load(std::memory_order_acquire);
        rt_ptr->status.drained = true;
        if (rt_ptr->status.ended_ms == 0)
            rt_ptr->status.ended_ms = now_ms();
        admission = std::move(rt_ptr->admission);
        admission_token = rt_ptr->admission_token;
        rt_ptr->admission_token = 0;
    }
    if (admission) {
        diag::log_tagged_fmt("scanner", "BURP-NETWORK-WORKER-RELEASE audit_id=%llu token=%llu reason=%s",
            static_cast<unsigned long long>(rt_ptr->status.id),
            static_cast<unsigned long long>(admission_token),
            reason ? reason : "drained");
        admission->release(reason ? reason : "drained");
    }
    rt_ptr->capacity_owned.store(false, std::memory_order_release);
    rt_ptr->cancel_cv.notify_all();
    diag::log_tagged_fmt("scanner", "active_scanner audit_drained id=%llu reason=%s",
        static_cast<unsigned long long>(rt_ptr->status.id), reason ? reason : "drained");
}

void run_audit_impl(std::shared_ptr<audit_runtime_t> rt_ptr)
{
    auto modules_all = scanner::all_modules();
    std::vector<scanner::module_t> enabled;
    if (rt_ptr->config.enabled_modules.empty()) {
        enabled = std::move(modules_all);
    } else {
        for (auto& m : modules_all) {
            if (std::find(rt_ptr->config.enabled_modules.begin(),
                          rt_ptr->config.enabled_modules.end(),
                          m.id) != rt_ptr->config.enabled_modules.end()) {
                enabled.push_back(std::move(m));
            }
        }
    }

    auto points = insertion_points::analyze(rt_ptr->raw_request, rt_ptr->status.url);
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.total_points = points.size();
        rt_ptr->status.total_probes = points.size() * enabled.size();
    }

    const auto start_load = collect_load_snapshot();
    diag::log_tagged_fmt("burp", "active_scanner audit_start id=%llu points=%zu modules=%zu url=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id),
        points.size(), enabled.size(), rt_ptr->status.url.c_str(), rt_ptr->raw_request.size(),
        start_load.active_audits, start_load.running_audits, start_load.queue_depth, start_load.in_flight_requests,
        static_cast<unsigned long>(GetCurrentThreadId()));

    for (const auto& ip : points) {
        if (rt_ptr->cancel_flag.load() || rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) break;
        for (const auto& mod : enabled) {
            if (rt_ptr->cancel_flag.load() || rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire)) break;
            std::shared_ptr<audit_runtime_t> captured = rt_ptr;
            scanner::module_t mod_copy = mod;
            insertion_point_t ip_copy = ip;
            rt_ptr->queued_workers.fetch_add(1, std::memory_order_acq_rel);
            struct queued_worker_guard_t
            {
                std::shared_ptr<audit_runtime_t> rt;
                bool active = true;

                ~queued_worker_guard_t()
                {
                    if (active) {
                        rt->queued_workers.fetch_sub(1, std::memory_order_acq_rel);
                        rt->cancel_cv.notify_all();
                    }
                }
            } queued_guard{rt_ptr};
            const bool posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.active_scanner";
                sub.label = "active_scanner.probe";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::feature_worker;
                sub.priority = 3;
                sub.body = [captured, mod_copy, ip_copy]() {
                 struct worker_guard_t
                 {
                     std::shared_ptr<audit_runtime_t> rt;
                     explicit worker_guard_t(std::shared_ptr<audit_runtime_t> runtime)
                         : rt(std::move(runtime))
                     {
                         rt->active_workers.fetch_add(1, std::memory_order_acq_rel);
                         rt->queued_workers.fetch_sub(1, std::memory_order_acq_rel);
                         rt->cancel_cv.notify_all();
                     }
                      ~worker_guard_t()
                      {
                          rt->active_workers.fetch_sub(1, std::memory_order_acq_rel);
                          rt->cancel_cv.notify_all();
                          complete_drain_if_ready(rt, "probe_workers_drained");
                      }
                 } guard{captured};
                 try {
                     run_module_for_point(captured, mod_copy, ip_copy);
                 } catch (const std::exception& ex) {
                     diag::log_tagged_fmt("scanner", "active_scanner probe_worker_exception audit=%llu module=%s err=%s",
                         static_cast<unsigned long long>(captured->status.id), mod_copy.id.c_str(), ex.what());
                     terminalize_audit(captured, "probe_worker_exception");
                 } catch (...) {
                     diag::log_tagged_fmt("scanner", "active_scanner probe_worker_exception audit=%llu module=%s err=unknown",
                         static_cast<unsigned long long>(captured->status.id), mod_copy.id.c_str());
                     terminalize_audit(captured, "probe_worker_exception_unknown");
                 }
             };
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
            if (posted)
                queued_guard.active = false;
            if (!posted) {
                diag::log_tagged_fmt("burp", "active_scanner worker_post_failed id=%llu module=%s ip=%s/%s",
                    static_cast<unsigned long long>(rt_ptr->status.id),
                    mod.id.c_str(),
                    ip.kind.c_str(),
                    ip.name.c_str());
                {
                    std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
                    if (rt_ptr->status.completed_probes < rt_ptr->status.total_probes)
                        rt_ptr->status.completed_probes++;
                }
            }
        }
    }

    auto cancel_wait_started = std::chrono::steady_clock::time_point{};
    while (true) {
        const size_t queued_workers = rt_ptr->queued_workers.load(std::memory_order_acquire);
        const size_t active_workers = rt_ptr->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt_ptr->in_flight.load(std::memory_order_acquire);
        if (queued_workers == 0 && active_workers == 0 && in_flight == 0) break;
        if (rt_ptr->cancel_flag.load(std::memory_order_acquire)) {
            if (cancel_wait_started == std::chrono::steady_clock::time_point{})
                cancel_wait_started = std::chrono::steady_clock::now();
            if (std::chrono::steady_clock::now() - cancel_wait_started > std::chrono::seconds(15)) {
                diag::log_tagged_fmt("burp", "active_scanner cancel_drain_timeout id=%llu queued_workers=%zu active_workers=%zu in_flight=%zu",
                    static_cast<unsigned long long>(rt_ptr->status.id), queued_workers, active_workers, in_flight);
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        const bool cancel_requested = rt_ptr->cancel_flag.load();
        rt_ptr->status.cancel_requested = rt_ptr->status.cancel_requested || cancel_requested;
        rt_ptr->status.cancelled = cancel_requested;
        rt_ptr->status.drained = false;
    }
    rt_ptr->cancel_cv.notify_all();
    sync_issue_count_from_store(rt_ptr, "audit_end");
    const auto end_load = collect_load_snapshot();
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.transport_backoff_ms = rt_ptr->transport_backoff_ms.load(std::memory_order_acquire);
        rt_ptr->status.effective_throttle_ms = rt_ptr->config.request_throttle_ms + rt_ptr->status.transport_backoff_ms;
        rt_ptr->status.transport_circuit_breaker_open = rt_ptr->transport_circuit_breaker_open.load(std::memory_order_acquire);
        rt_ptr->status.transport_circuit_breaker_hits = rt_ptr->wsaenobufs_preinit_hits.load(std::memory_order_acquire);
        rt_ptr->status.transport_circuit_breaker_threshold = kWsaEnobufsPreinitCircuitThreshold;
        if (rt_ptr->status.responses_received == 0 && rt_ptr->status.transport_failures > 0) {
            diag::log_tagged_fmt("burp", "active_scanner audit_transport_failed_no_responses id=%llu completed=%zu no_response=%zu failures=%zu transport_error_code=%u transport_error_class=%s circuit_open=%d circuit_hits=%zu last_error=%s",
                static_cast<unsigned long long>(rt_ptr->status.id),
                rt_ptr->status.completed_probes,
                rt_ptr->status.no_response_count,
                rt_ptr->status.transport_failures,
                rt_ptr->status.transport_error_code,
                rt_ptr->status.transport_error_class.c_str(),
                rt_ptr->status.transport_circuit_breaker_open ? 1 : 0,
                rt_ptr->status.transport_circuit_breaker_hits,
                rt_ptr->status.last_transport_error.c_str());
        }
    }
    diag::log_tagged_fmt("burp", "active_scanner audit_coordinator_exit id=%llu issues=%zu responses=%zu no_response=%zu transport_failures=%zu transport_error_code=%u transport_error_class=%s circuit_open=%d circuit_hits=%zu circuit_threshold=%zu last_transport_error=%s cancelled=%d cancel_requested=%d drain_pending=1 active_workers=%zu in_flight=%zu active_audits=%zu running_audits=%zu queue_depth=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id),
        rt_ptr->status.issues_found,
        rt_ptr->status.responses_received,
        rt_ptr->status.no_response_count,
        rt_ptr->status.transport_failures,
        rt_ptr->status.transport_error_code,
        rt_ptr->status.transport_error_class.c_str(),
        rt_ptr->status.transport_circuit_breaker_open ? 1 : 0,
        rt_ptr->status.transport_circuit_breaker_hits,
        rt_ptr->status.transport_circuit_breaker_threshold,
        rt_ptr->status.last_transport_error.c_str(),
        rt_ptr->status.cancelled ? 1 : 0,
        rt_ptr->status.cancel_requested ? 1 : 0,
        rt_ptr->active_workers.load(std::memory_order_acquire),
        rt_ptr->in_flight.load(std::memory_order_acquire),
        end_load.active_audits,
        end_load.running_audits,
        end_load.queue_depth,
        static_cast<unsigned long long>(now_ms() - rt_ptr->status.started_ms),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

void run_audit(std::shared_ptr<audit_runtime_t> rt_ptr)
{
    try {
        run_audit_impl(rt_ptr);
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("scanner", "active_scanner audit_worker_exception audit=%llu err=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), ex.what());
        terminalize_audit(rt_ptr, "audit_worker_exception");
    } catch (...) {
        diag::log_tagged_fmt("scanner", "active_scanner audit_worker_exception audit=%llu err=unknown",
            static_cast<unsigned long long>(rt_ptr->status.id));
        terminalize_audit(rt_ptr, "audit_worker_exception_unknown");
    }
}

}

bool initialize()
{
    diag::log_tagged_fmt("scanner", "active_scanner initialize called");
    auto& s = state();
    std::lock_guard<std::mutex> lifecycle_lock(s.lifecycle_mtx);
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) {
        const bool stopping = s.shutting_down.load(std::memory_order_acquire);
        diag::log_tagged_fmt("scanner", "active_scanner already_initialized shutting_down=%d", stopping ? 1 : 0);
        return !stopping;
    }
    s.shutting_down.store(false, std::memory_order_release);
    diag::log_tagged_fmt("scanner", "active_scanner initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("scanner", "active_scanner shutdown called");
    auto& s = state();
    std::lock_guard<std::mutex> lifecycle_lock(s.lifecycle_mtx);
    if (!s.initialized.load()) {
        diag::log_tagged_fmt("scanner", "active_scanner shutdown skipped not_initialized");
        return;
    }
    bool expected = false;
    if (!s.shutting_down.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        diag::log_tagged_fmt("scanner", "active_scanner shutdown retry already_shutting_down");
    std::vector<std::shared_ptr<audit_runtime_t>> alive;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        for (auto& kv : s.audits) alive.push_back(kv.second);
    }
    diag::log_tagged_fmt("scanner", "active_scanner shutdown cancelling %zu audits", alive.size());
    for (auto& rt : alive) {
        rt->cancel_flag.store(true, std::memory_order_release);
        rt->cancel_cv.notify_all();
    }
    auto t0 = std::chrono::steady_clock::now();
    bool all_done = false;
    while (true) {
        all_done = true;
        for (auto& rt : alive) {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            if (rt->capacity_owned.load(std::memory_order_acquire) || rt->audit_worker_active.load(std::memory_order_acquire) ||
                rt->queued_workers.load(std::memory_order_acquire) != 0 ||
                rt->active_workers.load(std::memory_order_acquire) != 0 ||
                rt->in_flight.load(std::memory_order_acquire) != 0) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;
        if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(5)) {
            diag::log_tagged_fmt("scanner", "active_scanner shutdown timeout waiting for audits");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (all_done) {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        s.audits.clear();
        s.initialized.store(false, std::memory_order_release);
        s.shutting_down.store(false, std::memory_order_release);
    } else {
        diag::log_tagged_fmt("scanner", "active_scanner shutdown incomplete audits=%zu", alive.size());
    }
    diag::log_tagged_fmt("scanner", "active_scanner shutdown complete");
}

uint64_t enqueue_target(const std::vector<uint8_t>& raw_request,
                        const std::string& url,
                        const audit_config_t& cfg)
{
    const uint64_t enqueue_started = now_ms();
    const auto entry_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "enqueue_target url=%s req_len=%zu scope_only=%d timeout=%d modules=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu max_active=%zu tid=%lu",
        url.c_str(), raw_request.size(), cfg.scope_only ? 1 : 0, cfg.timeout_ms, cfg.enabled_modules.size(),
        entry_load.active_audits, entry_load.running_audits, entry_load.queue_depth, entry_load.in_flight_requests, entry_load.max_active_audits,
        static_cast<unsigned long>(GetCurrentThreadId()));
    auto& s = state();
    if (!s.initialized.load() && !initialize()) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected initialize_failed");
        set_err("active_scanner.enqueue: initialization failed");
        return 0;
    }
    if (s.shutting_down.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected shutting_down");
        set_err("active_scanner.enqueue: scanner is shutting down");
        return 0;
    }
    if (raw_request.empty() || url.empty()) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected empty_request=%d empty_url=%d",
            raw_request.empty() ? 1 : 0, url.empty() ? 1 : 0);
        set_err("active_scanner.enqueue: empty request or url");
        return 0;
    }

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected invalid_url=%s", url.c_str());
        set_err("active_scanner.enqueue: invalid url");
        return 0;
    }
    if (cfg.scope_only && !scope::in_scope(url)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected out_of_scope url=%s", url.c_str());
        set_err("active_scanner.enqueue: target out of scope");
        return 0;
    }
    audit_config_t normalized_cfg = cfg;
    const bool external_host = !is_local_or_private_host(host);
    if (external_host && !normalized_cfg.max_concurrent_explicit &&
        normalized_cfg.max_concurrent_requests > kExternalDefaultMaxConcurrentRequests) {
        diag::log_tagged_fmt("scanner", "enqueue_target external_default_concurrency url=%s host=%s requested=%zu effective=%zu",
            url.c_str(), host.c_str(), normalized_cfg.max_concurrent_requests, kExternalDefaultMaxConcurrentRequests);
        normalized_cfg.max_concurrent_requests = kExternalDefaultMaxConcurrentRequests;
    }
    if (external_host && !normalized_cfg.request_throttle_explicit &&
        normalized_cfg.request_throttle_ms < kExternalDefaultThrottleMs) {
        diag::log_tagged_fmt("scanner", "enqueue_target external_default_throttle url=%s host=%s requested=%zu effective=%zu",
            url.c_str(), host.c_str(), normalized_cfg.request_throttle_ms, kExternalDefaultThrottleMs);
        normalized_cfg.request_throttle_ms = kExternalDefaultThrottleMs;
    }
    normalized_cfg.max_concurrent_requests = (std::max)(static_cast<size_t>(1), (std::min)(normalized_cfg.max_concurrent_requests, kMaxPerAuditInFlightRequests));
    auto rt = std::make_shared<audit_runtime_t>();
    rt->config = normalized_cfg;
    rt->raw_request = raw_request;
    rt->status.id = s.next_id.fetch_add(1);
    rt->status.session_id = normalized_cfg.session_id;
    rt->status.scan_id = normalized_cfg.scan_id != 0 ? normalized_cfg.scan_id : rt->status.id;
    rt->status.url = url;
    rt->status.host = host;
    rt->status.port = port;
    rt->status.tls = (scheme == "https");
    rt->status.running = true;
    rt->status.started_ms = now_ms();
    rt->status.request_length = raw_request.size();
    rt->status.effective_max_concurrent = normalized_cfg.max_concurrent_requests;
    rt->status.effective_throttle_ms = normalized_cfg.request_throttle_ms;
    rt->status.transport_circuit_breaker_threshold = kWsaEnobufsPreinitCircuitThreshold;
    rt->capacity_owned.store(true, std::memory_order_release);
    try {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        if (s.shutting_down.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("scanner", "enqueue_target rejected shutting_down_during_admission url=%s", url.c_str());
            set_err("active_scanner.enqueue: scanner is shutting down");
            return 0;
        }
        size_t running_audits = 0;
        size_t queued_workers = 0;
        size_t in_flight = s.global_in_flight.load(std::memory_order_acquire);
        for (auto& kv : s.audits) {
            const auto& existing = kv.second;
            if (!existing)
                continue;
            queued_workers += existing->queued_workers.load(std::memory_order_acquire);
            if (existing->capacity_owned.load(std::memory_order_acquire))
                ++running_audits;
        }
        if (running_audits >= kMaxActiveAudits) {
            diag::log_tagged_fmt("scanner", "enqueue_target rejected busy url=%s req_len=%zu running_audits=%zu active_audits=%zu queue_depth=%zu in_flight=%zu max_active=%zu elapsed_ms=%llu tid=%lu",
                url.c_str(), raw_request.size(), running_audits, s.audits.size(), queued_workers, in_flight, kMaxActiveAudits,
                static_cast<unsigned long long>(now_ms() - enqueue_started), static_cast<unsigned long>(GetCurrentThreadId()));
            set_err("active_scanner.enqueue: scanner busy", "scanner_busy");
            return 0;
        }
        auto inserted = s.audits.emplace(rt->status.id, rt);
        if (!inserted.second) {
            diag::log_tagged_fmt("scanner", "enqueue_target rejected duplicate_id=%llu", static_cast<unsigned long long>(rt->status.id));
            set_err("active_scanner.enqueue: duplicate audit id");
            return 0;
        }
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("scanner", "enqueue_target audit_map_insert_exception id=%llu err=%s",
            static_cast<unsigned long long>(rt->status.id), ex.what());
        set_err("active_scanner.enqueue: audit registration failed");
        return 0;
    } catch (...) {
        diag::log_tagged_fmt("scanner", "enqueue_target audit_map_insert_exception id=%llu err=unknown",
            static_cast<unsigned long long>(rt->status.id));
        set_err("active_scanner.enqueue: audit registration failed");
        return 0;
    }

    const auto queued_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "enqueue_target queued audit_id=%llu scan_id=%llu session_present=%d host=%s port=%u tls=%d req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(rt->status.id),
        static_cast<unsigned long long>(rt->status.scan_id),
        rt->status.session_id.empty() ? 0 : 1,
        host.c_str(), port, rt->status.tls ? 1 : 0, raw_request.size(),
        queued_load.active_audits, queued_load.running_audits, queued_load.queue_depth, queued_load.in_flight_requests,
        static_cast<unsigned long long>(now_ms() - enqueue_started), static_cast<unsigned long>(GetCurrentThreadId()));

    std::shared_ptr<audit_runtime_t> captured = rt;
    mcp_standalone::downstream::producer_identity_t admission_id;
    admission_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
    admission_id.tool_name = "active_scanner.run_audit";
    admission_id.domain = host;
    auto admission = mcp_standalone::downstream::scoped_admission_t::acquire(admission_id);
    if (!admission.active()) {
        diag::log_tagged_fmt("scanner", "BURP-NETWORK-WORKER-REJECT audit_id=%llu host=%s reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            static_cast<unsigned long long>(rt->status.id), host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().quota_scope.c_str(),
            admission.result().observed, admission.result().limit);
        {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            rt->status.running = false;
            rt->status.cancelled = true;
            rt->status.cancel_requested = true;
            rt->status.drained = true;
            rt->status.ended_ms = now_ms();
        }
        rt->cancel_flag.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(s.audits_mtx);
            s.audits.erase(rt->status.id);
        }
        set_err("active_scanner.enqueue: downstream capacity exhausted");
        return 0;
    }
    const uint64_t admission_token = admission.token();
    auto admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(admission));
    {
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        rt->admission = admission_ptr;
        rt->admission_token = admission_token;
    }
    diag::log_tagged_fmt("scanner", "BURP-NETWORK-WORKER-ADMIT audit_id=%llu host=%s token=%llu",
        static_cast<unsigned long long>(rt->status.id), host.c_str(),
        static_cast<unsigned long long>(admission_token));
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "burp.active_scanner";
    sub.label = "active_scanner.run_audit";
    sub.thread_class = "long_running";
    sub.domain = aida::infra::executor::domain_t::long_running;
    sub.priority = 3;
    sub.lease_token = admission_token;
    sub.body = [captured]() {
        struct audit_worker_guard_t
        {
            std::shared_ptr<audit_runtime_t> rt;

            ~audit_worker_guard_t()
            {
                rt->audit_worker_active.store(false, std::memory_order_release);
                rt->cancel_cv.notify_all();
                complete_drain_if_ready(rt, "audit_worker_exit");
            }
        } audit_worker_guard{captured};
        run_audit(captured);
    };
    rt->audit_worker_active.store(true, std::memory_order_release);
    const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
    if (!posted) {
        rt->audit_worker_active.store(false, std::memory_order_release);
        admission_ptr->release("worker_post_failed");
        rt->capacity_owned.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            rt->status.running = false;
            rt->status.cancelled = true;
            rt->status.cancel_requested = true;
            rt->status.drained = true;
            rt->status.ended_ms = now_ms();
        }
        rt->cancel_flag.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            rt->admission.reset();
            rt->admission_token = 0;
        }
        {
            std::lock_guard<std::mutex> lk(s.audits_mtx);
            s.audits.erase(rt->status.id);
        }
        diag::log_tagged_fmt("scanner", "enqueue_target worker_post_failed audit_id=%llu",
            static_cast<unsigned long long>(rt->status.id));
        set_err("active_scanner.enqueue: worker queue unavailable");
        return 0;
    }

    return rt->status.id;
}

bool cancel_audit(uint64_t audit_id)
{
    diag::log_tagged_fmt("scanner", "cancel_audit id=%llu", static_cast<unsigned long long>(audit_id));
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "cancel_audit id=%llu not_found", static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }
    rt->cancel_flag.store(true);
    {
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        rt->status.cancel_requested = true;
    }
    rt->cancel_cv.notify_all();
    diag::log_tagged_fmt("scanner", "cancel_audit id=%llu cancel_flag_set", static_cast<unsigned long long>(audit_id));
    return true;
}

bool wait_for_audit_idle(uint64_t audit_id, uint32_t timeout_ms)
{
    diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu timeout_ms=%u",
        static_cast<unsigned long long>(audit_id),
        timeout_ms);
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu not_found",
                static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
        const bool running = rt->capacity_owned.load(std::memory_order_acquire);
        const size_t queued_workers = rt->queued_workers.load(std::memory_order_acquire);
        if (!running && queued_workers == 0 && active_workers == 0 && in_flight == 0) {
            {
                std::lock_guard<std::mutex> lk(rt->status_mtx);
                rt->status.drained = true;
            }
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu idle",
                static_cast<unsigned long long>(audit_id));
            return true;
        }
        if (timeout_ms == 0 || std::chrono::steady_clock::now() >= deadline) {
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu timeout running=%d queued_workers=%zu active_workers=%zu in_flight=%zu",
                static_cast<unsigned long long>(audit_id),
                running ? 1 : 0,
                queued_workers,
                active_workers,
                in_flight);
            return false;
        }
        std::unique_lock<std::mutex> lk(rt->status_mtx);
        rt->cancel_cv.wait_for(lk, std::chrono::milliseconds(50));
    }
}

std::vector<audit_status_t> list_audits()
{
    auto& s = state();
    std::vector<audit_status_t> out;
    std::vector<std::shared_ptr<audit_runtime_t>> alive;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        for (auto& kv : s.audits) alive.push_back(kv.second);
    }
    for (auto& rt : alive) {
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
        const size_t queued_workers = rt->queued_workers.load(std::memory_order_acquire);
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        rt->status.transport_backoff_ms = rt->transport_backoff_ms.load(std::memory_order_acquire);
        rt->status.effective_throttle_ms = rt->config.request_throttle_ms + rt->status.transport_backoff_ms;
        rt->status.transport_circuit_breaker_open = rt->transport_circuit_breaker_open.load(std::memory_order_acquire);
        rt->status.transport_circuit_breaker_hits = rt->wsaenobufs_preinit_hits.load(std::memory_order_acquire);
        rt->status.transport_circuit_breaker_threshold = kWsaEnobufsPreinitCircuitThreshold;
        audit_status_t st = rt->status;
        st.cancel_requested = st.cancel_requested || rt->cancel_flag.load(std::memory_order_acquire);
        st.running = rt->capacity_owned.load(std::memory_order_acquire);
        st.drained = !st.running && queued_workers == 0 && active_workers == 0 && in_flight == 0;
        st.active_workers = active_workers;
        st.queued_workers = queued_workers;
        st.in_flight_requests = in_flight;
        if (st.cancel_requested)
            rt->status.cancel_requested = true;
        if (st.drained)
            rt->status.drained = true;
        out.push_back(std::move(st));
    }
    std::sort(out.begin(), out.end(), [](const audit_status_t& a, const audit_status_t& b) {
        return a.started_ms > b.started_ms;
    });
    return out;
}

bool get_status(uint64_t audit_id, audit_status_t& out)
{
    diag::log_tagged_fmt("scanner", "get_status id=%llu", static_cast<unsigned long long>(audit_id));
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "get_status id=%llu not_found", static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }
    const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
    const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
    const size_t queued_workers = rt->queued_workers.load(std::memory_order_acquire);
    std::lock_guard<std::mutex> lk(rt->status_mtx);
    rt->status.transport_backoff_ms = rt->transport_backoff_ms.load(std::memory_order_acquire);
    rt->status.effective_throttle_ms = rt->config.request_throttle_ms + rt->status.transport_backoff_ms;
    rt->status.transport_circuit_breaker_open = rt->transport_circuit_breaker_open.load(std::memory_order_acquire);
    rt->status.transport_circuit_breaker_hits = rt->wsaenobufs_preinit_hits.load(std::memory_order_acquire);
    rt->status.transport_circuit_breaker_threshold = kWsaEnobufsPreinitCircuitThreshold;
    out = rt->status;
    out.cancel_requested = out.cancel_requested || rt->cancel_flag.load(std::memory_order_acquire);
    out.running = rt->capacity_owned.load(std::memory_order_acquire);
    out.drained = !out.running && queued_workers == 0 && active_workers == 0 && in_flight == 0;
    out.active_workers = active_workers;
    out.queued_workers = queued_workers;
    out.in_flight_requests = in_flight;
    if (out.drained)
        rt->status.drained = true;
    if (out.cancel_requested)
        rt->status.cancel_requested = true;
    diag::log_tagged_fmt("scanner", "get_status id=%llu running=%d issues=%zu completed=%zu total=%zu responses=%zu no_response=%zu transport_failures=%zu transport_error_code=%u transport_error_class=%s circuit_open=%d circuit_hits=%zu circuit_threshold=%zu last_transport_error=%s cancel_requested=%d drained=%d req_len=%zu queued_workers=%zu active_workers=%zu in_flight=%zu effective_concurrency=%zu effective_throttle_ms=%zu tid=%lu",
        static_cast<unsigned long long>(audit_id), out.running ? 1 : 0,
        out.issues_found, out.completed_probes, out.total_probes,
        out.responses_received,
        out.no_response_count,
        out.transport_failures,
        out.transport_error_code,
        out.transport_error_class.c_str(),
        out.transport_circuit_breaker_open ? 1 : 0,
        out.transport_circuit_breaker_hits,
        out.transport_circuit_breaker_threshold,
        out.last_transport_error.c_str(),
        out.cancel_requested ? 1 : 0,
        out.drained ? 1 : 0,
        out.request_length,
        queued_workers,
        active_workers,
        in_flight,
        out.effective_max_concurrent,
        out.effective_throttle_ms,
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

scanner_load_t load_snapshot()
{
    const auto load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "load_snapshot active_audits=%zu running_audits=%zu queue_depth=%zu active_workers=%zu in_flight=%zu max_active=%zu shutting_down=%d tid=%lu",
        load.active_audits,
        load.running_audits,
        load.queue_depth,
        load.active_workers,
        load.in_flight_requests,
        load.max_active_audits,
        load.shutting_down ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()));
    return load;
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error;
}

std::string last_error_code()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error_code;
}

}
}
}
