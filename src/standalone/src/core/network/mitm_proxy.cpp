#include "mitm_proxy.hpp"
#include "cert_generator.hpp"
#include "standalone_driver.hpp"
#include "protocol_parser.hpp"
#include "http_parser_engine.hpp"
#include "http2_session.hpp"
#include "map_resource.hpp"
#include "server_replay.hpp"
#include "tls_policy.hpp"
#include "pac_resolver.hpp"
#include "conn_pool.hpp"
#include "script_engine.hpp"
#include "../infra/executor.hpp"
#include "../infra/event_bus.hpp"
#include "../infra/win_thread.hpp"
#include "helpers/diag_log.hpp"
#include "burp/burp_events.hpp"
#include "burp/cookie_jar.hpp"
#include "burp/match_replace.hpp"
#include "burp/session_handler.hpp"
#include "burp/upstream_chain.hpp"

#include <chrono>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

namespace mitm_proxy {

struct wsa_guard_t {
    WSADATA data{};
    bool ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;


static void publish_exchange_event(const http_exchange& ex) {
    aida::burp::exchange_observed_t e;
    e.id = ex.id;
    e.timestamp_ms = ex.timestamp;
    e.method = ex.request.method;
    e.scheme = ex.is_tls ? std::string("https") : std::string("http");
    if (e.scheme == "https" && ex.is_websocket) e.scheme = "wss";
    else if (e.scheme == "http" && ex.is_websocket) e.scheme = "ws";
    e.host = ex.target_host;
    e.port = ex.target_port;

    std::string raw_uri = ex.request.uri;
    size_t qmark = raw_uri.find('?');
    if (qmark == std::string::npos) {
        e.path = raw_uri;
    } else {
        e.path = raw_uri.substr(0, qmark);
        e.query = raw_uri.substr(qmark + 1);
    }

    e.req_headers.reserve(ex.request.headers.size());
    for (const auto& h : ex.request.headers)
        e.req_headers.emplace_back(h.name, h.value);
    e.req_body = ex.request.body;

    e.status_code = ex.response.status_code;
    e.reason_phrase = ex.response.reason;
    e.resp_headers.reserve(ex.response.headers.size());
    for (const auto& h : ex.response.headers)
        e.resp_headers.emplace_back(h.name, h.value);
    e.resp_body = ex.response.body;
    e.latency_ms = ex.latency_ms;
    e.is_websocket = ex.is_websocket;
    e.is_h2 = ex.is_h2;
    e.tls_version = ex.tls_version_str;
    e.alpn = ex.alpn_protocol;
    e.client_addr = ex.client_addr;
    e.client_port = ex.client_port;

    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "network.mitm";
    sub.label = "mitm.exchange_observed";
    sub.thread_class = "bounded_task";
    sub.domain = aida::infra::executor::domain_t::feature_worker;
    sub.priority = 3;
    sub.body = [copy = std::move(e)]() mutable {
        aida::events::publish(aida::burp::kExchangeObservedEvent, copy);
    };
    (void)aida::infra::executor::submit(std::move(sub));
}


static std::string addr_to_string(const sockaddr_in& addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return buf;
}

static void close_socket(SOCKET s) {
    if (s != INVALID_SOCKET) {
        ::shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

static void set_shutdown_bounded_io(SOCKET s) {
    constexpr DWORD timeout_ms = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
}

const char* to_string(tls_observation_kind_t kind) {
    switch (kind) {
    case tls_observation_kind_t::http_tls: return "http_tls";
    case tls_observation_kind_t::client_handshake_failed: return "client_handshake_failed";
    case tls_observation_kind_t::upstream_handshake_failed: return "upstream_handshake_failed";
    case tls_observation_kind_t::upstream_pin_mismatch: return "upstream_pin_mismatch";
    case tls_observation_kind_t::sni_authority_mismatch: return "sni_authority_mismatch";
    case tls_observation_kind_t::non_http_tls: return "non_http_tls";
    case tls_observation_kind_t::tunnel_passthrough: return "tunnel_passthrough";
    default: return "unknown";
    }
}

static std::string openssl_error_text() {
    unsigned long code = ERR_get_error();
    if (code == 0) return std::string();
    char buf[256] = {};
    ERR_error_string_n(code, buf, sizeof(buf));
    return std::string(buf);
}

static void record_tls_observation(state_t& state,
                                   tls_observation_kind_t kind,
                                   const std::string& target_host,
                                   uint16_t target_port,
                                   const std::string& client_addr,
                                   uint16_t client_port,
                                   const std::string& sni,
                                   const std::string& alpn,
                                   const std::string& detail) {
    tls_observation_t obs;
    obs.timestamp = GetTickCount64();
    obs.kind = kind;
    obs.target_host = target_host;
    obs.target_port = target_port;
    obs.client_addr = client_addr;
    obs.client_port = client_port;
    obs.sni = sni;
    obs.alpn = alpn;
    obs.detail = detail;
    {
        std::lock_guard<std::mutex> lock(state.tls_observation_mutex);
        state.tls_observations.push_back(obs);
        while (state.tls_observations.size() > 256)
            state.tls_observations.pop_front();
    }
    diag::log_tagged_fmt("mitm", "tls_observation kind=%s host=%s:%u sni=%s alpn=%s detail=%s",
        to_string(kind), target_host.c_str(), target_port, sni.c_str(), alpn.c_str(), detail.c_str());
}


struct hold_outcome_t {
    hold_decision_t       decision = hold_decision_t::forward;
    std::vector<uint8_t>  modified_request;
};

static hold_outcome_t hold_until_decision(state_t& state, http_exchange exchange) {
    diag::log_tagged_fmt("mitm", "hold_until_decision entry exchange_id=%llu method=%s uri=%s host=%s",
        static_cast<unsigned long long>(exchange.id), exchange.request.method.c_str(), exchange.request.uri.c_str(), exchange.target_host.c_str());
    auto wait = std::make_shared<held_wait_t>();
    uint64_t exchange_id = exchange.id;

    http_exchange* held_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(state.held_mutex);
        state.held_storage.push_back(std::move(exchange));
        held_ptr = &state.held_storage.back();
        state.held_exchanges.push_back(held_ptr);
        state.held_waits.emplace(exchange_id, wait);
    }
    state.held_cv.notify_all();

    bool released = false;
    hold_decision_t decision = hold_decision_t::forward;
    std::vector<uint8_t> modified;
    {
        std::unique_lock<std::mutex> wlock(wait->mtx);
        wait->cv.wait(wlock, [&wait, &state]() {
            return wait->released || !state.running.load() || !state.proxy_alive.load();
        });
        released = wait->released;
        decision = wait->decision;
        modified = std::move(wait->modified_request);
    }

    {
        std::lock_guard<std::mutex> lock(state.held_mutex);
        if (held_ptr) {
            auto vit = std::find(state.held_exchanges.begin(), state.held_exchanges.end(), held_ptr);
            if (vit != state.held_exchanges.end())
                state.held_exchanges.erase(vit);

            auto wit = state.held_waits.find(exchange_id);
            if (wit != state.held_waits.end())
                state.held_waits.erase(wit);

            for (auto it = state.held_storage.begin(); it != state.held_storage.end(); ++it) {
                if (&(*it) == held_ptr) {
                    state.held_storage.erase(it);
                    break;
                }
            }
        }
    }

    hold_outcome_t outcome;
    if (!released) {
        outcome.decision = hold_decision_t::drop;
        diag::log_tagged_fmt("mitm", "hold_until_decision proxy stopped exchange_id=%llu -> drop", static_cast<unsigned long long>(exchange_id));
    } else if (decision == hold_decision_t::pending) {
        outcome.decision = hold_decision_t::forward;
        diag::log_tagged_fmt("mitm", "hold_until_decision exchange_id=%llu decision=pending -> forward", static_cast<unsigned long long>(exchange_id));
    } else {
        outcome.decision = decision;
        diag::log_tagged_fmt("mitm", "hold_until_decision exchange_id=%llu decision=%d modified_size=%zu",
            static_cast<unsigned long long>(exchange_id), (int)decision, modified.size());
    }
    outcome.modified_request = std::move(modified);
    return outcome;
}

static constexpr uint8_t kCrlfCrlf[4] = { '\r', '\n', '\r', '\n' };

static std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(::tolower(c));
    });
    return value;
}

static std::string trim_ascii(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])))
        ++begin;
    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;
    return value.substr(begin, end - begin);
}

static bool starts_with_ci(const std::string& value, const std::string& prefix) {
    if (value.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (::tolower(static_cast<unsigned char>(value[i])) !=
            ::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

static bool constant_time_equal(const std::string& a, const std::string& b) {
    const size_t n = std::max(a.size(), b.size());
    unsigned char diff = static_cast<unsigned char>(a.size() ^ b.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned char av = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char bv = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<unsigned char>(av ^ bv);
    }
    return diff == 0;
}

static std::string base64_encode_text(const std::string& value) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((value.size() + 2) / 3) * 4);
    for (size_t i = 0; i < value.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(value[i])) << 16;
        if (i + 1 < value.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(value[i + 1])) << 8;
        if (i + 2 < value.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(value[i + 2]));
        encoded.push_back(b64[(n >> 18) & 0x3F]);
        encoded.push_back(b64[(n >> 12) & 0x3F]);
        encoded.push_back((i + 1 < value.size()) ? b64[(n >> 6) & 0x3F] : '=');
        encoded.push_back((i + 2 < value.size()) ? b64[n & 0x3F] : '=');
    }
    return encoded;
}

static bool proxy_authorization_valid(const protocol_parser::http_request& req, const proxy_config& config) {
    if (!config.require_proxy_auth)
        return true;
    if (config.proxy_auth_username.empty() || config.proxy_auth_password.empty())
        return false;
    std::string value = trim_ascii(protocol_parser::find_header(req.headers, "Proxy-Authorization"));
    if (!starts_with_ci(value, "Basic "))
        return false;
    value = trim_ascii(value.substr(6));
    const std::string expected = base64_encode_text(config.proxy_auth_username + ":" + config.proxy_auth_password);
    return constant_time_equal(value, expected);
}

static void send_proxy_auth_required(SOCKET client_sock, const proxy_config& config) {
    std::string realm = config.proxy_auth_realm.empty() ? std::string("AiDA Proxy") : config.proxy_auth_realm;
    for (char& c : realm) {
        if (c == '"' || c == '\r' || c == '\n')
            c = '_';
    }
    const std::string body = "Proxy authentication required";
    std::ostringstream resp;
    resp << "HTTP/1.1 407 Proxy Authentication Required\r\n"
         << "Proxy-Authenticate: Basic realm=\"" << realm << "\"\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << body;
    const std::string bytes = resp.str();
    send(client_sock, bytes.data(), static_cast<int>(bytes.size()), 0);
}

static size_t header_end_offset(const std::vector<uint8_t>& data) {
    auto it = std::search(data.begin(), data.end(), kCrlfCrlf, kCrlfCrlf + 4);
    if (it == data.end())
        return std::string::npos;
    return static_cast<size_t>(std::distance(data.begin(), it)) + 4;
}

static std::string origin_form_from_uri(const std::string& uri) {
    if (uri.rfind("http://", 0) != 0 && uri.rfind("https://", 0) != 0)
        return uri.empty() ? std::string("/") : uri;
    const size_t scheme_end = uri.find("://");
    const size_t path = uri.find('/', scheme_end == std::string::npos ? 0 : scheme_end + 3);
    if (path == std::string::npos)
        return "/";
    return uri.substr(path);
}

static bool rewrite_request_headers(std::vector<uint8_t>& raw,
                                    const std::map<std::string, std::string>& set_headers,
                                    const std::unordered_set<std::string>& remove_headers,
                                    bool normalize_absolute_uri) {
    const size_t header_end = header_end_offset(raw);
    if (header_end == std::string::npos)
        return false;
    std::string headers(raw.begin(), raw.begin() + static_cast<ptrdiff_t>(header_end));
    const size_t line_end = headers.find("\r\n");
    if (line_end == std::string::npos)
        return false;
    std::string first_line = headers.substr(0, line_end);
    if (normalize_absolute_uri) {
        const size_t sp1 = first_line.find(' ');
        const size_t sp2 = sp1 == std::string::npos ? std::string::npos : first_line.find(' ', sp1 + 1);
        if (sp1 != std::string::npos && sp2 != std::string::npos) {
            const std::string method = first_line.substr(0, sp1);
            const std::string uri = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            const std::string version = first_line.substr(sp2 + 1);
            first_line = method + " " + origin_form_from_uri(uri) + " " + version;
        }
    }
    std::ostringstream out;
    out << first_line << "\r\n";
    std::unordered_set<std::string> emitted;
    size_t pos = line_end + 2;
    while (pos + 2 <= headers.size()) {
        const size_t next = headers.find("\r\n", pos);
        if (next == std::string::npos || next == pos)
            break;
        const std::string line = headers.substr(pos, next - pos);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string name = line.substr(0, colon);
            const std::string lname = lower_ascii(name);
            if (remove_headers.find(lname) != remove_headers.end()) {
                pos = next + 2;
                continue;
            }
            auto sit = set_headers.find(lname);
            if (sit != set_headers.end()) {
                out << name << ": " << sit->second << "\r\n";
                emitted.insert(lname);
                pos = next + 2;
                continue;
            }
        }
        out << line << "\r\n";
        pos = next + 2;
    }
    for (const auto& kv : set_headers) {
        if (emitted.find(kv.first) == emitted.end())
            out << kv.first << ": " << kv.second << "\r\n";
    }
    out << "\r\n";
    const std::string head = out.str();
    std::vector<uint8_t> rewritten(head.begin(), head.end());
    rewritten.insert(rewritten.end(), raw.begin() + static_cast<ptrdiff_t>(header_end), raw.end());
    raw.swap(rewritten);
    return true;
}

static void remove_proxy_headers(std::vector<uint8_t>& raw) {
    std::unordered_set<std::string> remove = {"proxy-authorization", "proxy-connection"};
    std::map<std::string, std::string> set;
    rewrite_request_headers(raw, set, remove, true);
}

static std::string path_from_request_uri(const std::string& uri) {
    return origin_form_from_uri(uri.empty() ? std::string("/") : uri);
}

static std::string exchange_url_for_session(const http_exchange& exchange) {
    std::ostringstream out;
    out << (exchange.is_tls ? "https://" : "http://") << exchange.target_host;
    if ((exchange.is_tls && exchange.target_port != 443) || (!exchange.is_tls && exchange.target_port != 80))
        out << ':' << exchange.target_port;
    const std::string path = path_from_request_uri(exchange.request.uri);
    if (path.empty() || path[0] != '/')
        out << '/';
    out << path;
    return out.str();
}

static void apply_sticky_session_request(const proxy_config& config, http_exchange& exchange, std::vector<uint8_t>& request_data) {
    if (!config.enable_sticky_sessions)
        return;
    const std::string path = path_from_request_uri(exchange.request.uri);
    const std::string cookie = aida::burp::cookie_jar::build_cookie_header(exchange.target_host, path, exchange.is_tls);
    std::map<std::string, std::string> set;
    if (!cookie.empty())
        set["cookie"] = cookie;
    std::unordered_set<std::string> remove = {"proxy-authorization", "proxy-connection"};
    rewrite_request_headers(request_data, set, remove, true);
    aida::burp::session_handler::apply_rules(request_data, exchange_url_for_session(exchange), 0);
    exchange.raw_request = request_data;
    exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
}

static void apply_sticky_session_response(const proxy_config& config, const http_exchange& exchange) {
    if (!config.enable_sticky_sessions || !exchange.response.valid)
        return;
    std::vector<std::pair<std::string, std::string>> headers;
    headers.reserve(exchange.response.headers.size());
    for (const auto& h : exchange.response.headers)
        headers.emplace_back(h.name, h.value);
    aida::burp::cookie_jar::ingest_set_cookie_headers(exchange.target_host, headers);
}

static void add_tags(http_exchange& exchange, const std::vector<std::string>& tags) {
    for (const auto& tag : tags) {
        if (!tag.empty() && std::find(exchange.tags.begin(), exchange.tags.end(), tag) == exchange.tags.end())
            exchange.tags.push_back(tag);
    }
}

static void record_history(state_t& state, const proxy_config& config, http_exchange exchange) {
    publish_exchange_event(exchange);
    std::lock_guard<std::mutex> lock(state.history_mutex);
    state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
    while (state.history.size() > config.max_history)
        state.history.pop_front();
}

static std::vector<uint8_t> build_error_response(uint16_t status, const std::string& reason, const std::string& body) {
    std::ostringstream out;
    out << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
        << "Content-Type: text/plain; charset=utf-8\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    const std::string text = out.str();
    return std::vector<uint8_t>(text.begin(), text.end());
}

static bool recv_all(SOCKET s, std::vector<uint8_t>& out, size_t max_size, int timeout_ms = 5000) {
    fd_set fds;
    timeval tv;

    out.clear();
    out.reserve(4096);

    while (out.size() < max_size) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        FD_ZERO(&fds);
        FD_SET(s, &fds);

        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) break;

        uint8_t buf[8192];
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);


        if (out.size() >= 4) {
            auto it = std::search(out.begin(), out.end(), kCrlfCrlf, kCrlfCrlf + 4);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}

static bool recv_ssl_all(SSL* ssl, std::vector<uint8_t>& out, size_t max_size) {
    out.clear();
    out.reserve(4096);

    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    while (out.size() < max_size) {
        uint8_t buf[8192];
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                WSAPOLLFD pfd{};
                pfd.fd = fd;
                pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
                int pr = WSAPoll(&pfd, 1, 30000);
                if (pr <= 0) break;
                continue;
            }
            break;
        }
        out.insert(out.end(), buf, buf + n);


        if (out.size() >= 4) {
            auto it = std::search(out.begin(), out.end(), kCrlfCrlf, kCrlfCrlf + 4);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}


static size_t parse_content_length(const std::string& headers) {
    auto find_ci = [](const std::string& h, const char* needle, size_t needle_len) -> size_t {
        if (needle_len == 0 || h.size() < needle_len) return std::string::npos;
        for (size_t i = 0; i + needle_len <= h.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle_len; ++j) {
                char a = static_cast<char>(::tolower(static_cast<unsigned char>(h[i + j])));
                char b = static_cast<char>(::tolower(static_cast<unsigned char>(needle[j])));
                if (a != b) { match = false; break; }
            }
            if (match) return i;
        }
        return std::string::npos;
    };
    static const char kCl[] = "content-length:";
    size_t cl_pos = find_ci(headers, kCl, sizeof(kCl) - 1);
    if (cl_pos == std::string::npos) return 0;
    size_t val_start = cl_pos + (sizeof(kCl) - 1);
    while (val_start < headers.size() && (headers[val_start] == ' ' || headers[val_start] == '\t')) val_start++;
    size_t val_end = headers.find("\r\n", val_start);
    if (val_end == std::string::npos) return 0;
    std::string val_str = headers.substr(val_start, val_end - val_start);
    char* end = nullptr;
    errno = 0;
    unsigned long long v = strtoull(val_str.c_str(), &end, 10);
    if (errno != 0 || end == val_str.c_str() || v > static_cast<unsigned long long>(SIZE_MAX)) return 0;
    return static_cast<size_t>(v);
}

static void read_remaining_body_ssl(SSL* ssl, std::vector<uint8_t>& data, size_t max_size) {
    auto hdr_end = std::search(data.begin(), data.end(), kCrlfCrlf, kCrlfCrlf + 4);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));


    bool is_chunked = false;
    {
        std::string headers_lower = headers;
        std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(),
            [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        is_chunked = (headers_lower.find("transfer-encoding: chunked") != std::string::npos);
    }

    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));

    auto ssl_read_one = [&](uint8_t* buf, int max_n) -> int {
        while (true) {
            int n = SSL_read(ssl, buf, max_n);
            if (n > 0) return n;
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                WSAPOLLFD pfd{};
                pfd.fd = fd;
                pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
                int pr = WSAPoll(&pfd, 1, 30000);
                if (pr <= 0) return -1;
                continue;
            }
            return -1;
        }
    };

    if (is_chunked) {

        while (data.size() < max_size) {

            if (data.size() >= hdr_size + 5) {
                std::string body_str(data.begin() + static_cast<ptrdiff_t>(hdr_size), data.end());
                if (body_str.find("\r\n0\r\n\r\n") != std::string::npos ||
                    (body_str.size() >= 5 && body_str.compare(0, 5, "0\r\n\r\n") == 0)) break;
            }

            uint8_t buf[8192];
            int n = ssl_read_one(buf, sizeof(buf));
            if (n <= 0) break;
            data.insert(data.end(), buf, buf + n);
        }
    } else {

        size_t content_length = parse_content_length(headers);
        if (content_length > 0) {
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            while (data.size() < total_needed) {
                uint8_t buf[8192];
                int remaining = static_cast<int>(std::min(sizeof(buf), total_needed - data.size()));
                int n = ssl_read_one(buf, remaining);
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}

static void read_remaining_body(SOCKET s, std::vector<uint8_t>& data, size_t max_size, int timeout_ms = 5000) {
    auto hdr_end = std::search(data.begin(), data.end(), kCrlfCrlf, kCrlfCrlf + 4);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));


    bool is_chunked = false;
    {
        std::string headers_lower = headers;
        std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(),
            [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        is_chunked = (headers_lower.find("transfer-encoding: chunked") != std::string::npos);
    }

    fd_set fds;
    timeval tv;

    if (is_chunked) {
        while (data.size() < max_size) {
            if (data.size() >= hdr_size + 5) {
                std::string body_str(data.begin() + static_cast<ptrdiff_t>(hdr_size), data.end());
                if (body_str.find("\r\n0\r\n\r\n") != std::string::npos ||
                    (body_str.size() >= 5 && body_str.compare(0, 5, "0\r\n\r\n") == 0)) break;
            }

            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) break;

            uint8_t buf[8192];
            int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n <= 0) break;
            data.insert(data.end(), buf, buf + n);
        }
    } else {
        size_t content_length = parse_content_length(headers);
        if (content_length > 0) {
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            while (data.size() < total_needed) {
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                FD_ZERO(&fds);
                FD_SET(s, &fds);
                int sel = select(0, &fds, nullptr, nullptr, &tv);
                if (sel <= 0) break;

                uint8_t buf[8192];
                int n = recv(s, reinterpret_cast<char*>(buf),
                    static_cast<int>(std::min(sizeof(buf), total_needed - data.size())), 0);
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}


static bool parse_uint16(const std::string& s, uint16_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long v = strtoul(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || v == 0 || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

static void parse_connect_target(const std::string& line, std::string& host, uint16_t& port) {

    size_t sp = line.find(' ');
    if (sp == std::string::npos) return;
    size_t sp2 = line.find(' ', sp + 1);
    std::string target = (sp2 != std::string::npos) ? line.substr(sp + 1, sp2 - sp - 1) : line.substr(sp + 1);

    size_t colon = target.rfind(':');
    if (colon != std::string::npos) {
        host = target.substr(0, colon);
        uint16_t parsed_port = 0;
        if (!parse_uint16(target.substr(colon + 1), parsed_port)) {
            port = 443;
            return;
        }
        port = parsed_port;
    } else {
        host = target;
        port = 443;
    }
}


static SOCKET try_connect_address(const sockaddr* addr, int addr_len, int family, int socktype, int proto,
                                  int connect_timeout_ms = 10000, DWORD io_timeout_ms = 30000) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("mitm",
        "try_connect_address ENTER family=%d socktype=%d proto=%d connect_timeout_ms=%d io_timeout_ms=%lu",
        family, socktype, proto, connect_timeout_ms, static_cast<unsigned long>(io_timeout_ms));
    SOCKET s = socket(family, socktype, proto);
    if (s == INVALID_SOCKET) {
        diag::log_tagged_fmt("mitm", "try_connect_address socket_failed family=%d wsa=%d", family, WSAGetLastError());
        return INVALID_SOCKET;
    }

    u_long nonblocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonblocking) != 0) {
        diag::log_tagged_fmt("mitm", "try_connect_address ioctlsocket_failed family=%d wsa=%d", family, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    int cr = connect(s, addr, addr_len);
    if (cr != 0) {
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK && werr != WSAEINPROGRESS) {
            diag::log_tagged_fmt("mitm", "try_connect_address connect_immediate_failed family=%d wsa=%d elapsed_ms=%llu",
                family, werr, static_cast<unsigned long long>(GetTickCount64() - t0));
            closesocket(s);
            return INVALID_SOCKET;
        }

        WSAPOLLFD pfd{};
        pfd.fd = s;
        pfd.events = POLLOUT;
        int pr = WSAPoll(&pfd, 1, connect_timeout_ms);
        if (pr <= 0) {
            diag::log_tagged_fmt("mitm", "try_connect_address poll_failed family=%d pr=%d wsa=%d elapsed_ms=%llu",
                family, pr, WSAGetLastError(), static_cast<unsigned long long>(GetTickCount64() - t0));
            closesocket(s);
            return INVALID_SOCKET;
        }

        int so_err = 0;
        int so_err_len = sizeof(so_err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_err_len) != 0 || so_err != 0) {
            diag::log_tagged_fmt("mitm", "try_connect_address so_error family=%d so_err=%d wsa=%d elapsed_ms=%llu",
                family, so_err, WSAGetLastError(), static_cast<unsigned long long>(GetTickCount64() - t0));
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    diag::log_tagged_fmt("mitm", "try_connect_address CONNECTED family=%d elapsed_ms=%llu",
        family, static_cast<unsigned long long>(GetTickCount64() - t0));
    return s;
}

static SOCKET try_connect_address_blocking(const sockaddr* addr, int addr_len, int family, int socktype, int proto,
                                           DWORD io_timeout_ms, int* last_error) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("mitm",
        "try_connect_address_blocking ENTER family=%d socktype=%d proto=%d io_timeout_ms=%lu",
        family, socktype, proto, static_cast<unsigned long>(io_timeout_ms));
    if (last_error)
        *last_error = 0;
    SOCKET s = socket(family, socktype, proto);
    if (s == INVALID_SOCKET) {
        int err = WSAGetLastError();
        if (last_error)
            *last_error = err;
        diag::log_tagged_fmt("mitm", "try_connect_address_blocking socket_failed family=%d wsa=%d", family, err);
        return INVALID_SOCKET;
    }
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    int cr = connect(s, addr, addr_len);
    if (cr != 0) {
        int err = WSAGetLastError();
        if (last_error)
            *last_error = err;
        diag::log_tagged_fmt("mitm", "try_connect_address_blocking connect_failed family=%d wsa=%d elapsed_ms=%llu",
            family, err, static_cast<unsigned long long>(GetTickCount64() - t0));
        closesocket(s);
        return INVALID_SOCKET;
    }
    diag::log_tagged_fmt("mitm", "try_connect_address_blocking CONNECTED family=%d elapsed_ms=%llu",
        family, static_cast<unsigned long long>(GetTickCount64() - t0));
    return s;
}

static bool is_loopback_host(const std::string& host) {
    if (host.empty()) return false;

    std::string lower = host;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    if (lower == "localhost" || lower == "localhost.") return true;

    in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        const uint32_t h = ntohl(addr4.s_addr);
        return (h >> 24) == 127;
    }

    in6_addr addr6{};
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) {
        static const uint8_t loop6[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
        return std::memcmp(&addr6, loop6, sizeof(loop6)) == 0;
    }

    return false;
}

static SOCKET connect_loopback(uint16_t port, int connect_timeout_ms, DWORD io_timeout_ms) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);

    const int attempts = std::clamp(connect_timeout_ms / 100, 3, 12);
    int last_err = 0;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        SOCKET s = try_connect_address_blocking(reinterpret_cast<const sockaddr*>(&sin), sizeof(sin),
                                                AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                                io_timeout_ms, &last_err);
        if (s != INVALID_SOCKET) {
            diag::log_tagged_fmt("mitm", "connect_loopback ipv4_ok port=%u attempt=%d", port, attempt);
            return s;
        }
        diag::log_tagged_fmt("mitm", "connect_loopback ipv4_retry port=%u attempt=%d err=%d",
            port, attempt, last_err);
        if (last_err != WSAENOBUFS && last_err != WSAEMFILE && last_err != WSAECONNREFUSED &&
            last_err != WSAETIMEDOUT && last_err != WSAEADDRNOTAVAIL && last_err != WSAEADDRINUSE)
            break;
        Sleep(static_cast<DWORD>(25 * attempt));
    }
    diag::log_tagged_fmt("mitm", "connect_loopback ipv4_failed_try_ipv6 port=%u", port);

    sockaddr_in6 sin6{};
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        SOCKET s = try_connect_address_blocking(reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6),
                                                AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                                                io_timeout_ms, &last_err);
        if (s != INVALID_SOCKET) {
            diag::log_tagged_fmt("mitm", "connect_loopback ipv6_ok port=%u attempt=%d", port, attempt);
            return s;
        }
        diag::log_tagged_fmt("mitm", "connect_loopback ipv6_retry port=%u attempt=%d err=%d",
            port, attempt, last_err);
        if (last_err != WSAENOBUFS && last_err != WSAEMFILE && last_err != WSAECONNREFUSED &&
            last_err != WSAETIMEDOUT && last_err != WSAEADDRNOTAVAIL && last_err != WSAEADDRINUSE)
            break;
        Sleep(static_cast<DWORD>(25 * attempt));
    }
    return INVALID_SOCKET;
}

static SOCKET connect_tcp(const std::string& host, uint16_t port) {
    if (is_loopback_host(host)) {
        diag::log_tagged_fmt("mitm", "connect_tcp loopback_fast_path host=%s port=%u", host.c_str(), port);
        SOCKET s = connect_loopback(port, 500, 5000);
        diag::log_tagged_fmt("mitm", "connect_tcp loopback_fast_path_done host=%s port=%u ok=%d",
            host.c_str(), port, s != INVALID_SOCKET ? 1 : 0);
        return s;
    }

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    diag::log_tagged_fmt("mitm", "connect_tcp getaddrinfo host=%s port=%u rc=%d has_result=%d",
        host.c_str(), port, rc, result ? 1 : 0);

    SOCKET connected = INVALID_SOCKET;
    if (rc == 0 && result) {
        for (addrinfo* ai = result; ai != nullptr && connected == INVALID_SOCKET; ai = ai->ai_next) {
            connected = try_connect_address(ai->ai_addr, static_cast<int>(ai->ai_addrlen),
                                            ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        }
        freeaddrinfo(result);
        if (connected != INVALID_SOCKET) return connected;
    }

    PDNS_RECORD dns_rec = nullptr;
    DNS_STATUS ds = DnsQuery_A(host.c_str(), DNS_TYPE_A,
                               DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                               nullptr, &dns_rec, nullptr);
    if (ds == 0 && dns_rec) {
        for (PDNS_RECORD r = dns_rec; r != nullptr && connected == INVALID_SOCKET; r = r->pNext) {
            if (r->wType != DNS_TYPE_A) continue;
            sockaddr_in sin = {};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            sin.sin_addr.s_addr = r->Data.A.IpAddress;
            connected = try_connect_address(reinterpret_cast<const sockaddr*>(&sin), sizeof(sin),
                                            AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
        DnsRecordListFree(dns_rec, DnsFreeRecordList);
        if (connected != INVALID_SOCKET) return connected;
    }

    PDNS_RECORD dns_rec6 = nullptr;
    ds = DnsQuery_A(host.c_str(), DNS_TYPE_AAAA,
                    DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                    nullptr, &dns_rec6, nullptr);
    if (ds == 0 && dns_rec6) {
        for (PDNS_RECORD r = dns_rec6; r != nullptr && connected == INVALID_SOCKET; r = r->pNext) {
            if (r->wType != DNS_TYPE_AAAA) continue;
            sockaddr_in6 sin6 = {};
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = htons(port);
            memcpy(&sin6.sin6_addr, &r->Data.AAAA.Ip6Address, sizeof(sin6.sin6_addr));
            connected = try_connect_address(reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6),
                                            AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        }
        DnsRecordListFree(dns_rec6, DnsFreeRecordList);
    }
    return connected;
}


static bool recv_exact(SOCKET s, uint8_t* buf, size_t need) {
    size_t got = 0;
    while (got < need) {
        int n = recv(s, reinterpret_cast<char*>(buf + got), static_cast<int>(need - got), 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

static bool send_exact(SOCKET s, const uint8_t* buf, size_t need) {
    size_t sent = 0;
    while (sent < need) {
        int n = send(s, reinterpret_cast<const char*>(buf + sent), static_cast<int>(need - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool socks5_handshake(SOCKET s, const std::string& target_host, uint16_t target_port,
                              const std::string& username, const std::string& password) {
    if (target_host.empty() || target_host.size() > 255) return false;
    if (username.size() > 255 || password.size() > 255) return false;

    bool use_auth = !username.empty();


    uint8_t greeting[4];
    greeting[0] = 0x05;
    if (use_auth) {
        greeting[1] = 0x02;
        greeting[2] = 0x00;
        greeting[3] = 0x02;
        if (!send_exact(s, greeting, 4)) return false;
    } else {
        greeting[1] = 0x01;
        greeting[2] = 0x00;
        if (!send_exact(s, greeting, 3)) return false;
    }


    uint8_t choice[2];
    if (!recv_exact(s, choice, 2)) return false;
    if (choice[0] != 0x05) return false;


    if (choice[1] == 0x02) {
        if (!use_auth) return false;
        std::vector<uint8_t> auth_req;
        auth_req.reserve(3 + username.size() + password.size());
        auth_req.push_back(0x01);
        auth_req.push_back(static_cast<uint8_t>(username.size()));
        auth_req.insert(auth_req.end(), username.begin(), username.end());
        auth_req.push_back(static_cast<uint8_t>(password.size()));
        auth_req.insert(auth_req.end(), password.begin(), password.end());
        if (!send_exact(s, auth_req.data(), auth_req.size())) return false;

        uint8_t auth_resp[2];
        if (!recv_exact(s, auth_resp, 2)) return false;
        if (auth_resp[1] != 0x00) return false;
    } else if (choice[1] != 0x00) {
        return false;
    }


    std::vector<uint8_t> conn_req;
    conn_req.reserve(7 + target_host.size());
    conn_req.push_back(0x05);
    conn_req.push_back(0x01);
    conn_req.push_back(0x00);
    conn_req.push_back(0x03);
    conn_req.push_back(static_cast<uint8_t>(target_host.size()));
    conn_req.insert(conn_req.end(), target_host.begin(), target_host.end());
    conn_req.push_back(static_cast<uint8_t>((target_port >> 8) & 0xFF));
    conn_req.push_back(static_cast<uint8_t>(target_port & 0xFF));

    if (!send_exact(s, conn_req.data(), conn_req.size())) return false;


    uint8_t resp[4];
    if (!recv_exact(s, resp, 4)) return false;
    if (resp[0] != 0x05 || resp[1] != 0x00) return false;


    if (resp[3] == 0x01) {
        uint8_t drain[6];
        if (!recv_exact(s, drain, 6)) return false;
    } else if (resp[3] == 0x04) {
        uint8_t drain[18];
        if (!recv_exact(s, drain, 18)) return false;
    } else if (resp[3] == 0x03) {
        uint8_t dlen;
        if (!recv_exact(s, &dlen, 1)) return false;
        std::vector<uint8_t> drain(static_cast<size_t>(dlen) + 2);
        if (!recv_exact(s, drain.data(), drain.size())) return false;
    } else {
        return false;
    }

    return true;
}


static bool http_connect_handshake(SOCKET s, const std::string& target_host, uint16_t target_port,
                                    const std::string& username, const std::string& password) {
    std::string req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\n"
                      "Host: " + target_host + ":" + std::to_string(target_port) + "\r\n";


    if (!username.empty()) {
        std::string creds = username + ":" + password;

        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        encoded.reserve(((creds.size() + 2) / 3) * 4);
        for (size_t i = 0; i < creds.size(); i += 3) {
            uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(creds[i])) << 16;
            if (i + 1 < creds.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(creds[i + 1])) << 8;
            if (i + 2 < creds.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(creds[i + 2]));
            encoded.push_back(b64[(n >> 18) & 0x3F]);
            encoded.push_back(b64[(n >> 12) & 0x3F]);
            encoded.push_back((i + 1 < creds.size()) ? b64[(n >> 6) & 0x3F] : '=');
            encoded.push_back((i + 2 < creds.size()) ? b64[n & 0x3F] : '=');
        }
        req += "Proxy-Authorization: Basic " + encoded + "\r\n";
    }
    req += "\r\n";

    if (!send_exact(s, reinterpret_cast<const uint8_t*>(req.data()), req.size())) return false;


    std::string response;
    char buf[1];
    while (response.size() < 4096) {
        int n = recv(s, buf, 1, 0);
        if (n <= 0) return false;
        response.push_back(buf[0]);
        if (response.size() >= 4 && response.compare(response.size() - 4, 4, "\r\n\r\n") == 0)
            break;
    }


    size_t sp = response.find(' ');
    if (sp == std::string::npos) return false;
    size_t sp2 = response.find(' ', sp + 1);
    std::string code = (sp2 == std::string::npos)
        ? response.substr(sp + 1)
        : response.substr(sp + 1, sp2 - sp - 1);
    return code.size() >= 3 && code[0] == '2' && code[1] == '0' && code[2] == '0';
}

static std::string proxy_url_for_pac(const std::string& host, uint16_t port, bool use_tls) {
    std::ostringstream out;
    out << (use_tls ? "https://" : "http://") << host;
    if ((use_tls && port != 443) || (!use_tls && port != 80))
        out << ':' << port;
    out << '/';
    return out.str();
}

static upstream_proxy_config select_upstream_proxy(const proxy_config& config,
                                                   const std::string& host,
                                                   uint16_t port,
                                                   bool use_tls,
                                                   bool& blocked,
                                                   std::string& error) {
    blocked = false;
    error.clear();
    if (!config.enable_pac || config.pac_script.empty())
        return config.upstream;

    auto resolved = pac_resolver::resolve(config.pac_script,
                                          proxy_url_for_pac(host, port, use_tls),
                                          host,
                                          port,
                                          config.pac_fail_closed);
    if (!resolved.supported || resolved.entries.empty()) {
        if (resolved.fail_closed) {
            blocked = true;
            error = resolved.error.empty() ? "pac_resolution_failed" : resolved.error;
            return {};
        }
        return {};
    }
    for (const auto& entry : resolved.entries) {
        if (entry.type == pac_resolver::proxy_entry_type::direct)
            return {};
        if (entry.type == pac_resolver::proxy_entry_type::http || entry.type == pac_resolver::proxy_entry_type::socks5) {
            upstream_proxy_config selected;
            selected.type = entry.type == pac_resolver::proxy_entry_type::http
                ? upstream_proxy_config::type_t::http_connect
                : upstream_proxy_config::type_t::socks5;
            selected.host = entry.host;
            selected.port = entry.port;
            return selected;
        }
        if (config.pac_fail_closed) {
            blocked = true;
            error = "pac_socks4_unsupported";
            return {};
        }
    }
    if (config.pac_fail_closed) {
        blocked = true;
        error = "pac_no_supported_route";
    }
    return {};
}

static SOCKET connect_to_target(const std::string& host, uint16_t port, const proxy_config& config, bool use_tls = false) {
    bool blocked = false;
    std::string route_error;
    const upstream_proxy_config upstream = select_upstream_proxy(config, host, port, use_tls, blocked, route_error);
    if (blocked) {
        diag::log_tagged_fmt("mitm", "connect_to_target blocked_by_pac host=%s port=%u err=%s",
            host.c_str(), port, route_error.c_str());
        return INVALID_SOCKET;
    }

    if (upstream.type == upstream_proxy_config::type_t::none) {

        return connect_tcp(host, port);
    }


    SOCKET s = connect_tcp(upstream.host, upstream.port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    bool ok = false;
    if (upstream.type == upstream_proxy_config::type_t::socks5) {
        ok = socks5_handshake(s, host, port, upstream.username, upstream.password);
    } else if (upstream.type == upstream_proxy_config::type_t::http_connect) {
        ok = http_connect_handshake(s, host, port, upstream.username, upstream.password);
    }

    if (!ok) {
        close_socket(s);
        return INVALID_SOCKET;
    }
    return s;
}


static bool ssl_handshake_with_timeout(SSL* ssl, int (*op)(SSL*), int timeout_ms_total = 30000) {
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    u_long nonblocking = 1;
    if (ioctlsocket(fd, FIONBIO, &nonblocking) != 0) return false;

    uint64_t deadline = GetTickCount64() + static_cast<uint64_t>(timeout_ms_total);
    bool success = false;

    while (true) {
        int rc = op(ssl);
        if (rc == 1) { success = true; break; }
        int err = SSL_get_error(ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;

        uint64_t now = GetTickCount64();
        if (now >= deadline) break;
        int remaining = static_cast<int>(deadline - now);

        WSAPOLLFD pfd{};
        pfd.fd = fd;
        pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        int pr = WSAPoll(&pfd, 1, remaining);
        if (pr <= 0) break;
    }

    u_long blocking = 0;
    ioctlsocket(fd, FIONBIO, &blocking);
    return success;
}

static bool verify_upstream_pin(SSL* ssl, const tls_policy::match_result_t& policy) {
    if (!tls_policy::pins_configured(policy))
        return true;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509* peer = SSL_get1_peer_certificate(ssl);
#else
    X509* peer = SSL_get_peer_certificate(ssl);
#endif
    if (!peer)
        return false;
    std::string fp = tls_policy::cert_sha256_fingerprint_hex(peer);
    X509_free(peer);
    return tls_policy::fingerprint_matches_pin(fp, policy);
}

static bool configure_client_tls(SSL_CTX* ctx,
                                 SSL* ssl,
                                 const std::string& host,
                                 const tls_policy::match_result_t& policy,
                                 const unsigned char* alpn,
                                 unsigned int alpn_len) {
    if (!tls_policy::apply_client_policy(ctx, policy))
        return false;
    if (!tls_policy::configure_hostname_verification(ssl, host, policy))
        return false;
    if (!tls_policy::apply_client_alpn(ssl, policy, alpn, alpn_len))
        return false;
    SSL_set_tlsext_host_name(ssl, host.c_str());
    return true;
}

static bool response_should_stream(const std::vector<uint8_t>& headers_data) {
    const size_t end = header_end_offset(headers_data);
    if (end == std::string::npos)
        return false;
    std::string headers(headers_data.begin(), headers_data.begin() + static_cast<ptrdiff_t>(end));
    headers = lower_ascii(headers);
    if (headers.find("content-type: text/event-stream") != std::string::npos)
        return true;
    const bool has_cl = headers.find("content-length:") != std::string::npos;
    const bool has_te = headers.find("transfer-encoding:") != std::string::npos;
    const bool close_delimited = headers.find("connection: close") != std::string::npos;
    return !has_cl && !has_te && close_delimited;
}

static int ssl_read_some_blocking(SSL* ssl, uint8_t* buf, int len, int timeout_ms) {
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    for (;;) {
        int n = SSL_read(ssl, buf, len);
        if (n > 0)
            return n;
        int err = SSL_get_error(ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            return -1;
        WSAPOLLFD pfd{};
        pfd.fd = fd;
        pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        int pr = WSAPoll(&pfd, 1, timeout_ms);
        if (pr <= 0)
            return 0;
    }
}

static int socket_read_some_blocking(SOCKET sock, uint8_t* buf, int len, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int sel = select(0, &fds, nullptr, nullptr, &tv);
    if (sel <= 0)
        return 0;
    int n = recv(sock, reinterpret_cast<char*>(buf), len, 0);
    return n > 0 ? n : -1;
}

static bool ssl_write_all(SSL* ssl, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const size_t chunk = std::min<size_t>(len - sent, 16 * 1024);
        int n = SSL_write(ssl, data + sent, static_cast<int>(chunk));
        if (n <= 0)
            return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool socket_write_all(SOCKET sock, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const size_t chunk = std::min<size_t>(len - sent, 64 * 1024);
        int n = send(sock, reinterpret_cast<const char*>(data + sent), static_cast<int>(chunk), 0);
        if (n <= 0)
            return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static void capture_limited(std::vector<uint8_t>& capture, const uint8_t* data, size_t len, size_t max_size) {
    if (capture.size() >= max_size)
        return;
    const size_t take = std::min(len, max_size - capture.size());
    capture.insert(capture.end(), data, data + take);
}

template <typename ReadFn, typename WriteFn>
static void relay_streaming_body(state_t& state,
                                 std::vector<uint8_t>& capture,
                                 size_t max_capture,
                                 uint64_t& bytes_out,
                                 ReadFn&& read_fn,
                                 WriteFn&& write_fn) {
    uint8_t buf[32768];
    while (state.running.load()) {
        int n = read_fn(buf, static_cast<int>(sizeof(buf)));
        if (n < 0)
            break;
        if (n == 0)
            continue;
        if (!write_fn(buf, static_cast<size_t>(n)))
            break;
        bytes_out += static_cast<uint64_t>(n);
        capture_limited(capture, buf, static_cast<size_t>(n), max_capture);
    }
}

static void websocket_relay(SSL* client_ssl, SSL* target_ssl, http_exchange& exchange, state_t& state) {
    diag::log_tagged_fmt("mitm", "websocket_relay entry exchange_id=%llu host=%s:%u",
        static_cast<unsigned long long>(exchange.id), exchange.target_host.c_str(), exchange.target_port);
    exchange.is_websocket = true;
    fd_set fds;
    bool done = false;

    SOCKET client_fd = static_cast<SOCKET>(SSL_get_fd(client_ssl));
    SOCKET target_fd = static_cast<SOCKET>(SSL_get_fd(target_ssl));


    std::vector<uint8_t> client_buf;
    std::vector<uint8_t> target_buf;
    client_buf.reserve(65536);
    target_buf.reserve(65536);

    auto process_frames = [&](std::vector<uint8_t>& buf, bool outbound,
                              SSL* from_ssl, SSL* to_ssl) {
        while (buf.size() >= 2) {
            auto frame = protocol_parser::parse_ws_frame(buf.data(), buf.size());
            if (!frame.valid || frame.total_consumed == 0) break;


            std::vector<uint8_t> payload;
            if (frame.masked) {
                payload = protocol_parser::unmask_payload(frame);
            } else {
                payload = std::move(frame.payload);
            }


            http_exchange::ws_frame_entry entry;
            entry.timestamp = GetTickCount64();
            entry.outbound = outbound;
            entry.opcode = frame.opcode;
            entry.payload = payload;
            {
                std::lock_guard<std::mutex> lock(state.history_mutex);
                exchange.ws_frames.push_back(std::move(entry));
            }

            diag::log_tagged_fmt("mitm", "websocket_relay frame opcode=%d outbound=%d payload=%zu fin=%d masked=%d exchange_id=%llu",
                (int)frame.opcode, (int)outbound, payload.size(), (int)frame.fin, (int)frame.masked, static_cast<unsigned long long>(exchange.id));
            ws_frame_observed_t observed;
            observed.timestamp = GetTickCount64();
            observed.exchange_id = exchange.id;
            observed.host = exchange.target_host;
            observed.port = exchange.target_port;
            observed.is_outbound = outbound;
            observed.is_text = (frame.opcode == protocol_parser::ws_opcode::text);
            observed.opcode = static_cast<uint8_t>(frame.opcode);
            observed.payload = payload;
            publish_ws_frame(observed);


            bool should_forward = true;
            std::vector<uint8_t> forward_payload = payload;
            if (script_engine::is_initialized()) {
                script_engine::hook_ws_frame_data ws_data;
                ws_data.host = exchange.target_host;
                ws_data.port = exchange.target_port;
                ws_data.is_outbound = outbound;
                ws_data.payload = payload;
                ws_data.is_text = (frame.opcode == protocol_parser::ws_opcode::text);
                script_engine::invoke_hook(script_engine::hook_type::on_websocket_frame, ws_data);
                if (ws_data.dropped) { should_forward = false; }
                if (ws_data.modified) { forward_payload = std::move(ws_data.payload); }
            }

            if (should_forward) {

                std::vector<uint8_t> out_frame;
                uint8_t b0 = static_cast<uint8_t>((frame.fin ? 0x80 : 0x00) |
                             (static_cast<uint8_t>(frame.opcode) & 0x0F));
                out_frame.push_back(b0);

                uint8_t mask_bit = outbound ? 0x80 : 0x00;

                if (forward_payload.size() < 126) {
                    out_frame.push_back(static_cast<uint8_t>(forward_payload.size()) | mask_bit);
                } else if (forward_payload.size() <= 0xFFFF) {
                    out_frame.push_back(static_cast<uint8_t>(126) | mask_bit);
                    uint16_t len16 = static_cast<uint16_t>(forward_payload.size());
                    out_frame.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
                    out_frame.push_back(static_cast<uint8_t>(len16 & 0xFF));
                } else {
                    out_frame.push_back(static_cast<uint8_t>(127) | mask_bit);
                    uint64_t len64 = forward_payload.size();
                    for (int i = 7; i >= 0; i--) {
                        out_frame.push_back(static_cast<uint8_t>((len64 >> (i * 8)) & 0xFF));
                    }
                }

                if (outbound) {
                    uint8_t mask_key[4];
                    if (RAND_bytes(mask_key, 4) != 1) {
                        uint64_t tk = GetTickCount64();
                        for (int i = 0; i < 4; i++) mask_key[i] = static_cast<uint8_t>((tk >> (i * 8)) & 0xFF);
                    }
                    out_frame.push_back(mask_key[0]);
                    out_frame.push_back(mask_key[1]);
                    out_frame.push_back(mask_key[2]);
                    out_frame.push_back(mask_key[3]);
                    size_t mask_off = out_frame.size();
                    out_frame.insert(out_frame.end(), forward_payload.begin(), forward_payload.end());
                    for (size_t i = 0; i < forward_payload.size(); ++i) {
                        out_frame[mask_off + i] ^= mask_key[i & 3];
                    }
                } else {
                    out_frame.insert(out_frame.end(), forward_payload.begin(), forward_payload.end());
                }
                SSL_write(to_ssl, out_frame.data(), static_cast<int>(out_frame.size()));
            }

            if (outbound) {
                exchange.ws_frames_sent++;
                state.total_bytes_in.fetch_add(frame.total_consumed);
            } else {
                exchange.ws_frames_recv++;
                state.total_bytes_out.fetch_add(frame.total_consumed);
            }


            if (frame.opcode == protocol_parser::ws_opcode::close) {
                diag::log_tagged_fmt("mitm", "websocket_relay close frame exchange_id=%llu outbound=%d",
                    static_cast<unsigned long long>(exchange.id), (int)outbound);
                done = true;
                break;
            }

            buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(frame.total_consumed));
        }
    };

    uint8_t read_buf[65536];
    diag::log_tagged_fmt("mitm", "websocket_relay loop starting exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
    while (!done && state.running.load()) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target_fd, &fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        SOCKET max_fd = (client_fd > target_fd) ? client_fd : target_fd;
        int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
        if (sel <= 0) { if (sel < 0) done = true; continue; }

        if (FD_ISSET(client_fd, &fds)) {
            int n = SSL_read(client_ssl, read_buf, sizeof(read_buf));
            if (n <= 0) { done = true; break; }
            client_buf.insert(client_buf.end(), read_buf, read_buf + n);
            process_frames(client_buf, true, client_ssl, target_ssl);
        }

        if (FD_ISSET(target_fd, &fds)) {
            int n = SSL_read(target_ssl, read_buf, sizeof(read_buf));
            if (n <= 0) { done = true; break; }
            target_buf.insert(target_buf.end(), read_buf, read_buf + n);
            process_frames(target_buf, false, target_ssl, client_ssl);
        }
    }
}


static bool is_websocket_upgrade(const protocol_parser::http_response& resp) {
    if (resp.status_code != 101) return false;
    auto iequal = [](const std::string& a, const char* b) -> bool {
        size_t blen = strlen(b);
        if (a.size() != blen) return false;
        for (size_t i = 0; i < blen; ++i) {
            char ca = static_cast<char>(::tolower(static_cast<unsigned char>(a[i])));
            char cb = static_cast<char>(::tolower(static_cast<unsigned char>(b[i])));
            if (ca != cb) return false;
        }
        return true;
    };
    for (const auto& h : resp.headers) {
        if (iequal(h.name, "Upgrade")) {
            std::string val = h.value;
            std::transform(val.begin(), val.end(), val.begin(),
                [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
            if (val == "websocket") return true;
        }
    }
    return false;
}


static void handle_h2_session(SSL* client_ssl, SSL* target_ssl,
                               const std::string& target_host, uint16_t target_port,
                               const std::string& client_addr, uint16_t client_port,
                               state_t& state, const proxy_config& config) {
    diag::log_tagged_fmt("mitm", "handle_h2_session entry host=%s:%u client=%s:%u",
        target_host.c_str(), target_port, client_addr.c_str(), client_port);
    h2_session::session client_session(h2_session::session::role::server);
    h2_session::session target_session(h2_session::session::role::client);

    bool init_ok = client_session.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
        return static_cast<ssize_t>(SSL_write(client_ssl, data, static_cast<int>(len)));
    }) && target_session.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
        return static_cast<ssize_t>(SSL_write(target_ssl, data, static_cast<int>(len)));
    });
    diag::log_tagged_fmt("mitm", "handle_h2_session init_ok=%d host=%s:%u", (int)init_ok, target_host.c_str(), target_port);
    if (!init_ok) {
        diag::log_tagged_fmt("mitm", "handle_h2_session session init failed host=%s:%u", target_host.c_str(), target_port);
        return;
    }


    client_session.set_on_request([&](const h2_session::stream_data& sd) {
        diag::log_tagged_fmt("mitm", "handle_h2_session on_request stream_id=%u method=%s path=%s host=%s:%u body_size=%zu",
            sd.stream_id, sd.method.c_str(), sd.path.c_str(), target_host.c_str(), target_port, sd.request_body.size());
        http_exchange exchange;
        exchange.id = state.next_id++;
        exchange.timestamp = GetTickCount64();
        exchange.client_addr = client_addr;
        exchange.client_port = client_port;
        exchange.target_host = target_host;
        exchange.target_port = target_port;
        exchange.is_tls = true;
        exchange.tls_sni = target_host;
        exchange.alpn_protocol = "h2";
        exchange.is_h2 = true;
        exchange.h2_stream_id = sd.stream_id;
        exchange.request_time = GetTickCount64();
        exchange.request.valid = true;
        exchange.request.method = sd.method;
        exchange.request.uri = sd.path;
        exchange.request.version = "HTTP/2";
        for (const auto& h : sd.request_headers) {
            exchange.request.headers.push_back({h.name, h.value});
        }
        exchange.request_size = sd.request_body.size();
        exchange.raw_request = sd.request_body;


        if (script_engine::is_initialized()) {
            script_engine::hook_request_data hook_data;
            hook_data.method = sd.method;
            hook_data.uri = sd.path;
            hook_data.host = target_host;
            hook_data.port = target_port;
            hook_data.is_tls = true;
            for (const auto& h : sd.request_headers)
                hook_data.headers[h.name] = h.value;
            hook_data.body = sd.request_body;
            script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
            if (hook_data.dropped) {
                exchange.state = http_exchange::state_t::dropped;
                record_history(state, config, std::move(exchange));
                return;
            }
        }

        state.total_requests.fetch_add(1);
        state.total_bytes_in.fetch_add(sd.request_body.size());
        exchange.state = http_exchange::state_t::forwarding;


        target_session.submit_request(sd.method, sd.path, sd.authority, sd.scheme, sd.request_headers, sd.request_body);


        publish_exchange_event(exchange);
        std::lock_guard<std::mutex> lock(state.history_mutex);
        state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
        while (state.history.size() > config.max_history)
            state.history.pop_front();
    });


    target_session.set_on_response([&](const h2_session::stream_data& sd) {
        diag::log_tagged_fmt("mitm", "handle_h2_session on_response stream_id=%u status=%d host=%s:%u body_size=%zu",
            sd.stream_id, sd.status_code, target_host.c_str(), target_port, sd.response_body.size());
        if (script_engine::is_initialized()) {
            script_engine::hook_response_data hook_data;
            hook_data.status_code = sd.status_code;
            hook_data.host = target_host;
            hook_data.port = target_port;
            for (const auto& h : sd.response_headers)
                hook_data.headers[h.name] = h.value;
            hook_data.body = sd.response_body;
            script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
            if (hook_data.dropped) return;
        }

        state.total_bytes_out.fetch_add(sd.response_body.size());


        client_session.submit_response(sd.stream_id, sd.status_code, sd.response_headers, sd.response_body);


        http_exchange complete_snapshot;
        bool have_snapshot = false;
        {
            std::lock_guard<std::mutex> lock(state.history_mutex);
            for (auto it = state.history.rbegin(); it != state.history.rend(); ++it) {
                auto& ex_ref = **it;
                if (ex_ref.is_h2 && ex_ref.target_host == target_host &&
                    ex_ref.target_port == target_port && ex_ref.h2_stream_id == sd.stream_id) {
                    ex_ref.response.valid = true;
                    ex_ref.response.status_code = sd.status_code;
                    for (const auto& h : sd.response_headers)
                        ex_ref.response.headers.push_back({h.name, h.value});
                    ex_ref.raw_response = sd.response_body;
                    ex_ref.response_size = sd.response_body.size();
                    ex_ref.response_time = GetTickCount64();
                    ex_ref.latency_ms = ex_ref.response_time - ex_ref.request_time;
                    ex_ref.state = http_exchange::state_t::complete;
                    complete_snapshot = ex_ref;
                    have_snapshot = true;
                    break;
                }
            }
        }
        if (have_snapshot) publish_exchange_event(complete_snapshot);
    });


    SOCKET client_fd = static_cast<SOCKET>(SSL_get_fd(client_ssl));
    SOCKET target_fd = static_cast<SOCKET>(SSL_get_fd(target_ssl));
    fd_set fds;
    uint8_t buf[16384];
    bool done = false;

    while (!done && state.running.load()) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target_fd, &fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        SOCKET max_fd = (client_fd > target_fd) ? client_fd : target_fd;
        int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
        if (sel <= 0) { if (sel < 0) done = true; continue; }

        if (FD_ISSET(client_fd, &fds)) {
            int n = SSL_read(client_ssl, buf, sizeof(buf));
            if (n <= 0) { done = true; break; }
            client_session.feed(buf, static_cast<size_t>(n));
        }

        if (FD_ISSET(target_fd, &fds)) {
            int n = SSL_read(target_ssl, buf, sizeof(buf));
            if (n <= 0) { done = true; break; }
            target_session.feed(buf, static_cast<size_t>(n));
        }
    }
}


static void handle_tls_connection(SOCKET client_sock, std::string target_host,
                                   uint16_t target_port, const std::string& client_addr,
                                   uint16_t client_port, state_t& state, const proxy_config& config) {
    diag::log_tagged_fmt("mitm", "handle_tls_connection entry host=%s:%u client=%s:%u",
        target_host.c_str(), target_port, client_addr.c_str(), client_port);

    const auto& ca = cert_generator::get_root_ca();
    if (!ca.valid) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection CA not valid host=%s:%u", target_host.c_str(), target_port);
        close_socket(client_sock);
        return;
    }

    SSL_CTX* ctx = cert_generator::get_ssl_ctx_for_domain(target_host, ca);
    if (!ctx) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection get_ssl_ctx_for_domain failed host=%s", target_host.c_str());
        close_socket(client_sock);
        return;
    }
    diag::log_tagged_fmt("mitm", "handle_tls_connection got ssl_ctx host=%s ctx=%p", target_host.c_str(), ctx);
    const auto server_policy = tls_policy::match_host(target_host);
    if (!tls_policy::apply_server_policy(ctx, server_policy)) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection server_tls_policy_failed host=%s", target_host.c_str());
        close_socket(client_sock);
        return;
    }


    static const unsigned char alpn_h2_h1[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    static const unsigned char alpn_h1[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };

    if (config.enable_h2 && (!server_policy.matched || server_policy.policy.alpn_protocols.empty())) {

        SSL_CTX_set_alpn_select_cb(ctx,
            [](SSL*, const unsigned char** out, unsigned char* outlen,
               const unsigned char* in, unsigned int inlen, void*) -> int {
                if (SSL_select_next_proto(
                        const_cast<unsigned char**>(out), outlen,
                        alpn_h2_h1, sizeof(alpn_h2_h1),
                        in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_NOACK;
                }
                return SSL_TLSEXT_ERR_OK;
            }, nullptr);
    }


    SSL* client_ssl = SSL_new(ctx);
    if (!client_ssl) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection SSL_new failed host=%s", target_host.c_str());
        close_socket(client_sock);
        return;
    }
    SSL_set_fd(client_ssl, static_cast<int>(client_sock));

    bool accept_ok = ssl_handshake_with_timeout(client_ssl, SSL_accept);
    diag::log_tagged_fmt("mitm", "handle_tls_connection SSL_accept host=%s ok=%d", target_host.c_str(), (int)accept_ok);
    if (!accept_ok) {
        std::string detail = openssl_error_text();
        if (detail.empty()) detail = "client_tls_handshake_failed";
        record_tls_observation(state, tls_observation_kind_t::client_handshake_failed,
            target_host, target_port, client_addr, client_port, std::string(), std::string(), detail);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    std::string client_sni;
    const char* ssl_sni = SSL_get_servername(client_ssl, TLSEXT_NAMETYPE_host_name);
    if (ssl_sni && *ssl_sni) client_sni = ssl_sni;

    const unsigned char* alpn_data = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(client_ssl, &alpn_data, &alpn_len);
    std::string client_alpn;
    if (alpn_data && alpn_len > 0)
        client_alpn.assign(reinterpret_cast<const char*>(alpn_data), alpn_len);
    diag::log_tagged_fmt("mitm", "handle_tls_connection client_alpn=%s client_sni=%s host=%s",
        client_alpn.c_str(), client_sni.c_str(), target_host.c_str());
    if (!client_sni.empty() && _stricmp(client_sni.c_str(), target_host.c_str()) != 0) {
        record_tls_observation(state, tls_observation_kind_t::sni_authority_mismatch,
            target_host, target_port, client_addr, client_port, client_sni, client_alpn,
            "client SNI differs from CONNECT authority");
    }

    SOCKET target_sock = connect_to_target(target_host, target_port, config, true);
    diag::log_tagged_fmt("mitm", "handle_tls_connection connect_to_target host=%s:%u sock=%lld",
        target_host.c_str(), target_port, (long long)target_sock);
    if (target_sock == INVALID_SOCKET) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection connect_to_target failed host=%s:%u", target_host.c_str(), target_port);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    SSL_CTX* target_ctx = SSL_CTX_new(TLS_client_method());
    if (!target_ctx) {
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    const auto upstream_policy = tls_policy::match_host(target_host);
    SSL* target_ssl = SSL_new(target_ctx);
    if (!target_ssl) {
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }
    SSL_set_fd(target_ssl, static_cast<int>(target_sock));
    const unsigned char* fallback_alpn = nullptr;
    unsigned int fallback_alpn_len = 0;
    if (config.enable_h2) {
        if (client_alpn == "h2") {
            fallback_alpn = alpn_h2_h1;
            fallback_alpn_len = sizeof(alpn_h2_h1);
        } else {
            fallback_alpn = alpn_h1;
            fallback_alpn_len = sizeof(alpn_h1);
        }
    }
    if (!configure_client_tls(target_ctx, target_ssl, target_host, upstream_policy, fallback_alpn, fallback_alpn_len)) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection client_tls_policy_failed host=%s", target_host.c_str());
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    bool connect_ok = ssl_handshake_with_timeout(target_ssl, SSL_connect);
    diag::log_tagged_fmt("mitm", "handle_tls_connection SSL_connect host=%s ok=%d", target_host.c_str(), (int)connect_ok);
    if (!connect_ok) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection SSL_connect failed host=%s:%u", target_host.c_str(), target_port);
        std::string detail = openssl_error_text();
        if (detail.empty()) detail = "upstream_tls_handshake_failed";
        record_tls_observation(state, tls_observation_kind_t::upstream_handshake_failed,
            target_host, target_port, client_addr, client_port, client_sni, client_alpn, detail);
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }
    if (SSL_get_verify_result(target_ssl) != X509_V_OK && !upstream_policy.policy.ignore_cert_errors) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection upstream_cert_verify_failed host=%s verify=%ld",
            target_host.c_str(), SSL_get_verify_result(target_ssl));
        record_tls_observation(state, tls_observation_kind_t::upstream_handshake_failed,
            target_host, target_port, client_addr, client_port, client_sni, client_alpn, "upstream_certificate_verify_failed");
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }
    if (!verify_upstream_pin(target_ssl, upstream_policy)) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection upstream_pin_mismatch host=%s", target_host.c_str());
        record_tls_observation(state, tls_observation_kind_t::upstream_pin_mismatch,
            target_host, target_port, client_addr, client_port, client_sni, client_alpn, "upstream_certificate_pin_mismatch");
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    const unsigned char* target_alpn_data = nullptr;
    unsigned int target_alpn_len = 0;
    SSL_get0_alpn_selected(target_ssl, &target_alpn_data, &target_alpn_len);
    std::string target_alpn;
    if (target_alpn_data && target_alpn_len > 0)
        target_alpn.assign(reinterpret_cast<const char*>(target_alpn_data), target_alpn_len);
    record_tls_observation(state, tls_observation_kind_t::http_tls,
        target_host, target_port, client_addr, client_port, client_sni, target_alpn.empty() ? client_alpn : target_alpn,
        "TLS handshake completed through proxy");

    state.active_connections.fetch_add(1);
    bool use_h2 = config.enable_h2 && client_alpn == "h2" && target_alpn == "h2";
    diag::log_tagged_fmt("mitm", "handle_tls_connection client_alpn=%s target_alpn=%s use_h2=%d host=%s:%u",
        client_alpn.c_str(), target_alpn.c_str(), (int)use_h2, target_host.c_str(), target_port);

    if (config.enable_h2 && client_alpn == "h2" && target_alpn != "h2") {
        diag::log_tagged_fmt("mitm", "handle_tls_connection h2 client without h2 upstream host=%s:%u", target_host.c_str(), target_port);
        goto cleanup_no_history;
    }

    if (use_h2) {
        diag::log_tagged_fmt("mitm", "handle_tls_connection dispatching to handle_h2_session host=%s:%u", target_host.c_str(), target_port);
        handle_h2_session(client_ssl, target_ssl, target_host, target_port,
                          client_addr, client_port, state, config);
    }

    else {
        diag::log_tagged_fmt("mitm", "handle_tls_connection HTTP/1.1 path host=%s:%u", target_host.c_str(), target_port);

        std::vector<uint8_t> request_data;
        if (recv_ssl_all(client_ssl, request_data, config.max_body_size)) {
            read_remaining_body_ssl(client_ssl, request_data, config.max_body_size);


            http_exchange exchange;
            exchange.id = state.next_id++;
            exchange.timestamp = GetTickCount64();
            exchange.client_addr = client_addr;
            exchange.client_port = client_port;
            exchange.target_host = target_host;
            exchange.target_port = target_port;
            exchange.is_tls = true;
            exchange.tls_sni = client_sni.empty() ? target_host : client_sni;
            exchange.alpn_protocol = target_alpn.empty() ? "http/1.1" : target_alpn;
            exchange.raw_request = request_data;
            exchange.request_size = request_data.size();
            exchange.request_time = GetTickCount64();
            exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
            exchange.state = http_exchange::state_t::pending;
            if (!exchange.request.valid) {
                diag::log_tagged_fmt("mitm", "handle_tls_connection invalid HTTP/1 request size=%zu host=%s:%u", request_data.size(), target_host.c_str(), target_port);
                record_tls_observation(state, tls_observation_kind_t::non_http_tls,
                    target_host, target_port, client_addr, client_port, client_sni, exchange.alpn_protocol,
                    "TLS payload did not parse as an HTTP request");
                goto cleanup_no_history;
            }
            if (!exchange.request.complete) {
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = "request body exceeds buffered interception limit";
                exchange.raw_response = build_error_response(413, "Payload Too Large", exchange.error_msg);
                exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                ssl_write_all(client_ssl, exchange.raw_response.data(), exchange.raw_response.size());
                record_history(state, config, std::move(exchange));
                goto cleanup_no_history;
            }

            state.total_requests.fetch_add(1);
            state.total_bytes_in.fetch_add(request_data.size());


            if (script_engine::is_initialized()) {
                script_engine::hook_request_data hook_data;
                hook_data.method = exchange.request.method;
                hook_data.uri = exchange.request.uri;
                hook_data.host = target_host;
                hook_data.port = target_port;
                hook_data.is_tls = true;
                for (const auto& h : exchange.request.headers)
                    hook_data.headers[h.name] = h.value;
                hook_data.body = request_data;
                script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
                if (hook_data.dropped) {
                    exchange.state = http_exchange::state_t::dropped;
                    record_history(state, config, std::move(exchange));
                    goto cleanup;
                }
                if (hook_data.modified)
                    request_data = hook_data.body;
            }

            apply_sticky_session_request(config, exchange, request_data);
            aida::burp::match_replace::apply_request(request_data, target_host, "https");
            exchange.raw_request = request_data;
            exchange.request_size = request_data.size();
            exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());

            bool should_forward = true;
            if (config.intercept_enabled) {
                bool cb_decided = false;
                if (state.intercept_cb) {
                    intercept_action action = state.intercept_cb(exchange);
                    if (action == intercept_action::drop) {
                        exchange.state = http_exchange::state_t::dropped;
                        should_forward = false;
                        cb_decided = true;
                    } else if (action == intercept_action::modify) {
                        request_data = exchange.raw_request;
                        cb_decided = true;
                    } else if (action == intercept_action::forward) {
                        cb_decided = true;
                    }
                }
                if (!cb_decided && should_forward) {
                    exchange.raw_request = request_data;
                    exchange.request_size = request_data.size();
                    hold_outcome_t outcome = hold_until_decision(state, exchange);
                    if (outcome.decision == hold_decision_t::drop) {
                        exchange.state = http_exchange::state_t::dropped;
                        should_forward = false;
                    } else if (outcome.decision == hold_decision_t::modified) {
                        request_data = std::move(outcome.modified_request);
                        exchange.raw_request = request_data;
                        exchange.request_size = request_data.size();
                        exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
                        if (!exchange.request.valid) {
                            diag::log_tagged_fmt("mitm", "handle_tls_connection modified request invalid exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                            exchange.state = http_exchange::state_t::dropped;
                            should_forward = false;
                        }
                    }
                }
            }

            diag::log_tagged_fmt("mitm", "handle_tls_connection http1 should_forward=%d exchange_id=%llu method=%s uri=%s",
                (int)should_forward, static_cast<unsigned long long>(exchange.id), exchange.request.method.c_str(), exchange.request.uri.c_str());
            if (should_forward) {
                exchange.state = http_exchange::state_t::forwarding;
                auto local = map_resource::try_local(exchange);
                if (local.matched) {
                    exchange.raw_response = local.raw_response.empty()
                        ? build_error_response(502, "Bad Gateway", local.error.empty() ? "map local failed" : local.error)
                        : local.raw_response;
                    add_tags(exchange, local.tags);
                    exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                    exchange.response_size = exchange.raw_response.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.state = local.raw_response.empty() ? http_exchange::state_t::error : http_exchange::state_t::complete;
                    if (exchange.state == http_exchange::state_t::error)
                        exchange.error_msg = local.error;
                    SSL_write(client_ssl, exchange.raw_response.data(), static_cast<int>(exchange.raw_response.size()));
                    state.total_bytes_out.fetch_add(exchange.raw_response.size());
                    apply_sticky_session_response(config, exchange);
                    record_history(state, config, std::move(exchange));
                    goto cleanup_no_history;
                }
                auto replay = server_replay::match(exchange, request_data);
                if (replay.matched) {
                    exchange.raw_response = replay.raw_response;
                    add_tags(exchange, replay.tags);
                    exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                    exchange.response_size = exchange.raw_response.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.state = http_exchange::state_t::complete;
                    SSL_write(client_ssl, exchange.raw_response.data(), static_cast<int>(exchange.raw_response.size()));
                    state.total_bytes_out.fetch_add(exchange.raw_response.size());
                    apply_sticky_session_response(config, exchange);
                    record_history(state, config, std::move(exchange));
                    goto cleanup_no_history;
                }
                auto remote = map_resource::try_remote(exchange, request_data);
                if (remote.matched) {
                    if (!remote.error.empty() || !remote.use_tls) {
                        const std::string reason = !remote.error.empty() ? remote.error : "https map-remote requires an https remote URL";
                        exchange.state = http_exchange::state_t::error;
                        exchange.error_msg = reason;
                        exchange.raw_response = build_error_response(502, "Bad Gateway", reason);
                        exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                        SSL_write(client_ssl, exchange.raw_response.data(), static_cast<int>(exchange.raw_response.size()));
                        record_history(state, config, std::move(exchange));
                        goto cleanup_no_history;
                    }
                    add_tags(exchange, remote.tags);
                    SSL_shutdown(target_ssl);
                    SSL_free(target_ssl);
                    SSL_CTX_free(target_ctx);
                    close_socket(target_sock);
                    target_ssl = nullptr;
                    target_ctx = nullptr;
                    target_sock = INVALID_SOCKET;
                    target_host = remote.host;
                    target_port = remote.port;
                    request_data = std::move(remote.raw_request);
                    exchange.target_host = target_host;
                    exchange.target_port = target_port;
                    exchange.raw_request = request_data;
                    exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
                    target_sock = connect_to_target(target_host, target_port, config, true);
                    target_ctx = target_sock == INVALID_SOCKET ? nullptr : SSL_CTX_new(TLS_client_method());
                    target_ssl = target_ctx ? SSL_new(target_ctx) : nullptr;
                    const auto remap_policy = tls_policy::match_host(target_host);
                    const bool remap_ok = target_ssl &&
                        (SSL_set_fd(target_ssl, static_cast<int>(target_sock)), true) &&
                        configure_client_tls(target_ctx, target_ssl, target_host, remap_policy, alpn_h1, sizeof(alpn_h1)) &&
                        ssl_handshake_with_timeout(target_ssl, SSL_connect) &&
                        (SSL_get_verify_result(target_ssl) == X509_V_OK || remap_policy.policy.ignore_cert_errors) &&
                        verify_upstream_pin(target_ssl, remap_policy);
                    if (!remap_ok) {
                        exchange.state = http_exchange::state_t::error;
                        exchange.error_msg = "map remote upstream TLS connection failed";
                        exchange.raw_response = build_error_response(502, "Bad Gateway", exchange.error_msg);
                        exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                        SSL_write(client_ssl, exchange.raw_response.data(), static_cast<int>(exchange.raw_response.size()));
                        record_history(state, config, std::move(exchange));
                        goto cleanup_no_history;
                    }
                }

                int sent = SSL_write(target_ssl, request_data.data(), static_cast<int>(request_data.size()));
                diag::log_tagged_fmt("mitm", "handle_tls_connection SSL_write request sent=%d size=%zu host=%s", sent, request_data.size(), target_host.c_str());
                if (sent > 0) {

                    std::vector<uint8_t> response_data;
                    if (recv_ssl_all(target_ssl, response_data, config.max_body_size)) {
                        if (response_should_stream(response_data)) {
                            exchange.raw_response = response_data;
                            exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                            exchange.response_time = GetTickCount64();
                            exchange.latency_ms = exchange.response_time - exchange.request_time;
                            exchange.state = http_exchange::state_t::complete;
                            add_tags(exchange, {"streamed-response"});
                            ssl_write_all(client_ssl, response_data.data(), response_data.size());
                            uint64_t streamed = response_data.size();
                            relay_streaming_body(state,
                                                 exchange.raw_response,
                                                 config.max_body_size,
                                                 streamed,
                                                 [&](uint8_t* buf, int len) { return ssl_read_some_blocking(target_ssl, buf, len, 1000); },
                                                 [&](const uint8_t* buf, size_t len) { return ssl_write_all(client_ssl, buf, len); });
                            exchange.response_size = static_cast<size_t>(streamed);
                            state.total_bytes_out.fetch_add(streamed);
                            apply_sticky_session_response(config, exchange);
                            record_history(state, config, std::move(exchange));
                            goto cleanup_no_history;
                        }
                        read_remaining_body_ssl(target_ssl, response_data, config.max_body_size);

                        exchange.raw_response = response_data;
                        exchange.response_size = response_data.size();
                        exchange.response_time = GetTickCount64();
                        exchange.latency_ms = exchange.response_time - exchange.request_time;
                        exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                        exchange.state = http_exchange::state_t::complete;
                        diag::log_tagged_fmt("mitm", "handle_tls_connection response status=%d size=%zu host=%s exchange_id=%llu latency_ms=%llu",
                            exchange.response.status_code, response_data.size(), target_host.c_str(),
                            static_cast<unsigned long long>(exchange.id),
                            static_cast<unsigned long long>(exchange.latency_ms));

                        state.total_bytes_out.fetch_add(response_data.size());

                        if (script_engine::is_initialized()) {
                            script_engine::hook_response_data hook_data;
                            hook_data.status_code = exchange.response.status_code;
                            hook_data.host = target_host;
                            hook_data.port = target_port;
                            for (const auto& h : exchange.response.headers)
                                hook_data.headers[h.name] = h.value;
                            hook_data.body = response_data;
                            script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
                            if (hook_data.dropped) {
                                diag::log_tagged_fmt("mitm", "handle_tls_connection script dropped response exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                                exchange.state = http_exchange::state_t::dropped;
                            } else if (hook_data.modified) {
                                diag::log_tagged_fmt("mitm", "handle_tls_connection script modified response exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                                response_data = hook_data.body;
                            }
                        }

                        aida::burp::match_replace::apply_response(response_data, target_host, "https");
                        exchange.raw_response = response_data;
                        exchange.response_size = response_data.size();
                        exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());

                        if (exchange.state != http_exchange::state_t::dropped)
                            SSL_write(client_ssl, response_data.data(), static_cast<int>(response_data.size()));
                        apply_sticky_session_response(config, exchange);

                        if (config.enable_websocket && is_websocket_upgrade(exchange.response)) {
                            diag::log_tagged_fmt("mitm", "handle_tls_connection WebSocket upgrade detected exchange_id=%llu host=%s:%u",
                                static_cast<unsigned long long>(exchange.id), target_host.c_str(), target_port);
                            std::shared_ptr<http_exchange> ws_exchange;
                            {
                                std::lock_guard<std::mutex> lock(state.history_mutex);
                                ws_exchange = std::make_shared<http_exchange>(exchange);
                                state.history.push_back(ws_exchange);
                                while (state.history.size() > config.max_history)
                                    state.history.pop_front();
                            }

                            websocket_relay(client_ssl, target_ssl, *ws_exchange, state);
                            goto cleanup_no_history;
                        }
                    } else {
                        exchange.state = http_exchange::state_t::error;
                        exchange.error_msg = "No response from target";
                    }
                } else {
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "Failed to send to target";
                }
            }


            {
                publish_exchange_event(exchange);
                std::lock_guard<std::mutex> lock(state.history_mutex);
                state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
                while (state.history.size() > config.max_history)
                    state.history.pop_front();
            }
        }
    }

cleanup:
cleanup_no_history:
    state.active_connections.fetch_sub(1);


    if (target_ssl) {
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
    }
    if (target_ctx)
        SSL_CTX_free(target_ctx);
    if (client_ssl) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
    }
    close_socket(target_sock);
    close_socket(client_sock);
}


static void handle_plain_connection(SOCKET client_sock, const std::string& client_addr,
                                     uint16_t client_port, state_t& state, const proxy_config& config,
                                     const std::string& forced_target_host = {},
                                     uint16_t forced_target_port = 0,
                                     bool forced_tls = false) {
    diag::log_tagged_fmt("mitm", "handle_plain_connection entry client=%s:%u", client_addr.c_str(), client_port);
    state.active_connections.fetch_add(1);

    std::vector<uint8_t> request_data;
    if (!recv_all(client_sock, request_data, config.max_body_size)) {
        diag::log_tagged_fmt("mitm", "handle_plain_connection recv_all failed client=%s:%u", client_addr.c_str(), client_port);
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }
    read_remaining_body(client_sock, request_data, config.max_body_size);
    diag::log_tagged_fmt("mitm", "handle_plain_connection recv request_data=%zu client=%s:%u", request_data.size(), client_addr.c_str(), client_port);

    auto req = protocol_parser::parse_http_request(request_data.data(), request_data.size());
    diag::log_tagged_fmt("mitm", "handle_plain_connection parse_http_request valid=%d method=%s uri=%s client=%s:%u",
        (int)req.valid, req.method.c_str(), req.uri.c_str(), client_addr.c_str(), client_port);
    if (!req.valid) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }
    if (!req.complete) {
        http_exchange exchange;
        exchange.id = state.next_id++;
        exchange.timestamp = GetTickCount64();
        exchange.client_addr = client_addr;
        exchange.client_port = client_port;
        exchange.raw_request = request_data;
        exchange.request = req;
        exchange.request_size = request_data.size();
        exchange.request_time = GetTickCount64();
        exchange.state = http_exchange::state_t::error;
        exchange.error_msg = "request body exceeds buffered interception limit";
        exchange.raw_response = build_error_response(413, "Payload Too Large", exchange.error_msg);
        exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
        send(client_sock, reinterpret_cast<const char*>(exchange.raw_response.data()), static_cast<int>(exchange.raw_response.size()), 0);
        record_history(state, config, std::move(exchange));
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }


    if (!proxy_authorization_valid(req, config)) {
        diag::log_tagged_fmt("mitm", "handle_plain_connection proxy_auth_required client=%s:%u", client_addr.c_str(), client_port);
        send_proxy_auth_required(client_sock, config);
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }
    remove_proxy_headers(request_data);
    req = protocol_parser::parse_http_request(request_data.data(), request_data.size());

    std::string target_host = forced_target_host.empty() ? protocol_parser::find_header(req.headers, "Host") : forced_target_host;
    uint16_t target_port = forced_target_port == 0 ? 80 : forced_target_port;
    bool upstream_tls = forced_tls;
    if (forced_target_host.empty()) {
        if (req.uri.rfind("https://", 0) == 0) {
            upstream_tls = true;
            target_port = 443;
        }
        size_t colon = target_host.rfind(':');
        if (colon != std::string::npos) {
            uint16_t parsed_port = 0;
            if (parse_uint16(target_host.substr(colon + 1), parsed_port))
                target_port = parsed_port;
            target_host = target_host.substr(0, colon);
        }
    }

    diag::log_tagged_fmt("mitm", "handle_plain_connection target_host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);
    if (target_host.empty()) {
        diag::log_tagged_fmt("mitm", "handle_plain_connection empty_target_host client=%s:%u", client_addr.c_str(), client_port);
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }

    http_exchange exchange;
    exchange.id = state.next_id++;
    exchange.timestamp = GetTickCount64();
    exchange.client_addr = client_addr;
    exchange.client_port = client_port;
    exchange.target_host = target_host;
    exchange.target_port = target_port;
    exchange.is_tls = upstream_tls;
    exchange.raw_request = request_data;
    exchange.request_size = request_data.size();
    exchange.request_time = GetTickCount64();
    exchange.request = req;
    exchange.state = http_exchange::state_t::pending;

    state.total_requests.fetch_add(1);
    state.total_bytes_in.fetch_add(request_data.size());


    if (script_engine::is_initialized()) {
        diag::log_tagged_fmt("mitm", "handle_plain_connection script_hook_request exchange_id=%llu method=%s uri=%s", static_cast<unsigned long long>(exchange.id), req.method.c_str(), req.uri.c_str());
        script_engine::hook_request_data hook_data;
        hook_data.method = req.method;
        hook_data.uri = req.uri;
        hook_data.host = target_host;
        hook_data.port = target_port;
        hook_data.is_tls = upstream_tls;
        for (const auto& h : req.headers)
            hook_data.headers[h.name] = h.value;
        hook_data.body = request_data;
        script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
        if (hook_data.dropped) {
            diag::log_tagged_fmt("mitm", "handle_plain_connection script_dropped exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
            exchange.state = http_exchange::state_t::dropped;
            publish_exchange_event(exchange);
            std::lock_guard<std::mutex> lock(state.history_mutex);
            state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
            while (state.history.size() > config.max_history)
                state.history.pop_front();
            state.active_connections.fetch_sub(1);
            close_socket(client_sock);
            return;
        }
        if (hook_data.modified) {
            diag::log_tagged_fmt("mitm", "handle_plain_connection script_modified exchange_id=%llu new_body=%zu", static_cast<unsigned long long>(exchange.id), hook_data.body.size());
            request_data = hook_data.body;
        }
    }

    apply_sticky_session_request(config, exchange, request_data);
    aida::burp::match_replace::apply_request(request_data, target_host, upstream_tls ? "https" : "http");
    exchange.raw_request = request_data;
    exchange.request_size = request_data.size();
    exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());

    bool should_forward = true;
    if (config.intercept_enabled) {
        bool cb_decided = false;
        if (state.intercept_cb) {
            intercept_action action = state.intercept_cb(exchange);
            if (action == intercept_action::drop) {
                diag::log_tagged_fmt("mitm", "handle_plain_connection intercept_cb_drop exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                exchange.state = http_exchange::state_t::dropped;
                should_forward = false;
                cb_decided = true;
            } else if (action == intercept_action::modify) {
                diag::log_tagged_fmt("mitm", "handle_plain_connection intercept_cb_modify exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                request_data = exchange.raw_request;
                cb_decided = true;
            } else if (action == intercept_action::forward) {
                diag::log_tagged_fmt("mitm", "handle_plain_connection intercept_cb_forward exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                cb_decided = true;
            }
        }
        if (!cb_decided && should_forward) {
            diag::log_tagged_fmt("mitm", "handle_plain_connection hold_until_decision exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
            exchange.raw_request = request_data;
            exchange.request_size = request_data.size();
            hold_outcome_t outcome = hold_until_decision(state, exchange);
            diag::log_tagged_fmt("mitm", "handle_plain_connection hold_decision=%d exchange_id=%llu", (int)outcome.decision, static_cast<unsigned long long>(exchange.id));
            if (outcome.decision == hold_decision_t::drop) {
                exchange.state = http_exchange::state_t::dropped;
                should_forward = false;
            } else if (outcome.decision == hold_decision_t::modified) {
                request_data = std::move(outcome.modified_request);
                exchange.raw_request = request_data;
                exchange.request_size = request_data.size();
                exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
                if (!exchange.request.valid) {
                    diag::log_tagged_fmt("mitm", "handle_plain_connection modified request invalid exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                    exchange.state = http_exchange::state_t::dropped;
                    should_forward = false;
                }
            }
        }
    }

    diag::log_tagged_fmt("mitm", "handle_plain_connection should_forward=%d exchange_id=%llu", (int)should_forward, static_cast<unsigned long long>(exchange.id));
    if (should_forward) {
        exchange.state = http_exchange::state_t::forwarding;
        auto local = map_resource::try_local(exchange);
        if (local.matched) {
            exchange.raw_response = local.raw_response.empty()
                ? build_error_response(502, "Bad Gateway", local.error.empty() ? "map local failed" : local.error)
                : local.raw_response;
            add_tags(exchange, local.tags);
            exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
            exchange.response_size = exchange.raw_response.size();
            exchange.response_time = GetTickCount64();
            exchange.latency_ms = exchange.response_time - exchange.request_time;
            exchange.state = local.raw_response.empty() ? http_exchange::state_t::error : http_exchange::state_t::complete;
            if (exchange.state == http_exchange::state_t::error)
                exchange.error_msg = local.error;
            send(client_sock, reinterpret_cast<const char*>(exchange.raw_response.data()), static_cast<int>(exchange.raw_response.size()), 0);
            state.total_bytes_out.fetch_add(exchange.raw_response.size());
            apply_sticky_session_response(config, exchange);
            record_history(state, config, std::move(exchange));
            state.active_connections.fetch_sub(1);
            close_socket(client_sock);
            return;
        }
        auto replay = server_replay::match(exchange, request_data);
        if (replay.matched) {
            exchange.raw_response = replay.raw_response;
            add_tags(exchange, replay.tags);
            exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
            exchange.response_size = exchange.raw_response.size();
            exchange.response_time = GetTickCount64();
            exchange.latency_ms = exchange.response_time - exchange.request_time;
            exchange.state = http_exchange::state_t::complete;
            send(client_sock, reinterpret_cast<const char*>(exchange.raw_response.data()), static_cast<int>(exchange.raw_response.size()), 0);
            state.total_bytes_out.fetch_add(exchange.raw_response.size());
            apply_sticky_session_response(config, exchange);
            record_history(state, config, std::move(exchange));
            state.active_connections.fetch_sub(1);
            close_socket(client_sock);
            return;
        }
        auto remote = map_resource::try_remote(exchange, request_data);
        if (remote.matched) {
            if (!remote.error.empty()) {
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = remote.error;
                exchange.raw_response = build_error_response(502, "Bad Gateway", remote.error);
                exchange.response = protocol_parser::parse_http_response(exchange.raw_response.data(), exchange.raw_response.size());
                send(client_sock, reinterpret_cast<const char*>(exchange.raw_response.data()), static_cast<int>(exchange.raw_response.size()), 0);
                record_history(state, config, std::move(exchange));
                state.active_connections.fetch_sub(1);
                close_socket(client_sock);
                return;
            }
            add_tags(exchange, remote.tags);
            target_host = remote.host;
            target_port = remote.port;
            upstream_tls = remote.use_tls;
            request_data = std::move(remote.raw_request);
            exchange.target_host = target_host;
            exchange.target_port = target_port;
            exchange.is_tls = upstream_tls;
            exchange.raw_request = request_data;
            exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
        }
        SOCKET target_sock = connect_to_target(target_host, target_port, config, upstream_tls);
        diag::log_tagged_fmt("mitm", "handle_plain_connection connect_to_target host=%s port=%u result=%d exchange_id=%llu", target_host.c_str(), target_port, (target_sock != INVALID_SOCKET) ? 1 : 0, static_cast<unsigned long long>(exchange.id));
        if (target_sock != INVALID_SOCKET) {
            SSL_CTX* upstream_ctx = nullptr;
            SSL* upstream_ssl = nullptr;
            bool upstream_ready = true;
            if (upstream_tls) {
                const auto upstream_policy = tls_policy::match_host(target_host);
                upstream_ctx = SSL_CTX_new(TLS_client_method());
                upstream_ssl = upstream_ctx ? SSL_new(upstream_ctx) : nullptr;
                if (!upstream_ssl) {
                    upstream_ready = false;
                } else {
                    SSL_set_fd(upstream_ssl, static_cast<int>(target_sock));
                    upstream_ready = configure_client_tls(upstream_ctx, upstream_ssl, target_host, upstream_policy, nullptr, 0) &&
                                     ssl_handshake_with_timeout(upstream_ssl, SSL_connect) &&
                                     (SSL_get_verify_result(upstream_ssl) == X509_V_OK || upstream_policy.policy.ignore_cert_errors) &&
                                     verify_upstream_pin(upstream_ssl, upstream_policy);
                }
            }
            int sent = -1;
            if (upstream_ready) {
                sent = upstream_tls
                    ? SSL_write(upstream_ssl, request_data.data(), static_cast<int>(request_data.size()))
                    : send(target_sock, reinterpret_cast<const char*>(request_data.data()), static_cast<int>(request_data.size()), 0);
            }
            diag::log_tagged_fmt("mitm", "handle_plain_connection send_request sent=%d size=%zu exchange_id=%llu", sent, request_data.size(), static_cast<unsigned long long>(exchange.id));
            if (sent > 0) {
                std::vector<uint8_t> response_data;
                bool response_ok = false;
                if (upstream_tls) {
                    response_ok = recv_ssl_all(upstream_ssl, response_data, config.max_body_size);
                } else {
                    response_ok = recv_all(target_sock, response_data, config.max_body_size);
                }
                if (response_ok) {
                    if (response_should_stream(response_data)) {
                        exchange.raw_response = response_data;
                        exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                        exchange.response_time = GetTickCount64();
                        exchange.latency_ms = exchange.response_time - exchange.request_time;
                        exchange.state = http_exchange::state_t::complete;
                        add_tags(exchange, {"streamed-response"});
                        socket_write_all(client_sock, response_data.data(), response_data.size());
                        uint64_t streamed = response_data.size();
                        if (upstream_tls) {
                            relay_streaming_body(state,
                                                 exchange.raw_response,
                                                 config.max_body_size,
                                                 streamed,
                                                 [&](uint8_t* buf, int len) { return ssl_read_some_blocking(upstream_ssl, buf, len, 1000); },
                                                 [&](const uint8_t* buf, size_t len) { return socket_write_all(client_sock, buf, len); });
                        } else {
                            relay_streaming_body(state,
                                                 exchange.raw_response,
                                                 config.max_body_size,
                                                 streamed,
                                                 [&](uint8_t* buf, int len) { return socket_read_some_blocking(target_sock, buf, len, 1000); },
                                                 [&](const uint8_t* buf, size_t len) { return socket_write_all(client_sock, buf, len); });
                        }
                        exchange.response_size = static_cast<size_t>(streamed);
                        state.total_bytes_out.fetch_add(streamed);
                        apply_sticky_session_response(config, exchange);
                        record_history(state, config, std::move(exchange));
                        if (upstream_ssl) {
                            SSL_shutdown(upstream_ssl);
                            SSL_free(upstream_ssl);
                        }
                        if (upstream_ctx)
                            SSL_CTX_free(upstream_ctx);
                        close_socket(target_sock);
                        state.active_connections.fetch_sub(1);
                        close_socket(client_sock);
                        return;
                    }
                    if (upstream_tls)
                        read_remaining_body_ssl(upstream_ssl, response_data, config.max_body_size);
                    else
                        read_remaining_body(target_sock, response_data, config.max_body_size);

                    exchange.raw_response = response_data;
                    exchange.response_size = response_data.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                    exchange.state = http_exchange::state_t::complete;
                    diag::log_tagged_fmt("mitm", "handle_plain_connection response_ok status=%d size=%zu latency_ms=%llu exchange_id=%llu", exchange.response.status_code, response_data.size(), static_cast<unsigned long long>(exchange.latency_ms), static_cast<unsigned long long>(exchange.id));

                    state.total_bytes_out.fetch_add(response_data.size());


                    if (script_engine::is_initialized()) {
                        script_engine::hook_response_data hook_data;
                        hook_data.status_code = exchange.response.status_code;
                            hook_data.host = target_host;
                        hook_data.port = target_port;
                        for (const auto& h : exchange.response.headers)
                            hook_data.headers[h.name] = h.value;
                        hook_data.body = response_data;
                        script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
                        if (hook_data.dropped) {
                            diag::log_tagged_fmt("mitm", "handle_plain_connection script_response_dropped exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                            exchange.state = http_exchange::state_t::dropped;
                        } else if (hook_data.modified) {
                            diag::log_tagged_fmt("mitm", "handle_plain_connection script_response_modified new_size=%zu exchange_id=%llu", hook_data.body.size(), static_cast<unsigned long long>(exchange.id));
                            response_data = hook_data.body;
                        }
                    }

                    aida::burp::match_replace::apply_response(response_data, target_host, upstream_tls ? "https" : "http");
                    exchange.raw_response = response_data;
                    exchange.response_size = response_data.size();
                    exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());

                    if (exchange.state != http_exchange::state_t::dropped)
                        send(client_sock, reinterpret_cast<const char*>(response_data.data()),
                             static_cast<int>(response_data.size()), 0);
                    apply_sticky_session_response(config, exchange);
                } else {
                    diag::log_tagged_fmt("mitm", "handle_plain_connection recv_response_failed exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "No response from target";
                }
            } else {
                diag::log_tagged_fmt("mitm", "handle_plain_connection send_failed exchange_id=%llu", static_cast<unsigned long long>(exchange.id));
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = "Failed to send to target";
            }
            if (upstream_ssl) {
                SSL_shutdown(upstream_ssl);
                SSL_free(upstream_ssl);
            }
            if (upstream_ctx)
                SSL_CTX_free(upstream_ctx);
            close_socket(target_sock);
        } else {
            diag::log_tagged_fmt("mitm", "handle_plain_connection connect_failed host=%s port=%u exchange_id=%llu", target_host.c_str(), target_port, static_cast<unsigned long long>(exchange.id));
            exchange.state = http_exchange::state_t::error;
            exchange.error_msg = "Cannot connect to target";
        }
    }

    {
        publish_exchange_event(exchange);
        std::lock_guard<std::mutex> lock(state.history_mutex);
        state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
        while (state.history.size() > config.max_history)
            state.history.pop_front();
    }

    state.active_connections.fetch_sub(1);
    close_socket(client_sock);
}


static bool handle_socks5_client(SOCKET client_sock,
                                 const std::string& client_addr,
                                 uint16_t client_port,
                                 state_t& state,
                                 const proxy_config& config) {
    uint8_t head[2] = {};
    if (!recv_exact(client_sock, head, sizeof(head)) || head[0] != 0x05 || head[1] == 0)
        return false;
    std::vector<uint8_t> methods(head[1]);
    if (!recv_exact(client_sock, methods.data(), methods.size()))
        return false;
    uint8_t selected = 0xFF;
    if (config.require_proxy_auth) {
        if (std::find(methods.begin(), methods.end(), 0x02) != methods.end())
            selected = 0x02;
    } else if (std::find(methods.begin(), methods.end(), 0x00) != methods.end()) {
        selected = 0x00;
    }
    uint8_t sel_resp[2] = {0x05, selected};
    send_exact(client_sock, sel_resp, sizeof(sel_resp));
    if (selected == 0xFF)
        return false;
    if (selected == 0x02) {
        uint8_t ah[2] = {};
        if (!recv_exact(client_sock, ah, sizeof(ah)) || ah[0] != 0x01)
            return false;
        std::string user(static_cast<size_t>(ah[1]), '\0');
        if (!user.empty() && !recv_exact(client_sock, reinterpret_cast<uint8_t*>(&user[0]), user.size()))
            return false;
        uint8_t plen = 0;
        if (!recv_exact(client_sock, &plen, 1))
            return false;
        std::string pass(static_cast<size_t>(plen), '\0');
        if (!pass.empty() && !recv_exact(client_sock, reinterpret_cast<uint8_t*>(&pass[0]), pass.size()))
            return false;
        const bool ok = constant_time_equal(user, config.proxy_auth_username) &&
                        constant_time_equal(pass, config.proxy_auth_password);
        uint8_t ar[2] = {0x01, static_cast<uint8_t>(ok ? 0x00 : 0x01)};
        send_exact(client_sock, ar, sizeof(ar));
        if (!ok)
            return false;
    }

    uint8_t reqh[4] = {};
    if (!recv_exact(client_sock, reqh, sizeof(reqh)) || reqh[0] != 0x05 || reqh[1] != 0x01 || reqh[2] != 0x00)
        return false;
    std::string target_host;
    if (reqh[3] == 0x01) {
        uint8_t addr[4] = {};
        if (!recv_exact(client_sock, addr, sizeof(addr)))
            return false;
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, addr, buf, sizeof(buf));
        target_host = buf;
    } else if (reqh[3] == 0x03) {
        uint8_t len = 0;
        if (!recv_exact(client_sock, &len, 1) || len == 0)
            return false;
        target_host.assign(static_cast<size_t>(len), '\0');
        if (!recv_exact(client_sock, reinterpret_cast<uint8_t*>(&target_host[0]), target_host.size()))
            return false;
    } else if (reqh[3] == 0x04) {
        uint8_t addr[16] = {};
        if (!recv_exact(client_sock, addr, sizeof(addr)))
            return false;
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
        target_host = buf;
    } else {
        return false;
    }
    uint8_t pbuf[2] = {};
    if (!recv_exact(client_sock, pbuf, sizeof(pbuf)))
        return false;
    const uint16_t target_port = static_cast<uint16_t>((pbuf[0] << 8) | pbuf[1]);
    uint8_t ok_resp[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send_exact(client_sock, ok_resp, sizeof(ok_resp));
    diag::log_tagged_fmt("mitm", "socks5_client connect target=%s:%u client=%s:%u decode_tls=%d",
        target_host.c_str(), target_port, client_addr.c_str(), client_port, config.decode_tls ? 1 : 0);
    if (config.decode_tls && target_port == 443) {
        handle_tls_connection(client_sock, target_host, target_port, client_addr, client_port, state, config);
        return true;
    }
    handle_plain_connection(client_sock, client_addr, client_port, state, config, target_host, target_port, false);
    return true;
}

static void handle_client(SOCKET client_sock, sockaddr_in client_addr_in, state_t& state, const proxy_config& config) {
    std::string client_addr = addr_to_string(client_addr_in);
    uint16_t client_port = ntohs(client_addr_in.sin_port);
    diag::log_tagged_fmt("mitm", "handle_client entry client=%s:%u", client_addr.c_str(), client_port);

    uint8_t peek_buf[16] = {};
    int peeked = recv(client_sock, reinterpret_cast<char*>(peek_buf), sizeof(peek_buf), MSG_PEEK);
    if (peeked <= 0) {
        diag::log_tagged_fmt("mitm", "handle_client peek_failed peeked=%d client=%s:%u", peeked, client_addr.c_str(), client_port);
        close_socket(client_sock);
        return;
    }

    diag::log_tagged_fmt("mitm", "handle_client peeked=%d first_bytes=%02x%02x%02x is_connect=%d mode=%d client=%s:%u", peeked, peek_buf[0], peek_buf[1], peek_buf[2], (peeked >= 7 && memcmp(peek_buf, "CONNECT", 7) == 0) ? 1 : 0, (int)config.mode, client_addr.c_str(), client_port);

    if (config.mode == proxy_mode_t::socks5 || peek_buf[0] == 0x05) {
        if (!handle_socks5_client(client_sock, client_addr, client_port, state, config))
            close_socket(client_sock);
        return;
    }

    if (config.mode == proxy_mode_t::reverse) {
        if (config.reverse_target_host.empty() || config.reverse_target_port == 0) {
            close_socket(client_sock);
            return;
        }
        if (config.decode_tls && peek_buf[0] == 0x16) {
            handle_tls_connection(client_sock, config.reverse_target_host, config.reverse_target_port, client_addr, client_port, state, config);
        } else {
            handle_plain_connection(client_sock, client_addr, client_port, state, config,
                                    config.reverse_target_host, config.reverse_target_port, config.reverse_target_tls);
        }
        return;
    }

    if (config.mode == proxy_mode_t::transparent && config.decode_tls && peek_buf[0] == 0x16) {
        std::vector<uint8_t> hello(4096);
        int got = recv(client_sock, reinterpret_cast<char*>(hello.data()), static_cast<int>(hello.size()), MSG_PEEK);
        std::string sni;
        if (got > 0) {
            auto parsed = protocol_parser::parse_client_hello(hello.data(), static_cast<size_t>(got));
            if (parsed.valid)
                sni = parsed.sni;
        }
        if (sni.empty()) {
            record_tls_observation(state, tls_observation_kind_t::client_handshake_failed,
                std::string(), config.redirect_target_port, client_addr, client_port, std::string(), std::string(),
                "transparent_tls_missing_sni");
            close_socket(client_sock);
            return;
        }
        handle_tls_connection(client_sock, sni, config.redirect_target_port, client_addr, client_port, state, config);
        return;
    }

    if (peeked >= 7 && memcmp(peek_buf, "CONNECT", 7) == 0) {

        std::vector<uint8_t> connect_req;
        if (!recv_all(client_sock, connect_req, 8192)) {
            diag::log_tagged_fmt("mitm", "handle_client connect_recv_all_failed client=%s:%u", client_addr.c_str(), client_port);
            close_socket(client_sock);
            return;
        }

        auto connect_parsed = protocol_parser::parse_http_request(connect_req.data(), connect_req.size());
        if (!proxy_authorization_valid(connect_parsed, config)) {
            diag::log_tagged_fmt("mitm", "handle_client connect_proxy_auth_required client=%s:%u", client_addr.c_str(), client_port);
            send_proxy_auth_required(client_sock, config);
            close_socket(client_sock);
            return;
        }

        std::string first_line(connect_req.begin(),
            std::find(connect_req.begin(), connect_req.end(), '\r'));
        std::string target_host;
        uint16_t target_port = 443;
        parse_connect_target(first_line, target_host, target_port);
        diag::log_tagged_fmt("mitm", "handle_client connect_target host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);

        if (target_host.empty()) {
            diag::log_tagged_fmt("mitm", "handle_client connect_empty_target client=%s:%u", client_addr.c_str(), client_port);
            close_socket(client_sock);
            return;
        }


        const char* ok_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_sock, ok_resp, static_cast<int>(strlen(ok_resp)), 0);

        if (config.decode_tls) {
            diag::log_tagged_fmt("mitm", "handle_client dispatch_tls host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);
            handle_tls_connection(client_sock, target_host, target_port, client_addr, client_port, state, config);
        } else {
            diag::log_tagged_fmt("mitm", "handle_client dispatch_tunnel host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);
            record_tls_observation(state, tls_observation_kind_t::tunnel_passthrough,
                target_host, target_port, client_addr, client_port, std::string(), std::string(),
                "CONNECT tunnel passed without TLS decoding");
            SOCKET target_sock = connect_to_target(target_host, target_port, config, target_port == 443);
            if (target_sock == INVALID_SOCKET) {
                diag::log_tagged_fmt("mitm", "handle_client tunnel_connect_failed host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);
                close_socket(client_sock);
                return;
            }

            state.active_connections.fetch_add(1);
            diag::log_tagged_fmt("mitm", "handle_client tunnel_started host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);

            fd_set fds;
            uint8_t buf[8192];
            bool done = false;
            while (!done && state.running.load()) {
                FD_ZERO(&fds);
                FD_SET(client_sock, &fds);
                FD_SET(target_sock, &fds);

                timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                SOCKET max_fd = (client_sock > target_sock) ? client_sock : target_sock;
                int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
                if (sel <= 0) { if (sel < 0) done = true; continue; }

                if (FD_ISSET(client_sock, &fds)) {
                    int n = recv(client_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(target_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_in.fetch_add(static_cast<uint64_t>(n));
                }
                if (FD_ISSET(target_sock, &fds)) {
                    int n = recv(target_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(client_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_out.fetch_add(static_cast<uint64_t>(n));
                }
            }

            state.active_connections.fetch_sub(1);
            diag::log_tagged_fmt("mitm", "handle_client tunnel_done host=%s port=%u client=%s:%u", target_host.c_str(), target_port, client_addr.c_str(), client_port);
            close_socket(target_sock);
            close_socket(client_sock);
        }
    } else {
        diag::log_tagged_fmt("mitm", "handle_client dispatch_plain client=%s:%u", client_addr.c_str(), client_port);
        handle_plain_connection(client_sock, client_addr, client_port, state, config);
    }
}


static void worker_thread_func(state_t& state) {
    diag::log_tagged("mitm", "worker_thread_func started");
    while (state.proxy_alive.load()) {
        {
            std::unique_lock<std::mutex> lk(state.proxy_start_mtx);
            state.proxy_start_cv.wait(lk, [&state]() {
                return state.running.load() || !state.proxy_alive.load();
            });
        }
        diag::log_tagged_fmt("mitm", "worker_thread_func running=%d proxy_alive=%d", (int)state.running.load(), (int)state.proxy_alive.load());
        while (state.running.load()) {
            work_item item;
            {
                std::unique_lock<std::mutex> lock(state.work_mutex);
                state.work_cv.wait(lock, [&] {
                    return !state.pending_work.empty() || !state.running.load() || !state.proxy_alive.load();
                });
                if (!state.running.load() && state.pending_work.empty()) break;
                if (state.pending_work.empty()) continue;
                item = state.pending_work.front();
                state.pending_work.pop();
            }
            diag::log_tagged_fmt("mitm", "worker_thread_func dequeued client_port=%u", item.client_port);

            sockaddr_in client_addr_in = {};
            client_addr_in.sin_family = AF_INET;
            client_addr_in.sin_addr.s_addr = item.client_ip;
            client_addr_in.sin_port = htons(item.client_port);
            handle_client(static_cast<SOCKET>(item.client_socket), client_addr_in, state, item.config);
        }
        diag::log_tagged("mitm", "worker_thread_func inner_loop_exit");
    }
    diag::log_tagged("mitm", "worker_thread_func exiting");
}

static void listener_thread_func(state_t& state) {
    while (state.proxy_alive.load()) {
        {
            std::unique_lock<std::mutex> lk(state.proxy_start_mtx);
            state.proxy_start_cv.wait(lk, [&state]() {
                return state.running.load() || !state.proxy_alive.load();
            });
        }
        while (state.running.load()) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(static_cast<SOCKET>(state.listen_socket), &fds);

            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;

            sockaddr_in client_addr = {};
            int addr_len = sizeof(client_addr);
            SOCKET client_sock = accept(static_cast<SOCKET>(state.listen_socket),
                reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

            if (client_sock == INVALID_SOCKET) continue;
            set_shutdown_bounded_io(client_sock);

            work_item item;
            item.client_socket = static_cast<uintptr_t>(client_sock);
            item.client_ip = client_addr.sin_addr.s_addr;
            item.client_port = ntohs(client_addr.sin_port);
            item.listener_id = 1;
            item.config = state.config;
            char addr_buf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &client_addr.sin_addr, addr_buf, sizeof(addr_buf));
            diag::log_tagged_fmt("network", "mitm_proxy_accept client=%s:%u",
                addr_buf, item.client_port);
            {
                std::lock_guard<std::mutex> lock(state.work_mutex);
                state.pending_work.push(item);
            }
            state.work_cv.notify_one();
        }
    }
}

struct extra_listener_runtime_t {
    uint64_t id = 0;
    proxy_config config;
    SOCKET listen_socket = INVALID_SOCKET;
    std::atomic<bool> running{false};
    std::atomic<uint64_t> accepted{0};
    aida::infra::win_thread::joinable_thread_t thread;
};

static std::mutex g_extra_listener_mutex;
static std::vector<std::shared_ptr<extra_listener_runtime_t>> g_extra_listeners;
static std::atomic<uint64_t> g_next_extra_listener_id{2};

static bool bind_listen_socket(const proxy_config& config, SOCKET& out_socket) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET)
        return false;
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(config.bind_port);
    if (inet_pton(AF_INET, config.bind_addr.c_str(), &bind_addr.sin_addr) != 1) {
        closesocket(listen_sock);
        return false;
    }
    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }
    out_socket = listen_sock;
    return true;
}

static void remove_wfp_redirect(proxy_config& config) {
    if (config.wfp_rule_id == 0)
        return;
    if (driver_bridge::using_kernel_driver())
        driver_bridge::traffic_redirect_op(1, config.wfp_rule_id);
    config.wfp_rule_id = 0;
}

static void install_wfp_redirect(proxy_config& config) {
    if (!config.use_wfp_redirect || config.wfp_rule_id != 0)
        return;
    if (!driver_bridge::using_kernel_driver())
        return;
    uint8_t local_addr[16] = {};
    inet_pton(AF_INET, config.bind_addr.c_str(), local_addr);
    uint32_t rule_id = 0;
    uint32_t own_pid = static_cast<uint32_t>(GetCurrentProcessId());
    bool ok = driver_bridge::traffic_redirect_op(
        0,
        0,
        6,
        config.redirect_target_port,
        nullptr,
        config.bind_port,
        local_addr,
        2,
        &rule_id,
        own_pid);
    if (ok)
        config.wfp_rule_id = rule_id;
}

static void extra_listener_loop(std::shared_ptr<extra_listener_runtime_t> rt) {
    diag::log_tagged_fmt("network", "mitm_extra_listener_started id=%llu bind=%s:%u mode=%d",
        static_cast<unsigned long long>(rt->id), rt->config.bind_addr.c_str(), rt->config.bind_port, (int)rt->config.mode);
    while (rt->running.load() && g_state.proxy_alive.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(rt->listen_socket, &fds);
        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0)
            continue;
        sockaddr_in client_addr = {};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(rt->listen_socket, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock == INVALID_SOCKET)
            continue;
        set_shutdown_bounded_io(client_sock);
        work_item item;
        item.client_socket = static_cast<uintptr_t>(client_sock);
        item.client_ip = client_addr.sin_addr.s_addr;
        item.client_port = ntohs(client_addr.sin_port);
        item.listener_id = rt->id;
        item.config = rt->config;
        rt->accepted.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(g_state.work_mutex);
            g_state.pending_work.push(item);
        }
        g_state.work_cv.notify_one();
    }
    diag::log_tagged_fmt("network", "mitm_extra_listener_stopped id=%llu", static_cast<unsigned long long>(rt->id));
}

static bool validate_listener_config(const proxy_config& config) {
    if (config.bind_addr.empty() || config.bind_port == 0)
        return false;
    if (config.mode == proxy_mode_t::reverse && (config.reverse_target_host.empty() || config.reverse_target_port == 0))
        return false;
    if (config.require_proxy_auth && (config.proxy_auth_username.empty() || config.proxy_auth_password.empty()))
        return false;
    return true;
}

static bool prepare_tls_if_needed(const proxy_config& config) {
    if (!config.decode_tls)
        return true;
    if (!cert_generator::is_ready() && !cert_generator::initialize())
        return false;
    const auto& ca = cert_generator::get_root_ca();
    if (!ca.valid || !ca.cert)
        return false;
    bool installed = cert_generator::is_root_ca_installed(ca);
    if (!installed)
        installed = cert_generator::install_root_ca(ca);
    return installed && cert_generator::is_root_ca_installed(ca);
}

static void configure_connection_pool(const proxy_config& config) {
    conn_pool::connection_pool_config pool_cfg;
    pool_cfg.max_idle_total = config.connection_pool_max_idle_total;
    pool_cfg.max_idle_per_key = config.connection_pool_max_idle_per_key;
    pool_cfg.idle_timeout_ms = config.connection_pool_idle_timeout_ms;
    pool_cfg.max_age_ms = config.connection_pool_max_age_ms;
    conn_pool::configure(pool_cfg);
    if (!config.enable_connection_pool)
        conn_pool::clear();
}

static void stop_extra_listeners() {
    std::vector<std::shared_ptr<extra_listener_runtime_t>> listeners;
    {
        std::lock_guard<std::mutex> lock(g_extra_listener_mutex);
        listeners.swap(g_extra_listeners);
    }
    for (auto& rt : listeners) {
        if (!rt)
            continue;
        rt->running.store(false);
        if (rt->listen_socket != INVALID_SOCKET) {
            closesocket(rt->listen_socket);
            rt->listen_socket = INVALID_SOCKET;
        }
        rt->thread.join_for(10000);
        remove_wfp_redirect(rt->config);
    }
}


bool start(const proxy_config& config) {
    if (g_state.running.load()) {
        diag::log_tagged("network", "mitm_proxy_start_skip already_running");
        return false;
    }

    if (!g_state.proxy_alive.load(std::memory_order_acquire)) {
        diag::log_tagged("network", "mitm_proxy_start_failed workers_not_ready");
        return false;
    }

    if (!validate_listener_config(config)) {
        diag::log_tagged("network", "mitm_proxy_start_failed invalid_config");
        return false;
    }

    if (!s_wsa_guard.ok) {
        diag::log_tagged("network", "mitm_proxy_start_failed wsa_guard_not_ok");
        return false;
    }

    if (!prepare_tls_if_needed(config)) {
        diag::log_tagged("network", "mitm_proxy_start_failed tls_not_ready");
        return false;
    }
    configure_connection_pool(config);

    g_state.config = config;


    SOCKET listen_sock = INVALID_SOCKET;
    if (!bind_listen_socket(config, listen_sock)) {
        diag::log_tagged_fmt("network", "mitm_proxy_start_failed socket_create err=%d", WSAGetLastError());
        return false;
    }

    g_state.listen_socket = static_cast<uintptr_t>(listen_sock);
    g_state.running.store(true);
    g_state.proxy_start_cv.notify_all();
    diag::log_tagged_fmt("network", "mitm_proxy_started bind=%s:%u decode_tls=%d enable_h2=%d enable_ws=%d wfp_redirect=%d",
        config.bind_addr.c_str(), config.bind_port, config.decode_tls ? 1 : 0,
        config.enable_h2 ? 1 : 0, config.enable_websocket ? 1 : 0,
        config.use_wfp_redirect ? 1 : 0);


    if (config.use_wfp_redirect) {
        install_wfp_redirect(g_state.config);
    }

    return true;
}

bool start_listener(const proxy_config& config, uint64_t* listener_id) {
    if (!g_state.running.load()) {
        const bool ok = start(config);
        if (ok && listener_id)
            *listener_id = 1;
        return ok;
    }
    if (!validate_listener_config(config) || !s_wsa_guard.ok)
        return false;
    if (!prepare_tls_if_needed(config))
        return false;
    configure_connection_pool(config);
    SOCKET listen_sock = INVALID_SOCKET;
    if (!bind_listen_socket(config, listen_sock))
        return false;
    auto rt = std::make_shared<extra_listener_runtime_t>();
    rt->id = g_next_extra_listener_id.fetch_add(1, std::memory_order_acq_rel);
    rt->config = config;
    rt->listen_socket = listen_sock;
    install_wfp_redirect(rt->config);
    rt->running.store(true);
    auto rt_for_thread = rt;
    std::string thread_start_err;
    if (!rt->thread.start([rt_for_thread]() { extra_listener_loop(rt_for_thread); }, &thread_start_err,
            aida::infra::win_thread::default_stack_reserve, "mitm_proxy.extra_listener")) {
        diag::log_tagged_fmt("mitm_proxy", "extra_listener_thread_start_failed err=%s", thread_start_err.c_str());
        rt->running.store(false);
        remove_wfp_redirect(rt->config);
        if (rt->listen_socket != INVALID_SOCKET) { closesocket(rt->listen_socket); rt->listen_socket = INVALID_SOCKET; }
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_extra_listener_mutex);
        g_extra_listeners.push_back(rt);
    }
    if (listener_id)
        *listener_id = rt->id;
    return true;
}

bool stop_listener(uint64_t listener_id) {
    if (listener_id == 0)
        return false;
    if (listener_id == 1) {
        stop();
        return true;
    }
    std::shared_ptr<extra_listener_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lock(g_extra_listener_mutex);
        auto it = std::find_if(g_extra_listeners.begin(), g_extra_listeners.end(), [listener_id](const std::shared_ptr<extra_listener_runtime_t>& item) {
            return item && item->id == listener_id;
        });
        if (it == g_extra_listeners.end())
            return false;
        rt = *it;
        g_extra_listeners.erase(it);
    }
    rt->running.store(false);
    if (rt->listen_socket != INVALID_SOCKET) {
        closesocket(rt->listen_socket);
        rt->listen_socket = INVALID_SOCKET;
    }
    rt->thread.join_for(10000);
    remove_wfp_redirect(rt->config);
    return true;
}

void stop() {
    if (!g_state.running.load()) return;
    diag::log_tagged_fmt("network", "mitm_proxy_stop_begin held_count=%zu history=%zu requests=%llu",
        g_state.held_waits.size(), g_state.history.size(),
        static_cast<unsigned long long>(g_state.total_requests.load()));

    stop_extra_listeners();

    remove_wfp_redirect(g_state.config);

    g_state.running.store(false);


    g_state.work_cv.notify_all();
    g_state.held_cv.notify_all();

    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (!wait->released) {
                wait->decision = hold_decision_t::drop;
                wait->released = true;
            }
        }
        wait->cv.notify_all();
    }


    if (g_state.listen_socket != ~static_cast<uintptr_t>(0)) {
        closesocket(static_cast<SOCKET>(g_state.listen_socket));
        g_state.listen_socket = ~static_cast<uintptr_t>(0);
    }
    diag::log_tagged("network", "mitm_proxy_stop_complete");
}

bool is_running() {
    return g_state.running.load();
}

proxy_config get_config() {
    return g_state.config;
}

bool set_config(const proxy_config& config) {
    if (!validate_listener_config(config))
        return false;
    if (g_state.running.load())
        return false;
    g_state.config = config;
    configure_connection_pool(config);
    return true;
}

std::vector<listener_snapshot> get_listeners() {
    std::vector<listener_snapshot> out;
    if (g_state.running.load()) {
        listener_snapshot primary;
        primary.id = 1;
        primary.config = g_state.config;
        primary.running = true;
        out.push_back(primary);
    }
    std::lock_guard<std::mutex> lock(g_extra_listener_mutex);
    out.reserve(out.size() + g_extra_listeners.size());
    for (const auto& rt : g_extra_listeners) {
        if (!rt)
            continue;
        listener_snapshot snap;
        snap.id = rt->id;
        snap.config = rt->config;
        snap.running = rt->running.load();
        snap.accepted = rt->accepted.load(std::memory_order_relaxed);
        out.push_back(std::move(snap));
    }
    return out;
}

void pre_initialize() {
    diag::log_tagged_fmt("mitm", "pre_initialize entry worker_pool_size=%u", WORKER_POOL_SIZE);
    auto& st = g_state;
    st.proxy_alive.store(true, std::memory_order_release);

    state_t* st_ptr = &st;

    st.listener_done.store(false, std::memory_order_release);
    aida::infra::executor::submission_t listener_sub;
    listener_sub.owner_subsystem = "network.mitm";
    listener_sub.label = "mitm.listener";
    listener_sub.thread_class = "service_loop";
    listener_sub.domain = aida::infra::executor::domain_t::service;
    listener_sub.priority = 4;
    listener_sub.body = [st_ptr]() {
        try {
            listener_thread_func(*st_ptr);
        } catch (const std::exception& ex) {
            st_ptr->listener_done.store(true, std::memory_order_release);
            st_ptr->running.store(false, std::memory_order_release);
            st_ptr->proxy_alive.store(false, std::memory_order_release);
            st_ptr->work_cv.notify_all();
            st_ptr->proxy_start_cv.notify_all();
            diag::log_tagged_fmt("mitm", "listener_thread_exception type=std what=%s", ex.what());
            return;
        } catch (...) {
            st_ptr->listener_done.store(true, std::memory_order_release);
            st_ptr->running.store(false, std::memory_order_release);
            st_ptr->proxy_alive.store(false, std::memory_order_release);
            st_ptr->work_cv.notify_all();
            st_ptr->proxy_start_cv.notify_all();
            diag::log_tagged("mitm", "listener_thread_exception type=unknown");
            return;
        }
        st_ptr->listener_done.store(true, std::memory_order_release);
    };
    const auto listener_submission = aida::infra::executor::submit(std::move(listener_sub));
    const bool listener_posted = listener_submission.submitted;
    if (!listener_posted) {
        diag::log_tagged_fmt("mitm", "pre_initialize listener_post_failed reason=%s",
            listener_submission.reject_reason.empty() ? "unknown" : listener_submission.reject_reason.c_str());
        st.listener_done.store(true, std::memory_order_release);
    } else {
        diag::log_tagged("mitm", "pre_initialize listener_posted");
    }

    for (uint32_t i = 0; i < WORKER_POOL_SIZE; ++i) {
        st.active_worker_count.fetch_add(1, std::memory_order_acq_rel);
        aida::infra::executor::submission_t worker_sub;
        worker_sub.owner_subsystem = "network.mitm";
        worker_sub.label = "mitm.worker";
        worker_sub.thread_class = "service_loop";
        worker_sub.domain = aida::infra::executor::domain_t::service;
        worker_sub.priority = 4;
        worker_sub.body = [st_ptr]() {
            try {
                worker_thread_func(*st_ptr);
            } catch (const std::exception& ex) {
                const auto previous = st_ptr->active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
                if (previous == 1) {
                    st_ptr->running.store(false, std::memory_order_release);
                    st_ptr->proxy_alive.store(false, std::memory_order_release);
                    st_ptr->proxy_start_cv.notify_all();
                }
                diag::log_tagged_fmt("mitm", "worker_thread_exception type=std what=%s", ex.what());
                return;
            } catch (...) {
                const auto previous = st_ptr->active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
                if (previous == 1) {
                    st_ptr->running.store(false, std::memory_order_release);
                    st_ptr->proxy_alive.store(false, std::memory_order_release);
                    st_ptr->proxy_start_cv.notify_all();
                }
                diag::log_tagged("mitm", "worker_thread_exception type=unknown");
                return;
            }
            st_ptr->active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
        };
        const auto worker_submission = aida::infra::executor::submit(std::move(worker_sub));
        const bool worker_posted = worker_submission.submitted;
        if (!worker_posted) {
            diag::log_tagged_fmt("mitm", "pre_initialize worker_post_failed i=%u reason=%s", i,
                worker_submission.reject_reason.empty() ? "unknown" : worker_submission.reject_reason.c_str());
            st.active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
        } else {
            diag::log_tagged_fmt("mitm", "pre_initialize worker_posted i=%u", i);
        }
    }
    const auto submitted_worker_count = st.active_worker_count.load(std::memory_order_acquire);
    if (!listener_posted || submitted_worker_count == 0) {
        st.proxy_alive.store(false, std::memory_order_release);
        st.proxy_start_cv.notify_all();
        diag::log_tagged_fmt("mitm", "pre_initialize not_alive listener_posted=%d workers=%u",
            listener_posted ? 1 : 0, submitted_worker_count);
    }
    diag::log_tagged_fmt("mitm", "pre_initialize complete worker_count=%d", (int)submitted_worker_count);
}

void shutdown() {
    const uint64_t started = GetTickCount64();
    size_t pending_count = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.work_mutex);
        pending_count = g_state.pending_work.size();
    }
    diag::log_tagged_fmt("mitm",
        "shutdown entry running=%d proxy_alive=%d active_workers=%u active_connections=%u pending=%zu listener_done=%d",
        g_state.running.load(std::memory_order_acquire) ? 1 : 0,
        g_state.proxy_alive.load(std::memory_order_acquire) ? 1 : 0,
        g_state.active_worker_count.load(std::memory_order_acquire),
        g_state.active_connections.load(std::memory_order_acquire), pending_count,
        g_state.listener_done.load(std::memory_order_acquire) ? 1 : 0);
    auto& st = g_state;
    stop();
    st.proxy_alive.store(false);
    size_t discarded = 0;
    {
        std::lock_guard<std::mutex> lock(st.work_mutex);
        while (!st.pending_work.empty()) {
            close_socket(static_cast<SOCKET>(st.pending_work.front().client_socket));
            st.pending_work.pop();
            ++discarded;
        }
    }
    st.work_cv.notify_all();
    st.proxy_start_cv.notify_all();
    diag::log_tagged("mitm", "shutdown draining_workers");
    const uint64_t worker_deadline = GetTickCount64() + 10000;
    while (st.active_worker_count.load(std::memory_order_acquire) > 0 && GetTickCount64() < worker_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (st.active_worker_count.load(std::memory_order_acquire) > 0)
        diag::log_tagged_fmt("mitm", "shutdown workers_not_drained active_workers=%u",
            st.active_worker_count.load(std::memory_order_acquire));
    diag::log_tagged("mitm", "shutdown draining_listener");
    const uint64_t listener_deadline = GetTickCount64() + 10000;
    while (!st.listener_done.load(std::memory_order_acquire) && GetTickCount64() < listener_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (!st.listener_done.load(std::memory_order_acquire))
        diag::log_tagged("mitm", "shutdown listener_not_drained");
    diag::log_tagged_fmt("mitm",
        "shutdown complete elapsed_ms=%llu active_workers=%u active_connections=%u discarded=%zu listener_done=%d",
        static_cast<unsigned long long>(GetTickCount64() - started),
        st.active_worker_count.load(std::memory_order_acquire),
        st.active_connections.load(std::memory_order_acquire), discarded,
        st.listener_done.load(std::memory_order_acquire) ? 1 : 0);
}

std::vector<http_exchange> get_history(size_t max_count) {
    diag::log_tagged_fmt("mitm", "get_history entry max_count=%zu", max_count);
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    std::vector<http_exchange> result;
    size_t count = g_state.history.size();
    size_t take = (max_count == 0 || max_count >= count) ? count : max_count;
    result.reserve(take);
    size_t skip = count - take;
    size_t i = 0;
    for (const auto& ex_ptr : g_state.history) {
        if (i++ < skip) continue;
        if (ex_ptr) result.push_back(*ex_ptr);
    }
    diag::log_tagged_fmt("mitm", "get_history result=%zu total_history=%zu", result.size(), count);
    return result;
}

std::vector<http_exchange> get_history_by_ids(const std::vector<uint64_t>& ids) {
    std::vector<http_exchange> result;
    if (ids.empty())
        return result;
    std::unordered_set<uint64_t> wanted(ids.begin(), ids.end());
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    result.reserve(std::min(wanted.size(), g_state.history.size()));
    for (const auto& ex_ptr : g_state.history) {
        if (ex_ptr && wanted.find(ex_ptr->id) != wanted.end())
            result.push_back(*ex_ptr);
    }
    std::sort(result.begin(), result.end(), [&ids](const http_exchange& a, const http_exchange& b) {
        auto ia = std::find(ids.begin(), ids.end(), a.id);
        auto ib = std::find(ids.begin(), ids.end(), b.id);
        return ia < ib;
    });
    return result;
}

const http_exchange* find_exchange(uint64_t id) {
    diag::log_tagged_fmt("mitm", "find_exchange entry id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (const auto& ex_ptr : g_state.history) {
        if (ex_ptr && ex_ptr->id == id) {
            diag::log_tagged_fmt("mitm", "find_exchange found id=%llu method=%s uri=%s", static_cast<unsigned long long>(id), ex_ptr->request.method.c_str(), ex_ptr->request.uri.c_str());
            return ex_ptr.get();
        }
    }
    diag::log_tagged_fmt("mitm", "find_exchange not_found id=%llu", static_cast<unsigned long long>(id));
    return nullptr;
}

void clear_history() {
    diag::log_tagged("mitm", "clear_history entry");
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    size_t was = g_state.history.size();
    g_state.history.clear();
    g_state.next_id.store(1);
    diag::log_tagged_fmt("mitm", "clear_history complete cleared=%zu", was);
}

bool clear_history_if_exact(const std::vector<uint64_t>& reviewed_ids) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (g_state.history.size() != reviewed_ids.size())
        return false;
    std::size_t index = 0;
    for (const auto& exchange : g_state.history) {
        if (!exchange || exchange->id != reviewed_ids[index++])
            return false;
    }
    const std::size_t cleared = g_state.history.size();
    g_state.history.clear();
    g_state.next_id.store(1, std::memory_order_release);
    diag::log_tagged_fmt("mitm", "clear_history_exact complete cleared=%zu", cleared);
    return true;
}

size_t history_count() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    return g_state.history.size();
}

bool append_history(const std::vector<http_exchange>& exchanges, bool preserve_ids) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto exchange : exchanges) {
        if (!preserve_ids || exchange.id == 0)
            exchange.id = g_state.next_id.fetch_add(1);
        else {
            uint64_t next = g_state.next_id.load(std::memory_order_acquire);
            while (next <= exchange.id && !g_state.next_id.compare_exchange_weak(next, exchange.id + 1, std::memory_order_acq_rel)) {
            }
        }
        if (exchange.timestamp == 0)
            exchange.timestamp = exchange.request_time == 0 ? GetTickCount64() : exchange.request_time;
        g_state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
        while (g_state.history.size() > g_state.config.max_history)
            g_state.history.pop_front();
    }
    return true;
}

bool set_exchange_tags(uint64_t id, const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& ex_ptr : g_state.history) {
        if (!ex_ptr || ex_ptr->id != id)
            continue;
        ex_ptr->tags.clear();
        for (const auto& tag : tags) {
            if (!tag.empty() && std::find(ex_ptr->tags.begin(), ex_ptr->tags.end(), tag) == ex_ptr->tags.end())
                ex_ptr->tags.push_back(tag);
        }
        return true;
    }
    return false;
}

bool add_exchange_tag(uint64_t id, const std::string& tag) {
    if (tag.empty())
        return false;
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& ex_ptr : g_state.history) {
        if (!ex_ptr || ex_ptr->id != id)
            continue;
        if (std::find(ex_ptr->tags.begin(), ex_ptr->tags.end(), tag) == ex_ptr->tags.end())
            ex_ptr->tags.push_back(tag);
        return true;
    }
    return false;
}

bool remove_exchange_tag(uint64_t id, const std::string& tag) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& ex_ptr : g_state.history) {
        if (!ex_ptr || ex_ptr->id != id)
            continue;
        auto it = std::remove(ex_ptr->tags.begin(), ex_ptr->tags.end(), tag);
        if (it != ex_ptr->tags.end()) {
            ex_ptr->tags.erase(it, ex_ptr->tags.end());
            return true;
        }
        return false;
    }
    return false;
}

bool set_exchange_notes(uint64_t id, const std::string& notes) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& ex_ptr : g_state.history) {
        if (!ex_ptr || ex_ptr->id != id)
            continue;
        ex_ptr->notes = notes;
        return true;
    }
    return false;
}

std::vector<tls_observation_t> get_tls_observations(size_t max_count) {
    std::lock_guard<std::mutex> lock(g_state.tls_observation_mutex);
    std::vector<tls_observation_t> result;
    size_t count = g_state.tls_observations.size();
    size_t take = (max_count == 0 || max_count >= count) ? count : max_count;
    result.reserve(take);
    size_t skip = count - take;
    size_t i = 0;
    for (const auto& obs : g_state.tls_observations) {
        if (i++ < skip) continue;
        result.push_back(obs);
    }
    return result;
}

void clear_tls_observations() {
    std::lock_guard<std::mutex> lock(g_state.tls_observation_mutex);
    g_state.tls_observations.clear();
}

void set_intercept_enabled(bool enabled) {
    g_state.config.intercept_enabled = enabled;
}

bool is_intercept_enabled() {
    return g_state.config.intercept_enabled;
}

void set_intercept_callback(intercept_callback_t cb) {
    g_state.intercept_cb = std::move(cb);
}

void set_ws_frame_callback(ws_frame_callback_t cb) {
    std::lock_guard<std::mutex> lock(g_state.ws_observer_mutex);
    g_state.ws_observer_cb = std::move(cb);
    diag::log_tagged_fmt("network", "[net_audit] proxy ws_frame_callback set has_cb=%d",
        g_state.ws_observer_cb ? 1 : 0);
}

void publish_ws_frame(const ws_frame_observed_t& frame) {
    ws_frame_callback_t cb_copy;
    {
        std::lock_guard<std::mutex> lock(g_state.ws_observer_mutex);
        cb_copy = g_state.ws_observer_cb;
    }
    if (cb_copy) {
        cb_copy(frame);
    }
}

static std::shared_ptr<held_wait_t> lookup_wait_locked(uint64_t id) {
    auto it = g_state.held_waits.find(id);
    if (it == g_state.held_waits.end()) return nullptr;
    return it->second;
}

void forward_exchange(uint64_t id) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) {
        diag::log_tagged_fmt("network", "mitm_forward_exchange_no_wait id=%llu",
            static_cast<unsigned long long>(id));
        return;
    }
    bool delivered = false;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->decision = hold_decision_t::forward;
        wait->released = true;
        delivered = true;
    }
    if (delivered) {
        diag::log_tagged_fmt("network", "mitm_forward_exchange id=%llu",
            static_cast<unsigned long long>(id));
    }
    wait->cv.notify_all();
}

void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) {
        diag::log_tagged_fmt("network", "mitm_forward_modified_no_wait id=%llu",
            static_cast<unsigned long long>(id));
        return;
    }
    bool delivered = false;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->modified_request = modified_request;
        wait->decision = hold_decision_t::modified;
        wait->released = true;
        delivered = true;
    }
    if (delivered) {
        diag::log_tagged_fmt("network", "mitm_forward_modified id=%llu new_size=%zu",
            static_cast<unsigned long long>(id), modified_request.size());
    }
    wait->cv.notify_all();
}

void drop_exchange(uint64_t id) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) {
        diag::log_tagged_fmt("network", "mitm_drop_exchange_no_wait id=%llu",
            static_cast<unsigned long long>(id));
        return;
    }
    bool delivered = false;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->decision = hold_decision_t::drop;
        wait->released = true;
        delivered = true;
    }
    if (delivered) {
        diag::log_tagged_fmt("network", "mitm_drop_exchange id=%llu",
            static_cast<unsigned long long>(id));
    }
    wait->cv.notify_all();
}

void forward_all() {
    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    diag::log_tagged_fmt("mitm", "forward_all count=%zu", waits.size());
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (wait->released) continue;
            wait->decision = hold_decision_t::forward;
            wait->released = true;
        }
        wait->cv.notify_all();
    }
    diag::log_tagged_fmt("mitm", "forward_all complete count=%zu", waits.size());
}

void drop_all() {
    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    diag::log_tagged_fmt("mitm", "drop_all count=%zu", waits.size());
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (wait->released) continue;
            wait->decision = hold_decision_t::drop;
            wait->released = true;
        }
        wait->cv.notify_all();
    }
    diag::log_tagged_fmt("mitm", "drop_all complete count=%zu", waits.size());
}

std::vector<http_exchange> get_held_exchanges() {
    diag::log_tagged("mitm", "get_held_exchanges entry");
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    std::vector<http_exchange> result;
    result.reserve(g_state.held_exchanges.size());
    for (const auto* ex : g_state.held_exchanges) {
        if (ex) result.push_back(*ex);
    }
    diag::log_tagged_fmt("mitm", "get_held_exchanges result=%zu", result.size());
    return result;
}

repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls,
                             const std::vector<uint8_t>& raw_request) {
    diag::log_tagged_fmt("mitm", "repeat_request entry host=%s port=%u use_tls=%d req_size=%zu", host.c_str(), port, (int)use_tls, raw_request.size());
    repeat_result result;

    if (!s_wsa_guard.ok) {
        diag::log_tagged("mitm", "repeat_request wsa_not_ok");
        result.error = "WSAStartup failed";
        return result;
    }

    proxy_config replay_config = g_state.config;
    SOCKET sock = connect_to_target(host, port, replay_config, use_tls);
    if (sock == INVALID_SOCKET) {
        diag::log_tagged_fmt("mitm", "repeat_request connect_failed host=%s port=%u", host.c_str(), port);
        result.error = "Cannot connect to " + host + ":" + std::to_string(port);
        return result;
    }
    diag::log_tagged_fmt("mitm", "repeat_request connected host=%s port=%u use_tls=%d", host.c_str(), port, (int)use_tls);

    result.exchange.target_host = host;
    result.exchange.target_port = port;
    result.exchange.is_tls = use_tls;
    result.exchange.raw_request = raw_request;
    result.exchange.request_size = raw_request.size();
    result.exchange.request = protocol_parser::parse_http_request(raw_request.data(), raw_request.size());
    result.exchange.request_time = GetTickCount64();

    if (use_tls) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close_socket(sock);
            result.error = "SSL_CTX_new failed";
            return result;
        }

        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "SSL_new failed";
            return result;
        }
        SSL_set_fd(ssl, static_cast<int>(sock));
        const auto upstream_policy = tls_policy::match_host(host);
        if (!configure_client_tls(ctx, ssl, host, upstream_policy, nullptr, 0)) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS policy setup failed";
            return result;
        }

        if (!ssl_handshake_with_timeout(ssl, SSL_connect)) {
            diag::log_tagged_fmt("mitm", "repeat_request tls_handshake_failed host=%s port=%u", host.c_str(), port);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS handshake failed";
            return result;
        }
        if (SSL_get_verify_result(ssl) != X509_V_OK && !upstream_policy.policy.ignore_cert_errors) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS certificate verification failed";
            return result;
        }
        if (!verify_upstream_pin(ssl, upstream_policy)) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS certificate pin mismatch";
            return result;
        }
        diag::log_tagged_fmt("mitm", "repeat_request tls_handshake_ok host=%s port=%u", host.c_str(), port);

        SSL_write(ssl, raw_request.data(), static_cast<int>(raw_request.size()));

        std::vector<uint8_t> response_data;
        if (recv_ssl_all(ssl, response_data, replay_config.max_body_size)) {
            read_remaining_body_ssl(ssl, response_data, replay_config.max_body_size);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
            diag::log_tagged_fmt("mitm", "repeat_request tls_response_ok host=%s status=%d size=%zu latency_ms=%llu", host.c_str(), result.exchange.response.status_code, response_data.size(), static_cast<unsigned long long>(result.exchange.latency_ms));
        } else {
            diag::log_tagged_fmt("mitm", "repeat_request tls_no_response host=%s port=%u", host.c_str(), port);
            result.error = "No response from server";
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        send(sock, reinterpret_cast<const char*>(raw_request.data()),
             static_cast<int>(raw_request.size()), 0);

        std::vector<uint8_t> response_data;
        if (recv_all(sock, response_data, replay_config.max_body_size)) {
            read_remaining_body(sock, response_data, replay_config.max_body_size);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
            diag::log_tagged_fmt("mitm", "repeat_request plain_response_ok host=%s status=%d size=%zu latency_ms=%llu", host.c_str(), result.exchange.response.status_code, response_data.size(), static_cast<unsigned long long>(result.exchange.latency_ms));
        } else {
            diag::log_tagged_fmt("mitm", "repeat_request plain_no_response host=%s port=%u", host.c_str(), port);
            result.error = "No response from server";
        }
    }

    close_socket(sock);
    if (result.success) {
        result.exchange.id = g_state.next_id.fetch_add(1);
        result.exchange.timestamp = result.exchange.request_time;
        result.exchange.client_addr = "repeater";
        {
            std::lock_guard<std::mutex> lock(g_state.history_mutex);
            g_state.history.push_back(std::make_shared<http_exchange>(result.exchange));
            while (g_state.history.size() > g_state.config.max_history) {
                g_state.history.pop_front();
            }
            diag::log_tagged_fmt("mitm", "repeat_request history_recorded id=%llu history_size=%zu status=%d req=%zu resp=%zu latency_ms=%llu",
                static_cast<unsigned long long>(result.exchange.id),
                g_state.history.size(),
                result.exchange.response.status_code,
                result.exchange.request_size,
                result.exchange.response_size,
                static_cast<unsigned long long>(result.exchange.latency_ms));
        }
        g_state.total_requests.fetch_add(1);
        g_state.total_bytes_in.fetch_add(static_cast<uint64_t>(result.exchange.request_size));
        g_state.total_bytes_out.fetch_add(static_cast<uint64_t>(result.exchange.response_size));
        publish_exchange_event(result.exchange);
    }
    diag::log_tagged_fmt("mitm", "repeat_request complete host=%s success=%d err=%s", host.c_str(), (int)result.success, result.error.c_str());
    return result;
}

proxy_stats get_stats() {
    diag::log_tagged("mitm", "get_stats entry");
    proxy_stats stats;
    stats.running = g_state.running.load();
    stats.total_requests = g_state.total_requests.load();
    stats.total_bytes_in = g_state.total_bytes_in.load();
    stats.total_bytes_out = g_state.total_bytes_out.load();
    stats.active_connections = g_state.active_connections.load();

    {
        std::lock_guard<std::mutex> lock(g_state.history_mutex);
        stats.history_size = g_state.history.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        stats.held_count = g_state.held_exchanges.size();
    }
    diag::log_tagged_fmt("mitm", "get_stats running=%d requests=%llu bytes_in=%llu bytes_out=%llu active=%llu history=%zu held=%zu",
        (int)stats.running,
        static_cast<unsigned long long>(stats.total_requests),
        static_cast<unsigned long long>(stats.total_bytes_in),
        static_cast<unsigned long long>(stats.total_bytes_out),
        static_cast<unsigned long long>(stats.active_connections),
        stats.history_size, stats.held_count);
    return stats;
}

}
