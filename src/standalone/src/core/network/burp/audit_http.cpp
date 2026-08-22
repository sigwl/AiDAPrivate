#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef small
#undef small
#endif

#include "audit_http.hpp"
#include "scope.hpp"
#include "active_scanner.hpp"

#include "../../infra/event_bus.hpp"
#include "../../runtime/standalone_driver.hpp"
#include "../../../helpers/diag_log.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace aida {
namespace burp {
namespace audit_http {

namespace {

std::mutex& err_mtx() { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }
std::atomic<uint64_t>& exchange_ids() { static std::atomic<uint64_t> ids{1000000000ULL}; return ids; }
std::atomic<uint64_t>& wsaenobufs_diag_ids() { static std::atomic<uint64_t> ids{0ULL}; return ids; }

struct circuit_snapshot_t
{
    bool available = false;
    bool open = false;
    uint64_t audit_id = 0;
    size_t hits = 0;
    size_t threshold = 0;
    size_t transport_failures = 0;
    std::string source;
    std::string state;
};

circuit_snapshot_t current_circuit_snapshot(const send_options_t& options,
                                            const std::string& host,
                                            uint16_t port,
                                            bool tls)
{
    circuit_snapshot_t out;
    out.source = options.exchange_source.empty() ? "api" : options.exchange_source;
    if (out.source != "scanner") {
        out.state = "not_scanner_source";
        return out;
    }

    auto audits = active_scanner::list_audits();
    for (const auto& audit : audits) {
        if (!audit.running)
            continue;
        if (audit.host != host || audit.port != port || audit.tls != tls)
            continue;
        out.available = true;
        out.open = audit.transport_circuit_breaker_open;
        out.audit_id = audit.id;
        out.hits = audit.transport_circuit_breaker_hits;
        out.threshold = audit.transport_circuit_breaker_threshold;
        out.transport_failures = audit.transport_failures;
        out.state = out.open ? "open" : "closed";
        return out;
    }
    out.state = "scanner_audit_not_matched";
    return out;
}

void set_err(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t now_steady_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

std::string lower_ascii(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool is_loopback_host(const std::string& host)
{
    std::string h = lower_ascii(host);
    if (h == "localhost" || h == "::1" || h == "[::1]") return true;
    return h.rfind("127.", 0) == 0;
}

const char* wsa_error_name(int err)
{
    switch (err) {
    case 0: return "WSA_OK";
    case WSAEINTR: return "WSAEINTR";
    case WSAEBADF: return "WSAEBADF";
    case WSAEACCES: return "WSAEACCES";
    case WSAEFAULT: return "WSAEFAULT";
    case WSAEINVAL: return "WSAEINVAL";
    case WSAEMFILE: return "WSAEMFILE";
    case WSAEWOULDBLOCK: return "WSAEWOULDBLOCK";
    case WSAEINPROGRESS: return "WSAEINPROGRESS";
    case WSAEALREADY: return "WSAEALREADY";
    case WSAENOTSOCK: return "WSAENOTSOCK";
    case WSAEDESTADDRREQ: return "WSAEDESTADDRREQ";
    case WSAEMSGSIZE: return "WSAEMSGSIZE";
    case WSAEPROTOTYPE: return "WSAEPROTOTYPE";
    case WSAENOPROTOOPT: return "WSAENOPROTOOPT";
    case WSAEPROTONOSUPPORT: return "WSAEPROTONOSUPPORT";
    case WSAESOCKTNOSUPPORT: return "WSAESOCKTNOSUPPORT";
    case WSAEOPNOTSUPP: return "WSAEOPNOTSUPP";
    case WSAEPFNOSUPPORT: return "WSAEPFNOSUPPORT";
    case WSAEAFNOSUPPORT: return "WSAEAFNOSUPPORT";
    case WSAEADDRINUSE: return "WSAEADDRINUSE";
    case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
    case WSAENETDOWN: return "WSAENETDOWN";
    case WSAENETUNREACH: return "WSAENETUNREACH";
    case WSAENETRESET: return "WSAENETRESET";
    case WSAECONNABORTED: return "WSAECONNABORTED";
    case WSAECONNRESET: return "WSAECONNRESET";
    case WSAENOBUFS: return "WSAENOBUFS";
    case WSAEISCONN: return "WSAEISCONN";
    case WSAENOTCONN: return "WSAENOTCONN";
    case WSAESHUTDOWN: return "WSAESHUTDOWN";
    case WSAETIMEDOUT: return "WSAETIMEDOUT";
    case WSAECONNREFUSED: return "WSAECONNREFUSED";
    case WSAEHOSTDOWN: return "WSAEHOSTDOWN";
    case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
    case WSAHOST_NOT_FOUND: return "WSAHOST_NOT_FOUND";
    case WSATRY_AGAIN: return "WSATRY_AGAIN";
    case WSANO_RECOVERY: return "WSANO_RECOVERY";
    case WSANO_DATA: return "WSANO_DATA";
    default: return "WSA_UNKNOWN";
    }
}

const char* socket_family_name(int family)
{
    switch (family) {
    case AF_INET: return "AF_INET";
    case AF_INET6: return "AF_INET6";
    default: return "AF_UNKNOWN";
    }
}

std::string sockaddr_address_string(const sockaddr_storage& sa)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa.ss_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(&sa);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&sin->sin_addr), buf, sizeof(buf)))
            return buf;
    } else if (sa.ss_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&sa);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&sin6->sin6_addr), buf, sizeof(buf)))
            return buf;
    }
    return {};
}

DWORD current_process_handle_count(bool& ok)
{
    DWORD count = 0;
    ok = GetProcessHandleCount(GetCurrentProcess(), &count) != FALSE;
    return count;
}

struct wsa_init_t
{
    bool ok = false;
    wsa_init_t() {
        WSADATA d{};
        ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
    }
};

void ensure_wsa()
{
    static wsa_init_t s_init;
    (void)s_init;
}

struct openssl_init_t
{
    openssl_init_t() {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }
};

void ensure_openssl()
{
    static openssl_init_t s_init;
    (void)s_init;
}

struct socket_holder_t
{
    SOCKET sock = INVALID_SOCKET;
    ~socket_holder_t() {
        if (sock != INVALID_SOCKET) {
            shutdown(sock, SD_BOTH);
            closesocket(sock);
        }
    }
};

struct ssl_holder_t
{
    SSL_CTX* ctx = nullptr;
    SSL*     ssl = nullptr;
    ~ssl_holder_t() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx) SSL_CTX_free(ctx);
    }
};

bool resolve_target(const std::string& host, uint16_t port, sockaddr_storage& out, int& out_len)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", port);

    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) return false;
    std::memcpy(&out, res->ai_addr, res->ai_addrlen);
    out_len = static_cast<int>(res->ai_addrlen);
    freeaddrinfo(res);
    return true;
}

bool set_nonblocking(SOCKET s, bool nb)
{
    u_long mode = nb ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
}

bool wait_socket(SOCKET s, int timeout_ms, bool for_write)
{
    if (timeout_ms <= 0) return false;
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = static_cast<short>(for_write ? POLLOUT : POLLIN);
    int rc = WSAPoll(&pfd, 1, timeout_ms);
    if (rc <= 0 || (pfd.revents & POLLNVAL) != 0) return false;
    const short wanted = static_cast<short>(for_write ? POLLOUT : (POLLIN | POLLRDNORM));
    return (pfd.revents & wanted) != 0 && (pfd.revents & POLLERR) == 0;
}

bool tcp_connect(SOCKET s, const sockaddr* sa, int sa_len, int timeout_ms, int& connect_err, int& poll_rc, short& revents, int& poll_wsa, std::string& connect_stage, bool& before_would_block)
{
    connect_err = 0;
    poll_rc = 0;
    revents = 0;
    poll_wsa = 0;
    connect_stage = "set_nonblocking";
    before_would_block = true;
    if (!set_nonblocking(s, true)) {
        connect_err = WSAGetLastError();
        return false;
    }
    connect_stage = "connect";
    int rc = connect(s, sa, sa_len);
    if (rc == 0) {
        connect_stage = "connect_immediate_success";
        before_would_block = false;
        return true;
    }
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        connect_stage = "connect_immediate_failure";
        connect_err = err;
        return false;
    }
    connect_stage = "poll_wait";
    before_would_block = false;
    if (timeout_ms <= 0) {
        connect_stage = "pre_poll_timeout";
        connect_err = WSAETIMEDOUT;
        return false;
    }
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLOUT;
    poll_rc = WSAPoll(&pfd, 1, timeout_ms);
    revents = pfd.revents;
    if (poll_rc <= 0 || (pfd.revents & POLLNVAL) != 0) {
        poll_wsa = poll_rc < 0 ? WSAGetLastError() : 0;
        connect_err = poll_rc == 0 ? WSAETIMEDOUT : poll_wsa;
        connect_stage = poll_rc == 0 ? "poll_timeout" : ((pfd.revents & POLLNVAL) != 0 ? "poll_invalid" : "poll_failed");
        return false;
    }
    int so_err = 0;
    int len = sizeof(so_err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len) != 0) {
        connect_stage = "getsockopt_so_error_failed";
        connect_err = WSAGetLastError();
        return false;
    }
    connect_err = so_err;
    connect_stage = so_err == 0 ? "connected" : "so_error";
    return so_err == 0;
}

bool tcp_connect_loopback(SOCKET s, const sockaddr* sa, int sa_len, int& connect_err, std::string& connect_stage, bool& before_would_block)
{
    connect_err = 0;
    connect_stage = "blocking_connect";
    before_would_block = true;
    set_nonblocking(s, false);
    int rc = connect(s, sa, sa_len);
    if (rc == 0) {
        set_nonblocking(s, true);
        connect_stage = "blocking_connect_success";
        before_would_block = false;
        return true;
    }
    connect_err = WSAGetLastError();
    set_nonblocking(s, true);
    connect_stage = "blocking_connect_failure";
    return false;
}

bool send_all(SOCKET s, const uint8_t* data, size_t len, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) return false;
        int n = ::send(s, reinterpret_cast<const char*>(data + off), static_cast<int>(len - off), 0);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                if (now_steady_ms() >= deadline) return false;
                continue;
            }
            return false;
        }
        off += static_cast<size_t>(n);
        if (now_steady_ms() >= deadline) return false;
    }
    return true;
}

bool ssl_send_all(SSL* ssl, const uint8_t* data, size_t len, SOCKET s, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, data + off, static_cast<int>(len - off));
        if (n > 0) { off += static_cast<size_t>(n); continue; }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), false)) return false;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) return false;
        } else {
            return false;
        }
        if (now_steady_ms() >= deadline) return false;
    }
    return true;
}

bool recv_until_complete(SOCKET s, std::vector<uint8_t>& buf, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    constexpr size_t kChunk = 16 * 1024;
    constexpr size_t kMaxResp = 32 * 1024 * 1024;
    char tmp[kChunk];
    bool headers_done = false;
    size_t header_end = 0;
    long long content_length = -1;
    bool chunked = false;
    while (buf.size() < kMaxResp) {
        if (now_steady_ms() >= deadline) break;
        int wait = static_cast<int>(deadline - now_steady_ms());
        if (!wait_socket(s, wait, false)) break;
        int n = recv(s, tmp, sizeof(tmp), 0);
        if (n == 0) break;
        if (n < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            break;
        }
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(tmp), reinterpret_cast<uint8_t*>(tmp) + n);
        if (!headers_done) {
            const std::string sep = "\r\n\r\n";
            for (size_t i = 0; i + sep.size() <= buf.size(); ++i) {
                if (std::memcmp(buf.data() + i, sep.data(), sep.size()) == 0) {
                    headers_done = true;
                    header_end = i + sep.size();
                    break;
                }
            }
            if (headers_done) {
                std::string headers_only(reinterpret_cast<const char*>(buf.data()), header_end);
                std::string lc = headers_only;
                std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                size_t cl = lc.find("\r\ncontent-length:");
                if (cl != std::string::npos) {
                    size_t vs = cl + 17;
                    while (vs < lc.size() && (lc[vs] == ' ' || lc[vs] == '\t')) ++vs;
                    size_t ve = vs;
                    while (ve < lc.size() && lc[ve] != '\r' && lc[ve] != '\n') ++ve;
                    try { content_length = std::stoll(headers_only.substr(vs, ve - vs)); } catch (...) { content_length = -1; }
                }
                size_t te = lc.find("\r\ntransfer-encoding:");
                if (te != std::string::npos) {
                    size_t vs = te + 20;
                    size_t ve = lc.find("\r\n", vs);
                    std::string tev = lc.substr(vs, ve - vs);
                    if (tev.find("chunked") != std::string::npos) chunked = true;
                }
            }
        }
        if (headers_done) {
            if (content_length >= 0) {
                size_t total_expected = header_end + static_cast<size_t>(content_length);
                if (buf.size() >= total_expected) break;
            } else if (chunked) {
                if (buf.size() >= 5 && std::memcmp(buf.data() + buf.size() - 5, "0\r\n\r\n", 5) == 0) break;
            }
        }
    }
    return !buf.empty();
}

bool ssl_recv_until_complete(SSL* ssl, SOCKET s, std::vector<uint8_t>& buf, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    constexpr size_t kChunk = 16 * 1024;
    constexpr size_t kMaxResp = 32 * 1024 * 1024;
    char tmp[kChunk];
    bool headers_done = false;
    size_t header_end = 0;
    long long content_length = -1;
    bool chunked = false;
    while (buf.size() < kMaxResp) {
        if (now_steady_ms() >= deadline) break;
        int n = SSL_read(ssl, tmp, static_cast<int>(sizeof(tmp)));
        if (n > 0) {
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(tmp), reinterpret_cast<uint8_t*>(tmp) + n);
            if (!headers_done) {
                const std::string sep = "\r\n\r\n";
                for (size_t i = 0; i + sep.size() <= buf.size(); ++i) {
                    if (std::memcmp(buf.data() + i, sep.data(), sep.size()) == 0) {
                        headers_done = true;
                        header_end = i + sep.size();
                        break;
                    }
                }
                if (headers_done) {
                    std::string headers_only(reinterpret_cast<const char*>(buf.data()), header_end);
                    std::string lc = headers_only;
                    std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    size_t cl = lc.find("\r\ncontent-length:");
                    if (cl != std::string::npos) {
                        size_t vs = cl + 17;
                        while (vs < lc.size() && (lc[vs] == ' ' || lc[vs] == '\t')) ++vs;
                        size_t ve = vs;
                        while (ve < lc.size() && lc[ve] != '\r' && lc[ve] != '\n') ++ve;
                        try { content_length = std::stoll(headers_only.substr(vs, ve - vs)); } catch (...) { content_length = -1; }
                    }
                    size_t te = lc.find("\r\ntransfer-encoding:");
                    if (te != std::string::npos) {
                        size_t vs = te + 20;
                        size_t ve = lc.find("\r\n", vs);
                        std::string tev = lc.substr(vs, ve - vs);
                        if (tev.find("chunked") != std::string::npos) chunked = true;
                    }
                }
            }
            if (headers_done) {
                if (content_length >= 0) {
                    size_t total_expected = header_end + static_cast<size_t>(content_length);
                    if (buf.size() >= total_expected) break;
                } else if (chunked) {
                    if (buf.size() >= 5 && std::memcmp(buf.data() + buf.size() - 5, "0\r\n\r\n", 5) == 0) break;
                }
            }
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) break;
        if (err == SSL_ERROR_WANT_READ) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), false)) break;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) break;
        } else {
            break;
        }
    }
    return !buf.empty();
}

void parse_response_status(const std::string& raw, int& status_code, std::string& reason)
{
    auto eol = raw.find("\r\n");
    if (eol == std::string::npos) return;
    std::string line = raw.substr(0, eol);
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return;
    auto sp2 = line.find(' ', sp1 + 1);
    std::string code_str = (sp2 == std::string::npos) ? line.substr(sp1 + 1) : line.substr(sp1 + 1, sp2 - sp1 - 1);
    try { status_code = std::stoi(code_str); } catch (...) { status_code = 0; }
    if (sp2 != std::string::npos) reason = line.substr(sp2 + 1);
}

void parse_response_headers(const std::string& raw,
                            std::vector<std::pair<std::string, std::string>>& out_headers,
                            size_t& body_offset)
{
    auto sep = raw.find("\r\n\r\n");
    if (sep == std::string::npos) { body_offset = raw.size(); return; }
    body_offset = sep + 4;
    size_t p = raw.find("\r\n");
    if (p == std::string::npos) return;
    p += 2;
    while (p < sep) {
        size_t eol = raw.find("\r\n", p);
        if (eol == std::string::npos || eol > sep) break;
        size_t colon = raw.find(':', p);
        if (colon == std::string::npos || colon > eol) { p = eol + 2; continue; }
        std::string name = raw.substr(p, colon - p);
        size_t vs = colon + 1;
        while (vs < eol && (raw[vs] == ' ' || raw[vs] == '\t')) ++vs;
        std::string value = raw.substr(vs, eol - vs);
        out_headers.emplace_back(std::move(name), std::move(value));
        p = eol + 2;
    }
}

std::vector<uint8_t> decode_chunked_body(const std::vector<uint8_t>& src, size_t body_offset)
{
    std::vector<uint8_t> out;
    size_t p = body_offset;
    while (p < src.size()) {
        size_t eol = p;
        while (eol + 1 < src.size() && !(src[eol] == '\r' && src[eol + 1] == '\n')) ++eol;
        if (eol + 1 >= src.size()) break;
        std::string len_line(reinterpret_cast<const char*>(src.data() + p), eol - p);
        size_t semi = len_line.find(';');
        if (semi != std::string::npos) len_line = len_line.substr(0, semi);
        size_t len = 0;
        try { len = std::stoul(len_line, nullptr, 16); } catch (...) { break; }
        p = eol + 2;
        if (len == 0) break;
        if (p + len > src.size()) break;
        out.insert(out.end(), src.begin() + static_cast<std::ptrdiff_t>(p),
                              src.begin() + static_cast<std::ptrdiff_t>(p + len));
        p += len + 2;
    }
    return out;
}

void normalize_host_header(std::vector<uint8_t>& raw_request, const std::string& host, uint16_t port, bool tls)
{
    std::string s(reinterpret_cast<const char*>(raw_request.data()), raw_request.size());
    auto eol = s.find("\r\n");
    if (eol == std::string::npos) return;
    std::string lc = s;
    std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    size_t pos = lc.find("\r\nhost:", eol);
    std::string normalized = host;
    if ((tls && port != 443) || (!tls && port != 80)) {
        normalized += ":";
        normalized += std::to_string(port);
    }
    if (pos != std::string::npos) {
        size_t vs = pos + 7;
        while (vs < s.size() && (s[vs] == ' ' || s[vs] == '\t')) ++vs;
        size_t ve = s.find("\r\n", vs);
        if (ve == std::string::npos) return;
        s = s.substr(0, vs) + normalized + s.substr(ve);
    } else {
        s = s.substr(0, eol + 2) + "Host: " + normalized + "\r\n" + s.substr(eol + 2);
    }
    raw_request.assign(s.begin(), s.end());
}

}

bool parse_url(const std::string& url,
               std::string& scheme,
               std::string& host,
               uint16_t& port,
               std::string& path)
{
    diag::log_tagged_fmt("audit_http", "parse_url url=%s", url.c_str());
    if (std::any_of(url.begin(), url.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; }))
        return false;
    auto sep = url.find("://");
    if (sep == std::string::npos) {
        scheme = "http";
        host.clear();
        port = 80;
        path = "/";
    } else {
        scheme = url.substr(0, sep);
        std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }
    size_t start = (sep == std::string::npos) ? 0 : sep + 3;
    size_t slash = url.find('/', start);
    std::string authority = (slash == std::string::npos) ? url.substr(start) : url.substr(start, slash - start);
    path = (slash == std::string::npos) ? "/" : url.substr(slash);
    auto colon = authority.find(':');
    if (colon == std::string::npos) {
        host = authority;
        port = (scheme == "https") ? 443 : 80;
    } else {
        host = authority.substr(0, colon);
        try {
            const std::string port_text = authority.substr(colon + 1);
            size_t consumed = 0;
            const unsigned long parsed = std::stoul(port_text, &consumed, 10);
            if (consumed != port_text.size() || parsed == 0 || parsed > 65535)
                return false;
            port = static_cast<uint16_t>(parsed);
        }
        catch (...) {
            diag::log_tagged_fmt("audit_http", "parse_url invalid_port authority=%s", authority.c_str());
            return false;
        }
    }
    if (host.empty()) {
        diag::log_tagged("audit_http", "parse_url empty_host");
        return false;
    }
    diag::log_tagged_fmt("audit_http", "parse_url ok scheme=%s host=%s port=%u path=%s",
        scheme.c_str(), host.c_str(), static_cast<unsigned>(port), path.c_str());
    return true;
}

std::optional<exchange_observed_t> send(const std::vector<uint8_t>& raw_request,
                                        const std::string& host,
                                        uint16_t port,
                                        bool tls,
                                        const send_options_t& options)
{
    diag::log_tagged_fmt("audit_http", "send host=%s port=%u tls=%d req_len=%zu scope_only=%d timeout_ms=%d",
        host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, raw_request.size(),
        options.enforce_scope ? 1 : 0, options.timeout_ms);
    if (raw_request.empty() || host.empty()) {
        diag::log_tagged("audit_http", "send rejected empty_request_or_host");
        set_err("audit_http.send: empty request or host");
        return std::nullopt;
    }
    if (options.enforce_scope) {
        std::string check_url;
        check_url += tls ? "https://" : "http://";
        check_url += host;
        if ((tls && port != 443) || (!tls && port != 80)) {
            check_url += ":"; check_url += std::to_string(port);
        }
        check_url += "/";
        if (!scope::in_scope(check_url)) {
            diag::log_tagged_fmt("audit_http", "send out_of_scope url=%s", check_url.c_str());
            set_err("audit_http.send: target out of scope");
            return std::nullopt;
        }
    }

    ensure_wsa();
    ensure_openssl();

    std::vector<uint8_t> req = raw_request;
    normalize_host_header(req, host, port, tls);

    sockaddr_storage sa{};
    int sa_len = 0;
    if (!resolve_target(host, port, sa, sa_len)) {
        diag::log_tagged_fmt("audit_http", "send dns_failed host=%s", host.c_str());
        set_err("audit_http.send: DNS resolution failed");
        return std::nullopt;
    }
    const std::string resolved_ip = sockaddr_address_string(sa);
    const char* resolved_family = socket_family_name(sa.ss_family);
    bool handle_count_before_ok = false;
    const DWORD handle_count_before = current_process_handle_count(handle_count_before_ok);
    diag::log_tagged_fmt("audit_http", "send dns_ok host=%s port=%u family=%s ip=%s handle_count_ok=%d handle_count=%lu",
        host.c_str(), static_cast<unsigned>(port), resolved_family, resolved_ip.c_str(),
        handle_count_before_ok ? 1 : 0, static_cast<unsigned long>(handle_count_before));

    uint64_t t_req_start = now_ms();
    uint64_t t_steady_start = now_steady_ms();

    socket_holder_t sh;
    const bool loopback = is_loopback_host(host);
    const int effective_timeout_ms = std::max(options.timeout_ms, 1);
    const int max_attempts = loopback ? 16 : 1;
    int last_connect_err = 0;
    int last_poll_rc = 0;
    short last_revents = 0;
    int last_poll_wsa = 0;
    SOCKET last_socket = INVALID_SOCKET;
    std::string last_connect_stage = "not_started";
    bool last_before_would_block = false;
    DWORD last_handle_count_after = 0;
    bool last_handle_count_after_ok = false;
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        const uint64_t now = now_steady_ms();
        const uint64_t elapsed = now > t_steady_start ? now - t_steady_start : 0;
        if (elapsed >= static_cast<uint64_t>(effective_timeout_ms)) break;
        const int remaining_ms = effective_timeout_ms - static_cast<int>(elapsed);
        const int attempt_timeout_ms = loopback ? std::min(remaining_ms, 250) : remaining_ms;
        SOCKET candidate = socket(sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
        last_socket = candidate;
        if (candidate == INVALID_SOCKET) {
            last_connect_err = WSAGetLastError();
            last_connect_stage = "socket_create";
            last_before_would_block = true;
            last_handle_count_after = current_process_handle_count(last_handle_count_after_ok);
            diag::log_tagged_fmt("audit_http", "send socket_create_failed host=%s port=%u attempt=%d err=%d err_name=%s pid=%lu tid=%lu family=%s ip=%s socket=%llu handle_before_ok=%d handle_before=%lu handle_after_ok=%d handle_after=%lu elapsed_ms=%llu",
                host.c_str(), static_cast<unsigned>(port), attempt, last_connect_err, wsa_error_name(last_connect_err),
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()),
                resolved_family, resolved_ip.c_str(), static_cast<unsigned long long>(candidate),
                handle_count_before_ok ? 1 : 0, static_cast<unsigned long>(handle_count_before),
                last_handle_count_after_ok ? 1 : 0, static_cast<unsigned long>(last_handle_count_after),
                static_cast<unsigned long long>(now_steady_ms() - t_steady_start));
            break;
        }
        BOOL nodelay = TRUE;
        setsockopt(candidate, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
        LINGER lin{}; lin.l_onoff = 1; lin.l_linger = 0;
        setsockopt(candidate, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lin), sizeof(lin));

        int connect_err = 0;
        int poll_rc = 0;
        short revents = 0;
        int poll_wsa = 0;
        std::string connect_stage;
        bool before_would_block = false;
        const bool connected = loopback
            ? tcp_connect_loopback(candidate, reinterpret_cast<sockaddr*>(&sa), sa_len, connect_err, connect_stage, before_would_block)
            : tcp_connect(candidate, reinterpret_cast<sockaddr*>(&sa), sa_len, attempt_timeout_ms, connect_err, poll_rc, revents, poll_wsa, connect_stage, before_would_block);
        if (connected) {
            sh.sock = candidate;
            diag::log_tagged_fmt("audit_http", "send tcp_connected host=%s port=%u tls=%d attempts=%d loopback=%d mode=%s",
                host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, attempt, loopback ? 1 : 0, loopback ? "blocking_loopback" : "poll");
            break;
        }

        last_connect_err = connect_err;
        last_poll_rc = poll_rc;
        last_revents = revents;
        last_poll_wsa = poll_wsa;
        last_connect_stage = connect_stage;
        last_before_would_block = before_would_block;
        ::shutdown(candidate, SD_BOTH);
        closesocket(candidate);
        last_handle_count_after = current_process_handle_count(last_handle_count_after_ok);
        diag::log_tagged_fmt("audit_http", "send tcp_connect_failed host=%s port=%u attempt=%d/%d timeout_ms=%d connect_err=%d err_name=%s poll_rc=%d revents=0x%04X poll_wsa=%d poll_wsa_name=%s pid=%lu tid=%lu family=%s ip=%s socket=%llu connect_stage=%s before_would_block=%d handle_before_ok=%d handle_before=%lu handle_after_ok=%d handle_after=%lu elapsed_ms=%llu",
            host.c_str(), static_cast<unsigned>(port), attempt, max_attempts, attempt_timeout_ms,
            connect_err, wsa_error_name(connect_err), poll_rc, static_cast<unsigned>(revents), poll_wsa,
            wsa_error_name(poll_wsa),
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()),
            resolved_family, resolved_ip.c_str(), static_cast<unsigned long long>(candidate),
            connect_stage.c_str(), before_would_block ? 1 : 0,
            handle_count_before_ok ? 1 : 0, static_cast<unsigned long>(handle_count_before),
            last_handle_count_after_ok ? 1 : 0, static_cast<unsigned long>(last_handle_count_after),
            static_cast<unsigned long long>(now_steady_ms() - t_steady_start));

        if (!loopback || attempt == max_attempts) break;
        const DWORD sleep_ms = static_cast<DWORD>(std::min(100, 10 * attempt));
        Sleep(sleep_ms);
    }

    if (sh.sock == INVALID_SOCKET) {
        if (!last_handle_count_after_ok)
            last_handle_count_after = current_process_handle_count(last_handle_count_after_ok);
        const bool enobufs_preinit = last_connect_err == WSAENOBUFS && last_before_would_block;
        uint64_t wsaenobufs_diag_id = 0;
        bool driver_loaded = false;
        bool driver_connected = false;
        uint32_t driver_attached_pid = 0;
        std::string driver_status;
        std::string driver_error;
        bool intercept_query_attempted = false;
        bool intercept_query_ok = false;
        size_t intercept_held_count = 0;
        std::string intercept_state = "not_queried";
        circuit_snapshot_t circuit_snapshot;
        const std::string caller_source = options.exchange_source.empty() ? "api" : options.exchange_source;
        if (enobufs_preinit) {
            wsaenobufs_diag_id = wsaenobufs_diag_ids().fetch_add(1, std::memory_order_acq_rel) + 1ULL;
            driver_loaded = driver_bridge::is_loaded();
            driver_connected = driver_bridge::using_kernel_driver();
            driver_attached_pid = driver_bridge::attached_pid();
            driver_status = driver_bridge::status();
            driver_error = driver_bridge::last_error();
            if (driver_connected) {
                intercept_query_attempted = true;
                auto held_packets = driver_bridge::get_held_packets();
                intercept_held_count = held_packets.size();
                intercept_query_ok = true;
                intercept_state = "held_query_ok";
            } else {
                intercept_state = "driver_not_connected";
            }
            circuit_snapshot = current_circuit_snapshot(options, host, port, tls);
            diag::log_tagged_fmt("audit_http",
                "send wsaenobufs_diagnostic id=%llu pid=%lu tid=%lu target=%s:%u tls=%d caller_source=%s connect_stage=%s socket=%llu socket_state=closed_after_failed_connect before_would_block=%d driver_loaded=%d driver_connected=%d driver_attached_pid=%u driver_status=%s driver_error=%s intercept_state=%s intercept_query_attempted=%d intercept_query_ok=%d intercept_held_count=%zu circuit_available=%d circuit_state=%s circuit_audit_id=%llu circuit_hits=%zu circuit_threshold=%zu circuit_failures=%zu handle_before_ok=%d handle_before=%lu handle_after_ok=%d handle_after=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(wsaenobufs_diag_id),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                host.c_str(),
                static_cast<unsigned>(port),
                tls ? 1 : 0,
                caller_source.c_str(),
                last_connect_stage.c_str(),
                static_cast<unsigned long long>(last_socket),
                last_before_would_block ? 1 : 0,
                driver_loaded ? 1 : 0,
                driver_connected ? 1 : 0,
                driver_attached_pid,
                driver_status.c_str(),
                driver_error.c_str(),
                intercept_state.c_str(),
                intercept_query_attempted ? 1 : 0,
                intercept_query_ok ? 1 : 0,
                intercept_held_count,
                circuit_snapshot.available ? 1 : 0,
                circuit_snapshot.state.c_str(),
                static_cast<unsigned long long>(circuit_snapshot.audit_id),
                circuit_snapshot.hits,
                circuit_snapshot.threshold,
                circuit_snapshot.transport_failures,
                handle_count_before_ok ? 1 : 0,
                static_cast<unsigned long>(handle_count_before),
                last_handle_count_after_ok ? 1 : 0,
                static_cast<unsigned long>(last_handle_count_after),
                static_cast<unsigned long long>(now_steady_ms() - t_steady_start));
        }
        diag::log_tagged_fmt("audit_http", "send tcp_connect_exhausted host=%s port=%u attempts=%d loopback=%d last_connect_err=%d err_name=%s last_poll_rc=%d last_revents=0x%04X last_poll_wsa=%d poll_wsa_name=%s pid=%lu tid=%lu family=%s ip=%s socket=%llu connect_stage=%s before_would_block=%d transport_error_class=%s handle_before_ok=%d handle_before=%lu handle_after_ok=%d handle_after=%lu elapsed_ms=%llu",
            host.c_str(), static_cast<unsigned>(port), max_attempts, loopback ? 1 : 0,
            last_connect_err, wsa_error_name(last_connect_err), last_poll_rc, static_cast<unsigned>(last_revents), last_poll_wsa,
            wsa_error_name(last_poll_wsa),
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()),
            resolved_family, resolved_ip.c_str(), static_cast<unsigned long long>(last_socket),
            last_connect_stage.c_str(), last_before_would_block ? 1 : 0,
            enobufs_preinit ? "wsaenobufs_preinit" : "connect_failure",
            handle_count_before_ok ? 1 : 0, static_cast<unsigned long>(handle_count_before),
            last_handle_count_after_ok ? 1 : 0, static_cast<unsigned long>(last_handle_count_after),
            static_cast<unsigned long long>(now_steady_ms() - t_steady_start));
        std::ostringstream oss;
        oss << "audit_http.send: connect failed"
            << " host=" << host
            << " port=" << static_cast<unsigned>(port)
            << " resolved_family=" << resolved_family
            << " resolved_ip=" << resolved_ip
            << " tls=" << (tls ? 1 : 0)
            << " attempts=" << max_attempts
            << " loopback=" << (loopback ? 1 : 0)
            << " last_connect_err=" << last_connect_err
            << " wsa_error_name=" << wsa_error_name(last_connect_err)
            << " transport_error_code=" << last_connect_err
            << " transport_error_class=" << (enobufs_preinit ? "wsaenobufs_preinit" : "connect_failure")
            << " last_poll_rc=" << last_poll_rc
            << " last_revents=0x" << std::hex << static_cast<unsigned>(last_revents) << std::dec
            << " last_poll_wsa=" << last_poll_wsa
            << " poll_wsa_name=" << wsa_error_name(last_poll_wsa)
            << " pid=" << static_cast<unsigned long>(GetCurrentProcessId())
            << " tid=" << static_cast<unsigned long>(GetCurrentThreadId())
            << " socket=" << static_cast<unsigned long long>(last_socket)
            << " connect_stage=" << last_connect_stage
            << " before_would_block=" << (last_before_would_block ? 1 : 0)
            << " handle_count_before_ok=" << (handle_count_before_ok ? 1 : 0)
            << " handle_count_before=" << static_cast<unsigned long>(handle_count_before)
            << " handle_count_after_ok=" << (last_handle_count_after_ok ? 1 : 0)
            << " handle_count_after=" << static_cast<unsigned long>(last_handle_count_after)
            << " elapsed_ms=" << static_cast<unsigned long long>(now_steady_ms() - t_steady_start);
        if (enobufs_preinit) {
            oss << " wsaenobufs_diag_id=" << static_cast<unsigned long long>(wsaenobufs_diag_id)
                << " caller_source=" << caller_source
                << " driver_loaded=" << (driver_loaded ? 1 : 0)
                << " driver_connected=" << (driver_connected ? 1 : 0)
                << " driver_attached_pid=" << driver_attached_pid
                << " driver_status=" << driver_status
                << " driver_error=" << driver_error
                << " intercept_state=" << intercept_state
                << " intercept_query_attempted=" << (intercept_query_attempted ? 1 : 0)
                << " intercept_query_ok=" << (intercept_query_ok ? 1 : 0)
                << " intercept_held_count=" << intercept_held_count
                << " circuit_available=" << (circuit_snapshot.available ? 1 : 0)
                << " circuit_state=" << circuit_snapshot.state
                << " circuit_audit_id=" << static_cast<unsigned long long>(circuit_snapshot.audit_id)
                << " circuit_hits=" << circuit_snapshot.hits
                << " circuit_threshold=" << circuit_snapshot.threshold
                << " circuit_failures=" << circuit_snapshot.transport_failures;
        }
        set_err(oss.str());
        return std::nullopt;
    }

    ssl_holder_t ssh;
    if (tls) {
        diag::log_tagged_fmt("audit_http", "send tls_handshake_start host=%s sni=%s",
            host.c_str(), options.sni_override.empty() ? host.c_str() : options.sni_override.c_str());
        const SSL_METHOD* m = TLS_client_method();
        ssh.ctx = SSL_CTX_new(m);
        if (!ssh.ctx) {
            diag::log_tagged("audit_http", "send ssl_ctx_new_failed");
            set_err("audit_http.send: SSL_CTX_new failed"); return std::nullopt;
        }
        SSL_CTX_set_min_proto_version(ssh.ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ssh.ctx, SSL_VERIFY_NONE, nullptr);
        ssh.ssl = SSL_new(ssh.ctx);
        if (!ssh.ssl) {
            diag::log_tagged("audit_http", "send ssl_new_failed");
            set_err("audit_http.send: SSL_new failed"); return std::nullopt;
        }
        SSL_set_fd(ssh.ssl, static_cast<int>(sh.sock));
        const std::string& sni = options.sni_override.empty() ? host : options.sni_override;
        SSL_set_tlsext_host_name(ssh.ssl, sni.c_str());

        uint64_t handshake_deadline = now_steady_ms() + static_cast<uint64_t>(options.timeout_ms);
        while (true) {
            int rc = SSL_connect(ssh.ssl);
            if (rc == 1) break;
            int err = SSL_get_error(ssh.ssl, rc);
            if (err == SSL_ERROR_WANT_READ) {
                if (now_steady_ms() >= handshake_deadline) {
                    diag::log_tagged("audit_http", "send tls_handshake_timeout want_read");
                    set_err("audit_http.send: TLS handshake timeout"); return std::nullopt;
                }
                if (!wait_socket(sh.sock, static_cast<int>(handshake_deadline - now_steady_ms()), false)) {
                    diag::log_tagged("audit_http", "send tls_handshake_poll_failed want_read");
                    set_err("audit_http.send: TLS handshake poll failed"); return std::nullopt;
                }
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (now_steady_ms() >= handshake_deadline) {
                    diag::log_tagged("audit_http", "send tls_handshake_timeout want_write");
                    set_err("audit_http.send: TLS handshake timeout"); return std::nullopt;
                }
                if (!wait_socket(sh.sock, static_cast<int>(handshake_deadline - now_steady_ms()), true)) {
                    diag::log_tagged("audit_http", "send tls_handshake_poll_failed want_write");
                    set_err("audit_http.send: TLS handshake poll failed"); return std::nullopt;
                }
            } else {
                diag::log_tagged_fmt("audit_http", "send tls_handshake_error ssl_err=%d", err);
                set_err("audit_http.send: TLS handshake error");
                return std::nullopt;
            }
        }
        diag::log_tagged_fmt("audit_http", "send tls_handshake_ok host=%s", host.c_str());
    }

    int remaining_ms = options.timeout_ms - static_cast<int>(now_steady_ms() - t_steady_start);
    if (remaining_ms <= 0) {
        diag::log_tagged("audit_http", "send post_connect_timeout");
        set_err("audit_http.send: post-connect timeout"); return std::nullopt;
    }

    diag::log_tagged_fmt("audit_http", "send sending req_len=%zu remaining_ms=%d", req.size(), remaining_ms);
    bool sent_ok;
    if (tls) sent_ok = ssl_send_all(ssh.ssl, req.data(), req.size(), sh.sock, remaining_ms);
    else     sent_ok = send_all(sh.sock, req.data(), req.size(), remaining_ms);
    if (!sent_ok) {
        diag::log_tagged("audit_http", "send send_failed");
        set_err("audit_http.send: send failed"); return std::nullopt;
    }

    remaining_ms = options.timeout_ms - static_cast<int>(now_steady_ms() - t_steady_start);
    if (remaining_ms <= 0) {
        diag::log_tagged("audit_http", "send post_send_timeout");
        set_err("audit_http.send: post-send timeout"); return std::nullopt;
    }

    diag::log_tagged_fmt("audit_http", "send receiving remaining_ms=%d", remaining_ms);
    std::vector<uint8_t> resp_buf;
    bool got_response;
    if (tls) got_response = ssl_recv_until_complete(ssh.ssl, sh.sock, resp_buf, remaining_ms);
    else     got_response = recv_until_complete(sh.sock, resp_buf, remaining_ms);
    if (!got_response) {
        diag::log_tagged("audit_http", "send no_response");
        set_err("audit_http.send: no response"); return std::nullopt;
    }
    diag::log_tagged_fmt("audit_http", "send recv_ok resp_buf=%zu", resp_buf.size());

    uint64_t latency = now_steady_ms() - t_steady_start;
    diag::log_tagged_fmt("audit_http", "send response_parsed latency_ms=%llu resp_size=%zu",
        static_cast<unsigned long long>(latency), resp_buf.size());

    exchange_observed_t ex;
    ex.id = exchange_ids().fetch_add(1, std::memory_order_relaxed);
    ex.timestamp_ms = t_req_start;
    ex.scheme = tls ? "https" : "http";
    ex.host = host;
    ex.port = port;
    ex.latency_ms = latency;
    ex.tls_version = tls ? "TLS1.2+" : std::string();

    {
        std::string raw_s(reinterpret_cast<const char*>(req.data()), req.size());
        auto eol = raw_s.find("\r\n");
        if (eol != std::string::npos) {
            std::string line = raw_s.substr(0, eol);
            auto sp1 = line.find(' ');
            auto sp2 = (sp1 == std::string::npos) ? std::string::npos : line.find(' ', sp1 + 1);
            if (sp1 != std::string::npos) ex.method = line.substr(0, sp1);
            if (sp1 != std::string::npos && sp2 != std::string::npos) {
                std::string uri = line.substr(sp1 + 1, sp2 - sp1 - 1);
                auto qm = uri.find('?');
                if (qm == std::string::npos) ex.path = uri;
                else { ex.path = uri.substr(0, qm); ex.query = uri.substr(qm + 1); }
            }
        }
        size_t headers_off = eol == std::string::npos ? raw_s.size() : eol + 2;
        size_t body_off = raw_s.find("\r\n\r\n");
        body_off = (body_off == std::string::npos) ? raw_s.size() : body_off + 4;
        size_t p = headers_off;
        while (p + 1 < body_off) {
            size_t le = raw_s.find("\r\n", p);
            if (le == std::string::npos || le >= body_off) break;
            size_t colon = raw_s.find(':', p);
            if (colon != std::string::npos && colon < le) {
                std::string name = raw_s.substr(p, colon - p);
                size_t vs = colon + 1;
                while (vs < le && (raw_s[vs] == ' ' || raw_s[vs] == '\t')) ++vs;
                ex.req_headers.emplace_back(std::move(name), raw_s.substr(vs, le - vs));
            }
            p = le + 2;
        }
        if (body_off < raw_s.size()) ex.req_body.assign(req.begin() + static_cast<std::ptrdiff_t>(body_off), req.end());
    }

    std::string resp_s(reinterpret_cast<const char*>(resp_buf.data()), resp_buf.size());
    parse_response_status(resp_s, ex.status_code, ex.reason_phrase);
    diag::log_tagged_fmt("audit_http", "send status=%d reason=%s method=%s path=%s",
        ex.status_code, ex.reason_phrase.c_str(), ex.method.c_str(), ex.path.c_str());
    size_t body_offset = resp_buf.size();
    parse_response_headers(resp_s, ex.resp_headers, body_offset);
    bool chunked = false;
    for (const auto& h : ex.resp_headers) {
        std::string lc = h.first;
        std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lc == "transfer-encoding") {
            std::string vlc = h.second;
            std::transform(vlc.begin(), vlc.end(), vlc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (vlc.find("chunked") != std::string::npos) chunked = true;
        }
    }
    if (chunked) {
        ex.resp_body = decode_chunked_body(resp_buf, body_offset);
    } else if (body_offset < resp_buf.size()) {
        ex.resp_body.assign(resp_buf.begin() + static_cast<std::ptrdiff_t>(body_offset), resp_buf.end());
    }

    if (options.return_first_redirect && (ex.status_code >= 300 && ex.status_code < 400)) {
        diag::log_tagged_fmt("audit_http", "send redirect_first_preserved status=%d follow_redirects=%d max_redirects=%d",
            ex.status_code, options.follow_redirects ? 1 : 0, options.max_redirects);
    }

    if (!options.return_first_redirect && options.follow_redirects && options.max_redirects > 0 &&
        (ex.status_code >= 300 && ex.status_code < 400)) {
        diag::log_tagged_fmt("audit_http", "send redirect status=%d max_redirects=%d", ex.status_code, options.max_redirects);
        for (const auto& h : ex.resp_headers) {
            std::string lc = h.first;
            std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lc == "location") {
                std::string new_url = h.second;
                diag::log_tagged_fmt("audit_http", "send redirect_to url=%s", new_url.c_str());
                if (!new_url.empty()) {
                    std::string ns, nh, np;
                    uint16_t nport = 0;
                    if (parse_url(new_url, ns, nh, nport, np)) {
                        bool ntls = (ns == "https");
                        std::vector<uint8_t> redir_req;
                        std::string line = "GET " + np + " HTTP/1.1\r\nHost: " + nh + "\r\nUser-Agent: AiDA-Scanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
                        redir_req.assign(line.begin(), line.end());
                        send_options_t opt2 = options;
                        opt2.max_redirects--;
                        opt2.follow_redirects = (opt2.max_redirects > 0);
                        auto next = send(redir_req, nh, nport, ntls, opt2);
                        if (next.has_value()) {
                            diag::log_tagged_fmt("audit_http", "send redirect_ok status=%d", next->status_code);
                            return next;
                        }
                    } else {
                        diag::log_tagged_fmt("audit_http", "send redirect_parse_failed url=%s", new_url.c_str());
                    }
                }
                break;
            }
        }
    }

    diag::log_tagged_fmt("audit_http", "send complete status=%d resp_body=%zu latency_ms=%llu",
        ex.status_code, ex.resp_body.size(), static_cast<unsigned long long>(latency));
    if (options.publish_exchange) {
        ex.source = options.exchange_source.empty() ? "api" : options.exchange_source;
        aida::events::publish(kExchangeObservedEvent, ex);
        diag::log_tagged_fmt("audit_http", "send published_exchange source=%s source_label=%s host=%s path=%s status=%d body=%zu",
            ex.source.c_str(), ex.source.c_str(), ex.host.c_str(), ex.path.c_str(), ex.status_code, ex.resp_body.size());
    }
    return ex;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("audit_http", "last_error=%s", e.c_str());
    return e;
}

}
}
}
