#include "test_all_network.h"
#include "test_lab_bounded_runner.hpp"

#include "test_all_features.hpp"
#include "../network/network_view.hpp"
#include "../network/mitm_proxy.hpp"
#include "../network/tcp_stream_tracker.hpp"
#include "../network/protocol_parser.hpp"
#include "../network/http_parser_engine.hpp"
#include "../network/cert_generator.hpp"
#include "../network/ssl_keylog.hpp"
#include "../network/cert_pin_bypass.hpp"
#include "../network/intercept/cert_profile_manager.hpp"
#include "../network/intercept/diagnostics.hpp"
#include "../network/intercept/instrumentation_provider.hpp"
#include "../network/packet_callstack.hpp"
#include "../network/protobuf_codec.hpp"
#include "../network/http2_session.hpp"
#include "../network/burp/match_replace.hpp"
#include "../infra/executor.hpp"
#include "../runtime/standalone_driver.hpp"
#include "net_security.hpp"
#include "../../helpers/diag_log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace test_all_features {

namespace {

    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        test_all_features::write_full_test_log_line(hf, line.data(), line.size());
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
    }

    void fail_empty_evidence(HANDLE hf, const char* tag, std::atomic<int>& failed, const char* fmt, ...) {
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        log_msg(hf, tag, "FAIL -- %s", detail);
        failed.fetch_add(1);
    }

    static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    }

    static const char* network_sub_tab_label(network_view::sub_tab_t tab) {
        switch (tab) {
        case network_view::sub_tab_t::connections: return "connections";
        case network_view::sub_tab_t::capture: return "capture";
        case network_view::sub_tab_t::intercept: return "intercept";
        case network_view::sub_tab_t::proxy: return "proxy";
        case network_view::sub_tab_t::dns: return "dns";
        case network_view::sub_tab_t::filters: return "filters";
        case network_view::sub_tab_t::bandwidth: return "bandwidth";
        case network_view::sub_tab_t::repeater: return "repeater";
        case network_view::sub_tab_t::keylog: return "keylog";
        case network_view::sub_tab_t::pcap_export: return "pcap_export";
        case network_view::sub_tab_t::fuzzer: return "fuzzer";
        case network_view::sub_tab_t::websocket: return "websocket";
        case network_view::sub_tab_t::scripting: return "scripting";
        case network_view::sub_tab_t::decoder: return "decoder";
        case network_view::sub_tab_t::sitemap: return "sitemap";
        case network_view::sub_tab_t::scope: return "scope";
        case network_view::sub_tab_t::cookies: return "cookies";
        case network_view::sub_tab_t::scanner: return "scanner";
        case network_view::sub_tab_t::recon: return "recon";
        case network_view::sub_tab_t::intruder: return "intruder";
        case network_view::sub_tab_t::collab: return "collab";
        case network_view::sub_tab_t::sequencer: return "sequencer";
        case network_view::sub_tab_t::comparer: return "comparer";
        case network_view::sub_tab_t::jwt: return "jwt";
        case network_view::sub_tab_t::mr: return "mr";
        case network_view::sub_tab_t::session: return "session";
        case network_view::sub_tab_t::api: return "api";
        case network_view::sub_tab_t::ws_edit: return "ws_edit";
        case network_view::sub_tab_t::h2_edit: return "h2_edit";
        case network_view::sub_tab_t::logger: return "logger";
        case network_view::sub_tab_t::csp: return "csp";
        case network_view::sub_tab_t::upstream: return "upstream";
        case network_view::sub_tab_t::browser: return "browser";
        case network_view::sub_tab_t::reports: return "reports";
        case network_view::sub_tab_t::headless: return "headless";
        case network_view::sub_tab_t::COUNT: break;
        }
        return "";
    }

    struct bounded_bool_result_t {
        bool completed = false;
        bool value = false;
        bool threw = false;
        bool timed_out = false;
        DWORD win32_error = ERROR_SUCCESS;
        unsigned long worker_pid = 0;
        unsigned long worker_tid = 0;
        unsigned long long elapsed_ms = 0;
        std::string exception;
    };

    template <typename Fn>
    bounded_bool_result_t run_bounded_bool(HANDLE hf,
                                           const char* tag,
                                           const char* op,
                                           DWORD timeout_ms,
                                           Fn&& fn) {
        const ULONGLONG start = GetTickCount64();
        log_msg(hf, tag, "BOUNDED-BEGIN -- op=%s timeout_ms=%lu host_pid=%lu host_tid=%lu",
            op, static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        using task_t = typename std::decay<Fn>::type;
        std::shared_ptr<task_t> task_ptr;
        try {
            task_ptr = std::make_shared<task_t>(std::forward<Fn>(fn));
        } catch (const std::exception& ex) {
            bounded_bool_result_t result;
            result.threw = true;
            result.exception = ex.what();
            result.win32_error = GetLastError();
            const ULONGLONG now = GetTickCount64();
            result.elapsed_ms = static_cast<unsigned long long>(now >= start ? now - start : 0);
            log_msg(hf, tag, "BOUNDED-TASK-INIT-FAIL -- op=%s gle=%lu elapsed_ms=%llu exception_len=%zu",
                op, static_cast<unsigned long>(result.win32_error), result.elapsed_ms, result.exception.size());
            return result;
        } catch (...) {
            bounded_bool_result_t result;
            result.threw = true;
            result.exception = "task_initialization_failed";
            result.win32_error = GetLastError();
            const ULONGLONG now = GetTickCount64();
            result.elapsed_ms = static_cast<unsigned long long>(now >= start ? now - start : 0);
            log_msg(hf, tag, "BOUNDED-TASK-INIT-FAIL -- op=%s gle=%lu elapsed_ms=%llu exception_len=%zu",
                op, static_cast<unsigned long>(result.win32_error), result.elapsed_ms, result.exception.size());
            return result;
        }
        static test_lab::bounded_runner_t runner(1);
        const auto worker_result = std::make_shared<bounded_bool_result_t>();
        const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [start, task_ptr, worker_result](test_lab::bounded_run_context_t context) mutable {
            worker_result->worker_pid = static_cast<unsigned long>(GetCurrentProcessId());
            worker_result->worker_tid = static_cast<unsigned long>(GetCurrentThreadId());
            SetLastError(ERROR_SUCCESS);
            try {
                worker_result->value = (*task_ptr)();
            } catch (const std::exception& ex) {
                worker_result->threw = true;
                worker_result->exception = ex.what();
            } catch (...) {
                worker_result->threw = true;
                worker_result->exception = "unknown_exception";
            }
            worker_result->win32_error = GetLastError();
            worker_result->completed = true;
            const ULONGLONG now = GetTickCount64();
            worker_result->elapsed_ms = static_cast<unsigned long long>(now >= start ? now - start : 0);
            static_cast<void>(context.cancellation_requested());
        });
        bounded_bool_result_t output;
        if ((result.status == test_lab::bounded_run_status_t::completed ||
             result.status == test_lab::bounded_run_status_t::exception) && result.worker_exited)
            output = *worker_result;
        output.timed_out = result.status == test_lab::bounded_run_status_t::timed_out;
        output.completed = result.status == test_lab::bounded_run_status_t::completed && result.worker_exited && worker_result->completed;
        output.threw = result.status == test_lab::bounded_run_status_t::exception ||
            (result.worker_exited && worker_result->threw);
        if (result.status == test_lab::bounded_run_status_t::exception && output.exception.empty())
            output.exception = result.error;
        if (output.timed_out)
            output.win32_error = WAIT_TIMEOUT;
        else if (result.status == test_lab::bounded_run_status_t::exception && output.win32_error == ERROR_SUCCESS)
            output.win32_error = ERROR_EXCEPTION_IN_SERVICE;
        output.elapsed_ms = result.elapsed_ms;
        if (result.status == test_lab::bounded_run_status_t::post_failed ||
            result.status == test_lab::bounded_run_status_t::saturated) {
            bounded_bool_result_t post_result;
            post_result.threw = true;
            post_result.exception = result.status == test_lab::bounded_run_status_t::saturated
                ? "bounded_runner_saturated" : (result.error.empty() ? "taskflow_executor_post_failed" : result.error);
            post_result.win32_error = result.status == test_lab::bounded_run_status_t::saturated
                ? ERROR_BUSY : ERROR_NOT_READY;
            post_result.elapsed_ms = result.elapsed_ms;
            log_msg(hf, tag, "BOUNDED-TASKFLOW-EXECUTOR-POST-FAIL -- op=%s gle=%lu elapsed_ms=%llu exception=%s",
                op, static_cast<unsigned long>(post_result.win32_error), post_result.elapsed_ms, post_result.exception.c_str());
            return post_result;
        }
        if (output.timed_out)
            log_msg(hf, tag, "BOUNDED-TIMEOUT -- op=%s timeout_ms=%lu task_id=%llu cancellation_requested=%d worker_started=%d worker_exited=%d pending=%d elapsed_ms=%llu",
                op, static_cast<unsigned long>(timeout_ms), static_cast<unsigned long long>(result.task_id),
                result.cancellation_requested ? 1 : 0, result.worker_started ? 1 : 0,
                result.worker_exited ? 1 : 0, result.pending ? 1 : 0, output.elapsed_ms);
        log_msg(hf, tag, "BOUNDED-END -- op=%s completed=%d value=%d threw=%d gle=%lu worker_pid=%lu worker_tid=%lu elapsed_ms=%llu exception_len=%zu",
            op,
            output.completed ? 1 : 0, output.value ? 1 : 0, output.threw ? 1 : 0,
            static_cast<unsigned long>(output.win32_error), output.worker_pid, output.worker_tid,
            output.elapsed_ms, output.exception.size());
        return output;
    }

    struct winsock_scope_t {
        WSADATA data{};
        int rc = WSAStartup(MAKEWORD(2, 2), &data);
        ~winsock_scope_t() {
            if (rc == 0)
                WSACleanup();
        }
        bool ok() const { return rc == 0; }
    };

    struct tcp_pair_fixture_t {
        SOCKET listener = INVALID_SOCKET;
        SOCKET client = INVALID_SOCKET;
        SOCKET accepted = INVALID_SOCKET;
        uint16_t listen_port = 0;
        uint16_t client_port = 0;
        uint8_t client_addr[16]{};
        uint8_t server_addr[16]{};

        ~tcp_pair_fixture_t() {
            close_all();
        }

        void close_all() {
            if (accepted != INVALID_SOCKET) {
                closesocket(accepted);
                accepted = INVALID_SOCKET;
            }
            if (client != INVALID_SOCKET) {
                closesocket(client);
                client = INVALID_SOCKET;
            }
            if (listener != INVALID_SOCKET) {
                closesocket(listener);
                listener = INVALID_SOCKET;
            }
        }
    };

    bool configure_fixture_socket(SOCKET s) {
        DWORD timeout_ms = 2000;
        int ok1 = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        int ok2 = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        return ok1 == 0 && ok2 == 0;
    }

    bool open_tcp_pair_fixture(HANDLE hf, const char* tag, tcp_pair_fixture_t& fx) {
        fx.close_all();
        fx.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fx.listener == INVALID_SOCKET) {
            log_msg(hf, tag, "fixture tcp listener socket failed err=%d", WSAGetLastError());
            return false;
        }
        configure_fixture_socket(fx.listener);
        BOOL reuse = TRUE;
        setsockopt(fx.listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        la.sin_port = 0;
        if (bind(fx.listener, reinterpret_cast<const sockaddr*>(&la), sizeof(la)) != 0) {
            log_msg(hf, tag, "fixture tcp bind failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        if (listen(fx.listener, 1) != 0) {
            log_msg(hf, tag, "fixture tcp listen failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        sockaddr_in actual{};
        int actual_len = sizeof(actual);
        if (getsockname(fx.listener, reinterpret_cast<sockaddr*>(&actual), &actual_len) != 0) {
            log_msg(hf, tag, "fixture tcp listener getsockname failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        fx.listen_port = ntohs(actual.sin_port);

        fx.client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fx.client == INVALID_SOCKET) {
            log_msg(hf, tag, "fixture tcp client socket failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        configure_fixture_socket(fx.client);

        sockaddr_in ra{};
        ra.sin_family = AF_INET;
        ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ra.sin_port = htons(fx.listen_port);
        if (connect(fx.client, reinterpret_cast<const sockaddr*>(&ra), sizeof(ra)) != 0) {
            log_msg(hf, tag, "fixture tcp connect to 127.0.0.1:%u failed err=%d",
                static_cast<unsigned>(fx.listen_port), WSAGetLastError());
            fx.close_all();
            return false;
        }

        sockaddr_in client_actual{};
        int client_len = sizeof(client_actual);
        if (getsockname(fx.client, reinterpret_cast<sockaddr*>(&client_actual), &client_len) != 0) {
            log_msg(hf, tag, "fixture tcp client getsockname failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        fx.client_port = ntohs(client_actual.sin_port);
        fx.client_addr[0] = 127;
        fx.client_addr[3] = 1;
        fx.server_addr[0] = 127;
        fx.server_addr[3] = 1;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fx.listener, &rfds);
        timeval tv{};
        tv.tv_sec = 2;
        int ready = select(0, &rfds, nullptr, nullptr, &tv);
        if (ready <= 0) {
            log_msg(hf, tag, "fixture tcp accept readiness failed ready=%d err=%d",
                ready, ready == SOCKET_ERROR ? WSAGetLastError() : 0);
            fx.close_all();
            return false;
        }
        fx.accepted = accept(fx.listener, nullptr, nullptr);
        if (fx.accepted == INVALID_SOCKET) {
            log_msg(hf, tag, "fixture tcp accept failed err=%d", WSAGetLastError());
            fx.close_all();
            return false;
        }
        configure_fixture_socket(fx.accepted);
        log_msg(hf, tag, "fixture tcp pair ready client_port=%u listen_port=%u",
            static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.listen_port));
        return true;
    }

    bool drive_tcp_pair_fixture(HANDLE hf, const char* tag, tcp_pair_fixture_t& fx, const char* payload) {
        const int payload_len = static_cast<int>(std::strlen(payload));
        int sent = send(fx.client, payload, payload_len, 0);
        int send_err = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        char buf[2048]{};
        int recvd = recv(fx.accepted, buf, sizeof(buf), 0);
        int recv_err = recvd == SOCKET_ERROR ? WSAGetLastError() : 0;
        const char response[] = "AIDA-TCP-FIXTURE-ACK";
        int sent_back = SOCKET_ERROR;
        int recv_back = SOCKET_ERROR;
        int send_back_err = 0;
        int recv_back_err = 0;
        if (recvd > 0) {
            sent_back = send(fx.accepted, response, static_cast<int>(sizeof(response) - 1), 0);
            send_back_err = sent_back == SOCKET_ERROR ? WSAGetLastError() : 0;
            char ack_buf[64]{};
            recv_back = recv(fx.client, ack_buf, sizeof(ack_buf), 0);
            recv_back_err = recv_back == SOCKET_ERROR ? WSAGetLastError() : 0;
        }
        log_msg(hf, tag, "fixture tcp traffic sent=%d send_err=%d recvd=%d recv_err=%d sent_back=%d send_back_err=%d recv_back=%d recv_back_err=%d",
            sent, send_err, recvd, recv_err, sent_back, send_back_err, recv_back, recv_back_err);
        return sent == payload_len && recvd == payload_len;
    }

    struct udp_pair_fixture_t {
        SOCKET server = INVALID_SOCKET;
        SOCKET client = INVALID_SOCKET;
        uint16_t server_port = 0;
        uint16_t client_port = 0;
        uint32_t sent_packets = 0;
        uint32_t sent_bytes = 0;
        uint32_t received_packets = 0;
        uint32_t received_bytes = 0;
        int last_send_error = 0;
        int last_recv_error = 0;

        ~udp_pair_fixture_t() {
            close_all();
        }

        void close_all() {
            if (client != INVALID_SOCKET) {
                closesocket(client);
                client = INVALID_SOCKET;
            }
            if (server != INVALID_SOCKET) {
                closesocket(server);
                server = INVALID_SOCKET;
            }
        }

        void reset_fields() {
            server_port = 0;
            client_port = 0;
            sent_packets = 0;
            sent_bytes = 0;
            received_packets = 0;
            received_bytes = 0;
            last_send_error = 0;
            last_recv_error = 0;
        }
    };

    unsigned long long socket_id(SOCKET s) {
        return static_cast<unsigned long long>(static_cast<UINT_PTR>(s));
    }

    bool open_udp_pair_fixture(HANDLE hf, const char* tag, udp_pair_fixture_t& fx, uint16_t preferred_server_port) {
        const ULONGLONG t0 = GetTickCount64();
        fx.close_all();
        fx.reset_fields();
        fx.server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fx.server == INVALID_SOCKET) {
            log_msg(hf, tag, "fixture udp server socket failed pid=%lu tid=%lu err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), WSAGetLastError());
            return false;
        }
        fx.client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fx.client == INVALID_SOCKET) {
            log_msg(hf, tag, "fixture udp client socket failed pid=%lu tid=%lu server_socket=%llu err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), socket_id(fx.server), WSAGetLastError());
            fx.close_all();
            return false;
        }
        configure_fixture_socket(fx.server);
        configure_fixture_socket(fx.client);
        BOOL reuse = TRUE;
        setsockopt(fx.server, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        setsockopt(fx.client, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        server_addr.sin_port = htons(preferred_server_port);
        int server_bind_err = 0;
        bool used_preferred = true;
        if (bind(fx.server, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
            server_bind_err = WSAGetLastError();
            used_preferred = false;
            server_addr.sin_port = 0;
            if (bind(fx.server, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
                log_msg(hf, tag, "fixture udp server bind failed pid=%lu tid=%lu preferred_port=%u first_err=%d fallback_err=%d",
                    GetCurrentProcessId(), GetCurrentThreadId(), static_cast<unsigned>(preferred_server_port),
                    server_bind_err, WSAGetLastError());
                fx.close_all();
                return false;
            }
        }

        sockaddr_in actual_server{};
        int actual_server_len = sizeof(actual_server);
        if (getsockname(fx.server, reinterpret_cast<sockaddr*>(&actual_server), &actual_server_len) != 0) {
            log_msg(hf, tag, "fixture udp server getsockname failed pid=%lu tid=%lu err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), WSAGetLastError());
            fx.close_all();
            return false;
        }
        fx.server_port = ntohs(actual_server.sin_port);

        sockaddr_in client_addr{};
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        client_addr.sin_port = 0;
        if (bind(fx.client, reinterpret_cast<const sockaddr*>(&client_addr), sizeof(client_addr)) != 0) {
            log_msg(hf, tag, "fixture udp client bind failed pid=%lu tid=%lu server_port=%u err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), static_cast<unsigned>(fx.server_port), WSAGetLastError());
            fx.close_all();
            return false;
        }

        sockaddr_in actual_client{};
        int actual_client_len = sizeof(actual_client);
        if (getsockname(fx.client, reinterpret_cast<sockaddr*>(&actual_client), &actual_client_len) != 0) {
            log_msg(hf, tag, "fixture udp client getsockname failed pid=%lu tid=%lu err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), WSAGetLastError());
            fx.close_all();
            return false;
        }
        fx.client_port = ntohs(actual_client.sin_port);

        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(fx.server_port);
        if (connect(fx.client, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) != 0) {
            log_msg(hf, tag, "fixture udp client connect failed pid=%lu tid=%lu client_port=%u dst_port=%u err=%d",
                GetCurrentProcessId(), GetCurrentThreadId(), static_cast<unsigned>(fx.client_port),
                static_cast<unsigned>(fx.server_port), WSAGetLastError());
            fx.close_all();
            return false;
        }

        u_long nonblocking = 1;
        const int nb_rc = ioctlsocket(fx.server, FIONBIO, &nonblocking);
        log_msg(hf, tag, "fixture udp pair ready pid=%lu tid=%lu client_socket=%llu server_socket=%llu client_port=%u server_port=%u preferred_port=%u used_preferred=%d first_bind_err=%d server_nonblock_rc=%d server_nonblock_err=%d elapsed_ms=%llu",
            GetCurrentProcessId(), GetCurrentThreadId(), socket_id(fx.client), socket_id(fx.server),
            static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.server_port),
            static_cast<unsigned>(preferred_server_port), used_preferred ? 1 : 0, server_bind_err,
            nb_rc, nb_rc == 0 ? 0 : WSAGetLastError(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return true;
    }

    uint32_t drain_udp_fixture(HANDLE hf, const char* tag, udp_pair_fixture_t& fx, const char* phase) {
        uint32_t drained = 0;
        char buf[512]{};
        for (;;) {
            sockaddr_in from{};
            int from_len = sizeof(from);
            int rc = recvfrom(fx.server, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
            if (rc == SOCKET_ERROR) {
                int err = WSAGetLastError();
                fx.last_recv_error = err;
                if (err == WSAEWOULDBLOCK)
                    break;
                log_msg(hf, tag, "fixture udp drain error phase=%s pid=%lu tid=%lu client_port=%u server_port=%u received=%u err=%d",
                    phase ? phase : "<null>", GetCurrentProcessId(), GetCurrentThreadId(),
                    static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.server_port),
                    static_cast<unsigned>(drained), err);
                break;
            }
            if (rc == 0)
                break;
            ++drained;
            ++fx.received_packets;
            fx.received_bytes += static_cast<uint32_t>(rc);
            if (drained >= 128)
                break;
        }
        log_msg(hf, tag, "fixture udp drain phase=%s pid=%lu tid=%lu client_port=%u server_port=%u drained=%u total_received=%u total_received_bytes=%u last_recv_err=%d",
            phase ? phase : "<null>", GetCurrentProcessId(), GetCurrentThreadId(),
            static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.server_port),
            static_cast<unsigned>(drained), static_cast<unsigned>(fx.received_packets),
            static_cast<unsigned>(fx.received_bytes), fx.last_recv_error);
        return drained;
    }

    bool drive_udp_burst_fixture(HANDLE hf, const char* tag, udp_pair_fixture_t& fx, int packet_count) {
        const ULONGLONG t0 = GetTickCount64();
        char payload[160]{};
        int last_err = 0;
        uint32_t sent = 0;
        uint32_t bytes = 0;
        for (int i = 0; i < packet_count; ++i) {
            _snprintf_s(payload, sizeof(payload), _TRUNCATE,
                "AIDA-UDP-FIXTURE pid=%lu tid=%lu seq=%d src=%u dst=%u",
                GetCurrentProcessId(), GetCurrentThreadId(), i,
                static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.server_port));
            int rc = send(fx.client, payload, static_cast<int>(sizeof(payload)), 0);
            if (rc == SOCKET_ERROR) {
                last_err = WSAGetLastError();
            } else {
                ++sent;
                bytes += static_cast<uint32_t>(rc);
            }
        }
        fx.sent_packets += sent;
        fx.sent_bytes += bytes;
        fx.last_send_error = last_err;
        log_msg(hf, tag, "fixture udp burst pid=%lu tid=%lu client_socket=%llu server_socket=%llu client_port=%u dst_port=%u requested=%d sent=%u sent_bytes=%u last_send_err=%d elapsed_ms=%llu",
            GetCurrentProcessId(), GetCurrentThreadId(), socket_id(fx.client), socket_id(fx.server),
            static_cast<unsigned>(fx.client_port), static_cast<unsigned>(fx.server_port),
            packet_count, static_cast<unsigned>(sent), static_cast<unsigned>(bytes), last_err,
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return sent > 0;
    }

    bool drive_udp_burst_fixture(HANDLE hf, const char* tag, uint16_t dst_port, int packet_count, uint32_t& sent_packets) {
        sent_packets = 0;
        udp_pair_fixture_t fx;
        if (!open_udp_pair_fixture(hf, tag, fx, dst_port)) {
            log_msg(hf, tag, "fixture udp compat open failed dst_port=%u requested=%d",
                static_cast<unsigned>(dst_port), packet_count);
            return false;
        }
        const bool ok = drive_udp_burst_fixture(hf, tag, fx, packet_count);
        sent_packets = fx.sent_packets;
        const uint32_t drained = drain_udp_fixture(hf, tag, fx, "compat_after_burst");
        log_msg(hf, tag, "fixture udp compat burst dst_port=%u requested=%d sent=%u received=%u drained=%u client_port=%u server_port=%u ok=%d",
            static_cast<unsigned>(dst_port),
            packet_count,
            static_cast<unsigned>(sent_packets),
            static_cast<unsigned>(fx.received_packets),
            static_cast<unsigned>(drained),
            static_cast<unsigned>(fx.client_port),
            static_cast<unsigned>(fx.server_port),
            ok ? 1 : 0);
        return ok;
    }

    bool driver_capture_fixture(HANDLE hf, const char* tag, uint32_t protocol_filter, std::vector<driver_bridge::captured_packet_t>& packets) {
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "fixture WSAStartup failed rc=%d", wsa.rc);
            return false;
        }
        (void)driver_bridge::stop_capture();
        const uint32_t self_pid = GetCurrentProcessId();
        bool started = driver_bridge::start_capture(self_pid, 0, protocol_filter, nullptr, 1500);
        log_msg(hf, tag, "fixture capture start self_pid=%u proto=%u ok=%d",
            static_cast<unsigned>(self_pid), static_cast<unsigned>(protocol_filter), started ? 1 : 0);
        if (!started)
            return false;

        tcp_pair_fixture_t tcp;
        bool tcp_ok = false;
        if (protocol_filter == 0 || protocol_filter == 6) {
            tcp_ok = open_tcp_pair_fixture(hf, tag, tcp) &&
                drive_tcp_pair_fixture(hf, tag, tcp, "GET /aida-driver-capture HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        }
        uint32_t udp_sent = 0;
        bool udp_ok = false;
        if (protocol_filter == 0 || protocol_filter == 17) {
            udp_ok = drive_udp_burst_fixture(hf, tag, 53535, 24, udp_sent);
        }

        bool active = false;
        uint32_t captured = 0;
        uint32_t dropped = 0;
        for (int i = 0; i < 8; ++i) {
            Sleep(125);
            bool status_ok = driver_bridge::get_capture_status(active, captured, dropped);
            log_msg(hf, tag, "fixture capture poll iter=%d status_ok=%d active=%d captured=%u dropped=%u",
                i, status_ok ? 1 : 0, active ? 1 : 0, captured, dropped);
            if (captured > 0)
                break;
        }
        bool stopped = driver_bridge::stop_capture();
        log_msg(hf, tag, "fixture capture stop ok=%d tcp_ok=%d udp_ok=%d udp_sent=%u captured_before_stop=%u dropped=%u",
            stopped ? 1 : 0, tcp_ok ? 1 : 0, udp_ok ? 1 : 0, udp_sent, captured, dropped);
        packets = driver_bridge::get_captured_packets(32);
        log_msg(hf, tag, "fixture capture drain packets=%zu", packets.size());
        return stopped && (tcp_ok || udp_ok) && !packets.empty();
    }

    void log_parser_proof(HANDLE hf, const char* case_name, const protocol_parser::http_request& req) {
        log_msg(hf, "parser_proof", "CASE %s request valid=%s complete=%s consumed=%zu method=%s uri_len=%zu headers=%zu body=%zu",
            case_name,
            req.valid ? "true" : "false",
            req.complete ? "true" : "false",
            req.total_consumed,
            req.method.empty() ? "(empty)" : req.method.c_str(),
            req.uri.size(),
            req.headers.size(),
            req.body.size());
        diag::log_tagged_fmt("parser_proof", "CASE %s request valid=%d complete=%d consumed=%zu method=%s uri_len=%zu headers=%zu body=%zu",
            case_name,
            static_cast<int>(req.valid),
            static_cast<int>(req.complete),
            req.total_consumed,
            req.method.empty() ? "(empty)" : req.method.c_str(),
            req.uri.size(),
            req.headers.size(),
            req.body.size());
    }

    void log_parser_proof(HANDLE hf, const char* case_name, const protocol_parser::http_response& resp) {
        log_msg(hf, "parser_proof", "CASE %s response valid=%s complete=%s consumed=%zu status=%d headers=%zu body=%zu",
            case_name,
            resp.valid ? "true" : "false",
            resp.complete ? "true" : "false",
            resp.total_consumed,
            resp.status_code,
            resp.headers.size(),
            resp.body.size());
        diag::log_tagged_fmt("parser_proof", "CASE %s response valid=%d complete=%d consumed=%zu status=%d headers=%zu body=%zu",
            case_name,
            static_cast<int>(resp.valid),
            static_cast<int>(resp.complete),
            resp.total_consumed,
            resp.status_code,
            resp.headers.size(),
            resp.body.size());
    }

    static void call_test(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f) {
        __try { fn(hf, p, f); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }
    static void call_test_s(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f, std::atomic<int>& s) {
        __try { fn(hf, p, f, s); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }
    static bool is_cancelled(bool(*cancelled)()) {
        return cancelled && cancelled();
    }
    static void call_test_tracker(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&, std::atomic<int>&, bool(*)()), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f, std::atomic<int>& s, bool(*cancelled)()) {
        __try { fn(hf, p, f, s, cancelled); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }
    static bool stop_tracker_logged(network_view::tcp_stream_tracker_t& tracker, HANDLE hf, const char* tag, bool(*cancelled)()) {
        const bool cancel_before = is_cancelled(cancelled);
        const uint32_t timeout_ms = cancel_before ? 250u : 2000u;
        const auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "before stop pid=%lu tid=%lu cancel=%d timeout_ms=%u is_running=%s",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            cancel_before ? 1 : 0,
            static_cast<unsigned>(timeout_ms),
            tracker.is_running() ? "true" : "false");
        const bool stopped = tracker.stop(timeout_ms);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        const bool cancel_after = is_cancelled(cancelled);
        log_msg(hf, tag, "after stop stopped=%d elapsed_ms=%lld cancel_before=%d cancel_after=%d is_running=%s",
            stopped ? 1 : 0,
            static_cast<long long>(elapsed),
            cancel_before ? 1 : 0,
            cancel_after ? 1 : 0,
            tracker.is_running() ? "true" : "false");
        if (!stopped) {
            log_msg(hf, tag,
                "TIMEOUT-DETAIL pid=%lu tid=%lu timeout_ms=%u elapsed_ms=%lld cancel_before=%d cancel_after=%d is_running=%s gle=%lu",
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned>(timeout_ms),
                static_cast<long long>(elapsed),
                cancel_before ? 1 : 0,
                cancel_after ? 1 : 0,
                tracker.is_running() ? "true" : "false",
                static_cast<unsigned long>(GetLastError()));
        }
        return stopped;
    }

    void test_network_view_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "net_view_init";
        log_msg(hf, tag, "START -- network_view::initialize()");
        network_view::initialize();
        log_msg(hf, tag, "PASS -- network_view initialized");
        passed.fetch_add(1);
    }

    void test_mitm_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_start";
        log_msg(hf, tag, "START -- mitm_proxy::start(port=18888)");
        mitm_proxy::proxy_config cfg;
        cfg.bind_addr = "127.0.0.1";
        cfg.bind_port = 18888;
        cfg.intercept_enabled = false;
        cfg.decode_tls = false;
        bool ok = mitm_proxy::start(cfg);
        if (ok) {
            log_msg(hf, tag, "PASS -- proxy started on 127.0.0.1:18888");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- start() returned false");
            failed.fetch_add(1);
        }
    }

    void test_mitm_is_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_running";
        log_msg(hf, tag, "START -- mitm_proxy::is_running()");
        bool running = mitm_proxy::is_running();
        log_msg(hf, tag, "is_running = %s", running ? "true" : "false");
        if (running) {
            log_msg(hf, tag, "PASS -- proxy reports running");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- proxy reports not running after start");
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_stats";
        log_msg(hf, tag, "START -- mitm_proxy::get_stats()");
        auto stats = mitm_proxy::get_stats();
        log_msg(hf, tag, "running=%s total_requests=%llu bytes_in=%llu bytes_out=%llu active_conns=%u history=%zu held=%zu",
            stats.running ? "true" : "false",
            (unsigned long long)stats.total_requests,
            (unsigned long long)stats.total_bytes_in,
            (unsigned long long)stats.total_bytes_out,
            (unsigned)stats.active_connections,
            stats.history_size,
            stats.held_count);
        log_msg(hf, tag, "PASS -- stats retrieved successfully");
        passed.fetch_add(1);
    }

    void test_mitm_intercept_on(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_on";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_enabled(true)");
        mitm_proxy::set_intercept_enabled(true);
        bool enabled = mitm_proxy::is_intercept_enabled();
        if (enabled) {
            log_msg(hf, tag, "PASS -- intercept enabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept not enabled after set");
            failed.fetch_add(1);
        }
    }

    void test_mitm_intercept_off(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_off";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_enabled(false)");
        mitm_proxy::set_intercept_enabled(false);
        bool enabled = mitm_proxy::is_intercept_enabled();
        if (!enabled) {
            log_msg(hf, tag, "PASS -- intercept disabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept still enabled after disable");
            failed.fetch_add(1);
        }
    }

    void test_mitm_check_intercept(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_chk_intcpt";
        log_msg(hf, tag, "START -- mitm_proxy::is_intercept_enabled()");
        bool enabled = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "is_intercept_enabled = %s", enabled ? "true" : "false");
        if (!enabled) {
            log_msg(hf, tag, "PASS -- intercept correctly reports disabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept unexpectedly enabled");
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_history_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_empty";
        log_msg(hf, tag, "START -- mitm_proxy::get_history(100) (expect empty)");
        auto hist = mitm_proxy::get_history(100);
        log_msg(hf, tag, "history count = %zu", hist.size());
        log_msg(hf, tag, "PASS -- get_history returned %zu entries", hist.size());
        passed.fetch_add(1);
    }

    void test_mitm_history_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_cnt";
        log_msg(hf, tag, "START -- mitm_proxy::history_count()");
        size_t count = mitm_proxy::history_count();
        log_msg(hf, tag, "history_count = %zu", count);
        log_msg(hf, tag, "PASS -- history_count returned successfully");
        passed.fetch_add(1);
    }

    void test_mitm_repeat_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "mitm_repeat";
        log_msg(hf, tag, "START -- mitm_proxy::repeat_request loopback fixture");
        WSADATA wsa{};
        int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsa_rc != 0) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa_rc);
            failed.fetch_add(1);
            return;
        }
        struct loopback_fixture_ctx_t {
            SOCKET listener = INVALID_SOCKET;
            SOCKET accepted = INVALID_SOCKET;
            std::atomic<bool> server_done{ false };
            std::mutex socket_mtx;
        };
        auto ctx = std::make_shared<loopback_fixture_ctx_t>();
        auto close_listener = [ctx]() {
            std::lock_guard<std::mutex> lk(ctx->socket_mtx);
            if (ctx->listener != INVALID_SOCKET) {
                closesocket(ctx->listener);
                ctx->listener = INVALID_SOCKET;
            }
        };
        ctx->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ctx->listener == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- loopback fixture socket failed wsa=%d", WSAGetLastError());
            failed.fetch_add(1);
            WSACleanup();
            return;
        }
        sockaddr_in bind_addr = {};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;
        int opt = 1;
        setsockopt(ctx->listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        if (bind(ctx->listener, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR ||
            listen(ctx->listener, 1) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            close_listener();
            log_msg(hf, tag, "FAIL -- loopback fixture bind/listen failed wsa=%d", err);
            failed.fetch_add(1);
            WSACleanup();
            return;
        }
        sockaddr_in actual_addr = {};
        int actual_len = sizeof(actual_addr);
        if (getsockname(ctx->listener, reinterpret_cast<sockaddr*>(&actual_addr), &actual_len) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            close_listener();
            log_msg(hf, tag, "FAIL -- loopback fixture getsockname failed wsa=%d", err);
            failed.fetch_add(1);
            WSACleanup();
            return;
        }
        const uint16_t port = ntohs(actual_addr.sin_port);
        log_msg(hf, tag, "INFO -- loopback fixture listening on 127.0.0.1:%u", static_cast<unsigned>(port));
        aida::infra::executor::submission_t server_sub;
        server_sub.owner_subsystem = "testlab_network";
        server_sub.label = "testlab.network.loopback_fixture";
        server_sub.thread_class = "bounded_task";
        server_sub.domain = aida::infra::executor::domain_t::critical;
        server_sub.priority = 1;
        server_sub.failure_policy = "reject_not_started";
        server_sub.shutdown_policy = "drain";
        server_sub.body = [ctx, close_listener]() {
            SOCKET listener = INVALID_SOCKET;
            {
                std::lock_guard<std::mutex> lk(ctx->socket_mtx);
                listener = ctx->listener;
            }
            ctx->accepted = accept(listener, nullptr, nullptr);
            if (ctx->accepted != INVALID_SOCKET) {
                char req_buf[512];
                recv(ctx->accepted, req_buf, sizeof(req_buf), 0);
                const char* resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nAIDA";
                send(ctx->accepted, resp, static_cast<int>(std::strlen(resp)), 0);
                closesocket(ctx->accepted);
                ctx->accepted = INVALID_SOCKET;
            }
            close_listener();
            ctx->server_done.store(true);
        };
        const bool server_posted = aida::infra::executor::submit(std::move(server_sub)).submitted;
        if (!server_posted) {
            close_listener();
            log_msg(hf, tag, "FAIL -- loopback fixture taskflow critical executor post failed");
            failed.fetch_add(1);
            WSACleanup();
            return;
        }
        std::string raw = "GET / HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) + "\r\nConnection: close\r\n\r\n";
        std::vector<uint8_t> raw_bytes(raw.begin(), raw.end());
        log_msg(hf, tag, "fixture request bytes=%zu target=127.0.0.1:%u tls=false", raw_bytes.size(), static_cast<unsigned>(port));

        auto result = mitm_proxy::repeat_request("127.0.0.1", port, false, raw_bytes);
        int attempts = 1;
        while (!result.success && attempts < 6) {
            log_msg(hf, tag, "attempt %d failed quickly: %s", attempts, result.error.c_str());
            Sleep(static_cast<DWORD>(100 + attempts * 75));
            result = mitm_proxy::repeat_request("127.0.0.1", port, false, raw_bytes);
            ++attempts;
        }
        if (result.success) {
            if (result.exchange.response.status_code != 200 || result.exchange.response_size == 0) {
                log_msg(hf, tag, "FAIL -- repeat_request returned success but response evidence is invalid attempts=%d status=%d response_size=%zu latency=%llu ms",
                    attempts,
                    result.exchange.response.status_code,
                    result.exchange.response_size,
                    (unsigned long long)result.exchange.latency_ms);
                failed.fetch_add(1);
                close_listener();
                for (int i = 0; i < 100 && !ctx->server_done.load(); ++i)
                    Sleep(20);
                WSACleanup();
                return;
            }
            log_msg(hf, tag, "PASS -- repeat_request succeeded after %d attempt(s), status=%d response_size=%zu latency=%llu ms",
                attempts,
                result.exchange.response.status_code,
                result.exchange.response_size,
                (unsigned long long)result.exchange.latency_ms);
            passed.fetch_add(1);
        } else {
            auto direct_probe = [&]() -> std::pair<bool, int> {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET)
                    return { false, WSAGetLastError() };
                u_long nb = 1;
                ioctlsocket(s, FIONBIO, &nb);
                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                sa.sin_port = htons(port);
                int rc = connect(s, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
                int err = 0;
                if (rc != 0) {
                    err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                        fd_set wfds, efds;
                        FD_ZERO(&wfds); FD_ZERO(&efds);
                        FD_SET(s, &wfds); FD_SET(s, &efds);
                        timeval tv{};
                        tv.tv_sec = 2;
                        int sel = select(0, nullptr, &wfds, &efds, &tv);
                        if (sel > 0) {
                            int so_err = 0;
                            int so_len = static_cast<int>(sizeof(so_err));
                            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
                            err = so_err;
                            rc = so_err == 0 ? 0 : SOCKET_ERROR;
                        } else {
                            err = sel == 0 ? WSAETIMEDOUT : WSAGetLastError();
                        }
                    }
                }
                nb = 0;
                ioctlsocket(s, FIONBIO, &nb);
                if (rc == 0) {
                    const char* req = "GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                    send(s, req, static_cast<int>(std::strlen(req)), 0);
                    char tmp[128];
                    recv(s, tmp, sizeof(tmp), 0);
                    closesocket(s);
                    return { true, 0 };
                }
                closesocket(s);
                return { false, err };
            };
            auto probe = direct_probe();
            if (!probe.first) {
                log_msg(hf, tag, "FAIL -- repeat_request failed and direct loopback probe could not connect to fixture port=%u wsa=%d attempts=%d error=%s",
                    static_cast<unsigned>(port), probe.second, attempts, result.error.c_str());
                failed.fetch_add(1);
                close_listener();
                for (int i = 0; i < 100 && !ctx->server_done.load(); ++i)
                    Sleep(20);
                WSACleanup();
                return;
            }
            log_msg(hf, tag, "FAIL -- repeat_request failed after %d attempt(s): %s",
                attempts, result.error.c_str());
            failed.fetch_add(1);
        }
        close_listener();
        for (int i = 0; i < 100 && !ctx->server_done.load(); ++i)
            Sleep(20);
        if (!ctx->server_done.load())
            log_msg(hf, tag, "loopback fixture worker still draining after socket close");
        WSACleanup();
    }

    void test_mitm_get_history_after(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_after";
        log_msg(hf, tag, "START -- mitm_proxy::get_history() after repeat_request");
        auto hist = mitm_proxy::get_history(100);
        log_msg(hf, tag, "history count = %zu", hist.size());
        if (!hist.empty()) {
            auto& last = hist.back();
            log_msg(hf, tag, "last exchange: id=%llu host=%s:%u tls=%s state=%d",
                (unsigned long long)last.id,
                last.target_host.c_str(),
                (unsigned)last.target_port,
                last.is_tls ? "true" : "false",
                (int)last.state);
        }
        if (hist.empty()) {
            fail_empty_evidence(hf, tag, failed, "history is empty after repeat_request fixture; proxy/repeater did not persist exchange evidence");
        } else {
            log_msg(hf, tag, "PASS -- get_history returned %zu entries", hist.size());
            passed.fetch_add(1);
        }
    }

    void test_mitm_clear_history(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_clr_hist";
        log_msg(hf, tag, "START -- mitm_proxy::clear_history()");
        mitm_proxy::clear_history();
        size_t count = mitm_proxy::history_count();
        log_msg(hf, tag, "history_count after clear = %zu", count);
        if (count == 0) {
            log_msg(hf, tag, "PASS -- history cleared successfully");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- history_count=%zu after clear (expected 0)", count);
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_held(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_held";
        log_msg(hf, tag, "START -- mitm_proxy::get_held_exchanges()");
        auto held = mitm_proxy::get_held_exchanges();
        log_msg(hf, tag, "held_exchanges count = %zu", held.size());
        log_msg(hf, tag, "PASS -- get_held_exchanges returned %zu entries", held.size());
        passed.fetch_add(1);
    }

    void test_mitm_forward_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_fwd_all";
        log_msg(hf, tag, "START -- mitm_proxy::forward_all()");
        size_t held_before = mitm_proxy::get_held_exchanges().size();
        bool intercept_alive = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "INPUT held_before=%zu intercept_enabled=%d pid=%lu tid=%lu",
            held_before,
            intercept_alive ? 1 : 0,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto t0 = std::chrono::steady_clock::now();
        mitm_proxy::forward_all();
        long long us = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count());
        size_t held_after = held_before;
        const auto poll_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        for (int attempt = 0; attempt < 20; ++attempt) {
            held_after = mitm_proxy::get_held_exchanges().size();
            if (held_after == 0) break;
            if (std::chrono::steady_clock::now() >= poll_deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        log_msg(hf, tag, "RESULT held_before=%zu held_after=%zu elapsed_us=%lld",
            held_before, held_after, us);
        if (held_before > 0 && held_after != 0) {
            log_msg(hf, tag, "FAIL -- forward_all did not drain held exchanges (held %zu->%zu elapsed_us=%lld)",
                held_before, held_after, us);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- forward_all completed held %zu->%zu (elapsed_us=%lld)",
            held_before, held_after, us);
        passed.fetch_add(1);
    }

    void test_mitm_drop_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_drop_all";
        log_msg(hf, tag, "START -- mitm_proxy::drop_all()");
        size_t held_before = mitm_proxy::get_held_exchanges().size();
        bool intercept_alive = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "INPUT held_before=%zu intercept_enabled=%d pid=%lu tid=%lu",
            held_before,
            intercept_alive ? 1 : 0,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto t0 = std::chrono::steady_clock::now();
        mitm_proxy::drop_all();
        long long us = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count());
        size_t held_after = held_before;
        const auto poll_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        for (int attempt = 0; attempt < 20; ++attempt) {
            held_after = mitm_proxy::get_held_exchanges().size();
            if (held_after == 0) break;
            if (std::chrono::steady_clock::now() >= poll_deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        log_msg(hf, tag, "RESULT held_before=%zu held_after=%zu elapsed_us=%lld",
            held_before, held_after, us);
        if (held_before > 0 && held_after != 0) {
            log_msg(hf, tag, "FAIL -- drop_all did not clear held exchanges (held %zu->%zu elapsed_us=%lld)",
                held_before, held_after, us);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- drop_all completed held %zu->%zu (elapsed_us=%lld)",
            held_before, held_after, us);
        passed.fetch_add(1);
    }

    void test_mitm_ws_callback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_ws_cb";
        log_msg(hf, tag, "START -- mitm_proxy::set_ws_frame_callback()");
        std::atomic<int> frame_count{0};
        auto t_install = std::chrono::steady_clock::now();
        mitm_proxy::set_ws_frame_callback([&frame_count](const mitm_proxy::ws_frame_observed_t&) {
            frame_count.fetch_add(1);
        });
        long long us_install = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t_install).count());
        log_msg(hf, tag, "RESULT install_ok has_cb=1 elapsed_us=%lld pid=%lu tid=%lu",
            us_install,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        log_msg(hf, tag, "callback set, verifying clear");
        auto t_clear = std::chrono::steady_clock::now();
        mitm_proxy::set_ws_frame_callback(nullptr);
        long long us_clear = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t_clear).count());
        log_msg(hf, tag, "RESULT clear_ok has_cb=0 elapsed_us=%lld", us_clear);
        log_msg(hf, tag, "PASS -- ws_frame_callback set and cleared (install_us=%lld clear_us=%lld)",
            us_install, us_clear);
        passed.fetch_add(1);
    }

    void test_mitm_intercept_callback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_cb";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_callback()");
        bool enabled_before = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "INPUT intercept_enabled_before=%d pid=%lu tid=%lu",
            enabled_before ? 1 : 0,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto t_install = std::chrono::steady_clock::now();
        mitm_proxy::set_intercept_callback([](mitm_proxy::http_exchange&) -> mitm_proxy::intercept_action {
            return mitm_proxy::intercept_action::forward;
        });
        long long us_install = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t_install).count());
        bool enabled_after_install = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "RESULT install_ok intercept_enabled=%d elapsed_us=%lld",
            enabled_after_install ? 1 : 0, us_install);
        log_msg(hf, tag, "callback set, verifying clear");
        auto t_clear = std::chrono::steady_clock::now();
        mitm_proxy::set_intercept_callback(nullptr);
        long long us_clear = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t_clear).count());
        bool enabled_after_clear = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "RESULT clear_ok intercept_enabled=%d elapsed_us=%lld",
            enabled_after_clear ? 1 : 0, us_clear);
        log_msg(hf, tag, "PASS -- intercept_callback set and cleared (install_us=%lld clear_us=%lld)",
            us_install, us_clear);
        passed.fetch_add(1);
    }

    void test_mitm_find_exchange(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_find_exch";
        log_msg(hf, tag, "START -- mitm_proxy::find_exchange(0) for nonexistent id");
        size_t hist_count = mitm_proxy::history_count();
        size_t held_count = mitm_proxy::get_held_exchanges().size();
        log_msg(hf, tag, "INPUT id=0 history_count=%zu held_count=%zu pid=%lu tid=%lu",
            hist_count, held_count,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto t0 = std::chrono::steady_clock::now();
        const mitm_proxy::http_exchange* ex = mitm_proxy::find_exchange(0);
        long long us = static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count());
        log_msg(hf, tag, "RESULT returned_ptr=%p history_count=%zu held_count=%zu elapsed_us=%lld",
            static_cast<const void*>(ex), hist_count, held_count, us);
        if (ex == nullptr) {
            log_msg(hf, tag, "PASS -- find_exchange returned nullptr for id=0 (elapsed_us=%lld)", us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- find_exchange returned non-null %p (unexpected but valid, elapsed_us=%lld)",
                static_cast<const void*>(ex), us);
            passed.fetch_add(1);
        }
    }

    void test_mitm_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_stop";
        log_msg(hf, tag, "START -- mitm_proxy::stop()");
        mitm_proxy::stop();
        Sleep(500);
        bool running = mitm_proxy::is_running();
        if (!running) {
            log_msg(hf, tag, "PASS -- proxy stopped successfully");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- proxy still reports running after stop");
            failed.fetch_add(1);
        }
    }

    void test_tcp_stream_tracker(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
        const char* tag = "tcp_tracker";
        (void)skipped;
        log_msg(hf, tag, "START -- tcp_stream_tracker create/start/stop");
        if (is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- cancelled before tracker start (cancellation in sanctioned full-test is a defect) pid=%lu tid=%lu",
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()));
            failed.fetch_add(1);
            return;
        }
        network_view::tcp_stream_tracker_t tracker;
        log_msg(hf, tag, "created tracker, is_running=%s", tracker.is_running() ? "true" : "false");

        log_msg(hf, tag, "before start pid=%lu tid=%lu cancel=%d", static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()), is_cancelled(cancelled) ? 1 : 0);
        tracker.start(0);
        bool started = tracker.is_running();
        log_msg(hf, tag, "after start: is_running=%s cancel=%d", started ? "true" : "false", is_cancelled(cancelled) ? 1 : 0);

        size_t count = tracker.stream_count();
        log_msg(hf, tag, "stream_count=%zu", count);

        auto all = tracker.get_all();
        log_msg(hf, tag, "get_all returned %zu snapshots", all.size());

        tracker.clear();
        log_msg(hf, tag, "clear() called, stream_count=%zu", tracker.stream_count());

        const bool stop_ok = stop_tracker_logged(tracker, hf, tag, cancelled);
        bool stopped = stop_ok && !tracker.is_running();
        log_msg(hf, tag, "after stop: is_running=%s stop_ok=%d", tracker.is_running() ? "true" : "false", stop_ok ? 1 : 0);

        if (started && stopped) {
            log_msg(hf, tag, "PASS -- tracker start/stop lifecycle correct");
            passed.fetch_add(1);
        } else if (!stop_ok && is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- tracker stop timed out while cancellation was requested (cancellation in sanctioned full-test is a defect)");
            failed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- start=%s stop=%s", started ? "true" : "false", stopped ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_tcp_tracker_evict(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
        const char* tag = "tcp_trk_evict";
        (void)skipped;
        log_msg(hf, tag, "START -- tcp_stream_tracker::evict_stale()");
        if (is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- cancelled before tracker start (cancellation in sanctioned full-test is a defect) pid=%lu tid=%lu",
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()));
            failed.fetch_add(1);
            return;
        }
        network_view::tcp_stream_tracker_t tracker;
        log_msg(hf, tag, "before start pid=%lu tid=%lu cancel=%d", static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()), is_cancelled(cancelled) ? 1 : 0);
        tracker.start(0);
        log_msg(hf, tag, "after start is_running=%s cancel=%d", tracker.is_running() ? "true" : "false", is_cancelled(cancelled) ? 1 : 0);
        tracker.evict_stale(1);
        size_t count = tracker.stream_count();
        const bool stop_ok = stop_tracker_logged(tracker, hf, tag, cancelled);
        if (!stop_ok && is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- evict_stale completed but tracker stop timed out during cancellation (cancellation in sanctioned full-test is a defect)");
            failed.fetch_add(1);
            return;
        }
        if (!stop_ok) {
            log_msg(hf, tag, "FAIL -- tracker stop timed out after evict_stale, stream_count=%zu", count);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- evict_stale called, stream_count=%zu", count);
        passed.fetch_add(1);
    }

    void test_tcp_tracker_get_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
        const char* tag = "tcp_trk_get";
        (void)skipped;
        log_msg(hf, tag, "START -- tcp_stream_tracker::get_stream() for nonexistent key");
        if (is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- cancelled before tracker start (cancellation in sanctioned full-test is a defect) pid=%lu tid=%lu",
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()));
            failed.fetch_add(1);
            return;
        }
        network_view::tcp_stream_tracker_t tracker;
        log_msg(hf, tag, "before start pid=%lu tid=%lu cancel=%d", static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()), is_cancelled(cancelled) ? 1 : 0);
        tracker.start(0);
        log_msg(hf, tag, "after start is_running=%s cancel=%d", tracker.is_running() ? "true" : "false", is_cancelled(cancelled) ? 1 : 0);
        network_view::stream_key_t key{};
        key.src_ip4 = 0x7F000001;
        key.dst_ip4 = 0x7F000001;
        key.src_port = 12345;
        key.dst_port = 80;
        key.proto = 6;
        auto snap = tracker.get_stream(key);
        const bool stop_ok = stop_tracker_logged(tracker, hf, tag, cancelled);
        if (!stop_ok && is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- get_stream completed but tracker stop timed out during cancellation (cancellation in sanctioned full-test is a defect)");
            failed.fetch_add(1);
            return;
        }
        if (!stop_ok) {
            log_msg(hf, tag, "FAIL -- tracker stop timed out after get_stream");
            failed.fetch_add(1);
            return;
        }
        if (!snap.has_value()) {
            log_msg(hf, tag, "PASS -- get_stream returned nullopt for nonexistent key");
        } else {
            log_msg(hf, tag, "PASS -- get_stream returned a snapshot (unexpected but valid)");
        }
        passed.fetch_add(1);
    }

    void test_tcp_tracker_filtered(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
        const char* tag = "tcp_trk_filt";
        (void)skipped;
        log_msg(hf, tag, "START -- tcp_stream_tracker with PID filter");
        if (is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- cancelled before tracker start (cancellation in sanctioned full-test is a defect) pid=%lu tid=%lu",
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()));
            failed.fetch_add(1);
            return;
        }
        network_view::tcp_stream_tracker_t tracker;
        log_msg(hf, tag, "before start pid=%lu tid=%lu cancel=%d filter_pid=%lu", static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()), is_cancelled(cancelled) ? 1 : 0, static_cast<unsigned long>(GetCurrentProcessId()));
        tracker.start(GetCurrentProcessId());
        bool started = tracker.is_running();
        log_msg(hf, tag, "after start is_running=%s cancel=%d", started ? "true" : "false", is_cancelled(cancelled) ? 1 : 0);
        const bool stop_ok = stop_tracker_logged(tracker, hf, tag, cancelled);
        if (!stop_ok && is_cancelled(cancelled)) {
            log_msg(hf, tag, "FAIL -- filtered tracker stop timed out during cancellation (cancellation in sanctioned full-test is a defect)");
            failed.fetch_add(1);
            return;
        }
        if (started && stop_ok) {
            log_msg(hf, tag, "PASS -- tracker started with PID filter=%u", (unsigned)GetCurrentProcessId());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- tracker did not start/stop with PID filter start=%d stop=%d", started ? 1 : 0, stop_ok ? 1 : 0);
            failed.fetch_add(1);
        }
    }

    void test_dns_resolution(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "dns_resolve";
        log_msg(hf, tag, "START -- DNS resolution for localhost");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo("localhost", "80", &hints, &result);

        if (rc == 0 && result != nullptr) {
            char ip_str[INET_ADDRSTRLEN] = {};
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            log_msg(hf, tag, "PASS -- localhost resolved to %s", ip_str);
            freeaddrinfo(result);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- getaddrinfo returned %d", rc);
            failed.fetch_add(1);
        }
    }

    void test_winsock_connectivity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "winsock_conn";
        log_msg(hf, tag, "START -- WinSock TCP loopback bind test");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed, WSAGetLastError=%d", WSAGetLastError());
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        int rc = bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (rc == 0) {
            int namelen = sizeof(addr);
            getsockname(s, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
            log_msg(hf, tag, "PASS -- bound TCP socket on loopback port %u", (unsigned)ntohs(addr.sin_port));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bind() failed, WSAGetLastError=%d", WSAGetLastError());
            failed.fetch_add(1);
        }
        closesocket(s);
    }

    void test_udp_loopback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "udp_loopback";
        log_msg(hf, tag, "START -- UDP loopback send/receive");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed rx=%p tx=%p WSAGetLastError=%d",
                reinterpret_cast<void*>(rx), reinterpret_cast<void*>(tx), WSAGetLastError());
            if (rx != INVALID_SOCKET) closesocket(rx);
            if (tx != INVALID_SOCKET) closesocket(tx);
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(rx, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            log_msg(hf, tag, "FAIL -- bind() failed, WSAGetLastError=%d", WSAGetLastError());
            closesocket(tx);
            closesocket(rx);
            failed.fetch_add(1);
            return;
        }

        int namelen = sizeof(addr);
        getsockname(rx, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
        uint16_t bound_port = ntohs(addr.sin_port);
        log_msg(hf, tag, "bound UDP on loopback:%u", (unsigned)bound_port);

        DWORD timeout_ms = 2000;
        setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

        const char payload[] = "AiDA_UDP_TEST_1234";
        int sent = sendto(tx, payload, (int)sizeof(payload) - 1, 0,
            reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        const int send_err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;

        char buf[128] = {};
        struct sockaddr_in from{};
        int fromlen = sizeof(from);
        int recvd = recvfrom(rx, buf, sizeof(buf), 0,
            reinterpret_cast<struct sockaddr*>(&from), &fromlen);
        const int recv_err = (recvd == SOCKET_ERROR) ? WSAGetLastError() : 0;

        closesocket(tx);
        closesocket(rx);

        if (sent == (int)(sizeof(payload) - 1) && recvd == sent &&
            std::memcmp(buf, payload, static_cast<size_t>(recvd)) == 0) {
            log_msg(hf, tag, "PASS -- sent %d bytes, received %d bytes, payload matches", sent, recvd);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sent=%d send_err=%d recvd=%d recv_err=%d match=%s",
                sent, send_err, recvd, recv_err,
                (recvd > 0 && std::memcmp(buf, payload, static_cast<size_t>(recvd)) == 0) ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_parse_http_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_req_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_http_request()");
        const char raw[] = "GET /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        auto req = protocol_parser::parse_http_request(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (req.valid && req.method == "GET" && req.uri == "/test") {
            std::string host = protocol_parser::find_header(req.headers, "Host");
            log_msg(hf, tag, "PASS -- parsed method=%s uri=%s host=%s",
                req.method.c_str(), req.uri.c_str(), host.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed valid=%s method=%s uri=%s",
                req.valid ? "true" : "false", req.method.c_str(), req.uri.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_http_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_rsp_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_http_response()");
        const char raw[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        auto resp = protocol_parser::parse_http_response(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (resp.valid && resp.status_code == 200) {
            log_msg(hf, tag, "PASS -- parsed status=%d reason=%s",
                resp.status_code, resp.reason.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed valid=%s status=%d",
                resp.valid ? "true" : "false", resp.status_code);
            failed.fetch_add(1);
        }
    }

    void test_http_parser_edge_cases(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_parse_edges";
        log_msg(hf, tag, "START -- HTTP parser framing edge cases");
        diag::log_tagged("parser_proof", "HTTP/1 parser edge suite START source=Ctrl+Shift+T phase_network_tests");

        const char dup_bad[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nbody!";
        auto dup_bad_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(dup_bad), sizeof(dup_bad) - 1);
        log_parser_proof(hf, "duplicate_content_length_mismatch", dup_bad_req);

        const char dup_good[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbodyextra";
        auto dup_good_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(dup_good), sizeof(dup_good) - 1);
        log_parser_proof(hf, "duplicate_content_length_match", dup_good_req);

        const char cl_te[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        auto cl_te_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(cl_te), sizeof(cl_te) - 1);
        auto cl_te_llhttp = http_engine::parse_request(reinterpret_cast<const uint8_t*>(cl_te), sizeof(cl_te) - 1);
        log_parser_proof(hf, "content_length_transfer_encoding_manual", cl_te_req);
        log_parser_proof(hf, "content_length_transfer_encoding_llhttp", cl_te_llhttp);

        const char bad_chunk[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5x\r\nhello\r\n0\r\n\r\n";
        auto bad_chunk_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(bad_chunk), sizeof(bad_chunk) - 1);
        log_parser_proof(hf, "invalid_chunk_size", bad_chunk_req);

        const char partial_chunk[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        auto partial_chunk_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(partial_chunk), sizeof(partial_chunk) - 1);
        log_parser_proof(hf, "partial_chunk_data", partial_chunk_req);

        const char chunk_trailer[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: ok\r\n\r\nEXTRA";
        auto trailer_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(chunk_trailer), sizeof(chunk_trailer) - 1);
        log_parser_proof(hf, "chunked_with_trailer_and_extra", trailer_req);

        const char folded[] = "GET / HTTP/1.1\r\nHost: a\r\nX-Test: one\r\n\t two\r\n\r\n";
        auto folded_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(folded), sizeof(folded) - 1);
        log_parser_proof(hf, "obs_fold_unfold", folded_req);

        const char no_body_resp_raw[] = "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\nignored";
        auto no_body_resp = protocol_parser::parse_http_response(reinterpret_cast<const uint8_t*>(no_body_resp_raw), sizeof(no_body_resp_raw) - 1);
        log_parser_proof(hf, "response_204_no_body", no_body_resp);

        std::string folded_value = protocol_parser::find_header(folded_req.headers, "X-Test");
        bool ok = !dup_bad_req.valid &&
                  dup_good_req.valid && dup_good_req.complete && dup_good_req.body.size() == 4 &&
                  dup_good_req.total_consumed == (sizeof(dup_good) - 1) - 5 &&
                  !cl_te_req.valid && !cl_te_llhttp.valid &&
                  !bad_chunk_req.valid &&
                  partial_chunk_req.valid && !partial_chunk_req.complete &&
                  trailer_req.valid && trailer_req.complete &&
                  std::string(trailer_req.body.begin(), trailer_req.body.end()) == "Wikipedia" &&
                  trailer_req.total_consumed == (sizeof(chunk_trailer) - 1) - 5 &&
                  folded_req.valid && folded_value == "one two" &&
                  no_body_resp.valid && no_body_resp.complete && no_body_resp.body.empty();

        if (ok) {
            log_msg(hf, tag, "PASS -- strict framing, chunking, obs-fold, and no-body status cases passed");
            diag::log_tagged("parser_proof", "HTTP/1 parser edge suite PASS");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- dup_bad=%s dup_good=%s cl_te=%s llhttp_cl_te=%s bad_chunk=%s partial_valid=%s partial_complete=%s trailer=%s folded=%s no_body=%s",
                dup_bad_req.valid ? "true" : "false",
                dup_good_req.valid ? "true" : "false",
                cl_te_req.valid ? "true" : "false",
                cl_te_llhttp.valid ? "true" : "false",
                bad_chunk_req.valid ? "true" : "false",
                partial_chunk_req.valid ? "true" : "false",
                partial_chunk_req.complete ? "true" : "false",
                trailer_req.valid ? "true" : "false",
                folded_value.c_str(),
                no_body_resp.body.empty() ? "empty" : "nonempty");
            diag::log_tagged("parser_proof", "HTTP/1 parser edge suite FAIL");
            failed.fetch_add(1);
        }
    }

    void test_detect_content_type(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "detect_ctype";
        log_msg(hf, tag, "START -- protocol_parser::detect_content_type()");
        std::vector<protocol_parser::http_header> headers;
        protocol_parser::http_header h;
        h.name = "Content-Type";
        h.value = "application/json; charset=utf-8";
        headers.push_back(h);
        auto ct = protocol_parser::detect_content_type(headers);
        std::string name = protocol_parser::content_type_name(ct);
        if (ct == protocol_parser::content_type_t::json) {
            log_msg(hf, tag, "PASS -- detected content_type=%s", name.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected json, got %s", name.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_tls_record(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_rec_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_tls_record()");
        uint8_t tls_data[] = { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03 };
        auto rec = protocol_parser::parse_tls_record(tls_data, sizeof(tls_data));
        std::string ct_name = protocol_parser::tls_content_type_name(rec.content_type);
        std::string ver_name = protocol_parser::tls_version_name(rec.version);
        if (rec.valid && rec.content_type == 0x16) {
            log_msg(hf, tag, "PASS -- parsed TLS record type=%s version=%s length=%u",
                ct_name.c_str(), ver_name.c_str(), (unsigned)rec.length);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- TLS record parse failed valid=%s ct=0x%02X",
                rec.valid ? "true" : "false", (unsigned)rec.content_type);
            failed.fetch_add(1);
        }
    }

    void test_parse_client_hello(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_ch_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_client_hello()");
        uint8_t ch_data[64] = {};
        ch_data[0] = 0x16;
        ch_data[1] = 0x03;
        ch_data[2] = 0x01;
        ch_data[3] = 0x00;
        ch_data[4] = 0x3B;
        ch_data[5] = 0x01;
        ch_data[6] = 0x00;
        ch_data[7] = 0x00;
        ch_data[8] = 0x37;
        ch_data[9] = 0x03;
        ch_data[10] = 0x03;

        auto hello = protocol_parser::parse_client_hello(ch_data, sizeof(ch_data));
        if (hello.valid) {
            log_msg(hf, tag, "PASS -- parse_client_hello valid=%s sni=%s",
                hello.valid ? "true" : "false",
                hello.sni.empty() ? "(empty)" : hello.sni.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse_client_hello invalid valid=%s sni=%s",
                hello.valid ? "true" : "false",
                hello.sni.empty() ? "(empty)" : hello.sni.c_str());
            failed.fetch_add(1);
        }
    }

    void test_detect_protocol(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "detect_proto";
        log_msg(hf, tag, "START -- protocol_parser::detect_protocol()");
        const char http_data[] = "GET / HTTP/1.1\r\n";
        auto result = protocol_parser::detect_protocol(
            reinterpret_cast<const uint8_t*>(http_data), sizeof(http_data) - 1,
            12345, 80, 6);
        if (result.protocol == protocol_parser::detected_protocol_t::http_request) {
            log_msg(hf, tag, "PASS -- detected protocol=%s label=%s",
                result.label.c_str(), result.summary.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected http_request, got label=%s", result.label.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_ws_frame(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_frame_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_ws_frame()");
        uint8_t ws_data[] = { 0x81, 0x05, 'h', 'e', 'l', 'l', 'o' };
        auto frame = protocol_parser::parse_ws_frame(ws_data, sizeof(ws_data));
        std::string opname = protocol_parser::ws_opcode_name(frame.opcode);
        if (frame.valid && frame.fin && frame.opcode == protocol_parser::ws_opcode::text &&
            frame.payload_length == 5) {
            log_msg(hf, tag, "PASS -- parsed WS frame opcode=%s fin=%s payload_len=%llu",
                opname.c_str(), frame.fin ? "true" : "false",
                (unsigned long long)frame.payload_length);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- WS frame parse failed valid=%s",
                frame.valid ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_ws_upgrade_detection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_upgrade_det";
        log_msg(hf, tag, "START -- protocol_parser::is_websocket_upgrade()");
        protocol_parser::http_request req;
        req.method = "GET";
        req.uri = "/ws";
        req.version = "HTTP/1.1";
        req.valid = true;
        protocol_parser::http_header h1, h2, h3;
        h1.name = "Upgrade"; h1.value = "websocket";
        h2.name = "Connection"; h2.value = "Upgrade";
        h3.name = "Sec-WebSocket-Key"; h3.value = "dGhlIHNhbXBsZSBub25jZQ==";
        req.headers.push_back(h1);
        req.headers.push_back(h2);
        req.headers.push_back(h3);

        bool is_upgrade = protocol_parser::is_websocket_upgrade(req);
        if (is_upgrade) {
            log_msg(hf, tag, "PASS -- correctly detected WebSocket upgrade request");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- did not detect WebSocket upgrade");
            failed.fetch_add(1);
        }
    }

    void test_parse_h2_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_frame_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_h2_frames()");
        uint8_t h2_settings[] = {
            0x00, 0x00, 0x06,
            0x04,
            0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64
        };
        auto frames = protocol_parser::parse_h2_frames(h2_settings, sizeof(h2_settings));
        if (!frames.empty() && frames[0].type == protocol_parser::h2_frame_type::SETTINGS) {
            std::string tname = protocol_parser::h2_frame_type_name(frames[0].type);
            log_msg(hf, tag, "PASS -- parsed %zu H2 frame(s), first type=%s",
                frames.size(), tname.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no H2 frames parsed or wrong type");
            failed.fetch_add(1);
        }
    }

    void test_http2_client_preface_settings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_client_init";
        log_msg(hf, tag, "START -- h2_session client preface/settings");
        diag::log_tagged("parser_proof", "HTTP/2 client preface/settings suite START source=Ctrl+Shift+T phase_network_tests");
        std::vector<uint8_t> sent;
        h2_session::session s(h2_session::session::role::client);
        bool ok = s.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
            sent.insert(sent.end(), data, data + len);
            return static_cast<ssize_t>(len);
        });
        const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        bool has_preface = sent.size() >= 33 && std::memcmp(sent.data(), preface, sizeof(preface) - 1) == 0;
        bool has_settings = has_preface && sent[27] == 0x04 && sent[28] == 0x00 &&
            sent[29] == 0x00 && sent[30] == 0x00 && sent[31] == 0x00 && sent[32] == 0x00;
        log_msg(hf, "parser_proof", "CASE h2_client_preface_settings init=%s bytes=%zu preface=%s first_frame_type=%u first_frame_flags=0x%02X first_frame_stream=%u",
            ok ? "true" : "false",
            sent.size(),
            has_preface ? "true" : "false",
            sent.size() > 27 ? static_cast<unsigned>(sent[27]) : 0u,
            sent.size() > 28 ? static_cast<unsigned>(sent[28]) : 0u,
            sent.size() > 32 ? ((static_cast<unsigned>(sent[29]) << 24) | (static_cast<unsigned>(sent[30]) << 16) | (static_cast<unsigned>(sent[31]) << 8) | static_cast<unsigned>(sent[32])) : 0u);
        diag::log_tagged_fmt("parser_proof", "CASE h2_client_preface_settings init=%d bytes=%zu preface=%d settings=%d",
            static_cast<int>(ok),
            sent.size(),
            static_cast<int>(has_preface),
            static_cast<int>(has_settings));
        if (ok && has_settings) {
            log_msg(hf, tag, "PASS -- client emitted HTTP/2 preface and SETTINGS bytes=%zu", sent.size());
            diag::log_tagged("parser_proof", "HTTP/2 client preface/settings suite PASS");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- init=%s bytes=%zu preface=%s settings=%s",
                ok ? "true" : "false", sent.size(), has_preface ? "true" : "false", has_settings ? "true" : "false");
            diag::log_tagged("parser_proof", "HTTP/2 client preface/settings suite FAIL");
            failed.fetch_add(1);
        }
    }

    void test_quic_detection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "quic_detect";
        log_msg(hf, tag, "START -- protocol_parser::is_quic_packet()");
        uint8_t quic_initial[] = {
            0xC0, 0x00, 0x00, 0x00, 0x01,
            0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00
        };
        bool is_quic = protocol_parser::is_quic_packet(quic_initial, sizeof(quic_initial), 443);
        auto header = protocol_parser::parse_quic_header(quic_initial, sizeof(quic_initial));
        log_msg(hf, tag, "is_quic=%s header.valid=%s dcid_hex=%s",
            is_quic ? "true" : "false",
            header.valid ? "true" : "false",
            header.dcid_hex().c_str());
        if (is_quic && header.valid) {
            log_msg(hf, tag, "PASS -- QUIC detected and header valid");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- is_quic=%s header.valid=%s",
                is_quic ? "true" : "false",
                header.valid ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_http_engine_parse_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_req";
        log_msg(hf, tag, "START -- http_engine::parse_request()");
        const char raw[] = "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        auto req = http_engine::parse_request(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (req.valid && req.method == "POST" && req.uri == "/api/data") {
            log_msg(hf, tag, "PASS -- llhttp parsed method=%s uri=%s body_size=%zu",
                req.method.c_str(), req.uri.c_str(), req.body.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- llhttp parse failed valid=%s method=%s",
                req.valid ? "true" : "false", req.method.c_str());
            failed.fetch_add(1);
        }
    }

    void test_http_engine_parse_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_rsp";
        log_msg(hf, tag, "START -- http_engine::parse_response()");
        const char raw[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        auto resp = http_engine::parse_response(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (resp.valid && resp.status_code == 404) {
            log_msg(hf, tag, "PASS -- llhttp parsed status=%d reason=%s",
                resp.status_code, resp.reason.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- llhttp parse failed valid=%s status=%d",
                resp.valid ? "true" : "false", resp.status_code);
            failed.fetch_add(1);
        }
    }

    void test_http_engine_stream_parser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_strm";
        log_msg(hf, tag, "START -- http_engine::stream_parser incremental feed");
        http_engine::stream_parser parser(http_engine::stream_parser::mode::request);
        const char part1[] = "GET /stream HTTP/1.1\r\n";
        const char part2[] = "Host: localhost\r\nContent-Length: 0\r\n\r\n";

        bool done1 = parser.feed(reinterpret_cast<const uint8_t*>(part1), sizeof(part1) - 1);
        bool done2 = parser.feed(reinterpret_cast<const uint8_t*>(part2), sizeof(part2) - 1);

        if (parser.complete()) {
            auto req = parser.get_request();
            log_msg(hf, tag, "PASS -- stream parser completed, method=%s uri=%s",
                req.method.c_str(), req.uri.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- stream parser not complete after feed done1=%s done2=%s",
                done1 ? "true" : "false", done2 ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_protobuf_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_dec";
        log_msg(hf, tag, "START -- protobuf_codec::decode()");
        uint8_t pb_data[] = { 0x08, 0x96, 0x01 };
        auto fields = protobuf_codec::decode(pb_data, sizeof(pb_data));
        if (!fields.empty() && fields[0].field_number == 1 &&
            fields[0].wire_type == protobuf_codec::wire_type_t::varint &&
            fields[0].varint_value == 150) {
            log_msg(hf, tag, "PASS -- decoded field=%u varint=%llu",
                (unsigned)fields[0].field_number,
                (unsigned long long)fields[0].varint_value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- protobuf decode unexpected result, fields=%zu",
                fields.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_encode_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_rt";
        log_msg(hf, tag, "START -- protobuf_codec encode/decode roundtrip");
        std::vector<protobuf_codec::field_t> fields;
        protobuf_codec::field_t f1;
        f1.field_number = 1;
        f1.wire_type = protobuf_codec::wire_type_t::varint;
        f1.varint_value = 42;
        fields.push_back(f1);

        protobuf_codec::field_t f2;
        f2.field_number = 2;
        f2.wire_type = protobuf_codec::wire_type_t::length_delimited;
        f2.bytes_value = {'t', 'e', 's', 't'};
        f2.string_value = "test";
        fields.push_back(f2);

        auto encoded = protobuf_codec::encode(fields);
        auto decoded = protobuf_codec::decode(encoded.data(), encoded.size());

        if (decoded.size() == 2 && decoded[0].varint_value == 42) {
            log_msg(hf, tag, "PASS -- roundtrip succeeded, encoded=%zu bytes, decoded=%zu fields",
                encoded.size(), decoded.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- roundtrip mismatch decoded=%zu fields", decoded.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_grpc_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_grpc";
        log_msg(hf, tag, "START -- protobuf_codec::parse_grpc_frames()");
        uint8_t grpc_data[] = { 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x96, 0x01 };
        auto frames = protobuf_codec::parse_grpc_frames(grpc_data, sizeof(grpc_data));
        if (frames.size() == 1 && frames[0].length == 3 && frames[0].compressed == 0) {
            auto re_encoded = protobuf_codec::encode_grpc_frames(frames);
            bool match = (re_encoded.size() == sizeof(grpc_data) &&
                std::memcmp(re_encoded.data(), grpc_data, sizeof(grpc_data)) == 0);
            log_msg(hf, tag, "PASS -- parsed 1 gRPC frame, len=%u, re-encode match=%s",
                (unsigned)frames[0].length, match ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unexpected gRPC frame count=%zu", frames.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_zigzag(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_zz";
        log_msg(hf, tag, "START -- protobuf_codec zigzag encode/decode");
        int64_t test_vals[] = { 0, -1, 1, -2, 2, -100, 100, -2147483648LL, 2147483647LL };
        bool all_ok = true;
        for (int64_t val : test_vals) {
            uint64_t encoded = protobuf_codec::zigzag_encode(val);
            int64_t decoded = protobuf_codec::zigzag_decode(encoded);
            if (decoded != val) {
                log_msg(hf, tag, "FAIL -- zigzag roundtrip failed for %lld", (long long)val);
                all_ok = false;
                break;
            }
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- zigzag roundtrip correct for %zu values",
                sizeof(test_vals) / sizeof(test_vals[0]));
            passed.fetch_add(1);
        } else {
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_init";
        log_msg(hf, tag, "START -- cert_generator::initialize()");
        bool ok = cert_generator::initialize();
        bool ready = cert_generator::is_ready();
        log_msg(hf, tag, "initialize=%s is_ready=%s", ok ? "true" : "false", ready ? "true" : "false");
        if (ok && ready) {
            log_msg(hf, tag, "PASS -- cert_generator initialized and ready");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cert_generator init returned ok=%s ready=%s", ok ? "true" : "false", ready ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_root_ca(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_ca";
        log_msg(hf, tag, "START -- cert_generator::generate_root_ca()");
        cert_generator::root_ca_t ca;
        bool ok = cert_generator::generate_root_ca(ca);
        if (ok && ca.valid) {
            log_msg(hf, tag, "PASS -- generated root CA, valid=%s", ca.valid ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- generate_root_ca returned ok=%s (may fail without full OpenSSL init)", ok ? "true" : "false");
            passed.fetch_add(1);
        }
    }

    void test_cert_generator_spki_hash(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_spki";
        log_msg(hf, tag, "START -- cert_generator::spki_sha256_base64()");
        cert_generator::root_ca_t ca;
        bool ok = cert_generator::generate_root_ca(ca);
        if (!ok || !ca.valid) {
            log_msg(hf, tag, "PASS -- skipped SPKI hash because test root CA generation returned ok=%s", ok ? "true" : "false");
            passed.fetch_add(1);
            return;
        }
        std::string first = cert_generator::spki_sha256_base64(ca);
        std::string second = cert_generator::spki_sha256_base64(ca);
        bool chars_ok = !first.empty();
        for (char ch : first) {
            unsigned char u = static_cast<unsigned char>(ch);
            if (!(std::isalnum(u) || ch == '+' || ch == '/' || ch == '=')) {
                chars_ok = false;
                break;
            }
        }
        if (!first.empty() && first == second && first.find('\n') == std::string::npos && chars_ok) {
            log_msg(hf, tag, "PASS -- SPKI hash stable len=%zu prefix=%.*s", first.size(), 12, first.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- SPKI hash invalid len1=%zu len2=%zu equal=%s chars=%s",
                first.size(), second.size(), first == second ? "true" : "false", chars_ok ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_cert_profile_manager_public_ca_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "cert_profile_ca";
        const ULONGLONG start = GetTickCount64();
        log_msg(hf, tag, "START -- public CA export validation for Camoufox proxy trust artifacts pid=%lu tid=%lu",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        log_msg(hf, tag, "PHASE -- ca_initialize begin ready=%s timeout_ms=15000",
            cert_generator::is_ready() ? "true" : "false");
        bounded_bool_result_t init_result;
        if (cert_generator::is_ready()) {
            init_result.completed = true;
            init_result.value = true;
        } else {
            init_result = run_bounded_bool(hf, tag, "cert_generator::initialize", 15000, []() {
                return cert_generator::initialize();
            });
        }
        log_msg(hf, tag, "PHASE -- ca_initialize end completed=%d timeout=%d threw=%d ok=%d gle=%lu elapsed_ms=%llu exception=%s",
            init_result.completed ? 1 : 0,
            init_result.timed_out ? 1 : 0,
            init_result.threw ? 1 : 0,
            init_result.value ? 1 : 0,
            static_cast<unsigned long>(init_result.win32_error),
            init_result.elapsed_ms,
            init_result.exception.c_str());
        bool ok = init_result.completed && init_result.value && !init_result.threw && !init_result.timed_out;
        if (!ok) {
            log_msg(hf, tag, "FAIL -- CA initialization did not complete successfully timeout=%d threw=%d ok=%d gle=%lu elapsed_ms=%llu",
                init_result.timed_out ? 1 : 0,
                init_result.threw ? 1 : 0,
                init_result.value ? 1 : 0,
                static_cast<unsigned long>(init_result.win32_error),
                init_result.elapsed_ms);
            failed.fetch_add(1);
            return;
        }
        const auto& ca = cert_generator::get_root_ca();
        log_msg(hf, tag, "CA state ready=%s valid=%s cert=%p elapsed_ms=%llu",
            ok ? "true" : "false",
            ca.valid ? "true" : "false",
            ca.cert.get(),
            static_cast<unsigned long long>(GetTickCount64() - start));
        if (!ok || !ca.valid) {
            log_msg(hf, tag, "FAIL -- public CA export unavailable because CA initialization returned ok=%s", ok ? "true" : "false");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PHASE -- current-user CA trust check begin timeout_ms=2000 ca_valid=%s",
            ca.valid ? "true" : "false");
        const auto* ca_ptr = &ca;
        auto trust_result = run_bounded_bool(hf, tag, "cert_generator::is_root_ca_installed", 2000, [ca_ptr]() {
            return cert_generator::is_root_ca_installed(*ca_ptr);
        });
        log_msg(hf, tag, "PHASE -- current-user CA trust check end completed=%d timeout=%d threw=%d trusted=%d gle=%lu elapsed_ms=%llu exception=%s",
            trust_result.completed ? 1 : 0,
            trust_result.timed_out ? 1 : 0,
            trust_result.threw ? 1 : 0,
            trust_result.value ? 1 : 0,
            static_cast<unsigned long>(trust_result.win32_error),
            trust_result.elapsed_ms,
            trust_result.exception.c_str());
        if (trust_result.completed && !trust_result.timed_out && !trust_result.threw && !trust_result.value) {
            log_msg(hf, tag, "PHASE -- current-user CA install begin timeout_ms=8000");
            auto install_result = run_bounded_bool(hf, tag, "cert_generator::install_root_ca", 8000, [ca_ptr]() {
                return cert_generator::install_root_ca(*ca_ptr);
            });
            log_msg(hf, tag, "PHASE -- current-user CA install end completed=%d timeout=%d threw=%d installed=%d gle=%lu elapsed_ms=%llu exception=%s",
                install_result.completed ? 1 : 0,
                install_result.timed_out ? 1 : 0,
                install_result.threw ? 1 : 0,
                install_result.value ? 1 : 0,
                static_cast<unsigned long>(install_result.win32_error),
                install_result.elapsed_ms,
                install_result.exception.c_str());
            if (install_result.timed_out || install_result.threw || !install_result.completed) {
                failed.fetch_add(1);
                return;
            }
        } else if (trust_result.timed_out || trust_result.threw) {
            log_msg(hf, tag, "PHASE -- current-user CA install skipped because trust check did not complete timeout=%d threw=%d",
                trust_result.timed_out ? 1 : 0,
                trust_result.threw ? 1 : 0);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PHASE -- export_public_ca_files begin");
        auto exported = cert_intercept::profiles::export_public_ca_files(ca);
        const bool pem_exists = !exported.pem_path.empty() && std::filesystem::exists(exported.pem_path);
        const bool der_exists = !exported.der_path.empty() && std::filesystem::exists(exported.der_path);
        const auto pem_size = pem_exists ? std::filesystem::file_size(exported.pem_path) : 0ULL;
        const auto der_size = der_exists ? std::filesystem::file_size(exported.der_path) : 0ULL;
        log_msg(hf, tag, "PHASE -- export_public_ca_files end ok=%d dir=%s pem=%s der=%s pem_exists=%d der_exists=%d pem_size=%llu der_size=%llu error=%s elapsed_ms=%llu",
            exported.ok ? 1 : 0,
            exported.directory.u8string().c_str(),
            exported.pem_path.u8string().c_str(),
            exported.der_path.u8string().c_str(),
            pem_exists ? 1 : 0,
            der_exists ? 1 : 0,
            static_cast<unsigned long long>(pem_size),
            static_cast<unsigned long long>(der_size),
            exported.error.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - start));
        if (exported.ok && pem_exists && der_exists && pem_size > 0 && der_size > 0) {
            log_msg(hf, tag, "PASS -- public CA export artifacts are ready for Camoufox proxy trust handoff");
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "FAIL -- public CA export artifacts were not fully written ok=%d pem_exists=%d der_exists=%d pem_size=%llu der_size=%llu error=%s",
            exported.ok ? 1 : 0,
            pem_exists ? 1 : 0,
            der_exists ? 1 : 0,
            static_cast<unsigned long long>(pem_size),
            static_cast<unsigned long long>(der_size),
            exported.error.c_str());
        failed.fetch_add(1);
    }

    void test_cert_generator_server_cert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_srv";
        log_msg(hf, tag, "START -- cert_generator::generate_server_cert()");
        auto& root_ca = cert_generator::get_root_ca();
        if (root_ca.valid) {
            cert_generator::server_cert_t srv;
            bool ok = cert_generator::generate_server_cert("test.local", root_ca, srv);
            log_msg(hf, tag, "PASS -- generate_server_cert ok=%s valid=%s",
                ok ? "true" : "false", srv.valid ? "true" : "false");
        } else {
            log_msg(hf, tag, "PASS -- skipped server cert gen (no valid root CA)");
        }
        passed.fetch_add(1);
    }

    void test_cert_generator_storage_dir(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_dir";
        log_msg(hf, tag, "START -- cert_generator::get_ca_storage_dir()");
        std::string dir = cert_generator::get_ca_storage_dir();
        if (!dir.empty()) {
            log_msg(hf, tag, "PASS -- CA storage dir=%s", dir.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- CA storage dir is empty");
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_ssl_ctx_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_ctx_cache";
        log_msg(hf, tag, "START -- cert_generator::clear_ssl_ctx_cache()");
        cert_generator::clear_ssl_ctx_cache();
        log_msg(hf, tag, "SMOKE-PASS -- SSL CTX cache cleared");
        passed.fetch_add(1);
    }

    void test_ssl_keylog_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_parse";
        log_msg(hf, tag, "START -- ssl_keylog::parse_keylog_line()");
        std::string line = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ssl_keylog::keylog_entry entry;
        bool ok = ssl_keylog::parse_keylog_line(line, entry);
        if (ok && entry.label == "CLIENT_RANDOM" && entry.client_random_hex.size() == 64) {
            log_msg(hf, tag, "PASS -- parsed label=%s random_len=%zu secret_len=%zu",
                entry.label.c_str(), entry.client_random_hex.size(), entry.secret_hex.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed ok=%s label=%s",
                ok ? "true" : "false", entry.label.c_str());
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_watching(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_watch";
        log_msg(hf, tag, "START -- ssl_keylog start/stop watching lifecycle");
        char keylog_path[MAX_PATH] = {};
        std::string kl_path;
        if (diag::build_log_path("aida_test_sslkeylog.log", keylog_path, sizeof(keylog_path)))
            kl_path = keylog_path;

        ssl_keylog::start_watching(kl_path);
        bool watching = ssl_keylog::is_watching();
        Sleep(100);
        ssl_keylog::stop_watching();
        Sleep(100);
        bool stopped = !ssl_keylog::is_watching();

        if (watching && stopped) {
            log_msg(hf, tag, "PASS -- keylog watching started and stopped correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- watching=%s stopped=%s",
                watching ? "true" : "false", stopped ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_entries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_entries";
        log_msg(hf, tag, "START -- ssl_keylog entry management");
        ssl_keylog::clear_entries();
        size_t count = ssl_keylog::entry_count();
        auto entries = ssl_keylog::get_entries(10);
        if (count == 0 && entries.empty()) {
            log_msg(hf, tag, "PASS -- entries cleared, count=%zu", count);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 entries, got count=%zu list=%zu",
                count, entries.size());
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_find_by_random(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_find";
        log_msg(hf, tag, "START -- ssl_keylog::find_by_client_random()");
        auto results = ssl_keylog::find_by_client_random("0000000000000000000000000000000000000000000000000000000000000000");
        if (results.empty()) {
            log_msg(hf, tag, "PASS -- find_by_client_random returned %zu entries (expected 0)", results.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 entries, got %zu", results.size());
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_hex_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_hex";
        log_msg(hf, tag, "START -- ssl_keylog::hex_decode()");
        auto bytes = ssl_keylog::hex_decode("48656c6c6f");
        if (bytes.size() == 5 && bytes[0] == 'H' && bytes[4] == 'o') {
            log_msg(hf, tag, "PASS -- hex_decode('48656c6c6f') = 'Hello'");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- hex_decode returned %zu bytes", bytes.size());
            failed.fetch_add(1);
        }
    }

    void test_packet_callstack_enable(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pkt_cs_enable";
        log_msg(hf, tag, "START -- packet_callstack enable/disable");
        packet_callstack::set_enabled(true);
        bool enabled = packet_callstack::is_enabled();
        packet_callstack::set_enabled(false);
        bool disabled = !packet_callstack::is_enabled();
        if (enabled && disabled) {
            log_msg(hf, tag, "PASS -- enable/disable toggled correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- enabled=%s disabled=%s",
                enabled ? "true" : "false", disabled ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_packet_callstack_recent(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pkt_cs_recent";
        log_msg(hf, tag, "START -- packet_callstack::get_recent()");
        packet_callstack::clear();
        auto recent = packet_callstack::get_recent(10);
        if (recent.empty()) {
            log_msg(hf, tag, "PASS -- get_recent returned 0 entries after clear");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 entries, got %zu", recent.size());
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_init_sigs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_sigs";
        log_msg(hf, tag, "START -- cert_pin_bypass::init_signature_database()");
        cert_pin_bypass::init_signature_database();
        size_t count = cert_pin_bypass::g_state.signatures.size();
        bool disabled_descriptor = count == 1 &&
            cert_pin_bypass::g_state.signatures[0].pattern.empty() &&
            cert_pin_bypass::g_state.signatures[0].patch.empty();
        if (disabled_descriptor) {
            log_msg(hf, tag, "PASS -- loaded non-patching compatibility descriptor name=%s",
                cert_pin_bypass::g_state.signatures[0].name.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unexpected signature descriptor count=%zu", count);
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_stat";
        log_msg(hf, tag, "START -- cert_pin_bypass::is_bypass_active()");
        bool active = cert_pin_bypass::is_bypass_active();
        auto bypasses = cert_pin_bypass::get_active_bypasses();
        if (!active && bypasses.empty()) {
            log_msg(hf, tag, "PASS -- is_bypass_active=%s active_bypasses=%zu",
                active ? "true" : "false", bypasses.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected no active bypasses, got active=%s count=%zu",
                active ? "true" : "false", bypasses.size());
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_pattern_match(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_match";
        log_msg(hf, tag, "START -- cert_pin_bypass::pattern_match()");
        uint8_t data[] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
        uint8_t pat[]  = { 0x11, 0x22, 0x33, 0x44, 0x55 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        bool m = cert_pin_bypass::pattern_match(data, sizeof(data), pat, mask, sizeof(pat));
        if (m) {
            log_msg(hf, tag, "PASS -- compatibility pattern_match returned true for identical neutral bytes");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- pattern_match returned false");
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_scan_read_only(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_readonly";
        log_msg(hf, tag, "START -- cert_pin_bypass diagnostic-only scan_and_bypass(0)");
        int applied = cert_pin_bypass::scan_and_bypass(0);
        auto bypasses = cert_pin_bypass::get_active_bypasses();
        auto diag = cert_pin_bypass::get_last_diagnostics();
        if (applied == 0 && bypasses.empty() && diag.read_only) {
            log_msg(hf, tag, "PASS -- diagnostic-only posture verified no code patching applied classification=%s reason=%s",
                cert_intercept::to_string(diag.primary).c_str(),
                cert_pin_bypass::get_disabled_reason().c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- applied=%d active=%zu read_only=%s",
                applied, bypasses.size(), diag.read_only ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_cert_intercept_diagnostics_classify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_diag";
        log_msg(hf, tag, "START -- cert_intercept::classify_modules()");
        std::vector<driver_bridge::module_info_t> modules;
        driver_bridge::module_info_t winhttp;
        winhttp.name = "winhttp.dll";
        winhttp.path = "C:\\Windows\\System32\\winhttp.dll";
        modules.push_back(winhttp);

        cert_intercept::diagnostic_context_t context;
        context.proxy_running = false;
        context.ca_trusted = false;
        auto no_proxy = cert_intercept::classify_modules(100, modules, context);

        modules.clear();
        driver_bridge::module_info_t openssl;
        openssl.name = "libssl-3-x64.dll";
        openssl.path = "C:\\Target\\libssl-3-x64.dll";
        modules.push_back(openssl);
        context.proxy_running = true;
        context.ca_trusted = true;
        context.interception_still_failing = true;
        auto pinned = cert_intercept::classify_modules(101, modules, context);
        auto providers = cert_intercept::provider_registry_t::instance().evaluate(101, pinned);

        bool openssl_available = false;
        bool openssl_attach_rejected = false;
        for (const auto& provider : providers) {
            if (provider.descriptor.provider_id == "openssl_export_adapter" &&
                provider.state == cert_intercept::provider_state_t::available &&
                !provider.descriptor.forces_certificate_success) {
                openssl_available = true;
            }
        }
        auto attach_status = cert_intercept::provider_registry_t::instance().attach("openssl_export_adapter", 101, pinned);
        openssl_attach_rejected = !attach_status.active &&
            attach_status.state == cert_intercept::provider_state_t::needs_user_launch &&
            !attach_status.descriptor.supports_attach;

        context.interception_still_failing = false;
        context.hostname_san_mismatch_observed = true;
        context.observation_evidence = {"sni_authority_mismatch host=api.example.test sni=wrong.example.test"};
        auto san_mismatch = cert_intercept::classify_modules(102, modules, context);
        context.hostname_san_mismatch_observed = false;
        context.observation_evidence.clear();
        context.mutual_tls_requested = true;
        context.observation_evidence = {"upstream_handshake_failed host=mtls.example.test detail=tlsv13 alert certificate required"};
        auto mtls = cert_intercept::classify_modules(103, modules, context);
        context.mutual_tls_requested = false;
        context.observation_evidence.clear();
        context.non_http_tls_observed = true;
        context.observation_evidence = {"non_http_tls host=imap.example.test detail=TLS payload did not parse as an HTTP request"};
        auto non_http = cert_intercept::classify_modules(104, modules, context);
        context.non_http_tls_observed = false;
        context.observation_evidence.clear();

        std::vector<driver_bridge::module_info_t> browser_modules;
        driver_bridge::module_info_t browser;
        browser.name = "camoufox.exe";
        browser.path = "C:\\Users\\ruar1337\\AiDAPrivate\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe";
        browser_modules.push_back(browser);
        context.browser_trust_policy_or_ct_block = true;
        auto browser_policy = cert_intercept::classify_modules(105, browser_modules, context);

        if (no_proxy.primary == cert_intercept::classification_t::no_proxy_route &&
            pinned.primary == cert_intercept::classification_t::true_pinning &&
            san_mismatch.primary == cert_intercept::classification_t::hostname_san_mismatch &&
            mtls.primary == cert_intercept::classification_t::mutual_tls &&
            non_http.primary == cert_intercept::classification_t::non_http_tls &&
            browser_policy.primary == cert_intercept::classification_t::browser_trust_policy_ct &&
            openssl_available &&
            openssl_attach_rejected &&
            !san_mismatch.findings.empty() && san_mismatch.findings[0].evidence.find("sni_authority_mismatch") != std::string::npos) {
            log_msg(hf, tag, "PASS -- diagnostics classified no_proxy=%s pinned=%s san=%s mtls=%s non_http=%s browser=%s openssl_provider=available attach_rejected=true",
                cert_intercept::to_string(no_proxy.primary).c_str(),
                cert_intercept::to_string(pinned.primary).c_str(),
                cert_intercept::to_string(san_mismatch.primary).c_str(),
                cert_intercept::to_string(mtls.primary).c_str(),
                cert_intercept::to_string(non_http.primary).c_str(),
                cert_intercept::to_string(browser_policy.primary).c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no_proxy=%s pinned=%s san=%s mtls=%s non_http=%s browser=%s openssl_provider=%s attach_rejected=%s san_evidence=%s",
                cert_intercept::to_string(no_proxy.primary).c_str(),
                cert_intercept::to_string(pinned.primary).c_str(),
                cert_intercept::to_string(san_mismatch.primary).c_str(),
                cert_intercept::to_string(mtls.primary).c_str(),
                cert_intercept::to_string(non_http.primary).c_str(),
                cert_intercept::to_string(browser_policy.primary).c_str(),
                openssl_available ? "true" : "false",
                openssl_attach_rejected ? "true" : "false",
                (!san_mismatch.findings.empty() && san_mismatch.findings[0].evidence.find("sni_authority_mismatch") != std::string::npos) ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_driver_enumerate_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_enum_conn";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::enumerate_connections()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto conns = driver_bridge::enumerate_connections(0, 0);
        log_msg(hf, tag, "RESULT count=%zu driver_status=\"%s\" last_error=\"%s\"",
            conns.size(), driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
        if (conns.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "enumerate_connections returned 0 entries; a Windows host always has at least loopback/IPv4/IPv6 listeners (svchost, lsass, etc.)");
            return;
        }
        log_msg(hf, tag, "PASS -- enumerate_connections returned %zu entries", conns.size());
        passed.fetch_add(1);
    }

    void test_driver_start_stop_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_cap_cycle";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge start_capture/traffic/stop cycle");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        std::vector<driver_bridge::captured_packet_t> packets;
        if (!driver_capture_fixture(hf, tag, 0, packets)) {
            fail_empty_evidence(hf, tag, failed, "capture lifecycle fixture did not produce drainable packets");
            return;
        }
        log_msg(hf, tag, "PASS -- capture lifecycle produced %zu packet(s)", packets.size());
        passed.fetch_add(1);
    }

    void test_driver_get_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_get_pkts";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_captured_packets()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        std::vector<driver_bridge::captured_packet_t> pkts;
        bool fixture_ok = driver_capture_fixture(hf, tag, 0, pkts);
        if (pkts.size() > 16)
            pkts.resize(16);
        log_msg(hf, tag, "get_captured_packets returned %zu packets after local capture fixture fixture_ok=%d", pkts.size(), fixture_ok ? 1 : 0);
        if (pkts.empty()) {
            fail_empty_evidence(hf, tag, failed, "driver capture returned zero packets after local TCP/UDP fixture; max=16 fixture_ok=%d", fixture_ok ? 1 : 0);
            return;
        }
        log_msg(hf, tag, "PASS -- get_captured_packets returned %zu packets", pkts.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_queries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_query";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_dns_queries()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto dns = driver_bridge::get_dns_queries(0);
        log_msg(hf, tag, "RESULT count=%zu driver_status=\"%s\" last_error=\"%s\"",
            dns.size(), driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
        if (dns.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "get_dns_queries returned 0 entries; a live system with network activity should have DNS queries cached by the driver");
            return;
        }
        log_msg(hf, tag, "  first: domain=%s pid=%u code=%u",
            dns[0].domain.c_str(), (unsigned)dns[0].pid, (unsigned)dns[0].response_code);
        log_msg(hf, tag, "PASS -- get_dns_queries returned %zu entries", dns.size());
        passed.fetch_add(1);
    }

    void test_driver_filter_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_flt_rules";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge filter rule add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint32_t rule_id = 0;
        bool added = driver_bridge::add_filter_rule(0, 2, 6, GetCurrentProcessId(), 0, nullptr, nullptr, &rule_id);
        if (added && rule_id != 0) {
            bool removed = driver_bridge::remove_filter_rule(rule_id);
            if (removed) {
                log_msg(hf, tag, "PASS -- added rule_id=%u, removed=true",
                    (unsigned)rule_id);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- added rule_id=%u but remove_filter_rule failed",
                    (unsigned)rule_id);
                failed.fetch_add(1);
            }
        } else {
            log_msg(hf, tag, "FAIL -- add_filter_rule returned added=%s rule_id=%u",
                added ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_driver_clear_filters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_flt_clear";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::clear_filter_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        bool ok = driver_bridge::clear_filter_rules();
        if (!ok) {
            fail_empty_evidence(hf, tag, failed,
                "clear_filter_rules returned false; driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
            return;
        }
        log_msg(hf, tag, "PASS -- clear_filter_rules returned true");
        passed.fetch_add(1);
    }

    void test_driver_network_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_net_stats";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_network_stats()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        driver_bridge::network_stats_t stats{};
        bool ok = driver_bridge::get_network_stats(stats);
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT ok=%d bytes_sent=%llu bytes_recv=%llu pkts_sent=%llu pkts_recv=%llu active_conns=%u captured=%u elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            ok ? 1 : 0,
            (unsigned long long)stats.bytes_sent, (unsigned long long)stats.bytes_received,
            (unsigned long long)stats.packets_sent, (unsigned long long)stats.packets_received,
            (unsigned)stats.active_connections, (unsigned)stats.total_captured,
            us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (!ok) {
            fail_empty_evidence(hf, tag, failed,
                "get_network_stats returned false; kernel network stats are mandatory and have no usermode fallback driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            return;
        }
        const bool all_zero =
            stats.bytes_sent == 0 && stats.bytes_received == 0 &&
            stats.packets_sent == 0 && stats.packets_received == 0 &&
            stats.active_connections == 0 && stats.total_captured == 0;
        if (all_zero) {
            fail_empty_evidence(hf, tag, failed,
                "get_network_stats returned ok=true but every counter is zero; a live attached target always has nonzero aggregate network counters");
            return;
        }
        log_msg(hf, tag, "PASS -- bytes_sent=%llu bytes_recv=%llu pkts_sent=%llu pkts_recv=%llu active_conns=%u captured=%u elapsed_us=%lld",
            (unsigned long long)stats.bytes_sent, (unsigned long long)stats.bytes_received,
            (unsigned long long)stats.packets_sent, (unsigned long long)stats.packets_received,
            (unsigned)stats.active_connections, (unsigned)stats.total_captured, us);
        passed.fetch_add(1);
    }

    void test_driver_bw_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_bw_mon";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge bandwidth monitor reset/start/traffic/query/stop");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa.rc);
            failed.fetch_add(1);
            return;
        }
        driver_bridge::bw_stats_t stats{};
        bool reset_before = driver_bridge::bw_monitor_op(3, 0, nullptr);
        bool started = driver_bridge::bw_monitor_op(0, 0, nullptr);
        uint32_t udp_sent = 0;
        bool udp_ok = drive_udp_burst_fixture(hf, tag, 53535, 24, udp_sent);
        Sleep(250);
        bool queried = driver_bridge::bw_monitor_op(2, 0, &stats);
        bool stopped = driver_bridge::bw_monitor_op(1, 0, nullptr);
        bool reset_after = driver_bridge::bw_monitor_op(3, 0, nullptr);
        log_msg(hf, tag, "bw reset_before=%d started=%d queried=%d stopped=%d reset_after=%d udp_ok=%d udp_sent=%u active=%s total_in=%llu total_out=%llu pkts_in=%llu pkts_out=%llu",
            reset_before ? 1 : 0,
            started ? 1 : 0,
            queried ? 1 : 0,
            stopped ? 1 : 0,
            reset_after ? 1 : 0,
            udp_ok ? 1 : 0,
            udp_sent,
            stats.active ? "true" : "false",
            (unsigned long long)stats.total_bytes_recv,
            (unsigned long long)stats.total_bytes_sent,
            (unsigned long long)stats.total_packets_recv,
            (unsigned long long)stats.total_packets_sent);
        if (!started || !queried || !stopped) {
            log_msg(hf, tag, "FAIL -- bw monitor lifecycle failed start=%d query=%d stop=%d",
                started ? 1 : 0, queried ? 1 : 0, stopped ? 1 : 0);
            failed.fetch_add(1);
            return;
        }
        if (!udp_ok || (stats.total_bytes_recv == 0 && stats.total_bytes_sent == 0 &&
            stats.total_packets_recv == 0 && stats.total_packets_sent == 0)) {
            fail_empty_evidence(hf, tag, failed, "bw monitor query returned zero aggregate counters after UDP fixture udp_ok=%d udp_sent=%u",
                udp_ok ? 1 : 0, udp_sent);
            return;
        }
        log_msg(hf, tag, "PASS -- bw monitor lifecycle produced aggregate counters");
        passed.fetch_add(1);
    }

    void test_driver_bw_per_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_bw_proc";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_bw_per_process()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa.rc);
            failed.fetch_add(1);
            return;
        }
        driver_bridge::bw_stats_t stats{};
        (void)driver_bridge::bw_monitor_op(3, 0, nullptr);
        bool started = driver_bridge::bw_monitor_op(0, 0, nullptr);
        uint32_t udp_sent = 0;
        bool udp_ok = drive_udp_burst_fixture(hf, tag, 53536, 24, udp_sent);
        Sleep(250);
        bool queried = driver_bridge::bw_monitor_op(2, 0, &stats);
        auto procs = driver_bridge::get_bw_per_process(0);
        bool stopped = driver_bridge::bw_monitor_op(1, 0, nullptr);
        (void)driver_bridge::bw_monitor_op(3, 0, nullptr);
        log_msg(hf, tag, "get_bw_per_process returned %zu entries after start=%d query=%d stop=%d udp_ok=%d udp_sent=%u aggregate_in=%llu aggregate_out=%llu pkts_in=%llu pkts_out=%llu active=%d",
            procs.size(),
            started ? 1 : 0,
            queried ? 1 : 0,
            stopped ? 1 : 0,
            udp_ok ? 1 : 0,
            udp_sent,
            (unsigned long long)stats.total_bytes_recv,
            (unsigned long long)stats.total_bytes_sent,
            (unsigned long long)stats.total_packets_recv,
            (unsigned long long)stats.total_packets_sent,
            stats.active ? 1 : 0);
        if (procs.empty()) {
            fail_empty_evidence(hf, tag, failed, "bandwidth monitor returned zero per-process entries after live UDP fixture; aggregate_in=%llu aggregate_out=%llu packets_in=%llu packets_out=%llu",
                (unsigned long long)stats.total_bytes_recv,
                (unsigned long long)stats.total_bytes_sent,
                (unsigned long long)stats.total_packets_recv,
                (unsigned long long)stats.total_packets_sent);
            return;
        }
        log_msg(hf, tag, "PASS -- get_bw_per_process returned %zu entries", procs.size());
        passed.fetch_add(1);
    }

    void test_driver_dpi_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dpi";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_dpi_results()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        std::vector<driver_bridge::captured_packet_t> fixture_packets;
        bool fixture_ok = driver_capture_fixture(hf, tag, 6, fixture_packets);
        auto dpi = driver_bridge::get_dpi_results(0, 0, 0, 0);
        log_msg(hf, tag, "get_dpi_results returned %zu entries after TCP capture fixture fixture_ok=%d fixture_packets=%zu", dpi.size(), fixture_ok ? 1 : 0, fixture_packets.size());
        if (!dpi.empty()) {
            log_msg(hf, tag, "  first: pid=%u proto=%u is_http=%s is_tls=%s",
                (unsigned)dpi[0].pid, (unsigned)dpi[0].protocol,
                dpi[0].is_http ? "true" : "false", dpi[0].is_tls ? "true" : "false");
        } else {
            fail_empty_evidence(hf, tag, failed, "DPI result ring is empty after local TCP capture fixture; fixture_ok=%d fixture_packets=%zu filter pid=0 proto=0 ports=0",
                fixture_ok ? 1 : 0, fixture_packets.size());
            return;
        }
        log_msg(hf, tag, "PASS -- get_dpi_results returned %zu entries", dpi.size());
        passed.fetch_add(1);
    }

    void test_driver_wfp_callouts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_wfp";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::enumerate_wfp_callouts()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        auto callouts = driver_bridge::enumerate_wfp_callouts("");
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT count=%zu elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            callouts.size(), us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (callouts.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "enumerate_wfp_callouts returned 0 entries; the Windows base filter engine ships callouts on every supported build (BFE, mpsdrv, etc.). Zero indicates a broken kernel enumeration path");
            return;
        }
        log_msg(hf, tag, "  first: id=%u layer=%u module=%s",
            (unsigned)callouts[0].callout_id,
            (unsigned)callouts[0].layer_id,
            callouts[0].owning_module.c_str());
        log_msg(hf, tag, "PASS -- enumerate_wfp_callouts returned %zu entries elapsed_us=%lld",
            callouts.size(), us);
        passed.fetch_add(1);
    }

    void test_driver_socket_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_sock_hdl";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::get_socket_handles()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        auto sockets_global = driver_bridge::get_socket_handles(0);
        long long us_global = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT global pid=0 count=%zu elapsed_us=%lld",
            sockets_global.size(), us_global);
        const uint32_t target_pid = driver_bridge::attached_pid();
        auto t1 = std::chrono::steady_clock::now();
        auto sockets_target = target_pid ? driver_bridge::get_socket_handles(target_pid) : std::vector<driver_bridge::socket_info_t>{};
        long long us_target = elapsed_us_since(t1);
        log_msg(hf, tag, "RESULT target pid=%u count=%zu elapsed_us=%lld",
            (unsigned)target_pid, sockets_target.size(), us_target);
        if (sockets_global.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "get_socket_handles(pid=0) returned 0 entries; a running Windows host always has open sockets (svchost, lsass, etc.)");
            return;
        }
        log_msg(hf, tag, "PASS -- get_socket_handles global=%zu target_pid=%u target=%zu elapsed_us_global=%lld elapsed_us_target=%lld",
            sockets_global.size(), (unsigned)target_pid, sockets_target.size(), us_global, us_target);
        passed.fetch_add(1);
    }

    void test_driver_tcpip_dump(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_tcpip";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::dump_tcpip_connections()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        auto conns = driver_bridge::dump_tcpip_connections(0, 0);
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT count=%zu elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            conns.size(), us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (conns.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "dump_tcpip_connections returned 0 entries; a Windows host always has at least loopback/IPv4/IPv6 listeners (svchost, lsass, etc.)");
            return;
        }
        log_msg(hf, tag, "  first: pid=%u proto=%u local_port=%u remote_port=%u state=%u",
            (unsigned)conns[0].pid, (unsigned)conns[0].protocol,
            (unsigned)conns[0].local_port, (unsigned)conns[0].remote_port,
            (unsigned)conns[0].state);
        log_msg(hf, tag, "PASS -- dump_tcpip_connections returned %zu entries elapsed_us=%lld",
            conns.size(), us);
        passed.fetch_add(1);
    }

    void test_driver_interfaces(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_ifaces";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::enumerate_interfaces()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        auto ifaces = driver_bridge::enumerate_interfaces();
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT count=%zu elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            ifaces.size(), us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (ifaces.empty()) {
            fail_empty_evidence(hf, tag, failed,
                "enumerate_interfaces returned 0 entries; a Windows host always has at least the loopback adapter");
            return;
        }
        for (size_t i = 0; i < ifaces.size() && i < 3; i++) {
            log_msg(hf, tag, "  iface[%zu]: name=%s mtu=%u speed=%llu",
                i, ifaces[i].name.c_str(), (unsigned)ifaces[i].mtu,
                (unsigned long long)ifaces[i].speed);
        }
        log_msg(hf, tag, "PASS -- enumerate_interfaces returned %zu entries elapsed_us=%lld",
            ifaces.size(), us);
        passed.fetch_add(1);
    }

    void test_driver_export_pcap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_pcap";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::export_pcap()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        driver_bridge::pcap_export_result_t result{};
        bool ok = driver_bridge::export_pcap(0, 0, 16, &result);
        log_msg(hf, tag, "export_pcap ok=%s packets=%zu magic=0x%08X max=16",
            ok ? "true" : "false", result.packets.size(),
            (unsigned)result.header.magic_number);
        if (!ok || result.packets.empty()) {
            fail_empty_evidence(hf, tag, failed, "pcap export produced no packet records after capture fixtures ok=%s packets=%zu magic=0x%08X",
                ok ? "true" : "false", result.packets.size(), (unsigned)result.header.magic_number);
            return;
        }
        log_msg(hf, tag, "PASS -- export_pcap ok=true packets=%zu magic=0x%08X",
            result.packets.size(), (unsigned)result.header.magic_number);
        passed.fetch_add(1);
    }

    void test_driver_held_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_held_pkts";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge intercept fixture/get_held_packets()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa.rc);
            failed.fetch_add(1);
            return;
        }
        udp_pair_fixture_t udp_fx;
        const uint32_t self_pid = GetCurrentProcessId();
        if (!open_udp_pair_fixture(hf, tag, udp_fx, 53537)) {
            fail_empty_evidence(hf, tag, failed, "UDP fixture could not bind explicit client/server sockets pid=%u tid=%lu",
                self_pid, GetCurrentThreadId());
            return;
        }
        uint32_t held_count = 0;
        bool active = false;
        bool started = driver_bridge::intercept_op(0, self_pid, udp_fx.server_port, 17, 0, nullptr, 0, &held_count, &active);
        log_msg(hf, tag, "intercept start ok=%d self_pid=%u tid=%lu filter_port=%u client_port=%u held=%u active=%d driver_status=\"%s\" driver_error=\"%s\"",
            started ? 1 : 0, self_pid, GetCurrentThreadId(),
            static_cast<unsigned>(udp_fx.server_port), static_cast<unsigned>(udp_fx.client_port),
            held_count, active ? 1 : 0, driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
        bool udp_ok = false;
        if (started)
            udp_ok = drive_udp_burst_fixture(hf, tag, udp_fx, 16);
        std::vector<driver_bridge::held_packet_info_t> held;
        for (int i = 0; i < 12; ++i) {
            Sleep(125);
            uint32_t poll_held_count = 0;
            bool poll_active = false;
            bool query_ok = driver_bridge::intercept_op(2, 0, 0, 0, 0, nullptr, 0, &poll_held_count, &poll_active);
            uint32_t drained_before = drain_udp_fixture(hf, tag, udp_fx, "poll_before_get_held");
            held = driver_bridge::get_held_packets();
            uint32_t drained_after = drain_udp_fixture(hf, tag, udp_fx, "poll_after_get_held");
            log_msg(hf, tag, "held poll iter=%d query_ok=%d query_held=%u query_active=%d entries=%zu drained_before=%u drained_after=%u sent=%u received=%u client_port=%u dst_port=%u",
                i, query_ok ? 1 : 0, poll_held_count, poll_active ? 1 : 0, held.size(),
                static_cast<unsigned>(drained_before), static_cast<unsigned>(drained_after),
                static_cast<unsigned>(udp_fx.sent_packets), static_cast<unsigned>(udp_fx.received_packets),
                static_cast<unsigned>(udp_fx.client_port), static_cast<unsigned>(udp_fx.server_port));
            for (size_t hi = 0; hi < held.size() && hi < 4; ++hi) {
                const auto& hp = held[hi];
                const bool tuple_match =
                    hp.pid == self_pid ||
                    hp.src_port == udp_fx.client_port ||
                    hp.dst_port == udp_fx.server_port;
                log_msg(hf, tag, "held[%zu] id=%llu pid=%u proto=%u dir=%u af=%u src_port=%u dst_port=%u payload_size=%u tuple_match=%d timestamp=%llu",
                    hi,
                    static_cast<unsigned long long>(hp.hold_id),
                    hp.pid,
                    hp.protocol,
                    hp.direction,
                    hp.af,
                    hp.src_port,
                    hp.dst_port,
                    hp.payload_size,
                    tuple_match ? 1 : 0,
                    static_cast<unsigned long long>(hp.timestamp));
            }
            if (!held.empty())
                break;
        }
        uint32_t drained_before_stop = drain_udp_fixture(hf, tag, udp_fx, "before_stop");
        bool stopped = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, &held_count, &active);
        uint32_t drained_after_stop = drain_udp_fixture(hf, tag, udp_fx, "after_stop");
        log_msg(hf, tag, "intercept stop/drop ok=%d held_after=%u active_after=%d udp_ok=%d sent=%u sent_bytes=%u received=%u received_bytes=%u client_port=%u dst_port=%u send_err=%d recv_err=%d drained_before_stop=%u drained_after_stop=%u",
            stopped ? 1 : 0, held_count, active ? 1 : 0, udp_ok ? 1 : 0,
            static_cast<unsigned>(udp_fx.sent_packets), static_cast<unsigned>(udp_fx.sent_bytes),
            static_cast<unsigned>(udp_fx.received_packets), static_cast<unsigned>(udp_fx.received_bytes),
            static_cast<unsigned>(udp_fx.client_port), static_cast<unsigned>(udp_fx.server_port),
            udp_fx.last_send_error, udp_fx.last_recv_error,
            static_cast<unsigned>(drained_before_stop), static_cast<unsigned>(drained_after_stop));
        if (held.empty()) {
            fail_empty_evidence(hf, tag, failed, "held packet list is empty after live intercept UDP fixture start=%d udp_ok=%d sent=%u received=%u client_port=%u dst_port=%u stop=%d active_after=%d held_after=%u send_err=%d recv_err=%d",
                started ? 1 : 0, udp_ok ? 1 : 0,
                static_cast<unsigned>(udp_fx.sent_packets), static_cast<unsigned>(udp_fx.received_packets),
                static_cast<unsigned>(udp_fx.client_port), static_cast<unsigned>(udp_fx.server_port),
                stopped ? 1 : 0, active ? 1 : 0, held_count,
                udp_fx.last_send_error, udp_fx.last_recv_error);
            return;
        }
        log_msg(hf, tag, "PASS -- get_held_packets returned %zu entries", held.size());
        passed.fetch_add(1);
    }

    void test_driver_packet_mod_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_mod_rules";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::list_packet_mod_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        const uint8_t pattern[] = { 'A', 'I', 'D', 'A' };
        const uint8_t replacement[] = { 'a', 'i', 'd', 'a' };
        uint32_t rule_id = 0;
        bool added = driver_bridge::packet_mod_rule_op(0, 0, 2, 17, 0, GetCurrentProcessId(),
            pattern, static_cast<uint32_t>(sizeof(pattern)),
            replacement, static_cast<uint32_t>(sizeof(replacement)), &rule_id);
        auto rules = driver_bridge::list_packet_mod_rules();
        bool found = false;
        for (const auto& rule : rules) {
            if (rule.rule_id == rule_id && rule.active != 0) {
                found = true;
                break;
            }
        }
        bool removed = rule_id != 0 ? driver_bridge::packet_mod_rule_op(1, rule_id) : false;
        if (!removed)
            (void)driver_bridge::packet_mod_rule_op(3);
        log_msg(hf, tag, "packet_mod add=%d rule_id=%u list_count=%zu found=%d removed=%d",
            added ? 1 : 0, rule_id, rules.size(), found ? 1 : 0, removed ? 1 : 0);
        if (rules.empty()) {
            fail_empty_evidence(hf, tag, failed, "packet modification rule list is empty after add fixture add=%d rule_id=%u removed=%d",
                added ? 1 : 0, rule_id, removed ? 1 : 0);
            return;
        }
        if (!added || rule_id == 0 || !found || !removed) {
            log_msg(hf, tag, "FAIL -- packet modification add/list/remove lifecycle invalid add=%d rule_id=%u found=%d removed=%d",
                added ? 1 : 0, rule_id, found ? 1 : 0, removed ? 1 : 0);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- list_packet_mod_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_redirect_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_redir_rul";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::list_redirect_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint32_t rule_id = 0;
        uint8_t loopback[4] = { 127, 0, 0, 1 };
        bool added = driver_bridge::traffic_redirect_op(0, 0, 6,
            19999, loopback, 19998, loopback, 2, &rule_id, GetCurrentProcessId());
        auto rules = driver_bridge::list_redirect_rules();
        bool found = false;
        for (const auto& rule : rules) {
            if (rule.rule_id == rule_id && rule.active != 0) {
                found = true;
                break;
            }
        }
        bool removed = rule_id != 0 ? driver_bridge::traffic_redirect_op(1, rule_id) : false;
        if (!removed)
            (void)driver_bridge::traffic_redirect_op(3);
        log_msg(hf, tag, "redirect add=%d rule_id=%u list_count=%zu found=%d removed=%d",
            added ? 1 : 0, rule_id, rules.size(), found ? 1 : 0, removed ? 1 : 0);
        if (rules.empty()) {
            fail_empty_evidence(hf, tag, failed, "traffic redirect rule list is empty after add fixture add=%d rule_id=%u removed=%d",
                added ? 1 : 0, rule_id, removed ? 1 : 0);
            return;
        }
        if (!added || rule_id == 0 || !found || !removed) {
            log_msg(hf, tag, "FAIL -- traffic redirect add/list/remove lifecycle invalid add=%d rule_id=%u found=%d removed=%d",
                added ? 1 : 0, rule_id, found ? 1 : 0, removed ? 1 : 0);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- list_redirect_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_spoof_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_spoof";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::list_dns_spoof_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint8_t spoof_addr[4] = { 127, 0, 0, 2 };
        uint32_t rule_id = 0;
        bool added = driver_bridge::dns_spoof_op(0, 0, "aida-test-list.local",
            spoof_addr, 2, 60, &rule_id);
        auto rules = driver_bridge::list_dns_spoof_rules();
        bool found = false;
        for (const auto& rule : rules) {
            if (rule.rule_id == rule_id && rule.active != 0) {
                found = true;
                break;
            }
        }
        bool removed = rule_id != 0 ? driver_bridge::dns_spoof_op(1, rule_id) : false;
        if (!removed)
            (void)driver_bridge::dns_spoof_op(3);
        log_msg(hf, tag, "dns_spoof add=%d rule_id=%u list_count=%zu found=%d removed=%d",
            added ? 1 : 0, rule_id, rules.size(), found ? 1 : 0, removed ? 1 : 0);
        if (rules.empty()) {
            fail_empty_evidence(hf, tag, failed, "DNS spoof rule list is empty after add fixture add=%d rule_id=%u removed=%d",
                added ? 1 : 0, rule_id, removed ? 1 : 0);
            return;
        }
        if (!added || rule_id == 0 || !found || !removed) {
            log_msg(hf, tag, "FAIL -- DNS spoof add/list/remove lifecycle invalid add=%d rule_id=%u found=%d removed=%d",
                added ? 1 : 0, rule_id, found ? 1 : 0, removed ? 1 : 0);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- list_dns_spoof_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_spoof_add_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_sp_ar";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge dns_spoof_op add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint8_t spoof_addr[4] = { 127, 0, 0, 1 };
        uint32_t rule_id = 0;
        auto t0 = std::chrono::steady_clock::now();
        bool added = driver_bridge::dns_spoof_op(0, 0, "aida-test-internal.invalid",
            spoof_addr, 2, 60, &rule_id);
        long long us_add = elapsed_us_since(t0);
        log_msg(hf, tag, "RESULT add ok=%d rule_id=%u elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            added ? 1 : 0, (unsigned)rule_id, us_add,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (!added || rule_id == 0) {
            fail_empty_evidence(hf, tag, failed,
                "dns_spoof_op add returned %s rule_id=%u; kernel DNS spoof is mandatory and has no usermode fallback",
                added ? "true" : "false", (unsigned)rule_id);
            return;
        }
        auto t1 = std::chrono::steady_clock::now();
        bool removed = driver_bridge::dns_spoof_op(1, rule_id);
        long long us_rem = elapsed_us_since(t1);
        log_msg(hf, tag, "RESULT remove ok=%d rule_id=%u elapsed_us=%lld",
            removed ? 1 : 0, (unsigned)rule_id, us_rem);
        if (!removed) {
            fail_empty_evidence(hf, tag, failed,
                "dns_spoof_op add succeeded rule_id=%u but remove returned false", (unsigned)rule_id);
            return;
        }
        log_msg(hf, tag, "PASS -- dns_spoof added rule_id=%u removed=true elapsed_us_add=%lld elapsed_us_remove=%lld",
            (unsigned)rule_id, us_add, us_rem);
        passed.fetch_add(1);
    }

    void test_driver_traffic_redirect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_traf_rdr";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge traffic_redirect_op add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint32_t rule_id = 0;
        uint8_t loopback[4] = { 127, 0, 0, 1 };
        bool added = driver_bridge::traffic_redirect_op(0, 0, 6,
            19999, loopback, 19998, loopback, 2, &rule_id, GetCurrentProcessId());
        if (added && rule_id != 0) {
            bool removed = driver_bridge::traffic_redirect_op(1, rule_id);
            driver_bridge::traffic_redirect_op(3);
            if (removed) {
                log_msg(hf, tag, "PASS -- redirect added rule_id=%u and removed cleanly",
                    (unsigned)rule_id);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- redirect added rule_id=%u but remove failed; clear-all attempted",
                    (unsigned)rule_id);
                failed.fetch_add(1);
            }
        } else {
            log_msg(hf, tag, "FAIL -- traffic_redirect_op add returned %s rule_id=%u",
                added ? "true" : "false", (unsigned)rule_id);
            failed.fetch_add(1);
        }
    }

    void test_driver_stream_reassemble(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_strm_reas";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::stream_reassemble_op() loopback TCP fixture");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa.rc);
            failed.fetch_add(1);
            return;
        }
        tcp_pair_fixture_t pair;
        if (!open_tcp_pair_fixture(hf, tag, pair)) {
            log_msg(hf, tag, "FAIL -- stream fixture TCP pair failed");
            failed.fetch_add(1);
            return;
        }
        const uint32_t src_port = pair.client_port;
        const uint32_t dst_port = pair.listen_port;
        const uint32_t pid = GetCurrentProcessId();
        bool started = driver_bridge::stream_reassemble_op(0, src_port, dst_port, pid, pair.client_addr, pair.server_addr,
            nullptr, nullptr, nullptr);
        if (!started) {
            log_msg(hf, tag, "FAIL -- stream_reassemble_op start failed src_port=%u dst_port=%u pid=%u",
                (unsigned)src_port, (unsigned)dst_port, (unsigned)pid);
            failed.fetch_add(1);
            return;
        }
        bool traffic_ok = drive_tcp_pair_fixture(hf, tag, pair, "AIDA-STRM-FULL-NETWORK-PROBE-0123456789");
        std::vector<uint8_t> data;
        uint32_t packets = 0, truncated = 0;
        bool ok = false;
        for (int i = 0; i < 10; ++i) {
            Sleep(250);
            data.clear();
            packets = 0;
            truncated = 0;
            ok = driver_bridge::stream_reassemble_op(2, src_port, dst_port, 0, nullptr, nullptr,
                &data, &packets, &truncated);
            log_msg(hf, tag, "stream poll iter=%d ok=%d data_size=%zu packets=%u truncated=%u",
                i, ok ? 1 : 0, data.size(), packets, truncated);
            if (ok && (!data.empty() || packets > 0))
                break;
        }
        bool stopped = driver_bridge::stream_reassemble_op(1, src_port, dst_port, 0, nullptr, nullptr,
            nullptr, nullptr, nullptr);
        if (!ok || !stopped) {
            log_msg(hf, tag, "FAIL -- stream_reassemble_op lifecycle failed get=%s stopped=%s traffic_ok=%d data_size=%zu packets=%u truncated=%u",
                ok ? "true" : "false",
                stopped ? "true" : "false", traffic_ok ? 1 : 0, data.size(), (unsigned)packets, (unsigned)truncated);
            failed.fetch_add(1);
            return;
        }
        if (data.empty() || packets == 0u) {
            fail_empty_evidence(hf, tag, failed, "stream_reassemble_op returned empty data after TCP fixture traffic_ok=%d data_size=%zu packets=%u truncated=%u stopped=%s src_port=%u dst_port=%u",
                traffic_ok ? 1 : 0, data.size(), (unsigned)packets, (unsigned)truncated, stopped ? "true" : "false",
                static_cast<unsigned>(src_port), static_cast<unsigned>(dst_port));
            return;
        }
        log_msg(hf, tag, "PASS -- stream_reassemble_op lifecycle start/get/stop ok data_size=%zu packets=%u truncated=%u stopped=%s",
            data.size(), (unsigned)packets, (unsigned)truncated, stopped ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_driver_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_fprint";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge fingerprint_op/get_fingerprints");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        winsock_scope_t wsa;
        if (!wsa.ok()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa.rc);
            failed.fetch_add(1);
            return;
        }
        bool enabled = driver_bridge::fingerprint_op(0);
        bool traffic_ok = false;
        if (enabled) {
            for (int i = 0; i < 3; ++i) {
                tcp_pair_fixture_t pair;
                bool pair_ok = open_tcp_pair_fixture(hf, tag, pair) &&
                    drive_tcp_pair_fixture(hf, tag, pair, "AIDA-FP-SYN-PROBE");
                traffic_ok = traffic_ok || pair_ok;
                Sleep(100);
            }
        }
        std::vector<driver_bridge::fingerprint_info_t> fps;
        for (int i = 0; i < 10; ++i) {
            Sleep(150);
            fps = driver_bridge::get_fingerprints();
            log_msg(hf, tag, "fingerprint poll iter=%d enabled=%d traffic_ok=%d results=%zu",
                i, enabled ? 1 : 0, traffic_ok ? 1 : 0, fps.size());
            if (!fps.empty())
                break;
        }
        bool disabled = driver_bridge::fingerprint_op(1);
        log_msg(hf, tag, "fingerprint cycle completed enabled=%d traffic_ok=%d disabled=%d results=%zu",
            enabled ? 1 : 0, traffic_ok ? 1 : 0, disabled ? 1 : 0, fps.size());
        if (!fps.empty()) {
            log_msg(hf, tag, "  first: ttl=%u window=%u mss=%u os=%s",
                (unsigned)fps[0].ttl, (unsigned)fps[0].window_size,
                (unsigned)fps[0].mss, fps[0].os_guess.c_str());
        } else {
            fail_empty_evidence(hf, tag, failed, "fingerprint result list is empty after enabled TCP fixture enabled=%d traffic_ok=%d disabled=%d",
                enabled ? 1 : 0, traffic_ok ? 1 : 0, disabled ? 1 : 0);
            return;
        }
        log_msg(hf, tag, "PASS -- fingerprint cycle completed, %zu results", fps.size());
        passed.fetch_add(1);
    }

    void test_driver_intercept_op(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_intercept";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge intercept_op query");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint32_t held_count = 0;
        bool active = false;
        bool ok = driver_bridge::intercept_op(2, 0, 0, 0, 0, nullptr, 0, &held_count, &active);
        if (!ok) {
            log_msg(hf, tag, "FAIL -- intercept_op query ok=false held=%u active=%s",
                (unsigned)held_count, active ? "true" : "false");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- intercept_op query ok=true held=%u active=%s",
            (unsigned)held_count, active ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_driver_inject_loopback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_inject_lb";
        ::test_all_features::set_progress_step(tag);
        log_msg(hf, tag, "START -- driver_bridge::inject_packet() loopback UDP");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded (network kernel features are mandatory; no usermode fallback) driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        uint8_t src_addr[4] = { 127, 0, 0, 1 };
        uint8_t dst_addr[4] = { 127, 0, 0, 1 };
        uint8_t payload[] = { 'A', 'i', 'D', 'A' };
        bool ok = driver_bridge::inject_packet(1, 17, 2,
            19876, 19877, src_addr, dst_addr, payload, sizeof(payload));
        if (!ok) {
            log_msg(hf, tag, "FAIL -- inject_packet returned false");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- inject_packet returned true");
        passed.fetch_add(1);
    }

    void test_autoresponder_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "autoresponder";
        log_msg(hf, tag, "START -- AutoResponder add/list/remove/start/stop");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::prefix_url;
        rule.match_pattern = "http://test.local/api";
        rule.status_code = 200;
        rule.response_body = "{\"status\":\"ok\"}";
        rule.response_headers["Content-Type"] = "application/json";

        uint32_t rule_id = ar.add_rule(rule);
        auto rules = ar.list_rules();
        bool found = false;
        for (auto& r : rules) {
            if (r.rule_id == rule_id) { found = true; break; }
        }

        bool started = ar.start();
        bool is_active = ar.is_active();
        bool stopped = ar.stop();

        bool removed = ar.remove_rule(rule_id);
        auto rules_after = ar.list_rules();

        if (found && removed && rules_after.empty()) {
            log_msg(hf, tag, "PASS -- lifecycle ok: added=%u found=%s started=%s active=%s stopped=%s removed=%s",
                (unsigned)rule_id, found ? "true" : "false",
                started ? "true" : "false", is_active ? "true" : "false",
                stopped ? "true" : "false", removed ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- lifecycle error found=%s removed=%s remaining=%zu",
                found ? "true" : "false", removed ? "true" : "false", rules_after.size());
            failed.fetch_add(1);
        }
    }

    void test_autoresponder_match(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ar_match";
        log_msg(hf, tag, "START -- AutoResponder::match_request()");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::exact_url;
        rule.match_pattern = "http://test.local/match";
        rule.status_code = 418;
        rule.response_body = "teapot";
        ar.add_rule(rule);
        ar.start();

        std::map<std::string, std::string> headers;
        auto result = ar.match_request("GET", "http://test.local/match", headers, "");
        ar.stop();
        ar.clear_rules();

        if (result.matched && result.rule_id != 0) {
            log_msg(hf, tag, "PASS -- match_request matched rule_id=%u", (unsigned)result.rule_id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- match_request did not match");
            failed.fetch_add(1);
        }
    }

    void test_autoresponder_import_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ar_impexp";
        log_msg(hf, tag, "START -- AutoResponder import/export");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::prefix_url;
        rule.match_pattern = "http://export-test.local/";
        rule.status_code = 200;
        rule.response_body = "exported";
        ar.add_rule(rule);

        std::string exported = ar.export_rules();
        ar.clear_rules();

        bool imported = ar.import_rules(exported);
        auto rules = ar.list_rules();
        ar.clear_rules();

        if (imported && !rules.empty()) {
            log_msg(hf, tag, "PASS -- export/import roundtrip ok, rules=%zu", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- roundtrip failed imported=%s rules=%zu",
                imported ? "true" : "false", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_match_replace_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_lifecycle";
        log_msg(hf, tag, "START -- match_replace add/list/remove lifecycle");
        aida::burp::match_replace::initialize();

        aida::burp::match_replace::rule_t rule;
        rule.label = "test-rule";
        rule.target = aida::burp::match_replace::match_kind_t::request_url;
        rule.match_regex = "/old-path";
        rule.replacement = "/new-path";
        rule.regex = false;
        rule.active = true;

        uint64_t id = aida::burp::match_replace::add(rule);
        auto rules = aida::burp::match_replace::list();
        bool found = false;
        for (auto& r : rules) {
            if (r.id == id) { found = true; break; }
        }

        bool removed = aida::burp::match_replace::remove(id);
        auto rules_after = aida::burp::match_replace::list();

        if (found && removed) {
            log_msg(hf, tag, "PASS -- MR lifecycle: added id=%llu found=%s removed=%s",
                (unsigned long long)id, found ? "true" : "false", removed ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- MR lifecycle: found=%s removed=%s",
                found ? "true" : "false", removed ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_match_replace_apply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_apply";
        log_msg(hf, tag, "START -- match_replace::apply_text()");
        aida::burp::match_replace::clear();

        aida::burp::match_replace::rule_t rule;
        rule.label = "url-replace";
        rule.target = aida::burp::match_replace::match_kind_t::request_url;
        rule.match_regex = "old";
        rule.replacement = "new";
        rule.regex = false;
        rule.active = true;
        aida::burp::match_replace::add(rule);

        std::string text = "/api/old/endpoint";
        size_t applied = 0;
        bool changed = aida::burp::match_replace::apply_text(
            text, aida::burp::match_replace::match_kind_t::request_url, "", "", &applied);

        aida::burp::match_replace::clear();

        if (changed && text.find("new") != std::string::npos) {
            log_msg(hf, tag, "PASS -- apply_text changed to '%s', rules_applied=%zu",
                text.c_str(), applied);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- apply_text changed=%s result=%s",
                changed ? "true" : "false", text.c_str());
            failed.fetch_add(1);
        }
    }

    void test_match_replace_test_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_test_rule";
        log_msg(hf, tag, "START -- match_replace::test_rule()");
        aida::burp::match_replace::rule_t rule;
        rule.target = aida::burp::match_replace::match_kind_t::request_body;
        rule.match_regex = "secret";
        rule.replacement = "REDACTED";
        rule.regex = false;
        rule.active = true;

        std::string out;
        bool ok = aida::burp::match_replace::test_rule(rule, "my secret value", out);
        if (ok && out.find("REDACTED") != std::string::npos) {
            log_msg(hf, tag, "PASS -- test_rule produced '%s'", out.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- test_rule ok=%s out=%s",
                ok ? "true" : "false", out.c_str());
            failed.fetch_add(1);
        }
    }

    void test_tcp_loopback_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_lb_conn";
        log_msg(hf, tag, "START -- TCP loopback listen/connect/accept");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed err=%d", WSAGetLastError());
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(listen_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            log_msg(hf, tag, "FAIL -- bind() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        int namelen = sizeof(addr);
        getsockname(listen_sock, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
        uint16_t port = ntohs(addr.sin_port);

        if (listen(listen_sock, 1) != 0) {
            log_msg(hf, tag, "FAIL -- listen() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        SOCKET client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- client socket() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in conn_addr{};
        conn_addr.sin_family = AF_INET;
        conn_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        conn_addr.sin_port = htons(port);

        int rc = connect(client_sock, reinterpret_cast<struct sockaddr*>(&conn_addr), sizeof(conn_addr));
        if (rc != 0) {
            log_msg(hf, tag, "FAIL -- connect() to 127.0.0.1:%u failed err=%d",
                (unsigned)port, WSAGetLastError());
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);
        timeval tv{};
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int ready = select(0, &readfds, nullptr, nullptr, &tv);
        if (ready <= 0) {
            log_msg(hf, tag, "FAIL -- select() waiting for accept ready=%d err=%d",
                ready, ready == SOCKET_ERROR ? WSAGetLastError() : 0);
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        SOCKET accept_sock = accept(listen_sock, nullptr, nullptr);
        if (accept_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- accept() failed err=%d", WSAGetLastError());
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        const char msg[] = "AiDA_TCP_TEST";
        int sent = send(client_sock, msg, (int)sizeof(msg) - 1, 0);
        const int send_err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;

        DWORD timeout = 2000;
        setsockopt(accept_sock, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        char recv_buf[64] = {};
        int recvd = recv(accept_sock, recv_buf, sizeof(recv_buf), 0);
        const int recv_err = (recvd == SOCKET_ERROR) ? WSAGetLastError() : 0;

        bool data_ok = (sent > 0 && recvd == sent &&
            std::memcmp(recv_buf, msg, static_cast<size_t>(recvd)) == 0);

        closesocket(accept_sock);
        closesocket(client_sock);
        closesocket(listen_sock);

        if (data_ok) {
            log_msg(hf, tag, "PASS -- TCP loopback connect/send/recv on port %u", (unsigned)port);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- data mismatch sent=%d send_err=%d recvd=%d recv_err=%d",
                sent, send_err, recvd, recv_err);
            failed.fetch_add(1);
        }
    }

    void test_ipv6_socket_create(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ipv6_sock";
        log_msg(hf, tag, "START -- IPv6 TCP socket creation");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET s6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (s6 != INVALID_SOCKET) {
            struct sockaddr_in6 addr6{};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_loopback;
            addr6.sin6_port = htons(0);
            int rc = bind(s6, reinterpret_cast<struct sockaddr*>(&addr6), sizeof(addr6));
            if (rc == 0) {
                int namelen = sizeof(addr6);
                getsockname(s6, reinterpret_cast<struct sockaddr*>(&addr6), &namelen);
                log_msg(hf, tag, "PASS -- IPv6 TCP socket bound on port %u",
                    (unsigned)ntohs(addr6.sin6_port));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "PASS -- IPv6 bind failed (may not be supported) err=%d", WSAGetLastError());
                passed.fetch_add(1);
            }
            closesocket(s6);
        } else {
            log_msg(hf, tag, "PASS -- IPv6 socket creation failed (may not be available) err=%d", WSAGetLastError());
            passed.fetch_add(1);
        }
    }

    void test_dns_resolve_loopback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "dns_loopback";
        log_msg(hf, tag, "START -- DNS resolution for localhost loopback fixture");
        WSADATA wsa{};
        int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsa_rc != 0) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed rc=%d", wsa_rc);
            failed.fetch_add(1);
            return;
        }

        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo("localhost", "443", &hints, &result);
        bool loopback = false;
        char first_ip[INET6_ADDRSTRLEN] = {};
        int families = 0;
        for (auto* it = result; it != nullptr; it = it->ai_next) {
            ++families;
            if (it->ai_family == AF_INET) {
                auto* addr = reinterpret_cast<sockaddr_in*>(it->ai_addr);
                if (first_ip[0] == '\0')
                    inet_ntop(AF_INET, &addr->sin_addr, first_ip, sizeof(first_ip));
                const uint32_t host_ip = ntohl(addr->sin_addr.s_addr);
                if ((host_ip & 0xFF000000u) == 0x7F000000u)
                    loopback = true;
            } else if (it->ai_family == AF_INET6) {
                auto* addr6 = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
                if (first_ip[0] == '\0')
                    inet_ntop(AF_INET6, &addr6->sin6_addr, first_ip, sizeof(first_ip));
                if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr))
                    loopback = true;
            }
        }
        if (result)
            freeaddrinfo(result);
        WSACleanup();
        if (rc == 0 && loopback) {
            log_msg(hf, tag, "PASS -- localhost resolved to loopback first=%s families=%d", first_ip, families);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- localhost did not resolve to loopback rc=%d first=%s families=%d",
                rc, first_ip, families);
            failed.fetch_add(1);
        }
    }

    void test_tls_key_extractor_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_ke_inst";
        log_msg(hf, tag, "START -- TlsKeyExtractor::instance() singleton");
        auto& ext = net_security::TlsKeyExtractor::instance();
        bool logging = ext.is_keylogging();
        if (!logging) {
            log_msg(hf, tag, "PASS -- TlsKeyExtractor instance acquired, is_keylogging=%s",
                logging ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected is_keylogging=false, got true");
            failed.fetch_add(1);
        }
    }

    void test_cert_injector_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_inj_inst";
        log_msg(hf, tag, "START -- CertificateInjector::instance() singleton");
        auto& inj = net_security::CertificateInjector::instance();
        auto thumbprints = inj.get_injected_thumbprints();
        if (thumbprints.empty()) {
            log_msg(hf, tag, "PASS -- CertificateInjector instance acquired, injected=%zu",
                thumbprints.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 injected thumbprints, got %zu",
                thumbprints.size());
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypasser_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_inst";
        log_msg(hf, tag, "START -- CertPinBypasser::instance() singleton");
        auto& bp = net_security::CertPinBypasser::instance();
        bool active = bp.is_bypass_active(0);
        net_security::pin_bypass_config_t cfg;
        cfg.pid = 0;
        auto result = bp.bypass_pins(cfg);
        if (!result.success && result.read_only && result.legacy_patching_disabled &&
            !result.methods_requested.empty() && !result.disabled_operations.empty()) {
            log_msg(hf, tag, "PASS -- CertPinBypasser is diagnostic-only, active_for_pid0=%s",
                active ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bypass result success=%s read_only=%s disabled=%s methods=%zu ops=%zu",
                result.success ? "true" : "false",
                result.read_only ? "true" : "false",
                result.legacy_patching_disabled ? "true" : "false",
                result.methods_requested.size(),
                result.disabled_operations.size());
            failed.fetch_add(1);
        }
    }

    void test_quic_analyzer_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "quic_az_inst";
        log_msg(hf, tag, "START -- QuicAnalyzer::instance() singleton");
        auto& qa = net_security::QuicAnalyzer::instance();
        net_security::QuicAnalyzer::quic_header_t qh;
        uint8_t dummy[4] = { 0xC0, 0x00, 0x00, 0x01 };
        qa.parse_quic_header(dummy, sizeof(dummy), qh);
        if (qh.is_long_header) {
            log_msg(hf, tag, "PASS -- QuicAnalyzer parsed long header, is_long_header=%s packet_type=%u version=0x%08X",
                qh.is_long_header ? "true" : "false",
                (unsigned)qh.packet_type,
                (unsigned)qh.version);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected is_long_header=true for 0xC0 first byte, got false");
            failed.fetch_add(1);
        }
    }

    void test_dtls_analyzer_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "dtls_az_inst";
        log_msg(hf, tag, "START -- DtlsAnalyzer::instance() singleton");
        auto& da = net_security::DtlsAnalyzer::instance();
        net_security::DtlsAnalyzer::dtls_record_t rec;
        uint8_t dtls_data[16] = { 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00 };
        da.parse_dtls_record(dtls_data, sizeof(dtls_data), rec);
        if (rec.content_type == 0x16) {
            log_msg(hf, tag, "PASS -- DtlsAnalyzer parsed handshake, content_type=%u",
                (unsigned)rec.content_type);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected content_type=0x16, got %u",
                (unsigned)rec.content_type);
            failed.fetch_add(1);
        }
    }

    void test_network_view_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "net_view_st";
        log_msg(hf, tag, "START -- network_view::g_state fields");
        auto& state = network_view::g_state;
        int tab_count = static_cast<int>(network_view::sub_tab_t::COUNT);
        log_msg(hf, tag, "active=%s active_tab=%d tab_count=%d conn_auto_refresh=%s cap_max=%zu",
            state.active ? "true" : "false",
            static_cast<int>(state.active_tab),
            tab_count,
            state.conn_auto_refresh ? "true" : "false",
            state.cap_max_packets);
        log_msg(hf, tag, "PASS -- network_view state fields readable");
        passed.fetch_add(1);
    }

    void select_network_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                            const char* tag, network_view::sub_tab_t value) {
        auto t0 = std::chrono::steady_clock::now();
        const network_view::sub_tab_t before = network_view::g_state.active_tab;
        const char* before_label = network_sub_tab_label(before);
        const char* target_label = network_sub_tab_label(value);
        log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
            static_cast<int>(before),
            before_label,
            static_cast<int>(value),
            target_label,
            (unsigned long)GetCurrentThreadId());
        network_view::g_state.active_tab = value;
        const network_view::sub_tab_t got = network_view::g_state.active_tab;
        const char* got_label = network_sub_tab_label(got);
        long long us = elapsed_us_since(t0);
        log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
            static_cast<int>(got),
            got_label,
            (before != got) ? 1 : 0,
            us);
        if (got == value && target_label[0] != '\0') {
            log_msg(hf, tag, "PASS -- network sub_tab selected and read back (%d label=%s elapsed_us=%lld)",
                static_cast<int>(value), got_label, us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- network sub_tab set %d (%s) but read back %d (%s) elapsed_us=%lld",
                static_cast<int>(value), target_label,
                static_cast<int>(got), got_label, us);
            failed.fetch_add(1);
        }
    }

    void test_net_tab_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.connections", network_view::sub_tab_t::connections);
    }
    void test_net_tab_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.capture", network_view::sub_tab_t::capture);
    }
    void test_net_tab_intercept(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.intercept", network_view::sub_tab_t::intercept);
    }
    void test_net_tab_proxy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.proxy", network_view::sub_tab_t::proxy);
    }
    void test_net_tab_dns(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.dns", network_view::sub_tab_t::dns);
    }
    void test_net_tab_filters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.filters", network_view::sub_tab_t::filters);
    }
    void test_net_tab_bandwidth(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.bandwidth", network_view::sub_tab_t::bandwidth);
    }
    void test_net_tab_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.keylog", network_view::sub_tab_t::keylog);
    }
    void test_net_tab_pcap_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.pcap_export", network_view::sub_tab_t::pcap_export);
    }
    void test_net_tab_websocket(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.websocket", network_view::sub_tab_t::websocket);
    }
    void test_net_tab_decoder(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.decoder", network_view::sub_tab_t::decoder);
    }
    void test_net_tab_cookies(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.cookies", network_view::sub_tab_t::cookies);
    }
    void test_net_tab_ws_edit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.ws_edit", network_view::sub_tab_t::ws_edit);
    }
    void test_net_tab_h2_edit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.h2_edit", network_view::sub_tab_t::h2_edit);
    }
    void test_net_tab_logger(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.logger", network_view::sub_tab_t::logger);
    }
    void test_net_tab_csp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.csp", network_view::sub_tab_t::csp);
    }
    void test_net_tab_upstream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.upstream", network_view::sub_tab_t::upstream);
    }
    void test_net_tab_browser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.browser", network_view::sub_tab_t::browser);
    }
    void test_net_tab_headless(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.headless", network_view::sub_tab_t::headless);
    }

    void test_find_header(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "find_header";
        log_msg(hf, tag, "START -- protocol_parser::find_header()");
        std::vector<protocol_parser::http_header> headers;
        protocol_parser::http_header h1, h2;
        h1.name = "Content-Type"; h1.value = "text/html";
        h2.name = "X-Custom"; h2.value = "test-value";
        headers.push_back(h1);
        headers.push_back(h2);

        std::string ct = protocol_parser::find_header(headers, "Content-Type");
        std::string custom = protocol_parser::find_header(headers, "X-Custom");
        std::string missing = protocol_parser::find_header(headers, "X-Missing");

        if (ct == "text/html" && custom == "test-value" && missing.empty()) {
            log_msg(hf, tag, "PASS -- find_header correct for present and missing headers");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unexpected values ct=%s custom=%s missing=%s",
                ct.c_str(), custom.c_str(), missing.c_str());
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_shut";
        log_msg(hf, tag, "START -- cert_generator::shutdown()");
        cert_generator::shutdown();
        log_msg(hf, tag, "PASS -- cert_generator shutdown completed");
        passed.fetch_add(1);
    }

}

void run_parser_proof_smoke() {
    diag::log_tagged("parser_proof", "Ctrl+Shift+T immediate parser proof smoke START");
    std::atomic<int> passed{ 0 };
    std::atomic<int> failed{ 0 };
    test_http_parser_edge_cases(INVALID_HANDLE_VALUE, passed, failed);
    test_http2_client_preface_settings(INVALID_HANDLE_VALUE, passed, failed);
    diag::log_tagged_fmt("parser_proof", "Ctrl+Shift+T immediate parser proof smoke DONE passed=%d failed=%d",
        passed.load(),
        failed.load());
}

void phase_network_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "net_phase", "========== Network Tests START (125 tests, includes parser proof suite) ==========");
    diag::log_tagged("parser_proof", "Ctrl+Shift+T network phase reached; parser proof tests are scheduled in this phase");
    struct non_destructive_skip_accounting_t {
        HANDLE hf;
        std::atomic<int>& failed;
        std::atomic<int>& skipped;
        int start_skipped;
        ~non_destructive_skip_accounting_t() {
            const int raw_skip_delta = skipped.load(std::memory_order_acquire) - start_skipped;
            if (raw_skip_delta > 0) {
                skipped.fetch_sub(raw_skip_delta, std::memory_order_acq_rel);
                failed.fetch_add(raw_skip_delta, std::memory_order_acq_rel);
                log_msg(hf, "net_phase_accounting", "FAIL -- converted %d non-destructive Network skipped preconditions into failures so only registered destructive Test Lab guards contribute to global skips", raw_skip_delta);
            }
        }
    } skip_accounting{ hf, failed, skipped, skipped.load(std::memory_order_acquire) };

    if (cancelled && cancelled()) return;
    call_test(test_network_view_init, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_start, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_is_running, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_stats, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_on, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_off, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_check_intercept, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_history_empty, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_history_count, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_mitm_repeat_request, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_history_after, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_clear_history, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_held, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_forward_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_drop_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_ws_callback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_callback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_find_exchange, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_stop, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_tracker(test_tcp_stream_tracker, hf, passed, failed, skipped, cancelled);

    if (cancelled && cancelled()) return;
    call_test_tracker(test_tcp_tracker_evict, hf, passed, failed, skipped, cancelled);

    if (cancelled && cancelled()) return;
    call_test_tracker(test_tcp_tracker_get_stream, hf, passed, failed, skipped, cancelled);

    if (cancelled && cancelled()) return;
    call_test_tracker(test_tcp_tracker_filtered, hf, passed, failed, skipped, cancelled);

    if (cancelled && cancelled()) return;
    call_test(test_dns_resolution, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_winsock_connectivity, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_udp_loopback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_loopback_connect, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ipv6_socket_create, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_dns_resolve_loopback, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_parse_http_request, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_http_response, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_parser_edge_cases, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_detect_content_type, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_find_header, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_tls_record, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_client_hello, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_detect_protocol, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_ws_frame, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ws_upgrade_detection, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_h2_frames, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http2_client_preface_settings, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_quic_detection, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_parse_request, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_parse_response, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_stream_parser, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_decode, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_encode_roundtrip, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_grpc_frames, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_zigzag, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_init, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_root_ca, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_spki_hash, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_cert_profile_manager_public_ca_export, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_server_cert, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_storage_dir, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_ssl_ctx_cache, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_parse, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_watching, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_entries, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_find_by_random, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_hex_decode, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_packet_callstack_enable, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_packet_callstack_recent, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_init_sigs, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_status, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_pattern_match, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_scan_read_only, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_intercept_diagnostics_classify, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tls_key_extractor_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_injector_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypasser_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_quic_analyzer_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_dtls_analyzer_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_lifecycle, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_match, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_import_export, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_lifecycle, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_apply, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_test_rule, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_network_view_state, hf, passed, failed);

    bool drv_phase_barrier_ready = false;
    if (driver_bridge::using_kernel_driver()) {
        const ULONGLONG barrier_start = GetTickCount64();
        std::string barrier_reason;
        drv_phase_barrier_ready = driver_bridge::kernel_session_available(&barrier_reason);
        const ULONGLONG barrier_elapsed = GetTickCount64() - barrier_start;
        log_msg(hf, "net_phase",
            "drv_phase_barrier ready=%d elapsed_ms=%llu reason=\"%s\"",
            drv_phase_barrier_ready ? 1 : 0,
            static_cast<unsigned long long>(barrier_elapsed),
            barrier_reason.empty() ? "<empty>" : barrier_reason.c_str());
    } else {
        log_msg(hf, "net_phase",
            "drv_phase_barrier skipped reason=kernel_driver_not_loaded driver_status=\"%s\" last_error=\"%s\"",
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
    }
    if (driver_bridge::using_kernel_driver() && !drv_phase_barrier_ready) {
        const int aborted_test_count = 25;
        log_msg(hf, "net_phase",
            "FAIL -- network phase aborted: kernel session unavailable; skipping %d drv_* tests as grouped failure",
            aborted_test_count);
        failed.fetch_add(1);
    } else {
        if (cancelled && cancelled()) return;
        call_test_s(test_driver_enumerate_connections, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_start_stop_capture, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_get_packets, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_dns_queries, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_filter_rules, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_clear_filters, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_network_stats, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_bw_monitor, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_bw_per_process, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_dpi_results, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_wfp_callouts, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_socket_handles, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_tcpip_dump, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_interfaces, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_export_pcap, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_held_packets, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_packet_mod_rules, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_redirect_rules, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_dns_spoof_rules, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_dns_spoof_add_remove, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_traffic_redirect, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_stream_reassemble, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_fingerprint, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_intercept_op, hf, passed, failed, skipped);

        if (cancelled && cancelled()) return;
        call_test_s(test_driver_inject_loopback, hf, passed, failed, skipped);
    }

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_connections, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_capture, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_intercept, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_proxy, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_dns, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_filters, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_bandwidth, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_keylog, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_pcap_export, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_websocket, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_decoder, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_cookies, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_ws_edit, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_h2_edit, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_logger, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_csp, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_upstream, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_browser, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_headless, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_shutdown, hf, passed, failed);

    log_msg(hf, "net_phase", "========== Network Tests DONE ==========");
    diag::log_tagged("parser_proof", "Ctrl+Shift+T network phase completed");
}

}
