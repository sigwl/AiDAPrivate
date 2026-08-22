#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include "standalone_driver.hpp"
#include "executor_status.hpp"
#include "../infra/executor.hpp"
#include "../mcp/downstream_producer_governor.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <future>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace api_monitor {

enum class api_kind_t : uint32_t {
    generic = 0,
    send_linear,
    wsa_send,
    send_to,
    wsa_send_to,
    recv_linear,
    wsa_recv,
    recv_from,
    wsa_recv_from,
    connect_call,
    device_io_control,
    nt_device_io_control,
    write_file,
    read_file,
    encrypt_message,
    custom_linear
};

struct api_request_t {
    std::string original;
    std::string module_name;
    std::string function_name;
    api_kind_t kind = api_kind_t::generic;
    int buffer_reg = -1;
    int size_reg = -1;
};

struct api_target_t {
    api_request_t request;
    uint64_t address = 0;
    std::string resolved_module;
    uint64_t module_base = 0;
    uint64_t module_offset = 0;
    uint32_t bp_index = 0;
    bool active = false;
    std::vector<uint32_t> armed_tids;
};

struct register_snapshot_t {
    uint64_t rax = 0;
    uint64_t rbx = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t rsi = 0;
    uint64_t rdi = 0;
    uint64_t rbp = 0;
    uint64_t rsp = 0;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t r12 = 0;
    uint64_t r13 = 0;
    uint64_t r14 = 0;
    uint64_t r15 = 0;
    uint64_t rip = 0;
    uint64_t rflags = 0;
};

struct buffer_capture_t {
    std::string kind;
    std::string direction;
    uint64_t address = 0;
    uint64_t requested_size = 0;
    uint64_t captured_size = 0;
    bool truncated = false;
    bool readable = false;
    std::vector<uint8_t> bytes;
};

struct frame_t {
    uint64_t address = 0;
    std::string module_name;
    uint64_t module_offset = 0;
};

struct api_event_t {
    uint64_t sequence = 0;
    uint64_t timestamp_ms = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    std::string api;
    uint64_t api_address = 0;
    std::string api_module;
    uint64_t api_module_offset = 0;
    uint64_t return_address = 0;
    uint64_t callsite_address = 0;
    std::string caller_module;
    uint64_t caller_module_offset = 0;
    register_snapshot_t regs;
    nlohmann::json metadata = nlohmann::json::object();
    std::vector<buffer_capture_t> buffers;
    std::vector<frame_t> callstack;
};

struct socket_cache_t {
    uint64_t timestamp_ms = 0;
    std::vector<driver_bridge::socket_info_t> sockets;
};

struct state_t {
    std::mutex mutex;
    std::vector<api_request_t> requested;
    std::vector<api_target_t> targets;
    std::vector<driver_bridge::module_info_t> modules;
    std::deque<api_event_t> events;
    socket_cache_t socket_cache;
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> debug_attached{false};
    std::atomic<bool> debug_loop_running{false};
    std::atomic<bool> cleanup_running{false};
    std::atomic<DWORD> debugger_error{0};
    std::atomic<uint64_t> total_hits{0};
    std::atomic<uint64_t> cleanup_attempts{0};
    std::atomic<uint64_t> cleanup_last_elapsed_ms{0};
    std::atomic<uint32_t> cleanup_last_requests{0};
    std::atomic<uint32_t> cleanup_last_succeeded{0};
    std::atomic<uint32_t> cleanup_last_failed{0};
    uint32_t pid = 0;
    bool capture_buffer = true;
    bool log_callstack = false;
    uint32_t max_capture_bytes = 256;
    size_t max_events = 4096;
    uint64_t next_sequence = 1;
};

inline state_t g_state;
inline std::mutex g_phase_execution_mutex;

inline nlohmann::json status_json();
inline uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, uint32_t slot);

inline bool phase_target_liveness(uint32_t pid) {
    if (pid == 0 || pid == 4)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

inline void log_phase_state(const char* event, const char* phase, uint32_t pid, DWORD tid, uint64_t elapsed_ms, uint32_t timeout_ms) {
    const auto q = aida::network::executor_status::work_stats();
    const auto sq = aida::network::executor_status::service_stats();
    const bool target_alive = phase_target_liveness(pid);
    diag::log_tagged_fmt("api_monitor",
        "phase_state event=%s phase=%s pid=%u tid=%lu elapsed_ms=%llu timeout_ms=%u target_alive=%d active=%d polling=%d debug_loop=%d attached=%d cleanup=%d q_alive=%d q_shutdown=%d q_workers=%zu q_pending=%llu q_active=%u q_posted=%llu q_rejected=%llu q_started=%llu q_finished=%llu svc_alive=%d svc_shutdown=%d svc_workers=%zu svc_pending=%llu svc_active=%u svc_posted=%llu svc_rejected=%llu svc_started=%llu svc_finished=%llu",
        event ? event : "unknown",
        phase ? phase : "unknown",
        pid,
        tid,
        static_cast<unsigned long long>(elapsed_ms),
        timeout_ms,
        target_alive ? 1 : 0,
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        g_state.cleanup_running.load() ? 1 : 0,
        q.alive ? 1 : 0,
        q.shutting_down ? 1 : 0,
        q.workers,
        static_cast<unsigned long long>(q.pending),
        q.active,
        static_cast<unsigned long long>(q.posted),
        static_cast<unsigned long long>(q.rejected),
        static_cast<unsigned long long>(q.started),
        static_cast<unsigned long long>(q.finished),
        sq.alive ? 1 : 0,
        sq.shutting_down ? 1 : 0,
        sq.workers,
        static_cast<unsigned long long>(sq.pending),
        sq.active,
        static_cast<unsigned long long>(sq.posted),
        static_cast<unsigned long long>(sq.rejected),
        static_cast<unsigned long long>(sq.started),
        static_cast<unsigned long long>(sq.finished));
}

template <typename T>
struct phase_result_t {
    bool completed = false;
    bool threw = false;
    DWORD gle = ERROR_SUCCESS;
    int exception_code = 0;
    uint64_t elapsed_ms = 0;
    T value{};
    std::string exception;
    std::string exception_category;
};

struct phase_cancel_t {
    std::atomic_bool requested{false};
};

template <typename Fn>
decltype(auto) invoke_phase(Fn& fn, phase_cancel_t& cancel) {
    if constexpr (std::is_invocable_v<Fn&, phase_cancel_t&>)
        return fn(cancel);
    else
        return fn();
}

template <typename T, typename Fn>
inline phase_result_t<T> run_phase_inline(const char* phase,
                                          uint32_t pid,
                                          uint32_t timeout_ms,
                                          Fn&& fn) {
    const uint64_t started_ms = GetTickCount64();
    const DWORD caller_tid = GetCurrentThreadId();
    phase_result_t<T> result;
    result.completed = true;
    diag::log_tagged_fmt("api_monitor",
        "phase_begin phase=%s pid=%u backend=inline caller_tid=%lu worker_tid=%lu timeout_ms=%u",
        phase,
        pid,
        caller_tid,
        caller_tid,
        timeout_ms);
    log_phase_state("begin_inline", phase, pid, caller_tid, 0, timeout_ms);
    try {
        SetLastError(ERROR_SUCCESS);
        result.value = std::forward<Fn>(fn)();
        result.gle = GetLastError();
    } catch (const std::system_error& ex) {
        result.threw = true;
        result.exception = ex.what();
        result.exception_code = ex.code().value();
        result.exception_category = ex.code().category().name();
        result.gle = GetLastError();
    } catch (const std::exception& ex) {
        result.threw = true;
        result.exception = ex.what();
        result.gle = GetLastError();
    } catch (...) {
        result.threw = true;
        result.exception = "unknown exception";
        result.gle = GetLastError();
    }
    result.elapsed_ms = GetTickCount64() - started_ms;
    if (result.threw) {
        diag::log_tagged_fmt("api_monitor",
            "phase_fail phase=%s pid=%u backend=inline caller_tid=%lu worker_tid=%lu reason=inline_exception elapsed_ms=%llu timeout_ms=%u gle=%lu code=%d category=%s message=%s",
            phase,
            pid,
            caller_tid,
            caller_tid,
            static_cast<unsigned long long>(result.elapsed_ms),
            timeout_ms,
            result.gle,
            result.exception_code,
            result.exception_category.c_str(),
            result.exception.c_str());
        log_phase_state("inline_exception", phase, pid, caller_tid, result.elapsed_ms, timeout_ms);
    } else {
        diag::log_tagged_fmt("api_monitor",
            "phase_complete phase=%s pid=%u backend=inline caller_tid=%lu worker_tid=%lu elapsed_ms=%llu timeout_ms=%u gle=%lu",
            phase,
            pid,
            caller_tid,
            caller_tid,
            static_cast<unsigned long long>(result.elapsed_ms),
            timeout_ms,
            result.gle);
        log_phase_state("complete_inline", phase, pid, caller_tid, result.elapsed_ms, timeout_ms);
    }
    return result;
}

template <typename T, typename Fn>
inline phase_result_t<T> run_phase_with_timeout(const char* phase,
                                                 uint32_t pid,
                                                 uint32_t timeout_ms,
                                                 Fn&& fn) {
    const uint64_t started_ms = GetTickCount64();
    const DWORD caller_tid = GetCurrentThreadId();
    const std::string phase_name = phase ? phase : "unknown";
    diag::log_tagged_fmt("api_monitor",
        "phase_begin phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu timeout_ms=%u",
        phase,
        pid,
        caller_tid,
        timeout_ms);
    log_phase_state("begin_queue", phase, pid, caller_tid, 0, timeout_ms);

    auto promise = std::make_shared<std::promise<phase_result_t<T>>>();
    auto fn_copy = std::make_shared<typename std::decay<Fn>::type>(std::forward<Fn>(fn));
    auto cancel = std::make_shared<phase_cancel_t>();
    auto timeout_elapsed = std::make_shared<std::atomic<uint64_t>>(0);
    std::future<phase_result_t<T>> future = promise->get_future();

    auto worker_body = [promise, fn_copy, cancel, timeout_elapsed, phase_name, pid, timeout_ms, started_ms](const char* backend) mutable {
        const DWORD worker_tid = GetCurrentThreadId();
        phase_result_t<T> result;
        result.completed = true;
        try {
            SetLastError(ERROR_SUCCESS);
            std::unique_lock<std::mutex> phase_lock(g_phase_execution_mutex);
            if (cancel->requested.load(std::memory_order_acquire)) {
                result.completed = false;
                result.gle = ERROR_CANCELLED;
                result.exception = "phase cancelled before worker execution";
            } else {
                result.value = invoke_phase(*fn_copy, *cancel);
                result.gle = GetLastError();
            }
        } catch (const std::system_error& ex) {
            result.threw = true;
            result.exception = ex.what();
            result.exception_code = ex.code().value();
            result.exception_category = ex.code().category().name();
            result.gle = GetLastError();
        } catch (const std::exception& ex) {
            result.threw = true;
            result.exception = ex.what();
            result.gle = GetLastError();
        } catch (...) {
            result.threw = true;
            result.exception = "unknown exception";
            result.gle = GetLastError();
        }
        result.elapsed_ms = GetTickCount64() - started_ms;
        const bool late = cancel->requested.load(std::memory_order_acquire);
        diag::log_tagged_fmt("api_monitor",
            "phase_worker_exit phase=%s pid=%u backend=%s worker_tid=%lu elapsed_ms=%llu gle=%lu threw=%d code=%d category=%s late=%d timeout_elapsed_ms=%llu",
            phase_name.c_str(),
            pid,
            backend ? backend : "executor",
            worker_tid,
            static_cast<unsigned long long>(result.elapsed_ms),
            result.gle,
            result.threw ? 1 : 0,
            result.exception_code,
            result.exception_category.c_str(),
            late ? 1 : 0,
            static_cast<unsigned long long>(timeout_elapsed->load(std::memory_order_acquire)));
        if (late) {
            diag::log_tagged_fmt("api_monitor",
                "phase_late_complete phase=%s pid=%u backend=%s worker_tid=%lu elapsed_ms=%llu timeout_ms=%u timeout_elapsed_ms=%llu gle=%lu threw=%d",
                phase_name.c_str(),
                pid,
                backend ? backend : "executor",
                worker_tid,
                static_cast<unsigned long long>(result.elapsed_ms),
                timeout_ms,
                static_cast<unsigned long long>(timeout_elapsed->load(std::memory_order_acquire)),
                result.gle,
                result.threw ? 1 : 0);
            log_phase_state("late_complete", phase_name.c_str(), pid, worker_tid, result.elapsed_ms, timeout_ms);
        }
        try {
            promise->set_value(std::move(result));
        } catch (...) {
        }
    };

    bool posted_executor = false;
    std::string executor_reject_reason;
    mcp_standalone::downstream::producer_identity_t api_mon_id;
    api_mon_id.kind = mcp_standalone::downstream::producer_kind_t::api_monitor;
    api_mon_id.tool_name = phase ? phase : "api_monitor.phase";
    api_mon_id.target_pid = pid;
    auto api_mon_admission = mcp_standalone::downstream::scoped_admission_t::acquire(api_mon_id);
    if (!api_mon_admission.active()) {
        diag::log_tagged_fmt("api_monitor",
            "BURP-NETWORK-WORKER-REJECT phase=%s pid=%u reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            phase ? phase : "unknown", pid,
            api_mon_admission.result().reason.c_str(),
            api_mon_admission.result().quota_name.c_str(),
            api_mon_admission.result().quota_scope.c_str(),
            api_mon_admission.result().observed, api_mon_admission.result().limit);
        phase_result_t<T> reject_result;
        reject_result.threw = true;
        reject_result.exception = "downstream api_monitor capacity exhausted";
        reject_result.elapsed_ms = GetTickCount64() - started_ms;
        log_phase_state("reject_downstream", phase, pid, caller_tid, reject_result.elapsed_ms, timeout_ms);
        return reject_result;
    }
    const uint64_t api_mon_token = api_mon_admission.token();
    diag::log_tagged_fmt("api_monitor",
        "BURP-NETWORK-WORKER-ADMIT phase=%s pid=%u token=%llu",
        phase ? phase : "unknown", pid,
        static_cast<unsigned long long>(api_mon_token));
    auto admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(api_mon_admission));
    try {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "api_monitor";
        sub.label = phase ? phase : "api_monitor.phase";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::diagnostics;
        sub.priority = 3;
        sub.target_pid = pid;
        sub.lease_token = api_mon_token;
        sub.cancel_hook = [cancel]() {
            cancel->requested.store(true, std::memory_order_release);
        };
        sub.body = [worker_body, admission_ptr, phase_name, pid, api_mon_token]() mutable {
            struct admission_release_t {
                mcp_standalone::downstream::scoped_admission_t* admission;
                const char* phase;
                uint32_t pid;
                uint64_t token;
                ~admission_release_t() {
                    diag::log_tagged_fmt("api_monitor",
                        "BURP-NETWORK-WORKER-RELEASE phase=%s pid=%u token=%llu reason=worker_exit",
                        phase ? phase : "unknown", pid,
                        static_cast<unsigned long long>(token));
                    admission->release("worker_exit");
                }
            } release_guard{admission_ptr.get(), phase_name.c_str(), pid, api_mon_token};
            worker_body("executor.diagnostics");
        };
        auto submit_result = aida::infra::executor::submit(std::move(sub));
        posted_executor = submit_result.submitted;
        executor_reject_reason = submit_result.reject_reason;
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("api_monitor",
            "phase_executor_post_exception phase=%s pid=%u caller_tid=%lu message=%s",
            phase,
            pid,
            caller_tid,
            ex.what());
    } catch (...) {
        diag::log_tagged_fmt("api_monitor",
            "phase_executor_post_exception phase=%s pid=%u caller_tid=%lu message=<unknown>",
            phase,
            pid,
            caller_tid);
    }

    const auto wq = aida::network::executor_status::work_stats();
    const auto sq = aida::network::executor_status::service_stats();
    diag::log_tagged_fmt("api_monitor",
        "phase_executor_post phase=%s pid=%u caller_tid=%lu diagnostics=%d elapsed_ms=%llu wq_alive=%d wq_workers=%zu wq_pending=%llu wq_active=%u sq_alive=%d sq_workers=%zu sq_pending=%llu sq_active=%u reject=%s",
        phase,
        pid,
        caller_tid,
        posted_executor ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started_ms),
        wq.alive ? 1 : 0,
        wq.workers,
        static_cast<unsigned long long>(wq.pending),
        static_cast<unsigned>(wq.active),
        sq.alive ? 1 : 0,
        sq.workers,
        static_cast<unsigned long long>(sq.pending),
        static_cast<unsigned>(sq.active),
        executor_reject_reason.empty() ? "<none>" : executor_reject_reason.c_str());

    if (!posted_executor) {
        admission_ptr->release("executor_rejected");
        log_phase_state("executor_post_failed", phase, pid, caller_tid, GetTickCount64() - started_ms, timeout_ms);
        phase_result_t<T> result;
        result.completed = false;
        result.threw = true;
        result.gle = ERROR_BUSY;
        result.exception = executor_reject_reason.empty() ? "api_monitor executor submission failed" : executor_reject_reason;
        result.elapsed_ms = GetTickCount64() - started_ms;
        return result;
    }

    if (future.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) {
        phase_result_t<T> timed_out;
        timed_out.completed = false;
        timed_out.gle = WAIT_TIMEOUT;
        timed_out.elapsed_ms = GetTickCount64() - started_ms;
        timeout_elapsed->store(timed_out.elapsed_ms, std::memory_order_release);
        cancel->requested.store(true, std::memory_order_release);
        diag::log_tagged_fmt("api_monitor",
            "phase_timeout phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu elapsed_ms=%llu timeout_ms=%u posted=%d current_phase=%s",
            phase,
            pid,
            caller_tid,
            static_cast<unsigned long long>(timed_out.elapsed_ms),
            timeout_ms,
            posted_executor ? 1 : 0,
            phase);
        log_phase_state("timeout", phase, pid, caller_tid, timed_out.elapsed_ms, timeout_ms);
        return timed_out;
    }

    try {
        phase_result_t<T> result = future.get();
        if (result.threw) {
            diag::log_tagged_fmt("api_monitor",
                "phase_fail phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu reason=worker_exception elapsed_ms=%llu gle=%lu code=%d category=%s message=%s",
                phase,
                pid,
                caller_tid,
                static_cast<unsigned long long>(result.elapsed_ms),
                result.gle,
                result.exception_code,
                result.exception_category.c_str(),
                result.exception.c_str());
            log_phase_state("worker_exception", phase, pid, caller_tid, result.elapsed_ms, timeout_ms);
        } else {
            diag::log_tagged_fmt("api_monitor",
                "phase_complete phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu elapsed_ms=%llu gle=%lu posted=%d",
                phase,
                pid,
                caller_tid,
                static_cast<unsigned long long>(result.elapsed_ms),
                result.gle,
                posted_executor ? 1 : 0);
            log_phase_state("complete", phase, pid, caller_tid, result.elapsed_ms, timeout_ms);
        }
        return result;
    } catch (const std::system_error& ex) {
        phase_result_t<T> failed;
        failed.completed = false;
        failed.threw = true;
        failed.gle = GetLastError();
        failed.exception = ex.what();
        failed.exception_code = ex.code().value();
        failed.exception_category = ex.code().category().name();
        failed.elapsed_ms = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("api_monitor",
            "phase_fail phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu reason=future_get_system_error elapsed_ms=%llu gle=%lu code=%d category=%s message=%s",
            phase,
            pid,
            caller_tid,
            static_cast<unsigned long long>(failed.elapsed_ms),
            failed.gle,
            failed.exception_code,
            failed.exception_category.c_str(),
            failed.exception.c_str());
        log_phase_state("future_get_system_error", phase, pid, caller_tid, failed.elapsed_ms, timeout_ms);
        return failed;
    } catch (const std::exception& ex) {
        phase_result_t<T> failed;
        failed.completed = false;
        failed.threw = true;
        failed.gle = GetLastError();
        failed.exception = ex.what();
        failed.elapsed_ms = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("api_monitor",
            "phase_fail phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu reason=future_get_exception elapsed_ms=%llu gle=%lu message=%s",
            phase,
            pid,
            caller_tid,
            static_cast<unsigned long long>(failed.elapsed_ms),
            failed.gle,
            failed.exception.c_str());
        log_phase_state("future_get_exception", phase, pid, caller_tid, failed.elapsed_ms, timeout_ms);
        return failed;
    } catch (...) {
        phase_result_t<T> failed;
        failed.completed = false;
        failed.threw = true;
        failed.gle = GetLastError();
        failed.exception = "unknown future retrieval exception";
        failed.elapsed_ms = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("api_monitor",
            "phase_fail phase=%s pid=%u backend=executor.diagnostics caller_tid=%lu reason=future_get_unknown elapsed_ms=%llu gle=%lu",
            phase,
            pid,
            caller_tid,
            static_cast<unsigned long long>(failed.elapsed_ms),
            failed.gle);
        log_phase_state("future_get_unknown", phase, pid, caller_tid, failed.elapsed_ms, timeout_ms);
        return failed;
    }
}

struct driver_attach_phase_result_t {
    bool ok = false;
    bool kernel = false;
    uint32_t attached_pid_before = 0;
    uint32_t attached_pid_after = 0;
    size_t attached_count = 0;
    std::string error;
};

struct resolve_phase_result_t {
    std::vector<api_target_t> targets;
    nlohmann::json resolved = nlohmann::json::array();
    nlohmann::json unresolved = nlohmann::json::array();
    uint32_t resolved_count = 0;
    size_t module_count = 0;
};

struct process_probe_result_t {
    bool alive = false;
    bool rejected_reserved_pid = false;
    bool open_ok = false;
    bool exit_code_ok = false;
    bool snapshot_ok = false;
    bool snapshot_found = false;
    DWORD open_gle = ERROR_SUCCESS;
    DWORD exit_code_gle = ERROR_SUCCESS;
    DWORD snapshot_gle = ERROR_SUCCESS;
    DWORD exit_code = 0;
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    uint32_t thread_count = 0;
};

struct target_open_process_result_t {
    HANDLE handle = nullptr;
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    uint64_t elapsed_ms = 0;
};

struct target_native_system_info_result_t {
    SYSTEM_INFO info{};
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    uint64_t elapsed_ms = 0;
};

struct target_iswow64process_call_result_t {
    BOOL ok = FALSE;
    BOOL wow64 = FALSE;
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    uint64_t elapsed_ms = 0;
};

struct target_close_handle_result_t {
    BOOL ok = FALSE;
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    uint64_t elapsed_ms = 0;
};

struct target_arch_api_cache_t {
    bool initialized = false;
    bool ready = false;
    WORD native_processor_architecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
    DWORD native_page_size = 0;
    DWORD native_number_of_processors = 0;
    bool host_native_amd64 = false;
    bool direct_iswow64process = false;
    DWORD native_info_gle = ERROR_SUCCESS;
    DWORD native_info_seh = 0;
    uint64_t native_info_elapsed_ms = 0;
    uint64_t elapsed_ms = 0;
    const char* resolution_mode = "direct_iswow64process";
    const char* reason = "";
};

struct target_arch_probe_result_t {
    DWORD process_id = 0;
    DWORD tid = 0;
    uint32_t target_pid = 0;
    HANDLE process_handle = nullptr;
    bool open_ok = false;
    DWORD open_gle = ERROR_SUCCESS;
    DWORD open_seh = 0;
    uint64_t open_elapsed_ms = 0;
    bool cache_initialized_now = false;
    target_arch_api_cache_t cache;
    bool used_fallback_iswow64process = false;
    BOOL call_ok = FALSE;
    USHORT process_machine = 0;
    USHORT native_machine = 0;
    BOOL wow64 = FALSE;
    DWORD call_gle = ERROR_SUCCESS;
    DWORD call_seh = 0;
    uint64_t call_elapsed_ms = 0;
    bool close_ok = false;
    DWORD close_gle = ERROR_SUCCESS;
    DWORD close_seh = 0;
    uint64_t close_elapsed_ms = 0;
    bool ok = false;
    bool x64 = false;
    bool uncertain = true;
    DWORD final_gle = ERROR_SUCCESS;
    DWORD final_seh = 0;
    uint64_t elapsed_ms = 0;
    const char* phase = "entry";
    const char* decision = "uncertain";
    const char* failure_reason = "";
};

inline nlohmann::json process_probe_to_json(const process_probe_result_t& p) {
    nlohmann::json j;
    j["pid"] = p.pid;
    j["alive"] = p.alive;
    j["rejected_reserved_pid"] = p.rejected_reserved_pid;
    j["open_ok"] = p.open_ok;
    j["open_gle"] = static_cast<unsigned long>(p.open_gle);
    j["exit_code_ok"] = p.exit_code_ok;
    j["exit_code_gle"] = static_cast<unsigned long>(p.exit_code_gle);
    j["exit_code"] = static_cast<unsigned long>(p.exit_code);
    j["snapshot_ok"] = p.snapshot_ok;
    j["snapshot_gle"] = static_cast<unsigned long>(p.snapshot_gle);
    j["snapshot_found"] = p.snapshot_found;
    j["parent_pid"] = p.parent_pid;
    j["thread_count"] = p.thread_count;
    return j;
}

inline std::string trim(std::string text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

inline std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

inline std::string basename_of(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

inline std::string strip_extension(std::string name) {
    const size_t dot = name.find_last_of('.');
    if (dot != std::string::npos)
        name.resize(dot);
    return name;
}

inline std::string hex_addr(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

inline target_open_process_result_t target_open_process_seh(DWORD access, uint32_t pid) {
    target_open_process_result_t r;
    const uint64_t t0 = GetTickCount64();
    __try {
        SetLastError(ERROR_SUCCESS);
        r.handle = OpenProcess(access, FALSE, pid);
        r.gle = GetLastError();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        r.seh = GetExceptionCode();
        r.gle = GetLastError();
        r.handle = nullptr;
    }
    r.elapsed_ms = GetTickCount64() - t0;
    return r;
}

inline target_native_system_info_result_t target_get_native_system_info_seh() {
    target_native_system_info_result_t r;
    const uint64_t t0 = GetTickCount64();
    __try {
        SetLastError(ERROR_SUCCESS);
        GetNativeSystemInfo(&r.info);
        r.gle = GetLastError();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        r.seh = GetExceptionCode();
        r.gle = GetLastError();
        std::memset(&r.info, 0, sizeof(r.info));
        r.info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
    }
    r.elapsed_ms = GetTickCount64() - t0;
    return r;
}

inline target_iswow64process_call_result_t target_call_iswow64process_seh(HANDLE handle) {
    target_iswow64process_call_result_t r;
    const uint64_t t0 = GetTickCount64();
    __try {
        SetLastError(ERROR_SUCCESS);
        r.ok = handle ? IsWow64Process(handle, &r.wow64) : FALSE;
        r.gle = GetLastError();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        r.seh = GetExceptionCode();
        r.gle = GetLastError();
        r.ok = FALSE;
    }
    r.elapsed_ms = GetTickCount64() - t0;
    return r;
}

inline target_close_handle_result_t target_close_handle_seh(HANDLE handle) {
    target_close_handle_result_t r;
    const uint64_t t0 = GetTickCount64();
    __try {
        SetLastError(ERROR_SUCCESS);
        r.ok = handle ? CloseHandle(handle) : FALSE;
        r.gle = GetLastError();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        r.seh = GetExceptionCode();
        r.gle = GetLastError();
        r.ok = FALSE;
    }
    r.elapsed_ms = GetTickCount64() - t0;
    return r;
}

inline target_arch_api_cache_t& target_arch_api_cache() {
    static target_arch_api_cache_t cache;
    return cache;
}

inline std::mutex& target_arch_api_cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

inline target_arch_api_cache_t initialize_target_arch_api_cache(uint32_t target_pid, DWORD tid) {
    target_arch_api_cache_t cache;
    const DWORD self_pid = GetCurrentProcessId();
    const uint64_t start_ms = GetTickCount64();
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_direct_probe_cache_init_begin pid=%lu tid=%lu target_pid=%u mode=%s",
        self_pid,
        tid,
        target_pid,
        cache.resolution_mode);

    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_getnativesysteminfo_begin pid=%lu tid=%lu target_pid=%u elapsed_ms=%llu",
        self_pid,
        tid,
        target_pid,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    const target_native_system_info_result_t native = target_get_native_system_info_seh();
    cache.initialized = true;
    cache.native_processor_architecture = native.info.wProcessorArchitecture;
    cache.native_page_size = native.info.dwPageSize;
    cache.native_number_of_processors = native.info.dwNumberOfProcessors;
    cache.host_native_amd64 = native.seh == 0 && native.info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
    cache.direct_iswow64process = true;
    cache.native_info_gle = native.gle;
    cache.native_info_seh = native.seh;
    cache.native_info_elapsed_ms = native.elapsed_ms;
    cache.ready = cache.host_native_amd64;
    cache.reason = cache.ready ? "" : (native.seh ? "GetNativeSystemInfo SEH" : "host native architecture is not AMD64");
    cache.elapsed_ms = GetTickCount64() - start_ms;
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_getnativesysteminfo_done pid=%lu tid=%lu target_pid=%u arch=%u page_size=%lu processors=%lu host_amd64=%d gle=%lu seh=0x%08lX phase_elapsed_ms=%llu elapsed_ms=%llu",
        self_pid,
        tid,
        target_pid,
        static_cast<unsigned>(cache.native_processor_architecture),
        static_cast<unsigned long>(cache.native_page_size),
        static_cast<unsigned long>(cache.native_number_of_processors),
        cache.host_native_amd64 ? 1 : 0,
        cache.native_info_gle,
        cache.native_info_seh,
        static_cast<unsigned long long>(cache.native_info_elapsed_ms),
        static_cast<unsigned long long>(cache.elapsed_ms));
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_direct_probe_cache_init_done pid=%lu tid=%lu target_pid=%u ready=%d mode=%s reason=%s elapsed_ms=%llu",
        self_pid,
        tid,
        target_pid,
        cache.ready ? 1 : 0,
        cache.resolution_mode,
        cache.reason,
        static_cast<unsigned long long>(cache.elapsed_ms));
    return cache;
}

inline target_arch_api_cache_t resolve_target_arch_api_cache(uint32_t target_pid, DWORD tid, bool& initialized_now) {
    initialized_now = false;
    {
        std::lock_guard<std::mutex> lock(target_arch_api_cache_mutex());
        const target_arch_api_cache_t cached = target_arch_api_cache();
        if (cached.ready)
            return cached;
    }

    target_arch_api_cache_t candidate = initialize_target_arch_api_cache(target_pid, tid);
    {
        std::lock_guard<std::mutex> lock(target_arch_api_cache_mutex());
        if (candidate.ready || !target_arch_api_cache().ready)
            target_arch_api_cache() = candidate;
        initialized_now = true;
        return target_arch_api_cache();
    }
}

inline nlohmann::json target_arch_probe_to_json(const target_arch_probe_result_t& p) {
    nlohmann::json j;
    j["process_id"] = static_cast<unsigned long>(p.process_id);
    j["tid"] = static_cast<unsigned long>(p.tid);
    j["target_pid"] = p.target_pid;
    j["phase"] = p.phase;
    j["decision"] = p.decision;
    j["failure_reason"] = p.failure_reason;
    j["ok"] = p.ok;
    j["x64"] = p.x64;
    j["uncertain"] = p.uncertain;
    j["last_error"] = static_cast<unsigned long>(p.final_gle);
    j["seh"] = static_cast<unsigned long>(p.final_seh);
    j["elapsed_ms"] = p.elapsed_ms;
    j["open"] = nlohmann::json{
        {"ok", p.open_ok},
        {"handle", hex_addr(reinterpret_cast<uint64_t>(p.process_handle))},
        {"gle", static_cast<unsigned long>(p.open_gle)},
        {"seh", static_cast<unsigned long>(p.open_seh)},
        {"elapsed_ms", p.open_elapsed_ms}
    };
    j["cache_initialized_now"] = p.cache_initialized_now;
    j["cache"] = nlohmann::json{
        {"initialized", p.cache.initialized},
        {"ready", p.cache.ready},
        {"resolution_mode", p.cache.resolution_mode},
        {"reason", p.cache.reason},
        {"native_processor_architecture", static_cast<unsigned>(p.cache.native_processor_architecture)},
        {"native_page_size", static_cast<unsigned long>(p.cache.native_page_size)},
        {"native_number_of_processors", static_cast<unsigned long>(p.cache.native_number_of_processors)},
        {"host_native_amd64", p.cache.host_native_amd64},
        {"direct_iswow64process", p.cache.direct_iswow64process},
        {"native_info_gle", static_cast<unsigned long>(p.cache.native_info_gle)},
        {"native_info_seh", static_cast<unsigned long>(p.cache.native_info_seh)},
        {"native_info_elapsed_ms", p.cache.native_info_elapsed_ms},
        {"elapsed_ms", p.cache.elapsed_ms}
    };
    j["call"] = nlohmann::json{
        {"used_fallback_iswow64process", p.used_fallback_iswow64process},
        {"ok", p.call_ok ? true : false},
        {"process_machine", static_cast<unsigned>(p.process_machine)},
        {"native_machine", static_cast<unsigned>(p.native_machine)},
        {"wow64", p.wow64 ? true : false},
        {"gle", static_cast<unsigned long>(p.call_gle)},
        {"seh", static_cast<unsigned long>(p.call_seh)},
        {"elapsed_ms", p.call_elapsed_ms}
    };
    j["close"] = nlohmann::json{
        {"ok", p.close_ok},
        {"gle", static_cast<unsigned long>(p.close_gle)},
        {"seh", static_cast<unsigned long>(p.close_seh)},
        {"elapsed_ms", p.close_elapsed_ms}
    };
    return j;
}

inline bool parse_u64(const std::string& text, uint64_t& out) {
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        return false;
    out = static_cast<uint64_t>(value);
    return true;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0)
            os << ' ';
        os << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return os.str();
}

inline bool module_name_matches(const driver_bridge::module_info_t& module, const std::string& requested) {
    if (requested.empty())
        return true;
    const std::string want = to_lower(strip_extension(basename_of(requested)));
    const std::string have_name = to_lower(strip_extension(basename_of(module.name)));
    const std::string have_path = to_lower(strip_extension(basename_of(module.path)));
    return have_name == want || have_path == want;
}

inline api_kind_t infer_kind(const std::string& function_name) {
    const std::string name = to_lower(function_name);
    if (name == "send")
        return api_kind_t::send_linear;
    if (name == "wsasend")
        return api_kind_t::wsa_send;
    if (name == "sendto")
        return api_kind_t::send_to;
    if (name == "wsasendto")
        return api_kind_t::wsa_send_to;
    if (name == "recv")
        return api_kind_t::recv_linear;
    if (name == "wsarecv")
        return api_kind_t::wsa_recv;
    if (name == "recvfrom")
        return api_kind_t::recv_from;
    if (name == "wsarecvfrom")
        return api_kind_t::wsa_recv_from;
    if (name == "connect" || name == "wsaconnect")
        return api_kind_t::connect_call;
    if (name == "deviceiocontrol")
        return api_kind_t::device_io_control;
    if (name == "ntdeviceiocontrolfile" || name == "zwdeviceiocontrolfile")
        return api_kind_t::nt_device_io_control;
    if (name == "writefile" || name == "writefileex")
        return api_kind_t::write_file;
    if (name == "readfile" || name == "readfileex")
        return api_kind_t::read_file;
    if (name == "encryptmessage")
        return api_kind_t::encrypt_message;
    if (name == "ssl_write" || name == "pr_write" || name == "sslencryptpacket")
        return api_kind_t::custom_linear;
    return api_kind_t::generic;
}

inline const char* kind_name(api_kind_t kind) {
    switch (kind) {
    case api_kind_t::send_linear: return "send";
    case api_kind_t::wsa_send: return "wsasend";
    case api_kind_t::send_to: return "sendto";
    case api_kind_t::wsa_send_to: return "wsasendto";
    case api_kind_t::recv_linear: return "recv";
    case api_kind_t::wsa_recv: return "wsarecv";
    case api_kind_t::recv_from: return "recvfrom";
    case api_kind_t::wsa_recv_from: return "wsarecvfrom";
    case api_kind_t::connect_call: return "connect";
    case api_kind_t::device_io_control: return "deviceiocontrol";
    case api_kind_t::nt_device_io_control: return "ntdeviceiocontrolfile";
    case api_kind_t::write_file: return "writefile";
    case api_kind_t::read_file: return "readfile";
    case api_kind_t::encrypt_message: return "encryptmessage";
    case api_kind_t::custom_linear: return "linear";
    default: return "generic";
    }
}

inline uint64_t register_value(const driver_bridge::thread_context_t& ctx, int index) {
    switch (index) {
    case 0: return ctx.rcx;
    case 1: return ctx.rdx;
    case 2: return ctx.r8;
    case 3: return ctx.r9;
    default: return 0;
    }
}

inline register_snapshot_t snapshot_registers(const driver_bridge::thread_context_t& ctx) {
    register_snapshot_t r;
    r.rax = ctx.rax;
    r.rbx = ctx.rbx;
    r.rcx = ctx.rcx;
    r.rdx = ctx.rdx;
    r.rsi = ctx.rsi;
    r.rdi = ctx.rdi;
    r.rbp = ctx.rbp;
    r.rsp = ctx.rsp;
    r.r8 = ctx.r8;
    r.r9 = ctx.r9;
    r.r10 = ctx.r10;
    r.r11 = ctx.r11;
    r.r12 = ctx.r12;
    r.r13 = ctx.r13;
    r.r14 = ctx.r14;
    r.r15 = ctx.r15;
    r.rip = ctx.rip;
    r.rflags = ctx.rflags;
    return r;
}

inline bool read_target(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out) {
    out.clear();
    if (pid == 0 || address == 0 || size == 0)
        return false;
    if (!driver_bridge::read_memory_for(pid, address, size, out))
        return false;
    if (out.size() > size)
        out.resize(size);
    return !out.empty();
}

template <typename T>
inline bool read_target_value(uint32_t pid, uint64_t address, T& out) {
    std::vector<uint8_t> raw;
    if (!read_target(pid, address, sizeof(T), raw) || raw.size() < sizeof(T))
        return false;
    std::memcpy(&out, raw.data(), sizeof(T));
    return true;
}

inline uint64_t stack_arg64(uint32_t pid, uint64_t rsp, uint32_t arg_index) {
    uint64_t value = 0;
    const uint64_t address = rsp + 0x28 + static_cast<uint64_t>(arg_index) * 8;
    read_target_value(pid, address, value);
    return value;
}

inline uint64_t bounded_size(uint64_t requested, uint32_t max_capture_bytes) {
    if (requested == 0)
        return 0;
    if (requested > max_capture_bytes)
        return max_capture_bytes;
    return requested;
}

inline void append_buffer_capture(std::vector<buffer_capture_t>& buffers,
                                  uint32_t pid,
                                  const std::string& kind,
                                  const std::string& direction,
                                  uint64_t address,
                                  uint64_t requested_size,
                                  uint32_t max_capture_bytes,
                                  bool capture_bytes) {
    buffer_capture_t b;
    b.kind = kind;
    b.direction = direction;
    b.address = address;
    b.requested_size = requested_size;
    b.truncated = requested_size > max_capture_bytes;
    if (capture_bytes && address != 0 && requested_size != 0) {
        const uint64_t take = bounded_size(requested_size, max_capture_bytes);
        std::vector<uint8_t> raw;
        if (read_target(pid, address, static_cast<size_t>(take), raw)) {
            b.bytes = std::move(raw);
            b.captured_size = static_cast<uint64_t>(b.bytes.size());
            b.readable = true;
        }
    }
    buffers.push_back(std::move(b));
}

inline void capture_linear_buffer(std::vector<buffer_capture_t>& buffers,
                                  uint32_t pid,
                                  const std::string& direction,
                                  uint64_t address,
                                  uint64_t size,
                                  uint32_t max_capture_bytes,
                                  bool capture_bytes) {
    append_buffer_capture(buffers, pid, "linear", direction, address, size, max_capture_bytes, capture_bytes);
}

inline void capture_wsabufs(std::vector<buffer_capture_t>& buffers,
                            uint32_t pid,
                            uint64_t array_address,
                            uint64_t count,
                            const std::string& direction,
                            uint32_t max_capture_bytes,
                            bool capture_bytes,
                            nlohmann::json& metadata) {
    struct remote_wsabuf_t {
        uint32_t len;
        uint32_t pad;
        uint64_t buf;
    };

    metadata["wsabuf_array"] = hex_addr(array_address);
    metadata["wsabuf_count_requested"] = count;
    if (array_address == 0 || count == 0)
        return;
    if (count > 16)
        count = 16;
    metadata["wsabuf_count_parsed"] = count;

    std::vector<uint8_t> raw;
    if (!read_target(pid, array_address, static_cast<size_t>(count) * sizeof(remote_wsabuf_t), raw))
        return;

    const size_t parsed = raw.size() / sizeof(remote_wsabuf_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_wsabuf_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_wsabuf_t), sizeof(entry));
        append_buffer_capture(buffers, pid, "wsabuf", direction, entry.buf, entry.len, max_capture_bytes, capture_bytes);
    }
}

inline void capture_sec_buffers(std::vector<buffer_capture_t>& buffers,
                                uint32_t pid,
                                uint64_t desc_address,
                                uint32_t max_capture_bytes,
                                bool capture_bytes,
                                nlohmann::json& metadata) {
    struct remote_sec_buffer_desc_t {
        uint32_t ulVersion;
        uint32_t cBuffers;
        uint64_t pBuffers;
    };
    struct remote_sec_buffer_t {
        uint32_t cbBuffer;
        uint32_t BufferType;
        uint64_t pvBuffer;
    };

    metadata["sec_buffer_desc"] = hex_addr(desc_address);
    if (desc_address == 0)
        return;

    remote_sec_buffer_desc_t desc{};
    if (!read_target_value(pid, desc_address, desc))
        return;
    metadata["sec_buffer_count_requested"] = desc.cBuffers;
    if (desc.cBuffers == 0 || desc.pBuffers == 0)
        return;
    if (desc.cBuffers > 16)
        desc.cBuffers = 16;
    metadata["sec_buffer_array"] = hex_addr(desc.pBuffers);
    metadata["sec_buffer_count_parsed"] = desc.cBuffers;

    std::vector<uint8_t> raw;
    if (!read_target(pid, desc.pBuffers, static_cast<size_t>(desc.cBuffers) * sizeof(remote_sec_buffer_t), raw))
        return;
    const size_t parsed = raw.size() / sizeof(remote_sec_buffer_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_sec_buffer_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_sec_buffer_t), sizeof(entry));
        if ((entry.BufferType & 0xFFFFu) != 1u)
            continue;
        append_buffer_capture(buffers, pid, "sec_buffer", "outbound", entry.pvBuffer, entry.cbBuffer,
                              max_capture_bytes, capture_bytes);
    }
}

inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline std::string format_ipv4(const uint8_t* p) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(p[0]),
                  static_cast<unsigned>(p[1]),
                  static_cast<unsigned>(p[2]),
                  static_cast<unsigned>(p[3]));
    return buf;
}

inline std::string format_ipv6(const uint8_t* p) {
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                  p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return buf;
}

inline bool parse_sockaddr(uint32_t pid, uint64_t address, uint64_t length, nlohmann::json& out) {
    if (address == 0 || length < 4)
        return false;
    if (length > 64)
        length = 64;
    std::vector<uint8_t> raw;
    if (!read_target(pid, address, static_cast<size_t>(length), raw) || raw.size() < 4)
        return false;
    const uint16_t family = static_cast<uint16_t>(raw[0] | (raw[1] << 8));
    out["sockaddr"] = hex_addr(address);
    out["family"] = family;
    if (family == 2 && raw.size() >= 8) {
        out["family_name"] = "AF_INET";
        out["port"] = read_be16(raw.data() + 2);
        out["address"] = format_ipv4(raw.data() + 4);
        return true;
    }
    if (family == 23 && raw.size() >= 24) {
        out["family_name"] = "AF_INET6";
        out["port"] = read_be16(raw.data() + 2);
        out["address"] = format_ipv6(raw.data() + 8);
        return true;
    }
    return true;
}

inline bool lookup_socket(uint32_t pid, uint64_t socket_handle, driver_bridge::socket_info_t& out) {
    if (socket_handle == 0)
        return false;
    const uint64_t now = GetTickCount64();
    std::vector<driver_bridge::socket_info_t> sockets;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.socket_cache.timestamp_ms != 0 &&
            now - g_state.socket_cache.timestamp_ms < 1000) {
            sockets = g_state.socket_cache.sockets;
        }
    }
    if (sockets.empty()) {
        sockets = driver_bridge::get_socket_handles(pid);
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.socket_cache.timestamp_ms = now;
        g_state.socket_cache.sockets = sockets;
    }
    for (const auto& s : sockets) {
        if (s.handle_value == socket_handle) {
            out = s;
            return true;
        }
    }
    return false;
}

inline nlohmann::json socket_to_json(const driver_bridge::socket_info_t& s) {
    nlohmann::json j;
    j["handle"] = hex_addr(s.handle_value);
    j["afd_endpoint"] = hex_addr(s.afd_endpoint_addr);
    j["pid"] = s.pid;
    j["protocol"] = s.protocol == 6 ? "TCP" : (s.protocol == 17 ? "UDP" : std::to_string(s.protocol));
    j["state"] = s.state;
    j["local_port"] = s.local_port;
    j["remote_port"] = s.remote_port;
    j["address_family"] = s.address_family;
    if (s.address_family == 23) {
        j["local_address"] = format_ipv6(s.local_addr);
        j["remote_address"] = format_ipv6(s.remote_addr);
    } else {
        j["local_address"] = format_ipv4(s.local_addr);
        j["remote_address"] = format_ipv4(s.remote_addr);
    }
    return j;
}

inline void add_socket_metadata(uint32_t pid, uint64_t socket_handle, nlohmann::json& metadata) {
    metadata["socket_handle"] = hex_addr(socket_handle);
    driver_bridge::socket_info_t sock{};
    if (lookup_socket(pid, socket_handle, sock))
        metadata["socket"] = socket_to_json(sock);
}

inline nlohmann::json ioctl_to_json(uint32_t code) {
    nlohmann::json j;
    j["code"] = hex_addr(code);
    j["device_type"] = static_cast<uint32_t>((code >> 16) & 0xFFFFu);
    j["access"] = static_cast<uint32_t>((code >> 14) & 0x3u);
    j["function"] = static_cast<uint32_t>((code >> 2) & 0xFFFu);
    j["method"] = static_cast<uint32_t>(code & 0x3u);
    return j;
}

inline bool address_in_modules(uint64_t address,
                               const std::vector<driver_bridge::module_info_t>& modules,
                               std::string& module_name,
                               uint64_t& module_offset) {
    for (const auto& m : modules) {
        if (address >= m.base && address < m.base + m.size) {
            module_name = !m.name.empty() ? m.name : basename_of(m.path);
            module_offset = address - m.base;
            return true;
        }
    }
    module_name.clear();
    module_offset = 0;
    return false;
}

inline bool is_code_address(uint64_t address, const std::vector<driver_bridge::module_info_t>& modules) {
    if (address < 0x10000)
        return false;
    std::string name;
    uint64_t offset = 0;
    return address_in_modules(address, modules, name, offset);
}

inline uint64_t read_return_address(uint32_t pid, uint64_t rsp) {
    uint64_t value = 0;
    read_target_value(pid, rsp, value);
    return value;
}

inline uint64_t find_callsite(uint32_t pid, uint64_t return_address) {
    if (return_address < 16)
        return 0;
    std::vector<uint8_t> raw;
    if (!read_target(pid, return_address - 8, 8, raw) || raw.size() < 8)
        return 0;
    if (raw[3] == 0xE8)
        return return_address - 5;
    if (raw[6] == 0xFF && ((raw[7] >> 3) & 7) == 2)
        return return_address - 2;
    if ((raw[5] & 0xF0) == 0x40 && raw[6] == 0xFF && ((raw[7] >> 3) & 7) == 2)
        return return_address - 3;
    if (raw[2] == 0xFF && ((raw[3] >> 3) & 7) == 2)
        return return_address - 6;
    if ((raw[1] & 0xF0) == 0x40 && raw[2] == 0xFF && ((raw[3] >> 3) & 7) == 2)
        return return_address - 7;
    return 0;
}

inline std::vector<frame_t> capture_callstack(uint32_t pid,
                                              const driver_bridge::thread_context_t& ctx,
                                              uint64_t return_address,
                                              const std::vector<driver_bridge::module_info_t>& modules) {
    std::vector<frame_t> frames;
    auto add_frame = [&](uint64_t address) {
        if (!is_code_address(address, modules))
            return;
        for (const auto& existing : frames) {
            if (existing.address == address)
                return;
        }
        frame_t f;
        f.address = address;
        address_in_modules(address, modules, f.module_name, f.module_offset);
        frames.push_back(std::move(f));
    };

    add_frame(ctx.rip);
    add_frame(return_address);

    uint64_t rbp = ctx.rbp;
    for (int i = 0; i < 24 && rbp >= 0x10000; ++i) {
        uint64_t next_rbp = 0;
        uint64_t ret = 0;
        if (!read_target_value(pid, rbp, next_rbp) || !read_target_value(pid, rbp + 8, ret))
            break;
        add_frame(ret);
        if (next_rbp <= rbp)
            break;
        rbp = next_rbp;
    }

    if (frames.size() < 4) {
        std::vector<uint8_t> stack;
        if (read_target(pid, ctx.rsp, 0x200, stack)) {
            const size_t aligned = stack.size() & ~static_cast<size_t>(7);
            for (size_t off = 0; off < aligned && frames.size() < 24; off += 8) {
                uint64_t candidate = 0;
                std::memcpy(&candidate, stack.data() + off, sizeof(candidate));
                add_frame(candidate);
            }
        }
    }
    return frames;
}

inline bool local_export_rva_fallback(const std::string& module_name,
                                      const std::string& function_name,
                                      const std::vector<driver_bridge::module_info_t>& target_modules,
                                      uint64_t& out_address,
                                      std::string& out_module) {
    if (module_name.empty())
        return false;
    HMODULE local_module = GetModuleHandleA(module_name.c_str());
    if (!local_module && module_name.find('.') == std::string::npos) {
        std::string with_ext = module_name + ".dll";
        local_module = GetModuleHandleA(with_ext.c_str());
    }
    if (!local_module)
        return false;
    FARPROC proc = GetProcAddress(local_module, function_name.c_str());
    if (!proc)
        return false;
    HMODULE owner = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(proc), &owner) || !owner)
        return false;
    char owner_path[MAX_PATH] = {};
    GetModuleFileNameA(owner, owner_path, MAX_PATH);
    const std::string owner_base = basename_of(owner_path);
    const uint64_t rva = reinterpret_cast<uint64_t>(proc) - reinterpret_cast<uint64_t>(owner);
    for (const auto& m : target_modules) {
        if (!module_name_matches(m, owner_base))
            continue;
        out_address = m.base + rva;
        out_module = !m.name.empty() ? m.name : owner_base;
        return true;
    }
    return false;
}

inline bool resolve_request(uint32_t pid,
                            const api_request_t& request,
                            const std::vector<driver_bridge::module_info_t>& modules,
                            api_target_t& out,
                            const phase_cancel_t* cancel = nullptr) {
    const uint64_t started_ms = GetTickCount64();
    uint64_t manual_address = 0;
    if (parse_u64(request.original, manual_address) && manual_address != 0) {
        out.request = request;
        out.address = manual_address;
        out.resolved_module.clear();
        out.module_base = 0;
        out.module_offset = 0;
        out.active = true;
        diag::log_tagged_fmt("api_monitor",
                             "resolve_request manual pid=%u api=%s address=%s elapsed_ms=%llu",
                             pid,
                             request.original.c_str(),
                             hex_addr(manual_address).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return true;
    }

    bool resolved = false;
    uint64_t address = 0;
    std::string module_name;

    if (!request.module_name.empty()) {
        const uint64_t local_start_ms = GetTickCount64();
        resolved = local_export_rva_fallback(request.module_name, request.function_name, modules, address, module_name);
        diag::log_tagged_fmt("api_monitor",
                             "resolve_request local_export pid=%u module=%s function=%s ok=%d address=%s resolved_module=%s elapsed_ms=%llu",
                             pid,
                             request.module_name.c_str(),
                             request.function_name.c_str(),
                             resolved ? 1 : 0,
                             resolved ? hex_addr(address).c_str() : "0x0",
                             module_name.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - local_start_ms));
    }

    if (!resolved) {
        for (const auto& m : modules) {
            if (cancel && cancel->requested.load(std::memory_order_acquire)) {
                SetLastError(ERROR_CANCELLED);
                return false;
            }
            if (!module_name_matches(m, request.module_name))
                continue;
            const uint64_t module_start_ms = GetTickCount64();
            const uint64_t candidate = driver_bridge::resolve_export_for(pid, m.base, request.function_name.c_str());
            const uint64_t elapsed_ms = GetTickCount64() - module_start_ms;
            if (elapsed_ms >= 250 || candidate != 0) {
                const std::string candidate_module = !m.name.empty() ? m.name : basename_of(m.path);
                diag::log_tagged_fmt("api_monitor",
                                     "resolve_request driver_export pid=%u module=%s base=%s function=%s ok=%d address=%s elapsed_ms=%llu",
                                     pid,
                                     candidate_module.c_str(),
                                     hex_addr(m.base).c_str(),
                                     request.function_name.c_str(),
                                     candidate != 0 ? 1 : 0,
                                     candidate != 0 ? hex_addr(candidate).c_str() : "0x0",
                                     static_cast<unsigned long long>(elapsed_ms));
            }
            if (candidate == 0)
                continue;
            address = candidate;
            module_name = !m.name.empty() ? m.name : basename_of(m.path);
            resolved = true;
            break;
        }
    }

    if (!resolved) {
        diag::log_tagged_fmt("api_monitor",
                             "resolve_request failed pid=%u module=%s function=%s elapsed_ms=%llu module_count=%zu",
                             pid,
                             request.module_name.c_str(),
                             request.function_name.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             modules.size());
        return false;
    }

    diag::log_tagged_fmt("api_monitor",
                         "resolve_request resolved pid=%u module=%s function=%s address=%s resolved_module=%s elapsed_ms=%llu",
                         pid,
                         request.module_name.c_str(),
                         request.function_name.c_str(),
                         hex_addr(address).c_str(),
                         module_name.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));

    out.request = request;
    out.address = address;
    out.resolved_module = module_name;
    out.active = true;
    for (const auto& m : modules) {
        if (address >= m.base && address < m.base + m.size) {
            out.module_base = m.base;
            out.module_offset = address - m.base;
            if (out.resolved_module.empty())
                out.resolved_module = !m.name.empty() ? m.name : basename_of(m.path);
            break;
        }
    }
    return true;
}

inline api_request_t parse_api_string(const std::string& text) {
    api_request_t request;
    request.original = trim(text);
    std::string spec = request.original;
    const size_t bang = spec.find('!');
    if (bang != std::string::npos) {
        request.module_name = trim(spec.substr(0, bang));
        request.function_name = trim(spec.substr(bang + 1));
    } else {
        uint64_t addr = 0;
        if (parse_u64(spec, addr)) {
            request.function_name = spec;
        } else {
            request.function_name = trim(spec);
        }
    }
    request.kind = infer_kind(request.function_name);
    if (request.kind == api_kind_t::custom_linear) {
        request.buffer_reg = 1;
        request.size_reg = 2;
    }
    return request;
}

inline api_kind_t parse_kind_override(const std::string& text, api_kind_t fallback) {
    const std::string v = to_lower(text);
    if (v == "linear")
        return api_kind_t::custom_linear;
    if (v == "wsabuf" || v == "wsabuf_array")
        return api_kind_t::wsa_send;
    if (v == "sec_buffer" || v == "secbuffer" || v == "sec_buffer_desc")
        return api_kind_t::encrypt_message;
    return fallback;
}

inline bool parse_request_json(const nlohmann::json& value, api_request_t& out, std::string& error) {
    if (value.is_string()) {
        out = parse_api_string(value.get<std::string>());
        if (out.original.empty()) {
            error = "empty api entry";
            return false;
        }
        return true;
    }
    if (!value.is_object()) {
        error = "api entries must be strings or objects";
        return false;
    }
    const std::string api = value.value("api", value.value("name", std::string{}));
    if (api.empty()) {
        error = "api object requires api";
        return false;
    }
    out = parse_api_string(api);
    if (value.contains("buffer_reg") && value["buffer_reg"].is_number_integer())
        out.buffer_reg = value["buffer_reg"].get<int>();
    if (value.contains("size_reg") && value["size_reg"].is_number_integer())
        out.size_reg = value["size_reg"].get<int>();
    if (value.contains("buffer_kind") && value["buffer_kind"].is_string())
        out.kind = parse_kind_override(value["buffer_kind"].get<std::string>(), out.kind);
    return true;
}

inline process_probe_result_t process_exists_probe(uint32_t pid) {
    const uint64_t start_ms = GetTickCount64();
    process_probe_result_t result;
    result.pid = pid;
    if (pid == 0 || pid == 4) {
        result.rejected_reserved_pid = true;
        result.open_gle = ERROR_INVALID_PARAMETER;
        result.snapshot_gle = ERROR_INVALID_PARAMETER;
        diag::log_tagged_fmt("api_monitor",
            "process_exists_probe pid=%u rejected_reserved=1 elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        SetLastError(ERROR_INVALID_PARAMETER);
        return result;
    }

    SetLastError(ERROR_SUCCESS);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    result.open_ok = h != nullptr;
    result.open_gle = h ? ERROR_SUCCESS : GetLastError();
    if (h) {
        SetLastError(ERROR_SUCCESS);
        result.exit_code_ok = GetExitCodeProcess(h, &result.exit_code) != FALSE;
        result.exit_code_gle = result.exit_code_ok ? ERROR_SUCCESS : GetLastError();
        result.alive = result.exit_code_ok && result.exit_code == STILL_ACTIVE;
        CloseHandle(h);
    }

    SetLastError(ERROR_SUCCESS);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    result.snapshot_ok = snapshot != INVALID_HANDLE_VALUE;
    result.snapshot_gle = result.snapshot_ok ? ERROR_SUCCESS : GetLastError();
    if (result.snapshot_ok) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    result.snapshot_found = true;
                    result.parent_pid = pe.th32ParentProcessID;
                    result.thread_count = pe.cntThreads;
                    break;
                }
            } while (Process32NextW(snapshot, &pe));
        } else {
            result.snapshot_gle = GetLastError();
        }
        CloseHandle(snapshot);
    }

    diag::log_tagged_fmt("api_monitor",
        "process_exists_probe pid=%u alive=%d open_ok=%d open_gle=%lu exit_ok=%d exit_gle=%lu exit_code=%lu snapshot_ok=%d snapshot_gle=%lu snapshot_found=%d parent_pid=%u thread_count=%u elapsed_ms=%llu",
        pid,
        result.alive ? 1 : 0,
        result.open_ok ? 1 : 0,
        result.open_gle,
        result.exit_code_ok ? 1 : 0,
        result.exit_code_gle,
        result.exit_code,
        result.snapshot_ok ? 1 : 0,
        result.snapshot_gle,
        result.snapshot_found ? 1 : 0,
        result.parent_pid,
        result.thread_count,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));

    if (!result.open_ok) {
        SetLastError(result.open_gle);
    } else if (!result.exit_code_ok) {
        SetLastError(result.exit_code_gle);
    } else {
        SetLastError(ERROR_SUCCESS);
    }
    return result;
}

inline bool process_exists(uint32_t pid) {
    return process_exists_probe(pid).alive;
}

inline target_arch_probe_result_t target_arch_probe(uint32_t pid) {
    target_arch_probe_result_t result;
    const uint64_t start_ms = GetTickCount64();
    result.process_id = GetCurrentProcessId();
    result.tid = GetCurrentThreadId();
    result.target_pid = pid;
    result.phase = "enter";
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_enter pid=%lu tid=%lu target_pid=%u",
        result.process_id,
        result.tid,
        result.target_pid);

    result.phase = "open_process";
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_open_process_begin pid=%lu tid=%lu target_pid=%u access=0x%08lX elapsed_ms=%llu",
        result.process_id,
        result.tid,
        result.target_pid,
        static_cast<unsigned long>(PROCESS_QUERY_LIMITED_INFORMATION),
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    const target_open_process_result_t open = target_open_process_seh(PROCESS_QUERY_LIMITED_INFORMATION, pid);
    result.process_handle = open.handle;
    result.open_ok = open.handle != nullptr;
    result.open_gle = open.gle;
    result.open_seh = open.seh;
    result.open_elapsed_ms = open.elapsed_ms;
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_open_process pid=%lu tid=%lu target_pid=%u handle=%p gle=%lu seh=0x%08lX phase_elapsed_ms=%llu elapsed_ms=%llu",
        result.process_id,
        result.tid,
        result.target_pid,
        result.process_handle,
        result.open_gle,
        result.open_seh,
        static_cast<unsigned long long>(result.open_elapsed_ms),
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    if (!result.open_ok) {
        result.ok = false;
        result.x64 = false;
        result.uncertain = true;
        result.final_gle = result.open_seh ? result.open_seh : result.open_gle;
        result.final_seh = result.open_seh;
        result.phase = "open_process";
        result.decision = "fail_closed";
        result.failure_reason = result.open_seh ? "OpenProcess SEH" : "OpenProcess failed";
        result.elapsed_ms = GetTickCount64() - start_ms;
        diag::log_tagged_fmt("api_monitor",
            "target_is_x64_final pid=%lu tid=%lu target_pid=%u result=0 uncertain=1 phase=%s reason=%s last_error=%lu seh=0x%08lX elapsed_ms=%llu",
            result.process_id,
            result.tid,
            result.target_pid,
            result.phase,
            result.failure_reason,
            result.final_gle,
            result.final_seh,
            static_cast<unsigned long long>(result.elapsed_ms));
        SetLastError(result.final_gle);
        return result;
    }

    result.phase = "resolve_cache";
    bool initialized_now = false;
    const target_arch_api_cache_t cache = resolve_target_arch_api_cache(pid, result.tid, initialized_now);
    result.cache_initialized_now = initialized_now;
    result.cache = cache;
    result.native_machine = cache.host_native_amd64 ? IMAGE_FILE_MACHINE_AMD64 : 0;
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_resolve_cache_done pid=%lu tid=%lu target_pid=%u initialized_now=%d ready=%d mode=%s native_arch=%u host_amd64=%d reason=%s elapsed_ms=%llu",
        result.process_id,
        result.tid,
        result.target_pid,
        initialized_now ? 1 : 0,
        cache.ready ? 1 : 0,
        cache.resolution_mode,
        static_cast<unsigned>(cache.native_processor_architecture),
        cache.host_native_amd64 ? 1 : 0,
        cache.reason,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));

    if (!cache.ready) {
        result.phase = "resolve_cache";
        result.ok = false;
        result.x64 = false;
        result.uncertain = true;
        result.final_seh = cache.native_info_seh;
        result.final_gle = result.final_seh ? result.final_seh : (cache.native_info_gle ? cache.native_info_gle : ERROR_NOT_SUPPORTED);
        result.decision = "fail_closed";
        result.failure_reason = cache.reason && cache.reason[0] ? cache.reason : "host architecture probe unavailable";
    } else {
        result.phase = "IsWow64Process";
        result.used_fallback_iswow64process = true;
        diag::log_tagged_fmt("api_monitor",
            "target_is_x64_iswow64process_begin pid=%lu tid=%lu target_pid=%u handle=%p mode=%s native_arch=%u elapsed_ms=%llu",
            result.process_id,
            result.tid,
            result.target_pid,
            result.process_handle,
            cache.resolution_mode,
            static_cast<unsigned>(cache.native_processor_architecture),
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        const target_iswow64process_call_result_t call = target_call_iswow64process_seh(result.process_handle);
        result.call_ok = call.ok;
        result.wow64 = call.wow64;
        result.process_machine = call.wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_UNKNOWN;
        result.native_machine = IMAGE_FILE_MACHINE_AMD64;
        result.call_gle = call.gle;
        result.call_seh = call.seh;
        result.call_elapsed_ms = call.elapsed_ms;
        result.final_seh = call.seh;
        result.final_gle = call.seh ? call.seh : call.gle;
        result.ok = call.ok && call.seh == 0;
#ifdef _WIN64
        result.x64 = result.ok && cache.host_native_amd64 && !call.wow64;
#else
        result.x64 = false;
#endif
        result.uncertain = !result.ok;
        result.decision = result.ok ? (result.x64 ? "native_x64_direct" : "not_native_x64_direct") : "fail_closed";
        result.failure_reason = result.ok ? (result.x64 ? "" : "direct IsWow64Process reported WOW64 or non-AMD64 host") : (call.seh ? "IsWow64Process SEH" : "IsWow64Process failed");
        diag::log_tagged_fmt("api_monitor",
            "target_is_x64_iswow64process_done pid=%lu tid=%lu target_pid=%u handle=%p ok=%d wow64=%d process_machine=0x%04X native_machine=0x%04X seh=0x%08lX call_gle=%lu result=%d uncertain=%d phase_elapsed_ms=%llu elapsed_ms=%llu",
            result.process_id,
            result.tid,
            result.target_pid,
            result.process_handle,
            call.ok ? 1 : 0,
            call.wow64 ? 1 : 0,
            static_cast<unsigned>(result.process_machine),
            static_cast<unsigned>(result.native_machine),
            call.seh,
            call.gle,
            result.x64 ? 1 : 0,
            result.uncertain ? 1 : 0,
            static_cast<unsigned long long>(call.elapsed_ms),
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
    }

    result.phase = result.phase ? result.phase : "close_handle";
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_closehandle_begin pid=%lu tid=%lu target_pid=%u handle=%p elapsed_ms=%llu",
        result.process_id,
        result.tid,
        result.target_pid,
        result.process_handle,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    const target_close_handle_result_t close = target_close_handle_seh(result.process_handle);
    result.close_ok = close.ok != FALSE;
    result.close_gle = close.gle;
    result.close_seh = close.seh;
    result.close_elapsed_ms = close.elapsed_ms;
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_closehandle_done pid=%lu tid=%lu target_pid=%u handle=%p ok=%d gle=%lu seh=0x%08lX phase_elapsed_ms=%llu elapsed_ms=%llu",
        result.process_id,
        result.tid,
        result.target_pid,
        result.process_handle,
        result.close_ok ? 1 : 0,
        result.close_gle,
        result.close_seh,
        static_cast<unsigned long long>(result.close_elapsed_ms),
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    if (!result.close_ok && result.final_gle == ERROR_SUCCESS) {
        result.final_gle = result.close_seh ? result.close_seh : result.close_gle;
        result.final_seh = result.close_seh;
    }
    if (!result.ok && result.final_gle == ERROR_SUCCESS)
        result.final_gle = ERROR_INVALID_FUNCTION;
    result.elapsed_ms = GetTickCount64() - start_ms;
    diag::log_tagged_fmt("api_monitor",
        "target_is_x64_final pid=%lu tid=%lu target_pid=%u result=%d ok=%d uncertain=%d phase=%s decision=%s reason=%s last_error=%lu seh=0x%08lX elapsed_ms=%llu close_ok=%d close_gle=%lu",
        result.process_id,
        result.tid,
        result.target_pid,
        result.x64 ? 1 : 0,
        result.ok ? 1 : 0,
        result.uncertain ? 1 : 0,
        result.phase,
        result.decision,
        result.failure_reason,
        result.final_gle,
        result.final_seh,
        static_cast<unsigned long long>(result.elapsed_ms),
        result.close_ok ? 1 : 0,
        result.close_gle);
    SetLastError(result.final_gle);
    return result;
}

inline bool target_is_x64(uint32_t pid) {
    const target_arch_probe_result_t probe = target_arch_probe(pid);
    SetLastError(probe.final_gle);
    return probe.ok && probe.x64;
}

inline bool ensure_driver_attached(uint32_t pid, std::string& error) {
    if (!driver_bridge::using_kernel_driver()) {
        error = "Driver bridge is not connected. Attach with sessions_manage action=attach_pid first.";
        return false;
    }
    if (driver_bridge::attached_pid() == pid)
        return true;
    const auto attached = driver_bridge::attached_pids();
    for (uint32_t attached_pid : attached) {
        if (attached_pid == pid) {
            if (!driver_bridge::set_active_pid(pid)) {
                error = "Failed to select attached PID " + std::to_string(pid);
                return false;
            }
            return true;
        }
    }
    if (!driver_bridge::attach(pid)) {
        error = "Failed to attach PID " + std::to_string(pid) + " through driver bridge.";
        return false;
    }
    return true;
}

inline std::vector<api_target_t> targets_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<api_target_t> result;
    for (const auto& target : g_state.targets) {
        if (target.active)
            result.push_back(target);
    }
    return result;
}

inline uint32_t pid_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.pid;
}

inline void mark_thread_armed(uint64_t address, uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        if (target.address != address)
            continue;
        if (std::find(target.armed_tids.begin(), target.armed_tids.end(), tid) == target.armed_tids.end())
            target.armed_tids.push_back(tid);
        return;
    }
}

inline void remove_thread_armed(uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        auto& tids = target.armed_tids;
        tids.erase(std::remove(tids.begin(), tids.end(), tid), tids.end());
    }
}

inline bool arm_breakpoints_for_thread(uint32_t tid) {
    if (tid == 0 || !driver_bridge::using_kernel_driver())
        return false;
    bool armed = false;
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        driver_bridge::thread_context_t before{};
        SetLastError(ERROR_SUCCESS);
        const bool before_ok = driver_bridge::get_thread_context(tid, before);
        const DWORD before_gle = before_ok ? ERROR_SUCCESS : GetLastError();
        SetLastError(ERROR_SUCCESS);
        const bool set_ok = driver_bridge::set_hardware_breakpoint(tid, static_cast<int>(target.bp_index), target.address, 0, 0);
        const DWORD set_gle = set_ok ? ERROR_SUCCESS : GetLastError();
        const std::string set_status = driver_bridge::status();
        const std::string set_last_error = driver_bridge::last_error();
        driver_bridge::thread_context_t after{};
        SetLastError(ERROR_SUCCESS);
        const bool after_ok = driver_bridge::get_thread_context(tid, after);
        const DWORD after_gle = after_ok ? ERROR_SUCCESS : GetLastError();
        const uint64_t slot_addr = after_ok ? context_dr_address(after, target.bp_index) : 0;
        const bool slot_enabled = after_ok && target.bp_index <= 3 && ((after.dr7 & (1ull << static_cast<unsigned>(target.bp_index * 2))) != 0);
        const bool verify_ok = set_ok && after_ok && slot_addr == target.address && slot_enabled;
        if (verify_ok) {
            mark_thread_armed(target.address, tid);
            armed = true;
        }
        diag::log_tagged_fmt("api_monitor",
            "arm_thread tid=%u slot=%u type=execute len=1 driver_type=%d driver_size=%d api=%s addr=%s set_ok=%d set_gle=%lu before_ok=%d before_gle=%lu after_ok=%d after_gle=%lu verify_ok=%d slot_addr=%s slot_enabled=%d rip=%s dr0=%s dr1=%s dr2=%s dr3=%s dr6=0x%llX dr7=0x%llX status=%s last_error=%s",
            tid,
            target.bp_index,
            0,
            0,
            target.request.original.c_str(),
            hex_addr(target.address).c_str(),
            set_ok ? 1 : 0,
            static_cast<unsigned long>(set_gle),
            before_ok ? 1 : 0,
            static_cast<unsigned long>(before_gle),
            after_ok ? 1 : 0,
            static_cast<unsigned long>(after_gle),
            verify_ok ? 1 : 0,
            hex_addr(slot_addr).c_str(),
            slot_enabled ? 1 : 0,
            hex_addr(after.rip).c_str(),
            hex_addr(after.dr0).c_str(),
            hex_addr(after.dr1).c_str(),
            hex_addr(after.dr2).c_str(),
            hex_addr(after.dr3).c_str(),
            static_cast<unsigned long long>(after.dr6),
            static_cast<unsigned long long>(after.dr7),
            set_status.c_str(),
            set_last_error.c_str());
        if (set_ok) {
            diag::log_tagged_fmt("api_monitor",
                "arm_thread_result tid=%u slot=%u api=%s addr=%s ok=1 verify_ok=%d readback_available=%d",
                tid,
                target.bp_index,
                target.request.original.c_str(),
                hex_addr(target.address).c_str(),
                verify_ok ? 1 : 0,
                after_ok ? 1 : 0);
        } else {
            diag::log_tagged_fmt("api_monitor",
                "arm_thread_result tid=%u slot=%u api=%s addr=%s ok=0 gle=%lu status=%s last_error=%s",
                tid,
                target.bp_index,
                target.request.original.c_str(),
                hex_addr(target.address).c_str(),
                static_cast<unsigned long>(set_gle),
                set_status.c_str(),
                set_last_error.c_str());
        }
    }
    return armed;
}

inline uint32_t arm_existing_threads() {
    const uint32_t pid = pid_snapshot();
    if (pid == 0)
        return 0;
    const auto threads = driver_bridge::enumerate_threads_for(pid);
    diag::log_tagged_fmt("api_monitor",
        "arm_existing_threads pid=%u thread_count=%llu",
        pid,
        static_cast<unsigned long long>(threads.size()));
    uint32_t armed = 0;
    for (const auto& thread : threads) {
        if (thread.owner_pid == pid && arm_breakpoints_for_thread(thread.tid))
            ++armed;
    }
    diag::log_tagged_fmt("api_monitor",
        "arm_existing_threads_done pid=%u armed_threads=%u",
        pid,
        armed);
    return armed;
}

struct clear_result_t {
    DWORD gle = ERROR_SUCCESS;
    uint64_t before_dr7 = 0;
    uint64_t after_dr7 = 0;
    uint64_t elapsed_ms = 0;
    std::string driver_error;
};

inline bool clear_hardware_breakpoint_kernel(uint32_t tid, uint32_t slot, clear_result_t& result) {
    const uint64_t start = GetTickCount64();
    auto finish = [&result, start](DWORD gle, bool ok) {
        result.gle = gle;
        result.elapsed_ms = GetTickCount64() - start;
        SetLastError(gle);
        return ok;
    };

    if (tid == 0 || slot > 3)
        return finish(ERROR_INVALID_PARAMETER, false);
    if (tid == GetCurrentThreadId())
        return finish(ERROR_INVALID_PARAMETER, false);
    if (!driver_bridge::using_kernel_driver()) {
        result.driver_error = "kernel driver unavailable";
        return finish(ERROR_INVALID_HANDLE, false);
    }

    driver_bridge::thread_context_t before{};
    SetLastError(ERROR_SUCCESS);
    const bool got_before = driver_bridge::get_thread_context(tid, before);
    const DWORD before_gle = got_before ? ERROR_SUCCESS : GetLastError();
    if (got_before)
        result.before_dr7 = before.dr7;

    SetLastError(ERROR_SUCCESS);
    const bool cleared = driver_bridge::clear_hardware_breakpoint(tid, static_cast<int>(slot));
    const DWORD clear_gle = cleared ? ERROR_SUCCESS : GetLastError();
    result.driver_error = driver_bridge::last_error();

    driver_bridge::thread_context_t after{};
    SetLastError(ERROR_SUCCESS);
    const bool got_after = driver_bridge::get_thread_context(tid, after);
    const DWORD after_gle = got_after ? ERROR_SUCCESS : GetLastError();
    if (got_after)
        result.after_dr7 = after.dr7;

    if (!got_before)
        return finish(before_gle, false);
    if (!cleared)
        return finish(clear_gle, false);
    if (!got_after)
        return finish(after_gle, false);
    return finish(ERROR_SUCCESS, true);
}

inline void clear_armed_breakpoints(const char* source) {
    struct clear_request_t {
        uint32_t tid;
        uint32_t slot;
    };
    const char* origin = source && *source ? source : "unknown";
    if (g_state.cleanup_running.exchange(true)) {
        diag::log_tagged_fmt("api_monitor",
            "clear_armed_breakpoints_busy source=%s",
            origin);
        return;
    }

    const uint64_t cleanup_start = GetTickCount64();
    g_state.cleanup_attempts.fetch_add(1, std::memory_order_relaxed);
    std::vector<clear_request_t> requests;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets) {
            for (uint32_t tid : target.armed_tids)
                requests.push_back({tid, target.bp_index});
            target.armed_tids.clear();
        }
    }
    g_state.cleanup_last_requests.store(static_cast<uint32_t>(requests.size()), std::memory_order_relaxed);
    diag::log_tagged_fmt("api_monitor",
        "clear_armed_breakpoints source=%s requests=%llu kernel=%d attached=%d",
        origin,
        static_cast<unsigned long long>(requests.size()),
        driver_bridge::using_kernel_driver() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);
    uint32_t succeeded = 0;
    uint32_t failed = 0;
    uint32_t index = 0;
    for (const auto& req : requests) {
        ++index;
        diag::log_tagged_fmt("api_monitor",
            "clear_breakpoint_begin source=%s index=%u total=%llu tid=%u slot=%u",
            origin,
            index,
            static_cast<unsigned long long>(requests.size()),
            req.tid,
            req.slot);
        clear_result_t clear_result;
        const bool ok = clear_hardware_breakpoint_kernel(req.tid, req.slot, clear_result);
        if (ok)
            ++succeeded;
        else
            ++failed;
        diag::log_tagged_fmt("api_monitor",
            "clear_breakpoint_end source=%s index=%u total=%llu tid=%u slot=%u ok=%d gle=%lu before_dr7=0x%llX after_dr7=0x%llX elapsed_ms=%llu driver_error=%s",
            origin,
            index,
            static_cast<unsigned long long>(requests.size()),
            req.tid,
            req.slot,
            ok ? 1 : 0,
            clear_result.gle,
            static_cast<unsigned long long>(clear_result.before_dr7),
            static_cast<unsigned long long>(clear_result.after_dr7),
            static_cast<unsigned long long>(clear_result.elapsed_ms),
            clear_result.driver_error.c_str());
    }
    const uint64_t elapsed = GetTickCount64() - cleanup_start;
    g_state.cleanup_last_succeeded.store(succeeded, std::memory_order_relaxed);
    g_state.cleanup_last_failed.store(failed, std::memory_order_relaxed);
    g_state.cleanup_last_elapsed_ms.store(elapsed, std::memory_order_relaxed);
    g_state.cleanup_running.store(false);
    diag::log_tagged_fmt("api_monitor",
        "clear_armed_breakpoints_done source=%s requests=%llu succeeded=%u failed=%u elapsed_ms=%llu",
        origin,
        static_cast<unsigned long long>(requests.size()),
        succeeded,
        failed,
        static_cast<unsigned long long>(elapsed));
}

inline void update_module_cache(uint32_t pid) {
    auto modules = driver_bridge::enumerate_modules_for(pid);
    if (modules.empty())
        return;
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.modules = std::move(modules);
}

inline void capture_known_arguments(uint32_t pid,
                                    const driver_bridge::thread_context_t& ctx,
                                    const api_target_t& target,
                                    api_event_t& event,
                                    bool capture_bytes,
                                    uint32_t max_capture_bytes) {
    const api_kind_t kind = target.request.kind;
    event.metadata["kind"] = kind_name(kind);

    if (kind == api_kind_t::send_linear || kind == api_kind_t::custom_linear) {
        const uint64_t socket_handle = register_value(ctx, 0);
        if (kind == api_kind_t::send_linear)
            add_socket_metadata(pid, socket_handle, event.metadata);
        capture_linear_buffer(event.buffers, pid, "outbound", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        event.metadata["flags"] = hex_addr(register_value(ctx, 3));
        return;
    }

    if (kind == api_kind_t::wsa_send) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "outbound",
                        max_capture_bytes, capture_bytes, event.metadata);
        event.metadata["bytes_sent_ptr"] = hex_addr(register_value(ctx, 3));
        return;
    }

    if (kind == api_kind_t::send_to) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_linear_buffer(event.buffers, pid, "outbound", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        event.metadata["flags"] = hex_addr(register_value(ctx, 3));
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, stack_arg64(pid, ctx.rsp, 0),
                           stack_arg64(pid, ctx.rsp, 1), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::wsa_send_to) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "outbound",
                        max_capture_bytes, capture_bytes, event.metadata);
        event.metadata["bytes_sent_ptr"] = hex_addr(register_value(ctx, 3));
        event.metadata["flags"] = hex_addr(stack_arg64(pid, ctx.rsp, 0));
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, stack_arg64(pid, ctx.rsp, 1),
                           stack_arg64(pid, ctx.rsp, 2), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::recv_linear || kind == api_kind_t::recv_from) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_linear_buffer(event.buffers, pid, "inbound_destination", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, false);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::wsa_recv || kind == api_kind_t::wsa_recv_from) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "inbound_destination",
                        max_capture_bytes, false, event.metadata);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::connect_call) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, register_value(ctx, 1), register_value(ctx, 2), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::device_io_control) {
        const uint32_t ioctl = static_cast<uint32_t>(register_value(ctx, 1));
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["ioctl"] = ioctl_to_json(ioctl);
        capture_linear_buffer(event.buffers, pid, "ioctl_input", register_value(ctx, 2), register_value(ctx, 3),
                              max_capture_bytes, capture_bytes);
        event.metadata["out_buffer"] = hex_addr(stack_arg64(pid, ctx.rsp, 0));
        event.metadata["out_buffer_size"] = stack_arg64(pid, ctx.rsp, 1);
        event.metadata["bytes_returned_ptr"] = hex_addr(stack_arg64(pid, ctx.rsp, 2));
        event.metadata["overlapped_ptr"] = hex_addr(stack_arg64(pid, ctx.rsp, 3));
        return;
    }

    if (kind == api_kind_t::nt_device_io_control) {
        const uint32_t ioctl = static_cast<uint32_t>(stack_arg64(pid, ctx.rsp, 1));
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["event_handle"] = hex_addr(register_value(ctx, 1));
        event.metadata["apc_routine"] = hex_addr(register_value(ctx, 2));
        event.metadata["apc_context"] = hex_addr(register_value(ctx, 3));
        event.metadata["io_status_block"] = hex_addr(stack_arg64(pid, ctx.rsp, 0));
        event.metadata["ioctl"] = ioctl_to_json(ioctl);
        capture_linear_buffer(event.buffers, pid, "ioctl_input", stack_arg64(pid, ctx.rsp, 2),
                              stack_arg64(pid, ctx.rsp, 3), max_capture_bytes, capture_bytes);
        event.metadata["out_buffer"] = hex_addr(stack_arg64(pid, ctx.rsp, 4));
        event.metadata["out_buffer_size"] = stack_arg64(pid, ctx.rsp, 5);
        return;
    }

    if (kind == api_kind_t::write_file) {
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["bytes_transferred_ptr"] = hex_addr(register_value(ctx, 3));
        capture_linear_buffer(event.buffers, pid, "write", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        return;
    }

    if (kind == api_kind_t::read_file) {
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["bytes_transferred_ptr"] = hex_addr(register_value(ctx, 3));
        capture_linear_buffer(event.buffers, pid, "read_destination", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, false);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::encrypt_message) {
        event.metadata["credential_or_context"] = hex_addr(register_value(ctx, 0));
        event.metadata["quality_of_protection"] = hex_addr(register_value(ctx, 1));
        event.metadata["message_seq_no"] = hex_addr(register_value(ctx, 3));
        capture_sec_buffers(event.buffers, pid, register_value(ctx, 2), max_capture_bytes, capture_bytes, event.metadata);
        return;
    }

    if (target.request.buffer_reg >= 0 && target.request.size_reg >= 0) {
        capture_linear_buffer(event.buffers, pid, "custom", register_value(ctx, target.request.buffer_reg),
                              register_value(ctx, target.request.size_reg), max_capture_bytes, capture_bytes);
    }
}

inline void record_event(uint32_t pid, uint32_t tid, const driver_bridge::thread_context_t& ctx, const api_target_t& target) {
    bool capture_bytes = true;
    bool log_callstack = false;
    uint32_t max_capture_bytes = 256;
    std::vector<driver_bridge::module_info_t> modules;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        capture_bytes = g_state.capture_buffer;
        log_callstack = g_state.log_callstack;
        max_capture_bytes = g_state.max_capture_bytes;
        modules = g_state.modules;
    }

    api_event_t event;
    event.pid = pid;
    event.tid = tid;
    event.timestamp_ms = GetTickCount64();
    event.api = target.request.original.empty() ? target.request.function_name : target.request.original;
    event.api_address = target.address;
    event.api_module = target.resolved_module;
    event.api_module_offset = target.module_offset;
    event.regs = snapshot_registers(ctx);
    event.return_address = read_return_address(pid, ctx.rsp);
    event.callsite_address = find_callsite(pid, event.return_address);
    address_in_modules(event.return_address, modules, event.caller_module, event.caller_module_offset);
    event.metadata["api_function"] = target.request.function_name;
    event.metadata["api_module"] = target.resolved_module;

    capture_known_arguments(pid, ctx, target, event, capture_bytes, max_capture_bytes);
    if (log_callstack)
        event.callstack = capture_callstack(pid, ctx, event.return_address, modules);

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        event.sequence = g_state.next_sequence++;
        g_state.events.push_back(std::move(event));
        while (g_state.events.size() > g_state.max_events)
            g_state.events.pop_front();
        g_state.total_hits.fetch_add(1, std::memory_order_relaxed);
    }
}

inline uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, uint32_t slot) {
    switch (slot) {
    case 0: return ctx.dr0;
    case 1: return ctx.dr1;
    case 2: return ctx.dr2;
    case 3: return ctx.dr3;
    default: return 0;
    }
}

inline bool context_matches_target(const driver_bridge::thread_context_t& ctx, const api_target_t& target) {
    if (target.bp_index > 3 || target.address == 0)
        return false;
    const uint64_t slot_address = context_dr_address(ctx, target.bp_index);
    const bool slot_matches = slot_address == target.address;
    const bool dr6_hit = (ctx.dr6 & (1ull << target.bp_index)) != 0;
    if (dr6_hit && slot_matches)
        return true;
    return slot_matches && ctx.rip == target.address;
}

inline bool find_target_for_context(const driver_bridge::thread_context_t& ctx, api_target_t& out) {
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (context_matches_target(ctx, target)) {
            out = target;
            return true;
        }
    }
    return false;
}

inline bool capture_breakpoint_hit(uint32_t pid, uint32_t tid, const driver_bridge::thread_context_t& ctx) {
    api_target_t target;
    if (!find_target_for_context(ctx, target))
        return false;

    record_event(pid, tid, ctx, target);
    driver_bridge::thread_context_t next = ctx;
    next.rflags |= 0x10000ull;
    next.dr6 = 0;
    SetLastError(ERROR_SUCCESS);
    const bool set_ok = driver_bridge::set_thread_context(tid, next, (1ull << 17) | (1ull << 22));
    const DWORD gle = set_ok ? ERROR_SUCCESS : GetLastError();
    diag::log_tagged_fmt("api_monitor",
        "kernel_context_hit_resume pid=%u tid=%u api=%s set_ok=%d gle=%lu rip=%s dr6=0x%llX dr7=0x%llX",
        pid,
        tid,
        target.request.original.c_str(),
        set_ok ? 1 : 0,
        static_cast<unsigned long>(gle),
        hex_addr(ctx.rip).c_str(),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7));
    return true;
}

inline std::vector<uint32_t> armed_threads_snapshot() {
    std::vector<uint32_t> tids;
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (const auto& target : g_state.targets) {
        for (uint32_t tid : target.armed_tids) {
            if (tid != 0 && std::find(tids.begin(), tids.end(), tid) == tids.end())
                tids.push_back(tid);
        }
    }
    return tids;
}

inline void poll_kernel_contexts(uint32_t pid) {
    for (uint32_t tid : armed_threads_snapshot()) {
        driver_bridge::thread_context_t ctx{};
        SetLastError(ERROR_SUCCESS);
        if (!driver_bridge::get_thread_context(tid, ctx)) {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("api_monitor",
                "kernel_context_poll_get_failed pid=%u tid=%u gle=%lu driver_error=%s",
                pid,
                tid,
                static_cast<unsigned long>(gle),
                driver_bridge::last_error().c_str());
            if (gle == ERROR_INVALID_PARAMETER || gle == ERROR_NOT_FOUND || gle == ERROR_INVALID_HANDLE)
                remove_thread_armed(tid);
            continue;
        }
        capture_breakpoint_hit(pid, tid, ctx);
    }
}

inline void kernel_context_loop() {
    const uint32_t pid = pid_snapshot();
    diag::log_tagged_fmt("api_monitor",
        "kernel_context_loop_entry pid=%u host_tid=%lu kernel=%d",
        pid,
        GetCurrentThreadId(),
        driver_bridge::using_kernel_driver() ? 1 : 0);
    if (pid == 0 || !driver_bridge::using_kernel_driver()) {
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        g_state.debugger_error.store(ERROR_INVALID_PARAMETER);
        diag::log_tagged_fmt("api_monitor",
            "kernel_context_loop_invalid pid=%u kernel=%d",
            pid,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }

    g_state.debug_attached.store(true);
    g_state.debugger_error.store(0);
    update_module_cache(pid);
    const uint32_t initial_armed = arm_existing_threads();
    diag::log_tagged_fmt("api_monitor",
        "kernel_context_loop_armed pid=%u initial_armed=%u",
        pid,
        initial_armed);

    uint64_t poll_count = 0;
    while (g_state.polling.load(std::memory_order_acquire) &&
           !g_state.stop_requested.load(std::memory_order_acquire)) {
        if (!driver_bridge::using_kernel_driver()) {
            g_state.debugger_error.store(ERROR_INVALID_HANDLE);
            g_state.active.store(false);
            g_state.polling.store(false);
            break;
        }
        if (targets_snapshot().empty()) {
            g_state.active.store(false);
            g_state.polling.store(false);
            break;
        }
        if ((poll_count % 20) == 0)
            arm_existing_threads();
        if ((poll_count % 100) == 0)
            update_module_cache(pid);
        poll_kernel_contexts(pid);
        ++poll_count;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    clear_armed_breakpoints("kernel_context_loop");
    g_state.debug_attached.store(false);
    g_state.debug_loop_running.store(false);
    diag::log_tagged_fmt("api_monitor",
        "kernel_context_loop_exit pid=%u polls=%llu active=%d polling=%d attached=%d debugger_error=%lu",
        pid,
        static_cast<unsigned long long>(poll_count),
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        g_state.debugger_error.load());
}

inline void stop() {
    diag::log_tagged_fmt("api_monitor",
        "stop_enter active=%d polling=%d debug_loop=%d attached=%d pid=%u",
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        pid_snapshot());
    const uint64_t stop_start = GetTickCount64();
    const uint32_t pid = pid_snapshot();
    g_state.stop_requested.store(true, std::memory_order_release);
    g_state.polling.store(false);
    std::shared_ptr<worker_lifetime_t> worker;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        worker = g_state.worker_owner;
    }
    bool worker_completed = !worker;
    if (worker) {
        std::unique_lock<std::mutex> lock(worker->mutex);
        worker_completed = worker->condition.wait_for(lock, std::chrono::milliseconds(1500),
            [&worker]() { return worker->completed; });
    }
    diag::log_tagged_fmt("api_monitor",
        "stop_wait_done pid=%u waited_ms=%llu iterations=%d debug_loop=%d attached=%d",
        pid,
        static_cast<unsigned long long>(GetTickCount64() - stop_start),
        worker_completed ? 0 : 60,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);
    if (!worker_completed || g_state.debug_loop_running.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("api_monitor",
            "stop_kernel_context_loop_still_running pid=%u waited_ms=%llu",
            pid,
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
        g_state.active.store(false, std::memory_order_release);
        diag::log_tagged_fmt("api_monitor",
            "stop_exit active=0 polling=%d debug_loop=%d attached=%d elapsed_ms=%llu deferred=1 worker_owned=%d worker_completed=%d stop_requested=%d",
            g_state.polling.load() ? 1 : 0,
            g_state.debug_loop_running.load() ? 1 : 0,
            g_state.debug_attached.load() ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - stop_start),
            worker ? 1 : 0,
            worker_completed ? 1 : 0,
            g_state.stop_requested.load(std::memory_order_acquire) ? 1 : 0);
        return;
    }
    if (!worker)
        clear_armed_breakpoints("stop");
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets)
            target.active = false;
        g_state.targets.clear();
        g_state.requested.clear();
        g_state.modules.clear();
        g_state.socket_cache = {};
        g_state.pid = 0;
        g_state.worker_owner.reset();
    }
    g_state.active.store(false);
    diag::log_tagged_fmt("api_monitor",
        "stop_exit active=%d polling=%d debug_loop=%d attached=%d elapsed_ms=%llu cleanup_requests=%u cleanup_ok=%u cleanup_failed=%u",
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - stop_start),
        g_state.cleanup_last_requests.load(std::memory_order_relaxed),
        g_state.cleanup_last_succeeded.load(std::memory_order_relaxed),
        g_state.cleanup_last_failed.load(std::memory_order_relaxed));
}

inline bool start_polling(std::string& error) {
    const uint64_t start_ms = GetTickCount64();
    diag::log_tagged_fmt("api_monitor",
        "start_polling_enter pid=%u caller_tid=%lu active=%d polling=%d debug_loop=%d attached=%d",
        pid_snapshot(),
        GetCurrentThreadId(),
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);
    if (!g_state.active.load()) {
        error = "No active API monitor targets.";
        diag::log_tagged_fmt("api_monitor",
            "start_polling_exit ok=0 reason=no_active elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    auto worker_owner = std::make_shared<worker_lifetime_t>();
    bool already_running = false;
    bool already_attached = false;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.worker_owner) {
            std::lock_guard<std::mutex> worker_lock(g_state.worker_owner->mutex);
            if (!g_state.worker_owner->completed) {
                error = "API monitor kernel context loop is still draining.";
                diag::log_tagged_fmt("api_monitor",
                    "start_polling_exit ok=0 reason=worker_draining elapsed_ms=%llu",
                    static_cast<unsigned long long>(GetTickCount64() - start_ms));
                return false;
            }
            g_state.worker_owner.reset();
        }
        already_running = g_state.debug_loop_running.exchange(true);
        already_attached = g_state.debug_attached.load();
        if (!already_running) {
            g_state.stop_requested.store(false, std::memory_order_release);
            g_state.polling.store(true, std::memory_order_release);
            g_state.worker_owner = worker_owner;
        }
    }
    if (already_running) {
        if (already_attached) {
            arm_existing_threads();
            diag::log_tagged_fmt("api_monitor",
                "start_polling_exit ok=1 reason=already_attached elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return true;
        }
        error = "API monitor kernel context loop is already starting.";
        diag::log_tagged_fmt("api_monitor",
            "start_polling_exit ok=0 reason=already_starting elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    bool posted = false;
    diag::log_tagged_fmt("api_monitor",
        "start_polling_post_begin pid=%u caller_tid=%lu",
        pid_snapshot(),
        GetCurrentThreadId());
    mcp_standalone::downstream::producer_identity_t poll_id;
    poll_id.kind = mcp_standalone::downstream::producer_kind_t::api_monitor;
    poll_id.tool_name = "api_monitor.kernel_context_loop";
    poll_id.target_pid = pid_snapshot();
    auto poll_admission = mcp_standalone::downstream::scoped_admission_t::acquire(poll_id);
    if (!poll_admission.active()) {
        diag::log_tagged_fmt("api_monitor",
            "BURP-NETWORK-WORKER-REJECT phase=kernel_context_loop pid=%u reason=%s quota=%s observed=%zu limit=%zu",
            pid_snapshot(),
            poll_admission.result().reason.c_str(),
            poll_admission.result().quota_name.c_str(),
            poll_admission.result().observed, poll_admission.result().limit);
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            if (g_state.worker_owner == worker_owner)
                g_state.worker_owner.reset();
        }
        error = "Downstream api_monitor capacity exhausted.";
        return false;
    }
    const uint64_t poll_token = poll_admission.token();
    diag::log_tagged_fmt("api_monitor",
        "BURP-NETWORK-WORKER-ADMIT phase=kernel_context_loop pid=%u token=%llu",
        pid_snapshot(),
        static_cast<unsigned long long>(poll_token));
    auto poll_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(poll_admission));
    std::string post_reject_reason;
    try {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "api_monitor";
        sub.label = "api_monitor.kernel_context_loop";
        sub.thread_class = "service_loop";
        sub.domain = aida::infra::executor::domain_t::service;
        sub.priority = 4;
        sub.target_pid = pid_snapshot();
        sub.lease_token = poll_token;
        sub.body = [poll_admission_ptr, poll_token, worker_owner]() {
            try {
                kernel_context_loop();
            } catch (const std::exception& ex) {
                g_state.debugger_error.store(ERROR_UNHANDLED_EXCEPTION);
                g_state.polling.store(false);
                g_state.active.store(false);
                clear_armed_breakpoints("kernel_context_loop_exception");
                g_state.debug_attached.store(false);
                g_state.debug_loop_running.store(false);
                diag::log_tagged_fmt("api_monitor",
                    "kernel_context_loop_exception token=%llu message=%s",
                    static_cast<unsigned long long>(poll_token), ex.what());
            } catch (...) {
                g_state.debugger_error.store(ERROR_UNHANDLED_EXCEPTION);
                g_state.polling.store(false);
                g_state.active.store(false);
                clear_armed_breakpoints("kernel_context_loop_exception");
                g_state.debug_attached.store(false);
                g_state.debug_loop_running.store(false);
                diag::log_tagged_fmt("api_monitor",
                    "kernel_context_loop_exception token=%llu message=unknown",
                    static_cast<unsigned long long>(poll_token));
            }
            if (g_state.stop_requested.load(std::memory_order_acquire)) {
                std::lock_guard<std::mutex> lock(g_state.mutex);
                for (auto& target : g_state.targets)
                    target.active = false;
                g_state.targets.clear();
                g_state.requested.clear();
                g_state.modules.clear();
                g_state.socket_cache = {};
                g_state.pid = 0;
                diag::log_tagged_fmt("api_monitor",
                    "kernel_context_loop_cancelled_state_released token=%llu",
                    static_cast<unsigned long long>(poll_token));
            }
            diag::log_tagged_fmt("api_monitor",
                "BURP-NETWORK-WORKER-RELEASE phase=kernel_context_loop token=%llu reason=completed",
                static_cast<unsigned long long>(poll_token));
            poll_admission_ptr->release("completed");
            {
                std::lock_guard<std::mutex> lock(worker_owner->mutex);
                worker_owner->completed = true;
            }
            worker_owner->condition.notify_all();
        };
        auto submit_result = aida::infra::executor::submit(std::move(sub));
        posted = submit_result.submitted;
        post_reject_reason = submit_result.reject_reason;
    } catch (...) {
        posted = false;
    }
    diag::log_tagged_fmt("api_monitor",
        "start_polling_post_end pid=%u posted=%d elapsed_ms=%llu gle=%lu reject=%s",
        pid_snapshot(),
        posted ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        GetLastError(),
        post_reject_reason.empty() ? "<none>" : post_reject_reason.c_str());
    if (!posted) {
        poll_admission_ptr->release("executor_rejected");
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            if (g_state.worker_owner == worker_owner)
                g_state.worker_owner.reset();
        }
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        error = "Failed to schedule API monitor worker on executor.";
        diag::log_tagged_fmt("api_monitor",
            "start_polling_post_failed");
        return false;
    }
    diag::log_tagged_fmt("api_monitor", "start_polling_worker_posted");

    for (int i = 0; i < 60; ++i) {
        if (g_state.debug_attached.load()) {
            diag::log_tagged_fmt("api_monitor",
                "start_polling_exit ok=1 reason=attached elapsed_ms=%llu iterations=%d",
                static_cast<unsigned long long>(GetTickCount64() - start_ms),
                i);
            return true;
        }
        if (!g_state.debug_loop_running.load()) {
            error = "kernel context loop failed, error=" + std::to_string(static_cast<unsigned long>(g_state.debugger_error.load()));
            diag::log_tagged_fmt("api_monitor",
                "start_polling_exit ok=0 reason=debug_loop_stopped elapsed_ms=%llu iterations=%d debugger_error=%lu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms),
                i,
                g_state.debugger_error.load());
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    if (g_state.debug_attached.load()) {
        diag::log_tagged_fmt("api_monitor",
            "start_polling_exit ok=1 reason=attached_after_wait elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return true;
    }
    error = "Timed out waiting for API monitor kernel context loop.";
    diag::log_tagged_fmt("api_monitor",
        "start_polling_exit ok=0 reason=kernel_context_timeout elapsed_ms=%llu timeout_ms=1500 debug_loop=%d debugger_error=%lu",
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debugger_error.load());
    return false;
}

inline bool start(uint32_t requested_pid,
                  const std::vector<api_request_t>& apis,
                  bool log_callstack,
                  bool capture_buffer,
                  uint32_t max_capture_bytes,
                  size_t max_events,
                  nlohmann::json& summary,
                  std::string& error) {
    const uint64_t start_ms = GetTickCount64();
    diag::log_tagged_fmt("api_monitor",
        "start_enter requested_pid=%u apis=%zu caller_tid=%lu active=%d polling=%d debug_loop=%d attached=%d cleanup=%d",
        requested_pid,
        apis.size(),
        GetCurrentThreadId(),
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        g_state.cleanup_running.load() ? 1 : 0);
    log_phase_state("start_enter", "start", requested_pid, GetCurrentThreadId(), 0, 0);
    if (apis.empty()) {
        error = "apis must contain at least one API name.";
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=no_apis elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    if (apis.size() > 4) {
        error = "api_monitor_start supports up to 4 APIs per session because it uses DR0-DR3 hardware execute breakpoints.";
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=too_many_apis elapsed_ms=%llu apis=%zu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms),
            apis.size());
        return false;
    }

    stop();
    diag::log_tagged_fmt("api_monitor",
        "start_after_stop elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    bool previous_worker_draining = false;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.worker_owner) {
            std::lock_guard<std::mutex> worker_lock(g_state.worker_owner->mutex);
            previous_worker_draining = !g_state.worker_owner->completed;
            if (!previous_worker_draining)
                g_state.worker_owner.reset();
        }
    }
    if (previous_worker_draining) {
        error = "Previous API monitor worker is still draining after cancellation.";
        summary["failed_phase"] = "stop_drain";
        summary["status"] = status_json();
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=previous_worker_draining elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    uint32_t pid = requested_pid;
    if (pid == 0)
        pid = driver_bridge::attached_pid();
    if (pid == 0) {
        error = "Missing pid and no driver target is attached.";
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=no_pid elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    if (pid == GetCurrentProcessId()) {
        error = "Refusing to debug the AiDA process itself.";
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=self_pid pid=%u elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    auto exists_phase = run_phase_inline<process_probe_result_t>("process_exists", pid, 1500, [pid]() {
        return process_exists_probe(pid);
    });
    if (exists_phase.threw) {
        error = "Exception while checking target PID " + std::to_string(pid) + ": " + exists_phase.exception;
        summary["failed_phase"] = "process_exists";
        summary["exception"] = exists_phase.exception;
        summary["exception_code"] = exists_phase.exception_code;
        summary["exception_category"] = exists_phase.exception_category;
        summary["status"] = status_json();
        log_phase_state("start_exit_process_exists_exception", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    if (!exists_phase.completed) {
        error = "Timed out checking whether target PID " + std::to_string(pid) + " is running.";
        summary["failed_phase"] = "process_exists";
        summary["elapsed_ms"] = exists_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(exists_phase.gle);
        summary["status"] = status_json();
        diag::log_tagged_fmt("api_monitor",
            "start_exit ok=0 reason=process_exists_timeout pid=%u elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        log_phase_state("start_exit_process_exists_timeout", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    const process_probe_result_t& process_probe = exists_phase.value;
    summary["process_probe"] = process_probe_to_json(process_probe);
    diag::log_tagged_fmt("api_monitor",
        "start_process_exists_result pid=%u alive=%d open_ok=%d open_gle=%lu exit_ok=%d exit_gle=%lu exit_code=%lu snapshot_ok=%d snapshot_gle=%lu snapshot_found=%d elapsed_ms=%llu phase_gle=%lu",
        pid,
        process_probe.alive ? 1 : 0,
        process_probe.open_ok ? 1 : 0,
        process_probe.open_gle,
        process_probe.exit_code_ok ? 1 : 0,
        process_probe.exit_code_gle,
        process_probe.exit_code,
        process_probe.snapshot_ok ? 1 : 0,
        process_probe.snapshot_gle,
        process_probe.snapshot_found ? 1 : 0,
        static_cast<unsigned long long>(exists_phase.elapsed_ms),
        exists_phase.gle);
    if (!process_probe.alive) {
        summary["failed_phase"] = "process_exists";
        summary["status"] = status_json();
        if (!process_probe.open_ok && process_probe.snapshot_found) {
            error = "Target PID " + std::to_string(pid) + " is present in the process snapshot but OpenProcess liveness check failed, last_error=" + std::to_string(static_cast<unsigned long>(process_probe.open_gle)) + ".";
        } else if (process_probe.open_ok && !process_probe.exit_code_ok) {
            error = "Target PID " + std::to_string(pid) + " opened but GetExitCodeProcess failed, last_error=" + std::to_string(static_cast<unsigned long>(process_probe.exit_code_gle)) + ".";
        } else {
            error = "Target PID " + std::to_string(pid) + " is not running.";
        }
        log_phase_state("start_exit_process_exists_false", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    auto x64_phase = run_phase_with_timeout<target_arch_probe_result_t>("target_is_x64", pid, 1500, [pid]() {
        return target_arch_probe(pid);
    });
    if (x64_phase.threw) {
        error = "Exception while checking target architecture for PID " + std::to_string(pid) + ": " + x64_phase.exception;
        summary["failed_phase"] = "target_is_x64";
        summary["exception"] = x64_phase.exception;
        summary["exception_code"] = x64_phase.exception_code;
        summary["exception_category"] = x64_phase.exception_category;
        summary["elapsed_ms"] = x64_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(x64_phase.gle);
        summary["status"] = status_json();
        diag::log_tagged_fmt("api_monitor",
            "start_target_is_x64_exception pid=%u elapsed_ms=%llu exception_code=0x%08lX category=%s detail=%s",
            pid,
            static_cast<unsigned long long>(x64_phase.elapsed_ms),
            static_cast<unsigned long>(x64_phase.exception_code),
            x64_phase.exception_category.c_str(),
            x64_phase.exception.c_str());
        log_phase_state("start_exit_target_is_x64_exception", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    if (!x64_phase.completed) {
        error = "Timed out checking target architecture for PID " + std::to_string(pid) + ".";
        summary["failed_phase"] = "target_is_x64";
        summary["elapsed_ms"] = x64_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(x64_phase.gle);
        summary["target_arch_probe"] = nlohmann::json{
            {"target_pid", pid},
            {"phase", "target_is_x64_timeout"},
            {"last_error", static_cast<unsigned long>(x64_phase.gle)},
            {"elapsed_ms", x64_phase.elapsed_ms},
            {"decision", "fail_closed"},
            {"failure_reason", "phase timeout before target architecture decision"}
        };
        summary["status"] = status_json();
        diag::log_tagged_fmt("api_monitor",
            "start_target_is_x64_timeout pid=%u elapsed_ms=%llu gle=%lu",
            pid,
            static_cast<unsigned long long>(x64_phase.elapsed_ms),
            x64_phase.gle);
        log_phase_state("start_exit_target_is_x64_timeout", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    summary["target_arch_probe"] = target_arch_probe_to_json(x64_phase.value);
    diag::log_tagged_fmt("api_monitor",
        "start_target_is_x64_result pid=%u ok=%d x64=%d uncertain=%d phase=%s decision=%s elapsed_ms=%llu gle=%lu probe_gle=%lu",
        pid,
        x64_phase.value.ok ? 1 : 0,
        x64_phase.value.x64 ? 1 : 0,
        x64_phase.value.uncertain ? 1 : 0,
        x64_phase.value.phase,
        x64_phase.value.decision,
        static_cast<unsigned long long>(x64_phase.elapsed_ms),
        x64_phase.gle,
        x64_phase.value.final_gle);
    if (!x64_phase.value.ok || !x64_phase.value.x64) {
        summary["failed_phase"] = "target_is_x64";
        summary["elapsed_ms"] = x64_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(x64_phase.value.final_gle);
        summary["status"] = status_json();
        error = std::string("API monitor requires a native x64 target process; target_is_x64 phase=") +
            (x64_phase.value.phase ? x64_phase.value.phase : "unknown") +
            ", decision=" + (x64_phase.value.decision ? x64_phase.value.decision : "unknown") +
            ", last_error=" + std::to_string(static_cast<unsigned long>(x64_phase.value.final_gle)) + ".";
        log_phase_state("start_exit_target_is_x64_false", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
        return false;
    }
    auto attach_phase = run_phase_with_timeout<driver_attach_phase_result_t>("driver_attach", pid, 7000, [pid](phase_cancel_t& cancel) {
        driver_attach_phase_result_t result;
        result.kernel = driver_bridge::using_kernel_driver();
        result.attached_pid_before = driver_bridge::attached_pid();
        struct active_pid_restore_t {
            phase_cancel_t& cancel;
            uint32_t target_pid;
            uint32_t previous_pid;
            ~active_pid_restore_t() {
                if (!cancel.requested.load(std::memory_order_acquire) || previous_pid == target_pid || driver_bridge::attached_pid() != target_pid)
                    return;
                const bool restored = previous_pid != 0
                    ? driver_bridge::set_active_pid(previous_pid)
                    : driver_bridge::clear_active_pid();
                diag::log_tagged_fmt("api_monitor",
                    "driver_attach_cancel_restore target_pid=%u previous_pid=%u restored=%d active_pid_after=%u",
                    target_pid,
                    previous_pid,
                    restored ? 1 : 0,
                    driver_bridge::attached_pid());
            }
        } restore{cancel, pid, result.attached_pid_before};
        const auto attached = driver_bridge::attached_pids();
        result.attached_count = attached.size();
        std::string phase_error;
        result.ok = ensure_driver_attached(pid, phase_error);
        result.error = phase_error;
        result.attached_pid_after = driver_bridge::attached_pid();
        return result;
    });
    if (attach_phase.threw) {
        error = "Exception during driver attach for PID " + std::to_string(pid) + ": " + attach_phase.exception;
        summary["failed_phase"] = "driver_attach";
        summary["exception"] = attach_phase.exception;
        summary["exception_code"] = attach_phase.exception_code;
        summary["exception_category"] = attach_phase.exception_category;
        return false;
    }
    if (!attach_phase.completed) {
        error = "Timed out attaching/selecting target PID " + std::to_string(pid) + " through driver bridge.";
        summary["failed_phase"] = "driver_attach";
        summary["elapsed_ms"] = attach_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(attach_phase.gle);
        return false;
    }
    diag::log_tagged_fmt("api_monitor",
        "start_driver_attach_result pid=%u ok=%d kernel=%d before=%u after=%u attached_count=%zu elapsed_ms=%llu gle=%lu error=%s",
        pid,
        attach_phase.value.ok ? 1 : 0,
        attach_phase.value.kernel ? 1 : 0,
        attach_phase.value.attached_pid_before,
        attach_phase.value.attached_pid_after,
        attach_phase.value.attached_count,
        static_cast<unsigned long long>(attach_phase.elapsed_ms),
        attach_phase.gle,
        attach_phase.value.error.c_str());
    if (!attach_phase.value.ok) {
        error = attach_phase.value.error.empty()
            ? ("Failed to attach/select target PID " + std::to_string(pid) + " through driver bridge.")
            : attach_phase.value.error;
        return false;
    }

    auto modules_phase = run_phase_with_timeout<std::vector<driver_bridge::module_info_t>>("module_enumeration", pid, 7000, [pid]() {
        return driver_bridge::enumerate_modules_for(pid);
    });
    if (modules_phase.threw) {
        error = "Exception while enumerating modules for PID " + std::to_string(pid) + ": " + modules_phase.exception;
        summary["failed_phase"] = "module_enumeration";
        summary["exception"] = modules_phase.exception;
        summary["exception_code"] = modules_phase.exception_code;
        summary["exception_category"] = modules_phase.exception_category;
        return false;
    }
    if (!modules_phase.completed) {
        error = "Timed out enumerating modules for PID " + std::to_string(pid) + ".";
        summary["failed_phase"] = "module_enumeration";
        summary["elapsed_ms"] = modules_phase.elapsed_ms;
        summary["last_error"] = static_cast<unsigned long>(modules_phase.gle);
        return false;
    }
    auto modules = std::move(modules_phase.value);
    diag::log_tagged_fmt("api_monitor",
        "start_module_enumeration_result pid=%u count=%zu elapsed_ms=%llu gle=%lu",
        pid,
        modules.size(),
        static_cast<unsigned long long>(modules_phase.elapsed_ms),
        modules_phase.gle);
    if (modules.empty()) {
        error = "Failed to enumerate modules for PID " + std::to_string(pid) + ".";
        return false;
    }

    const auto apis_copy = apis;
    const auto modules_copy = modules;
    auto resolve_phase = run_phase_with_timeout<resolve_phase_result_t>("api_resolve", pid, 9000, [pid, apis_copy, modules_copy](phase_cancel_t& cancel) {
        resolve_phase_result_t result;
        result.module_count = modules_copy.size();
        uint32_t slot = 0;
        for (const auto& request : apis_copy) {
            if (cancel.requested.load(std::memory_order_acquire)) {
                SetLastError(ERROR_CANCELLED);
                break;
            }
            api_target_t target;
            if (resolve_request(pid, request, modules_copy, target, &cancel)) {
                target.bp_index = slot++;
                result.targets.push_back(target);
                nlohmann::json item;
                item["api"] = request.original;
                item["address"] = hex_addr(target.address);
                item["module"] = target.resolved_module;
                item["module_offset"] = hex_addr(target.module_offset);
                item["bp_slot"] = target.bp_index;
                item["kind"] = kind_name(target.request.kind);
                result.resolved.push_back(item);
            } else {
                result.unresolved.push_back(request.original);
            }
        }
        result.resolved_count = static_cast<uint32_t>(result.targets.size());
        return result;
    });
    if (resolve_phase.threw) {
        error = "Exception while resolving requested APIs for PID " + std::to_string(pid) + ": " + resolve_phase.exception;
        summary["failed_phase"] = "api_resolve";
        summary["exception"] = resolve_phase.exception;
        summary["exception_code"] = resolve_phase.exception_code;
        summary["exception_category"] = resolve_phase.exception_category;
        return false;
    }
    if (!resolve_phase.completed) {
        error = "Timed out resolving requested API exports for PID " + std::to_string(pid) + ".";
        summary["failed_phase"] = "api_resolve";
        summary["elapsed_ms"] = resolve_phase.elapsed_ms;
        summary["module_count"] = modules.size();
        summary["last_error"] = static_cast<unsigned long>(resolve_phase.gle);
        return false;
    }

    auto targets = std::move(resolve_phase.value.targets);
    nlohmann::json resolved = std::move(resolve_phase.value.resolved);
    nlohmann::json unresolved = std::move(resolve_phase.value.unresolved);
    diag::log_tagged_fmt("api_monitor",
        "start_api_resolve_result pid=%u resolved=%u unresolved=%zu module_count=%zu elapsed_ms=%llu gle=%lu",
        pid,
        resolve_phase.value.resolved_count,
        unresolved.is_array() ? unresolved.size() : 0,
        resolve_phase.value.module_count,
        static_cast<unsigned long long>(resolve_phase.elapsed_ms),
        resolve_phase.gle);

    if (targets.empty()) {
        error = "No requested APIs resolved in the target process.";
        summary["unresolved"] = unresolved;
        summary["failed_phase"] = "api_resolve";
        return false;
    }

    if (max_capture_bytes == 0)
        max_capture_bytes = 256;
    if (max_capture_bytes > 2048)
        max_capture_bytes = 2048;
    if (max_events < 64)
        max_events = 64;
    if (max_events > 16384)
        max_events = 16384;

    diag::log_tagged_fmt("api_monitor",
        "state_setup_begin pid=%u targets=%zu modules=%zu max_events=%zu max_capture_bytes=%u",
        pid,
        targets.size(),
        modules.size(),
        max_events,
        max_capture_bytes);
    const size_t target_count_for_state = targets.size();
    const size_t module_count_for_state = modules.size();
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.pid = pid;
        g_state.requested = apis;
        g_state.targets = std::move(targets);
        g_state.modules = std::move(modules);
        g_state.events.clear();
        g_state.socket_cache = {};
        g_state.capture_buffer = capture_buffer;
        g_state.log_callstack = log_callstack;
        g_state.max_capture_bytes = max_capture_bytes;
        g_state.max_events = max_events;
        g_state.next_sequence = 1;
    }
    diag::log_tagged_fmt("api_monitor",
        "state_setup_end pid=%u targets=%zu modules=%zu elapsed_ms=%llu",
        pid,
        target_count_for_state,
        module_count_for_state,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    g_state.total_hits.store(0, std::memory_order_relaxed);
    g_state.debugger_error.store(0);
    g_state.active.store(true);

    if (!start_polling(error)) {
        summary["failed_phase"] = "start_polling";
        summary["status"] = status_json();
        stop();
        return false;
    }

    uint32_t armed_thread_breakpoints = 0;
    const uint64_t arm_wait_start = GetTickCount64();
    for (int i = 0; i < 80; ++i) {
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            armed_thread_breakpoints = 0;
            for (const auto& target : g_state.targets)
                armed_thread_breakpoints += static_cast<uint32_t>(target.armed_tids.size());
        }
        if (armed_thread_breakpoints != 0 || !g_state.debug_loop_running.load())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    diag::log_tagged_fmt("api_monitor",
        "breakpoint_arming_wait_done pid=%u armed_thread_breakpoints=%u elapsed_ms=%llu active=%d polling=%d debug_loop=%d attached=%d",
        pid,
        armed_thread_breakpoints,
        static_cast<unsigned long long>(GetTickCount64() - arm_wait_start),
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);

    if (!g_state.active.load() || !g_state.debug_attached.load() || !g_state.debug_loop_running.load()) {
        error = "API monitor kernel context loop did not remain active after startup.";
        summary["failed_phase"] = "breakpoint_arming";
        summary["status"] = status_json();
        stop();
        return false;
    }

    if (armed_thread_breakpoints == 0) {
        error = "API monitor kernel context loop started but no thread hardware breakpoints were armed.";
        summary["failed_phase"] = "breakpoint_arming";
        summary["status"] = status_json();
        stop();
        return false;
    }

    summary["pid"] = pid;
    summary["backend"] = "hardware_breakpoint_kernel_context";
    summary["kernel_context_loop"] = true;
    summary["capture_buffer"] = capture_buffer;
    summary["log_callstack"] = log_callstack;
    summary["max_capture_bytes"] = max_capture_bytes;
    summary["max_events"] = max_events;
    summary["resolved"] = resolved;
    summary["unresolved"] = unresolved;
    summary["armed_thread_breakpoints"] = armed_thread_breakpoints;
    summary["active"] = g_state.active.load();
    summary["debug_attached"] = g_state.debug_attached.load();
    summary["debug_loop_running"] = g_state.debug_loop_running.load();
    summary["startup_elapsed_ms"] = GetTickCount64() - start_ms;
    summary["status"] = status_json();
    diag::log_tagged_fmt("api_monitor",
        "start_exit ok=1 pid=%u resolved=%zu unresolved=%zu armed_thread_breakpoints=%u elapsed_ms=%llu",
        pid,
        resolved.is_array() ? resolved.size() : 0,
        unresolved.is_array() ? unresolved.size() : 0,
        armed_thread_breakpoints,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    log_phase_state("start_exit_success", "start", pid, GetCurrentThreadId(), GetTickCount64() - start_ms, 0);
    return true;
}

inline nlohmann::json registers_to_json(const register_snapshot_t& r) {
    nlohmann::json j;
    j["rax"] = hex_addr(r.rax);
    j["rbx"] = hex_addr(r.rbx);
    j["rcx"] = hex_addr(r.rcx);
    j["rdx"] = hex_addr(r.rdx);
    j["rsi"] = hex_addr(r.rsi);
    j["rdi"] = hex_addr(r.rdi);
    j["rbp"] = hex_addr(r.rbp);
    j["rsp"] = hex_addr(r.rsp);
    j["r8"] = hex_addr(r.r8);
    j["r9"] = hex_addr(r.r9);
    j["r10"] = hex_addr(r.r10);
    j["r11"] = hex_addr(r.r11);
    j["r12"] = hex_addr(r.r12);
    j["r13"] = hex_addr(r.r13);
    j["r14"] = hex_addr(r.r14);
    j["r15"] = hex_addr(r.r15);
    j["rip"] = hex_addr(r.rip);
    j["rflags"] = hex_addr(r.rflags);
    return j;
}

inline nlohmann::json buffer_to_json(const buffer_capture_t& b) {
    nlohmann::json j;
    j["kind"] = b.kind;
    j["direction"] = b.direction;
    j["address"] = hex_addr(b.address);
    j["requested_size"] = b.requested_size;
    j["captured_size"] = b.captured_size;
    j["truncated"] = b.truncated;
    j["readable"] = b.readable;
    if (!b.bytes.empty())
        j["hex"] = bytes_to_hex(b.bytes);
    return j;
}

inline nlohmann::json frame_to_json(const frame_t& f) {
    nlohmann::json j;
    j["address"] = hex_addr(f.address);
    j["module"] = f.module_name;
    j["module_offset"] = hex_addr(f.module_offset);
    return j;
}

inline nlohmann::json event_to_json(const api_event_t& event) {
    nlohmann::json j;
    j["sequence"] = event.sequence;
    j["timestamp_ms"] = event.timestamp_ms;
    j["pid"] = event.pid;
    j["tid"] = event.tid;
    j["api"] = event.api;
    j["api_address"] = hex_addr(event.api_address);
    j["api_module"] = event.api_module;
    j["api_module_offset"] = hex_addr(event.api_module_offset);
    if (event.return_address != 0)
        j["return_address"] = hex_addr(event.return_address);
    if (event.callsite_address != 0)
        j["caller_address"] = hex_addr(event.callsite_address);
    if (!event.caller_module.empty()) {
        j["caller_module"] = event.caller_module;
        j["caller_module_offset"] = hex_addr(event.caller_module_offset);
    }
    j["registers"] = registers_to_json(event.regs);
    j["metadata"] = event.metadata;

    nlohmann::json buffers = nlohmann::json::array();
    for (const auto& b : event.buffers)
        buffers.push_back(buffer_to_json(b));
    j["buffers"] = buffers;

    if (!event.callstack.empty()) {
        nlohmann::json frames = nlohmann::json::array();
        for (const auto& f : event.callstack)
            frames.push_back(frame_to_json(f));
        j["callstack"] = frames;
    }
    return j;
}

inline nlohmann::json status_json() {
    nlohmann::json j;
    uint32_t armed = 0;
    std::vector<std::pair<api_target_t, uint32_t>> readback_requests;
    std::shared_ptr<worker_lifetime_t> worker;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        worker = g_state.worker_owner;
        j["pid"] = g_state.pid;
        j["target_count"] = static_cast<int>(g_state.targets.size());
        j["event_count"] = static_cast<int>(g_state.events.size());
        nlohmann::json targets = nlohmann::json::array();
        for (const auto& target : g_state.targets) {
            armed += static_cast<uint32_t>(target.armed_tids.size());
            nlohmann::json item;
            item["api"] = target.request.original;
            item["address"] = hex_addr(target.address);
            item["module"] = target.resolved_module;
            item["bp_slot"] = target.bp_index;
            item["active"] = target.active;
            item["armed_thread_count"] = static_cast<int>(target.armed_tids.size());
            item["armed_tids"] = target.armed_tids;
            for (uint32_t tid : target.armed_tids) {
                if (readback_requests.size() < 64)
                    readback_requests.emplace_back(target, tid);
            }
            targets.push_back(std::move(item));
        }
        j["targets"] = std::move(targets);
    }
    nlohmann::json armed_readback = nlohmann::json::array();
    for (const auto& request : readback_requests) {
        const api_target_t& target = request.first;
        const uint32_t tid = request.second;
        driver_bridge::thread_context_t ctx{};
        SetLastError(ERROR_SUCCESS);
        const bool got_context = driver_bridge::get_thread_context(tid, ctx);
        const DWORD gle = got_context ? ERROR_SUCCESS : GetLastError();
        const uint64_t slot_addr = got_context ? context_dr_address(ctx, target.bp_index) : 0;
        const bool slot_enabled = got_context && target.bp_index <= 3 && ((ctx.dr7 & (1ull << static_cast<unsigned>(target.bp_index * 2))) != 0);
        armed_readback.push_back(nlohmann::json{
            {"api", target.request.original},
            {"tid", tid},
            {"slot", target.bp_index},
            {"type", "execute"},
            {"length", 1},
            {"driver_type", 0},
            {"driver_size", 0},
            {"requested_address", hex_addr(target.address)},
            {"got_context", got_context},
            {"gle", static_cast<unsigned long>(gle)},
            {"driver_status", driver_bridge::status()},
            {"driver_last_error", driver_bridge::last_error()},
            {"rip", hex_addr(ctx.rip)},
            {"dr0", hex_addr(ctx.dr0)},
            {"dr1", hex_addr(ctx.dr1)},
            {"dr2", hex_addr(ctx.dr2)},
            {"dr3", hex_addr(ctx.dr3)},
            {"dr6", hex_addr(ctx.dr6)},
            {"dr7", hex_addr(ctx.dr7)},
            {"slot_address", hex_addr(slot_addr)},
            {"slot_matches", slot_addr != 0 && slot_addr == target.address},
            {"slot_enabled", slot_enabled}
        });
    }
    j["armed_readback"] = std::move(armed_readback);
    j["armed_readback_count"] = readback_requests.size();
    const auto wq = aida::network::executor_status::work_stats();
    const auto sq = aida::network::executor_status::service_stats();
    j["executor_work"] = {
        {"alive", wq.alive},
        {"workers", wq.workers},
        {"pending", wq.pending},
        {"active", wq.active},
        {"rejected", wq.rejected}
    };
    j["executor_service"] = {
        {"alive", sq.alive},
        {"workers", sq.workers},
        {"pending", sq.pending},
        {"active", sq.active},
        {"rejected", sq.rejected}
    };
    j["active"] = g_state.active.load();
    j["polling"] = g_state.polling.load();
    j["stop_requested"] = g_state.stop_requested.load(std::memory_order_acquire);
    j["debug_attached"] = g_state.debug_attached.load();
    j["debug_loop_running"] = g_state.debug_loop_running.load();
    bool worker_completed = true;
    if (worker) {
        std::lock_guard<std::mutex> lock(worker->mutex);
        worker_completed = worker->completed;
    }
    j["worker_owned"] = static_cast<bool>(worker);
    j["worker_completed"] = worker_completed;
    j["worker_draining"] = worker && !worker_completed;
    j["cleanup_running"] = g_state.cleanup_running.load();
    j["debugger_error"] = static_cast<unsigned long>(g_state.debugger_error.load());
    j["total_hits"] = g_state.total_hits.load(std::memory_order_relaxed);
    j["armed_thread_breakpoints"] = armed;
    j["cleanup_attempts"] = g_state.cleanup_attempts.load(std::memory_order_relaxed);
    j["cleanup_last_elapsed_ms"] = g_state.cleanup_last_elapsed_ms.load(std::memory_order_relaxed);
    j["cleanup_last_requests"] = g_state.cleanup_last_requests.load(std::memory_order_relaxed);
    j["cleanup_last_succeeded"] = g_state.cleanup_last_succeeded.load(std::memory_order_relaxed);
    j["cleanup_last_failed"] = g_state.cleanup_last_failed.load(std::memory_order_relaxed);
    return j;
}

inline nlohmann::json results(size_t limit,
                              const std::string& filter_api,
                              bool clear_after,
                              bool stop_after) {
    if (limit == 0)
        limit = 64;
    if (limit > 512)
        limit = 512;

    const std::string filter = to_lower(filter_api);
    std::vector<api_event_t> selected;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto it = g_state.events.rbegin(); it != g_state.events.rend() && selected.size() < limit; ++it) {
            if (!filter.empty() && to_lower(it->api).find(filter) == std::string::npos)
                continue;
            selected.push_back(*it);
        }
        std::reverse(selected.begin(), selected.end());
        if (clear_after)
            g_state.events.clear();
    }

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& event : selected)
        arr.push_back(event_to_json(event));

    if (stop_after)
        stop();

    nlohmann::json out;
    out["events"] = arr;
    out["count"] = static_cast<int>(arr.size());
    out["status"] = status_json();
    out["stopped"] = stop_after;
    return out;
}

inline void clear_events() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.events.clear();
}

}
