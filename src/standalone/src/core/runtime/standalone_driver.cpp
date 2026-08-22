#define WIN32_LEAN_AND_MEAN
#include "standalone_driver.hpp"
#include "standalone_driver_identity.hpp"
#include "driver_loader.hpp"
#include "toast_notification.hpp"
#include "comm.h"
#include "win_thread.hpp"
#include "../infra/executor.hpp"
#include "../infra/event_bus.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "../helpers/diag_log.hpp"
#include "../diagnostics/metadata_ring.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstdarg>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace driver_bridge
{
    bool current_remote_call_cancelled() noexcept;
}

namespace driver_bridge_pid_call
{
    std::recursive_mutex g_target_context_mtx;
}

namespace
{
    driver_bridge::log_fn_t     g_log_fn;
    driver_bridge::confirm_fn_t g_confirm_fn;
    std::vector<driver_bridge::pre_detach_fn_t> g_pre_detach_hooks;
    std::mutex                  g_callback_mtx;

    std::mutex      g_state_mtx;
    HANDLE          g_process = nullptr;

    struct bridge_region_snapshot_t
    {
        bool ok = false;
        DWORD gle = ERROR_SUCCESS;
        uint64_t base = 0;
        uint64_t allocation_base = 0;
        uint64_t size = 0;
        DWORD state = 0;
        DWORD protect = 0;
        DWORD type = 0;
        DWORD allocation_protect = 0;
    };

    bridge_region_snapshot_t capture_bridge_region_snapshot(uint64_t address)
    {
        bridge_region_snapshot_t snap{};
        HANDLE process = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
        }
        if (!process) {
            snap.gle = ERROR_INVALID_HANDLE;
            return snap;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        SetLastError(ERROR_SUCCESS);
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            snap.ok = true;
            snap.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            snap.allocation_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
            snap.size = static_cast<uint64_t>(mbi.RegionSize);
            snap.state = mbi.State;
            snap.protect = mbi.Protect;
            snap.type = mbi.Type;
            snap.allocation_protect = mbi.AllocationProtect;
        } else {
            snap.gle = GetLastError();
        }
        return snap;
    }

    std::string format_byte_prefix(const uint8_t* data, size_t size)
    {
        if (!data || size == 0)
            return "<empty>";
        char tmp[4] = {};
        std::string out;
        const size_t n = (std::min)(size, static_cast<size_t>(16));
        out.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) {
            _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "%02X", static_cast<unsigned>(data[i]));
            out += tmp;
        }
        return out;
    }

    bool bytes_all_zero(const uint8_t* data, size_t size)
    {
        if (!data || size == 0)
            return false;
        for (size_t i = 0; i < size; ++i) {
            if (data[i] != 0)
                return false;
        }
        return true;
    }

    uint32_t        g_pid = 0;
    std::atomic<uint32_t> g_pid_snapshot{0};
    uint32_t        g_primary_pid = 0;
    std::atomic_bool g_lower_remote_call_last_abandoned{false};
    std::string     g_process_name;
    std::string     g_last_error;
    std::atomic<bool> g_last_error_present{false};
    bool            g_initialized = false;
    bool            g_kernel_mode = false;
    bool            g_has_vm_read = false;
    bool            g_kernel_attached = false;
    std::atomic<std::uint64_t> g_active_pid_generation{1};
    std::atomic<std::uint64_t> g_remote_call_sequence{1};
    std::atomic<std::uint32_t> g_remote_call_lower_inflight{0};
    std::atomic_bool g_remote_call_lower_worker_started{false};
    std::atomic_bool g_remote_call_lower_worker_alive{false};
    std::atomic<DWORD> g_remote_call_lower_worker_tid{0};
    std::atomic<std::uint32_t> g_remote_call_lower_queue_depth{0};
    thread_local driver_bridge::remote_call_execution_diag_t g_last_remote_call_execution_diag{};
    bool env_flag_enabled(const char* name)
    {
        if (!name || !*name)
            return false;
        char value[16] = {};
        DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
        if (n == 0)
            return false;
        if (n >= sizeof(value))
            return true;
        return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
    }

    bool driver_error_toast_suppressed()
    {
        return env_flag_enabled("AIDA_FULL_TEST_RUNNING");
    }

    struct process_ctx_t {
        HANDLE      h_process = nullptr;
        bool        kernel_attached = false;
        bool        has_vm_read = false;
        std::string name;
        uint64_t    cached_image_base = 0;
        uint64_t    cached_dtb = 0;
        uint64_t    cached_kernel_dtb = 0;
        bool        has_identity = false;
        driver_bridge::identity::live_target_identity_t identity;
    };

    std::unordered_map<uint32_t, process_ctx_t> g_processes;

    struct target_context_snapshot_t
    {
        uint32_t pid = 0;
        uint64_t generation = 0;
        uint64_t dtb = 0;
    };

    class target_context_lock_t
    {
    public:
        explicit target_context_lock_t(const char* operation)
            : operation_(operation ? operation : "unknown")
        {
            const ULONGLONG started = GetTickCount64();
            lock_ = std::unique_lock<std::recursive_mutex>(driver_bridge_pid_call::g_target_context_mtx);
            wait_ms_ = GetTickCount64() - started;
            diag::log_tagged_fmt("driver_bridge",
                "target_context_lock_acquired op=%s tid=%lu wait_ms=%llu active_pid=%u generation=%llu device_pid=%u dtb=0x%llX",
                operation_,
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(wait_ms_),
                g_pid_snapshot.load(std::memory_order_acquire),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                device ? device->get_process_id() : 0,
                static_cast<unsigned long long>(device ? device->get_dtb() : 0));
        }

        target_context_lock_t(const target_context_lock_t&) = delete;
        target_context_lock_t& operator=(const target_context_lock_t&) = delete;

    private:
        const char* operation_;
        ULONGLONG wait_ms_ = 0;
        std::unique_lock<std::recursive_mutex> lock_;
    };

    target_context_snapshot_t capture_target_context_snapshot()
    {
        target_context_snapshot_t snapshot;
        snapshot.pid = g_pid_snapshot.load(std::memory_order_acquire);
        snapshot.generation = g_active_pid_generation.load(std::memory_order_acquire);
        snapshot.dtb = device ? device->get_dtb() : 0;
        return snapshot;
    }

    bool validate_target_context_snapshot(const char* operation,
                                          const target_context_snapshot_t& expected)
    {
        const uint32_t actual_pid = g_pid_snapshot.load(std::memory_order_acquire);
        const uint64_t actual_generation = g_active_pid_generation.load(std::memory_order_acquire);
        const uint32_t actual_device_pid = device ? device->get_process_id() : 0;
        const uint64_t actual_dtb = device ? device->get_dtb() : 0;
        const bool dtb_valid = expected.dtb == 0 ? actual_dtb == 0 : expected.dtb == actual_dtb;
        const bool valid = expected.pid == actual_pid &&
            (expected.pid == 0 || expected.pid == actual_device_pid) &&
            expected.generation == actual_generation && dtb_valid;
        if (!valid) {
            diag::log_tagged_critical_fmt("driver_bridge",
                "target_context_stale_reject op=%s tid=%lu expected_pid=%u actual_pid=%u device_pid=%u expected_generation=%llu actual_generation=%llu expected_dtb=0x%llX actual_dtb=0x%llX",
                operation ? operation : "unknown",
                static_cast<unsigned long>(GetCurrentThreadId()),
                expected.pid, actual_pid, actual_device_pid,
                static_cast<unsigned long long>(expected.generation),
                static_cast<unsigned long long>(actual_generation),
                static_cast<unsigned long long>(expected.dtb),
                static_cast<unsigned long long>(actual_dtb));
            SetLastError(ERROR_OPERATION_ABORTED);
        }
        return valid;
    }

    thread_local driver_bridge::remote_call_context_t g_remote_call_context_tls;
    thread_local bool g_remote_call_context_active_tls = false;

    const char* nonempty_cstr(const char* value, const char* fallback) noexcept
    {
        return value && value[0] ? value : fallback;
    }

    struct remote_call_snapshot_t
    {
        const char* label = "";
        const char* tool = "";
        const char* diag_id = "";
        uint32_t pid = 0;
        uint32_t timeout_ms = 0;
        uint64_t deadline_ms = 0;
        bool cancelled = false;
        bool require_deadline = false;
        bool allow_zero_result = false;
        bool context_active = false;
    };

    remote_call_snapshot_t capture_remote_call_snapshot() noexcept
    {
        remote_call_snapshot_t snapshot{};
        const driver_bridge::remote_call_context_t* ctx = g_remote_call_context_active_tls ? &g_remote_call_context_tls : nullptr;
        snapshot.context_active = ctx != nullptr;
        snapshot.label = ctx ? nonempty_cstr(ctx->label, "driver_bridge::call_function") : "driver_bridge::call_function";
        snapshot.tool = ctx ? nonempty_cstr(ctx->tool, mcp_standalone::current_call_tool_name()) : mcp_standalone::current_call_tool_name();
        snapshot.diag_id = ctx ? nonempty_cstr(ctx->diag_id, mcp_standalone::current_call_diag_id()) : mcp_standalone::current_call_diag_id();
        snapshot.pid = ctx && ctx->pid != 0 ? ctx->pid : driver_bridge::attached_pid();
        snapshot.timeout_ms = ctx ? ctx->timeout_ms : 0;
        snapshot.deadline_ms = ctx && ctx->deadline_ms != 0 ? ctx->deadline_ms : mcp_standalone::current_call_deadline_ms();
        snapshot.require_deadline = ctx ? ctx->require_deadline : false;
        snapshot.allow_zero_result = ctx ? ctx->allow_zero_result : false;
        snapshot.cancelled = mcp_standalone::current_call_cancelled() ||
            (ctx && ctx->cancel_token && ctx->cancel_token->load(std::memory_order_acquire));
        snapshot.label = nonempty_cstr(snapshot.label, "");
        snapshot.tool = nonempty_cstr(snapshot.tool, "");
        snapshot.diag_id = nonempty_cstr(snapshot.diag_id, "");
        return snapshot;
    }

    uint64_t deadline_remaining_ms(uint64_t deadline_ms, ULONGLONG now) noexcept
    {
        if (deadline_ms == 0 || now >= deadline_ms)
            return 0;
        return deadline_ms - now;
    }

    struct lower_remote_call_outcome_t
    {
        bool completed = false;
        bool lower_ok = false;
        bool stale_generation = false;
        bool cancelled = false;
        bool deadline_expired = false;
        bool lower_lock_timeout = false;
        bool worker_exception = false;
        bool worker_creation_failed = false;
        bool allow_zero_result = false;
        bool zero_result_rejected = false;
        bool caller_abandoned = false;
        bool removed_from_queue = false;
        bool popped_from_queue = false;
        bool execution_started = false;
        bool executing_abandoned = false;
        bool seh_exception = false;
        uint32_t seh_exception_code = 0;
        uint64_t seh_exception_address = 0;
        uint64_t seh_fault_address = 0;
        uint64_t seh_rip = 0;
        uint64_t seh_rsp = 0;
        uint64_t seh_rbp = 0;
        DWORD gle = ERROR_SUCCESS;
        uint64_t result = 0;
        uint32_t active_pid_after = 0;
        uint64_t generation_after = 0;
        ULONGLONG elapsed_ms = 0;
        ULONGLONG lower_elapsed_ms = 0;
        ULONGLONG queue_wait_ms = 0;
        ULONGLONG deadline_remaining_at_queue_ms = 0;
        ULONGLONG deadline_remaining_at_start_ms = 0;
        ULONGLONG deadline_remaining_at_finish_ms = 0;
        uint32_t worker_tid = 0;
        uint32_t worker_alive = 0;
        uint32_t queue_depth_at_submit = 0;
        uint32_t queue_depth_at_start = 0;
        uint32_t queue_depth_after_pop = 0;
        uint32_t inflight_at_submit = 0;
        uint32_t inflight_at_start = 0;
        uint32_t inflight_after = 0;
        int worker_error_value = 0;
        std::string worker_error_category;
        std::string worker_error_message;
        std::string completion_reason;
    };

    struct lower_remote_call_shared_state_t
    {
        std::mutex mutex;
        std::condition_variable cv;
        lower_remote_call_outcome_t outcome;
        bool done = false;
        bool abandoned = false;
        bool popped = false;
        bool executing = false;
        bool lower_returned = false;
        DWORD worker_tid = 0;
        ULONGLONG popped_at = 0;
        ULONGLONG executing_at = 0;
        char abandoned_reason[32] = {};
    };

    bool lower_remote_call_uninterruptible(const lower_remote_call_outcome_t& outcome) noexcept
    {
        return outcome.executing_abandoned ||
               (!outcome.completed &&
                (outcome.completion_reason == "cancelled" || outcome.completion_reason == "deadline"));
    }

    struct lower_executor_pe_stack_t
    {
        bool ok = false;
        DWORD gle = ERROR_SUCCESS;
        uint64_t reserve = 0;
        uint64_t commit = 0;
    };

    struct lower_executor_job_snapshot_t
    {
        bool is_process_in_job_ok = false;
        bool in_job = false;
        bool limits_ok = false;
        DWORD is_process_in_job_gle = ERROR_SUCCESS;
        DWORD limits_gle = ERROR_SUCCESS;
        DWORD limit_flags = 0;
        DWORD active_process_limit = 0;
        SIZE_T process_memory_limit = 0;
        SIZE_T job_memory_limit = 0;
        SIZE_T peak_process_memory_used = 0;
        SIZE_T peak_job_memory_used = 0;
    };

    struct lower_executor_pool_snapshot_t
    {
        bool alive = false;
        bool shutting_down = false;
        int pool_size = 0;
        size_t workers = 0;
        size_t pending = 0;
        uint32_t active = 0;
        uint64_t post_attempts = 0;
        uint64_t posted = 0;
        uint64_t rejected = 0;
        uint64_t started = 0;
        uint64_t finished = 0;
        uint64_t oldest_active_ms = 0;
        uint32_t active_label_count = 0;
        std::string active_labels;
    };

    struct lower_executor_thread_inventory_t
    {
        lower_executor_pool_snapshot_t executor_general;
        lower_executor_pool_snapshot_t executor_service;
        lower_executor_pool_snapshot_t executor_critical;
    };

    struct lower_executor_process_stats_t
    {
        DWORD handle_count = 0;
        DWORD thread_count = 0;
        SIZE_T private_bytes = 0;
        SIZE_T working_set = 0;
        SIZE_T pagefile_usage = 0;
        SIZE_T peak_working_set = 0;
        SIZE_T quota_paged_pool = 0;
        SIZE_T quota_nonpaged_pool = 0;
        SIZE_T min_working_set = 0;
        SIZE_T max_working_set = 0;
        DWORD working_set_flags = 0;
        DWORD memory_load = 0;
        DWORDLONG total_phys = 0;
        DWORDLONG avail_phys = 0;
        DWORDLONG total_page_file = 0;
        DWORDLONG avail_page_file = 0;
        DWORDLONG total_virtual = 0;
        DWORDLONG avail_virtual = 0;
        SIZE_T commit_total = 0;
        SIZE_T commit_limit = 0;
        SIZE_T commit_peak = 0;
        SIZE_T physical_total = 0;
        SIZE_T physical_available = 0;
        SIZE_T system_cache = 0;
        SIZE_T kernel_total = 0;
        SIZE_T kernel_paged = 0;
        SIZE_T kernel_nonpaged = 0;
        bool handle_count_ok = false;
        bool memory_ok = false;
        bool working_set_limits_ok = false;
        bool global_memory_ok = false;
        bool performance_ok = false;
        lower_executor_pe_stack_t pe_stack;
        lower_executor_job_snapshot_t job;
        lower_executor_thread_inventory_t pools;
    };

    struct lower_remote_call_work_item_t
    {
        std::shared_ptr<lower_remote_call_shared_state_t> state;
        std::function<bool(uint64_t&, DWORD&, bool&)> lower_fn;
        std::string phase;
        std::string label;
        std::string tool;
        std::string diag_id;
        uint64_t call_id = 0;
        uint64_t generation_at_entry = 0;
        uint64_t function_address = 0;
        uint32_t expected_pid = 0;
        uint32_t active_pid_at_entry = 0;
        uint32_t timeout_ms = 0;
        bool allow_zero_result = false;
        ULONGLONG deadline_ms = 0;
        ULONGLONG call_start = 0;
        ULONGLONG queued_at = 0;
        ULONGLONG deadline_remaining_at_queue_ms = 0;
        uint32_t queue_depth_at_submit = 0;
        uint32_t inflight_at_submit = 0;
    };

    std::mutex g_remote_call_lower_executor_mutex;
    std::condition_variable g_remote_call_lower_executor_cv;
    std::condition_variable g_remote_call_lower_start_cv;
    std::deque<std::shared_ptr<lower_remote_call_work_item_t>> g_remote_call_lower_queue;
    HANDLE g_remote_call_lower_worker_handle = nullptr;
    unsigned g_remote_call_lower_worker_begin_tid = 0;
    std::atomic_bool g_remote_call_lower_executor_stop{false};
    std::atomic_bool g_remote_call_lower_worker_loop_ready{false};
    static constexpr std::uint32_t kLowerRemoteCallMaxQueueDepth = 32;
    static constexpr DWORD kLowerRemoteCallWorkerReadyWaitMs = 1000;
    static constexpr DWORD kLowerRemoteCallStartBackoffInitialMs = 500;
    static constexpr DWORD kLowerRemoteCallStartBackoffMaxMs = 10000;
    HANDLE g_remote_call_lower_worker2_handle = nullptr;
    unsigned g_remote_call_lower_worker2_begin_tid = 0;
    std::atomic_bool g_remote_call_lower_worker2_started{false};
    std::atomic_bool g_remote_call_lower_worker2_alive{false};
    std::atomic<DWORD> g_remote_call_lower_worker2_tid{0};
    std::atomic_bool g_remote_call_lower_worker2_loop_ready{false};
    std::condition_variable g_remote_call_lower_start2_cv;
    std::atomic_bool g_lower_remote_call_worker_recovering{false};
    struct lower_worker_heartbeat_t {
        std::atomic<uint64_t> call_id{0};
        std::atomic<ULONGLONG> popped_at{0};
        std::atomic<bool> executing{false};
        std::mutex str_mutex;
        char phase[32] = {};
        char label[64] = {};
    };
    lower_worker_heartbeat_t g_lower_worker_heartbeat;

    struct lower_executor_start_failure_cache_t
    {
        bool valid = false;
        uint64_t first_call_id = 0;
        uint64_t last_call_id = 0;
        uint64_t generation_at_failure = 0;
        ULONGLONG first_failure_ms = 0;
        ULONGLONG last_failure_ms = 0;
        ULONGLONG next_retry_ms = 0;
        ULONGLONG last_suppressed_log_ms = 0;
        uint32_t failure_count = 0;
        uint32_t suppressed_count = 0;
        DWORD gle = ERROR_SUCCESS;
        DWORD win32_error = ERROR_SUCCESS;
        int crt_errno = 0;
        unsigned long crt_doserrno = 0;
        int system_error_value = 0;
        uint32_t active_pid_at_failure = 0;
        uint32_t queue_depth = 0;
        uint32_t inflight = 0;
        uint32_t worker_alive = 0;
        DWORD worker_tid = 0;
        DWORD backoff_ms = 0;
        uint64_t resource_signature = 0;
        std::string api;
        std::string system_error_category;
        std::string system_error_message;
        std::string what;
        lower_executor_process_stats_t stats;
    };

    lower_executor_start_failure_cache_t g_remote_call_lower_start_failure;

    DWORD current_process_thread_count() noexcept
    {
        DWORD count = 0;
        const DWORD pid = GetCurrentProcessId();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid)
                    ++count;
                entry.dwSize = sizeof(entry);
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return count;
    }

    uint64_t lower_executor_mix_u64(uint64_t h, uint64_t v) noexcept
    {
        h ^= v + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
        return h;
    }

    lower_executor_pe_stack_t capture_lower_executor_pe_stack() noexcept
    {
        lower_executor_pe_stack_t stack{};
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module) {
            stack.gle = GetLastError();
            return stack;
        }
        __try {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                stack.gle = ERROR_BAD_EXE_FORMAT;
                return stack;
            }
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) {
                stack.gle = ERROR_BAD_EXE_FORMAT;
                return stack;
            }
            stack.reserve = static_cast<uint64_t>(nt->OptionalHeader.SizeOfStackReserve);
            stack.commit = static_cast<uint64_t>(nt->OptionalHeader.SizeOfStackCommit);
            stack.ok = true;
            stack.gle = ERROR_SUCCESS;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            stack.ok = false;
            stack.gle = GetExceptionCode();
        }
        return stack;
    }

    lower_executor_pool_snapshot_t lower_executor_pool_from_executor_snapshot(
        const aida::infra::executor::active_snapshot_t& exec,
        const aida::infra::taskflow_runtime::runtime_snapshot_t& runtime,
        aida::infra::executor::domain_t domain)
    {
        lower_executor_pool_snapshot_t out{};
        out.alive = runtime.accepting;
        out.shutting_down = runtime.shutting_down;
        if (domain == aida::infra::executor::domain_t::service) {
            out.pending = static_cast<size_t>(exec.service_queue_pending);
            out.active = exec.service_queue_active;
        } else if (domain == aida::infra::executor::domain_t::critical) {
            out.pending = static_cast<size_t>(exec.critical_queue_pending);
            out.active = exec.critical_queue_active;
        } else {
            out.pending = static_cast<size_t>(exec.work_queue_pending);
            out.active = exec.work_queue_active;
        }
        out.post_attempts = aida::infra::executor::total_submits.load(std::memory_order_acquire);
        out.posted = runtime.total_submitted;
        out.rejected = runtime.total_rejected;
        out.started = runtime.total_active;
        out.finished = runtime.total_submitted >= runtime.total_active ? runtime.total_submitted - runtime.total_active : 0;
        out.oldest_active_ms = exec.oldest_active_ms;
        out.active_label_count = static_cast<uint32_t>(runtime.active_jobs.size());
        out.active_labels = exec.labels_under_pressure;
        return out;
    }

    lower_executor_thread_inventory_t capture_lower_executor_thread_inventory()
    {
        lower_executor_thread_inventory_t inv{};
        const auto exec = aida::infra::executor::active_snapshot();
        const auto runtime = aida::infra::taskflow_runtime::active_snapshot(64);
        inv.executor_general = lower_executor_pool_from_executor_snapshot(exec, runtime, aida::infra::executor::domain_t::general);
        inv.executor_service = lower_executor_pool_from_executor_snapshot(exec, runtime, aida::infra::executor::domain_t::service);
        inv.executor_critical = lower_executor_pool_from_executor_snapshot(exec, runtime, aida::infra::executor::domain_t::critical);
        return inv;
    }

    lower_executor_process_stats_t capture_lower_executor_process_stats() noexcept
    {
        lower_executor_process_stats_t stats{};
        DWORD handle_count = 0;
        if (GetProcessHandleCount(GetCurrentProcess(), &handle_count)) {
            stats.handle_count_ok = true;
            stats.handle_count = handle_count;
        }
        PROCESS_MEMORY_COUNTERS_EX counters{};
        counters.cb = sizeof(counters);
        if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
            stats.memory_ok = true;
            stats.private_bytes = counters.PrivateUsage;
            stats.working_set = counters.WorkingSetSize;
            stats.pagefile_usage = counters.PagefileUsage;
            stats.peak_working_set = counters.PeakWorkingSetSize;
            stats.quota_paged_pool = counters.QuotaPagedPoolUsage;
            stats.quota_nonpaged_pool = counters.QuotaNonPagedPoolUsage;
        }
        SIZE_T min_ws = 0;
        SIZE_T max_ws = 0;
        DWORD ws_flags = 0;
        if (GetProcessWorkingSetSizeEx(GetCurrentProcess(), &min_ws, &max_ws, &ws_flags)) {
            stats.working_set_limits_ok = true;
            stats.min_working_set = min_ws;
            stats.max_working_set = max_ws;
            stats.working_set_flags = ws_flags;
        }
        MEMORYSTATUSEX memory_status{};
        memory_status.dwLength = sizeof(memory_status);
        if (GlobalMemoryStatusEx(&memory_status)) {
            stats.global_memory_ok = true;
            stats.memory_load = memory_status.dwMemoryLoad;
            stats.total_phys = memory_status.ullTotalPhys;
            stats.avail_phys = memory_status.ullAvailPhys;
            stats.total_page_file = memory_status.ullTotalPageFile;
            stats.avail_page_file = memory_status.ullAvailPageFile;
            stats.total_virtual = memory_status.ullTotalVirtual;
            stats.avail_virtual = memory_status.ullAvailVirtual;
        }
        PERFORMANCE_INFORMATION perf{};
        perf.cb = sizeof(perf);
        if (GetPerformanceInfo(&perf, sizeof(perf))) {
            stats.performance_ok = true;
            stats.commit_total = perf.CommitTotal * perf.PageSize;
            stats.commit_limit = perf.CommitLimit * perf.PageSize;
            stats.commit_peak = perf.CommitPeak * perf.PageSize;
            stats.physical_total = perf.PhysicalTotal * perf.PageSize;
            stats.physical_available = perf.PhysicalAvailable * perf.PageSize;
            stats.system_cache = perf.SystemCache * perf.PageSize;
            stats.kernel_total = perf.KernelTotal * perf.PageSize;
            stats.kernel_paged = perf.KernelPaged * perf.PageSize;
            stats.kernel_nonpaged = perf.KernelNonpaged * perf.PageSize;
        }
        stats.pe_stack = capture_lower_executor_pe_stack();
        BOOL in_job = FALSE;
        if (IsProcessInJob(GetCurrentProcess(), nullptr, &in_job)) {
            stats.job.is_process_in_job_ok = true;
            stats.job.in_job = in_job ? true : false;
            stats.job.is_process_in_job_gle = ERROR_SUCCESS;
            if (in_job) {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
                if (QueryInformationJobObject(nullptr,
                        JobObjectExtendedLimitInformation,
                        &limits,
                        sizeof(limits),
                        nullptr)) {
                    stats.job.limits_ok = true;
                    stats.job.limits_gle = ERROR_SUCCESS;
                    stats.job.limit_flags = limits.BasicLimitInformation.LimitFlags;
                    stats.job.active_process_limit = limits.BasicLimitInformation.ActiveProcessLimit;
                    stats.job.process_memory_limit = limits.ProcessMemoryLimit;
                    stats.job.job_memory_limit = limits.JobMemoryLimit;
                    stats.job.peak_process_memory_used = limits.PeakProcessMemoryUsed;
                    stats.job.peak_job_memory_used = limits.PeakJobMemoryUsed;
                } else {
                    stats.job.limits_gle = GetLastError();
                }
            }
        } else {
            stats.job.is_process_in_job_gle = GetLastError();
        }
        try {
            stats.pools = capture_lower_executor_thread_inventory();
        } catch (...) {
            stats.pools = {};
        }
        stats.thread_count = current_process_thread_count();
        return stats;
    }

    uint64_t lower_executor_resource_signature(const lower_executor_process_stats_t& stats) noexcept
    {
        uint64_t h = 0xCBF29CE484222325ull;
        h = lower_executor_mix_u64(h, stats.handle_count);
        h = lower_executor_mix_u64(h, stats.thread_count);
        h = lower_executor_mix_u64(h, static_cast<uint64_t>(stats.private_bytes >> 20));
        h = lower_executor_mix_u64(h, static_cast<uint64_t>(stats.working_set >> 20));
        h = lower_executor_mix_u64(h, static_cast<uint64_t>(stats.commit_total >> 20));
        h = lower_executor_mix_u64(h, static_cast<uint64_t>(stats.commit_limit >> 20));
        h = lower_executor_mix_u64(h, static_cast<uint64_t>(stats.avail_phys >> 20));
        h = lower_executor_mix_u64(h, stats.pools.executor_general.pending);
        h = lower_executor_mix_u64(h, stats.pools.executor_service.pending);
        h = lower_executor_mix_u64(h, stats.pools.executor_critical.pending);
        h = lower_executor_mix_u64(h, stats.pools.executor_general.active);
        h = lower_executor_mix_u64(h, stats.pools.executor_service.active);
        h = lower_executor_mix_u64(h, stats.pools.executor_critical.active);
        return h;
    }

    void log_lower_executor_pool_snapshot(const char* marker,
                                          const char* name,
                                          const lower_executor_pool_snapshot_t& pool)
    {
        diag::log_tagged_fmt("driver",
            "%s pool=%s alive=%d shutting_down=%d pool_size=%d workers=%llu pending=%llu active=%u attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu oldest_active_ms=%llu active_label_count=%u labels=%s",
            marker ? marker : "lower_executor_pool_snapshot",
            name ? name : "",
            pool.alive ? 1 : 0,
            pool.shutting_down ? 1 : 0,
            pool.pool_size,
            static_cast<unsigned long long>(pool.workers),
            static_cast<unsigned long long>(pool.pending),
            pool.active,
            static_cast<unsigned long long>(pool.post_attempts),
            static_cast<unsigned long long>(pool.posted),
            static_cast<unsigned long long>(pool.rejected),
            static_cast<unsigned long long>(pool.started),
            static_cast<unsigned long long>(pool.finished),
            static_cast<unsigned long long>(pool.oldest_active_ms),
            pool.active_label_count,
            pool.active_labels.empty() ? "" : pool.active_labels.c_str());
    }

    void log_lower_executor_resource_snapshot(const char* marker,
                                              uint64_t call_id,
                                              const char* phase,
                                              const remote_call_snapshot_t& call_ctx,
                                              uint32_t expected_pid,
                                              uint32_t active_pid_at_entry,
                                              uint64_t generation_at_entry,
                                              uint64_t function_address,
                                              const lower_executor_process_stats_t& stats,
                                              uint64_t resource_signature,
                                              ULONGLONG elapsed_ms)
    {
        const char* name = marker && marker[0] ? marker : "lower_executor_resource_snapshot";
        diag::log_tagged_fmt("driver",
            "%s core call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX caller_pid=%lu caller_tid=%lu queue_depth=%u inflight=%u worker_started=%d worker_alive=%d worker_loop_ready=%d worker_tid=%lu begin_tid=%u stop=%d resource_sig=0x%016llX elapsed_ms=%llu",
            name,
            static_cast<unsigned long long>(call_id),
            phase ? phase : "",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            expected_pid,
            active_pid_at_entry,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            g_remote_call_lower_worker_started.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker_begin_tid,
            g_remote_call_lower_executor_stop.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(resource_signature),
            static_cast<unsigned long long>(elapsed_ms));
        diag::log_tagged_fmt("driver",
            "%s memory handle_ok=%d handle_count=%lu thread_count=%lu memory_ok=%d private_bytes=%llu working_set=%llu pagefile_usage=%llu peak_working_set=%llu paged_pool=%llu nonpaged_pool=%llu ws_limits_ok=%d min_ws=%llu max_ws=%llu ws_flags=0x%08lX",
            name,
            stats.handle_count_ok ? 1 : 0,
            static_cast<unsigned long>(stats.handle_count),
            static_cast<unsigned long>(stats.thread_count),
            stats.memory_ok ? 1 : 0,
            static_cast<unsigned long long>(stats.private_bytes),
            static_cast<unsigned long long>(stats.working_set),
            static_cast<unsigned long long>(stats.pagefile_usage),
            static_cast<unsigned long long>(stats.peak_working_set),
            static_cast<unsigned long long>(stats.quota_paged_pool),
            static_cast<unsigned long long>(stats.quota_nonpaged_pool),
            stats.working_set_limits_ok ? 1 : 0,
            static_cast<unsigned long long>(stats.min_working_set),
            static_cast<unsigned long long>(stats.max_working_set),
            static_cast<unsigned long>(stats.working_set_flags));
        diag::log_tagged_fmt("driver",
            "%s system global_ok=%d memory_load=%lu total_phys=%llu avail_phys=%llu total_page_file=%llu avail_page_file=%llu total_virtual=%llu avail_virtual=%llu perf_ok=%d commit_total=%llu commit_limit=%llu commit_peak=%llu physical_total=%llu physical_available=%llu system_cache=%llu kernel_total=%llu kernel_paged=%llu kernel_nonpaged=%llu",
            name,
            stats.global_memory_ok ? 1 : 0,
            static_cast<unsigned long>(stats.memory_load),
            static_cast<unsigned long long>(stats.total_phys),
            static_cast<unsigned long long>(stats.avail_phys),
            static_cast<unsigned long long>(stats.total_page_file),
            static_cast<unsigned long long>(stats.avail_page_file),
            static_cast<unsigned long long>(stats.total_virtual),
            static_cast<unsigned long long>(stats.avail_virtual),
            stats.performance_ok ? 1 : 0,
            static_cast<unsigned long long>(stats.commit_total),
            static_cast<unsigned long long>(stats.commit_limit),
            static_cast<unsigned long long>(stats.commit_peak),
            static_cast<unsigned long long>(stats.physical_total),
            static_cast<unsigned long long>(stats.physical_available),
            static_cast<unsigned long long>(stats.system_cache),
            static_cast<unsigned long long>(stats.kernel_total),
            static_cast<unsigned long long>(stats.kernel_paged),
            static_cast<unsigned long long>(stats.kernel_nonpaged));
        diag::log_tagged_fmt("driver",
            "%s stack_job pe_stack_ok=%d pe_stack_gle=%lu pe_stack_reserve=%llu pe_stack_commit=%llu in_job_ok=%d in_job=%d in_job_gle=%lu job_limits_ok=%d job_limits_gle=%lu job_limit_flags=0x%08lX active_process_limit=%lu process_memory_limit=%llu job_memory_limit=%llu peak_process_memory=%llu peak_job_memory=%llu",
            name,
            stats.pe_stack.ok ? 1 : 0,
            static_cast<unsigned long>(stats.pe_stack.gle),
            static_cast<unsigned long long>(stats.pe_stack.reserve),
            static_cast<unsigned long long>(stats.pe_stack.commit),
            stats.job.is_process_in_job_ok ? 1 : 0,
            stats.job.in_job ? 1 : 0,
            static_cast<unsigned long>(stats.job.is_process_in_job_gle),
            stats.job.limits_ok ? 1 : 0,
            static_cast<unsigned long>(stats.job.limits_gle),
            static_cast<unsigned long>(stats.job.limit_flags),
            static_cast<unsigned long>(stats.job.active_process_limit),
            static_cast<unsigned long long>(stats.job.process_memory_limit),
            static_cast<unsigned long long>(stats.job.job_memory_limit),
            static_cast<unsigned long long>(stats.job.peak_process_memory_used),
            static_cast<unsigned long long>(stats.job.peak_job_memory_used));
        log_lower_executor_pool_snapshot(name, "executor_general", stats.pools.executor_general);
        log_lower_executor_pool_snapshot(name, "executor_service", stats.pools.executor_service);
        log_lower_executor_pool_snapshot(name, "executor_critical", stats.pools.executor_critical);
    }

    uint64_t lower_executor_abs_diff(uint64_t a, uint64_t b) noexcept
    {
        return a >= b ? a - b : b - a;
    }

    bool lower_executor_resource_materially_changed(const lower_executor_start_failure_cache_t& cache,
                                                    const lower_executor_process_stats_t& stats,
                                                    uint64_t resource_signature,
                                                    uint64_t generation,
                                                    const char** reason) noexcept
    {
        if (!cache.valid) {
            if (reason)
                *reason = "no_cached_failure";
            return true;
        }
        if (generation != cache.generation_at_failure) {
            if (reason)
                *reason = "generation_changed";
            return true;
        }
        if (resource_signature != cache.resource_signature) {
            const uint64_t thread_delta = lower_executor_abs_diff(stats.thread_count, cache.stats.thread_count);
            const uint64_t handle_delta = lower_executor_abs_diff(stats.handle_count, cache.stats.handle_count);
            const uint64_t private_delta = lower_executor_abs_diff(static_cast<uint64_t>(stats.private_bytes), static_cast<uint64_t>(cache.stats.private_bytes));
            const uint64_t commit_delta = lower_executor_abs_diff(static_cast<uint64_t>(stats.commit_total), static_cast<uint64_t>(cache.stats.commit_total));
            if (thread_delta >= 2 || handle_delta >= 16 || private_delta >= (16ull * 1024ull * 1024ull) || commit_delta >= (16ull * 1024ull * 1024ull)) {
                if (reason)
                    *reason = "resource_changed";
                return true;
            }
        }
        if (reason)
            *reason = "cached_backoff";
        return false;
    }

    bool lower_executor_should_log_cached_suppression(lower_executor_start_failure_cache_t& cache, ULONGLONG now) noexcept
    {
        if (cache.suppressed_count <= 3)
            return true;
        if ((cache.suppressed_count & (cache.suppressed_count - 1u)) == 0)
            return true;
        if (cache.last_suppressed_log_ms == 0 || now - cache.last_suppressed_log_ms >= 2000)
            return true;
        return false;
    }

    void populate_lower_executor_start_failure_outcome(lower_remote_call_outcome_t& outcome,
                                                       const lower_executor_start_failure_cache_t& cache,
                                                       ULONGLONG call_start,
                                                       const lower_executor_process_stats_t& stats,
                                                       const char* reason)
    {
        outcome.completed = false;
        outcome.lower_ok = false;
        outcome.worker_exception = true;
        outcome.worker_creation_failed = true;
        outcome.gle = cache.gle != ERROR_SUCCESS ? cache.gle : ERROR_NOT_ENOUGH_MEMORY;
        outcome.active_pid_after = driver_bridge::attached_pid();
        outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
        outcome.elapsed_ms = GetTickCount64() - call_start;
        outcome.worker_error_value = cache.crt_errno;
        outcome.worker_error_category = cache.api.empty() ? "_beginthreadex" : cache.api;
        char message[512];
        _snprintf_s(message, sizeof(message), _TRUNCATE,
            "cached=%d reason=%s first_call_id=%llu last_call_id=%llu failures=%u suppressed=%u backoff_ms=%lu next_retry_in_ms=%llu win32=%lu errno=%d doserrno=%lu system_value=%d system_category=%s system_message=%s what=%s current_threads=%lu current_handles=%lu",
            cache.valid ? 1 : 0,
            reason ? reason : "",
            static_cast<unsigned long long>(cache.first_call_id),
            static_cast<unsigned long long>(cache.last_call_id),
            cache.failure_count,
            cache.suppressed_count,
            static_cast<unsigned long>(cache.backoff_ms),
            cache.next_retry_ms > GetTickCount64() ? static_cast<unsigned long long>(cache.next_retry_ms - GetTickCount64()) : 0ull,
            static_cast<unsigned long>(cache.win32_error),
            cache.crt_errno,
            cache.crt_doserrno,
            cache.system_error_value,
            cache.system_error_category.empty() ? "" : cache.system_error_category.c_str(),
            cache.system_error_message.empty() ? "" : cache.system_error_message.c_str(),
            cache.what.empty() ? "" : cache.what.c_str(),
            static_cast<unsigned long>(stats.thread_count),
            static_cast<unsigned long>(stats.handle_count));
        outcome.worker_error_message = message;
        outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
        outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
        outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        outcome.inflight_at_submit = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        outcome.inflight_after = outcome.inflight_at_submit;
        outcome.completion_reason = "worker_create_failed";
    }

    void record_lower_executor_start_failure(uint64_t call_id,
                                             uint32_t active_pid_at_entry,
                                             uint64_t generation_at_entry,
                                             const lower_executor_process_stats_t& stats,
                                             uint64_t resource_signature,
                                             DWORD gle,
                                             DWORD win32_error,
                                             int crt_errno,
                                             unsigned long crt_doserrno,
                                             int system_error_value,
                                             const char* api,
                                             const char* system_category,
                                             const char* system_message,
                                             const char* what)
    {
        lower_executor_start_failure_cache_t& cache = g_remote_call_lower_start_failure;
        const ULONGLONG now = GetTickCount64();
        if (!cache.valid) {
            cache.first_call_id = call_id;
            cache.first_failure_ms = now;
            cache.failure_count = 0;
            cache.suppressed_count = 0;
            cache.backoff_ms = kLowerRemoteCallStartBackoffInitialMs;
        } else {
            const DWORD next_backoff = cache.backoff_ms == 0 ? kLowerRemoteCallStartBackoffInitialMs : std::min<DWORD>(cache.backoff_ms * 2u, kLowerRemoteCallStartBackoffMaxMs);
            cache.backoff_ms = next_backoff;
        }
        cache.valid = true;
        cache.last_call_id = call_id;
        cache.generation_at_failure = generation_at_entry;
        cache.last_failure_ms = now;
        cache.next_retry_ms = now + cache.backoff_ms;
        cache.failure_count += 1u;
        cache.gle = gle != ERROR_SUCCESS ? gle : ERROR_NOT_ENOUGH_MEMORY;
        cache.win32_error = win32_error;
        cache.crt_errno = crt_errno;
        cache.crt_doserrno = crt_doserrno;
        cache.system_error_value = system_error_value;
        cache.active_pid_at_failure = active_pid_at_entry;
        cache.queue_depth = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        cache.inflight = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        cache.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
        cache.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
        cache.resource_signature = resource_signature;
        cache.api = api && api[0] ? api : "_beginthreadex";
        cache.system_error_category = system_category && system_category[0] ? system_category : "none";
        cache.system_error_message = system_message && system_message[0] ? system_message : "not_applicable";
        cache.what = what && what[0] ? what : "not_applicable";
        cache.stats = stats;
    }

    void reset_lower_executor_start_failure_cache(const char* reason)
    {
        if (!g_remote_call_lower_start_failure.valid)
            return;
        diag::log_tagged_fmt("driver",
            "lower_executor_start_failure_cache_reset reason=%s first_call_id=%llu last_call_id=%llu failures=%u suppressed=%u backoff_ms=%lu generation=%llu",
            reason && reason[0] ? reason : "",
            static_cast<unsigned long long>(g_remote_call_lower_start_failure.first_call_id),
            static_cast<unsigned long long>(g_remote_call_lower_start_failure.last_call_id),
            g_remote_call_lower_start_failure.failure_count,
            g_remote_call_lower_start_failure.suppressed_count,
            static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
            static_cast<unsigned long long>(g_remote_call_lower_start_failure.generation_at_failure));
        g_remote_call_lower_start_failure = {};
    }

    void store_lower_remote_call_diag(const char* phase,
                                      uint64_t call_id,
                                      const remote_call_snapshot_t& call_ctx,
                                      uint32_t active_pid_at_entry,
                                      uint64_t generation_at_entry,
                                      uint64_t function_address,
                                      const lower_remote_call_outcome_t& outcome)
    {
        driver_bridge::remote_call_execution_diag_t diag{};
        diag.phase = phase ? phase : "";
        diag.completion_reason = outcome.completion_reason;
        diag.worker_error_category = outcome.worker_error_category;
        diag.worker_error_message = outcome.worker_error_message;
        diag.call_id = call_id;
        diag.function_address = function_address;
        diag.result = outcome.result;
        diag.generation_at_entry = generation_at_entry;
        diag.generation_after = outcome.generation_after;
        diag.queue_wait_ms = outcome.queue_wait_ms;
        diag.elapsed_ms = outcome.elapsed_ms;
        diag.lower_elapsed_ms = outcome.lower_elapsed_ms;
        diag.deadline_remaining_at_queue_ms = outcome.deadline_remaining_at_queue_ms;
        diag.deadline_remaining_at_start_ms = outcome.deadline_remaining_at_start_ms;
        diag.deadline_remaining_at_finish_ms = outcome.deadline_remaining_at_finish_ms;
        diag.pid = call_ctx.pid != 0 ? call_ctx.pid : active_pid_at_entry;
        diag.active_pid_entry = active_pid_at_entry;
        diag.active_pid_after = outcome.active_pid_after;
        diag.timeout_ms = call_ctx.timeout_ms;
        diag.gle = outcome.gle;
        diag.worker_tid = outcome.worker_tid;
        diag.worker_alive = outcome.worker_alive;
        diag.queue_depth_at_submit = outcome.queue_depth_at_submit;
        diag.queue_depth_at_start = outcome.queue_depth_at_start;
        diag.queue_depth_after_pop = outcome.queue_depth_after_pop;
        diag.inflight_at_submit = outcome.inflight_at_submit;
        diag.inflight_at_start = outcome.inflight_at_start;
        diag.inflight_after = outcome.inflight_after;
        diag.worker_error_value = outcome.worker_error_value;
        diag.completed = outcome.completed;
        diag.lower_ok = outcome.lower_ok;
        diag.stale_generation = outcome.stale_generation;
        diag.cancelled = outcome.cancelled;
        diag.deadline_expired = outcome.deadline_expired;
        diag.lower_lock_timeout = outcome.lower_lock_timeout;
        diag.worker_exception = outcome.worker_exception;
        diag.worker_creation_failed = outcome.worker_creation_failed;
        diag.late_completion = outcome.deadline_expired || outcome.stale_generation || outcome.cancelled || !outcome.completed || outcome.executing_abandoned;
        diag.allow_zero_result = outcome.allow_zero_result;
        diag.zero_result_rejected = outcome.zero_result_rejected;
        diag.caller_abandoned = outcome.caller_abandoned;
        diag.removed_from_queue = outcome.removed_from_queue;
        diag.popped_from_queue = outcome.popped_from_queue;
        diag.execution_started = outcome.execution_started;
        diag.executing_abandoned = outcome.executing_abandoned;
        diag.seh_exception = outcome.seh_exception;
        diag.seh_exception_code = outcome.seh_exception_code;
        diag.seh_exception_address = outcome.seh_exception_address;
        diag.seh_fault_address = outcome.seh_fault_address;
        diag.seh_rip = outcome.seh_rip;
        diag.seh_rsp = outcome.seh_rsp;
        diag.seh_rbp = outcome.seh_rbp;
        g_last_remote_call_execution_diag = std::move(diag);
        if (outcome.executing_abandoned)
            g_lower_remote_call_last_abandoned.store(true, std::memory_order_release);
        else if (outcome.completed && outcome.lower_ok && !outcome.lower_lock_timeout)
            g_lower_remote_call_last_abandoned.store(false, std::memory_order_release);
    }

    void complete_lower_remote_call_item(const std::shared_ptr<lower_remote_call_work_item_t>& item,
                                         lower_remote_call_outcome_t outcome)
    {
        bool abandoned = false;
        char abandoned_reason[32] = {};
        {
            std::lock_guard<std::mutex> lk(item->state->mutex);
            abandoned = item->state->abandoned;
            if (item->state->abandoned_reason[0])
                strcpy_s(abandoned_reason, item->state->abandoned_reason);
            item->state->outcome = outcome;
            item->state->done = true;
        }
        item->state->cv.notify_all();
        if (abandoned) {
            diag::log_tagged_fmt("driver",
                "call_function_lower_late_discard call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX result=0x%llX lower_ok=%d gle=%lu abandoned_reason=%s completion_reason=%s deadline_ms=%llu deadline_remaining_finish_ms=%llu deadline_expired=%d stale_generation=%d removed_from_queue=%d popped=%d execution_started=%d executing_abandoned=%d zero_result_rejected=%d seh_exception=%d seh_code=0x%08lX queue_wait_ms=%llu elapsed_ms=%llu worker_tid=%lu worker_alive=%u queue_depth_submit=%u queue_depth_start=%u queue_depth_after_pop=%u inflight_after=%u",
                static_cast<unsigned long long>(item->call_id),
                item->phase.c_str(),
                item->label.c_str(),
                item->tool.c_str(),
                item->diag_id.c_str(),
                item->expected_pid,
                item->active_pid_at_entry,
                outcome.active_pid_after,
                static_cast<unsigned long long>(item->generation_at_entry),
                static_cast<unsigned long long>(outcome.generation_after),
                static_cast<unsigned long long>(item->function_address),
                static_cast<unsigned long long>(outcome.result),
                outcome.lower_ok ? 1 : 0,
                static_cast<unsigned long>(outcome.gle),
                abandoned_reason[0] ? abandoned_reason : "unknown",
                outcome.completion_reason.c_str(),
                static_cast<unsigned long long>(item->deadline_ms),
                static_cast<unsigned long long>(outcome.deadline_remaining_at_finish_ms),
                outcome.deadline_expired ? 1 : 0,
                outcome.stale_generation ? 1 : 0,
                outcome.removed_from_queue ? 1 : 0,
                outcome.popped_from_queue ? 1 : 0,
                outcome.execution_started ? 1 : 0,
                outcome.executing_abandoned ? 1 : 0,
                outcome.zero_result_rejected ? 1 : 0,
                outcome.seh_exception ? 1 : 0,
                static_cast<unsigned long>(outcome.seh_exception_code),
                static_cast<unsigned long long>(outcome.queue_wait_ms),
                static_cast<unsigned long long>(outcome.elapsed_ms),
                static_cast<unsigned long>(outcome.worker_tid),
                outcome.worker_alive,
                outcome.queue_depth_at_submit,
                outcome.queue_depth_at_start,
                outcome.queue_depth_after_pop,
                outcome.inflight_after);
        }
    }

    void complete_lower_remote_call_cancelled(const std::shared_ptr<lower_remote_call_work_item_t>& item,
                                              const char* reason,
                                              ULONGLONG now) noexcept
    {
        if (!item)
            return;
        lower_remote_call_outcome_t outcome{};
        outcome.completed = false;
        outcome.lower_ok = false;
        outcome.cancelled = true;
        outcome.lower_lock_timeout = true;
        outcome.caller_abandoned = true;
        outcome.removed_from_queue = true;
        outcome.allow_zero_result = item->allow_zero_result;
        outcome.gle = ERROR_OPERATION_ABORTED;
        outcome.active_pid_after = driver_bridge::attached_pid();
        outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
        outcome.elapsed_ms = now >= item->call_start ? now - item->call_start : 0;
        outcome.queue_wait_ms = now >= item->queued_at ? now - item->queued_at : 0;
        outcome.deadline_remaining_at_queue_ms = item->deadline_remaining_at_queue_ms;
        outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(item->deadline_ms, now);
        outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
        outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
        outcome.queue_depth_at_submit = item->queue_depth_at_submit;
        outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        outcome.inflight_at_submit = item->inflight_at_submit;
        outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        outcome.completion_reason = reason && reason[0] ? reason : "executor_cancelled";
        complete_lower_remote_call_item(item, outcome);
    }

    struct lower_remote_call_seh_record_t
    {
        uint32_t code = 0;
        uint64_t exception_address = 0;
        uint64_t fault_address = 0;
        uint64_t rip = 0;
        uint64_t rsp = 0;
        uint64_t rbp = 0;
        DWORD last_error_after_seh = ERROR_SUCCESS;
        DWORD caller_pid = 0;
        DWORD worker_tid = 0;
        ULONGLONG captured_tick = 0;
    };

    int capture_lower_remote_call_seh(EXCEPTION_POINTERS* info, lower_remote_call_seh_record_t* record) noexcept
    {
        const DWORD last_error_at_entry = GetLastError();
        if (record) {
            record->last_error_after_seh = last_error_at_entry;
            record->caller_pid = GetCurrentProcessId();
            record->worker_tid = GetCurrentThreadId();
            record->captured_tick = GetTickCount64();
        }
        if (record && info && info->ExceptionRecord) {
            record->code = info->ExceptionRecord->ExceptionCode;
            record->exception_address = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
            if (info->ExceptionRecord->NumberParameters > 1)
                record->fault_address = static_cast<uint64_t>(info->ExceptionRecord->ExceptionInformation[1]);
#if defined(_M_X64) || defined(_M_AMD64)
            if (info->ContextRecord) {
                record->rip = static_cast<uint64_t>(info->ContextRecord->Rip);
                record->rsp = static_cast<uint64_t>(info->ContextRecord->Rsp);
                record->rbp = static_cast<uint64_t>(info->ContextRecord->Rbp);
            }
#elif defined(_M_IX86)
            if (info->ContextRecord) {
                record->rip = static_cast<uint64_t>(info->ContextRecord->Eip);
                record->rsp = static_cast<uint64_t>(info->ContextRecord->Esp);
                record->rbp = static_cast<uint64_t>(info->ContextRecord->Ebp);
            }
#endif
            if (record->code == static_cast<uint32_t>(EXCEPTION_ACCESS_VIOLATION)) {
                diag::log_tagged_critical_fmt("driver",
                    "call_function_lower_seh_handler caller_pid=%lu worker_tid=%lu code=0x%08lX exception_address=0x%llX fault_address=0x%llX rip=0x%llX rsp=0x%llX rbp=0x%llX last_error=%lu tick=%llu",
                    static_cast<unsigned long>(record->caller_pid),
                    static_cast<unsigned long>(record->worker_tid),
                    static_cast<unsigned long>(record->code),
                    static_cast<unsigned long long>(record->exception_address),
                    static_cast<unsigned long long>(record->fault_address),
                    static_cast<unsigned long long>(record->rip),
                    static_cast<unsigned long long>(record->rsp),
                    static_cast<unsigned long long>(record->rbp),
                    static_cast<unsigned long>(record->last_error_after_seh),
                    static_cast<unsigned long long>(record->captured_tick));
            }
        }
        SetLastError(last_error_at_entry);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    void execute_lower_remote_call_body_cpp(lower_remote_call_work_item_t* item,
                                            lower_remote_call_outcome_t* outcome) noexcept
    {
        try {
            SetLastError(ERROR_SUCCESS);
            bool zero_result_rejected = false;
            outcome->lower_ok = item->lower_fn(outcome->result, outcome->gle, zero_result_rejected);
            outcome->zero_result_rejected = zero_result_rejected;
            if (!outcome->lower_ok && outcome->gle == ERROR_SUCCESS) {
                outcome->gle = outcome->zero_result_rejected ? ERROR_GEN_FAILURE : GetLastError();
                if (outcome->gle == ERROR_SUCCESS)
                    outcome->gle = ERROR_GEN_FAILURE;
            }
        } catch (const std::system_error& ex) {
            outcome->lower_ok = false;
            outcome->worker_exception = true;
            outcome->gle = ERROR_GEN_FAILURE;
            outcome->worker_error_value = ex.code().value();
            outcome->worker_error_category = ex.code().category().name();
            outcome->worker_error_message = ex.what();
        } catch (const std::exception& ex) {
            outcome->lower_ok = false;
            outcome->worker_exception = true;
            outcome->gle = ERROR_GEN_FAILURE;
            outcome->worker_error_message = ex.what();
        } catch (...) {
            outcome->lower_ok = false;
            outcome->worker_exception = true;
            outcome->gle = ERROR_GEN_FAILURE;
            outcome->worker_error_message = "<unknown>";
        }
    }

    bool execute_lower_remote_call_body_guarded(lower_remote_call_work_item_t* item,
                                                lower_remote_call_outcome_t* outcome,
                                                lower_remote_call_seh_record_t* seh_record) noexcept
    {
#if defined(_MSC_VER)
        __try {
            execute_lower_remote_call_body_cpp(item, outcome);
            return true;
        } __except (capture_lower_remote_call_seh(GetExceptionInformation(), seh_record)) {
            return false;
        }
#else
        execute_lower_remote_call_body_cpp(item, outcome);
        return true;
#endif
    }

    void execute_lower_remote_call_item(const std::shared_ptr<lower_remote_call_work_item_t>& item, DWORD worker_tid) noexcept
    {
        lower_remote_call_outcome_t outcome{};
        outcome.gle = ERROR_SUCCESS;
        outcome.worker_tid = worker_tid;
        outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
        outcome.allow_zero_result = item->allow_zero_result;
        outcome.queue_depth_at_submit = item->queue_depth_at_submit;
        outcome.queue_depth_at_start = item->queue_depth_at_submit;
        outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        outcome.inflight_at_submit = item->inflight_at_submit;
        outcome.inflight_at_start = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        outcome.deadline_remaining_at_queue_ms = item->deadline_remaining_at_queue_ms;
        const ULONGLONG worker_start = GetTickCount64();
        outcome.queue_wait_ms = worker_start >= item->queued_at ? worker_start - item->queued_at : 0;
        outcome.deadline_remaining_at_start_ms = deadline_remaining_ms(item->deadline_ms, worker_start);
        bool abandoned = false;
        bool popped = false;
        bool executing = false;
        char abandoned_reason[32] = {};
        {
            std::lock_guard<std::mutex> lk(item->state->mutex);
            abandoned = item->state->abandoned;
            popped = item->state->popped;
            executing = item->state->executing;
            if (item->state->abandoned_reason[0])
                strcpy_s(abandoned_reason, item->state->abandoned_reason);
        }
        outcome.caller_abandoned = abandoned;
        outcome.popped_from_queue = popped;
        outcome.execution_started = executing;
        diag::log_tagged_fmt("driver",
            "call_function_lower_thread_begin call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu queue_depth_submit=%u queue_depth_after_pop=%u queue_wait_ms=%llu inflight=%u worker_tid=%lu worker_alive=%u abandoned=%d abandoned_reason=%s popped=%d executing=%d allow_zero=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(item->call_id),
            item->phase.c_str(),
            item->label.c_str(),
            item->tool.c_str(),
            item->diag_id.c_str(),
            item->expected_pid,
            item->active_pid_at_entry,
            static_cast<unsigned long long>(item->generation_at_entry),
            static_cast<unsigned long long>(item->function_address),
            item->timeout_ms,
            static_cast<unsigned long long>(item->deadline_ms),
            static_cast<unsigned long long>(outcome.deadline_remaining_at_start_ms),
            item->queue_depth_at_submit,
            outcome.queue_depth_after_pop,
            static_cast<unsigned long long>(outcome.queue_wait_ms),
            outcome.inflight_at_start,
            static_cast<unsigned long>(worker_tid),
            outcome.worker_alive,
            abandoned ? 1 : 0,
            abandoned_reason[0] ? abandoned_reason : "",
            popped ? 1 : 0,
            executing ? 1 : 0,
            item->allow_zero_result ? 1 : 0,
            static_cast<unsigned long long>(worker_start - item->call_start));

        const bool cancelled_before = driver_bridge::current_remote_call_cancelled();
        const bool deadline_expired_before = item->deadline_ms != 0 && worker_start >= item->deadline_ms;
        const uint32_t active_before = driver_bridge::attached_pid();
        const uint64_t generation_before = g_active_pid_generation.load(std::memory_order_acquire);
        const bool stale_before = active_before != item->expected_pid || generation_before != item->generation_at_entry;
        if (abandoned || cancelled_before || deadline_expired_before || stale_before) {
            outcome.completed = false;
            outcome.cancelled = abandoned && std::strcmp(abandoned_reason, "cancelled") == 0 ? true : cancelled_before;
            outcome.deadline_expired = deadline_expired_before || (abandoned && std::strcmp(abandoned_reason, "deadline") == 0);
            outcome.stale_generation = stale_before;
            outcome.lower_lock_timeout = outcome.deadline_expired || outcome.cancelled || abandoned;
            outcome.caller_abandoned = abandoned;
            outcome.popped_from_queue = popped;
            outcome.execution_started = false;
            outcome.executing_abandoned = false;
            outcome.gle = outcome.stale_generation ? ERROR_OPERATION_ABORTED : (outcome.cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT);
            outcome.active_pid_after = active_before;
            outcome.generation_after = generation_before;
            outcome.elapsed_ms = GetTickCount64() - item->call_start;
            outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(item->deadline_ms, GetTickCount64());
            outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            outcome.completion_reason = abandoned ? (abandoned_reason[0] ? abandoned_reason : "abandoned") :
                (outcome.stale_generation ? "stale_before_start" : (outcome.cancelled ? "cancelled_before_start" : "deadline_before_start"));
            diag::log_tagged_fmt("driver",
                "call_function_lower_start_discard call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX reason=%s cancelled=%d deadline_expired=%d stale_generation=%d abandoned=%d popped=%d executing=%d deadline_ms=%llu deadline_remaining_ms=%llu queue_wait_ms=%llu elapsed_ms=%llu worker_tid=%lu queue_depth_submit=%u queue_depth_after_pop=%u inflight=%u",
                static_cast<unsigned long long>(item->call_id),
                item->phase.c_str(),
                item->label.c_str(),
                item->tool.c_str(),
                item->diag_id.c_str(),
                item->expected_pid,
                item->active_pid_at_entry,
                outcome.active_pid_after,
                static_cast<unsigned long long>(item->generation_at_entry),
                static_cast<unsigned long long>(outcome.generation_after),
                static_cast<unsigned long long>(item->function_address),
                outcome.completion_reason.c_str(),
                outcome.cancelled ? 1 : 0,
                outcome.deadline_expired ? 1 : 0,
                outcome.stale_generation ? 1 : 0,
                abandoned ? 1 : 0,
                popped ? 1 : 0,
                executing ? 1 : 0,
                static_cast<unsigned long long>(item->deadline_ms),
                static_cast<unsigned long long>(outcome.deadline_remaining_at_finish_ms),
                static_cast<unsigned long long>(outcome.queue_wait_ms),
                static_cast<unsigned long long>(outcome.elapsed_ms),
                static_cast<unsigned long>(worker_tid),
                outcome.queue_depth_at_submit,
                outcome.queue_depth_after_pop,
                outcome.inflight_after);
            complete_lower_remote_call_item(item, outcome);
            return;
        }

        const ULONGLONG lower_start = GetTickCount64();
        bool abandoned_before_execute = false;
        char abandoned_before_execute_reason[32] = {};
        {
            std::lock_guard<std::mutex> lk(item->state->mutex);
            abandoned_before_execute = item->state->abandoned;
            if (item->state->abandoned_reason[0])
                strcpy_s(abandoned_before_execute_reason, item->state->abandoned_reason);
            if (!abandoned_before_execute) {
                item->state->executing = true;
                item->state->executing_at = lower_start;
                item->state->worker_tid = worker_tid;
            }
        }
        if (abandoned_before_execute) {
            outcome.completed = false;
            outcome.cancelled = std::strcmp(abandoned_before_execute_reason, "cancelled") == 0;
            outcome.deadline_expired = std::strcmp(abandoned_before_execute_reason, "deadline") == 0;
            outcome.lower_lock_timeout = true;
            outcome.caller_abandoned = true;
            outcome.popped_from_queue = true;
            outcome.execution_started = false;
            outcome.executing_abandoned = false;
            outcome.gle = outcome.cancelled ? ERROR_CANCELLED : (outcome.deadline_expired ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED);
            outcome.active_pid_after = driver_bridge::attached_pid();
            outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
            outcome.elapsed_ms = lower_start - item->call_start;
            outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(item->deadline_ms, lower_start);
            outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            outcome.completion_reason = outcome.cancelled ? "cancelled_popped_not_started" :
                (outcome.deadline_expired ? "deadline_popped_not_started" : "abandoned_popped_not_started");
            diag::log_tagged_fmt("driver",
                "call_function_lower_start_discard call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX reason=%s cancelled=%d deadline_expired=%d stale_generation=%d abandoned=%d popped=%d executing=%d deadline_ms=%llu deadline_remaining_ms=%llu queue_wait_ms=%llu elapsed_ms=%llu worker_tid=%lu queue_depth_submit=%u queue_depth_after_pop=%u inflight=%u",
                static_cast<unsigned long long>(item->call_id),
                item->phase.c_str(),
                item->label.c_str(),
                item->tool.c_str(),
                item->diag_id.c_str(),
                item->expected_pid,
                item->active_pid_at_entry,
                outcome.active_pid_after,
                static_cast<unsigned long long>(item->generation_at_entry),
                static_cast<unsigned long long>(outcome.generation_after),
                static_cast<unsigned long long>(item->function_address),
                outcome.completion_reason.c_str(),
                outcome.cancelled ? 1 : 0,
                outcome.deadline_expired ? 1 : 0,
                outcome.stale_generation ? 1 : 0,
                1,
                1,
                0,
                static_cast<unsigned long long>(item->deadline_ms),
                static_cast<unsigned long long>(outcome.deadline_remaining_at_finish_ms),
                static_cast<unsigned long long>(outcome.queue_wait_ms),
                static_cast<unsigned long long>(outcome.elapsed_ms),
                static_cast<unsigned long>(worker_tid),
                outcome.queue_depth_at_submit,
                outcome.queue_depth_after_pop,
                outcome.inflight_after);
            complete_lower_remote_call_item(item, outcome);
            return;
        }
        g_remote_call_lower_inflight.fetch_add(1, std::memory_order_acq_rel);
        outcome.execution_started = true;
        outcome.inflight_at_start = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        outcome.deadline_remaining_at_start_ms = deadline_remaining_ms(item->deadline_ms, lower_start);
        diag::log_tagged_fmt("driver",
            "call_function_lower_enter call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX deadline_ms=%llu deadline_remaining_ms=%llu queue_wait_ms=%llu elapsed_ms=%llu inflight=%u worker_tid=%lu queue_depth_submit=%u queue_depth_after_pop=%u abandoned=%d allow_zero=%d",
            static_cast<unsigned long long>(item->call_id),
            item->phase.c_str(),
            item->label.c_str(),
            item->tool.c_str(),
            item->diag_id.c_str(),
            item->expected_pid,
            item->active_pid_at_entry,
            static_cast<unsigned long long>(item->generation_at_entry),
            static_cast<unsigned long long>(item->function_address),
            static_cast<unsigned long long>(item->deadline_ms),
            static_cast<unsigned long long>(outcome.deadline_remaining_at_start_ms),
            static_cast<unsigned long long>(outcome.queue_wait_ms),
            static_cast<unsigned long long>(lower_start - item->call_start),
            outcome.inflight_at_start,
            static_cast<unsigned long>(worker_tid),
            outcome.queue_depth_at_submit,
            outcome.queue_depth_after_pop,
            abandoned ? 1 : 0,
            item->allow_zero_result ? 1 : 0);
        lower_remote_call_seh_record_t seh_record{};
        const DWORD last_error_before_call = GetLastError();
        const bool seh_ok = execute_lower_remote_call_body_guarded(item.get(), &outcome, &seh_record);
        if (!seh_ok) {
            outcome.lower_ok = false;
            outcome.worker_exception = true;
            outcome.seh_exception = true;
            outcome.gle = ERROR_UNHANDLED_EXCEPTION;
            outcome.seh_exception_code = seh_record.code;
            outcome.seh_exception_address = seh_record.exception_address;
            outcome.seh_fault_address = seh_record.fault_address;
            outcome.seh_rip = seh_record.rip;
            outcome.seh_rsp = seh_record.rsp;
            outcome.seh_rbp = seh_record.rbp;
            outcome.worker_error_message = "seh_exception";
            const ULONGLONG seh_now = GetTickCount64();
            diag::log_tagged_critical_fmt("driver",
                "call_function_lower_seh_exception call_id=%llu phase=%s label=%s tool=%s diag_id=%s caller_pid=%lu expected_pid=%u active_pid_entry=%u active_pid_now=%u generation=%llu generation_now=%llu fn=0x%llX exception_code=0x%08lX exception_address=0x%llX fault_address=0x%llX rip=0x%llX rsp=0x%llX rbp=0x%llX worker_tid=%lu seh_caller_pid=%lu seh_worker_tid=%lu deadline_ms=%llu deadline_remaining_ms=%llu queue_depth_submit=%u queue_depth_after_pop=%u inflight=%u queue_wait_ms=%llu lower_elapsed_ms=%llu elapsed_ms=%llu abandoned=%d allow_zero=%d last_error_before_call=%lu last_error_after_seh=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(item->call_id),
                item->phase.c_str(),
                item->label.c_str(),
                item->tool.c_str(),
                item->diag_id.c_str(),
                static_cast<unsigned long>(GetCurrentProcessId()),
                item->expected_pid,
                item->active_pid_at_entry,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(item->generation_at_entry),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(item->function_address),
                static_cast<unsigned long>(seh_record.code),
                static_cast<unsigned long long>(seh_record.exception_address),
                static_cast<unsigned long long>(seh_record.fault_address),
                static_cast<unsigned long long>(seh_record.rip),
                static_cast<unsigned long long>(seh_record.rsp),
                static_cast<unsigned long long>(seh_record.rbp),
                static_cast<unsigned long>(worker_tid),
                static_cast<unsigned long>(seh_record.caller_pid),
                static_cast<unsigned long>(seh_record.worker_tid),
                static_cast<unsigned long long>(item->deadline_ms),
                static_cast<unsigned long long>(deadline_remaining_ms(item->deadline_ms, seh_now)),
                outcome.queue_depth_at_submit,
                outcome.queue_depth_after_pop,
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long long>(outcome.queue_wait_ms),
                static_cast<unsigned long long>(seh_now - lower_start),
                static_cast<unsigned long long>(seh_now - item->call_start),
                abandoned ? 1 : 0,
                item->allow_zero_result ? 1 : 0,
                static_cast<unsigned long>(last_error_before_call),
                static_cast<unsigned long>(seh_record.last_error_after_seh),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
        }
        {
            std::lock_guard<std::mutex> lk(item->state->mutex);
            item->state->executing = false;
            item->state->lower_returned = true;
        }
        if (g_lower_remote_call_worker_recovering.load(std::memory_order_acquire)) {
            g_lower_remote_call_worker_recovering.store(false, std::memory_order_release);
            outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            diag::log_tagged_critical_fmt("driver",
                "lower_remote_call_worker_recovered_skip_decrement call_id=%llu inflight_skipped=1 worker_tid=%lu",
                static_cast<unsigned long long>(item->call_id),
                static_cast<unsigned long>(worker_tid));
        } else {
            const uint32_t previous_inflight = g_remote_call_lower_inflight.fetch_sub(1, std::memory_order_acq_rel);
            outcome.inflight_after = previous_inflight == 0 ? 0 : previous_inflight - 1;
        }
        outcome.active_pid_after = driver_bridge::attached_pid();
        outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
        const ULONGLONG finish = GetTickCount64();
        bool abandoned_after_execution = false;
        char abandoned_after_reason[32] = {};
        {
            std::lock_guard<std::mutex> lk(item->state->mutex);
            abandoned_after_execution = item->state->abandoned;
            if (item->state->abandoned_reason[0])
                strcpy_s(abandoned_after_reason, item->state->abandoned_reason);
        }
        outcome.elapsed_ms = finish - item->call_start;
        outcome.lower_elapsed_ms = finish - lower_start;
        outcome.deadline_expired = item->deadline_ms != 0 && finish >= item->deadline_ms;
        outcome.cancelled = driver_bridge::current_remote_call_cancelled();
        if (abandoned_after_execution) {
            outcome.caller_abandoned = true;
            outcome.executing_abandoned = outcome.execution_started;
            outcome.lower_lock_timeout = true;
            if (std::strcmp(abandoned_after_reason, "cancelled") == 0)
                outcome.cancelled = true;
            if (std::strcmp(abandoned_after_reason, "deadline") == 0)
                outcome.deadline_expired = true;
        }
        outcome.stale_generation = outcome.active_pid_after != item->expected_pid ||
                                   outcome.generation_after != item->generation_at_entry;
        outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(item->deadline_ms, finish);
        outcome.completed = !outcome.lower_lock_timeout;
        outcome.completion_reason = outcome.seh_exception ? "seh_exception" :
            (outcome.worker_exception ? "worker_exception" :
            (outcome.stale_generation ? "stale_after_completion" :
             (outcome.executing_abandoned ? (outcome.cancelled ? "cancelled_executing_abandoned" : "deadline_executing_abandoned") :
              (outcome.deadline_expired ? "deadline_after_completion" :
               (outcome.cancelled ? "cancelled_after_completion" :
                (outcome.zero_result_rejected ? "zero_result_rejected" :
                 (outcome.lower_ok ? "completed" : "lower_failed")))))));
        diag::log_tagged_fmt("driver",
            "call_function_lower_exit call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX result=0x%llX lower_ok=%d gle=%lu deadline_ms=%llu deadline_remaining_finish_ms=%llu deadline_expired=%d cancelled=%d stale_generation=%d worker_exception=%d seh_exception=%d seh_code=0x%08lX zero_result_rejected=%d caller_abandoned=%d executing_abandoned=%d allow_zero=%d completion_reason=%s queue_wait_ms=%llu elapsed_ms=%llu lower_elapsed_ms=%llu inflight=%u worker_tid=%lu queue_depth_submit=%u queue_depth_after_pop=%u",
            static_cast<unsigned long long>(item->call_id),
            item->phase.c_str(),
            item->label.c_str(),
            item->tool.c_str(),
            item->diag_id.c_str(),
            item->expected_pid,
            item->active_pid_at_entry,
            outcome.active_pid_after,
            static_cast<unsigned long long>(item->generation_at_entry),
            static_cast<unsigned long long>(outcome.generation_after),
            static_cast<unsigned long long>(item->function_address),
            static_cast<unsigned long long>(outcome.result),
            outcome.lower_ok ? 1 : 0,
            static_cast<unsigned long>(outcome.gle),
            static_cast<unsigned long long>(item->deadline_ms),
            static_cast<unsigned long long>(outcome.deadline_remaining_at_finish_ms),
            outcome.deadline_expired ? 1 : 0,
            outcome.cancelled ? 1 : 0,
            outcome.stale_generation ? 1 : 0,
            outcome.worker_exception ? 1 : 0,
            outcome.seh_exception ? 1 : 0,
            static_cast<unsigned long>(outcome.seh_exception_code),
            outcome.zero_result_rejected ? 1 : 0,
            outcome.caller_abandoned ? 1 : 0,
            outcome.executing_abandoned ? 1 : 0,
            outcome.allow_zero_result ? 1 : 0,
            outcome.completion_reason.c_str(),
            static_cast<unsigned long long>(outcome.queue_wait_ms),
            static_cast<unsigned long long>(outcome.elapsed_ms),
            static_cast<unsigned long long>(outcome.lower_elapsed_ms),
            outcome.inflight_after,
            static_cast<unsigned long>(worker_tid),
            outcome.queue_depth_at_submit,
            outcome.queue_depth_after_pop);
        complete_lower_remote_call_item(item, outcome);
    }

    void lower_remote_call_worker_main(int worker_index) noexcept
    {
        const DWORD worker_tid = GetCurrentThreadId();
        auto& tid_atomic = worker_index == 0 ? g_remote_call_lower_worker_tid : g_remote_call_lower_worker2_tid;
        auto& alive_atomic = worker_index == 0 ? g_remote_call_lower_worker_alive : g_remote_call_lower_worker2_alive;
        auto& loop_ready_atomic = worker_index == 0 ? g_remote_call_lower_worker_loop_ready : g_remote_call_lower_worker2_loop_ready;
        auto& started_atomic = worker_index == 0 ? g_remote_call_lower_worker_started : g_remote_call_lower_worker2_started;
        auto& begin_tid_ref = worker_index == 0 ? g_remote_call_lower_worker_begin_tid : g_remote_call_lower_worker2_begin_tid;
        auto& start_cv = worker_index == 0 ? g_remote_call_lower_start_cv : g_remote_call_lower_start2_cv;
        tid_atomic.store(worker_tid, std::memory_order_release);
        alive_atomic.store(true, std::memory_order_release);
        loop_ready_atomic.store(true, std::memory_order_release);
        start_cv.notify_all();
        const lower_executor_process_stats_t stats = capture_lower_executor_process_stats();
        diag::log_tagged_fmt("driver",
            "call_function_lower_worker_started worker_tid=%lu worker_index=%d begin_tid=%u queue_depth=%u inflight=%u handle_count_ok=%d handle_count=%lu thread_count=%lu memory_ok=%d private_bytes=%llu working_set=%llu commit_total=%llu commit_limit=%llu loop_ready=%d",
            static_cast<unsigned long>(worker_tid),
            worker_index,
            begin_tid_ref,
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            stats.handle_count_ok ? 1 : 0,
            static_cast<unsigned long>(stats.handle_count),
            static_cast<unsigned long>(stats.thread_count),
            stats.memory_ok ? 1 : 0,
            static_cast<unsigned long long>(stats.private_bytes),
            static_cast<unsigned long long>(stats.working_set),
            static_cast<unsigned long long>(stats.commit_total),
            static_cast<unsigned long long>(stats.commit_limit),
            loop_ready_atomic.load(std::memory_order_acquire) ? 1 : 0);
        ULONGLONG idle_zero_since = 0;
        ULONGLONG last_heartbeat = GetTickCount64();
        for (;;) {
            const ULONGLONG hb_check_now = GetTickCount64();
            if (hb_check_now - last_heartbeat >= 5000) {
                last_heartbeat = hb_check_now;
                const uint32_t hb_inflight = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                const uint32_t hb_queue = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                const bool hb_executing = g_lower_worker_heartbeat.executing.load(std::memory_order_acquire);
                const uint64_t hb_call_id = g_lower_worker_heartbeat.call_id.load(std::memory_order_acquire);
                const ULONGLONG hb_popped_at = g_lower_worker_heartbeat.popped_at.load(std::memory_order_acquire);
                const DWORD hb_elapsed_since_pop = (hb_executing && hb_popped_at > 0) ? static_cast<DWORD>(hb_check_now - hb_popped_at) : 0;
                char hb_phase[32] = {};
                char hb_label[64] = {};
                {
                    std::lock_guard<std::mutex> hb_lk(g_lower_worker_heartbeat.str_mutex);
                    strncpy_s(hb_phase, sizeof(hb_phase), g_lower_worker_heartbeat.phase, _TRUNCATE);
                    strncpy_s(hb_label, sizeof(hb_label), g_lower_worker_heartbeat.label, _TRUNCATE);
                }
                diag::log_tagged_fmt("driver",
                    "lower_remote_call_worker_heartbeat worker_tid=%lu worker_index=%d inflight=%u queue_depth=%u executing=%d call_id=%llu phase=%s label=%s elapsed_since_pop_ms=%lu",
                    static_cast<unsigned long>(worker_tid),
                    worker_index,
                    hb_inflight,
                    hb_queue,
                    hb_executing ? 1 : 0,
                    static_cast<unsigned long long>(hb_call_id),
                    hb_phase,
                    hb_label,
                    static_cast<unsigned long>(hb_elapsed_since_pop));
            }
            std::shared_ptr<lower_remote_call_work_item_t> item;
            {
                std::unique_lock<std::mutex> lk(g_remote_call_lower_executor_mutex);
                g_remote_call_lower_executor_cv.wait_for(lk, std::chrono::milliseconds(500), []() {
                    return g_remote_call_lower_executor_stop.load(std::memory_order_acquire) ||
                           !g_remote_call_lower_queue.empty();
                });
                if (g_remote_call_lower_queue.empty()) {
                    if (g_remote_call_lower_executor_stop.load(std::memory_order_acquire))
                        break;
                    const uint32_t inflight_now = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                    const uint32_t queue_now = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                    if (inflight_now == 0 && queue_now == 0) {
                        const ULONGLONG now = GetTickCount64();
                        if (idle_zero_since == 0) {
                            idle_zero_since = now;
                        } else if (now - idle_zero_since >= 3000 &&
                                   g_lower_remote_call_last_abandoned.load(std::memory_order_acquire)) {
                            g_lower_remote_call_last_abandoned.store(false, std::memory_order_release);
                            const ULONGLONG idle_ms = now - idle_zero_since;
                            idle_zero_since = 0;
                            lk.unlock();
                            diag::log_tagged_critical_fmt("driver",
                                "lower_remote_call_last_abandoned_auto_clear idle_ms=%llu reason=executor_idle_watchdog worker_tid=%lu",
                                static_cast<unsigned long long>(idle_ms),
                                static_cast<unsigned long>(worker_tid));
                            continue;
                        }
                    } else {
                        idle_zero_since = 0;
                    }
                    continue;
                }
                idle_zero_since = 0;
                item = g_remote_call_lower_queue.front();
                g_remote_call_lower_queue.pop_front();
                g_remote_call_lower_queue_depth.store(static_cast<std::uint32_t>(g_remote_call_lower_queue.size()), std::memory_order_release);
            }
            if (!item)
                continue;
            bool item_abandoned_in_queue = false;
            char item_abandoned_reason[32] = {};
            {
                std::lock_guard<std::mutex> item_lk(item->state->mutex);
                item->state->popped = true;
                item->state->worker_tid = worker_tid;
                item->state->popped_at = GetTickCount64();
                item_abandoned_in_queue = item->state->abandoned;
                if (item->state->abandoned_reason[0])
                    strcpy_s(item_abandoned_reason, item->state->abandoned_reason);
            }
            if (item_abandoned_in_queue) {
                const ULONGLONG skip_now = GetTickCount64();
                lower_remote_call_outcome_t skip_outcome{};
                skip_outcome.completed = false;
                skip_outcome.lower_ok = false;
                skip_outcome.cancelled = std::strcmp(item_abandoned_reason, "cancelled") == 0;
                skip_outcome.deadline_expired = std::strcmp(item_abandoned_reason, "deadline") == 0;
                skip_outcome.lower_lock_timeout = true;
                skip_outcome.caller_abandoned = true;
                skip_outcome.popped_from_queue = true;
                skip_outcome.execution_started = false;
                skip_outcome.executing_abandoned = false;
                skip_outcome.allow_zero_result = item->allow_zero_result;
                skip_outcome.gle = skip_outcome.cancelled ? ERROR_CANCELLED : (skip_outcome.deadline_expired ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED);
                skip_outcome.active_pid_after = driver_bridge::attached_pid();
                skip_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                skip_outcome.stale_generation = skip_outcome.active_pid_after != item->expected_pid ||
                                                skip_outcome.generation_after != item->generation_at_entry;
                skip_outcome.elapsed_ms = skip_now >= item->call_start ? skip_now - item->call_start : 0;
                skip_outcome.queue_wait_ms = skip_now >= item->queued_at ? skip_now - item->queued_at : 0;
                skip_outcome.deadline_remaining_at_queue_ms = item->deadline_remaining_at_queue_ms;
                skip_outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(item->deadline_ms, skip_now);
                skip_outcome.worker_tid = worker_tid;
                skip_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
                skip_outcome.queue_depth_at_submit = item->queue_depth_at_submit;
                skip_outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                skip_outcome.inflight_at_submit = item->inflight_at_submit;
                skip_outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                skip_outcome.completion_reason = skip_outcome.cancelled ? "cancelled_in_queue_worker_skip" :
                    (skip_outcome.deadline_expired ? "deadline_in_queue_worker_skip" : "abandoned_in_queue_worker_skip");
                complete_lower_remote_call_item(item, skip_outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_worker_queue_cancel_skip call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX reason=%s cancelled=%d deadline_expired=%d stale_generation=%d queue_wait_ms=%llu elapsed_ms=%llu worker_tid=%lu queue_depth_submit=%u queue_depth_after_pop=%u inflight=%u",
                    static_cast<unsigned long long>(item->call_id),
                    item->phase.c_str(),
                    item->label.c_str(),
                    item->tool.c_str(),
                    item->diag_id.c_str(),
                    item->expected_pid,
                    item->active_pid_at_entry,
                    skip_outcome.active_pid_after,
                    static_cast<unsigned long long>(item->generation_at_entry),
                    static_cast<unsigned long long>(skip_outcome.generation_after),
                    static_cast<unsigned long long>(item->function_address),
                    skip_outcome.completion_reason.c_str(),
                    skip_outcome.cancelled ? 1 : 0,
                    skip_outcome.deadline_expired ? 1 : 0,
                    skip_outcome.stale_generation ? 1 : 0,
                    static_cast<unsigned long long>(skip_outcome.queue_wait_ms),
                    static_cast<unsigned long long>(skip_outcome.elapsed_ms),
                    static_cast<unsigned long>(worker_tid),
                    skip_outcome.queue_depth_at_submit,
                    skip_outcome.queue_depth_after_pop,
                    skip_outcome.inflight_after);
                continue;
            }
            g_lower_worker_heartbeat.call_id.store(item->call_id, std::memory_order_release);
            g_lower_worker_heartbeat.popped_at.store(item->state->popped_at, std::memory_order_release);
            g_lower_worker_heartbeat.executing.store(true, std::memory_order_release);
            {
                std::lock_guard<std::mutex> hb_lk(g_lower_worker_heartbeat.str_mutex);
                strncpy_s(g_lower_worker_heartbeat.phase, sizeof(g_lower_worker_heartbeat.phase), item->phase.c_str(), _TRUNCATE);
                strncpy_s(g_lower_worker_heartbeat.label, sizeof(g_lower_worker_heartbeat.label), item->label.c_str(), _TRUNCATE);
            }
            try {
                execute_lower_remote_call_item(item, worker_tid);
            } catch (const std::exception& ex) {
                lower_remote_call_outcome_t outcome{};
                outcome.completed = false;
                outcome.lower_ok = false;
                outcome.worker_exception = true;
                outcome.gle = ERROR_GEN_FAILURE;
                outcome.worker_tid = worker_tid;
                outcome.worker_alive = 1;
                outcome.allow_zero_result = item->allow_zero_result;
                outcome.popped_from_queue = true;
                {
                    std::lock_guard<std::mutex> item_lk(item->state->mutex);
                    outcome.execution_started = item->state->executing;
                    outcome.caller_abandoned = item->state->abandoned;
                    outcome.executing_abandoned = outcome.execution_started && outcome.caller_abandoned;
                }
                outcome.active_pid_after = driver_bridge::attached_pid();
                outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                outcome.elapsed_ms = GetTickCount64() - item->call_start;
                outcome.queue_depth_at_submit = item->queue_depth_at_submit;
                outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                outcome.completion_reason = "worker_outer_exception";
                outcome.worker_error_message = ex.what();
                complete_lower_remote_call_item(item, outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_worker_item_exception call_id=%llu phase=%s label=%s tool=%s diag_id=%s err=%s worker_tid=%lu elapsed_ms=%llu",
                    static_cast<unsigned long long>(item->call_id),
                    item->phase.c_str(),
                    item->label.c_str(),
                    item->tool.c_str(),
                    item->diag_id.c_str(),
                    ex.what(),
                    static_cast<unsigned long>(worker_tid),
                    static_cast<unsigned long long>(outcome.elapsed_ms));
            } catch (...) {
                lower_remote_call_outcome_t outcome{};
                outcome.completed = false;
                outcome.lower_ok = false;
                outcome.worker_exception = true;
                outcome.gle = ERROR_GEN_FAILURE;
                outcome.worker_tid = worker_tid;
                outcome.worker_alive = 1;
                outcome.allow_zero_result = item->allow_zero_result;
                outcome.popped_from_queue = true;
                {
                    std::lock_guard<std::mutex> item_lk(item->state->mutex);
                    outcome.execution_started = item->state->executing;
                    outcome.caller_abandoned = item->state->abandoned;
                    outcome.executing_abandoned = outcome.execution_started && outcome.caller_abandoned;
                }
                outcome.active_pid_after = driver_bridge::attached_pid();
                outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                outcome.elapsed_ms = GetTickCount64() - item->call_start;
                outcome.queue_depth_at_submit = item->queue_depth_at_submit;
                outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                outcome.completion_reason = "worker_outer_exception";
                outcome.worker_error_message = "<unknown>";
                complete_lower_remote_call_item(item, outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_worker_item_exception call_id=%llu phase=%s label=%s tool=%s diag_id=%s err=<unknown> worker_tid=%lu elapsed_ms=%llu",
                    static_cast<unsigned long long>(item->call_id),
                    item->phase.c_str(),
                    item->label.c_str(),
                    item->tool.c_str(),
                    item->diag_id.c_str(),
                    static_cast<unsigned long>(worker_tid),
                    static_cast<unsigned long long>(outcome.elapsed_ms));
            }
            g_lower_worker_heartbeat.executing.store(false, std::memory_order_release);
            g_lower_worker_heartbeat.call_id.store(0, std::memory_order_release);
            g_lower_worker_heartbeat.popped_at.store(0, std::memory_order_release);
        }
        alive_atomic.store(false, std::memory_order_release);
        started_atomic.store(false, std::memory_order_release);
        loop_ready_atomic.store(false, std::memory_order_release);
        tid_atomic.store(0, std::memory_order_release);
        start_cv.notify_all();
        diag::log_tagged_fmt("driver",
            "call_function_lower_worker_stopped worker_tid=%lu worker_index=%d begin_tid=%u queue_depth=%u inflight=%u stop=%d loop_ready=%d",
            static_cast<unsigned long>(worker_tid),
            worker_index,
            begin_tid_ref,
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            g_remote_call_lower_executor_stop.load(std::memory_order_acquire) ? 1 : 0,
            loop_ready_atomic.load(std::memory_order_acquire) ? 1 : 0);
    }

    unsigned __stdcall lower_remote_call_worker_entry(void*) noexcept
    {
        lower_remote_call_worker_main(0);
        return 0;
    }

    unsigned __stdcall lower_remote_call_worker2_entry(void*) noexcept
    {
        lower_remote_call_worker_main(1);
        return 0;
    }

    bool start_lower_remote_call_executor_locked(std::unique_lock<std::mutex>& lk,
                                                 const char* trigger,
                                                 const char* phase,
                                                 uint64_t call_id,
                                                 const remote_call_snapshot_t& call_ctx,
                                                 uint32_t expected_pid,
                                                 uint32_t active_pid_at_entry,
                                                 uint64_t generation_at_entry,
                                                 uint64_t function_address,
                                                 ULONGLONG call_start,
                                                 lower_remote_call_outcome_t* failure_outcome)
    {
        g_remote_call_lower_executor_stop.store(false, std::memory_order_release);
        g_remote_call_lower_worker_loop_ready.store(false, std::memory_order_release);
        g_remote_call_lower_worker_tid.store(0, std::memory_order_release);
        g_remote_call_lower_worker_begin_tid = 0;
        g_remote_call_lower_worker2_loop_ready.store(false, std::memory_order_release);
        g_remote_call_lower_worker2_tid.store(0, std::memory_order_release);
        g_remote_call_lower_worker2_begin_tid = 0;

        const lower_executor_process_stats_t stats = capture_lower_executor_process_stats();
        const uint64_t resource_signature = lower_executor_resource_signature(stats);
        const ULONGLONG elapsed_before = GetTickCount64() - call_start;
        log_lower_executor_resource_snapshot("lower_executor_start_begin",
                                             call_id,
                                             phase,
                                             call_ctx,
                                             expected_pid,
                                             active_pid_at_entry,
                                             generation_at_entry,
                                             function_address,
                                             stats,
                                             resource_signature,
                                             elapsed_before);
        diag::log_tagged_fmt("driver",
            "call_function_lower_worker_create_begin call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX queue_depth=%u inflight=%u handle_count_ok=%d handle_count=%lu thread_count=%lu memory_ok=%d private_bytes=%llu working_set=%llu commit_total=%llu commit_limit=%llu elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            trigger && trigger[0] ? trigger : "",
            phase ? phase : "",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            expected_pid,
            active_pid_at_entry,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(function_address),
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            stats.handle_count_ok ? 1 : 0,
            static_cast<unsigned long>(stats.handle_count),
            static_cast<unsigned long>(stats.thread_count),
            stats.memory_ok ? 1 : 0,
            static_cast<unsigned long long>(stats.private_bytes),
            static_cast<unsigned long long>(stats.working_set),
            static_cast<unsigned long long>(stats.commit_total),
            static_cast<unsigned long long>(stats.commit_limit),
            static_cast<unsigned long long>(elapsed_before));

        const ULONGLONG now = GetTickCount64();
        const char* retry_reason = "no_cached_failure";
        const bool material_change = lower_executor_resource_materially_changed(g_remote_call_lower_start_failure,
                                                                                stats,
                                                                                resource_signature,
                                                                                generation_at_entry,
                                                                                &retry_reason);
        const bool backoff_elapsed = g_remote_call_lower_start_failure.valid && now >= g_remote_call_lower_start_failure.next_retry_ms;
        if (g_remote_call_lower_start_failure.valid && !material_change && !backoff_elapsed) {
            g_remote_call_lower_start_failure.suppressed_count += 1u;
            if (failure_outcome)
                populate_lower_executor_start_failure_outcome(*failure_outcome,
                                                              g_remote_call_lower_start_failure,
                                                              call_start,
                                                              stats,
                                                              retry_reason);
            if (lower_executor_should_log_cached_suppression(g_remote_call_lower_start_failure, now)) {
                g_remote_call_lower_start_failure.last_suppressed_log_ms = now;
                diag::log_tagged_fmt("driver",
                    "lower_executor_start_cached_failure call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=%s first_call_id=%llu last_call_id=%llu failures=%u suppressed=%u backoff_ms=%lu next_retry_in_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%u resource_sig=0x%016llX current_sig=0x%016llX elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    trigger && trigger[0] ? trigger : "",
                    phase ? phase : "",
                    call_ctx.label,
                    call_ctx.tool,
                    call_ctx.diag_id,
                    expected_pid,
                    active_pid_at_entry,
                    static_cast<unsigned long long>(generation_at_entry),
                    static_cast<unsigned long long>(function_address),
                    retry_reason,
                    static_cast<unsigned long long>(g_remote_call_lower_start_failure.first_call_id),
                    static_cast<unsigned long long>(g_remote_call_lower_start_failure.last_call_id),
                    g_remote_call_lower_start_failure.failure_count,
                    g_remote_call_lower_start_failure.suppressed_count,
                    static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
                    g_remote_call_lower_start_failure.next_retry_ms > now ? static_cast<unsigned long long>(g_remote_call_lower_start_failure.next_retry_ms - now) : 0ull,
                    g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                    g_remote_call_lower_inflight.load(std::memory_order_acquire),
                    static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                    g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u,
                    static_cast<unsigned long long>(g_remote_call_lower_start_failure.resource_signature),
                    static_cast<unsigned long long>(resource_signature),
                    static_cast<unsigned long long>(GetTickCount64() - call_start));
            }
            return false;
        }
        if (g_remote_call_lower_start_failure.valid) {
            diag::log_tagged_fmt("driver",
                "lower_executor_start_retry_allowed call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s reason=%s backoff_elapsed=%d first_call_id=%llu last_call_id=%llu failures=%u suppressed=%u backoff_ms=%lu resource_sig=0x%016llX cached_sig=0x%016llX",
                static_cast<unsigned long long>(call_id),
                trigger && trigger[0] ? trigger : "",
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                material_change ? retry_reason : "backoff_elapsed",
                backoff_elapsed ? 1 : 0,
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.first_call_id),
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.last_call_id),
                g_remote_call_lower_start_failure.failure_count,
                g_remote_call_lower_start_failure.suppressed_count,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
                static_cast<unsigned long long>(resource_signature),
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.resource_signature));
        }

        constexpr unsigned requested_stack_bytes = aida::infra::win_thread::default_stack_reserve;
        errno = 0;
        _set_doserrno(0);
        SetLastError(ERROR_SUCCESS);
        const ULONGLONG create_start = GetTickCount64();
        unsigned begin_tid = 0;
        uintptr_t raw = _beginthreadex(nullptr,
                                       requested_stack_bytes,
                                       &lower_remote_call_worker_entry,
                                       nullptr,
                                       0,
                                       &begin_tid);
        const DWORD create_gle = GetLastError();
        const int create_errno = errno;
        unsigned long create_doserrno = 0;
        _get_doserrno(&create_doserrno);
        const ULONGLONG create_elapsed = GetTickCount64() - create_start;
        HANDLE worker_handle = reinterpret_cast<HANDLE>(raw);
        diag::log_tagged_fmt("driver",
            "lower_executor_thread_create_result call_id=%llu trigger=%s api=_beginthreadex requested_stack_bytes=%u pe_stack_reserve=%llu pe_stack_commit=%llu handle=%p begin_tid=%u gle=%lu errno=%d doserrno=%lu system_value=%d system_category=%s system_message=%s what=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            trigger && trigger[0] ? trigger : "",
            requested_stack_bytes,
            static_cast<unsigned long long>(stats.pe_stack.reserve),
            static_cast<unsigned long long>(stats.pe_stack.commit),
            worker_handle,
            begin_tid,
            static_cast<unsigned long>(create_gle),
            create_errno,
            create_doserrno,
            0,
            "none",
            "not_applicable",
            "not_applicable",
            static_cast<unsigned long long>(create_elapsed));
        if (raw == 0) {
            const DWORD failure_gle = create_gle != ERROR_SUCCESS ? create_gle : ERROR_NOT_ENOUGH_MEMORY;
            record_lower_executor_start_failure(call_id,
                                                active_pid_at_entry,
                                                generation_at_entry,
                                                stats,
                                                resource_signature,
                                                failure_gle,
                                                create_gle,
                                                create_errno,
                                                create_doserrno,
                                                0,
                                                "_beginthreadex",
                                                "none",
                                                "not_applicable",
                                                "not_applicable");
            if (failure_outcome)
                populate_lower_executor_start_failure_outcome(*failure_outcome,
                                                              g_remote_call_lower_start_failure,
                                                              call_start,
                                                              stats,
                                                              "create_failed");
            log_lower_executor_resource_snapshot("lower_executor_start_failure",
                                                 call_id,
                                                 phase,
                                                 call_ctx,
                                                 expected_pid,
                                                 active_pid_at_entry,
                                                 generation_at_entry,
                                                 function_address,
                                                 stats,
                                                 resource_signature,
                                                 GetTickCount64() - call_start);
            diag::log_tagged_fmt("driver",
                "call_function_lower_thread_create_failed call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX api=_beginthreadex requested_stack_bytes=%u returned_handle=%p returned_tid=%u gle=%lu win32_gle=%lu errno=%d doserrno=%lu system_value=%d system_category=%s system_message=%s what=%s queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%u first_call_id=%llu last_call_id=%llu failure_count=%u suppressed_count=%u backoff_ms=%lu next_retry_in_ms=%llu handle_count_ok=%d handle_count=%lu thread_count=%lu memory_ok=%d private_bytes=%llu working_set=%llu commit_total=%llu commit_limit=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                trigger && trigger[0] ? trigger : "",
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                expected_pid,
                active_pid_at_entry,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(function_address),
                requested_stack_bytes,
                worker_handle,
                begin_tid,
                static_cast<unsigned long>(failure_gle),
                static_cast<unsigned long>(create_gle),
                create_errno,
                create_doserrno,
                0,
                "none",
                "not_applicable",
                "not_applicable",
                g_remote_call_lower_start_failure.queue_depth,
                g_remote_call_lower_start_failure.inflight,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.worker_tid),
                g_remote_call_lower_start_failure.worker_alive,
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.first_call_id),
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.last_call_id),
                g_remote_call_lower_start_failure.failure_count,
                g_remote_call_lower_start_failure.suppressed_count,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
                g_remote_call_lower_start_failure.next_retry_ms > GetTickCount64() ? static_cast<unsigned long long>(g_remote_call_lower_start_failure.next_retry_ms - GetTickCount64()) : 0ull,
                stats.handle_count_ok ? 1 : 0,
                static_cast<unsigned long>(stats.handle_count),
                static_cast<unsigned long>(stats.thread_count),
                stats.memory_ok ? 1 : 0,
                static_cast<unsigned long long>(stats.private_bytes),
                static_cast<unsigned long long>(stats.working_set),
                static_cast<unsigned long long>(stats.commit_total),
                static_cast<unsigned long long>(stats.commit_limit),
                static_cast<unsigned long long>(GetTickCount64() - call_start));
            return false;
        }

        g_remote_call_lower_worker_handle = worker_handle;
        g_remote_call_lower_worker_begin_tid = begin_tid;
        g_remote_call_lower_worker_started.store(true, std::memory_order_release);
        const ULONGLONG ready_wait_start = GetTickCount64();
        g_remote_call_lower_start_cv.wait_for(lk,
            std::chrono::milliseconds(kLowerRemoteCallWorkerReadyWaitMs),
            []() {
                return g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
                       g_remote_call_lower_executor_stop.load(std::memory_order_acquire) ||
                       !g_remote_call_lower_worker_started.load(std::memory_order_acquire);
            });
        const DWORD wait_rc = WaitForSingleObject(g_remote_call_lower_worker_handle, 0);
        const bool ready = g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
                           g_remote_call_lower_worker_alive.load(std::memory_order_acquire);
        if (!ready && wait_rc == WAIT_OBJECT_0) {
            CloseHandle(g_remote_call_lower_worker_handle);
            g_remote_call_lower_worker_handle = nullptr;
            g_remote_call_lower_worker_begin_tid = 0;
            g_remote_call_lower_worker_started.store(false, std::memory_order_release);
            record_lower_executor_start_failure(call_id,
                                                active_pid_at_entry,
                                                generation_at_entry,
                                                stats,
                                                resource_signature,
                                                ERROR_GEN_FAILURE,
                                                ERROR_GEN_FAILURE,
                                                0,
                                                0,
                                                ERROR_GEN_FAILURE,
                                                "_beginthreadex",
                                                "runtime",
                                                "worker_exited_before_ready",
                                                "worker_exited_before_ready");
            if (failure_outcome)
                populate_lower_executor_start_failure_outcome(*failure_outcome,
                                                              g_remote_call_lower_start_failure,
                                                              call_start,
                                                              stats,
                                                              "worker_exited_before_ready");
            diag::log_tagged_fmt("driver",
                "call_function_lower_thread_create_failed call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX api=_beginthreadex requested_stack_bytes=%u returned_handle=%p returned_tid=%u gle=%lu win32_gle=%lu errno=%d doserrno=%lu system_value=%d system_category=%s system_message=%s what=%s queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%u first_call_id=%llu last_call_id=%llu failure_count=%u suppressed_count=%u backoff_ms=%lu next_retry_in_ms=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                trigger && trigger[0] ? trigger : "",
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                expected_pid,
                active_pid_at_entry,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(function_address),
                requested_stack_bytes,
                worker_handle,
                begin_tid,
                static_cast<unsigned long>(ERROR_GEN_FAILURE),
                static_cast<unsigned long>(ERROR_GEN_FAILURE),
                0,
                0ul,
                ERROR_GEN_FAILURE,
                "runtime",
                "worker_exited_before_ready",
                "worker_exited_before_ready",
                g_remote_call_lower_start_failure.queue_depth,
                g_remote_call_lower_start_failure.inflight,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.worker_tid),
                g_remote_call_lower_start_failure.worker_alive,
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.first_call_id),
                static_cast<unsigned long long>(g_remote_call_lower_start_failure.last_call_id),
                g_remote_call_lower_start_failure.failure_count,
                g_remote_call_lower_start_failure.suppressed_count,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
                g_remote_call_lower_start_failure.next_retry_ms > GetTickCount64() ? static_cast<unsigned long long>(g_remote_call_lower_start_failure.next_retry_ms - GetTickCount64()) : 0ull,
                static_cast<unsigned long long>(GetTickCount64() - call_start));
            return false;
        }
        reset_lower_executor_start_failure_cache("start_success");
        diag::log_tagged_fmt("driver",
            "call_function_lower_worker_create_ok call_id=%llu trigger=%s phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX api=_beginthreadex requested_stack_bytes=%u handle=%p begin_tid=%u worker_tid=%lu worker_alive=%d loop_ready=%d ready_wait_ms=%llu wait_rc=%lu queue_depth=%u inflight=%u elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            trigger && trigger[0] ? trigger : "",
            phase ? phase : "",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            expected_pid,
            active_pid_at_entry,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(function_address),
            requested_stack_bytes,
            worker_handle,
            begin_tid,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - ready_wait_start),
            static_cast<unsigned long>(wait_rc),
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        constexpr unsigned requested_stack_bytes2 = aida::infra::win_thread::default_stack_reserve;
        errno = 0;
        _set_doserrno(0);
        SetLastError(ERROR_SUCCESS);
        const ULONGLONG create2_start = GetTickCount64();
        unsigned begin_tid2 = 0;
        uintptr_t raw2 = _beginthreadex(nullptr,
                                       requested_stack_bytes2,
                                       &lower_remote_call_worker2_entry,
                                       nullptr,
                                       0,
                                       &begin_tid2);
        const DWORD create2_gle = GetLastError();
        HANDLE worker2_handle = reinterpret_cast<HANDLE>(raw2);
        if (raw2 != 0) {
            g_remote_call_lower_worker2_handle = worker2_handle;
            g_remote_call_lower_worker2_begin_tid = begin_tid2;
            g_remote_call_lower_worker2_started.store(true, std::memory_order_release);
            const ULONGLONG ready2_wait_start = GetTickCount64();
            g_remote_call_lower_start2_cv.wait_for(lk,
                std::chrono::milliseconds(kLowerRemoteCallWorkerReadyWaitMs),
                []() {
                    return g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
                           g_remote_call_lower_executor_stop.load(std::memory_order_acquire) ||
                           !g_remote_call_lower_worker2_started.load(std::memory_order_acquire);
                });
            const bool ready2 = g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
                                g_remote_call_lower_worker2_alive.load(std::memory_order_acquire);
            if (!ready2) {
                CloseHandle(g_remote_call_lower_worker2_handle);
                g_remote_call_lower_worker2_handle = nullptr;
                g_remote_call_lower_worker2_begin_tid = 0;
                g_remote_call_lower_worker2_started.store(false, std::memory_order_release);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_worker2_create_failed_best_effort call_id=%llu reason=worker2_not_ready gle=%lu begin_tid2=%u ready_wait_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    static_cast<unsigned long>(create2_gle),
                    begin_tid2,
                    static_cast<unsigned long long>(GetTickCount64() - ready2_wait_start));
            } else {
                diag::log_tagged_fmt("driver",
                    "call_function_lower_worker2_create_ok call_id=%llu handle=%p begin_tid2=%u worker2_tid=%lu worker2_alive=%d loop2_ready=%d ready_wait_ms=%llu queue_depth=%u inflight=%u",
                    static_cast<unsigned long long>(call_id),
                    g_remote_call_lower_worker2_handle,
                    begin_tid2,
                    static_cast<unsigned long>(g_remote_call_lower_worker2_tid.load(std::memory_order_acquire)),
                    g_remote_call_lower_worker2_alive.load(std::memory_order_acquire) ? 1 : 0,
                    g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
                    static_cast<unsigned long long>(GetTickCount64() - ready2_wait_start),
                    g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                    g_remote_call_lower_inflight.load(std::memory_order_acquire));
            }
        } else {
            diag::log_tagged_fmt("driver",
                "call_function_lower_worker2_create_failed_best_effort call_id=%llu reason=_beginthreadex_failed gle=%lu",
                static_cast<unsigned long long>(call_id),
                static_cast<unsigned long>(create2_gle));
        }
        return true;
    }

    void stop_lower_remote_call_executor(const char* reason, DWORD wait_ms) noexcept
    {
        const ULONGLONG stop_start = GetTickCount64();
        std::vector<std::shared_ptr<lower_remote_call_work_item_t>> cancelled;
        const char* reason_text = reason && reason[0] ? reason : "shutdown";
        bool had_worker = false;
        bool had_worker2 = false;
        {
            std::lock_guard<std::mutex> lk(g_remote_call_lower_executor_mutex);
            had_worker = g_remote_call_lower_worker_started.load(std::memory_order_acquire) ||
                         g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ||
                         g_remote_call_lower_worker_handle != nullptr;
            had_worker2 = g_remote_call_lower_worker2_started.load(std::memory_order_acquire) ||
                          g_remote_call_lower_worker2_alive.load(std::memory_order_acquire) ||
                          g_remote_call_lower_worker2_handle != nullptr;
            g_remote_call_lower_executor_stop.store(true, std::memory_order_release);
            while (!g_remote_call_lower_queue.empty()) {
                cancelled.push_back(g_remote_call_lower_queue.front());
                g_remote_call_lower_queue.pop_front();
            }
            g_remote_call_lower_queue_depth.store(0, std::memory_order_release);
        }
        const ULONGLONG cancel_time = GetTickCount64();
        for (const auto& item : cancelled)
            complete_lower_remote_call_cancelled(item, "executor_shutdown", cancel_time);
        g_remote_call_lower_executor_cv.notify_all();
        diag::log_tagged_fmt("driver",
            "call_function_lower_executor_stop_begin reason=%s had_worker=%d had_worker2=%d cancelled_queued=%zu worker_tid=%lu begin_tid=%u worker_alive=%d loop_ready=%d worker2_tid=%lu begin_tid2=%u worker2_alive=%d loop2_ready=%d inflight=%u wait_ms=%lu cached_failure=%d cached_failures=%u cached_suppressed=%u cached_backoff_ms=%lu elapsed_ms=%llu",
            reason_text,
            had_worker ? 1 : 0,
            had_worker2 ? 1 : 0,
            cancelled.size(),
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker_begin_tid,
            g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(g_remote_call_lower_worker2_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker2_begin_tid,
            g_remote_call_lower_worker2_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            static_cast<unsigned long>(wait_ms),
            g_remote_call_lower_start_failure.valid ? 1 : 0,
            g_remote_call_lower_start_failure.failure_count,
            g_remote_call_lower_start_failure.suppressed_count,
            static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
        if (!had_worker && !had_worker2)
            return;
        const ULONGLONG deadline = stop_start + wait_ms;
        while ((g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ||
                g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)) &&
               GetTickCount64() < deadline)
            Sleep(10);
        bool joined = false;
        bool detached = false;
        HANDLE worker_to_join = nullptr;
        HANDLE worker2_to_join = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_remote_call_lower_executor_mutex);
            if (g_remote_call_lower_worker_handle) {
                if (!g_remote_call_lower_worker_alive.load(std::memory_order_acquire)) {
                    worker_to_join = g_remote_call_lower_worker_handle;
                    g_remote_call_lower_worker_handle = nullptr;
                    g_remote_call_lower_worker_begin_tid = 0;
                } else {
                    CloseHandle(g_remote_call_lower_worker_handle);
                    g_remote_call_lower_worker_handle = nullptr;
                    g_remote_call_lower_worker_begin_tid = 0;
                    detached = true;
                }
            }
            if (g_remote_call_lower_worker2_handle) {
                if (!g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)) {
                    worker2_to_join = g_remote_call_lower_worker2_handle;
                    g_remote_call_lower_worker2_handle = nullptr;
                    g_remote_call_lower_worker2_begin_tid = 0;
                } else {
                    CloseHandle(g_remote_call_lower_worker2_handle);
                    g_remote_call_lower_worker2_handle = nullptr;
                    g_remote_call_lower_worker2_begin_tid = 0;
                    detached = true;
                }
            }
        }
        if (worker_to_join) {
            WaitForSingleObject(worker_to_join, INFINITE);
            CloseHandle(worker_to_join);
            joined = true;
        }
        if (worker2_to_join) {
            WaitForSingleObject(worker2_to_join, INFINITE);
            CloseHandle(worker2_to_join);
            joined = true;
        }
        if (!g_remote_call_lower_worker_handle &&
            !g_remote_call_lower_worker_alive.load(std::memory_order_acquire) &&
            !g_remote_call_lower_worker_started.load(std::memory_order_acquire) &&
            !g_remote_call_lower_worker2_handle &&
            !g_remote_call_lower_worker2_alive.load(std::memory_order_acquire) &&
            !g_remote_call_lower_worker2_started.load(std::memory_order_acquire))
            reset_lower_executor_start_failure_cache("executor_stopped");
        diag::log_tagged_fmt("driver",
            "call_function_lower_executor_stop_done reason=%s joined=%d detached=%d worker_alive=%d loop_ready=%d worker_tid=%lu begin_tid=%u worker2_alive=%d loop2_ready=%d worker2_tid=%lu begin_tid2=%u queue_depth=%u inflight=%u cached_failure=%d cached_failures=%u cached_suppressed=%u elapsed_ms=%llu",
            reason_text,
            joined ? 1 : 0,
            detached ? 1 : 0,
            g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker_begin_tid,
            g_remote_call_lower_worker2_alive.load(std::memory_order_acquire) ? 1 : 0,
            g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(g_remote_call_lower_worker2_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker2_begin_tid,
            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            g_remote_call_lower_start_failure.valid ? 1 : 0,
            g_remote_call_lower_start_failure.failure_count,
            g_remote_call_lower_start_failure.suppressed_count,
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
    }

    bool ensure_lower_remote_call_executor(const char* phase,
                                           uint64_t call_id,
                                           const remote_call_snapshot_t& call_ctx,
                                           uint32_t expected_pid,
                                           uint32_t active_pid_at_entry,
                                           uint64_t generation_at_entry,
                                           uint64_t function_address,
                                           ULONGLONG call_start,
                                           lower_remote_call_outcome_t& failure_outcome)
    {
        if (!g_remote_call_lower_executor_stop.load(std::memory_order_acquire) &&
            ((g_remote_call_lower_worker_started.load(std::memory_order_acquire) &&
              (g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
               g_remote_call_lower_worker_alive.load(std::memory_order_acquire))) ||
             (g_remote_call_lower_worker2_started.load(std::memory_order_acquire) &&
              (g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
               g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)))))
            return true;

        std::unique_lock<std::mutex> lk(g_remote_call_lower_executor_mutex);
        if (!g_remote_call_lower_executor_stop.load(std::memory_order_acquire) &&
            ((g_remote_call_lower_worker_started.load(std::memory_order_acquire) &&
              (g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
               g_remote_call_lower_worker_alive.load(std::memory_order_acquire))) ||
             (g_remote_call_lower_worker2_started.load(std::memory_order_acquire) &&
              (g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
               g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)))))
            return true;
        if (g_remote_call_lower_executor_stop.load(std::memory_order_acquire)) {
            failure_outcome.gle = ERROR_OPERATION_ABORTED;
            failure_outcome.cancelled = true;
            failure_outcome.lower_lock_timeout = true;
            failure_outcome.active_pid_after = driver_bridge::attached_pid();
            failure_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
            failure_outcome.elapsed_ms = GetTickCount64() - call_start;
            failure_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
            failure_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
            failure_outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
            failure_outcome.inflight_at_submit = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            failure_outcome.inflight_after = failure_outcome.inflight_at_submit;
            failure_outcome.completion_reason = "executor_stopping";
            diag::log_tagged_fmt("driver",
                "call_function_lower_executor_reject call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=executor_stopping queue_depth=%u inflight=%u worker_tid=%lu begin_tid=%u worker_alive=%u loop_ready=%d elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                expected_pid,
                active_pid_at_entry,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(function_address),
                failure_outcome.queue_depth_at_submit,
                failure_outcome.inflight_at_submit,
                static_cast<unsigned long>(failure_outcome.worker_tid),
                g_remote_call_lower_worker_begin_tid,
                failure_outcome.worker_alive,
                g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(failure_outcome.elapsed_ms));
            return false;
        }
        if (g_remote_call_lower_worker_handle) {
            HANDLE previous_worker = g_remote_call_lower_worker_handle;
            g_remote_call_lower_worker_handle = nullptr;
            g_remote_call_lower_worker_begin_tid = 0;
            lk.unlock();
            WaitForSingleObject(previous_worker, INFINITE);
            CloseHandle(previous_worker);
            lk.lock();
            if (!g_remote_call_lower_executor_stop.load(std::memory_order_acquire) &&
                ((g_remote_call_lower_worker_started.load(std::memory_order_acquire) &&
                  (g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
                   g_remote_call_lower_worker_alive.load(std::memory_order_acquire))) ||
                 (g_remote_call_lower_worker2_started.load(std::memory_order_acquire) &&
                  (g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
                   g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)))))
                return true;
            if (g_remote_call_lower_executor_stop.load(std::memory_order_acquire)) {
                failure_outcome.gle = ERROR_OPERATION_ABORTED;
                failure_outcome.cancelled = true;
                failure_outcome.lower_lock_timeout = true;
                failure_outcome.active_pid_after = driver_bridge::attached_pid();
                failure_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                failure_outcome.elapsed_ms = GetTickCount64() - call_start;
                failure_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
                failure_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
                failure_outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                failure_outcome.inflight_at_submit = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                failure_outcome.inflight_after = failure_outcome.inflight_at_submit;
                failure_outcome.completion_reason = "executor_stopping";
                return false;
            }
        }
        if (g_remote_call_lower_worker2_handle) {
            HANDLE previous_worker2 = g_remote_call_lower_worker2_handle;
            g_remote_call_lower_worker2_handle = nullptr;
            g_remote_call_lower_worker2_begin_tid = 0;
            lk.unlock();
            WaitForSingleObject(previous_worker2, INFINITE);
            CloseHandle(previous_worker2);
            lk.lock();
        }
        return start_lower_remote_call_executor_locked(lk,
                                                       "demand",
                                                       phase,
                                                       call_id,
                                                       call_ctx,
                                                       expected_pid,
                                                       active_pid_at_entry,
                                                       generation_at_entry,
                                                       function_address,
                                                       call_start,
                                                       &failure_outcome);
    }

    void prestart_lower_remote_call_executor_state_known(const char* reason,
                                                         ULONGLONG call_start,
                                                         uint32_t active_pid,
                                                         uint64_t generation,
                                                         bool state_mutex_held) noexcept
    {
        try {
            remote_call_snapshot_t call_ctx{};
            call_ctx.label = "lower_executor_prestart";
            call_ctx.tool = "";
            call_ctx.diag_id = "";
            call_ctx.pid = active_pid;
            call_ctx.timeout_ms = 0;
            call_ctx.deadline_ms = 0;
            call_ctx.cancelled = false;
            call_ctx.require_deadline = false;
            call_ctx.context_active = false;
            std::unique_lock<std::mutex> lk(g_remote_call_lower_executor_mutex);
            if (!g_remote_call_lower_executor_stop.load(std::memory_order_acquire) &&
                ((g_remote_call_lower_worker_started.load(std::memory_order_acquire) &&
                  (g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ||
                   g_remote_call_lower_worker_alive.load(std::memory_order_acquire))) ||
                 (g_remote_call_lower_worker2_started.load(std::memory_order_acquire) &&
                  (g_remote_call_lower_worker2_loop_ready.load(std::memory_order_acquire) ||
                   g_remote_call_lower_worker2_alive.load(std::memory_order_acquire))))) {
                diag::log_tagged_fmt("driver",
                    "lower_executor_prestart_skip reason=%s already_started=1 active_pid=%u generation=%llu state_mutex_held=%d worker_tid=%lu begin_tid=%u loop_ready=%d elapsed_ms=%llu",
                    reason && reason[0] ? reason : "",
                    active_pid,
                    static_cast<unsigned long long>(generation),
                    state_mutex_held ? 1 : 0,
                    static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                    g_remote_call_lower_worker_begin_tid,
                    g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
                    static_cast<unsigned long long>(GetTickCount64() - call_start));
                return;
            }
            if (g_remote_call_lower_worker_handle &&
                !g_remote_call_lower_worker_alive.load(std::memory_order_acquire)) {
                HANDLE previous = g_remote_call_lower_worker_handle;
                g_remote_call_lower_worker_handle = nullptr;
                g_remote_call_lower_worker_begin_tid = 0;
                lk.unlock();
                WaitForSingleObject(previous, INFINITE);
                CloseHandle(previous);
                lk.lock();
            }
            if (g_remote_call_lower_worker2_handle &&
                !g_remote_call_lower_worker2_alive.load(std::memory_order_acquire)) {
                HANDLE previous2 = g_remote_call_lower_worker2_handle;
                g_remote_call_lower_worker2_handle = nullptr;
                g_remote_call_lower_worker2_begin_tid = 0;
                lk.unlock();
                WaitForSingleObject(previous2, INFINITE);
                CloseHandle(previous2);
                lk.lock();
            }
            const bool ok = start_lower_remote_call_executor_locked(lk,
                                                                    reason && reason[0] ? reason : "prestart",
                                                                    "prestart",
                                                                    0,
                                                                    call_ctx,
                                                                    active_pid,
                                                                    active_pid,
                                                                    generation,
                                                                    0,
                                                                    call_start,
                                                                    nullptr);
            diag::log_tagged_fmt("driver",
                "lower_executor_prestart_done reason=%s ok=%d active_pid=%u generation=%llu state_mutex_held=%d cached_failure=%d cached_failures=%u cached_suppressed=%u cached_backoff_ms=%lu worker_tid=%lu begin_tid=%u worker_alive=%u loop_ready=%d queue_depth=%u inflight=%u elapsed_ms=%llu",
                reason && reason[0] ? reason : "",
                ok ? 1 : 0,
                active_pid,
                static_cast<unsigned long long>(generation),
                state_mutex_held ? 1 : 0,
                g_remote_call_lower_start_failure.valid ? 1 : 0,
                g_remote_call_lower_start_failure.failure_count,
                g_remote_call_lower_start_failure.suppressed_count,
                static_cast<unsigned long>(g_remote_call_lower_start_failure.backoff_ms),
                static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                g_remote_call_lower_worker_begin_tid,
                g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u,
                g_remote_call_lower_worker_loop_ready.load(std::memory_order_acquire) ? 1 : 0,
                g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long long>(GetTickCount64() - call_start));
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("driver",
                "lower_executor_prestart_exception reason=%s err=%s elapsed_ms=%llu",
                reason && reason[0] ? reason : "",
                ex.what(),
                static_cast<unsigned long long>(GetTickCount64() - call_start));
        } catch (...) {
            diag::log_tagged_fmt("driver",
                "lower_executor_prestart_exception reason=%s err=<unknown> elapsed_ms=%llu",
                reason && reason[0] ? reason : "",
                static_cast<unsigned long long>(GetTickCount64() - call_start));
        }
    }

    void prestart_lower_remote_call_executor(const char* reason, ULONGLONG call_start) noexcept
    {
        prestart_lower_remote_call_executor_state_known(reason,
                                                        call_start,
                                                        driver_bridge::attached_pid(),
                                                        g_active_pid_generation.load(std::memory_order_acquire),
                                                        false);
    }

    struct lower_remote_call_drain_result_t {
        bool drained = false;
        uint32_t queue_depth = 0;
        uint32_t inflight = 0;
        uint32_t worker_alive = 0;
        uint32_t last_abandoned = 0;
        DWORD stable_zero_ms = 0;
        DWORD elapsed_ms = 0;
    };

    constexpr DWORD kSetActivePidDrainTimeoutMs = 2500;
    constexpr DWORD kAttachAdditionalDrainTimeoutMs = 6000;
    constexpr DWORD kStuckWorkerBypassMs = 3000;

    lower_remote_call_drain_result_t wait_lower_remote_call_drain_for_pid_switch(uint32_t from_pid,
                                                                                 uint32_t to_pid,
                                                                                 const char* phase,
                                                                                 DWORD timeout_ms) noexcept
    {
        const ULONGLONG started = GetTickCount64();
        ULONGLONG zero_since = 0;
        ULONGLONG stuck_since = 0;
        lower_remote_call_drain_result_t result{};
        for (;;) {
            const ULONGLONG now = GetTickCount64();
            result.queue_depth = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
            result.inflight = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            result.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
            result.last_abandoned = g_lower_remote_call_last_abandoned.load(std::memory_order_acquire) ? 1u : 0u;
            result.elapsed_ms = static_cast<DWORD>(now - started);
            if (result.queue_depth == 0 && result.inflight == 0) {
                if (zero_since == 0)
                    zero_since = now;
                result.stable_zero_ms = static_cast<DWORD>(now - zero_since);
                const DWORD settle_ms = result.last_abandoned ? 1200u : 50u;
                if (result.stable_zero_ms >= settle_ms) {
                    result.drained = true;
                    if (result.last_abandoned)
                        g_lower_remote_call_last_abandoned.store(false, std::memory_order_release);
                    diag::log_tagged_fmt("driver",
                        "lower_remote_call_drain_before_pid_switch phase=%s from_pid=%u to_pid=%u drained=1 queue_depth=%u inflight=%u worker_alive=%u worker_tid=%lu last_abandoned=%u stable_zero_ms=%lu settle_ms=%lu elapsed_ms=%lu",
                        phase ? phase : "",
                        from_pid,
                        to_pid,
                        result.queue_depth,
                        result.inflight,
                        result.worker_alive,
                        static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                        result.last_abandoned,
                        static_cast<unsigned long>(result.stable_zero_ms),
                        static_cast<unsigned long>(settle_ms),
                        static_cast<unsigned long>(result.elapsed_ms));
                    return result;
                }
            } else {
                zero_since = 0;
                result.stable_zero_ms = 0;
                if (result.inflight == 1 && result.last_abandoned == 1) {
                    if (stuck_since == 0)
                        stuck_since = now;
                    const DWORD stuck_ms = static_cast<DWORD>(now - stuck_since);
                    if (stuck_ms >= kStuckWorkerBypassMs) {
                        g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel);
                        g_remote_call_lower_inflight.store(0, std::memory_order_release);
                        g_lower_remote_call_worker_recovering.store(true, std::memory_order_release);
                        g_lower_remote_call_last_abandoned.store(false, std::memory_order_release);
                        result.drained = true;
                        result.inflight = 0;
                        result.last_abandoned = 0;
                        diag::log_tagged_critical_fmt("driver",
                            "lower_remote_call_drain_stuck_bypass phase=%s from_pid=%u to_pid=%u stuck_ms=%lu generation_bumped=1 inflight_forced=0 worker_tid=%lu elapsed_ms=%lu",
                            phase ? phase : "",
                            from_pid,
                            to_pid,
                            static_cast<unsigned long>(stuck_ms),
                            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                            static_cast<unsigned long>(result.elapsed_ms));
                        return result;
                    }
                } else {
                    stuck_since = 0;
                }
            }
            if (result.elapsed_ms >= timeout_ms) {
                diag::log_tagged_fmt("driver",
                    "lower_remote_call_drain_before_pid_switch phase=%s from_pid=%u to_pid=%u drained=0 queue_depth=%u inflight=%u worker_alive=%u worker_tid=%lu last_abandoned=%u stable_zero_ms=%lu timeout_ms=%lu elapsed_ms=%lu",
                    phase ? phase : "",
                    from_pid,
                    to_pid,
                    result.queue_depth,
                    result.inflight,
                    result.worker_alive,
                    static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                    result.last_abandoned,
                    static_cast<unsigned long>(result.stable_zero_ms),
                    static_cast<unsigned long>(timeout_ms),
                    static_cast<unsigned long>(result.elapsed_ms));
                return result;
            }
            Sleep(25);
        }
    }

    template <typename Fn>
    lower_remote_call_outcome_t run_bounded_lower_remote_call(const char* phase,
                                                             uint64_t call_id,
                                                             const remote_call_snapshot_t& call_ctx,
                                                             uint32_t active_pid_at_entry,
                                                             uint64_t generation_at_entry,
                                                             uint64_t function_address,
                                                             ULONGLONG call_start,
                                                             Fn&& lower_fn)
    {
        lower_remote_call_outcome_t timeout_outcome{};
        timeout_outcome.gle = ERROR_TIMEOUT;
        timeout_outcome.active_pid_after = driver_bridge::attached_pid();
        timeout_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
        timeout_outcome.elapsed_ms = GetTickCount64() - call_start;
        timeout_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
        timeout_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
        timeout_outcome.allow_zero_result = call_ctx.allow_zero_result;
        timeout_outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        timeout_outcome.inflight_at_submit = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        timeout_outcome.inflight_after = timeout_outcome.inflight_at_submit;

        const uint32_t expected_pid = call_ctx.pid != 0 ? call_ctx.pid : active_pid_at_entry;
        if (expected_pid == 0 || active_pid_at_entry == 0 || active_pid_at_entry != expected_pid) {
            timeout_outcome.gle = ERROR_OPERATION_ABORTED;
            timeout_outcome.stale_generation = true;
            timeout_outcome.completion_reason = "active_pid_mismatch";
            store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
            diag::log_tagged_fmt("driver",
                "call_function_lower_reject call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u expected_pid=%u generation=%llu reason=active_pid_mismatch fn=0x%llX elapsed_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%u",
                static_cast<unsigned long long>(call_id),
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                active_pid_at_entry,
                expected_pid,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(function_address),
                static_cast<unsigned long long>(timeout_outcome.elapsed_ms),
                timeout_outcome.queue_depth_at_submit,
                timeout_outcome.inflight_at_submit,
                static_cast<unsigned long>(timeout_outcome.worker_tid),
                timeout_outcome.worker_alive);
            return timeout_outcome;
        }

        if (!ensure_lower_remote_call_executor(phase,
                                               call_id,
                                               call_ctx,
                                               expected_pid,
                                               active_pid_at_entry,
                                               generation_at_entry,
                                               function_address,
                                               call_start,
                                               timeout_outcome)) {
            store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
            return timeout_outcome;
        }

        if (driver_bridge::current_remote_call_cancelled()) {
            timeout_outcome.gle = ERROR_CANCELLED;
            timeout_outcome.cancelled = true;
            timeout_outcome.completion_reason = "cancelled_before_enqueue";
            timeout_outcome.active_pid_after = driver_bridge::attached_pid();
            timeout_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
            timeout_outcome.elapsed_ms = GetTickCount64() - call_start;
            timeout_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
            timeout_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
            timeout_outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
            timeout_outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
            diag::log_tagged_fmt("driver",
                "call_function_lower_cancelled_before_enqueue call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX queue_depth=%u inflight=%u worker_tid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                expected_pid,
                active_pid_at_entry,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(function_address),
                timeout_outcome.queue_depth_at_submit,
                timeout_outcome.inflight_after,
                static_cast<unsigned long>(timeout_outcome.worker_tid),
                static_cast<unsigned long long>(timeout_outcome.elapsed_ms));
            return timeout_outcome;
        }

        using lower_fn_t = std::decay_t<Fn>;
        auto lower_callable = std::make_shared<lower_fn_t>(std::forward<Fn>(lower_fn));
        auto item = std::make_shared<lower_remote_call_work_item_t>();
        item->state = std::make_shared<lower_remote_call_shared_state_t>();
        item->lower_fn = [lower_callable](uint64_t& result, DWORD& gle, bool& zero_result_rejected) -> bool {
            return (*lower_callable)(result, gle, zero_result_rejected);
        };
        item->phase = phase ? phase : "";
        item->label = call_ctx.label ? call_ctx.label : "";
        item->tool = call_ctx.tool ? call_ctx.tool : "";
        item->diag_id = call_ctx.diag_id ? call_ctx.diag_id : "";
        item->call_id = call_id;
        item->generation_at_entry = generation_at_entry;
        item->function_address = function_address;
        item->expected_pid = expected_pid;
        item->active_pid_at_entry = active_pid_at_entry;
        item->timeout_ms = call_ctx.timeout_ms;
        item->allow_zero_result = call_ctx.allow_zero_result;
        item->deadline_ms = call_ctx.deadline_ms;
        item->call_start = call_start;
        item->queued_at = GetTickCount64();
        item->deadline_remaining_at_queue_ms = deadline_remaining_ms(call_ctx.deadline_ms, item->queued_at);
        item->inflight_at_submit = g_remote_call_lower_inflight.load(std::memory_order_acquire);

        {
            std::lock_guard<std::mutex> lk(g_remote_call_lower_executor_mutex);
            if (g_remote_call_lower_executor_stop.load(std::memory_order_acquire)) {
                timeout_outcome.gle = ERROR_OPERATION_ABORTED;
                timeout_outcome.cancelled = true;
                timeout_outcome.lower_lock_timeout = true;
                timeout_outcome.active_pid_after = driver_bridge::attached_pid();
                timeout_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                timeout_outcome.elapsed_ms = GetTickCount64() - call_start;
                timeout_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
                timeout_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
                timeout_outcome.queue_depth_at_submit = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                timeout_outcome.inflight_at_submit = item->inflight_at_submit;
                timeout_outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                timeout_outcome.completion_reason = "executor_stopping";
                store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_enqueue_reject call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=executor_stopping queue_depth=%u inflight=%u worker_tid=%lu elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    item->phase.c_str(),
                    item->label.c_str(),
                    item->tool.c_str(),
                    item->diag_id.c_str(),
                    expected_pid,
                    active_pid_at_entry,
                    static_cast<unsigned long long>(generation_at_entry),
                    static_cast<unsigned long long>(function_address),
                    timeout_outcome.queue_depth_at_submit,
                    timeout_outcome.inflight_after,
                    static_cast<unsigned long>(timeout_outcome.worker_tid),
                    static_cast<unsigned long long>(timeout_outcome.elapsed_ms));
                return timeout_outcome;
            }
            if (g_remote_call_lower_queue.size() >= kLowerRemoteCallMaxQueueDepth) {
                timeout_outcome.gle = ERROR_BUSY;
                timeout_outcome.active_pid_after = driver_bridge::attached_pid();
                timeout_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                timeout_outcome.elapsed_ms = GetTickCount64() - call_start;
                timeout_outcome.queue_wait_ms = 0;
                timeout_outcome.deadline_remaining_at_queue_ms = item->deadline_remaining_at_queue_ms;
                timeout_outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(call_ctx.deadline_ms, GetTickCount64());
                timeout_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
                timeout_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
                timeout_outcome.queue_depth_at_submit = static_cast<uint32_t>(g_remote_call_lower_queue.size());
                timeout_outcome.queue_depth_after_pop = timeout_outcome.queue_depth_at_submit;
                timeout_outcome.inflight_at_submit = item->inflight_at_submit;
                timeout_outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                timeout_outcome.completion_reason = "queue_full";
                store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_enqueue_reject call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=queue_full queue_depth=%u max_queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%u elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    item->phase.c_str(),
                    item->label.c_str(),
                    item->tool.c_str(),
                    item->diag_id.c_str(),
                    expected_pid,
                    active_pid_at_entry,
                    static_cast<unsigned long long>(generation_at_entry),
                    static_cast<unsigned long long>(function_address),
                    timeout_outcome.queue_depth_at_submit,
                    kLowerRemoteCallMaxQueueDepth,
                    timeout_outcome.inflight_after,
                    static_cast<unsigned long>(timeout_outcome.worker_tid),
                    timeout_outcome.worker_alive,
                    static_cast<unsigned long long>(timeout_outcome.elapsed_ms));
                return timeout_outcome;
            }
            item->queue_depth_at_submit = static_cast<uint32_t>(g_remote_call_lower_queue.size() + 1);
            g_remote_call_lower_queue.emplace_back(item);
            g_remote_call_lower_queue_depth.store(static_cast<std::uint32_t>(g_remote_call_lower_queue.size()), std::memory_order_release);
        }
        g_remote_call_lower_executor_cv.notify_one();
        diag::log_tagged_fmt("driver",
            "call_function_lower_enqueue call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu worker_alive=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            item->phase.c_str(),
            item->label.c_str(),
            item->tool.c_str(),
            item->diag_id.c_str(),
            expected_pid,
            active_pid_at_entry,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(function_address),
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(item->deadline_remaining_at_queue_ms),
            item->queue_depth_at_submit,
            item->inflight_at_submit,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - call_start));

        std::unique_lock<std::mutex> lk(item->state->mutex);
        while (!item->state->done) {
            const ULONGLONG now = GetTickCount64();
            const bool cancelled = driver_bridge::current_remote_call_cancelled();
            const bool deadline_expired = call_ctx.deadline_ms != 0 && now >= call_ctx.deadline_ms;
            if (cancelled || deadline_expired) {
                if (deadline_expired && !cancelled && !item->state->done) {
                    constexpr DWORD kDeadlineGracePeriodMs = 200;
                    const ULONGLONG grace_start = GetTickCount64();
                    diag::log_tagged_fmt("driver",
                        "call_function_lower_grace_wait_begin call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX grace_period_ms=%lu deadline_ms=%llu elapsed_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu",
                        static_cast<unsigned long long>(call_id),
                        phase ? phase : "",
                        call_ctx.label,
                        call_ctx.tool,
                        call_ctx.diag_id,
                        expected_pid,
                        active_pid_at_entry,
                        static_cast<unsigned long long>(generation_at_entry),
                        static_cast<unsigned long long>(function_address),
                        static_cast<unsigned long>(kDeadlineGracePeriodMs),
                        static_cast<unsigned long long>(call_ctx.deadline_ms),
                        static_cast<unsigned long long>(now - call_start),
                        g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                        g_remote_call_lower_inflight.load(std::memory_order_acquire),
                        static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)));
                    while (!item->state->done) {
                        const ULONGLONG grace_now = GetTickCount64();
                        if (driver_bridge::current_remote_call_cancelled() || (grace_now - grace_start) >= kDeadlineGracePeriodMs)
                            break;
                        const DWORD grace_remaining = kDeadlineGracePeriodMs - static_cast<DWORD>(grace_now - grace_start);
                        item->state->cv.wait_for(lk, std::chrono::milliseconds(std::min<DWORD>(grace_remaining, 25u)));
                    }
                    if (item->state->done) {
                        const ULONGLONG grace_done_now = GetTickCount64();
                        diag::log_tagged_fmt("driver",
                            "call_function_lower_grace_wait_completed call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX grace_elapsed_ms=%llu deadline_ms=%llu elapsed_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu",
                            static_cast<unsigned long long>(call_id),
                            phase ? phase : "",
                            call_ctx.label,
                            call_ctx.tool,
                            call_ctx.diag_id,
                            expected_pid,
                            active_pid_at_entry,
                            static_cast<unsigned long long>(generation_at_entry),
                            static_cast<unsigned long long>(function_address),
                            static_cast<unsigned long long>(grace_done_now - grace_start),
                            static_cast<unsigned long long>(call_ctx.deadline_ms),
                            static_cast<unsigned long long>(grace_done_now - call_start),
                            g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                            g_remote_call_lower_inflight.load(std::memory_order_acquire),
                            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)));
                        break;
                    }
                    const ULONGLONG grace_expired_now = GetTickCount64();
                    diag::log_tagged_fmt("driver",
                        "call_function_lower_grace_wait_expired call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX grace_elapsed_ms=%llu deadline_ms=%llu elapsed_ms=%llu queue_depth=%u inflight=%u worker_tid=%lu",
                        static_cast<unsigned long long>(call_id),
                        phase ? phase : "",
                        call_ctx.label,
                        call_ctx.tool,
                        call_ctx.diag_id,
                        expected_pid,
                        active_pid_at_entry,
                        static_cast<unsigned long long>(generation_at_entry),
                        static_cast<unsigned long long>(function_address),
                        static_cast<unsigned long long>(grace_expired_now - grace_start),
                        static_cast<unsigned long long>(call_ctx.deadline_ms),
                        static_cast<unsigned long long>(grace_expired_now - call_start),
                        g_remote_call_lower_queue_depth.load(std::memory_order_acquire),
                        g_remote_call_lower_inflight.load(std::memory_order_acquire),
                        static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)));
                }
                const ULONGLONG abandon_now = GetTickCount64();
                item->state->abandoned = true;
                strcpy_s(item->state->abandoned_reason, cancelled ? "cancelled" : "deadline");
                timeout_outcome.cancelled = cancelled;
                timeout_outcome.deadline_expired = deadline_expired;
                timeout_outcome.gle = cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT;
                timeout_outcome.active_pid_after = driver_bridge::attached_pid();
                timeout_outcome.generation_after = g_active_pid_generation.load(std::memory_order_acquire);
                timeout_outcome.stale_generation = timeout_outcome.active_pid_after != expected_pid ||
                                                   timeout_outcome.generation_after != generation_at_entry;
                timeout_outcome.elapsed_ms = abandon_now - call_start;
                timeout_outcome.queue_wait_ms = abandon_now >= item->queued_at ? abandon_now - item->queued_at : 0;
                timeout_outcome.deadline_remaining_at_queue_ms = item->deadline_remaining_at_queue_ms;
                timeout_outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(call_ctx.deadline_ms, abandon_now);
                timeout_outcome.queue_depth_at_submit = item->queue_depth_at_submit;
                bool removed_from_queue = false;
                bool popped_from_queue = false;
                bool executing = false;
                ULONGLONG popped_at = 0;
                ULONGLONG executing_at = 0;
                {
                    std::lock_guard<std::mutex> queue_lk(g_remote_call_lower_executor_mutex);
                    auto queued_it = std::find(g_remote_call_lower_queue.begin(), g_remote_call_lower_queue.end(), item);
                    if (queued_it != g_remote_call_lower_queue.end()) {
                        g_remote_call_lower_queue.erase(queued_it);
                        removed_from_queue = true;
                        g_remote_call_lower_queue_depth.store(static_cast<std::uint32_t>(g_remote_call_lower_queue.size()), std::memory_order_release);
                    }
                    timeout_outcome.queue_depth_after_pop = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
                }
                popped_from_queue = item->state->popped;
                executing = item->state->executing;
                popped_at = item->state->popped_at;
                executing_at = item->state->executing_at;
                timeout_outcome.inflight_at_submit = item->inflight_at_submit;
                timeout_outcome.inflight_after = g_remote_call_lower_inflight.load(std::memory_order_acquire);
                timeout_outcome.worker_alive = g_remote_call_lower_worker_alive.load(std::memory_order_acquire) ? 1u : 0u;
                timeout_outcome.worker_tid = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
                timeout_outcome.allow_zero_result = call_ctx.allow_zero_result;
                timeout_outcome.caller_abandoned = true;
                timeout_outcome.removed_from_queue = removed_from_queue;
                timeout_outcome.popped_from_queue = popped_from_queue;
                timeout_outcome.execution_started = executing;
                timeout_outcome.executing_abandoned = executing;
                timeout_outcome.lower_lock_timeout = true;
                timeout_outcome.completed = false;
                timeout_outcome.completion_reason = removed_from_queue ? (cancelled ? "cancelled_removed_from_queue" : "deadline_removed_from_queue") :
                    (cancelled ? (executing ? "cancelled_executing_abandoned" : "cancelled_popped_not_started") :
                                 (executing ? "deadline_executing_abandoned" : "deadline_popped_not_started"));
                store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, timeout_outcome);
                diag::log_tagged_fmt("driver",
                    "call_function_lower_abandon call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX reason=%s completion_reason=%s removed_from_queue=%d popped=%d executing=%d executing_abandoned=%d popped_elapsed_ms=%llu executing_elapsed_ms=%llu timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu queue_wait_ms=%llu elapsed_ms=%llu queue_depth_submit=%u queue_depth_current=%u inflight=%u worker_tid=%lu worker_alive=%u stale_generation=%d allow_zero=%d",
                    static_cast<unsigned long long>(call_id),
                    phase ? phase : "",
                    call_ctx.label,
                    call_ctx.tool,
                    call_ctx.diag_id,
                    expected_pid,
                    active_pid_at_entry,
                    timeout_outcome.active_pid_after,
                    static_cast<unsigned long long>(generation_at_entry),
                    static_cast<unsigned long long>(timeout_outcome.generation_after),
                    static_cast<unsigned long long>(function_address),
                    cancelled ? "cancelled" : "deadline",
                    timeout_outcome.completion_reason.c_str(),
                    removed_from_queue ? 1 : 0,
                    popped_from_queue ? 1 : 0,
                    executing ? 1 : 0,
                    timeout_outcome.executing_abandoned ? 1 : 0,
                    popped_at != 0 && now >= popped_at ? static_cast<unsigned long long>(now - popped_at) : 0ull,
                    executing_at != 0 && now >= executing_at ? static_cast<unsigned long long>(now - executing_at) : 0ull,
                    call_ctx.timeout_ms,
                    static_cast<unsigned long long>(call_ctx.deadline_ms),
                    static_cast<unsigned long long>(timeout_outcome.deadline_remaining_at_finish_ms),
                    static_cast<unsigned long long>(timeout_outcome.queue_wait_ms),
                    static_cast<unsigned long long>(timeout_outcome.elapsed_ms),
                    timeout_outcome.queue_depth_at_submit,
                    timeout_outcome.queue_depth_after_pop,
                    timeout_outcome.inflight_after,
                    static_cast<unsigned long>(timeout_outcome.worker_tid),
                    timeout_outcome.worker_alive,
                    timeout_outcome.stale_generation ? 1 : 0,
                    call_ctx.allow_zero_result ? 1 : 0);
                return timeout_outcome;
            }
            const std::uint64_t remaining = deadline_remaining_ms(call_ctx.deadline_ms, now);
            const DWORD wait_ms = static_cast<DWORD>(std::min<std::uint64_t>(25, remaining == 0 ? 25 : remaining));
            item->state->cv.wait_for(lk, std::chrono::milliseconds(wait_ms));
        }
        lower_remote_call_outcome_t outcome = item->state->outcome;
        outcome.allow_zero_result = call_ctx.allow_zero_result;
        outcome.completed = !outcome.lower_lock_timeout;
        const ULONGLONG after_wait = GetTickCount64();
        const uint32_t active_after_wait = driver_bridge::attached_pid();
        const uint64_t generation_after_wait = g_active_pid_generation.load(std::memory_order_acquire);
        const bool deadline_after_wait = call_ctx.deadline_ms != 0 && after_wait >= call_ctx.deadline_ms;
        const bool cancelled_after_wait = driver_bridge::current_remote_call_cancelled();
        const bool stale_after_wait = active_after_wait != expected_pid || generation_after_wait != generation_at_entry;
        if (deadline_after_wait || cancelled_after_wait || stale_after_wait) {
            outcome.deadline_expired = outcome.deadline_expired || deadline_after_wait;
            outcome.cancelled = outcome.cancelled || cancelled_after_wait;
            outcome.stale_generation = outcome.stale_generation || stale_after_wait;
            outcome.lower_lock_timeout = true;
            outcome.completed = false;
            outcome.active_pid_after = active_after_wait;
            outcome.generation_after = generation_after_wait;
            outcome.deadline_remaining_at_finish_ms = deadline_remaining_ms(call_ctx.deadline_ms, after_wait);
            outcome.gle = stale_after_wait ? ERROR_OPERATION_ABORTED : (cancelled_after_wait ? ERROR_CANCELLED : ERROR_TIMEOUT);
            if (outcome.completion_reason.empty() ||
                outcome.completion_reason == "completed" ||
                outcome.completion_reason == "lower_failed")
                outcome.completion_reason = stale_after_wait ? "stale_after_wait" : (cancelled_after_wait ? "cancelled_after_wait" : "deadline_after_wait");
            diag::log_tagged_fmt("driver",
                "call_function_lower_late_reject call_id=%llu phase=%s label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX deadline_expired=%d cancelled=%d stale_generation=%d result=0x%llX gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                phase ? phase : "",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                expected_pid,
                active_pid_at_entry,
                active_after_wait,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(generation_after_wait),
                static_cast<unsigned long long>(function_address),
                outcome.deadline_expired ? 1 : 0,
                outcome.cancelled ? 1 : 0,
                outcome.stale_generation ? 1 : 0,
                static_cast<unsigned long long>(outcome.result),
                static_cast<unsigned long>(outcome.gle),
                static_cast<unsigned long long>(after_wait - call_start));
        }
        store_lower_remote_call_diag(phase, call_id, call_ctx, active_pid_at_entry, generation_at_entry, function_address, outcome);
        return outcome;
    }

    void release_ctx_handle(process_ctx_t& ctx)
    {
        if (ctx.h_process) {
            CloseHandle(ctx.h_process);
            ctx.h_process = nullptr;
        }
    }

    struct handle_closer
    {
        void operator()(HANDLE h) const
        {
            if (h && h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };

    using unique_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer>;

    unique_handle make_handle(HANDLE h)
    {
        return unique_handle((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
    }

    void logf(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        OutputDebugStringA(buf);
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        if (g_log_fn)
            g_log_fn(buf);
    }

    void driver_critical_fmt(const char* fmt, ...)
    {
        char buf[2048] = {};
        va_list ap;
        va_start(ap, fmt);
        _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        diag::log_tagged_critical("driver", buf);
    }

    std::vector<driver_bridge::thread_info_t> enumerate_threads_usermode_snapshot(uint32_t pid)
    {
        std::vector<driver_bridge::thread_info_t> result;
        if (pid == 0)
            return result;
        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snapshot)
            return result;
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (Thread32First(snapshot.get(), &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    driver_bridge::thread_info_t t;
                    t.tid = te.th32ThreadID;
                    t.owner_pid = pid;
                    t.priority = te.tpBasePri;
                    t.state = 0;
                    t.rip = 0;
                    result.push_back(t);
                }
            } while (Thread32Next(snapshot.get(), &te));
        }
        std::sort(result.begin(), result.end(), [](const driver_bridge::thread_info_t& a, const driver_bridge::thread_info_t& b) {
            return a.tid < b.tid;
        });
        return result;
    }

    uint64_t driver_fnv1a64(const void* data, size_t len)
    {
        if (!data)
            return 0;
        const auto* p = static_cast<const uint8_t*>(data);
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < len; ++i) {
            h ^= static_cast<uint64_t>(p[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }

    void set_last_error_locked(const std::string& text, bool allow_toast = true)
    {
        g_last_error = text;
        g_last_error_present.store(!text.empty(), std::memory_order_release);
        if (!text.empty()) {
            static std::mutex s_dedupe_mtx;
            static std::string s_last_text;
            static uint64_t s_last_log_ms = 0;
            static uint64_t s_suppressed_count = 0;
            bool emit_log = true;
            uint64_t suppressed_now = 0;
            {
                std::lock_guard<std::mutex> dl(s_dedupe_mtx);
                const uint64_t now = static_cast<uint64_t>(GetTickCount64());
                if (text == s_last_text && (now - s_last_log_ms) < 5000) {
                    emit_log = false;
                    ++s_suppressed_count;
                } else {
                    suppressed_now = s_suppressed_count;
                    s_suppressed_count = 0;
                    s_last_text = text;
                    s_last_log_ms = now;
                }
            }
            if (emit_log) {
                if (suppressed_now > 0) {
                    logf("AiDA Standalone: (suppressed %llu duplicate errors in last 5s)\n",
                        static_cast<unsigned long long>(suppressed_now));
                }
                logf("AiDA Standalone: %s\n", text.c_str());
                if (!allow_toast || driver_error_toast_suppressed()) {
                    diag::log_tagged_critical_fmt("driver", "driver_error_toast_suppressed text_len=%zu allow_toast=%d env_full_test=%d suppressed_dupes=%llu",
                        text.size(),
                        allow_toast ? 1 : 0,
                        env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0,
                        static_cast<unsigned long long>(suppressed_now));
                } else {
                    toast_notification::push(text, toast_notification::toast_type_t::error);
                }
            }
        }
    }

    void clear_last_error_locked_after_success(const char* source)
    {
        if (!g_last_error.empty()) {
            diag::log_tagged_fmt("driver",
                "last_error_clear_after_success source=%s stale=\"%s\"",
                source ? source : "<null>",
                g_last_error.c_str());
        }
        set_last_error_locked({});
    }

    void clear_last_error_after_success(const char* source)
    {
        if (!g_last_error_present.load(std::memory_order_acquire))
            return;
        std::lock_guard<std::mutex> lk(g_state_mtx);
        clear_last_error_locked_after_success(source);
    }

    void require_kernel_fail(const char* func_name)
    {
        logf("AiDA Standalone: %s requires kernel driver.\n", func_name);
        if (driver_error_toast_suppressed()) {
            diag::log_tagged_critical_fmt("driver", "driver_kernel_required_toast_suppressed func=%s env_full_test=%d",
                func_name ? func_name : "<null>",
                env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0);
        } else {
            toast_notification::push(std::string(func_name) + " requires kernel driver",
                                      toast_notification::toast_type_t::error);
        }
    }

    std::atomic<bool> g_driver_watchdog_started{false};
    std::atomic<bool> g_driver_watchdog_running{false};
    std::atomic<bool> g_driver_watchdog_stop{false};
    std::atomic<uint64_t> g_driver_watchdog_epoch{0};
    std::atomic<int>  g_driver_consecutive_fail{0};
    std::atomic<uint64_t> g_driver_watchdog_last_ok_tick{0};
    std::mutex g_driver_background_wait_mutex;
    std::condition_variable g_driver_background_wait_cv;

    constexpr int    kDriverWatchdogPeriodMs       = 4000;

    bool driver_startup_fail_closed(const char* phase, DWORD err)
    {
        const std::string loader_error = driver_loader::last_error();
        diag::log_tagged_critical_fmt("driver",
            "driver_startup_failed phase=%s err=0x%08X loader=\"%s\"",
            phase ? phase : "?",
            static_cast<unsigned long>(err),
            loader_error.empty() ? "<empty>" : loader_error.c_str());

        char crash[1024];
        _snprintf_s(crash, sizeof(crash), _TRUNCATE,
            "DRIVER_STARTUP_FAILED: phase=%s err=0x%08X tid=%lu\r\n"
            "Reason=Kernel driver did not produce a connectable device; kernel-backed features are unavailable.\r\n"
            "DriverLoaderLastError=%s\r\n",
            phase ? phase : "?",
            err,
            GetCurrentThreadId(),
            loader_error.empty() ? "<empty>" : loader_error.c_str());
        diag::write_crash_log(crash, false);

        std::string ui_error = "Kernel driver could not be started.";
        if (!loader_error.empty())
            ui_error += " " + loader_error;
        set_last_error_locked(ui_error);
        return false;
    }

    bool driver_liveness_probe() noexcept
    {
        if (!device || !device->is_connected())
            return false;
        voyager::device_t::ssdt_info info{};
        return device->query_ssdt(info);
    }

    void driver_watchdog_thread(uint64_t epoch)
    {
        diag::log_tagged_critical("driver", "watchdog_thread_entry");
        uint64_t probe_iter = 0;
        while (!g_driver_watchdog_stop.load(std::memory_order_acquire) &&
               g_driver_watchdog_epoch.load(std::memory_order_acquire) == epoch) {
            {
                std::unique_lock<std::mutex> wait_lock(g_driver_background_wait_mutex);
                g_driver_background_wait_cv.wait_for(wait_lock,
                    std::chrono::milliseconds(kDriverWatchdogPeriodMs),
                    [epoch]() {
                        return g_driver_watchdog_stop.load(std::memory_order_acquire) ||
                            g_driver_watchdog_epoch.load(std::memory_order_acquire) != epoch;
                    });
            }
            if (g_driver_watchdog_stop.load(std::memory_order_acquire) ||
                g_driver_watchdog_epoch.load(std::memory_order_acquire) != epoch) {
                break;
            }
            ++probe_iter;
            const bool connected = (device && device->is_connected());
            const bool ok = connected && driver_liveness_probe();
            diag::log_tagged_fmt("driver",
                "watchdog_liveness iter=%llu connected=%d ok=%d last_ok_ms=%llu",
                static_cast<unsigned long long>(probe_iter),
                connected ? 1 : 0,
                ok ? 1 : 0,
                static_cast<unsigned long long>(g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire)));
            aida::diagnostics::breadcrumb_options_t wd_opts{};
            wd_opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
            wd_opts.label = "driver_watchdog_liveness";
            wd_opts.reason = ok ? "ok" : (connected ? "probe_failed" : "not_connected");
            wd_opts.owner_subsystem = "driver_bridge";
            wd_opts.status_code = ok ? 0 : static_cast<std::uint16_t>(GetLastError() & 0xFFFFu);
            aida::diagnostics::emit(std::move(wd_opts));
            if (ok) {
                g_driver_watchdog_last_ok_tick.store(GetTickCount64(), std::memory_order_release);
                g_driver_consecutive_fail.store(0, std::memory_order_release);
                continue;
            }
            const int n = g_driver_consecutive_fail.fetch_add(1, std::memory_order_acq_rel) + 1;
            diag::log_tagged_fmt("driver",
                "watchdog_liveness_fail consecutive=%d connected=%d gle=%lu",
                n,
                connected ? 1 : 0,
                static_cast<unsigned long>(GetLastError()));
        }
        g_driver_watchdog_running.store(false, std::memory_order_release);
        if (g_driver_watchdog_epoch.load(std::memory_order_acquire) == epoch)
            g_driver_watchdog_started.store(false, std::memory_order_release);
        g_driver_background_wait_cv.notify_all();
        diag::log_tagged_critical("driver", "watchdog_thread_exit");
    }

    void start_driver_watchdog_locked()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("driver_watchdog_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        g_driver_watchdog_stop.store(false, std::memory_order_release);
        const uint64_t epoch = g_driver_watchdog_epoch.load(std::memory_order_acquire);
        bool expected = false;
        if (!g_driver_watchdog_started.compare_exchange_strong(expected, true)) {
            driver_critical_fmt("driver_watchdog_post_skip reason=already_started elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return;
        }
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "runtime_driver";
        sub.label = "driver_watchdog";
        sub.thread_class = "security_loop";
        sub.domain = aida::infra::executor::domain_t::security_liveness;
        sub.priority = 0;
        sub.generation = epoch;
        sub.body = [epoch]() {
            g_driver_watchdog_running.store(true, std::memory_order_release);
            driver_critical_fmt("driver_watchdog_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            driver_watchdog_thread(epoch);
            driver_critical_fmt("driver_watchdog_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        };
        bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
        driver_critical_fmt("driver_watchdog_post_post posted=%d elapsed_ms=%llu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!posted) {
            g_driver_watchdog_started.store(false, std::memory_order_release);
            diag::log_tagged("driver", "watchdog_post_failed");
        }
    }

    std::atomic<bool> g_event_poller_started{false};
    std::atomic<bool> g_event_poller_running{false};
    std::atomic<bool> g_event_poller_stop{false};
    std::atomic<uint64_t> g_event_poller_epoch{0};
    std::atomic<uint64_t> g_tctx_kernel_bypass_until_ms{0};
    std::atomic<uint32_t> g_tctx_kernel_failures{0};

    struct tctx_kernel_failure_key_t
    {
        uint32_t pid = 0;
        uint32_t tid = 0;
        DWORD status = ERROR_SUCCESS;
        std::string op;
    };
    struct tctx_kernel_failure_state_t
    {
        tctx_kernel_failure_key_t active_key;
        tctx_kernel_failure_key_t last_stable_key;
        bool have_active_key = false;
        bool have_last_stable_key = false;
        uint32_t active_repeats = 0;
        uint32_t distinct_stable_failures = 0;
        uint64_t first_seen_ms = 0;
        uint64_t last_seen_ms = 0;
    };
    std::mutex g_tctx_kernel_failure_mtx;
    tctx_kernel_failure_state_t g_tctx_kernel_failure_state;
    constexpr uint64_t kTctxKernelBypassMs = 120000;
    constexpr uint64_t kTctxSlowFailureMs = 250;
    constexpr uint64_t kTctxFailureEvidenceWindowMs = 30000;
    constexpr uint32_t kTctxStableFailureRepeats = 2;
    constexpr uint32_t kTctxDistinctStableFailuresBeforeBypass = 2;

    bool tctx_kernel_bypass_active()
    {
        const uint64_t until = g_tctx_kernel_bypass_until_ms.load(std::memory_order_acquire);
        return until != 0 && static_cast<uint64_t>(GetTickCount64()) < until;
    }

    void note_tctx_kernel_success()
    {
        g_tctx_kernel_failures.store(0, std::memory_order_release);
        std::lock_guard<std::mutex> lk(g_tctx_kernel_failure_mtx);
        g_tctx_kernel_failure_state = {};
    }

    bool same_tctx_failure_key(const tctx_kernel_failure_key_t& a, const tctx_kernel_failure_key_t& b)
    {
        return a.pid == b.pid && a.tid == b.tid && a.status == b.status && a.op == b.op;
    }

    void arm_tctx_kernel_bypass(const char* op, uint32_t pid, uint32_t tid, DWORD gle, uint64_t elapsed_ms, uint32_t failures, uint32_t key_repeats, uint32_t distinct_stable_failures, const char* reason)
    {
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        const uint64_t previous = g_tctx_kernel_bypass_until_ms.exchange(0, std::memory_order_acq_rel);
        diag::log_tagged_fmt("driver",
            "tctx_kernel_bypass_rejected op=%s pid=%u tid=%u gle=%lu elapsed_ms=%llu failures=%u key_repeats=%u distinct_stable_failures=%u previous_remaining_ms=%llu reason=%s fail_closed=1",
            op ? op : "tctx",
            pid,
            tid,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_ms),
            failures,
            key_repeats,
            distinct_stable_failures,
            previous > now ? static_cast<unsigned long long>(previous - now) : 0ULL,
            reason ? reason : "unspecified");
    }

    void note_tctx_kernel_failure(const char* op, uint32_t pid, uint32_t tid, DWORD gle, uint64_t elapsed_ms)
    {
        const uint32_t failures = g_tctx_kernel_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
        const bool proven_unavailable = gle == ERROR_PROC_NOT_FOUND || gle == ERROR_INVALID_FUNCTION || gle == ERROR_CALL_NOT_IMPLEMENTED;
        if (proven_unavailable) {
            arm_tctx_kernel_bypass(op, pid, tid, gle, elapsed_ms, failures, failures, failures, "driver_path_unavailable");
            return;
        }

        bool should_arm = false;
        uint32_t key_repeats = 0;
        uint32_t distinct_stable_failures = 0;
        bool stable_evidence = false;
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        {
            std::lock_guard<std::mutex> lk(g_tctx_kernel_failure_mtx);
            tctx_kernel_failure_state_t& state = g_tctx_kernel_failure_state;
            if (state.last_seen_ms != 0 && now >= state.last_seen_ms &&
                (now - state.last_seen_ms) > kTctxFailureEvidenceWindowMs) {
                state = {};
            }
            tctx_kernel_failure_key_t key{};
            key.pid = pid;
            key.tid = tid;
            key.status = gle;
            key.op = op ? op : "tctx";
            if (!state.have_active_key || !same_tctx_failure_key(state.active_key, key)) {
                state.active_key = key;
                state.have_active_key = true;
                state.active_repeats = 1;
                if (state.first_seen_ms == 0)
                    state.first_seen_ms = now;
            } else {
                state.active_repeats++;
            }
            state.last_seen_ms = now;
            key_repeats = state.active_repeats;
            stable_evidence = key_repeats >= kTctxStableFailureRepeats || elapsed_ms >= kTctxSlowFailureMs;
            if (stable_evidence &&
                (!state.have_last_stable_key || !same_tctx_failure_key(state.last_stable_key, key))) {
                state.last_stable_key = key;
                state.have_last_stable_key = true;
                state.distinct_stable_failures++;
            }
            distinct_stable_failures = state.distinct_stable_failures;
            should_arm = distinct_stable_failures >= kTctxDistinctStableFailuresBeforeBypass;
        }
        diag::log_tagged_fmt("driver",
            "tctx_kernel_failure_scoped op=%s pid=%u tid=%u gle=%lu elapsed_ms=%llu failures=%u key_repeats=%u stable_evidence=%d distinct_stable_failures=%u arm_global=%d",
            op ? op : "tctx",
            pid,
            tid,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_ms),
            failures,
            key_repeats,
            stable_evidence ? 1 : 0,
            distinct_stable_failures,
            should_arm ? 1 : 0);
        if (should_arm) {
            arm_tctx_kernel_bypass(op, pid, tid, gle, elapsed_ms, failures, key_repeats, distinct_stable_failures, "distinct_stable_thread_context_failures");
        }
    }
    constexpr int kEventPollerPeriodMs = 250;
    constexpr size_t kEventPollerDrainBatch = 64;

    std::string utf8_from_wstring(const std::wstring& w)
    {
        if (w.empty()) return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    std::string extract_basename_utf8(const std::string& path)
    {
        if (path.empty()) return {};
        size_t slash = path.find_last_of("\\/");
        if (slash == std::string::npos) return path;
        return path.substr(slash + 1);
    }

    void publish_drained_event(const driver_bridge::debug_event_t& evt)
    {
        switch (evt.type) {
            case driver_bridge::debug_event_type_e::image_loaded: {
                aida::events::dll_loaded_t payload{};
                payload.process_id = evt.process_id;
                payload.thread_id = evt.thread_id;
                payload.image_base = evt.image_base;
                payload.image_size = evt.image_size;
                payload.timestamp = evt.timestamp;
                payload.flags = evt.flags;
                payload.image_path = evt.image_path;
                payload.image_name = evt.image_name;
                aida::events::publish(aida::events::event_dll_loaded, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::process_created: {
                aida::events::process_created_t payload{};
                payload.process_id = evt.process_id;
                payload.timestamp = evt.timestamp;
                payload.image_path = evt.image_path;
                payload.image_name = evt.image_name;
                aida::events::publish(aida::events::event_process_created, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::process_exited: {
                aida::events::process_exited_t payload{};
                payload.process_id = evt.process_id;
                payload.timestamp = evt.timestamp;
                aida::events::publish(aida::events::event_process_exited, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::invalid:
            default:
                break;
        }
    }

    void event_poller_thread(uint64_t epoch)
    {
        diag::log_tagged("driver", "event_poller_thread_entry");
        while (!g_event_poller_stop.load(std::memory_order_acquire) &&
               g_event_poller_epoch.load(std::memory_order_acquire) == epoch) {
            {
                std::unique_lock<std::mutex> wait_lock(g_driver_background_wait_mutex);
                g_driver_background_wait_cv.wait_for(wait_lock,
                    std::chrono::milliseconds(kEventPollerPeriodMs),
                    [epoch]() {
                        return g_event_poller_stop.load(std::memory_order_acquire) ||
                            g_event_poller_epoch.load(std::memory_order_acquire) != epoch;
                    });
            }
            if (g_event_poller_stop.load(std::memory_order_acquire) ||
                g_event_poller_epoch.load(std::memory_order_acquire) != epoch)
                break;

            bool kernel_active = false;
            uint32_t pid_filter = 0;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                kernel_active = g_kernel_mode && device && device->is_connected();
                pid_filter = g_pid;
            }
            if (!kernel_active || pid_filter == 0)
                continue;

            std::vector<driver_bridge::debug_event_t> events;
            driver_bridge::debug_event_stats_t stats{};
            if (!driver_bridge::drain_debug_events(events, kEventPollerDrainBatch, &stats))
                continue;

            if (stats.returned_count == 0 && stats.dropped_since_last_drain == 0)
                continue;

            if (stats.returned_count > 0 || stats.dropped_since_last_drain > 0) {
                aida::events::debug_events_drained_t payload{};
                payload.returned_count = stats.returned_count;
                payload.dropped_since_last_drain = stats.dropped_since_last_drain;
                payload.total_dropped = stats.total_dropped;
                payload.total_published = stats.total_published;
                aida::events::publish(aida::events::event_debug_events_drained, payload);
            }

            for (auto& evt : events) {
                publish_drained_event(evt);
            }
        }
        g_event_poller_running.store(false, std::memory_order_release);
        if (g_event_poller_epoch.load(std::memory_order_acquire) == epoch)
            g_event_poller_started.store(false, std::memory_order_release);
        g_driver_background_wait_cv.notify_all();
        diag::log_tagged("driver", "event_poller_thread_exit");
    }

    void start_event_poller_locked()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("event_poller_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        g_event_poller_stop.store(false, std::memory_order_release);
        const uint64_t epoch = g_event_poller_epoch.load(std::memory_order_acquire);
        bool expected = false;
        if (!g_event_poller_started.compare_exchange_strong(expected, true)) {
            driver_critical_fmt("event_poller_post_skip reason=already_started elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return;
        }
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "runtime_driver";
        sub.label = "driver_event_poller";
        sub.thread_class = "security_loop";
        sub.domain = aida::infra::executor::domain_t::security_liveness;
        sub.priority = 0;
        sub.generation = epoch;
        sub.body = [epoch]() {
            g_event_poller_running.store(true, std::memory_order_release);
            driver_critical_fmt("event_poller_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            event_poller_thread(epoch);
            driver_critical_fmt("event_poller_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        };
        bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
        driver_critical_fmt("event_poller_post_post posted=%d elapsed_ms=%llu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!posted) {
            g_event_poller_started.store(false, std::memory_order_release);
            diag::log_tagged("driver", "event_poller_post_failed");
        }
    }

    std::string utf8_from_wide(const wchar_t* text)
    {
        if (!text || !*text)
            return {};
        char narrow[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, text, -1, narrow, sizeof(narrow), nullptr, nullptr);
        return narrow;
    }

    bool refresh_process_name_locked()
    {
        g_process_name.clear();
        if (!g_process)
            return false;

        wchar_t path[MAX_PATH] = {};
        DWORD len = static_cast<DWORD>(std::size(path));
        if (QueryFullProcessImageNameW(g_process, 0, path, &len) && len > 0) {
            std::wstring full(path, path + len);
            auto slash = full.find_last_of(L"\\/");
            g_process_name = utf8_from_wide(slash == std::wstring::npos ? full.c_str() : full.c_str() + slash + 1);
            return true;
        }
        return false;
    }

    std::string process_name_from_pid(uint32_t pid)
    {
        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return {};

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return {};

        do {
            if (pe.th32ProcessID == pid)
                return utf8_from_wide(pe.szExeFile);
        } while (Process32NextW(snapshot.get(), &pe));

        return {};
    }

    void close_process_handle_locked()
    {
        if (g_process) {
            CloseHandle(g_process);
            g_process = nullptr;
        }
    }

    bool same_live_identity(const driver_bridge::identity::live_target_identity_t& lhs,
                            const driver_bridge::identity::live_target_identity_t& rhs)
    {
        return lhs.process.pid == rhs.process.pid &&
            lhs.process.creation_time_100ns == rhs.process.creation_time_100ns &&
            lhs.process.normalized_process_path == rhs.process.normalized_process_path &&
            lhs.module.base == rhs.module.base &&
            lhs.module.size == rhs.module.size &&
            lhs.module.normalized_name == rhs.module.normalized_name &&
            lhs.module.normalized_path == rhs.module.normalized_path;
    }

    std::string to_lower_copy(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }
}

namespace driver_bridge
{
    bool refresh_kernel_context_locked(std::unique_lock<std::mutex>& lk, uint32_t pid, process_ctx_t& ctx, const char* op = "refresh");

    scoped_remote_call_context_t::scoped_remote_call_context_t(const remote_call_context_t& context)
        : previous_(g_remote_call_context_tls)
        , previous_active_(g_remote_call_context_active_tls)
        , active_(true)
    {
        g_remote_call_context_tls = context;
        g_remote_call_context_active_tls = true;
    }

    scoped_remote_call_context_t::~scoped_remote_call_context_t()
    {
        if (!active_)
            return;
        if (previous_active_) {
            g_remote_call_context_tls = previous_;
            g_remote_call_context_active_tls = true;
        } else {
            g_remote_call_context_tls = {};
            g_remote_call_context_active_tls = false;
        }
        active_ = false;
    }

    const char* current_remote_call_label() noexcept
    {
        return capture_remote_call_snapshot().label;
    }

    const char* current_remote_call_tool_name() noexcept
    {
        return capture_remote_call_snapshot().tool;
    }

    const char* current_remote_call_diag_id() noexcept
    {
        return capture_remote_call_snapshot().diag_id;
    }

    uint32_t current_remote_call_pid() noexcept
    {
        return capture_remote_call_snapshot().pid;
    }

    uint32_t current_remote_call_timeout_ms() noexcept
    {
        return capture_remote_call_snapshot().timeout_ms;
    }

    uint64_t current_remote_call_deadline_ms() noexcept
    {
        return capture_remote_call_snapshot().deadline_ms;
    }

    bool current_remote_call_cancelled() noexcept
    {
        return capture_remote_call_snapshot().cancelled;
    }

    remote_call_execution_diag_t last_remote_call_execution_diag()
    {
        return g_last_remote_call_execution_diag;
    }

    bool lower_remote_call_last_abandoned() noexcept
    {
        return g_lower_remote_call_last_abandoned.load(std::memory_order_acquire);
    }

    namespace detail {
        uint32_t remote_call_um_inflight_count_global() noexcept
        {
            return g_remote_call_lower_inflight.load(std::memory_order_acquire);
        }

        uint32_t remote_call_um_abandoned_count_global() noexcept
        {
            return g_lower_remote_call_last_abandoned.load(std::memory_order_acquire) ? 1u : 0u;
        }
    }

    void set_log_callback(log_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_log_fn = std::move(fn);
    }

    void set_confirm_callback(confirm_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_confirm_fn = std::move(fn);
    }

    void add_pre_detach_callback(pre_detach_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_pre_detach_hooks.push_back(std::move(fn));
    }

    void debug_log(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        logf("%s", buf);
    }

    void shutdown(const char* reason)
    {
        const char* reason_text = (reason && *reason) ? reason : "shutdown";
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        uint32_t active_pid = 0;
        size_t attached_count = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            active_pid = g_pid;
            attached_count = g_processes.size();
            driver_critical_fmt(
                "shutdown_begin reason=%s initialized=%d kernel=%d connected=%d active_pid=%u attached=%llu watchdog_started=%d watchdog_stop=%d event_started=%d event_stop=%d tid=%lu",
                reason_text,
                g_initialized ? 1 : 0,
                g_kernel_mode ? 1 : 0,
                (device && device->is_connected()) ? 1 : 0,
                active_pid,
                static_cast<unsigned long long>(attached_count),
                g_driver_watchdog_started.load(std::memory_order_acquire) ? 1 : 0,
                g_driver_watchdog_stop.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_started.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_stop.load(std::memory_order_acquire) ? 1 : 0,
                GetCurrentThreadId());
            g_driver_watchdog_stop.store(true, std::memory_order_release);
            g_event_poller_stop.store(true, std::memory_order_release);
            g_driver_watchdog_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_event_poller_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_driver_consecutive_fail.store(0, std::memory_order_release);
            g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        }

        g_driver_background_wait_cv.notify_all();
        {
            std::unique_lock<std::mutex> wait_lock(g_driver_background_wait_mutex);
            const bool drained = g_driver_background_wait_cv.wait_for(wait_lock,
                std::chrono::milliseconds(5000), []() {
                    return !g_driver_watchdog_running.load(std::memory_order_acquire) &&
                        !g_event_poller_running.load(std::memory_order_acquire);
                });
            driver_critical_fmt(
                "shutdown_background_drain drained=%d watchdog_started=%d watchdog_running=%d event_started=%d event_running=%d elapsed_ms=%llu tid=%lu",
                drained ? 1 : 0,
                g_driver_watchdog_started.load(std::memory_order_acquire) ? 1 : 0,
                g_driver_watchdog_running.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_started.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_running.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                GetCurrentThreadId());
            if (drained) {
                g_driver_watchdog_started.store(false, std::memory_order_release);
                g_event_poller_started.store(false, std::memory_order_release);
            }
        }

        stop_lower_remote_call_executor(reason_text, 2500);

        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            if (g_kernel_mode && device && device->is_connected())
                device->clear_process_context();
            close_process_handle_locked();
            for (auto& kv : g_processes)
                release_ctx_handle(kv.second);
            g_processes.clear();
            g_pid = 0;
            g_primary_pid = 0;
            g_pid_snapshot.store(0, std::memory_order_release);
            g_process_name.clear();
            g_has_vm_read = false;
            g_kernel_attached = false;
            g_kernel_mode = false;
            g_initialized = false;
            bool disconnect_attempted = device != nullptr;
            bool disconnect_connected_before = device && device->is_connected();
            if (device)
                device->disconnect();
            bool disconnect_connected_after = device && device->is_connected();
            set_last_error_locked({});
            driver_critical_fmt(
                "shutdown_done reason=%s disconnect_attempted=%d connected_before=%d connected_after=%d elapsed_ms=%llu tid=%lu",
                reason_text,
                disconnect_attempted ? 1 : 0,
                disconnect_connected_before ? 1 : 0,
                disconnect_connected_after ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                GetCurrentThreadId());
        }
    }

    bool initialize()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("initialize_enter pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        std::lock_guard<std::mutex> lk(g_state_mtx);
        driver_critical_fmt("initialize_state initialized=%d kernel=%d elapsed_ms=%llu",
            g_initialized ? 1 : 0,
            g_kernel_mode ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (g_initialized)
        {
            driver_critical_fmt("initialize_exit reason=already_initialized kernel=%d elapsed_ms=%llu",
                g_kernel_mode ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return true;
        }

        g_remote_call_lower_executor_stop.store(false, std::memory_order_release);
        g_kernel_mode = false;
        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        clear_last_error_locked_after_success("initialize_reset");

        driver_critical_fmt("initialize_connect_existing_pre device=%d elapsed_ms=%llu",
            device ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device && device->connect()) {
            driver_critical_fmt("initialize_connect_existing_post ok=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("driver", "connected to existing driver instance, skipping mapper");
            driver_loader::mark_already_loaded();
            g_kernel_mode = true;
            g_initialized = true;
            logf("AiDA Standalone: Connected to already-loaded driver (reuse, no remap).\n");
            start_driver_watchdog_locked();
            start_event_poller_locked();
            driver_critical_fmt("initialize_exit reason=existing_driver ok=1 kernel=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            prestart_lower_remote_call_executor_state_known("initialize_existing_driver",
                                                            started,
                                                            g_pid,
                                                            g_active_pid_generation.load(std::memory_order_acquire),
                                                            true);
            return true;
        }
        DWORD existing_connect_err = device ? device->get_last_connect_error() : GetLastError();
        driver_critical_fmt("initialize_connect_existing_post ok=0 err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(existing_connect_err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));

        const bool existing_driver_unreachable =
            existing_connect_err == 433u ||
            existing_connect_err == ERROR_ACCESS_DENIED;
        if (device && existing_driver_unreachable) {
            for (int attempt = 1; attempt <= 3; ++attempt) {
                Sleep(300);
                driver_critical_fmt("initialize_existing_driver_retry_pre attempt=%d err=%lu elapsed_ms=%llu",
                    attempt,
                    static_cast<unsigned long>(device->get_last_connect_error()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                if (device->connect()) {
                    driver_critical_fmt("initialize_existing_driver_retry_post attempt=%d ok=1 elapsed_ms=%llu",
                        attempt,
                        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                    diag::log_tagged_fmt("driver", "connected to existing driver instance after guarded retry, skipping mapper");
                    driver_loader::mark_already_loaded();
                    g_kernel_mode = true;
                    g_initialized = true;
                    logf("AiDA Standalone: Connected to already-loaded driver after guarded retry.\n");
                    start_driver_watchdog_locked();
                    start_event_poller_locked();
                    driver_critical_fmt("initialize_exit reason=existing_driver_retry ok=1 kernel=1 elapsed_ms=%llu",
                        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                    prestart_lower_remote_call_executor_state_known("initialize_existing_driver_retry",
                                                                    started,
                                                                    g_pid,
                                                                    g_active_pid_generation.load(std::memory_order_acquire),
                                                                    true);
                    return true;
                }
                driver_critical_fmt("initialize_existing_driver_retry_post attempt=%d ok=0 err=%lu elapsed_ms=%llu",
                    attempt,
                    static_cast<unsigned long>(device->get_last_connect_error()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            }
            DWORD guarded_err = device->get_last_connect_error();
            driver_critical_fmt("initialize_exit reason=existing_driver_unreachable_no_remap err=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(guarded_err),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return driver_startup_fail_closed("initialize_existing_driver_unreachable_no_remap", guarded_err);
        }

        driver_critical_fmt("initialize_loader_pre elapsed_ms=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        bool loader_ok = driver_loader::initialize_and_load();
        const std::string loader_error_after_load = driver_loader::last_error();
        driver_critical_fmt("initialize_loader_post ok=%d elapsed_ms=%llu loader_error_hash=0x%016llX",
            loader_ok ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long long>(driver_fnv1a64(loader_error_after_load.data(), loader_error_after_load.size())));
        diag::log_tagged_fmt("driver", "loader_initialize_result=%d", loader_ok ? 1 : 0);
        if (!loader_ok) {
            const std::string loader_error = loader_error_after_load;
            diag::log_tagged_critical_fmt("driver", "loader_last_error=\"%s\"",
                loader_error.empty() ? "<empty>" : loader_error.c_str());
            driver_critical_fmt("initialize_loader_failed_connect_retry_pre elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            if (device && device->connect()) {
                driver_critical_fmt("initialize_loader_failed_connect_retry_post ok=1 elapsed_ms=%llu",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("driver", "loader_failed_but_driver_connect_ok");
                driver_loader::mark_already_loaded();
                g_kernel_mode = true;
                g_initialized = true;
                logf("AiDA Standalone: Mapper reported failure after load, but kernel driver backend is reachable.\n");
                start_driver_watchdog_locked();
                start_event_poller_locked();
                driver_critical_fmt("initialize_exit reason=loader_failed_but_connect_ok ok=1 kernel=1 elapsed_ms=%llu",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                prestart_lower_remote_call_executor_state_known("initialize_loader_failed_connect_retry",
                                                                started,
                                                                g_pid,
                                                                g_active_pid_generation.load(std::memory_order_acquire),
                                                                true);
                return true;
            }
            driver_critical_fmt("initialize_loader_failed_connect_retry_post ok=0 err=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(device ? device->get_last_connect_error() : GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return driver_startup_fail_closed("initialize_loader", ERROR_BAD_DRIVER);
        }

        driver_critical_fmt("initialize_connect_after_loader_pre elapsed_ms=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device && device->connect()) {
            driver_critical_fmt("initialize_connect_after_loader_post ok=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            g_kernel_mode = true;
            g_initialized = true;
            logf("AiDA Standalone: Live inspection bridge initialized with kernel driver backend.\n");
            start_driver_watchdog_locked();
            start_event_poller_locked();
            driver_critical_fmt("initialize_exit reason=loaded_connect_ok ok=1 kernel=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            prestart_lower_remote_call_executor_state_known("initialize_connect_after_loader",
                                                            started,
                                                            g_pid,
                                                            g_active_pid_generation.load(std::memory_order_acquire),
                                                            true);
            return true;
        }

        DWORD err = device ? device->get_last_connect_error() : 0xFFFFFFFFu;
        driver_critical_fmt("initialize_connect_after_loader_post ok=0 err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device) {
            logf("AiDA Standalone: Kernel driver connection failed (error 0x%08X).\n", err);
        }

        driver_critical_fmt("initialize_exit reason=connect_failed err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return driver_startup_fail_closed("initialize", err);
    }

    bool load_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_kernel_mode && device && device->is_connected())
            return true;

        if (device && device->connect()) {
            driver_loader::mark_already_loaded();
            g_kernel_mode = true;
            g_initialized = true;
            g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
            start_driver_watchdog_locked();
            start_event_poller_locked();
            return true;
        }

        if (device) {
            DWORD existing_connect_err = device->get_last_connect_error();
            const bool existing_driver_unreachable =
                existing_connect_err == 433u ||
                existing_connect_err == ERROR_ACCESS_DENIED;
            if (existing_driver_unreachable) {
                for (int attempt = 1; attempt <= 3; ++attempt) {
                    Sleep(300);
                    driver_critical_fmt("load_kernel_driver_existing_retry_pre attempt=%d err=%lu",
                        attempt,
                        static_cast<unsigned long>(device->get_last_connect_error()));
                    if (device->connect()) {
                        driver_loader::mark_already_loaded();
                        g_kernel_mode = true;
                        g_initialized = true;
                        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
                        start_driver_watchdog_locked();
                        start_event_poller_locked();
                        driver_critical_fmt("load_kernel_driver_existing_retry_post attempt=%d ok=1",
                            attempt);
                        return true;
                    }
                    driver_critical_fmt("load_kernel_driver_existing_retry_post attempt=%d ok=0 err=%lu",
                        attempt,
                        static_cast<unsigned long>(device->get_last_connect_error()));
                }
                DWORD guarded_err = device->get_last_connect_error();
                driver_critical_fmt("load_kernel_driver_no_remap_existing_unreachable err=%lu",
                    static_cast<unsigned long>(guarded_err));
                return driver_startup_fail_closed("load_kernel_driver_existing_unreachable_no_remap", guarded_err);
            }
        }

        bool loader_ok = driver_loader::initialize_and_load();
        const std::string loader_error = driver_loader::last_error();
        diag::log_tagged_fmt("driver", "load_kernel_driver loader_initialize_result=%d", loader_ok ? 1 : 0);
        if (!loader_ok) {
            diag::log_tagged_critical_fmt("driver", "load_kernel_driver loader_last_error=\"%s\"",
                loader_error.empty() ? "<empty>" : loader_error.c_str());
        }

        if (!device || !device->connect()) {
            DWORD err = device ? device->get_last_connect_error() : 0xFFFFFFFFu;
            char buf[256];
            if (err == 0xFFFFFFFFu) {
                snprintf(buf, sizeof(buf), "Failed to connect to the kernel driver (device object is null).");
            } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                snprintf(buf, sizeof(buf),
                    "Driver device not found (error %lu). "
                    "The kernel driver may not be loaded.",
                    (unsigned long)err);
            } else if (err == ERROR_ACCESS_DENIED) {
                snprintf(buf, sizeof(buf),
                    "Access denied opening driver device. "
                    "Run AiDA as Administrator.");
            } else {
                snprintf(buf, sizeof(buf),
                    "Failed to connect to the kernel driver (error 0x%08X).",
                    err);
            }
            std::string reconnect_error = buf;
            if (!loader_error.empty())
                reconnect_error += " Loader error: " + loader_error;
            set_last_error_locked(reconnect_error);
            logf("AiDA Standalone: %s\n", buf);
            return false;
        }

        g_kernel_mode = true;
        g_initialized = true;
        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        clear_last_error_locked_after_success("load_kernel_driver");
        logf("AiDA Standalone: Kernel driver backend is active.\n");
        start_driver_watchdog_locked();
        start_event_poller_locked();
        return true;
    }

    bool is_loaded()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_initialized;
    }

    bool using_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_kernel_mode && device && device->is_connected();
    }

    availability_t availability()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        availability_t result;
        result.initialized = g_initialized;
        result.kernel_backend = g_kernel_mode;
        result.device_connected = device && device->is_connected();
        result.target_attached = g_pid != 0 && g_kernel_attached;
        result.target_pid = g_pid;
        result.detail = g_last_error;

        if (!result.initialized) {
            result.state = "not_initialized";
            result.reason = "kernel_session_not_initialized";
        } else if (!result.kernel_backend) {
            result.state = "unavailable";
            result.reason = "kernel_driver_degraded";
        } else if (!result.device_connected) {
            result.state = "unavailable";
            result.reason = "kernel_device_disconnected";
        } else if (result.target_pid == 0) {
            result.state = "ready_no_target";
            result.reason = "no_process_attached";
        } else if (!result.target_attached) {
            result.state = "target_unavailable";
            result.reason = "target_not_attached";
        } else {
            result.state = "ready";
        }
        return result;
    }

    bool kernel_session_available(std::string* reason)
    {
        bool initialized = false;
        bool kernel_mode = false;
        bool connected = false;
        std::string last_error_copy;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            initialized = g_initialized;
            kernel_mode = g_kernel_mode;
            connected = device && device->is_connected();
            last_error_copy = g_last_error;
        }

        auto set_reason = [&](const char* value) {
            if (reason)
                *reason = value ? value : "kernel_session_unavailable";
        };

        if (!initialized) {
            set_reason("kernel_session_not_initialized");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_session_not_initialized kernel=%d connected=%d last_error='%.160s'",
                kernel_mode ? 1 : 0,
                connected ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }
        if (!kernel_mode) {
            set_reason("kernel_driver_degraded");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_driver_degraded initialized=%d connected=%d last_error='%.160s'",
                initialized ? 1 : 0,
                connected ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }
        if (!connected) {
            set_reason("kernel_device_disconnected");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_device_disconnected initialized=%d kernel=%d last_error='%.160s'",
                initialized ? 1 : 0,
                kernel_mode ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }

        if (reason)
            reason->clear();
        return true;
    }

    bool can_read_memory()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_pid != 0 && g_kernel_attached && g_kernel_mode && device && device->is_connected();
    }

    bool attach(uint32_t pid)
    {
        diag::log_tagged_critical_fmt("driver", "attach_enter pid=%u tid=%lu", pid, GetCurrentThreadId());

        if (pid == static_cast<uint32_t>(GetCurrentProcessId())) {
            diag::log_tagged_critical("driver", "attach_REJECTED_self_pid");
            return false;
        }

        diag::log_tagged_critical("driver", "attach_pre_state_mtx_lock");
        std::unique_lock<std::mutex> lk(g_state_mtx);
        diag::log_tagged_critical("driver", "attach_post_state_mtx_lock");

        constexpr DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
        diag::log_tagged_critical_fmt("driver", "attach_pre_OpenProcess access=0x%X pid=%u", access, pid);
        unique_handle process(OpenProcess(access, FALSE, pid));
        diag::log_tagged_critical_fmt("driver", "attach_post_OpenProcess handle=%p gle=%lu",
            process.get(), process ? 0UL : GetLastError());
        if (!process) {
            set_last_error_locked("OpenProcess query failed for PID " + std::to_string(pid) +
                                  " (error " + std::to_string(GetLastError()) + ")");
            return false;
        }

        bool kernel_ok = g_kernel_mode && device && device->is_connected();
        diag::log_tagged_critical_fmt("driver", "attach_kernel_check kernel_mode=%d device=%p connected=%d kernel_ok=%d",
            g_kernel_mode ? 1 : 0, device.get(),
            (device && device->is_connected()) ? 1 : 0,
            kernel_ok ? 1 : 0);
        if (!kernel_ok) {
            require_kernel_fail("attach");
            set_last_error_locked("attach requires WhosWho kernel driver for PID " + std::to_string(pid));
            return false;
        }

        diag::log_tagged_critical("driver", "attach_pre_set_process_id");
        if (!device->set_process_id(pid)) {
            set_last_error_locked("WhosWho failed to bind PID " + std::to_string(pid));
            return false;
        }

        close_process_handle_locked();
        g_process = process.release();
        g_pid = pid;
        g_primary_pid = pid;
        g_pid_snapshot.store(pid, std::memory_order_release);
        const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (!refresh_process_name_locked())
            g_process_name = process_name_from_pid(pid);

        {
            auto it = g_processes.find(pid);
            if (it != g_processes.end()) {
                release_ctx_handle(it->second);
                g_processes.erase(it);
            }
        }

        diag::log_tagged_critical("driver", "attach_post_set_process_id");

        {
            diag::log_tagged_critical("driver", "attach_pre_device_solve_dtb_fallback");
            device->solve_dtb();
            diag::log_tagged_critical_fmt("driver", "attach_post_device_solve_dtb_fallback dtb=0x%llX",
                (unsigned long long)device->get_dtb());
            if (device->get_dtb() == 0) {
                diag::log_tagged_critical_fmt("driver",
                    "attach_device_solve_dtb_zero connected=%d",
                    device->is_connected() ? 1 : 0);
                const bool context_cleared = device->clear_process_context();
                close_process_handle_locked();
                g_pid = 0;
                g_pid_snapshot.store(0, std::memory_order_release);
                g_primary_pid = 0;
                g_process_name.clear();
                g_has_vm_read = false;
                g_kernel_attached = false;
                device->set_dtb(0);
                device->set_kernel_dtb(0);
                device->set_base_address(0);
                set_last_error_locked(std::string("WhosWho failed to resolve DTB for PID ") +
                    std::to_string(pid) + (context_cleared ? "" : "; allocation release failed"));
                return false;
            }
            diag::log_tagged_critical("driver", "attach_pre_device_find_image_fallback");
            const auto image_base = device->find_image();
            diag::log_tagged_critical_fmt("driver", "attach_post_device_find_image_fallback base=0x%llX",
                (unsigned long long)image_base);
            if (image_base != 0)
                device->set_base_address(image_base);
        }

        g_kernel_attached = true;
        diag::log_tagged_critical("driver", "attach_pre_solve_kernel_dtb");
        device->solve_kernel_dtb();
        diag::log_tagged_critical_fmt("driver", "attach_post_solve_kernel_dtb kdtb=0x%llX",
            (unsigned long long)device->get_kernel_dtb());
        if (device->get_kernel_dtb() != 0) {
            logf("AiDA Standalone: Kernel DTB solved: 0x%llX\n",
                 static_cast<unsigned long long>(device->get_kernel_dtb()));
        }

        clear_last_error_locked_after_success("attach");
        logf("AiDA Standalone: Attached to PID %u (%s) via kernel driver. DTB=0x%llX\n",
             g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str(),
             static_cast<unsigned long long>(device->get_dtb()));

        process_ctx_t ctx;
        ctx.h_process = nullptr;
        ctx.kernel_attached = g_kernel_attached;
        ctx.has_vm_read = false;
        ctx.name = g_process_name;
        diag::log_tagged_critical("driver", "attach_pre_ctx_cached_find_image");
        ctx.cached_image_base = device->find_image();
        diag::log_tagged_critical_fmt("driver", "attach_post_ctx_cached_find_image base=0x%llX",
            static_cast<unsigned long long>(ctx.cached_image_base));
        ctx.cached_dtb = device->get_dtb();
        ctx.cached_kernel_dtb = device->get_kernel_dtb();
        g_processes[pid] = std::move(ctx);

        diag::log_tagged_critical_fmt("driver", "attach_exit_ok pid=%u kernel_ok=1 has_vm_read=0", pid);
        prestart_lower_remote_call_executor_state_known("attach", GetTickCount64(), pid, active_generation, true);
        return true;
    }

    bool attach_by_name(const std::string& process_name)
    {
        uint32_t kernel_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            if (g_kernel_mode && device && device->is_connected()) {
                kernel_pid = device->find_process(process_name.c_str());
            }
        }
        if (kernel_pid != 0)
            return attach(kernel_pid);

        auto lowered = to_lower_copy(process_name);
        for (const auto& proc : enumerate_processes()) {
            if (to_lower_copy(proc.name) == lowered)
                return attach(proc.pid);
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        set_last_error_locked("Process not found: " + process_name);
        return false;
    }

    void detach()
    {


        {
            std::lock_guard<std::mutex> lk(g_callback_mtx);
            for (auto& hook : g_pre_detach_hooks) {
                if (hook) hook();
            }
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        uint32_t prev_pid = g_pid;
        if (g_kernel_mode && device && device->is_connected() && !device->clear_process_context()) {
            set_last_error_locked("WhosWho failed to release active process allocation");
            return;
        }
        close_process_handle_locked();
        g_pid = 0;
        g_primary_pid = 0;
        g_pid_snapshot.store(0, std::memory_order_release);
        const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_process_name.clear();
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (prev_pid != 0) {
            auto it = g_processes.find(prev_pid);
            if (it != g_processes.end()) {
                release_ctx_handle(it->second);
                g_processes.erase(it);
            }
        }
        clear_last_error_locked_after_success("detach");
        diag::log_tagged_fmt("driver", "detach_done previous_pid=%u active_generation=%llu", prev_pid, static_cast<unsigned long long>(active_generation));
    }

    bool attach_additional(uint32_t pid)
    {
        if (pid == 0)
            return false;
        if (pid == static_cast<uint32_t>(GetCurrentProcessId()))
            return false;

        const DWORD caller_tid = GetCurrentThreadId();
        const ULONGLONG attach_additional_entry_tick = GetTickCount64();

        std::unique_lock<std::mutex> lk(g_state_mtx);
        if (g_processes.find(pid) != g_processes.end()) {
            clear_last_error_locked_after_success("attach_additional_existing");
            diag::log_tagged_fmt("driver",
                "attach_additional_existing pid=%u current_g_pid=%u caller_tid=%lu entry_tick=%llu",
                pid,
                g_pid,
                static_cast<unsigned long>(caller_tid),
                static_cast<unsigned long long>(attach_additional_entry_tick));
            return true;
        }

        if (!g_kernel_mode || !device || !device->is_connected()) {
            require_kernel_fail("attach_additional");
            set_last_error_locked("attach_additional requires WhosWho kernel driver for PID " + std::to_string(pid));
            return false;
        }

        const uint32_t bind_before_pid = g_pid;
        const uint32_t inflight_before = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        const uint32_t queue_depth_before = g_remote_call_lower_queue_depth.load(std::memory_order_acquire);
        const DWORD worker_tid_before = g_remote_call_lower_worker_tid.load(std::memory_order_acquire);
        diag::log_tagged_fmt("driver",
            "attach_additional_enter pid=%u from_pid=%u inflight=%u queue_depth=%u worker_tid=%lu caller_tid=%lu entry_tick=%llu",
            pid,
            bind_before_pid,
            inflight_before,
            queue_depth_before,
            static_cast<unsigned long>(worker_tid_before),
            static_cast<unsigned long>(caller_tid),
            static_cast<unsigned long long>(attach_additional_entry_tick));

        if (bind_before_pid != 0 && bind_before_pid != pid &&
            (inflight_before != 0 || queue_depth_before != 0)) {
            lk.unlock();
            lower_remote_call_drain_result_t drain =
                wait_lower_remote_call_drain_for_pid_switch(bind_before_pid, pid, "attach_additional", kAttachAdditionalDrainTimeoutMs);
            lk.lock();
            if (!drain.drained) {
                set_last_error_locked("attach_additional: lower remote call drain failed from pid " +
                    std::to_string(bind_before_pid) + " to pid " + std::to_string(pid) +
                    " queue_depth=" + std::to_string(drain.queue_depth) +
                    " inflight=" + std::to_string(drain.inflight));
                diag::log_tagged_fmt("driver",
                    "attach_additional_drain_reject pid=%u from_pid=%u queue_depth=%u inflight=%u worker_alive=%u worker_tid=%lu caller_tid=%lu elapsed_ms=%lu last_error=%s",
                    pid,
                    bind_before_pid,
                    drain.queue_depth,
                    drain.inflight,
                    drain.worker_alive,
                    static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(caller_tid),
                    static_cast<unsigned long>(drain.elapsed_ms),
                    g_last_error.c_str());
                return false;
            }
            if (g_processes.find(pid) != g_processes.end()) {
                clear_last_error_locked_after_success("attach_additional_existing_after_drain");
                diag::log_tagged_fmt("driver",
                    "attach_additional_existing_after_drain pid=%u current_g_pid=%u drain_elapsed_ms=%lu",
                    pid,
                    g_pid,
                    static_cast<unsigned long>(drain.elapsed_ms));
                return true;
            }
        }

        constexpr DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
        unique_handle process(OpenProcess(access, FALSE, pid));
        if (!process) {
            set_last_error_locked("OpenProcess query failed for PID " + std::to_string(pid) +
                                  " (error " + std::to_string(GetLastError()) + ")");
            return false;
        }

        process_ctx_t ctx;
        ctx.h_process = process.release();
        ctx.has_vm_read = false;
        ctx.kernel_attached = false;
        ctx.name = process_name_from_pid(pid);
        ctx.cached_image_base = 0;
        ctx.cached_dtb = 0;
        ctx.cached_kernel_dtb = 0;
        if (!refresh_kernel_context_locked(lk, pid, ctx, "attach_additional")) {
            release_ctx_handle(ctx);
            set_last_error_locked("WhosWho failed to attach additional PID " + std::to_string(pid));
            diag::log_tagged_fmt("driver",
                "attach_additional_reject pid=%u reason=dtb_unresolved current_g_pid=%u inflight=%u caller_tid=%lu elapsed_ms=%llu",
                pid,
                g_pid,
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long>(caller_tid),
                static_cast<unsigned long long>(GetTickCount64() - attach_additional_entry_tick));
            return false;
        }
        g_processes[pid] = std::move(ctx);

        diag::log_tagged_fmt("driver",
            "attach_additional_ok pid=%u kernel_attached=1 has_vm_read=0 current_g_pid=%u caller_tid=%lu elapsed_ms=%llu",
            pid,
            g_pid,
            static_cast<unsigned long>(caller_tid),
            static_cast<unsigned long long>(GetTickCount64() - attach_additional_entry_tick));
        clear_last_error_locked_after_success("attach_additional");
        return true;
    }

    bool refresh_kernel_context_locked(std::unique_lock<std::mutex>& lk, uint32_t pid, process_ctx_t& ctx, const char* op)
    {
        if (!g_kernel_mode || !device || !device->is_connected()) {
            ctx.kernel_attached = false;
            return false;
        }

        const char* op_label = (op && op[0]) ? op : "refresh";
        const DWORD caller_tid = GetCurrentThreadId();
        const uint64_t dtb_before = device->get_dtb();
        const uint64_t kernel_dtb_before = device->get_kernel_dtb();
        const uint64_t base_before = device->get_base_address();
        const std::uint32_t device_pid_before = device->get_process_id();
        const uint32_t inflight_pre = g_remote_call_lower_inflight.load(std::memory_order_acquire);
        diag::log_tagged_fmt("driver",
            "refresh_kernel_context_pre op=%s pid=%u current_g_pid=%u device_pid_before=%u dtb_before=0x%llX kernel_dtb_before=0x%llX base_before=0x%llX inflight=%u worker_tid=%lu caller_tid=%lu",
            op_label,
            pid,
            g_pid,
            device_pid_before,
            static_cast<unsigned long long>(dtb_before),
            static_cast<unsigned long long>(kernel_dtb_before),
            static_cast<unsigned long long>(base_before),
            inflight_pre,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            static_cast<unsigned long>(caller_tid));

        if (inflight_pre > 0 && g_lower_remote_call_last_abandoned.load(std::memory_order_acquire)) {
            const ULONGLONG drain_t0 = GetTickCount64();
            constexpr ULONGLONG kAbandonedDrainBudgetMs = 1500;
            uint32_t inflight_during = inflight_pre;
            uint32_t inflight_global_prev = inflight_pre;
            ULONGLONG drain_elapsed = 0;
            while (true) {
                const uint32_t inflight_global_now = driver_bridge::detail::remote_call_um_inflight_count_global();
                if (inflight_global_now != inflight_global_prev) {
                    diag::log_tagged_fmt("driver",
                        "refresh_kernel_context_global_inflight_observed op=%s trigger_pid=%u prev_global=%u current_global=%u drain_elapsed_ms=%llu reason=poll_lower_remote_call_drain scope=global worker_tid=%lu caller_tid=%lu",
                        op_label,
                        pid,
                        inflight_global_prev,
                        inflight_global_now,
                        static_cast<unsigned long long>(GetTickCount64() - drain_t0),
                        static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                        static_cast<unsigned long>(caller_tid));
                    inflight_global_prev = inflight_global_now;
                }
                inflight_during = inflight_global_now;
                if (inflight_during == 0)
                    break;
                drain_elapsed = GetTickCount64() - drain_t0;
                if (drain_elapsed > kAbandonedDrainBudgetMs)
                    break;
                Sleep(25);
            }
            drain_elapsed = GetTickCount64() - drain_t0;
            diag::log_tagged_critical_fmt("driver",
                "refresh_kernel_context_abandoned_drain op=%s pid=%u drain_elapsed_ms=%llu inflight_pre=%u inflight_after=%u budget_ms=%llu scope=global note=counter_is_process_wide_not_per_pid worker_tid=%lu caller_tid=%lu",
                op_label,
                pid,
                static_cast<unsigned long long>(drain_elapsed),
                inflight_pre,
                inflight_during,
                static_cast<unsigned long long>(kAbandonedDrainBudgetMs),
                static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                static_cast<unsigned long>(caller_tid));
            if (inflight_during == 0) {
                g_lower_remote_call_last_abandoned.store(false, std::memory_order_release);
                diag::log_tagged_critical_fmt("driver",
                    "refresh_kernel_context_abandoned_drain_cleared op=%s pid=%u drain_elapsed_ms=%llu reason=global_inflight_reached_zero scope=global caller_tid=%lu",
                    op_label,
                    pid,
                    static_cast<unsigned long long>(drain_elapsed),
                    static_cast<unsigned long>(caller_tid));
            } else {
                const uint32_t abandoned_after = driver_bridge::detail::remote_call_um_abandoned_count_global();
                set_last_error_locked("Kernel context refresh deferred while an abandoned lower remote call is still unwinding (global lower-remote-call counter is process-wide; PID " + std::to_string(pid) + " observed pending inflight on the shared worker)");
                diag::log_tagged_critical_fmt("driver",
                    "refresh_kernel_context_deferred_unwinding op=%s pid=%u reason=lower_remote_uninterruptible_abandoned inflight_pre=%u inflight_after=%u abandoned_count=%u abandoned_scope=global drain_elapsed_ms=%llu note=global_counter_blocks_active_pid_refresh worker_tid=%lu caller_tid=%lu",
                    op_label,
                    pid,
                    inflight_pre,
                    inflight_during,
                    abandoned_after,
                    static_cast<unsigned long long>(drain_elapsed),
                    static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(caller_tid));
                return false;
            }
        }

        if (device_pid_before != pid) {
            uint64_t pre_validated_dtb = 0;
            const ULONGLONG pre_validate_start = GetTickCount64();

            for (uint32_t pre_attempt = 0; pre_attempt < 10 && pre_validated_dtb == 0; ++pre_attempt) {
                if (pre_attempt > 0)
                    Sleep(25);
                pre_validated_dtb = device->solve_dtb_for_pid(pid);
            }

            const ULONGLONG pre_validate_elapsed = GetTickCount64() - pre_validate_start;
            const DWORD pre_validate_gle = GetLastError();

            diag::log_tagged_critical_fmt("driver",
                "refresh_kernel_context_pre_validate op=%s pid=%u pre_dtb=0x%llX pre_validate_elapsed_ms=%llu pre_validate_gle=%lu device_pid_before=%u device_pid_preserved=1",
                op_label,
                pid,
                static_cast<unsigned long long>(pre_validated_dtb),
                static_cast<unsigned long long>(pre_validate_elapsed),
                static_cast<unsigned long>(pre_validate_gle),
                device_pid_before);

            if (pre_validated_dtb == 0) {
                ctx.kernel_attached = false;
                ctx.cached_dtb = 0;
                diag::log_tagged_critical_fmt("driver",
                    "refresh_kernel_context_pre_validate_failed op=%s pid=%u device_pid_before=%u device_pid_preserved=1 dtb=0 reason=pre_validation_failed caller_tid=%lu",
                    op_label,
                    pid,
                    device_pid_before,
                    static_cast<unsigned long>(caller_tid));
                return false;
            }

            device->set_dtb(0);
            device->set_kernel_dtb(0);
            device->set_base_address(0);
        }

        if (!device->set_process_id(pid)) {
            if (device_pid_before != 0 && device_pid_before != pid) {
                device->set_process_id(device_pid_before);
                device->set_dtb(dtb_before);
                device->set_kernel_dtb(kernel_dtb_before);
                device->set_base_address(base_before);
            }
            ctx.kernel_attached = false;
            return false;
        }
        diag::log_tagged_fmt("driver",
            "refresh_kernel_context_device_set_pid op=%s pid=%u device_pid_after=%u shellcode_after=0x%llX shellcode_pid_after=%u shellcode_dtb_after=0x%llX",
            op_label,
            pid,
            device->get_process_id(),
            static_cast<unsigned long long>(device->get_shellcode_address_diag()),
            device->get_shellcode_pid_diag(),
            static_cast<unsigned long long>(device->get_shellcode_dtb_at_alloc_diag()));

        const ULONGLONG solve_dtb_start = GetTickCount64();
        device->solve_dtb();
        uint32_t solve_dtb_retries = 0;
        for (uint32_t solve_attempt = 0; solve_attempt < 10 && device->get_dtb() == 0; ++solve_attempt) {
            Sleep(25);
            device->solve_dtb();
            ++solve_dtb_retries;
        }
        diag::log_tagged_critical_fmt("driver",
            "refresh_kernel_context_step op=%s pid=%u step_name=device_solve_dtb elapsed_ms=%llu inflight_at_step=%u retries=%u dtb_after=0x%llX caller_tid=%lu",
            op_label,
            pid,
            static_cast<unsigned long long>(GetTickCount64() - solve_dtb_start),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            solve_dtb_retries,
            static_cast<unsigned long long>(device->get_dtb()),
            static_cast<unsigned long>(caller_tid));
        if (device->get_dtb() == 0 && ctx.cached_dtb != 0)
            device->set_dtb(ctx.cached_dtb);
        if (device->get_dtb() == 0) {
            ctx.kernel_attached = false;
            if (device_pid_before != 0 && device_pid_before != pid) {
                diag::log_tagged_critical_fmt("driver",
                    "refresh_kernel_context_rollback op=%s pid=%u device_pid_before=%u reason=post_switch_dtb_zero rolling_back_to_previous_pid",
                    op_label, pid, device_pid_before);
                device->set_process_id(device_pid_before);
                auto prev_it = g_processes.find(device_pid_before);
                if (prev_it != g_processes.end()) {
                    if (prev_it->second.cached_dtb != 0) {
                        device->set_dtb(prev_it->second.cached_dtb);
                    }
                    if (prev_it->second.cached_kernel_dtb != 0) {
                        device->set_kernel_dtb(prev_it->second.cached_kernel_dtb);
                    }
                    if (prev_it->second.cached_image_base != 0) {
                        device->set_base_address(prev_it->second.cached_image_base);
                    }
                }
            } else {
                device->set_process_id(0);
            }
            diag::log_tagged_fmt("driver",
                "refresh_kernel_context_post op=%s pid=%u dtb_before=0x%llX dtb_after=0x0 kernel_dtb_after=0x0 base_after=0x0 kernel_attached=0 cached_dtb=0x%llX inflight_after=%u caller_tid=%lu rolled_back_pid=%u",
                op_label,
                pid,
                static_cast<unsigned long long>(dtb_before),
                static_cast<unsigned long long>(ctx.cached_dtb),
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long>(caller_tid),
                device_pid_before);
            return false;
        }

        ctx.kernel_attached = true;
        ctx.cached_dtb = device->get_dtb();

        if (ctx.cached_image_base == 0) {
            const ULONGLONG find_image_start = GetTickCount64();
            ctx.cached_image_base = device->find_image();
            diag::log_tagged_critical_fmt("driver",
                "refresh_kernel_context_step op=%s pid=%u step_name=device_find_image elapsed_ms=%llu inflight_at_step=%u caller_tid=%lu",
                op_label,
                pid,
                static_cast<unsigned long long>(GetTickCount64() - find_image_start),
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long>(caller_tid));
        }
        if (ctx.cached_image_base != 0) {
            device->set_base_address(ctx.cached_image_base);
        }

        if (ctx.cached_kernel_dtb != 0) {
            device->set_kernel_dtb(ctx.cached_kernel_dtb);
        } else {
            const ULONGLONG solve_kernel_dtb_start = GetTickCount64();
            device->solve_kernel_dtb();
            diag::log_tagged_critical_fmt("driver",
                "refresh_kernel_context_step op=%s pid=%u step_name=device_solve_kernel_dtb elapsed_ms=%llu inflight_at_step=%u caller_tid=%lu",
                op_label,
                pid,
                static_cast<unsigned long long>(GetTickCount64() - solve_kernel_dtb_start),
                g_remote_call_lower_inflight.load(std::memory_order_acquire),
                static_cast<unsigned long>(caller_tid));
            ctx.cached_kernel_dtb = device->get_kernel_dtb();
        }
        diag::log_tagged_fmt("driver",
            "refresh_kernel_context_post op=%s pid=%u dtb_before=0x%llX dtb_after=0x%llX kernel_dtb_after=0x%llX base_after=0x%llX kernel_attached=1 cached_dtb=0x%llX cached_kernel_dtb=0x%llX cached_image_base=0x%llX inflight_after=%u caller_tid=%lu",
            op_label,
            pid,
            static_cast<unsigned long long>(dtb_before),
            static_cast<unsigned long long>(device->get_dtb()),
            static_cast<unsigned long long>(device->get_kernel_dtb()),
            static_cast<unsigned long long>(device->get_base_address()),
            static_cast<unsigned long long>(ctx.cached_dtb),
            static_cast<unsigned long long>(ctx.cached_kernel_dtb),
            static_cast<unsigned long long>(ctx.cached_image_base),
            g_remote_call_lower_inflight.load(std::memory_order_acquire),
            static_cast<unsigned long>(caller_tid));
        return true;
    }

    bool set_active_pid(uint32_t pid)
    {
        if (pid == 0)
            return false;

        std::unique_lock<std::mutex> lk(g_state_mtx);
        if (g_pid == pid) {
            const uint32_t inflight_pre = g_remote_call_lower_inflight.load(std::memory_order_acquire);
            const bool last_abandoned = g_lower_remote_call_last_abandoned.load(std::memory_order_acquire);
            lower_remote_call_drain_result_t same_drain{};
            same_drain.drained = true;
            if (inflight_pre > 0 && last_abandoned) {
                lk.unlock();
                same_drain = wait_lower_remote_call_drain_for_pid_switch(pid, pid, "set_active_pid_same_drain", kSetActivePidDrainTimeoutMs);
                lk.lock();
                diag::log_tagged_fmt("driver",
                    "set_active_pid_same_drain pid=%u drained=%d inflight_after=%u queue_depth_after=%u last_abandoned_after=%u elapsed_ms=%lu",
                    pid,
                    same_drain.drained ? 1 : 0,
                    same_drain.inflight,
                    same_drain.queue_depth,
                    g_lower_remote_call_last_abandoned.load(std::memory_order_acquire) ? 1u : 0u,
                    static_cast<unsigned long>(same_drain.elapsed_ms));
                if (!same_drain.drained) {
                    set_last_error_locked("set_active_pid: lower remote call drain failed for active pid " +
                        std::to_string(pid) +
                        " queue_depth=" + std::to_string(same_drain.queue_depth) +
                        " inflight=" + std::to_string(same_drain.inflight));
                    return false;
                }
            }
            auto it = g_processes.find(pid);
            process_ctx_t transient;
            process_ctx_t& ctx = (it != g_processes.end()) ? it->second : transient;
            bool refresh_ok = true;
            if (g_kernel_mode && device && device->is_connected()) {
                refresh_ok = refresh_kernel_context_locked(lk, pid, ctx, "set_active_pid_same");
                g_kernel_attached = refresh_ok;
            }
            const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
            diag::log_tagged_fmt("driver", "set_active_pid_same pid=%u kernel_attached=%d dtb=0x%llX cached_dtb=0x%llX active_generation=%llu",
                pid,
                g_kernel_attached ? 1 : 0,
                static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0),
                static_cast<unsigned long long>(ctx.cached_dtb),
                static_cast<unsigned long long>(active_generation));
            if (!refresh_ok)
                return false;
            clear_last_error_locked_after_success("set_active_pid_same");
            return true;
        }

        auto it = g_processes.find(pid);
        if (it == g_processes.end()) {
            set_last_error_locked("set_active_pid: pid " + std::to_string(pid) + " not in attached set");
            return false;
        }
        const uint32_t switching_from_pid = g_pid;
        const std::string switching_from_name = g_process_name;
        const bool switching_from_vm_read = g_has_vm_read;
        const bool switching_from_kernel_attached = g_kernel_attached;
        lk.unlock();
        lower_remote_call_drain_result_t drain{};
        if (switching_from_pid != 0 && switching_from_pid != pid)
            drain = wait_lower_remote_call_drain_for_pid_switch(switching_from_pid, pid, "set_active_pid", kSetActivePidDrainTimeoutMs);
        else
            drain.drained = true;
        lk.lock();
        if (!drain.drained) {
            set_last_error_locked("set_active_pid: lower remote call drain failed from pid " +
                std::to_string(switching_from_pid) + " to pid " + std::to_string(pid) +
                " queue_depth=" + std::to_string(drain.queue_depth) +
                " inflight=" + std::to_string(drain.inflight));
            diag::log_tagged_fmt("driver",
                "set_active_pid_reject pid=%u current_pid=%u reason=lower_remote_call_drain_failed queue_depth=%u inflight=%u worker_alive=%u elapsed_ms=%lu last_error=%s",
                pid,
                g_pid,
                drain.queue_depth,
                drain.inflight,
                drain.worker_alive,
                static_cast<unsigned long>(drain.elapsed_ms),
                g_last_error.c_str());
            return false;
        }
        diag::log_tagged_fmt("driver",
            "set_active_pid_drain_ok pid=%u current_pid=%u from_pid=%u inflight_after=%u queue_depth_after=%u worker_alive=%u worker_tid=%lu drain_elapsed_ms=%lu",
            pid,
            g_pid,
            switching_from_pid,
            drain.inflight,
            drain.queue_depth,
            drain.worker_alive,
            static_cast<unsigned long>(g_remote_call_lower_worker_tid.load(std::memory_order_acquire)),
            static_cast<unsigned long>(drain.elapsed_ms));
        if (g_pid == pid) {
            auto same_it = g_processes.find(pid);
            process_ctx_t transient;
            process_ctx_t& ctx = (same_it != g_processes.end()) ? same_it->second : transient;
            bool refresh_ok = true;
            if (g_kernel_mode && device && device->is_connected()) {
                refresh_ok = refresh_kernel_context_locked(lk, pid, ctx, "set_active_pid_same_after_drain");
                g_kernel_attached = refresh_ok;
            }
            const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
            diag::log_tagged_fmt("driver", "set_active_pid_same_after_drain pid=%u kernel_attached=%d dtb=0x%llX cached_dtb=0x%llX active_generation=%llu drain_elapsed_ms=%lu",
                pid,
                g_kernel_attached ? 1 : 0,
                static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0),
                static_cast<unsigned long long>(ctx.cached_dtb),
                static_cast<unsigned long long>(active_generation),
                static_cast<unsigned long>(drain.elapsed_ms));
            if (!refresh_ok)
                return false;
            clear_last_error_locked_after_success("set_active_pid_same_after_drain");
            return true;
        }
        it = g_processes.find(pid);
        if (it == g_processes.end()) {
            set_last_error_locked("set_active_pid: pid " + std::to_string(pid) + " not in attached set after drain");
            return false;
        }
        process_ctx_t& target = it->second;

        if (g_pid != 0) {
            auto cur_it = g_processes.find(g_pid);
            if (cur_it != g_processes.end()) {
                cur_it->second.kernel_attached = g_kernel_attached;
                cur_it->second.has_vm_read = g_has_vm_read;
                cur_it->second.name = g_process_name;
                if (g_kernel_attached && device) {
                    cur_it->second.cached_image_base = device->find_image();
                    cur_it->second.cached_dtb = device->get_dtb();
                    cur_it->second.cached_kernel_dtb = device->get_kernel_dtb();
                }
                if (cur_it->second.h_process == nullptr && g_process != nullptr) {
                    cur_it->second.h_process = g_process;
                    g_process = nullptr;
                }
            }
        }

        close_process_handle_locked();
        g_pid = pid;
        g_pid_snapshot.store(pid, std::memory_order_release);
        const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_process_name = target.name;
        g_has_vm_read = target.has_vm_read;
        g_kernel_attached = target.kernel_attached;
        g_process = target.h_process;
        target.h_process = nullptr;

        bool kernel_mode = g_kernel_mode && device && device->is_connected();
        bool refresh_ok = true;
        if (kernel_mode) {
            refresh_ok = refresh_kernel_context_locked(lk, pid, target, "set_active_pid_switch");
            g_kernel_attached = refresh_ok;
        }
        diag::log_tagged_fmt("driver", "set_active_pid_ok pid=%u kernel_attached=%d dtb=0x%llX cached_dtb=0x%llX active_generation=%llu",
            pid,
            g_kernel_attached ? 1 : 0,
            static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0),
            static_cast<unsigned long long>(target.cached_dtb),
            static_cast<unsigned long long>(active_generation));
        if (!refresh_ok)
        {
            if (g_process != nullptr && target.h_process == nullptr)
            {
                target.h_process = g_process;
                g_process = nullptr;
            }
            g_pid = switching_from_pid;
            g_pid_snapshot.store(switching_from_pid, std::memory_order_release);
            g_process_name = switching_from_name;
            g_has_vm_read = switching_from_vm_read;
            g_kernel_attached = switching_from_kernel_attached;
            if (switching_from_pid != 0) {
                auto previous_it = g_processes.find(switching_from_pid);
                if (previous_it != g_processes.end()) {
                    g_process = previous_it->second.h_process;
                    previous_it->second.h_process = nullptr;
                    if (kernel_mode) {
                        device->set_process_id(switching_from_pid);
                        device->set_dtb(previous_it->second.cached_dtb);
                        device->set_kernel_dtb(previous_it->second.cached_kernel_dtb);
                        device->set_base_address(previous_it->second.cached_image_base);
                    }
                }
            }
            diag::log_tagged_critical_fmt("driver", "set_active_pid_rollback target_pid=%u restored_pid=%u generation=%llu",
                pid,
                switching_from_pid,
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)));
            return false;
        }
        clear_last_error_locked_after_success("set_active_pid");
        return true;
    }

    bool detach_one(uint32_t pid)
    {
        if (pid == 0)
            return false;

        std::lock_guard<std::mutex> lk(g_state_mtx);
        auto it = g_processes.find(pid);
        if (it == g_processes.end())
            return false;

        if (g_pid == pid) {
            const bool is_secondary = (g_primary_pid != 0 && pid != g_primary_pid);
            if (is_secondary) {
                const uint32_t restore_pid = g_primary_pid;
                auto primary_it = g_processes.find(restore_pid);
                const bool primary_available = (primary_it != g_processes.end());
                const bool kernel_ready = g_kernel_mode && device && device->is_connected();

                if (primary_available && kernel_ready) {
                    const uint64_t saved_dtb = primary_it->second.cached_dtb;
                    const uint64_t saved_kernel_dtb = primary_it->second.cached_kernel_dtb;
                    const uint64_t saved_image_base = primary_it->second.cached_image_base;
                    const bool saved_kernel_attached = primary_it->second.kernel_attached;
                    const bool saved_has_vm_read = primary_it->second.has_vm_read;
                    const std::string saved_name = primary_it->second.name;
                    HANDLE saved_h_process = primary_it->second.h_process;
                    primary_it->second.h_process = nullptr;

                    close_process_handle_locked();
                    g_pid = 0;
                    g_pid_snapshot.store(0, std::memory_order_release);
                    g_process_name.clear();
                    g_has_vm_read = false;
                    g_kernel_attached = false;

                    const uint32_t device_pid_before = device->get_process_id();
                    const uint64_t device_dtb_before = device->get_dtb();
                    const uint64_t device_shellcode_before = device->get_shellcode_address_diag();

                    device->set_process_id(restore_pid);
                    device->set_dtb(saved_dtb);
                    device->set_kernel_dtb(saved_kernel_dtb);
                    device->set_base_address(saved_image_base);

                    g_pid = restore_pid;
                    g_pid_snapshot.store(restore_pid, std::memory_order_release);
                    g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel);
                    g_process_name = saved_name;
                    g_has_vm_read = saved_has_vm_read;
                    g_kernel_attached = saved_kernel_attached;
                    if (saved_h_process != nullptr) {
                        g_process = saved_h_process;
                    }

                    diag::log_tagged_critical_fmt("driver",
                        "detach_one_secondary_restore detached_pid=%u primary_pid=%u device_pid_before=%u device_dtb_before=0x%llX device_shellcode_before=0x%llX restored_dtb=0x%llX restored_kernel_dtb=0x%llX restored_base=0x%llX kernel_attached=%d has_vm_read=%d",
                        pid, restore_pid,
                        device_pid_before,
                        static_cast<unsigned long long>(device_dtb_before),
                        static_cast<unsigned long long>(device_shellcode_before),
                        static_cast<unsigned long long>(saved_dtb),
                        static_cast<unsigned long long>(saved_kernel_dtb),
                        static_cast<unsigned long long>(saved_image_base),
                        g_kernel_attached ? 1 : 0,
                        g_has_vm_read ? 1 : 0);
                } else {
                    close_process_handle_locked();
                    g_pid = 0;
                    g_pid_snapshot.store(0, std::memory_order_release);
                    g_process_name.clear();
                    g_has_vm_read = false;
                    g_kernel_attached = false;
                    if (kernel_ready) {
                        device->clear_process_context();
                    }
                    diag::log_tagged_fmt("driver",
                        "detach_one_secondary_fallback_clear pid=%u primary_pid=%u primary_available=%d kernel_ready=%d",
                        pid, restore_pid, primary_available ? 1 : 0, kernel_ready ? 1 : 0);
                }
            } else {
                g_primary_pid = 0;
                close_process_handle_locked();
                g_pid = 0;
                g_pid_snapshot.store(0, std::memory_order_release);
                g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel);
                g_process_name.clear();
                g_has_vm_read = false;
                g_kernel_attached = false;
                if (g_kernel_mode && device && device->is_connected()) {
                    device->clear_process_context();
                }
            }
        } else {
            release_ctx_handle(it->second);
        }
        g_processes.erase(it);
        diag::log_tagged_fmt("driver", "detach_one_ok pid=%u", pid);
        return true;
    }

    bool clear_active_pid()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_pid == 0) {
            clear_last_error_locked_after_success("clear_active_pid_noop");
            return true;
        }
        auto it = g_processes.find(g_pid);
        if (it != g_processes.end()) {
            if (it->second.h_process == nullptr && g_process != nullptr) {
                it->second.h_process = g_process;
                g_process = nullptr;
            }
            it->second.kernel_attached = g_kernel_attached;
            it->second.has_vm_read = g_has_vm_read;
            it->second.name = g_process_name;
            if (g_kernel_attached && device) {
                it->second.cached_image_base = device->find_image();
                it->second.cached_dtb = device->get_dtb();
                it->second.cached_kernel_dtb = device->get_kernel_dtb();
            }
        }
        close_process_handle_locked();
        g_pid = 0;
        g_primary_pid = 0;
        g_pid_snapshot.store(0, std::memory_order_release);
        const std::uint64_t active_generation = g_active_pid_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_process_name.clear();
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (g_kernel_mode && device && device->is_connected()) {
            device->clear_process_context();
        }
        clear_last_error_locked_after_success("clear_active_pid");
        diag::log_tagged_fmt("driver", "clear_active_pid_done active_generation=%llu", static_cast<unsigned long long>(active_generation));
        return true;
    }

    std::vector<uint32_t> attached_pids()
    {
        std::vector<uint32_t> out;
        std::lock_guard<std::mutex> lk(g_state_mtx);
        out.reserve(g_processes.size());
        for (const auto& kv : g_processes)
            out.push_back(kv.first);
        return out;
    }

    std::string status()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (!g_initialized)
            return "Live inspection bridge: not initialized";
        const bool kernel_active = g_kernel_mode && device && device->is_connected();
        if (g_pid == 0) {
            return kernel_active
                ? "Live inspection bridge: kernel backend ready (no process attached)"
                : "Live inspection bridge: kernel driver required (not loaded)";
        }

        char buf[256];
        if (kernel_active && !g_kernel_attached) {
            snprintf(buf, sizeof(buf), "Live inspection bridge: kernel backend selected PID %u (%s), not attached",
                     g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        } else {
            snprintf(buf, sizeof(buf), "Live inspection bridge: %s attached to PID %u (%s)",
                     kernel_active ? "kernel backend" : "kernel driver required (not loaded)",
                     g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        }
        return buf;
    }

    std::string last_error()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_last_error;
    }

    uint32_t attached_pid()
    {
        return g_pid_snapshot.load(std::memory_order_acquire);
    }

    bool attached_process_alive(uint32_t* exit_code_out)
    {
        uint32_t pid = 0;
        DWORD exit_code = 0;
        bool got_exit_code = false;

        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            pid = g_pid;
            if (pid == 0) {
                if (exit_code_out) *exit_code_out = 0;
                return false;
            }
            if (g_process && GetExitCodeProcess(g_process, &exit_code)) {
                got_exit_code = true;
            }
        }

        if (!got_exit_code) {
            auto proc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!proc) {
                const DWORD err = GetLastError();
                if (exit_code_out) *exit_code_out = err;
                diag::log_tagged_fmt("driver",
                    "attached_process_alive open_failed pid=%u err=%lu",
                    pid, static_cast<unsigned long>(err));
                return err == ERROR_ACCESS_DENIED;
            }
            if (!GetExitCodeProcess(proc.get(), &exit_code)) {
                const DWORD err = GetLastError();
                if (exit_code_out) *exit_code_out = err;
                diag::log_tagged_fmt("driver",
                    "attached_process_alive get_exit_failed pid=%u err=%lu",
                    pid, static_cast<unsigned long>(err));
                return false;
            }
        }

        if (exit_code_out) *exit_code_out = static_cast<uint32_t>(exit_code);
        return exit_code == STILL_ACTIVE;
    }

    std::string attached_process_name()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_process_name;
    }

    struct enum_main_window_ctx {
        DWORD pid;
        HWND  result;
    };

    static BOOL CALLBACK find_main_window_cb(HWND hwnd, LPARAM lParam)
    {
        auto* ctx = reinterpret_cast<enum_main_window_ctx*>(lParam);
        DWORD wnd_pid = 0;
        GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid != ctx->pid) return TRUE;
        if (GetWindow(hwnd, GW_OWNER)) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        ctx->result = hwnd;
        return FALSE;
    }

    static std::string get_window_title(DWORD pid)
    {
        enum_main_window_ctx ctx{pid, nullptr};
        EnumWindows(find_main_window_cb, reinterpret_cast<LPARAM>(&ctx));
        if (!ctx.result) return {};
        wchar_t buf[256] = {};
        if (!GetWindowTextW(ctx.result, buf, 256)) return {};
        return utf8_from_wide(buf);
    }

    std::vector<process_info_t> enumerate_processes()
    {
        std::vector<process_info_t> result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return result;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return result;

        DWORD self_pid = GetCurrentProcessId();

        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;
            if (pe.th32ProcessID == self_pid)
                continue;

            process_info_t proc;
            proc.pid  = pe.th32ProcessID;
            proc.name = utf8_from_wide(pe.szExeFile);

            auto hProc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID));
            if (hProc) {
                wchar_t path_buf[MAX_PATH] = {};
                DWORD path_len = static_cast<DWORD>(std::size(path_buf));
                if (QueryFullProcessImageNameW(hProc.get(), 0, path_buf, &path_len) && path_len > 0)
                    proc.path = utf8_from_wide(path_buf);
            }

            proc.window_title = get_window_title(pe.th32ProcessID);

            result.push_back(std::move(proc));
        } while (Process32NextW(snapshot.get(), &pe));

        std::sort(result.begin(), result.end(), [](const process_info_t& a, const process_info_t& b) {
            if (!a.window_title.empty() && b.window_title.empty()) return true;
            if (a.window_title.empty() && !b.window_title.empty()) return false;
            return a.pid < b.pid;
        });
        return result;
    }

    static std::vector<module_info_t> enumerate_modules_usermode(uint32_t pid, HANDLE process)
    {
        const ULONGLONG t0 = GetTickCount64();
        std::vector<module_info_t> result;

        SetLastError(ERROR_SUCCESS);
        HANDLE raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        DWORD snapshot_error = raw_snapshot == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_usermode_toolhelp_snapshot pid=%u process=%p handle=%p gle=%lu elapsed_ms=%llu",
            pid,
            process,
            raw_snapshot == INVALID_HANDLE_VALUE ? nullptr : raw_snapshot,
            static_cast<unsigned long>(snapshot_error),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        auto snapshot = make_handle(raw_snapshot);
        if (!snapshot)
            return result;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        SetLastError(ERROR_SUCCESS);
        BOOL first_ok = Module32FirstW(snapshot.get(), &me);
        DWORD first_error = first_ok ? ERROR_SUCCESS : GetLastError();
        if (first_ok) {
            do {
                module_info_t mod;
                mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                mod.size = me.modBaseSize;
                mod.name = utf8_from_wide(me.szModule);
                mod.path = utf8_from_wide(me.szExePath);
                result.push_back(std::move(mod));
            } while (Module32NextW(snapshot.get(), &me));
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_usermode_toolhelp_result pid=%u first_ok=%d first_gle=%lu count=%llu elapsed_ms=%llu",
            pid,
            first_ok ? 1 : 0,
            static_cast<unsigned long>(first_error),
            static_cast<unsigned long long>(result.size()),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<module_info_t> enumerate_modules()
    {
        target_context_lock_t target_lock("enumerate_modules");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        const ULONGLONG t0 = GetTickCount64();
        diag::log_tagged_critical_fmt("driver", "enumerate_modules_enter tid=%lu", GetCurrentThreadId());
        std::vector<module_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid) {
            diag::log_tagged_critical("driver", "enumerate_modules_no_pid");
            return result;
        }

        HANDLE process = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
        }

        if (process) {
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_pre_usermode pid=%u handle=%p", pid, process);
            result = enumerate_modules_usermode(pid, process);
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_post_usermode count=%llu", (unsigned long long)result.size());
        }

        if (!result.empty()) {
            logf("AiDA Standalone: enumerate_modules: resolved %zu modules via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_exit_ok count=%llu", (unsigned long long)result.size());
            return result;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            logf("AiDA Standalone: enumerate_modules: no modules resolved for PID %u.\n", pid);
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_kernel_unavailable pid=%u elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return result;
        }

        voyager::device_t::peb_info peb{};
        const ULONGLONG peb_start = GetTickCount64();
        bool peb_ok = device->read_peb(peb);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_peb pid=%u ok=%d peb=0x%llX image=0x%llX ldr=0x%llX elapsed_ms=%llu",
            pid,
            peb_ok ? 1 : 0,
            static_cast<unsigned long long>(peb.peb_address),
            static_cast<unsigned long long>(peb.image_base),
            static_cast<unsigned long long>(peb.ldr_address),
            static_cast<unsigned long long>(GetTickCount64() - peb_start));
        if (!peb_ok || peb.ldr_address == 0) {
            logf("AiDA Standalone: enumerate_modules: failed to read PEB/LDR for PID %u.\n", pid);
            return result;
        }

        const uint64_t list_head = peb.ldr_address + 0x10;
        uint64_t current = device->read<uint64_t>(list_head);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_ldr_head pid=%u list_head=0x%llX first=0x%llX",
            pid,
            static_cast<unsigned long long>(list_head),
            static_cast<unsigned long long>(current));
        if (current == 0 || current == list_head) {
            logf("AiDA Standalone: enumerate_modules: LDR list empty for PID %u.\n", pid);
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_kernel_ldr_empty pid=%u list_head=0x%llX first=0x%llX",
                pid,
                static_cast<unsigned long long>(list_head),
                static_cast<unsigned long long>(current));
            return result;
        }

        int max_iter = 1024;
        while (current != list_head && current != 0 && max_iter-- > 0) {
            const uint64_t dll_base = device->read<uint64_t>(current + 0x30);
            const uint32_t size_of_image = device->read<uint32_t>(current + 0x40);

            const uint16_t full_name_len = device->read<uint16_t>(current + 0x48);
            const uint64_t full_name_ptr = device->read<uint64_t>(current + 0x50);
            const uint16_t base_name_len = device->read<uint16_t>(current + 0x58);
            const uint64_t base_name_ptr = device->read<uint64_t>(current + 0x60);

            std::string base_name;
            if (base_name_ptr != 0 && base_name_len > 0 && base_name_len <= 520) {
                std::vector<uint8_t> raw(base_name_len, 0);
                if (device->read_raw(base_name_ptr, raw.data(), base_name_len) > 0) {
                    base_name.reserve(base_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        base_name += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            std::string full_path;
            if (full_name_ptr != 0 && full_name_len > 0 && full_name_len <= 1024) {
                std::vector<uint8_t> raw(full_name_len, 0);
                if (device->read_raw(full_name_ptr, raw.data(), full_name_len) > 0) {
                    full_path.reserve(full_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        full_path += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            if (dll_base != 0 && !base_name.empty()) {
                module_info_t mod;
                mod.base = dll_base;
                mod.size = size_of_image;
                mod.name = std::move(base_name);
                mod.path = std::move(full_path);
                result.push_back(std::move(mod));
            }

            const uint64_t next = device->read<uint64_t>(current);
            if (next == current || next == 0)
                break;
            current = next;
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });

        logf("AiDA Standalone: enumerate_modules: resolved %zu modules via kernel LDR walk for PID %u.\n",
             result.size(), pid);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_ldr_result pid=%u count=%llu final_current=0x%llX elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(result.size()),
            static_cast<unsigned long long>(current),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<thread_info_t> enumerate_threads()
    {
        target_context_lock_t target_lock("enumerate_threads");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        std::vector<thread_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            result = enumerate_threads_usermode_snapshot(pid);
            logf("AiDA Standalone: enumerate_threads: resolved %zu threads via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            if (result.empty()) {
                uint32_t exit_code = 0;
                if (!attached_process_alive(&exit_code)) {
                    diag::log_tagged_fmt("driver",
                        "enumerate_threads_dead_target_user pid=%u exit_code_or_err=0x%08X; detaching stale target",
                        pid, exit_code);
                    detach();
                }
            }
            return result;
        }

        {
            auto kernel_threads = device->enumerate_threads();
            result.reserve(kernel_threads.size());
            for (const auto& kt : kernel_threads) {
                thread_info_t t;
                t.tid = kt.tid;
                t.owner_pid = pid;
                t.priority = 0;
                t.state = kt.state;
                t.rip = kt.rip;
                result.push_back(t);
            }
        }

        std::sort(result.begin(), result.end(), [](const thread_info_t& a, const thread_info_t& b) {
            return a.tid < b.tid;
        });

        logf("AiDA Standalone: enumerate_threads: resolved %zu threads via kernel IOCTL for PID %u.\n",
             result.size(), pid);
        if (result.empty()) {
            result = enumerate_threads_usermode_snapshot(pid);
            diag::log_tagged_fmt("driver",
                "enumerate_threads_kernel_empty_usermode_fallback pid=%u count=%zu",
                pid,
                result.size());
        }
        if (result.empty()) {
            uint32_t exit_code = 0;
            if (!attached_process_alive(&exit_code)) {
                diag::log_tagged_fmt("driver",
                    "enumerate_threads_dead_target_kernel pid=%u exit_code_or_err=0x%08X; detaching stale target",
                    pid, exit_code);
                detach();
            }
        }
        return result;
    }

    std::vector<memory_region_t> enumerate_memory_regions(size_t max_regions)
    {
        target_context_lock_t target_lock("enumerate_memory_regions");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        std::vector<memory_region_t> result;
        HANDLE process = nullptr;
        bool kernel_mode = false;
        bool kernel_attached = false;
        uint32_t pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
            pid = g_pid;
        }

        if (kernel_mode) {
            {
                DWORD direct_gle = ERROR_SUCCESS;
                size_t raw_count = 0;
                if (!device) {
                    return result;
                }
                SetLastError(ERROR_SUCCESS);
                const auto regions = device->enumerate_memory_regions(0, 0, false);
                direct_gle = GetLastError();
                raw_count = regions.size();
                for (const auto& src : regions) {
                    memory_region_t region;
                    region.base = src.base;
                    region.size = src.size;
                    region.state = src.state;
                    region.protect = src.protect;
                    region.type = src.type;
                    result.push_back(region);
                    if (result.size() >= max_regions)
                        break;
                }
                diag::log_tagged_fmt("driver",
                    "enumerate_memory_regions_direct pid=%u max=%zu raw_count=%zu copied=%zu gle=%lu kernel_attached=%d dtb=0x%llX",
                    pid,
                    max_regions,
                    raw_count,
                    result.size(),
                    static_cast<unsigned long>(direct_gle),
                    kernel_attached ? 1 : 0,
                    static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0));
            }
            return result;
        }

        if (process) {
            MEMORY_BASIC_INFORMATION mbi{};
            uint64_t addr = 0;
            while (result.size() < max_regions &&
                   VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                memory_region_t region;
                region.base    = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region.size    = mbi.RegionSize;
                region.state   = mbi.State;
                region.protect = mbi.Protect;
                region.type    = mbi.Type;
                result.push_back(region);
                uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
        }

        return result;
    }

    bool query_memory(uint64_t address, memory_region_t& region)
    {
        target_context_lock_t target_lock("query_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        memory_region_t candidate{};
        HANDLE process = nullptr;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (kernel_mode) {
            voyager::device_t::memory_region_info info = {};
            if (!device->query_memory(address, info))
                return false;
            candidate.base = info.base;
            candidate.size = info.size;
            candidate.state = info.state;
            candidate.protect = info.protect;
            candidate.type = info.type;
            if (!validate_target_context_snapshot("query_memory", target)) {
                region = {};
                return false;
            }
            region = candidate;
            return true;
        }

        if (process) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
                               &mbi, sizeof(mbi)) == sizeof(mbi)) {
                region.base    = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region.size    = mbi.RegionSize;
                region.state   = mbi.State;
                region.protect = mbi.Protect;
                region.type    = mbi.Type;
                return true;
            }
        }

        return false;
    }

    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        target_context_lock_t target_lock("read_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        out.clear();
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (size == 0)
            return false;

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "read_memory_kernel_required addr=0x%llX sz=%llu kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("read_memory");
            return false;
        }

        const uint32_t diag_pid = attached_pid();
        const DWORD diag_tid = GetCurrentThreadId();
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        diag::log_tagged_fmt("driver",
            "read_memory_kernel_begin pid=%u tid=%lu addr=0x%llX size=%llu kernel=%d attached=%d dtb=0x%llX region_ok=%d region_gle=%lu region_base=0x%llX region_size=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
            diag_pid,
            static_cast<unsigned long>(diag_tid),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            kernel_mode ? 1 : 0,
            kernel_attached ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            region_before.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.gle),
            static_cast<unsigned long long>(region_before.base),
            static_cast<unsigned long long>(region_before.size),
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_before.type));

        out.resize(size);
        size_t bytes_read = 0;
        size_t direct_bytes = 0;

        if (device && device->get_dtb() != 0) {
            direct_bytes = device->read_raw(address, out.data(), size);
            bytes_read = direct_bytes;
        }

        {
            static int s_read_log_count = 0;
            if (s_read_log_count < 50) {
                s_read_log_count++;
                logf("read_memory: addr=0x%llX sz=%llu kernel=%d dtb=0x%llX bytes=%llu\n",
                    (unsigned long long)address, (unsigned long long)size,
                    kernel_mode ? 1 : 0,
                    device ? (unsigned long long)device->get_dtb() : 0ULL,
                    (unsigned long long)bytes_read);
            }
        }

        if (bytes_read == 0) {
            bool re_resolved = false;
            uint64_t dtb_before_refresh = device ? device->get_dtb() : 0;
            uint64_t dtb_after_refresh = 0;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                if (device) {
                    device->solve_dtb();
                    re_resolved = (device->get_dtb() != 0);
                    dtb_after_refresh = device->get_dtb();
                }
            }

            size_t retry_direct_bytes = 0;
            if (re_resolved) {
                std::memset(out.data(), 0, size);
                if (device) {
                    retry_direct_bytes = device->read_raw(address, out.data(), size);
                    bytes_read = retry_direct_bytes;
                }
            }
            const DWORD retry_gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "read_memory_kernel_retry pid=%u tid=%lu addr=0x%llX size=%llu re_resolved=%d dtb_before=0x%llX dtb_after=0x%llX direct_first=%llu retry_direct=%llu final_bytes=%llu gle=%lu",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                re_resolved ? 1 : 0,
                static_cast<unsigned long long>(dtb_before_refresh),
                static_cast<unsigned long long>(dtb_after_refresh),
                static_cast<unsigned long long>(direct_bytes),
                static_cast<unsigned long long>(retry_direct_bytes),
                static_cast<unsigned long long>(bytes_read),
                static_cast<unsigned long>(retry_gle));
            SetLastError(retry_gle);
        }

        if (bytes_read > 0) {
            out.resize(bytes_read);
            if (!validate_target_context_snapshot("read_memory", target)) {
                out.clear();
                return false;
            }
            const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
            diag::log_tagged_fmt("driver",
                "read_memory_kernel_done pid=%u tid=%lu addr=0x%llX size=%llu ok=1 bytes=%llu direct_bytes=%llu dtb_entry=0x%llX dtb_exit=0x%llX all_zero=%d first16=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(bytes_read),
                static_cast<unsigned long long>(direct_bytes),
                static_cast<unsigned long long>(dtb_entry),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                bytes_all_zero(out.data(), out.size()) ? 1 : 0,
                format_byte_prefix(out.data(), out.size()).c_str(),
                region_before.ok ? 1 : 0,
                region_after.ok ? 1 : 0,
                static_cast<unsigned long>(region_before.state),
                static_cast<unsigned long>(region_before.protect),
                static_cast<unsigned long>(region_after.state),
                static_cast<unsigned long>(region_after.protect));
            clear_last_error_after_success("read_memory_kernel");
            return true;
        }

        out.clear();
        const DWORD final_gle = GetLastError();
        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        const DWORD observed_gle_after_snapshot = GetLastError();
        diag::log_tagged_fmt("driver",
            "read_memory_kernel_failed pid=%u tid=%lu addr=0x%llX sz=%llu dtb_entry=0x%llX dtb_exit=0x%llX direct_bytes=%llu gle=%lu observed_gle_after_snapshot=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
            diag_pid,
            static_cast<unsigned long>(diag_tid),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long long>(direct_bytes),
            static_cast<unsigned long>(final_gle),
            static_cast<unsigned long>(observed_gle_after_snapshot),
            last_error().empty() ? "<empty>" : last_error().c_str(),
            region_before.ok ? 1 : 0,
            region_after.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect));
        SetLastError(final_gle);
        return false;
    }

    bool write_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        target_context_lock_t target_lock("write_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        if (data.empty())
            return false;

        constexpr size_t kVerifyLimit = 4096;
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "write_memory_kernel_required addr=0x%llX sz=%llu kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("write_memory");
            return false;
        }

        const uint32_t diag_pid = attached_pid();
        const DWORD diag_tid = GetCurrentThreadId();
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        diag::log_tagged_fmt("driver",
            "write_memory_kernel_begin pid=%u tid=%lu addr=0x%llX size=%llu kernel=%d attached=%d dtb=0x%llX expected_first16=%s region_ok=%d region_gle=%lu region_base=0x%llX region_size=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
            diag_pid,
            static_cast<unsigned long>(diag_tid),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(data.size()),
            kernel_mode ? 1 : 0,
            kernel_attached ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            format_byte_prefix(data.data(), data.size()).c_str(),
            region_before.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.gle),
            static_cast<unsigned long long>(region_before.base),
            static_cast<unsigned long long>(region_before.size),
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_before.type));

        auto first_mismatch = [](const std::vector<uint8_t>& expected, const std::vector<uint8_t>& actual) -> size_t {
            const size_t n = std::min(expected.size(), actual.size());
            for (size_t i = 0; i < n; ++i) {
                if (expected[i] != actual[i])
                    return i;
            }
            return n;
        };

        size_t bytes_written = 0;
        size_t direct_written = 0;
        size_t retry_direct_written = 0;
        bool re_resolved = false;
        uint64_t dtb_before_refresh = dtb_entry;
        uint64_t dtb_after_refresh = dtb_entry;

        if (device && device->get_dtb() != 0) {
            direct_written = device->write_raw(address, data.data(), data.size());
            if (direct_written > bytes_written)
                bytes_written = direct_written;
        }

        if (bytes_written != data.size()) {
            dtb_before_refresh = device ? device->get_dtb() : 0;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                if (device) {
                    device->solve_dtb();
                    re_resolved = (device->get_dtb() != 0);
                    dtb_after_refresh = device->get_dtb();
                }
            }

            if (re_resolved && device) {
                retry_direct_written = device->write_raw(address, data.data(), data.size());
                if (retry_direct_written > bytes_written)
                    bytes_written = retry_direct_written;
            }
            diag::log_tagged_fmt("driver",
                "write_memory_kernel_retry pid=%u tid=%lu addr=0x%llX size=%llu re_resolved=%d dtb_before=0x%llX dtb_after=0x%llX direct_first=%llu retry_direct=%llu final_bytes=%llu gle=%lu",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                re_resolved ? 1 : 0,
                static_cast<unsigned long long>(dtb_before_refresh),
                static_cast<unsigned long long>(dtb_after_refresh),
                static_cast<unsigned long long>(direct_written),
                static_cast<unsigned long long>(retry_direct_written),
                static_cast<unsigned long long>(bytes_written),
                static_cast<unsigned long>(GetLastError()));
        }

        if (bytes_written == data.size()) {
            if (!validate_target_context_snapshot("write_memory", target))
                return false;
            if (data.size() > kVerifyLimit) {
                const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
                diag::log_tagged_fmt("driver",
                    "write_memory_kernel_done pid=%u tid=%lu addr=0x%llX size=%llu ok=1 verify_skipped=1 reason=size_limit direct_bytes=%llu retry_direct=%llu dtb_entry=0x%llX dtb_exit=0x%llX region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                    diag_pid,
                    static_cast<unsigned long>(diag_tid),
                    static_cast<unsigned long long>(address),
                    static_cast<unsigned long long>(data.size()),
                    static_cast<unsigned long long>(direct_written),
                    static_cast<unsigned long long>(retry_direct_written),
                    static_cast<unsigned long long>(dtb_entry),
                    static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                    region_before.ok ? 1 : 0,
                    region_after.ok ? 1 : 0,
                    static_cast<unsigned long>(region_before.state),
                    static_cast<unsigned long>(region_before.protect),
                    static_cast<unsigned long>(region_after.state),
                    static_cast<unsigned long>(region_after.protect));
                clear_last_error_after_success("write_memory_kernel");
                return true;
            }
            std::vector<uint8_t> bridge_verify;
            bool bridge_read_ok = read_memory(address, data.size(), bridge_verify);
            bool bridge_match = bridge_read_ok &&
                bridge_verify.size() == data.size() &&
                std::equal(data.begin(), data.end(), bridge_verify.begin());
            if (bridge_match) {
                const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
                diag::log_tagged_fmt("driver",
                    "write_memory_kernel_done pid=%u tid=%lu addr=0x%llX size=%llu ok=1 verify_skipped=0 bridge_read=1 bridge_bytes=%llu direct_bytes=%llu retry_direct=%llu dtb_entry=0x%llX dtb_exit=0x%llX expected_first16=%s actual_first16=%s all_zero_readback=0 region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                    diag_pid,
                    static_cast<unsigned long>(diag_tid),
                    static_cast<unsigned long long>(address),
                    static_cast<unsigned long long>(data.size()),
                    static_cast<unsigned long long>(bridge_verify.size()),
                    static_cast<unsigned long long>(direct_written),
                    static_cast<unsigned long long>(retry_direct_written),
                    static_cast<unsigned long long>(dtb_entry),
                    static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                    format_byte_prefix(data.data(), data.size()).c_str(),
                    format_byte_prefix(bridge_verify.data(), bridge_verify.size()).c_str(),
                    region_before.ok ? 1 : 0,
                    region_after.ok ? 1 : 0,
                    static_cast<unsigned long>(region_before.state),
                    static_cast<unsigned long>(region_before.protect),
                    static_cast<unsigned long>(region_after.state),
                    static_cast<unsigned long>(region_after.protect));
                clear_last_error_after_success("write_memory_kernel_verified");
                return true;
            }
            const size_t mismatch = first_mismatch(data, bridge_verify);
            const uint8_t expected = mismatch < data.size() ? data[mismatch] : 0;
            const uint8_t actual = mismatch < bridge_verify.size() ? bridge_verify[mismatch] : 0;
            const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
            diag::log_tagged_fmt("driver",
                "write_memory kernel verify_mismatch pid=%u tid=%lu addr=0x%llX sz=%llu bridge_read=%d bridge_bytes=%llu mismatch=%llu expected=0x%02X actual=0x%02X expected_first16=%s actual_first16=%s all_zero_readback=%d direct_bytes=%llu retry_direct=%llu dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                bridge_read_ok ? 1 : 0,
                static_cast<unsigned long long>(bridge_verify.size()),
                static_cast<unsigned long long>(mismatch),
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual),
                format_byte_prefix(data.data(), data.size()).c_str(),
                format_byte_prefix(bridge_verify.data(), bridge_verify.size()).c_str(),
                bytes_all_zero(bridge_verify.data(), bridge_verify.size()) ? 1 : 0,
                static_cast<unsigned long long>(direct_written),
                static_cast<unsigned long long>(retry_direct_written),
                static_cast<unsigned long long>(dtb_entry),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                static_cast<unsigned long>(GetLastError()),
                last_error().empty() ? "<empty>" : last_error().c_str(),
                region_before.ok ? 1 : 0,
                region_after.ok ? 1 : 0,
                static_cast<unsigned long>(region_before.state),
                static_cast<unsigned long>(region_before.protect),
                static_cast<unsigned long>(region_after.state),
                static_cast<unsigned long>(region_after.protect));
            return false;
        }

        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        if (bytes_written > 0) {
            diag::log_tagged_fmt("driver",
                "write_memory kernel partial pid=%u tid=%lu addr=0x%llX sz=%llu bytes=%llu direct_bytes=%llu retry_direct=%llu dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(bytes_written),
                static_cast<unsigned long long>(direct_written),
                static_cast<unsigned long long>(retry_direct_written),
                static_cast<unsigned long long>(dtb_entry),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                static_cast<unsigned long>(GetLastError()),
                last_error().empty() ? "<empty>" : last_error().c_str(),
                region_before.ok ? 1 : 0,
                region_after.ok ? 1 : 0,
                static_cast<unsigned long>(region_before.state),
                static_cast<unsigned long>(region_before.protect),
                static_cast<unsigned long>(region_after.state),
                static_cast<unsigned long>(region_after.protect));
        } else {
            diag::log_tagged_fmt("driver",
                "write_memory kernel failed pid=%u tid=%lu addr=0x%llX sz=%llu dtb_entry=0x%llX dtb_exit=0x%llX direct_bytes=%llu retry_direct=%llu re_resolved=%d gle=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX",
                diag_pid,
                static_cast<unsigned long>(diag_tid),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(dtb_entry),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                static_cast<unsigned long long>(direct_written),
                static_cast<unsigned long long>(retry_direct_written),
                re_resolved ? 1 : 0,
                static_cast<unsigned long>(GetLastError()),
                last_error().empty() ? "<empty>" : last_error().c_str(),
                region_before.ok ? 1 : 0,
                region_after.ok ? 1 : 0,
                static_cast<unsigned long>(region_before.state),
                static_cast<unsigned long>(region_before.protect),
                static_cast<unsigned long>(region_after.state),
                static_cast<unsigned long>(region_after.protect));
        }

        return false;
    }

    bool read_string(uint64_t address, size_t max_length, std::string& out)
    {
        target_context_lock_t target_lock("read_string");
        out.clear();
        if (max_length == 0)
            return false;

        std::vector<uint8_t> bytes;
        if (!read_memory(address, max_length, bytes))
            return false;

        for (uint8_t b : bytes) {
            if (b == 0)
                break;
            out.push_back(static_cast<char>(b));
        }
        return !out.empty();
    }

}

namespace driver_bridge_pid_call
{
    inline bool pid_is_alive(uint32_t pid, uint32_t* exit_code_out)
    {
        if (pid == 0) {
            if (exit_code_out) *exit_code_out = 0;
            return false;
        }
        auto proc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!proc) {
            const DWORD err = GetLastError();
            if (exit_code_out) *exit_code_out = err;
            return err == ERROR_ACCESS_DENIED;
        }
        DWORD exit_code = 0;
        if (!GetExitCodeProcess(proc.get(), &exit_code)) {
            const DWORD err = GetLastError();
            if (exit_code_out) *exit_code_out = err;
            return false;
        }
        if (exit_code_out) *exit_code_out = static_cast<uint32_t>(exit_code);
        return exit_code == STILL_ACTIVE;
    }

    struct pid_scope_t
    {
        bool     ok = false;
        bool     swapped = false;
        uint32_t prev_pid = 0;
        uint32_t target_pid = 0;
        std::unique_lock<std::recursive_mutex> lk;

        pid_scope_t() = default;
        pid_scope_t(const pid_scope_t&) = delete;
        pid_scope_t& operator=(const pid_scope_t&) = delete;

        ~pid_scope_t()
        {
            if (!ok) return;
            if (!swapped) return;
            const DWORD restore_start = GetTickCount();
            const uint32_t active_before = driver_bridge::attached_pid();
            uint32_t active_exit = 0;
            const bool active_alive = active_before != 0 && pid_is_alive(active_before, &active_exit);
            if (active_before != target_pid && active_before != 0 && active_alive) {
                diag::log_tagged_fmt("driver_bridge",
                    "pid_scope_exit_restore_skip target=%u previous=%u active_before=%u active_alive=%d active_exit=0x%08X status=%s last_error=%s elapsed_ms=%lu",
                    target_pid,
                    prev_pid,
                    active_before,
                    active_alive ? 1 : 0,
                    active_exit,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str(),
                    static_cast<unsigned long>(GetTickCount() - restore_start));
                return;
            }
            uint32_t selected_pid = 0;
            uint32_t previous_exit = 0;
            bool previous_alive = false;
            bool previous_known = false;
            bool restored = false;
            const char* method = "none";
            if (prev_pid != 0 && prev_pid != target_pid) {
                previous_alive = pid_is_alive(prev_pid, &previous_exit);
                const auto pids = driver_bridge::attached_pids();
                for (auto pid : pids) {
                    if (pid == prev_pid) {
                        previous_known = true;
                        break;
                    }
                }
                if (!previous_known && previous_alive)
                    previous_known = driver_bridge::attach_additional(prev_pid);
                if (previous_known && previous_alive) {
                    method = "previous";
                    restored = driver_bridge::set_active_pid(prev_pid);
                    if (restored)
                        selected_pid = prev_pid;
                }
            }
            if (!restored) {
                const auto pids = driver_bridge::attached_pids();
                for (auto pid : pids) {
                    if (pid == 0 || pid == target_pid)
                        continue;
                    uint32_t exit_code = 0;
                    if (!pid_is_alive(pid, &exit_code))
                        continue;
                    method = "fallback_live_attached";
                    restored = driver_bridge::set_active_pid(pid);
                    if (restored) {
                        selected_pid = pid;
                        break;
                    }
                }
            }
            if (!restored) {
                method = prev_pid == 0 ? "clear_no_previous" : "clear_no_live_restore";
                (void)driver_bridge::clear_active_pid();
            }
            diag::log_tagged_fmt("driver_bridge",
                "pid_scope_exit_restore target=%u previous=%u active_before=%u previous_known=%d previous_alive=%d previous_exit=0x%08X method=%s restored=%d selected=%u active_after=%u status=%s last_error=%s elapsed_ms=%lu",
                target_pid,
                prev_pid,
                active_before,
                previous_known ? 1 : 0,
                previous_alive ? 1 : 0,
                previous_exit,
                method,
                restored ? 1 : 0,
                selected_pid,
                driver_bridge::attached_pid(),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long>(GetTickCount() - restore_start));
        }
    };

    inline bool enter(pid_scope_t& scope, uint32_t pid)
    {
        if (pid == 0)
            return false;
        const ULONGLONG lock_started = GetTickCount64();
        scope.lk = std::unique_lock<std::recursive_mutex>(g_target_context_mtx);
        diag::log_tagged_fmt("driver_bridge",
            "target_context_lock_acquired op=pid_scope_enter requested_pid=%u tid=%lu wait_ms=%llu active_pid=%u generation=%llu device_pid=%u dtb=0x%llX",
            pid,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(GetTickCount64() - lock_started),
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
            device ? device->get_process_id() : 0,
            static_cast<unsigned long long>(device ? device->get_dtb() : 0));
        scope.prev_pid = driver_bridge::attached_pid();
        scope.target_pid = pid;
        uint32_t exit_code = 0;
        if (!pid_is_alive(pid, &exit_code)) {
            diag::log_tagged_fmt("driver_bridge",
                "pid_scope_enter_dead_target pid=%u exit_code_or_err=0x%08X",
                pid, exit_code);
            (void)driver_bridge::detach_one(pid);
            return false;
        }
        if (scope.prev_pid == pid) {
            scope.ok = true;
            scope.swapped = false;
            return true;
        }
        const auto pids = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : pids) { if (p == pid) { in_map = true; break; } }
        if (!in_map) {
            if (!driver_bridge::attach_additional(pid))
                return false;
        }
        if (!driver_bridge::set_active_pid(pid))
            return false;
        scope.ok = true;
        scope.swapped = true;
        return true;
    }
}

namespace driver_bridge
{
    bool read_memory_for(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        out.clear();
        const ULONGLONG t0 = GetTickCount64();
        diag::log_tagged_fmt("driver_bridge",
            "read_memory_for_enter pid=%u tid=%lu addr=0x%llX size=%zu attached_pid=%u",
            pid,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            attached_pid());
        const ULONGLONG t_enter_start = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        const bool enter_ok = driver_bridge_pid_call::enter(scope, pid);
        const ULONGLONG enter_elapsed_ms = GetTickCount64() - t_enter_start;
        if (!enter_ok) {
            const std::string err = last_error();
            diag::log_tagged_fmt("driver_bridge",
                "read_memory_for pid=%u addr=0x%llX size=%zu enter_failed active_pid=%u status=%s last_error=%s gle=%lu enter_elapsed_ms=%llu outer_elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(address),
                size,
                attached_pid(),
                status().c_str(),
                err.empty() ? "(empty)" : err.c_str(),
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(enter_elapsed_ms),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            diag::log_tagged_fmt("driver_bridge",
                "read_memory_for_exit pid=%u tid=%lu addr=0x%llX size=%zu ok=0 outer_elapsed_ms=%llu enter_elapsed_ms=%llu kernel_call_elapsed_ms=0 reason=enter_failed",
                pid,
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(address),
                size,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long long>(enter_elapsed_ms));
            return false;
        }
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const target_context_snapshot_t target = capture_target_context_snapshot();
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        const ULONGLONG t_kernel_start = GetTickCount64();
        bool ok = read_memory(address, size, out);
        if (ok && !validate_target_context_snapshot("read_memory_for", target)) {
            out.clear();
            ok = false;
        }
        const ULONGLONG kernel_call_elapsed_ms = GetTickCount64() - t_kernel_start;
        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        const ULONGLONG outer_elapsed_ms = GetTickCount64() - t0;
        diag::log_tagged_fmt("driver_bridge",
            "read_memory_for pid=%u active_pid=%u tid=%lu addr=0x%llX size=%zu ok=%d bytes=%zu dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s all_zero=%d first16=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX enter_elapsed_ms=%llu kernel_call_elapsed_ms=%llu outer_elapsed_ms=%llu",
            pid,
            attached_pid(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            ok ? 1 : 0,
            out.size(),
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long>(GetLastError()),
            last_error().empty() ? "<empty>" : last_error().c_str(),
            bytes_all_zero(out.data(), out.size()) ? 1 : 0,
            format_byte_prefix(out.data(), out.size()).c_str(),
            region_before.ok ? 1 : 0,
            region_after.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect),
            static_cast<unsigned long long>(enter_elapsed_ms),
            static_cast<unsigned long long>(kernel_call_elapsed_ms),
            static_cast<unsigned long long>(outer_elapsed_ms));
        diag::log_tagged_fmt("driver_bridge",
            "read_memory_for_exit pid=%u tid=%lu addr=0x%llX size=%zu ok=%d outer_elapsed_ms=%llu enter_elapsed_ms=%llu kernel_call_elapsed_ms=%llu",
            pid,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            ok ? 1 : 0,
            static_cast<unsigned long long>(outer_elapsed_ms),
            static_cast<unsigned long long>(enter_elapsed_ms),
            static_cast<unsigned long long>(kernel_call_elapsed_ms));
        return ok;
    }

    bool write_memory_for(uint32_t pid, uint64_t address, const std::vector<uint8_t>& data)
    {
        const ULONGLONG t0 = GetTickCount64();
        const uint32_t active_before = attached_pid();
        const uint64_t generation_before = g_active_pid_generation.load(std::memory_order_acquire);
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            const DWORD gle = GetLastError();
            const std::string err = last_error();
            diag::log_tagged_fmt("driver_bridge",
                "write_memory_for_enter_failed pid=%u active_pid_before=%u active_pid_after=%u generation_before=%llu generation_after=%llu addr=0x%llX size=%zu status=%s last_error=%s gle=%lu elapsed_ms=%llu",
                pid,
                active_before,
                attached_pid(),
                static_cast<unsigned long long>(generation_before),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(address),
                data.size(),
                status().c_str(),
                err.empty() ? "<empty>" : err.c_str(),
                static_cast<unsigned long>(gle),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        const uint32_t active_after_enter = attached_pid();
        const uint64_t generation_after_enter = g_active_pid_generation.load(std::memory_order_acquire);
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const target_context_snapshot_t target = capture_target_context_snapshot();
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        SetLastError(ERROR_SUCCESS);
        bool ok = write_memory(address, data);
        if (ok && !validate_target_context_snapshot("write_memory_for", target))
            ok = false;
        const DWORD gle = GetLastError();
        const std::string err = last_error();
        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        diag::log_tagged_fmt("driver_bridge",
            "write_memory_for_result pid=%u active_pid_before=%u active_pid_after_enter=%u active_pid_after=%u generation_before=%llu generation_after_enter=%llu generation_after=%llu tid=%lu addr=0x%llX size=%zu ok=%d backend=kernel_driver dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s expected_first16=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX elapsed_ms=%llu",
            pid,
            active_before,
            active_after_enter,
            attached_pid(),
            static_cast<unsigned long long>(generation_before),
            static_cast<unsigned long long>(generation_after_enter),
            static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            data.size(),
            ok ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long>(gle),
            err.empty() ? "<empty>" : err.c_str(),
            format_byte_prefix(data.data(), data.size()).c_str(),
            region_before.ok ? 1 : 0,
            region_after.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool query_memory_for(uint32_t pid, uint64_t address, memory_region_t& region)
    {
        region = {};
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return false;
        const target_context_snapshot_t target = capture_target_context_snapshot();
        if (!query_memory(address, region) || !validate_target_context_snapshot("query_memory_for", target)) {
            region = {};
            return false;
        }
        return true;
    }

    bool protect_memory_for_bounded(uint32_t pid, uint64_t address, uint64_t size,
                                    uint32_t new_protect, uint32_t* old_protect,
                                    uint32_t deadline_ms)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "protect_memory_for_bounded_enter_failed pid=%u active_pid=%u addr=0x%llX size=0x%llX new=0x%08X deadline_ms=%u status=%s last_error=%s gle=%lu elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                static_cast<unsigned int>(new_protect),
                deadline_ms,
                status().c_str(),
                last_error().empty() ? "<empty>" : last_error().c_str(),
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver_bridge",
                "protect_memory_for_bounded_no_kernel pid=%u deadline_ms=%u", pid, deadline_ms);
            return false;
        }
        const uint64_t dtb_entry = device->get_dtb();
        diag::log_tagged_fmt("driver_bridge",
            "protect_memory_for_about_to_call pid=%u addr=0x%llX size=0x%llX new=0x%08X deadline_ms=%u diag_id=%s dtb=0x%llX",
            pid,
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned int>(new_protect),
            deadline_ms,
            driver_bridge::current_remote_call_diag_id(),
            static_cast<unsigned long long>(dtb_entry));
        uint32_t local_old = 0;
        bool ok = device->protect_memory_bounded(address, size, new_protect,
            old_protect ? old_protect : &local_old, deadline_ms);
        DWORD post_err = ok ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("driver_bridge",
            "protect_memory_for_bounded_post pid=%u active_pid=%u tid=%lu addr=0x%llX size=0x%llX new=0x%08X old=0x%08X ok=%d gle=%lu deadline_ms=%u elapsed_ms=%llu",
            pid,
            attached_pid(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned int>(old_protect ? *old_protect : local_old),
            ok ? 1 : 0,
            static_cast<unsigned long>(post_err),
            deadline_ms,
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool protect_memory_for(uint32_t pid, uint64_t address, uint64_t size,
                            uint32_t new_protect, uint32_t* old_protect)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "protect_memory_for_enter_failed pid=%u active_pid=%u addr=0x%llX size=0x%llX new=0x%08X status=%s last_error=%s gle=%lu elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                static_cast<unsigned int>(new_protect),
                status().c_str(),
                last_error().empty() ? "<empty>" : last_error().c_str(),
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        uint32_t local_old = 0;
        bool ok = protect_memory(address, size, new_protect, old_protect ? old_protect : &local_old);
        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        diag::log_tagged_fmt("driver_bridge",
            "protect_memory_for pid=%u active_pid=%u tid=%lu addr=0x%llX size=0x%llX new=0x%08X old=0x%08X ok=%d dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX elapsed_ms=%llu",
            pid,
            attached_pid(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned int>(old_protect ? *old_protect : local_old),
            ok ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long>(GetLastError()),
            last_error().empty() ? "<empty>" : last_error().c_str(),
            region_before.ok ? 1 : 0,
            region_after.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<module_info_t> enumerate_modules_for(uint32_t pid)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_for_enter_failed requested_pid=%u active_pid=%u status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return {};
        }
        auto result = enumerate_modules();
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_for_exit requested_pid=%u active_pid=%u count=%llu status=%s last_error=%s elapsed_ms=%llu",
            pid,
            attached_pid(),
            static_cast<unsigned long long>(result.size()),
            status().c_str(),
            last_error().c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<thread_info_t> enumerate_threads_for(uint32_t pid)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return {};
        return enumerate_threads();
    }

    std::vector<memory_region_t> enumerate_memory_regions_for(uint32_t pid, size_t max_regions)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return {};
        return enumerate_memory_regions(max_regions);
    }

    bool read_peb_for(uint32_t pid, peb_info_t& out)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return false;
        return read_peb(out);
    }

    uint64_t resolve_export_for(uint32_t pid, uint64_t module_base, const char* export_name)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_for_enter_failed pid=%u active_pid=%u module=0x%llX export=%s status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(module_base),
                export_name ? export_name : "(null)",
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        const uint32_t active = attached_pid();
        const uint64_t resolved = resolve_export(module_base, export_name);
        diag::log_tagged_fmt("driver_bridge",
            "resolve_export_for pid=%u active_pid=%u module=0x%llX export=%s result=0x%llX elapsed_ms=%llu",
            pid,
            active,
            static_cast<unsigned long long>(module_base),
            export_name ? export_name : "(null)",
            static_cast<unsigned long long>(resolved),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return resolved;
    }

    uint64_t resolve_export_for_kernel_strict(uint32_t pid, uint64_t module_base, const char* export_name)
    {
        const ULONGLONG t0 = GetTickCount64();
        if (pid == 0 || module_base == 0 || !export_name || !*export_name) {
            SetLastError(ERROR_INVALID_PARAMETER);
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_for_kernel_strict_reject pid=%u active_pid=%u module=0x%llX export=%s reason=invalid_args elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(module_base),
                export_name ? export_name : "(null)",
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }

        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_for_kernel_strict_enter_failed pid=%u active_pid=%u module=0x%llX export=%s status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(module_base),
                export_name,
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }

        bool kernel_mode = false;
        voyager::device_t* device_snapshot = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            device_snapshot = device.get();
        }
        if (!kernel_mode || !device_snapshot) {
            require_kernel_fail("resolve_export_for_kernel_strict");
            SetLastError(ERROR_NOT_READY);
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_for_kernel_strict_fail_closed pid=%u active_pid=%u module=0x%llX export=%s kernel_mode=%d status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(module_base),
                export_name,
                kernel_mode ? 1 : 0,
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }

        SetLastError(ERROR_SUCCESS);
        const uint32_t active = attached_pid();
        const uint64_t resolved = device_snapshot->resolve_export(module_base, export_name);
        DWORD gle = resolved != 0 ? ERROR_SUCCESS : GetLastError();
        if (resolved == 0 && gle == ERROR_SUCCESS)
            gle = ERROR_NOT_FOUND;
        diag::log_tagged_fmt("driver_bridge",
            "resolve_export_for_kernel_strict pid=%u active_pid=%u module=0x%llX export=%s result=0x%llX gle=%lu elapsed_ms=%llu",
            pid,
            active,
            static_cast<unsigned long long>(module_base),
            export_name,
            static_cast<unsigned long long>(resolved),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        if (resolved == 0)
            SetLastError(gle);
        return resolved;
    }

    uint64_t allocate_memory_for(uint32_t pid, size_t size)
    {
        const ULONGLONG t0 = GetTickCount64();
        const uint32_t active_before = attached_pid();
        const uint64_t generation_before = g_active_pid_generation.load(std::memory_order_acquire);
        if (size == 0) {
            diag::log_tagged_fmt("driver_bridge",
                "allocate_memory_for_reject pid=%u active_pid=%u generation=%llu size=%zu protection=unspecified reason=zero elapsed_ms=%llu",
                pid,
                active_before,
                static_cast<unsigned long long>(generation_before),
                size,
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            const DWORD gle = GetLastError();
            const std::string err = last_error();
            diag::log_tagged_fmt("driver_bridge",
                "allocate_memory_for_enter_failed pid=%u active_pid_before=%u active_pid_after=%u generation_before=%llu generation_after=%llu size=%zu protection=unspecified status=%s last_error=%s gle=%lu elapsed_ms=%llu",
                pid,
                active_before,
                attached_pid(),
                static_cast<unsigned long long>(generation_before),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                size,
                status().c_str(),
                err.empty() ? "<empty>" : err.c_str(),
                static_cast<unsigned long>(gle),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        const uint32_t active = attached_pid();
        const uint64_t generation_after_enter = g_active_pid_generation.load(std::memory_order_acquire);
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        diag::log_tagged_fmt("driver_bridge",
            "allocate_memory_for_begin pid=%u active_pid_before=%u active_pid_after_enter=%u generation_before=%llu generation_after_enter=%llu size=%zu protection=unspecified backend=kernel_driver dtb_entry=0x%llX elapsed_ms=%llu",
            pid,
            active_before,
            active,
            static_cast<unsigned long long>(generation_before),
            static_cast<unsigned long long>(generation_after_enter),
            size,
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        SetLastError(ERROR_SUCCESS);
        const uint64_t remote = allocate_memory(size);
        const DWORD gle = GetLastError();
        const std::string err = last_error();
        const bridge_region_snapshot_t region_after = remote != 0 ? capture_bridge_region_snapshot(remote) : bridge_region_snapshot_t{};
        diag::log_tagged_fmt("driver_bridge",
            "allocate_memory_for_result pid=%u active_pid_before=%u active_pid_after_enter=%u active_pid_after=%u generation_before=%llu generation_after_enter=%llu generation_after=%llu tid=%lu size=%zu protection=unspecified backend=kernel_driver result=0x%llX ok=%d dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s region_ok=%d region_base=0x%llX region_size=0x%llX state=0x%lX protect=0x%lX type=0x%lX elapsed_ms=%llu",
            pid,
            active_before,
            active,
            attached_pid(),
            static_cast<unsigned long long>(generation_before),
            static_cast<unsigned long long>(generation_after_enter),
            static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long>(GetCurrentThreadId()),
            size,
            static_cast<unsigned long long>(remote),
            remote != 0 ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long>(gle),
            err.empty() ? "<empty>" : err.c_str(),
            region_after.ok ? 1 : 0,
            static_cast<unsigned long long>(region_after.base),
            static_cast<unsigned long long>(region_after.size),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect),
            static_cast<unsigned long>(region_after.type),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return remote;
    }

    bool free_memory_for(uint32_t pid, uint64_t address)
    {
        const ULONGLONG t0 = GetTickCount64();
        if (address == 0) {
            diag::log_tagged_fmt("driver_bridge",
                "free_memory_for_reject pid=%u addr=0x%llX reason=zero elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "free_memory_for_enter_failed pid=%u active_pid=%u addr=0x%llX status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(address),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            SetLastError(ERROR_INVALID_HANDLE);
            return false;
        }
        const uint32_t active = attached_pid();
        const uint64_t dtb_entry = device ? device->get_dtb() : 0;
        const bridge_region_snapshot_t region_before = capture_bridge_region_snapshot(address);
        const bool ok = free_memory(address);
        const bridge_region_snapshot_t region_after = capture_bridge_region_snapshot(address);
        diag::log_tagged_fmt("driver_bridge",
            "free_memory_for pid=%u active_pid=%u tid=%lu addr=0x%llX ok=%d dtb_entry=0x%llX dtb_exit=0x%llX gle=%lu driver_last_error=%s region_before_ok=%d region_after_ok=%d state_before=0x%lX protect_before=0x%lX state_after=0x%lX protect_after=0x%lX elapsed_ms=%llu",
            pid,
            active,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            ok ? 1 : 0,
            static_cast<unsigned long long>(dtb_entry),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long>(GetLastError()),
            last_error().empty() ? "<empty>" : last_error().c_str(),
            region_before.ok ? 1 : 0,
            region_after.ok ? 1 : 0,
            static_cast<unsigned long>(region_before.state),
            static_cast<unsigned long>(region_before.protect),
            static_cast<unsigned long>(region_after.state),
            static_cast<unsigned long>(region_after.protect),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }


    bool read_kernel_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        target_context_lock_t target_lock("read_kernel_memory");
        out.clear();
        if (size == 0)
            return false;

        bool kernel_mode = false;
        uint64_t current_dtb = 0;
        uint64_t current_kernel_dtb = 0;
        uint32_t current_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            current_pid = g_pid;
            if (device) {
                current_dtb = device->get_dtb();
                current_kernel_dtb = device->get_kernel_dtb();
            }
        }
        if (!kernel_mode) {
            require_kernel_fail("read_kernel_memory");
            return false;
        }

        out.resize(size);
        const size_t bytes_read = device->read_kernel_raw(address, out.data(), size);
        if (bytes_read == 0) {
            static std::atomic<int> s_kernel_read_fail_logs{0};
            const int log_index = s_kernel_read_fail_logs.fetch_add(1);
            if (log_index < 160) {
                diag::log_tagged_fmt("driver_bridge",
                    "read_kernel_memory_failed addr=0x%llX size=%llu pid=%u dtb=0x%llX kdtb=0x%llX connected=%d",
                    static_cast<unsigned long long>(address),
                    static_cast<unsigned long long>(size),
                    current_pid,
                    static_cast<unsigned long long>(current_dtb),
                    static_cast<unsigned long long>(current_kernel_dtb),
                    device && device->is_connected() ? 1 : 0);
            }
            out.clear();
            return false;
        }
        out.resize(bytes_read);
        clear_last_error_after_success("read_kernel_memory");
        return true;
    }

    bool write_kernel_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        target_context_lock_t target_lock("write_kernel_memory");
        if (data.empty())
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("write_kernel_memory");
            return false;
        }

        const size_t bytes_written = device->write_kernel_raw(address, data.data(), data.size());
        if (bytes_written != data.size()) {
            diag::log_tagged_fmt("driver_bridge",
                "write_kernel_memory_failed addr=0x%llX requested=%llu written=%llu complete=0 pid=%u dtb=0x%llX kdtb=0x%llX connected=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(bytes_written),
                attached_pid(),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0),
                static_cast<unsigned long long>(device ? device->get_kernel_dtb() : 0),
                device && device->is_connected() ? 1 : 0);
            std::lock_guard<std::mutex> lk(g_state_mtx);
            set_last_error_locked(
                "Kernel memory write was partial: requested=" + std::to_string(data.size()) +
                " written=" + std::to_string(bytes_written), false);
            return false;
        }
        clear_last_error_after_success("write_kernel_memory");
        return true;
    }

    uint64_t allocate_memory(size_t size)
    {
        target_context_lock_t target_lock("allocate_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        const ULONGLONG t0 = GetTickCount64();
        if (size == 0)
            return 0;

        bool kernel_mode = false;
        bool kernel_attached = false;
        uint32_t active_pid_snapshot = 0;
        uint64_t dtb_snapshot = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
            active_pid_snapshot = g_pid;
            dtb_snapshot = device ? device->get_dtb() : 0;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "allocate_memory_kernel_required pid=%u sz=%llu kernel=%d attached=%d dtb=0x%llX elapsed_ms=%llu",
                active_pid_snapshot,
                static_cast<unsigned long long>(size),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                static_cast<unsigned long long>(dtb_snapshot),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            require_kernel_fail("allocate_memory");
            return 0;
        }

        SetLastError(ERROR_SUCCESS);
        const uint64_t remote = device->allocate_memory(size);
        if (remote != 0 && !validate_target_context_snapshot("allocate_memory", target))
            return 0;
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("driver",
            "allocate_memory_kernel pid=%u sz=%llu addr=0x%llX ok=%d gle=%lu dtb_entry=0x%llX dtb_exit=0x%llX elapsed_ms=%llu",
            active_pid_snapshot,
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(remote),
            remote != 0 ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(dtb_snapshot),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        if (remote != 0)
            clear_last_error_after_success("allocate_memory_kernel");
        return remote;
    }

    bool free_memory(uint64_t address)
    {
        target_context_lock_t target_lock("free_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        if (address == 0)
            return false;

        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "free_memory_kernel_required addr=0x%llX kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("free_memory");
            return false;
        }

        const bool ok = device->free_memory(address);
        if (ok && !validate_target_context_snapshot("free_memory", target))
            return false;
        diag::log_tagged_fmt("driver",
            "free_memory kernel addr=0x%llX ok=%d",
            static_cast<unsigned long long>(address), ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("free_memory_kernel");
        return ok;
    }

    bool protect_memory(uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect)
    {
        target_context_lock_t target_lock("protect_memory");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached || size == 0) {
            diag::log_tagged_fmt("driver",
                "protect_memory_kernel_required addr=0x%llX sz=0x%llX protect=0x%X kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                new_protect,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("protect_memory");
            return false;
        }

        const bool ok = device->protect_memory(address, size, new_protect, old_protect);
        if (ok && !validate_target_context_snapshot("protect_memory", target))
            return false;
        diag::log_tagged_fmt("driver",
            "protect_memory kernel addr=0x%llX sz=0x%llX protect=0x%X ok=%d",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            new_protect, ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("protect_memory_kernel");
        return ok;
    }


    bool get_thread_context(uint32_t tid, thread_context_t& ctx)
    {
        target_context_lock_t target_lock("get_thread_context");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "get_thread_context_kernel_required tid=%u kernel=%d attached=%d bypass=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("get_thread_context");
            return false;
        }

        voyager::device_t::thread_context kctx{};
        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        if (!device->get_thread_context(tid, kctx)) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("get_thread_context", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "get_thread_context_kernel_failed tid=%u gle=%lu attached_pid=%u elapsed_ms=%llu fail_closed=1",
                tid,
                gle,
                pid,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
            return false;
        }
        note_tctx_kernel_success();

        ctx.rax = kctx.rax;  ctx.rbx = kctx.rbx;  ctx.rcx = kctx.rcx;  ctx.rdx = kctx.rdx;
        ctx.rsi = kctx.rsi;  ctx.rdi = kctx.rdi;  ctx.rbp = kctx.rbp;  ctx.rsp = kctx.rsp;
        ctx.r8  = kctx.r8;   ctx.r9  = kctx.r9;   ctx.r10 = kctx.r10;  ctx.r11 = kctx.r11;
        ctx.r12 = kctx.r12;  ctx.r13 = kctx.r13;  ctx.r14 = kctx.r14;  ctx.r15 = kctx.r15;
        ctx.rip = kctx.rip;  ctx.rflags = kctx.rflags;
        ctx.cs  = kctx.cs;   ctx.ss  = kctx.ss;
        ctx.dr0 = kctx.dr0;  ctx.dr1 = kctx.dr1;  ctx.dr2 = kctx.dr2;  ctx.dr3 = kctx.dr3;
        ctx.dr6 = kctx.dr6;  ctx.dr7 = kctx.dr7;
        if (ctx.rip == 0 || ctx.rsp == 0 || ctx.rflags == 0) {
            diag::log_tagged_fmt("driver",
                "get_thread_context_REJECTED_ZERO tid=%u rip=0x%llX rsp=0x%llX rflags=0x%llX fail_closed=1",
                tid,
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                static_cast<unsigned long long>(ctx.rflags));
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
        if (!validate_target_context_snapshot("get_thread_context", target)) {
            ctx = {};
            return false;
        }
        diag::log_tagged_fmt("driver",
            "get_thread_context_kernel_ok tid=%u rip=0x%llX rsp=0x%llX dr7=0x%llX",
            tid,
            static_cast<unsigned long long>(ctx.rip),
            static_cast<unsigned long long>(ctx.rsp),
            static_cast<unsigned long long>(ctx.dr7));
        return true;
    }

    bool set_thread_context(uint32_t tid, const thread_context_t& ctx, uint64_t register_mask)
    {
        target_context_lock_t target_lock("set_thread_context");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "set_thread_context_kernel_required tid=%u mask=0x%llX kernel=%d attached=%d bypass=%d",
                tid,
                static_cast<unsigned long long>(register_mask),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("set_thread_context");
            return false;
        }

        voyager::device_t::thread_context kctx{};
        kctx.rax = ctx.rax;  kctx.rbx = ctx.rbx;  kctx.rcx = ctx.rcx;  kctx.rdx = ctx.rdx;
        kctx.rsi = ctx.rsi;  kctx.rdi = ctx.rdi;  kctx.rbp = ctx.rbp;  kctx.rsp = ctx.rsp;
        kctx.r8  = ctx.r8;   kctx.r9  = ctx.r9;   kctx.r10 = ctx.r10;  kctx.r11 = ctx.r11;
        kctx.r12 = ctx.r12;  kctx.r13 = ctx.r13;  kctx.r14 = ctx.r14;  kctx.r15 = ctx.r15;
        kctx.rip = ctx.rip;  kctx.rflags = ctx.rflags;
        kctx.cs  = ctx.cs;   kctx.ss  = ctx.ss;
        kctx.dr0 = ctx.dr0;  kctx.dr1 = ctx.dr1;  kctx.dr2 = ctx.dr2;  kctx.dr3 = ctx.dr3;
        kctx.dr6 = ctx.dr6;  kctx.dr7 = ctx.dr7;
        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->set_thread_context(tid, kctx, register_mask);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("set_thread_context", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "set_thread_context_KERNEL_FAILED tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX attached_pid=%u kernel_mode=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                tid,
                static_cast<unsigned long long>(register_mask),
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                pid,
                kernel_mode ? 1 : 0,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
            diag::log_tagged_fmt("driver",
                "set_thread_context_kernel_ok tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX dr7=0x%llX",
                tid,
                static_cast<unsigned long long>(register_mask),
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                static_cast<unsigned long long>(ctx.dr7));
        }
        if (ok && !validate_target_context_snapshot("set_thread_context", target))
            return false;
        return ok;
    }

    bool suspend_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "suspend_thread_kernel_required tid=%u kernel=%d attached=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("suspend_thread");
            return false;
        }

        bool ok = device->suspend_thread(tid, prev_count);
        if (!ok) {
            DWORD gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "suspend_thread_kernel_failed tid=%u gle=%lu fail_closed=1",
                tid,
                gle);
            SetLastError(gle);
        }
        return ok;
    }

    bool resume_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "resume_thread_kernel_required tid=%u kernel=%d attached=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("resume_thread");
            return false;
        }

        bool ok = device->resume_thread(tid, prev_count);
        if (!ok) {
            DWORD gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "resume_thread_kernel_failed tid=%u gle=%lu fail_closed=1",
                tid,
                gle);
            SetLastError(gle);
        }
        return ok;
    }

    bool query_thread_information(uint32_t tid, uint32_t info_class, void* buffer, uint32_t buffer_size, uint32_t* return_length)
    {
        if (return_length != nullptr)
            *return_length = 0;
        if (tid == 0 || buffer == nullptr || buffer_size == 0)
            return false;
        if (info_class != 0)
            return false;

        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "query_thread_information_kernel_required tid=%u class=%u size=%u kernel=%d attached=%d",
                tid,
                info_class,
                buffer_size,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("query_thread_information");
            return false;
        }

        voyager::detail::thread_query_information_request info{};
        if (!device->query_thread_basic_information(tid, info)) {
            diag::log_tagged_fmt("driver",
                "query_thread_information_kernel_failed tid=%u status=0x%08X",
                tid,
                info.status);
            SetLastError(ERROR_GEN_FAILURE);
            return false;
        }

        struct teb_basic_t {
            long      exit_status;
            void*     teb_base;
            void*     unique_process;
            void*     unique_thread;
            uintptr_t affinity_mask;
            long      priority;
            long      base_priority;
        };
        if (buffer_size < sizeof(teb_basic_t)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return false;
        }
        teb_basic_t out{};
        out.exit_status = static_cast<long>(info.exit_status);
        out.teb_base = reinterpret_cast<void*>(static_cast<uintptr_t>(info.teb_base));
        out.unique_process = reinterpret_cast<void*>(static_cast<uintptr_t>(info.client_process));
        out.unique_thread = reinterpret_cast<void*>(static_cast<uintptr_t>(info.client_thread));
        out.affinity_mask = static_cast<uintptr_t>(info.affinity_mask);
        out.priority = static_cast<long>(info.priority);
        out.base_priority = static_cast<long>(info.base_priority);
        std::memcpy(buffer, &out, sizeof(out));
        if (return_length != nullptr)
            *return_length = sizeof(out);
        clear_last_error_after_success("query_thread_information_kernel");
        return true;
    }

    bool terminate_thread(uint32_t tid, uint32_t exit_status)
    {
        if (tid == 0)
            return false;
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "terminate_thread_kernel_required tid=%u exit=0x%08X kernel=%d attached=%d",
                tid,
                exit_status,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("terminate_thread");
            return false;
        }
        const bool ok = device->terminate_thread(tid, exit_status);
        diag::log_tagged_fmt("driver",
            "terminate_thread_kernel tid=%u exit=0x%08X ok=%d",
            tid,
            exit_status,
            ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("terminate_thread_kernel");
        return ok;
    }

    bool close_process_handle(uint32_t pid, uint64_t handle_value)
    {
        if (pid == 0 || handle_value == 0)
            return false;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "close_process_handle_kernel_required pid=%u handle=0x%llX kernel=%d",
                pid,
                static_cast<unsigned long long>(handle_value),
                kernel_mode ? 1 : 0);
            require_kernel_fail("close_process_handle");
            return false;
        }
        const bool ok = device->close_process_handle(pid, handle_value);
        diag::log_tagged_fmt("driver",
            "close_process_handle_kernel pid=%u handle=0x%llX ok=%d",
            pid,
            static_cast<unsigned long long>(handle_value),
            ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("close_process_handle_kernel");
        return ok;
    }


    bool read_peb(peb_info_t& out)
    {
        target_context_lock_t target_lock("read_peb");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("read_peb");
            return false;
        }

        voyager::device_t::peb_info kpeb{};
        if (!device->read_peb(kpeb))
            return false;

        if (!validate_target_context_snapshot("read_peb", target)) {
            out = {};
            return false;
        }

        out.peb_address     = kpeb.peb_address;
        out.image_base      = kpeb.image_base;
        out.being_debugged  = kpeb.being_debugged;
        out.nt_global_flag  = kpeb.nt_global_flag;
        out.ldr_address     = kpeb.ldr_address;
        out.process_heap    = kpeb.process_heap;
        out.number_of_heaps = kpeb.number_of_heaps;
        out.max_heaps       = kpeb.max_heaps;
        out.process_heaps   = kpeb.process_heaps;
        return true;
    }

    bool usermode_module_base(uint64_t module_base)
    {
        return module_base != 0 && module_base < 0x0000800000000000ULL;
    }

    bool read_process_exact(uint64_t address, void* buffer, size_t size)
    {
        if (address == 0 || !buffer || size == 0)
            return false;
        std::vector<uint8_t> bytes;
        if (!read_memory(address, size, bytes) || bytes.size() < size)
            return false;
        std::memcpy(buffer, bytes.data(), size);
        return true;
    }

    std::string read_process_c_string(uint64_t address, size_t max_len)
    {
        if (address == 0 || max_len == 0 || max_len > 4096)
            return {};
        std::vector<uint8_t> bytes;
        if (!read_memory(address, max_len, bytes) || bytes.empty())
            return {};
        std::string out;
        out.reserve((std::min<size_t>)(bytes.size(), max_len));
        for (uint8_t b : bytes) {
            if (b == 0)
                break;
            if (b < 0x20 || b > 0x7E)
                return {};
            out.push_back(static_cast<char>(b));
            if (out.size() >= max_len)
                break;
        }
        return out;
    }

    uint64_t resolve_export_usermode_pe(uint64_t module_base, const char* export_name, uint32_t* ordinal_out)
    {
        if (!usermode_module_base(module_base) || !export_name || !*export_name)
            return 0;

        IMAGE_DOS_HEADER dos{};
        if (!read_process_exact(module_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
            return 0;

        const uint64_t nt_va = module_base + static_cast<uint32_t>(dos.e_lfanew);
        DWORD sig = 0;
        if (!read_process_exact(nt_va, &sig, sizeof(sig)) || sig != IMAGE_NT_SIGNATURE)
            return 0;

        IMAGE_FILE_HEADER fh{};
        if (!read_process_exact(nt_va + sizeof(DWORD), &fh, sizeof(fh)))
            return 0;
        if (fh.NumberOfSections == 0 || fh.NumberOfSections > 128)
            return 0;

        const uint64_t opt_va = nt_va + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        WORD magic = 0;
        if (!read_process_exact(opt_va, &magic, sizeof(magic)))
            return 0;

        DWORD export_rva = 0;
        DWORD export_size = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt{};
            if (!read_process_exact(opt_va, &opt, sizeof(opt)))
                return 0;
            if (IMAGE_DIRECTORY_ENTRY_EXPORT >= opt.NumberOfRvaAndSizes)
                return 0;
            export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 opt{};
            if (!read_process_exact(opt_va, &opt, sizeof(opt)))
                return 0;
            if (IMAGE_DIRECTORY_ENTRY_EXPORT >= opt.NumberOfRvaAndSizes)
                return 0;
            export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            return 0;
        }

        if (export_rva == 0 || export_size < sizeof(IMAGE_EXPORT_DIRECTORY))
            return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if (!read_process_exact(module_base + export_rva, &exp, sizeof(exp)))
            return 0;
        if (exp.NumberOfNames == 0 || exp.NumberOfFunctions == 0 ||
            exp.AddressOfNames == 0 || exp.AddressOfNameOrdinals == 0 || exp.AddressOfFunctions == 0)
            return 0;

        const DWORD name_count = (std::min<DWORD>)(exp.NumberOfNames, 65536u);
        const ULONGLONG export_walk_started_ms = GetTickCount64();
        for (DWORD i = 0; i < name_count; ++i) {
            if ((i & 0x0F) == 0) {
                const bool cancelled = mcp_standalone::current_call_cancelled();
                const uint64_t deadline_ms = mcp_standalone::current_call_deadline_ms();
                const ULONGLONG now_tick = GetTickCount64();
                if (cancelled || (deadline_ms != 0 && now_tick >= deadline_ms)) {
                    diag::log_tagged_fmt("driver_bridge",
                        "resolve_export_user_fallback_cancelled module=0x%llX export=%s names_scanned=%u name_count=%u elapsed_ms=%llu cancelled=%d deadline_ms=%llu diag_id=%s",
                        static_cast<unsigned long long>(module_base),
                        export_name,
                        static_cast<unsigned int>(i),
                        static_cast<unsigned int>(name_count),
                        static_cast<unsigned long long>(now_tick - export_walk_started_ms),
                        cancelled ? 1 : 0,
                        static_cast<unsigned long long>(deadline_ms),
                        mcp_standalone::current_call_diag_id());
                    SetLastError(ERROR_CANCELLED);
                    return 0;
                }
            }
            DWORD name_rva = 0;
            WORD ordinal_index = 0;
            if (!read_process_exact(module_base + exp.AddressOfNames + static_cast<uint64_t>(i) * sizeof(DWORD),
                                    &name_rva, sizeof(name_rva)) || name_rva == 0)
                continue;
            if (!read_process_exact(module_base + exp.AddressOfNameOrdinals + static_cast<uint64_t>(i) * sizeof(WORD),
                                    &ordinal_index, sizeof(ordinal_index)))
                continue;
            if (ordinal_index >= exp.NumberOfFunctions)
                continue;
            const std::string candidate = read_process_c_string(module_base + name_rva, 512);
            if (candidate != export_name)
                continue;

            DWORD func_rva = 0;
            if (!read_process_exact(module_base + exp.AddressOfFunctions + static_cast<uint64_t>(ordinal_index) * sizeof(DWORD),
                                    &func_rva, sizeof(func_rva)) || func_rva == 0)
                return 0;
            if (func_rva >= export_rva && func_rva < export_rva + export_size)
                return 0;
            if (ordinal_out)
                *ordinal_out = exp.Base + ordinal_index;
            return module_base + func_rva;
        }

        return 0;
    }

    uint64_t resolve_export(uint64_t module_base, const char* export_name)
    {
        target_context_lock_t target_lock("resolve_export");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        if (module_base == 0 || !export_name || !*export_name)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            uint32_t ordinal = 0;
            const uint64_t fallback = resolve_export_usermode_pe(module_base, export_name, &ordinal);
            if (fallback != 0)
                return fallback;
            require_kernel_fail("resolve_export");
            return 0;
        }

        const uint64_t resolved = device->resolve_export(module_base, export_name);
        if (resolved != 0 && !validate_target_context_snapshot("resolve_export", target))
            return 0;
        if (resolved != 0)
            return resolved;
        if (!usermode_module_base(module_base))
            return 0;

        uint32_t ordinal = 0;
        const uint64_t fallback = resolve_export_usermode_pe(module_base, export_name, &ordinal);
        static std::atomic<int> s_export_fallback_logs{0};
        const int log_index = s_export_fallback_logs.fetch_add(1);
        if (log_index < 160) {
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_user_fallback module=0x%llX export=%s result=0x%llX ordinal=%u kernel_mode=%d",
                static_cast<unsigned long long>(module_base),
                export_name,
                static_cast<unsigned long long>(fallback),
                ordinal,
                kernel_mode ? 1 : 0);
        }
        return fallback;
    }

    uint64_t virtual_to_physical(uint64_t virtual_address)
    {
        target_context_lock_t target_lock("virtual_to_physical");
        const target_context_snapshot_t target = capture_target_context_snapshot();
        if (virtual_address == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("virtual_to_physical");
            return 0;
        }

        const uint64_t physical = device->virtual_to_physical(virtual_address);
        return validate_target_context_snapshot("virtual_to_physical", target) ? physical : 0;
    }


    std::vector<net_connection_info_t> enumerate_connections(uint32_t filter_pid, uint32_t filter_protocol)
    {
        const ULONGLONG t0 = GetTickCount64();
        std::vector<net_connection_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("enumerate_connections");
            return result;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "enumerate_connections ENTER filter_pid=%u filter_protocol=%u",
            filter_pid, filter_protocol);
        SetLastError(ERROR_SUCCESS);
        auto raw = device->enumerate_connections(filter_pid, filter_protocol);
        const DWORD ioctl_gle = GetLastError();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_connection_info_t c;
            c.pid            = src.pid;
            c.protocol       = src.protocol;
            c.state          = src.state;
            c.local_port     = src.local_port;
            c.remote_port    = src.remote_port;
            c.address_family = src.address_family;
            std::memcpy(c.local_addr,  src.local_addr,  sizeof(c.local_addr));
            std::memcpy(c.remote_addr, src.remote_addr, sizeof(c.remote_addr));
            std::memcpy(c.process_path, src.process_path, sizeof(c.process_path));
            result.push_back(c);
        }
        diag::log_tagged_fmt("driver_bridge_net",
            "enumerate_connections EXIT filter_pid=%u filter_protocol=%u raw=%zu mapped=%zu gle=%lu elapsed_ms=%llu",
            filter_pid, filter_protocol, raw.size(), result.size(),
            static_cast<unsigned long>(ioctl_gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }


    bool start_capture(uint32_t filter_pid, uint32_t filter_port, uint32_t filter_protocol, const uint8_t* filter_ip, uint32_t max_payload)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        logf("start_capture: kernel_mode=%d pid=%u port=%u proto=%u\n", kernel_mode ? 1 : 0, filter_pid, filter_port, filter_protocol);
        if (!kernel_mode) {
            require_kernel_fail("start_capture");
            return false;
        }

        bool result = device->start_capture(filter_pid, filter_port, filter_protocol, filter_ip, max_payload);
        logf("start_capture: device->start_capture returned %d\n", result ? 1 : 0);
        return result;
    }

    bool stop_capture()
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stop_capture");
            return false;
        }

        bool ok = device->stop_capture();
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "stop_capture EXIT ok=%d gle=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool get_capture_status(bool& active, uint32_t& captured, uint32_t& dropped)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_capture_status ABORT kernel_mode=false");
            return false;
        }

        bool ok = device->get_capture_status(active, captured, dropped);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_capture_status EXIT ok=%d active=%d captured=%u dropped=%u gle=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            active ? 1 : 0,
            captured,
            dropped,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<captured_packet_t> get_captured_packets(uint32_t max_packets)
    {
        std::vector<captured_packet_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            logf("get_captured_packets: kernel_mode=false, returning empty\n");
            return result;
        }

        auto raw = device->get_captured_packets(max_packets);
        logf("get_captured_packets: got %zu raw packets\n", raw.size());
        diag::log_tagged_fmt("driver_bridge_net",
            "get_captured_packets EXIT max=%u raw=%zu kernel_mode=1",
            max_packets,
            raw.size());
        result.reserve(raw.size());
        for (auto& src : raw) {
            captured_packet_t pkt;
            pkt.timestamp      = src.timestamp;
            pkt.pid            = src.pid;
            pkt.protocol       = src.protocol;
            pkt.direction      = src.direction;
            pkt.payload_size   = src.payload_size;
            pkt.local_port     = src.local_port;
            pkt.remote_port    = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr,  src.local_addr,  sizeof(pkt.local_addr));
            std::memcpy(pkt.remote_addr, src.remote_addr, sizeof(pkt.remote_addr));
            pkt.payload = std::move(src.payload);
            result.push_back(std::move(pkt));
        }
        return result;
    }

    std::vector<captured_packet_t> get_captured_packets_bounded(uint32_t max_packets, uint32_t deadline_ms)
    {
        const ULONGLONG t0 = GetTickCount64();
        std::vector<captured_packet_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver_bridge_net",
                "get_captured_packets_bounded SKIP kernel_mode=0 max=%u deadline_ms=%u",
                max_packets, deadline_ms);
            return result;
        }
        auto raw = device->get_captured_packets_bounded(max_packets, deadline_ms);
        diag::log_tagged_fmt("driver_bridge_net",
            "get_captured_packets_bounded EXIT max=%u deadline_ms=%u raw=%zu kernel_mode=1 elapsed_ms=%llu",
            max_packets,
            deadline_ms,
            raw.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        result.reserve(raw.size());
        for (auto& src : raw) {
            captured_packet_t pkt;
            pkt.timestamp      = src.timestamp;
            pkt.pid            = src.pid;
            pkt.protocol       = src.protocol;
            pkt.direction      = src.direction;
            pkt.payload_size   = src.payload_size;
            pkt.local_port     = src.local_port;
            pkt.remote_port    = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr,  src.local_addr,  sizeof(pkt.local_addr));
            std::memcpy(pkt.remote_addr, src.remote_addr, sizeof(pkt.remote_addr));
            pkt.payload = std::move(src.payload);
            result.push_back(std::move(pkt));
        }
        return result;
    }

    void cancel_inflight_capture()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver_bridge_net",
                "cancel_inflight_capture SKIP kernel_mode=0");
            return;
        }
        device->cancel_inflight_capture();
        diag::log_tagged_fmt("driver_bridge_net", "cancel_inflight_capture dispatched");
    }


    std::vector<dns_entry_t> get_dns_queries(uint32_t filter_pid)
    {
        std::vector<dns_entry_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            logf("get_dns_queries: kernel_mode=false, returning empty\n");
            return result;
        }

        SetLastError(ERROR_SUCCESS);
        auto raw = device->get_dns_queries(filter_pid);
        const DWORD ioctl_gle = GetLastError();
        logf("get_dns_queries: got %zu raw entries (filter_pid=%u) gle=%lu\n", raw.size(), filter_pid, ioctl_gle);
        result.reserve(raw.size());
        for (auto& src : raw) {
            dns_entry_t entry;
            entry.timestamp     = src.timestamp;
            entry.pid           = src.pid;
            entry.query_type    = src.query_type;
            entry.domain        = std::move(src.domain);
            std::memcpy(entry.resolved_addr, src.resolved_addr, sizeof(entry.resolved_addr));
            entry.response_code = src.response_code;
            entry.ttl           = src.ttl;
            result.push_back(std::move(entry));
        }
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }


    bool add_filter_rule(uint32_t action, uint32_t direction, uint32_t protocol, uint32_t pid, uint32_t port, const uint8_t* ip_addr, const uint8_t* ip_mask, uint32_t* out_rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("add_filter_rule");
            return false;
        }

        return device->add_filter_rule(action, direction, protocol, pid, port, ip_addr, ip_mask, out_rule_id);
    }

    bool remove_filter_rule(uint32_t rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("remove_filter_rule");
            return false;
        }

        return device->remove_filter_rule(rule_id);
    }

    bool clear_filter_rules()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("clear_filter_rules");
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        const bool ok = device->clear_filter_rules();
        if (ok) {
            SetLastError(ERROR_SUCCESS);
        }
        return ok;
    }


    bool get_network_stats(network_stats_t& stats)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        voyager::device_t::network_stats ks{};
        SetLastError(ERROR_SUCCESS);
        if (!device->get_network_stats(ks))
            return false;

        stats.bytes_sent          = ks.bytes_sent;
        stats.bytes_received      = ks.bytes_received;
        stats.packets_sent        = ks.packets_sent;
        stats.packets_received    = ks.packets_received;
        stats.active_connections  = ks.active_connections;
        stats.capture_active      = ks.capture_active;
        stats.total_captured      = ks.total_captured;
        stats.total_dropped       = ks.total_dropped;
        stats.total_dns_logged    = ks.total_dns_logged;
        stats.active_filter_rules = ks.active_filter_rules;
        SetLastError(ERROR_SUCCESS);
        return true;
    }

    bool bw_monitor_op(uint32_t operation, uint32_t filter_pid, bw_stats_t* out_stats)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("bw_monitor_op");
            return false;
        }

        voyager::device_t::bw_stats raw{};
        bool ok = device->bw_monitor_op(operation, filter_pid, out_stats ? &raw : nullptr);
        DWORD gle = ok ? 0 : GetLastError();
        if (ok && out_stats) {
            out_stats->total_bytes_sent    = raw.total_bytes_sent;
            out_stats->total_bytes_recv    = raw.total_bytes_recv;
            out_stats->total_packets_sent  = raw.total_packets_sent;
            out_stats->total_packets_recv  = raw.total_packets_recv;
            out_stats->bps_in              = raw.bps_in;
            out_stats->bps_out             = raw.bps_out;
            out_stats->active              = raw.active;
        }
        diag::log_tagged_fmt("driver_bridge_net",
            "bw_monitor_op EXIT op=%u filter_pid=%u ok=%d active=%d sent=%llu recv=%llu pkts_sent=%llu pkts_recv=%llu gle=%lu elapsed_ms=%llu",
            operation,
            filter_pid,
            ok ? 1 : 0,
            raw.active ? 1 : 0,
            static_cast<unsigned long long>(raw.total_bytes_sent),
            static_cast<unsigned long long>(raw.total_bytes_recv),
            static_cast<unsigned long long>(raw.total_packets_sent),
            static_cast<unsigned long long>(raw.total_packets_recv),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid)
    {
        std::vector<bw_process_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return result;

        auto raw = device->get_bw_per_process(filter_pid);
        diag::log_tagged_fmt("driver_bridge_net",
            "get_bw_per_process EXIT filter_pid=%u raw=%zu",
            filter_pid,
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            bw_process_info_t bw;
            bw.pid           = src.pid;
            bw.bytes_sent    = src.bytes_sent;
            bw.bytes_recv    = src.bytes_recv;
            bw.packets_sent  = src.packets_sent;
            bw.packets_recv  = src.packets_recv;
            bw.last_activity = src.last_activity;
            result.push_back(bw);
        }
        return result;
    }


    uint64_t call_function(uint64_t function_address, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
    {
        const ULONGLONG call_start = GetTickCount64();
        const remote_call_snapshot_t call_ctx = capture_remote_call_snapshot();
        const uint64_t call_id = g_remote_call_sequence.fetch_add(1, std::memory_order_acq_rel);
        const uint32_t active_at_entry = attached_pid();
        const uint64_t generation_at_entry = g_active_pid_generation.load(std::memory_order_acquire);
        g_last_remote_call_execution_diag = {};
        g_last_remote_call_execution_diag.call_id = call_id;
        g_last_remote_call_execution_diag.function_address = function_address;
        g_last_remote_call_execution_diag.pid = call_ctx.pid;
        g_last_remote_call_execution_diag.active_pid_entry = active_at_entry;
        g_last_remote_call_execution_diag.generation_at_entry = generation_at_entry;
        g_last_remote_call_execution_diag.timeout_ms = call_ctx.timeout_ms;
        diag::log_tagged_fmt("driver",
            "call_function_entry call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled=%d require_deadline=%d allow_zero=%d context=%d",
            static_cast<unsigned long long>(call_id),
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            active_at_entry,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(arg1),
            static_cast<unsigned long long>(arg2),
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(arg4),
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, call_start)),
            call_ctx.cancelled ? 1 : 0,
            call_ctx.require_deadline ? 1 : 0,
            call_ctx.allow_zero_result ? 1 : 0,
            call_ctx.context_active ? 1 : 0);
        if (function_address == 0) {
            SetLastError(ERROR_INVALID_PARAMETER);
            diag::log_tagged_fmt("driver",
                "call_function_reject call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=invalid_function elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(function_address),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }
        if (call_ctx.require_deadline && call_ctx.deadline_ms == 0) {
            SetLastError(ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_reject call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX reason=missing_required_deadline timeout_ms=%u elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(function_address),
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }
        if (call_ctx.cancelled || (call_ctx.deadline_ms != 0 && call_start >= call_ctx.deadline_ms)) {
            SetLastError(call_ctx.cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_deadline_preempt call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(function_address),
                call_ctx.cancelled ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("call_function");
            diag::log_tagged_fmt("driver",
                "call_function_kernel_unavailable call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(function_address),
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        if (current_remote_call_cancelled() || (call_ctx.deadline_ms != 0 && GetTickCount64() >= call_ctx.deadline_ms)) {
            const bool cancelled = current_remote_call_cancelled();
            SetLastError(cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_deadline_before_device call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(function_address),
                cancelled ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        diag::log_tagged_fmt("driver",
            "call_function_device_wait_begin call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u generation=%llu fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            attached_pid(),
            static_cast<unsigned long long>(g_active_pid_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(function_address),
            current_remote_call_cancelled() ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, GetTickCount64())),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        voyager::device_t* device_snapshot = device.get();
        auto device_outcome = run_bounded_lower_remote_call("device",
            call_id,
            call_ctx,
            active_at_entry,
            generation_at_entry,
            function_address,
            call_start,
            [device_snapshot, function_address, arg1, arg2, arg3, arg4, allow_zero_result = call_ctx.allow_zero_result](uint64_t& result, DWORD& gle, bool& zero_result_rejected) -> bool {
                result = 0;
                zero_result_rejected = false;
                if (!device_snapshot || !device_snapshot->is_connected()) {
                    gle = ERROR_INVALID_HANDLE;
                    return false;
                }
                SetLastError(ERROR_SUCCESS);
                result = device_snapshot->call_function(function_address, arg1, arg2, arg3, arg4);
                gle = GetLastError();
                if (result != 0) {
                    gle = ERROR_SUCCESS;
                    return true;
                }
                if (allow_zero_result && gle == ERROR_SUCCESS)
                    return true;
                zero_result_rejected = true;
                if (gle == ERROR_SUCCESS)
                    gle = ERROR_GEN_FAILURE;
                return false;
            });
        if (!device_outcome.completed) {
            SetLastError(device_outcome.gle);
            diag::log_tagged_fmt("driver",
                "call_function_device_wait_done call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX result=0x%llX ok=0 lower_completed=%d lower_ok=%d lower_reason=%s gle=%lu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d late_completion=%d lower_uninterruptible=%d stale_generation=%d elapsed_ms=%llu status=%s last_error=%s",
                static_cast<unsigned long long>(call_id),
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                active_at_entry,
                device_outcome.active_pid_after,
                static_cast<unsigned long long>(generation_at_entry),
                static_cast<unsigned long long>(device_outcome.generation_after),
                static_cast<unsigned long long>(function_address),
                0ull,
                device_outcome.completed ? 1 : 0,
                device_outcome.lower_ok ? 1 : 0,
                device_outcome.completion_reason.c_str(),
                static_cast<unsigned long>(device_outcome.gle),
                device_outcome.cancelled ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                device_outcome.deadline_expired ? 1 : 0,
                1,
                lower_remote_call_uninterruptible(device_outcome) ? 1 : 0,
                device_outcome.stale_generation ? 1 : 0,
                static_cast<unsigned long long>(device_outcome.elapsed_ms),
                status().c_str(),
                last_error().c_str());
            return 0;
        }
        const uint64_t result = device_outcome.result;
        const bool device_success = device_outcome.lower_ok && !device_outcome.stale_generation && !device_outcome.cancelled && !device_outcome.deadline_expired;
        const DWORD gle = device_success ? ERROR_SUCCESS : device_outcome.gle;
        diag::log_tagged_fmt("driver",
            "call_function_device_wait_done call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX result=0x%llX ok=%d lower_completed=%d lower_ok=%d lower_reason=%s gle=%lu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d late_completion=%d lower_uninterruptible=%d stale_generation=%d elapsed_ms=%llu status=%s last_error=%s",
            static_cast<unsigned long long>(call_id),
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            active_at_entry,
            device_outcome.active_pid_after,
            static_cast<unsigned long long>(generation_at_entry),
            static_cast<unsigned long long>(device_outcome.generation_after),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(result),
            device_success ? 1 : 0,
            device_outcome.completed ? 1 : 0,
            device_outcome.lower_ok ? 1 : 0,
            device_outcome.completion_reason.c_str(),
            static_cast<unsigned long>(device_outcome.stale_generation ? ERROR_OPERATION_ABORTED : (device_outcome.cancelled ? ERROR_CANCELLED : (device_outcome.deadline_expired ? ERROR_TIMEOUT : gle))),
            device_outcome.cancelled ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            device_outcome.deadline_expired ? 1 : 0,
            (device_outcome.deadline_expired || device_outcome.stale_generation || device_outcome.cancelled) ? 1 : 0,
            lower_remote_call_uninterruptible(device_outcome) ? 1 : 0,
            device_outcome.stale_generation ? 1 : 0,
            static_cast<unsigned long long>(device_outcome.elapsed_ms),
            status().c_str(),
            last_error().c_str());
        if (device_outcome.stale_generation || device_outcome.cancelled || device_outcome.deadline_expired) {
            SetLastError(device_outcome.stale_generation ? ERROR_OPERATION_ABORTED : (device_outcome.cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT));
            if (device_outcome.stale_generation) {
                diag::log_tagged_fmt("driver",
                    "call_function_stale_reject call_id=%llu phase=device label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u generation=%llu generation_after=%llu fn=0x%llX elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    call_ctx.label,
                    call_ctx.tool,
                    call_ctx.diag_id,
                    call_ctx.pid,
                    active_at_entry,
                    device_outcome.active_pid_after,
                    static_cast<unsigned long long>(generation_at_entry),
                    static_cast<unsigned long long>(device_outcome.generation_after),
                    static_cast<unsigned long long>(function_address),
                    static_cast<unsigned long long>(device_outcome.elapsed_ms));
            }
            return 0;
        }
        if (!device_success) {
            SetLastError(gle);
            return 0;
        }
        SetLastError(ERROR_SUCCESS);
        return result;
    }

    uint64_t find_gadget(const char* pattern, size_t pattern_size)
    {
        if (!pattern || pattern_size == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("find_gadget");
            return 0;
        }

        return device->find_gadget(pattern, pattern_size);
    }

    bool set_hardware_breakpoint(uint32_t tid, int index, uint64_t address, int type, int size)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "set_hardware_breakpoint_kernel_required tid=%u index=%d addr=0x%llX type=%d size=%d kernel=%d attached=%d bypass=%d",
                tid,
                index,
                static_cast<unsigned long long>(address),
                type,
                size,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("set_hardware_breakpoint");
            return false;
        }

        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->set_hardware_breakpoint(tid, index, address, type, size);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("set_hardware_breakpoint", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "set_hardware_breakpoint_kernel_failed pid=%u tid=%u index=%d addr=0x%llX type=%d size=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                pid,
                tid,
                index,
                static_cast<unsigned long long>(address),
                type,
                size,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
        }
        return ok;
    }

    bool clear_hardware_breakpoint(uint32_t tid, int index)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "clear_hardware_breakpoint_kernel_required tid=%u index=%d kernel=%d attached=%d bypass=%d",
                tid,
                index,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("clear_hardware_breakpoint");
            return false;
        }

        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->clear_hardware_breakpoint(tid, index);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("clear_hardware_breakpoint", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "clear_hardware_breakpoint_kernel_failed pid=%u tid=%u index=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                pid,
                tid,
                index,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
        }
        return ok;
    }

    bool spoof_debug_flags(uint32_t* result_flags)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("spoof_debug_flags");
            return false;
        }

        return device->spoof_debug_flags(result_flags);
    }

    uint64_t driver_watchdog_age_ms()
    {
        const uint64_t last_ok = g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire);
        if (last_ok == 0)
            return 0;
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        return now >= last_ok ? now - last_ok : 0;
    }

    bool malware_safe_protect_pid(uint32_t pid, uint32_t flags, uint64_t* out_denials)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "malware_safe_protect_pid skip_kernel_mode pid=%u flags=0x%08X",
                pid, flags);
            return false;
        }
        bool ok = device->protect_sandbox_pid(pid, flags, out_denials);
        diag::log_tagged_fmt("driver",
            "malware_safe_protect_pid pid=%u flags=0x%08X ok=%d",
            pid, flags, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_unprotect_pid(uint32_t pid, uint64_t* out_denials)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        bool ok = device->unprotect_sandbox_pid(pid, out_denials);
        diag::log_tagged_fmt("driver",
            "malware_safe_unprotect_pid pid=%u ok=%d",
            pid, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_net_log(uint32_t pid, bool enable)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        bool ok = device->net_log_register_pid(pid, enable);
        diag::log_tagged_fmt("driver",
            "malware_safe_net_log pid=%u enable=%d ok=%d",
            pid, enable ? 1 : 0, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_pull_packets(uint32_t pid, uint32_t max_records,
                                   std::vector<packet_record_t>& out,
                                   uint64_t* out_dropped)
    {
        out.clear();
        if (out_dropped) *out_dropped = 0;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "malware_safe_pull_packets skip_kernel_mode pid=%u max=%u",
                pid, max_records);
            return false;
        }
        std::vector<voyager::detail::net_packet_record> raw;
        uint64_t dropped = 0;
        bool ok = device->malware_safe_pull_packets(pid, max_records, raw, &dropped);
        if (out_dropped) *out_dropped = dropped;
        if (!ok) {
            diag::log_tagged_fmt("driver",
                "malware_safe_pull_packets FAILED pid=%u max=%u",
                pid, max_records);
            return false;
        }
        out.reserve(raw.size());
        for (const auto& r : raw) {
            packet_record_t pr{};
            pr.timestamp = r.timestamp;
            pr.tcp_seq = r.tcp_seq;
            pr.pid = r.pid;
            pr.payload_len = r.payload_len;
            pr.flags = r.flags;
            pr.local_port = r.local_port;
            pr.remote_port = r.remote_port;
            pr.address_family = r.address_family;
            pr.protocol = r.protocol;
            pr.direction = r.direction;
            for (int i = 0; i < 16; ++i) pr.local_addr[i] = r.local_addr[i];
            for (int i = 0; i < 16; ++i) pr.remote_addr[i] = r.remote_addr[i];
            for (int i = 0; i < 256; ++i) pr.payload[i] = r.payload[i];
            out.push_back(pr);
        }
        diag::log_tagged_fmt("driver",
            "malware_safe_pull_packets pid=%u max=%u returned=%zu dropped_since=%llu",
            pid, max_records, out.size(), (unsigned long long)dropped);
        return true;
    }

    bool traffic_redirect_op(uint32_t operation, uint32_t rule_id, uint32_t protocol,
                             uint32_t match_port, const uint8_t* match_addr,
                             uint32_t redirect_port, const uint8_t* redirect_addr,
                             uint32_t af, uint32_t* out_rule_id, uint32_t exclude_pid)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("traffic_redirect_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "traffic_redirect_op ENTER op=%u rule_id=%u proto=%u match_port=%u redir_port=%u af=%u exclude_pid=%u match=%02X.%02X.%02X.%02X redir=%02X.%02X.%02X.%02X",
            operation, rule_id, protocol, match_port, redirect_port, af, exclude_pid,
            match_addr ? match_addr[0] : 0, match_addr ? match_addr[1] : 0,
            match_addr ? match_addr[2] : 0, match_addr ? match_addr[3] : 0,
            redirect_addr ? redirect_addr[0] : 0, redirect_addr ? redirect_addr[1] : 0,
            redirect_addr ? redirect_addr[2] : 0, redirect_addr ? redirect_addr[3] : 0);
        bool ok = device->traffic_redirect_op(operation, rule_id, protocol, match_port, match_addr,
                                              redirect_port, redirect_addr, af, out_rule_id, exclude_pid);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "traffic_redirect_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool inject_packet(uint32_t direction, uint32_t protocol, uint32_t af,
                       uint32_t src_port, uint32_t dst_port,
                       const uint8_t* src_addr, const uint8_t* dst_addr,
                       const uint8_t* payload, uint32_t payload_size,
                       uint32_t tcp_flags, uint32_t tcp_seq, uint32_t tcp_ack)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("inject_packet");
            return false;
        }

        return device->inject_packet(direction, protocol, af, src_port, dst_port,
                                     src_addr, dst_addr, payload, payload_size,
                                     tcp_flags, tcp_seq, tcp_ack);
    }

    bool kill_connection(uint32_t protocol, uint32_t af,
                         uint32_t src_port, uint32_t dst_port,
                         const uint8_t* src_addr, const uint8_t* dst_addr,
                         uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("kill_connection");
            return false;
        }

        return device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    }

    bool intercept_op(uint32_t operation, uint32_t filter_pid, uint32_t filter_port,
                      uint32_t filter_protocol, uint64_t hold_id,
                      const uint8_t* modify_payload, uint32_t modify_size,
                      uint32_t* out_held_count, bool* out_active)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("intercept_op");
            SetLastError(ERROR_INVALID_HANDLE);
            diag::log_tagged_fmt("driver_bridge_net",
                "intercept_op EXIT op=%u pid=%u port=%u proto=%u hold_id=%llu ok=0 preserved_gle=%lu attached_pid=%u kernel_mode=0 status=%s driver_error=%s elapsed_ms=%llu",
                operation,
                filter_pid,
                filter_port,
                filter_protocol,
                static_cast<unsigned long long>(hold_id),
                static_cast<unsigned long>(ERROR_INVALID_HANDLE),
                attached_pid(),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "intercept_op ENTER op=%u pid=%u port=%u proto=%u hold_id=%llu modify_size=%u attached_pid=%u kernel_mode=%d status=%s",
            operation, filter_pid, filter_port, filter_protocol,
            static_cast<unsigned long long>(hold_id), modify_size,
            attached_pid(), kernel_mode ? 1 : 0, status().c_str());
        SetLastError(ERROR_SUCCESS);
        bool ok = device->intercept_op(operation, filter_pid, filter_port, filter_protocol,
                                       hold_id, modify_payload, modify_size,
                                       out_held_count, out_active);
        DWORD gle = GetLastError();
        if (!ok && gle == ERROR_SUCCESS)
            gle = ERROR_GEN_FAILURE;
        diag::log_tagged_fmt("driver_bridge_net",
            "intercept_op EXIT op=%u pid=%u port=%u proto=%u hold_id=%llu ok=%d held_count=%u active=%d preserved_gle=%lu attached_pid=%u kernel_mode=%d status=%s driver_error=%s elapsed_ms=%llu",
            operation, filter_pid, filter_port, filter_protocol,
            static_cast<unsigned long long>(hold_id),
            ok ? 1 : 0,
            out_held_count ? *out_held_count : 0,
            out_active && *out_active ? 1 : 0,
            static_cast<unsigned long>(ok ? ERROR_SUCCESS : gle),
            attached_pid(),
            kernel_mode ? 1 : 0,
            status().c_str(),
            last_error().c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        SetLastError(ok ? ERROR_SUCCESS : gle);
        return ok;
    }

    bool dns_spoof_op(uint32_t operation, uint32_t rule_id, const char* domain,
                      const uint8_t* spoof_addr, uint32_t af,
                      uint32_t ttl, uint32_t* out_rule_id)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("dns_spoof_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "dns_spoof_op ENTER op=%u rule_id=%u domain=\"%.96s\" af=%u ttl=%u spoof=%02X.%02X.%02X.%02X",
            operation, rule_id, domain ? domain : "", af, ttl,
            spoof_addr ? spoof_addr[0] : 0, spoof_addr ? spoof_addr[1] : 0,
            spoof_addr ? spoof_addr[2] : 0, spoof_addr ? spoof_addr[3] : 0);
        SetLastError(ERROR_SUCCESS);
        bool ok = device->dns_spoof_op(operation, rule_id, domain, spoof_addr, af, ttl, out_rule_id);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "dns_spoof_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        SetLastError(ok ? ERROR_SUCCESS : gle);
        return ok;
    }

    bool packet_mod_rule_op(uint32_t operation, uint32_t rule_id,
                            uint32_t direction, uint32_t protocol,
                            uint32_t port, uint32_t pid,
                            const uint8_t* pattern, uint32_t pattern_size,
                            const uint8_t* replacement, uint32_t replace_size,
                            uint32_t* out_rule_id)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("packet_mod_rule_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "packet_mod_rule_op ENTER op=%u rule_id=%u dir=%u proto=%u port=%u pid=%u pattern_size=%u replace_size=%u",
            operation, rule_id, direction, protocol, port, pid, pattern_size, replace_size);
        bool ok = device->packet_mod_rule_op(operation, rule_id, direction, protocol,
                                             port, pid, pattern, pattern_size,
                                             replacement, replace_size, out_rule_id);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "packet_mod_rule_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool stream_reassemble_op(uint32_t operation, uint32_t src_port, uint32_t dst_port,
                              uint32_t pid, const uint8_t* src_addr,
                              const uint8_t* dst_addr,
                              std::vector<uint8_t>* out_data,
                              uint32_t* out_packets, uint32_t* out_truncated)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stream_reassemble_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "stream_reassemble_op ENTER op=%u src_port=%u dst_port=%u pid=%u src=%02X.%02X.%02X.%02X dst=%02X.%02X.%02X.%02X",
            operation, src_port, dst_port, pid,
            src_addr ? src_addr[0] : 0, src_addr ? src_addr[1] : 0,
            src_addr ? src_addr[2] : 0, src_addr ? src_addr[3] : 0,
            dst_addr ? dst_addr[0] : 0, dst_addr ? dst_addr[1] : 0,
            dst_addr ? dst_addr[2] : 0, dst_addr ? dst_addr[3] : 0);
        bool ok = device->stream_reassemble_op(operation, src_port, dst_port, pid,
                                               src_addr, dst_addr, out_data,
                                               out_packets, out_truncated);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "stream_reassemble_op EXIT op=%u ok=%d data_size=%zu packets=%u truncated=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_data ? out_data->size() : 0,
            out_packets ? *out_packets : 0, out_truncated ? *out_truncated : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool sniff_net_buffers_start(uint64_t address, uint32_t buf_reg, uint32_t size_reg,
                                 uint32_t max_captures, uint32_t tid, uint32_t bp_index)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_start");
            return false;
        }

        return device->sniff_net_buffers_start(address, buf_reg, size_reg, max_captures, tid, bp_index);
    }

    bool sniff_net_buffers_stop()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_stop");
            return false;
        }

        return device->sniff_net_buffers_stop();
    }

    std::vector<sniff_result_t> sniff_net_buffers_get(bool& active)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            active = false;
            return {};
        }

        auto raw = device->sniff_net_buffers_get(active);
        std::vector<sniff_result_t> out;
        out.reserve(raw.size());
        for (auto& r : raw) {
            sniff_result_t sr;
            sr.timestamp = r.timestamp;
            sr.thread_id = r.thread_id;
            sr.buffer    = std::move(r.buffer);
            out.push_back(std::move(sr));
        }
        return out;
    }

    std::vector<dpi_result_t> get_dpi_results(uint32_t filter_pid, uint32_t filter_protocol, uint32_t filter_port, uint32_t flags)
    {
        std::vector<dpi_result_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver_bridge_net",
                "get_dpi_results ABORT kernel_mode=false filter_pid=%u proto=%u port=%u flags=0x%X",
                filter_pid, filter_protocol, filter_port, flags);
            return result;
        }

        auto raw = device->get_dpi_results(filter_pid, filter_protocol, filter_port, flags);
        diag::log_tagged_fmt("driver_bridge_net",
            "get_dpi_results EXIT filter_pid=%u proto=%u port=%u flags=0x%X raw=%zu",
            filter_pid, filter_protocol, filter_port, flags, raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dpi_result_t d;
            d.timestamp      = src.timestamp;
            d.direction      = src.direction;
            d.protocol       = src.protocol;
            d.src_port       = src.src_port;
            d.dst_port       = src.dst_port;
            d.pid            = src.pid;
            d.payload_size   = src.payload_size;
            d.af             = src.af;
            std::memcpy(d.src_addr, src.src_addr, 16);
            std::memcpy(d.dst_addr, src.dst_addr, 16);
            d.tcp_flags      = src.tcp_flags;
            d.tcp_window     = src.tcp_window;
            d.is_http        = src.is_http;
            d.is_tls         = src.is_tls;
            d.is_dns         = src.is_dns;
            d.http_method    = src.http_method;
            d.tls_version    = src.tls_version;
            d.tls_content_type = src.tls_content_type;
            d.http_host      = src.http_host;
            d.http_path      = src.http_path;
            d.tls_sni        = src.tls_sni;
            result.push_back(std::move(d));
        }
        return result;
    }

    std::vector<wfp_callout_info_t> enumerate_wfp_callouts(const std::string& filter_module)
    {
        std::vector<wfp_callout_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        SetLastError(ERROR_SUCCESS);
        auto raw = device->enumerate_wfp_callouts(filter_module);
        const DWORD ioctl_gle = GetLastError();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            wfp_callout_info_t c;
            c.classify_fn          = src.classify_fn;
            c.notify_fn            = src.notify_fn;
            c.flow_delete_fn       = src.flow_delete_fn;
            c.owning_module_base   = src.owning_module_base;
            c.filter_id            = src.filter_id;
            c.callout_id           = src.callout_id;
            c.layer_id             = src.layer_id;
            c.flags                = src.flags;
            c.entry_type           = src.entry_type;
            c.action_type          = src.action_type;
            c.provider_present     = src.provider_present;
            c.aida_match_reason    = src.aida_match_reason;
            c.callout_key_str      = src.callout_key_str;
            c.applicable_layer_str = src.applicable_layer_str;
            c.sublayer_key_str     = src.sublayer_key_str;
            c.owning_module        = src.owning_module;
            result.push_back(std::move(c));
        }
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }

    std::vector<socket_info_t> get_socket_handles(uint32_t target_pid)
    {
        std::vector<socket_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        SetLastError(ERROR_SUCCESS);
        auto raw = device->get_socket_handles(target_pid);
        const DWORD ioctl_gle = GetLastError();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            socket_info_t s;
            s.handle_value     = src.handle_value;
            s.afd_endpoint_addr = src.afd_endpoint_addr;
            s.pid              = src.pid;
            s.protocol         = src.protocol;
            s.state            = src.state;
            s.local_port       = src.local_port;
            s.remote_port      = src.remote_port;
            s.address_family   = src.address_family;
            std::memcpy(s.local_addr, src.local_addr, 16);
            std::memcpy(s.remote_addr, src.remote_addr, 16);
            result.push_back(s);
        }
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }

    std::vector<tcpip_connection_t> dump_tcpip_connections(uint32_t target_pid, uint32_t filter_protocol)
    {
        std::vector<tcpip_connection_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        SetLastError(ERROR_SUCCESS);
        auto raw = device->dump_tcpip_connections(target_pid, filter_protocol);
        const DWORD ioctl_gle = GetLastError();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            tcpip_connection_t c;
            c.tcb_address        = src.tcb_address;
            c.owning_module_base = src.owning_module_base;
            c.pid                = src.pid;
            c.protocol           = src.protocol;
            c.state              = src.state;
            c.local_port         = src.local_port;
            c.remote_port        = src.remote_port;
            c.address_family     = src.address_family;
            std::memcpy(c.local_addr, src.local_addr, 16);
            std::memcpy(c.remote_addr, src.remote_addr, 16);
            c.create_time        = src.create_time;
            c.bytes_in           = src.bytes_in;
            c.bytes_out          = src.bytes_out;
            result.push_back(c);
        }
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }

    std::vector<net_iface_info_t> enumerate_interfaces()
    {
        std::vector<net_iface_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        SetLastError(ERROR_SUCCESS);
        auto raw = device->enumerate_interfaces();
        const DWORD ioctl_gle = GetLastError();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_iface_info_t ifc;
            ifc.if_index    = src.if_index;
            ifc.if_type     = src.if_type;
            ifc.mtu         = src.mtu;
            ifc.oper_status = src.oper_status;
            ifc.speed       = src.speed;
            std::memcpy(ifc.mac_addr, src.mac_addr, 6);
            std::memcpy(ifc.ipv4_addr, src.ipv4_addr, 4);
            std::memcpy(ifc.ipv4_mask, src.ipv4_mask, 4);
            std::memcpy(ifc.ipv6_addr, src.ipv6_addr, 16);
            ifc.name        = src.name;
            ifc.description = src.description;
            ifc.in_octets   = src.in_octets;
            ifc.out_octets  = src.out_octets;
            result.push_back(std::move(ifc));
        }
        if (!raw.empty()) {
            SetLastError(ERROR_SUCCESS);
        } else {
            SetLastError(ioctl_gle);
        }
        return result;
    }

    std::vector<held_packet_info_t> get_held_packets()
    {
        std::vector<held_packet_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_held_packets ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->get_held_packets();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_held_packets EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (auto& src : raw) {
            held_packet_info_t h;
            h.hold_id      = src.hold_id;
            h.timestamp    = src.timestamp;
            h.direction    = src.direction;
            h.protocol     = src.protocol;
            h.src_port     = src.src_port;
            h.dst_port     = src.dst_port;
            h.pid          = src.pid;
            h.payload_size = src.payload_size;
            h.af           = src.af;
            std::memcpy(h.src_addr, src.src_addr, 16);
            std::memcpy(h.dst_addr, src.dst_addr, 16);
            h.payload      = std::move(src.payload);
            result.push_back(std::move(h));
        }
        return result;
    }

    std::vector<mod_rule_info_t> list_packet_mod_rules()
    {
        std::vector<mod_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_packet_mod_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_packet_mod_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_packet_mod_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            mod_rule_info_t r;
            r.rule_id     = src.rule_id;
            r.direction   = src.direction;
            r.protocol    = src.protocol;
            r.port        = src.port;
            r.pid         = src.pid;
            r.match_count = src.match_count;
            r.active      = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<redirect_rule_info_t> list_redirect_rules()
    {
        std::vector<redirect_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_redirect_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_redirect_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_redirect_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            redirect_rule_info_t r;
            r.rule_id       = src.rule_id;
            r.protocol      = src.protocol;
            r.match_port    = src.match_port;
            r.redirect_port = src.redirect_port;
            r.af            = src.af;
            r.match_count   = src.match_count;
            r.active        = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<dns_spoof_info_t> list_dns_spoof_rules()
    {
        std::vector<dns_spoof_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_dns_spoof_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_dns_spoof_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_dns_spoof_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dns_spoof_info_t r;
            r.rule_id     = src.rule_id;
            r.domain      = src.domain;
            r.af          = src.af;
            r.match_count = src.match_count;
            r.active      = src.active;
            r.ttl         = src.ttl;
            result.push_back(std::move(r));
        }
        return result;
    }

    bool fingerprint_op(uint32_t operation)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("fingerprint_op");
            return false;
        }
        bool ok = device->fingerprint_op(operation);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "fingerprint_op EXIT op=%u ok=%d gle=%lu elapsed_ms=%llu",
            operation,
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<fingerprint_info_t> get_fingerprints()
    {
        std::vector<fingerprint_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_fingerprints ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->get_fingerprints();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_fingerprints EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            fingerprint_info_t f;
            std::memcpy(f.remote_addr, src.remote_addr, 16);
            f.af             = src.af;
            f.ttl            = src.ttl;
            f.window_size    = src.window_size;
            f.mss            = src.mss;
            f.window_scale   = src.window_scale;
            f.df_flag        = src.df_flag;
            f.sack_permitted = src.sack_permitted;
            f.nop_count      = src.nop_count;
            f.os_guess       = src.os_guess;
            result.push_back(std::move(f));
        }
        return result;
    }

    bool export_pcap(uint32_t filter_pid, uint32_t filter_protocol, uint32_t max_packets, pcap_export_result_t* out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("export_pcap");
            return false;
        }

        voyager::device_t::pcap_export_result raw{};
        bool ok = device->export_pcap(filter_pid, filter_protocol, max_packets, out ? &raw : nullptr);
        if (ok && out) {
            out->header.magic_number  = raw.header.magic_number;
            out->header.version_major = raw.header.version_major;
            out->header.version_minor = raw.header.version_minor;
            out->header.thiszone      = raw.header.thiszone;
            out->header.sigfigs       = raw.header.sigfigs;
            out->header.snaplen       = raw.header.snaplen;
            out->header.network       = raw.header.network;
            out->packets.reserve(raw.packets.size());
            for (auto& src : raw.packets) {
                pcap_packet_t p;
                p.ts_sec  = src.ts_sec;
                p.ts_usec = src.ts_usec;
                p.data    = std::move(src.data);
                out->packets.push_back(std::move(p));
            }
        }
        return ok;
    }

    bool drain_debug_events(std::vector<debug_event_t>& out,
                            size_t max_events,
                            debug_event_stats_t* out_stats)
    {
        out.clear();
        if (out_stats) *out_stats = debug_event_stats_t{};

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        std::vector<voyager::device_t::debug_event_record> raw;
        voyager::device_t::debug_event_drain_stats raw_stats{};
        if (!device->drain_debug_events(raw, max_events, &raw_stats))
            return false;

        if (out_stats) {
            out_stats->returned_count = raw_stats.returned_count;
            out_stats->dropped_since_last_drain = raw_stats.dropped_since_last_drain;
            out_stats->total_dropped = raw_stats.total_dropped;
            out_stats->total_published = raw_stats.total_published;
        }

        out.reserve(raw.size());
        for (auto& src : raw) {
            debug_event_t dst;
            dst.type       = static_cast<debug_event_type_e>(static_cast<uint32_t>(src.type));
            dst.process_id = src.process_id;
            dst.thread_id  = src.thread_id;
            dst.flags      = src.flags;
            dst.timestamp  = src.timestamp;
            dst.image_base = src.image_base;
            dst.image_size = src.image_size;
            dst.image_path_wide = std::move(src.image_path);
            dst.image_path = utf8_from_wstring(dst.image_path_wide);
            dst.image_name = extract_basename_utf8(dst.image_path);
            out.push_back(std::move(dst));
        }
        return true;
    }

    uint64_t watchdog_last_ok_tick()
    {
        return g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire);
    }
}

namespace driver_bridge::identity {
namespace {

std::uint64_t filetime_to_u64(const FILETIME& value) noexcept
{
    ULARGE_INTEGER converted{};
    converted.LowPart = value.dwLowDateTime;
    converted.HighPart = value.dwHighDateTime;
    return converted.QuadPart;
}

std::string normalize_identity_text(std::string value)
{
    std::replace(value.begin(), value.end(), '/', '\\');
    for (char& character : value) {
        if (character >= 'A' && character <= 'Z')
            character = static_cast<char>(character - 'A' + 'a');
    }
    return value;
}

std::string module_filename(std::string value)
{
    const std::size_t separator = value.find_last_of("\\\\/");
    if (separator != std::string::npos)
        value.erase(0, separator + 1);
    return value;
}

bool wide_path_to_utf8(const std::wstring& value, std::string& out)
{
    if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return false;
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0)
        return false;
    out.resize(static_cast<std::size_t>(required));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), out.data(), required, nullptr, nullptr) == required;
}

bool capture_identity_impl(std::uint32_t pid, std::uint64_t preferred_module_base,
                           live_target_identity_t& out, staleness_t& out_staleness,
                           std::string& out_detail)
{
    out = {};
    out_staleness = staleness_t::process_unavailable;
    out_detail.clear();
    if (pid == 0) {
        out_detail = "TARGET_STALE: PID is zero";
        return false;
    }
    if (pid == static_cast<std::uint32_t>(GetCurrentProcessId())) {
        out_staleness = staleness_t::self_target_refused;
        out_detail = "SELF_TARGET_REFUSED";
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process) {
        out_detail = "TARGET_STALE: process query failed gle=" + std::to_string(GetLastError());
        return false;
    }
    struct handle_guard_t {
        HANDLE value = nullptr;
        ~handle_guard_t() { if (value) CloseHandle(value); }
    } process_guard{process};

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process, &exit_code)) {
        out_detail = "TARGET_STALE: process status query failed gle=" +
            std::to_string(GetLastError());
        return false;
    }
    if (exit_code != STILL_ACTIVE) {
        out_staleness = staleness_t::process_exited;
        out_detail = "TARGET_STALE: process exited code=" + std::to_string(exit_code);
        return false;
    }

    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        out_detail = "TARGET_STALE: process creation query failed gle=" +
            std::to_string(GetLastError());
        return false;
    }

    std::wstring process_path(32768, L'\0');
    DWORD process_path_size = static_cast<DWORD>(process_path.size());
    if (!QueryFullProcessImageNameW(process, 0, process_path.data(), &process_path_size) ||
        process_path_size == 0) {
        out_detail = "TARGET_STALE: process path query failed gle=" + std::to_string(GetLastError());
        return false;
    }
    process_path.resize(process_path_size);
    std::string process_path_utf8;
    if (!wide_path_to_utf8(process_path, process_path_utf8)) {
        out_detail = "TARGET_STALE: process path encoding failed gle=" + std::to_string(GetLastError());
        return false;
    }

    std::vector<driver_bridge::module_info_t> modules;
    HANDLE module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       static_cast<DWORD>(pid));
    if (module_snapshot == INVALID_HANDLE_VALUE) {
        out_staleness = staleness_t::module_unavailable;
        out_detail = "TARGET_STALE: target module snapshot failed gle=" +
            std::to_string(GetLastError());
        return false;
    }
    handle_guard_t module_snapshot_guard{module_snapshot};
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(module_snapshot, &entry)) {
        out_staleness = staleness_t::module_unavailable;
        out_detail = "TARGET_STALE: target module list is unavailable gle=" +
            std::to_string(GetLastError());
        return false;
    }
    do {
        std::string module_name;
        std::string module_path;
        if (!wide_path_to_utf8(entry.szModule, module_name) ||
            !wide_path_to_utf8(entry.szExePath, module_path)) {
            out_staleness = staleness_t::module_unavailable;
            out_detail = "TARGET_STALE: target module identity encoding failed gle=" +
                std::to_string(GetLastError());
            return false;
        }
        driver_bridge::module_info_t module;
        module.base = reinterpret_cast<std::uint64_t>(entry.modBaseAddr);
        module.size = entry.modBaseSize;
        module.name = std::move(module_name);
        module.path = std::move(module_path);
        modules.push_back(std::move(module));
    } while (Module32NextW(module_snapshot, &entry));

    const std::string normalized_process_path = normalize_identity_text(process_path_utf8);
    const std::string expected_name = module_filename(normalized_process_path);
    const driver_bridge::module_info_t* selected = nullptr;
    if (preferred_module_base != 0) {
        const auto it = std::find_if(modules.begin(), modules.end(),
            [preferred_module_base](const driver_bridge::module_info_t& module) {
                return module.base == preferred_module_base;
            });
        if (it != modules.end())
            selected = &*it;
    } else {
        for (const auto& module : modules) {
            const std::string normalized_module_path = normalize_identity_text(module.path);
            const std::string normalized_module_name = normalize_identity_text(module.name);
            if ((!normalized_module_path.empty() && normalized_module_path == normalized_process_path) ||
                (!normalized_module_name.empty() && normalized_module_name == expected_name)) {
                selected = &module;
                break;
            }
        }
        if (!selected) {
            selected = &*std::min_element(modules.begin(), modules.end(),
                [](const driver_bridge::module_info_t& left,
                   const driver_bridge::module_info_t& right) {
                    return left.base < right.base;
                });
        }
    }

    if (!selected || selected->base == 0 || selected->size == 0) {
        out_staleness = staleness_t::module_unavailable;
        out_detail = "TARGET_STALE: selected module is unavailable";
        return false;
    }
    const std::string normalized_module_path = normalize_identity_text(selected->path);
    std::string normalized_module_name = normalize_identity_text(selected->name);
    if (normalized_module_name.empty())
        normalized_module_name = module_filename(normalized_module_path);
    if (normalized_module_name.empty() || normalized_module_path.empty()) {
        out_staleness = staleness_t::module_unavailable;
        out_detail = "TARGET_STALE: selected module identity is incomplete";
        return false;
    }

    FILETIME observed_at{};
    GetSystemTimeAsFileTime(&observed_at);
    out.process.pid = pid;
    out.process.creation_time_100ns = filetime_to_u64(creation);
    out.process.normalized_process_path = normalized_process_path;
    out.module.base = selected->base;
    out.module.size = selected->size;
    out.module.normalized_name = std::move(normalized_module_name);
    out.module.normalized_path = normalized_module_path;
    out.observed_at_100ns = filetime_to_u64(observed_at);
    out_staleness = staleness_t::none;
    return true;
}

}

const char* staleness_code(staleness_t value) noexcept
{
    switch (value) {
    case staleness_t::none: return "NONE";
    case staleness_t::self_target_refused: return "SELF_TARGET_REFUSED";
    case staleness_t::process_unavailable: return "TARGET_PROCESS_UNAVAILABLE";
    case staleness_t::process_exited: return "TARGET_PROCESS_EXITED";
    case staleness_t::process_identity_changed: return "TARGET_PROCESS_IDENTITY_CHANGED";
    case staleness_t::module_unavailable: return "TARGET_MODULE_UNAVAILABLE";
    case staleness_t::module_identity_changed: return "TARGET_MODULE_IDENTITY_CHANGED";
    }
    return "TARGET_IDENTITY_UNKNOWN";
}

bool capture_live_target_identity(std::uint32_t pid, std::uint64_t preferred_module_base,
                                  live_target_identity_t& out, std::string* out_error)
{
    staleness_t staleness = staleness_t::process_unavailable;
    std::string detail;
    const bool captured = capture_identity_impl(pid, preferred_module_base, out, staleness, detail);
    if (out_error)
        *out_error = captured ? std::string{} : std::string(staleness_code(staleness)) + ": " + detail;
    return captured;
}

validation_result_t validate_attached_target_identity(const live_target_identity_t& expected)
{
    validation_result_t result = validate_live_target_identity(expected);
    if (!result.matches)
        return result;
    std::lock_guard<std::mutex> lk(g_state_mtx);
    const auto found = g_processes.find(expected.process.pid);
    if (found == g_processes.end()) {
        result.matches = false;
        result.staleness = staleness_t::process_unavailable;
        result.detail = "TARGET_STALE: driver context is not attached";
        return result;
    }
    if (!found->second.has_identity) {
        result.matches = false;
        result.staleness = staleness_t::process_identity_changed;
        result.detail = "TARGET_STALE: driver context identity is not bound";
        return result;
    }
    if (!same_live_identity(found->second.identity, expected)) {
        result.matches = false;
        result.staleness = staleness_t::process_identity_changed;
        result.observed = found->second.identity;
        result.detail = "TARGET_STALE: driver context identity changed";
        return result;
    }
    return result;
}

bool refresh_attached_target_identity(const live_target_identity_t& expected,
                                      std::string* out_error)
{
    const auto current = validate_live_target_identity(expected);
    if (!current.matches) {
        if (out_error)
            *out_error = std::string(staleness_code(current.staleness)) + ": " + current.detail;
        return false;
    }
    std::unique_lock<std::mutex> lk(g_state_mtx);
    auto found = g_processes.find(expected.process.pid);
    if (found == g_processes.end()) {
        if (out_error)
            *out_error = "TARGET_DRIVER_CONTEXT_MISSING";
        return false;
    }
    constexpr DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
    unique_handle process(OpenProcess(access, FALSE, expected.process.pid));
    if (!process) {
        if (out_error)
            *out_error = "OpenProcess query failed for PID " +
                std::to_string(expected.process.pid) +
                " (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    process_ctx_t& ctx = found->second;
    release_ctx_handle(ctx);
    ctx.h_process = process.release();
    ctx.has_vm_read = false;
    ctx.name = process_name_from_pid(expected.process.pid);
    ctx.cached_image_base = 0;
    ctx.cached_dtb = 0;
    ctx.cached_kernel_dtb = 0;
    if (g_pid == expected.process.pid) {
        close_process_handle_locked();
        g_process = ctx.h_process;
        ctx.h_process = nullptr;
        g_process_name = ctx.name;
        g_has_vm_read = false;
    }
    if (!refresh_kernel_context_locked(lk, expected.process.pid, ctx,
                                       "refresh_attached_target_identity")) {
        ctx.has_identity = false;
        if (out_error)
            *out_error = "TARGET_DRIVER_CONTEXT_REFRESH_FAILED: " + g_last_error;
        return false;
    }
    ctx.identity = expected;
    ctx.has_identity = true;
    if (g_pid == expected.process.pid) {
        g_kernel_attached = ctx.kernel_attached;
        g_has_vm_read = ctx.has_vm_read;
        if (g_process_name.empty())
            g_process_name = ctx.name;
    }
    if (out_error)
        out_error->clear();
    return true;
}

validation_result_t validate_live_target_identity(const live_target_identity_t& expected)
{
    validation_result_t result;
    if (expected.process.pid == 0 || expected.module.base == 0 || expected.module.size == 0) {
        result.staleness = staleness_t::process_identity_changed;
        result.detail = "TARGET_STALE: expected live target identity is incomplete";
        return result;
    }
    std::string detail;
    if (!capture_identity_impl(expected.process.pid, expected.module.base, result.observed,
                               result.staleness, detail)) {
        result.detail = std::move(detail);
        return result;
    }
    if (result.observed.process.pid != expected.process.pid ||
        result.observed.process.creation_time_100ns != expected.process.creation_time_100ns ||
        result.observed.process.normalized_process_path != expected.process.normalized_process_path) {
        result.staleness = staleness_t::process_identity_changed;
        result.detail = "TARGET_STALE: process creation identity changed";
        return result;
    }
    if (result.observed.module.base != expected.module.base ||
        result.observed.module.size != expected.module.size ||
        result.observed.module.normalized_name != expected.module.normalized_name ||
        result.observed.module.normalized_path != expected.module.normalized_path) {
        result.staleness = staleness_t::module_identity_changed;
        result.detail = "TARGET_STALE: module identity changed";
        return result;
    }
    result.matches = true;
    result.staleness = staleness_t::none;
    return result;
}

}
