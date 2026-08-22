#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../../preview/executor_preview.hpp"

#else

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "taskflow_runtime.hpp"
#include "taskflow_evaluation.hpp"
#include "../diagnostics/metadata_ring.hpp"
#include "../mcp/downstream_producer_governor.hpp"
#include "../../helpers/diag_log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::infra::executor {

enum class domain_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2,
    ui_dispatch = 3,
    external_tool = 4,
    long_running = 5,
    security_liveness = 6,
    feature_worker = 7,
    diagnostics = 8
};

inline constexpr std::size_t domain_count = 9;

inline const char* domain_name(domain_t d) {
    switch (d) {
    case domain_t::general: return "general";
    case domain_t::service: return "service";
    case domain_t::critical: return "critical";
    case domain_t::ui_dispatch: return "ui_dispatch";
    case domain_t::external_tool: return "external_tool";
    case domain_t::long_running: return "long_running";
    case domain_t::security_liveness: return "security_liveness";
    case domain_t::feature_worker: return "feature_worker";
    case domain_t::diagnostics: return "diagnostics";
    default: return "unknown";
    }
}

inline const char* domain_to_queue_name(domain_t d) {
    switch (d) {
    case domain_t::general: return "taskflow_runtime.general";
    case domain_t::service: return "taskflow_runtime.service";
    case domain_t::critical: return "taskflow_runtime.critical";
    case domain_t::ui_dispatch: return "taskflow_runtime.ui_dispatch";
    case domain_t::external_tool: return "taskflow_runtime.external_tool+capacity_governor";
    case domain_t::long_running: return "taskflow_runtime.long_running+downstream_governor";
    case domain_t::security_liveness: return "taskflow_runtime.security_liveness";
    case domain_t::feature_worker: return "taskflow_runtime.feature_worker+downstream_governor";
    case domain_t::diagnostics: return "taskflow_runtime.diagnostics";
    default: return "unknown";
    }
}

inline aida::diagnostics::breadcrumb_category_t domain_to_breadcrumb_category(domain_t d) {
    switch (d) {
    case domain_t::general:
    case domain_t::service:
    case domain_t::feature_worker:
        return aida::diagnostics::breadcrumb_category_t::work_queue;
    case domain_t::critical:
    case domain_t::security_liveness:
        return aida::diagnostics::breadcrumb_category_t::critical_queue;
    case domain_t::external_tool:
        return aida::diagnostics::breadcrumb_category_t::capacity_governor;
    case domain_t::long_running:
        return aida::diagnostics::breadcrumb_category_t::downstream_producer;
    case domain_t::ui_dispatch:
        return aida::diagnostics::breadcrumb_category_t::ui_dispatcher;
    case domain_t::diagnostics:
        return aida::diagnostics::breadcrumb_category_t::thread_runtime;
    default:
        return aida::diagnostics::breadcrumb_category_t::thread_runtime;
    }
}

inline aida::infra::taskflow_runtime::executor_domain_t to_runtime_domain(domain_t d) {
    using runtime_domain_t = aida::infra::taskflow_runtime::executor_domain_t;
    switch (d) {
    case domain_t::service: return runtime_domain_t::service;
    case domain_t::critical: return runtime_domain_t::critical;
    case domain_t::ui_dispatch: return runtime_domain_t::ui_dispatch;
    case domain_t::external_tool: return runtime_domain_t::external_tool;
    case domain_t::long_running: return runtime_domain_t::long_running;
    case domain_t::security_liveness: return runtime_domain_t::security_liveness;
    case domain_t::feature_worker: return runtime_domain_t::feature_worker;
    case domain_t::diagnostics: return runtime_domain_t::diagnostics;
    case domain_t::general:
    default:
        return runtime_domain_t::general;
    }
}

inline domain_t from_runtime_domain(aida::infra::taskflow_runtime::executor_domain_t d) {
    using runtime_domain_t = aida::infra::taskflow_runtime::executor_domain_t;
    switch (d) {
    case runtime_domain_t::service: return domain_t::service;
    case runtime_domain_t::critical: return domain_t::critical;
    case runtime_domain_t::ui_dispatch: return domain_t::ui_dispatch;
    case runtime_domain_t::external_tool: return domain_t::external_tool;
    case runtime_domain_t::long_running: return domain_t::long_running;
    case runtime_domain_t::security_liveness: return domain_t::security_liveness;
    case runtime_domain_t::feature_worker: return domain_t::feature_worker;
    case runtime_domain_t::diagnostics: return domain_t::diagnostics;
    case runtime_domain_t::general:
    default:
        return domain_t::general;
    }
}

struct submission_t {
    const char* owner_subsystem = nullptr;
    const char* label = nullptr;
    const char* thread_class = nullptr;
    domain_t domain = domain_t::general;
    int priority = 3;
    std::function<void()> cancel_hook;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    const char* no_capacity_reason = nullptr;
    const char* session_id = nullptr;
    const char* target_id = nullptr;
    std::uint32_t target_pid = 0;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    const char* diagnostic_id = nullptr;
    const char* request_id = nullptr;
    const char* ui_access_policy = "none";
    const char* failure_policy = "reject_not_started";
    const char* shutdown_policy = "drain";
    std::function<void()> body;
};

struct submit_result_t {
    bool submitted = false;
    std::uint64_t task_id = 0;
    std::string reject_reason;
};

struct wait_result_t {
    bool completed = false;
    bool cancelled = false;
    bool failed = false;
    bool timed_out = false;
    bool rejected = false;
};

struct active_snapshot_t {
    std::uint32_t active_per_domain[domain_count] = {};
    std::uint64_t oldest_active_ms = 0;
    std::string labels_under_pressure;
    std::uint32_t total_active = 0;
    std::uint32_t work_queue_active = 0;
    std::uint32_t service_queue_active = 0;
    std::uint32_t critical_queue_active = 0;
    std::uint64_t work_queue_pending = 0;
    std::uint64_t service_queue_pending = 0;
    std::uint64_t critical_queue_pending = 0;
};

inline std::atomic<std::uint64_t> total_submits{0};
inline std::atomic<std::uint64_t> total_rejected{0};
inline std::atomic<std::uint64_t> total_ui_wait_rejected{0};
inline std::atomic<std::uint64_t> total_cancels{0};
inline std::atomic<std::uint64_t> total_timeouts{0};
inline std::atomic<std::uint64_t> submits_per_domain[domain_count] = {};
inline std::atomic<std::uint64_t> rejects_per_domain[domain_count] = {};
inline std::atomic<DWORD> g_executor_ui_owner_tid{0};
inline std::atomic<bool> g_shutdown_requested{false};
inline std::mutex g_reject_reason_mutex;
inline std::map<std::string, std::uint64_t> g_reject_reasons;
inline constexpr std::size_t kMaxRejectReasonEntries = 32;
inline std::mutex g_deadline_reported_mutex;
inline std::map<std::uint64_t, bool> g_deadline_reported;

inline void record_reject_reason(const char* reason) {
    if (!reason)
        return;
    std::lock_guard<std::mutex> lk(g_reject_reason_mutex);
    auto it = g_reject_reasons.find(reason);
    if (it != g_reject_reasons.end()) {
        ++it->second;
    } else if (g_reject_reasons.size() < kMaxRejectReasonEntries) {
        g_reject_reasons[reason] = 1;
    } else {
        ++g_reject_reasons["other"];
    }
}

inline const char* taskflow_evaluation_status() {
    return aida::infra::taskflow_eval::kTaskflowEvaluationStatus;
}

inline void set_ui_owner_tid(DWORD tid) {
    g_executor_ui_owner_tid.store(tid, std::memory_order_release);
    diag::log_tagged_fmt("executor",
        "EXECUTOR-UI-OWNER-TID-SET tid=%lu caller_tid=%lu",
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

inline bool is_ui_thread() {
    const DWORD owner = g_executor_ui_owner_tid.load(std::memory_order_acquire);
    if (owner == 0)
        return false;
    return GetCurrentThreadId() == owner;
}

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

inline std::size_t domain_index(domain_t d) {
    return static_cast<std::size_t>(d);
}

inline void emit_breadcrumb(domain_t domain, const char* event, const submission_t& sub, std::uint64_t task_id, std::uint16_t status_code) {
    aida::diagnostics::breadcrumb_options_t opts;
    opts.category = domain_to_breadcrumb_category(domain);
    opts.label = sub.label ? sub.label : "<unnamed>";
    opts.reason = event;
    opts.owner_subsystem = sub.owner_subsystem ? sub.owner_subsystem : "<unknown>";
    opts.tool_or_request_id = sub.request_id ? sub.request_id : (sub.diagnostic_id ? sub.diagnostic_id : nullptr);
    opts.session_or_target = sub.session_id ? sub.session_id : (sub.target_id ? sub.target_id : nullptr);
    opts.lease_token = sub.lease_token;
    opts.generation = sub.generation;
    opts.status_code = status_code;
    opts.priority = static_cast<std::uint8_t>(sub.priority > 5 ? 5 : sub.priority);
    aida::diagnostics::emit(std::move(opts));
}

inline void emit_simple_breadcrumb(domain_t domain, const char* label, const char* owner, const char* event, std::uint16_t status_code) {
    aida::diagnostics::breadcrumb_options_t opts;
    opts.category = domain_to_breadcrumb_category(domain);
    opts.label = label ? label : "<unnamed>";
    opts.reason = event;
    opts.owner_subsystem = owner ? owner : "<unknown>";
    opts.status_code = status_code;
    aida::diagnostics::emit(std::move(opts));
}

inline submit_result_t reject_submission(const submission_t& sub, const char* reason) {
    submit_result_t result;
    result.reject_reason = reason ? reason : "rejected";
    total_rejected.fetch_add(1, std::memory_order_acq_rel);
    std::size_t idx = domain_index(sub.domain);
    if (idx < domain_count)
        rejects_per_domain[idx].fetch_add(1, std::memory_order_acq_rel);
    record_reject_reason(result.reject_reason.c_str());
    diag::log_tagged_fmt("executor",
        "EXECUTOR-REJECT reason=%s owner=%s label=%s domain=%s priority=%d tid=%lu",
        result.reject_reason.c_str(),
        sub.owner_subsystem ? sub.owner_subsystem : "<null>",
        sub.label ? sub.label : "<null>",
        domain_name(sub.domain),
        sub.priority,
        static_cast<unsigned long>(GetCurrentThreadId()));
    emit_breadcrumb(sub.domain, "EXECUTOR-REJECT", sub, 0, 2);
    return result;
}

inline submit_result_t submit(submission_t&& sub) {
    submit_result_t result;
    total_submits.fetch_add(1, std::memory_order_acq_rel);

    if (!sub.owner_subsystem || sub.owner_subsystem[0] == '\0')
        return reject_submission(sub, "missing_owner_subsystem");
    if (!sub.label || sub.label[0] == '\0')
        return reject_submission(sub, "missing_label");
    if (!sub.body)
        return reject_submission(sub, "missing_body");
    if (sub.domain == domain_t::ui_dispatch && is_ui_thread()) {
        total_ui_wait_rejected.fetch_add(1, std::memory_order_acq_rel);
        auto rejected = reject_submission(sub, "EXECUTOR-UI-WAIT-REJECTED");
        diag::log_tagged_fmt("executor",
            "EXECUTOR-UI-WAIT-REJECTED owner=%s label=%s domain=ui_dispatch priority=%d thread_class=%s session=%s target=%s diag_id=%s request_id=%s tid=%lu",
            sub.owner_subsystem,
            sub.label,
            sub.priority,
            sub.thread_class ? sub.thread_class : "<none>",
            sub.session_id ? sub.session_id : "<none>",
            sub.target_id ? sub.target_id : "<none>",
            sub.diagnostic_id ? sub.diagnostic_id : "<none>",
            sub.request_id ? sub.request_id : "<none>",
            static_cast<unsigned long>(GetCurrentThreadId()));
        return rejected;
    }
    if (g_shutdown_requested.load(std::memory_order_acquire))
        return reject_submission(sub, "executor_shutdown_requested");

    std::uint64_t submit_gate_suppressed = 0;
    auto& submit_gate = aida::infra::taskflow_runtime::hot_log_gate_for("executor_submit");
    const bool submit_gate_open = aida::infra::taskflow_runtime::hot_log_should_emit(submit_gate, submit_gate_suppressed);
    if (submit_gate_open || aida::infra::taskflow_runtime::fabric_log_verbose()) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-SUBMIT owner=%s label=%s domain=%s queue=%s priority=%d thread_class=%s deadline_ms=%llu capacity_lease=%llu no_capacity_reason=%s session=%s target=%s target_pid=%u lease_token=%llu generation=%llu diag_id=%s request_id=%s ui_access=%s failure_policy=%s shutdown_policy=%s suppressed=%llu total=%llu tid=%lu",
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain),
            domain_to_queue_name(sub.domain),
            sub.priority,
            sub.thread_class ? sub.thread_class : "<none>",
            static_cast<unsigned long long>(sub.deadline_ms),
            static_cast<unsigned long long>(sub.capacity_lease),
            sub.no_capacity_reason ? sub.no_capacity_reason : "<none>",
            sub.session_id ? sub.session_id : "<none>",
            sub.target_id ? sub.target_id : "<none>",
            static_cast<unsigned>(sub.target_pid),
            static_cast<unsigned long long>(sub.lease_token),
            static_cast<unsigned long long>(sub.generation),
            sub.diagnostic_id ? sub.diagnostic_id : "<none>",
            sub.request_id ? sub.request_id : "<none>",
            sub.ui_access_policy ? sub.ui_access_policy : "none",
            sub.failure_policy ? sub.failure_policy : "reject_not_started",
            sub.shutdown_policy ? sub.shutdown_policy : "drain",
            static_cast<unsigned long long>(submit_gate_suppressed),
            static_cast<unsigned long long>(aida::infra::taskflow_runtime::hot_log_gate_total(submit_gate)),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }

    auto owner = std::string(sub.owner_subsystem);
    auto label = std::string(sub.label);
    auto body = std::move(sub.body);
    const domain_t domain = sub.domain;

    aida::infra::taskflow_runtime::task_descriptor_t desc;
    desc.owner_subsystem = sub.owner_subsystem;
    desc.label = sub.label;
    desc.thread_class = sub.thread_class;
    desc.domain = to_runtime_domain(sub.domain);
    desc.priority = sub.priority;
    desc.cancel_hook = std::move(sub.cancel_hook);
    desc.deadline_ms = sub.deadline_ms;
    desc.capacity_lease = sub.capacity_lease;
    desc.no_capacity_reason = sub.no_capacity_reason;
    desc.session_id = sub.session_id;
    desc.target_id = sub.target_id;
    desc.target_pid = sub.target_pid;
    desc.lease_token = sub.lease_token;
    desc.generation = sub.generation;
    desc.diagnostic_id = sub.diagnostic_id;
    desc.request_id = sub.request_id;
    desc.ui_access_policy = sub.ui_access_policy;
    desc.failure_policy = sub.failure_policy;
    desc.shutdown_policy = sub.shutdown_policy;
    desc.body = [owner, label, domain, body = std::move(body)]() mutable {
        std::uint64_t start_gate_suppressed = 0;
        auto& start_gate = aida::infra::taskflow_runtime::hot_log_gate_for("executor_start");
        const bool start_gate_open = aida::infra::taskflow_runtime::hot_log_should_emit(start_gate, start_gate_suppressed);
        if (start_gate_open || aida::infra::taskflow_runtime::fabric_log_verbose()) {
            diag::log_tagged_fmt("executor",
                "EXECUTOR-START owner=%s label=%s domain=%s queue=%s suppressed=%llu total=%llu tid=%lu note=start_observed_via_taskflow_runtime",
                owner.c_str(),
                label.c_str(),
                domain_name(domain),
                domain_to_queue_name(domain),
                static_cast<unsigned long long>(start_gate_suppressed),
                static_cast<unsigned long long>(aida::infra::taskflow_runtime::hot_log_gate_total(start_gate)),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
        bool exception_path = false;
        struct scoped_finish_t {
            const std::string& owner;
            const std::string& label;
            domain_t domain;
            bool& exception_path;
            ~scoped_finish_t() {
                if (exception_path) {
                    diag::log_tagged_fmt("executor",
                        "EXECUTOR-FINISH-EXCEPTION owner=%s label=%s domain=%s queue=%s tid=%lu note=body_exception_recorded_by_runtime",
                        owner.c_str(),
                        label.c_str(),
                        domain_name(domain),
                        domain_to_queue_name(domain),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                    return;
                }
                std::uint64_t finish_gate_suppressed = 0;
                auto& finish_gate = aida::infra::taskflow_runtime::hot_log_gate_for("executor_finish");
                const bool finish_gate_open = aida::infra::taskflow_runtime::hot_log_should_emit(finish_gate, finish_gate_suppressed);
                if (finish_gate_open || aida::infra::taskflow_runtime::fabric_log_verbose()) {
                    diag::log_tagged_fmt("executor",
                        "EXECUTOR-FINISH owner=%s label=%s domain=%s queue=%s suppressed=%llu total=%llu tid=%lu note=finish_observed_via_taskflow_runtime",
                        owner.c_str(),
                        label.c_str(),
                        domain_name(domain),
                        domain_to_queue_name(domain),
                        static_cast<unsigned long long>(finish_gate_suppressed),
                        static_cast<unsigned long long>(aida::infra::taskflow_runtime::hot_log_gate_total(finish_gate)),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                }
            }
        } finish_guard{owner, label, domain, exception_path};
        try {
            body();
        } catch (const std::exception& ex) {
            exception_path = true;
            diag::log_tagged_fmt("executor",
                "EXECUTOR-BODY-EXCEPTION owner=%s label=%s domain=%s err=%s tid=%lu note=exception_propagating_to_taskflow_runtime",
                owner.c_str(),
                label.c_str(),
                domain_name(domain),
                ex.what(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            throw;
        } catch (...) {
            exception_path = true;
            diag::log_tagged_fmt("executor",
                "EXECUTOR-BODY-EXCEPTION owner=%s label=%s domain=%s err=unknown tid=%lu note=exception_propagating_to_taskflow_runtime",
                owner.c_str(),
                label.c_str(),
                domain_name(domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
            throw;
        }
    };

    if (sub.domain == domain_t::external_tool) {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        diag::log_tagged_fmt("executor",
            "EXECUTOR-CAPACITY-AWARE domain=external_tool label=%s governor_total_active=%zu governor_total_rejected=%zu p0_reserve=%zu p1_reserve=%zu",
            sub.label,
            gov_snap.total_active,
            gov_snap.total_rejected,
            gov_snap.p0_reserve_available,
            gov_snap.p1_reserve_available);
    } else if (sub.domain == domain_t::long_running) {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        diag::log_tagged_fmt("executor",
            "EXECUTOR-DOWNSTREAM-AWARE domain=long_running label=%s governor_total_active=%zu governor_total_rejected=%zu shutdown_pending=%zu",
            sub.label,
            gov_snap.total_active,
            gov_snap.total_rejected,
            gov_snap.shutdown_pending);
    } else if (sub.domain == domain_t::feature_worker) {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        std::size_t fw_active = 0;
        auto it = gov_snap.by_kind.find("feature_worker");
        if (it != gov_snap.by_kind.end())
            fw_active = it->second.active;
        diag::log_tagged_fmt("executor",
            "EXECUTOR-FEATURE-WORKER-AWARE domain=feature_worker label=%s governor_fw_active=%zu governor_fw_total_admitted=%llu",
            sub.label,
            fw_active,
            it != gov_snap.by_kind.end() ? static_cast<unsigned long long>(it->second.total_admitted) : 0ULL);
    }

    auto runtime_result = aida::infra::taskflow_runtime::submit(std::move(desc));
    if (!runtime_result.submitted) {
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        std::size_t idx = domain_index(sub.domain);
        if (idx < domain_count)
            rejects_per_domain[idx].fetch_add(1, std::memory_order_acq_rel);
        result.reject_reason = runtime_result.reject_reason.empty() ? "taskflow_runtime_submit_failed" : runtime_result.reject_reason;
        record_reject_reason(result.reject_reason.c_str());
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=%s owner=%s label=%s domain=%s queue=%s priority=%d tid=%lu",
            result.reject_reason.c_str(),
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain),
            domain_to_queue_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        emit_breadcrumb(sub.domain, "EXECUTOR-REJECT", sub, 0, 2);
        return result;
    }

    std::size_t idx = domain_index(sub.domain);
    if (idx < domain_count)
        submits_per_domain[idx].fetch_add(1, std::memory_order_acq_rel);
    result.submitted = true;
    result.task_id = runtime_result.handle.id;
    emit_breadcrumb(sub.domain, "EXECUTOR-SUBMIT", sub, result.task_id, 0);
    diag::log_tagged_fmt("executor",
        "EXECUTOR-SUBMITTED task_id=%llu owner=%s label=%s domain=%s queue=%s tid=%lu",
        static_cast<unsigned long long>(result.task_id),
        sub.owner_subsystem,
        sub.label,
        domain_name(sub.domain),
        domain_to_queue_name(sub.domain),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return result;
}

inline active_snapshot_t active_snapshot() {
    active_snapshot_t snap;
    auto runtime_snap = aida::infra::taskflow_runtime::active_snapshot();
    snap.oldest_active_ms = runtime_snap.oldest_active_ms;
    snap.labels_under_pressure = runtime_snap.labels_under_pressure;
    snap.total_active = runtime_snap.total_active;
    snap.work_queue_active = runtime_snap.work_queue_active;
    snap.service_queue_active = runtime_snap.service_queue_active;
    snap.critical_queue_active = runtime_snap.critical_queue_active;
    snap.work_queue_pending = runtime_snap.work_queue_pending;
    snap.service_queue_pending = runtime_snap.service_queue_pending;
    snap.critical_queue_pending = runtime_snap.critical_queue_pending;
    for (std::size_t i = 0; i < domain_count && i < aida::infra::taskflow_runtime::executor_domain_count; ++i)
        snap.active_per_domain[i] = runtime_snap.active_per_domain[i];
    return snap;
}

inline wait_result_t wait_for(std::uint64_t task_id, std::uint32_t timeout_ms) {
    wait_result_t result;
    if (is_ui_thread()) {
        result.rejected = true;
        total_ui_wait_rejected.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-UI-WAIT-REJECTED reason=wait_for_from_ui_thread task_id=%llu timeout_ms=%u tid=%lu",
            static_cast<unsigned long long>(task_id),
            static_cast<unsigned>(timeout_ms),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }
    auto rt = aida::infra::taskflow_runtime::wait_for(task_id, timeout_ms);
    result.completed = rt.completed;
    result.cancelled = rt.cancelled;
    result.failed = rt.failed;
    result.timed_out = rt.timed_out;
    result.rejected = rt.rejected;
    if (rt.timed_out) {
        total_timeouts.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-TIMEOUT task_id=%llu timeout_ms=%u tid=%lu note=bounded_wait_or_runtime_deadline_expired",
            static_cast<unsigned long long>(task_id),
            static_cast<unsigned>(timeout_ms),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    return result;
}

inline bool cancel(std::uint64_t task_id) {
    if (task_id == 0)
        return false;
    const bool ok = aida::infra::taskflow_runtime::cancel(task_id);
    if (!ok) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-CANCEL task_id=%llu result=not_found tid=%lu",
            static_cast<unsigned long long>(task_id),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    total_cancels.fetch_add(1, std::memory_order_acq_rel);
    diag::log_tagged_fmt("executor",
        "EXECUTOR-CANCEL task_id=%llu result=cancelled tid=%lu",
        static_cast<unsigned long long>(task_id),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

inline void check_deadlines() {
    const std::uint64_t current = now_ms();
    auto snap = aida::infra::taskflow_runtime::active_snapshot(128);
    std::vector<aida::infra::taskflow_runtime::active_job_snapshot_t> expired;
    {
        std::lock_guard<std::mutex> lk(g_deadline_reported_mutex);
        for (const auto& job : snap.active_jobs) {
            if (job.deadline_ms == 0 || current < job.deadline_ms)
                continue;
            if (g_deadline_reported[job.job_id])
                continue;
            g_deadline_reported[job.job_id] = true;
            expired.push_back(job);
        }
    }
    aida::infra::taskflow_runtime::check_deadlines();
    for (const auto& job : expired) {
        total_timeouts.fetch_add(1, std::memory_order_acq_rel);
        const domain_t d = from_runtime_domain(job.domain);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-TIMEOUT task_id=%llu label=%s domain=%s deadline_ms=%llu now_ms=%llu overdue_ms=%llu tid=%lu note=deadline_exceeded_runtime_cancel_requested",
            static_cast<unsigned long long>(job.job_id),
            job.label.c_str(),
            domain_name(d),
            static_cast<unsigned long long>(job.deadline_ms),
            static_cast<unsigned long long>(current),
            static_cast<unsigned long long>(current - job.deadline_ms),
            static_cast<unsigned long>(GetCurrentThreadId()));
        emit_simple_breadcrumb(d, job.label.c_str(), job.owner_subsystem.c_str(), "EXECUTOR-TIMEOUT", 4);
    }
}

inline bool shutdown(std::uint32_t timeout_ms = 15000) {
    const bool first_request = !g_shutdown_requested.exchange(true, std::memory_order_acq_rel);
    auto snap = active_snapshot();
    if (first_request) diag::log_tagged_fmt("executor",
        "EXECUTOR-SNAPSHOT phase=pre_shutdown total_active=%u work_queue_active=%u service_queue_active=%u critical_queue_active=%u work_queue_pending=%llu service_queue_pending=%llu critical_queue_pending=%llu oldest_active_ms=%llu total_submits=%llu total_rejected=%llu total_ui_wait_rejected=%llu total_cancels=%llu total_timeouts=%llu labels_under_pressure=%.800s tid=%lu",
        static_cast<unsigned>(snap.total_active),
        static_cast<unsigned>(snap.work_queue_active),
        static_cast<unsigned>(snap.service_queue_active),
        static_cast<unsigned>(snap.critical_queue_active),
        static_cast<unsigned long long>(snap.work_queue_pending),
        static_cast<unsigned long long>(snap.service_queue_pending),
        static_cast<unsigned long long>(snap.critical_queue_pending),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        static_cast<unsigned long long>(total_submits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_ui_wait_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_cancels.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_timeouts.load(std::memory_order_acquire)),
        snap.labels_under_pressure.c_str(),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (first_request) {
        aida::diagnostics::breadcrumb_options_t opts;
        opts.category = aida::diagnostics::breadcrumb_category_t::startup_shutdown;
        opts.label = "executor_shutdown";
        opts.reason = "EXECUTOR-SNAPSHOT";
        opts.owner_subsystem = "executor";
        opts.status_code = 5;
        aida::diagnostics::emit(std::move(opts));
    }
    auto runtime_snap = aida::infra::taskflow_runtime::active_snapshot(128);
    for (const auto& job : runtime_snap.active_jobs) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-SHUTDOWN-ACTIVE task_id=%llu label=%s owner=%s domain=%s state=%s deadline_ms=%llu active_ms=%llu",
            static_cast<unsigned long long>(job.job_id),
            job.label.c_str(),
            job.owner_subsystem.c_str(),
            domain_name(from_runtime_domain(job.domain)),
            aida::infra::taskflow_runtime::job_state_name(job.state),
            static_cast<unsigned long long>(job.deadline_ms),
            static_cast<unsigned long long>(job.active_ms));
    }
    const bool complete = aida::infra::taskflow_runtime::shutdown(timeout_ms);
    diag::log_tagged_fmt("executor",
        complete ? "EXECUTOR-SHUTDOWN-COMPLETE tid=%lu"
            : "EXECUTOR-SHUTDOWN-DEFERRED tid=%lu",
        static_cast<unsigned long>(GetCurrentThreadId()));
    return complete;
}

inline void json_append_escaped(std::string& out, const std::string& s) {
    for (char c : s) {
        if (c == '"' || c == '\\')
            out += '\\';
        if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else
            out += c;
    }
}

inline std::string snapshot_json_string() {
    auto snap = active_snapshot();
    auto runtime_snap = aida::infra::taskflow_runtime::active_snapshot(64);
    std::string out;
    out.reserve(8192);
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"total_submits\":%llu,\"total_rejected\":%llu,\"total_ui_wait_rejected\":%llu,\"total_cancels\":%llu,\"total_timeouts\":%llu,"
        "\"taskflow_evaluation_status\":\"%s\","
        "\"oldest_active_ms\":%llu,\"total_active\":%u,\"work_queue_active\":%u,\"service_queue_active\":%u,\"critical_queue_active\":%u,"
        "\"work_queue_pending\":%llu,\"service_queue_pending\":%llu,\"critical_queue_pending\":%llu,"
        "\"domains\":[",
        static_cast<unsigned long long>(total_submits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_ui_wait_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_cancels.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_timeouts.load(std::memory_order_acquire)),
        taskflow_evaluation_status(),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        static_cast<unsigned>(snap.total_active),
        static_cast<unsigned>(snap.work_queue_active),
        static_cast<unsigned>(snap.service_queue_active),
        static_cast<unsigned>(snap.critical_queue_active),
        static_cast<unsigned long long>(snap.work_queue_pending),
        static_cast<unsigned long long>(snap.service_queue_pending),
        static_cast<unsigned long long>(snap.critical_queue_pending));
    out += buf;
    for (std::size_t i = 0; i < domain_count; ++i) {
        if (i > 0)
            out += ",";
        const domain_t d = static_cast<domain_t>(i);
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"name\":\"%s\",\"active\":%u,\"submitted\":%llu,\"rejected\":%llu,\"queue\":\"%s\"}",
            domain_name(d),
            static_cast<unsigned>(snap.active_per_domain[i]),
            static_cast<unsigned long long>(submits_per_domain[i].load(std::memory_order_acquire)),
            static_cast<unsigned long long>(rejects_per_domain[i].load(std::memory_order_acquire)),
            domain_to_queue_name(d));
        out += buf;
    }
    out += "],\"labels_under_pressure\":\"";
    json_append_escaped(out, snap.labels_under_pressure);
    out += "\",\"reject_reasons\":[";
    {
        std::lock_guard<std::mutex> lk(g_reject_reason_mutex);
        bool first_reason = true;
        for (const auto& kr : g_reject_reasons) {
            if (!first_reason)
                out += ",";
            first_reason = false;
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"reason\":\"%s\",\"count\":%llu}",
                kr.first.c_str(),
                static_cast<unsigned long long>(kr.second));
            out += buf;
        }
    }
    out += "]";
    {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            ",\"downstream_governor\":{\"total_active\":%zu,\"total_rejected\":%zu,\"p0_reserve_available\":%zu,\"p1_reserve_available\":%zu,\"shutdown_pending\":%zu}",
            gov_snap.total_active,
            gov_snap.total_rejected,
            gov_snap.p0_reserve_available,
            gov_snap.p1_reserve_available,
            gov_snap.shutdown_pending);
        out += buf;
    }
    std::uint32_t capacity_lease_active = 0;
    for (const auto& job : runtime_snap.active_jobs) {
        if (job.capacity_lease != 0)
            ++capacity_lease_active;
    }
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        ",\"capacity_lease_active\":%u,\"taskflow_runtime\":",
        static_cast<unsigned>(capacity_lease_active));
    out += buf;
    out += aida::infra::taskflow_runtime::snapshot_json_string();
    out += "}";
    return out;
}

struct shutdown_guard_t {
    ~shutdown_guard_t() noexcept { try { static_cast<void>(shutdown()); } catch (...) {} }
};

inline shutdown_guard_t g_shutdown_guard;

}

#endif
