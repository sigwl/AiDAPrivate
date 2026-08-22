#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <cctype>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../helpers/diag_log.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../infra/win_thread.hpp"

namespace mcp_standalone {
namespace downstream {

using json = nlohmann::json;

inline std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

enum class producer_kind_t : int
{
    background_command = 0,
    camoufox_longop = 1,
    driver_debugger = 2,
    scanner = 3,
    decompiler = 4,
    pdb_parser = 5,
    broad_enumeration = 6,
    burp_network = 7,
    api_monitor = 8,
    feature_worker = 9,
    unknown = 99
};

inline const char* producer_kind_name(producer_kind_t kind)
{
    switch (kind) {
    case producer_kind_t::background_command: return "background_command";
    case producer_kind_t::camoufox_longop: return "camoufox_longop";
    case producer_kind_t::driver_debugger: return "driver_debugger";
    case producer_kind_t::scanner: return "scanner";
    case producer_kind_t::decompiler: return "decompiler";
    case producer_kind_t::pdb_parser: return "pdb_parser";
    case producer_kind_t::broad_enumeration: return "broad_enumeration";
    case producer_kind_t::burp_network: return "burp_network";
    case producer_kind_t::api_monitor: return "api_monitor";
    case producer_kind_t::feature_worker: return "feature_worker";
    default: return "unknown";
    }
}

inline producer_kind_t producer_kind_from_name(const std::string& name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "background_command") return producer_kind_t::background_command;
    if (lower == "camoufox_longop") return producer_kind_t::camoufox_longop;
    if (lower == "driver_debugger") return producer_kind_t::driver_debugger;
    if (lower == "scanner") return producer_kind_t::scanner;
    if (lower == "decompiler") return producer_kind_t::decompiler;
    if (lower == "pdb_parser") return producer_kind_t::pdb_parser;
    if (lower == "broad_enumeration") return producer_kind_t::broad_enumeration;
    if (lower == "burp_network") return producer_kind_t::burp_network;
    if (lower == "api_monitor") return producer_kind_t::api_monitor;
    if (lower == "feature_worker") return producer_kind_t::feature_worker;
    return producer_kind_t::unknown;
}

struct producer_quota_set_t
{
    std::size_t global_active_background_commands = 8;
    std::size_t per_principal_active_background_commands = 2;
    std::size_t global_queued_background_commands = 16;

    std::size_t global_active_camoufox_longops = 2;
    std::size_t per_principal_active_camoufox_longops = 1;
    std::size_t per_session_active_camoufox_longops = 2;

    std::size_t global_active_driver_debugger = 4;
    std::size_t per_principal_active_driver_debugger = 2;
    std::size_t per_target_active_driver_debugger = 2;

    std::size_t global_active_scanner = 4;
    std::size_t per_principal_active_scanner = 2;
    std::size_t scanner_worker_group_size = 4;
    std::size_t scanner_queue_depth = 32;

    std::size_t global_active_decompiler = 2;
    std::size_t per_principal_active_decompiler = 1;
    std::size_t decompiler_worker_group_size = 8;
    std::size_t decompiler_queue_depth = 16;

    std::size_t global_active_pdb = 2;
    std::size_t per_principal_active_pdb = 1;
    std::size_t pdb_worker_group_size = 2;
    std::size_t pdb_queue_depth = 8;

    std::size_t global_active_broad_enum = 4;
    std::size_t per_principal_active_broad_enum = 2;
    std::size_t broad_enum_worker_group_size = 4;
    std::size_t broad_enum_queue_depth = 32;

    std::size_t global_active_burp_network = 6;
    std::size_t per_principal_active_burp_network = 3;
    std::size_t per_session_active_burp_network = 2;
    std::size_t burp_network_worker_group_size = 4;
    std::size_t burp_network_queue_depth = 48;

    std::size_t global_active_api_monitor = 2;
    std::size_t per_principal_active_api_monitor = 1;
    std::size_t api_monitor_worker_group_size = 2;
    std::size_t api_monitor_queue_depth = 16;

    std::size_t global_active_feature_worker = 8;
    std::size_t feature_worker_group_size = 4;
    std::size_t feature_worker_queue_depth = 32;

    std::size_t p0_reserved_liveness_slots = 2;
    std::size_t p1_reserved_foreground_slots = 1;
};

inline producer_quota_set_t default_quotas() { return {}; }

struct producer_identity_t
{
    producer_kind_t kind = producer_kind_t::unknown;
    std::string principal_id;
    std::string session_id;
    std::string target_id;
    std::uint32_t target_pid = 0;
    std::string domain;
    std::string tool_name;
    std::string lane;
    std::string diagnostic_id;
    std::string request_id;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    std::uint64_t deadline_ms = 0;
    std::string command_label;
    std::uint32_t child_pid = 0;
    std::string sidecar_executable_path;
    std::uint64_t sidecar_generation = 0;
};

struct admission_result_t
{
    bool admitted = false;
    std::uint64_t admission_token = 0;
    std::string reason;
    std::string quota_name;
    std::string quota_scope;
    std::size_t observed = 0;
    std::size_t limit = 0;

    static admission_result_t admitted_result(std::uint64_t token)
    {
        admission_result_t r;
        r.admitted = true;
        r.admission_token = token;
        r.reason = "downstream_admitted";
        return r;
    }

    static admission_result_t rejected_result(const char* reason, const char* quota,
                                               const char* scope, std::size_t observed,
                                               std::size_t limit)
    {
        admission_result_t r;
        r.admitted = false;
        r.reason = reason ? reason : "downstream_rejected";
        r.quota_name = quota ? quota : "";
        r.quota_scope = scope ? scope : "";
        r.observed = observed;
        r.limit = limit;
        return r;
    }
};

struct active_record_t
{
    std::uint64_t token = 0;
    producer_kind_t kind = producer_kind_t::unknown;
    std::string principal_id;
    std::string session_id;
    std::string target_id;
    std::uint32_t target_pid = 0;
    std::string domain;
    std::string tool_name;
    std::string lane;
    std::string diagnostic_id;
    std::string request_id;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t deadline_ms = 0;
    std::string command_label;
    std::uint32_t child_pid = 0;
    std::string sidecar_executable_path;
    std::uint64_t sidecar_generation = 0;
};

struct kind_stats_t
{
    std::atomic<std::uint64_t> total_admitted{0};
    std::atomic<std::uint64_t> total_rejected{0};
    std::atomic<std::uint64_t> total_released{0};
};

struct governor_snapshot_t
{
    struct kind_snapshot_t
    {
        std::size_t active = 0;
        std::size_t queued = 0;
        std::size_t rejected = 0;
        std::size_t released = 0;
        std::uint64_t oldest_active_ms = 0;
        std::uint64_t total_admitted = 0;
        std::uint64_t total_rejected = 0;
        std::uint64_t total_released = 0;
    };
    std::map<std::string, kind_snapshot_t> by_kind;
    std::map<std::string, std::size_t> active_per_principal;
    std::map<std::string, std::size_t> active_per_session;
    std::map<std::string, std::size_t> active_per_target;
    std::map<std::string, std::size_t> active_per_domain;
    std::size_t total_active = 0;
    std::size_t total_queued = 0;
    std::size_t total_rejected = 0;
    std::size_t shutdown_pending = 0;
    std::size_t p0_reserve_available = 0;
    std::size_t p1_reserve_available = 0;
    bool registry_lock_busy = false;
    std::vector<json> active_records;
};

class governor_t
{
public:
    static governor_t& instance()
    {
        static governor_t g;
        return g;
    }

    governor_t() : quotas_(default_quotas()) {}

    void set_quotas(const producer_quota_set_t& q) { quotas_ = q; }
    const producer_quota_set_t& quotas() const { return quotas_; }

    void request_shutdown() { shutdown_requested_.store(true, std::memory_order_release); }
    void clear_shutdown() { shutdown_requested_.store(false, std::memory_order_release); }
    bool shutdown_requested() const { return shutdown_requested_.load(std::memory_order_acquire); }

    admission_result_t try_admit(const producer_identity_t& identity)
    {
        if (shutdown_requested_.load(std::memory_order_acquire)) {
            log_event("MCP-DOWNSTREAM-REJECT", identity, "shutdown_requested", 0, 0);
            return admission_result_t::rejected_result(
                "downstream_shutdown_requested", "shutdown", "global", 0, 0);
        }

        const std::uint64_t token = next_token_.fetch_add(1, std::memory_order_acq_rel) + 1;
        const std::uint64_t ts = now_ms();

        bool admitted = false;
        std::string reject_reason;
        std::string reject_quota;
        std::string reject_scope;
        std::size_t reject_observed = 0;
        std::size_t reject_limit = 0;

        {
            std::lock_guard<std::mutex> lk(mutex_);
            const auto& q = quotas_;
            const std::string target_key = identity.target_id.empty()
                ? std::string("target_unknown") : identity.target_id;

            switch (identity.kind) {
            case producer_kind_t::background_command: {
                const std::size_t ga = count_kind_locked(producer_kind_t::background_command);
                if (ga >= q.global_active_background_commands) {
                    reject_reason = "global_active_background_commands";
                    reject_quota = "global_active_background_commands";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_background_commands;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::background_command);
                    if (pa >= q.per_principal_active_background_commands) {
                        reject_reason = "per_principal_active_background_commands";
                        reject_quota = "per_principal_active_background_commands";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_background_commands;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::camoufox_longop: {
                const std::size_t ga = count_kind_locked(producer_kind_t::camoufox_longop);
                if (ga >= q.global_active_camoufox_longops) {
                    reject_reason = "global_active_camoufox_longops";
                    reject_quota = "global_active_camoufox_longops";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_camoufox_longops;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::camoufox_longop);
                    if (pa >= q.per_principal_active_camoufox_longops) {
                        reject_reason = "per_principal_active_camoufox_longops";
                        reject_quota = "per_principal_active_camoufox_longops";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_camoufox_longops;
                        break;
                    }
                }
                if (!identity.session_id.empty() && identity.session_id != "session_unknown") {
                    const std::size_t sa = count_session_kind_locked(identity.session_id, producer_kind_t::camoufox_longop);
                    if (sa >= q.per_session_active_camoufox_longops) {
                        reject_reason = "per_session_active_camoufox_longops";
                        reject_quota = "per_session_active_camoufox_longops";
                        reject_scope = "session";
                        reject_observed = sa;
                        reject_limit = q.per_session_active_camoufox_longops;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::driver_debugger: {
                const std::size_t ga = count_kind_locked(producer_kind_t::driver_debugger);
                if (ga >= q.global_active_driver_debugger) {
                    reject_reason = "global_active_driver_debugger";
                    reject_quota = "global_active_driver_debugger";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_driver_debugger;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::driver_debugger);
                    if (pa >= q.per_principal_active_driver_debugger) {
                        reject_reason = "per_principal_active_driver_debugger";
                        reject_quota = "per_principal_active_driver_debugger";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_driver_debugger;
                        break;
                    }
                }
                if (!target_key.empty() && target_key != "target_unknown") {
                    const std::size_t ta = count_target_kind_locked(target_key, producer_kind_t::driver_debugger);
                    if (ta >= q.per_target_active_driver_debugger) {
                        reject_reason = "per_target_active_driver_debugger";
                        reject_quota = "per_target_active_driver_debugger";
                        reject_scope = "target";
                        reject_observed = ta;
                        reject_limit = q.per_target_active_driver_debugger;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::scanner: {
                const std::size_t ga = count_kind_locked(producer_kind_t::scanner);
                if (ga >= q.global_active_scanner) {
                    reject_reason = "global_active_scanner";
                    reject_quota = "global_active_scanner";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_scanner;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::scanner);
                    if (pa >= q.per_principal_active_scanner) {
                        reject_reason = "per_principal_active_scanner";
                        reject_quota = "per_principal_active_scanner";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_scanner;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::decompiler: {
                const std::size_t ga = count_kind_locked(producer_kind_t::decompiler);
                if (ga >= q.global_active_decompiler) {
                    reject_reason = "global_active_decompiler";
                    reject_quota = "global_active_decompiler";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_decompiler;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::decompiler);
                    if (pa >= q.per_principal_active_decompiler) {
                        reject_reason = "per_principal_active_decompiler";
                        reject_quota = "per_principal_active_decompiler";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_decompiler;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::pdb_parser: {
                const std::size_t ga = count_kind_locked(producer_kind_t::pdb_parser);
                if (ga >= q.global_active_pdb) {
                    reject_reason = "global_active_pdb";
                    reject_quota = "global_active_pdb";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_pdb;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::pdb_parser);
                    if (pa >= q.per_principal_active_pdb) {
                        reject_reason = "per_principal_active_pdb";
                        reject_quota = "per_principal_active_pdb";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_pdb;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::broad_enumeration: {
                const std::size_t ga = count_kind_locked(producer_kind_t::broad_enumeration);
                if (ga >= q.global_active_broad_enum) {
                    reject_reason = "global_active_broad_enumeration";
                    reject_quota = "global_active_broad_enumeration";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_broad_enum;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::broad_enumeration);
                    if (pa >= q.per_principal_active_broad_enum) {
                        reject_reason = "per_principal_active_broad_enumeration";
                        reject_quota = "per_principal_active_broad_enumeration";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_broad_enum;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::burp_network: {
                const std::size_t ga = count_kind_locked(producer_kind_t::burp_network);
                if (ga >= q.global_active_burp_network) {
                    reject_reason = "global_active_burp_network";
                    reject_quota = "global_active_burp_network";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_burp_network;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::burp_network);
                    if (pa >= q.per_principal_active_burp_network) {
                        reject_reason = "per_principal_active_burp_network";
                        reject_quota = "per_principal_active_burp_network";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_burp_network;
                        break;
                    }
                }
                if (!identity.session_id.empty() && identity.session_id != "session_unknown") {
                    const std::size_t sa = count_session_kind_locked(identity.session_id, producer_kind_t::burp_network);
                    if (sa >= q.per_session_active_burp_network) {
                        reject_reason = "per_session_active_burp_network";
                        reject_quota = "per_session_active_burp_network";
                        reject_scope = "session";
                        reject_observed = sa;
                        reject_limit = q.per_session_active_burp_network;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::api_monitor: {
                const std::size_t ga = count_kind_locked(producer_kind_t::api_monitor);
                if (ga >= q.global_active_api_monitor) {
                    reject_reason = "global_active_api_monitor";
                    reject_quota = "global_active_api_monitor";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_api_monitor;
                    break;
                }
                if (!identity.principal_id.empty()) {
                    const std::size_t pa = count_principal_kind_locked(identity.principal_id, producer_kind_t::api_monitor);
                    if (pa >= q.per_principal_active_api_monitor) {
                        reject_reason = "per_principal_active_api_monitor";
                        reject_quota = "per_principal_active_api_monitor";
                        reject_scope = "principal";
                        reject_observed = pa;
                        reject_limit = q.per_principal_active_api_monitor;
                        break;
                    }
                }
                admitted = true;
                break;
            }
            case producer_kind_t::feature_worker: {
                const std::size_t ga = count_kind_locked(producer_kind_t::feature_worker);
                if (ga >= q.global_active_feature_worker) {
                    reject_reason = "global_active_feature_worker";
                    reject_quota = "global_active_feature_worker";
                    reject_scope = "global";
                    reject_observed = ga;
                    reject_limit = q.global_active_feature_worker;
                    break;
                }
                admitted = true;
                break;
            }
            default:
                reject_reason = "unknown_producer_kind";
                reject_quota = "unknown_producer_kind";
                reject_scope = "global";
                break;
            }

            if (admitted) {
                active_record_t rec;
                rec.token = token;
                rec.kind = identity.kind;
                rec.principal_id = identity.principal_id;
                rec.session_id = identity.session_id;
                rec.target_id = target_key;
                rec.target_pid = identity.target_pid;
                rec.domain = identity.domain;
                rec.tool_name = identity.tool_name;
                rec.lane = identity.lane;
                rec.diagnostic_id = identity.diagnostic_id;
                rec.request_id = identity.request_id;
                rec.lease_token = identity.lease_token;
                rec.generation = identity.generation;
                rec.started_ms = ts;
                rec.deadline_ms = identity.deadline_ms;
                rec.command_label = identity.command_label;
                rec.child_pid = identity.child_pid;
                rec.sidecar_executable_path = identity.sidecar_executable_path;
                rec.sidecar_generation = identity.sidecar_generation;
                active_[token] = rec;
                kind_stats_[producer_kind_name(identity.kind)].total_admitted
                    .fetch_add(1, std::memory_order_relaxed);
            } else {
                kind_stats_[producer_kind_name(identity.kind)].total_rejected
                    .fetch_add(1, std::memory_order_relaxed);
                if (!reject_reason.empty())
                    rejection_by_reason_[reject_reason]++;
            }
        }

        if (admitted) {
            log_event("MCP-DOWNSTREAM-ADMIT", identity, "admitted", token, 0);
            return admission_result_t::admitted_result(token);
        }
        log_event("MCP-DOWNSTREAM-REJECT", identity, reject_reason.c_str(),
                  reject_observed, reject_limit);
        return admission_result_t::rejected_result(
            reject_reason.c_str(), reject_quota.c_str(),
            reject_scope.c_str(), reject_observed, reject_limit);
    }

    void release(std::uint64_t token, const char* reason = "completed")
    {
        if (token == 0) return;
        producer_identity_t id_for_log;
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            auto it = active_.find(token);
            if (it == active_.end()) return;
            id_for_log.kind = it->second.kind;
            id_for_log.principal_id = it->second.principal_id;
            id_for_log.session_id = it->second.session_id;
            id_for_log.target_id = it->second.target_id;
            id_for_log.target_pid = it->second.target_pid;
            id_for_log.domain = it->second.domain;
            id_for_log.tool_name = it->second.tool_name;
            id_for_log.lane = it->second.lane;
            id_for_log.diagnostic_id = it->second.diagnostic_id;
            id_for_log.request_id = it->second.request_id;
            id_for_log.lease_token = it->second.lease_token;
            id_for_log.generation = it->second.generation;
            id_for_log.deadline_ms = it->second.deadline_ms;
            id_for_log.command_label = it->second.command_label;
            id_for_log.child_pid = it->second.child_pid;
            id_for_log.sidecar_executable_path = it->second.sidecar_executable_path;
            id_for_log.sidecar_generation = it->second.sidecar_generation;
            active_.erase(it);
            kind_stats_[producer_kind_name(id_for_log.kind)].total_released
                .fetch_add(1, std::memory_order_relaxed);
            found = true;
        }
        if (found)
            log_event("MCP-DOWNSTREAM-RELEASE", id_for_log, reason, token, 0);
    }

    bool is_admitted(std::uint64_t token) const
    {
        if (token == 0) return false;
        std::lock_guard<std::mutex> lk(mutex_);
        return active_.find(token) != active_.end();
    }

    governor_snapshot_t snapshot() const
    {
        governor_snapshot_t snap;
        const std::uint64_t now = now_ms();
        std::lock_guard<std::mutex> lk(mutex_);
        snap.total_active = active_.size();
        snap.p0_reserve_available = quotas_.p0_reserved_liveness_slots;
        snap.p1_reserve_available = quotas_.p1_reserved_foreground_slots;
        for (const auto& kv : active_) {
            const auto& rec = kv.second;
            const std::string kind_name = producer_kind_name(rec.kind);
            auto& ks = snap.by_kind[kind_name];
            ++ks.active;
            const std::uint64_t age = now >= rec.started_ms ? now - rec.started_ms : 0;
            if (age > ks.oldest_active_ms) ks.oldest_active_ms = age;
            if (!rec.principal_id.empty()) ++snap.active_per_principal[rec.principal_id];
            if (!rec.session_id.empty() && rec.session_id != "session_unknown")
                ++snap.active_per_session[rec.session_id];
            if (!rec.target_id.empty() && rec.target_id != "target_unknown")
                ++snap.active_per_target[rec.target_id];
            if (!rec.domain.empty()) ++snap.active_per_domain[rec.domain];
            if (snap.active_records.size() < 32) {
                snap.active_records.push_back({
                    {"token", rec.token}, {"kind", kind_name},
                    {"principal_id", rec.principal_id}, {"session_id", rec.session_id},
                    {"target_id", rec.target_id}, {"target_pid", rec.target_pid},
                    {"domain", rec.domain}, {"tool", rec.tool_name},
                    {"lane", rec.lane}, {"diagnostic_id", rec.diagnostic_id},
                    {"request_id", rec.request_id}, {"lease_token", rec.lease_token},
                    {"generation", rec.generation}, {"started_ms", rec.started_ms},
                    {"deadline_ms", rec.deadline_ms}, {"age_ms", age},
                    {"command_label", rec.command_label}, {"child_pid", rec.child_pid},
                    {"sidecar_executable_path", rec.sidecar_executable_path},
                    {"sidecar_generation", rec.sidecar_generation}
                });
            }
        }
        for (const auto& kv : kind_stats_) {
            auto& ks = snap.by_kind[kv.first];
            ks.total_admitted = kv.second.total_admitted.load(std::memory_order_relaxed);
            ks.total_rejected = kv.second.total_rejected.load(std::memory_order_relaxed);
            ks.total_released = kv.second.total_released.load(std::memory_order_relaxed);
            ks.rejected = static_cast<std::size_t>(ks.total_rejected);
            ks.released = static_cast<std::size_t>(ks.total_released);
        }
        snap.total_rejected = 0;
        for (const auto& kv : snap.by_kind) snap.total_rejected += kv.second.rejected;
        snap.shutdown_pending = shutdown_requested_.load(std::memory_order_acquire) ? 1 : 0;
        return snap;
    }

    json snapshot_json() const
    {
        const auto snap = snapshot();
        json out;
        out["total_active"] = snap.total_active;
        out["total_queued"] = snap.total_queued;
        out["total_rejected"] = snap.total_rejected;
        out["shutdown_pending"] = snap.shutdown_pending;
        out["p0_reserve_available"] = snap.p0_reserve_available;
        out["p1_reserve_available"] = snap.p1_reserve_available;
        out["registry_lock_busy"] = snap.registry_lock_busy;
        json by_kind = json::array();
        for (const auto& kv : snap.by_kind) {
            by_kind.push_back({
                {"kind", kv.first}, {"active", kv.second.active},
                {"queued", kv.second.queued}, {"rejected", kv.second.rejected},
                {"released", kv.second.released}, {"oldest_active_ms", kv.second.oldest_active_ms},
                {"total_admitted", kv.second.total_admitted},
                {"total_rejected", kv.second.total_rejected},
                {"total_released", kv.second.total_released}
            });
        }
        out["by_kind"] = by_kind;
        json per_principal = json::array();
        for (const auto& kv : snap.active_per_principal)
            per_principal.push_back({{"principal", kv.first}, {"active", kv.second}});
        out["per_principal"] = per_principal;
        json per_session = json::array();
        for (const auto& kv : snap.active_per_session)
            per_session.push_back({{"session", kv.first}, {"active", kv.second}});
        out["per_session"] = per_session;
        json per_target = json::array();
        for (const auto& kv : snap.active_per_target)
            per_target.push_back({{"target", kv.first}, {"active", kv.second}});
        out["per_target"] = per_target;
        json per_domain = json::array();
        for (const auto& kv : snap.active_per_domain)
            per_domain.push_back({{"domain", kv.first}, {"active", kv.second}});
        out["per_domain"] = per_domain;
        json rejection_by_reason = json::array();
        for (const auto& kv : rejection_by_reason_)
            rejection_by_reason.push_back({{"reason", kv.first}, {"count", kv.second}});
        out["rejection_by_reason"] = rejection_by_reason;
        out["active_records"] = snap.active_records;
        return out;
    }

    json quota_json() const
    {
        const auto& q = quotas_;
        return {
            {"background_command", {{"global_active", q.global_active_background_commands},
                {"per_principal_active", q.per_principal_active_background_commands},
                {"queued", q.global_queued_background_commands}}},
            {"camoufox_longop", {{"global_active", q.global_active_camoufox_longops},
                {"per_principal_active", q.per_principal_active_camoufox_longops},
                {"per_session_active", q.per_session_active_camoufox_longops}}},
            {"driver_debugger", {{"global_active", q.global_active_driver_debugger},
                {"per_principal_active", q.per_principal_active_driver_debugger},
                {"per_target_active", q.per_target_active_driver_debugger}}},
            {"scanner", {{"global_active", q.global_active_scanner},
                {"per_principal_active", q.per_principal_active_scanner},
                {"worker_group_size", q.scanner_worker_group_size},
                {"queue_depth", q.scanner_queue_depth}}},
            {"decompiler", {{"global_active", q.global_active_decompiler},
                {"per_principal_active", q.per_principal_active_decompiler},
                {"worker_group_size", q.decompiler_worker_group_size},
                {"queue_depth", q.decompiler_queue_depth}}},
            {"pdb_parser", {{"global_active", q.global_active_pdb},
                {"per_principal_active", q.per_principal_active_pdb},
                {"worker_group_size", q.pdb_worker_group_size},
                {"queue_depth", q.pdb_queue_depth}}},
            {"broad_enumeration", {{"global_active", q.global_active_broad_enum},
                {"per_principal_active", q.per_principal_active_broad_enum},
                {"worker_group_size", q.broad_enum_worker_group_size},
                {"queue_depth", q.broad_enum_queue_depth}}},
            {"burp_network", {{"global_active", q.global_active_burp_network},
                {"per_principal_active", q.per_principal_active_burp_network},
                {"per_session_active", q.per_session_active_burp_network},
                {"worker_group_size", q.burp_network_worker_group_size},
                {"queue_depth", q.burp_network_queue_depth}}},
            {"api_monitor", {{"global_active", q.global_active_api_monitor},
                {"per_principal_active", q.per_principal_active_api_monitor},
                {"worker_group_size", q.api_monitor_worker_group_size},
                {"queue_depth", q.api_monitor_queue_depth}}},
            {"feature_worker", {{"global_active", q.global_active_feature_worker},
                {"worker_group_size", q.feature_worker_group_size},
                {"queue_depth", q.feature_worker_queue_depth}}},
            {"p0_reserved_liveness_slots", q.p0_reserved_liveness_slots},
            {"p1_reserved_foreground_slots", q.p1_reserved_foreground_slots}
        };
    }

private:
    void log_event(const char* event_name, const producer_identity_t& id,
                   const char* reason, std::uint64_t token, std::size_t limit)
    {
        diag::log_tagged_fmt("mcp_srv",
            "%s token=%llu kind=%s reason=%s principal=%s session=%s target=%s target_pid=%u "
            "domain=%s tool=%s lane=%s diag_id=%s request_id=%s lease_token=%llu generation=%llu "
            "child_pid=%u limit=%zu",
            event_name ? event_name : "MCP-DOWNSTREAM-EVENT",
            static_cast<unsigned long long>(token),
            producer_kind_name(id.kind),
            reason ? reason : "",
            id.principal_id.c_str(),
            id.session_id.c_str(),
            id.target_id.c_str(),
            id.target_pid,
            id.domain.c_str(),
            id.tool_name.c_str(),
            id.lane.c_str(),
            id.diagnostic_id.c_str(),
            id.request_id.c_str(),
            static_cast<unsigned long long>(id.lease_token),
            static_cast<unsigned long long>(id.generation),
            id.child_pid,
            limit);
    }

    std::size_t count_kind_locked(producer_kind_t kind) const
    {
        std::size_t count = 0;
        for (const auto& kv : active_)
            if (kv.second.kind == kind) ++count;
        return count;
    }

    std::size_t count_principal_kind_locked(const std::string& principal, producer_kind_t kind) const
    {
        if (principal.empty()) return 0;
        std::size_t count = 0;
        for (const auto& kv : active_)
            if (kv.second.kind == kind && kv.second.principal_id == principal) ++count;
        return count;
    }

    std::size_t count_session_kind_locked(const std::string& session, producer_kind_t kind) const
    {
        if (session.empty()) return 0;
        std::size_t count = 0;
        for (const auto& kv : active_)
            if (kv.second.kind == kind && kv.second.session_id == session) ++count;
        return count;
    }

    std::size_t count_target_kind_locked(const std::string& target, producer_kind_t kind) const
    {
        if (target.empty()) return 0;
        std::size_t count = 0;
        for (const auto& kv : active_)
            if (kv.second.kind == kind && kv.second.target_id == target) ++count;
        return count;
    }

public:
    struct bounded_snapshot_t {
        bool lock_busy = false;
        std::size_t total_active = 0;
        std::uint64_t total_rejected = 0;
        std::size_t camoufox_longop_active = 0;
        std::size_t background_command_active = 0;
        bool shutdown_pending = false;
    };

    bounded_snapshot_t try_snapshot_bounded() const
    {
        bounded_snapshot_t out;
        std::unique_lock<std::mutex> lk(mutex_, std::try_to_lock);
        if (!lk.owns_lock()) {
            out.lock_busy = true;
            return out;
        }
        out.total_active = active_.size();
        out.shutdown_pending = shutdown_requested_.load(std::memory_order_acquire);
        for (const auto& kv : active_) {
            if (kv.second.kind == producer_kind_t::camoufox_longop)
                ++out.camoufox_longop_active;
            else if (kv.second.kind == producer_kind_t::background_command)
                ++out.background_command_active;
        }
        for (const auto& kv : kind_stats_)
            out.total_rejected += kv.second.total_rejected.load(std::memory_order_relaxed);
        return out;
    }

private:
    producer_quota_set_t quotas_;
    std::map<std::uint64_t, active_record_t> active_;
    std::map<std::string, kind_stats_t> kind_stats_;
    std::map<std::string, std::uint64_t> rejection_by_reason_;
    std::atomic<std::uint64_t> next_token_{0};
    std::atomic<bool> shutdown_requested_{false};
    mutable std::mutex mutex_;
};

class scoped_admission_t
{
public:
    scoped_admission_t() = default;
    scoped_admission_t(const scoped_admission_t&) = delete;
    scoped_admission_t& operator=(const scoped_admission_t&) = delete;

    scoped_admission_t(scoped_admission_t&& other) noexcept
    {
        move_from(other);
    }

    scoped_admission_t& operator=(scoped_admission_t&& other) noexcept
    {
        if (this != &other) {
            release("move_assign");
            move_from(other);
        }
        return *this;
    }

    ~scoped_admission_t()
    {
        release("scope_exit");
    }

    static scoped_admission_t acquire(const producer_identity_t& identity)
    {
        scoped_admission_t result;
        auto r = governor_t::instance().try_admit(identity);
        if (r.admitted) {
            result.token_ = r.admission_token;
            result.active_ = true;
            result.identity_ = identity;
        }
        return result;
    }

    bool active() const noexcept { return active_; }
    std::uint64_t token() const noexcept { return token_; }
    const admission_result_t& result() const noexcept { return result_; }

    void release(const char* reason = "completed")
    {
        if (!active_) return;
        governor_t::instance().release(token_, reason);
        active_ = false;
        token_ = 0;
    }

private:
    void move_from(scoped_admission_t& other) noexcept
    {
        token_ = other.token_;
        active_ = other.active_;
        identity_ = std::move(other.identity_);
        result_ = std::move(other.result_);
        other.active_ = false;
        other.token_ = 0;
    }

    std::uint64_t token_ = 0;
    bool active_ = false;
    producer_identity_t identity_;
    admission_result_t result_;
};

inline json rejection_json(const admission_result_t& r, const producer_identity_t& id)
{
    return {
        {"code", "MCP_DOWNSTREAM_CAPACITY_REJECT"},
        {"message", "Downstream producer capacity exhausted; work was not started."},
        {"disposition", "not_started"},
        {"reason", r.reason},
        {"quota", r.quota_name},
        {"scope", r.quota_scope},
        {"observed", r.observed},
        {"limit", r.limit},
        {"producer_kind", producer_kind_name(id.kind)},
        {"principal_id", id.principal_id},
        {"session_id", id.session_id},
        {"target_id", id.target_id},
        {"target_pid", id.target_pid},
        {"domain", id.domain},
        {"tool", id.tool_name},
        {"lane", id.lane},
        {"diagnostic_id", id.diagnostic_id},
        {"request_id", id.request_id},
        {"lease_token", id.lease_token},
        {"generation", id.generation}
    };
}

struct feature_worker_group_config_t
{
    std::string owner_subsystem;
    producer_kind_t kind = producer_kind_t::feature_worker;
    std::size_t worker_count = 4;
    std::size_t queue_depth = 32;
    std::uint64_t default_timeout_ms = 120000;
    std::string label_prefix;
};

class feature_worker_group_t
{
public:
    explicit feature_worker_group_t(const feature_worker_group_config_t& cfg)
        : state_(std::make_shared<state_t>(cfg))
    {
        diag::log_tagged_fmt("mcp_srv",
            "FEATURE-WORKER-GROUP-READY owner=%s kind=%s workers=%zu queue_depth=%zu runtime=central_taskflow",
            state_->cfg.owner_subsystem.c_str(),
            producer_kind_name(state_->cfg.kind),
            state_->cfg.worker_count,
            state_->cfg.queue_depth);
    }

    ~feature_worker_group_t()
    {
        shutdown();
    }

    bool post(std::function<void()> task, std::uint64_t timeout_ms = 0)
    {
        auto state = state_;
        if (!state || !task)
            return false;
        if (state->shutdown.load(std::memory_order_acquire)) {
            state->rejected.fetch_add(1, std::memory_order_acq_rel);
            return false;
        }
        if (state->queued_tasks.load(std::memory_order_acquire) >= state->cfg.queue_depth) {
            state->rejected.fetch_add(1, std::memory_order_acq_rel);
            return false;
        }
        auto job = std::make_shared<job_t>();
        job->seq = state->submitted.fetch_add(1, std::memory_order_acq_rel) + 1;
        job->label = state->cfg.label_prefix.empty()
            ? (state->cfg.owner_subsystem + ".fwt." + std::to_string(job->seq))
            : (state->cfg.label_prefix + "." + std::to_string(job->seq));
        job->fn = std::move(task);
        job->deadline_ms = now_ms() + (timeout_ms != 0 ? timeout_ms : state->cfg.default_timeout_ms);

        aida::infra::taskflow_runtime::task_descriptor_t desc;
        desc.owner_subsystem = state->cfg.owner_subsystem.c_str();
        desc.label = job->label.c_str();
        desc.thread_class = "feature_worker";
        desc.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        desc.priority = 3;
        desc.deadline_ms = job->deadline_ms;
        desc.failure_policy = "reject_not_started";
        desc.shutdown_policy = "cancel_or_drain";
        desc.no_capacity_reason = "feature_worker_runtime_rejected";
        desc.cancel_hook = [state, job]() {
            cancel_not_started(state, job, "runtime_cancel_hook");
        };
        desc.cancellable_body = [state, job](const aida::infra::taskflow_runtime::cancellation_token_t& token) {
            run_job(state, job, token);
        };
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            if (state->shutdown.load(std::memory_order_acquire)) {
                state->rejected.fetch_add(1, std::memory_order_acq_rel);
                return false;
            }
            if (state->queued_jobs.size() >= state->cfg.queue_depth) {
                state->rejected.fetch_add(1, std::memory_order_acq_rel);
                return false;
            }
            state->queued_jobs[job->seq] = job;
            state->queued_tasks.fetch_add(1, std::memory_order_acq_rel);
            auto submit_result = aida::infra::taskflow_runtime::submit(std::move(desc));
            if (!submit_result.submitted) {
                state->queued_jobs.erase(job->seq);
                decrement_counter_if_nonzero(state->queued_tasks);
                state->rejected.fetch_add(1, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv",
                    "FEATURE-WORKER-GROUP-REJECT owner=%s label=%s reason=runtime_submit_failed runtime_reason='%s' queued=%zu active=%zu",
                    state->cfg.owner_subsystem.c_str(),
                    job->label.c_str(),
                    submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str(),
                    state->queued_jobs.size(),
                    state->active_jobs.size());
                return false;
            }
            job->runtime_job_id.store(submit_result.handle.id, std::memory_order_release);
            state->outstanding_jobs[job->seq] = job;
        }
        return true;
    }

    void shutdown()
    {
        auto state = state_;
        if (!state)
            return;
        if (state->shutdown.exchange(true, std::memory_order_acq_rel))
            return;
        std::vector<std::shared_ptr<job_t>> outstanding;
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            outstanding.reserve(state->outstanding_jobs.size());
            for (const auto& kv : state->outstanding_jobs) {
                if (kv.second)
                    outstanding.push_back(kv.second);
            }
        }
        for (const auto& job : outstanding) {
            if (!job)
                continue;
            job->cancel_requested.store(true, std::memory_order_release);
            const std::uint64_t job_id = job->runtime_job_id.load(std::memory_order_acquire);
            if (job_id != 0)
                (void)aida::infra::taskflow_runtime::cancel(aida::infra::taskflow_runtime::job_handle_t{job_id});
        }
        const std::uint64_t begin = now_ms();
        const std::uint64_t deadline = begin + 10000ULL;
        bool timed_out = false;
        for (const auto& job : outstanding) {
            if (!job)
                continue;
            const std::uint64_t job_id = job->runtime_job_id.load(std::memory_order_acquire);
            if (job_id == 0)
                continue;
            const std::uint64_t current = now_ms();
            if (current >= deadline) {
                timed_out = true;
                break;
            }
            const std::uint32_t wait_ms = static_cast<std::uint32_t>((std::min<std::uint64_t>)(deadline - current, 250ULL));
            auto wait_result = aida::infra::taskflow_runtime::wait_for(aida::infra::taskflow_runtime::job_handle_t{job_id}, wait_ms);
            if (wait_result.timed_out) {
                timed_out = true;
                break;
            }
        }
        std::size_t queued = 0;
        std::size_t active = 0;
        std::size_t live = 0;
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            queued = state->queued_jobs.size();
            active = state->active_jobs.size();
            live = state->outstanding_jobs.size();
            if (!timed_out && active == 0) {
                state->queued_jobs.clear();
                state->active_jobs.clear();
                state->outstanding_jobs.clear();
            }
        }
        diag::log_tagged_fmt("mcp_srv",
            "FEATURE-WORKER-GROUP-SHUTDOWN owner=%s queued=%zu active=%zu outstanding=%zu submitted=%llu finished=%llu rejected=%llu timed_out=%d",
            state->cfg.owner_subsystem.c_str(),
            queued,
            active,
            live,
            static_cast<unsigned long long>(state->submitted.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(state->finished.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(state->rejected.load(std::memory_order_acquire)),
            timed_out ? 1 : 0);
    }

    std::size_t active_workers() const
    {
        auto state = state_;
        return state ? state->active_workers.load(std::memory_order_acquire) : 0;
    }

    std::size_t queued_tasks() const
    {
        auto state = state_;
        return state ? state->queued_tasks.load(std::memory_order_acquire) : 0;
    }

    std::size_t worker_count() const
    {
        auto state = state_;
        return state ? state->cfg.worker_count : 0;
    }

    json stats_json() const
    {
        auto state = state_;
        if (!state)
            return json::object();
        return {
            {"owner", state->cfg.owner_subsystem},
            {"kind", producer_kind_name(state->cfg.kind)},
            {"workers", state->cfg.worker_count},
            {"active_workers", state->active_workers.load(std::memory_order_acquire)},
            {"queued_tasks", state->queued_tasks.load(std::memory_order_acquire)},
            {"queue_depth", state->cfg.queue_depth},
            {"shutdown", state->shutdown.load(std::memory_order_acquire)},
            {"submitted", state->submitted.load(std::memory_order_acquire)},
            {"finished", state->finished.load(std::memory_order_acquire)},
            {"rejected", state->rejected.load(std::memory_order_acquire)}
        };
    }

private:
    struct job_t
    {
        std::uint64_t seq = 0;
        std::string label;
        std::function<void()> fn;
        std::uint64_t deadline_ms = 0;
        std::atomic<std::uint64_t> runtime_job_id{0};
        std::atomic<bool> cancel_requested{false};
        std::atomic<bool> not_started_finalized{false};
    };

    struct state_t
    {
        explicit state_t(const feature_worker_group_config_t& input) : cfg(input) {}
        feature_worker_group_config_t cfg;
        mutable std::mutex mutex;
        std::map<std::uint64_t, std::shared_ptr<job_t>> queued_jobs;
        std::map<std::uint64_t, std::shared_ptr<job_t>> active_jobs;
        std::map<std::uint64_t, std::shared_ptr<job_t>> outstanding_jobs;
        std::atomic<bool> shutdown{false};
        std::atomic<std::size_t> active_workers{0};
        std::atomic<std::size_t> queued_tasks{0};
        std::atomic<std::uint64_t> submitted{0};
        std::atomic<std::uint64_t> finished{0};
        std::atomic<std::uint64_t> rejected{0};
    };

    static void decrement_counter_if_nonzero(std::atomic<std::size_t>& value)
    {
        std::size_t current = value.load(std::memory_order_acquire);
        while (current != 0 &&
               !value.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }
    }

    static bool cancel_not_started(const std::shared_ptr<state_t>& state, const std::shared_ptr<job_t>& job, const char* reason)
    {
        if (!state || !job)
            return false;
        job->cancel_requested.store(true, std::memory_order_release);
        bool removed = false;
        std::size_t queued_after = 0;
        std::size_t active_after = 0;
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            auto it = state->queued_jobs.find(job->seq);
            if (it != state->queued_jobs.end()) {
                state->queued_jobs.erase(it);
                state->outstanding_jobs.erase(job->seq);
                removed = true;
                decrement_counter_if_nonzero(state->queued_tasks);
            }
            queued_after = state->queued_jobs.size();
            active_after = state->active_jobs.size();
        }
        if (!removed)
            return false;
        if (!job->not_started_finalized.exchange(true, std::memory_order_acq_rel)) {
            job->fn = {};
            state->finished.fetch_add(1, std::memory_order_acq_rel);
            diag::log_tagged_fmt("mcp_srv",
                "FEATURE-WORKER-GROUP-CANCELLED owner=%s label=%s job_id=%llu reason=%s queued=%zu active=%zu",
                state->cfg.owner_subsystem.c_str(),
                job->label.c_str(),
                static_cast<unsigned long long>(job->runtime_job_id.load(std::memory_order_acquire)),
                reason ? reason : "cancelled",
                queued_after,
                active_after);
        }
        return true;
    }

    static DWORD invoke_task_seh(const std::shared_ptr<job_t>& job)
    {
        if (!job || !job->fn)
            return 0;
        return aida::infra::win_thread::run_function_seh_guarded(job->fn);
    }

    static void run_job(const std::shared_ptr<state_t>& state,
                        const std::shared_ptr<job_t>& job,
                        const aida::infra::taskflow_runtime::cancellation_token_t& token)
    {
        if (!state || !job)
            return;
        if (token.requested.load(std::memory_order_acquire) || job->cancel_requested.load(std::memory_order_acquire)) {
            if (cancel_not_started(state, job, "cancelled_before_start"))
                return;
            if (job->not_started_finalized.load(std::memory_order_acquire))
                return;
        }
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            state->queued_jobs.erase(job->seq);
            state->active_jobs[job->seq] = job;
            decrement_counter_if_nonzero(state->queued_tasks);
        }
        state->active_workers.fetch_add(1, std::memory_order_acq_rel);
        struct finish_guard_t {
            std::shared_ptr<state_t> state;
            std::shared_ptr<job_t> job;
            ~finish_guard_t()
            {
                if (!state || !job)
                    return;
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->active_jobs.erase(job->seq);
                    state->outstanding_jobs.erase(job->seq);
                }
                state->active_workers.fetch_sub(1, std::memory_order_acq_rel);
                job->fn = {};
                state->finished.fetch_add(1, std::memory_order_acq_rel);
            }
        } finish{state, job};
        if (token.requested.load(std::memory_order_acquire) || job->cancel_requested.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("mcp_srv",
                "FEATURE-WORKER-GROUP-CANCELLED-ACTIVE owner=%s label=%s job_id=%llu",
                state->cfg.owner_subsystem.c_str(),
                job->label.c_str(),
                static_cast<unsigned long long>(job->runtime_job_id.load(std::memory_order_acquire)));
            return;
        }
        DWORD code = 0;
        try {
            code = invoke_task_seh(job);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "FEATURE-WORKER-GROUP-EXCEPTION owner=%s label=%s err='%s'",
                state->cfg.owner_subsystem.c_str(),
                job->label.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "FEATURE-WORKER-GROUP-EXCEPTION owner=%s label=%s err='<unknown>'",
                state->cfg.owner_subsystem.c_str(),
                job->label.c_str());
        }
        if (code != 0)
            diag::log_tagged_fmt("mcp_srv",
                "FEATURE-WORKER-GROUP-EXCEPTION owner=%s label=%s code=0x%08lX",
                state->cfg.owner_subsystem.c_str(),
                job->label.c_str(),
                static_cast<unsigned long>(code));
    }

    std::shared_ptr<state_t> state_;
};

}
}
