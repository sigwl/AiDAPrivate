#include "test_all_analysis.h"

#include "test_all_features.hpp"
#include "test_lab_bounded_runner.hpp"
#include "../emulation/symbolic_engine.hpp"
#include "../emulation/deobfuscation_engine.hpp"
#include "../analysis/code_patcher.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/binary_map.hpp"
#include "../analysis/benchmark/benchmark_runner.hpp"
#include "../analysis/benchmark/benchmark_sla.hpp"
#include "../analysis/source_reconstructor.hpp"
#include "../analysis/xref_engine.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../analysis/workspace/advanced_cfg.hpp"
#include "../analysis/workspace/calling_convention.hpp"
#include "../analysis/workspace/compact_ir.hpp"
#include "../analysis/workspace/fact_residency.hpp"
#include "../analysis/workspace/paged_fact_staging.hpp"
#include "../analysis/workspace/publication_indexes.hpp"
#include "../analysis/workspace/decompiler_feedback.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/pseudocode_readability.hpp"
#include "../analysis/workspace/semantic_fusion.hpp"
#include "../analysis/workspace/type_recovery.hpp"
#include "../analysis/fuzzer_engine.hpp"
#include "../analysis/struct_recon_engine.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/pdb_downloader.hpp"
#include "../analysis/analysis_hub_view.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/xref_index.hpp"
#include "../editor/expression_eval.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../infra/fast_containers.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <Windows.h>
#include <psapi.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace test_all_features {

namespace {

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...);

static void format_timestamp(char* out, std::size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void write_log_file(HANDLE hf, const std::string& line) {
    test_all_features::write_full_test_log_line(hf, line.data(), line.size());
}

static std::shared_ptr<aida::analysis::analysis_workspace_t> analysis_fixture_workspace() {
    for (const auto& workspace : aida::analysis::workspace_registry().list()) {
        if (workspace && workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
            !workspace->closing() && !workspace->closed())
            return workspace;
    }
    return {};
}

static disasm_view::workspace_context_t analysis_fixture_context() {
    return disasm_view::capture_workspace(analysis_fixture_workspace());
}

static bool wait_for_analysis_overlay(const disasm_view::workspace_context_t& context,
                                      std::string& error) {
    if (!context || !context.view)
        return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (context.view->pending_mutations.load(std::memory_order_acquire) != 0 &&
           std::chrono::steady_clock::now() < deadline)
        Sleep(10);
    std::lock_guard<std::mutex> lock(context.view->mutex);
    error = context.view->mutation_error;
    return context.view->pending_mutations.load(std::memory_order_acquire) == 0 && error.empty();
}

static bool analysis_comment(const disasm_view::workspace_context_t& context,
                             const aida::analysis::address_t& address,
                             const std::string& text, std::string& error) {
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->mutation_error.clear();
    }
    return disasm_view::queue_comment(context, address, text) &&
        wait_for_analysis_overlay(context, error);
}

static bool analysis_rename(const disasm_view::workspace_context_t& context,
                            const aida::analysis::address_t& address,
                            const std::string& name, std::string& error) {
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->mutation_error.clear();
    }
    return disasm_view::queue_rename(context, address, name) &&
        wait_for_analysis_overlay(context, error);
}

static std::vector<aida::analysis::address_t> analysis_fixture_addresses(
    const disasm_view::workspace_context_t& context, std::size_t count) {
    std::vector<aida::analysis::address_t> result;
    if (!context || !context.publication || !context.publication->snapshot)
        return result;
    for (const auto& instruction : context.publication->snapshot->instructions) {
        if (std::find(result.begin(), result.end(), instruction.address) == result.end())
            result.push_back(instruction.address);
        if (result.size() == count)
            break;
    }
    return result;
}

struct analysis_xref_fixture_t {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::analysis::address_t target;
    std::size_t count = 0;
};

static analysis_xref_fixture_t analysis_xref_fixture() {
    analysis_xref_fixture_t result;
    for (const auto& workspace : aida::analysis::workspace_registry().list()) {
        if (!workspace || workspace->target_kind() != aida::analysis::target_kind_t::static_file)
            continue;
        const auto snapshot = workspace->snapshot();
        if (!snapshot)
            continue;
        std::map<aida::analysis::address_t, std::size_t> counts;
        for (const auto& xref : snapshot->xrefs)
            ++counts[xref.target];
        for (const auto& item : counts) {
            if (item.second > result.count) {
                result.workspace = workspace;
                result.target = item.first;
                result.count = item.second;
            }
        }
    }
    return result;
}

static void test_xref_db_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto fixture = analysis_xref_fixture();
    if (!fixture.workspace || fixture.count == 0) {
        log_msg(hf, "xrefdb_st", "FAIL -- no explicit static workspace with published xrefs");
        failed.fetch_add(1);
        return;
    }
    const auto publication = fixture.workspace->analysis_publication();
    const auto queried = xref_index::query_to(fixture.workspace, fixture.target, fixture.count);
    const bool valid = publication && publication->snapshot && queried &&
        queried.value().size() == fixture.count &&
        publication->snapshot->xrefs.size() >= fixture.count;
    log_msg(hf, "xrefdb_st", "STATE -- binary_id=%s published=%d total_xrefs=%zu target_count=%zu queried=%zu",
        fixture.workspace->identity().binary_id().to_hex().c_str(), publication ? 1 : 0,
        publication && publication->snapshot ? publication->snapshot->xrefs.size() : 0,
        fixture.count, queried ? queried.value().size() : 0);
    if (valid) {
        log_msg(hf, "xrefdb_st", "PASS -- workspace-owned xref publication is complete and queryable");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xrefdb_st", "FAIL -- workspace-owned xref publication/query mismatch");
        failed.fetch_add(1);
    }
}

static void test_xref_db_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto fixture = analysis_xref_fixture();
    if (!fixture.workspace || fixture.count == 0) {
        log_msg(hf, "xrefdb_qt", "FAIL -- no explicit static workspace xref fixture");
        failed.fetch_add(1);
        return;
    }
    const auto queried = xref_index::query_to(fixture.workspace, fixture.target, fixture.count + 1);
    const bool valid = queried && queried.value().size() == fixture.count &&
        !xref_index::has_more(fixture.workspace, fixture.target, fixture.count);
    log_msg(hf, "xrefdb_qt", "STATE -- binary_id=%s expected=%zu returned=%zu has_more_at_total=%d",
        fixture.workspace->identity().binary_id().to_hex().c_str(), fixture.count,
        queried ? queried.value().size() : 0,
        xref_index::has_more(fixture.workspace, fixture.target, fixture.count) ? 1 : 0);
    if (valid) {
        log_msg(hf, "xrefdb_qt", "PASS -- explicit workspace query_to returned the complete target set");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xrefdb_qt", "FAIL -- explicit workspace query_to result mismatch");
        failed.fetch_add(1);
    }
}

static bool restore_analysis_comment(const disasm_view::workspace_context_t& context,
                                     const aida::analysis::address_t& address,
                                     const std::string& original) {
    std::string error;
    return analysis_comment(context, address, original, error);
}

static bool restore_analysis_name(const disasm_view::workspace_context_t& context,
                                  const aida::analysis::address_t& address,
                                  const std::string& original_symbol,
                                  const std::string& original_resolved) {
    std::string error;
    const std::string original_custom = original_resolved == original_symbol ? std::string() : original_resolved;
    return analysis_rename(context, address, original_custom, error);
}

static void test_comment_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto context = analysis_fixture_context();
    const auto addresses = analysis_fixture_addresses(context, 1);
    if (addresses.size() != 1) {
        log_msg(hf, "cmt_store", "FAIL -- no explicit workspace instruction address");
        failed.fetch_add(1);
        return;
    }
    const auto original = disasm_view::comment(context, addresses[0]);
    std::string error;
    const bool written = analysis_comment(context, addresses[0], "test_comment_analysis", error);
    const bool roundtrip = written && disasm_view::comment(context, addresses[0]) == "test_comment_analysis";
    const bool cleared = analysis_comment(context, addresses[0], std::string(), error) &&
        disasm_view::comment(context, addresses[0]).empty();
    const bool restored = restore_analysis_comment(context, addresses[0], original);
    if (roundtrip && cleared && restored) {
        log_msg(hf, "cmt_store", "PASS -- workspace comment set/get/clear roundtrip preserved prior state");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_store", "FAIL -- workspace comment roundtrip failed error=\"%s\"", error.c_str());
        failed.fetch_add(1);
    }
}

static void test_comment_store_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto context = analysis_fixture_context();
    const auto addresses = analysis_fixture_addresses(context, 2);
    if (addresses.size() != 2) {
        log_msg(hf, "cmt_multi", "FAIL -- fewer than two workspace instruction addresses");
        failed.fetch_add(1);
        return;
    }
    const std::string original_a = disasm_view::comment(context, addresses[0]);
    const std::string original_b = disasm_view::comment(context, addresses[1]);
    std::string error;
    const bool set_a = analysis_comment(context, addresses[0], "analysis_comment_a", error);
    const bool set_b = analysis_comment(context, addresses[1], "analysis_comment_b", error);
    const bool distinct = set_a && set_b &&
        disasm_view::comment(context, addresses[0]) == "analysis_comment_a" &&
        disasm_view::comment(context, addresses[1]) == "analysis_comment_b";
    const bool restored = restore_analysis_comment(context, addresses[0], original_a) &&
        restore_analysis_comment(context, addresses[1], original_b);
    if (distinct && restored) {
        log_msg(hf, "cmt_multi", "PASS -- two workspace comments remained address-isolated");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_multi", "FAIL -- workspace comment isolation failed error=\"%s\"", error.c_str());
        failed.fetch_add(1);
    }
}

static void test_comment_store_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto context = analysis_fixture_context();
    const auto addresses = analysis_fixture_addresses(context, 1);
    if (addresses.empty()) {
        log_msg(hf, "cmt_over", "FAIL -- no workspace instruction address");
        failed.fetch_add(1);
        return;
    }
    const auto original = disasm_view::comment(context, addresses[0]);
    std::string error;
    const bool first = analysis_comment(context, addresses[0], "analysis_comment_first", error);
    const bool second = analysis_comment(context, addresses[0], "analysis_comment_second", error);
    const bool overwritten = first && second &&
        disasm_view::comment(context, addresses[0]) == "analysis_comment_second";
    const bool restored = restore_analysis_comment(context, addresses[0], original);
    if (overwritten && restored) {
        log_msg(hf, "cmt_over", "PASS -- workspace comment overwrite retained the newest value");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_over", "FAIL -- workspace comment overwrite failed error=\"%s\"", error.c_str());
        failed.fetch_add(1);
    }
}

static void test_rename_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto context = analysis_fixture_context();
    const auto addresses = analysis_fixture_addresses(context, 1);
    if (addresses.empty()) {
        log_msg(hf, "ren_store", "FAIL -- no workspace instruction address");
        failed.fetch_add(1);
        return;
    }
    const auto symbol = disasm_view::resolve_symbol(context, addresses[0]);
    const auto original = disasm_view::resolve_name(context, addresses[0]);
    std::string error;
    const bool written = analysis_rename(context, addresses[0], "test_label_analysis", error);
    const bool roundtrip = written && disasm_view::resolve_name(context, addresses[0]) == "test_label_analysis";
    const bool restored = restore_analysis_name(context, addresses[0], symbol, original);
    if (roundtrip && restored) {
        log_msg(hf, "ren_store", "PASS -- workspace rename set/get roundtrip preserved prior state");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_store", "FAIL -- workspace rename roundtrip failed error=\"%s\"", error.c_str());
        failed.fetch_add(1);
    }
}

static void test_rename_store_resolve_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    const auto context = analysis_fixture_context();
    const auto addresses = analysis_fixture_addresses(context, 1);
    if (addresses.empty()) {
        log_msg(hf, "ren_resolve", "FAIL -- no workspace instruction address");
        failed.fetch_add(1);
        return;
    }
    const auto symbol = disasm_view::resolve_symbol(context, addresses[0]);
    const auto original = disasm_view::resolve_name(context, addresses[0]);
    std::string error;
    const bool renamed = analysis_rename(context, addresses[0], "analysis_resolve_override", error) &&
        disasm_view::resolve_name(context, addresses[0]) == "analysis_resolve_override";
    const bool cleared = analysis_rename(context, addresses[0], std::string(), error) &&
        disasm_view::resolve_name(context, addresses[0]) == symbol;
    const bool restored = restore_analysis_name(context, addresses[0], symbol, original);
    if (renamed && cleared && restored) {
        log_msg(hf, "ren_resolve", "PASS -- workspace rename override fell back to the published symbol");
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_resolve", "FAIL -- workspace resolve-or behavior failed error=\"%s\"", error.c_str());
        failed.fetch_add(1);
    }
}

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
    char ts[40];
    format_timestamp(ts, sizeof(ts));

    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
    std::string s(line);

    write_log_file(hf, s);
    test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
}

static int driver_attached_flag(uint32_t pid) {
    return (pid != 0 && driver_bridge::using_kernel_driver()) ? 1 : 0;
}

static bool require_attached_live_target(HANDLE hf, const char* tag, std::atomic<int>& failed) {
    uint32_t pid = driver_bridge::attached_pid();
    const int driver_attached = driver_attached_flag(pid);
    if (pid == 0) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: no active attached test target PID (target_pid=0 driver_attached=%d status=\"%s\" last_error=\"%s\")",
            driver_attached,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    uint32_t exit_code = 0;
    if (!driver_bridge::attached_process_alive(&exit_code)) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: attached test target is not alive (target_pid=%u driver_attached=%d exit_code_or_error=0x%08X status=\"%s\" last_error=\"%s\")",
            (unsigned)pid,
            driver_attached,
            (unsigned)exit_code,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    if (!driver_attached) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: kernel driver bridge is not attached for live target (target_pid=%u driver_attached=0 status=\"%s\" last_error=\"%s\")",
            (unsigned)pid,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    return true;
}

static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count());
}

struct ntdll_export_resolution_t {
    uint64_t address = 0;
    uint64_t local_rva = 0;
    std::string module_name;
    const char* method = "unresolved";
    bool local_export_ok = false;
    bool ntdll_seen = false;
    size_t module_count = 0;
    uint32_t slow_attempts = 0;
    long long local_us = 0;
    long long enum_us = 0;
    long long slow_us = 0;
};

static bool contains_ascii_ci(const std::string& text, const char* needle) {
    if (!needle || !needle[0])
        return true;
    const size_t needle_len = std::strlen(needle);
    if (text.size() < needle_len)
        return false;
    for (size_t i = 0; i + needle_len <= text.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            char a = text[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
            if (a != b) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

static bool module_is_ntdll(const driver_bridge::module_info_t& mod) {
    return _stricmp(mod.name.c_str(), "ntdll.dll") == 0 ||
        contains_ascii_ci(mod.name, "ntdll") ||
        contains_ascii_ci(mod.path, "ntdll");
}

static std::string wide_to_utf8_lossy(const std::wstring& text) {
    if (text.empty())
        return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<size_t>(needed), '\0');
    int wrote = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    if (wrote <= 0)
        return {};
    out.resize(static_cast<size_t>(wrote));
    return out;
}

static std::string format_win32_error_text(DWORD err) {
    char* buf = nullptr;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string text;
    if (n != 0 && buf)
        text.assign(buf, n);
    if (buf)
        LocalFree(buf);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '\t'))
        text.pop_back();
    if (text.empty())
        text = "unknown error";
    return text;
}

static bool analysis_process_alive_by_pid(uint32_t pid, uint32_t* exit_code_out = nullptr) {
    if (exit_code_out)
        *exit_code_out = 0;
    if (pid == 0)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        const DWORD err = GetLastError();
        if (exit_code_out)
            *exit_code_out = err;
        return err == ERROR_ACCESS_DENIED;
    }
    DWORD exit_code = 0;
    const BOOL ok = GetExitCodeProcess(h, &exit_code);
    const DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (exit_code_out)
        *exit_code_out = ok ? static_cast<uint32_t>(exit_code) : err;
    return ok && exit_code == STILL_ACTIVE;
}

static void close_handle_if_open(HANDLE& h) {
    if (h && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        h = nullptr;
    }
}

static std::wstring quote_wide_arg(const std::wstring& arg) {
    std::wstring out;
    out.reserve(arg.size() + 2);
    out.push_back(L'"');
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(c);
            slashes = 0;
            continue;
        }
        if (slashes != 0) {
            out.append(slashes, L'\\');
            slashes = 0;
        }
        out.push_back(c);
    }
    if (slashes != 0)
        out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

static uint64_t remote_module_base_ci(uint32_t pid, const char* module_fragment) {
    if (pid == 0 || !module_fragment || !module_fragment[0])
        return 0;
    for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
        if (mod.base != 0 && (contains_ascii_ci(mod.name, module_fragment) || contains_ascii_ci(mod.path, module_fragment)))
            return mod.base;
    }
    return 0;
}

static std::wstring current_module_path_wide() {
    std::vector<wchar_t> buf(MAX_PATH);
    for (;;) {
        SetLastError(ERROR_SUCCESS);
        DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0)
            return {};
        if (static_cast<size_t>(len) < buf.size() - 1)
            return std::wstring(buf.data(), len);
        buf.resize(buf.size() * 2);
        if (buf.size() > 32768)
            return {};
    }
}

static std::wstring parent_path_wide(const std::wstring& path) {
    if (path.empty())
        return {};
    std::filesystem::path p(path);
    std::filesystem::path parent = p.parent_path();
    return parent.wstring();
}

static std::wstring join_path_wide(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty())
        return leaf;
    std::filesystem::path p(base);
    p /= leaf;
    return p.wstring();
}

static bool file_exists_wide(const std::wstring& path) {
    if (path.empty())
        return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static bool dir_exists_wide(const std::wstring& path) {
    if (path.empty())
        return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static std::wstring read_env_wide_local(const wchar_t* name) {
    if (!name || !name[0])
        return {};
    DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0)
        return {};
    std::wstring value(need, L'\0');
    DWORD got = GetEnvironmentVariableW(name, value.data(), need);
    if (got == 0 || got >= need)
        return {};
    value.resize(got);
    return value;
}

static void add_integrity_target_candidate(std::vector<std::pair<std::wstring, std::string>>& candidates,
                                           const std::wstring& path,
                                           const char* label) {
    if (!path.empty())
        candidates.emplace_back(path, label ? label : "candidate");
}

static void add_integrity_target_root_candidates(std::vector<std::pair<std::wstring, std::string>>& candidates,
                                                 const std::wstring& root,
                                                 const char* label) {
    if (root.empty())
        return;
    std::string prefix = label ? label : "root";
    add_integrity_target_candidate(candidates, join_path_wide(root, L"AiDA_TestTarget.exe"), (prefix + "/direct").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(root, L"Release"), L"AiDA_TestTarget.exe"), (prefix + "/Release").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(root, L"Debug"), L"AiDA_TestTarget.exe"), (prefix + "/Debug").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(root, L"RelWithDebInfo"), L"AiDA_TestTarget.exe"), (prefix + "/RelWithDebInfo").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(join_path_wide(root, L"build-ninja"), L"Release"), L"AiDA_TestTarget.exe"), (prefix + "/build-ninja/Release").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(root, L"build-ninja"), L"AiDA_TestTarget.exe"), (prefix + "/build-ninja").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(root, L"deps"), L"AiDA_TestTarget.exe"), (prefix + "/deps").c_str());
    add_integrity_target_candidate(candidates, join_path_wide(join_path_wide(join_path_wide(root, L"package"), L"deps"), L"AiDA_TestTarget.exe"), (prefix + "/package/deps").c_str());
}

static std::wstring find_integrity_test_target(HANDLE hf, const char* tag) {
    std::vector<std::pair<std::wstring, std::string>> candidates;
    const std::wstring env = read_env_wide_local(L"AIDA_TEST_TARGET");
    if (!env.empty()) {
        if (dir_exists_wide(env))
            add_integrity_target_root_candidates(candidates, env, "AIDA_TEST_TARGET");
        else
            add_integrity_target_candidate(candidates, env, "AIDA_TEST_TARGET");
    }

    const std::wstring module_path = current_module_path_wide();
    const std::wstring module_dir = parent_path_wide(module_path);
    if (!module_dir.empty())
        add_integrity_target_root_candidates(candidates, module_dir, "module_dir");

    wchar_t cwd_buf[MAX_PATH] = {};
    DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, cwd_buf);
    if (cwd_len != 0 && cwd_len < MAX_PATH)
        add_integrity_target_root_candidates(candidates, cwd_buf, "cwd");

    std::wstring cursor = module_dir;
    for (int i = 0; i < 8 && !cursor.empty(); ++i) {
        char label[64] = {};
        _snprintf_s(label, sizeof(label), _TRUNCATE, "module_parent_%02d", i);
        add_integrity_target_root_candidates(candidates, cursor, label);
        std::wstring parent = parent_path_wide(cursor);
        if (parent.empty() || _wcsicmp(parent.c_str(), cursor.c_str()) == 0)
            break;
        cursor = parent;
    }

    add_integrity_target_candidate(candidates, L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\Release\\AiDA_TestTarget.exe", "fallback/build-ninja/Release");
    add_integrity_target_candidate(candidates, L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\AiDA_TestTarget.exe", "fallback/build-ninja");

    for (const auto& candidate : candidates) {
        const bool exists = file_exists_wide(candidate.first);
        log_msg(hf, tag, "SIDE-FIXTURE-TARGET-CANDIDATE -- label=%s exists=%d path=%s",
            candidate.second.c_str(),
            exists ? 1 : 0,
            wide_to_utf8_lossy(candidate.first).c_str());
        if (exists)
            return candidate.first;
    }

    log_msg(hf, tag, "FAIL -- AiDA_TestTarget.exe sidecar not found candidates=%zu module_path=%s cwd_len=%lu",
        candidates.size(),
        wide_to_utf8_lossy(module_path).c_str(),
        static_cast<unsigned long>(cwd_len));
    return {};
}

static std::wstring make_integrity_sidecar_log_path() {
    wchar_t temp[MAX_PATH] = {};
    DWORD temp_len = GetTempPathW(MAX_PATH, temp);
    std::error_code temp_ec;
    std::filesystem::path root = (temp_len != 0 && temp_len < MAX_PATH) ? std::filesystem::path(temp) : std::filesystem::temp_directory_path(temp_ec);
    if (root.empty())
        root = std::filesystem::current_path(temp_ec);
    if (root.empty())
        root = L".";
    root /= L"AiDA_TestLab";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    wchar_t file[128] = {};
    _snwprintf_s(file, _TRUNCATE, L"integrity_sidecar_%lu_%llu.log",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(GetTickCount64()));
    root /= file;
    return root.wstring();
}

static bool env_entry_matches_key(const wchar_t* entry, const wchar_t* key) {
    if (!entry || !key || !key[0])
        return false;
    const size_t key_len = std::wcslen(key);
    return _wcsnicmp(entry, key, key_len) == 0 && entry[key_len] == L'=';
}

static std::vector<wchar_t> build_integrity_sidecar_environment(const std::vector<std::pair<std::wstring, std::wstring>>& overrides) {
    std::vector<wchar_t> block;
    wchar_t* inherited = GetEnvironmentStringsW();
    if (inherited) {
        const wchar_t* p = inherited;
        while (*p) {
            bool skip = false;
            for (const auto& kv : overrides) {
                if (env_entry_matches_key(p, kv.first.c_str())) {
                    skip = true;
                    break;
                }
            }
            const size_t len = std::wcslen(p) + 1;
            if (!skip)
                block.insert(block.end(), p, p + len);
            p += len;
        }
        FreeEnvironmentStringsW(inherited);
    }
    for (const auto& kv : overrides) {
        if (kv.first.empty())
            continue;
        block.insert(block.end(), kv.first.begin(), kv.first.end());
        block.push_back(L'=');
        block.insert(block.end(), kv.second.begin(), kv.second.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

struct system_export_resolution_t {
    uint64_t address = 0;
    uint64_t local_rva = 0;
    std::string module_name;
    const char* method = "unresolved";
    bool local_export_ok = false;
    bool module_seen = false;
    size_t module_count = 0;
    uint32_t slow_attempts = 0;
    long long local_us = 0;
    long long enum_us = 0;
    long long slow_us = 0;
};

static const wchar_t* local_system_module_wide(const char* module_name) {
    if (!module_name)
        return nullptr;
    if (_stricmp(module_name, "kernel32.dll") == 0)
        return L"kernel32.dll";
    if (_stricmp(module_name, "kernelbase.dll") == 0)
        return L"kernelbase.dll";
    if (_stricmp(module_name, "ntdll.dll") == 0)
        return L"ntdll.dll";
    return nullptr;
}

static bool module_matches_name_ci(const driver_bridge::module_info_t& mod, const char* module_name) {
    if (!module_name || !module_name[0])
        return false;
    return _stricmp(mod.name.c_str(), module_name) == 0 ||
        contains_ascii_ci(mod.name, module_name) ||
        contains_ascii_ci(mod.path, module_name);
}

static system_export_resolution_t resolve_attached_system_export(HANDLE hf,
                                                                 const char* tag,
                                                                 uint32_t pid,
                                                                 const char* module_name,
                                                                 const char* export_name) {
    system_export_resolution_t out;
    if (pid == 0 || !module_name || !module_name[0] || !export_name || !export_name[0])
        return out;

    auto local_t0 = std::chrono::steady_clock::now();
    HMODULE local_mod = nullptr;
    const wchar_t* local_name = local_system_module_wide(module_name);
    if (local_name)
        local_mod = GetModuleHandleW(local_name);
    FARPROC local_fn = local_mod ? GetProcAddress(local_mod, export_name) : nullptr;
    HMODULE owner = nullptr;
    const bool owner_ok = local_fn &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(local_fn), &owner) &&
        owner == local_mod;
    if (local_mod && local_fn && owner_ok) {
        const uintptr_t local_base = reinterpret_cast<uintptr_t>(local_mod);
        const uintptr_t local_addr = reinterpret_cast<uintptr_t>(local_fn);
        if (local_addr > local_base) {
            out.local_rva = static_cast<uint64_t>(local_addr - local_base);
            out.local_export_ok = true;
        }
    }
    out.local_us = elapsed_us_since(local_t0);

    auto enum_t0 = std::chrono::steady_clock::now();
    const auto modules = driver_bridge::enumerate_modules_for(pid);
    out.enum_us = elapsed_us_since(enum_t0);
    out.module_count = modules.size();

    for (const auto& mod : modules) {
        if (mod.base == 0 || !module_matches_name_ci(mod, module_name))
            continue;
        out.module_seen = true;
        if (out.local_export_ok && out.local_rva != 0 && (mod.size == 0 || out.local_rva < mod.size)) {
            out.address = mod.base + out.local_rva;
            out.module_name = mod.name.empty() ? mod.path : mod.name;
            out.method = "local_rva";
            diag::log_tagged_fmt("test_analysis_detail",
                "%s resolve_system_export name=%s module=%s pid=%u method=%s remote_module=%s base=0x%llX size=0x%llX rva=0x%llX va=0x%llX local_us=%lld enum_us=%lld modules=%zu",
                tag ? tag : "analysis",
                export_name,
                module_name,
                (unsigned)pid,
                out.method,
                out.module_name.empty() ? "<none>" : out.module_name.c_str(),
                (unsigned long long)mod.base,
                (unsigned long long)mod.size,
                (unsigned long long)out.local_rva,
                (unsigned long long)out.address,
                out.local_us,
                out.enum_us,
                out.module_count);
            return out;
        }
    }

    for (const auto& mod : modules) {
        if (mod.base == 0 || !module_matches_name_ci(mod, module_name))
            continue;
        auto slow_t0 = std::chrono::steady_clock::now();
        uint64_t fn = driver_bridge::resolve_export_for(pid, mod.base, export_name);
        const long long slow_call_us = elapsed_us_since(slow_t0);
        out.slow_us += slow_call_us;
        ++out.slow_attempts;
        diag::log_tagged_fmt("test_analysis_detail",
            "%s resolve_system_export_fallback name=%s module=%s pid=%u remote_module=%s base=0x%llX size=0x%llX result=0x%llX slow_call_us=%lld slow_total_us=%lld attempts=%u local_export_ok=%d local_rva=0x%llX enum_us=%lld status='%s' last_error='%s'",
            tag ? tag : "analysis",
            export_name,
            module_name,
            (unsigned)pid,
            (mod.name.empty() ? mod.path : mod.name).c_str(),
            (unsigned long long)mod.base,
            (unsigned long long)mod.size,
            (unsigned long long)fn,
            slow_call_us,
            out.slow_us,
            out.slow_attempts,
            out.local_export_ok ? 1 : 0,
            (unsigned long long)out.local_rva,
            out.enum_us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (fn != 0) {
            out.address = fn;
            out.module_name = mod.name.empty() ? mod.path : mod.name;
            out.method = "driver_resolver";
            return out;
        }
    }

    log_msg(hf, tag ? tag : "analysis",
        "WARN -- unresolved system export module=%s name=%s pid=%u local_export_ok=%d local_rva=0x%016llX module_seen=%d modules=%zu local_us=%lld enum_us=%lld slow_attempts=%u slow_us=%lld status=\"%s\" last_error=\"%s\"",
        module_name,
        export_name,
        (unsigned)pid,
        out.local_export_ok ? 1 : 0,
        (unsigned long long)out.local_rva,
        out.module_seen ? 1 : 0,
        out.module_count,
        out.local_us,
        out.enum_us,
        out.slow_attempts,
        out.slow_us,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    return out;
}

struct integrity_sidecar_probe_t {
    bool ok = false;
    const char* module = "";
    system_export_resolution_t resolved;
    page_guard_engine::remote_call_diag_snapshot_t remote_diag;
    driver_bridge::remote_call_execution_diag_t lower_diag;
    uint64_t result = 0;
    DWORD gle = 0;
    long long elapsed_ms = 0;
};

static integrity_sidecar_probe_t probe_integrity_sidecar_remote_call(HANDLE hf, const char* tag, uint32_t pid, int attempts = 1) {
    integrity_sidecar_probe_t out;
    auto t0 = std::chrono::steady_clock::now();
    const char* modules[] = { "kernel32.dll", "kernelbase.dll" };
    const uint32_t probe_timeout_ms = (attempts <= 1) ? 4500u : 2500u;
    for (const char* module_name : modules) {
        system_export_resolution_t resolved = resolve_attached_system_export(hf, tag, pid, module_name, "GetCurrentProcessId");
        if (resolved.address == 0) {
            out.module = module_name;
            out.resolved = resolved;
            continue;
        }
        SetLastError(ERROR_SUCCESS);
        const uint64_t result = page_guard_engine::remote_thread_call(pid, resolved.address, 0, 0, 0, 0, probe_timeout_ms, "testlab_integrity_sidecar_GetCurrentProcessId");
        const auto remote_diag = page_guard_engine::last_driver_remote_call_diag();
        const auto lower_diag = driver_bridge::last_remote_call_execution_diag();
        const DWORD gle = result == static_cast<uint64_t>(pid) ? ERROR_SUCCESS : GetLastError();
        out.module = module_name;
        out.resolved = resolved;
        out.remote_diag = remote_diag;
        out.lower_diag = lower_diag;
        out.result = result;
        out.gle = gle;
        out.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        out.ok = result == static_cast<uint64_t>(pid);
        diag::log_tagged_fmt("test_analysis_detail",
            "%s sidecar_remote_probe pid=%u active_pid=%u module=%s fn=GetCurrentProcessId va=0x%llX method=%s result=0x%llX expected=0x%llX ok=%d gle=%lu remote_call_id=%llu remote_ok=%d remote_execution_completed=%d remote_gle=%lu lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_generation_entry=%llu lower_generation_after=%llu lower_queue_depth_submit=%u lower_queue_depth_start=%u lower_queue_depth_after_pop=%u lower_inflight_submit=%u lower_inflight_start=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu elapsed_ms=%lld status='%s' last_error='%s'",
            tag ? tag : "analysis",
            (unsigned)pid,
            (unsigned)driver_bridge::attached_pid(),
            module_name,
            (unsigned long long)resolved.address,
            resolved.method,
            (unsigned long long)result,
            (unsigned long long)pid,
            out.ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            (unsigned long long)remote_diag.call_id,
            remote_diag.ok ? 1 : 0,
            remote_diag.lower_completed && remote_diag.lower_ok ? 1 : 0,
            static_cast<unsigned long>(remote_diag.gle),
            (unsigned long long)lower_diag.call_id,
            lower_diag.phase.c_str(),
            lower_diag.completion_reason.c_str(),
            lower_diag.completed ? 1 : 0,
            lower_diag.lower_ok ? 1 : 0,
            static_cast<unsigned long>(lower_diag.gle),
            (unsigned long long)lower_diag.generation_at_entry,
            (unsigned long long)lower_diag.generation_after,
            lower_diag.queue_depth_at_submit,
            lower_diag.queue_depth_at_start,
            lower_diag.queue_depth_after_pop,
            lower_diag.inflight_at_submit,
            lower_diag.inflight_at_start,
            lower_diag.inflight_after,
            (unsigned long long)lower_diag.queue_wait_ms,
            (unsigned long long)lower_diag.lower_elapsed_ms,
            out.elapsed_ms,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return out;
    }
    out.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    out.gle = GetLastError();
    return out;
}

struct integrity_hunter_sidecar_t {
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    DWORD pid = 0;
    std::wstring exe;
    std::wstring command;
    std::wstring workdir;
    std::wstring log_path;
    std::wstring ready_event;
    std::wstring done_event;
    std::wstring run_id;
    uint16_t port = 0;
    uint16_t http_port = 0;
};

static bool integrity_sidecar_exited(const integrity_hunter_sidecar_t& sidecar, DWORD& exit_code) {
    exit_code = 0;
    if (!sidecar.process)
        return true;
    if (!GetExitCodeProcess(sidecar.process, &exit_code))
        return true;
    return exit_code != STILL_ACTIVE;
}

static bool launch_integrity_hunter_sidecar(HANDLE hf, const char* tag, integrity_hunter_sidecar_t& sidecar) {
    sidecar.exe = find_integrity_test_target(hf, tag);
    if (sidecar.exe.empty())
        return false;

    if (GetFileAttributesW(sidecar.exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        const DWORD err = GetLastError();
        log_msg(hf, tag, "FAIL -- integrity sidecar AiDA_TestTarget.exe missing path=%s err=%lu text=%s",
            wide_to_utf8_lossy(sidecar.exe).c_str(),
            static_cast<unsigned long>(err),
            format_win32_error_text(err).c_str());
        return false;
    }

    sidecar.workdir = parent_path_wide(sidecar.exe);
    const ULONGLONG tick = GetTickCount64();
    sidecar.port = static_cast<uint16_t>(31000u + ((static_cast<uint32_t>(GetCurrentProcessId()) + static_cast<uint32_t>(tick)) % 20000u));
    sidecar.http_port = static_cast<uint16_t>(sidecar.port + 1u);
    wchar_t run_id_buf[128] = {};
    _snwprintf_s(run_id_buf, _TRUNCATE, L"integrity_hunter_%lu_%llu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(tick));
    sidecar.run_id = run_id_buf;
    sidecar.ready_event = L"Local\\AiDAIntegrityHunterReady_" + sidecar.run_id;
    sidecar.done_event = L"Local\\AiDAIntegrityHunterDone_" + sidecar.run_id;
    sidecar.log_path = make_integrity_sidecar_log_path();

    wchar_t args[512] = {};
    _snwprintf_s(args, _TRUNCATE,
        L" --no-external --skip-network --duration 180 --net-rate 2000 --port %u --http-port %u --disable-re-fixtures --disable-proto-re-fixtures --disable-protected-re-fixtures --disable-single-step-absorber",
        static_cast<unsigned>(sidecar.port),
        static_cast<unsigned>(sidecar.http_port));
    sidecar.command = quote_wide_arg(sidecar.exe) + args;

    std::vector<std::pair<std::wstring, std::wstring>> env_overrides = {
        { L"AIDA_TARGET_LOG_PATH", sidecar.log_path },
        { L"AIDA_INTEGRITY_HUNTER_SIDECAR", L"1" },
        { L"AIDA_INTEGRITY_HUNTER_SIDECAR_RUN_ID", sidecar.run_id },
        { L"AIDA_TEST_TARGET_READY_EVENT", sidecar.ready_event },
        { L"AIDA_TEST_TARGET_DONE_EVENT", sidecar.done_event }
    };
    std::vector<wchar_t> env_block = build_integrity_sidecar_environment(env_overrides);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> command_mutable(sidecar.command.begin(), sidecar.command.end());
    command_mutable.push_back(L'\0');
    SetLastError(0);
    BOOL ok = CreateProcessW(sidecar.exe.c_str(),
        command_mutable.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        sidecar.workdir.empty() ? nullptr : sidecar.workdir.c_str(),
        &si,
        &pi);
    const DWORD err = ok ? 0 : GetLastError();
    log_msg(hf, tag, "SIDE-FIXTURE-LAUNCH -- app=%s cmd=%s cwd=%s log=%s run_id=%s ready_event=%s done_event=%s port=%u http_port=%u isolated_event_env=1 fixed_event_names_not_used_for_readiness=1 ok=%d err=%lu text=%s",
        wide_to_utf8_lossy(sidecar.exe).c_str(),
        wide_to_utf8_lossy(sidecar.command).c_str(),
        wide_to_utf8_lossy(sidecar.workdir).c_str(),
        wide_to_utf8_lossy(sidecar.log_path).c_str(),
        wide_to_utf8_lossy(sidecar.run_id).c_str(),
        wide_to_utf8_lossy(sidecar.ready_event).c_str(),
        wide_to_utf8_lossy(sidecar.done_event).c_str(),
        static_cast<unsigned>(sidecar.port),
        static_cast<unsigned>(sidecar.http_port),
        ok ? 1 : 0,
        static_cast<unsigned long>(err),
        ok ? "success" : format_win32_error_text(err).c_str());
    if (!ok)
        return false;

    sidecar.process = pi.hProcess;
    sidecar.thread = pi.hThread;
    sidecar.pid = pi.dwProcessId;
    log_msg(hf, tag, "SIDE-FIXTURE-LAUNCHED -- pid=%lu thread=%lu",
        static_cast<unsigned long>(sidecar.pid),
        static_cast<unsigned long>(pi.dwThreadId));
    return true;
}

static bool select_integrity_hunter_sidecar_pid(HANDLE hf, const char* tag, uint32_t pid) {
    if (pid == 0)
        return false;
    const auto lower_before = driver_bridge::last_remote_call_execution_diag();
    log_msg(hf, tag, "SIDE-FIXTURE-SELECT-PRE -- pid=%u active_before=%u lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_generation_entry=%llu lower_generation_after=%llu lower_queue_depth_submit=%u lower_queue_depth_after_pop=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu",
        (unsigned)pid,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned long long)lower_before.call_id,
        lower_before.phase.c_str(),
        lower_before.completion_reason.c_str(),
        lower_before.completed ? 1 : 0,
        lower_before.lower_ok ? 1 : 0,
        static_cast<unsigned long>(lower_before.gle),
        (unsigned long long)lower_before.generation_at_entry,
        (unsigned long long)lower_before.generation_after,
        lower_before.queue_depth_at_submit,
        lower_before.queue_depth_after_pop,
        lower_before.inflight_after,
        (unsigned long long)lower_before.queue_wait_ms,
        (unsigned long long)lower_before.lower_elapsed_ms);
    bool known = false;
    for (uint32_t attached_pid : driver_bridge::attached_pids()) {
        if (attached_pid == pid) {
            known = true;
            break;
        }
    }
    if (!known && !driver_bridge::attach_additional(pid)) {
        log_msg(hf, tag, "FAIL -- integrity sidecar attach_additional failed pid=%u status=\"%s\" last_error=\"%s\"",
            (unsigned)pid,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return false;
    }
    if (!driver_bridge::set_active_pid(pid)) {
        const auto lower_after = driver_bridge::last_remote_call_execution_diag();
        log_msg(hf, tag, "FAIL -- integrity sidecar set_active_pid failed pid=%u active_now=%u lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_queue_depth_after_pop=%u lower_inflight_after=%u status=\"%s\" last_error=\"%s\"",
            (unsigned)pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)lower_after.call_id,
            lower_after.phase.c_str(),
            lower_after.completion_reason.c_str(),
            lower_after.completed ? 1 : 0,
            lower_after.lower_ok ? 1 : 0,
            static_cast<unsigned long>(lower_after.gle),
            lower_after.queue_depth_after_pop,
            lower_after.inflight_after,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return false;
    }
    const auto lower_after = driver_bridge::last_remote_call_execution_diag();
    log_msg(hf, tag, "SIDE-FIXTURE-SELECT-OK -- pid=%u active_now=%u lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_queue_depth_after_pop=%u lower_inflight_after=%u",
        (unsigned)pid,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned long long)lower_after.call_id,
        lower_after.phase.c_str(),
        lower_after.completion_reason.c_str(),
        lower_after.completed ? 1 : 0,
        lower_after.lower_ok ? 1 : 0,
        static_cast<unsigned long>(lower_after.gle),
        lower_after.queue_depth_after_pop,
        lower_after.inflight_after);
    return true;
}

static bool wait_integrity_hunter_sidecar_ready(HANDLE hf, const char* tag, const integrity_hunter_sidecar_t& sidecar, DWORD timeout_ms) {
    const DWORD started = GetTickCount();
    int attempts = 0;
    DWORD last_probe_wait_logged_ms = 0;
    uint64_t cached_ntdll = 0, cached_kernel32 = 0, cached_kernelbase = 0;
    for (;;) {
        ++attempts;
        DWORD exit_code = 0;
        if (integrity_sidecar_exited(sidecar, exit_code)) {
            log_msg(hf, tag, "FAIL -- integrity sidecar exited before attach ready pid=%lu exit=0x%08lX attempts=%d elapsed_ms=%lu",
                static_cast<unsigned long>(sidecar.pid),
                static_cast<unsigned long>(exit_code),
                attempts,
                static_cast<unsigned long>(GetTickCount() - started));
            return false;
        }

        const bool selected = select_integrity_hunter_sidecar_pid(hf, tag, sidecar.pid);
        const uint32_t active = driver_bridge::attached_pid();
        uint32_t bridge_code = 0;
        const bool bridge_alive = selected && active == sidecar.pid && driver_bridge::attached_process_alive(&bridge_code);
        uint64_t ntdll_base = cached_ntdll;
        uint64_t kernel32_base = cached_kernel32;
        uint64_t kernelbase_base = cached_kernelbase;
        if (selected) {
            if (ntdll_base == 0) {
                ntdll_base = remote_module_base_ci(sidecar.pid, "ntdll");
                if (ntdll_base != 0) cached_ntdll = ntdll_base;
            }
            if (kernel32_base == 0) {
                kernel32_base = remote_module_base_ci(sidecar.pid, "kernel32");
                if (kernel32_base != 0) cached_kernel32 = kernel32_base;
            }
            if (kernelbase_base == 0) {
                kernelbase_base = remote_module_base_ci(sidecar.pid, "kernelbase");
                if (kernelbase_base != 0) cached_kernelbase = kernelbase_base;
            }
        }
        const DWORD elapsed = GetTickCount() - started;
        if (selected && bridge_alive && ntdll_base != 0 && kernel32_base != 0) {
            integrity_sidecar_probe_t probe = probe_integrity_sidecar_remote_call(hf, tag, sidecar.pid, attempts);
            if (probe.ok) {
                log_msg(hf, tag, "SIDE-FIXTURE-READY -- pid=%lu attempts=%d active=%u ntdll=0x%016llX kernel32=0x%016llX kernelbase=0x%016llX probe_module=%s probe_fn=0x%016llX probe_result=0x%016llX remote_call_id=%llu remote_execution_completed=%d lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_queue_depth_submit=%u lower_inflight_after=%u bridge_code=0x%08X elapsed_ms=%lu probe_elapsed_ms=%lld",
                    static_cast<unsigned long>(sidecar.pid),
                    attempts,
                    active,
                    static_cast<unsigned long long>(ntdll_base),
                    static_cast<unsigned long long>(kernel32_base),
                    static_cast<unsigned long long>(kernelbase_base),
                    probe.module ? probe.module : "",
                    static_cast<unsigned long long>(probe.resolved.address),
                    static_cast<unsigned long long>(probe.result),
                    (unsigned long long)probe.remote_diag.call_id,
                    probe.remote_diag.lower_completed && probe.remote_diag.lower_ok ? 1 : 0,
                    probe.lower_diag.phase.c_str(),
                    probe.lower_diag.completion_reason.c_str(),
                    probe.lower_diag.completed ? 1 : 0,
                    probe.lower_diag.lower_ok ? 1 : 0,
                    static_cast<unsigned long>(probe.lower_diag.gle),
                    probe.lower_diag.queue_depth_at_submit,
                    probe.lower_diag.inflight_after,
                    bridge_code,
                    static_cast<unsigned long>(elapsed),
                    probe.elapsed_ms);
                return true;
            }
            const bool probe_wait_should_log = (attempts == 1) ||
                (elapsed >= last_probe_wait_logged_ms && (elapsed - last_probe_wait_logged_ms) >= 500);
            if (probe_wait_should_log) {
                last_probe_wait_logged_ms = elapsed;
            log_msg(hf, tag, "SIDE-FIXTURE-PROBE-WAIT -- pid=%lu attempts=%d active=%u ntdll=0x%016llX kernel32=0x%016llX kernelbase=0x%016llX module=%s fn=0x%016llX method=%s result=0x%016llX expected=0x%016llX ok=0 gle=%lu text=%s remote_call_id=%llu remote_ok=%d remote_execution_completed=%d remote_gle=%lu lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_generation_entry=%llu lower_generation_after=%llu lower_queue_depth_submit=%u lower_queue_depth_start=%u lower_queue_depth_after_pop=%u lower_inflight_submit=%u lower_inflight_start=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu elapsed_ms=%lu probe_elapsed_ms=%lld status=\"%s\" last_error=\"%s\"",
                static_cast<unsigned long>(sidecar.pid),
                attempts,
                active,
                static_cast<unsigned long long>(ntdll_base),
                static_cast<unsigned long long>(kernel32_base),
                static_cast<unsigned long long>(kernelbase_base),
                probe.module ? probe.module : "",
                static_cast<unsigned long long>(probe.resolved.address),
                probe.resolved.method,
                static_cast<unsigned long long>(probe.result),
                static_cast<unsigned long long>(sidecar.pid),
                static_cast<unsigned long>(probe.gle),
                format_win32_error_text(probe.gle).c_str(),
                (unsigned long long)probe.remote_diag.call_id,
                probe.remote_diag.ok ? 1 : 0,
                probe.remote_diag.lower_completed && probe.remote_diag.lower_ok ? 1 : 0,
                static_cast<unsigned long>(probe.remote_diag.gle),
                (unsigned long long)probe.lower_diag.call_id,
                probe.lower_diag.phase.c_str(),
                probe.lower_diag.completion_reason.c_str(),
                probe.lower_diag.completed ? 1 : 0,
                probe.lower_diag.lower_ok ? 1 : 0,
                static_cast<unsigned long>(probe.lower_diag.gle),
                (unsigned long long)probe.lower_diag.generation_at_entry,
                (unsigned long long)probe.lower_diag.generation_after,
                probe.lower_diag.queue_depth_at_submit,
                probe.lower_diag.queue_depth_at_start,
                probe.lower_diag.queue_depth_after_pop,
                probe.lower_diag.inflight_at_submit,
                probe.lower_diag.inflight_at_start,
                probe.lower_diag.inflight_after,
                (unsigned long long)probe.lower_diag.queue_wait_ms,
                (unsigned long long)probe.lower_diag.lower_elapsed_ms,
                static_cast<unsigned long>(elapsed),
                probe.elapsed_ms,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            }
        }
        if (attempts == 1 || (elapsed % 500) < 100) {
            log_msg(hf, tag, "SIDE-FIXTURE-WAIT -- pid=%lu attempt=%d selected=%d active=%u bridge_alive=%d bridge_code=0x%08X ntdll=0x%016llX kernel32=0x%016llX kernelbase=0x%016llX elapsed_ms=%lu",
                static_cast<unsigned long>(sidecar.pid),
                attempts,
                selected ? 1 : 0,
                active,
                bridge_alive ? 1 : 0,
                bridge_code,
                static_cast<unsigned long long>(ntdll_base),
                static_cast<unsigned long long>(kernel32_base),
                static_cast<unsigned long long>(kernelbase_base),
                static_cast<unsigned long>(elapsed));
        }
        if (elapsed >= timeout_ms) {
            log_msg(hf, tag, "FAIL -- integrity sidecar attach readiness timeout pid=%lu attempts=%d active=%u ntdll=0x%016llX kernel32=0x%016llX kernelbase=0x%016llX required_probe=GetCurrentProcessId expected_pid=%lu status=\"%s\" last_error=\"%s\"",
                static_cast<unsigned long>(sidecar.pid),
                attempts,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(ntdll_base),
                static_cast<unsigned long long>(kernel32_base),
                static_cast<unsigned long long>(kernelbase_base),
                static_cast<unsigned long>(sidecar.pid),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            return false;
        }
        const bool latch_set = driver_bridge::lower_remote_call_last_abandoned();
        Sleep(latch_set ? 150 : 50);
    }
}

static bool restore_integrity_primary_pid(HANDLE hf, const char* tag, uint32_t primary_pid, uint32_t sidecar_pid = 0, const char* phase = "restore") {
    const uint32_t active_before = driver_bridge::attached_pid();
    const DWORD started = GetTickCount();
    if (primary_pid == 0) {
        log_msg(hf, tag, "SIDE-FIXTURE-RESTORE -- phase=%s primary_pid=0 sidecar_pid=%u active_before=%u method=no_primary restored=1 active_now=%u status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
            phase ? phase : "restore",
            (unsigned)sidecar_pid,
            active_before,
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            static_cast<unsigned long>(GetTickCount() - started));
        return true;
    }
    bool known = false;
    for (uint32_t attached_pid : driver_bridge::attached_pids()) {
        if (attached_pid == primary_pid) {
            known = true;
            break;
        }
    }
    uint32_t primary_code = 0;
    const bool primary_alive = analysis_process_alive_by_pid(primary_pid, &primary_code);
    uint32_t sidecar_code = 0;
    const bool sidecar_alive = sidecar_pid != 0 && analysis_process_alive_by_pid(sidecar_pid, &sidecar_code);
    uint32_t bridge_code = 0;
    auto primary_bridge_ready = [&]() -> bool {
        bridge_code = 0;
        if (driver_bridge::attached_pid() != primary_pid)
            return false;
        if (!driver_bridge::can_read_memory())
            return false;
        return driver_bridge::attached_process_alive(&bridge_code);
    };
    bool restored = primary_bridge_ready();
    const char* method = restored ? "already_active" : (active_before == primary_pid ? "already_active_unready" : "none");
    if (!restored && known) {
        method = "set_active";
        restored = driver_bridge::set_active_pid(primary_pid);
        if (restored && !primary_bridge_ready())
            restored = false;
    }
    if (!restored && primary_alive && driver_bridge::attached_pid() == primary_pid) {
        method = "reattach_active_primary";
        restored = driver_bridge::attach(primary_pid);
        if (restored && !primary_bridge_ready())
            restored = false;
    }
    if (!restored && primary_alive) {
        method = "attach_additional";
        const bool attached = driver_bridge::attach_additional(primary_pid);
        if (attached) {
            method = "attach_additional_set_active";
            restored = driver_bridge::set_active_pid(primary_pid);
            if (restored && !primary_bridge_ready())
                restored = false;
        }
    }
    if (!restored && primary_alive) {
        method = "attach";
        restored = driver_bridge::attach(primary_pid);
        if (restored && !primary_bridge_ready())
            restored = false;
    }
    const uint32_t active_now = driver_bridge::attached_pid();
    const bool kernel_ready = driver_bridge::can_read_memory();
    const bool bridge_alive = active_now == primary_pid && kernel_ready && driver_bridge::attached_process_alive(&bridge_code);
    log_msg(hf, tag, "SIDE-FIXTURE-RESTORE -- phase=%s sidecar_pid=%u primary_pid=%u active_before=%u known=%d method=%s restored=%d active_now=%u primary_alive=%d primary_code=0x%08X sidecar_alive=%d sidecar_code=0x%08X kernel_ready=%d bridge_alive=%d bridge_code=0x%08X status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
        phase ? phase : "restore",
        (unsigned)sidecar_pid,
        (unsigned)primary_pid,
        active_before,
        known ? 1 : 0,
        method,
        restored ? 1 : 0,
        active_now,
        primary_alive ? 1 : 0,
        primary_code,
        sidecar_alive ? 1 : 0,
        sidecar_code,
        kernel_ready ? 1 : 0,
        bridge_alive ? 1 : 0,
        bridge_code,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str(),
        static_cast<unsigned long>(GetTickCount() - started));
    return restored && bridge_alive;
}

static void close_integrity_hunter_sidecar(HANDLE hf, const char* tag, integrity_hunter_sidecar_t& sidecar, bool force) {
    DWORD exit_code = 0;
    const bool exited = integrity_sidecar_exited(sidecar, exit_code);
    log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- begin pid=%lu force=%d exited=%d exit=0x%08lX active_pid=%u",
        static_cast<unsigned long>(sidecar.pid),
        force ? 1 : 0,
        exited ? 1 : 0,
        static_cast<unsigned long>(exit_code),
        driver_bridge::attached_pid());
    if (sidecar.process && !exited && force) {
        SetLastError(0);
        BOOL term_ok = TerminateProcess(sidecar.process, 0xA1DA);
        const DWORD term_err = term_ok ? 0 : GetLastError();
        DWORD wait = WaitForSingleObject(sidecar.process, 1500);
        const DWORD wait_err = wait == WAIT_FAILED ? GetLastError() : 0;
        DWORD exit_after = 0;
        BOOL exit_after_ok = GetExitCodeProcess(sidecar.process, &exit_after);
        const DWORD exit_after_err = exit_after_ok ? 0 : GetLastError();
        log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- terminate pid=%lu ok=%d err=%lu text=%s wait=0x%08lX wait_err=%lu exit_ok=%d exit_err=%lu exit=0x%08lX",
            static_cast<unsigned long>(sidecar.pid),
            term_ok ? 1 : 0,
            static_cast<unsigned long>(term_err),
            term_ok ? "success" : format_win32_error_text(term_err).c_str(),
            static_cast<unsigned long>(wait),
            static_cast<unsigned long>(wait_err),
            exit_after_ok ? 1 : 0,
            static_cast<unsigned long>(exit_after_err),
            exit_after_ok ? static_cast<unsigned long>(exit_after) : 0UL);
    }
    close_handle_if_open(sidecar.thread);
    close_handle_if_open(sidecar.process);
    if (sidecar.pid != 0) {
        const bool detached = driver_bridge::detach_one(sidecar.pid);
        log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- detached pid=%lu ok=%d active_now=%u",
            static_cast<unsigned long>(sidecar.pid),
            detached ? 1 : 0,
            driver_bridge::attached_pid());
    }
    sidecar.pid = 0;
}

static bool fence_integrity_hunter_cleanup_before_sidecar_switch(HANDLE hf, const char* tag, uint32_t primary_pid, DWORD timeout_ms) {
    const DWORD started = GetTickCount();
    integrity_hunter::stop_hunt();
    const auto idle = integrity_hunter::wait_until_idle_result(timeout_ms);
    const auto lower = driver_bridge::last_remote_call_execution_diag();
    const bool hunting = integrity_hunter::g_state.hunting.load(std::memory_order_acquire);
    const bool worker = integrity_hunter::g_state.worker_active.load(std::memory_order_acquire);
    const bool ok = idle.idle && !hunting && !worker;
    log_msg(hf, tag, "SIDE-FIXTURE-CLEANUP-FENCE -- primary_pid=%u active_pid=%u ok=%d idle=%d hunting=%d worker=%d cleanup_elapsed_ms=%lld generation=%llu install_generation=%llu session=%u lower_call_id=%llu lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_generation_entry=%llu lower_generation_after=%llu lower_queue_depth_submit=%u lower_queue_depth_after_pop=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu elapsed_ms=%lu status=\"%s\" last_error=\"%s\"",
        (unsigned)primary_pid,
        (unsigned)driver_bridge::attached_pid(),
        ok ? 1 : 0,
        idle.idle ? 1 : 0,
        hunting ? 1 : 0,
        worker ? 1 : 0,
        (long long)idle.elapsed_ms,
        (unsigned long long)idle.generation,
        (unsigned long long)idle.install_generation,
        idle.session_id,
        (unsigned long long)lower.call_id,
        lower.phase.c_str(),
        lower.completion_reason.c_str(),
        lower.completed ? 1 : 0,
        lower.lower_ok ? 1 : 0,
        static_cast<unsigned long>(lower.gle),
        (unsigned long long)lower.generation_at_entry,
        (unsigned long long)lower.generation_after,
        lower.queue_depth_at_submit,
        lower.queue_depth_after_pop,
        lower.inflight_after,
        (unsigned long long)lower.queue_wait_ms,
        (unsigned long long)lower.lower_elapsed_ms,
        static_cast<unsigned long>(GetTickCount() - started),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    if (!ok) {
        log_msg(hf, tag, "FAIL -- integrity sidecar cleanup fence did not drain before PID switch: primary_pid=%u active_pid=%u idle=%d hunting=%d worker=%d cleanup_elapsed_ms=%lld lower_reason=%s lower_completed=%d lower_ok=%d lower_inflight_after=%u status=\"%s\" last_error=\"%s\"",
            (unsigned)primary_pid,
            (unsigned)driver_bridge::attached_pid(),
            idle.idle ? 1 : 0,
            hunting ? 1 : 0,
            worker ? 1 : 0,
            (long long)idle.elapsed_ms,
            lower.completion_reason.c_str(),
            lower.completed ? 1 : 0,
            lower.lower_ok ? 1 : 0,
            lower.inflight_after,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
    }
    return ok;
}

struct integrity_hunter_sidecar_scope_t {
    HANDLE hf = nullptr;
    const char* tag = nullptr;
    uint32_t primary_pid = 0;
    integrity_hunter_sidecar_t sidecar;
    bool active = false;

    integrity_hunter_sidecar_scope_t(HANDLE h, const char* t, uint32_t p) : hf(h), tag(t), primary_pid(p) {}

    ~integrity_hunter_sidecar_scope_t() {
        const uint32_t sidecar_pid_snapshot = sidecar.pid;
        if (active)
            close_integrity_hunter_sidecar(hf, tag, sidecar, true);
        restore_integrity_primary_pid(hf, tag, primary_pid, sidecar_pid_snapshot, "scope_exit");
    }

    bool start(DWORD timeout_ms) {
        if (!fence_integrity_hunter_cleanup_before_sidecar_switch(hf, tag, primary_pid, 3000))
            return false;
        if (!launch_integrity_hunter_sidecar(hf, tag, sidecar))
            return false;
        active = true;
        return wait_integrity_hunter_sidecar_ready(hf, tag, sidecar, timeout_ms);
    }
};

struct integrity_hunter_fixture_t {
    uint32_t pid = 0;
    uint64_t address = 0;
    size_t size = 0;

    integrity_hunter_fixture_t() = default;
    integrity_hunter_fixture_t(const integrity_hunter_fixture_t&) = delete;
    integrity_hunter_fixture_t& operator=(const integrity_hunter_fixture_t&) = delete;
    integrity_hunter_fixture_t(integrity_hunter_fixture_t&& other) noexcept {
        pid = other.pid;
        address = other.address;
        size = other.size;
        other.pid = 0;
        other.address = 0;
        other.size = 0;
    }
    integrity_hunter_fixture_t& operator=(integrity_hunter_fixture_t&& other) noexcept {
        if (this != &other) {
            reset();
            pid = other.pid;
            address = other.address;
            size = other.size;
            other.pid = 0;
            other.address = 0;
            other.size = 0;
        }
        return *this;
    }
    ~integrity_hunter_fixture_t() {
        reset();
    }
    void reset() {
        if (address != 0) {
            if (pid != 0)
                driver_bridge::free_memory_for(pid, address);
            else
                driver_bridge::free_memory(address);
            pid = 0;
            address = 0;
            size = 0;
        }
    }
};

static ntdll_export_resolution_t resolve_attached_ntdll_export(HANDLE hf, const char* tag, uint32_t pid, const char* name) {
    ntdll_export_resolution_t out;
    if (pid == 0 || !name || !name[0])
        return out;

    auto local_t0 = std::chrono::steady_clock::now();
    HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC local_fn = local_ntdll ? GetProcAddress(local_ntdll, name) : nullptr;
    HMODULE owner = nullptr;
    const bool owner_ok = local_fn &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(local_fn), &owner) &&
        owner == local_ntdll;
    if (local_ntdll && local_fn && owner_ok) {
        const uintptr_t local_base = reinterpret_cast<uintptr_t>(local_ntdll);
        const uintptr_t local_addr = reinterpret_cast<uintptr_t>(local_fn);
        if (local_addr > local_base) {
            out.local_rva = static_cast<uint64_t>(local_addr - local_base);
            out.local_export_ok = true;
        }
    }
    out.local_us = elapsed_us_since(local_t0);

    auto enum_t0 = std::chrono::steady_clock::now();
    const std::vector<driver_bridge::module_info_t> modules = driver_bridge::enumerate_modules_for(pid);
    out.enum_us = elapsed_us_since(enum_t0);
    out.module_count = modules.size();

    for (const auto& mod : modules) {
        if (mod.base == 0 || !module_is_ntdll(mod))
            continue;
        out.ntdll_seen = true;
        if (out.local_export_ok && out.local_rva != 0 && (mod.size == 0 || out.local_rva < mod.size)) {
            out.address = mod.base + out.local_rva;
            out.module_name = mod.name.empty() ? mod.path : mod.name;
            out.method = "local_rva";
            diag::log_tagged_fmt("test_analysis_detail",
                "%s resolve_ntdll_export name=%s pid=%u method=%s module=%s base=0x%llX size=0x%llX rva=0x%llX va=0x%llX local_us=%lld enum_us=%lld modules=%zu",
                tag ? tag : "analysis",
                name,
                (unsigned)pid,
                out.method,
                out.module_name.empty() ? "<none>" : out.module_name.c_str(),
                (unsigned long long)mod.base,
                (unsigned long long)mod.size,
                (unsigned long long)out.local_rva,
                (unsigned long long)out.address,
                out.local_us,
                out.enum_us,
                out.module_count);
            return out;
        }
    }

    for (const auto& mod : modules) {
        if (mod.base == 0 || !module_is_ntdll(mod))
            continue;
        auto slow_t0 = std::chrono::steady_clock::now();
        uint64_t fn = driver_bridge::resolve_export_for(pid, mod.base, name);
        const long long slow_call_us = elapsed_us_since(slow_t0);
        out.slow_us += slow_call_us;
        ++out.slow_attempts;
        diag::log_tagged_fmt("test_analysis_detail",
            "%s resolve_ntdll_export_fallback name=%s pid=%u module=%s base=0x%llX size=0x%llX result=0x%llX slow_call_us=%lld slow_total_us=%lld attempts=%u local_export_ok=%d local_rva=0x%llX enum_us=%lld status='%s' last_error='%s'",
            tag ? tag : "analysis",
            name,
            (unsigned)pid,
            (mod.name.empty() ? mod.path : mod.name).c_str(),
            (unsigned long long)mod.base,
            (unsigned long long)mod.size,
            (unsigned long long)fn,
            slow_call_us,
            out.slow_us,
            out.slow_attempts,
            out.local_export_ok ? 1 : 0,
            (unsigned long long)out.local_rva,
            out.enum_us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (fn != 0) {
            out.address = fn;
            out.module_name = mod.name.empty() ? mod.path : mod.name;
            out.method = "driver_resolver";
            return out;
        }
    }

    log_msg(hf, tag ? tag : "analysis",
        "WARN -- unresolved ntdll export name=%s pid=%u local_export_ok=%d local_rva=0x%016llX ntdll_seen=%d modules=%zu local_us=%lld enum_us=%lld slow_attempts=%u slow_us=%lld status=\"%s\" last_error=\"%s\"",
        name,
        (unsigned)pid,
        out.local_export_ok ? 1 : 0,
        (unsigned long long)out.local_rva,
        out.ntdll_seen ? 1 : 0,
        out.module_count,
        out.local_us,
        out.enum_us,
        out.slow_attempts,
        out.slow_us,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    return out;
}

static integrity_hunter_fixture_t make_integrity_hunter_fixture(HANDLE hf, const char* tag) {
    integrity_hunter_fixture_t fx;
    fx.pid = driver_bridge::attached_pid();
    fx.size = 4096;
    if (fx.pid == 0) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: cannot allocate integrity fixture without attached target PID (target_pid=0 driver_attached=%d status=\"%s\" last_error=\"%s\")",
            driver_attached_flag(fx.pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return fx;
    }
    fx.address = driver_bridge::allocate_memory_for(fx.pid, fx.size);
    if (fx.address == 0) {
        log_msg(hf, tag, "FAIL -- allocate_memory_for returned 0 for integrity hunter fixture (target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\")",
            (unsigned)fx.pid,
            driver_attached_flag(fx.pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return fx;
    }

    std::vector<uint8_t> bytes(fx.size);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((i * 31u + 0x53u) & 0xFFu);

    if (!driver_bridge::write_memory_for(fx.pid, fx.address, bytes)) {
        log_msg(hf, tag, "FAIL -- write_memory_for failed for integrity hunter fixture target_pid=%u addr=0x%016llX size=%zu status=\"%s\" last_error=\"%s\"",
            (unsigned)fx.pid,
            (unsigned long long)fx.address,
            fx.size,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        fx.reset();
        return fx;
    }

    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory_for(fx.pid, fx.address, fx.size, PAGE_READWRITE, &old_protect)) {
        log_msg(hf, tag, "FAIL -- protect_memory_for failed for integrity hunter fixture target_pid=%u addr=0x%016llX size=%zu status=\"%s\" last_error=\"%s\"",
            (unsigned)fx.pid,
            (unsigned long long)fx.address,
            fx.size,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        fx.reset();
        return fx;
    }

    driver_bridge::memory_region_t region{};
    const bool query_ok = driver_bridge::query_memory_for(fx.pid, fx.address, region);
    log_msg(hf, tag, "fixture target_pid=%u driver_attached=%d addr=0x%016llX size=%zu old_protect=0x%08X query_ok=%d base=0x%016llX region_size=0x%016llX state=0x%08X protect=0x%08X type=0x%08X",
        (unsigned)fx.pid,
        driver_attached_flag(fx.pid),
        (unsigned long long)fx.address,
        fx.size,
        old_protect,
        query_ok ? 1 : 0,
        (unsigned long long)region.base,
        (unsigned long long)region.size,
        (unsigned)region.state,
        (unsigned)region.protect,
        (unsigned)region.type);
    return fx;
}

struct symbolic_fixture_t {
    uint64_t address = 0;
    size_t size = 0;

    symbolic_fixture_t() = default;
    symbolic_fixture_t(const symbolic_fixture_t&) = delete;
    symbolic_fixture_t& operator=(const symbolic_fixture_t&) = delete;
    symbolic_fixture_t(symbolic_fixture_t&& other) noexcept {
        address = other.address;
        size = other.size;
        other.address = 0;
        other.size = 0;
    }
    symbolic_fixture_t& operator=(symbolic_fixture_t&& other) noexcept {
        if (this != &other) {
            reset();
            address = other.address;
            size = other.size;
            other.address = 0;
            other.size = 0;
        }
        return *this;
    }
    ~symbolic_fixture_t() {
        reset();
    }
    void reset() {
        if (address != 0) {
            driver_bridge::free_memory(address);
            address = 0;
            size = 0;
        }
    }
};

static symbolic_fixture_t make_symbolic_fixture(HANDLE hf, const char* tag, const std::vector<uint8_t>& code) {
    symbolic_fixture_t fx;
    fx.size = code.empty() ? 1 : ((code.size() + 0xFFFu) & ~0xFFFu);
    fx.address = driver_bridge::allocate_memory(fx.size);
    if (fx.address == 0) {
        log_msg(hf, tag, "FAIL -- allocate_memory returned 0 for symbolic fixture");
        fx.size = 0;
        return fx;
    }
    std::vector<uint8_t> page(fx.size, 0x90);
    if (!code.empty())
        std::memcpy(page.data(), code.data(), code.size());
    if (!driver_bridge::write_memory(fx.address, page)) {
        log_msg(hf, tag, "FAIL -- write_memory failed for symbolic fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), page.size());
        fx.reset();
        return fx;
    }
    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory(fx.address, fx.size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        log_msg(hf, tag, "FAIL -- protect_memory failed for symbolic fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), fx.size);
        fx.reset();
        return fx;
    }
    log_msg(hf, tag, "fixture addr=0x%016llX size=%zu bytes=%zu",
        static_cast<unsigned long long>(fx.address), fx.size, code.size());
    return fx;
}

static std::vector<uint8_t> symbolic_arithmetic_fixture() {
    return {
        0x48, 0x89, 0xC8,
        0x48, 0x83, 0xC0, 0x05,
        0x48, 0x31, 0xD0,
        0x48, 0x85, 0xC0,
        0x75, 0x03,
        0x48, 0xFF, 0xC0,
        0xC3
    };
}

static std::vector<uint8_t> symbolic_r10_fixture() {
    return {
        0x4C, 0x8B, 0xD1,
        0x49, 0x83, 0xC2, 0x01,
        0x4C, 0x89, 0xD0,
        0xC3
    };
}

static std::vector<uint8_t> symbolic_branch_fixture() {
    return {
        0x48, 0x85, 0xC9,
        0x75, 0x03,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
}

static std::string source_recon_output_dir() {
    char tmp[MAX_PATH + 1] = {};
    DWORD len = GetTempPathA(MAX_PATH, tmp);
    std::string base = (len > 0 && len < MAX_PATH) ? std::string(tmp, len) : std::string(".\\");
    if (!base.empty()) {
        char last = base.back();
        if (last != '\\' && last != '/')
            base.push_back('\\');
    }
    char suffix[160];
    _snprintf_s(suffix, sizeof(suffix), _TRUNCATE, "AiDA_TestLab\\source_recon_%lu_%llu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(GetTickCount64()));
    return base + suffix;
}

static bool file_exists_nonempty(const std::string& path, unsigned long long* size_out = nullptr) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER sz{};
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart > 0;
    if (size_out)
        *size_out = GetFileSizeEx(h, &sz) ? static_cast<unsigned long long>(sz.QuadPart) : 0ULL;
    CloseHandle(h);
    return ok;
}

static bool read_text_file_limited(const std::string& path, std::string& out, size_t limit) {
    out.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    std::vector<char> buf(limit);
    ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    std::streamsize got = ifs.gcount();
    if (got <= 0)
        return false;
    out.assign(buf.data(), static_cast<size_t>(got));
    return true;
}

static aida::binary_map::map_t make_binary_map_fixture() {
    aida::binary_map::map_t map;
    map.module_name = "fixture.exe";
    map.module_path = "fixture.exe";
    map.architecture = "x64";
    map.format = "PE";
    map.image_base = 0x140000000;
    map.image_size = 0x3000;

    aida::binary_map::map_section_t text;
    text.name = ".text";
    text.va = map.image_base + 0x1000;
    text.size = 0x600;
    text.executable = true;
    text.readable = true;
    text.entropy = 0.42f;
    text.sampled_bytes = 0x600;
    map.sections.push_back(std::move(text));

    aida::binary_map::map_function_t fn;
    fn.va = map.image_base + 0x1010;
    fn.name = "fixture_entry";
    fn.xref_count = 2;
    fn.callee_count = 1;
    fn.top_callees.push_back("fixture_leaf");
    fn.section_name = ".text";
    fn.score = 80;
    map.functions.push_back(std::move(fn));

    aida::binary_map::map_global_t global;
    global.va = map.image_base + 0x2200;
    global.name = "fixture_counter";
    global.xref_count = 1;
    global.writable = true;
    global.section_name = ".data";
    map.globals.push_back(std::move(global));

    map.imports.push_back("kernel32!CloseHandle");
    map.exports.push_back("FixtureExport");
    return map;
}

static void test_symbolic_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exec", "START -- symbolic engine execute on small range");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_exec", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exec", "PASS -- success=%d traced=%u tainted=%u junk=%u opaque=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count,
        result.junk_count, result.opaque_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slice", "START -- symbolic engine slice to register");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_slice", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(fx.address, fx.address + code.size(), 16, "rax");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slice", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_taint", "START -- symbolic engine taint trace");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_taint", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_taint", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_opaque_predicate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_opq", "START -- symbolic engine check opaque predicate");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_branch_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_opq", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    bool is_opaque = symbolic_engine::is_opaque_predicate(fx.address + 3, 8);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_opq", "PASS -- is_opaque_predicate(fixture_branch)=%d (elapsed %lld ms)",
        is_opaque, (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_strip_junk(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_jnk", "START -- deobfuscation engine strip junk code");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_jnk", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::strip_junk_code(fx.address, fx.address + code.size(), { "rax" }, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_jnk", "FAIL -- fixture-limited deobfuscation success=0 error=\"%s\" original=%u clean=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty()) {
        log_msg(hf, "deob_jnk", "FAIL -- fixture-limited deobfuscation returned empty clean result success=%d original=%u clean=%u (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_jnk", "PASS -- success=%d original=%u clean=%u removed=%u junk_ratio=%.2f (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.removed_junk, static_cast<double>(result.junk_ratio), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_resolve_constants(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_cst", "START -- deobfuscation engine resolve constants");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_cst", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto constants = deobfuscation_engine::resolve_constants(fx.address, fx.address + code.size(), 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (constants.empty()) {
        log_msg(hf, "deob_cst", "FAIL -- resolve_constants returned 0 constants (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_cst", "PASS -- resolved %zu constants (elapsed %lld ms)", constants.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_create_apply_revert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_car", "START -- code patcher create/apply/revert");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t scratch = driver_bridge::allocate_memory(16);
    if (scratch == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "patch_car", "FAIL -- allocate_memory returned 0 for patch fixture (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }

    std::vector<uint8_t> original = { 0x41, 0x42, 0x43 };
    std::vector<uint8_t> patched = { 0x90, 0x90, 0x90 };
    bool seed_ok = driver_bridge::write_memory(scratch, original);
    int idx = seed_ok ? code_patcher::create_patch(scratch, patched, "test patch fixture") : -1;
    bool apply_ok = idx >= 0 && code_patcher::apply_patch(idx);
    std::vector<uint8_t> after_apply;
    bool read_apply_ok = driver_bridge::read_memory(scratch, patched.size(), after_apply);
    bool revert_ok = idx >= 0 && code_patcher::revert_patch(idx);
    std::vector<uint8_t> after_revert;
    bool read_revert_ok = driver_bridge::read_memory(scratch, original.size(), after_revert);
    size_t count = code_patcher::count();
    size_t active = code_patcher::active_count();

    if (idx >= 0)
        code_patcher::remove_patch(idx);
    bool freed = driver_bridge::free_memory(scratch);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (seed_ok && idx >= 0 && apply_ok && read_apply_ok && after_apply == patched &&
        revert_ok && read_revert_ok && after_revert == original && freed) {
        log_msg(hf, "patch_car", "PASS -- patch idx=%d applied/reverted on scratch=0x%016llX count=%zu active=%zu (elapsed %lld ms)",
            idx, (unsigned long long)scratch, count, active, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_car", "FAIL -- seed=%d idx=%d apply=%d read_apply=%d revert=%d read_revert=%d freed=%d active=%zu (elapsed %lld ms)",
            seed_ok ? 1 : 0, idx, apply_ok ? 1 : 0, read_apply_ok ? 1 : 0,
            revert_ok ? 1 : 0, read_revert_ok ? 1 : 0, freed ? 1 : 0, active, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_nop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_nop", "START -- code patcher NOP region");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = code_patcher::nop_region(0xBAADF00D, 4, "test nop region");

    size_t count = code_patcher::count();
    if (count > 0) {
        code_patcher::remove_patch(static_cast<int>(count - 1));
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_nop", "PASS -- nop_region returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_find_caves(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cav", "START -- code patcher find code caves");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        log_msg(hf, "patch_cav", "FAIL -- ntdll not loaded");
        failed.fetch_add(1); return;
    }

    uint64_t base = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
    auto caves = code_patcher::find_code_caves(base, 0x40000, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cav", "PASS -- found %zu code caves >= 16 bytes (elapsed %lld ms)",
        caves.size(), (long long)ms);
    for (size_t i = 0; i < caves.size() && i < 5; ++i) {
        log_msg(hf, "patch_cav", "  cave[%zu]: addr=0x%llX size=%llu module=%s",
            i, (unsigned long long)caves[i].address,
            (unsigned long long)caves[i].size, caves[i].module_name.c_str());
    }
    passed.fetch_add(1);
}

static void test_integrity_hunter_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_st", "START -- integrity hunter state contract check");
    auto t0 = std::chrono::steady_clock::now();

    bool hunting = integrity_hunter::g_state.hunting.load();
    bool cancel = integrity_hunter::g_state.cancel.load();
    bool worker = integrity_hunter::g_state.worker_active.load();
    bool install_complete = integrity_hunter::g_state.install_complete.load();
    bool install_success = integrity_hunter::g_state.install_success.load();
    uint64_t reads = integrity_hunter::g_state.total_reads.load();
    uint64_t generation = integrity_hunter::g_state.generation.load();
    uint32_t session = integrity_hunter::g_state.pg_session_id.load();
    size_t node_count = 0;
    size_t event_count = 0;
    int first_node_reads = 0;
    std::string status;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        node_count = integrity_hunter::g_state.nodes.size();
        event_count = integrity_hunter::g_state.event_log.size();
        if (!integrity_hunter::g_state.nodes.empty())
            first_node_reads = integrity_hunter::g_state.nodes.front().read_count;
        status = integrity_hunter::g_state.status_text;
    }
    bool lifecycle_ok;
    if (!hunting) {
        lifecycle_ok = !worker && (install_complete || status.empty());
    } else {
        lifecycle_ok = worker || install_complete || !status.empty();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "integ_st", "STATE target_pid=%u tid=%lu hunting=%d cancel=%d worker=%d install_complete=%d install_success=%d session=%u generation=%llu nodes=%zu events=%zu total_reads=%llu first_node_reads=%d status_len=%zu status=\"%s\" bridge_status=\"%s\" last_error=\"%s\" elapsed_ms=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        hunting ? 1 : 0,
        cancel ? 1 : 0,
        worker ? 1 : 0,
        install_complete ? 1 : 0,
        install_success ? 1 : 0,
        session,
        (unsigned long long)generation,
        node_count,
        event_count,
        (unsigned long long)reads,
        first_node_reads,
        status.size(),
        status.c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str(),
        (long long)ms);
    if (lifecycle_ok) {
        log_msg(hf, "integ_st", "CONTRACT-PASS -- integrity hunter idle/state contract coherent; live guard coverage comes from fixture tests elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "integ_st", "FAIL -- integrity hunter state incoherent hunting=%d worker=%d install_complete=%d status_len=%zu elapsed_ms=%lld",
            hunting ? 1 : 0, worker ? 1 : 0, install_complete ? 1 : 0, status.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_generate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap", "START -- binary map render fixture coverage");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 2;
    opts.max_globals = 1;
    opts.max_chars = 1024;

    aida::binary_map::map_t map = make_binary_map_fixture();
    std::string text = aida::binary_map::render_text(map, opts);
    bool ok = !text.empty() &&
        text.find("fixture.exe") != std::string::npos &&
        text.find("fixture_entry") != std::string::npos &&
        text.find("fixture_counter") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap", "RESULT coverage=fixture module=%s path=%s base=0x%llX end=0x%llX image_size=0x%llX sections=%zu functions=%zu globals=%zu imports=%zu exports=%zu text_chars=%zu last_error=\"%s\" elapsed_ms=%lld",
        map.module_name.c_str(),
        map.module_path.c_str(),
        (unsigned long long)map.image_base,
        (unsigned long long)(map.image_base + map.image_size),
        (unsigned long long)map.image_size,
        map.sections.size(),
        map.functions.size(),
        map.globals.size(),
        map.imports.size(),
        map.exports.size(),
        text.size(),
        aida::binary_map::last_error().c_str(),
        (long long)ms);
    if (!ok) {
        log_msg(hf, "binmap", "FAIL -- fixture map render missing required evidence chars=%zu module_hit=%d function_hit=%d global_hit=%d (elapsed %lld ms)",
            text.size(),
            text.find("fixture.exe") != std::string::npos ? 1 : 0,
            text.find("fixture_entry") != std::string::npos ? 1 : 0,
            text.find("fixture_counter") != std::string::npos ? 1 : 0,
            (long long)ms);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "binmap", "FIXTURE-PASS -- binary map render proved deterministic fixture module=%s arch=%s sections=%zu functions=%zu globals=%zu (elapsed %lld ms)",
        map.module_name.c_str(), map.architecture.c_str(),
        map.sections.size(), map.functions.size(), map.globals.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon", "START -- source reconstructor workspace state contract check");
    auto t0 = std::chrono::steady_clock::now();

    source_reconstructor::workspace_reconstruction_state_t state;
    bool running = source_reconstructor::is_running_workspace(state);
    float progress = source_reconstructor::get_progress_workspace(state);
    int stage = state.stage.load(std::memory_order_relaxed);
    std::string status = source_reconstructor::get_status_workspace(state);
    const auto& result = source_reconstructor::get_last_result_workspace(state);
    bool progress_ok = progress >= 0.f && progress <= 1.f;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon", "STATE tid=%lu running=%d progress=%.3f stage=%d status_len=%zu status=\"%s\" last_success=%d last_error_len=%zu last_error=\"%s\" module=%s funcs=%d decompiled=%d files=%zu elapsed_ms=%lld",
        GetCurrentThreadId(),
        running ? 1 : 0,
        static_cast<double>(progress),
        stage,
        status.size(),
        status.c_str(),
        result.success ? 1 : 0,
        result.error.size(),
        result.error.c_str(),
        result.module_name.c_str(),
        result.total_functions,
        result.decompiled_functions,
        result.files_created.size(),
        (long long)ms);
    if (progress_ok) {
        log_msg(hf, "srcrecon", "CONTRACT-PASS -- workspace reconstruction state accessible and coherent elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "srcrecon", "FAIL -- workspace reconstruction progress out of range progress=%.3f elapsed_ms=%lld",
            static_cast<double>(progress), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_xref_find(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_find", "START -- xref engine find xrefs to known function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t scratch = driver_bridge::allocate_memory(32);
    if (scratch == 0) {
        log_msg(hf, "xref_find", "FAIL -- allocate_memory returned 0 for xref fixture");
        failed.fetch_add(1); return;
    }

    uint8_t code[16] = { 0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    uint64_t target = scratch + 8;
    bool wrote = driver_bridge::write_memory(scratch, std::vector<uint8_t>(code, code + sizeof(code)));
    xref_engine::find_xrefs_to(target, scratch, sizeof(code));

    for (int i = 0; i < 50; ++i) {
        if (!xref_engine::is_scanning()) break;
        Sleep(100);
    }
    xref_engine::cancel_scan();

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
        count = xref_engine::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count == 0) {
        driver_bridge::free_memory(scratch);
        log_msg(hf, "xref_find", "FAIL -- found 0 xrefs to fixture target 0x%llX (wrote=%d elapsed %lld ms)",
            (unsigned long long)target, static_cast<int>(wrote), (long long)ms);
        failed.fetch_add(1); return;
    }
    driver_bridge::free_memory(scratch);
    log_msg(hf, "xref_find", "PASS -- found %zu fixture xrefs to 0x%llX (elapsed %lld ms)",
        count, (unsigned long long)target, (long long)ms);
    passed.fetch_add(1);
}

static void test_expression_eval_hex(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_hex", "START -- expression eval: 0x1000 + 0x20");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x1000 + 0x20", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x1020) {
        log_msg(hf, "expr_hex", "PASS -- 0x1000 + 0x20 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_hex", "FAIL -- ok=%d value=0x%llX error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_reg", "START -- expression eval: rax + rbx with context");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 100;
    ctx.rbx = 200;
    auto result = expression_eval::evaluate("rax + rbx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_reg", "PASS -- rax(100) + rbx(200) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_reg", "FAIL -- ok=%d value=%llu error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_symbolic_execute_larger(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exlg", "START -- symbolic engine execute on larger range");
    auto t0 = std::chrono::steady_clock::now();

    auto code = symbolic_arithmetic_fixture();
    const auto r10 = symbolic_r10_fixture();
    code.insert(code.end(), r10.begin(), r10.end());
    auto fx = make_symbolic_fixture(hf, "sym_exlg", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(fx.address, fx.address + code.size(), 32, {"rcx", "rdx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exlg", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice_rsi(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slrsi", "START -- symbolic engine slice to syscall argument mirror r10");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_r10_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_slrsi", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(fx.address, fx.address + code.size(), 16, "r10");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slrsi", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint_rdx(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_trdx", "START -- symbolic engine taint trace syscall input rcx");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_trdx", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count,
            result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_trdx", "PASS -- success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count,
        result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_solve_for_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_solv", "START -- symbolic engine solve_for_path");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_branch_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_solv", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::solve_for_path(fx.address, fx.address + 8, 16, {"rcx"});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_solv", "FAIL -- solve_for_path success=0 error=\"%s\" satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
            result.error.c_str(), result.satisfiable,
            result.variable_values.size(), result.solving_time_ms, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (!result.satisfiable || result.variable_values.empty()) {
        log_msg(hf, "sym_solv", "FAIL -- solve_for_path returned no satisfying input satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
            result.satisfiable,
            result.variable_values.size(), result.solving_time_ms, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_solv", "PASS -- success=%d satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
        result.success, result.satisfiable,
        result.variable_values.size(), result.solving_time_ms, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_state_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_stch", "START -- symbolic engine state contract check");
    auto t0 = std::chrono::steady_clock::now();

    bool processing = symbolic_engine::g_state.processing.load();
    uint32_t progress_current = symbolic_engine::g_state.progress_current.load();
    uint32_t progress_total = symbolic_engine::g_state.progress_total.load();
    size_t trace_count = 0;
    size_t slice_count = 0;
    size_t taint_count = 0;
    size_t solve_vars = 0;
    std::string last_error;
    {
        std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
        trace_count = symbolic_engine::g_state.last_result.trace.size();
        slice_count = symbolic_engine::g_state.last_slice.effective_instructions.size();
        taint_count = symbolic_engine::g_state.last_taint.tainted_instructions.size();
        solve_vars = symbolic_engine::g_state.last_solve.variable_values.size();
        if (!symbolic_engine::g_state.last_result.error.empty())
            last_error = symbolic_engine::g_state.last_result.error;
        else if (!symbolic_engine::g_state.last_slice.error.empty())
            last_error = symbolic_engine::g_state.last_slice.error;
        else if (!symbolic_engine::g_state.last_taint.error.empty())
            last_error = symbolic_engine::g_state.last_taint.error;
        else
            last_error = symbolic_engine::g_state.last_solve.error;
    }
    bool progress_ok = progress_total == 0 || progress_current <= progress_total;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_stch", "STATE target_pid=%u tid=%lu processing=%d progress=%u/%u trace=%zu slice=%zu taint=%zu solve_vars=%zu last_error_len=%zu elapsed_ms=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        processing ? 1 : 0,
        progress_current,
        progress_total,
        trace_count,
        slice_count,
        taint_count,
        solve_vars,
        last_error.size(),
        (long long)ms);
    if (progress_ok) {
        log_msg(hf, "sym_stch", "CONTRACT-PASS -- symbolic idle/state counters are coherent; no live fixture claimed elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "sym_stch", "FAIL -- symbolic progress counters incoherent current=%u total=%u elapsed_ms=%lld",
            progress_current, progress_total, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_deobfusc_deobfuscate_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_fn", "START -- deobfuscation engine deobfuscate_function");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_fn", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::deobfuscate_function(fx.address, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function success=0 error=\"%s\" original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty() || result.clean_blocks.empty()) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function returned empty result success=%d original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_fn", "PASS -- success=%d original=%u clean=%u blocks=%zu edges=%zu (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.clean_blocks.size(), result.clean_edges.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_export_asm(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_asm", "START -- deobfuscation engine export_clean_asm");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t empty_result;
    empty_result.success = true;

    deobfuscation_engine::clean_instruction_t ci;
    ci.address = 0x1000;
    ci.size = 3;
    ci.disasm = "mov eax, ecx";
    empty_result.clean_instructions.push_back(ci);

    std::string asm_text = deobfuscation_engine::export_clean_asm(empty_result);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!asm_text.empty()) {
        log_msg(hf, "deob_asm", "PASS -- export_clean_asm returned %zu chars (elapsed %lld ms)",
            asm_text.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_asm", "FAIL -- export_clean_asm returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_deobfusc_export_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_stat", "START -- deobfuscation engine export_statistics pure helper coverage");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t result;
    result.success = true;
    result.total_original = 100;
    result.total_clean = 80;
    result.removed_junk = 15;
    result.opaque_predicates_found = 3;
    result.constants_resolved = 2;
    result.junk_ratio = 0.15f;

    std::string stats = deobfuscation_engine::export_statistics(result);
    bool has_original = stats.find("100") != std::string::npos;
    bool has_clean = stats.find("80") != std::string::npos;
    bool has_ratio = stats.find("15") != std::string::npos || stats.find("0.15") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "deob_stat", "RESULT coverage=pure_helper chars=%zu original=%u clean=%u removed=%u opaque=%u constants=%u junk_ratio=%.3f has_original=%d has_clean=%d has_ratio=%d elapsed_ms=%lld",
        stats.size(),
        result.total_original,
        result.total_clean,
        result.removed_junk,
        result.opaque_predicates_found,
        result.constants_resolved,
        static_cast<double>(result.junk_ratio),
        has_original ? 1 : 0,
        has_clean ? 1 : 0,
        has_ratio ? 1 : 0,
        (long long)ms);
    if (!stats.empty() && has_original && has_clean && has_ratio) {
        log_msg(hf, "deob_stat", "PURE-PASS -- export_statistics reflected supplied fixture counters chars=%zu elapsed_ms=%lld",
            stats.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_stat", "FAIL -- export_statistics evidence missing chars=%zu has_original=%d has_clean=%d has_ratio=%d elapsed_ms=%lld",
            stats.size(), has_original ? 1 : 0, has_clean ? 1 : 0, has_ratio ? 1 : 0, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_format_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_fp", "START -- code patcher format_bytes/parse_bytes");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> original = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
    std::string formatted = code_patcher::format_bytes(original);
    std::vector<uint8_t> parsed = code_patcher::parse_bytes(formatted);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (parsed == original) {
        log_msg(hf, "patch_fp", "PASS -- format/parse roundtrip: \"%s\" => %zu bytes (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_fp", "FAIL -- format=\"%s\" parsed_size=%zu (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cnt", "START -- code patcher count/active_count state contract");
    auto t0 = std::chrono::steady_clock::now();

    size_t total = code_patcher::count();
    size_t active = code_patcher::active_count();
    bool counts_ok = active <= total;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cnt", "STATE target_pid=%u tid=%lu total=%zu active=%zu last_error=\"%s\" elapsed_ms=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        total,
        active,
        driver_bridge::last_error().c_str(),
        (long long)ms);
    if (counts_ok) {
        log_msg(hf, "patch_cnt", "CONTRACT-PASS -- patch registry counts coherent; no live patch fixture claimed elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_cnt", "FAIL -- active patch count exceeds total active=%zu total=%zu elapsed_ms=%lld",
            active, total, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_integrity_hunter_start_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_ss", "START -- integrity hunter start/stop hunt");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "integ_ss", failed))
        return;

    integrity_hunter::stop_hunt();
    const auto pre_idle_result = integrity_hunter::wait_until_idle_result(15000);
    const bool pre_idle = pre_idle_result.idle;
    const bool pre_hunting = integrity_hunter::g_state.hunting.load();
    const bool pre_worker = integrity_hunter::g_state.worker_active.load();
    const uint32_t pre_session = integrity_hunter::g_state.pg_session_id.load();
    if (!pre_idle || pre_hunting || pre_worker) {
        auto ms_pre = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_ss", "FAIL -- stale integrity hunter state before start/stop test: pre_idle=%d hunting=%d worker=%d session=%u target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_session,
            (unsigned)driver_bridge::attached_pid(),
            driver_attached_flag(driver_bridge::attached_pid()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms_pre);
        failed.fetch_add(1);
        return;
    }

    const uint32_t target_pid = driver_bridge::attached_pid();
    uint64_t addr = 0;
    for (const auto& mod : driver_bridge::enumerate_modules_for(target_pid)) {
        if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
            addr = mod.base;
            break;
        }
    }
    if (addr == 0) {
        auto ms_mod = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_ss", "FAIL -- root dependency unavailable: target ntdll module not found (target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\" elapsed %lld ms)",
            (unsigned)target_pid,
            driver_attached_flag(target_pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms_mod);
        failed.fetch_add(1);
        return;
    }

    bool started = integrity_hunter::start_hunt(addr, 4096);

    Sleep(200);

    integrity_hunter::stop_hunt();

    const uint64_t generation = integrity_hunter::g_state.generation.load(std::memory_order_acquire);
    auto idle_result = integrity_hunter::wait_until_idle_result(15000);
    bool idle = idle_result.idle;
    bool hunting = integrity_hunter::g_state.hunting.load();
    bool worker = integrity_hunter::g_state.worker_active.load();
    bool install_complete = integrity_hunter::install_complete_for_generation(generation);
    bool install_success = integrity_hunter::install_success_for_generation(generation);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && idle && !hunting && !worker) {
        log_msg(hf, "integ_ss", "PASS -- target_pid=%u driver_attached=%d target=0x%016llX generation=%llu install_generation=%llu started=%d idle=%d cleanup_elapsed_ms=%lld stop_to_cancel_ms=%llu stop_to_uninstall_begin_ms=%llu uninstall_ms=%llu stop_to_worker_exit_ms=%llu last_uninstall_elapsed_ms=%llu hunting_after_stop=%d worker=%d install_complete=%d install_success=%d nodes=%zu events=%zu total_reads=%llu (elapsed %lld ms)",
            (unsigned)target_pid, driver_attached_flag(target_pid), (unsigned long long)addr,
            (unsigned long long)generation,
            (unsigned long long)idle_result.install_generation,
            started ? 1 : 0, idle ? 1 : 0, (long long)idle_result.elapsed_ms,
            (unsigned long long)idle_result.stop_to_cancel_ms,
            (unsigned long long)idle_result.stop_to_uninstall_begin_ms,
            (unsigned long long)idle_result.uninstall_ms,
            (unsigned long long)idle_result.stop_to_worker_exit_ms,
            (unsigned long long)idle_result.last_uninstall_elapsed_ms,
            hunting ? 1 : 0, worker ? 1 : 0,
            install_complete ? 1 : 0, install_success ? 1 : 0,
            idle_result.nodes,
            idle_result.events,
            (unsigned long long)idle_result.total_reads,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "integ_ss", "FAIL -- target_pid=%u active_pid=%u driver_attached=%d target=0x%016llX generation=%llu install_generation=%llu started=%d idle=%d cleanup_elapsed_ms=%lld stop_to_cancel_ms=%llu stop_to_uninstall_begin_ms=%llu uninstall_ms=%llu stop_to_worker_exit_ms=%llu last_uninstall_elapsed_ms=%llu hunting_after_stop=%d worker=%d install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d nodes=%zu events=%zu total_reads=%llu status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)target_pid,
            (unsigned)driver_bridge::attached_pid(),
            driver_attached_flag(target_pid),
            (unsigned long long)addr,
            (unsigned long long)generation,
            (unsigned long long)idle_result.install_generation,
            started ? 1 : 0, idle ? 1 : 0, (long long)idle_result.elapsed_ms,
            (unsigned long long)idle_result.stop_to_cancel_ms,
            (unsigned long long)idle_result.stop_to_uninstall_begin_ms,
            (unsigned long long)idle_result.uninstall_ms,
            (unsigned long long)idle_result.stop_to_worker_exit_ms,
            (unsigned long long)idle_result.last_uninstall_elapsed_ms,
            hunting ? 1 : 0, worker ? 1 : 0,
            install_complete ? 1 : 0, install_success ? 1 : 0,
            idle_result.install_complete ? 1 : 0,
            idle_result.install_success ? 1 : 0,
            idle_result.nodes,
            idle_result.events,
            (unsigned long long)idle_result.total_reads,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_integrity_hunter_nodes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_nd", "START -- integrity hunter node list with deterministic page-guard stimulus");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "integ_nd", failed))
        return;

    integrity_hunter::stop_hunt();
    const bool pre_idle = integrity_hunter::wait_until_idle(5000);
    const bool pre_hunting = integrity_hunter::g_state.hunting.load();
    const bool pre_worker = integrity_hunter::g_state.worker_active.load();
    const bool pre_install_complete = integrity_hunter::g_state.install_complete.load();
    const bool pre_install_success = integrity_hunter::g_state.install_success.load();
    const uint32_t pre_session = integrity_hunter::g_state.pg_session_id.load();
    std::string pre_status_text;
    size_t pre_nodes = 0;
    size_t pre_events = 0;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        pre_status_text = integrity_hunter::g_state.status_text;
        pre_nodes = integrity_hunter::g_state.nodes.size();
        pre_events = integrity_hunter::g_state.event_log.size();
    }
    if (!pre_idle || pre_hunting || pre_worker) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        diag::log_tagged_fmt("test_analysis_detail",
            "integ_nd stale_pre_idle: pid=%u pre_idle=%d hunting=%d worker=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu status='%s' bridge_status='%s' bridge_last_error='%s' elapsed_ms=%lld",
            (unsigned)driver_bridge::attached_pid(),
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_install_complete ? 1 : 0,
            pre_install_success ? 1 : 0,
            pre_session,
            pre_nodes,
            pre_events,
            (unsigned long long)integrity_hunter::g_state.total_reads.load(),
            pre_status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        log_msg(hf, "integ_nd", "FAIL -- stale integrity hunter state before node test: pre_idle=%d hunting=%d worker=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu status=\"%s\" bridge_status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_install_complete ? 1 : 0,
            pre_install_success ? 1 : 0,
            pre_session,
            pre_nodes,
            pre_events,
            (unsigned long long)integrity_hunter::g_state.total_reads.load(),
            pre_status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    const uint32_t primary_pid = driver_bridge::attached_pid();
    integrity_hunter_sidecar_scope_t sidecar_scope(hf, "integ_nd", primary_pid);
    if (!sidecar_scope.start(5000)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_nd", "FAIL -- isolated integrity hunter sidecar was not ready primary_pid=%u active_pid=%u status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)primary_pid,
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "integ_nd", "SAFE-FIXTURE -- isolated integrity hunter target sidecar_pid=%lu primary_pid=%u active_pid=%u",
        static_cast<unsigned long>(sidecar_scope.sidecar.pid),
        (unsigned)primary_pid,
        driver_bridge::attached_pid());

    integrity_hunter_fixture_t fixture = make_integrity_hunter_fixture(hf, "integ_nd");
    if (fixture.address == 0) {
        failed.fetch_add(1);
        return;
    }
    const uint32_t target_pid = fixture.pid;

    driver_bridge::memory_region_t before_region{};
    const bool before_query = driver_bridge::query_memory_for(target_pid, fixture.address, before_region);

    ntdll_export_resolution_t target_resolve = resolve_attached_ntdll_export(hf, "integ_nd", target_pid, "RtlComputeCrc32");
    std::string read_module = target_resolve.module_name;
    uint64_t target_read_fn = target_resolve.address;
    const char* target_read_kind = "RtlComputeCrc32";
    if (target_read_fn == 0) {
        target_resolve = resolve_attached_ntdll_export(hf, "integ_nd", target_pid, "RtlCompareMemory");
        read_module = target_resolve.module_name;
        target_read_fn = target_resolve.address;
        target_read_kind = "RtlCompareMemory";
    }

    if (target_read_fn == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_nd", "FAIL -- no target-side ntdll read function resolved for integrity fixture pid=%u addr=0x%016llX before_query=%d before_protect=0x%08X resolve_method=%s local_export_ok=%d local_rva=0x%016llX ntdll_seen=%d modules=%zu local_us=%lld enum_us=%lld slow_attempts=%u slow_us=%lld status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)target_pid,
            (unsigned long long)fixture.address,
            before_query ? 1 : 0,
            (unsigned)before_region.protect,
            target_resolve.method,
            target_resolve.local_export_ok ? 1 : 0,
            (unsigned long long)target_resolve.local_rva,
            target_resolve.ntdll_seen ? 1 : 0,
            target_resolve.module_count,
            target_resolve.local_us,
            target_resolve.enum_us,
            target_resolve.slow_attempts,
            target_resolve.slow_us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    const bool started = integrity_hunter::start_hunt(fixture.address, 128);
    const uint64_t generation = integrity_hunter::g_state.generation.load(std::memory_order_acquire);
    if (!started) {
        const auto idle_state = integrity_hunter::snapshot_idle_state();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_nd", "FAIL -- integrity hunter start failed: generation=%llu install_generation=%llu pid=%u active_pid=%u addr=0x%016llX size=%u install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d nodes=%zu events=%zu total_reads=%llu status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned long long)generation,
            (unsigned long long)idle_state.install_generation,
            (unsigned)idle_state.target_pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)fixture.address,
            128u,
            integrity_hunter::install_complete_for_generation(generation) ? 1 : 0,
            integrity_hunter::install_success_for_generation(generation) ? 1 : 0,
            idle_state.install_complete ? 1 : 0,
            idle_state.install_success ? 1 : 0,
            idle_state.nodes,
            idle_state.events,
            (unsigned long long)idle_state.total_reads,
            idle_state.status_text.c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }
    bool install_seen = false;
    const DWORD install_start = GetTickCount();
    while (GetTickCount() - install_start < 3000) {
        if (integrity_hunter::install_complete_for_generation(generation)) {
            install_seen = true;
            break;
        }
        if (!integrity_hunter::g_state.hunting.load() && !integrity_hunter::g_state.worker_active.load())
            break;
        Sleep(25);
    }

    const bool install_complete = integrity_hunter::install_complete_for_generation(generation);
    const bool install_success = integrity_hunter::install_success_for_generation(generation);
    const uint32_t pg_session = integrity_hunter::g_state.pg_session_id.load();

    driver_bridge::memory_region_t guard_region{};
    const bool guard_query = driver_bridge::query_memory_for(target_pid, fixture.address, guard_region);
    const bool guard_set = guard_query && ((guard_region.protect & PAGE_GUARD) != 0);

    if (!install_complete || !install_success) {
        integrity_hunter::stop_hunt();
        const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
        const char* status = idle_state.idle ? "page_guard_install_failed" : "page_guard_install_cleanup_exceeded";
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        const auto pg_failure = page_guard_engine::g_pg_engine.last_install_failure();
        diag::log_tagged_fmt("test_analysis_detail",
            "integ_nd install_failure status=%s generation=%llu install_generation=%llu pid=%u active_pid=%u addr=0x%llX size=%u install_seen=%d install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d idle=%d cleanup_elapsed_ms=%lld pg_session=%u guard_query=%d guard_state=%d guard_protect=0x%08X nodes=%zu events=%zu total_reads=%llu status_text='%s' bridge_status='%s' last_error='%s' elapsed_ms=%lld",
            status,
            (unsigned long long)generation,
            (unsigned long long)idle_state.install_generation,
            (unsigned)idle_state.target_pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)fixture.address,
            128u,
            install_seen ? 1 : 0,
            install_complete ? 1 : 0,
            install_success ? 1 : 0,
            idle_state.install_complete ? 1 : 0,
            idle_state.install_success ? 1 : 0,
            idle_state.idle ? 1 : 0,
            (long long)idle_state.elapsed_ms,
            pg_session,
            guard_query ? 1 : 0,
            guard_set ? 1 : 0,
            (unsigned)guard_region.protect,
            idle_state.nodes,
            idle_state.events,
            (unsigned long long)idle_state.total_reads,
            idle_state.status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        diag::log_tagged_fmt("test_analysis_detail",
            "integ_nd pg_last_failure reason=%s detail='%s' pid=%u active_pid=%u requested_addr=0x%llX requested_size=0x%llX guard_addr=0x%llX guard_size=0x%llX region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X region_type=0x%08X original_protect=0x%08X proposed_protect=0x%08X attempted_protect=0x%08X ring=0x%llX shellcode=0x%llX context=0x%llX ntdll=0x%llX ntdll_size=0x%llX rtl_add=0x%llX rtl_remove=0x%llX veh_result=0x%llX remote_gle=%lu remote_elapsed_ms=%llu install_elapsed_ms=%llu install_generation=%llu current_generation=%llu cleanup_sc_ok=%u cleanup_ring_ok=%u mitigation_open=%u mitigation_open_error=%lu dyn_ok=%u dyn_error=%lu dyn_flags=0x%08X cfg_ok=%u cfg_error=%lu cfg_flags=0x%08X driver_status='%s' driver_last_error='%s' remote_status='%s' remote_last_error='%s'",
            pg_failure.reason.c_str(),
            pg_failure.detail.c_str(),
            (unsigned)pg_failure.pid,
            (unsigned)pg_failure.active_pid,
            (unsigned long long)pg_failure.requested_addr,
            (unsigned long long)pg_failure.requested_size,
            (unsigned long long)pg_failure.guard_addr,
            (unsigned long long)pg_failure.guard_size,
            (unsigned long long)pg_failure.region_base,
            (unsigned long long)pg_failure.region_size,
            (unsigned)pg_failure.region_state,
            (unsigned)pg_failure.region_protect,
            (unsigned)pg_failure.region_type,
            (unsigned)pg_failure.original_protect,
            (unsigned)pg_failure.proposed_protect,
            (unsigned)pg_failure.attempted_protect,
            (unsigned long long)pg_failure.ring_addr,
            (unsigned long long)pg_failure.shellcode_addr,
            (unsigned long long)pg_failure.context_addr,
            (unsigned long long)pg_failure.ntdll_base,
            (unsigned long long)pg_failure.ntdll_size,
            (unsigned long long)pg_failure.rtl_add_veh,
            (unsigned long long)pg_failure.rtl_remove_veh,
            (unsigned long long)pg_failure.veh_result,
            static_cast<unsigned long>(pg_failure.remote_call_gle),
            (unsigned long long)pg_failure.remote_call_elapsed_ms,
            (unsigned long long)pg_failure.install_elapsed_ms,
            (unsigned long long)pg_failure.install_generation,
            (unsigned long long)pg_failure.current_generation,
            (unsigned)pg_failure.cleanup_shellcode_ok,
            (unsigned)pg_failure.cleanup_ring_ok,
            (unsigned)pg_failure.mitigation_open_ok,
            static_cast<unsigned long>(pg_failure.mitigation_open_error),
            (unsigned)pg_failure.mitigation_dynamic_ok,
            static_cast<unsigned long>(pg_failure.mitigation_dynamic_error),
            (unsigned)pg_failure.mitigation_dynamic_flags,
            (unsigned)pg_failure.mitigation_cfg_ok,
            static_cast<unsigned long>(pg_failure.mitigation_cfg_error),
            (unsigned)pg_failure.mitigation_cfg_flags,
            pg_failure.driver_status.c_str(),
            pg_failure.driver_last_error.c_str(),
            pg_failure.remote_call_driver_status.c_str(),
            pg_failure.remote_call_driver_last_error.c_str());
        log_msg(hf, "integ_nd", "PG-LAST-FAILURE -- reason=%s detail=\"%s\" pid=%u active_pid=%u requested=0x%016llX size=0x%016llX guard=0x%016llX guard_size=0x%016llX region_base=0x%016llX region_size=0x%016llX region_state=0x%08X region_protect=0x%08X region_type=0x%08X original_protect=0x%08X proposed_protect=0x%08X attempted_protect=0x%08X ring=0x%016llX shellcode=0x%016llX context=0x%016llX ntdll=0x%016llX ntdll_size=0x%016llX rtl_add=0x%016llX rtl_remove=0x%016llX veh_result=0x%016llX remote_gle=%lu remote_elapsed_ms=%llu install_elapsed_ms=%llu install_generation=%llu current_generation=%llu cleanup_sc_ok=%u cleanup_ring_ok=%u mitigation_open=%u mitigation_open_error=%lu dyn_ok=%u dyn_error=%lu dyn_flags=0x%08X cfg_ok=%u cfg_error=%lu cfg_flags=0x%08X driver_status=\"%s\" driver_last_error=\"%s\" remote_status=\"%s\" remote_last_error=\"%s\"",
            pg_failure.reason.c_str(),
            pg_failure.detail.c_str(),
            (unsigned)pg_failure.pid,
            (unsigned)pg_failure.active_pid,
            (unsigned long long)pg_failure.requested_addr,
            (unsigned long long)pg_failure.requested_size,
            (unsigned long long)pg_failure.guard_addr,
            (unsigned long long)pg_failure.guard_size,
            (unsigned long long)pg_failure.region_base,
            (unsigned long long)pg_failure.region_size,
            (unsigned)pg_failure.region_state,
            (unsigned)pg_failure.region_protect,
            (unsigned)pg_failure.region_type,
            (unsigned)pg_failure.original_protect,
            (unsigned)pg_failure.proposed_protect,
            (unsigned)pg_failure.attempted_protect,
            (unsigned long long)pg_failure.ring_addr,
            (unsigned long long)pg_failure.shellcode_addr,
            (unsigned long long)pg_failure.context_addr,
            (unsigned long long)pg_failure.ntdll_base,
            (unsigned long long)pg_failure.ntdll_size,
            (unsigned long long)pg_failure.rtl_add_veh,
            (unsigned long long)pg_failure.rtl_remove_veh,
            (unsigned long long)pg_failure.veh_result,
            static_cast<unsigned long>(pg_failure.remote_call_gle),
            (unsigned long long)pg_failure.remote_call_elapsed_ms,
            (unsigned long long)pg_failure.install_elapsed_ms,
            (unsigned long long)pg_failure.install_generation,
            (unsigned long long)pg_failure.current_generation,
            (unsigned)pg_failure.cleanup_shellcode_ok,
            (unsigned)pg_failure.cleanup_ring_ok,
            (unsigned)pg_failure.mitigation_open_ok,
            static_cast<unsigned long>(pg_failure.mitigation_open_error),
            (unsigned)pg_failure.mitigation_dynamic_ok,
            static_cast<unsigned long>(pg_failure.mitigation_dynamic_error),
            (unsigned)pg_failure.mitigation_dynamic_flags,
            (unsigned)pg_failure.mitigation_cfg_ok,
            static_cast<unsigned long>(pg_failure.mitigation_cfg_error),
            (unsigned)pg_failure.mitigation_cfg_flags,
            pg_failure.driver_status.c_str(),
            pg_failure.driver_last_error.c_str(),
            pg_failure.remote_call_driver_status.c_str(),
            pg_failure.remote_call_driver_last_error.c_str());
        log_msg(hf, "integ_nd", "PG-LAST-FAILURE-CORE -- reason=%s detail=\"%s\" pid=%u active_pid=%u requested=0x%016llX size=0x%016llX guard=0x%016llX guard_size=0x%016llX region_base=0x%016llX region_size=0x%016llX region_state=0x%08X region_protect=0x%08X region_type=0x%08X original_protect=0x%08X proposed_protect=0x%08X attempted_protect=0x%08X",
            pg_failure.reason.c_str(),
            pg_failure.detail.c_str(),
            (unsigned)pg_failure.pid,
            (unsigned)pg_failure.active_pid,
            (unsigned long long)pg_failure.requested_addr,
            (unsigned long long)pg_failure.requested_size,
            (unsigned long long)pg_failure.guard_addr,
            (unsigned long long)pg_failure.guard_size,
            (unsigned long long)pg_failure.region_base,
            (unsigned long long)pg_failure.region_size,
            (unsigned)pg_failure.region_state,
            (unsigned)pg_failure.region_protect,
            (unsigned)pg_failure.region_type,
            (unsigned)pg_failure.original_protect,
            (unsigned)pg_failure.proposed_protect,
            (unsigned)pg_failure.attempted_protect);
        log_msg(hf, "integ_nd", "PG-LAST-FAILURE-VEH -- ring=0x%016llX shellcode=0x%016llX context=0x%016llX ntdll=0x%016llX ntdll_size=0x%016llX rtl_add=0x%016llX rtl_remove=0x%016llX veh_result=0x%016llX remote_gle=%lu remote_elapsed_ms=%llu install_elapsed_ms=%llu install_generation=%llu current_generation=%llu cleanup_sc_ok=%u cleanup_ring_ok=%u",
            (unsigned long long)pg_failure.ring_addr,
            (unsigned long long)pg_failure.shellcode_addr,
            (unsigned long long)pg_failure.context_addr,
            (unsigned long long)pg_failure.ntdll_base,
            (unsigned long long)pg_failure.ntdll_size,
            (unsigned long long)pg_failure.rtl_add_veh,
            (unsigned long long)pg_failure.rtl_remove_veh,
            (unsigned long long)pg_failure.veh_result,
            static_cast<unsigned long>(pg_failure.remote_call_gle),
            (unsigned long long)pg_failure.remote_call_elapsed_ms,
            (unsigned long long)pg_failure.install_elapsed_ms,
            (unsigned long long)pg_failure.install_generation,
            (unsigned long long)pg_failure.current_generation,
            (unsigned)pg_failure.cleanup_shellcode_ok,
            (unsigned)pg_failure.cleanup_ring_ok);
        log_msg(hf, "integ_nd", "PG-LAST-FAILURE-MITIGATION -- mitigation_open=%u mitigation_open_error=%lu dyn_ok=%u dyn_error=%lu dyn_flags=0x%08X cfg_ok=%u cfg_error=%lu cfg_flags=0x%08X driver_status=\"%s\" driver_last_error=\"%s\" remote_status=\"%s\" remote_last_error=\"%s\"",
            (unsigned)pg_failure.mitigation_open_ok,
            static_cast<unsigned long>(pg_failure.mitigation_open_error),
            (unsigned)pg_failure.mitigation_dynamic_ok,
            static_cast<unsigned long>(pg_failure.mitigation_dynamic_error),
            (unsigned)pg_failure.mitigation_dynamic_flags,
            (unsigned)pg_failure.mitigation_cfg_ok,
            static_cast<unsigned long>(pg_failure.mitigation_cfg_error),
            (unsigned)pg_failure.mitigation_cfg_flags,
            pg_failure.driver_status.c_str(),
            pg_failure.driver_last_error.c_str(),
            pg_failure.remote_call_driver_status.c_str(),
            pg_failure.remote_call_driver_last_error.c_str());
        log_msg(hf, "integ_nd", "FAIL -- integrity hunter page-guard install failure: status=%s generation=%llu install_generation=%llu pid=%u active_pid=%u fixture=0x%016llX size=%u install_seen=%d install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d idle=%d cleanup_elapsed_ms=%lld pg_session=%u guard_query=%d guard_state=%d guard_protect=0x%08X nodes=%zu events=%zu total_reads=%llu status_text=\"%s\" bridge_status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            status,
            (unsigned long long)generation,
            (unsigned long long)idle_state.install_generation,
            (unsigned)idle_state.target_pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)fixture.address,
            128u,
            install_seen ? 1 : 0,
            install_complete ? 1 : 0,
            install_success ? 1 : 0,
            idle_state.install_complete ? 1 : 0,
            idle_state.install_success ? 1 : 0,
            idle_state.idle ? 1 : 0,
            (long long)idle_state.elapsed_ms,
            pg_session,
            guard_query ? 1 : 0,
            guard_set ? 1 : 0,
            (unsigned)guard_region.protect,
            idle_state.nodes,
            idle_state.events,
            (unsigned long long)idle_state.total_reads,
            idle_state.status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint32_t target_read_attempts = 0;
    uint32_t target_read_ok = 0;
    uint64_t target_read_result = 0;
    if (started && install_seen && install_success) {
        for (uint32_t i = 0; i < 2; ++i) {
            ++target_read_attempts;
            target_read_result = std::strcmp(target_read_kind, "RtlCompareMemory") == 0
                ? page_guard_engine::remote_thread_call(target_pid, target_read_fn, fixture.address, fixture.address, 128, 0, 2500, "testlab_integrity_RtlCompareMemory")
                : page_guard_engine::remote_thread_call(target_pid, target_read_fn, i, fixture.address, 128, 0, 2500, "testlab_integrity_RtlComputeCrc32");
            if (target_read_result != 0)
                ++target_read_ok;
        }
    }

    std::vector<uint8_t> readback;
    const bool driver_read_ok = driver_bridge::read_memory_for(target_pid, fixture.address, 128, readback) && !readback.empty();
    std::vector<uint8_t> writeback = readback;
    if (!writeback.empty())
        writeback[0] ^= 0x5Au;
    const bool driver_write_ok = !writeback.empty() && driver_bridge::write_memory_for(target_pid, fixture.address, writeback);

    integrity_hunter::stop_hunt();
    const auto idle_state = integrity_hunter::wait_until_idle_result(6000);
    const bool idle = idle_state.idle;

    size_t node_count = 0;
    size_t event_count = 0;
    uint64_t first_reader = 0;
    uint64_t first_fault = 0;
    uint32_t first_access = 0;
    int first_node_reads = 0;
    std::string status_text;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        node_count = integrity_hunter::g_state.nodes.size();
        event_count = integrity_hunter::g_state.event_log.size();
        if (!integrity_hunter::g_state.event_log.empty()) {
            first_reader = integrity_hunter::g_state.event_log.front().rip;
            first_fault = integrity_hunter::g_state.event_log.front().fault_addr;
            first_access = integrity_hunter::g_state.event_log.front().access_type;
        }
        if (!integrity_hunter::g_state.nodes.empty()) {
            first_node_reads = integrity_hunter::g_state.nodes.front().read_count;
        }
        status_text = integrity_hunter::g_state.status_text;
    }
    const uint64_t total_reads = integrity_hunter::g_state.total_reads.load();

    driver_bridge::memory_region_t after_region{};
    const bool after_query = driver_bridge::query_memory_for(target_pid, fixture.address, after_region);
    const bool after_guard = after_query && ((after_region.protect & PAGE_GUARD) != 0);

    diag::log_tagged_fmt("test_analysis_detail", "integ_nd result: pid=%u active_pid=%u addr=0x%llX generation=%llu install_generation=%llu started=%d install_seen=%d install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d idle=%d cleanup_elapsed_ms=%lld pg_session=%u before_query=%d before_protect=0x%08X guard_query=%d guard_state=%d guard_protect=0x%08X after_query=%d after_guard=%d after_protect=0x%08X driver_read_ok=%d read_bytes=%zu driver_write_ok=%d target_read_kind=%s target_read_module=%s target_read_fn=0x%llX target_read_resolve_method=%s target_read_rva=0x%llX resolve_local_us=%lld resolve_enum_us=%lld resolve_slow_attempts=%u resolve_slow_us=%lld target_read_attempts=%u target_read_ok=%u target_read_result=0x%llX nodes=%zu events=%zu total_reads=%llu first_reader=0x%llX first_fault=0x%llX first_access=%u first_node_reads=%d status='%s'",
        (unsigned)target_pid,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned long long)fixture.address,
        (unsigned long long)generation,
        (unsigned long long)idle_state.install_generation,
        started ? 1 : 0,
        install_seen ? 1 : 0,
        install_complete ? 1 : 0,
        install_success ? 1 : 0,
        idle_state.install_complete ? 1 : 0,
        idle_state.install_success ? 1 : 0,
        idle ? 1 : 0,
        (long long)idle_state.elapsed_ms,
        pg_session,
        before_query ? 1 : 0,
        (unsigned)before_region.protect,
        guard_query ? 1 : 0,
        guard_set ? 1 : 0,
        (unsigned)guard_region.protect,
        after_query ? 1 : 0,
        after_guard ? 1 : 0,
        (unsigned)after_region.protect,
        driver_read_ok ? 1 : 0,
        readback.size(),
        driver_write_ok ? 1 : 0,
        target_read_kind,
        read_module.empty() ? "<none>" : read_module.c_str(),
        (unsigned long long)target_read_fn,
        target_resolve.method,
        (unsigned long long)target_resolve.local_rva,
        target_resolve.local_us,
        target_resolve.enum_us,
        target_resolve.slow_attempts,
        target_resolve.slow_us,
        target_read_attempts,
        target_read_ok,
        (unsigned long long)target_read_result,
        node_count,
        event_count,
        (unsigned long long)total_reads,
        (unsigned long long)first_reader,
        (unsigned long long)first_fault,
        first_access,
        first_node_reads,
        status_text.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && install_seen && install_complete && install_success && idle && guard_query && guard_set && target_read_ok > 0 && total_reads > 0 && event_count > 0 && node_count > 0) {
        log_msg(hf, "integ_nd", "PASS -- generation=%llu install_generation=%llu pid=%u active_pid=%u fixture=0x%016llX guard_state=%d cleanup_elapsed_ms=%lld read_ok=%d write_ok=%d target_read=%s module=%s resolve_method=%s rva=0x%016llX resolve_local_us=%lld resolve_enum_us=%lld resolve_slow_attempts=%u resolve_slow_us=%lld attempts=%u ok=%u nodes=%zu events=%zu total_reads=%llu first_reader=0x%016llX first_fault=0x%016llX node_reads=%d status=\"%s\" (elapsed %lld ms)",
            (unsigned long long)generation,
            (unsigned long long)idle_state.install_generation,
            (unsigned)target_pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)fixture.address,
            guard_set ? 1 : 0,
            (long long)idle_state.elapsed_ms,
            driver_read_ok ? 1 : 0,
            driver_write_ok ? 1 : 0,
            target_read_kind,
            read_module.empty() ? "<none>" : read_module.c_str(),
            target_resolve.method,
            (unsigned long long)target_resolve.local_rva,
            target_resolve.local_us,
            target_resolve.enum_us,
            target_resolve.slow_attempts,
            target_resolve.slow_us,
            target_read_attempts,
            target_read_ok,
            node_count,
            event_count,
            (unsigned long long)total_reads,
            (unsigned long long)first_reader,
            (unsigned long long)first_fault,
            first_node_reads,
            status_text.c_str(),
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "integ_nd", "FAIL -- integrity hunter evidence insufficient: generation=%llu install_generation=%llu pid=%u active_pid=%u fixture=0x%016llX started=%d install_seen=%d install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d idle=%d cleanup_elapsed_ms=%lld pg_session=%u guard_query=%d guard_state=%d guard_protect=0x%08X read_ok=%d read_bytes=%zu write_ok=%d target_read=%s module=%s resolve_method=%s rva=0x%016llX resolve_local_us=%lld resolve_enum_us=%lld resolve_slow_attempts=%u resolve_slow_us=%lld attempts=%u ok=%u result=0x%016llX nodes=%zu events=%zu total_reads=%llu first_reader=0x%016llX first_fault=0x%016llX first_access=%u node_reads=%d status=\"%s\" status_bridge=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned long long)generation,
            (unsigned long long)idle_state.install_generation,
            (unsigned)target_pid,
            (unsigned)driver_bridge::attached_pid(),
            (unsigned long long)fixture.address,
            started ? 1 : 0,
            install_seen ? 1 : 0,
            install_complete ? 1 : 0,
            install_success ? 1 : 0,
            idle_state.install_complete ? 1 : 0,
            idle_state.install_success ? 1 : 0,
            idle ? 1 : 0,
            (long long)idle_state.elapsed_ms,
            pg_session,
            guard_query ? 1 : 0,
            guard_set ? 1 : 0,
            (unsigned)guard_region.protect,
            driver_read_ok ? 1 : 0,
            readback.size(),
            driver_write_ok ? 1 : 0,
            target_read_kind,
            read_module.empty() ? "<none>" : read_module.c_str(),
            target_resolve.method,
            (unsigned long long)target_resolve.local_rva,
            target_resolve.local_us,
            target_resolve.enum_us,
            target_resolve.slow_attempts,
            target_resolve.slow_us,
            target_read_attempts,
            target_read_ok,
            (unsigned long long)target_read_result,
            node_count,
            event_count,
            (unsigned long long)total_reads,
            (unsigned long long)first_reader,
            (unsigned long long)first_fault,
            first_access,
            first_node_reads,
            status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_options(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_op", "START -- binary map fixture render with import/export options");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 5;
    opts.max_globals = 3;
    opts.max_chars = 1024;
    opts.include_imports = true;
    opts.include_exports = true;

    aida::binary_map::map_t map = make_binary_map_fixture();
    std::string text = aida::binary_map::render_text(map, opts);
    bool has_import = text.find("kernel32!CloseHandle") != std::string::npos;
    bool has_export = text.find("FixtureExport") != std::string::npos;
    bool ok = !text.empty() && has_import && has_export && text.size() <= opts.max_chars;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_op", "RESULT coverage=fixture module=%s base=0x%llX end=0x%llX max_chars=%zu text_chars=%zu sections=%zu funcs=%zu globals=%zu imports=%zu exports=%zu has_import=%d has_export=%d elapsed_ms=%lld",
        map.module_name.c_str(),
        (unsigned long long)map.image_base,
        (unsigned long long)(map.image_base + map.image_size),
        opts.max_chars,
        text.size(),
        map.sections.size(),
        map.functions.size(),
        map.globals.size(),
        map.imports.size(),
        map.exports.size(),
        has_import ? 1 : 0,
        has_export ? 1 : 0,
        (long long)ms);
    if (ok) {
        log_msg(hf, "binmap_op", "FIXTURE-PASS -- binary map options rendered fixture import/export evidence elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "binmap_op", "FAIL -- option render evidence missing text_chars=%zu has_import=%d has_export=%d max_chars=%zu elapsed_ms=%lld",
            text.size(), has_import ? 1 : 0, has_export ? 1 : 0, opts.max_chars, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_pin_unpin(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_pin", "START -- binary map pin/unpin function");
    auto t0 = std::chrono::steady_clock::now();

    auto workspace = analysis_fixture_workspace();
    if (!workspace || !workspace->image()) {
        log_msg(hf, "binmap_pin", "FAIL -- no explicit static workspace fixture");
        failed.fetch_add(1);
        return;
    }
    uint64_t test_va = workspace->image()->image_base() + workspace->image()->entry_rva();
    aida::binary_map::pin_function(workspace, test_va);

    auto pinned = aida::binary_map::pinned_functions(workspace);
    bool found = false;
    for (auto va : pinned) {
        if (va == test_va) { found = true; break; }
    }

    aida::binary_map::unpin_function(workspace, test_va);

    auto pinned_after = aida::binary_map::pinned_functions(workspace);
    bool found_after = false;
    for (auto va : pinned_after) {
        if (va == test_va) { found_after = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (found && !found_after) {
        log_msg(hf, "binmap_pin", "CONTRACT-PASS -- pin/unpin registry roundtrip correct va=0x%llX pinned_before=%zu pinned_after=%zu elapsed_ms=%lld",
            (unsigned long long)test_va, pinned.size(), pinned_after.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "binmap_pin", "FAIL -- pinned=%d unpinned=%d (elapsed %lld ms)", found, !found_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_clear_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_cc", "START -- binary map clear_cache contract");
    auto t0 = std::chrono::steady_clock::now();

    auto workspace = analysis_fixture_workspace();
    if (!workspace) {
        log_msg(hf, "binmap_cc", "FAIL -- no explicit static workspace fixture");
        failed.fetch_add(1);
        return;
    }
    bool ok = aida::binary_map::clear_cache(workspace);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_cc", "CONTRACT-PASS -- clear_cache returned %d last_error=\"%s\" elapsed_ms=%lld",
        ok ? 1 : 0, aida::binary_map::last_error().c_str(), (long long)ms);
    if (ok) {
        passed.fetch_add(1);
    } else {
        failed.fetch_add(1);
    }
}

static void test_binary_map_render_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_rt", "START -- binary map render_text fixture coverage");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 3;
    opts.max_globals = 2;
    opts.max_chars = 512;

    aida::binary_map::map_t map = make_binary_map_fixture();

    std::string text = aida::binary_map::render_text(map, opts);
    bool has_module = text.find(map.module_name) != std::string::npos;
    bool has_function = text.find("fixture_entry") != std::string::npos;
    bool has_section = text.find(".text") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_rt", "RESULT coverage=fixture module=%s path=%s base=0x%llX end=0x%llX sections=%zu funcs=%zu globals=%zu text_chars=%zu has_module=%d has_function=%d has_section=%d elapsed_ms=%lld",
        map.module_name.c_str(),
        map.module_path.c_str(),
        (unsigned long long)map.image_base,
        (unsigned long long)(map.image_base + map.image_size),
        map.sections.size(),
        map.functions.size(),
        map.globals.size(),
        text.size(),
        has_module ? 1 : 0,
        has_function ? 1 : 0,
        has_section ? 1 : 0,
        (long long)ms);
    if (!text.empty() && has_module && has_function && has_section) {
        log_msg(hf, "binmap_rt", "FIXTURE-PASS -- render_text returned expected fixture content chars=%zu elapsed_ms=%lld",
            text.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "binmap_rt", "FAIL -- render_text fixture evidence missing chars=%zu module=%d function=%d section=%d elapsed_ms=%lld",
            text.size(), has_module ? 1 : 0, has_function ? 1 : 0, has_section ? 1 : 0, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_source_reconstructor_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_r", "START -- source reconstructor workspace running/progress state contract");
    auto t0 = std::chrono::steady_clock::now();

    source_reconstructor::workspace_reconstruction_state_t state;
    bool running = source_reconstructor::is_running_workspace(state);
    float progress = source_reconstructor::get_progress_workspace(state);
    std::string status = source_reconstructor::get_status_workspace(state);
    int stage = state.stage.load(std::memory_order_relaxed);
    const auto& result = source_reconstructor::get_last_result_workspace(state);
    bool progress_ok = progress >= 0.f && progress <= 1.f;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon_r", "STATE tid=%lu running=%d progress=%.3f stage=%d status_len=%zu status=\"%s\" last_success=%d last_error_len=%zu last_error=\"%s\" result_funcs=%d result_files=%zu elapsed_ms=%lld",
        GetCurrentThreadId(),
        running ? 1 : 0,
        static_cast<double>(progress),
        stage,
        status.size(),
        status.c_str(),
        result.success ? 1 : 0,
        result.error.size(),
        result.error.c_str(),
        result.total_functions,
        result.files_created.size(),
        (long long)ms);
    if (progress_ok) {
        log_msg(hf, "srcrecon_r", "CONTRACT-PASS -- workspace running/progress state coherent elapsed_ms=%lld",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "srcrecon_r", "FAIL -- invalid workspace reconstruction progress %.3f elapsed_ms=%lld",
            static_cast<double>(progress), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_source_reconstructor_last_result(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_lr", "START -- source reconstructor workspace last_result");
    auto t0 = std::chrono::steady_clock::now();

    auto workspace = analysis_fixture_workspace();
    if (!workspace) {
        log_msg(hf, "srcrecon_lr", "SKIP -- no static workspace available for reconstruction test");
        failed.fetch_add(1);
        return;
    }

    auto snapshot = workspace->snapshot();
    if (!snapshot || snapshot->functions.empty()) {
        log_msg(hf, "srcrecon_lr", "SKIP -- workspace has no snapshot or no functions");
        failed.fetch_add(1);
        return;
    }

    source_reconstructor::workspace_reconstruction_state_t state;
    source_reconstructor::workspace_reconstruction_config_t config;
    config.workspace = workspace;
    config.project_name = "aida_test_recon";
    config.output_dir = source_recon_output_dir();
    config.include_imports = false;
    config.include_exports = true;
    config.generate_cmake = true;
    config.max_functions = 1;

    log_msg(hf, "srcrecon_lr", "RUN -- reconstruct_workspace bin=%s functions=%zu output=\"%s\" max_functions=%d",
        workspace->identity().bin_name().c_str(),
        snapshot->functions.size(),
        config.output_dir.c_str(),
        config.max_functions);

    source_reconstructor::reconstruct_workspace(config, state);
    if (!source_reconstructor::is_running_workspace(state)) {
        const auto& immediate = source_reconstructor::get_last_result_workspace(state);
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruct_workspace returned without entering running state success=%d error=\"%s\" total_funcs=%d files=%zu",
            immediate.success ? 1 : 0,
            immediate.error.c_str(),
            immediate.total_functions,
            immediate.files_created.size());
        failed.fetch_add(1);
        return;
    }

    const ULONGLONG run_start = GetTickCount64();
    ULONGLONG next_log = run_start + 500;
    bool timed_out = false;
    while (source_reconstructor::is_running_workspace(state)) {
        ULONGLONG now = GetTickCount64();
        if (now >= next_log) {
            log_msg(hf, "srcrecon_lr", "WAIT -- elapsed_ms=%llu progress=%.2f stage=%d status=\"%s\"",
                static_cast<unsigned long long>(now - run_start),
                source_reconstructor::get_progress_workspace(state),
                state.stage.load(std::memory_order_relaxed),
                source_reconstructor::get_status_workspace(state).c_str());
            next_log = now + 500;
        }
        if (now - run_start >= 8000) {
            timed_out = true;
            break;
        }
        Sleep(10);
    }

    if (timed_out) {
        source_reconstructor::cancel_workspace(state);
        const ULONGLONG cancel_start = GetTickCount64();
        while (source_reconstructor::is_running_workspace(state) && GetTickCount64() - cancel_start < 5000)
            Sleep(25);
        const ULONGLONG cancel_elapsed = GetTickCount64() - cancel_start;
        const auto& result = source_reconstructor::get_last_result_workspace(state);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruction timeout cancel_wait_ms=%llu running=%d progress=%.2f stage=%d status=\"%s\" success=%d error=\"%s\" total_funcs=%d decompiled=%d modules=%d files=%zu elapsed=%lld ms",
            static_cast<unsigned long long>(cancel_elapsed),
            source_reconstructor::is_running_workspace(state) ? 1 : 0,
            source_reconstructor::get_progress_workspace(state),
            state.stage.load(std::memory_order_relaxed),
            source_reconstructor::get_status_workspace(state).c_str(),
            result.success ? 1 : 0,
            result.error.c_str(),
            result.total_functions,
            result.decompiled_functions,
            result.modules_created,
            result.files_created.size(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    const auto& result = source_reconstructor::get_last_result_workspace(state);

    size_t existing_files = 0;
    size_t source_files = 0;
    unsigned long long total_bytes = 0;
    bool source_content_ok = false;
    for (const auto& path : result.files_created) {
        unsigned long long file_size = 0;
        if (file_exists_nonempty(path, &file_size)) {
            ++existing_files;
            total_bytes += file_size;
        }
        if (path.size() >= 4 && _stricmp(path.c_str() + path.size() - 4, ".cpp") == 0) {
            ++source_files;
            std::string text;
            if (read_text_file_limited(path, text, 65536) &&
                (text.find("sub_") != std::string::npos ||
                 text.find("void ") != std::string::npos)) {
                source_content_ok = true;
            }
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    const bool ok = result.success && result.total_functions > 0 &&
        !result.files_created.empty() &&
        existing_files == result.files_created.size() && source_files > 0 &&
        source_content_ok;

    if (!ok) {
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruction result bin=%s success=%d error=\"%s\" total_funcs=%d decompiled=%d modules=%d files=%zu existing=%zu source_files=%zu source_content=%d bytes=%llu output=\"%s\" status=\"%s\" (elapsed %lld ms)",
            workspace->identity().bin_name().c_str(),
            result.success ? 1 : 0,
            result.error.c_str(),
            result.total_functions,
            result.decompiled_functions,
            result.modules_created,
            result.files_created.size(),
            existing_files,
            source_files,
            source_content_ok ? 1 : 0,
            total_bytes,
            result.output_dir.c_str(),
            source_reconstructor::get_status_workspace(state).c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "srcrecon_lr", "PASS -- bin=%s success=%d total_funcs=%d decompiled=%d modules=%d files=%zu existing=%zu source_files=%zu bytes=%llu output=\"%s\" (elapsed %lld ms)",
        workspace->identity().bin_name().c_str(),
        result.success ? 1 : 0,
        result.total_functions,
        result.decompiled_functions,
        result.modules_created,
        result.files_created.size(),
        existing_files,
        source_files,
        total_bytes,
        result.output_dir.c_str(),
        (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_engine_scan_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_st", "START -- xref engine scan/cancel state contract");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning_before = xref_engine::is_scanning();
    bool cancel_before = xref_engine::g_state.cancel.load(std::memory_order_acquire);
    float progress_before = xref_engine::g_state.progress.load(std::memory_order_acquire);
    size_t results_before = 0;
    {
        std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
        results_before = xref_engine::g_state.results.size();
    }
    log_msg(hf, "xref_st", "STATE before_cancel target_pid=%u tid=%lu scanning=%d cancel=%d progress=%.3f results=%zu",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        scanning_before ? 1 : 0,
        cancel_before ? 1 : 0,
        static_cast<double>(progress_before),
        results_before);

    xref_engine::cancel_scan();
    bool idle_after_cancel = xref_engine::wait_until_idle(scanning_before ? 250 : 1);

    bool scanning_after = xref_engine::is_scanning();
    bool cancel_after = xref_engine::g_state.cancel.load(std::memory_order_acquire);
    float progress_after = xref_engine::g_state.progress.load(std::memory_order_acquire);
    size_t results_after = 0;
    {
        std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
        results_after = xref_engine::g_state.results.size();
    }

    long long us = elapsed_us_since(t0);
    bool progress_ok = progress_before >= 0.f && progress_before <= 1.f && progress_after >= 0.f && progress_after <= 1.f;
    log_msg(hf, "xref_st", "STATE after_cancel target_pid=%u tid=%lu scanning=%d cancel=%d progress=%.3f results=%zu idle_after_cancel=%d elapsed_us=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        scanning_after ? 1 : 0,
        cancel_after ? 1 : 0,
        static_cast<double>(progress_after),
        results_after,
        idle_after_cancel ? 1 : 0,
        us);
    if (progress_ok && idle_after_cancel && (!scanning_before || !scanning_after)) {
        log_msg(hf, "xref_st", "CONTRACT-PASS -- xref cancel/state invariants verified before(scanning=%d results=%zu) after(scanning=%d results=%zu); no live xref coverage claimed elapsed_us=%lld",
            scanning_before ? 1 : 0,
            results_before,
            scanning_after ? 1 : 0,
            results_after,
            us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xref_st", "FAIL -- invalid xref scan state progress_ok=%d idle_after_cancel=%d scanning_before=%d scanning_after=%d progress_before=%.3f progress_after=%.3f elapsed_us=%lld",
            progress_ok ? 1 : 0,
            idle_after_cancel ? 1 : 0,
            scanning_before ? 1 : 0,
            scanning_after ? 1 : 0,
            static_cast<double>(progress_before),
            static_cast<double>(progress_after),
            us);
        failed.fetch_add(1);
    }
}

static void test_xref_type_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_tn", "START -- xref engine type names");
    auto t0 = std::chrono::steady_clock::now();

    std::string call_name = xref_engine::xref_type_name(xref_engine::xref_type_t::call);
    std::string jmp_name = xref_engine::xref_type_name(xref_engine::xref_type_t::jump);
    std::string jcc_name = xref_engine::xref_type_name(xref_engine::xref_type_t::conditional_jump);
    std::string lea_name = xref_engine::xref_type_name(xref_engine::xref_type_t::lea);
    std::string data_name = xref_engine::xref_type_name(xref_engine::xref_type_t::data_ref);

    bool ok = (call_name == "CALL" && jmp_name == "JMP" && jcc_name == "Jcc" &&
               lea_name == "LEA" && data_name == "DATA");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "xref_tn", "PASS -- all xref type names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xref_tn", "FAIL -- unexpected type names (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_multiply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mul", "START -- expression eval: 0x10 * 0x10");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x10 * 0x10", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x100) {
        log_msg(hf, "expr_mul", "PASS -- 0x10 * 0x10 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mul", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_bitwise(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_bit", "START -- expression eval: 0xFF & 0x0F | 0xF0");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xFF & 0x0F | 0xF0", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFF) {
        log_msg(hf, "expr_bit", "PASS -- 0xFF & 0x0F | 0xF0 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_bit", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_shift(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_shl", "START -- expression eval: 1 << 16");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("1 << 16", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 65536) {
        log_msg(hf, "expr_shl", "PASS -- 1 << 16 = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_shl", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_nested_parens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_par", "START -- expression eval: (10 + 20) * (3 + 7)");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("(10 + 20) * (3 + 7)", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_par", "PASS -- (10+20)*(3+7) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_par", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_xor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_xor", "START -- expression eval: 0xAAAA ^ 0x5555");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xAAAA ^ 0x5555", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFFFF) {
        log_msg(hf, "expr_xor", "PASS -- 0xAAAA ^ 0x5555 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_xor", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_multi_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mreg", "START -- expression eval: rax + rbx * rcx");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 10;
    ctx.rbx = 5;
    ctx.rcx = 3;
    auto result = expression_eval::evaluate("rax + rbx * rcx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 25) {
        log_msg(hf, "expr_mreg", "PASS -- rax(10) + rbx(5)*rcx(3) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mreg", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_fuzzer_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_st", "START -- fuzzer engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool running = fuzzer_engine::g_state.running.load();
    bool cancel = fuzzer_engine::g_state.cancel.load();
    bool minimizing = fuzzer_engine::g_state.minimizing.load();
    bool analyzing_crash = fuzzer_engine::g_state.analyzing_crash.load();
    bool worker_active = fuzzer_engine::g_state.worker_active.load();
    bool setup_complete = fuzzer_engine::g_state.setup_complete.load();
    bool setup_success = fuzzer_engine::g_state.setup_success.load();
    bool active = false;

    uint64_t total_exec = 0;
    uint64_t total_crash = 0;
    uint64_t unique_crash = 0;
    uint64_t new_coverage = 0;
    uint64_t execs_per_second = 0;
    double elapsed_seconds = 0.0;
    uint32_t corpus_size_stat = 0;
    uint32_t edge_coverage = 0;
    size_t corpus_size = 0;
    size_t crashes_size = 0;
    size_t unique_crashes_size = 0;
    size_t rate_history_size = 0;
    std::string setup_error;
    {
        std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
        total_exec = fuzzer_engine::g_state.stats.total_executions;
        total_crash = fuzzer_engine::g_state.stats.total_crashes;
        unique_crash = fuzzer_engine::g_state.stats.total_unique_crashes;
        new_coverage = fuzzer_engine::g_state.stats.new_coverage_finds;
        execs_per_second = fuzzer_engine::g_state.stats.executions_per_second;
        elapsed_seconds = fuzzer_engine::g_state.stats.elapsed_seconds;
        corpus_size_stat = fuzzer_engine::g_state.stats.corpus_size;
        edge_coverage = fuzzer_engine::g_state.stats.edge_coverage;
        corpus_size = fuzzer_engine::g_state.corpus.size();
        crashes_size = static_cast<std::size_t>(fuzzer_engine::g_state.stats.total_crashes);
        unique_crashes_size = fuzzer_engine::g_state.unique_crashes.size();
        rate_history_size = fuzzer_engine::g_state.stats.exec_rate_history.size();
        setup_error = fuzzer_engine::g_state.setup_error;
        active = fuzzer_engine::g_state.active;
    }

    long long us = elapsed_us_since(t0);
    bool counters_ok = total_crash <= total_exec && unique_crash <= total_crash && crashes_size >= unique_crashes_size;
    bool lifecycle_ok = running || !worker_active || setup_complete || !setup_error.empty();
    log_msg(hf, "fuzz_st", "STATE target_pid=%u tid=%lu running=%d cancel=%d minimizing=%d analyzing=%d worker_active=%d setup_complete=%d setup_success=%d active=%d execs=%llu crashes=%llu unique=%llu new_cov=%llu eps=%llu elapsed_s=%.3f corpus_stat=%u corpus_size=%zu crashes_size=%zu unique_size=%zu edge_cov=%u rate_history=%zu setup_error_len=%zu setup_error=\"%s\" elapsed_us=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        running ? 1 : 0,
        cancel ? 1 : 0,
        minimizing ? 1 : 0,
        analyzing_crash ? 1 : 0,
        worker_active ? 1 : 0,
        setup_complete ? 1 : 0,
        setup_success ? 1 : 0,
        active ? 1 : 0,
        (unsigned long long)total_exec,
        (unsigned long long)total_crash,
        (unsigned long long)unique_crash,
        (unsigned long long)new_coverage,
        (unsigned long long)execs_per_second,
        elapsed_seconds,
        corpus_size_stat,
        corpus_size,
        crashes_size,
        unique_crashes_size,
        edge_coverage,
        rate_history_size,
        setup_error.size(),
        setup_error.c_str(),
        us);
    if (counters_ok && lifecycle_ok) {
        log_msg(hf, "fuzz_st", "CONTRACT-PASS -- fuzzer idle/state counters and lifecycle flags are coherent; no live fuzz run claimed elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "fuzz_st", "FAIL -- fuzzer state incoherent counters_ok=%d lifecycle_ok=%d execs=%llu crashes=%llu unique=%llu worker_active=%d setup_complete=%d setup_error_len=%zu elapsed_us=%lld",
            counters_ok ? 1 : 0,
            lifecycle_ok ? 1 : 0,
            (unsigned long long)total_exec,
            (unsigned long long)total_crash,
            (unsigned long long)unique_crash,
            worker_active ? 1 : 0,
            setup_complete ? 1 : 0,
            setup_error.size(),
            us);
        failed.fetch_add(1);
    }
}

static void test_fuzzer_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_cfg", "START -- fuzzer engine config defaults");
    auto t0 = std::chrono::steady_clock::now();

    fuzzer_engine::fuzz_config_t cfg;
    bool strategies_ok = cfg.strategies[0] && cfg.strategies[1] && cfg.strategies[2] &&
                         cfg.strategies[3] && cfg.strategies[4] && !cfg.strategies[5];
    bool ok = (cfg.max_instructions == 100000 &&
               cfg.timeout_ms == 5000 &&
               cfg.max_iterations == 100000 &&
               cfg.input_size == 256 &&
               cfg.mutation_count == 4 &&
               strategies_ok &&
               cfg.target_address == 0 &&
               cfg.end_address == 0 &&
               cfg.pid == 0 &&
               cfg.tid == 0 &&
               cfg.input_address == 0);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "fuzz_cfg", "CONFIG max_instructions=%u timeout_ms=%u max_iterations=%u input_size=%d mutation_count=%d strategies=[%d,%d,%d,%d,%d,%d] target=0x%llX end=0x%llX pid=%u tid=%u input=0x%llX expected={100000,5000,100000,256,4,[1,1,1,1,1,0],zero-targets} elapsed_us=%lld",
        cfg.max_instructions,
        cfg.timeout_ms,
        cfg.max_iterations,
        cfg.input_size,
        cfg.mutation_count,
        cfg.strategies[0] ? 1 : 0,
        cfg.strategies[1] ? 1 : 0,
        cfg.strategies[2] ? 1 : 0,
        cfg.strategies[3] ? 1 : 0,
        cfg.strategies[4] ? 1 : 0,
        cfg.strategies[5] ? 1 : 0,
        (unsigned long long)cfg.target_address,
        (unsigned long long)cfg.end_address,
        cfg.pid,
        cfg.tid,
        (unsigned long long)cfg.input_address,
        us);
    if (ok) {
        log_msg(hf, "fuzz_cfg", "PASS -- config defaults and strategy bitmap match expected elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "fuzz_cfg", "FAIL -- unexpected config defaults strategies_ok=%d elapsed_us=%lld", strategies_ok ? 1 : 0, us);
        failed.fetch_add(1);
    }
}

static void test_stealth_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_st", "START -- stealth engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool active = stealth_engine::g_state.active.load();
    uint32_t attached_pid = driver_bridge::attached_pid();
    bool active_for_attached = attached_pid != 0 && stealth_engine::is_active_for_pid(attached_pid);
    auto session = stealth_engine::get_session_info();
    std::string status = stealth_engine::get_status();
    size_t hook_count = session.hooks.size();
    size_t alloc_count = session.allocated_regions.size();
    bool session_coherent = !active || (session.pid != 0 && !status.empty());
    bool attached_coherent = attached_pid == 0 || !active || active_for_attached;

    long long us = elapsed_us_since(t0);
    log_msg(hf, "stealth_st", "STATE target_pid=%u tid=%lu active=%d attached_pid=%u active_for_attached=%d session_pid=%u peb=%d context=%d rdtsc=%d hooks=%zu allocs=%zu status_len=%zu status=\"%s\" elapsed_us=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        active ? 1 : 0,
        attached_pid,
        active_for_attached ? 1 : 0,
        session.pid,
        session.peb_spoofed ? 1 : 0,
        session.context_hooked ? 1 : 0,
        session.rdtsc_hooked ? 1 : 0,
        hook_count,
        alloc_count,
        status.size(),
        status.c_str(),
        us);
    if (session_coherent && attached_coherent) {
        log_msg(hf, "stealth_st", "CONTRACT-PASS -- stealth idle/session state coherent active=%d session_pid=%u attached_pid=%u elapsed_us=%lld",
            active ? 1 : 0, session.pid, attached_pid, us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "stealth_st", "FAIL -- incoherent stealth state session_coherent=%d attached_coherent=%d attached_pid=%u active=%d session_pid=%u status=\"%s\" elapsed_us=%lld",
            session_coherent ? 1 : 0,
            attached_coherent ? 1 : 0,
            attached_pid,
            active ? 1 : 0,
            session.pid,
            status.c_str(),
            us);
        failed.fetch_add(1);
    }
}

static void test_stealth_options_default(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_op", "START -- stealth engine default options");
    auto t0 = std::chrono::steady_clock::now();

    stealth_engine::stealth_options_t opts;
    bool ok = (opts.spoof_peb == true && opts.hook_rdtsc == true && opts.scrub_context == false);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "stealth_op", "CONFIG spoof_peb=%d hook_rdtsc=%d scrub_context=%d expected={1,1,0} elapsed_us=%lld",
        opts.spoof_peb ? 1 : 0,
        opts.hook_rdtsc ? 1 : 0,
        opts.scrub_context ? 1 : 0,
        us);
    if (ok) {
        log_msg(hf, "stealth_op", "PASS -- default options match expected strict stealth posture elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "stealth_op", "FAIL -- unexpected defaults spoof_peb=%d hook_rdtsc=%d scrub_context=%d elapsed_us=%lld",
            opts.spoof_peb ? 1 : 0,
            opts.hook_rdtsc ? 1 : 0,
            opts.scrub_context ? 1 : 0,
            us);
        failed.fetch_add(1);
    }
}

static void test_struct_recon_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_st", "START -- struct recon state check");
    auto t0 = std::chrono::steady_clock::now();

    bool monitoring = struct_recon::g_state.monitoring.load();
    bool cancel = struct_recon::g_state.cancel.load();
    bool ai_naming = struct_recon::g_state.ai_naming.load();
    float progress = struct_recon::g_state.progress.load();
    bool active = false;
    size_t field_count = 0;
    size_t access_count = 0;
    size_t history_count = 0;
    size_t saved_count = 0;
    bool disk_cache_loaded = false;
    {
        std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
        active = struct_recon::g_state.active;
        field_count = struct_recon::g_state.current.fields.size();
        access_count = struct_recon::g_state.access_log.size();
        history_count = struct_recon::g_state.history.size();
        saved_count = struct_recon::g_state.saved_structs.size();
        disk_cache_loaded = struct_recon::g_state.disk_cache_loaded;
    }

    long long us = elapsed_us_since(t0);
    bool progress_ok = progress >= 0.f && progress <= 1.f;
    log_msg(hf, "strecon_st", "STATE target_pid=%u tid=%lu monitoring=%d cancel=%d ai_naming=%d active=%d progress=%.3f fields=%zu accesses=%zu history=%zu saved=%zu disk_cache=%d elapsed_us=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        monitoring ? 1 : 0,
        cancel ? 1 : 0,
        ai_naming ? 1 : 0,
        active ? 1 : 0,
        static_cast<double>(progress),
        field_count,
        access_count,
        history_count,
        saved_count,
        disk_cache_loaded ? 1 : 0,
        us);
    if (progress_ok) {
        log_msg(hf, "strecon_st", "CONTRACT-PASS -- struct recon idle/state progress and snapshots are coherent; no live monitor claimed elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "strecon_st", "FAIL -- progress out of range progress=%.3f elapsed_us=%lld", static_cast<double>(progress), us);
        failed.fetch_add(1);
    }
}

static void test_struct_recon_field_types(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_ft", "START -- struct recon field type enum range");
    auto t0 = std::chrono::steady_clock::now();

    int count_val = static_cast<int>(struct_recon::field_type_t::COUNT);
    bool ok = (count_val > 20 &&
               static_cast<int>(struct_recon::field_type_t::unknown) == 0 &&
               static_cast<int>(struct_recon::field_type_t::pointer) == 11 &&
               static_cast<int>(struct_recon::field_type_t::vtable_ptr) == 12 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::pointer), "void*") == 0 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::vtable_ptr), "vtable*") == 0);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "strecon_ft", "TYPES count=%d unknown=%d pointer=%d pointer_name=%s vtable=%d vtable_name=%s utf8_name=%s bool_name=%s expected_count_gt=20 elapsed_us=%lld",
        count_val,
        static_cast<int>(struct_recon::field_type_t::unknown),
        static_cast<int>(struct_recon::field_type_t::pointer),
        struct_recon::field_type_name(struct_recon::field_type_t::pointer),
        static_cast<int>(struct_recon::field_type_t::vtable_ptr),
        struct_recon::field_type_name(struct_recon::field_type_t::vtable_ptr),
        struct_recon::field_type_name(struct_recon::field_type_t::utf8_string),
        struct_recon::field_type_name(struct_recon::field_type_t::bool8),
        us);
    if (ok) {
        log_msg(hf, "strecon_ft", "PASS -- field_type_t ordinals and names verified count=%d elapsed_us=%lld", count_val, us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "strecon_ft", "FAIL -- unexpected field_type_t layout count=%d elapsed_us=%lld", count_val, us);
        failed.fetch_add(1);
    }
}

static void test_decrypt_oracle_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_st", "START -- decrypt oracle state check");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning = decrypt_oracle::g_state.scanning.load();
    bool cancel = decrypt_oracle::g_state.cancel.load();
    bool timed_out = decrypt_oracle::g_state.timed_out.load();
    float progress = decrypt_oracle::g_state.progress.load();
    int total_xrefs = decrypt_oracle::g_state.total_xrefs.load();
    int processed_xrefs = decrypt_oracle::g_state.processed_xrefs.load();
    size_t result_count = 0;
    std::string status;
    {
        std::lock_guard<std::mutex> lk(decrypt_oracle::g_state.mutex);
        result_count = decrypt_oracle::g_state.results.size();
        status = decrypt_oracle::g_state.status_text;
    }

    long long us = elapsed_us_since(t0);
    bool progress_ok = progress >= 0.f && progress <= 1.f;
    bool counts_ok = total_xrefs >= 0 && processed_xrefs >= 0 && (total_xrefs == 0 || processed_xrefs <= total_xrefs);
    log_msg(hf, "decr_st", "STATE target_pid=%u tid=%lu scanning=%d cancel=%d timed_out=%d progress=%.3f total_xrefs=%d processed=%d results=%zu status_len=%zu status=\"%s\" elapsed_us=%lld",
        driver_bridge::attached_pid(),
        GetCurrentThreadId(),
        scanning ? 1 : 0,
        cancel ? 1 : 0,
        timed_out ? 1 : 0,
        static_cast<double>(progress),
        total_xrefs,
        processed_xrefs,
        result_count,
        status.size(),
        status.c_str(),
        us);
    if (progress_ok && counts_ok) {
        log_msg(hf, "decr_st", "CONTRACT-PASS -- decrypt oracle idle/state progress and counters are coherent; no live oracle scan claimed elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "decr_st", "FAIL -- invalid decrypt oracle state progress_ok=%d counts_ok=%d progress=%.3f total=%d processed=%d elapsed_us=%lld",
            progress_ok ? 1 : 0,
            counts_ok ? 1 : 0,
            static_cast<double>(progress),
            total_xrefs,
            processed_xrefs,
            us);
        failed.fetch_add(1);
    }
}

static void test_decrypt_oracle_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_cfg", "START -- decrypt oracle config defaults");
    auto t0 = std::chrono::steady_clock::now();

    decrypt_oracle::scan_config_t cfg;
    bool ok = (cfg.max_instructions == 50000 &&
               cfg.timeout_ms == 5000 &&
               cfg.min_string_length == 4 &&
               cfg.min_printable_ratio == 0.75f &&
               cfg.region_address == 0 &&
               cfg.region_size == 0);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "decr_cfg", "CONFIG region=0x%llX size=0x%llX max_instructions=%u timeout_ms=%u min_string_length=%d printable_ratio=%.3f expected={0,0,50000,5000,4,0.750} elapsed_us=%lld",
        (unsigned long long)cfg.region_address,
        (unsigned long long)cfg.region_size,
        cfg.max_instructions,
        cfg.timeout_ms,
        cfg.min_string_length,
        static_cast<double>(cfg.min_printable_ratio),
        us);
    if (ok) {
        log_msg(hf, "decr_cfg", "PASS -- config defaults match expected decrypt-oracle scan limits elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "decr_cfg", "FAIL -- unexpected config defaults elapsed_us=%lld", us);
        failed.fetch_add(1);
    }
}

static void test_pdb_resolve_cache_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "pdb_cache", "START -- pdb downloader resolve_cache_path dummy cache fixture");
    auto t0 = std::chrono::steady_clock::now();

    pdb_downloader::download_request_t req;
    req.pdb_name = "aida_dummy.pdb";
    req.pdb_guid = "11111111222233334444555555555555";
    req.pdb_age = 2;

    char tmp[MAX_PATH + 1] = {};
    DWORD tmp_len = GetTempPathA(MAX_PATH, tmp);
    std::filesystem::path cache_root = (tmp_len > 0 && tmp_len < MAX_PATH)
        ? std::filesystem::path(std::string(tmp, tmp_len))
        : std::filesystem::current_path();
    cache_root /= "AiDA_TestLab";
    cache_root /= "pdb_cache_dummy";
    cache_root /= std::to_string(GetCurrentProcessId());
    cache_root /= std::to_string(GetCurrentThreadId());
    req.cache_root = cache_root.string();

    char age_buf[16];
    std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(req.pdb_age));
    std::filesystem::path expected_path = cache_root / req.pdb_name / (req.pdb_guid + std::string(age_buf)) / req.pdb_name;
    std::error_code ec;
    bool dirs_ok = std::filesystem::create_directories(expected_path.parent_path(), ec) || std::filesystem::exists(expected_path.parent_path(), ec);
    const char marker[] = "AIDA_PDB_CACHE_DUMMY_V1";
    bool write_ok = false;
    if (dirs_ok) {
        std::ofstream ofs(expected_path, std::ios::binary | std::ios::trunc);
        ofs.write(marker, static_cast<std::streamsize>(sizeof(marker) - 1));
        write_ok = ofs.good();
    }
    ec.clear();
    std::uintmax_t expected_size = std::filesystem::exists(expected_path, ec) ? std::filesystem::file_size(expected_path, ec) : 0;

    std::string out_path;
    bool resolved = pdb_downloader::resolve_cache_path(req, out_path);
    ec.clear();
    std::filesystem::path resolved_path(out_path);
    std::uintmax_t resolved_size = resolved && std::filesystem::exists(resolved_path, ec) ? std::filesystem::file_size(resolved_path, ec) : 0;
    std::string expected_string = expected_path.string();
    bool path_match = resolved && _stricmp(out_path.c_str(), expected_string.c_str()) == 0;
    bool size_match = expected_size == sizeof(marker) - 1 && resolved_size == expected_size;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "pdb_cache", "RESULT coverage=dummy_cache_fixture root=\"%s\" expected=\"%s\" resolved=%d path=\"%s\" dirs_ok=%d write_ok=%d expected_size=%llu resolved_size=%llu path_match=%d size_match=%d elapsed_ms=%lld",
        req.cache_root.c_str(),
        expected_string.c_str(),
        resolved ? 1 : 0,
        out_path.c_str(),
        dirs_ok ? 1 : 0,
        write_ok ? 1 : 0,
        static_cast<unsigned long long>(expected_size),
        static_cast<unsigned long long>(resolved_size),
        path_match ? 1 : 0,
        size_match ? 1 : 0,
        (long long)ms);
    std::filesystem::remove_all(cache_root, ec);
    if (dirs_ok && write_ok && resolved && path_match && size_match) {
        log_msg(hf, "pdb_cache", "FIXTURE-PASS -- resolve_cache_path found dummy cache file with exact path and size bytes=%llu elapsed_ms=%lld",
            static_cast<unsigned long long>(resolved_size), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "pdb_cache", "FAIL -- dummy cache resolve evidence insufficient dirs_ok=%d write_ok=%d resolved=%d path_match=%d size_match=%d expected_size=%llu resolved_size=%llu elapsed_ms=%lld",
            dirs_ok ? 1 : 0,
            write_ok ? 1 : 0,
            resolved ? 1 : 0,
            path_match ? 1 : 0,
            size_match ? 1 : 0,
            static_cast<unsigned long long>(expected_size),
            static_cast<unsigned long long>(resolved_size),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_analysis_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                     const char* tag, analysis_hub_view::sub_tab_t value) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t before = analysis_hub_view::active_sub_tab();
    const char* before_label = analysis_hub_view::sub_tab_label(before);
    const char* target_label = analysis_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
        static_cast<int>(before),
        before_label,
        static_cast<int>(value),
        target_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(value);
    analysis_hub_view::sub_tab_t got = analysis_hub_view::active_sub_tab();
    const char* label = analysis_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(got),
        analysis_hub_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && label[0] != '\0') {
        log_msg(hf, tag, "PASS -- analysis_hub sub_tab selected and read back (%d label=%s)",
            static_cast<int>(value), label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- analysis_hub sub_tab set %d but read back %d label=\"%s\"",
            static_cast<int>(value), static_cast<int>(got), label);
        failed.fetch_add(1);
    }
}

static void select_symbolic_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                      const char* tag, int value, const char* expected_label) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t parent_before = analysis_hub_view::active_sub_tab();
    int before = symbolic_view::active_tab();
    log_msg(hf, tag, "STATE -- parent_before=%d parent_label=%s inner_before=%d inner_label=%s target=%d expected_label=%s tid=%lu",
        static_cast<int>(parent_before),
        analysis_hub_view::sub_tab_label(parent_before),
        before,
        symbolic_view::tab_label(before),
        value,
        expected_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::symbolic);
    symbolic_view::set_active_tab(value);
    int got = symbolic_view::active_tab();
    const char* label = symbolic_view::tab_label(value);
    log_msg(hf, tag, "STATE -- parent_after=%d parent_label=%s inner_after=%d readback_label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(analysis_hub_view::active_sub_tab()),
        analysis_hub_view::sub_tab_label(analysis_hub_view::active_sub_tab()),
        got,
        symbolic_view::tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- symbolic inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- symbolic inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void select_protection_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                        const char* tag, int value, const char* expected_label) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t parent_before = analysis_hub_view::active_sub_tab();
    int before = stealth_view::active_sub_tab();
    log_msg(hf, tag, "STATE -- parent_before=%d parent_label=%s inner_before=%d inner_label=%s target=%d expected_label=%s tid=%lu",
        static_cast<int>(parent_before),
        analysis_hub_view::sub_tab_label(parent_before),
        before,
        stealth_view::sub_tab_label(before),
        value,
        expected_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::stealth);
    stealth_view::set_sub_tab(value);
    int got = stealth_view::active_sub_tab();
    const char* label = stealth_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- parent_after=%d parent_label=%s inner_after=%d readback_label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(analysis_hub_view::active_sub_tab()),
        analysis_hub_view::sub_tab_label(analysis_hub_view::active_sub_tab()),
        got,
        stealth_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- protection inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- protection inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void test_analysis_hub_tab_symbolic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.symbolic", analysis_hub_view::sub_tab_t::symbolic);
}
static void test_analysis_hub_tab_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.taint", analysis_hub_view::sub_tab_t::taint);
}
static void test_analysis_hub_tab_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.deobfuscation", analysis_hub_view::sub_tab_t::deobfuscation);
}
static void test_analysis_hub_tab_fuzzer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.fuzzer", analysis_hub_view::sub_tab_t::fuzzer);
}
static void test_analysis_hub_tab_protection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.protection", analysis_hub_view::sub_tab_t::stealth);
}

static void select_types_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                 const char* tag, types_hub_view::sub_tab_t value) {
    auto t0 = std::chrono::steady_clock::now();
    types_hub_view::sub_tab_t before = types_hub_view::active_sub_tab();
    const char* before_label = types_hub_view::sub_tab_label(before);
    const char* target_label = types_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
        static_cast<int>(before),
        before_label,
        static_cast<int>(value),
        target_label,
        (unsigned long)GetCurrentThreadId());
    types_hub_view::set_sub_tab(value);
    types_hub_view::sub_tab_t got = types_hub_view::active_sub_tab();
    const char* label = types_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(got),
        types_hub_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && label[0] != '\0') {
        log_msg(hf, tag, "PASS -- types_hub sub_tab selected and read back (%d label=%s)",
            static_cast<int>(value), label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- types_hub sub_tab set %d but read back %d label=\"%s\"",
            static_cast<int>(value), static_cast<int>(got), label);
        failed.fetch_add(1);
    }
}

static void test_types_hub_tab_structs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.structs", types_hub_view::sub_tab_t::structs);
}
static void test_types_hub_tab_unions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.unions", types_hub_view::sub_tab_t::unions);
}
static void test_types_hub_tab_enums(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.enums", types_hub_view::sub_tab_t::enums);
}
static void test_types_hub_tab_typedefs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.typedefs", types_hub_view::sub_tab_t::typedefs);
}
static void test_types_hub_tab_functions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.functions", types_hub_view::sub_tab_t::functions);
}
static void test_types_hub_tab_inferred(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.inferred", types_hub_view::sub_tab_t::inferred);
}
static void test_types_hub_tab_dissector(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.dissector", types_hub_view::sub_tab_t::dissector);
}

static void test_symbolic_inner_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.trace", 0, "Trace");
}
static void test_symbolic_inner_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.deobfuscation", 1, "Deobfuscation");
}
static void test_symbolic_inner_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.slice", 2, "Slice");
}
static void test_symbolic_inner_solver(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.solver", 3, "Solver");
}
static void test_symbolic_inner_constraints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.constraints", 4, "Constraints");
}
static void test_symbolic_inner_expression(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.expression", 5, "Expression");
}

static void test_protection_inner_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.scan", 0, "Protection Scan");
}
static void test_protection_inner_controls(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.controls", 1, "Stealth Status");
}

static aida::analysis::semantic_scope_key_t quality_semantic_scope() {
    aida::analysis::semantic_scope_key_t scope;
    scope.function_address.space = aida::analysis::address_space_id_t::relative_virtual;
    scope.function_address.value = 0x1400;
    scope.function_address.architecture = aida::analysis::architecture_id_t::x86_64;
    scope.function_address.mode = aida::analysis::architecture_mode_t::x86_64;
    scope.architecture = scope.function_address.architecture;
    scope.architecture_mode = scope.function_address.mode;
    scope.abi = aida::analysis::abi_id_t::windows_x64;
    scope.generation = 17;
    scope.analysis_revision = 23;
    scope.overlay_revision = 29;
    return scope;
}

static aida::analysis::semantic_evidence_t quality_constant_evidence(
    const aida::analysis::semantic_scope_key_t& scope, std::uint64_t evidence_id) {
    aida::analysis::semantic_evidence_t evidence;
    evidence.evidence_id = evidence_id;
    evidence.kind = aida::analysis::semantic_fact_kind_t::value;
    evidence.subject.kind = aida::analysis::semantic_subject_kind_t::function;
    evidence.subject.function_id = 7;
    evidence.subject.address = scope.function_address;
    aida::analysis::constant_value_t value;
    value.kind = aida::analysis::semantic_value_kind_t::constant;
    value.value = 0x41;
    value.bit_width = 32;
    value.known = true;
    evidence.payload = value;
    evidence.provenance.origin = aida::analysis::semantic_origin_t::decompiler_type_recovery;
    evidence.provenance.source = aida::analysis::fact_provenance_t::decompiler_feedback;
    evidence.provenance.source_entity_id = evidence_id;
    evidence.provenance.source_address = scope.function_address;
    evidence.provenance.stable_source_id = evidence_id;
    evidence.provenance.source_generation = scope.generation;
    evidence.provenance.source_analysis_revision = scope.analysis_revision;
    evidence.provenance.source_overlay_revision = scope.overlay_revision;
    evidence.provenance.independently_validated = true;
    evidence.validation = aida::analysis::semantic_validation_t::validated;
    evidence.confidence = 100;
    return evidence;
}

static void test_semantic_fusion_bounded_deterministic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_sem", "START -- bounded semantic evidence reduction and deterministic ordering");
    const auto scope = quality_semantic_scope();
    aida::analysis::semantic_merge_budget_t budget;
    budget.max_evidence_records = 8;
    budget.max_evidence_per_subject = 2;
    budget.max_fused_facts = 8;
    budget.max_conflicts = 8;
    budget.max_abstentions = 8;
    budget.max_provenance_per_fact = 8;
    budget.cancellation_poll_interval = 1;
    std::vector<aida::analysis::semantic_evidence_t> evidence;
    evidence.push_back(quality_constant_evidence(scope, 31));
    evidence.push_back(quality_constant_evidence(scope, 11));
    evidence.push_back(quality_constant_evidence(scope, 23));
    const auto forward = aida::analysis::reduce_semantic_evidence(scope, evidence, budget);
    std::reverse(evidence.begin(), evidence.end());
    const auto reversed = aida::analysis::reduce_semantic_evidence(scope, evidence, budget);
    const bool bounded = forward && reversed && forward.value().bounded && reversed.value().bounded &&
        forward.value().evidence_dropped == 1 && reversed.value().evidence_dropped == 1 &&
        forward.value().facts.size() == 1 && reversed.value().facts.size() == 1 &&
        forward.value().facts.front().contributing_evidence_ids.size() == 2 &&
        forward.value().facts.front().contributing_evidence_ids ==
            reversed.value().facts.front().contributing_evidence_ids &&
        forward.value().cache_key.evidence_fingerprint == reversed.value().cache_key.evidence_fingerprint;
    if (!bounded) {
        log_msg(hf, "quality_sem", "FAIL -- bounded=%d/%d dropped=%llu/%llu facts=%zu/%zu contributors=%zu/%zu fingerprint=%llu/%llu",
            forward && forward.value().bounded ? 1 : 0,
            reversed && reversed.value().bounded ? 1 : 0,
            (unsigned long long)(forward ? forward.value().evidence_dropped : 0),
            (unsigned long long)(reversed ? reversed.value().evidence_dropped : 0),
            forward ? forward.value().facts.size() : 0,
            reversed ? reversed.value().facts.size() : 0,
            forward && !forward.value().facts.empty() ? forward.value().facts.front().contributing_evidence_ids.size() : 0,
            reversed && !reversed.value().facts.empty() ? reversed.value().facts.front().contributing_evidence_ids.size() : 0,
            (unsigned long long)(forward ? forward.value().cache_key.evidence_fingerprint : 0),
            (unsigned long long)(reversed ? reversed.value().cache_key.evidence_fingerprint : 0));
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_sem", "PASS -- bounded propagation dropped=%llu contributors=%zu deterministic_fingerprint=%llu",
        (unsigned long long)forward.value().evidence_dropped,
        forward.value().facts.front().contributing_evidence_ids.size(),
        (unsigned long long)forward.value().cache_key.evidence_fingerprint);
    passed.fetch_add(1);
}

static void test_semantic_fusion_cancellation_deadline(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_cancel", "START -- semantic fusion cancellation and deadline propagation");
    const auto scope = quality_semantic_scope();
    aida::analysis::semantic_merge_budget_t budget;
    budget.cancellation_poll_interval = 1;
    budget.max_abstentions = 4;
    std::vector<aida::analysis::semantic_evidence_t> evidence;
    evidence.push_back(quality_constant_evidence(scope, 41));
    aida::analysis::cancellation_source_t cancelled;
    cancelled.request_cancel();
    const auto cancelled_result = aida::analysis::reduce_semantic_evidence(
        scope, evidence, budget, {}, cancelled.token());
    aida::analysis::cancellation_source_t expired{
        std::optional<std::chrono::steady_clock::time_point>(
            std::chrono::steady_clock::now() - std::chrono::milliseconds(1))};
    const auto deadline_result = aida::analysis::reduce_semantic_evidence(
        scope, evidence, budget, {}, expired.token());
    const bool cancellation_observed = cancelled_result && cancelled_result.value().cancelled &&
        !cancelled_result.value().deadline_exceeded && !cancelled_result.value().abstentions.empty() &&
        cancelled_result.value().abstentions.front().reason ==
            aida::analysis::semantic_abstention_reason_t::cancellation_requested;
    const bool deadline_observed = deadline_result && deadline_result.value().cancelled &&
        deadline_result.value().deadline_exceeded && !deadline_result.value().abstentions.empty() &&
        deadline_result.value().abstentions.front().reason ==
            aida::analysis::semantic_abstention_reason_t::deadline_exceeded;
    if (!cancellation_observed || !deadline_observed) {
        log_msg(hf, "quality_cancel", "FAIL -- cancelled_ok=%d deadline_ok=%d cancelled_flags=%d/%d deadline_flags=%d/%d",
            cancellation_observed ? 1 : 0, deadline_observed ? 1 : 0,
            cancelled_result && cancelled_result.value().cancelled ? 1 : 0,
            deadline_result && deadline_result.value().cancelled ? 1 : 0,
            cancelled_result && cancelled_result.value().deadline_exceeded ? 1 : 0,
            deadline_result && deadline_result.value().deadline_exceeded ? 1 : 0);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_cancel", "PASS -- cancellation and expired deadline produced distinct abstentions");
    passed.fetch_add(1);
}

static void test_decompiler_feedback_range_publication(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_feedback", "START -- range-validated decompiler feedback publication");
    aida::analysis::decompiler_feedback_model_t model;
    aida::analysis::decompiler_feedback_scope_key_t scope;
    scope.workspace_id = "testlab-quality";
    scope.binary_id = "quality-binary";
    scope.address_space_id = "relative-virtual";
    scope.architecture_id = "x86-64";
    scope.generation = 3;
    scope.overlay_revision = 5;
    scope.type_revision = 7;
    aida::analysis::decompiler_feedback_fact_t valid;
    valid.fact_id = "quality-valid-name";
    valid.logical_key = "name:0x401004";
    valid.publisher_id = "testlab-quality";
    valid.kind = aida::analysis::decompiler_feedback_fact_kind_t::name;
    valid.authority = aida::analysis::decompiler_feedback_authority_t::trusted_recovery;
    valid.validation.grade = aida::analysis::decompiler_feedback_validation_grade_t::proven;
    valid.validation.validator_id = "quality-validator";
    valid.validation.evidence_id = "quality-evidence";
    valid.validation.evidence_revision = 11;
    valid.source_revision = 13;
    valid.affected_range = {0x401000, 0x20};
    valid.payload = aida::analysis::decompiler_feedback_name_t{0x401004, "quality_name"};
    auto invalid = valid;
    invalid.fact_id = "quality-invalid-range";
    invalid.logical_key = "name:0x402000";
    invalid.affected_range = {0x402000, 0};
    invalid.payload = aida::analysis::decompiler_feedback_name_t{0x402000, "invalid_name"};
    aida::analysis::decompiler_feedback_publication_request_t request;
    request.scope = scope;
    request.facts = {invalid, valid};
    const auto result = model.publish(request);
    const auto snapshot = model.snapshot(scope);
    const bool range_rejected = result.rejections.size() == 1 &&
        result.rejections.front().fact_id == invalid.fact_id &&
        result.rejections.front().code == "invalid_affected_range";
    const bool published = result.status == aida::analysis::decompiler_feedback_publication_status_t::published &&
        result.accepted_fact_ids.size() == 1 && result.accepted_fact_ids.front() == valid.fact_id &&
        result.affected_ranges.bounded && result.affected_ranges.ranges.size() == 1 &&
        result.cache_invalidations.bounded && !result.cache_invalidations.keys.empty() &&
        snapshot.exists && snapshot.facts.size() == 1 && snapshot.facts.front().fact_id == valid.fact_id;
    if (!range_rejected || !published) {
        log_msg(hf, "quality_feedback", "FAIL -- status=%d accepted=%zu rejected=%zu range_bounded=%d ranges=%zu cache_bounded=%d cache_keys=%zu snapshot=%d/%zu",
            static_cast<int>(result.status), result.accepted_fact_ids.size(), result.rejections.size(),
            result.affected_ranges.bounded ? 1 : 0, result.affected_ranges.ranges.size(),
            result.cache_invalidations.bounded ? 1 : 0, result.cache_invalidations.keys.size(),
            snapshot.exists ? 1 : 0, snapshot.facts.size());
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_feedback", "PASS -- published proven in-range feedback and rejected zero-length range");
    passed.fetch_add(1);
}

static void test_pseudocode_typed_ast_rendering(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_pseudo", "START -- typed AST pseudocode rendering and deterministic node ordering");
    aida::analysis::pseudocode_type_t unsigned32;
    unsigned32.kind = aida::analysis::pseudocode_type_kind_t::unsigned_integer;
    unsigned32.spelling = "uint32_t";
    unsigned32.bit_width = 32;
    aida::analysis::typed_pseudocode_variable_t parameter;
    parameter.id = 1;
    parameter.source_name = "input_value";
    parameter.role = aida::analysis::pseudocode_variable_role_t::parameter;
    parameter.type = unsigned32;
    aida::analysis::typed_pseudocode_node_t function;
    function.id = 1;
    function.kind = aida::analysis::pseudocode_node_kind_t::function;
    function.type = unsigned32;
    aida::analysis::pseudocode_function_t function_payload;
    function_payload.name = "quality_identity";
    function_payload.return_type = unsigned32;
    function_payload.parameters = {parameter.id};
    function_payload.body = 2;
    function.payload = function_payload;
    aida::analysis::typed_pseudocode_node_t block;
    block.id = 2;
    block.kind = aida::analysis::pseudocode_node_kind_t::block;
    block.payload = aida::analysis::pseudocode_block_t{{3}};
    aida::analysis::typed_pseudocode_node_t returned;
    returned.id = 3;
    returned.kind = aida::analysis::pseudocode_node_kind_t::return_statement;
    returned.type = unsigned32;
    returned.payload = aida::analysis::pseudocode_return_statement_t{4};
    aida::analysis::typed_pseudocode_node_t identifier;
    identifier.id = 4;
    identifier.kind = aida::analysis::pseudocode_node_kind_t::identifier_expression;
    identifier.type = unsigned32;
    identifier.payload = aida::analysis::pseudocode_identifier_expression_t{parameter.id};
    aida::analysis::typed_pseudocode_ast_t ast;
    ast.root = function.id;
    ast.nodes = {function, block, returned, identifier};
    ast.variables = {parameter};
    ast.revision = 17;
    aida::analysis::pseudocode_render_request_t request;
    request.cache_key_material.workspace_identity = "testlab-quality";
    request.cache_key_material.workspace_generation = 3;
    request.cache_key_material.overlay_revision = 5;
    request.cache_key_material.type_revision = 7;
    request.cache_key_material.function_address = 0x401000;
    request.cache_key_material.ast_revision = ast.revision;
    request.cache_key_material.service_revision = "quality";
    const auto rendered = aida::analysis::render_typed_pseudocode(ast, request);
    auto reordered = ast;
    std::reverse(reordered.nodes.begin(), reordered.nodes.end());
    const auto rendered_reordered = aida::analysis::render_typed_pseudocode(reordered, request);
    const bool output_ok = rendered.succeeded() && rendered_reordered.succeeded() &&
        rendered.output->text.find("uint32_t") != std::string::npos &&
        rendered.output->text.find("quality_identity") != std::string::npos &&
        rendered.output->text.find("return input_value;") != std::string::npos &&
        rendered.output->variable_decisions.size() == 1 &&
        rendered.output->text == rendered_reordered.output->text &&
        rendered.output->cache_key == rendered_reordered.output->cache_key;
    if (!output_ok) {
        log_msg(hf, "quality_pseudo", "FAIL -- rendered=%d reordered=%d text_bytes=%zu/%zu variables=%zu/%zu",
            rendered.succeeded() ? 1 : 0, rendered_reordered.succeeded() ? 1 : 0,
            rendered.output ? rendered.output->text.size() : 0,
            rendered_reordered.output ? rendered_reordered.output->text.size() : 0,
            rendered.output ? rendered.output->variable_decisions.size() : 0,
            rendered_reordered.output ? rendered_reordered.output->variable_decisions.size() : 0);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_pseudo", "PASS -- typed AST rendered %zu bytes with deterministic output", rendered.output->text.size());
    passed.fetch_add(1);
}

static void test_type_recovery_semantic_cfg_cc_binding(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_types", "START -- type recovery consuming semantic, CFG, and calling-convention evidence");
    const auto workspace = analysis_fixture_workspace();
    const auto snapshot = workspace ? workspace->snapshot() : nullptr;
    if (!workspace || !snapshot || snapshot->functions.empty()) {
        log_msg(hf, "quality_types", "FAIL -- static workspace fixture with published functions is required");
        failed.fetch_add(1);
        return;
    }
    std::vector<const aida::analysis::function_record_t*> functions;
    functions.reserve(snapshot->functions.size());
    for (const auto& function : snapshot->functions)
        functions.push_back(&function);
    std::sort(functions.begin(), functions.end(), [](const auto* lhs, const auto* rhs) {
        return lhs->start < rhs->start || (!(rhs->start < lhs->start) && lhs->id < rhs->id);
    });
    const aida::analysis::function_record_t* selected_function = nullptr;
    std::optional<aida::analysis::cfg_analysis_result_t> selected_cfg;
    const std::size_t candidates = (std::min)(functions.size(), static_cast<std::size_t>(16));
    for (std::size_t index = 0; index < candidates; ++index) {
        const auto candidate = aida::analysis::analyze_advanced_cfg(*workspace, functions[index]->start.value, {});
        if (!candidate)
            continue;
        const auto& cfg = candidate.value();
        if (!cfg.function_noreturn && cfg.callgraph_edges.empty() && cfg.thunks.empty() && cfg.noreturn_effects.empty())
            continue;
        selected_function = functions[index];
        selected_cfg = candidate.value();
        break;
    }
    if (!selected_function || !selected_cfg) {
        log_msg(hf, "quality_types", "FAIL -- no CFG-bearing function found in %zu published fixture functions", candidates);
        failed.fetch_add(1);
        return;
    }
    aida::analysis::semantic_evidence_t type_evidence;
    type_evidence.evidence_id = 101;
    type_evidence.kind = aida::analysis::semantic_fact_kind_t::type;
    type_evidence.subject.kind = aida::analysis::semantic_subject_kind_t::function;
    type_evidence.subject.function_id = selected_function->id;
    type_evidence.subject.address = selected_function->start;
    aida::analysis::type_evidence_t semantic_type;
    semantic_type.location.kind = aida::analysis::semantic_location_kind_t::function_return;
    semantic_type.type.kind = aida::analysis::semantic_type_kind_t::integer;
    semantic_type.type.bit_width = 32;
    semantic_type.type.display_name = "uint32_t";
    semantic_type.instruction_id = selected_function->id;
    semantic_type.address = selected_function->start;
    type_evidence.payload = semantic_type;
    type_evidence.provenance.origin = aida::analysis::semantic_origin_t::decompiler_type_recovery;
    type_evidence.provenance.source = aida::analysis::fact_provenance_t::decompiler_feedback;
    type_evidence.provenance.source_entity_id = selected_function->id;
    type_evidence.provenance.source_address = selected_function->start;
    type_evidence.provenance.stable_source_id = 101;
    type_evidence.provenance.source_generation = snapshot->generation;
    type_evidence.provenance.source_analysis_revision = snapshot->analysis_revision;
    type_evidence.provenance.source_overlay_revision = snapshot->overlay_revision;
    type_evidence.provenance.independently_validated = true;
    type_evidence.validation = aida::analysis::semantic_validation_t::validated;
    type_evidence.confidence = 100;
    aida::analysis::semantic_fusion_request_t semantic_request;
    semantic_request.function_rva = selected_function->start.value;
    semantic_request.derive_workspace_evidence = false;
    semantic_request.decompiler_evidence = {type_evidence};
    const auto semantic = aida::analysis::fuse_semantic_evidence(*workspace, semantic_request);
    const aida::analysis::cancellation_token_t quality_cancel;
    const auto calling_convention = aida::analysis::analyze_calling_convention(
        *workspace, selected_function->start.value, quality_cancel);
    if (!semantic || !calling_convention) {
        log_msg(hf, "quality_types", "FAIL -- semantic=%d cc=%d semantic_error=%s cc_error=%s",
            semantic ? 1 : 0, calling_convention ? 1 : 0,
            semantic ? "" : semantic.error().stable_code().c_str(),
            calling_convention ? "" : calling_convention.error().stable_code().c_str());
        failed.fetch_add(1);
        return;
    }
    aida::analysis::type_recovery_request_t request;
    request.function_rva = selected_function->start.value;
    request.include_image_metadata = false;
    request.include_interprocedural = false;
    request.semantic_result = &semantic.value();
    request.cfg_result = &*selected_cfg;
    request.calling_convention_result = &calling_convention.value();
    const auto recovered = aida::analysis::recover_types(*workspace, request, quality_cancel);
    const bool semantic_consumed = recovered && std::any_of(recovered.value().evidence.begin(), recovered.value().evidence.end(),
        [](const auto& evidence) { return evidence.detail == "semantic_type"; });
    const bool cfg_consumed = recovered && std::any_of(recovered.value().evidence.begin(), recovered.value().evidence.end(),
        [](const auto& evidence) { return evidence.detail.find("cfg_") == 0; });
    const bool cc_consumed = recovered && std::any_of(recovered.value().evidence.begin(), recovered.value().evidence.end(),
        [](const auto& evidence) {
            return evidence.provenance == aida::analysis::type_evidence_provenance_t::calling_convention &&
                evidence.kind == aida::analysis::type_evidence_kind_t::calling_convention_function;
        });
    if (!semantic_consumed || !cfg_consumed || !cc_consumed) {
        log_msg(hf, "quality_types", "FAIL -- recovered=%d semantic=%d cfg=%d cc=%d evidence=%zu constraints=%zu function_rva=0x%llX",
            recovered ? 1 : 0, semantic_consumed ? 1 : 0, cfg_consumed ? 1 : 0, cc_consumed ? 1 : 0,
            recovered ? recovered.value().evidence.size() : 0,
            recovered ? recovered.value().constraints.size() : 0,
            (unsigned long long)selected_function->start.value);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_types", "PASS -- semantic, CFG, and calling-convention evidence reached type recovery for 0x%llX",
        (unsigned long long)selected_function->start.value);
    passed.fetch_add(1);
}

static void test_stale_revisions_and_decompiler_errors(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "quality_service", "START -- stale revision rejection and structured decompiler errors");
    const auto workspace = analysis_fixture_workspace();
    const auto snapshot = workspace ? workspace->snapshot() : nullptr;
    if (!workspace || !snapshot || snapshot->functions.empty() || !workspace->decompiler()) {
        log_msg(hf, "quality_service", "FAIL -- workspace, snapshot, functions, and decompiler service are required");
        failed.fetch_add(1);
        return;
    }
    const auto function = std::find_if(snapshot->functions.begin(), snapshot->functions.end(),
        [](const auto& item) { return item.id != 0; });
    if (function == snapshot->functions.end()) {
        log_msg(hf, "quality_service", "FAIL -- published snapshot has no function with a stable entity id");
        failed.fetch_add(1);
        return;
    }
    aida::analysis::calling_convention_request_t stale_cc_request;
    stale_cc_request.function = function->start;
    stale_cc_request.expected_generation = snapshot->generation + 1;
    stale_cc_request.expected_analysis_revision = snapshot->analysis_revision + 1;
    stale_cc_request.expected_overlay_revision = snapshot->overlay_revision + 1;
    const auto stale_cc = aida::analysis::infer_calling_convention(*workspace, stale_cc_request, {});
    aida::analysis::cancellation_source_t cancelled;
    cancelled.request_cancel();
    const auto cancelled_service = workspace->decompiler()->decompile(function->start, {}, cancelled.token());
    aida::analysis::decompiler_request_t deadline_request;
    deadline_request.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
    const auto deadline_service = workspace->decompiler()->decompile(function->start, deadline_request);
    aida::analysis::decompiler_request_context_t stale_context;
    stale_context.workspace_id = "testlab-quality";
    stale_context.function_id = function->id;
    stale_context.function_address = function->start;
    stale_context.address_space = function->start.space;
    stale_context.generation = workspace->generation() + 1;
    stale_context.overlay_revision = workspace->overlay_revision() + 1;
    stale_context.type_revision = 1;
    aida::analysis::decompiler_request_t stale_request;
    stale_request.use_memory_cache = false;
    stale_request.use_persistent_cache = false;
    stale_request.publish_feedback = false;
    stale_request.context = stale_context;
    const auto stale_service = workspace->decompiler()->decompile(function->start, stale_request);
    const bool cc_stale = !stale_cc && stale_cc.error().code == aida::analysis::workspace_error_code_t::stale_generation &&
        !stale_cc.error().phase.empty();
    const bool service_cancelled = !cancelled_service &&
        cancelled_service.error().code == aida::analysis::workspace_error_code_t::cancelled &&
        cancelled_service.error().cancellation && !cancelled_service.error().phase.empty();
    const bool service_deadline = !deadline_service &&
        deadline_service.error().code == aida::analysis::workspace_error_code_t::deadline_exceeded &&
        deadline_service.error().deadline && !deadline_service.error().phase.empty();
    const bool service_stale = !stale_service &&
        stale_service.error().code == aida::analysis::workspace_error_code_t::stale_generation &&
        stale_service.error().phase == "decompiler.context" && !stale_service.error().message.empty();
    if (!cc_stale || !service_cancelled || !service_deadline || !service_stale) {
        log_msg(hf, "quality_service", "FAIL -- cc_stale=%d cancelled=%d deadline=%d service_stale=%d codes=%d/%d/%d/%d",
            cc_stale ? 1 : 0, service_cancelled ? 1 : 0, service_deadline ? 1 : 0, service_stale ? 1 : 0,
            stale_cc ? -1 : static_cast<int>(stale_cc.error().code),
            cancelled_service ? -1 : static_cast<int>(cancelled_service.error().code),
            deadline_service ? -1 : static_cast<int>(deadline_service.error().code),
            stale_service ? -1 : static_cast<int>(stale_service.error().code));
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "quality_service", "PASS -- stale, cancellation, and deadline requests preserved structured errors");
    passed.fetch_add(1);
}

enum class benchmark_real_state_t {
    not_run_no_fixture,
    measured,
    failed
};

static benchmark_real_state_t g_benchmark_real_state = benchmark_real_state_t::not_run_no_fixture;
static std::string g_benchmark_real_detail = "not_run";

static const char* benchmark_real_state_name(benchmark_real_state_t state) noexcept {
    switch (state) {
    case benchmark_real_state_t::measured:
        return "MEASURED";
    case benchmark_real_state_t::failed:
        return "FAILED";
    default:
        return "SKIPPED_NO_FIXTURE";
    }
}

static void test_analysis_benchmark_real_300mb(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    char path_buffer[MAX_PATH]{};
    const DWORD path_length = GetEnvironmentVariableA("AIDA_BENCHMARK_REAL_PE", path_buffer, MAX_PATH);
    if (path_length == 0 || path_length >= MAX_PATH) {
        g_benchmark_real_state = benchmark_real_state_t::not_run_no_fixture;
        g_benchmark_real_detail = "AIDA_BENCHMARK_REAL_PE_unset";
        log_msg(hf, "analysis", "SKIP-LOUD -- analysis_benchmark_real_300mb state=SKIPPED_NO_FIXTURE evidence=AIDA_BENCHMARK_REAL_PE_unset action=set AIDA_BENCHMARK_REAL_PE=<300-500MB PE> to arm the release gate");
        passed.fetch_add(1);
        return;
    }
    std::error_code path_error;
    const auto fixture_path = std::filesystem::u8path(path_buffer);
    if (!std::filesystem::is_regular_file(fixture_path, path_error)) {
        g_benchmark_real_state = benchmark_real_state_t::failed;
        g_benchmark_real_detail = std::string("fixture_not_regular_file path=") + path_buffer;
        log_msg(hf, "analysis", "FAIL -- AIDA_BENCHMARK_REAL_PE is not a regular file path=%s", path_buffer);
        failed.fetch_add(1);
        return;
    }
    std::error_code size_error;
    const auto fixture_size = std::filesystem::file_size(fixture_path, size_error);
    if (size_error || fixture_size < 300000000ULL || fixture_size > 500000000ULL) {
        g_benchmark_real_state = benchmark_real_state_t::failed;
        g_benchmark_real_detail = "fixture_outside_300000000..500000000_window size=" +
            std::to_string(static_cast<unsigned long long>(fixture_size));
        log_msg(hf, "analysis", "FAIL -- real benchmark fixture outside the 300000000..500000000 byte window path=%s size=%llu error=%d",
            path_buffer, static_cast<unsigned long long>(fixture_size),
            size_error ? size_error.value() : 0);
        failed.fetch_add(1);
        return;
    }
    char relax_buffer[8]{};
    const DWORD relax_length = GetEnvironmentVariableA("AIDA_BENCHMARK_REAL_SLA_RELAX", relax_buffer, sizeof(relax_buffer));
    const bool sla_relaxed = relax_length != 0 && relax_length < sizeof(relax_buffer) && relax_buffer[0] == '1';
    const double wall_scale = aida::analysis::benchmark::program_sla_wall_scale(fixture_size);
    log_msg(hf, "analysis", "benchmark run_begin mode=%s path=%s size=%llu relaxed=%d wall_scale=%.4f wall_gate_ms=%.0f",
        "real", path_buffer, static_cast<unsigned long long>(fixture_size), sla_relaxed ? 1 : 0,
        wall_scale, 300000.0 * wall_scale);

    aida::analysis::benchmark::benchmark_run_request_t request;
    request.mode = aida::analysis::benchmark::benchmark_mode_t::real;
    request.real_path = path_buffer;
    request.sla_relaxed = sla_relaxed;
    request.run_cancellation_stage = true;
    request.cancellation_samples = 3;
    const auto run_begin = GetTickCount64();
    auto result = aida::analysis::benchmark::run_benchmark(request, {});
    const auto run_wall_ms = GetTickCount64() - run_begin;

    std::string failing_keys;
    bool parse_ok = false;
    bool v2_complete = true;
    if (!result.scorecard_json.empty()) {
        try {
            const auto scorecard = nlohmann::json::parse(result.scorecard_json);
            parse_ok = true;
            const auto number_or_zero = [](const nlohmann::json& object, const char* key) {
                return object.contains(key) && object[key].is_number()
                    ? object[key].get<double>() : 0.0;
            };
            if (scorecard.contains("throughput")) {
                const auto& throughput = scorecard["throughput"];
                log_msg(hf, "analysis", "benchmark throughput file_Bps=%.1f decode_Bps=%.1f instr_s=%.1f funcs_s=%.2f",
                    number_or_zero(throughput, "file_bytes_per_s"),
                    number_or_zero(throughput, "decode_bytes_per_s"),
                    number_or_zero(throughput, "instructions_per_s"),
                    number_or_zero(throughput, "decompile_all_funcs_per_s"));
            }
            if (scorecard.contains("memory")) {
                const auto& memory = scorecard["memory"];
                const auto u64_or_zero = [](const nlohmann::json& object, const char* key) {
                    return object.contains(key) && object[key].is_number()
                        ? object[key].get<std::uint64_t>() : 0ULL;
                };
                log_msg(hf, "analysis", "benchmark memory peak_private=%llu resident_peak=%llu",
                    static_cast<unsigned long long>(u64_or_zero(memory, "peak_private_bytes")),
                    static_cast<unsigned long long>(u64_or_zero(memory, "resident_bytes_peak")));
            }
            if (scorecard.contains("sla") && scorecard["sla"].contains("verdicts")) {
                for (const auto& verdict : scorecard["sla"]["verdicts"]) {
                    const auto key = verdict.value("key", std::string());
                    const auto state = verdict.value("verdict", std::string());
                    log_msg(hf, "analysis", "benchmark sla key=%s target=%s actual=%s verdict=%s",
                        key.c_str(),
                        verdict["target"].is_null() ? "null" : verdict["target"].dump().c_str(),
                        verdict["actual"].is_null() ? "null" : verdict["actual"].dump().c_str(),
                        state.c_str());
                    if (state == "FAIL") {
                        if (!failing_keys.empty())
                            failing_keys += ",";
                        failing_keys += key;
                    }
                }
            }
            std::string v2_failures;
            const auto v2_fail = [&v2_failures](const char* what) {
                if (!v2_failures.empty())
                    v2_failures += ",";
                v2_failures += what;
            };
            if (!scorecard.contains("scorecard_schema_version") ||
                !scorecard["scorecard_schema_version"].is_number() ||
                scorecard["scorecard_schema_version"].get<int>() != 2)
                v2_fail("scorecard_schema_version");
            if (!scorecard.contains("phases") || !scorecard["phases"].is_array() ||
                scorecard["phases"].size() != 13) {
                v2_fail("phases");
            } else {
                for (const auto& phase : scorecard["phases"]) {
                    const auto wall_ns = phase.value("wall_ns", 0ULL);
                    log_msg(hf, "analysis", "benchmark phase name=%s wall_ms=%.3f bytes_out=%llu",
                        phase.value("name", std::string()).c_str(),
                        static_cast<double>(wall_ns) / 1000000.0,
                        static_cast<unsigned long long>(phase.value("bytes_out", 0ULL)));
                }
            }
            if (!scorecard.contains("worker_pool") || !scorecard["worker_pool"].is_object() ||
                !scorecard["worker_pool"].contains("parallelism_efficiency") ||
                !scorecard["worker_pool"]["parallelism_efficiency"].is_number() ||
                scorecard["worker_pool"]["parallelism_efficiency"].get<double>() <= 0.0 ||
                scorecard["worker_pool"]["parallelism_efficiency"].get<double>() > 1.0) {
                v2_fail("worker_pool.parallelism_efficiency");
            } else {
                log_msg(hf, "analysis", "benchmark worker_pool parallelism_efficiency=%.4f utilization=%.4f",
                    scorecard["worker_pool"]["parallelism_efficiency"].get<double>(),
                    number_or_zero(scorecard["worker_pool"], "utilization"));
            }
            if (!scorecard.contains("memory") || !scorecard["memory"].is_object() ||
                !scorecard["memory"].contains("peak_rss_bytes") ||
                !scorecard["memory"]["peak_rss_bytes"].is_number() ||
                scorecard["memory"]["peak_rss_bytes"].get<std::uint64_t>() == 0)
                v2_fail("memory.peak_rss_bytes");
            const bool functions_present = scorecard.contains("counts") &&
                scorecard["counts"].is_object() &&
                scorecard["counts"].value("functions", 0ULL) > 0;
            if (functions_present &&
                (!scorecard.contains("decompile") || !scorecard["decompile"].is_object() ||
                    !scorecard["decompile"].contains("funcs_per_s") ||
                    !scorecard["decompile"]["funcs_per_s"].is_number() ||
                    scorecard["decompile"]["funcs_per_s"].get<double>() <= 0.0))
                v2_fail("decompile.funcs_per_s");
            if (functions_present &&
                (!scorecard.contains("decompile") || !scorecard["decompile"].is_object() ||
                    !scorecard["decompile"].contains("slots") ||
                    !scorecard["decompile"]["slots"].is_number() ||
                    scorecard["decompile"]["slots"].get<std::uint64_t>() < 1 ||
                    !scorecard["decompile"].contains("slots_effective_peak") ||
                    !scorecard["decompile"]["slots_effective_peak"].is_number() ||
                    scorecard["decompile"]["slots_effective_peak"].get<std::uint64_t>() < 1))
                v2_fail("decompile.slots");
            if (!v2_failures.empty()) {
                v2_complete = false;
                log_msg(hf, "analysis", "benchmark scorecard_v2_incomplete failures=%s",
                    v2_failures.c_str());
            }
        } catch (const nlohmann::json::exception& exception) {
            log_msg(hf, "analysis", "benchmark scorecard parse failed: %s", exception.what());
        }
    }
    log_msg(hf, "analysis", "benchmark run_end wall_ms=%llu verdict=%s report=%s",
        static_cast<unsigned long long>(run_wall_ms),
        result.verdict.c_str(),
        result.report_json_path.empty() ? result.error.c_str() : result.report_json_path.c_str());

    if (result.ok && result.verdict == "PASS" && v2_complete) {
        g_benchmark_real_state = benchmark_real_state_t::measured;
        g_benchmark_real_detail = "verdict=PASS sla_overall=" + result.sla_overall +
            " wall_ms=" + std::to_string(static_cast<unsigned long long>(run_wall_ms));
        log_msg(hf, "analysis", "PASS -- analysis_benchmark_real_300mb sla_overall=%s parse_ok=%d v2_complete=%d relaxed=%d",
            result.sla_overall.c_str(), parse_ok ? 1 : 0, v2_complete ? 1 : 0, sla_relaxed ? 1 : 0);
        passed.fetch_add(1);
        return;
    }
    g_benchmark_real_state = benchmark_real_state_t::failed;
    g_benchmark_real_detail = "verdict=" + result.verdict + " sla_overall=" + result.sla_overall +
        " failing_keys=" + (failing_keys.empty() ? std::string("<none>") : failing_keys);
    log_msg(hf, "analysis", "FAIL -- analysis_benchmark_real_300mb verdict=%s sla_overall=%s failing_keys=%s v2_complete=%d error=%s",
        result.verdict.c_str(), result.sla_overall.c_str(),
        failing_keys.empty() ? "<none>" : failing_keys.c_str(),
        v2_complete ? 1 : 0,
        result.error.empty() ? "<none>" : result.error.c_str());
    failed.fetch_add(1);
}

static void test_analysis_fast_containers_bench(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    constexpr std::size_t k_map_key_count = 4000000;
    std::vector<std::uint64_t> keys;
    keys.reserve(k_map_key_count);
    std::uint64_t key_state = 0xA1DAF457C0FFEE99ULL;
    for (std::size_t index = 0; index < k_map_key_count; ++index) {
        key_state += 0x9E3779B97F4A7C15ULL;
        std::uint64_t mixed = key_state;
        mixed = (mixed ^ (mixed >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        mixed = (mixed ^ (mixed >> 27U)) * 0x94D049BB133111EBULL;
        keys.push_back(mixed ^ (mixed >> 31U));
    }
    const auto private_bytes_now = []() -> std::uint64_t {
        PROCESS_MEMORY_COUNTERS_EX counters{};
        if (GetProcessMemoryInfo(GetCurrentProcess(),
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
            return static_cast<std::uint64_t>(counters.PrivateUsage);
        }
        return 0;
    };

    double unordered_insert_ns_per_op = 0.0;
    double unordered_lookup_ns_per_op = 0.0;
    std::uint64_t unordered_private_delta = 0;
    std::uint64_t unordered_checksum = 0;
    std::size_t unordered_found = 0;
    {
        const std::uint64_t memory_before = private_bytes_now();
        std::unordered_map<std::uint64_t, std::uint64_t> reference_map;
        reference_map.reserve(k_map_key_count);
        const auto insert_begin = std::chrono::steady_clock::now();
        for (const std::uint64_t key : keys) {
            reference_map.emplace(key, key ^ 0x5A5A5A5A5A5A5A5AULL);
        }
        const auto insert_end = std::chrono::steady_clock::now();
        unordered_insert_ns_per_op =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(insert_end - insert_begin).count()) /
            static_cast<double>(k_map_key_count);
        const auto lookup_begin = std::chrono::steady_clock::now();
        for (const std::uint64_t key : keys) {
            const auto found = reference_map.find(key);
            if (found != reference_map.end()) {
                unordered_checksum += found->second;
                ++unordered_found;
            }
        }
        const auto lookup_end = std::chrono::steady_clock::now();
        unordered_lookup_ns_per_op =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(lookup_end - lookup_begin).count()) /
            static_cast<double>(k_map_key_count);
        const std::uint64_t memory_after = private_bytes_now();
        unordered_private_delta = memory_after >= memory_before ? memory_after - memory_before : 0;
    }

    double flat_insert_ns_per_op = 0.0;
    double flat_lookup_ns_per_op = 0.0;
    std::uint64_t flat_private_delta = 0;
    std::uint64_t flat_checksum = 0;
    std::size_t flat_found = 0;
    {
        const std::uint64_t memory_before = private_bytes_now();
        aida::infra::fast_u64_map<std::uint64_t> flat_map;
        flat_map.reserve(k_map_key_count);
        const auto insert_begin = std::chrono::steady_clock::now();
        for (const std::uint64_t key : keys) {
            flat_map.emplace(key, key ^ 0x5A5A5A5A5A5A5A5AULL);
        }
        const auto insert_end = std::chrono::steady_clock::now();
        flat_insert_ns_per_op =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(insert_end - insert_begin).count()) /
            static_cast<double>(k_map_key_count);
        const auto lookup_begin = std::chrono::steady_clock::now();
        for (const std::uint64_t key : keys) {
            const auto found = flat_map.find(key);
            if (found != flat_map.end()) {
                flat_checksum += found->second;
                ++flat_found;
            }
        }
        const auto lookup_end = std::chrono::steady_clock::now();
        flat_lookup_ns_per_op =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(lookup_end - lookup_begin).count()) /
            static_cast<double>(k_map_key_count);
        const std::uint64_t memory_after = private_bytes_now();
        flat_private_delta = memory_after >= memory_before ? memory_after - memory_before : 0;
    }

    const double insert_speedup = flat_insert_ns_per_op > 0.0
        ? unordered_insert_ns_per_op / flat_insert_ns_per_op : 0.0;
    const double lookup_speedup = flat_lookup_ns_per_op > 0.0
        ? unordered_lookup_ns_per_op / flat_lookup_ns_per_op : 0.0;
    log_msg(hf, "analysis",
        "fast_containers bench map keys=%llu unordered_insert_ns=%.2f flat_insert_ns=%.2f insert_speedup=%.3f unordered_lookup_ns=%.2f flat_lookup_ns=%.2f lookup_speedup=%.3f unordered_private_delta=%llu flat_private_delta=%llu unordered_found=%llu flat_found=%llu checksum_match=%d",
        static_cast<unsigned long long>(k_map_key_count),
        unordered_insert_ns_per_op, flat_insert_ns_per_op, insert_speedup,
        unordered_lookup_ns_per_op, flat_lookup_ns_per_op, lookup_speedup,
        static_cast<unsigned long long>(unordered_private_delta),
        static_cast<unsigned long long>(flat_private_delta),
        static_cast<unsigned long long>(unordered_found),
        static_cast<unsigned long long>(flat_found),
        (unordered_checksum == flat_checksum) ? 1 : 0);

    const bool map_ok = unordered_found == k_map_key_count &&
        flat_found == k_map_key_count &&
        unordered_checksum == flat_checksum &&
        flat_insert_ns_per_op > 0.0 &&
        insert_speedup >= 1.5;
    if (!map_ok) {
        log_msg(hf, "analysis",
            "FAIL -- analysis_fast_containers_bench map stage unordered_found=%llu flat_found=%llu checksum_match=%d insert_speedup=%.3f required=1.500",
            static_cast<unsigned long long>(unordered_found),
            static_cast<unsigned long long>(flat_found),
            (unordered_checksum == flat_checksum) ? 1 : 0,
            insert_speedup);
    }

    constexpr std::uint32_t k_producer_count = 16;
    constexpr std::uint32_t k_items_per_producer = 18750;
    constexpr std::uint64_t k_expected_total =
        static_cast<std::uint64_t>(k_producer_count) * static_cast<std::uint64_t>(k_items_per_producer);
    struct queue_item_t {
        std::uint32_t producer;
        std::uint32_t sequence;
    };
    aida::infra::fast_blocking_queue<queue_item_t> queue;
    std::atomic<std::uint64_t> enqueued{0};
    std::vector<std::thread> producers;
    producers.reserve(k_producer_count);
    for (std::uint32_t producer_index = 0; producer_index < k_producer_count; ++producer_index) {
        producers.emplace_back([&queue, &enqueued, producer_index]() {
            for (std::uint32_t sequence = 0; sequence < k_items_per_producer; ++sequence) {
                queue.enqueue(queue_item_t{producer_index, sequence});
                enqueued.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    std::vector<std::uint32_t> expected_next(k_producer_count, 0);
    std::uint64_t dequeued = 0;
    std::uint64_t fifo_violations = 0;
    bool consumer_stalled = false;
    while (dequeued < k_expected_total) {
        queue_item_t item{};
        if (!queue.wait_dequeue_timed(item, std::chrono::milliseconds(30000))) {
            consumer_stalled = true;
            log_msg(hf, "analysis",
                "FAIL -- analysis_fast_containers_bench queue stage consumer stall enqueued=%llu dequeued=%llu expected=%llu",
                static_cast<unsigned long long>(enqueued.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(dequeued),
                static_cast<unsigned long long>(k_expected_total));
            break;
        }
        if (item.producer >= k_producer_count) {
            ++fifo_violations;
        } else if (item.sequence != expected_next[item.producer]) {
            ++fifo_violations;
            expected_next[item.producer] = item.sequence + 1;
        } else {
            ++expected_next[item.producer];
        }
        ++dequeued;
    }
    for (std::thread& producer : producers) {
        producer.join();
    }
    std::uint64_t drained_extra = 0;
    {
        queue_item_t item{};
        while (queue.try_dequeue(item)) {
            ++drained_extra;
        }
    }
    std::uint64_t per_producer_deficits = 0;
    for (std::uint32_t producer_index = 0; producer_index < k_producer_count; ++producer_index) {
        if (expected_next[producer_index] != k_items_per_producer) {
            ++per_producer_deficits;
        }
    }
    log_msg(hf, "analysis",
        "fast_containers bench queue producers=%lu items_per_producer=%lu enqueued=%llu dequeued=%llu fifo_violations=%llu drained_extra=%llu per_producer_deficits=%llu stalled=%d",
        static_cast<unsigned long>(k_producer_count),
        static_cast<unsigned long>(k_items_per_producer),
        static_cast<unsigned long long>(enqueued.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(dequeued),
        static_cast<unsigned long long>(fifo_violations),
        static_cast<unsigned long long>(drained_extra),
        static_cast<unsigned long long>(per_producer_deficits),
        consumer_stalled ? 1 : 0);

    const bool queue_ok = !consumer_stalled &&
        dequeued == k_expected_total &&
        enqueued.load(std::memory_order_acquire) == k_expected_total &&
        fifo_violations == 0 &&
        drained_extra == 0 &&
        per_producer_deficits == 0;
    if (!queue_ok) {
        log_msg(hf, "analysis",
            "FAIL -- analysis_fast_containers_bench queue stage dequeued=%llu expected=%llu fifo_violations=%llu drained_extra=%llu per_producer_deficits=%llu stalled=%d",
            static_cast<unsigned long long>(dequeued),
            static_cast<unsigned long long>(k_expected_total),
            static_cast<unsigned long long>(fifo_violations),
            static_cast<unsigned long long>(drained_extra),
            static_cast<unsigned long long>(per_producer_deficits),
            consumer_stalled ? 1 : 0);
    }

    if (map_ok && queue_ok) {
        log_msg(hf, "analysis",
            "PASS -- analysis_fast_containers_bench insert_speedup=%.3f lookup_speedup=%.3f queue_fifo=1 queue_count=%llu",
            insert_speedup, lookup_speedup,
            static_cast<unsigned long long>(dequeued));
        passed.fetch_add(1);
        return;
    }
    failed.fetch_add(1);
}

static void test_memory_scale_hot_cold_golden(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    using namespace aida::analysis;
    std::vector<operand_fact_t> golden;
    const auto append = [&](operand_fact_t record) {
        golden.push_back(record);
        auto& last = golden.back();
        last.id = operand_entity_tag | (golden.size() - 1);
        last.instruction_id = instruction_entity_tag |
            ((golden.size() - 1) / 2 + 1);
    };
    operand_fact_t base;
    base.operand_index = 0;
    base.decoder_operand_id = 1;
    base.kind = operand_kind_t::reg;
    base.access = 1;
    base.visibility = 2;
    base.encoding = 3;
    base.memory_type = 1;
    base.access_width = 8;
    base.bit_width = 64;
    base.access_width_bits = 64;
    base.reg = 7;
    append(base);
    operand_fact_t memory = base;
    memory.operand_index = 1;
    memory.kind = operand_kind_t::memory;
    memory.segment_reg = 71;
    memory.base_reg = 5;
    memory.index_reg = 6;
    memory.scale = 8;
    memory.displacement = -4096;
    memory.has_displacement = true;
    memory.address_components = address_component_base | address_component_index |
        address_component_scale | address_component_displacement;
    memory.address_expression = address_expression_kind_t::base_index_displacement;
    memory.address_resolution = target_resolution_t::image_relative;
    memory.address_width_bits = 64;
    memory.address_expression_id = address_expression_entity_tag | 3ULL;
    append(memory);
    operand_fact_t wide = base;
    wide.operand_index = 2;
    wide.memory_type = 4;
    wide.bit_width = 80;
    wide.access = 13;
    wide.resolved_expression_value = 0xDEADBEEFCAFEULL;
    wide.has_resolved_expression_value = true;
    wide.element_width_bits = 16;
    wide.element_count = 8;
    wide.access_count = 2;
    append(wide);
    operand_fact_t segment = base;
    segment.operand_index = 3;
    segment.segment_reg = 300;
    segment.immediate = 0x1122334455667788ULL;
    segment.signed_value = true;
    segment.relative = true;
    append(segment);
    operand_fact_store_t store;
    store.hot.reserve(golden.size());
    std::vector<instruction_record_t> instructions(2);
    for (std::size_t index = 0; index < instructions.size(); ++index)
        instructions[index].id = instruction_entity_tag | (index + 1);
    for (std::size_t index = 0; index < golden.size(); ++index) {
        auto parts = operand_fact_split(golden[index],
            static_cast<std::uint32_t>(index / 2));
        if (parts.has_cold) {
            store.cold.push_back(parts.cold);
            parts.hot.cold_index = static_cast<std::uint32_t>(store.cold.size());
        }
        store.hot.push_back(parts.hot);
    }
    bool identical = true;
    std::size_t mismatch = golden.size();
    for (std::size_t index = 0; index < golden.size() && identical; ++index) {
        const auto rebuilt = operand_fact_materialize(store, index, instructions);
        const auto& expected = golden[index];
        if (rebuilt.id != expected.id ||
            rebuilt.instruction_id != expected.instruction_id ||
            rebuilt.address_expression_id != expected.address_expression_id ||
            rebuilt.displacement != expected.displacement ||
            rebuilt.immediate != expected.immediate ||
            rebuilt.resolved_expression_value != expected.resolved_expression_value ||
            rebuilt.bit_width != expected.bit_width ||
            rebuilt.access_width_bits != expected.access_width_bits ||
            rebuilt.element_width_bits != expected.element_width_bits ||
            rebuilt.reg != expected.reg || rebuilt.segment_reg != expected.segment_reg ||
            rebuilt.base_reg != expected.base_reg || rebuilt.index_reg != expected.index_reg ||
            rebuilt.address_components != expected.address_components ||
            rebuilt.access_count != expected.access_count ||
            rebuilt.element_count != expected.element_count ||
            rebuilt.address_width_bits != expected.address_width_bits ||
            rebuilt.operand_index != expected.operand_index ||
            rebuilt.decoder_operand_id != expected.decoder_operand_id ||
            rebuilt.kind != expected.kind || rebuilt.access != expected.access ||
            rebuilt.visibility != expected.visibility ||
            rebuilt.encoding != expected.encoding ||
            rebuilt.memory_type != expected.memory_type ||
            rebuilt.access_width != expected.access_width ||
            rebuilt.scale != expected.scale || rebuilt.relative != expected.relative ||
            rebuilt.signed_value != expected.signed_value ||
            rebuilt.has_displacement != expected.has_displacement ||
            rebuilt.has_resolved_expression_value != expected.has_resolved_expression_value ||
            rebuilt.address_expression != expected.address_expression ||
            rebuilt.address_resolution != expected.address_resolution) {
            identical = false;
            mismatch = index;
        }
    }
    if (identical) {
        log_msg(hf, "memory_scale", "PASS -- hot/cold golden round-trip records=%zu cold=%zu",
            golden.size(), store.cold.size());
        passed.fetch_add(1);
        return;
    }
    log_msg(hf, "memory_scale", "FAIL -- hot/cold golden round-trip mismatch at record=%zu",
        mismatch);
    failed.fetch_add(1);
}

static void test_memory_scale_residency_plan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    using namespace aida::analysis;
    std::array<fact_domain_projection_t, fact_domain_count> projections{};
    projections[static_cast<std::size_t>(fact_domain_t::instructions)] = {
        47500000ULL, sizeof(instruction_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::operand_facts)] = {
        109000000ULL, 45};
    projections[static_cast<std::size_t>(fact_domain_t::target_facts)] = {
        16600000ULL, sizeof(target_fact_t)};
    projections[static_cast<std::size_t>(fact_domain_t::edges)] = {
        17800000ULL, sizeof(edge_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::xrefs)] = {
        23800000ULL, sizeof(xref_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::blocks)] = {
        7100000ULL, sizeof(basic_block_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::functions)] = {
        1190000ULL, sizeof(function_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::function_chunks)] = {
        1500000ULL, sizeof(function_chunk_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::function_block_memberships)] = {
        7100000ULL, sizeof(function_block_membership_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::strings)] = {
        300000ULL, sizeof(string_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::symbols)] = {
        400000ULL, sizeof(symbol_record_t)};
    projections[static_cast<std::size_t>(fact_domain_t::coverage)] = {
        50000ULL, sizeof(coverage_span_t)};
    host_memory_envelope_t small;
    small.usable_bytes = 4ULL << 30;
    const auto small_budget = fact_resident_budget_bytes(small);
    const auto small_plan = fact_residency_select(projections, small_budget);
    host_memory_envelope_t large;
    large.usable_bytes = 60ULL << 30;
    const auto large_budget = fact_resident_budget_bytes(large);
    const auto large_plan = fact_residency_select(projections, large_budget);
    const bool small_pages =
        small_plan.domains[static_cast<std::size_t>(
            fact_domain_t::instructions)].mode == fact_residency_mode_t::paged &&
        small_plan.resident_bytes <= small_budget &&
        small_plan.paged_bytes != 0;
    const std::uint64_t projected_total =
        projections[static_cast<std::size_t>(fact_domain_t::instructions)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::operand_facts)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::target_facts)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::edges)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::xrefs)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::blocks)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::functions)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::function_chunks)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::function_block_memberships)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::strings)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::symbols)].projected_bytes() +
        projections[static_cast<std::size_t>(fact_domain_t::coverage)].projected_bytes();
    const bool large_resident =
        large_plan.resident_bytes == projected_total &&
        !large_plan.any_paged();
    if (small_pages && large_resident) {
        log_msg(hf, "memory_scale",
            "PASS -- residency plan small_budget=%llu small_resident=%llu small_paged=%llu large_budget=%llu large_resident=%llu",
            static_cast<unsigned long long>(small_budget),
            static_cast<unsigned long long>(small_plan.resident_bytes),
            static_cast<unsigned long long>(small_plan.paged_bytes),
            static_cast<unsigned long long>(large_budget),
            static_cast<unsigned long long>(large_plan.resident_bytes));
        passed.fetch_add(1);
        return;
    }
    log_msg(hf, "memory_scale",
        "FAIL -- residency plan small_pages=%d small_resident=%llu small_budget=%llu large_resident=%llu projected_total=%llu large_budget=%llu",
        small_pages ? 1 : 0,
        static_cast<unsigned long long>(small_plan.resident_bytes),
        static_cast<unsigned long long>(small_budget),
        static_cast<unsigned long long>(large_plan.resident_bytes),
        static_cast<unsigned long long>(projected_total),
        static_cast<unsigned long long>(large_budget));
    failed.fetch_add(1);
}

static void test_memory_scale_paged_staging(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    using namespace aida::analysis;
    auto staging = paged_fact_staging_t::create(64ULL << 10);
    if (!staging) {
        log_msg(hf, "memory_scale", "FAIL -- staging create failed");
        failed.fetch_add(1);
        return;
    }
    auto store = staging.take_value();
    std::uint64_t expected_ordinal = 0;
    for (std::uint32_t page = 0; page < 8; ++page) {
        std::vector<std::uint8_t> payload(32ULL << 10, static_cast<std::uint8_t>(page + 1));
        paged_fact_page_meta_t meta;
        meta.ordinal_begin = expected_ordinal;
        meta.record_count = 64;
        meta.address_value_min = page * 0x1000ULL;
        meta.address_value_max = meta.address_value_min + 0xFFFULL;
        expected_ordinal += meta.record_count;
        auto staged = store->stage_page(fact_domain_t::operand_facts,
                                        std::move(payload), meta, {});
        if (!staged) {
            log_msg(hf, "memory_scale", "FAIL -- stage_page page=%lu code=%d",
                static_cast<unsigned long>(page), static_cast<int>(staged.error().code));
            failed.fetch_add(1);
            return;
        }
    }
    const auto resident = store->resident_bytes();
    const auto spilled = store->spilled_bytes();
    auto contiguous = store->validate_contiguous(fact_domain_t::operand_facts);
    if (!contiguous) {
        log_msg(hf, "memory_scale", "FAIL -- staging contiguity rejected");
        failed.fetch_add(1);
        return;
    }
    bool visit_ok = resident != 0 && spilled != 0;
    std::uint64_t visited_pages = 0;
    std::uint64_t visited_records = 0;
    auto visited = store->for_each_page(fact_domain_t::operand_facts,
        [&](const paged_fact_page_meta_t& meta,
            const std::vector<std::uint8_t>& payload) -> workspace_result_t<void> {
            if (meta.ordinal_begin != visited_records ||
                meta.record_count != 64 || payload.size() != (32ULL << 10) ||
                payload[0] != static_cast<std::uint8_t>(visited_pages + 1)) {
                visit_ok = false;
            }
            visited_records += meta.record_count;
            ++visited_pages;
            return workspace_result_t<void>::success();
        }, {});
    if (!visited)
        visit_ok = false;
    visit_ok = visit_ok && visited_pages == 8 && visited_records == expected_ordinal;
    paged_fact_page_meta_t meta;
    auto payload = store->page_payload(fact_domain_t::operand_facts, 3, meta, {});
    visit_ok = visit_ok && payload && payload.value().size() == (32ULL << 10) &&
        payload.value()[0] == 4;
    if (visit_ok) {
        log_msg(hf, "memory_scale",
            "PASS -- staging spill/readback resident=%llu spilled=%llu pages=%llu",
            static_cast<unsigned long long>(resident),
            static_cast<unsigned long long>(spilled),
            static_cast<unsigned long long>(visited_pages));
        passed.fetch_add(1);
        return;
    }
    log_msg(hf, "memory_scale",
        "FAIL -- staging spill/readback resident=%llu spilled=%llu pages=%llu records=%llu",
        static_cast<unsigned long long>(resident),
        static_cast<unsigned long long>(spilled),
        static_cast<unsigned long long>(visited_pages),
        static_cast<unsigned long long>(visited_records));
    failed.fetch_add(1);
}

static void test_memory_scale_publication_index_differential(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    std::string detail;
    if (aida::analysis::publication_indexes::differential_selftest(detail)) {
        log_msg(hf, "memory_scale", "PASS -- publication index differential selftest");
        passed.fetch_add(1);
        return;
    }
    log_msg(hf, "memory_scale", "FAIL -- publication index differential selftest: %s",
        detail.c_str());
    failed.fetch_add(1);
}

using analysis_test_fn_t = void (*)(HANDLE, std::atomic<int>&, std::atomic<int>&);

struct analysis_test_entry_t {
    const char* name;
    analysis_test_fn_t fn;
    DWORD timeout_ms = 5000;
};

static void run_analysis_test_seh(HANDLE hf, const analysis_test_entry_t& test, std::atomic<int>& passed, std::atomic<int>& failed) {
    __try {
        test.fn(hf, passed, failed);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg(hf, "analysis", "FAIL -- %s threw SEH exception 0x%08X",
            test.name, GetExceptionCode());
        failed.fetch_add(1);
    }
}

struct analysis_worker_state_t {
    std::atomic<int> passed{0};
    std::atomic<int> failed{0};
};

struct analysis_log_handle_t {
    HANDLE handle = nullptr;
    explicit analysis_log_handle_t(HANDLE h) : handle(h) {}
    ~analysis_log_handle_t() {
        if (handle && handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
    HANDLE get() const {
        return handle;
    }
};

static HANDLE duplicate_analysis_log_handle(HANDLE hf) {
    if (!hf || hf == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;
    HANDLE dup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hf, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return INVALID_HANDLE_VALUE;
    return dup;
}

static bool run_analysis_test_bounded(HANDLE hf, const analysis_test_entry_t& test, std::atomic<int>& passed, std::atomic<int>& failed, DWORD timeout_ms) {
    static test_lab::bounded_runner_t runner(1);
    auto state = std::make_shared<analysis_worker_state_t>();

    auto worker_log = std::make_shared<analysis_log_handle_t>(duplicate_analysis_log_handle(hf));
    const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [worker_log, test, state]() {
        HANDLE log_hf = worker_log->get();
        try {
            run_analysis_test_seh(log_hf, test, state->passed, state->failed);
        } catch (const std::exception& ex) {
            log_msg(log_hf, "analysis", "FAIL -- %s threw C++ exception: %s", test.name, ex.what());
            state->failed.fetch_add(1);
        } catch (...) {
            log_msg(log_hf, "analysis", "FAIL -- %s threw unknown C++ exception", test.name);
            state->failed.fetch_add(1);
        }
    });

    if (result.status == test_lab::bounded_run_status_t::completed) {
        passed.fetch_add(state->passed.load(std::memory_order_acquire));
        failed.fetch_add(state->failed.load(std::memory_order_acquire));
        return true;
    }

    if (result.status == test_lab::bounded_run_status_t::timed_out) {
        if (std::strcmp(test.name, "integrity_hunter_nodes") == 0 ||
            std::strcmp(test.name, "integrity_hunter_start_stop") == 0) {
            integrity_hunter::stop_hunt();
            const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
            log_msg(hf, "analysis", "TIMEOUT-CLEANUP -- %s stop_hunt issued idle_after_cleanup=%d cleanup_elapsed_ms=%lld generation=%llu install_generation=%llu pid=%u active_pid=%u install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d hunting=%d worker=%d nodes=%zu events=%zu total_reads=%llu status=\"%s\" last_error=\"%s\"",
                test.name,
                idle_state.idle ? 1 : 0,
                (long long)idle_state.elapsed_ms,
                (unsigned long long)idle_state.generation,
                (unsigned long long)idle_state.install_generation,
                (unsigned)idle_state.target_pid,
                (unsigned)driver_bridge::attached_pid(),
                integrity_hunter::install_complete_for_generation(idle_state.generation) ? 1 : 0,
                integrity_hunter::install_success_for_generation(idle_state.generation) ? 1 : 0,
                idle_state.install_complete ? 1 : 0,
                idle_state.install_success ? 1 : 0,
                idle_state.hunting ? 1 : 0,
                idle_state.worker_active ? 1 : 0,
                idle_state.nodes,
                idle_state.events,
                (unsigned long long)idle_state.total_reads,
                idle_state.status_text.c_str(),
                driver_bridge::last_error().c_str());
            if (!idle_state.idle) {
                log_msg(hf, "analysis", "FAIL -- %s integrity hunter cleanup exceeded 12000 ms after watchdog",
                    test.name);
                failed.fetch_add(1);
                return false;
            }
        }
        log_msg(hf, "analysis", "FAIL -- %s exceeded %lu ms watchdog; bounded worker still draining",
            test.name, static_cast<unsigned long>(timeout_ms));
        failed.fetch_add(1);
        return false;
    }

    if (result.status == test_lab::bounded_run_status_t::saturated) {
        log_msg(hf, "analysis", "FAIL -- %s bounded runner saturated; previous timed-out workers still draining", test.name);
        failed.fetch_add(1);
        return false;
    }

    if (result.status == test_lab::bounded_run_status_t::exception) {
        log_msg(hf, "analysis", "FAIL -- %s bounded worker escaped exception: %s",
            test.name, result.error.empty() ? "<unknown>" : result.error.c_str());
        failed.fetch_add(1);
        return false;
    }

    log_msg(hf, "analysis", "FAIL -- %s worker post failed%s%s",
        test.name,
        result.error.empty() ? "" : ": ",
        result.error.empty() ? "" : result.error.c_str());
    failed.fetch_add(1);
    return false;
}

}

void phase_analysis_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    static const analysis_test_entry_t tests[] = {
        { "symbolic_execute",            test_symbolic_execute            },
        { "symbolic_execute_larger",     test_symbolic_execute_larger     },
        { "symbolic_slice",              test_symbolic_slice              },
        { "symbolic_slice_rsi",          test_symbolic_slice_rsi          },
        { "symbolic_taint",              test_symbolic_taint              },
        { "symbolic_taint_rdx",          test_symbolic_taint_rdx          },
        { "symbolic_opaque_predicate",   test_symbolic_opaque_predicate   },
        { "symbolic_solve_for_path",     test_symbolic_solve_for_path     },
        { "symbolic_state_check",        test_symbolic_state_check        },
        { "deobfusc_strip_junk",         test_deobfusc_strip_junk         },
        { "deobfusc_resolve_constants",  test_deobfusc_resolve_constants  },
        { "deobfusc_deobfuscate_fn",     test_deobfusc_deobfuscate_function },
        { "deobfusc_export_asm",         test_deobfusc_export_asm         },
        { "deobfusc_export_stats",       test_deobfusc_export_stats       },
        { "code_patcher_create_revert",  test_code_patcher_create_apply_revert },
        { "code_patcher_nop",            test_code_patcher_nop            },
        { "code_patcher_find_caves",     test_code_patcher_find_caves     },
        { "code_patcher_format_parse",   test_code_patcher_format_parse   },
        { "code_patcher_count",          test_code_patcher_count          },
        { "integrity_hunter_state",      test_integrity_hunter_state      },
        { "integrity_hunter_start_stop", test_integrity_hunter_start_stop, 20000 },
        { "integrity_hunter_nodes",      test_integrity_hunter_nodes, 45000 },
        { "binary_map_generate",         test_binary_map_generate         },
        { "binary_map_options",          test_binary_map_options          },
        { "binary_map_pin_unpin",        test_binary_map_pin_unpin        },
        { "binary_map_clear_cache",      test_binary_map_clear_cache      },
        { "binary_map_render_text",      test_binary_map_render_text      },
        { "source_reconstructor_status", test_source_reconstructor_status },
        { "source_recon_running",        test_source_reconstructor_running },
        { "source_recon_last_result",    test_source_reconstructor_last_result, 22000 },
        { "xref_find",                   test_xref_find                   },
        { "xref_engine_scan_state",      test_xref_engine_scan_state      },
        { "xref_type_names",             test_xref_type_names             },
        { "xref_db_state",               test_xref_db_state               },
        { "xref_db_query_to",            test_xref_db_query_to            },
        { "comment_store",               test_comment_store               },
        { "comment_store_multiple",      test_comment_store_multiple      },
        { "comment_store_overwrite",     test_comment_store_overwrite     },
        { "rename_store",                test_rename_store                },
        { "rename_store_resolve_or",     test_rename_store_resolve_or     },
        { "expression_eval_hex",         test_expression_eval_hex         },
        { "expression_eval_register",    test_expression_eval_register    },
        { "expression_eval_multiply",    test_expression_eval_multiply    },
        { "expression_eval_bitwise",     test_expression_eval_bitwise     },
        { "expression_eval_shift",       test_expression_eval_shift       },
        { "expression_eval_nested_paren",test_expression_eval_nested_parens},
        { "expression_eval_xor",         test_expression_eval_xor         },
        { "expression_eval_multi_reg",   test_expression_eval_multi_register },
        { "fuzzer_state",                test_fuzzer_state                },
        { "fuzzer_config",               test_fuzzer_config               },
        { "stealth_state",               test_stealth_state               },
        { "stealth_options_default",     test_stealth_options_default     },
        { "struct_recon_state",          test_struct_recon_state          },
        { "struct_recon_field_types",    test_struct_recon_field_types    },
        { "decrypt_oracle_state",        test_decrypt_oracle_state        },
        { "decrypt_oracle_config",       test_decrypt_oracle_config       },
        { "pdb_resolve_cache_path",      test_pdb_resolve_cache_path      },
        { "quality_semantic_bounded",    test_semantic_fusion_bounded_deterministic },
        { "quality_semantic_cancel",     test_semantic_fusion_cancellation_deadline },
        { "quality_feedback_ranges",     test_decompiler_feedback_range_publication },
        { "quality_pseudocode_typed",    test_pseudocode_typed_ast_rendering },
        { "quality_type_evidence",       test_type_recovery_semantic_cfg_cc_binding, 15000 },
        { "quality_service_errors",      test_stale_revisions_and_decompiler_errors },
        { "memory_scale_hot_cold_golden", test_memory_scale_hot_cold_golden },
        { "memory_scale_residency_plan", test_memory_scale_residency_plan },
        { "memory_scale_paged_staging",  test_memory_scale_paged_staging, 20000 },
        { "memory_scale_publication_index_differential", test_memory_scale_publication_index_differential, 60000 },

        { "analysis_hub_tab_symbolic",   test_analysis_hub_tab_symbolic   },
        { "analysis_hub_tab_taint",      test_analysis_hub_tab_taint      },
        { "analysis_hub_tab_deobfusc",   test_analysis_hub_tab_deobfuscation },
        { "analysis_hub_tab_fuzzer",     test_analysis_hub_tab_fuzzer     },
        { "analysis_hub_tab_protection", test_analysis_hub_tab_protection },
        { "types_hub_tab_structs",       test_types_hub_tab_structs       },
        { "types_hub_tab_unions",        test_types_hub_tab_unions        },
        { "types_hub_tab_enums",         test_types_hub_tab_enums         },
        { "types_hub_tab_typedefs",      test_types_hub_tab_typedefs      },
        { "types_hub_tab_functions",     test_types_hub_tab_functions     },
        { "types_hub_tab_inferred",      test_types_hub_tab_inferred      },
        { "types_hub_tab_dissector",     test_types_hub_tab_dissector     },
        { "symbolic_inner_trace",        test_symbolic_inner_trace        },
        { "symbolic_inner_deobfusc",     test_symbolic_inner_deobfuscation },
        { "symbolic_inner_slice",        test_symbolic_inner_slice        },
        { "symbolic_inner_solver",       test_symbolic_inner_solver       },
        { "symbolic_inner_constraints",  test_symbolic_inner_constraints  },
        { "symbolic_inner_expression",   test_symbolic_inner_expression   },
        { "protection_inner_scan",       test_protection_inner_scan       },
        { "protection_inner_controls",   test_protection_inner_controls   },
        { "analysis_benchmark_real_300mb", test_analysis_benchmark_real_300mb, 1200000 },
        { "analysis_fast_containers_bench", test_analysis_fast_containers_bench, 120000 },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    (void)skipped;
    log_msg(hf, "analysis", "=== BEGIN analysis tests (%d tests) ===", total);
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            failed.fetch_add(remaining);
            log_msg(hf, "analysis", "FAIL -- cancellation requested mid-analysis-phase with %d test(s) remaining; cancellation is a defect in the sanctioned full-test run pid=%lu tid=%lu",
                remaining,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()));
            break;
        }

        log_msg(hf, "analysis", "[%d/%d] %s", i + 1, total, tests[i].name);
        const ULONGLONG t0 = GetTickCount64();
        const int pass_before = passed.load(std::memory_order_acquire);
        const int fail_before = failed.load(std::memory_order_acquire);
        run_analysis_test_bounded(hf, tests[i], passed, failed, tests[i].timeout_ms);
        log_msg(hf, "analysis", "[%d/%d] END %s elapsed_ms=%llu pass_delta=%d fail_delta=%d",
            i + 1, total, tests[i].name,
            static_cast<unsigned long long>(GetTickCount64() - t0),
            passed.load(std::memory_order_acquire) - pass_before,
            failed.load(std::memory_order_acquire) - fail_before);
    }

    log_msg(hf, "analysis", "analysis phase benchmark coverage: real_300mb=%s detail=%s",
        benchmark_real_state_name(g_benchmark_real_state), g_benchmark_real_detail.c_str());
    log_msg(hf, "analysis", "=== END analysis tests ===");
}

}
