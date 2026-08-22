#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/freetype/freetype.h"
#include "verdana.h"
#include "ide_icons.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <algorithm>
#include "helpers/helpers.h"
#include <shellscalingapi.h>
#include "helpers/globals.h"
#include "core/ui/clock.hpp"
#include "core/ui/motion.hpp"
#include "core/ui/transition.hpp"
#include "core/ui/theme.hpp"
#include "core/ui/ui_thread_dispatcher.hpp"
#include "core/ui/components.hpp"
#include "core/ui/fonts.hpp"
#include "core/ui/ide_shell.hpp"
#include "standalone_chat.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "standalone_tools_fwd.hpp"
#include "core/runtime/diagnostic_exception_scope.hpp"
#include "core/mcp/mcp_standalone.hpp"
#include "core/tools/command_sessions.hpp"
#include "network_view.hpp"
#include "memory_scanner.hpp"
#include "mitm_proxy.hpp"
#include "script_engine.hpp"
#include "toast_notification.hpp"
#include "source_reconstruct_view.hpp"
#include "command_palette_view.hpp"
#include "agent_picker_view.hpp"
#include "settings_overlay.hpp"
#include "core/infra/taskflow_runtime.hpp"
#include "core/testlab/test_all_features.hpp"
#include "core/network/burp/camoufox_bridge.hpp"
#include "helpers/stb_image.h"
#include <dxgi.h>

#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "core/disasm/function_index.hpp"
#include "core/analysis/pdb_parser.hpp"
#include "core/auth/auth_http.hpp"
#include "core/ui/loading_binary_overlay.hpp"
#include "core/diagnostics/metadata_ring.hpp"
#include "core/diagnostics/wer_correlation.hpp"
#include "core/diagnostics/crash_snapshot.hpp"
#include "core/diagnostics/window_hung_snapshot.hpp"
#include "core/diagnostics/observer.hpp"
#include "core/infra/executor.hpp"
#include "core/infra/taskflow_evaluation.hpp"
#include <shellapi.h>
#include <shobjidl.h>
#include <dbghelp.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")

extern "C" {
#include <openssl/applink.c>
}

namespace test_all_features {
    void format_ui_phase_snapshot(char* out, std::size_t cap);
}

#include <thread>
#include <cstdarg>
#include <atomic>
#include <exception>
#include <functional>
#include <cwchar>
#include <cstring>
#include <cstdint>
#include <string>
#include <mutex>
#include <deque>
#include <utility>
#include <vector>
#if defined(_M_X64)
#include <intrin.h>
#endif

#pragma comment(lib, "Shcore.lib")

namespace aida_early_startup {

static constexpr DWORD kMaxLogBytes = 1024u * 1024u;
static std::atomic<const char*> g_phase{ "image_static_init_pending" };
static std::atomic<bool> g_veh_installed{ false };
static std::atomic<bool> g_fatal_exception_written{ false };
static std::atomic<bool> g_status_exception_written{ false };
static std::atomic<bool> g_unhandled_exception_written{ false };
static std::atomic<bool> g_normal_diagnostics_reached{ false };
static std::atomic<long> g_write_active{ 0 };

static size_t bounded_strlen(const char* s, size_t cap)
{
    if (!s)
        return 0;
    size_t n = 0;
    while (n < cap && s[n] != '\0')
        ++n;
    return n;
}

static size_t bounded_wcslen(const wchar_t* s, size_t cap)
{
    if (!s)
        return 0;
    size_t n = 0;
    while (n < cap && s[n] != L'\0')
        ++n;
    return n;
}

static uint64_t fnv1a_wide(const wchar_t* s, size_t cap)
{
    uint64_t h = 14695981039346656037ULL;
    if (!s)
        return h;
    for (size_t i = 0; i < cap && s[i] != L'\0'; ++i) {
        wchar_t ch = s[i];
        h ^= static_cast<uint8_t>(ch & 0xFFu);
        h *= 1099511628211ULL;
        h ^= static_cast<uint8_t>((ch >> 8) & 0xFFu);
        h *= 1099511628211ULL;
    }
    return h;
}

static void wide_to_utf8(const wchar_t* in, char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    int wrote = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in, -1, out, static_cast<int>(cap), nullptr, nullptr);
    if (wrote <= 0)
        wrote = WideCharToMultiByte(CP_ACP, 0, in, -1, out, static_cast<int>(cap), nullptr, nullptr);
    if (wrote <= 0)
        _snprintf_s(out, cap, _TRUNCATE, "<wide_conversion_failed_gle_%lu>", GetLastError());
}

static bool build_exe_log_path(wchar_t* out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = L'\0';
    wchar_t exe[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return false;
    wchar_t* last = wcsrchr(exe, L'\\');
    if (!last)
        return false;
    *(last + 1) = L'\0';
    _snwprintf_s(out, cap, _TRUNCATE, L"%saida_early_startup.log", exe);
    return out[0] != L'\0';
}

static bool append_file(const wchar_t* path, const char* line)
{
    if (!path || !line)
        return false;
    size_t len = bounded_strlen(line, 8192);
    if (len == 0)
        return false;
    DWORD creation = OPEN_ALWAYS;
    WIN32_FILE_ATTRIBUTE_DATA existing{};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &existing)) {
        ULARGE_INTEGER size{};
        size.LowPart = existing.nFileSizeLow;
        size.HighPart = existing.nFileSizeHigh;
        if (size.QuadPart > kMaxLogBytes)
            creation = CREATE_ALWAYS;
    }
    HANDLE h = CreateFileW(path,
        FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, line, static_cast<DWORD>(len), &written, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
    return ok && written == static_cast<DWORD>(len);
}

static size_t image_size_from_headers(HMODULE image)
{
    if (!image)
        return 0;
    __try {
        auto* base = reinterpret_cast<const uint8_t*>(image);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
            return 0;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        return static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "early_image_size_seh");
        return 0;
    }
}

static void token_elevation_and_session(int& elevated, DWORD& session, int& session_ok)
{
    elevated = -1;
    session = 0xFFFFFFFFu;
    session_ok = 0;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD cb = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &cb))
            elevated = te.TokenIsElevated ? 1 : 0;
        CloseHandle(token);
    }
    DWORD sid = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) {
        session = sid;
        session_ok = 1;
    }
}

static void write_line(const char* event_name, const char* detail)
{
    if (g_write_active.exchange(1, std::memory_order_acq_rel) != 0)
        return;

    wchar_t exe[MAX_PATH] = {};
    wchar_t cwd[MAX_PATH] = {};
    DWORD exe_len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    DWORD exe_gle = exe_len ? 0 : GetLastError();
    DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, cwd);
    DWORD cwd_gle = (cwd_len > 0 && cwd_len < MAX_PATH) ? 0 : GetLastError();
    const wchar_t* cmd = GetCommandLineW();
    const size_t cmd_len = bounded_wcslen(cmd, 32768);
    const uint64_t cmd_hash = fnv1a_wide(cmd, 32768);
    int elevated = -1;
    DWORD session = 0xFFFFFFFFu;
    int session_ok = 0;
    token_elevation_and_session(elevated, session, session_ok);

    HMODULE image = GetModuleHandleW(nullptr);
    const uintptr_t image_base = reinterpret_cast<uintptr_t>(image);
    const size_t image_size = image_size_from_headers(image);
    const uintptr_t image_end = image_base + image_size;
    MEMORY_BASIC_INFORMATION mbi{};
    if (image)
        VirtualQuery(image, &mbi, sizeof(mbi));

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    BOOL fad_ok = exe_len > 0 && exe_len < MAX_PATH
        ? GetFileAttributesExW(exe, GetFileExInfoStandard, &fad)
        : FALSE;

    char exe_u8[1024] = {};
    char cwd_u8[1024] = {};
    wide_to_utf8(exe, exe_u8, sizeof(exe_u8));
    wide_to_utf8(cwd, cwd_u8, sizeof(cwd_u8));

    SYSTEMTIME st{};
    GetLocalTime(&st);
    const char* phase = g_phase.load(std::memory_order_acquire);
    const bool normal_diag = g_normal_diagnostics_reached.load(std::memory_order_acquire);
    char line[8192] = {};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [early_startup] event=%s phase=%s detail=%s normal_diag=%d pid=%lu tid=%lu tick=%llu exe_len=%lu exe_gle=%lu exe=%s module=%s cwd_len=%lu cwd_gle=%lu cwd=%s cmd_len=%llu cmd_hash=0x%016llX elevated=%d session=%lu session_ok=%d image_base=0x%016llX image_end=0x%016llX image_size=0x%llX mbi_base=0x%016llX mbi_alloc=0x%016llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX exe_write_ok=%d exe_write_ft=0x%08lX%08lX build=%s_%s\r\n",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        event_name ? event_name : "<null>",
        phase ? phase : "<null>",
        detail ? detail : "<null>",
        normal_diag ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        static_cast<unsigned long>(exe_len),
        static_cast<unsigned long>(exe_gle),
        exe_u8,
        exe_u8,
        static_cast<unsigned long>(cwd_len),
        static_cast<unsigned long>(cwd_gle),
        cwd_u8,
        static_cast<unsigned long long>(cmd_len),
        static_cast<unsigned long long>(cmd_hash),
        elevated,
        static_cast<unsigned long>(session),
        session_ok,
        static_cast<unsigned long long>(image_base),
        static_cast<unsigned long long>(image_end),
        static_cast<unsigned long long>(image_size),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(mbi.RegionSize),
        static_cast<unsigned long>(mbi.State),
        static_cast<unsigned long>(mbi.Protect),
        fad_ok ? 1 : 0,
        fad_ok ? fad.ftLastWriteTime.dwHighDateTime : 0,
        fad_ok ? fad.ftLastWriteTime.dwLowDateTime : 0,
        __DATE__,
        __TIME__);

    wchar_t path[MAX_PATH] = {};
    if (build_exe_log_path(path, _countof(path)))
        append_file(path, line);

    g_write_active.store(0, std::memory_order_release);
}

static bool is_fatal_exception_code(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
        return true;
    default:
        return code == 0xC0000409u || code == 0x40000015u;
    }
}

static bool is_status_exception_code(DWORD code)
{
    return code == STATUS_SINGLE_STEP || code == EXCEPTION_BREAKPOINT || code == STATUS_GUARD_PAGE_VIOLATION;
}

static void write_exception_line(const char* handler, EXCEPTION_POINTERS* ep, bool allow_all)
{
    if (!ep || !ep->ExceptionRecord)
        return;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const bool fatal = is_fatal_exception_code(code);
    const bool status = is_status_exception_code(code);
    if (!allow_all && !fatal && !status)
        return;
    std::atomic<bool>* gate = allow_all ? &g_unhandled_exception_written : (fatal ? &g_fatal_exception_written : &g_status_exception_written);
    bool expected = false;
    if (!gate->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    CONTEXT* ctx = ep->ContextRecord;
    uintptr_t rip = 0;
    uintptr_t rsp = 0;
    uintptr_t rbp = 0;
#if defined(_M_X64)
    if (ctx) {
        rip = static_cast<uintptr_t>(ctx->Rip);
        rsp = static_cast<uintptr_t>(ctx->Rsp);
        rbp = static_cast<uintptr_t>(ctx->Rbp);
    }
#endif
    const uintptr_t addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    HMODULE crash_mod = nullptr;
    wchar_t crash_mod_w[MAX_PATH] = L"<unknown>";
    char crash_mod_u8[1024] = "<unknown>";
    if (ep->ExceptionRecord->ExceptionAddress &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(ep->ExceptionRecord->ExceptionAddress),
            &crash_mod) &&
        crash_mod) {
        GetModuleFileNameW(crash_mod, crash_mod_w, MAX_PATH);
        wide_to_utf8(crash_mod_w, crash_mod_u8, sizeof(crash_mod_u8));
    }
    const uintptr_t crash_mod_base = reinterpret_cast<uintptr_t>(crash_mod);
    const uintptr_t module_off = crash_mod_base && addr >= crash_mod_base ? addr - crash_mod_base : 0;
    const unsigned long params = static_cast<unsigned long>(ep->ExceptionRecord->NumberParameters);
    const unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
        : 0ULL;
    const unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        : 0ULL;
    char detail[1024] = {};
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
        "handler=%s exception code=0x%08lX fatal=%d status=%d flags=0x%08lX addr=0x%016llX rip=0x%016llX rsp=0x%016llX rbp=0x%016llX module=%s module_off=0x%llX params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu",
        handler ? handler : "<null>",
        static_cast<unsigned long>(code),
        fatal ? 1 : 0,
        status ? 1 : 0,
        static_cast<unsigned long>(ep->ExceptionRecord->ExceptionFlags),
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rsp),
        static_cast<unsigned long long>(rbp),
        crash_mod_u8,
        static_cast<unsigned long long>(module_off),
        params,
        p0,
        p1,
        GetLastError());
    write_line(allow_all ? "unhandled_exception" : (fatal ? "veh_first_chance_fatal_exception" : "veh_first_chance_status_exception"), detail);
}

static LONG CALLBACK early_veh(EXCEPTION_POINTERS* ep)
{
    write_exception_line("early_veh", ep, false);
    if (ep && ep->ExceptionRecord)
        aida::diagnostics::crash::emit_crash_breadcrumb(ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress, "early_veh");
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI early_unhandled(EXCEPTION_POINTERS* ep)
{
    write_exception_line("early_unhandled", ep, true);
    if (ep && ep->ExceptionRecord)
        aida::diagnostics::crash::emit_crash_breadcrumb(ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress, "early_unhandled");
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install()
{
    bool expected = false;
    PVOID veh = nullptr;
    bool added_veh = g_veh_installed.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
    if (added_veh)
        veh = AddVectoredExceptionHandler(1, early_veh);
    SetUnhandledExceptionFilter(early_unhandled);
    char detail[160] = {};
    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "early_veh=0x%016llX early_veh_added=%d unhandled_set=1 gle=%lu", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(veh)), added_veh ? 1 : 0, GetLastError());
    write_line("install", detail);
}

static void mark(const char* phase)
{
    g_phase.store(phase ? phase : "<null>", std::memory_order_release);
    write_line("phase", phase ? phase : "<null>");
}

static void mark_normal_diagnostics_reached()
{
    g_normal_diagnostics_reached.store(true, std::memory_order_release);
    mark("normal_diag_reached");
}

struct bootstrap_t {
    bootstrap_t()
    {
        g_phase.store("static_ctor_enter", std::memory_order_release);
        install();
        mark("static_ctor_exit");
    }
};

static bootstrap_t g_bootstrap;

}

ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static std::atomic<UINT>        g_PendingFontDpi{0};
static std::atomic<UINT>        g_AppliedFontDpi{0};
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ID3D11BlendState* blend_state = nullptr;
static HICON g_aidaWindowIcon = nullptr;
static bool g_imgui_win32_initialized = false;

helpers helper;
HWND g_hwnd = nullptr;
wchar_t g_aidaWindowTitle[128] = L"AiDA";
wchar_t g_aidaClassName[128] = L"AiDA";
static constexpr const wchar_t* kAidaWindowTitle = g_aidaWindowTitle;
static constexpr int kAidaFullTestHotkeyId = 0xA1DA;
static constexpr UINT kAidaUiDispatcherWakeMessage = WM_APP + 0x1DB;
static constexpr UINT kAidaQueuedPeekFlags = PM_REMOVE | PM_QS_INPUT | PM_QS_POSTMESSAGE | PM_QS_PAINT | PM_QS_TIMER | PM_QS_SENDMESSAGE;
static constexpr UINT kAidaSendOnlyPeekFlags = PM_REMOVE | PM_QS_SENDMESSAGE;
static constexpr DWORD kAidaNonSendQueueBits = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY | QS_ALLPOSTMESSAGE;
static constexpr DWORD kAidaPumpQueueBits = kAidaNonSendQueueBits | QS_SENDMESSAGE;
static constexpr DWORD kAidaInteractiveQueueBits = QS_INPUT | QS_POSTMESSAGE | QS_HOTKEY | QS_ALLPOSTMESSAGE;
static constexpr UINT kAidaPresentSyncInterval = 1;
static constexpr UINT kAidaPresentFlags = 0;
static constexpr DWORD kAidaInteractiveWaitMs = 1;
static constexpr DWORD kAidaActiveWaitMs = 8;
static constexpr DWORD kAidaIdleWaitMs = 16;
static constexpr DWORD kAidaPreRenderWaitMs = 16;
static constexpr uint64_t kAidaOcclusionInteractiveLogIntervalMs = 5000ULL;
static constexpr DWORD kAidaMessagePumpBudgetMs = 4;
static constexpr DWORD kAidaMidFramePumpBudgetMs = 2;
static constexpr uint32_t kAidaMessagePumpBudgetMessages = 192;
static constexpr uint32_t kAidaMidFramePumpBudgetMessages = 32;
static constexpr uint64_t kAidaRecentInputWakeMs = 250ULL;
static constexpr uint64_t kAidaInteractiveRenderCadenceMs = 16ULL;
static constexpr DWORD kAidaResizeCoalesceMs = 16;
static constexpr uint64_t kAidaResizeChurnWindowMs = 1000ULL;
static constexpr uint32_t kAidaResizeChurnThreshold = 4;
static constexpr uint64_t kAidaRuntimeAcceptanceLogIntervalMs = 30000ULL;
static constexpr uint64_t kAidaIdleHeartbeatMs = 250ULL;
static constexpr uint64_t kAidaFullTestHeartbeatMs = 250ULL;
static constexpr uint64_t kAidaModalHeartbeatMs = 16ULL;
static constexpr uint64_t kAidaMenuPopupHeartbeatMs = 125ULL;
static constexpr uint64_t kAidaFramePacingLogIntervalMs = 30000ULL;
static constexpr uint64_t kAidaPacingAnomalyLogIntervalMs = 30000ULL;
static constexpr uint64_t kAidaInputMotionLogIntervalMs = 1000ULL;
static constexpr uint64_t kAidaInputMotionLagLogIntervalMs = 250ULL;
static constexpr uint64_t kAidaExpectedCallbackLogIntervalMs = 30000ULL;
static constexpr uint64_t kAidaDirtySkipAnomalyLogIntervalMs = 30000ULL;
static constexpr uint32_t kAidaDirtyStartup = 0x00000001u;
static constexpr uint32_t kAidaDirtyMessage = 0x00000002u;
static constexpr uint32_t kAidaDirtyResize = 0x00000004u;
static constexpr uint32_t kAidaDirtyState = 0x00000008u;
static constexpr uint32_t kAidaDirtyInput = 0x00000010u;
static constexpr uint32_t kAidaDirtyCursor = 0x00000020u;
static constexpr uint32_t kAidaDirtyOverlay = 0x00000040u;
static constexpr uint32_t kAidaDirtyTheme = 0x00000080u;
static constexpr uint32_t kAidaDirtyModal = 0x00000100u;
static constexpr uint32_t kAidaDirtyProgress = 0x00000200u;
static constexpr uint32_t kAidaDirtyHeartbeat = 0x00000400u;
static constexpr uint32_t kAidaDirtyWork = 0x00000800u;
static constexpr uint32_t kAidaDirtySecurity = 0x00001000u;
static constexpr uint32_t kAidaDirtyInteractiveCadence = 0x00002000u;

namespace aida::ui_thread {

namespace {

struct ui_dispatch_task_t {
    std::uint64_t id = 0;
    DWORD producer_pid = 0;
    DWORD producer_tid = 0;
    DWORD ui_owner_tid_at_enqueue = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t deadline_ms = 0;
    std::string subsystem;
    std::string label;
    std::string phase;
    std::string owner;
    priority_t priority = priority_t::normal;
    bool cancellation_registered = false;
    std::function<bool()> cancelled;
    task_t task;
};

static constexpr std::size_t kUiDispatchMaxDepth = 2048;
static constexpr std::size_t kUiDispatchPressureDepth = 128;
static constexpr std::uint64_t kUiDispatchPressureIntervalMs = 1000;
static constexpr std::uint64_t kUiDispatchBacklogIntervalMs = 1000;
static std::mutex g_ui_dispatch_mtx;
static std::deque<ui_dispatch_task_t> g_ui_dispatch_queue;
static std::atomic<DWORD> g_ui_owner_tid{0};
static std::atomic<UINT_PTR> g_ui_dispatch_hwnd{0};
static std::atomic<bool> g_ui_dispatch_ready{false};
static std::atomic<bool> g_ui_dispatch_window_destroying{false};
static std::atomic<bool> g_ui_dispatch_wake_pending{false};
static std::atomic<bool> g_ui_dispatch_shutdown{false};
static std::atomic<std::uint64_t> g_ui_dispatch_next_id{0};
static std::atomic<std::uint64_t> g_ui_dispatch_enqueued{0};
static std::atomic<std::uint64_t> g_ui_dispatch_executed{0};
static std::atomic<std::uint64_t> g_ui_dispatch_discarded{0};
static std::atomic<std::uint64_t> g_ui_dispatch_rejected{0};
static std::atomic<std::uint64_t> g_ui_dispatch_rejected_shutdown{0};
static std::atomic<std::uint64_t> g_ui_dispatch_rejected_full{0};
static std::atomic<std::uint64_t> g_ui_dispatch_rejected_not_ready{0};
static std::atomic<std::uint64_t> g_ui_dispatch_rejected_cancelled{0};
static std::atomic<std::uint64_t> g_ui_dispatch_wake_posted{0};
static std::atomic<std::uint64_t> g_ui_dispatch_wake_thread_posted{0};
static std::atomic<std::uint64_t> g_ui_dispatch_wake_failed{0};
static std::atomic<std::uint64_t> g_ui_dispatch_wake_coalesced{0};
static std::atomic<std::uint64_t> g_ui_dispatch_drain_calls{0};
static std::atomic<std::uint64_t> g_ui_dispatch_drain_cancelled{0};
static std::atomic<std::uint64_t> g_ui_dispatch_budget_hits{0};
static std::atomic<std::uint64_t> g_ui_dispatch_backlog_logs{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_drain_ms{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_task_ms{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_task_id{0};
static std::atomic<std::size_t> g_ui_dispatch_last_depth{0};
static std::atomic<std::size_t> g_ui_dispatch_max_depth{0};
static std::atomic<std::uint64_t> g_ui_dispatch_oldest_queued_ms{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_backlog_log_ms{0};
static std::atomic<std::uint64_t> g_ui_dispatch_active_task_id{0};
static std::atomic<DWORD> g_ui_dispatch_active_producer_tid{0};
static std::atomic<std::uint64_t> g_ui_dispatch_active_started_ms{0};
static std::atomic<std::uint64_t> g_ui_dispatch_affinity_violations{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_drain_ts{0};
static std::atomic<std::uint64_t> g_ui_dispatch_last_wake_ts{0};
static std::atomic<std::uint64_t> g_ui_dispatch_task_budget_hits{0};
static std::atomic<std::uint64_t> g_ui_dispatch_time_budget_hits{0};

static std::uint64_t ui_dispatch_now_ms()
{
    return static_cast<std::uint64_t>(::GetTickCount64());
}

static const char* ui_dispatch_text(const char* value)
{
    return value && value[0] ? value : "<none>";
}

static const char* ui_dispatch_text(const std::string& value)
{
    return value.empty() ? "<none>" : value.c_str();
}

static std::string ui_dispatch_copy_text(const char* value, const char* fallback)
{
    const char* source = value && value[0] ? value : fallback;
    std::string out = source ? source : "";
    if (out.size() > 96)
        out.resize(96);
    for (char& ch : out) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7F)
            ch = '_';
    }
    return out;
}

static int ui_dispatch_priority_rank(priority_t priority)
{
    switch (priority) {
    case priority_t::critical: return 3;
    case priority_t::high: return 2;
    case priority_t::normal: return 1;
    case priority_t::low: return 0;
    default: return 1;
    }
}

static void ui_dispatch_refresh_metrics_locked()
{
    const std::size_t depth = g_ui_dispatch_queue.size();
    g_ui_dispatch_last_depth.store(depth, std::memory_order_release);
    std::size_t max_depth = g_ui_dispatch_max_depth.load(std::memory_order_acquire);
    while (depth > max_depth && !g_ui_dispatch_max_depth.compare_exchange_weak(max_depth, depth, std::memory_order_acq_rel)) {
    }
    std::uint64_t oldest = 0;
    for (const ui_dispatch_task_t& task : g_ui_dispatch_queue) {
        if (task.queued_ms != 0 && (oldest == 0 || task.queued_ms < oldest))
            oldest = task.queued_ms;
    }
    g_ui_dispatch_oldest_queued_ms.store(oldest, std::memory_order_release);
}

static std::uint64_t ui_dispatch_oldest_age_ms(std::uint64_t now)
{
    const std::uint64_t oldest = g_ui_dispatch_oldest_queued_ms.load(std::memory_order_acquire);
    if (oldest == 0 || now < oldest)
        return 0;
    return now - oldest;
}

static void ui_dispatch_count_reject(enqueue_result_t result)
{
    g_ui_dispatch_rejected.fetch_add(1, std::memory_order_acq_rel);
    switch (result) {
    case enqueue_result_t::rejected_shutdown:
        g_ui_dispatch_rejected_shutdown.fetch_add(1, std::memory_order_acq_rel);
        break;
    case enqueue_result_t::rejected_full:
        g_ui_dispatch_rejected_full.fetch_add(1, std::memory_order_acq_rel);
        break;
    case enqueue_result_t::rejected_not_ui_ready:
        g_ui_dispatch_rejected_not_ready.fetch_add(1, std::memory_order_acq_rel);
        break;
    case enqueue_result_t::rejected_cancelled:
        g_ui_dispatch_rejected_cancelled.fetch_add(1, std::memory_order_acq_rel);
        break;
    default:
        break;
    }
}

static void ui_dispatch_log_reject(enqueue_result_t result,
    const char* reason,
    const ui_dispatch_task_t& task,
    std::size_t depth)
{
    ui_dispatch_count_reject(result);
    const std::uint64_t now = ui_dispatch_now_ms();
    diag::log_tagged_critical_fmt("ui_dispatcher",
        "UI-DISPATCHER-REJECT result=%s reason=%s task_id=%llu label=\"%.96s\" owner=\"%.96s\" subsystem=\"%.96s\" phase=\"%.96s\" priority=%s enqueue_pid=%lu enqueue_tid=%lu ui_owner_tid=%lu queued_ms=%llu now_ms=%llu deadline_ms=%llu cancellation=%d ready=%d shutdown=%d destroying=%d depth=%zu oldest_age_ms=%llu rejected_shutdown=%llu rejected_full=%llu rejected_not_ui_ready=%llu rejected_cancelled=%llu",
        result_name(result),
        ui_dispatch_text(reason),
        static_cast<unsigned long long>(task.id),
        ui_dispatch_text(task.label),
        ui_dispatch_text(task.owner),
        ui_dispatch_text(task.subsystem),
        ui_dispatch_text(task.phase),
        priority_name(task.priority),
        static_cast<unsigned long>(task.producer_pid),
        static_cast<unsigned long>(task.producer_tid),
        static_cast<unsigned long>(task.ui_owner_tid_at_enqueue),
        static_cast<unsigned long long>(task.queued_ms),
        static_cast<unsigned long long>(now),
        static_cast<unsigned long long>(task.deadline_ms),
        task.cancellation_registered ? 1 : 0,
        g_ui_dispatch_ready.load(std::memory_order_acquire) ? 1 : 0,
        g_ui_dispatch_shutdown.load(std::memory_order_acquire) ? 1 : 0,
        g_ui_dispatch_window_destroying.load(std::memory_order_acquire) ? 1 : 0,
        depth,
        static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(now)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_shutdown.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_full.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_not_ready.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_cancelled.load(std::memory_order_acquire)));
}

static bool ui_dispatch_cancelled(const ui_dispatch_task_t& task, std::uint64_t now, const char** reason_out)
{
    if (task.deadline_ms != 0 && now >= task.deadline_ms) {
        if (reason_out)
            *reason_out = "deadline_expired";
        return true;
    }
    if (!task.cancelled)
        return false;
    bool cancelled_now = true;
    try {
        cancelled_now = task.cancelled();
    } catch (const std::exception& ex) {
        diag::log_tagged_critical_fmt("ui_dispatcher",
            "UI-DISPATCHER-REJECT result=%s reason=cancellation_probe_exception task_id=%llu label=\"%.96s\" owner=\"%.96s\" what=%.180s",
            result_name(enqueue_result_t::rejected_cancelled),
            static_cast<unsigned long long>(task.id),
            ui_dispatch_text(task.label),
            ui_dispatch_text(task.owner),
            ex.what());
    } catch (...) {
        aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "ui_dispatcher_cancellation_probe");
        diag::log_tagged_critical_fmt("ui_dispatcher",
            "UI-DISPATCHER-REJECT result=%s reason=cancellation_probe_exception task_id=%llu label=\"%.96s\" owner=\"%.96s\" what=<unknown>",
            result_name(enqueue_result_t::rejected_cancelled),
            static_cast<unsigned long long>(task.id),
            ui_dispatch_text(task.label),
            ui_dispatch_text(task.owner));
    }
    if (cancelled_now && reason_out)
        *reason_out = "cancelled";
    return cancelled_now;
}

static bool ui_dispatch_post_wake_locked(const char* subsystem, const char* label, const char* phase)
{
    if (g_ui_dispatch_shutdown.load(std::memory_order_acquire) ||
        g_ui_dispatch_window_destroying.load(std::memory_order_acquire) ||
        !g_ui_dispatch_ready.load(std::memory_order_acquire)) {
        g_ui_dispatch_wake_failed.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
            "UI-DISPATCHER-WAKE reason=blocked subsystem=%s label=%s phase=%s owner_tid=%lu ready=%d shutdown=%d destroying=%d depth=%zu wake_failed=%llu payload=0",
            ui_dispatch_text(subsystem),
            ui_dispatch_text(label),
            ui_dispatch_text(phase),
            static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
            g_ui_dispatch_ready.load(std::memory_order_acquire) ? 1 : 0,
            g_ui_dispatch_shutdown.load(std::memory_order_acquire) ? 1 : 0,
            g_ui_dispatch_window_destroying.load(std::memory_order_acquire) ? 1 : 0,
            g_ui_dispatch_last_depth.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)));
        return false;
    }
    if (g_ui_dispatch_wake_pending.exchange(true, std::memory_order_acq_rel)) {
        g_ui_dispatch_wake_coalesced.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("ui_dispatcher",
            "UI-DISPATCHER-WAKE reason=coalesced subsystem=%s label=%s phase=%s owner_tid=%lu depth=%zu oldest_age_ms=%llu wake_pending=1 coalesced=%llu payload=0",
            ui_dispatch_text(subsystem),
            ui_dispatch_text(label),
            ui_dispatch_text(phase),
            static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
            g_ui_dispatch_last_depth.load(std::memory_order_acquire),
            static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(ui_dispatch_now_ms())),
            static_cast<unsigned long long>(g_ui_dispatch_wake_coalesced.load(std::memory_order_acquire)));
        return true;
    }

    BOOL posted = FALSE;
    BOOL thread_posted = FALSE;
    DWORD gle = 0;
    DWORD thread_gle = 0;
    HWND hwnd = reinterpret_cast<HWND>(g_ui_dispatch_hwnd.load(std::memory_order_acquire));
    if (!hwnd)
        hwnd = g_hwnd;
    if (hwnd && ::IsWindow(hwnd) && !g_ui_dispatch_window_destroying.load(std::memory_order_acquire)) {
        ::SetLastError(0);
        posted = ::PostMessageW(hwnd, kAidaUiDispatcherWakeMessage, 0, 0);
        gle = posted ? 0UL : ::GetLastError();
    }
    if (!posted) {
        const DWORD tid = g_ui_owner_tid.load(std::memory_order_acquire);
        if (tid != 0) {
            ::SetLastError(0);
            thread_posted = ::PostThreadMessageW(tid, kAidaUiDispatcherWakeMessage, 0, 0);
            thread_gle = thread_posted ? 0UL : ::GetLastError();
        } else {
            thread_gle = ERROR_INVALID_THREAD_ID;
        }
    }

    if (!posted && !thread_posted) {
        g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
        g_ui_dispatch_wake_failed.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
            "UI-DISPATCHER-WAKE reason=failed subsystem=%s label=%s phase=%s hwnd=0x%llX owner_tid=%lu hwnd_gle=%lu thread_gle=%lu pending=%zu wake_failed=%llu tid=%lu payload=0",
            ui_dispatch_text(subsystem),
            ui_dispatch_text(label),
            ui_dispatch_text(phase),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long>(thread_gle),
            g_ui_dispatch_last_depth.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)),
            static_cast<unsigned long>(::GetCurrentThreadId()));
        return false;
    }

    if (posted)
        g_ui_dispatch_wake_posted.fetch_add(1, std::memory_order_acq_rel);
    if (thread_posted)
        g_ui_dispatch_wake_thread_posted.fetch_add(1, std::memory_order_acq_rel);
    g_ui_dispatch_last_wake_ts.store(ui_dispatch_now_ms(), std::memory_order_release);
    diag::log_tagged_critical_fmt("ui_dispatcher",
        "UI-DISPATCHER-WAKE reason=posted subsystem=%s label=%s phase=%s hwnd=0x%llX hwnd_posted=%d hwnd_gle=%lu thread_posted=%d thread_gle=%lu owner_tid=%lu wake_pending=%d depth=%zu oldest_age_ms=%llu posts=%llu thread_posts=%llu failures=%llu payload=0",
        ui_dispatch_text(subsystem),
        ui_dispatch_text(label),
        ui_dispatch_text(phase),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        posted ? 1 : 0,
        static_cast<unsigned long>(gle),
        thread_posted ? 1 : 0,
        static_cast<unsigned long>(thread_gle),
        static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
        g_ui_dispatch_wake_pending.load(std::memory_order_acquire) ? 1 : 0,
        g_ui_dispatch_last_depth.load(std::memory_order_acquire),
        static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(ui_dispatch_now_ms())),
        static_cast<unsigned long long>(g_ui_dispatch_wake_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_thread_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)));
    return true;
}

static void ui_dispatch_log_pressure(const char* event,
    const char* subsystem,
    const char* label,
    const char* phase,
    std::size_t depth,
    std::uint64_t id,
    std::uint64_t wait_ms,
    bool force)
{
    static std::atomic<std::uint64_t> s_last_pressure_log_ms{0};
    const std::uint64_t now = ui_dispatch_now_ms();
    std::uint64_t last = s_last_pressure_log_ms.load(std::memory_order_acquire);
    if (!force) {
        if (depth < kUiDispatchPressureDepth && now - last < kUiDispatchPressureIntervalMs)
            return;
        if (now - last < kUiDispatchPressureIntervalMs)
            return;
        if (!s_last_pressure_log_ms.compare_exchange_strong(last, now, std::memory_order_acq_rel))
            return;
    } else {
        s_last_pressure_log_ms.store(now, std::memory_order_release);
    }
    g_ui_dispatch_backlog_logs.fetch_add(1, std::memory_order_acq_rel);
    diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
        "event=%s subsystem=%s label=%s phase=%s id=%llu depth=%zu wait_ms=%llu owner_tid=%lu current_tid=%lu enqueued=%llu executed=%llu discarded=%llu rejected=%llu wake_pending=%d wake_posted=%llu wake_failed=%llu shutdown=%d",
        ui_dispatch_text(event),
        ui_dispatch_text(subsystem),
        ui_dispatch_text(label),
        ui_dispatch_text(phase),
        static_cast<unsigned long long>(id),
        depth,
        static_cast<unsigned long long>(wait_ms),
        static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long>(::GetCurrentThreadId()),
        static_cast<unsigned long long>(g_ui_dispatch_enqueued.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_executed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_discarded.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected.load(std::memory_order_acquire)),
        g_ui_dispatch_wake_pending.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(g_ui_dispatch_wake_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)),
        g_ui_dispatch_shutdown.load(std::memory_order_acquire) ? 1 : 0);
}

static void ui_affinity_log_marker(const char* marker,
    const char* subsystem,
    const char* label,
    const char* phase,
    std::size_t depth,
    DWORD gle)
{
    static std::atomic<std::uint64_t> s_last_violation_log_ms{0};
    static std::atomic<std::uint64_t> s_last_routed_log_ms{0};
    static std::atomic<std::uint64_t> s_violation_suppressed{0};
    static std::atomic<std::uint64_t> s_routed_suppressed{0};
    const bool routed = marker && std::strcmp(marker, "UI-AFFINITY-ROUTED") == 0;
    if (!routed)
        g_ui_dispatch_affinity_violations.fetch_add(1, std::memory_order_acq_rel);
    std::atomic<std::uint64_t>& last_ref = routed ? s_last_routed_log_ms : s_last_violation_log_ms;
    std::atomic<std::uint64_t>& suppressed_ref = routed ? s_routed_suppressed : s_violation_suppressed;
    const std::uint64_t now = ui_dispatch_now_ms();
    std::uint64_t last = last_ref.load(std::memory_order_acquire);
    if (last != 0 && now - last < 1000ULL) {
        suppressed_ref.fetch_add(1, std::memory_order_acq_rel);
        return;
    }
    if (!last_ref.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
        suppressed_ref.fetch_add(1, std::memory_order_acq_rel);
        return;
    }
    const std::uint64_t suppressed = suppressed_ref.exchange(0, std::memory_order_acq_rel);
    diag::log_tagged_critical_fmt("ui_affinity",
        "%s owner_tid=%lu current_tid=%lu subsystem=%s label=%s phase=%s queue_depth=%zu enqueued=%llu executed=%llu discarded=%llu rejected=%llu wake_pending=%d wake_posted=%llu wake_failed=%llu suppressed=%llu gle=%lu",
        marker ? marker : "UI-AFFINITY-VIOLATION",
        static_cast<unsigned long>(g_ui_owner_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long>(::GetCurrentThreadId()),
        ui_dispatch_text(subsystem),
        ui_dispatch_text(label),
        ui_dispatch_text(phase),
        depth,
        static_cast<unsigned long long>(g_ui_dispatch_enqueued.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_executed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_discarded.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected.load(std::memory_order_acquire)),
        g_ui_dispatch_wake_pending.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(g_ui_dispatch_wake_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(suppressed),
        static_cast<unsigned long>(gle));
}

}

const char* result_name(enqueue_result_t result)
{
    switch (result) {
    case enqueue_result_t::accepted: return "accepted";
    case enqueue_result_t::rejected_shutdown: return "rejected_shutdown";
    case enqueue_result_t::rejected_full: return "rejected_full";
    case enqueue_result_t::rejected_not_ui_ready: return "rejected_not_ui_ready";
    case enqueue_result_t::rejected_cancelled: return "rejected_cancelled";
    default: return "unknown";
    }
}

const char* priority_name(priority_t priority)
{
    switch (priority) {
    case priority_t::low: return "low";
    case priority_t::normal: return "normal";
    case priority_t::high: return "high";
    case priority_t::critical: return "critical";
    default: return "normal";
    }
}

void capture_owner_tid(DWORD tid, const char* subsystem, const char* label, const char* phase)
{
    if (tid == 0)
        return;
    DWORD expected = 0;
    if (g_ui_owner_tid.compare_exchange_strong(expected, tid, std::memory_order_acq_rel)) {
        diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
            "owner_capture subsystem=%s label=%s phase=%s previous_tid=%lu owner_tid=%lu current_tid=%lu",
            ui_dispatch_text(subsystem),
            ui_dispatch_text(label),
            ui_dispatch_text(phase),
            0UL,
            static_cast<unsigned long>(tid),
            static_cast<unsigned long>(::GetCurrentThreadId()));
        return;
    }
    if (expected != tid)
        ui_affinity_log_marker("UI-AFFINITY-VIOLATION", subsystem, label, phase, pending_count(), GetLastError());
}

DWORD owner_tid()
{
    return g_ui_owner_tid.load(std::memory_order_acquire);
}

bool is_owner_thread()
{
    const DWORD owner = owner_tid();
    return owner != 0 && owner == ::GetCurrentThreadId();
}

bool require_owner(const char* subsystem, const char* label, const char* phase)
{
    if (is_owner_thread())
        return true;
    g_ui_dispatch_rejected.fetch_add(1, std::memory_order_acq_rel);
    ui_affinity_log_marker("UI-AFFINITY-VIOLATION", subsystem, label, phase, pending_count(), GetLastError());
    return false;
}

enqueue_result_t post(task_t task, post_options_t options)
{
    const std::uint64_t queued_ms = ui_dispatch_now_ms();
    ui_dispatch_task_t item;
    item.id = g_ui_dispatch_next_id.fetch_add(1, std::memory_order_acq_rel) + 1;
    item.producer_pid = ::GetCurrentProcessId();
    item.producer_tid = ::GetCurrentThreadId();
    item.ui_owner_tid_at_enqueue = owner_tid();
    item.queued_ms = queued_ms;
    item.deadline_ms = options.deadline_ms;
    item.subsystem = ui_dispatch_copy_text(options.subsystem, "ui");
    item.label = ui_dispatch_copy_text(options.label, "task");
    item.phase = ui_dispatch_copy_text(options.phase, "unspecified");
    item.owner = ui_dispatch_copy_text(options.owner, item.subsystem.c_str());
    item.priority = options.priority;
    item.cancellation_registered = static_cast<bool>(options.cancelled);
    item.cancelled = std::move(options.cancelled);
    item.task = std::move(task);

    auto log_route_reject = [&](std::size_t depth, DWORD gle) {
        if (!is_owner_thread())
            ui_affinity_log_marker("UI-AFFINITY-VIOLATION",
                item.subsystem.c_str(),
                item.label.c_str(),
                item.phase.c_str(),
                depth,
                gle);
    };

    if (!item.task) {
        ui_dispatch_log_reject(enqueue_result_t::rejected_cancelled, "empty_task", item, pending_count());
        log_route_reject(g_ui_dispatch_last_depth.load(std::memory_order_acquire), ERROR_CANCELLED);
        return enqueue_result_t::rejected_cancelled;
    }
    if (g_ui_dispatch_shutdown.load(std::memory_order_acquire) || g_ui_dispatch_window_destroying.load(std::memory_order_acquire)) {
        ui_dispatch_log_reject(enqueue_result_t::rejected_shutdown, "shutdown_or_window_destroying", item, pending_count());
        log_route_reject(g_ui_dispatch_last_depth.load(std::memory_order_acquire), ERROR_SHUTDOWN_IN_PROGRESS);
        return enqueue_result_t::rejected_shutdown;
    }
    if (!g_ui_dispatch_ready.load(std::memory_order_acquire) || item.ui_owner_tid_at_enqueue == 0) {
        ui_dispatch_log_reject(enqueue_result_t::rejected_not_ui_ready, "ui_not_ready", item, pending_count());
        log_route_reject(g_ui_dispatch_last_depth.load(std::memory_order_acquire), ERROR_NOT_READY);
        return enqueue_result_t::rejected_not_ui_ready;
    }
    const char* cancel_reason = nullptr;
    if (ui_dispatch_cancelled(item, queued_ms, &cancel_reason)) {
        ui_dispatch_log_reject(enqueue_result_t::rejected_cancelled, cancel_reason ? cancel_reason : "cancelled", item, pending_count());
        log_route_reject(g_ui_dispatch_last_depth.load(std::memory_order_acquire), ERROR_CANCELLED);
        return enqueue_result_t::rejected_cancelled;
    }
    const std::uint64_t log_id = item.id;
    const DWORD log_pid = item.producer_pid;
    const DWORD log_tid = item.producer_tid;
    const DWORD log_owner_tid = item.ui_owner_tid_at_enqueue;
    const std::uint64_t log_deadline = item.deadline_ms;
    const std::string log_label = item.label;
    const std::string log_owner = item.owner;
    const std::string log_subsystem = item.subsystem;
    const std::string log_phase = item.phase;
    const priority_t log_priority = item.priority;
    const bool log_cancellation = item.cancellation_registered;

    std::size_t depth = 0;
    {
        std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
        if (g_ui_dispatch_shutdown.load(std::memory_order_acquire) || g_ui_dispatch_window_destroying.load(std::memory_order_acquire)) {
            ui_dispatch_refresh_metrics_locked();
            const std::size_t locked_depth = g_ui_dispatch_last_depth.load(std::memory_order_acquire);
            ui_dispatch_log_reject(enqueue_result_t::rejected_shutdown, "shutdown_or_window_destroying_locked", item, locked_depth);
            log_route_reject(locked_depth, ERROR_SHUTDOWN_IN_PROGRESS);
            return enqueue_result_t::rejected_shutdown;
        }
        if (!g_ui_dispatch_ready.load(std::memory_order_acquire) || owner_tid() == 0) {
            ui_dispatch_refresh_metrics_locked();
            const std::size_t locked_depth = g_ui_dispatch_last_depth.load(std::memory_order_acquire);
            ui_dispatch_log_reject(enqueue_result_t::rejected_not_ui_ready, "ui_not_ready_locked", item, locked_depth);
            log_route_reject(locked_depth, ERROR_NOT_READY);
            return enqueue_result_t::rejected_not_ui_ready;
        }
        if (g_ui_dispatch_queue.size() >= kUiDispatchMaxDepth) {
            depth = g_ui_dispatch_queue.size();
            ui_dispatch_refresh_metrics_locked();
            ui_dispatch_log_reject(enqueue_result_t::rejected_full, "queue_full", item, depth);
            log_route_reject(depth, ERROR_NOT_ENOUGH_MEMORY);
            return enqueue_result_t::rejected_full;
        }
        g_ui_dispatch_queue.push_back(std::move(item));
        depth = g_ui_dispatch_queue.size();
        ui_dispatch_refresh_metrics_locked();
        g_ui_dispatch_enqueued.fetch_add(1, std::memory_order_acq_rel);
    }

    const std::uint64_t now = ui_dispatch_now_ms();
    diag::log_tagged_critical_fmt("ui_dispatcher",
        "UI-DISPATCHER-ENQUEUE result=%s task_id=%llu label=\"%.96s\" owner=\"%.96s\" subsystem=\"%.96s\" phase=\"%.96s\" priority=%s enqueue_pid=%lu enqueue_tid=%lu ui_owner_tid=%lu queued_ms=%llu deadline_ms=%llu cancellation=%d depth=%zu max_depth=%zu oldest_age_ms=%llu accepted=%llu",
        result_name(enqueue_result_t::accepted),
        static_cast<unsigned long long>(log_id),
        ui_dispatch_text(log_label),
        ui_dispatch_text(log_owner),
        ui_dispatch_text(log_subsystem),
        ui_dispatch_text(log_phase),
        priority_name(log_priority),
        static_cast<unsigned long>(log_pid),
        static_cast<unsigned long>(log_tid),
        static_cast<unsigned long>(log_owner_tid),
        static_cast<unsigned long long>(queued_ms),
        static_cast<unsigned long long>(log_deadline),
        log_cancellation ? 1 : 0,
        depth,
        g_ui_dispatch_max_depth.load(std::memory_order_acquire),
        static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(now)),
        static_cast<unsigned long long>(g_ui_dispatch_enqueued.load(std::memory_order_acquire)));
    ui_dispatch_log_pressure("queued", options.subsystem, options.label, options.phase, depth, g_ui_dispatch_next_id.load(std::memory_order_acquire), 0, false);
    const bool wake_posted = ui_dispatch_post_wake_locked(options.subsystem, options.label, options.phase);
    const DWORD owner = owner_tid();
    if (owner != 0 && ::GetCurrentThreadId() != owner)
        ui_affinity_log_marker(wake_posted ? "UI-AFFINITY-ROUTED" : "UI-AFFINITY-VIOLATION",
            options.subsystem,
            options.label,
            options.phase,
            depth,
            wake_posted ? 0UL : GetLastError());
    return enqueue_result_t::accepted;
}

bool post(task_t task, const char* subsystem, const char* label, const char* phase)
{
    post_options_t options;
    options.subsystem = subsystem;
    options.label = label;
    options.phase = phase;
    options.owner = subsystem;
    options.priority = priority_t::normal;
    return post(std::move(task), std::move(options)) == enqueue_result_t::accepted;
}

bool wake(const char* subsystem, const char* label, const char* phase)
{
    const bool posted = ui_dispatch_post_wake_locked(subsystem, label, phase);
    const DWORD owner = owner_tid();
    if (owner != 0 && owner != ::GetCurrentThreadId())
        ui_affinity_log_marker(posted ? "UI-AFFINITY-ROUTED" : "UI-AFFINITY-VIOLATION",
            subsystem,
            label,
            phase,
            pending_count(),
            posted ? 0UL : GetLastError());
    return posted;
}

std::uint32_t drain(std::uint32_t task_budget, std::uint64_t time_budget_ms, const char* phase)
{
    capture_owner_tid(::GetCurrentThreadId(), "ui_dispatcher", "drain", phase);
    g_ui_dispatch_drain_calls.fetch_add(1, std::memory_order_acq_rel);
    if (g_ui_dispatch_shutdown.load(std::memory_order_acquire)) {
        shutdown();
        return 0;
    }
    if (!g_ui_dispatch_ready.load(std::memory_order_acquire) ||
        g_ui_dispatch_window_destroying.load(std::memory_order_acquire))
        return 0;

    const std::uint32_t max_tasks = task_budget == 0 ? 1u : task_budget;
    const std::uint64_t budget_ms = time_budget_ms == 0 ? 1u : time_budget_ms;
    const std::uint64_t drain_start = ui_dispatch_now_ms();
    std::uint32_t ran = 0;
    for (;;) {
        ui_dispatch_task_t item;
        std::size_t depth_after_pop = 0;
        {
            std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
            if (g_ui_dispatch_queue.empty()) {
                ui_dispatch_refresh_metrics_locked();
                break;
            }
            auto best = g_ui_dispatch_queue.begin();
            for (auto it = g_ui_dispatch_queue.begin(); it != g_ui_dispatch_queue.end(); ++it) {
                const int rank = ui_dispatch_priority_rank(it->priority);
                const int best_rank = ui_dispatch_priority_rank(best->priority);
                if (rank > best_rank || (rank == best_rank && it->queued_ms < best->queued_ms))
                    best = it;
            }
            item = std::move(*best);
            g_ui_dispatch_queue.erase(best);
            depth_after_pop = g_ui_dispatch_queue.size();
            ui_dispatch_refresh_metrics_locked();
        }

        if (!item.task) {
            g_ui_dispatch_discarded.fetch_add(1, std::memory_order_acq_rel);
            ui_dispatch_log_pressure("discard_empty_task", item.subsystem.c_str(), item.label.c_str(), item.phase.c_str(), depth_after_pop, item.id, 0, true);
        } else {
            const std::uint64_t task_start = ui_dispatch_now_ms();
            const std::uint64_t wait_ms = task_start >= item.queued_ms ? task_start - item.queued_ms : 0;
            const char* cancel_reason = nullptr;
            if (ui_dispatch_cancelled(item, task_start, &cancel_reason)) {
                g_ui_dispatch_drain_cancelled.fetch_add(1, std::memory_order_acq_rel);
                g_ui_dispatch_discarded.fetch_add(1, std::memory_order_acq_rel);
                ui_dispatch_log_reject(enqueue_result_t::rejected_cancelled, cancel_reason ? cancel_reason : "cancelled_before_drain", item, depth_after_pop);
            } else {
                if (wait_ms >= 250 || depth_after_pop >= kUiDispatchPressureDepth)
                    ui_dispatch_log_pressure("dequeue_pressure", item.subsystem.c_str(), item.label.c_str(), item.phase.c_str(), depth_after_pop, item.id, wait_ms, false);
                g_ui_dispatch_active_task_id.store(item.id, std::memory_order_release);
                g_ui_dispatch_active_producer_tid.store(item.producer_tid, std::memory_order_release);
                g_ui_dispatch_active_started_ms.store(task_start, std::memory_order_release);
                diag::log_tagged_critical_fmt("ui_dispatcher",
                    "UI-DISPATCHER-DRAIN event=task_start phase=%s task_id=%llu label=\"%.96s\" owner=\"%.96s\" subsystem=\"%.96s\" priority=%s enqueue_pid=%lu enqueue_tid=%lu ui_owner_tid=%lu ui_tid=%lu queued_ms=%llu queued_age_ms=%llu deadline_ms=%llu cancellation=%d remaining_before=%zu",
                    ui_dispatch_text(phase),
                    static_cast<unsigned long long>(item.id),
                    ui_dispatch_text(item.label),
                    ui_dispatch_text(item.owner),
                    ui_dispatch_text(item.subsystem),
                    priority_name(item.priority),
                    static_cast<unsigned long>(item.producer_pid),
                    static_cast<unsigned long>(item.producer_tid),
                    static_cast<unsigned long>(item.ui_owner_tid_at_enqueue),
                    static_cast<unsigned long>(::GetCurrentThreadId()),
                    static_cast<unsigned long long>(item.queued_ms),
                    static_cast<unsigned long long>(wait_ms),
                    static_cast<unsigned long long>(item.deadline_ms),
                    item.cancellation_registered ? 1 : 0,
                    depth_after_pop);
            try {
                aida::diagnostic_exception_scope::scope_t exception_scope("ui_thread_dispatcher.task");
                item.task();
                g_ui_dispatch_executed.fetch_add(1, std::memory_order_acq_rel);
            } catch (const std::exception& ex) {
                g_ui_dispatch_discarded.fetch_add(1, std::memory_order_acq_rel);
                diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
                    "task_exception subsystem=%s label=%s phase=%s id=%llu wait_ms=%llu err=%s",
                    ui_dispatch_text(item.subsystem),
                    ui_dispatch_text(item.label),
                    ui_dispatch_text(item.phase),
                    static_cast<unsigned long long>(item.id),
                    static_cast<unsigned long long>(wait_ms),
                    ex.what());
            } catch (...) {
                aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "ui_dispatcher_backlog");
                g_ui_dispatch_discarded.fetch_add(1, std::memory_order_acq_rel);
                diag::log_tagged_critical_fmt("UI-DISPATCHER-BACKLOG",
                    "task_unknown_exception subsystem=%s label=%s phase=%s id=%llu wait_ms=%llu",
                    ui_dispatch_text(item.subsystem),
                    ui_dispatch_text(item.label),
                    ui_dispatch_text(item.phase),
                    static_cast<unsigned long long>(item.id),
                    static_cast<unsigned long long>(wait_ms));
            }
            const std::uint64_t task_ms = ui_dispatch_now_ms() - task_start;
            g_ui_dispatch_last_task_ms.store(task_ms, std::memory_order_release);
            g_ui_dispatch_last_task_id.store(item.id, std::memory_order_release);
            g_ui_dispatch_active_task_id.store(0, std::memory_order_release);
            g_ui_dispatch_active_producer_tid.store(0, std::memory_order_release);
            g_ui_dispatch_active_started_ms.store(0, std::memory_order_release);
            diag::log_tagged_critical_fmt("ui_dispatcher",
                "UI-DISPATCHER-DRAIN event=task_end phase=%s task_id=%llu label=\"%.96s\" owner=\"%.96s\" run_ms=%llu ran=%u remaining_after=%zu total_drained=%llu",
                ui_dispatch_text(phase),
                static_cast<unsigned long long>(item.id),
                ui_dispatch_text(item.label),
                ui_dispatch_text(item.owner),
                static_cast<unsigned long long>(task_ms),
                ran + 1,
                g_ui_dispatch_last_depth.load(std::memory_order_acquire),
                static_cast<unsigned long long>(g_ui_dispatch_executed.load(std::memory_order_acquire)));
            if (task_ms >= 8) {
                ui_dispatch_log_pressure("task_slow", item.subsystem.c_str(), item.label.c_str(), item.phase.c_str(), depth_after_pop, item.id, wait_ms, true);
            }
            }
        }

        ++ran;
        const std::uint64_t elapsed = ui_dispatch_now_ms() - drain_start;
        if (ran >= max_tasks) {
            g_ui_dispatch_task_budget_hits.fetch_add(1, std::memory_order_acq_rel);
            break;
        }
        if (elapsed >= budget_ms) {
            g_ui_dispatch_time_budget_hits.fetch_add(1, std::memory_order_acq_rel);
            break;
        }
    }

    const std::uint64_t drain_ms = ui_dispatch_now_ms() - drain_start;
    g_ui_dispatch_last_drain_ms.store(drain_ms, std::memory_order_release);
    g_ui_dispatch_last_drain_ts.store(ui_dispatch_now_ms(), std::memory_order_release);
    const std::size_t remaining = pending_count();
    if (remaining != 0) {
        g_ui_dispatch_budget_hits.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("ui_dispatcher",
            "UI-DISPATCHER-BUDGET-HIT phase=%s ran=%u remaining=%zu task_budget=%u time_budget_ms=%llu elapsed_ms=%llu oldest_age_ms=%llu budget_hits=%llu",
            ui_dispatch_text(phase),
            ran,
            remaining,
            max_tasks,
            static_cast<unsigned long long>(budget_ms),
            static_cast<unsigned long long>(drain_ms),
            static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(ui_dispatch_now_ms())),
            static_cast<unsigned long long>(g_ui_dispatch_budget_hits.load(std::memory_order_acquire)));
        ui_dispatch_log_pressure("drain_budget_yield", "ui_dispatcher", "drain", phase, remaining, 0, drain_ms, false);
        wake("ui_dispatcher", "drain_rewake", phase);
    } else {
        g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
    }
    if (ran != 0 || remaining != 0) {
        diag::log_tagged_fmt("ui_dispatcher",
            "UI-DISPATCHER-DRAIN event=summary phase=%s ran=%u remaining=%zu elapsed_ms=%llu task_budget=%u time_budget_ms=%llu drain_calls=%llu drain_cancelled=%llu oldest_age_ms=%llu",
            ui_dispatch_text(phase),
            ran,
            remaining,
            static_cast<unsigned long long>(drain_ms),
            max_tasks,
            static_cast<unsigned long long>(budget_ms),
            static_cast<unsigned long long>(g_ui_dispatch_drain_calls.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_ui_dispatch_drain_cancelled.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(ui_dispatch_now_ms())));
    }
    return ran;
}

std::size_t pending_count()
{
    std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
    ui_dispatch_refresh_metrics_locked();
    return g_ui_dispatch_queue.size();
}

void format_snapshot(char* out, std::size_t cap)
{
    if (!out || cap == 0)
        return;
    const std::uint64_t now = ui_dispatch_now_ms();
    const std::size_t pending = pending_count();
    const std::uint64_t active_started = g_ui_dispatch_active_started_ms.load(std::memory_order_acquire);
    const std::uint64_t active_age = active_started != 0 && now >= active_started ? now - active_started : 0;
    _snprintf_s(out, cap, _TRUNCATE,
        "ui_dispatcher{ready=%d shutdown=%d destroying=%d hwnd=0x%llX pending=%zu max_depth=%zu oldest_age_ms=%llu owner_tid=%lu current_tid=%lu wake_pending=%d enqueued=%llu executed=%llu discarded=%llu rejected=%llu rejected_shutdown=%llu rejected_full=%llu rejected_not_ready=%llu rejected_cancelled=%llu drain_calls=%llu drain_cancelled=%llu budget_hits=%llu task_budget_hits=%llu time_budget_hits=%llu affinity_violations=%llu last_drain_ts=%llu last_wake_ts=%llu wake_posted=%llu wake_thread_posted=%llu wake_coalesced=%llu wake_failed=%llu backlog_logs=%llu last_drain_ms=%llu last_task_id=%llu last_task_ms=%llu active_task=%llu active_producer_tid=%lu active_age_ms=%llu}",
        g_ui_dispatch_ready.load(std::memory_order_acquire) ? 1 : 0,
        g_ui_dispatch_shutdown.load(std::memory_order_acquire) ? 1 : 0,
        g_ui_dispatch_window_destroying.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(g_ui_dispatch_hwnd.load(std::memory_order_acquire)),
        pending,
        g_ui_dispatch_max_depth.load(std::memory_order_acquire),
        static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(now)),
        static_cast<unsigned long>(owner_tid()),
        static_cast<unsigned long>(::GetCurrentThreadId()),
        g_ui_dispatch_wake_pending.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(g_ui_dispatch_enqueued.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_executed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_discarded.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_shutdown.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_full.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_not_ready.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_rejected_cancelled.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_drain_calls.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_drain_cancelled.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_budget_hits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_task_budget_hits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_time_budget_hits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_affinity_violations.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_last_drain_ts.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_last_wake_ts.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_thread_posted.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_coalesced.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_wake_failed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_backlog_logs.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_last_drain_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_last_task_id.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_last_task_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_dispatch_active_task_id.load(std::memory_order_acquire)),
        static_cast<unsigned long>(g_ui_dispatch_active_producer_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(active_age));
}

std::uint64_t affinity_violation_count()
{
    return g_ui_dispatch_affinity_violations.load(std::memory_order_acquire);
}

std::uint64_t last_drain_timestamp()
{
    return g_ui_dispatch_last_drain_ts.load(std::memory_order_acquire);
}

std::uint64_t last_wake_timestamp()
{
    return g_ui_dispatch_last_wake_ts.load(std::memory_order_acquire);
}

std::uint64_t task_budget_hit_count()
{
    return g_ui_dispatch_task_budget_hits.load(std::memory_order_acquire);
}

std::uint64_t time_budget_hit_count()
{
    return g_ui_dispatch_time_budget_hits.load(std::memory_order_acquire);
}

std::uint64_t budget_hit_count()
{
    return g_ui_dispatch_budget_hits.load(std::memory_order_acquire);
}

std::uint64_t rejected_count()
{
    return g_ui_dispatch_rejected.load(std::memory_order_acquire);
}

std::uint64_t drained_count()
{
    return g_ui_dispatch_drain_calls.load(std::memory_order_acquire);
}

bool wake_pending()
{
    return g_ui_dispatch_wake_pending.load(std::memory_order_acquire);
}

std::uint64_t oldest_queued_age_ms()
{
    const std::uint64_t now = ui_dispatch_now_ms();
    std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
    ui_dispatch_refresh_metrics_locked();
    return ui_dispatch_oldest_age_ms(now);
}

std::string top_queued_labels(std::size_t max_entries)
{
    if (max_entries == 0)
        max_entries = 8;
    std::string out;
    std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
    std::size_t count = 0;
    for (const auto& item : g_ui_dispatch_queue) {
        if (count >= max_entries)
            break;
        if (count > 0)
            out += '|';
        out += ui_dispatch_copy_text(item.label.c_str(), "");
        out += '/';
        out += ui_dispatch_copy_text(item.owner.c_str(), "");
        ++count;
    }
    return out;
}

bool is_wake_message(UINT msg)
{
    return msg == kAidaUiDispatcherWakeMessage;
}

void acknowledge_wake_message()
{
    g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
    diag::log_tagged_fmt("ui_dispatcher",
        "UI-DISPATCHER-WAKE reason=dequeued tid=%lu depth=%zu wake_pending=0",
        static_cast<unsigned long>(::GetCurrentThreadId()),
        g_ui_dispatch_last_depth.load(std::memory_order_acquire));
}

void mark_ready(HWND hwnd, const char* subsystem, const char* label, const char* phase)
{
    if (hwnd) {
        DWORD owner_pid = 0;
        const DWORD tid = ::GetWindowThreadProcessId(hwnd, &owner_pid);
        if (tid != 0)
            capture_owner_tid(tid, subsystem, label, phase);
        g_ui_dispatch_hwnd.store(reinterpret_cast<UINT_PTR>(hwnd), std::memory_order_release);
    }
    g_ui_dispatch_window_destroying.store(false, std::memory_order_release);
    g_ui_dispatch_shutdown.store(false, std::memory_order_release);
    g_ui_dispatch_ready.store(owner_tid() != 0, std::memory_order_release);
    g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
    diag::log_tagged_critical_fmt("ui_dispatcher",
        "UI-DISPATCHER-DRAIN event=ready subsystem=%s label=%s phase=%s hwnd=0x%llX owner_tid=%lu ready=%d depth=%zu",
        ui_dispatch_text(subsystem),
        ui_dispatch_text(label),
        ui_dispatch_text(phase),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(owner_tid()),
        g_ui_dispatch_ready.load(std::memory_order_acquire) ? 1 : 0,
        pending_count());
}

void mark_window_destroying(HWND hwnd, const char* subsystem, const char* label, const char* phase)
{
    g_ui_dispatch_ready.store(false, std::memory_order_release);
    g_ui_dispatch_window_destroying.store(true, std::memory_order_release);
    g_ui_dispatch_hwnd.store(0, std::memory_order_release);
    g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
    std::size_t discarded = 0;
    {
        std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
        discarded = g_ui_dispatch_queue.size();
        g_ui_dispatch_queue.clear();
        ui_dispatch_refresh_metrics_locked();
    }
    if (discarded != 0) {
        g_ui_dispatch_discarded.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
        g_ui_dispatch_rejected_shutdown.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
        g_ui_dispatch_rejected.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
    }
    diag::log_tagged_critical_fmt("ui_dispatcher",
        "UI-DISPATCHER-DRAIN event=window_destroying subsystem=%s label=%s phase=%s hwnd=0x%llX owner_tid=%lu depth=%zu dropped=%zu oldest_age_ms=%llu",
        ui_dispatch_text(subsystem),
        ui_dispatch_text(label),
        ui_dispatch_text(phase),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(owner_tid()),
        pending_count(),
        discarded,
        static_cast<unsigned long long>(ui_dispatch_oldest_age_ms(ui_dispatch_now_ms())));
    if (discarded != 0) {
        diag::log_tagged_critical_fmt("ui_dispatcher",
            "UI-DISPATCHER-REJECT result=%s reason=window_destroying_drop dropped=%zu owner_tid=%lu rejected_shutdown=%llu",
            result_name(enqueue_result_t::rejected_shutdown),
            discarded,
            static_cast<unsigned long>(owner_tid()),
            static_cast<unsigned long long>(g_ui_dispatch_rejected_shutdown.load(std::memory_order_acquire)));
    }
}

void shutdown()
{
    g_ui_dispatch_shutdown.store(true, std::memory_order_release);
    g_ui_dispatch_ready.store(false, std::memory_order_release);
    g_ui_dispatch_window_destroying.store(true, std::memory_order_release);
    g_ui_dispatch_hwnd.store(0, std::memory_order_release);
    std::size_t discarded = 0;
    {
        std::lock_guard<std::mutex> lock(g_ui_dispatch_mtx);
        discarded = g_ui_dispatch_queue.size();
        g_ui_dispatch_queue.clear();
        ui_dispatch_refresh_metrics_locked();
    }
    if (discarded != 0) {
        g_ui_dispatch_discarded.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
        g_ui_dispatch_rejected_shutdown.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
        g_ui_dispatch_rejected.fetch_add(static_cast<std::uint64_t>(discarded), std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("ui_dispatcher",
            "UI-DISPATCHER-REJECT result=%s reason=shutdown_drop dropped=%zu owner_tid=%lu accepted=%llu drained=%llu rejected_shutdown=%llu",
            result_name(enqueue_result_t::rejected_shutdown),
            discarded,
            static_cast<unsigned long>(owner_tid()),
            static_cast<unsigned long long>(g_ui_dispatch_enqueued.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_ui_dispatch_executed.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_ui_dispatch_rejected_shutdown.load(std::memory_order_acquire)));
    }
    g_ui_dispatch_wake_pending.store(false, std::memory_order_release);
}

}

static bool aida_key_down(int vk)
{
    return (::GetAsyncKeyState(vk) & 0x8000) != 0;
}

static bool aida_ctrl_shift_t_chord_down()
{
    return aida_key_down(VK_CONTROL) && aida_key_down(VK_SHIFT) && aida_key_down('T');
}

static bool aida_wide_to_utf8_owned(const std::wstring& in, std::string& out)
{
    out.clear();
    if (in.empty())
        return false;
    UINT codepage = CP_UTF8;
    DWORD flags = WC_ERR_INVALID_CHARS;
    int needed = ::WideCharToMultiByte(codepage, flags, in.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        codepage = CP_ACP;
        flags = 0;
        needed = ::WideCharToMultiByte(codepage, flags, in.c_str(), -1, nullptr, 0, nullptr, nullptr);
    }
    if (needed <= 1)
        return false;
    std::string converted(static_cast<std::size_t>(needed), '\0');
    const int written = ::WideCharToMultiByte(codepage, flags, in.c_str(), -1, &converted[0], needed, nullptr, nullptr);
    if (written <= 1)
        return false;
    converted.resize(static_cast<std::size_t>(written - 1));
    out = std::move(converted);
    return !out.empty();
}

static std::atomic<uint64_t> g_dragdrop_ui_generation{0};

static void aida_dispatch_dropped_file_open(const std::string& path_for_ui,
                                            uint64_t generation,
                                            DWORD producer_tid,
                                            uint64_t capture_start_ms)
{
    const uint64_t current_generation = g_dragdrop_ui_generation.load(std::memory_order_acquire);
    const uint64_t dispatch_start_ms = static_cast<uint64_t>(::GetTickCount64());
    if (current_generation != generation) {
        diag::log_tagged_critical_fmt("DRAGDROP-UI-DISPATCH",
            "stale generation=%llu current_generation=%llu producer_tid=%lu ui_tid=%lu queued_age_ms=%llu path=%.260s",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(current_generation),
            static_cast<unsigned long>(producer_tid),
            static_cast<unsigned long>(::GetCurrentThreadId()),
            static_cast<unsigned long long>(dispatch_start_ms - capture_start_ms),
            path_for_ui.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("dragdrop", "open_path", "dispatch")) {
        diag::log_tagged_critical_fmt("DRAGDROP-UI-DISPATCH",
            "owner_rejected generation=%llu producer_tid=%lu ui_tid=%lu path=%.260s",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(producer_tid),
            static_cast<unsigned long>(::GetCurrentThreadId()),
            path_for_ui.c_str());
        return;
    }
    diag::log_tagged_critical_fmt("DRAGDROP-UI-DISPATCH",
        "begin generation=%llu producer_tid=%lu ui_tid=%lu queued_age_ms=%llu path=%.260s",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(producer_tid),
        static_cast<unsigned long>(::GetCurrentThreadId()),
        static_cast<unsigned long long>(dispatch_start_ms - capture_start_ms),
        path_for_ui.c_str());
    file_browser::open_path(path_for_ui);
    diag::log_tagged_critical_fmt("DRAGDROP-UI-DISPATCH",
        "end generation=%llu ui_tid=%lu elapsed_ms=%llu path=%.260s",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(::GetCurrentThreadId()),
        static_cast<unsigned long long>(static_cast<uint64_t>(::GetTickCount64()) - dispatch_start_ms),
        path_for_ui.c_str());
}

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

inline int prev_w = 0;
inline int prev_h = 0;
static uint64_t g_ResizeRequestTickMs = 0;

struct resize_perf_state_t {
    uint64_t requests = 0;
    uint64_t applied = 0;
    uint64_t skipped_redundant = 0;
    uint64_t coalesced = 0;
    uint64_t render_target_recreates = 0;
    uint64_t churn_window_start_ms = 0;
    uint32_t churn_window_recreates = 0;
    uint64_t last_churn_log_ms = 0;
};

static resize_perf_state_t g_resize_perf;

static uint64_t g_last_input_event_tick_ms = 0;
static DWORD g_last_input_msg_time = 0;
static UINT g_last_input_msg = 0;
static uint64_t g_input_event_count = 0;

static bool aida_is_input_or_attention_message(UINT message)
{
    switch (message) {
    case WM_MOUSEMOVE:
    case WM_NCMOUSEMOVE:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_RBUTTONDBLCLK:
    case WM_MBUTTONDOWN:
    case WM_MBUTTONUP:
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_NCLBUTTONDOWN:
    case WM_NCLBUTTONUP:
    case WM_NCLBUTTONDBLCLK:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_CHAR:
    case WM_HOTKEY:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ACTIVATE:
    case WM_ACTIVATEAPP:
    case WM_CAPTURECHANGED:
    case WM_MOUSEACTIVATE:
        return true;
    default:
        return false;
    }
}

static bool aida_is_resize_message(UINT message)
{
    return message == WM_SIZE || message == WM_MOVE || message == WM_DPICHANGED;
}

static bool aida_is_paint_message(UINT message)
{
    return message == WM_PAINT || message == WM_NCPAINT || message == WM_ERASEBKGND;
}

static void aida_record_input_message(const MSG& msg, uint64_t now_ms)
{
    g_last_input_event_tick_ms = now_ms;
    g_last_input_msg_time = msg.time;
    g_last_input_msg = msg.message;
    ++g_input_event_count;
}

struct aida_message_pump_slice_t {
    uint32_t messages = 0;
    uint32_t input_messages = 0;
    uint32_t resize_messages = 0;
    uint32_t paint_messages = 0;
    bool quit = false;
    bool budget_exhausted = false;
};

static aida_message_pump_slice_t aida_pump_messages_budgeted(const char* reason, uint32_t message_budget, DWORD time_budget_ms)
{
    aida_message_pump_slice_t out{};
    MSG msg{};
    const uint64_t start_ms = static_cast<uint64_t>(GetTickCount64());
    const uint32_t max_messages = message_budget == 0 ? 1u : message_budget;
    for (;;) {
        DWORD queue_status_before = ::GetQueueStatus(QS_ALLINPUT);
        const DWORD queue_changed = LOWORD(queue_status_before);
        const DWORD queue_current = HIWORD(queue_status_before);
        if ((queue_current & QS_KEY) != 0 && aida_ctrl_shift_t_chord_down())
            break;
        const bool send_message_pending = (queue_current & QS_SENDMESSAGE) != 0;
        const bool non_send_pending = ((queue_current | queue_changed) & kAidaNonSendQueueBits) != 0;
        if (send_message_pending && !non_send_pending) {
            MSG sent_probe{};
            (void)::PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags);
            if (static_cast<uint64_t>(GetTickCount64()) - start_ms >= time_budget_ms) {
                out.budget_exhausted = true;
                break;
            }
            continue;
        }

        const UINT peek_flags = kAidaQueuedPeekFlags;
        BOOL has_message = ::PeekMessage(&msg, nullptr, 0U, 0U, peek_flags);
        if (!has_message)
            break;

        ++out.messages;
        if (aida::ui_thread::is_wake_message(msg.message)) {
            aida::ui_thread::acknowledge_wake_message();
            continue;
        }
        if (aida_is_input_or_attention_message(msg.message)) {
            ++out.input_messages;
            aida_record_input_message(msg, static_cast<uint64_t>(GetTickCount64()));
        } else if (aida_is_resize_message(msg.message)) {
            ++out.resize_messages;
        } else if (aida_is_paint_message(msg.message)) {
            ++out.paint_messages;
        }

        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
        if (msg.message == WM_QUIT) {
            out.quit = true;
            break;
        }

        const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - start_ms;
        if (out.messages >= max_messages || elapsed_ms >= time_budget_ms) {
            out.budget_exhausted = true;
            break;
        }
    }

    if (out.budget_exhausted) {
        static uint64_t s_last_budget_log_ms = 0;
        const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
        if (s_last_budget_log_ms == 0 || now_ms - s_last_budget_log_ms >= 1000ULL) {
            s_last_budget_log_ms = now_ms;
            diag::log_tagged_fmt("msgpump",
                "pump_slice_budget_exhausted reason=%s messages=%u input=%u resize=%u paint=%u budget_messages=%u budget_ms=%lu qs=0x%08lX",
                reason && reason[0] ? reason : "unknown",
                out.messages,
                out.input_messages,
                out.resize_messages,
                out.paint_messages,
                max_messages,
                static_cast<unsigned long>(time_budget_ms),
                static_cast<unsigned long>(::GetQueueStatus(QS_ALLINPUT)));
        }
    }
    return out;
}

struct gpu_frame_sample_t {
    bool available = false;
    bool valid = false;
    bool disjoint = false;
    bool pending = false;
    HRESULT data_hr = S_FALSE;
    HRESULT create_hr = S_OK;
    uint64_t frame = 0;
    uint64_t ready_frame = 0;
    uint64_t frequency = 0;
    uint64_t begin = 0;
    uint64_t end = 0;
    double gpu_ms = 0.0;
    uint64_t samples = 0;
    uint64_t misses = 0;
};

struct gpu_frame_query_state_t {
    ID3D11Query* disjoint = nullptr;
    ID3D11Query* begin = nullptr;
    ID3D11Query* end = nullptr;
    bool active = false;
    bool pending = false;
    uint64_t active_frame = 0;
    uint64_t pending_frame = 0;
    HRESULT create_hr = S_OK;
    uint64_t samples = 0;
    uint64_t misses = 0;
    gpu_frame_sample_t last;
};

static gpu_frame_query_state_t g_gpu_frame_query;

ImFont* g_font_ui_400 = nullptr;
ImFont* g_font_ui_500 = nullptr;
ImFont* g_font_ui_600 = nullptr;
ImFont* g_font_ui_700 = nullptr;
ImFont* g_font_ui_400_lg = nullptr;
ImFont* g_font_ui_500_sm = nullptr;
ImFont* g_font_ui_700_xl = nullptr;
ImFont* g_font_code_400 = nullptr;
ImFont* g_font_code_600 = nullptr;
ImFont* g_font_code_400_lg = nullptr;

static bool font_file_exists(const std::string& path)
{
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string repo_fonts_dir()
{
    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string s = exe;
    size_t cut = s.find_last_of('\\');
    if (cut != std::string::npos) s = s.substr(0, cut);
    return s + "\\fonts";
}

static std::string user_fonts_dir()
{
    char appdata[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("LOCALAPPDATA", appdata, MAX_PATH))
        return {};
    return std::string(appdata) + "\\Microsoft\\Windows\\Fonts";
}

static std::string sys_fonts_dir()
{
    char win_dir[MAX_PATH] = {};
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    return std::string(win_dir) + "\\Fonts";
}

static ImFont* load_font_with_fallbacks(ImGuiIO& io,
                                         const char* embed_data, size_t embed_size,
                                         const std::vector<std::string>& candidate_paths,
                                         float pixel_size,
                                         const ImFontConfig& cfg_in)
{
    diag::log_tagged_critical_fmt("fonts",
        "load_font_enter px=%.2f candidates=%zu embed_size=%zu atlas=0x%llX",
        pixel_size,
        candidate_paths.size(),
        embed_size,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)));
    ImFontConfig cfg = cfg_in;
    cfg.FontDataOwnedByAtlas = true;
    for (const auto& p : candidate_paths) {
        if (font_file_exists(p)) {
            const char* leaf = p.c_str();
            const char* slash = std::strrchr(leaf, '\\');
            if (slash) leaf = slash + 1;
            diag::log_tagged_critical_fmt("fonts",
                "load_font_file_pre leaf=%.120s path_len=%zu px=%.2f",
                leaf,
                p.size(),
                pixel_size);
            ImFont* f = io.Fonts->AddFontFromFileTTF(p.c_str(), pixel_size, &cfg);
            diag::log_tagged_critical_fmt("fonts",
                "load_font_file_post leaf=%.120s font=0x%llX atlas_count=%d",
                leaf,
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(f)),
                io.Fonts ? io.Fonts->Fonts.Size : -1);
            if (f) return f;
        }
    }
    if (embed_data && embed_size > 0) {
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_alloc_pre bytes=%zu px=%.2f",
            embed_size,
            pixel_size);
        void* copy = IM_ALLOC(embed_size);
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_alloc_post ptr=0x%llX bytes=%zu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(copy)),
            embed_size);
        if (!copy) return nullptr;
        memcpy(copy, embed_data, embed_size);
        ImFont* f = io.Fonts->AddFontFromMemoryTTF(copy, (int)embed_size, pixel_size, &cfg);
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_post font=0x%llX atlas_count=%d",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(f)),
            io.Fonts ? io.Fonts->Fonts.Size : -1);
        return f;
    }
    diag::log_tagged_critical_fmt("fonts", "load_font_none px=%.2f", pixel_size);
    return nullptr;
}

static void merge_icon_font(ImGuiIO& io, float pixel_size)
{
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_enter px=%.2f icon_bytes=%u atlas=0x%llX count=%d",
        pixel_size,
        ide_icon_font_size,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1);
    static const ImWchar icon_ranges[] = { ICON_MIN_IDE, ICON_MAX_IDE, 0 };
    ImFontConfig icon_cfg{};
    icon_cfg.MergeMode = true;
    icon_cfg.PixelSnapH = true;
    icon_cfg.GlyphMinAdvanceX = pixel_size * 0.92f;
    icon_cfg.GlyphOffset = ImVec2(0.f, pixel_size * 0.05f);
    icon_cfg.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_config builder_flags=0x%X",
        icon_cfg.FontLoaderFlags);
    void* icon_data_copy = IM_ALLOC(ide_icon_font_size);
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_alloc_post ptr=0x%llX bytes=%u",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(icon_data_copy)),
        ide_icon_font_size);
    if (!icon_data_copy) return;
    memcpy(icon_data_copy, ide_icon_font_data, ide_icon_font_size);
    ImFont* merged = io.Fonts->AddFontFromMemoryTTF(icon_data_copy, ide_icon_font_size, pixel_size, &icon_cfg, icon_ranges);
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_post font=0x%llX atlas_count=%d",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(merged)),
        io.Fonts ? io.Fonts->Fonts.Size : -1);
}

static void rebuild_fonts(float dpi_scale)
{
    if (!aida::ui_thread::require_owner("imgui", "rebuild_fonts", "enter"))
        return;
    ImGuiIO& io = ImGui::GetIO();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_enter dpi_scale=%.3f ctx=0x%llX atlas=0x%llX count=%d builder_before=0x%llX flags_before=0x%X",
        dpi_scale,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontLoader)) : 0ULL,
        io.Fonts ? io.Fonts->FontLoaderFlags : 0U);
    io.Fonts->Clear();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_clear_post atlas=0x%llX count=%d builder=0x%llX flags=0x%X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontLoader)) : 0ULL,
        io.Fonts ? io.Fonts->FontLoaderFlags : 0U);

    const auto font_policy = aida::ui::fonts::policy_for_dpi(dpi_scale);
    const float screen_factor = 1.0f;
    const float texture_scale = font_policy.scale;
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_scale screen_factor=%.3f texture_scale=%.3f body=%.2f caption=%.2f code=%.2f",
        screen_factor,
        texture_scale,
        font_policy.body_px,
        font_policy.caption_px,
        font_policy.code_px);
    const float base = font_policy.body_px;
    const float lg   = font_policy.large_px;
    const float sm   = font_policy.caption_px;
    const float xl   = font_policy.display_px;
    const float code = font_policy.code_px;
    const float code_lg = font_policy.code_large_px;
    io.FontGlobalScale = 1.0f;

    const bool enable_lcd = font_policy.enable_lcd;
    constexpr unsigned int lcd_flag_value = 1u << 10;

    auto cfg_ui_smooth = [&](float multiply) {
        ImFontConfig c{};
        c.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_NoHinting;
        if (enable_lcd) c.FontLoaderFlags |= lcd_flag_value;
        c.PixelSnapH = false;
        c.OversampleH = 3;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_ui_hinted = [&](float multiply) {
        ImFontConfig c{};
        c.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
        if (enable_lcd) c.FontLoaderFlags |= lcd_flag_value;
        c.PixelSnapH = false;
        c.OversampleH = 3;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_mono = [&](float multiply) {
        ImFontConfig c{};
        c.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
        c.PixelSnapH = true;
        c.OversampleH = 2;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_caption = [&](float multiply) {
        ImFontConfig c = cfg_ui_hinted(multiply);
        c.PixelSnapH = true;
        c.OversampleH = 2;
        return c;
    };

    const std::string repo_dir = repo_fonts_dir();
    const std::string user_dir = user_fonts_dir();
    const std::string sys_dir  = sys_fonts_dir();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_dirs repo_len=%zu user_len=%zu sys_len=%zu",
        repo_dir.size(),
        user_dir.size(),
        sys_dir.size());

    auto inter_paths = [&](const char* fname) -> std::vector<std::string> {
        std::vector<std::string> v;
        v.push_back(repo_dir + "\\" + fname);
        v.push_back(repo_dir + "\\inter\\" + fname);
        if (!user_dir.empty()) v.push_back(user_dir + "\\" + fname);
        v.push_back(sys_dir + "\\" + fname);
        return v;
    };
    auto seguivar      = sys_dir + "\\seguivar.ttf";
    auto segoe_var_alt = sys_dir + "\\SegoeUIVariable.ttf";
    auto segoe_ui      = sys_dir + "\\segoeui.ttf";
    auto segoe_uib     = sys_dir + "\\segoeuib.ttf";
    auto segoe_uisl    = sys_dir + "\\segoeuisl.ttf";

    auto inter_400 = inter_paths("Inter-Regular.ttf");
    inter_400.push_back(seguivar); inter_400.push_back(segoe_var_alt);
    inter_400.push_back(segoe_uisl); inter_400.push_back(segoe_ui);

    auto inter_500 = inter_paths("Inter-Medium.ttf");
    inter_500.push_back(seguivar); inter_500.push_back(segoe_var_alt); inter_500.push_back(segoe_ui);

    auto inter_600 = inter_paths("Inter-SemiBold.ttf");
    inter_600.push_back(seguivar); inter_600.push_back(segoe_var_alt); inter_600.push_back(segoe_uib); inter_600.push_back(segoe_ui);

    auto inter_700 = inter_paths("Inter-Bold.ttf");
    inter_700.push_back(seguivar); inter_700.push_back(segoe_var_alt); inter_700.push_back(segoe_uib); inter_700.push_back(segoe_ui);

    auto jbm_paths = [&](const char* fname) -> std::vector<std::string> {
        std::vector<std::string> v;
        v.push_back(repo_dir + "\\" + fname);
        v.push_back(repo_dir + "\\jetbrains-mono\\" + fname);
        if (!user_dir.empty()) v.push_back(user_dir + "\\" + fname);
        v.push_back(sys_dir + "\\" + fname);
        return v;
    };
    auto cascadia_mono = sys_dir + "\\CascadiaMono.ttf";
    auto cascadia_code = sys_dir + "\\CascadiaCode.ttf";
    auto consolas      = sys_dir + "\\consola.ttf";
    auto consolasb     = sys_dir + "\\consolab.ttf";

    auto jbm_400 = jbm_paths("JetBrainsMono-Regular.ttf");
    jbm_400.push_back(cascadia_mono); jbm_400.push_back(cascadia_code); jbm_400.push_back(consolas);

    auto jbm_600 = jbm_paths("JetBrainsMono-SemiBold.ttf");
    jbm_600.push_back(cascadia_mono); jbm_600.push_back(consolasb); jbm_600.push_back(consolas);

    ImFontConfig c_400 = cfg_ui_hinted(1.08f);
    ImFontConfig c_500 = cfg_ui_hinted(1.08f);
    ImFontConfig c_600 = cfg_ui_hinted(1.05f);
    ImFontConfig c_700 = cfg_ui_hinted(1.05f);
    ImFontConfig c_caption = cfg_caption(1.08f);
    ImFontConfig c_mono = cfg_mono(1.00f);

    g_font_ui_400 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_400, base, c_400);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui400 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400)));
    merge_icon_font(io, base);
    diag::log_tagged_critical("fonts", "rebuild_fonts_icon_merge_post");

    g_font_ui_500 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_500, base, c_500);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui500 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_500)));
    g_font_ui_600 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_600, base, c_600);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui600 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_600)));
    g_font_ui_700 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_700, base, c_700);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui700 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_700)));
    g_font_ui_400_lg = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_400, lg, c_400);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui400_lg font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400_lg)));
    g_font_ui_500_sm = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_500, sm, c_caption);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui500_sm font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_500_sm)));
    g_font_ui_700_xl = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_700, xl, c_700);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui700_xl font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_700_xl)));

    g_font_code_400 = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code400 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400)));
    g_font_code_600 = load_font_with_fallbacks(io, nullptr, 0, jbm_600, code, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code600 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_600)));
    g_font_code_400_lg = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code_lg, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code400_lg font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400_lg)));
    if (!g_font_code_400) g_font_code_400 = g_font_ui_400;
    if (!g_font_code_600) g_font_code_600 = g_font_code_400;
    if (!g_font_code_400_lg) g_font_code_400_lg = g_font_code_400;

    g_code_font = g_font_code_400;
    if (!g_font_ui_400) g_font_ui_400 = io.Fonts->Fonts.empty() ? nullptr : io.Fonts->Fonts[0];
    if (!g_font_ui_500) g_font_ui_500 = g_font_ui_400;
    if (!g_font_ui_600) g_font_ui_600 = g_font_ui_400;
    if (!g_font_ui_700) g_font_ui_700 = g_font_ui_400;
    if (!g_font_ui_400_lg) g_font_ui_400_lg = g_font_ui_400;
    if (!g_font_ui_500_sm) g_font_ui_500_sm = g_font_ui_400;
    if (!g_font_ui_700_xl) g_font_ui_700_xl = g_font_ui_700;

    io.FontDefault = g_font_ui_400;
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_build_pre default=0x%llX atlas_count=%d config_count=%d builder=0x%llX flags=0x%X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.FontDefault)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? io.Fonts->Sources.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontLoader)) : 0ULL,
        io.Fonts ? io.Fonts->FontLoaderFlags : 0U);
    io.Fonts->Build();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_build_post atlas_count=%d tex_alpha=0x%llX tex_rgba=0x%llX tex_w=%d tex_h=%d use_colors=%d",
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        (io.Fonts && io.Fonts->TexData && io.Fonts->TexData->Format == ImTextureFormat_Alpha8) ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->TexData->Pixels)) : 0ULL,
        (io.Fonts && io.Fonts->TexData && io.Fonts->TexData->Format == ImTextureFormat_RGBA32) ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->TexData->Pixels)) : 0ULL,
        (io.Fonts && io.Fonts->TexData) ? io.Fonts->TexData->Width : 0,
        (io.Fonts && io.Fonts->TexData) ? io.Fonts->TexData->Height : 0,
        (io.Fonts && io.Fonts->TexData && io.Fonts->TexData->UseColors) ? 1 : 0);
    extern bool g_imgui_dx11_initialized;
    if (g_imgui_dx11_initialized) {
        diag::log_tagged_critical("fonts", "rebuild_fonts_dx11_invalidate_pre");
        ImGui_ImplDX11_InvalidateDeviceObjects();
        diag::log_tagged_critical("fonts", "rebuild_fonts_dx11_invalidate_post");
    }
    diag::log_tagged_critical("fonts", "rebuild_fonts_exit");
}

bool g_imgui_dx11_initialized = false;

static bool os_prefers_dark()
{
    HKEY hk;
    LONG ok = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        0, KEY_READ, &hk);
    if (ok != ERROR_SUCCESS) return true;
    DWORD val = 1, sz = sizeof(val), type = 0;
    ok = RegQueryValueExW(hk, L"AppsUseLightTheme", nullptr, &type,
                          reinterpret_cast<BYTE*>(&val), &sz);
    RegCloseKey(hk);
    if (ok != ERROR_SUCCESS) return true;
    return val == 0;
}

static void apply_initial_theme()
{
    diag::log_tagged_critical_fmt("theme",
        "apply_initial_theme_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida::ui::apply_immediate(aida::ui::detail::make_default());
    diag::log_tagged_critical_fmt("theme",
        "apply_initial_theme_exit pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
}

static void crash_log_write(const char* msg)
{
    diag::log_tagged("main", msg);
}

static void crash_log_fmt(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    diag::log_tagged("main", buf);
}

static void startup_log_critical(const char* detail)
{
    diag::log_tagged_critical("startup", detail ? detail : "<null>");
}

static void startup_log_critical_fmt(const char* fmt, ...)
{
    char buf[2048] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    startup_log_critical(buf);
}

static HANDLE& single_instance_mutex_handle()
{
    static HANDLE h = nullptr;
    return h;
}

static void focus_existing_aida_window()
{
    HWND existing = FindWindowW(g_aidaClassName, g_aidaWindowTitle);
    if (!existing) {
        startup_log_critical_fmt("single_instance_existing_window_missing pid=%lu tid=%lu gle=%lu",
            GetCurrentProcessId(), GetCurrentThreadId(), GetLastError());
        return;
    }
    BOOL iconic = IsIconic(existing);
    ShowWindow(existing, iconic ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(existing);
    PostMessageW(existing, WM_APP + 0x1DA, 0, 0);
    startup_log_critical_fmt("single_instance_existing_window_focused hwnd=0x%llX iconic=%d pid=%lu tid=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(existing)),
        iconic ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId());
}

static bool acquire_single_instance_gate()
{
    HANDLE h = CreateMutexW(nullptr, TRUE, L"Local\\AiDAStandalone_8E9F73D8_SingleInstance");
    DWORD gle = GetLastError();
    if (!h) {
        startup_log_critical_fmt("single_instance_mutex_create_failed gle=%lu pid=%lu tid=%lu",
            gle, GetCurrentProcessId(), GetCurrentThreadId());
        crash_log_fmt("single_instance_mutex_create_failed gle=%lu", gle);
        return false;
    }
    if (gle == ERROR_ALREADY_EXISTS) {
        startup_log_critical_fmt("single_instance_duplicate_exit pid=%lu tid=%lu mutex=0x%llX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(h)));
        focus_existing_aida_window();
        CloseHandle(h);
        crash_log_write("single_instance_duplicate_exit");
        return false;
    }
    single_instance_mutex_handle() = h;
    startup_log_critical_fmt("single_instance_acquired pid=%lu tid=%lu mutex=0x%llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(h)));
    return true;
}

static void release_single_instance_gate()
{
    HANDLE& h = single_instance_mutex_handle();
    if (!h) return;
    ReleaseMutex(h);
    CloseHandle(h);
    diag::log_tagged_critical_fmt("main", "single_instance_released pid=%lu tid=%lu",
        GetCurrentProcessId(), GetCurrentThreadId());
    h = nullptr;
}

static const char* startup_bg_phase_label(int step)
{
    switch (step)
    {
    case 0: return "Bootstrapping";
    case 1: return "Connecting kernel driver";
    case 2: return "Initializing AiDA runtime core";
    case 3: return "Probing network surface";
    case 4: return "Arming memory scanner";
    case 5: return "Spinning up MITM proxy";
    case 6: return "Loading script engine";
    case 7: return "Ready";
    default: return "<out_of_range>";
    }
}

static void startup_store_bg_step(int step, const char* source, const char* phase)
{
    int before = globals::ui::bg_init_step.load(std::memory_order_acquire);
    globals::ui::bg_init_step.store(step, std::memory_order_release);
    startup_log_critical_fmt(
        "bg_init_step_transition source=%s phase=%s before=%d after=%d label=%s pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        phase ? phase : "unknown",
        before,
        step,
        startup_bg_phase_label(step),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
}

static void format_phase0_utc_timestamp(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    SYSTEMTIME st{};
    GetSystemTime(&st);
    _snprintf_s(out, cap, _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static uint64_t phase0_fnv1a64_update(uint64_t hash, const void* data, size_t len)
{
    if (!data)
        return hash;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(p[i]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t phase0_fnv1a64_update_u64(uint64_t hash, uint64_t value)
{
    return phase0_fnv1a64_update(hash, &value, sizeof(value));
}

static uint64_t phase0_fnv1a64_update_cstr(uint64_t hash, const char* value)
{
    if (!value)
        return phase0_fnv1a64_update_u64(hash, 0);
    return phase0_fnv1a64_update(hash, value, std::strlen(value) + 1);
}

static uint64_t phase0_message_pump_invariant_mask()
{
    uint64_t mask = 0;
    if ((kAidaQueuedPeekFlags & PM_QS_SENDMESSAGE) == PM_QS_SENDMESSAGE)
        mask |= 1ULL << 0;
    if ((kAidaQueuedPeekFlags & PM_REMOVE) == PM_REMOVE)
        mask |= 1ULL << 1;
    if (kAidaSendOnlyPeekFlags == (PM_REMOVE | PM_QS_SENDMESSAGE))
        mask |= 1ULL << 2;
    if ((kAidaNonSendQueueBits & QS_SENDMESSAGE) == 0)
        mask |= 1ULL << 3;
    if ((kAidaPumpQueueBits & QS_SENDMESSAGE) == QS_SENDMESSAGE)
        mask |= 1ULL << 4;
    if ((kAidaPumpQueueBits & kAidaNonSendQueueBits) == kAidaNonSendQueueBits)
        mask |= 1ULL << 5;
    if ((kAidaInteractiveQueueBits & QS_SENDMESSAGE) == 0)
        mask |= 1ULL << 6;
    mask |= 1ULL << 7;
    mask |= 1ULL << 8;
    mask |= 1ULL << 9;
    return mask;
}

static uint64_t phase0_message_pump_invariant_fingerprint()
{
    uint64_t hash = 14695981039346656037ULL;
    hash = phase0_fnv1a64_update_cstr(hash, "aida.phase0.message_pump.invariants.v1");
    hash = phase0_fnv1a64_update_u64(hash, static_cast<uint64_t>(kAidaQueuedPeekFlags));
    hash = phase0_fnv1a64_update_u64(hash, static_cast<uint64_t>(kAidaSendOnlyPeekFlags));
    hash = phase0_fnv1a64_update_u64(hash, static_cast<uint64_t>(kAidaNonSendQueueBits));
    hash = phase0_fnv1a64_update_u64(hash, static_cast<uint64_t>(kAidaPumpQueueBits));
    hash = phase0_fnv1a64_update_u64(hash, static_cast<uint64_t>(kAidaInteractiveQueueBits));
    hash = phase0_fnv1a64_update_u64(hash, phase0_message_pump_invariant_mask());
    return hash;
}

static void phase0_log_startup_invariants(const char* phase, HWND hwnd)
{
    char utc[48] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    DWORD owner_pid = 0;
    DWORD owner_tid = 0;
    DWORD owner_gle = 0;
    if (hwnd) {
        SetLastError(0);
        owner_tid = GetWindowThreadProcessId(hwnd, &owner_pid);
        owner_gle = owner_tid != 0 ? 0UL : GetLastError();
    } else {
        owner_gle = ERROR_INVALID_WINDOW_HANDLE;
    }
    const DWORD queue_status = GetQueueStatus(QS_ALLINPUT);
    const DWORD queue_changed = LOWORD(queue_status);
    const DWORD queue_current = HIWORD(queue_status);
    const uint64_t invariant_mask = phase0_message_pump_invariant_mask();
    const uint64_t invariant_hash = phase0_message_pump_invariant_fingerprint();
    const DWORD current_tid = GetCurrentThreadId();
    diag::log_tagged_critical_fmt("PHASE0-INVARIANTS",
        "record=message_pump_invariants phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu hwnd=0x%llX ui_owner_available=%d ui_owner_tid=%lu ui_owner_pid=%lu ui_owner_gle=%lu ui_owner_matches_current=%d queued_flags=0x%08X send_only_flags=0x%08X non_send_queue_bits=0x%08lX pump_queue_bits=0x%08lX interactive_queue_bits=0x%08lX pm_remove=0x%08X pm_qs_input=0x%08X pm_qs_postmessage=0x%08X pm_qs_paint=0x%08X pm_qs_sendmessage=0x%08X qs_allinput=0x%08lX qs_current=0x%04lX qs_changed=0x%04lX invariant_mask=0x%016llX invariant_fingerprint=0x%016llX queued_includes_send=%d queued_includes_remove=%d send_only_exact=%d non_send_bits_exclude_send=%d pump_bits_include_send=%d pump_bits_include_non_send=%d interactive_bits_exclude_send=%d empty_queue_nonblocking_probe_contract=%d send_only_drain_contract=%d queued_send_codrain_contract=%d",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        current_tid,
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        owner_tid != 0 ? 1 : 0,
        owner_tid,
        owner_pid,
        owner_gle,
        owner_tid != 0 && owner_tid == current_tid ? 1 : 0,
        kAidaQueuedPeekFlags,
        kAidaSendOnlyPeekFlags,
        static_cast<unsigned long>(kAidaNonSendQueueBits),
        static_cast<unsigned long>(kAidaPumpQueueBits),
        static_cast<unsigned long>(kAidaInteractiveQueueBits),
        PM_REMOVE,
        PM_QS_INPUT,
        PM_QS_POSTMESSAGE,
        PM_QS_PAINT,
        PM_QS_SENDMESSAGE,
        static_cast<unsigned long>(queue_status),
        static_cast<unsigned long>(queue_current),
        static_cast<unsigned long>(queue_changed),
        static_cast<unsigned long long>(invariant_mask),
        static_cast<unsigned long long>(invariant_hash),
        (kAidaQueuedPeekFlags & PM_QS_SENDMESSAGE) == PM_QS_SENDMESSAGE ? 1 : 0,
        (kAidaQueuedPeekFlags & PM_REMOVE) == PM_REMOVE ? 1 : 0,
        kAidaSendOnlyPeekFlags == (PM_REMOVE | PM_QS_SENDMESSAGE) ? 1 : 0,
        (kAidaNonSendQueueBits & QS_SENDMESSAGE) == 0 ? 1 : 0,
        (kAidaPumpQueueBits & QS_SENDMESSAGE) == QS_SENDMESSAGE ? 1 : 0,
        (kAidaPumpQueueBits & kAidaNonSendQueueBits) == kAidaNonSendQueueBits ? 1 : 0,
        (kAidaInteractiveQueueBits & QS_SENDMESSAGE) == 0 ? 1 : 0,
        1,
        1,
        1);
}

static void phase0_copy_diag_text(char* out, size_t cap, const char* value)
{
    if (!out || cap == 0)
        return;
    _snprintf_s(out, cap, _TRUNCATE, "%s", value ? value : "");
}

static void phase0_sanitize_log_field(char* value)
{
    if (!value)
        return;
    for (char* p = value; *p; ++p) {
        unsigned char ch = static_cast<unsigned char>(*p);
        if (ch < 0x20 || ch == 0x7F)
            *p = '_';
    }
}

static void phase0_wide_to_diag_utf8(const wchar_t* in, char* out, size_t cap)
{
    aida_early_startup::wide_to_utf8(in, out, cap);
    phase0_sanitize_log_field(out);
}

struct phase0_registry_string_result_t {
    bool present = false;
    bool read_ok = false;
    bool expand_ok = false;
    DWORD gle = ERROR_FILE_NOT_FOUND;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD expand_gle = ERROR_FILE_NOT_FOUND;
    char value[768] = {};
    char expanded[768] = {};
};

struct phase0_registry_dword_result_t {
    bool present = false;
    bool read_ok = false;
    DWORD gle = ERROR_FILE_NOT_FOUND;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD value = 0;
};

static phase0_registry_string_result_t phase0_query_registry_string(HKEY key, const wchar_t* value_name, DWORD unavailable_gle)
{
    phase0_registry_string_result_t result{};
    result.gle = unavailable_gle;
    result.expand_gle = unavailable_gle;
    phase0_copy_diag_text(result.value, sizeof(result.value), "<key_unavailable>");
    phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<key_unavailable>");
    if (!key)
        return result;

    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        result.expand_gle = static_cast<DWORD>(rc);
        if (rc == ERROR_FILE_NOT_FOUND) {
            phase0_copy_diag_text(result.value, sizeof(result.value), "<missing>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<missing>");
        } else {
            phase0_copy_diag_text(result.value, sizeof(result.value), "<unreadable>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<unreadable>");
        }
        return result;
    }

    result.present = true;
    result.type = type;
    result.bytes = bytes;
    if (bytes > 32768u) {
        result.gle = ERROR_MORE_DATA;
        result.expand_gle = ERROR_MORE_DATA;
        phase0_copy_diag_text(result.value, sizeof(result.value), "<too_large>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<too_large>");
        return result;
    }
    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2u, L'\0');
    DWORD read_bytes = bytes;
    rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &read_bytes);
    if (rc == ERROR_MORE_DATA) {
        if (read_bytes > 32768u) {
            result.type = type;
            result.bytes = read_bytes;
            result.gle = ERROR_MORE_DATA;
            result.expand_gle = ERROR_MORE_DATA;
            phase0_copy_diag_text(result.value, sizeof(result.value), "<too_large>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<too_large>");
            return result;
        }
        buffer.assign((read_bytes / sizeof(wchar_t)) + 2u, L'\0');
        rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &read_bytes);
    }
    result.type = type;
    result.bytes = read_bytes;
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        result.expand_gle = static_cast<DWORD>(rc);
        phase0_copy_diag_text(result.value, sizeof(result.value), "<unreadable>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<unreadable>");
        return result;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        result.gle = ERROR_INVALID_DATA;
        result.expand_gle = ERROR_INVALID_DATA;
        phase0_copy_diag_text(result.value, sizeof(result.value), "<non_string>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<non_string>");
        return result;
    }

    const size_t char_count = read_bytes / sizeof(wchar_t);
    if (char_count < buffer.size())
        buffer[char_count] = L'\0';
    else
        buffer.back() = L'\0';

    phase0_wide_to_diag_utf8(buffer.data(), result.value, sizeof(result.value));
    result.read_ok = true;
    result.gle = 0;
    if (type == REG_EXPAND_SZ) {
        wchar_t expanded_stack[1024] = {};
        constexpr DWORD expanded_stack_count = static_cast<DWORD>(sizeof(expanded_stack) / sizeof(expanded_stack[0]));
        DWORD expanded_count = ExpandEnvironmentStringsW(buffer.data(), expanded_stack, expanded_stack_count);
        if (expanded_count != 0 && expanded_count <= expanded_stack_count) {
            result.expand_ok = true;
            result.expand_gle = 0;
            phase0_wide_to_diag_utf8(expanded_stack, result.expanded, sizeof(result.expanded));
        } else if (expanded_count > expanded_stack_count && expanded_count <= 32768u) {
            std::vector<wchar_t> expanded(static_cast<size_t>(expanded_count) + 1u, L'\0');
            DWORD expanded_retry = ExpandEnvironmentStringsW(buffer.data(), expanded.data(), expanded_count);
            if (expanded_retry != 0 && expanded_retry <= expanded_count) {
                result.expand_ok = true;
                result.expand_gle = 0;
                phase0_wide_to_diag_utf8(expanded.data(), result.expanded, sizeof(result.expanded));
            } else {
                result.expand_gle = GetLastError();
                phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_failed>");
            }
        } else if (expanded_count > 32768u) {
            result.expand_gle = ERROR_MORE_DATA;
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_too_large>");
        } else {
            result.expand_gle = GetLastError();
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_failed>");
        }
    } else {
        result.expand_ok = true;
        result.expand_gle = 0;
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), result.value);
    }
    return result;
}

static phase0_registry_dword_result_t phase0_query_registry_dword(HKEY key, const wchar_t* value_name, DWORD unavailable_gle)
{
    phase0_registry_dword_result_t result{};
    result.gle = unavailable_gle;
    if (!key)
        return result;
    DWORD type = 0;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes);
    result.type = type;
    result.bytes = bytes;
    if (rc == ERROR_FILE_NOT_FOUND) {
        result.gle = static_cast<DWORD>(rc);
        return result;
    }
    result.present = true;
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        return result;
    }
    if (type != REG_DWORD || bytes < sizeof(DWORD)) {
        result.gle = ERROR_INVALID_DATA;
        return result;
    }
    result.read_ok = true;
    result.gle = 0;
    result.value = value;
    return result;
}

static void phase0_log_wer_registry_scope(const char* phase, HKEY root, const char* root_name, const wchar_t* subkey, const char* scope)
{
    char utc[48] = {};
    char key_utf8[512] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    phase0_wide_to_diag_utf8(subkey, key_utf8, sizeof(key_utf8));
    HKEY key = nullptr;
    LONG open_rc = RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    const bool open_ok = open_rc == ERROR_SUCCESS;
    const DWORD open_gle = static_cast<DWORD>(open_rc);
    phase0_registry_string_result_t dump_folder = phase0_query_registry_string(key, L"DumpFolder", open_gle);
    phase0_registry_dword_result_t dump_type = phase0_query_registry_dword(key, L"DumpType", open_gle);
    phase0_registry_dword_result_t dump_count = phase0_query_registry_dword(key, L"DumpCount", open_gle);
    phase0_registry_dword_result_t custom_flags = phase0_query_registry_dword(key, L"CustomDumpFlags", open_gle);
    char msg[3600] = {};
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "record=localdumps_registry phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu app=AiDAStandalone.exe root=%s view=64 scope=%s key=%s open_ok=%d open_gle=%lu dump_folder_present=%d dump_folder_read_ok=%d dump_folder_gle=%lu dump_folder_type=%lu dump_folder_bytes=%lu dump_folder=%s dump_folder_expand_ok=%d dump_folder_expand_gle=%lu dump_folder_expanded=%s dump_type_present=%d dump_type_read_ok=%d dump_type_gle=%lu dump_type_type=%lu dump_type_bytes=%lu dump_type_value=%lu dump_count_present=%d dump_count_read_ok=%d dump_count_gle=%lu dump_count_type=%lu dump_count_bytes=%lu dump_count_value=%lu custom_dump_flags_present=%d custom_dump_flags_read_ok=%d custom_dump_flags_gle=%lu custom_dump_flags_type=%lu custom_dump_flags_bytes=%lu custom_dump_flags_value=%lu",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        root_name ? root_name : "<root>",
        scope ? scope : "<scope>",
        key_utf8,
        open_ok ? 1 : 0,
        open_gle,
        dump_folder.present ? 1 : 0,
        dump_folder.read_ok ? 1 : 0,
        dump_folder.gle,
        dump_folder.type,
        dump_folder.bytes,
        dump_folder.value,
        dump_folder.expand_ok ? 1 : 0,
        dump_folder.expand_gle,
        dump_folder.expanded,
        dump_type.present ? 1 : 0,
        dump_type.read_ok ? 1 : 0,
        dump_type.gle,
        dump_type.type,
        dump_type.bytes,
        dump_type.value,
        dump_count.present ? 1 : 0,
        dump_count.read_ok ? 1 : 0,
        dump_count.gle,
        dump_count.type,
        dump_count.bytes,
        dump_count.value,
        custom_flags.present ? 1 : 0,
        custom_flags.read_ok ? 1 : 0,
        custom_flags.gle,
        custom_flags.type,
        custom_flags.bytes,
        custom_flags.value);
    diag::log_tagged_critical("WER-CONFIG", msg);
    if (key)
        RegCloseKey(key);
}

static void phase0_log_wer_configuration(const char* phase)
{
    const uint64_t start_ms = static_cast<uint64_t>(GetTickCount64());
    char utc[48] = {};
    char module[MAX_PATH] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_start phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu app=AiDAStandalone.exe module=%s",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        module);
    constexpr const wchar_t* default_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
    constexpr const wchar_t* exe_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\AiDAStandalone.exe";
    phase0_log_wer_registry_scope(phase, HKEY_CURRENT_USER, "HKCU", exe_subkey, "per_exe");
    phase0_log_wer_registry_scope(phase, HKEY_CURRENT_USER, "HKCU", default_subkey, "default");
    phase0_log_wer_registry_scope(phase, HKEY_LOCAL_MACHINE, "HKLM", exe_subkey, "per_exe");
    phase0_log_wer_registry_scope(phase, HKEY_LOCAL_MACHINE, "HKLM", default_subkey, "default");
    format_phase0_utc_timestamp(utc, sizeof(utc));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_end phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu elapsed_ms=%llu app=AiDAStandalone.exe",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_ms));
}

static aida::infra::executor::submit_result_t submit_main_executor_task(
    const char* owner_subsystem,
    const char* label,
    aida::infra::executor::domain_t domain,
    const char* thread_class,
    std::function<void()> body,
    int priority = 3)
{
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = owner_subsystem;
    submission.label = label;
    submission.thread_class = thread_class;
    submission.domain = domain;
    submission.priority = priority;
    submission.body = std::move(body);
    return aida::infra::executor::submit(std::move(submission));
}

static void phase0_post_wer_configuration_logging(const char* phase)
{
    std::string phase_copy = phase && phase[0] ? phase : "startup";
    const auto submit_result = submit_main_executor_task(
        "startup",
        "phase0.wer_config",
        aida::infra::executor::domain_t::diagnostics,
        "startup_diagnostics",
        [phase_copy]() {
            phase0_log_wer_configuration(phase_copy.c_str());
    });
    const bool posted = submit_result.submitted;
    char utc[48] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_post phase=%s posted=%d pid=%lu tid=%lu utc=%s tick_ms=%llu worker=executor_diagnostics",
        phase_copy.c_str(),
        posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()));
    if (!posted) {
        diag::log_tagged_critical_fmt("WER-CONFIG",
            "record=localdumps_scan_post_failed phase=%s reason=%.180s pid=%lu tid=%lu utc=%s tick_ms=%llu worker=executor_diagnostics",
            phase_copy.c_str(),
            submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str(),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            utc,
            static_cast<unsigned long long>(GetTickCount64()));
    }
}

static void format_message_pump_stall_context(char* out, size_t cap);
static void emit_window_hung_snapshot(
    uint64_t stall_streak,
    uint64_t frame,
    uint64_t age_ms,
    uint64_t phase_id,
    const char* phase_name,
    const char* render_section,
    DWORD render_tid,
    DWORD peek_status,
    DWORD peek_error,
    const char* dispatch_stage,
    UINT dispatch_msg,
    UINT_PTR dispatch_hwnd,
    const char* wndproc_stage,
    UINT wndproc_msg,
    UINT_PTR wndproc_hwnd);

namespace aida_tracer {
    inline std::atomic<uint64_t> g_render_frame{0};
    inline std::atomic<uint64_t> g_render_last_tick_ms{0};
    inline std::atomic<uint64_t> g_render_phase_id{0};
    inline std::atomic<const char*> g_render_phase_name{"<startup>"};
    inline std::atomic<DWORD> g_render_thread_id{0};
    inline std::atomic<uint64_t> g_attach_phase_id{0};
    inline std::atomic<const char*> g_attach_phase_name{"<idle>"};
    inline std::atomic<const char*> g_dispatch_stage{"<idle>"};
    inline std::atomic<UINT> g_dispatch_msg{0};
    inline std::atomic<UINT_PTR> g_dispatch_hwnd{0};
    inline std::atomic<UINT_PTR> g_dispatch_wparam{0};
    inline std::atomic<LONG_PTR> g_dispatch_lparam{0};
    inline std::atomic<DWORD> g_peek_queue_status{0};
    inline std::atomic<DWORD> g_peek_last_error{0};
    inline std::atomic<UINT> g_peek_remove_flags{kAidaQueuedPeekFlags};
    inline std::atomic<UINT_PTR> g_peek_filter_hwnd{0};
    inline std::atomic<uint64_t> g_peek_send_only_defers{0};
    inline std::atomic<uint64_t> g_peek_send_only_flushes{0};
    inline std::atomic<const char*> g_wndproc_stage{"<idle>"};
    inline std::atomic<UINT> g_wndproc_msg{0};
    inline std::atomic<UINT_PTR> g_wndproc_hwnd{0};
    inline std::atomic<UINT_PTR> g_wndproc_wparam{0};
    inline std::atomic<LONG_PTR> g_wndproc_lparam{0};
    inline std::atomic<uint64_t> g_wndproc_enter_count{0};
    inline std::atomic<uint64_t> g_wndproc_exit_count{0};
    inline std::atomic<uint64_t> g_peek_call_count{0};
    inline std::atomic<uint64_t> g_peek_return_count{0};
    inline std::atomic<uint64_t> g_dispatch_enter_count{0};
    inline std::atomic<uint64_t> g_dispatch_exit_count{0};
    inline std::atomic<uint64_t> g_last_thread_snapshot_ms{0};
    inline std::atomic<uint64_t> g_dx11_frame{0};
    inline std::atomic<uint64_t> g_dx11_enter_tick_ms{0};
    inline std::atomic<UINT_PTR> g_dx11_draw_data{0};
    inline std::atomic<UINT_PTR> g_dx11_device{0};
    inline std::atomic<UINT_PTR> g_dx11_context{0};
    inline std::atomic<UINT_PTR> g_dx11_rtv{0};
    inline std::atomic<uint64_t> g_dx11_cmd_lists{0};
    inline std::atomic<uint64_t> g_dx11_vtx_count{0};
    inline std::atomic<uint64_t> g_dx11_idx_count{0};
    inline std::atomic<int> g_dx11_display_w1000{0};
    inline std::atomic<int> g_dx11_display_h1000{0};
    inline std::atomic<int> g_dx11_fb_scale_w1000{0};
    inline std::atomic<int> g_dx11_fb_scale_h1000{0};
    inline std::atomic<long> g_dx11_device_removed{S_OK};
    inline std::atomic<uint64_t> g_dx11_draw_cmd_count{0};
    inline std::atomic<uint64_t> g_dx11_user_callback_count{0};
    inline std::atomic<uint64_t> g_dx11_reset_callback_count{0};
    inline std::atomic<uint64_t> g_dx11_unexpected_callback_count{0};
    inline std::atomic<UINT_PTR> g_dx11_first_callback{0};
    inline std::atomic<UINT_PTR> g_dx11_first_callback_data{0};
    inline std::atomic<UINT_PTR> g_dx11_first_texture{0};
    inline std::atomic<uint64_t> g_dx11_texture_hash{0};
    inline std::atomic<uint64_t> g_dx11_max_elem_count{0};
    inline std::atomic<uint32_t> g_dx11_bad_flags{0};
    inline std::atomic<int> g_dx11_bad_list{ -1 };
    inline std::atomic<int> g_dx11_bad_cmd{ -1 };
    inline std::atomic<uint64_t> g_present_frame{0};
    inline std::atomic<uint64_t> g_present_enter_tick_ms{0};
    inline std::atomic<UINT_PTR> g_present_swapchain{0};
    inline std::atomic<long> g_present_hr{S_OK};
    inline std::atomic<bool> g_stop{false};

    inline const char* message_name(UINT msg) {
        switch (msg) {
        case WM_NULL: return "WM_NULL";
        case WM_CREATE: return "WM_CREATE";
        case WM_DESTROY: return "WM_DESTROY";
        case WM_MOVE: return "WM_MOVE";
        case WM_SIZE: return "WM_SIZE";
        case WM_ACTIVATE: return "WM_ACTIVATE";
        case WM_SETFOCUS: return "WM_SETFOCUS";
        case WM_KILLFOCUS: return "WM_KILLFOCUS";
        case WM_ENABLE: return "WM_ENABLE";
        case WM_SETREDRAW: return "WM_SETREDRAW";
        case WM_SETTEXT: return "WM_SETTEXT";
        case WM_GETTEXT: return "WM_GETTEXT";
        case WM_GETTEXTLENGTH: return "WM_GETTEXTLENGTH";
        case WM_PAINT: return "WM_PAINT";
        case WM_CLOSE: return "WM_CLOSE";
        case WM_QUIT: return "WM_QUIT";
        case WM_ERASEBKGND: return "WM_ERASEBKGND";
        case WM_SYSCOLORCHANGE: return "WM_SYSCOLORCHANGE";
        case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
        case WM_SETTINGCHANGE: return "WM_SETTINGCHANGE";
        case WM_DEVMODECHANGE: return "WM_DEVMODECHANGE";
        case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
        case WM_FONTCHANGE: return "WM_FONTCHANGE";
        case WM_TIMECHANGE: return "WM_TIMECHANGE";
        case WM_CANCELMODE: return "WM_CANCELMODE";
        case WM_SETCURSOR: return "WM_SETCURSOR";
        case WM_MOUSEACTIVATE: return "WM_MOUSEACTIVATE";
        case WM_CHILDACTIVATE: return "WM_CHILDACTIVATE";
        case WM_QUEUESYNC: return "WM_QUEUESYNC";
        case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
        case WM_WINDOWPOSCHANGING: return "WM_WINDOWPOSCHANGING";
        case WM_WINDOWPOSCHANGED: return "WM_WINDOWPOSCHANGED";
        case WM_CONTEXTMENU: return "WM_CONTEXTMENU";
        case WM_STYLECHANGING: return "WM_STYLECHANGING";
        case WM_STYLECHANGED: return "WM_STYLECHANGED";
        case WM_DISPLAYCHANGE: return "WM_DISPLAYCHANGE";
        case WM_GETICON: return "WM_GETICON";
        case WM_SETICON: return "WM_SETICON";
        case WM_NCCREATE: return "WM_NCCREATE";
        case WM_NCDESTROY: return "WM_NCDESTROY";
        case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
        case WM_NCHITTEST: return "WM_NCHITTEST";
        case WM_NCPAINT: return "WM_NCPAINT";
        case WM_NCACTIVATE: return "WM_NCACTIVATE";
        case WM_GETDLGCODE: return "WM_GETDLGCODE";
        case WM_SYNCPAINT: return "WM_SYNCPAINT";
        case WM_NCMOUSEMOVE: return "WM_NCMOUSEMOVE";
        case WM_NCLBUTTONDOWN: return "WM_NCLBUTTONDOWN";
        case WM_NCLBUTTONUP: return "WM_NCLBUTTONUP";
        case WM_NCLBUTTONDBLCLK: return "WM_NCLBUTTONDBLCLK";
        case WM_KEYDOWN: return "WM_KEYDOWN";
        case WM_KEYUP: return "WM_KEYUP";
        case WM_CHAR: return "WM_CHAR";
        case WM_SYSKEYDOWN: return "WM_SYSKEYDOWN";
        case WM_SYSKEYUP: return "WM_SYSKEYUP";
        case WM_SYSCHAR: return "WM_SYSCHAR";
        case WM_INITDIALOG: return "WM_INITDIALOG";
        case WM_COMMAND: return "WM_COMMAND";
        case WM_SYSCOMMAND: return "WM_SYSCOMMAND";
        case WM_TIMER: return "WM_TIMER";
        case WM_HSCROLL: return "WM_HSCROLL";
        case WM_VSCROLL: return "WM_VSCROLL";
        case WM_INITMENU: return "WM_INITMENU";
        case WM_INITMENUPOPUP: return "WM_INITMENUPOPUP";
        case WM_MENUSELECT: return "WM_MENUSELECT";
        case WM_MENUCHAR: return "WM_MENUCHAR";
        case WM_ENTERIDLE: return "WM_ENTERIDLE";
        case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
        case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
        case WM_LBUTTONUP: return "WM_LBUTTONUP";
        case WM_LBUTTONDBLCLK: return "WM_LBUTTONDBLCLK";
        case WM_RBUTTONDOWN: return "WM_RBUTTONDOWN";
        case WM_RBUTTONUP: return "WM_RBUTTONUP";
        case WM_RBUTTONDBLCLK: return "WM_RBUTTONDBLCLK";
        case WM_MBUTTONDOWN: return "WM_MBUTTONDOWN";
        case WM_MBUTTONUP: return "WM_MBUTTONUP";
        case WM_MOUSEWHEEL: return "WM_MOUSEWHEEL";
        case WM_XBUTTONDOWN: return "WM_XBUTTONDOWN";
        case WM_XBUTTONUP: return "WM_XBUTTONUP";
        case WM_MOUSELEAVE: return "WM_MOUSELEAVE";
        case WM_MOUSEHOVER: return "WM_MOUSEHOVER";
        case WM_MOUSEHWHEEL: return "WM_MOUSEHWHEEL";
        case WM_PARENTNOTIFY: return "WM_PARENTNOTIFY";
        case WM_ENTERMENULOOP: return "WM_ENTERMENULOOP";
        case WM_EXITMENULOOP: return "WM_EXITMENULOOP";
        case WM_NEXTMENU: return "WM_NEXTMENU";
        case WM_SIZING: return "WM_SIZING";
        case WM_CAPTURECHANGED: return "WM_CAPTURECHANGED";
        case WM_MOVING: return "WM_MOVING";
        case WM_POWERBROADCAST: return "WM_POWERBROADCAST";
        case WM_DEVICECHANGE: return "WM_DEVICECHANGE";
        case WM_ENTERSIZEMOVE: return "WM_ENTERSIZEMOVE";
        case WM_EXITSIZEMOVE: return "WM_EXITSIZEMOVE";
        case WM_DROPFILES: return "WM_DROPFILES";
        case WM_DPICHANGED: return "WM_DPICHANGED";
        default: return "WM_UNKNOWN";
        }
    }

    inline void set_dispatch_state(const char* stage, const MSG& msg) {
        g_dispatch_msg.store(msg.message, std::memory_order_release);
        g_dispatch_hwnd.store(reinterpret_cast<UINT_PTR>(msg.hwnd), std::memory_order_release);
        g_dispatch_wparam.store(static_cast<UINT_PTR>(msg.wParam), std::memory_order_release);
        g_dispatch_lparam.store(static_cast<LONG_PTR>(msg.lParam), std::memory_order_release);
        g_dispatch_stage.store(stage, std::memory_order_release);
    }

    inline void clear_dispatch_state() {
        g_dispatch_stage.store("<idle>", std::memory_order_release);
    }

    inline void set_peek_state(DWORD queue_status, DWORD last_error) {
        g_peek_queue_status.store(queue_status, std::memory_order_release);
        g_peek_last_error.store(last_error, std::memory_order_release);
    }

    inline void set_peek_call_shape(UINT remove_flags, HWND filter_hwnd) {
        g_peek_remove_flags.store(remove_flags, std::memory_order_release);
        g_peek_filter_hwnd.store(reinterpret_cast<UINT_PTR>(filter_hwnd), std::memory_order_release);
    }

    inline bool should_log_wndproc_input_message(UINT) {
        return false;
    }

    inline bool should_log_wndproc_completion(UINT msg, uint64_t elapsed_ms) {
        if (elapsed_ms >= 32)
            return true;
        switch (msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
        case WM_QUERYENDSESSION:
        case WM_ENDSESSION:
        case WM_SYSCOMMAND:
        case WM_DPICHANGED:
        case WM_SETTINGCHANGE:
            return true;
        default:
            return should_log_wndproc_input_message(msg);
        }
    }

    inline bool is_shutdown_stall_context(const char* phase_name, UINT dispatch_msg, UINT wndproc_msg) {
        if (phase_name && std::strncmp(phase_name, "shutdown", 8) == 0)
            return true;
        switch (dispatch_msg) {
        case WM_QUIT:
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            break;
        }
        switch (wndproc_msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            return false;
        }
    }

    inline void set_wndproc_state(const char* stage, HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        g_wndproc_msg.store(msg, std::memory_order_release);
        g_wndproc_hwnd.store(reinterpret_cast<UINT_PTR>(hwnd), std::memory_order_release);
        g_wndproc_wparam.store(static_cast<UINT_PTR>(wParam), std::memory_order_release);
        g_wndproc_lparam.store(static_cast<LONG_PTR>(lParam), std::memory_order_release);
        g_wndproc_stage.store(stage, std::memory_order_release);
        if (stage && strcmp(stage, "enter") == 0)
            g_wndproc_enter_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void clear_wndproc_state() {
        g_wndproc_stage.store("<idle>", std::memory_order_release);
        g_wndproc_exit_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline int scaled_1000(float v) {
        return static_cast<int>(v * 1000.0f);
    }

    inline bool sane_float(float v) {
        return v == v && v > -10000000.0f && v < 10000000.0f;
    }

    inline uint64_t mix_u64(uint64_t h, uint64_t v) {
        h ^= v + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
        return h;
    }

    inline void describe_address(uint64_t va, char* out, size_t out_size) {
        if (!out || out_size == 0) return;
        out[0] = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        HMODULE mod = nullptr;
        char module_path[MAX_PATH * 4] = {};
        char mapped_path[MAX_PATH * 4] = {};
        const bool have_mbi = VirtualQuery(reinterpret_cast<LPCVOID>(va), &mbi, sizeof(mbi)) != 0;
        DWORD module_len = 0;
        DWORD module_gle = 0;
        DWORD mapped_len = 0;
        DWORD mapped_gle = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(va), &mod) && mod) {
            module_len = GetModuleFileNameA(mod, module_path, static_cast<DWORD>(sizeof(module_path)));
            module_gle = module_len ? 0 : GetLastError();
        }
        mapped_len = GetMappedFileNameA(GetCurrentProcess(), reinterpret_cast<LPVOID>(va), mapped_path, static_cast<DWORD>(sizeof(mapped_path)));
        mapped_gle = mapped_len ? 0 : GetLastError();
        uint64_t mod_base = static_cast<uint64_t>(reinterpret_cast<UINT_PTR>(mod));
        uint64_t mod_off = (mod_base != 0 && va >= mod_base) ? (va - mod_base) : 0;
        _snprintf_s(out, out_size, _TRUNCATE,
            "addr=0x%016llX mbi=%d base=0x%016llX alloc=0x%016llX protect=0x%lX state=0x%lX type=0x%lX module=0x%016llX mod_off=0x%llX path='%s' path_len=%lu path_gle=%lu mapped='%s' mapped_len=%lu mapped_gle=%lu",
            static_cast<unsigned long long>(va),
            have_mbi ? 1 : 0,
            have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.BaseAddress)) : 0ull,
            have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.AllocationBase)) : 0ull,
            have_mbi ? static_cast<unsigned long>(mbi.Protect) : 0ul,
            have_mbi ? static_cast<unsigned long>(mbi.State) : 0ul,
            have_mbi ? static_cast<unsigned long>(mbi.Type) : 0ul,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mod)),
            static_cast<unsigned long long>(mod_off),
            module_path[0] ? module_path : "<none>",
            static_cast<unsigned long>(module_len),
            static_cast<unsigned long>(module_gle),
            mapped_path[0] ? mapped_path : "<none>",
            static_cast<unsigned long>(mapped_len),
            static_cast<unsigned long>(mapped_gle));
    }

    inline void capture_render_thread_snapshot(DWORD render_tid, uint64_t age_ms) {
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        uint64_t prev = g_last_thread_snapshot_ms.load(std::memory_order_acquire);
        if (prev != 0 && now >= prev && now - prev < 30000)
            return;
        g_last_thread_snapshot_ms.store(now, std::memory_order_release);

        HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, render_tid);
        DWORD open_gle = th ? 0 : GetLastError();
        DWORD exit_code = 0;
        DWORD exit_gle = 0;
        BOOL exit_ok = FALSE;
        FILETIME create_time{};
        FILETIME exit_time{};
        FILETIME kernel_time{};
        FILETIME user_time{};
        DWORD times_gle = 0;
        BOOL times_ok = FALSE;
        if (th) {
            SetLastError(0);
            exit_ok = GetExitCodeThread(th, &exit_code);
            exit_gle = exit_ok ? 0 : GetLastError();
            SetLastError(0);
            times_ok = GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time);
            times_gle = times_ok ? 0 : GetLastError();
            CloseHandle(th);
        }

        diag::log_tagged_critical_fmt("tracer",
            "render_thread_snapshot_no_suspend tid=%lu age_ms=%llu open_ok=%d open_gle=%lu exit_ok=%d exit_code=0x%08lX exit_gle=%lu times_ok=%d times_gle=%lu kernel_time_low=0x%08lX kernel_time_high=0x%08lX user_time_low=0x%08lX user_time_high=0x%08lX peek_calls=%llu peek_returns=%llu dispatch_enter=%llu dispatch_exit=%llu wnd_enter=%llu wnd_exit=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms),
            th ? 1 : 0,
            static_cast<unsigned long>(open_gle),
            exit_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(exit_gle),
            times_ok ? 1 : 0,
            static_cast<unsigned long>(times_gle),
            static_cast<unsigned long>(kernel_time.dwLowDateTime),
            static_cast<unsigned long>(kernel_time.dwHighDateTime),
            static_cast<unsigned long>(user_time.dwLowDateTime),
            static_cast<unsigned long>(user_time.dwHighDateTime),
            static_cast<unsigned long long>(g_peek_call_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_return_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_exit_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_exit_count.load(std::memory_order_acquire)));

        HANDLE stack_th = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            render_tid);
        const DWORD stack_open_gle = stack_th ? 0 : GetLastError();
        if (!stack_th) {
            diag::log_tagged_critical_fmt("tracer",
                "render_thread_stack_open_fail tid=%lu gle=%lu",
                render_tid,
                static_cast<unsigned long>(stack_open_gle));
            return;
        }

        DWORD suspend_count = static_cast<DWORD>(-1);
        unsigned frames_walked = 0;
        const char* abort_reason = nullptr;
        const uint64_t suspend_t0 = static_cast<uint64_t>(GetTickCount64());
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_begin tid=%lu age_ms=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms));

        __try {
            suspend_count = SuspendThread(stack_th);
            if (suspend_count == static_cast<DWORD>(-1)) {
                abort_reason = "suspend_failed";
            } else {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_FULL;
                if (!GetThreadContext(stack_th, &ctx)) {
                    abort_reason = "get_thread_context_failed";
                } else {
                    STACKFRAME64 frame{};
#if defined(_M_X64)
                    frame.AddrPC.Offset = ctx.Rip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Rbp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Rsp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
#else
                    frame.AddrPC.Offset = ctx.Eip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Ebp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Esp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_I386;
#endif
                    HANDLE proc = GetCurrentProcess();
                    constexpr unsigned kMaxFrames = 64;
                    for (unsigned i = 0; i < kMaxFrames; ++i) {
                        const uint64_t walk_now = static_cast<uint64_t>(GetTickCount64());
                        if (walk_now - suspend_t0 >= 50ULL) {
                            abort_reason = "suspend_budget_exceeded";
                            break;
                        }
                        if (!StackWalk64(
                                machine,
                                proc,
                                stack_th,
                                &frame,
                                machine == IMAGE_FILE_MACHINE_AMD64 ? &ctx : nullptr,
                                nullptr,
                                SymFunctionTableAccess64,
                                SymGetModuleBase64,
                                nullptr)) {
                            abort_reason = "stack_walk_end_or_fail";
                            break;
                        }
                        if (frame.AddrPC.Offset == 0)
                            break;
                        char module_path[MAX_PATH] = {};
                        unsigned long long module_base = 0;
                        unsigned long long module_off = frame.AddrPC.Offset;
                        HMODULE mod = nullptr;
                        if (GetModuleHandleExA(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(static_cast<UINT_PTR>(frame.AddrPC.Offset)),
                                &mod) &&
                            mod) {
                            module_base = static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mod));
                            module_off = frame.AddrPC.Offset - module_base;
                            GetModuleFileNameA(mod, module_path, sizeof(module_path));
                        }
                        const char* short_name = module_path;
                        for (const char* p = module_path; *p; ++p) {
                            if (*p == '\\' || *p == '/')
                                short_name = p + 1;
                        }
                        diag::log_tagged_critical_fmt("tracer",
                            "render_thread_stack idx=%u rip=0x%llX module=%s base=0x%llX offset=0x%llX frame_rbp=0x%llX frame_rsp=0x%llX",
                            i,
                            static_cast<unsigned long long>(frame.AddrPC.Offset),
                            short_name[0] ? short_name : "<unknown>",
                            module_base,
                            module_off,
                            static_cast<unsigned long long>(frame.AddrFrame.Offset),
                            static_cast<unsigned long long>(frame.AddrStack.Offset));
                        ++frames_walked;
                    }
                }
                ResumeThread(stack_th);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "stall_watcher_stack_walk");
            if (suspend_count != static_cast<DWORD>(-1))
                ResumeThread(stack_th);
            abort_reason = "seh_exception";
        }

        const uint64_t suspend_elapsed = static_cast<uint64_t>(GetTickCount64()) - suspend_t0;
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_end tid=%lu frames=%u suspend_count=%lu elapsed_ms=%llu reason=%s",
            render_tid,
            frames_walked,
            static_cast<unsigned long>(suspend_count),
            static_cast<unsigned long long>(suspend_elapsed),
            abort_reason ? abort_reason : "ok");

        CloseHandle(stack_th);
    }

    inline void mark_render_phase(const char* name) {
        g_render_phase_name.store(name, std::memory_order_release);
        g_render_phase_id.fetch_add(1, std::memory_order_acq_rel);
    }
    inline void mark_attach_phase(const char* name) {
        g_attach_phase_name.store(name, std::memory_order_release);
        g_attach_phase_id.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("attach", "phase=%s", name);
    }
    inline void render_pulse(uint64_t frame) {
        g_render_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        g_render_frame.store(frame, std::memory_order_release);
        g_render_last_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
    }

    inline void set_dx11_draw_state(const char* stage,
                                    uint64_t frame,
                                    ImDrawData* dd,
                                    ID3D11Device* device,
                                    ID3D11DeviceContext* context,
                                    ID3D11RenderTargetView* rtv,
                                    HRESULT device_removed) {
        g_dx11_frame.store(frame, std::memory_order_release);
        g_dx11_enter_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        g_dx11_draw_data.store(reinterpret_cast<UINT_PTR>(dd), std::memory_order_release);
        g_dx11_device.store(reinterpret_cast<UINT_PTR>(device), std::memory_order_release);
        g_dx11_context.store(reinterpret_cast<UINT_PTR>(context), std::memory_order_release);
        g_dx11_rtv.store(reinterpret_cast<UINT_PTR>(rtv), std::memory_order_release);
        g_dx11_cmd_lists.store(dd ? static_cast<uint64_t>(dd->CmdListsCount) : 0, std::memory_order_release);
        g_dx11_vtx_count.store(dd ? static_cast<uint64_t>(dd->TotalVtxCount) : 0, std::memory_order_release);
        g_dx11_idx_count.store(dd ? static_cast<uint64_t>(dd->TotalIdxCount) : 0, std::memory_order_release);
        g_dx11_display_w1000.store(dd ? scaled_1000(dd->DisplaySize.x) : 0, std::memory_order_release);
        g_dx11_display_h1000.store(dd ? scaled_1000(dd->DisplaySize.y) : 0, std::memory_order_release);
        g_dx11_fb_scale_w1000.store(dd ? scaled_1000(dd->FramebufferScale.x) : 0, std::memory_order_release);
        g_dx11_fb_scale_h1000.store(dd ? scaled_1000(dd->FramebufferScale.y) : 0, std::memory_order_release);
        g_dx11_device_removed.store(static_cast<long>(device_removed), std::memory_order_release);
        mark_render_phase(stage);
    }

    inline uint32_t inspect_dx11_draw_data(ImDrawData* dd, uint64_t frame, bool full_walk) {
        uint64_t draw_cmds = 0;
        uint64_t user_callbacks = 0;
        uint64_t reset_callbacks = 0;
        uint64_t unexpected_callbacks = 0;
        UINT_PTR first_callback = 0;
        UINT_PTR first_callback_data = 0;
        UINT_PTR first_unexpected_callback = 0;
        UINT_PTR first_unexpected_callback_data = 0;
        UINT_PTR first_texture = 0;
        uint64_t texture_hash = 14695981039346656037ULL;
        uint64_t max_elem_count = 0;
        uint32_t bad_flags = 0;
        int bad_list = -1;
        int bad_cmd = -1;

        if (!dd) {
            bad_flags |= 0x00000001u;
        } else {
            if (!sane_float(dd->DisplaySize.x) || !sane_float(dd->DisplaySize.y) ||
                !sane_float(dd->FramebufferScale.x) || !sane_float(dd->FramebufferScale.y) ||
                dd->DisplaySize.x < 0.0f || dd->DisplaySize.y < 0.0f ||
                dd->FramebufferScale.x <= 0.0f || dd->FramebufferScale.y <= 0.0f) {
                bad_flags |= 0x00000002u;
            }
            if (dd->CmdListsCount < 0 || dd->CmdListsCount > 4096 ||
                dd->TotalVtxCount < 0 || dd->TotalVtxCount > 4000000 ||
                dd->TotalIdxCount < 0 || dd->TotalIdxCount > 8000000) {
                bad_flags |= 0x00000004u;
            }
            if (dd->CmdListsCount > 0 && !dd->CmdLists.Data) {
                bad_flags |= 0x00000008u;
            }
            if (dd->CmdLists.Size != dd->CmdListsCount) {
                bad_flags |= 0x00000100u;
            }
            if (!full_walk && bad_flags == 0) {
                g_dx11_draw_cmd_count.store(0, std::memory_order_release);
                g_dx11_user_callback_count.store(0, std::memory_order_release);
                g_dx11_reset_callback_count.store(0, std::memory_order_release);
                g_dx11_unexpected_callback_count.store(0, std::memory_order_release);
                g_dx11_first_callback.store(0, std::memory_order_release);
                g_dx11_first_callback_data.store(0, std::memory_order_release);
                g_dx11_first_texture.store(0, std::memory_order_release);
                g_dx11_texture_hash.store(texture_hash, std::memory_order_release);
                g_dx11_max_elem_count.store(0, std::memory_order_release);
                g_dx11_bad_flags.store(0, std::memory_order_release);
                g_dx11_bad_list.store(-1, std::memory_order_release);
                g_dx11_bad_cmd.store(-1, std::memory_order_release);
                return 0;
            }
            int list_count = dd->CmdListsCount;
            if (list_count < 0) list_count = 0;
            if (list_count > 4096) list_count = 4096;
            if (list_count > dd->CmdLists.Size)
                list_count = dd->CmdLists.Size;
            for (int i = 0; i < list_count; ++i) {
                ImDrawList* list = dd->CmdLists.Data ? dd->CmdLists[i] : nullptr;
                if (!list) {
                    bad_flags |= 0x00000010u;
                    if (bad_list < 0) bad_list = i;
                    continue;
                }
                if (list->CmdBuffer.Size < 0 || list->CmdBuffer.Size > 200000 ||
                    list->VtxBuffer.Size < 0 || list->VtxBuffer.Size > 4000000 ||
                    list->IdxBuffer.Size < 0 || list->IdxBuffer.Size > 8000000) {
                    bad_flags |= 0x00000020u;
                    if (bad_list < 0) bad_list = i;
                }
                int cmd_count = list->CmdBuffer.Size;
                if (cmd_count < 0) cmd_count = 0;
                if (cmd_count > 200000) cmd_count = 200000;
                for (int j = 0; j < cmd_count; ++j) {
                    ImDrawCmd& cmd = list->CmdBuffer[j];
                    ++draw_cmds;
                    ImTextureID tex_id = cmd.GetTexID();
                    UINT_PTR tex = 0;
                    std::memcpy(&tex, &tex_id, std::min(sizeof(tex), sizeof(tex_id)));
                    if (first_texture == 0 && tex != 0)
                        first_texture = tex;
                    texture_hash = mix_u64(texture_hash, static_cast<uint64_t>(tex));
                    texture_hash = mix_u64(texture_hash, static_cast<uint64_t>(cmd.ElemCount));
                    if (cmd.ElemCount > max_elem_count)
                        max_elem_count = cmd.ElemCount;
                    if (!sane_float(cmd.ClipRect.x) || !sane_float(cmd.ClipRect.y) ||
                        !sane_float(cmd.ClipRect.z) || !sane_float(cmd.ClipRect.w) ||
                        cmd.ClipRect.z < cmd.ClipRect.x || cmd.ClipRect.w < cmd.ClipRect.y) {
                        bad_flags |= 0x00000040u;
                        if (bad_list < 0) bad_list = i;
                        if (bad_cmd < 0) bad_cmd = j;
                    }
                    uint64_t idx_size = static_cast<uint64_t>(list->IdxBuffer.Size);
                    uint64_t vtx_size = static_cast<uint64_t>(list->VtxBuffer.Size);
                    uint64_t idx_offset = static_cast<uint64_t>(cmd.IdxOffset);
                    uint64_t elem_count = static_cast<uint64_t>(cmd.ElemCount);
                    if (idx_offset > idx_size ||
                        static_cast<uint64_t>(cmd.VtxOffset) > vtx_size ||
                        elem_count > idx_size ||
                        idx_offset + elem_count > idx_size) {
                        bad_flags |= 0x00000080u;
                        if (bad_list < 0) bad_list = i;
                        if (bad_cmd < 0) bad_cmd = j;
                    }
                    if (cmd.UserCallback) {
                        if (cmd.UserCallback == ImDrawCallback_ResetRenderState) {
                            ++reset_callbacks;
                        } else {
                            ++user_callbacks;
                            ++unexpected_callbacks;
                            if (first_callback == 0) {
                                first_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                            if (first_unexpected_callback == 0) {
                                first_unexpected_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_unexpected_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                        }
                    }
                }
            }
        }

        g_dx11_draw_cmd_count.store(draw_cmds, std::memory_order_release);
        g_dx11_user_callback_count.store(user_callbacks, std::memory_order_release);
        g_dx11_reset_callback_count.store(reset_callbacks, std::memory_order_release);
        g_dx11_unexpected_callback_count.store(unexpected_callbacks, std::memory_order_release);
        g_dx11_first_callback.store(first_callback, std::memory_order_release);
        g_dx11_first_callback_data.store(first_callback_data, std::memory_order_release);
        g_dx11_first_texture.store(first_texture, std::memory_order_release);
        g_dx11_texture_hash.store(texture_hash, std::memory_order_release);
        g_dx11_max_elem_count.store(max_elem_count, std::memory_order_release);
        g_dx11_bad_flags.store(bad_flags, std::memory_order_release);
        g_dx11_bad_list.store(bad_list, std::memory_order_release);
        g_dx11_bad_cmd.store(bad_cmd, std::memory_order_release);

        if (bad_flags != 0 || unexpected_callbacks != 0) {
            diag::log_tagged_critical_fmt("render",
                "dx11_drawdata_inspect frame=%llu bad=0x%08lX bad_list=%d bad_cmd=%d lists=%d total_vtx=%d total_idx=%d draw_cmds=%llu callbacks=%llu unexpected_callbacks=%llu reset_callbacks=%llu first_cb=0x%llX cb_data=0x%llX first_unexpected_cb=0x%llX unexpected_cb_data=0x%llX first_tex=0x%llX tex_hash=0x%016llX max_elem=%llu full_test=%d",
                static_cast<unsigned long long>(frame),
                static_cast<unsigned long>(bad_flags),
                bad_list,
                bad_cmd,
                dd ? dd->CmdListsCount : -1,
                dd ? dd->TotalVtxCount : -1,
                dd ? dd->TotalIdxCount : -1,
                static_cast<unsigned long long>(draw_cmds),
                static_cast<unsigned long long>(user_callbacks),
                static_cast<unsigned long long>(unexpected_callbacks),
                static_cast<unsigned long long>(reset_callbacks),
                static_cast<unsigned long long>(first_callback),
                static_cast<unsigned long long>(first_callback_data),
                static_cast<unsigned long long>(first_unexpected_callback),
                static_cast<unsigned long long>(first_unexpected_callback_data),
                static_cast<unsigned long long>(first_texture),
                static_cast<unsigned long long>(texture_hash),
                static_cast<unsigned long long>(max_elem_count),
                test_all_features::is_running() ? 1 : 0);
            if (unexpected_callbacks != 0 && first_unexpected_callback != 0) {
                char cb_desc[1200] = {};
                describe_address(static_cast<uint64_t>(first_unexpected_callback), cb_desc, sizeof(cb_desc));
                diag::log_tagged_critical_fmt("render",
                    "dx11_drawdata_unexpected_callback frame=%llu callbacks=%llu first_unexpected_cb=0x%llX cb_data=0x%llX desc={%.1000s}",
                    static_cast<unsigned long long>(frame),
                    static_cast<unsigned long long>(unexpected_callbacks),
                    static_cast<unsigned long long>(first_unexpected_callback),
                    static_cast<unsigned long long>(first_unexpected_callback_data),
                    cb_desc[0] ? cb_desc : "<empty>");
            }
        } else if (user_callbacks != 0 || reset_callbacks != 0) {
            static std::atomic<uint64_t> s_last_expected_callback_hash{0};
            static std::atomic<uint64_t> s_last_expected_callback_log_ms{0};
            static std::atomic<uint64_t> s_expected_callback_suppressed{0};
            uint64_t callback_hash = 14695981039346656037ULL;
            callback_hash = mix_u64(callback_hash, user_callbacks);
            callback_hash = mix_u64(callback_hash, reset_callbacks);
            callback_hash = mix_u64(callback_hash, first_callback);
            callback_hash = mix_u64(callback_hash, max_elem_count);
            const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
            const uint64_t last_hash = s_last_expected_callback_hash.load(std::memory_order_acquire);
            const uint64_t last_log_ms = s_last_expected_callback_log_ms.load(std::memory_order_acquire);
            if (last_log_ms == 0 || now_ms - last_log_ms >= kAidaExpectedCallbackLogIntervalMs) {
                const uint64_t suppressed = s_expected_callback_suppressed.exchange(0, std::memory_order_acq_rel);
                s_last_expected_callback_hash.store(callback_hash, std::memory_order_release);
                s_last_expected_callback_log_ms.store(now_ms, std::memory_order_release);
                diag::log_tagged_fmt("render",
                    "dx11_drawdata_callbacks_summary frame=%llu callbacks=%llu unexpected_callbacks=%llu reset_callbacks=%llu first_cb=0x%llX cb_data=0x%llX tex_hash=0x%016llX max_elem=%llu suppressed=%llu full_test=%d",
                    static_cast<unsigned long long>(frame),
                    static_cast<unsigned long long>(user_callbacks),
                    static_cast<unsigned long long>(unexpected_callbacks),
                    static_cast<unsigned long long>(reset_callbacks),
                    static_cast<unsigned long long>(first_callback),
                    static_cast<unsigned long long>(first_callback_data),
                    static_cast<unsigned long long>(texture_hash),
                    static_cast<unsigned long long>(max_elem_count),
                    static_cast<unsigned long long>(suppressed),
                    test_all_features::is_running() ? 1 : 0);
            } else {
                s_expected_callback_suppressed.fetch_add(1, std::memory_order_acq_rel);
                if (callback_hash != last_hash)
                    s_last_expected_callback_hash.store(callback_hash, std::memory_order_release);
            }
        }
        return bad_flags;
    }

    inline void set_present_state(const char* stage, uint64_t frame, IDXGISwapChain* sc, HRESULT hr) {
        g_present_frame.store(frame, std::memory_order_release);
        g_present_enter_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        g_present_swapchain.store(reinterpret_cast<UINT_PTR>(sc), std::memory_order_release);
        g_present_hr.store(static_cast<long>(hr), std::memory_order_release);
        mark_render_phase(stage);
    }

    inline void run_tracer_thread() {
        uint64_t prev_frame = 0;
        uint64_t prev_render_phase_id = 0;
        uint64_t stall_streak = 0;
        uint64_t last_peek_rescue_ms = 0;
        const uint64_t kStallThresholdMs = 2000;
        while (!g_stop.load(std::memory_order_acquire)) {
            ::Sleep(250);

            uint64_t now = static_cast<uint64_t>(GetTickCount64());
            uint64_t frame = g_render_frame.load(std::memory_order_acquire);
            uint64_t last_tick = g_render_last_tick_ms.load(std::memory_order_acquire);
            uint64_t phase_id = g_render_phase_id.load(std::memory_order_acquire);
            const char* phase_name = g_render_phase_name.load(std::memory_order_acquire);
            const char* render_section = g_render_section.c_str();
            uint64_t attach_phase_id = g_attach_phase_id.load(std::memory_order_acquire);
            const char* attach_phase = g_attach_phase_name.load(std::memory_order_acquire);
            DWORD render_tid = g_render_thread_id.load(std::memory_order_acquire);
            const char* dispatch_stage = g_dispatch_stage.load(std::memory_order_acquire);
            UINT dispatch_msg = g_dispatch_msg.load(std::memory_order_acquire);
            UINT_PTR dispatch_hwnd = g_dispatch_hwnd.load(std::memory_order_acquire);
            UINT_PTR dispatch_wparam = g_dispatch_wparam.load(std::memory_order_acquire);
            LONG_PTR dispatch_lparam = g_dispatch_lparam.load(std::memory_order_acquire);
            DWORD peek_status = g_peek_queue_status.load(std::memory_order_acquire);
            DWORD peek_error = g_peek_last_error.load(std::memory_order_acquire);
            const char* wndproc_stage = g_wndproc_stage.load(std::memory_order_acquire);
            UINT wndproc_msg = g_wndproc_msg.load(std::memory_order_acquire);
            UINT_PTR wndproc_hwnd = g_wndproc_hwnd.load(std::memory_order_acquire);
            UINT_PTR wndproc_wparam = g_wndproc_wparam.load(std::memory_order_acquire);
            LONG_PTR wndproc_lparam = g_wndproc_lparam.load(std::memory_order_acquire);
            uint64_t dx11_enter = g_dx11_enter_tick_ms.load(std::memory_order_acquire);
            uint64_t present_enter = g_present_enter_tick_ms.load(std::memory_order_acquire);
            uint64_t dx11_age = (dx11_enter > 0 && now >= dx11_enter) ? (now - dx11_enter) : 0;
            uint64_t present_age = (present_enter > 0 && now >= present_enter) ? (now - present_enter) : 0;

            uint64_t age_ms = (last_tick > 0 && now >= last_tick) ? (now - last_tick) : 0;
            bool render_stalled = (last_tick > 0 && age_ms > kStallThresholdMs && frame == prev_frame
                                   && phase_id == prev_render_phase_id);

            if (render_stalled) {
                stall_streak++;
                const uint64_t peek_calls = g_peek_call_count.load(std::memory_order_acquire);
                const uint64_t peek_returns = g_peek_return_count.load(std::memory_order_acquire);
                const bool stuck_in_peek =
                    phase_name && std::strcmp(phase_name, "peek_message_call") == 0 &&
                    peek_calls > peek_returns;
                if (stuck_in_peek && now - last_peek_rescue_ms >= 1000) {
                    last_peek_rescue_ms = now;
                    ::SetLastError(0);
                    BOOL thread_posted = render_tid ? ::PostThreadMessageW(render_tid, WM_NULL, 0, 0) : FALSE;
                    DWORD thread_gle = ::GetLastError();
                    BOOL hwnd_posted = FALSE;
                    DWORD hwnd_gle = 0;
                    HWND rescue_hwnd = g_hwnd;
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        hwnd_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        hwnd_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "peek_rescue frame=%llu age_ms=%llu render_tid=%lu calls=%llu returns=%llu thread_posted=%d thread_gle=%lu hwnd=0x%llX hwnd_posted=%d hwnd_gle=%lu qs=0x%08lX flags=0x%08X",
                        static_cast<unsigned long long>(frame),
                        static_cast<unsigned long long>(age_ms),
                        render_tid,
                        static_cast<unsigned long long>(peek_calls),
                        static_cast<unsigned long long>(peek_returns),
                        thread_posted ? 1 : 0,
                        static_cast<unsigned long>(thread_gle),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rescue_hwnd)),
                        hwnd_posted ? 1 : 0,
                        static_cast<unsigned long>(hwnd_gle),
                        static_cast<unsigned long>(peek_status),
                        g_peek_remove_flags.load(std::memory_order_acquire));
                }
                if (stall_streak == 1 || (stall_streak % 20ULL) == 0ULL) {
                    aida::diagnostics::metadata_ring::emit(
                        aida::diagnostics::metadata_ring::breadcrumb_category_t::render,
                        "render_stall_detected", nullptr, false);
                    char stall_context[4600] = {};
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                    diag::log_tagged_critical_fmt("tracer",
                        "RENDER_STALL streak=%llu frame=%llu age_ms=%llu phase=%s section=%s phase_id=%llu render_tid=%lu attach=%s attach_id=%llu peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX send_only_defers=%llu send_only_flushes=%llu dispatch=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX wndproc=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX dx_frame=%llu dx_age_ms=%llu dx_dd=0x%llX dx_dev=0x%llX dx_ctx=0x%llX dx_rtv=0x%llX dx_lists=%llu dx_draw_cmds=%llu dx_vtx=%llu dx_idx=%llu dx_callbacks=%llu dx_reset_callbacks=%llu dx_first_cb=0x%llX dx_cb_data=0x%llX dx_first_tex=0x%llX dx_tex_hash=0x%016llX dx_max_elem=%llu dx_bad=0x%08lX dx_bad_at=%d,%d dx_disp1000=%d,%d dx_fb1000=%d,%d dx_removed=0x%08lX present_frame=%llu present_age_ms=%llu present_sc=0x%llX present_hr=0x%08lX tracer_tid=%lu ctx={%.3600s}",
                        (unsigned long long)stall_streak,
                        (unsigned long long)frame,
                        (unsigned long long)age_ms,
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        (unsigned long long)phase_id,
                        render_tid,
                        attach_phase ? attach_phase : "<null>",
                        (unsigned long long)attach_phase_id,
                        static_cast<unsigned long>(peek_status),
                        static_cast<unsigned long>(peek_error),
                        g_peek_remove_flags.load(std::memory_order_acquire),
                        static_cast<unsigned long long>(g_peek_filter_hwnd.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_defers.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_flushes.load(std::memory_order_acquire)),
                        dispatch_stage ? dispatch_stage : "<null>",
                        message_name(dispatch_msg),
                        dispatch_msg,
                        (unsigned long long)dispatch_hwnd,
                        (unsigned long long)dispatch_wparam,
                        (unsigned long long)dispatch_lparam,
                        wndproc_stage ? wndproc_stage : "<null>",
                        message_name(wndproc_msg),
                        wndproc_msg,
                        (unsigned long long)wndproc_hwnd,
                        (unsigned long long)wndproc_wparam,
                        (unsigned long long)wndproc_lparam,
                        static_cast<unsigned long long>(g_dx11_frame.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(dx11_age),
                        static_cast<unsigned long long>(g_dx11_draw_data.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_device.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_context.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_rtv.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_cmd_lists.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_draw_cmd_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_vtx_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_idx_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_user_callback_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_reset_callback_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_callback.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_callback_data.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_texture.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_texture_hash.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_max_elem_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long>(g_dx11_bad_flags.load(std::memory_order_acquire)),
                        g_dx11_bad_list.load(std::memory_order_acquire),
                        g_dx11_bad_cmd.load(std::memory_order_acquire),
                        g_dx11_display_w1000.load(std::memory_order_acquire),
                        g_dx11_display_h1000.load(std::memory_order_acquire),
                        g_dx11_fb_scale_w1000.load(std::memory_order_acquire),
                        g_dx11_fb_scale_h1000.load(std::memory_order_acquire),
                        static_cast<unsigned long>(g_dx11_device_removed.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_present_frame.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(present_age),
                        static_cast<unsigned long long>(g_present_swapchain.load(std::memory_order_acquire)),
                        static_cast<unsigned long>(g_present_hr.load(std::memory_order_acquire)),
                        GetCurrentThreadId(),
                        stall_context[0] ? stall_context : "<empty>");
                    ::emit_window_hung_snapshot(
                        stall_streak,
                        frame,
                        age_ms,
                        phase_id,
                        phase_name,
                        render_section,
                        render_tid,
                        peek_status,
                        peek_error,
                        dispatch_stage,
                        dispatch_msg,
                        dispatch_hwnd,
                        wndproc_stage,
                        wndproc_msg,
                        wndproc_hwnd);
                    const bool shutdown_context = is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                    const bool sustained_hang = age_ms >= 2500ULL && (stall_streak == 1ULL || (stall_streak % 20ULL) == 0ULL);
                    if (render_tid != 0 && sustained_hang && !shutdown_context)
                        capture_render_thread_snapshot(render_tid, age_ms);
                }
                static uint64_t s_last_dbghelp_recovery_ms = 0;
                const bool render_disasm_section = render_section &&
                    std::strcmp(render_section, "center_view_disassembly") == 0;
                const bool dbghelp_in_progress = pdb_parser::g_dbghelp_load_state.in_progress;
                const uint64_t dbghelp_started_ms = pdb_parser::g_dbghelp_load_state.started_ms;
                const uint64_t dbghelp_owner_age_ms = (dbghelp_in_progress && dbghelp_started_ms != 0 && now >= dbghelp_started_ms)
                    ? (now - dbghelp_started_ms)
                    : 0ULL;
                const bool dbghelp_actually_stuck = dbghelp_in_progress && dbghelp_owner_age_ms > 30000ULL;
                const bool dbghelp_recovery_eligible = age_ms > 60000ULL && render_disasm_section && dbghelp_actually_stuck &&
                    !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                if (dbghelp_recovery_eligible && (s_last_dbghelp_recovery_ms == 0 ||
                                                  now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    const bool quarantined_before = pdb_parser::dbghelp_is_quarantined();
                    bool quarantine_triggered = false;
                    if (!quarantined_before) {
                        pdb_parser::quarantine_dbghelp_and_recycle();
                        quarantine_triggered = true;
                    }
                    HWND rescue_hwnd = g_hwnd;
                    BOOL nudge_posted = FALSE;
                    DWORD nudge_gle = 0;
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        nudge_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        nudge_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_attempt age_ms=%llu phase=%s section=%s render_tid=%lu dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu quarantine_triggered=%d quarantined_before=%d nudge_posted=%d nudge_gle=%lu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms),
                        quarantine_triggered ? 1 : 0,
                        quarantined_before ? 1 : 0,
                        nudge_posted ? 1 : 0,
                        static_cast<unsigned long>(nudge_gle));
                } else if (age_ms > 60000ULL && render_disasm_section &&
                           !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg) &&
                           (s_last_dbghelp_recovery_ms == 0 ||
                            now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_skipped age_ms=%llu phase=%s section=%s render_tid=%lu reason=dbghelp_not_in_flight dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms));
                }
            } else {
                stall_streak = 0;
            }

            prev_frame = frame;
            prev_render_phase_id = phase_id;
        }
    }

    inline void start() {
        diag::log_tagged_critical("tracer", "tracer_thread_starting");
        startup_log_critical_fmt("tracer_thread_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        const auto submit_result = submit_main_executor_task(
            "render",
            "render_tracer",
            aida::infra::executor::domain_t::diagnostics,
            "render_tracer",
            []() {
            startup_log_critical_fmt("tracer_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            run_tracer_thread();
            startup_log_critical_fmt("tracer_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        bool posted = submit_result.submitted;
        startup_log_critical_fmt("tracer_thread_post_post posted=%d pid=%lu tid=%lu tick=%llu",
            posted ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged_critical("tracer", "tracer_thread_started");
    }
}

namespace aida_focus_monitor {
    inline std::atomic<bool> g_focused{true};
    inline std::atomic<bool> g_stop{false};

    inline bool foreground_belongs_to_process(HWND hwnd) {
        HWND fg = ::GetForegroundWindow();
        if (!fg) return false;
        if (fg == hwnd) return true;
        DWORD pid = 0;
        ::GetWindowThreadProcessId(fg, &pid);
        return pid == ::GetCurrentProcessId();
    }

    inline void start(HWND hwnd) {
        const uint64_t start_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("focus_monitor_start_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(start_tick));
        g_stop.store(false, std::memory_order_release);
        g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
        const auto submit_result = submit_main_executor_task(
            "ui",
            "focus_monitor",
            aida::infra::executor::domain_t::service,
            "long_lived_service",
            [hwnd]() {
            startup_log_critical_fmt("focus_monitor_worker_enter hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            while (!g_stop.load(std::memory_order_acquire)) {
                g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
                ::Sleep(200);
            }
            startup_log_critical_fmt("focus_monitor_worker_exit hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        bool posted = submit_result.submitted;
        startup_log_critical_fmt("focus_monitor_start_post posted=%d focused=%d elapsed_ms=%llu hwnd=0x%llX",
            posted ? 1 : 0,
            g_focused.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_tick),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    }

    inline void stop() {
        g_stop.store(true, std::memory_order_release);
    }

    inline bool focused() {
        return g_focused.load(std::memory_order_acquire);
    }
}

namespace aida_hotkey_monitor {
    inline std::atomic<bool> g_started{ false };
    inline std::atomic<bool> g_stop{ false };
    inline std::atomic<bool> g_registered{ false };
    inline std::atomic<DWORD> g_thread_id{ 0 };
    inline std::atomic<std::uint64_t> g_last_trigger_ms{ 0 };

    inline bool trigger(HWND hwnd, const char* source, WORD mods, WORD vk, DWORD queue_status) {
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        const std::uint64_t last_ms = g_last_trigger_ms.load(std::memory_order_acquire);
        if (last_ms != 0 && now_ms >= last_ms && now_ms - last_ms < 750ULL)
            return false;
        const bool foreground = aida_focus_monitor::foreground_belongs_to_process(hwnd);
        diag::log_tagged_critical_fmt("ui",
            "test_all_start hotkey=%s id=0x%X mods=0x%04X vk=0x%04X foreground=%d hwnd=0x%llX queue=0x%08lX caller_tid=%lu registered=%d running=%d",
            source && source[0] ? source : "ctrl_shift_t",
            kAidaFullTestHotkeyId,
            static_cast<unsigned>(mods),
            static_cast<unsigned>(vk),
            foreground ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            static_cast<unsigned long>(queue_status),
            GetCurrentThreadId(),
            g_registered.load(std::memory_order_acquire) ? 1 : 0,
            test_all_features::is_running() ? 1 : 0);
        if (!foreground)
            return false;
        const bool posted = test_all_features::post_hotkey_trigger(source && source[0] ? source : "ctrl_shift_t");
        if (posted)
            g_last_trigger_ms.store(now_ms, std::memory_order_release);
        return posted;
    }

    inline void run(HWND hwnd) {
            const DWORD tid = GetCurrentThreadId();
        g_thread_id.store(tid, std::memory_order_release);
        startup_log_critical_fmt("hotkey_monitor_worker_enter hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            tid,
            static_cast<unsigned long long>(GetTickCount64()));
        MSG init_msg{};
        (void)::PeekMessageW(&init_msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
        ::SetLastError(0);
        const BOOL registered = ::RegisterHotKey(nullptr,
            kAidaFullTestHotkeyId,
            MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
            'T');
        const DWORD register_gle = ::GetLastError();
        g_registered.store(registered != FALSE, std::memory_order_release);
        startup_log_critical_fmt("hotkey_register ctrl_shift_t worker ok=%d id=0x%X tid=%lu gle=%lu hwnd=0x%llX",
            registered ? 1 : 0,
            kAidaFullTestHotkeyId,
            tid,
            static_cast<unsigned long>(register_gle),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
        bool chord_latched = false;
        while (!g_stop.load(std::memory_order_acquire)) {
            const DWORD wait_result = ::MsgWaitForMultipleObjectsEx(0, nullptr, 25, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            if (wait_result == WAIT_OBJECT_0) {
                for (unsigned drained = 0; drained < 32; ++drained) {
                    MSG msg{};
                    ::SetLastError(0);
                    if (!::PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
                        break;
                    if (msg.message == WM_QUIT) {
                        g_stop.store(true, std::memory_order_release);
                        break;
                    }
                    if (msg.message == WM_HOTKEY && static_cast<int>(msg.wParam) == kAidaFullTestHotkeyId) {
                        const WORD mods = LOWORD(msg.lParam);
                        const WORD vk = HIWORD(msg.lParam);
                        (void)trigger(hwnd, "worker_wm_hotkey_ctrl_shift_t", mods, vk, ::GetQueueStatus(QS_ALLINPUT));
                        continue;
                    }
                    if (msg.hwnd) {
                        ::TranslateMessage(&msg);
                        ::DispatchMessageW(&msg);
                    }
                }
            }
            const bool chord_down = aida_ctrl_shift_t_chord_down();
            if (chord_down && !chord_latched)
                (void)trigger(hwnd, "worker_async_ctrl_shift_t", static_cast<WORD>(MOD_CONTROL | MOD_SHIFT), 'T', ::GetQueueStatus(QS_ALLINPUT));
            chord_latched = chord_down;
        }
        if (g_registered.exchange(false, std::memory_order_acq_rel)) {
            ::SetLastError(0);
            const BOOL unregistered = ::UnregisterHotKey(nullptr, kAidaFullTestHotkeyId);
            startup_log_critical_fmt("hotkey_unregister ctrl_shift_t worker ok=%d id=0x%X tid=%lu gle=%lu",
                unregistered ? 1 : 0,
                kAidaFullTestHotkeyId,
                tid,
                static_cast<unsigned long>(GetLastError()));
        }
        g_thread_id.store(0, std::memory_order_release);
        g_started.store(false, std::memory_order_release);
        startup_log_critical_fmt("hotkey_monitor_worker_exit hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            tid,
            static_cast<unsigned long long>(GetTickCount64()));
    }

    inline void start(HWND hwnd) {
        const uint64_t start_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("hotkey_monitor_start_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(start_tick));
        bool expected = false;
        if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            startup_log_critical_fmt("hotkey_monitor_start_already_active hwnd=0x%llX worker_tid=%lu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                g_thread_id.load(std::memory_order_acquire));
            return;
        }
        g_stop.store(false, std::memory_order_release);
        const auto submit_result = submit_main_executor_task(
            "ui",
            "hotkey_monitor",
            aida::infra::executor::domain_t::service,
            "long_lived_service",
            [hwnd]() {
            run(hwnd);
        });
        bool posted = submit_result.submitted;
        if (!posted) {
            g_started.store(false, std::memory_order_release);
            g_stop.store(true, std::memory_order_release);
        }
        startup_log_critical_fmt("hotkey_monitor_start_post posted=%d elapsed_ms=%llu hwnd=0x%llX worker_tid=%lu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_tick),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            g_thread_id.load(std::memory_order_acquire));
    }

    inline void stop() {
        g_stop.store(true, std::memory_order_release);
        const DWORD tid = g_thread_id.load(std::memory_order_acquire);
        BOOL posted = FALSE;
        DWORD gle = 0;
        if (tid != 0) {
            ::SetLastError(0);
            posted = ::PostThreadMessageW(tid, WM_QUIT, 0, 0);
            gle = ::GetLastError();
        }
        startup_log_critical_fmt("hotkey_monitor_stop tid=%lu posted=%d gle=%lu registered=%d",
            tid,
            posted ? 1 : 0,
            static_cast<unsigned long>(gle),
            g_registered.load(std::memory_order_acquire) ? 1 : 0);
    }
}

static void format_tracer_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    POINT cursor{};
    GetCursorPos(&cursor);
    int imgui_ctx = 0;
    int imgui_frame = -1;
    __try {
        imgui_ctx = ImGui::GetCurrentContext() ? 1 : 0;
        if (imgui_ctx)
            imgui_frame = ImGui::GetFrameCount();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "format_tracer_snapshot_imgui_check");
        imgui_ctx = -1;
        imgui_frame = -2;
    }
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* render_section = g_render_section.c_str();
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "render_frame=%llu render_tick=%llu render_phase=%s render_section=%s render_tid=%lu "
        "peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX peek_calls=%llu peek_returns=%llu send_only_defers=%llu send_only_flushes=%llu "
        "dispatch_stage=%s dispatch_msg=%s(0x%04X) dispatch_hwnd=0x%llX dispatch_wp=0x%llX dispatch_lp=0x%llX dispatch_enter=%llu dispatch_exit=%llu "
        "wndproc_stage=%s wndproc_msg=%s(0x%04X) wndproc_hwnd=0x%llX wndproc_wp=0x%llX wndproc_lp=0x%llX wnd_enter=%llu wnd_exit=%llu "
        "dx_frame=%llu dx_dd=0x%llX dx_dev=0x%llX dx_ctx=0x%llX dx_rtv=0x%llX dx_lists=%llu dx_draw_cmds=%llu dx_vtx=%llu dx_idx=%llu dx_callbacks=%llu dx_bad=0x%08lX dx_bad_at=%d,%d dx_removed=0x%08lX "
        "present_frame=%llu present_sc=0x%llX present_hr=0x%08lX imgui_ctx=%d imgui_frame=%d cursor=%ld,%ld buttons=0x%04X fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
        static_cast<unsigned long long>(aida_tracer::g_render_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_render_last_tick_ms.load(std::memory_order_acquire)),
        render_phase ? render_phase : "<null>",
        render_section ? render_section : "<null>",
        aida_tracer::g_render_thread_id.load(std::memory_order_acquire),
        static_cast<unsigned long>(aida_tracer::g_peek_queue_status.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_peek_last_error.load(std::memory_order_acquire)),
        aida_tracer::g_peek_remove_flags.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_peek_filter_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_call_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_return_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_send_only_defers.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_send_only_flushes.load(std::memory_order_acquire)),
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_wparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_lparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_enter_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_exit_count.load(std::memory_order_acquire)),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_wparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_lparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_enter_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_exit_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_draw_data.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_device.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_context.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_rtv.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_cmd_lists.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_draw_cmd_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_vtx_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_idx_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_user_callback_count.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_dx11_bad_flags.load(std::memory_order_acquire)),
        aida_tracer::g_dx11_bad_list.load(std::memory_order_acquire),
        aida_tracer::g_dx11_bad_cmd.load(std::memory_order_acquire),
        static_cast<unsigned long>(aida_tracer::g_dx11_device_removed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_present_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_present_swapchain.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_present_hr.load(std::memory_order_acquire)),
        imgui_ctx,
        imgui_frame,
        cursor.x,
        cursor.y,
        static_cast<unsigned>((GetAsyncKeyState(VK_LBUTTON) & 0x8000 ? 1u : 0u) |
            (GetAsyncKeyState(VK_RBUTTON) & 0x8000 ? 2u : 0u) |
            (GetAsyncKeyState(VK_MBUTTON) & 0x8000 ? 4u : 0u) |
            (GetAsyncKeyState(VK_XBUTTON1) & 0x8000 ? 8u : 0u) |
            (GetAsyncKeyState(VK_XBUTTON2) & 0x8000 ? 16u : 0u)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
}

namespace aida_shutdown_diag {
    inline std::atomic<const char*> g_phase{"running"};
    inline std::atomic<uint64_t> g_phase_tick_ms{0};

    inline void mark(const char* phase)
    {
        const char* value = phase ? phase : "<null>";
        g_phase.store(value, std::memory_order_release);
        g_phase_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        diag::log_tagged_critical_fmt("shutdown",
            "phase=%s pid=%lu tid=%lu tick=%llu",
            value,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
    }

    inline uint64_t phase_age_ms()
    {
        const uint64_t tick = g_phase_tick_ms.load(std::memory_order_acquire);
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        return tick != 0 && now >= tick ? now - tick : 0;
    }
}

__declspec(noinline) static DWORD cpp_render_title(helpers* h, uint64_t frame_number, ImGuiErrorRecoveryState* imgui_state_backup)
{
    try {
        h->render_title();
    } catch (const std::exception& e) {
        ImGui::ErrorRecoveryTryToRecoverState(imgui_state_backup);
        diag::log_tagged_critical_fmt("render",
            "CPP_in_render_title frame=%llu section=%s what=%s",
            (unsigned long long)frame_number,
            g_render_section.c_str(),
            e.what());
        return 0xE06D7363u;
    } catch (...) {
        aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "cpp_render_title");
        ImGui::ErrorRecoveryTryToRecoverState(imgui_state_backup);
        diag::log_tagged_critical_fmt("render",
            "CPP_in_render_title frame=%llu section=%s what=<unknown>",
            (unsigned long long)frame_number,
            g_render_section.c_str());
        return 0xE06D7363u;
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_title(helpers* h, uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("imgui", "render_title", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);

    __try {
        return cpp_render_title(h, frame_number, &imgui_state_backup);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_render_title");
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
}

__declspec(noinline) static DWORD seh_render_source_reconstruct(uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("imgui", "render_source_reconstruct", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        source_reconstruct_view::render(1.0f, globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_render_source_reconstruct");
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_toast(uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("imgui", "render_toast", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        toast_notification::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_render_toast");
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_render()
{
    if (!aida::ui_thread::require_owner("imgui", "render", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    __try {
        ImGui::Render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_imgui_render");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_dx11_render(ImDrawData* dd, uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("dx11", "imgui_dx11_render", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    HRESULT removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    aida_tracer::set_dx11_draw_state("imgui_dx11_render_enter",
        frame_number,
        dd,
        g_pd3dDevice,
        g_pd3dDeviceContext,
        g_mainRenderTargetView,
        removed);
    __try {
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_call",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
        const bool inspect_full_walk =
            frame_number < 5ULL ||
            (frame_number % 120ULL) == 0ULL ||
            test_all_features::is_running();
        uint32_t draw_bad = aida_tracer::inspect_dx11_draw_data(dd, frame_number, inspect_full_walk);
        if (draw_bad != 0) {
            diag::log_tagged_critical_fmt("render",
                "imgui_dx11_render_skipped_invalid_draw_data frame=%llu bad=0x%08lX",
                static_cast<unsigned long long>(frame_number),
                static_cast<unsigned long>(draw_bad));
            aida_tracer::set_dx11_draw_state("imgui_dx11_render_invalid_skip",
                frame_number,
                dd,
                g_pd3dDevice,
                g_pd3dDeviceContext,
                g_mainRenderTargetView,
                removed);
            return 0;
        }
        ImGui_ImplDX11_RenderDrawData(dd);
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_returned",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_imgui_dx11_render");
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_seh",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_new_frame()
{
    if (!aida::ui_thread::require_owner("imgui", "new_frame", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    __try {
        ImGui::NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_imgui_new_frame");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_dx11_new_frame()
{
    if (!aida::ui_thread::require_owner("dx11", "new_frame", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    __try {
        ImGui_ImplDX11_NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_dx11_new_frame");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_win32_new_frame()
{
    if (!aida::ui_thread::require_owner("imgui_win32", "new_frame", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    __try {
        ImGui_ImplWin32_NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_win32_new_frame");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_swapchain_present(IDXGISwapChain* sc, HRESULT* hr_out, uint64_t frame_number, UINT sync_interval, UINT present_flags)
{
    aida_tracer::set_present_state("present_enter", frame_number, sc, hr_out ? *hr_out : E_POINTER);
    if (!aida::ui_thread::require_owner("swapchain", "present", "seh_enter")) {
        if (hr_out)
            *hr_out = E_ACCESSDENIED;
        aida_tracer::set_present_state("present_affinity_denied", frame_number, sc, E_ACCESSDENIED);
        return ERROR_ACCESS_DENIED;
    }
    if (!sc || !hr_out) {
        if (hr_out)
            *hr_out = E_POINTER;
        aida_tracer::set_present_state("present_missing_pointer", frame_number, sc, E_POINTER);
        return 0;
    }
    __try {
        aida_tracer::set_present_state("present_call", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        *hr_out = sc->Present(sync_interval, present_flags);
        aida_tracer::set_present_state("present_returned", frame_number, sc, *hr_out);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_swapchain_present");
        aida_tracer::set_present_state("present_seh", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        return GetExceptionCode();
    }
    return 0;
}

static bool aida_cursor_over_window(HWND hwnd)
{
    if (!hwnd || !::IsWindow(hwnd))
        return false;
    POINT cursor{};
    if (!::GetCursorPos(&cursor))
        return false;
    RECT rc{};
    if (!::GetWindowRect(hwnd, &rc))
        return false;
    return ::PtInRect(&rc, cursor) != FALSE;
}

__declspec(noinline) static DWORD seh_resize_buffers(IDXGISwapChain* sc, UINT w, UINT h, HRESULT* hr_out, uint64_t frame_number, const char* source)
{
    if (!aida::ui_thread::require_owner("swapchain", "resize_buffers", source ? source : "seh_enter")) {
        if (hr_out)
            *hr_out = E_ACCESSDENIED;
        return ERROR_ACCESS_DENIED;
    }
    if (hr_out)
        *hr_out = E_POINTER;
    if (!sc || !hr_out) {
        diag::log_tagged_critical_fmt("render",
            "resize_missing_pointer source=%s frame=%llu sc=0x%llX hr_out=0x%llX w=%u h=%u",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(sc)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hr_out)),
            w,
            h);
        return 0;
    }
    __try {
        *hr_out = sc->ResizeBuffers(0, w, h, DXGI_FORMAT_UNKNOWN, 0);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_resize_buffers");
        return GetExceptionCode();
    }
    diag::log_tagged_critical_fmt("render",
        "resize_buffers_result source=%s frame=%llu w=%u h=%u hr=0x%08X",
        source ? source : "<null>",
        static_cast<unsigned long long>(frame_number),
        w,
        h,
        static_cast<unsigned>(*hr_out));
    return 0;
}

static void release_gpu_frame_queries()
{
    if (g_gpu_frame_query.end) { g_gpu_frame_query.end->Release(); g_gpu_frame_query.end = nullptr; }
    if (g_gpu_frame_query.begin) { g_gpu_frame_query.begin->Release(); g_gpu_frame_query.begin = nullptr; }
    if (g_gpu_frame_query.disjoint) { g_gpu_frame_query.disjoint->Release(); g_gpu_frame_query.disjoint = nullptr; }
    g_gpu_frame_query = {};
}

static void initialize_gpu_frame_queries()
{
    release_gpu_frame_queries();
    if (!g_pd3dDevice || !g_pd3dDeviceContext)
        return;
    D3D11_QUERY_DESC desc{};
    desc.Query = D3D11_QUERY_TIMESTAMP_DISJOINT;
    HRESULT hr_disjoint = g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.disjoint);
    desc.Query = D3D11_QUERY_TIMESTAMP;
    HRESULT hr_begin = SUCCEEDED(hr_disjoint) ? g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.begin) : hr_disjoint;
    HRESULT hr_end = SUCCEEDED(hr_begin) ? g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.end) : hr_begin;
    HRESULT hr = FAILED(hr_disjoint) ? hr_disjoint : (FAILED(hr_begin) ? hr_begin : hr_end);
    g_gpu_frame_query.create_hr = hr;
    g_gpu_frame_query.last.create_hr = hr;
    if (FAILED(hr) || !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end) {
        diag::log_tagged_fmt("render",
            "gpu_frame_query_unavailable hr=0x%08X disjoint=0x%llX begin=0x%llX end=0x%llX device=0x%llX ctx=0x%llX",
            static_cast<unsigned>(hr),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.disjoint)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.begin)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.end)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
        release_gpu_frame_queries();
        g_gpu_frame_query.create_hr = hr;
        g_gpu_frame_query.last.create_hr = hr;
    }
}

static void collect_gpu_frame_query(uint64_t frame_number)
{
    if (!g_gpu_frame_query.pending || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    D3D11_QUERY_DATA_TIMESTAMP_DISJOINT disjoint{};
    UINT64 begin_ts = 0;
    UINT64 end_ts = 0;
    HRESULT hr_disjoint = g_pd3dDeviceContext->GetData(g_gpu_frame_query.disjoint, &disjoint, sizeof(disjoint), D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (hr_disjoint == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr_begin = SUCCEEDED(hr_disjoint) ? g_pd3dDeviceContext->GetData(g_gpu_frame_query.begin, &begin_ts, sizeof(begin_ts), D3D11_ASYNC_GETDATA_DONOTFLUSH) : hr_disjoint;
    if (hr_begin == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr_end = SUCCEEDED(hr_begin) ? g_pd3dDeviceContext->GetData(g_gpu_frame_query.end, &end_ts, sizeof(end_ts), D3D11_ASYNC_GETDATA_DONOTFLUSH) : hr_begin;
    if (hr_end == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr = FAILED(hr_disjoint) ? hr_disjoint : (FAILED(hr_begin) ? hr_begin : hr_end);
    g_gpu_frame_query.pending = false;
    ++g_gpu_frame_query.samples;
    gpu_frame_sample_t sample{};
    sample.available = true;
    sample.create_hr = g_gpu_frame_query.create_hr;
    sample.data_hr = hr;
    sample.frame = g_gpu_frame_query.pending_frame;
    sample.ready_frame = frame_number;
    sample.frequency = disjoint.Frequency;
    sample.begin = begin_ts;
    sample.end = end_ts;
    sample.disjoint = disjoint.Disjoint != FALSE;
    sample.pending = false;
    sample.samples = g_gpu_frame_query.samples;
    sample.misses = g_gpu_frame_query.misses;
    sample.valid = SUCCEEDED(hr) && !sample.disjoint && sample.frequency != 0 && end_ts >= begin_ts;
    if (sample.valid)
        sample.gpu_ms = (static_cast<double>(end_ts - begin_ts) * 1000.0) / static_cast<double>(sample.frequency);
    g_gpu_frame_query.last = sample;
}

static void begin_gpu_frame_query(uint64_t frame_number)
{
    collect_gpu_frame_query(frame_number);
    if (g_gpu_frame_query.pending || g_gpu_frame_query.active || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    g_pd3dDeviceContext->Begin(g_gpu_frame_query.disjoint);
    g_pd3dDeviceContext->End(g_gpu_frame_query.begin);
    g_gpu_frame_query.active = true;
    g_gpu_frame_query.active_frame = frame_number;
}

static void end_gpu_frame_query(uint64_t frame_number)
{
    if (!g_gpu_frame_query.active || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    g_pd3dDeviceContext->End(g_gpu_frame_query.end);
    g_pd3dDeviceContext->End(g_gpu_frame_query.disjoint);
    g_gpu_frame_query.active = false;
    g_gpu_frame_query.pending = true;
    g_gpu_frame_query.pending_frame = g_gpu_frame_query.active_frame ? g_gpu_frame_query.active_frame : frame_number;
    g_gpu_frame_query.last.pending = true;
}

static gpu_frame_sample_t latest_gpu_frame_sample(uint64_t frame_number)
{
    collect_gpu_frame_query(frame_number);
    gpu_frame_sample_t sample = g_gpu_frame_query.last;
    sample.pending = g_gpu_frame_query.pending;
    sample.create_hr = g_gpu_frame_query.create_hr;
    sample.samples = g_gpu_frame_query.samples;
    sample.misses = g_gpu_frame_query.misses;
    return sample;
}

static void record_resize_recreate(const char* source, UINT w, UINT h, uint64_t frame_number)
{
    const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
    if (g_resize_perf.churn_window_start_ms == 0 || now_ms - g_resize_perf.churn_window_start_ms > kAidaResizeChurnWindowMs) {
        g_resize_perf.churn_window_start_ms = now_ms;
        g_resize_perf.churn_window_recreates = 0;
    }
    ++g_resize_perf.churn_window_recreates;
    if (g_resize_perf.churn_window_recreates >= kAidaResizeChurnThreshold &&
        now_ms - g_resize_perf.last_churn_log_ms >= kAidaResizeChurnWindowMs) {
        g_resize_perf.last_churn_log_ms = now_ms;
        diag::log_tagged_fmt("render",
            "resize_churn source=%s frame=%llu w=%u h=%u window_ms=%llu recreates=%u requests=%llu applied=%llu coalesced=%llu skipped=%llu rt_recreates=%llu",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            w,
            h,
            static_cast<unsigned long long>(now_ms - g_resize_perf.churn_window_start_ms),
            static_cast<unsigned>(g_resize_perf.churn_window_recreates),
            static_cast<unsigned long long>(g_resize_perf.requests),
            static_cast<unsigned long long>(g_resize_perf.applied),
            static_cast<unsigned long long>(g_resize_perf.coalesced),
            static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
            static_cast<unsigned long long>(g_resize_perf.render_target_recreates));
    }
}

static bool resize_swapchain_and_target(UINT w, UINT h, uint64_t frame_number, const char* source)
{
    if (!aida::ui_thread::require_owner("swapchain", "resize_swapchain_and_target", source ? source : "enter"))
        return false;
    CleanupRenderTarget();
    HRESULT resize_hr = S_OK;
    DWORD resize_seh = seh_resize_buffers(g_pSwapChain, w, h, &resize_hr, frame_number, source);
    if (resize_seh != 0 || FAILED(resize_hr)) {
        diag::log_tagged_critical_fmt("render",
            "resize_failed source=%s frame=%llu w=%u h=%u seh=0x%08X hr=0x%08X device_removed=0x%08X",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            w,
            h,
            resize_seh,
            static_cast<unsigned>(resize_hr),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        CreateRenderTarget();
        return false;
    }
    ++g_resize_perf.applied;
    CreateRenderTarget();
    record_resize_recreate(source, w, h, frame_number);
    return true;
}

__declspec(noinline) static DWORD seh_clear_main_render_target(ID3D11DeviceContext* ctx, ID3D11RenderTargetView* rtv, const float* color, HRESULT* removed_out, uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("dx11", "clear_render_target", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    if (removed_out)
        *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    if (!ctx || !rtv || !color) {
        diag::log_tagged_critical_fmt("render",
            "clear_missing_pointer frame=%llu ctx=0x%llX rtv=0x%llX color=0x%llX device_removed=0x%08X",
            static_cast<unsigned long long>(frame_number),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ctx)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rtv)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(color)),
            static_cast<unsigned>(removed_out ? *removed_out : E_POINTER));
        return ERROR_INVALID_HANDLE;
    }
    __try {
        ID3D11RenderTargetView* local_rtv = rtv;
        ctx->OMSetRenderTargets(1, &local_rtv, nullptr);
        ctx->ClearRenderTargetView(rtv, color);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_clear_render_target");
        if (removed_out)
            *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        return GetExceptionCode();
    }
    if (removed_out)
        *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    return 0;
}

__declspec(noinline) static DWORD seh_render_command_palette(uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("imgui", "render_command_palette", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        aida::command_palette::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_render_command_palette");
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_agent_picker(uint64_t frame_number)
{
    if (!aida::ui_thread::require_owner("imgui", "render_agent_picker", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        aida::agent_picker::render_if_open();
        if (aida::agent_picker::consume_manager_request()) {
            aida::settings_overlay::set_active_tab(aida::settings_overlay::tab_agents);
            aida::settings_overlay::open();
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_render_agent_picker");
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static bool safe_read_qword(const void* p, uintptr_t& out)
{
    __try {
        out = *reinterpret_cast<const uintptr_t*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "safe_read_qword");
        out = 0;
        return false;
    }
}

static const char* crash_basename_ptr(const char* path)
{
    if (!path)
        return "<none>";
    const char* slash = std::strrchr(path, '\\');
    const char* fwd = std::strrchr(path, '/');
    const char* base = slash && fwd ? (slash > fwd ? slash : fwd) : (slash ? slash : fwd);
    return base ? base + 1 : path;
}

static void format_current_thread_description(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    using get_thread_description_t = HRESULT(WINAPI*)(HANDLE, PWSTR*);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    auto fn = kernel ? reinterpret_cast<get_thread_description_t>(GetProcAddress(kernel, "GetThreadDescription")) : nullptr;
    if (!fn) {
        HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
        fn = kernelbase ? reinterpret_cast<get_thread_description_t>(GetProcAddress(kernelbase, "GetThreadDescription")) : nullptr;
    }
    if (!fn) {
        _snprintf_s(out, cap, _TRUNCATE, "<unavailable>");
        return;
    }
    PWSTR desc = nullptr;
    HRESULT hr = fn(GetCurrentThread(), &desc);
    if (SUCCEEDED(hr) && desc) {
        int wrote = WideCharToMultiByte(CP_UTF8, 0, desc, -1, out, static_cast<int>(cap), nullptr, nullptr);
        if (wrote <= 0)
            _snprintf_s(out, cap, _TRUNCATE, "<convert_failed gle=%lu>", GetLastError());
        LocalFree(desc);
        if (out[0] == 0)
            _snprintf_s(out, cap, _TRUNCATE, "<empty>");
        return;
    }
    _snprintf_s(out, cap, _TRUNCATE, "<hr=0x%08lX>", static_cast<unsigned long>(hr));
}

static void append_stack_module_token(char* out, size_t cap, int idx, uintptr_t value)
{
    if (!out || cap == 0)
        return;
    size_t len = 0;
    while (len < cap && out[len] != 0)
        ++len;
    if (len >= cap - 1)
        return;
    HMODULE mod = nullptr;
    char path[MAX_PATH] = {};
    const bool have_mod = value != 0 &&
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(value), &mod) &&
        mod;
    if (have_mod)
        GetModuleFileNameA(mod, path, static_cast<DWORD>(sizeof(path)));
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod);
    const uintptr_t off = have_mod && value >= base ? value - base : 0;
    _snprintf_s(out + len, cap - len, _TRUNCATE,
        "%s[%02d]=0x%016llX:%s+0x%llX",
        len == 0 ? "" : " ",
        idx,
        static_cast<unsigned long long>(value),
        have_mod ? crash_basename_ptr(path) : "no_module",
        static_cast<unsigned long long>(off));
}

static void format_context_stack_modules(CONTEXT* ctx, char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    if (!ctx) {
        _snprintf_s(out, cap, _TRUNCATE, "<no_context>");
        return;
    }
#if defined(_M_X64)
    const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ctx->Rsp);
#else
    const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ctx->Esp);
#endif
    for (int i = 0; i < 32; ++i) {
        uintptr_t value = 0;
        if (!safe_read_qword(rsp_ptr + i, value))
            break;
        if (value == 0)
            continue;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(value), &mod) || !mod)
            continue;
        append_stack_module_token(out, cap, i, value);
    }
    if (out[0] == 0)
        _snprintf_s(out, cap, _TRUNCATE, "<no_module_stack_values>");
}

enum class taskflow_family_diag_kind_t {
    work,
    service,
    critical
};

struct taskflow_family_diag_t {
    uint32_t active = 0;
    uint64_t pending = 0;
    uint64_t oldest_active_ms = 0;
    uint32_t active_label_count = 0;
    std::string active_labels;
};

static taskflow_family_diag_kind_t taskflow_family_for_domain(aida::infra::taskflow_runtime::executor_domain_t domain)
{
    using domain_t = aida::infra::taskflow_runtime::executor_domain_t;
    switch (domain) {
    case domain_t::service:
    case domain_t::long_running:
        return taskflow_family_diag_kind_t::service;
    case domain_t::critical:
    case domain_t::security_liveness:
        return taskflow_family_diag_kind_t::critical;
    case domain_t::general:
    case domain_t::ui_dispatch:
    case domain_t::external_tool:
    case domain_t::feature_worker:
    case domain_t::diagnostics:
    default:
        return taskflow_family_diag_kind_t::work;
    }
}

static taskflow_family_diag_t make_taskflow_family_diag(
    const aida::infra::taskflow_runtime::runtime_snapshot_t& snapshot,
    taskflow_family_diag_kind_t family)
{
    taskflow_family_diag_t out;
    if (family == taskflow_family_diag_kind_t::service) {
        out.active = snapshot.service_queue_active;
        out.pending = snapshot.service_queue_pending;
    } else if (family == taskflow_family_diag_kind_t::critical) {
        out.active = snapshot.critical_queue_active;
        out.pending = snapshot.critical_queue_pending;
    } else {
        out.active = snapshot.work_queue_active;
        out.pending = snapshot.work_queue_pending;
    }
    for (const auto& job : snapshot.active_jobs) {
        if (taskflow_family_for_domain(job.domain) != family)
            continue;
        ++out.active_label_count;
        if (job.active_ms > out.oldest_active_ms)
            out.oldest_active_ms = job.active_ms;
        if (out.active_labels.size() < 900) {
            if (!out.active_labels.empty())
                out.active_labels += ";";
            out.active_labels += "#";
            out.active_labels += std::to_string(job.job_id);
            out.active_labels += ":";
            out.active_labels += aida::infra::taskflow_runtime::domain_name(job.domain);
            out.active_labels += ":";
            out.active_labels += aida::infra::taskflow_runtime::job_state_name(job.state);
            out.active_labels += ":";
            out.active_labels += job.label.empty() ? "<unnamed>" : job.label;
        }
    }
    return out;
}

static void format_taskflow_runtime_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    const auto runtime_snapshot = aida::infra::taskflow_runtime::active_snapshot(128);
    const auto work = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::work);
    const auto service = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::service);
    const auto critical = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::critical);
    _snprintf_s(out, cap, _TRUNCATE,
        "taskflow{accepting=%d shutdown=%d total_active=%u oldest_active_ms=%llu submitted=%llu rejected=%llu cancelled=%llu failed=%llu timed_out=%llu labels=%.700s} work{pending=%llu active=%u active_labels=%u oldest_active_ms=%llu labels=%.700s} service{pending=%llu active=%u active_labels=%u oldest_active_ms=%llu labels=%.700s} critical{pending=%llu active=%u active_labels=%u oldest_active_ms=%llu labels=%.700s}",
        runtime_snapshot.accepting ? 1 : 0,
        runtime_snapshot.shutting_down ? 1 : 0,
        static_cast<unsigned>(runtime_snapshot.total_active),
        static_cast<unsigned long long>(runtime_snapshot.oldest_active_ms),
        static_cast<unsigned long long>(runtime_snapshot.total_submitted),
        static_cast<unsigned long long>(runtime_snapshot.total_rejected),
        static_cast<unsigned long long>(runtime_snapshot.total_cancelled),
        static_cast<unsigned long long>(runtime_snapshot.total_failed),
        static_cast<unsigned long long>(runtime_snapshot.total_timed_out),
        runtime_snapshot.labels_under_pressure.empty() ? "<none>" : runtime_snapshot.labels_under_pressure.c_str(),
        static_cast<unsigned long long>(work.pending),
        static_cast<unsigned>(work.active),
        static_cast<unsigned>(work.active_label_count),
        static_cast<unsigned long long>(work.oldest_active_ms),
        work.active_labels.empty() ? "<none>" : work.active_labels.c_str(),
        static_cast<unsigned long long>(service.pending),
        static_cast<unsigned>(service.active),
        static_cast<unsigned>(service.active_label_count),
        static_cast<unsigned long long>(service.oldest_active_ms),
        service.active_labels.empty() ? "<none>" : service.active_labels.c_str(),
        static_cast<unsigned long long>(critical.pending),
        static_cast<unsigned>(critical.active),
        static_cast<unsigned>(critical.active_label_count),
        static_cast<unsigned long long>(critical.oldest_active_ms),
        critical.active_labels.empty() ? "<none>" : critical.active_labels.c_str());
}

static void format_taskflow_runtime_hung_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    constexpr uint64_t kStuckAgeMs = 5000ULL;
    const auto runtime_snapshot = aida::infra::taskflow_runtime::active_snapshot(128);
    const auto work = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::work);
    const auto service = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::service);
    const auto critical = make_taskflow_family_diag(runtime_snapshot, taskflow_family_diag_kind_t::critical);
    _snprintf_s(out, cap, _TRUNCATE,
        "taskflow{accepting=%d shutdown=%d total_active=%u stuck=%d oldest_active_ms=%llu submitted=%llu rejected=%llu failed=%llu timed_out=%llu labels=%.520s} work{pending=%llu active=%u stuck=%d oldest_active_ms=%llu active_labels=%u labels=%.520s} service{pending=%llu active=%u stuck=%d oldest_active_ms=%llu active_labels=%u labels=%.520s} critical{pending=%llu active=%u stuck=%d oldest_active_ms=%llu active_labels=%u labels=%.520s}",
        runtime_snapshot.accepting ? 1 : 0,
        runtime_snapshot.shutting_down ? 1 : 0,
        static_cast<unsigned>(runtime_snapshot.total_active),
        runtime_snapshot.oldest_active_ms >= kStuckAgeMs ? 1 : 0,
        static_cast<unsigned long long>(runtime_snapshot.oldest_active_ms),
        static_cast<unsigned long long>(runtime_snapshot.total_submitted),
        static_cast<unsigned long long>(runtime_snapshot.total_rejected),
        static_cast<unsigned long long>(runtime_snapshot.total_failed),
        static_cast<unsigned long long>(runtime_snapshot.total_timed_out),
        runtime_snapshot.labels_under_pressure.empty() ? "<none>" : runtime_snapshot.labels_under_pressure.c_str(),
        static_cast<unsigned long long>(work.pending),
        static_cast<unsigned>(work.active),
        work.oldest_active_ms >= kStuckAgeMs ? 1 : 0,
        static_cast<unsigned long long>(work.oldest_active_ms),
        static_cast<unsigned>(work.active_label_count),
        work.active_labels.empty() ? "<none>" : work.active_labels.c_str(),
        static_cast<unsigned long long>(service.pending),
        static_cast<unsigned>(service.active),
        service.oldest_active_ms >= kStuckAgeMs ? 1 : 0,
        static_cast<unsigned long long>(service.oldest_active_ms),
        static_cast<unsigned>(service.active_label_count),
        service.active_labels.empty() ? "<none>" : service.active_labels.c_str(),
        static_cast<unsigned long long>(critical.pending),
        static_cast<unsigned>(critical.active),
        critical.oldest_active_ms >= kStuckAgeMs ? 1 : 0,
        static_cast<unsigned long long>(critical.oldest_active_ms),
        static_cast<unsigned>(critical.active_label_count),
        critical.active_labels.empty() ? "<none>" : critical.active_labels.c_str());
}

static DWORD count_current_process_threads(DWORD* err_out)
{
    if (err_out)
        *err_out = 0;
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (err_out)
            *err_out = GetLastError();
        return 0;
    }
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                ++count;
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    } else if (err_out) {
        *err_out = GetLastError();
    }
    CloseHandle(snap);
    return count;
}

static uint64_t filetime_to_u64(const FILETIME& ft)
{
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

static void emit_window_hung_snapshot(
    uint64_t stall_streak,
    uint64_t frame,
    uint64_t age_ms,
    uint64_t phase_id,
    const char* phase_name,
    const char* render_section,
    DWORD render_tid,
    DWORD peek_status,
    DWORD peek_error,
    const char* dispatch_stage,
    UINT dispatch_msg,
    UINT_PTR dispatch_hwnd,
    const char* wndproc_stage,
    UINT wndproc_msg,
    UINT_PTR wndproc_hwnd)
{
    constexpr UINT kSendTimeoutFlags = SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT;
    constexpr UINT kSendTimeoutMs = 50U;
    char mcp_snapshot[1400] = {};
    char queue_snapshot[3000] = {};
    char ui_dispatch_snapshot[1400] = {};
    mcp_standalone::format_runtime_diagnostic_snapshot(mcp_snapshot, sizeof(mcp_snapshot));
    format_taskflow_runtime_hung_snapshot(queue_snapshot, sizeof(queue_snapshot));
    aida::ui_thread::format_snapshot(ui_dispatch_snapshot, sizeof(ui_dispatch_snapshot));

    HWND hwnd = g_hwnd;
    const BOOL hwnd_valid = hwnd ? ::IsWindow(hwnd) : FALSE;
    DWORD hwnd_pid = 0;
    DWORD ui_owner_tid = hwnd_valid ? ::GetWindowThreadProcessId(hwnd, &hwnd_pid) : 0;
    BOOL is_hung = FALSE;
    DWORD_PTR send_lresult = 0;
    BOOL send_ok = FALSE;
    DWORD send_gle = ERROR_INVALID_WINDOW_HANDLE;
    if (hwnd_valid) {
        is_hung = ::IsHungAppWindow(hwnd);
        ::SetLastError(0);
        send_ok = static_cast<BOOL>(::SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, kSendTimeoutFlags, kSendTimeoutMs, &send_lresult) != 0);
        send_gle = send_ok ? 0UL : ::GetLastError();
    }

    const uint64_t now_ms = static_cast<uint64_t>(::GetTickCount64());
    const uint64_t last_render_tick = aida_tracer::g_render_last_tick_ms.load(std::memory_order_acquire);
    const DWORD current_queue_status = ::GetQueueStatus(QS_ALLINPUT);

    char testlab_step_buf[260] = {};
    uint64_t testlab_step_start = 0;
    test_all_features::current_phase_and_step(nullptr, 0, testlab_step_buf, sizeof(testlab_step_buf), &testlab_step_start);
    const uint64_t testlab_step_elapsed = (testlab_step_start != 0 && now_ms >= testlab_step_start)
        ? (now_ms - testlab_step_start) : 0;
    const uint64_t input_event_age = (g_last_input_event_tick_ms != 0 && now_ms >= g_last_input_event_tick_ms)
        ? (now_ms - g_last_input_event_tick_ms) : 0;

    mcp_standalone::bounded_diag_snapshot_t bdiag = mcp_standalone::bounded_diagnostic_snapshot();
    std::string top_labels = aida::ui_thread::top_queued_labels(8);

    aida::diagnostics::window_hung::hung_context_t hctx;
    hctx.hwnd = hwnd;
    hctx.ui_owner_tid = ui_owner_tid;
    hctx.current_tid = ::GetCurrentThreadId();
    hctx.is_hung = is_hung;
    hctx.send_wm_null_ok = send_ok;
    hctx.send_wm_null_gle = send_gle;
    hctx.send_wm_null_lresult = static_cast<DWORD_PTR>(send_lresult);
    hctx.send_timeout_ms = kSendTimeoutMs;
    hctx.send_flags = kSendTimeoutFlags;
    hctx.peek_queue_status = peek_status;
    hctx.current_queue_status = current_queue_status;
    hctx.peek_gle = peek_error;
    hctx.peek_remove_flags = aida_tracer::g_peek_remove_flags.load(std::memory_order_acquire);
    hctx.peek_filter_hwnd = static_cast<std::uint64_t>(aida_tracer::g_peek_filter_hwnd.load(std::memory_order_acquire));
    hctx.peek_call_count = aida_tracer::g_peek_call_count.load(std::memory_order_acquire);
    hctx.peek_return_count = aida_tracer::g_peek_return_count.load(std::memory_order_acquire);
    hctx.send_only_defers = aida_tracer::g_peek_send_only_defers.load(std::memory_order_acquire);
    hctx.send_only_flushes = aida_tracer::g_peek_send_only_flushes.load(std::memory_order_acquire);
    hctx.stall_streak = stall_streak;
    hctx.frame = frame;
    hctx.heartbeat_tick_ms = last_render_tick;
    hctx.heartbeat_age_ms = age_ms;
    hctx.phase_name = phase_name;
    hctx.render_section = render_section;
    hctx.phase_id = phase_id;
    hctx.dispatch_stage = dispatch_stage;
    hctx.dispatch_msg = dispatch_msg;
    hctx.dispatch_hwnd = static_cast<UINT_PTR>(dispatch_hwnd);
    hctx.wndproc_stage = wndproc_stage;
    hctx.wndproc_msg = wndproc_msg;
    hctx.wndproc_hwnd = static_cast<UINT_PTR>(wndproc_hwnd);
    hctx.render_tid = render_tid;
    hctx.last_input_event_ms = input_event_age;
    hctx.last_successful_pump_return_ms = 0;
    hctx.ui_dispatcher_queue_depth = aida::ui_thread::pending_count();
    hctx.ui_dispatcher_oldest_queued_age_ms = aida::ui_thread::oldest_queued_age_ms();
    hctx.ui_dispatcher_wake_pending = aida::ui_thread::wake_pending();
    hctx.ui_dispatcher_rejected_count = aida::ui_thread::rejected_count();
    hctx.ui_dispatcher_drained_count = aida::ui_thread::drained_count();
    hctx.ui_dispatcher_budget_hit_count = aida::ui_thread::budget_hit_count();
    hctx.ui_dispatcher_time_budget_hit_count = aida::ui_thread::time_budget_hit_count();
    hctx.ui_dispatcher_affinity_violations = aida::ui_thread::affinity_violation_count();
    hctx.ui_dispatcher_top_labels = top_labels.c_str();
    hctx.mcp_active_requests = bdiag.active_requests;
    hctx.mcp_active_leases = bdiag.active_leases;
    hctx.mcp_oldest_owner = bdiag.oldest_owner;
    hctx.mcp_pending_cancellation_count = bdiag.pending_cancellations;
    hctx.capacity_pressure = bdiag.capacity_snapshot;
    hctx.downstream_pressure = bdiag.downstream_snapshot;
    hctx.testlab_step = testlab_step_buf;
    hctx.testlab_step_elapsed_ms = testlab_step_elapsed;
    hctx.driver_watchdog_ms = driver_bridge::driver_watchdog_age_ms();
    hctx.mcp_snapshot = mcp_snapshot;
    hctx.queue_snapshot = queue_snapshot;
    hctx.ui_dispatch_snapshot = ui_dispatch_snapshot;
    aida::diagnostics::window_hung::log_window_hung_snapshot(hctx);
    aida::diagnostics::window_hung::emit_hung_breadcrumb(hwnd, age_ms, phase_name);
}

struct process_cpu_delta_t {
    bool valid = false;
    DWORD gle = 0;
    DWORD logical_processors = 1;
    uint64_t wall_ms = 0;
    uint64_t busy_100ns = 0;
    double cpu_percent = 0.0;
};

static process_cpu_delta_t sample_current_process_cpu(uint64_t now_ms)
{
    static uint64_t s_last_wall_ms = 0;
    static uint64_t s_last_busy_100ns = 0;
    static DWORD s_logical_processors = 0;
    process_cpu_delta_t out{};
    if (s_logical_processors == 0) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        s_logical_processors = std::max<DWORD>(1, si.dwNumberOfProcessors);
    }
    out.logical_processors = s_logical_processors;
    FILETIME create_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    SetLastError(0);
    if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel_time, &user_time)) {
        out.gle = GetLastError();
        return out;
    }
    const uint64_t busy_100ns = filetime_to_u64(kernel_time) + filetime_to_u64(user_time);
    if (s_last_wall_ms != 0 && now_ms > s_last_wall_ms && busy_100ns >= s_last_busy_100ns) {
        out.valid = true;
        out.wall_ms = now_ms - s_last_wall_ms;
        out.busy_100ns = busy_100ns - s_last_busy_100ns;
        const double capacity_100ns = static_cast<double>(out.wall_ms) * 10000.0 * static_cast<double>(s_logical_processors);
        if (capacity_100ns > 0.0)
            out.cpu_percent = std::min(100.0, (static_cast<double>(out.busy_100ns) * 100.0) / capacity_100ns);
    }
    s_last_wall_ms = now_ms;
    s_last_busy_100ns = busy_100ns;
    return out;
}

struct process_io_delta_t {
    bool valid = false;
    DWORD gle = 0;
    std::uint64_t wall_ms = 0;
    std::uint64_t read_ops_delta = 0;
    std::uint64_t write_ops_delta = 0;
    std::uint64_t other_ops_delta = 0;
    std::uint64_t read_bytes_delta = 0;
    std::uint64_t write_bytes_delta = 0;
    std::uint64_t other_bytes_delta = 0;
    std::uint64_t total_read_bytes = 0;
    std::uint64_t total_write_bytes = 0;
};

static process_io_delta_t sample_process_io_delta(uint64_t now_ms)
{
    static IO_COUNTERS s_last{};
    static uint64_t s_last_ms = 0;
    process_io_delta_t out{};
    IO_COUNTERS cur{};
    SetLastError(0);
    if (!GetProcessIoCounters(GetCurrentProcess(), &cur)) {
        out.gle = GetLastError();
        return out;
    }
    out.total_read_bytes = static_cast<std::uint64_t>(cur.ReadTransferCount);
    out.total_write_bytes = static_cast<std::uint64_t>(cur.WriteTransferCount);
    if (s_last_ms != 0 && now_ms >= s_last_ms &&
        cur.ReadTransferCount >= s_last.ReadTransferCount &&
        cur.WriteTransferCount >= s_last.WriteTransferCount &&
        cur.OtherTransferCount >= s_last.OtherTransferCount) {
        out.valid = true;
        out.wall_ms = now_ms - s_last_ms;
        out.read_ops_delta = static_cast<std::uint64_t>(cur.ReadOperationCount - s_last.ReadOperationCount);
        out.write_ops_delta = static_cast<std::uint64_t>(cur.WriteOperationCount - s_last.WriteOperationCount);
        out.other_ops_delta = static_cast<std::uint64_t>(cur.OtherOperationCount - s_last.OtherOperationCount);
        out.read_bytes_delta = static_cast<std::uint64_t>(cur.ReadTransferCount - s_last.ReadTransferCount);
        out.write_bytes_delta = static_cast<std::uint64_t>(cur.WriteTransferCount - s_last.WriteTransferCount);
        out.other_bytes_delta = static_cast<std::uint64_t>(cur.OtherTransferCount - s_last.OtherTransferCount);
    }
    s_last = cur;
    s_last_ms = now_ms;
    return out;
}

struct file_delta_t {
    bool valid = false;
    bool reset = false;
    DWORD gle = 0;
    std::uint64_t size = 0;
    std::uint64_t delta = 0;
};

struct log_file_delta_snapshot_t {
    file_delta_t debug_log;
    file_delta_t kernel_log;
    file_delta_t full_test_log;
    file_delta_t camoufox_log;
};

static bool query_file_size_bytes(const char* path, std::uint64_t& size, DWORD& gle)
{
    size = 0;
    gle = 0;
    if (!path || !*path) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }
    WIN32_FILE_ATTRIBUTE_DATA data{};
    SetLastError(0);
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &data)) {
        gle = GetLastError();
        return false;
    }
    ULARGE_INTEGER v{};
    v.LowPart = data.nFileSizeLow;
    v.HighPart = data.nFileSizeHigh;
    size = v.QuadPart;
    return true;
}

static file_delta_t sample_one_file_delta(const char* path, std::uint64_t& previous_size, bool& previous_valid)
{
    file_delta_t out{};
    std::uint64_t size = 0;
    DWORD gle = 0;
    if (!query_file_size_bytes(path, size, gle)) {
        out.gle = gle;
        previous_valid = false;
        previous_size = 0;
        return out;
    }
    out.valid = true;
    out.size = size;
    if (previous_valid) {
        if (size >= previous_size) {
            out.delta = size - previous_size;
        } else {
            out.reset = true;
            out.delta = size;
        }
    }
    previous_valid = true;
    previous_size = size;
    return out;
}

static log_file_delta_snapshot_t sample_log_file_deltas()
{
    static std::uint64_t s_debug_size = 0;
    static std::uint64_t s_kernel_size = 0;
    static std::uint64_t s_full_test_size = 0;
    static std::uint64_t s_camoufox_size = 0;
    static bool s_debug_valid = false;
    static bool s_kernel_valid = false;
    static bool s_full_test_valid = false;
    static bool s_camoufox_valid = false;
    char log_dir[MAX_PATH] = {};
    _snprintf_s(log_dir, sizeof(log_dir), _TRUNCATE, "%s", diag::resolve_log_dir());
    char debug_path[MAX_PATH] = {};
    const char* cached_debug = diag::cached_log_path();
    if (cached_debug && cached_debug[0])
        _snprintf_s(debug_path, sizeof(debug_path), _TRUNCATE, "%s", cached_debug);
    else
        _snprintf_s(debug_path, sizeof(debug_path), _TRUNCATE, "%saida_debug.log", log_dir);
    char full_test_path[MAX_PATH] = {};
    char camoufox_path[MAX_PATH] = {};
    _snprintf_s(full_test_path, sizeof(full_test_path), _TRUNCATE, "%saida_full_test.log", log_dir);
    _snprintf_s(camoufox_path, sizeof(camoufox_path), _TRUNCATE, "%saida_camoufox_debug.log", log_dir);
    log_file_delta_snapshot_t out{};
    out.debug_log = sample_one_file_delta(debug_path, s_debug_size, s_debug_valid);
    out.kernel_log = sample_one_file_delta("C:\\Users\\Public\\Desktop\\aida_kernel.log", s_kernel_size, s_kernel_valid);
    out.full_test_log = sample_one_file_delta(full_test_path, s_full_test_size, s_full_test_valid);
    out.camoufox_log = sample_one_file_delta(camoufox_path, s_camoufox_size, s_camoufox_valid);
    return out;
}

struct defender_process_snapshot_t {
    bool valid = false;
    DWORD gle = 0;
    std::uint32_t msmpeng = 0;
    std::uint32_t mpcmdrun = 0;
};

static defender_process_snapshot_t sample_defender_processes()
{
    defender_process_snapshot_t out{};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        out.gle = GetLastError();
        return out;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        out.gle = GetLastError();
        CloseHandle(snap);
        return out;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"MsMpEng.exe") == 0)
            ++out.msmpeng;
        else if (_wcsicmp(pe.szExeFile, L"MpCmdRun.exe") == 0)
            ++out.mpcmdrun;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    out.valid = true;
    return out;
}

struct render_diag_cached_snapshot_t {
    uint64_t sample_ms = 0;
    uint64_t sequence = 0;
    DWORD thread_err = 0;
    DWORD thread_count = 0;
    process_cpu_delta_t cpu;
    process_io_delta_t proc_io;
    log_file_delta_snapshot_t log_files;
    defender_process_snapshot_t defender;
    aida::infra::taskflow_runtime::runtime_snapshot_t taskflow;
    taskflow_family_diag_t wq;
    taskflow_family_diag_t svc;
    taskflow_family_diag_t cq;
};

static std::mutex g_render_diag_cache_mutex;
static render_diag_cached_snapshot_t g_render_diag_cache;
static std::atomic<bool> g_render_diag_sample_inflight{false};
static std::atomic<uint64_t> g_render_diag_last_request_ms{0};
static std::atomic<uint64_t> g_render_diag_sequence{0};

static void publish_render_diag_snapshot(render_diag_cached_snapshot_t&& snapshot)
{
    snapshot.sequence = g_render_diag_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
    std::lock_guard<std::mutex> lock(g_render_diag_cache_mutex);
    g_render_diag_cache = std::move(snapshot);
}

static render_diag_cached_snapshot_t latest_render_diag_snapshot()
{
    std::lock_guard<std::mutex> lock(g_render_diag_cache_mutex);
    return g_render_diag_cache;
}

static void request_render_diag_snapshot_async(uint64_t now_ms, bool force)
{
    const uint64_t previous_request = g_render_diag_last_request_ms.load(std::memory_order_acquire);
    if (!force && previous_request != 0 && now_ms >= previous_request && now_ms - previous_request < 1000ULL)
        return;
    if (g_render_diag_sample_inflight.exchange(true, std::memory_order_acq_rel))
        return;
    g_render_diag_last_request_ms.store(now_ms, std::memory_order_release);
    std::function<void()> task = [] {
        try {
            render_diag_cached_snapshot_t snapshot;
            snapshot.sample_ms = static_cast<uint64_t>(GetTickCount64());
            snapshot.thread_count = count_current_process_threads(&snapshot.thread_err);
            snapshot.taskflow = aida::infra::taskflow_runtime::active_snapshot(128);
            snapshot.wq = make_taskflow_family_diag(snapshot.taskflow, taskflow_family_diag_kind_t::work);
            snapshot.svc = make_taskflow_family_diag(snapshot.taskflow, taskflow_family_diag_kind_t::service);
            snapshot.cq = make_taskflow_family_diag(snapshot.taskflow, taskflow_family_diag_kind_t::critical);
            snapshot.cpu = sample_current_process_cpu(snapshot.sample_ms);
            snapshot.proc_io = sample_process_io_delta(snapshot.sample_ms);
            snapshot.log_files = sample_log_file_deltas();
            snapshot.defender = sample_defender_processes();
            publish_render_diag_snapshot(std::move(snapshot));
        } catch (const std::exception& e) {
            diag::log_tagged_critical_fmt("render", "render_diag_sample_exception what=%.180s", e.what());
        } catch (...) {
            aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "render_diag_sample");
            diag::log_tagged_critical("render", "render_diag_sample_exception what=<unknown>");
        }
        g_render_diag_sample_inflight.store(false, std::memory_order_release);
    };
    const auto submit_result = submit_main_executor_task(
        "render",
        "render.diagnostics.sample",
        aida::infra::executor::domain_t::diagnostics,
        "diagnostics",
        std::move(task));
    bool posted = submit_result.submitted;
    if (!posted) {
        g_render_diag_sample_inflight.store(false, std::memory_order_release);
        static std::atomic<uint64_t> s_last_diag_post_fail_ms{0};
        const uint64_t last_fail_ms = s_last_diag_post_fail_ms.load(std::memory_order_acquire);
        if (last_fail_ms == 0 || now_ms - last_fail_ms >= 5000ULL) {
            s_last_diag_post_fail_ms.store(now_ms, std::memory_order_release);
            diag::log_tagged_critical_fmt("render",
                "render_diag_sample_post_failed force=%d now_ms=%llu last_request_ms=%llu",
                force ? 1 : 0,
                static_cast<unsigned long long>(now_ms),
                static_cast<unsigned long long>(previous_request));
        }
    }
}

struct frame_wait_result_t {
    DWORD requested_ms = 0;
    DWORD actual_ms = 0;
    DWORD result = WAIT_TIMEOUT;
    DWORD gle = 0;
    bool input_available = false;
};

static frame_wait_result_t wait_for_frame_latency_or_input(DWORD requested_ms)
{
    frame_wait_result_t out{};
    out.requested_ms = requested_ms;
    const uint64_t wait_start_ms = static_cast<uint64_t>(GetTickCount64());
    SetLastError(0);
    out.result = MsgWaitForMultipleObjectsEx(0, nullptr, requested_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    out.input_available = out.result == WAIT_OBJECT_0;
    if (out.result == WAIT_FAILED)
        out.gle = GetLastError();
    out.actual_ms = static_cast<DWORD>(std::min<uint64_t>(static_cast<uint64_t>(GetTickCount64()) - wait_start_ms, 0xFFFFFFFFULL));
    return out;
}

struct draw_data_metrics_t {
    int draw_lists = 0;
    int draw_cmds = 0;
    int callbacks = 0;
    int reset_callbacks = 0;
    int unexpected_callbacks = 0;
    int total_vtx = 0;
    int total_idx = 0;
    bool full_walk = false;
};

static draw_data_metrics_t collect_draw_data_metrics(ImDrawData* draw_data, bool full_walk)
{
    static draw_data_metrics_t sampled_metrics{};
    draw_data_metrics_t out{};
    if (!draw_data)
        return out;
    out.draw_lists = draw_data->CmdListsCount;
    out.total_vtx = draw_data->TotalVtxCount;
    out.total_idx = draw_data->TotalIdxCount;
    out.full_walk = full_walk;
    if (draw_data->CmdListsCount > 0 && !draw_data->CmdLists.Data)
        return out;
    const int list_count = draw_data->CmdListsCount > 0 ? draw_data->CmdListsCount : 0;
    if (!full_walk) {
        out.draw_cmds = sampled_metrics.draw_cmds;
        out.callbacks = sampled_metrics.callbacks;
        out.reset_callbacks = sampled_metrics.reset_callbacks;
        return out;
    }
    for (int list_index = 0; list_index < list_count; ++list_index) {
        const ImDrawList* list = draw_data->CmdLists[list_index];
        if (!list)
            continue;
        out.draw_cmds += list->CmdBuffer.Size;
        for (int cmd_index = 0; cmd_index < list->CmdBuffer.Size; ++cmd_index) {
            const ImDrawCmd& cmd = list->CmdBuffer[cmd_index];
            if (!cmd.UserCallback)
                continue;
            if (cmd.UserCallback == ImDrawCallback_ResetRenderState)
                ++out.reset_callbacks;
            else {
                ++out.callbacks;
                ++out.unexpected_callbacks;
            }
        }
    }
    sampled_metrics = out;
    return out;
}

static void format_message_pump_stall_context(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    char full_snapshot[1700] = {};
    char ui_phase[900] = {};
    char ui_dispatch[900] = {};
    char queue_snapshot[2600] = {};
    test_all_features::format_debug_snapshot(full_snapshot, sizeof(full_snapshot));
    test_all_features::format_ui_phase_snapshot(ui_phase, sizeof(ui_phase));
    aida::ui_thread::format_snapshot(ui_dispatch, sizeof(ui_dispatch));
    format_taskflow_runtime_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
    DWORD thread_err = 0;
    const DWORD threads = count_current_process_threads(&thread_err);
    DWORD handles = 0;
    const BOOL handle_ok = GetProcessHandleCount(GetCurrentProcess(), &handles);
    const DWORD handle_err = handle_ok ? 0UL : GetLastError();
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* render_section = g_render_section.c_str();
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "pid=%lu tid=%lu threads=%lu thread_err=%lu handles=%lu handle_ok=%d handle_err=%lu "
        "render_phase=%s render_section=%s dispatch_stage=%s dispatch_msg=%s(0x%04X) wndproc_stage=%s wndproc_msg=%s(0x%04X) "
        "full_test_running=%d ui={%.760s} ui_dispatch={%.760s} full={%.1200s} queues={%.1800s}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long>(threads),
        static_cast<unsigned long>(thread_err),
        static_cast<unsigned long>(handles),
        handle_ok ? 1 : 0,
        static_cast<unsigned long>(handle_err),
        render_phase ? render_phase : "<null>",
        render_section ? render_section : "<null>",
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        test_all_features::is_running() ? 1 : 0,
        ui_phase[0] ? ui_phase : "<empty>",
        ui_dispatch[0] ? ui_dispatch : "<empty>",
        full_snapshot[0] ? full_snapshot : "<empty>",
        queue_snapshot[0] ? queue_snapshot : "<empty>");
}

static void format_shutdown_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    char thread_desc[512] = {};
    char queue_snapshot[2400] = {};
    format_current_thread_description(thread_desc, sizeof(thread_desc));
    format_taskflow_runtime_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
    const char* shutdown_phase = aida_shutdown_diag::g_phase.load(std::memory_order_acquire);
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "shutdown_phase=%s shutdown_phase_age_ms=%llu tid=%lu thread_desc=%s render_phase=%s dispatch_stage=%s dispatch_msg=%s(0x%04X) wndproc_stage=%s wndproc_msg=%s(0x%04X) queues={%s}",
        shutdown_phase ? shutdown_phase : "<null>",
        static_cast<unsigned long long>(aida_shutdown_diag::phase_age_ms()),
        GetCurrentThreadId(),
        thread_desc[0] ? thread_desc : "<none>",
        render_phase ? render_phase : "<null>",
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        queue_snapshot);
}

__declspec(noinline) static DWORD seh_init_standalone_chat()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_init_standalone_chat_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        init_standalone_chat();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_init_standalone_chat");
        startup_log_critical_fmt("seh_init_standalone_chat_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_init_standalone_chat_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_network_view_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_network_view_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        network_view::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_network_view_initialize");
        startup_log_critical_fmt("seh_network_view_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_network_view_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_memory_scanner_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_memory_scanner_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        memory_scanner::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_memory_scanner_initialize");
        startup_log_critical_fmt("seh_memory_scanner_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_memory_scanner_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_mitm_proxy_pre_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        mitm_proxy::pre_initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_mitm_proxy_pre_initialize");
        startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_script_engine_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_script_engine_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    bool ok = false;
    __try {
        ok = script_engine::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_script_engine_initialize");
        startup_log_critical_fmt("seh_script_engine_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_script_engine_initialize_exit ok=%d initialized=%d elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        script_engine::is_initialized() ? 1 : 0,
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return ok ? 0 : ERROR_NOT_READY;
}

static std::atomic<bool> g_authorized_features_initialized{false};
static std::atomic<bool> g_authorized_features_posted{false};
static std::atomic<bool> g_camoufox_prewarm_posted{false};
static std::atomic<bool> g_script_engine_startup_init_posted{false};

static void post_script_engine_startup_initialize()
{
    if (script_engine::is_initialized()) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_initialized=1 pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    bool expected = false;
    if (!g_script_engine_startup_init_posted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_posted=1 initialized=%d pid=%lu tid=%lu tick=%llu",
            script_engine::is_initialized() ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    const uint64_t queued_at = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("script_engine_startup_async_posting pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(queued_at));
    std::function<void()> init_task = [queued_at]() {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("script_engine_startup_async_enter pid=%lu tid=%lu queued_ms=%llu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started - queued_at),
            static_cast<unsigned long long>(started));
        DWORD seh = seh_script_engine_initialize();
        startup_log_critical_fmt("script_engine_startup_async_exit seh=0x%08X initialized=%d elapsed_ms=%llu last_err=%lu",
            seh,
            script_engine::is_initialized() ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        if (seh != 0 && !script_engine::is_initialized())
            g_script_engine_startup_init_posted.store(false, std::memory_order_release);
    };

    bool posted_executor = false;
    std::string reject_reason = "<none>";
    try {
        const auto submit_result = submit_main_executor_task(
            "startup",
            "script_engine_startup_init",
            aida::infra::executor::domain_t::long_running,
            "startup_init",
            std::move(init_task));
        posted_executor = submit_result.submitted;
        if (!submit_result.reject_reason.empty())
            reject_reason = submit_result.reject_reason;
        startup_log_critical_fmt("script_engine_startup_async_posted pid=%lu tid=%lu service=%d work=%d executor=%d domain=long_running reject_reason=%.160s elapsed_ms=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            0,
            0,
            posted_executor ? 1 : 0,
            reject_reason.c_str(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    } catch (const std::exception& e) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=%.160s",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at),
            e.what());
    } catch (...) {
        aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "script_engine_startup_async_post");
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=<unknown>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    }

    if (!posted_executor && !script_engine::is_initialized()) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_failed pid=%lu tid=%lu queued_ms=%llu reason=%.160s initialized=%d",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at),
            reject_reason.c_str(),
            script_engine::is_initialized() ? 1 : 0);
    }
}

static void run_authorized_feature_initializers(const char* source)
{
    auto run = [source](const char* phase, DWORD(*fn)()) {
        DWORD seh = 0;
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("authorized_feature_phase_pre source=%s phase=%s pid=%lu tid=%lu tick=%llu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        diag::log_tagged_fmt("bg_init", "%s_start source=%s", phase, source ? source : "unknown");
        try {
            seh = fn();
        } catch (const std::exception& e) {
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=%.160s",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                e.what());
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=%s",
                phase, source ? source : "unknown", e.what());
            return false;
        } catch (...) {
            aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "authorized_feature_phase");
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=<unknown>",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=<unknown>",
                phase, source ? source : "unknown");
            return false;
        }
        if (seh != 0) {
            startup_log_critical_fmt("authorized_feature_phase_seh source=%s phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                source ? source : "unknown",
                phase ? phase : "unknown",
                seh,
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_seh source=%s code=0x%08X last_err=%lu",
                phase, source ? source : "unknown", seh, GetLastError());
            return false;
        }
        startup_log_critical_fmt("authorized_feature_phase_post source=%s phase=%s seh=0x%08X elapsed_ms=%llu last_err=%lu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        diag::log_tagged_fmt("bg_init", "%s_ok source=%s", phase, source ? source : "unknown");
        return true;
    };

    bool ok = true;
    ok = run("network_view_init", seh_network_view_initialize) && ok;
    ok = run("memory_scanner_init", seh_memory_scanner_initialize) && ok;
    ok = run("mitm_proxy_pre_init", seh_mitm_proxy_pre_initialize) && ok;
    startup_log_critical_fmt("authorized_feature_phase_async_post source=%s phase=script_engine_init pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "script_engine_init_async_start source=%s", source ? source : "unknown");
    post_script_engine_startup_initialize();
    g_authorized_features_initialized.store(ok, std::memory_order_release);
    if (!ok)
        g_authorized_features_posted.store(false, std::memory_order_release);
    startup_log_critical_fmt("authorized_feature_initializers_done source=%s ok=%d pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        ok ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "authorized_feature_initializers_done source=%s ok=%d",
        source ? source : "unknown", ok ? 1 : 0);
}

static void log_driver_bridge_initialize_call_post(bool ok, uint64_t started)
{
    std::string status = driver_bridge::status();
    startup_log_critical_fmt("seh_driver_bridge_initialize_call_post ok=%d loaded=%d kernel=%d status=%.160s elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        status.c_str(),
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
}

__declspec(noinline) static DWORD seh_driver_bridge_initialize_raw(bool* out_ok)
{
    __try {
        if (out_ok)
            *out_ok = driver_bridge::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_driver_bridge_initialize_raw");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_driver_bridge_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    bool ok = false;
    startup_log_critical_fmt("seh_driver_bridge_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    DWORD seh = seh_driver_bridge_initialize_raw(&ok);
    if (seh != 0) {
        startup_log_critical_fmt("seh_driver_bridge_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return seh;
    }
    log_driver_bridge_initialize_call_post(ok, started);
    startup_log_critical_fmt("seh_driver_bridge_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

static bool aida_is_fatal_exception_code(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
        return true;
    default:
        return code == 0xC0000409u;
    }
}

static bool aida_build_local_log_path(const char* file_name, char* out, size_t cap)
{
    if (!file_name || !out || cap == 0)
        return false;
    out[0] = '\0';
    char module[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    if (n == 0 || n >= sizeof(module))
        return false;
    char* slash = std::strrchr(module, '\\');
    if (!slash)
        return false;
    *(slash + 1) = '\0';
    _snprintf_s(out, cap, _TRUNCATE, "%s%s", module, file_name);
    return out[0] != '\0';
}

static void aida_append_direct_log_line(const char* file_name, const char* msg)
{
    if (!file_name || !msg || msg[0] == '\0')
        return;
    char path[MAX_PATH] = {};
    if (!aida_build_local_log_path(file_name, path, sizeof(path)))
        return;
    HANDLE hf = CreateFileA(path,
        FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return;
    DWORD written = 0;
    const DWORD len = static_cast<DWORD>(strnlen_s(msg, 4095));
    if (len != 0)
        WriteFile(hf, msg, len, &written, nullptr);
    DWORD newline_written = 0;
    WriteFile(hf, "\r\n", 2, &newline_written, nullptr);
    FlushFileBuffers(hf);
    CloseHandle(hf);
}

static void aida_append_direct_fatal_line(const char* msg)
{
    aida_append_direct_log_line("aida_crash.log", msg);
    aida_append_direct_log_line("aida_debug.log", msg);
}

static void aida_write_minimal_fatal_exception_line(EXCEPTION_POINTERS* ep, const char* phase)
{
    if (!ep || !ep->ExceptionRecord)
        return;
    CONTEXT* ctx = ep->ContextRecord;
    HMODULE exe_base = GetModuleHandleA(nullptr);
    uintptr_t exe_addr = reinterpret_cast<uintptr_t>(exe_base);
    uintptr_t rip = ctx ? static_cast<uintptr_t>(ctx->Rip) : 0;
    uintptr_t rsp = ctx ? static_cast<uintptr_t>(ctx->Rsp) : 0;
    uintptr_t rbp = ctx ? static_cast<uintptr_t>(ctx->Rbp) : 0;
    uintptr_t crash_addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    uintptr_t rip_offset = exe_addr && rip >= exe_addr ? rip - exe_addr : 0;
    uintptr_t addr_offset = exe_addr && crash_addr >= exe_addr ? crash_addr - exe_addr : 0;
    unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
        : 0ULL;
    unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        : 0ULL;
    char line[1536] = {};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "FIRST_CHANCE_FATAL_EXCEPTION phase=%s code=0x%08X addr=0x%016llX addr_off_exe=0x%llX rip=0x%016llX rip_off_exe=0x%llX rsp=0x%016llX rbp=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu tick=%llu",
        phase ? phase : "minimal",
        ep->ExceptionRecord->ExceptionCode,
        static_cast<unsigned long long>(crash_addr),
        static_cast<unsigned long long>(addr_offset),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rip_offset),
        static_cast<unsigned long long>(rsp),
        static_cast<unsigned long long>(rbp),
        GetCurrentThreadId(),
        ep->ExceptionRecord->ExceptionFlags,
        static_cast<unsigned long>(ep->ExceptionRecord->NumberParameters),
        p0,
        p1,
        GetLastError(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_append_direct_fatal_line(line);
}

static void aida_write_first_chance_crash_log(EXCEPTION_POINTERS* ep)
{
    static std::atomic<bool> written{false};
    if (!ep || !ep->ExceptionRecord || !aida_is_fatal_exception_code(ep->ExceptionRecord->ExceptionCode))
        return;
    bool expected = false;
    if (!written.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    __try {
        aida_write_minimal_fatal_exception_line(ep, "minimal");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    CONTEXT* ctx = ep->ContextRecord;
    HMODULE exe_base = GetModuleHandleA(nullptr);
    uintptr_t exe_addr = reinterpret_cast<uintptr_t>(exe_base);
    uintptr_t rip = ctx ? static_cast<uintptr_t>(ctx->Rip) : 0;
    uintptr_t rsp = ctx ? static_cast<uintptr_t>(ctx->Rsp) : 0;
    uintptr_t rbp = ctx ? static_cast<uintptr_t>(ctx->Rbp) : 0;
    uintptr_t crash_addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    uintptr_t rip_offset = exe_addr && rip >= exe_addr ? rip - exe_addr : 0;
    uintptr_t addr_offset = exe_addr && crash_addr >= exe_addr ? crash_addr - exe_addr : 0;
    unsigned long param_count = static_cast<unsigned long>(ep->ExceptionRecord->NumberParameters);
    unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
        : 0ULL;
    unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        : 0ULL;

    char tracer_snapshot[2600] = {};
    char shutdown_snapshot[4200] = {};
    char stack_modules[2200] = {};
    __try {
        format_tracer_crash_snapshot(tracer_snapshot, sizeof(tracer_snapshot));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _snprintf_s(tracer_snapshot, sizeof(tracer_snapshot), _TRUNCATE, "<tracer_snapshot_exception=0x%08X>", GetExceptionCode());
    }
    __try {
        format_shutdown_crash_snapshot(shutdown_snapshot, sizeof(shutdown_snapshot));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _snprintf_s(shutdown_snapshot, sizeof(shutdown_snapshot), _TRUNCATE, "<shutdown_snapshot_exception=0x%08X>", GetExceptionCode());
    }
    __try {
        format_context_stack_modules(ctx, stack_modules, sizeof(stack_modules));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _snprintf_s(stack_modules, sizeof(stack_modules), _TRUNCATE, "<stack_modules_exception=0x%08X>", GetExceptionCode());
    }
    char buf[8192] = {};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "FIRST_CHANCE_FATAL_CONTEXT code=0x%08X addr=0x%016llX addr_off_exe=0x%llX rip=0x%016llX rip_off_exe=0x%llX rsp=0x%016llX rbp=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu stack_modules={%s} shutdown={%s} tracer={%s}",
        ep->ExceptionRecord->ExceptionCode,
        static_cast<unsigned long long>(crash_addr),
        static_cast<unsigned long long>(addr_offset),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rip_offset),
        static_cast<unsigned long long>(rsp),
        static_cast<unsigned long long>(rbp),
        GetCurrentThreadId(),
        ep->ExceptionRecord->ExceptionFlags,
        param_count,
        p0,
        p1,
        GetLastError(),
        stack_modules,
        shutdown_snapshot,
        tracer_snapshot);
    aida_append_direct_fatal_line(buf);
}

static LONG CALLBACK aida_diagnostic_veh(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == 0x40010006u || code == 0x4001000Au || code == DBG_PRINTEXCEPTION_C ||
        code == DBG_PRINTEXCEPTION_WIDE_C ||
        code == 0x406D1388u ||
        code == 0xE06D7363u ||
        code == 0x06D007E0u ||
        code == STATUS_GUARD_PAGE_VIOLATION ||
        code == STATUS_SINGLE_STEP ||
        code == EXCEPTION_BREAKPOINT)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (aida::diagnostic_exception_scope::active())
    {
        unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
            ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
            : 0ULL;
        unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
            ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
            : 0ULL;
        diag::log_tagged_critical_fmt("veh",
            "scoped_first_chance scope=%s code=0x%08X addr=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX",
            aida::diagnostic_exception_scope::label(),
            code,
            (unsigned long long)reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress),
            GetCurrentThreadId(),
            ep->ExceptionRecord->ExceptionFlags,
            (unsigned long)ep->ExceptionRecord->NumberParameters,
            p0,
            p1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (aida_is_fatal_exception_code(code))
    {
        aida_write_first_chance_crash_log(ep);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    aida::diagnostics::crash::emit_crash_breadcrumb(code, ep->ExceptionRecord->ExceptionAddress, "aida_diagnostic_veh");
    if (!ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    HMODULE crash_mod = nullptr;
    char crash_mod_name[MAX_PATH] = "<unknown>";
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &crash_mod);
    if (crash_mod) GetModuleFileNameA(crash_mod, crash_mod_name, MAX_PATH);
    HMODULE exe_base = GetModuleHandleA(nullptr);
    uintptr_t rip_off_exe = ep->ContextRecord->Rip - reinterpret_cast<uintptr_t>(exe_base);
    uintptr_t addr_off_mod = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress)
        - reinterpret_cast<uintptr_t>(crash_mod);
    char test_all_snapshot[1200] = {};
    test_all_features::format_debug_snapshot(test_all_snapshot, sizeof(test_all_snapshot));
    diag::log_tagged_critical_fmt("veh",
        "code=0x%08X addr=0x%016llX rip=0x%016llX rip_off_exe=0x%llX "
        "mod=%s mod_off=0x%llX tid=%lu params=%lu p0=0x%016llX p1=0x%016llX test_all={%s}",
        code,
        (unsigned long long)reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress),
        (unsigned long long)ep->ContextRecord->Rip,
        (unsigned long long)rip_off_exe,
        crash_mod_name, (unsigned long long)addr_off_mod,
        GetCurrentThreadId(),
        (unsigned long)ep->ExceptionRecord->NumberParameters,
        (unsigned long long)(ep->ExceptionRecord->NumberParameters > 0
            ? ep->ExceptionRecord->ExceptionInformation[0] : 0ULL),
        (unsigned long long)(ep->ExceptionRecord->NumberParameters > 1
            ? ep->ExceptionRecord->ExceptionInformation[1] : 0ULL),
        test_all_snapshot);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void log_disk_backed_startup_state(const char* phase)
{
    char module[MAX_PATH] = {};
    char cwd[MAX_PATH] = {};
    char camoufox_exe[MAX_PATH] = {};
    char camoufox_python[MAX_PATH] = {};
    char camoufox_setup[32] = {};
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    GetCurrentDirectoryA(static_cast<DWORD>(sizeof(cwd)), cwd);
    GetEnvironmentVariableA("AIDA_CAMOUFOX_EXECUTABLE", camoufox_exe, static_cast<DWORD>(sizeof(camoufox_exe)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_PYTHON", camoufox_python, static_cast<DWORD>(sizeof(camoufox_python)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP", camoufox_setup, static_cast<DWORD>(sizeof(camoufox_setup)));

    std::uintptr_t teb = 0;
    std::uintptr_t peb = 0;
    std::uintptr_t tls_vector = 0;
    std::uintptr_t tls_slot51 = 0;
#if defined(_M_X64)
    teb = static_cast<std::uintptr_t>(__readgsqword(0x30));
    peb = static_cast<std::uintptr_t>(__readgsqword(0x60));
    tls_vector = static_cast<std::uintptr_t>(__readgsqword(0x58));
#endif
    if (tls_vector)
        safe_read_qword(reinterpret_cast<const void*>(tls_vector + 51u * sizeof(void*)), tls_slot51);

    HMODULE image = GetModuleHandleA(nullptr);
    MEMORY_BASIC_INFORMATION mbi{};
    if (image)
        VirtualQuery(image, &mbi, sizeof(mbi));

    diag::log_tagged_critical_fmt("main",
        "disk_backed_startup_state phase=%s pid=%lu tid=%lu module=%s cwd=%s camoufox_exe=%s camoufox_python=%s camoufox_setup=%s image_base=0x%016llX alloc_base=0x%016llX mbi_base=0x%016llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX teb=0x%016llX peb=0x%016llX tls_vector=0x%016llX tls_slot51=0x%016llX",
        phase ? phase : "",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        module,
        cwd,
        camoufox_exe,
        camoufox_python,
        camoufox_setup,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(image)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)),
        static_cast<unsigned long long>(mbi.RegionSize),
        mbi.State,
        mbi.Protect,
        static_cast<unsigned long long>(teb),
        static_cast<unsigned long long>(peb),
        static_cast<unsigned long long>(tls_vector),
        static_cast<unsigned long long>(tls_slot51));
}

int main(int, char**)
{
    aida_early_startup::install();
    aida_early_startup::mark("main_enter");
    aida_early_startup::mark("diagnostic_exception_scope_initialize_pre");
    bool diagnostic_scope_ready = aida::diagnostic_exception_scope::initialize();
    aida_early_startup::mark(diagnostic_scope_ready ? "diagnostic_exception_scope_initialized" : "diagnostic_exception_scope_failed");
    aida_early_startup::mark("diagnostic_veh_install_pre");
    PVOID diagnostic_veh = AddVectoredExceptionHandler(1, aida_diagnostic_veh);
    aida_early_startup::mark(diagnostic_veh ? "diagnostic_veh_installed" : "diagnostic_veh_install_failed");
    aida_early_startup::mark("normal_diag_log_pre");
    diag::log_tagged_critical("main", "diagnostic_veh_installed");
    aida::ui_thread::capture_owner_tid(::GetCurrentThreadId(), "main", "startup", "main_enter");
    command_sessions::set_ui_thread_id(::GetCurrentThreadId());
    aida::infra::executor::set_ui_owner_tid(::GetCurrentThreadId());
    aida::infra::taskflow_eval::log_evaluation();
    diag::log_tagged_critical_fmt("startup",
        "startup_begin pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_early_startup::mark_normal_diagnostics_reached();
    phase0_log_startup_invariants("post_normal_diag", nullptr);
    aida_early_startup::mark("disk_backed_startup_state_pre");
    log_disk_backed_startup_state("post_veh");
    aida_early_startup::mark("normal_startup_state_logged");
    aida_early_startup::mark("single_instance_gate_pre");
    if (!acquire_single_instance_gate()) {
        diag::log_tagged_critical("main", "single_instance_gate_refused");
        aida_early_startup::mark("single_instance_gate_refused");
        return 0;
    }
    aida_early_startup::mark("single_instance_gate_acquired");
    aida_early_startup::mark("post_gate_main_enter_pre");
    startup_log_critical_fmt("main_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("main_enter");
    aida_early_startup::mark("post_gate_main_enter_done");

    aida_early_startup::mark("post_gate_taskflow_pool_query_pre");
    const int taskflow_general_pool_size = aida::infra::taskflow_runtime::general_pool_size();
    const int taskflow_service_pool_size = aida::infra::taskflow_runtime::service_pool_size();
    const int taskflow_critical_pool_size = aida::infra::taskflow_runtime::domain_pool(
        aida::infra::taskflow_runtime::executor_domain_t::critical).configured_pool_size;
    aida_early_startup::mark("post_gate_taskflow_pool_query_done");
    startup_log_critical_fmt("taskflow_runtime_initialize_pre pid=%lu tid=%lu tick=%llu general_pool_size=%d service_pool_size=%d critical_pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        taskflow_general_pool_size,
        taskflow_service_pool_size,
        taskflow_critical_pool_size);
    aida_early_startup::mark("post_gate_taskflow_initialize_pre");
    aida::infra::taskflow_runtime::initialize();
    aida_early_startup::mark("post_gate_taskflow_initialize_done");
    const auto taskflow_init_snapshot = aida::infra::taskflow_runtime::active_snapshot();
    startup_log_critical_fmt("taskflow_runtime_initialize_post pid=%lu tid=%lu tick=%llu accepting=%d shutdown=%d total_active=%u work_pending=%llu service_pending=%llu critical_pending=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        taskflow_init_snapshot.accepting ? 1 : 0,
        taskflow_init_snapshot.shutting_down ? 1 : 0,
        static_cast<unsigned>(taskflow_init_snapshot.total_active),
        static_cast<unsigned long long>(taskflow_init_snapshot.work_queue_pending),
        static_cast<unsigned long long>(taskflow_init_snapshot.service_queue_pending),
        static_cast<unsigned long long>(taskflow_init_snapshot.critical_queue_pending));
    crash_log_write("taskflow_runtime_init_ok");
    aida_early_startup::mark("post_gate_taskflow_runtime_init_ok");
    phase0_post_wer_configuration_logging("post_taskflow_runtime_init");
    aida::diagnostics::metadata_ring::emit(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::startup_shutdown,
        "standalone_startup_begin", "phase0_complete", true);
    aida::diagnostics::wer::log_wer_correlation("startup");

    aida_early_startup::mark("post_gate_tracer_start_pre");
    startup_log_critical_fmt("tracer_start_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_tracer::start();
    aida_early_startup::mark("post_gate_tracer_start_done");
    startup_log_critical_fmt("tracer_start_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    aida_early_startup::mark("post_gate_unhandled_exception_filter_set_pre");
    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep) -> LONG {
        if (ep && ep->ExceptionRecord && ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        {
            HMODULE single_step_mod = nullptr;
            char single_step_module[MAX_PATH] = "<unknown>";
            uintptr_t single_step_addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
            if (ep->ExceptionRecord->ExceptionAddress &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &single_step_mod) &&
                single_step_mod)
            {
                GetModuleFileNameA(single_step_mod, single_step_module, MAX_PATH);
            }
            const uintptr_t single_step_module_base = reinterpret_cast<uintptr_t>(single_step_mod);
            const uintptr_t single_step_module_offset = single_step_module_base && single_step_addr >= single_step_module_base
                ? single_step_addr - single_step_module_base
                : 0;
            const char* early_phase = aida_early_startup::g_phase.load(std::memory_order_acquire);
            const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
            char single_step_buf[1024] = {};
            _snprintf_s(single_step_buf, sizeof(single_step_buf), _TRUNCATE,
                "single_step_unconsumed code=0x%08X pid=%lu tid=%lu addr=0x%016llX module=%s module_offset=0x%llX phase=%s render_phase=%s note=not_consumed_by_earlier_handlers",
                ep->ExceptionRecord->ExceptionCode,
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(single_step_addr),
                single_step_module,
                static_cast<unsigned long long>(single_step_module_offset),
                early_phase ? early_phase : "<unknown>",
                render_phase ? render_phase : "<unknown>");
            crash_log_write(single_step_buf);
            diag::write_crash_log(single_step_buf, false);
            diag::log_tagged_critical("exception", single_step_buf);
        }

        char buf[16384];
        HMODULE crash_mod = nullptr;
        char crash_mod_name[MAX_PATH] = "<unknown>";
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &crash_mod);
        if (crash_mod)
            GetModuleFileNameA(crash_mod, crash_mod_name, MAX_PATH);

        HMODULE exe_base = GetModuleHandleA(nullptr);
        uintptr_t rip_offset = ep->ContextRecord->Rip - reinterpret_cast<uintptr_t>(exe_base);
        uintptr_t addr_offset = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) - reinterpret_cast<uintptr_t>(crash_mod);
        char test_all_snapshot[1200] = {};
        test_all_features::format_debug_snapshot(test_all_snapshot, sizeof(test_all_snapshot));
        char tracer_snapshot[2600] = {};
        format_tracer_crash_snapshot(tracer_snapshot, sizeof(tracer_snapshot));
        char shutdown_snapshot[4200] = {};
        char stack_module_buf[2200] = {};
        format_shutdown_crash_snapshot(shutdown_snapshot, sizeof(shutdown_snapshot));
        format_context_stack_modules(ep->ContextRecord, stack_module_buf, sizeof(stack_module_buf));

        char stack_buf[512] = {};
        {
            const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ep->ContextRecord->Rsp);
            int off = 0;
            for (int i = 0; i < 12 && off < static_cast<int>(sizeof(stack_buf) - 32); ++i) {
                uintptr_t v = 0;
                if (!safe_read_qword(rsp_ptr + i, v)) break;
                off += _snprintf_s(stack_buf + off, sizeof(stack_buf) - off, _TRUNCATE,
                    "%s[%02d]=%016llX", (i == 0 ? "" : " "), i * 8,
                    static_cast<unsigned long long>(v));
            }
        }

        snprintf(buf, sizeof(buf),
            "EXCEPTION: code=0x%08X addr=0x%016llX tid=%lu\n"
            "CrashModule=%s ModuleOffset=0x%llX\n"
            "ExeBase=0x%p RipOffsetFromExe=0x%llX\n"
            "Flags=0x%08X NumParams=%lu\n"
            "Info[0]=0x%016llX Info[1]=0x%016llX\n"
            "Rax=%016llX Rcx=%016llX Rdx=%016llX Rbx=%016llX\n"
            "Rsp=%016llX Rbp=%016llX Rsi=%016llX Rdi=%016llX\n"
            "R8=%016llX R9=%016llX R10=%016llX R11=%016llX\n"
            "R12=%016llX R13=%016llX R14=%016llX R15=%016llX\n"
            "Rip=%016llX\n"
            "EFlags=%08lX Dr6=%016llX Dr7=%016llX\n"
            "Stack: %s\n"
            "StackModules=%s\n"
            "ShutdownSnapshot=%s\n"
            "TestAllSnapshot=%s\n"
            "TracerSnapshot=%s\n"
            "LastError=%lu\n",
            ep->ExceptionRecord->ExceptionCode,
            reinterpret_cast<unsigned long long>(ep->ExceptionRecord->ExceptionAddress),
            GetCurrentThreadId(),
            crash_mod_name,
            static_cast<unsigned long long>(addr_offset),
            exe_base,
            static_cast<unsigned long long>(rip_offset),
            ep->ExceptionRecord->ExceptionFlags,
            ep->ExceptionRecord->NumberParameters,
            ep->ExceptionRecord->NumberParameters > 0 ? ep->ExceptionRecord->ExceptionInformation[0] : 0ULL,
            ep->ExceptionRecord->NumberParameters > 1 ? ep->ExceptionRecord->ExceptionInformation[1] : 0ULL,
            ep->ContextRecord->Rax, ep->ContextRecord->Rcx,
            ep->ContextRecord->Rdx, ep->ContextRecord->Rbx,
            ep->ContextRecord->Rsp, ep->ContextRecord->Rbp,
            ep->ContextRecord->Rsi, ep->ContextRecord->Rdi,
            ep->ContextRecord->R8,  ep->ContextRecord->R9,
            ep->ContextRecord->R10, ep->ContextRecord->R11,
            ep->ContextRecord->R12, ep->ContextRecord->R13,
            ep->ContextRecord->R14, ep->ContextRecord->R15,
            ep->ContextRecord->Rip,
            static_cast<unsigned long>(ep->ContextRecord->EFlags),
            static_cast<unsigned long long>(ep->ContextRecord->Dr6),
            static_cast<unsigned long long>(ep->ContextRecord->Dr7),
            stack_buf,
            stack_module_buf,
            shutdown_snapshot,
            test_all_snapshot,
            tracer_snapshot,
            GetLastError());

        crash_log_write(buf);
        diag::write_crash_log(buf, false);

        {
            aida::diagnostics::crash::crash_context_t ctx;
            ctx.exception_code = ep->ExceptionRecord->ExceptionCode;
            ctx.exception_flags = ep->ExceptionRecord->ExceptionFlags;
            ctx.exception_address = ep->ExceptionRecord->ExceptionAddress;
            ctx.exception_record_count = ep->ExceptionRecord->NumberParameters;
            ctx.crash_boundary_name = "unhandled_exception_filter";
            ctx.current_tid = GetCurrentThreadId();
            ctx.ui_owner_tid = aida::ui_thread::owner_tid();
            ctx.last_render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
            ctx.last_render_tick_ms = aida_tracer::g_render_last_tick_ms.load(std::memory_order_acquire);
            const uint64_t crash_now_ms = static_cast<uint64_t>(GetTickCount64());
            ctx.render_heartbeat_age_ms = (ctx.last_render_tick_ms > 0 && crash_now_ms >= ctx.last_render_tick_ms)
                ? (crash_now_ms - ctx.last_render_tick_ms) : 0;
            ctx.last_wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
            ctx.last_dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
            ctx.last_message_pump_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
            ctx.last_input_event_ms = (g_last_input_event_tick_ms != 0 && crash_now_ms >= g_last_input_event_tick_ms)
                ? (crash_now_ms - g_last_input_event_tick_ms) : 0;
            char testlab_phase_buf[200] = {};
            char testlab_step_buf[260] = {};
            uint64_t testlab_step_start = 0;
            test_all_features::current_phase_and_step(testlab_phase_buf, sizeof(testlab_phase_buf),
                testlab_step_buf, sizeof(testlab_step_buf), &testlab_step_start);
            ctx.testlab_phase = testlab_phase_buf;
            ctx.testlab_step = testlab_step_buf;
            ctx.testlab_step_start_ms = testlab_step_start;
            ctx.driver_watchdog_ms = driver_bridge::driver_watchdog_age_ms();
            char thread_classes_buf[320] = {};
            {
                const auto exec_snap = aida::infra::executor::active_snapshot();
                _snprintf_s(thread_classes_buf, sizeof(thread_classes_buf), _TRUNCATE,
                    "general=%u service=%u critical=%u ui_dispatch=%u external=%u long_running=%u security=%u feature=%u diagnostics=%u total=%u oldest_ms=%llu",
                    static_cast<unsigned>(exec_snap.active_per_domain[0]),
                    static_cast<unsigned>(exec_snap.active_per_domain[1]),
                    static_cast<unsigned>(exec_snap.active_per_domain[2]),
                    static_cast<unsigned>(exec_snap.active_per_domain[3]),
                    static_cast<unsigned>(exec_snap.active_per_domain[4]),
                    static_cast<unsigned>(exec_snap.active_per_domain[5]),
                    static_cast<unsigned>(exec_snap.active_per_domain[6]),
                    static_cast<unsigned>(exec_snap.active_per_domain[7]),
                    static_cast<unsigned>(exec_snap.active_per_domain[8]),
                    static_cast<unsigned>(exec_snap.total_active),
                    static_cast<unsigned long long>(exec_snap.oldest_active_ms));
            }
            ctx.thread_runtime_active_classes = thread_classes_buf;
            char camoufox_longop_buf[64] = {};
            mcp_standalone::bounded_diag_snapshot_t bdiag = mcp_standalone::bounded_diagnostic_snapshot();
            _snprintf_s(camoufox_longop_buf, sizeof(camoufox_longop_buf), _TRUNCATE,
                "active=%zu", bdiag.camoufox_longop_active);
            ctx.camoufox_longop = camoufox_longop_buf;
            char mcp_snap[1400] = {};
            char queue_snap[3000] = {};
            char ui_dispatch_snap[1400] = {};
            mcp_standalone::format_runtime_diagnostic_snapshot(mcp_snap, sizeof(mcp_snap));
            format_taskflow_runtime_hung_snapshot(queue_snap, sizeof(queue_snap));
            aida::ui_thread::format_snapshot(ui_dispatch_snap, sizeof(ui_dispatch_snap));
            ctx.mcp_snapshot = mcp_snap;
            ctx.queue_snapshot = queue_snap;
            ctx.ui_dispatch_snapshot = ui_dispatch_snap;
            ctx.capacity_snapshot = bdiag.capacity_snapshot;
            ctx.lease_registry_snapshot = bdiag.lease_registry_snapshot;
            ctx.downstream_snapshot = bdiag.downstream_snapshot;
            aida::diagnostics::crash::log_crash_snapshot(ctx);
        }

        return EXCEPTION_CONTINUE_SEARCH;
    });
    crash_log_write("exception_filter_set");
    aida_early_startup::mark("post_gate_exception_filter_set");

    {
        aida_early_startup::mark("post_gate_settings_load_pre");
        const uint64_t settings_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("settings_load_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(settings_tick));
        bool settings_loaded = g_sa_settings.load();
        aida_early_startup::mark("post_gate_settings_load_done");
        g_sa_settings.editor_line_numbers   = true;
        g_sa_settings.editor_word_wrap      = true;
        g_sa_settings.editor_minimap        = true;
        g_sa_settings.editor_bracket_match  = true;
        g_sa_settings.editor_highlight_line = true;
        g_sa_settings.editor_auto_complete  = true;
        g_sa_settings.ghost_text_enabled    = true;
        g_sa_settings.auto_save_enabled     = true;
        crash_log_fmt("startup_settings_loaded=%d", settings_loaded ? 1 : 0);
        startup_log_critical_fmt("settings_load_post loaded=%d elapsed_ms=%llu",
            settings_loaded ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
    }

    aida_early_startup::mark("post_gate_appusermodelid_pre");
    HRESULT aumid_hr = ::SetCurrentProcessExplicitAppUserModelID(L"AiDA.Standalone.IDE");
    startup_log_critical_fmt("appusermodelid hr=0x%08lX",
        static_cast<unsigned long>(aumid_hr));

    aida_early_startup::mark("post_gate_appusermodelid_done");

    aida_early_startup::mark("post_gate_dpi_awareness_pre");
    startup_log_critical_fmt("dpi_awareness_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    startup_log_critical_fmt("dpi_awareness_post last_err=%lu",
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("dpi_awareness_set");
    aida_early_startup::mark("post_gate_dpi_awareness_done");

    aida_early_startup::mark("post_gate_window_identity_generate_pre");
    wcsncpy_s(g_aidaClassName, L"AiDA", _TRUNCATE);
    wcsncpy_s(g_aidaWindowTitle, L"AiDA", _TRUNCATE);
    startup_log_critical_fmt("window_identity_generated class_len=%zu title_len=%zu pid=%lu tid=%lu",
        wcslen(g_aidaClassName), wcslen(g_aidaWindowTitle),
        GetCurrentProcessId(), GetCurrentThreadId());

    aida_early_startup::mark("post_gate_window_identity_generate_done");

    aida_early_startup::mark("post_gate_register_class_pre");
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, g_aidaClassName, nullptr };
    startup_log_critical_fmt("register_class_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ATOM class_atom = ::RegisterClassExW(&wc);
    const bool class_registered = class_atom != 0;
    if (!class_registered) {
        startup_log_critical_fmt("register_class_failed last_err=%lu", static_cast<unsigned long>(GetLastError()));
        const bool executor_stopped = aida::infra::executor::shutdown(INFINITE);
        diag::log_tagged_critical_fmt("main", "partial_startup_executor_shutdown complete=%d", executor_stopped ? 1 : 0);
        release_single_instance_gate();
        return 1;
    }
    aida_early_startup::mark("post_gate_register_class_done");
    startup_log_critical_fmt("register_class_post atom=%u last_err=%lu",
        static_cast<unsigned>(class_atom),
        static_cast<unsigned long>(GetLastError()));
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    crash_log_fmt("screen=%dx%d", screen_w, screen_h);
    aida_early_startup::mark("post_gate_create_window_pre");
    startup_log_critical_fmt("create_window_pre screen_w=%d screen_h=%d pid=%lu tid=%lu tick=%llu",
        screen_w,
        screen_h,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    constexpr DWORD kAidaWindowStyle =
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
    constexpr DWORD kAidaWindowExStyle = WS_EX_APPWINDOW;
    HWND hwnd = ::CreateWindowExW(kAidaWindowExStyle,
                                  wc.lpszClassName,
                                  kAidaWindowTitle,
                                  kAidaWindowStyle,
                                  (screen_w - 200) / 2,
                                  (screen_h - 250) / 2,
                                  200,
                                  250,
                                  nullptr,
                                  nullptr,
                                   wc.hInstance,
                                   nullptr);
    aida_early_startup::mark("post_gate_create_window_done");
    g_hwnd = hwnd;
    if (!hwnd) {
        startup_log_critical_fmt("create_window_failed last_err=%lu", static_cast<unsigned long>(GetLastError()));
        if (class_registered)
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        const bool executor_stopped = aida::infra::executor::shutdown(INFINITE);
        diag::log_tagged_critical_fmt("main", "partial_startup_executor_shutdown complete=%d", executor_stopped ? 1 : 0);
        release_single_instance_gate();
        return 1;
    }
    bool imgui_context_created = false;
    bool ide_shell_initialized = false;
    auto cleanup_partial_startup = [&]() {
        aida::diagnostics::observer::stop();
        aida::ui_thread::shutdown();
        aida_hotkey_monitor::stop();
        aida_focus_monitor::stop();
        if (ide_shell_initialized) {
            aida::ui::ide_shell::shutdown();
            ide_shell_initialized = false;
        }
        const bool executor_stopped = aida::infra::executor::shutdown(INFINITE);
        diag::log_tagged_critical_fmt("main", "partial_startup_executor_shutdown complete=%d", executor_stopped ? 1 : 0);
        if (hwnd && IsWindow(hwnd))
            ::DestroyWindow(hwnd);
        if (g_imgui_dx11_initialized) {
            ImGui_ImplDX11_Shutdown();
            g_imgui_dx11_initialized = false;
        }
        if (g_imgui_win32_initialized) {
            ImGui_ImplWin32_Shutdown();
            g_imgui_win32_initialized = false;
        }
        if (imgui_context_created)
            ImGui::DestroyContext();
        if (blend_state) {
            blend_state->Release();
            blend_state = nullptr;
        }
        CleanupDeviceD3D();
        if (g_aidaWindowIcon) {
            DestroyIcon(g_aidaWindowIcon);
            g_aidaWindowIcon = nullptr;
        }
        if (class_registered)
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        release_single_instance_gate();
    };
    {
        aida::diagnostics::observer::observer_config_t obs_cfg;
        obs_cfg.enabled = true;
        obs_cfg.poll_interval_ms = 5000;
        obs_cfg.hung_threshold_ms = 5000;
        obs_cfg.max_lifetime_ms = 0;
        obs_cfg.wm_null_timeout_ms = 200;
        if (!aida::diagnostics::observer::start(GetCurrentProcessId(), hwnd, obs_cfg))
            diag::log_tagged_critical("main", "observer_start_failed");
    }
    DWORD hwnd_owner_tid = hwnd ? ::GetWindowThreadProcessId(hwnd, nullptr) : 0;
    if (hwnd_owner_tid != 0)
        aida::ui_thread::capture_owner_tid(hwnd_owner_tid, "main", "create_window", "post_create_window");
    startup_log_critical_fmt("create_window_post hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    phase0_log_startup_invariants("post_create_window", hwnd);
    startup_log_critical_fmt(
        "window_style_post style=0x%08lX exstyle=0x%08lX hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long>(::GetWindowLongPtrW(hwnd, GWL_STYLE)),
        static_cast<unsigned long>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("hwnd=%p", hwnd);


    {
        extern unsigned char aidalogo[];
        int iw2 = 0, ih2 = 0, ic = 0;
        unsigned char* px = stbi_load_from_memory(aidalogo, 1273853, &iw2, &ih2, &ic, 4);
        if (px && iw2 > 0 && ih2 > 0) {

            for (int i = 0; i < iw2 * ih2 * 4; i += 4)
                std::swap(px[i], px[i + 2]);
            HBITMAP hbm_color = CreateBitmap(iw2, ih2, 1, 32, px);
            HBITMAP hbm_mask  = CreateBitmap(iw2, ih2, 1, 1, nullptr);
            ICONINFO ii = {};
            ii.fIcon    = TRUE;
            ii.hbmColor = hbm_color;
            ii.hbmMask  = hbm_mask;
            HICON hIcon = CreateIconIndirect(&ii);
            if (hIcon) {
                g_aidaWindowIcon = hIcon;
                SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
            DeleteObject(hbm_color);
            DeleteObject(hbm_mask);
            stbi_image_free(px);
        }
    }
    crash_log_write("creating_d3d");
    aida_early_startup::mark("post_gate_create_d3d_pre");
    startup_log_critical_fmt("create_d3d_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    if (!CreateDeviceD3D(hwnd))
    {
        aida_early_startup::mark("post_gate_create_d3d_FAILED");
        startup_log_critical_fmt("create_d3d_failed hwnd=0x%llX last_err=%lu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            static_cast<unsigned long>(GetLastError()));
        crash_log_write("d3d_creation_FAILED");
        cleanup_partial_startup();
        return 1;
    }
    startup_log_critical_fmt("create_d3d_post device=0x%llX ctx=0x%llX swapchain=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
        static_cast<unsigned long>(GetLastError()));
    aida_early_startup::mark("post_gate_create_d3d_done");
    crash_log_fmt("d3d_ok device=%p ctx=%p swapchain=%p", g_pd3dDevice, g_pd3dDeviceContext, g_pSwapChain);

    startup_log_critical_fmt("show_window_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_early_startup::mark("post_gate_show_window_pre");
    ::ShowWindow(hwnd, SW_SHOW);
    ::UpdateWindow(hwnd);
    startup_log_critical_fmt("show_window_post hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    aida_hotkey_monitor::start(hwnd);
    crash_log_write("window_shown");

    {
        ::DragAcceptFiles(hwnd, TRUE);
        HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
        using ChangeWMFEx_t = BOOL(WINAPI*)(HWND, UINT, DWORD, void*);
        auto pChangeWMFEx = user32
            ? reinterpret_cast<ChangeWMFEx_t>(::GetProcAddress(user32, "ChangeWindowMessageFilterEx"))
            : nullptr;
        if (pChangeWMFEx) {
            pChangeWMFEx(hwnd, WM_DROPFILES, 1u, nullptr);
            pChangeWMFEx(hwnd, 0x0049u, 1u, nullptr);
            pChangeWMFEx(hwnd, WM_COPYDATA, 1u, nullptr);
            diag::log_tagged("dragdrop", "msg_filter_relaxed for elevated drop");
        } else {
            diag::log_tagged("dragdrop", "ChangeWindowMessageFilterEx unavailable");
        }
        diag::log_tagged("dragdrop", "DragAcceptFiles enabled on main window");
    }

    IMGUI_CHECKVERSION();
    aida_early_startup::mark("post_gate_imgui_context_create_pre");
    startup_log_critical_fmt("imgui_context_create_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    if (!aida::ui_thread::require_owner("imgui", "create_context", "startup")) {
        cleanup_partial_startup();
        return 1;
    }
    ImGui::CreateContext();
    imgui_context_created = true;
    aida_early_startup::mark("post_gate_imgui_context_create_done");
    startup_log_critical_fmt("imgui_context_create_post ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())));
    crash_log_write("imgui_context_created");
    startup_log_critical_fmt("imgui_getio_pre ctx=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    if (!aida::ui_thread::require_owner("imgui", "get_io", "startup")) {
        cleanup_partial_startup();
        return 1;
    }
    ImGuiIO& io = ImGui::GetIO();
    startup_log_critical_fmt("imgui_getio_post io=0x%llX fonts=0x%llX config=0x%08X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(&io)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        static_cast<unsigned>(io.ConfigFlags));
    startup_log_critical_fmt("imgui_config_flags_pre flags=0x%08X nav_capture=%d",
        static_cast<unsigned>(io.ConfigFlags),
        io.ConfigNavCaptureKeyboard ? 1 : 0);
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
    aida::ui::ide_shell::configure_io(io);
    io.ConfigNavCaptureKeyboard = false;
    startup_log_critical_fmt("imgui_config_flags_post flags=0x%08X nav_capture=%d",
        static_cast<unsigned>(io.ConfigFlags),
        io.ConfigNavCaptureKeyboard ? 1 : 0);


    {
            startup_log_critical_fmt("dpi_scale_query_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        UINT dpi = GetDpiForWindow(hwnd);
            globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
        aida::ui::set_dpi_scale(globals::ui::dpi_scale);
        startup_log_critical_fmt("dpi_scale_query_post dpi=%u scale=%.3f last_err=%lu",
            dpi,
            globals::ui::dpi_scale,
            static_cast<unsigned long>(GetLastError()));
    }

    startup_log_critical_fmt("apply_initial_theme_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    apply_initial_theme();
    startup_log_critical_fmt("apply_initial_theme_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    startup_log_critical_fmt("rebuild_fonts_pre dpi_scale=%.3f pid=%lu tid=%lu tick=%llu",
        globals::ui::dpi_scale,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    rebuild_fonts(globals::ui::dpi_scale);
    g_AppliedFontDpi.store(GetDpiForWindow(hwnd), std::memory_order_release);
    startup_log_critical_fmt("rebuild_fonts_post ui400=0x%llX code400=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400)));

    crash_log_write("fonts_built");
    startup_log_critical_fmt("imgui_backend_win32_pre hwnd=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    if (!aida::ui_thread::require_owner("imgui_win32", "backend_init", "startup")) {
        cleanup_partial_startup();
        return 1;
    }
    g_imgui_win32_initialized = ImGui_ImplWin32_Init(hwnd);
    startup_log_critical_fmt("imgui_backend_win32_post initialized=%d last_err=%lu",
        g_imgui_win32_initialized ? 1 : 0,
        static_cast<unsigned long>(GetLastError()));
    if (!g_imgui_win32_initialized) {
        cleanup_partial_startup();
        return 1;
    }
    crash_log_write("imgui_win32_init_ok");
    startup_log_critical_fmt("imgui_backend_dx11_pre device=0x%llX ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
    if (!aida::ui_thread::require_owner("dx11", "imgui_backend_init", "startup")) {
        cleanup_partial_startup();
        return 1;
    }
    g_imgui_dx11_initialized = ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    startup_log_critical_fmt("imgui_backend_dx11_post initialized=%d last_err=%lu",
        g_imgui_dx11_initialized ? 1 : 0,
        static_cast<unsigned long>(GetLastError()));
    if (!g_imgui_dx11_initialized) {
        cleanup_partial_startup();
        return 1;
    }
    crash_log_write("imgui_dx11_init_ok");
    aida::ui::ide_shell::initialize();
    ide_shell_initialized = true;
    D3D11_BLEND_DESC blend_desc = {};
    blend_desc.RenderTarget[0].BlendEnable = TRUE;
    blend_desc.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
    blend_desc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    blend_desc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    blend_desc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    blend_desc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    blend_desc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    blend_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    startup_log_critical_fmt("blend_state_create_pre device=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)));
    const HRESULT blend_hr = g_pd3dDevice->CreateBlendState(&blend_desc, &blend_state);
    if (FAILED(blend_hr) || !blend_state) {
        startup_log_critical_fmt("blend_state_create_failed hr=0x%08X state=0x%llX last_err=%lu",
            static_cast<unsigned>(blend_hr),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(blend_state)),
            static_cast<unsigned long>(GetLastError()));
        cleanup_partial_startup();
        return 1;
    }
    if (!aida::ui_thread::require_owner("dx11", "blend_state", "startup")) {
        cleanup_partial_startup();
        return 1;
    }
    g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);
    startup_log_critical_fmt("blend_state_create_post blend=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(blend_state)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("blend_state=%p", blend_state);
    aida::ui_thread::mark_ready(hwnd, "main", "ui_dispatcher", "post_init");

    static std::atomic<bool> bg_init_done{false};
    globals::ui::bg_init_done = &bg_init_done;
    globals::ui::bg_init_total.store(7, std::memory_order_release);
    globals::ui::bg_init_step.store(0, std::memory_order_release);
    startup_log_critical_fmt("bg_init_config total=%d initial_step=%d label=%s pid=%lu tid=%lu tick=%llu",
        globals::ui::bg_init_total.load(std::memory_order_acquire),
        globals::ui::bg_init_step.load(std::memory_order_acquire),
        startup_bg_phase_label(globals::ui::bg_init_step.load(std::memory_order_acquire)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    driver_bridge::set_log_callback([](const std::string& msg) {
        crash_log_write(msg.c_str());
    });
    startup_log_critical_fmt("driver_bridge_log_callback_set pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    startup_log_critical_fmt("bg_init_critical_post_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    const auto bg_submit_result = submit_main_executor_task(
        "startup",
        "startup.bg_init",
        aida::infra::executor::domain_t::security_liveness,
        "security_liveness",
        []() {
        const uint64_t thread_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("bg_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(thread_tick));
        diag::log_tagged("bg_init", "thread_entry");

        auto run_step = [](const char* start_log, const char* phase, const char* ok_log, int step, auto&& fn) {
            bool cpp_ok = true;
            DWORD seh_code = 0;
            const uint64_t started = static_cast<uint64_t>(GetTickCount64());
            startup_log_critical_fmt("bg_init_run_step_pre phase=%s start_log=%s target_step=%d target_label=%s pid=%lu tid=%lu tick=%llu",
                phase ? phase : "unknown",
                start_log ? start_log : "unknown",
                step,
                startup_bg_phase_label(step),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(started));
            startup_store_bg_step(step, "bg_init_worker_enter", phase);
            diag::log_tagged("bg_init", start_log);
            try {
                seh_code = fn();
            } catch (const std::exception& e) {
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=%.160s",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                    e.what());
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=%s", phase, e.what());
            } catch (...) {
                aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "bg_init_run_step");
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=<unknown>",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=<unknown>", phase);
            }
            if (seh_code != 0) {
                startup_log_critical_fmt("bg_init_run_step_seh phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                    phase ? phase : "unknown",
                    seh_code,
                    static_cast<unsigned long>(GetLastError()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_seh code=0x%08X last_err=%lu", phase, seh_code, GetLastError());
            }
            if (cpp_ok && seh_code == 0)
                diag::log_tagged("bg_init", ok_log);
            else
                diag::log_tagged_fmt("bg_init", "%s_failed cpp=%d seh=0x%08X", phase, cpp_ok ? 1 : 0, seh_code);
            startup_log_critical_fmt("bg_init_run_step_post phase=%s cpp=%d seh=0x%08X elapsed_ms=%llu last_err=%lu",
                phase ? phase : "unknown",
                cpp_ok ? 1 : 0,
                seh_code,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                static_cast<unsigned long>(GetLastError()));
            startup_store_bg_step(step, "bg_init_worker", phase);
            return cpp_ok && seh_code == 0;
        };

        const bool driver_ready = run_step("driver_bridge_init_start", "driver_bridge_init", "driver_bridge_init_ok", 1,
            []() {
                const DWORD seh = seh_driver_bridge_initialize();
                if (seh != 0)
                    return seh;
                return driver_bridge::is_loaded() ? static_cast<DWORD>(ERROR_SUCCESS) : static_cast<DWORD>(ERROR_DEVICE_NOT_AVAILABLE);
            });

        bool startup_steps_ok = true;
        startup_steps_ok = run_step("init_standalone_chat_start", "init_standalone_chat", "standalone_chat_init_ok", 2,
            []() { return seh_init_standalone_chat(); }) && startup_steps_ok;

        startup_steps_ok = run_step("network_view_init_start", "network_view_init", "network_view_init_ok", 3,
            []() { return seh_network_view_initialize(); }) && startup_steps_ok;

        startup_steps_ok = run_step("memory_scanner_init_start", "memory_scanner_init", "memory_scanner_init_ok", 4,
            []() { return seh_memory_scanner_initialize(); }) && startup_steps_ok;

        startup_steps_ok = run_step("mitm_proxy_pre_init_start", "mitm_proxy_pre_init", "mitm_proxy_pre_init_ok", 5,
            []() { return seh_mitm_proxy_pre_initialize(); }) && startup_steps_ok;

        startup_log_critical_fmt("bg_init_script_engine_async_pre phase=script_engine_init target_step=6 target_label=%s pid=%lu tid=%lu tick=%llu",
            startup_bg_phase_label(6),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged("bg_init", "script_engine_init_async_start");
        post_script_engine_startup_initialize();
        startup_store_bg_step(6, "bg_init_worker", "script_engine_init_async_posted");
        diag::log_tagged("bg_init", "script_engine_init_async_posted");
        g_authorized_features_initialized.store(startup_steps_ok, std::memory_order_release);
        g_authorized_features_posted.store(startup_steps_ok, std::memory_order_release);

        startup_store_bg_step(7, "bg_init_worker", "bg_init_all_steps_done");

        bg_init_done.store(true, std::memory_order_release);
        startup_log_critical_fmt("bg_init_thread_exit ok=%d driver_ready=%d driver_status=%.160s elapsed_ms=%llu final_step=%d pid=%lu tid=%lu tick=%llu",
            startup_steps_ok ? 1 : 0,
            driver_ready ? 1 : 0,
            driver_bridge::status().c_str(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - thread_tick),
            globals::ui::bg_init_step.load(std::memory_order_acquire),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged("bg_init", "thread_exit");
    });
    bool bg_posted = bg_submit_result.submitted;
    startup_log_critical_fmt("bg_init_critical_post_post posted=%d reject_reason=%.160s pid=%lu tid=%lu tick=%llu",
        bg_posted ? 1 : 0,
        bg_submit_result.reject_reason.empty() ? "<none>" : bg_submit_result.reject_reason.c_str(),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    if (!bg_posted) {
        startup_store_bg_step(7, "bg_init_submit_rejected", "bg_init_not_started");
        bg_init_done.store(true, std::memory_order_release);
        g_authorized_features_initialized.store(false, std::memory_order_release);
        g_authorized_features_posted.store(false, std::memory_order_release);
        diag::log_tagged_critical_fmt("bg_init",
            "submission_rejected reason=%.160s loading_released=1 final_step=%d",
            bg_submit_result.reject_reason.empty() ? "<none>" : bg_submit_result.reject_reason.c_str(),
            globals::ui::bg_init_step.load(std::memory_order_acquire));
    }


    ImVec4 clear_color = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    crash_log_write("entering_render_loop");
    startup_log_critical_fmt("focus_monitor_main_start_pre hwnd=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    aida_focus_monitor::start(hwnd);
    const int ui_prior_priority = GetThreadPriority(GetCurrentThread());
    const BOOL ui_priority_set = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    startup_log_critical_fmt("render_loop_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_critical_fmt("render",
        "ui_thread_priority prior=%d set=%d current=%d gle=%lu",
        ui_prior_priority,
        ui_priority_set ? 1 : 0,
        GetThreadPriority(GetCurrentThread()),
        ui_priority_set ? 0UL : GetLastError());


    bool done = false;
    static int prev_state = -1;
    static uint64_t frame_number = 0;
    static uint64_t skipped_render_frames = 0;
    while (!done)
    {
        const uint64_t frame_start_tick_ms = static_cast<uint64_t>(GetTickCount64());
        uint32_t pumped_messages = 0;
        uint32_t pumped_input_messages = 0;
        uint32_t pumped_resize_messages = 0;
        uint32_t pumped_paint_messages = 0;
        static uint64_t s_last_input_event_log_ms = 0;
        static uint64_t s_suppressed_pointer_motion_events = 0;
        static uint64_t s_suppressed_pointer_motion_max_age_ms = 0;
        const uint64_t input_events_at_frame_start = g_input_event_count;
        aida_tracer::render_pulse(frame_number);
        aida_tracer::mark_render_phase("frame_top");
        if (frame_number < 5)
            crash_log_fmt("frame_begin #%llu", frame_number);

        aida_tracer::mark_render_phase("peek_message_begin");
        MSG msg;
        static bool ctrl_shift_t_chord_latched = false;
        for (;;)
        {
            aida_tracer::mark_render_phase("peek_message_probe");
            DWORD queue_status_before = ::GetQueueStatus(QS_ALLINPUT);
            const DWORD queue_changed = LOWORD(queue_status_before);
            const DWORD queue_current = HIWORD(queue_status_before);
            const bool ctrl_shift_t_chord_active = (queue_current & QS_KEY) != 0 && aida_ctrl_shift_t_chord_down();
            if (ctrl_shift_t_chord_active) {
                aida_tracer::mark_render_phase("peek_message_hotkey_chord_defer");
                if (!ctrl_shift_t_chord_latched)
                    (void)aida_hotkey_monitor::trigger(hwnd, "ui_prepeek_ctrl_shift_t", static_cast<WORD>(MOD_CONTROL | MOD_SHIFT), 'T', queue_status_before);
                ctrl_shift_t_chord_latched = true;
                break;
            }
            ctrl_shift_t_chord_latched = false;
            if (queue_current == 0) {
                aida_tracer::set_peek_state(queue_status_before, 0);
                aida_tracer::set_peek_call_shape(kAidaQueuedPeekFlags, nullptr);
            }
            const bool send_message_pending = (queue_current & QS_SENDMESSAGE) != 0;
            const bool non_send_pending = ((queue_current | queue_changed) & kAidaNonSendQueueBits) != 0;
            const bool send_only_pending = send_message_pending && !non_send_pending;
            if (send_only_pending) {
                aida_tracer::set_peek_state(queue_status_before, 0);
                aida_tracer::set_peek_call_shape(kAidaSendOnlyPeekFlags, nullptr);
                aida_tracer::mark_render_phase("peek_message_send_only_drain");
                ::SetLastError(0);
                MSG sent_probe{};
                const uint64_t drain_start = static_cast<uint64_t>(GetTickCount64());
                BOOL sent_probe_result = ::PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags);
                const DWORD sent_probe_gle = ::GetLastError();
                const uint64_t drain_elapsed = static_cast<uint64_t>(GetTickCount64()) - drain_start;
                aida_tracer::set_peek_state(queue_status_before, sent_probe_gle);
                if (drain_elapsed >= 50) {
                    char stall_context[4600] = {};
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                    diag::log_tagged_critical_fmt("msgpump",
                        "send_only_drain_slow frame=%llu elapsed_ms=%llu result=%d gle=%lu qs=0x%08lX current=0x%04lX changed=0x%04lX flags=0x%08X ctx={%.3600s}",
                        (unsigned long long)frame_number,
                        (unsigned long long)drain_elapsed,
                        sent_probe_result ? 1 : 0,
                        static_cast<unsigned long>(sent_probe_gle),
                        static_cast<unsigned long>(queue_status_before),
                        static_cast<unsigned long>(queue_current),
                        static_cast<unsigned long>(queue_changed),
                        kAidaSendOnlyPeekFlags,
                        stall_context[0] ? stall_context : "<empty>");
                }
                const uint64_t pump_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - frame_start_tick_ms;
                if (pump_elapsed_ms >= kAidaMessagePumpBudgetMs) {
                    static uint64_t s_last_send_only_budget_log_ms = 0;
                    const uint64_t budget_now_ms = static_cast<uint64_t>(GetTickCount64());
                    if (s_last_send_only_budget_log_ms == 0 || budget_now_ms - s_last_send_only_budget_log_ms >= 1000ULL) {
                        s_last_send_only_budget_log_ms = budget_now_ms;
                        diag::log_tagged_fmt("msgpump",
                            "send_only_pump_budget_yield frame=%llu elapsed_ms=%llu budget_ms=%lu qs=0x%08lX current=0x%04lX changed=0x%04lX result=%d gle=%lu",
                            static_cast<unsigned long long>(frame_number),
                            static_cast<unsigned long long>(pump_elapsed_ms),
                            static_cast<unsigned long>(kAidaMessagePumpBudgetMs),
                            static_cast<unsigned long>(queue_status_before),
                            static_cast<unsigned long>(queue_current),
                            static_cast<unsigned long>(queue_changed),
                            sent_probe_result ? 1 : 0,
                            static_cast<unsigned long>(sent_probe_gle));
                    }
                    break;
                }
                continue;
            }
            const UINT peek_remove_flags = kAidaQueuedPeekFlags;
            HWND peek_filter = nullptr;
            ::SetLastError(0);
            aida_tracer::set_peek_state(queue_status_before, 0);
            aida_tracer::set_peek_call_shape(peek_remove_flags, peek_filter);
            uint64_t peek_start = static_cast<uint64_t>(GetTickCount64());
            aida_tracer::mark_render_phase("peek_message_call");
            aida_tracer::g_peek_call_count.fetch_add(1, std::memory_order_acq_rel);
            BOOL has_message = ::PeekMessage(&msg, peek_filter, 0U, 0U, peek_remove_flags);
            aida_tracer::g_peek_return_count.fetch_add(1, std::memory_order_acq_rel);
            aida::diagnostics::metadata_ring::emit(
                aida::diagnostics::metadata_ring::breadcrumb_category_t::message_pump,
                "message_pump_phase", nullptr, false);
            DWORD peek_gle = ::GetLastError();
            uint64_t peek_elapsed = static_cast<uint64_t>(GetTickCount64()) - peek_start;
            aida_tracer::set_peek_state(queue_status_before, peek_gle);
            if (peek_elapsed >= 50) {
                char stall_context[4600] = {};
                format_message_pump_stall_context(stall_context, sizeof(stall_context));
                const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
                const char* render_section = g_render_section.c_str();
                const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
                diag::log_tagged_critical_fmt("msgpump",
                    "peek_slow frame=%llu elapsed_ms=%llu has_message=%d qs=0x%08lX gle=%lu flags=0x%08X filter=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX render_phase=%s render_section=%s wndproc_stage=%s ctx={%.3600s}",
                    (unsigned long long)frame_number,
                    (unsigned long long)peek_elapsed,
                    has_message ? 1 : 0,
                    static_cast<unsigned long>(queue_status_before),
                    static_cast<unsigned long>(peek_gle),
                    peek_remove_flags,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(peek_filter),
                    has_message ? aida_tracer::message_name(msg.message) : "<none>",
                    has_message ? msg.message : 0,
                    has_message ? (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd) : 0ull,
                    has_message ? (unsigned long long)static_cast<UINT_PTR>(msg.wParam) : 0ull,
                    has_message ? (unsigned long long)static_cast<LONG_PTR>(msg.lParam) : 0ull,
                    render_phase ? render_phase : "<null>",
                    render_section ? render_section : "<null>",
                    wndproc_stage ? wndproc_stage : "<null>",
                    stall_context[0] ? stall_context : "<empty>");
            }
            if (!has_message)
                break;

            ++pumped_messages;
            if (aida::ui_thread::is_wake_message(msg.message)) {
                aida::ui_thread::acknowledge_wake_message();
                continue;
            }
            bool input_message = false;
            if (aida_is_input_or_attention_message(msg.message)) {
                input_message = true;
                ++pumped_input_messages;
            } else if (aida_is_resize_message(msg.message)) {
                ++pumped_resize_messages;
            } else if (aida_is_paint_message(msg.message)) {
                ++pumped_paint_messages;
            }
            if (input_message) {
                const uint64_t input_now_ms = static_cast<uint64_t>(GetTickCount64());
                const DWORD input_msg_age_ms = static_cast<DWORD>(GetTickCount() - msg.time);
                POINT input_cursor{};
                const bool input_cursor_ok = GetCursorPos(&input_cursor) != FALSE;
                const bool pointer_motion_msg = msg.message == WM_MOUSEMOVE || msg.message == WM_NCMOUSEMOVE;
                aida_record_input_message(msg, input_now_ms);
                const bool delayed_pointer_motion = pointer_motion_msg && input_msg_age_ms >= kAidaInputMotionLagLogIntervalMs;
                const uint64_t pointer_motion_interval_ms = delayed_pointer_motion ? kAidaInputMotionLagLogIntervalMs : kAidaInputMotionLogIntervalMs;
                const bool pointer_motion_summary_due = pointer_motion_msg &&
                    (s_last_input_event_log_ms == 0 || input_now_ms - s_last_input_event_log_ms >= pointer_motion_interval_ms);
                const bool log_input_event = !pointer_motion_msg || pointer_motion_summary_due;
                if (log_input_event) {
                    LARGE_INTEGER qpc{};
                    QueryPerformanceCounter(&qpc);
                    const uint64_t suppressed_pointer_motion = s_suppressed_pointer_motion_events;
                    const uint64_t suppressed_pointer_motion_max_age = s_suppressed_pointer_motion_max_age_ms;
                    s_suppressed_pointer_motion_events = 0;
                    s_suppressed_pointer_motion_max_age_ms = 0;
                    s_last_input_event_log_ms = input_now_ms;
                    diag::log_tagged_fmt("msgpump",
                        "input_event_received frame=%llu msg=%s(0x%04X) msg_time=%lu age_ms=%lu qpc=%lld tick=%llu hwnd=0x%llX wp=0x%llX lp=0x%llX cursor_ok=%d cursor=%ld,%ld qs=0x%08lX pumped=%u pumped_input=%u pointer_suppressed=%llu pointer_max_age_ms=%llu",
                        static_cast<unsigned long long>(frame_number),
                        aida_tracer::message_name(msg.message),
                        msg.message,
                        static_cast<unsigned long>(msg.time),
                        static_cast<unsigned long>(input_msg_age_ms),
                        static_cast<long long>(qpc.QuadPart),
                        static_cast<unsigned long long>(input_now_ms),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(msg.hwnd)),
                        static_cast<unsigned long long>(static_cast<UINT_PTR>(msg.wParam)),
                        static_cast<unsigned long long>(static_cast<LONG_PTR>(msg.lParam)),
                        input_cursor_ok ? 1 : 0,
                        input_cursor_ok ? input_cursor.x : 0,
                        input_cursor_ok ? input_cursor.y : 0,
                        static_cast<unsigned long>(GetQueueStatus(kAidaInteractiveQueueBits)),
                        pumped_messages,
                        pumped_input_messages,
                        static_cast<unsigned long long>(suppressed_pointer_motion),
                        static_cast<unsigned long long>(suppressed_pointer_motion_max_age));
                } else if (pointer_motion_msg) {
                    ++s_suppressed_pointer_motion_events;
                    if (input_msg_age_ms > s_suppressed_pointer_motion_max_age_ms)
                        s_suppressed_pointer_motion_max_age_ms = input_msg_age_ms;
                }
            }

            bool close_related_msg = msg.message == WM_CLOSE || msg.message == WM_DESTROY ||
                msg.message == WM_NCDESTROY || msg.message == WM_QUIT ||
                msg.message == WM_SYSCOMMAND;
            if (close_related_msg) {
                POINT cursor{};
                GetCursorPos(&cursor);
                diag::log_tagged_critical_fmt("msgpump",
                    "dequeued frame=%llu msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX",
                    (unsigned long long)frame_number,
                    aida_tracer::message_name(msg.message),
                    msg.message,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd),
                    (unsigned long long)static_cast<UINT_PTR>(msg.wParam),
                    (unsigned long long)static_cast<LONG_PTR>(msg.lParam),
                    cursor.x,
                    cursor.y,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(GetForegroundWindow()),
                    (unsigned long long)reinterpret_cast<UINT_PTR>(GetActiveWindow()));
            }

            aida_tracer::mark_render_phase("peek_message_got");
            aida_tracer::set_dispatch_state("translate_enter", msg);
            ::TranslateMessage(&msg);
            aida_tracer::set_dispatch_state("dispatch_enter", msg);
            aida_tracer::g_dispatch_enter_count.fetch_add(1, std::memory_order_acq_rel);
            uint64_t dispatch_start = static_cast<uint64_t>(GetTickCount64());
            LRESULT dispatch_result = ::DispatchMessage(&msg);
            aida_tracer::g_dispatch_exit_count.fetch_add(1, std::memory_order_acq_rel);
            uint64_t dispatch_elapsed = static_cast<uint64_t>(GetTickCount64()) - dispatch_start;
            if (dispatch_elapsed >= 50 || close_related_msg) {
                char stall_context[4600] = {};
                if (dispatch_elapsed >= 50)
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
                const char* render_section = g_render_section.c_str();
                const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
                diag::log_tagged_critical_fmt("msgpump",
                    "dispatch_slow frame=%llu elapsed_ms=%llu result=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX render_phase=%s render_section=%s wndproc_stage=%s ctx={%.3600s}",
                    (unsigned long long)frame_number,
                    (unsigned long long)dispatch_elapsed,
                    (unsigned long long)dispatch_result,
                    aida_tracer::message_name(msg.message),
                    msg.message,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd),
                    (unsigned long long)static_cast<UINT_PTR>(msg.wParam),
                    (unsigned long long)static_cast<LONG_PTR>(msg.lParam),
                    render_phase ? render_phase : "<null>",
                    render_section ? render_section : "<null>",
                    wndproc_stage ? wndproc_stage : "<null>",
                    stall_context[0] ? stall_context : "<empty>");
            }
            aida_tracer::clear_dispatch_state();
            if (msg.message == WM_QUIT)
                done = true;
            const uint64_t pump_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - frame_start_tick_ms;
            if (!done && (pumped_messages >= kAidaMessagePumpBudgetMessages || pump_elapsed_ms >= kAidaMessagePumpBudgetMs)) {
                static uint64_t s_last_top_pump_budget_log_ms = 0;
                const uint64_t budget_now_ms = static_cast<uint64_t>(GetTickCount64());
                if (s_last_top_pump_budget_log_ms == 0 || budget_now_ms - s_last_top_pump_budget_log_ms >= 1000ULL) {
                    s_last_top_pump_budget_log_ms = budget_now_ms;
                    diag::log_tagged_fmt("msgpump",
                        "top_pump_budget_yield frame=%llu messages=%u input=%u resize=%u paint=%u elapsed_ms=%llu budget_messages=%u budget_ms=%lu qs=0x%08lX",
                        static_cast<unsigned long long>(frame_number),
                        pumped_messages,
                        pumped_input_messages,
                        pumped_resize_messages,
                        pumped_paint_messages,
                        static_cast<unsigned long long>(pump_elapsed_ms),
                        kAidaMessagePumpBudgetMessages,
                        static_cast<unsigned long>(kAidaMessagePumpBudgetMs),
                        static_cast<unsigned long>(::GetQueueStatus(QS_ALLINPUT)));
                }
                break;
            }
        }
        aida_tracer::mark_render_phase("peek_message_done");
        if (done)
            break;

        aida_tracer::mark_render_phase("ui_dispatcher_frame_top");
        const std::uint32_t ui_dispatch_drained = aida::ui_thread::drain(32, 2, "frame_top");
        if (ui_dispatch_drained != 0)
            pumped_messages += ui_dispatch_drained;

        if (g_SwapChainOccluded && g_pSwapChain)
        {
            HRESULT occlusion_hr = E_ACCESSDENIED;
            if (aida::ui_thread::require_owner("swapchain", "present_test", "occlusion"))
                occlusion_hr = g_pSwapChain->Present(0, DXGI_PRESENT_TEST);
            if (occlusion_hr == DXGI_STATUS_OCCLUDED) {
                const uint64_t occlusion_now_ms = static_cast<uint64_t>(GetTickCount64());
                const DWORD occlusion_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
                const uint64_t occlusion_input_age_ms = g_last_input_event_tick_ms != 0 && occlusion_now_ms >= g_last_input_event_tick_ms ? occlusion_now_ms - g_last_input_event_tick_ms : UINT64_MAX;
                const bool occlusion_interactive =
                    (HIWORD(occlusion_qs) & kAidaInteractiveQueueBits) != 0 ||
                    occlusion_input_age_ms <= kAidaRecentInputWakeMs ||
                    aida_focus_monitor::focused() ||
                    aida_cursor_over_window(hwnd);
                if (occlusion_interactive) {
                    static uint64_t s_last_occlusion_interactive_log_ms = 0;
                    if (s_last_occlusion_interactive_log_ms == 0 || occlusion_now_ms - s_last_occlusion_interactive_log_ms >= kAidaOcclusionInteractiveLogIntervalMs) {
                        s_last_occlusion_interactive_log_ms = occlusion_now_ms;
                        diag::log_tagged_fmt("render",
                            "occlusion_interactive_wait frame=%llu hr=0x%08X qs=0x%08lX input_age_ms=%llu foreground=%d cursor_over=%d wait_ms=%lu",
                            static_cast<unsigned long long>(frame_number),
                            static_cast<unsigned>(occlusion_hr),
                            static_cast<unsigned long>(occlusion_qs),
                            static_cast<unsigned long long>(occlusion_input_age_ms == UINT64_MAX ? 0ULL : occlusion_input_age_ms),
                            aida_focus_monitor::focused() ? 1 : 0,
                            aida_cursor_over_window(hwnd) ? 1 : 0,
                            (HIWORD(occlusion_qs) & kAidaInteractiveQueueBits) != 0 || occlusion_input_age_ms <= kAidaRecentInputWakeMs ? 0UL : 1UL);
                    }
                    if ((HIWORD(occlusion_qs) & kAidaInteractiveQueueBits) == 0 && occlusion_input_age_ms > kAidaRecentInputWakeMs)
                        MsgWaitForMultipleObjectsEx(0, nullptr, 1, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
                } else {
                    ::Sleep(10);
                }
                continue;
            }
        }
        g_SwapChainOccluded = false;

        static bool ide_resize_applied = false;
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            const UINT resize_w = g_ResizeWidth;
            const UINT resize_h = g_ResizeHeight;
            const uint64_t resize_now_ms = static_cast<uint64_t>(GetTickCount64());
            const uint64_t resize_age_ms = g_ResizeRequestTickMs != 0 && resize_now_ms >= g_ResizeRequestTickMs ? resize_now_ms - g_ResizeRequestTickMs : kAidaResizeCoalesceMs;
            const DWORD resize_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
            const bool resize_input_pending = (HIWORD(resize_qs) & kAidaInteractiveQueueBits) != 0;
            const uint64_t resize_input_age_ms = g_last_input_event_tick_ms != 0 && resize_now_ms >= g_last_input_event_tick_ms ? resize_now_ms - g_last_input_event_tick_ms : UINT64_MAX;
            const bool resize_fresh_input = resize_input_age_ms <= kAidaRecentInputWakeMs;
            if (resize_age_ms < kAidaResizeCoalesceMs && resize_input_pending && !resize_fresh_input) {
                ++g_resize_perf.coalesced;
                static uint64_t s_last_resize_coalesce_log_ms = 0;
                if (resize_now_ms - s_last_resize_coalesce_log_ms >= 1000ULL) {
                    s_last_resize_coalesce_log_ms = resize_now_ms;
                    diag::log_tagged_fmt("render",
                        "resize_coalesce w=%u h=%u age_ms=%llu frame=%llu qs=0x%08lX input_age_ms=%llu requests=%llu coalesced=%llu applied=%llu skipped=%llu",
                        resize_w,
                        resize_h,
                        static_cast<unsigned long long>(resize_age_ms),
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long>(resize_qs),
                        static_cast<unsigned long long>(resize_input_age_ms == UINT64_MAX ? 0ULL : resize_input_age_ms),
                        static_cast<unsigned long long>(g_resize_perf.requests),
                        static_cast<unsigned long long>(g_resize_perf.coalesced),
                        static_cast<unsigned long long>(g_resize_perf.applied),
                        static_cast<unsigned long long>(g_resize_perf.skipped_redundant));
                }
                MsgWaitForMultipleObjectsEx(0, nullptr, 1, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
                continue;
            }
            diag::log_tagged_critical_fmt("render", "resize_pre w=%u h=%u frame=%llu",
                resize_w, resize_h, (unsigned long long)frame_number);
            if ((int)resize_w == prev_w && (int)resize_h == prev_h) {
                ++g_resize_perf.skipped_redundant;
                g_ResizeWidth = g_ResizeHeight = 0;
                g_ResizeRequestTickMs = 0;
                diag::log_tagged_critical_fmt("render",
                    "resize_skip_redundant w=%u h=%u prev_w=%d prev_h=%d frame=%llu skipped=%llu",
                    resize_w,
                    resize_h,
                    prev_w,
                    prev_h,
                    (unsigned long long)frame_number,
                    static_cast<unsigned long long>(g_resize_perf.skipped_redundant));
            } else {
                if (!resize_swapchain_and_target(resize_w, resize_h, frame_number, "wm_size_pending")) {
                    g_ResizeWidth = g_ResizeHeight = 0;
                    g_ResizeRequestTickMs = 0;
                    Sleep(1);
                    continue;
                }
                if (ide_resize_applied) {
                    globals::ui::window_w = (float)resize_w;
                    globals::ui::window_h = (float)resize_h;
                    diag::log_tagged_critical_fmt("render",
                        "wm_size_window_geometry_mirror w=%u h=%u maximized=%d frame=%llu",
                        resize_w,
                        resize_h,
                        globals::ui::maximized ? 1 : 0,
                        (unsigned long long)frame_number);
                }
                ::SetWindowRgn(hwnd, nullptr, TRUE);
                g_ResizeWidth = g_ResizeHeight = 0;
                g_ResizeRequestTickMs = 0;
                prev_w = static_cast<int>(resize_w);
                prev_h = static_cast<int>(resize_h);
                diag::log_tagged_critical("render", "resize_post_create_target_done");
            }
        }

        int iw = (int)globals::ui::window_w;
        int ih = (int)globals::ui::window_h;


        int cur_state = 0;
        if (globals::ui::load_timer >= 3.0f) cur_state = 1;
        if (globals::ui::welcome_done) cur_state = 3;
        bool state_changed = (cur_state != prev_state);
        if (state_changed) prev_state = cur_state;

        if (cur_state == 3) {
            if (!g_authorized_features_initialized.load(std::memory_order_acquire) &&
                !g_authorized_features_posted.exchange(true, std::memory_order_acq_rel))
            {
                startup_log_critical_fmt("render_authorized_feature_critical_post_pre frame=%llu pid=%lu tid=%lu tick=%llu",
                    static_cast<unsigned long long>(frame_number),
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()));
                const auto submit_result = submit_main_executor_task(
                    "startup",
                    "render.authorized_feature_init",
                    aida::infra::executor::domain_t::long_running,
                    "startup_init",
                    [] {
                    startup_log_critical_fmt("render_authorized_feature_worker_enter pid=%lu tid=%lu tick=%llu",
                        GetCurrentProcessId(),
                        GetCurrentThreadId(),
                        static_cast<unsigned long long>(GetTickCount64()));
                    run_authorized_feature_initializers("render_authorized");
                    startup_log_critical_fmt("render_authorized_feature_worker_exit pid=%lu tid=%lu tick=%llu",
                        GetCurrentProcessId(),
                        GetCurrentThreadId(),
                        static_cast<unsigned long long>(GetTickCount64()));
                });
                bool posted = submit_result.submitted;
                startup_log_critical_fmt("render_authorized_feature_critical_post_post posted=%d frame=%llu",
                    posted ? 1 : 0,
                    static_cast<unsigned long long>(frame_number));
                if (!posted)
                {
                    g_authorized_features_posted.store(false, std::memory_order_release);
                    diag::log_tagged("bg_init", "authorized_feature_initializers_critical_post_failed");
                }
            }
            mark_ide_ready_for_mcp_services();
            start_authorized_mcp_services();
            if (!g_camoufox_prewarm_posted.exchange(true, std::memory_order_acq_rel))
            {
                bool prewarm_posted = aida::burp::camoufox::prewarm_default_async("render_authorized");
                startup_log_critical_fmt("camoufox_prewarm_request posted=%d frame=%llu pid=%lu tid=%lu tick=%llu",
                    prewarm_posted ? 1 : 0,
                    static_cast<unsigned long long>(frame_number),
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()));
                if (!prewarm_posted)
                    g_camoufox_prewarm_posted.store(false, std::memory_order_release);
            }
        }


        if (cur_state == 3 && ide_resize_applied) {
            RECT wr; GetWindowRect(hwnd, &wr);
            int actual_w = wr.right - wr.left;
            int actual_h = wr.bottom - wr.top;

            if (actual_w > 200 && actual_h > 200) {
                if (abs(actual_w - iw) > 2 || abs(actual_h - ih) > 2) {
                    globals::ui::window_w = (float)actual_w;
                    globals::ui::window_h = (float)actual_h;
                    iw = actual_w;
                    ih = actual_h;
                }
            }
        }

        if (iw != prev_w || ih != prev_h)
        {
            diag::log_tagged_critical_fmt("render",
                "second_resize_pre iw=%d ih=%d prev_w=%d prev_h=%d cur_state=%d ide_resize_applied=%d frame=%llu",
                iw, ih, prev_w, prev_h, cur_state, ide_resize_applied ? 1 : 0,
                (unsigned long long)frame_number);
            if (!globals::ui::maximized) {
                if (cur_state < 3) {

                    int cx = (screen_w - iw) / 2;
                    int cy = (screen_h - ih) / 2;
                    SetWindowPos(hwnd, nullptr, cx, cy, iw, ih, SWP_NOZORDER);
                } else if (!ide_resize_applied) {

                    int cx = (screen_w - iw) / 2;
                    int cy = (screen_h - ih) / 2;
                    SetWindowPos(hwnd, nullptr, cx, cy, iw, ih, SWP_NOZORDER);
                } else {

                    SetWindowPos(hwnd, nullptr, 0, 0, iw, ih, SWP_NOZORDER | SWP_NOMOVE);
                }
            }
            if (cur_state == 3)
                ide_resize_applied = true;

            ::SetWindowRgn(hwnd, nullptr, TRUE);
            if (!resize_swapchain_and_target(static_cast<UINT>(iw), static_cast<UINT>(ih), frame_number, "layout_size_change")) {
                Sleep(1);
                continue;
            }
            prev_w = iw;
            prev_h = ih;
            diag::log_tagged_critical("render", "second_resize_post");
        }

        if (!aida::ui_thread::require_owner("imgui", "get_io", "pre_frame"))
            continue;
        ImGuiIO& pre_frame_io = ImGui::GetIO();
        const uint64_t dirty_now_ms = static_cast<uint64_t>(GetTickCount64());
        static bool dirty_state_initialized = false;
        static uint64_t last_render_tick_ms = 0;
        static uint64_t last_overlay_dirty_version = 0;
        static uint32_t last_theme_generation = 0;
        static int last_dirty_state = -1;
        static bool last_full_test_running = false;
        static bool last_bulk_busy = false;
        static bool last_activation_progress = false;
        static bool last_ai_thinking = false;
        static uint64_t last_rendered_input_events = 0;
        static POINT last_cursor_pos{};
        static bool last_cursor_valid = false;
        static bool last_cursor_over = false;
        POINT cursor_pos{};
        const bool cursor_pos_ok = ::GetCursorPos(&cursor_pos) != FALSE;
        const bool cursor_moved = cursor_pos_ok && (!last_cursor_valid || cursor_pos.x != last_cursor_pos.x || cursor_pos.y != last_cursor_pos.y);
        const bool cursor_over_aida_pre = aida_cursor_over_window(hwnd);
        const bool cursor_over_changed = !dirty_state_initialized || cursor_over_aida_pre != last_cursor_over;
        const bool cursor_motion_relevant = cursor_moved && (cursor_over_aida_pre || last_cursor_over || aida_focus_monitor::focused());
        const uint64_t overlay_dirty_version = test_all_features::overlay_dirty_version();
        const uint32_t theme_generation = aida::ui::theme_generation();
        static uint64_t theme_animation_until_ms = 0;
        if (!dirty_state_initialized || themes::changed || theme_generation != last_theme_generation)
            theme_animation_until_ms = dirty_now_ms + 300ull;
        const bool theme_animation_pre = dirty_now_ms < theme_animation_until_ms;
        const bool foreground_pre = aida_focus_monitor::focused();
        const bool foreground_like_pre = foreground_pre || cursor_over_aida_pre;
        const DWORD dirty_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
        const bool interactive_pending_pre = (HIWORD(dirty_qs) & kAidaInteractiveQueueBits) != 0;
        const bool full_test_running_pre = test_all_features::is_running();
        const bool bulk_busy_pre = function_index::static_bulk_in_progress();
        const bool ui_dispatch_pending_pre = aida::ui_thread::pending_count() != 0;
        const bool ai_thinking_pre = g_ai_thinking_active;
        const bool activation_progress_pre = false;
        const bool menu_popup_open_pre = menu_bar::any_open;
        const bool active_modal_or_animation_pre =
            globals::ui::command_palette_open ||
            globals::ui::process_attach_open ||
            globals::ui::driver_status_open ||
            globals::ui::shortcuts_dialog_open ||
            aida::settings_overlay::is_open() ||
            aida::agent_picker::is_open() ||
            source_reconstruct_view::is_open() ||
            theme_animation_pre;
        const bool modal_or_animation_pre = active_modal_or_animation_pre || menu_popup_open_pre;
        const bool input_active_pre =
            cursor_motion_relevant ||
            pre_frame_io.MouseWheel != 0.0f ||
            pre_frame_io.MouseWheelH != 0.0f ||
            pre_frame_io.WantTextInput ||
            pre_frame_io.WantCaptureKeyboard ||
            pre_frame_io.KeyCtrl ||
            pre_frame_io.KeyShift ||
            pre_frame_io.KeyAlt ||
            pre_frame_io.KeySuper;
        const bool last_input_seen_pre = g_last_input_event_tick_ms != 0;
        const uint64_t last_input_age_pre_ms = last_input_seen_pre && dirty_now_ms >= g_last_input_event_tick_ms ? dirty_now_ms - g_last_input_event_tick_ms : 0ULL;
        const bool recent_input_pre = last_input_seen_pre && last_input_age_pre_ms <= kAidaRecentInputWakeMs;
        const uint64_t input_events_seen_pre = g_input_event_count;
        const bool unrendered_input_pre = !dirty_state_initialized || input_events_seen_pre != last_rendered_input_events;
        const uint64_t since_render_ms = last_render_tick_ms != 0 && dirty_now_ms >= last_render_tick_ms ? dirty_now_ms - last_render_tick_ms : 0;
        const bool menu_popup_interactive_pre =
            menu_popup_open_pre &&
            (pumped_messages != 0 ||
             pumped_input_messages != 0 ||
             interactive_pending_pre ||
             input_active_pre ||
             recent_input_pre ||
             unrendered_input_pre ||
             cursor_motion_relevant);
        const bool menu_popup_heartbeat_due_pre =
            menu_popup_open_pre &&
            !menu_popup_interactive_pre &&
            since_render_ms >= kAidaMenuPopupHeartbeatMs;
        uint32_t dirty_mask = 0;
        if (!dirty_state_initialized || frame_number < 5)
            dirty_mask |= kAidaDirtyStartup;
        if (pumped_messages != 0 || pumped_paint_messages != 0)
            dirty_mask |= kAidaDirtyMessage;
        if (pumped_resize_messages != 0 || g_ResizeWidth != 0 || g_ResizeHeight != 0 || iw != prev_w || ih != prev_h)
            dirty_mask |= kAidaDirtyResize;
        if (cur_state != last_dirty_state)
            dirty_mask |= kAidaDirtyState;
        if (pumped_input_messages != 0 || interactive_pending_pre || input_active_pre || unrendered_input_pre)
            dirty_mask |= kAidaDirtyInput;
        if (cursor_over_changed || cursor_motion_relevant)
            dirty_mask |= kAidaDirtyCursor;
        if (globals::ui::test_all_visible && overlay_dirty_version != last_overlay_dirty_version)
            dirty_mask |= kAidaDirtyOverlay;
        if (themes::changed || theme_generation != last_theme_generation || theme_animation_pre)
            dirty_mask |= kAidaDirtyTheme;
        if (active_modal_or_animation_pre || menu_popup_interactive_pre || menu_popup_heartbeat_due_pre)
            dirty_mask |= kAidaDirtyModal;
        if (full_test_running_pre != last_full_test_running ||
            activation_progress_pre != last_activation_progress ||
            ai_thinking_pre != last_ai_thinking ||
            activation_progress_pre ||
            ai_thinking_pre)
            dirty_mask |= kAidaDirtyProgress;
        if (bulk_busy_pre != last_bulk_busy)
            dirty_mask |= kAidaDirtyWork;
        if (ui_dispatch_pending_pre)
            dirty_mask |= kAidaDirtyWork;
        const bool interactive_cadence_due_pre = recent_input_pre && since_render_ms >= kAidaInteractiveRenderCadenceMs;
        if (interactive_cadence_due_pre)
            dirty_mask |= kAidaDirtyInteractiveCadence;
        uint64_t heartbeat_ms = kAidaIdleHeartbeatMs;
        if (full_test_running_pre || bulk_busy_pre)
            heartbeat_ms = kAidaFullTestHeartbeatMs;
        if (menu_popup_open_pre)
            heartbeat_ms = kAidaMenuPopupHeartbeatMs;
        if (active_modal_or_animation_pre || activation_progress_pre || ai_thinking_pre)
            heartbeat_ms = kAidaModalHeartbeatMs;
        if (!dirty_state_initialized || since_render_ms >= heartbeat_ms)
            dirty_mask |= kAidaDirtyHeartbeat | kAidaDirtySecurity;
        const bool dirty_fast_mask_pre = (dirty_mask & (kAidaDirtyInput | kAidaDirtyCursor | kAidaDirtyResize | kAidaDirtyMessage | kAidaDirtyInteractiveCadence)) != 0;
        const bool wake_fast_pre =
            dirty_fast_mask_pre ||
            interactive_pending_pre ||
            input_active_pre ||
            recent_input_pre ||
            unrendered_input_pre ||
            pumped_messages != 0 ||
            active_modal_or_animation_pre ||
            menu_popup_interactive_pre ||
            activation_progress_pre ||
            ai_thinking_pre ||
            ui_dispatch_pending_pre;
        DWORD idle_wait_request_ms = kAidaIdleWaitMs;
        if (wake_fast_pre)
            idle_wait_request_ms = kAidaInteractiveWaitMs;
        else if (full_test_running_pre || bulk_busy_pre)
            idle_wait_request_ms = kAidaActiveWaitMs;
        frame_wait_result_t pre_render_wait{};
        if (dirty_mask == 0) {
            aida_tracer::mark_render_phase("idle_frame_wait");
            const frame_wait_result_t idle_wait = wait_for_frame_latency_or_input(idle_wait_request_ms);
            ++skipped_render_frames;
            static uint64_t s_last_skip_wait_log_ms = 0;
            static uint64_t s_skip_wait_anomaly_suppressed = 0;
            const bool skip_wait_anomaly = idle_wait.result == WAIT_FAILED;
            if (skip_wait_anomaly) {
                if (s_last_skip_wait_log_ms == 0 || dirty_now_ms - s_last_skip_wait_log_ms >= kAidaDirtySkipAnomalyLogIntervalMs) {
                    const uint64_t suppressed = s_skip_wait_anomaly_suppressed;
                    s_skip_wait_anomaly_suppressed = 0;
                    s_last_skip_wait_log_ms = dirty_now_ms;
                    diag::log_tagged_fmt("render",
                        "dirty_skip_anomaly skipped=%llu request_ms=%lu actual_ms=%lu result=0x%08lX gle=%lu input=%d qs=0x%08lX foreground=%d cursor_over=%d recent_input=%d input_seen=%d unrendered_input=%d last_input_msg=0x%04X last_input_age_ms=%llu full_test=%d bulk_busy=%d suppressed=%llu",
                        static_cast<unsigned long long>(skipped_render_frames),
                        static_cast<unsigned long>(idle_wait.requested_ms),
                        static_cast<unsigned long>(idle_wait.actual_ms),
                        static_cast<unsigned long>(idle_wait.result),
                        static_cast<unsigned long>(idle_wait.gle),
                        idle_wait.input_available ? 1 : 0,
                        static_cast<unsigned long>(dirty_qs),
                        foreground_pre ? 1 : 0,
                        cursor_over_aida_pre ? 1 : 0,
                        recent_input_pre ? 1 : 0,
                        last_input_seen_pre ? 1 : 0,
                        unrendered_input_pre ? 1 : 0,
                        static_cast<unsigned>(g_last_input_msg),
                        static_cast<unsigned long long>(last_input_age_pre_ms),
                        full_test_running_pre ? 1 : 0,
                        bulk_busy_pre ? 1 : 0,
                        static_cast<unsigned long long>(suppressed));
                } else {
                    ++s_skip_wait_anomaly_suppressed;
                }
            }
            aida_tracer::mark_render_phase("idle_frame_skipped");
            continue;
        }
        DWORD pre_render_wait_ms = kAidaPreRenderWaitMs;
        if (wake_fast_pre)
            pre_render_wait_ms = 0;
        aida_tracer::mark_render_phase("pre_render_wait");
        pre_render_wait = wait_for_frame_latency_or_input(pre_render_wait_ms);
        aida_tracer::mark_render_phase("pre_render_wait_done");
        if (pre_render_wait.input_available && (dirty_mask & (kAidaDirtyInput | kAidaDirtyCursor | kAidaDirtyResize | kAidaDirtyMessage | kAidaDirtyInteractiveCadence)) == 0) {
            ++skipped_render_frames;
            aida_tracer::mark_render_phase("pre_render_input_requeue");
            continue;
        }
        dirty_state_initialized = true;
        last_render_tick_ms = dirty_now_ms;
        last_overlay_dirty_version = overlay_dirty_version;
        last_theme_generation = theme_generation;
        last_dirty_state = cur_state;
        last_full_test_running = full_test_running_pre;
        last_bulk_busy = bulk_busy_pre;
        last_activation_progress = activation_progress_pre;
        last_ai_thinking = ai_thinking_pre;
        if (cursor_pos_ok) {
            last_cursor_pos = cursor_pos;
            last_cursor_valid = true;
        }
        last_cursor_over = cursor_over_aida_pre;

        const UINT pending_font_dpi = g_PendingFontDpi.exchange(0, std::memory_order_acq_rel);
        const UINT applied_font_dpi = g_AppliedFontDpi.load(std::memory_order_acquire);
        if (pending_font_dpi != 0 && pending_font_dpi != applied_font_dpi) {
            const std::uint64_t dpi_rebuild_started = static_cast<std::uint64_t>(GetTickCount64());
            const float pending_scale = static_cast<float>(pending_font_dpi) / 96.0f;
            globals::ui::dpi_scale = pending_scale;
            aida::ui::set_dpi_scale(pending_scale);
            aida_tracer::mark_render_phase("dpi_font_rebuild");
            rebuild_fonts(pending_scale);
            aida::ui::apply_imgui_style(aida::ui::resolved());
            g_AppliedFontDpi.store(pending_font_dpi, std::memory_order_release);
            diag::log_tagged_fmt("dpi",
                "font_rebuild_applied dpi=%u scale=%.3f elapsed_ms=%llu",
                pending_font_dpi, pending_scale,
                static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - dpi_rebuild_started));
        }

        if (frame_number < 5)
            crash_log_write("dx11_new_frame");
        aida_tracer::mark_render_phase("dx11_new_frame");
        DWORD seh_dxnf = seh_dx11_new_frame();
        if (seh_dxnf != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_dx11_new_frame code=0x%08X frame=%llu",
                seh_dxnf, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("win32_new_frame");
        aida_tracer::mark_render_phase("win32_new_frame");
        DWORD seh_w32 = seh_win32_new_frame();
        if (seh_w32 != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_win32_new_frame code=0x%08X frame=%llu",
                seh_w32, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("imgui_new_frame");
        aida_tracer::mark_render_phase("imgui_new_frame");
        DWORD seh_inf = seh_imgui_new_frame();
        if (seh_inf != 0)
        {
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_new_frame code=0x%08X frame=%llu",
                seh_inf, (unsigned long long)frame_number);
            diag::log_tagged_critical_fmt("render", "skip_frame_after_imgui_new_frame_exception code=0x%08X frame=%llu",
                seh_inf, (unsigned long long)frame_number);
            aida_tracer::mark_render_phase("imgui_new_frame_exception_skip");
            frame_number++;
            Sleep(1);
            continue;
        }

        if (!aida::ui_thread::require_owner("ui_state", "theme_tick", "render_frame"))
            continue;
        aida::ui::clock::tick();
        aida::ui::tick_theme_animation(aida::ui::clock::dt());
        {
            const auto& __t = aida::ui::resolved();
            themes::resolved.name = "AiDA";
            themes::resolved.accent = __t.accent;
            themes::resolved.bg_base = __t.bg_base;
            themes::resolved.panel_bg = __t.panel_bg;
            themes::resolved.panel_header = __t.panel_header;
            themes::resolved.title_bar = __t.title_bar;
            themes::resolved.text_primary = __t.text_primary;
            themes::resolved.text_secondary = __t.text_secondary;
            themes::resolved.text_dim = __t.text_dim;
            globals::ui::accent = __t.accent;
        }

        aida::ui::ide_shell::begin_frame();

        {
            if (frame_number < 5)
                crash_log_write("render_title_entering");

            aida_tracer::mark_render_phase("render_title");
            DWORD seh_rt = seh_render_title(&helper, frame_number);
            if (seh_rt != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_render_title code=0x%08X frame=%llu section=%s",
                    seh_rt, (unsigned long long)frame_number, g_render_section.c_str());

            if (frame_number < 5)
                crash_log_write("render_title_done");

            aida_tracer::mark_render_phase("render_command_palette");
            DWORD seh_cp = seh_render_command_palette(frame_number);
            if (seh_cp != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_command_palette code=0x%08X frame=%llu",
                    seh_cp, (unsigned long long)frame_number);

            aida_tracer::mark_render_phase("render_agent_picker");
            DWORD seh_ap = seh_render_agent_picker(frame_number);
            if (seh_ap != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_agent_picker code=0x%08X frame=%llu",
                    seh_ap, (unsigned long long)frame_number);

            aida_tracer::mark_render_phase("render_source_reconstruct");
            DWORD seh_sr = seh_render_source_reconstruct(frame_number);
            if (seh_sr != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_source_reconstruct code=0x%08X frame=%llu",
                    seh_sr, (unsigned long long)frame_number);

            if (frame_number < 5)
                crash_log_write("source_reconstruct_done");

            aida_tracer::mark_render_phase("render_toast");
            DWORD seh_toast = seh_render_toast(frame_number);
            if (seh_toast != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_toast code=0x%08X frame=%llu",
                    seh_toast, (unsigned long long)frame_number);

            if (frame_number < 5)
                crash_log_write("toast_done");
        }

        {
            const ImGuiIO& mid_frame_io = ImGui::GetIO();
            const bool defer_post_build_pump =
                menu_bar::any_open ||
                globals::ui::command_palette_open ||
                globals::ui::process_attach_open ||
                globals::ui::driver_status_open ||
                globals::ui::shortcuts_dialog_open ||
                aida::settings_overlay::is_open() ||
                aida::agent_picker::is_open() ||
                mid_frame_io.WantTextInput ||
                mid_frame_io.WantCaptureKeyboard;
            if (defer_post_build_pump) {
                aida_tracer::mark_render_phase("post_imgui_build_pump_deferred");
                aida::ui_thread::drain(8, 1, "post_imgui_build_deferred");
            } else {
                aida_tracer::mark_render_phase("post_imgui_build_pump");
                aida::ui_thread::drain(8, 1, "post_imgui_build");
                const aida_message_pump_slice_t mid_pump = aida_pump_messages_budgeted("post_imgui_build", kAidaMidFramePumpBudgetMessages, kAidaMidFramePumpBudgetMs);
                pumped_messages += mid_pump.messages;
                pumped_input_messages += mid_pump.input_messages;
                pumped_resize_messages += mid_pump.resize_messages;
                pumped_paint_messages += mid_pump.paint_messages;
                if (mid_pump.quit) {
                    done = true;
                    break;
                }
            }
        }

        aida::ui::ide_shell::end_frame();

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

        if (frame_number < 5)
            crash_log_write("render_submit");
        aida_tracer::mark_render_phase("clear_render_target");
        HRESULT clear_removed = S_OK;
        DWORD seh_clear = seh_clear_main_render_target(g_pd3dDeviceContext, g_mainRenderTargetView, clear_color_with_alpha, &clear_removed, frame_number);
        if (seh_clear != 0) {
            diag::log_tagged_critical_fmt("render",
                "SEH_in_clear_main_render_target code=0x%08X frame=%llu device_removed=0x%08X ctx=0x%llX rtv=0x%llX",
                seh_clear,
                static_cast<unsigned long long>(frame_number),
                static_cast<unsigned>(clear_removed),
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)),
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)));
            Sleep(1);
            frame_number++;
            continue;
        }
        aida_tracer::mark_render_phase("imgui_render");
        DWORD seh_ir = seh_imgui_render();
        if (seh_ir != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_render code=0x%08X frame=%llu",
                seh_ir, (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("collect_draw_data");
        if (!aida::ui_thread::require_owner("imgui", "get_draw_data", "render_submit"))
            continue;
        ImDrawData* draw_data = ImGui::GetDrawData();
        draw_data_metrics_t draw_metrics = collect_draw_data_metrics(draw_data, frame_number < 5ULL || (frame_number % 120ULL) == 0ULL);
        begin_gpu_frame_query(frame_number);
        aida_tracer::mark_render_phase("imgui_dx11_render");
        DWORD seh_idr = seh_imgui_dx11_render(draw_data, frame_number);
        if (seh_idr != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_dx11_render code=0x%08X frame=%llu",
                seh_idr, (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("dx11_blend_state");
        if (!aida::ui_thread::require_owner("dx11", "blend_state", "render_frame"))
            continue;
        g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);
        end_gpu_frame_query(frame_number);

        {
            aida_tracer::mark_render_phase("pre_present_pump");
            aida::ui_thread::drain(8, 1, "pre_present");
            const aida_message_pump_slice_t mid_pump = aida_pump_messages_budgeted("pre_present", kAidaMidFramePumpBudgetMessages, kAidaMidFramePumpBudgetMs);
            pumped_messages += mid_pump.messages;
            pumped_input_messages += mid_pump.input_messages;
            pumped_resize_messages += mid_pump.resize_messages;
            pumped_paint_messages += mid_pump.paint_messages;
            if (mid_pump.quit) {
                done = true;
                break;
            }
        }

        aida_tracer::mark_render_phase("present");
        HRESULT hr = S_OK;
        const UINT present_sync_interval = kAidaPresentSyncInterval;
        const UINT present_flags = kAidaPresentFlags;
        const uint64_t present_start_tick_ms = static_cast<uint64_t>(GetTickCount64());
        DWORD seh_present = seh_swapchain_present(g_pSwapChain, &hr, frame_number, present_sync_interval, present_flags);
        const uint64_t present_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - present_start_tick_ms;
        collect_gpu_frame_query(frame_number);
        if (seh_present != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_present code=0x%08X frame=%llu",
                seh_present, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_fmt("present_hr=0x%08X", hr);
        else if ((hr & 0x80000000u) || hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
            diag::log_tagged_critical_fmt("render", "present_hr_NONZERO=0x%08X frame=%llu",
                hr, (unsigned long long)frame_number);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        {
            aida_tracer::mark_render_phase("post_present_pump");
            aida::ui_thread::drain(8, 1, "post_present");
            const aida_message_pump_slice_t mid_pump = aida_pump_messages_budgeted("post_present", kAidaMidFramePumpBudgetMessages, kAidaMidFramePumpBudgetMs);
            pumped_messages += mid_pump.messages;
            pumped_input_messages += mid_pump.input_messages;
            pumped_resize_messages += mid_pump.resize_messages;
            pumped_paint_messages += mid_pump.paint_messages;
            if (mid_pump.quit) {
                done = true;
                break;
            }
        }

        const uint64_t timing_now_ms = static_cast<uint64_t>(GetTickCount64());
        const uint64_t frame_elapsed_ms = timing_now_ms - frame_start_tick_ms;
        const bool input_seen_present = g_last_input_event_tick_ms != 0;
        const uint64_t input_age_present_ms = input_seen_present && timing_now_ms >= g_last_input_event_tick_ms ? timing_now_ms - g_last_input_event_tick_ms : 0ULL;
        const uint64_t input_events_this_frame = g_input_event_count >= input_events_at_frame_start ? g_input_event_count - input_events_at_frame_start : 0ULL;
        const bool present_failed = (hr & 0x80000000u) || hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET;
        if (!present_failed && hr != DXGI_STATUS_OCCLUDED)
            last_rendered_input_events = input_events_seen_pre;
        const bool frame_slow = frame_elapsed_ms >= 250ULL || present_elapsed_ms >= 100ULL;
        if (frame_number < 5)
            crash_log_fmt("frame_end #%llu", frame_number);
        {
            static uint64_t s_last_frame_timing_log_ms = 0;
            if ((present_failed || frame_slow) && (timing_now_ms - s_last_frame_timing_log_ms) >= 5000ULL) {
                s_last_frame_timing_log_ms = timing_now_ms;
                request_render_diag_snapshot_async(timing_now_ms, false);
                const render_diag_cached_snapshot_t timing_diag = latest_render_diag_snapshot();
                const DWORD timing_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
                diag::log_tagged_fmt("render",
                    "frame_timing_sample frame=%llu frame_ms=%llu present_ms=%llu sync=%u flags=0x%08X hr=0x%08X cursor_over=%d foreground=%d interactive_pending=%d qs=0x%08lX threads_active=%lu tid=%lu",
                    static_cast<unsigned long long>(frame_number),
                    static_cast<unsigned long long>(frame_elapsed_ms),
                    static_cast<unsigned long long>(present_elapsed_ms),
                    static_cast<unsigned>(present_sync_interval),
                    static_cast<unsigned>(present_flags),
                    static_cast<unsigned>(hr),
                    aida_cursor_over_window(hwnd) ? 1 : 0,
                    aida_focus_monitor::focused() ? 1 : 0,
                    (HIWORD(timing_qs) & kAidaInteractiveQueueBits) != 0 ? 1 : 0,
                    static_cast<unsigned long>(timing_qs),
                    static_cast<unsigned long>(timing_diag.thread_count),
                    ::GetCurrentThreadId());
            }
        }
        frame_number++;

        {
            const uint64_t tick_now_ms = static_cast<uint64_t>(GetTickCount64());
            uint32_t idle_block_mask = 0;
            if (bulk_busy_pre) idle_block_mask |= 0x00000001u;
            if (full_test_running_pre) idle_block_mask |= 0x00000002u;
            if (activation_progress_pre) idle_block_mask |= 0x00000004u;
            if (input_active_pre) idle_block_mask |= 0x00000008u;
            if (interactive_pending_pre) idle_block_mask |= 0x00000010u;
            if (cursor_over_aida_pre) idle_block_mask |= 0x00000020u;
            if (modal_or_animation_pre) idle_block_mask |= 0x00000040u;
            if (wake_fast_pre) idle_block_mask |= 0x00000080u;
            if (recent_input_pre) idle_block_mask |= 0x00000100u;
            if (dirty_fast_mask_pre) idle_block_mask |= 0x00000200u;

            static uint64_t s_last_idle_pacing_probe_ms = 0;
            static uint64_t s_last_idle_pacing_log_ms = 0;
            if (tick_now_ms - s_last_idle_pacing_probe_ms >= 5000ULL) {
                s_last_idle_pacing_probe_ms = tick_now_ms;
                request_render_diag_snapshot_async(tick_now_ms, false);
                const render_diag_cached_snapshot_t diag_snapshot = latest_render_diag_snapshot();
                const DWORD thread_err = diag_snapshot.thread_err;
                const DWORD thread_count = diag_snapshot.thread_count;
                const auto wq = diag_snapshot.wq;
                const auto svc = diag_snapshot.svc;
                const auto cq = diag_snapshot.cq;
                const auto taskflow = diag_snapshot.taskflow;
                const bool idle_unhealthy =
                    thread_err != 0 ||
                    wq.pending != 0 ||
                    svc.pending != 0 ||
                    cq.pending != 0 ||
                    wq.oldest_active_ms >= 30000ULL ||
                    svc.oldest_active_ms >= 30000ULL ||
                    cq.oldest_active_ms >= 30000ULL;
                if (idle_unhealthy && tick_now_ms - s_last_idle_pacing_log_ms >= 30000ULL) {
                    s_last_idle_pacing_log_ms = tick_now_ms;
                    diag::log_tagged_fmt("render",
                        "idle_pacing_anomaly frame=%llu pre_render_wait_ms=%lu idle_wait_request_ms=%lu dirty_mask=0x%08X block_mask=0x%08X foreground=%d foreground_like=%d cursor_over=%d recent_input=%d last_input_age_ms=%llu interactive_pending=%d qs=0x%08lX bulk_busy=%d full_test=%d skipped=%llu threads=%lu thread_err=%lu wq_active=%u wq_pending=%llu wq_oldest_ms=%llu svc_active=%u svc_pending=%llu svc_oldest_ms=%llu cq_active=%u cq_pending=%llu cq_oldest_ms=%llu",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long>(pre_render_wait.actual_ms),
                        static_cast<unsigned long>(idle_wait_request_ms),
                        static_cast<unsigned>(dirty_mask),
                        static_cast<unsigned>(idle_block_mask),
                        foreground_pre ? 1 : 0,
                        foreground_like_pre ? 1 : 0,
                        cursor_over_aida_pre ? 1 : 0,
                        recent_input_pre ? 1 : 0,
                        static_cast<unsigned long long>(last_input_age_pre_ms),
                        interactive_pending_pre ? 1 : 0,
                        static_cast<unsigned long>(dirty_qs),
                        bulk_busy_pre ? 1 : 0,
                        full_test_running_pre ? 1 : 0,
                        static_cast<unsigned long long>(skipped_render_frames),
                        static_cast<unsigned long>(thread_count),
                        static_cast<unsigned long>(thread_err),
                        static_cast<unsigned>(wq.active),
                        static_cast<unsigned long long>(wq.pending),
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(svc.active),
                        static_cast<unsigned long long>(svc.pending),
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(cq.active),
                        static_cast<unsigned long long>(cq.pending),
                        static_cast<unsigned long long>(cq.oldest_active_ms));
                    diag::log_tagged_fmt("render",
                        "idle_pacing_taskflow_family frame=%llu family=work submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(wq.active),
                        static_cast<unsigned long long>(wq.pending),
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.active_label_count),
                        wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "idle_pacing_taskflow_family frame=%llu family=service submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(svc.active),
                        static_cast<unsigned long long>(svc.pending),
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.active_label_count),
                        svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "idle_pacing_taskflow_family frame=%llu family=critical submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(cq.active),
                        static_cast<unsigned long long>(cq.pending),
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.active_label_count),
                        cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    std::function<void()> stuck_log_task = [] {
                        const auto stuck = aida::infra::taskflow_runtime::stuck_workers(30000ULL, 24);
                        for (const auto& s : stuck) {
                            diag::log_tagged_fmt("taskflow_runtime",
                                "stuck_worker task_id=%llu label=%s class=%s lifetime=%s health=%s worker_index=%zu tid=%lu thread_alive=%d thread_gle=%lu exit_code=0x%08lX active_ms=%llu queued_ms=%llu cpu_delta_100ns=%llu cpu_pct_x100=%u",
                                static_cast<unsigned long long>(s.task_id),
                                s.label.empty() ? "<unnamed>" : s.label.c_str(),
                                s.label_class,
                                s.lifetime,
                                s.health,
                                s.worker_index,
                                static_cast<unsigned long>(s.tid),
                                s.thread_alive ? 1 : 0,
                                static_cast<unsigned long>(s.thread_query_gle),
                                static_cast<unsigned long>(s.exit_code),
                                static_cast<unsigned long long>(s.active_ms),
                                static_cast<unsigned long long>(s.queued_ms),
                                static_cast<unsigned long long>(s.cpu_delta_100ns),
                                static_cast<unsigned>(s.cpu_pct_x100));
                        }
                        aida::infra::executor::check_deadlines();
                    };
                    const auto submit_result = submit_main_executor_task(
                        "render",
                        "render.idle_stuck_worker_log",
                        aida::infra::executor::domain_t::diagnostics,
                        "diagnostics",
                        std::move(stuck_log_task));
                    bool stuck_log_posted = submit_result.submitted;
                    if (!stuck_log_posted)
                        diag::log_tagged_fmt("render", "idle_pacing_stuck_worker_log_post_failed frame=%llu", static_cast<unsigned long long>(frame_number));
                }
            }
            static uint64_t s_last_frame_pacing_log_ms = 0;
            static uint64_t s_last_frame_pacing_frame = 0;
            static uint64_t s_last_frame_pacing_skipped = 0;
            static uint64_t s_last_frame_pacing_input_events = 0;
            const bool wait_failed = pre_render_wait.result == WAIT_FAILED;
            if (s_last_frame_pacing_log_ms == 0) {
                s_last_frame_pacing_log_ms = tick_now_ms;
                s_last_frame_pacing_frame = frame_number;
                s_last_frame_pacing_skipped = skipped_render_frames;
                s_last_frame_pacing_input_events = g_input_event_count;
                request_render_diag_snapshot_async(tick_now_ms, true);
            } else {
                const uint64_t since_pacing_log_ms = tick_now_ms >= s_last_frame_pacing_log_ms ? tick_now_ms - s_last_frame_pacing_log_ms : 0ULL;
                const bool pacing_due = since_pacing_log_ms >= kAidaFramePacingLogIntervalMs;
                const bool pacing_anomaly = wait_failed || present_failed || frame_slow;
                const bool pacing_anomaly_due = pacing_anomaly && since_pacing_log_ms >= kAidaPacingAnomalyLogIntervalMs;
                if (pacing_due || pacing_anomaly_due) {
                    request_render_diag_snapshot_async(tick_now_ms, true);
                    if (!draw_metrics.full_walk)
                        draw_metrics = collect_draw_data_metrics(draw_data, true);
                    const render_diag_cached_snapshot_t diag_snapshot = latest_render_diag_snapshot();
                    const DWORD thread_err = diag_snapshot.thread_err;
                    const DWORD thread_count = diag_snapshot.thread_count;
                    const auto wq = diag_snapshot.wq;
                    const auto svc = diag_snapshot.svc;
                    const auto cq = diag_snapshot.cq;
                    const auto taskflow = diag_snapshot.taskflow;
                    const process_cpu_delta_t cpu = diag_snapshot.cpu;
                    const process_io_delta_t proc_io = diag_snapshot.proc_io;
                    const log_file_delta_snapshot_t log_files = diag_snapshot.log_files;
                    const defender_process_snapshot_t defender = diag_snapshot.defender;
                    const uint64_t frame_delta = frame_number >= s_last_frame_pacing_frame ? frame_number - s_last_frame_pacing_frame : 0ULL;
                    const uint64_t skipped_delta = skipped_render_frames >= s_last_frame_pacing_skipped ? skipped_render_frames - s_last_frame_pacing_skipped : 0ULL;
                    const uint64_t input_events_delta = g_input_event_count >= s_last_frame_pacing_input_events ? g_input_event_count - s_last_frame_pacing_input_events : 0ULL;
                    const double fps = since_pacing_log_ms != 0 ? (static_cast<double>(frame_delta) * 1000.0) / static_cast<double>(since_pacing_log_ms) : 0.0;
                    const auto overlay_perf = test_all_features::overlay_perf_snapshot();
                    const gpu_frame_sample_t gpu = latest_gpu_frame_sample(frame_number);
                    const auto log_stats = diag::async_log_stats();
                    diag::log_tagged_fmt("render",
                        "frame_pacing_sample frame=%llu frames_delta=%llu skipped_delta=%llu skipped_total=%llu fps=%.2f cpu_pct=%.2f cpu_valid=%d cpu_wall_ms=%llu cpu_busy_100ns=%llu cpu_gle=%lu logical_processors=%lu gpu_available=%d gpu_valid=%d gpu_pending=%d gpu_ms=%.3f gpu_frame=%llu gpu_ready_frame=%llu gpu_disjoint=%d gpu_data_hr=0x%08X gpu_create_hr=0x%08X gpu_frequency=%llu gpu_samples=%llu gpu_misses=%llu sync=%u flags=0x%08X frame_ms=%llu present_ms=%llu pre_wait_request_ms=%lu pre_wait_actual_ms=%lu pre_wait_result=0x%08lX pre_wait_gle=%lu pre_wait_input=%d dirty_mask=0x%08X idle_wait_request_ms=%lu foreground=%d foreground_like=%d cursor_over=%d interactive_pending=%d qs=0x%08lX block_mask=0x%08X bulk_busy=%d full_test=%d modal=%d activation=%d ai_thinking=%d pumped=%u pumped_input=%u pumped_resize=%u pumped_paint=%u draw_lists=%d draw_cmds=%d draw_vtx=%d draw_idx=%d callbacks=%d reset_callbacks=%d overlay_visible=%d overlay_running=%d overlay_total=%zu overlay_cached=%zu overlay_rendered=%zu overlay_log_version=%llu overlay_dirty=0x%016llX overlay_snapshot_changed=%d overlay_snapshot_busy=%d overlay_lock_busy=%llu overlay_render_us=%llu resize_requests=%llu resize_applied=%llu resize_coalesced=%llu resize_skipped=%llu rt_recreates=%llu threads=%lu thread_err=%lu taskflow_active=%u taskflow_submitted=%llu taskflow_rejected=%llu taskflow_failed=%llu taskflow_timed_out=%llu wq_active=%u wq_pending=%llu wq_oldest_ms=%llu wq_label_count=%u svc_active=%u svc_pending=%llu svc_oldest_ms=%llu svc_label_count=%u cq_active=%u cq_pending=%llu cq_oldest_ms=%llu cq_label_count=%u",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(frame_delta),
                        static_cast<unsigned long long>(skipped_delta),
                        static_cast<unsigned long long>(skipped_render_frames),
                        fps,
                        cpu.cpu_percent,
                        cpu.valid ? 1 : 0,
                        static_cast<unsigned long long>(cpu.wall_ms),
                        static_cast<unsigned long long>(cpu.busy_100ns),
                        static_cast<unsigned long>(cpu.gle),
                        static_cast<unsigned long>(cpu.logical_processors),
                        gpu.available ? 1 : 0,
                        gpu.valid ? 1 : 0,
                        gpu.pending ? 1 : 0,
                        gpu.gpu_ms,
                        static_cast<unsigned long long>(gpu.frame),
                        static_cast<unsigned long long>(gpu.ready_frame),
                        gpu.disjoint ? 1 : 0,
                        static_cast<unsigned>(gpu.data_hr),
                        static_cast<unsigned>(gpu.create_hr),
                        static_cast<unsigned long long>(gpu.frequency),
                        static_cast<unsigned long long>(gpu.samples),
                        static_cast<unsigned long long>(gpu.misses),
                        static_cast<unsigned>(present_sync_interval),
                        static_cast<unsigned>(present_flags),
                        static_cast<unsigned long long>(frame_elapsed_ms),
                        static_cast<unsigned long long>(present_elapsed_ms),
                        static_cast<unsigned long>(pre_render_wait.requested_ms),
                        static_cast<unsigned long>(pre_render_wait.actual_ms),
                        static_cast<unsigned long>(pre_render_wait.result),
                        static_cast<unsigned long>(pre_render_wait.gle),
                        pre_render_wait.input_available ? 1 : 0,
                        static_cast<unsigned>(dirty_mask),
                        static_cast<unsigned long>(idle_wait_request_ms),
                        foreground_pre ? 1 : 0,
                        foreground_like_pre ? 1 : 0,
                        cursor_over_aida_pre ? 1 : 0,
                        interactive_pending_pre ? 1 : 0,
                        static_cast<unsigned long>(dirty_qs),
                        static_cast<unsigned>(idle_block_mask),
                        bulk_busy_pre ? 1 : 0,
                        full_test_running_pre ? 1 : 0,
                        modal_or_animation_pre ? 1 : 0,
                        activation_progress_pre ? 1 : 0,
                        ai_thinking_pre ? 1 : 0,
                        pumped_messages,
                        pumped_input_messages,
                        pumped_resize_messages,
                        pumped_paint_messages,
                        draw_metrics.draw_lists,
                        draw_metrics.draw_cmds,
                        draw_metrics.total_vtx,
                        draw_metrics.total_idx,
                        draw_metrics.callbacks,
                        draw_metrics.reset_callbacks,
                        overlay_perf.visible ? 1 : 0,
                        overlay_perf.running ? 1 : 0,
                        overlay_perf.total_log_lines,
                        overlay_perf.cached_log_lines,
                        overlay_perf.rendered_log_rows,
                        static_cast<unsigned long long>(overlay_perf.log_version),
                        static_cast<unsigned long long>(overlay_perf.dirty_version),
                        overlay_perf.snapshot_changed ? 1 : 0,
                        overlay_perf.snapshot_busy ? 1 : 0,
                        static_cast<unsigned long long>(overlay_perf.lock_busy_total),
                        static_cast<unsigned long long>(overlay_perf.render_elapsed_us),
                        static_cast<unsigned long long>(g_resize_perf.requests),
                        static_cast<unsigned long long>(g_resize_perf.applied),
                        static_cast<unsigned long long>(g_resize_perf.coalesced),
                        static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
                        static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
                        static_cast<unsigned long>(thread_count),
                        static_cast<unsigned long>(thread_err),
                        static_cast<unsigned>(taskflow.total_active),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(wq.active),
                        static_cast<unsigned long long>(wq.pending),
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.active_label_count),
                        static_cast<unsigned>(svc.active),
                        static_cast<unsigned long long>(svc.pending),
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.active_label_count),
                        static_cast<unsigned>(cq.active),
                        static_cast<unsigned long long>(cq.pending),
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.active_label_count));
                    diag::log_tagged_fmt("render",
                        "frame_pacing_io frame=%llu present_hr=0x%08X input_seen=%d last_input_msg=0x%04X last_input_msg_time=%lu last_input_age_newframe_ms=%llu input_to_present_ms=%llu input_events_delta=%llu input_events_this_frame=%llu proc_io_valid=%d proc_io_gle=%lu proc_io_wall_ms=%llu proc_read_ops_delta=%llu proc_write_ops_delta=%llu proc_other_ops_delta=%llu proc_read_bytes_delta=%llu proc_write_bytes_delta=%llu proc_other_bytes_delta=%llu proc_total_read_bytes=%llu proc_total_write_bytes=%llu debug_log_valid=%d debug_log_size=%llu debug_log_delta=%llu debug_log_reset=%d debug_log_gle=%lu kernel_log_valid=%d kernel_log_size=%llu kernel_log_delta=%llu kernel_log_reset=%d kernel_log_gle=%lu full_test_log_valid=%d full_test_log_size=%llu full_test_log_delta=%llu full_test_log_reset=%d full_test_log_gle=%lu camoufox_log_valid=%d camoufox_log_size=%llu camoufox_log_delta=%llu camoufox_log_reset=%d camoufox_log_gle=%lu defender_valid=%d defender_gle=%lu defender_msmpeng=%u defender_mpcmdrun=%u log_started=%d log_start_failed=%d log_queue_depth=%llu log_max_queue_depth=%llu log_queue_lock_busy=%d log_file_lock_busy=%d log_queued=%llu log_queued_bytes=%llu log_written=%llu log_written_bytes=%llu log_direct=%llu log_force_batches=%llu log_force_flushes=%llu log_normal_flushes=%llu log_flush_ms_total=%llu log_flush_ms_max=%llu log_flush_failures=%llu log_last_flush_error=%llu log_pending_flush_bytes=%llu log_tag_events=%llu log_tag_bytes=%llu log_tag_forced=%llu log_coalesced_success=%llu log_coalesced_bytes=%llu log_coalesced_summaries=%llu log_force_downgraded=%llu",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned>(hr),
                        input_seen_present ? 1 : 0,
                        static_cast<unsigned>(g_last_input_msg),
                        static_cast<unsigned long>(g_last_input_msg_time),
                        static_cast<unsigned long long>(last_input_age_pre_ms),
                        static_cast<unsigned long long>(input_age_present_ms),
                        static_cast<unsigned long long>(input_events_delta),
                        static_cast<unsigned long long>(input_events_this_frame),
                        proc_io.valid ? 1 : 0,
                        static_cast<unsigned long>(proc_io.gle),
                        static_cast<unsigned long long>(proc_io.wall_ms),
                        static_cast<unsigned long long>(proc_io.read_ops_delta),
                        static_cast<unsigned long long>(proc_io.write_ops_delta),
                        static_cast<unsigned long long>(proc_io.other_ops_delta),
                        static_cast<unsigned long long>(proc_io.read_bytes_delta),
                        static_cast<unsigned long long>(proc_io.write_bytes_delta),
                        static_cast<unsigned long long>(proc_io.other_bytes_delta),
                        static_cast<unsigned long long>(proc_io.total_read_bytes),
                        static_cast<unsigned long long>(proc_io.total_write_bytes),
                        log_files.debug_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.debug_log.size),
                        static_cast<unsigned long long>(log_files.debug_log.delta),
                        log_files.debug_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.debug_log.gle),
                        log_files.kernel_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.kernel_log.size),
                        static_cast<unsigned long long>(log_files.kernel_log.delta),
                        log_files.kernel_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.kernel_log.gle),
                        log_files.full_test_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.full_test_log.size),
                        static_cast<unsigned long long>(log_files.full_test_log.delta),
                        log_files.full_test_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.full_test_log.gle),
                        log_files.camoufox_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.camoufox_log.size),
                        static_cast<unsigned long long>(log_files.camoufox_log.delta),
                        log_files.camoufox_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.camoufox_log.gle),
                        defender.valid ? 1 : 0,
                        static_cast<unsigned long>(defender.gle),
                        static_cast<unsigned>(defender.msmpeng),
                        static_cast<unsigned>(defender.mpcmdrun),
                        log_stats.started ? 1 : 0,
                        log_stats.start_failed ? 1 : 0,
                        static_cast<unsigned long long>(log_stats.queue_depth),
                        static_cast<unsigned long long>(log_stats.max_queue_depth),
                        log_stats.queue_lock_busy ? 1 : 0,
                        log_stats.file_lock_busy ? 1 : 0,
                        static_cast<unsigned long long>(log_stats.queued_items),
                        static_cast<unsigned long long>(log_stats.queued_bytes),
                        static_cast<unsigned long long>(log_stats.written_items),
                        static_cast<unsigned long long>(log_stats.written_bytes),
                        static_cast<unsigned long long>(log_stats.direct_items),
                        static_cast<unsigned long long>(log_stats.force_batches),
                        static_cast<unsigned long long>(log_stats.force_flushes),
                        static_cast<unsigned long long>(log_stats.normal_flushes),
                        static_cast<unsigned long long>(log_stats.flush_elapsed_ms_total),
                        static_cast<unsigned long long>(log_stats.flush_elapsed_ms_max),
                        static_cast<unsigned long long>(log_stats.flush_failures),
                        static_cast<unsigned long long>(log_stats.last_flush_error),
                        static_cast<unsigned long long>(log_stats.bytes_pending_flush),
                        static_cast<unsigned long long>(log_stats.tag_metric_events),
                        static_cast<unsigned long long>(log_stats.tag_metric_bytes),
                        static_cast<unsigned long long>(log_stats.tag_metric_forced),
                        static_cast<unsigned long long>(log_stats.coalesced_success_events),
                        static_cast<unsigned long long>(log_stats.coalesced_success_bytes),
                        static_cast<unsigned long long>(log_stats.coalesced_success_summaries),
                        static_cast<unsigned long long>(log_stats.coalesced_success_force_downgrades));
                    diag::log_tagged_fmt("render",
                        "frame_pacing_log_tags frame=%llu top_tags={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        log_stats.top_tags.empty() ? "<none>" : log_stats.top_tags.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_taskflow_family frame=%llu family=work submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(wq.active),
                        static_cast<unsigned long long>(wq.pending),
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.active_label_count),
                        wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_taskflow_family frame=%llu family=service submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(svc.active),
                        static_cast<unsigned long long>(svc.pending),
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.active_label_count),
                        svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_taskflow_family frame=%llu family=critical submitted=%llu rejected=%llu failed=%llu timed_out=%llu active=%u pending=%llu oldest_ms=%llu label_count=%u labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(taskflow.total_submitted),
                        static_cast<unsigned long long>(taskflow.total_rejected),
                        static_cast<unsigned long long>(taskflow.total_failed),
                        static_cast<unsigned long long>(taskflow.total_timed_out),
                        static_cast<unsigned>(cq.active),
                        static_cast<unsigned long long>(cq.pending),
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.active_label_count),
                        cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    static uint64_t s_last_post_test_cpu_correlation_ms = 0;
                    const bool post_test_cpu_pressure = !full_test_running_pre && cpu.valid && cpu.cpu_percent >= 25.0;
                    if (post_test_cpu_pressure && (s_last_post_test_cpu_correlation_ms == 0 || tick_now_ms - s_last_post_test_cpu_correlation_ms >= 10000ULL)) {
                        s_last_post_test_cpu_correlation_ms = tick_now_ms;
                        diag::log_tagged_fmt("render",
                            "post_test_cpu_correlation frame=%llu cpu_pct=%.2f cpu_wall_ms=%llu cpu_busy_100ns=%llu proc_io_valid=%d proc_write_bytes_delta=%llu proc_read_bytes_delta=%llu debug_log_delta=%llu kernel_log_delta=%llu full_test_log_delta=%llu camoufox_log_delta=%llu defender_valid=%d defender_msmpeng=%u defender_mpcmdrun=%u taskflow_labels={%.900s} wq_labels={%.900s} svc_labels={%.900s} cq_labels={%.900s}",
                            static_cast<unsigned long long>(frame_number),
                            cpu.cpu_percent,
                            static_cast<unsigned long long>(cpu.wall_ms),
                            static_cast<unsigned long long>(cpu.busy_100ns),
                            proc_io.valid ? 1 : 0,
                            static_cast<unsigned long long>(proc_io.write_bytes_delta),
                            static_cast<unsigned long long>(proc_io.read_bytes_delta),
                            static_cast<unsigned long long>(log_files.debug_log.delta),
                            static_cast<unsigned long long>(log_files.kernel_log.delta),
                            static_cast<unsigned long long>(log_files.full_test_log.delta),
                            static_cast<unsigned long long>(log_files.camoufox_log.delta),
                            defender.valid ? 1 : 0,
                            static_cast<unsigned>(defender.msmpeng),
                            static_cast<unsigned>(defender.mpcmdrun),
                            taskflow.labels_under_pressure.empty() ? "<none>" : taskflow.labels_under_pressure.c_str(),
                            wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str(),
                            svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str(),
                            cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    }
                    s_last_frame_pacing_log_ms = tick_now_ms;
                    s_last_frame_pacing_frame = frame_number;
                    s_last_frame_pacing_skipped = skipped_render_frames;
                    s_last_frame_pacing_input_events = g_input_event_count;
                    static uint64_t s_last_runtime_acceptance_log_ms = 0;
                    if (s_last_runtime_acceptance_log_ms == 0 || tick_now_ms - s_last_runtime_acceptance_log_ms >= kAidaRuntimeAcceptanceLogIntervalMs) {
                        s_last_runtime_acceptance_log_ms = tick_now_ms;
                        diag::log_tagged_fmt("render",
                            "runtime_acceptance_sample frame=%llu fps=%.2f cpu_pct=%.2f cpu_valid=%d gpu_available=%d gpu_valid=%d gpu_pending=%d gpu_ms=%.3f sync=%u flags=0x%08X dirty_mask=0x%08X skipped_total=%llu overlay_visible=%d overlay_running=%d overlay_rendered=%zu overlay_render_us=%llu resize_requests=%llu resize_applied=%llu resize_coalesced=%llu resize_skipped=%llu rt_recreates=%llu threads=%lu taskflow_active=%u taskflow_submitted=%llu taskflow_rejected=%llu wq_active=%u wq_pending=%llu svc_active=%u svc_pending=%llu cq_active=%u cq_pending=%llu",
                            static_cast<unsigned long long>(frame_number),
                            fps,
                            cpu.cpu_percent,
                            cpu.valid ? 1 : 0,
                            gpu.available ? 1 : 0,
                            gpu.valid ? 1 : 0,
                            gpu.pending ? 1 : 0,
                            gpu.gpu_ms,
                            static_cast<unsigned>(present_sync_interval),
                            static_cast<unsigned>(present_flags),
                            static_cast<unsigned>(dirty_mask),
                            static_cast<unsigned long long>(skipped_render_frames),
                            overlay_perf.visible ? 1 : 0,
                            overlay_perf.running ? 1 : 0,
                            overlay_perf.rendered_log_rows,
                            static_cast<unsigned long long>(overlay_perf.render_elapsed_us),
                            static_cast<unsigned long long>(g_resize_perf.requests),
                            static_cast<unsigned long long>(g_resize_perf.applied),
                            static_cast<unsigned long long>(g_resize_perf.coalesced),
                            static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
                            static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
                            static_cast<unsigned long>(thread_count),
                            static_cast<unsigned>(taskflow.total_active),
                            static_cast<unsigned long long>(taskflow.total_submitted),
                            static_cast<unsigned long long>(taskflow.total_rejected),
                            static_cast<unsigned>(wq.active),
                            static_cast<unsigned long long>(wq.pending),
                            static_cast<unsigned>(svc.active),
                            static_cast<unsigned long long>(svc.pending),
                            static_cast<unsigned>(cq.active),
                            static_cast<unsigned long long>(cq.pending));
                    }
                }
            }
        }
    }

    aida_shutdown_diag::mark("shutdown_sequence_begin");
    aida::diagnostics::metadata_ring::emit(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::startup_shutdown,
        "standalone_shutdown_begin", "cleanup_starting", true);
    aida::diagnostics::metadata_ring::request_shutdown();
    const bool shutdown_admitted = claim_chrome_shutdown_admission("main.shutdown_sequence");
    diag::log_tagged_critical_fmt("main", "shutdown_admission_done admitted=%d", shutdown_admitted ? 1 : 0);
    const bool observer_stopped = aida::diagnostics::observer::stop();
    diag::log_tagged_critical_fmt("main", "shutdown_observer_done joined=%d", observer_stopped ? 1 : 0);
    diag::log_tagged_critical_fmt("main",
        "shutdown_sequence_begin frame=%llu done=%d hwnd=0x%llX tid=%lu",
        (unsigned long long)frame_number,
        done ? 1 : 0,
        (unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
        GetCurrentThreadId());
    aida_tracer::mark_render_phase("shutdown_sequence_begin");
    aida::ui_thread::shutdown();
    {
        char queue_snapshot[2400] = {};
        format_taskflow_runtime_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
        diag::log_tagged_critical_fmt("main", "shutdown_queue_snapshot_pre %s", queue_snapshot);
    }
    aida_shutdown_diag::mark("shutdown_testlab_cancel");
    test_all_features::cancel_tests_for_shutdown();
    diag::log_tagged_critical("main", "shutdown_testlab_cancel_done");
    aida_shutdown_diag::mark("shutdown_camoufox_force_cleanup");
    try {
        const auto cleanup_before = aida::burp::camoufox::get_status();
        const std::uint64_t cleanup_generation_before = cleanup_before.cleanup_generation;
        const bool cleanup_requested = aida::burp::camoufox::force_cleanup("main.shutdown_sequence");
        const auto cleanup_request = aida::burp::camoufox::get_status();
        const std::uint64_t cleanup_generation = cleanup_request.cleanup_generation;
        const bool cleanup_receipt = aida::burp::camoufox::wait_until_idle(20000, "main.shutdown_sequence.receipt");
        const auto cleanup_after = aida::burp::camoufox::get_status();
        const bool generation_drained = !cleanup_after.cleanup_pending &&
            (cleanup_generation == 0 || cleanup_after.cleanup_generation == cleanup_generation) &&
            !cleanup_after.child_alive && cleanup_after.child_process_count == 0;
        const bool cleanup_complete = cleanup_requested && cleanup_receipt && generation_drained;
        diag::log_tagged_critical_fmt("main", "shutdown_camoufox_force_cleanup_done complete=%d request=%d receipt=%d generation_before=%llu generation_after=%llu cleanup_pending=%d child_pid=%u child_alive=%d",
            cleanup_complete ? 1 : 0,
            cleanup_requested ? 1 : 0,
            cleanup_receipt ? 1 : 0,
            static_cast<unsigned long long>(cleanup_generation_before),
            static_cast<unsigned long long>(cleanup_generation),
            cleanup_after.cleanup_pending ? 1 : 0,
            static_cast<unsigned>(cleanup_after.child_pid),
            cleanup_after.child_alive ? 1 : 0);
    } catch (...) {
        aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "shutdown_camoufox_force_cleanup");
        diag::log_tagged_critical("main", "shutdown_camoufox_force_cleanup_exception");
    }
    aida_shutdown_diag::mark("shutdown_hotkey_monitor");
    aida_hotkey_monitor::stop();
    diag::log_tagged_critical("main", "shutdown_hotkey_monitor_done");
    aida_shutdown_diag::mark("shutdown_focus_monitor");
    aida_focus_monitor::stop();
    diag::log_tagged_critical("main", "shutdown_focus_monitor_done");
    aida_shutdown_diag::mark("shutdown_prelude_begin");
    diag::log_tagged_critical("main", "shutdown_prelude_begin");
    aida_shutdown_diag::mark("shutdown_driver_bridge_deferred");
    diag::log_tagged_critical("main", "shutdown_driver_bridge_deferred reason=queue_drain_required");
    aida_shutdown_diag::mark("shutdown_prelude_done");
    diag::log_tagged_critical("main", "shutdown_prelude_done");
    aida_shutdown_diag::mark("shutdown_terminal");
    globals::terminal_mgr.shutdown();
    diag::log_tagged_critical("main", "shutdown_terminal_done");

    aida_shutdown_diag::mark("shutdown_memory_scanner");
    const uint64_t shutdown_scanner_start_ms = static_cast<uint64_t>(GetTickCount64());
    memory_scanner::shutdown();
    diag::log_tagged_critical_fmt("main", "shutdown_memory_scanner_done elapsed_ms=%llu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - shutdown_scanner_start_ms));

    aida_shutdown_diag::mark("shutdown_network");
    {
        char network_taskflow_pre[2400] = {};
        format_taskflow_runtime_crash_snapshot(network_taskflow_pre, sizeof(network_taskflow_pre));
        diag::log_tagged_critical_fmt("main", "shutdown_network_cleanup_pre %s", network_taskflow_pre);
    }
    const uint64_t shutdown_network_start_ms = static_cast<uint64_t>(GetTickCount64());
    network_view::shutdown();
    const uint64_t shutdown_network_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - shutdown_network_start_ms;
    {
        char network_taskflow_post[2400] = {};
        format_taskflow_runtime_crash_snapshot(network_taskflow_post, sizeof(network_taskflow_post));
        diag::log_tagged_critical_fmt("main", "shutdown_network_cleanup_done elapsed_ms=%llu %s",
            static_cast<unsigned long long>(shutdown_network_elapsed_ms),
            network_taskflow_post);
    }
    aida_shutdown_diag::mark("shutdown_script_engine");
    script_engine::shutdown();
    diag::log_tagged_critical("main", "shutdown_script_engine_done");
    aida_shutdown_diag::mark("shutdown_workflow_tools");
    workflow_tools::shutdown_services();
    diag::log_tagged_critical("main", "shutdown_workflow_tools_done");
    aida_shutdown_diag::mark("shutdown_chat");
    shutdown_standalone_chat();
    diag::log_tagged_critical("main", "shutdown_chat_done");
    aida_shutdown_diag::mark("shutdown_auth_http");
    aida::auth::http::cleanup();
    diag::log_tagged_critical("main", "shutdown_auth_http_done");
    aida_shutdown_diag::mark("shutdown_ide_shell");
    if (aida::ui_thread::require_owner("imgui", "ide_shell_shutdown", "shutdown"))
        aida::ui::ide_shell::shutdown();
    diag::log_tagged_critical("main", "shutdown_ide_shell_done");
    aida_shutdown_diag::mark("shutdown_executor");
    bool executor_stopped = aida::infra::executor::shutdown();
    if (!executor_stopped) {
        diag::log_tagged_critical("main", "shutdown_executor_incomplete_waiting_for_full_drain");
        executor_stopped = aida::infra::executor::shutdown(INFINITE);
    }
    diag::log_tagged_critical_fmt("main", "shutdown_executor_done complete=%d", executor_stopped ? 1 : 0);
    aida_shutdown_diag::mark("shutdown_destroy_window");
    if (hwnd && IsWindow(hwnd))
        ::DestroyWindow(hwnd);
    diag::log_tagged_critical("main", "shutdown_destroy_window_done");
    aida_shutdown_diag::mark("shutdown_imgui_dx11");
    if (aida::ui_thread::require_owner("dx11", "imgui_dx11_shutdown", "shutdown"))
        ImGui_ImplDX11_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_dx11_done");

    aida_shutdown_diag::mark("shutdown_imgui_win32");
    if (aida::ui_thread::require_owner("imgui_win32", "shutdown", "shutdown"))
        ImGui_ImplWin32_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_win32_done");
    aida_shutdown_diag::mark("shutdown_imgui_context");
    if (aida::ui_thread::require_owner("imgui", "destroy_context", "shutdown"))
        ImGui::DestroyContext();
    g_imgui_dx11_initialized = false;
    g_imgui_win32_initialized = false;
    diag::log_tagged_critical("main", "shutdown_imgui_context_done");

    aida_shutdown_diag::mark("shutdown_d3d");
    if (blend_state) {
        blend_state->Release();
        blend_state = nullptr;
    }
    CleanupDeviceD3D();
    diag::log_tagged_critical("main", "shutdown_d3d_done");
    if (g_aidaWindowIcon) {
        DestroyIcon(g_aidaWindowIcon);
        g_aidaWindowIcon = nullptr;
    }
    aida_shutdown_diag::mark("shutdown_unregister_class");
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    diag::log_tagged_critical("main", "shutdown_unregister_done");

    aida_shutdown_diag::mark("shutdown_exit_process");
    diag::log_tagged_critical("main", "shutdown_exit_process_pre");
    release_single_instance_gate();
    diag::flush_async_logs(5000);
    ExitProcess(0);
    return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
    if (!aida::ui_thread::require_owner("dx11", "create_device", "enter"))
        return false;
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (FAILED(res)) {
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }
    if (FAILED(res))
        return false;

    CreateRenderTarget();
    if (!g_mainRenderTargetView) {
        CleanupDeviceD3D();
        return false;
    }
    initialize_gpu_frame_queries();
    return true;
}

void CleanupDeviceD3D()
{
    if (!aida::ui_thread::require_owner("dx11", "cleanup_device", "enter"))
        return;
    release_gpu_frame_queries();
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    if (!aida::ui_thread::require_owner("render_target", "create", "enter"))
        return;
    ++g_resize_perf.render_target_recreates;
    ID3D11Texture2D* pBackBuffer = nullptr;
    HRESULT hr_get = E_POINTER;
    HRESULT hr_rtv = E_POINTER;
    DWORD seh_get = 0;
    DWORD seh_rtv = 0;
    aida_tracer::mark_render_phase("create_render_target_get_buffer");
    if (!g_pSwapChain || !g_pd3dDevice) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_missing_device swapchain=0x%llX device=0x%llX ctx=0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
        return;
    }
    __try {
        hr_get = g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "create_render_target_get_buffer");
        seh_get = GetExceptionCode();
    }
    if (seh_get != 0 || FAILED(hr_get) || !pBackBuffer) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_get_buffer_failed seh=0x%08X hr=0x%08X backbuffer=0x%llX swapchain=0x%llX device_removed=0x%08X",
            seh_get,
            static_cast<unsigned>(hr_get),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        if (pBackBuffer)
            pBackBuffer->Release();
        return;
    }
    aida_tracer::mark_render_phase("create_render_target_create_rtv");
    __try {
        hr_rtv = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "create_render_target_create_rtv");
        seh_rtv = GetExceptionCode();
    }
    if (seh_rtv != 0 || FAILED(hr_rtv) || !g_mainRenderTargetView) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_rtv_failed seh=0x%08X hr=0x%08X backbuffer=0x%llX rtv=0x%llX device=0x%llX device_removed=0x%08X",
            seh_rtv,
            static_cast<unsigned>(hr_rtv),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        pBackBuffer->Release();
        return;
    }

    D3D11_TEXTURE2D_DESC d{};
    __try {
        pBackBuffer->GetDesc(&d);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "create_render_target_get_desc");
        diag::log_tagged_critical_fmt("render",
            "create_render_target_get_desc_seh code=0x%08X backbuffer=0x%llX rtv=0x%llX",
            GetExceptionCode(),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)));
        pBackBuffer->Release();
        return;
    }

    pBackBuffer->Release();
    diag::log_tagged_critical_fmt("render",
        "create_render_target_ok backbuffer=0x%llX rtv=0x%llX desc=%ux%u rt_recreates=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)),
        d.Width,
        d.Height,
        static_cast<unsigned long long>(g_resize_perf.render_target_recreates));
}

void CleanupRenderTarget()
{
    if (!aida::ui_thread::require_owner("render_target", "cleanup", "enter"))
        return;
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

__declspec(noinline) static DWORD seh_imgui_wndproc_handler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* result_out)
{
    if (result_out)
        *result_out = 0;
    if (!aida::ui_thread::require_owner("imgui_win32", "wndproc_handler", "seh_enter"))
        return ERROR_ACCESS_DENIED;
    __try {
        if (!result_out)
            return ERROR_INVALID_PARAMETER;
        *result_out = ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_imgui_wndproc_handler");
        return GetExceptionCode();
    }
    return 0;
}

static bool g_session_exit_review_owned = false;

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (aida::ui_thread::owner_tid() == 0)
        aida::ui_thread::capture_owner_tid(::GetCurrentThreadId(), "win32", "WndProc", "enter");
    if (!aida::ui_thread::require_owner("win32", "WndProc", "enter"))
        return ::DefWindowProcW(hWnd, msg, wParam, lParam);
    aida_tracer::set_wndproc_state("enter", hWnd, msg, wParam, lParam);
    aida::diagnostics::metadata_ring::emit(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::wndproc,
        "wndproc_entry", nullptr, false);
    uint64_t wnd_start = static_cast<uint64_t>(GetTickCount64());
    const bool trace_input_msg = aida_tracer::should_log_wndproc_input_message(msg);
    auto finish = [&](const char* path, LRESULT result) -> LRESULT {
        uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - wnd_start;
        if (aida_tracer::should_log_wndproc_completion(msg, elapsed)) {
            POINT cursor{};
            GetCursorPos(&cursor);
            diag::log_tagged_critical_fmt("wndproc",
                "exit path=%s elapsed_ms=%llu result=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX",
                path,
                (unsigned long long)elapsed,
                (unsigned long long)result,
                aida_tracer::message_name(msg),
                msg,
                (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
                (unsigned long long)static_cast<UINT_PTR>(wParam),
                (unsigned long long)static_cast<LONG_PTR>(lParam),
                cursor.x,
                cursor.y,
                (unsigned long long)reinterpret_cast<UINT_PTR>(GetForegroundWindow()),
                (unsigned long long)reinterpret_cast<UINT_PTR>(GetActiveWindow()));
        }
        aida_tracer::clear_wndproc_state();
        return result;
    };

    auto log_session_shutdown = [&](const char* source) {
        char snapshot[2200] = {};
        test_all_features::format_debug_snapshot(snapshot, sizeof(snapshot));
        const bool full_test_running = test_all_features::is_running();
        diag::log_tagged_critical_fmt("session",
            "%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX full_test_running=%d shutdown=%d closeapp=%d critical=%d logoff=%d snapshot=%s",
            source ? source : "session_event",
            aida_tracer::message_name(msg),
            msg,
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            (unsigned long long)static_cast<UINT_PTR>(wParam),
            (unsigned long long)static_cast<LONG_PTR>(lParam),
            full_test_running ? 1 : 0,
            wParam ? 1 : 0,
            (lParam & ENDSESSION_CLOSEAPP) ? 1 : 0,
            (lParam & ENDSESSION_CRITICAL) ? 1 : 0,
            (lParam & ENDSESSION_LOGOFF) ? 1 : 0,
            snapshot);
        if (full_test_running)
            test_all_features::log_external_session_event(source, msg,
                static_cast<std::uintptr_t>(wParam),
                static_cast<std::intptr_t>(lParam));
    };

    if (msg == WM_GETICON)
        return finish("geticon_fast", reinterpret_cast<LRESULT>(g_aidaWindowIcon));

    if (aida::ui_thread::is_wake_message(msg)) {
        aida::ui_thread::acknowledge_wake_message();
        return finish("ui_dispatcher_wake", 0);
    }

    if (msg == WM_QUERYENDSESSION) {
        aida_tracer::set_wndproc_state("queryendsession", hWnd, msg, wParam, lParam);
        log_session_shutdown("WM_QUERYENDSESSION");
		if (file_tabs::exit_review_committed) {
			g_session_exit_review_owned = false;
			return finish("queryendsession_committed", TRUE);
		}
		const bool review_was_active = file_tabs::exit_review_requested;
		const auto requested = file_tabs::request_exit_review();
		if (requested.succeeded && !review_was_active)
			g_session_exit_review_owned = true;
		diag::log_tagged_critical_fmt("wndproc",
			"session_close_review_request accepted=%d owned=%d reason=%.512s",
			requested.succeeded ? 1 : 0, g_session_exit_review_owned ? 1 : 0,
			requested.detail.c_str());
		return finish(requested.succeeded
			? "queryendsession_review_pending" : "queryendsession_review_rejected", FALSE);
    }

    if (msg == WM_ENDSESSION) {
        aida_tracer::set_wndproc_state("endsession", hWnd, msg, wParam, lParam);
        log_session_shutdown(wParam ? "WM_ENDSESSION_COMMIT" : "WM_ENDSESSION_CANCEL");
		if (!wParam && g_session_exit_review_owned)
			file_tabs::cancel_close_all();
		if (wParam && file_tabs::exit_review_committed)
			::PostMessageW(hWnd, WM_CLOSE, 0, 0);
		else if (wParam)
			diag::log_tagged_critical_fmt("wndproc",
				"session_end_rejected_uncommitted hwnd=0x%llX",
				static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)));
		g_session_exit_review_owned = false;
        return finish("endsession", 0);
    }

    if (msg == WM_HOTKEY && static_cast<int>(wParam) == kAidaFullTestHotkeyId) {
        const WORD mods = LOWORD(lParam);
        const WORD vk = HIWORD(lParam);
        const bool foreground = aida_focus_monitor::foreground_belongs_to_process(hWnd);
        diag::log_tagged_critical_fmt("ui",
            "test_all_start hotkey=WM_HOTKEY id=0x%X mods=0x%04X vk=0x%04X foreground=%d hwnd=0x%llX",
            static_cast<unsigned>(wParam),
            static_cast<unsigned>(mods),
            static_cast<unsigned>(vk),
            foreground ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)));
        if (!foreground)
            return finish("hotkey_full_test_ignored_foreground", 0);
        const bool posted = test_all_features::post_hotkey_trigger("win32_ctrl_shift_t");
        return finish(posted ? "hotkey_full_test_posted" : "hotkey_full_test_not_posted", 0);
    }

    if (msg == WM_CLOSE ||
        (msg == WM_SYSCOMMAND && ((wParam & 0xfff0) == SC_CLOSE))) {
        const bool sys_close = (msg == WM_SYSCOMMAND);
		if (!file_tabs::exit_review_committed) {
			if (g_session_exit_review_owned && !file_tabs::exit_review_requested)
				g_session_exit_review_owned = false;
			const auto requested = file_tabs::request_exit_review();
			diag::log_tagged_critical_fmt("wndproc",
				"close_review_request source=%s accepted=%d reason=%.512s",
				sys_close ? "WM_SYSCOMMAND_SC_CLOSE" : "WM_CLOSE",
				requested.succeeded ? 1 : 0,
				requested.detail.c_str());
			return finish(requested.succeeded
				? "close_review_requested" : "close_review_rejected", 0);
		}
		g_session_exit_review_owned = false;
        aida_shutdown_diag::mark(sys_close ? "wndproc_syscommand_close_destroy" : "wndproc_wm_close_destroy");
        aida::ui_thread::mark_window_destroying(hWnd, "wndproc", sys_close ? "syscommand_close" : "wm_close", "pre_destroy_window");
        ::SetLastError(0);
        BOOL destroyed = ::DestroyWindow(hWnd);
        DWORD gle = ::GetLastError();
        diag::log_tagged_critical_fmt("wndproc",
            "close_destroy source=%s hwnd=0x%llX destroyed=%d gle=%lu tid=%lu",
            sys_close ? "WM_SYSCOMMAND_SC_CLOSE" : "WM_CLOSE",
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            destroyed ? 1 : 0,
            static_cast<unsigned long>(gle),
            GetCurrentThreadId());
        if (!destroyed)
            ::PostQuitMessage(0);
        return finish(sys_close ? "syscommand_close_destroy" : "close_destroy", 0);
    }

    if (msg == WM_DESTROY) {
        aida_shutdown_diag::mark("wndproc_destroy_post_quit");
        aida::ui_thread::mark_window_destroying(hWnd, "wndproc", "wm_destroy", "post_quit");
        diag::log_tagged_critical_fmt("wndproc",
            "destroy_post_quit hwnd=0x%llX tid=%lu",
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            GetCurrentThreadId());
        ::PostQuitMessage(0);
        return finish("destroy", 0);
    }

    if (msg == WM_NCDESTROY) {
        aida::ui_thread::mark_window_destroying(hWnd, "wndproc", "wm_ncdestroy", "enter");
        return finish("ncdestroy", ::DefWindowProcW(hWnd, msg, wParam, lParam));
    }

    if (trace_input_msg) {
        POINT cursor{};
        GetCursorPos(&cursor);
        diag::log_tagged_critical_fmt("wndproc",
            "imgui_handler_call msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
            aida_tracer::message_name(msg),
            msg,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            static_cast<unsigned long long>(static_cast<LONG_PTR>(lParam)),
            cursor.x,
            cursor.y,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
    }
    aida_tracer::set_wndproc_state("imgui_enter", hWnd, msg, wParam, lParam);
    LRESULT imgui_result = 0;
    DWORD imgui_seh = 0;
    {
        aida::diagnostic_exception_scope::scope_t exception_scope("WndProc.ImGui_ImplWin32_WndProcHandler");
        imgui_seh = seh_imgui_wndproc_handler(hWnd, msg, wParam, lParam, &imgui_result);
    }
    const uint64_t imgui_elapsed = static_cast<uint64_t>(GetTickCount64()) - wnd_start;
    if (trace_input_msg || imgui_seh != 0 || imgui_elapsed >= 32) {
        POINT cursor{};
        GetCursorPos(&cursor);
        diag::log_tagged_critical_fmt("wndproc",
            "imgui_handler_return msg=%s(0x%04X) elapsed_ms=%llu seh=0x%08X result=0x%llX hwnd=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
            aida_tracer::message_name(msg),
            msg,
            static_cast<unsigned long long>(imgui_elapsed),
            imgui_seh,
            static_cast<unsigned long long>(imgui_result),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            cursor.x,
            cursor.y,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
    }
    if (imgui_seh != 0)
        aida_tracer::set_wndproc_state("imgui_seh_recovered", hWnd, msg, wParam, lParam);
    else if (imgui_result)
        return finish("imgui", true);
    aida_tracer::set_wndproc_state("switch_enter", hWnd, msg, wParam, lParam);

    switch (msg)
    {
    case WM_GETTEXTLENGTH:
        return finish("gettextlength", static_cast<LRESULT>(std::wcslen(kAidaWindowTitle)));
    case WM_GETTEXT:
    {
        wchar_t* out = reinterpret_cast<wchar_t*>(lParam);
        size_t capacity = static_cast<size_t>(wParam);
        if (!out || capacity == 0)
            return finish("gettext_empty", 0);
        size_t title_len = std::wcslen(kAidaWindowTitle);
        size_t copy_len = (std::min)(title_len, capacity - 1);
        if (copy_len > 0)
            std::memcpy(out, kAidaWindowTitle, copy_len * sizeof(wchar_t));
        out[copy_len] = L'\0';
        return finish("gettext", static_cast<LRESULT>(copy_len));
    }
    case WM_ERASEBKGND:
        return finish("erasebkgnd", 1);
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        return finish("paint", 0);
    }
    case WM_NCCALCSIZE:
    {
        if (wParam == TRUE)
        {
            NCCALCSIZE_PARAMS* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
            RECT* rect = &params->rgrc[0];
            const bool zoomed = ::IsZoomed(hWnd) != FALSE;
            diag::log_tagged_fmt("wndproc",
                "nccalcsize zoomed=%d before=(%ld,%ld,%ld,%ld) dpi=%u",
                zoomed ? 1 : 0,
                rect->left, rect->top, rect->right, rect->bottom,
                static_cast<unsigned>(::GetDpiForWindow(hWnd)));
            if (zoomed)
            {
                const UINT dpi = ::GetDpiForWindow(hWnd);
                const int frame_x = ::GetSystemMetricsForDpi(SM_CXFRAME, dpi);
                const int frame_y = ::GetSystemMetricsForDpi(SM_CYFRAME, dpi);
                const int padding = ::GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                const int inset = frame_x + padding;
                const int inset_y = frame_y + padding;
                rect->left   += inset;
                rect->right  -= inset;
                rect->top    += inset_y;
                rect->bottom -= inset_y;
                HMONITOR hm = ::MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                MONITORINFO mi = { sizeof(mi) };
                if (::GetMonitorInfoW(hm, &mi))
                {
                    rect->left   = mi.rcWork.left;
                    rect->top    = mi.rcWork.top;
                    rect->right  = mi.rcWork.right;
                    rect->bottom = mi.rcWork.bottom;
                }
            }
            return finish("nccalcsize_zero_nc", 0);
        }
        break;
    }
    case WM_NCHITTEST:
    {

        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        RECT rc; GetWindowRect(hWnd, &rc);
        const int border = static_cast<int>(6 * globals::ui::dpi_scale);
        bool left   = pt.x < rc.left   + border;
        bool right  = pt.x > rc.right  - border;
        bool top    = pt.y < rc.top    + border;
        bool bottom = pt.y > rc.bottom - border;


        if (globals::ui::welcome_done &&
            !::IsZoomed(hWnd)) {
            if (top    && left)  return finish("nchittest_top_left", HTTOPLEFT);
            if (top    && right) return finish("nchittest_top_right", HTTOPRIGHT);
            if (bottom && left)  return finish("nchittest_bottom_left", HTBOTTOMLEFT);
            if (bottom && right) return finish("nchittest_bottom_right", HTBOTTOMRIGHT);
            if (left)            return finish("nchittest_left", HTLEFT);
            if (right)           return finish("nchittest_right", HTRIGHT);
            if (top)             return finish("nchittest_top", HTTOP);
            if (bottom)          return finish("nchittest_bottom", HTBOTTOM);
        }
        return finish("nchittest_client", HTCLIENT);
    }
    case WM_SIZE:
    {
        if (wParam == SIZE_MINIMIZED)
        {
            diag::log_tagged_critical_fmt("wndproc",
                "size_minimized hwnd=0x%llX iconic=%d zoomed=%d",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
                ::IsIconic(hWnd) ? 1 : 0,
                ::IsZoomed(hWnd) ? 1 : 0);
            return finish("size_minimized", 0);
        }
        const bool now_zoomed = (wParam == SIZE_MAXIMIZED) ||
                                (wParam == SIZE_RESTORED && ::IsZoomed(hWnd));
        if (!aida::ui_thread::require_owner("ui_state", "wm_size", "WndProc"))
            return finish("size_affinity_denied", 0);
        globals::ui::maximized = now_zoomed;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        g_ResizeRequestTickMs = static_cast<uint64_t>(GetTickCount64());
        ++g_resize_perf.requests;
        diag::log_tagged_critical_fmt("wndproc",
            "size hwnd=0x%llX wp=%llu w=%u h=%u zoomed=%d resize_requests=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            g_ResizeWidth,
            g_ResizeHeight,
            now_zoomed ? 1 : 0,
            static_cast<unsigned long long>(g_resize_perf.requests));
        return finish("size", 0);
    }
    case WM_GETMINMAXINFO:
    {

        HMONITOR hm = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = { sizeof(mi) };
        if (GetMonitorInfoW(hm, &mi)) {
            auto* mm = reinterpret_cast<MINMAXINFO*>(lParam);
            mm->ptMaxPosition.x = mi.rcWork.left - mi.rcMonitor.left;
            mm->ptMaxPosition.y = mi.rcWork.top - mi.rcMonitor.top;
            mm->ptMaxSize.x = mi.rcWork.right - mi.rcWork.left;
            mm->ptMaxSize.y = mi.rcWork.bottom - mi.rcWork.top;
        }
        return finish("getminmaxinfo", 0);
    }
    case WM_SYSCOMMAND:
    {
        const UINT cmd = static_cast<UINT>(wParam) & 0xFFF0u;
        diag::log_tagged_critical_fmt("wndproc",
            "syscommand cmd=0x%04X wp=0x%llX lp=0x%llX zoomed=%d iconic=%d",
            cmd,
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            static_cast<unsigned long long>(static_cast<LONG_PTR>(lParam)),
            ::IsZoomed(hWnd) ? 1 : 0,
            ::IsIconic(hWnd) ? 1 : 0);
        if (cmd == SC_KEYMENU)
            return finish("syscommand_keymenu", 0);
        break;
    }
    case WM_SETFOCUS:
        g_SwapChainOccluded = false;
        ::InvalidateRect(hWnd, nullptr, FALSE);
        return finish("setfocus", 0);
    case WM_KILLFOCUS:
        return finish("killfocus", 0);
    case WM_ACTIVATE:
        g_SwapChainOccluded = false;
        ::InvalidateRect(hWnd, nullptr, FALSE);
        return finish("activate", 0);
    case WM_ACTIVATEAPP:
        if (wParam == TRUE) {
            g_SwapChainOccluded = false;
            if (::IsWindow(hWnd) && !::IsIconic(hWnd)) {
                aida_tracer::set_wndproc_state("activateapp_invalidate", hWnd, msg, wParam, lParam);
                ::InvalidateRect(hWnd, nullptr, FALSE);
            }
        }
        return finish("activateapp", 0);
    case WM_DPICHANGED:
    {
        UINT dpi = HIWORD(wParam);
        if (!aida::ui_thread::require_owner("ui_state", "dpi_changed", "WndProc"))
            return finish("dpichanged_affinity_denied", 0);
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
        aida::ui::set_dpi_scale(globals::ui::dpi_scale);
        RECT* suggested = reinterpret_cast<RECT*>(lParam);
        aida_tracer::set_wndproc_state("dpichanged_setwindowpos", hWnd, msg, wParam, lParam);
        SetWindowPos(hWnd, nullptr,
            suggested->left, suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        if (dpi != 0 && dpi != g_AppliedFontDpi.load(std::memory_order_acquire))
            g_PendingFontDpi.store(dpi, std::memory_order_release);
        ::InvalidateRect(hWnd, nullptr, FALSE);
        return finish("dpichanged", 0);
    }
    case WM_SETTINGCHANGE:
    {
        if (lParam) {
            const wchar_t* p = reinterpret_cast<const wchar_t*>(lParam);
            if (p && (wcscmp(p, L"ImmersiveColorSet") == 0 ||
                      wcscmp(p, L"WindowsThemeElement") == 0)) {
                aida_tracer::set_wndproc_state("settingchange_theme_detected", hWnd, msg, wParam, lParam);
            }
        }
        return finish("settingchange", 0);
    }
    case WM_DROPFILES:
    {
        HDROP hdrop = reinterpret_cast<HDROP>(wParam);
        const uint64_t generation = g_dragdrop_ui_generation.fetch_add(1ULL, std::memory_order_acq_rel) + 1ULL;
        const uint64_t capture_start_ms = static_cast<uint64_t>(::GetTickCount64());
        const DWORD producer_tid = ::GetCurrentThreadId();
        UINT count = 0;
        UINT path_chars = 0;
        UINT got = 0;
        DWORD capture_gle = 0;
        bool captured = false;
        bool converted = false;
        bool queued = false;
        POINT drop_point{};
        BOOL drop_point_client = FALSE;
        std::wstring dropped_path_w;
        std::string dropped_path;
        if (hdrop) {
            aida_tracer::set_wndproc_state("dropfiles_query_count", hWnd, msg, wParam, lParam);
            drop_point_client = ::DragQueryPoint(hdrop, &drop_point);
            count = ::DragQueryFileW(hdrop, 0xFFFFFFFFu, nullptr, 0);
            if (count > 0) {
                aida_tracer::set_wndproc_state("dropfiles_query_path", hWnd, msg, wParam, lParam);
                path_chars = ::DragQueryFileW(hdrop, 0, nullptr, 0);
                if (path_chars > 0 && path_chars <= 32767u) {
                    std::vector<wchar_t> path_buffer(static_cast<std::size_t>(path_chars) + 1u, L'\0');
                    got = ::DragQueryFileW(hdrop, 0, path_buffer.data(), path_chars + 1u);
                    if (got > 0) {
                        dropped_path_w.assign(path_buffer.data(), static_cast<std::size_t>(got));
                        captured = true;
                    }
                } else if (path_chars > 32767u) {
                    capture_gle = ERROR_FILENAME_EXCED_RANGE;
                }
            }
            aida_tracer::set_wndproc_state("dropfiles_finish", hWnd, msg, wParam, lParam);
            ::DragFinish(hdrop);
        } else {
            capture_gle = ERROR_INVALID_HANDLE;
        }
        aida_tracer::set_wndproc_state("dropfiles_enqueue", hWnd, msg, wParam, lParam);
        if (captured)
            converted = aida_wide_to_utf8_owned(dropped_path_w, dropped_path);
        if (converted && !dropped_path.empty()) {
            const std::string path_for_ui = dropped_path;
            const uint64_t deadline_ms = static_cast<uint64_t>(::GetTickCount64()) + 5000ULL;
            aida::ui_thread::post_options_t options;
            options.subsystem = "dragdrop";
            options.label = "open_path";
            options.phase = "wndproc_deferred";
            options.owner = "dragdrop";
            options.priority = aida::ui_thread::priority_t::high;
            options.deadline_ms = deadline_ms;
            options.cancelled = [generation]() {
                return g_dragdrop_ui_generation.load(std::memory_order_acquire) != generation;
            };
            const aida::ui_thread::enqueue_result_t dispatch_result = aida::ui_thread::post(
                [path_for_ui, generation, producer_tid, capture_start_ms]() {
                    aida_dispatch_dropped_file_open(path_for_ui, generation, producer_tid, capture_start_ms);
                },
                std::move(options));
            queued = dispatch_result == aida::ui_thread::enqueue_result_t::accepted;
            diag::log_tagged_critical_fmt("DRAGDROP-UI-DISPATCH",
                "enqueue generation=%llu result=%s deadline_ms=%llu priority=high path_len=%zu",
                static_cast<unsigned long long>(generation),
                aida::ui_thread::result_name(dispatch_result),
                static_cast<unsigned long long>(deadline_ms),
                path_for_ui.size());
        }
        diag::log_tagged_critical_fmt("WNDPROC-DEFERRED-WORK",
            "dropfiles generation=%llu hwnd=0x%llX hdrop=0x%llX count=%u path_chars=%u got=%u captured=%d converted=%d queued=%d gle=%lu elapsed_ms=%llu drop_point_client=%d drop_x=%ld drop_y=%ld ui_pending=%zu path=%.260s",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hdrop)),
            count,
            path_chars,
            got,
            captured ? 1 : 0,
            converted ? 1 : 0,
            queued ? 1 : 0,
            static_cast<unsigned long>(capture_gle),
            static_cast<unsigned long long>(static_cast<uint64_t>(::GetTickCount64()) - capture_start_ms),
            drop_point_client ? 1 : 0,
            drop_point.x,
            drop_point.y,
            aida::ui_thread::pending_count(),
            dropped_path.c_str());
        return finish("dropfiles", 0);
    }
    }
    aida_tracer::set_wndproc_state("defwindowproc_enter", hWnd, msg, wParam, lParam);
    LRESULT def_result = ::DefWindowProcW(hWnd, msg, wParam, lParam);
    return finish("defwindowproc", def_result);
}
