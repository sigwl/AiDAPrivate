#include "comm.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cwchar>
#include <cwctype>
#include "../src/standalone/src/helpers/diag_log.hpp"
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <intrin.h>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <mutex>
#include <optional>

#ifdef _DEBUG
#define RC_UM_DBG(fmt, ...) do { char _rc_buf[512]; _snprintf_s(_rc_buf, sizeof(_rc_buf), _TRUNCATE, "[AIDA-RC-UM] " fmt "\n", ##__VA_ARGS__); OutputDebugStringA(_rc_buf); } while(0)
#else
#define RC_UM_DBG(fmt, ...) do { char _rc_buf[512]; _snprintf_s(_rc_buf, sizeof(_rc_buf), _TRUNCATE, "[AIDA-RC-UM] " fmt "\n", ##__VA_ARGS__); OutputDebugStringA(_rc_buf); } while(0)
#endif

#pragma comment(lib, "ntdll.lib")

#ifndef _PCLIENT_ID_DEFINED
#define _PCLIENT_ID_DEFINED
typedef CLIENT_ID* PCLIENT_ID;
#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace {
    std::atomic<std::uint64_t> g_remote_call_um_sequence{1};

    struct remote_call_um_attempt_diag_t {
        const char* failure_class = "none";
        DWORD gle = ERROR_SUCCESS;
        DWORD tid = 0;
        DWORD scanned = 0;
        LONG ntstatus = 0;
        int poll_failures = 0;
        bool selected = false;
        bool request_sent = false;
        bool hijack_set = false;
    };

    struct remote_call_um_failure_counts_t {
        int no_suitable_thread = 0;
        int request_send_failed = 0;
        int poll_timeout = 0;
        int poll_ioctl_failed = 0;
        int context_restore_failed = 0;
        int hijack_set_failed = 0;
        int thread_snapshot_failed = 0;
        int thread_blacklisted = 0;
        int unknown = 0;
    };

    thread_local remote_call_um_attempt_diag_t g_remote_call_um_attempt_diag{};

    void remote_call_um_set_failure(const char* failure_class,
                                    DWORD gle,
                                    DWORD tid,
                                    DWORD scanned,
                                    LONG ntstatus = 0,
                                    int poll_failures = 0) noexcept
    {
        g_remote_call_um_attempt_diag.failure_class = failure_class && failure_class[0] ? failure_class : "unknown";
        g_remote_call_um_attempt_diag.gle = gle;
        g_remote_call_um_attempt_diag.tid = tid;
        g_remote_call_um_attempt_diag.scanned = scanned;
        g_remote_call_um_attempt_diag.ntstatus = ntstatus;
        g_remote_call_um_attempt_diag.poll_failures = poll_failures;
    }

    void remote_call_um_note_failure(remote_call_um_failure_counts_t& counts, const char* failure_class) noexcept
    {
        if (!failure_class || !failure_class[0] || std::strcmp(failure_class, "none") == 0) {
            ++counts.unknown;
        } else if (std::strcmp(failure_class, "no_suitable_thread") == 0) {
            ++counts.no_suitable_thread;
        } else if (std::strcmp(failure_class, "request_send_failed") == 0) {
            ++counts.request_send_failed;
        } else if (std::strcmp(failure_class, "poll_timeout") == 0) {
            ++counts.poll_timeout;
        } else if (std::strcmp(failure_class, "poll_ioctl_failed") == 0) {
            ++counts.poll_ioctl_failed;
        } else if (std::strcmp(failure_class, "context_restore_failed") == 0) {
            ++counts.context_restore_failed;
        } else if (std::strcmp(failure_class, "hijack_set_failed") == 0) {
            ++counts.hijack_set_failed;
        } else if (std::strcmp(failure_class, "thread_snapshot_failed") == 0) {
            ++counts.thread_snapshot_failed;
        } else if (std::strcmp(failure_class, "thread_blacklisted") == 0) {
            ++counts.thread_blacklisted;
        } else {
            ++counts.unknown;
        }
    }

    DWORD remote_call_um_failure_gle(const remote_call_um_attempt_diag_t& diag) noexcept
    {
        if (diag.gle != ERROR_SUCCESS)
            return diag.gle;
        if (std::strcmp(diag.failure_class, "no_suitable_thread") == 0)
            return ERROR_NOT_FOUND;
        if (std::strcmp(diag.failure_class, "thread_snapshot_failed") == 0)
            return ERROR_GEN_FAILURE;
        if (std::strcmp(diag.failure_class, "request_send_failed") == 0)
            return ERROR_IO_DEVICE;
        if (std::strcmp(diag.failure_class, "poll_ioctl_failed") == 0)
            return ERROR_IO_DEVICE;
        if (std::strcmp(diag.failure_class, "hijack_set_failed") == 0)
            return ERROR_ACCESS_DENIED;
        if (std::strcmp(diag.failure_class, "context_restore_failed") == 0)
            return ERROR_ACCESS_DENIED;
        return ERROR_TIMEOUT;
    }

    static std::uint64_t mix_remote_call_diag(std::uint64_t value, std::uint64_t input) noexcept
    {
        value ^= input + 0x9E3779B97F4A7C15ull + (value << 6) + (value >> 2);
        return value;
    }

    static std::uint64_t remote_call_request_fingerprint(const voyager::detail::remote_call_request& req) noexcept
    {
        std::uint64_t value = 0xA1DA778100000001ull;
        value = mix_remote_call_diag(value, req.dtb);
        value = mix_remote_call_diag(value, req.target_function);
        value = mix_remote_call_diag(value, req.shellcode_address);
        value = mix_remote_call_diag(value, req.spoof_return);
        value = mix_remote_call_diag(value, req.arg1);
        value = mix_remote_call_diag(value, req.arg2);
        value = mix_remote_call_diag(value, req.arg3);
        value = mix_remote_call_diag(value, req.arg4);
        value = mix_remote_call_diag(value, req.original_rip);
        return value;
    }

    static std::uint64_t remote_result_request_fingerprint(const voyager::detail::call_result_request& req) noexcept
    {
        std::uint64_t value = 0xA1DA778200000001ull;
        value = mix_remote_call_diag(value, req.dtb);
        value = mix_remote_call_diag(value, req.result_address);
        value = mix_remote_call_diag(value, req.result);
        value = mix_remote_call_diag(value, req.completed);
        return value;
    }
}

namespace syscall_indices {
    inline std::uint32_t NtOpenThread_idx = 0;
    inline std::uint32_t NtSuspendThread_idx = 0;
    inline std::uint32_t NtResumeThread_idx = 0;
    inline std::uint32_t NtGetContextThread_idx = 0;
    inline std::uint32_t NtSetContextThread_idx = 0;
    inline std::uint32_t NtClose_idx = 0;
    inline std::uint8_t* syscall_instruction_addr = nullptr;
    inline volatile bool indices_resolved = false;

    __forceinline std::uint8_t* find_syscall_ret() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return nullptr;

        std::uint8_t* base = reinterpret_cast<std::uint8_t*>(ntdll);
        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        std::uint32_t text_size = nt->OptionalHeader.SizeOfCode;
        std::uint32_t text_rva = nt->OptionalHeader.BaseOfCode;
        std::uint8_t* text = base + text_rva;

        for (std::uint32_t i = 0; i < text_size - 3; i++) {
            if (text[i] == 0x0F && text[i + 1] == 0x05 && text[i + 2] == 0xC3) {
                return &text[i];
            }
        }
        return nullptr;
    }

    __forceinline bool resolve_syscall_indices() {
        if (indices_resolved) return true;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        syscall_instruction_addr = find_syscall_ret();
        if (!syscall_instruction_addr) return false;

        auto get_syscall_number = [&](const char* name) -> std::uint32_t {
            PVOID func = reinterpret_cast<PVOID>(GetProcAddress(ntdll, name));
            if (!func) return 0;
            std::uint8_t* bytes = reinterpret_cast<std::uint8_t*>(func);
            if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
                return *reinterpret_cast<std::uint32_t*>(&bytes[4]);
            }
            if (bytes[0] == 0xB8) {
                return *reinterpret_cast<std::uint32_t*>(&bytes[1]);
            }
            for (int j = 0; j < 32; j++) {
                if (bytes[j] == 0xB8 && bytes[j + 5] == 0x0F && bytes[j + 6] == 0x05) {
                    return *reinterpret_cast<std::uint32_t*>(&bytes[j + 1]);
                }
            }
            return 0;
        };

        NtOpenThread_idx = get_syscall_number("NtOpenThread");
        NtSuspendThread_idx = get_syscall_number("NtSuspendThread");
        NtResumeThread_idx = get_syscall_number("NtResumeThread");
        NtGetContextThread_idx = get_syscall_number("NtGetContextThread");
        NtSetContextThread_idx = get_syscall_number("NtSetContextThread");
        NtClose_idx = get_syscall_number("NtClose");

        indices_resolved = (NtOpenThread_idx && NtSuspendThread_idx && NtResumeThread_idx &&
                           NtGetContextThread_idx && NtSetContextThread_idx && NtClose_idx &&
                           syscall_instruction_addr);
        return indices_resolved;
    }
}

namespace {
    constexpr std::size_t k_staged_physical_chunk_size = 0x1000;
    constexpr std::uint64_t k_tctx_user_address_max = 0x00007FFFFFFFFFFFull;
    constexpr std::uint64_t k_tctx_kernel_address_min = 0xFFFF800000000000ull;
    static bool tctx_user_canonical(std::uint64_t value) noexcept {
        return value != 0 && value <= k_tctx_user_address_max;
    }

    static bool tctx_kernel_canonical(std::uint64_t value) noexcept {
        return value >= k_tctx_kernel_address_min;
    }

    static const char* tctx_address_class(std::uint64_t value) noexcept {
        if (value == 0) {
            return "zero";
        }
        if (tctx_user_canonical(value)) {
            return "user";
        }
        if (tctx_kernel_canonical(value)) {
            return "kernel";
        }
        return "noncanonical";
    }

    static bool tctx_user_context_sane(std::uint64_t rip, std::uint64_t rsp, std::uint64_t rflags) noexcept {
        return rflags != 0 && tctx_user_canonical(rip) && tctx_user_canonical(rsp);
    }

    struct dpi_payload_view_t {
        const std::uint8_t* data = nullptr;
        std::uint32_t size = 0;
    };

    static dpi_payload_view_t dpi_select_app_payload(const std::vector<std::uint8_t>& payload, std::uint32_t protocol) noexcept {
        dpi_payload_view_t direct{payload.data(), static_cast<std::uint32_t>(payload.size())};
        if (protocol != 6 || payload.size() < 20)
            return direct;
        const std::uint8_t header_len = static_cast<std::uint8_t>(((payload[12] >> 4) & 0x0F) * 4);
        if (header_len >= 20 && header_len <= payload.size())
            return {payload.data() + header_len, static_cast<std::uint32_t>(payload.size() - header_len)};
        return direct;
    }

    static std::uint32_t dpi_http_method_id(const std::uint8_t* data, std::uint32_t len) noexcept {
        if (!data || len < 4) return 0;
        if (len >= 4 && std::memcmp(data, "GET ", 4) == 0) return 1;
        if (len >= 5 && std::memcmp(data, "POST ", 5) == 0) return 2;
        if (len >= 4 && std::memcmp(data, "PUT ", 4) == 0) return 3;
        if (len >= 7 && std::memcmp(data, "DELETE ", 7) == 0) return 4;
        if (len >= 5 && std::memcmp(data, "HEAD ", 5) == 0) return 5;
        if (len >= 5 && std::memcmp(data, "HTTP/", 5) == 0) return 6;
        return 0;
    }

    static void dpi_extract_http_header_value(const std::uint8_t* data, std::uint32_t len, const char* name, std::string& out) {
        out.clear();
        if (!data || !name || len == 0) return;
        const std::size_t name_len = std::strlen(name);
        for (std::uint32_t i = 0; i + name_len + 1 < len; ++i) {
            if (i != 0 && data[i - 1] != '\n') continue;
            std::uint32_t j = 0;
            while (j < name_len && i + j < len &&
                   std::tolower(static_cast<unsigned char>(data[i + j])) == std::tolower(static_cast<unsigned char>(name[j]))) {
                ++j;
            }
            if (j != name_len || i + j >= len || data[i + j] != ':') continue;
            j++;
            while (i + j < len && (data[i + j] == ' ' || data[i + j] == '\t')) ++j;
            const std::uint32_t start = i + j;
            while (i + j < len && data[i + j] != '\r' && data[i + j] != '\n') ++j;
            out.assign(reinterpret_cast<const char*>(data + start), j - (start - i));
            return;
        }
    }

    static void dpi_extract_http_path(const std::uint8_t* data, std::uint32_t len, std::string& out) {
        out.clear();
        if (!data || len == 0) return;
        std::uint32_t i = 0;
        while (i < len && data[i] != ' ' && data[i] != '\r' && data[i] != '\n') ++i;
        if (i >= len || data[i] != ' ') return;
        ++i;
        const std::uint32_t start = i;
        while (i < len && data[i] != ' ' && data[i] != '\r' && data[i] != '\n') ++i;
        if (i > start)
            out.assign(reinterpret_cast<const char*>(data + start), i - start);
    }

    static void dpi_detect_tls(const std::uint8_t* data, std::uint32_t len, voyager::device_t::dpi_result& out) {
        if (!data || len < 5) return;
        const std::uint8_t content_type = data[0];
        const std::uint16_t version = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[1]) << 8) | data[2]);
        if (content_type < 20 || content_type > 23 || data[1] != 0x03)
            return;
        out.is_tls = true;
        out.tls_version = version;
        out.tls_content_type = content_type;
        if (content_type != 22 || len < 9 || data[5] != 1)
            return;
        std::uint32_t pos = 5 + 4 + 2 + 32;
        if (pos >= len) return;
        pos += 1 + data[pos];
        if (pos + 2 > len) return;
        const std::uint16_t cs_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1]);
        pos += 2 + cs_len;
        if (pos >= len) return;
        pos += 1 + data[pos];
        if (pos + 2 > len) return;
        const std::uint16_t ext_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1]);
        pos += 2;
        std::uint32_t ext_end = pos + ext_len;
        if (ext_end > len) ext_end = len;
        while (pos + 4 <= ext_end) {
            const std::uint16_t ext_type = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1]);
            const std::uint16_t item_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos + 2]) << 8) | data[pos + 3]);
            pos += 4;
            if (pos + item_len > ext_end) break;
            if (ext_type == 0 && item_len >= 5) {
                std::uint32_t sni_pos = pos + 2;
                if (sni_pos < pos + item_len && data[sni_pos] == 0) {
                    ++sni_pos;
                    if (sni_pos + 2 <= pos + item_len) {
                        const std::uint16_t name_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[sni_pos]) << 8) | data[sni_pos + 1]);
                        sni_pos += 2;
                        if (sni_pos + name_len <= pos + item_len)
                            out.tls_sni.assign(reinterpret_cast<const char*>(data + sni_pos), name_len);
                    }
                }
                return;
            }
            pos += item_len;
        }
    }

    static bool dpi_result_matches_filters(const voyager::device_t::dpi_result& d,
                                           std::uint32_t filter_pid,
                                           std::uint32_t filter_protocol,
                                           std::uint32_t filter_port,
                                           std::uint32_t flags) noexcept {
        if (filter_pid != 0 && d.pid != filter_pid) return false;
        if (filter_protocol != 0 && d.protocol != filter_protocol) return false;
        if (filter_port != 0 && d.src_port != filter_port && d.dst_port != filter_port) return false;
        if ((flags & 1) != 0 && !d.is_http) return false;
        if ((flags & 2) != 0 && !d.is_tls) return false;
        if ((flags & 4) != 0 && !d.is_dns) return false;
        return true;
    }

    static bool dpi_from_captured_packet(const voyager::device_t::captured_packet& pkt,
                                         voyager::device_t::dpi_result& out) {
        if (pkt.payload.empty()) return false;
        out = {};
        out.timestamp = pkt.timestamp;
        out.direction = pkt.direction;
        out.protocol = pkt.protocol;
        out.src_port = pkt.local_port;
        out.dst_port = pkt.remote_port;
        out.pid = pkt.pid;
        out.payload_size = pkt.payload_size;
        out.af = pkt.address_family;
        std::memcpy(out.src_addr, pkt.local_addr, sizeof(out.src_addr));
        std::memcpy(out.dst_addr, pkt.remote_addr, sizeof(out.dst_addr));
        const auto app = dpi_select_app_payload(pkt.payload, pkt.protocol);
        const std::uint32_t method = dpi_http_method_id(app.data, app.size);
        if (method != 0) {
            out.is_http = true;
            out.http_method = method;
            dpi_extract_http_header_value(app.data, app.size, "host", out.http_host);
            dpi_extract_http_path(app.data, app.size, out.http_path);
        }
        dpi_detect_tls(app.data, app.size, out);
        if ((pkt.local_port == 53 || pkt.remote_port == 53) && app.size >= 12)
            out.is_dns = true;
        return true;
    }

    class virtual_alloc_buffer_t final {
    public:
        explicit virtual_alloc_buffer_t(std::size_t size) noexcept : size_(size) {
            data_ = static_cast<std::uint8_t*>(::VirtualAlloc(
                nullptr,
                size_,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE));

            if (data_ != nullptr) {
                std::memset(data_, 0, size_);
            }
        }

        ~virtual_alloc_buffer_t() {
            if (data_ != nullptr) {
                ::VirtualFree(data_, 0, MEM_RELEASE);
            }
        }

        virtual_alloc_buffer_t(const virtual_alloc_buffer_t&) = delete;
        virtual_alloc_buffer_t& operator=(const virtual_alloc_buffer_t&) = delete;

        std::uint8_t* data() const noexcept { return data_; }
        explicit operator bool() const noexcept { return data_ != nullptr; }

    private:
        std::uint8_t* data_ = nullptr;
        std::size_t size_ = 0;
    };
}
bool voyager::device_t::connect() noexcept {
    if (is_connected()) {
        diag::log_tagged_critical_fmt("comm-startup",
            "connect_skip already_connected=1 handle=0x%llX pid=%u",
            reinterpret_cast<unsigned long long>(driver_handle_),
            process_id_);
        return true;
    }

    std::wstring device_path = device_names_um::get_device_path();
    std::wstring leaf = device_path;
    constexpr const wchar_t* dos_prefix = L"\\\\.\\";
    constexpr std::size_t dos_prefix_len = 4;
    if (leaf.size() > dos_prefix_len && leaf.compare(0, dos_prefix_len, dos_prefix) == 0) {
        leaf.erase(0, dos_prefix_len);
    }
    std::wstring global_dos_path = L"\\\\.\\Global\\";
    global_dos_path += leaf;
    std::wstring globalroot_device_path = L"\\\\?\\GLOBALROOT\\Device\\";
    globalroot_device_path += leaf;
    std::wstring globalroot_dos_path = L"\\\\?\\GLOBALROOT\\GLOBAL??\\";
    globalroot_dos_path += leaf;
    const std::wstring* candidates[] = {
        &device_path,
        &global_dos_path,
        &globalroot_device_path,
        &globalroot_dos_path,
    };
    diag::log_tagged_critical_fmt("comm-startup",
        "connect_enter local_pid=%lu local_tid=%lu path_chars=%zu candidates=%zu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<std::size_t>(device_path.size()),
        static_cast<std::size_t>(_countof(candidates)));

    DWORD first_error = ERROR_SUCCESS;
    DWORD last_error = ERROR_SUCCESS;
    std::size_t opened_index = static_cast<std::size_t>(-1);
    for (std::size_t i = 0; i < _countof(candidates); ++i) {
        const std::wstring& candidate = *candidates[i];
        driver_handle_ = CreateFileW(
            candidate.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        DWORD rw_error = is_connected() ? ERROR_SUCCESS : GetLastError();
        if (!is_connected()) {
            if (first_error == ERROR_SUCCESS) {
                first_error = rw_error;
            }
            last_error = rw_error;
            driver_handle_ = CreateFileW(
                candidate.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            DWORD ro_error = is_connected() ? ERROR_SUCCESS : GetLastError();
            if (!is_connected()) {
                if (first_error == ERROR_SUCCESS) {
                    first_error = ro_error;
                }
                last_error = ro_error;
            }
            diag::log_tagged_critical_fmt("comm-startup",
                "connect_candidate index=%zu chars=%zu rw_gle=%lu ro_gle=%lu opened=%u",
                i,
                static_cast<std::size_t>(candidate.size()),
                static_cast<unsigned long>(rw_error),
                static_cast<unsigned long>(ro_error),
                is_connected() ? 1u : 0u);
        } else {
            diag::log_tagged_critical_fmt("comm-startup",
                "connect_candidate index=%zu chars=%zu rw_gle=0 ro_gle=0 opened=1",
                i,
                static_cast<std::size_t>(candidate.size()));
        }

        if (is_connected()) {
            opened_index = i;
            if (rw_error != ERROR_SUCCESS) {
                diag::log_tagged_fmt("comm", "connect_rw_denied_fallback_read path_opened=1 rw_gle=%lu candidate=%zu",
                    static_cast<unsigned long>(rw_error),
                    i);
            }
            break;
        }
    }

    if (!is_connected()) {
        driver_handle_ = INVALID_HANDLE_VALUE;
        last_connect_error_ = last_error != ERROR_SUCCESS ? last_error : first_error;
        if (last_connect_error_ == ERROR_SUCCESS) {
            last_connect_error_ = ERROR_NO_SUCH_DEVICE;
        }
        diag::log_tagged_critical_fmt("comm-startup",
            "connect_failed gle=%lu first_gle=%lu handle=0x%llX candidates=%zu",
            static_cast<unsigned long>(last_connect_error_),
            static_cast<unsigned long>(first_error),
            reinterpret_cast<unsigned long long>(driver_handle_),
            static_cast<std::size_t>(_countof(candidates)));
        return false;
    }
    diag::log_tagged_critical_fmt("comm-startup",
        "connect_handle_opened handle=0x%llX candidate=%zu",
        reinterpret_cast<unsigned long long>(driver_handle_),
        opened_index);
    last_connect_error_ = 0;
    diag::log_tagged_critical_fmt("comm-startup",
        "connect_success handle=0x%llX",
        reinterpret_cast<unsigned long long>(driver_handle_));
    return true;
}
void voyager::device_t::disconnect() noexcept {
    const bool context_cleared = clear_process_context();

    if (is_connected()) {
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
    }

    kernel_dtb_ = 0;
    if (!context_cleared)
        SetLastError(ERROR_BUSY);
}

bool voyager::device_t::set_process_id(std::uint32_t pid) noexcept {
    const std::uint32_t prev_pid = process_id_;
    const std::uint64_t prev_shellcode = shellcode_address_;
    const std::uint64_t prev_spoof_gadget = spoof_gadget_;
    const std::uint64_t prev_base = base_address_;
    const std::uint64_t prev_dtb = dtb_;
    const std::uint64_t prev_kernel_dtb = kernel_dtb_;
    const DWORD prev_last_failed_tid = last_failed_tid_;
    const DWORD prev_last_hijacked_tid = last_hijacked_tid_;
    const bool connected = is_connected();
    const bool pid_changing = (prev_pid != 0 && prev_pid != pid);
    int shellcode_freed = 0;
    int shellcode_free_failed = 0;
    int shellcode_free_skipped_disconnected = 0;
    int shellcode_free_skipped_no_address = 0;

    bool prev_pid_alive = true;
    if (prev_pid != 0) {
        HANDLE prev_h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(prev_pid));
        if (prev_h == nullptr) {
            prev_pid_alive = false;
        } else {
            DWORD exit_code = 0;
            if (GetExitCodeProcess(prev_h, &exit_code) && exit_code != STILL_ACTIVE)
                prev_pid_alive = false;
            CloseHandle(prev_h);
        }
    }

    if (pid_changing) {
        if (prev_shellcode != 0) {
            if (connected && prev_pid_alive) {
                if (free_memory(prev_shellcode)) {
                    shellcode_freed = 1;
                } else {
                    shellcode_free_failed = 1;
                }
            } else {
                shellcode_free_skipped_disconnected = 1;
                shellcode_free_failed = 1;
            }
        } else {
            shellcode_free_skipped_no_address = 1;
        }
        if (shellcode_free_failed) {
            SetLastError(GetLastError() == ERROR_SUCCESS ? ERROR_BUSY : GetLastError());
            return false;
        }
        shellcode_address_ = 0;
        shellcode_pid_ = 0;
        shellcode_dtb_at_alloc_ = 0;
        spoof_gadget_ = 0;
        base_address_ = 0;
        dtb_ = 0;
        kernel_dtb_ = 0;
        last_failed_tid_ = 0;
        last_hijacked_tid_ = 0;
    } else if (prev_pid != pid && shellcode_address_ != 0) {
        if (connected) {
            if (free_memory(shellcode_address_)) {
                shellcode_freed = 1;
            } else {
                shellcode_free_failed = 1;
            }
        } else {
            shellcode_free_skipped_disconnected = 1;
            shellcode_free_failed = 1;
        }
        if (shellcode_free_failed) {
            SetLastError(GetLastError() == ERROR_SUCCESS ? ERROR_BUSY : GetLastError());
            return false;
        }
        shellcode_address_ = 0;
        shellcode_pid_ = 0;
        shellcode_dtb_at_alloc_ = 0;
    }

    process_id_ = pid;

    if (pid_changing || prev_pid != pid) {
        if (prev_pid != 0 && !prev_pid_alive) {
            diag::log_tagged_fmt("comm",
                "set_process_id_switch from_pid=%u to_pid=%u pid_changing=%d connected=%d shellcode_freed=%d shellcode_free_skipped_disconnected=%d shellcode_free_skipped_no_address=%d prev_pid_alive=0 prev_shellcode=0x%llX prev_spoof_gadget=0x%llX prev_base=0x%llX prev_dtb=0x%llX prev_kernel_dtb=0x%llX prev_last_failed_tid=%lu prev_last_hijacked_tid=%lu local_pid=%lu local_tid=%lu handle=0x%llX",
                prev_pid,
                pid,
                pid_changing ? 1 : 0,
                connected ? 1 : 0,
                shellcode_freed,
                shellcode_free_skipped_disconnected,
                shellcode_free_skipped_no_address,
                static_cast<unsigned long long>(prev_shellcode),
                static_cast<unsigned long long>(prev_spoof_gadget),
                static_cast<unsigned long long>(prev_base),
                static_cast<unsigned long long>(prev_dtb),
                static_cast<unsigned long long>(prev_kernel_dtb),
                static_cast<unsigned long>(prev_last_failed_tid),
                static_cast<unsigned long>(prev_last_hijacked_tid),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                reinterpret_cast<unsigned long long>(driver_handle_));
        } else {
            diag::log_tagged_critical_fmt("comm",
                "set_process_id_switch from_pid=%u to_pid=%u pid_changing=%d connected=%d shellcode_freed=%d shellcode_free_skipped_disconnected=%d shellcode_free_skipped_no_address=%d prev_pid_alive=%d prev_shellcode=0x%llX prev_spoof_gadget=0x%llX prev_base=0x%llX prev_dtb=0x%llX prev_kernel_dtb=0x%llX prev_last_failed_tid=%lu prev_last_hijacked_tid=%lu local_pid=%lu local_tid=%lu handle=0x%llX",
                prev_pid,
                pid,
                pid_changing ? 1 : 0,
                connected ? 1 : 0,
                shellcode_freed,
                shellcode_free_skipped_disconnected,
                shellcode_free_skipped_no_address,
                prev_pid_alive ? 1 : 0,
                static_cast<unsigned long long>(prev_shellcode),
                static_cast<unsigned long long>(prev_spoof_gadget),
                static_cast<unsigned long long>(prev_base),
                static_cast<unsigned long long>(prev_dtb),
                static_cast<unsigned long long>(prev_kernel_dtb),
                static_cast<unsigned long>(prev_last_failed_tid),
                static_cast<unsigned long>(prev_last_hijacked_tid),
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                reinterpret_cast<unsigned long long>(driver_handle_));
        }
    }
    return true;
}

bool voyager::device_t::clear_process_context() noexcept {
    if (shellcode_address_ != 0) {
        if (!is_connected() || !free_memory(shellcode_address_)) {
            return false;
        }
    }

    shellcode_address_ = 0;
    shellcode_pid_ = 0;
    shellcode_dtb_at_alloc_ = 0;
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    spoof_gadget_ = 0;
    last_failed_tid_ = 0;
    last_hijacked_tid_ = 0;
    kernel_dtb_ = 0;
    return true;
}

std::uint32_t voyager::device_t::find_process(const char* process_name) noexcept {
    if (!process_name || std::strlen(process_name) == 0 || std::strlen(process_name) >= MAX_PATH) {
        return 0;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    std::uint32_t found_pid = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            const size_t exe_len = std::wcslen(entry.szExeFile);
            const size_t target_len = std::strlen(process_name);

            if (exe_len == target_len) {
                bool match = true;
                for (std::size_t i = 0; i < exe_len; ++i) {
                    if (std::towlower(static_cast<wint_t>(entry.szExeFile[i])) !=
                        std::towlower(static_cast<wint_t>(static_cast<unsigned char>(process_name[i])))) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    found_pid = entry.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (found_pid != 0) {
        if (process_id_ != found_pid && !set_process_id(found_pid)) {
            return 0;
        }
    }

    return found_pid;
}
void voyager::device_t::solve_dtb() noexcept {
    if (process_id_ == 0) {
        dtb_ = 0;
        diag::log_tagged_fmt("comm",
            "solve_dtb_result pid=0 ok=0 gle=0 req_dtb=0x0 result_dtb=0x0 preserved=0 reason=zero_pid");
        return;
    }

    detail::dtb_solve req{};
    req.pid = process_id_;
    req.padding = 0;
    req.dtb = 0;

    SetLastError(ERROR_SUCCESS);
    const bool ok = send_request(ioctl_codes::DTB(), &req, sizeof(req));
    const DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && req.dtb != 0) {
        const std::uint64_t prior_dtb = dtb_;
        dtb_ = req.dtb;
        diag::log_tagged_fmt("comm",
            "solve_dtb_result pid=%u ok=1 gle=0 req_dtb=0x%llX result_dtb=0x%llX prior_dtb=0x%llX preserved=0",
            process_id_,
            static_cast<unsigned long long>(req.dtb),
            static_cast<unsigned long long>(dtb_),
            static_cast<unsigned long long>(prior_dtb));
        return;
    }
    if (!ok) {
        diag::log_tagged_fmt("comm",
            "solve_dtb_ioctl_failed_preserve_cached pid=%u prior_dtb=0x%llX gle=%lu req_dtb=0x%llX",
            process_id_,
            static_cast<unsigned long long>(dtb_),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(req.dtb));
        diag::log_tagged_fmt("comm",
            "solve_dtb_result pid=%u ok=0 gle=%lu req_dtb=0x%llX result_dtb=0x%llX prior_dtb=0x%llX preserved=1",
            process_id_,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(req.dtb),
            static_cast<unsigned long long>(dtb_),
            static_cast<unsigned long long>(dtb_));
        SetLastError(gle);
        return;
    }
    const std::uint64_t prior_dtb_clear = dtb_;
    diag::log_tagged_fmt("comm",
        "solve_dtb_kernel_returned_zero pid=%u prior_dtb=0x%llX gle=%lu req_dtb=0x0",
        process_id_,
        static_cast<unsigned long long>(prior_dtb_clear),
        static_cast<unsigned long>(gle));
    dtb_ = 0;
    diag::log_tagged_fmt("comm",
        "solve_dtb_result pid=%u ok=1 gle=0 req_dtb=0x0 result_dtb=0x0 prior_dtb=0x%llX preserved=0",
        process_id_,
        static_cast<unsigned long long>(prior_dtb_clear));
    SetLastError(ERROR_SUCCESS);
}

std::uint64_t voyager::device_t::solve_dtb_for_pid(std::uint32_t pid) noexcept {
    if (pid == 0 || !is_connected()) {
        diag::log_tagged_fmt("comm",
            "solve_dtb_for_pid_skip pid=%u connected=%d reason=%s",
            pid, is_connected() ? 1 : 0,
            pid == 0 ? "zero_pid" : "not_connected");
        return 0;
    }

    detail::dtb_solve req{};
    req.pid = pid;
    req.padding = 0;
    req.dtb = 0;

    SetLastError(ERROR_SUCCESS);
    const bool ok = send_request(ioctl_codes::DTB(), &req, sizeof(req));
    const DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && req.dtb != 0) {
        diag::log_tagged_fmt("comm",
            "solve_dtb_for_pid_result pid=%u ok=1 dtb=0x%llX gle=0",
            pid, static_cast<unsigned long long>(req.dtb));
        return req.dtb;
    }

    diag::log_tagged_fmt("comm",
        "solve_dtb_for_pid_result pid=%u ok=%d dtb=0x0 gle=%lu",
        pid, ok ? 1 : 0, static_cast<unsigned long>(gle));
    SetLastError(gle);
    return 0;
}

void voyager::device_t::solve_kernel_dtb() noexcept {
    detail::dtb_solve req{};
    req.pid = 4;
    req.padding = 0;
    req.dtb = 0;

    SetLastError(ERROR_SUCCESS);
    const bool ok = send_request(ioctl_codes::DTB(), &req, sizeof(req));
    const DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && req.dtb != 0) {
        const std::uint64_t prior_kernel_dtb = kernel_dtb_;
        kernel_dtb_ = req.dtb;
        diag::log_tagged_fmt("comm",
            "solve_kernel_dtb_result pid=4 ok=1 gle=0 req_dtb=0x%llX result_dtb=0x%llX prior_dtb=0x%llX preserved=0",
            static_cast<unsigned long long>(req.dtb),
            static_cast<unsigned long long>(kernel_dtb_),
            static_cast<unsigned long long>(prior_kernel_dtb));
        return;
    }
    if (gle == ERROR_INVALID_FUNCTION) {
        diag::log_tagged_fmt("comm",
            "solve_kernel_dtb_invalid_function_preserve_cached prior_kernel_dtb=0x%llX prior_dtb=0x%llX req_dtb=0x%llX",
            static_cast<unsigned long long>(kernel_dtb_),
            static_cast<unsigned long long>(dtb_),
            static_cast<unsigned long long>(req.dtb));
        diag::log_tagged_fmt("comm",
            "solve_kernel_dtb_result pid=4 ok=0 gle=%lu req_dtb=0x%llX result_dtb=0x%llX preserved=1",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(req.dtb),
            static_cast<unsigned long long>(kernel_dtb_));
        SetLastError(gle);
        return;
    }
    const std::uint64_t prior_kernel_dtb_clear = kernel_dtb_;
    if (dtb_ != 0) {
        kernel_dtb_ = dtb_;
    } else {
        kernel_dtb_ = 0;
    }
    diag::log_tagged_fmt("comm",
        "solve_kernel_dtb_result pid=4 ok=%d gle=%lu req_dtb=0x%llX result_dtb=0x%llX prior_dtb=0x%llX preserved=0 fallback_dtb=0x%llX",
        ok ? 1 : 0,
        static_cast<unsigned long>(gle),
        static_cast<unsigned long long>(req.dtb),
        static_cast<unsigned long long>(kernel_dtb_),
        static_cast<unsigned long long>(prior_kernel_dtb_clear),
        static_cast<unsigned long long>(dtb_));
    SetLastError(gle);
}

std::size_t voyager::device_t::transfer_physical_read(
    std::uint32_t pid,
    std::uint64_t dtb,
    std::uint64_t address,
    void* buffer,
    std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected() || dtb == 0 ||
        size - 1 > UINT64_MAX - address ||
        size - 1 > UINTPTR_MAX - reinterpret_cast<std::uintptr_t>(buffer)) {
        diag::log_tagged_fmt("comm",
            "phys_transfer_read_reject pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX buffer=%p connected=%d reason=invalid_args gle=%lu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            static_cast<unsigned long long>(dtb),
            buffer,
            is_connected() ? 1 : 0,
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }

    const std::size_t staging_size = (size < k_staged_physical_chunk_size)
        ? size
        : k_staged_physical_chunk_size;
    virtual_alloc_buffer_t staging(staging_size);
    if (!staging) {
        diag::log_tagged_fmt("comm",
            "phys_transfer_read_reject pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX staging_size=%zu reason=staging_alloc_failed gle=%lu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            static_cast<unsigned long long>(dtb),
            staging_size,
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }

    auto* destination = static_cast<std::uint8_t*>(buffer);
    std::size_t total_read = 0;
    const ULONGLONG start_ms = GetTickCount64();
    diag::log_tagged_fmt("comm",
        "phys_transfer_read_begin pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX staging_size=%zu ioctl=0x%08X",
        pid,
        process_id_,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(address),
        size,
        static_cast<unsigned long long>(dtb),
        staging_size,
        static_cast<unsigned int>(ioctl_codes::PHYS()));

    while (total_read < size) {
        const std::size_t chunk_size = (size - total_read < k_staged_physical_chunk_size)
            ? (size - total_read)
            : k_staged_physical_chunk_size;

        std::memset(staging.data(), 0, chunk_size);

        detail::physical_request req{};
        req.pid = pid;
        req.dtb = dtb;
        req.address = reinterpret_cast<void*>(address + total_read);
        req.buffer = staging.data();
        req.size = chunk_size;
        req.ret_size = 0;
        req.should_write = 0;
        std::memset(req.padding_2, 0, sizeof(req.padding_2));

        SetLastError(ERROR_SUCCESS);
        const bool sent = send_request(ioctl_codes::PHYS(), &req, sizeof(req));
        const DWORD gle = sent ? ERROR_SUCCESS : GetLastError();
        if (!sent) {
            diag::log_tagged_fmt("comm",
                "phys_transfer_read_chunk pid=%u attached_pid=%u tid=%lu va=0x%llX chunk=%zu offset=%zu sent=0 gle=%lu ret_size=%zu total=%zu dtb=0x%llX elapsed_ms=%llu",
                pid,
                process_id_,
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(address + total_read),
                chunk_size,
                total_read,
                static_cast<unsigned long>(gle),
                req.ret_size,
                total_read,
                static_cast<unsigned long long>(dtb),
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            break;
        }

        const std::size_t bytes_read = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        diag::log_tagged_fmt("comm",
            "phys_transfer_read_chunk pid=%u attached_pid=%u tid=%lu va=0x%llX chunk=%zu offset=%zu sent=1 gle=0 ret_size=%zu bytes=%zu total_before=%zu dtb=0x%llX elapsed_ms=%llu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address + total_read),
            chunk_size,
            total_read,
            req.ret_size,
            bytes_read,
            total_read,
            static_cast<unsigned long long>(dtb),
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        if (bytes_read == 0) {
            break;
        }

        std::memcpy(destination + total_read, staging.data(), bytes_read);
        total_read += bytes_read;

        if (bytes_read < chunk_size) {
            break;
        }
    }

    diag::log_tagged_fmt("comm",
        "phys_transfer_read_done pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX bytes=%zu complete=%d elapsed_ms=%llu",
        pid,
        process_id_,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(address),
        size,
        static_cast<unsigned long long>(dtb),
        total_read,
        total_read == size ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    return total_read;
}

std::size_t voyager::device_t::transfer_physical_write(
    std::uint32_t pid,
    std::uint64_t dtb,
    std::uint64_t address,
    const void* buffer,
    std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected() || dtb == 0 ||
        size - 1 > UINT64_MAX - address ||
        size - 1 > UINTPTR_MAX - reinterpret_cast<std::uintptr_t>(buffer)) {
        diag::log_tagged_fmt("comm",
            "phys_transfer_write_reject pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX buffer=%p connected=%d reason=invalid_args gle=%lu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            static_cast<unsigned long long>(dtb),
            buffer,
            is_connected() ? 1 : 0,
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }

    const std::size_t staging_size = (size < k_staged_physical_chunk_size)
        ? size
        : k_staged_physical_chunk_size;
    virtual_alloc_buffer_t staging(staging_size);
    if (!staging) {
        diag::log_tagged_fmt("comm",
            "phys_transfer_write_reject pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX staging_size=%zu reason=staging_alloc_failed gle=%lu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address),
            size,
            static_cast<unsigned long long>(dtb),
            staging_size,
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }

    const auto* source = static_cast<const std::uint8_t*>(buffer);
    std::size_t total_written = 0;
    const ULONGLONG start_ms = GetTickCount64();
    diag::log_tagged_fmt("comm",
        "phys_transfer_write_begin pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX staging_size=%zu ioctl=0x%08X",
        pid,
        process_id_,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(address),
        size,
        static_cast<unsigned long long>(dtb),
        staging_size,
        static_cast<unsigned int>(ioctl_codes::PHYS()));

    while (total_written < size) {
        const std::size_t chunk_size = (size - total_written < k_staged_physical_chunk_size)
            ? (size - total_written)
            : k_staged_physical_chunk_size;

        std::memcpy(staging.data(), source + total_written, chunk_size);

        detail::physical_request req{};
        req.pid = pid;
        req.dtb = dtb;
        req.address = reinterpret_cast<void*>(address + total_written);
        req.buffer = staging.data();
        req.size = chunk_size;
        req.ret_size = 0;
        req.should_write = 1;
        std::memset(req.padding_2, 0, sizeof(req.padding_2));

        SetLastError(ERROR_SUCCESS);
        const bool sent = send_request(ioctl_codes::PHYS(), &req, sizeof(req));
        const DWORD gle = sent ? ERROR_SUCCESS : GetLastError();
        if (!sent) {
            diag::log_tagged_fmt("comm",
                "phys_transfer_write_chunk pid=%u attached_pid=%u tid=%lu va=0x%llX chunk=%zu offset=%zu sent=0 gle=%lu ret_size=%zu total=%zu dtb=0x%llX elapsed_ms=%llu",
                pid,
                process_id_,
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(address + total_written),
                chunk_size,
                total_written,
                static_cast<unsigned long>(gle),
                req.ret_size,
                total_written,
                static_cast<unsigned long long>(dtb),
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            break;
        }

        const std::size_t bytes_written = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        diag::log_tagged_fmt("comm",
            "phys_transfer_write_chunk pid=%u attached_pid=%u tid=%lu va=0x%llX chunk=%zu offset=%zu sent=1 gle=0 ret_size=%zu bytes=%zu total_before=%zu dtb=0x%llX elapsed_ms=%llu",
            pid,
            process_id_,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(address + total_written),
            chunk_size,
            total_written,
            req.ret_size,
            bytes_written,
            total_written,
            static_cast<unsigned long long>(dtb),
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        if (bytes_written == 0) {
            break;
        }

        total_written += bytes_written;
        if (bytes_written < chunk_size) {
            break;
        }
    }

    diag::log_tagged_fmt("comm",
        "phys_transfer_write_done pid=%u attached_pid=%u tid=%lu va=0x%llX size=%zu dtb=0x%llX bytes=%zu complete=%d elapsed_ms=%llu",
        pid,
        process_id_,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(address),
        size,
        static_cast<unsigned long long>(dtb),
        total_written,
        total_written == size ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    return total_written;
}

std::size_t voyager::device_t::read_kernel_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected()) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }


    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        return 0;
    }
    std::size_t result = transfer_physical_read(4, use_dtb, address, buffer, size);
    return result;
}

std::size_t voyager::device_t::write_kernel_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected()) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        return 0;
    }

    std::size_t result = transfer_physical_write(4, use_dtb, address, buffer, size);
    return result;
}
std::uint64_t voyager::device_t::find_image() noexcept {
    std::uint64_t image_address = 0;

    detail::base_address_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.out_address = &image_address;

    if (send_request(ioctl_codes::BASE(), &req, sizeof(req))) {
        base_address_ = image_address;
    }

    return image_address;
}

std::size_t voyager::device_t::read_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    return transfer_physical_read(process_id_, dtb_, address, buffer, size);
}

std::size_t voyager::device_t::write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    return transfer_physical_write(process_id_, dtb_, address, buffer, size);
}

std::uint64_t voyager::device_t::allocate_memory(std::size_t size) noexcept {
    if (!is_connected() || process_id_ == 0 || size == 0) {
        return 0;
    }

    detail::alloc_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.size = size;
    req.allocated_address = 0;
    req.actual_size = 0;

    if (send_request(ioctl_codes::AM(), &req, sizeof(req)) && req.allocated_address != 0) {
        return req.allocated_address;
    }

    return 0;
}

bool voyager::device_t::free_memory(std::uint64_t address) noexcept {
    if (!is_connected() || process_id_ == 0 || address == 0) {
        return false;
    }

    detail::free_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.address = address;

    bool ok = send_request(ioctl_codes::FM(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::ensure_shellcode_allocated() noexcept {
    const std::uint32_t bound_pid = process_id_;
    const std::uint64_t bound_dtb = dtb_;
    if (bound_pid == 0 || bound_dtb == 0) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    if (shellcode_address_ != 0 &&
        shellcode_pid_ == bound_pid &&
        shellcode_dtb_at_alloc_ == bound_dtb) {
        return true;
    }

    const std::uint64_t prev_shellcode = shellcode_address_;
    const std::uint32_t prev_shellcode_pid = shellcode_pid_;
    const std::uint64_t prev_shellcode_dtb = shellcode_dtb_at_alloc_;
    const bool needs_realloc = shellcode_address_ != 0;

    if (shellcode_address_ != 0) {
        if (!is_connected() || !free_memory(shellcode_address_)) {
            SetLastError(GetLastError() == ERROR_SUCCESS ? ERROR_BUSY : GetLastError());
            return false;
        }
    }
    shellcode_address_ = 0;
    shellcode_pid_ = 0;
    shellcode_dtb_at_alloc_ = 0;

    const std::uint64_t addr = allocate_memory(detail::SHELLCODE_ALLOC_SIZE);
    if (addr == 0) {
        diag::log_tagged_critical_fmt("comm",
            "shellcode_alloc_failed pid=%u dtb=0x%llX prev_shellcode=0x%llX prev_shellcode_pid=%u prev_shellcode_dtb=0x%llX realloc=%d gle=%lu",
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(prev_shellcode),
            prev_shellcode_pid,
            static_cast<unsigned long long>(prev_shellcode_dtb),
            needs_realloc ? 1 : 0,
            static_cast<unsigned long>(GetLastError()));
        return false;
    }

    shellcode_address_ = addr;
    shellcode_pid_ = bound_pid;
    shellcode_dtb_at_alloc_ = bound_dtb;

    if (needs_realloc) {
        diag::log_tagged_critical_fmt("comm",
            "shellcode_realloc_for_pid_switch pid=%u dtb=0x%llX shellcode=0x%llX size=%llu prev_pid=%u prev_dtb=0x%llX prev_shellcode=0x%llX",
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(detail::SHELLCODE_ALLOC_SIZE),
            prev_shellcode_pid,
            static_cast<unsigned long long>(prev_shellcode_dtb),
            static_cast<unsigned long long>(prev_shellcode));
    }

    diag::log_tagged_critical_fmt("comm",
        "shellcode_alloc_bind pid=%u dtb=0x%llX shellcode=0x%llX size=%llu",
        bound_pid,
        static_cast<unsigned long long>(bound_dtb),
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(detail::SHELLCODE_ALLOC_SIZE));
    return true;
}

bool voyager::device_t::find_spoof_gadget() noexcept {
    if (spoof_gadget_ != 0) {
        return true;
    }

    if (base_address_ == 0 || dtb_ == 0) {
        return false;
    }

    std::uint8_t dos_header[64] = {};
    if (read_raw(base_address_, dos_header, sizeof(dos_header)) != sizeof(dos_header)) {
        return false;
    }

    if (dos_header[0] != 'M' || dos_header[1] != 'Z') {
        return false;
    }

    std::uint32_t e_lfanew = *reinterpret_cast<std::uint32_t*>(&dos_header[60]);
    if (e_lfanew > 0x1000) {
        return false;
    }

    std::uint8_t nt_headers[264] = {};
    if (read_raw(base_address_ + e_lfanew, nt_headers, sizeof(nt_headers)) != sizeof(nt_headers)) {
        return false;
    }

    if (nt_headers[0] != 'P' || nt_headers[1] != 'E') {
        return false;
    }

    std::uint32_t size_of_image = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 56]);
    std::uint32_t size_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 28]);
    std::uint32_t base_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 20]);

    if (size_of_code == 0 || size_of_code > size_of_image) {
        size_of_code = 0x100000;
        base_of_code = 0x1000;
    }

    std::uint64_t code_start = base_address_ + base_of_code;
    std::uint64_t search_size = (size_of_code > 0x200000) ? 0x200000 : size_of_code;

    constexpr std::size_t chunk_size = 0x10000;
    std::uint8_t buffer[chunk_size];

    for (std::uint64_t offset = 0; offset < search_size; offset += chunk_size - 16) {
        std::size_t to_read = chunk_size;
        if (offset + to_read > search_size) {
            to_read = static_cast<std::size_t>(search_size - offset);
        }

        if (read_raw(code_start + offset, buffer, to_read) != to_read) {
            continue;
        }

        for (std::size_t i = 0; i < to_read - 2; ++i) {
            if (buffer[i] == 0xFF && buffer[i + 1] == 0xE3) {
                spoof_gadget_ = code_start + offset + i;
                return true;
            }
        }
    }

    return true;
}

std::uint64_t voyager::device_t::find_gadget(const char* pattern, std::size_t pattern_size) noexcept {
    if (!pattern || pattern_size == 0 || base_address_ == 0 || dtb_ == 0) {
        return 0;
    }

    std::uint8_t dos_header[64] = {};
    if (read_raw(base_address_, dos_header, sizeof(dos_header)) != sizeof(dos_header)) {
        return 0;
    }

    std::uint32_t e_lfanew = *reinterpret_cast<std::uint32_t*>(&dos_header[60]);

    std::uint8_t nt_headers[264] = {};
    if (read_raw(base_address_ + e_lfanew, nt_headers, sizeof(nt_headers)) != sizeof(nt_headers)) {
        return 0;
    }

    std::uint32_t size_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 28]);
    std::uint32_t base_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 20]);

    std::uint64_t code_start = base_address_ + base_of_code;

    constexpr std::size_t chunk_size = 0x10000;
    std::uint8_t buffer[chunk_size];

    for (std::uint64_t offset = 0; offset < size_of_code; offset += chunk_size - pattern_size) {
        std::size_t to_read = chunk_size;
        if (offset + to_read > size_of_code) {
            to_read = static_cast<std::size_t>(size_of_code - offset);
        }

        if (read_raw(code_start + offset, buffer, to_read) != to_read) {
            continue;
        }

        for (std::size_t i = 0; i <= to_read - pattern_size; ++i) {
            bool found = true;
            for (std::size_t j = 0; j < pattern_size; ++j) {
                if (pattern[j] != '?' && buffer[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                    found = false;
                    break;
                }
            }
            if (found) {
                std::uint64_t gadget_addr = code_start + offset + i;
                return gadget_addr;
            }
        }
    }

    return 0;
}

namespace thread_hijack {
    typedef NTSTATUS(NTAPI* NtSuspendThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE, PCONTEXT);
    typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE, PCONTEXT);
    typedef NTSTATUS(NTAPI* NtOpenThread_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);
    typedef NTSTATUS(NTAPI* NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
    typedef NTSTATUS(NTAPI* NtYieldExecution_t)();
    typedef NTSTATUS(NTAPI* NtAlertThread_t)(HANDLE);
    typedef BOOL(WINAPI* CancelSynchronousIo_t)(HANDLE);

    inline NtSuspendThread_t pNtSuspendThread = nullptr;
    inline NtResumeThread_t pNtResumeThread = nullptr;
    inline NtGetContextThread_t pNtGetContextThread = nullptr;
    inline NtSetContextThread_t pNtSetContextThread = nullptr;
    inline NtOpenThread_t pNtOpenThread = nullptr;
    inline NtClose_t pNtClose = nullptr;
    inline NtDelayExecution_t pNtDelayExecution = nullptr;
    inline NtYieldExecution_t pNtYieldExecution = nullptr;
    inline NtAlertThread_t pNtAlertThread = nullptr;
    inline CancelSynchronousIo_t pCancelSynchronousIo = nullptr;
    inline volatile bool g_initialized = false;
    inline volatile std::uint64_t g_entropy_pool = 0;


    inline std::uint64_t g_ntdll_base = 0;
    inline std::uint64_t g_ntdll_size = 0;

    extern "C" NTSTATUS do_syscall_4(std::uint32_t syscall_idx, std::uint8_t* syscall_addr, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);

    __forceinline NTSTATUS syscall_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtOpenThread_idx) {
            return do_syscall_4(
                syscall_indices::NtOpenThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                static_cast<std::uint64_t>(DesiredAccess),
                reinterpret_cast<std::uint64_t>(ObjectAttributes),
                reinterpret_cast<std::uint64_t>(ClientId)
            );
        }
        return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    __forceinline NTSTATUS syscall_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtSuspendThread_idx) {
            return do_syscall_4(
                syscall_indices::NtSuspendThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(PreviousSuspendCount),
                0, 0
            );
        }
        return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }

    __forceinline NTSTATUS syscall_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtResumeThread_idx) {
            return do_syscall_4(
                syscall_indices::NtResumeThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(PreviousSuspendCount),
                0, 0
            );
        }
        return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
    }

    __forceinline NTSTATUS syscall_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtGetContextThread_idx) {
            return do_syscall_4(
                syscall_indices::NtGetContextThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(ThreadContext),
                0, 0
            );
        }
        return pNtGetContextThread(ThreadHandle, ThreadContext);
    }

    __forceinline NTSTATUS syscall_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtSetContextThread_idx) {
            return do_syscall_4(
                syscall_indices::NtSetContextThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(ThreadContext),
                0, 0
            );
        }
        return pNtSetContextThread(ThreadHandle, ThreadContext);
    }

    __forceinline NTSTATUS syscall_NtClose(HANDLE Handle) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtClose_idx) {
            return do_syscall_4(
                syscall_indices::NtClose_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(Handle),
                0, 0, 0
            );
        }
        return pNtClose(Handle);
    }

#pragma warning(push)
#pragma warning(disable: 4100)
    __forceinline NTSTATUS indirect_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        return syscall_NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    __forceinline NTSTATUS indirect_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        return syscall_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }

    __forceinline NTSTATUS indirect_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        return syscall_NtResumeThread(ThreadHandle, PreviousSuspendCount);
    }

    __forceinline NTSTATUS indirect_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        return syscall_NtGetContextThread(ThreadHandle, ThreadContext);
    }

    __forceinline NTSTATUS indirect_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        return syscall_NtSetContextThread(ThreadHandle, ThreadContext);
    }

    __forceinline NTSTATUS indirect_NtClose(HANDLE Handle) {
        return syscall_NtClose(Handle);
    }
#pragma warning(pop)

    __forceinline void collect_entropy() {
        std::uint64_t tsc = __rdtsc();
        std::uint64_t mix = tsc ^ (tsc >> 17);
        mix *= 0xff51afd7ed558ccdULL;
        mix ^= mix >> 33;
        mix *= 0xc4ceb9fe1a85ec53ULL;
        g_entropy_pool ^= mix;
    }

    __forceinline bool initialize() {
        if (g_initialized) return true;

        collect_entropy();

        if (!syscall_indices::resolve_syscall_indices()) {
            return false;
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        auto get_func = [&](const char* name) -> void* {
            void* addr = reinterpret_cast<void*>(GetProcAddress(ntdll, name));
            return addr;
        };

        pNtSuspendThread = (NtSuspendThread_t)get_func("NtSuspendThread");
        pNtResumeThread = (NtResumeThread_t)get_func("NtResumeThread");
        pNtGetContextThread = (NtGetContextThread_t)get_func("NtGetContextThread");
        pNtSetContextThread = (NtSetContextThread_t)get_func("NtSetContextThread");
        pNtOpenThread = (NtOpenThread_t)get_func("NtOpenThread");
        pNtClose = (NtClose_t)get_func("NtClose");
        pNtDelayExecution = (NtDelayExecution_t)get_func("NtDelayExecution");
        pNtYieldExecution = (NtYieldExecution_t)get_func("NtYieldExecution");
        pNtAlertThread = (NtAlertThread_t)get_func("NtAlertThread");


        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32) {
            pCancelSynchronousIo = reinterpret_cast<CancelSynchronousIo_t>(
                GetProcAddress(kernel32, "CancelSynchronousIo"));
        }


        {
            std::uint8_t* base = reinterpret_cast<std::uint8_t*>(ntdll);
            g_ntdll_base = reinterpret_cast<std::uint64_t>(base);
            g_ntdll_size = 0;

            __try {
                PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        g_ntdll_size = static_cast<std::uint64_t>(nt->OptionalHeader.SizeOfImage);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {

            }

            if (g_ntdll_size == 0) {
                g_ntdll_size = 0x200000;
            }
        }

        g_initialized = (pNtSuspendThread && pNtResumeThread && pNtGetContextThread &&
                        pNtSetContextThread && pNtOpenThread && pNtClose && pNtDelayExecution);

        collect_entropy();
        return g_initialized;
    }

    __forceinline void delay_random() {
        collect_entropy();
        if (pNtYieldExecution) {
            std::uint32_t spin = static_cast<std::uint32_t>((g_entropy_pool ^ __rdtsc()) & 0xF) + 1;
            while (spin--) {
                pNtYieldExecution();
            }
        }
    }

    __forceinline void delay_us(LONGLONG microseconds) {
        collect_entropy();
        LONGLONG jitter = static_cast<LONGLONG>((g_entropy_pool ^ __rdtsc()) & 0x3F);
        if (pNtDelayExecution) {
            LARGE_INTEGER interval;
            interval.QuadPart = -((microseconds + jitter) * 10);
            pNtDelayExecution(FALSE, &interval);
        }
    }

    __forceinline void scatter_timing() {
        collect_entropy();
        std::uint32_t pattern = static_cast<std::uint32_t>(g_entropy_pool & 0x7);
        switch (pattern) {
            case 0: _mm_pause(); break;
            case 1: delay_random(); break;
            case 2: _mm_pause(); _mm_pause(); break;
            case 3: if (pNtYieldExecution) pNtYieldExecution(); break;
            default: break;
        }
    }


    inline std::uint64_t g_tsc_ticks_per_us = 0;

    __forceinline void calibrate_tsc() {
        if (g_tsc_ticks_per_us != 0) return;

        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);


        LARGE_INTEGER qpc_start, qpc_end;
        QueryPerformanceCounter(&qpc_start);
        std::uint64_t tsc_start = __rdtsc();


        for (;;) {
            QueryPerformanceCounter(&qpc_end);
            if ((qpc_end.QuadPart - qpc_start.QuadPart) * 1000 >= freq.QuadPart)
                break;
            _mm_pause();
        }

        std::uint64_t tsc_end = __rdtsc();
        std::uint64_t tsc_elapsed = tsc_end - tsc_start;
        std::uint64_t us_elapsed = static_cast<std::uint64_t>(
            (qpc_end.QuadPart - qpc_start.QuadPart) * 1000000 / freq.QuadPart);

        if (us_elapsed > 0) {
            g_tsc_ticks_per_us = tsc_elapsed / us_elapsed;
        }
        if (g_tsc_ticks_per_us == 0) {
            g_tsc_ticks_per_us = 3000;
        }
    }

    __forceinline void delay_us_rdtsc(std::uint64_t microseconds) {
        if (g_tsc_ticks_per_us == 0) calibrate_tsc();
        std::uint64_t target = __rdtsc() + (microseconds * g_tsc_ticks_per_us);
        while (__rdtsc() < target) {
            _mm_pause();
        }
    }


    __forceinline void force_wake_thread(HANDLE thread_handle) {


        if (pCancelSynchronousIo) {
            pCancelSynchronousIo(thread_handle);
        }


        if (pNtAlertThread) {
            pNtAlertThread(thread_handle);
        }
    }


    __forceinline bool is_rip_in_ntdll(std::uint64_t rip) {
        if (g_ntdll_base == 0) return false;
        return (rip >= g_ntdll_base && rip < g_ntdll_base + g_ntdll_size);
    }
}

std::uint64_t voyager::device_t::call_function(std::uint64_t function_address, std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4) noexcept {
    const std::uint64_t call_id = g_remote_call_um_sequence.fetch_add(1, std::memory_order_acq_rel);
    const ULONGLONG call_start = GetTickCount64();
    remote_call_um_failure_counts_t failure_counts{};
    SetLastError(ERROR_SUCCESS);

    const std::uint32_t bound_pid = process_id_;
    const std::uint64_t bound_dtb = dtb_;
    const std::uint64_t bound_kernel_dtb = kernel_dtb_;
    const std::uint64_t bound_base = base_address_;
    std::uint64_t bound_shellcode = shellcode_address_;
    std::uint64_t bound_spoof = spoof_gadget_;
    RC_UM_DBG("call_function: ENTER target=0x%llX args=(0x%llX, 0x%llX, 0x%llX, 0x%llX)",
        function_address, arg1, arg2, arg3, arg4);
    diag::log_tagged_fmt("comm",
        "remote_call_um_entry call_id=%llu pid=%u dtb=0x%llX shellcode=0x%llX spoof=0x%llX fn=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX connected=%d local_pid=%lu local_tid=%lu",
        static_cast<unsigned long long>(call_id),
        bound_pid,
        static_cast<unsigned long long>(bound_dtb),
        static_cast<unsigned long long>(bound_shellcode),
        static_cast<unsigned long long>(bound_spoof),
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(arg1),
        static_cast<unsigned long long>(arg2),
        static_cast<unsigned long long>(arg3),
        static_cast<unsigned long long>(arg4),
        is_connected() ? 1 : 0,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    diag::log_tagged_fmt("comm",
        "remote_call_um_bind_snapshot call_id=%llu bound_pid=%u bound_dtb=0x%llX bound_kernel_dtb=0x%llX bound_base=0x%llX bound_shellcode=0x%llX bound_spoof=0x%llX tid=%lu",
        static_cast<unsigned long long>(call_id),
        bound_pid,
        static_cast<unsigned long long>(bound_dtb),
        static_cast<unsigned long long>(bound_kernel_dtb),
        static_cast<unsigned long long>(bound_base),
        static_cast<unsigned long long>(bound_shellcode),
        static_cast<unsigned long long>(bound_spoof),
        static_cast<unsigned long>(GetCurrentThreadId()));

    if (!is_connected() || bound_dtb == 0 || function_address == 0) {
        const DWORD reject_gle = function_address == 0 ? ERROR_INVALID_PARAMETER : ERROR_INVALID_HANDLE;
        SetLastError(reject_gle);
        RC_UM_DBG("call_function: ABORT connected=%d dtb=0x%llX func=0x%llX",
            is_connected() ? 1 : 0, bound_dtb, function_address);
        diag::log_tagged_fmt("comm",
            "remote_call_um_reject call_id=%llu reason=invalid_state connected=%d pid=%u dtb=0x%llX fn=0x%llX elapsed_ms=%llu gle=%lu",
            static_cast<unsigned long long>(call_id),
            is_connected() ? 1 : 0,
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            static_cast<unsigned long>(reject_gle));
        return 0;
    }

    if (!ensure_shellcode_allocated()) {
        DWORD err = GetLastError();
        if (err == ERROR_SUCCESS)
            err = ERROR_OUTOFMEMORY;
        SetLastError(err);
        RC_UM_DBG("call_function: ensure_shellcode_allocated FAILED");
        diag::log_tagged_fmt("comm",
            "remote_call_um_reject call_id=%llu reason=shellcode_alloc_failed pid=%u dtb=0x%llX fn=0x%llX elapsed_ms=%llu gle=%lu",
            static_cast<unsigned long long>(call_id),
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            static_cast<unsigned long>(err));
        return 0;
    }

    if (shellcode_pid_ != bound_pid || shellcode_dtb_at_alloc_ != bound_dtb) {
        diag::log_tagged_critical_fmt("comm",
            "remote_call_um_reject call_id=%llu reason=shellcode_pid_dtb_mismatch bound_pid=%u bound_dtb=0x%llX shellcode_pid=%u shellcode_dtb=0x%llX shellcode=0x%llX elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            shellcode_pid_,
            static_cast<unsigned long long>(shellcode_dtb_at_alloc_),
            static_cast<unsigned long long>(shellcode_address_),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        SetLastError(ERROR_INVALID_DATA);
        return 0;
    }

    {
        std::uint64_t probe_value = 0;
        SetLastError(ERROR_SUCCESS);
        const std::size_t probe_bytes = read_raw(shellcode_address_ + detail::CTX_EXEC_DONE,
                                                 &probe_value, sizeof(probe_value));
        if (probe_bytes != sizeof(probe_value)) {
            DWORD probe_gle = GetLastError();
            if (probe_gle == ERROR_SUCCESS)
                probe_gle = ERROR_INVALID_ADDRESS;
            diag::log_tagged_critical_fmt("comm",
                "remote_call_um_reject call_id=%llu reason=shellcode_unmapped_in_bound_dtb bound_pid=%u bound_dtb=0x%llX shellcode=0x%llX shellcode_pid=%u shellcode_dtb=0x%llX probe_bytes=%llu gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                bound_pid,
                static_cast<unsigned long long>(bound_dtb),
                static_cast<unsigned long long>(shellcode_address_),
                shellcode_pid_,
                static_cast<unsigned long long>(shellcode_dtb_at_alloc_),
                static_cast<unsigned long long>(probe_bytes),
                static_cast<unsigned long>(probe_gle),
                static_cast<unsigned long long>(GetTickCount64() - call_start));
            if (is_connected()) {
                free_memory(shellcode_address_);
            }
            shellcode_address_ = 0;
            shellcode_pid_ = 0;
            shellcode_dtb_at_alloc_ = 0;
            SetLastError(probe_gle);
            return 0;
        }
    }
    if (!find_spoof_gadget()) {
        DWORD err = GetLastError();
        if (err == ERROR_SUCCESS)
            err = ERROR_NOT_FOUND;
        SetLastError(err);
        RC_UM_DBG("call_function: find_spoof_gadget FAILED");
        diag::log_tagged_fmt("comm",
            "remote_call_um_reject call_id=%llu reason=spoof_gadget_missing pid=%u dtb=0x%llX shellcode=0x%llX fn=0x%llX elapsed_ms=%llu gle=%lu",
            static_cast<unsigned long long>(call_id),
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(shellcode_address_),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            static_cast<unsigned long>(err));
        return 0;
    }
    if (!thread_hijack::initialize()) {
        DWORD err = GetLastError();
        if (err == ERROR_SUCCESS)
            err = ERROR_NOT_READY;
        SetLastError(err);
        RC_UM_DBG("call_function: thread_hijack::initialize FAILED");
        diag::log_tagged_fmt("comm",
            "remote_call_um_reject call_id=%llu reason=thread_hijack_init_failed pid=%u dtb=0x%llX shellcode=0x%llX spoof=0x%llX fn=0x%llX elapsed_ms=%llu gle=%lu",
            static_cast<unsigned long long>(call_id),
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(shellcode_address_),
            static_cast<unsigned long long>(spoof_gadget_),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            static_cast<unsigned long>(err));
        return 0;
    }


    bound_shellcode = shellcode_address_;
    bound_spoof = spoof_gadget_;

    ntdll_base_ = thread_hijack::g_ntdll_base;
    ntdll_size_ = thread_hijack::g_ntdll_size;


    thread_hijack::calibrate_tsc();


    constexpr int MAX_ATTEMPTS = 5;
    DWORD blacklist[MAX_ATTEMPTS] = {};
    int blacklist_count = 0;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (attempt > 0) {
            RC_UM_DBG("call_function: RETRY attempt=%d/%d blacklisted=%d tids",
                attempt + 1, MAX_ATTEMPTS, blacklist_count);

            thread_hijack::delay_us(5000);
        }

        const std::uint32_t current_pid_for_check = process_id_;
        const std::uint64_t current_dtb_for_check = dtb_;
        const std::uint64_t current_base_for_check = base_address_;
        const bool bind_delta_pid = current_pid_for_check != bound_pid;
        const bool bind_delta_dtb = current_dtb_for_check != bound_dtb;
        const bool bind_delta_base = current_base_for_check != bound_base;
        diag::log_tagged_fmt("comm",
            "remote_call_um_bind_check call_id=%llu attempt=%d bound_pid=%u current_pid=%u bound_dtb=0x%llX current_dtb=0x%llX bound_base=0x%llX current_base=0x%llX delta_pid=%d delta_dtb=%d delta_base=%d tid=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt + 1,
            bound_pid,
            current_pid_for_check,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(current_dtb_for_check),
            static_cast<unsigned long long>(bound_base),
            static_cast<unsigned long long>(current_base_for_check),
            bind_delta_pid ? 1 : 0,
            bind_delta_dtb ? 1 : 0,
            bind_delta_base ? 1 : 0,
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        if (bind_delta_pid || bind_delta_dtb) {
            remote_call_um_set_failure("session_bind_changed_under_call", ERROR_OPERATION_ABORTED, 0, 0);
            SetLastError(ERROR_OPERATION_ABORTED);
            diag::log_tagged_fmt("comm",
                "remote_call_um_exit call_id=%llu completed=0 reason=session_bind_changed_under_call attempts=%d bound_pid=%u current_pid=%u bound_dtb=0x%llX current_dtb=0x%llX no_suitable_thread=%d request_send_failed=%d poll_timeout=%d poll_ioctl_failed=%d hijack_set_failed=%d context_restore_failed=%d thread_snapshot_failed=%d unknown=%d elapsed_ms=%llu gle=%lu",
                static_cast<unsigned long long>(call_id),
                attempt + 1,
                bound_pid,
                current_pid_for_check,
                static_cast<unsigned long long>(bound_dtb),
                static_cast<unsigned long long>(current_dtb_for_check),
                failure_counts.no_suitable_thread,
                failure_counts.request_send_failed,
                failure_counts.poll_timeout,
                failure_counts.poll_ioctl_failed,
                failure_counts.hijack_set_failed,
                failure_counts.context_restore_failed,
                failure_counts.thread_snapshot_failed,
                failure_counts.unknown,
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(ERROR_OPERATION_ABORTED));
            return 0;
        }

        bool attempt_completed = false;
        g_remote_call_um_attempt_diag = {};
        diag::log_tagged_fmt("comm",
            "remote_call_um_attempt_begin call_id=%llu attempt=%d max_attempts=%d pid=%u dtb=0x%llX shellcode=0x%llX spoof=0x%llX fn=0x%llX blacklist_count=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt + 1,
            MAX_ATTEMPTS,
            bound_pid,
            static_cast<unsigned long long>(bound_dtb),
            static_cast<unsigned long long>(bound_shellcode),
            static_cast<unsigned long long>(bound_spoof),
            static_cast<unsigned long long>(function_address),
            blacklist_count,
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        std::uint64_t result = call_function_attempt(
            call_id, attempt + 1, function_address, arg1, arg2, arg3, arg4,
            blacklist, blacklist_count,
            bound_pid, bound_dtb, bound_base, bound_shellcode, bound_spoof,
            attempt_completed);
        diag::log_tagged_fmt("comm",
            "remote_call_um_attempt_done call_id=%llu attempt=%d completed=%d result=0x%llX failure_class=%s failure_gle=%lu selected_tid=%u scanned=%u ntstatus=0x%08lX poll_failures=%d request_sent=%d hijack_set=%d last_failed_tid=%u blacklist_count=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt + 1,
            attempt_completed ? 1 : 0,
            static_cast<unsigned long long>(result),
            g_remote_call_um_attempt_diag.failure_class,
            static_cast<unsigned long>(remote_call_um_failure_gle(g_remote_call_um_attempt_diag)),
            g_remote_call_um_attempt_diag.tid,
            g_remote_call_um_attempt_diag.scanned,
            static_cast<unsigned long>(g_remote_call_um_attempt_diag.ntstatus),
            g_remote_call_um_attempt_diag.poll_failures,
            g_remote_call_um_attempt_diag.request_sent ? 1 : 0,
            g_remote_call_um_attempt_diag.hijack_set ? 1 : 0,
            last_failed_tid_,
            blacklist_count,
            static_cast<unsigned long long>(GetTickCount64() - call_start));

        if (attempt_completed) {
            SetLastError(ERROR_SUCCESS);
            diag::log_tagged_fmt("comm",
                "remote_call_um_exit call_id=%llu completed=1 reason=executed result=0x%llX attempts=%d no_suitable_thread=%d request_send_failed=%d poll_timeout=%d poll_ioctl_failed=%d hijack_set_failed=%d context_restore_failed=%d thread_snapshot_failed=%d unknown=%d elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                static_cast<unsigned long long>(result),
                attempt + 1,
                failure_counts.no_suitable_thread,
                failure_counts.request_send_failed,
                failure_counts.poll_timeout,
                failure_counts.poll_ioctl_failed,
                failure_counts.hijack_set_failed,
                failure_counts.context_restore_failed,
                failure_counts.thread_snapshot_failed,
                failure_counts.unknown,
                static_cast<unsigned long long>(GetTickCount64() - call_start));
            return result;
        }

        remote_call_um_note_failure(failure_counts, g_remote_call_um_attempt_diag.failure_class);


        if (last_failed_tid_ != 0 && blacklist_count < MAX_ATTEMPTS) {
            blacklist[blacklist_count++] = last_failed_tid_;
        }


        if (shellcode_address_ == 0) {
            if (!ensure_shellcode_allocated()) {
                DWORD err = GetLastError();
                if (err == ERROR_SUCCESS)
                    err = ERROR_OUTOFMEMORY;
                SetLastError(err);
                RC_UM_DBG("call_function: re-alloc FAILED on attempt %d", attempt + 1);
                diag::log_tagged_fmt("comm",
                    "remote_call_um_exit call_id=%llu completed=0 reason=realloc_failed attempts=%d no_suitable_thread=%d request_send_failed=%d poll_timeout=%d poll_ioctl_failed=%d hijack_set_failed=%d context_restore_failed=%d thread_snapshot_failed=%d unknown=%d elapsed_ms=%llu gle=%lu",
                    static_cast<unsigned long long>(call_id),
                    attempt + 1,
                    failure_counts.no_suitable_thread,
                    failure_counts.request_send_failed,
                    failure_counts.poll_timeout,
                    failure_counts.poll_ioctl_failed,
                    failure_counts.hijack_set_failed,
                    failure_counts.context_restore_failed,
                    failure_counts.thread_snapshot_failed,
                    failure_counts.unknown,
                    static_cast<unsigned long long>(GetTickCount64() - call_start),
                    static_cast<unsigned long>(err));
                return 0;
            }
            bound_shellcode = shellcode_address_;
        }
    }

    RC_UM_DBG("call_function: ALL %d attempts FAILED for target=0x%llX", MAX_ATTEMPTS, function_address);
    const DWORD final_gle = remote_call_um_failure_gle(g_remote_call_um_attempt_diag);
    SetLastError(final_gle);
    diag::log_tagged_fmt("comm",
        "remote_call_um_exit call_id=%llu completed=0 reason=attempts_exhausted attempts=%d final_failure_class=%s final_gle=%lu last_failed_tid=%u no_suitable_thread=%d request_send_failed=%d poll_timeout=%d poll_ioctl_failed=%d hijack_set_failed=%d context_restore_failed=%d thread_snapshot_failed=%d unknown=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        MAX_ATTEMPTS,
        g_remote_call_um_attempt_diag.failure_class,
        static_cast<unsigned long>(final_gle),
        last_failed_tid_,
        failure_counts.no_suitable_thread,
        failure_counts.request_send_failed,
        failure_counts.poll_timeout,
        failure_counts.poll_ioctl_failed,
        failure_counts.hijack_set_failed,
        failure_counts.context_restore_failed,
        failure_counts.thread_snapshot_failed,
        failure_counts.unknown,
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    return 0;
}


bool voyager::device_t::send_poll_request(void* input, DWORD input_size, std::uint64_t call_id, int iteration) const noexcept {
    auto* req = (input && input_size >= sizeof(detail::call_result_request))
        ? static_cast<detail::call_result_request*>(input)
        : nullptr;
    const std::uint64_t fp_before = req ? remote_result_request_fingerprint(*req) : 0;
    DWORD bytes_ret = 0;
    const ULONGLONG poll_start = GetTickCount64();
    if (iteration < 8 || (iteration % 512) == 0) {
        diag::log_tagged_fmt("comm",
            "remote_call_um_poll_ioctl_begin call_id=%llu iter=%d ioctl=0x%08X input_size=%u dtb=0x%llX result_addr=0x%llX fingerprint=0x%llX",
            static_cast<unsigned long long>(call_id),
            iteration,
            ioctl_codes::CR(),
            input_size,
            req ? static_cast<unsigned long long>(req->dtb) : 0ull,
            req ? static_cast<unsigned long long>(req->result_address) : 0ull,
            static_cast<unsigned long long>(fp_before));
    }
    SetLastError(ERROR_SUCCESS);
    BOOL ok = DeviceIoControl(
        driver_handle_,
        ioctl_codes::CR(),
        input, input_size,
        input, input_size,
        &bytes_ret, nullptr);

    if (ok && bytes_ret >= input_size) {
        if (iteration < 8 || (iteration % 512) == 0 || (req && req->completed != 0)) {
            diag::log_tagged_fmt("comm",
                "remote_call_um_poll_ioctl_done call_id=%llu iter=%d ok=1 bytes=%lu gle=0 elapsed_ms=%llu completed=%llu result=0x%llX fingerprint_before=0x%llX fingerprint_after=0x%llX",
                static_cast<unsigned long long>(call_id),
                iteration,
                static_cast<unsigned long>(bytes_ret),
                static_cast<unsigned long long>(GetTickCount64() - poll_start),
                req ? static_cast<unsigned long long>(req->completed) : 0ull,
                req ? static_cast<unsigned long long>(req->result) : 0ull,
                static_cast<unsigned long long>(fp_before),
                req ? static_cast<unsigned long long>(remote_result_request_fingerprint(*req)) : 0ull);
        }
        return true;
    }


    DWORD err = GetLastError();
    if (!ok && err != ERROR_IO_PENDING && err != ERROR_IO_INCOMPLETE) {
        bytes_ret = 0;
        ok = DeviceIoControl(
            driver_handle_,
            ioctl_codes::CR(),
            input, input_size,
            input, input_size,
            &bytes_ret, nullptr);

        if (ok && bytes_ret >= input_size) {
            if (iteration < 8 || (iteration % 512) == 0 || (req && req->completed != 0)) {
                diag::log_tagged_fmt("comm",
                    "remote_call_um_poll_ioctl_retry_done call_id=%llu iter=%d ok=1 bytes=%lu first_gle=%lu elapsed_ms=%llu completed=%llu result=0x%llX fingerprint_before=0x%llX fingerprint_after=0x%llX",
                    static_cast<unsigned long long>(call_id),
                    iteration,
                    static_cast<unsigned long>(bytes_ret),
                    static_cast<unsigned long>(err),
                    static_cast<unsigned long long>(GetTickCount64() - poll_start),
                    req ? static_cast<unsigned long long>(req->completed) : 0ull,
                    req ? static_cast<unsigned long long>(req->result) : 0ull,
                    static_cast<unsigned long long>(fp_before),
                    req ? static_cast<unsigned long long>(remote_result_request_fingerprint(*req)) : 0ull);
            }
            return true;
        }
    }

    diag::log_tagged_fmt("comm",
        "remote_call_um_poll_ioctl_failed call_id=%llu iter=%d ok=%d bytes=%lu gle=%lu elapsed_ms=%llu completed=%llu result=0x%llX fingerprint_before=0x%llX fingerprint_after=0x%llX",
        static_cast<unsigned long long>(call_id),
        iteration,
        ok ? 1 : 0,
        static_cast<unsigned long>(bytes_ret),
        static_cast<unsigned long>(GetLastError()),
        static_cast<unsigned long long>(GetTickCount64() - poll_start),
        req ? static_cast<unsigned long long>(req->completed) : 0ull,
        req ? static_cast<unsigned long long>(req->result) : 0ull,
        static_cast<unsigned long long>(fp_before),
        req ? static_cast<unsigned long long>(remote_result_request_fingerprint(*req)) : 0ull);
    return false;
}
std::uint64_t voyager::device_t::call_function_attempt(
    std::uint64_t call_id,
    int attempt_index,
    std::uint64_t function_address,
    std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4,
    const DWORD* blacklist, int blacklist_count,
    std::uint32_t bound_pid,
    std::uint64_t bound_dtb,
    std::uint64_t bound_base,
    std::uint64_t bound_shellcode,
    std::uint64_t bound_spoof,
    bool& out_completed) noexcept
{
    out_completed = false;
    const ULONGLONG attempt_start = GetTickCount64();

    RC_UM_DBG("call_function: shellcode_addr=0x%llX spoof_gadget=0x%llX dtb=0x%llX",
        bound_shellcode, bound_spoof, bound_dtb);
    diag::log_tagged_fmt("comm",
        "remote_call_um_attempt_entry call_id=%llu attempt=%d pid=%u dtb=0x%llX shellcode=0x%llX spoof=0x%llX fn=0x%llX blacklist_count=%d",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        bound_pid,
        static_cast<unsigned long long>(bound_dtb),
        static_cast<unsigned long long>(bound_shellcode),
        static_cast<unsigned long long>(bound_spoof),
        static_cast<unsigned long long>(function_address),
        blacklist_count);

    thread_hijack::scatter_timing();

    std::uint64_t context_base = bound_shellcode;

    thread_hijack::scatter_timing();


    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        remote_call_um_set_failure("thread_snapshot_failed", err, 0, 0);
        diag::log_tagged_fmt("comm",
            "remote_call_um_attempt_abort call_id=%llu attempt=%d reason=thread_snapshot_failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt_index,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        SetLastError(err);
        return 0;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);

    DWORD target_tid = 0;
    HANDLE target_thread = nullptr;

    DWORD current_tid = GetCurrentThreadId();
    std::uint32_t thread_scan_count = 0;
    constexpr std::uint32_t MAX_TARGET_THREAD_SCANS = 64;

    std::int32_t best_priority = -999;
    HANDLE best_thread = nullptr;
    DWORD best_tid = 0;
    ULONG best_prev_count = 0;
    CONTEXT best_ctx{};

    if (Thread32First(snapshot, &te)) {
        do {
            if (thread_scan_count >= MAX_TARGET_THREAD_SCANS) break;

            if (te.th32OwnerProcessID == bound_pid && te.th32ThreadID != current_tid) {

                if (last_failed_tid_ != 0 && te.th32ThreadID == last_failed_tid_) {
                    continue;
                }

                if (last_hijacked_tid_ != 0 && te.th32ThreadID == last_hijacked_tid_) {
                    continue;
                }


                bool is_blacklisted = false;
                for (int b = 0; b < blacklist_count; ++b) {
                    if (blacklist[b] == te.th32ThreadID) {
                        is_blacklisted = true;
                        break;
                    }
                }
                if (is_blacklisted) continue;

                thread_scan_count++;
                thread_hijack::scatter_timing();

                OBJECT_ATTRIBUTES objAttr = {};
                objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

                CLIENT_ID clientId = {};
                clientId.UniqueProcess = nullptr;
                clientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(te.th32ThreadID));

                HANDLE th = nullptr;
                NTSTATUS status = thread_hijack::indirect_NtOpenThread(
                    &th,
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_TERMINATE,
                    &objAttr,
                    &clientId
                );

                if (status >= 0 && th) {
                    thread_hijack::scatter_timing();

                    ULONG prev_count = 0;
                    status = thread_hijack::indirect_NtSuspendThread(th, &prev_count);

                    if (status >= 0) {
                        if (prev_count > 0) {
                            thread_hijack::indirect_NtResumeThread(th, nullptr);
                            thread_hijack::indirect_NtClose(th);
                            continue;
                        }
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_FULL;

                        thread_hijack::scatter_timing();

                        if (thread_hijack::indirect_NtGetContextThread(th, &ctx) >= 0) {
                            if (ctx.Rip > 0x10000 && ctx.Rip < 0x00007FFFFFFFFFFFULL &&
                                ctx.Rsp > 0x10000 && ctx.Rsp < 0x00007FFFFFFFFFFFULL &&
                                (ctx.Rsp & 0x7) == 0) {
                                std::int32_t priority = static_cast<std::int32_t>(te.tpBasePri);


                                bool in_ntdll = thread_hijack::is_rip_in_ntdll(ctx.Rip);


                                bool in_target = (bound_base != 0 &&
                                                  ctx.Rip >= bound_base &&
                                                  ctx.Rip < bound_base + 0x100000);

                                if (in_target) {
                                    priority += 20;
                                } else if (in_ntdll) {
                                    priority -= 20;
                                }

                                priority += 5;

                                if (priority > best_priority) {
                                    if (best_thread) {
                                        thread_hijack::indirect_NtResumeThread(best_thread, nullptr);
                                        thread_hijack::indirect_NtClose(best_thread);
                                    }
                                    best_priority = priority;
                                    best_thread = th;
                                    best_tid = te.th32ThreadID;
                                    best_prev_count = prev_count;
                                    best_ctx = ctx;
                                    continue;
                                }
                            }
                        }
                        thread_hijack::indirect_NtResumeThread(th, nullptr);
                    }
                    thread_hijack::indirect_NtClose(th);
                }
            }

            if ((thread_scan_count & 0xF) == 0) {
                thread_hijack::scatter_timing();
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);

    if (!best_thread || best_tid == 0) {
        remote_call_um_set_failure("no_suitable_thread", ERROR_NOT_FOUND, 0, thread_scan_count);
        SetLastError(ERROR_NOT_FOUND);
        RC_UM_DBG("call_function: NO suitable thread found (scanned %u)", thread_scan_count);
        diag::log_tagged_fmt("comm",
            "remote_call_um_attempt_abort call_id=%llu attempt=%d reason=no_suitable_thread scanned=%u blacklist_count=%d last_failed_tid=%u elapsed_ms=%llu gle=%lu",
            static_cast<unsigned long long>(call_id),
            attempt_index,
            thread_scan_count,
            blacklist_count,
            last_failed_tid_,
            static_cast<unsigned long long>(GetTickCount64() - attempt_start),
            static_cast<unsigned long>(ERROR_NOT_FOUND));
        return 0;
    }

    target_thread = best_thread;
    target_tid = best_tid;

    bool is_in_ntdll = thread_hijack::is_rip_in_ntdll(best_ctx.Rip);
    bool is_in_target = (bound_base != 0 && best_ctx.Rip >= bound_base && best_ctx.Rip < bound_base + 0x100000);
    RC_UM_DBG("call_function: SELECTED tid=%u rip=0x%llX rsp=0x%llX priority=%d in_ntdll=%d in_target=%d scanned=%u",
        target_tid, best_ctx.Rip, best_ctx.Rsp, best_priority, is_in_ntdll ? 1 : 0, is_in_target ? 1 : 0, thread_scan_count);
    diag::log_tagged_fmt("comm",
        "remote_call_um_selected_thread call_id=%llu attempt=%d pid=%u tid=%u scanned=%u priority=%d in_ntdll=%d in_target=%d rip=0x%llX rsp=0x%llX suspend_count=%lu thread_state=unknown wait_reason=unknown role=unknown prev_last_hijacked=%u elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        bound_pid,
        target_tid,
        thread_scan_count,
        best_priority,
        is_in_ntdll ? 1 : 0,
        is_in_target ? 1 : 0,
        static_cast<unsigned long long>(best_ctx.Rip),
        static_cast<unsigned long long>(best_ctx.Rsp),
        static_cast<unsigned long>(best_prev_count),
        last_hijacked_tid_,
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));
    g_remote_call_um_attempt_diag.selected = true;
    g_remote_call_um_attempt_diag.tid = target_tid;
    g_remote_call_um_attempt_diag.scanned = thread_scan_count;

    thread_hijack::scatter_timing();

    CONTEXT original_ctx = best_ctx;


    constexpr std::uint64_t EXEC_DONE_OFFSET = 0x50;
    constexpr std::uint64_t RESULT_VALUE_OFFSET = 0x30;
    constexpr std::uint64_t SAVED_RSP_OFFSET = 0x38;
    std::uint64_t zero_done = 0;
    const std::size_t done_write_bytes = write_raw(context_base + EXEC_DONE_OFFSET, &zero_done, sizeof(zero_done));
    const bool done_write_ok = done_write_bytes == sizeof(zero_done);
    diag::log_tagged_fmt("comm",
        "remote_call_um_context_slots call_id=%llu attempt=%d pid=%u tid=%u shellcode=0x%llX result_addr=0x%llX saved_rsp_addr=0x%llX completed_addr=0x%llX completed_zero_write=%d completed_zero_bytes=%zu elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        bound_pid,
        target_tid,
        static_cast<unsigned long long>(context_base),
        static_cast<unsigned long long>(context_base + RESULT_VALUE_OFFSET),
        static_cast<unsigned long long>(context_base + SAVED_RSP_OFFSET),
        static_cast<unsigned long long>(context_base + EXEC_DONE_OFFSET),
        done_write_ok ? 1 : 0,
        done_write_bytes,
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));
    if (!done_write_ok) {
        remote_call_um_set_failure("request_send_failed", ERROR_WRITE_FAULT, target_tid, thread_scan_count);
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        SetLastError(ERROR_WRITE_FAULT);
        return 0;
    }

    detail::remote_call_request req{};
    req.dtb = bound_dtb;
    req.target_function = function_address;
    req.shellcode_address = context_base;
    req.spoof_return = bound_spoof;
    req.arg1 = arg1;
    req.arg2 = arg2;
    req.arg3 = arg3;
    req.arg4 = arg4;
    req.result = 0;
    req.completed = 0;
    req.original_rip = original_ctx.Rip;
    req.trampoline_addr = 0;
    const std::uint64_t request_fp = remote_call_request_fingerprint(req);

    thread_hijack::scatter_timing();

    diag::log_tagged_fmt("comm",
        "remote_call_um_request_send_begin call_id=%llu attempt=%d pid=%u tid=%u ioctl=0x%08X dtb=0x%llX fn=0x%llX shellcode=0x%llX spoof=0x%llX original_rip=0x%llX fingerprint=0x%llX elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        bound_pid,
        target_tid,
        ioctl_codes::RC(),
        static_cast<unsigned long long>(req.dtb),
        static_cast<unsigned long long>(req.target_function),
        static_cast<unsigned long long>(req.shellcode_address),
        static_cast<unsigned long long>(req.spoof_return),
        static_cast<unsigned long long>(req.original_rip),
        static_cast<unsigned long long>(request_fp),
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));
    if (!send_request(ioctl_codes::RC(), &req, sizeof(req))) {
        DWORD send_gle = GetLastError();
        if (send_gle == ERROR_SUCCESS)
            send_gle = ERROR_IO_DEVICE;
        remote_call_um_set_failure("request_send_failed", send_gle, target_tid, thread_scan_count);
        diag::log_tagged_fmt("comm",
            "remote_call_um_request_send_done call_id=%llu attempt=%d ok=0 gle=%lu pid=%u tid=%u fingerprint=0x%llX elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt_index,
            static_cast<unsigned long>(send_gle),
            bound_pid,
            target_tid,
            static_cast<unsigned long long>(request_fp),
            static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        SetLastError(send_gle);
        return 0;
    }
    g_remote_call_um_attempt_diag.request_sent = true;
    diag::log_tagged_fmt("comm",
        "remote_call_um_request_send_done call_id=%llu attempt=%d ok=1 gle=0 pid=%u tid=%u code_entry=0x%llX trampoline=0x%llX fingerprint_before=0x%llX fingerprint_after=0x%llX elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        bound_pid,
        target_tid,
        static_cast<unsigned long long>(req.shellcode_address),
        static_cast<unsigned long long>(req.trampoline_addr),
        static_cast<unsigned long long>(request_fp),
        static_cast<unsigned long long>(remote_call_request_fingerprint(req)),
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));

    std::uint64_t code_entry = req.shellcode_address;


    CONTEXT hijack_ctx = original_ctx;
    hijack_ctx.Rip = code_entry;

    std::uint64_t shellcode_rsp = ((hijack_ctx.Rsp - 0x108) & ~0xFULL) + 0x8;
    hijack_ctx.Rsp = shellcode_rsp;

    RC_UM_DBG("call_function: HIJACK rip=0x%llX->0x%llX rsp=0x%llX->0x%llX",
        original_ctx.Rip, hijack_ctx.Rip, original_ctx.Rsp, hijack_ctx.Rsp);

    thread_hijack::scatter_timing();

    NTSTATUS set_status = thread_hijack::indirect_NtSetContextThread(target_thread, &hijack_ctx);
    if (set_status < 0) {
        remote_call_um_set_failure("hijack_set_failed", ERROR_ACCESS_DENIED, target_tid, thread_scan_count, static_cast<LONG>(set_status));
        RC_UM_DBG("call_function: NtSetContextThread FAILED status=0x%08X", (unsigned)set_status);
        diag::log_tagged_fmt("comm",
            "remote_call_um_hijack_set_failed call_id=%llu attempt=%d tid=%u status=0x%08X original_rip=0x%llX code_entry=0x%llX elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt_index,
            target_tid,
            static_cast<unsigned>(set_status),
            static_cast<unsigned long long>(original_ctx.Rip),
            static_cast<unsigned long long>(code_entry),
            static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }
    g_remote_call_um_attempt_diag.hijack_set = true;
    RC_UM_DBG("call_function: NtSetContextThread OK, resuming tid=%u", target_tid);
    last_hijacked_tid_ = target_tid;


    {
        ULONG resume_prev = 1;
        int resume_calls = 0;
        while (resume_prev > 0) {
            resume_prev = 0;
            thread_hijack::indirect_NtResumeThread(target_thread, &resume_prev);
            ++resume_calls;
        }
        if (resume_calls > 1) {
            diag::log_tagged_fmt("comm",
                "remote_call_um_resume_safety_net call_id=%llu attempt=%d tid=%u resume_calls=%d best_prev_count=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                resume_calls,
                static_cast<unsigned long>(best_prev_count),
                static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        }
    }


    if (is_in_ntdll || is_in_target) {
        thread_hijack::force_wake_thread(target_thread);
        RC_UM_DBG("call_function: force_wake sent to tid=%u (in_ntdll=%d in_target=%d)", target_tid, is_in_ntdll ? 1 : 0, is_in_target ? 1 : 0);
        diag::log_tagged_fmt("comm",
            "remote_call_um_force_wake_initial call_id=%llu attempt=%d tid=%u in_ntdll=%d in_target=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(call_id),
            attempt_index,
            target_tid,
            is_in_ntdll ? 1 : 0,
            is_in_target ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - attempt_start));
    }


    constexpr int MAX_WAIT_ITERATIONS = 2000;
    constexpr int FAST_POLL_THRESHOLD = 500;
    constexpr int MEDIUM_POLL_THRESHOLD = 2000;
    constexpr ULONGLONG MAX_POLL_DURATION_MS = 15000;

    std::uint64_t result = 0;
    bool completed = false;
    int consecutive_poll_failures = 0;

    RC_UM_DBG("call_function: POLLING start (max=%d iterations) ctx_base=0x%llX",
        MAX_WAIT_ITERATIONS, context_base);
    diag::log_tagged_fmt("comm",
        "remote_call_um_poll_begin call_id=%llu attempt=%d tid=%u max_iterations=%d context_base=0x%llX code_entry=0x%llX is_in_ntdll=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        target_tid,
        MAX_WAIT_ITERATIONS,
        static_cast<unsigned long long>(context_base),
        static_cast<unsigned long long>(code_entry),
        is_in_ntdll ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));



    int last_log_iteration = 0;
    bool alert_force_wake_attempted = false;
    for (int i = 0; i < MAX_WAIT_ITERATIONS && !completed; ++i) {

        if (GetTickCount64() - attempt_start > MAX_POLL_DURATION_MS) {
            diag::log_tagged_fmt("comm",
                "remote_call_um_poll_deadline_exceeded call_id=%llu attempt=%d tid=%u iter=%d elapsed_ms=%llu max_poll_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                i,
                static_cast<unsigned long long>(GetTickCount64() - attempt_start),
                static_cast<unsigned long long>(MAX_POLL_DURATION_MS));
            break;
        }


        if (i < FAST_POLL_THRESHOLD) {

            thread_hijack::delay_us_rdtsc(25);
        } else if (i < MEDIUM_POLL_THRESHOLD) {

            thread_hijack::delay_us_rdtsc(100);
        } else {

            std::uint64_t jitter = static_cast<std::uint64_t>((thread_hijack::g_entropy_pool ^ __rdtsc()) & 0x7F);
            thread_hijack::delay_us(static_cast<LONGLONG>(500 + jitter));
        }


        detail::call_result_request result_req{};
        result_req.dtb = bound_dtb;
        result_req.result_address = context_base;
        result_req.result = 0;
        result_req.completed = 0;

        if (send_poll_request(&result_req, sizeof(result_req), call_id, i)) {
            if (result_req.completed != 0) {
                result = result_req.result;
                completed = true;
                RC_UM_DBG("call_function: COMPLETED at iteration %d result=0x%llX", i, result);
                diag::log_tagged_fmt("comm",
                    "remote_call_um_poll_done call_id=%llu attempt=%d tid=%u iter=%d result=0x%llX completed=%llu elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    attempt_index,
                    target_tid,
                    i,
                    static_cast<unsigned long long>(result),
                    static_cast<unsigned long long>(result_req.completed),
                    static_cast<unsigned long long>(GetTickCount64() - attempt_start));
                break;
            }

            consecutive_poll_failures = 0;
            if (i - last_log_iteration >= 2000) {
                RC_UM_DBG("call_function: POLLING iter=%d still waiting (exec_done=0)", i);
                diag::log_tagged_fmt("comm",
                    "remote_call_um_poll_progress call_id=%llu attempt=%d tid=%u iter=%d completed=0 consecutive_failures=%d elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    attempt_index,
                    target_tid,
                    i,
                    consecutive_poll_failures,
                    static_cast<unsigned long long>(GetTickCount64() - attempt_start));
                last_log_iteration = i;
            }
        } else {


            ++consecutive_poll_failures;
            if (consecutive_poll_failures >= 16) {
                remote_call_um_set_failure("poll_ioctl_failed", GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_IO_DEVICE, target_tid, thread_scan_count, 0, consecutive_poll_failures);
                RC_UM_DBG("call_function: POLL FAILED 16x consecutively, iter=%d", i);
                diag::log_tagged_fmt("comm",
                    "remote_call_um_poll_failed call_id=%llu attempt=%d tid=%u iter=%d consecutive_failures=%d gle=%lu elapsed_ms=%llu",
                    static_cast<unsigned long long>(call_id),
                    attempt_index,
                    target_tid,
                    i,
                    consecutive_poll_failures,
                    static_cast<unsigned long>(remote_call_um_failure_gle(g_remote_call_um_attempt_diag)),
                    static_cast<unsigned long long>(GetTickCount64() - attempt_start));
                break;
            }
        }


        if ((i & 0xF) == 0) {
            if ((i & 0xFF) == 0 && i > 0) {
                thread_hijack::force_wake_thread(target_thread);
            }
            if (!alert_force_wake_attempted && GetTickCount64() - attempt_start > 500) {
                alert_force_wake_attempted = true;
                thread_hijack::force_wake_thread(target_thread);
                diag::log_tagged_fmt("comm",
                    "remote_call_um_force_wake_alert call_id=%llu attempt=%d tid=%u elapsed_ms=%llu reason=poll_500ms_no_completion",
                    static_cast<unsigned long long>(call_id),
                    attempt_index,
                    target_tid,
                    static_cast<unsigned long long>(GetTickCount64() - attempt_start));
            }
        }
    }


    thread_hijack::scatter_timing();

    ULONG suspend_count = 0;
    thread_hijack::indirect_NtSuspendThread(target_thread, &suspend_count);
    thread_hijack::scatter_timing();

    if (!completed) {
        if (std::strcmp(g_remote_call_um_attempt_diag.failure_class, "none") == 0)
            remote_call_um_set_failure("poll_timeout", ERROR_TIMEOUT, target_tid, thread_scan_count, 0, consecutive_poll_failures);
        RC_UM_DBG("call_function: TIMEOUT after %d iterations, tid=%u rip_was=0x%llX target=0x%llX",
            MAX_WAIT_ITERATIONS, target_tid, original_ctx.Rip, function_address);


        CONTEXT check_ctx{};
        check_ctx.ContextFlags = CONTEXT_FULL;
        if (thread_hijack::indirect_NtGetContextThread(target_thread, &check_ctx) >= 0) {
            RC_UM_DBG("call_function: TIMEOUT current_rip=0x%llX current_rsp=0x%llX (expected_rip=0x%llX)",
                check_ctx.Rip, check_ctx.Rsp, code_entry);
            diag::log_tagged_fmt("comm",
                "remote_call_um_timeout_context call_id=%llu attempt=%d tid=%u current_rip=0x%llX current_rsp=0x%llX expected_rip=0x%llX elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                static_cast<unsigned long long>(check_ctx.Rip),
                static_cast<unsigned long long>(check_ctx.Rsp),
                static_cast<unsigned long long>(code_entry),
                static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        }


        {
            std::uint64_t diag_done = read<std::uint64_t>(context_base + 0x50);
            std::uint64_t diag_ret = read<std::uint64_t>(context_base + 0x30);
            std::uint64_t diag_rsp = read<std::uint64_t>(context_base + 0x38);
            RC_UM_DBG("call_function: TIMEOUT diag exec_done=0x%llX ret_value=0x%llX saved_rsp=0x%llX",
                diag_done, diag_ret, diag_rsp);
            diag::log_tagged_fmt("comm",
                "remote_call_um_timeout call_id=%llu attempt=%d tid=%u iterations=%d exec_done=0x%llX ret_value=0x%llX saved_rsp=0x%llX target=0x%llX elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                MAX_WAIT_ITERATIONS,
                static_cast<unsigned long long>(diag_done),
                static_cast<unsigned long long>(diag_ret),
                static_cast<unsigned long long>(diag_rsp),
                static_cast<unsigned long long>(function_address),
                static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        }

        NTSTATUS restore_status = thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
        if (restore_status < 0) {
            remote_call_um_set_failure("context_restore_failed", ERROR_ACCESS_DENIED, target_tid, thread_scan_count, static_cast<LONG>(restore_status), consecutive_poll_failures);
            diag::log_tagged_fmt("comm",
                "remote_call_um_restore_failed call_id=%llu attempt=%d tid=%u status=0x%08X elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                static_cast<unsigned>(restore_status),
                static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        }
        last_failed_tid_ = target_tid;


    } else {
        RC_UM_DBG("call_function: SUCCESS result=0x%llX tid=%u target=0x%llX",
            result, target_tid, function_address);
        NTSTATUS restore_status = thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
        if (restore_status < 0) {
            remote_call_um_set_failure("context_restore_failed", ERROR_ACCESS_DENIED, target_tid, thread_scan_count, static_cast<LONG>(restore_status), consecutive_poll_failures);
            completed = false;
            result = 0;
            diag::log_tagged_fmt("comm",
                "remote_call_um_restore_failed call_id=%llu attempt=%d tid=%u status=0x%08X after_completed=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(call_id),
                attempt_index,
                target_tid,
                static_cast<unsigned>(restore_status),
                static_cast<unsigned long long>(GetTickCount64() - attempt_start));
        }
        if (completed) {
            last_failed_tid_ = 0;
            last_hijacked_tid_ = 0;
        } else {
            last_failed_tid_ = target_tid;
        }
    }

    {
        ULONG cleanup_resume_prev = 1;
        while (cleanup_resume_prev > 0) {
            cleanup_resume_prev = 0;
            thread_hijack::indirect_NtResumeThread(target_thread, &cleanup_resume_prev);
        }
    }
    thread_hijack::indirect_NtClose(target_thread);

    out_completed = completed;
    diag::log_tagged_fmt("comm",
        "remote_call_um_attempt_exit call_id=%llu attempt=%d completed=%d result=0x%llX tid=%u failure_class=%s failure_gle=%lu scanned=%u poll_failures=%d request_sent=%d hijack_set=%d last_failed_tid=%u elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        attempt_index,
        completed ? 1 : 0,
        static_cast<unsigned long long>(result),
        target_tid,
        completed ? "none" : g_remote_call_um_attempt_diag.failure_class,
        static_cast<unsigned long>(completed ? ERROR_SUCCESS : remote_call_um_failure_gle(g_remote_call_um_attempt_diag)),
        thread_scan_count,
        consecutive_poll_failures,
        g_remote_call_um_attempt_diag.request_sent ? 1 : 0,
        g_remote_call_um_attempt_diag.hijack_set ? 1 : 0,
        last_failed_tid_,
        static_cast<unsigned long long>(GetTickCount64() - attempt_start));
    SetLastError(completed ? ERROR_SUCCESS : remote_call_um_failure_gle(g_remote_call_um_attempt_diag));
    return result;
}

namespace {
}
bool voyager::device_t::send_request(DWORD control_code, void* input, DWORD input_size) const noexcept {
    if (!is_connected() || !input || input_size == 0) {
        diag::log_tagged_fmt("comm",
            "send_request REJECT ioctl=0x%08X input_size=%u connected=%d input=%p handle=0x%llX pid=%u",
            control_code, input_size, is_connected() ? 1 : 0, input,
            reinterpret_cast<unsigned long long>(driver_handle_), process_id_);
        SetLastError(!is_connected() ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER);
        return false;
    }

    DWORD bytes_returned = 0;
    const ULONGLONG ioctl_start = GetTickCount64();
    SetLastError(ERROR_SUCCESS);
    const BOOL ok = DeviceIoControl(
        driver_handle_,
        control_code,
        input,
        input_size,
        input,
        input_size,
        &bytes_returned,
        nullptr
    );
    const DWORD err = ok ? ERROR_SUCCESS : GetLastError();

    detail::raw_ioctl_telemetry trace{};
    trace.requested_code = control_code;
    trace.buffer_size = input_size;
    trace.bytes_returned = static_cast<std::uint32_t>(bytes_returned);
    trace.gle = ok ? 0u : err;
    trace.elapsed_ms = static_cast<std::uint64_t>(GetTickCount64() - ioctl_start);
    trace.local_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
    trace.local_tid = static_cast<std::uint32_t>(GetCurrentThreadId());
    trace.attached_pid = process_id_;
    trace.connected = 1u;
    trace.handle_value = reinterpret_cast<std::uint64_t>(driver_handle_);
    if (input != nullptr && input_size >= sizeof(std::uint32_t)) {
        std::memcpy(&trace.req_pid, input, sizeof(trace.req_pid));
    }
    if (input != nullptr && input_size >= sizeof(std::uint32_t) * 2u) {
        std::memcpy(&trace.req_tid, static_cast<const std::uint8_t*>(input) + sizeof(std::uint32_t), sizeof(trace.req_tid));
    }
    last_raw_ioctl_ = trace;

    if (!ok) {
        RC_UM_DBG("send_request FAILED ioctl=0x%08X input_size=%u err=%lu handle=0x%llX",
            control_code, input_size, err, reinterpret_cast<unsigned long long>(driver_handle_));
        diag::log_tagged_fmt("comm",
            "send_request FAILED ioctl=0x%08X input_size=%u bytes=%lu err=%lu handle=0x%llX pid=%u elapsed_ms=%llu",
            control_code, input_size, static_cast<unsigned long>(bytes_returned), err,
            reinterpret_cast<unsigned long long>(driver_handle_), process_id_,
            static_cast<unsigned long long>(GetTickCount64() - ioctl_start));
        detail::debug_ioctl_raw_log("FAILED", trace);
        SetLastError(err);
        return false;
    }

    return true;
}
bool voyager::device_t::get_thread_context(std::uint32_t tid, thread_context& ctx) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        RC_UM_DBG("TCTX get skip connected=%d pid=%u tid=%u", is_connected() ? 1 : 0, process_id_, tid);
        return false;
    }

    voyager::detail::thread_ctx_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.should_set = 0;
    req.register_mask = 0;
    const voyager::detail::thread_ctx_request req_initial_snapshot = req;
    DWORD tctx_ioctl = ioctl_codes::TCTX();
    diag::log_tagged_fmt("comm",
        "TCTX get begin pid=%u tid=%u ioctl=0x%08X connected=%d local_pid=%lu local_tid=%lu",
        process_id_,
        tid,
        tctx_ioctl,
        is_connected() ? 1 : 0,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    auto context_sane = [&req]() noexcept {
        return tctx_user_context_sane(req.rip, req.rsp, req.rflags);
    };


    const ULONGLONG initial_start = GetTickCount64();
    const char* context_provenance = "raw_tctx_ioctl";
    bool ok = send_request(tctx_ioctl, &req, sizeof(req));
    DWORD first_gle = ok ? ERROR_SUCCESS : GetLastError();
    const ULONGLONG initial_elapsed = GetTickCount64() - initial_start;
    bool sane = ok && context_sane();
    diag::log_tagged_fmt("comm",
        "TCTX get initial pid=%u tid=%u ok=%d gle=%lu sane=%d elapsed_ms=%llu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr7=0x%llX provenance=%s",
        process_id_,
        tid,
        ok ? 1 : 0,
        static_cast<unsigned long>(first_gle),
        sane ? 1 : 0,
        static_cast<unsigned long long>(initial_elapsed),
        static_cast<unsigned long long>(req.rip),
        tctx_address_class(req.rip),
        static_cast<unsigned long long>(req.rsp),
        tctx_address_class(req.rsp),
        static_cast<unsigned long long>(req.rflags),
        static_cast<unsigned long long>(req.dr7),
        context_provenance);
    if (!ok || !sane) {
        std::uint32_t prev_count = 0;
        const ULONGLONG suspend_start = GetTickCount64();
        bool suspended = suspend_thread(tid, &prev_count);
        DWORD suspend_gle = suspended ? ERROR_SUCCESS : GetLastError();
        const ULONGLONG suspend_elapsed = GetTickCount64() - suspend_start;
        if (suspended) {
            req = {};
            req.pid = process_id_;
            req.tid = tid;
            req.should_set = 0;
            req.register_mask = 0;
            const voyager::detail::thread_ctx_request req_suspended_snapshot = req;
            const ULONGLONG retry_start = GetTickCount64();
            ok = send_request(tctx_ioctl, &req, sizeof(req));
            context_provenance = "raw_tctx_ioctl_suspended_retry";
            first_gle = ok ? ERROR_SUCCESS : GetLastError();
            const ULONGLONG retry_elapsed = GetTickCount64() - retry_start;
            sane = ok && context_sane();
            std::uint32_t ignored = 0;
            const ULONGLONG resume_start = GetTickCount64();
            const bool resumed = resume_thread(tid, &ignored);
            const DWORD resume_gle = resumed ? ERROR_SUCCESS : GetLastError();
            const ULONGLONG resume_elapsed = GetTickCount64() - resume_start;
            diag::log_tagged_fmt("comm",
                "TCTX get suspended_retry pid=%u tid=%u suspended=1 suspend_gle=%lu suspend_prev=%u suspend_elapsed_ms=%llu retry_ok=%d retry_gle=%lu retry_sane=%d retry_elapsed_ms=%llu resume_ok=%d resume_gle=%lu resume_prev=%u resume_elapsed_ms=%llu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr7=0x%llX provenance=%s",
                process_id_,
                tid,
                static_cast<unsigned long>(suspend_gle),
                prev_count,
                static_cast<unsigned long long>(suspend_elapsed),
                ok ? 1 : 0,
                static_cast<unsigned long>(first_gle),
                sane ? 1 : 0,
                static_cast<unsigned long long>(retry_elapsed),
                resumed ? 1 : 0,
                static_cast<unsigned long>(resume_gle),
                ignored,
                static_cast<unsigned long long>(resume_elapsed),
                static_cast<unsigned long long>(req.rip),
                tctx_address_class(req.rip),
                static_cast<unsigned long long>(req.rsp),
                tctx_address_class(req.rsp),
                static_cast<unsigned long long>(req.rflags),
                static_cast<unsigned long long>(req.dr7),
                context_provenance);
        } else {
            RC_UM_DBG("TCTX get suspend_failed pid=%u tid=%u initial_ok=%d initial_sane=%d rip=0x%llX rsp=0x%llX rflags=0x%llX gle=%lu",
                process_id_,
                tid,
                ok ? 1 : 0,
                sane ? 1 : 0,
                req.rip,
                req.rsp,
                req.rflags,
                suspend_gle);
            diag::log_tagged_fmt("comm",
                "TCTX get suspend_failed pid=%u tid=%u initial_ok=%d initial_gle=%lu initial_sane=%d suspend_gle=%lu suspend_elapsed_ms=%llu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX provenance=raw_tctx_ioctl",
                process_id_,
                tid,
                ok ? 1 : 0,
                static_cast<unsigned long>(first_gle),
                sane ? 1 : 0,
                static_cast<unsigned long>(suspend_gle),
                static_cast<unsigned long long>(suspend_elapsed),
                static_cast<unsigned long long>(req.rip),
                tctx_address_class(req.rip),
                static_cast<unsigned long long>(req.rsp),
                tctx_address_class(req.rsp),
                static_cast<unsigned long long>(req.rflags));
        }
    }
    if (!ok) {
        RC_UM_DBG("TCTX get send_failed pid=%u tid=%u gle=%lu ioctl=0x%08X", process_id_, tid, first_gle, tctx_ioctl);
        diag::log_tagged_fmt("comm",
            "TCTX get final_failed pid=%u tid=%u reason=raw_send_failed gle=%lu ioctl=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX provenance=%s",
            process_id_,
            tid,
            static_cast<unsigned long>(first_gle),
            tctx_ioctl,
            static_cast<unsigned long long>(req.rip),
            tctx_address_class(req.rip),
            static_cast<unsigned long long>(req.rsp),
            tctx_address_class(req.rsp),
            static_cast<unsigned long long>(req.rflags),
            context_provenance);
        return false;
    }
    if (!sane) {
        const bool core_present = req.rip != 0 && req.rsp != 0 && req.rflags != 0;
        const DWORD reject_error = core_present ? ERROR_INVALID_ADDRESS : ERROR_INVALID_DATA;
        RC_UM_DBG("TCTX get invalid_user_context pid=%u tid=%u rip=0x%llX rsp=0x%llX rflags=0x%llX ioctl=0x%08X gle=%lu",
            process_id_,
            tid,
            req.rip,
            req.rsp,
            req.rflags,
            tctx_ioctl,
            reject_error);
        diag::log_tagged_fmt("comm",
            "TCTX get final_failed pid=%u tid=%u reason=%s gle=%lu ntstatus=0x%08X ioctl=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr7=0x%llX provenance=%s",
            process_id_,
            tid,
            core_present ? "kernel_or_noncanonical_context" : "zero_context",
            static_cast<unsigned long>(reject_error),
            core_present ? 0xC0000141u : 0xC0000001u,
            tctx_ioctl,
            static_cast<unsigned long long>(req.rip),
            tctx_address_class(req.rip),
            static_cast<unsigned long long>(req.rsp),
            tctx_address_class(req.rsp),
            static_cast<unsigned long long>(req.rflags),
            static_cast<unsigned long long>(req.dr7),
            context_provenance);
        SetLastError(reject_error);
        return false;
    }

    ctx.rax = req.rax; ctx.rbx = req.rbx; ctx.rcx = req.rcx; ctx.rdx = req.rdx;
    ctx.rsi = req.rsi; ctx.rdi = req.rdi; ctx.rbp = req.rbp; ctx.rsp = req.rsp;
    ctx.r8 = req.r8;   ctx.r9 = req.r9;   ctx.r10 = req.r10; ctx.r11 = req.r11;
    ctx.r12 = req.r12; ctx.r13 = req.r13; ctx.r14 = req.r14; ctx.r15 = req.r15;
    ctx.rip = req.rip; ctx.rflags = req.rflags;
    ctx.cs = req.cs;   ctx.ss = req.ss;
    ctx.dr0 = req.dr0; ctx.dr1 = req.dr1; ctx.dr2 = req.dr2; ctx.dr3 = req.dr3;
    ctx.dr6 = req.dr6; ctx.dr7 = req.dr7;
    ctx.kernel_gs_base = 0;
    diag::log_tagged_fmt("comm",
        "TCTX get final_ok pid=%u tid=%u rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr7=0x%llX ioctl=0x%08X provenance=%s",
        process_id_,
        tid,
        static_cast<unsigned long long>(ctx.rip),
        tctx_address_class(ctx.rip),
        static_cast<unsigned long long>(ctx.rsp),
        tctx_address_class(ctx.rsp),
        static_cast<unsigned long long>(ctx.rflags),
        static_cast<unsigned long long>(ctx.dr7),
        tctx_ioctl,
        context_provenance);

    return true;
}

bool voyager::device_t::set_thread_context(std::uint32_t tid, const thread_context& ctx, std::uint64_t register_mask) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        RC_UM_DBG("TCTX set skip connected=%d pid=%u tid=%u mask=0x%llX", is_connected() ? 1 : 0, process_id_, tid, register_mask);
        return false;
    }

    voyager::detail::thread_ctx_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.should_set = 1;
    req.register_mask = register_mask;

    req.rax = ctx.rax; req.rbx = ctx.rbx; req.rcx = ctx.rcx; req.rdx = ctx.rdx;
    req.rsi = ctx.rsi; req.rdi = ctx.rdi; req.rbp = ctx.rbp; req.rsp = ctx.rsp;
    req.r8 = ctx.r8;   req.r9 = ctx.r9;   req.r10 = ctx.r10; req.r11 = ctx.r11;
    req.r12 = ctx.r12; req.r13 = ctx.r13; req.r14 = ctx.r14; req.r15 = ctx.r15;
    req.rip = ctx.rip; req.rflags = ctx.rflags;
    req.cs = ctx.cs;   req.ss = ctx.ss;
    req.dr0 = ctx.dr0; req.dr1 = ctx.dr1; req.dr2 = ctx.dr2; req.dr3 = ctx.dr3;
    req.dr6 = ctx.dr6; req.dr7 = ctx.dr7;

    DWORD tctx_ioctl = ioctl_codes::TCTX();
    const voyager::detail::thread_ctx_request req_initial_snapshot = req;
    const bool debug_register_mask = (register_mask & ((1ULL << 18) | (1ULL << 19) | (1ULL << 20) | (1ULL << 21) | (1ULL << 22) | (1ULL << 23))) != 0;
    diag::log_tagged_fmt("comm",
        "TCTX set begin pid=%u tid=%u mask=0x%llX debug_register_mask=%d ioctl=0x%08X local_pid=%lu local_tid=%lu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        static_cast<unsigned long long>(register_mask),
        debug_register_mask ? 1 : 0,
        tctx_ioctl,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(ctx.rip),
        tctx_address_class(ctx.rip),
        static_cast<unsigned long long>(ctx.rsp),
        tctx_address_class(ctx.rsp),
        static_cast<unsigned long long>(ctx.rflags),
        static_cast<unsigned long long>(ctx.dr0),
        static_cast<unsigned long long>(ctx.dr1),
        static_cast<unsigned long long>(ctx.dr2),
        static_cast<unsigned long long>(ctx.dr3),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7));

    const ULONGLONG initial_start = GetTickCount64();
    bool ok = send_request(tctx_ioctl, &req, sizeof(req));
    DWORD first_gle = ok ? ERROR_SUCCESS : GetLastError();
    diag::log_tagged_fmt("comm",
        "TCTX set initial pid=%u tid=%u ok=%d gle=%lu mask=0x%llX debug_register_mask=%d elapsed_ms=%llu ioctl=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        ok ? 1 : 0,
        static_cast<unsigned long>(first_gle),
        static_cast<unsigned long long>(register_mask),
        debug_register_mask ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - initial_start),
        tctx_ioctl,
        static_cast<unsigned long long>(ctx.rip),
        tctx_address_class(ctx.rip),
        static_cast<unsigned long long>(ctx.rsp),
        tctx_address_class(ctx.rsp),
        static_cast<unsigned long long>(ctx.rflags),
        static_cast<unsigned long long>(ctx.dr0),
        static_cast<unsigned long long>(ctx.dr1),
        static_cast<unsigned long long>(ctx.dr2),
        static_cast<unsigned long long>(ctx.dr3),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7));
    if (!ok) {
        std::uint32_t prev_count = 0;
        const ULONGLONG suspend_start = GetTickCount64();
        bool suspended = suspend_thread(tid, &prev_count);
        DWORD suspend_gle = suspended ? ERROR_SUCCESS : GetLastError();
        const ULONGLONG suspend_elapsed = GetTickCount64() - suspend_start;
        if (suspended) {
            const voyager::detail::thread_ctx_request req_suspended_snapshot = req;
            const ULONGLONG retry_start = GetTickCount64();
            ok = send_request(tctx_ioctl, &req, sizeof(req));
            first_gle = ok ? ERROR_SUCCESS : GetLastError();
            std::uint32_t ignored = 0;
            const ULONGLONG resume_start = GetTickCount64();
            const bool resumed = resume_thread(tid, &ignored);
            const DWORD resume_gle = resumed ? ERROR_SUCCESS : GetLastError();
            diag::log_tagged_fmt("comm",
                "TCTX set suspended_retry pid=%u tid=%u suspended=1 suspend_gle=%lu suspend_prev=%u suspend_elapsed_ms=%llu retry_ok=%d retry_gle=%lu retry_elapsed_ms=%llu resume_ok=%d resume_gle=%lu resume_prev=%u resume_elapsed_ms=%llu mask=0x%llX debug_register_mask=%d ioctl=0x%08X rip=0x%llX rsp=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
                process_id_,
                tid,
                static_cast<unsigned long>(suspend_gle),
                prev_count,
                static_cast<unsigned long long>(suspend_elapsed),
                ok ? 1 : 0,
                static_cast<unsigned long>(first_gle),
                static_cast<unsigned long long>(GetTickCount64() - retry_start),
                resumed ? 1 : 0,
                static_cast<unsigned long>(resume_gle),
                ignored,
                static_cast<unsigned long long>(GetTickCount64() - resume_start),
                static_cast<unsigned long long>(register_mask),
                debug_register_mask ? 1 : 0,
                tctx_ioctl,
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                static_cast<unsigned long long>(ctx.dr0),
                static_cast<unsigned long long>(ctx.dr1),
                static_cast<unsigned long long>(ctx.dr2),
                static_cast<unsigned long long>(ctx.dr3),
                static_cast<unsigned long long>(ctx.dr6),
                static_cast<unsigned long long>(ctx.dr7));
        } else {
            RC_UM_DBG("TCTX set suspend_failed pid=%u tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX gle=%lu",
                process_id_,
                tid,
                register_mask,
                ctx.rip,
                ctx.rsp,
                suspend_gle);
            diag::log_tagged_fmt("comm",
                "TCTX set suspend_failed pid=%u tid=%u mask=0x%llX debug_register_mask=%d initial_gle=%lu suspend_gle=%lu suspend_elapsed_ms=%llu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr7=0x%llX ioctl=0x%08X",
                process_id_,
                tid,
                static_cast<unsigned long long>(register_mask),
                debug_register_mask ? 1 : 0,
                static_cast<unsigned long>(first_gle),
                static_cast<unsigned long>(suspend_gle),
                static_cast<unsigned long long>(suspend_elapsed),
                static_cast<unsigned long long>(ctx.rip),
                tctx_address_class(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                tctx_address_class(ctx.rsp),
                static_cast<unsigned long long>(ctx.rflags),
                static_cast<unsigned long long>(ctx.dr7),
                tctx_ioctl);
        }
    }
    if (!ok) {
        RC_UM_DBG("TCTX set send_failed pid=%u tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX gle=%lu ioctl=0x%08X",
            process_id_,
            tid,
            register_mask,
            ctx.rip,
            ctx.rsp,
            first_gle,
            tctx_ioctl);
    }
    diag::log_tagged_fmt("comm",
        "TCTX set final pid=%u tid=%u ok=%d gle=%lu mask=0x%llX debug_register_mask=%d ioctl=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        ok ? 1 : 0,
        static_cast<unsigned long>(first_gle),
        static_cast<unsigned long long>(register_mask),
        debug_register_mask ? 1 : 0,
        tctx_ioctl,
        static_cast<unsigned long long>(ctx.rip),
        tctx_address_class(ctx.rip),
        static_cast<unsigned long long>(ctx.rsp),
        tctx_address_class(ctx.rsp),
        static_cast<unsigned long long>(ctx.rflags),
        static_cast<unsigned long long>(ctx.dr0),
        static_cast<unsigned long long>(ctx.dr1),
        static_cast<unsigned long long>(ctx.dr2),
        static_cast<unsigned long long>(ctx.dr3),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7));
    return ok;
}

std::vector<voyager::device_t::thread_info> voyager::device_t::enumerate_threads() noexcept {
    std::vector<thread_info> result;
    if (!is_connected() || process_id_ == 0) {
        return result;
    }

    auto* req = static_cast<voyager::detail::thread_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::thread_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->pid = process_id_;
    req->thread_count = 0;

    if (send_request(ioctl_codes::TENUM(), req, sizeof(*req))) {
        result.reserve(req->thread_count);
        for (std::uint32_t i = 0; i < req->thread_count && i < voyager::detail::MAX_ENUM_THREADS; i++) {
            thread_info ti;
            ti.tid = req->entries[i].tid;
            ti.state = req->entries[i].state;
            ti.rip = req->entries[i].rip;
            result.push_back(ti);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::suspend_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    if (!is_connected() || tid == 0) {
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 0;
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::resume_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    if (!is_connected() || tid == 0) {
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 1;
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::query_thread_basic_information(std::uint32_t tid, detail::thread_query_information_request& info) noexcept {
    std::memset(&info, 0, sizeof(info));
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        return false;
    }

    info.pid = process_id_;
    info.tid = tid;
    info.info_class = 0;
    bool ok = send_request(ioctl_codes::TQIF(), &info, sizeof(info));
    return ok && info.status == 0;
}

bool voyager::device_t::terminate_thread(std::uint32_t tid, std::uint32_t exit_status) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        return false;
    }

    voyager::detail::terminate_thread_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.exit_status = exit_status;
    bool ok = send_request(ioctl_codes::TTERM(), &req, sizeof(req));
    return ok && req.status == 0;
}

bool voyager::device_t::close_process_handle(std::uint32_t pid, std::uint64_t handle_value) noexcept {
    if (!is_connected() || pid == 0 || handle_value == 0) {
        return false;
    }

    voyager::detail::close_handle_request req{};
    req.pid = pid;
    req.handle_value = handle_value;
    bool ok = send_request(ioctl_codes::HCLS(), &req, sizeof(req));
    return ok && req.status == 0;
}

bool voyager::device_t::query_memory(std::uint64_t address, memory_region_info& info) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::query_memory_request req{};
    req.pid = process_id_;
    req.address = address;

    if (!send_request(ioctl_codes::QM(), &req, sizeof(req))) {
        return false;
    }

    info.base = req.region_base;
    info.size = req.region_size;
    info.state = req.state;
    info.protect = req.protect;
    info.type = req.type;
    info.allocation_protect = req.allocation_protect;
    info.allocation_base = req.allocation_base;

    return true;
}

namespace {
    struct bounded_io_watchdog_ctx_t {
        HANDLE thread_handle;
        std::atomic<bool>* fired;
    };

    VOID CALLBACK bounded_io_watchdog_fire(PVOID arg, BOOLEAN ) {
        auto* ctx = static_cast<bounded_io_watchdog_ctx_t*>(arg);
        if (!ctx) return;
        if (ctx->fired) ctx->fired->store(true, std::memory_order_release);
        if (ctx->thread_handle && thread_hijack::pCancelSynchronousIo) {
            thread_hijack::pCancelSynchronousIo(ctx->thread_handle);
        }
    }
}

bool voyager::device_t::protect_memory_bounded(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect, std::uint32_t deadline_ms) noexcept {
    const ULONGLONG t0 = GetTickCount64();
    HANDLE self_thread = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
            &self_thread, THREAD_TERMINATE | THREAD_SET_CONTEXT | SYNCHRONIZE | 0x0001 ,
            FALSE, 0)) {
        self_thread = nullptr;
    }
    std::atomic<bool> cancel_fired{false};
    bounded_io_watchdog_ctx_t ctx{ self_thread, &cancel_fired };
    HANDLE timer = nullptr;
    if (deadline_ms > 0 && self_thread != nullptr) {
        if (!CreateTimerQueueTimer(&timer, nullptr, bounded_io_watchdog_fire, &ctx,
                deadline_ms, 0, WT_EXECUTEONLYONCE)) {
            timer = nullptr;
        }
    }
    diag::log_tagged_fmt("comm",
        "protect_memory_bounded_pre pid=%lu addr=0x%016llX size=0x%llX new=0x%08X deadline_ms=%u timer=%p self_thread=%p",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        deadline_ms,
        timer,
        self_thread);
    bool ok = protect_memory(address, size, new_protect, old_protect);
    DWORD post_err = ok ? ERROR_SUCCESS : GetLastError();
    if (timer) {
        DeleteTimerQueueTimer(nullptr, timer, INVALID_HANDLE_VALUE);
    }
    bool was_cancelled = cancel_fired.load(std::memory_order_acquire);
    if (self_thread) {
        CloseHandle(self_thread);
    }
    diag::log_tagged_fmt("comm",
        "protect_memory_bounded_post pid=%lu addr=0x%016llX size=0x%llX new=0x%08X ok=%d cancelled=%d err=%lu elapsed_ms=%llu deadline_ms=%u",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        ok ? 1 : 0,
        was_cancelled ? 1 : 0,
        static_cast<unsigned long>(post_err),
        static_cast<unsigned long long>(GetTickCount64() - t0),
        deadline_ms);
    if (!ok) {
        SetLastError(was_cancelled ? ERROR_OPERATION_ABORTED : post_err);
    }
    return ok;
}

void voyager::device_t::cancel_inflight_capture() noexcept {
    inflight_capture_cancel_pending_.store(true, std::memory_order_release);
    void* thread_handle = inflight_capture_thread_.load(std::memory_order_acquire);
    if (thread_handle && thread_hijack::pCancelSynchronousIo) {
        thread_hijack::pCancelSynchronousIo(static_cast<HANDLE>(thread_handle));
        diag::log_tagged_fmt("driver_comm_net",
            "cancel_inflight_capture fired thread_handle=%p", thread_handle);
    } else {
        diag::log_tagged_fmt("driver_comm_net",
            "cancel_inflight_capture noop thread_handle=%p pCancelSynchronousIo=%p",
            thread_handle, thread_hijack::pCancelSynchronousIo);
    }
}

std::vector<voyager::device_t::captured_packet> voyager::device_t::get_captured_packets_bounded(std::uint32_t max_packets, std::uint32_t deadline_ms) noexcept {
    const ULONGLONG t0 = GetTickCount64();
    HANDLE self_thread = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
            &self_thread, THREAD_TERMINATE | THREAD_SET_CONTEXT | SYNCHRONIZE | 0x0001,
            FALSE, 0)) {
        self_thread = nullptr;
    }
    inflight_capture_thread_.store(self_thread, std::memory_order_release);
    const std::uint64_t self_thread_low32 = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(self_thread)) & 0xFFFFFFFFull;
    diag::log_tagged_fmt("driver_comm_net",
        "inflight_capture_handle_store self_thread=%p handle_low32=0x%08llX inflight_thread_addr=%p",
        self_thread,
        static_cast<unsigned long long>(self_thread_low32),
        static_cast<const void*>(&inflight_capture_thread_));
    inflight_capture_cancel_pending_.store(false, std::memory_order_release);
    std::atomic<bool> deadline_fired{false};
    bounded_io_watchdog_ctx_t ctx{ self_thread, &deadline_fired };
    HANDLE timer = nullptr;
    if (deadline_ms > 0 && self_thread != nullptr) {
        if (!CreateTimerQueueTimer(&timer, nullptr, bounded_io_watchdog_fire, &ctx,
                deadline_ms, 0, WT_EXECUTEONLYONCE)) {
            timer = nullptr;
        }
    }
    diag::log_tagged_fmt("driver_comm_net",
        "get_captured_packets_bounded_pre max=%u deadline_ms=%u timer=%p self_thread=%p",
        max_packets, deadline_ms, timer, self_thread);
    std::vector<captured_packet> packets = get_captured_packets(max_packets);
    DWORD post_err = GetLastError();
    if (timer) {
        DeleteTimerQueueTimer(nullptr, timer, INVALID_HANDLE_VALUE);
    }
    bool cancelled_by_stop = inflight_capture_cancel_pending_.exchange(false, std::memory_order_acq_rel);
    bool cancelled_by_deadline = deadline_fired.load(std::memory_order_acquire) && !cancelled_by_stop;
    inflight_capture_thread_.store(nullptr, std::memory_order_release);
    if (self_thread) {
        CloseHandle(self_thread);
    }
    diag::log_tagged_fmt("driver_comm_net",
        "get_captured_packets_bounded_post max=%u deadline_ms=%u packets=%zu cancelled_by_stop=%d cancelled_by_deadline=%d err=%lu elapsed_ms=%llu",
        max_packets,
        deadline_ms,
        packets.size(),
        cancelled_by_stop ? 1 : 0,
        cancelled_by_deadline ? 1 : 0,
        static_cast<unsigned long>(post_err),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return packets;
}

bool voyager::device_t::protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect) noexcept {
    const DWORD pm_code = ioctl_codes::PM();
    RC_UM_DBG("protect_memory: ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X ioctl=0x%08X connected=%d",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        static_cast<unsigned int>(pm_code),
        is_connected() ? 1 : 0);

    if (!is_connected() || process_id_ == 0 || size == 0) {
        RC_UM_DBG("protect_memory: ABORT connected=%d pid=%lu size=0x%llX",
            is_connected() ? 1 : 0,
            static_cast<unsigned long>(process_id_),
            static_cast<unsigned long long>(size));
        return false;
    }

    if (address == 0) {
        RC_UM_DBG("protect_memory: ABORT address_zero");
        return false;
    }

    constexpr std::uint64_t kUserAddressMax = 0x00007FFFFFFFFFFFULL;
    if (address >= kUserAddressMax) {
        RC_UM_DBG("protect_memory: ABORT address_in_kernel_range addr=0x%016llX",
            static_cast<unsigned long long>(address));
        return false;
    }

    if (size > 0xFFFFFFFFULL) {
        RC_UM_DBG("protect_memory: ABORT size_too_large size=0x%llX",
            static_cast<unsigned long long>(size));
        return false;
    }

    const std::uint64_t end_addr = address + size;
    if (end_addr < address || end_addr >= kUserAddressMax) {
        RC_UM_DBG("protect_memory: ABORT range_overflow addr=0x%016llX size=0x%llX end=0x%016llX",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(end_addr));
        return false;
    }

    constexpr std::uint32_t kAllowedProtect =
        0x01u | 0x02u | 0x04u | 0x08u |
        0x10u | 0x20u | 0x40u | 0x80u |
        0x100u | 0x200u | 0x400u;
    if ((new_protect & ~kAllowedProtect) != 0 || new_protect == 0) {
        RC_UM_DBG("protect_memory: ABORT bad_protect_flags new=0x%08X mask=0x%08X",
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned int>(kAllowedProtect));
        return false;
    }

    voyager::detail::protect_memory_request req{};
    req.pid = process_id_;
    req.address = address;
    req.size = size;
    req.new_protect = new_protect;

    bool ok = send_request(pm_code, &req, sizeof(req));
    DWORD post_err = GetLastError();

    if (!ok) {
        RC_UM_DBG("protect_memory: send_request FAILED ioctl=0x%08X pid=%lu addr=0x%016llX size=0x%llX new=0x%08X gle=%lu",
            static_cast<unsigned int>(pm_code),
            static_cast<unsigned long>(process_id_),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned long>(post_err));
        return false;
    }

    if (old_protect) *old_protect = req.old_protect;

    RC_UM_DBG("protect_memory: OK pid=%lu addr=0x%016llX size=0x%llX new=0x%08X old=0x%08X",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        static_cast<unsigned int>(req.old_protect));
    return true;
}

std::vector<voyager::detail::region_entry> voyager::device_t::enumerate_memory_regions(std::uint64_t start, std::uint64_t end_addr, bool include_all) noexcept {
    std::vector<voyager::detail::region_entry> result;
    if (!is_connected() || process_id_ == 0) {
        return result;
    }

    auto* req = static_cast<voyager::detail::enum_regions_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::enum_regions_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->pid = process_id_;
    req->include_all = include_all ? 1 : 0;
    req->start_address = start;
    req->max_address = end_addr;
    req->region_count = 0;

    if (send_request(ioctl_codes::ER(), req, sizeof(*req))) {
        result.reserve(req->region_count);
        for (std::uint32_t i = 0; i < req->region_count && i < voyager::detail::MAX_ENUM_REGIONS; i++) {
            result.push_back(req->entries[i]);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::read_peb(peb_info& info) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::read_peb_request req{};
    req.pid = process_id_;

    if (!send_request(ioctl_codes::RPEB(), &req, sizeof(req))) {
        return false;
    }

    info.peb_address = req.peb_address;
    info.image_base = req.image_base;
    info.being_debugged = req.being_debugged;
    info.nt_global_flag = req.nt_global_flag;
    info.ldr_address = req.ldr_address;
    info.process_heap = req.process_heap;
    info.number_of_heaps = req.number_of_heaps;
    info.max_heaps = req.max_heaps;
    info.process_heaps = req.process_heaps;

    return true;
}

bool voyager::device_t::spoof_debug_flags(std::uint32_t* result_flags) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::spoof_debug_request req{};
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::SDF(), &req, sizeof(req));
    if (ok && result_flags) *result_flags = req.result_flags;
    return ok;
}

std::uint64_t voyager::device_t::resolve_export(std::uint64_t module_base, const char* export_name) noexcept {
    if (!is_connected() || dtb_ == 0 || module_base == 0 || !export_name) {
        return 0;
    }

    voyager::detail::module_export_request req{};
    req.dtb = dtb_;
    req.module_base = module_base;
    std::memset(req.export_name, 0, sizeof(req.export_name));
    for (int i = 0; i < 127 && export_name[i]; i++) {
        req.export_name[i] = export_name[i];
    }

    if (!send_request(ioctl_codes::MEX(), &req, sizeof(req))) {
        return 0;
    }
    return req.resolved_address;
}

std::uint64_t voyager::device_t::virtual_to_physical(std::uint64_t virtual_address) noexcept {
    if (!is_connected() || dtb_ == 0 || virtual_address == 0) {
        return 0;
    }

    voyager::detail::virt_to_phys_request req{};
    req.dtb = dtb_;
    req.virtual_address = virtual_address;

    if (!send_request(ioctl_codes::V2P(), &req, sizeof(req))) {
        return 0;
    }
    return req.physical_address;
}

bool voyager::device_t::query_ssdt(ssdt_info& info) noexcept {
    std::memset(&info, 0, sizeof(info));
    if (!is_connected()) {
        return false;
    }

    voyager::detail::ssdt_query_request req{};
    if (!send_request(ioctl_codes::SSDT(), &req, sizeof(req))) {
        return false;
    }

    info.lstar = req.lstar;
    info.descriptor_address = req.descriptor_address;
    info.service_table = req.service_table;
    info.counter_table = req.counter_table;
    info.argument_table = req.argument_table;
    info.service_limit = req.service_limit;
    info.flags = req.flags;
    return info.descriptor_address != 0 && info.service_table != 0 && info.service_limit != 0;
}

bool voyager::device_t::set_hardware_breakpoint(std::uint32_t tid, int index, std::uint64_t address, int type, int size) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        return false;
    }

    const ULONGLONG begin = GetTickCount64();
    diag::log_tagged_fmt("comm",
        "HWBP set begin pid=%u tid=%u index=%d address=0x%llX type=%d size=%d connected=%d",
        process_id_,
        tid,
        index,
        static_cast<unsigned long long>(address),
        type,
        size,
        is_connected() ? 1 : 0);

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("comm",
            "HWBP set get_before_failed pid=%u tid=%u index=%d address=0x%llX type=%d size=%d gle=%lu elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long long>(address),
            type,
            size,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }
    const thread_context before = ctx;
    diag::log_tagged_fmt("comm",
        "HWBP set before pid=%u tid=%u index=%d address=0x%llX type=%d size=%d rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        index,
        static_cast<unsigned long long>(address),
        type,
        size,
        static_cast<unsigned long long>(before.rip),
        tctx_address_class(before.rip),
        static_cast<unsigned long long>(before.rsp),
        tctx_address_class(before.rsp),
        static_cast<unsigned long long>(before.rflags),
        static_cast<unsigned long long>(before.dr0),
        static_cast<unsigned long long>(before.dr1),
        static_cast<unsigned long long>(before.dr2),
        static_cast<unsigned long long>(before.dr3),
        static_cast<unsigned long long>(before.dr6),
        static_cast<unsigned long long>(before.dr7));

    switch (index) {
        case 0: ctx.dr0 = address; break;
        case 1: ctx.dr1 = address; break;
        case 2: ctx.dr2 = address; break;
        case 3: ctx.dr3 = address; break;
    }


    ctx.dr6 = 0;


    std::uint64_t dr7 = ctx.dr7;
    constexpr std::uint64_t kDr7UserMask = 0xFFFF0355ULL;
    constexpr std::uint64_t kDr7GlobalEnableMask = 0xAAULL;
    dr7 &= kDr7UserMask;
    dr7 &= ~kDr7GlobalEnableMask;


    int rw_shift = 16 + index * 4;
    int len_shift = 18 + index * 4;
    dr7 &= ~(3ULL << (index * 2));
    dr7 &= ~(3ULL << rw_shift);
    dr7 &= ~(3ULL << len_shift);


    dr7 |= (1ULL << (index * 2));


    std::uint64_t rw_val = static_cast<std::uint64_t>(type) & 3;
    dr7 |= (rw_val << rw_shift);


    std::uint64_t len_val = static_cast<std::uint64_t>(size) & 3;
    dr7 |= (len_val << len_shift);

    ctx.dr7 = dr7;

    std::uint64_t mask = (1ULL << 22) | (1ULL << 23);
    mask |= (1ULL << (18 + index));

    const ULONGLONG set_start = GetTickCount64();
    if (!set_thread_context(tid, ctx, mask)) {
        DWORD gle = GetLastError();
        RC_UM_DBG("set_hardware_breakpoint: set_context_failed pid=%u tid=%u index=%d address=0x%llX type=%d size=%d dr7=0x%llX mask=0x%llX",
            process_id_,
            tid,
            index,
            address,
            type,
            size,
            ctx.dr7,
            mask);
        diag::log_tagged_fmt("comm",
            "HWBP set context_failed pid=%u tid=%u index=%d address=0x%llX type=%d size=%d gle=%lu mask=0x%llX before_rip=0x%llX before_rsp=0x%llX before_dr0=0x%llX before_dr1=0x%llX before_dr2=0x%llX before_dr3=0x%llX before_dr6=0x%llX before_dr7=0x%llX requested_dr0=0x%llX requested_dr1=0x%llX requested_dr2=0x%llX requested_dr3=0x%llX requested_dr6=0x%llX requested_dr7=0x%llX set_elapsed_ms=%llu total_elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long long>(address),
            type,
            size,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(mask),
            static_cast<unsigned long long>(before.rip),
            static_cast<unsigned long long>(before.rsp),
            static_cast<unsigned long long>(before.dr0),
            static_cast<unsigned long long>(before.dr1),
            static_cast<unsigned long long>(before.dr2),
            static_cast<unsigned long long>(before.dr3),
            static_cast<unsigned long long>(before.dr6),
            static_cast<unsigned long long>(before.dr7),
            static_cast<unsigned long long>(ctx.dr0),
            static_cast<unsigned long long>(ctx.dr1),
            static_cast<unsigned long long>(ctx.dr2),
            static_cast<unsigned long long>(ctx.dr3),
            static_cast<unsigned long long>(ctx.dr6),
            static_cast<unsigned long long>(ctx.dr7),
            static_cast<unsigned long long>(GetTickCount64() - set_start),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }
    const DWORD set_gle = GetLastError();
    diag::log_tagged_fmt("comm",
        "HWBP set context_ok pid=%u tid=%u index=%d address=0x%llX type=%d size=%d gle=%lu mask=0x%llX requested_dr0=0x%llX requested_dr1=0x%llX requested_dr2=0x%llX requested_dr3=0x%llX requested_dr6=0x%llX requested_dr7=0x%llX set_elapsed_ms=%llu",
        process_id_,
        tid,
        index,
        static_cast<unsigned long long>(address),
        type,
        size,
        static_cast<unsigned long>(set_gle),
        static_cast<unsigned long long>(mask),
        static_cast<unsigned long long>(ctx.dr0),
        static_cast<unsigned long long>(ctx.dr1),
        static_cast<unsigned long long>(ctx.dr2),
        static_cast<unsigned long long>(ctx.dr3),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7),
        static_cast<unsigned long long>(GetTickCount64() - set_start));

    thread_context verify{};
    if (!get_thread_context(tid, verify)) {
        DWORD gle = GetLastError();
        RC_UM_DBG("set_hardware_breakpoint: verify_get_failed pid=%u tid=%u index=%d address=0x%llX",
            process_id_,
            tid,
            index,
            address);
        diag::log_tagged_fmt("comm",
            "HWBP set verify_get_failed pid=%u tid=%u index=%d address=0x%llX type=%d size=%d gle=%lu total_elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long long>(address),
            type,
            size,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }

    std::uint64_t verify_addr = 0;
    switch (index) {
        case 0: verify_addr = verify.dr0; break;
        case 1: verify_addr = verify.dr1; break;
        case 2: verify_addr = verify.dr2; break;
        case 3: verify_addr = verify.dr3; break;
    }
    const bool enabled = (verify.dr7 & (1ULL << (index * 2))) != 0;
    const bool address_ok = verify_addr == address;
    const bool dr7_ok = (verify.dr7 & ((3ULL << (16 + index * 4)) | (3ULL << (18 + index * 4)))) ==
        (ctx.dr7 & ((3ULL << (16 + index * 4)) | (3ULL << (18 + index * 4))));
    diag::log_tagged_fmt("comm",
        "HWBP set verify pid=%u tid=%u index=%d address=0x%llX type=%d size=%d enabled=%d address_ok=%d dr7_ok=%d verify_addr=0x%llX rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX expected_dr7=0x%llX total_elapsed_ms=%llu",
        process_id_,
        tid,
        index,
        static_cast<unsigned long long>(address),
        type,
        size,
        enabled ? 1 : 0,
        address_ok ? 1 : 0,
        dr7_ok ? 1 : 0,
        static_cast<unsigned long long>(verify_addr),
        static_cast<unsigned long long>(verify.rip),
        tctx_address_class(verify.rip),
        static_cast<unsigned long long>(verify.rsp),
        tctx_address_class(verify.rsp),
        static_cast<unsigned long long>(verify.rflags),
        static_cast<unsigned long long>(verify.dr0),
        static_cast<unsigned long long>(verify.dr1),
        static_cast<unsigned long long>(verify.dr2),
        static_cast<unsigned long long>(verify.dr3),
        static_cast<unsigned long long>(verify.dr6),
        static_cast<unsigned long long>(verify.dr7),
        static_cast<unsigned long long>(ctx.dr7),
        static_cast<unsigned long long>(GetTickCount64() - begin));
    if (!enabled || !address_ok || !dr7_ok) {
        RC_UM_DBG("set_hardware_breakpoint: verify_mismatch pid=%u tid=%u index=%d address=0x%llX verify_addr=0x%llX dr7=0x%llX expected_dr7=0x%llX enabled=%d address_ok=%d dr7_ok=%d",
            process_id_,
            tid,
            index,
            address,
            verify_addr,
            verify.dr7,
            ctx.dr7,
            enabled ? 1 : 0,
            address_ok ? 1 : 0,
            dr7_ok ? 1 : 0);
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    RC_UM_DBG("set_hardware_breakpoint: verify_ok pid=%u tid=%u index=%d address=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        index,
        address,
        verify.dr7);
    return true;
}

bool voyager::device_t::clear_hardware_breakpoint(std::uint32_t tid, int index) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        return false;
    }

    const ULONGLONG begin = GetTickCount64();
    diag::log_tagged_fmt("comm",
        "HWBP clear begin pid=%u tid=%u index=%d connected=%d",
        process_id_,
        tid,
        index,
        is_connected() ? 1 : 0);

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("comm",
            "HWBP clear get_before_failed pid=%u tid=%u index=%d gle=%lu elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }
    const thread_context before = ctx;
    diag::log_tagged_fmt("comm",
        "HWBP clear before pid=%u tid=%u index=%d rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        process_id_,
        tid,
        index,
        static_cast<unsigned long long>(before.rip),
        tctx_address_class(before.rip),
        static_cast<unsigned long long>(before.rsp),
        tctx_address_class(before.rsp),
        static_cast<unsigned long long>(before.rflags),
        static_cast<unsigned long long>(before.dr0),
        static_cast<unsigned long long>(before.dr1),
        static_cast<unsigned long long>(before.dr2),
        static_cast<unsigned long long>(before.dr3),
        static_cast<unsigned long long>(before.dr6),
        static_cast<unsigned long long>(before.dr7));

    switch (index) {
        case 0: ctx.dr0 = 0; break;
        case 1: ctx.dr1 = 0; break;
        case 2: ctx.dr2 = 0; break;
        case 3: ctx.dr3 = 0; break;
    }


    std::uint64_t dr7 = ctx.dr7;
    constexpr std::uint64_t kDr7UserMask = 0xFFFF0355ULL;
    constexpr std::uint64_t kDr7GlobalEnableMask = 0xAAULL;
    dr7 &= kDr7UserMask;
    dr7 &= ~kDr7GlobalEnableMask;
    dr7 &= ~(3ULL << (index * 2));
    dr7 &= ~(3ULL << (16 + index * 4));
    dr7 &= ~(3ULL << (18 + index * 4));
    ctx.dr6 = 0;
    ctx.dr7 = dr7;

    std::uint64_t mask = (1ULL << (18 + index)) | (1ULL << 22) | (1ULL << 23);

    const ULONGLONG set_start = GetTickCount64();
    if (!set_thread_context(tid, ctx, mask)) {
        DWORD gle = GetLastError();
        RC_UM_DBG("clear_hardware_breakpoint: set_context_failed pid=%u tid=%u index=%d dr7=0x%llX mask=0x%llX",
            process_id_,
            tid,
            index,
            ctx.dr7,
            mask);
        diag::log_tagged_fmt("comm",
            "HWBP clear context_failed pid=%u tid=%u index=%d gle=%lu mask=0x%llX before_rip=0x%llX before_rsp=0x%llX before_dr0=0x%llX before_dr1=0x%llX before_dr2=0x%llX before_dr3=0x%llX before_dr6=0x%llX before_dr7=0x%llX requested_dr0=0x%llX requested_dr1=0x%llX requested_dr2=0x%llX requested_dr3=0x%llX requested_dr6=0x%llX requested_dr7=0x%llX set_elapsed_ms=%llu total_elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(mask),
            static_cast<unsigned long long>(before.rip),
            static_cast<unsigned long long>(before.rsp),
            static_cast<unsigned long long>(before.dr0),
            static_cast<unsigned long long>(before.dr1),
            static_cast<unsigned long long>(before.dr2),
            static_cast<unsigned long long>(before.dr3),
            static_cast<unsigned long long>(before.dr6),
            static_cast<unsigned long long>(before.dr7),
            static_cast<unsigned long long>(ctx.dr0),
            static_cast<unsigned long long>(ctx.dr1),
            static_cast<unsigned long long>(ctx.dr2),
            static_cast<unsigned long long>(ctx.dr3),
            static_cast<unsigned long long>(ctx.dr6),
            static_cast<unsigned long long>(ctx.dr7),
            static_cast<unsigned long long>(GetTickCount64() - set_start),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }
    const DWORD set_gle = GetLastError();
    thread_context verify{};
    if (!get_thread_context(tid, verify)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("comm",
            "HWBP clear verify_get_failed pid=%u tid=%u index=%d set_gle=%lu verify_gle=%lu mask=0x%llX total_elapsed_ms=%llu",
            process_id_,
            tid,
            index,
            static_cast<unsigned long>(set_gle),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(mask),
            static_cast<unsigned long long>(GetTickCount64() - begin));
        return false;
    }
    std::uint64_t verify_addr = 0;
    switch (index) {
        case 0: verify_addr = verify.dr0; break;
        case 1: verify_addr = verify.dr1; break;
        case 2: verify_addr = verify.dr2; break;
        case 3: verify_addr = verify.dr3; break;
    }
    const bool enabled_clear = (verify.dr7 & (1ULL << (index * 2))) == 0;
    const bool address_clear = verify_addr == 0;
    const bool dr7_clear = (verify.dr7 & ((3ULL << (16 + index * 4)) | (3ULL << (18 + index * 4)))) == 0;
    diag::log_tagged_fmt("comm",
        "HWBP clear verify pid=%u tid=%u index=%d enabled_clear=%d address_clear=%d dr7_clear=%d verify_addr=0x%llX set_gle=%lu mask=0x%llX rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX total_elapsed_ms=%llu",
        process_id_,
        tid,
        index,
        enabled_clear ? 1 : 0,
        address_clear ? 1 : 0,
        dr7_clear ? 1 : 0,
        static_cast<unsigned long long>(verify_addr),
        static_cast<unsigned long>(set_gle),
        static_cast<unsigned long long>(mask),
        static_cast<unsigned long long>(verify.rip),
        tctx_address_class(verify.rip),
        static_cast<unsigned long long>(verify.rsp),
        tctx_address_class(verify.rsp),
        static_cast<unsigned long long>(verify.rflags),
        static_cast<unsigned long long>(verify.dr0),
        static_cast<unsigned long long>(verify.dr1),
        static_cast<unsigned long long>(verify.dr2),
        static_cast<unsigned long long>(verify.dr3),
        static_cast<unsigned long long>(verify.dr6),
        static_cast<unsigned long long>(verify.dr7),
        static_cast<unsigned long long>(GetTickCount64() - begin));
    if (!enabled_clear || !address_clear || !dr7_clear) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}


std::vector<voyager::device_t::net_connection_info> voyager::device_t::enumerate_connections(std::uint32_t filter_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<net_connection_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::net_enum_conn_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_enum_conn_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;

    if (send_request(ioctl_codes::NCON(), req, static_cast<DWORD>(sizeof(*req)))) {
        RC_UM_DBG("enumerate_connections: ioctl OK, connection_count=%u", req->connection_count);
        result.reserve(req->connection_count);
        for (std::uint32_t i = 0; i < req->connection_count; i++) {
            net_connection_info info{};
            info.pid = req->entries[i].pid;
            info.protocol = req->entries[i].protocol;
            info.state = req->entries[i].state;
            info.local_port = req->entries[i].local_port;
            info.remote_port = req->entries[i].remote_port;
            info.address_family = req->entries[i].address_family;
            std::memcpy(info.local_addr, req->entries[i].local_addr, 16);
            std::memcpy(info.remote_addr, req->entries[i].remote_addr, 16);
            std::memcpy(info.process_path, req->entries[i].process_path, 260);
            info.process_path[259] = '\0';
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::start_capture(std::uint32_t filter_pid, std::uint32_t filter_port,
    std::uint32_t filter_protocol, const std::uint8_t* filter_ip, std::uint32_t max_payload) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 0;
    req.filter_pid = filter_pid;
    req.filter_port = filter_port;
    req.filter_protocol = filter_protocol;
    req.max_packet_bytes = max_payload;
    if (filter_ip) std::memcpy(req.filter_ip, filter_ip, 16);

    if (!send_request(ioctl_codes::NCAP(), &req, sizeof(req))) {
        RC_UM_DBG("start_capture: ioctl FAILED");
        return false;
    }
    RC_UM_DBG("start_capture: ioctl OK, capture_active=%u", req.capture_active);
    return req.capture_active != 0;
}

bool voyager::device_t::stop_capture() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::NCAP(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::get_capture_status(bool& active, std::uint32_t& captured, std::uint32_t& dropped) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 2;

    if (!send_request(ioctl_codes::NCAP(), &req, sizeof(req))) {
        return false;
    }

    active = req.capture_active != 0;
    captured = req.packets_captured;
    dropped = req.packets_dropped;
    return true;
}

std::vector<voyager::device_t::captured_packet> voyager::device_t::get_captured_packets(std::uint32_t max_packets) noexcept {
    std::vector<captured_packet> result;
    const DWORD ioctl_code = ioctl_codes::NCPG();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "get_captured_packets ABORT not_connected max=%u ioctl=0x%08X",
            max_packets, ioctl_code);
        return result;
    }

    auto* req = static_cast<voyager::detail::net_cap_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_cap_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "get_captured_packets ABORT alloc_failed max=%u bytes=%zu gle=%lu",
            max_packets, sizeof(voyager::detail::net_cap_get_request), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->max_packets = std::min<std::uint32_t>(max_packets, static_cast<std::uint32_t>(voyager::detail::NET_CAP_GET_MAX));

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t raw_count = req->packet_count;
    const std::uint32_t count = std::min<std::uint32_t>(raw_count, static_cast<std::uint32_t>(voyager::detail::NET_CAP_GET_MAX));
    diag::log_tagged_fmt("driver_comm_net",
        "get_captured_packets EXIT ok=%d gle=%lu requested=%u sent_max=%u raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, max_packets, req->max_packets, raw_count, count, ioctl_code);
    if (ok) {
        RC_UM_DBG("get_captured_packets: ioctl OK, packet_count=%u", req->packet_count);
        result.reserve(count);
        for (std::uint32_t i = 0; i < count; i++) {
            captured_packet pkt{};
            const auto& src = req->packets[i];
            pkt.timestamp = src.timestamp;
            pkt.pid = src.pid;
            pkt.protocol = src.protocol;
            pkt.direction = src.direction;
            pkt.payload_size = src.payload_size;
            pkt.local_port = src.local_port;
            pkt.remote_port = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr, src.local_addr, 16);
            std::memcpy(pkt.remote_addr, src.remote_addr, 16);
            if (src.payload_size > 0) {
                std::uint32_t sz = src.payload_size;
                if (sz > voyager::detail::NET_PKT_MAX_PAYLOAD) sz = static_cast<std::uint32_t>(voyager::detail::NET_PKT_MAX_PAYLOAD);
                pkt.payload.assign(src.payload, src.payload + sz);
            }
            result.push_back(std::move(pkt));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::dns_entry> voyager::device_t::get_dns_queries(std::uint32_t filter_pid) noexcept {
    std::vector<dns_entry> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::net_dns_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_dns_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;

    if (send_request(ioctl_codes::NDNS(), req, static_cast<DWORD>(sizeof(*req)))) {
        RC_UM_DBG("get_dns_queries: ioctl OK, entry_count=%u", req->entry_count);
        result.reserve(req->entry_count);
        for (std::uint32_t i = 0; i < req->entry_count; i++) {
            dns_entry entry{};
            const auto& src = req->entries[i];
            entry.timestamp = src.timestamp;
            entry.pid = src.pid;
            entry.query_type = src.query_type;
            entry.domain = std::string(src.domain);
            std::memcpy(entry.resolved_addr, src.resolved_addr, 16);
            entry.response_code = src.response_code;
            entry.ttl = src.ttl;
            result.push_back(std::move(entry));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::add_filter_rule(std::uint32_t action, std::uint32_t direction,
    std::uint32_t protocol, std::uint32_t pid, std::uint32_t port,
    const std::uint8_t* ip_addr, const std::uint8_t* ip_mask,
    std::uint32_t* out_rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 0;
    req.action = action;
    req.direction = direction;
    req.protocol = protocol;
    req.pid = pid;
    req.port = port;
    if (ip_addr) std::memcpy(req.ip_addr, ip_addr, 16);
    if (ip_mask) std::memcpy(req.ip_mask, ip_mask, 16);

    if (!send_request(ioctl_codes::NFLT(), &req, sizeof(req))) {
        return false;
    }
    if (out_rule_id) *out_rule_id = req.rule_id;
    return true;
}

bool voyager::device_t::remove_filter_rule(std::uint32_t rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 1;
    req.rule_id = rule_id;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::clear_filter_rules() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 2;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::get_network_stats(network_stats& stats) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_stats_request req{};

    if (!send_request(ioctl_codes::NSTS(), &req, sizeof(req))) {
        return false;
    }

    stats.bytes_sent = req.bytes_sent;
    stats.bytes_received = req.bytes_received;
    stats.packets_sent = req.packets_sent;
    stats.packets_received = req.packets_received;
    stats.active_connections = req.active_connections;
    stats.capture_active = req.capture_active;
    stats.total_captured = req.total_captured;
    stats.total_dropped = req.total_dropped;
    stats.total_dns_logged = req.total_dns_logged;
    stats.active_filter_rules = req.active_filter_rules;
    return true;
}


static std::string guid_to_string(const voyager::detail::GUID_COMPAT& g) {
    char buf[40];
    snprintf(buf, sizeof(buf), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

std::vector<voyager::device_t::wfp_callout_info>
voyager::device_t::enumerate_wfp_callouts(const std::string& filter_module) noexcept {
    std::vector<wfp_callout_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::wfp_callout_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::wfp_callout_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    if (!filter_module.empty()) {
        std::size_t len = filter_module.size();
        if (len > 63) len = 63;
        std::memcpy(req->filter_module, filter_module.c_str(), len);
    }

    if (send_request(ioctl_codes::EWFP(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->callout_count);
        for (std::uint32_t i = 0; i < req->callout_count; i++) {
            const auto& e = req->entries[i];
            wfp_callout_info info{};
            info.classify_fn = e.classify_fn;
            info.notify_fn = e.notify_fn;
            info.flow_delete_fn = e.flow_delete_fn;
            info.owning_module_base = e.owning_module_base;
            info.filter_id = e.filter_id;
            info.callout_id = e.callout_id;
            info.layer_id = e.layer_id;
            info.flags = e.flags;
            info.entry_type = e.entry_type;
            info.action_type = e.action_type;
            info.provider_present = e.provider_present;
            info.aida_match_reason = e.aida_match_reason;
            info.callout_key_str = guid_to_string(e.callout_key);
            info.applicable_layer_str = guid_to_string(e.applicable_layer);
            info.sublayer_key_str = guid_to_string(e.sublayer_key);
            info.owning_module = std::string(e.owning_module,
                strnlen(e.owning_module, sizeof(e.owning_module)));
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::socket_info>
voyager::device_t::get_socket_handles(std::uint32_t target_pid) noexcept {
    std::vector<socket_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::socket_handle_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::socket_handle_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->target_pid = (target_pid != 0) ? target_pid : process_id_;

    if (send_request(ioctl_codes::GSKT(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->socket_count);
        for (std::uint32_t i = 0; i < req->socket_count; i++) {
            const auto& e = req->entries[i];
            socket_info info{};
            info.handle_value = e.handle_value;
            info.afd_endpoint_addr = e.afd_endpoint_addr;
            info.pid = e.pid;
            info.protocol = e.protocol;
            info.state = e.state;
            info.local_port = e.local_port;
            info.remote_port = e.remote_port;
            info.address_family = e.address_family;
            std::memcpy(info.local_addr, e.local_addr, 16);
            std::memcpy(info.remote_addr, e.remote_addr, 16);
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::sniff_net_buffers_start(std::uint64_t address, std::uint32_t buf_reg,
    std::uint32_t size_reg, std::uint32_t max_captures, std::uint32_t tid, std::uint32_t bp_index) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::sniff_net_buffers_request req{};
    req.target_address = address;
    req.buffer_reg_index = buf_reg;
    req.size_reg_index = size_reg;
    req.max_captures = max_captures;
    req.operation = 0;
    req.target_tid = tid;
    req.bp_index = bp_index;

    bool ok_sniff = send_request(ioctl_codes::SNBF(), &req, sizeof(req));
    return ok_sniff;
}

bool voyager::device_t::sniff_net_buffers_stop() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::sniff_net_buffers_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::SNBF(), &req, sizeof(req));
    return ok;
}

std::vector<voyager::device_t::sniff_result>
voyager::device_t::sniff_net_buffers_get(bool& active) noexcept {
    std::vector<sniff_result> result;
    active = false;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::sniff_net_buffers_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::sniff_net_buffers_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::SNBF(), req, static_cast<DWORD>(sizeof(*req)))) {
        active = (req->active != 0);
        result.reserve(req->capture_count);
        for (std::uint32_t i = 0; i < req->capture_count; i++) {
            const auto& c = req->captures[i];
            sniff_result sr;
            sr.timestamp = c.timestamp;
            sr.thread_id = c.thread_id;
            std::uint32_t sz = c.buffer_size;
            if (sz > voyager::detail::SNIFF_MAX_BUF_SIZE)
                sz = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE);
            sr.buffer.assign(c.buffer, c.buffer + sz);
            result.push_back(std::move(sr));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::sniff_net_buffers_store(std::uint64_t timestamp, std::uint64_t thread_id,
    const std::uint8_t* data, std::uint32_t size) noexcept {
    if (!is_connected() || !data || size == 0) {
        return false;
    }

    auto* req = static_cast<voyager::detail::sniff_net_buffers_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::sniff_net_buffers_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = 3;

    std::uint32_t copy_sz = size;
    if (copy_sz > static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE))
        copy_sz = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE);

    req->captures[0].timestamp = timestamp;
    req->captures[0].thread_id = thread_id;
    req->captures[0].buffer_size = copy_sz;
    std::memcpy(req->captures[0].buffer, data, copy_sz);

    bool ok = send_request(ioctl_codes::SNBF(), req, static_cast<DWORD>(sizeof(*req)));
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::tcpip_connection>
voyager::device_t::dump_tcpip_connections(std::uint32_t target_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<tcpip_connection> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::tcpip_conn_dump_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::tcpip_conn_dump_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->target_pid = target_pid;
    req->filter_protocol = filter_protocol;

    if (send_request(ioctl_codes::DTCP(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->connection_count);
        for (std::uint32_t i = 0; i < req->connection_count; i++) {
            const auto& e = req->entries[i];
            tcpip_connection conn{};
            conn.tcb_address = e.tcb_address;
            conn.owning_module_base = e.owning_module_base;
            conn.pid = e.pid;
            conn.protocol = e.protocol;
            conn.state = e.state;
            conn.local_port = e.local_port;
            conn.remote_port = e.remote_port;
            conn.address_family = e.address_family;
            std::memcpy(conn.local_addr, e.local_addr, 16);
            std::memcpy(conn.remote_addr, e.remote_addr, 16);
            conn.create_time = e.create_time;
            conn.bytes_in = e.bytes_in;
            conn.bytes_out = e.bytes_out;
            result.push_back(conn);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}


bool voyager::device_t::inject_packet(std::uint32_t direction, std::uint32_t protocol, std::uint32_t af,
                                       std::uint32_t src_port, std::uint32_t dst_port,
                                       const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                                       const std::uint8_t* payload, std::uint32_t payload_size,
                                       std::uint32_t tcp_flags, std::uint32_t tcp_seq, std::uint32_t tcp_ack) noexcept {
    if (!is_connected() || !payload || payload_size == 0) {
        return false;
    }
    if (payload_size > detail::INJECT_MAX_PAYLOAD) payload_size = detail::INJECT_MAX_PAYLOAD;

    auto* req = static_cast<detail::packet_inject_request*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_inject_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->direction = direction;
    req->protocol = protocol;
    req->address_family = af;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->payload_size = payload_size;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);
    req->tcp_flags = tcp_flags;
    req->tcp_seq = tcp_seq;
    req->tcp_ack = tcp_ack;
    std::memcpy(req->payload, payload, payload_size);

    bool ok = send_request(ioctl_codes::PINJ(), req, static_cast<DWORD>(sizeof(*req)));
    bool success = ok && (req->status == 0);
    VirtualFree(req, 0, MEM_RELEASE);
    return success;
}

bool voyager::device_t::packet_mod_rule_op(std::uint32_t operation, std::uint32_t rule_id,
                                            std::uint32_t direction, std::uint32_t protocol,
                                            std::uint32_t port, std::uint32_t pid,
                                            const std::uint8_t* pattern, std::uint32_t pattern_size,
                                            const std::uint8_t* replacement, std::uint32_t replace_size,
                                            std::uint32_t* out_rule_id) noexcept {
    const DWORD ioctl_code = ioctl_codes::PMOD();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net",
            "packet_mod_rule_op ABORT not_connected op=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u ioctl=0x%08X",
            operation, rule_id, direction, protocol, port, pid, ioctl_code);
        return false;
    }

    auto* req = static_cast<detail::packet_mod_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_mod_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "packet_mod_rule_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::packet_mod_rule), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->direction = direction;
    req->protocol = protocol;
    req->port = port;
    req->pid = pid;
    if (pattern && pattern_size > 0) {
        req->pattern_size = (pattern_size > detail::MOD_MAX_PATTERN) ? detail::MOD_MAX_PATTERN : pattern_size;
        std::memcpy(req->pattern, pattern, req->pattern_size);
    }
    if (replacement && replace_size > 0) {
        req->replace_size = (replace_size > detail::MOD_MAX_REPLACE) ? detail::MOD_MAX_REPLACE : replace_size;
        std::memcpy(req->replacement, replacement, req->replace_size);
    }

    SetLastError(0);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("driver_comm_net",
        "packet_mod_rule_op EXIT ok=%d gle=%lu op=%u in_rule_id=%u out_rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, rule_id, req->rule_id, direction, protocol, port, pid,
        req->pattern_size, req->replace_size, ioctl_code);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::mod_rule_info> voyager::device_t::list_packet_mod_rules() noexcept {
    std::vector<mod_rule_info> result;
    const DWORD ioctl_code = ioctl_codes::PMOD();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "list_packet_mod_rules ABORT not_connected ioctl=0x%08X", ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::packet_mod_rule_list*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_mod_rule_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "list_packet_mod_rules ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::packet_mod_rule_list), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->rule_count, detail::MOD_MAX_RULES);
    diag::log_tagged_fmt("driver_comm_net", "list_packet_mod_rules EXIT ok=%d gle=%lu raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, req->rule_count, count, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& r = req->rules[i];
            mod_rule_info info{};
            info.rule_id = r.rule_id;
            info.direction = r.direction;
            info.protocol = r.protocol;
            info.port = r.port;
            info.pid = r.pid;
            info.match_count = r.match_count;
            info.active = r.active;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::traffic_redirect_op(std::uint32_t operation, std::uint32_t rule_id,
                                             std::uint32_t protocol,
                                             std::uint32_t match_port, const std::uint8_t* match_addr,
                                             std::uint32_t redirect_port, const std::uint8_t* redirect_addr,
                                             std::uint32_t af, std::uint32_t* out_rule_id,
                                             std::uint32_t exclude_pid) noexcept {
    const DWORD ioctl_code = ioctl_codes::PRED();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net",
            "traffic_redirect_op ABORT not_connected op=%u rule_id=%u protocol=%u match_port=%u redirect_port=%u af=%u exclude_pid=%u ioctl=0x%08X",
            operation, rule_id, protocol, match_port, redirect_port, af, exclude_pid, ioctl_code);
        return false;
    }

    auto* req = static_cast<detail::traffic_redirect_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::traffic_redirect_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "traffic_redirect_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::traffic_redirect_rule), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->protocol = protocol;
    req->match_port = match_port;
    req->redirect_port = redirect_port;
    req->address_family = af;
    if (match_addr) std::memcpy(req->match_addr, match_addr, 16);
    if (redirect_addr) std::memcpy(req->redirect_addr, redirect_addr, 16);
    req->exclude_pid = exclude_pid;

    SetLastError(0);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("driver_comm_net",
        "traffic_redirect_op EXIT ok=%d gle=%lu op=%u in_rule_id=%u out_rule_id=%u protocol=%u match_port=%u redirect_port=%u af=%u exclude_pid=%u match_count=%u active=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, rule_id, req->rule_id, protocol, match_port, redirect_port,
        af, exclude_pid, req->match_count, req->active, ioctl_code);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::redirect_rule_info> voyager::device_t::list_redirect_rules() noexcept {
    std::vector<redirect_rule_info> result;
    const DWORD ioctl_code = ioctl_codes::PRED();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "list_redirect_rules ABORT not_connected ioctl=0x%08X", ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::traffic_redirect_list*>(
        VirtualAlloc(nullptr, sizeof(detail::traffic_redirect_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "list_redirect_rules ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::traffic_redirect_list), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->rule_count, detail::REDIR_MAX_RULES);
    diag::log_tagged_fmt("driver_comm_net", "list_redirect_rules EXIT ok=%d gle=%lu raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, req->rule_count, count, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& r = req->rules[i];
            redirect_rule_info info{};
            info.rule_id = r.rule_id;
            info.protocol = r.protocol;
            info.match_port = r.match_port;
            info.redirect_port = r.redirect_port;
            info.af = r.address_family;
            info.match_count = r.match_count;
            info.active = r.active;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::stream_reassemble_op(std::uint32_t operation, std::uint32_t src_port, std::uint32_t dst_port,
                                              std::uint32_t pid, const std::uint8_t* src_addr,
                                              const std::uint8_t* dst_addr,
                                              std::vector<std::uint8_t>* out_data,
                                              std::uint32_t* out_packets, std::uint32_t* out_truncated) noexcept {
    DWORD strm_code = ioctl_codes::STRM();
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op ENTER op=%u src_port=%u dst_port=%u pid=%u ioctl=0x%08X struct_size=%zu connected=%d",
        operation, src_port, dst_port, pid, strm_code,
        sizeof(detail::stream_reassemble_request), is_connected() ? 1 : 0);

    if (!is_connected()) {
        diag::log_tagged_fmt("netaction-strm",
            "stream_reassemble_op ABORT not_connected handle=0x%llX",
            reinterpret_cast<unsigned long long>(driver_handle_));
        return false;
    }

    auto* req = static_cast<detail::stream_reassemble_request*>(
        VirtualAlloc(nullptr, sizeof(detail::stream_reassemble_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("netaction-strm",
            "stream_reassemble_op ABORT VirtualAlloc_failed bytes=%zu err=%lu",
            sizeof(detail::stream_reassemble_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    SetLastError(0);
    bool ok = send_request(strm_code, req, static_cast<DWORD>(sizeof(*req)));
    DWORD post_err = GetLastError();
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op send_request ok=%d last_error=%lu stream_size=%u total_packets=%u stream_count=%u truncated=%u",
        ok ? 1 : 0, post_err,
        req->stream_size, req->total_packets, req->stream_count, req->truncated);

    if (ok) {
        if (out_data && req->stream_size > 0) {
            out_data->assign(req->stream_data, req->stream_data + req->stream_size);
        }
        if (out_packets) *out_packets = req->total_packets;
        if (out_truncated) *out_truncated = req->truncated;
    }

    VirtualFree(req, 0, MEM_RELEASE);
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op EXIT ok=%d", ok ? 1 : 0);
    return ok;
}

std::vector<voyager::device_t::dpi_result> voyager::device_t::get_dpi_results(
    std::uint32_t filter_pid, std::uint32_t filter_protocol,
    std::uint32_t filter_port, std::uint32_t flags) noexcept {
    std::vector<dpi_result> result;
    const DWORD ioctl_code = ioctl_codes::DPIN();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net",
            "get_dpi_results ABORT not_connected filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X ioctl=0x%08X",
            filter_pid, filter_protocol, filter_port, flags, ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::dpi_request*>(
        VirtualAlloc(nullptr, sizeof(detail::dpi_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "get_dpi_results ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::dpi_request), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;
    req->filter_port = filter_port;
    req->flags = flags;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->result_count, detail::DPI_MAX_RESULTS);
    diag::log_tagged_fmt("driver_comm_net",
        "get_dpi_results IOCTL ok=%d gle=%lu filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, filter_pid, filter_protocol, filter_port, flags, req->result_count, count, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& h = req->results[i];
            dpi_result d{};
            d.timestamp = h.timestamp;
            d.direction = h.direction;
            d.protocol = h.protocol;
            d.src_port = h.src_port;
            d.dst_port = h.dst_port;
            d.pid = h.pid;
            d.payload_size = h.payload_size;
            d.af = h.address_family;
            std::memcpy(d.src_addr, h.src_addr, 16);
            std::memcpy(d.dst_addr, h.dst_addr, 16);
            d.tcp_flags = h.tcp_flags;
            d.tcp_window = h.tcp_window;
            d.is_http = (h.is_http != 0);
            d.is_tls = (h.is_tls != 0);
            d.is_dns = (h.is_dns != 0);
            d.http_method = h.http_method;
            d.tls_version = h.tls_version;
            d.tls_content_type = h.tls_content_type;
            if (h.http_host[0]) d.http_host = h.http_host;
            if (h.http_path[0]) d.http_path = h.http_path;
            if (h.tls_sni[0]) d.tls_sni = h.tls_sni;
            result.push_back(std::move(d));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    if (result.empty()) {
        const auto captured = get_captured_packets(detail::DPI_MAX_RESULTS);
        std::size_t fallback_added = 0;
        result.reserve(captured.size());
        for (const auto& pkt : captured) {
            dpi_result d{};
            if (!dpi_from_captured_packet(pkt, d))
                continue;
            if (!dpi_result_matches_filters(d, filter_pid, filter_protocol, filter_port, flags))
                continue;
            result.push_back(std::move(d));
            ++fallback_added;
        }
        diag::log_tagged_fmt("driver_comm_net",
            "get_dpi_results FALLBACK captured=%zu added=%zu filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X",
            captured.size(), fallback_added, filter_pid, filter_protocol, filter_port, flags);
    }
    diag::log_tagged_fmt("driver_comm_net", "get_dpi_results EXIT result_count=%zu", result.size());
    return result;
}

bool voyager::device_t::intercept_op(std::uint32_t operation, std::uint32_t filter_pid, std::uint32_t filter_port,
                                      std::uint32_t filter_protocol, std::uint64_t hold_id,
                                      const std::uint8_t* modify_payload, std::uint32_t modify_size,
                                      std::uint32_t* out_held_count, bool* out_active) noexcept {
    const DWORD ioctl_code = ioctl_codes::IHLD();
    if (!is_connected()) {
        SetLastError(ERROR_INVALID_HANDLE);
        diag::log_tagged_fmt("driver_comm_net",
            "intercept_op ABORT not_connected op=%u pid=%u port=%u protocol=%u hold_id=%llu ioctl=0x%08X gle=%lu",
            operation, filter_pid, filter_port, filter_protocol, static_cast<unsigned long long>(hold_id), ioctl_code,
            static_cast<unsigned long>(ERROR_INVALID_HANDLE));
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    auto* req = static_cast<detail::intercept_request*>(
        VirtualAlloc(nullptr, sizeof(detail::intercept_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        DWORD err = GetLastError();
        if (err == ERROR_SUCCESS)
            err = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(err);
        diag::log_tagged_fmt("driver_comm_net", "intercept_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::intercept_request), static_cast<unsigned long>(err));
        SetLastError(err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->filter_pid = filter_pid;
    req->filter_port = filter_port;
    req->filter_protocol = filter_protocol;
    req->hold_id = hold_id;
    if (modify_payload && modify_size > 0) {
        req->modify_payload_size = (modify_size > detail::INTERCEPT_MAX_PAYLOAD) ? detail::INTERCEPT_MAX_PAYLOAD : modify_size;
        std::memcpy(req->modify_payload, modify_payload, req->modify_payload_size);
    }

    SetLastError(ERROR_SUCCESS);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    DWORD gle = GetLastError();
    if (!ok && gle == ERROR_SUCCESS) {
        gle = ERROR_GEN_FAILURE;
        SetLastError(gle);
    }
    diag::log_tagged_fmt("driver_comm_net",
        "intercept_op EXIT ok=%d gle=%lu op=%u pid=%u port=%u protocol=%u hold_id=%llu held_count=%u active=%u modify_size=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, filter_pid, filter_port, filter_protocol,
        static_cast<unsigned long long>(hold_id), req->held_count, req->intercepting,
        req->modify_payload_size, ioctl_code);
    if (ok) {
        if (out_held_count) *out_held_count = req->held_count;
        if (out_active) *out_active = (req->intercepting != 0);
    }

    VirtualFree(req, 0, MEM_RELEASE);
    SetLastError(ok ? ERROR_SUCCESS : gle);
    return ok;
}

std::vector<voyager::device_t::held_packet_info> voyager::device_t::get_held_packets() noexcept {
    std::vector<held_packet_info> result;
    const DWORD ioctl_code = ioctl_codes::IHLD();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "get_held_packets ABORT not_connected ioctl=0x%08X", ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::intercept_request*>(
        VirtualAlloc(nullptr, sizeof(detail::intercept_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "get_held_packets ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::intercept_request), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->held_count, detail::INTERCEPT_MAX_HELD);
    diag::log_tagged_fmt("driver_comm_net", "get_held_packets EXIT ok=%d gle=%lu raw_count=%u used_count=%u active=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, req->held_count, count, req->intercepting, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& h = req->held_packets[i];
            held_packet_info info{};
            info.hold_id = h.hold_id;
            info.timestamp = h.timestamp;
            info.direction = h.direction;
            info.protocol = h.protocol;
            info.src_port = h.src_port;
            info.dst_port = h.dst_port;
            info.pid = h.pid;
            info.payload_size = h.payload_size;
            info.af = h.address_family;
            std::memcpy(info.src_addr, h.src_addr, 16);
            std::memcpy(info.dst_addr, h.dst_addr, 16);
            if (h.payload_size > 0) {
                std::uint32_t sz = (h.payload_size > detail::INTERCEPT_MAX_PAYLOAD) ? detail::INTERCEPT_MAX_PAYLOAD : h.payload_size;
                info.payload.assign(h.payload, h.payload + sz);
            }
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::kill_connection(std::uint32_t protocol, std::uint32_t af,
                                         std::uint32_t src_port, std::uint32_t dst_port,
                                         const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                                         std::uint32_t pid) noexcept {
    DWORD ckil_code = ioctl_codes::CKIL();
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u ioctl=0x%08X struct_size=%zu connected=%d",
        protocol, af, src_port, dst_port, pid, ckil_code,
        sizeof(detail::conn_kill_request), is_connected() ? 1 : 0);

    if (!is_connected()) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection ABORT not_connected handle=0x%llX",
            reinterpret_cast<unsigned long long>(driver_handle_));
        return false;
    }

    auto* req = static_cast<detail::conn_kill_request*>(
        VirtualAlloc(nullptr, sizeof(detail::conn_kill_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection ABORT VirtualAlloc_failed bytes=%zu err=%lu",
            sizeof(detail::conn_kill_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->protocol = protocol;
    req->address_family = af;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    if (src_addr) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection src_addr=%u.%u.%u.%u",
            (unsigned)src_addr[0], (unsigned)src_addr[1],
            (unsigned)src_addr[2], (unsigned)src_addr[3]);
    }
    if (dst_addr) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection dst_addr=%u.%u.%u.%u",
            (unsigned)dst_addr[0], (unsigned)dst_addr[1],
            (unsigned)dst_addr[2], (unsigned)dst_addr[3]);
    }

    SetLastError(0);
    bool ok = send_request(ckil_code, req, static_cast<DWORD>(sizeof(*req)));
    DWORD post_err = GetLastError();
    bool success = ok && (req->status == 0);
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection send_request ok=%d last_error=%lu request_status=%u success=%d",
        ok ? 1 : 0, post_err, req->status, success ? 1 : 0);

    VirtualFree(req, 0, MEM_RELEASE);
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection EXIT success=%d", success ? 1 : 0);
    return success;
}

bool voyager::device_t::dns_spoof_op(std::uint32_t operation, std::uint32_t rule_id,
                                      const char* domain,
                                      const std::uint8_t* spoof_addr, std::uint32_t af,
                                      std::uint32_t ttl, std::uint32_t* out_rule_id) noexcept {
    const DWORD ioctl_code = ioctl_codes::DNSS();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net",
            "dns_spoof_op ABORT not_connected op=%u rule_id=%u af=%u ttl=%u ioctl=0x%08X",
            operation, rule_id, af, ttl, ioctl_code);
        return false;
    }

    auto* req = static_cast<detail::dns_spoof_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::dns_spoof_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "dns_spoof_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::dns_spoof_rule), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->address_family = af;
    req->ttl = ttl;
    if (domain) {
        size_t len = strlen(domain);
        if (len >= detail::DNS_SPOOF_MAX_DOMAIN) len = detail::DNS_SPOOF_MAX_DOMAIN - 1;
        std::memcpy(req->domain, domain, len);
    }
    if (spoof_addr) std::memcpy(req->spoof_addr, spoof_addr, 16);

    SetLastError(0);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("driver_comm_net",
        "dns_spoof_op EXIT ok=%d gle=%lu op=%u in_rule_id=%u out_rule_id=%u af=%u ttl=%u match_count=%u active=%u has_domain=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, rule_id, req->rule_id, af, ttl, req->match_count,
        req->active, req->domain[0] ? 1u : 0u, ioctl_code);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::dns_spoof_info> voyager::device_t::list_dns_spoof_rules() noexcept {
    std::vector<dns_spoof_info> result;
    const DWORD ioctl_code = ioctl_codes::DNSS();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "list_dns_spoof_rules ABORT not_connected ioctl=0x%08X", ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::dns_spoof_list*>(
        VirtualAlloc(nullptr, sizeof(detail::dns_spoof_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "list_dns_spoof_rules ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::dns_spoof_list), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->rule_count, detail::DNS_SPOOF_MAX_RULES);
    diag::log_tagged_fmt("driver_comm_net", "list_dns_spoof_rules EXIT ok=%d gle=%lu raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, req->rule_count, count, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& r = req->rules[i];
            dns_spoof_info info{};
            info.rule_id = r.rule_id;
            if (r.domain[0]) info.domain = r.domain;
            info.af = r.address_family;
            info.match_count = r.match_count;
            info.active = r.active;
            info.ttl = r.ttl;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::bw_monitor_op(std::uint32_t operation, std::uint32_t filter_pid,
                                       bw_stats* out_stats) noexcept {
    const DWORD ioctl_code = ioctl_codes::BWMN();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "bw_monitor_op ABORT not_connected op=%u filter_pid=%u ioctl=0x%08X",
            operation, filter_pid, ioctl_code);
        return false;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "bw_monitor_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::bw_monitor_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->filter_pid = filter_pid;

    SetLastError(0);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("driver_comm_net",
        "bw_monitor_op EXIT ok=%d gle=%lu op=%u filter_pid=%u active=%u sent_bytes=%llu recv_bytes=%llu sent_pkts=%llu recv_pkts=%llu bps_in=%llu bps_out=%llu process_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, filter_pid, req->monitoring_active,
        static_cast<unsigned long long>(req->total_bytes_sent),
        static_cast<unsigned long long>(req->total_bytes_recv),
        static_cast<unsigned long long>(req->total_packets_sent),
        static_cast<unsigned long long>(req->total_packets_recv),
        static_cast<unsigned long long>(req->bytes_per_second_in),
        static_cast<unsigned long long>(req->bytes_per_second_out),
        req->process_count, ioctl_code);
    if (ok && out_stats) {
        out_stats->total_bytes_sent = req->total_bytes_sent;
        out_stats->total_bytes_recv = req->total_bytes_recv;
        out_stats->total_packets_sent = req->total_packets_sent;
        out_stats->total_packets_recv = req->total_packets_recv;
        out_stats->bps_in = req->bytes_per_second_in;
        out_stats->bps_out = req->bytes_per_second_out;
        out_stats->active = (req->monitoring_active != 0);
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::bw_process_info> voyager::device_t::get_bw_per_process(std::uint32_t filter_pid) noexcept {
    std::vector<bw_process_info> result;
    const DWORD ioctl_code = ioctl_codes::BWMN();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "get_bw_per_process ABORT not_connected filter_pid=%u ioctl=0x%08X",
            filter_pid, ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "get_bw_per_process ABORT alloc_failed filter_pid=%u bytes=%zu gle=%lu",
            filter_pid, sizeof(detail::bw_monitor_request), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 4;
    req->filter_pid = filter_pid;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->process_count, detail::BW_MAX_PROCESSES);
    diag::log_tagged_fmt("driver_comm_net",
        "get_bw_per_process EXIT ok=%d gle=%lu filter_pid=%u raw_count=%u used_count=%u active=%u sent_bytes=%llu recv_bytes=%llu sent_pkts=%llu recv_pkts=%llu ioctl=0x%08X",
        ok ? 1 : 0, gle, filter_pid, req->process_count, count, req->monitoring_active,
        static_cast<unsigned long long>(req->total_bytes_sent),
        static_cast<unsigned long long>(req->total_bytes_recv),
        static_cast<unsigned long long>(req->total_packets_sent),
        static_cast<unsigned long long>(req->total_packets_recv),
        ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& p = req->processes[i];
            bw_process_info info{};
            info.pid = p.pid;
            info.bytes_sent = p.bytes_sent;
            info.bytes_recv = p.bytes_recv;
            info.packets_sent = p.packets_sent;
            info.packets_recv = p.packets_recv;
            info.last_activity = p.last_activity_time;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::net_iface_info> voyager::device_t::enumerate_interfaces() noexcept {
    std::vector<net_iface_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::net_interface_enum*>(
        VirtualAlloc(nullptr, sizeof(detail::net_interface_enum), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));

    if (send_request(ioctl_codes::NIFS(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->interface_count && i < detail::NET_IF_MAX; i++) {
            const auto& e = req->interfaces[i];
            net_iface_info info{};
            info.if_index = e.if_index;
            info.if_type = e.if_type;
            info.mtu = e.mtu;
            info.oper_status = e.oper_status;
            info.speed = e.speed;
            std::memcpy(info.mac_addr, e.mac_addr, 6);
            std::memcpy(info.ipv4_addr, e.ipv4_addr, 4);
            std::memcpy(info.ipv4_mask, e.ipv4_mask, 4);
            std::memcpy(info.ipv6_addr, e.ipv6_addr, 16);
            if (e.name[0]) info.name = e.name;
            if (e.description[0]) info.description = e.description;
            info.in_octets = e.in_octets;
            info.out_octets = e.out_octets;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::export_pcap(std::uint32_t filter_pid, std::uint32_t filter_protocol,
                                     std::uint32_t max_packets, pcap_export_result* out) noexcept {
    if (!is_connected()) {
        return false;
    }
    if (max_packets > detail::PCAP_MAX_EXPORT_PACKETS) max_packets = detail::PCAP_MAX_EXPORT_PACKETS;

    auto* req = static_cast<detail::pcap_export_request*>(
        VirtualAlloc(nullptr, sizeof(detail::pcap_export_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = 0;
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;
    req->max_packets = max_packets;

    bool ok = send_request(ioctl_codes::PCEX(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out) {
        out->header = req->header;
        out->packets.clear();
        for (std::uint32_t i = 0; i < req->packet_count && i < detail::PCAP_MAX_EXPORT_PACKETS; i++) {
            const auto& r = req->records[i];
            pcap_packet pkt{};
            pkt.ts_sec = r.ts_sec;
            pkt.ts_usec = r.ts_usec;
            std::uint32_t len = (r.incl_len > detail::PCAP_RECORD_MAX_SIZE) ? detail::PCAP_RECORD_MAX_SIZE : r.incl_len;
            pkt.data.assign(r.data, r.data + len);
            out->packets.push_back(std::move(pkt));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

bool voyager::device_t::fingerprint_op(std::uint32_t operation) noexcept {
    const DWORD ioctl_code = ioctl_codes::NFPR();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "fingerprint_op ABORT not_connected op=%u ioctl=0x%08X",
            operation, ioctl_code);
        return false;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "fingerprint_op ABORT alloc_failed op=%u bytes=%zu gle=%lu",
            operation, sizeof(detail::net_fingerprint_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;

    SetLastError(0);
    bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("driver_comm_net", "fingerprint_op EXIT ok=%d gle=%lu op=%u raw_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, operation, req->result_count, ioctl_code);
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::fingerprint_info> voyager::device_t::get_fingerprints() noexcept {
    std::vector<fingerprint_info> result;
    const DWORD ioctl_code = ioctl_codes::NFPR();
    if (!is_connected()) {
        diag::log_tagged_fmt("driver_comm_net", "get_fingerprints ABORT not_connected ioctl=0x%08X", ioctl_code);
        return result;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        const DWORD err = GetLastError();
        diag::log_tagged_fmt("driver_comm_net", "get_fingerprints ABORT alloc_failed bytes=%zu gle=%lu",
            sizeof(detail::net_fingerprint_request), err);
        return result;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    SetLastError(0);
    const bool ok = send_request(ioctl_code, req, static_cast<DWORD>(sizeof(*req)));
    const DWORD gle = GetLastError();
    const std::uint32_t count = std::min<std::uint32_t>(req->result_count, detail::FINGERPRINT_MAX);
    diag::log_tagged_fmt("driver_comm_net", "get_fingerprints EXIT ok=%d gle=%lu raw_count=%u used_count=%u ioctl=0x%08X",
        ok ? 1 : 0, gle, req->result_count, count, ioctl_code);
    if (ok) {
        for (std::uint32_t i = 0; i < count; i++) {
            const auto& e = req->entries[i];
            fingerprint_info info{};
            std::memcpy(info.remote_addr, e.remote_addr, 16);
            info.af = e.address_family;
            info.ttl = e.ttl;
            info.window_size = e.window_size;
            info.mss = e.mss;
            info.window_scale = e.window_scale;
            info.df_flag = e.df_flag;
            info.sack_permitted = e.sack_permitted;
            info.nop_count = e.nop_count;
            if (e.os_guess[0]) info.os_guess = e.os_guess;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}
bool voyager::device_t::protect_sandbox_pid(std::uint32_t pid, std::uint32_t flags, std::uint64_t* out_denials) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid ENTER pid=%u flags_in=0x%08X connected=%d session_present=%d self_pid=%lu",
        pid, flags, is_connected() ? 1 : 0, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid REJECT pid=0");
        return false;
    }

    detail::protect_sandbox_request req{};
    req.pid = pid;
    req.flags = (flags == 0) ? detail::SANDBOX_FLAG_DEFAULT : flags;

    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid SEND ioctl=0x%08X pid=%u flags_effective=0x%08X size=%u",
        ioctl_codes::PSBX(), req.pid, req.flags, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::PSBX(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    if (out_denials) *out_denials = req.denials_so_far;
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid RESULT pid=%u result=%u denials=%llu ok=%d",
        pid, req.result, static_cast<unsigned long long>(req.denials_so_far), ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::unprotect_sandbox_pid(std::uint32_t pid, std::uint64_t* out_denials) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid ENTER pid=%u connected=%d session_present=%d self_pid=%lu",
        pid, is_connected() ? 1 : 0, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid REJECT pid=0");
        return false;
    }

    detail::protect_sandbox_request req{};
    req.pid = pid;
    req.flags = 0;

    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid SEND ioctl=0x%08X pid=%u size=%u",
        ioctl_codes::USBX(), req.pid, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::USBX(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    if (out_denials) *out_denials = req.denials_so_far;
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid RESULT pid=%u result=%u denials=%llu ok=%d",
        pid, req.result, static_cast<unsigned long long>(req.denials_so_far), ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::net_log_register_pid(std::uint32_t pid, bool enable) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid ENTER pid=%u enable=%d connected=%d session_present=%d self_pid=%lu",
        pid, enable ? 1 : 0, is_connected() ? 1 : 0, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid REJECT pid=0");
        return false;
    }

    detail::net_log_register_request req{};
    req.pid = pid;
    req.operation = enable ? 1u : 0u;

    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid SEND ioctl=0x%08X pid=%u op=%u size=%u",
        ioctl_codes::NLOG(), req.pid, req.operation, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::NLOG(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid RESULT pid=%u op=%u result=%u ok=%d",
        pid, req.operation, req.result, ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::malware_safe_pull_packets(std::uint32_t pid,
                                                  std::uint32_t max_records,
                                                  std::vector<detail::net_packet_record>& out,
                                                  std::uint64_t* out_dropped_since_last_pull) noexcept
{
    out.clear();
    if (out_dropped_since_last_pull) *out_dropped_since_last_pull = 0;
    if (!is_connected()) return false;
    if (pid == 0) return false;
    if (max_records == 0) max_records = detail::NET_PKT_PULL_RING_CAPACITY;
    if (max_records > detail::NET_PKT_PULL_RING_CAPACITY) max_records = detail::NET_PKT_PULL_RING_CAPACITY;

    const std::size_t request_size = sizeof(detail::net_packet_pull_request);
    const std::size_t response_size = sizeof(detail::net_packet_pull_response_header) +
        static_cast<std::size_t>(max_records) * sizeof(detail::net_packet_record);
    const std::size_t total_size = (request_size > response_size) ? request_size : response_size;
    if (total_size > 0xFFFFFFFFu) return false;

    std::unique_ptr<std::uint8_t[]> buf(new (std::nothrow) std::uint8_t[total_size]);
    if (!buf) return false;
    std::memset(buf.get(), 0, total_size);

    auto* req = reinterpret_cast<detail::net_packet_pull_request*>(buf.get());
    req->pid = pid;
    req->max_records = max_records;
    req->reserved = 0;
    req->padding = 0;

    DWORD dw_size = static_cast<DWORD>(total_size);
    if (!send_request(ioctl_codes::NPKT(), buf.get(), dw_size)) {
        return false;
    }

    auto* resp = reinterpret_cast<detail::net_packet_pull_response_header*>(buf.get());
    if (resp->magic != detail::NET_PKT_PULL_RESP_MAGIC) {
        return false;
    }
    std::uint32_t count = resp->record_count;
    if (count > max_records) count = max_records;
    if (out_dropped_since_last_pull) *out_dropped_since_last_pull = resp->dropped_since_last_pull;

    if (count > 0) {
        const auto* recs = reinterpret_cast<const detail::net_packet_record*>(
            buf.get() + sizeof(detail::net_packet_pull_response_header));
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            out.push_back(recs[i]);
        }
    }
    return true;
}
bool voyager::device_t::drain_debug_events(std::vector<debug_event_record>& out,
                                           std::size_t max_events,
                                           debug_event_drain_stats* out_stats) noexcept {
    out.clear();
    if (out_stats) {
        *out_stats = debug_event_drain_stats{};
    }

    if (!is_connected()) {
        return false;
    }

    if (max_events == 0) {
        return true;
    }

    if (max_events > detail::DRAIN_DEBUG_EVENTS_CAP) {
        max_events = detail::DRAIN_DEBUG_EVENTS_CAP;
    }

    auto buffer = std::make_unique<detail::drain_debug_events_request>();
    std::memset(buffer.get(), 0, sizeof(*buffer));
    buffer->max_events = static_cast<std::uint32_t>(max_events);

    if (!send_request(ioctl_codes::EVTS(), buffer.get(),
                      static_cast<DWORD>(sizeof(*buffer)))) {
        return false;
    }

    std::uint32_t count = buffer->returned_count;
    if (count > detail::DRAIN_DEBUG_EVENTS_CAP) {
        count = detail::DRAIN_DEBUG_EVENTS_CAP;
    }

    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const detail::debug_event_t& src = buffer->events[i];
        debug_event_record rec;
        rec.type = static_cast<debug_event_type_e>(src.event_type);
        rec.process_id = src.process_id;
        rec.thread_id = src.thread_id;
        rec.flags = src.flags;
        rec.timestamp = src.timestamp;
        rec.image_base = src.image_base;
        rec.image_size = src.image_size;

        std::size_t path_chars = 0;
        while (path_chars < detail::DEBUG_EVENT_PATH_CHARS &&
               src.image_path[path_chars] != L'\0') {
            ++path_chars;
        }
        if (path_chars > 0) {
            rec.image_path.assign(src.image_path, src.image_path + path_chars);
        }

        out.push_back(std::move(rec));
    }

    if (out_stats) {
        out_stats->returned_count = buffer->returned_count;
        out_stats->dropped_since_last_drain = buffer->dropped_since_last_drain;
        out_stats->total_dropped = buffer->total_dropped;
        out_stats->total_published = buffer->total_published;
    }

    return true;
}
