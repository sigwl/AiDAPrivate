#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <userenv.h>
#include <objbase.h>
#include <objidl.h>
#include <oleauto.h>
#include <comdef.h>
#include <netfw.h>
#include <shlwapi.h>
#include <processthreadsapi.h>
#include <jobapi2.h>
#include <jobapi.h>
#include <winsafer.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>

#include "run_target.hpp"
#include "vm_guest_bridge.hpp"
#include "standalone_driver.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <locale>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
    ProcThreadAttributeValue(7, FALSE, TRUE, FALSE)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
#define PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE                                        0x00000001ULL
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
#define PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE                              0x00000002ULL
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE
#define PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE                                      0x00000004ULL
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON                   (0x00000001ULL << 8)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON                          (0x00000001ULL << 12)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON                          (0x00000001ULL << 16)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON                       (0x00000001ULL << 20)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON                    (0x00000001ULL << 24)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON              (0x00000001ULL << 28)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON                 (0x00000001ULL << 32)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON                      (0x00000001ULL << 40)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON            (0x00000001ULL << 44)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON                            (0x00000001ULL << 48)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON                    (0x00000001ULL << 52)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON                 (0x00000001ULL << 56)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON              (0x00000001ULL << 60)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_ALWAYS_ON            (0x00000001ULL << 4)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON              (0x00000001ULL << 8)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON            (0x00000001ULL << 12)
#endif

namespace run_target {

namespace {

struct co_init_scope_t {
	bool need_uninit = false;
	bool ok = false;
	co_init_scope_t() {
		HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		if (hr == RPC_E_CHANGED_MODE) {
			ok = true;
			need_uninit = false;
		} else if (SUCCEEDED(hr)) {
			ok = true;
			need_uninit = true;
		} else if (hr == S_FALSE) {
			ok = true;
			need_uninit = true;
		} else {
			ok = false;
			need_uninit = false;
		}
	}
	~co_init_scope_t() {
		if (need_uninit) CoUninitialize();
	}
	co_init_scope_t(const co_init_scope_t&) = delete;
	co_init_scope_t& operator=(const co_init_scope_t&) = delete;
};

std::string narrow_utf8(const std::wstring& w) {
	if (w.empty()) return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
	return out;
}

std::wstring widen_utf8(const std::string& s) {
	if (s.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
	return out;
}

std::string format_win_message(DWORD err) {
	LPSTR buf = nullptr;
	DWORD n = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&buf), 0, nullptr);
	std::string out;
	if (n > 0 && buf) {
		while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == '.' || buf[n - 1] == ' ')) {
			buf[--n] = '\0';
		}
		out.assign(buf, buf + n);
	} else {
		char tmp[64];
		std::snprintf(tmp, sizeof(tmp), "Unknown error 0x%08lX", static_cast<unsigned long>(err));
		out = tmp;
	}
	if (buf) LocalFree(buf);
	return out;
}

void log_fail(const char* step, DWORD gle, const std::string& extra = {}) {
	std::string m = format_win_message(gle);
	if (!extra.empty()) {
		diag::log_tagged_critical_fmt("run_target",
			"launch_FAILED step=%s gle=%lu msg='%s' %s",
			step ? step : "?",
			static_cast<unsigned long>(gle),
			m.c_str(),
			extra.c_str());
	} else {
		diag::log_tagged_critical_fmt("run_target",
			"launch_FAILED step=%s gle=%lu msg='%s'",
			step ? step : "?",
			static_cast<unsigned long>(gle),
			m.c_str());
	}
}

std::string format_error(const char* step, DWORD gle) {
	char buf[512];
	std::string m = format_win_message(gle);
	std::snprintf(buf, sizeof(buf), "%s failed (gle=%lu): %s",
		step ? step : "step", static_cast<unsigned long>(gle), m.c_str());
	return std::string(buf);
}

struct async_create_process_state_t {
	std::vector<wchar_t> cmd_buf;
	std::wstring cwd;
	STARTUPINFOW si{};
	PROCESS_INFORMATION pi{};
	DWORD flags = 0;
	HANDLE done = nullptr;
	std::atomic<bool> abandoned{ false };
	BOOL ok = FALSE;
	DWORD gle = 0;
	std::atomic<DWORD> worker_tid{ 0 };

	~async_create_process_state_t() {
		if (abandoned.load(std::memory_order_acquire)) {
			if (pi.hProcess) TerminateProcess(pi.hProcess, 0xC0FFEEu);
			if (pi.hThread) CloseHandle(pi.hThread);
			if (pi.hProcess) CloseHandle(pi.hProcess);
		}
		if (done) CloseHandle(done);
	}
};

constexpr DWORD kCreateProcessDeadlineMs = 15000;
constexpr SIZE_T kCreateProcessWorkerStackReserve = 256u * 1024u;

DWORD WINAPI create_process_worker_proc(void* param)
{
	std::unique_ptr<std::shared_ptr<async_create_process_state_t>> owner(
		static_cast<std::shared_ptr<async_create_process_state_t>*>(param));
	std::shared_ptr<async_create_process_state_t> cp_state = *owner;
	cp_state->worker_tid.store(GetCurrentThreadId(), std::memory_order_release);
	const wchar_t* async_cwd = cp_state->cwd.empty() ? nullptr : cp_state->cwd.c_str();
	PROCESS_INFORMATION local_pi{};
	BOOL local_ok = CreateProcessW(
		nullptr,
		cp_state->cmd_buf.data(),
		nullptr, nullptr, FALSE,
		cp_state->flags,
		nullptr,
		async_cwd,
		&cp_state->si,
		&local_pi);
	cp_state->gle = local_ok ? 0 : GetLastError();
	cp_state->ok = local_ok;
	cp_state->pi = local_pi;
	if (cp_state->abandoned.load(std::memory_order_acquire)) {
		if (local_ok) {
			TerminateProcess(local_pi.hProcess, 0xC0FFEEu);
			CloseHandle(local_pi.hThread);
			CloseHandle(local_pi.hProcess);
			cp_state->pi = PROCESS_INFORMATION{};
		}
		diag::log_tagged_critical_fmt("run",
			"CreateProcessW.late_result ok=%d pid=%lu tid=%lu gle=%lu worker_tid=%lu",
			local_ok ? 1 : 0,
			local_ok ? local_pi.dwProcessId : 0u,
			local_ok ? local_pi.dwThreadId : 0u,
			static_cast<unsigned long>(cp_state->gle),
			static_cast<unsigned long>(cp_state->worker_tid.load(std::memory_order_acquire)));
	}
	SetEvent(cp_state->done);
	return 0;
}

uint32_t get_windows_build_number() {
	HMODULE h = GetModuleHandleW(L"ntdll.dll");
	if (!h) return 0;
	using rtl_get_version_fn = LONG (NTAPI*)(PRTL_OSVERSIONINFOW);
	rtl_get_version_fn fn = reinterpret_cast<rtl_get_version_fn>(
		reinterpret_cast<void*>(GetProcAddress(h, "RtlGetVersion")));
	if (!fn) return 0;
	RTL_OSVERSIONINFOEXW info{};
	info.dwOSVersionInfoSize = sizeof(info);
	if (fn(reinterpret_cast<PRTL_OSVERSIONINFOW>(&info)) != 0) return 0;
	return static_cast<uint32_t>(info.dwBuildNumber);
}

bool file_exists_w(const std::wstring& path) {
	DWORD a = GetFileAttributesW(path.c_str());
	return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool directory_exists_w(const std::wstring& path, DWORD* err_out = nullptr) {
	if (err_out) *err_out = 0;
	if (path.empty()) {
		if (err_out) *err_out = ERROR_PATH_NOT_FOUND;
		return false;
	}
	DWORD attrs = GetFileAttributesW(path.c_str());
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		if (err_out) *err_out = GetLastError();
		return false;
	}
	if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
		if (err_out) *err_out = ERROR_DIRECTORY;
		return false;
	}
	return true;
}

std::wstring valid_executable_parent_dir(const std::wstring& exe_path) {
	std::filesystem::path p(exe_path);
	std::filesystem::path parent = p.parent_path();
	if (parent.empty())
		return {};
	std::wstring parent_w = parent.wstring();
	DWORD err = 0;
	if (directory_exists_w(parent_w, &err))
		return parent_w;
	diag::log_tagged_critical_fmt("run_target",
		"launch exe_parent_unavailable exe='%s' parent='%s' gle=%lu",
		narrow_utf8(exe_path).c_str(),
		narrow_utf8(parent_w).c_str(),
		static_cast<unsigned long>(err));
	return {};
}

bool normalize_launch_working_dir(const launch_options_t& requested, launch_options_t& effective, launch_result_t& out) {
	effective = requested;
	const std::wstring parent = valid_executable_parent_dir(requested.exe_path);
	if (requested.working_dir.empty()) {
		if (!parent.empty()) {
			effective.working_dir = parent;
			diag::log_tagged_critical_fmt("run_target",
				"launch cwd_defaulted_to_exe_parent exe='%s' cwd='%s'",
				narrow_utf8(requested.exe_path).c_str(),
				narrow_utf8(effective.working_dir).c_str());
		}
		return true;
	}

	DWORD cwd_err = 0;
	if (directory_exists_w(requested.working_dir, &cwd_err))
		return true;

	if (!parent.empty()) {
		effective.working_dir = parent;
		diag::log_tagged_critical_fmt("run_target",
			"launch cwd_normalized requested='%s' effective='%s' gle=%lu exe='%s'",
			narrow_utf8(requested.working_dir).c_str(),
			narrow_utf8(effective.working_dir).c_str(),
			static_cast<unsigned long>(cwd_err),
			narrow_utf8(requested.exe_path).c_str());
		return true;
	}

	out.error = format_error("Working directory validation", cwd_err == 0 ? ERROR_DIRECTORY : cwd_err);
	diag::log_tagged_critical_fmt("run_target",
		"launch_REJECTED invalid_working_dir requested='%s' gle=%lu exe='%s'",
		narrow_utf8(requested.working_dir).c_str(),
		static_cast<unsigned long>(cwd_err),
		narrow_utf8(requested.exe_path).c_str());
	return false;
}

std::wstring resolve_windows_sandbox_exe() {
	wchar_t sysroot[MAX_PATH] = {};
	UINT n = GetSystemDirectoryW(sysroot, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return {};
	std::wstring p = std::wstring(sysroot) + L"\\WindowsSandbox.exe";
	if (!file_exists_w(p)) return {};
	return p;
}

std::filesystem::path current_module_dir() {
	wchar_t module_path[MAX_PATH] = {};
	DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return {};
	return std::filesystem::path(module_path).parent_path();
}

std::wstring resolve_guest_agent_exe() {
	std::filesystem::path module_dir = current_module_dir();
	if (module_dir.empty()) return {};
	std::filesystem::path agent = module_dir / L"AiDAGuestAgent.exe";
	if (!file_exists_w(agent.wstring())) return {};
	return agent.wstring();
}

void stage_file_if_present(const std::filesystem::path& src, const std::filesystem::path& dst_dir) {
	std::error_code ec;
	if (src.empty() || !std::filesystem::exists(src, ec) || ec)
		return;
	ec.clear();
	std::filesystem::copy_file(src, dst_dir / src.filename(),
		std::filesystem::copy_options::overwrite_existing, ec);
	diag::log_tagged_critical_fmt("run_target",
		"stage_dependency name='%s' copied=%d ec=%d msg='%s'",
		narrow_utf8(src.filename().wstring()).c_str(),
		ec ? 0 : 1,
		ec.value(),
		ec.message().c_str());
}

void stage_directory_if_present(const std::filesystem::path& src,
                                const std::filesystem::path& dst,
                                const char* label) {
	std::error_code ec;
	if (src.empty() || !std::filesystem::exists(src, ec) || ec)
		return;
	ec.clear();
	if (!std::filesystem::is_directory(src, ec) || ec)
		return;
	ec.clear();
	std::filesystem::create_directories(dst.parent_path(), ec);
	if (ec) {
		diag::log_tagged_critical_fmt("run_target",
			"stage_dependency_dir name='%s' copied=0 src='%s' dst='%s' ec=%d msg='%s'",
			label,
			narrow_utf8(src.wstring()).c_str(),
			narrow_utf8(dst.wstring()).c_str(),
			ec.value(),
			ec.message().c_str());
		return;
	}
	ec.clear();
	std::filesystem::copy(src, dst,
		std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
		ec);
	diag::log_tagged_critical_fmt("run_target",
		"stage_dependency_dir name='%s' copied=%d src='%s' dst='%s' ec=%d msg='%s'",
		label,
		ec ? 0 : 1,
		narrow_utf8(src.wstring()).c_str(),
		narrow_utf8(dst.wstring()).c_str(),
		ec.value(),
		ec.message().c_str());
}

std::wstring lowercase_ascii(std::wstring value) {
	for (wchar_t& ch : value) {
		if (ch >= L'A' && ch <= L'Z')
			ch = static_cast<wchar_t>(ch - L'A' + L'a');
	}
	return value;
}

bool starts_with_w(const std::wstring& value, const wchar_t* prefix) {
	if (prefix == nullptr) return false;
	size_t i = 0;
	for (; prefix[i] != L'\0'; ++i) {
		if (i >= value.size() || value[i] != prefix[i])
			return false;
	}
	return true;
}

bool is_runtime_dependency_filename(const std::wstring& filename) {
	std::wstring lower = lowercase_ascii(filename);
	return lower == L"msvcp140.dll"
		|| lower == L"msvcp140_1.dll"
		|| lower == L"msvcp140_2.dll"
		|| lower == L"msvcp140_atomic_wait.dll"
		|| lower == L"msvcp140_codecvt_ids.dll"
		|| lower == L"vcruntime140.dll"
		|| lower == L"vcruntime140_1.dll"
		|| lower == L"vcruntime140_threads.dll"
		|| lower == L"vccorlib140.dll"
		|| lower == L"vcomp140.dll"
		|| lower == L"concrt140.dll"
		|| lower == L"ucrtbase.dll"
		|| lower == L"d3dcompiler_47.dll"
		|| starts_with_w(lower, L"api-ms-win-crt-")
		|| starts_with_w(lower, L"api-ms-win-core-");
}

void stage_runtime_dependency_directory(const std::filesystem::path& root,
                                        const std::filesystem::path& dst_dir) {
	std::error_code ec;
	if (root.empty() || !std::filesystem::exists(root, ec) || ec)
		return;
	for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
		if (ec) {
			ec.clear();
			break;
		}
		if (!entry.is_regular_file(ec)) {
			ec.clear();
			continue;
		}
		const std::wstring filename = entry.path().filename().wstring();
		if (!is_runtime_dependency_filename(filename))
			continue;
		stage_file_if_present(entry.path(), dst_dir);
	}
}

void stage_common_runtime_dependencies(const std::filesystem::path& host_input) {
	std::vector<std::filesystem::path> roots;
	wchar_t sysdir[MAX_PATH] = {};
	UINT sys_n = GetSystemDirectoryW(sysdir, MAX_PATH);
	if (sys_n > 0 && sys_n < MAX_PATH)
		roots.emplace_back(sysdir);

	std::filesystem::path module_dir;
	wchar_t module_path[MAX_PATH] = {};
	DWORD module_n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
	if (module_n > 0 && module_n < MAX_PATH) {
		module_dir = std::filesystem::path(module_path).parent_path();
		roots.emplace_back(module_dir);
	}

	const wchar_t* names[] = {
		L"MSVCP140.dll",
		L"MSVCP140_1.dll",
		L"MSVCP140_2.dll",
		L"MSVCP140_ATOMIC_WAIT.dll",
		L"MSVCP140_CODECVT_IDS.dll",
		L"VCRUNTIME140.dll",
		L"VCRUNTIME140_1.dll",
		L"VCRUNTIME140_THREADS.dll",
		L"VCOMP140.dll",
		L"concrt140.dll",
		L"vccorlib140.dll",
		L"ucrtbase.dll",
		L"D3DCompiler_47.dll",
		L"api-ms-win-crt-conio-l1-1-0.dll",
		L"api-ms-win-crt-convert-l1-1-0.dll",
		L"api-ms-win-crt-environment-l1-1-0.dll",
		L"api-ms-win-crt-filesystem-l1-1-0.dll",
		L"api-ms-win-crt-heap-l1-1-0.dll",
		L"api-ms-win-crt-locale-l1-1-0.dll",
		L"api-ms-win-crt-math-l1-1-0.dll",
		L"api-ms-win-crt-multibyte-l1-1-0.dll",
		L"api-ms-win-crt-private-l1-1-0.dll",
		L"api-ms-win-crt-process-l1-1-0.dll",
		L"api-ms-win-crt-runtime-l1-1-0.dll",
		L"api-ms-win-crt-stdio-l1-1-0.dll",
		L"api-ms-win-crt-string-l1-1-0.dll",
		L"api-ms-win-crt-time-l1-1-0.dll",
		L"api-ms-win-crt-utility-l1-1-0.dll"
	};
	for (const wchar_t* name : names) {
		bool copied = false;
		for (const auto& root : roots) {
			std::error_code ec;
			std::filesystem::path src = root / name;
			if (!std::filesystem::exists(src, ec) || ec)
				continue;
			stage_file_if_present(src, host_input);
			copied = true;
			break;
		}
		if (!copied) {
			diag::log_tagged_critical_fmt("run_target",
				"stage_dependency_missing name='%s'",
				narrow_utf8(name).c_str());
		}
	}
	if (!module_dir.empty())
		stage_runtime_dependency_directory(module_dir, host_input);
}

void stage_packaged_analysis_dependencies(const std::filesystem::path& host_input) {
	std::filesystem::path module_dir = current_module_dir();
	if (module_dir.empty())
		return;
	stage_directory_if_present(module_dir / L"ghidra_specs",
		host_input / L"ghidra_specs",
		"ghidra_specs");
	stage_directory_if_present(module_dir / L"deps" / L"ghidra_specs",
		host_input / L"deps" / L"ghidra_specs",
		"deps_ghidra_specs");
	stage_directory_if_present(module_dir / L"test_binaries" / L"target_protocol",
		host_input / L"test_binaries" / L"target_protocol",
		"target_protocol");
	stage_directory_if_present(module_dir / L"deps" / L"test_binaries" / L"target_protocol",
		host_input / L"deps" / L"test_binaries" / L"target_protocol",
		"deps_target_protocol");
}

std::string make_unique_rule_name() {
	GUID g{};
	if (CoCreateGuid(&g) != S_OK) {
		auto tick = static_cast<uint64_t>(GetTickCount64());
		char buf[64];
		std::snprintf(buf, sizeof(buf), "AiDA-Run-%llu-%lu",
			static_cast<unsigned long long>(tick),
			static_cast<unsigned long>(GetCurrentProcessId()));
		return std::string(buf);
	}
	char buf[80];
	std::snprintf(buf, sizeof(buf),
		"AiDA-Run-%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		static_cast<unsigned long>(g.Data1), g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
	return std::string(buf);
}

bool firewall_add_block_rule(const std::wstring& exe_path,
                              const std::string& rule_name_utf8,
                              std::string* fail_reason) {
	co_init_scope_t coscope;
	if (!coscope.ok) {
		if (fail_reason) *fail_reason = "CoInitializeEx failed";
		return false;
	}

	INetFwPolicy2* policy = nullptr;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
		reinterpret_cast<void**>(&policy));
	if (FAILED(hr) || !policy) {
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "CoCreate NetFwPolicy2 hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	INetFwRules* rules = nullptr;
	hr = policy->get_Rules(&rules);
	if (FAILED(hr) || !rules) {
		policy->Release();
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "get_Rules hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	INetFwRule* rule = nullptr;
	hr = CoCreateInstance(__uuidof(NetFwRule), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
		reinterpret_cast<void**>(&rule));
	if (FAILED(hr) || !rule) {
		rules->Release();
		policy->Release();
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "CoCreate NetFwRule hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	auto sysalloc_w = [](const wchar_t* s) -> BSTR {
		return SysAllocString(s ? s : L"");
	};

	std::wstring rule_name_w = widen_utf8(rule_name_utf8);
	std::wstring desc_w = L"AiDA Run Target outbound block (auto-cleaned).";

	BSTR b_name = sysalloc_w(rule_name_w.c_str());
	BSTR b_desc = sysalloc_w(desc_w.c_str());
	BSTR b_path = sysalloc_w(exe_path.c_str());
	BSTR b_grouping = sysalloc_w(L"AiDA Run Target");

	bool ok = true;
	HRESULT lasthr = S_OK;
	auto check = [&](HRESULT h, const char* label) {
		if (FAILED(h)) {
			ok = false;
			lasthr = h;
			if (fail_reason && fail_reason->empty()) {
				char buf[96];
				std::snprintf(buf, sizeof(buf), "%s hr=0x%08lX",
					label, static_cast<unsigned long>(h));
				*fail_reason = buf;
			}
		}
	};

	check(rule->put_Name(b_name), "put_Name");
	check(rule->put_Description(b_desc), "put_Description");
	check(rule->put_ApplicationName(b_path), "put_ApplicationName");
	check(rule->put_Action(NET_FW_ACTION_BLOCK), "put_Action");
	check(rule->put_Direction(NET_FW_RULE_DIR_OUT), "put_Direction");
	check(rule->put_Enabled(VARIANT_TRUE), "put_Enabled");
	check(rule->put_Profiles(NET_FW_PROFILE2_ALL), "put_Profiles");
	check(rule->put_Grouping(b_grouping), "put_Grouping");

	if (ok) {
		hr = rules->Add(rule);
		if (FAILED(hr)) {
			ok = false;
			lasthr = hr;
			if (fail_reason) {
				char buf[96];
				std::snprintf(buf, sizeof(buf), "rules->Add hr=0x%08lX",
					static_cast<unsigned long>(hr));
				*fail_reason = buf;
			}
		}
	}

	SysFreeString(b_name);
	SysFreeString(b_desc);
	SysFreeString(b_path);
	SysFreeString(b_grouping);
	rule->Release();
	rules->Release();
	policy->Release();

	if (!ok) {
		(void)lasthr;
	}
	return ok;
}

bool firewall_remove_rule(const std::string& rule_name_utf8) {
	if (rule_name_utf8.empty()) return true;
	co_init_scope_t coscope;
	if (!coscope.ok) return false;

	INetFwPolicy2* policy = nullptr;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
		reinterpret_cast<void**>(&policy));
	if (FAILED(hr) || !policy) return false;

	INetFwRules* rules = nullptr;
	hr = policy->get_Rules(&rules);
	if (FAILED(hr) || !rules) {
		policy->Release();
		return false;
	}

	std::wstring name_w = widen_utf8(rule_name_utf8);
	BSTR b = SysAllocString(name_w.c_str());
	HRESULT del_hr = rules->Remove(b);
	SysFreeString(b);

	rules->Release();
	policy->Release();
	return SUCCEEDED(del_hr);
}

void spawn_watchdog_kill(HANDLE process_handle, HANDLE job_handle, uint32_t sec, uint32_t pid) {
	if (sec == 0) {
		diag::log_tagged_critical_fmt("run_target", "watchdog not installed pid=%u reason=timeout_zero", pid);
		return;
	}
	if (process_handle == nullptr) {
		diag::log_tagged_critical_fmt("run_target", "watchdog not installed pid=%u reason=null_process_handle", pid);
		return;
	}

	HANDLE dup_proc = nullptr;
	HANDLE dup_job = nullptr;
	HANDLE me = GetCurrentProcess();
	if (!DuplicateHandle(me, process_handle, me, &dup_proc, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		diag::log_tagged_critical_fmt("run_target",
			"watchdog DuplicateHandle(process) FAILED pid=%u err=%lu",
			pid, GetLastError());
		return;
	}
	if (job_handle != nullptr) {
		if (!DuplicateHandle(me, job_handle, me, &dup_job, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			diag::log_tagged_critical_fmt("run_target",
				"watchdog DuplicateHandle(job) FAILED pid=%u err=%lu",
				pid, GetLastError());
			dup_job = nullptr;
		}
	}
	diag::log_tagged_critical_fmt("run_target",
		"watchdog installed pid=%u timeout_sec=%u dup_proc=%p dup_job=%p",
		pid, sec, dup_proc, dup_job);

	const uint32_t timeout_ms = sec > (INFINITE - 1u) / 1000u
		? INFINITE - 1u
		: sec * 1000u;
	uint32_t local_pid = pid;
	try {
		const ULONGLONG post_ms = GetTickCount64();
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "runtime_target";
		sub.label = "run_target.watchdog_kill";
		sub.thread_class = "target_wait";
		sub.domain = aida::infra::executor::domain_t::long_running;
		sub.priority = 1;
		sub.target_pid = local_pid;
		sub.body = [dup_proc, dup_job, timeout_ms, local_pid, post_ms]() mutable {
			const ULONGLONG start_ms = GetTickCount64();
			const DWORD tid = GetCurrentThreadId();
			diag::log_tagged_critical_fmt("run_target",
				"watchdog worker_enter pid=%u timeout_ms=%lu queued_ms=%llu tid=%lu dup_proc=%p dup_job=%p",
				static_cast<unsigned>(local_pid),
				static_cast<unsigned long>(timeout_ms),
				static_cast<unsigned long long>(start_ms >= post_ms ? start_ms - post_ms : 0),
				static_cast<unsigned long>(tid),
				dup_proc,
				dup_job);
			DWORD w = WaitForSingleObject(dup_proc, timeout_ms);
			if (w == WAIT_TIMEOUT) {
				diag::log_tagged_critical_fmt("run_target",
					"watchdog auto_terminate pid=%u after_ms=%lu",
					static_cast<unsigned>(local_pid),
					static_cast<unsigned long>(timeout_ms));
				if (dup_job) {
					TerminateJobObject(dup_job, 0xDEAD);
				} else {
					TerminateProcess(dup_proc, 0xDEAD);
				}
			}
			if (dup_job) CloseHandle(dup_job);
			CloseHandle(dup_proc);
			diag::log_tagged_critical_fmt("run_target",
				"watchdog worker_exit pid=%u wait=0x%08lX elapsed_ms=%llu tid=%lu",
				static_cast<unsigned>(local_pid),
				static_cast<unsigned long>(w),
				static_cast<unsigned long long>(GetTickCount64() - start_ms),
				static_cast<unsigned long>(tid));
		};
		const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
		if (!posted) {
			const auto qs = aida::infra::executor::active_snapshot();
			diag::log_tagged_critical_fmt("run_target",
				"watchdog worker post failed pid=%u executor_total_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u work_pending=%llu work_active=%u",
				static_cast<unsigned>(local_pid),
				static_cast<unsigned>(qs.total_active),
				static_cast<unsigned long long>(qs.service_queue_pending),
				static_cast<unsigned>(qs.service_queue_active),
				static_cast<unsigned long long>(qs.critical_queue_pending),
				static_cast<unsigned>(qs.critical_queue_active),
				static_cast<unsigned long long>(qs.work_queue_pending),
				static_cast<unsigned>(qs.work_queue_active));
			if (dup_job) CloseHandle(dup_job);
			CloseHandle(dup_proc);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_critical_fmt("run_target",
			"watchdog worker unavailable pid=%u err=%s",
			static_cast<unsigned>(local_pid),
			ex.what());
		if (dup_job) CloseHandle(dup_job);
		CloseHandle(dup_proc);
	} catch (...) {
		diag::log_tagged_critical_fmt("run_target",
			"watchdog worker unavailable pid=%u",
			static_cast<unsigned>(local_pid));
		if (dup_job) CloseHandle(dup_job);
		CloseHandle(dup_proc);
	}
}

bool launch_jobbed(const launch_options_t& opts, launch_result_t& out, bool inherit_appcontainer);

bool launch_same_desktop(const launch_options_t& opts, launch_result_t& out) {
	return launch_jobbed(opts, out, false);
}

std::wstring resolve_local_appdata_dir() {
	PWSTR raw = nullptr;
	if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw) != S_OK || raw == nullptr) {
		wchar_t buf[MAX_PATH] = {};
		if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) > 0) {
			return std::wstring(buf);
		}
		return {};
	}
	std::wstring out(raw);
	CoTaskMemFree(raw);
	return out;
}

uint64_t make_launch_id() {
	uint64_t tick = static_cast<uint64_t>(GetTickCount64());
	uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
	uint64_t qpc = 0;
	LARGE_INTEGER li{};
	if (QueryPerformanceCounter(&li)) qpc = static_cast<uint64_t>(li.QuadPart);
	uint64_t mix = (tick << 24) ^ (pid << 8) ^ qpc;
	if (mix == 0) mix = tick + pid + 1;
	return mix;
}

std::wstring format_launch_id_hex(uint64_t v) {
	wchar_t buf[24];
	std::swprintf(buf, 24, L"%016llX", static_cast<unsigned long long>(v));
	return std::wstring(buf);
}

bool create_sandbox_directory(const std::wstring& launch_id_hex,
                              std::wstring& out_root,
                              std::string* fail_reason) {
	std::wstring local_app = resolve_local_appdata_dir();
	if (local_app.empty()) {
		if (fail_reason) *fail_reason = "LocalAppData path unavailable";
		return false;
	}
	std::filesystem::path root = std::filesystem::path(local_app) / L"AiDA" / L"Sandboxes" / launch_id_hex;
	std::error_code ec;
	std::filesystem::create_directories(root, ec);
	if (ec) {
		if (fail_reason) *fail_reason = "create sandbox root failed: " + ec.message();
		return false;
	}
	const wchar_t* subs[] = {
		L"AppData", L"AppData\\Local", L"AppData\\Roaming", L"AppData\\LocalLow",
		L"Temp", L"Tmp", L"UserProfile", L"Drops", L"Output", L"Logs"
	};
	for (auto sub : subs) {
		std::filesystem::create_directories(root / sub, ec);
		ec.clear();
	}
	out_root = root.wstring();
	return true;
}

bool build_sandbox_environment(const std::wstring& sandbox_root,
                               std::vector<wchar_t>& out_env_block) {
	wchar_t* env_strings = GetEnvironmentStringsW();
	if (env_strings == nullptr) return false;
	out_env_block.clear();

	std::wstring tmp_dir   = sandbox_root + L"\\Temp";
	std::wstring tmp_dir_alt = sandbox_root + L"\\Tmp";
	std::wstring appdata   = sandbox_root + L"\\AppData\\Roaming";
	std::wstring localapp  = sandbox_root + L"\\AppData\\Local";
	std::wstring userprof  = sandbox_root + L"\\UserProfile";

	auto upper_w = [](std::wstring s) {
		for (auto& c : s) {
			if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
		}
		return s;
	};

	auto get_var_name_upper = [&](const wchar_t* entry) -> std::wstring {
		const wchar_t* eq = wcschr(entry, L'=');
		if (eq == nullptr) return {};
		return upper_w(std::wstring(entry, eq));
	};

	const wchar_t* p = env_strings;
	while (*p) {
		std::wstring name_u = get_var_name_upper(p);
		if (!name_u.empty()
		    && name_u != L"TEMP" && name_u != L"TMP"
		    && name_u != L"APPDATA" && name_u != L"LOCALAPPDATA"
		    && name_u != L"USERPROFILE") {
			while (*p) {
				out_env_block.push_back(*p++);
			}
			out_env_block.push_back(L'\0');
			++p;
		} else {
			while (*p) ++p;
			++p;
		}
	}
	FreeEnvironmentStringsW(env_strings);

	auto push_var = [&](const wchar_t* name, const std::wstring& value) {
		while (*name) out_env_block.push_back(*name++);
		out_env_block.push_back(L'=');
		for (wchar_t c : value) out_env_block.push_back(c);
		out_env_block.push_back(L'\0');
	};
	push_var(L"TEMP",         tmp_dir);
	push_var(L"TMP",          tmp_dir_alt);
	push_var(L"APPDATA",      appdata);
	push_var(L"LOCALAPPDATA", localapp);
	push_var(L"USERPROFILE",  userprof);
	out_env_block.push_back(L'\0');
	return true;
}

bool drop_token_integrity_level(HANDLE token, bool to_untrusted) {
	const wchar_t* sddl = to_untrusted ? L"S-1-16-0" : L"S-1-16-4096";
	PSID il_sid = nullptr;
	if (!ConvertStringSidToSidW(sddl, &il_sid) || il_sid == nullptr) {
		return false;
	}
	TOKEN_MANDATORY_LABEL tml{};
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = il_sid;
	DWORD info_len = sizeof(tml) + GetLengthSid(il_sid);
	BOOL ok = SetTokenInformation(token, TokenIntegrityLevel, &tml, info_len);
	DWORD gle = ok ? 0 : GetLastError();
	LocalFree(il_sid);
	if (!ok) {
		diag::log_tagged_critical_fmt("malware_safe",
			"set_il_FAILED to_untrusted=%d gle=%lu",
			to_untrusted ? 1 : 0, static_cast<unsigned long>(gle));
		return false;
	}
	return true;
}

bool build_restricted_token(HANDLE source_token,
                            HANDLE& out_restricted,
                            std::string* fail_reason) {
	out_restricted = nullptr;
	HANDLE primary = nullptr;

	using fn_saferCreateLevel = BOOL(WINAPI*)(DWORD, DWORD, DWORD, SAFER_LEVEL_HANDLE*, LPVOID);
	using fn_saferComputeTokenFromLevel = BOOL(WINAPI*)(SAFER_LEVEL_HANDLE, HANDLE, PHANDLE, DWORD, LPVOID);
	using fn_saferCloseLevel = BOOL(WINAPI*)(SAFER_LEVEL_HANDLE);

	HMODULE adv = GetModuleHandleW(L"advapi32.dll");
	if (adv == nullptr) adv = LoadLibraryW(L"advapi32.dll");
	if (adv != nullptr) {
		fn_saferCreateLevel pCreate =
			reinterpret_cast<fn_saferCreateLevel>(
				reinterpret_cast<void*>(GetProcAddress(adv, "SaferCreateLevel")));
		fn_saferComputeTokenFromLevel pCompute =
			reinterpret_cast<fn_saferComputeTokenFromLevel>(
				reinterpret_cast<void*>(GetProcAddress(adv, "SaferComputeTokenFromLevel")));
		fn_saferCloseLevel pClose =
			reinterpret_cast<fn_saferCloseLevel>(
				reinterpret_cast<void*>(GetProcAddress(adv, "SaferCloseLevel")));

		if (pCreate && pCompute && pClose) {
			SAFER_LEVEL_HANDLE level = nullptr;
			if (pCreate(SAFER_SCOPEID_USER, SAFER_LEVELID_CONSTRAINED, 0, &level, nullptr) && level) {
				HANDLE safer_tok = nullptr;
				if (pCompute(level, source_token, &safer_tok, 0, nullptr) && safer_tok) {
					primary = safer_tok;
				} else {
					DWORD gle = GetLastError();
					diag::log_tagged_critical_fmt("malware_safe",
						"safer_compute_FAILED gle=%lu", static_cast<unsigned long>(gle));
				}
				pClose(level);
			} else {
				DWORD gle = GetLastError();
				diag::log_tagged_critical_fmt("malware_safe",
					"safer_create_FAILED gle=%lu", static_cast<unsigned long>(gle));
			}
		}
	}

	if (primary == nullptr) {
		HANDLE restricted = nullptr;
		if (!CreateRestrictedToken(
				source_token,
				DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
				0, nullptr,
				0, nullptr,
				0, nullptr,
				&restricted) || restricted == nullptr) {
			DWORD gle = GetLastError();
			if (fail_reason) {
				char tmp[96];
				std::snprintf(tmp, sizeof(tmp),
					"CreateRestrictedToken gle=%lu", static_cast<unsigned long>(gle));
				*fail_reason = tmp;
			}
			diag::log_tagged_critical_fmt("malware_safe",
				"create_restricted_token_FAILED gle=%lu",
				static_cast<unsigned long>(gle));
			return false;
		}
		primary = restricted;
	}

	HANDLE dup = nullptr;
	if (!DuplicateTokenEx(primary, MAXIMUM_ALLOWED, nullptr,
	                     SecurityImpersonation, TokenPrimary, &dup) || dup == nullptr) {
		DWORD gle = GetLastError();
		if (fail_reason) {
			char tmp[96];
			std::snprintf(tmp, sizeof(tmp),
				"DuplicateTokenEx gle=%lu", static_cast<unsigned long>(gle));
			*fail_reason = tmp;
		}
		CloseHandle(primary);
		return false;
	}
	CloseHandle(primary);

	out_restricted = dup;
	return true;
}

bool grant_sandbox_dir_access(const std::wstring& sandbox_root) {
	PSID everyone_sid = nullptr;
	SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
	if (!AllocateAndInitializeSid(&world_authority, 1,
	                              SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid)
	    || everyone_sid == nullptr) {
		return false;
	}

	EXPLICIT_ACCESSW ea{};
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode        = SET_ACCESS;
	ea.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName    = reinterpret_cast<LPWSTR>(everyone_sid);

	PACL new_acl = nullptr;
	DWORD r = SetEntriesInAclW(1, &ea, nullptr, &new_acl);
	bool ok = false;
	if (r == ERROR_SUCCESS && new_acl) {
		DWORD set_r = SetNamedSecurityInfoW(
			const_cast<LPWSTR>(sandbox_root.c_str()),
			SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
			nullptr, nullptr, new_acl, nullptr);
		ok = (set_r == ERROR_SUCCESS);
		if (!ok) {
			diag::log_tagged_critical_fmt("malware_safe",
				"sandbox_dir_acl_FAILED r=%lu", static_cast<unsigned long>(set_r));
		}
	} else {
		diag::log_tagged_critical_fmt("malware_safe",
			"set_entries_in_acl_FAILED r=%lu", static_cast<unsigned long>(r));
	}
	if (new_acl) LocalFree(new_acl);
	FreeSid(everyone_sid);
	return ok;
}

bool try_register_kernel_sandbox_guard(uint32_t pid, bool log_network, bool block_child_spawn) {
	if (pid == 0) return false;
	if (!driver_bridge::is_loaded()) {
		diag::log_tagged_critical_fmt("malware_safe",
			"kernel_register_skip driver_not_loaded pid=%u", pid);
		return false;
	}
	bool any_ok = false;
	uint32_t flags =
		  0x00000001u
		| 0x00000002u
		| 0x00000004u
		| 0x00000008u;
	if (log_network) flags |= 0x00000010u;
	if (block_child_spawn) flags |= 0x00000020u;
	bool protect_ok = driver_bridge::malware_safe_protect_pid(pid, flags, nullptr);
	diag::log_tagged_critical_fmt("malware_safe",
		"kernel_protect_sandbox pid=%u flags=0x%08X ok=%d", pid, flags, protect_ok ? 1 : 0);
	if (protect_ok) any_ok = true;

	if (log_network) {
		bool net_ok = driver_bridge::malware_safe_net_log(pid, true);
		bool started = driver_bridge::start_capture(pid, 0, 0, nullptr, 1500);
		diag::log_tagged_critical_fmt("malware_safe",
			"kernel_net_log_register pid=%u net_log=%d start_capture=%d",
			pid, net_ok ? 1 : 0, started ? 1 : 0);
		if (net_ok || started) any_ok = true;
	}
	return any_ok;
}

void try_unregister_kernel_sandbox_guard(uint32_t pid) {
	if (pid == 0) return;
	if (!driver_bridge::is_loaded()) return;
	bool stopped = driver_bridge::stop_capture();
	bool net_off = driver_bridge::malware_safe_net_log(pid, false);
	bool unprotect = driver_bridge::malware_safe_unprotect_pid(pid, nullptr);
	diag::log_tagged_critical_fmt("malware_safe",
		"kernel_unregister pid=%u stop_capture=%d net_off=%d unprotect=%d",
		pid, stopped ? 1 : 0, net_off ? 1 : 0, unprotect ? 1 : 0);
}

bool launch_malware_safe_desktop(const launch_options_t& opts, launch_result_t& out);


bool launch_appcontainer(const launch_options_t& opts, launch_result_t& out) {
	uint32_t build = get_windows_build_number();
	if (build < 15063) {
		out.error = "AppContainer requires Windows 10 build 15063 or newer.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_appcontainer_unsupported windows_build=%u", build);
		return false;
	}

	wchar_t name_buf[64];
	uint64_t tick = GetTickCount64();
	uint32_t self_pid = GetCurrentProcessId();
	int wn = std::swprintf(name_buf, 64, L"AiDA.RunTarget.%llu.%lu",
		static_cast<unsigned long long>(tick),
		static_cast<unsigned long>(self_pid));
	if (wn <= 0) {
		out.error = "Internal: failed to format AppContainer profile name";
		return false;
	}
	std::wstring profile_name(name_buf);
	out.appcontainer_profile_name = profile_name;
	std::wstring display_name = L"AiDA Run Target";
	std::wstring description = L"Ephemeral AppContainer profile created by AiDAStandalone.";

	PSID app_sid = nullptr;
	HRESULT hr = ::CreateAppContainerProfile(
		profile_name.c_str(), display_name.c_str(), description.c_str(),
		nullptr, 0, &app_sid);
	bool profile_existed = false;
	if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		profile_existed = true;
		hr = ::DeriveAppContainerSidFromAppContainerName(profile_name.c_str(), &app_sid);
	}
	if (FAILED(hr) || app_sid == nullptr) {
		out.error = format_error("CreateAppContainerProfile", static_cast<DWORD>(hr));
		diag::log_tagged_critical_fmt("run_target",
			"launch_appcontainer CreateAppContainerProfile_FAILED hr=0x%08lX existed=%d",
			static_cast<unsigned long>(hr), profile_existed ? 1 : 0);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer profile_ready name='%ls' existed=%d",
		profile_name.c_str(), profile_existed ? 1 : 0);

	SECURITY_CAPABILITIES sec_caps{};
	sec_caps.AppContainerSid = app_sid;
	sec_caps.Capabilities = nullptr;
	sec_caps.CapabilityCount = 0;
	sec_caps.Reserved = 0;

	SIZE_T attr_size = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
	if (attr_size == 0) {
		out.error = "InitializeProcThreadAttributeList sizing failed";
		::FreeSid(app_sid);
		return false;
	}
	std::vector<uint8_t> attr_buf(attr_size, 0);
	LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
		reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
	if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
		DWORD gle = GetLastError();
		out.error = format_error("InitializeProcThreadAttributeList", gle);
		log_fail("InitializeProcThreadAttributeList", gle);
		::FreeSid(app_sid);
		return false;
	}
	if (!UpdateProcThreadAttribute(attr_list, 0,
		PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
		&sec_caps, sizeof(sec_caps),
		nullptr, nullptr)) {
		DWORD gle = GetLastError();
		out.error = format_error("UpdateProcThreadAttribute SECURITY_CAPABILITIES", gle);
		log_fail("UpdateProcThreadAttribute", gle);
		DeleteProcThreadAttributeList(attr_list);
		::FreeSid(app_sid);
		return false;
	}

	STARTUPINFOEXW siex{};
	siex.StartupInfo.cb = sizeof(siex);
	siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	siex.StartupInfo.wShowWindow = SW_SHOWNORMAL;
	siex.lpAttributeList = attr_list;

	std::wstring cmd;
	cmd.reserve(opts.exe_path.size() + opts.args.size() + 4);
	cmd.push_back(L'"');
	cmd.append(opts.exe_path);
	cmd.push_back(L'"');
	if (!opts.args.empty()) {
		cmd.push_back(L' ');
		cmd.append(opts.args);
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	const wchar_t* cwd_ptr = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();
	DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE;
	PROCESS_INFORMATION pi{};

	BOOL cp_ok = CreateProcessW(
		nullptr,
		cmd_buf.data(),
		nullptr, nullptr, FALSE,
		flags,
		nullptr,
		cwd_ptr,
		&siex.StartupInfo,
		&pi);
	if (!cp_ok) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateProcessW (AppContainer)", gle);
		log_fail("CreateProcessW.AppContainer", gle);
		DeleteProcThreadAttributeList(attr_list);
		::FreeSid(app_sid);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer CreateProcessW ok pid=%lu tid=%lu",
		pi.dwProcessId, pi.dwThreadId);

	DeleteProcThreadAttributeList(attr_list);
	::FreeSid(app_sid);

	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateJobObjectW (AppContainer)", gle);
		log_fail("CreateJobObjectW.AppContainer", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
	DWORD lim_flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	if (opts.kill_on_host_exit) lim_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (opts.memory_cap_mb > 0) {
		lim_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = static_cast<SIZE_T>(opts.memory_cap_mb) * 1024ull * 1024ull;
	}
	jeli.BasicLimitInformation.LimitFlags = lim_flags;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
		DWORD gle = GetLastError();
		log_fail("SetInformationJobObject.AppContainer", gle);
		out.error = format_error("SetInformationJobObject (AppContainer)", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(job);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer SetInformationJobObject ok flags=0x%lX mem_mb=%u",
		static_cast<unsigned long>(lim_flags), opts.memory_cap_mb);

	if (!AssignProcessToJobObject(job, pi.hProcess)) {
		DWORD gle = GetLastError();
		log_fail("AssignProcessToJobObject.AppContainer", gle);
		out.error = format_error("AssignProcessToJobObject (AppContainer)", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(job);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer AssignProcessToJobObject ok pid=%lu",
		pi.dwProcessId);

	if (opts.block_network) {
		std::string rule = make_unique_rule_name();
		std::string fr;
		bool fok = firewall_add_block_rule(opts.exe_path, rule, &fr);
		if (fok) {
			out.firewall_rule_name = rule;
			diag::log_tagged_critical_fmt("run_target",
				"launch_appcontainer firewall_block ok rule_name='%s'", rule.c_str());
		} else {
			diag::log_tagged_critical_fmt("run_target",
				"launch_appcontainer firewall_block FAILED rule_name='%s' reason='%s'",
				rule.c_str(), fr.c_str());
		}
	}

	out.ok = true;
	out.pid = pi.dwProcessId;
	out.thread_id = pi.dwThreadId;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = reinterpret_cast<uintptr_t>(pi.hThread);
	out.job_handle = reinterpret_cast<uintptr_t>(job);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, job, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

bool launch_jobbed(const launch_options_t& opts, launch_result_t& out, bool /*inherit_appcontainer*/) {
	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateJobObjectW", gle);
		log_fail("CreateJobObjectW", gle);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed CreateJobObjectW handle=%p", static_cast<void*>(job));

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
	DWORD lim_flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	if (opts.kill_on_host_exit) lim_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (opts.memory_cap_mb > 0) {
		lim_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = static_cast<SIZE_T>(opts.memory_cap_mb) * 1024ull * 1024ull;
	}
	jeli.BasicLimitInformation.LimitFlags = lim_flags;

	BOOL set_ok = SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
	if (!set_ok) {
		DWORD gle = GetLastError();
		log_fail("SetInformationJobObject", gle);
		out.error = format_error("SetInformationJobObject", gle);
		CloseHandle(job);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed SetInformationJobObject ok=1 flags=0x%lX mem_mb=%u",
		static_cast<unsigned long>(lim_flags), opts.memory_cap_mb);

	std::wstring cmd;
	cmd.reserve(opts.exe_path.size() + opts.args.size() + 4);
	cmd.push_back(L'"');
	cmd.append(opts.exe_path);
	cmd.push_back(L'"');
	if (!opts.args.empty()) {
		cmd.push_back(L' ');
		cmd.append(opts.args);
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	STARTUPINFOW si{};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;

	PROCESS_INFORMATION pi{};
	const wchar_t* cwd_ptr = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();
	DWORD flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE;
	std::string exe_utf8 = narrow_utf8(opts.exe_path);
	std::string args_utf8 = narrow_utf8(opts.args);
	std::string cwd_utf8 = narrow_utf8(opts.working_dir);
	diag::log_tagged_critical_fmt("run",
		"CreateProcessW.invoke flags=0x%08lX exe='%s' args='%.160s' cwd='%s'",
		static_cast<unsigned long>(flags),
		exe_utf8.c_str(),
		args_utf8.c_str(),
		cwd_ptr ? cwd_utf8.c_str() : "<inherit>");

	auto cp_state = std::make_shared<async_create_process_state_t>();
	cp_state->cmd_buf = std::move(cmd_buf);
	cp_state->cwd = opts.working_dir;
	cp_state->si = si;
	cp_state->flags = flags;
	cp_state->done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!cp_state->done) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateEventW(CreateProcess deadline)", gle);
		log_fail("CreateEventW.CreateProcessDeadline", gle);
		CloseHandle(job);
		return false;
	}
	auto* worker_owner = new (std::nothrow) std::shared_ptr<async_create_process_state_t>(cp_state);
	if (!worker_owner) {
		out.error = "CreateProcessW worker start failed: shared state allocation failed";
		diag::log_tagged_critical_fmt("run_target",
			"launch_FAILED step=CreateProcessWWorkerStateAlloc exe='%s' cwd='%s'",
			exe_utf8.c_str(),
			cwd_ptr ? cwd_utf8.c_str() : "<inherit>");
		CloseHandle(job);
		return false;
	}
	DWORD create_thread_id = 0;
	SetLastError(0);
	HANDLE create_thread = CreateThread(
		nullptr,
		kCreateProcessWorkerStackReserve,
		create_process_worker_proc,
		worker_owner,
		STACK_SIZE_PARAM_IS_A_RESERVATION,
		&create_thread_id);
	DWORD create_thread_gle = create_thread ? 0 : GetLastError();
	diag::log_tagged_critical_fmt("run",
		"CreateProcessW.worker_start thread=0x%p tid=%lu gle=%lu stack_reserve=%llu flags=0x%08lX exe='%s' cwd='%s'",
		static_cast<void*>(create_thread),
		static_cast<unsigned long>(create_thread_id),
		static_cast<unsigned long>(create_thread_gle),
		static_cast<unsigned long long>(kCreateProcessWorkerStackReserve),
		static_cast<unsigned long>(flags),
		exe_utf8.c_str(),
		cwd_ptr ? cwd_utf8.c_str() : "<inherit>");
	if (!create_thread) {
		delete worker_owner;
		out.error = format_error("CreateThread(CreateProcess worker)", create_thread_gle);
		log_fail("CreateThread.CreateProcessWorker", create_thread_gle);
		CloseHandle(job);
		return false;
	}
	CloseHandle(create_thread);

	const DWORD cp_wait = WaitForSingleObject(cp_state->done, kCreateProcessDeadlineMs);
	if (cp_wait != WAIT_OBJECT_0) {
		DWORD wait_gle = cp_wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
		cp_state->abandoned.store(true, std::memory_order_release);
		char err[512];
		std::snprintf(err, sizeof(err),
			"CreateProcessW did not return within %lu ms (wait=0x%08lX gle=%lu worker_tid=%lu)",
			static_cast<unsigned long>(kCreateProcessDeadlineMs),
			static_cast<unsigned long>(cp_wait),
			static_cast<unsigned long>(wait_gle),
			static_cast<unsigned long>(cp_state->worker_tid.load(std::memory_order_acquire)));
		out.error = err;
		diag::log_tagged_critical_fmt("run",
			"CreateProcessW.timeout elapsed_ms=%lu wait=0x%08lX gle=%lu worker_tid=%lu flags=0x%08lX exe='%s' cwd='%s'",
			static_cast<unsigned long>(kCreateProcessDeadlineMs),
			static_cast<unsigned long>(cp_wait),
			static_cast<unsigned long>(wait_gle),
			static_cast<unsigned long>(cp_state->worker_tid.load(std::memory_order_acquire)),
			static_cast<unsigned long>(flags),
			exe_utf8.c_str(),
			cwd_ptr ? cwd_utf8.c_str() : "<inherit>");
		CloseHandle(job);
		return false;
	}

	BOOL cp_ok = cp_state->ok;
	DWORD cp_gle = cp_ok ? 0 : cp_state->gle;
	pi = cp_state->pi;
	cp_state->pi = PROCESS_INFORMATION{};
	diag::log_tagged_critical_fmt("run",
		"CreateProcessW.result ok=%d pid=%lu tid=%lu gle=%lu flags=0x%08lX",
		cp_ok ? 1 : 0,
		cp_ok ? pi.dwProcessId : 0u,
		cp_ok ? pi.dwThreadId : 0u,
		static_cast<unsigned long>(cp_gle),
		static_cast<unsigned long>(flags));
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed CreateProcessW ok=%d pid=%lu tid=%lu proc=%p thread=%p gle=%lu",
		cp_ok ? 1 : 0,
		cp_ok ? pi.dwProcessId : 0u,
		cp_ok ? pi.dwThreadId : 0u,
		cp_ok ? pi.hProcess : nullptr,
		cp_ok ? pi.hThread : nullptr,
		static_cast<unsigned long>(cp_gle));
	if (!cp_ok) {
		out.win32_error = cp_gle;
		out.error = format_error("CreateProcessW", cp_gle);
		log_fail("CreateProcessW", cp_gle);
		CloseHandle(job);
		return false;
	}

	BOOL assign_ok = AssignProcessToJobObject(job, pi.hProcess);
	DWORD assign_gle = assign_ok ? 0 : GetLastError();
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed AssignProcessToJobObject ok=%d gle=%lu",
		assign_ok ? 1 : 0,
		static_cast<unsigned long>(assign_gle));
	if (!assign_ok) {
		log_fail("AssignProcessToJobObject", assign_gle);
		out.error = format_error("AssignProcessToJobObject", assign_gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(job);
		return false;
	}

	if (opts.block_network) {
		std::string rule = make_unique_rule_name();
		std::string fr;
		bool fok = firewall_add_block_rule(opts.exe_path, rule, &fr);
		diag::log_tagged_critical_fmt("run_target",
			"launch_jobbed firewall_block ok=%d rule_name='%s'%s%s",
			fok ? 1 : 0, rule.c_str(),
			fok ? "" : " reason=",
			fok ? "" : fr.c_str());
		if (fok) {
			out.firewall_rule_name = rule;
		}
	}

	out.ok = true;
	out.pid = pi.dwProcessId;
	out.thread_id = pi.dwThreadId;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = reinterpret_cast<uintptr_t>(pi.hThread);
	out.job_handle = reinterpret_cast<uintptr_t>(job);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, job, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

bool launch_malware_safe_desktop(const launch_options_t& opts, launch_result_t& out) {
	diag::log_tagged_critical_fmt("malware_safe",
		"launch entry safe_mode=%d block_net=%d log_net=%d untrusted=%d allow_children=%d strict_mitigations=%d redirect_paths=%d kernel_guard=%d mem_cap=%u auto_term=%u",
		opts.malware_safe_mode ? 1 : 0,
		opts.block_network ? 1 : 0,
		opts.log_network_traffic ? 1 : 0,
		opts.lower_integrity_untrusted ? 1 : 0,
		opts.allow_child_processes ? 1 : 0,
		opts.force_mitigations_strict ? 1 : 0,
		opts.redirect_user_paths_to_sandbox ? 1 : 0,
		opts.register_kernel_sandbox_guard ? 1 : 0,
		static_cast<unsigned>(opts.memory_cap_mb),
		static_cast<unsigned>(opts.auto_terminate_sec));

	uint64_t launch_id = make_launch_id();
	std::wstring launch_id_hex = format_launch_id_hex(launch_id);
	std::wstring sandbox_root;
	{
		std::string fr;
		if (!create_sandbox_directory(launch_id_hex, sandbox_root, &fr)) {
			out.error = "Failed to create sandbox directory: " + fr;
			diag::log_tagged_critical_fmt("malware_safe",
				"sandbox_dir_create_FAILED reason='%s'", fr.c_str());
			return false;
		}
	}
	out.sandbox_dir = sandbox_root;
	diag::log_tagged_critical_fmt("malware_safe",
		"sandbox_dir_ready path='%s' launch_id=%016llX",
		narrow_utf8(sandbox_root).c_str(),
		static_cast<unsigned long long>(launch_id));

	grant_sandbox_dir_access(sandbox_root);

	HANDLE own_token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),
	                     TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY
	                     | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS,
	                     &own_token) || own_token == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("OpenProcessToken", gle);
		log_fail("OpenProcessToken.malware_safe", gle);
		return false;
	}

	HANDLE restricted_token = nullptr;
	{
		std::string fr;
		if (!build_restricted_token(own_token, restricted_token, &fr)) {
			out.error = "Failed to build restricted token: " + fr;
			CloseHandle(own_token);
			return false;
		}
	}
	CloseHandle(own_token);

	bool il_lowered = drop_token_integrity_level(restricted_token, opts.lower_integrity_untrusted);
	out.integrity_lowered = il_lowered;
	out.token_restricted = true;
	diag::log_tagged_critical_fmt("malware_safe",
		"token_built restricted=1 integrity_lowered=%d untrusted=%d",
		il_lowered ? 1 : 0,
		opts.lower_integrity_untrusted ? 1 : 0);

	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateJobObjectW (malware_safe)", gle);
		log_fail("CreateJobObjectW.malware_safe", gle);
		CloseHandle(restricted_token);
		return false;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
	DWORD lim_flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	                | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
	jeli.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
	if (opts.kill_on_host_exit) lim_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	lim_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	jeli.BasicLimitInformation.ActiveProcessLimit = opts.allow_child_processes ? 64 : 1;
	if (opts.memory_cap_mb > 0) {
		lim_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = static_cast<SIZE_T>(opts.memory_cap_mb) * 1024ull * 1024ull;
	}
	jeli.BasicLimitInformation.LimitFlags = lim_flags;

	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
		DWORD gle = GetLastError();
		out.error = format_error("SetInformationJobObject (malware_safe)", gle);
		log_fail("SetInformationJobObject.malware_safe", gle);
		CloseHandle(job);
		CloseHandle(restricted_token);
		return false;
	}
	diag::log_tagged_critical_fmt("malware_safe",
		"job_ext_limits ok flags=0x%lX active_proc_limit=%u mem_mb=%u",
		static_cast<unsigned long>(lim_flags),
		static_cast<unsigned>(jeli.BasicLimitInformation.ActiveProcessLimit),
		opts.memory_cap_mb);

	JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
	ui.UIRestrictionsClass =
		JOB_OBJECT_UILIMIT_DESKTOP
		| JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
		| JOB_OBJECT_UILIMIT_EXITWINDOWS
		| JOB_OBJECT_UILIMIT_GLOBALATOMS
		| JOB_OBJECT_UILIMIT_HANDLES
		| JOB_OBJECT_UILIMIT_READCLIPBOARD
		| JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
		| JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui))) {
		DWORD gle = GetLastError();
		diag::log_tagged_critical_fmt("malware_safe",
			"job_ui_limits_FAILED gle=%lu", static_cast<unsigned long>(gle));
	} else {
		diag::log_tagged_critical_fmt("malware_safe",
			"job_ui_limits ok mask=0x%lX", static_cast<unsigned long>(ui.UIRestrictionsClass));
	}

	uint32_t windows_build = get_windows_build_number();

	DWORD64 mitig_policy = 0;
	DWORD64 mitig_policy2 = 0;
	mitig_policy |=
		PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
		| PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
		| PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE
		| PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
		| PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
	if (opts.force_mitigations_strict) {
		mitig_policy |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
		mitig_policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
		mitig_policy2 |= PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_ALWAYS_ON;
		mitig_policy2 |= PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON;
	}

	bool use_v2_mitig = (windows_build >= 17134);
	DWORD64 mitig_arr[2] = { mitig_policy, mitig_policy2 };

	SIZE_T attr_size = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
	if (attr_size == 0) {
		out.error = "Internal: InitializeProcThreadAttributeList sizing failed";
		CloseHandle(job);
		CloseHandle(restricted_token);
		return false;
	}
	std::vector<uint8_t> attr_buf(attr_size, 0);
	LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
		reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
	if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
		DWORD gle = GetLastError();
		out.error = format_error("InitializeProcThreadAttributeList (malware_safe)", gle);
		log_fail("InitializeProcThreadAttributeList.malware_safe", gle);
		CloseHandle(job);
		CloseHandle(restricted_token);
		return false;
	}

	BOOL mitig_attr_ok = UpdateProcThreadAttribute(attr_list, 0,
		PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
		mitig_arr,
		use_v2_mitig ? sizeof(mitig_arr) : sizeof(mitig_arr[0]),
		nullptr, nullptr);
	if (!mitig_attr_ok) {
		DWORD gle = GetLastError();
		diag::log_tagged_critical_fmt("malware_safe",
			"mitigation_attribute_FAILED gle=%lu (continuing without mitigation policy)",
			static_cast<unsigned long>(gle));
		DeleteProcThreadAttributeList(attr_list);
		attr_buf.clear();
		attr_size = 0;
		InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
		attr_buf.assign(attr_size, 0);
		attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
		if (!InitializeProcThreadAttributeList(attr_list, 0, 0, &attr_size)) {
			DWORD gle2 = GetLastError();
			out.error = format_error("InitializeProcThreadAttributeList retry", gle2);
			CloseHandle(job);
			CloseHandle(restricted_token);
			return false;
		}
	} else {
		out.mitigations_applied = true;
		diag::log_tagged_critical_fmt("malware_safe",
			"mitigation_attribute ok v2=%d policy=0x%016llX policy2=0x%016llX",
			use_v2_mitig ? 1 : 0,
			static_cast<unsigned long long>(mitig_policy),
			static_cast<unsigned long long>(mitig_policy2));
	}

	std::wstring cmd;
	cmd.reserve(opts.exe_path.size() + opts.args.size() + 4);
	cmd.push_back(L'"');
	cmd.append(opts.exe_path);
	cmd.push_back(L'"');
	if (!opts.args.empty()) {
		cmd.push_back(L' ');
		cmd.append(opts.args);
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	std::wstring working_dir_w = opts.working_dir;
	if (working_dir_w.empty()) {
		std::filesystem::path exe_path(opts.exe_path);
		std::error_code ec;
		auto parent = exe_path.parent_path();
		if (!parent.empty() && std::filesystem::exists(parent, ec)) {
			working_dir_w = parent.wstring();
		}
	}

	std::vector<wchar_t> env_block;
	const wchar_t* env_ptr = nullptr;
	bool env_redirected = false;
	if (opts.redirect_user_paths_to_sandbox) {
		if (build_sandbox_environment(sandbox_root, env_block) && !env_block.empty()) {
			env_redirected = true;
			diag::log_tagged_critical_fmt("malware_safe",
				"env_redirected appdata='%s\\AppData\\Roaming' temp='%s\\Temp'",
				narrow_utf8(sandbox_root).c_str(),
				narrow_utf8(sandbox_root).c_str());
		} else {
			diag::log_tagged_critical("malware_safe",
				"env_redirect_FAILED proceeding_with_inherited_env");
		}
	}
	if (!env_redirected) {
		wchar_t* inherited = GetEnvironmentStringsW();
		if (inherited != nullptr) {
			const wchar_t* p = inherited;
			while (*p) {
				while (*p) env_block.push_back(*p++);
				env_block.push_back(L'\0');
				++p;
			}
			env_block.push_back(L'\0');
			FreeEnvironmentStringsW(inherited);
		}
	}
	{
		auto push_var = [&](const wchar_t* name, const wchar_t* value) {
			while (*name) env_block.push_back(*name++);
			env_block.push_back(L'=');
			while (*value) env_block.push_back(*value++);
			env_block.push_back(L'\0');
		};
		if (env_block.empty()) {
			env_block.push_back(L'\0');
		}
		if (!env_block.empty() && env_block.back() == L'\0') {
			env_block.pop_back();
		}
		uint32_t tester_flags = 0;
		tester_flags |= 0x00000001u;
		tester_flags |= 0x00000002u;
		tester_flags |= 0x00000004u;
		tester_flags |= 0x00000008u;
		if (opts.log_network_traffic) tester_flags |= 0x00000010u;
		if (!opts.allow_child_processes) tester_flags |= 0x00000020u;
		if (opts.block_network) tester_flags |= 0x00010000u;
		if (opts.lower_integrity_untrusted) tester_flags |= 0x00020000u;
		if (opts.force_mitigations_strict) tester_flags |= 0x00040000u;
		if (opts.redirect_user_paths_to_sandbox) tester_flags |= 0x00080000u;
		if (opts.register_kernel_sandbox_guard) tester_flags |= 0x00100000u;
		tester_flags |= 0x80000000u;
		wchar_t flag_str[20] = {};
		_snwprintf_s(flag_str, _countof(flag_str), _TRUNCATE,
			L"0x%08X", tester_flags);
		push_var(L"AIDA_MALWARESAFE_SANDBOXED", L"1");
		push_var(L"AIDA_MALWARESAFE_FLAGS", flag_str);
		push_var(L"AIDA_MALWARESAFE_LAUNCH_ID", launch_id_hex.c_str());
		push_var(L"AIDA_MALWARESAFE_SANDBOX_ROOT", sandbox_root.c_str());
		env_block.push_back(L'\0');
		env_ptr = env_block.data();
		diag::log_tagged_critical_fmt("malware_safe",
			"env_injected_tester_vars flags=0x%08X sandbox_root='%s'",
			tester_flags, narrow_utf8(sandbox_root).c_str());
	}

	STARTUPINFOEXW siex{};
	siex.StartupInfo.cb = sizeof(siex);
	siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	siex.StartupInfo.wShowWindow = SW_SHOWNORMAL;
	siex.lpAttributeList = attr_list;

	DWORD flags =
		EXTENDED_STARTUPINFO_PRESENT
		| CREATE_SUSPENDED
		| CREATE_NEW_CONSOLE
		| CREATE_DEFAULT_ERROR_MODE
		| CREATE_UNICODE_ENVIRONMENT;

	PROCESS_INFORMATION pi{};
	const wchar_t* cwd_ptr = working_dir_w.empty() ? nullptr : working_dir_w.c_str();

	BOOL cp_ok = CreateProcessAsUserW(
		restricted_token,
		nullptr,
		cmd_buf.data(),
		nullptr, nullptr, FALSE,
		flags,
		const_cast<wchar_t*>(env_ptr),
		cwd_ptr,
		&siex.StartupInfo,
		&pi);
	DWORD cp_gle = cp_ok ? 0 : GetLastError();
	diag::log_tagged_critical_fmt("malware_safe",
		"CreateProcessAsUserW ok=%d pid=%lu tid=%lu gle=%lu flags=0x%08lX",
		cp_ok ? 1 : 0,
		cp_ok ? pi.dwProcessId : 0u,
		cp_ok ? pi.dwThreadId : 0u,
		static_cast<unsigned long>(cp_gle),
		static_cast<unsigned long>(flags));

	DeleteProcThreadAttributeList(attr_list);

	if (!cp_ok) {
		out.error = format_error("CreateProcessAsUserW (malware_safe)", cp_gle);
		log_fail("CreateProcessAsUserW.malware_safe", cp_gle);
		CloseHandle(job);
		CloseHandle(restricted_token);
		return false;
	}

	CloseHandle(restricted_token);

	if (!AssignProcessToJobObject(job, pi.hProcess)) {
		DWORD gle = GetLastError();
		out.error = format_error("AssignProcessToJobObject (malware_safe)", gle);
		log_fail("AssignProcessToJobObject.malware_safe", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(job);
		return false;
	}
	diag::log_tagged_critical_fmt("malware_safe",
		"assign_to_job ok pid=%lu", pi.dwProcessId);

	if (opts.block_network) {
		std::string rule = make_unique_rule_name();
		std::string fr;
		bool fok = firewall_add_block_rule(opts.exe_path, rule, &fr);
		diag::log_tagged_critical_fmt("malware_safe",
			"firewall_block ok=%d rule_name='%s'%s%s",
			fok ? 1 : 0, rule.c_str(),
			fok ? "" : " reason=",
			fok ? "" : fr.c_str());
		if (fok) out.firewall_rule_name = rule;
	}

	if (opts.register_kernel_sandbox_guard) {
		bool any = try_register_kernel_sandbox_guard(
			pi.dwProcessId,
			opts.log_network_traffic,
			!opts.allow_child_processes);
		out.sandbox_pid_registered = any;
		out.net_logger_registered = (opts.log_network_traffic && any);
		if (!any) {
			diag::log_tagged_critical_fmt("malware_safe",
				"kernel_guard_unavailable pid=%lu (driver not loaded or guard refused) (continuing)",
				pi.dwProcessId);
		}
	} else if (opts.log_network_traffic && driver_bridge::is_loaded()) {
		bool started = driver_bridge::start_capture(pi.dwProcessId, 0, 0, nullptr, 1500);
		out.net_logger_registered = started;
		diag::log_tagged_critical_fmt("malware_safe",
			"net_log_only pid=%lu started=%d",
			pi.dwProcessId, started ? 1 : 0);
	}

	out.ok = true;
	out.pid = pi.dwProcessId;
	out.thread_id = pi.dwThreadId;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = reinterpret_cast<uintptr_t>(pi.hThread);
	out.job_handle = reinterpret_cast<uintptr_t>(job);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, job, opts.auto_terminate_sec, pi.dwProcessId);
	}

	diag::log_tagged_critical_fmt("malware_safe",
		"launch ok pid=%lu sandbox='%s' kernel_guard=%d net_log=%d il_lowered=%d mitigations=%d firewall_rule='%s'",
		pi.dwProcessId,
		narrow_utf8(sandbox_root).c_str(),
		out.sandbox_pid_registered ? 1 : 0,
		out.net_logger_registered ? 1 : 0,
		out.integrity_lowered ? 1 : 0,
		out.mitigations_applied ? 1 : 0,
		out.firewall_rule_name.c_str());

	return true;
}

std::wstring xml_escape_w(const std::wstring& text) {
	std::wstring out;
	out.reserve(text.size() + 16);
	for (wchar_t c : text) {
		switch (c) {
			case L'&':  out += L"&amp;";  break;
			case L'<':  out += L"&lt;";   break;
			case L'>':  out += L"&gt;";   break;
			case L'"':  out += L"&quot;"; break;
			case L'\'': out += L"&apos;"; break;
			default:    out.push_back(c); break;
		}
	}
	return out;
}

std::wstring ps_quote_w(const std::wstring& text) {
	std::wstring out;
	out.push_back(L'\'');
	for (wchar_t c : text) {
		if (c == L'\'') out += L"''";
		else            out.push_back(c);
	}
	out.push_back(L'\'');
	return out;
}

bool launch_windows_sandbox(const launch_options_t& opts, launch_result_t& out) {
	std::wstring sandbox_exe = resolve_windows_sandbox_exe();
	if (sandbox_exe.empty()) {
		out.error = "Windows Sandbox is unavailable. Enable Windows Sandbox on Windows Pro, Enterprise, or Education with virtualization enabled. Admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All";
		diag::log_tagged_critical("run_target",
			"launch_windows_sandbox unavailable_no_exe");
		return false;
	}

	if (opts.exe_path.empty()) {
		out.error = "Empty executable path.";
		return false;
	}

	std::filesystem::path exe_path(opts.exe_path);
	std::error_code ec;
	if (!std::filesystem::exists(exe_path, ec)) {
		out.error = "Target executable does not exist.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox exe_missing path='%s'",
			narrow_utf8(opts.exe_path).c_str());
		return false;
	}

	std::wstring guest_agent_src = resolve_guest_agent_exe();
	if (guest_agent_src.empty()) {
		out.error = "AiDAGuestAgent.exe is missing beside AiDAStandalone.exe. Rebuild AiDAStandalone so the sandbox bridge agent is staged.";
		diag::log_tagged_critical("run_target",
			"launch_windows_sandbox guest_agent_missing");
		return false;
	}

	wchar_t temp_path[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, temp_path);
	uint64_t tick = static_cast<uint64_t>(GetTickCount64());
	std::filesystem::path session_dir = std::filesystem::path(temp_path)
		/ L"AiDAStandalone" / L"RunTarget"
		/ std::to_wstring(GetCurrentProcessId())
		/ std::to_wstring(tick);
	auto remove_failed_session = [&]() {
		std::error_code remove_ec;
		const uintmax_t removed = std::filesystem::remove_all(session_dir, remove_ec);
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox failure_cleanup session_dir='%s' removed=%llu ok=%d ec=%d msg='%s'",
			narrow_utf8(session_dir.wstring()).c_str(),
			static_cast<unsigned long long>(removed),
			remove_ec ? 0 : 1,
			remove_ec.value(),
			remove_ec.message().c_str());
	};
	std::filesystem::create_directories(session_dir, ec);
	if (ec) {
		out.error = "Failed to create session directory.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox create_session_dir_FAILED ec=%d msg='%s'",
			ec.value(), ec.message().c_str());
		remove_failed_session();
		return false;
	}

	std::filesystem::path host_input = session_dir / L"input";
	std::filesystem::create_directories(host_input, ec);
	if (ec) {
		out.error = "Failed to create sandbox input directory.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox create_input_dir_FAILED ec=%d msg='%s'",
			ec.value(), ec.message().c_str());
		remove_failed_session();
		return false;
	}

	std::filesystem::path host_output = session_dir / L"output";
	std::filesystem::create_directories(host_output, ec);
	if (ec) {
		out.error = "Failed to create sandbox output directory.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox create_output_dir_FAILED ec=%d msg='%s'",
			ec.value(), ec.message().c_str());
		remove_failed_session();
		return false;
	}

	std::filesystem::path host_script = host_input / L"run.ps1";
	std::filesystem::path host_wsb = session_dir / L"session.wsb";

	std::filesystem::path target_in_input = host_input / exe_path.filename();
	std::filesystem::copy_file(exe_path, target_in_input,
		std::filesystem::copy_options::overwrite_existing, ec);
	if (ec) {
		out.error = "Failed to stage target executable for Windows Sandbox.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox copy_target_FAILED src='%s' dst='%s' ec=%d msg='%s'",
				narrow_utf8(exe_path.wstring()).c_str(),
				narrow_utf8(target_in_input.wstring()).c_str(),
				ec.value(), ec.message().c_str());
		remove_failed_session();
		return false;
	}
	ec.clear();

	std::filesystem::path host_agent = host_input / L"AiDAGuestAgent.exe";
	std::filesystem::copy_file(std::filesystem::path(guest_agent_src), host_agent,
		std::filesystem::copy_options::overwrite_existing, ec);
	if (ec) {
		out.error = "Failed to stage AiDA guest agent for Windows Sandbox.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox copy_guest_agent_FAILED src='%s' dst='%s' ec=%d msg='%s'",
				narrow_utf8(guest_agent_src).c_str(),
				narrow_utf8(host_agent.wstring()).c_str(),
				ec.value(), ec.message().c_str());
		remove_failed_session();
		return false;
	}
	ec.clear();

	stage_common_runtime_dependencies(host_input);
	stage_packaged_analysis_dependencies(host_input);

	std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
	std::wstring guest_input = guest_root + L"\\input";
	std::wstring guest_output = guest_root + L"\\output";
	std::wstring guest_exe = guest_input + L"\\" + exe_path.filename().wstring();
	std::wstring guest_agent = guest_input + L"\\AiDAGuestAgent.exe";

	{
		std::wofstream ofs(host_script.wstring(), std::ios::trunc);
		if (!ofs.is_open()) {
			out.error = "Failed to write run.ps1 in session directory.";
			remove_failed_session();
			return false;
		}
		ofs.imbue(std::locale::classic());
		ofs << L"$ErrorActionPreference = 'Continue'\n";
		ofs << L"$exePath = " << ps_quote_w(guest_exe) << L"\n";
		ofs << L"$argLine = " << ps_quote_w(opts.args) << L"\n";
		ofs << L"$outDir = " << ps_quote_w(guest_output) << L"\n";
		ofs << L"$agentPath = " << ps_quote_w(guest_agent) << L"\n";
		ofs << L"New-Item -ItemType Directory -Force -Path $outDir | Out-Null\n";
		ofs << L"New-Item -ItemType Directory -Force -Path (Join-Path $outDir 'requests') | Out-Null\n";
		ofs << L"New-Item -ItemType Directory -Force -Path (Join-Path $outDir 'responses') | Out-Null\n";
		ofs << L"New-Item -ItemType Directory -Force -Path (Join-Path $outDir 'artifacts') | Out-Null\n";
		ofs << L"Set-Content -Path (Join-Path $outDir 'launch.txt') -Value ('AiDA sandbox launch ' + (Get-Date).ToString('o'))\n";
		ofs << L"$workDir = Split-Path -Path $exePath -Parent\n";
		ofs << L"[Environment]::SetEnvironmentVariable(\"AIDA_PACKAGE_DIR\", $workDir, \"Process\"); $env:AIDA_PACKAGE_DIR = $workDir\n";
		ofs << L"$depsDir = Join-Path $workDir 'deps'\n";
		ofs << L"if (Test-Path -LiteralPath $depsDir) { [Environment]::SetEnvironmentVariable(\"AIDA_DEPS_DIR\", $depsDir, \"Process\"); $env:AIDA_DEPS_DIR = $depsDir }\n";
		ofs << L"$fixtureDir = Join-Path $workDir 'test_binaries\\target_protocol'\n";
		ofs << L"if (Test-Path -LiteralPath $fixtureDir) { [Environment]::SetEnvironmentVariable(\"AIDA_TARGET_PROTOCOL_FIXTURE_DIR\", $fixtureDir, \"Process\"); $env:AIDA_TARGET_PROTOCOL_FIXTURE_DIR = $fixtureDir }\n";
		ofs << L"$specsDir = Join-Path $workDir 'ghidra_specs'\n";
		ofs << L"if (Test-Path -LiteralPath $specsDir) { [Environment]::SetEnvironmentVariable(\"AIDA_GHIDRA_SPECS_DIR\", $specsDir, \"Process\"); $env:AIDA_GHIDRA_SPECS_DIR = $specsDir }\n";
		ofs << L"$cfg = @{ sample = $exePath; args = $argLine; created = (Get-Date).ToString('o') } | ConvertTo-Json -Compress\n";
		ofs << L"$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\n";
		ofs << L"[System.IO.File]::WriteAllText((Join-Path $outDir 'launch_config.json'), $cfg, $utf8NoBom)\n";
		ofs << L"try {\n";
		ofs << L"  $proc = Start-Process -FilePath $agentPath -ArgumentList @('--bridge', $outDir) -WorkingDirectory $workDir -PassThru -WindowStyle Hidden\n";
		ofs << L"  if ($proc -ne $null) {\n";
		ofs << L"    Set-Content -Path (Join-Path $outDir 'agent_pid.txt') -Value $proc.Id\n";
		ofs << L"  }\n";
		ofs << L"} catch {\n";
		ofs << L"  Set-Content -Path (Join-Path $outDir 'launch_error.txt') -Value $_.Exception.Message\n";
		ofs << L"}\n";
	}

	uint64_t script_bytes = 0;
	{
		std::error_code sec_ec;
		auto sz = std::filesystem::file_size(host_script, sec_ec);
		if (!sec_ec) script_bytes = static_cast<uint64_t>(sz);
	}

	{
		std::wofstream ofs(host_wsb.wstring(), std::ios::trunc);
		if (!ofs.is_open()) {
			out.error = "Failed to write session.wsb in session directory.";
			remove_failed_session();
			return false;
		}
		ofs.imbue(std::locale::classic());
		std::wstring host_input_esc = xml_escape_w(host_input.wstring());
		std::wstring guest_input_esc = xml_escape_w(guest_input);
		std::wstring host_output_esc = xml_escape_w(host_output.wstring());
		std::wstring guest_output_esc = xml_escape_w(guest_output);

		ofs << L"<Configuration>\n";
		ofs << L"  <Networking>" << (opts.block_network ? L"Disable" : L"Default") << L"</Networking>\n";
		ofs << L"  <ProtectedClient>Enable</ProtectedClient>\n";
		ofs << L"  <ClipboardRedirection>Disable</ClipboardRedirection>\n";
		ofs << L"  <PrinterRedirection>Disable</PrinterRedirection>\n";
		ofs << L"  <AudioInput>Disable</AudioInput>\n";
		ofs << L"  <VideoInput>Disable</VideoInput>\n";
		ofs << L"  <vGPU>Disable</vGPU>\n";
		if (opts.memory_cap_mb > 0)
			ofs << L"  <MemoryInMB>" << opts.memory_cap_mb << L"</MemoryInMB>\n";
		ofs << L"  <MappedFolders>\n";
		ofs << L"    <MappedFolder>\n";
		ofs << L"      <HostFolder>" << host_input_esc << L"</HostFolder>\n";
		ofs << L"      <SandboxFolder>" << guest_input_esc << L"</SandboxFolder>\n";
		ofs << L"      <ReadOnly>true</ReadOnly>\n";
		ofs << L"    </MappedFolder>\n";
		ofs << L"    <MappedFolder>\n";
		ofs << L"      <HostFolder>" << host_output_esc << L"</HostFolder>\n";
		ofs << L"      <SandboxFolder>" << guest_output_esc << L"</SandboxFolder>\n";
		ofs << L"      <ReadOnly>false</ReadOnly>\n";
		ofs << L"    </MappedFolder>\n";
		ofs << L"  </MappedFolders>\n";
		ofs << L"  <LogonCommand>\n";
		ofs << L"    <Command>powershell.exe -ExecutionPolicy Bypass -File "
		    << guest_input_esc << L"\\run.ps1</Command>\n";
		ofs << L"  </LogonCommand>\n";
		ofs << L"</Configuration>\n";
	}

	diag::log_tagged_critical_fmt("run_target",
		"launch_windows_sandbox wsb_written session_dir='%s' script_bytes=%llu interactive_window=1",
		narrow_utf8(session_dir.wstring()).c_str(),
		static_cast<unsigned long long>(script_bytes));

	std::wstring cmd = L"\"" + sandbox_exe + L"\" \"" + host_wsb.wstring() + L"\"";
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	STARTUPINFOW si{};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi{};

	BOOL cp_ok = CreateProcessW(nullptr, cmd_buf.data(),
		nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE,
		nullptr, session_dir.c_str(), &si, &pi);
	if (!cp_ok) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateProcessW (WindowsSandbox.exe)", gle);
		log_fail("CreateProcessW.WindowsSandbox", gle);
		remove_failed_session();
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_windows_sandbox WindowsSandbox.exe_started host_pid=%lu",
		pi.dwProcessId);

	CloseHandle(pi.hThread);

	out.ok = true;
	out.pid = 0;
	out.thread_id = 0;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = 0;
	out.job_handle = 0;
	out.sandbox_dir = session_dir.wstring();
	out.windows_sandbox_host_owned = true;
	vm_guest_bridge::activate(out.sandbox_dir, opts.exe_path);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, nullptr, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

}

capability_probe_t probe_capabilities() {
	capability_probe_t p{};
	p.windows_build = get_windows_build_number();
	p.has_jobobject = true;
	p.has_appcontainer = (p.windows_build >= 15063);
	p.has_firewall_inet = (p.windows_build >= 7600);
	p.has_windows_sandbox = !resolve_windows_sandbox_exe().empty();
	p.has_restricted_token = true;
	p.has_mitigation_policy = (p.windows_build >= 9200);
	p.has_kernel_sandbox_guard = driver_bridge::is_loaded();
	diag::log_tagged_critical_fmt("run_target",
		"probe_capabilities win_build=%u job=%d ac=%d fw=%d wsb=%d restok=%d mitig=%d kguard=%d",
		p.windows_build,
		p.has_jobobject ? 1 : 0,
		p.has_appcontainer ? 1 : 0,
		p.has_firewall_inet ? 1 : 0,
		p.has_windows_sandbox ? 1 : 0,
		p.has_restricted_token ? 1 : 0,
		p.has_mitigation_policy ? 1 : 0,
		p.has_kernel_sandbox_guard ? 1 : 0);
	return p;
}

bool launch(const launch_options_t& opts, launch_result_t& out) {
	out = launch_result_t{};
	if (opts.exe_path.empty()) {
		out.error = "Empty executable path.";
		diag::log_tagged_critical("run_target", "launch_REJECTED empty_exe_path");
		return false;
	}

	launch_options_t effective_opts;
	if (!normalize_launch_working_dir(opts, effective_opts, out))
		return false;

	std::string exe_utf8 = narrow_utf8(effective_opts.exe_path);
	std::string cwd_utf8 = narrow_utf8(effective_opts.working_dir);
	std::string requested_cwd_utf8 = narrow_utf8(opts.working_dir);
	diag::log_tagged_critical_fmt("run_target",
		"launch entry exe='%s' args_len=%zu iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u cwd='%s' requested_cwd='%s'",
		exe_utf8.c_str(),
		effective_opts.args.size(),
		static_cast<int>(effective_opts.isolation),
		effective_opts.block_network ? 1 : 0,
		effective_opts.kill_on_host_exit ? 1 : 0,
		static_cast<unsigned>(effective_opts.memory_cap_mb),
		static_cast<unsigned>(effective_opts.auto_terminate_sec),
		cwd_utf8.empty() ? "<inherit>" : cwd_utf8.c_str(),
		requested_cwd_utf8.empty() ? "<inherit>" : requested_cwd_utf8.c_str());

	if (effective_opts.isolation == isolation_t::same_desktop_jobbed
	    || effective_opts.isolation == isolation_t::appcontainer
	    || effective_opts.isolation == isolation_t::malware_safe_desktop) {
		DWORD attrs = GetFileAttributesW(effective_opts.exe_path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			DWORD gle = GetLastError();
			out.error = "Target executable does not exist.";
			diag::log_tagged_critical_fmt("run_target",
				"launch exe_missing path='%s' gle=%lu",
				exe_utf8.c_str(), static_cast<unsigned long>(gle));
			return false;
		}
		if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
			out.error = "Path is a directory, not an executable.";
			return false;
		}
	}

	bool ok = false;
	switch (effective_opts.isolation) {
		case isolation_t::same_desktop_jobbed:
			if (effective_opts.malware_safe_mode) {
				ok = launch_malware_safe_desktop(effective_opts, out);
			} else {
				ok = launch_same_desktop(effective_opts, out);
			}
			break;
		case isolation_t::malware_safe_desktop:
			ok = launch_malware_safe_desktop(effective_opts, out);
			break;
		case isolation_t::appcontainer:
			ok = launch_appcontainer(effective_opts, out);
			break;
		case isolation_t::windows_sandbox:
			ok = launch_windows_sandbox(effective_opts, out);
			break;
		default:
			out.error = "Unknown isolation mode.";
			return false;
	}

	if (ok) {
		diag::log_tagged_critical_fmt("run_target",
			"launch ok iso=%d pid=%u job=%p firewall_rule='%s'",
			static_cast<int>(effective_opts.isolation),
			out.pid,
			reinterpret_cast<void*>(out.job_handle),
			out.firewall_rule_name.c_str());
	} else {
		diag::log_tagged_critical_fmt("run_target",
			"launch FAILED iso=%d error='%s'",
			static_cast<int>(effective_opts.isolation),
			out.error.c_str());
		const std::string launch_error = out.error;
		(void)cleanup(out);
		out.error = launch_error;
	}
	return ok;
}

bool cleanup(launch_result_t& result) {
	bool fw_removed = true;
	bool job_closed = false;
	bool proc_closed = false;
	bool thr_closed = false;
	bool kernel_unregistered = false;
	bool bridge_deactivated = false;
	bool sandbox_host_stopped = true;
	bool sandbox_dir_removed = true;

	if (result.job_handle != 0) {
		CloseHandle(reinterpret_cast<HANDLE>(result.job_handle));
		result.job_handle = 0;
		job_closed = true;
	}
	bool target_stopped = true;
	if (result.process_handle != 0 && !result.windows_sandbox_host_owned) {
		HANDLE process = reinterpret_cast<HANDLE>(result.process_handle);
		DWORD wait = WaitForSingleObject(process, 5000);
		if (wait == WAIT_TIMEOUT) {
			const BOOL terminated = TerminateProcess(process, 0xDEADu);
			const DWORD terminate_gle = terminated ? 0 : GetLastError();
			if (terminated)
				wait = WaitForSingleObject(process, 5000);
			if (wait != WAIT_OBJECT_0) {
				target_stopped = false;
				result.error = terminated
					? "Target did not stop within 5000 ms after termination request."
					: format_error("TerminateProcess (target cleanup)", terminate_gle);
			}
		}
		if (wait != WAIT_OBJECT_0) {
			target_stopped = false;
			if (wait == WAIT_FAILED && result.error.empty())
				result.error = format_error("WaitForSingleObject (target cleanup)", GetLastError());
			else if (wait == WAIT_TIMEOUT && result.error.empty())
				result.error = "Target did not stop within 5000 ms during cleanup.";
			diag::log_tagged_critical_fmt("run_target",
				"cleanup target_wait FAILED pid=%u wait=0x%08lX",
				result.pid, static_cast<unsigned long>(wait));
		}
	}
	if (target_stopped) {
		if (result.sandbox_pid_registered && result.pid != 0) {
			try_unregister_kernel_sandbox_guard(result.pid);
			kernel_unregistered = true;
			result.sandbox_pid_registered = false;
			result.net_logger_registered = false;
		} else if (result.net_logger_registered && driver_bridge::is_loaded()) {
			driver_bridge::stop_capture();
			result.net_logger_registered = false;
		}

		if (!result.firewall_rule_name.empty()) {
			fw_removed = firewall_remove_rule(result.firewall_rule_name);
			if (fw_removed) {
				result.firewall_rule_name.clear();
			} else {
				result.error = "Failed to remove firewall rule: " + result.firewall_rule_name;
				diag::log_tagged_critical_fmt("run_target",
					"cleanup firewall_remove FAILED rule_name='%s'",
					result.firewall_rule_name.c_str());
			}
		}
	}
	if (result.thread_handle != 0) {
		CloseHandle(reinterpret_cast<HANDLE>(result.thread_handle));
		result.thread_handle = 0;
		thr_closed = true;
	}
	if (result.process_handle != 0) {
		HANDLE process = reinterpret_cast<HANDLE>(result.process_handle);
		if (result.windows_sandbox_host_owned) {
			DWORD wait = WaitForSingleObject(process, 0);
			if (wait == WAIT_TIMEOUT) {
				if (!TerminateProcess(process, 0xDEAD)) {
					DWORD gle = GetLastError();
					wait = WaitForSingleObject(process, 0);
					if (wait == WAIT_TIMEOUT || wait == WAIT_FAILED) {
						sandbox_host_stopped = false;
						result.error = format_error("TerminateProcess (WindowsSandbox.exe)", gle);
						diag::log_tagged_critical_fmt("run_target",
							"cleanup WindowsSandbox.exe terminate_FAILED gle=%lu wait=0x%08lX",
							static_cast<unsigned long>(gle),
							static_cast<unsigned long>(wait));
					}
				} else {
					wait = WaitForSingleObject(process, 5000);
					if (wait != WAIT_OBJECT_0) {
						sandbox_host_stopped = false;
						result.error = wait == WAIT_FAILED
							? format_error("WaitForSingleObject (WindowsSandbox.exe)", GetLastError())
							: "WindowsSandbox.exe did not stop within 5000 ms.";
					}
				}
			} else if (wait == WAIT_FAILED) {
				sandbox_host_stopped = false;
				result.error = format_error("WaitForSingleObject (WindowsSandbox.exe)", GetLastError());
			}
		}
		if (!result.windows_sandbox_host_owned || sandbox_host_stopped) {
			CloseHandle(process);
			result.process_handle = 0;
			proc_closed = true;
		}
	}
	if (!result.sandbox_dir.empty()) {
		const auto bridge_session = vm_guest_bridge::current();
		if (bridge_session.active && bridge_session.session_dir == result.sandbox_dir) {
			vm_guest_bridge::deactivate();
			bridge_deactivated = true;
		}
	}
	if (result.windows_sandbox_host_owned && sandbox_host_stopped && !result.sandbox_dir.empty()) {
		std::error_code ec;
		const uintmax_t removed = std::filesystem::remove_all(result.sandbox_dir, ec);
		sandbox_dir_removed = !ec;
		if (!sandbox_dir_removed) {
			result.error = "Failed to remove Windows Sandbox session directory: " + ec.message();
		}
		diag::log_tagged_critical_fmt("run_target",
			"cleanup WindowsSandbox session_remove path='%s' removed=%llu ok=%d ec=%d msg='%s'",
			narrow_utf8(result.sandbox_dir).c_str(),
			static_cast<unsigned long long>(removed),
			sandbox_dir_removed ? 1 : 0,
			ec.value(),
			ec.message().c_str());
		if (sandbox_dir_removed)
			result.sandbox_dir.clear();
	}
	if (result.windows_sandbox_host_owned && sandbox_host_stopped && sandbox_dir_removed)
		result.windows_sandbox_host_owned = false;
	if (!result.appcontainer_profile_name.empty() && target_stopped) {
		HRESULT profile_hr = DeleteAppContainerProfile(result.appcontainer_profile_name.c_str());
		if (FAILED(profile_hr) && profile_hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) {
			result.error = format_error("DeleteAppContainerProfile", static_cast<DWORD>(profile_hr));
			fw_removed = false;
			diag::log_tagged_critical_fmt("run_target",
				"cleanup appcontainer_profile_remove FAILED name='%ls' hr=0x%08lX",
				result.appcontainer_profile_name.c_str(),
				static_cast<unsigned long>(profile_hr));
		} else {
			result.appcontainer_profile_name.clear();
		}
	}
	if (!result.sandbox_dir.empty() && !result.windows_sandbox_host_owned && target_stopped) {
		std::error_code ec;
		const uintmax_t removed = std::filesystem::remove_all(result.sandbox_dir, ec);
		sandbox_dir_removed = !ec;
		if (!sandbox_dir_removed)
			result.error = "Failed to remove sandbox directory: " + ec.message();
		diag::log_tagged_critical_fmt("run_target",
			"cleanup sandbox_dir_remove path='%s' removed=%llu ok=%d ec=%d",
			narrow_utf8(result.sandbox_dir).c_str(),
			static_cast<unsigned long long>(removed), sandbox_dir_removed ? 1 : 0,
			ec.value());
		if (sandbox_dir_removed)
			result.sandbox_dir.clear();
	}
	const bool ok = target_stopped && fw_removed && sandbox_host_stopped && sandbox_dir_removed;
	diag::log_tagged_critical_fmt("run_target",
		"cleanup ok=%d job_closed=%d proc_closed=%d thr_closed=%d firewall_removed=%d kernel_unregistered=%d bridge_deactivated=%d sandbox_host_stopped=%d sandbox_dir_removed=%d sandbox_dir='%s'",
		ok ? 1 : 0,
		job_closed ? 1 : 0,
		proc_closed ? 1 : 0,
		thr_closed ? 1 : 0,
		fw_removed ? 1 : 0,
		kernel_unregistered ? 1 : 0,
		bridge_deactivated ? 1 : 0,
		sandbox_host_stopped ? 1 : 0,
		sandbox_dir_removed ? 1 : 0,
		narrow_utf8(result.sandbox_dir).c_str());
	return ok;
}

}
