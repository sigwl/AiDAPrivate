#pragma once

#include <cstdint>
#include <string>

namespace run_target {

enum class isolation_t : int {
	same_desktop_jobbed   = 0,
	appcontainer          = 1,
	windows_sandbox       = 2,
	malware_safe_desktop  = 3,
};

struct launch_options_t {
	std::wstring exe_path;
	std::wstring args;
	std::wstring working_dir;

	isolation_t  isolation = isolation_t::same_desktop_jobbed;

	bool         block_network = true;
	bool         kill_on_host_exit = true;
	bool         attach_after_resume = true;

	uint32_t     memory_cap_mb = 0;
	uint32_t     auto_terminate_sec = 0;

	bool         malware_safe_mode = false;
	bool         log_network_traffic = false;
	bool         lower_integrity_untrusted = false;
	bool         allow_child_processes = true;
	bool         force_mitigations_strict = false;
	bool         redirect_user_paths_to_sandbox = true;
	bool         register_kernel_sandbox_guard = true;
};

struct launch_result_t {
	bool        ok = false;
	uint32_t    win32_error = 0;
	uint32_t    pid = 0;
	uint32_t    thread_id = 0;
	uintptr_t   process_handle = 0;
	uintptr_t   thread_handle = 0;
	uintptr_t   job_handle = 0;
	std::string firewall_rule_name;
	std::wstring sandbox_dir;
	std::wstring appcontainer_profile_name;
	bool        sandbox_pid_registered = false;
	bool        net_logger_registered = false;
	bool        token_restricted = false;
	bool        integrity_lowered = false;
	bool        mitigations_applied = false;
	bool        windows_sandbox_host_owned = false;
	std::string error;
};

struct capability_probe_t {
	bool     has_jobobject = false;
	bool     has_appcontainer = false;
	bool     has_firewall_inet = false;
	bool     has_windows_sandbox = false;
	bool     has_restricted_token = false;
	bool     has_mitigation_policy = false;
	bool     has_kernel_sandbox_guard = false;
	uint32_t windows_build = 0;
};

bool launch(const launch_options_t& opts, launch_result_t& out);
bool cleanup(launch_result_t& result);

capability_probe_t probe_capabilities();

}
