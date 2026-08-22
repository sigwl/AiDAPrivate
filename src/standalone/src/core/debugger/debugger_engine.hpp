#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../runtime/run_target.hpp"

namespace debugger_engine {


enum class bp_type_t : int {
	software = 0,
	hardware_execute,
	hardware_write,
	hardware_read,
	memory_access,
	COUNT
};

enum class bp_state_t : int {
	disabled = 0,
	enabled,
	one_shot,
};

enum class breakpoint_install_state_t : int {
	requested = 0,
	installing,
	installed,
	removing,
	error,
};

struct breakpoint_t {
	uint64_t    address = 0;
	bp_type_t   type = bp_type_t::software;
	bp_state_t  state = bp_state_t::enabled;
	int         hw_slot = -1;
	int         size = 1;
	std::string name;
	std::string condition;
	std::string log_text;
	int         hit_count = 0;
	uint8_t     original_byte = 0;
	bool        is_internal = false;
	bool        auto_continue = false;
	bool        byte_written = false;
	breakpoint_install_state_t install_state = breakpoint_install_state_t::installed;
	bool        readback_verified = false;
	std::string install_detail;
	std::string definition_module;
	uint64_t    definition_module_offset = 0;
	uint32_t    definition_module_size = 0;
	bool        persistent_definition = false;
	bool        definition_resolved = true;
	std::string definition_status;
	std::string source_definition_id;
	std::string source_file;
	uint32_t    source_line = 0;
	uint32_t    source_location_ordinal = 0;
	uint64_t    mutation_identity = 0;
	uint64_t    mutation_generation = 0;
};

struct internal_bp_t {
	uint64_t address = 0;
	uint8_t  original_byte = 0;
	bool     active = false;
};


struct register_set_t {
	uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
	uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
	uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
	uint64_t rip = 0, rflags = 0;
	uint64_t cs = 0, ds = 0, es = 0, fs = 0, gs = 0, ss = 0;
	uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;
};


struct stack_frame_t {
	uint64_t    address = 0;
	uint64_t    return_addr = 0;
	uint64_t    module_base = 0;
	uint64_t    module_size = 0;
	std::string module_name;
	std::string module_path;
	std::string function_name;
	uint64_t    module_offset = 0;
	uint64_t    symbol_address = 0;
	uint64_t    symbol_offset = 0;
	std::string symbol_source;
	std::string symbol_status;
};

struct call_stack_symbol_resolution_t {
	uint64_t address = 0;
	uint64_t module_base = 0;
	uint64_t module_size = 0;
	uint64_t module_offset = 0;
	uint64_t symbol_address = 0;
	uint64_t symbol_offset = 0;
	uint64_t elapsed_us = 0;
	std::string module_name;
	std::string module_path;
	std::string function_name;
	std::string source = "none";
	std::string status = "not_attempted";
};


struct memory_region_t {
	uint64_t    base = 0;
	uint64_t    size = 0;
	uint32_t    protect = 0;
	uint32_t    state = 0;
	uint32_t    type = 0;
	std::string module_name;
	std::string info;
};


struct watch_entry_t {
	std::string expression;
	std::string value;
	std::string type;
	std::string error;
	bool        valid = false;
	std::string persistent_expression;
	std::string definition_module;
	uint64_t    definition_module_offset = 0;
	uint32_t    definition_module_size = 0;
	bool        persistent_definition = false;
	bool        definition_resolved = true;
};

struct expression_evaluation_t {
	bool succeeded = false;
	uint64_t value = 0;
	std::string rendered_value;
	std::string type;
	std::string error;
};

inline constexpr std::size_t k_max_watch_count = 4096;
inline constexpr std::size_t k_max_watch_expression_bytes = 96;

struct watch_refresh_target_t {
	std::string expression;
	std::string persistent_expression;
	std::string definition_module;
	uint64_t definition_module_offset = 0;
	uint32_t definition_module_size = 0;
	bool persistent_definition = false;
	bool definition_resolved = true;
	std::string unresolved_error;
};

struct watch_refresh_batch_t {
	uint64_t generation = 0;
	std::size_t cardinality = 0;
	std::vector<watch_refresh_target_t> targets;
	std::string error;

	bool valid() const noexcept {
		return error.empty() && cardinality == targets.size();
	}
};

using watch_refresh_batch_ptr = std::shared_ptr<const watch_refresh_batch_t>;

struct watch_refresh_evaluation_batch_t {
	watch_refresh_batch_ptr source;
	std::vector<expression_evaluation_t> results;
	std::string error;
	bool cancelled = false;

	bool valid() const noexcept {
		return source && source->valid() && error.empty() && !cancelled &&
			results.size() == source->targets.size();
	}
};

using watch_refresh_cancel_fn_t = std::function<bool()>;

enum class watch_refresh_publish_result_t : uint8_t {
	published = 0,
	invalid_batch,
	stale_generation,
	cardinality_mismatch,
	identity_mismatch,
	result_mismatch
};


struct trace_record_t {
	uint64_t       address = 0;
	register_set_t regs;
	std::string    disasm_text;
	int            index = 0;
};


struct annotation_t {
	std::string text;
	uint64_t    address = 0;
};


struct handle_info_t {
	uint64_t    handle = 0;
	uint32_t    type_index = 0;
	std::string type_name;
	std::string name;
	uint32_t    access = 0;
};


struct string_ref_t {
	uint64_t    address = 0;
	std::string value;
	std::string module_name;
	uint64_t    module_offset = 0;
	bool        is_unicode = false;
};


struct cached_thread_t {
	uint32_t    tid = 0;
	uint32_t    owner_pid = 0;
	int         priority = 0;
	uint32_t    state = 0;
	uint64_t    rip = 0;
};


enum class dbg_status_t : int {
	idle = 0,
	running,
	paused,
	stepping,
	terminated,
};

struct state_t {

	std::atomic<dbg_status_t>  status{dbg_status_t::idle};
	uint32_t                   target_pid = 0;
	uint32_t                   active_tid = 0;


	std::mutex                 bp_mutex;
	std::vector<breakpoint_t>  breakpoints;
	std::vector<internal_bp_t> internal_breakpoints;
	std::atomic<uint64_t>      breakpoints_generation{1};
	int                        next_bp_id = 1;


	std::mutex                 reg_mutex;
	register_set_t             registers;


	std::mutex                 stack_mutex;
	std::vector<stack_frame_t> call_stack;
	std::atomic<uint64_t>      call_stack_generation{1};


	std::mutex                       memmap_mutex;
	std::vector<memory_region_t>     memory_map;


	std::mutex                 watch_mutex;
	std::vector<watch_entry_t> watches;
	std::atomic<uint64_t>      watches_generation{1};


	std::mutex                     trace_mutex;
	std::vector<trace_record_t>    trace_log;
	std::atomic<bool>              tracing{false};
	std::atomic<uint64_t>          trace_generation{1};
	std::atomic<uint64_t>          trace_dropped{0};
	int                            trace_max_depth = 50000;


	std::mutex                          anno_mutex;
	std::map<uint64_t, annotation_t>    comments;
	std::map<uint64_t, annotation_t>    labels;
	std::vector<uint64_t>               bookmarks;


	std::mutex                   handle_mutex;
	std::vector<handle_info_t>   handles;
	std::atomic<uint64_t>        handles_generation{1};


	std::mutex                   strings_mutex;
	std::vector<string_ref_t>    strings;
	std::atomic<uint64_t>        strings_generation{1};
	std::atomic<bool>            strings_scanning{false};
	std::atomic<bool>            strings_cancel{false};
	std::atomic<uint64_t>        strings_pages_scanned{0};
	std::atomic<uint64_t>        strings_found_so_far{0};


	std::atomic<bool>            worker_thread_done{true};
	std::atomic<bool>            worker_active{false};


	std::mutex                   log_mutex;
	std::deque<std::string>      log_messages;
	size_t                       log_messages_max = 4096;


	std::mutex                       cache_mtx;
	std::mutex                       error_mtx;
	std::string                      error_text;
	register_set_t                   cached_regs{};
	std::vector<cached_thread_t>     cached_threads;
	std::atomic<uint64_t>            cached_threads_generation{1};
	std::vector<uint8_t>             cached_stack;
	uint64_t                         cached_stack_addr = 0;
	std::vector<uint8_t>             cached_dump;
	uint64_t                         cached_dump_addr = 0;
	size_t                           cached_dump_size = 0;
	std::vector<uint8_t>             cached_disasm_bytes;
	uint64_t                         cached_disasm_base = 0;
	std::atomic<uint64_t>            last_refresh_ms{0};
	std::atomic<uint64_t>            last_thread_refresh_ms{0};
	std::atomic<uint64_t>            last_stack_refresh_ms{0};
	std::atomic<uint64_t>            last_dump_refresh_ms{0};
	std::atomic<uint64_t>            last_disasm_refresh_ms{0};
	std::atomic<bool>                refresh_in_flight{false};
	std::atomic<bool>                thread_refresh_in_flight{false};
	std::atomic<bool>                stack_refresh_in_flight{false};
	std::atomic<bool>                dump_refresh_in_flight{false};
	std::atomic<bool>                disasm_refresh_in_flight{false};


	std::mutex                       trap_mtx;
	std::condition_variable          trap_cv;
	std::atomic<bool>                trap_signaled{false};
	uint64_t                         pending_trap_address = 0;
};

inline state_t g_state;


void initialize();
void shutdown();


int  add_breakpoint(uint64_t address, bp_type_t type = bp_type_t::software,
					const std::string& name = "", const std::string& condition = "",
					int size = 1);
int add_source_breakpoint(uint64_t address, const std::string& definition_id,
	const std::string& file_path, uint32_t line, uint32_t location_ordinal);
bool remove_breakpoint(int index);
bool remove_source_breakpoint(const std::string& definition_id,
	uint32_t location_ordinal);
bool discard_source_breakpoints_for_target_change(uint32_t previous_pid,
	uint32_t current_pid);
bool toggle_breakpoint(int index);
bool clear_all_breakpoints();
bool set_breakpoint_condition(int index, const std::string& condition);
bool set_breakpoint_log(int index, const std::string& log_text, bool auto_continue);


enum class bp_hit_action_t : int {
	stop = 0,
	resume,
};

bp_hit_action_t handle_breakpoint_hit(uint64_t address);


std::vector<std::string> pop_log_messages();
size_t log_message_count();
const std::string& last_error();


bool run_target();
bool pause_target();
bool step_into();
bool step_over();
bool step_out();
bool run_to_address(uint64_t address, bool wait_for_completion = false, uint32_t timeout_ms = 30000);

bool spawn_and_attach_target(const std::wstring& exe_path,
                             const std::wstring& args,
                             const std::wstring& working_dir,
                             uint32_t* out_pid);

bool spawn_and_attach_target(const run_target::launch_options_t& opts,
                             uint32_t* out_pid,
                             run_target::launch_result_t* out_result = nullptr);


register_set_t get_registers();
bool set_register(const std::string& name, uint64_t value);


register_set_t              cached_registers();
bool                        try_cached_registers(register_set_t& output);
std::vector<cached_thread_t> cached_thread_list();
std::vector<uint8_t>        cached_stack_bytes(uint64_t& addr_out);
std::vector<uint8_t>        cached_dump_bytes(uint64_t& addr_out, size_t& size_out);
bool                        dump_refresh_in_flight();
std::vector<uint8_t>        cached_disasm_window(uint64_t& base_out);

void request_refresh(uint32_t max_age_ms = 100);
void request_thread_refresh(uint32_t max_age_ms = 250);
void request_stack_refresh(uint64_t rsp, size_t bytes, uint32_t max_age_ms = 100);
void request_dump_refresh(uint64_t addr, size_t bytes, uint32_t max_age_ms = 100);
void request_disasm_refresh(uint64_t rip, uint32_t max_age_ms = 100);
void invalidate_cache();


void signal_trap(uint64_t address);
bool wait_for_trap(uint64_t expected_address, uint32_t timeout_ms);


std::vector<stack_frame_t> get_call_stack();
std::vector<call_stack_symbol_resolution_t> resolve_call_stack_frames(const std::vector<uint64_t>& addresses);
call_stack_symbol_resolution_t resolve_call_stack_frame(uint64_t address);
std::string call_stack_frame_resolver_evidence(uint64_t address);


std::vector<memory_region_t> get_memory_map();


int  add_watch(const std::string& expression);
bool remove_watch(int index);
void refresh_watches();
expression_evaluation_t evaluate_expression(const std::string& expression);
watch_refresh_batch_ptr capture_watch_refresh_batch();
watch_refresh_evaluation_batch_t evaluate_watch_refresh_batch(
	watch_refresh_batch_ptr batch,
	watch_refresh_cancel_fn_t cancel_requested = {});
watch_refresh_publish_result_t publish_watch_refresh_batch(
	const watch_refresh_evaluation_batch_t& batch);
bool publish_watch_evaluation(int index, const std::string& expected_expression,
	uint64_t expected_watches_generation,
	const expression_evaluation_t& evaluation);


bool start_trace(int max_records = 50000);
bool stop_trace();


void set_comment(uint64_t address, const std::string& text);
void set_label(uint64_t address, const std::string& text);
void toggle_bookmark(uint64_t address);
std::string get_comment(uint64_t address);
std::string get_label(uint64_t address);


void enumerate_handles();
void find_strings(size_t min_length = 4);
void find_strings_async(size_t min_length = 4);
void request_strings_cancel();


std::string format_flags(uint64_t rflags);
std::string format_protect(uint32_t protect);

std::vector<breakpoint_t> snapshot_breakpoints();
std::vector<watch_entry_t> snapshot_watches();
void restore_breakpoints_and_watches(std::vector<breakpoint_t> bps,
									 std::vector<watch_entry_t> ws);
void clear_breakpoints_and_watches();

}
