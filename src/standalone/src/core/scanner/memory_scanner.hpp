#pragma once

#include <atomic>
#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../runtime/standalone_driver_identity.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/preview_fixture_controls.hpp"
#endif

namespace aida::analysis {
class byte_provider_t;
class pe_image_t;
}

namespace memory_scanner {

enum class value_type_t : int {
	byte_val     = 0,
	int16_val    = 1,
	int32_val    = 2,
	int64_val    = 3,
	float_val    = 4,
	double_val   = 5,
	string_ascii = 6,
	string_utf16 = 7,
	byte_array   = 8,
	all_types    = 9,
	COUNT
};

enum class scan_mode_t : int {
	exact          = 0,
	bigger_than    = 1,
	smaller_than   = 2,
	value_between  = 3,
	changed        = 4,
	unchanged      = 5,
	increased      = 6,
	decreased      = 7,
	unknown_initial = 8,
	COUNT
};

inline const char* value_type_name(value_type_t t) {
	static const char* names[] = {
		"Byte", "Int16", "Int32", "Int64", "Float", "Double",
		"ASCII String", "UTF-16 String", "Byte Array", "All Types"
	};
	return (static_cast<int>(t) < static_cast<int>(value_type_t::COUNT))
		? names[static_cast<int>(t)] : "Unknown";
}

inline const char* scan_mode_name(scan_mode_t m) {
	static const char* names[] = {
		"Exact Value", "Bigger Than", "Smaller Than", "Between",
		"Changed", "Unchanged", "Increased", "Decreased", "Unknown Initial"
	};
	return (static_cast<int>(m) < static_cast<int>(scan_mode_t::COUNT))
		? names[static_cast<int>(m)] : "Unknown";
}

inline size_t value_type_size(value_type_t t) {
	switch (t) {
		case value_type_t::byte_val:     return 1;
		case value_type_t::int16_val:    return 2;
		case value_type_t::int32_val:    return 4;
		case value_type_t::int64_val:    return 8;
		case value_type_t::float_val:    return 4;
		case value_type_t::double_val:   return 8;
		default: return 4;
	}
}

struct scan_result_t {
	uint64_t             address = 0;
	std::vector<uint8_t> current_value;
	std::vector<uint8_t> previous_value;
	std::string          module_name;
	uint64_t             module_offset = 0;
};

struct address_entry_t {
	uint64_t    address = 0;
	std::string description;
	value_type_t value_type = value_type_t::int32_val;
	bool        frozen = false;
	std::vector<uint8_t> freeze_value;
	std::vector<uint8_t> last_value;
	uint32_t    target_pid = 0;
	uint64_t    target_epoch = 0;
	driver_bridge::identity::live_target_identity_t target_identity;
};

struct write_transaction_result_t {
	bool original_read_ok = false;
	bool write_attempted = false;
	bool write_ok = false;
	bool readback_ok = false;
	bool verified = false;
	bool rollback_attempted = false;
	bool rollback_write_ok = false;
	bool rollback_readback_ok = false;
	bool rollback_verified = false;
	uint32_t target_pid = 0;
	uint64_t process_creation_time_100ns = 0;
	std::vector<uint8_t> original_bytes;
	std::vector<uint8_t> readback_bytes;
	std::vector<uint8_t> rollback_readback_bytes;
	std::string error;
};

struct pointer_result_t {
	uint64_t              base_address = 0;
	std::string           module_name;
	uint64_t              module_offset = 0;
	std::vector<int64_t>  offsets;
};

struct scan_config_t {
	value_type_t  value_type = value_type_t::int32_val;
	scan_mode_t   scan_mode = scan_mode_t::exact;
	std::string   value_text;
	std::string   value_text2;
	bool          hex_input = false;
	bool          is_signed = true;
	size_t        alignment = 4;
	bool          writable_only = true;
	bool          executable_exclude = true;
	uint64_t      range_base = 0;
	uint64_t      range_size = 0;
};

struct state_t {
	std::mutex                     results_mutex;
	std::vector<scan_result_t>     results;
	size_t                         total_found = 0;

	std::mutex                     address_mutex;
	std::vector<address_entry_t>   address_list;

	std::mutex                     pointer_mutex;
	std::vector<pointer_result_t>  pointer_results;

	scan_config_t                  config;
	bool                           has_initial_scan = false;
	int                            scan_count = 0;

	std::atomic<bool>              scanning{false};
	std::atomic<float>             scan_progress{0.f};
	std::atomic<bool>              scan_thread_done{true};

	std::atomic<bool>              freeze_active{false};
	std::atomic<bool>              freeze_thread_done{true};

	std::atomic<bool>              pointer_scanning{false};
	std::atomic<float>             pointer_progress{0.f};
	std::atomic<bool>              pointer_thread_done{true};
	uint32_t                       pointer_target_pid = 0;
	uint64_t                       pointer_target_epoch = 0;
	driver_bridge::identity::live_target_identity_t pointer_target_identity;

	std::vector<std::vector<scan_result_t>> scan_history;

	std::mutex                         target_binding_mutex;
	std::atomic<uint32_t>              observed_target_pid{0};
	std::atomic<uint64_t>              observed_target_creation_time_100ns{0};
	std::atomic<uint64_t>              target_epoch{1};
	uint32_t                           scan_target_pid = 0;
	uint64_t                           scan_target_epoch = 0;
	driver_bridge::identity::live_target_identity_t scan_target_identity;
	bool                               scan_static_binary = false;
	std::string                        scan_workspace_id;
	uint64_t                           scan_workspace_generation = 0;
	std::atomic<uint32_t>              persisted_loaded_pid{0};
	std::atomic<uint64_t>              persisted_loaded_creation_time_100ns{0};
	std::atomic<bool>                  persisted_config_loaded{false};
	std::mutex                         freeze_wait_mutex;
	std::condition_variable            freeze_wait_cv;
};

inline state_t g_state;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/scan_memory_preview.inl"
#else
void initialize();
void shutdown();

bool first_scan(const scan_config_t& config);
bool first_static_scan(const scan_config_t& config,
	std::shared_ptr<const aida::analysis::byte_provider_t> provider,
	std::shared_ptr<const aida::analysis::pe_image_t> image,
	std::string workspace_id, uint64_t workspace_generation);
bool next_scan(scan_mode_t mode, const std::string& value_text, const std::string& value_text2 = "");
bool cancel_scan();
void undo_scan();
void reset_scan();

void add_address(uint64_t address, const std::string& description, value_type_t type);
void remove_address(size_t index);
void freeze_address(size_t index, bool enable);
bool freeze_address_exact(size_t index, bool enable, const address_entry_t& expected);
write_transaction_result_t write_value_exact(uint64_t address, value_type_t type,
	const std::string& value_text, bool hex, uint32_t expected_pid,
	uint64_t expected_process_creation_time_100ns);
void write_value(uint64_t address, value_type_t type, const std::string& value_text, bool hex = false);
std::string read_value_string(uint64_t address, value_type_t type);
void refresh_address_list();
uint64_t observe_target_binding(uint32_t pid);
bool target_binding_current(uint32_t pid, uint64_t epoch);
bool validate_target_binding(uint32_t pid, uint64_t epoch,
	uint64_t process_creation_time_100ns);

bool start_pointer_scan(uint64_t target_address, int max_depth, int max_offset, uint64_t scan_base = 0, uint64_t scan_size = 0);
void cancel_pointer_scan();

std::string format_value(const std::vector<uint8_t>& bytes, value_type_t type);
std::vector<uint8_t> parse_value(const std::string& text, value_type_t type, bool hex);
#endif

}
