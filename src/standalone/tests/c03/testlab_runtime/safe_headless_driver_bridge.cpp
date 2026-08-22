#if !defined(AIDA_C03_SAFE_HEADLESS_RUNTIME) || AIDA_C03_SAFE_HEADLESS_RUNTIME != 1
#error AIDA_C03_SAFE_HEADLESS_RUNTIME_must_equal_1
#endif

#include <algorithm>

#include "../../../src/core/runtime/standalone_driver.hpp"
#include "../../../src/core/runtime/standalone_driver_identity.hpp"
#include "../../../../../driver/comm.h"

namespace {

thread_local driver_bridge::remote_call_context_t g_safe_remote_call_context{};
thread_local bool g_safe_remote_call_context_active = false;

}

namespace driver_bridge {

bool initialize()
{
    return false;
}

bool load_kernel_driver()
{
    return false;
}

bool is_loaded()
{
    return false;
}

bool using_kernel_driver()
{
    return false;
}

bool can_read_memory()
{
    return false;
}

bool kernel_session_available(std::string* reason)
{
    if (reason)
        *reason = "Safe headless runtime has no kernel session";
    return false;
}

bool attach(uint32_t)
{
    return false;
}

void detach()
{
}

void shutdown(const char*)
{
}

bool attach_additional(uint32_t)
{
    return false;
}

bool set_active_pid(uint32_t)
{
    return false;
}

bool detach_one(uint32_t)
{
    return false;
}

bool clear_active_pid()
{
    return false;
}

std::vector<uint32_t> attached_pids()
{
    return {};
}

std::string status()
{
    return "Safe headless runtime: driver unavailable";
}

std::string last_error()
{
    return "Safe headless runtime prohibits driver and process access";
}

uint32_t attached_pid()
{
    return 0;
}

bool attached_process_alive(uint32_t* exit_code_out)
{
    if (exit_code_out)
        *exit_code_out = 0;
    return false;
}

std::string attached_process_name()
{
    return {};
}

std::vector<process_info_t> enumerate_processes()
{
    return {};
}

std::vector<module_info_t> enumerate_modules()
{
    return {};
}

std::vector<thread_info_t> enumerate_threads()
{
    return {};
}

std::vector<memory_region_t> enumerate_memory_regions(size_t)
{
    return {};
}

bool query_memory(uint64_t, memory_region_t& region)
{
    region = {};
    return false;
}

bool read_memory(uint64_t, size_t, std::vector<uint8_t>& out)
{
    out.clear();
    return false;
}

bool write_memory(uint64_t, const std::vector<uint8_t>&)
{
    return false;
}

bool read_string(uint64_t, size_t, std::string& out)
{
    out.clear();
    return false;
}

bool read_memory_for(uint32_t, uint64_t, size_t, std::vector<uint8_t>& out)
{
    out.clear();
    return false;
}

bool write_memory_for(uint32_t, uint64_t, const std::vector<uint8_t>&)
{
    return false;
}

bool query_memory_for(uint32_t, uint64_t, memory_region_t& region)
{
    region = {};
    return false;
}

bool protect_memory_for(uint32_t, uint64_t, uint64_t, uint32_t, uint32_t* old_protect)
{
    if (old_protect)
        *old_protect = 0;
    return false;
}

bool protect_memory_for_bounded(uint32_t, uint64_t, uint64_t, uint32_t, uint32_t* old_protect, uint32_t)
{
    if (old_protect)
        *old_protect = 0;
    return false;
}

std::vector<module_info_t> enumerate_modules_for(uint32_t)
{
    return {};
}

std::vector<thread_info_t> enumerate_threads_for(uint32_t)
{
    return {};
}

std::vector<memory_region_t> enumerate_memory_regions_for(uint32_t, size_t)
{
    return {};
}

bool read_peb_for(uint32_t, peb_info_t& out)
{
    out = {};
    return false;
}

uint64_t resolve_export_for(uint32_t, uint64_t, const char*)
{
    return 0;
}

uint64_t resolve_export_for_kernel_strict(uint32_t, uint64_t, const char*)
{
    return 0;
}

uint64_t allocate_memory_for(uint32_t, size_t)
{
    return 0;
}

bool free_memory_for(uint32_t, uint64_t)
{
    return false;
}

bool read_kernel_memory(uint64_t, size_t, std::vector<uint8_t>& out)
{
    out.clear();
    return false;
}

bool write_kernel_memory(uint64_t, const std::vector<uint8_t>&)
{
    return false;
}

uint64_t allocate_memory(size_t)
{
    return 0;
}

bool free_memory(uint64_t)
{
    return false;
}

bool protect_memory(uint64_t, uint64_t, uint32_t, uint32_t* old_protect)
{
    if (old_protect)
        *old_protect = 0;
    return false;
}

bool get_thread_context(uint32_t, thread_context_t& context)
{
    context = {};
    return false;
}

bool set_thread_context(uint32_t, const thread_context_t&, uint64_t)
{
    return false;
}

bool suspend_thread(uint32_t, uint32_t* prev_count)
{
    if (prev_count)
        *prev_count = 0;
    return false;
}

bool resume_thread(uint32_t, uint32_t* prev_count)
{
    if (prev_count)
        *prev_count = 0;
    return false;
}

bool query_thread_information(uint32_t, uint32_t, void* buffer, uint32_t buffer_size, uint32_t* return_length)
{
    if (buffer && buffer_size != 0)
        std::fill_n(static_cast<uint8_t*>(buffer), buffer_size, static_cast<uint8_t>(0));
    if (return_length)
        *return_length = 0;
    return false;
}

uint64_t resolve_export(uint64_t, const char*)
{
    return 0;
}

uint64_t call_function(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
    return 0;
}

bool set_hardware_breakpoint(uint32_t, int, uint64_t, int, int)
{
    return false;
}

bool clear_hardware_breakpoint(uint32_t, int)
{
    return false;
}

scoped_remote_call_context_t::scoped_remote_call_context_t(const remote_call_context_t& context)
    : previous_(g_safe_remote_call_context)
    , previous_active_(g_safe_remote_call_context_active)
    , active_(true)
{
    g_safe_remote_call_context = context;
    g_safe_remote_call_context_active = true;
}

scoped_remote_call_context_t::~scoped_remote_call_context_t()
{
    if (!active_)
        return;
    if (previous_active_) {
        g_safe_remote_call_context = previous_;
        g_safe_remote_call_context_active = true;
    } else {
        g_safe_remote_call_context = {};
        g_safe_remote_call_context_active = false;
    }
    active_ = false;
}

const char* current_remote_call_tool_name() noexcept
{
    return g_safe_remote_call_context_active ? g_safe_remote_call_context.tool : nullptr;
}

const char* current_remote_call_diag_id() noexcept
{
    return g_safe_remote_call_context_active ? g_safe_remote_call_context.diag_id : nullptr;
}

uint32_t current_remote_call_timeout_ms() noexcept
{
    return g_safe_remote_call_context_active ? g_safe_remote_call_context.timeout_ms : 0;
}

uint64_t current_remote_call_deadline_ms() noexcept
{
    return g_safe_remote_call_context_active ? g_safe_remote_call_context.deadline_ms : 0;
}

bool current_remote_call_cancelled() noexcept
{
    if (!g_safe_remote_call_context_active)
        return false;
    if (g_safe_remote_call_context.cancel_token &&
        g_safe_remote_call_context.cancel_token->load(std::memory_order_acquire))
        return true;
    return g_safe_remote_call_context.deadline_ms != 0 &&
           GetTickCount64() >= g_safe_remote_call_context.deadline_ms;
}

remote_call_execution_diag_t last_remote_call_execution_diag()
{
    return {};
}

bool lower_remote_call_last_abandoned() noexcept
{
    return false;
}

namespace detail {

uint32_t remote_call_um_inflight_count_global() noexcept
{
    return 0;
}

}

std::vector<net_connection_info_t> enumerate_connections(uint32_t, uint32_t)
{
    return {};
}

bool start_capture(uint32_t, uint32_t, uint32_t, const uint8_t*, uint32_t)
{
    return false;
}

bool stop_capture()
{
    return false;
}

void cancel_inflight_capture()
{
}

bool get_capture_status(bool& active, uint32_t& captured, uint32_t& dropped)
{
    active = false;
    captured = 0;
    dropped = 0;
    return false;
}

std::vector<captured_packet_t> get_captured_packets(uint32_t)
{
    return {};
}

std::vector<captured_packet_t> get_captured_packets_bounded(uint32_t, uint32_t)
{
    return {};
}

std::vector<dns_entry_t> get_dns_queries(uint32_t)
{
    return {};
}

bool add_filter_rule(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    const uint8_t*, const uint8_t*, uint32_t* out_rule_id)
{
    if (out_rule_id)
        *out_rule_id = 0;
    return false;
}

bool remove_filter_rule(uint32_t)
{
    return false;
}

bool clear_filter_rules()
{
    return false;
}

bool get_network_stats(network_stats_t& stats)
{
    stats = {};
    return false;
}

bool bw_monitor_op(uint32_t, uint32_t, bw_stats_t* out_stats)
{
    if (out_stats)
        *out_stats = {};
    return false;
}

std::vector<bw_process_info_t> get_bw_per_process(uint32_t)
{
    return {};
}

std::vector<dpi_result_t> get_dpi_results(uint32_t, uint32_t, uint32_t, uint32_t)
{
    return {};
}

std::vector<wfp_callout_info_t> enumerate_wfp_callouts(const std::string&)
{
    return {};
}

std::vector<socket_info_t> get_socket_handles(uint32_t)
{
    return {};
}

std::vector<tcpip_connection_t> dump_tcpip_connections(uint32_t, uint32_t)
{
    return {};
}

std::vector<net_iface_info_t> enumerate_interfaces()
{
    return {};
}

std::vector<held_packet_info_t> get_held_packets()
{
    return {};
}

std::vector<mod_rule_info_t> list_packet_mod_rules()
{
    return {};
}

std::vector<redirect_rule_info_t> list_redirect_rules()
{
    return {};
}

std::vector<dns_spoof_info_t> list_dns_spoof_rules()
{
    return {};
}

bool fingerprint_op(uint32_t)
{
    return false;
}

std::vector<fingerprint_info_t> get_fingerprints()
{
    return {};
}

bool export_pcap(uint32_t, uint32_t, uint32_t, pcap_export_result_t* out)
{
    if (out)
        *out = {};
    return false;
}

bool traffic_redirect_op(uint32_t, uint32_t, uint32_t, uint32_t, const uint8_t*,
    uint32_t, const uint8_t*, uint32_t, uint32_t* out_rule_id, uint32_t)
{
    if (out_rule_id)
        *out_rule_id = 0;
    return false;
}

bool inject_packet(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    const uint8_t*, const uint8_t*, const uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t)
{
    return false;
}

bool kill_connection(uint32_t, uint32_t, uint32_t, uint32_t,
    const uint8_t*, const uint8_t*, uint32_t)
{
    return false;
}

bool intercept_op(uint32_t, uint32_t, uint32_t, uint32_t, uint64_t,
    const uint8_t*, uint32_t, uint32_t* out_held_count, bool* out_active)
{
    if (out_held_count)
        *out_held_count = 0;
    if (out_active)
        *out_active = false;
    return false;
}

bool dns_spoof_op(uint32_t, uint32_t, const char*, const uint8_t*,
    uint32_t, uint32_t, uint32_t* out_rule_id)
{
    if (out_rule_id)
        *out_rule_id = 0;
    return false;
}

bool packet_mod_rule_op(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    const uint8_t*, uint32_t, const uint8_t*, uint32_t, uint32_t* out_rule_id)
{
    if (out_rule_id)
        *out_rule_id = 0;
    return false;
}

bool stream_reassemble_op(uint32_t, uint32_t, uint32_t, uint32_t,
    const uint8_t*, const uint8_t*, std::vector<uint8_t>* out_data,
    uint32_t* out_packets, uint32_t* out_truncated)
{
    if (out_data)
        out_data->clear();
    if (out_packets)
        *out_packets = 0;
    if (out_truncated)
        *out_truncated = 0;
    return false;
}

bool sniff_net_buffers_start(uint64_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)
{
    return false;
}

bool sniff_net_buffers_stop()
{
    return false;
}

std::vector<sniff_result_t> sniff_net_buffers_get(bool& active)
{
    active = false;
    return {};
}

bool spoof_debug_flags(uint32_t* result_flags)
{
    if (result_flags)
        *result_flags = 0;
    return false;
}

}

namespace voyager {

bool device_t::connect() noexcept
{
    disconnect();
    last_connect_error_ = ERROR_ACCESS_DENIED;
    return false;
}

bool device_t::clear_process_context() noexcept
{
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    shellcode_address_ = 0;
    spoof_gadget_ = 0;
    shellcode_pid_ = 0;
    shellcode_dtb_at_alloc_ = 0;
    return true;
}

std::uint64_t device_t::find_image() noexcept
{
    base_address_ = 0;
    return 0;
}

void device_t::solve_dtb() noexcept
{
    dtb_ = 0;
}

std::size_t device_t::read_raw(std::uint64_t, void* buffer, std::size_t size) const noexcept
{
    if (buffer && size != 0)
        std::fill_n(static_cast<std::uint8_t*>(buffer), size, static_cast<std::uint8_t>(0));
    return 0;
}

std::size_t device_t::write_raw(std::uint64_t, const void*, std::size_t) const noexcept
{
    return 0;
}

std::size_t device_t::read_kernel_raw(std::uint64_t, void* buffer, std::size_t size) const noexcept
{
    if (buffer && size != 0)
        std::fill_n(static_cast<std::uint8_t*>(buffer), size, static_cast<std::uint8_t>(0));
    return 0;
}

std::uint64_t device_t::allocate_memory(std::size_t) noexcept
{
    return 0;
}

bool device_t::free_memory(std::uint64_t) noexcept
{
    return false;
}

std::uint64_t device_t::call_function(std::uint64_t, std::uint64_t, std::uint64_t,
    std::uint64_t, std::uint64_t) noexcept
{
    return 0;
}

bool device_t::get_thread_context(std::uint32_t, thread_context& context) noexcept
{
    context = {};
    return false;
}

std::vector<device_t::thread_info> device_t::enumerate_threads() noexcept
{
    return {};
}

bool device_t::suspend_thread(std::uint32_t, std::uint32_t* prev_count) noexcept
{
    if (prev_count)
        *prev_count = 0;
    return false;
}

bool device_t::resume_thread(std::uint32_t, std::uint32_t* prev_count) noexcept
{
    if (prev_count)
        *prev_count = 0;
    return false;
}

bool device_t::query_thread_basic_information(
    std::uint32_t, detail::thread_query_information_request& info) noexcept
{
    info = {};
    return false;
}

bool device_t::query_memory(std::uint64_t, memory_region_info& info) noexcept
{
    info = {};
    return false;
}

bool device_t::protect_memory(std::uint64_t, std::uint64_t, std::uint32_t,
    std::uint32_t* old_protect) noexcept
{
    if (old_protect)
        *old_protect = 0;
    return false;
}

std::vector<detail::region_entry> device_t::enumerate_memory_regions(
    std::uint64_t, std::uint64_t, bool) noexcept
{
    return {};
}

bool device_t::read_peb(peb_info& info) noexcept
{
    info = {};
    return false;
}

std::uint64_t device_t::resolve_export(std::uint64_t, const char*) noexcept
{
    return 0;
}

std::uint64_t device_t::virtual_to_physical(std::uint64_t) noexcept
{
    return 0;
}

bool device_t::query_ssdt(ssdt_info& info) noexcept
{
    info = {};
    return false;
}

bool device_t::set_hardware_breakpoint(std::uint32_t, int, std::uint64_t, int, int) noexcept
{
    return false;
}

bool device_t::clear_hardware_breakpoint(std::uint32_t, int) noexcept
{
    return false;
}

bool device_t::start_capture(std::uint32_t, std::uint32_t, std::uint32_t,
    const std::uint8_t*, std::uint32_t) noexcept
{
    return false;
}

bool device_t::stop_capture() noexcept
{
    return false;
}

bool device_t::get_capture_status(bool& active, std::uint32_t& captured,
    std::uint32_t& dropped) noexcept
{
    active = false;
    captured = 0;
    dropped = 0;
    return false;
}

std::vector<device_t::captured_packet> device_t::get_captured_packets(std::uint32_t) noexcept
{
    return {};
}

bool device_t::sniff_net_buffers_start(std::uint64_t, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, std::uint32_t) noexcept
{
    return false;
}

bool device_t::sniff_net_buffers_stop() noexcept
{
    return false;
}

std::vector<device_t::sniff_result> device_t::sniff_net_buffers_get(bool& active) noexcept
{
    active = false;
    return {};
}

bool device_t::sniff_net_buffers_store(std::uint64_t, std::uint64_t,
    const std::uint8_t*, std::uint32_t) noexcept
{
    return false;
}

std::vector<device_t::dpi_result> device_t::get_dpi_results(
    std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t) noexcept
{
    return {};
}

bool device_t::intercept_op(std::uint32_t, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint64_t, const std::uint8_t*, std::uint32_t,
    std::uint32_t* out_held_count, bool* out_active) noexcept
{
    if (out_held_count)
        *out_held_count = 0;
    if (out_active)
        *out_active = false;
    return false;
}

std::vector<device_t::held_packet_info> device_t::get_held_packets() noexcept
{
    return {};
}

bool device_t::stream_reassemble_op(std::uint32_t, std::uint32_t, std::uint32_t,
    std::uint32_t, const std::uint8_t*, const std::uint8_t*,
    std::vector<std::uint8_t>* out_data, std::uint32_t* out_packets,
    std::uint32_t* out_truncated) noexcept
{
    if (out_data)
        out_data->clear();
    if (out_packets)
        *out_packets = 0;
    if (out_truncated)
        *out_truncated = 0;
    return false;
}

bool device_t::set_process_id(std::uint32_t) noexcept
{
    return clear_process_context();
}

void device_t::disconnect() noexcept
{
    driver_handle_ = INVALID_HANDLE_VALUE;
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    kernel_dtb_ = 0;
    shellcode_address_ = 0;
    spoof_gadget_ = 0;
    last_failed_tid_ = 0;
    last_hijacked_tid_ = 0;
    last_connect_error_ = 0;
    inflight_capture_thread_.store(nullptr, std::memory_order_release);
    inflight_capture_cancel_pending_.store(false, std::memory_order_release);
    ntdll_base_ = 0;
    ntdll_size_ = 0;
    shellcode_pid_ = 0;
    shellcode_dtb_at_alloc_ = 0;
}

}

namespace driver_bridge::identity {

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

bool capture_live_target_identity(std::uint32_t, std::uint64_t,
    live_target_identity_t& out, std::string* out_error)
{
    out = {};
    if (out_error)
        *out_error = "TARGET_PROCESS_UNAVAILABLE: safe headless runtime prohibits process identity capture";
    return false;
}

validation_result_t validate_live_target_identity(const live_target_identity_t&)
{
    validation_result_t result;
    result.matches = false;
    result.staleness = staleness_t::process_unavailable;
    result.detail = "Safe headless runtime prohibits process identity validation";
    return result;
}

validation_result_t validate_attached_target_identity(const live_target_identity_t&)
{
    validation_result_t result;
    result.matches = false;
    result.staleness = staleness_t::process_unavailable;
    result.detail = "Safe headless runtime has no attached target identity";
    return result;
}

bool refresh_attached_target_identity(const live_target_identity_t&, std::string* out_error)
{
    if (out_error)
        *out_error = "TARGET_PROCESS_UNAVAILABLE: safe headless runtime has no attached target identity";
    return false;
}

}
