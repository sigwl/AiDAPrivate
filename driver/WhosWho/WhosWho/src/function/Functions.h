#pragma once
#include <ntifs.h>
#include "Struct.h"
#include "impl/driver/Strong.h"

namespace functions {
    NTSTATUS handle777d(p_dtb_solve request);
    NTSTATUS handle777e(p_physical_rw request, KPROCESSOR_MODE requestor_mode);
    NTSTATUS handle777f(p_base_address request);
    NTSTATUS handle7781(p_remote_call request);
    NTSTATUS handle7782(p_call_result request);
    NTSTATUS handle7782_legacy(p_call_result request);
    NTSTATUS handle7783(p_alloc_mem request);
    NTSTATUS handle7784(p_free_mem request);


    NTSTATUS handle_thread_ctx(p_thread_ctx request);
    NTSTATUS handle_thread_enum(p_thread_enum request);
    NTSTATUS handle_suspend_resume_thread(p_suspend_resume_thread request);
    NTSTATUS handle_thread_query_information(p_thread_query_information request);
    NTSTATUS handle_terminate_thread(p_terminate_thread_request request);
    NTSTATUS handle_close_process_handle(p_close_handle_request request);
    NTSTATUS handle_query_memory(p_query_memory request);
    NTSTATUS handle_protect_memory(p_protect_memory request);
    NTSTATUS handle_enum_regions(p_enum_regions request);
    NTSTATUS handle_read_peb(p_read_peb request);
    NTSTATUS handle_spoof_debug_flags(p_spoof_debug request);
    NTSTATUS handle_get_module_export(p_module_export request);
    NTSTATUS handle_virt_to_phys(p_virt_to_phys request);
    NTSTATUS handle_query_ssdt(p_ssdt_query request);


    NTSTATUS handle_net_enum_conn(p_net_enum_conn request);
    NTSTATUS handle_net_cap_ctrl(p_net_cap_ctrl request);
    NTSTATUS handle_net_cap_get(p_net_cap_get request);
    NTSTATUS handle_net_dns_get(p_net_dns_get request);
    NTSTATUS handle_net_filter_rule(p_net_filter_rule request);
    NTSTATUS handle_net_stats(p_net_stats request);


    NTSTATUS handle_wfp_callout_enum(p_wfp_callout_enum request);
    NTSTATUS handle_socket_handle_enum(p_socket_handle_enum request);
    NTSTATUS handle_sniff_net_buffers(p_sniff_net_buffers request);
    NTSTATUS handle_tcpip_conn_dump(p_tcpip_conn_dump request);


    NTSTATUS handle_packet_inject(p_packet_inject_request request);
    NTSTATUS handle_packet_mod_rule(p_packet_mod_rule request);
    NTSTATUS handle_packet_mod_rule_list(p_packet_mod_rule_list request);
    NTSTATUS handle_traffic_redirect(p_traffic_redirect_rule request);
    NTSTATUS handle_traffic_redirect_list(p_traffic_redirect_list request);
    NTSTATUS handle_stream_reassemble(p_stream_reassemble_request request);
    NTSTATUS handle_deep_inspect(p_dpi_request request);
    NTSTATUS handle_intercept_hold(p_intercept_request request);
    NTSTATUS handle_conn_kill(p_conn_kill_request request);
    NTSTATUS handle_dns_spoof(p_dns_spoof_rule request);
    NTSTATUS handle_dns_spoof_list(p_dns_spoof_list request);
    NTSTATUS handle_bw_monitor(p_bw_monitor_request request);
    NTSTATUS handle_net_iface_enum(p_net_interface_enum request);
    NTSTATUS handle_pcap_export(p_pcap_export_request request);
    NTSTATUS handle_net_fingerprint(p_net_fingerprint_request request);
}
